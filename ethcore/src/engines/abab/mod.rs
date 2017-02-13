// Copyright 2015-2017 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

/// Abab BFT consensus engine with round robin proof-of-authority.

mod message;
mod params;

use std::sync::Weak;
use std::sync::atomic::{AtomicUsize, Ordering as AtomicOrdering};
use util::*;
use client::{Client, EngineClient};
use error::{Error, BlockError};
use header::Header;
use builtin::Builtin;
use env_info::EnvInfo;
use rlp::{UntrustedRlp, View as RlpView};
use ethkey::{recover, public_to_address};
use account_provider::AccountProvider;
use block::*;
use spec::CommonParams;
use engines::{Engine, Seal, EngineError};
use blockchain::extras::BlockDetails;
use views::HeaderView;
use evm::Schedule;
use state::CleanupMode;
use io::IoService;
use super::signer::EngineSigner;
use super::validator_set::{ValidatorSet, new_validator_set};
use super::transition::TransitionHandler;
use super::vote_collector::VoteCollector;
use self::message::*;
use self::params::AbabParams;

pub type Height = usize;
pub type View = usize;
pub type BlockHash = H256;

/// Engine using `Abab` consensus algorithm, suitable for EVM chain.
pub struct Abab {
	params: CommonParams,
	gas_limit_bound_divisor: U256,
	builtins: BTreeMap<Address, Builtin>,
	transition: IoService<()>,
	client: RwLock<Option<Weak<EngineClient>>>,
	block_reward: U256,
	/// Blockchain height.
	height: AtomicUsize,
	/// Consensus view.
	view: AtomicUsize,
	/// Vote accumulator.
	votes: VoteCollector<AbabMessage>,
	/// Used to sign messages and proposals.
	signer: EngineSigner,
	/// Bare hash of the proposed block, used for seal submission.
	proposal: RwLock<Option<H256>>,
	/// Set used to determine the current validators.
	validators: Box<ValidatorSet + Send + Sync>,
}

impl Abab {
	/// Create a new instance of Abab engine
	pub fn new(params: CommonParams, our_params: AbabParams, builtins: BTreeMap<Address, Builtin>) -> Result<Arc<Self>, Error> {
		let engine = Arc::new(
			Abab {
				params: params,
				gas_limit_bound_divisor: our_params.gas_limit_bound_divisor,
				builtins: builtins,
				client: RwLock::new(None),
				transition: IoService::<()>::start()?,
				block_reward: our_params.block_reward,
				height: AtomicUsize::new(1),
				view: AtomicUsize::new(0),
				votes: VoteCollector::default(),
				signer: Default::default(),
				proposal: RwLock::new(None),
				validators: new_validator_set(our_params.validators),
			});
		let handler = TransitionHandler::new(Arc::downgrade(&engine) as Weak<Engine>, Box::new(our_params.timeout));
		engine.transition.register_handler(Arc::new(handler))?;
		Ok(engine)
	}

	fn update_sealing(&self) {
		if let Some(ref weak) = *self.client.read() {
			if let Some(c) = weak.upgrade() {
				c.update_sealing();
			}
		}
	}

	fn submit_seal(&self, block_hash: H256, seal: Vec<Bytes>) {
		if let Some(ref weak) = *self.client.read() {
			if let Some(c) = weak.upgrade() {
				c.submit_seal(block_hash, seal);
			}
		}
	}

	fn broadcast_message(&self, message: Bytes) {
		if let Some(ref weak) = *self.client.read() {
			if let Some(c) = weak.upgrade() {
				c.broadcast_consensus_message(message);
			}
		}
	}

	fn broadcast_view_change(&self) {
		let view_vote = ViewVote::new_view_change(self.height.load(AtomicOrdering::SeqCst), self.view.load(AtomicOrdering::SeqCst));
		let vote_rlp = ::rlp::encode(&view_vote).to_vec();
		match self.signer.sign(vote_rlp.sha3()).map(Into::into) {
			Ok(signature) => {
				let message_rlp = message_rlp(&signature, &vote_rlp);
				let message = AbabMessage::new(signature, view_vote);
				let validator = self.signer.address();
				self.votes.vote(message.clone(), &validator);
				debug!(target: "engine", "Generated {:?} as {}.", message, validator);
				self.handle_valid_message(&message);
				self.broadcast_message(message_rlp);
			},
			Err(e) => trace!(target: "engine", "Could not sign a consensus message {}", e),
		}
	}

	/// Broadcast all messages since last issued block to get the peers up to speed.
	fn broadcast_old_messages(&self) {
		for m in self.votes.get_up_to(&ViewVote::new_view_change(self.height.load(AtomicOrdering::SeqCst), self.view.load(AtomicOrdering::SeqCst))).into_iter() {
			self.broadcast_message(m);
		}
	}

	fn to_next_height(&self, height: Height) {
		let new_height = height + 1;
		debug!(target: "engine", "Received a Commit, transitioning to height {}.", new_height);
		self.height.store(new_height, AtomicOrdering::SeqCst);
		self.view.store(0, AtomicOrdering::SeqCst);
	}

	fn is_validator(&self, address: &Address) -> bool {
		self.validators.contains(address)
	}

	fn is_above_threshold(&self, n: usize) -> bool {
		n > self.validators.count() * 2/3
	}

	/// Find the designated for the given view.
	fn view_primary(&self, height: Height, view: View) -> Address {
		let primary_nonce = height + view;
		trace!(target: "engine", "Proposer nonce: {}", primary_nonce);
		self.validators.get(primary_nonce)
	}

	/// Check if current signer is a primary for given view.
	fn is_view_primary(&self, height: Height, view: View) -> bool {
		self.signer.is_address(&self.view_primary(height, view))
	}

	/// Check if current signer is the current primary.
	fn is_primary(&self) -> bool {
		self.is_view_primary(self.height.load(AtomicOrdering::SeqCst), self.view.load(AtomicOrdering::SeqCst))
	}

	fn is_height(&self, message: &AbabMessage) -> bool {
		message.view_vote.is_height(self.height.load(AtomicOrdering::SeqCst))
	}

	fn is_view(&self, message: &AbabMessage) -> bool {
		message.view_vote.is_view(self.height.load(AtomicOrdering::SeqCst), self.view.load(AtomicOrdering::SeqCst)) 
	}

	fn new_view(&self) {
		trace!(target: "engine", "New view.");
		self.view.fetch_add(1, AtomicOrdering::SeqCst);
	}

	fn has_enough_votes(&self, message: &AbabMessage) -> bool {
		let aligned_count = self.votes.count_aligned_votes(&message);
		self.is_above_threshold(aligned_count)
	}

	fn is_new_view(&self, view: View) -> bool {
		self.votes.count_aligned_votes(&AbabMessage::new_view_change(Default::default(), self.height.load(AtomicOrdering::SeqCst), view)) > self.validators.count() * 1/3
	}

	fn set_timeout(&self) {
		if let Err(io_err) = self.transition.send_message(()) {
			warn!(target: "engine", "Could not set a new view timeout: {}", io_err)
		}
	}

	fn handle_valid_message(&self, message: &AbabMessage) {
		// Check if it can affect the step transition.
		if !self.is_height(message) { return; }
		let view = self.view.load(AtomicOrdering::SeqCst);
		let height = self.height.load(AtomicOrdering::SeqCst);
		match message.view_vote.vote {
			Vote::Vote(hash) if self.is_primary() && self.has_enough_votes(message) => {
				// Commit the block using a complete signature set.
				let maybe_proposal = self.votes.round_signatures(ViewVote::new_proposal(height, view), hash).get(0);
				if let (Some(block_hash), Some(proposal)) = (*self.proposal.read(), maybe_proposal) {
					// Generate seal and remove old votes.
					let new_view = self.votes.round_signatures(ViewVote::new_view_change(height, view), hash);
					let votes = self.votes.round_signatures(message.view_vote, hash);
					self.votes.throw_out_old(&votes);
					Seal::Proposal(vec![
						::rlp::encode(&view).to_vec(),
						::rlp::encode(&signature).to_vec(),
						::rlp::encode(&new_view).to_vec(),
						::rlp::encode(&votes).to_vec()
					])
				}		
			},
			Vote::ViewChange if self.is_view_primary(height, view) && self.is_new_view(message.view_vote.view) => {
				// Generate a block in the new view.
				self.new_view();
				self.update_sealing();
			},
			_ => {},
		};
	}
}

impl Engine for Abab {
	fn name(&self) -> &str { "Abab" }
	fn version(&self) -> SemanticVersion { SemanticVersion::new(1, 0, 0) }
	/// (consensus view, proposal signature, view change signatures, vote signatures)
	fn seal_fields(&self) -> usize { 4 }

	fn params(&self) -> &CommonParams { &self.params }
	fn builtins(&self) -> &BTreeMap<Address, Builtin> { &self.builtins }

	fn maximum_uncle_count(&self) -> usize { 0 }
	fn maximum_uncle_age(&self) -> usize { 0 }

	/// Additional engine-specific information for the user/developer concerning `header`.
	fn extra_info(&self, header: &Header) -> BTreeMap<String, String> {
		let message = AbabMessage::new_proposal(header).expect("Invalid header.");
		message.info()
	}

	fn schedule(&self, _env_info: &EnvInfo) -> Schedule {
		Schedule::new_post_eip150(usize::max_value(), true, true, true)
	}

	fn populate_from_parent(&self, header: &mut Header, parent: &Header, gas_floor_target: U256, _gas_ceil_target: U256) {
		header.set_difficulty(parent.difficulty().clone());
		header.set_gas_limit({
			let gas_limit = parent.gas_limit().clone();
			let bound_divisor = self.gas_limit_bound_divisor;
			if gas_limit < gas_floor_target {
				min(gas_floor_target, gas_limit + gas_limit / bound_divisor - 1.into())
			} else {
				max(gas_floor_target, gas_limit - gas_limit / bound_divisor + 1.into())
			}
		});
	}

	/// Should this node participate.
	fn is_sealer(&self, address: &Address) -> Option<bool> {
		Some(self.is_validator(address))
	}

	/// Attempt to seal generate a proposal seal.
	fn generate_seal(&self, block: &ExecutedBlock) -> Seal {
		let header = block.header();
		let author = header.author();
		// Only primary can generate seal if None was generated.
		if !self.is_primary() || self.proposal.read().is_some() {
			return Seal::None;
		}

		let height = header.number() as Height;
		let view = self.view.load(AtomicOrdering::SeqCst);
		let bh = header.bare_hash();
		let proposal = ViewVote::new_proposal(height, view, bh);
		if let Ok(signature) = self.signer.sign(::rlp::encode(&proposal).sha3()).map(Into::into) {
			// Insert Propose vote.
			debug!(target: "engine", "Submitting proposal {} at height {} view {}.", bh, height, view);
			self.votes.vote(AbabMessage { signature: signature, message: proposal }, author);
			// Remember proposal for later seal submission.
			*self.proposal.write() = Some(bh);
			let new_view = self.votes.round_signatures(ViewVote::new_view_change(proposal_step.height, proposal_step.view), bh);
			Seal::Proposal(vec![
				::rlp::encode(&view).to_vec(),
				::rlp::encode(&signature).to_vec(),
				::rlp::encode(&new_view).to_vec(),
				::rlp::EMPTY_LIST_RLP.to_vec()
			])
		} else {
			warn!(target: "engine", "generate_seal: FAIL: accounts secret key unavailable");
			Seal::None
		}
	}

	fn handle_message(&self, rlp: &[u8]) -> Result<(), Error> {
		let rlp = UntrustedRlp::new(rlp);
		let message: AbabMessage = rlp.as_val()?;
		if !self.votes.is_old_or_known(&message) {
			let sender = message.verify_raw(rlp)?;
			if !self.is_validator(&sender) {
				Err(EngineError::NotAuthorized(sender))?;
			}
			if self.votes.vote(message.clone(), &sender).is_some() {
				Err(EngineError::DoubleVote(sender))?
			}
			trace!(target: "engine", "Handling a valid {:?} from {}.", message, sender);
			self.broadcast_message(rlp.as_raw().to_vec());
			self.handle_valid_message(&message);
		}
		Ok(())
	}

	/// Apply the block reward on finalisation of the block.
	fn on_close_block(&self, block: &mut ExecutedBlock) {
		let fields = block.fields_mut();
		// Bestow block reward
		fields.state.add_balance(fields.header.author(), &self.block_reward, CleanupMode::NoEmpty);
		// Commit state so that we can actually figure out the state root.
		if let Err(e) = fields.state.commit() {
			warn!("Encountered error on state commit: {}", e);
		}
	}

	fn verify_block_basic(&self, header: &Header, _block: Option<&[u8]>) -> Result<(), Error> {
		let seal_length = header.seal().len();
		if seal_length == self.seal_fields() {
			let signatures_len = header.seal()[2].len();
			if signatures_len >= 1 {
				Ok(())
			} else {
				Err(From::from(EngineError::BadSealFieldSize(OutOfBounds {
					min: Some(1),
					max: None,
					found: signatures_len
				})))
			}
		} else {
			Err(From::from(BlockError::InvalidSealArity(
				Mismatch { expected: self.seal_fields(), found: seal_length }
			)))
		}

	}

	fn verify_block_unordered(&self, header: &Header, _block: Option<&[u8]>) -> Result<(), Error> {
		let proposal = AbabMessage::new_proposal(header)?;
		let primary = proposal.verify()?;
		if !self.is_validator(&primary) {
			Err(EngineError::NotAuthorized(primary))?
		}

		let vote_hash = proposal.view_vote.vote_hash();
		let ref signatures_field = header.seal()[2];
		let mut signature_count = 0;
		let mut origins = HashSet::new();
		for rlp in UntrustedRlp::new(signatures_field).iter() {
			let vote: AbabMessage = AbabMessage::new_vote(&proposal, rlp.as_val()?);
			let address = match self.votes.get(&vote) {
				Some(a) => a,
				None => vote.verify_hash(&vote_hash)?,
			};
			if !self.validators.contains(&address) {
				Err(EngineError::NotAuthorized(address.to_owned()))?
			}

			if origins.insert(address) {
				signature_count += 1;
			} else {
				warn!(target: "engine", "verify_block_unordered: Duplicate signature from {} on the seal.", address);
				Err(BlockError::InvalidSeal)?;
			}
		}

		// Check if its a proposal if there is not enough votes.
		if !self.is_above_threshold(signature_count) {
			let signatures_len = signatures_field.len();
			// Proposal has to have an empty signature list.
			if signatures_len != 1 {
				Err(EngineError::BadSealFieldSize(OutOfBounds {
					min: Some(1),
					max: Some(1),
					found: signatures_len
				}))?;
			}
			let correct_primary = self.view_primary(proposal.view_vote.height, proposal.view_vote.view);
			if correct_primary != primary {
				Err(EngineError::NotProposer(Mismatch { expected: correct_primary, found: primary }))?
			}
		}
		Ok(())
	}

	fn verify_block_family(&self, header: &Header, parent: &Header, _block: Option<&[u8]>) -> Result<(), Error> {
		if header.number() == 0 {
			Err(BlockError::RidiculousNumber(OutOfBounds { min: Some(1), max: None, found: header.number() }))?;
		}

		let gas_limit_divisor = self.gas_limit_bound_divisor;
		let min_gas = parent.gas_limit().clone() - parent.gas_limit().clone() / gas_limit_divisor;
		let max_gas = parent.gas_limit().clone() + parent.gas_limit().clone() / gas_limit_divisor;
		if header.gas_limit() <= &min_gas || header.gas_limit() >= &max_gas {
			Err(BlockError::InvalidGasLimit(OutOfBounds { min: Some(min_gas), max: Some(max_gas), found: header.gas_limit().clone() }))?;
		}

		Ok(())
	}

	fn set_signer(&self, ap: Arc<AccountProvider>, address: Address, password: String) {
		self.signer.set(ap, address, password);
	}

	fn stop(&self) {
		self.transition.stop()
	}

	fn is_proposal(&self, header: &Header) -> bool {
		let signatures_len = header.seal()[3].len();
		// Signatures have to be an empty list rlp.
		let proposal = AbabMessage::new_proposal(header).expect("block went through full verification; this Engine verifies new_proposal creation; qed");
		let message = proposal.message;
		if signatures_len != 1 {
			// New Commit received, skip to next height.
			self.to_next_height(message.height);
			if self.is_view_primary(self.height.load(AtomicOrdering::SeqCst), self.view.load(AtomicOrdering::SeqCst)) {
				self.update_sealing()
			}
			return false;
		}
		let primary = proposal.verify().expect("block went through full verification; this Engine tries verify; qed");
		debug!(target: "engine", "Received a new proposal {:?} from {}.", message, primary);
		if self.is_view(&proposal) {
			*self.proposal.write() = Some(message.block_hash.clone());
			self.transition.send_message(());
		}
		self.votes.vote(proposal, &primary);
		true
	}

	/// Called on timeout.
	fn step(&self) {
		self.set_timeout();
		self.broadcast_view_change();
	}

	fn register_client(&self, client: Weak<Client>) {
		*self.client.write() = Some(client.clone());
		self.validators.register_contract(client);
	}
}
