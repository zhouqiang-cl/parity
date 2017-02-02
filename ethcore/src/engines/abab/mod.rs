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
				lock_change: RwLock::new(None),
				last_lock: AtomicUsize::new(0),
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
		let vote_rlp = ::rlp::encode(&view_vote);
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
		for m in self.votes.get_up_to(&ViewVote::new(self.height.load(AtomicOrdering::SeqCst), self.view.load(AtomicOrdering::SeqCst))).into_iter() {
			self.broadcast_message(m);
		}
	}

	fn to_next_height(&self, height: Height) {
		let new_height = height + 1;
		debug!(target: "engine", "Received a Commit, transitioning to height {}.", new_height);
		self.last_lock.store(0, AtomicOrdering::SeqCst);
		self.height.store(new_height, AtomicOrdering::SeqCst);
		self.view.store(0, AtomicOrdering::SeqCst);
		*self.lock_change.write() = None;
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

	/// Check if address is a primary for given view.
	fn is_view_primary(&self, height: Height, view: View, address: &Address) -> Result<(), EngineError> {
		let primary = self.view_primary(height, view);
		if primary == *address {
			Ok(())
		} else {
			Err(EngineError::NotProposer(Mismatch { expected: primary, found: address.clone() }))
		}
	}

	/// Check if current signer is the current primary.
	fn is_signer_primary(&self) -> bool {
		let primary = self.view_primary(self.height.load(AtomicOrdering::SeqCst), self.view.load(AtomicOrdering::SeqCst));
		self.signer.is_address(&primary)
	}

	/// Check if current signer is the next primary.
	fn is_signer_next_primary(&self) -> bool {
		let primary = self.view_primary(self.height.load(AtomicOrdering::SeqCst), self.view.load(AtomicOrdering::SeqCst) + 1);
		self.signer.is_address(&primary)
	}

	fn is_height(&self, message: &AbabMessage) -> bool {
		message.vote_step.is_height(self.height.load(AtomicOrdering::SeqCst)) 
	}

	fn is_view(&self, message: &AbabMessage) -> bool {
		message.vote_step.is_view(self.height.load(AtomicOrdering::SeqCst), self.view.load(AtomicOrdering::SeqCst)) 
	}

	fn increment_view(&self, n: View) {
		trace!(target: "engine", "increment_view: New view.");
		self.view.fetch_add(n, AtomicOrdering::SeqCst);
	}

	fn has_enough_votes(&self, message: &AbabMessage) -> bool {
		let aligned_count = self.votes.count_aligned_votes(&message);
		self.is_above_threshold(aligned_count)
	}

	fn is_new_view(&self) -> bool {
		self.vote.count_round_votes(&ViewVote::new_view_change(self.height.load(AtomicOrdering::SeqCst), self.view.load(AtomicOrdering::SeqCst))) > self.validators.count() * 1/3
	}

	fn set_timeout(&self) {
		if let Err(io_err) = self.transition.send_message(()) {
			warn!(target: "engine", "Could not set a new view timeout: {}", io_err)
		}
	}

	fn handle_valid_message(&self, message: &AbabMessage) {
		// Check if it can affect the step transition.
		if !self.is_height(message) { return; }

		match message.view_vote.vote {
			Vote::Vote(hash) if self.is_signer_primary() && self.has_enough_votes(message) => {
				// Commit the block using a complete signature set.
				let view = self.view.load(AtomicOrdering::SeqCst);
				let height = self.height.load(AtomicOrdering::SeqCst);
				if let Some(block_hash) = *self.proposal.read() {
					// Generate seal and remove old votes.
					let proposal_step = ViewVote::new_proposal(height, view, block_hash);
					let precommit_step = ViewVote::new(proposal_step.height, proposal_step.view);
					if let Some(seal) = self.votes.seal_signatures(proposal_step, precommit_step, &block_hash) {
						trace!(target: "engine", "Collected seal: {:?}", seal);
						let seal = vec![
							::rlp::encode(&view).to_vec(),
							::rlp::encode(&seal.proposal).to_vec(),
							::rlp::EMPTY_LIST_RLP.to_vec(),
							::rlp::encode(&seal.votes).to_vec()
						];
						self.submit_seal(block_hash, seal);
						self.to_next_height(height);
					} else {
						warn!(target: "engine", "Not enough votes found!");
					}
				}		
			},
			Vote::ViewChange if self.is_signer_next_primary() && self.is_new_view() => {},
			Vote::Proposal(hash) => {},
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
		map![
			"signature".into() => message.signature.to_string(),
			"height".into() => message.vote_step.height.to_string(),
			"view".into() => message.vote_step.view.to_string(),
			"block_hash".into() => message.block_hash.as_ref().map(ToString::to_string).unwrap_or("".into())
		]
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
		if !self.is_signer_primary() || self.proposal.read().is_some() || !self.is_new_view() {
			return Seal::None;
		}

		let height = header.number() as Height;
		let view = self.view.load(AtomicOrdering::SeqCst);
		let bh = header.bare_hash();
		let proposal = ViewVote::new_proposal(height, view, bh);
		if let Ok(signature) = self.signer.sign(encode(&proposal).sha3()).map(Into::into) {
			// Insert Propose vote.
			debug!(target: "engine", "Submitting proposal {} at height {} view {}.", bh, height, view);
			self.votes.vote(AbabMessage { signature: signature, message: proposal }, author);
			// Remember proposal for later seal submission.
			*self.proposal.write() = bh;
			let signatures = self.votes.seal_signatures(proposal, ViewVote::new_view_change(height, view), bh);
			Seal::Proposal(vec![
				::rlp::encode(&view).to_vec(),
				::rlp::encode(&signatures.proposal).to_vec(),
				::rlp::encode(&signatures.votes).to_vec(),
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
			let sender = public_to_address(&recover(&message.signature.into(), &rlp.at(1)?.as_raw().sha3())?);
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

		let vote_hash = proposal.vote_hash();
		let ref signatures_field = header.seal()[2];
		let mut signature_count = 0;
		let mut origins = HashSet::new();
		for rlp in UntrustedRlp::new(signatures_field).iter() {
			let precommit: AbabMessage = AbabMessage::new_commit(&proposal, rlp.as_val()?);
			let address = match self.votes.get(&precommit) {
				Some(a) => a,
				None => public_to_address(&recover(&precommit.signature.into(), &vote_hash)?),
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

		// Check if its a proposal if there is not enough precommits.
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
			self.is_view_primary(proposal.vote_step.height, proposal.vote_step.view, &primary)?;
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
			trace!(target: "engine", "Received a commit: {:?}.", message);
			self.to_next_height(message.height);
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
		self.validators.register_call_contract(client);
	}
}

#[cfg(test)]
mod tests {
	use util::*;
	use block::*;
	use error::{Error, BlockError};
	use header::Header;
	use env_info::EnvInfo;
	use ethkey::Secret;
	use client::chain_notify::ChainNotify;
	use miner::MinerService;
	use tests::helpers::*;
	use account_provider::AccountProvider;
	use spec::Spec;
	use engines::{Engine, EngineError, Seal};
	use super::*;
	use super::message::*;

	/// Accounts inserted with "0" and "1" are validators. First primary is "0".
	fn setup() -> (Spec, Arc<AccountProvider>) {
		let tap = Arc::new(AccountProvider::transient_provider());
		let spec = Spec::new_test_tendermint();
		(spec, tap)
	}

	fn propose_default(spec: &Spec, primary: Address) -> (ClosedBlock, Vec<Bytes>) {
		let mut db_result = get_temp_state_db();
		let db = spec.ensure_db_good(db_result.take(), &Default::default()).unwrap();
		let genesis_header = spec.genesis_header();
		let last_hashes = Arc::new(vec![genesis_header.hash()]);
		let b = OpenBlock::new(spec.engine.as_ref(), Default::default(), false, db.boxed_clone(), &genesis_header, last_hashes, primary, (3141562.into(), 31415620.into()), vec![]).unwrap();
		let b = b.close();
		if let Seal::Proposal(seal) = spec.engine.generate_seal(b.block()) {
			(b, seal)
		} else {
			panic!()
		}
	}

	fn vote<F>(engine: &Engine, signer: F, height: usize, view: usize, step: Step, block_hash: Option<H256>) -> Bytes where F: FnOnce(H256) -> Result<H520, ::account_provider::Error> {
		let mi = message_info_rlp(&ViewVote::new(height, view, step), block_hash);
		let m = message_full_rlp(&signer(mi.sha3()).unwrap().into(), &mi);
		engine.handle_message(&m).unwrap();
		m
	}

	fn proposal_seal(tap: &Arc<AccountProvider>, header: &Header, view: View) -> Vec<Bytes> {
		let author = header.author();
		let vote_info = message_info_rlp(&ViewVote::new(header.number() as Height, view, Step::Propose), Some(header.bare_hash()));
		let signature = tap.sign(*author, None, vote_info.sha3()).unwrap();
		vec![
			::rlp::encode(&view).to_vec(),
			::rlp::encode(&H520::from(signature)).to_vec(),
			::rlp::EMPTY_LIST_RLP.to_vec()
		]
	}

	fn insert_and_unlock(tap: &Arc<AccountProvider>, acc: &str) -> Address {
		let addr = tap.insert_account(Secret::from_slice(&acc.sha3()).unwrap(), acc).unwrap();
		tap.unlock_account_permanently(addr, acc.into()).unwrap();
		addr
	}

	fn insert_and_register(tap: &Arc<AccountProvider>, engine: &Engine, acc: &str) -> Address {
		let addr = insert_and_unlock(tap, acc);
		engine.set_signer(tap.clone(), addr.clone(), acc.into());
		addr
	}

	#[derive(Default)]
	struct TestNotify {
		messages: RwLock<Vec<Bytes>>,
	}

	impl ChainNotify for TestNotify {
		fn broadcast(&self, data: Vec<u8>) {
			self.messages.write().push(data);
		}
	}

	#[test]
	fn has_valid_metadata() {
		let engine = Spec::new_test_tendermint().engine;
		assert!(!engine.name().is_empty());
		assert!(engine.version().major >= 1);
	}

	#[test]
	fn can_return_schedule() {
		let engine = Spec::new_test_tendermint().engine;
		let schedule = engine.schedule(&EnvInfo {
			number: 10000000,
			author: 0.into(),
			timestamp: 0,
			difficulty: 0.into(),
			last_hashes: Arc::new(vec![]),
			gas_used: 0.into(),
			gas_limit: 0.into(),
		});

		assert!(schedule.stack_limit > 0);
	}

	#[test]
	fn verification_fails_on_short_seal() {
		let engine = Spec::new_test_tendermint().engine;
		let header = Header::default();

		let verify_result = engine.verify_block_basic(&header, None);

		match verify_result {
			Err(Error::Block(BlockError::InvalidSealArity(_))) => {},
			Err(_) => { panic!("should be block seal-arity mismatch error (got {:?})", verify_result); },
			_ => { panic!("Should be error, got Ok"); },
		}
	}

	#[test]
	fn allows_correct_primary() {
		let (spec, tap) = setup();
		let engine = spec.engine;

		let mut header = Header::default();
		let validator = insert_and_unlock(&tap, "0");
		header.set_author(validator);
		let seal = proposal_seal(&tap, &header, 0);
		header.set_seal(seal);
		// Good primary.
		assert!(engine.verify_block_unordered(&header.clone(), None).is_ok());

		let validator = insert_and_unlock(&tap, "1");
		header.set_author(validator);
		let seal = proposal_seal(&tap, &header, 0);
		header.set_seal(seal);
		// Bad primary.
		match engine.verify_block_unordered(&header, None) {
			Err(Error::Engine(EngineError::NotProposer(_))) => {},
			_ => panic!(),
		}

		let random = insert_and_unlock(&tap, "101");
		header.set_author(random);
		let seal = proposal_seal(&tap, &header, 0);
		header.set_seal(seal);
		// Not authority.
		match engine.verify_block_unordered(&header, None) {
			Err(Error::Engine(EngineError::NotAuthorized(_))) => {},
			_ => panic!(),
		};
		engine.stop();
	}

	#[test]
	fn seal_signatures_checking() {
		let (spec, tap) = setup();
		let engine = spec.engine;

		let mut header = Header::default();
		let primary = insert_and_unlock(&tap, "1");
		header.set_author(primary);
		let mut seal = proposal_seal(&tap, &header, 0);

		let vote_info = message_info_rlp(&ViewVote::new(0, 0, Step::Precommit), Some(header.bare_hash()));
		let signature1 = tap.sign(primary, None, vote_info.sha3()).unwrap();

		seal[2] = ::rlp::encode(&vec![H520::from(signature1.clone())]).to_vec();
		header.set_seal(seal.clone());

		// One good signature is not enough.
		match engine.verify_block_unordered(&header, None) {
			Err(Error::Engine(EngineError::BadSealFieldSize(_))) => {},
			_ => panic!(),
		}

		let voter = insert_and_unlock(&tap, "0");
		let signature0 = tap.sign(voter, None, vote_info.sha3()).unwrap();

		seal[2] = ::rlp::encode(&vec![H520::from(signature1.clone()), H520::from(signature0.clone())]).to_vec();
		header.set_seal(seal.clone());

		assert!(engine.verify_block_unordered(&header, None).is_ok());

		let bad_voter = insert_and_unlock(&tap, "101");
		let bad_signature = tap.sign(bad_voter, None, vote_info.sha3()).unwrap();

		seal[2] = ::rlp::encode(&vec![H520::from(signature1), H520::from(bad_signature)]).to_vec();
		header.set_seal(seal);

		// One good and one bad signature.
		match engine.verify_block_unordered(&header, None) {
			Err(Error::Engine(EngineError::NotAuthorized(_))) => {},
			_ => panic!(),
		};
		engine.stop();
	}

	#[test]
	fn can_generate_seal() {
		let (spec, tap) = setup();

		let primary = insert_and_register(&tap, spec.engine.as_ref(), "1");

		let (b, seal) = propose_default(&spec, primary);
		assert!(b.lock().try_seal(spec.engine.as_ref(), seal).is_ok());
		spec.engine.stop();
	}

	#[test]
	fn can_recognize_proposal() {
		let (spec, tap) = setup();

		let primary = insert_and_register(&tap, spec.engine.as_ref(), "1");

		let (b, seal) = propose_default(&spec, primary);
		let sealed = b.lock().seal(spec.engine.as_ref(), seal).unwrap();
		assert!(spec.engine.is_proposal(sealed.header()));
		spec.engine.stop();
	}

	#[test]
	fn relays_messages() {
		let (spec, tap) = setup();
		let engine = spec.engine.clone();

		let v0 = insert_and_register(&tap, engine.as_ref(), "0");
		let v1 = insert_and_register(&tap, engine.as_ref(), "1");

		let h = 1;
		let r = 0;

		// Propose
		let (b, _) = propose_default(&spec, v1.clone());
		let proposal = Some(b.header().bare_hash());

		let client = generate_dummy_client(0);
		let notify = Arc::new(TestNotify::default());
		client.add_notify(notify.clone());
		engine.register_client(Arc::downgrade(&client));

		let prevote_current = vote(engine.as_ref(), |mh| tap.sign(v0, None, mh).map(H520::from), h, r, Step::Prevote, proposal);

		let precommit_current = vote(engine.as_ref(), |mh| tap.sign(v0, None, mh).map(H520::from), h, r, Step::Precommit, proposal);

		let prevote_future = vote(engine.as_ref(), |mh| tap.sign(v0, None, mh).map(H520::from), h + 1, r, Step::Prevote, proposal);

		// Relays all valid present and future messages.
		assert!(notify.messages.read().contains(&prevote_current));
		assert!(notify.messages.read().contains(&precommit_current));
		assert!(notify.messages.read().contains(&prevote_future));
		engine.stop();
	}

	#[test]
	fn seal_submission() {
		use ethkey::{Generator, Random};
		use types::transaction::{Transaction, Action};
		use client::BlockChainClient;

		let tap = Arc::new(AccountProvider::transient_provider());
		// Accounts for signing votes.
		let v0 = insert_and_unlock(&tap, "0");
		let v1 = insert_and_unlock(&tap, "1");
		let client = generate_dummy_client_with_spec_and_accounts(Spec::new_test_tendermint, Some(tap.clone()));
		let engine = client.engine();

		client.miner().set_engine_signer(v1.clone(), "1".into()).unwrap();

		let notify = Arc::new(TestNotify::default());
		client.add_notify(notify.clone());
		engine.register_client(Arc::downgrade(&client));

		let keypair = Random.generate().unwrap();
		let transaction = Transaction {
			action: Action::Create,
			value: U256::zero(),
			data: "3331600055".from_hex().unwrap(),
			gas: U256::from(100_000),
			gas_price: U256::zero(),
			nonce: U256::zero(),
		}.sign(keypair.secret(), None);
		client.miner().import_own_transaction(client.as_ref(), transaction.into()).unwrap();

		// Propose
		let proposal = Some(client.miner().pending_block().unwrap().header.bare_hash());
		// Propose timeout
		engine.step();

		let h = 1;
		let r = 0;

		// Prevote.
		vote(engine, |mh| tap.sign(v1, None, mh).map(H520::from), h, r, Step::Prevote, proposal);
		vote(engine, |mh| tap.sign(v0, None, mh).map(H520::from), h, r, Step::Prevote, proposal);
		vote(engine, |mh| tap.sign(v1, None, mh).map(H520::from), h, r, Step::Precommit, proposal);

		assert_eq!(client.chain_info().best_block_number, 0);
		// Last precommit.
		vote(engine, |mh| tap.sign(v0, None, mh).map(H520::from), h, r, Step::Precommit, proposal);
		assert_eq!(client.chain_info().best_block_number, 1);

		engine.stop();
	}
}
