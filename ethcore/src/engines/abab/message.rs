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

//! Tendermint message handling.

use util::*;
use super::{Height, View};
use error::Error;
use header::Header;
use rlp::{UntrustedRlp, RlpStream, Stream, Encodable, Decodable, Decoder, DecoderError, View as RlpView, encode};
use ethkey::{recover, public_to_address};
use super::super::vote_collector::Message;

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum Vote {
	Vote(H256),
	ViewChange,
	Proposal(H256),
}

impl Default for Vote {
	fn default() -> Self {
		Vote::ViewChange
	}
}

impl Vote {
	fn number(&self) -> usize {
		match *self {
			Vote::Proposal(_) => 0,
			Vote::ViewChange => 1,
			Vote::Vote(_) => 2,
		}
	}
}

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct ViewVote {
	pub vote: Vote,
	height: Height,
	view: View,
}

impl ViewVote {
	pub fn new_proposal(height: Height, view: View, block_hash: H256) -> Self {
		ViewVote {
			vote: Vote::Proposal(block_hash),
			height: height,
			view: view,
		}
	}

	fn new_vote(height: Height, view: View, block_hash: H256) -> Self {
		ViewVote {
			vote: Vote::Vote(block_hash),
			height: height,
			view: view,
		}
	}

	pub fn new_view_change(height: Height, view: View) -> Self {
		ViewVote {
			vote: Vote::ViewChange,
			height: height,
			view: view,
		}
	}

	fn block_hash(&self) -> Option<H256> {
		match self.vote {
			Vote::Vote(bh) => Some(bh),
			Vote::Proposal(bh) => Some(bh),
			_ => None,
		}
	}

	pub fn vote_hash(&self) -> H256 {
		encode(&ViewVote::new_vote(self.height, self.view, self.block_hash().unwrap_or_else(Default::default))).sha3()
	}

	pub fn view_change_hash(&self) -> H256 {
		encode(&ViewVote::new_view_change(self.height, self.view)).sha3()
	}

	pub fn is_height(&self, h: Height) -> bool {
		self.height == h
	}

	pub fn is_view(&self, h: Height, v: View) -> bool {
		self.is_height(h) && self.view == v
	}

	pub fn is_first_view(&self) -> bool {
		self.view == 0
	}

	pub fn to_view_change(&self) -> Self {
		ViewVote::new_view_change(self.height, self.view)
	}
}

/// Message transmitted between consensus participants.
#[derive(Debug, PartialEq, Eq, Clone, Hash, Default)]
pub struct AbabMessage {
	pub view_vote: ViewVote,
	signature: H520,
}

fn view(header: &Header) -> Result<View, ::rlp::DecoderError> {
	let message_type_rlp = header.seal().get(0).expect("seal passed basic verification; seal has 4 fields; qed");
	UntrustedRlp::new(message_type_rlp.as_slice()).as_val()
}

impl Message for AbabMessage {
	type Round = ViewVote;

	fn signature(&self) -> H520 { self.signature }

	fn block_hash(&self) -> Option<H256> { self.view_vote.block_hash() }

	fn round(&self) -> &ViewVote { &self.view_vote }

	fn is_broadcastable(&self) -> bool { true }
}

impl AbabMessage {
	pub fn new(signature: H520, view_vote: ViewVote) -> Self {
		AbabMessage { view_vote: view_vote, signature: signature }
	}

	pub fn new_vote(signature: H520, height: Height, view: View, block_hash: H256) -> Self {
		AbabMessage {
			signature: signature,
			view_vote: ViewVote::new_vote(height, view, block_hash),
		}
	}

	pub fn new_view_change(signature: H520, height: Height, message_type: View) -> Self {
		AbabMessage {
			signature: signature,
			view_vote: ViewVote::new_view_change(height, message_type),
		}
	}

	pub fn new_proposal(header: &Header) -> Result<Self, ::rlp::DecoderError> {
		Ok(AbabMessage {
			view_vote: ViewVote::new_proposal(header.number() as Height, view(header)?, header.bare_hash()),
			signature: UntrustedRlp::new(header.seal().get(1).expect("seal passed basic verification; seal has 4 fields; qed").as_slice()).as_val()?,
		})
	}

	pub fn height(&self) -> Height {
		self.view_vote.height
	}

	pub fn view(&self) -> View {
		self.view_vote.view
	}

	pub fn verify_hash(&self, h: &H256) -> Result<Address, Error> {
		Ok(public_to_address(&recover(&self.signature.into(), h)?))
	}

	pub fn verify(&self) -> Result<Address, Error> {
		Ok(self.verify_hash(&encode(&self.view_vote).sha3())?)
	}

	pub fn verify_raw(&self, rlp: &UntrustedRlp) -> Result<Address, Error> {
		Ok(self.verify_hash(&rlp.at(1)?.as_raw().sha3())?)
	}

	pub fn info(&self) -> BTreeMap<String, String> {
		map![
			"signature".into() => self.signature.to_string(),
			"height".into() => self.view_vote.height.to_string(),
			"view".into() => self.view_vote.view.to_string(),
			"block_hash".into() => self.block_hash().as_ref().map(ToString::to_string).unwrap_or("".into())
		]
	}
}

impl Default for ViewVote {
	fn default() -> Self {
		ViewVote::new_view_change(0, 0)
	}
}

impl PartialOrd for ViewVote {
	fn partial_cmp(&self, m: &ViewVote) -> Option<Ordering> {
		Some(self.cmp(m))
	}
}

impl Ord for ViewVote {
	fn cmp(&self, m: &ViewVote) -> Ordering {
		if self.height != m.height {
			self.height.cmp(&m.height)
		} else if self.view != m.view {
			self.view.cmp(&m.view)
		} else {
			self.vote.number().cmp(&m.vote.number())
		}
	}
}

/// Vote (signature, (height, view, block_hash))
/// ViewChange (signature, (height, view))
impl Decodable for AbabMessage {
	fn decode<D>(decoder: &D) -> Result<Self, DecoderError> where D: Decoder {
		let rlp = decoder.as_rlp();
		let m = rlp.at(1)?;
		let height = m.val_at(0)?;
		let view = m.val_at(1)?;
		Ok(AbabMessage {
			signature: rlp.val_at(0)?,
			view_vote: match m.iter().count() {
				2 => ViewVote::new_view_change(height, view),
				_ => ViewVote::new_vote(height, view, m.val_at(2)?),
			},
		})
  }
}

impl Encodable for AbabMessage {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(2)
			.append(&self.signature)
			.append(&self.view_vote);
	}
}

impl Encodable for ViewVote {
	fn rlp_append(&self, s: &mut RlpStream) {
		match self.vote {
			Vote::Proposal(ref bh) => s.begin_list(4).append(&self.height).append(&self.view).append(bh).append(&true),
			Vote::Vote(ref bh) => s.begin_list(3).append(&self.height).append(&self.view).append(bh),
			Vote::ViewChange => s.begin_list(2).append(&self.height).append(&self.view),
		};
	}
}

pub fn message_rlp(signature: &H520, vote_info: &Bytes) -> Bytes {
	let mut s = RlpStream::new_list(2);
	s.append(signature).append_raw(vote_info, 1);
	s.out()
}

#[cfg(test)]
mod tests {
	use util::*;
	use rlp::*;
	use ethkey::Secret;
	use account_provider::AccountProvider;
	use header::Header;
	use super::*;

	#[test]
	fn encode_decode() {
		let vote = AbabMessage::new_vote(Default::default(), 10, 123, "1".sha3());
		let raw_rlp = ::rlp::encode(&vote).to_vec();
		let rlp = Rlp::new(&raw_rlp);
		assert_eq!(vote, rlp.as_val());

		let view_change = AbabMessage::new_view_change(Default::default(), 1, 0);
		let raw_rlp = ::rlp::encode(&view_change).to_vec();
		let rlp = Rlp::new(&raw_rlp);
		assert_eq!(view_change, rlp.as_val());
	}

	#[test]
	fn generate_and_verify() {
		let tap = Arc::new(AccountProvider::transient_provider());
		let addr = tap.insert_account(Secret::from_slice(&"0".sha3()).unwrap(), "0").unwrap();
		tap.unlock_account_permanently(addr, "0".into()).unwrap();

		let view_vote = ::rlp::encode(&ViewVote::new_vote(123, 2, "0".sha3())).to_vec();

		let raw_rlp = message_rlp(&tap.sign(addr, None, view_vote.sha3()).unwrap().into(), &view_vote);

		let rlp = UntrustedRlp::new(&raw_rlp);
		let message: AbabMessage = rlp.as_val().unwrap();
		match message.verify() { Ok(a) if a == addr => {}, _ => panic!(), };
	}

	#[test]
	fn proposal_message() {
		let mut header = Header::default();
		let seal = vec![
			::rlp::encode(&2u8).to_vec(),
			::rlp::encode(&H520::default()).to_vec(),
			Vec::new(),
			Vec::new()
		];
		header.set_seal(seal);
		let message = AbabMessage::new_proposal(&header).unwrap();
		assert_eq!(
			message,
			AbabMessage::new(Default::default(), ViewVote::new_proposal(0, 2, header.bare_hash()))
		);
	}

	#[test]
	fn message_info_from_header() {
		let header = Header::default();
		let pro = AbabMessage::new(Default::default(), ViewVote::new_proposal(0, 0, header.bare_hash()));

		let vc = ::rlp::encode(&ViewVote::new_view_change(0, 0));
		assert_eq!(pro.view_vote.view_change_hash(), vc.sha3());
		let vote = ::rlp::encode(&ViewVote::new_vote(0, 0, header.bare_hash()));
		assert_eq!(pro.view_vote.vote_hash(), vote.sha3());
	}
}
