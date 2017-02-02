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
use super::{Height, View, BlockHash};
use error::Error;
use header::Header;
use rlp::{Rlp, UntrustedRlp, RlpStream, Stream, Encodable, Decodable, Decoder, DecoderError, View as RlpView, encode};
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

#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub struct ViewVote {
	vote: Vote,
	height: Height,
	view: View,
}

impl ViewVote {
	fn new_proposal(height: Height, view: View, block_hash: H256) -> Self {
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

	fn new_view_change(height: Height, view: View) -> Self {
		ViewVote {
			vote: Vote::ViewChange,
			height: height,
			view: view,
		}
	}

	fn vote_hash(&self) -> H256 {
		let rlp = encode(&ViewVote::new_vote(self.height, self.view, self.block_hash));
		rlp.sha3()
	}
}

/// Message transmitted between consensus participants.
#[derive(Debug, PartialEq, Eq, Clone, Hash, Default)]
pub struct AbabMessage {
	view_vote: ViewVote,
	signature: H520,
}

fn view(header: &Header) -> Result<View, ::rlp::DecoderError> {
	let message_type_rlp = header.seal().get(0).expect("seal passed basic verification; seal has 4 fields; qed");
	UntrustedRlp::new(message_type_rlp.as_slice()).as_val()
}

impl Message for AbabMessage {
	type Round = ViewVote;

	fn signature(&self) -> H520 { self.signature }

	fn block_hash(&self) -> Option<H256> {
		match self.view_vote.vote {
			Vote::Vote(bh) => Some(bh),
			_ => None,
		}
	}

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
			view_vote: ViewVote::new_view_change(height, view),
		}
	}

	pub fn new_proposal(header: &Header) -> Result<Self, ::rlp::DecoderError> {
		Ok(AbabMessage {
			view_vote: ViewVote::new_proposal(header.number() as Height, view(header)?, header.bare_hash()),
			signature: UntrustedRlp::new(header.seal().get(1).expect("seal passed basic verification; seal has 4 fields; qed").as_slice()).as_val()?,
		})
	}

	pub fn verify(&self) -> Result<Address, Error> {
		let vote_rlp = encode(&self.view_vote);
		let public_key = recover(&self.signature.into(), &vote_rlp.as_raw().sha3())?;
		Ok(public_to_address(&public_key))
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

			self.step.number().cmp(&m.step.number())
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
			view_vote: match m.len() {
				2 => ViewVote::new_view_change(height, view),
				_ => ViewVote::new(height, view, m.val_at(2)?),
			},
		})
  }
}

impl Encodable for AbabMessage {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(2)
			.append(&self.signature)
			.append_raw(&self.view_vote);
	}
}

impl Encodable for ViewVote {
	fn rlp_append(&self, s: &mut RlpStream) {
		match self.vote {
			Vote::Proposal(bh) => s.begin_list(4).append(&self.height).append(&self.view).append(bh).append(&true),
			Vote::Vote(bh) => s.begin_list(3).append(&self.height).append(&self.view).append(bh),
			Vote::ViewChange => s.begin_list(2).append(&self.height).append(&self.view),
		};
	}
}

pub fn message_rlp(signature: &H520, vote_info: &Bytes) -> Bytes {
	let mut s = RlpStream::new_list(2);
	s.append(signature).append_raw(vote_info, 1);
	s.out()
}
