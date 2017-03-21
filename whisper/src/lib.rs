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

//! Rust implementation of the Whisper P2P messaging protocol.

extern crate rlp;
extern crate ethcore_network as network;
extern crate ethcore_util as util;
extern crate time;
extern crate ethkey;
extern crate rand;

use std::collections::{HashSet, VecDeque};

use ethkey::{Public, Secret, Signature};
use time::{Duration, Timespec};
use util::U256;
use rlp::*;

// maximum tolerated message size. will be lifted in future versions.
const MAX_MESSAGE_SIZE: usize = 1 << 16;

/// An envelope is passed over the network. It contains an encrypted payload,
/// which should decrypt to a `Message`.
#[derive(Debug, Clone, PartialEq)]
pub struct Envelope {
	version: usize,
	expiry: Timespec,
	ttl: Duration,
	topic: u32,
	aes_data: Option<(Vec<u8>, Vec<u8>)>, // AES data: nonce and salt.
	message: Vec<u8>,
	pow_nonce: U256, // proof-of-work
}

impl Encodable for Envelope {
	fn rlp_append(&self, s: &mut RlpStream) {
		s.begin_list(8)
			.append(&self.version)
			.append(&(self.expiry.sec as u64))
			.append(&(self.ttl.num_seconds() as u64))
			.append(&self.topic);

		match self.aes_data {
			Some((ref nonce, ref salt)) => s.append_list(nonce).append_list(salt),
			None => s.begin_list(0).begin_list(0),
		};

		s.append_list(&self.message).append(&self.pow_nonce);
	}
}

impl Decodable for Envelope {
	fn decode<D>(decoder: &D) -> Result<Self, DecoderError> where D: Decoder {
		let rlp = decoder.as_rlp();

		Ok(Envelope {
			version: rlp.val_at(0)?,
			expiry: Timespec {
				sec: rlp.val_at::<u64>(1)? as i64,
				nsec: 0,
			},
			ttl: Duration::seconds(rlp.val_at::<u64>(2)? as i64),
			topic: rlp.val_at(3)?,
			aes_data: if rlp.at(4)?.is_empty() {
				if !rlp.at(5)?.is_empty() { return Err(DecoderError::Custom("only one of AES fields included.")) }
				None
			} else {
				Some((rlp.val_at(4)?, rlp.val_at(5)?))
			},
			message: rlp.val_at(6)?,
			pow_nonce: rlp.val_at(7)?,
		})
	}
}

/// Whisper message.
#[derive(Debug, Clone, PartialEq)]
pub struct Message {
	/// Message flags.
	pub flags: u8,
	/// Random padding data.
	pub padding: Vec<u8>,
	/// Message payload.
	pub payload: Vec<u8>,
	/// Maybe a signature of sha3(payload).
	pub signature: Option<Signature>,
}

struct Peer;

/// The whisper protocol handler.
pub struct Whisper {
	envelope_pool: VecDeque<Envelope>,
	peers: HashSet<Peer>,
}
