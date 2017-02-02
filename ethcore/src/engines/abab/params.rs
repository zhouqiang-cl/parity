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

//! Abab specific parameters.

use ethjson;
use util::{U256, Uint};
use time::Duration;
use super::super::transition::Timeouts;

/// `Abab` params.
#[derive(Debug)]
pub struct AbabParams {
	/// Gas limit divisor.
	pub gas_limit_bound_divisor: U256,
	/// List of validators.
	pub validators: ethjson::spec::ValidatorSet,
	/// Timeout durations for different steps.
	pub timeout: AbabTimeout,
	/// Block reward.
	pub block_reward: U256,
}

/// Base timeout of each step in ms.
#[derive(Debug, Clone)]
pub struct AbabTimeout(Duration);

impl Default for AbabTimeout {
	fn default() -> Self {
		AbabTimeout(Duration::milliseconds(1000))
	}
}

impl Timeouts<()> for AbabTimeout {
	fn initial(&self) -> Duration {
		self.0
	}

	fn timeout(&self, _: &()) -> Duration {
		self.0
	}
}

fn to_duration(ms: ethjson::uint::Uint) -> Duration {
	let ms: usize = ms.into();
	Duration::milliseconds(ms as i64)
}

impl From<ethjson::spec::AbabParams> for AbabParams {
	fn from(p: ethjson::spec::AbabParams) -> Self {
		AbabParams {
			gas_limit_bound_divisor: p.gas_limit_bound_divisor.into(),
			validators: p.validators,
			timeout: p.timeout.map_or_else(
				Default::default,
				|ms| AbabTimeout(Duration::milliseconds(u64::from(ms) as i64))
			),
			block_reward: p.block_reward.map_or_else(U256::zero, Into::into),
		}
	}
}
