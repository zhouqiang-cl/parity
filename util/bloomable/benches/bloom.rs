#![feature(test)]

extern crate test;
extern crate ethcore_bigint as bigint;
extern crate rustc_hex;
extern crate tiny_keccak;
extern crate bloomable;

use test::Bencher;
use rustc_hex::FromHex;
use tiny_keccak::keccak256;
use bigint::hash::{H2048, H256};
use bloomable::Bloomable;

fn test_bloom() -> H2048 {
	"00000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002020000000000000000000000000000000000000000000008000000001000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000".into()
}

fn test_topic() -> Vec<u8> {
	"02c69be41d0b7e40352fc85be1cd65eb03d40ef8427a0ca4596b1ead9a00e9fc".from_hex().unwrap()
}

fn test_address() -> Vec<u8> {
	"ef2d6d194084c2de36e0dabfce45d046b37d1106".from_hex().unwrap()
}

fn test_dummy() -> Vec<u8> {
	b"123456".to_vec()
}

fn test_dummy2() -> Vec<u8> {
	b"654321".to_vec()
}

#[bench]
fn accrue_hash(b: &mut Bencher) {
	let mut bloom = H2048::default();
	let topic: H256 = keccak256(&test_topic()).into();
	let address: H256 = keccak256(&test_address()).into();
	b.iter(|| {
		bloom.shift_bloomed(&topic);
		bloom.shift_bloomed(&address);
	});
}

#[bench]
fn contains_hash(b: &mut Bencher) {
	let bloom = test_bloom();
	let topic: H256 = keccak256(&test_topic()).into();
	let address: H256 = keccak256(&test_address()).into();
	b.iter(|| {
		assert!(bloom.contains_bloomed(&topic));
		assert!(bloom.contains_bloomed(&address));
	});
}

#[bench]
fn does_not_contain_hash(b: &mut Bencher) {
	let bloom = test_bloom();
	let dummy: H256 = keccak256(&test_dummy()).into();
	let dummy2: H256 = keccak256(&test_dummy2()).into();
	b.iter(|| {
		assert!(!bloom.contains_bloomed(&dummy));
		assert!(!bloom.contains_bloomed(&dummy2));
	});
}

#[bench]
fn does_not_contain_random_hash(b: &mut Bencher) {
	let bloom = test_bloom();
	let dummy: Vec<H256> = (0..255u8).into_iter().map(|i| keccak256(&[i]).into()).collect();
	b.iter(|| {
		for d in &dummy {
			assert!(!bloom.contains_bloomed(d));
		}
	});
}
