//! Fuzz target for `mceliece::decapsulate` (Classic McEliece mceliece348864).
//!
//! The secret key is fixed (generated once from a deterministic generator); every fuzz
//! byte is a candidate ciphertext. Exercises the full decoding and implicit-rejection
//! path. Must never panic, and must return a 32-byte value for any well-sized ciphertext.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use tpt_crypto_core::{CryptoRng, Error};
use tpt_crypto_kem::mceliece::{decapsulate, keypair, CIPHERTEXT_LEN, SECRET_KEY_LEN};

/// xorshift64 generator: deterministic, for the fixed key only.
struct Xorshift(u64);

impl CryptoRng for Xorshift {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        for b in dest.iter_mut() {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            *b = self.0 as u8;
        }
        Ok(())
    }
}

fn fixed_sk() -> &'static Vec<u8> {
    static SK: OnceLock<Vec<u8>> = OnceLock::new();
    SK.get_or_init(|| {
        let (_pk, sk) = keypair(&mut Xorshift(0x9E37_79B9_7F4A_7C15)).expect("keypair");
        assert_eq!(sk.len(), SECRET_KEY_LEN);
        sk
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() < CIPHERTEXT_LEN {
        return;
    }
    let out = decapsulate(fixed_sk(), &data[..CIPHERTEXT_LEN]).expect("well-sized inputs");
    assert_eq!(out.len(), 32);
});
