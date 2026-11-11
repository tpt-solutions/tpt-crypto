//! Fuzz target for `frodo::shake::decapsulate` at FrodoKEM-640 (SHAKE variant).
//!
//! The secret key is fixed (derived from a constant randomness); every fuzz byte is a
//! candidate ciphertext. Exercises the full implicit-rejection path. Must never panic,
//! and must return a 16-byte value for any well-sized ciphertext.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use tpt_crypto_kem::frodo::shake::{decapsulate, keygen_derand};
use tpt_crypto_kem::frodo::{Frodo640, FrodoParams, SecretKey};

fn fixed_sk() -> &'static SecretKey {
    static SK: OnceLock<SecretKey> = OnceLock::new();
    SK.get_or_init(|| {
        let r = vec![0x3Cu8; Frodo640::KEYGEN_RANDOM_LEN];
        let (_pk, sk) = keygen_derand::<Frodo640>(&r).expect("fixed randomness has the right length");
        sk
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() < Frodo640::CIPHERTEXT_LEN {
        return;
    }
    let out = decapsulate::<Frodo640>(fixed_sk(), &data[..Frodo640::CIPHERTEXT_LEN])
        .expect("well-sized inputs");
    assert_eq!(out.len(), 16);
});
