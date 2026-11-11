//! Fuzz target for `frodo::shake::decapsulate` (FrodoKEM-640-SHAKE).
//!
//! The secret key is fixed (derived from a constant randomness); every fuzz byte is a
//! candidate ciphertext. Exercises the full implicit-rejection path. Must never panic,
//! and must return a 16-byte value for any well-sized ciphertext.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use tpt_crypto_kem::frodo::shake::{decapsulate, keygen_derand};
use tpt_crypto_kem::frodo::{SecretKey, CIPHERTEXT_LEN, KEYGEN_RANDOM_LEN};

fn fixed_sk() -> &'static SecretKey {
    static SK: OnceLock<SecretKey> = OnceLock::new();
    SK.get_or_init(|| {
        let r = [0x3Cu8; KEYGEN_RANDOM_LEN];
        let (_pk, sk) = keygen_derand(&r);
        sk
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() < CIPHERTEXT_LEN {
        return;
    }
    let out = decapsulate(fixed_sk(), &data[..CIPHERTEXT_LEN]).expect("well-sized inputs");
    assert_eq!(out.len(), 16);
});
