//! Fuzz target for `frodo::shake::decapsulate` at FrodoKEM-1344 (SHAKE variant).
//!
//! The secret key is fixed (derived once from a constant randomness); every fuzz byte is a
//! candidate ciphertext. Must never panic, and must return a shared secret of the set's size.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use tpt_crypto_kem::frodo::shake::{decapsulate, keygen_derand};
use tpt_crypto_kem::frodo::{Frodo1344, FrodoParams, SecretKey};

fn fixed_sk() -> &'static SecretKey {
    static SK: OnceLock<SecretKey> = OnceLock::new();
    SK.get_or_init(|| {
        let r = vec![0x3Cu8; Frodo1344::KEYGEN_RANDOM_LEN];
        let (_pk, sk) = keygen_derand::<Frodo1344>(&r).expect("fixed randomness has the right length");
        sk
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() < Frodo1344::CIPHERTEXT_LEN {
        return;
    }
    let out = decapsulate::<Frodo1344>(fixed_sk(), &data[..Frodo1344::CIPHERTEXT_LEN]).expect("well-sized inputs");
    assert_eq!(out.len(), Frodo1344::CRYPTO_BYTES);
});
