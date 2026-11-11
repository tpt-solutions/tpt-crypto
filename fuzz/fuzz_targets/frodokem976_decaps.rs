//! Fuzz target for `frodo::shake::decapsulate` at FrodoKEM-976 (SHAKE variant).
//!
//! The secret key is fixed (derived once from a constant randomness); every fuzz byte is a
//! candidate ciphertext. Must never panic, and must return a shared secret of the set's size.

#![no_main]

use libfuzzer_sys::fuzz_target;
use std::sync::OnceLock;
use tpt_crypto_kem::frodo::shake::{decapsulate, keygen_derand};
use tpt_crypto_kem::frodo::{Frodo976, FrodoParams, SecretKey};

fn fixed_sk() -> &'static SecretKey {
    static SK: OnceLock<SecretKey> = OnceLock::new();
    SK.get_or_init(|| {
        let r = vec![0x3Cu8; Frodo976::KEYGEN_RANDOM_LEN];
        let (_pk, sk) = keygen_derand::<Frodo976>(&r).expect("fixed randomness has the right length");
        sk
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() < Frodo976::CIPHERTEXT_LEN {
        return;
    }
    let out = decapsulate::<Frodo976>(fixed_sk(), &data[..Frodo976::CIPHERTEXT_LEN]).expect("well-sized inputs");
    assert_eq!(out.len(), Frodo976::CRYPTO_BYTES);
});
