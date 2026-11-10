//! Fuzz target for `xwing::encapsulate_with` on an attacker-supplied public key.
//!
//! The first 1216 bytes of the input form the public key (ML-KEM-768 `ek` then
//! X25519 `pk_X`); the next 64 are the ephemeral scalar and ML-KEM message.
//! Malformed keys must return an error and never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tpt_crypto_kem::xwing::{encapsulate_with, PublicKey, PUBLIC_KEY_LEN};

fuzz_target!(|data: &[u8]| {
    if data.len() < PUBLIC_KEY_LEN + 64 {
        return;
    }
    let mut pk = [0u8; PUBLIC_KEY_LEN];
    pk.copy_from_slice(&data[..PUBLIC_KEY_LEN]);
    let mut eph = [0u8; 32];
    eph.copy_from_slice(&data[PUBLIC_KEY_LEN..PUBLIC_KEY_LEN + 32]);
    let mut m = [0u8; 32];
    m.copy_from_slice(&data[PUBLIC_KEY_LEN + 32..PUBLIC_KEY_LEN + 64]);

    // Must not panic on any key; the result itself is not checked here.
    let _ = encapsulate_with(&PublicKey(pk), &eph, &m);
});
