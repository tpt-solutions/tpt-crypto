//! Fuzz target for `hybrid::verify` (Ed25519 + ML-DSA-65).
//!
//! The verifying key is fixed; every fuzz input is a candidate signature over a
//! fixed message. Exercises the length check, the ML-DSA signature parser and
//! both verification paths. Must never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tpt_crypto_sig::hybrid::{keygen_from_seeds, verify, SIGNATURE_LEN};

fuzz_target!(|data: &[u8]| {
    let sk = keygen_from_seeds(&[0x42; 32], &[0x24; 32]);
    let len = core::cmp::min(data.len(), SIGNATURE_LEN + 8);
    let _ = verify(sk.verifying_key(), b"ctx", b"fuzz message", &data[..len]);
});
