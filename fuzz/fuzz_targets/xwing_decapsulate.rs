//! Fuzz target for `xwing::decapsulate` (X25519 + ML-KEM-768 hybrid).
//!
//! The secret key is fixed; every fuzz byte string is a candidate ciphertext.
//! Exercises the length check, the ML-KEM implicit-rejection path and the
//! X25519 low-order check. Must never panic.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tpt_crypto_kem::xwing::{decapsulate, keygen_seed, SecretKey, CIPHERTEXT_LEN};

fuzz_target!(|data: &[u8]| {
    let (_pk, sk): (_, SecretKey) = keygen_seed(&[0x42; 32]);
    let len = core::cmp::min(data.len(), CIPHERTEXT_LEN + 8);
    let _ = decapsulate(&sk, &data[..len]);
});
