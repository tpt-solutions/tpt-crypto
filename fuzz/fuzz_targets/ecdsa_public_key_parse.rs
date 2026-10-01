//! Fuzz target for ECDSA public-key parsing (SEC1, compressed and uncompressed).
//!
//! `VerifyingKey::from_sec1` decodes an attacker-supplied encoding that may
//! carry a prefix byte, a wrong-length field, a non-canonical coordinate, or a
//! point that is not on the curve. Rejection must be total and non-panicking.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tpt_crypto_sig::ecdsa::{VerifyingKey, P256, P384};

fuzz_target!(|data: &[u8]| {
    if data.is_empty() {
        return;
    }
    if data[0] % 2 == 0 {
        if let Ok(vk) = VerifyingKey::<P256>::from_sec1(&data[1..]) {
            // An accepted key must re-encode to a parseable SEC1 encoding.
            let enc = vk.to_sec1_uncompressed();
            assert!(VerifyingKey::<P256>::from_sec1(&enc).is_ok());
            assert_eq!(enc.len(), 65);
        }
    } else if let Ok(vk) = VerifyingKey::<P384>::from_sec1(&data[1..]) {
        assert_eq!(vk.to_sec1_uncompressed().len(), 97);
    }
});