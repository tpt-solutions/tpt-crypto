//! Fuzz target for Ed25519 point decompression.
//!
//! Arbitrary 32-byte candidate encodings are attempted; both the canonical and
//! rejected (non-curve / non-canonical) paths are exercised in constant time.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tpt_crypto_curve::edwards25519::EdwardsPoint;

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let bytes: [u8; 32] = data[..32].try_into().unwrap();
    let opt = EdwardsPoint::decompress(&bytes);
    // Materialise the result so the decompression work is not elided.
    let usable = opt.is_some().into_bool();
    let _ = core::hint::black_box(usable);
});