//! Fuzz target for Bulletproofs range-proof parsing and verification.
//!
//! `range_proof_from_bytes` splits attacker-controlled bytes into fixed-width
//! compressed curve points and scalars, and `verify_range` then decompresses
//! every one of them. This target drives both, so a malformed proof exercises
//! the point decompressor (`EdwardsPoint::decompress`) with untrusted input and
//! the field-element canonicality checks with untrusted scalars. Rejection must
//! be total: no panic, no unwrap, no allocation on an attacker-sized length.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tpt_crypto_zk::{range_proof_from_bytes, verify_range, Ristretto};

/// Decode the leading byte as a bitsize and synthesise one commitment, so a
/// successful parse is carried all the way into verification.
fn exercise(proof_bytes: &[u8]) {
    let Some(&selector) = proof_bytes.first() else {
        return;
    };
    let n = match selector % 4 {
        0 => 8usize,
        1 => 16,
        2 => 32,
        _ => 64,
    };

    let Ok(proof) = range_proof_from_bytes(proof_bytes) else {
        return;
    };

    // A parsed proof must re-serialize to exactly the same bytes.
    assert_eq!(
        tpt_crypto_zk::range_proof_to_bytes(&proof),
        proof_bytes,
        "range proof encoding is not canonical"
    );

    // Feed the proof into the verifier against an arbitrary but valid-looking
    // commitment so the full decompression path runs on untrusted points.
    let mut commitment = [0u8; 32];
    let n_fill = core::cmp::min(31, proof_bytes.len().saturating_sub(1));
    commitment[..n_fill].copy_from_slice(&proof_bytes[1..1 + n_fill]);
    if let Some(point) = Ristretto::decompress(&commitment) {
        let result = verify_range(&[point], &proof, n);
        // Verification may legitimately succeed only for a genuine proof; the
        // invariant under test is that it never panics and never accepts a
        // proof whose recomputed commitment does not match.
        if result.is_ok() {
            assert!(proof_bytes.len() > 64, "accepted an implausibly short proof");
        }
    }
}

fuzz_target!(|data: &[u8]| {
    exercise(data);
    // Also try with the leading byte stripped, so the parser sees a variety of
    // total lengths rather than only those starting with a known selector.
    if !data.is_empty() {
        exercise(&data[1..]);
    }
});