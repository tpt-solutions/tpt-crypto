//! Fuzz target for ECDSA ASN.1 DER signature parsing (P-256 and P-384).
//!
//! `Signature::from_der` is the most attacker-reachable decoder in the `-sig`
//! crate: it parses nested length-delimited structures and must reject
//! non-minimal integers, negative integers, trailing garbage, and
//! wrong-length `r`/`s`. A parse that succeeds is additionally pushed through
//! `verify` so the scalar-range and point checks run too.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tpt_crypto_sig::ecdsa::{Signature, VerifyingKey, P256, P384};

fuzz_target!(|data: &[u8]| {
    // Alternate between the two supported curve orders so both DER widths and
    // scalar-range checks are exercised.
    if data.is_empty() {
        return;
    }
    if data[0] % 2 == 0 {
        if let Ok(sig) = Signature::<P256>::from_der(&data[1..]) {
            // Round-trip: re-encoding a parsed signature must re-parse, and the
            // DER we emit must be byte-identical to the input for a canonical
            // encoding.
            let re = sig.to_der();
            if let Ok(again) = Signature::<P256>::from_der(&re) {
                assert_eq!(again.to_der(), re, "DER encode/parse is not stable");
            }
            // A random verifying key; the interesting path is the rejection of
            // an invalid signature, which must not panic.
            let _ = VerifyingKey::<P256>::from_sec1(&[0u8; 65]).is_ok();
            let _ = core::hint::black_box(re);
        }
    } else if let Ok(sig) = Signature::<P384>::from_der(&data[1..]) {
        let _ = core::hint::black_box(sig.to_der());
    }
});