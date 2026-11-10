//! Binary-level constant-time probe for Ed25519 scalar multiplication (todo V3).
//!
//! Report-only: the body contains fixed-count loops (window and digit counters,
//! public) that the scan flags as conditional jumps. Not triaged yet beyond the
//! loop-counter reading noted in todo.md.

#![allow(dead_code)]

use tpt_crypto_curve::edwards25519::EdwardsPoint;

/// Full scalar multiplication then compression. Compiled for the assembly scan only.
pub fn probe_ed25519_scalar_mul(p: &EdwardsPoint, k: &[u8; 32]) -> [u8; 32] {
    p.mul(k).compress()
}

/// Not run. Taking the address keeps the probe in the emitted code.
#[test]
#[ignore = "keeps the probe in the emitted assembly; never run"]
fn keep_probes_alive() {
    std::hint::black_box(probe_ed25519_scalar_mul as fn(&EdwardsPoint, &[u8; 32]) -> [u8; 32]);
}
