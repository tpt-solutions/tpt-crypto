//! Binary-level constant-time probes for Ed25519 point addition (todo V3).
//!
//! `cargo xtask ct-asm` compiles this file to assembly and checks the `probe_*`
//! functions for conditional jumps. The probes are compiled only, not called.
//! The scan reads each probe's own body and does not follow calls, so the
//! scalar-multiplication probe lives in its own target (`curve_mul_asm_probe`).

#![allow(dead_code)]

use tpt_crypto_curve::edwards25519::EdwardsPoint;

/// Unified point addition. Compiled for the assembly scan only.
pub fn probe_ed25519_add(p: &EdwardsPoint, q: &EdwardsPoint) -> EdwardsPoint {
    p.add(q)
}

/// Not run. Taking the address keeps the probe in the emitted code.
#[test]
#[ignore = "keeps the probe in the emitted assembly; never run"]
fn keep_probes_alive() {
    std::hint::black_box(probe_ed25519_add as fn(&EdwardsPoint, &EdwardsPoint) -> EdwardsPoint);
}
