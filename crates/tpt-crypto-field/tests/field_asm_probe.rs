//! Binary-level constant-time probes for Ed25519 field add/sub (todo V3).
//!
//! `cargo xtask ct-asm` compiles this file to assembly and checks the `probe_*`
//! functions for conditional jumps. The probes are compiled only, not called.

#![allow(dead_code)]

use tpt_crypto_field::params::Ed25519Field;

/// Field addition mod p (2^255 - 19). Compiled for the assembly scan only.
pub fn probe_ed25519_fe_add(a: &Ed25519Field, b: &Ed25519Field) -> Ed25519Field {
    a.add(b)
}

/// Field subtraction mod p. Compiled for the assembly scan only.
pub fn probe_ed25519_fe_sub(a: &Ed25519Field, b: &Ed25519Field) -> Ed25519Field {
    a.sub(b)
}

/// Not run. Taking the addresses keeps the probes in the emitted code.
#[test]
#[ignore = "keeps the probes in the emitted assembly; never run"]
fn keep_probes_alive() {
    std::hint::black_box((
        probe_ed25519_fe_add as fn(&Ed25519Field, &Ed25519Field) -> Ed25519Field,
        probe_ed25519_fe_sub as fn(&Ed25519Field, &Ed25519Field) -> Ed25519Field,
    ));
}
