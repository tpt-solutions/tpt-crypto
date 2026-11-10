//! Binary-level constant-time probes for AEAD tag verification (todo V3).
//!
//! `cargo xtask ct-asm` compiles this file to assembly and checks the `probe_*`
//! functions for conditional jumps. The probes are compiled only, not called.

#![allow(dead_code)]

use tpt_crypto_aead::Tag;

/// Compiled for the assembly scan only.
pub fn probe_tag16_verify(a: &[u8; 16], b: &[u8; 16]) -> u8 {
    Tag::<16>(*a).ct_eq(&Tag::<16>(*b)) as u8
}

/// Compiled for the assembly scan only.
pub fn probe_tag32_verify(a: &[u8; 32], b: &[u8; 32]) -> u8 {
    Tag::<32>(*a).ct_eq(&Tag::<32>(*b)) as u8
}

/// Not run. Taking the addresses keeps the probes in the emitted code.
#[test]
#[ignore = "keeps the probes in the emitted assembly; never run"]
fn keep_probes_alive() {
    std::hint::black_box((
        probe_tag16_verify as fn(&[u8; 16], &[u8; 16]) -> u8,
        probe_tag32_verify as fn(&[u8; 32], &[u8; 32]) -> u8,
    ));
}
