//! Binary-level probe for the eta = 2 centered-binomial sampler, which expands
//! secret randomness in ML-KEM-768 keygen and encryption (todo V3).
//!
//! Report-only. The release build keeps the 256-coefficient loop, so the scan finds
//! 67 conditional jumps. Most are loop control over public counts. Triage is open.
//! `cargo xtask ct-asm` compiles this file to assembly and checks the `probe_*`
//! functions. The probe is compiled only, not called.

#![allow(dead_code)]

use tpt_crypto_kem::sampler::cbd;

/// CBD with eta = 2 from a secret seed. Compiled for the assembly scan only.
pub fn probe_cbd_eta2(out: &mut [i32; 256], seed: &[u8; 32], counter: u8) {
    cbd(out, seed, counter, 2)
}

/// Not run. Taking the address keeps the probe in the emitted code.
#[test]
#[ignore = "keeps the probe in the emitted assembly; never run"]
fn keep_probes_alive() {
    std::hint::black_box(probe_cbd_eta2 as fn(&mut [i32; 256], &[u8; 32], u8));
}
