//! Binary-level constant-time probes for ML-KEM decapsulation (todo V3).
//!
//! `cargo xtask ct-asm` compiles this file to assembly and inspects the `probe_*`
//! functions. These are compiled only, not called here.

#![cfg(feature = "alloc")]
#![allow(dead_code)]

use tpt_crypto_kem::ml_kem::{decapsulate, DecapsKey};
use tpt_crypto_kem::params::MlKem768;

/// Compiled for the assembly scan only; see the module docs.
pub fn probe_ml_kem768_decapsulate(
    dk: &DecapsKey,
    ct: &[u8],
) -> Result<[u8; 32], tpt_crypto_core::Error> {
    decapsulate::<MlKem768>(dk, ct)
}

/// Not run. Taking the function's address keeps it in the emitted code, because
/// rustc drops unreferenced `pub fn`s from a test binary.
#[test]
#[ignore = "keeps the probe in the emitted assembly; never run"]
fn keep_probes_alive() {
    let f: fn(&DecapsKey, &[u8]) -> Result<[u8; 32], tpt_crypto_core::Error> =
        probe_ml_kem768_decapsulate;
    std::hint::black_box(f);
}
