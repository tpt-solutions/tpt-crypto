//! Binary-level constant-time probes for the ML-KEM-768 K-PKE callees of
//! decapsulation (todo V3). The decapsulation probe calls these out of line, so the
//! scan of that probe does not see them.
//!
//! Report-only: both functions loop over public counts (rows, polynomials,
//! coefficients) and call the hash out of line, so the jumps are not triaged.
//! `cargo xtask ct-asm` compiles this file to assembly. The probes are not called.

#![allow(dead_code)]

use tpt_crypto_kem::params::MlKem768;
use tpt_crypto_kem::pke::{kpke_decrypt, kpke_encrypt, PolyVec};

/// K-PKE decryption with the secret `s_hat`. Compiled for the assembly scan only.
pub fn probe_kpke_decrypt_768(
    s_hat: &PolyVec,
    ct: &[u8],
) -> Result<[u8; 32], tpt_crypto_core::Error> {
    kpke_decrypt::<MlKem768>(s_hat, ct)
}

/// K-PKE re-encryption on the secret message `m`. Compiled for the assembly scan only.
pub fn probe_kpke_encrypt_768(
    rho: &[u8; 32],
    t_hat: &PolyVec,
    m: &[u8; 32],
    r_seed: &[u8; 32],
) -> Vec<u8> {
    kpke_encrypt::<MlKem768>(rho, t_hat, m, r_seed)
}

/// Not run. Taking the addresses keeps the probes in the emitted code.
#[test]
#[ignore = "keeps the probes in the emitted assembly; never run"]
fn keep_probes_alive() {
    std::hint::black_box((
        probe_kpke_decrypt_768 as fn(&PolyVec, &[u8]) -> Result<[u8; 32], tpt_crypto_core::Error>,
        probe_kpke_encrypt_768 as fn(&[u8; 32], &PolyVec, &[u8; 32], &[u8; 32]) -> Vec<u8>,
    ));
}
