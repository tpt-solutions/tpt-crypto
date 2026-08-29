//! ML-KEM parameter sets.
//!
//! Every ML-KEM parameter set shares `q = 3329` and `n = 256`; they differ in
//! the module rank `k`, the CBD widths `eta1`/`eta2`, and the ciphertext
//! compression bits `du`/`dv`. The associated consts also give the exact
//! serialized sizes of the public key, secret key, and ciphertext, which are
//! derived from the NIST parameter table.

/// A concrete ML-KEM parameter set.
///
/// Implementors fix `k`, `eta1`, `eta2`, `du`, `dv` and the serialized sizes.
pub trait MlKemParams {
    /// Module rank (number of rows/columns of the matrix `A`).
    const K: usize;
    /// CBD width for the secret `s` and the encryption randomness `r`.
    const ETA1: usize;
    /// CBD width for the noise polynomials `e1`/`e2`.
    const ETA2: usize;
    /// Compression bits for the ciphertext `c1` (the `u` vector).
    const DU: usize;
    /// Compression bits for the ciphertext `c2` (the `v` polynomial).
    const DV: usize;
    /// Byte length of the encoded public key (`rho ‖ t_hat`).
    const PK_LEN: usize = 384 * Self::K + 32;
    /// Byte length of the encoded secret key (`ek ‖ d ‖ H(ek) ‖ z`).
    const SK_LEN: usize = 768 * Self::K + 96;
    /// Byte length of the ciphertext (`c1 ‖ c2`).
    const CT_LEN: usize = 32 * Self::DU * Self::K + 32 * Self::DV;
    /// Human-readable name (e.g. `"ML-KEM-768"`).
    const NAME: &'static str;
}

/// ML-KEM-512 (security category ~128 bits).
pub struct MlKem512;
impl MlKemParams for MlKem512 {
    const K: usize = 2;
    const ETA1: usize = 3;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
    const NAME: &'static str = "ML-KEM-512";
}

/// ML-KEM-768 (security category ~192 bits).
pub struct MlKem768;
impl MlKemParams for MlKem768 {
    const K: usize = 3;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 10;
    const DV: usize = 4;
    const NAME: &'static str = "ML-KEM-768";
}

/// ML-KEM-1024 (security category ~256 bits).
pub struct MlKem1024;
impl MlKemParams for MlKem1024 {
    const K: usize = 4;
    const ETA1: usize = 2;
    const ETA2: usize = 2;
    const DU: usize = 11;
    const DV: usize = 5;
    const NAME: &'static str = "ML-KEM-1024";
}
