//! Minimal PLONK verifier (placeholder).
//!
//! The crate's lib surface lists [`plonk`] as a module so downstream users can
//! rely on a stable path, but the verifier itself is not yet implemented in
//! this build. The intended design (per `spec.txt` §4 and the crate todo) is a
//! ~500 LoC verifier that checks a compliant PLONK proof against a trusted
//! setup: a Fiat–Shamir transcript, a KZG or inner-product commitment opening
//! check, and the permutation + gate/arithmetic constraint equations.
//!
//! Until that lands, [`verify_proof`] returns [`ZkError::Unsupported`] so the
//! crate still compiles and the API surface is stable.

use crate::error::ZkError;

/// A PLONK proof in serialized form (opaque placeholder).
#[derive(Clone, Debug)]
pub struct PlonkProof(pub alloc::vec::Vec<u8>);

/// Verify a PLONK proof.
///
/// # Errors
///
/// Always returns [`ZkError::Unsupported`] until the verifier is implemented.
pub fn verify_proof(_proof: &PlonkProof, _public_inputs: &[u8]) -> Result<(), ZkError> {
    Err(ZkError::Unsupported)
}
