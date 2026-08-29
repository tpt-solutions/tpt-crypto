//! FrodoKEM (feature `frodo`).
//!
//! FrodoKEM is a lattice-based KEM that, unlike ML-KEM, uses a module-/algebra-
//! free LWE construction for conservative, structure-free security. This is a
//! larger, separately-gated module: the present build exposes the API surface
//! but the implementation is not yet wired and returns
//! [`tpt_crypto_core::Error::Unsupported`]. Enable the `frodo` feature to opt in.
use tpt_crypto_core::{CryptoRng, Error};

/// FrodoKEM operation set (placeholder until the implementation lands).
pub struct FrodoKem;

impl FrodoKem {
    /// Placeholder key generation.
    pub fn keygen(_rng: &mut impl CryptoRng) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    /// Placeholder encapsulation.
    pub fn encapsulate(_pk: &[u8], _rng: &mut impl CryptoRng) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    /// Placeholder decapsulation.
    pub fn decapsulate(_sk: &[u8], _ct: &[u8]) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
}
