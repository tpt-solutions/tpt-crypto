//! Classic McEliece (feature `mceliece`).
//!
//! Classic McEliece is a code-based KEM whose public key is a generating matrix
//! and whose secret key is a structured error-correcting code — a *long-term*
//! secret that must be protected for the lifetime of the deployment. This is a
//! large, separately-gated module; the present build exposes the API surface but
//! the implementation is not yet wired and returns
//! [`tpt_crypto_core::Error::Unsupported`]. Enable the `mceliece` feature to opt
//! in.
use tpt_crypto_core::{CryptoRng, Error};

/// Classic McEliece operation set (placeholder until the implementation lands).
pub struct McEliece;

impl McEliece {
    /// Placeholder key generation (long-term secret).
    pub fn keygen(_rng: &mut impl CryptoRng) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    /// Placeholder encapsulation.
    pub fn encapsulate(_pk: &[u8], _rng: &mut impl CryptoRng) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
    /// Placeholder decapsulation (uses the long-term secret key).
    pub fn decapsulate(_sk: &[u8], _ct: &[u8]) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
}
