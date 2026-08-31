//! SLH-DSA (FIPS 205) — hash-based stateless signatures.
//!
//! This module is scaffolded but not yet implemented. The public surface
//! below documents the intended API; operations currently return
//! [`crate::Error::Unsupported`] until the WOTS+/XMSS/FORS/hypertree
//! construction lands.

use crate::{Error, Result};

/// SLH-DSA parameter set identifier (FIPS 205).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum SlhDsaParam {
    /// SHA2-128f (small/secure).
    Sha2_128f,
    /// SHA2-128s (small/fast).
    Sha2_128s,
    /// SHAKE-128f.
    Shake128f,
    /// SHAKE-128s.
    Shake128s,
}

/// A SLH-DSA public key (stub).
#[derive(Clone, Copy, Debug)]
pub struct PublicKey {
    /// Reserved for the encoded key bytes.
    _reserved: [u8; 0],
}

/// A SLH-DSA secret key (stub).
#[derive(Clone, Copy, Debug)]
pub struct SecretKey {
    /// Reserved for the encoded key bytes.
    _reserved: [u8; 0],
}

/// Not yet implemented.
pub fn keygen(_rng: &mut impl tpt_crypto_core::CryptoRng) -> Result<(PublicKey, SecretKey)> {
    Err(Error::Unsupported)
}

/// Not yet implemented.
pub fn sign(_sk: &SecretKey, _msg: &[u8], _ctx: &[u8]) -> Result<()> {
    Err(Error::Unsupported)
}

/// Not yet implemented.
pub fn verify(_pk: &PublicKey, _msg: &[u8], _sig: &[u8], _ctx: &[u8]) -> Result<()> {
    Err(Error::Unsupported)
}
