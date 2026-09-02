//! BLS12-381 signatures (stub until `tpt-crypto-curve` lands BLS support).
//!
//! The API surface matches `spec.txt §4` so callers can be written against
//! this module and will work unchanged once the `-curve` implementation
//! is ready.

#![allow(dead_code)]

use tpt_crypto_core::{Error, Result};

/// BLS12-381 public key (placeholder until `-curve` exposes it).
#[derive(Debug, Clone, Copy)]
pub struct PublicKey([u8; 48]);

/// BLS12-381 secret key (placeholder).
#[derive(Debug, Clone, Copy)]
pub struct SecretKey([u8; 32]);

/// BLS12-381 signature (placeholder).
#[derive(Debug, Clone, Copy)]
pub struct Signature([u8; 96]);

/// Stub: sign `msg` with `sk`.
pub fn sign(_sk: &SecretKey, _msg: &[u8]) -> Signature {
    Signature([0u8; 96])
}

/// Stub: aggregate `sigs`.
pub fn aggregate(_sigs: &[Signature]) -> Signature {
    Signature([0u8; 96])
}

/// Stub: verify `agg` against `pks` and `msg`.
pub fn verify_aggregate(_pks: &[PublicKey], _msg: &[u8], _agg: &Signature) -> Result<(), Error> {
    Err(Error::Unsupported)
}
