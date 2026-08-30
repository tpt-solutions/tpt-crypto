//! Digital signature schemes for the `tpt-crypto` substrate.
//!
//! This crate implements the FIPS 204 (ML-DSA) and FIPS 205 (SLH-DSA)
//! stateless signature standards in pure Rust, `#![no_std]`, constant-time
//! by construction, and allocation-free on the hot paths.
//!
//! - [`ml_dsa`] — ML-DSA-44 / -65 / -87 (lattice-based, FIPS 204).
//! - [`slh_dsa`] — SLH-DSA (hash-based, FIPS 205).

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod bytes;
pub mod constant_time;
pub mod ml_dsa;
pub mod poly;
pub mod test_rng;

#[cfg(feature = "slh-dsa")]
pub mod slh_dsa;

#[cfg(any(test, feature = "signature"))]
pub mod signature_impls;

use core::fmt;

/// A non-secret error type for the signature layer.
///
/// Carries no timing- or oracle-relevant information: verification failures and
/// malformed-input conditions are reported opaquely so they cannot be
/// distinguished by a caller observing side channels.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A byte string had the wrong length for the operation (key, signature,
    /// context, or KAT buffer).
    InvalidLength,
    /// A signature did not verify.
    Verification,
    /// The RNG failed to produce the requested bytes.
    RngFailure,
    /// A decoding (public key, secret key, or signature) was malformed.
    InvalidEncoding,
    /// A KAT file was missing, malformed, or failed to match.
    Kat,
    /// The requested operation or parameter set is not yet implemented.
    Unsupported,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Error::InvalidLength => "invalid length",
            Error::Verification => "verification failed",
            Error::RngFailure => "RNG failure",
            Error::InvalidEncoding => "malformed encoding",
            Error::Kat => "known-answer test mismatch",
            Error::Unsupported => "operation not implemented",
        };
        f.write_str(s)
    }
}

impl core::error::Error for Error {}

/// Convenience result alias for the signature layer.
pub type Result<T> = core::result::Result<T, Error>;
