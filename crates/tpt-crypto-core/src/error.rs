//! Error type for the substrate.
//!
//! [`Error`] is the single error type used across the substrate. It is
//! deliberately **non-secret**: it carries no key material, no plaintext, and no
//! detail that would let a caller distinguish *why* an operation failed beyond
//! the broad category. In particular every variant is indistinguishable to a
//! timing or error-type oracle — a verification failure and a malformed-encoding
//! failure take the same shape.

use core::fmt;

/// Errors returned by the `tpt-crypto` substrate.
///
/// The discriminant reveals only a coarse category, never secret material or an
/// oracle-distinguishing detail. Convert to a string only for diagnostics — never
/// branch on the variant in a secret-dependent way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A verification (signature, tag, proof, MAC) did not check out.
    Verification,
    /// An input had the wrong length for the operation.
    InvalidLength,
    /// An input was not a valid encoding (e.g. non-canonical point, bad DER).
    InvalidEncoding,
    /// The RNG or DRBG failed to produce bytes.
    RngFailure,
    /// A point was not on its curve / not in the expected subgroup.
    NotOnCurve,
    /// A decoded curve point was invalid.
    InvalidPoint,
    /// A signature was syntactically invalid (wrong size, bad structure).
    InvalidSignature,
    /// A ciphertext was syntactically invalid or failed implicit rejection.
    InvalidCiphertext,
    /// A key was syntactically invalid (wrong size, wrong domain).
    InvalidKey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Error::Verification => "verification failed",
            Error::InvalidLength => "invalid length",
            Error::InvalidEncoding => "invalid encoding",
            Error::RngFailure => "rng failure",
            Error::NotOnCurve => "point not on curve",
            Error::InvalidPoint => "invalid point",
            Error::InvalidSignature => "invalid signature",
            Error::InvalidCiphertext => "invalid ciphertext",
            Error::InvalidKey => "invalid key",
        };
        f.write_str(s)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Convenience `Result` alias with the substrate [`Error`] as the error type.
pub type Result<T, E = Error> = core::result::Result<T, E>;
