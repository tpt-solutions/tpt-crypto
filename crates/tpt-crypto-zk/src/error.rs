//! Error type for the `tpt-crypto-zk` crate.
//!
//! Errors carry no secret information (no timing or oracle leakage) and are
//! used by higher-level APIs to signal verification or malformed-input failures.

/// Errors returned by the zero-knowledge protocols in this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ZkError {
    /// A proof or commitment failed to verify.
    Verification,
    /// Input (e.g. a point encoding) was malformed / non-canonical.
    Malformed,
    /// The requested range bit-length `n` is unsupported (must be 8/16/32/64).
    InvalidBitsize,
    /// The aggregation size `m` is not a power of two (required for `n·m` to be
    /// a power of two).
    InvalidAggregation,
    /// An input had an invalid length.
    InvalidLength,
}
