//! `tpt-crypto-field` — constant-time prime field arithmetic.
//!
//! This crate provides a stack-only, `no_std`-first implementation of finite
//! field arithmetic for the curves needed by `tpt-crypto`:
//!
//! * NIST P-256 and P-384 base and scalar fields ([`P256Base`], [`P256Scalar`],
//!   [`P384Base`], [`P384Scalar`]),
//! * BLS12-381 base and scalar fields ([`Bls12381Fp`], [`Bls12381Fr`]),
//! * the BLS12-381 extension towers [`Fp2`], [`Fp6`], [`Fp12`].
//!
//! The core type is [`FieldElement<P, LIMBS>`], which stores elements in Montgomery
//! form and monomorphizes a fully unrolled arithmetic routine per modulus. All
//! secret-dependent operations are implemented with bitwise masks and `cmov`, never
//! with branches on secret data.
//!
//! In the full layout this crate builds on `tpt-math-linalg-fixed` (limb-vector
//! ops) and `tpt-crypto-ct` / `tpt-crypto-core` (constant-time primitives and the
//! error type). Those crates are not yet landed, so minimal, self-contained
//! substitutes live in [`ct`], [`limb`], and [`Error`].

#![no_std]
#![warn(missing_docs)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod ct;
pub mod limb;
pub mod consts;
pub mod field;
pub mod params;
pub mod extension;

mod big;

pub use consts::MAX_LIMBS;
pub use ct::{Choice, CtEq, CtOption};
pub use field::{Field, FieldElement, FieldParams};
pub use limb::Limb;
pub use params::{
    Bls12381Fp, Bls12381FpParams, Bls12381Fr, Bls12381FrParams, Ed25519Field,
    Ed25519FieldParams, Ed25519Scalar, Ed25519ScalarParams, P256Base, P256BaseParams,
    P256Scalar, P256ScalarParams, P384Base, P384BaseParams, P384Scalar, P384ScalarParams,
};
pub use extension::{Fp12, Fp2, Fp6};

/// Error type for field operations.
///
/// This mirrors the planned `tpt-crypto-core::Error`; it carries no secret
/// information (no timing or oracle leakage) and is used by higher-level APIs
/// that wrap this crate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// A verification (e.g. signature / tag) failed.
    Verification,
    /// An input had an invalid length.
    InvalidLength,
    /// An encoding was invalid or non-canonical.
    InvalidEncoding,
    /// Randomness generation failed.
    RngFailure,
    /// A point was not on its curve.
    NotOnCurve,
}
