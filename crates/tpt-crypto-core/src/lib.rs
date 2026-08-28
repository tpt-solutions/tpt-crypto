//! `tpt-crypto-core` — shared types, traits, and secret-handling wrappers for
//! the `tpt-crypto` constant-time cryptographic substrate.
//!
//! This crate is the lowest layer of the workspace. It defines the vocabulary
//! every other crate builds on:
//!
//! - [`Error`] — the substrate's non-secret error type (carries no timing/oracle
//!   information).
//! - [`Zeroize`] / [`Zeroizing`] — a volatile byte-wipe so secrets never linger
//!   in memory after `Drop`.
//! - [`SecretBox`] — an owned secret that *cannot* be printed, compared, hashed,
//!   or accidentally observed; reading it requires an explicit
//!   [`SecretBox::expose_secret`] call.
//! - [`CtEq`] / [`ConstantTimeSelect`] — the constant-time *trait surface*. The
//!   concrete algorithms live in `tpt-crypto-ct` (one layer up) so that `-core`
//!   stays dependency-free of `unsafe`.
//! - [`CryptoRng`] / [`DrbgCore`] — the RNG traits implemented by the DRBGs in
//!   `tpt-crypto-hash` / `tpt-crypto-aead`.
//!
//! # Layering
//!
//! `core → ct → field → curve`. This crate depends on no internal crate. The
//! constant-time *implementations* are provided by `tpt-crypto-ct`, which
//! re-exports the [`CtEq`] / [`ConstantTimeSelect`] trait impls there.
//!
//! # `no_std`
//!
//! `#![no_std]` by default. Enable `std` (on by default) for
//! [`std::error::Error`] integration.

#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

#[cfg(feature = "std")]
extern crate std;

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod choice;
pub mod constant_time;
pub mod error;
pub mod impls;
pub mod rng;
pub mod secret;
pub mod traits;
pub mod zeroize;

#[cfg(feature = "rand_core")]
pub mod rand_core_bridge;

/// Convenience re-exports of the most-used items.
pub use choice::Choice;
pub use error::{Error, Result};
pub use rng::{CryptoRng, DrbgCore};
pub use secret::SecretBox;
pub use traits::{ct_eq, ct_ne, ct_select, ConstantTimeSelect, CtEq};
pub use zeroize::{Zeroize, Zeroizing};

#[cfg(feature = "rand_core")]
pub use rand_core_bridge::{CoreRng, RandCoreRng};
