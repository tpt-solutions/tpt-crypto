#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
//! Constant-time hash functions and MACs for `tpt-crypto`.
//!
//! All streaming state machines here are fixed-trace: the compression and
//! permutation routines never branch or index on secret data, so hashing is
//! constant-time by construction. MAC verification is performed with the
//! `ct_eq` / `ct_select` primitives from `tpt-crypto-ct`.
//!
//! # Streaming API
//!
//! Fixed-output hashes implement [`Hasher`] (`update` / `finalize` /
//! `finalize_reset` / `reset`); extendable outputs (SHAKE, cSHAKE, KMAC,
//! BLAKE3, K12) implement [`Xof`] (`update` / `finalize_xof` /
//! `finalize_xof_reset` / `reset`).
//!
//! # One-shot API
//!
//! Each primitive also has a one-shot free function, e.g.
//! [`sha2::sha256`], [`sha3::shake256`], [`mac::hmac_sha256`],
//! [`kdf::hkdf_sha256`].
//!
//! # Features
//!
//! - `std` (default): enables `std`/`alloc` on the core crates.
//! - `alloc`: heap support without `std`.
//! - `digest`: implements the `digest` crate traits (`digest::Digest`,
//!   `digest::ExtendableOutput`, …) for the relevant types.

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod blake2b;
pub mod blake3;
pub mod k12;
pub mod kdf;
pub mod mac;
pub mod sha2;
pub mod sha3;

mod drbg;
mod traits;

pub use drbg::HmacDrbg;
pub use traits::{Hasher, Xof};

#[cfg(feature = "digest")]
pub mod digest_impls;
