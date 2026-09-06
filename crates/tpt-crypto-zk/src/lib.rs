//! `tpt-crypto-zk` — zero-knowledge proofs over Ed25519.
//!
//! High-assurance, `no_std` + `alloc` zero-knowledge primitives:
//!
//! * [`Transcript`] — a Fiat–Shamir transcript (Merlin-style STROBE-lite) built
//!   on SHAKE256, with `append_message` / `challenge_scalar`.
//! * [`PedersenGens`] / [`Ristretto`] — Pedersen commitments over the
//!   prime-order subgroup of Ed25519 (`commit(value, blind) = value·G + blind·H`).
//! * [`InnerProductProof`] — the inner-product argument, the core building block.
//! * [`prove_range`] / [`verify_range`] — Bulletproofs range proofs (single and
//!   aggregated, ranges up to `2^64`).
//! * [`plonk`] — a minimal PLONK verifier (~500 LoC) using inner-product
//!   commitment opening.
//!
//! All secret-dependent operations are constant-time. The group used is the
//! prime-order subgroup of Ed25519 (order `L`), so discrete logarithms are
//! well defined and the cofactor never introduces ambiguity.

#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]
#![cfg_attr(docsrs, feature(doc_cfg))]

extern crate alloc;

pub use tpt_crypto_curve::EdwardsPoint;
pub use tpt_crypto_field::Ed25519Scalar;

mod error;
mod generators;
mod group;
mod pedersen;
mod transcript;

pub mod bulletproofs;
pub mod ipa;
pub mod plonk;

pub use crate::bulletproofs::{
    prove_range, range_proof_from_bytes, range_proof_to_bytes, verify_range, RangeProof,
    SeedExpander,
};
pub use crate::error::ZkError;
pub use crate::generators::BulletproofGens;
pub use crate::group::Ristretto;
pub use crate::ipa::InnerProductProof;
pub use crate::pedersen::PedersenGens;
pub use crate::transcript::Transcript;
