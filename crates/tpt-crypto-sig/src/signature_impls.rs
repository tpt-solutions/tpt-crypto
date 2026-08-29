//! Optional `signature`-crate trait compatibility.
//!
//! When the `signature` Cargo feature is enabled (or under `cfg(test)`), this
//! module wires `tpt-crypto-sig` key/signature types to the
//! [`signature::Signer`] / [`signature::Verifier`] traits. It is currently a
//! placeholder; the checklist item "Optional `signature` trait-compat impls
//! behind `signature` feature" tracks the full wiring.

#![allow(unused)]
