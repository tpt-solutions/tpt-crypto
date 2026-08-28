//! # tpt-crypto-ct — Constant-Time Arithmetic Substrate
//!
//! This crate provides the low-level, **constant-time-by-construction**
//! primitives used by every higher layer of `tpt-crypto`:
//!
//! - [`Choice`] — a 1-bit secret-carrying type (`0`/`1` as `u8`) with
//!   branch-free boolean operators.
//! - [`cmp`] — `ct_eq` / `ct_ne` for the integer types and byte/limb slices.
//! - [`select`] — `ct_select`, `cmov`, `cswap`, `ct_select_slice`.
//! - [`arch`] — the **only** `unsafe` module: platform conditional-move
//!   primitives (`cmov`/`csel`/portable bitmask fallback), each with a
//!   `// SAFETY:` comment.
//! - [`masked`] — additive (XOR) and multiplicative masking for limbs.
//! - [`blinding`] — scalar and base-point blinding scaffolds.
//! - [`lookup`] — branch-free table lookup (`ct_lookup`) for window methods.
//!
//! ## Safety / `unsafe` policy
//!
//! The whole workspace has `unsafe_code = "forbid"` via `[workspace.lints]`.
//! **This crate is the single documented exception.** It re-declares its own
//! lints in `Cargo.toml` (keeping `unsafe_op_in_unsafe_fn = "deny"`) and does
//! *not* inherit the workspace forbid. The only `unsafe` code lives in
//! [`arch`] and every `unsafe` block carries a `// SAFETY:` comment. This is
//! recorded in `SECURITY.md`.
//!
//! All other modules are written with ordinary safe Rust; there are no
//! secret-dependent branches or memory accesses anywhere in the public API.
#![no_std]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]
#![deny(unsafe_op_in_unsafe_fn)]

pub mod arch;
pub mod blinding;
pub mod choice;
pub mod cmp;
pub mod lookup;
pub mod masked;
pub mod select;

pub use choice::Choice;
pub use cmp::{ct_eq, ct_eq_bytes, ct_eq_limbs, ct_ne, CtEq};
pub use select::{cmov, cswap, ct_select, ct_select_slice, CtSelect};

/// A single machine word used for field/curve limb arithmetic.
///
/// This is defined here (rather than in `-field`) because `-ct` is layered
/// *below* `-field`; the field crate depends on this one.
pub type Limb = u64;
