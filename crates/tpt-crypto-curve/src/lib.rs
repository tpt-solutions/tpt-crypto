//! `tpt-crypto-curve` — constant-time elliptic-curve arithmetic.
//!
//! Pure Rust, `#![no_std]` (plus `alloc` where needed). Every primitive is
//! branch-free and index-free on secret data, using the `ct_select` /
//! `ct_lookup` primitives from `tpt-crypto-ct`.
#![no_std]
#![forbid(unsafe_code)]
#![warn(missing_docs)]

pub mod edwards25519;
pub mod montgomery25519;
pub mod weierstrass;

pub use edwards25519::EdwardsPoint;
pub use montgomery25519::X25519;
pub use weierstrass::{P256Point, P384Point, ProjectivePoint, WeierstrassParams, P256, P384};
