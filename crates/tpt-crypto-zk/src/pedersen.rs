//! Pedersen commitments over the prime-order group.
//!
//! A Pedersen commitment `commit(value, blind) = value·G + blind·H` is
//! perfectly hiding in the blinding and computationally binding in the value
//! (discrete-logarithm assumption). The generators `G` and `H` are fixed,
//! independent, and lie in the prime-order subgroup.

use tpt_crypto_field::Ed25519Scalar;

use crate::group::Ristretto;

/// Pedersen commitment generators `G` (value) and `H` (blinding).
#[derive(Clone, Copy, Debug)]
pub struct PedersenGens {
    /// Generator for the committed value.
    pub g: Ristretto,
    /// Generator for the blinding factor.
    pub h: Ristretto,
}

impl Default for PedersenGens {
    fn default() -> Self {
        PedersenGens {
            g: Ristretto::map_to_point(b"tpt-crypto-zk.Pedersen.g"),
            h: Ristretto::map_to_point(b"tpt-crypto-zk.Pedersen.h"),
        }
    }
}

impl PedersenGens {
    /// `commit(value, blind) = value·G + blind·H`.
    pub fn commit(&self, value: &Ed25519Scalar, blind: &Ed25519Scalar) -> Ristretto {
        self.g.scalar_mul(value).add(&self.h.scalar_mul(blind))
    }

    /// Commit a `u64` value with a scalar blinding factor.
    pub fn commit_u64(&self, value: u64, blind: &Ed25519Scalar) -> Ristretto {
        self.commit(&Ed25519Scalar::from_u64(value), blind)
    }
}
