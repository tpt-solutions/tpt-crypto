//! Blinding helpers for scalar and base-point operations.
//!
//! Scalar blinding masks a secret scalar `x` as `x * k` (with odd `k`) so that
//! variable-time or SPA-prone operations (e.g. scalar multiplication) run on a
//! randomized input. The result is later unblinded with `k^{-1}`.
//!
//! Base-point blinding randomizes a fixed group element (e.g. the standard
//! generator) by adding a random multiple before use, defeating
//! address/value prediction in repeated operations. The [`BasePointBlinding`]
//! scaffold below is generic over a group-like type so it can be instantiated
//! by `-curve` once a point type exists.

use crate::masked::{mod_inv_odd_u64, random_odd};

/// Blind a scalar `x` by a random odd factor `k`, returning `(x*k, k)`.
///
/// `k` is supplied by the caller (use [`random_odd`] to draw one). Unblind
/// with [`unblind_scalar`].
#[inline]
#[must_use]
pub fn blind_scalar(x: u64, k: u64) -> (u64, u64) {
    (x.wrapping_mul(k), k)
}

/// Recover `x` from a blinded scalar `(x*k, k)` using `k^{-1} mod 2^64`.
///
/// Requires `k` to be odd (which [`random_odd`] guarantees).
#[inline]
#[must_use]
pub fn unblind_scalar(blinded: (u64, u64)) -> u64 {
    let (m, k) = blinded;
    m.wrapping_mul(mod_inv_odd_u64(k))
}

/// Draw a fresh odd blinding factor from `rng`.
#[inline]
#[must_use]
pub fn fresh_blinding<R: crate::masked::Random<u64>>(rng: &mut R) -> u64 {
    random_odd(rng)
}

/// A scaffold for base-point blinding.
///
/// Stores a base point together with a random blinding offset. The
/// *effective* point used in computation is `base + blind`; re-blinding
/// refreshes `blind` so successive operations use independent material.
///
/// This is intentionally generic and minimal — `-curve` will plug in its
/// concrete point type (which must form an additive group).
#[derive(Copy, Clone)]
pub struct BasePointBlinding<P> {
    base: P,
    blind: P,
}

impl<P: Copy + core::ops::Add<Output = P>> BasePointBlinding<P> {
    /// Create a blinded base point from a base and an initial offset.
    #[inline]
    pub fn new(base: P, blind: P) -> Self {
        Self { base, blind }
    }

    /// The base point being protected.
    #[inline]
    #[must_use]
    pub fn base(&self) -> P {
        self.base
    }

    /// The current blinding offset.
    #[inline]
    #[must_use]
    pub fn blind(&self) -> P {
        self.blind
    }

    /// The effective, blinded point `base + blind`.
    #[inline]
    #[must_use]
    pub fn blinded(&self) -> P {
        self.base + self.blind
    }

    /// Refresh the blinding offset by adding `new_blind` to it. The effective
    /// point changes, but remains of the form `base + (refreshed blind)`.
    #[inline]
    pub fn reblind(&mut self, new_blind: P) {
        self.blind = self.blind + new_blind;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scalar_blind_roundtrip() {
        let mut rng = 0x1357_9bdf_2468_ace0u64;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let x = 0x1234_5678_9abc_def0u64;
        let k = fresh_blinding(&mut next);
        let blinded = blind_scalar(x, k);
        assert_eq!(unblind_scalar(blinded), x);
        // a different odd factor must still round-trip
        let k2 = fresh_blinding(&mut next);
        assert_eq!(unblind_scalar(blind_scalar(x, k2)), x);
    }

    #[test]
    fn base_point_blinding() {
        // Use u64 addition as a stand-in group for the scaffold.
        let mut bp = BasePointBlinding::new(5u64, 1u64);
        assert_eq!(bp.blinded(), 6);
        bp.reblind(10u64);
        assert_eq!(bp.blinded(), 16);
    }
}
