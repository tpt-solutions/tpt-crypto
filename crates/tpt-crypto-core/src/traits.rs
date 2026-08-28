//! Constant-time trait surface and facades.
//!
//! [`CtEq`] and [`ConstantTimeSelect`] are defined here and given portable,
//! constant-time implementations for the primitive integer types, byte slices,
//! and `str`. `tpt-crypto-ct` provides architecture-optimized (`core::arch` /
//! inline `asm!`) variants building on these same types and re-exports them.
//!
//! The free functions [`ct_eq`], [`ct_ne`], and [`ct_select`] are the ergonomic
//! facades: `ct_eq(&a, &b)` returns a set [`Choice`] iff `a == b`, in constant
//! time; `ct_select(&a, &b, c)` yields `a` when `c` is true and `b` otherwise, in
//! constant time. Always go through these instead of `if`/`match`/indexing on a
//! secret.

use crate::Choice;
use core::ops::Not;

/// Constant-time equality.
///
/// Implementors compare two values without branching on the secret content.
pub trait CtEq {
    /// Return [`Choice::TRUE`] iff `self` and `rhs` are equal.
    fn ct_eq(&self, rhs: &Self) -> Choice;

    /// Constant-time inequality.
    #[inline]
    fn ct_ne(&self, rhs: &Self) -> Choice {
        self.ct_eq(rhs).not()
    }
}

/// Constant-time conditional selection / assignment.
///
/// `ct_select` must run in time independent of `c` and of the selected value.
/// Implementors that are unsized (e.g. `str`) need not provide it.
pub trait ConstantTimeSelect {
    /// Select `a` if `c == Choice::TRUE`, else `b`.
    fn ct_select(a: &Self, b: &Self, c: Choice) -> Self
    where
        Self: Sized;

    /// Conditionally assign `other` into `self` iff `c == Choice::TRUE`.
    #[inline]
    fn ct_assign(&mut self, other: &Self, c: Choice)
    where
        Self: Sized,
    {
        *self = Self::ct_select(self, other, c);
    }
}

/// Constant-time equality: a set [`Choice`] iff `a == b`.
#[inline]
#[must_use]
pub fn ct_eq<T: CtEq>(a: &T, b: &T) -> Choice {
    a.ct_eq(b)
}

/// Constant-time inequality: a set [`Choice`] iff `a != b`.
#[inline]
#[must_use]
pub fn ct_ne<T: CtEq>(a: &T, b: &T) -> Choice {
    a.ct_eq(b).not()
}

/// Constant-time selection: `a` if `c` is true, else `b`. Branch- and
/// index-free with respect to `c` and the selected value.
#[inline]
#[must_use]
pub fn ct_select<T: ConstantTimeSelect>(a: &T, b: &T, c: Choice) -> T {
    T::ct_select(a, b, c)
}
