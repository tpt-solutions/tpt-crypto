//! Constant-time selection and conditional moves: [`CtSelect`], `ct_select`,
//! `cmov`, `cswap`, `ct_select_slice`.
//!
//! The defining law is
//!
//! ```text
//! ct_select(cond, a, b) == if cond { a } else { b }
//! ```
//!
//! but evaluated with **no branch on `cond`**. The `u64` implementation routes
//! through [`crate::arch::cmov_u64`] (a real `cmov`/`csel` on supported
//! targets); every other width uses an equivalent full-width bitmask.

use crate::arch;
use crate::choice::Choice;
use crate::cmp::CtEq;

/// A type that supports a constant-time selection between two values.
///
/// `CtSelect::ct_select(cond, a, b)` must return `a` when `cond` is true and
/// `b` otherwise, using only data-flow operations.
pub trait CtSelect {
    /// Return `a` if `cond` is [`Choice::TRUE`], else `b`.
    fn ct_select(cond: Choice, a: Self, b: Self) -> Self;
}

impl CtSelect for u64 {
    #[inline]
    fn ct_select(cond: Choice, a: u64, b: u64) -> u64 {
        let mut out = b; // start at the "false" value
                         // SAFETY: `out` and `a` are aligned, non-overlapping locals. The
                         // platform `cmov` writes `out` only when `cond != 0`, selecting `a`
                         // without a control-flow branch.
        unsafe { arch::cmov_u64(cond.0, &mut out, &a) };
        out
    }
}

macro_rules! impl_ct_select_int {
    ($($t:ty),*) => {
        $(
            impl CtSelect for $t {
                #[inline]
                fn ct_select(cond: Choice, a: $t, b: $t) -> $t {
                    let m = (cond.0 as $t).wrapping_neg(); // 0 or !0
                    b ^ (m & (a ^ b))
                }
            }
        )*
    };
}

impl_ct_select_int!(u8, u16, u32, u128, usize);

/// Generic constant-time selection for any [`CtSelect`] type.
#[inline]
#[must_use]
pub fn ct_select<T: CtSelect>(cond: Choice, a: T, b: T) -> T {
    T::ct_select(cond, a, b)
}

/// Conditionally copy `*src` into `*dst` when `cond` is true.
///
/// This is the canonical "conditional move" used to update state without a
/// branch. `dst` is unchanged when `cond` is false.
#[inline]
pub fn cmov<T: CtSelect + Copy>(cond: Choice, dst: &mut T, src: &T) {
    // dst = cond ? src : dst  ==  ct_select(cond, src, dst)
    *dst = T::ct_select(cond, *src, *dst);
}

/// Conditionally swap `*a` and `*b` when `cond` is true.
#[inline]
pub fn cswap<T: CtSelect + Copy>(cond: Choice, a: &mut T, b: &mut T) {
    let t = T::ct_select(cond, *b, *a);
    let u = T::ct_select(cond, *a, *b);
    *a = t;
    *b = u;
}

/// Constant-time selection between two byte slices, written into `out`.
///
/// For every index `i`, `out[i] = if cond { a[i] } else { b[i] }`. The three
/// slices are assumed to have equal length (their lengths are public).
#[inline]
#[allow(clippy::needless_range_loop)]
pub fn ct_select_slice(cond: Choice, a: &[u8], b: &[u8], out: &mut [u8]) {
    let m = cond.0.wrapping_neg();
    let n = out.len();
    for i in 0..n {
        let av = a.get(i).copied().unwrap_or(0);
        let bv = b.get(i).copied().unwrap_or(0);
        out[i] = bv ^ (m & (av ^ bv));
    }
}

/// Constant-time selection over fixed-size arrays (a thin generic helper used
/// by callers that prefer arrays to slices).
#[inline]
#[must_use]
pub fn ct_select_array<T: CtSelect + Copy, const N: usize>(
    cond: Choice,
    a: [T; N],
    b: [T; N],
) -> [T; N] {
    let mut out = b;
    for i in 0..N {
        out[i] = T::ct_select(cond, a[i], b[i]);
    }
    out
}

/// Convenience: `ct_eq` on two `usize` values (used by the lookup harness).
#[inline]
#[must_use]
pub fn ct_eq_usize(a: usize, b: usize) -> Choice {
    <usize as CtEq>::ct_eq(&a, &b)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn select_law() {
        for c in [Choice::FALSE, Choice::TRUE] {
            assert_eq!(
                ct_select(c, 11u64, 22u64),
                if c.is_true() { 11 } else { 22 }
            );
            assert_eq!(ct_select(c, 11u8, 22u8), if c.is_true() { 11 } else { 22 });
            assert_eq!(
                ct_select(c, 11usize, 22usize),
                if c.is_true() { 11 } else { 22 }
            );
            assert_eq!(
                ct_select(c, 0x1234u128, 0x5678u128),
                if c.is_true() { 0x1234 } else { 0x5678 }
            );
        }
    }

    #[test]
    fn cmov_cswap() {
        let mut dst = 5u64;
        cmov(Choice::TRUE, &mut dst, &42);
        assert_eq!(dst, 42);
        cmov(Choice::FALSE, &mut dst, &7);
        assert_eq!(dst, 42);

        let (mut x, mut y) = (1u32, 2u32);
        cswap(Choice::TRUE, &mut x, &mut y);
        assert_eq!((x, y), (2, 1));
        cswap(Choice::FALSE, &mut x, &mut y);
        assert_eq!((x, y), (2, 1));
    }

    #[test]
    fn slice_select() {
        let a = [1u8, 2, 3, 4];
        let b = [9u8, 8, 7, 6];
        let mut out = [0u8; 4];
        ct_select_slice(Choice::TRUE, &a, &b, &mut out);
        assert_eq!(out, a);
        ct_select_slice(Choice::FALSE, &a, &b, &mut out);
        assert_eq!(out, b);
    }
}
