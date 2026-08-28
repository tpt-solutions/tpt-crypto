//! Constant-time equality: [`CtEq`] and the free functions `ct_eq` / `ct_ne`.
//!
//! All comparisons are data-flow driven: they compute a [`Choice`] using only
//! bitwise reductions and never branch on the secret material.

use crate::choice::Choice;
use crate::Limb;

/// A type that can be compared for equality in constant time.
///
/// Implementors must guarantee that `ct_eq` / `ct_ne` do not introduce any
/// control-flow or memory-access pattern that depends on the compared values.
pub trait CtEq {
    /// Return [`Choice::TRUE`] iff `self` and `other` are equal.
    fn ct_eq(&self, other: &Self) -> Choice;

    /// Return [`Choice::TRUE`] iff `self` and `other` are *not* equal.
    #[inline]
    fn ct_ne(&self, other: &Self) -> Choice {
        !self.ct_eq(other)
    }
}

/// Reduce a byte-difference accumulator to a [`Choice`] ("all bytes equal").
#[inline]
fn eq_reduce(diff: u8) -> Choice {
    // Branchless "is zero" idiom: 0xFF iff `diff == 0`, else 0x00. Works for
    // any accumulator shape (single bit or 0xFF).
    let eq = ((diff | diff.wrapping_neg()) >> 7 ^ 1).wrapping_neg();
    Choice::from_u8_lsb(eq)
}

macro_rules! impl_ct_eq_int {
    ($($t:ty),*) => {
        $(
            impl CtEq for $t {
                #[inline]
                fn ct_eq(&self, other: &Self) -> Choice {
                    let a = self.to_ne_bytes();
                    let b = other.to_ne_bytes();
                    let mut diff = 0u8;
                    for i in 0..a.len() {
                        diff |= a[i] ^ b[i];
                    }
                    eq_reduce(diff)
                }
            }
        )*
    };
}

impl_ct_eq_int!(u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize);

/// Constant-time "not-equal" mask for a `u64` limb: `0xFF` iff `a != b`.
#[inline]
fn neq_mask_u64(a: u64, b: u64) -> u8 {
    // `a ^ b != 0` lowers to a flag-setting compare (no control-flow branch);
    // the resulting 0/1 then broadcasts to a full mask via wrapping negation.
    let ne = (a ^ b) != 0;
    u8::from(ne).wrapping_neg()
}

/// Constant-time equality for two byte slices.
///
/// Returns [`Choice::TRUE`] iff the slices have equal length *and* equal
/// contents. Slice lengths are public, so comparing them is not a leak.
#[inline]
#[must_use]
pub fn ct_eq_bytes(a: &[u8], b: &[u8]) -> Choice {
    let mut diff = (a.len() ^ b.len()) as u8;
    let n = a.len().min(b.len());
    for i in 0..n {
        diff |= a[i] ^ b[i];
    }
    eq_reduce(diff)
}

/// Constant-time equality for two limb slices.
#[inline]
#[must_use]
pub fn ct_eq_limbs(a: &[Limb], b: &[Limb]) -> Choice {
    let mut diff = (a.len() ^ b.len()) as u8;
    let n = a.len().min(b.len());
    for i in 0..n {
        diff |= neq_mask_u64(a[i], b[i]);
    }
    eq_reduce(diff)
}

/// Constant-time equality for two slices of a [`CtEq`] element type.
#[inline]
#[must_use]
pub fn ct_eq_slices<T: CtEq>(a: &[T], b: &[T]) -> Choice {
    let mut diff = (a.len() ^ b.len()) as u8;
    let n = a.len().min(b.len());
    for i in 0..n {
        diff |= a[i].ct_eq(&b[i]).unwrap_u8();
    }
    eq_reduce(diff)
}

/// Constant-time equality between two values of a [`CtEq`] type.
#[inline]
#[must_use]
pub fn ct_eq<T: CtEq>(a: &T, b: &T) -> Choice {
    a.ct_eq(b)
}

/// Constant-time inequality between two values of a [`CtEq`] type.
#[inline]
#[must_use]
pub fn ct_ne<T: CtEq>(a: &T, b: &T) -> Choice {
    a.ct_ne(b)
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ops::Not;

    #[test]
    fn int_eq() {
        assert!(bool::from(ct_eq(&12u64, &12u64)));
        assert!(bool::from(ct_eq(&12u64, &13u64).not()));
        assert!(bool::from(ct_ne(&12u32, &13u32)));
        assert!(bool::from(ct_eq(&0xFFFFu128, &0xFFFFu128)));
        assert!(bool::from(ct_eq(&7usize, &7usize)));
    }

    #[test]
    fn slice_eq() {
        let a = [1u8, 2, 3];
        let b = [1u8, 2, 3];
        let c = [1u8, 2, 4];
        assert!(bool::from(ct_eq_bytes(&a, &b)));
        assert!(bool::from(ct_ne_bytes(&a, &c)));
        assert!(bool::from(ct_ne_bytes(&a, &[1u8, 2])));
        let la = [1u64, 2, 3];
        let lb = [1u64, 2, 3];
        let lc = [1u64, 2, 9];
        assert!(bool::from(ct_eq_limbs(&la, &lb)));
        assert!(bool::from(ct_ne_limbs(&la, &lc)));
    }

    // re-exported helper names for the slice tests above
    use crate::choice::Choice;
    fn ct_ne_bytes(a: &[u8], b: &[u8]) -> Choice {
        ct_eq_bytes(a, b).not()
    }
    fn ct_ne_limbs(a: &[Limb], b: &[Limb]) -> Choice {
        ct_eq_limbs(a, b).not()
    }
}
