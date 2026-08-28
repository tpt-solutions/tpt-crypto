//! Portable, constant-time implementations of [`CtEq`] / [`ConstantTimeSelect`].
//!
//! These are the foundation-layer algorithms: no `unsafe`, no secret-dependent
//! branch or index. `tpt-crypto-ct` supplies architecture-optimized equivalents
//! and re-exports the same traits.

use crate::choice::Choice;
use crate::traits::{ConstantTimeSelect, CtEq};

/// `Choice::TRUE` iff `a == b`, computed with branch-free arithmetic.
#[inline]
fn ct_eq_u8(a: u8, b: u8) -> Choice {
    // `diff` is 0 iff equal. `diff | (diff - 1)` is 0 iff `diff == 0`; otherwise
    // it is nonzero, so `(... >> 7) ^ 1` is `1` (TRUE) iff `diff == 0`.
    let diff = a ^ b;
    let is_zero = (diff | diff.wrapping_sub(1)) >> 7;
    Choice::from_u8_lsb(is_zero ^ 1)
}

/// Select `a` if `c` is true, else `b`, in constant time.
#[inline]
fn ct_select_u8(c: Choice, a: u8, b: u8) -> u8 {
    // `c.to_u8()` is `0x00` (false) or `0x01` (true); `wrapping_sub` turns that
    // into a `0x00`/`0xff` mask without branching.
    let m = 0u8.wrapping_sub(c.to_u8());
    (a & m) | (b & !m)
}

macro_rules! impl_ct_int {
    ($($t:ty),* $(,)?) => {$(
        impl CtEq for $t {
            #[inline]
            fn ct_eq(&self, other: &Self) -> Choice {
                let diff = (*self ^ *other).to_ne_bytes();
                let mut acc: u8 = 0;
                let mut i = 0;
                while i < diff.len() {
                    acc |= diff[i];
                    i += 1;
                }
                ct_eq_u8(0, acc)
            }
        }

        impl ConstantTimeSelect for $t {
            #[inline]
            fn ct_select(a: &Self, b: &Self, c: Choice) -> Self {
                let av = a.to_ne_bytes();
                let bv = b.to_ne_bytes();
                let mut out = [0u8; core::mem::size_of::<Self>()];
                let n = out.len();
                let mut i = 0;
                while i < n {
                    out[i] = ct_select_u8(c, av[i], bv[i]);
                    i += 1;
                }
                Self::from_ne_bytes(out)
            }
        }
    )*};
}

impl_ct_int!(u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize);

impl CtEq for [u8] {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        // Lengths are public; fold any mismatch into `diff` so the result is 0
        // (unequal) when lengths differ.
        let mut diff: u8 = (self.len() ^ other.len()) as u8;
        let n = self.len().min(other.len());
        let mut i = 0;
        while i < n {
            diff |= self[i] ^ other[i];
            i += 1;
        }
        ct_eq_u8(diff, 0)
    }
}

impl CtEq for str {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.as_bytes().ct_eq(other.as_bytes())
    }
}

#[cfg(test)]
mod tests {
use super::*;
use crate::traits::ct_select;

    #[test]
    fn int_eq_and_select() {
        for a in [0u64, 1, 42, u64::MAX] {
            for b in [0u64, 1, 42, u64::MAX] {
                assert_eq!(a.ct_eq(&b).is_true(), a == b);
                assert_eq!(ct_select(&a, &b, Choice::TRUE), a);
                assert_eq!(ct_select(&a, &b, Choice::FALSE), b);
            }
        }
    }

    #[test]
    fn slice_eq() {
        assert!(<[u8]>::ct_eq(b"abc", b"abc").is_true());
        assert!(!<[u8]>::ct_eq(b"abc", b"abd").is_true());
        assert!(!<[u8]>::ct_eq(b"abc", b"ab").is_true());
    }

    #[test]
    fn str_eq() {
        assert!("hello".ct_eq("hello").is_true());
        assert!(!"hello".ct_eq("world").is_true());
    }
}









#[test]
fn dbg7() { extern crate std; use std::eprintln; eprintln!("u8(0,0)={} u8(0,ff)={}", ct_eq_u8(0,0).to_u8(), ct_eq_u8(0,255).to_u8()); eprintln!("u64(0,0)={} is_true={}", (0u64).ct_eq(&0u64).to_u8(), (0u64).ct_eq(&0u64).is_true()); }

