//! Property tests for the constant-time selection / comparison primitives.
//!
//! The central law exercised here is
//!
//! ```text
//! ct_select(cond, a, b) == if cond { a } else { b }
//! ```
//!
//! verified uniformly over `c`, `a`, `b` for `u8`, `u64`, and `usize`.

use proptest::prelude::*;
use tpt_crypto_ct::choice::Choice;
use tpt_crypto_ct::cmp::{ct_eq, ct_ne};
use tpt_crypto_ct::select::{cmov, cswap, ct_select};

proptest! {
    #[test]
    fn ct_select_u8_law(c in any::<u8>(), a in any::<u8>(), b in any::<u8>()) {
        let cond = Choice::from_u8_lsb(c);
        let got = ct_select(cond, a, b);
        let want = if cond.is_true() { a } else { b };
        prop_assert_eq!(got, want);
    }

    #[test]
    fn ct_select_u64_law(c in any::<u64>(), a in any::<u64>(), b in any::<u64>()) {
        let cond = Choice::from_u8_lsb((c & 1) as u8);
        let got = ct_select(cond, a, b);
        let want = if cond.is_true() { a } else { b };
        prop_assert_eq!(got, want);
    }

    #[test]
    fn ct_select_usize_law(c in any::<usize>(), a in any::<usize>(), b in any::<usize>()) {
        let cond = Choice::from_u8_lsb((c & 1) as u8);
        let got = ct_select(cond, a, b);
        let want = if cond.is_true() { a } else { b };
        prop_assert_eq!(got, want);
    }

    #[test]
    fn cmov_law(c in any::<u8>(), a in any::<u64>(), b in any::<u64>()) {
        let cond = Choice::from_u8_lsb(c);
        let mut dst = a;
        cmov(cond, &mut dst, &b);
        let want = if cond.is_true() { b } else { a };
        prop_assert_eq!(dst, want);
    }

    #[test]
    fn cswap_law(c in any::<u8>(), a in any::<u64>(), b in any::<u64>()) {
        let cond = Choice::from_u8_lsb(c);
        let (mut x, mut y) = (a, b);
        cswap(cond, &mut x, &mut y);
        if cond.is_true() {
            prop_assert_eq!((x, y), (b, a));
        } else {
            prop_assert_eq!((x, y), (a, b));
        }
    }

    #[test]
    fn ct_eq_law(a in any::<u64>(), b in any::<u64>()) {
        prop_assert_eq!(bool::from(ct_eq(&a, &b)), a == b);
        prop_assert_eq!(bool::from(ct_ne(&a, &b)), a != b);
    }
}
