//! Exhaustive bounded-domain checks for the constant-time primitives (todo V1).
//!
//! Each check enumerates every input in its domain and compares the result with a
//! plain reference. These are exhaustive over the stated domain, not formal proofs.
//!
//! * `u8`: every `(a, b)` pair and both conditions. Runs in every `cargo test`.
//! * `u16`: every `(a, b)` pair, `#[ignore]`d because it is about 8.6 billion
//!   pairs. Run it with `cargo xtask exhaustive` (release mode).

use tpt_crypto_ct::{cswap, ct_eq, ct_ne, ct_select, Choice, CtEq};

fn choice(b: bool) -> Choice {
    Choice::from_u8_lsb(b as u8)
}

macro_rules! exhaustive_select_swap_eq {
    ($name:ident, $t:ty, $domain:expr) => {
        /// Checks ct_select, cswap, ct_eq and ct_ne against plain references over
        /// the whole domain. Returns the number of `(a, b)` pairs checked.
        fn $name() -> u64 {
            let mut pairs = 0u64;
            for a in $domain {
                for b in $domain {
                    pairs += 1;
                    for cond in [false, true] {
                        // ct_select: cond ? a : b
                        let sel = ct_select(choice(cond), a, b);
                        assert_eq!(
                            sel,
                            if cond { a } else { b },
                            "select cond={cond} a={a} b={b}"
                        );

                        // cswap: swap when cond, otherwise leave both alone.
                        let (mut x, mut y) = (a, b);
                        cswap(choice(cond), &mut x, &mut y);
                        let (ex, ey) = if cond { (b, a) } else { (a, b) };
                        assert_eq!((x, y), (ex, ey), "cswap cond={cond} a={a} b={b}");
                    }
                    // ct_eq / ct_ne against ==.
                    assert_eq!(ct_eq(&a, &b).is_true(), a == b, "eq a={a} b={b}");
                    assert_eq!(ct_ne(&a, &b).is_true(), a != b, "ne a={a} b={b}");
                    assert_eq!(a.ct_eq(&b).is_true(), a == b, "CtEq a={a} b={b}");
                }
            }
            pairs
        }
    };
}

exhaustive_select_swap_eq!(check_u8, u8, 0u8..=255);
exhaustive_select_swap_eq!(check_u16, u16, 0u16..=u16::MAX);

#[test]
fn u8_select_swap_eq_exhaustive() {
    // 256 * 256 pairs, both conditions.
    assert_eq!(check_u8(), 256 * 256);
}

#[test]
#[ignore = "about 8.6e9 pairs; run with `cargo xtask exhaustive`"]
fn u16_select_swap_eq_exhaustive() {
    assert_eq!(check_u16(), 65_536 * 65_536);
}
