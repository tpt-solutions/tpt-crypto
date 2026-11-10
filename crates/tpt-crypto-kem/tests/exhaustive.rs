//! Exhaustive bounded-domain checks for ML-KEM coefficient arithmetic (todo V1).
//!
//! Each check enumerates a domain and compares the result with a reference
//! computed in `i64`. The full-range checks are `#[ignore]`d and run by
//! `cargo xtask exhaustive` in release mode. The quick versions run in every
//! `cargo test`.

use tpt_crypto_kem::poly::{compress, decompress, fqmul, freeze, montgomery_reduce, Q};

const Q64: i64 = Q as i64;
/// 2^16 mod q inverse: the Montgomery factor is R = 2^16.
fn r_inv_mod_q() -> i64 {
    // Find R^{-1} mod q by search (q is small); avoids hard-coding the constant.
    (1..Q64).find(|x| (x * (1 << 16)) % Q64 == 1).unwrap()
}

/// `freeze` returns the canonical residue in [0, q) for every i32.
fn check_freeze(range: impl Iterator<Item = i32>) -> u64 {
    let mut n = 0;
    for x in range {
        let r = freeze(x);
        assert!((0..Q).contains(&r), "freeze({x}) = {r} out of range");
        assert_eq!(
            (x as i64 - r as i64).rem_euclid(Q64),
            0,
            "freeze({x}) = {r} not congruent"
        );
        n += 1;
    }
    n
}

/// `montgomery_reduce(a) ≡ a · R^{-1} (mod q)`, canonical, for `|a| < 2^15 · q`.
/// That is the documented input range: Kyber's reference bound on products of
/// reduced coefficients. Outside it the 16-bit arithmetic wraps and the result is
/// wrong, which the callers never reach.
fn check_montgomery(range: impl Iterator<Item = i32>) -> u64 {
    let rinv = r_inv_mod_q();
    let mut n = 0;
    for a in range {
        let r = montgomery_reduce(a);
        assert!(
            (0..Q).contains(&r),
            "montgomery_reduce({a}) = {r} out of range"
        );
        let expect = (a as i64 * rinv).rem_euclid(Q64);
        assert_eq!(r as i64, expect, "montgomery_reduce({a})");
        n += 1;
    }
    n
}

/// `fqmul(a, b) ≡ a · b · R^{-1} (mod q)` for reduced inputs `|a|, |b| < q`.
fn check_fqmul() -> u64 {
    let rinv = r_inv_mod_q();
    let mut n = 0;
    for a in -(Q - 1)..Q {
        for b in -(Q - 1)..Q {
            let r = fqmul(a, b);
            assert!((0..Q).contains(&r), "fqmul({a},{b}) = {r} out of range");
            let expect = (a as i64 * b as i64 * rinv).rem_euclid(Q64);
            assert_eq!(r as i64, expect, "fqmul({a},{b})");
            n += 1;
        }
    }
    n
}

/// Every `(x, d)` the scheme uses: `compress` lands in `[0, 2^d)`, `decompress`
/// in `[0, q)`, `decompress` is a right inverse of `compress` on `[0, 2^d)`, and
/// the round trip moves `x` by at most the rounding bound `⌈q / 2^(d+1)⌉`.
fn check_compress() -> u64 {
    let mut n = 0;
    for d in [1usize, 4, 5, 10, 11] {
        let top = 1i32 << d;
        for x in 0..Q {
            let c = compress(x, d);
            assert!((0..top).contains(&c), "compress({x},{d}) = {c}");
            let back = decompress(c, d);
            assert!((0..Q).contains(&back), "decompress({c},{d}) = {back}");
            // Circular distance between x and back, modulo q.
            let diff = (x as i64 - back as i64).rem_euclid(Q64);
            let dist = diff.min(Q64 - diff);
            let bound = (Q64 + (1i64 << (d + 1)) - 1) >> (d + 1);
            assert!(
                dist <= bound,
                "round trip x={x} d={d}: moved {dist} > {bound}"
            );
            n += 1;
        }
        for y in 0..top {
            let x = decompress(y, d);
            assert_eq!(compress(x, d), y, "compress(decompress({y},{d}))");
        }
    }
    n
}

#[test]
fn freeze_quick_range() {
    assert_eq!(check_freeze(-2_000_000..=2_000_000), 4_000_001);
}

#[test]
fn montgomery_quick_range() {
    let bound = (1i32 << 15) * Q;
    let n = check_montgomery((-bound / 64..=bound / 64).step_by(1));
    assert!(n > 0);
}

#[test]
fn fqmul_is_exhaustive_over_reduced_inputs() {
    assert_eq!(check_fqmul(), (2 * (Q as u64) - 1).pow(2));
}

#[test]
fn compress_round_trip_is_exhaustive() {
    assert!(check_compress() > 0);
}

#[test]
#[ignore = "all 2^32 i32 values; run with `cargo xtask exhaustive`"]
fn freeze_full_i32_domain() {
    assert_eq!(check_freeze(i32::MIN..=i32::MAX), 1u64 << 32);
}

#[test]
#[ignore = "all |a| < 2^15 * q; run with `cargo xtask exhaustive`"]
fn montgomery_full_documented_domain() {
    let bound = (1i32 << 15) * Q;
    check_montgomery(-bound + 1..bound);
}
