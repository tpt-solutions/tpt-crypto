//! Exhaustive bounded-domain checks for ML-DSA polynomial arithmetic (todo V1).
//!
//! Each check enumerates a documented domain and compares against a reference in
//! `i64`. Quick versions run in every `cargo test`. The full-range versions are
//! `#[ignore]`d and run by `cargo xtask exhaustive` in release mode.

use tpt_crypto_sig::poly::{
    decompose_impl, polyeta_pack, polyeta_unpack, polyt0_pack, polyt0_unpack, polyt1_pack,
    polyt1_unpack, polyz_pack, polyz_unpack, Poly, N, Q,
};

const Q64: i64 = Q as i64;

/// Congruence mod q, as a residue in [0, q).
fn residue(x: i64) -> i64 {
    x.rem_euclid(Q64)
}

/// `Poly::reduce` and `Poly::canonicalize` on 256 consecutive values at a time.
///
/// Documented domain of `reduce32` (the Dilithium reference bound): `a` must not
/// exceed `i32::MAX - 2^22`, because `a + 2^22` would overflow. Everything the
/// callers pass is far inside that range. `reduce` must return a value congruent
/// to the input with `|r| < q`, and `canonicalize` must return the residue in
/// `[0, q)`.
fn check_reduce_range(lo: i64, hi: i64) -> u64 {
    let mut n = 0u64;
    let mut start = lo;
    while start <= hi {
        let mut p = Poly::ZERO;
        let count = (hi - start + 1).min(N as i64);
        for i in 0..count as usize {
            p.coeffs[i] = (start + i as i64) as i32;
        }
        let input = p;
        p.reduce();
        for i in 0..count as usize {
            let x = input.coeffs[i] as i64;
            let r = p.coeffs[i] as i64;
            assert_eq!(residue(r), residue(x), "reduce({x}) = {r} not congruent");
            assert!(r.abs() < Q64, "reduce({x}) = {r} out of (-q, q)");
        }
        let mut c = p;
        c.canonicalize();
        for i in 0..count as usize {
            let r = p.coeffs[i] as i64;
            let c_val = c.coeffs[i] as i64;
            assert_eq!(c_val, residue(r), "canonicalize({r}) = {c_val}");
            n += 1;
        }
        start += count;
    }
    n
}

/// `decompose_impl` on every canonical `a ∈ [0, q)`, for both gamma2 values.
///
/// Checks: `a ≡ r1·2γ₂ + r0 (mod q)`, `r1` in its range, and `r0` in
/// `(-γ₂, γ₂]`, except for the wrap case handled by the reference, where
/// `r1·2γ₂ = q - 1` and the result is `(0, r0 - 1)`.
fn check_decompose(gamma2: i32, r1_max: i32) -> u64 {
    for a in 0..Q {
        let (r1, r0) = decompose_impl(gamma2, a);
        assert!((0..=r1_max).contains(&r1), "decompose({a}) r1 = {r1}");
        // The wrap case returns r0 - 1, which can step just below -γ2.
        let g = gamma2 as i64;
        assert!(
            (-g - 1..=g).contains(&(r0 as i64)),
            "decompose({a}) r0 = {r0} outside [-γ2-1, γ2]"
        );
        assert_eq!(
            residue(r1 as i64 * 2 * g + r0 as i64),
            residue(a as i64),
            "decompose({a}): r1={r1} r0={r0} does not rebuild a"
        );
    }
    Q as u64
}

/// `Poly::power2round_into` on every canonical `a ∈ [0, q)`, `d = 13`.
///
/// The reference contract: `a = t1·2^d + t0` exactly, with `t0` in `(-2^(d-1), 2^(d-1)]`
/// and `t1` in `[0, (q-1)/2^d]`.
fn check_power2round() -> u64 {
    let mut n = 0u64;
    let mut start = 0i64;
    while start < Q64 {
        let mut p = Poly::ZERO;
        let count = (Q64 - start).min(N as i64);
        for i in 0..count as usize {
            p.coeffs[i] = (start + i as i64) as i32;
        }
        let mut t1 = Poly::ZERO;
        let mut t0 = Poly::ZERO;
        p.power2round_into(&mut t1, &mut t0);
        for i in 0..count as usize {
            let a = start + i as i64;
            let hi = t1.coeffs[i] as i64;
            let lo = t0.coeffs[i] as i64;
            assert_eq!(hi * (1 << 13) + lo, a, "power2round({a})");
            assert!((-(1 << 12) + 1..=(1 << 12)).contains(&lo), "t0({a}) = {lo}");
            assert!((0..=(Q64 - 1) >> 13).contains(&hi), "t1({a}) = {hi}");
            n += 1;
        }
        start += count;
    }
    n
}

/// Every value of each coefficient, at every position, round-trips through a
/// packer. The packers mix coefficients across byte boundaries, so testing one
/// value at one position at a time catches bit-offset bugs.
fn check_pack_per_position<const B: usize>(
    values: impl Iterator<Item = i32> + Clone,
    pack: impl Fn(&Poly, &mut [u8]),
    unpack: impl Fn(&[u8]) -> Option<Poly>,
) -> u64 {
    let mut n = 0u64;
    for v in values {
        for pos in 0..N {
            let mut p = Poly::ZERO;
            p.coeffs[pos] = v;
            let mut buf = vec![0u8; B];
            pack(&p, &mut buf);
            let back = unpack(&buf).expect("unpack accepts packer output");
            assert_eq!(back.coeffs[pos], v, "round trip of {v} at position {pos}");
            n += 1;
        }
    }
    n
}

#[test]
fn reduce_quick_range() {
    // A window around zero and around the reduce32 boundary of the documented domain.
    let bound = i32::MAX as i64 - (1 << 22);
    check_reduce_range(-100_000, 100_000);
    check_reduce_range(bound - 100_000, bound);
    check_reduce_range(-bound - 100_000, -bound);
}

#[test]
fn decompose_is_exhaustive_over_canonical_inputs() {
    // gamma2 = (q-1)/88 (ML-DSA-44 / -87 path, r1 in 0..=43) and (q-1)/32 (ML-DSA-65, r1 in 0..=15).
    assert_eq!(check_decompose(95_232, 43), Q as u64);
    assert_eq!(check_decompose(261_888, 15), Q as u64);
}

#[test]
fn power2round_is_exhaustive_over_canonical_inputs() {
    assert_eq!(check_power2round(), Q as u64);
}

#[test]
fn packers_round_trip_every_value_per_position() {
    // eta = 2 and 4: coefficients in [-eta, eta].
    for eta in [2i32, 4] {
        let bytes = if eta == 2 { 96 } else { 128 };
        let n = check_pack_per_position::<128>(
            -eta..=eta,
            |p, out| polyeta_pack(eta, p, &mut out[..bytes]),
            |buf| polyeta_unpack(eta, &buf[..bytes]),
        );
        assert_eq!(n, (2 * eta as u64 + 1) * N as u64);
    }
    // t1: 10-bit unsigned.
    let n = check_pack_per_position::<320>(
        0..1024,
        |p, out| polyt1_pack(p, &mut out[..320]),
        |buf| polyt1_unpack(&buf[..320]),
    );
    assert_eq!(n, 1024 * N as u64);
}

#[test]
#[ignore = "all 2^13 t0 values at every position; run with `cargo xtask exhaustive`"]
fn packers_t0_every_value() {
    // t0 is in (-2^12, 2^12]: 13 bits.
    let values = -(1 << 12) + 1..=(1 << 12);
    let n = check_pack_per_position::<416>(
        values,
        |p, out| polyt0_pack(p, &mut out[..416]),
        |buf| polyt0_unpack(&buf[..416]),
    );
    assert_eq!(n, (1u64 << 13) * N as u64);
}

#[test]
#[ignore = "z packers for gamma1 = 2^17 and 2^19 at every value and position; run with `cargo xtask exhaustive`"]
fn packers_z_every_value() {
    for (gamma1, bytes) in [(1i32 << 17, 576usize), (1 << 19, 640)] {
        let values = -(gamma1 - 1)..=gamma1;
        let n = check_pack_per_position::<640>(
            values,
            |p, out| polyz_pack(gamma1, p, &mut out[..bytes]),
            |buf| polyz_unpack(gamma1, &buf[..bytes]),
        );
        // The range -(gamma1-1)..=gamma1 has 2*gamma1 values.
        assert_eq!(n, (2 * gamma1 as u64) * N as u64);
    }
}

#[test]
#[ignore = "all 2^32 i32 inputs in the reduce32 domain; run with `cargo xtask exhaustive`"]
fn reduce_full_documented_domain() {
    let bound = i32::MAX as i64 - (1 << 22);
    let n = check_reduce_range(-bound, bound);
    assert_eq!(n, 2 * bound as u64 + 1);
}
