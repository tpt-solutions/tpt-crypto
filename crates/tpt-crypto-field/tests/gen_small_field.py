"""Derive FieldParams constants for small primes (independent of the Rust code)."""

PRIMES = [
    ("SmallP97", 97),
    ("SmallP251", 251),
    ("SmallP65521", 65521),
    ("Prime64", 2**64 - 59),
]


def is_prime(n):
    if n < 2:
        return False
    i = 2
    while i * i <= n:
        if n % i == 0:
            return False
        i += 1
    return True


def trailing_zeros(n):
    s = 0
    while n % 2 == 0:
        n //= 2
        s += 1
    return s


def consts(p):
    assert p == 2**64 - 59 or is_prime(p), p
    S = trailing_zeros(p - 1)
    one_mont = (2**64) % p
    r2 = (2**128) % p
    mu = (-pow(p, -1, 2**64)) % 2**64
    return S, one_mont, r2, mu


def limbs(v):
    return [(v >> (64 * i)) & (2**64 - 1) for i in range(6)]


def arr(vals):
    return "[" + ", ".join("0x%016x" % x for x in vals) + "]"


out = []
out.append("""//! Small-scope field verification (todo V2).
//!
//! The field code is generic over `FieldParams`, so these tests instantiate it
//! with small primes whose arithmetic can be enumerated. Every operation is checked
//! against a `u128` reference over the whole domain for the small primes, and over
//! boundary values plus a deterministic sample for the 64-bit prime `2^64 - 59`,
//! whose pairs cannot be enumerated.
//!
//! The Montgomery constants (`S`, `ONE_MONT`, `R2`, `MU`) are computed by
//! `gen_small_field.py` (independent of the crate's compile-time derivation). The
//! checks below rely on them being right, so a wrong constant shows up as an
//! arithmetic failure.

use tpt_crypto_field::{FieldElement, FieldParams, MAX_LIMBS};

macro_rules! small_params {
    ($name:ident, $p:expr, $s:expr, $one:expr, $r2:expr, $mu:expr) => {
        #[derive(Copy, Clone, Default, Eq, PartialEq, Debug)]
        struct $name;
        impl FieldParams for $name {
            const LIMBS: usize = 1;
            const MODULUS: [u64; MAX_LIMBS] = $p;
            const S: u32 = $s;
            const ONE_MONT: [u64; MAX_LIMBS] = $one;
            const R2: [u64; MAX_LIMBS] = $r2;
            const MU: u64 = $mu;
        }
    };
}
""")

for name, p in PRIMES:
    S, one, r2, mu = consts(p)
    out.append("small_params!(%s, %s, %d, %s, %s, 0x%016x);" % (
        name, arr(limbs(p)), S, arr(limbs(one)), arr(limbs(r2)), mu))
    out.append("")

out.append("""
/// Canonical value of a field element, as a `u128` (its low limb is enough for the
/// primes here, but both limbs are checked for the 64-bit prime).
fn value<P: FieldParams>(x: &FieldElement<P>) -> u128 {
    let l = x.to_integer();
    assert!(l[1..].iter().all(|&w| w == 0), "value out of single-limb range");
    l[0] as u128
}

fn fe<P: FieldParams>(v: u128) -> FieldElement<P> {
    FieldElement::<P>::from_limbs([v as u64, (v >> 64) as u64, 0, 0, 0, 0])
}

fn mulmod(a: u128, b: u128, p: u128) -> u128 {
    // p < 2^64 so the product fits in u128.
    (a * b) % p
}

/// Check one pair (a, b) against the reference for every operation.
fn check_pair<P: FieldParams>(p: u128, a: u128, b: u128) {
    let x = fe::<P>(a);
    let y = fe::<P>(b);
    assert_eq!(value(&x.add(&y)), (a + b) % p, "add {a} {b}");
    assert_eq!(value(&x.sub(&y)), (a + p - b) % p, "sub {a} {b}");
    assert_eq!(value(&x.mul(&y)), mulmod(a, b, p), "mul {a} {b}");
    assert_eq!(value(&x.square()), mulmod(a, a, p), "square {a}");
    assert_eq!(value(&x.neg()), (p - a) % p, "neg {a}");
}

fn check_all_pairs<P: FieldParams>(p: u128) -> u64 {
    let mut n = 0u64;
    for a in 0..p {
        let x = fe::<P>(a);
        assert_eq!(value(&x), a, "round trip of {a}");
        for b in 0..p {
            check_pair::<P>(p, a, b);
            n += 1;
        }
    }
    n
}

fn check_inverses<P: FieldParams>(p: u128) -> u64 {
    let mut n = 0u64;
    for a in 1..p {
        let inv = fe::<P>(a).invert();
        assert!(inv.is_some().into_bool(), "{a} should be invertible");
        let i = inv.unwrap();
        assert_eq!(value(&i), modpow(a, p - 2, p), "inverse of {a}");
        assert_eq!(value(&fe::<P>(a).mul(&i)), 1, "a * a^-1 for {a}");
        n += 1;
    }
    assert!(!fe::<P>(0).invert().is_some().into_bool(), "0 has no inverse");
    n
}

fn modpow(mut base: u128, mut exp: u128, m: u128) -> u128 {
    let mut acc = 1u128 % m;
    base %= m;
    while exp > 0 {
        if exp & 1 == 1 {
            acc = mulmod(acc, base, m);
        }
        base = mulmod(base, base, m);
        exp >>= 1;
    }
    acc
}

fn check_bytes<P: FieldParams>(p: u128) {
    for a in [0u128, 1, 2, p / 2, p - 2, p - 1] {
        let x = fe::<P>(a);
        let bytes = x.to_bytes();
        let back = FieldElement::<P>::from_bytes(&bytes);
        assert!(back.is_some().into_bool(), "canonical {a} must decode");
        assert_eq!(value(&back.unwrap()), a);
    }
    // p itself is not canonical: must be rejected.
    let mut enc = [0u8; MAX_LIMBS * 8];
    // Big-endian, significant limb last (see `to_bytes`).
    enc[MAX_LIMBS * 8 - 8..].copy_from_slice(&(p as u64).to_be_bytes());
    assert!(!FieldElement::<P>::from_bytes(&enc).is_some().into_bool(), "p must be rejected");
}

#[test]
fn small_p97_all_operations_exhaustive() {
    let p = 97u128;
    assert_eq!(check_all_pairs::<SmallP97>(p), (p * p) as u64);
    assert_eq!(check_inverses::<SmallP97>(p), (p - 1) as u64);
    check_bytes::<SmallP97>(p);
}

#[test]
fn small_p251_all_operations_exhaustive() {
    let p = 251u128;
    assert_eq!(check_all_pairs::<SmallP251>(p), (p * p) as u64);
    assert_eq!(check_inverses::<SmallP251>(p), (p - 1) as u64);
    check_bytes::<SmallP251>(p);
}

#[test]
#[ignore = "all 65521^2 pairs; run with `cargo xtask exhaustive`"]
fn small_p65521_all_operations_exhaustive() {
    let p = 65521u128;
    assert_eq!(check_all_pairs::<SmallP65521>(p), (p * p) as u64);
    assert_eq!(check_inverses::<SmallP65521>(p), (p - 1) as u64);
    check_bytes::<SmallP65521>(p);
}

#[test]
fn prime64_boundary_and_sampled_operations() {
    // 2^64 - 59 is prime and fills one limb completely: the carry and borrow edges
    // of the single-limb code sit at its top. Pairs cannot be enumerated, so check
    // every edge value against every other, plus a deterministic sample.
    let p = (1u128 << 64) - 59;
    let edges = [0u128, 1, 2, 3, 59, 60, p / 2, p / 2 + 1, p - 3, p - 2, p - 1];
    for &a in &edges {
        for &b in &edges {
            check_pair::<Prime64>(p, a, b);
        }
    }
    let mut s = 0x9e37_79b9_7f4a_7c15u128;
    for _ in 0..200_000 {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let a = (s >> 3) % p;
        let b = (s.rotate_left(29) >> 3) % p;
        check_pair::<Prime64>(p, a, b);
    }
    assert_eq!(check_inverses_sampled::<Prime64>(p), 200);
    check_bytes::<Prime64>(p);
}

fn check_inverses_sampled<P: FieldParams>(p: u128) -> u64 {
    let mut n = 0u64;
    let mut s = 0x0123_4567_89ab_cdefu128;
    for _ in 0..200 {
        s = s.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        let a = 1 + (s >> 3) % (p - 1);
        let i = fe::<P>(a).invert().unwrap();
        assert_eq!(value(&fe::<P>(a).mul(&i)), 1, "a * a^-1 for {a}");
        n += 1;
    }
    n
}
""")

import os
path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "small_field.rs")
with open(path, "w", encoding="utf-8", newline="\n") as f:
    f.write("\n".join(out))
print("wrote", path)
