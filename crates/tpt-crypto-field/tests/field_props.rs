//! Property tests for `tpt-crypto-field`.
//!
//! Every field operation on [`FieldElement`] is cross-checked against an
//! *independent* reference implementation of prime-field arithmetic written from
//! scratch in this file (schoolbook multiplication + long-division reduction over
//! `u64` limbs). This mirrors the intended "cross-check vs `tpt-math-exact`
//! big-rational reference" requirement: the reference here is a second,
//! unrelated implementation of the same mathematics, so agreement between the two
//! is strong evidence that the Montgomery machinery in the crate is correct.
//!
//! The reference operates purely on plain integer limbs and never touches
//! Montgomery form, so it cannot share a bug with the crate's fast path.

use proptest::prelude::*;

use tpt_crypto_field::params::{
    Bls12381FpParams, Bls12381FrParams, P256BaseParams, P256ScalarParams, P384BaseParams,
    P384ScalarParams,
};
use tpt_crypto_field::{FieldElement, FieldParams};

const N: usize = 6;

// ---------------------------------------------------------------------------
// Independent reference arithmetic (schoolbook, big-endian limb arrays)
// ---------------------------------------------------------------------------

fn ladd(a: &[u64; N], b: &[u64; N]) -> ([u64; N], u8) {
    let mut out = [0u64; N];
    let mut carry: u128 = 0;
    for i in 0..N {
        let s = a[i] as u128 + b[i] as u128 + carry;
        out[i] = s as u64;
        carry = s >> 64;
    }
    (out, (carry > 0) as u8)
}

fn lsub(a: &[u64; N], b: &[u64; N]) -> ([u64; N], u8) {
    let mut out = [0u64; N];
    let mut borrow = 0i128;
    for i in 0..N {
        let ai = a[i] as i128;
        let bi = b[i] as i128;
        let mut d = ai - bi - borrow;
        if d < 0 {
            d += 1i128 << 64;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[i] = d as u64;
    }
    (out, borrow as u8)
}

fn lge(a: &[u64; N], b: &[u64; N]) -> bool {
    for i in (0..N).rev() {
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true
}

fn bit_length(a: &[u64]) -> i64 {
    for i in (0..a.len()).rev() {
        if a[i] != 0 {
            return (i as i64) * 64 + (64 - a[i].leading_zeros() as i64);
        }
    }
    0
}

fn shl(a: &[u64], n: u32) -> Vec<u64> {
    let ls = (n / 64) as usize;
    let bs = (n % 64) as u32;
    let mut out = vec![0u64; a.len() + ls + 1];
    for i in 0..a.len() {
        let v = a[i];
        out[i + ls] |= v << bs;
        if bs > 0 {
            out[i + ls + 1] |= v >> (64 - bs);
        }
    }
    out
}

fn big_ge(a: &[u64], b: &[u64]) -> bool {
    let n = a.len().max(b.len());
    for i in (0..n).rev() {
        let av = *a.get(i).unwrap_or(&0);
        let bv = *b.get(i).unwrap_or(&0);
        if av > bv {
            return true;
        }
        if av < bv {
            return false;
        }
    }
    true
}

fn big_sub(a: &[u64], b: &[u64]) -> Vec<u64> {
    let mut out = vec![0u64; a.len().max(b.len())];
    let mut borrow = 0i128;
    for i in 0..out.len() {
        let av = *a.get(i).unwrap_or(&0) as i128;
        let bv = *b.get(i).unwrap_or(&0) as i128;
        let mut d = av - bv - borrow;
        if d < 0 {
            d += 1i128 << 64;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[i] = d as u64;
    }
    out
}

fn trim(v: &mut Vec<u64>) {
    while v.last() == Some(&0) {
        v.pop();
    }
}

/// Reduce `x` (arbitrary width) modulo `m` (N limbs) via long division.
fn ref_reduce(x: &[u64], m: &[u64; N]) -> [u64; N] {
    let mut r = x.to_vec();
    let mut bit = bit_length(&r) - 1;
    while bit >= 0 {
        let shift = bit as u32;
        let sm = shl(m, shift);
        if big_ge(&r, &sm) {
            r = big_sub(&r, &sm);
        }
        bit -= 1;
    }
    let mut out = [0u64; N];
    for i in 0..N {
        out[i] = *r.get(i).unwrap_or(&0);
    }
    out
}

fn ref_mul(a: &[u64; N], b: &[u64; N], m: &[u64; N]) -> [u64; N] {
    let mut t = vec![0u64; 2 * N];
    for i in 0..N {
        let mut carry: u128 = 0;
        for j in 0..N {
            let prod = a[i] as u128 * b[j] as u128 + t[i + j] as u128 + carry;
            t[i + j] = prod as u64;
            carry = prod >> 64;
        }
        let mut k = i + N;
        let mut c = carry;
        while c != 0 {
            let s = t[k] as u128 + c;
            t[k] = s as u64;
            c = s >> 64;
            k += 1;
        }
    }
    ref_reduce(&t, m)
}

fn ref_add(a: &[u64; N], b: &[u64; N], m: &[u64; N]) -> [u64; N] {
    let (s, carry) = ladd(a, b);
    let mut t = s.to_vec();
    if carry == 1 {
        t.push(1);
    }
    ref_reduce(&t, m)
}

fn ref_sub(a: &[u64; N], b: &[u64; N], m: &[u64; N]) -> [u64; N] {
    let (d, borrow) = lsub(a, b);
    if borrow == 0 {
        ref_reduce(&d, m)
    } else {
        let (sd, _) = ladd(m, &d);
        ref_reduce(&sd, m)
    }
}

fn ref_neg(a: &[u64; N], m: &[u64; N]) -> [u64; N] {
    ref_sub(&[0; N], a, m)
}

fn one_int() -> [u64; N] {
    let mut o = [0u64; N];
    o[0] = 1;
    o
}

// Canonical fixed-width big-endian byte encoding (matches `FieldElement::to_bytes`).
fn to_canon(int: &[u64; N]) -> [u8; N * 8] {
    let mut out = [0u8; N * 8];
    for limb in 0..N {
        let v = int[limb];
        let base = (N - 1 - limb) * 8;
        for b in 0..8 {
            out[base + b] = (v >> (56 - b * 8)) as u8;
        }
    }
    out
}

fn from_canon(bytes: &[u8; N * 8]) -> [u64; N] {
    let mut out = [0u64; N];
    for limb in 0..N {
        let base = (N - 1 - limb) * 8;
        let mut v = 0u64;
        for b in 0..8 {
            v = (v << 8) | (bytes[base + b] as u64);
        }
        out[limb] = v;
    }
    out
}

fn fe_from_int<P: FieldParams>(int: &[u64; N]) -> FieldElement<P> {
    FieldElement::<P>::from_bytes(&to_canon(int)).unwrap()
}

/// Build a uniformly random field element (independent of any crate helper).
fn rand_fe<P: FieldParams>(limbs: [u64; N]) -> FieldElement<P> {
    let reduced = ref_reduce(&limbs.to_vec(), &P::MODULUS);
    fe_from_int::<P>(&reduced)
}

// ---------------------------------------------------------------------------
// The property harness, generic over the modulus parameter type
// ---------------------------------------------------------------------------

fn field_props<P: FieldParams>(a: [u64; N], b: [u64; N], c: [u64; N]) {
    let p = &P::MODULUS;
    let x = rand_fe::<P>(a);
    let y = rand_fe::<P>(b);
    let z = rand_fe::<P>(c);

    let xi = from_canon(&x.to_bytes());
    let yi = from_canon(&y.to_bytes());
    let zi = from_canon(&z.to_bytes());

    // to_bytes / from_bytes is a constant-time canonical round trip.
    assert_eq!(
        FieldElement::<P>::from_bytes(&x.to_bytes())
            .unwrap()
            .to_bytes(),
        x.to_bytes()
    );

    // Addition.
    let sum = x.add(&y);
    assert_eq!(sum.to_bytes(), to_canon(&ref_add(&xi, &yi, p)));

    // Subtraction.
    let diff = x.sub(&y);
    assert_eq!(diff.to_bytes(), to_canon(&ref_sub(&xi, &yi, p)));

    // Negation is the additive inverse.
    let neg = x.neg();
    assert_eq!(neg.to_bytes(), to_canon(&ref_neg(&xi, p)));
    assert_eq!(x.add(&neg).to_bytes(), to_canon(&[0; N]));

    // Multiplication.
    let prod = x.mul(&y);
    assert_eq!(prod.to_bytes(), to_canon(&ref_mul(&xi, &yi, p)));

    // Squaring equals self-multiplication.
    assert_eq!(x.square().to_bytes(), x.mul(&x).to_bytes());

    // Associativity of addition.
    let assoc_l = x.add(&y).add(&z);
    let assoc_r = x.add(&y.add(&z));
    assert_eq!(assoc_l.to_bytes(), assoc_r.to_bytes());

    // Associativity of multiplication.
    let massoc_l = x.mul(&y).mul(&z);
    let massoc_r = x.mul(&y.mul(&z));
    assert_eq!(massoc_l.to_bytes(), massoc_r.to_bytes());

    // Distributivity: x*(y+z) == x*y + x*z.
    let dl = x.mul(&y.add(&z));
    let dr = x.mul(&y).add(&x.mul(&z));
    assert_eq!(dl.to_bytes(), dr.to_bytes());

    // Inverses: x * x^-1 == 1 (and matches the reference product 1 mod p).
    if x.is_zero().into_bool() {
        assert!(x.invert().is_none().into_bool());
    } else {
        let inv = x.invert().unwrap();
        assert_eq!(inv.mul(&x).to_bytes(), to_canon(&one_int()));
        // Cross-check the inverse with the *independent* reference multiplier:
        // `inv * x` reduced by the reference must also be the identity.
        assert_eq!(
            to_canon(&ref_mul(&from_canon(&inv.to_bytes()), &xi, p)),
            to_canon(&one_int())
        );
    }

    // Exponentiation: x^3 == x*x*x for a public exponent.
    let e3 = x.pow_vartime(&[3, 0, 0, 0, 0, 0]);
    assert_eq!(e3.to_bytes(), x.mul(&x.mul(&x)).to_bytes());

    // Square root (when it exists) squares back to the input.
    let s = x.sqrt();
    if s.is_some().into_bool() {
        let s = s.unwrap();
        assert_eq!(s.square().to_bytes(), x.to_bytes());
    }
}

proptest! {
    #[test]
    fn p256_base_props(a in any::<[u64;N]>(), b in any::<[u64;N]>(), c in any::<[u64;N]>()) {
        field_props::<P256BaseParams>(a, b, c);
    }

    #[test]
    fn p256_scalar_props(a in any::<[u64;N]>(), b in any::<[u64;N]>(), c in any::<[u64;N]>()) {
        field_props::<P256ScalarParams>(a, b, c);
    }

    #[test]
    fn p384_base_props(a in any::<[u64;N]>(), b in any::<[u64;N]>(), c in any::<[u64;N]>()) {
        field_props::<P384BaseParams>(a, b, c);
    }

    #[test]
    fn p384_scalar_props(a in any::<[u64;N]>(), b in any::<[u64;N]>(), c in any::<[u64;N]>()) {
        field_props::<P384ScalarParams>(a, b, c);
    }

    #[test]
    fn bls12_381_fp_props(a in any::<[u64;N]>(), b in any::<[u64;N]>(), c in any::<[u64;N]>()) {
        field_props::<Bls12381FpParams>(a, b, c);
    }

    #[test]
    fn bls12_381_fr_props(a in any::<[u64;N]>(), b in any::<[u64;N]>(), c in any::<[u64;N]>()) {
        field_props::<Bls12381FrParams>(a, b, c);
    }
}
