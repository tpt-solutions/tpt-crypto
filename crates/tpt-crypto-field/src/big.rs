//! Minimal little-endian big-integer arithmetic (private).
//!
//! Used only to compute the field order `q = p^k` and the large exponents needed
//! by Fermat inversion and Tonelli–Shanks for the BLS extension towers (`Fp6`,
//! `Fp12`). This is intentionally a small, self-contained implementation — it is
//! not on any secret-dependent path and is only exercised when building tower
//! square roots/inverses.

#![allow(dead_code, unused_mut)]

use core::cmp::Ordering;

use alloc::vec;
use alloc::vec::Vec;

use crate::field::FieldParams;

#[derive(Clone, Debug)]
pub(crate) struct Big(Vec<u64>);

fn trim(v: &mut Vec<u64>) {
    while let Some(&0) = v.last() {
        v.pop();
    }
}

fn bit_length(a: &[u64]) -> u32 {
    let mut i = a.len();
    while i > 0 {
        i -= 1;
        if a[i] != 0 {
            return (i as u32) * 64 + (64 - a[i].leading_zeros());
        }
    }
    0
}

fn big_ge(a: &[u64], b: &[u64]) -> bool {
    let n = a.len().max(b.len());
    let mut i = n;
    while i > 0 {
        i -= 1;
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

fn sub_big(a: &[u64], b: &[u64]) -> Vec<u64> {
    let mut out = vec![0u64; a.len().max(b.len())];
    let mut borrow = 0u64;
    for (i, out_i) in out.iter_mut().enumerate() {
        let av = *a.get(i).unwrap_or(&0);
        let bv = *b.get(i).unwrap_or(&0);
        let (d, bo) = av.overflowing_sub(bv.wrapping_add(borrow));
        *out_i = d;
        borrow = bo as u64;
    }
    trim(&mut out);
    out
}

fn shl_bits(a: &[u64], n: u32) -> Vec<u64> {
    let ls = (n / 64) as usize;
    let bs = n % 64;
    let mut out = vec![0u64; a.len() + ls + 1];
    for i in 0..a.len() {
        let v = a[i];
        if bs > 0 {
            out[i + ls + 1] |= v >> (64 - bs);
        }
        out[i + ls] |= v << bs;
    }
    trim(&mut out);
    out
}

fn shr_bits(a: &[u64], n: u32) -> Vec<u64> {
    let ls = (n / 64) as usize;
    let bs = n % 64;
    let mut out = vec![0u64; a.len()];
    for (i, out_i) in out.iter_mut().enumerate() {
        let src = i + ls;
        if src >= a.len() {
            break;
        }
        *out_i = if bs == 0 {
            a[src]
        } else {
            // Bits flow in from the *next higher* limb (little-endian).
            let hi = if src + 1 < a.len() { a[src + 1] } else { 0 };
            (a[src] >> bs) | (hi << (64 - bs))
        };
    }
    trim(&mut out);
    out
}

fn add_pow2(q: &mut Vec<u64>, shift: u32) {
    let ls = (shift / 64) as usize;
    let bs = shift % 64;
    if q.len() <= ls {
        q.resize(ls + 1, 0);
    }
    let mut carry: u128 = (1u128) << bs;
    let mut k = ls;
    loop {
        let s = (q[k] as u128) + carry;
        q[k] = s as u64;
        carry = s >> 64;
        if carry == 0 {
            break;
        }
        k += 1;
        if k >= q.len() {
            q.push(0);
        }
    }
}

impl Big {
    pub fn from_u64(v: u64) -> Self {
        if v == 0 {
            Big(vec![])
        } else {
            Big(vec![v])
        }
    }

    pub fn from_limbs<const L: usize>(a: &[u64; L]) -> Self {
        let mut v = a.to_vec();
        trim(&mut v);
        Big(v)
    }

    pub fn is_zero(&self) -> bool {
        self.0.is_empty()
    }

    pub fn is_one(&self) -> bool {
        self.0.len() == 1 && self.0[0] == 1
    }

    pub fn to_vec(&self) -> Vec<u64> {
        self.0.clone()
    }

    fn add(&self, o: &Big) -> Big {
        let n = self.0.len().max(o.0.len());
        let mut out = vec![0u64; n + 1];
        let mut carry = 0u128;
        for (i, out_i) in out.iter_mut().enumerate().take(n) {
            let av = *self.0.get(i).unwrap_or(&0) as u128;
            let bv = *o.0.get(i).unwrap_or(&0) as u128;
            let s = av + bv + carry;
            *out_i = s as u64;
            carry = s >> 64;
        }
        out[n] = carry as u64;
        trim(&mut out);
        Big(out)
    }

    fn sub(&self, o: &Big) -> (Big, u8) {
        if !big_ge(&self.0, &o.0) {
            // return (0, 1) borrow; caller guards
            return (Big(vec![]), 1);
        }
        (Big(sub_big(&self.0, &o.0)), 0)
    }

    fn dec(&self) -> Big {
        let one = Big::from_u64(1);
        let (d, _) = self.sub(&one);
        d
    }

    fn mul(&self, o: &Big) -> Big {
        if self.is_zero() || o.is_zero() {
            return Big(vec![]);
        }
        let mut t = vec![0u64; self.0.len() + o.0.len()];
        for i in 0..self.0.len() {
            let mut carry: u128 = 0;
            for j in 0..o.0.len() {
                let prod = (self.0[i] as u128) * (o.0[j] as u128) + (t[i + j] as u128) + carry;
                t[i + j] = prod as u64;
                carry = prod >> 64;
            }
            let mut k = i + o.0.len();
            let mut c = carry;
            while c != 0 {
                let s = (t[k] as u128) + c;
                t[k] = s as u64;
                c = s >> 64;
                k += 1;
            }
        }
        trim(&mut t);
        Big(t)
    }

    /// `self mod m` via long division (remainder).
    fn reduce(&self, m: &Big) -> Big {
        if m.is_zero() {
            return Big(vec![]);
        }
        let mbits = bit_length(&m.0);
        let mut r = self.0.clone();
        let mut bit = bit_length(&r);
        while bit as i32 >= mbits as i32 - 1 {
            let shift = bit - (mbits - 1);
            let sm = shl_bits(&m.0, shift);
            if big_ge(&r, &sm) {
                r = sub_big(&r, &sm);
            }
            if bit == 0 {
                break;
            }
            bit -= 1;
        }
        if big_ge(&r, &m.0) {
            r = sub_big(&r, &m.0);
        }
        trim(&mut r);
        Big(r)
    }

    fn mul_mod(&self, o: &Big, m: &Big) -> Big {
        self.mul(o).reduce(m)
    }

    fn pow_mod(&self, exp: &Big, m: &Big) -> Big {
        let mut result = Big::from_u64(1);
        let mut base = self.reduce(m);
        let mut limb = exp.0.len();
        while limb > 0 {
            limb -= 1;
            let mut bit = 63u32;
            loop {
                result = result.mul_mod(&result, m);
                let b = (exp.0[limb] >> bit) & 1;
                if b == 1 {
                    result = result.mul_mod(&base, m);
                }
                if bit == 0 {
                    break;
                }
                bit -= 1;
            }
        }
        result
    }

    fn trailing_zeros(&self) -> u32 {
        let mut z = 0u32;
        for &limb in &self.0 {
            if limb == 0 {
                z += 64;
            } else {
                z += limb.trailing_zeros();
                break;
            }
        }
        z
    }

    fn shr(&self, n: u32) -> Big {
        Big(shr_bits(&self.0, n))
    }

    fn cmp_big(&self, o: &Big) -> Ordering {
        if big_ge(&self.0, &o.0) {
            if big_ge(&o.0, &self.0) {
                Ordering::Equal
            } else {
                Ordering::Greater
            }
        } else {
            Ordering::Less
        }
    }
}

/// Precomputed tower data: `q = p^k`, with `q - 1 = 2^S * T`.
pub(crate) struct TowerInfo {
    pub s: u32,
    pub t_exp: Vec<u64>,
    pub tp1_over_2: Vec<u64>,
    pub q_minus_2: Vec<u64>,
    pub half: Vec<u64>,
}

/// Compute `q = p^k` and the exponents used by Fermat inversion / Tonelli–Shanks.
pub(crate) fn tower_info(k: u32) -> TowerInfo {
    use crate::params::Bls12381FpParams;
    let p = Big::from_limbs(&Bls12381FpParams::MODULUS);
    let mut q = Big::from_u64(1);
    for _ in 0..k {
        q = q.mul(&p);
    }
    let qm1 = q.dec();
    let s = qm1.trailing_zeros();
    let t = qm1.shr(s);
    let tp1 = t.add(&Big::from_u64(1)).shr(1);
    let qm2 = q.dec().dec();
    let half = qm1.shr(1);
    TowerInfo {
        s,
        t_exp: t.to_vec(),
        tp1_over_2: tp1.to_vec(),
        q_minus_2: qm2.to_vec(),
        half: half.to_vec(),
    }
}

impl Big {
    /// Binary long division: returns `(quotient, remainder)` for `self / m`.
    fn divmod(&self, m: &Big) -> (Big, Big) {
        assert!(!m.is_zero(), "division by zero");
        let n = bit_length(&self.0);
        if n == 0 {
            return (Big(vec![]), Big(vec![]));
        }
        let mut q = vec![0u64; (n as usize / 64) + 1];
        let mut r: Vec<u64> = vec![];
        let mut i = n;
        while i > 0 {
            i -= 1;
            r = shl_bits(&r, 1);
            let bit = (self.0[i as usize / 64] >> (i % 64)) & 1;
            if bit == 1 {
                if r.is_empty() {
                    r.push(1);
                } else {
                    r[0] |= 1;
                }
            }
            if big_ge(&r, &m.0) {
                r = sub_big(&r, &m.0);
                q[i as usize / 64] |= 1u64 << (i % 64);
            }
        }
        trim(&mut q);
        trim(&mut r);
        (Big(q), Big(r))
    }
}

/// The BLS12-381 final-exponentiation exponent `(p^12 - 1) / r`, little-endian
/// `u64` words. Used by the pairing in `tpt-crypto-curve`.
#[must_use]
pub fn bls12381_final_exp_exponent() -> Vec<u64> {
    use crate::params::{Bls12381FpParams, Bls12381FrParams};
    let p = Big::from_limbs(&Bls12381FpParams::MODULUS);
    let mut q = Big::from_u64(1);
    for _ in 0..12 {
        q = q.mul(&p);
    }
    let qm1 = q.dec();
    let r = Big::from_limbs(&Bls12381FrParams::MODULUS);
    let (quot, rem) = qm1.divmod(&r);
    debug_assert!(rem.is_zero(), "r must divide p^12 - 1");
    quot.to_vec()
}

/// The BLS12-381 final exponentiation split `(p^12-1)/r = (p^6-1)·(p^2+1)·h`
/// with `h = (p^4 - p^2 + 1)/r`. Returns `(p^2, h)`, little-endian `u64` words.
///
/// The `p^6 - 1` factor is applied as `conj(f)/f` by the caller, `p^2 + 1` as
/// `f^(p^2)·f`, and `h` is the (much shorter) hard-part exponent.
#[must_use]
pub fn bls12381_final_exp_split() -> (Vec<u64>, Vec<u64>) {
    use crate::params::{Bls12381FpParams, Bls12381FrParams};
    let p = Big::from_limbs(&Bls12381FpParams::MODULUS);
    let p2 = p.mul(&p);
    let p4 = p2.mul(&p2);
    let (num, borrow) = p4.sub(&p2);
    debug_assert_eq!(borrow, 0);
    let num = num.add(&Big::from_u64(1));
    let r = Big::from_limbs(&Bls12381FrParams::MODULUS);
    let (h, rem) = num.divmod(&r);
    debug_assert!(rem.is_zero(), "r must divide p^4 - p^2 + 1");
    (p2.to_vec(), h.to_vec())
}

/// Smallest quadratic non-residue `z >= 2` in a tower field, via Euler's criterion.
pub(crate) fn find_nonresidue_field<F: crate::field::Field + crate::ct::CtEq>(half: &[u64]) -> F {
    let minus_one = F::one().neg();
    let mut zc = 2u64;
    loop {
        let z = F::enumerate(zc);
        if !z.is_zero().into_bool() {
            let e = z.pow_vartime(half);
            if e.ct_eq(&minus_one).into_bool() {
                return z;
            }
        }
        zc += 1;
    }
}
