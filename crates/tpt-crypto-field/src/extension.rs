//! Extension towers for BLS12-381: `Fp2`, `Fp6`, `Fp12`.
//!
//! These follow the standard BLS12-381 tower:
//! * `Fp2 = Fp[u] / (u^2 + 1)`  (so `u^2 = -1`),
//! * `Fp6 = Fp2[v] / (v^3 - ξ)` with `ξ = u + 1`,
//! * `Fp12 = Fp6[w] / (w^2 - v)`.
//!
//! All types implement the shared [`Field`] interface so the towers compose with
//! the prime field. Inversion and square roots for the towers use the field order
//! `q = p^k` (computed in [`crate::big`]) via Fermat's little theorem and a generic
//! Tonelli–Shanks, keeping this module free of bespoke per-tower formulas.

use crate::big::{find_nonresidue_field, tower_info};
use crate::ct::{Choice, CtEq, CtOption};
use crate::field::Field;
use crate::params::Bls12381Fp as Fp;

/// A quadratic extension element `c0 + c1 * u` with `u^2 = -1`.
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub struct Fp2 {
    /// The constant term.
    pub c0: Fp,
    /// The `u` coefficient.
    pub c1: Fp,
}

impl Fp2 {
    /// Construct a new element `c0 + c1 * u`.
    #[inline]
    #[must_use]
    pub fn new(c0: Fp, c1: Fp) -> Self {
        Fp2 { c0, c1 }
    }

    /// The constant term.
    #[inline]
    #[must_use]
    pub fn c0(&self) -> Fp {
        self.c0
    }

    /// The `u` coefficient.
    #[inline]
    #[must_use]
    pub fn c1(&self) -> Fp {
        self.c1
    }
}

impl CtEq for Fp2 {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.c0.ct_eq(&other.c0).and(self.c1.ct_eq(&other.c1))
    }
}

impl Field for Fp2 {
    #[inline]
    fn zero() -> Self {
        Fp2::new(Fp::zero(), Fp::zero())
    }
    #[inline]
    fn one() -> Self {
        Fp2::new(Fp::one(), Fp::zero())
    }
    #[inline]
    fn from_u64(v: u64) -> Self {
        Fp2::new(Fp::from_u64(v), Fp::zero())
    }
    #[inline]
    fn ct_select(a: &Self, b: &Self, c: Choice) -> Self {
        Fp2::new(
            Fp::ct_select(&a.c0, &b.c0, c),
            Fp::ct_select(&a.c1, &b.c1, c),
        )
    }
    #[inline]
    fn is_zero(&self) -> Choice {
        self.c0.is_zero().and(self.c1.is_zero())
    }
    #[inline]
    fn add(&self, o: &Self) -> Self {
        Fp2::new(self.c0.add(&o.c0), self.c1.add(&o.c1))
    }
    #[inline]
    fn sub(&self, o: &Self) -> Self {
        Fp2::new(self.c0.sub(&o.c0), self.c1.sub(&o.c1))
    }
    #[inline]
    fn neg(&self) -> Self {
        Fp2::new(self.c0.neg(), self.c1.neg())
    }
    #[inline]
    fn mul(&self, o: &Self) -> Self {
        // (a0 + a1 u)(b0 + b1 u) = (a0 b0 - a1 b1, a0 b1 + a1 b0), u^2 = -1.
        let a0b0 = self.c0.mul(&o.c0);
        let a1b1 = self.c1.mul(&o.c1);
        let a0b1 = self.c0.mul(&o.c1);
        let a1b0 = self.c1.mul(&o.c0);
        Fp2::new(a0b0.sub(&a1b1), a0b1.add(&a1b0))
    }
    #[inline]
    fn invert(&self) -> CtOption<Self> {
        let info = tower_info(2);
        let r = self.pow_vartime(&info.q_minus_2);
        CtOption::new(r, self.is_zero().not())
    }
    #[inline]
    fn pow_vartime(&self, exp: &[u64]) -> Self {
        let mut result = Self::one();
        let mut limb = exp.len();
        while limb > 0 {
            limb -= 1;
            let mut bit = 63u32;
            loop {
                result = result.square();
                let b = (exp[limb] >> bit) & 1;
                if b == 1 {
                    result = result.mul(self);
                }
                if bit == 0 {
                    break;
                }
                bit -= 1;
            }
        }
        result
    }
    #[inline]
    fn sqrt(&self) -> CtOption<Self> {
        let info = tower_info(2);
        let z = find_nonresidue_field::<Self>(&info.half);
        tonelli_shanks_field(self, info.s, &info.t_exp, &info.tp1_over_2, &z)
    }
}

/// A cubic extension element `c0 + c1 * v + c2 * v^2` with `v^3 = ξ = u + 1`.
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub struct Fp6 {
    /// Coefficient of `1`.
    pub c0: Fp2,
    /// Coefficient of `v`.
    pub c1: Fp2,
    /// Coefficient of `v^2`.
    pub c2: Fp2,
}

impl Fp6 {
    /// Construct a new element.
    #[inline]
    #[must_use]
    pub fn new(c0: Fp2, c1: Fp2, c2: Fp2) -> Self {
        Fp6 { c0, c1, c2 }
    }

    /// The `ξ = u + 1` non-residue (built once).
    #[inline]
    fn xi() -> Fp2 {
        Fp2::new(Fp::one(), Fp::one())
    }
}

impl CtEq for Fp6 {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.c0
            .ct_eq(&other.c0)
            .and(self.c1.ct_eq(&other.c1))
            .and(self.c2.ct_eq(&other.c2))
    }
}

impl Field for Fp6 {
    #[inline]
    fn zero() -> Self {
        Fp6::new(Fp2::zero(), Fp2::zero(), Fp2::zero())
    }
    #[inline]
    fn one() -> Self {
        Fp6::new(Fp2::one(), Fp2::zero(), Fp2::zero())
    }
    #[inline]
    fn from_u64(v: u64) -> Self {
        Fp6::new(Fp2::from_u64(v), Fp2::zero(), Fp2::zero())
    }
    #[inline]
    fn ct_select(a: &Self, b: &Self, c: Choice) -> Self {
        Fp6::new(
            Fp2::ct_select(&a.c0, &b.c0, c),
            Fp2::ct_select(&a.c1, &b.c1, c),
            Fp2::ct_select(&a.c2, &b.c2, c),
        )
    }
    #[inline]
    fn is_zero(&self) -> Choice {
        self.c0
            .is_zero()
            .and(self.c1.is_zero())
            .and(self.c2.is_zero())
    }
    #[inline]
    fn add(&self, o: &Self) -> Self {
        Fp6::new(self.c0.add(&o.c0), self.c1.add(&o.c1), self.c2.add(&o.c2))
    }
    #[inline]
    fn sub(&self, o: &Self) -> Self {
        Fp6::new(self.c0.sub(&o.c0), self.c1.sub(&o.c1), self.c2.sub(&o.c2))
    }
    #[inline]
    fn neg(&self) -> Self {
        Fp6::new(self.c0.neg(), self.c1.neg(), self.c2.neg())
    }
    #[inline]
    fn mul(&self, o: &Self) -> Self {
        let xi = Self::xi();
        let a0b0 = self.c0.mul(&o.c0);
        let a1b1 = self.c1.mul(&o.c1);
        let a2b2 = self.c2.mul(&o.c2);
        let a0b1 = self.c0.mul(&o.c1);
        let a1b0 = self.c1.mul(&o.c0);
        let a0b2 = self.c0.mul(&o.c2);
        let a2b0 = self.c2.mul(&o.c0);
        let a1b2 = self.c1.mul(&o.c2);
        let a2b1 = self.c2.mul(&o.c1);
        let c0 = a0b0.add(&xi.mul(&a1b2.add(&a2b1)));
        let c1 = a0b1.add(&a1b0).add(&xi.mul(&a2b2));
        let c2 = a0b2.add(&a2b0).add(&a1b1);
        Fp6::new(c0, c1, c2)
    }
    #[inline]
    fn invert(&self) -> CtOption<Self> {
        let info = tower_info(6);
        let r = self.pow_vartime(&info.q_minus_2);
        CtOption::new(r, self.is_zero().not())
    }
    #[inline]
    fn pow_vartime(&self, exp: &[u64]) -> Self {
        let mut result = Self::one();
        let mut limb = exp.len();
        while limb > 0 {
            limb -= 1;
            let mut bit = 63u32;
            loop {
                result = result.square();
                let b = (exp[limb] >> bit) & 1;
                if b == 1 {
                    result = result.mul(self);
                }
                if bit == 0 {
                    break;
                }
                bit -= 1;
            }
        }
        result
    }
    #[inline]
    fn sqrt(&self) -> CtOption<Self> {
        let info = tower_info(6);
        let z = find_nonresidue_field::<Self>(&info.half);
        tonelli_shanks_field(self, info.s, &info.t_exp, &info.tp1_over_2, &z)
    }
}

/// A quadratic extension `Fp12 = Fp6[w] / (w^2 - v)`.
#[derive(Clone, Copy, Default, PartialEq, Debug)]
pub struct Fp12 {
    /// The constant term (in `Fp6`).
    pub c0: Fp6,
    /// The `w` coefficient (in `Fp6`).
    pub c1: Fp6,
}

impl Fp12 {
    /// Construct a new element `c0 + c1 * w`.
    #[inline]
    #[must_use]
    pub fn new(c0: Fp6, c1: Fp6) -> Self {
        Fp12 { c0, c1 }
    }

    /// The element `v` (the `Fp6` basis element with `v` coefficient 1).
    #[inline]
    fn v() -> Fp6 {
        Fp6::new(Fp2::zero(), Fp2::one(), Fp2::zero())
    }
}

impl CtEq for Fp12 {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        self.c0.ct_eq(&other.c0).and(self.c1.ct_eq(&other.c1))
    }
}

impl Field for Fp12 {
    #[inline]
    fn zero() -> Self {
        Fp12::new(Fp6::zero(), Fp6::zero())
    }
    #[inline]
    fn one() -> Self {
        Fp12::new(Fp6::one(), Fp6::zero())
    }
    #[inline]
    fn from_u64(v: u64) -> Self {
        Fp12::new(Fp6::from_u64(v), Fp6::zero())
    }
    #[inline]
    fn ct_select(a: &Self, b: &Self, c: Choice) -> Self {
        Fp12::new(
            Fp6::ct_select(&a.c0, &b.c0, c),
            Fp6::ct_select(&a.c1, &b.c1, c),
        )
    }
    #[inline]
    fn is_zero(&self) -> Choice {
        self.c0.is_zero().and(self.c1.is_zero())
    }
    #[inline]
    fn add(&self, o: &Self) -> Self {
        Fp12::new(self.c0.add(&o.c0), self.c1.add(&o.c1))
    }
    #[inline]
    fn sub(&self, o: &Self) -> Self {
        Fp12::new(self.c0.sub(&o.c0), self.c1.sub(&o.c1))
    }
    #[inline]
    fn neg(&self) -> Self {
        Fp12::new(self.c0.neg(), self.c1.neg())
    }
    #[inline]
    fn mul(&self, o: &Self) -> Self {
        let v = Self::v();
        let a0b0 = self.c0.mul(&o.c0);
        let a1b1 = self.c1.mul(&o.c1);
        let a0b1 = self.c0.mul(&o.c1);
        let a1b0 = self.c1.mul(&o.c0);
        let c0 = a0b0.add(&v.mul(&a1b1));
        let c1 = a0b1.add(&a1b0);
        Fp12::new(c0, c1)
    }
    #[inline]
    fn invert(&self) -> CtOption<Self> {
        let info = tower_info(12);
        let r = self.pow_vartime(&info.q_minus_2);
        CtOption::new(r, self.is_zero().not())
    }
    #[inline]
    fn pow_vartime(&self, exp: &[u64]) -> Self {
        let mut result = Self::one();
        let mut limb = exp.len();
        while limb > 0 {
            limb -= 1;
            let mut bit = 63u32;
            loop {
                result = result.square();
                let b = (exp[limb] >> bit) & 1;
                if b == 1 {
                    result = result.mul(self);
                }
                if bit == 0 {
                    break;
                }
                bit -= 1;
            }
        }
        result
    }
    #[inline]
    fn sqrt(&self) -> CtOption<Self> {
        let info = tower_info(12);
        let z = find_nonresidue_field::<Self>(&info.half);
        tonelli_shanks_field(self, info.s, &info.t_exp, &info.tp1_over_2, &z)
    }
}

/// Generic constant-time Tonelli–Shanks over any [`Field`] whose group order has
/// `2`-adic decomposition `q - 1 = 2^S * T`. `z` must be a quadratic non-residue.
#[inline]
fn tonelli_shanks_field<F: Field + CtEq>(
    a: &F,
    s: u32,
    t: &[u64],
    tp1: &[u64],
    z: &F,
) -> CtOption<F> {
    let mut c = z.pow_vartime(t);
    let mut x = a.pow_vartime(tp1);
    let mut b = a.pow_vartime(t);
    let mut i = s;
    let mut result = x;
    let mut done = Choice::FALSE;
    let mut step = 0u32;
    while step < s {
        let b_is_one = b.ct_eq(&F::one());
        let mut found = 0u32;
        let mut t2 = b;
        let mut k = 1u32;
        while k <= i {
            t2 = t2.square();
            let is_one = t2.ct_eq(&F::one());
            if is_one.into_bool() && found == 0 {
                found = k;
            }
            k += 1;
        }
        let mut e2 = i;
        if found != 0 {
            e2 = i - found - 1;
        }
        let mut d = c;
        let mut sq = 0u32;
        while sq < e2 {
            d = d.square();
            sq += 1;
        }
        let x_new = x.mul(&d);
        let c_new = d.square();
        let b_new = b.mul(&c_new);
        let apply = done.not();
        x = F::ct_select(&x, &x_new, apply);
        c = F::ct_select(&c, &c_new, apply);
        b = F::ct_select(&b, &b_new, apply);
        result = x;
        done = done.or(b_is_one);
        if apply.into_bool() {
            i = found;
        }
        step += 1;
    }
    let ok = result.square().ct_eq(a);
    CtOption::new(result, ok)
}

#[cfg(feature = "alloc")]
mod enc {
    use super::*;
    use alloc::vec::Vec;

    impl Fp2 {
        /// Canonical byte encoding (little-endian concatenation of `c0`,`c1`).
        #[must_use]
        pub fn to_bytes(&self) -> Vec<u8> {
            let mut v = self.c0.to_bytes().to_vec();
            v.extend_from_slice(&self.c1.to_bytes());
            v
        }
        /// Parse a canonical encoding, rejecting non-canonical input.
        #[must_use]
        pub fn from_bytes(slice: &[u8]) -> CtOption<Self> {
            let bl = Fp::zero().to_bytes().len();
            if slice.len() != 2 * bl {
                return CtOption::none();
            }
            let c0 = Fp::from_bytes(&slice[0..bl]);
            let c1 = Fp::from_bytes(&slice[bl..2 * bl]);
            let valid = c0.is_some().and(c1.is_some());
            CtOption::new(
                Fp2::new(c0.unwrap_or_default(), c1.unwrap_or_default()),
                valid,
            )
        }
    }

    impl Fp6 {
        /// Canonical byte encoding.
        #[must_use]
        pub fn to_bytes(&self) -> Vec<u8> {
            let mut v = self.c0.to_bytes();
            v.extend_from_slice(&self.c1.to_bytes());
            v.extend_from_slice(&self.c2.to_bytes());
            v
        }
        /// Parse a canonical encoding.
        #[must_use]
        pub fn from_bytes(slice: &[u8]) -> CtOption<Self> {
            let bl = Fp2::zero().to_bytes().len();
            if slice.len() != 3 * bl {
                return CtOption::none();
            }
            let c0 = Fp2::from_bytes(&slice[0..bl]);
            let c1 = Fp2::from_bytes(&slice[bl..2 * bl]);
            let c2 = Fp2::from_bytes(&slice[2 * bl..3 * bl]);
            let valid = c0.is_some().and(c1.is_some()).and(c2.is_some());
            CtOption::new(
                Fp6::new(
                    c0.unwrap_or_default(),
                    c1.unwrap_or_default(),
                    c2.unwrap_or_default(),
                ),
                valid,
            )
        }
    }

    impl Fp12 {
        /// Canonical byte encoding.
        #[must_use]
        pub fn to_bytes(&self) -> Vec<u8> {
            let mut v = self.c0.to_bytes();
            v.extend_from_slice(&self.c1.to_bytes());
            v
        }
        /// Parse a canonical encoding.
        #[must_use]
        pub fn from_bytes(slice: &[u8]) -> CtOption<Self> {
            let bl = Fp6::zero().to_bytes().len();
            if slice.len() != 2 * bl {
                return CtOption::none();
            }
            let c0 = Fp6::from_bytes(&slice[0..bl]);
            let c1 = Fp6::from_bytes(&slice[bl..2 * bl]);
            let valid = c0.is_some().and(c1.is_some());
            CtOption::new(
                Fp12::new(c0.unwrap_or_default(), c1.unwrap_or_default()),
                valid,
            )
        }
    }
}
