//! Ed25519 (`Ed25519Field`) has `S = 2`, so its `sqrt` routes through the
//! generic Tonelli–Shanks path whose compile-time constant derivation (a
//! quadratic-non-residue search over a 256-bit modulus) trips the
//! `long_running_const_eval` lint. The derivation is correct, just large, so we
//! allow it here.
#![allow(long_running_const_eval)]

//! Prime field arithmetic over a compile-time modulus.
//!
//! [`FieldElement<P>`] stores a field element in **Montgomery form** and
//! monomorphizes a fully unrolled, stack-only, constant-time arithmetic routine
//! per curve. All operations — add/sub/neg/mul/square/reduce/invert — are
//! implemented with bitwise masks and `cmov`, never conditional branches on
//! secret data.

use core::fmt;
use core::marker::PhantomData;
use core::ops::Neg;

use crate::consts::{self, MAX_LIMBS};
use crate::ct::{Choice, CtEq, CtOption};
use crate::ct::ct_select_u64;
use tpt_crypto_ct::CtSelect;

/// Parameters of a prime field `GF(p)`.
///
/// Implementors supply the [`MODULUS`], the limb count [`LIMBS`], and the
/// exponent [`S`] from `p - 1 = 2^S * T` (with `T` odd). Every other constant
/// (`MU`, `R2`, `ONE_MONT`, `T`, the square-root exponent, a quadratic non-residue)
/// is derived at compile time by [`FieldElement`] from these three.
pub trait FieldParams: Copy + Clone + Default + Eq + fmt::Debug + Send + Sync + 'static {
    /// Number of significant limbs in the modulus (the modulus uses the low
    /// [`LIMBS`] limbs of a [`MAX_LIMBS`]-wide array).
    const LIMBS: usize;
    /// The prime modulus `p` (low [`LIMBS`] limbs significant, little-endian).
    const MODULUS: [u64; MAX_LIMBS];
    /// The exponent `S` in `p - 1 = 2^S * T` (number of factors of two in `p-1`).
    const S: u32;
    /// The Montgomery constant `R mod p` (the Montgomery encoding of `1`),
    /// precomputed at build time: `2^(64 * LIMBS) mod p`, little-endian limbs.
    const ONE_MONT: [u64; MAX_LIMBS];
    /// The Montgomery constant `R^2 mod p`, precomputed at build time.
    const R2: [u64; MAX_LIMBS];
    /// The Montgomery constant `MU = -p^{-1} mod 2^64`, precomputed at build time.
    const MU: u64;
}

/// A constant-time, stack-only element of `GF(p)`.
///
/// Internally the value is held in Montgomery form. Construct via
/// [`FieldElement::from_bytes`] (canonical encoding, constant-time rejection of
/// non-canonical input) or [`FieldElement::from_u64`].
#[derive(Clone, Copy)]
pub struct FieldElement<P: FieldParams> {
    /// Montgomery-form limbs (little-endian).
    limbs: [u64; MAX_LIMBS],
    _p: PhantomData<P>,
}

impl<P: FieldParams> FieldElement<P> {
    /// The Montgomery constant `R^2 mod p` (precomputed per field).
    const R2: [u64; MAX_LIMBS] = P::R2;
    /// The Montgomery constant `-p^{-1} mod 2^64` (precomputed per field).
    const MU: u64 = P::MU;
    /// The Montgomery constant `R mod p` = the Montgomery encoding of `1`.
    const ONE_MONT: [u64; MAX_LIMBS] = P::ONE_MONT;
    /// The Fermat inversion exponent `p - 2`.
    const MOD_MINUS_2: [u64; MAX_LIMBS] = consts::mod_minus_2(&P::MODULUS);
    /// `T = (p - 1) >> S`.
    const T: [u64; MAX_LIMBS] = consts::t_of(&P::MODULUS, P::S);
    /// `(T + 1) >> 1`, used by Tonelli–Shanks.
    const T_PLUS_1_OVER_2: [u64; MAX_LIMBS] =
        consts::t_plus_1_over_2(&consts::t_of(&P::MODULUS, P::S));
    /// `(p + 1) >> 2`, the square-root exponent for `p ≡ 3 (mod 4)`.
    const SQRT_EXP: [u64; MAX_LIMBS] = consts::sqrt_exp(&P::MODULUS);

    /// Constant-time Montgomery multiplication.
    ///
    /// Computes `a * b * R^{-1} mod p` (the Montgomery product) using the
    /// standard operand-scanning Montgomery reduction (HAC §14.32). `a` and `b`
    /// are assumed to already be in Montgomery form (`*R mod p`). The integer
    /// product `a*b` is accumulated into a `2n`-limb buffer (note `a*b < p^2 <
    /// R*p`, so the reduction precondition is satisfied), reduced, and the result
    /// shifted right by `n` limbs and conditionally subtracted by `p`.
    #[inline]
    fn mont_mul(a: &[u64; MAX_LIMBS], b: &[u64; MAX_LIMBS]) -> [u64; MAX_LIMBS] {
        let p = &P::MODULUS;
        let mu = Self::MU;
        let n = P::LIMBS;
        // t = a * b as a (up to) 2n-limb integer.
        let mut t = [0u64; 2 * MAX_LIMBS + 2];
        let mut i = 0;
        while i < n {
            let ai = a[i];
            let mut carry: u128 = 0;
            let mut j = 0;
            while j < n {
                let sum = (t[i + j] as u128) + (ai as u128) * (b[j] as u128) + carry;
                t[i + j] = sum as u64;
                carry = sum >> 64;
                j += 1;
            }
            let mut k = i + n;
            let mut c = carry;
            while c != 0 {
                let sum = (t[k] as u128) + c;
                t[k] = sum as u64;
                c = sum >> 64;
                k += 1;
            }
            i += 1;
        }
        // Montgomery reduction: for i in 0..n, m = t[i]*mu mod 2^64, t += m*p (into
        // the 2n-limb buffer), shifting the result one limb right each step.
        i = 0;
        while i < n {
            let m = (t[i].wrapping_mul(mu)) as u128;
            let mut carry: u128 = 0;
            let mut j = 0;
            while j < n {
                let sum = (t[i + j] as u128) + m * (p[j] as u128) + carry;
                t[i + j] = sum as u64;
                carry = sum >> 64;
                j += 1;
            }
            let mut k = i + n;
            let mut c = carry;
            while c != 0 {
                let sum = (t[k] as u128) + c;
                t[k] = sum as u64;
                c = sum >> 64;
                k += 1;
            }
            i += 1;
        }
        // The reduced value lives in t[n..2n]; copy it out.
        let mut out = [0u64; MAX_LIMBS];
        let mut idx = 0;
        while idx < MAX_LIMBS {
            out[idx] = t[n + idx];
            idx += 1;
        }
        // Final conditional subtraction of `p` (the reduction leaves a value in
        // [0, 2p)). Compare `out` against `p` (zero-extended) and select.
        let mut sub = [0u64; MAX_LIMBS];
        let mut borrow: u64 = 0;
        let mut idx2 = 0;
        while idx2 < MAX_LIMBS {
            let pv = if idx2 < n { p[idx2] } else { 0u64 };
            let (d1, b1) = out[idx2].overflowing_sub(pv);
            let (d, b2) = d1.overflowing_sub(borrow);
            sub[idx2] = d;
            borrow = (b1 | b2) as u64;
            idx2 += 1;
        }
        let ge = Choice::from_bool(borrow == 0);
        let mut res = [0u64; MAX_LIMBS];
        let mut idx3 = 0;
        while idx3 < MAX_LIMBS {
            res[idx3] = ct_select_u64(out[idx3], sub[idx3], ge);
            idx3 += 1;
        }
        res
    }

    /// Encode an integer (`< p`) into Montgomery form.
    #[inline]
    fn from_integer(int: &[u64; MAX_LIMBS]) -> Self {
        FieldElement {
            limbs: Self::mont_mul(int, &Self::R2),
            _p: PhantomData,
        }
    }

    /// Decode from Montgomery form to a plain integer (`< p`).
    #[inline]
    fn to_integer(&self) -> [u64; MAX_LIMBS] {
        let mut one = [0u64; MAX_LIMBS];
        one[0] = 1;
        Self::mont_mul(&self.limbs, &one)
    }

    /// Build the additive identity `0`.
    #[inline]
    #[must_use]
    pub fn zero() -> Self {
        FieldElement {
            limbs: [0u64; MAX_LIMBS],
            _p: PhantomData,
        }
    }

    /// Build the multiplicative identity `1`.
    #[inline]
    #[must_use]
    pub fn one() -> Self {
        FieldElement {
            limbs: Self::ONE_MONT,
            _p: PhantomData,
        }
    }

    /// Build a field element directly from its Montgomery-form limbs.
    ///
    /// This is used by higher layers (e.g. the curve crate) to inject
    /// precomputed constants without running the Montgomery conversion at
    /// runtime. The supplied limbs are interpreted as-is (little-endian,
    /// `[u64; MAX_LIMBS]`), so callers must ensure they represent a value in
    /// canonical Montgomery form.
    #[inline]
    #[must_use]
    pub const fn from_mont(limbs: [u64; MAX_LIMBS]) -> Self {
        FieldElement {
            limbs,
            _p: PhantomData,
        }
    }

    /// Return the raw Montgomery-form limbs of this element.
    #[inline]
    #[must_use]
    pub fn to_montgomery_limbs(&self) -> [u64; MAX_LIMBS] {
        self.limbs
    }

    /// Construct from a `u64`, reducing modulo `p`.
    #[inline]
    #[must_use]
    pub fn from_u64(v: u64) -> Self {
        let mut int = [0u64; MAX_LIMBS];
        int[0] = v;
        let (sub, borrow) = consts::sub_limbs(&int, &P::MODULUS);
        let mut reduced = [0u64; MAX_LIMBS];
        let mut i = 0;
        while i < MAX_LIMBS {
            // borrow == 1 means int < p (valid): keep `int`; else use `int - p`.
            reduced[i] = ct_select_u64(int[i], sub[i], Choice::from_bool(borrow != 1));
            i += 1;
        }
        Self::from_integer(&reduced)
    }

    /// Construct from integer limbs (little-endian), reducing modulo `p`.
    #[inline]
    #[must_use]
    pub fn from_limbs(int: [u64; MAX_LIMBS]) -> Self {
        Self::from_integer(&int)
    }

    /// Constant-time selection between two field elements.
    #[inline]
    fn ct_select_fe(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut limbs = [0u64; MAX_LIMBS];
        let mut i = 0;
        while i < MAX_LIMBS {
            limbs[i] = ct_select_u64(a.limbs[i], b.limbs[i], choice);
            i += 1;
        }
        FieldElement {
            limbs,
            _p: PhantomData,
        }
    }

    /// Addition in `GF(p)`.
    #[inline]
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        let (r, carry) = consts::add_limbs(&self.limbs, &other.limbs);
        let ge_p = consts::limbs_ge(&r, &P::MODULUS);
        let (rsub, _) = consts::sub_limbs(&r, &P::MODULUS);
        let cond = Choice::from_bool(carry != 0 || ge_p);
        let mut out = [0u64; MAX_LIMBS];
        let mut i = 0;
        while i < MAX_LIMBS {
            out[i] = ct_select_u64(r[i], rsub[i], cond);
            i += 1;
        }
        FieldElement {
            limbs: out,
            _p: PhantomData,
        }
    }

    /// Subtraction in `GF(p)`.
    #[inline]
    #[must_use]
    pub fn sub(&self, other: &Self) -> Self {
        let (r, borrow) = consts::sub_limbs(&self.limbs, &other.limbs);
        let (padd, _) = consts::add_limbs(&r, &P::MODULUS);
        let cond = Choice::from_u8(borrow);
        let mut out = [0u64; MAX_LIMBS];
        let mut i = 0;
        while i < MAX_LIMBS {
            out[i] = ct_select_u64(r[i], padd[i], cond);
            i += 1;
        }
        FieldElement {
            limbs: out,
            _p: PhantomData,
        }
    }

    /// Additive inverse (negation) in `GF(p)`.
    #[inline]
    #[must_use]
    pub fn neg(&self) -> Self {
        let zero = [0u64; MAX_LIMBS];
        let (r, borrow) = consts::sub_limbs(&zero, &self.limbs);
        let (padd, _) = consts::add_limbs(&r, &P::MODULUS);
        let cond = Choice::from_u8(borrow);
        let mut out = [0u64; MAX_LIMBS];
        let mut i = 0;
        while i < MAX_LIMBS {
            out[i] = ct_select_u64(r[i], padd[i], cond);
            i += 1;
        }
        FieldElement {
            limbs: out,
            _p: PhantomData,
        }
    }

    /// Multiplication in `GF(p)` (Montgomery multiply).
    #[inline]
    #[must_use]
    pub fn mul(&self, other: &Self) -> Self {
        FieldElement {
            limbs: Self::mont_mul(&self.limbs, &other.limbs),
            _p: PhantomData,
        }
    }

    /// Squaring in `GF(p)`.
    #[inline]
    #[must_use]
    pub fn square(&self) -> Self {
        self.mul(self)
    }

    /// Doubling in `GF(p)`.
    #[inline]
    #[must_use]
    pub fn double(&self) -> Self {
        self.add(self)
    }

    /// Whether this element is zero, as a [`Choice`].
    #[inline]
    #[must_use]
    pub fn is_zero(&self) -> Choice {
        let mut acc = 0u64;
        let mut i = 0;
        while i < MAX_LIMBS {
            acc |= self.limbs[i];
            i += 1;
        }
        Choice::from_u8((acc == 0) as u8)
    }

    /// Exponentiation by a fixed (possibly secret) exponent, constant-time in the
    /// base. The exponent is little-endian limbs and must be `< p`.
    #[inline]
    #[must_use]
    pub fn pow(&self, exp: &[u64; MAX_LIMBS]) -> Self {
        let mut result = Self::one();
        let mut limb = MAX_LIMBS;
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

    /// Exponentiation by a *public* exponent (variable-time is fine; no secret is
    /// involved). The exponent is little-endian `u64` words of arbitrary length.
    #[inline]
    #[must_use]
    pub fn pow_vartime(&self, exp: &[u64]) -> Self {
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

    /// Multiplicative inverse, computed via Fermat's little theorem (`a^(p-2)`).
    /// Returns `None` iff `self == 0`.
    #[inline]
    #[must_use]
    pub fn invert(&self) -> CtOption<Self> {
        let r = self.pow(&Self::MOD_MINUS_2);
        CtOption::new(r, self.is_zero().not())
    }

    /// Square root via Tonelli–Shanks. Returns `Some(s)` with `s^2 == self` iff
    /// `self` is a quadratic residue; `None` otherwise.
    #[inline]
    #[must_use]
    pub fn sqrt(&self) -> CtOption<Self> {
        if P::S == 1 {
            // p ≡ 3 (mod 4): sqrt(a) = a^((p+1)/4).
            let r = self.pow(&Self::SQRT_EXP);
            let ok = r.square().ct_eq(self);
            CtOption::new(r, ok)
        } else {
            self.tonelli_shanks()
        }
    }

    fn tonelli_shanks(&self) -> CtOption<Self> {
        let z = Self::from_integer(&consts::find_nonresidue(&P::MODULUS));
        let mut c = z.pow(&Self::T); // order 2^S
        let mut x = self.pow(&Self::T_PLUS_1_OVER_2);
        let mut b = self.pow(&Self::T);
        let s = P::S;
        let mut i = s;
        let mut result = x;
        let mut done = Choice::FALSE;
        let mut step = 0u32;
        while step < s {
            let b_is_one = b.ct_eq(&Self::one());
            // Smallest e in [1, i) with b^(2^e) == 1. Per HAC §3.36 the search is
            // `1 <= i < E` (strictly below the current exponent), which keeps
            // `e2 = i - found - 1` non-negative and matches the invariant
            // `b^(2^(i-1)) == 1`.
            let mut found = 0u32;
            let mut t = b;
            let mut k = 1u32;
            while k < i {
                t = t.square();
                let is_one = t.ct_eq(&Self::one());
                if is_one.into_bool() && found == 0 {
                    found = k;
                }
                k += 1;
            }
            let e2 = i.saturating_sub(found).saturating_sub(1);
            let mut d = c;
            let mut sq = 0u32;
            while sq < e2 {
                d = d.square();
                sq += 1;
            }
            let x_new = x.mul(&d);
            let c_new = d.square();
            let b_new = b.mul(&c_new);
            // Apply the update only while we have not yet reached 1; applying once
            // `b == 1` would corrupt an already-correct `x`.
            let apply = done.not().and(b_is_one.not());
            x = Self::ct_select_fe(&x, &x_new, apply);
            c = Self::ct_select_fe(&c, &c_new, apply);
            b = Self::ct_select_fe(&b, &b_new, apply);
            result = x;
            done = done.or(b_is_one);
            if apply.into_bool() {
                i = found;
            }
            step += 1;
        }
        let ok = result.square().ct_eq(self);
        CtOption::new(result, ok)
    }

    /// Canonical fixed-width big-endian encoding (`MAX_LIMBS * 8` bytes). For
    /// fields with fewer than `MAX_LIMBS` significant limbs, the most-significant
    /// bytes are zero and the value occupies the low `P::LIMBS * 8` bytes.
    #[inline]
    #[must_use]
    pub fn to_bytes(&self) -> [u8; MAX_LIMBS * 8] {
        let int = self.to_integer();
        let mut out = [0u8; MAX_LIMBS * 8];
        let base = (MAX_LIMBS - P::LIMBS) * 8;
        let mut idx = base;
        let mut limb = P::LIMBS;
        while limb > 0 {
            limb -= 1;
            let v = int[limb];
            let mut b = 0;
            while b < 8 {
                out[idx + b] = (v >> (56 - b * 8)) as u8;
                b += 1;
            }
            idx += 8;
        }
        out
    }

    /// Parse a canonical big-endian encoding, rejecting non-canonical input
    /// (value `>= p`, including non-zero high bytes) in constant time. Wrong
    /// length yields `None`.
    #[inline]
    #[must_use]
    pub fn from_bytes(slice: &[u8]) -> CtOption<Self> {
        if slice.len() != MAX_LIMBS * 8 {
            return CtOption::none();
        }
        let mut int = [0u64; MAX_LIMBS];
        let base = (MAX_LIMBS - P::LIMBS) * 8;
        let mut pos = 0;
        while pos < P::LIMBS {
            let mut v = 0u64;
            let mut b = 0;
            while b < 8 {
                v = (v << 8) | (slice[base + pos * 8 + b] as u64);
                b += 1;
            }
            // `to_bytes` writes limb `L` at offset `base + (P::LIMBS - 1 - L) * 8`,
            // so position `pos` within the significant block holds limb `LIMBS-1-pos`.
            int[P::LIMBS - 1 - pos] = v;
            pos += 1;
        }
        let (sub, borrow) = consts::sub_limbs(&int, &P::MODULUS);
        // borrow == 1 means int < p (canonical).
        let valid = Choice::from_bool(borrow == 1);
        let mut reduced = [0u64; MAX_LIMBS];
        let mut i = 0;
        while i < MAX_LIMBS {
            reduced[i] = ct_select_u64(sub[i], int[i], valid);
            i += 1;
        }
        CtOption::new(Self::from_integer(&reduced), valid)
    }
}

impl<P: FieldParams> CtEq for FieldElement<P> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        let mut acc = 0u64;
        let mut i = 0;
        while i < MAX_LIMBS {
            acc |= self.limbs[i] ^ other.limbs[i];
            i += 1;
        }
        Choice::from_u8((acc == 0) as u8)
    }
}

impl<P: FieldParams> Neg for FieldElement<P> {
    type Output = Self;
    #[inline]
    fn neg(self) -> Self {
        FieldElement::neg(&self)
    }
}

impl<P: FieldParams> CtSelect for FieldElement<P> {
    #[inline]
    fn ct_select(cond: tpt_crypto_ct::Choice, a: Self, b: Self) -> Self {
        let mut limbs = [0u64; MAX_LIMBS];
        let mut i = 0;
        while i < MAX_LIMBS {
            limbs[i] = u64::ct_select(cond, a.limbs[i], b.limbs[i]);
            i += 1;
        }
        FieldElement {
            limbs,
            _p: PhantomData,
        }
    }
}

impl<P: FieldParams> PartialEq for FieldElement<P> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into_bool()
    }
}
impl<P: FieldParams> Eq for FieldElement<P> {}

impl<P: FieldParams> Default for FieldElement<P> {
    #[inline]
    fn default() -> Self {
        Self::zero()
    }
}

impl<P: FieldParams> fmt::Debug for FieldElement<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FieldElement(0x")?;
        let int = self.to_integer();
        let mut limb = MAX_LIMBS;
        while limb > 0 {
            limb -= 1;
            write!(f, "{:016x}", int[limb])?;
        }
        write!(f, ")")
    }
}

impl<P: FieldParams> fmt::Display for FieldElement<P> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self, f)
    }
}

/// Abstract field interface shared by [`FieldElement`] and the extension towers.
///
/// All methods are constant-time in their secret operands except
/// [`Field::pow_vartime`], which is meant for *public* exponents only.
pub trait Field: Copy + Clone + Default + PartialEq + fmt::Debug + Send + Sync + 'static {
    /// The additive identity.
    fn zero() -> Self;
    /// The multiplicative identity.
    fn one() -> Self;
    /// Embed a small integer into the field (reduced modulo the characteristic).
    fn from_u64(v: u64) -> Self;
    /// Constant-time selection between two field elements. If `c == 1` returns `b`.
    fn ct_select(a: &Self, b: &Self, c: Choice) -> Self;
    /// Constant-time zero test.
    fn is_zero(&self) -> Choice;
    /// `self + other`.
    fn add(&self, other: &Self) -> Self;
    /// `self - other`.
    fn sub(&self, other: &Self) -> Self;
    /// `-self`.
    fn neg(&self) -> Self;
    /// `self * other`.
    fn mul(&self, other: &Self) -> Self;
    /// `self^2`.
    fn square(&self) -> Self {
        self.mul(self)
    }
    /// `self + self`.
    fn double(&self) -> Self {
        self.add(self)
    }
    /// `self^{-1}`, or `None` for zero.
    fn invert(&self) -> CtOption<Self>;
    /// `self^exp` for a public exponent (little-endian `u64` words).
    fn pow_vartime(&self, exp: &[u64]) -> Self;
    /// Square root, or `None` if not a quadratic residue.
    fn sqrt(&self) -> CtOption<Self>;
}

impl<P: FieldParams> Field for FieldElement<P> {
    #[inline]
    fn zero() -> Self {
        Self::zero()
    }
    #[inline]
    fn one() -> Self {
        Self::one()
    }
    #[inline]
    fn from_u64(v: u64) -> Self {
        Self::from_u64(v)
    }
    #[inline]
    fn ct_select(a: &Self, b: &Self, c: Choice) -> Self {
        Self::ct_select_fe(a, b, c)
    }
    #[inline]
    fn is_zero(&self) -> Choice {
        self.is_zero()
    }
    #[inline]
    fn add(&self, other: &Self) -> Self {
        Self::add(self, other)
    }
    #[inline]
    fn sub(&self, other: &Self) -> Self {
        Self::sub(self, other)
    }
    #[inline]
    fn neg(&self) -> Self {
        self.neg()
    }
    #[inline]
    fn mul(&self, other: &Self) -> Self {
        Self::mul(self, other)
    }
    #[inline]
    fn invert(&self) -> CtOption<Self> {
        self.invert()
    }
    #[inline]
    fn pow_vartime(&self, exp: &[u64]) -> Self {
        Self::pow_vartime(self, exp)
    }
    #[inline]
    fn sqrt(&self) -> CtOption<Self> {
        self.sqrt()
    }
}

#[cfg(test)]
mod const_audit {
    extern crate std;
    use super::*;
    use crate::params::{Ed25519FieldParams, Ed25519ScalarParams};
    use std::eprintln;

    // Reference 320-bit little-endian arithmetic to cross-check the derived
    // Montgomery constants for Ed25519Scalar (L).
    const L: [u64; 5] = [
        0xEDD3_F55C_1A63_1258,
        0x14DE_F9DE_A2F7_9CD6,
        0x0000_0000_0000_0000,
        0x1000_0000_0000_0000,
        0,
    ];

    fn limb_ge(a: &[u64; 5], b: &[u64; 5]) -> bool {
        let mut i = 5;
        while i > 0 {
            i -= 1;
            if a[i] > b[i] {
                return true;
            }
            if a[i] < b[i] {
                return false;
            }
        }
        true
    }

    fn limb_sub(a: &[u64; 5], b: &[u64; 5]) -> [u64; 5] {
        let mut out = [0u64; 5];
        let mut borrow = 0u64;
        for i in 0..5 {
            let (d1, b1) = a[i].overflowing_sub(b[i]);
            let (d, b2) = d1.overflowing_sub(borrow);
            out[i] = d;
            borrow = (b1 | b2) as u64;
        }
        out
    }

    #[test]
    fn audit_scalar_constants() {
        // Proper 2^256 mod L via repeated doubling with a correct reduction.
        assert_eq!(mul_mod_ref(&[1, 0, 0, 0, 0], &[1, 0, 0, 0, 0])[0], 1, "mul_mod_ref 1*1");
        assert_eq!(mul_mod_ref(&[2, 0, 0, 0, 0], &[3, 0, 0, 0, 0])[0], 6, "mul_mod_ref 2*3");
        assert_eq!(mul_mod_ref(&[7, 0, 0, 0, 0], &[6, 0, 0, 0, 0])[0], 42, "mul_mod_ref 7*6");

        let mut acc = [0u64; 5];
        acc[0] = 1;
        let mut m6 = [0u64; 6];
        m6[0] = L[0];
        m6[1] = L[1];
        m6[2] = L[2];
        m6[3] = L[3];
        m6[4] = L[4];
        for _ in 0..256 {
            let mut t = [0u64; 6];
            let mut carry: u128 = 0;
            for i in 0..5 {
                let s = (acc[i] as u128) * 2 + carry;
                t[i] = s as u64;
                carry = s >> 64;
            }
            t[5] = carry as u64;
            // compare t[0..6] with m6
            let ge = {
                let mut i = 6;
                let mut r = true;
                let mut lt = false;
                while i > 0 {
                    i -= 1;
                    if t[i] > m6[i] {
                        r = true;
                        break;
                    }
                    if t[i] < m6[i] {
                        lt = true;
                        break;
                    }
                }
                r && !lt
            };
            let red = if ge { limb_sub6(&t, &m6) } else { t };
            acc[0] = red[0];
            acc[1] = red[1];
            acc[2] = red[2];
            acc[3] = red[3];
            acc[4] = red[4];
        }

        // --- Base field cross-check (is mont_mul globally broken or scalar-specific?) ---
        {
            let bf = FieldElement::<Ed25519FieldParams>::from_u64(0x1234_5678_9abc_def0);
            let bf2 = bf.mul(&bf);
            let bfb = bf2.to_bytes();
            eprintln!(
                "BASE x^2 plain tail = {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                bfb[40], bfb[41], bfb[42], bfb[43], bfb[44], bfb[45], bfb[46], bfb[47]
            );
            let p255: [u64; 5] = [
                0xFFFF_FFFF_FFFF_FFED,
                0xFFFF_FFFF_FFFF_FFFF,
                0xFFFF_FFFF_FFFF_FFFF,
                0x7FFF_FFFF_FFFF_FFFF,
                0,
            ];
            let xv = [0x9abc_def0u64, 0x1234_5678, 0, 0, 0];
            let expected = mul_mod_ref(&xv, &xv);
            eprintln!(
                "BASE ref x^2 tail = {:016x}{:016x}{:016x}{:016x}",
                expected[3], expected[2], expected[1], expected[0]
            );
        }

        // Compare to the field-derived ONE_MONT.
        let one_mont = Ed25519ScalarParams::ONE_MONT;
        let matches = acc[0] == one_mont[0]
            && acc[1] == one_mont[1]
            && acc[2] == one_mont[2]
            && acc[3] == one_mont[3]
            && one_mont[4] == 0
            && one_mont[5] == 0;
        eprintln!("ref R=2^256 mod L = {:016x}{:016x}{:016x}{:016x}", acc[3], acc[2], acc[1], acc[0]);
        eprintln!("ONE_MONT          = {:016x}{:016x}{:016x}{:016x}", one_mont[3], one_mont[2], one_mont[1], one_mont[0]);
        assert!(matches, "ONE_MONT mismatch vs reference");

        // Reference R^2 mod L.
        let r = acc;
        let r2 = mul_mod_ref(&r, &r);
        let field_r2 = Ed25519ScalarParams::R2;
        let r2ok = r2[0] == field_r2[0]
            && r2[1] == field_r2[1]
            && r2[2] == field_r2[2]
            && r2[3] == field_r2[3]
            && field_r2[4] == 0
            && field_r2[5] == 0;
        eprintln!("ref R2  = {:016x}{:016x}{:016x}{:016x}", r2[3], r2[2], r2[1], r2[0]);
        eprintln!("field R2= {:016x}{:016x}{:016x}{:016x}", field_r2[3], field_r2[2], field_r2[1], field_r2[0]);
        assert!(r2ok, "R2 mismatch vs reference");

        // Reference CIOS Montgomery multiply to cross-check the field's `mont_mul`.
        let p = Ed25519ScalarParams::MODULUS;
        let mu = Ed25519ScalarParams::MU;
        let a = Ed25519ScalarParams::ONE_MONT;
        let r_ref = cios_ref(&a, &a, &p, mu, 4);
        eprintln!("REF ONE_MONT^2 = {:016x}{:016x}{:016x}{:016x}", r_ref[3], r_ref[2], r_ref[1], r_ref[0]);
        let mut y: u64 = L[0];
        for _ in 0..5 {
            y = y.wrapping_mul(2u64.wrapping_sub(L[0].wrapping_mul(y)));
        }
        let ref_mu = y.wrapping_neg();
        eprintln!("ref mu = {:016x}, field mu = {:016x}", ref_mu, Ed25519ScalarParams::MU);
        assert_eq!(ref_mu, Ed25519ScalarParams::MU);

        // to_bytes(ONE_MONT) must equal the plain integer 1.
        let r_elem = FieldElement::<Ed25519ScalarParams>::from_mont(Ed25519ScalarParams::ONE_MONT);
        let rb = r_elem.to_bytes();
        eprintln!("to_bytes(ONE_MONT) tail = {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            rb[40], rb[41], rb[42], rb[43], rb[44], rb[45], rb[46], rb[47]);

        // ONE_MONT * ONE_MONT (Montgomery) must equal ONE_MONT, whose plain form is 1.
        let a = FieldElement::<Ed25519ScalarParams>::from_mont(Ed25519ScalarParams::ONE_MONT);
        let aa = a.mul(&a);
        let aab = aa.to_bytes();
        eprintln!("ONE_MONT^2 plain tail = {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            aab[40], aab[41], aab[42], aab[43], aab[44], aab[45], aab[46], aab[47]);

        // Reference: (plain 1 * plain 1) mod L = 1.
        // Build field element for plain value 0x1234... and multiply.
        let x = FieldElement::<Ed25519ScalarParams>::from_u64(0x1234_5678_9abc_def0);
        let xx = x.mul(&x);
        let xxb = xx.to_bytes();
        eprintln!("x^2 plain tail = {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
            xxb[40], xxb[41], xxb[42], xxb[43], xxb[44], xxb[45], xxb[46], xxb[47]);
        // Expected x^2 mod L via reference mul_mod.
        let xv = [0x9abc_def0u64, 0x1234_5678, 0, 0, 0];
        let expected = mul_mod_ref(&xv, &xv);
        eprintln!("ref x^2 tail = {:016x}{:016x}{:016x}{:016x}",
            expected[3], expected[2], expected[1], expected[0]);

    }

    fn limb_sub6(a: &[u64; 6], b: &[u64; 6]) -> [u64; 6] {
        let mut out = [0u64; 6];
        let mut borrow = 0u64;
        for i in 0..6 {
            let (d1, b1) = a[i].overflowing_sub(b[i]);
            let (d, b2) = d1.overflowing_sub(borrow);
            out[i] = d;
            borrow = (b1 | b2) as u64;
        }
        out
    }

    // Mul two 5-limb values mod L using schoolbook + long division.
    fn mul_mod_ref(a: &[u64; 5], b: &[u64; 5]) -> [u64; 5] {
        let mut t = [0u64; 10];
        for i in 0..5 {
            let mut carry: u128 = 0;
            for j in 0..5 {
                let prod = (a[i] as u128) * (b[j] as u128) + (t[i + j] as u128) + carry;
                t[i + j] = prod as u64;
                carry = prod >> 64;
            }
            let mut k = i + 5;
            let mut c = carry;
            while c != 0 {
                let s = (t[k] as u128) + c;
                t[k] = s as u64;
                c = s >> 64;
                k += 1;
            }
        }
        // long division by L (5 limbs).
        let mut r = t;
        let mut bit = (10u32 * 64) - 1;
        while bit >= 252 {
            // shift L left by (bit - 251)
            let shift = bit - 251;
            let mut sm = [0u64; 10];
            let ls = (shift / 64) as usize;
            let bs = shift % 64;
            for i in 0..5 {
                if ls + i < 10 {
                    sm[ls + i] = sm[ls + i].wrapping_add(L[i] << bs);
                }
                if bs > 0 && ls + i + 1 < 10 {
                    sm[ls + i + 1] = sm[ls + i + 1].wrapping_add(L[i] >> (64 - bs));
                }
            }
            if big_ge(&r, &sm) {
                r = big_sub(&r, &sm);
            }
            bit -= 1;
        }
        let mut out = [0u64; 5];
        out.copy_from_slice(&r[0..5]);
        if limb_ge(&out, &L) {
            out = limb_sub(&out, &L);
        }
        out
    }

    fn big_ge(a: &[u64; 10], b: &[u64; 10]) -> bool {
        let mut i = 10;
        while i > 0 {
            i -= 1;
            if a[i] > b[i] {
                return true;
            }
            if a[i] < b[i] {
                return false;
            }
        }
        true
    }

    fn big_sub(a: &[u64; 10], b: &[u64; 10]) -> [u64; 10] {
        let mut out = [0u64; 10];
        let mut borrow = 0u64;
        for i in 0..10 {
            let (d1, b1) = a[i].overflowing_sub(b[i]);
            let (d, b2) = d1.overflowing_sub(borrow);
            out[i] = d;
            borrow = (b1 | b2) as u64;
        }
        out
    }

    // Independent standard CIOS Montgomery multiplication (n limbs) used only to
    // cross-check the field's `mont_mul`.
    fn cios_ref(a: &[u64; 6], b: &[u64; 6], p: &[u64; 6], mu: u64, n: usize) -> [u64; 6] {
        let mut t = [0u64; 7];
        let mut i = 0;
        while i < n {
            let ai = a[i];
            let mut c: u128 = 0;
            let mut j = 0;
            while j < n {
                let prod = (ai as u128) * (b[j] as u128);
                let sum = (t[j] as u128) + prod + c;
                t[j] = sum as u64;
                c = sum >> 64;
                j += 1;
            }
            let sum = (t[n] as u128) + c;
            t[n] = sum as u64;
            c = sum >> 64;
            let m = (t[0].wrapping_mul(mu)) as u128;
            let s0 = (t[0] as u128) + m * (p[0] as u128);
            c = c + (s0 >> 64);
            let mut j = 1;
            while j < n {
                let mp = m * (p[j] as u128);
                let sum2 = (t[j] as u128) + mp + c;
                t[j - 1] = sum2 as u64;
                c = sum2 >> 64;
                j += 1;
            }
            let sum3 = (t[n] as u128) + c;
            t[n - 1] = sum3 as u64;
            t[n] = (sum3 >> 64) as u64;
            i += 1;
        }
        // Normalize: t is in [0, 2p); subtract p once if t >= p.
        // Compare t[0..n+1] with p[0..n] (p zero-extended).
        let mut ge = true;
        let mut lt = false;
        let mut k = n + 1;
        while k > 0 {
            k -= 1;
            let tv = if k <= n { t[k] } else { 0 };
            let pv = if k < n { p[k] } else { 0 };
            if tv > pv {
                ge = true;
                lt = false;
                break;
            }
            if tv < pv {
                ge = false;
                lt = true;
                break;
            }
        }
        let mut out = [0u64; 6];
        if ge && !lt {
            let mut borrow = 0u64;
            for idx in 0..=n {
                let pv = if idx < n { p[idx] } else { 0 };
                let (d1, b1) = t[idx].overflowing_sub(pv);
                let (d, b2) = d1.overflowing_sub(borrow);
                out[idx] = d;
                borrow = (b1 | b2) as u64;
            }
            out
        } else {
            let mut o = [0u64; 6];
            o[..=n].copy_from_slice(&t[..=n]);
            o
        }
    }
}
