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
    /// The Montgomery constant `R^2 mod p` (compile-time derived).
    const R2: [u64; MAX_LIMBS] = consts::r2_of(&P::MODULUS, P::LIMBS);
    /// The Montgomery constant `-p^{-1} mod 2^64` (compile-time derived).
    const MU: u64 = consts::mu_of(&P::MODULUS);
    /// The Montgomery constant `R mod p` = the Montgomery encoding of `1`.
    const ONE_MONT: [u64; MAX_LIMBS] = consts::one_mont_of(&P::MODULUS, P::LIMBS);
    /// The Fermat inversion exponent `p - 2`.
    const MOD_MINUS_2: [u64; MAX_LIMBS] = consts::mod_minus_2(&P::MODULUS);
    /// `T = (p - 1) >> S`.
    const T: [u64; MAX_LIMBS] = consts::t_of(&P::MODULUS, P::S);
    /// `(T + 1) >> 1`, used by Tonelli–Shanks.
    const T_PLUS_1_OVER_2: [u64; MAX_LIMBS] =
        consts::t_plus_1_over_2(&consts::t_of(&P::MODULUS, P::S));
    /// `(p + 1) >> 2`, the square-root exponent for `p ≡ 3 (mod 4)`.
    const SQRT_EXP: [u64; MAX_LIMBS] = consts::sqrt_exp(&P::MODULUS);

    /// Constant-time Montgomery multiplication (CIOS).
    #[inline]
    fn mont_mul(a: &[u64; MAX_LIMBS], b: &[u64; MAX_LIMBS]) -> [u64; MAX_LIMBS] {
        let p = &P::MODULUS;
        let mu = Self::MU;
        let mut t = [0u64; MAX_LIMBS + 1];
        let mut i = 0;
        while i < P::LIMBS {
            let ai = a[i];
            let mut c: u128 = 0;
            let mut j = 0;
            while j < P::LIMBS {
                let prod = (ai as u128) * (b[j] as u128);
                let sum = (t[j] as u128) + prod + c;
                t[j] = sum as u64;
                c = sum >> 64;
                j += 1;
            }
            let sum = (t[MAX_LIMBS] as u128) + c;
            t[MAX_LIMBS] = sum as u64;
            c = sum >> 64;
            // m = (t[0] * mu) mod 2^64
            let m = (t[0].wrapping_mul(mu)) as u128;
            // (t[0] + m*p[0]) is a multiple of 2^64; discard its low word, keep carry.
            let s0 = (t[0] as u128) + m * (p[0] as u128);
            c = c + (s0 >> 64);
            let mut j = 1;
            while j < P::LIMBS {
                let mp = m * (p[j] as u128);
                let sum2 = (t[j] as u128) + mp + c;
                t[j - 1] = sum2 as u64;
                c = sum2 >> 64;
                j += 1;
            }
            let sum3 = (t[MAX_LIMBS] as u128) + c;
            t[MAX_LIMBS - 1] = sum3 as u64;
            t[MAX_LIMBS] = (sum3 >> 64) as u64;
            i += 1;
        }
        // Normalize t (MAX+1 limbs, in [0, 2p)) to [0, p) with a ct conditional subtract.
        let mut r = [0u64; MAX_LIMBS + 1];
        r[0..MAX_LIMBS].copy_from_slice(&t[0..MAX_LIMBS]);
        r[MAX_LIMBS] = t[MAX_LIMBS];
        let mut pp = [0u64; MAX_LIMBS + 1];
        pp[0..MAX_LIMBS].copy_from_slice(p);
        let (sub, borrow) = consts::sub_limbs(&r, &pp);
        let ge = borrow == 0;
        let mut out = [0u64; MAX_LIMBS];
        let mut k = 0;
        while k < MAX_LIMBS {
            out[k] = ct_select_u64(r[k], sub[k], Choice::from_bool(ge));
            k += 1;
        }
        out
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
            // Smallest e in [1, i] with b^(2^e) == 1.
            let mut found = 0u32;
            let mut t = b;
            let mut k = 1u32;
            while k <= i {
                t = t.square();
                let is_one = t.ct_eq(&Self::one());
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
