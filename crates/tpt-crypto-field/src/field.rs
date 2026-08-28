//! Prime field arithmetic over a compile-time modulus.
//!
//! [`FieldElement<P, LIMBS>`] stores a field element in **Montgomery form** and
//! monomorphizes a fully unrolled, stack-only, constant-time arithmetic routine
//! per curve (the compiler specializes the limb count `LIMBS` and the modulus
//! `P`). All operations — add/sub/neg/mul/square/reduce/invert — are implemented
//! with bitwise masks and `cmov`, never conditional branches on secret data.

use core::fmt;
use core::marker::PhantomData;

use crate::ct::{Choice, CtOption, CtEq};
use crate::limb::ct_select_u64;

/// Parameters of a prime field `GF(p)`.
///
/// Implementors supply only the [`MODULUS`] and the exponent [`S`] from the
/// factorization `p - 1 = 2^S * T` (with `T` odd). Every other constant
/// (`MU`, `R2`, `ONE_MONT`, `T`, the square-root exponent, a quadratic
/// non-residue, …) is derived at compile time by [`FieldElement`] from these two.
///
/// [`MODULUS`]: FieldParams::MODULUS
/// [`S`]: FieldParams::S
pub trait FieldParams<const LIMBS: usize = 4>:
    Copy + Clone + Default + Eq + fmt::Debug + Send + Sync + 'static
{
    /// The prime modulus `p`, little-endian 64-bit limbs, with `p < 2^(64*LIMBS)`.
    const MODULUS: [u64; LIMBS];

    /// The exponent `S` in `p - 1 = 2^S * T` (number of factors of two in `p-1`).
    const S: u32;
}

/// A constant-time, stack-only element of `GF(p)`.
///
/// Internally the value is held in Montgomery form. Construction via
/// [`FieldElement::from_bytes`] (canonical encoding, constant-time rejection of
/// non-canonical input) or [`FieldElement::from_u64`].
#[derive(Clone, Copy)]
pub struct FieldElement<P: FieldParams<L>, const L: usize> {
    /// Montgomery-form limbs (little-endian).
    limbs: [u64; L],
    _p: PhantomData<P>,
}

impl<P: FieldParams<L>, const L: usize> FieldElement<P, L> {
    /// The Montgomery constant `R^2 mod p` (compile-time derived).
    const R2: [u64; L] = crate::consts::r2_of(&P::MODULUS);
    /// The Montgomery constant `-p^{-1} mod 2^64` (compile-time derived).
    const MU: u64 = crate::consts::mu_of(&P::MODULUS);
    /// The Montgomery constant `R mod p` = the Montgomery encoding of `1`.
    const ONE_MONT: [u64; L] = crate::consts::one_mont_of(&P::MODULUS);
    /// The Fermat inversion exponent `p - 2`.
    const MOD_MINUS_2: [u64; L] = crate::consts::mod_minus_2(&P::MODULUS);
    /// `T = (p - 1) >> S`.
    const T: [u64; L] = crate::consts::t_of(&P::MODULUS, P::S);
    /// `(T + 1) >> 1`, used by Tonelli–Shanks.
    const T_PLUS_1_OVER_2: [u64; L] =
        crate::consts::t_plus_1_over_2(&crate::consts::t_of(&P::MODULUS, P::S));
    /// `(p + 1) >> 2`, the square-root exponent for `p ≡ 3 (mod 4)`.
    const SQRT_EXP: [u64; L] = crate::consts::sqrt_exp(&P::MODULUS);
    /// A quadratic non-residue modulo `p` (compile-time search).
    const Z: [u64; L] = crate::consts::find_nonresidue(&P::MODULUS);

    /// Constant-time Montgomery multiplication (CIOS).
    #[inline]
    fn mont_mul(a: &[u64; L], b: &[u64; L]) -> [u64; L] {
        let p = &P::MODULUS;
        let mu = Self::MU;
        let mut t = [0u64; L + 1];
        let mut i = 0;
        while i < L {
            let ai = a[i];
            let mut c: u128 = 0;
            let mut j = 0;
            while j < L {
                let prod = (ai as u128) * (b[j] as u128);
                let sum = (t[j] as u128) + prod + c;
                t[j] = sum as u64;
                c = sum >> 64;
                j += 1;
            }
            let sum = (t[L] as u128) + c;
            t[L] = sum as u64;
            c = sum >> 64;
            // m = (t[0] * mu) mod 2^64
            let m = (t[0].wrapping_mul(mu)) as u128;
            // (t[0] + m*p[0]) is a multiple of 2^64; discard its low word, keep carry.
            let s0 = (t[0] as u128) + m * (p[0] as u128);
            c = c + (s0 >> 64);
            let mut j = 1;
            while j < L {
                let mp = m * (p[j] as u128);
                let sum2 = (t[j] as u128) + mp + c;
                t[j - 1] = sum2 as u64;
                c = sum2 >> 64;
                j += 1;
            }
            let sum3 = (t[L] as u128) + c;
            t[L - 1] = sum3 as u64;
            t[L] = (sum3 >> 64) as u64;
            i += 1;
        }
        // Normalize t (L+1 limbs, in [0, 2p)) to [0, p) with a ct conditional subtract.
        let mut r = [0u64; L + 1];
        r[0..L].copy_from_slice(&t[0..L]);
        r[L] = t[L];
        let mut pp = [0u64; L + 1];
        pp[0..L].copy_from_slice(p);
        let (sub, borrow) = crate::consts::sub_limbs(&r, &pp);
        let ge = !borrow;
        let mut out = [0u64; L];
        let mut k = 0;
        while k < L {
            out[k] = ct_select_u64(r[k], sub[k], Choice::from_u8(if ge { 1 } else { 0 }));
            k += 1;
        }
        out
    }

    /// Encode an integer (`< p`) into Montgomery form.
    #[inline]
    fn from_integer(int: &[u64; L]) -> Self {
        FieldElement {
            limbs: Self::mont_mul(int, &Self::R2),
            _p: PhantomData,
        }
    }

    /// Decode from Montgomery form to a plain integer (`< p`).
    #[inline]
    fn to_integer(&self) -> [u64; L] {
        let mut one = [0u64; L];
        one[0] = 1;
        Self::mont_mul(&self.limbs, &one)
    }

    /// Build the additive identity `0`.
    #[inline]
    #[must_use]
    pub fn zero() -> Self {
        FieldElement {
            limbs: [0u64; L],
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

    /// Construct from a `u64`, reducing modulo `p`.
    #[inline]
    #[must_use]
    pub fn from_u64(v: u64) -> Self {
        let mut int = [0u64; L];
        int[0] = v;
        let (sub, borrow) = crate::consts::sub_limbs(&int, &P::MODULUS);
        let mut reduced = [0u64; L];
        let mut i = 0;
        while i < L {
            reduced[i] = ct_select_u64(int[i], sub[i], Choice::from_u8(if borrow == 1 { 0 } else { 1 }));
            i += 1;
        }
        Self::from_integer(&reduced)
    }

    /// Constant-time selection between two field elements.
    #[inline]
    fn ct_select_fe(a: &Self, b: &Self, choice: Choice) -> Self {
        let mut limbs = [0u64; L];
        let mut i = 0;
        while i < L {
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
        let (r, carry) = crate::consts::add_limbs(&self.limbs, &other.limbs);
        let ge_p = crate::consts::limbs_ge(&r, &P::MODULUS);
        let (rsub, _) = crate::consts::sub_limbs(&r, &P::MODULUS);
        let cond = Choice::from_bool(carry != 0 || ge_p);
        let mut out = [0u64; L];
        let mut i = 0;
        while i < L {
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
        let (r, borrow) = crate::consts::sub_limbs(&self.limbs, &other.limbs);
        let (padd, _) = crate::consts::add_limbs(&r, &P::MODULUS);
        let cond = Choice::from_u8(borrow);
        let mut out = [0u64; L];
        let mut i = 0;
        while i < L {
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
        let zero = [0u64; L];
        let (r, borrow) = crate::consts::sub_limbs(&zero, &self.limbs);
        let (padd, _) = crate::consts::add_limbs(&r, &P::MODULUS);
        let cond = Choice::from_u8(borrow);
        let mut out = [0u64; L];
        let mut i = 0;
        while i < L {
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
        while i < L {
            acc |= self.limbs[i];
            i += 1;
        }
        Choice::from_u8((acc == 0) as u8)
    }

    /// Exponentiation by a fixed (possibly secret) exponent, constant-time in the
    /// base. The exponent is little-endian limbs and must be `< p`.
    #[inline]
    #[must_use]
    pub fn pow(&self, exp: &[u64; L]) -> Self {
        let mut result = Self::one();
        let mut limb = L;
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
        let z = Self::from_integer(&Self::Z);
        let c = z.pow(&Self::T); // order 2^S
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

    /// Canonical big-endian encoding (`LIMBS * 8` bytes).
    #[inline]
    #[must_use]
    pub fn to_bytes(&self) -> [u8; L * 8] {
        let int = self.to_integer();
        let mut out = [0u8; L * 8];
        let mut idx = 0;
        let mut limb = L;
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
    /// (value `>= p`) in constant time. Wrong length yields `None`.
    #[inline]
    #[must_use]
    pub fn from_bytes(slice: &[u8]) -> CtOption<Self> {
        if slice.len() != L * 8 {
            return CtOption::none();
        }
        let mut int = [0u64; L];
        let mut limb = 0;
        let mut idx = 0;
        while limb < L {
            let mut v = 0u64;
            let mut b = 0;
            while b < 8 {
                v = (v << 8) | (slice[idx + b] as u64);
                b += 1;
            }
            int[limb] = v;
            limb += 1;
            idx += 8;
        }
        let (sub, borrow) = crate::consts::sub_limbs(&int, &P::MODULUS);
        // borrow == 0 means int >= p (non-canonical) -> reject.
        let valid = Choice::from_u8(borrow);
        let mut reduced = [0u64; L];
        let mut i = 0;
        while i < L {
            reduced[i] = ct_select_u64(int[i], sub[i], valid);
            i += 1;
        }
        CtOption::new(Self::from_integer(&reduced), valid)
    }
}

impl<P: FieldParams<L>, const L: usize> CtEq for FieldElement<P, L> {
    #[inline]
    fn ct_eq(&self, other: &Self) -> Choice {
        let mut acc = 0u64;
        let mut i = 0;
        while i < L {
            acc |= self.limbs[i] ^ other.limbs[i];
            i += 1;
        }
        Choice::from_u8((acc == 0) as u8)
    }
}

impl<P: FieldParams<L>, const L: usize> PartialEq for FieldElement<P, L> {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into_bool()
    }
}
impl<P: FieldParams<L>, const L: usize> Eq for FieldElement<P, L> {}

impl<P: FieldParams<L>, const L: usize> Default for FieldElement<P, L> {
    #[inline]
    fn default() -> Self {
        Self::zero()
    }
}

impl<P: FieldParams<L>, const L: usize> fmt::Debug for FieldElement<P, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "FieldElement(0x")?;
        let int = self.to_integer();
        let mut limb = L;
        while limb > 0 {
            limb -= 1;
            write!(f, "{:016x}", int[limb])?;
        }
        write!(f, ")")
    }
}

impl<P: FieldParams<L>, const L: usize> fmt::Display for FieldElement<P, L> {
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

impl<P: FieldParams<L>, const L: usize> Field for FieldElement<P, L> {
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
        Self::is_zero()
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
        Self::neg()
    }
    #[inline]
    fn mul(&self, other: &Self) -> Self {
        Self::mul(self, other)
    }
    #[inline]
    fn invert(&self) -> CtOption<Self> {
        Self::invert()
    }
    #[inline]
    fn pow_vartime(&self, exp: &[u64]) -> Self {
        Self::pow_vartime(self, exp)
    }
    #[inline]
    fn sqrt(&self) -> CtOption<Self> {
        Self::sqrt()
    }
}
