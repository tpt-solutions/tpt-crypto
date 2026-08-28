//! Masked arithmetic for side-channel resistance.
//!
//! Two complementary masking schemes are provided:
//!
//! - [`Masked<T>`] — **additive (XOR) sharing**: a secret `x` is stored as the
//!   pair `(x ^ r, r)`. The raw secret is never materialized. Boolean
//!   operations (`xor`/`and`) are evaluated share-wise; `and` refreshes with a
//!   fresh random mask (an ISW-style refresh) so the output shares stay
//!   independent.
//!
//! - [`MaskedMul<T>`] — **multiplicative sharing**: `x` is stored as
//!   `(x * r, r)`. Multiplying two such sharings multiplies both the values
//!   and the blinding factors, so the product stays masked.
//!
//! Both schemes expose `mask`/`unmask`/`remask`. The integer `add`/`sub`/`mul`
//! operations here are the *group* operations of the chosen mask over a limb
//! (`GF(2)^w` for XOR sharing, the multiplicative monoid for `MaskedMul`),
//! which is exactly what bitsliced/masked ciphers need.

/// A randomly-maskable source of fresh masking material.
pub trait Random<T> {
    /// Produce a fresh random mask value of type `T`.
    fn next(&mut self) -> T;
}

impl<F, T> Random<T> for F
where
    F: FnMut() -> T,
{
    #[inline]
    fn next(&mut self) -> T {
        self()
    }
}

/// Wrapping multiplication, needed for generic masked arithmetic where the
/// underlying `Mul` would panic on overflow under `overflow-checks`.
pub trait WrappingMul: Copy {
    /// Multiply, wrapping on overflow (modulo the width of `Self`).
    fn wmul(self, rhs: Self) -> Self;
}

macro_rules! impl_wrapping_mul {
    ($($t:ty),*) => {
        $(
            impl WrappingMul for $t {
                #[inline]
                fn wmul(self, rhs: Self) -> Self {
                    self.wrapping_mul(rhs)
                }
            }
        )*
    };
}

impl_wrapping_mul!(u8, u16, u32, u64, u128, usize);

/// An additively (XOR) masked value of type `T`.
///
/// Invariant: `unmask()` returns `hi ^ lo`. The value is never stored in the
/// clear, so power/EM side channels see only the randomized shares.
#[derive(Copy, Clone)]
pub struct Masked<T> {
    hi: T,
    lo: T,
}

impl<T: Copy + core::ops::BitXor<Output = T>> Masked<T> {
    /// Mask `value` with a fresh random share produced by `rng`.
    #[inline]
    pub fn mask<R: Random<T>>(value: T, rng: &mut R) -> Self {
        let r = rng.next();
        Masked {
            hi: value ^ r,
            lo: r,
        }
    }

    /// Recover the underlying value (`hi ^ lo`).
    #[inline]
    #[must_use]
    pub fn unmask(&self) -> T {
        self.hi ^ self.lo
    }

    /// Re-randomize the masking using a fresh random share (keeps the value).
    #[inline]
    pub fn remask<R: Random<T>>(&mut self, rng: &mut R) {
        let r = rng.next();
        let v = self.unmask();
        self.hi = v ^ r;
        self.lo = r;
    }

    /// Masked XOR — share-wise XOR. `unmask(a.xor(b)) == unmask(a) ^ unmask(b)`.
    #[inline]
    #[must_use]
    pub fn xor(&self, other: &Self) -> Self {
        Masked {
            hi: self.hi ^ other.hi,
            lo: self.lo ^ other.lo,
        }
    }

    /// Masked "add" in the XOR-mask group is XOR.
    #[inline]
    #[must_use]
    pub fn add(&self, other: &Self) -> Self {
        self.xor(other)
    }

    /// Masked "sub" in the XOR-mask group is XOR.
    #[inline]
    #[must_use]
    pub fn sub(&self, other: &Self) -> Self {
        self.xor(other)
    }
}

impl<T: Copy + core::ops::BitXor<Output = T> + core::ops::BitAnd<Output = T>> Masked<T> {
    /// Masked AND with ISW-style refresh.
    ///
    /// Computes the boolean `and` of the two masked values and re-masks the
    /// result with a fresh random share so the output shares are independent.
    /// `unmask(a.and(b)) == unmask(a) & unmask(b)`.
    #[inline]
    #[must_use]
    pub fn and<R: Random<T>>(&self, other: &Self, rng: &mut R) -> Self {
        let r = rng.next();
        let base = (self.hi & other.hi)
            ^ (self.lo & other.lo)
            ^ (self.hi & other.lo)
            ^ (self.lo & other.hi);
        Masked {
            hi: base ^ r,
            lo: r,
        }
    }

    /// Masked "mul" in the XOR-mask group is AND.
    #[inline]
    #[must_use]
    pub fn mul<R: Random<T>>(&self, other: &Self, rng: &mut R) -> Self {
        self.and(other, rng)
    }
}

/// A multiplicatively masked value of type `T`.
///
/// Stored as `(value * blind, blind)`. The blind must be invertible in the
/// multiplicative monoid of `T` (for `u64`, it must be **odd**); use
/// [`random_odd`] to draw one.
#[derive(Copy, Clone)]
pub struct MaskedMul<T> {
    m: T,
    b: T,
}

impl<T: WrappingMul> MaskedMul<T> {
    /// Mask `value` under a caller-chosen blinding factor `blind`.
    ///
    /// `blind` must be a unit of the multiplicative monoid (odd for `u64`).
    #[inline]
    pub fn mask(value: T, blind: T) -> Self {
        MaskedMul {
            m: value.wmul(blind),
            b: blind,
        }
    }

    /// Return the masked value `value * blind` (the protected representation).
    #[inline]
    #[must_use]
    pub fn unmask_share(&self) -> T {
        self.m
    }

    /// Return the current blinding factor.
    #[inline]
    #[must_use]
    pub fn blind(&self) -> T {
        self.b
    }

    /// Multiply two multiplicatively masked values.
    ///
    /// `(x*k) * (y*l) = (x*y) * (k*l)`, so the product stays masked under the
    /// combined blinding `k*l`.
    #[inline]
    #[must_use]
    pub fn mul(&self, other: &Self) -> Self {
        MaskedMul {
            m: self.m.wmul(other.m),
            b: self.b.wmul(other.b),
        }
    }

    /// Re-blind under a fresh factor `nb` (must be a unit). The protected
    /// value `x * (old_blind * nb)` is preserved.
    #[inline]
    pub fn remask(&mut self, nb: T) {
        self.m = self.m.wmul(nb);
        self.b = self.b.wmul(nb);
    }
}

/// Draw a random odd `u64` from `rng` (used as a multiplicative blinding unit).
#[inline]
#[must_use]
pub fn random_odd<R: Random<u64>>(rng: &mut R) -> u64 {
    rng.next() | 1
}

/// Modular inverse of an odd `u64` modulo `2^64`.
///
/// Used to unblind multiplicatively masked scalars. The input must be odd.
#[must_use]
pub fn mod_inv_odd_u64(x: u64) -> u64 {
    debug_assert!(x & 1 == 1, "mod_inv_odd_u64 requires an odd input");
    let mut y = 1u64;
    // Newton iteration: x^{-1} mod 2^k doubles in precision each step.
    for _ in 0..6 {
        y = y.wrapping_mul(2u64.wrapping_sub(x.wrapping_mul(y)));
    }
    y
}

impl MaskedMul<u64> {
    /// Unblind: recover the raw value `m * blind^{-1} mod 2^64`.
    ///
    /// The stored blind must be odd (which `random_odd` guarantees).
    #[inline]
    #[must_use]
    pub fn unblind(&self) -> u64 {
        self.m.wrapping_mul(mod_inv_odd_u64(self.b))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn xor_mask_roundtrip() {
        let mut rng = 0x1234_5678_9abc_def0u64;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        for v in [0u64, 1, 0xFFFF_FFFF_FFFF_FFFF, 0x1234_5678_9abc_def0] {
            let m = Masked::<u64>::mask(v, &mut next);
            assert_eq!(m.unmask(), v);
            let mut m2 = m;
            m2.remask(&mut next);
            assert_eq!(m2.unmask(), v);
        }
    }

    #[test]
    fn xor_group_ops() {
        let mut rng = 0x0f0f_0f0f_0f0f_0f0fu64;
        let mut next = || {
            rng = rng.wrapping_mul(6364136223846793005).wrapping_add(1);
            rng
        };
        let a = Masked::<u64>::mask(0b1100, &mut next);
        let b = Masked::<u64>::mask(0b1010, &mut next);
        assert_eq!(a.xor(&b).unmask(), 0b1100 ^ 0b1010);
        assert_eq!(a.add(&b).unmask(), 0b1100 ^ 0b1010);
        assert_eq!(a.mul(&b, &mut next).unmask(), 0b1100 & 0b1010);
    }

    #[test]
    fn mul_mask_roundtrip() {
        let mut rng = 0xa5a5_a5a5_a5a5_a5a5u64;
        let mut next = || {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            rng
        };
        let k = random_odd(&mut next);
        let x = 0x1234_5678_9abc_def0u64;
        let m = MaskedMul::<u64>::mask(x, k);
        assert_eq!(m.unblind(), x);
        let mut m2 = m;
        m2.remask(random_odd(&mut next));
        assert_eq!(m2.unblind(), x);

        let l = random_odd(&mut next);
        let y = 0x0f0f_0f0f_0f0f_0f0fu64;
        let n = MaskedMul::<u64>::mask(y, l);
        assert_eq!(m.mul(&n).unblind(), x.wrapping_mul(y));
    }
}
