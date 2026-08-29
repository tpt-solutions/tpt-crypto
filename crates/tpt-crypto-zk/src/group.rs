//! Ristretto-style prime-order group over Ed25519.
//!
//! Every element used by this crate lives in the prime-order subgroup of
//! Ed25519 (order `L`), so discrete logarithms are well defined and the
//! cofactor (8) never introduces ambiguity. All operations are constant-time
//! in their secret operands (they reduce to the curve crate's complete
//! Edwards25519 formulas and fixed-window scalar multiplication).

use tpt_crypto_curve::EdwardsPoint;
use tpt_crypto_field::Ed25519Scalar;
use tpt_crypto_hash::sha3::{Shake256, Xof};

/// A group element in the prime-order subgroup of Ed25519.
#[derive(Clone, Copy, Debug)]
pub struct Ristretto(pub(crate) EdwardsPoint);

impl Ristretto {
    /// The identity element.
    pub fn identity() -> Self {
        Ristretto(EdwardsPoint::identity())
    }

    /// The standard Ed25519 base point (a generator of the prime-order subgroup).
    pub fn basepoint() -> Self {
        Ristretto(EdwardsPoint::basepoint())
    }

    /// Group addition `self + other`.
    pub fn add(&self, other: &Self) -> Self {
        Ristretto(self.0.add(&other.0))
    }

    /// Scalar multiplication `s · self`.
    pub fn scalar_mul(&self, s: &Ed25519Scalar) -> Self {
        Ristretto(self.0.mul(&scalar_le_bytes(s)))
    }

    /// The additive inverse `-self`.
    pub fn neg(&self) -> Self {
        self.scalar_mul(&(-Ed25519Scalar::one()))
    }

    /// Canonical 32-byte encoding (the Ed25519 compressed point).
    pub fn compress(&self) -> [u8; 32] {
        self.0.compress()
    }

    /// Decode a canonical 32-byte encoding, or `None` if it is not a valid
    /// prime-order-subgroup element.
    pub fn decompress(bytes: &[u8; 32]) -> Option<Self> {
        let opt = EdwardsPoint::decompress(bytes);
        if opt.is_some().into_bool() {
            Some(Ristretto(opt.unwrap()))
        } else {
            None
        }
    }

    /// Constant-time equality with another group element.
    pub fn ct_eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into_bool()
    }

    /// Whether this element is the identity.
    pub fn is_identity(&self) -> bool {
        self.ct_eq(&Ristretto::identity())
    }

    /// Deterministically maps a seed to a group element via `H(seed) · B`,
    /// where `B` is the base point and `H` is SHAKE256. The result lies in the
    /// prime-order subgroup.
    pub fn map_to_point(seed: &[u8]) -> Self {
        let mut buf = [0u8; 64];
        let mut h = Shake256::new();
        h.update(b"tpt-crypto-zk.map_to_point");
        h.update(seed);
        h.finalize_xof(&mut buf);
        let s = scalar_from_wide(&buf);
        Ristretto::basepoint().scalar_mul(&s)
    }

    /// Constant-time multiscalar multiplication `Σ s_i · P_i`.
    pub fn msm(scalars: &[Ed25519Scalar], points: &[Ristretto]) -> Self {
        let mut acc = Ristretto::identity();
        for (s, p) in scalars.iter().zip(points.iter()) {
            acc = acc.add(&p.scalar_mul(s));
        }
        acc
    }
}

impl core::ops::Add for Ristretto {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        self.add(&rhs)
    }
}

impl core::ops::Sub for Ristretto {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        self.add(&rhs.neg())
    }
}

impl core::ops::Neg for Ristretto {
    type Output = Self;
    fn neg(self) -> Self {
        self.neg()
    }
}

impl core::ops::Mul<Ed25519Scalar> for Ristretto {
    type Output = Self;
    fn mul(self, rhs: Ed25519Scalar) -> Self {
        self.scalar_mul(&rhs)
    }
}

/// Convert a scalar to the 32-byte little-endian form expected by
/// [`EdwardsPoint::mul`].
pub(crate) fn scalar_le_bytes(s: &Ed25519Scalar) -> [u8; 32] {
    // `to_bytes` yields the 48-byte big-endian integer; the value occupies the
    // low 32 bytes (offset 16), which we reverse to little-endian.
    let b = s.to_bytes();
    let mut le = [0u8; 32];
    for i in 0..32 {
        le[i] = b[16 + (31 - i)];
    }
    le
}

/// Reduce a 64-byte little-endian integer modulo the scalar-field modulus `L`.
///
/// The bias from the reduction is negligible and irrelevant for Fiat–Shamir
/// challenges, which only need to be unpredictable and bind the transcript.
pub(crate) fn scalar_from_wide(bytes: &[u8; 64]) -> Ed25519Scalar {
    let mut limbs = [0u64; 8];
    for i in 0..8 {
        let mut v = 0u64;
        for j in 0..8 {
            v |= (bytes[i * 8 + j] as u64) << (8 * j);
        }
        limbs[i] = v;
    }
    let two64 = Ed25519Scalar::from_u64(2).pow_vartime(&[64]);
    let mut powers = [Ed25519Scalar::one(); 8];
    let mut i = 1;
    while i < 8 {
        powers[i] = powers[i - 1].mul(&two64);
        i += 1;
    }
    let mut acc = Ed25519Scalar::zero();
    for i in 0..8 {
        acc = acc.add(&Ed25519Scalar::from_u64(limbs[i]).mul(&powers[i]));
    }
    acc
}
