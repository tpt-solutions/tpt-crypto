//! Ed25519 (RFC 8032): Edwards25519 twisted-Edwards curve, constant-time
//! scalar multiplication (fixed-window + `ct_lookup`), point compress/decompress,
//! cofactored verification, and the RFC 8032 signing/verification algorithms.

use tpt_crypto_ct::lookup::ct_lookup;
use tpt_crypto_ct::{Choice as CtChoice, CtSelect};
use tpt_crypto_field::{Choice, CtEq, CtOption, Ed25519Field, Ed25519Scalar, Field, MAX_LIMBS};
use tpt_crypto_hash::sha2::Sha512;
use tpt_crypto_hash::Hasher;

/// Constant-time selection of two field elements via the `Field` trait.
fn fe_ct_select(a: &Ed25519Field, b: &Ed25519Field, choice: Choice) -> Ed25519Field {
    <Ed25519Field as Field>::ct_select(a, b, choice)
}

/// `d = -121665 / 121666 mod p` as little-endian 64-bit limbs.
const CURVE_D_LIMBS: [u64; 4] = [
    0x75eb_4dca_1359_78a3,
    0x0070_0a4d_4141_d8ab,
    0x8cc7_4079_7779_e898,
    0x5203_6cee_2b6f_fe73,
];

/// Edwards25519 curve parameter `d = -121665 / 121666 mod p`.
///
/// A literal rather than a computed value: deriving it costs a field
/// inversion (~30 µs), which the group law would otherwise pay per addition.
fn curve_d() -> Ed25519Field {
    fe_from_limbs(CURVE_D_LIMBS)
}

/// Base point `x` (RFC 8032 §5.1), little-endian limbs.
const BASE_X_LIMBS: [u64; 4] = [
    0xc956_2d60_8f25_d51a,
    0x692c_c760_9525_a7b2,
    0xc0a4_e231_fdd6_dc5c,
    0x2169_36d3_cd6e_53fe,
];

/// Base point `y = 4/5`, little-endian limbs.
const BASE_Y_LIMBS: [u64; 4] = [
    0x6666_6666_6666_6658,
    0x6666_6666_6666_6666,
    0x6666_6666_6666_6666,
    0x6666_6666_6666_6666,
];

fn fe_from_limbs(l: [u64; 4]) -> Ed25519Field {
    let mut limbs = [0u64; MAX_LIMBS];
    limbs[..4].copy_from_slice(&l);
    Ed25519Field::from_limbs(limbs)
}

/// Edwards25519 point in extended homogeneous coordinates (X:Y:Z:T).
#[derive(Clone, Copy, Debug)]
pub struct EdwardsPoint {
    x: Ed25519Field,
    y: Ed25519Field,
    z: Ed25519Field,
    t: Ed25519Field,
}

impl EdwardsPoint {
    /// Identity point (0, 1).
    pub fn identity() -> Self {
        EdwardsPoint {
            x: Ed25519Field::zero(),
            y: Ed25519Field::one(),
            z: Ed25519Field::one(),
            t: Ed25519Field::zero(),
        }
    }

    /// Build an extended-coordinate point directly from affine `(x, y)`
    /// **without** checking that it lies on the curve.
    ///
    /// Used by hash-to-curve, whose map output is on-curve by construction.
    pub fn from_affine_unchecked(x: Ed25519Field, y: Ed25519Field) -> Self {
        EdwardsPoint {
            x,
            y,
            z: Ed25519Field::one(),
            t: x.mul(&y),
        }
    }

    /// Ed25519 base point (RFC 8032 §5.1), from its literal affine coordinates
    /// (deriving it costs an inversion and a square root per call).
    pub fn basepoint() -> Self {
        let x = fe_from_limbs(BASE_X_LIMBS);
        let y = fe_from_limbs(BASE_Y_LIMBS);
        EdwardsPoint {
            x,
            y,
            z: Ed25519Field::one(),
            t: x.mul(&y),
        }
    }

    /// Recover the x-coordinate from y and the desired sign of x.
    ///
    /// Returns the canonical x in `[0, p)` whose least-significant bit equals
    /// `sign` when `sign` is `true` (i.e. we want the odd x). Used during
    /// decompression and base-point construction; for on-curve points `x^2`
    /// is always a quadratic residue so `sqrt` succeeds.
    #[cfg(test)]
    fn recover_x(y: &Ed25519Field, sign: bool) -> Ed25519Field {
        let d = curve_d();
        let y2 = y.square();
        let u = y2.sub(&Ed25519Field::one());
        let v = d.mul(&y2).add(&Ed25519Field::one());
        let x2 = u.mul(&v.invert().unwrap());
        let x = x2.sqrt().unwrap_or_else(Ed25519Field::zero);
        let xb = x.to_bytes();
        // sign of x = LSB of canonical x (byte 47 of the big-endian encoding).
        let negate = Choice::from_bool((xb[47] & 1 != 0) ^ sign);
        fe_ct_select(&x, &x.neg(), negate)
    }

    /// Extended-coordinate addition (complete addition formula, H-C-D).
    pub fn add(&self, other: &Self) -> Self {
        let a = self.y.sub(&self.x).mul(&other.y.sub(&other.x));
        let b = self.y.add(&self.x).mul(&other.y.add(&other.x));
        let c = self.t.mul(&other.t).mul(&curve_d()).double();
        let d = self.z.mul(&other.z).double();
        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);
        EdwardsPoint {
            x: e.mul(&f),
            y: g.mul(&h),
            t: e.mul(&h),
            z: f.mul(&g),
        }
    }

    /// Negate this point (`-P`), constant-time. In extended coordinates this
    /// flips the sign of `x` and `t` while leaving `y` and `z` unchanged.
    #[must_use]
    pub fn neg(&self) -> Self {
        EdwardsPoint {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
    }

    /// Constant-time point subtraction (`self - other`).
    #[must_use]
    pub fn sub(&self, other: &Self) -> Self {
        self.add(&other.neg())
    }

    /// Constant-time point doubling.
    pub fn double(&self) -> Self {
        let a = self.x.square();
        let b = self.y.square();
        let c = self.z.square().double();
        let h = a.add(&b);
        let xpy = self.x.add(&self.y);
        let e = h.sub(&xpy.square());
        let g = a.sub(&b);
        let f = c.add(&g);
        EdwardsPoint {
            x: e.mul(&f),
            y: g.mul(&h),
            t: e.mul(&h),
            z: f.mul(&g),
        }
    }

    /// Multiply this point by a 32-byte little-endian scalar, constant-time.
    ///
    /// Uses a fixed window of `w = 4` with a precomputed table of `1·P .. 15·P`
    /// and a branch-free `ct_lookup`, so the memory-access and control-flow
    /// patterns do not depend on the secret scalar.
    pub fn mul(&self, scalar: &[u8; 32]) -> Self {
        let mut table = [EdwardsPoint::identity(); 16];
        let mut p = *self;
        for tbl in table.iter_mut().skip(1) {
            *tbl = p;
            p = p.add(self);
        }
        let mut acc = EdwardsPoint::identity();
        // Process from the most-significant nibble to the least.
        for i in (0..64).rev() {
            let byte = scalar[i / 2] as usize;
            let nibble = if (i % 2) == 0 {
                byte & 0x0F
            } else {
                (byte >> 4) & 0x0F
            };
            for _ in 0..4 {
                acc = acc.double();
            }
            let addend = ct_lookup(&table, nibble, EdwardsPoint::identity());
            acc = acc.add(&addend);
        }
        acc
    }

    /// Multiply by the cofactor 8 (used for cofactored verification).
    pub fn mul_by_cofactor(&self) -> Self {
        self.double().double().double()
    }

    /// Affine y-coordinate of this point (y / z).
    pub fn affine_y(&self) -> Ed25519Field {
        let zinv = self.z.invert().unwrap_or(Ed25519Field::zero());
        self.y.mul(&zinv)
    }

    /// The Montgomery u-coordinate of this Edwards point via the birational map
    /// `u = (1 + y) / (1 - y)` (RFC 7748 §4.1).
    pub fn to_montgomery_u(&self) -> Ed25519Field {
        let y = self.affine_y();
        let one = Ed25519Field::one();
        let num = one.add(&y);
        let den = one.sub(&y);
        num.mul(&den.invert().unwrap_or(Ed25519Field::zero()))
    }

    /// Compress to the canonical 32-byte little-endian encoding (y with sign of x).
    pub fn compress(&self) -> [u8; 32] {
        let zinv = self.z.invert().unwrap_or(Ed25519Field::zero());
        let x = self.x.mul(&zinv);
        let y = self.y.mul(&zinv);
        let bytes48 = y.to_bytes();
        // The field encodes big-endian into 48 bytes; the 32-byte value sits at
        // offset 16. Reverse to little-endian for the Ed25519 encoding.
        let mut bytes = [0u8; 32];
        for i in 0..32 {
            bytes[i] = bytes48[16 + (31 - i)];
        }
        // Sign of x = LSB of canonical x (byte 47 of the big-endian encoding).
        let x_int = x.to_bytes();
        let sign = (x_int[47] & 1) != 0;
        bytes[31] |= (sign as u8) << 7;
        bytes
    }

    /// Decompress from the canonical 32-byte little-endian encoding.
    ///
    /// Returns `None` (constant-time) if the input is not canonical or does not
    /// lie on the curve.
    pub fn decompress(bytes: &[u8; 32]) -> CtOption<Self> {
        let sign = (bytes[31] >> 7) & 1;
        // Reverse little-endian encoding into the field's big-endian form and
        // clear the (now superflous) top bit of y.
        let mut be = [0u8; 48];
        for i in 0..32 {
            be[16 + i] = bytes[31 - i];
        }
        be[16] &= 0x7F;
        let y_opt = Ed25519Field::from_bytes(&be);
        let y = y_opt.unwrap_or_else(Ed25519Field::zero);
        let d = curve_d();
        let y2 = y.square();
        let u = y2.sub(&Ed25519Field::one());
        let v = d.mul(&y2).add(&Ed25519Field::one());
        let v_inv = v.invert();
        let x2 = u.mul(&v_inv.unwrap_or_else(Ed25519Field::zero));
        let x_opt = x2.sqrt();
        let mut x = x_opt.unwrap_or_else(Ed25519Field::zero);
        let xb = x.to_bytes();
        let negate = Choice::from_bool((xb[47] & 1 != 0) ^ (sign != 0));
        x = fe_ct_select(&x, &x.neg(), negate);
        let point = EdwardsPoint {
            x,
            y,
            z: Ed25519Field::one(),
            t: x.mul(&y),
        };
        CtOption::new(
            point,
            y_opt.is_some().and(x_opt.is_some()).and(v_inv.is_some()),
        )
    }

    /// Clamp a 32-byte seed into the Ed25519 secret scalar `a` (RFC 8032 §5.1.5).
    fn clamp(seed: &[u8; 32]) -> [u8; 32] {
        let mut a = [0u8; 32];
        a.copy_from_slice(seed);
        a[0] &= 248;
        a[31] &= 127;
        a[31] |= 64;
        a
    }
}

impl CtEq for EdwardsPoint {
    fn ct_eq(&self, other: &Self) -> Choice {
        let zinv1 = self.z.invert().unwrap_or(Ed25519Field::zero());
        let zinv2 = other.z.invert().unwrap_or(Ed25519Field::zero());
        let x1 = self.x.mul(&zinv1);
        let y1 = self.y.mul(&zinv1);
        let x2 = other.x.mul(&zinv2);
        let y2 = other.y.mul(&zinv2);
        x1.ct_eq(&x2).and(y1.ct_eq(&y2))
    }
}

impl CtSelect for EdwardsPoint {
    fn ct_select(cond: CtChoice, a: Self, b: Self) -> Self {
        EdwardsPoint {
            x: <Ed25519Field as CtSelect>::ct_select(cond, a.x, b.x),
            y: <Ed25519Field as CtSelect>::ct_select(cond, a.y, b.y),
            z: <Ed25519Field as CtSelect>::ct_select(cond, a.z, b.z),
            t: <Ed25519Field as CtSelect>::ct_select(cond, a.t, b.t),
        }
    }
}

impl EdwardsPoint {
    /// Derive the Ed25519 public key (compressed) from a 32-byte seed.
    pub fn public_key(seed: &[u8; 32]) -> [u8; 32] {
        let h = sha512_concat(&[seed]);
        let mut a = [0u8; 32];
        a.copy_from_slice(&h[..32]);
        let a = Self::clamp(&a);
        Self::basepoint().mul(&a).compress()
    }

    /// Sign `msg` with the RFC 8032 Ed25519 algorithm, returning a 64-byte signature.
    pub fn sign(seed: &[u8; 32], msg: &[u8]) -> [u8; 64] {
        let h = sha512_concat(&[seed]);
        let mut a = [0u8; 32];
        a.copy_from_slice(&h[..32]);
        let a = Self::clamp(&a);
        let mut prefix = [0u8; 32];
        prefix.copy_from_slice(&h[32..64]);

        // r = SHA512(prefix || msg) mod L.
        let r_digest = sha512_concat(&[&prefix, msg]);
        let r = reduce_wide(&r_digest);
        let r_point = Self::basepoint().mul(&scalar_to_le32(r)).compress();

        // k = SHA512(R || A || msg) mod L.
        let a_point = Self::basepoint().mul(&a).compress();
        let k_digest = sha512_concat(&[&r_point, &a_point, msg]);
        let k = reduce_wide(&k_digest);

        // S = (r + k * a) mod L.
        let a_scalar = le32_to_scalar(&a);
        let s = r.add(&k.mul(&a_scalar));

        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&r_point);
        sig[32..].copy_from_slice(&scalar_to_le32(s));
        sig
    }

    /// Verify an RFC 8032 Ed25519 signature, cofactored (RFC 8032 §5.1.7).
    pub fn verify(pubkey: &[u8; 32], msg: &[u8], sig: &[u8; 64]) -> bool {
        let a_opt = Self::decompress(pubkey);
        let r_point: [u8; 32] = sig[..32].try_into().unwrap();
        let r_opt = Self::decompress(&r_point);
        let a = a_opt.unwrap_or_else(EdwardsPoint::identity);
        let r = r_opt.unwrap_or_else(EdwardsPoint::identity);
        let present = a_opt.is_some().and(r_opt.is_some());

        let s = le32_to_scalar(&sig[32..].try_into().unwrap());
        let k_digest = sha512_concat(&[&r_point, pubkey, msg]);
        let k = reduce_wide(&k_digest);

        let lhs = Self::basepoint().mul(&scalar_to_le32(s)).mul_by_cofactor();
        let rhs = r.add(&a.mul(&scalar_to_le32(k))).mul_by_cofactor();
        (present.and(lhs.ct_eq(&rhs))).into_bool()
    }
}

/// RFC 8032 group-order (`L`) scalar helpers, exposed for higher layers that
/// build on Ed25519 (e.g. batch verification in `tpt-crypto-sig`).
pub mod scalar {
    use super::{le32_to_scalar, reduce_wide, scalar_to_le32, Ed25519Scalar};

    /// `L` — the Edwards25519 group order — in 32-byte little-endian form.
    pub const ORDER_LE: [u8; 32] = [
        0xED, 0xD3, 0xF5, 0x5C, 0x1A, 0x63, 0x12, 0x58, 0xD6, 0x9C, 0xF7, 0xA2, 0xDE, 0xF9, 0xDE,
        0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x10,
    ];

    /// Reduce a 64-byte little-endian value modulo `L`.
    #[must_use]
    pub fn reduce_wide_le(d: &[u8; 64]) -> Ed25519Scalar {
        reduce_wide(d)
    }

    /// Parse a 32-byte little-endian value modulo `L`.
    #[must_use]
    pub fn from_le32(b: &[u8; 32]) -> Ed25519Scalar {
        le32_to_scalar(b)
    }

    /// Encode a scalar as a canonical 32-byte little-endian value (`< L`).
    #[must_use]
    pub fn to_le32(s: Ed25519Scalar) -> [u8; 32] {
        scalar_to_le32(s)
    }

    /// Is `b` a canonical scalar encoding, i.e. `0 <= b < L`?
    ///
    /// RFC 8032 §5.1.7 requires rejecting signatures whose `S` component is not
    /// in `[0, L)`. Compares `b` against [`ORDER_LE`] byte-by-byte, MSB first.
    #[must_use]
    pub fn is_canonical_le32(b: &[u8; 32]) -> bool {
        for i in (0..32).rev() {
            if b[i] < ORDER_LE[i] {
                return true;
            }
            if b[i] > ORDER_LE[i] {
                return false;
            }
        }
        // b == L is not canonical.
        false
    }
}

/// Parse a 32-byte little-endian value into an `Ed25519Scalar`, reducing mod L.
fn le32_to_scalar(bytes: &[u8; 32]) -> Ed25519Scalar {
    let mut limbs = [0u64; MAX_LIMBS];
    for i in 0..4 {
        let mut v = 0u64;
        for j in 0..8 {
            v |= (bytes[i * 8 + j] as u64) << (8 * j);
        }
        limbs[i] = v;
    }
    Ed25519Scalar::from_limbs(limbs)
}

/// Encode an `Ed25519Scalar` as a 32-byte little-endian value.
fn scalar_to_le32(s: Ed25519Scalar) -> [u8; 32] {
    let b = s.to_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = b[16 + (31 - i)];
    }
    out
}

/// Reduce a 64-byte (512-bit) little-endian digest modulo L.
///
/// The field's `from_limbs`/`mont_mul` only consider the low `P::LIMBS` limbs,
/// so a naive `hi * 2^256 + lo` overflows and silently drops the high part.
/// Instead we accumulate `sum_i limb_i * (2^64i mod L)` limb-by-limb, each
/// product reduced modulo L by the field arithmetic.
fn reduce_wide(d: &[u8; 64]) -> Ed25519Scalar {
    let mut limbs = [0u64; 8];
    for i in 0..8 {
        let mut v = 0u64;
        for j in 0..8 {
            v |= (d[i * 8 + j] as u64) << (8 * j);
        }
        limbs[i] = v;
    }
    // base = 2^64 mod L.
    let mut base = Ed25519Scalar::one();
    let mut i = 0;
    while i < 64 {
        base = base.double();
        i += 1;
    }
    let mut powers = [Ed25519Scalar::one(); 8];
    let mut k = 1;
    while k < 8 {
        powers[k] = powers[k - 1].mul(&base);
        k += 1;
    }
    let mut acc = Ed25519Scalar::zero();
    let mut j = 0;
    while j < 8 {
        let term = Ed25519Scalar::from_u64(limbs[j]).mul(&powers[j]);
        acc = acc.add(&term);
        j += 1;
    }
    Ed25519Scalar::from_limbs(acc.to_integer())
}

/// Incremental SHA-512 over a list of byte slices (no allocation).
fn sha512_concat(parts: &[&[u8]]) -> [u8; 64] {
    let mut h = Sha512::new();
    for p in parts {
        h.update(p);
    }
    h.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn curve_d_literal_matches_definition() {
        let computed = Ed25519Field::from_u64(121_665)
            .mul(&Ed25519Field::from_u64(121_666).invert().unwrap())
            .neg();
        assert!(curve_d().ct_eq(&computed).into_bool());
    }

    #[test]
    fn basepoint_literal_matches_definition() {
        let y = Ed25519Field::from_u64(4).mul(&Ed25519Field::from_u64(5).invert().unwrap());
        let x = EdwardsPoint::recover_x(&y, false);
        let b = EdwardsPoint::basepoint();
        assert!(b.x.ct_eq(&x).into_bool());
        assert!(b.y.ct_eq(&y).into_bool());
    }
}
