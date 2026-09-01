//! NIST P-256 / P-384 short-Weierstrass curves (`a = -3`), constant-time.
//!
//! Points are held in projective `(X : Y : Z)` coordinates and combined with the
//! complete Renes–Costello–Batina addition formulas (eprint 2015/1060, Alg. 4
//! for addition and Alg. 6 for doubling). Those formulas are exception-free for
//! prime-order curves, and P-256 / P-384 both have cofactor 1, so a single code
//! path handles the identity, doublings, and `P + (-P)` with no branch on point
//! values.
//!
//! [`ProjectivePoint::mul`] is a fixed-length double-and-add that performs one
//! [`ct_select`](tpt_crypto_field::Field::ct_select) per scalar bit, so the
//! instruction trace and memory-access pattern are independent of the scalar.
//! Point *decompression* branches on the (public) encoding and is not intended
//! to be constant-time.

use tpt_crypto_field::{
    Choice, CtEq, Field, FieldElement, FieldParams, P256BaseParams, P256ScalarParams,
    P384BaseParams, P384ScalarParams, MAX_LIMBS,
};

/// Width of the fixed big-endian encoding of a `MAX_LIMBS`-limb field element.
const FE_BYTES: usize = MAX_LIMBS * 8;

/// Parameters describing a short-Weierstrass curve `y² = x³ − 3·x + b`.
pub trait WeierstrassParams: Copy + 'static {
    /// Base-field parameters (coordinate arithmetic).
    type Base: FieldParams;
    /// Scalar-field parameters (group order).
    type Scalar: FieldParams;
    /// Curve `b` coefficient, little-endian integer limbs.
    const B: [u64; MAX_LIMBS];
    /// Generator x-coordinate, little-endian integer limbs.
    const GX: [u64; MAX_LIMBS];
    /// Generator y-coordinate, little-endian integer limbs.
    const GY: [u64; MAX_LIMBS];
    /// Number of bytes in the SEC1 encoding of one coordinate / scalar.
    const FIELD_BYTES: usize;
}

/// NIST P-256 (secp256r1 / prime256v1).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct P256;

impl WeierstrassParams for P256 {
    type Base = P256BaseParams;
    type Scalar = P256ScalarParams;
    const B: [u64; MAX_LIMBS] = [
        0x3bce_3c3e_27d2_604b,
        0x651d_06b0_cc53_b0f6,
        0xb3eb_bd55_7698_86bc,
        0x5ac6_35d8_aa3a_93e7,
        0,
        0,
    ];
    const GX: [u64; MAX_LIMBS] = [
        0xf4a1_3945_d898_c296,
        0x7703_7d81_2deb_33a0,
        0xf8bc_e6e5_63a4_40f2,
        0x6b17_d1f2_e12c_4247,
        0,
        0,
    ];
    const GY: [u64; MAX_LIMBS] = [
        0xcbb6_4068_37bf_51f5,
        0x2bce_3357_6b31_5ece,
        0x8ee7_eb4a_7c0f_9e16,
        0x4fe3_42e2_fe1a_7f9b,
        0,
        0,
    ];
    const FIELD_BYTES: usize = 32;
}

/// NIST P-384 (secp384r1).
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct P384;

impl WeierstrassParams for P384 {
    type Base = P384BaseParams;
    type Scalar = P384ScalarParams;
    const B: [u64; MAX_LIMBS] = [
        0x2a85_c8ed_d3ec_2aef,
        0xc656_398d_8a2e_d19d,
        0x0314_088f_5013_875a,
        0x181d_9c6e_fe81_4112,
        0x988e_056b_e3f8_2d19,
        0xb331_2fa7_e23e_e7e4,
    ];
    const GX: [u64; MAX_LIMBS] = [
        0x3a54_5e38_7276_0ab7,
        0x5502_f25d_bf55_296c,
        0x59f7_41e0_8254_2a38,
        0x6e1d_3b62_8ba7_9b98,
        0x8eb1_c71e_f320_ad74,
        0xaa87_ca22_be8b_0537,
    ];
    const GY: [u64; MAX_LIMBS] = [
        0x7a43_1d7c_90ea_0e5f,
        0x0a60_b1ce_1d7e_819d,
        0xe9da_3113_b5f0_b8c0,
        0xf8f4_1dbd_289a_147c,
        0x5d9e_98bf_9292_dc29,
        0x3617_de4a_9626_2c6f,
    ];
    const FIELD_BYTES: usize = 48;
}

type Fe<C> = FieldElement<<C as WeierstrassParams>::Base>;

#[inline]
fn b_coeff<C: WeierstrassParams>() -> Fe<C> {
    FieldElement::from_limbs(C::B)
}

/// A point on the curve in projective `(X : Y : Z)` coordinates.
///
/// The identity element is `(0 : 1 : 0)`.
#[derive(Copy, Clone, Debug)]
pub struct ProjectivePoint<C: WeierstrassParams> {
    x: Fe<C>,
    y: Fe<C>,
    z: Fe<C>,
}

impl<C: WeierstrassParams> ProjectivePoint<C> {
    /// The identity element `(0 : 1 : 0)`.
    #[must_use]
    pub fn identity() -> Self {
        Self {
            x: FieldElement::zero(),
            y: FieldElement::one(),
            z: FieldElement::zero(),
        }
    }

    /// The standard generator `G`.
    #[must_use]
    pub fn generator() -> Self {
        Self {
            x: FieldElement::from_limbs(C::GX),
            y: FieldElement::from_limbs(C::GY),
            z: FieldElement::one(),
        }
    }

    /// Whether this point is the identity, as a [`Choice`].
    #[must_use]
    pub fn is_identity(&self) -> Choice {
        self.z.is_zero()
    }

    /// Negate this point (`-P`): flip the sign of `Y`.
    #[must_use]
    pub fn neg(&self) -> Self {
        Self {
            x: self.x,
            y: self.y.neg(),
            z: self.z,
        }
    }

    /// Constant-time point addition (RCB 2015, Algorithm 4, `a = -3`).
    #[must_use]
    pub fn add(&self, rhs: &Self) -> Self {
        let bb = b_coeff::<C>();
        let (x1, y1, z1) = (self.x, self.y, self.z);
        let (x2, y2, z2) = (rhs.x, rhs.y, rhs.z);

        let xx = x1.mul(&x2);
        let yy = y1.mul(&y2);
        let zz = z1.mul(&z2);
        let xy_pairs = x1.add(&y1).mul(&x2.add(&y2)).sub(&xx.add(&yy));
        let yz_pairs = y1.add(&z1).mul(&y2.add(&z2)).sub(&yy.add(&zz));
        let xz_pairs = x1.add(&z1).mul(&x2.add(&z2)).sub(&xx.add(&zz));

        let bzz_part = xz_pairs.sub(&bb.mul(&zz));
        let bzz3_part = bzz_part.double().add(&bzz_part);
        let yy_m_bzz3 = yy.sub(&bzz3_part);
        let yy_p_bzz3 = yy.add(&bzz3_part);

        let zz3 = zz.double().add(&zz);
        let bxz_part = bb.mul(&xz_pairs).sub(&zz3.add(&xx));
        let bxz3_part = bxz_part.double().add(&bxz_part);
        let xx3_m_zz3 = xx.double().add(&xx).sub(&zz3);

        Self {
            x: yy_p_bzz3.mul(&xy_pairs).sub(&yz_pairs.mul(&bxz3_part)),
            y: yy_p_bzz3.mul(&yy_m_bzz3).add(&xx3_m_zz3.mul(&bxz3_part)),
            z: yy_m_bzz3.mul(&yz_pairs).add(&xy_pairs.mul(&xx3_m_zz3)),
        }
    }

    /// Constant-time point doubling (RCB 2015, Algorithm 6, `a = -3`).
    #[must_use]
    pub fn double(&self) -> Self {
        let bb = b_coeff::<C>();
        let (x, y, z) = (self.x, self.y, self.z);

        let xx = x.square();
        let yy = y.square();
        let zz = z.square();
        let xy2 = x.mul(&y).double();
        let xz2 = x.mul(&z).double();

        let bzz_part = bb.mul(&zz).sub(&xz2);
        let bzz3_part = bzz_part.double().add(&bzz_part);
        let yy_m_bzz3 = yy.sub(&bzz3_part);
        let yy_p_bzz3 = yy.add(&bzz3_part);
        let y_frag = yy_p_bzz3.mul(&yy_m_bzz3);
        let x_frag = yy_m_bzz3.mul(&xy2);

        let zz3 = zz.double().add(&zz);
        let bxz2_part = bb.mul(&xz2).sub(&zz3.add(&xx));
        let bxz6_part = bxz2_part.double().add(&bxz2_part);
        let xx3_m_zz3 = xx.double().add(&xx).sub(&zz3);

        let yv = y_frag.add(&xx3_m_zz3.mul(&bxz6_part));
        let yz2 = y.mul(&z).double();
        let xv = x_frag.sub(&bxz6_part.mul(&yz2));
        let zv = yz2.mul(&yy).double().double();

        Self {
            x: xv,
            y: yv,
            z: zv,
        }
    }

    /// Constant-time subtraction (`self - rhs`).
    #[must_use]
    pub fn sub(&self, rhs: &Self) -> Self {
        self.add(&rhs.neg())
    }

    /// Constant-time selection: returns `b` when `c == 1`, else `a`.
    #[must_use]
    fn conditional_select(a: &Self, b: &Self, c: Choice) -> Self {
        Self {
            x: Fe::<C>::ct_select(&a.x, &b.x, c),
            y: Fe::<C>::ct_select(&a.y, &b.y, c),
            z: Fe::<C>::ct_select(&a.z, &b.z, c),
        }
    }

    /// Multiply this point by a big-endian scalar, constant-time in the scalar.
    ///
    /// The scalar is consumed as raw bytes (any length); callers are responsible
    /// for reducing it modulo the group order beforehand if required.
    #[must_use]
    pub fn mul(&self, scalar: &[u8]) -> Self {
        let mut acc = Self::identity();
        for &byte in scalar {
            let mut bit = 8;
            while bit > 0 {
                bit -= 1;
                acc = acc.double();
                let set = Choice::from_u8((byte >> bit) & 1);
                let sum = acc.add(self);
                acc = Self::conditional_select(&acc, &sum, set);
            }
        }
        acc
    }

    /// The affine `(x, y)` coordinates, or `None` for the identity.
    ///
    /// Not constant-time (the identity is a public condition).
    #[must_use]
    pub fn to_affine(&self) -> Option<(Fe<C>, Fe<C>)> {
        let zinv = self.z.invert();
        if zinv.is_none().into_bool() {
            return None;
        }
        let zi = zinv.unwrap();
        Some((self.x.mul(&zi), self.y.mul(&zi)))
    }

    /// Whether the projective point satisfies `Y²·Z = X³ − 3·X·Z² + b·Z³`.
    #[must_use]
    pub fn is_on_curve(&self) -> Choice {
        let bb = b_coeff::<C>();
        let three = Fe::<C>::from_u64(3);
        let z2 = self.z.square();
        let lhs = self.y.square().mul(&self.z);
        let x3 = self.x.square().mul(&self.x);
        let rhs = x3
            .sub(&three.mul(&self.x).mul(&z2))
            .add(&bb.mul(&z2).mul(&self.z));
        lhs.ct_eq(&rhs)
    }

    /// Parse a SEC1 point encoding: `04 || X || Y` (uncompressed) or
    /// `02|03 || X` (compressed). Returns `None` on a malformed encoding or a
    /// point that is not on the curve. Not constant-time.
    #[must_use]
    pub fn from_sec1(bytes: &[u8]) -> Option<Self> {
        let n = C::FIELD_BYTES;
        match bytes.first().copied()? {
            0x04 if bytes.len() == 1 + 2 * n => {
                let x = fe_from_be::<C::Base>(&bytes[1..1 + n])?;
                let y = fe_from_be::<C::Base>(&bytes[1 + n..1 + 2 * n])?;
                let p = Self {
                    x,
                    y,
                    z: FieldElement::one(),
                };
                p.is_on_curve().into_bool().then_some(p)
            }
            tag @ (0x02 | 0x03) if bytes.len() == 1 + n => {
                let x = fe_from_be::<C::Base>(&bytes[1..1 + n])?;
                let three = Fe::<C>::from_u64(3);
                let rhs = x.square().mul(&x).sub(&three.mul(&x)).add(&b_coeff::<C>());
                let root = rhs.sqrt();
                if root.is_none().into_bool() {
                    return None;
                }
                let mut y = root.unwrap();
                let want_odd = (tag & 1) == 1;
                let is_odd = (y.to_bytes()[FE_BYTES - 1] & 1) == 1;
                if is_odd != want_odd {
                    y = y.neg();
                }
                Some(Self {
                    x,
                    y,
                    z: FieldElement::one(),
                })
            }
            _ => None,
        }
    }

    /// Write the SEC1 uncompressed encoding `04 || X || Y` into `out`.
    ///
    /// `out` must be exactly `1 + 2 * FIELD_BYTES` long; returns `None` for the
    /// identity (which has no affine encoding) or a wrong-length buffer.
    #[must_use]
    pub fn to_sec1_uncompressed(&self, out: &mut [u8]) -> Option<()> {
        let n = C::FIELD_BYTES;
        if out.len() != 1 + 2 * n {
            return None;
        }
        let (x, y) = self.to_affine()?;
        out[0] = 0x04;
        out[1..1 + n].copy_from_slice(&x.to_bytes()[FE_BYTES - n..]);
        out[1 + n..1 + 2 * n].copy_from_slice(&y.to_bytes()[FE_BYTES - n..]);
        Some(())
    }

    /// Write the SEC1 compressed encoding `02|03 || X` into `out`.
    ///
    /// `out` must be exactly `1 + FIELD_BYTES` long.
    #[must_use]
    pub fn to_sec1_compressed(&self, out: &mut [u8]) -> Option<()> {
        let n = C::FIELD_BYTES;
        if out.len() != 1 + n {
            return None;
        }
        let (x, y) = self.to_affine()?;
        out[0] = 0x02 | (y.to_bytes()[FE_BYTES - 1] & 1);
        out[1..1 + n].copy_from_slice(&x.to_bytes()[FE_BYTES - n..]);
        Some(())
    }
}

impl<C: WeierstrassParams> CtEq for ProjectivePoint<C> {
    fn ct_eq(&self, other: &Self) -> Choice {
        // (X1:Y1:Z1) == (X2:Y2:Z2)  iff  X1·Z2 == X2·Z1  and  Y1·Z2 == Y2·Z1.
        let x_ok = self.x.mul(&other.z).ct_eq(&other.x.mul(&self.z));
        let y_ok = self.y.mul(&other.z).ct_eq(&other.y.mul(&self.z));
        x_ok.and(y_ok)
    }
}

/// Parse a big-endian coordinate of `n` bytes into a base-field element,
/// rejecting non-canonical (`>= p`) encodings.
fn fe_from_be<P: FieldParams>(bytes: &[u8]) -> Option<FieldElement<P>> {
    if bytes.len() > FE_BYTES {
        return None;
    }
    let mut buf = [0u8; FE_BYTES];
    buf[FE_BYTES - bytes.len()..].copy_from_slice(bytes);
    let fe = FieldElement::<P>::from_bytes(&buf);
    if fe.is_some().into_bool() {
        Some(fe.unwrap())
    } else {
        None
    }
}

/// P-256 projective point.
pub type P256Point = ProjectivePoint<P256>;
/// P-384 projective point.
pub type P384Point = ProjectivePoint<P384>;
