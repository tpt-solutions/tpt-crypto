//! RFC 9380 hash-to-curve.
//!
//! Implements the `expand_message_xmd` message expander (SHA-256 / SHA-384 /
//! SHA-512, including the oversize-DST rule), `hash_to_field`, a generic
//! branch-free Simplified SWU map (any `a ≠ 0`, over `Fp` or `Fp²`), the
//! Elligator 2 map for curve25519, and the full `hash_to_curve`
//! (random-oracle) suites:
//!
//! * `P256_XMD:SHA-256_SSWU_RO_`
//! * `P384_XMD:SHA-384_SSWU_RO_`
//! * `edwards25519_XMD:SHA-512_ELL2_RO_` ([`hash_to_curve_edwards25519`])
//! * `BLS12381G1_XMD:SHA-256_SSWU_RO_` ([`hash_to_curve_bls12381_g1`], `alloc`)
//! * `BLS12381G2_XMD:SHA-256_SSWU_RO_` ([`hash_to_curve_bls12381_g2`], `alloc`)
//!
//! P-256 / P-384 have cofactor 1 (`clear_cofactor` is the identity);
//! edwards25519 clears with `[8]`; BLS12-381 G1 with `[0xd201000000010001]`;
//! G2 with the ψ-based Budroni–Pintore map. G1 goes through the isogenous
//! curve `E'` (`Z = 11`) + the 11-isogeny; G2 through `E'/Fp²`
//! (`Z = -(2 + u)`) + the 3-isogeny.
//!
//! The SSWU / Elligator 2 maps are branch-free on the field element `u` (all
//! conditional steps go through [`Field::ct_select`]); the message expander and
//! `hash_to_field` are fixed-trace.

use tpt_crypto_field::{
    Choice, CtEq, Ed25519Field, Ed25519FieldParams, Field, FieldElement, FieldParams, MAX_LIMBS,
};
use tpt_crypto_hash::{
    sha2::{Sha256, Sha384, Sha512},
    Hasher,
};

use crate::edwards25519::EdwardsPoint;
use crate::weierstrass::{b_coeff, ProjectivePoint, WeierstrassParams, P256, P384};

type Fe<C> = FieldElement<<C as WeierstrassParams>::Base>;

const FE_BYTES: usize = MAX_LIMBS * 8;

/// A short-Weierstrass curve (`a = -3`) wired for the SSWU hash-to-curve suite.
pub trait Sswu: WeierstrassParams {
    /// `L` from RFC 9380 §5.1 — bytes of expander output per field element.
    const L: usize;
    /// The map parameter `Z` is `-(Z_NEG)` (a small non-residue).
    const Z_NEG: u64;
    /// `true` selects `expand_message_xmd` with SHA-384, `false` SHA-256.
    const XMD_SHA384: bool;
}

impl Sswu for P256 {
    const L: usize = 48;
    const Z_NEG: u64 = 10;
    const XMD_SHA384: bool = false;
}

impl Sswu for P384 {
    const L: usize = 72;
    const Z_NEG: u64 = 12;
    const XMD_SHA384: bool = true;
}

// --- expand_message_xmd -----------------------------------------------------

fn hash_all<const BB: usize, H: Hasher<BB> + Default>(parts: &[&[u8]]) -> [u8; BB] {
    let mut h = H::default();
    for p in parts {
        h.update(p);
    }
    h.finalize()
}

/// `expand_message_xmd` (RFC 9380 §5.3.1). `BB` is the hash output length,
/// `s_in_bytes` its input block size. Panics only on out-of-range parameters
/// (all fixed and valid for the suites here).
pub fn expand_message_xmd<const BB: usize, H: Hasher<BB> + Default>(
    msg: &[u8],
    dst: &[u8],
    out: &mut [u8],
    s_in_bytes: usize,
) {
    let ell = out.len().div_ceil(BB);
    assert!(ell <= 255 && out.len() <= 65535 && !dst.is_empty());

    // DST_prime, applying the oversize-DST hash rule (RFC 9380 §5.3.3).
    let mut short = [0u8; 256];
    let dst_src: &[u8] = if dst.len() > 255 {
        let h = hash_all::<BB, H>(&[b"H2C-OVERSIZE-DST-", dst]);
        short[..BB].copy_from_slice(&h);
        &short[..BB]
    } else {
        dst
    };
    let mut dstp = [0u8; 257];
    dstp[..dst_src.len()].copy_from_slice(dst_src);
    dstp[dst_src.len()] = dst_src.len() as u8;
    let dst_prime = &dstp[..dst_src.len() + 1];

    let z_pad = [0u8; 128];
    let l_i_b_str = (out.len() as u16).to_be_bytes();

    let b0 = hash_all::<BB, H>(&[&z_pad[..s_in_bytes], msg, &l_i_b_str, &[0u8], dst_prime]);
    let b1 = hash_all::<BB, H>(&[&b0, &[1u8], dst_prime]);

    let mut prev = b1;
    let mut off = 0usize;
    let n = core::cmp::min(BB, out.len());
    out[..n].copy_from_slice(&b1[..n]);
    off += BB;
    let mut i = 2u8;
    while off < out.len() {
        let mut xored = [0u8; BB];
        for j in 0..BB {
            xored[j] = b0[j] ^ prev[j];
        }
        let bi = hash_all::<BB, H>(&[&xored, &[i], dst_prime]);
        let n = core::cmp::min(BB, out.len() - off);
        out[off..off + n].copy_from_slice(&bi[..n]);
        prev = bi;
        off += BB;
        i += 1;
    }
}

// --- hash_to_field --------------------------------------------------------

/// `OS2IP(bytes) mod p`, reduced into `GF(p)` by Horner's method (fixed-trace).
fn os2ip_mod<P: FieldParams>(bytes: &[u8]) -> FieldElement<P> {
    let mut acc = FieldElement::<P>::zero();
    let b256 = FieldElement::<P>::from_u64(256);
    for &byte in bytes {
        acc = acc
            .mul(&b256)
            .add(&FieldElement::<P>::from_u64(u64::from(byte)));
    }
    acc
}

fn hash_to_field_2<C: Sswu>(msg: &[u8], dst: &[u8]) -> (Fe<C>, Fe<C>) {
    let total = 2 * C::L;
    let mut uni = [0u8; 144];
    if C::XMD_SHA384 {
        expand_message_xmd::<48, Sha384>(msg, dst, &mut uni[..total], 128);
    } else {
        expand_message_xmd::<32, Sha256>(msg, dst, &mut uni[..total], 64);
    }
    (
        os2ip_mod::<C::Base>(&uni[..C::L]),
        os2ip_mod::<C::Base>(&uni[C::L..total]),
    )
}

// --- Simplified SWU (generic, RFC 9380 §6.6.2 / Appendix F.2) -----------

fn inv0<P: FieldParams>(x: &FieldElement<P>) -> FieldElement<P> {
    x.invert().unwrap_or(FieldElement::<P>::zero())
}

fn inv0f<F: Field>(x: &F) -> F {
    x.invert().unwrap_or(F::zero())
}

fn sgn0<P: FieldParams>(x: &FieldElement<P>) -> u8 {
    x.to_bytes()[FE_BYTES - 1] & 1
}

/// `(sqrt(v), is_square(v))` for a prime field via the trait `sqrt`.
fn fe_sqrt<P: FieldParams>(v: &FieldElement<P>) -> (FieldElement<P>, bool) {
    let r = v.sqrt();
    (
        r.unwrap_or(FieldElement::<P>::zero()),
        r.is_some().into_bool(),
    )
}

/// Branch-free Simplified SWU for any Weierstrass curve `y² = x³ + a·x + b`
/// with `a ≠ 0` (the generic `(-b/a)(1 + tv1)` form). `z` is the map parameter,
/// `sgn0` the field's sign function, `sqrt` returns `(root, is_square)`.
/// Returns affine `(x, y)`.
fn sswu_affine<F: Field>(
    u: &F,
    a: &F,
    b: &F,
    z: &F,
    sgn0: fn(&F) -> u8,
    sqrt: fn(&F) -> (F, bool),
) -> (F, F) {
    let one = F::one();
    let u2 = u.square();
    let zu2 = z.mul(&u2);
    let den = zu2.square().add(&zu2); // Z²u⁴ + Zu²
    let tv1 = inv0f(&den);
    let den_zero = den.is_zero();

    let x1a = b.neg().mul(&inv0f(a)).mul(&one.add(&tv1)); // (-b/a)(1 + tv1)
    let x1b = b.mul(&inv0f(&z.mul(a))); // b / (Z·a)
    let x1 = F::ct_select(&x1a, &x1b, den_zero);
    let gx1 = x1.square().mul(&x1).add(&a.mul(&x1)).add(b);

    let x2 = zu2.mul(&x1);
    let gx2 = x2.square().mul(&x2).add(&a.mul(&x2)).add(b);

    let (y1, ok1) = sqrt(&gx1);
    let (y2, _) = sqrt(&gx2);
    let use1 = Choice::from_u8(u8::from(ok1));

    let x = F::ct_select(&x2, &x1, use1);
    let y0 = F::ct_select(&y2, &y1, use1);
    let flip = Choice::from_u8(sgn0(u) ^ sgn0(&y0));
    let y = F::ct_select(&y0, &y0.neg(), flip);
    (x, y)
}

/// `map_to_curve` for a cofactor-1 NIST SSWU suite (`a = -3`).
fn map_to_curve<C: Sswu>(u: &Fe<C>) -> ProjectivePoint<C> {
    let a = Fe::<C>::from_u64(3).neg();
    let b = b_coeff::<C>();
    let z = Fe::<C>::from_u64(C::Z_NEG).neg();
    let (x, y) = sswu_affine(u, &a, &b, &z, sgn0::<C::Base>, fe_sqrt::<C::Base>);
    ProjectivePoint::from_affine_unchecked(x, y)
}

// --- suites --------------------------------------------------------------

/// `hash_to_curve` (random-oracle) for a cofactor-1 SSWU suite.
///
/// `dst` is the full domain-separation tag (e.g.
/// `b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_"`).
#[must_use]
pub fn hash_to_curve<C: Sswu>(msg: &[u8], dst: &[u8]) -> ProjectivePoint<C> {
    let (u0, u1) = hash_to_field_2::<C>(msg, dst);
    // clear_cofactor is the identity for cofactor 1.
    map_to_curve::<C>(&u0).add(&map_to_curve::<C>(&u1))
}

// --- edwards25519 (Elligator 2) -----------------------------------------

/// Elligator 2 map to curve25519 (`y² = x³ + 486662·x² + x`, `Z = 2`),
/// straight-line / branch-free form (RFC 9380 §6.7.1). Returns the Montgomery
/// affine `(s, t)`.
fn map_to_curve_ell2_25519(u: &Ed25519Field) -> (Ed25519Field, Ed25519Field) {
    let j = Ed25519Field::from_u64(486_662);
    let one = Ed25519Field::one();
    let z = Ed25519Field::from_u64(2);

    let tv1 = z.mul(&u.square()); // Z·u²
    let e1 = tv1.ct_eq(&one.neg());
    let tv1 = <Ed25519Field as Field>::ct_select(&tv1, &Ed25519Field::zero(), e1);

    let x1 = j.neg().mul(&inv0(&tv1.add(&one))); // -J / (1 + Z·u²)
                                                 // gx1 = x1³ + J·x1² + x1  (K = 1)
    let gx1 = x1.add(&j).mul(&x1).add(&one).mul(&x1);
    let x2 = x1.neg().sub(&j);
    let gx2 = tv1.mul(&gx1);

    let s1 = gx1.sqrt();
    let e2 = s1.is_some();
    let x = <Ed25519Field as Field>::ct_select(&x2, &x1, e2);
    let y1 = s1.unwrap_or(Ed25519Field::zero());
    let y2 = gx2.sqrt().unwrap_or(Ed25519Field::zero());
    let y0 = <Ed25519Field as Field>::ct_select(&y2, &y1, e2);

    // y = CMOV(y0, -y0, e2 XOR (sgn0(y0) == 1))
    let e3 = sgn0(&y0) == 1;
    let flip = Choice::from_bool(e2.into_bool() ^ e3);
    let y = <Ed25519Field as Field>::ct_select(&y0, &y0.neg(), flip);
    (x, y)
}

/// `sqrt(-486664)` with `sgn0 == 0` — the birational-map constant for
/// curve25519 → edwards25519 (RFC 9380).
fn sqrt_minus_486664() -> Ed25519Field {
    let r = Ed25519Field::from_u64(486_664)
        .neg()
        .sqrt()
        .unwrap_or(Ed25519Field::zero());
    let odd = Choice::from_u8(sgn0(&r));
    <Ed25519Field as Field>::ct_select(&r, &r.neg(), odd)
}

/// Birational map curve25519 → edwards25519 (RFC 9380 `m2e_25519`):
/// `v = sqrt(-486664)·x / y`, `w = (x - 1) / (x + 1)`, with the exceptional
/// Montgomery points folded in branch-free. Input `(x, y)` Montgomery affine,
/// output `(v, w)` = twisted-Edwards `(x, y)`.
fn ell2_curve25519_to_edwards(x: &Ed25519Field, y: &Ed25519Field) -> (Ed25519Field, Ed25519Field) {
    let one = Ed25519Field::one();
    let sel = <Ed25519Field as Field>::ct_select;

    let v = sqrt_minus_486664().mul(x).mul(&inv0(y)); // 0 when y == 0
    let w = x.sub(&one).mul(&inv0(&x.add(&one)));

    let y_zero = y.is_zero();
    let x_neg1 = x.ct_eq(&one.neg());
    let exc = y_zero.or(x_neg1); // → (0, 1)
    let at_2t = x.is_zero().and(y_zero); // (0, 0) → (0, -1)

    let v = sel(&v, &Ed25519Field::zero(), exc);
    let w = sel(&w, &one, exc);
    let w = sel(&w, &one.neg(), at_2t);
    (v, w)
}

fn map_to_edwards25519(u: &Ed25519Field) -> EdwardsPoint {
    let (s, t) = map_to_curve_ell2_25519(u);
    let (v, w) = ell2_curve25519_to_edwards(&s, &t);
    EdwardsPoint::from_affine_unchecked(v, w)
}

/// `hash_to_curve` for the `edwards25519_XMD:SHA-512_ELL2_RO_` suite (RFC 9380).
///
/// `dst` is the full domain-separation tag, e.g.
/// `b"QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_RO_"`.
#[must_use]
pub fn hash_to_curve_edwards25519(msg: &[u8], dst: &[u8]) -> EdwardsPoint {
    let mut uni = [0u8; 96];
    expand_message_xmd::<64, Sha512>(msg, dst, &mut uni, 128);
    let u0 = os2ip_mod::<Ed25519FieldParams>(&uni[..48]);
    let u1 = os2ip_mod::<Ed25519FieldParams>(&uni[48..]);
    let r = map_to_edwards25519(&u0).add(&map_to_edwards25519(&u1));
    r.mul_by_cofactor() // clear_cofactor = [8]
}

// --- BLS12-381 G1 / G2 (SSWU + isogeny) -------------------------------

/// `hash_to_curve` for `BLS12381G1_XMD:SHA-256_SSWU_RO_` (RFC 9380 §8.8.1)
/// and `BLS12381G2_XMD:SHA-256_SSWU_RO_` (§8.8.2).
#[cfg(feature = "alloc")]
mod bls {
    use super::{expand_message_xmd, fe_sqrt, inv0, inv0f, os2ip_mod, sgn0, sswu_affine};
    use crate::bls12_381::{G1, G2};
    use tpt_crypto_field::{Bls12381Fp as Fp, Bls12381FpParams, CtEq, Field, Fp2};
    use tpt_crypto_hash::sha2::Sha256;

    // Isogenous-curve parameters E': y² = x³ + A'x + B'  (RFC 9380 §8.8.1), Z = 11.
    const AP: &str =
        "00144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d";
    const BP: &str =
        "12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0";

    include!("iso11_g1.rs");
    include!("iso3_g2.rs");

    const fn hx(c: u8) -> u8 {
        match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            _ => 0,
        }
    }

    fn fp_be_hex(s: &str) -> Fp {
        let b = s.as_bytes();
        debug_assert!(b.len() == 96);
        let mut be = [0u8; 48];
        let mut i = 0;
        while i < 48 {
            be[i] = (hx(b[2 * i]) << 4) | hx(b[2 * i + 1]);
            i += 1;
        }
        Fp::from_bytes(&be).unwrap_or(Fp::zero())
    }

    /// Horner evaluation of `Σ coeffs[i]·xⁱ` (coefficients ascending).
    fn poly(coeffs: &[&str], x: &Fp) -> Fp {
        let mut acc = Fp::zero();
        for c in coeffs.iter().rev() {
            acc = acc.mul(x).add(&fp_be_hex(c));
        }
        acc
    }

    /// 11-isogeny E' → E on affine `(x', y')`.
    fn iso11(xp: &Fp, yp: &Fp) -> (Fp, Fp) {
        let x = poly(&ISO11_XNUM, xp).mul(&inv0(&poly(&ISO11_XDEN, xp)));
        let y = yp
            .mul(&poly(&ISO11_YNUM, xp))
            .mul(&inv0(&poly(&ISO11_YDEN, xp)));
        (x, y)
    }

    fn map_to_g1(u: &Fp, a: &Fp, b: &Fp, z: &Fp) -> G1 {
        let (xp, yp) = sswu_affine(
            u,
            a,
            b,
            z,
            sgn0::<Bls12381FpParams>,
            fe_sqrt::<Bls12381FpParams>,
        );
        let (x, y) = iso11(&xp, &yp);
        G1::from_affine_unchecked(x, y)
    }

    // (p − 3) / 4 and (p − 1) / 2 for the BLS12-381 base prime, LE u64 words.
    const P_M3_D4: [u64; 6] = [
        0xee7f_bfff_ffff_eaaa,
        0x07aa_ffff_ac54_ffff,
        0xd9cc_34a8_3dac_3d89,
        0xd91d_d2e1_3ce1_44af,
        0x92c6_e9ed_90d2_eb35,
        0x0680_447a_8e5f_f9a6,
    ];
    const P_M1_D2: [u64; 6] = [
        0xdcff_7fff_ffff_d555,
        0x0f55_ffff_58a9_ffff,
        0xb398_6950_7b58_7b12,
        0xb23b_a5c2_79c2_895f,
        0x258d_d3db_21a5_d66b,
        0x0d00_88f5_1cbf_f34d,
    ];

    /// Fp2 square root (Adj–Rodríguez, eprint 2012/685 Alg. 9; base prime
    /// `p ≡ 3 (mod 4)`). Returns `(root, is_square)`.
    fn fp2_sqrt(a: &Fp2) -> (Fp2, bool) {
        let neg_one = Fp2::one().neg();
        let a1 = a.pow_vartime(&P_M3_D4);
        let alpha = a1.square().mul(a);
        let a1a = a1.mul(a);
        let a0 = alpha.conjugate().mul(&alpha);
        if a0.ct_eq(&neg_one).into_bool() {
            return (Fp2::zero(), false);
        }
        let x0 = if alpha.ct_eq(&neg_one).into_bool() {
            a1a.mul(&Fp2::new(Fp::zero(), Fp::one())) // · u
        } else {
            alpha.add(&Fp2::one()).pow_vartime(&P_M1_D2).mul(&a1a)
        };
        let ok = x0.square().ct_eq(a).into_bool();
        (x0, ok)
    }

    /// `hash_to_curve` (random oracle) into `G1`.
    #[must_use]
    pub fn hash_to_curve_bls12381_g1(msg: &[u8], dst: &[u8]) -> G1 {
        let a = fp_be_hex(AP);
        let b = fp_be_hex(BP);
        let z = Fp::from_u64(11);
        let mut uni = [0u8; 128];
        expand_message_xmd::<32, Sha256>(msg, dst, &mut uni, 64);
        let u0 = os2ip_mod::<Bls12381FpParams>(&uni[..64]);
        let u1 = os2ip_mod::<Bls12381FpParams>(&uni[64..]);
        map_to_g1(&u0, &a, &b, &z)
            .add(&map_to_g1(&u1, &a, &b, &z))
            .clear_cofactor()
    }

    // --- G2 (SSWU over Fp2 + 3-isogeny) -------------------------------

    fn fp2_hex(c0: &str, c1: &str) -> Fp2 {
        Fp2::new(fp_be_hex(c0), fp_be_hex(c1))
    }

    fn sgn0_fp2(x: &Fp2) -> u8 {
        let s0 = sgn0::<Bls12381FpParams>(&x.c0);
        let s1 = sgn0::<Bls12381FpParams>(&x.c1);
        let z0 = u8::from(x.c0.is_zero().into_bool());
        s0 | (z0 & s1)
    }

    fn poly2(coeffs: &[(&str, &str)], x: &Fp2) -> Fp2 {
        let mut acc = Fp2::zero();
        for (a, b) in coeffs.iter().rev() {
            acc = acc.mul(x).add(&fp2_hex(a, b));
        }
        acc
    }

    /// 3-isogeny E' → E on affine `(x', y')` over Fp2.
    fn iso3(xp: &Fp2, yp: &Fp2) -> (Fp2, Fp2) {
        let x = poly2(&ISO3_XNUM, xp).mul(&inv0f(&poly2(&ISO3_XDEN, xp)));
        let y = yp
            .mul(&poly2(&ISO3_YNUM, xp))
            .mul(&inv0f(&poly2(&ISO3_YDEN, xp)));
        (x, y)
    }

    fn map_to_g2(u: &Fp2, a: &Fp2, b: &Fp2, z: &Fp2) -> G2 {
        let (xp, yp) = sswu_affine(u, a, b, z, sgn0_fp2, fp2_sqrt);
        let (x, y) = iso3(&xp, &yp);
        G2::from_affine_unchecked(x, y)
    }

    /// `hash_to_curve` (random oracle) into `G2`.
    #[must_use]
    pub fn hash_to_curve_bls12381_g2(msg: &[u8], dst: &[u8]) -> G2 {
        // E': A' = 240·u, B' = 1012·(1 + u), Z = -(2 + u).
        let a = Fp2::new(Fp::zero(), Fp::from_u64(240));
        let b = Fp2::new(Fp::from_u64(1012), Fp::from_u64(1012));
        let z = Fp2::new(Fp::from_u64(2), Fp::from_u64(1)).neg();

        let mut uni = [0u8; 256];
        expand_message_xmd::<32, Sha256>(msg, dst, &mut uni, 64);
        let e = |i: usize| os2ip_mod::<Bls12381FpParams>(&uni[i * 64..(i + 1) * 64]);
        let u0 = Fp2::new(e(0), e(1));
        let u1 = Fp2::new(e(2), e(3));

        map_to_g2(&u0, &a, &b, &z)
            .add(&map_to_g2(&u1, &a, &b, &z))
            .clear_cofactor()
    }
}

#[cfg(feature = "alloc")]
pub use bls::{hash_to_curve_bls12381_g1, hash_to_curve_bls12381_g2};
