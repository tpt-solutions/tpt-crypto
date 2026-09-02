//! RFC 9380 hash-to-curve for the NIST prime curves.
//!
//! Implements the `expand_message_xmd` message expander (SHA-256 / SHA-384,
//! including the oversize-DST rule), `hash_to_field`, the constant-time
//! Simplified SWU map for `a = -3` short-Weierstrass curves, and the full
//! `hash_to_curve` (random-oracle) suites:
//!
//! * `P256_XMD:SHA-256_SSWU_RO_`
//! * `P384_XMD:SHA-384_SSWU_RO_`
//!
//! Both curves have cofactor 1, so `clear_cofactor` is the identity map and the
//! two mapped points are simply added.
//!
//! The SSWU map is branch-free on the field element `u` (all conditional steps
//! go through [`Field::ct_select`]); the message expander and `hash_to_field`
//! are fixed-trace. Edwards25519 (Elligator2) and BLS12-381 G1/G2 (isogeny
//! maps) are not yet covered here.

use tpt_crypto_field::{Choice, Field, FieldElement, FieldParams, MAX_LIMBS};
use tpt_crypto_hash::{
    sha2::{Sha256, Sha384},
    Hasher,
};

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

// --- Simplified SWU (a = -3) ---------------------------------------------

fn inv0<P: FieldParams>(x: &FieldElement<P>) -> FieldElement<P> {
    x.invert().unwrap_or(FieldElement::<P>::zero())
}

fn sgn0<P: FieldParams>(x: &FieldElement<P>) -> u8 {
    x.to_bytes()[FE_BYTES - 1] & 1
}

/// `map_to_curve_simple_swu` (RFC 9380 §6.6.2 / Appendix F.2), branch-free in `u`.
fn map_to_curve<C: Sswu>(u: &Fe<C>) -> ProjectivePoint<C> {
    let a = Fe::<C>::from_u64(3).neg();
    let b = b_coeff::<C>();
    let z = Fe::<C>::from_u64(C::Z_NEG).neg();
    let one = Fe::<C>::one();

    let u2 = u.square();
    let zu2 = z.mul(&u2);
    let den = zu2.square().add(&zu2); // Z^2 u^4 + Z u^2
    let tv1 = inv0(&den);
    let den_zero = den.is_zero();

    let x1a = b.neg().mul(&inv0(&a)).mul(&one.add(&tv1)); // (-B/A)(1 + tv1)
    let x1b = b.mul(&inv0(&z.mul(&a))); // B / (Z*A)
    let x1 = <Fe<C> as Field>::ct_select(&x1a, &x1b, den_zero);
    let gx1 = x1.square().mul(&x1).add(&a.mul(&x1)).add(&b);

    let x2 = zu2.mul(&x1);
    let gx2 = x2.square().mul(&x2).add(&a.mul(&x2)).add(&b);

    let s1 = gx1.sqrt();
    let use1 = s1.is_some();
    let y1 = s1.unwrap_or(Fe::<C>::zero());
    let y2 = gx2.sqrt().unwrap_or(Fe::<C>::zero());

    let x = <Fe<C> as Field>::ct_select(&x2, &x1, use1);
    let y0 = <Fe<C> as Field>::ct_select(&y2, &y1, use1);
    let flip = Choice::from_u8(sgn0(u) ^ sgn0(&y0));
    let y = <Fe<C> as Field>::ct_select(&y0, &y0.neg(), flip);

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
