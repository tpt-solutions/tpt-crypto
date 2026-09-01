//! P-256 / P-384 short-Weierstrass KATs.
//!
//! * generator is on the curve and has the stated prime order (`n·G = O`);
//! * RFC 5903 §8.1 / §8.2 ECDH test vectors (public key + shared secret);
//! * scalar-multiplication homomorphism and SEC1 encoding round-trips.

use tpt_crypto_curve::{P256Point, P384Point, ProjectivePoint, WeierstrassParams};
use tpt_crypto_field::CtEq;

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s).unwrap()
}

fn affine_xy<C: WeierstrassParams>(p: &ProjectivePoint<C>) -> (Vec<u8>, Vec<u8>) {
    let n = C::FIELD_BYTES;
    let mut out = vec![0u8; 1 + 2 * n];
    p.to_sec1_uncompressed(&mut out).expect("not identity");
    (out[1..1 + n].to_vec(), out[1 + n..].to_vec())
}

// ---------------------------------------------------------------- P-256

const P256_N: &str = "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551";

#[test]
fn p256_generator_on_curve_and_order() {
    let g = P256Point::generator();
    assert!(g.is_on_curve().into_bool());
    let ng = g.mul(&hx(P256_N));
    assert!(ng.is_identity().into_bool(), "n·G must be the identity");
}

#[test]
fn p256_rfc5903_ecdh() {
    let i = hx("C88F01F510D9AC3F70A292DAA2316DE544E9AAB8AFE84049C62A9C57862D1433");
    let gix = "dad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c3772581180";
    let giy = "5271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3";
    let r = hx("C6EF9C5D78AE012A011164ACB397CE2088685D8F06BF9BE0B283AB46476BEE53");
    let shared_x = "d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de";

    let g = P256Point::generator();
    let pub_i = g.mul(&i);
    let (x, y) = affine_xy(&pub_i);
    assert_eq!(hex::encode(&x), format!("{gix:0>64}"));
    assert_eq!(hex::encode(&y), format!("{giy:0>64}"));

    let pub_r = g.mul(&r);
    let s_ir = pub_r.mul(&i);
    let s_ri = pub_i.mul(&r);
    assert!(s_ir.ct_eq(&s_ri).into_bool());
    let (sx, _) = affine_xy(&s_ir);
    assert_eq!(hex::encode(&sx), format!("{shared_x:0>64}"));
}

#[test]
fn p256_scalar_homomorphism_and_encoding() {
    let g = P256Point::generator();
    let a = [0u8; 31].iter().copied().chain([7u8]).collect::<Vec<_>>();
    let b = [0u8; 31].iter().copied().chain([13u8]).collect::<Vec<_>>();
    let ab = [0u8; 31].iter().copied().chain([20u8]).collect::<Vec<_>>();
    let lhs = g.mul(&ab);
    let rhs = g.mul(&a).add(&g.mul(&b));
    assert!(lhs.ct_eq(&rhs).into_bool());

    let mut comp = [0u8; 33];
    lhs.to_sec1_compressed(&mut comp).unwrap();
    let back = P256Point::from_sec1(&comp).unwrap();
    assert!(back.ct_eq(&lhs).into_bool());

    let mut unc = [0u8; 65];
    lhs.to_sec1_uncompressed(&mut unc).unwrap();
    let back2 = P256Point::from_sec1(&unc).unwrap();
    assert!(back2.ct_eq(&lhs).into_bool());
}

// ---------------------------------------------------------------- P-384

const P384_N: &str = "ffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973";

#[test]
fn p384_generator_on_curve_and_order() {
    let g = P384Point::generator();
    assert!(g.is_on_curve().into_bool());
    let ng = g.mul(&hx(P384_N));
    assert!(ng.is_identity().into_bool(), "n·G must be the identity");
}

#[test]
fn p384_rfc5903_ecdh() {
    let i = hx("099F3C7034D4A2C699884D73A375A67F7624EF7C6B3C0F160647B67414DCE655E35B538041E649EE3FAEF896783AB194");
    let gix = "667842d7d180ac2cde6f74f37551f55755c7645c20ef73e31634fe72b4c55ee6de3ac808acb4bdb4c88732aee95f41aa";
    let giy = "9482ed1fc0eeb9cafc4984625ccfc23f65032149e0e144ada024181535a0f38eeb9fcff3c2c947dae69b4c634573a81c";
    let r = hx("41CB0779B4BDB85D47846725FBEC3C9430FAB46CC8DC5060855CC9BDA0AA2942E0308312916B8ED2960E4BD55A7448FC");
    let shared_x = "11187331c279962d93d604243fd592cb9d0a926f422e47187521287e7156c5c4d603135569b9e9d09cf5d4a270f59746";

    let g = P384Point::generator();
    let pub_i = g.mul(&i);
    let (x, y) = affine_xy(&pub_i);
    assert_eq!(hex::encode(&x), gix);
    assert_eq!(hex::encode(&y), giy);

    let pub_r = g.mul(&r);
    let s_ir = pub_r.mul(&i);
    let (sx, _) = affine_xy(&s_ir);
    assert_eq!(hex::encode(&sx), shared_x);
}
