//! BLS12-381 group + pairing tests: subgroup structure, bilinearity,
//! non-degeneracy, and `GT ⊂ μ_r`.

#![cfg(feature = "alloc")]

use tpt_crypto_curve::bls12_381::{multi_pairing, pairing, Gt, G1, G2};
use tpt_crypto_field::{CtEq, Field};

/// `r` as little-endian `u64` limbs (BLS12-381 scalar-field modulus).
const R_LE: [u64; 4] = [
    0xffff_ffff_0000_0001,
    0x53bd_a402_fffe_5bfe,
    0x3339_d808_09a1_d805,
    0x73ed_a753_299d_7d48,
];

#[test]
fn generators_on_curve_and_in_subgroup() {
    assert!(G1::generator().is_on_curve().into_bool());
    assert!(G2::generator().is_on_curve().into_bool());
    assert!(G1::generator().is_torsion_free().into_bool());
    assert!(G2::generator().is_torsion_free().into_bool());
}

#[test]
fn r_kills_the_generators() {
    let rn = tpt_crypto_curve::bls12_381::subgroup_order_be();
    assert!(G1::generator().mul(&rn).is_identity().into_bool());
    assert!(G2::generator().mul(&rn).is_identity().into_bool());
}

#[test]
fn pairing_non_degenerate() {
    let e = pairing(&G1::generator(), &G2::generator());
    assert!(!e.ct_eq(&Gt::one()).into_bool(), "e(G1,G2) must not be 1");
    // e(O, Q) = 1
    assert!(pairing(&G1::identity(), &G2::generator())
        .ct_eq(&Gt::one())
        .into_bool());
}

#[test]
fn pairing_output_in_mu_r() {
    let e = pairing(&G1::generator(), &G2::generator());
    let raised = e.0.pow_vartime(&R_LE);
    assert!(raised.ct_eq(&Field::one()).into_bool(), "e(G1,G2)^r must be 1");
}

#[test]
fn bilinearity_scalar_moves_across() {
    let g1 = G1::generator();
    let g2 = G2::generator();

    // e([3]P, [5]Q) == e([15]P, Q) == e(P, [15]Q)
    let lhs = pairing(&g1.mul(&[3]), &g2.mul(&[5]));
    let mid = pairing(&g1.mul(&[15]), &g2);
    let rhs = pairing(&g1, &g2.mul(&[15]));
    assert!(lhs.ct_eq(&mid).into_bool());
    assert!(mid.ct_eq(&rhs).into_bool());
}

#[test]
fn bilinearity_additive_in_g2() {
    let p = G1::generator().mul(&[7]);
    let q1 = G2::generator().mul(&[2]);
    let q2 = G2::generator().mul(&[9]);

    let product = pairing(&p, &q1).mul(&pairing(&p, &q2));
    let combined = pairing(&p, &q1.add(&q2));
    assert!(product.ct_eq(&combined).into_bool());
}

#[test]
fn multi_pairing_matches_product() {
    let p1 = G1::generator().mul(&[4]);
    let q1 = G2::generator().mul(&[6]);
    let p2 = G1::generator().mul(&[5]);
    let q2 = G2::generator().mul(&[3]);

    let via_multi = multi_pairing(&[(p1, q1), (p2, q2)]);
    let via_each = pairing(&p1, &q1).mul(&pairing(&p2, &q2));
    assert!(via_multi.ct_eq(&via_each).into_bool());

    // e(P,Q)·e(-P,Q) == 1
    let p = G1::generator();
    let q = G2::generator();
    let both = multi_pairing(&[(p, q), (p.neg(), q)]);
    assert!(both.ct_eq(&Gt::one()).into_bool());
}
