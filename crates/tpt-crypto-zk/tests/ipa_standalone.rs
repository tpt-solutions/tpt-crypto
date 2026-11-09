//! Regression test for the standalone `InnerProductProof::verify`.
//!
//! Round-trips honest proofs from `InnerProductProof::create` through
//! `InnerProductProof::verify` across several sizes (all-ones generator factors).

use tpt_crypto_zk::{BulletproofGens, Ed25519Scalar, InnerProductProof, Ristretto, Transcript};

fn scalars(seed: u64, n: usize) -> Vec<Ed25519Scalar> {
    (0..n as u64)
        .map(|i| Ed25519Scalar::from_u64(seed.wrapping_mul(0x9E37_79B9).wrapping_add(i + 1)))
        .collect()
}

#[test]
fn standalone_verify_accepts_honest_proof() {
    for n in [2usize, 4, 8, 16, 32] {
        for seed in 1..=3u64 {
            check(n, seed);
        }
    }
}

fn check(n: usize, seed: u64) {
    let one = vec![Ed25519Scalar::from_u64(1); n];
    let g = BulletproofGens::g_vec(n, 1);
    let h = BulletproofGens::h_vec(n, 1);
    let q = Ristretto::map_to_point(b"ipa-standalone-q");
    let a = scalars(3 * seed, n);
    let b = scalars(5 * seed, n);

    let mut inner = Ed25519Scalar::from_u64(0);
    for i in 0..n {
        inner = inner.add(&a[i].mul(&b[i]));
    }
    let p = Ristretto::msm(&a, &g)
        .add(&Ristretto::msm(&b, &h))
        .add(&q.scalar_mul(&inner));

    let mut tp = Transcript::new(b"ipa-standalone");
    let proof = InnerProductProof::create(
        &mut tp,
        &q,
        &one,
        &one,
        g.clone(),
        h.clone(),
        a.clone(),
        b.clone(),
    );

    let mut tv = Transcript::new(b"ipa-standalone");
    proof
        .verify(n, &mut tv, &one, &one, &p, &q, &g, &h)
        .expect("honest proof must verify");

    // A commitment to a different inner product must be rejected.
    let wrong_p = p.add(&q);
    let mut tw = Transcript::new(b"ipa-standalone");
    assert!(proof
        .verify(n, &mut tw, &one, &one, &wrong_p, &q, &g, &h)
        .is_err());
}
