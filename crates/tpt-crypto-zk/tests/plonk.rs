//! PLONK verifier tests: prover–verifier round trip (completeness), proof
//! tampering negatives (soundness), and serialization round trip. The prover
//! lives in `tests/plonk_common` — the shipped crate is verifier-only.
#![allow(missing_docs, clippy::too_many_arguments, clippy::needless_range_loop)]

mod plonk_common;

use plonk_common::{prove, tutorial_circuit};
use tpt_crypto_zk::plonk::Proof;

#[test]
fn plonk_honest_proof_verifies() {
    let circ = tutorial_circuit(3); // 27 + 3 + 5 = 35
    let (vk, proof) = prove(&circ, 1);
    vk.verify(&proof).expect("honest proof must verify");
}

#[test]
fn plonk_proof_round_trips_through_bytes() {
    let circ = tutorial_circuit(3);
    let (vk, proof) = prove(&circ, 2);
    let bytes = proof.to_bytes();
    let parsed = Proof::from_bytes(&bytes).expect("parse");
    vk.verify(&parsed).expect("parsed proof must verify");
}

#[test]
fn plonk_rejects_tampered_evaluations() {
    let circ = tutorial_circuit(3);
    let (vk, proof) = prove(&circ, 3);
    // Tamper each scalar evaluation in turn; every variant must fail.
    let scalars = [
        proof.a_eval,
        proof.b_eval,
        proof.c_eval,
        proof.ql_eval,
        proof.qr_eval,
        proof.qo_eval,
        proof.qm_eval,
        proof.qc_eval,
        proof.s1_eval,
        proof.s2_eval,
        proof.s3_eval,
        proof.z_eval,
        proof.z_omega_eval,
        proof.t_lo_eval,
        proof.t_mid_eval,
        proof.t_hi_eval,
    ];
    for i in 0..scalars.len() {
        let mut p = proof.clone();
        let bumped = scalars[i].add(&tpt_crypto_zk::Ed25519Scalar::one());
        match i {
            0 => p.a_eval = bumped,
            1 => p.b_eval = bumped,
            2 => p.c_eval = bumped,
            3 => p.ql_eval = bumped,
            4 => p.qr_eval = bumped,
            5 => p.qo_eval = bumped,
            6 => p.qm_eval = bumped,
            7 => p.qc_eval = bumped,
            8 => p.s1_eval = bumped,
            9 => p.s2_eval = bumped,
            10 => p.s3_eval = bumped,
            11 => p.z_eval = bumped,
            12 => p.z_omega_eval = bumped,
            13 => p.t_lo_eval = bumped,
            14 => p.t_mid_eval = bumped,
            15 => p.t_hi_eval = bumped,
            _ => unreachable!(),
        }
        assert!(
            vk.verify(&p).is_err(),
            "tampered evaluation {i} must not verify"
        );
    }
}

#[test]
fn plonk_rejects_wrong_public_input() {
    use plonk_common::setup;
    // A proof for x³+x = 30 (i.e. x³+x+5 = 35) must not verify against a
    // circuit whose baked-in public constant is 36.
    let circ = tutorial_circuit(3);
    let (vk, proof) = prove(&circ, 4);
    let mut circ36 = tutorial_circuit(3);
    circ36.q_c[3] = tpt_crypto_zk::Ed25519Scalar::from_u64(36).neg();
    let vk36 = setup(&circ36);
    assert!(
        vk36.verify(&proof).is_err(),
        "proof for constant 30 must fail under the 36 key"
    );
    let _ = vk;
}

#[test]
fn plonk_rejects_tampered_commitments() {
    let circ = tutorial_circuit(3);
    let (vk, proof) = prove(&circ, 5);
    for i in 0..7u8 {
        let mut p = proof.clone();
        let mut cm = match i {
            0 => p.a,
            1 => p.b,
            2 => p.c,
            3 => p.z,
            4 => p.t_lo,
            5 => p.t_mid,
            6 => p.t_hi,
            _ => unreachable!(),
        };
        cm[5] ^= 0x40;
        match i {
            0 => p.a = cm,
            1 => p.b = cm,
            2 => p.c = cm,
            3 => p.z = cm,
            4 => p.t_lo = cm,
            5 => p.t_mid = cm,
            6 => p.t_hi = cm,
            _ => unreachable!(),
        }
        // Either the decompression fails or the opening checks fail.
        assert!(vk.verify(&p).is_err(), "tampered commitment {i} must fail");
    }
}

#[test]
fn plonk_rejects_truncated_serialization() {
    let circ = tutorial_circuit(3);
    let (_, proof) = prove(&circ, 6);
    let bytes = proof.to_bytes();
    assert!(Proof::from_bytes(&bytes[..bytes.len() - 1]).is_err());
    assert!(Proof::from_bytes(&bytes[..224]).is_err());
}
