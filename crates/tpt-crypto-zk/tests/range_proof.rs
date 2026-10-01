//! Bulletproofs range-proof properties backing `specs/bulletproofs_verify.spec`.

use proptest::prelude::*;
use tpt_crypto_zk::{
    prove_range, range_proof_from_bytes, range_proof_to_bytes, verify_range, Ed25519Scalar,
    PedersenGens, SeedExpander, ZkError,
};

fn blinds(seed: u64, m: usize) -> Vec<Ed25519Scalar> {
    (0..m as u64)
        .map(|j| Ed25519Scalar::from_u64(seed.wrapping_mul(0x9E37_79B9).wrapping_add(j + 1)))
        .collect()
}

fn honest(values: &[u64], n: usize, seed: u64) -> (Vec<u8>, Vec<tpt_crypto_zk::Ristretto>) {
    let mut rng = SeedExpander::new(&seed.to_le_bytes());
    let (proof, vs) = prove_range(values, &blinds(seed, values.len()), n, &mut rng);
    (range_proof_to_bytes(&proof), vs)
}

/// Completeness: honest proofs verify, including after a serialization round trip.
#[test]
fn range_proof_completeness() {
    for (values, n) in [
        (vec![0u64], 8),
        (vec![255], 8),
        (vec![u16::MAX as u64], 16),
        (vec![u32::MAX as u64], 32),
        (vec![u64::MAX], 64),
        (vec![1, 4_000_000_000], 32), // aggregated, m = 2
    ] {
        let (bytes, vs) = honest(&values, n, 7);
        let proof = range_proof_from_bytes(&bytes).expect("canonical bytes parse");
        assert_eq!(verify_range(&vs, &proof, n), Ok(()), "n={n} {values:?}");
    }
}

/// Binding: a proof does not verify against a commitment to a different value.
#[test]
fn range_proof_rejects_wrong_commitment() {
    let (bytes, _) = honest(&[42], 8, 3);
    let proof = range_proof_from_bytes(&bytes).unwrap();
    let other = PedersenGens::default().commit_u64(43, &blinds(3, 1)[0]);
    assert!(verify_range(&[other], &proof, 8).is_err());
}

/// Soundness (sanity): an out-of-range value cannot yield an accepting proof.
#[test]
fn range_proof_out_of_range_never_verifies() {
    let result = std::panic::catch_unwind(|| honest(&[300], 8, 5));
    if let Ok((bytes, vs)) = result {
        // Prover did not refuse: the proof must not verify.
        let ok = range_proof_from_bytes(&bytes)
            .map(|p| verify_range(&vs, &p, 8).is_ok())
            .unwrap_or(false);
        assert!(!ok, "out-of-range value accepted");
    }
}

/// Parameter validation on the verifier.
#[test]
fn range_proof_rejects_bad_parameters() {
    let (bytes, vs) = honest(&[9], 8, 1);
    let proof = range_proof_from_bytes(&bytes).unwrap();
    assert_eq!(verify_range(&vs, &proof, 12), Err(ZkError::InvalidBitsize));
    assert!(range_proof_from_bytes(&bytes[..100]).is_err());
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]

    /// Honest proofs of random in-range values always verify.
    #[test]
    fn range_proof_random_values_verify(v in any::<u32>(), seed in any::<u64>()) {
        let (bytes, vs) = honest(&[v as u64], 32, seed);
        let proof = range_proof_from_bytes(&bytes).unwrap();
        prop_assert_eq!(verify_range(&vs, &proof, 32), Ok(()));
    }

    /// Flipping any single bit of the serialized proof makes verification fail.
    #[test]
    fn range_proof_bitflip_rejected(v in any::<u8>(), seed in any::<u64>(), bit in any::<usize>()) {
        let (mut bytes, vs) = honest(&[v as u64], 8, seed);
        let i = bit % (bytes.len() * 8);
        bytes[i / 8] ^= 1 << (i % 8);
        let ok = range_proof_from_bytes(&bytes)
            .map(|p| verify_range(&vs, &p, 8).is_ok())
            .unwrap_or(false);
        prop_assert!(!ok);
    }
}
