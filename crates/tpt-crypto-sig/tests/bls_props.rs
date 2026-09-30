//! Randomized properties for the BLS12-381 signature scheme
//! (discharges `specs/bls_aggregate.telos`: the aggregate verifies iff every
//! contribution is valid, plus honest sign→verify round-trips).

use tpt_crypto_sig::bls::{
    aggregate, aggregate_verify, proof_of_possession, sign, verify, verify_aggregate,
    verify_proof_of_possession, Ciphersuite, PublicKey, SecretKey, Signature, PK_LEN,
};

/// Deterministic 32-byte test scalar from a counter (nonzero).
fn sk_from(i: u8) -> SecretKey {
    let mut b = [0u8; 32];
    b[31] = i;
    SecretKey::from_bytes(&b).expect("nonzero scalar")
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| (self.next() & 0xff) as u8).collect()
    }
}

#[test]
fn honest_round_trip_and_aggregate_iff_all_valid() {
    let mut rng = Rng(0x5eed_1234_abcd_0042);
    for case in 0..8u8 {
        // Distinct signers, distinct messages.
        let n = 1 + (case % 4) as usize;
        let sks: Vec<SecretKey> = (0..n).map(|i| sk_from(case * 8 + i as u8 + 1)).collect();
        let msgs: Vec<Vec<u8>> = (0..n).map(|_| rng.bytes(48)).collect();
        let pks: Vec<PublicKey> = sks.iter().map(|sk| sk.public_key()).collect();

        // Individual honest round trip.
        let sigs: Vec<Signature> = sks
            .iter()
            .zip(msgs.iter())
            .map(|(sk, m)| {
                let sig = sign(sk, m);
                assert!(verify(&sk.public_key(), m, &sig).is_ok(), "honest verify");
                sig
            })
            .collect();

        // Aggregate over distinct messages: valid iff every contribution is.
        let agg = aggregate(&sigs).expect("nonempty aggregate");
        let refs: Vec<&[u8]> = msgs.iter().map(|m| m.as_slice()).collect();
        assert!(
            aggregate_verify(&pks, &refs, &agg).is_ok(),
            "honest distinct-message aggregate must verify"
        );

        // Tamper with exactly one contribution: the aggregate must reject.
        for bad in 0..n {
            let mut bad_sigs = sigs.clone();
            let mut bytes = bad_sigs[bad].to_bytes();
            bytes[7] ^= 0x40;
            if let Ok(bad_sig) = Signature::from_bytes(&bytes) {
                bad_sigs[bad] = bad_sig;
                let agg_bad = aggregate(&bad_sigs).unwrap();
                assert!(
                    aggregate_verify(&pks, &refs, &agg_bad).is_err(),
                    "aggregate with tampered contribution {bad} must reject"
                );
            }
        }

        // Same-message aggregation: all signers sign one message.
        let m0 = &msgs[0];
        let same: Vec<Signature> = sks.iter().map(|sk| sign(sk, m0)).collect();
        let agg_same = aggregate(&same).unwrap();
        assert!(verify_aggregate(&pks, m0, &agg_same).is_ok());
        let wrong = rng.bytes(32);
        assert!(verify_aggregate(&pks, &wrong, &agg_same).is_err());

        // Wrong key on an individual signature.
        let other = sk_from(200);
        assert!(verify(&other.public_key(), &msgs[0], &sigs[0]).is_err());
    }
}

#[test]
fn keys_and_pop() {
    let mut rng = Rng(0xdead_beef_cafe_0001);
    for _ in 0..4 {
        let ikm = rng.bytes(64);
        let sk = SecretKey::keygen(&ikm).expect("keygen");
        let pk = sk.public_key();
        // pk round-trips through the compressed serialization.
        let bytes = pk.to_bytes();
        assert_eq!(bytes.len(), PK_LEN);
        let pk2 = PublicKey::from_bytes(&bytes).expect("reparse");
        assert_eq!(pk2.to_bytes(), bytes);
        // PoP verifies for the right key and fails for another.
        let pop = proof_of_possession(&sk);
        assert!(verify_proof_of_possession(&pk, &pop).is_ok());
        let other = sk_from(199);
        assert!(verify_proof_of_possession(&other.public_key(), &pop).is_err());
    }
    // Deterministic KeyGen, and IKM below 32 bytes is rejected.
    let a = SecretKey::keygen(&[7u8; 32]).unwrap();
    let b = SecretKey::keygen(&[7u8; 32]).unwrap();
    assert_eq!(a.to_bytes(), b.to_bytes());
    assert!(SecretKey::keygen(&[7u8; 16]).is_err());
    // Zero secret key rejected.
    assert!(SecretKey::from_bytes(&[0u8; 32]).is_err());
}

#[test]
fn augmentation_scheme_allows_duplicate_messages() {
    // The Aug ciphersuite binds pk into the hash, so the same message can be
    // signed by multiple signers and the aggregate still verifies.
    let sks: Vec<SecretKey> = (1..=3).map(sk_from).collect();
    let pks: Vec<PublicKey> = sks.iter().map(|sk| sk.public_key()).collect();
    let msg = b"duplicate message is fine under AUG";
    let sigs: Vec<Signature> = sks
        .iter()
        .map(|sk| tpt_crypto_sig::bls::sign_with(sk, msg, Ciphersuite::Aug))
        .collect();
    let agg = aggregate(&sigs).unwrap();
    let refs: Vec<&[u8]> = (0..3).map(|_| msg.as_slice()).collect();
    assert!(
        tpt_crypto_sig::bls::aggregate_verify_with(&pks, &refs, &agg, Ciphersuite::Aug).is_ok()
    );
    // …while the Basic/Pop schemes reject duplicate messages up front.
    assert!(aggregate_verify(&pks, &refs, &agg).is_err());
}
