//! Ed25519 (RFC 8032) tests: the §7.1 test-1 KAT, tamper rejection,
//! non-canonical-`S` rejection, and batch verification.

use tpt_crypto_sig::ed25519::{verify_batch, BatchEntry, Signature, SigningKey, VerifyingKey};
use tpt_crypto_sig::test_rng::TestRng;

fn arr32(h: &str) -> [u8; 32] {
    let v = hex::decode(h).unwrap();
    v.try_into().unwrap()
}
fn arr64(h: &str) -> [u8; 64] {
    let v = hex::decode(h).unwrap();
    v.try_into().unwrap()
}

#[test]
fn rfc8032_test1_kat() {
    let seed = arr32("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let want_pk = arr32("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a");
    let want_sig = arr64(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555\
         fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    );

    let sk = SigningKey::from_seed(seed);
    let vk = sk.verifying_key();
    assert_eq!(vk.to_bytes(), want_pk);

    let sig = sk.sign(b"");
    assert_eq!(sig.to_bytes(), want_sig);
    vk.verify(b"", &sig).expect("valid signature verifies");
}

#[test]
fn tamper_and_wrong_message_rejected() {
    let sk = SigningKey::from_seed([0x42; 32]);
    let vk = sk.verifying_key();
    let sig = sk.sign(b"hello world");

    vk.verify(b"hello world", &sig).unwrap();
    assert!(vk.verify(b"hello worlD", &sig).is_err());

    let mut bad = sig.to_bytes();
    bad[10] ^= 1;
    assert!(vk
        .verify(b"hello world", &Signature::from_bytes(bad))
        .is_err());

    // Wrong key.
    let other = SigningKey::from_seed([0x43; 32]).verifying_key();
    assert!(other.verify(b"hello world", &sig).is_err());
}

#[test]
fn non_canonical_s_rejected() {
    let sk = SigningKey::from_seed([1; 32]);
    let vk = sk.verifying_key();
    let sig = sk.sign(b"m");
    let mut bytes = sig.to_bytes();
    // Force S to 0xFF.. which is >= L.
    for b in bytes[32..].iter_mut() {
        *b = 0xFF;
    }
    assert!(vk.verify(b"m", &Signature::from_bytes(bytes)).is_err());
}

#[test]
fn batch_verifies_and_catches_a_bad_entry() {
    let mut rng = TestRng::from_seed(&[9; 32]);

    let keys: [SigningKey; 4] = [
        SigningKey::from_seed([1; 32]),
        SigningKey::from_seed([2; 32]),
        SigningKey::from_seed([3; 32]),
        SigningKey::from_seed([4; 32]),
    ];
    let msgs: [&[u8]; 4] = [b"alpha", b"beta", b"gamma", b""];
    let vks: Vec<VerifyingKey> = keys.iter().map(|k| k.verifying_key()).collect();
    let sigs: Vec<Signature> = keys.iter().zip(msgs).map(|(k, m)| k.sign(m)).collect();

    let good: Vec<BatchEntry> = (0..4)
        .map(|i| BatchEntry {
            key: vks[i],
            msg: msgs[i],
            sig: sigs[i],
        })
        .collect();
    verify_batch(&good, &mut rng).expect("all-valid batch verifies");

    // Corrupt one signature.
    let mut b2 = sigs[2].to_bytes();
    b2[3] ^= 0x20;
    let mut bad = good;
    bad[2].sig = Signature::from_bytes(b2);
    assert!(verify_batch(&bad, &mut rng).is_err());

    // Empty batch is vacuously valid.
    verify_batch(&[], &mut rng).unwrap();
}
