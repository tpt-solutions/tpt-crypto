//! End-to-end usage samples for the `tpt-crypto` substrate.
//!
//! These are compiled and tested as part of the workspace so the documented
//! patterns never rot. Each module mirrors a snippet from `spec.txt` §4 where the
//! relevant primitive has landed; for now it exercises `tpt-crypto-core`.

/// Hold a key in a `SecretBox`, compare secrets in constant time, and wipe on
/// drop. Mirrors the `spec.txt` §4 "Constant-time secret handling" snippet.
///
/// ```
/// use tpt_crypto_core::secret::SecretBox;
/// use tpt_crypto_core::{ct_eq, ct_select, Choice};
/// use tpt_crypto_core::zeroize::Zeroizing;
///
/// // A key we want to keep out of logs and equality checks.
/// let key = SecretBox::new([0x42u8; 32]);
///
/// // Reading the secret is an explicit, greppable action.
/// assert_eq!(key.expose_secret(), &[0x42u8; 32]);
///
/// // Comparing secrets must go through the constant-time primitives — never `==`.
/// let other = SecretBox::new([0x42u8; 32]);
/// assert!(ct_eq(key.expose_secret().as_slice(), other.expose_secret().as_slice()).is_true());
///
/// // Constant-time selection: `picked` is `a` when `cond` is set, else `b`.
/// let a = 1u64;
/// let b = 2u64;
/// let cond = Choice::from_bool(true);
/// let picked = ct_select(&a, &b, cond);
/// assert_eq!(picked, a);
///
/// // Move a secret out with a guaranteed wipe on scope exit.
/// let owned: Zeroizing<[u8; 32]> = Zeroizing::new(*key.expose_secret());
/// assert_eq!(*owned, [0x42u8; 32]);
/// ```
pub fn secret_handling_snippet() {}

/// Post-quantum KEM round-trip through the `tpt-crypto` facade. Mirrors the
/// `spec.txt` §4 "Post-quantum KEM (ML-KEM / Kyber)" snippet.
///
/// ```
/// use tpt_crypto::ml_kem::{decapsulate, encapsulate, keygen, MlKem768};
/// use tpt_crypto::sig::test_rng::TestRng;
///
/// let mut rng = TestRng::from_seed(&[0x11; 32]);
///
/// let (pk, sk) = keygen::<MlKem768>(&mut rng);
/// let (shared_secret, ciphertext) = encapsulate::<MlKem768>(&pk, &mut rng);
/// let recovered = decapsulate::<MlKem768>(&sk, &ciphertext.bytes)
///     .expect("valid ciphertext decapsulates");
///
/// assert_eq!(shared_secret, recovered);
/// ```
pub fn ml_kem_snippet() {}

/// Post-quantum signature round-trip through the `tpt-crypto` facade. Mirrors
/// the `spec.txt` §4 "Post-quantum signatures (ML-DSA / Dilithium)" snippet.
///
/// ```
/// use tpt_crypto::ml_dsa::{keygen, sign, verify, MlDsa65};
/// use tpt_crypto::sig::test_rng::TestRng;
///
/// let mut rng = TestRng::from_seed(&[0x22; 32]);
///
/// let (pk, sk) = keygen::<MlDsa65, _>(&mut rng);
/// let message = b"transfer 10 to alice";
/// let ctx = b"tpt-crypto-example-v1";
///
/// let signature = sign::<MlDsa65>(&sk, message, ctx).expect("sign");
/// assert!(verify::<MlDsa65>(&pk, message, &signature, ctx).is_ok());
///
/// // A different message, or a different context, must not verify.
/// assert!(verify::<MlDsa65>(&pk, b"transfer 10 to eve", &signature, ctx).is_err());
/// assert!(verify::<MlDsa65>(&pk, message, &signature, b"other-ctx").is_err());
/// ```
pub fn ml_dsa_snippet() {}

/// A "ring subset" of what a TLS library (`ring`) provides — SHA-256, P-256
/// ECDSA, and AES-128-GCM — stitched together end to end through the facade.
///
/// The flow: hash a message with SHA-256 → sign+verify the digest with ECDSA
/// (RFC 6979 deterministic, no RNG) → derive an AES-128-GCM key from the
/// digest → seal/open a payload with authenticated encryption.
///
/// ```
/// use tpt_crypto::aead::{Aead, Aes128Gcm, Nonce};
/// use tpt_crypto::hash::sha2::sha256;
/// use tpt_crypto::prelude::{CryptoRng, SecretBox};
/// use tpt_crypto::sig::ecdsa::{SigningKey, P256};
/// use tpt_crypto::sig::test_rng::TestRng;
///
/// let mut rng = TestRng::from_seed(&[0x5e; 32]);
///
/// // 1) SHA-256 over the message.
/// let msg = b"ring subset demo payload";
/// let digest = sha256(msg);
///
/// // 2) P-256 ECDSA: sign the digest, then verify. RFC 6979 makes signing
/// //    deterministic, so no RNG is needed here. The key scalar is held in a
/// //    SecretBox (wiped on drop); `SigningKey` self-wipes its internal copy.
/// let secret = SecretBox::new(rng.gen_array::<32>());
/// let sk = SigningKey::<P256>::from_bytes(secret.expose_secret())
///     .expect("random scalar is in [1, n-1]");
/// let vk = sk.verifying_key();
/// let sig = sk.sign_prehash(&digest).expect("sign");
/// vk.verify_prehash(&digest, &sig).expect("verify");
///
/// // A tampered message must not verify.
/// let bad = sha256(b"tampered payload");
/// assert!(vk.verify_prehash(&bad, &sig).is_err());
///
/// // 3) AES-128-GCM keyed from half the digest, with a random nonce + AAD.
/// let key: [u8; 16] = digest[..16].try_into().unwrap();
/// let cipher = Aes128Gcm::new(&key).expect("16-byte key");
/// let nonce = Nonce::<12>::new(rng.gen_array::<12>());
/// let aad = b"tpt-crypto-ring-subset";
///
/// let ct = cipher.encrypt(&nonce, aad, b"secret plaintext");
/// let pt = cipher.decrypt(&nonce, aad, &ct).expect("authentication");
/// assert_eq!(pt, b"secret plaintext");
///
/// // A tampered ciphertext (one flipped byte) must be rejected.
/// let mut bad = ct.clone();
/// bad[0] ^= 0x01;
/// assert!(cipher.decrypt(&nonce, aad, &bad).is_err());
/// ```
pub fn ring_subset_snippet() {}

#[cfg(test)]
mod tests {
    use tpt_crypto_core::ct_eq;
    use tpt_crypto_core::secret::SecretBox;

    #[test]
    fn secret_box_is_not_observable_by_accident() {
        let key = SecretBox::new([7u8; 16]);
        // The only read path is explicit:
        assert!(ct_eq(key.expose_secret().as_slice(), &[7u8; 16]).is_true());
    }

    #[test]
    fn ml_kem_facade_round_trip() {
        use tpt_crypto::ml_kem::{decapsulate, encapsulate, keygen, MlKem512};
        use tpt_crypto::sig::test_rng::TestRng;

        let mut rng = TestRng::from_seed(&[0x33; 32]);
        let (pk, sk) = keygen::<MlKem512>(&mut rng);
        let (ss1, ct) = encapsulate::<MlKem512>(&pk, &mut rng);
        let ss2 = decapsulate::<MlKem512>(&sk, &ct.bytes).expect("decapsulate");
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn ml_dsa_facade_round_trip() {
        use tpt_crypto::ml_dsa::{keygen, sign, verify, MlDsa44};
        use tpt_crypto::sig::test_rng::TestRng;

        let mut rng = TestRng::from_seed(&[0x44; 32]);
        let (pk, sk) = keygen::<MlDsa44, _>(&mut rng);
        let msg = b"facade example";
        let sig = sign::<MlDsa44>(&sk, msg, &[]).expect("sign");
        assert!(verify::<MlDsa44>(&pk, msg, &sig, &[]).is_ok());
        assert!(verify::<MlDsa44>(&pk, b"tampered", &sig, &[]).is_err());
    }

    #[test]
    fn ring_subset_facade_round_trip() {
        use tpt_crypto::aead::{Aead, Aes128Gcm, Nonce};
        use tpt_crypto::hash::sha2::sha256;
        use tpt_crypto::prelude::{CryptoRng, SecretBox};
        use tpt_crypto::sig::ecdsa::{SigningKey, P256};
        use tpt_crypto::sig::test_rng::TestRng;

        let mut rng = TestRng::from_seed(&[0x6e; 32]);
        let msg = b"ring subset facade test";
        let digest = sha256(msg);

        let secret = SecretBox::new(rng.gen_array::<32>());
        let sk = SigningKey::<P256>::from_bytes(secret.expose_secret()).unwrap();
        let vk = sk.verifying_key();
        let sig = sk.sign_prehash(&digest).unwrap();
        vk.verify_prehash(&digest, &sig).unwrap();

        let key: [u8; 16] = digest[..16].try_into().unwrap();
        let cipher = Aes128Gcm::new(&key).unwrap();
        let nonce = Nonce::<12>::new(rng.gen_array::<12>());
        let ct = cipher.encrypt(&nonce, b"aad", b"payload");
        let pt = cipher.decrypt(&nonce, b"aad", &ct).unwrap();
        assert_eq!(pt, b"payload");
    }
}
