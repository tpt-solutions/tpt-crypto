//! `signature`-crate trait-compat tests: every scheme in `-sig` exercised
//! through `signature::Signer` / `signature::Verifier` /
//! `signature::SignatureEncoding` instead of the native free functions.

use signature::{SignatureEncoding, Signer, Verifier};
use tpt_crypto_sig as sig;

// ── Ed25519 ──────────────────────────────────────────────────────────────────

#[test]
fn ed25519_signer_verifier_round_trip() {
    let sk = sig::ed25519::SigningKey::from_seed([7u8; 32]);
    let vk = sk.verifying_key();
    let msg = b"trait-compat round trip";

    let s = sig::ed25519::SigningKey::try_sign(&sk, msg).expect("try_sign");
    sig::ed25519::VerifyingKey::verify(&vk, msg, &s).expect("verify");

    // Native path and trait path agree byte-for-byte (Ed25519 is
    // deterministic).
    assert_eq!(sk.sign(msg).to_bytes(), s.to_bytes());

    // Wrong message / tampered signature must fail.
    assert!(sig::ed25519::VerifyingKey::verify(&vk, b"other", &s).is_err());
    let mut bad = s.to_bytes();
    bad[0] ^= 1;
    let bad = sig::ed25519::Signature::try_from(&bad[..]).expect("64 bytes");
    assert!(sig::ed25519::VerifyingKey::verify(&vk, msg, &bad).is_err());
}

#[test]
fn ed25519_signature_encoding_round_trip() {
    let sk = sig::ed25519::SigningKey::from_seed([9u8; 32]);
    let s = sig::ed25519::SigningKey::try_sign(&sk, b"encoding").expect("try_sign");

    let bytes = s.to_bytes();
    assert_eq!(bytes.len(), 64);
    let parsed = sig::ed25519::Signature::try_from(&bytes[..]).expect("parse");
    assert_eq!(parsed.to_bytes(), bytes);

    // Wrong length is rejected.
    assert!(sig::ed25519::Signature::try_from(&bytes[..63]).is_err());
    assert!(sig::ed25519::Signature::try_from(&bytes[..]).is_ok());
}

// ── ECDSA P-256 / P-384 ──────────────────────────────────────────────────────

// The fixed-size `Repr` arrays are curve-specific, so the two curves are
// tested individually rather than generically.

#[test]
fn ecdsa_p256_signer_verifier_round_trip() {
    use sig::ecdsa::{Signature, SigningKey, VerifyingKey, P256};
    use signature::hazmat::{PrehashSigner, PrehashVerifier};
    use tpt_crypto_hash::Hasher;

    // A valid scalar in [1, n-1]; any fixed key works (signing is
    // deterministic via RFC 6979).
    let mut key = [0u8; 32];
    key[31] = 0x2A;
    let sk = SigningKey::<P256>::from_bytes(&key).expect("key");
    let vk = sk.verifying_key();
    let msg = b"p256 trait compat";

    let s = SigningKey::<P256>::try_sign(&sk, msg).expect("try_sign");
    VerifyingKey::<P256>::verify(&vk, msg, &s).expect("verify");

    // Deterministic: matches the direct prehash path.
    let mut h = tpt_crypto_hash::sha2::Sha256::new();
    h.update(msg);
    let digest = h.finalize();
    let direct = sk.sign_prehash(&digest).expect("sign_prehash");
    assert_eq!(s.to_bytes(), direct.to_bytes());

    // Hazmat prehash surface maps 1:1.
    let pre = <SigningKey<P256> as PrehashSigner<Signature<P256>>>::sign_prehash(&sk, &digest)
        .expect("sign_prehash");
    <VerifyingKey<P256> as PrehashVerifier<Signature<P256>>>::verify_prehash(&vk, &digest, &pre)
        .expect("verify_prehash");

    // Wrong message fails.
    assert!(VerifyingKey::<P256>::verify(&vk, b"other", &s).is_err());
}

#[test]
fn ecdsa_p256_signature_encoding_round_trip() {
    use sig::ecdsa::{Signature, SigningKey, P256};
    let mut key = [0u8; 32];
    key[31] = 0x11;
    let sk = SigningKey::<P256>::from_bytes(&key).unwrap();
    let s = SigningKey::<P256>::try_sign(&sk, b"encoding").unwrap();

    let bytes = s.to_bytes();
    assert_eq!(bytes.len(), 64);
    let parsed = Signature::<P256>::try_from(&bytes[..]).expect("fixed parse");
    assert_eq!(parsed.to_bytes(), bytes);
    assert!(Signature::<P256>::try_from(&bytes[..63]).is_err());
}

#[test]
fn ecdsa_p384_signer_verifier_round_trip() {
    use sig::ecdsa::{Signature, SigningKey, VerifyingKey, P384};

    let mut key = [0u8; 48];
    key[47] = 0x2B;
    let sk = SigningKey::<P384>::from_bytes(&key).expect("key");
    let vk = sk.verifying_key();
    let msg = b"p384 trait compat";

    let s = SigningKey::<P384>::try_sign(&sk, msg).expect("try_sign");
    VerifyingKey::<P384>::verify(&vk, msg, &s).expect("verify");

    let bytes = s.to_bytes();
    assert_eq!(bytes.len(), 96);
    let parsed = Signature::<P384>::try_from(&bytes[..]).expect("fixed parse");
    assert_eq!(parsed.to_bytes(), bytes);
    assert!(VerifyingKey::<P384>::verify(&vk, b"other", &s).is_err());
}

// ── ML-DSA ───────────────────────────────────────────────────────────────────

macro_rules! ml_dsa_compat_tests {
    ($modname:ident, $set:ty, $sig_len:expr) => {
        mod $modname {
            use signature::{SignatureEncoding, Signer, Verifier};
            use tpt_crypto_sig as sig;

            #[test]
            fn signer_verifier_round_trip() {
                let (pk, sk) = sig::ml_dsa::keygen_from_seed::<$set>(&[0x33u8; 32]);
                let msg = b"ml-dsa trait compat";

                let s = sig::ml_dsa::SecretKey::<$set>::try_sign(&sk, msg).expect("try_sign");
                sig::ml_dsa::PublicKey::<$set>::verify(&pk, msg, &s).expect("verify");

                // Deterministic path: same bytes as the free function with the
                // empty context.
                let direct = sig::ml_dsa::sign::<$set>(&sk, msg, &[]).expect("sign");
                assert_eq!(s.as_bytes(), direct.as_bytes());

                // Wrong message fails; tampered signature fails.
                assert!(sig::ml_dsa::PublicKey::<$set>::verify(&pk, b"other", &s).is_err());
                let mut bad = s.as_bytes().to_vec();
                bad[0] ^= 1;
                let bad = sig::ml_dsa::Signature::<$set>::from_bytes(&bad).expect("len ok");
                assert!(sig::ml_dsa::PublicKey::<$set>::verify(&pk, msg, &bad).is_err());
            }

            #[test]
            fn signature_encoding_round_trip() {
                let (_, sk) = sig::ml_dsa::keygen_from_seed::<$set>(&[0x34u8; 32]);
                let s = sig::ml_dsa::SecretKey::<$set>::try_sign(&sk, b"encoding").expect("sign");

                let bytes = s.to_bytes();
                assert_eq!(bytes.len(), $sig_len);
                let parsed = sig::ml_dsa::Signature::<$set>::try_from(&bytes[..]).expect("parse");
                assert_eq!(parsed.to_bytes(), bytes);
                assert!(sig::ml_dsa::Signature::<$set>::try_from(&bytes[..$sig_len - 1]).is_err());
            }
        }
    };
}

ml_dsa_compat_tests!(ml_dsa44, sig::ml_dsa::MlDsa44, 2420);
ml_dsa_compat_tests!(ml_dsa65, sig::ml_dsa::MlDsa65, 3309);
ml_dsa_compat_tests!(ml_dsa87, sig::ml_dsa::MlDsa87, 4627);

// ── BLS12-381 ────────────────────────────────────────────────────────────────

#[test]
fn bls_signer_verifier_round_trip() {
    let sk = sig::bls::SecretKey::keygen(&[0x5Au8; 32]).expect("keygen");
    let pk = sk.public_key();
    let msg = b"bls trait compat";

    let s = sig::bls::SecretKey::try_sign(&sk, msg).expect("try_sign");
    sig::bls::PublicKey::verify(&pk, msg, &s).expect("verify");

    // Wrong message / tampered signature fail. (Byte 0 carries the compressed
    // point flags and `from_bytes` fully validates the point, so a tampered
    // encoding is typically rejected at parse — also a legitimate rejection.)
    assert!(sig::bls::PublicKey::verify(&pk, b"other", &s).is_err());
    let mut bad = s.to_bytes();
    bad[10] ^= 1;
    let rejected = match sig::bls::Signature::try_from(&bad[..]) {
        Ok(bad) => sig::bls::PublicKey::verify(&pk, msg, &bad).is_err(),
        Err(_) => true,
    };
    assert!(rejected);
}

#[test]
fn bls_signature_encoding_round_trip() {
    let sk = sig::bls::SecretKey::keygen(&[0x5Bu8; 32]).expect("keygen");
    let s = sig::bls::SecretKey::try_sign(&sk, b"encoding").expect("try_sign");

    let bytes = s.to_bytes();
    assert_eq!(bytes.len(), 96);
    let parsed = sig::bls::Signature::try_from(&bytes[..]).expect("parse");
    assert_eq!(parsed.to_bytes(), bytes);
    assert!(sig::bls::Signature::try_from(&bytes[..95]).is_err());
}
