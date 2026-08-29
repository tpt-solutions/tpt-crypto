use tpt_crypto_curve::{EdwardsPoint, X25519};

/// RFC 8032 §7.1 Test 1.
#[test]
fn ed25519_rfc8032_test1() {
    let secret_key = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        .unwrap();
    let expected_pub = hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        .unwrap();

    // Expand secret key: SHA-512, clamp lower 32 bytes.
    let h = tpt_crypto_hash::sha2::sha512(&secret_key);
    let mut scalar_bytes = [0u8; 32];
    scalar_bytes.copy_from_slice(&h[..32]);
    scalar_bytes[0] &= 248;
    scalar_bytes[31] &= 127;
    scalar_bytes[31] |= 64;

    let bp = EdwardsPoint::basepoint();
    let pub_point = bp.mul(&scalar_bytes);
    let pub_compressed = pub_point.compress();
    assert_eq!(pub_compressed.to_vec(), expected_pub, "public key mismatch");
}

/// RFC 8032 §7.1 Test 1 — full signature and verification.
#[test]
fn ed25519_rfc8032_test1_signature() {
    let seed = hex::decode("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        .unwrap();
    let expected_pub = hex::decode("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        .unwrap();
    let expected_sig = hex::decode(
        "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
    )
    .unwrap();

    let seed: [u8; 32] = seed.try_into().unwrap();
    assert_eq!(EdwardsPoint::public_key(&seed).to_vec(), expected_pub);

    let msg: &[u8] = &[];
    let sig = EdwardsPoint::sign(&seed, msg);
    assert_eq!(sig.to_vec(), expected_sig, "signature mismatch");

    let pub_arr: [u8; 32] = expected_pub.try_into().unwrap();
    assert!(EdwardsPoint::verify(&pub_arr, msg, &sig));
    // Tampered message must fail.
    assert!(!EdwardsPoint::verify(&pub_arr, b"x", &sig));
}

/// Compress/decompress round-trip for the base point.
#[test]
fn ed25519_compress_roundtrip() {
    let bp = EdwardsPoint::basepoint();
    let c = bp.compress();
    let dec = EdwardsPoint::decompress(&c).unwrap();
    assert_eq!(dec.compress(), c);
}

/// RFC 7748 X25519 test vector.
#[test]
fn x25519_rfc7748() {
    let scalar = hex::decode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5e1859cb6e918c0c5e1f")
        .unwrap();
    let u_coord = hex::decode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        .unwrap();
    let expected = hex::decode("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552")
        .unwrap();

    let mut k = [0u8; 32];
    k.copy_from_slice(&scalar);
    let mut u = [0u8; 32];
    u.copy_from_slice(&u_coord);
    let result = X25519::diffie_hellman(&k, &u);
    assert_eq!(result.to_vec(), expected, "X25519 RFC 7748 mismatch");
}

/// RFC 7748 §6.1 — Alice's scalar/base, shared secret.
#[test]
fn x25519_rfc7748_alice() {
    let scalar = hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        .unwrap();
    let base = hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        .unwrap();
    let expected = hex::decode("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742")
        .unwrap();

    let mut k = [0u8; 32];
    k.copy_from_slice(&scalar);
    let mut u = [0u8; 32];
    u.copy_from_slice(&base);
    let result = X25519::diffie_hellman(&k, &u);
    assert_eq!(result.to_vec(), expected, "X25519 RFC 7748 §6.1 mismatch");
}

// Helper for hex decoding without external crate in tests.
mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        let mut out = Vec::with_capacity(s.len() / 2);
        let bytes = s.as_bytes();
        let mut i = 0;
        while i < bytes.len() {
            let hi = hex_val(bytes[i])?;
            let lo = hex_val(bytes[i + 1])?;
            out.push((hi << 4) | lo);
            i += 2;
        }
        Ok(out)
    }
    fn hex_val(b: u8) -> Result<u8, ()> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(()),
        }
    }
}
