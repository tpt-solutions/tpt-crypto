//! ECDSA tests: RFC 6979 deterministic-`r` KATs (P-256/SHA-256, P-384/SHA-384),
//! sign/verify round-trips, tamper rejection, low-`S` policy, and encoding
//! round-trips.

use tpt_crypto_hash::sha2::{Sha256, Sha384};
use tpt_crypto_hash::Hasher;
use tpt_crypto_sig::ecdsa::{Signature, SigningKey, VerifyingKey, P256, P384};

fn hx(s: &str) -> Vec<u8> {
    hex::decode(s.replace([' ', '\n'], "")).unwrap()
}
fn sha256(m: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(m);
    h.finalize()
}
fn sha384(m: &[u8]) -> [u8; 48] {
    let mut h = Sha384::new();
    h.update(m);
    h.finalize()
}

// RFC 6979 Appendix A.2.5 — P-256, SHA-256.
const P256_X: &str = "C9AFA9D845BA75166B5C215767B1D6934E50C3DB36E89B127B8A622B120F6721";
const P256_UX: &str = "60FED4BA255A9D31C961EB74C6356D68C049B8923B61FA6CE669622E60F29FB6";
const P256_UY: &str = "7903FE1008B8BC99A41AE9E95628BC64F2F1B20C2D7E9F5177A3C294D4462299";

#[test]
fn rfc6979_p256_sha256_r_kats() {
    let sk = SigningKey::<P256>::from_bytes(&hx(P256_X)).unwrap();

    // Public key matches the RFC.
    let sec1 = sk.verifying_key().to_sec1_uncompressed();
    assert_eq!(&sec1[1..33], hx(P256_UX).as_slice());
    assert_eq!(&sec1[33..65], hx(P256_UY).as_slice());

    // message "sample": r = EFD48B2A...
    let sig = sk.sign_prehash(&sha256(b"sample")).unwrap();
    assert_eq!(
        &sig.r_bytes()[..32],
        hx("EFD48B2AACB6A8FD1140DD9CD45E81D69D2C877B56AAF991C34D0EA84EAF3716").as_slice()
    );
    sk.verifying_key()
        .verify_prehash(&sha256(b"sample"), &sig)
        .unwrap();

    // message "test": r = F1ABB023...
    let sig = sk.sign_prehash(&sha256(b"test")).unwrap();
    assert_eq!(
        &sig.r_bytes()[..32],
        hx("F1ABB023518351CD71D881567B1EA663ED3EFCF6C5132B354F28D3B0B7D38367").as_slice()
    );
    sk.verifying_key()
        .verify_prehash(&sha256(b"test"), &sig)
        .unwrap();
}

#[test]
fn rfc6979_p256_is_deterministic() {
    let sk = SigningKey::<P256>::from_bytes(&hx(P256_X)).unwrap();
    let a = sk.sign_prehash(&sha256(b"sample")).unwrap();
    let b = sk.sign_prehash(&sha256(b"sample")).unwrap();
    assert_eq!(a.to_der(), b.to_der());
}

// RFC 6979 Appendix A.2.6 — P-384, SHA-384.
const P384_X: &str =
    "6B9D3DAD2E1B8C1C05B19875B6659F4DE23C3B667BF297BA9AA47740787137D896D5724E4C70A825F872C9EA60D2EDF5";

#[test]
fn rfc6979_p384_sha384_r_kat() {
    let sk = SigningKey::<P384>::from_bytes(&hx(P384_X)).unwrap();
    // message "sample": r = 94EDBB92...
    let sig = sk.sign_prehash(&sha384(b"sample")).unwrap();
    assert_eq!(
        &sig.r_bytes()[..48],
        hx(
            "94EDBB92A5ECB8AAD4736E56C691916B3F88140666CE9FA73D64C4EA95AD133C8\
            1A648152E44ACF96E36DD1E80FABE46"
        )
        .as_slice()
    );
    sk.verifying_key()
        .verify_prehash(&sha384(b"sample"), &sig)
        .unwrap();
}

#[test]
fn round_trip_and_tamper() {
    let sk = SigningKey::<P256>::from_bytes(&hx(P256_X)).unwrap();
    let vk = sk.verifying_key();
    let d = sha256(b"a real message");
    let sig = sk.sign_prehash(&d).unwrap();

    vk.verify_prehash(&d, &sig).unwrap();
    // wrong digest
    assert!(vk
        .verify_prehash(&sha256(b"another message"), &sig)
        .is_err());
    // wrong key
    let other = SigningKey::<P256>::from_bytes(&hx(
        "0000000000000000000000000000000000000000000000000000000000000002",
    ))
    .unwrap();
    assert!(other.verifying_key().verify_prehash(&d, &sig).is_err());
}

#[test]
fn signatures_are_low_s() {
    // Sign many messages; every `s` must be canonical (verify enforces it).
    let sk = SigningKey::<P256>::from_bytes(&hx(P256_X)).unwrap();
    let vk = sk.verifying_key();
    for i in 0..32u8 {
        let d = sha256(&[i; 7]);
        let sig = sk.sign_prehash(&d).unwrap();
        vk.verify_prehash(&d, &sig).expect("low-s verifies");
    }
}

#[test]
fn encoding_round_trips() {
    let sk = SigningKey::<P256>::from_bytes(&hx(P256_X)).unwrap();
    let d = sha256(b"encode me");
    let sig = sk.sign_prehash(&d).unwrap();

    let der = sig.to_der();
    let back = Signature::<P256>::from_der(&der).unwrap();
    assert_eq!(back.to_der(), der);

    let fixed = sig.to_fixed();
    assert_eq!(fixed.len(), 64);
    let back = Signature::<P256>::from_fixed(&fixed).unwrap();
    assert_eq!(back.to_fixed(), fixed);

    // Truncated / garbage DER is rejected, not panicked.
    assert!(Signature::<P256>::from_der(&der[..der.len() - 1]).is_err());
    assert!(Signature::<P256>::from_der(b"\x30\x00").is_err());
}

#[test]
fn public_key_sec1_round_trip() {
    let sk = SigningKey::<P384>::from_bytes(&hx(P384_X)).unwrap();
    let vk = sk.verifying_key();
    let enc = vk.to_sec1_uncompressed();
    let back = VerifyingKey::<P384>::from_sec1(&enc).unwrap();
    assert_eq!(back.to_sec1_uncompressed(), enc);
}
