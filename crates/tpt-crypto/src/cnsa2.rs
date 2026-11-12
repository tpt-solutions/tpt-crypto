//! CNSA 2.0 approved-only recipes (feature `cnsa2`).
//!
//! Every function here uses only the algorithms on the CNSA 2.0 suite:
//!
//! | Purpose        | Algorithm                  | Function(s)                          |
//! |----------------|----------------------------|--------------------------------------|
//! | Symmetric AEAD | AES-256-GCM                | [`generate_key`], [`seal`], [`open`] |
//! | Hash           | SHA-384, SHA-512           | [`sha384`], [`sha512`]               |
//! | Key establish  | ML-KEM-1024 (FIPS 203)     | [`kem_keygen`], [`kem_encapsulate`], [`kem_decapsulate`] |
//! | Signature      | ML-DSA-87 (FIPS 204)       | [`sign_keygen`], [`sign`], [`verify`] |
//!
//! Nothing here uses Ed25519, X25519, ChaCha20, P-256, or SHA-256. The classical
//! primitives stay available elsewhere in the crate for other uses.
//!
//! # What this is not
//!
//! * **Not a certification or compliance claim.** Using these recipes does not
//!   make a system CNSA 2.0 compliant. The approved set is set by NSA guidance,
//!   and the overall system has to meet it.
//! * **Not a runtime policy.** Nothing elsewhere in the crate is disabled by this
//!   feature, so `--all-features` builds are unaffected. Code that calls the
//!   other primitives directly is not checked.
//! * **LMS and XMSS are approved but not implemented here.** [`APPROVED`] lists them
//!   so the allow-list is complete. The workspace's SLH-DSA is *not* approved
//!   under CNSA 2.0 and is not used by these recipes.
//! * **SHA-3 is left out.** The guidance sources disagree on whether SHA-3 is
//!   approved as a general hash. It is not used here until that is resolved
//!   against the NSA FAQ.

use crate::aead::{Aead, Aes256Gcm, Nonce};
use crate::kem::ml_kem::{self, Ciphertext, DecapsKey, EncapsKey, SharedSecret};
use crate::kem::params::MlKem1024;
use crate::ml_dsa::{MlDsa87, PublicKey, SecretKey, Signature};
use alloc::vec::Vec;
use tpt_crypto_core::{CryptoRng, Error, OsRng, Result, SecretBox};
use tpt_crypto_hash::sha2;

/// AES-256 key length in bytes.
pub const KEY_LEN: usize = 32;
/// GCM nonce length in bytes (SP 800-38D default).
pub const NONCE_LEN: usize = 12;
/// GCM tag length in bytes.
pub const TAG_LEN: usize = 16;
/// Bytes added by [`seal`] on top of the plaintext (nonce + tag).
pub const OVERHEAD: usize = NONCE_LEN + TAG_LEN;

/// The CNSA 2.0 suite as this crate names it. `IMPLEMENTED` is the subset that
/// has recipes here; `LMS` and `XMSS` are approved but not implemented.
pub const APPROVED: &[&str] = &[
    "AES-256-GCM",
    "SHA-384",
    "SHA-512",
    "ML-KEM-1024",
    "ML-DSA-87",
    "LMS",
    "XMSS",
];

/// The subset of [`APPROVED`] that has recipes in this module.
pub const IMPLEMENTED: &[&str] = &[
    "AES-256-GCM",
    "SHA-384",
    "SHA-512",
    "ML-KEM-1024",
    "ML-DSA-87",
];

/// A fresh random AES-256 key from the OS RNG.
pub fn generate_key() -> Result<SecretBox<[u8; KEY_LEN]>> {
    let mut key = [0u8; KEY_LEN];
    OsRng.try_fill_bytes(&mut key)?;
    Ok(SecretBox::new(key))
}

/// Encrypt and authenticate `plaintext` with AES-256-GCM under `key`, binding `aad`.
/// A fresh random 96-bit nonce is generated per call. Returns `nonce ‖ ciphertext ‖ tag`.
pub fn seal(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.try_fill_bytes(&mut nonce)?;
    let cipher = Aes256Gcm::new(key)?;
    let body = cipher.encrypt(&Nonce(nonce), aad, plaintext);
    let mut out = Vec::with_capacity(NONCE_LEN + body.len());
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&body);
    Ok(out)
}

/// Decrypt a value produced by [`seal`]. Returns [`Error::Verification`] if the tag
/// does not verify, and [`Error::InvalidLength`] if the input is too short.
pub fn open(key: &[u8; KEY_LEN], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < OVERHEAD {
        return Err(Error::InvalidLength);
    }
    let (nonce, body) = sealed.split_at(NONCE_LEN);
    let mut n = [0u8; NONCE_LEN];
    n.copy_from_slice(nonce);
    let cipher = Aes256Gcm::new(key)?;
    cipher.decrypt(&Nonce(n), aad, body)
}

/// SHA-384 digest.
#[must_use]
pub fn sha384(data: &[u8]) -> [u8; 48] {
    sha2::sha384(data)
}

/// SHA-512 digest.
#[must_use]
pub fn sha512(data: &[u8]) -> [u8; 64] {
    sha2::sha512(data)
}

/// ML-KEM-1024 key pair from the OS RNG.
pub fn kem_keygen() -> (EncapsKey, DecapsKey) {
    ml_kem::keygen::<MlKem1024>(&mut OsRng)
}

/// Encapsulate to an ML-KEM-1024 public key. Returns the shared secret and ciphertext.
pub fn kem_encapsulate(pk: &EncapsKey) -> Result<(SharedSecret, Ciphertext)> {
    ml_kem::encapsulate::<MlKem1024>(pk, &mut OsRng)
}

/// Decapsulate an ML-KEM-1024 ciphertext (implicit rejection, per FIPS 203).
pub fn kem_decapsulate(sk: &DecapsKey, ct: &[u8]) -> Result<SharedSecret> {
    ml_kem::decapsulate::<MlKem1024>(sk, ct)
}

/// ML-DSA-87 key pair from the OS RNG.
pub fn sign_keygen() -> (PublicKey<MlDsa87>, SecretKey<MlDsa87>) {
    crate::ml_dsa::keygen::<MlDsa87, _>(&mut OsRng)
}

/// ML-DSA-87 signature over `msg`, with the empty context string.
pub fn sign(sk: &SecretKey<MlDsa87>, msg: &[u8]) -> Result<Signature<MlDsa87>> {
    crate::ml_dsa::sign::<MlDsa87>(sk, msg, &[]).map_err(sig_error)
}

/// Verify an ML-DSA-87 signature over `msg`, with the empty context string.
pub fn verify(pk: &PublicKey<MlDsa87>, msg: &[u8], sig: &Signature<MlDsa87>) -> Result<()> {
    crate::ml_dsa::verify::<MlDsa87>(pk, msg, sig, &[]).map_err(sig_error)
}

/// Map an ML-DSA error onto the crate's core error type. Variants with the same
/// meaning pass through; anything else is reported as an encoding error.
fn sig_error(e: tpt_crypto_sig::Error) -> Error {
    use tpt_crypto_sig::Error as S;
    match e {
        S::Verification => Error::Verification,
        S::InvalidLength => Error::InvalidLength,
        S::RngFailure => Error::RngFailure,
        _ => Error::InvalidEncoding,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_round_trip_and_rejection() {
        let key = [0x42u8; KEY_LEN];
        let sealed = seal(&key, b"attack at dawn", b"hdr").unwrap();
        assert_eq!(sealed.len(), b"attack at dawn".len() + OVERHEAD);
        assert_eq!(open(&key, &sealed, b"hdr").unwrap(), b"attack at dawn");
        assert!(open(&key, &sealed, b"other").is_err());
        let mut bad = sealed.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(open(&key, &bad, b"hdr").is_err());
        assert!(open(&key, &sealed[..OVERHEAD - 1], b"hdr").is_err());
    }

    #[test]
    fn sha384_and_sha512_of_abc() {
        // FIPS 180-4 example vectors.
        assert_eq!(sha384(b"abc")[..4], [0xcb, 0x00, 0x75, 0x3f],);
        assert_eq!(sha512(b"abc")[..4], [0xdd, 0xaf, 0x35, 0xa1]);
    }

    #[test]
    fn kem_round_trip() {
        let (pk, sk) = kem_keygen();
        let (ss, ct) = kem_encapsulate(&pk).unwrap();
        assert_eq!(kem_decapsulate(&sk, ct.as_bytes()).unwrap(), ss);
    }

    #[test]
    fn sign_round_trip_and_tamper() {
        let (pk, sk) = sign_keygen();
        let sig = sign(&sk, b"message").unwrap();
        verify(&pk, b"message", &sig).unwrap();
        assert!(verify(&pk, b"messagE", &sig).is_err());
    }

    #[test]
    fn approved_list_covers_implemented() {
        for name in IMPLEMENTED {
            assert!(APPROVED.contains(name), "{name} not in APPROVED");
        }
        assert!(!IMPLEMENTED.contains(&"LMS"));
    }
}
