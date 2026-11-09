//! One-call recipes with misuse-resistant defaults (feature `os-rng`).
//!
//! The functions here make the safe choice for you:
//!
//! * [`seal`] / [`open`] use **XChaCha20-Poly1305** with a fresh random 192-bit
//!   nonce per message, prepended to the output. The nonce is too long to
//!   collide in practice when drawn at random, so callers never manage nonces.
//! * Randomness comes from the operating system ([`tpt_crypto_core::OsRng`]).
//!   If the OS RNG fails, the call fails; there is no fallback.
//! * Authentication is checked before any plaintext is returned.
//!
//! Hashing and signing recipes:
//!
//! * [`hash`] / [`hmac`] — SHA-256 and HMAC-SHA-256.
//! * [`hkdf_derive`] — HKDF-SHA-256 to a caller-chosen length.
//! * [`ed25519_generate`], [`ed25519_public_key`], [`sign`], [`verify`] —
//!   Ed25519 with a 32-byte seed as the secret key.
//! * [`random_bytes`] — OS-RNG bytes.
//!
//! Wire format of [`seal`]: `nonce (24 B) ‖ ciphertext ‖ tag (16 B)`, so the
//! output is `plaintext.len() + OVERHEAD` bytes.
//!
//! ```
//! use tpt_crypto::easy;
//!
//! let key = easy::generate_key().unwrap();
//! let sealed = easy::seal(key.expose_secret(), b"hello", b"context").unwrap();
//! let opened = easy::open(key.expose_secret(), &sealed, b"context").unwrap();
//! assert_eq!(opened, b"hello");
//! ```

use crate::aead::{Aead, Nonce, XChaCha20Poly1305};
use alloc::vec::Vec;
use tpt_crypto_core::{CryptoRng, Error, OsRng, Result, SecretBox};
use tpt_crypto_hash::{kdf, mac, sha2::Sha256};
use tpt_crypto_sig::ed25519::{self, Signature, SigningKey, VerifyingKey};

/// Key length in bytes (256-bit key).
pub const KEY_LEN: usize = 32;
/// Nonce length in bytes (192-bit XChaCha20 nonce).
pub const NONCE_LEN: usize = 24;
/// Authentication tag length in bytes.
pub const TAG_LEN: usize = 16;
/// Bytes added by [`seal`] on top of the plaintext (nonce + tag).
pub const OVERHEAD: usize = NONCE_LEN + TAG_LEN;

/// Generate a fresh random key from the operating-system RNG.
///
/// The key is returned inside a [`SecretBox`], which zeroes it on drop and
/// does not implement `Debug`, `Display`, or `PartialEq`.
pub fn generate_key() -> Result<SecretBox<[u8; KEY_LEN]>> {
    let mut key = [0u8; KEY_LEN];
    OsRng.try_fill_bytes(&mut key)?;
    Ok(SecretBox::new(key))
}

/// Encrypt and authenticate `plaintext` under `key`, binding `aad`.
///
/// Returns `nonce ‖ ciphertext ‖ tag`. The same `aad` must be supplied to
/// [`open`]; it is authenticated but not encrypted or included in the output.
pub fn seal(key: &[u8; KEY_LEN], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRng.try_fill_bytes(&mut nonce)?;

    let cipher = XChaCha20Poly1305::new(key);
    let mut out = Vec::with_capacity(plaintext.len() + OVERHEAD);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(plaintext);
    let tag = cipher.encrypt_in_place_detached(&Nonce::new(nonce), aad, &mut out[NONCE_LEN..]);
    out.extend_from_slice(&tag.0);
    Ok(out)
}

/// Verify and decrypt a message produced by [`seal`].
///
/// Returns [`Error::InvalidLength`] if `sealed` is shorter than [`OVERHEAD`],
/// and [`Error::Verification`] if the tag, key, or `aad` does not match. No
/// plaintext is returned on failure.
pub fn open(key: &[u8; KEY_LEN], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    if sealed.len() < OVERHEAD {
        return Err(Error::InvalidLength);
    }
    let (nonce_bytes, rest) = sealed.split_at(NONCE_LEN);
    let (ciphertext, tag_bytes) = rest.split_at(rest.len() - TAG_LEN);

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(nonce_bytes);
    let mut tag = [0u8; TAG_LEN];
    tag.copy_from_slice(tag_bytes);

    let cipher = XChaCha20Poly1305::new(key);
    let mut buf = ciphertext.to_vec();
    cipher.decrypt_in_place_detached(
        &Nonce::new(nonce),
        aad,
        &mut buf,
        &crate::aead::Tag::new(tag),
    )?;
    Ok(buf)
}

/// Largest HKDF-SHA-256 output: 255 blocks of 32 bytes (RFC 5869 §2.3).
pub const HKDF_MAX_LEN: usize = 255 * 32;

/// `len` random bytes from the operating-system RNG.
pub fn random_bytes(len: usize) -> Result<Vec<u8>> {
    let mut out = alloc::vec![0u8; len];
    OsRng.try_fill_bytes(&mut out)?;
    Ok(out)
}

/// SHA-256 digest of `data`.
#[must_use]
pub fn hash(data: &[u8]) -> [u8; 32] {
    tpt_crypto_hash::sha2::sha256(data)
}

/// HMAC-SHA-256 tag of `msg` under `key`.
#[must_use]
pub fn hmac(key: &[u8], msg: &[u8]) -> [u8; 32] {
    mac::hmac_sha256(key, msg)
}

/// Derive `len` bytes of keying material with HKDF-SHA-256.
///
/// Returns [`Error::InvalidLength`] if `len` exceeds [`HKDF_MAX_LEN`].
pub fn hkdf_derive(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>> {
    if len > HKDF_MAX_LEN {
        return Err(Error::InvalidLength);
    }
    let mut prk = [0u8; 32];
    kdf::hkdf_extract::<Sha256, 64, 32>(salt, ikm, &mut prk);
    let mut okm = alloc::vec![0u8; len];
    kdf::hkdf_expand::<Sha256, 64, 32>(&prk, info, &mut okm);
    Ok(okm)
}

/// Generate a fresh Ed25519 secret key (a 32-byte seed) from the OS RNG.
pub fn ed25519_generate() -> Result<SecretBox<[u8; ed25519::SEED_LEN]>> {
    let mut seed = [0u8; ed25519::SEED_LEN];
    OsRng.try_fill_bytes(&mut seed)?;
    Ok(SecretBox::new(seed))
}

/// The Ed25519 public key for a secret seed.
#[must_use]
pub fn ed25519_public_key(seed: &[u8; ed25519::SEED_LEN]) -> [u8; ed25519::PUBLIC_KEY_LEN] {
    SigningKey::from_seed(*seed).verifying_key().to_bytes()
}

/// Sign `msg` with an Ed25519 seed. Deterministic (RFC 8032).
#[must_use]
pub fn sign(seed: &[u8; ed25519::SEED_LEN], msg: &[u8]) -> [u8; ed25519::SIGNATURE_LEN] {
    SigningKey::from_seed(*seed).sign(msg).to_bytes()
}

/// Verify an Ed25519 signature over `msg`.
///
/// Returns [`Error::Verification`] (or [`Error::InvalidEncoding`] for a public
/// key that is not a valid point) when the signature does not check out.
pub fn verify(
    public: &[u8; ed25519::PUBLIC_KEY_LEN],
    msg: &[u8],
    sig: &[u8; ed25519::SIGNATURE_LEN],
) -> Result<()> {
    let key = VerifyingKey::from_bytes(public)?;
    key.verify(msg, &Signature::from_bytes(*sig))
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; KEY_LEN] = [0x42; KEY_LEN];

    #[test]
    fn round_trip_including_empty_plaintext() {
        for msg in [&b""[..], b"x", b"hello world", &[0xAAu8; 1000][..]] {
            let sealed = seal(&KEY, msg, b"aad").unwrap();
            assert_eq!(sealed.len(), msg.len() + OVERHEAD);
            assert_eq!(open(&KEY, &sealed, b"aad").unwrap(), msg);
        }
    }

    #[test]
    fn seal_is_randomised() {
        let a = seal(&KEY, b"same", b"").unwrap();
        let b = seal(&KEY, b"same", b"").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn any_single_bit_flip_is_rejected() {
        let sealed = seal(&KEY, b"attack at dawn", b"ctx").unwrap();
        for byte in 0..sealed.len() {
            for bit in 0..8 {
                let mut bad = sealed.clone();
                bad[byte] ^= 1 << bit;
                assert!(open(&KEY, &bad, b"ctx").is_err(), "byte {byte} bit {bit}");
            }
        }
    }

    #[test]
    fn wrong_key_or_aad_is_rejected() {
        let sealed = seal(&KEY, b"msg", b"right").unwrap();
        let other_key = [0x43u8; KEY_LEN];
        assert!(open(&other_key, &sealed, b"right").is_err());
        assert!(open(&KEY, &sealed, b"wrong").is_err());
    }

    #[test]
    fn short_input_is_rejected_as_invalid_length() {
        assert_eq!(
            open(&KEY, &[0u8; OVERHEAD - 1], b"").unwrap_err(),
            Error::InvalidLength
        );
    }

    #[test]
    fn generated_keys_are_distinct() {
        let a = generate_key().unwrap();
        let b = generate_key().unwrap();
        assert_ne!(a.expose_secret(), b.expose_secret());
    }

    #[test]
    fn hash_and_hmac_match_known_vectors() {
        // SHA-256("abc") — FIPS 180-4 example.
        assert_eq!(
            hash(b"abc"),
            [
                0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae,
                0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61,
                0xf2, 0x00, 0x15, 0xad,
            ]
        );
        // RFC 4231 test case 2.
        let tag = hmac(b"Jefe", b"what do ya want for nothing?");
        assert_eq!(tag[..4], [0x5b, 0xdc, 0xc1, 0x46]);
    }

    #[test]
    fn hkdf_derive_length_and_limit() {
        let a = hkdf_derive(b"ikm", b"salt", b"info", 80).unwrap();
        assert_eq!(a.len(), 80);
        assert_eq!(a, hkdf_derive(b"ikm", b"salt", b"info", 80).unwrap());
        assert_ne!(a, hkdf_derive(b"ikm", b"salt", b"other", 80).unwrap());
        assert!(hkdf_derive(b"ikm", b"", b"", HKDF_MAX_LEN).is_ok());
        assert_eq!(
            hkdf_derive(b"ikm", b"", b"", HKDF_MAX_LEN + 1).unwrap_err(),
            Error::InvalidLength
        );
    }

    #[test]
    fn ed25519_sign_verify_round_trip_and_rejection() {
        let seed = ed25519_generate().unwrap();
        let public = ed25519_public_key(seed.expose_secret());
        let sig = sign(seed.expose_secret(), b"message");
        assert!(verify(&public, b"message", &sig).is_ok());
        assert!(verify(&public, b"messagE", &sig).is_err());
        let mut bad = sig;
        bad[0] ^= 1;
        assert!(verify(&public, b"message", &bad).is_err());
    }

    #[test]
    fn random_bytes_has_requested_length() {
        assert_eq!(random_bytes(0).unwrap().len(), 0);
        assert_eq!(random_bytes(57).unwrap().len(), 57);
    }
}
