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
}
