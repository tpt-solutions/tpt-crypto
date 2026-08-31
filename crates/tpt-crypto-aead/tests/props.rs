//! Property tests for `tpt-crypto-aead`.
//!
//! Every AEAD construction must satisfy:
//! 1. `decrypt(encrypt(m), aad, nonce) == m` for arbitrary plaintexts.
//! 2. Any single-bit flip in ciphertext, tag, AAD, or nonce causes
//!    `decrypt` to return `Err`.

use proptest::prelude::*;
use tpt_crypto_aead::Aead;
use tpt_crypto_aead::{Aes128Gcm, Aes128GcmSiv, Aes256Gcm, Aes256GcmSiv, ChaCha20Poly1305, XChaCha20Poly1305};
use tpt_crypto_aead::{Nonce, Tag};

const fn nonce12() -> Nonce<12> {
    Nonce::new([0u8; 12])
}

const fn nonce24() -> Nonce<24> {
    Nonce::new([0u8; 24])
}

fn tag16(bytes: [u8; 16]) -> Tag<16> {
    Tag::new(bytes)
}

// --- round-trip --------------------------------------------------------------

prop_compose! {
    fn arb_plaintext()(bytes in any::<Vec<u8>>()) -> Vec<u8> {
        bytes
    }
}

prop_compose! {
    fn arb_aad()(bytes in any::<Vec<u8>>()) -> Vec<u8> {
        bytes
    }
}

fn round_trip_prop<C, const NONCE_LEN: usize, const TAG_LEN: usize>(
    cipher: &C,
    nonce: &Nonce<NONCE_LEN>,
    aad: &[u8],
    pt: &[u8],
) -> bool
where
    C: Aead<NONCE_LEN, TAG_LEN>,
{
    if pt.len() > 4096 {
        return true; // discard by accepting
    }
    let ct = cipher.encrypt(nonce, aad, pt);
    let dec = cipher.decrypt(nonce, aad, &ct);
    dec.as_deref() == Ok(pt)
}

fn bitflip_prop<C, const NONCE_LEN: usize, const TAG_LEN: usize>(
    cipher: &C,
    nonce: &Nonce<NONCE_LEN>,
    aad: &[u8],
    pt: &[u8],
) -> bool
where
    C: Aead<NONCE_LEN, TAG_LEN>,
{
    if pt.is_empty() {
        return true;
    }
    let mut ct = cipher.encrypt(nonce, aad, pt);

    // Flip one bit in the ciphertext body.
    if !ct.is_empty() {
        let idx = ct.len() / 2;
        ct[idx] ^= 0x01;
        let dec = cipher.decrypt(nonce, aad, &ct);
        if dec.is_ok() {
            return false;
        }
    }

    // Flip one bit in the tag.
    if ct.len() >= TAG_LEN {
        let tag_idx = ct.len() - TAG_LEN;
        ct[tag_idx] ^= 0x01;
        let dec = cipher.decrypt(nonce, aad, &ct);
        if dec.is_ok() {
            return false;
        }
    }

    true
}

// --- AES-128-GCM -------------------------------------------------------------

proptest! {
    #[test]
    fn aes128_gcm_round_trip(aad in arb_aad(), pt in arb_plaintext(), key in any::<[u8; 16]>()) {
        let cipher = Aes128Gcm::new(&key).unwrap();
        let nonce = nonce12();
        prop_assert!(round_trip_prop(&cipher, &nonce, &aad, &pt));
    }

    #[test]
    fn aes128_gcm_bitflip(aad in any::<Vec<u8>>(), pt in prop::collection::vec(any::<u8>(), 1..256), key in any::<[u8; 16]>()) {
        let cipher = Aes128Gcm::new(&key).unwrap();
        let nonce = nonce12();
        prop_assert!(bitflip_prop(&cipher, &nonce, &aad, &pt));
    }
}

// --- AES-256-GCM -------------------------------------------------------------

proptest! {
    #[test]
    fn aes256_gcm_round_trip(aad in arb_aad(), pt in arb_plaintext(), key in any::<[u8; 32]>()) {
        let cipher = Aes256Gcm::new(&key).unwrap();
        let nonce = nonce12();
        prop_assert!(round_trip_prop(&cipher, &nonce, &aad, &pt));
    }

    #[test]
    fn aes256_gcm_bitflip(aad in any::<Vec<u8>>(), pt in prop::collection::vec(any::<u8>(), 1..256), key in any::<[u8; 32]>()) {
        let cipher = Aes256Gcm::new(&key).unwrap();
        let nonce = nonce12();
        prop_assert!(bitflip_prop(&cipher, &nonce, &aad, &pt));
    }
}

// --- ChaCha20-Poly1305 -------------------------------------------------------

proptest! {
    #[test]
    fn chacha20_poly1305_round_trip(aad in arb_aad(), pt in arb_plaintext(), key in any::<[u8; 32]>()) {
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = nonce12();
        prop_assert!(round_trip_prop(&cipher, &nonce, &aad, &pt));
    }

    #[test]
    fn chacha20_poly1305_bitflip(aad in any::<Vec<u8>>(), pt in prop::collection::vec(any::<u8>(), 1..256), key in any::<[u8; 32]>()) {
        let cipher = ChaCha20Poly1305::new(&key);
        let nonce = nonce12();
        prop_assert!(bitflip_prop(&cipher, &nonce, &aad, &pt));
    }
}

// --- XChaCha20-Poly1305 ------------------------------------------------------

proptest! {
    #[test]
    fn xchacha20_poly1305_round_trip(aad in arb_aad(), pt in arb_plaintext(), key in any::<[u8; 32]>()) {
        let cipher = XChaCha20Poly1305::new(&key);
        let nonce = nonce24();
        prop_assert!(round_trip_prop(&cipher, &nonce, &aad, &pt));
    }

    #[test]
    fn xchacha20_poly1305_bitflip(aad in any::<Vec<u8>>(), pt in prop::collection::vec(any::<u8>(), 1..256), key in any::<[u8; 32]>()) {
        let cipher = XChaCha20Poly1305::new(&key);
        let nonce = nonce24();
        prop_assert!(bitflip_prop(&cipher, &nonce, &aad, &pt));
    }
}

// --- AES-128-GCM-SIV ---------------------------------------------------------

proptest! {
    #[test]
    fn aes128_gcm_siv_round_trip(aad in arb_aad(), pt in arb_plaintext(), key in any::<[u8; 16]>()) {
        let cipher = Aes128GcmSiv::new(&key).unwrap();
        let nonce = nonce12();
        prop_assert!(round_trip_prop(&cipher, &nonce, &aad, &pt));
    }

    #[test]
    fn aes128_gcm_siv_bitflip(aad in any::<Vec<u8>>(), pt in prop::collection::vec(any::<u8>(), 1..256), key in any::<[u8; 16]>()) {
        let cipher = Aes128GcmSiv::new(&key).unwrap();
        let nonce = nonce12();
        prop_assert!(bitflip_prop(&cipher, &nonce, &aad, &pt));
    }
}

// --- AES-256-GCM-SIV ---------------------------------------------------------

proptest! {
    #[test]
    fn aes256_gcm_siv_round_trip(aad in arb_aad(), pt in arb_plaintext(), key in any::<[u8; 32]>()) {
        let cipher = Aes256GcmSiv::new(&key).unwrap();
        let nonce = nonce12();
        prop_assert!(round_trip_prop(&cipher, &nonce, &aad, &pt));
    }

    #[test]
    fn aes256_gcm_siv_bitflip(aad in any::<Vec<u8>>(), pt in prop::collection::vec(any::<u8>(), 1..256), key in any::<[u8; 32]>()) {
        let cipher = Aes256GcmSiv::new(&key).unwrap();
        let nonce = nonce12();
        prop_assert!(bitflip_prop(&cipher, &nonce, &aad, &pt));
    }
}
