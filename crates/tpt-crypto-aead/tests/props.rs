//! Property-style tests for `tpt-crypto-aead`.
//!
//! Every AEAD construction must satisfy:
//! 1. `decrypt(encrypt(m), aad, nonce) == m` for arbitrary plaintexts.
//! 2. Any single-bit flip in ciphertext causes `decrypt` to return `Err`.

use rand::rngs::SmallRng;
use rand::{Rng, SeedableRng};
use tpt_crypto_aead::Aead;
use tpt_crypto_aead::Nonce;
use tpt_crypto_aead::{
    Aes128Gcm, Aes128GcmSiv, Aes256Gcm, Aes256GcmSiv, ChaCha20Poly1305, XChaCha20Poly1305,
};

const fn nonce12() -> Nonce<12> {
    Nonce::new([0u8; 12])
}

const fn nonce24() -> Nonce<24> {
    Nonce::new([0u8; 24])
}

fn rand_vec(rng: &mut SmallRng, max_len: usize) -> Vec<u8> {
    let len = rng.random_range(0..max_len);
    let mut v = vec![0u8; len];
    rng.fill(&mut v[..]);
    v
}

// --- round-trip --------------------------------------------------------------

#[test]
fn aes128_gcm_round_trip() {
    let mut rng = SmallRng::seed_from_u64(0xDEAD_BEEF_CAFE_BABE);
    let key: [u8; 16] = rng.random();
    let cipher = Aes128Gcm::new(&key).unwrap();
    let nonce = nonce12();
    for _ in 0..64 {
        let aad = rand_vec(&mut rng, 128);
        let pt = rand_vec(&mut rng, 256);
        let ct = cipher.encrypt(&nonce, &aad, &pt);
        let dec = cipher.decrypt(&nonce, &aad, &ct);
        assert_eq!(dec.as_deref(), Ok(&pt[..]));
    }
}

#[test]
fn aes256_gcm_round_trip() {
    let mut rng = SmallRng::seed_from_u64(0xDEAD_BEEF_CAFE_BABE);
    let key: [u8; 32] = rng.random();
    let cipher = Aes256Gcm::new(&key).unwrap();
    let nonce = nonce12();
    for _ in 0..64 {
        let aad = rand_vec(&mut rng, 128);
        let pt = rand_vec(&mut rng, 256);
        let ct = cipher.encrypt(&nonce, &aad, &pt);
        let dec = cipher.decrypt(&nonce, &aad, &ct);
        assert_eq!(dec.as_deref(), Ok(&pt[..]));
    }
}

#[test]
fn chacha20_poly1305_round_trip() {
    let mut rng = SmallRng::seed_from_u64(0xDEAD_BEEF_CAFE_BABE);
    let key: [u8; 32] = rng.random();
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = nonce12();
    for _ in 0..64 {
        let aad = rand_vec(&mut rng, 128);
        let pt = rand_vec(&mut rng, 256);
        let ct = cipher.encrypt(&nonce, &aad, &pt);
        let dec = cipher.decrypt(&nonce, &aad, &ct);
        assert_eq!(dec.as_deref(), Ok(&pt[..]));
    }
}

#[test]
fn xchacha20_poly1305_round_trip() {
    let mut rng = SmallRng::seed_from_u64(0xDEAD_BEEF_CAFE_BABE);
    let key: [u8; 32] = rng.random();
    let cipher = XChaCha20Poly1305::new(&key);
    let nonce = nonce24();
    for _ in 0..64 {
        let aad = rand_vec(&mut rng, 128);
        let pt = rand_vec(&mut rng, 256);
        let ct = cipher.encrypt(&nonce, &aad, &pt);
        let dec = cipher.decrypt(&nonce, &aad, &ct);
        assert_eq!(dec.as_deref(), Ok(&pt[..]));
    }
}

#[test]
fn aes128_gcm_siv_round_trip() {
    let mut rng = SmallRng::seed_from_u64(0xDEAD_BEEF_CAFE_BABE);
    let key: [u8; 16] = rng.random();
    let cipher = Aes128GcmSiv::new(&key).unwrap();
    let nonce = nonce12();
    for _ in 0..64 {
        let aad = rand_vec(&mut rng, 128);
        let pt = rand_vec(&mut rng, 256);
        let ct = cipher.encrypt(&nonce, &aad, &pt);
        let dec = cipher.decrypt(&nonce, &aad, &ct);
        assert_eq!(dec.as_deref(), Ok(&pt[..]));
    }
}

#[test]
fn aes256_gcm_siv_round_trip() {
    let mut rng = SmallRng::seed_from_u64(0xDEAD_BEEF_CAFE_BABE);
    let key: [u8; 32] = rng.random();
    let cipher = Aes256GcmSiv::new(&key).unwrap();
    let nonce = nonce12();
    for _ in 0..64 {
        let aad = rand_vec(&mut rng, 128);
        let pt = rand_vec(&mut rng, 256);
        let ct = cipher.encrypt(&nonce, &aad, &pt);
        let dec = cipher.decrypt(&nonce, &aad, &ct);
        assert_eq!(dec.as_deref(), Ok(&pt[..]));
    }
}

// --- bitflip --------------------------------------------------------------

fn bitflip_test<C, const NONCE_LEN: usize, const TAG_LEN: usize>(
    cipher: &C,
    nonce: &Nonce<NONCE_LEN>,
) where
    C: Aead<NONCE_LEN, TAG_LEN>,
{
    let mut rng = SmallRng::seed_from_u64(0xCAFE_BABE_DEAD_BEEF);
    for _ in 0..64 {
        let aad = rand_vec(&mut rng, 128);
        let mut pt = rand_vec(&mut rng, 256);
        while pt.is_empty() {
            pt = rand_vec(&mut rng, 256);
        }
        let ct = cipher.encrypt(nonce, &aad, &pt);
        let body_len = ct.len() - TAG_LEN;
        if body_len == 0 {
            continue;
        }
        let mut corrupted = ct.clone();
        let flip_idx = rng.random_range(0..body_len);
        corrupted[flip_idx] ^= 0x01;
        let dec = cipher.decrypt(nonce, &aad, &corrupted);
        assert!(
            dec.is_err(),
            "bitflip at idx={} should fail (pt_len={}, aad_len={})",
            flip_idx,
            pt.len(),
            aad.len()
        );
    }
}

#[test]
fn aes128_gcm_bitflip() {
    let mut rng = SmallRng::seed_from_u64(0xCAFE_BABE_DEAD_BEEF);
    let key: [u8; 16] = rng.random();
    let cipher = Aes128Gcm::new(&key).unwrap();
    let nonce = nonce12();
    bitflip_test(&cipher, &nonce);
}

#[test]
fn aes256_gcm_bitflip() {
    let mut rng = SmallRng::seed_from_u64(0xCAFE_BABE_DEAD_BEEF);
    let key: [u8; 32] = rng.random();
    let cipher = Aes256Gcm::new(&key).unwrap();
    let nonce = nonce12();
    bitflip_test(&cipher, &nonce);
}

#[test]
fn chacha20_poly1305_bitflip() {
    let mut rng = SmallRng::seed_from_u64(0xCAFE_BABE_DEAD_BEEF);
    let key: [u8; 32] = rng.random();
    let cipher = ChaCha20Poly1305::new(&key);
    let nonce = nonce12();
    bitflip_test(&cipher, &nonce);
}

#[test]
fn xchacha20_poly1305_bitflip() {
    let mut rng = SmallRng::seed_from_u64(0xCAFE_BABE_DEAD_BEEF);
    let key: [u8; 32] = rng.random();
    let cipher = XChaCha20Poly1305::new(&key);
    let nonce = nonce24();
    bitflip_test(&cipher, &nonce);
}

#[test]
fn aes128_gcm_siv_bitflip() {
    let mut rng = SmallRng::seed_from_u64(0xCAFE_BABE_DEAD_BEEF);
    let key: [u8; 16] = rng.random();
    let cipher = Aes128GcmSiv::new(&key).unwrap();
    let nonce = nonce12();
    bitflip_test(&cipher, &nonce);
}

#[test]
fn aes256_gcm_siv_bitflip() {
    let mut rng = SmallRng::seed_from_u64(0xCAFE_BABE_DEAD_BEEF);
    let key: [u8; 32] = rng.random();
    let cipher = Aes256GcmSiv::new(&key).unwrap();
    let nonce = nonce12();
    bitflip_test(&cipher, &nonce);
}
