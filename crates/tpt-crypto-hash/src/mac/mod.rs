//! HMAC (RFC 2104), generic over any [`Hasher`] with a known block size.

use crate::traits::Hasher;
use tpt_crypto_core::ct::{ct_eq_slice, Choice};

/// HMAC over hash `H` with block size `BLOCK` bytes.
#[derive(Clone)]
pub struct Hmac<H: Hasher + Default, const BLOCK: usize> {
    inner: H,
    outer: H,
}

impl<H: Hasher + Default, const BLOCK: usize> Hmac<H, BLOCK> {
    /// Build an HMAC keyed with `key`.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        let mut key_block = [0u8; BLOCK];
        if key.len() > BLOCK {
            let mut h = H::default();
            h.update(key);
            let d = h.finalize();
            key_block[..d.len()].copy_from_slice(&d);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0u8; BLOCK];
        let mut opad = [0u8; BLOCK];
        for i in 0..BLOCK {
            ipad[i] = key_block[i] ^ 0x36;
            opad[i] = key_block[i] ^ 0x5c;
        }
        let mut inner = H::default();
        inner.update(&ipad);
        let mut outer = H::default();
        outer.update(&opad);
        Hmac { inner, outer }
    }

    /// Absorb message bytes.
    #[inline]
    pub fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    /// Finalize, leaving the MAC keyed state intact (reusable).
    pub fn finalize_reset(&mut self) -> [u8; H::OUTPUT_SIZE] {
        let inner_out = self.inner.finalize_reset();
        self.outer.update(&inner_out);
        self.outer.finalize_reset()
    }

    /// Finalize, consuming `self`.
    #[inline]
    pub fn finalize(self) -> [u8; H::OUTPUT_SIZE] {
        self.clone().finalize_reset()
    }

    /// Constant-time verification of a candidate tag.
    #[inline]
    pub fn verify(&self, tag: &[u8]) -> Choice {
        let mac = self.clone().finalize_reset();
        ct_eq_slice(&mac, tag)
    }

    /// Reset to the initial keyed state.
    pub fn reset(&mut self) {
        *self = self.clone();
    }
}

/// One-shot HMAC-SHA-256.
#[inline]
#[must_use]
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut h = Hmac::<crate::sha2::Sha256, 64>::new(key);
    h.update(msg);
    h.finalize()
}

/// One-shot HMAC-SHA-512.
#[inline]
#[must_use]
pub fn hmac_sha512(key: &[u8], msg: &[u8]) -> [u8; 64] {
    let mut h = Hmac::<crate::sha2::Sha512, 128>::new(key);
    h.update(msg);
    h.finalize()
}
