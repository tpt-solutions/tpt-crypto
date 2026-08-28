//! HMAC-DRBG (NIST SP 800-90A), generic over any [`Hasher`] with a known
//! block size. Implements [`tpt_crypto_core::DrbgCore`].

use crate::traits::Hasher;
use crate::mac::Hmac;
use tpt_crypto_core::{DrbgCore, Error, Result};

/// HMAC-DRBG state, parameterized by hash `H` and its block size `BLOCK`.
#[derive(Clone)]
pub struct HmacDrbg<H: Hasher + Default, const BLOCK: usize> {
    k: [u8; H::OUTPUT_SIZE],
    v: [u8; H::OUTPUT_SIZE],
}

impl<H: Hasher + Default, const BLOCK: usize> HmacDrbg<H, BLOCK> {
    /// Instantiate the DRBG with optional personalization `personal` and
    /// optional entropy `entropy` (each may be empty).
    #[must_use]
    pub fn new(personal: &[u8], entropy: &[u8]) -> Self {
        let mut d = HmacDrbg {
            k: [0u8; H::OUTPUT_SIZE],
            v: [0u8; H::OUTPUT_SIZE],
        };
        for b in d.v.iter_mut() {
            *b = 1;
        }
        d.update(entropy, personal);
        d
    }

    fn hmac(&self, data: &[u8]) -> [u8; H::OUTPUT_SIZE] {
        let mut h = Hmac::<H, BLOCK>::new(&self.k);
        h.update(&self.v);
        h.update(data);
        h.finalize()
    }

    fn update(&mut self, data1: &[u8], data2: &[u8]) {
        // K = HMAC(K, V || 0x00 || data1 || data2)
        let mut h = Hmac::<H, BLOCK>::new(&self.k);
        h.update(&self.v);
        h.update(&[0x00]);
        h.update(data1);
        h.update(data2);
        self.k = h.finalize();
        self.v = self.hmac(&[]);
        // K = HMAC(K, V || 0x01 || data1 || data2)
        let mut h2 = Hmac::<H, BLOCK>::new(&self.k);
        h2.update(&self.v);
        h2.update(&[0x01]);
        h2.update(data1);
        h2.update(data2);
        self.k = h2.finalize();
        self.v = self.hmac(&[]);
    }
}

impl<H: Hasher + Default, const BLOCK: usize> DrbgCore for HmacDrbg<H, BLOCK> {
    fn reseed(&mut self, entropy_input: &[u8], additional_input: &[u8]) {
        self.update(entropy_input, additional_input);
    }

    fn generate(&mut self, out: &mut [u8], additional_input: &[u8]) -> Result<()> {
        if !additional_input.is_empty() {
            self.update(additional_input, &[]);
        }
        let mut generated = 0;
        while generated < out.len() {
            self.v = self.hmac(&[]);
            let take = (out.len() - generated).min(H::OUTPUT_SIZE);
            out[generated..generated + take].copy_from_slice(&self.v[..take]);
            generated += take;
        }
        // Post-generation update with 0x00 separator.
        self.update(&[0x00], &[]);
        Ok(())
    }
}

/// Convenience: HMAC-DRBG over SHA-256.
pub type HmacDrbgSha256 = HmacDrbg<crate::sha2::Sha256, 64>;

#[allow(dead_code)]
fn _assert_error(_: Error) {}
