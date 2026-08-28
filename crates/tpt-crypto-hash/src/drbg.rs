//! HMAC-DRBG (NIST SP 800-90A), generic over any [`Hasher`] with a known
//! block size. Implements [`tpt_crypto_core::DrbgCore`].

use crate::mac::Hmac;
use crate::traits::Hasher;
use core::marker::PhantomData;
use tpt_crypto_core::{DrbgCore, Error, Result};

/// HMAC-DRBG state, parameterized by hash `H` (`Hasher<OUT>`) and block size `BLOCK`.
#[derive(Clone)]
pub struct HmacDrbg<H: Hasher<OUT> + Default + Clone, const BLOCK: usize, const OUT: usize> {
    k: [u8; OUT],
    v: [u8; OUT],
    _h: PhantomData<H>,
}

impl<H: Hasher<OUT> + Default + Clone, const BLOCK: usize, const OUT: usize> HmacDrbg<H, BLOCK, OUT> {
    /// Instantiate the DRBG with optional personalization and entropy.
    #[must_use]
    pub fn new(personal: &[u8], entropy: &[u8]) -> Self {
        let mut d = HmacDrbg {
            k: [0u8; OUT],
            v: [0u8; OUT],
            _h: PhantomData,
        };
        for b in d.v.iter_mut() {
            *b = 1;
        }
        d.update(entropy, personal);
        d
    }

    fn hmac(&self, data: &[u8]) -> [u8; OUT] {
        let mut h = Hmac::<H, BLOCK, OUT>::new(&self.k);
        h.update(&self.v);
        h.update(data);
        h.finalize()
    }

    fn update(&mut self, data1: &[u8], data2: &[u8]) {
        let mut h = Hmac::<H, BLOCK, OUT>::new(&self.k);
        h.update(&self.v);
        h.update(&[0x00]);
        h.update(data1);
        h.update(data2);
        self.k = h.finalize();
        self.v = self.hmac(&[]);
        let mut h2 = Hmac::<H, BLOCK, OUT>::new(&self.k);
        h2.update(&self.v);
        h2.update(&[0x01]);
        h2.update(data1);
        h2.update(data2);
        self.k = h2.finalize();
        self.v = self.hmac(&[]);
    }
}

impl<H: Hasher<OUT> + Default + Clone, const BLOCK: usize, const OUT: usize> DrbgCore
    for HmacDrbg<H, BLOCK, OUT>
{
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
            let take = (out.len() - generated).min(OUT);
            out[generated..generated + take].copy_from_slice(&self.v[..take]);
            generated += take;
        }
        self.update(&[0x00], &[]);
        Ok(())
    }
}

/// Convenience: HMAC-DRBG over SHA-256.
#[allow(dead_code)]
pub type HmacDrbgSha256 = HmacDrbg<crate::sha2::Sha256, 64, 32>;

#[allow(dead_code)]
fn _assert_error(_: Error) {}
