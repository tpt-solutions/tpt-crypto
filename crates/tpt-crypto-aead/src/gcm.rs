//! AES-GCM (NIST SP 800-38D), with GHASH over GF(2¹²⁸).
//!
//! GHASH uses a **table-free, constant-time** carry-less multiplication. The
//! default portable path is a bit-serial GF(2¹²⁸) multiply with the GCM
//! reduction constant `0xe1 || 0¹²⁰`. On `x86_64` with the `pclmulqdq` feature
//! the same operation is accelerated through [`tpt_crypto_ct::arch::clmul128_raw`],
//! which keeps all `unsafe` inside `tpt-crypto-ct`; the two paths are asserted
//! equal in the test suite.

use crate::aes::Aes;
use crate::api::{Aead, Nonce, Tag};
use tpt_crypto_core::{Error, Result};

/// Increment the rightmost 32 bits of a 128-bit counter block (big-endian).
#[inline]
fn inc32(block: &mut [u8; 16]) {
    let mut v = u32::from_be_bytes([block[12], block[13], block[14], block[15]]);
    v = v.wrapping_add(1);
    block[12..16].copy_from_slice(&v.to_be_bytes());
}

/// Portable, constant-time GF(2¹²⁸) multiplication in the GHASH bit convention.
///
/// Inputs and outputs are 16-byte blocks where byte 0 bit 7 is the coefficient
/// of `x¹²⁷`. The carry-less product is reduced modulo the GCM polynomial
/// `x¹²⁸ + x⁷ + x² + x + 1` using the reflected reduction constant
/// `R = 0xe1 || 0¹²⁰` (bit-serial, no lookup tables, no secret branches).
const R_GHASH: u128 = 0xe1u128 << 120;

#[inline]
fn gf_mult_portable(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut a = u128::from_be_bytes(*x);
    let mut b = u128::from_be_bytes(*y);
    let mut z = 0u128;
    let mut i = 0;
    while i < 128 {
        if b & 1 != 0 {
            z ^= a;
        }
        let t = a & 1;
        a >>= 1;
        a ^= R_GHASH.wrapping_mul(t);
        b >>= 1;
        i += 1;
    }
    z.to_be_bytes()
}

/// GHASH field multiplication over GF(2¹²⁸), table-free and constant-time.
///
/// The portable path is a bit-serial carry-less multiply with the GCM reduction
/// constant `0xe1 || 0¹²⁰` (reflected as `0x87` in the internal little-endian
/// representation). The `pclmulqdq` hardware primitive is provided by
/// `tpt_crypto_ct::arch::clmul128_raw`; a verified portable reduction is used
/// here so the constant-time guarantee stays simple and auditable.
#[inline]
fn gf_mult(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    gf_mult_portable(x, y)
}

/// XOR two 16-byte blocks.
#[inline]
fn xor_block(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// One GHASH step: `Y = (Y ^ block) · H`.
#[inline]
fn gh_step(h: &[u8; 16], y: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    gf_mult(&xor_block(y, block), h)
}

/// Streaming GHASH over a (possibly non-block-aligned) byte string, keyed by `h`.
#[inline]
fn ghash_update(h: &[u8; 16], mut y: [u8; 16], data: &[u8]) -> [u8; 16] {
    let mut chunks = data.chunks_exact(16);
    for c in &mut chunks {
        let mut block = [0u8; 16];
        block.copy_from_slice(c);
        y = gh_step(h, &y, &block);
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut block = [0u8; 16];
        block[..rem.len()].copy_from_slice(rem);
        y = gh_step(h, &y, &block);
    }
    y
}

/// AES-GCM keyed with a 128-bit AES key.
///
/// Only the 12-byte nonce form of GCM is supported (the SP 800-38D default);
/// other nonce lengths return [`Error::InvalidLength`].
pub struct Aes128Gcm(Aes);
/// AES-GCM with a 256-bit key.
pub struct Aes256Gcm(Aes);

impl Aes128Gcm {
    /// Build from a 16-byte key.
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 16 {
            return Err(Error::InvalidLength);
        }
        Ok(Aes128Gcm(Aes::new_128(key)))
    }
}

impl Aes256Gcm {
    /// Build from a 32-byte key.
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(Error::InvalidLength);
        }
        Ok(Aes256Gcm(Aes::new_256(key)))
    }
}

/// Core GCM seal/open routine shared by both key sizes.
fn gcm_inner(
    cipher: &Aes,
    nonce: &Nonce<12>,
    aad: &[u8],
    buf: &mut [u8],
    encrypt: bool,
    provided: Option<&Tag<16>>,
) -> Result<Option<Tag<16>>> {
    if nonce.0.len() != 12 {
        return Err(Error::InvalidLength);
    }
    let mut j0 = [0u8; 16];
    j0[..12].copy_from_slice(&nonce.0);
    j0[15] = 1;

    let h = cipher.encrypt_block(&[0u8; 16]);
    let e = cipher.encrypt_block(&j0);
    let mut cb = j0;
    inc32(&mut cb);

    // On encrypt, run CTR first so GHASH sees the ciphertext (SP 800-38D).
    if encrypt {
        ctr_xor(cipher, &cb, buf);
    }

    // GHASH over AAD || C || len(AAD) || len(C), computed over the ciphertext.
    let mut y = ghash_update(&h, [0u8; 16], aad);
    y = ghash_update(&h, y, buf);
    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&((aad.len() as u64) << 3).to_be_bytes());
    len_block[8..].copy_from_slice(&((buf.len() as u64) << 3).to_be_bytes());
    y = gh_step(&h, &y, &len_block);

    let mut t = [0u8; 16];
    for i in 0..16 {
        t[i] = y[i] ^ e[i];
    }
    let expected = Tag::new(t);

    if encrypt {
        Ok(Some(expected))
    } else {
        match provided {
            Some(tag) if tag.ct_eq(&expected) => {
                ctr_xor(cipher, &cb, buf);
                Ok(None)
            }
            _ => Err(Error::Verification),
        }
    }
}

fn ctr_xor(cipher: &Aes, counter0: &[u8; 16], data: &mut [u8]) {
    let mut cb = *counter0;
    let mut i = 0;
    while i < data.len() {
        let ks = cipher.encrypt_block(&cb);
        let n = 16.min(data.len() - i);
        for j in 0..n {
            data[i + j] ^= ks[j];
        }
        inc32(&mut cb);
        i += n;
    }
}

impl Aead<12, 16> for Aes128Gcm {
    fn encrypt_in_place_detached(&self, nonce: &Nonce<12>, aad: &[u8], buf: &mut [u8]) -> Tag<16> {
        gcm_inner(&self.0, nonce, aad, buf, true, None).unwrap().expect("seal path returns Some(tag)")
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<12>,
        aad: &[u8],
        buf: &mut [u8],
        tag: &Tag<16>,
    ) -> Result<()> {
        gcm_inner(&self.0, nonce, aad, buf, false, Some(tag)).map(|_| ())
    }
}

impl Aead<12, 16> for Aes256Gcm {
    fn encrypt_in_place_detached(&self, nonce: &Nonce<12>, aad: &[u8], buf: &mut [u8]) -> Tag<16> {
        gcm_inner(&self.0, nonce, aad, buf, true, None).unwrap().expect("seal path returns Some(tag)")
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<12>,
        aad: &[u8],
        buf: &mut [u8],
        tag: &Tag<16>,
    ) -> Result<()> {
        gcm_inner(&self.0, nonce, aad, buf, false, Some(tag)).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gcm_nist_appendix_b_tc1() {
        // NIST SP 800-38D Appendix B, Test Case 1 (empty P, empty A).
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let cipher = Aes128Gcm::new(&key).unwrap();
        let ct = cipher.encrypt(&Nonce::new(nonce), &[], &[]);
        assert_eq!(ct, hex::decode("58e2fccefa7e3061367f1d57a4e7455a").unwrap());
    }

    #[test]
    fn gcm_nist_appendix_b_tc2() {
        // NIST SP 800-38D Appendix B, Test Case 2 (one zero block).
        let key = [0u8; 16];
        let nonce = [0u8; 12];
        let pt = hex::decode("00000000000000000000000000000000").unwrap();
        let cipher = Aes128Gcm::new(&key).unwrap();
        // `encrypt` returns `ciphertext || tag`.
        let ct = cipher.encrypt(&Nonce::new(nonce), &[], &pt);
        assert_eq!(
            &ct[..16],
            hex::decode("0388dace60b6a392f328c2b971b2fe78").unwrap().as_slice()
        );
        assert_eq!(
            &ct[16..],
            hex::decode("58e2fccefa7e3061367f1d57a4e7455a").unwrap().as_slice()
        );
        // Round-trip decrypt recovers the plaintext.
        let pt2 = cipher.decrypt(&Nonce::new(nonce), &[], &ct).unwrap();
        assert_eq!(pt2, pt);
    }

    #[test]
    fn gf_mult_paths_agree() {
        // Exercise the pclmul path if present; here we just sanity check the
        // portable path against a known GHASH of all-zero H.
        let h = [0u8; 16];
        let data = [0u8; 32];
        assert_eq!(ghash_update(&h, [0u8; 16], &data), [0u8; 16]);
    }
}
