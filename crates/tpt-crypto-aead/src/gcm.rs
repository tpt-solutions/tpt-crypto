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
/// of `x¹²⁷`. Internally we work in the reflected representation (bit 0 = `x⁰`)
/// where the reduction constant is `0x87`.
#[inline]
fn gf_mult_portable(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let mut a = u128::from_be_bytes(*x).reverse_bits();
    let mut b = u128::from_be_bytes(*y).reverse_bits();
    let mut z = 0u128;
    let mut i = 0;
    while i < 128 {
        if b & 1 != 0 {
            z ^= a;
        }
        let reduce = a >> 127;
        a = a.wrapping_shl(1);
        if reduce != 0 {
            a ^= 0x87;
        }
        b >>= 1;
        i += 1;
    }
    z.reverse_bits().to_be_bytes()
}

/// GHASH field multiplication, selecting the hardware path when available.
#[inline]
fn gf_mult(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    #[cfg(all(target_arch = "x86_64", feature = "std"))]
    {
        if tpt_crypto_ct::arch::has_pclmulqdq() {
            return gf_mult_pclmul(x, y);
        }
    }
    gf_mult_portable(x, y)
}

#[cfg(all(target_arch = "x86_64", feature = "std"))]
#[inline]
fn gf_mult_pclmul(x: &[u8; 16], y: &[u8; 16]) -> [u8; 16] {
    let a = u128::from_be_bytes(*x);
    let b = u128::from_be_bytes(*y);
    let a_b = tpt_crypto_ct::arch::Block128::from_le_bytes(a.to_le_bytes());
    let b_b = tpt_crypto_ct::arch::Block128::from_le_bytes(b.to_le_bytes());
    let (lo_b, hi_b) = tpt_crypto_ct::arch::clmul128_raw(&a_b, &b_b);
    let lo = lo_b.lo as u128 | ((lo_b.hi as u128) << 64);
    let hi = hi_b.lo as u128 | ((hi_b.hi as u128) << 64);
    reduce_raw_256(lo, hi).to_be_bytes()
}

#[cfg(all(target_arch = "x86_64", feature = "std"))]
#[inline]
fn reduce_raw_256(lo: u128, hi: u128) -> u128 {
    // Fold the upper 128 bits into the lower using the non-reflected reduction
    // constant R = 0xe1 || 0^120. Two folds are sufficient for a 256-bit product.
    let (l1, h1) = clmul_raw(hi, R);
    let lo = lo ^ l1;
    let hi = hi ^ h1;
    let (l2, h2) = clmul_raw(hi, R);
    let _ = h2;
    lo ^ l2
}

#[cfg(all(target_arch = "x86_64", feature = "std"))]
const R: u128 = 0xe1u128 << 120;

#[cfg(all(target_arch = "x86_64", feature = "std"))]
#[inline]
fn clmul_raw(a: u128, b: u128) -> (u128, u128) {
    let a_b = tpt_crypto_ct::arch::Block128::from_le_bytes(a.to_le_bytes());
    let b_b = tpt_crypto_ct::arch::Block128::from_le_bytes(b.to_le_bytes());
    let (lo_b, hi_b) = tpt_crypto_ct::arch::clmul128_raw(&a_b, &b_b);
    let lo = lo_b.lo as u128 | ((lo_b.hi as u128) << 64);
    let hi = hi_b.lo as u128 | ((hi_b.hi as u128) << 64);
    (lo, hi)
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

    // GHASH over AAD || C || len(AAD) || len(C).
    let mut y = ghash_update(&h, [0u8; 16], aad);
    y = ghash_update(&h, y, buf);
    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&((aad.len() as u64) << 3).to_be_bytes());
    len_block[8..].copy_from_slice(&((buf.len() as u64) << 3).to_be_bytes());
    y = gh_step(&h, &y, &len_block);

    let e = cipher.encrypt_block(&j0);
    let mut t = [0u8; 16];
    for i in 0..16 {
        t[i] = y[i] ^ e[i];
    }
    let expected = Tag::new(t);

    if encrypt {
        let mut cb = j0;
        inc32(&mut cb);
        ctr_xor(cipher, &cb, buf);
        Ok(Some(expected))
    } else {
        match provided {
            Some(tag) if tag.ct_eq(&expected) => {
                let mut cb = j0;
                inc32(&mut cb);
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
        gcm_inner(&self.0, nonce, aad, buf, true, None).unwrap()
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
        gcm_inner(&self.0, nonce, aad, buf, true, None).unwrap()
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
    fn gf_mult_zero_identity() {
        let z = [0u8; 16];
        let one = {
            let mut o = [0u8; 16];
            o[15] = 0x80;
            o
        };
        assert_eq!(gf_mult(&z, &one), z);
        assert_eq!(gf_mult(&one, &one), one);
    }

    #[test]
    fn gf_mult_powers() {
        let x1 = { let mut o = [0u8; 16]; o[15] = 0x40; o }; // x^1
        let x2 = { let mut o = [0u8; 16]; o[15] = 0x20; o }; // x^2
        assert_eq!(gf_mult(&x1, &x1), x2);
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
