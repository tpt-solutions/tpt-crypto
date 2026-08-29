//! AES-GCM-SIV (RFC 8452) — a nonce-misuse-resistant AEAD — built on POLYVAL
//! (the GF(2¹²⁸) hash used by GCM-SIV, little-endian / POLYVAL convention).
//!
//! POLYVAL uses the field GF(2¹²⁸) with the polynomial `x¹²⁸ + x¹²⁷ + x¹²⁶ +
//! x¹²¹ + 1` and a little-endian byte convention: the first byte's low bit is
//! `x⁰`. The constant-time carry-less multiply and reduction follow the same
//! table-free approach as GHASH; the `dot` operation additionally multiplies by
//! `x⁻¹²⁸` (the field element `0100…0492`) as the RFC requires.

use crate::aes::Aes;
use crate::api::{Aead, Nonce, Tag};
use tpt_crypto_core::{Error, Result};

/// `x⁻¹²⁸` in the POLYVAL field (RFC 8452 §3): `x¹²⁷ + x¹²⁴ + x¹²¹ + x¹¹⁴ + 1`,
/// i.e. the 16-byte little-endian value `01000000000000000000000000000492`.
const X_INV: [u8; 16] = [0x01, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x04, 0x92];

#[inline]
fn xor_block(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut out = [0u8; 16];
    for i in 0..16 {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// POLYVAL defining polynomial `x¹²⁸ + x¹²⁷ + x¹²⁶ + x¹²¹ + 1` as the low-128-bit
/// reduction constant in the little-endian representation (RFC 8452 §3):
/// `0xc2` in the top byte (bits 121, 126, 127) plus bit 0.
const POLYVAL_R: u128 = (0xc2u128 << 120) | 1;

/// POLYVAL field multiplication `a · b` (little-endian POLYVAL convention).
///
/// `a`, `b` are 16-byte blocks interpreted as `Σ bit[i]·xⁱ` (byte 0 bit 0 = `x⁰`).
/// Multiplication by `x` is a left shift; when it overflows `x¹²⁸` the result is
/// reduced by [`POLYVAL_R`]. Branch-free (no secret-dependent control flow).
#[inline]
fn polyval_mul(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let mut acc = u128::from_le_bytes(*a);
    let b = u128::from_le_bytes(*b);
    let mut z = 0u128;
    let mut i = 0;
    while i < 128 {
        let bi = ((b >> i) & 1).wrapping_neg();
        z ^= acc & bi;
        let carry = ((acc >> 127) & 1).wrapping_neg();
        acc <<= 1;
        acc ^= POLYVAL_R & carry;
        i += 1;
    }
    z.to_le_bytes()
}

/// POLYVAL `dot(a, b) = a · b · x⁻¹²⁸`.
#[inline]
fn polyval_dot(a: &[u8; 16], b: &[u8; 16]) -> [u8; 16] {
    let p = polyval_mul(a, b);
    polyval_mul(&p, &X_INV)
}

/// One POLYVAL step: `S = dot(S ⊕ block, H)` (little-endian).
#[inline]
fn polyval_step(h: &[u8; 16], s: &[u8; 16], block: &[u8; 16]) -> [u8; 16] {
    polyval_dot(&xor_block(s, block), h)
}

/// Streaming POLYVAL over a (possibly non-block-aligned) byte string, keyed by `h`.
#[inline]
fn polyval_update(h: &[u8; 16], mut s: [u8; 16], data: &[u8]) -> [u8; 16] {
    let mut chunks = data.chunks_exact(16);
    for c in &mut chunks {
        let mut block = [0u8; 16];
        block.copy_from_slice(c);
        s = polyval_step(h, &s, &block);
    }
    let rem = chunks.remainder();
    if !rem.is_empty() {
        let mut block = [0u8; 16];
        block[..rem.len()].copy_from_slice(rem);
        s = polyval_step(h, &s, &block);
    }
    s
}

/// AES-GCM-SIV with a 128-bit key.
pub struct Aes128GcmSiv(Aes);
/// AES-GCM-SIV with a 256-bit key.
pub struct Aes256GcmSiv(Aes);

impl Aes128GcmSiv {
    /// Build from a 16-byte key.
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 16 {
            return Err(Error::InvalidLength);
        }
        Ok(Aes128GcmSiv(Aes::new_128(key)))
    }
}

impl Aes256GcmSiv {
    /// Build from a 32-byte key.
    pub fn new(key: &[u8]) -> Result<Self> {
        if key.len() != 32 {
            return Err(Error::InvalidLength);
        }
        Ok(Aes256GcmSiv(Aes::new_256(key)))
    }
}

/// Core GCM-SIV seal/open (RFC 8452). 12-byte nonce.
fn gcm_siv_inner(
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

    let mut mac_key = [0u8; 32];
    let mut enc_key = [0u8; 32];
    derive_keys(cipher, &nonce.0, &mut mac_key, &mut enc_key);

    // POLYVAL key H = E(K_mac, 0^16). For AES-128-GCM-SIV K_mac/K_enc are
    // 128-bit; for AES-256-GCM-SIV they are 256-bit (RFC 8452 §4).
    let is_aes256 = cipher.rounds() == 14;
    let mac_cipher = if is_aes256 {
        Aes::new_256(&mac_key)
    } else {
        Aes::new_128(&mac_key[..16])
    };
    let auth_key = mac_cipher.encrypt_block(&[0u8; 16]);

    let enc_cipher = if is_aes256 {
        Aes::new_256(&enc_key)
    } else {
        Aes::new_128(&enc_key[..16])
    };

    let length_block = {
        let mut lb = [0u8; 16];
        lb[..8].copy_from_slice(&((aad.len() as u64) << 3).to_le_bytes());
        lb[8..].copy_from_slice(&((buf.len() as u64) << 3).to_le_bytes());
        lb
    };

    if encrypt {
        // S = POLYVAL over (padded AAD || padded plaintext || length).
        let s = polyval_update(&auth_key, [0u8; 16], aad);
        let s = polyval_update(&auth_key, s, buf);
        let s = polyval_step(&auth_key, &s, &length_block);

        let mut tag_input = s;
        for i in 0..12 {
            tag_input[i] ^= nonce.0[i];
        }
        tag_input[15] &= 0x7f;
        let tag = enc_cipher.encrypt_block(&tag_input);

        // CTR keystream: initial counter block = tag with top bit set.
        let mut cb = tag;
        cb[15] |= 0x80;
        ctr_xor(&enc_cipher, &cb, buf);

        Ok(Some(Tag::new(tag)))
    } else {
        // Recompute expected tag from (AAD || C), compare, then decrypt.
        let s = polyval_update(&auth_key, [0u8; 16], aad);
        let s = polyval_update(&auth_key, s, buf);
        let s = polyval_step(&auth_key, &s, &length_block);

        let mut tag_input = s;
        for i in 0..12 {
            tag_input[i] ^= nonce.0[i];
        }
        tag_input[15] &= 0x7f;
        let expected = enc_cipher.encrypt_block(&tag_input);

        match provided {
            Some(tag) if tag.ct_eq(&Tag::new(expected)) => {
                let mut cb = expected;
                cb[15] |= 0x80;
                ctr_xor(&enc_cipher, &cb, buf);
                Ok(None)
            }
            _ => Err(Error::Verification),
        }
    }
}

/// Derive (mac_key, enc_key) from the base key and nonce (RFC 8452 §4).
///
/// `E(K, le_u32(i) || nonce)[:8]` for `i = 0..4` (AES-128) or `i = 0..6`
/// (AES-256); the first 8 bytes of each block are kept.
fn derive_keys(base: &Aes, nonce: &[u8; 12], mac_key: &mut [u8; 32], enc_key: &mut [u8; 32]) {
    let blocks = if base.rounds() == 14 { 6 } else { 4 };
    for i in 0..blocks {
        let mut block = [0u8; 16];
        block[..4].copy_from_slice(&(i as u32).to_le_bytes());
        block[4..16].copy_from_slice(nonce);
        let ct = base.encrypt_block(&block);
        let dst = if i < 2 {
            &mut mac_key[i * 8..i * 8 + 8]
        } else {
            &mut enc_key[(i - 2) * 8..(i - 2) * 8 + 8]
        };
        dst.copy_from_slice(&ct[..8]);
    }
}

/// CTR mode with a little-endian 32-bit counter (RFC 8452 §4).
fn ctr_xor(cipher: &Aes, counter0: &[u8; 16], data: &mut [u8]) {
    let mut cb = *counter0;
    let mut i = 0;
    while i < data.len() {
        let ks = cipher.encrypt_block(&cb);
        let n = 16.min(data.len() - i);
        for j in 0..n {
            data[i + j] ^= ks[j];
        }
        // Increment the first 32 bits, little-endian.
        let c = u32::from_le_bytes([cb[0], cb[1], cb[2], cb[3]]).wrapping_add(1);
        cb[..4].copy_from_slice(&c.to_le_bytes());
        i += n;
    }
}

impl Aead<12, 16> for Aes128GcmSiv {
    fn encrypt_in_place_detached(&self, nonce: &Nonce<12>, aad: &[u8], buf: &mut [u8]) -> Tag<16> {
        gcm_siv_inner(&self.0, nonce, aad, buf, true, None).unwrap().expect("seal path returns Some(tag)")
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<12>,
        aad: &[u8],
        buf: &mut [u8],
        tag: &Tag<16>,
    ) -> Result<()> {
        gcm_siv_inner(&self.0, nonce, aad, buf, false, Some(tag)).map(|_| ())
    }
}

impl Aead<12, 16> for Aes256GcmSiv {
    fn encrypt_in_place_detached(&self, nonce: &Nonce<12>, aad: &[u8], buf: &mut [u8]) -> Tag<16> {
        gcm_siv_inner(&self.0, nonce, aad, buf, true, None).unwrap().expect("seal path returns Some(tag)")
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<12>,
        aad: &[u8],
        buf: &mut [u8],
        tag: &Tag<16>,
    ) -> Result<()> {
        gcm_siv_inner(&self.0, nonce, aad, buf, false, Some(tag)).map(|_| ())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn polyval_identity() {
        // POLYVAL with the multiplicative identity (x^0, little-endian 0x01) is a no-op.
        let id = [0x01u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        let x = hex::decode("4f4f95668c8305f0484736a9dcb81ec7").unwrap();
        let x: [u8; 16] = x.try_into().unwrap();
        assert_eq!(polyval_mul(&x, &id), x);
        assert_eq!(polyval_mul(&id, &x), x);
    }

    #[test]
    fn gcm_siv_rfc8452_kat() {
        // RFC 8452 Appendix C.1, first vector (zero plaintext, zero AAD).
        let key = hex::decode("01000000000000000000000000000000").unwrap();
        let nonce = hex::decode("030000000000000000000000").unwrap();
        let key: [u8; 16] = key.try_into().unwrap();
        let nonce: [u8; 12] = nonce.try_into().unwrap();
        let cipher = Aes128GcmSiv::new(&key).unwrap();
        let ct = cipher.encrypt(&Nonce::new(nonce), &[], &[]);
        let expected = hex::decode("dc20e2d83f25705bb49e439eca56de25").unwrap();
        assert_eq!(ct, expected);
        // Round-trip.
        let pt = cipher
            .decrypt(&Nonce::new(nonce), &[], &ct)
            .unwrap();
        assert_eq!(pt, &[] as &[u8]);
    }
}
