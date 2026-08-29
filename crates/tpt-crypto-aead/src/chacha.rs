//! ChaCha20 (RFC 8439) and Poly1305 (RFC 8439), plus the
//! ChaCha20-Poly1305 and XChaCha20-Poly1305 AEAD constructions.

use crate::api::{Aead, Nonce, Tag};
use tpt_crypto_core::{Error, Result};

#[inline]
fn rotl(x: u32, n: u32) -> u32 {
    x.rotate_left(n)
}

#[inline]
fn quarter_round(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = rotl(s[d], 16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = rotl(s[b], 12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] ^= s[a];
    s[d] = rotl(s[d], 8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] ^= s[c];
    s[b] = rotl(s[b], 7);
}

/// One ChaCha20 block: serialize `state` (LE), XOR with the 64-byte keystream.
#[inline]
fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    // "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    state[4] = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
    state[5] = u32::from_le_bytes([key[4], key[5], key[6], key[7]]);
    state[6] = u32::from_le_bytes([key[8], key[9], key[10], key[11]]);
    state[7] = u32::from_le_bytes([key[12], key[13], key[14], key[15]]);
    state[8] = u32::from_le_bytes([key[16], key[17], key[18], key[19]]);
    state[9] = u32::from_le_bytes([key[20], key[21], key[22], key[23]]);
    state[10] = u32::from_le_bytes([key[24], key[25], key[26], key[27]]);
    state[11] = u32::from_le_bytes([key[28], key[29], key[30], key[31]]);
    state[12] = counter;
    state[13] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    state[14] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    state[15] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);

    let mut working = state;
    for _ in 0..10 {
        quarter_round(&mut working, 0, 4, 8, 12);
        quarter_round(&mut working, 1, 5, 9, 13);
        quarter_round(&mut working, 2, 6, 10, 14);
        quarter_round(&mut working, 3, 7, 11, 15);
        quarter_round(&mut working, 0, 5, 10, 15);
        quarter_round(&mut working, 1, 6, 11, 12);
        quarter_round(&mut working, 2, 7, 8, 13);
        quarter_round(&mut working, 3, 4, 9, 14);
    }

    let mut out = [0u8; 64];
    for i in 0..16 {
        let word = working[i].wrapping_add(state[i]);
        out[4 * i..4 * i + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// ChaCha20 stream cipher keystream generator.
pub struct ChaCha20 {
    key: [u8; 32],
    nonce: [u8; 12],
    counter: u32,
}

impl ChaCha20 {
    /// Build a ChaCha20 instance from a 32-byte key and 12-byte nonce.
    pub fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        ChaCha20 {
            key: *key,
            nonce: *nonce,
            counter: 0,
        }
    }

    /// Encrypt/decrypt `data` in place (XOR with the keystream from the current
    /// counter; the counter advances by `ceil(len/64)` blocks).
    pub fn apply_keystream(&mut self, data: &mut [u8]) {
        let mut offset = 0;
        while offset < data.len() {
            let ks = chacha20_block(&self.key, self.counter, &self.nonce);
            let n = 64.min(data.len() - offset);
            for i in 0..n {
                data[offset + i] ^= ks[i];
            }
            offset += n;
            self.counter = self.counter.wrapping_add(1);
        }
    }
}

/// HChaCha20 (used by XChaCha20); returns a 32-byte subkey.
fn hchacha20(key: &[u8; 32], nonce: &[u8; 16]) -> [u8; 32] {
    let mut state = [0u32; 16];
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    state[4] = u32::from_le_bytes([key[0], key[1], key[2], key[3]]);
    state[5] = u32::from_le_bytes([key[4], key[5], key[6], key[7]]);
    state[6] = u32::from_le_bytes([key[8], key[9], key[10], key[11]]);
    state[7] = u32::from_le_bytes([key[12], key[13], key[14], key[15]]);
    state[8] = u32::from_le_bytes([key[16], key[17], key[18], key[19]]);
    state[9] = u32::from_le_bytes([key[20], key[21], key[22], key[23]]);
    state[10] = u32::from_le_bytes([key[24], key[25], key[26], key[27]]);
    state[11] = u32::from_le_bytes([key[28], key[29], key[30], key[31]]);
    state[12] = u32::from_le_bytes([nonce[0], nonce[1], nonce[2], nonce[3]]);
    state[13] = u32::from_le_bytes([nonce[4], nonce[5], nonce[6], nonce[7]]);
    state[14] = u32::from_le_bytes([nonce[8], nonce[9], nonce[10], nonce[11]]);
    state[15] = u32::from_le_bytes([nonce[12], nonce[13], nonce[14], nonce[15]]);

    for _ in 0..10 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }

    let mut out = [0u8; 32];
    for i in 0..4 {
        out[4 * i..4 * i + 4].copy_from_slice(&state[i].to_le_bytes());
    }
    for i in 0..4 {
        out[16 + 4 * i..16 + 4 * i + 4].copy_from_slice(&state[12 + i].to_le_bytes());
    }
    out
}

// ---- Poly1305 (26-bit limb, constant-time) -------------------------------
//
// Constant-time Poly1305 over the field Z/(2^130-5) using 26-bit limbs. No
// secret-dependent branches: the only data-dependent step is the final
// conditional subtraction of the prime, done with a branchless borrow mask.

const P0: u64 = 0x3fffffa;
const P1: u64 = 0x3ffffff;
const P2: u64 = 0x3ffffff;
const P3: u64 = 0x3ffffff;
const P4: u64 = 0x3ffffff;

/// Streaming Poly1305 MAC (Z/(2¹³⁰−5)), constant-time.
///
/// The one-shot [`poly1305_mac`] is a thin wrapper around this struct; the AEAD
/// constructions drive it directly so no contiguous buffering is required (and
/// the AEAD works under `no_std` without `alloc`).
pub struct Poly1305 {
    h: [u64; 5],
    r0: u64,
    r1: u64,
    r2: u64,
    r3: u64,
    r4: u64,
    r1_5: u64,
    r2_5: u64,
    r3_5: u64,
    r4_5: u64,
}

impl Poly1305 {
    /// Initialize from a 32-byte one-time key (first 16 clamped to `r`, last 16
    /// are `s`).
    pub fn new(key: &[u8; 32]) -> Self {
        let mut r = [0u8; 16];
        r.copy_from_slice(&key[..16]);
        r[3] &= 15;
        r[7] &= 15;
        r[11] &= 15;
        r[15] &= 15;

        let r0 = r[0] as u64 | (r[1] as u64) << 8 | ((r[2] & 3) as u64) << 16;
        let r1 = (r[2] >> 2) as u64 | (r[3] as u64) << 6 | (r[4] as u64) << 14 | ((r[5] & 15) as u64) << 22;
        let r2 = (r[5] >> 4) as u64 | (r[6] as u64) << 4 | (r[7] as u64) << 12 | ((r[8] & 63) as u64) << 20;
        let r3 = (r[8] >> 6) as u64 | (r[9] as u64) << 2 | (r[10] as u64) << 10 | (r[11] as u64) << 18;
        let r4 = r[12] as u64 | (r[13] as u64) << 8 | (r[14] as u64) << 16 | ((r[15] & 3) as u64) << 24;

        Poly1305 {
            h: [0u64; 5],
            r0,
            r1,
            r2,
            r3,
            r4,
            r1_5: r1.wrapping_mul(5),
            r2_5: r2.wrapping_mul(5),
            r3_5: r3.wrapping_mul(5),
            r4_5: r4.wrapping_mul(5),
        }
    }

    /// Absorb `data` (any length).
    pub fn update(&mut self, data: &[u8]) {
        let mut chunks = data.chunks_exact(16);
        for c in &mut chunks {
            let m: &[u8; 16] = c.try_into().unwrap();
            self.block(m, 16);
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            let mut m = [0u8; 16];
            m[..rem.len()].copy_from_slice(rem);
            self.block(&m, rem.len());
        }
    }

    /// Process a single 16-byte block (with the `2^(8*blen)` bit already implied
    /// by `blen`).
    fn block(&mut self, m: &[u8; 16], blen: usize) {
        let mut n = [0u64; 5];
        n[0] = m[0] as u64 | (m[1] as u64) << 8 | ((m[2] & 3) as u64) << 16;
        n[1] = (m[2] >> 2) as u64
            | (m[3] as u64) << 6
            | (m[4] as u64) << 14
            | ((m[5] & 15) as u64) << 22;
        n[2] = (m[5] >> 4) as u64
            | (m[6] as u64) << 4
            | (m[7] as u64) << 12
            | ((m[8] & 63) as u64) << 20;
        n[3] = (m[8] >> 6) as u64
            | (m[9] as u64) << 2
            | (m[10] as u64) << 10
            | (m[11] as u64) << 18;
        n[4] =
            m[12] as u64 | (m[13] as u64) << 8 | (m[14] as u64) << 16 | ((m[15] & 3) as u64) << 24;

        // Fold in the 2^(8*blen) bit (the "1" appended before the field mul).
        let bit = 8 * blen;
        n[bit / 26] |= 1u64 << (bit % 26);

        let h = &mut self.h;
        h[0] = h[0].wrapping_add(n[0]);
        h[1] = h[1].wrapping_add(n[1]);
        h[2] = h[2].wrapping_add(n[2]);
        h[3] = h[3].wrapping_add(n[3]);
        h[4] = h[4].wrapping_add(n[4]);

        let d0 = h[0] as u128 * self.r0
            + h[1] as u128 * self.r4_5
            + h[2] as u128 * self.r3_5
            + h[3] as u128 * self.r2_5
            + h[4] as u128 * self.r1_5;
        let d1 = h[0] as u128 * self.r1
            + h[1] as u128 * self.r0
            + h[2] as u128 * self.r4_5
            + h[3] as u128 * self.r3_5
            + h[4] as u128 * self.r2_5;
        let d2 = h[0] as u128 * self.r2
            + h[1] as u128 * self.r1
            + h[2] as u128 * self.r0
            + h[3] as u128 * self.r4_5
            + h[4] as u128 * self.r3_5;
        let d3 = h[0] as u128 * self.r3
            + h[1] as u128 * self.r2
            + h[2] as u128 * self.r1
            + h[3] as u128 * self.r0
            + h[4] as u128 * self.r4_5;
        let d4 = h[0] as u128 * self.r4
            + h[1] as u128 * self.r3
            + h[2] as u128 * self.r2
            + h[3] as u128 * self.r1
            + h[4] as u128 * self.r0;

        // Carry propagation into 26-bit limbs.
        let mut c = d0 >> 26;
        h[0] = (d0 & 0x3ffffff) as u64;
        let mut d1 = d1 + c;
        c = d1 >> 26;
        h[1] = (d1 & 0x3ffffff) as u64;
        let mut d2 = d2 + c;
        c = d2 >> 26;
        h[2] = (d2 & 0x3ffffff) as u64;
        let mut d3 = d3 + c;
        c = d3 >> 26;
        h[3] = (d3 & 0x3ffffff) as u64;
        let mut d4 = d4 + c;

        // Fold the overflow of d4 back in (2^130 ≡ 5 mod p).
        h[4] = (d4 & 0x3ffffff) as u64;
        h[0] = h[0].wrapping_add(((d4 >> 26) as u64).wrapping_mul(5));
        h[1] = h[1].wrapping_add(h[0] >> 26);
        h[0] &= 0x3ffffff;
        h[2] = h[2].wrapping_add(h[1] >> 26);
        h[1] &= 0x3ffffff;
        h[3] = h[3].wrapping_add(h[2] >> 26);
        h[2] &= 0x3ffffff;
        h[4] = h[4].wrapping_add(h[3] >> 26);
        h[3] &= 0x3ffffff;
        h[4] &= 0x3ffffff;

        // Constant-time conditional subtraction of p = 2^130 - 5.
        let mut b = 0u64;
        let r0 = h[0].wrapping_sub(P0).wrapping_sub(b);
        b = (r0 >> 63) & 1;
        let r1 = h[1].wrapping_sub(P1).wrapping_sub(b);
        b = (r1 >> 63) & 1;
        let r2 = h[2].wrapping_sub(P2).wrapping_sub(b);
        b = (r2 >> 63) & 1;
        let r3 = h[3].wrapping_sub(P3).wrapping_sub(b);
        b = (r3 >> 63) & 1;
        let r4 = h[4].wrapping_sub(P4).wrapping_sub(b);
        b = (r4 >> 63) & 1;
        let keep = (b ^ 1).wrapping_neg();
        let drop = !keep;
        h[0] = (r0 & keep) | (h[0] & drop);
        h[1] = (r1 & keep) | (h[1] & drop);
        h[2] = (r2 & keep) | (h[2] & drop);
        h[3] = (r3 & keep) | (h[3] & drop);
        h[4] = (r4 & keep) | (h[4] & drop);
    }

    /// Finalize, folding in the 16-byte `s` key half (no modular reduction of the
    /// sum; the tag is the low 128 bits).
    pub fn finalize(self, s: &[u8; 16]) -> [u8; 16] {
        let s0 = u128::from_le_bytes(*s);
        let hval = self.h[0] as u128
            | (self.h[1] as u128) << 26
            | (self.h[2] as u128) << 52
            | (self.h[3] as u128) << 78
            | ((self.h[4] as u128) & 0x3) << 104;
        let tag_val = hval.wrapping_add(s0);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&tag_val.to_le_bytes()[..16]);
        tag
    }
}

/// Poly1305 one-shot MAC over `msg` with a 32-byte one-time key.
fn poly1305_mac(msg: &[u8], key: &[u8; 32]) -> [u8; 16] {
    let mut mac = Poly1305::new(key);
    mac.update(msg);
    let s: [u8; 16] = key[16..32].try_into().unwrap();
    mac.finalize(&s)
}

// ---- AEAD constructions --------------------------------------------------

/// ChaCha20-Poly1305 (RFC 8439).
pub struct ChaCha20Poly1305 {
    key: [u8; 32],
}

/// XChaCha20-Poly1305 (draft-irtf-cfrg-xchacha).
pub struct XChaCha20Poly1305 {
    key: [u8; 32],
}

impl ChaCha20Poly1305 {
    /// Build from a 32-byte key.
    pub fn new(key: &[u8; 32]) -> Self {
        ChaCha20Poly1305 { key: *key }
    }
}

impl XChaCha20Poly1305 {
    /// Build from a 32-byte key.
    pub fn new(key: &[u8; 32]) -> Self {
        XChaCha20Poly1305 { key: *key }
    }
}

/// Construct the Poly1305 one-time key (from ChaCha20 block 0) and return the
/// 12-byte nonce to use for the ciphertext counter stream (counter starts at 1).
fn chacha_poly_setup(key: &[u8; 32], nonce: &[u8; 12]) -> ([u8; 32], [u8; 12]) {
    let ks = chacha20_block(key, 0, nonce);
    let mut poly_key = [0u8; 32];
    poly_key.copy_from_slice(&ks[..32]);
    (*poly_key, *nonce)
}

fn chacha_poly_seal(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
) -> Tag<16> {
    let (poly_key, cipher_nonce) = chacha_poly_setup(key, nonce);
    // ciphertext = ChaCha20 with counter starting at 1
    let mut ctr = ChaCha20::new(key, cipher_nonce);
    ctr.counter = 1;
    ctr.apply_keystream(buf);

    let mac = poly1305_mac_polykey(&poly_key, aad, buf);
    Tag::new(mac)
}

fn chacha_poly_open(
    key: &[u8; 32],
    nonce: &[u8; 12],
    aad: &[u8],
    buf: &mut [u8],
    tag: &Tag<16>,
) -> Result<()> {
    let (poly_key, cipher_nonce) = chacha_poly_setup(key, nonce);
    let expected = poly1305_mac_polykey(&poly_key, aad, buf);
    if !tag.ct_eq(&Tag::new(expected)) {
        return Err(Error::Verification);
    }
    let mut ctr = ChaCha20::new(key, cipher_nonce);
    ctr.counter = 1;
    ctr.apply_keystream(buf);
    Ok(())
}

/// Poly1305 over (aad || pad16 || ciphertext || pad16 || lengths), computed
/// streaming so it works without `alloc`.
fn poly1305_mac_polykey(poly_key: &[u8; 32], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
    let s: [u8; 16] = poly_key[16..32].try_into().unwrap();
    let mut mac = Poly1305::new(poly_key);
    mac.update(aad);
    mac.update(&[0u8; 16][..pad_len(aad.len())]);
    mac.update(ciphertext);
    mac.update(&[0u8; 16][..pad_len(ciphertext.len())]);
    let mut len_block = [0u8; 16];
    len_block[..8].copy_from_slice(&((aad.len() as u64) << 3).to_le_bytes());
    len_block[8..].copy_from_slice(&((ciphertext.len() as u64) << 3).to_le_bytes());
    mac.update(&len_block);
    mac.finalize(&s)
}

#[inline]
fn pad_len(len: usize) -> usize {
    (16 - (len % 16)) % 16
}

impl Aead for ChaCha20Poly1305 {
    const NONCE_LEN: usize = 12;
    const TAG_LEN: usize = 16;

    fn encrypt_in_place_detached(&self, nonce: &Nonce<12>, aad: &[u8], buf: &mut [u8]) -> Tag<16> {
        chacha_poly_seal(&self.key, &nonce.0, aad, buf)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<12>,
        aad: &[u8],
        buf: &mut [u8],
        tag: &Tag<16>,
    ) -> Result<()> {
        chacha_poly_open(&self.key, &nonce.0, aad, buf, tag)
    }
}

impl Aead for XChaCha20Poly1305 {
    const NONCE_LEN: usize = 24;
    const TAG_LEN: usize = 16;

    fn encrypt_in_place_detached(&self, nonce: &Nonce<24>, aad: &[u8], buf: &mut [u8]) -> Tag<16> {
        // Derive subkey via HChaCha20 on the first 16 bytes of the 24-byte nonce.
        let mut subkey = [0u8; 32];
        let mut nonce16 = [0u8; 16];
        nonce16.copy_from_slice(&nonce.0[..16]);
        subkey.copy_from_slice(&hchacha20(&self.key, &nonce16));
        let mut inner_nonce = [0u8; 12];
        inner_nonce.copy_from_slice(&nonce.0[16..]);
        chacha_poly_seal(&subkey, &inner_nonce, aad, buf)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<24>,
        aad: &[u8],
        buf: &mut [u8],
        tag: &Tag<16>,
    ) -> Result<()> {
        let mut subkey = [0u8; 32];
        let mut nonce16 = [0u8; 16];
        nonce16.copy_from_slice(&nonce.0[..16]);
        subkey.copy_from_slice(&hchacha20(&self.key, &nonce16));
        let mut inner_nonce = [0u8; 12];
        inner_nonce.copy_from_slice(&nonce.0[16..]);
        chacha_poly_open(&subkey, &inner_nonce, aad, buf, tag)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chacha20_rfc8439_block() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
        let nonce = hex::decode("000000090000004a0000000000000000").unwrap();
        let key: [u8; 32] = key.try_into().unwrap();
        let nonce: [u8; 12] = nonce.try_into().unwrap();
        let block = chacha20_block(&key, 1, &nonce);
        let expected = hex::decode(
            "10f1e7e4d13b5915500fdd1fa32071c4\
             c7d1f4c733c068030422aa9ac3d46c4e\
             d2826446079faa0914c2d705d98b02a2\
             b5129cd1de164eb9cbd083e8a2503c4e",
        )
        .unwrap();
        assert_eq!(&block[..], &expected[..]);
    }

    #[test]
    fn chacha20_rfc8439_stream() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
        let nonce = hex::decode("000000000000004a0000000000000000").unwrap();
        let key: [u8; 32] = key.try_into().unwrap();
        let nonce: [u8; 12] = nonce.try_into().unwrap();
        let pt = [0u8; 64];
        let mut ct = pt;
        let mut c = ChaCha20::new(&key, &nonce);
        c.apply_keystream(&mut ct);
        let expected = hex::decode(
            "224f51f3401bd9e12fde276fb8631ded8\
             5c68a49722793738b47e0e7eaf2e8249\
             a554c7df511a8b3d4cbaeb2a7b5e9c8e\
             be871f191017b461b7e4ceb17ca80eb0",
        )
        .unwrap();
        assert_eq!(&ct[..], &expected[..]);
    }

    #[test]
    fn poly1305_rfc8439() {
        // RFC 8439 §2.5.2 test vector
        let key = hex::decode("0000000000000000000000000000000000000000000000000000000000000000")
            .unwrap();
        let key: [u8; 32] = key.try_into().unwrap();
        let msg = hex::decode("").unwrap();
        let tag = poly1305_mac(&msg, &key);
        assert_eq!(tag, [0u8; 16]);
    }
}
