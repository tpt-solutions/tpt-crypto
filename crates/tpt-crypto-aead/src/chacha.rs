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

/// Streaming Poly1305 MAC (Z/(2¹³⁰−5)), constant-time.
///
/// Standard 5×26-bit-limb arithmetic (the "poly1305-donna" layout). Partial
/// blocks are buffered across [`update`](Self::update) calls, so the AEAD may
/// feed it the AAD, padding, ciphertext and length block as separate slices.
/// The one-shot [`poly1305_mac`] is a thin wrapper.
pub struct Poly1305 {
    r: [u32; 5],
    h: [u32; 5],
    buffer: [u8; 16],
    leftover: usize,
}

#[inline]
fn u8to32(s: &[u8]) -> u32 {
    u32::from_le_bytes([s[0], s[1], s[2], s[3]])
}

impl Poly1305 {
    /// Initialize from a 32-byte one-time key (first 16 clamped to `r`, last 16
    /// are the `s` addend passed to [`finalize`](Self::finalize)).
    pub fn new(key: &[u8; 32]) -> Self {
        let r = [
            u8to32(&key[0..]) & 0x3ff_ffff,
            (u8to32(&key[3..]) >> 2) & 0x3ff_ff03,
            (u8to32(&key[6..]) >> 4) & 0x3ff_c0ff,
            (u8to32(&key[9..]) >> 6) & 0x3f0_3fff,
            (u8to32(&key[12..]) >> 8) & 0x00f_ffff,
        ];
        Poly1305 {
            r,
            h: [0u32; 5],
            buffer: [0u8; 16],
            leftover: 0,
        }
    }

    /// Absorb `data` (any length), buffering a trailing partial block.
    pub fn update(&mut self, mut data: &[u8]) {
        if self.leftover > 0 {
            let want = core::cmp::min(16 - self.leftover, data.len());
            self.buffer[self.leftover..self.leftover + want].copy_from_slice(&data[..want]);
            self.leftover += want;
            data = &data[want..];
            if self.leftover < 16 {
                return;
            }
            let block = self.buffer;
            self.block(&block, false);
            self.leftover = 0;
        }
        let mut chunks = data.chunks_exact(16);
        for c in &mut chunks {
            let m: &[u8; 16] = c.try_into().unwrap();
            self.block(m, false);
        }
        let rem = chunks.remainder();
        if !rem.is_empty() {
            self.buffer[..rem.len()].copy_from_slice(rem);
            self.leftover = rem.len();
        }
    }

    /// Process one 16-byte block. `final_block` omits the high `2^128` bit and is
    /// only set for a short trailing block from [`finalize`](Self::finalize).
    fn block(&mut self, m: &[u8; 16], final_block: bool) {
        let hibit: u32 = if final_block { 0 } else { 1 << 24 };
        let [r0, r1, r2, r3, r4] = self.r;
        let s1 = r1.wrapping_mul(5);
        let s2 = r2.wrapping_mul(5);
        let s3 = r3.wrapping_mul(5);
        let s4 = r4.wrapping_mul(5);

        let mut h0 = self.h[0] + (u8to32(&m[0..]) & 0x3ff_ffff);
        let mut h1 = self.h[1] + ((u8to32(&m[3..]) >> 2) & 0x3ff_ffff);
        let mut h2 = self.h[2] + ((u8to32(&m[6..]) >> 4) & 0x3ff_ffff);
        let mut h3 = self.h[3] + ((u8to32(&m[9..]) >> 6) & 0x3ff_ffff);
        let mut h4 = self.h[4] + ((u8to32(&m[12..]) >> 8) | hibit);

        let mul = |a: u32, b: u32| (a as u64) * (b as u64);
        let d0 = mul(h0, r0) + mul(h1, s4) + mul(h2, s3) + mul(h3, s2) + mul(h4, s1);
        let d1 = mul(h0, r1) + mul(h1, r0) + mul(h2, s4) + mul(h3, s3) + mul(h4, s2);
        let d2 = mul(h0, r2) + mul(h1, r1) + mul(h2, r0) + mul(h3, s4) + mul(h4, s3);
        let d3 = mul(h0, r3) + mul(h1, r2) + mul(h2, r1) + mul(h3, r0) + mul(h4, s4);
        let d4 = mul(h0, r4) + mul(h1, r3) + mul(h2, r2) + mul(h3, r1) + mul(h4, r0);

        let mut c;
        c = (d0 >> 26) as u32;
        h0 = (d0 as u32) & 0x3ff_ffff;
        let d1 = d1 + c as u64;
        c = (d1 >> 26) as u32;
        h1 = (d1 as u32) & 0x3ff_ffff;
        let d2 = d2 + c as u64;
        c = (d2 >> 26) as u32;
        h2 = (d2 as u32) & 0x3ff_ffff;
        let d3 = d3 + c as u64;
        c = (d3 >> 26) as u32;
        h3 = (d3 as u32) & 0x3ff_ffff;
        let d4 = d4 + c as u64;
        c = (d4 >> 26) as u32;
        h4 = (d4 as u32) & 0x3ff_ffff;
        h0 += c.wrapping_mul(5);
        c = h0 >> 26;
        h0 &= 0x3ff_ffff;
        h1 += c;

        self.h = [h0, h1, h2, h3, h4];
    }

    /// Finalize, folding in the 16-byte `s` key half; returns the 16-byte tag.
    pub fn finalize(mut self, s: &[u8; 16]) -> [u8; 16] {
        if self.leftover > 0 {
            self.buffer[self.leftover] = 1;
            for b in self.buffer[self.leftover + 1..].iter_mut() {
                *b = 0;
            }
            let block = self.buffer;
            self.block(&block, true);
        }

        let [mut h0, mut h1, mut h2, mut h3, mut h4] = self.h;

        // Fully carry h.
        let mut c = h1 >> 26;
        h1 &= 0x3ff_ffff;
        h2 += c;
        c = h2 >> 26;
        h2 &= 0x3ff_ffff;
        h3 += c;
        c = h3 >> 26;
        h3 &= 0x3ff_ffff;
        h4 += c;
        c = h4 >> 26;
        h4 &= 0x3ff_ffff;
        h0 += c.wrapping_mul(5);
        c = h0 >> 26;
        h0 &= 0x3ff_ffff;
        h1 += c;

        // Compute h + -p.
        let mut g0 = h0.wrapping_add(5);
        c = g0 >> 26;
        g0 &= 0x3ff_ffff;
        let mut g1 = h1.wrapping_add(c);
        c = g1 >> 26;
        g1 &= 0x3ff_ffff;
        let mut g2 = h2.wrapping_add(c);
        c = g2 >> 26;
        g2 &= 0x3ff_ffff;
        let mut g3 = h3.wrapping_add(c);
        c = g3 >> 26;
        g3 &= 0x3ff_ffff;
        let g4 = h4.wrapping_add(c).wrapping_sub(1 << 26);

        // Select h if h < p (g4 borrow), else g — branch-free.
        let mask = (g4 >> 31).wrapping_sub(1);
        g0 &= mask;
        g1 &= mask;
        g2 &= mask;
        g3 &= mask;
        let g4m = g4 & mask;
        let nmask = !mask;
        h0 = (h0 & nmask) | g0;
        h1 = (h1 & nmask) | g1;
        h2 = (h2 & nmask) | g2;
        h3 = (h3 & nmask) | g3;
        h4 = (h4 & nmask) | g4m;

        // Collapse to 4×32-bit little-endian words (each expression already fits
        // in 32 bits after the shifts).
        let h0f = h0 | (h1 << 26);
        let h1f = (h1 >> 6) | (h2 << 20);
        let h2f = (h2 >> 12) | (h3 << 14);
        let h3f = (h3 >> 18) | (h4 << 8);

        // mac = (h + s) mod 2^128.
        let mut f = h0f as u64 + u8to32(&s[0..]) as u64;
        let w0 = f as u32;
        f = h1f as u64 + u8to32(&s[4..]) as u64 + (f >> 32);
        let w1 = f as u32;
        f = h2f as u64 + u8to32(&s[8..]) as u64 + (f >> 32);
        let w2 = f as u32;
        f = h3f as u64 + u8to32(&s[12..]) as u64 + (f >> 32);
        let w3 = f as u32;

        let mut tag = [0u8; 16];
        tag[0..4].copy_from_slice(&w0.to_le_bytes());
        tag[4..8].copy_from_slice(&w1.to_le_bytes());
        tag[8..12].copy_from_slice(&w2.to_le_bytes());
        tag[12..16].copy_from_slice(&w3.to_le_bytes());
        tag
    }
}

/// Poly1305 one-shot MAC over `msg` with a 32-byte one-time key.
pub fn poly1305_mac(msg: &[u8], key: &[u8; 32]) -> [u8; 16] {
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
    (poly_key, *nonce)
}

fn chacha_poly_seal(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> Tag<16> {
    let (poly_key, cipher_nonce) = chacha_poly_setup(key, nonce);
    // ciphertext = ChaCha20 with counter starting at 1
    let mut ctr = ChaCha20::new(key, &cipher_nonce);
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
    let mut ctr = ChaCha20::new(key, &cipher_nonce);
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
    len_block[..8].copy_from_slice(&(aad.len() as u64).to_le_bytes());
    len_block[8..].copy_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    mac.update(&len_block);
    mac.finalize(&s)
}

#[inline]
fn pad_len(len: usize) -> usize {
    (16 - (len % 16)) % 16
}

impl Aead<12, 16> for ChaCha20Poly1305 {
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

impl Aead<24, 16> for XChaCha20Poly1305 {
    fn encrypt_in_place_detached(&self, nonce: &Nonce<24>, aad: &[u8], buf: &mut [u8]) -> Tag<16> {
        // Derive subkey via HChaCha20 on the first 16 bytes of the 24-byte nonce.
        let mut subkey = [0u8; 32];
        let mut nonce16 = [0u8; 16];
        nonce16.copy_from_slice(&nonce.0[..16]);
        subkey.copy_from_slice(&hchacha20(&self.key, &nonce16));
        let mut inner_nonce = [0u8; 12];
        inner_nonce[4..12].copy_from_slice(&nonce.0[16..]);
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
        inner_nonce[4..12].copy_from_slice(&nonce.0[16..]);
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
        let nonce = hex::decode("000000090000004a00000000").unwrap();
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
        assert_eq!(&block[..], &expected[..], "got: {:02x?}", &block[..]);
    }

    #[test]
    fn chacha20_rfc8439_stream() {
        // RFC 8439 §2.4.2: encrypt the sunscreen plaintext with initial counter 1.
        let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
            .unwrap();
        let nonce = hex::decode("000000000000004a00000000").unwrap();
        let key: [u8; 32] = key.try_into().unwrap();
        let nonce: [u8; 12] = nonce.try_into().unwrap();
        let mut buf = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut c = ChaCha20::new(&key, &nonce);
        c.counter = 1;
        c.apply_keystream(&mut buf);
        let expected = hex::decode(
            "6e2e359a2568f98041ba0728dd0d6981\
             e97e7aec1d4360c20a27afccfd9fae0b\
             f91b65c5524733ab8f593dabcd62b357\
             1639d624e65152ab8f530c359f0861d8\
             07ca0dbf500d6a6156a38e088a22b65e\
             52bc514d16ccf806818ce91ab7793736\
             5af90bbf74a35be6b40b8eedf2785e42\
             874d",
        )
        .unwrap();
        assert_eq!(&buf[..], &expected[..]);
    }

    #[test]
    fn poly1305_rfc8439() {
        // Degenerate case: empty message, zero key -> zero tag.
        let tag = poly1305_mac(&[], &[0u8; 32]);
        assert_eq!(tag, [0u8; 16]);

        // RFC 8439 §2.5.2 test vector.
        let key: [u8; 32] =
            hex::decode("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
                .unwrap()
                .try_into()
                .unwrap();
        let msg = b"Cryptographic Forum Research Group";
        let tag = poly1305_mac(msg, &key);
        assert_eq!(
            tag.to_vec(),
            hex::decode("a8061dc1305136c6c22b8baf0c0127a9").unwrap()
        );

        // RFC 8439 A.3 test #1: all-zero key and 64-byte all-zero message.
        let tag = poly1305_mac(&[0u8; 64], &[0u8; 32]);
        assert_eq!(tag, [0u8; 16]);

        // Feed the §2.5.2 message in awkward 7-byte chunks to exercise buffering.
        let mut mac = Poly1305::new(&key);
        for chunk in msg.chunks(7) {
            mac.update(chunk);
        }
        assert_eq!(
            mac.finalize(&key[16..32].try_into().unwrap()).to_vec(),
            hex::decode("a8061dc1305136c6c22b8baf0c0127a9").unwrap()
        );
    }
}
