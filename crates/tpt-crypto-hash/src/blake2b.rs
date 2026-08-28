//! BLAKE2b (RFC 7693), including keyed mode. Branch-free, `no_std`.

use crate::traits::Hasher;

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

#[inline]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// BLAKE2b with a compile-time output length `OUT` (1..=64).
#[derive(Clone)]
pub struct Blake2b<const OUT: usize> {
    h: [u64; 8],
    buf: [u8; 128],
    buflen: usize,
    t: u128,
}

impl<const OUT: usize> Blake2b<OUT> {
    /// Create a new (unkeyed) BLAKE2b hasher.
    #[inline]
    pub fn new() -> Self {
        Self::with_key(&[])
    }

    /// Create a keyed BLAKE2b hasher. `key` must be 0..=64 bytes.
    #[must_use]
    pub fn with_key(key: &[u8]) -> Self {
        debug_assert!(OUT >= 1 && OUT <= 64);
        debug_assert!(key.len() <= 64);
        let mut p = [0u8; 64];
        p[0] = OUT as u8;
        p[1] = key.len() as u8;
        p[2] = 1;
        p[3] = 1;
        let mut h = [0u64; 8];
        for i in 0..8 {
            h[i] = IV[i] ^ u64::from_le_bytes(p[8 * i..8 * i + 8].try_into().unwrap());
        }
        let mut b = Blake2b {
            h,
            buf: [0; 128],
            buflen: 0,
            t: 0,
        };
        if !key.is_empty() {
            let mut kb = [0u8; 128];
            kb[..key.len()].copy_from_slice(key);
            b.compress(&kb, false);
            b.t = b.t.wrapping_add(128);
        }
        b
    }

    fn compress(&mut self, block: &[u8; 128], last: bool) {
        let mut m = [0u64; 16];
        for i in 0..16 {
            m[i] = u64::from_le_bytes(block[8 * i..8 * i + 8].try_into().unwrap());
        }
        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&self.h);
        v[8] = IV[0] ^ (self.t as u64);
        v[9] = IV[1] ^ (self.t >> 64) as u64;
        v[10] = IV[2];
        v[11] = IV[3];
        v[12] = IV[4] ^ if last { 0xffff_ffff_ffff_ffff } else { 0 };
        v[13] = IV[5];
        v[14] = IV[6];
        v[15] = IV[7];
        for r in 0..12 {
            let s = &SIGMA[r];
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }

    fn finalize_to(&mut self, out: &mut [u8; OUT]) {
        let mut block = [0u8; 128];
        block[..self.buflen].copy_from_slice(&self.buf[..self.buflen]);
        self.t = self.t.wrapping_add(self.buflen as u128);
        self.compress(&block, true);
        for i in 0..OUT {
            out[i] = (self.h[i / 8] >> (8 * (i % 8))) as u8;
        }
    }
}

impl<const OUT: usize> Default for Blake2b<OUT> {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl<const OUT: usize> Hasher<OUT> for Blake2b<OUT> {
    const OUTPUT_SIZE: usize = OUT;

    #[inline]
    fn update(&mut self, data: &[u8]) {
        let mut data = data;
        if self.buflen > 0 {
            let need = 128 - self.buflen;
            let take = need.min(data.len());
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
            self.buflen += take;
            data = &data[take..];
            if self.buflen == 128 {
                let b = self.buf;
                self.compress(&b, false);
                self.t = self.t.wrapping_add(128);
                self.buflen = 0;
            }
        }
        while data.len() >= 128 {
            let mut b = [0u8; 128];
            b.copy_from_slice(&data[..128]);
            self.compress(&b, false);
            self.t = self.t.wrapping_add(128);
            data = &data[128..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buflen = data.len();
        }
    }

    fn finalize_reset(&mut self) -> [u8; OUT] {
        let mut out = [0u8; OUT];
        self.finalize_to(&mut out);
        self.h = [0u64; 8];
        let mut p = [0u8; 64];
        p[0] = OUT as u8;
        p[2] = 1;
        p[3] = 1;
        for i in 0..8 {
            self.h[i] = IV[i] ^ u64::from_le_bytes(p[8 * i..8 * i + 8].try_into().unwrap());
        }
        self.buf = [0; 128];
        self.buflen = 0;
        self.t = 0;
        out
    }

    #[inline]
    fn finalize(self) -> [u8; OUT] {
        self.clone().finalize_reset()
    }

    fn reset(&mut self) {
        *self = Self::new();
    }
}

/// One-shot unkeyed BLAKE2b with default 64-byte output.
#[inline]
#[must_use]
pub fn blake2b(data: &[u8]) -> [u8; 64] {
    let mut h = Blake2b::<64>::new();
    h.update(data);
    h.finalize()
}

/// One-shot keyed BLAKE2b with default 64-byte output.
#[inline]
#[must_use]
pub fn blake2b_keyed(data: &[u8], key: &[u8]) -> [u8; 64] {
    let mut h = Blake2b::<64>::with_key(key);
    h.update(data);
    h.finalize()
}
