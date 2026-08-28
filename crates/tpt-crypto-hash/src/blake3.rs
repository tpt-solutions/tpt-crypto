//! BLAKE3 (RFC draft, chunked Merkle tree, XOF). Branch-free, `no_std`.

use crate::traits::Xof;

// BLAKE3 uses the SHA-256 IV constants.
const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab,
    0x5be0cd19,
];

const MSG_SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 12, 5, 13, 14, 10, 15, 6, 11, 8, 2, 0, 1, 9, 4, 7],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 13, 14, 0, 11, 8, 10, 1, 9, 4, 5, 6, 2, 15, 3, 12],
    [9, 11, 1, 3, 8, 13, 5, 6, 4, 2, 15, 12, 0, 14, 7, 10],
];

const CHUNK_START: u32 = 1;
const CHUNK_END: u32 = 2;
const PARENT: u32 = 4;
const ROOT: u32 = 8;
const KEYED_HASH: u32 = 16;

const CHUNK_LEN: usize = 1024;

#[inline]
fn g(v: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize, mx: u32, my: u32) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(mx);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(12);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(my);
    v[d] = (v[d] ^ v[a]).rotate_right(8);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(7);
}

/// BLAKE3 compression function. Returns the full 64-byte output block.
#[inline]
fn compress(cv: &[u8; 32], block: &[u8; 64], counter: u64, block_len: u32, flags: u32) -> [u8; 64] {
    let mut h = [0u32; 8];
    for i in 0..4 {
        h[i] = u32::from_le_bytes(cv[4 * i..4 * i + 4].try_into().unwrap());
    }
    for i in 4..8 {
        h[i] = IV[i];
    }
    let mut m = [0u32; 16];
    for i in 0..16 {
        m[i] = u32::from_le_bytes(block[4 * i..4 * i + 4].try_into().unwrap());
    }
    let mut v = [0u32; 16];
    v[..8].copy_from_slice(&h);
    v[8] = IV[0];
    v[9] = IV[1];
    v[10] = IV[2];
    v[11] = IV[3];
    v[12] = (counter as u32) ^ IV[4];
    v[13] = ((counter >> 32) as u32) ^ IV[5];
    v[14] = block_len ^ IV[6];
    v[15] = flags ^ IV[7];
    for r in 0..7 {
        let s = &MSG_SCHEDULE[r];
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
        h[i] ^= v[i] ^ v[i + 8];
    }
    let mut out = [0u8; 64];
    for i in 0..8 {
        out[4 * i..4 * i + 4].copy_from_slice(&h[i].to_le_bytes());
    }
    for i in 8..16 {
        out[4 * i..4 * i + 4].copy_from_slice(&v[i].to_le_bytes());
    }
    out
}

fn iv_first_four() -> [u8; 32] {
    let mut b = [0u8; 32];
    for i in 0..4 {
        b[4 * i..4 * i + 4].copy_from_slice(&IV[i].to_le_bytes());
    }
    b
}

/// BLAKE3 (streaming XOF). Default output is 32 bytes via [`blake3`].
#[derive(Clone)]
pub struct Blake3 {
    key: [u8; 32],
    keyed: bool,
    cv: [u8; 32],
    chunk_index: u64,
    buf: [u8; CHUNK_LEN],
    buflen: usize,
    stack: [[u8; 32]; 32],
    stack_len: usize,
}

impl Blake3 {
    /// New (unkeyed) BLAKE3 hasher.
    #[inline]
    pub fn new() -> Self {
        Self::with_key(&[])
    }

    /// New keyed BLAKE3 hasher (32-byte key).
    #[must_use]
    pub fn with_key(key: &[u8]) -> Self {
        let keyed = key.len() == 32;
        let mut k = [0u8; 32];
        if keyed {
            k.copy_from_slice(key);
        }
        let start_cv = if keyed { k } else { iv_first_four() };
        Blake3 {
            key: k,
            keyed,
            cv: start_cv,
            chunk_index: 0,
            buf: [0; CHUNK_LEN],
            buflen: 0,
            stack: [[0u8; 32]; 32],
            stack_len: 0,
        }
    }

    #[inline]
    fn parent_cv(&self, left: &[u8; 32], right: &[u8; 32], counter: u64, flags: u32) -> [u8; 32] {
        let mut block = [0u8; 64];
        block[..32].copy_from_slice(left);
        block[32..].copy_from_slice(right);
        let out = compress(&iv_first_four(), &block, counter, 64, flags);
        let mut cv = [0u8; 32];
        cv.copy_from_slice(&out[..32]);
        cv
    }

    fn push_chunk_cv(&mut self, cv: [u8; 32]) {
        self.stack[self.stack_len] = cv;
        self.stack_len += 1;
        let mut idx = self.chunk_index;
        while (idx & 1) == 1 {
            let right = self.stack[self.stack_len - 1];
            let left = self.stack[self.stack_len - 2];
            let parent = self.parent_cv(&left, &right, idx >> 1, PARENT);
            self.stack_len -= 2;
            self.stack[self.stack_len] = parent;
            self.stack_len += 1;
            idx >>= 1;
        }
        self.chunk_index += 1;
    }

    fn compress_chunk(&mut self, chunk: &[u8; CHUNK_LEN]) {
        for bi in 0..16 {
            let blk = chunk[64 * bi..64 * bi + 64].try_into().unwrap();
            let mut flags = 0u32;
            if bi == 0 {
                flags |= CHUNK_START;
            }
            if bi == 15 {
                flags |= CHUNK_END;
            }
            if self.keyed && self.chunk_index == 0 {
                flags |= KEYED_HASH;
            }
            let out = compress(&self.cv, &blk, self.chunk_index, 64, flags);
            self.cv.copy_from_slice(&out[..32]);
        }
        let cv = self.cv;
        self.push_chunk_cv(cv);
        self.cv = if self.keyed { self.key } else { iv_first_four() };
    }

    fn root_cv(&self) -> [u8; 32] {
        if self.stack_len == 0 {
            // No chunks: the (empty) chunk is the root.
            let mut block = [0u8; 64];
            let mut flags = CHUNK_START | CHUNK_END | ROOT;
            if self.keyed {
                flags |= KEYED_HASH;
            }
            let out = compress(&self.cv, &block, 0, 0, flags);
            let mut cv = [0u8; 32];
            cv.copy_from_slice(&out[..32]);
            return cv;
        }
        let mut cv = self.stack[0];
        for i in 1..self.stack_len {
            let is_root = (i == self.stack_len - 1);
            let mut flags = PARENT;
            if is_root {
                flags |= ROOT;
            }
            cv = self.parent_cv(&cv, &self.stack[i], i as u64, flags);
        }
        cv
    }

    fn squeeze(&mut self, root_cv: [u8; 32], out: &mut [u8]) {
        let mut counter = 0u64;
        let mut written = 0;
        while written < out.len() {
            let block = compress(&root_cv, &[0u8; 64], counter, 64, ROOT);
            let take = (out.len() - written).min(64);
            out[written..written + take].copy_from_slice(&block[..take]);
            written += take;
            counter += 1;
        }
    }
}

impl Default for Blake3 {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

impl Xof for Blake3 {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        let mut data = data;
        if self.buflen > 0 {
            let need = CHUNK_LEN - self.buflen;
            let take = need.min(data.len());
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
            self.buflen += take;
            data = &data[take..];
            if self.buflen == CHUNK_LEN {
                let c = self.buf;
                self.compress_chunk(&c);
                self.buflen = 0;
            }
        }
        while data.len() >= CHUNK_LEN {
            let c: &[u8; CHUNK_LEN] = data[..CHUNK_LEN].try_into().unwrap();
            self.compress_chunk(c);
            data = &data[CHUNK_LEN..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buflen = data.len();
        }
    }

    fn finalize_xof_reset(&mut self, out: &mut [u8]) {
        let mut chunk = [0u8; CHUNK_LEN];
        chunk[..self.buflen].copy_from_slice(&self.buf[..self.buflen]);
        let nblocks = if self.buflen == 0 { 1 } else { (self.buflen + 63) / 64 };
        let is_root = self.stack_len == 0 && self.chunk_index == 0;
        for bi in 0..nblocks {
            let start = 64 * bi;
            let end = (start + 64).min(self.buflen);
            let mut blk = [0u8; 64];
            blk[..end - start].copy_from_slice(&chunk[start..end]);
            let block_len = (end - start) as u32;
            let mut flags = 0u32;
            if bi == 0 {
                flags |= CHUNK_START;
            }
            if bi == nblocks - 1 {
                flags |= CHUNK_END;
            }
            if is_root {
                flags |= ROOT;
            }
            if self.keyed && self.chunk_index == 0 {
                flags |= KEYED_HASH;
            }
            let c = self.cv;
            let out_c = compress(&c, &blk, self.chunk_index, block_len, flags);
            self.cv.copy_from_slice(&out_c[..32]);
        }
        if self.buflen > 0 || is_root {
            let cv = self.cv;
            self.push_chunk_cv(cv);
        }
        let root = self.root_cv();
        self.squeeze(root, out);
        // reset
        *self = Self::with_key(if self.keyed { &self.key } else { &[] });
    }

    #[inline]
    fn finalize_xof(self, out: &mut [u8]) {
        self.clone().finalize_xof_reset(out);
    }

    fn reset(&mut self) {
        *self = Self::with_key(if self.keyed { &self.key } else { &[] });
    }
}

/// One-shot BLAKE3, 32-byte output.
#[inline]
#[must_use]
pub fn blake3(data: &[u8]) -> [u8; 32] {
    let mut h = Blake3::new();
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize_xof(&mut out);
    out
}

/// One-shot keyed BLAKE3 (32-byte key), 32-byte output.
#[inline]
#[must_use]
pub fn blake3_keyed(data: &[u8], key: &[u8]) -> [u8; 32] {
    let mut h = Blake3::with_key(key);
    h.update(data);
    let mut out = [0u8; 32];
    h.finalize_xof(&mut out);
    out
}
