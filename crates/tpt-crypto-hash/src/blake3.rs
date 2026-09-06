//! BLAKE3 (RFC draft, chunked Merkle tree, XOF). Branch-free, `no_std`.

use crate::traits::Xof;

// BLAKE3 uses the SHA-256 IV constants.
const IV: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

// Each round's schedule is the previous one under the BLAKE3 message
// permutation [2,6,3,10,7,0,4,13,1,11,12,5,9,14,15,8].
const MSG_SCHEDULE: [[usize; 16]; 7] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8],
    [3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1],
    [10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6],
    [12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4],
    [9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7],
    [11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13],
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
    for i in 0..8 {
        h[i] = u32::from_le_bytes(cv[4 * i..4 * i + 4].try_into().unwrap());
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
    v[12] = counter as u32;
    v[13] = (counter >> 32) as u32;
    v[14] = block_len;
    v[15] = flags;
    for s in &MSG_SCHEDULE {
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    let mut out = [0u8; 64];
    for i in 0..8 {
        let lo = v[i] ^ v[i + 8];
        let hi = v[i + 8] ^ h[i];
        out[4 * i..4 * i + 4].copy_from_slice(&lo.to_le_bytes());
        out[32 + 4 * i..32 + 4 * i + 4].copy_from_slice(&hi.to_le_bytes());
    }
    out
}

fn iv_bytes() -> [u8; 32] {
    let mut b = [0u8; 32];
    for i in 0..8 {
        b[4 * i..4 * i + 4].copy_from_slice(&IV[i].to_le_bytes());
    }
    b
}

/// BLAKE3 (streaming XOF). Default output is 32 bytes via [`blake3`].
#[derive(Clone)]
pub struct Blake3 {
    key: [u8; 32],
    keyed: bool,
    chunk_index: u64,
    buf: [u8; CHUNK_LEN],
    buflen: usize,
    stack: [[u8; 32]; 54],
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
        Blake3 {
            key: k,
            keyed,
            chunk_index: 0,
            buf: [0; CHUNK_LEN],
            buflen: 0,
            stack: [[0u8; 32]; 54],
            stack_len: 0,
        }
    }

    #[inline]
    fn key_words(&self) -> [u8; 32] {
        if self.keyed {
            self.key
        } else {
            iv_bytes()
        }
    }

    #[inline]
    fn base_flags(&self) -> u32 {
        if self.keyed {
            KEYED_HASH
        } else {
            0
        }
    }

    /// A deferred compression: the last block of a chunk, or a parent node.
    /// `chaining_value` produces the CV fed up the tree; `root_bytes` produces
    /// the extendable root output.
    fn output_chaining_value(&self, o: &Output) -> [u8; 32] {
        let out = compress(&o.input_cv, &o.block, o.counter, o.block_len, o.flags);
        let mut cv = [0u8; 32];
        cv.copy_from_slice(&out[..32]);
        cv
    }

    fn output_root_bytes(&self, o: &Output, out: &mut [u8]) {
        let mut counter = 0u64;
        let mut written = 0;
        while written < out.len() {
            let block = compress(&o.input_cv, &o.block, counter, o.block_len, o.flags | ROOT);
            let take = (out.len() - written).min(64);
            out[written..written + take].copy_from_slice(&block[..take]);
            written += take;
            counter += 1;
        }
    }

    fn parent_output(&self, left: &[u8; 32], right: &[u8; 32]) -> Output {
        let mut block = [0u8; 64];
        block[..32].copy_from_slice(left);
        block[32..].copy_from_slice(right);
        Output {
            input_cv: self.key_words(),
            block,
            counter: 0,
            block_len: 64,
            flags: PARENT | self.base_flags(),
        }
    }

    fn push_chunk_cv(&mut self, mut cv: [u8; 32], chunk_index: u64) {
        // Merge as many completed subtrees as there are trailing zero bits in
        // the post-increment chunk count.
        let mut total = chunk_index + 1;
        while total & 1 == 0 {
            let left = self.stack[self.stack_len - 1];
            let po = self.parent_output(&left, &cv);
            cv = self.output_chaining_value(&po);
            self.stack_len -= 1;
            total >>= 1;
        }
        self.stack[self.stack_len] = cv;
        self.stack_len += 1;
    }

    /// Compress a full 1024-byte chunk into a chaining value and add it to the
    /// tree. Never used for the final chunk (which becomes an [`Output`]).
    fn compress_chunk(&mut self, chunk: &[u8; CHUNK_LEN]) {
        let mut cv = self.key_words();
        for bi in 0..16 {
            let blk = chunk[64 * bi..64 * bi + 64].try_into().unwrap();
            let mut flags = self.base_flags();
            if bi == 0 {
                flags |= CHUNK_START;
            }
            if bi == 15 {
                flags |= CHUNK_END;
            }
            let out = compress(&cv, &blk, self.chunk_index, 64, flags);
            cv.copy_from_slice(&out[..32]);
        }
        let idx = self.chunk_index;
        self.push_chunk_cv(cv, idx);
        self.chunk_index += 1;
    }

    /// Build the [`Output`] for the final (buffered) chunk.
    fn final_chunk_output(&self) -> Output {
        let len = self.buflen;
        let nblocks = if len <= 64 { 1 } else { len.div_ceil(64) };
        let mut cv = self.key_words();
        for bi in 0..nblocks - 1 {
            let blk: &[u8; 64] = self.buf[64 * bi..64 * bi + 64].try_into().unwrap();
            let mut flags = self.base_flags();
            if bi == 0 {
                flags |= CHUNK_START;
            }
            let out = compress(&cv, blk, self.chunk_index, 64, flags);
            cv.copy_from_slice(&out[..32]);
        }
        let bi = nblocks - 1;
        let start = 64 * bi;
        let end = len.max(start); // 0-length chunk => start == end == 0
        let mut block = [0u8; 64];
        block[..end - start].copy_from_slice(&self.buf[start..end]);
        let mut flags = self.base_flags() | CHUNK_END;
        if bi == 0 {
            flags |= CHUNK_START;
        }
        Output {
            input_cv: cv,
            block,
            counter: self.chunk_index,
            block_len: (end - start) as u32,
            flags,
        }
    }

    fn root_output(&self) -> Output {
        let mut output = self.final_chunk_output();
        if self.stack_len == 0 {
            return output;
        }
        let mut cv = self.output_chaining_value(&output);
        let mut i = self.stack_len;
        while i > 0 {
            i -= 1;
            output = self.parent_output(&self.stack[i], &cv);
            if i > 0 {
                cv = self.output_chaining_value(&output);
            }
        }
        output
    }
}

/// A deferred BLAKE3 compression (final chunk block or parent node).
#[derive(Clone)]
struct Output {
    input_cv: [u8; 32],
    block: [u8; 64],
    counter: u64,
    block_len: u32,
    flags: u32,
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
        // The final chunk must be turned into an `Output` at finalization, so
        // the buffer is only flushed once we know more input follows.
        if self.buflen > 0 && data.len() > CHUNK_LEN - self.buflen {
            let need = CHUNK_LEN - self.buflen;
            self.buf[self.buflen..].copy_from_slice(&data[..need]);
            data = &data[need..];
            let c = self.buf;
            self.compress_chunk(&c);
            self.buflen = 0;
        }
        while data.len() > CHUNK_LEN {
            let c: &[u8; CHUNK_LEN] = data[..CHUNK_LEN].try_into().unwrap();
            self.compress_chunk(c);
            data = &data[CHUNK_LEN..];
        }
        if !data.is_empty() {
            self.buf[self.buflen..self.buflen + data.len()].copy_from_slice(data);
            self.buflen += data.len();
        }
    }

    fn finalize_xof_reset(&mut self, out: &mut [u8]) {
        let root = self.root_output();
        self.output_root_bytes(&root, out);
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
