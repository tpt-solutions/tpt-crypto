//! Merkle–Damgård SHA-2: SHA-224, SHA-256, SHA-384, SHA-512, SHA-512/256,
//! SHA-512/224. Branch-free, `no_std`.

use crate::traits::Hasher;

const K32: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

const K64: [u64; 80] = [
    0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
    0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
    0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
    0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
    0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
    0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
    0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
    0xc6e00bf33da88fc2, 0xd5a79147c28c9f3a, 0x06ca6351e003826f, 0x142929670a0e6e70,
    0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
    0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
    0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
    0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
    0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
    0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
    0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
    0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
    0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
    0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
    0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
    0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
];

// SHA-256 / SHA-224 initial vectors.
const IV_SHA256: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];
const IV_SHA224: [u32; 8] = [
    0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939, 0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
];

// SHA-512 / SHA-384 / SHA-512/256 / SHA-512/224 initial vectors.
const IV_SHA512: [u64; 8] = [
    0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
    0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
];
const IV_SHA384: [u64; 8] = [
    0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
    0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
];
const IV_SHA512_256: [u64; 8] = [
    0xcbbb9d5dc1059ed3, 0x1ec20b20216f029e, 0x99cb56d75b315d8e, 0x00ea509ffab89354,
    0xf4abf75f7bcd8874, 0x3ea0cd298e9bc9ba, 0xba267c0e5ee418ce, 0xfe4568bcb6db84dc,
];

#[inline]
fn compress32(state: &mut [u32; 8], block: &[u8; 64]) {
    let mut w = [0u32; 64];
    for (i, c) in w.iter_mut().take(16).enumerate() {
        *c = u32::from_be_bytes([
            block[4 * i],
            block[4 * i + 1],
            block[4 * i + 2],
            block[4 * i + 3],
        ]);
    }
    for i in 16..64 {
        let s0 = w[i - 15].rotate_right(7) ^ w[i - 15].rotate_right(18) ^ (w[i - 15] >> 3);
        let s1 = w[i - 2].rotate_right(17) ^ w[i - 2].rotate_right(19) ^ (w[i - 2] >> 10);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];
    for i in 0..64 {
        let big_s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(big_s1)
            .wrapping_add(ch)
            .wrapping_add(K32[i])
            .wrapping_add(w[i]);
        let big_s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = big_s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[inline]
fn compress64(state: &mut [u64; 8], block: &[u8; 128]) {
    let mut w = [0u64; 80];
    for (i, c) in w.iter_mut().take(16).enumerate() {
        *c = u64::from_be_bytes([
            block[8 * i],
            block[8 * i + 1],
            block[8 * i + 2],
            block[8 * i + 3],
            block[8 * i + 4],
            block[8 * i + 5],
            block[8 * i + 6],
            block[8 * i + 7],
        ]);
    }
    for i in 16..80 {
        let s0 = w[i - 15].rotate_right(1) ^ w[i - 15].rotate_right(8) ^ (w[i - 15] >> 7);
        let s1 = w[i - 2].rotate_right(19) ^ w[i - 2].rotate_right(61) ^ (w[i - 2] >> 6);
        w[i] = w[i - 16]
            .wrapping_add(s0)
            .wrapping_add(w[i - 7])
            .wrapping_add(s1);
    }
    let mut a = state[0];
    let mut b = state[1];
    let mut c = state[2];
    let mut d = state[3];
    let mut e = state[4];
    let mut f = state[5];
    let mut g = state[6];
    let mut h = state[7];
    for i in 0..80 {
        let big_s1 = e.rotate_right(14) ^ e.rotate_right(18) ^ e.rotate_right(41);
        let ch = (e & f) ^ ((!e) & g);
        let t1 = h
            .wrapping_add(big_s1)
            .wrapping_add(ch)
            .wrapping_add(K64[i])
            .wrapping_add(w[i]);
        let big_s0 = a.rotate_right(28) ^ a.rotate_right(34) ^ a.rotate_right(39);
        let maj = (a & b) ^ (a & c) ^ (b & c);
        let t2 = big_s0.wrapping_add(maj);
        h = g;
        g = f;
        f = e;
        e = d.wrapping_add(t1);
        d = c;
        c = b;
        b = a;
        a = t1.wrapping_add(t2);
    }
    state[0] = state[0].wrapping_add(a);
    state[1] = state[1].wrapping_add(b);
    state[2] = state[2].wrapping_add(c);
    state[3] = state[3].wrapping_add(d);
    state[4] = state[4].wrapping_add(e);
    state[5] = state[5].wrapping_add(f);
    state[6] = state[6].wrapping_add(g);
    state[7] = state[7].wrapping_add(h);
}

#[derive(Clone)]
struct Engine32 {
    state: [u32; 8],
    buf: [u8; 64],
    buflen: usize,
    total: u64,
    out_len: usize,
}

impl Engine32 {
    #[inline]
    fn new(iv: [u32; 8], out_len: usize) -> Self {
        Engine32 {
            state: iv,
            buf: [0; 64],
            buflen: 0,
            total: 0,
            out_len,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.buflen > 0 {
            let need = 64 - self.buflen;
            let take = need.min(data.len());
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
            self.buflen += take;
            data = &data[take..];
            if self.buflen == 64 {
                let block: &[u8; 64] = self.buf.as_slice().try_into().unwrap();
                compress32(&mut self.state, block);
                self.buflen = 0;
            }
        }
        while data.len() >= 64 {
            let block: &[u8; 64] = data[..64].try_into().unwrap();
            compress32(&mut self.state, block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buflen = data.len();
        }
    }

    fn finalize_blocks(&mut self) -> [u8; 32] {
        let bitlen = self.total.wrapping_mul(8);
        let n = self.buflen;
        self.buf[n] = 0x80;
        if n <= 55 {
            for b in self.buf[n + 1..56].iter_mut() {
                *b = 0;
            }
            self.buf[56..64].copy_from_slice(&bitlen.to_be_bytes());
            let block: &[u8; 64] = self.buf.as_slice().try_into().unwrap();
            compress32(&mut self.state, block);
        } else {
            for b in self.buf[n + 1..64].iter_mut() {
                *b = 0;
            }
            let block: &[u8; 64] = self.buf.as_slice().try_into().unwrap();
            compress32(&mut self.state, block);
            let mut buf2 = [0u8; 64];
            buf2[56..64].copy_from_slice(&bitlen.to_be_bytes());
            let block2: &[u8; 64] = buf2.as_slice().try_into().unwrap();
            compress32(&mut self.state, block2);
        }
        let mut out = [0u8; 32];
        for i in 0..8 {
            out[4 * i..4 * i + 4].copy_from_slice(&self.state[i].to_be_bytes());
        }
        out
    }

    fn finalize_reset(&mut self) -> [u8; 32] {
        let out = self.finalize_blocks();
        self.state = if self.out_len == 28 { IV_SHA224 } else { IV_SHA256 };
        self.buf = [0; 64];
        self.buflen = 0;
        self.total = 0;
        out
    }
}

#[derive(Clone)]
struct Engine64 {
    state: [u64; 8],
    buf: [u8; 128],
    buflen: usize,
    total: u128,
    out_len: usize,
}

impl Engine64 {
    #[inline]
    fn new(iv: [u64; 8], out_len: usize) -> Self {
        Engine64 {
            state: iv,
            buf: [0; 128],
            buflen: 0,
            total: 0,
            out_len,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u128);
        if self.buflen > 0 {
            let need = 128 - self.buflen;
            let take = need.min(data.len());
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
            self.buflen += take;
            data = &data[take..];
            if self.buflen == 128 {
                let block: &[u8; 128] = self.buf.as_slice().try_into().unwrap();
                compress64(&mut self.state, block);
                self.buflen = 0;
            }
        }
        while data.len() >= 128 {
            let block: &[u8; 128] = data[..128].try_into().unwrap();
            compress64(&mut self.state, block);
            data = &data[128..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buflen = data.len();
        }
    }

    fn finalize_blocks(&mut self) -> [u8; 64] {
        let bitlen = self.total.wrapping_mul(8);
        let hi = (bitlen >> 64) as u64;
        let lo = bitlen as u64;
        let n = self.buflen;
        self.buf[n] = 0x80;
        if n <= 111 {
            for b in self.buf[n + 1..112].iter_mut() {
                *b = 0;
            }
            self.buf[112..120].copy_from_slice(&hi.to_be_bytes());
            self.buf[120..128].copy_from_slice(&lo.to_be_bytes());
            let block: &[u8; 128] = self.buf.as_slice().try_into().unwrap();
            compress64(&mut self.state, block);
        } else {
            for b in self.buf[n + 1..128].iter_mut() {
                *b = 0;
            }
            let block: &[u8; 128] = self.buf.as_slice().try_into().unwrap();
            compress64(&mut self.state, block);
            let mut buf2 = [0u8; 128];
            buf2[112..120].copy_from_slice(&hi.to_be_bytes());
            buf2[120..128].copy_from_slice(&lo.to_be_bytes());
            let block2: &[u8; 128] = buf2.as_slice().try_into().unwrap();
            compress64(&mut self.state, block2);
        }
        let mut out = [0u8; 64];
        for i in 0..8 {
            out[8 * i..8 * i + 8].copy_from_slice(&self.state[i].to_be_bytes());
        }
        out
    }

    fn finalize_reset(&mut self) -> [u8; 64] {
        let out = self.finalize_blocks();
        self.state = match self.out_len {
            48 => IV_SHA384,
            28 | 32 => IV_SHA512_256,
            _ => IV_SHA512,
        };
        self.buf = [0; 128];
        self.buflen = 0;
        self.total = 0;
        out
    }
}

macro_rules! sha2_type {
    ($name:ident, $engine_ty:ident, $iv:expr, $out:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name {
            e: $engine_ty,
        }

        impl $name {
            /// Create a new hasher in its initial state.
            #[inline]
            pub fn new() -> Self {
                $name {
                    e: $engine_ty::new($iv, $out),
                }
            }
        }

        impl Default for $name {
            #[inline]
            fn default() -> Self {
                Self::new()
            }
        }

        impl Hasher<$out> for $name {
            const OUTPUT_SIZE: usize = $out;

            #[inline]
            fn update(&mut self, data: &[u8]) {
                self.e.update(data);
            }

            fn finalize_reset(&mut self) -> [u8; $out] {
                let full = self.e.finalize_reset();
                let mut out = [0u8; $out];
                out.copy_from_slice(&full[..$out]);
                out
            }

            #[inline]
            fn finalize(self) -> [u8; $out] {
                let full = self.e.clone().finalize_reset();
                let mut out = [0u8; $out];
                out.copy_from_slice(&full[..$out]);
                out
            }

            fn reset(&mut self) {
                self.e = $engine_ty::new($iv, $out);
            }
        }
    };
}

sha2_type!(Sha224, Engine32, IV_SHA224, 28, "SHA-224 (Merkle–Damgård, 32-bit words).");
sha2_type!(Sha256, Engine32, IV_SHA256, 32, "SHA-256 (Merkle–Damgård, 32-bit words).");
sha2_type!(Sha384, Engine64, IV_SHA384, 48, "SHA-384 (Merkle–Damgård, 64-bit words).");
sha2_type!(Sha512, Engine64, IV_SHA512, 64, "SHA-512 (Merkle–Damgård, 64-bit words).");
sha2_type!(Sha512_256, Engine64, IV_SHA512_256, 32, "SHA-512/256 (truncated SHA-512, custom IV).");
sha2_type!(Sha512_224, Engine64, IV_SHA512_256, 28, "SHA-512/224 (truncated SHA-512, custom IV).");

/// One-shot SHA-224.
#[inline]
#[must_use]
pub fn sha224(data: &[u8]) -> [u8; 28] {
    let mut h = Sha224::new();
    h.update(data);
    h.finalize()
}

/// One-shot SHA-256.
#[inline]
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize()
}

/// One-shot SHA-384.
#[inline]
#[must_use]
pub fn sha384(data: &[u8]) -> [u8; 48] {
    let mut h = Sha384::new();
    h.update(data);
    h.finalize()
}

/// One-shot SHA-512.
#[inline]
#[must_use]
pub fn sha512(data: &[u8]) -> [u8; 64] {
    let mut h = Sha512::new();
    h.update(data);
    h.finalize()
}

/// One-shot SHA-512/256.
#[inline]
#[must_use]
pub fn sha512_256(data: &[u8]) -> [u8; 32] {
    let mut h = Sha512_256::new();
    h.update(data);
    h.finalize()
}

/// One-shot SHA-512/224.
#[inline]
#[must_use]
pub fn sha512_224(data: &[u8]) -> [u8; 28] {
    let mut h = Sha512_224::new();
    h.update(data);
    h.finalize()
}
