//! KangarooTwelve (K12) over Keccak-p[1600, 12] / TurboSHAKE128. `no_std`.
//!
//! `KangarooTwelve(M, C, L)` builds `S = M || C || right_encode(|C|)` and:
//! - if `|S| <= 8192`: returns `TurboSHAKE128(S, 0x07, L)`;
//! - else builds a Sakura tree: `FinalNode = S0 || 03 00*7 || CV1.. || CV_{n-1}
//!   || right_encode(n-1) || FF FF`, then `TurboSHAKE128(FinalNode, 0x06, L)`,
//!   where each `CV_i = TurboSHAKE128(S_i, 0x0B, 32)`.

use crate::traits::Xof;

const RC12: [u64; 12] = [
    0x0000_0000_8080_008b,
    0x8000_0000_0000_008b,
    0x8000_0000_0000_8089,
    0x8000_0000_0000_8003,
    0x8000_0000_0000_8002,
    0x8000_0000_0000_0080,
    0x0000_0000_0000_800a,
    0x8000_0000_0080_000a,
    0x8000_0000_8000_8081,
    0x8000_0000_0000_8080,
    0x0000_0000_8000_0001,
    0x8000_0000_8000_8008,
];

const ROTC: [[u32; 5]; 5] = [
    [0, 1, 62, 28, 27],
    [36, 44, 6, 55, 20],
    [3, 10, 43, 25, 39],
    [41, 45, 15, 21, 8],
    [18, 2, 61, 56, 14],
];

#[inline]
fn keccak_p12(a: &mut [u64; 25]) {
    for round in 0..12 {
        let mut c = [0u64; 5];
        for x in 0..5 {
            c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20];
        }
        let mut d = [0u64; 5];
        for x in 0..5 {
            d[x] = c[(x + 4) % 5] ^ c[(x + 1) % 5].rotate_left(1);
        }
        for x in 0..5 {
            for y in 0..5 {
                a[x + 5 * y] ^= d[x];
            }
        }
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                let rot = ROTC[y][x];
                let nx = (2 * x + 3 * y) % 5;
                let ny = x;
                b[nx + 5 * ny] = a[x + 5 * y].rotate_left(rot);
            }
        }
        for x in 0..5 {
            for y in 0..5 {
                let idx = x + 5 * y;
                let b1 = b[((x + 1) % 5) + 5 * y];
                let b2 = b[((x + 2) % 5) + 5 * y];
                a[idx] = b[idx] ^ ((!b1) & b2);
            }
        }
        a[0] ^= RC12[round];
    }
}

/// A TurboSHAKE128 sponge (Keccak-p[1600, 12], rate 168, capacity 32).
struct TurboShake {
    state: [u8; 200],
    buflen: usize,
}

impl TurboShake {
    fn new() -> Self {
        TurboShake {
            state: [0; 200],
            buflen: 0,
        }
    }

    fn absorb(&mut self, mut data: &[u8]) {
        let rate = 168;
        if self.buflen > 0 {
            let need = rate - self.buflen;
            let take = need.min(data.len());
            self.state[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
            self.buflen += take;
            data = &data[take..];
            if self.buflen == rate {
                permute(&mut self.state);
                self.buflen = 0;
            }
        }
        while data.len() >= rate {
            for k in 0..(rate / 8) {
                let lane = u64::from_le_bytes(data[8 * k..8 * k + 8].try_into().unwrap());
                let cur = u64::from_le_bytes(self.state[8 * k..8 * k + 8].try_into().unwrap());
                self.state[8 * k..8 * k + 8].copy_from_slice(&(cur ^ lane).to_le_bytes());
            }
            permute(&mut self.state);
            data = &data[rate..];
        }
        if !data.is_empty() {
            self.state[..data.len()].copy_from_slice(data);
            self.buflen = data.len();
        }
    }

    fn finalize(&mut self, suffix: u8, out: &mut [u8]) {
        let rate = 168;
        self.state[self.buflen] ^= suffix;
        if (suffix & 0x80) != 0 && self.buflen == rate - 1 {
            permute(&mut self.state);
        }
        self.state[rate - 1] ^= 0x80;
        permute(&mut self.state);
        let mut produced = 0;
        while produced < out.len() {
            let take = (out.len() - produced).min(rate);
            out[produced..produced + take].copy_from_slice(&self.state[..take]);
            produced += take;
            if produced < out.len() {
                permute(&mut self.state);
            }
        }
    }
}

#[inline]
fn permute(state: &mut [u8; 200]) {
    let mut a = [0u64; 25];
    for k in 0..25 {
        a[k] = u64::from_le_bytes(state[8 * k..8 * k + 8].try_into().unwrap());
    }
    keccak_p12(&mut a);
    for k in 0..25 {
        state[8 * k..8 * k + 8].copy_from_slice(&a[k].to_le_bytes());
    }
}

fn right_encode(mut value: usize) -> (usize, [u8; 9]) {
    let mut dst = [0u8; 9];
    let mut n = 0;
    if value == 0 {
        dst[0] = 0;
        n = 1;
    } else {
        while value != 0 {
            dst[n] = (value & 0xff) as u8;
            value >>= 8;
            n += 1;
        }
        for i in 0..n / 2 {
            dst.swap(i, n - 1 - i);
        }
    }
    dst[n] = n as u8;
    n += 1;
    (n, dst)
}

struct SFeeder<'a> {
    m: &'a [u8],
    c: &'a [u8],
    right: &'a [u8],
    pos: usize,
    total: usize,
}

impl<'a> SFeeder<'a> {
    fn fill(&mut self, buf: &mut [u8]) -> usize {
        let mut n = 0;
        while n < buf.len() && self.pos < self.total {
            let (src, idx) = if self.pos < self.m.len() {
                (self.m, self.pos)
            } else if self.pos < self.m.len() + self.c.len() {
                (self.c, self.pos - self.m.len())
            } else {
                (self.right, self.pos - self.m.len() - self.c.len())
            };
            buf[n] = src[idx];
            n += 1;
            self.pos += 1;
        }
        n
    }
}

const CHUNK: usize = 8192;

/// KangarooTwelve one-shot XOF. `c` is the customization string.
pub fn kangaroo_twelve(m: &[u8], c: &[u8], out: &mut [u8]) {
    let (clen, right_arr) = right_encode(c.len());
    let right = &right_arr[..clen];
    let total = m.len() + c.len() + clen;

    if total <= CHUNK {
        let mut ts = TurboShake::new();
        let mut feeder = SFeeder {
            m,
            c,
            right,
            pos: 0,
            total,
        };
        let mut buf = [0u8; CHUNK];
        let got = feeder.fill(&mut buf);
        ts.absorb(&buf[..got]);
        ts.finalize(0x07, out);
        return;
    }

    let mut finals = TurboShake::new();
    let mut feeder = SFeeder {
        m,
        c,
        right,
        pos: 0,
        total,
    };
    let mut buf = [0u8; CHUNK];
    let s0 = feeder.fill(&mut buf[..CHUNK]);
    finals.absorb(&buf[..s0]);
    finals.absorb(&[0x03, 0, 0, 0, 0, 0, 0, 0]);

    let mut num_block = 0usize;
    let mut block = [0u8; CHUNK];
    loop {
        let g = feeder.fill(&mut block);
        if g == 0 {
            break;
        }
        let mut cv_ts = TurboShake::new();
        cv_ts.absorb(&block[..g]);
        let mut cv = [0u8; 32];
        cv_ts.finalize(0x0B, &mut cv);
        finals.absorb(&cv);
        num_block += 1;
    }
    let (elen, ebytes) = right_encode(num_block);
    finals.absorb(&ebytes[..elen]);
    finals.absorb(&[0xFF, 0xFF]);
    finals.finalize(0x06, out);
}

/// Streaming KangarooTwelve XOF. The customization string is fixed at
/// construction; message bytes are fed via [`Xof::update`].
#[cfg(feature = "alloc")]
pub struct KangarooTwelve {
    m: alloc::vec::Vec<u8>,
    c: alloc::vec::Vec<u8>,
}

#[cfg(feature = "alloc")]
impl KangarooTwelve {
    /// Create a K12 XOF with customization string `c`.
    #[inline]
    pub fn new(c: &[u8]) -> Self {
        KangarooTwelve {
            m: alloc::vec::Vec::new(),
            c: c.to_vec(),
        }
    }
}

#[cfg(feature = "alloc")]
impl Xof for KangarooTwelve {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.m.extend_from_slice(data);
    }

    fn finalize_xof_reset(&mut self, out: &mut [u8]) {
        kangaroo_twelve(&self.m, &self.c, out);
        self.m.clear();
    }

    #[inline]
    fn finalize_xof(self, out: &mut [u8]) {
        kangaroo_twelve(&self.m, &self.c, out);
    }

    fn reset(&mut self) {
        self.m.clear();
    }
}
