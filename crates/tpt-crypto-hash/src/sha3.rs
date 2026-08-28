//! Keccak-f[1600] sponge and its instantiations: SHA3-224/256/384/512,
//! SHAKE128/256, cSHAKE128/256, KMAC128/256. Branch-free, `no_std`.

use crate::traits::{Hasher, Xof};

// Round constants for Keccak-f[1600].
const RC: [u64; 24] = [
    0x0000000000000001,
    0x0000000000008082,
    0x800000000000808a,
    0x8000000080008000,
    0x000000000000808b,
    0x0000000080000001,
    0x8000000080008081,
    0x8000000000008009,
    0x000000000000008a,
    0x0000000000000088,
    0x0000000080008009,
    0x000000008000000a,
    0x000000008000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x000000000000800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x0000000080000001,
    0x8000000080008008,
];

// Rotation offsets `r[x][y]` (indexed `[y][x]`), per FIPS 202.
const ROTC: [[u32; 5]; 5] = [
    [0, 1, 62, 28, 27],
    [36, 44, 6, 55, 20],
    [3, 10, 43, 25, 39],
    [41, 45, 15, 21, 8],
    [18, 2, 61, 56, 14],
];

#[inline]
fn keccak_f(a: &mut [u64; 25]) {
    for round in 0..24 {
        // Theta
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
        // Rho + Pi
        let mut b = [0u64; 25];
        for x in 0..5 {
            for y in 0..5 {
                let rot = ROTC[y][x];
                let nx = (2 * x + 3 * y) % 5;
                let ny = x;
                b[nx + 5 * ny] = a[x + 5 * y].rotate_left(rot);
            }
        }
        // Chi
        for x in 0..5 {
            for y in 0..5 {
                let idx = x + 5 * y;
                let b1 = b[((x + 1) % 5) + 5 * y];
                let b2 = b[((x + 2) % 5) + 5 * y];
                a[idx] = b[idx] ^ ((!b1) & b2);
            }
        }
        // Iota
        a[0] ^= RC[round];
    }
}

/// A Keccak-f[1600] sponge parameterized by rate and padding byte.
#[derive(Clone)]
struct Keccak {
    state: [u64; 25],
    rate: usize,
    pad: u8,
    buf: [u8; 200],
    buflen: usize,
    squeeze_buf: [u8; 200],
    squeeze_pos: usize,
    prefix: [u8; 512],
    prefix_len: usize,
}

impl Keccak {
    fn new(rate: usize, pad: u8) -> Self {
        Keccak {
            state: [0; 25],
            rate,
            pad,
            buf: [0; 200],
            buflen: 0,
            squeeze_buf: [0; 200],
            squeeze_pos: rate,
            prefix: [0; 512],
            prefix_len: 0,
        }
    }

    /// Set the prefix (e.g. cSHAKE/KMAC pre-processing) and absorb it.
    fn set_prefix(&mut self, prefix: &[u8]) {
        let mut p = [0u8; 512];
        p[..prefix.len()].copy_from_slice(prefix);
        self.prefix = p;
        self.prefix_len = prefix.len();
        if prefix.len() > 0 {
            self.absorb(prefix);
        }
    }

    fn absorb(&mut self, mut data: &[u8]) {
        if self.buflen > 0 {
            let need = self.rate - self.buflen;
            let take = need.min(data.len());
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&data[..take]);
            self.buflen += take;
            data = &data[take..];
            if self.buflen == self.rate {
                self.xor_block();
                keccak_f(&mut self.state);
                self.buflen = 0;
            }
        }
        while data.len() >= self.rate {
            let block = &data[..self.rate];
            for k in 0..(self.rate / 8) {
                let lane = u64::from_le_bytes(block[8 * k..8 * k + 8].try_into().unwrap());
                self.state[k] ^= lane;
            }
            keccak_f(&mut self.state);
            data = &data[self.rate..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buflen = data.len();
        }
    }

    fn update(&mut self, data: &[u8]) {
        self.absorb(data);
    }

    fn xor_block(&mut self) {
        for k in 0..(self.rate / 8) {
            let lane = u64::from_le_bytes(self.buf[8 * k..8 * k + 8].try_into().unwrap());
            self.state[k] ^= lane;
        }
    }

    fn finish(&mut self, extra: &[u8]) {
        let mut i = 0;
        while i < extra.len() {
            if self.buflen == self.rate {
                self.xor_block();
                keccak_f(&mut self.state);
                self.buflen = 0;
            }
            let space = self.rate - self.buflen;
            let take = space.min(extra.len() - i);
            self.buf[self.buflen..self.buflen + take].copy_from_slice(&extra[i..i + take]);
            self.buflen += take;
            i += take;
        }
        if self.buflen == self.rate {
            self.xor_block();
            keccak_f(&mut self.state);
            self.buflen = 0;
        }
        self.buf[self.buflen] = self.pad;
        for b in self.buf[self.buflen + 1..self.rate].iter_mut() {
            *b = 0;
        }
        self.buf[self.rate - 1] |= 0x80;
        self.xor_block();
        keccak_f(&mut self.state);
        for k in 0..(self.rate / 8) {
            self.squeeze_buf[8 * k..8 * k + 8].copy_from_slice(&self.state[k].to_le_bytes());
        }
        self.squeeze_pos = 0;
    }

    fn squeeze(&mut self, out: &mut [u8]) {
        let mut out = out;
        while !out.is_empty() {
            if self.squeeze_pos == self.rate {
                keccak_f(&mut self.state);
                for k in 0..(self.rate / 8) {
                    self.squeeze_buf[8 * k..8 * k + 8].copy_from_slice(&self.state[k].to_le_bytes());
                }
                self.squeeze_pos = 0;
            }
            let avail = self.rate - self.squeeze_pos;
            let take = avail.min(out.len());
            out[..take].copy_from_slice(&self.squeeze_buf[self.squeeze_pos..self.squeeze_pos + take]);
            self.squeeze_pos += take;
            out = &mut out[take..];
        }
    }

    /// Finalize with `extra` bytes appended before padding, squeeze `out`, reset.
    fn digest_out(&mut self, extra: &[u8], out: &mut [u8]) {
        self.finish(extra);
        self.squeeze(out);
        self.reset();
    }

    fn reset(&mut self) {
        self.state = [0; 25];
        self.buf = [0; 200];
        self.buflen = 0;
        self.squeeze_pos = self.rate;
        if self.prefix_len > 0 {
            let p = self.prefix;
            self.absorb(&p[..self.prefix_len]);
        }
    }
}

// ---- left_encode / encode_string / bytepad (NIST SP 800-185) ----

fn left_encode(mut x: u64, out: &mut [u8; 9]) -> usize {
    if x == 0 {
        out[0] = 0;
        return 1;
    }
    let mut tmp = [0u8; 8];
    let mut n = 0;
    while x > 0 {
        tmp[n] = (x & 0xff) as u8;
        x >>= 8;
        n += 1;
    }
    out[0] = n as u8;
    for i in 0..n {
        out[1 + i] = tmp[n - 1 - i];
    }
    n + 1
}

fn encode_string(s: &[u8], out: &mut [u8; 256]) -> usize {
    let mut tmp = [0u8; 9];
    if s.is_empty() {
        out[0] = 0;
        1
    } else {
        let l = left_encode(s.len() as u64, &mut tmp);
        out[..l].copy_from_slice(&tmp[..l]);
        out[l..l + s.len()].copy_from_slice(s);
        l + s.len()
    }
}

fn bytepad(z: &[u8], rate: usize, out: &mut [u8; 512]) -> usize {
    let mut tmp = [0u8; 9];
    let le = left_encode(rate as u64, &mut tmp);
    let mut n = 0;
    out[..le].copy_from_slice(&tmp[..le]);
    n += le;
    out[n..n + z.len()].copy_from_slice(z);
    n += z.len();
    while n % rate != 0 {
        out[n] = 0;
        n += 1;
    }
    n
}

// ---- SHA3 fixed-output types ----

macro_rules! sha3_type {
    ($name:ident, $rate:expr, $out:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Clone)]
        pub struct $name {
            e: Keccak,
        }

        impl $name {
            /// Create a new hasher.
            #[inline]
            pub fn new() -> Self {
                $name {
                    e: Keccak::new($rate, 0x06),
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
                let mut out = [0u8; $out];
                self.e.digest_out(&[], &mut out);
                out
            }

            #[inline]
            fn finalize(self) -> [u8; $out] {
                self.e.clone().finalize_reset()
            }

            fn reset(&mut self) {
                self.e.reset();
            }
        }
    };
}

sha3_type!(Sha3_224, 144, 28, "SHA3-224 (Keccak, capacity 448).");
sha3_type!(Sha3_256, 136, 32, "SHA3-256 (Keccak, capacity 512).");
sha3_type!(Sha3_384, 104, 48, "SHA3-384 (Keccak, capacity 768).");
sha3_type!(Sha3_512, 72, 64, "SHA3-512 (Keccak, capacity 1024).");

macro_rules! sha3_oneshot {
    ($fn:ident, $ty:ident, $out:expr, $doc:expr) => {
        #[doc = $doc]
        #[inline]
        #[must_use]
        pub fn $fn(data: &[u8]) -> [u8; $out] {
            let mut h = $ty::new();
            h.update(data);
            h.finalize()
        }
    };
}

sha3_oneshot!(sha3_224, Sha3_224, 28, "One-shot SHA3-224.");
sha3_oneshot!(sha3_256, Sha3_256, 32, "One-shot SHA3-256.");
sha3_oneshot!(sha3_384, Sha3_384, 48, "One-shot SHA3-384.");
sha3_oneshot!(sha3_512, Sha3_512, 64, "One-shot SHA3-512.");

// ---- SHAKE ----

/// SHAKE128 extendable-output function (rate 168).
#[derive(Clone)]
pub struct Shake128 {
    e: Keccak,
}
/// SHAKE256 extendable-output function (rate 136).
#[derive(Clone)]
pub struct Shake256 {
    e: Keccak,
}

impl Shake128 {
    /// Create a new SHAKE128 XOF.
    #[inline]
    pub fn new() -> Self {
        Shake128 {
            e: Keccak::new(168, 0x1f),
        }
    }
}
impl Shake256 {
    /// Create a new SHAKE256 XOF.
    #[inline]
    pub fn new() -> Self {
        Shake256 {
            e: Keccak::new(136, 0x1f),
        }
    }
}
impl Default for Shake128 {
    fn default() -> Self {
        Self::new()
    }
}
impl Default for Shake256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Xof for Shake128 {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.e.update(data);
    }
    fn finalize_xof_reset(&mut self, out: &mut [u8]) {
        self.e.digest_out(&[], out);
    }
    #[inline]
    fn finalize_xof(self, out: &mut [u8]) {
        self.e.clone().finalize_xof_reset(out);
    }
    fn reset(&mut self) {
        self.e.reset();
    }
}
impl Xof for Shake256 {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.e.update(data);
    }
    fn finalize_xof_reset(&mut self, out: &mut [u8]) {
        self.e.digest_out(&[], out);
    }
    #[inline]
    fn finalize_xof(self, out: &mut [u8]) {
        self.e.clone().finalize_xof_reset(out);
    }
    fn reset(&mut self) {
        self.e.reset();
    }
}

/// One-shot SHAKE128 producing `out.len()` bytes.
#[inline]
#[must_use]
pub fn shake128(data: &[u8], out: &mut [u8]) {
    let mut h = Shake128::new();
    h.update(data);
    h.finalize_xof(out);
}

/// One-shot SHAKE256 producing `out.len()` bytes.
#[inline]
#[must_use]
pub fn shake256(data: &[u8], out: &mut [u8]) {
    let mut h = Shake256::new();
    h.update(data);
    h.finalize_xof(out);
}

// ---- cSHAKE ----

/// cSHAKE128 (customizable SHAKE, rate 168).
#[derive(Clone)]
pub struct CShake128 {
    e: Keccak,
}
/// cSHAKE256 (customizable SHAKE, rate 136).
#[derive(Clone)]
pub struct CShake256 {
    e: Keccak,
}

impl CShake128 {
    /// Create a cSHAKE128 XOF with function name `n` and customization `s`.
    /// If both are empty it behaves exactly like SHAKE128.
    #[must_use]
    pub fn new(n: &[u8], s: &[u8]) -> Self {
        let mut e = Keccak::new(168, 0x1f);
        if !(n.is_empty() && s.is_empty()) {
            e = Keccak::new(168, 0x04);
            let mut z = [0u8; 256];
            let zlen = encode_string(n, &mut z);
            let mut z2 = [0u8; 256];
            let z2len = encode_string(s, &mut z2);
            let mut combined = [0u8; 512];
            combined[..zlen].copy_from_slice(&z[..zlen]);
            combined[zlen..zlen + z2len].copy_from_slice(&z2[..z2len]);
            let mut pad = [0u8; 512];
            let plen = bytepad(&combined[..zlen + z2len], 168, &mut pad);
            e.set_prefix(&pad[..plen]);
        }
        CShake128 { e }
    }
}

impl CShake256 {
    /// Create a cSHAKE256 XOF with function name `n` and customization `s`.
    #[must_use]
    pub fn new(n: &[u8], s: &[u8]) -> Self {
        let mut e = Keccak::new(136, 0x1f);
        if !(n.is_empty() && s.is_empty()) {
            e = Keccak::new(136, 0x04);
            let mut z = [0u8; 256];
            let zlen = encode_string(n, &mut z);
            let mut z2 = [0u8; 256];
            let z2len = encode_string(s, &mut z2);
            let mut combined = [0u8; 512];
            combined[..zlen].copy_from_slice(&z[..zlen]);
            combined[zlen..zlen + z2len].copy_from_slice(&z2[..z2len]);
            let mut pad = [0u8; 512];
            let plen = bytepad(&combined[..zlen + z2len], 136, &mut pad);
            e.set_prefix(&pad[..plen]);
        }
        CShake256 { e }
    }
}

impl Default for CShake128 {
    fn default() -> Self {
        Self::new(&[], &[])
    }
}
impl Default for CShake256 {
    fn default() -> Self {
        Self::new(&[], &[])
    }
}

impl Xof for CShake128 {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.e.update(data);
    }
    fn finalize_xof_reset(&mut self, out: &mut [u8]) {
        self.e.digest_out(&[], out);
    }
    #[inline]
    fn finalize_xof(self, out: &mut [u8]) {
        self.e.clone().finalize_xof_reset(out);
    }
    fn reset(&mut self) {
        self.e.reset();
    }
}
impl Xof for CShake256 {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.e.update(data);
    }
    fn finalize_xof_reset(&mut self, out: &mut [u8]) {
        self.e.digest_out(&[], out);
    }
    #[inline]
    fn finalize_xof(self, out: &mut [u8]) {
        self.e.clone().finalize_xof_reset(out);
    }
    fn reset(&mut self) {
        self.e.reset();
    }
}

/// One-shot cSHAKE128 producing `out.len()` bytes.
#[inline]
#[must_use]
pub fn cshake128(data: &[u8], out: &mut [u8], n: &[u8], s: &[u8]) {
    let mut h = CShake128::new(n, s);
    h.update(data);
    h.finalize_xof(out);
}

/// One-shot cSHAKE256 producing `out.len()` bytes.
#[inline]
#[must_use]
pub fn cshake256(data: &[u8], out: &mut [u8], n: &[u8], s: &[u8]) {
    let mut h = CShake256::new(n, s);
    h.update(data);
    h.finalize_xof(out);
}

// ---- KMAC ----

/// KMAC128 (keyed MAC over cSHAKE128).
#[derive(Clone)]
pub struct Kmac128 {
    e: Keccak,
    msg_len: u64,
}
/// KMAC256 (keyed MAC over cSHAKE256).
#[derive(Clone)]
pub struct Kmac256 {
    e: Keccak,
    msg_len: u64,
}

impl Kmac128 {
    /// Create a KMAC128 with key `k` and customization `s`.
    #[must_use]
    pub fn new(k: &[u8], s: &[u8]) -> Self {
        let mut e = Keccak::new(168, 0x04);
        let mut z = [0u8; 256];
        let zlen = encode_string(b"KMAC", &mut z);
        let mut z2 = [0u8; 256];
        let z2len = encode_string(s, &mut z2);
        let mut combined = [0u8; 512];
        combined[..zlen].copy_from_slice(&z[..zlen]);
        combined[zlen..zlen + z2len].copy_from_slice(&z2[..z2len]);
        let mut pad = [0u8; 512];
        let plen = bytepad(&combined[..zlen + z2len], 168, &mut pad);
        // Prefix is Z || K.
        let mut prefix = [0u8; 512];
        prefix[..plen].copy_from_slice(&pad[..plen]);
        prefix[plen..plen + k.len()].copy_from_slice(k);
        e.set_prefix(&prefix[..plen + k.len()]);
        Kmac128 { e, msg_len: 0 }
    }
}

impl Kmac256 {
    /// Create a KMAC256 with key `k` and customization `s`.
    #[must_use]
    pub fn new(k: &[u8], s: &[u8]) -> Self {
        let mut e = Keccak::new(136, 0x04);
        let mut z = [0u8; 256];
        let zlen = encode_string(b"KMAC", &mut z);
        let mut z2 = [0u8; 256];
        let z2len = encode_string(s, &mut z2);
        let mut combined = [0u8; 512];
        combined[..zlen].copy_from_slice(&z[..zlen]);
        combined[zlen..zlen + z2len].copy_from_slice(&z2[..z2len]);
        let mut pad = [0u8; 512];
        let plen = bytepad(&combined[..zlen + z2len], 136, &mut pad);
        let mut prefix = [0u8; 512];
        prefix[..plen].copy_from_slice(&pad[..plen]);
        prefix[plen..plen + k.len()].copy_from_slice(k);
        e.set_prefix(&prefix[..plen + k.len()]);
        Kmac256 { e, msg_len: 0 }
    }
}

impl Xof for Kmac128 {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.msg_len = self.msg_len.wrapping_add(data.len() as u64);
        self.e.update(data);
    }
    fn finalize_xof_reset(&mut self, out: &mut [u8]) {
        let mut extra = [0u8; 256];
        let elen = encode_string(self.msg_len.wrapping_mul(8), &mut extra);
        self.e.digest_out(&extra[..elen], out);
        self.msg_len = 0;
    }
    #[inline]
    fn finalize_xof(self, out: &mut [u8]) {
        self.e.clone().finalize_xof_reset(out);
    }
    fn reset(&mut self) {
        self.e.reset();
        self.msg_len = 0;
    }
}
impl Xof for Kmac256 {
    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.msg_len = self.msg_len.wrapping_add(data.len() as u64);
        self.e.update(data);
    }
    fn finalize_xof_reset(&mut self, out: &mut [u8]) {
        let mut extra = [0u8; 256];
        let elen = encode_string(self.msg_len.wrapping_mul(8), &mut extra);
        self.e.digest_out(&extra[..elen], out);
        self.msg_len = 0;
    }
    #[inline]
    fn finalize_xof(self, out: &mut [u8]) {
        self.e.clone().finalize_xof_reset(out);
    }
    fn reset(&mut self) {
        self.e.reset();
        self.msg_len = 0;
    }
}

/// One-shot KMAC128 producing `out.len()` bytes.
#[inline]
#[must_use]
pub fn kmac128(k: &[u8], data: &[u8], out: &mut [u8], s: &[u8]) {
    let mut h = Kmac128::new(k, s);
    h.update(data);
    h.finalize_xof(out);
}

/// One-shot KMAC256 producing `out.len()` bytes.
#[inline]
#[must_use]
pub fn kmac256(k: &[u8], data: &[u8], out: &mut [u8], s: &[u8]) {
    let mut h = Kmac256::new(k, s);
    h.update(data);
    h.finalize_xof(out);
}
