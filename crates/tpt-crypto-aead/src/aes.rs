//! AES-128 / AES-192 / AES-256 block cipher — portable, constant-time.
//!
//! The portable implementation is **table-free**: the S-box is computed
//! algebraically as the AES affine transform applied to the GF(2⁸) multiplicative
//! inverse, where the inverse itself is obtained by a fixed-shape exponentiation
//! `x^254` (no secret-dependent branches, no lookup tables). `SubWord` in the key
//! schedule uses the same algebraic S-box.
//!
//! On `x86_64` the dispatcher additionally routes through the hardware AES-NI
//! instructions via [`tpt_crypto_ct::arch`], selected by compile-time
//! `target_feature` or (with `std`) runtime detection. All `unsafe` for that path
//! lives in `tpt-crypto-ct`, per the layering rules.

use crate::api::BlockCipher;
use tpt_crypto_ct::arch;

/// A portable / hardware AES block-cipher instance (the round-key schedule).
#[derive(Clone)]
pub struct Aes {
    rk: [u32; 60],
    rounds: usize,
}

/// Which AES key length an instance uses (drives the round count).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum KeyLen {
    K128,
    K192,
    K256,
}

impl KeyLen {
    fn nk(self) -> usize {
        match self {
            KeyLen::K128 => 4,
            KeyLen::K192 => 6,
            KeyLen::K256 => 8,
        }
    }
    fn rounds(self) -> usize {
        match self {
            KeyLen::K128 => 10,
            KeyLen::K192 => 12,
            KeyLen::K256 => 14,
        }
    }
}

// ----- GF(2⁸) helpers (constant-time, table-free) ---------------------------

/// Carry-less (polynomial) multiplication in GF(2⁸), reduced by the AES
/// polynomial `x⁸ + x⁴ + x³ + x + 1` (`0x11b`). Fixed-shape loop, no
/// secret-dependent control flow.
#[inline]
fn gf8_mul(mut a: u8, mut b: u8) -> u8 {
    let mut p = 0u8;
    let mut i = 0usize;
    while i < 8 {
        if b & 1 != 0 {
            p ^= a;
        }
        let reduce = a & 0x80;
        a = (a << 1) ^ if reduce != 0 { 0x1b } else { 0 };
        b >>= 1;
        i += 1;
    }
    p
}

/// Multiplicative inverse in GF(2⁸), computed by fixed-shape exponentiation
/// `x^254`. For `x == 0` the raw exponentiation yields `1`, which is masked to
/// `0` with a constant-time selector so that `inv(0) == 0`.
#[inline]
fn gf8_inv(x: u8) -> u8 {
    let mut base = x;
    let mut result: u8 = 1;
    let mut e: u16 = 254;
    loop {
        if e & 1 != 0 {
            result = gf8_mul(result, base);
        }
        e >>= 1;
        if e == 0 {
            break;
        }
        base = gf8_mul(base, base);
    }
    let nz = (x != 0) as u8;
    let mask = 0u8.wrapping_sub(nz); // 0xff if x != 0, else 0
    result & mask
}

/// The AES S-box applied to a single byte (algebraic, table-free).
#[inline]
fn sbox_byte(x: u8) -> u8 {
    let inv = gf8_inv(x);
    inv ^ inv.rotate_left(1) ^ inv.rotate_left(2) ^ inv.rotate_left(3) ^ inv.rotate_left(4) ^ 0x63
}

// ----- key schedule --------------------------------------------------------

impl Aes {
    /// AES-128 from a 16-byte key.
    pub fn new_128(key: &[u8]) -> Aes {
        Self::new(key, KeyLen::K128)
    }
    /// AES-192 from a 24-byte key.
    pub fn new_192(key: &[u8]) -> Aes {
        Self::new(key, KeyLen::K192)
    }
    /// AES-256 from a 32-byte key.
    pub fn new_256(key: &[u8]) -> Aes {
        Self::new(key, KeyLen::K256)
    }

    fn new(key: &[u8], kl: KeyLen) -> Aes {
        let nk = kl.nk();
        assert_eq!(key.len(), nk * 4, "AES key length mismatch");
        let rounds = kl.rounds();
        let mut w = [0u32; 60];
        let mut i = 0;
        while i < nk {
            w[i] = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
            i += 1;
        }
        let mut rcon = 1u8;
        let mut i = nk;
        while i <= rounds * 4 + 3 {
            let mut temp = w[i - 1];
            if i % nk == 0 {
                temp = subword(rotword(temp)) ^ u32::from_be_bytes([rcon, 0, 0, 0]);
                rcon = gf8_mul(rcon, 2);
            } else if nk > 6 && i % nk == 4 {
                temp = subword(temp);
            }
            w[i] = w[i - nk] ^ temp;
            i += 1;
        }
        Aes { rk: w, rounds }
    }

    /// Number of rounds (10, 12, or 14).
    pub const fn rounds(&self) -> usize {
        self.rounds
    }

    /// Encrypt a single 16-byte block.
    #[inline]
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        self.dispatch_encrypt(block)
    }
}

impl BlockCipher for Aes {
    fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        self.dispatch_encrypt(block)
    }
}

#[inline]
fn subword(w: u32) -> u32 {
    let b = w.to_be_bytes();
    u32::from_be_bytes([sbox_byte(b[0]), sbox_byte(b[1]), sbox_byte(b[2]), sbox_byte(b[3])])
}

#[inline]
fn rotword(w: u32) -> u32 {
    w.rotate_left(8)
}

// ----- portable encryption ------------------------------------------------

impl Aes {
    #[inline(always)]
    fn encrypt_core(&self, block: &[u8; 16]) -> [u8; 16] {
        let mut state = [0u32; 4];
        for i in 0..4 {
            state[i] = u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
        }
        add_round_key(&mut state, &self.rk[0..4]);

        for r in 1..self.rounds {
            sub_bytes(&mut state);
            shift_rows(&mut state);
            mix_columns(&mut state);
            add_round_key(&mut state, &self.rk[4 * r..4 * r + 4]);
        }
        sub_bytes(&mut state);
        shift_rows(&mut state);
        add_round_key(&mut state, &self.rk[4 * self.rounds..4 * self.rounds + 4]);

        let mut out = [0u8; 16];
        for i in 0..4 {
            out[4 * i..4 * i + 4].copy_from_slice(&state[i].to_be_bytes());
        }
        out
    }
}

#[inline]
fn add_round_key(state: &mut [u32; 4], rk: &[u32]) {
    for i in 0..4 {
        state[i] ^= rk[i];
    }
}

#[inline]
fn sub_bytes(state: &mut [u32; 4]) {
    for w in state.iter_mut() {
        let b = w.to_be_bytes();
        *w = u32::from_be_bytes([sbox_byte(b[0]), sbox_byte(b[1]), sbox_byte(b[2]), sbox_byte(b[3])]);
    }
}

#[inline]
fn shift_rows(state: &mut [u32; 4]) {
    let mut b = [0u8; 16];
    for col in 0..4 {
        let w = state[col].to_be_bytes();
        for row in 0..4 {
            b[4 * col + row] = w[row];
        }
    }
    for r in 1..4 {
        let row: [u8; 4] = [b[r], b[4 + r], b[8 + r], b[12 + r]];
        for col in 0..4 {
            b[4 * col + r] = row[(col + 4 - r) % 4];
        }
    }
    for col in 0..4 {
        let mut w = [0u8; 4];
        w.copy_from_slice(&b[4 * col..4 * col + 4]);
        state[col] = u32::from_be_bytes(w);
    }
}

#[inline]
fn mix_columns(state: &mut [u32; 4]) {
    let bytes: [[u8; 4]; 4] = [
        state[0].to_be_bytes(),
        state[1].to_be_bytes(),
        state[2].to_be_bytes(),
        state[3].to_be_bytes(),
    ];
    for c in 0..4 {
        let s0 = bytes[0][c];
        let s1 = bytes[1][c];
        let s2 = bytes[2][c];
        let s3 = bytes[3][c];
        let out = [
            gf8_mul(s0, 2) ^ gf8_mul(s1, 3) ^ s2 ^ s3,
            s0 ^ gf8_mul(s1, 2) ^ gf8_mul(s2, 3) ^ s3,
            s0 ^ s1 ^ gf8_mul(s2, 2) ^ gf8_mul(s3, 3),
            gf8_mul(s0, 3) ^ s1 ^ s2 ^ gf8_mul(s3, 2),
        ];
        state[c] = u32::from_be_bytes(out);
    }
}

// ----- AES-NI path (x86_64, routed through tpt-crypto-ct::arch) -----------

#[cfg(target_arch = "x86_64")]
#[inline(always)]
fn aesni_encrypt(core: &Aes, block: &[u8; 16]) -> [u8; 16] {
    let mut rk: [arch::Block128; 15] = [arch::Block128 { lo: 0, hi: 0 }; 15];
    for (i, item) in rk.iter_mut().enumerate().take(core.rounds + 1) {
        let mut kb = [0u8; 16];
        for j in 0..4 {
            kb[4 * j..4 * j + 4].copy_from_slice(&core.rk[4 * i + j].to_be_bytes());
        }
        *item = arch::Block128::from_le_bytes(kb);
    }
    let b = arch::Block128::from_le_bytes(*block);
    let out = arch::aes_ni_encrypt_block_safe(&rk[..=core.rounds], b)
        .expect("aesni_encrypt called without AES support");
    let mut r = [0u8; 16];
    r[0..8].copy_from_slice(&out.lo.to_le_bytes());
    r[8..16].copy_from_slice(&out.hi.to_le_bytes());
    r
}

impl Aes {
    #[cfg(target_arch = "x86_64")]
    #[inline(always)]
    fn dispatch_encrypt(&self, block: &[u8; 16]) -> [u8; 16] {
        #[cfg(target_feature = "aes")]
        {
            aesni_encrypt(self, block)
        }
        #[cfg(not(target_feature = "aes"))]
        {
            if arch::has_aes_ni() {
                aesni_encrypt(self, block)
            } else {
                self.encrypt_core(block)
            }
        }
    }

    #[cfg(not(target_arch = "x86_64"))]
    #[inline(always)]
    fn dispatch_encrypt(&self, block: &[u8; 16]) -> [u8; 16] {
        self.encrypt_core(block)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf8_inverse() {
        for x in 1u16..=255u16 {
            let x = x as u8;
            assert_eq!(gf8_mul(gf8_inv(x), x), 1, "x={x}");
        }
        assert_eq!(gf8_inv(0), 0);
        assert_eq!(sbox_byte(0), 0x63);
        assert_eq!(sbox_byte(1), 0x7c);
    }

    fn ecb(core: &Aes, pt: &[u8; 16]) -> [u8; 16] {
        core.encrypt_block(pt)
    }

    #[test]
    fn aes128_fips197() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let pt = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        let ct = hex::decode("69c4e0d86a7b0430d8cdb78070b4c55a").unwrap();
        let core = Aes::new_128(&key);
        let pt: [u8; 16] = pt.try_into().unwrap();
        let ct: [u8; 16] = ct.try_into().unwrap();
        assert_eq!(ecb(&core, &pt), ct);
    }

    #[test]
    fn aes192_fips197() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f1011121314151617").unwrap();
        let pt = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        let ct = hex::decode("dda97ca4864cdfe06eaf70a0ec0d7191").unwrap();
        let core = Aes::new_192(&key);
        let pt: [u8; 16] = pt.try_into().unwrap();
        let ct: [u8; 16] = ct.try_into().unwrap();
        assert_eq!(ecb(&core, &pt), ct);
    }

    #[test]
    fn aes256_fips197() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let pt = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        let ct = hex::decode("8ea2b7ca516745bfeafc49904b496089").unwrap();
        let core = Aes::new_256(&key);
        let pt: [u8; 16] = pt.try_into().unwrap();
        let ct: [u8; 16] = ct.try_into().unwrap();
        assert_eq!(ecb(&core, &pt), ct);
    }
}
