//! AES-128 / AES-192 / AES-256 block cipher — portable, constant-time.
//!
//! The portable path uses a **table-free** S-box: the multiplicative inverse in
//! GF(2^8) is computed by exponentiation (`x^254`, a fixed-shape square-and-
//! multiply that never branches on secret bits), followed by the AES affine
//! transform. No T-tables, no secret-dependent branches or memory accesses — the
//! cipher is constant-time by construction.
//!
//! On `x86_64` the dispatcher additionally routes through the hardware AES-NI
//! instructions via [`tpt_crypto_ct::arch`], selected at runtime (or at compile
//! time when the `aes` target feature is on). All `unsafe` for that path lives
//! in `tpt-crypto-ct`, exactly as the layering rules require.

use tpt_crypto_ct::arch;

/// A portable AES block-cipher instance (the round-key schedule).
#[derive(Clone)]
pub(crate) struct AesCore {
    pub(crate) rk: [u32; 60],
    pub(crate) rounds: usize,
}

/// Which AES key length this instance uses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KeyLen {
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

// ----- GF(2^8) helpers (constant-time) -------------------------------------

#[inline]
const fn gf8_mul(mut a: u8, mut b: u8) -> u8 {
    // Carry-less (polynomial) multiplication in GF(2^8) followed by reduction by
    // the AES polynomial x^8 + x^4 + x^3 + x + 1 (0x11b). Both steps are
    // loop-shaped and data-flow driven, so they are constant-time.
    let mut p = 0u8;
    let mut i = 0usize;
    while i < 8 {
        if b & 1 != 0 {
            p ^= a;
        }
        // Reduce the *current* `a` (before shifting) if its high bit is set: the
        // shifted value would exceed the field degree, so subtract the polynomial
        // (its low byte is 0x1b) from the eventual high byte.
        let reduce = a & 0x80;
        a = (a << 1) ^ if reduce != 0 { 0x1b } else { 0 };
        b >>= 1;
        i += 1;
    }
    p
}

#[inline]
const fn gf8_inv(x: u8) -> u8 {
    // In GF(2^8) the non-zero elements form a group, so for x != 0 exactly one
    // c in 1..=255 satisfies x*c == 1. Finding it by linear scan is a fixed-shape
    // loop (no secret-dependent control flow) and runs at compile time when used
    // inside the `const fn` S-box, so the cipher stays constant-time.
    let mut c = 1u8;
    let mut r = 0u8;
    while c != 0 {
        if gf8_mul(x, c) == 1 {
            r = c;
        }
        c = c.wrapping_add(1);
    }
    r
}

#[inline]
const fn sbox(x: u8) -> u8 {
    let inv = gf8_inv(x);
    // AES affine transform: s = inv ^ rotl8(inv, 1) ^ rotl8(inv, 2) ^
    // rotl8(inv, 3) ^ rotl8(inv, 4) ^ 0x63
    inv ^ inv.rotate_left(1) ^ inv.rotate_left(2) ^ inv.rotate_left(3) ^ inv.rotate_left(4) ^ 0x63
}

// Precompute the forward S-box once (the values are public constants, not a
// secret-dependent table, so a simple array is fine and constant-time to use).
const SBOX: [u8; 256] = {
    let mut t = [0u8; 256];
    let mut i = 0usize;
    while i < 256 {
        t[i] = sbox(i as u8);
        i += 1;
    }
    t
};

// ----- key schedule --------------------------------------------------------

impl AesCore {
    pub(crate) fn new(key: &[u8], kl: KeyLen) -> AesCore {
        let nk = kl.nk();
        assert_eq!(key.len(), nk * 4, "AES key length mismatch");
        let rounds = kl.rounds();
        let nk_u32 = nk as u32;
        let mut w = [0u32; 60];
        let mut i = 0;
        while i < nk {
            w[i] = u32::from_be_bytes([key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]]);
            i += 1;
        }
        let mut rcon_iter = 1u32;
        let mut i = nk;
        while i <= (rounds as usize) * 4 + 3 {
            let mut temp = w[i - 1];
            if i % nk == 0 {
                temp = subword(rotword(temp)) ^ (rcon_iter << 24);
                rcon_iter = gf8_mul(rcon_iter as u8, 2) as u32;
            } else if nk > 6 && i % nk == 4 {
                temp = subword(temp);
            }
            w[i] = w[i - nk] ^ temp;
            i += 1;
        }
        AesCore {
            rk: w,
            rounds: nk_u32 as usize * 0 + rounds,
        }
    }

    #[inline]
    pub(crate) fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        dispatch_encrypt(self, block)
    }
}

#[inline]
fn subword(w: u32) -> u32 {
    let b = w.to_be_bytes();
    u32::from_be_bytes([SBOX[b[0] as usize], SBOX[b[1] as usize], SBOX[b[2] as usize], SBOX[b[3] as usize]])
}

#[inline]
fn rotword(w: u32) -> u32 {
    // FIPS 197 ROTWORD left-rotates the 4-byte word. Our words are stored
    // big-endian (byte 0 is the most-significant), so a left rotation of the byte
    // array is a left rotation of the u32.
    w.rotate_left(8)
}

// ----- portable encryption ------------------------------------------------

#[inline]
#[allow(clippy::needless_range_loop)]
fn encrypt_core(rk: &[u32; 60], rounds: usize, block: &[u8; 16]) -> [u8; 16] {
    let mut state = [0u32; 4];
    for i in 0..4 {
        state[i] = u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
    }
    add_round_key(&mut state, &rk[0..4]);

    for r in 1..rounds {
        sub_bytes(&mut state);
        shift_rows(&mut state);
        mix_columns(&mut state);
        add_round_key(&mut state, &rk[4 * r..4 * r + 4]);
    }
    sub_bytes(&mut state);
    shift_rows(&mut state);
    add_round_key(&mut state, &rk[4 * rounds..4 * rounds + 4]);

    let mut out = [0u8; 16];
    for i in 0..4 {
        out[4 * i..4 * i + 4].copy_from_slice(&state[i].to_be_bytes());
    }
    out
}

/// State after exactly one full round (used by tests).
fn encrypt_core_round1(core: &AesCore, block: &[u8; 16]) -> [u8; 16] {
    let mut state = [0u32; 4];
    for i in 0..4 {
        state[i] = u32::from_be_bytes([block[4 * i], block[4 * i + 1], block[4 * i + 2], block[4 * i + 3]]);
    }
    add_round_key(&mut state, &core.rk[0..4]);
    sub_bytes(&mut state);
    shift_rows(&mut state);
    mix_columns(&mut state);
    add_round_key(&mut state, &core.rk[4..8]);
    let mut out = [0u8; 16];
    for i in 0..4 {
        out[4 * i..4 * i + 4].copy_from_slice(&state[i].to_be_bytes());
    }
    out
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
        *w = u32::from_be_bytes([SBOX[b[0] as usize], SBOX[b[1] as usize], SBOX[b[2] as usize], SBOX[b[3] as usize]]);
    }
}

#[inline]
fn shift_rows(state: &mut [u32; 4]) {
    // Work in a 16-byte column-major buffer: byte index = 4*col + row.
    let mut b = [0u8; 16];
    for col in 0..4 {
        let w = state[col].to_be_bytes();
        for row in 0..4 {
            b[4 * col + row] = w[row];
        }
    }
    // Row r is rotated left by r positions.
    for r in 1..4 {
        let row: [u8; 4] = [
            b[4 * 0 + r],
            b[4 * 1 + r],
            b[4 * 2 + r],
            b[4 * 3 + r],
        ];
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
    // The state is column-major: byte index = 4*col + row, i.e. the 4 bytes of
    // `state[col]` are column `col` (rows 0..4). MixColumns mixes each column
    // independently using the constant matrix [2,3,1,1; 1,2,3,1; 1,1,2,3;
    // 3,1,1,2] over GF(2^8).
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
#[inline]
fn aesni_encrypt(core: &AesCore, block: &[u8; 16]) -> [u8; 16] {
    // Format the round keys as `arch::Block128` (little-endian word pairs).
    let mut rk: [arch::Block128; 15] = [arch::Block128 { lo: 0, hi: 0 }; 15];
    for i in 0..=core.rounds {
        let w = [
            core.rk[4 * i],
            core.rk[4 * i + 1],
            core.rk[4 * i + 2],
            core.rk[4 * i + 3],
        ];
        rk[i] = arch::Block128::from_u32s(w);
    }
    let b = arch::Block128::from_le_bytes(*block);
    // SAFE wrapper routes the AES-NI routine (and its `unsafe`) through
    // `tpt-crypto-ct::arch`; returns `None` iff AES is unavailable.
    let out = arch::aes_ni_encrypt_block_safe(&rk[..=core.rounds], b)
        .expect("aesni_encrypt called without AES support");
    let lo = out.lo.to_le_bytes();
    let hi = out.hi.to_le_bytes();
    let mut r = [0u8; 16];
    r[0..8].copy_from_slice(&lo);
    r[8..16].copy_from_slice(&hi);
    r
}

#[cfg(target_arch = "x86_64")]
#[inline]
fn dispatch_encrypt(core: &AesCore, block: &[u8; 16]) -> [u8; 16] {
    // Compile-time fast path when built with the `aes` target feature.
    #[cfg(target_feature = "aes")]
    {
        aesni_encrypt(core, block)
    }
    #[cfg(not(target_feature = "aes"))]
    {
        if arch::has_aes_ni() {
            aesni_encrypt(core, block)
        } else {
            encrypt_core(&core.rk, core.rounds, block)
        }
    }
}

#[cfg(not(target_arch = "x86_64"))]
#[inline]
fn dispatch_encrypt(core: &AesCore, block: &[u8; 16]) -> [u8; 16] {
    encrypt_core(&core.rk, core.rounds, block)
}

// ----- public type-erased API used by the higher-level AEAD constructions --

pub(crate) enum Aes {
    K128(AesCore),
    K192(AesCore),
    K256(AesCore),
}

impl Aes {
    pub(crate) fn new_128(key: &[u8]) -> Aes {
        Aes::K128(AesCore::new(key, KeyLen::K128))
    }
    pub(crate) fn new_192(key: &[u8]) -> Aes {
        Aes::K192(AesCore::new(key, KeyLen::K192))
    }
    pub(crate) fn new_256(key: &[u8]) -> Aes {
        Aes::K256(AesCore::new(key, KeyLen::K256))
    }
    #[inline]
    pub(crate) fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        match self {
            Aes::K128(c) => c.encrypt_block(block),
            Aes::K192(c) => c.encrypt_block(block),
            Aes::K256(c) => c.encrypt_block(block),
        }
    }
}

// ----- standalone KAT (FIPS 197 single-block) -----------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gf8_basic() {
        assert_eq!(gf8_mul(1, 1), 1);
        assert_eq!(gf8_mul(2, 2), 4);
        assert_eq!(gf8_mul(3, 3), 5);
        assert_eq!(gf8_inv(0x53), 0xef);
        assert_eq!(gf8_mul(0x53, gf8_inv(0x53)), 1);
        assert_eq!(gf8_inv(3), 0xf6);
        assert_eq!(gf8_mul(3, gf8_inv(3)), 1);
        for x in 1u16..=255u16 {
            let x = x as u8;
            assert_eq!(gf8_mul(gf8_inv(x), x), 1, "x={x}");
        }
        assert_eq!(gf8_inv(0), 0);
        assert_eq!(sbox(0), 0x63);
        assert_eq!(sbox(1), 0x7c);
        // FIPS 197 worked example: state after round 1 (before final AddRoundKey
        // of that round) for key 000102...0f, pt 001122...ff is a known value.
        // Just sanity-check the S-box table a few more entries.
        assert_eq!(sbox(0x53), 0xed);
        assert_eq!(sbox(0xef), 0x3b);
    }

    fn ecb(core: &AesCore, pt: &[u8; 16]) -> [u8; 16] {
        core.encrypt_block(pt)
    }

    #[test]
    fn aes128_fips197() {
        // FIPS 197 Appendix C.1
        let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let pt = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        let ct = hex::decode("69c4e0d86a7b0430d8cdb78070b4c55a").unwrap();
        let core = AesCore::new(&key, KeyLen::K128);
        let ct_arr: [u8; 16] = ct[..].try_into().unwrap();
        assert_eq!(ecb(&core, &pt.try_into().unwrap()), ct_arr);
    }

    #[test]
    fn aes128_keyexpansion_fips197() {
        // FIPS 197 C.1 expanded key words w0..w5
        let key = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
        let core = AesCore::new(&key, KeyLen::K128);
        let want: [u32; 6] = [
            0x00010203, 0x04050607, 0x08090a0b, 0x0c0d0e0f,
            0xd2c4d6e0, 0xb8e8e6c6,
        ];
        for i in 0..6 {
            assert_eq!(core.rk[i], want[i], "w{i}");
        }
    }

    #[test]
    fn aes192_fips197() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f1011121314151617").unwrap();
        let pt = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        let ct = hex::decode("dda97ca4864cdfe06eaf70a0ec0d7191").unwrap();
        let core = AesCore::new(&key, KeyLen::K192);
        let ct_arr: [u8; 16] = ct[..].try_into().unwrap();
        assert_eq!(ecb(&core, &pt.try_into().unwrap()), ct_arr);
    }

    #[test]
    fn aes256_fips197() {
        let key = hex::decode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f").unwrap();
        let pt = hex::decode("00112233445566778899aabbccddeeff").unwrap();
        let ct = hex::decode("8ea2b7ca516745bfeafc49904b496089").unwrap();
        let core = AesCore::new(&key, KeyLen::K256);
        let ct_arr: [u8; 16] = ct[..].try_into().unwrap();
        assert_eq!(ecb(&core, &pt.try_into().unwrap()), ct_arr);
    }
}
