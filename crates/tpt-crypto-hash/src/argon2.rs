//! Argon2id (RFC 9106) password hashing and key derivation. Requires `alloc`.
//!
//! Only Argon2id with version `0x13` is provided. The first half of pass 0
//! uses data-independent addressing (RFC 9106 §3.4.1.3); later blocks take
//! their reference index from the previous block's contents.
//!
//! # Side channels
//!
//! Argon2id is chosen so that the data-independent first half limits cache
//! timing leakage, but the reference index in the remaining blocks depends on
//! password-derived data. That is part of the Argon2 design, not an
//! implementation shortcut. The arithmetic itself has no secret-dependent
//! branches.
//!
//! ```
//! use tpt_crypto_hash::argon2::{argon2id, Params};
//!
//! let mut tag = [0u8; 32];
//! let params = Params { m_kib: 64, t: 1, p: 1 };
//! argon2id(b"password", b"sixteen-byte-slt", &[], &[], params, &mut tag).unwrap();
//! ```

use crate::blake2b::blake2b_var;
use alloc::vec;
use alloc::vec::Vec;
use tpt_crypto_core::{Error, Zeroize};

const BLOCK_WORDS: usize = 128;
const BLOCK_BYTES: usize = 1024;
const SYNC_POINTS: usize = 4;
const VERSION: u32 = 0x13;
/// Argon2 type identifier for Argon2id.
const TYPE_ID: u32 = 2;
const ADDRESSES_PER_BLOCK: usize = 128;
const MIN_SALT_LEN: usize = 8;
const MIN_TAG_LEN: usize = 4;

/// Argon2id cost parameters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Params {
    /// Memory cost in KiB. Rounded down to a multiple of `4 * p`.
    pub m_kib: u32,
    /// Number of passes (time cost), at least 1.
    pub t: u32,
    /// Degree of parallelism (lanes), 1 to 2^24 - 1.
    pub p: u32,
}

type Block = [u64; BLOCK_WORDS];
const ZERO_BLOCK: Block = [0u64; BLOCK_WORDS];

/// Derive `out.len()` bytes with Argon2id.
///
/// `salt` must be at least 8 bytes. `secret` (the optional "pepper") and
/// `associated_data` may be empty. `out.len()` must be at least 4.
///
/// # Errors
///
/// Returns [`Error::InvalidLength`] if a parameter or length violates RFC 9106:
/// `p` outside `1..2^24`, `t == 0`, `m_kib < 8 * p`, a salt shorter than 8
/// bytes, or a tag shorter than 4 bytes.
pub fn argon2id(
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated_data: &[u8],
    params: Params,
    out: &mut [u8],
) -> Result<(), Error> {
    let Params { m_kib, t, p } = params;
    if p == 0 || p >= (1 << 24) || t == 0 || m_kib < 8 * p || salt.len() < MIN_SALT_LEN {
        return Err(Error::InvalidLength);
    }
    if out.len() < MIN_TAG_LEN || u32::try_from(out.len()).is_err() {
        return Err(Error::InvalidLength);
    }
    let p_us = p as usize;
    let m_prime = 4 * p_us * (m_kib as usize / (4 * p_us));
    let q = m_prime / p_us;
    let seg = q / SYNC_POINTS;

    let mut h0 = initial_hash(password, salt, secret, associated_data, params, out.len());
    let mut mem = vec![ZERO_BLOCK; m_prime];
    for lane in 0..p_us {
        for col in 0..2u32 {
            let col_b = col.to_le_bytes();
            let lane_b = (lane as u32).to_le_bytes();
            let input: [&[u8]; 3] = [&h0, &col_b, &lane_b];
            let bytes = h_prime(BLOCK_BYTES, &input);
            mem[lane * q + col as usize] = block_from_bytes(&bytes);
        }
    }

    for pass in 0..t {
        for slice in 0..SYNC_POINTS {
            for lane in 0..p_us {
                fill_segment(&mut mem, Geometry { lanes: p_us, q, seg, m_prime, t, pass, slice, lane });
            }
        }
    }

    let mut c: Block = ZERO_BLOCK;
    for lane in 0..p_us {
        let last = &mem[lane * q + q - 1];
        for (ci, li) in c.iter_mut().zip(last.iter()) {
            *ci ^= li;
        }
    }
    let c_bytes = block_to_bytes(&c);
    let tag = h_prime(out.len(), &[c_bytes.as_slice()]);
    out.copy_from_slice(&tag);

    // Best-effort wipe of password-derived material.
    for block in mem.iter_mut() {
        block.zeroize();
    }
    mem.clear();
    c.zeroize();
    h0.zeroize();
    Ok(())
}

#[derive(Clone, Copy)]
struct Geometry {
    lanes: usize,
    q: usize,
    seg: usize,
    m_prime: usize,
    t: u32,
    pass: u32,
    slice: usize,
    lane: usize,
}

fn fill_segment(mem: &mut [Block], g: Geometry) {
    let Geometry { lanes, q, seg, m_prime, t, pass, slice, lane } = g;
    let data_independent = pass == 0 && slice <= 1;
    let start = if pass == 0 && slice == 0 { 2 } else { 0 };

    // Address generator state (Argon2id first half only).
    let mut input = ZERO_BLOCK;
    let mut addr = ZERO_BLOCK;
    if data_independent {
        input[0] = pass as u64;
        input[1] = lane as u64;
        input[2] = slice as u64;
        input[3] = m_prime as u64;
        input[4] = t as u64;
        input[5] = TYPE_ID as u64;
        if pass == 0 && slice == 0 {
            next_addresses(&mut input, &mut addr);
        }
    }

    for idx in start..seg {
        let j = slice * seg + idx;
        let cur = lane * q + j;
        let prev = lane * q + if j == 0 { q - 1 } else { j - 1 };

        let pseudo = if data_independent {
            if idx % ADDRESSES_PER_BLOCK == 0 {
                next_addresses(&mut input, &mut addr);
            }
            addr[idx % ADDRESSES_PER_BLOCK]
        } else {
            mem[prev][0]
        };
        let j1 = pseudo & 0xffff_ffff;
        let j2 = pseudo >> 32;

        let ref_lane = if pass == 0 && slice == 0 {
            lane
        } else {
            (j2 % lanes as u64) as usize
        };
        let same_lane = ref_lane == lane;

        // Size of the reference window W (RFC 9106 §3.4.2).
        let area: i64 = if pass == 0 {
            if slice == 0 {
                idx as i64 - 1
            } else if same_lane {
                (slice * seg + idx) as i64 - 1
            } else {
                (slice * seg) as i64 + if idx == 0 { -1 } else { 0 }
            }
        } else if same_lane {
            (q - seg + idx) as i64 - 1
        } else {
            (q - seg) as i64 + if idx == 0 { -1 } else { 0 }
        };

        // Non-uniform map of J1 into [0, area) (Figures 12–13).
        let x = (j1 * j1) >> 32;
        let y = ((area as u64) * x) >> 32;
        let zz = area - 1 - y as i64;
        let start_pos = if pass == 0 || slice == SYNC_POINTS - 1 {
            0
        } else {
            (slice + 1) * seg
        };
        let ref_col = (start_pos + zz as usize) % q;
        let ref_idx = ref_lane * q + ref_col;

        let new = compress_g(&mem[prev], &mem[ref_idx]);
        mem[cur] = if pass == 0 { new } else { xor_block(&new, &mem[cur]) };
    }

    input.zeroize();
    addr.zeroize();
}

/// Generate the next 128-word address block (RFC 9106 §3.4.1.2).
fn next_addresses(input: &mut Block, addr: &mut Block) {
    input[6] = input[6].wrapping_add(1);
    let inner = compress_g(&ZERO_BLOCK, input);
    *addr = compress_g(&ZERO_BLOCK, &inner);
}

fn initial_hash(
    password: &[u8],
    salt: &[u8],
    secret: &[u8],
    associated_data: &[u8],
    params: Params,
    tag_len: usize,
) -> Vec<u8> {
    let parts: [&[u8]; 14] = [
        &le32(params.p),
        &le32(tag_len as u32),
        &le32(params.m_kib),
        &le32(params.t),
        &le32(VERSION),
        &le32(TYPE_ID),
        &le32(password.len() as u32),
        password,
        &le32(salt.len() as u32),
        salt,
        &le32(secret.len() as u32),
        secret,
        &le32(associated_data.len() as u32),
        associated_data,
    ];
    blake2b_var(64, &parts)
}

/// Variable-length hash `H'` (RFC 9106 §3.3), built on BLAKE2b.
fn h_prime(out_len: usize, input: &[&[u8]]) -> Vec<u8> {
    let mut prefixed: Vec<&[u8]> = Vec::with_capacity(input.len() + 1);
    let len_bytes = le32(out_len as u32);
    prefixed.push(&len_bytes[..]);
    prefixed.extend_from_slice(input);

    if out_len <= 64 {
        return blake2b_var(out_len, &prefixed);
    }
    let r = out_len.div_ceil(32) - 2;
    let mut out = Vec::with_capacity(out_len);
    let mut v = blake2b_var(64, &prefixed);
    out.extend_from_slice(&v[..32]);
    for _ in 1..r {
        v = blake2b_var(64, &[v.as_slice()]);
        out.extend_from_slice(&v[..32]);
    }
    out.extend_from_slice(&blake2b_var(out_len - 32 * r, &[v.as_slice()]));
    out
}

fn le32(x: u32) -> [u8; 4] {
    x.to_le_bytes()
}

fn block_from_bytes(bytes: &[u8]) -> Block {
    debug_assert_eq!(bytes.len(), BLOCK_BYTES);
    let mut b = ZERO_BLOCK;
    for (w, chunk) in b.iter_mut().zip(bytes.chunks_exact(8)) {
        let mut buf = [0u8; 8];
        buf.copy_from_slice(chunk);
        *w = u64::from_le_bytes(buf);
    }
    b
}

fn block_to_bytes(b: &Block) -> Vec<u8> {
    let mut out = Vec::with_capacity(BLOCK_BYTES);
    for w in b {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}

fn xor_block(a: &Block, b: &Block) -> Block {
    let mut out = ZERO_BLOCK;
    for i in 0..BLOCK_WORDS {
        out[i] = a[i] ^ b[i];
    }
    out
}

/// Argon2 compression function `G(X, Y)` (RFC 9106 §3.5).
fn compress_g(x: &Block, y: &Block) -> Block {
    let mut r = ZERO_BLOCK;
    for i in 0..BLOCK_WORDS {
        r[i] = x[i] ^ y[i];
    }
    let mut q = r;

    // Row-wise: each row is 8 registers of 16 bytes, i.e. 16 consecutive words.
    for row in 0..8 {
        let mut v = [0u64; 16];
        v.copy_from_slice(&q[16 * row..16 * row + 16]);
        permute_p(&mut v);
        q[16 * row..16 * row + 16].copy_from_slice(&v);
    }

    // Column-wise: register `col + 8k` for k in 0..8, each register holding two words.
    for col in 0..8 {
        let mut v = [0u64; 16];
        for k in 0..8 {
            let reg = col + 8 * k;
            v[2 * k] = q[2 * reg];
            v[2 * k + 1] = q[2 * reg + 1];
        }
        permute_p(&mut v);
        for k in 0..8 {
            let reg = col + 8 * k;
            q[2 * reg] = v[2 * k];
            q[2 * reg + 1] = v[2 * k + 1];
        }
    }

    let mut z = ZERO_BLOCK;
    for i in 0..BLOCK_WORDS {
        z[i] = q[i] ^ r[i];
    }
    z
}

/// Permutation `P` (RFC 9106 §3.6): the BLAKE2b round with multiplicative GB.
fn permute_p(v: &mut [u64; 16]) {
    gb(v, 0, 4, 8, 12);
    gb(v, 1, 5, 9, 13);
    gb(v, 2, 6, 10, 14);
    gb(v, 3, 7, 11, 15);
    gb(v, 0, 5, 10, 15);
    gb(v, 1, 6, 11, 12);
    gb(v, 2, 7, 8, 13);
    gb(v, 3, 4, 9, 14);
}

#[inline(always)]
fn fbla(x: u64, y: u64) -> u64 {
    // a + b + 2 * trunc(a) * trunc(b), mod 2^64.
    x.wrapping_add(y)
        .wrapping_add(2u64.wrapping_mul(x & 0xffff_ffff).wrapping_mul(y & 0xffff_ffff))
}

#[inline(always)]
fn gb(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize) {
    v[a] = fbla(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = fbla(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = fbla(v[a], v[b]);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = fbla(v[c], v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> Vec<u8> {
        let s: Vec<u8> = s.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
        s.chunks(2)
            .map(|p| u8::from_str_radix(core::str::from_utf8(p).unwrap(), 16).unwrap())
            .collect()
    }

    /// RFC 9106 §5.3: Argon2id, version 0x13, m=32 KiB, t=3, p=4, 32-byte tag.
    #[test]
    fn rfc9106_argon2id_test_vector() {
        let password = [0x01u8; 32];
        let salt = [0x02u8; 16];
        let secret = [0x03u8; 8];
        let ad = [0x04u8; 12];
        let mut tag = [0u8; 32];
        argon2id(
            &password,
            &salt,
            &secret,
            &ad,
            Params { m_kib: 32, t: 3, p: 4 },
            &mut tag,
        )
        .unwrap();
        assert_eq!(
            tag.to_vec(),
            hex("0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659")
        );
    }

    /// RFC 9106 §5.3 "Pre-hashing digest" (H_0) for the same inputs.
    #[test]
    fn rfc9106_pre_hashing_digest() {
        let h0 = initial_hash(
            &[0x01u8; 32],
            &[0x02u8; 16],
            &[0x03u8; 8],
            &[0x04u8; 12],
            Params { m_kib: 32, t: 3, p: 4 },
            32,
        );
        assert_eq!(
            h0,
            hex(
                "28 89 de 48 7e b4 2a e5 00 c0 00 7e d9 25 2f
                 10 69 ea de c4 0d 57 65 b4 85 de 6d c2 43 7a 67 b8 54 6a 2f 0a
                 cc 1a 08 82 db 8f cf 74 71 4b 47 2e 94 df 42 1a 5d a1 11 2f fa
                 11 43 43 70 a1 e9 97"
            )
        );
    }

    #[test]
    fn variable_hash_matches_blake2b_for_64_bytes() {
        let data: &[u8] = b"abc";
        assert_eq!(
            blake2b_var(64, &[data]),
            crate::blake2b::blake2b(data).to_vec()
        );
    }

    #[test]
    fn parameter_validation() {
        let mut tag = [0u8; 32];
        let ok = Params { m_kib: 32, t: 1, p: 1 };
        let bad_salt = [0u8; 7];
        assert!(argon2id(b"pw", &bad_salt, &[], &[], ok, &mut tag).is_err());
        assert!(argon2id(b"pw", &[0u8; 8], &[], &[], Params { t: 0, ..ok }, &mut tag).is_err());
        assert!(argon2id(b"pw", &[0u8; 8], &[], &[], Params { p: 0, ..ok }, &mut tag).is_err());
        assert!(argon2id(b"pw", &[0u8; 8], &[], &[], Params { m_kib: 7, ..ok }, &mut tag).is_err());
        let mut short = [0u8; 3];
        assert!(argon2id(b"pw", &[0u8; 8], &[], &[], ok, &mut short).is_err());
    }

    #[test]
    fn output_depends_on_every_input() {
        let params = Params { m_kib: 64, t: 2, p: 2 };
        let run = |pw: &[u8], salt: &[u8], sec: &[u8], ad: &[u8]| {
            let mut tag = [0u8; 32];
            argon2id(pw, salt, sec, ad, params, &mut tag).unwrap();
            tag
        };
        let base = run(b"password", b"saltsalt", b"", b"");
        assert_eq!(base, run(b"password", b"saltsalt", b"", b""));
        assert_ne!(base, run(b"passwore", b"saltsalt", b"", b""));
        assert_ne!(base, run(b"password", b"saltsalz", b"", b""));
        assert_ne!(base, run(b"password", b"saltsalt", b"x", b""));
        assert_ne!(base, run(b"password", b"saltsalt", b"", b"x"));
    }
}
