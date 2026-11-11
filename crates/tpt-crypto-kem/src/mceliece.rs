//! Classic McEliece (NIST round-4 KEM, parameter sets 348864, 460896, 6688128, 6960119, 8192128).
//!
//! Port of the `Reference_Implementation` in the official submission (`mceliece-20221023`,
//! Classic McEliece team, public domain). One generic implementation covers the five sets
//! through [`McParams`]. Integer semantics follow the C, including the 16-bit wrap-around in
//! `bm` and the 32-bit wrap-around in the control-bit generator.
//!
//! Field and network: the 12-bit set uses GF(2^12) with `x^12 + x^3 + 1` and a single-plane
//! Benes network; the four 13-bit sets use GF(2^13) with `x^13 + x^4 + x^3 + x + 1` and the
//! two-plane Benes network of the reference. The reduction of the Goppa-code products
//! modulo the set's polynomial is in [`McParams::REDUCE`], taken from each reference `gf.c`.
//!
//! Checked against the official `kat_kem.rsp` records (see `tests/mceliece_kat.rs`).
//!
//! Randomness: keypair draws 32 bytes; encapsulation draws 256 bytes per attempt to sample
//! the error vector. The reference's rejection-sampling loop in `gen_e` branches on the
//! sampled positions, as the reference does (it uses declassified masks there).

// The index loops below mirror the reference C one for one; the known-answer tests
// check the result, so the loops are kept rather than rewritten as iterators.
#![allow(clippy::needless_range_loop, clippy::manual_memcpy)]

use alloc::vec;
use alloc::vec::Vec;
use tpt_crypto_core::{CryptoRng, Error, Result, Zeroize};

/// Field element.
pub type Gf = u16;

/// Per-set Classic McEliece parameters.
pub trait McParams {
    /// Field degree `m` (12 or 13).
    const GFBITS: u32;
    /// Code length `n`.
    const SYS_N: usize;
    /// Error-correction capability `t`.
    const SYS_T: usize;
    /// Terms of the reduction `X^t = sum c_k X^k` used by the Goppa-polynomial products:
    /// `(k, c_k)` with `c_k` a field element. Taken from the reference `GF_mul`.
    const REDUCE: &'static [(usize, Gf)];
    /// Error vector drawn as SYS_T values from 2*SYS_T bytes, without the range check (8192128).
    const SHORT_GEN_E: bool;
    /// Public-key rows stored shifted by PK_NROWS % 8 bits (6960119).
    const SHIFTED_PK: bool;
    /// Padding bits of pk and ciphertext are checked; outputs cleared or set otherwise (6960119).
    const PADDING_CHECKS: bool;

    /// `2^m` field elements.
    const Q: usize = 1 << Self::GFBITS;
    /// Mask of one field element.
    const GFMASK: Gf = ((1u32 << Self::GFBITS) - 1) as Gf;
    /// Rows of the systematic parity-check matrix, `m * t`.
    const PK_NROWS: usize = Self::SYS_T * Self::GFBITS as usize;
    /// Columns of the non-identity part, `n - m t`.
    const PK_NCOLS: usize = Self::SYS_N - Self::PK_NROWS;
    /// Bytes per row of the public matrix.
    const PK_ROW_BYTES: usize = Self::PK_NCOLS.div_ceil(8);
    /// Bytes of the syndrome, which is also the ciphertext length.
    const SYND_BYTES: usize = Self::PK_NROWS.div_ceil(8);
    /// Bytes of the Goppa polynomial in the secret key.
    const IRR_BYTES: usize = Self::SYS_T * 2;
    /// Bytes of the Benes control bits in the secret key.
    const COND_BYTES: usize = (1 << (Self::GFBITS - 4)) * (2 * Self::GFBITS as usize - 1);
    /// Bytes of the random string `s` (the fallback when decapsulation rejects).
    const S_LEN: usize = Self::SYS_N / 8;
    /// Bytes of the randomness used by keypair before the loop.
    const DELTA_LEN: usize = 32;

    /// Public-key length.
    const PUBLIC_KEY_LEN: usize = Self::PK_NROWS * Self::PK_ROW_BYTES;
    /// Secret-key length: `delta(32) || pad(8) || irr || cond || s`.
    const SECRET_KEY_LEN: usize = 40 + Self::IRR_BYTES + Self::COND_BYTES + Self::S_LEN;
    /// Ciphertext length.
    const CIPHERTEXT_LEN: usize = Self::SYND_BYTES;
}

/// Shared-secret length (all sets).
pub const SHARED_SECRET_LEN: usize = 32;

/// `mceliece348864`: GF(2^12), n = 3488, t = 64.
pub struct Mc348864;

impl McParams for Mc348864 {
    const GFBITS: u32 = 12;
    const SYS_N: usize = 3488;
    const SYS_T: usize = 64;
    const REDUCE: &'static [(usize, Gf)] = &[(3, 1), (1, 1), (0, 2)];
    const SHORT_GEN_E: bool = false;
    const SHIFTED_PK: bool = false;
    const PADDING_CHECKS: bool = false;
}

/// `mceliece460896`: GF(2^13), n = 4608, t = 96.
pub struct Mc460896;

impl McParams for Mc460896 {
    const GFBITS: u32 = 13;
    const SYS_N: usize = 4608;
    const SYS_T: usize = 96;
    const REDUCE: &'static [(usize, Gf)] = &[(10, 1), (9, 1), (6, 1), (0, 1)];
    const SHORT_GEN_E: bool = false;
    const SHIFTED_PK: bool = false;
    const PADDING_CHECKS: bool = false;
}

/// `mceliece6688128`: GF(2^13), n = 6688, t = 128.
pub struct Mc6688128;

impl McParams for Mc6688128 {
    const GFBITS: u32 = 13;
    const SYS_N: usize = 6688;
    const SYS_T: usize = 128;
    const REDUCE: &'static [(usize, Gf)] = &[(7, 1), (2, 1), (1, 1), (0, 1)];
    const SHORT_GEN_E: bool = false;
    const SHIFTED_PK: bool = false;
    const PADDING_CHECKS: bool = false;
}

/// `mceliece6960119`: GF(2^13), n = 6960, t = 119.
pub struct Mc6960119;

impl McParams for Mc6960119 {
    const GFBITS: u32 = 13;
    const SYS_N: usize = 6960;
    const SYS_T: usize = 119;
    const REDUCE: &'static [(usize, Gf)] = &[(8, 1), (0, 1)];
    const SHORT_GEN_E: bool = false;
    const SHIFTED_PK: bool = true;
    const PADDING_CHECKS: bool = true;
}

/// `mceliece8192128`: GF(2^13), n = 8192, t = 128.
pub struct Mc8192128;

impl McParams for Mc8192128 {
    const GFBITS: u32 = 13;
    const SYS_N: usize = 8192;
    const SYS_T: usize = 128;
    const REDUCE: &'static [(usize, Gf)] = &[(7, 1), (2, 1), (1, 1), (0, 1)];
    const SHORT_GEN_E: bool = true;
    const SHIFTED_PK: bool = false;
    const PADDING_CHECKS: bool = false;
}

fn shake256_into(out: &mut [u8], input: &[u8]) {
    tpt_crypto_hash::sha3::shake256(input, out);
}

// ---- Byte helpers (util.c) ---------------------------------------------------------

fn store_gf<P: McParams>(dest: &mut [u8], a: Gf) {
    let _ = P::GFBITS;
    dest[0] = (a & 0xFF) as u8;
    dest[1] = (a >> 8) as u8;
}

fn load_gf<P: McParams>(src: &[u8]) -> Gf {
    let a = (u16::from(src[1]) << 8) | u16::from(src[0]);
    a & P::GFMASK
}

fn load4(src: &[u8]) -> u32 {
    u32::from_le_bytes([src[0], src[1], src[2], src[3]])
}

fn load8(src: &[u8]) -> u64 {
    u64::from_le_bytes([
        src[0], src[1], src[2], src[3], src[4], src[5], src[6], src[7],
    ])
}

fn store8(out: &mut [u8], v: u64) {
    out[..8].copy_from_slice(&v.to_le_bytes());
}

/// Reverse the `m` low bits of `a` (`bitrev` in util.c).
fn bitrev<P: McParams>(a: Gf) -> Gf {
    let mut a = ((a & 0x00FF) << 8) | ((a & 0xFF00) >> 8);
    a = ((a & 0x0F0F) << 4) | ((a & 0xF0F0) >> 4);
    a = ((a & 0x3333) << 2) | ((a & 0xCCCC) >> 2);
    a = ((a & 0x5555) << 1) | ((a & 0xAAAA) >> 1);
    a >> (16 - P::GFBITS)
}

// ---- Field arithmetic (gf.c) -------------------------------------------------------

/// Irreducible polynomial of GF(2^m): `x^12 + x^3 + 1` or `x^13 + x^4 + x^3 + x + 1`.
fn field_poly<P: McParams>() -> u32 {
    if P::GFBITS == 12 {
        0x1009
    } else {
        0x201B
    }
}

/// Zero for nonzero input; for zero input the result is `0x1FFF` (callers mask with `& 1`
/// or use it as a mask, as the reference does).
fn gf_iszero(a: Gf) -> Gf {
    let t = u32::from(a).wrapping_sub(1) >> 19;
    t as Gf
}

/// Product in GF(2^m).
fn gf_mul<P: McParams>(in0: Gf, in1: Gf) -> Gf {
    let m = P::GFBITS;
    // Mask form, not `if`: the operands are secret during decoding, so no branch may depend
    // on their bits.
    let mut acc: u32 = 0;
    for i in 0..m {
        let mask = 0u32.wrapping_sub((u32::from(in1) >> i) & 1);
        acc ^= (u32::from(in0) << i) & mask;
    }
    let poly = field_poly::<P>();
    for d in (m..=2 * m - 2).rev() {
        let mask = 0u32.wrapping_sub((acc >> d) & 1);
        acc ^= (poly << (d - m)) & mask;
    }
    (acc & ((1u32 << m) - 1)) as Gf
}

/// Inverse in GF(2^m) by `x^(2^m - 2)`; zero maps to zero, as in the reference.
fn gf_inv<P: McParams>(input: Gf) -> Gf {
    let mut e: u32 = (1u32 << P::GFBITS) - 2;
    let mut r: Gf = 1;
    let mut b = input;
    while e > 0 {
        if e & 1 == 1 {
            r = gf_mul::<P>(r, b);
        }
        b = gf_mul::<P>(b, b);
        e >>= 1;
    }
    r
}

/// `num / den` in GF(2^m).
fn gf_frac<P: McParams>(den: Gf, num: Gf) -> Gf {
    gf_mul::<P>(gf_inv::<P>(den), num)
}

/// Product of two polynomials of degree below `t`, reduced by [`McParams::REDUCE`].
fn gf_poly_mul<P: McParams>(out: &mut [Gf], in0: &[Gf], in1: &[Gf]) {
    let t = P::SYS_T;
    let mut prod = vec![0 as Gf; t * 2 - 1];
    for i in 0..t {
        for j in 0..t {
            prod[i + j] ^= gf_mul::<P>(in0[i], in1[j]);
        }
    }
    for i in (t..=t * 2 - 2).rev() {
        for &(k, c) in P::REDUCE {
            let v = gf_mul::<P>(prod[i], c);
            prod[i - t + k] ^= v;
        }
    }
    out[..t].copy_from_slice(&prod[..t]);
}

// ---- Goppa polynomial (sk_gen.c) ---------------------------------------------------

/// Minimal polynomial of `f` (`genpoly_gen`). `None` when the Gaussian elimination is
/// not systematic, in which case the caller draws new randomness.
fn genpoly_gen<P: McParams>(f: &[Gf]) -> Option<Vec<Gf>> {
    let t = P::SYS_T;
    let mut mat = vec![vec![0 as Gf; t]; t + 1];
    mat[0][0] = 1;
    for i in 0..t {
        mat[1][i] = f[i];
    }
    for j in 2..=t {
        let (prev, cur) = mat.split_at_mut(j);
        gf_poly_mul::<P>(&mut cur[0], &prev[j - 1], f);
    }

    for j in 0..t {
        for k in j + 1..t {
            let mask = gf_iszero(mat[j][j]);
            for c in j..t + 1 {
                mat[c][j] ^= mat[c][k] & mask;
            }
        }
        if mat[j][j] == 0 {
            return None;
        }
        let inv = gf_inv::<P>(mat[j][j]);
        for c in j..t + 1 {
            mat[c][j] = gf_mul::<P>(mat[c][j], inv);
        }
        for k in 0..t {
            if k != j {
                let tt = mat[j][k];
                for c in j..t + 1 {
                    let prod = gf_mul::<P>(mat[c][j], tt);
                    mat[c][k] ^= prod;
                }
            }
        }
    }
    Some(mat[t][..t].to_vec())
}

// ---- Evaluation and syndromes (root.c, synd.c) -------------------------------------

/// `f(a)` for `f` of degree at most `SYS_T` given as `SYS_T + 1` coefficients.
fn eval<P: McParams>(f: &[Gf], a: Gf) -> Gf {
    let t = P::SYS_T;
    let mut r = f[t];
    for i in (0..t).rev() {
        r = gf_mul::<P>(r, a);
        r ^= f[i];
    }
    r
}

fn root<P: McParams>(out: &mut [Gf], f: &[Gf], l: &[Gf]) {
    for i in 0..P::SYS_N {
        out[i] = eval::<P>(f, l[i]);
    }
}

/// Syndrome of the word `r` (bit-packed) under the Goppa code `(f, L)`.
fn synd<P: McParams>(out: &mut [Gf], f: &[Gf], l: &[Gf], r: &[u8]) {
    let two_t = 2 * P::SYS_T;
    for v in out.iter_mut().take(two_t) {
        *v = 0;
    }
    for i in 0..P::SYS_N {
        let c = Gf::from((r[i / 8] >> (i % 8)) & 1);
        let e = eval::<P>(f, l[i]);
        let mut e_inv = gf_inv::<P>(gf_mul::<P>(e, e));
        for v in out.iter_mut().take(two_t) {
            *v ^= gf_mul::<P>(e_inv, c);
            e_inv = gf_mul::<P>(e_inv, l[i]);
        }
    }
}

// ---- Berlekamp-Massey (bm.c) -------------------------------------------------------

fn bm<P: McParams>(out: &mut [Gf], s: &[Gf]) {
    let t = P::SYS_T;
    let mut l: u16 = 0;
    let mut tt = vec![0 as Gf; t + 1];
    let mut c = vec![0 as Gf; t + 1];
    let mut b = vec![0 as Gf; t + 1];
    let mut bb: Gf = 1;

    b[1] = 1;
    c[0] = 1;

    for nn in 0..2 * t {
        let n = nn as u16;
        let mut d: Gf = 0;
        for i in 0..=core::cmp::min(nn, t) {
            d ^= gf_mul::<P>(c[i], s[nn - i]);
        }

        let mut mne = d;
        mne = mne.wrapping_sub(1);
        mne >>= 15;
        mne = mne.wrapping_sub(1);
        let mut mle = n;
        mle = mle.wrapping_sub(2u16.wrapping_mul(l));
        mle >>= 15;
        mle = mle.wrapping_sub(1);
        mle &= mne;

        tt.copy_from_slice(&c);
        let f = gf_frac::<P>(bb, d);
        for i in 0..=t {
            c[i] ^= gf_mul::<P>(f, b[i]) & mne;
        }
        l = (l & !mle) | (n.wrapping_add(1).wrapping_sub(l) & mle);
        for i in 0..=t {
            b[i] = (b[i] & !mle) | (tt[i] & mle);
        }
        bb = (bb & !mle) | (d & mle);
        for i in (1..=t).rev() {
            b[i] = b[i - 1];
        }
        b[0] = 0;
    }
    for i in 0..=t {
        out[i] = c[t - i];
    }
}

// ---- Benes network (benes.c, transpose.c) ------------------------------------------

fn transpose_64x64(input: &[u64; 64]) -> [u64; 64] {
    const MASKS: [[u64; 2]; 6] = [
        [0x5555_5555_5555_5555, 0xAAAA_AAAA_AAAA_AAAA],
        [0x3333_3333_3333_3333, 0xCCCC_CCCC_CCCC_CCCC],
        [0x0F0F_0F0F_0F0F_0F0F, 0xF0F0_F0F0_F0F0_F0F0],
        [0x00FF_00FF_00FF_00FF, 0xFF00_FF00_FF00_FF00],
        [0x0000_FFFF_0000_FFFF, 0xFFFF_0000_FFFF_0000],
        [0x0000_0000_FFFF_FFFF, 0xFFFF_FFFF_0000_0000],
    ];
    let mut out = *input;
    for d in (0..6).rev() {
        let s = 1usize << d;
        let mut i = 0;
        while i < 64 {
            for j in i..i + s {
                let x = (out[j] & MASKS[d][0]) | ((out[j + s] & MASKS[d][0]) << s);
                let y = ((out[j] & MASKS[d][1]) >> s) | (out[j + s] & MASKS[d][1]);
                out[j] = x;
                out[j + s] = y;
            }
            i += s * 2;
        }
    }
    out
}

fn benes_layer(data: &mut [u64; 64], bits: &[u64; 64], lgs: usize) {
    let s = 1usize << lgs;
    let mut k = 0usize;
    let mut i = 0usize;
    while i < 64 {
        for j in i..i + s {
            let d = (data[j] ^ data[j + s]) & bits[k];
            k += 1;
            data[j] ^= d;
            data[j + s] ^= d;
        }
        i += s * 2;
    }
}

/// Apply the 12-bit Benes network (one 64x64 plane) with control bits `bits` to the 512-byte
/// word `r`, forward direction.
fn apply_benes_12(r: &mut [u8], bits: &[u8]) {
    let mut bs = [0u64; 64];
    for (i, v) in bs.iter_mut().enumerate() {
        *v = load8(&r[i * 8..]);
    }
    let mut cond_ptr = 0usize;
    let mut cond = [0u64; 64];

    bs = transpose_64x64(&bs);
    for low in 0..=5 {
        for (i, v) in cond.iter_mut().enumerate() {
            *v = u64::from(load4(&bits[cond_ptr + i * 4..]));
        }
        cond = transpose_64x64(&cond);
        benes_layer(&mut bs, &cond, low);
        cond_ptr += 256;
    }
    bs = transpose_64x64(&bs);
    for low in 0..=5 {
        for i in 0..32 {
            cond[i] = load8(&bits[cond_ptr + i * 8..]);
        }
        benes_layer(&mut bs, &cond, low);
        cond_ptr += 256;
    }
    for low in (0..=4).rev() {
        for i in 0..32 {
            cond[i] = load8(&bits[cond_ptr + i * 8..]);
        }
        benes_layer(&mut bs, &cond, low);
        cond_ptr += 256;
    }
    bs = transpose_64x64(&bs);
    for low in (0..=5).rev() {
        for (i, v) in cond.iter_mut().enumerate() {
            *v = u64::from(load4(&bits[cond_ptr + i * 4..]));
        }
        cond = transpose_64x64(&cond);
        benes_layer(&mut bs, &cond, low);
        cond_ptr += 256;
    }
    bs = transpose_64x64(&bs);
    for (i, v) in bs.iter().enumerate() {
        store8(&mut r[i * 8..], *v);
    }
}

/// Layer over two planes of 64 words each (`layer_in` in the 13-bit reference): two bits per
/// pair, one for each plane.
fn benes_layer_in(data: &mut [[u64; 64]; 2], bits: &[u64; 64], lgs: usize) {
    let s = 1usize << lgs;
    let mut k = 0usize;
    let mut i = 0usize;
    while i < 64 {
        for j in i..i + s {
            let d0 = (data[0][j] ^ data[0][j + s]) & bits[k];
            k += 1;
            data[0][j] ^= d0;
            data[0][j + s] ^= d0;
            let d1 = (data[1][j] ^ data[1][j + s]) & bits[k];
            k += 1;
            data[1][j] ^= d1;
            data[1][j + s] ^= d1;
        }
        i += s * 2;
    }
}

/// Layer over one flat array of 128 words (`layer_ex`, the outer layers of the 13-bit
/// reference). `data` is the two transposed planes laid end to end.
fn benes_layer_ex(data: &mut [u64], bits: &[u64; 64], lgs: usize) {
    let s = 1usize << lgs;
    let mut k = 0usize;
    let mut i = 0usize;
    while i < 128 {
        for j in i..i + s {
            let d = (data[j] ^ data[j + s]) & bits[k];
            k += 1;
            data[j] ^= d;
            data[j + s] ^= d;
        }
        i += s * 2;
    }
}

/// Apply the 13-bit Benes network (two planes of 64x64) with control bits `bits` to the
/// 1024-byte word `r`, forward direction (`apply_benes` in the 13-bit reference).
fn apply_benes_13(r: &mut [u8], bits: &[u8]) {
    let mut r_int_v = [[0u64; 64]; 2];
    let mut r_int_h = [[0u64; 64]; 2];
    let mut b_int_v = [0u64; 64];
    let mut bp = 0usize;

    for i in 0..64 {
        r_int_v[0][i] = load8(&r[i * 16..]);
        r_int_v[1][i] = load8(&r[i * 16 + 8..]);
    }
    r_int_h[0] = transpose_64x64(&r_int_v[0]);
    r_int_h[1] = transpose_64x64(&r_int_v[1]);

    // The outer layers work on the two transposed planes as one array of 128 words.
    let mut flat = [0u64; 128];
    for iter in 0..=6 {
        for i in 0..64 {
            b_int_v[i] = load8(&bits[bp..]);
            bp += 8;
        }
        let b_int_h = transpose_64x64(&b_int_v);
        flat[..64].copy_from_slice(&r_int_h[0]);
        flat[64..].copy_from_slice(&r_int_h[1]);
        benes_layer_ex(&mut flat, &b_int_h, iter);
        r_int_h[0].copy_from_slice(&flat[..64]);
        r_int_h[1].copy_from_slice(&flat[64..]);
    }

    r_int_v[0] = transpose_64x64(&r_int_h[0]);
    r_int_v[1] = transpose_64x64(&r_int_h[1]);

    for iter in 0..=5 {
        for i in 0..64 {
            b_int_v[i] = load8(&bits[bp..]);
            bp += 8;
        }
        benes_layer_in(&mut r_int_v, &b_int_v, iter);
    }
    for iter in (0..=4).rev() {
        for i in 0..64 {
            b_int_v[i] = load8(&bits[bp..]);
            bp += 8;
        }
        benes_layer_in(&mut r_int_v, &b_int_v, iter);
    }

    r_int_h[0] = transpose_64x64(&r_int_v[0]);
    r_int_h[1] = transpose_64x64(&r_int_v[1]);

    for iter in (0..=6).rev() {
        for i in 0..64 {
            b_int_v[i] = load8(&bits[bp..]);
            bp += 8;
        }
        let b_int_h = transpose_64x64(&b_int_v);
        flat[..64].copy_from_slice(&r_int_h[0]);
        flat[64..].copy_from_slice(&r_int_h[1]);
        benes_layer_ex(&mut flat, &b_int_h, iter);
        r_int_h[0].copy_from_slice(&flat[..64]);
        r_int_h[1].copy_from_slice(&flat[64..]);
    }

    r_int_v[0] = transpose_64x64(&r_int_h[0]);
    r_int_v[1] = transpose_64x64(&r_int_h[1]);

    for i in 0..64 {
        store8(&mut r[i * 16..], r_int_v[0][i]);
        store8(&mut r[i * 16 + 8..], r_int_v[1][i]);
    }
}

/// The support `L` of the code: `L[i] = (apply Benes control bits c to bitrev(i))`.
fn support_gen<P: McParams>(s: &mut [Gf], c: &[u8]) {
    let plane = P::Q / 8;
    let mut l = vec![vec![0u8; plane]; P::GFBITS as usize];
    for i in 0..P::Q {
        let a = bitrev::<P>(i as Gf);
        for j in 0..P::GFBITS as usize {
            l[j][i / 8] |= (((a >> j) & 1) as u8) << (i % 8);
        }
    }
    for lj in l.iter_mut() {
        if P::GFBITS == 12 {
            apply_benes_12(lj, c);
        } else {
            apply_benes_13(lj, c);
        }
    }
    for i in 0..P::SYS_N {
        let mut v: Gf = 0;
        for j in (0..P::GFBITS as usize).rev() {
            v <<= 1;
            v |= Gf::from((l[j][i / 8] >> (i % 8)) & 1);
        }
        s[i] = v;
    }
}

// ---- Control bits (controlbits.c) --------------------------------------------------

/// Constant-time bitonic sort of `v` (length a power of two) into ascending order.
///
/// The comparison network is fixed by the length, and each compare-exchange selects its
/// result with a mask, so neither the running time nor the memory access pattern depends on
/// the values. The values here are secret (they come from the secret permutation), which is
/// why Rust's data-dependent `sort_unstable` is not used. Values are widened to `i128`, so the
/// comparison is exact for the full `i64` range.
fn ct_sort_i64(v: &mut [i64]) {
    let n = v.len();
    if n < 2 {
        return;
    }
    debug_assert!(n.is_power_of_two());
    let mut k = 2usize;
    while k <= n {
        let mut j = k / 2;
        while j > 0 {
            for i in 0..n {
                let l = i ^ j;
                if l > i {
                    // Public indices decide the direction; the swap decision is masked.
                    let ascending = (i & k) == 0;
                    let a = v[i];
                    let b = v[l];
                    let lt_ba = (((i128::from(b) - i128::from(a)) >> 127) & 1) as i64; // b < a
                    let lt_ab = (((i128::from(a) - i128::from(b)) >> 127) & 1) as i64; // a < b
                    let swap = if ascending { lt_ba } else { lt_ab };
                    let mask = 0i64.wrapping_sub(swap);
                    let diff = (a ^ b) & mask;
                    v[i] = a ^ diff;
                    v[l] = b ^ diff;
                }
            }
            j /= 2;
        }
        k *= 2;
    }
}

/// Constant-time ascending sort of `i32` values (see [`ct_sort_i64`]).
fn ct_sort_i32(v: &mut [i32]) {
    let mut w: Vec<i64> = v.iter().map(|&x| i64::from(x)).collect();
    ct_sort_i64(&mut w);
    for (dst, src) in v.iter_mut().zip(w) {
        *dst = src as i32;
    }
}

/// Constant-time ascending sort of `u64` values below 2^63 (see [`ct_sort_i64`]).
fn ct_sort_u64(v: &mut [u64]) {
    let mut w: Vec<i64> = v.iter().map(|&x| x as i64).collect();
    ct_sort_i64(&mut w);
    for (dst, src) in v.iter_mut().zip(w) {
        *dst = src as u64;
    }
}

fn i32_min(a: i32, b: i32) -> i32 {
    if a < b {
        a
    } else {
        b
    }
}

/// One level of the Nassimi-Sahni recursion. Arithmetic is 32-bit wrapping, as in the C.
fn cbrecursion(out: &mut [u8], mut pos: i64, step: i64, pi: &[i16], w: i64, n: usize) {
    if w == 1 {
        out[(pos >> 3) as usize] ^= (pi[0] << (pos & 7)) as u8;
        return;
    }

    let mut a = vec![0i32; n];
    let mut b = vec![0i32; n];
    let mut q = vec![0i16; n];

    for x in 0..n {
        a[x] = ((i32::from(pi[x]) ^ 1) << 16) | i32::from(pi[x ^ 1]);
    }
    ct_sort_i32(&mut a);

    for x in 0..n {
        let ax = a[x];
        let px = ax & 0xffff;
        let cx = i32_min(px, x as i32);
        b[x] = (px << 16) | cx;
    }

    for x in 0..n {
        a[x] = (a[x] << 16) | x as i32;
    }
    ct_sort_i32(&mut a);

    for x in 0..n {
        a[x] = (a[x] << 16).wrapping_add(b[x] >> 16);
    }
    ct_sort_i32(&mut a);

    if w <= 10 {
        for x in 0..n {
            b[x] = ((a[x] & 0xffff) << 10) | (b[x] & 0x3ff);
        }
        for _i in 1..w - 1 {
            for x in 0..n {
                a[x] = ((b[x] & !0x3ff) << 6) | x as i32;
            }
            ct_sort_i32(&mut a);
            for x in 0..n {
                a[x] = (a[x] << 20) | b[x];
            }
            ct_sort_i32(&mut a);
            for x in 0..n {
                let ppcpx = a[x] & 0xfffff;
                let ppcx = (a[x] & 0xffc00) | (b[x] & 0x3ff);
                b[x] = i32_min(ppcx, ppcpx);
            }
        }
        for x in 0..n {
            b[x] &= 0x3ff;
        }
    } else {
        for x in 0..n {
            b[x] = (a[x] << 16) | (b[x] & 0xffff);
        }
        for i in 1..w - 1 {
            for x in 0..n {
                a[x] = (b[x] & !0xffff) | x as i32;
            }
            ct_sort_i32(&mut a);
            for x in 0..n {
                a[x] = (a[x] << 16) | (b[x] & 0xffff);
            }
            if i < w - 2 {
                for x in 0..n {
                    b[x] = (a[x] & !0xffff) | (b[x] >> 16);
                }
                ct_sort_i32(&mut b);
                for x in 0..n {
                    b[x] = (b[x] << 16) | (a[x] & 0xffff);
                }
            }
            ct_sort_i32(&mut a);
            for x in 0..n {
                let cpx = (b[x] & !0xffff) | (a[x] & 0xffff);
                b[x] = i32_min(b[x], cpx);
            }
        }
        for x in 0..n {
            b[x] &= 0xffff;
        }
    }

    for x in 0..n {
        a[x] = (i32::from(pi[x]) << 16).wrapping_add(x as i32);
    }
    ct_sort_i32(&mut a);

    let half = n / 2;
    for j in 0..half {
        let x = 2 * j;
        let fj = b[x] & 1;
        let fx = x as i32 + fj;
        let fx1 = fx ^ 1;
        out[(pos >> 3) as usize] ^= (fj << (pos & 7)) as u8;
        pos += step;
        b[x] = (a[x] << 16) | fx;
        b[x + 1] = (a[x + 1] << 16) | fx1;
    }

    ct_sort_i32(&mut b);

    pos += (2 * w - 3) * step * half as i64;

    for k in 0..half {
        let y = 2 * k;
        let lk = b[y] & 1;
        let ly = y as i32 + lk;
        let ly1 = ly ^ 1;
        out[(pos >> 3) as usize] ^= (lk << (pos & 7)) as u8;
        pos += step;
        a[y] = (ly << 16) | (b[y] & 0xffff);
        a[y + 1] = (ly1 << 16) | (b[y + 1] & 0xffff);
    }

    ct_sort_i32(&mut a);

    pos -= (2 * w - 2) * step * half as i64;

    for j in 0..half {
        q[j] = ((a[2 * j] & 0xffff) >> 1) as i16;
        q[j + half] = ((a[2 * j + 1] & 0xffff) >> 1) as i16;
    }

    cbrecursion(out, pos, step * 2, &q[..half], w - 1, half);
    cbrecursion(out, pos + step, step * 2, &q[half..], w - 1, half);
}

/// Apply the control bits `cb` (stride `2^s`) to `p` (`controlbits.c` `layer`).
fn cb_layer(p: &mut [i16], cb: &[u8], s: u32, n: usize) {
    let stride = 1usize << s;
    let mut index = 0usize;
    let mut i = 0usize;
    while i < n {
        for j in 0..stride {
            let mut d = p[i + j] ^ p[i + j + stride];
            let m = -(((cb[index >> 3] >> (index & 7)) & 1) as i16);
            d &= m;
            p[i + j] ^= d;
            p[i + j + stride] ^= d;
            index += 1;
        }
        i += stride * 2;
    }
}

/// Control bits realising the permutation `pi` of `{0..n-1}` (`n = 2^w`), written to `out`.
fn controlbitsfrompermutation(out: &mut [u8], pi: &[i16], w: i64, n: usize) {
    let w_us = w as usize;
    loop {
        for v in out
            .iter_mut()
            .take(((2 * w as usize - 1) * n / 2).div_ceil(8))
        {
            *v = 0;
        }
        cbrecursion(out, 0, 1, pi, w, n);

        let mut pi_test: Vec<i16> = (0..n as i16).collect();
        let mut ptr = 0usize;
        for i in 0..w_us {
            cb_layer(&mut pi_test, &out[ptr..], i as u32, n);
            ptr += n >> 4;
        }
        for i in (0..=w_us - 2).rev() {
            cb_layer(&mut pi_test, &out[ptr..], i as u32, n);
            ptr += n >> 4;
        }
        if pi_test[..n] == pi[..n] {
            break;
        }
    }
}

// ---- Public-key generation (pk_gen.c) ----------------------------------------------

/// Systematic public matrix from the Goppa polynomial `irr` and the permutation `perm`.
/// `None` when the permutation repeats or the matrix is not systematic.
fn pk_gen<P: McParams>(pk: &mut [u8], irr: &[u8], perm: &[u32], pi: &mut [i16]) -> Option<()> {
    let t = P::SYS_T;
    let q = P::Q;
    let n = P::SYS_N;
    let mut g = vec![0 as Gf; t + 1];
    g[t] = 1;
    for i in 0..t {
        g[i] = load_gf::<P>(&irr[2 * i..]);
    }

    let mut buf = vec![0u64; q];
    for i in 0..q {
        buf[i] = (u64::from(perm[i]) << 31) | i as u64;
    }
    ct_sort_u64(&mut buf);
    for i in 1..q {
        if (buf[i - 1] >> 31) == (buf[i] >> 31) {
            return None;
        }
    }
    for i in 0..q {
        pi[i] = (buf[i] & u64::from(P::GFMASK)) as i16;
    }
    let mut l = vec![0 as Gf; n];
    for i in 0..n {
        l[i] = bitrev::<P>(pi[i] as Gf);
    }

    let mut inv = vec![0 as Gf; n];
    root::<P>(&mut inv, &g, &l);
    for v in inv.iter_mut() {
        *v = gf_inv::<P>(*v);
    }

    let mut mat = vec![vec![0u8; n / 8]; P::PK_NROWS];
    for i in 0..t {
        let mut j = 0;
        while j < n {
            for k in 0..P::GFBITS as usize {
                let mut b: u8 = 0;
                for tt in (0..8).rev() {
                    b = (b << 1) | (((inv[j + tt] >> k) & 1) as u8);
                }
                mat[i * P::GFBITS as usize + k][j / 8] = b;
            }
            j += 8;
        }
        for j in 0..n {
            inv[j] = gf_mul::<P>(inv[j], l[j]);
        }
    }

    // Gaussian elimination to systematic form.
    let nrows = P::PK_NROWS;
    for i in 0..nrows.div_ceil(8) {
        for j in 0..8 {
            let row = i * 8 + j;
            if row >= nrows {
                break;
            }
            for k in row + 1..nrows {
                let mut mask = mat[row][i] ^ mat[k][i];
                mask >>= j;
                mask &= 1;
                mask = 0u8.wrapping_sub(mask);
                for c in 0..n / 8 {
                    let v = mat[k][c] & mask;
                    mat[row][c] ^= v;
                }
            }
            if (mat[row][i] >> j) & 1 == 0 {
                return None;
            }
            for k in 0..nrows {
                if k != row {
                    let mut mask = mat[k][i] >> j;
                    mask &= 1;
                    mask = 0u8.wrapping_sub(mask);
                    for c in 0..n / 8 {
                        let v = mat[row][c] & mask;
                        mat[k][c] ^= v;
                    }
                }
            }
        }
    }

    let rb = P::PK_ROW_BYTES;
    if P::SHIFTED_PK {
        // Rows start at bit PK_NROWS % 8 of byte PK_NROWS / 8 (reference pk_gen, 6960119).
        let tail = (nrows % 8) as u32;
        let mut pk_ptr = 0usize;
        for i in 0..nrows {
            let mut j = (nrows - 1) / 8;
            while j < n / 8 - 1 {
                pk[pk_ptr] = (mat[i][j] >> tail) | (mat[i][j + 1] << (8 - tail));
                pk_ptr += 1;
                j += 1;
            }
            pk[pk_ptr] = mat[i][j] >> tail;
            pk_ptr += 1;
        }
    } else {
        let off = nrows / 8;
        for i in 0..nrows {
            pk[i * rb..(i + 1) * rb].copy_from_slice(&mat[i][off..off + rb]);
        }
    }
    Some(())
}

// ---- Encryption (encrypt.c) --------------------------------------------------------

/// Error vector of weight `t`, drawn from `rng` (`gen_e`).
fn gen_e<P: McParams>(rng: &mut impl CryptoRng) -> Result<Vec<u8>> {
    let t = P::SYS_T;
    let mut ind = vec![0u16; t];
    let short = P::SHORT_GEN_E;
    loop {
        // The 8192128 reference draws t values (2t bytes) and skips the range check, which
        // is vacuous there because 2^13 = n. The others draw 2t values and keep the first t
        // that are below n.
        let draws = if short { t } else { 2 * t };
        let mut bytes = vec![0u8; draws * 2];
        rng.try_fill_bytes(&mut bytes)?;
        let mut nums = vec![0u16; draws];
        for i in 0..draws {
            nums[i] = load_gf::<P>(&bytes[i * 2..]);
        }

        if short {
            ind.copy_from_slice(&nums);
        } else {
            let mut count = 0usize;
            let mut i = 0usize;
            while i < t * 2 && count < t {
                if nums[i] < P::SYS_N as u16 {
                    ind[count] = nums[i];
                    count += 1;
                }
                i += 1;
            }
            if count < t {
                continue;
            }
        }

        let mut eq = false;
        for i in 1..t {
            for j in 0..i {
                if ind[i] == ind[j] {
                    eq = true;
                }
            }
        }
        if !eq {
            break;
        }
    }

    let mut val = vec![0u8; t];
    for j in 0..t {
        val[j] = 1 << (ind[j] & 7);
    }
    let mut e = vec![0u8; P::SYS_N / 8];
    for i in 0..P::SYS_N / 8 {
        for j in 0..t {
            let x = i as u32 ^ u32::from(ind[j] >> 3);
            let mut mask = x.wrapping_sub(1) >> 31;
            mask = 0u32.wrapping_sub(mask);
            let mask = (mask & 0xFF) as u8;
            e[i] |= val[j] & mask;
        }
    }
    Ok(e)
}

/// Syndrome `H e` of the error vector `e` under the public matrix `pk`.
fn syndrome<P: McParams>(pk: &[u8], e: &[u8]) -> Vec<u8> {
    let rb = P::PK_ROW_BYTES;
    let mut s = vec![0u8; P::SYND_BYTES];
    let mut pk_ptr = 0usize;
    for i in 0..P::PK_NROWS {
        let mut row = vec![0u8; P::SYS_N / 8];
        let off = P::SYS_N / 8 - rb;
        row[off..].copy_from_slice(&pk[pk_ptr..pk_ptr + rb]);
        if P::SHIFTED_PK {
            // Undo the bit shift of the stored rows (reference syndrome, 6960119).
            let tail = (P::PK_NROWS % 8) as u32;
            let mut j = P::SYS_N / 8 - 1;
            while j >= off {
                row[j] = (row[j] << tail) | (row[j - 1] >> (8 - tail));
                j -= 1;
            }
        }
        row[i / 8] |= 1 << (i % 8);

        let mut b: u8 = 0;
        for j in 0..P::SYS_N / 8 {
            b ^= row[j] & e[j];
        }
        b ^= b >> 4;
        b ^= b >> 2;
        b ^= b >> 1;
        b &= 1;
        s[i / 8] |= b << (i % 8);
        pk_ptr += rb;
    }
    s
}

// ---- Decryption (decrypt.c) --------------------------------------------------------

/// Berlekamp decoder. Returns `(e, ok)`: `ok` is true when the decoded word is a valid
/// error vector of weight `t` with the right syndrome.
fn decrypt<P: McParams>(sk_irr_cond: &[u8], c: &[u8]) -> (Vec<u8>, bool) {
    let t = P::SYS_T;
    let mut r = vec![0u8; P::SYS_N / 8];
    r[..P::SYND_BYTES].copy_from_slice(&c[..P::SYND_BYTES]);

    let mut g = vec![0 as Gf; t + 1];
    for i in 0..t {
        g[i] = load_gf::<P>(&sk_irr_cond[2 * i..]);
    }
    g[t] = 1;

    let cond = &sk_irr_cond[P::IRR_BYTES..P::IRR_BYTES + P::COND_BYTES];
    let mut l = vec![0 as Gf; P::SYS_N];
    support_gen::<P>(&mut l, cond);

    let mut s = vec![0 as Gf; 2 * t];
    synd::<P>(&mut s, &g, &l, &r);

    let mut locator = vec![0 as Gf; t + 1];
    bm::<P>(&mut locator, &s);

    let mut images = vec![0 as Gf; P::SYS_N];
    root::<P>(&mut images, &locator, &l);

    let mut e = vec![0u8; P::SYS_N / 8];
    let mut w: u16 = 0;
    for i in 0..P::SYS_N {
        let tt = gf_iszero(images[i]) & 1;
        e[i / 8] |= (tt << (i % 8)) as u8;
        w = w.wrapping_add(tt);
    }

    let mut s_cmp = vec![0 as Gf; 2 * t];
    synd::<P>(&mut s_cmp, &g, &l, &e);

    let mut check: u16 = w;
    check ^= t as u16;
    for i in 0..2 * t {
        check |= s[i] ^ s_cmp[i];
    }
    check = check.wrapping_sub(1);
    check >>= 15;
    // The reference returns 0 on success: check is 1 exactly when the word decodes.
    (e, (check ^ 1) == 0)
}

// ---- Key generation, encapsulation, decapsulation (operations.c) -------------------

/// Keypair from the 32-byte `delta` (`crypto_kem_keypair` with its randomness drawn).
/// Returns `(pk, sk)`.
fn keypair_from_delta<P: McParams>(delta: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut seed = vec![0u8; 33];
    seed[0] = 64;
    seed[1..].copy_from_slice(delta);

    let t = P::SYS_T;
    let q = P::Q;
    let r_len = P::S_LEN + q * 4 + t * 2 + 32;
    let mut pk = vec![0u8; P::PUBLIC_KEY_LEN];
    let mut sk = vec![0u8; P::SECRET_KEY_LEN];
    loop {
        let mut r = vec![0u8; r_len];
        shake256_into(&mut r, &seed);

        let mut skp = 0usize;
        sk[skp..skp + 32].copy_from_slice(&seed[1..33]);
        skp += 32 + 8;
        seed[1..33].copy_from_slice(&r[r_len - 32..]);

        // Goppa polynomial from the random bytes.
        let mut rp = r_len - 32;
        rp -= t * 2;
        let mut f = vec![0 as Gf; t];
        for i in 0..t {
            f[i] = load_gf::<P>(&r[rp + i * 2..]);
        }
        let irr = match genpoly_gen::<P>(&f) {
            Some(irr) => irr,
            None => continue,
        };
        for i in 0..t {
            store_gf::<P>(&mut sk[skp + i * 2..], irr[i]);
        }
        skp += P::IRR_BYTES;

        // Permutation from the random bytes.
        rp -= q * 4;
        let mut perm = vec![0u32; q];
        for i in 0..q {
            perm[i] = load4(&r[rp + i * 4..]);
        }
        let mut pi = vec![0i16; q];
        let irr_bytes = sk[skp - P::IRR_BYTES..skp].to_vec();
        if pk_gen::<P>(&mut pk, &irr_bytes, &perm, &mut pi).is_none() {
            continue;
        }

        let mut cond = vec![0u8; P::COND_BYTES];
        controlbitsfrompermutation(&mut cond, &pi, P::GFBITS as i64, q);
        sk[skp..skp + P::COND_BYTES].copy_from_slice(&cond);
        skp += P::COND_BYTES;

        // The random string s.
        rp -= P::S_LEN;
        sk[skp..skp + P::S_LEN].copy_from_slice(&r[rp..rp + P::S_LEN]);

        // Positions of the pivots: fixed by the reference.
        store8(&mut sk[32..40], 0xFFFF_FFFF);
        break;
    }
    (pk, sk)
}

/// Keypair for set `P` from the RNG. Returns `(pk, sk)`.
///
/// # Errors
///
/// Returns the RNG's error if it fails.
pub fn keypair<P: McParams>(rng: &mut impl CryptoRng) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut delta = vec![0u8; P::DELTA_LEN];
    rng.try_fill_bytes(&mut delta)?;
    let out = keypair_from_delta::<P>(&delta);
    delta.zeroize();
    Ok(out)
}

/// The padding bits of the last byte of every public-key row are zero (6960119 check).
fn pk_padding_ok<P: McParams>(pk: &[u8]) -> bool {
    let rb = P::PK_ROW_BYTES;
    let mut b = 0u8;
    for i in 0..P::PK_NROWS {
        b |= pk[i * rb + rb - 1];
    }
    (b >> (P::PK_NCOLS % 8)) == 0
}

/// The padding bits of the ciphertext are zero (6960119 check).
fn c_padding_ok<P: McParams>(c: &[u8]) -> bool {
    (c[P::SYND_BYTES - 1] >> (P::PK_NROWS % 8)) == 0
}

/// Encapsulation to `pk` for set `P`: draws the error vector from `rng`. Returns
/// `(ciphertext, shared_secret)`.
///
/// # Errors
///
/// [`Error::InvalidLength`] if `pk` has the wrong length; the RNG's error otherwise.
pub fn encapsulate<P: McParams>(
    pk: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<(Vec<u8>, [u8; SHARED_SECRET_LEN])> {
    if pk.len() != P::PUBLIC_KEY_LEN {
        return Err(Error::InvalidLength);
    }
    if P::PADDING_CHECKS && !pk_padding_ok::<P>(pk) {
        return Err(Error::InvalidEncoding);
    }
    let mut e = gen_e::<P>(rng)?;
    let c = syndrome::<P>(pk, &e);

    let mut one_ec = vec![0u8; 1 + P::SYS_N / 8 + P::SYND_BYTES];
    one_ec[0] = 1;
    one_ec[1..1 + P::SYS_N / 8].copy_from_slice(&e);
    one_ec[1 + P::SYS_N / 8..].copy_from_slice(&c);
    let mut key = [0u8; SHARED_SECRET_LEN];
    shake256_into(&mut key, &one_ec);

    e.zeroize();
    one_ec.zeroize();
    Ok((c, key))
}

/// Decapsulation with implicit rejection for set `P`: a ciphertext that does not decode
/// yields the shared secret derived from the stored random string `s`.
///
/// # Errors
///
/// [`Error::InvalidLength`] if `sk` or `ct` has the wrong length.
pub fn decapsulate<P: McParams>(sk: &[u8], ct: &[u8]) -> Result<[u8; SHARED_SECRET_LEN]> {
    if sk.len() != P::SECRET_KEY_LEN || ct.len() != P::CIPHERTEXT_LEN {
        return Err(Error::InvalidLength);
    }
    let (mut e, ok) = decrypt::<P>(&sk[40..], ct);
    let s_off = 40 + P::IRR_BYTES + P::COND_BYTES;
    let s = &sk[s_off..s_off + P::S_LEN];

    // m = 0xFF on success, 0 on failure: selects e or s byte by byte.
    let mut pre = vec![0u8; 1 + P::SYS_N / 8 + P::SYND_BYTES];
    pre[0] = u8::from(ok);
    // Mask from the success flag without a branch: 0xFF when the word decoded.
    let mm = 0u8.wrapping_sub(u8::from(ok));
    for i in 0..P::SYS_N / 8 {
        pre[1 + i] = (!mm & s[i]) | (mm & e[i]);
    }
    pre[1 + P::SYS_N / 8..].copy_from_slice(&ct[..P::SYND_BYTES]);

    let mut key = [0u8; SHARED_SECRET_LEN];
    shake256_into(&mut key, &pre);
    e.zeroize();
    pre.zeroize();
    // The reference sets the key to all ones when the ciphertext padding bits are not zero.
    if P::PADDING_CHECKS && !c_padding_ok::<P>(ct) {
        key = [0xFF; SHARED_SECRET_LEN];
    }
    Ok(key)
}
