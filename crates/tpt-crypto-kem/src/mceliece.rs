//! Classic McEliece `mceliece348864` (NIST round-4 KEM, GF(2^12), n = 3488, t = 64).
//!
//! Port of the Reference_Implementation in the official submission
//! (`mceliece-20221023`, Classic McEliece team, public domain). Integer semantics follow the C
//! exactly, including the 16-bit wrap-around in `bm` and the 32-bit wrap-around in the
//! control-bit generator. The other parameter sets (460896, 6688128, 6960119, 8192128)
//! are not implemented.
//!
//! Checked against the official `kat_kem.rsp` records for this set: keypair, encapsulation
//! and decapsulation reproduce the public key, secret key, ciphertext and shared secret.
//!
//! Randomness: keypair draws 32 bytes, encapsulation draws 256 bytes per attempt to sample
//! the error vector. The reference's rejection-sampling loop in `gen_e` branches on the
//! sampled positions, as the reference does (it uses declassified masks there).

// The index loops below mirror the reference C one for one; the known-answer tests
// check the result, so the loops are kept rather than rewritten as iterators.
#![allow(clippy::needless_range_loop, clippy::manual_memcpy)]

use alloc::vec;
use alloc::vec::Vec;
use tpt_crypto_core::{CryptoRng, Error, Result, Zeroize};

// ---- Parameters (mceliece348864) ---------------------------------------------------

const GFBITS: u32 = 12;
/// Code length `n`.
const SYS_N: usize = 3488;
/// Error-correction capability `t`.
const SYS_T: usize = 64;
/// `2^GFBITS` field elements.
const Q: usize = 1 << GFBITS;
const GFMASK: u16 = (1 << GFBITS) - 1;
/// Rows of the systematic parity-check matrix: `m * t`.
const PK_NROWS: usize = SYS_T * GFBITS as usize;
/// Columns of the non-identity part: `n - mt`.
const PK_NCOLS: usize = SYS_N - PK_NROWS;
/// Bytes per row of the public matrix.
const PK_ROW_BYTES: usize = PK_NCOLS.div_ceil(8);
/// Bytes of the syndrome (and of the ciphertext).
const SYND_BYTES: usize = PK_NROWS.div_ceil(8);
/// Bytes of the Goppa polynomial in the secret key.
const IRR_BYTES: usize = SYS_T * 2;
/// Bytes of the Benes control bits in the secret key.
const COND_BYTES: usize = (1 << (GFBITS - 4)) * (2 * GFBITS as usize - 1);

/// Public-key length.
pub const PUBLIC_KEY_LEN: usize = 261120;
/// Secret-key length: `delta(32) || pad(8) || irr || cond || s`.
pub const SECRET_KEY_LEN: usize = 40 + IRR_BYTES + COND_BYTES + SYS_N / 8;
/// Ciphertext length.
pub const CIPHERTEXT_LEN: usize = SYND_BYTES;
/// Shared-secret length.
pub const SHARED_SECRET_LEN: usize = 32;

/// Bytes of the random string `s` (the fallback when decapsulation rejects).
const S_LEN: usize = SYS_N / 8;

type Gf = u16;

fn shake256_into(out: &mut [u8], input: &[u8]) {
    tpt_crypto_hash::sha3::shake256(input, out);
}

// ---- Byte helpers (util.c) ---------------------------------------------------------

fn store_gf(dest: &mut [u8], a: Gf) {
    dest[0] = (a & 0xFF) as u8;
    dest[1] = (a >> 8) as u8;
}

fn load_gf(src: &[u8]) -> Gf {
    let a = (u16::from(src[1]) << 8) | u16::from(src[0]);
    a & GFMASK
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

fn bitrev(a: Gf) -> Gf {
    let mut a = ((a & 0x00FF) << 8) | ((a & 0xFF00) >> 8);
    a = ((a & 0x0F0F) << 4) | ((a & 0xF0F0) >> 4);
    a = ((a & 0x3333) << 2) | ((a & 0xCCCC) >> 2);
    a = ((a & 0x5555) << 1) | ((a & 0xAAAA) >> 1);
    a >> 4
}

// ---- Field arithmetic (gf.c) -------------------------------------------------------

/// Zero for nonzero input; for zero input the result is `0x1FFF` (callers mask with `& 1`
/// or use it as a mask, as the reference does).
fn gf_iszero(a: Gf) -> Gf {
    let t = u32::from(a).wrapping_sub(1) >> 19;
    t as Gf
}

fn gf_mul(in0: Gf, in1: Gf) -> Gf {
    let t0 = u32::from(in0);
    let t1 = u32::from(in1);
    let mut tmp = t0 * (t1 & 1);
    for i in 1..GFBITS {
        tmp ^= t0 * (t1 & (1 << i));
    }
    let mut t = tmp & 0x7FC000;
    tmp ^= t >> 9;
    tmp ^= t >> 12;
    t = tmp & 0x3000;
    tmp ^= t >> 9;
    tmp ^= t >> 12;
    (tmp & ((1 << GFBITS) - 1)) as Gf
}

fn gf_sq(input: Gf) -> Gf {
    const B: [u32; 4] = [0x5555_5555, 0x3333_3333, 0x0F0F_0F0F, 0x00FF_00FF];
    let mut x = u32::from(input);
    x = (x | (x << 8)) & B[3];
    x = (x | (x << 4)) & B[2];
    x = (x | (x << 2)) & B[1];
    x = (x | (x << 1)) & B[0];
    let mut t = x & 0x7FC000;
    x ^= t >> 9;
    x ^= t >> 12;
    t = x & 0x3000;
    x ^= t >> 9;
    x ^= t >> 12;
    (x & ((1 << GFBITS) - 1)) as Gf
}

fn gf_inv(input: Gf) -> Gf {
    let mut out = gf_sq(input);
    let tmp_11 = gf_mul(out, input);
    out = gf_sq(tmp_11);
    out = gf_sq(out);
    let tmp_1111 = gf_mul(out, tmp_11);
    out = gf_sq(tmp_1111);
    out = gf_sq(out);
    out = gf_sq(out);
    out = gf_sq(out);
    out = gf_mul(out, tmp_1111);
    out = gf_sq(out);
    out = gf_sq(out);
    out = gf_mul(out, tmp_11);
    out = gf_sq(out);
    out = gf_mul(out, input);
    gf_sq(out)
}

/// `out = in0 * in1` in GF(2^12)[x] / (x^t + ...), the reduction used by the reference.
fn gf_poly_mul(out: &mut [Gf], in0: &[Gf], in1: &[Gf]) {
    let mut prod = [0 as Gf; SYS_T * 2 - 1];
    for i in 0..SYS_T {
        for j in 0..SYS_T {
            prod[i + j] ^= gf_mul(in0[i], in1[j]);
        }
    }
    for i in (SYS_T..=SYS_T * 2 - 2).rev() {
        prod[i - SYS_T + 3] ^= prod[i];
        prod[i - SYS_T + 1] ^= prod[i];
        prod[i - SYS_T] ^= gf_mul(prod[i], 2);
    }
    out[..SYS_T].copy_from_slice(&prod[..SYS_T]);
}

// ---- Goppa polynomial (sk_gen.c) ---------------------------------------------------

/// Minimal polynomial of `f` (`genpoly_gen`). `None` when the Gaussian elimination is
/// not systematic, in which case the caller draws new randomness.
fn genpoly_gen(f: &[Gf]) -> Option<[Gf; SYS_T]> {
    let mut mat = [[0 as Gf; SYS_T]; SYS_T + 1];
    mat[0][0] = 1;
    for i in 0..SYS_T {
        mat[1][i] = f[i];
    }
    for j in 2..=SYS_T {
        let (prev, cur) = mat.split_at_mut(j);
        gf_poly_mul(&mut cur[0], &prev[j - 1], f);
    }

    for j in 0..SYS_T {
        for k in j + 1..SYS_T {
            let mask = gf_iszero(mat[j][j]);
            for c in j..SYS_T + 1 {
                mat[c][j] ^= mat[c][k] & mask;
            }
        }
        if mat[j][j] == 0 {
            return None;
        }
        let inv = gf_inv(mat[j][j]);
        for c in j..SYS_T + 1 {
            mat[c][j] = gf_mul(mat[c][j], inv);
        }
        for k in 0..SYS_T {
            if k != j {
                let t = mat[j][k];
                for c in j..SYS_T + 1 {
                    let prod = gf_mul(mat[c][j], t);
                    mat[c][k] ^= prod;
                }
            }
        }
    }
    let mut out = [0 as Gf; SYS_T];
    out.copy_from_slice(&mat[SYS_T][..SYS_T]);
    Some(out)
}

// ---- Evaluation and syndromes (root.c, synd.c) -------------------------------------

/// `f(a)` for `f` of degree at most `SYS_T` given as `SYS_T + 1` coefficients.
fn eval(f: &[Gf], a: Gf) -> Gf {
    let mut r = f[SYS_T];
    for i in (0..SYS_T).rev() {
        r = gf_mul(r, a);
        r ^= f[i];
    }
    r
}

fn root(out: &mut [Gf], f: &[Gf], l: &[Gf]) {
    for i in 0..SYS_N {
        out[i] = eval(f, l[i]);
    }
}

/// Syndrome of the word `r` (bit-packed) under the Goppa code `(f, L)`.
fn synd(out: &mut [Gf], f: &[Gf], l: &[Gf], r: &[u8]) {
    for v in out.iter_mut().take(2 * SYS_T) {
        *v = 0;
    }
    for i in 0..SYS_N {
        let c = Gf::from((r[i / 8] >> (i % 8)) & 1);
        let e = eval(f, l[i]);
        let mut e_inv = gf_inv(gf_mul(e, e));
        for v in out.iter_mut().take(2 * SYS_T) {
            *v ^= gf_mul(e_inv, c);
            e_inv = gf_mul(e_inv, l[i]);
        }
    }
}

// ---- Berlekamp-Massey (bm.c) -------------------------------------------------------

fn bm(out: &mut [Gf], s: &[Gf]) {
    let mut l: u16 = 0;
    let mut t = [0 as Gf; SYS_T + 1];
    let mut c = [0 as Gf; SYS_T + 1];
    let mut b = [0 as Gf; SYS_T + 1];
    let mut bb: Gf = 1;

    b[1] = 1;
    c[0] = 1;

    for nn in 0..2 * SYS_T {
        let n = nn as u16;
        let mut d: Gf = 0;
        for i in 0..=core::cmp::min(nn, SYS_T) {
            d ^= gf_mul(c[i], s[nn - i]);
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

        t.copy_from_slice(&c);
        let f = gf_mul(gf_inv(bb), d);
        for i in 0..=SYS_T {
            c[i] ^= gf_mul(f, b[i]) & mne;
        }
        l = (l & !mle) | (n.wrapping_add(1).wrapping_sub(l) & mle);
        for i in 0..=SYS_T {
            b[i] = (b[i] & !mle) | (t[i] & mle);
        }
        bb = (bb & !mle) | (d & mle);
        for i in (1..=SYS_T).rev() {
            b[i] = b[i - 1];
        }
        b[0] = 0;
    }
    for i in 0..=SYS_T {
        out[i] = c[SYS_T - i];
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

/// Apply the Benes network with control bits `bits` (forward direction) to the 4096-bit
/// word `r` (`r.len() == 512`).
fn apply_benes(r: &mut [u8], bits: &[u8]) {
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

/// The support `L` of the code: `L[i] = (apply Benes control bits c to bitrev(i))`.
fn support_gen(s: &mut [Gf], c: &[u8]) {
    let mut l = vec![[0u8; Q / 8]; GFBITS as usize];
    for i in 0..Q {
        let a = bitrev(i as Gf);
        for j in 0..GFBITS as usize {
            l[j][i / 8] |= (((a >> j) & 1) as u8) << (i % 8);
        }
    }
    for lj in l.iter_mut() {
        apply_benes(lj, c);
    }
    for i in 0..SYS_N {
        let mut v: Gf = 0;
        for j in (0..GFBITS as usize).rev() {
            v <<= 1;
            v |= Gf::from((l[j][i / 8] >> (i % 8)) & 1);
        }
        s[i] = v;
    }
}

// ---- Control bits (controlbits.c) --------------------------------------------------

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
    a.sort_unstable();

    for x in 0..n {
        let ax = a[x];
        let px = ax & 0xffff;
        let cx = i32_min(px, x as i32);
        b[x] = (px << 16) | cx;
    }

    for x in 0..n {
        a[x] = (a[x] << 16) | x as i32;
    }
    a.sort_unstable();

    for x in 0..n {
        a[x] = (a[x] << 16).wrapping_add(b[x] >> 16);
    }
    a.sort_unstable();

    if w <= 10 {
        for x in 0..n {
            b[x] = ((a[x] & 0xffff) << 10) | (b[x] & 0x3ff);
        }
        for _i in 1..w - 1 {
            for x in 0..n {
                a[x] = ((b[x] & !0x3ff) << 6) | x as i32;
            }
            a.sort_unstable();
            for x in 0..n {
                a[x] = (a[x] << 20) | b[x];
            }
            a.sort_unstable();
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
            a.sort_unstable();
            for x in 0..n {
                a[x] = (a[x] << 16) | (b[x] & 0xffff);
            }
            if i < w - 2 {
                for x in 0..n {
                    b[x] = (a[x] & !0xffff) | (b[x] >> 16);
                }
                b.sort_unstable();
                for x in 0..n {
                    b[x] = (b[x] << 16) | (a[x] & 0xffff);
                }
            }
            a.sort_unstable();
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
    a.sort_unstable();

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

    b.sort_unstable();

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

    a.sort_unstable();

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
fn pk_gen(pk: &mut [u8], irr: &[u8], perm: &[u32], pi: &mut [i16]) -> Option<()> {
    let mut g = [0 as Gf; SYS_T + 1];
    g[SYS_T] = 1;
    for i in 0..SYS_T {
        g[i] = load_gf(&irr[2 * i..]);
    }

    let mut buf = vec![0u64; Q];
    for i in 0..Q {
        buf[i] = (u64::from(perm[i]) << 31) | i as u64;
    }
    buf.sort_unstable();
    for i in 1..Q {
        if (buf[i - 1] >> 31) == (buf[i] >> 31) {
            return None;
        }
    }
    for i in 0..Q {
        pi[i] = (buf[i] & u64::from(GFMASK)) as i16;
    }
    let mut l = vec![0 as Gf; SYS_N];
    for i in 0..SYS_N {
        l[i] = bitrev(pi[i] as Gf);
    }

    let mut inv = vec![0 as Gf; SYS_N];
    root(&mut inv, &g, &l);
    for v in inv.iter_mut() {
        *v = gf_inv(*v);
    }

    let mut mat = vec![[0u8; SYS_N / 8]; PK_NROWS];
    for i in 0..SYS_T {
        let mut j = 0;
        while j < SYS_N {
            for k in 0..GFBITS as usize {
                let mut b: u8 = 0;
                for t in (0..8).rev() {
                    b = (b << 1) | (((inv[j + t] >> k) & 1) as u8);
                }
                mat[i * GFBITS as usize + k][j / 8] = b;
            }
            j += 8;
        }
        for j in 0..SYS_N {
            inv[j] = gf_mul(inv[j], l[j]);
        }
    }

    // Gaussian elimination to systematic form.
    for i in 0..PK_NROWS.div_ceil(8) {
        for j in 0..8 {
            let row = i * 8 + j;
            if row >= PK_NROWS {
                break;
            }
            for k in row + 1..PK_NROWS {
                let mut mask = mat[row][i] ^ mat[k][i];
                mask >>= j;
                mask &= 1;
                mask = 0u8.wrapping_sub(mask);
                for c in 0..SYS_N / 8 {
                    let v = mat[k][c] & mask;
                    mat[row][c] ^= v;
                }
            }
            if (mat[row][i] >> j) & 1 == 0 {
                return None;
            }
            for k in 0..PK_NROWS {
                if k != row {
                    let mut mask = mat[k][i] >> j;
                    mask &= 1;
                    mask = 0u8.wrapping_sub(mask);
                    for c in 0..SYS_N / 8 {
                        let v = mat[row][c] & mask;
                        mat[k][c] ^= v;
                    }
                }
            }
        }
    }

    for i in 0..PK_NROWS {
        pk[i * PK_ROW_BYTES..(i + 1) * PK_ROW_BYTES]
            .copy_from_slice(&mat[i][PK_NROWS / 8..PK_NROWS / 8 + PK_ROW_BYTES]);
    }
    Some(())
}

// ---- Encryption (encrypt.c) --------------------------------------------------------

/// Error vector of weight `t`, drawn from `rng` (`gen_e`).
fn gen_e(rng: &mut impl CryptoRng) -> Result<[u8; SYS_N / 8]> {
    let mut ind = [0u16; SYS_T];
    loop {
        let mut bytes = [0u8; SYS_T * 2 * 2];
        rng.try_fill_bytes(&mut bytes)?;
        let mut nums = [0u16; SYS_T * 2];
        for i in 0..SYS_T * 2 {
            nums[i] = load_gf(&bytes[i * 2..]);
        }

        let mut count = 0usize;
        let mut i = 0usize;
        while i < SYS_T * 2 && count < SYS_T {
            if nums[i] < SYS_N as u16 {
                ind[count] = nums[i];
                count += 1;
            }
            i += 1;
        }
        if count < SYS_T {
            continue;
        }

        let mut eq = false;
        for i in 1..SYS_T {
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

    let mut val = [0u8; SYS_T];
    for j in 0..SYS_T {
        val[j] = 1 << (ind[j] & 7);
    }
    let mut e = [0u8; SYS_N / 8];
    for i in 0..SYS_N / 8 {
        for j in 0..SYS_T {
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
fn syndrome(pk: &[u8], e: &[u8]) -> [u8; SYND_BYTES] {
    let mut s = [0u8; SYND_BYTES];
    let mut pk_ptr = 0usize;
    for i in 0..PK_NROWS {
        let mut row = [0u8; SYS_N / 8];
        row[SYS_N / 8 - PK_ROW_BYTES..].copy_from_slice(&pk[pk_ptr..pk_ptr + PK_ROW_BYTES]);
        row[i / 8] |= 1 << (i % 8);

        let mut b: u8 = 0;
        for j in 0..SYS_N / 8 {
            b ^= row[j] & e[j];
        }
        b ^= b >> 4;
        b ^= b >> 2;
        b ^= b >> 1;
        b &= 1;
        s[i / 8] |= b << (i % 8);
        pk_ptr += PK_ROW_BYTES;
    }
    s
}

// ---- Decryption (decrypt.c) --------------------------------------------------------

/// Berlekamp decoder. Returns `(e, ok)`: `ok` is true when the decoded word is a valid
/// error vector of weight `t` with the right syndrome.
fn decrypt(sk_irr_cond: &[u8], c: &[u8]) -> ([u8; SYS_N / 8], bool) {
    let mut r = [0u8; SYS_N / 8];
    r[..SYND_BYTES].copy_from_slice(&c[..SYND_BYTES]);

    let mut g = [0 as Gf; SYS_T + 1];
    for i in 0..SYS_T {
        g[i] = load_gf(&sk_irr_cond[2 * i..]);
    }
    g[SYS_T] = 1;

    let cond = &sk_irr_cond[IRR_BYTES..IRR_BYTES + COND_BYTES];
    let mut l = vec![0 as Gf; SYS_N];
    support_gen(&mut l, cond);

    let mut s = [0 as Gf; SYS_T * 2];
    synd(&mut s, &g, &l, &r);

    let mut locator = [0 as Gf; SYS_T + 1];
    bm(&mut locator, &s);

    let mut images = vec![0 as Gf; SYS_N];
    root(&mut images, &locator, &l);

    let mut e = [0u8; SYS_N / 8];
    let mut w: u16 = 0;
    for i in 0..SYS_N {
        let t = gf_iszero(images[i]) & 1;
        e[i / 8] |= (t << (i % 8)) as u8;
        w = w.wrapping_add(t);
    }

    let mut s_cmp = [0 as Gf; SYS_T * 2];
    synd(&mut s_cmp, &g, &l, &e);

    let mut check: u16 = w;
    check ^= SYS_T as u16;
    for i in 0..SYS_T * 2 {
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
fn keypair_from_delta(delta: &[u8; 32]) -> (Vec<u8>, Vec<u8>) {
    let mut seed = [0u8; 33];
    seed[0] = 64;
    seed[1..].copy_from_slice(delta);

    let r_len = S_LEN + Q * 4 + SYS_T * 2 + 32;
    let mut pk = vec![0u8; PUBLIC_KEY_LEN];
    let mut sk = vec![0u8; SECRET_KEY_LEN];
    loop {
        let mut r = vec![0u8; r_len];
        shake256_into(&mut r, &seed);

        let mut skp = 0usize;
        sk[skp..skp + 32].copy_from_slice(&seed[1..33]);
        skp += 32 + 8;
        seed[1..33].copy_from_slice(&r[r_len - 32..]);

        // Goppa polynomial from the random bytes.
        let mut rp = r_len - 32;
        rp -= SYS_T * 2;
        let mut f = [0 as Gf; SYS_T];
        for i in 0..SYS_T {
            f[i] = load_gf(&r[rp + i * 2..]);
        }
        let irr = match genpoly_gen(&f) {
            Some(irr) => irr,
            None => continue,
        };
        for i in 0..SYS_T {
            store_gf(&mut sk[skp + i * 2..], irr[i]);
        }
        skp += IRR_BYTES;

        // Permutation from the random bytes.
        rp -= Q * 4;
        let mut perm = vec![0u32; Q];
        for i in 0..Q {
            perm[i] = load4(&r[rp + i * 4..]);
        }
        let mut pi = vec![0i16; Q];
        let irr_bytes = sk[skp - IRR_BYTES..skp].to_vec();
        if pk_gen(&mut pk, &irr_bytes, &perm, &mut pi).is_none() {
            continue;
        }

        let mut cond = vec![0u8; COND_BYTES];
        controlbitsfrompermutation(&mut cond, &pi, GFBITS as i64, Q);
        sk[skp..skp + COND_BYTES].copy_from_slice(&cond);
        skp += COND_BYTES;

        // The random string s.
        rp -= S_LEN;
        sk[skp..skp + S_LEN].copy_from_slice(&r[rp..rp + S_LEN]);

        // Positions of the pivots: fixed by the reference.
        store8(&mut sk[32..40], 0xFFFF_FFFF);
        break;
    }
    (pk, sk)
}

/// Keypair from the RNG. Returns `(pk, sk)`.
///
/// # Errors
///
/// Returns the RNG's error if it fails.
pub fn keypair(rng: &mut impl CryptoRng) -> Result<(Vec<u8>, Vec<u8>)> {
    let mut delta = [0u8; 32];
    rng.try_fill_bytes(&mut delta)?;
    let out = keypair_from_delta(&delta);
    delta.zeroize();
    Ok(out)
}

/// Encapsulation to `pk`: draws the error vector from `rng`. Returns `(ciphertext, ss)`.
///
/// # Errors
///
/// [`Error::InvalidLength`] if `pk` has the wrong length; the RNG's error otherwise.
pub fn encapsulate(
    pk: &[u8],
    rng: &mut impl CryptoRng,
) -> Result<(Vec<u8>, [u8; SHARED_SECRET_LEN])> {
    if pk.len() != PUBLIC_KEY_LEN {
        return Err(Error::InvalidLength);
    }
    let mut e = gen_e(rng)?;
    let c = syndrome(pk, &e);

    let mut one_ec = vec![0u8; 1 + SYS_N / 8 + SYND_BYTES];
    one_ec[0] = 1;
    one_ec[1..1 + SYS_N / 8].copy_from_slice(&e);
    one_ec[1 + SYS_N / 8..].copy_from_slice(&c);
    let mut key = [0u8; SHARED_SECRET_LEN];
    shake256_into(&mut key, &one_ec);

    e.zeroize();
    one_ec.zeroize();
    Ok((c.to_vec(), key))
}

/// Decapsulation with implicit rejection: a ciphertext that does not decode yields the
/// shared secret derived from the stored random string `s`.
///
/// # Errors
///
/// [`Error::InvalidLength`] if `sk` or `ct` has the wrong length.
pub fn decapsulate(sk: &[u8], ct: &[u8]) -> Result<[u8; SHARED_SECRET_LEN]> {
    if sk.len() != SECRET_KEY_LEN || ct.len() != CIPHERTEXT_LEN {
        return Err(Error::InvalidLength);
    }
    let (mut e, ok) = decrypt(&sk[40..], ct);
    let s_off = 40 + IRR_BYTES + COND_BYTES;
    let s = &sk[s_off..s_off + S_LEN];

    // m = 0x00FF on success, 0 on failure: selects e or s byte by byte.
    let mut pre = vec![0u8; 1 + SYS_N / 8 + SYND_BYTES];
    pre[0] = u8::from(ok);
    for i in 0..SYS_N / 8 {
        let mm = if ok { 0xFFu8 } else { 0u8 };
        pre[1 + i] = (!mm & s[i]) | (mm & e[i]);
    }
    pre[1 + SYS_N / 8..].copy_from_slice(&ct[..SYND_BYTES]);

    let mut key = [0u8; SHARED_SECRET_LEN];
    shake256_into(&mut key, &pre);
    e.zeroize();
    pre.zeroize();
    Ok(key)
}
