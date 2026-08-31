//! ML-DSA samplers and matrix expansion (FIPS 204 Algorithms 30–34, 29).
//!
//! `expand_a` / `expand_s` / `expand_mask` drive the SHAKE-128/256 rejection
//! samplers that turn seed material into polynomials, and fold the resulting
//! canonical polynomials into Montgomery/NTT form so the matrix–vector product
//! in [`super::mod.rs`] is a clean pointwise multiply.

use tpt_crypto_hash::sha3::{Shake128, Shake256};
use tpt_crypto_hash::Xof;

use crate::bytes::PolyArray;
use crate::ml_dsa::MlDsaParams;
use crate::poly::Poly;

/// SHAKE-128 rate.
const SHAKE128_RATE: usize = 168;
/// SHAKE-256 rate.
const SHAKE256_RATE: usize = 136;

/// Rejection-sample up to `len` uniform coefficients in `[0, q)` from `buf`.
fn rej_uniform(dst: &mut [i32], len: usize, buf: &[u8]) -> usize {
    let mut ctr = 0usize;
    let mut pos = 0usize;
    while ctr < len && pos + 3 <= buf.len() {
        let mut t = u32::from(buf[pos]);
        pos += 1;
        t |= u32::from(buf[pos]) << 8;
        pos += 1;
        t |= u32::from(buf[pos]) << 16;
        pos += 1;
        t &= 0x7F_FFFF;
        if t < crate::poly::Q as u32 {
            dst[ctr] = t as i32;
            ctr += 1;
        }
    }
    ctr
}

/// Sample one polynomial uniformly in `R_q` from `seed` and `nonce`.
pub fn poly_uniform(seed: &[u8; 32], nonce: u16) -> Poly {
    const NBLOCKS: usize = (3 * crate::poly::N).div_ceil(SHAKE128_RATE);
    let mut xof = Shake128::new();
    xof.update(seed);
    xof.update(&nonce.to_le_bytes());

    let mut buf = [0u8; NBLOCKS * SHAKE128_RATE + 2];
    let mut buflen = NBLOCKS * SHAKE128_RATE;
    xof.squeeze(&mut buf[..buflen]);

    let mut out = Poly::ZERO;
    let mut ctr = rej_uniform(&mut out.coeffs, crate::poly::N, &buf[..buflen]);
    while ctr < crate::poly::N {
        let off = buflen % 3;
        for i in 0..off {
            buf[i] = buf[buflen - off + i];
        }
        xof.squeeze(&mut buf[off..off + SHAKE128_RATE]);
        buflen = SHAKE128_RATE + off;
        ctr += rej_uniform(&mut out.coeffs[ctr..], crate::poly::N - ctr, &buf[..buflen]);
    }
    out
}

/// Rejection-sample up to `len` coefficients in `[−η, η]` from `buf`.
fn rej_eta(dst: &mut [i32], len: usize, buf: &[u8], eta: i32) -> usize {
    let mut ctr = 0usize;
    let mut pos = 0usize;
    while ctr < len && pos < buf.len() {
        let mut t0 = i32::from(buf[pos] & 0x0F);
        let mut t1 = i32::from(buf[pos] >> 4);
        pos += 1;

        if eta == 2 {
            if t0 < 15 {
                t0 = t0 - ((205 * t0) >> 10) * 5;
                dst[ctr] = 2 - t0;
                ctr += 1;
            }
            if t1 < 15 && ctr < len {
                t1 = t1 - ((205 * t1) >> 10) * 5;
                dst[ctr] = 2 - t1;
                ctr += 1;
            }
        } else {
            if t0 < 9 {
                dst[ctr] = 4 - t0;
                ctr += 1;
            }
            if t1 < 9 && ctr < len {
                dst[ctr] = 4 - t1;
                ctr += 1;
            }
        }
    }
    ctr
}

/// Sample one `s₁` / `s₂` polynomial (coefficients in `[−η, η]`).
pub fn poly_uniform_eta(seed: &[u8; 64], nonce: u16, eta: i32) -> Poly {
    let req: usize = if eta == 2 { 136 } else { 227 };
    let nblocks = req.div_ceil(SHAKE256_RATE);
    let mut xof = Shake256::new();
    xof.update(seed);
    xof.update(&nonce.to_le_bytes());

    let mut buf = [0u8; 2 * SHAKE256_RATE];
    let buflen = nblocks * SHAKE256_RATE;
    xof.squeeze(&mut buf[..buflen]);

    let mut out = Poly::ZERO;
    let mut ctr = rej_eta(&mut out.coeffs, crate::poly::N, &buf[..buflen], eta);
    while ctr < crate::poly::N {
        xof.squeeze(&mut buf[..SHAKE256_RATE]);
        ctr += rej_eta(&mut out.coeffs[ctr..], crate::poly::N - ctr, &buf[..SHAKE256_RATE], eta);
    }
    out
}

/// Sample one `y` polynomial (coefficients in `[−γ₁, γ₁]`).
pub fn poly_uniform_gamma1(seed: &[u8; 64], nonce: u16, gamma1: i32) -> Poly {
    let packed = if gamma1 == (1 << 17) { 9 * (crate::poly::N / 4) } else { 5 * (crate::poly::N / 2) };
    let nblocks = packed.div_ceil(SHAKE256_RATE);
    let mut xof = Shake256::new();
    xof.update(seed);
    xof.update(&nonce.to_le_bytes());
    let mut buf = [0u8; 5 * SHAKE256_RATE];
    xof.squeeze(&mut buf[..nblocks * SHAKE256_RATE]);
    crate::poly::polyz_unpack(gamma1, &buf[..packed]).expect("gamma1 sampler: unpack")
}

/// Sample the challenge polynomial `c` (FIPS 204 Algorithm 29 `SampleInBall`).
pub fn poly_challenge(seed: &[u8], tau: usize) -> Poly {
    let mut xof = Shake256::new();
    xof.update(seed);
    let mut buf = [0u8; SHAKE256_RATE];
    xof.squeeze(&mut buf);

    let mut signs = 0u64;
    for (i, b) in buf.iter().enumerate().take(8) {
        signs |= u64::from(*b) << (8 * i);
    }
    let mut pos = 8usize;
    let mut out = Poly::ZERO;
    for i in (crate::poly::N - tau)..crate::poly::N {
        let b = loop {
            if pos >= SHAKE256_RATE {
                xof.squeeze(&mut buf);
                pos = 0;
            }
            let b = usize::from(buf[pos]);
            pos += 1;
            if b <= i {
                break b;
            }
        };
        out.coeffs[i] = out.coeffs[b];
        out.coeffs[b] = 1 - 2 * (signs as i32 & 1);
        signs >>= 1;
    }
    out
}

/// `ExpandA` (FIPS 204 Algorithm 32): the NTT-domain public matrix `Â`.
pub fn expand_a<P: MlDsaParams>(rho: &[u8; 32]) -> P::Mat {
    let mut mat = P::Mat::zeroed();
    let m = mat.as_poly_slice_mut();
    for i in 0..P::K {
        for j in 0..P::L {
            let mut p = poly_uniform(rho, ((i << 8) + j) as u16);
            p.ntt();
            m[i * P::L + j] = p;
        }
    }
    mat
}

/// `ExpandS` (FIPS 204 Algorithm 33): the secret vectors `s₁`, `s₂` (canonical).
pub fn expand_s<P: MlDsaParams>(rhoprime: &[u8; 64]) -> (P::VecL, P::VecK) {
    let mut s1 = P::VecL::zeroed();
    let mut s2 = P::VecK::zeroed();
    let s1m = s1.as_poly_slice_mut();
    for (i, s1m_i) in s1m.iter_mut().enumerate().take(P::L) {
        s1m_i.clone_from(&poly_uniform_eta(rhoprime, i as u16, P::ETA));
    }
    let s2m = s2.as_poly_slice_mut();
    for (i, s2m_i) in s2m.iter_mut().enumerate().take(P::K) {
        s2m_i.clone_from(&poly_uniform_eta(rhoprime, (P::L as u16) + i as u16, P::ETA));
    }
    (s1, s2)
}

/// `ExpandMask` (FIPS 204 Algorithm 34): the masking vector `y`.
pub fn expand_mask<P: MlDsaParams>(rhoprime: &[u8; 64], kappa: u16) -> P::VecL {
    let mut y = P::VecL::zeroed();
    let ym = y.as_poly_slice_mut();
    for (i, ym_i) in ym.iter_mut().enumerate().take(P::L) {
        let nonce = (P::L as u16).wrapping_mul(kappa) + i as u16;
        *ym_i = poly_uniform_gamma1(rhoprime, nonce, P::GAMMA1);
    }
    y
}
