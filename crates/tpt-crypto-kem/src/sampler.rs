//! Samplers: centered-binomial (CBD) noise and uniform NTT-domain polynomials.
//!
//! * [`cbd`] draws small error polynomials with a fixed, secret-independent
//!   byte count (no rejection loop, constant time).
//! * [`sample_ntt`] draws a uniform polynomial in NTT domain via a SHAKE128 XOF
//!   with constant-time rejection sampling over a *fixed-length* byte stream
//!   (public randomness only — never the secret key).

use crate::poly::{Poly, N, Q};
use tpt_crypto_hash::sha3::{Shake128, Shake256};
use tpt_crypto_hash::Xof;

/// Sample a polynomial uniformly in `R_q` (canonical form) from the XOF
/// `SHAKE128(rho ‖ i ‖ j)`.
pub fn sample_ntt(rho: &[u8; 32], i: u8, j: u8) -> Poly {
    let mut xof = Shake128::new();
    xof.update(rho);
    xof.update(&[i]);
    xof.update(&[j]);
    let mut src = ByteSource::new(xof);
    let mut r = [0i32; N];
    let mut ctr = 0usize;
    while ctr < N {
        let b0 = src.next();
        let b1 = src.next();
        let b2 = src.next();
        let a = (b0 as u32) | ((b1 as u32) << 8) | ((b2 as u32) << 16);
        let d1 = (a & 0x0FFF) as i32;
        let d2 = (a >> 12) as i32;
        if d1 < Q && ctr < N {
            r[ctr] = d1;
            ctr += 1;
        }
        if d2 < Q && ctr < N {
            r[ctr] = d2;
            ctr += 1;
        }
    }
    r
}

/// Streaming SHAKE128 byte reader (no bytes discarded across refills).
struct ByteSource {
    xof: Shake128,
    buf: [u8; 168],
    pos: usize,
}

impl ByteSource {
    fn new(xof: Shake128) -> Self {
        ByteSource {
            xof,
            buf: [0u8; 168],
            pos: 168,
        }
    }

    fn next(&mut self) -> u8 {
        if self.pos >= 168 {
            self.xof.squeeze(&mut self.buf);
            self.pos = 0;
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        b
    }
}

/// Centered-binomial sample into `out` (coefficients centred on 0).
///
/// `eta` is the binomial half-width: `2` (`4` bits/coeff, `128` bytes) or `3`
/// (`6` bits/coeff, `192` bytes). The seed stream is `SHAKE256(seed ‖ counter)`.
pub fn cbd(out: &mut Poly, seed: &[u8; 32], counter: u8, eta: usize) {
    let mut xof = Shake256::new();
    xof.update(seed);
    xof.update(&[counter]);
    let nbytes = if eta == 2 { 128 } else { 192 };
    let mut buf = [0u8; 192];
    xof.squeeze(&mut buf[..nbytes]);
    if eta == 2 {
        // 4 bits/coefficient: two coin bits for `+`, two for `-` (so result in [-2, 2]).
        for i in 0..N {
            let nib = if i % 2 == 0 {
                buf[i / 2] & 0x0F
            } else {
                buf[i / 2] >> 4
            };
            let a = (nib & 1) + ((nib >> 1) & 1);
            let b = ((nib >> 2) & 1) + ((nib >> 3) & 1);
            out[i] = (a as i32) - (b as i32);
        }
    } else {
        // 6 bits/coefficient: three coin bits for `+`, three for `-` (result in [-3, 3]).
        for g in 0..64usize {
            let t = (buf[3 * g] as u32)
                | ((buf[3 * g + 1] as u32) << 8)
                | ((buf[3 * g + 2] as u32) << 16);
            for j in 0..4 {
                let d = (t >> (6 * j)) & 0x3F;
                let a = (d & 1) + ((d >> 1) & 1) + ((d >> 2) & 1);
                let b = ((d >> 3) & 1) + ((d >> 4) & 1) + ((d >> 5) & 1);
                out[4 * g + j] = (a as i32) - (b as i32);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cbd_is_centered() {
        let seed = [7u8; 32];
        let mut p = [0i32; N];
        cbd(&mut p, &seed, 0, 2);
        let sum: i32 = p.iter().copied().sum();
        // Small absolute total expected for centered binomial.
        assert!(sum.unsigned_abs() < 200);
        for &c in &p {
            assert!(c.unsigned_abs() <= 2);
        }
    }

    #[test]
    fn sample_ntt_in_range() {
        let rho = [42u8; 32];
        let p = sample_ntt(&rho, 0, 0);
        for &c in &p {
            assert!((0..Q).contains(&c));
        }
    }
}
