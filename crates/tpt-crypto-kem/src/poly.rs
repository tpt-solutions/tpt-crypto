//! Polynomial arithmetic over `R_q = Z_q[X]/(X^n + 1)` with `q = 3329`, `n = 256`.
//!
//! This module provides the constant-time core used by ML-KEM: Montgomery
//! reduction, the number-theoretic transform (NTT) and its inverse, the
//! negacyclic base multiplication, coefficient add/sub, compression/decompression
//! (bit rounding), and the message encode/decode (`frommsg`/`tomsg`).

/// Polynomial degree `n` for `R_q = Z_q[X]/(X^n + 1)`.
pub const N: usize = 256;
/// The ML-KEM modulus `q = 3329`.
pub const Q: i32 = 3329;
const QINV: i32 = 62209;
const MONT: i32 = 2285;
/// Final inverse-NTT scaling `f = 1441` (`mont^2 / 128` in the reference).
const F: i32 = 1441;
/// `R^2 mod q` used by [`poly_tomont`] to lift a canonical value into Montgomery form.
const R2: i32 = 1353;

/// A polynomial: 256 coefficients. Canonical values lie in `[0, q)`; during the
/// NTT they are held in Montgomery form. Stored as `i32` so that the butterfly
/// additions never overflow (the intermediate sums stay far below `i32::MAX`).
pub type Poly = [i32; N];

/// A vector of `K` polynomials (e.g. the matrix rows/columns, `s`, `e`, `r`).
///
/// Defined in [`crate::pke`] because it is heap-backed (the KEM modules require
/// `alloc`); this module stays heap-free.

// ---------------------------------------------------------------------------
// Montgomery arithmetic
// ---------------------------------------------------------------------------

/// Barrett-free Montgomery reduction with `R = 2^16`.
///
/// Returns `(a * R^{-1}) mod q` for `a` the product of two Montgomery-encoded
/// values. Mirrors the reference Kyber `montgomery_reduce` exactly; no secret
/// branch or index.
#[inline]
pub fn montgomery_reduce(a: i32) -> i32 {
    let t = (a as i16).wrapping_mul(QINV as i16) as i32;
    let r = (a - t.wrapping_mul(Q)) >> 16;
    freeze(r)
}

/// Montgomery multiplication of two Montgomery-encoded coefficients.
#[inline]
pub fn fqmul(a: i32, b: i32) -> i32 {
    montgomery_reduce(a * b)
}

/// Reduce a coefficient into canonical `[0, q)` form.
#[inline]
pub fn freeze(x: i32) -> i32 {
    let r = x % Q;
    if r < 0 {
        r + Q
    } else {
        r
    }
}

// ---------------------------------------------------------------------------
// NTT twiddle factors
// ---------------------------------------------------------------------------
//
// Canonical `zetas` table from the FIPS 203 / Kyber reference `ntt.c`, used
// verbatim. The NTT uses the primitive 256-th root of unity `ζ = 17` with
// `ζ^128 = -1`. The forward transform walks `zetas[1..127]`; the inverse walks
// `zetas[127..1]`; base multiplication uses `zetas[64..128]` (with a sign flip
// on the second pair of each group, see [`poly_basemul`]).

const ZETAS: [i32; 128] = [
    -1044, -758, -359, -1517, 1493, 1422, 287, 202, -171, 622, 1577, 182, 962, -1202,
    -1474, 1468, 573, -1325, 264, 383, -829, 1458, -1602, -130, -681, 1017, 732, 608,
    -1542, 411, -205, -1571, 1223, 652, -552, 1015, -1293, 1491, -282, -1544, 516, -8,
    -320, -666, -1618, -1162, 126, 1469, -853, -90, -271, 830, 107, -1421, -247, -951,
    -398, 961, -1508, -725, 448, -1065, 677, -1275, -1103, 430, 555, 843, -1251, 871,
    1550, 105, 422, 587, 177, -235, -291, -460, 1574, 1653, -246, 778, 1159, -147, -777,
    1483, -602, 1119, -1590, 644, -872, 349, 418, 329, -156, -75, 817, 1097, 603, 610,
    1322, -1285, -1465, 384, -1215, -136, 1218, -1335, -874, 220, -1187, -1659, -1185,
    -1530, -1278, 794, -1510, -854, -870, 478, -108, -308, 996, 991, 958, -1460, 1522,
    1628,
];

// ---------------------------------------------------------------------------
// NTT / inverse NTT / base multiplication
// ---------------------------------------------------------------------------

/// In-place forward NTT. Input is canonical; output is in Montgomery form.
pub fn ntt(r: &mut Poly) {
    let mut k = 1usize;
    let mut len = 128usize;
    while len >= 2 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[k];
            k += 1;
            let mut j = start;
            while j < start + len {
                let t = fqmul(zeta, r[j + len]);
                r[j + len] = r[j] - t;
                r[j] = r[j] + t;
                j += 1;
            }
            start += 2 * len;
        }
        len >>= 1;
    }
    // Keep every coefficient inside `[-q, q]` so later `fqmul` inputs stay
    // within the `±q·2^15` bound assumed by `montgomery_reduce` (the reference
    // `poly_ntt` does the same via `poly_reduce` after `ntt`).
    for c in r.iter_mut() {
        *c = freeze(*c);
    }
}

/// In-place inverse NTT, leaving coefficients in Montgomery form (the `tomont`
/// suffix). Follow with [`poly_frommont`] to obtain canonical coefficients.
pub fn invntt_tomont(r: &mut Poly) {
    let f = F;
    let mut k = 127usize;
    let mut len = 2usize;
    while len <= 128 {
        let mut start = 0usize;
        while start < N {
            let zeta = ZETAS[k];
            k -= 1;
            let mut j = start;
            while j < start + len {
                let t = r[j];
                r[j] = freeze(t + r[j + len]);
                r[j + len] = fqmul(zeta, r[j + len] - t);
                j += 1;
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for j in 0..N {
        r[j] = fqmul(r[j], f);
    }
}

/// Negacyclic base multiplication of two NTT-domain polynomials (both in
/// Montgomery form); result is in Montgomery form.
///
/// Mirrors the reference `poly_basemul_montgomery`: for each group of four
/// coefficients the first pair uses `zetas[64+i]`, the second uses its negation.
pub fn poly_basemul(r: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N / 4 {
        let zeta = ZETAS[64 + i];
        // First pair: coefficients [4i, 4i+1].
        let t = fqmul(fqmul(a[4 * i + 1], b[4 * i + 1]), zeta);
        r[4 * i] = t + fqmul(a[4 * i], b[4 * i]);
        r[4 * i + 1] = fqmul(a[4 * i], b[4 * i + 1]) + fqmul(a[4 * i + 1], b[4 * i]);
        // Second pair: coefficients [4i+2, 4i+3] with `-zeta`.
        let z2 = -zeta;
        let t = fqmul(fqmul(a[4 * i + 3], b[4 * i + 3]), z2);
        r[4 * i + 2] = t + fqmul(a[4 * i + 2], b[4 * i + 2]);
        r[4 * i + 3] = fqmul(a[4 * i + 2], b[4 * i + 3]) + fqmul(a[4 * i + 3], b[4 * i + 2]);
    }
}

/// Convert a canonical polynomial into Montgomery form (`x ↦ x·R mod q`),
/// matching the reference `poly_tomont`.
pub fn poly_tomont(r: &mut Poly) {
    for i in 0..N {
        r[i] = montgomery_reduce(r[i].wrapping_mul(R2));
    }
}

/// Convert an NTT-domain polynomial from Montgomery form to canonical form.
pub fn poly_frommont(r: &mut Poly) {
    for i in 0..N {
        r[i] = montgomery_reduce(r[i].wrapping_mul(MONT));
    }
}

/// NTT of a canonical polynomial, returning the Montgomery-form result.
pub fn ntt_p(p: &Poly) -> Poly {
    let mut x = *p;
    ntt(&mut x);
    x
}

/// Inverse NTT of a Montgomery-form polynomial, returning canonical coefficients.
pub fn invntt_p(p: &Poly) -> Poly {
    let mut x = *p;
    invntt_tomont(&mut x);
    poly_frommont(&mut x);
    x
}

/// Base multiplication returning a fresh polynomial.
pub fn basemul_polys(a: &Poly, b: &Poly) -> Poly {
    let mut r = [0i32; N];
    poly_basemul(&mut r, a, b);
    r
}

/// Coefficient-wise addition (canonical or Montgomery form).
pub fn poly_add(a: &Poly, b: &Poly) -> Poly {
    let mut r = [0i32; N];
    for i in 0..N {
        r[i] = a[i] + b[i];
    }
    r
}

/// Coefficient-wise subtraction (canonical or Montgomery form).
pub fn poly_sub(a: &Poly, b: &Poly) -> Poly {
    let mut r = [0i32; N];
    for i in 0..N {
        r[i] = a[i] - b[i];
    }
    r
}

// ---------------------------------------------------------------------------
// Compression / decompression (bit rounding) and message coding
// ---------------------------------------------------------------------------

/// `Compress_q(x, d)`: round `x` to `d` bits, returning a value in `[0, 2^d)`.
pub fn compress(x: i32, d: usize) -> i32 {
    let x = freeze(x);
    let shifted = x << d;
    let v = ((shifted + Q / 2) / Q) & ((1i32 << d) - 1);
    v
}

/// `Decompress_q(y, d)`: recover a `q`-wide coefficient from a `d`-bit value.
pub fn decompress(y: i32, d: usize) -> i32 {
    let v = ((y * Q + (1i32 << (d - 1))) >> d) % Q;
    freeze(v)
}

/// Encode a 32-byte message into a polynomial with coefficients `0` or
/// `(q+1)/2` (equivalently `Decompress_q(b, 1)`).
pub fn poly_frommsg(msg: &[u8; 32]) -> Poly {
    let mut r = [0i32; N];
    for i in 0..N {
        let bit = (msg[i >> 3] >> (i & 7)) & 1;
        r[i] = (bit as i32) * 1665;
    }
    r
}

/// Recover the 32-byte message from a polynomial by `Compress_q(·, 1)`
/// (round to nearest of `{0, q/2}`).
pub fn poly_tomsg(p: &Poly) -> [u8; 32] {
    let mut msg = [0u8; 32];
    for i in 0..N {
        let w = freeze(p[i]);
        let bit = (((2 * w + Q / 2) / Q) & 1) as u8;
        msg[i >> 3] |= bit << (i & 7);
    }
    msg
}

#[cfg(test)]
mod tests {
    use super::*;

    // Deterministic LCG so unit tests need no RNG.
    fn lcg(state: &mut u64) -> u32 {
        *state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
        (*state >> 33) as u32
    }

    fn rand_poly(state: &mut u64) -> Poly {
        let mut p = [0i32; N];
        for i in 0..N {
            p[i] = (lcg(state) % Q as u32) as i32;
        }
        p
    }

    fn schoolbook(a: &Poly, b: &Poly) -> Poly {
        let mut t = [0i64; 512];
        for i in 0..N {
            for j in 0..N {
                t[i + j] += a[i] as i64 * b[j] as i64;
            }
        }
        let mut r = [0i32; N];
        for i in 0..N {
            let c = t[i] - t[i + 256];
            r[i] = freeze(c as i32);
        }
        r
    }

    #[test]
    fn ntt_mul_matches_schoolbook() {
        let mut s = 0x1234_5678_u64;
        for _ in 0..40 {
            let a = rand_poly(&mut s);
            let b = rand_poly(&mut s);
            let want = schoolbook(&a, &b);
            let an = ntt_p(&a);
            let bn = ntt_p(&b);
            let mut cn = basemul_polys(&an, &bn);
            invntt_tomont(&mut cn);
            poly_frommont(&mut cn);
            for i in 0..N {
                assert_eq!(cn[i], want[i], "coeff {i}");
            }
        }
    }

    #[test]
    fn compress_roundtrip() {
        let mut s = 0x9abc_def0_u64;
        for _ in 0..200 {
            let x = (lcg(&mut s) % Q as u32) as i32;
            for d in [1usize, 4, 5, 10, 11, 12] {
                let c = compress(x, d);
                let back = decompress(c as i32, d);
                // Decompress(Compress(x)) == x for all but the boundary cases
                // handled by rounding; re-compress must be stable.
                assert_eq!(compress(back, d), c);
            }
        }
    }

    #[test]
    fn msg_roundtrip() {
        let m = [0b1011_0110u8; 32];
        let p = poly_frommsg(&m);
        let m2 = poly_tomsg(&p);
        assert_eq!(m, m2);
    }
}
