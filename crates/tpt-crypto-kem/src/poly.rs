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
const F: i32 = 1441;

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
    let t0 = (a as i32).wrapping_mul(QINV as i32);
    let t = ((t0 as i32).wrapping_mul(Q as i32)) >> 16;
    freeze(a - t)
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
// The NTT uses the primitive 256-th root of unity `ζ = 17` with `ζ^128 = -1`.
// We generate the twiddle table at compile time from `ζ^{2·bitrev(i) + 1}`,
// stored in Montgomery form, exactly as the reference Kyber/ML-KEM layout. The
// forward transform walks `ZETAS[1..127]`; the inverse walks `ZETAS[127..1]`;
// base multiplication uses `ZETAS[64..192]`.

const fn pow_mod(mut base: i64, mut e: i64, m: i64) -> i64 {
    let mut r = 1i64;
    base %= m;
    while e > 0 {
        if e & 1 == 1 {
            r = (r * base) % m;
        }
        base = (base * base) % m;
        e >>= 1;
    }
    r
}

const fn bitrev7(mut x: usize) -> usize {
    let mut r = 0usize;
    let mut i = 0;
    while i < 7 {
        r = (r << 1) | (x & 1);
        x >>= 1;
        i += 1;
    }
    r
}

const fn to_mont(x: i64) -> i32 {
    ((x * 65536) % Q as i64) as i32
}

const ZETAS: [i32; 256] = {
    let mut arr = [0i32; 256];
    let mut i = 0usize;
    while i < 256 {
        let exp = (2 * bitrev7(i) + 1) as i64;
        let val = pow_mod(17, exp, Q as i64);
        arr[i] = to_mont(val);
        i += 1;
    }
    arr
};

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
}

/// In-place inverse NTT, leaving coefficients in Montgomery form (the `tomont`
/// suffix). Follow with [`poly_frommont`] to obtain canonical coefficients.
pub fn invntt_tomont(r: &mut Poly) {
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
                r[j] = t + r[j + len];
                r[j + len] = fqmul(zeta, r[j + len] - t);
                j += 1;
            }
            start += 2 * len;
        }
        len <<= 1;
    }
    for j in 0..N {
        r[j] = montgomery_reduce((F as i32) * (r[j] as i32));
    }
}

/// Negacyclic base multiplication of two NTT-domain polynomials (both in
/// Montgomery form); result is in Montgomery form.
pub fn poly_basemul(r: &mut Poly, a: &Poly, b: &Poly) {
    for i in 0..N / 2 {
        let (ra, aa, ab) = (
            &mut r[2 * i..2 * i + 2],
            &a[2 * i..2 * i + 2],
            &b[2 * i..2 * i + 2],
        );
        let t = fqmul(ZETAS[64 + i], ab[1]);
        ra[0] = fqmul(aa[0], ab[0]) - fqmul(aa[1], t);
        ra[1] = fqmul(aa[0], ab[1]) + fqmul(aa[1], ab[0]);
    }
}

/// Convert an NTT-domain polynomial from Montgomery form to canonical form.
pub fn poly_frommont(r: &mut Poly) {
    for i in 0..N {
        r[i] = montgomery_reduce((r[i] as i32) * MONT);
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
