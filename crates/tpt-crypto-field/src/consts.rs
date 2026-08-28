//! Compile-time arithmetic over fixed-size little-endian limb arrays.
//!
//! These helpers power two things:
//! 1. Deriving the Montgomery constants (`MU`, `R2`, `ONE_MONT`, …) for each
//!    prime at *compile time*, so the runtime field arithmetic is branch-free
//!    and allocation-free.
//! 2. A small, independent reference modular arithmetic used by the test suite
//!    to cross-check the Montgomery implementation (matching a `tpt-math-exact`
//!    style big-integer reduction, but computed locally).
//!
//! All limb arrays use the concrete length [`MAX_LIMBS`] so that intermediate
//! buffers (`2 * MAX_LIMBS`, `MAX_LIMBS + 1`) are concrete literals and the crate
//! builds on stable Rust (no `generic_const_exprs` needed).

#![allow(dead_code)]

/// Maximum limb count supported by this crate (384 bits), covering every field
/// here (P-256/P-384/BLS base and scalar fields, and Ed25519).
pub const MAX_LIMBS: usize = 6;

/// `a - b` over `N` limbs, returning the result and a borrow flag (`1` if `a < b`).
///
/// The borrow is applied as two separate single-limb subtractions so that a
/// borrow propagating through a limb equal to `0xFF..FF` is never lost to a
/// wrapping add.
#[inline]
pub(crate) const fn sub_limbs<const N: usize>(a: &[u64; N], b: &[u64; N]) -> ([u64; N], u8) {
    let mut out = [0u64; N];
    let mut borrow = 0u64;
    let mut i = 0;
    while i < N {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d, b2) = d1.overflowing_sub(borrow);
        out[i] = d;
        borrow = (b1 | b2) as u64;
        i += 1;
    }
    (out, borrow as u8)
}

/// `a + b` over `N` limbs, returning the result and a carry flag.
///
/// The carry is applied as two separate single-limb additions so that a carry
/// propagating into a limb equal to `0xFF..FF` is never lost to a wrapping add.
#[inline]
pub(crate) const fn add_limbs<const N: usize>(a: &[u64; N], b: &[u64; N]) -> ([u64; N], u8) {
    let mut out = [0u64; N];
    let mut carry = 0u64;
    let mut i = 0;
    while i < N {
        let (s1, c1) = a[i].overflowing_add(b[i]);
        let (s, c2) = s1.overflowing_add(carry);
        out[i] = s;
        carry = (c1 | c2) as u64;
        i += 1;
    }
    (out, carry as u8)
}

/// Lexicographic `a >= b` over limb arrays (most-significant limb first).
#[inline]
pub(crate) const fn limbs_ge<const N: usize>(a: &[u64; N], b: &[u64; N]) -> bool {
    let mut i = N;
    while i > 0 {
        i -= 1;
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true
}

/// Lexicographic `a == b` over limb arrays.
#[inline]
pub(crate) const fn limbs_eq<const N: usize>(a: &[u64; N], b: &[u64; N]) -> bool {
    let mut i = 0;
    while i < N {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// `a - b mod m`, assuming `a < m` and `b < m`.
#[inline]
pub(crate) const fn sub_mod(
    a: &[u64; MAX_LIMBS],
    b: &[u64; MAX_LIMBS],
    m: &[u64; MAX_LIMBS],
) -> [u64; MAX_LIMBS] {
    let (mut r, borrow) = sub_limbs(a, b);
    if borrow == 1 {
        let (s, _) = add_limbs(&r, m);
        r = s;
    }
    r
}

/// `a + b mod m`, assuming `a < m` and `b < m`.
#[inline]
pub(crate) const fn add_mod(
    a: &[u64; MAX_LIMBS],
    b: &[u64; MAX_LIMBS],
    m: &[u64; MAX_LIMBS],
) -> [u64; MAX_LIMBS] {
    let (r, _) = add_limbs(a, b);
    if limbs_ge(&r, m) {
        sub_mod(&r, m, m)
    } else {
        r
    }
}

/// `2 * a mod m`, assuming `a < m`.
#[inline]
pub(crate) const fn double_mod(a: &[u64; MAX_LIMBS], m: &[u64; MAX_LIMBS]) -> [u64; MAX_LIMBS] {
    let (r, _) = add_limbs(a, a);
    if limbs_ge(&r, m) {
        sub_mod(&r, m, m)
    } else {
        r
    }
}

/// Shift a `MAX_LIMBS`-limb value left by `bits`, producing `2 * MAX_LIMBS` limbs.
#[inline]
pub(crate) const fn shl_bits(m: &[u64; MAX_LIMBS], bits: u32) -> [u64; 2 * MAX_LIMBS] {
    let mut out = [0u64; 2 * MAX_LIMBS];
    let limb_shift = (bits / 64) as usize;
    let bit_shift = (bits % 64) as u32;
    let mut i = 0;
    while i < MAX_LIMBS {
        let v = m[i];
        if limb_shift + i < 2 * MAX_LIMBS {
            out[limb_shift + i] = out[limb_shift + i].wrapping_add(v << bit_shift);
        }
        if bit_shift > 0 && limb_shift + i + 1 < 2 * MAX_LIMBS {
            out[limb_shift + i + 1] = out[limb_shift + i + 1].wrapping_add(v >> (64 - bit_shift));
        }
        i += 1;
    }
    out
}

/// Plain `2*MAX_LIMBS`-limb subtraction (assumes `a >= b`).
///
/// The borrow is applied as two separate single-limb subtractions so that a
/// borrow propagating through a limb equal to `0xFF..FF` is never lost to a
/// wrapping add.
#[inline]
pub(crate) const fn sub_big(
    a: &[u64; 2 * MAX_LIMBS],
    b: &[u64; 2 * MAX_LIMBS],
) -> [u64; 2 * MAX_LIMBS] {
    let mut out = [0u64; 2 * MAX_LIMBS];
    let mut borrow = 0u64;
    let mut i = 0;
    while i < 2 * MAX_LIMBS {
        let (d1, b1) = a[i].overflowing_sub(b[i]);
        let (d, b2) = d1.overflowing_sub(borrow);
        out[i] = d;
        borrow = (b1 | b2) as u64;
        i += 1;
    }
    out
}

/// Reduce a `2*MAX_LIMBS`-limb value modulo an `MAX_LIMBS`-limb modulus via long division.
#[inline]
pub(crate) const fn mod_reduce(t: &[u64; 2 * MAX_LIMBS], m: &[u64; MAX_LIMBS]) -> [u64; MAX_LIMBS] {
    let mbits = (MAX_LIMBS as u32) * 64;
    let mut r = *t;
    let mut bit = (2u32 * MAX_LIMBS as u32) * 64 - 1;
    while bit >= mbits - 1 {
        let shift = bit - (mbits - 1);
        let sm = shl_bits(m, shift);
        if limbs_ge(&r, &sm) {
            r = sub_big(&r, &sm);
        }
        bit -= 1;
    }
    let mut out = [0u64; MAX_LIMBS];
    let mut i = 0;
    while i < MAX_LIMBS {
        out[i] = r[i];
        i += 1;
    }
    if limbs_ge(&out, m) {
        let (d, _) = sub_limbs(&out, m);
        out = d;
    }
    out
}

/// Schoolbook multiplication followed by modular reduction: `(a * b) mod m`.
#[inline]
pub(crate) const fn mul_mod(
    a: &[u64; MAX_LIMBS],
    b: &[u64; MAX_LIMBS],
    m: &[u64; MAX_LIMBS],
) -> [u64; MAX_LIMBS] {
    let mut t = [0u64; 2 * MAX_LIMBS];
    let mut i = 0;
    while i < MAX_LIMBS {
        let mut carry: u128 = 0;
        let mut j = 0;
        while j < MAX_LIMBS {
            let prod = (a[i] as u128) * (b[j] as u128) + (t[i + j] as u128) + carry;
            t[i + j] = prod as u64;
            carry = prod >> 64;
            j += 1;
        }
        let mut k = i + MAX_LIMBS;
        let mut c = carry;
        while k < 2 * MAX_LIMBS {
            let sum = (t[k] as u128) + c;
            t[k] = sum as u64;
            c = sum >> 64;
            if c == 0 {
                break;
            }
            k += 1;
        }
        i += 1;
    }
    mod_reduce(&t, m)
}

/// Left-to-right square-and-multiply exponentiation: `base^exp mod m`.
#[inline]
pub(crate) const fn pow_mod(
    base: &[u64; MAX_LIMBS],
    exp: &[u64; MAX_LIMBS],
    m: &[u64; MAX_LIMBS],
) -> [u64; MAX_LIMBS] {
    let mut result = [0u64; MAX_LIMBS];
    result[0] = 1;
    let mut limb = MAX_LIMBS;
    while limb > 0 {
        limb -= 1;
        let mut bit = 63u32;
        loop {
            result = mul_mod(&result, &result, m);
            let b = (exp[limb] >> bit) & 1;
            if b == 1 {
                result = mul_mod(&result, base, m);
            }
            if bit == 0 {
                break;
            }
            bit -= 1;
        }
    }
    result
}

/// `m0^{-1} mod 2^64` via Newton iteration, then negated: `mu = -p^{-1} mod 2^64`.
#[inline]
pub(crate) const fn mu_of(m: &[u64; MAX_LIMBS]) -> u64 {
    let x = m[0];
    let mut y: u64 = x; // correct mod 2^3 for odd x
    y = y.wrapping_mul(2u64.wrapping_sub(x.wrapping_mul(y)));
    y = y.wrapping_mul(2u64.wrapping_sub(x.wrapping_mul(y)));
    y = y.wrapping_mul(2u64.wrapping_sub(x.wrapping_mul(y)));
    y = y.wrapping_mul(2u64.wrapping_sub(x.wrapping_mul(y)));
    y = y.wrapping_mul(2u64.wrapping_sub(x.wrapping_mul(y)));
    y.wrapping_neg()
}

/// `2^(64*l) mod m` — the Montgomery constant `R mod p`.
#[inline]
pub(crate) const fn one_mont_of(m: &[u64; MAX_LIMBS], l: usize) -> [u64; MAX_LIMBS] {
    let mut acc = [0u64; MAX_LIMBS];
    acc[0] = 1;
    let mut i = 0u32;
    while i < (l as u32) * 64 {
        acc = double_mod(&acc, m);
        i += 1;
    }
    acc
}

/// `2^(128*l) mod m` — the Montgomery constant `R^2 mod p`.
#[inline]
pub(crate) const fn r2_of(m: &[u64; MAX_LIMBS], l: usize) -> [u64; MAX_LIMBS] {
    let one = one_mont_of(m, l);
    mul_mod(&one, &one, m)
}

/// `m - 2`, as plain integer limbs (used for the Fermat inversion exponent `p-2`).
#[inline]
pub(crate) const fn mod_minus_2(m: &[u64; MAX_LIMBS]) -> [u64; MAX_LIMBS] {
    let mut out = *m;
    let mut borrow = 2u64;
    let mut i = 0;
    while i < MAX_LIMBS && borrow > 0 {
        let (d, bo) = out[i].overflowing_sub(borrow);
        out[i] = d;
        borrow = bo as u64;
        i += 1;
    }
    out
}

/// Shift a limb array right by `bits`.
#[inline]
pub(crate) const fn shr_limbs(a: &[u64; MAX_LIMBS], bits: u32) -> [u64; MAX_LIMBS] {
    let mut out = [0u64; MAX_LIMBS];
    let ls = (bits / 64) as usize;
    let bs = (bits % 64) as u32;
    let mut i = 0;
    while i < MAX_LIMBS {
        if i + ls < MAX_LIMBS {
            let mut v = a[i + ls] >> bs;
            if bs > 0 && i + ls + 1 < MAX_LIMBS {
                v |= a[i + ls + 1] << (64 - bs);
            }
            out[i] = v;
        }
        i += 1;
    }
    out
}

/// The exponent `S` in `p - 1 = 2^S * T` (number of trailing zero bits of `p-1`).
#[inline]
pub(crate) const fn s_of(m: &[u64; MAX_LIMBS]) -> u32 {
    let mut one = [0u64; MAX_LIMBS];
    one[0] = 1;
    let (mm1, _) = sub_limbs(m, &one);
    let mut s = 0u32;
    let mut i = 0;
    while i < MAX_LIMBS {
        if mm1[i] == 0 {
            s += 64;
            i += 1;
            continue;
        }
        let mut v = mm1[i];
        let mut tz = 0u32;
        while v & 1 == 0 {
            v >>= 1;
            tz += 1;
        }
        s += tz;
        break;
    }
    s
}

/// `T = (p - 1) >> S` (odd part of `p - 1`).
#[inline]
pub(crate) const fn t_of(m: &[u64; MAX_LIMBS], s: u32) -> [u64; MAX_LIMBS] {
    let mut one = [0u64; MAX_LIMBS];
    one[0] = 1;
    let (mm1, _) = sub_limbs(m, &one);
    shr_limbs(&mm1, s)
}

/// `(T + 1) >> 1`, used by Tonelli–Shanks.
#[inline]
pub(crate) const fn t_plus_1_over_2(t: &[u64; MAX_LIMBS]) -> [u64; MAX_LIMBS] {
    let mut one = [0u64; MAX_LIMBS];
    one[0] = 1;
    let (tp1, _) = add_limbs(t, &one);
    shr_limbs(&tp1, 1)
}

/// `(p + 1) >> 2`, used for `p ≡ 3 (mod 4)` square roots.
#[inline]
pub(crate) const fn sqrt_exp(m: &[u64; MAX_LIMBS]) -> [u64; MAX_LIMBS] {
    let mut one = [0u64; MAX_LIMBS];
    one[0] = 1;
    let (mp1, _) = add_limbs(m, &one);
    shr_limbs(&mp1, 2)
}

/// Smallest quadratic non-residue `a >= 2` modulo `m` (via Euler's criterion).
#[inline]
pub(crate) const fn find_nonresidue(m: &[u64; MAX_LIMBS]) -> [u64; MAX_LIMBS] {
    let mut one = [0u64; MAX_LIMBS];
    one[0] = 1;
    let (mm1, _) = sub_limbs(m, &one);
    let e = shr_limbs(&mm1, 1);
    let mut a: u64 = 2;
    loop {
        let mut base = [0u64; MAX_LIMBS];
        base[0] = a;
        let res = pow_mod(&base, &e, m);
        if limbs_eq(&res, &mm1) {
            return base;
        }
        a += 1;
    }
}
