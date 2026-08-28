//! Compile-time arithmetic over fixed-size little-endian limb arrays.
//!
//! These helpers power two things:
//! 1. Deriving the Montgomery constants (`MU`, `R2`, `ONE_MONT`, …) for each
//!    prime at *compile time*, so the runtime field arithmetic is branch-free
//!    and allocation-free.
//! 2. A small, independent reference modular arithmetic used by the test suite
//!    to cross-check the Montgomery implementation (`mul` matches `tpt-math-exact`
//!    style big-integer reduction, but computed locally so the crate stays
//!    dependency-free).

#![allow(dead_code)]

/// `a - b` over `L` limbs, returning the result and a borrow flag (`1` if `a < b`).
#[inline]
pub(crate) const fn sub_limbs<const L: usize>(a: &[u64; L], b: &[u64; L]) -> ([u64; L], u8) {
    let mut out = [0u64; L];
    let mut borrow = 0u64;
    let mut i = 0;
    while i < L {
        let (d, bo) = a[i].overflowing_sub(b[i].wrapping_add(borrow));
        out[i] = d;
        borrow = bo as u64;
        i += 1;
    }
    (out, borrow as u8)
}

/// `a + b` over `L` limbs, returning the result and a carry flag.
#[inline]
pub(crate) const fn add_limbs<const L: usize>(a: &[u64; L], b: &[u64; L]) -> ([u64; L], u8) {
    let mut out = [0u64; L];
    let mut carry = 0u64;
    let mut i = 0;
    while i < L {
        let (s, co) = a[i].overflowing_add(b[i].wrapping_add(carry));
        out[i] = s;
        carry = co as u64;
        i += 1;
    }
    (out, carry as u8)
}

/// Lexicographic `a >= b` over limb arrays (most-significant limb first).
#[inline]
pub(crate) const fn limbs_ge<const L: usize>(a: &[u64; L], b: &[u64; L]) -> bool {
    let mut i = L;
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
pub(crate) const fn limbs_eq<const L: usize>(a: &[u64; L], b: &[u64; L]) -> bool {
    let mut i = 0;
    while i < L {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// `a - b mod m`, assuming `a < m` and `b < m`.
#[inline]
pub(crate) const fn sub_mod<const L: usize>(a: &[u64; L], b: &[u64; L], m: &[u64; L]) -> [u64; L] {
    let (mut r, borrow) = sub_limbs(a, b);
    if borrow == 1 {
        let (s, _) = add_limbs(&r, m);
        r = s;
    }
    r
}

/// `a + b mod m`, assuming `a < m` and `b < m`.
#[inline]
pub(crate) const fn add_mod<const L: usize>(a: &[u64; L], b: &[u64; L], m: &[u64; L]) -> [u64; L] {
    let (r, _) = add_limbs(a, b);
    if limbs_ge(&r, m) {
        sub_mod(&r, m, m)
    } else {
        r
    }
}

/// `2 * a mod m`, assuming `a < m`.
#[inline]
pub(crate) const fn double_mod<const L: usize>(a: &[u64; L], m: &[u64; L]) -> [u64; L] {
    let (r, _) = add_limbs(a, a);
    if limbs_ge(&r, m) {
        sub_mod(&r, m, m)
    } else {
        r
    }
}

/// Shift a `L`-limb value left by `bits` (which is `< L*64`), producing `2L` limbs.
#[inline]
pub(crate) const fn shl_bits<const L: usize>(m: &[u64; L], bits: u32) -> [u64; 2 * L] {
    let mut out = [0u64; 2 * L];
    let limb_shift = (bits / 64) as usize;
    let bit_shift = (bits % 64) as u32;
    let mut i = 0;
    while i < L {
        let v = m[i];
        if limb_shift + i < 2 * L {
            out[limb_shift + i] = out[limb_shift + i].wrapping_add(v << bit_shift);
        }
        if bit_shift > 0 && limb_shift + i + 1 < 2 * L {
            out[limb_shift + i + 1] =
                out[limb_shift + i + 1].wrapping_add(v >> (64 - bit_shift));
        }
        i += 1;
    }
    out
}

/// Plain `2L`-limb subtraction (assumes `a >= b`).
#[inline]
pub(crate) const fn sub_big<const N: usize>(a: &[u64; N], b: &[u64; N]) -> [u64; N] {
    let mut out = [0u64; N];
    let mut borrow = 0u64;
    let mut i = 0;
    while i < N {
        let (d, bo) = a[i].overflowing_sub(b[i].wrapping_add(borrow));
        out[i] = d;
        borrow = bo as u64;
        i += 1;
    }
    out
}

/// Reduce a `2L`-limb value modulo an `L`-limb modulus via long division.
#[inline]
pub(crate) const fn mod_reduce<const L: usize>(t: &[u64; 2 * L], m: &[u64; L]) -> [u64; L] {
    let mbits = (L as u32) * 64;
    let mut r = *t;
    let mut bit = (2u32 * L as u32) * 64 - 1;
    while bit >= mbits - 1 {
        let shift = bit - (mbits - 1);
        let sm = shl_bits(m, shift);
        if limbs_ge(&r, &sm) {
            r = sub_big(&r, &sm);
        }
        bit -= 1;
    }
    let mut out = [0u64; L];
    let mut i = 0;
    while i < L {
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
pub(crate) const fn mul_mod<const L: usize>(a: &[u64; L], b: &[u64; L], m: &[u64; L]) -> [u64; L] {
    let mut t = [0u64; 2 * L];
    let mut i = 0;
    while i < L {
        let mut carry: u128 = 0;
        let mut j = 0;
        while j < L {
            let prod =
                (a[i] as u128) * (b[j] as u128) + (t[i + j] as u128) + carry;
            t[i + j] = prod as u64;
            carry = prod >> 64;
            j += 1;
        }
        let mut k = i + L;
        let mut c = carry;
        while k < 2 * L {
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
pub(crate) const fn pow_mod<const L: usize>(
    base: &[u64; L],
    exp: &[u64; L],
    m: &[u64; L],
) -> [u64; L] {
    let mut result = [0u64; L];
    result[0] = 1;
    let mut limb = L;
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
pub(crate) const fn mu_of<const L: usize>(m: &[u64; L]) -> u64 {
    let x = m[0];
    let mut y: u64 = x; // correct mod 2^3 for odd x
    y = y.wrapping_mul(2u64.wrapping_sub(x.wrapping_mul(y)));
    y = y.wrapping_mul(2u64.wrapping_sub(x.wrapping_mul(y)));
    y = y.wrapping_mul(2u64.wrapping_sub(x.wrapping_mul(y)));
    y = y.wrapping_mul(2u64.wrapping_sub(x.wrapping_mul(y)));
    y = y.wrapping_mul(2u64.wrapping_sub(x.wrapping_mul(y)));
    y.wrapping_neg()
}

/// `2^(64*L) mod m` — the Montgomery constant `R mod p`.
#[inline]
pub(crate) const fn one_mont_of<const L: usize>(m: &[u64; L]) -> [u64; L] {
    let mut acc = [0u64; L];
    acc[0] = 1;
    let mut i = 0u32;
    while i < (L as u32) * 64 {
        acc = double_mod(&acc, m);
        i += 1;
    }
    acc
}

/// `2^(128*L) mod m` — the Montgomery constant `R^2 mod p`.
#[inline]
pub(crate) const fn r2_of<const L: usize>(m: &[u64; L]) -> [u64; L] {
    let one = one_mont_of(m);
    mul_mod(&one, &one, m)
}

/// `m - 2`, as plain integer limbs (used for Fermat inversion exponent `p-2`).
#[inline]
pub(crate) const fn mod_minus_2<const L: usize>(m: &[u64; L]) -> [u64; L] {
    let mut out = *m;
    let mut borrow = 2u64;
    let mut i = 0;
    while i < L && borrow > 0 {
        let (d, bo) = out[i].overflowing_sub(borrow);
        out[i] = d;
        borrow = bo as u64;
        i += 1;
    }
    out
}

/// Shift a limb array right by `bits` (`< L*64`).
#[inline]
pub(crate) const fn shr_limbs<const L: usize>(a: &[u64; L], bits: u32) -> [u64; L] {
    let mut out = [0u64; L];
    let ls = (bits / 64) as usize;
    let bs = (bits % 64) as u32;
    let mut i = 0;
    while i < L {
        if i + ls < L {
            let mut v = a[i + ls] >> bs;
            if bs > 0 && i + ls + 1 < L {
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
pub(crate) const fn s_of<const L: usize>(m: &[u64; L]) -> u32 {
    let mut one = [0u64; L];
    one[0] = 1;
    let (mm1, _) = sub_limbs(m, &one);
    let mut s = 0u32;
    let mut i = 0;
    while i < L {
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
pub(crate) const fn t_of<const L: usize>(m: &[u64; L], s: u32) -> [u64; L] {
    let mut one = [0u64; L];
    one[0] = 1;
    let (mm1, _) = sub_limbs(m, &one);
    shr_limbs(&mm1, s)
}

/// `(T + 1) >> 1`, used by Tonelli–Shanks.
#[inline]
pub(crate) const fn t_plus_1_over_2<const L: usize>(t: &[u64; L]) -> [u64; L] {
    let mut one = [0u64; L];
    one[0] = 1;
    let (tp1, _) = add_limbs(t, &one);
    shr_limbs(&tp1, 1)
}

/// `(p + 1) >> 2`, used for `p ≡ 3 (mod 4)` square roots.
#[inline]
pub(crate) const fn sqrt_exp<const L: usize>(m: &[u64; L]) -> [u64; L] {
    let mut one = [0u64; L];
    one[0] = 1;
    let (mp1, _) = add_limbs(m, &one);
    shr_limbs(&mp1, 2)
}

/// Smallest quadratic non-residue `a >= 2` modulo `m` (via Euler's criterion).
#[inline]
pub(crate) const fn find_nonresidue<const L: usize>(m: &[u64; L]) -> [u64; L] {
    let mut one = [0u64; L];
    one[0] = 1;
    let (mm1, _) = sub_limbs(m, &one);
    let e = shr_limbs(&mm1, 1);
    let mut a: u64 = 2;
    loop {
        let mut base = [0u64; L];
        base[0] = a;
        let res = pow_mod(&base, &e, m);
        if limbs_eq(&res, &mm1) {
            return base;
        }
        a += 1;
    }
}
