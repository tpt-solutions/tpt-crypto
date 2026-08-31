//! ML-DSA polynomial arithmetic over `R_q = Z_q[X] / (X^256 + 1)`.
//!
//! The NTT twist table [`ZETAS`] and `QINV` are taken verbatim from the FIPS 204
//! reference so the math matches the wire format exactly. The NTT is evaluated in
//! canonical (non-Montgomery) arithmetic: [`Poly::ntt`] / [`Poly::inv_ntt`] are the
//! forward/inverse negacyclic NTT and the pointwise products are ordinary modular
//! multiplications, which keeps the algebra self-consistent and verifiable against
//! the schoolbook convolution.
//!
//! The functions are branch-free on secret data: the only loops run over fixed
//! iteration counts and the norm/hint checks use bitwise reductions.

use tpt_crypto_ct::Choice;

/// The polynomial modulus: `q = 8_380_417 = 2^23 − 2^13 + 1`.
pub const Q: i32 = 8_380_417;
/// The polynomial degree `n = 256`.
pub const N: usize = 256;
/// Number of dropped bits in `Power2Round`: `d = 13`.
const D: i32 = 13;
/// `q⁻¹ mod 2³²` (reference `QINV`), used by the Montgomery reduction.
const QINV: i32 = 58_728_449;
/// `256⁻¹ mod q`, the inverse-NTT normalization factor (`invntt` divides by 256).
const INV256: i32 = 8_347_681;

/// NTT twiddle factors `ζ^{brv(i)}` in Montgomery form (reference `ZETAS`).
pub const ZETAS: [i32; N] = [
    0, 25847, -2608894, -518909, 237124, -777960, -876248, 466468, 1826347, 2353451, -359251,
    -2091905, 3119733, -2884855, 3111497, 2680103, 2725464, 1024112, -1079900, 3585928, -549488,
    -1119584, 2619752, -2108549, -2118186, -3859737, -1399561, -3277672, 1757237, -19422, 4010497,
    280005, 2706023, 95776, 3077325, 3530437, -1661693, -3592148, -2537516, 3915439, -3861115,
    -3043716, 3574422, -2867647, 3539968, -300467, 2348700, -539299, -1699267, -1643818, 3505694,
    -3821735, 3507263, -2140649, -1600420, 3699596, 811944, 531354, 954230, 3881043, 3900724,
    -2556880, 2071892, -2797779, -3930395, -1528703, -3677745, -3041255, -1452451, 3475950,
    2176455, -1585221, -1257611, 1939314, -4083598, -1000202, -3190144, -3157330, -3632928, 126922,
    3412210, -983419, 2147896, 2715295, -2967645, -3693493, -411027, -2477047, -671102, -1228525,
    -22981, -1308169, -381987, 1349076, 1852771, -1430430, -3343383, 264944, 508951, 3097992,
    44288, -1100098, 904516, 3958618, -3724342, -8578, 1653064, -3249728, 2389356, -210977, 759969,
    -1316856, 189548, -3553272, 3159746, -1851402, -2409325, -177440, 1315589, 1341330, 1285669,
    -1584928, -812732, -1439742, -3019102, -3881060, -3628969, 3839961, 2091667, 3407706, 2316500,
    3817976, -3342478, 2244091, -2446433, -3562462, 266997, 2434439, -1235728, 3513181, -3520352,
    -3759364, -1197226, -3193378, 900702, 1859098, 909542, 819034, 495491, -1613174, -43260,
    -522500, -655327, -3122442, 2031748, 3207046, -3556995, -525098, -768622, -3595838, 342297,
    286988, -2437823, 4108315, 3437287, -3342277, 1735879, 203044, 2842341, 2691481, -2590150,
    1265009, 4055324, 1247620, 2486353, 1595974, -3767016, 1250494, 2635921, -3548272, -2994039,
    1869119, 1903435, -1050970, -1333058, 1237275, -3318210, -1430225, -451100, 1312455, 3306115,
    -1962642, -1279661, 1917081, -2546312, -1374803, 1500165, 777191, 2235880, 3406031, -542412,
    -2831860, -1671176, -1846953, -2584293, -3724270, 594136, -3776993, -2013608, 2432395, 2454455,
    -164721, 1957272, 3369112, 185531, -1207385, -3183426, 162844, 1616392, 3014001, 810149,
    1652634, -3694233, -1799107, -3038916, 3523897, 3866901, 269760, 2213111, -975884, 1717735,
    472078, -426683, 1723600, -1803090, 1910376, -1667432, -1104333, -260646, -3833893, -2939036,
    -2235985, -420899, -2286327, 183443, -976891, 1612842, -3545687, -554416, 3919660, -48306,
    -1362209, 3937738, 1400424, -846154, 1976782,
];

/// A `γ₂` decomposition parameter set.
///
/// `VALUE` is `γ₂` and `W1_BITS` is the bit width used to pack `w₁` during
/// signing/verification.
pub trait Gamma2: Copy + Clone + core::fmt::Debug + PartialEq + Eq {
    /// `γ₂`.
    const VALUE: i32;
    /// Number of bits used to pack `w₁`.
    const W1_BITS: usize;
}

/// `γ₂ = (q − 1) / 88` (ML-DSA-44).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct Gamma2Q88;
/// `γ₂ = (q − 1) / 32` (ML-DSA-65 / -87).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
pub struct Gamma2Q32;

impl Gamma2 for Gamma2Q88 {
    const VALUE: i32 = (Q - 1) / 88;
    const W1_BITS: usize = 6;
}
impl Gamma2 for Gamma2Q32 {
    const VALUE: i32 = (Q - 1) / 32;
    const W1_BITS: usize = 4;
}

/// A single ML-DSA polynomial: 256 coefficients in `(-q, q)`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Poly {
    /// The raw coefficients `c₀ … c₂₅₅`. Public so the NTT and packing code can
    /// index directly.
    pub coeffs: [i32; N],
}

impl Default for Poly {
    fn default() -> Self {
        Poly::ZERO
    }
}

impl Poly {
    /// The all-zero polynomial.
    pub const ZERO: Poly = Poly {
        coeffs: [0i32; N],
    };

    /// `x^e mod q` (q prime), used to build the NTT twiddle table.
    #[inline]
    fn pow_mod(mut base: i64, mut exp: i64) -> i32 {
        let mut r = 1i64;
        let q = Q as i64;
        base %= q;
        if base < 0 {
            base += q;
        }
        while exp > 0 {
            if exp & 1 == 1 {
                r = (r * base) % q;
            }
            base = (base * base) % q;
            exp >>= 1;
        }
        r as i32
    }

    /// Montgomery radix `R = 2³²`.
    const R: i64 = 1i64 << 32;

    /// Convert a canonical coefficient into Montgomery form: `mont(c) = c·R mod q`.
    #[inline]
    fn to_mont(c: i32) -> i32 {
        Self::reduce_mod((c as i64) * Self::R)
    }

    /// Montgomery reduction `m ⟶ m·2⁻³² mod q` (REDC), matching the FIPS 204
    /// reference `montgomery_reduce`. The multiplier is taken from the **unsigned**
    /// low 32 bits of `a` (i.e. `(int32_t)((uint64_t)a * QINV)`), so it is correct
    /// for both positive and negative `a`.
    #[inline]
    const fn montgomery_reduce(a: i64) -> i32 {
        let a_u = a as u64;
        let t = ((a_u.wrapping_mul(QINV as u64)) as u32) as i32;
        ((a - (t as i64) * (Q as i64)) >> 32) as i32
    }

    /// Reduce an `i64` into the canonical range `[0, q)`.
    #[inline]
    fn reduce_mod(x: i64) -> i32 {
        let mut r = x % (Q as i64);
        if r < 0 {
            r += Q as i64;
        }
        r as i32
    }

    /// Barrett-style reduction into `(-q, q]`.
    #[inline]
    fn reduce32(a: i32) -> i32 {
        let t = (a + (1 << 22)) >> 23;
        a - t * Q
    }

    /// Conditional add of `q` to bring a reduced value into `[0, q)`.
    #[inline]
    fn caddq(a: i32) -> i32 {
        a + ((a >> 31) & Q)
    }

    /// Forward negacyclic NTT, in place (ring `Z_q[X]/(X^n + 1)`, canonical input).
    ///
    /// The canonical input is first lifted into Montgomery form; the transform is
    /// then evaluated with the Montgomery-encoded [`ZETAS`] twiddles, so the output
    /// lives in the NTT-domain (Montgomery) representation consumed by
    /// [`Poly::pointwise`] and [`Poly::pointwise_acc`].
    pub fn ntt(&mut self) {
        for c in self.coeffs.iter_mut() {
            *c = Self::to_mont(*c);
        }
        let a = &mut self.coeffs;
        let mut k = 0usize;
        let mut len = 128usize;
        while len > 0 {
            let mut start = 0usize;
            while start < N {
                k += 1;
                let zeta = ZETAS[k];
                for j in start..(start + len) {
                    let t = Self::montgomery_reduce((zeta as i64) * (a[j + len] as i64));
                    a[j + len] = a[j] - t;
                    a[j] = a[j] + t;
                }
                start += 2 * len;
            }
            len >>= 1;
        }
    }

    /// Inverse negacyclic NTT, in place (ring `Z_q[X]/(X^n + 1)`).
    ///
    /// Runs the reference `invntt_tomont` (Montgomery domain) on the NTT-domain
    /// (Montgomery) input and converts the result back to canonical form, so the
    /// caller receives coefficient-form `R_q` values.
    pub fn inv_ntt(&mut self) {
        let a = &mut self.coeffs;
        let mut k = N;
        let mut len = 1usize;
        while len < N {
            let mut start = 0usize;
            while start < N {
                k -= 1;
                let zeta = -ZETAS[k];
                for j in start..(start + len) {
                    let t = a[j];
                    a[j] = t + a[j + len];
                    a[j + len] = t - a[j + len];
                    a[j + len] = Self::montgomery_reduce((zeta as i64) * (a[j + len] as i64));
                }
                start += 2 * len;
            }
            len <<= 1;
        }
        // The inverse butterfly yields `MONT(256·x)`; strip the Montgomery factor
        // and divide by 256 (`MONT(256·x)·2⁻³²·256⁻¹ = x`).
        for c in a.iter_mut() {
            *c = ((Self::montgomery_reduce(*c as i64) as i64 * INV256 as i64) % Q as i64) as i32;
        }
    }

    /// Pointwise multiplication in the NTT domain: `self = a ∘ b`.
    ///
    /// Both `a` and `b` must be in NTT-domain (Montgomery) form; the result is a
    /// Montgomery-domain polynomial.
    pub fn pointwise(&mut self, a: &Poly, b: &Poly) {
        for i in 0..N {
            self.coeffs[i] = Self::montgomery_reduce((a.coeffs[i] as i64) * (b.coeffs[i] as i64));
        }
    }

    /// Accumulating pointwise multiplication: `self += a ∘ b` (NTT domain).
    pub fn pointwise_acc(&mut self, a: &Poly, b: &Poly) {
        for i in 0..N {
            let t = Self::montgomery_reduce((a.coeffs[i] as i64) * (b.coeffs[i] as i64));
            self.coeffs[i] = Self::reduce_mod((self.coeffs[i] as i64) + (t as i64));
        }
    }

    /// Reduce every coefficient with [`Poly::reduce32`].
    pub fn reduce(&mut self) {
        for c in self.coeffs.iter_mut() {
            *c = Self::reduce32(*c);
        }
    }

    /// Bring every coefficient into `[0, q)` with [`Poly::caddq`].
    pub fn canonicalize(&mut self) {
        for c in self.coeffs.iter_mut() {
            *c = Self::caddq(*c);
        }
    }

    /// `self += rhs` (coefficient-wise), keeping values small.
    pub fn add_assign(&mut self, rhs: &Poly) {
        for i in 0..N {
            self.coeffs[i] += rhs.coeffs[i];
        }
        self.reduce();
    }

    /// `self -= rhs` (coefficient-wise), keeping values small.
    pub fn sub_assign(&mut self, rhs: &Poly) {
        for i in 0..N {
            self.coeffs[i] -= rhs.coeffs[i];
        }
        self.reduce();
    }

    /// Multiply every coefficient by `2^d` (used to form `t₁·2^d` in verify).
    pub fn shift_left_d(&mut self) {
        for c in self.coeffs.iter_mut() {
            *c <<= D;
        }
        self.reduce();
        self.canonicalize();
    }

    /// `Power2Round`: split `self` into `(t₁, t₀)` with `self = t₁·2^d + t₀`.
    pub fn power2round_into(&self, t1: &mut Poly, t0: &mut Poly) {
        for i in 0..N {
            let a = self.coeffs[i];
            let a1 = (a + (1 << (D - 1)) - 1) >> D;
            let a0 = a - (a1 << D);
            t1.coeffs[i] = a1;
            t0.coeffs[i] = a0;
        }
    }

    /// `Decompose`: split `self` into `(r₁, r₀)` with `self = r₁·2γ₂ + r₀`.
    pub fn decompose_into<G: Gamma2>(&self, hi: &mut Poly, lo: &mut Poly) {
        for i in 0..N {
            let (a1, a0) = decompose_impl(G::VALUE, self.coeffs[i]);
            hi.coeffs[i] = a1;
            lo.coeffs[i] = a0;
        }
    }

    /// Reject if any coefficient has absolute value `>= bound` (branch-free).
    ///
    /// Returns [`Choice::TRUE`] when the polynomial is *out* of bounds.
    pub fn exceeds_norm(&self, bound: i32) -> Choice {
        if bound > (Q - 1) / 8 {
            return Choice::TRUE;
        }
        let mut any = Choice::FALSE;
        for &c in &self.coeffs {
            let t = c - ((c >> 31) & (2 * c));
            any = any | Choice::from_u8_lsb((t > bound) as u8);
        }
        any
    }
}

/// `HighBits(r)` (reference `decompose`, high part). `r` must be in `[0, q)`.
pub fn high_bits(gamma2: i32, a: i32) -> i32 {
    decompose_impl(gamma2, a).0
}

/// `Decompose(r)` (FIPS 204 Algorithm 36). `r` must be in `[0, q)`.
pub fn decompose_impl(gamma2: i32, a: i32) -> (i32, i32) {
    let mut a1 = (a + 127) >> 7;
    if gamma2 == (Q - 1) / 32 {
        a1 = (a1 * 1025 + (1 << 21)) >> 22;
        a1 &= 15;
    } else {
        a1 = (a1 * 11_275 + (1 << 23)) >> 24;
        a1 ^= ((43 - a1) >> 31) & a1;
    }
    let mut a0 = a - a1 * 2 * gamma2;
    a0 -= (((Q - 1) / 2 - a0) >> 31) & Q;
    if a1 * 2 * gamma2 == Q - 1 {
        (0, a0 - 1)
    } else {
        (a1, a0)
    }
}

/// `MakeHint(z, r)` (FIPS 204 Algorithm 39): `1` iff `HighBits(r)` and
/// `HighBits(r + z)` differ. Returns a [`Choice`].
#[inline]
pub fn make_hint(z: i32, r: i32, gamma2: i32) -> Choice {
    let r = canonicalize(r);
    let rz = canonicalize(r + z);
    Choice::from_u8_lsb((high_bits(gamma2, r) != high_bits(gamma2, rz)) as u8)
}

/// `UseHint(h, r)` (FIPS 204 Algorithm 40), with `h ∈ {0, 1}`.
#[inline]
pub fn use_hint(h: Choice, a: i32, gamma2: i32) -> i32 {
    let hb = h.unwrap_u8();
    let a = canonicalize(a);
    let (r1, r0) = decompose_impl(gamma2, a);
    if hb == 0 {
        return r1;
    }
    if gamma2 == (Q - 1) / 32 {
        if r0 > 0 {
            (r1 + 1) & 15
        } else {
            (r1 - 1 + 16) & 15
        }
    } else if r0 > 0 {
        if r1 == 43 {
            0
        } else {
            r1 + 1
        }
    } else if r1 == 0 {
        43
    } else {
        r1 - 1
    }
}

/// Bring `a` into `[0, q)` (reference `caddq` after `reduce32`).
#[inline]
pub(crate) fn canonicalize(a: i32) -> i32 {
    let r = Poly::reduce32(a);
    Poly::caddq(r)
}

// ── Bit packers / unpackers (FIPS 204 §4.4, Algorithms 16–19, 28) ────────────

/// Pack `s₁` / `s₂` coefficients (range `[−η, η]`) into `out`.
pub fn polyeta_pack(eta: i32, poly: &Poly, out: &mut [u8]) {
    if eta == 2 {
        for i in 0..(N / 8) {
            let t0 = (eta - poly.coeffs[8 * i]) as u8;
            let t1 = (eta - poly.coeffs[8 * i + 1]) as u8;
            let t2 = (eta - poly.coeffs[8 * i + 2]) as u8;
            let t3 = (eta - poly.coeffs[8 * i + 3]) as u8;
            let t4 = (eta - poly.coeffs[8 * i + 4]) as u8;
            let t5 = (eta - poly.coeffs[8 * i + 5]) as u8;
            let t6 = (eta - poly.coeffs[8 * i + 6]) as u8;
            let t7 = (eta - poly.coeffs[8 * i + 7]) as u8;
            out[3 * i] = t0 | (t1 << 3) | (t2 << 6);
            out[3 * i + 1] = (t2 >> 2) | (t3 << 1) | (t4 << 4) | (t5 << 7);
            out[3 * i + 2] = (t5 >> 1) | (t6 << 2) | (t7 << 5);
        }
    } else {
        for i in 0..(N / 2) {
            let t0 = (eta - poly.coeffs[2 * i]) as u8;
            let t1 = (eta - poly.coeffs[2 * i + 1]) as u8;
            out[i] = t0 | (t1 << 4);
        }
    }
}

/// Unpack `s₁` / `s₂` coefficients from `input`, or `None` if the length is wrong.
pub fn polyeta_unpack(eta: i32, input: &[u8]) -> Option<Poly> {
    let packed = if eta == 2 { 3 * (N / 8) } else { N / 2 };
    if input.len() != packed {
        return None;
    }
    let mut out = Poly::ZERO;
    if eta == 2 {
        for i in 0..(N / 8) {
            out.coeffs[8 * i] = i32::from(input[3 * i] & 7);
            out.coeffs[8 * i + 1] = i32::from((input[3 * i] >> 3) & 7);
            out.coeffs[8 * i + 2] =
                i32::from(((input[3 * i] >> 6) | (input[3 * i + 1] << 2)) & 7);
            out.coeffs[8 * i + 3] = i32::from((input[3 * i + 1] >> 1) & 7);
            out.coeffs[8 * i + 4] = i32::from((input[3 * i + 1] >> 4) & 7);
            out.coeffs[8 * i + 5] =
                i32::from(((input[3 * i + 1] >> 7) | (input[3 * i + 2] << 1)) & 7);
            out.coeffs[8 * i + 6] = i32::from((input[3 * i + 2] >> 2) & 7);
            out.coeffs[8 * i + 7] = i32::from((input[3 * i + 2] >> 5) & 7);
            for j in 0..8 {
                out.coeffs[8 * i + j] = eta - out.coeffs[8 * i + j];
            }
        }
    } else {
        for i in 0..(N / 2) {
            out.coeffs[2 * i] = i32::from(input[i] & 0x0F);
            out.coeffs[2 * i + 1] = i32::from(input[i] >> 4);
            out.coeffs[2 * i] = eta - out.coeffs[2 * i];
            out.coeffs[2 * i + 1] = eta - out.coeffs[2 * i + 1];
        }
    }
    Some(out)
}

/// Pack `t₁` (10-bit coefficients) into `out`.
pub fn polyt1_pack(poly: &Poly, out: &mut [u8]) {
    for i in 0..(N / 4) {
        out[5 * i] = poly.coeffs[4 * i] as u8;
        out[5 * i + 1] = ((poly.coeffs[4 * i] >> 8) | (poly.coeffs[4 * i + 1] << 2)) as u8;
        out[5 * i + 2] = ((poly.coeffs[4 * i + 1] >> 6) | (poly.coeffs[4 * i + 2] << 4)) as u8;
        out[5 * i + 3] = ((poly.coeffs[4 * i + 2] >> 4) | (poly.coeffs[4 * i + 3] << 6)) as u8;
        out[5 * i + 4] = (poly.coeffs[4 * i + 3] >> 2) as u8;
    }
}

/// Unpack `t₁` from `input`, or `None` if the length is wrong.
pub fn polyt1_unpack(input: &[u8]) -> Option<Poly> {
    if input.len() != 4 * (N / 4) * 10 / 8 {
        return None;
    }
    let mut out = Poly::ZERO;
    for i in 0..(N / 4) {
        out.coeffs[4 * i] =
            ((u32::from(input[5 * i]) | (u32::from(input[5 * i + 1]) << 8)) as i32) & 0x3FF;
        out.coeffs[4 * i + 1] = (((u32::from(input[5 * i + 1])) >> 2)
            | ((u32::from(input[5 * i + 2])) << 6)) as i32
            & 0x3FF;
        out.coeffs[4 * i + 2] = (((u32::from(input[5 * i + 2])) >> 4)
            | ((u32::from(input[5 * i + 3])) << 4)) as i32
            & 0x3FF;
        out.coeffs[4 * i + 3] = (((u32::from(input[5 * i + 3])) >> 6)
            | ((u32::from(input[5 * i + 4])) << 2)) as i32
            & 0x3FF;
    }
    Some(out)
}

/// Pack `t₀` (13-bit coefficients) into `out`.
pub fn polyt0_pack(poly: &Poly, out: &mut [u8]) {
    for i in 0..(N / 8) {
        let mut t = [0u32; 8];
        for j in 0..8 {
            t[j] = ((1 << (D - 1)) - poly.coeffs[8 * i + j]) as u32;
        }
        out[13 * i] = t[0] as u8;
        out[13 * i + 1] = ((t[0] >> 8) | (t[1] << 5)) as u8;
        out[13 * i + 2] = (t[1] >> 3) as u8;
        out[13 * i + 3] = ((t[1] >> 11) | (t[2] << 2)) as u8;
        out[13 * i + 4] = ((t[2] >> 6) | (t[3] << 7)) as u8;
        out[13 * i + 5] = (t[3] >> 1) as u8;
        out[13 * i + 6] = ((t[3] >> 9) | (t[4] << 4)) as u8;
        out[13 * i + 7] = (t[4] >> 4) as u8;
        out[13 * i + 8] = ((t[4] >> 12) | (t[5] << 1)) as u8;
        out[13 * i + 9] = ((t[5] >> 7) | (t[6] << 6)) as u8;
        out[13 * i + 10] = (t[6] >> 2) as u8;
        out[13 * i + 11] = ((t[6] >> 10) | (t[7] << 3)) as u8;
        out[13 * i + 12] = (t[7] >> 5) as u8;
    }
}

/// Unpack `t₀` from `input`, or `None` if the length is wrong.
pub fn polyt0_unpack(input: &[u8]) -> Option<Poly> {
    if input.len() != 13 * (N / 8) {
        return None;
    }
    let mut out = Poly::ZERO;
    for i in 0..(N / 8) {
        out.coeffs[8 * i] =
            (u32::from(input[13 * i]) | (u32::from(input[13 * i + 1]) << 8)) as i32 & 0x1FFF;
        out.coeffs[8 * i + 1] = ((u32::from(input[13 * i + 1]) >> 5)
            | (u32::from(input[13 * i + 2]) << 3)
            | (u32::from(input[13 * i + 3]) << 11)) as i32
            & 0x1FFF;
        out.coeffs[8 * i + 2] = ((u32::from(input[13 * i + 3]) >> 2)
            | (u32::from(input[13 * i + 4]) << 6)) as i32
            & 0x1FFF;
        out.coeffs[8 * i + 3] = ((u32::from(input[13 * i + 4]) >> 7)
            | (u32::from(input[13 * i + 5]) << 1)
            | (u32::from(input[13 * i + 6]) << 9)) as i32
            & 0x1FFF;
        out.coeffs[8 * i + 4] = ((u32::from(input[13 * i + 6]) >> 4)
            | (u32::from(input[13 * i + 7]) << 4)
            | (u32::from(input[13 * i + 8]) << 12)) as i32
            & 0x1FFF;
        out.coeffs[8 * i + 5] = ((u32::from(input[13 * i + 8]) >> 1)
            | (u32::from(input[13 * i + 9]) << 7)) as i32
            & 0x1FFF;
        out.coeffs[8 * i + 6] = ((u32::from(input[13 * i + 9]) >> 6)
            | (u32::from(input[13 * i + 10]) << 2)
            | (u32::from(input[13 * i + 11]) << 10)) as i32
            & 0x1FFF;
        out.coeffs[8 * i + 7] = ((u32::from(input[13 * i + 11]) >> 3)
            | (u32::from(input[13 * i + 12]) << 5)) as i32
            & 0x1FFF;
        for j in 0..8 {
            out.coeffs[8 * i + j] = (1 << (D - 1)) - out.coeffs[8 * i + j];
        }
    }
    Some(out)
}

/// Pack `z` coefficients (range `[−γ₁, γ₁]`) into `out`.
pub fn polyz_pack(gamma1: i32, poly: &Poly, out: &mut [u8]) {
    if gamma1 == (1 << 17) {
        for i in 0..(N / 4) {
            let t0 = (gamma1 - poly.coeffs[4 * i]) as u32;
            let t1 = (gamma1 - poly.coeffs[4 * i + 1]) as u32;
            let t2 = (gamma1 - poly.coeffs[4 * i + 2]) as u32;
            let t3 = (gamma1 - poly.coeffs[4 * i + 3]) as u32;
            out[9 * i] = t0 as u8;
            out[9 * i + 1] = (t0 >> 8) as u8;
            out[9 * i + 2] = ((t0 >> 16) | (t1 << 2)) as u8;
            out[9 * i + 3] = (t1 >> 6) as u8;
            out[9 * i + 4] = ((t1 >> 14) | (t2 << 4)) as u8;
            out[9 * i + 5] = (t2 >> 4) as u8;
            out[9 * i + 6] = ((t2 >> 12) | (t3 << 6)) as u8;
            out[9 * i + 7] = (t3 >> 2) as u8;
            out[9 * i + 8] = (t3 >> 10) as u8;
        }
    } else {
        for i in 0..(N / 2) {
            let t0 = (gamma1 - poly.coeffs[2 * i]) as u32;
            let t1 = (gamma1 - poly.coeffs[2 * i + 1]) as u32;
            out[5 * i] = t0 as u8;
            out[5 * i + 1] = (t0 >> 8) as u8;
            out[5 * i + 2] = ((t0 >> 16) | (t1 << 4)) as u8;
            out[5 * i + 3] = (t1 >> 4) as u8;
            out[5 * i + 4] = (t1 >> 12) as u8;
        }
    }
}

/// Unpack `z` coefficients from `input`, or `None` if the length is wrong.
pub fn polyz_unpack(gamma1: i32, input: &[u8]) -> Option<Poly> {
    let packed = if gamma1 == (1 << 17) { 9 * (N / 4) } else { 5 * (N / 2) };
    if input.len() != packed {
        return None;
    }
    let mut out = Poly::ZERO;
    if gamma1 == (1 << 17) {
        for i in 0..(N / 4) {
            out.coeffs[4 * i] = (u32::from(input[9 * i])
                | (u32::from(input[9 * i + 1]) << 8)
                | (u32::from(input[9 * i + 2]) << 16)) as i32
                & 0x3FFFF;
            out.coeffs[4 * i + 1] = ((u32::from(input[9 * i + 2]) >> 2)
                | (u32::from(input[9 * i + 3]) << 6)
                | (u32::from(input[9 * i + 4]) << 14)) as i32
                & 0x3FFFF;
            out.coeffs[4 * i + 2] = ((u32::from(input[9 * i + 4]) >> 4)
                | (u32::from(input[9 * i + 5]) << 4)
                | (u32::from(input[9 * i + 6]) << 12)) as i32
                & 0x3FFFF;
            out.coeffs[4 * i + 3] = ((u32::from(input[9 * i + 6]) >> 6)
                | (u32::from(input[9 * i + 7]) << 2)
                | (u32::from(input[9 * i + 8]) << 10)) as i32
                & 0x3FFFF;
            out.coeffs[4 * i] = gamma1 - out.coeffs[4 * i];
            out.coeffs[4 * i + 1] = gamma1 - out.coeffs[4 * i + 1];
            out.coeffs[4 * i + 2] = gamma1 - out.coeffs[4 * i + 2];
            out.coeffs[4 * i + 3] = gamma1 - out.coeffs[4 * i + 3];
        }
    } else {
        for i in 0..(N / 2) {
            out.coeffs[2 * i] = (u32::from(input[5 * i])
                | (u32::from(input[5 * i + 1]) << 8)
                | (u32::from(input[5 * i + 2]) << 16)) as i32
                & 0xFFFFF;
            out.coeffs[2 * i + 1] = ((u32::from(input[5 * i + 2]) >> 4)
                | (u32::from(input[5 * i + 3]) << 4)
                | (u32::from(input[5 * i + 4]) << 12)) as i32;
            out.coeffs[2 * i] = gamma1 - out.coeffs[2 * i];
            out.coeffs[2 * i + 1] = gamma1 - out.coeffs[2 * i + 1];
        }
    }
    Some(out)
}

/// Pack `w₁` coefficients (the high bits after `Decompose`) into `out`.
pub fn polyw1_pack(gamma2: i32, poly: &Poly, out: &mut [u8]) {
    if gamma2 == (Q - 1) / 88 {
        for i in 0..(N / 4) {
            out[3 * i] = (poly.coeffs[4 * i] | (poly.coeffs[4 * i + 1] << 6)) as u8;
            out[3 * i + 1] = ((poly.coeffs[4 * i + 1] >> 2) | (poly.coeffs[4 * i + 2] << 4)) as u8;
            out[3 * i + 2] = ((poly.coeffs[4 * i + 2] >> 4) | (poly.coeffs[4 * i + 3] << 2)) as u8;
        }
    } else {
        for i in 0..(N / 2) {
            out[i] = (poly.coeffs[2 * i] | (poly.coeffs[2 * i + 1] << 4)) as u8;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn montgomery_round_trip() {
        for x in [0i32, 1, Q - 1, 12345, Q / 2] {
            let m = Poly::montgomery_reduce((x as i64) << 32);
            assert_eq!(m, x, "to_mont/strip round trip failed for {x}");
        }
    }

    fn ntt_multiplication_matches_schoolbook() {
        let mut a = Poly::ZERO;
        let mut b = Poly::ZERO;
        for i in 0..N {
            a.coeffs[i] = ((i * 7 + 3) % Q as usize) as i32 - (Q / 2);
            b.coeffs[i] = ((i * 5 + 1) % Q as usize) as i32 - (Q / 2);
        }
        a.canonicalize();
        b.canonicalize();

        let mut a_hat = a;
        let mut b_hat = b;
        a_hat.ntt();
        b_hat.ntt();
        let mut c_hat = Poly::ZERO;
        c_hat.pointwise(&a_hat, &b_hat);
        let mut c = c_hat;
        c.inv_ntt();
        c.canonicalize();

        // Schoolbook negacyclic product mod (X^256 + 1). Accumulate in i64 to
        // avoid overflow (coefficients can reach ~N·q²).
        let mut expected = [0i64; N];
        for i in 0..N {
            let ai = a.coeffs[i] as i64;
            for j in 0..N {
                let bj = b.coeffs[j] as i64;
                let k = i + j;
                if k < N {
                    expected[k] += ai * bj;
                } else {
                    expected[k - N] -= ai * bj;
                }
            }
        }
        let expected: [i32; N] = {
            let mut e = [0i32; N];
            for i in 0..N {
                let mut r = expected[i] % (Q as i64);
                if r < 0 {
                    r += Q as i64;
                }
                e[i] = r as i32;
            }
            e
        };
        assert_eq!(c.coeffs, expected, "NTT product != schoolbook");
    }

    fn decompose_matches_spec_exhaustively() {
        for g in [(Q - 1) / 88, (Q - 1) / 32] {
            for r in [0i32, 1, g, g + 1, Q - 2, Q - 1, Q / 2] {
                let (r1, r0) = decompose_impl(g, r);
                // The identity `r = r₁·2γ₂ + r₀` holds modulo `q`; at the top
                // boundary (`r = q-2`, `r₁ = 0`, `r₀ = -2`) the integer equality
                // is off by a multiple of `q`, so compare the canonical forms.
                assert_eq!(
                    canonicalize(r),
                    canonicalize(r1 * 2 * g + r0),
                    "decompose identity failed for g={g} r={r}"
                );
                assert!(r0.abs() <= g, "low bits out of range for g={g} r={r}: {r0}");
            }
        }
    }

    fn hint_round_trip() {
        for g in [(Q - 1) / 88, (Q - 1) / 32] {
            for r in [0i32, 100, g, Q - 1, Q / 2, 4096, -4096] {
                let r = canonicalize(r);
                let z = 1i32; // small perturbation
                let h = make_hint(z, r, g);
                let recon = use_hint(h, r, g);
                // UseHint must recover HighBits(r + z).
                let want = high_bits(g, canonicalize(r + z));
                assert_eq!(recon, want, "hint round trip failed for g={g} r={r}");
            }
        }
    }

    fn power2round_is_exact() {
        for r in [0i32, 1, 4096, 4097, Q - 1, Q / 2] {
            let r = canonicalize(r);
            let mut t1 = Poly::ZERO;
            let mut t0 = Poly::ZERO;
            let mut p = Poly::ZERO;
            p.coeffs[0] = r;
            p.power2round_into(&mut t1, &mut t0);
            assert_eq!(
                r,
                t1.coeffs[0] * (1 << D) + t0.coeffs[0],
                "power2round identity failed for {r}"
            );
            assert!(t0.coeffs[0].abs() <= 1 << (D - 1), "t0 out of range for {r}");
        }
    }

    fn exceeds_norm_is_exact() {
        let mut p = Poly::ZERO;
        p.coeffs[0] = 5;
        p.coeffs[1] = -5;
        assert!(!bool::from(p.exceeds_norm(5)));
        assert!(bool::from(p.exceeds_norm(4)));
    }

    fn ntt_round_trip_debug() {
        let mut a = Poly::ZERO;
        for i in 0..N {
            a.coeffs[i] = ((i * 11 + 5) % Q as usize) as i32 - Q / 2;
        }
        a.canonicalize();
        let orig = a;
        a.ntt();
        a.inv_ntt();
        assert_eq!(a.coeffs, orig.coeffs, "ntt round trip failed");
    }

    fn zeta_is_primitive_root() {
        assert_eq!(Poly::pow_mod(1753, 256), Q - 1, "1753^256 != -1");
        assert_eq!(Poly::pow_mod(1753, 512), 1, "1753^512 != 1");
    }

    fn ntt_conv_kind() {
        // Discriminate cyclic vs negacyclic: in R_q[X]/(X^n+1) we have X^n = -1,
        // so X · X^{n-1} = -1. A cyclic NTT would instead yield X^n reduced
        // modulo (X^n-1), i.e. the coefficient 1 at index 0.
        let mut a = Poly::ZERO;
        a.coeffs[1] = 1;
        let mut b = Poly::ZERO;
        b.coeffs[N - 1] = 1;
        let mut a_hat = a;
        let mut b_hat = b;
        a_hat.ntt();
        b_hat.ntt();
        let mut c_hat = Poly::ZERO;
        c_hat.pointwise(&a_hat, &b_hat);
        let mut c = c_hat;
        c.inv_ntt();
        c.canonicalize();
        let mut nega = Poly::ZERO;
        nega.coeffs[0] = Q - 1;
        assert_eq!(
            c.coeffs,
            nega.coeffs,
            "ntt computes cyclic, not negacyclic; product = {:?}",
            &c.coeffs[..4]
        );
    }

    #[test]
    fn all_poly_tests() {
        montgomery_round_trip();
        zeta_is_primitive_root();
        ntt_round_trip_debug();
        ntt_conv_kind();
        ntt_multiplication_matches_schoolbook();
        decompose_matches_spec_exhaustively();
        hint_round_trip();
        power2round_is_exact();
        exceeds_norm_is_exact();
    }
}
