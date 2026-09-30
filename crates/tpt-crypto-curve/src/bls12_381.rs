//! BLS12-381 pairing-friendly curve: `G1`, `G2`, and the optimal-ate pairing.
//!
//! * `E  / Fp  : y² = x³ + 4`            — group `G1` (r-torsion of `E(Fp)`),
//! * `E' / Fp²  : y² = x³ + 4·(u + 1)`   — group `G2` (r-torsion of the sextic
//!   D-type twist), mapped into `E(Fp¹²)` by the untwisting isomorphism,
//! * `pairing : G1 × G2 → GT ⊂ Fp¹²*`.
//!
//! Point arithmetic uses the Renes–Costello–Batina complete formulas (eprint
//! 2015/1060, Algorithm 1, specialised to `a = 0`), which are unified and
//! exception-free for every pair of inputs, so a single branch-free path covers
//! the identity, doublings and `P + (−P)`. Scalar multiplication is a
//! fixed-length double-and-add with one [`Field::ct_select`] per bit.
//!
//! The Miller loop is carried out with full `Fp¹²` arithmetic on the untwisted
//! `G2` point (denominator elimination applies for the degree-6 twist, so only
//! the numerator line functions are accumulated). The final exponentiation is a
//! single `f^((p¹² − 1)/r)` — correct and simple, not the fastest known method.
//!
//! Subgroup membership is checked by the definitional `[r]·P == O` test. Faster
//! endomorphism-based checks exist and can replace it without changing the API.

extern crate alloc;

use alloc::vec::Vec;

use tpt_crypto_field::{
    bls12381_final_exp_exponent, Bls12381Fp as Fp, Choice, CtEq, CtOption, Field, Fp12, Fp2, Fp6,
};

/// BLS parameter `|x|` (the seed `x = -0xd201_0000_0001_0000` is negative).
const BLS_X: u64 = 0xd201_0000_0001_0000;
/// The seed `x` is negative, so the Miller result is conjugated.
const BLS_X_NEG: bool = true;

/// Big-endian encoding of the scalar-field modulus `r` (subgroup order).
const R_BE: [u8; 32] = [
    0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48, 0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
    0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe, 0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
];

// --- hex helpers for the generator constants ---------------------------------

const fn h2b(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        _ => panic!("bad hex digit"),
    }
}

/// Decode a lowercase-hex ASCII string of `2*N` characters into `N` big-endian
/// bytes at compile time.
const fn dh<const N: usize>(s: &[u8]) -> [u8; N] {
    assert!(s.len() == 2 * N, "hex length mismatch");
    let mut out = [0u8; N];
    let mut i = 0;
    while i < N {
        out[i] = (h2b(s[2 * i]) << 4) | h2b(s[2 * i + 1]);
        i += 1;
    }
    out
}

// G1 generator (affine, big-endian coordinates).
const G1X: [u8; 48] = dh(b"17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb");
const G1Y: [u8; 48] = dh(b"08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1");

// G2 generator (affine, x = x0 + x1·u, y = y0 + y1·u), big-endian.
const G2X0: [u8; 48] = dh(b"024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8");
const G2X1: [u8; 48] = dh(b"13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e");
const G2Y0: [u8; 48] = dh(b"0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801");
const G2Y1: [u8; 48] = dh(b"0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be");

#[inline]
fn fp(be: &[u8; 48]) -> Fp {
    let o = Fp::from_bytes(be);
    debug_assert!(o.is_some().into_bool(), "non-canonical Fp constant");
    o.unwrap_or_default()
}

#[inline]
fn fp2(c0: Fp, c1: Fp) -> Fp2 {
    Fp2::new(c0, c1)
}

// --- generic complete point arithmetic (short Weierstrass, a = 0) ------------

/// RCB 2015 Algorithm 1 (`a = 0`): unified, complete addition. Handles `P == Q`
/// (doubling) and `P + (−P) == O` with no branch on point values.
#[inline]
fn w_add<F: Field>(p: (F, F, F), q: (F, F, F), b3: &F) -> (F, F, F) {
    let (x1, y1, z1) = p;
    let (x2, y2, z2) = q;

    let t0 = x1.mul(&x2);
    let t1 = y1.mul(&y2);
    let t2 = z1.mul(&z2);
    let t3 = x1.add(&y1).mul(&x2.add(&y2)).sub(&t0.add(&t1));
    let t4 = x1.add(&z1).mul(&x2.add(&z2)).sub(&t0.add(&t2));
    let t5 = y1.add(&z1).mul(&y2.add(&z2)).sub(&t1.add(&t2));

    let z3a = b3.mul(&t2);
    let x3a = t1.sub(&z3a);
    let z3b = t1.add(&z3a);
    let y3a = x3a.mul(&z3b);
    let tt1 = t0.double().add(&t0);
    let t4b = b3.mul(&t4);

    let y3 = y3a.add(&tt1.mul(&t4b));
    let x3 = t3.mul(&x3a).sub(&t5.mul(&t4b));
    let z3 = t5.mul(&z3b).add(&t3.mul(&tt1));
    (x3, y3, z3)
}

#[inline]
fn w_neg<F: Field>(p: &(F, F, F)) -> (F, F, F) {
    (p.0, p.1.neg(), p.2)
}

#[inline]
fn w_is_identity<F: Field>(p: &(F, F, F)) -> Choice {
    p.2.is_zero()
}

#[inline]
fn w_ct_eq<F: Field + CtEq>(a: &(F, F, F), b: &(F, F, F)) -> Choice {
    let x = a.0.mul(&b.2).ct_eq(&b.0.mul(&a.2));
    let y = a.1.mul(&b.2).ct_eq(&b.1.mul(&a.2));
    x.and(y)
}

/// Fixed-length double-and-add over a big-endian scalar, constant-time in the
/// scalar bits.
fn w_mul<F: Field>(p: &(F, F, F), scalar: &[u8], b3: &F) -> (F, F, F) {
    let id = (F::zero(), F::one(), F::zero());
    let mut acc = id;
    for &byte in scalar {
        let mut bit = 8;
        while bit > 0 {
            bit -= 1;
            acc = w_add(acc, acc, b3);
            let sum = w_add(acc, *p, b3);
            let set = Choice::from_bool(((byte >> bit) & 1) == 1);
            acc = (
                F::ct_select(&acc.0, &sum.0, set),
                F::ct_select(&acc.1, &sum.1, set),
                F::ct_select(&acc.2, &sum.2, set),
            );
        }
    }
    acc
}

#[inline]
fn w_to_affine<F: Field>(p: &(F, F, F)) -> Option<(F, F)> {
    let zi = p.2.invert();
    if zi.is_none().into_bool() {
        return None;
    }
    let zi = zi.unwrap_or_default();
    Some((p.0.mul(&zi), p.1.mul(&zi)))
}

// --- G1 ---------------------------------------------------------------------

/// A point of `E(Fp): y² = x³ + 4` in projective coordinates.
#[derive(Clone, Copy, Debug)]
pub struct G1 {
    x: Fp,
    y: Fp,
    z: Fp,
}

#[inline]
fn g1_b3() -> Fp {
    Fp::from_u64(12)
}

impl G1 {
    /// The identity element `O`.
    #[must_use]
    pub fn identity() -> Self {
        G1 {
            x: Fp::zero(),
            y: Fp::one(),
            z: Fp::zero(),
        }
    }

    /// The standard generator of `G1`.
    #[must_use]
    pub fn generator() -> Self {
        G1 {
            x: fp(&G1X),
            y: fp(&G1Y),
            z: Fp::one(),
        }
    }

    /// Build a projective point directly from affine `(x, y)` **without**
    /// checking that it lies on the curve or in the subgroup. Used by
    /// hash-to-curve, whose isogeny output is on `E` by construction.
    #[must_use]
    pub fn from_affine_unchecked(x: Fp, y: Fp) -> Self {
        G1 { x, y, z: Fp::one() }
    }

    /// Clear the `G1` cofactor: `[h_eff]·P` with `h_eff = 0xd201000000010001`
    /// (RFC 9380 §8.8.1 — `(1 - z)` maps `E(Fp)` into the prime-order subgroup).
    #[must_use]
    pub fn clear_cofactor(&self) -> Self {
        const H_EFF: [u8; 8] = [0xd2, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01];
        self.mul(&H_EFF)
    }

    /// Whether this is the identity.
    #[must_use]
    pub fn is_identity(&self) -> Choice {
        w_is_identity(&(self.x, self.y, self.z))
    }

    /// `self + rhs` (complete, constant-time).
    #[must_use]
    pub fn add(&self, rhs: &Self) -> Self {
        let (x, y, z) = w_add((self.x, self.y, self.z), (rhs.x, rhs.y, rhs.z), &g1_b3());
        G1 { x, y, z }
    }

    /// `-self`.
    #[must_use]
    pub fn neg(&self) -> Self {
        let (x, y, z) = w_neg(&(self.x, self.y, self.z));
        G1 { x, y, z }
    }

    /// `[scalar]·self` for a big-endian scalar (reduced mod `r` by the caller if
    /// required), constant-time in the scalar.
    #[must_use]
    pub fn mul(&self, scalar: &[u8]) -> Self {
        let (x, y, z) = w_mul(&(self.x, self.y, self.z), scalar, &g1_b3());
        G1 { x, y, z }
    }

    /// Whether the projective point satisfies `Y²Z = X³ + 4Z³`.
    #[must_use]
    pub fn is_on_curve(&self) -> Choice {
        let z2 = self.z.square();
        let lhs = self.y.square().mul(&self.z);
        let rhs = self
            .x
            .square()
            .mul(&self.x)
            .add(&Fp::from_u64(4).mul(&z2).mul(&self.z));
        lhs.ct_eq(&rhs)
    }

    /// Whether this point lies in the prime-order subgroup `G1` (`[r]P == O`).
    #[must_use]
    pub fn is_torsion_free(&self) -> Choice {
        self.mul(&R_BE).is_identity()
    }

    /// Affine `(x, y)` coordinates, or `None` for the identity.
    #[must_use]
    pub fn to_affine(&self) -> Option<(Fp, Fp)> {
        w_to_affine(&(self.x, self.y, self.z))
    }
}

impl CtEq for G1 {
    fn ct_eq(&self, other: &Self) -> Choice {
        w_ct_eq(&(self.x, self.y, self.z), &(other.x, other.y, other.z))
    }
}

// --- G2 ---------------------------------------------------------------------

/// A point of `E'(Fp²): y² = x³ + 4·(u + 1)` in projective coordinates.
#[derive(Clone, Copy, Debug)]
pub struct G2 {
    x: Fp2,
    y: Fp2,
    z: Fp2,
}

#[inline]
fn g2_b3() -> Fp2 {
    // 3 · (4 + 4u) = 12 + 12u.
    fp2(Fp::from_u64(12), Fp::from_u64(12))
}

impl G2 {
    /// The identity element `O`.
    #[must_use]
    pub fn identity() -> Self {
        G2 {
            x: Fp2::zero(),
            y: Fp2::one(),
            z: Fp2::zero(),
        }
    }

    /// The standard generator of `G2`.
    #[must_use]
    pub fn generator() -> Self {
        G2 {
            x: fp2(fp(&G2X0), fp(&G2X1)),
            y: fp2(fp(&G2Y0), fp(&G2Y1)),
            z: Fp2::one(),
        }
    }

    /// Whether this is the identity.
    #[must_use]
    pub fn is_identity(&self) -> Choice {
        w_is_identity(&(self.x, self.y, self.z))
    }

    /// `self + rhs` (complete, constant-time).
    #[must_use]
    pub fn add(&self, rhs: &Self) -> Self {
        let (x, y, z) = w_add((self.x, self.y, self.z), (rhs.x, rhs.y, rhs.z), &g2_b3());
        G2 { x, y, z }
    }

    /// `-self`.
    #[must_use]
    pub fn neg(&self) -> Self {
        let (x, y, z) = w_neg(&(self.x, self.y, self.z));
        G2 { x, y, z }
    }

    /// `[scalar]·self` for a big-endian scalar, constant-time in the scalar.
    #[must_use]
    pub fn mul(&self, scalar: &[u8]) -> Self {
        let (x, y, z) = w_mul(&(self.x, self.y, self.z), scalar, &g2_b3());
        G2 { x, y, z }
    }

    /// Whether the projective point satisfies `Y²Z = X³ + 4(u+1)Z³`.
    #[must_use]
    pub fn is_on_curve(&self) -> Choice {
        let z2 = self.z.square();
        let lhs = self.y.square().mul(&self.z);
        let b = fp2(Fp::from_u64(4), Fp::from_u64(4));
        let rhs = self.x.square().mul(&self.x).add(&b.mul(&z2).mul(&self.z));
        lhs.ct_eq(&rhs)
    }

    /// Whether this point lies in the prime-order subgroup `G2` (`[r]P == O`).
    #[must_use]
    pub fn is_torsion_free(&self) -> Choice {
        self.mul(&R_BE).is_identity()
    }

    /// Affine `(x, y)` coordinates, or `None` for the identity.
    #[must_use]
    pub fn to_affine(&self) -> Option<(Fp2, Fp2)> {
        w_to_affine(&(self.x, self.y, self.z))
    }

    /// Build a projective point directly from affine `(x, y)` **without**
    /// checking that it lies on the curve or in the subgroup. Used by
    /// hash-to-curve.
    #[must_use]
    pub fn from_affine_unchecked(x: Fp2, y: Fp2) -> Self {
        G2 {
            x,
            y,
            z: Fp2::one(),
        }
    }

    /// Clear the `G2` cofactor (RFC 9380 §8.8.2 / Budroni–Pintore):
    /// `[x²−x−1]P + [x−1]·ψ(P) + ψ²([2]P)` with the BLS seed `x` and the
    /// untwist-Frobenius-twist endomorphism `ψ`.
    #[must_use]
    pub fn clear_cofactor(&self) -> Self {
        // BLS_X is the magnitude |x|; the seed x itself is negative, so
        // `[x]Q == -[|x|]Q`.
        let xabs: [u8; 8] = BLS_X.to_be_bytes();
        let x_mul = |q: &G2| q.mul(&xabs).neg();

        let t1 = x_mul(self); // [x]P
        let t2 = g2_psi(self); // ψ(P)
        let mut t3 = g2_psi2(&self.add(self)); // ψ²([2]P)
        t3 = t3.add(&t2.neg()); // ψ²(2P) − ψ(P)
        let t2b = x_mul(&t1.add(&t2)); // [x]([x]P + ψ(P)) = [x²]P + [x]ψ(P)
        t3 = t3.add(&t2b); // + [x²]P + [x]ψ(P)
        t3 = t3.add(&t1.neg()); // − [x]P
        t3.add(&self.neg()) // − P
    }
}

/// `1 / ξ` with `ξ = u + 1` — the Frobenius base for `ψ` (RFC 9380 §8.8.2).
#[inline]
fn psi_base() -> Fp2 {
    fp2(Fp::one(), Fp::one()).invert().unwrap_or_default()
}

/// `ψ`: `(x, y) ↦ (x^p · PSI_X, y^p · PSI_Y)` where `x^p` on `Fp²` is
/// conjugation, `PSI_X = base^((p−1)/3)`, `PSI_Y = base^((p−1)/2)`.
fn g2_psi(q: &G2) -> G2 {
    // (p - 1) / 3 and (p - 1) / 2, little-endian u64 words.
    const P_M1_D3: [u64; 6] = [
        0x9354_ffff_ffff_e38e,
        0x0a39_5554_e5c6_aaaa,
        0xcd10_4635_a790_520c,
        0xcc27_c3d6_fbd7_063f,
        0x1909_37e7_6bc3_e447,
        0x08ab_05f8_bdd5_4cde,
    ];
    const P_M1_D2: [u64; 6] = [
        0xdcff_7fff_ffff_d555,
        0x0f55_ffff_58a9_ffff,
        0xb398_6950_7b58_7b12,
        0xb23b_a5c2_79c2_895f,
        0x258d_d3db_21a5_d66b,
        0x0d00_88f5_1cbf_f34d,
    ];
    let base = psi_base();
    let psi_x = base.pow_vartime(&P_M1_D3);
    let psi_y = base.pow_vartime(&P_M1_D2);
    let (x, y) = q.to_affine().expect("psi of identity");
    G2::from_affine_unchecked(x.conjugate().mul(&psi_x), y.conjugate().mul(&psi_y))
}

/// `ψ²`: `(x, y) ↦ (x · PSI2_X, −y)` with `PSI2_X = base^((p²−1)/3)`.
fn g2_psi2(q: &G2) -> G2 {
    const P2_M1_D3: [u64; 12] = [
        0xb78e_0000_097b_2f68,
        0xd44f_23b4_7cbd_64e3,
        0x5cb9_6681_20b0_69a9,
        0xccea_85f9_bf7b_3d16,
        0x0dba_2c8d_7adb_356d,
        0x09cd_75de_d75d_7429,
        0xfc65_c311_0328_4fab,
        0xc58c_b9a9_b249_ee24,
        0xccf7_34c3_118a_2e9a,
        0xa0f4_304c_5a25_6ce6,
        0xc3f0_d2f8_e0ba_61f8,
        0x00e1_67e1_92eb_ca97,
    ];
    let psi2_x = psi_base().pow_vartime(&P2_M1_D3);
    let (x, y) = q.to_affine().expect("psi2 of identity");
    G2::from_affine_unchecked(x.mul(&psi2_x), y.neg())
}

impl CtEq for G2 {
    fn ct_eq(&self, other: &Self) -> Choice {
        w_ct_eq(&(self.x, self.y, self.z), &(other.x, other.y, other.z))
    }
}

// --- Fp12 embedding / untwist ---------------------------------------------

#[inline]
fn fp6_zero() -> Fp6 {
    Fp6::new(Fp2::zero(), Fp2::zero(), Fp2::zero())
}

/// Embed `a ∈ Fp` into `Fp¹²` as a constant term.
#[inline]
fn fp_in_fp12(a: Fp) -> Fp12 {
    Fp12::new(
        Fp6::new(fp2(a, Fp::zero()), Fp2::zero(), Fp2::zero()),
        fp6_zero(),
    )
}

/// `ξ⁻¹` where `ξ = u + 1` (the Fp6/Fp12 non-residue).
#[inline]
fn xi_inv() -> Fp2 {
    fp2(Fp::one(), Fp::one()).invert().unwrap_or_default()
}

/// The untwisting isomorphism `ψ : E'(Fp²) → E(Fp¹²)`,
/// `(x', y') ↦ (x'·w⁻², y'·w⁻³)` with `w² = v`, `v³ = ξ`. Returns the affine
/// `Fp¹²` coordinates. `q` must not be the identity.
fn untwist(q: &G2) -> (Fp12, Fp12) {
    let (xp, yp) = q.to_affine().expect("untwist of identity");
    let xi = xi_inv();
    // x = x'·ξ⁻¹ · v²   (lives in the v² slot of the lower Fp6)
    let x = Fp12::new(Fp6::new(Fp2::zero(), Fp2::zero(), xp.mul(&xi)), fp6_zero());
    // y = y'·ξ⁻¹ · v · w   (v slot of the upper Fp6)
    let y = Fp12::new(fp6_zero(), Fp6::new(Fp2::zero(), yp.mul(&xi), Fp2::zero()));
    (x, y)
}

// --- Miller loop --------------------------------------------------------------

/// Tangent line at `t` evaluated at `P = (xp, yp)` (numerator only), plus `2t`.
fn double_line(t: &(Fp12, Fp12), xp: &Fp12, yp: &Fp12) -> (Fp12, (Fp12, Fp12)) {
    let (x1, y1) = *t;
    let two = Fp12::one().double();
    let three = two.add(&Fp12::one());
    let lam = three
        .mul(&x1.square())
        .mul(&two.mul(&y1).invert().unwrap_or_default());
    let l = yp.sub(&y1).sub(&lam.mul(&xp.sub(&x1)));
    let x3 = lam.square().sub(&x1.double());
    let y3 = lam.mul(&x1.sub(&x3)).sub(&y1);
    (l, (x3, y3))
}

/// Chord line through `t` and `q` evaluated at `P` (numerator only), plus `t+q`.
fn add_line(t: &(Fp12, Fp12), q: &(Fp12, Fp12), xp: &Fp12, yp: &Fp12) -> (Fp12, (Fp12, Fp12)) {
    let (x1, y1) = *t;
    let (x2, y2) = *q;
    let lam = y2.sub(&y1).mul(&x2.sub(&x1).invert().unwrap_or_default());
    let l = yp.sub(&y1).sub(&lam.mul(&xp.sub(&x1)));
    let x3 = lam.square().sub(&x1).sub(&x2);
    let y3 = lam.mul(&x1.sub(&x3)).sub(&y1);
    (l, (x3, y3))
}

/// The Miller function `f_{x, ψ(Q)}(P)` (before final exponentiation).
fn miller(p: &G1, q: &G2) -> Fp12 {
    let (px, py) = p.to_affine().expect("miller of identity");
    let (xp, yp) = (fp_in_fp12(px), fp_in_fp12(py));
    let qxy = untwist(q);

    let mut t = qxy;
    let mut f = Fp12::one();
    let mut i = 62i32;
    while i >= 0 {
        f = f.square();
        let (l, nt) = double_line(&t, &xp, &yp);
        f = f.mul(&l);
        t = nt;
        if (BLS_X >> i) & 1 == 1 {
            let (l, nt) = add_line(&t, &qxy, &xp, &yp);
            f = f.mul(&l);
            t = nt;
        }
        i -= 1;
    }
    if BLS_X_NEG {
        f = f.conjugate();
    }
    f
}

// --- pairing ----------------------------------------------------------------

/// An element of the target group `GT ⊂ Fp¹²*` (the image of [`pairing`]).
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Gt(pub Fp12);

impl Gt {
    /// The identity of `GT`.
    #[must_use]
    pub fn one() -> Self {
        Gt(Fp12::one())
    }

    /// `self · rhs` in `GT`.
    #[must_use]
    pub fn mul(&self, rhs: &Self) -> Self {
        Gt(self.0.mul(&rhs.0))
    }
}

impl CtEq for Gt {
    fn ct_eq(&self, other: &Self) -> Choice {
        self.0.ct_eq(&other.0)
    }
}

fn final_exp(f: &Fp12, exp: &[u64]) -> Fp12 {
    f.pow_vartime(exp)
}

/// The optimal-ate pairing `e(P, Q)`.
///
/// Returns [`Gt::one`] if either argument is the identity.
#[must_use]
pub fn pairing(p: &G1, q: &G2) -> Gt {
    if p.is_identity().into_bool() || q.is_identity().into_bool() {
        return Gt::one();
    }
    let m = miller(p, q);
    Gt(final_exp(&m, &bls12381_final_exp_exponent()))
}

/// The product pairing `∏ e(Pᵢ, Qᵢ)` with a single final exponentiation.
///
/// Identity terms are skipped.
#[must_use]
pub fn multi_pairing(terms: &[(G1, G2)]) -> Gt {
    let mut acc = Fp12::one();
    let mut any = false;
    for (p, q) in terms {
        if p.is_identity().into_bool() || q.is_identity().into_bool() {
            continue;
        }
        acc = acc.mul(&miller(p, q));
        any = true;
    }
    if !any {
        return Gt::one();
    }
    Gt(final_exp(&acc, &bls12381_final_exp_exponent()))
}

/// The scalar-field modulus `r`, big-endian.
#[must_use]
pub fn subgroup_order_be() -> [u8; 32] {
    R_BE
}

// --- compressed point serialization (the standard BLS12-381 "zcash" format) --

/// `(p-1)/2` as canonical little-endian limbs; field elements above this are
/// the lexicographically-largest square root.
const HALF_P_LE: [u64; 6] = [
    0xdcff_7fff_ffff_d555,
    0x0f55_ffff_58a9_ffff,
    0xb398_6950_7b58_7b12,
    0xb23b_a5c2_79c2_895f,
    0x258d_d3db_21a5_d66b,
    0x0d00_88f5_1cff_f34d,
];

/// `a > (p-1)/2` for a canonical `Fp` (public data — plain limb compare).
fn fp_is_lex_largest(y: &Fp) -> Choice {
    let int = y.to_integer();
    let mut gt = Choice::from_bool(false);
    let mut eq = Choice::from_bool(true);
    let mut i = 6usize;
    while i > 0 {
        i -= 1;
        gt = gt.or(eq.and(Choice::from_bool(int[i] > HALF_P_LE[i])));
        eq = eq.and(Choice::from_bool(int[i] == HALF_P_LE[i]));
    }
    gt
}

/// Whether `y = c0 + c1·u` is the lexicographically-largest square root of its
/// square: `c1 > (p-1)/2`, or `c1 == 0 && c0 > (p-1)/2`.
fn fp2_is_lex_largest(y: &Fp2) -> Choice {
    fp_is_lex_largest(&y.c1).or(y.c1.is_zero().and(fp_is_lex_largest(&y.c0)))
}

/// Serialize the `y`-sign flag bit (`0x20`) plus the compression flag (`0x80`).
fn flag_byte(lex_largest: Choice) -> u8 {
    0x80 | if lex_largest.into_bool() { 0x20 } else { 0x00 }
}

/// `a ⊕ b` for a [`Choice`] and a plain bool (the sort-flag comparison).
fn choice_xor_bool(a: Choice, b: bool) -> Choice {
    a.and(Choice::from_bool(!b))
        .or(a.invert().and(Choice::from_bool(b)))
}

/// Lift a `CtOption` into a plain `Option` (public-data parsing — the branch
/// is on a public value, like the SEC1 tag dispatch).
fn to_opt<T>(o: CtOption<T>) -> Option<T> {
    if o.is_some().into_bool() {
        Some(o.unwrap())
    } else {
        None
    }
}

/// Strip the three flag bits from the most significant byte.
fn strip_flags(b: u8) -> u8 {
    b & 0x1f
}

impl G1 {
    /// Compressed 48-byte serialization: `x` big-endian with the top-byte
    /// flags `0x80` (compressed), `0x40` (infinity), `0x20` (y sort bit).
    /// The identity serializes as `0xc0 ‖ 0x00…0`.
    #[must_use]
    pub fn to_compressed(&self) -> [u8; 48] {
        let mut out = [0u8; 48];
        if self.is_identity().into_bool() {
            out[0] = 0xc0;
            return out;
        }
        if let Some((x, y)) = self.to_affine() {
            out = x.to_bytes();
            out[0] |= flag_byte(fp_is_lex_largest(&y));
        }
        out
    }

    /// Parse a compressed 48-byte point: validates the flags (compression set;
    /// infinity only for the all-zero payload), canonical `x < p`, that `x³+4`
    /// is a square, and subgroup membership. Public-data parsing — branching on
    /// the flags is fine, exactly like SEC1 in [`crate::weierstrass`].
    pub fn from_compressed(bytes: &[u8; 48]) -> Option<Self> {
        let compressed = bytes[0] & 0x80 != 0;
        let inf = bytes[0] & 0x40 != 0;
        let sign = bytes[0] & 0x20 != 0;
        if !compressed {
            return None;
        }
        if inf {
            // Infinity must be all-zero apart from the two set flags.
            if sign || bytes[1..].iter().any(|&b| b != 0) {
                return None;
            }
            return Some(G1::identity());
        }
        let mut xb = *bytes;
        xb[0] = strip_flags(xb[0]);
        let x = to_opt(Fp::from_bytes(&xb))?;
        // y² = x³ + 4 — solve, then pick the root matching the sort bit.
        let y2 = x.square().mul(&x).add(&Fp::from_u64(4));
        let root = to_opt(y2.sqrt())?;
        let y = Fp::ct_select(
            &root,
            &root.neg(),
            choice_xor_bool(fp_is_lex_largest(&root), sign),
        );
        let p = G1::from_affine_unchecked(x, y);
        if p.is_on_curve()
            .and(p.is_torsion_free())
            .invert()
            .into_bool()
        {
            return None;
        }
        Some(p)
    }
}

impl G2 {
    /// Compressed 96-byte serialization: the first 48 bytes are the `u`-
    /// coefficient `x.c1` (with the top-byte flags, sort bit on `y`), the next
    /// 48 bytes are `x.c0`. The identity serializes as `0xc0 ‖ 0x00…0`.
    #[must_use]
    pub fn to_compressed(&self) -> [u8; 96] {
        let mut out = [0u8; 96];
        if self.is_identity().into_bool() {
            out[0] = 0xc0;
            return out;
        }
        if let Some((x, y)) = self.to_affine() {
            out[..48].copy_from_slice(&x.c1.to_bytes());
            out[48..].copy_from_slice(&x.c0.to_bytes());
            out[0] |= flag_byte(fp2_is_lex_largest(&y));
        }
        out
    }

    /// Parse a compressed 96-byte point (same validation as
    /// [`G1::from_compressed`], over `Fp²`).
    pub fn from_compressed(bytes: &[u8; 96]) -> Option<Self> {
        let compressed = bytes[0] & 0x80 != 0;
        let inf = bytes[0] & 0x40 != 0;
        let sign = bytes[0] & 0x20 != 0;
        if !compressed {
            return None;
        }
        if inf {
            if sign || bytes[1..].iter().any(|&b| b != 0) {
                return None;
            }
            return Some(G2::identity());
        }
        let mut c1b = [0u8; 48];
        c1b.copy_from_slice(&bytes[..48]);
        c1b[0] = strip_flags(c1b[0]);
        let c0b: [u8; 48] = bytes[48..].try_into().ok()?;
        let c1 = to_opt(Fp::from_bytes(&c1b))?;
        let c0 = to_opt(Fp::from_bytes(&c0b))?;
        let x = Fp2::new(c0, c1);
        let b = Fp2::new(Fp::from_u64(4), Fp::from_u64(4));
        let y2 = x.square().mul(&x).add(&b);
        let root = to_opt(y2.sqrt())?;
        let y = Fp2::ct_select(
            &root,
            &root.neg(),
            choice_xor_bool(fp2_is_lex_largest(&root), sign),
        );
        let p = G2::from_affine_unchecked(x, y);
        if p.is_on_curve()
            .and(p.is_torsion_free())
            .invert()
            .into_bool()
        {
            return None;
        }
        Some(p)
    }
}

#[allow(dead_code)]
fn _exp_owned() -> Vec<u64> {
    bls12381_final_exp_exponent()
}
