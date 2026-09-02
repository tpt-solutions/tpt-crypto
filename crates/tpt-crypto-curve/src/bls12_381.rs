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
    bls12381_final_exp_exponent, Bls12381Fp as Fp, Choice, CtEq, Field, Fp12, Fp2, Fp6,
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

    /// Whether this is the identity.
    #[must_use]
    pub fn is_identity(&self) -> Choice {
        w_is_identity(&(self.x, self.y, self.z))
    }

    /// `self + rhs` (complete, constant-time).
    #[must_use]
    pub fn add(&self, rhs: &Self) -> Self {
        let (x, y, z) = w_add(
            (self.x, self.y, self.z),
            (rhs.x, rhs.y, rhs.z),
            &g1_b3(),
        );
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
        let (x, y, z) = w_add(
            (self.x, self.y, self.z),
            (rhs.x, rhs.y, rhs.z),
            &g2_b3(),
        );
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
        let rhs = self
            .x
            .square()
            .mul(&self.x)
            .add(&b.mul(&z2).mul(&self.z));
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
    fp2(Fp::one(), Fp::one())
        .invert()
        .unwrap_or_default()
}

/// The untwisting isomorphism `ψ : E'(Fp²) → E(Fp¹²)`,
/// `(x', y') ↦ (x'·w⁻², y'·w⁻³)` with `w² = v`, `v³ = ξ`. Returns the affine
/// `Fp¹²` coordinates. `q` must not be the identity.
fn untwist(q: &G2) -> (Fp12, Fp12) {
    let (xp, yp) = q.to_affine().expect("untwist of identity");
    let xi = xi_inv();
    // x = x'·ξ⁻¹ · v²   (lives in the v² slot of the lower Fp6)
    let x = Fp12::new(
        Fp6::new(Fp2::zero(), Fp2::zero(), xp.mul(&xi)),
        fp6_zero(),
    );
    // y = y'·ξ⁻¹ · v · w   (v slot of the upper Fp6)
    let y = Fp12::new(
        fp6_zero(),
        Fp6::new(Fp2::zero(), yp.mul(&xi), Fp2::zero()),
    );
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
fn add_line(
    t: &(Fp12, Fp12),
    q: &(Fp12, Fp12),
    xp: &Fp12,
    yp: &Fp12,
) -> (Fp12, (Fp12, Fp12)) {
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

#[allow(dead_code)]
fn _exp_owned() -> Vec<u64> {
    bls12381_final_exp_exponent()
}
