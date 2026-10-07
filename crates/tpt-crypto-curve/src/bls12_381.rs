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

/// Fixed 4-bit-window multiplication by a big-endian scalar, constant-time in
/// the scalar: every nibble does four doublings, one addition, and a table
/// lookup that scans all 16 entries with `ct_select`.
fn w_mul<F: Field>(p: &(F, F, F), scalar: &[u8], b3: &F) -> (F, F, F) {
    let id = (F::zero(), F::one(), F::zero());
    let mut table = [id; 16];
    for i in 1..16 {
        table[i] = w_add(table[i - 1], *p, b3);
    }
    let mut acc = id;
    for &byte in scalar {
        for nibble in [byte >> 4, byte & 0x0F] {
            for _ in 0..4 {
                acc = w_add(acc, acc, b3);
            }
            let mut sel = id;
            for (i, t) in table.iter().enumerate() {
                let hit = Choice::from_bool(nibble as usize == i);
                sel = (
                    F::ct_select(&sel.0, &t.0, hit),
                    F::ct_select(&sel.1, &t.1, hit),
                    F::ct_select(&sel.2, &t.2, hit),
                );
            }
            acc = w_add(acc, sel, b3);
        }
    }
    acc
}

/// Double-and-add by a *public* 64-bit constant (branches on the scalar bits,
/// never on the point). Used only for the fixed BLS parameter `|x|`.
fn w_mul_public_u64<F: Field>(p: &(F, F, F), k: u64, b3: &F) -> (F, F, F) {
    let mut acc = (F::zero(), F::one(), F::zero());
    let mut started = false;
    for bit in (0..64).rev() {
        if started {
            acc = w_add(acc, acc, b3);
        }
        if (k >> bit) & 1 == 1 {
            acc = if started { w_add(acc, *p, b3) } else { *p };
            started = true;
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
        let x_mul = |q: &G2| {
            let (x, y, z) = w_mul_public_u64(&(q.x, q.y, q.z), BLS_X, &g2_b3());
            G2 { x, y, z }.neg()
        };

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

// Frobenius constants as literals (`base = 1/ξ`, `ξ = u + 1`); the tests below
// re-derive each from its defining exponent.
/// `PSI_X = base^((p−1)/3)` (RFC 9380 §8.8.2): `(c0, c1)`.
const PSI_X: ([u8; 48], [u8; 48]) = (
    dh(b"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
    dh(b"1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaad"),
);
/// `PSI_Y = base^((p−1)/2)`.
const PSI_Y: ([u8; 48], [u8; 48]) = (
    dh(b"135203e60180a68ee2e9c448d77a2cd91c3dedd930b1cf60ef396489f61eb45e304466cf3e67fa0af1ee7b04121bdea2"),
    dh(b"06af0e0437ff400b6831e36d6bd17ffe48395dabc2d3435e77f76e17009241c5ee67992f72ec05f4c81084fbede3cc09"),
);
/// `PSI2_X = base^((p²−1)/3)`.
const PSI2_X: ([u8; 48], [u8; 48]) = (
    dh(b"1a0111ea397fe699ec02408663d4de85aa0d857d89759ad4897d29650fb85f9b409427eb4f49fffd8bfd00000000aaac"),
    dh(b"000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"),
);
/// `γ = ξ^((p−1)/6)`, the `Fp¹²` Frobenius base.
const FROB_GAMMA: ([u8; 48], [u8; 48]) = (
    dh(b"1904d3bf02bb0667c231beb4202c0d1f0fd603fd3cbd5f4f7b2443d784bab9c4f67ea53d63e7813d8d0775ed92235fb8"),
    dh(b"00fc3e2b36c4e03288e9e902231f9fb854a14787b6c7b36fec0c8ec971f63c5f282d5ac14d6c7ec22cf78a126ddc4af3"),
);

fn fp2_const(c: &([u8; 48], [u8; 48])) -> Fp2 {
    fp2(fp(&c.0), fp(&c.1))
}

/// `ψ`: `(x, y) ↦ (x^p · PSI_X, y^p · PSI_Y)` where `x^p` on `Fp²` is conjugation.
fn g2_psi(q: &G2) -> G2 {
    let (x, y) = q.to_affine().expect("psi of identity");
    G2::from_affine_unchecked(
        x.conjugate().mul(&fp2_const(&PSI_X)),
        y.conjugate().mul(&fp2_const(&PSI_Y)),
    )
}

/// `ψ²`: `(x, y) ↦ (x · PSI2_X, −y)`.
fn g2_psi2(q: &G2) -> G2 {
    let (x, y) = q.to_affine().expect("psi2 of identity");
    G2::from_affine_unchecked(x.mul(&fp2_const(&PSI2_X)), y.neg())
}

impl CtEq for G2 {
    fn ct_eq(&self, other: &Self) -> Choice {
        w_ct_eq(&(self.x, self.y, self.z), &(other.x, other.y, other.z))
    }
}

// --- Miller loop --------------------------------------------------------------
//
// `T` lives on the twist `E'(Fp²)` in Jacobian coordinates `(X, Y, Z)`
// (`x = X/Z²`, `y = Y/Z³`), so no inversion is needed per step. With the
// untwist `ψ(x', y') = (x'·w⁻², y'·w⁻³)` (`w² = v`, `v³ = ξ`), a line through
// twist points of slope `λ'` evaluated at `P = (xP, yP)` is
//
//   l = yP + w·[(λ'·x_T − y_T)·v − λ'·xP·v²] / ξ.
//
// Each line below is scaled by `ξ` and by an `Fp²` factor from clearing the
// Jacobian denominators; `Fp² ⊂ Fp⁶` is annihilated by the `p⁶ − 1` factor of
// the final exponentiation, so the pairing value is unchanged.

type Jac2 = (Fp2, Fp2, Fp2);

/// `x · s` for `s ∈ Fp` (2 base-field multiplications).
#[inline]
fn fp2_scale(x: &Fp2, s: &Fp) -> Fp2 {
    Fp2::new(x.c0.mul(s), x.c1.mul(s))
}

/// A sparse line `y + w·(a·v + b·v²)` (three nonzero `Fp²` coefficients).
struct Line {
    y: Fp2,
    a: Fp2,
    b: Fp2,
}

/// `f · line` exploiting the line's sparsity (15 `Fp²` multiplications
/// against 18 for a general `Fp12` product).
fn mul_by_line(f: &Fp12, l: &Line) -> Fp12 {
    let scale = |x: &Fp6| Fp6::new(x.c0.mul(&l.y), x.c1.mul(&l.y), x.c2.mul(&l.y));
    // `x · (a·v + b·v²)` for `x ∈ Fp⁶`, `v³ = ξ`.
    let by_ab = |x: &Fp6| {
        Fp6::new(
            x.c1.mul(&l.b).add(&x.c2.mul(&l.a)).mul_by_nonresidue(),
            x.c0.mul(&l.a).add(&x.c2.mul(&l.b).mul_by_nonresidue()),
            x.c0.mul(&l.b).add(&x.c1.mul(&l.a)),
        )
    };
    let t0 = scale(&f.c0);
    let t1 = by_ab(&f.c1);
    // (f0 + f1)·(y + a·v + b·v²), a general (Karatsuba) Fp6 product.
    let cross = f.c0.add(&f.c1).mul(&Fp6::new(l.y, l.a, l.b));
    Fp12::new(t0.add(&t1.mul_by_v()), cross.sub(&t0).sub(&t1))
}

/// Double `t` and return the tangent line at `P` (scaled).
fn double_step(t: &Jac2, xp: &Fp, yp: &Fp) -> (Line, Jac2) {
    let (x, y, z) = *t;
    let a = x.square();
    let b = y.square();
    let c = b.square();
    let d = x.add(&b).square().sub(&a).sub(&c).double();
    let e = a.double().add(&a);
    let f = e.square();
    let x3 = f.sub(&d.double());
    let c8 = c.double().double().double();
    let y3 = e.mul(&d.sub(&x3)).sub(&c8);
    let z3 = y.mul(&z).double();

    let zz = z.square();
    let l = Line {
        y: fp2_scale(&z3.mul(&zz).mul_by_nonresidue(), yp),
        a: e.mul(&x).sub(&b.double()),
        b: fp2_scale(&e.mul(&zz), xp).neg(),
    };
    (l, (x3, y3, z3))
}

/// Add affine `q` to `t` and return the chord line at `P` (scaled).
fn add_step(t: &Jac2, q: &(Fp2, Fp2), xp: &Fp, yp: &Fp) -> (Line, Jac2) {
    let (x, y, z) = *t;
    let (x2, y2) = *q;
    let z1z1 = z.square();
    let u2 = x2.mul(&z1z1);
    let s2 = y2.mul(&z).mul(&z1z1);
    let h = u2.sub(&x);
    let r = s2.sub(&y);
    let hh = h.square();
    let hhh = h.mul(&hh);
    let v = x.mul(&hh);
    let x3 = r.square().sub(&hhh).sub(&v.double());
    let y3 = r.mul(&v.sub(&x3)).sub(&y.mul(&hhh));
    let z3 = z.mul(&h);

    let l = Line {
        y: fp2_scale(&z3.mul_by_nonresidue(), yp),
        a: r.mul(&x2).sub(&y2.mul(&z3)),
        b: fp2_scale(&r, xp).neg(),
    };
    (l, (x3, y3, z3))
}

/// The Miller function `f_{x, ψ(Q)}(P)` (before final exponentiation).
fn miller(p: &G1, q: &G2) -> Fp12 {
    let (px, py) = p.to_affine().expect("miller of identity");
    let qa = q.to_affine().expect("miller of identity");

    let mut t: Jac2 = (qa.0, qa.1, Fp2::one());
    let mut f = Fp12::one();
    let mut i = 62i32;
    while i >= 0 {
        f = f.square();
        let (l, nt) = double_step(&t, &px, &py);
        f = mul_by_line(&f, &l);
        t = nt;
        if (BLS_X >> i) & 1 == 1 {
            let (l, nt) = add_step(&t, &qa, &px, &py);
            f = mul_by_line(&f, &l);
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

/// Frobenius constants for `Fp12`: `γ^k` for `k = 0..6` with `γ = ξ^((p-1)/6)`.
struct Frob {
    g: [Fp2; 6],
}

impl Frob {
    fn new() -> Self {
        let gamma = fp2_const(&FROB_GAMMA);
        let mut g = [Fp2::one(); 6];
        for k in 1..6 {
            g[k] = g[k - 1].mul(&gamma);
        }
        Frob { g }
    }

    /// The `p`-power Frobenius. With `f = Σ a_k·w^k` (`a_k ∈ Fp²`, `w^6 = ξ`):
    /// `f^p = Σ conj(a_k)·γ^k·w^k`.
    fn frob(&self, f: &Fp12) -> Fp12 {
        let a = |x: &Fp2, k: usize| x.conjugate().mul(&self.g[k]);
        Fp12::new(
            Fp6::new(a(&f.c0.c0, 0), a(&f.c0.c1, 2), a(&f.c0.c2, 4)),
            Fp6::new(a(&f.c1.c0, 1), a(&f.c1.c1, 3), a(&f.c1.c2, 5)),
        )
    }

    /// The `p²`-power Frobenius (`f ↦ (f^p)^p`).
    fn frob2(&self, f: &Fp12) -> Fp12 {
        self.frob(&self.frob(f))
    }
}

/// Square in the cyclotomic subgroup `GΦ₆(p²)` (Granger–Scott). Only valid for
/// elements with `f^(p⁶+1) = 1`, which holds after the easy part.
fn cyclotomic_square(f: &Fp12) -> Fp12 {
    fn fp4_square(a: &Fp2, b: &Fp2) -> (Fp2, Fp2) {
        let t0 = a.square();
        let t1 = b.square();
        let c0 = t1.mul_by_nonresidue().add(&t0);
        let c1 = a.add(b).square().sub(&t0).sub(&t1);
        (c0, c1)
    }
    let (z0, z4, z3) = (f.c0.c0, f.c0.c1, f.c0.c2);
    let (z2, z1, z5) = (f.c1.c0, f.c1.c1, f.c1.c2);

    let (t0, t1) = fp4_square(&z0, &z1);
    let z0 = t0.sub(&z0).double().add(&t0);
    let z1 = t1.add(&z1).double().add(&t1);

    let (t0, t1) = fp4_square(&z2, &z3);
    let (t2, t3) = fp4_square(&z4, &z5);
    let z4 = t0.sub(&z4).double().add(&t0);
    let z5 = t1.add(&z5).double().add(&t1);

    let t0 = t3.mul_by_nonresidue();
    let z2 = t0.add(&z2).double().add(&t0);
    let z3 = t2.sub(&z3).double().add(&t2);

    Fp12::new(Fp6::new(z0, z4, z3), Fp6::new(z2, z1, z5))
}

/// `f^e` in the cyclotomic subgroup for a little-endian `u64` exponent.
fn cyclotomic_pow(f: &Fp12, exp: &[u64]) -> Fp12 {
    let mut r = Fp12::one();
    for &limb in exp.iter().rev() {
        for bit in (0..64).rev() {
            r = cyclotomic_square(&r);
            if (limb >> bit) & 1 == 1 {
                r = r.mul(f);
            }
        }
    }
    r
}

/// `f^x` for the (negative) BLS parameter `x = -BLS_X`, in the cyclotomic
/// subgroup, where inversion is conjugation.
fn cyclotomic_exp_x(f: &Fp12) -> Fp12 {
    let r = cyclotomic_pow(f, &[BLS_X]);
    if BLS_X_NEG {
        r.conjugate()
    } else {
        r
    }
}

/// `(|x|+1)² / 3` as little-endian words (`(x-1)²/3`, since `x < 0`).
const XM1_SQ_OVER_3: [u64; 2] = [0x8c00_aaab_0000_aaab, 0x396c_8c00_5555_e156];

/// Final exponentiation `f^((p^12-1)/r)`.
///
/// Easy part `(p^6-1)(p^2+1)` via conjugation, one inversion and `p²`-Frobenius;
/// hard part `(p^4-p^2+1)/r = (x-1)²/3·(x+p)·(x²+p²-1) + 1` with cyclotomic
/// squarings and Frobenius maps.
fn final_exp(f: &Fp12) -> Fp12 {
    let fr = Frob::new();
    // `f` is a nonzero Miller output, so the inversion succeeds.
    let g = f.conjugate().mul(&f.invert().unwrap_or_default());
    let g = fr.frob2(&g).mul(&g);

    let t0 = cyclotomic_pow(&g, &XM1_SQ_OVER_3);
    let t1 = cyclotomic_exp_x(&t0).mul(&fr.frob(&t0));
    let t2 = cyclotomic_exp_x(&cyclotomic_exp_x(&t1))
        .mul(&fr.frob2(&t1))
        .mul(&t1.conjugate());
    t2.mul(&g)
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
    Gt(final_exp(&m))
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
    Gt(final_exp(&acc))
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

#[cfg(test)]
mod final_exp_tests {
    use super::*;
    use tpt_crypto_field::bls12381_final_exp_split;

    #[test]
    fn split_final_exp_matches_full_exponent() {
        let m = miller(&G1::generator(), &G2::generator());
        let full = m.pow_vartime(&bls12381_final_exp_exponent());
        assert_eq!(final_exp(&m), full);
    }

    #[test]
    fn frobenius_literals_match_definitions() {
        let xi = fp2(Fp::one(), Fp::one());
        let base = xi.invert().unwrap();
        let p_m1 = tpt_crypto_field::bls12381_frobenius_exponent(); // (p-1)/6
                                                                    // (p-1)/3 = 2·((p-1)/6), (p-1)/2 = 3·((p-1)/6); build via repeated pow.
        let sq = |f: Fp2| f.square();
        let g6 = xi.pow_vartime(&p_m1);
        assert_eq!(fp2_const(&FROB_GAMMA), g6);
        let b6 = base.pow_vartime(&p_m1);
        let b3 = sq(b6);
        let b2 = b6.mul(&b6).mul(&b6);
        assert_eq!(fp2_const(&PSI_X), b3);
        assert_eq!(fp2_const(&PSI_Y), b2);
        // PSI2_X = base^((p²−1)/3) = PSI_X^(p+1) = PSI_X · conj(PSI_X).
        assert_eq!(
            fp2_const(&PSI2_X),
            fp2_const(&PSI_X).mul(&fp2_const(&PSI_X).conjugate())
        );
    }

    #[test]
    fn frobenius_and_cyclotomic_square() {
        let m = miller(&G1::generator(), &G2::generator());
        let fr = Frob::new();
        // f^p via the exponent definition.
        let p_exp = {
            let (p2, _) = bls12381_final_exp_split();
            // p = sqrt(p²) is not available; check p² instead.
            p2
        };
        assert_eq!(fr.frob2(&m), m.pow_vartime(&p_exp));
        // Cyclotomic square agrees with the generic square after the easy part.
        let g = m.conjugate().mul(&m.invert().unwrap());
        let g = fr.frob2(&g).mul(&g);
        assert_eq!(cyclotomic_square(&g), g.square());
    }
}

#[cfg(test)]
mod window_mul_tests {
    use super::*;

    /// Reference: plain MSB-first double-and-add.
    fn naive_g2(p: &G2, scalar: &[u8]) -> G2 {
        let mut acc = G2::identity();
        for &byte in scalar {
            for bit in (0..8).rev() {
                acc = acc.add(&acc);
                if (byte >> bit) & 1 == 1 {
                    acc = acc.add(p);
                }
            }
        }
        acc
    }

    #[test]
    fn windowed_mul_matches_double_and_add() {
        let g = G2::generator();
        for sc in [
            &[0u8][..],
            &[1],
            &[0x0F, 0xF0, 0x01],
            &[0xAB; 32],
            &[0x00, 0x00, 0x7E, 0x12],
        ] {
            assert!(g.mul(sc).ct_eq(&naive_g2(&g, sc)).into_bool());
        }
        let g1 = G1::generator();
        let a = g1.mul(&[0x12, 0x34]);
        let b = g1.mul(&[0x12, 0x00]).add(&g1.mul(&[0x34]));
        assert!(a.ct_eq(&b).into_bool());
    }
}
