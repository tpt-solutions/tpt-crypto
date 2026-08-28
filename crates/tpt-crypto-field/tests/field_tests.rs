//! Known-answer and property tests for `tpt-crypto-field`.
//!
//! A small, dependency-free reference modular arithmetic (schoolbook + long
//! division) cross-checks the Montgomery implementation: `from(to(x)) == x`,
//! `mul` matches `a*b mod p`, `invert`/`sqrt` are consistent, and encoding round
//! trips. Random inputs come from a seeded xorshift so the suite is deterministic
//! and needs no `proptest`/network dependency.

use tpt_crypto_field::{
    Bls12381Fp, Bls12381FpParams, Bls12381Fr, Bls12381FrParams, Choice, CtEq, Field,
    FieldElement, FieldParams, Fp12, Fp2, Fp6, P256Base, P256BaseParams, P256Scalar,
    P256ScalarParams, P384Base, P384BaseParams, P384Scalar, P384ScalarParams,
};

// ---------------------------------------------------------------------------
// Reference arithmetic (independent of the Montgomery code under test).
// ---------------------------------------------------------------------------

const MAX: usize = 6;

fn ref_sub(a: &[u64; MAX], b: &[u64; MAX]) -> ([u64; MAX], u8) {
    let mut out = [0u64; MAX];
    let mut borrow = 0u64;
    for i in 0..MAX {
        let (d, bo) = a[i].overflowing_sub(b[i].wrapping_add(borrow));
        out[i] = d;
        borrow = bo as u64;
    }
    (out, borrow as u8)
}

fn ref_add(a: &[u64; MAX], b: &[u64; MAX]) -> ([u64; MAX], u8) {
    let mut out = [0u64; MAX];
    let mut carry = 0u64;
    for i in 0..MAX {
        let (s, co) = a[i].overflowing_add(b[i].wrapping_add(carry));
        out[i] = s;
        carry = co as u64;
    }
    (out, carry as u8)
}

fn ref_ge(a: &[u64; MAX], b: &[u64; MAX]) -> bool {
    let mut i = MAX;
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

fn ref_ge12(a: &[u64; 2 * MAX], b: &[u64; 2 * MAX]) -> bool {
    let mut i = 2 * MAX;
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

fn ref_sub12(a: &[u64; 2 * MAX], b: &[u64; 2 * MAX]) -> ([u64; 2 * MAX], u8) {
    let mut out = [0u64; 2 * MAX];
    let mut borrow = 0u64;
    for i in 0..2 * MAX {
        let (d, bo) = a[i].overflowing_sub(b[i].wrapping_add(borrow));
        out[i] = d;
        borrow = bo as u64;
    }
    (out, borrow as u8)
}

fn ref_mod(a: &[u64; 2 * MAX], m: &[u64; MAX]) -> [u64; MAX] {
    let mbits = (MAX as u32) * 64;
    let mut r = *a;
    let mut bit = (2u32 * MAX as u32) * 64 - 1;
    while bit >= mbits - 1 {
        let shift = bit - (mbits - 1);
        let mut sm = [0u64; 2 * MAX];
        let ls = (shift / 64) as usize;
        let bs = (shift % 64) as u32;
        for i in 0..MAX {
            let v = m[i];
            if bs > 0 {
                sm[i + ls + 1] |= v >> (64 - bs);
            }
            sm[i + ls] |= v << bs;
        }
        if ref_ge12(&r, &sm) {
            let (d, _) = ref_sub12(&r, &sm);
            r = d;
        }
        bit -= 1;
    }
    let mut out = [0u64; MAX];
    out.copy_from_slice(&r[0..MAX]);
    if ref_ge(&out, m) {
        out = ref_sub(&out, m).0;
    }
    out
}

fn ref_mul_mod(a: &[u64; MAX], b: &[u64; MAX], m: &[u64; MAX]) -> [u64; MAX] {
    let mut t = [0u64; 2 * MAX];
    for i in 0..MAX {
        let mut carry: u128 = 0;
        for j in 0..MAX {
            let prod = (a[i] as u128) * (b[j] as u128) + (t[i + j] as u128) + carry;
            t[i + j] = prod as u64;
            carry = prod >> 64;
        }
        let mut k = i + MAX;
        let mut c = carry;
        while k < 2 * MAX {
            let sum = (t[k] as u128) + c;
            t[k] = sum as u64;
            c = sum >> 64;
            if c == 0 {
                break;
            }
            k += 1;
        }
    }
    ref_mod(&t, m)
}

fn ref_pow_mod(base: &[u64; MAX], exp: &[u64; MAX], m: &[u64; MAX]) -> [u64; MAX] {
    let mut result = [0u64; MAX];
    result[0] = 1;
    for limb in (0..MAX).rev() {
        for bit in (0..64).rev() {
            result = ref_mul_mod(&result, &result, m);
            if (exp[limb] >> bit) & 1 == 1 {
                result = ref_mul_mod(&result, base, m);
            }
        }
    }
    result
}

// ---------------------------------------------------------------------------
// Deterministic PRNG (xorshift64*).
// ---------------------------------------------------------------------------

struct Rng(u64);
impl Rng {
    fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545F4914F6CDD1D)
    }
    fn below(&mut self, m: u64) -> u64 {
        // simple rejection for values < m (m is small here).
        loop {
            let v = self.next() % m;
            if v < m {
                return v;
            }
        }
    }
}

// Per-field test harness.
fn check_field<P: FieldParams>(
    name: &str,
    moduli: &[[u64; MAX]; 1],
) {
    let m = &moduli[0];
    let mut rng = Rng::new(0x1234_5678 ^ (name.len() as u64));
    let mut fails = 0;
    for _ in 0..200 {
        let a = rng.next() % (1u64 << 32);
        let b = rng.next() % (1u64 << 32);
        // mul cross-check
        let fa = FieldElement::<P>::from_u64(a);
        let fb = FieldElement::<P>::from_u64(b);
        let prod = fa.mul(&fb);
        let expected = ref_mul_mod(&[a, 0, 0, 0, 0, 0], &[b, 0, 0, 0, 0, 0], m);
        let expected_fe = FieldElement::<P>::from_u64(le_u64(&expected));
        if !prod.ct_eq(&expected_fe).into_bool() {
            fails += 1;
        }
        // add cross-check
        let sum = fa.add(&fb);
        let (exp_add, _) = ref_add(&[a, 0, 0, 0, 0, 0], &[b, 0, 0, 0, 0, 0]);
        let exp_add_fe = FieldElement::<P>::from_u64(le_u64(&exp_add));
        if !sum.ct_eq(&exp_add_fe).into_bool() {
            fails += 1;
        }
        // sub cross-check
        let diff = fa.sub(&fb);
        let (exp_sub, _) = ref_sub(&[a, 0, 0, 0, 0, 0], &[b, 0, 0, 0, 0, 0]);
        let exp_sub_fe = FieldElement::<P>::from_u64(le_u64(&exp_sub));
        if !diff.ct_eq(&exp_sub_fe).into_bool() {
            fails += 1;
        }
        // invert: a * a^-1 == 1 (for a != 0)
        if a != 0 {
            let inv = fa.invert();
            if inv.is_none().into_bool() {
                fails += 1;
            } else {
                let one = fa.mul(&inv.unwrap());
                if !one.ct_eq(&FieldElement::<P>::one()).into_bool() {
                    fails += 1;
                }
            }
        }
        // pow: a^2 via pow_vartime
        let sq = fa.pow_vartime(&[2, 0, 0, 0, 0, 0]);
        let sq_exp = ref_mul_mod(&[a, 0, 0, 0, 0, 0], &[a, 0, 0, 0, 0, 0], m);
        if !sq.ct_eq(&FieldElement::<P>::from_u64(le_u64(&sq_exp))).into_bool() {
            fails += 1;
        }
        // to_bytes/from_bytes round trip
        let bytes = fa.to_bytes();
        let back = FieldElement::<P>::from_bytes(&bytes);
        if back.is_none().into_bool() || !back.unwrap().ct_eq(&fa).into_bool() {
            fails += 1;
        }
        // sqrt consistency: if Some(s), then s^2 == a
        let s = fa.sqrt();
        if s.is_some().into_bool() {
            let ss = s.unwrap().square();
            if !ss.ct_eq(&fa).into_bool() {
                fails += 1;
            }
        }
    }
    // from_bytes must reject the modulus itself (non-canonical).
    let p_bytes = encode_big_endian(m);
    if FieldElement::<P>::from_bytes(&p_bytes).is_some().into_bool() {
        fails += 1;
    }
    assert_eq!(fails, 0, "{name}: {fails} cross-check failures");
}

fn le_u64(a: &[u64; MAX]) -> u64 {
    a[0]
}

fn encode_big_endian(m: &[u64; MAX]) -> [u8; MAX * 8] {
    let mut out = [0u8; MAX * 8];
    for limb in 0..MAX {
        let v = m[MAX - 1 - limb];
        for b in 0..8 {
            out[limb * 8 + b] = (v >> (56 - b * 8)) as u8;
        }
    }
    out
}

#[test]
fn prime_fields_cross_check() {
    check_field::<P256BaseParams>("P256Base", &[P256BaseParams::MODULUS]);
    check_field::<P256ScalarParams>("P256Scalar", &[P256ScalarParams::MODULUS]);
    check_field::<P384BaseParams>("P384Base", &[P384BaseParams::MODULUS]);
    check_field::<P384ScalarParams>("P384Scalar", &[P384ScalarParams::MODULUS]);
    check_field::<Bls12381FpParams>("BlsFp", &[Bls12381FpParams::MODULUS]);
    check_field::<Bls12381FrParams>("BlsFr", &[Bls12381FrParams::MODULUS]);
}

// ---------------------------------------------------------------------------
// Hand-computed KATs (independent of modulus except that values stay < p).
// ---------------------------------------------------------------------------

#[test]
fn basic_kats() {
    macro_rules! kat {
        ($t:ty) => {{
            let z = <$t>::zero();
            let o = <$t>::one();
            assert!(z.ct_eq(&z.add(&z)).into_bool());
            assert!(o.ct_eq(&o.mul(&o)).into_bool());
            assert!(<$t>::from_u64(2).add(&<$t>::from_u64(3)).ct_eq(&<$t>::from_u64(5)).into_bool());
            assert!(<$t>::from_u64(2).mul(&<$t>::from_u64(3)).ct_eq(&<$t>::from_u64(6)).into_bool());
            assert!(<$t>::from_u64(5).sub(&<$t>::from_u64(3)).ct_eq(&<$t>::from_u64(2)).into_bool());
            assert!(<$t>::from_u64(4).sqrt().unwrap().square().ct_eq(&<$t>::from_u64(4)).into_bool());
            // invert of 2 gives 2^{-1}; 2 * 2^{-1} == 1
            let inv2 = <$t>::from_u64(2).invert().unwrap();
            assert!(<$t>::from_u64(2).mul(&inv2).ct_eq(&o).into_bool());
            // to_bytes(0) is all zero
            assert!(<$t>::zero().to_bytes().iter().all(|&x| x == 0));
            // from_bytes(0) == 0
            let zero_bytes = [0u8; 48];
            assert!(<$t>::from_bytes(&zero_bytes).unwrap().ct_eq(&z).into_bool());
        }};
    }
    kat!(P256Base);
    kat!(P256Scalar);
    kat!(P384Base);
    kat!(P384Scalar);
    kat!(Bls12381Fp);
    kat!(Bls12381Fr);
}

// ---------------------------------------------------------------------------
// Extension tower property checks.
// ---------------------------------------------------------------------------

#[test]
fn fp2_properties() {
    let mut rng = Rng::new(0xBEEF);
    for _ in 0..50 {
        let a0 = Bls12381Fp::from_u64(rng.next() % (1 << 30));
        let a1 = Bls12381Fp::from_u64(rng.next() % (1 << 30));
        let b0 = Bls12381Fp::from_u64(rng.next() % (1 << 30));
        let b1 = Bls12381Fp::from_u64(rng.next() % (1 << 30));
        let a = Fp2::new(a0, a1);
        let b = Fp2::new(b0, b1);
        // u^2 == -1
        let u = Fp2::new(Bls12381Fp::zero(), Bls12381Fp::one());
        assert!(u.square().ct_eq(&Fp2::new(Bls12381Fp::one().neg(), Bls12381Fp::zero())).into_bool());
        // associativity of mul
        let c0 = Bls12381Fp::from_u64(rng.next() % (1 << 30));
        let c1 = Bls12381Fp::from_u64(rng.next() % (1 << 30));
        let c = Fp2::new(c0, c1);
        let lhs = a.mul(&b).mul(&c);
        let rhs = a.mul(&b.mul(&c));
        assert!(lhs.ct_eq(&rhs).into_bool());
        // distributivity
        let dl = a.mul(&b.add(&c));
        let dr = a.mul(&b).add(&a.mul(&c));
        assert!(dl.ct_eq(&dr).into_bool());
        // invert
        if a.is_zero().not().into_bool() {
            assert!(a.mul(&a.invert().unwrap()).ct_eq(&Fp2::one()).into_bool());
        }
        // encoding round trip
        let bytes = a.to_bytes();
        assert!(Fp2::from_bytes(&bytes).unwrap().ct_eq(&a).into_bool());
        // sqrt consistency
        let s = a.sqrt();
        if s.is_some().into_bool() {
            assert!(s.unwrap().square().ct_eq(&a).into_bool());
        }
    }
}

#[test]
fn fp6_fp12_properties() {
    let mut rng = Rng::new(0xF00D);
    for _ in 0..30 {
        let mut r = || {
            Fp2::new(
                Bls12381Fp::from_u64(rng.next() % (1 << 28)),
                Bls12381Fp::from_u64(rng.next() % (1 << 28)),
            )
        };
        let a = Fp6::new(r(), r(), r());
        let b = Fp6::new(r(), r(), r());
        let c = Fp6::new(r(), r(), r());
        // associativity
        assert!(a.mul(&b).mul(&c).ct_eq(&a.mul(&b.mul(&c))).into_bool());
        // distributivity
        assert!(a.mul(&b.add(&c))
            .ct_eq(&a.mul(&b).add(&a.mul(&c)))
            .into_bool());
        if a.is_zero().not().into_bool() {
            assert!(a.mul(&a.invert().unwrap()).ct_eq(&Fp6::one()).into_bool());
        }
        // w^2 == v in Fp12
        let w = Fp12::new(Fp6::zero(), Fp6::one());
        let v = Fp6::new(Fp2::zero(), Fp2::one(), Fp2::zero());
        assert!(w.square().ct_eq(&Fp12::new(v, Fp6::zero())).into_bool());
        // Fp12 associativity
        let mut e = || Fp12::new(
            Fp6::new(r(), r(), r()),
            Fp6::new(r(), r(), r()),
        );
        let x = e();
        let y = e();
        let z = e();
        assert!(x.mul(&y).mul(&z).ct_eq(&x.mul(&y.mul(&z))).into_bool());
        // sqrt consistency
        let s = a.sqrt();
        if s.is_some().into_bool() {
            assert!(s.unwrap().square().ct_eq(&a).into_bool());
        }
        let s12 = x.sqrt();
        if s12.is_some().into_bool() {
            assert!(s12.unwrap().square().ct_eq(&x).into_bool());
        }
        // encoding round trips
        assert!(Fp6::from_bytes(&a.to_bytes()).unwrap().ct_eq(&a).into_bool());
        assert!(Fp12::from_bytes(&x.to_bytes()).unwrap().ct_eq(&x).into_bool());
    }
}

// ---------------------------------------------------------------------------
// Constant-time rejection of non-canonical encodings (Wycheproof-style edges).
// ---------------------------------------------------------------------------

#[test]
fn noncanonical_rejection() {
    // A 48-byte value with a set high byte is >= 2^256 > p for the 256-bit
    // fields, and >= p for the 384-bit fields as well; all must be rejected.
    let mut bad = [0xFFu8; 48];
    assert!(P256Base::from_bytes(&bad).is_none().into_bool());
    assert!(Bls12381Fr::from_bytes(&bad).is_none().into_bool());
    assert!(P384Base::from_bytes(&bad).is_none().into_bool());
    // Wrong length rejected.
    assert!(P256Base::from_bytes(&[0u8; 32]).is_none().into_bool());
    assert!(P256Base::from_bytes(&[0u8; 64]).is_none().into_bool());
    // A canonical all-zero is accepted as zero.
    assert!(P256Base::from_bytes(&[0u8; 48]).unwrap().is_zero().into_bool());
    // Choice from a boolean is consistent.
    let ch = Choice::from_bool(true);
    assert!(ch.into_bool());
}
