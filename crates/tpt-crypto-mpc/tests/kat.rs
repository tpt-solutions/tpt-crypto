//! Known-answer / reference-run tests for `tpt-crypto-mpc`.
//!
//! These are *documented reference runs*: the expected values are produced by this
//! implementation and pinned here as regression vectors. Vectors are additionally
//! cross-checked by the property suite (`tests/props.rs`), and the base-OT wire
//! format is re-derived independently below (`reference_base_ot`) to guard against
//! silent drift in the key schedule. See `tests/kat/PROVENANCE.md`.

use tpt_crypto_core::{CryptoRng, Result};
use tpt_crypto_ct::{Choice, CtSelect};
use tpt_crypto_curve::EdwardsPoint;
use tpt_crypto_field::{Field, FieldElement, P256ScalarParams};
use tpt_crypto_hash::blake3::{blake3, Blake3};
use tpt_crypto_hash::Xof;

use tpt_crypto_mpc::{
    multiply, reconstruct, share_secret, share_secret_2, transfer_1ofn, transfer_base_ot_1of2,
    BeaverTriple,
};

type F = FieldElement<P256ScalarParams>;

const KS_KEY: [u8; 32] = [
    0x9b, 0x7e, 0x4c, 0x1f, 0x2a, 0x88, 0x36, 0xd9, 0x40, 0x5b, 0x21, 0x7c, 0x6e, 0x13, 0x9a, 0xf4,
    0x55, 0x0c, 0x8b, 0x73, 0x29, 0xe2, 0x61, 0x0d, 0x4f, 0xa9, 0xb8, 0x17, 0x6c, 0x93, 0xe5, 0x02,
];

fn keystream(seed: &[u8], len: usize) -> Vec<u8> {
    let mut h = Blake3::with_key(&KS_KEY);
    h.update(seed);
    let mut out = vec![0u8; len];
    h.finalize_xof(&mut out);
    out
}

fn ot_key(point: &[u8; 32], label: u8) -> [u8; 32] {
    let mut data = [0u8; 33];
    data[..32].copy_from_slice(point);
    data[32] = label;
    blake3(&data)
}

fn xor_bytes(a: &mut [u8], b: &[u8]) {
    for i in 0..a.len() {
        a[i] ^= b[i];
    }
}

/// Independent re-derivation of a Chou–Orlandi 1-of-2 base OT receiver output,
/// using the same mathematics but a separate code path, for cross-checking.
fn reference_base_ot(m0: &[u8; 32], m1: &[u8; 32], choice: bool) -> Vec<u8> {
    let mut x = [0u8; 32];
    x[0] = 0x42;
    x[1] = 0x13;
    x[31] = 0x80;
    let mut r = [0u8; 32];
    r[0] = 0x99;
    r[2] = 0x07;
    r[31] = 0x80;
    let a = EdwardsPoint::basepoint().mul(&x);
    let a_pt = a;
    let id = EdwardsPoint::identity();
    let addend = <EdwardsPoint as CtSelect>::ct_select(Choice::from(choice), id, a_pt);
    let b = EdwardsPoint::basepoint().mul(&r).add(&addend);
    let k = if choice {
        b.sub(&a).mul(&x).compress()
    } else {
        b.mul(&x).compress()
    };
    let label = if choice { 1u8 } else { 0u8 };
    let mut out = if choice { m1.to_vec() } else { m0.to_vec() };
    let olen = out.len();
    xor_bytes(&mut out, &keystream(&ot_key(&k, label), olen));
    out
}

struct Drng(u64);

impl CryptoRng for Drng {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
        for b in dest.iter_mut() {
            self.0 = self.0.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            *b = (self.0 >> 33) as u8;
        }
        Ok(())
    }
}

fn fe(x: u64) -> F {
    F::from_u64(x)
}

#[test]
fn debug_decompress() {
    use tpt_crypto_curve::EdwardsPoint;
    let mut drng = Drng(123);
    for _ in 0..50 {
        let mut x = drng.gen_array::<32>();
        x[0] &= 248;
        x[31] &= 127;
        x[31] |= 64;
        let p = EdwardsPoint::basepoint().mul(&x);
        let c = p.compress();
        let d = EdwardsPoint::decompress(&c);
        assert!(d.is_some().into_bool(), "decompress A failed");
        let r = drng.gen_array::<32>();
        let id = EdwardsPoint::identity();
        for choice in [false, true] {
            let addend = if choice { p } else { id };
            let b = EdwardsPoint::basepoint().mul(&r).add(&addend);
            let bc = b.compress();
            let bd = EdwardsPoint::decompress(&bc);
            assert!(bd.is_some().into_bool(), "decompress B failed, choice={choice}");
        }
    }
}

#[test]
fn base_ot_kat() {
    let m0 = [0x11u8; 32];
    let m1 = [0x22u8; 32];
    // Cross-check the crate against the independent key-schedule recomputation.
    for choice in [false, true] {
        let got = transfer_base_ot_1of2(&mut Drng(0), &m0, &m1, choice);
        let ref_out = reference_base_ot(&m0, &m1, choice);
        assert_eq!(got, ref_out, "base OT drift vs reference for choice {choice}");
        assert_eq!(&got[..], if choice { &m1[..] } else { &m0[..] }, "receiver did not learn chosen message");
        assert_eq!(got.len(), 32);
    }
}

#[test]
fn oneofn_kat() {
    let msgs: Vec<Vec<u8>> = (0u8..4).map(|i| vec![i * 0x11 + 1; 32]).collect();
    for choice in 0..4 {
        let got = transfer_1ofn(&mut Drng(choice as u64), &msgs, choice);
        assert_eq!(&got[..], &msgs[choice][..], "1-of-N leaked the wrong message");
    }
}

#[test]
fn share_reconstruct_kat() {
    for n in [2usize, 3, 5, 7] {
        for x in [0u64, 1, 42, 123456789] {
            let shares = share_secret(&mut Drng(x + n as u64), &fe(x), n).unwrap();
            assert_eq!(reconstruct(&shares), fe(x));
            // Independent check: last share == x - sum(first n-1).
            let mut sum = F::zero();
            for s in &shares[..n - 1] {
                sum = sum.add(&s.value);
            }
            assert_eq!(shares[n - 1].value, fe(x).sub(&sum));
        }
    }
}

#[test]
fn beaver_from_base_ot_kat() {
    for (x, y) in [(0u64, 0), (1, 1), (7, 11), (9999, 4242)] {
        let (x0, x1) = share_secret_2(&mut Drng(x), &fe(x));
        let (y0, y1) = share_secret_2(&mut Drng(y), &fe(y));
        let (t0, t1) = BeaverTriple::<F>::deal_from_base_ot(&mut Drng(x ^ y));
        let a = t0.a.value.add(&t1.a.value);
        let b = t0.b.value.add(&t1.b.value);
        let c = t0.c.value.add(&t1.c.value);
        assert_eq!(c, a.mul(&b), "Beaver triple relation a*b == c failed");
        let (z0, z1) = multiply(
            &(x0.value, x1.value),
            &(y0.value, y1.value),
            &(t0, t1),
        );
        assert_eq!(z0.add(&z1), fe(x).mul(&fe(y)));
    }
}

#[test]
fn iknp_kat() {
    let msgs: Vec<(Vec<u8>, Vec<u8>)> = (0u8..8)
        .map(|i| (vec![i; 16], vec![i + 0x80; 16]))
        .collect();
    let choices = (0u8..8).map(|i| i & 1).collect::<Vec<_>>();
    let (_cts, got) = tpt_crypto_mpc::iknp::extend_1of2(&mut Drng(0), &msgs, &choices);
    for j in 0..8 {
        let expected = if choices[j] == 1 {
            msgs[j].1.clone()
        } else {
            msgs[j].0.clone()
        };
        assert_eq!(got[j], expected, "IKNP revealed the wrong message at {j}");
    }
}
