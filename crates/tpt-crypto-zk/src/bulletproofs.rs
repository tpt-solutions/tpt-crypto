//! Aggregated Bulletproofs range proofs over the prime-order group.
//!
//! `prove_range` / `verify_range` prove/verify that `m` committed `u64` values
//! all lie in `[0, 2^n)` for `n ∈ {8, 16, 32, 64}`, with `n·m` a power of two.
//! The construction is the standard aggregated Bulletproofs range proof: a
//! Pedersen commitment to the bits, a weighted inner-product argument, and a
//! single multiscalar-check verification equation (the "mega-check").

use alloc::vec::Vec;

use tpt_crypto_field::Ed25519Scalar;
use tpt_crypto_hash::{sha3::Shake256, Xof};

use crate::error::ZkError;
use crate::generators::BulletproofGens;
use crate::group::{scalar_from_wide, Ristretto};
use crate::ipa::InnerProductProof;
use crate::pedersen::PedersenGens;
use crate::transcript::Transcript;

/// A Bulletproofs range proof for `m` values of `n` bits each.
#[derive(Clone, Debug)]
pub struct RangeProof {
    /// Commitment `A` to the bits and their blinding.
    pub a: [u8; 32],
    /// Commitment `S` to the blinding vectors.
    pub s: [u8; 32],
    /// Commitment `T1` to the linear coefficient of the polynomial `t(X)`.
    pub t1: [u8; 32],
    /// Commitment `T2` to the quadratic coefficient of `t(X)`.
    pub t2: [u8; 32],
    /// Evaluation `t(x)` of the polynomial at the challenge `x`.
    pub t_x: Ed25519Scalar,
    /// Blinding of the synthetic commitment to `t(x)`.
    pub t_x_blinding: Ed25519Scalar,
    /// Blinding of the inner-product commitment.
    pub e_blinding: Ed25519Scalar,
    /// The inner-product argument.
    pub ipp: InnerProductProof,
}

/// A deterministic scalar expander used by the prover (a SHAKE256-driven CSPRNG
/// over a caller-provided seed). Soundness only requires the prover's
/// randomness to be unknown to the verifier, which holds here.
pub struct SeedExpander {
    state: Shake256,
    ctr: u64,
}

impl SeedExpander {
    /// Seed the expander.
    pub fn new(seed: &[u8]) -> Self {
        let mut state = Shake256::new();
        state.update(b"tpt-crypto-zk.SeedExpander");
        state.update(seed);
        SeedExpander { state, ctr: 0 }
    }

    /// Produce the next scalar (used for blinding/commitment randomness).
    pub fn next_scalar(&mut self) -> Ed25519Scalar {
        let mut buf = [0u8; 64];
        let ctr = self.ctr.to_le_bytes();
        let mut t = self.state.clone();
        t.update(&ctr);
        t.squeeze(&mut buf);
        self.state.update(&ctr);
        self.ctr += 1;
        scalar_from_wide(&buf)
    }
}

fn domain_sep(t: &mut Transcript, n: usize, m: usize) {
    t.append_message(b"dom", b"RangeProof");
    t.append_message(b"dom", &n.to_le_bytes());
    t.append_message(b"dom", &m.to_le_bytes());
}

fn zeros(len: usize) -> Vec<Ed25519Scalar> {
    let mut v = Vec::with_capacity(len);
    for _ in 0..len {
        v.push(Ed25519Scalar::zero());
    }
    v
}

fn _inner_product(a: &[Ed25519Scalar], b: &[Ed25519Scalar]) -> Ed25519Scalar {
    let mut out = Ed25519Scalar::zero();
    for i in 0..a.len() {
        out = out.add(&a[i].mul(&b[i]));
    }
    out
}

fn sum_of_powers(base: &Ed25519Scalar, len: usize) -> Ed25519Scalar {
    let mut acc = Ed25519Scalar::zero();
    let mut term = Ed25519Scalar::one();
    for _ in 0..len {
        acc = acc.add(&term);
        term = term.mul(base);
    }
    acc
}

/// The `δ(y, z)` term of the aggregated range proof.
pub fn delta(n: usize, m: usize, y: &Ed25519Scalar, z: &Ed25519Scalar) -> Ed25519Scalar {
    let sum_y = sum_of_powers(y, n * m);
    let sum_2 = sum_of_powers(&Ed25519Scalar::from_u64(2), n);
    let sum_z = sum_of_powers(z, m);
    let zz = z.mul(z);
    (z.sub(&zz))
        .mul(&sum_y)
        .sub(&zz.mul(z).mul(&sum_2).mul(&sum_z))
}

fn concat_z_and_2(n: usize, m: usize, z: &Ed25519Scalar) -> Vec<Ed25519Scalar> {
    let mut out = Vec::with_capacity(n * m);
    let mut zexp = Ed25519Scalar::one();
    for _ in 0..m {
        let mut e2 = Ed25519Scalar::one();
        for _ in 0..n {
            out.push(zexp.mul(&e2));
            e2 = e2.add(&e2);
        }
        zexp = zexp.mul(z);
    }
    out
}

/// Prove that each `values[j]` lies in `[0, 2^n)`, returning the proof and the
/// value commitments `V_j = value·G + blindings[j]·H`.
///
/// `n` must be `8`, `16`, `32`, or `64`, and `n·m` must be a power of two.
pub fn prove_range(
    values: &[u64],
    blindings: &[Ed25519Scalar],
    n: usize,
    rng: &mut SeedExpander,
) -> (RangeProof, Vec<Ristretto>) {
    let m = values.len();
    assert!(
        n == 8 || n == 16 || n == 32 || n == 64,
        "unsupported bitsize"
    );
    let nm = n * m;
    assert!(nm.is_power_of_two(), "n*m must be a power of two");
    assert_eq!(values.len(), blindings.len());

    let pc = PedersenGens::default();
    let g_vec = BulletproofGens::g_vec(n, m);
    let h_vec = BulletproofGens::h_vec(n, m);

    let mut transcript = Transcript::new(b"RangeProof");
    domain_sep(&mut transcript, n, m);

    let mut vs = Vec::with_capacity(m);
    for j in 0..m {
        let v = pc.commit_u64(values[j], &blindings[j]);
        transcript.append_point(b"V", &v);
        vs.push(v);
    }

    let mut a_l = zeros(nm);
    let mut a_r = zeros(nm);
    let mut a_blind = zeros(m);
    let mut s_blind = zeros(m);
    let mut offset_zz = zeros(m);

    let mut a = Ristretto::identity();
    for j in 0..m {
        a_blind[j] = rng.next_scalar();
        a = a.add(&pc.h.scalar_mul(&a_blind[j]));
        for i in 0..n {
            let vi = ((values[j] >> i) & 1) as u64;
            let gi = &g_vec[j * n + i];
            let hi = &h_vec[j * n + i];
            if vi == 1 {
                a = a.add(gi);
            } else {
                a = a.add(&hi.neg());
            }
            a_l[j * n + i] = Ed25519Scalar::from_u64(vi);
            a_r[j * n + i] = a_l[j * n + i].sub(&Ed25519Scalar::one());
        }
    }

    let mut s_l = zeros(nm);
    let mut s_r = zeros(nm);
    for i in 0..nm {
        s_l[i] = rng.next_scalar();
        s_r[i] = rng.next_scalar();
    }

    let mut s = Ristretto::identity();
    for i in 0..nm {
        s = s.add(&g_vec[i].scalar_mul(&s_l[i]));
        s = s.add(&h_vec[i].scalar_mul(&s_r[i]));
    }
    for j in 0..m {
        s_blind[j] = rng.next_scalar();
        s = s.add(&pc.h.scalar_mul(&s_blind[j]));
    }

    transcript.append_point(b"A", &a);
    transcript.append_point(b"S", &s);
    let y = transcript.challenge_scalar(b"y");
    let z = transcript.challenge_scalar(b"z");
    let zz = z.mul(&z);

    let mut l0 = zeros(nm);
    let mut l1 = zeros(nm);
    let mut r0 = zeros(nm);
    let mut r1 = zeros(nm);
    let mut t0 = Ed25519Scalar::zero();
    let mut t1 = Ed25519Scalar::zero();
    let mut t2 = Ed25519Scalar::zero();
    let one = Ed25519Scalar::one();
    for j in 0..m {
        let offset_y = y.pow_vartime(&[(j * n) as u64]);
        let offset_z = z.pow_vartime(&[j as u64]);
        offset_zz[j] = zz.mul(&offset_z);
        let mut ey = offset_y;
        let mut e2 = one;
        for i in 0..n {
            let idx = j * n + i;
            l0[idx] = a_l[idx].sub(&z);
            l1[idx] = s_l[idx];
            r0[idx] = ey.mul(&a_r[idx].add(&z)).add(&offset_zz[j].mul(&e2));
            r1[idx] = ey.mul(&s_r[idx]);
            let t0j = l0[idx].mul(&r0[idx]);
            let t1j = l0[idx].mul(&r1[idx]).add(&l1[idx].mul(&r0[idx]));
            let t2j = l1[idx].mul(&r1[idx]);
            t0 = t0.add(&t0j);
            t1 = t1.add(&t1j);
            t2 = t2.add(&t2j);
            ey = ey.mul(&y);
            e2 = e2.add(&e2);
        }
    }

    // T1 = t1·G + τ1·H and T2 = t2·G + τ2·H: one commitment each, regardless of m.
    let t1_blind = rng.next_scalar();
    let t2_blind = rng.next_scalar();
    let t1_commit = pc.commit(&t1, &t1_blind);
    let t2_commit = pc.commit(&t2, &t2_blind);

    transcript.append_point(b"T_1", &t1_commit);
    transcript.append_point(b"T_2", &t2_commit);
    let x = transcript.challenge_scalar(b"x");

    let t_x = t0.add(&x.mul(&t1)).add(&x.mul(&x).mul(&t2));
    let mut t_x_blinding = Ed25519Scalar::zero();
    let mut e_blinding = Ed25519Scalar::zero();
    let xx = x.mul(&x);
    for j in 0..m {
        t_x_blinding = t_x_blinding.add(&offset_zz[j].mul(&blindings[j]));
        e_blinding = e_blinding.add(&a_blind[j]).add(&s_blind[j].mul(&x));
    }
    t_x_blinding = t_x_blinding.add(&t1_blind.mul(&x)).add(&t2_blind.mul(&xx));

    let mut l_vec = zeros(nm);
    let mut r_vec = zeros(nm);
    for i in 0..nm {
        l_vec[i] = l0[i].add(&x.mul(&l1[i]));
        r_vec[i] = r0[i].add(&x.mul(&r1[i]));
    }

    transcript.append_scalar(b"t_x", &t_x);
    transcript.append_scalar(b"t_x_blinding", &t_x_blinding);
    transcript.append_scalar(b"e_blinding", &e_blinding);
    let w = transcript.challenge_scalar(b"w");
    let q = pc.g.scalar_mul(&w);

    let g_factors = {
        let mut v = Vec::with_capacity(nm);
        for _ in 0..nm {
            v.push(Ed25519Scalar::one());
        }
        v
    };
    let mut h_factors = Vec::with_capacity(nm);
    let y_inv = y.invert().unwrap();
    let mut acc = Ed25519Scalar::one();
    for _ in 0..nm {
        h_factors.push(acc);
        acc = acc.mul(&y_inv);
    }

    let ipp = InnerProductProof::create(
        &mut transcript,
        &q,
        &g_factors,
        &h_factors,
        g_vec,
        h_vec,
        l_vec,
        r_vec,
    );

    let proof = RangeProof {
        a: a.compress(),
        s: s.compress(),
        t1: t1_commit.compress(),
        t2: t2_commit.compress(),
        t_x,
        t_x_blinding,
        e_blinding,
        ipp,
    };
    (proof, vs)
}

/// Verify a range proof for the given value commitments.
pub fn verify_range(
    commitments: &[Ristretto],
    proof: &RangeProof,
    n: usize,
) -> Result<(), ZkError> {
    let m = commitments.len();
    if !(n == 8 || n == 16 || n == 32 || n == 64) {
        return Err(ZkError::InvalidBitsize);
    }
    let nm = n * m;
    if !nm.is_power_of_two() {
        return Err(ZkError::InvalidAggregation);
    }
    let pc = PedersenGens::default();
    let g_vec = BulletproofGens::g_vec(n, m);
    let h_vec = BulletproofGens::h_vec(n, m);

    let a_pt = Ristretto::decompress(&proof.a).ok_or(ZkError::Malformed)?;
    let s_pt = Ristretto::decompress(&proof.s).ok_or(ZkError::Malformed)?;
    let t1_pt = Ristretto::decompress(&proof.t1).ok_or(ZkError::Malformed)?;
    let t2_pt = Ristretto::decompress(&proof.t2).ok_or(ZkError::Malformed)?;
    let l_pts: Vec<Ristretto> = proof
        .ipp
        .l_vec
        .iter()
        .map(|b| Ristretto::decompress(b).ok_or(ZkError::Malformed))
        .collect::<Result<_, _>>()?;
    let r_pts: Vec<Ristretto> = proof
        .ipp
        .r_vec
        .iter()
        .map(|b| Ristretto::decompress(b).ok_or(ZkError::Malformed))
        .collect::<Result<_, _>>()?;

    let mut transcript = Transcript::new(b"RangeProof");
    domain_sep(&mut transcript, n, m);
    for v in commitments {
        transcript.append_point(b"V", v);
    }
    transcript.append_point(b"A", &a_pt);
    transcript.append_point(b"S", &s_pt);
    let y = transcript.challenge_scalar(b"y");
    let z = transcript.challenge_scalar(b"z");
    let zz = z.mul(&z);
    let minus_z = z.neg();
    transcript.append_point(b"T_1", &t1_pt);
    transcript.append_point(b"T_2", &t2_pt);
    let x = transcript.challenge_scalar(b"x");
    transcript.append_scalar(b"t_x", &proof.t_x);
    transcript.append_scalar(b"t_x_blinding", &proof.t_x_blinding);
    transcript.append_scalar(b"e_blinding", &proof.e_blinding);
    let w = transcript.challenge_scalar(b"w");

    let (x_sq, x_inv_sq, s) = proof
        .ipp
        .verification_scalars(nm, &mut transcript)
        .map_err(|_| ZkError::Verification)?;
    let c = transcript.challenge_scalar(b"c");

    let _q = pc.g.scalar_mul(&w);
    let one = Ed25519Scalar::one();
    let a = proof.ipp.a;
    let b = proof.ipp.b;
    let delta_v = delta(n, m, &y, &z);

    let mut scalars: Vec<Ed25519Scalar> = Vec::new();
    let mut points: Vec<Ristretto> = Vec::new();

    scalars.push(one);
    scalars.push(x);
    scalars.push(c.mul(&x));
    scalars.push(c.mul(&x).mul(&x));
    for v in &x_sq {
        scalars.push(*v);
    }
    for v in &x_inv_sq {
        scalars.push(*v);
    }
    scalars.push(proof.e_blinding.neg().sub(&c.mul(&proof.t_x_blinding)));
    let basepoint_scalar = w
        .mul(&proof.t_x.sub(&a.mul(&b)))
        .add(&c.mul(&delta_v.sub(&proof.t_x)));
    scalars.push(basepoint_scalar);

    for i in 0..nm {
        scalars.push(minus_z.sub(&a.mul(&s[i])));
    }

    let y_inv = y.invert().unwrap();
    let concat = concat_z_and_2(n, m, &z);
    let s_inv: Vec<Ed25519Scalar> = s.iter().rev().copied().collect();
    let mut acc = Ed25519Scalar::one();
    for i in 0..nm {
        let yi = acc;
        let zc = concat[i];
        let si_inv = s_inv[i];
        scalars.push(z.add(&yi.mul(&zz.mul(&zc).sub(&b.mul(&si_inv)))));
        acc = acc.mul(&y_inv);
    }

    let mut zexp = one;
    for _ in 0..m {
        scalars.push(c.mul(&zz).mul(&zexp));
        zexp = zexp.mul(&z);
    }

    points.push(a_pt);
    points.push(s_pt);
    points.push(t1_pt);
    points.push(t2_pt);
    for p in &l_pts {
        points.push(*p);
    }
    for p in &r_pts {
        points.push(*p);
    }
    points.push(pc.h);
    points.push(pc.g);
    for p in &g_vec {
        points.push(*p);
    }
    for p in &h_vec {
        points.push(*p);
    }
    for v in commitments {
        points.push(*v);
    }

    let acc2 = Ristretto::msm(&scalars, &points);
    if acc2.is_identity() {
        Ok(())
    } else {
        Err(ZkError::Verification)
    }
}

/// Serialize the range proof to its canonical byte layout.
pub fn range_proof_to_bytes(proof: &RangeProof) -> Vec<u8> {
    let mut buf = Vec::with_capacity(7 * 32 + proof.ipp.l_vec.len() * 64 + 64);
    buf.extend_from_slice(&proof.a);
    buf.extend_from_slice(&proof.s);
    buf.extend_from_slice(&proof.t1);
    buf.extend_from_slice(&proof.t2);
    buf.extend_from_slice(&crate::ipa::scalar_to_le_bytes(&proof.t_x));
    buf.extend_from_slice(&crate::ipa::scalar_to_le_bytes(&proof.t_x_blinding));
    buf.extend_from_slice(&crate::ipa::scalar_to_le_bytes(&proof.e_blinding));
    buf.extend_from_slice(&crate::ipa::InnerProductProof::to_bytes(&proof.ipp));
    buf
}

/// Deserialize a range proof from bytes.
pub fn range_proof_from_bytes(slice: &[u8]) -> Result<RangeProof, ZkError> {
    if slice.len() < 7 * 32 {
        return Err(ZkError::InvalidLength);
    }
    let mut a = [0u8; 32];
    let mut s = [0u8; 32];
    let mut t1 = [0u8; 32];
    let mut t2 = [0u8; 32];
    a.copy_from_slice(&slice[0..32]);
    s.copy_from_slice(&slice[32..64]);
    t1.copy_from_slice(&slice[64..96]);
    t2.copy_from_slice(&slice[96..128]);
    let t_x = crate::ipa::bytes_to_scalar_checked(&slice[128..160]).ok_or(ZkError::Malformed)?;
    let t_x_blinding =
        crate::ipa::bytes_to_scalar_checked(&slice[160..192]).ok_or(ZkError::Malformed)?;
    let e_blinding =
        crate::ipa::bytes_to_scalar_checked(&slice[192..224]).ok_or(ZkError::Malformed)?;
    let ipp = crate::ipa::InnerProductProof::from_bytes(&slice[224..])?;
    Ok(RangeProof {
        a,
        s,
        t1,
        t2,
        t_x,
        t_x_blinding,
        e_blinding,
        ipp,
    })
}
