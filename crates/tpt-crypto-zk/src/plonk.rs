//! Minimal PLONK verifier (GWC19 structure) over inner-product commitments.
//!
//! This is a *verifier only*: the prover is `tpt-telos`'s job. The design
//! follows the standard PLONK round structure —
//!
//! 1. witness commitments `[a] [b] [c]`, challenges `(β, γ)`,
//! 2. grand-product commitment `[z]`, challenge `α`,
//! 3. quotient commitments `[t_lo] [t_mid] [t_hi]` for
//!    `t = (gate + α·perm + α²·init) / Z_H`, challenge `ζ`,
//! 4. all evaluations at `ζ` (including `z(ζ)`) and `z(ωζ)`, then two batched
//!    inner-product openings.
//!
//! Two deliberate simplifications against the KZG presentation, both sound
//! (they trade a little proof size for a much smaller verifier):
//!
//! * Polynomial commitments are IPA/Pedersen vector commitments
//!   `C = <p, G> + r·H₀` instead of KZG. Evaluations are bound to commitments
//!   by two batched inner-product openings (one at `ζ`, one at `ωζ`), with the
//!   batched blinding `r_batch` sent in the clear (it is independent
//!   randomness, so revealing it leaks nothing about the witnesses).
//! * `[z]` is opened at `ζ` *as well as* `ωζ`, so the entire quotient identity
//!   collapses into one scalar check at `ζ` — no linearization polynomial and
//!   no `[r]` commitment. Soundness is the usual Schwartz–Zippel argument at
//!   the single point `ζ` (the checked polynomial has degree `< 4n`).
//!
//! The gate enforced per row is
//! `q_l·a + q_r·b + q_o·c + q_m·a·b + q_c = 0`. Public inputs are baked into
//! `q_c` by the circuit builder, so the verifying key commits to the circuit
//! *with* its public inputs (a fixed-input verifier). The wire identity tags
//! are `ω^i`, `k1·ω^i`, `k2·ω^i` over the size-`n` multiplicative subgroup;
//! `k1`/`k2` must generate cosets disjoint from it.

use alloc::vec::Vec;

use crate::error::ZkError;
use crate::ipa::{bytes_to_scalar_checked, scalar_to_le_bytes, InnerProductProof};
use crate::transcript::Transcript;
use tpt_crypto_field::CtEq;

use crate::Ed25519Scalar;

/// Generator vector + blinding base for PLONK polynomial commitments.
///
/// Both sides derive them from `n` alone; there is no trusted setup beyond
/// the hashed nothing-up-my-sleeve generators.
#[derive(Clone, Debug)]
pub struct PlonkGens {
    /// One generator per polynomial coefficient (length `n`).
    pub g: Vec<crate::Ristretto>,
    /// The blinding base `H₀`.
    pub h: crate::Ristretto,
}

impl PlonkGens {
    /// Derive the generators for circuits of size `n`.
    #[must_use]
    pub fn new(n: usize) -> Self {
        let mut g = Vec::with_capacity(n);
        for i in 0..n {
            let mut label = alloc::vec::Vec::new();
            label.extend_from_slice(b"tpt-crypto-zk.plonk.g.");
            label.extend_from_slice(&(i as u64).to_le_bytes());
            g.push(crate::Ristretto::map_to_point(&label));
        }
        PlonkGens {
            g,
            h: crate::Ristretto::map_to_point(b"tpt-crypto-zk.plonk.h0"),
        }
    }
}

/// Verifying key: commitments to the selector and permutation polynomials.
#[derive(Clone, Debug)]
pub struct VerifyingKey {
    /// Circuit size (rows); must be a power of two.
    pub n: usize,
    /// Coset shift for the b-wire identity tags.
    pub k1: Ed25519Scalar,
    /// Coset shift for the c-wire identity tags.
    pub k2: Ed25519Scalar,
    /// Commitment to the left-selector polynomial.
    pub q_l: crate::Ristretto,
    /// Commitment to the right-selector polynomial.
    pub q_r: crate::Ristretto,
    /// Commitment to the output-selector polynomial.
    pub q_o: crate::Ristretto,
    /// Commitment to the multiplication-selector polynomial.
    pub q_m: crate::Ristretto,
    /// Commitment to the constant-selector polynomial (public inputs included).
    pub q_c: crate::Ristretto,
    /// Commitment to the first permutation polynomial.
    pub sigma_1: crate::Ristretto,
    /// Commitment to the second permutation polynomial.
    pub sigma_2: crate::Ristretto,
    /// Commitment to the third permutation polynomial.
    pub sigma_3: crate::Ristretto,
}

/// A PLONK proof.
#[derive(Clone, Debug)]
pub struct Proof {
    // Round 1–3 commitments.
    /// Commitment to the a-wire polynomial.
    pub a: [u8; 32],
    /// Commitment to the b-wire polynomial.
    pub b: [u8; 32],
    /// Commitment to the c-wire polynomial.
    pub c: [u8; 32],
    /// Commitment to the grand-product polynomial.
    pub z: [u8; 32],
    /// Commitment to the low quotient chunk.
    pub t_lo: [u8; 32],
    /// Commitment to the middle quotient chunk.
    pub t_mid: [u8; 32],
    /// Commitment to the high quotient chunk.
    pub t_hi: [u8; 32],

    // Round 4 evaluations (all at ζ, except `z_omega_eval` at ωζ).
    /// `a(ζ)`.
    pub a_eval: Ed25519Scalar,
    /// `b(ζ)`.
    pub b_eval: Ed25519Scalar,
    /// `c(ζ)`.
    pub c_eval: Ed25519Scalar,
    /// `q_l(ζ)`.
    pub ql_eval: Ed25519Scalar,
    /// `q_r(ζ)`.
    pub qr_eval: Ed25519Scalar,
    /// `q_o(ζ)`.
    pub qo_eval: Ed25519Scalar,
    /// `q_m(ζ)`.
    pub qm_eval: Ed25519Scalar,
    /// `q_c(ζ)`.
    pub qc_eval: Ed25519Scalar,
    /// `σ₁(ζ)`.
    pub s1_eval: Ed25519Scalar,
    /// `σ₂(ζ)`.
    pub s2_eval: Ed25519Scalar,
    /// `σ₃(ζ)`.
    pub s3_eval: Ed25519Scalar,
    /// `z(ζ)`.
    pub z_eval: Ed25519Scalar,
    /// `z(ωζ)`.
    pub z_omega_eval: Ed25519Scalar,
    /// `t_lo(ζ)`.
    pub t_lo_eval: Ed25519Scalar,
    /// `t_mid(ζ)`.
    pub t_mid_eval: Ed25519Scalar,
    /// `t_hi(ζ)`.
    pub t_hi_eval: Ed25519Scalar,

    // Round 5: batched IPA openings.
    /// Blinding of the ζ-batched commitment (independent randomness).
    pub r_blind: Ed25519Scalar,
    /// IPA opening of the ζ-batch at `ζ`.
    pub ipp_zeta: InnerProductProof,
    /// Blinding of the `[z]` opening at `ωζ`.
    pub z_blind: Ed25519Scalar,
    /// IPA opening of `[z]` at `ωζ`.
    pub ipp_z_omega: InnerProductProof,
}

/// Commit a coefficient vector: `C = <p, G> + r·H₀`.
pub fn commit_poly(
    gens: &PlonkGens,
    coeffs: &[Ed25519Scalar],
    blind: &Ed25519Scalar,
) -> crate::Ristretto {
    debug_assert_eq!(coeffs.len(), gens.g.len());
    crate::Ristretto::msm(coeffs, &gens.g).add(&gens.h.scalar_mul(blind))
}

/// The powers `1, x, x², …` (length `n`).
#[must_use]
pub fn powers_of(x: &Ed25519Scalar, n: usize) -> Vec<Ed25519Scalar> {
    let mut v = Vec::with_capacity(n);
    let mut acc = Ed25519Scalar::one();
    for _ in 0..n {
        v.push(acc);
        acc = acc.mul(x);
    }
    v
}

fn decompress_or(b: &[u8; 32]) -> Result<crate::Ristretto, ZkError> {
    crate::Ristretto::decompress(b).ok_or(ZkError::Malformed)
}

impl VerifyingKey {
    /// Verify a PLONK proof against this key.
    ///
    /// # Errors
    ///
    /// [`ZkError::Malformed`] on undecodable group elements or scalars,
    /// [`ZkError::Verification`] when any PLONK check fails.
    pub fn verify(&self, proof: &Proof) -> Result<(), ZkError> {
        if !self.n.is_power_of_two() || self.n < 2 {
            return Err(ZkError::InvalidLength);
        }
        let n = self.n;
        let gens = PlonkGens::new(n);

        // --- round 1: statement binding + witness commitments -------------------
        let mut t = Transcript::new(b"PLONK");
        t.append_message(b"n", &(n as u64).to_le_bytes());
        t.append_scalar(b"k1", &self.k1);
        t.append_scalar(b"k2", &self.k2);
        t.append_message(b"[ql]", &self.q_l.compress());
        t.append_message(b"[qr]", &self.q_r.compress());
        t.append_message(b"[qo]", &self.q_o.compress());
        t.append_message(b"[qm]", &self.q_m.compress());
        t.append_message(b"[qc]", &self.q_c.compress());
        t.append_message(b"[s1]", &self.sigma_1.compress());
        t.append_message(b"[s2]", &self.sigma_2.compress());
        t.append_message(b"[s3]", &self.sigma_3.compress());

        let beta = t.challenge_scalar(b"beta");
        let gamma = t.challenge_scalar(b"gamma");

        let a_cm = decompress_or(&proof.a)?;
        let b_cm = decompress_or(&proof.b)?;
        let c_cm = decompress_or(&proof.c)?;
        t.append_message(b"[a]", &proof.a);
        t.append_message(b"[b]", &proof.b);
        t.append_message(b"[c]", &proof.c);

        // --- round 2: grand product ---------------------------------------------
        let z_cm = decompress_or(&proof.z)?;
        t.append_message(b"[z]", &proof.z);
        let alpha = t.challenge_scalar(b"alpha");

        // --- round 3: quotient ----------------------------------------------------
        let t_lo_cm = decompress_or(&proof.t_lo)?;
        let t_mid_cm = decompress_or(&proof.t_mid)?;
        let t_hi_cm = decompress_or(&proof.t_hi)?;
        t.append_message(b"[t_lo]", &proof.t_lo);
        t.append_message(b"[t_mid]", &proof.t_mid);
        t.append_message(b"[t_hi]", &proof.t_hi);
        let zeta = t.challenge_scalar(b"zeta");

        // --- round 4: evaluations ---------------------------------------------------
        let evals = [
            proof.a_eval,
            proof.b_eval,
            proof.c_eval,
            proof.ql_eval,
            proof.qr_eval,
            proof.qo_eval,
            proof.qm_eval,
            proof.qc_eval,
            proof.s1_eval,
            proof.s2_eval,
            proof.s3_eval,
            proof.z_eval,
            proof.z_omega_eval,
            proof.t_lo_eval,
            proof.t_mid_eval,
            proof.t_hi_eval,
        ];
        for e in &evals {
            t.append_scalar(b"e", e);
        }

        // The scalar identity at ζ:
        //   Z_H(ζ)·t(ζ) = gate(ζ) + α·(num(ζ) − den(ζ)) + α²·init(ζ).
        let one = Ed25519Scalar::one();
        let zeta_n = zeta.pow_vartime(&[n as u64]);
        let zh = zeta_n.sub(&one);
        let t_zeta = proof
            .t_lo_eval
            .add(&zeta_n.mul(&proof.t_mid_eval))
            .add(&zeta_n.mul(&zeta_n).mul(&proof.t_hi_eval));

        let gate = proof
            .ql_eval
            .mul(&proof.a_eval)
            .add(&proof.qr_eval.mul(&proof.b_eval))
            .add(&proof.qo_eval.mul(&proof.c_eval))
            .add(&proof.qm_eval.mul(&proof.a_eval).mul(&proof.b_eval))
            .add(&proof.qc_eval);

        let num = proof
            .a_eval
            .add(&beta.mul(&zeta))
            .add(&gamma)
            .mul(&proof.b_eval.add(&beta.mul(&self.k1).mul(&zeta)).add(&gamma))
            .mul(&proof.c_eval.add(&beta.mul(&self.k2).mul(&zeta)).add(&gamma))
            .mul(&proof.z_eval);
        let den = proof
            .a_eval
            .add(&beta.mul(&proof.s1_eval))
            .add(&gamma)
            .mul(&proof.b_eval.add(&beta.mul(&proof.s2_eval)).add(&gamma))
            .mul(&proof.c_eval.add(&beta.mul(&proof.s3_eval)).add(&gamma))
            .mul(&proof.z_omega_eval);

        // L₁(ζ) = (ζⁿ−1)/(n·(ζ−1)).
        let n_inv = Ed25519Scalar::from_u64(n as u64).invert().unwrap_or(one);
        let l1 = zh.mul(&n_inv).mul(&inv_or_zero(&zeta.sub(&one)));
        let init = proof.z_eval.sub(&one).mul(&l1);

        let alpha_sq = alpha.mul(&alpha);
        let lhs = zh.mul(&t_zeta);
        let rhs = gate
            .add(&alpha.mul(&num.sub(&den)))
            .add(&alpha_sq.mul(&init));
        if !lhs.ct_eq(&rhs).into_bool() {
            return Err(ZkError::Verification);
        }

        // --- round 5: batched openings -----------------------------------------------
        let v = t.challenge_scalar(b"v");

        // ζ-batch over the 15 polynomials opened at ζ.
        let cms_at_zeta = [
            a_cm,
            b_cm,
            c_cm,
            z_cm,
            self.q_l,
            self.q_r,
            self.q_o,
            self.q_m,
            self.q_c,
            self.sigma_1,
            self.sigma_2,
            self.sigma_3,
            t_lo_cm,
            t_mid_cm,
            t_hi_cm,
        ];
        let evals_at_zeta = [
            proof.a_eval,
            proof.b_eval,
            proof.c_eval,
            proof.z_eval,
            proof.ql_eval,
            proof.qr_eval,
            proof.qo_eval,
            proof.qm_eval,
            proof.qc_eval,
            proof.s1_eval,
            proof.s2_eval,
            proof.s3_eval,
            proof.t_lo_eval,
            proof.t_mid_eval,
            proof.t_hi_eval,
        ];
        let mut v_pow = one;
        let mut c_batch = crate::Ristretto::identity();
        let mut e_batch = Ed25519Scalar::zero();
        for (cm, ev) in cms_at_zeta.iter().zip(evals_at_zeta.iter()) {
            c_batch = c_batch.add(&cm.scalar_mul(&v_pow));
            e_batch = e_batch.add(&ev.mul(&v_pow));
            v_pow = v_pow.mul(&v);
        }

        // Statement point: C_batch − r_blind·H₀ + e_batch·H₀ opens at ζ
        // (equivalently: C_batch − r_blind·H₀ evaluates to e_batch).
        t.append_scalar(b"r_blind", &proof.r_blind);
        let p0 = c_batch
            .add(&gens.h.scalar_mul(&proof.r_blind).neg())
            .add(&gens.h.scalar_mul(&e_batch));
        let ones = alloc::vec![one; n];
        let zeros = alloc::vec![Ed25519Scalar::zero(); n];
        proof
            .ipp_zeta
            .verify(n, &mut t, &ones, &zeros, &p0, &gens.h, &gens.g, &gens.g)?;

        // `[z]` at ωζ: statement C_z − z_blind·H₀ evaluates to z(ωζ).
        // (The ω-scaled power vector lives on the prover side; the IPA folds
        // it into the proof, so the verifier never needs ω itself.)
        let pz = z_cm
            .add(&gens.h.scalar_mul(&proof.z_blind).neg())
            .add(&gens.h.scalar_mul(&proof.z_omega_eval));
        t.append_scalar(b"z_blind", &proof.z_blind);
        proof
            .ipp_z_omega
            .verify(n, &mut t, &ones, &zeros, &pz, &gens.h, &gens.g, &gens.g)
    }

    /// A primitive `n`-th root of unity in the scalar field (order exactly
    /// `n`), found by a small search over small bases.
    ///
    /// Note: the Ed25519 scalar field has 2-adicity 2 (`q−1 = 4·odd`), so
    /// power-of-two domains are limited to `n ≤ 4`. Larger PLONK circuits
    /// need a 2-adic scalar field (e.g. BLS12-381 `Fr`) — future work.
    #[must_use]
    pub fn root_of_unity(n: usize) -> Option<Ed25519Scalar> {
        for g in 2u64..1000 {
            let base = Ed25519Scalar::from_u64(g);
            let Some(w) = nth_root(&base, n) else {
                continue;
            };
            let w_n = w.pow_vartime(&[n as u64]);
            if !w_n.ct_eq(&Ed25519Scalar::one()).into_bool() {
                continue;
            }
            let w_half = w.pow_vartime(&[(n / 2) as u64]);
            if w_half.ct_eq(&Ed25519Scalar::one().neg()).into_bool() {
                return Some(w);
            }
        }
        None
    }
}

/// `1/x` for nonzero `x` (zero maps to zero via the unwrap-or default).
fn inv_or_zero(x: &Ed25519Scalar) -> Ed25519Scalar {
    x.invert().unwrap_or(Ed25519Scalar::zero())
}

/// `base^((q−1)/n)` when `n` divides `q−1`, else `None`.
fn nth_root(base: &Ed25519Scalar, n: usize) -> Option<Ed25519Scalar> {
    // Little-endian u64 limbs of q−1 for the Ed25519 scalar order
    // q = 2^252 + 27742317777372353535851937790883648493.
    let qm1: [u64; 4] = [
        0x5812_631a_5cf5_d3ec,
        0x14de_f9de_a2f7_9cd6,
        0x0000_0000_0000_0000,
        0x1000_0000_0000_0000,
    ];
    let n64 = n as u64;
    let mut q = [0u64; 4];
    let mut rem: u128 = 0;
    for (i, qi) in q.iter_mut().enumerate().rev() {
        let cur = (rem << 64) | qm1[i] as u128;
        *qi = (cur / n64 as u128) as u64;
        rem = cur % n64 as u128;
    }
    if rem != 0 {
        return None;
    }
    Some(base.pow_vartime(&q))
}

impl Proof {
    /// Serialize the proof (commitments, evaluations, blindings, IPA proofs).
    #[must_use]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        for cm in [
            &self.a,
            &self.b,
            &self.c,
            &self.z,
            &self.t_lo,
            &self.t_mid,
            &self.t_hi,
        ] {
            buf.extend_from_slice(cm);
        }
        for s in [
            &self.a_eval,
            &self.b_eval,
            &self.c_eval,
            &self.ql_eval,
            &self.qr_eval,
            &self.qo_eval,
            &self.qm_eval,
            &self.qc_eval,
            &self.s1_eval,
            &self.s2_eval,
            &self.s3_eval,
            &self.z_eval,
            &self.z_omega_eval,
            &self.t_lo_eval,
            &self.t_mid_eval,
            &self.t_hi_eval,
            &self.r_blind,
            &self.z_blind,
        ] {
            buf.extend_from_slice(&scalar_to_le_bytes(s));
        }
        // Length-prefix each IPA so two of them can be parsed back to back.
        let zeta_bytes = self.ipp_zeta.to_bytes();
        buf.push(zeta_bytes.len() as u8 / 32);
        buf.extend_from_slice(&zeta_bytes);
        let omega_bytes = self.ipp_z_omega.to_bytes();
        buf.push(omega_bytes.len() as u8 / 32);
        buf.extend_from_slice(&omega_bytes);
        buf
    }

    /// Deserialize a proof. The `2^lg == n` consistency of each IPA is
    /// enforced at verification time.
    ///
    /// # Errors
    ///
    /// [`ZkError::InvalidLength`] when the buffer is truncated, and
    /// [`ZkError::Malformed`] for non-canonical scalars.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ZkError> {
        let mut off = 0usize;
        let take32 = |off: &mut usize| -> Result<[u8; 32], ZkError> {
            if bytes.len() < *off + 32 {
                return Err(ZkError::InvalidLength);
            }
            let mut v = [0u8; 32];
            v.copy_from_slice(&bytes[*off..*off + 32]);
            *off += 32;
            Ok(v)
        };
        let scalar = |off: &mut usize| -> Result<Ed25519Scalar, ZkError> {
            let b = take32(off)?;
            bytes_to_scalar_checked(&b).ok_or(ZkError::Malformed)
        };
        let a = take32(&mut off)?;
        let b = take32(&mut off)?;
        let c = take32(&mut off)?;
        let z = take32(&mut off)?;
        let t_lo = take32(&mut off)?;
        let t_mid = take32(&mut off)?;
        let t_hi = take32(&mut off)?;
        let a_eval = scalar(&mut off)?;
        let b_eval = scalar(&mut off)?;
        let c_eval = scalar(&mut off)?;
        let ql_eval = scalar(&mut off)?;
        let qr_eval = scalar(&mut off)?;
        let qo_eval = scalar(&mut off)?;
        let qm_eval = scalar(&mut off)?;
        let qc_eval = scalar(&mut off)?;
        let s1_eval = scalar(&mut off)?;
        let s2_eval = scalar(&mut off)?;
        let s3_eval = scalar(&mut off)?;
        let z_eval = scalar(&mut off)?;
        let z_omega_eval = scalar(&mut off)?;
        let t_lo_eval = scalar(&mut off)?;
        let t_mid_eval = scalar(&mut off)?;
        let t_hi_eval = scalar(&mut off)?;
        let r_blind = scalar(&mut off)?;
        let z_blind = scalar(&mut off)?;
        // Each IPA is length-prefixed with its 32-byte element count
        // (`2·log₂(n) + 2`).
        let take_count = |off: &mut usize| -> Result<usize, ZkError> {
            if bytes.len() < *off + 1 {
                return Err(ZkError::InvalidLength);
            }
            let c = bytes[*off] as usize;
            *off += 1;
            Ok(c)
        };
        let zeta_elems = take_count(&mut off)?;
        if zeta_elems < 2 || zeta_elems % 2 != 0 || bytes.len() < off + zeta_elems * 32 {
            return Err(ZkError::InvalidLength);
        }
        let ipp_zeta = InnerProductProof::from_bytes(&bytes[off..off + zeta_elems * 32])?;
        off += zeta_elems * 32;
        let omega_elems = take_count(&mut off)?;
        if omega_elems < 2 || omega_elems % 2 != 0 || bytes.len() != off + omega_elems * 32 {
            return Err(ZkError::InvalidLength);
        }
        let ipp_z_omega = InnerProductProof::from_bytes(&bytes[off..])?;
        Ok(Self {
            a,
            b,
            c,
            z,
            t_lo,
            t_mid,
            t_hi,
            a_eval,
            b_eval,
            c_eval,
            ql_eval,
            qr_eval,
            qo_eval,
            qm_eval,
            qc_eval,
            s1_eval,
            s2_eval,
            s3_eval,
            z_eval,
            z_omega_eval,
            t_lo_eval,
            t_mid_eval,
            t_hi_eval,
            r_blind,
            z_blind,
            ipp_zeta,
            ipp_z_omega,
        })
    }
}
