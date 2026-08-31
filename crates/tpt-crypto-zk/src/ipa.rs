//! Inner-product argument (IPA) over the prime-order group.
//!
//! The argument lets a prover convince a verifier that, for public generator
//! vectors `G`, `H` and a public point `Q`, the relation
//!
//! ```text
//! P = <a, G> + <b, H'> + <a, b> · Q        where H'_i = H_factors[i] · H_i
//! ```
//!
//! holds for secret `a`, `b` (the IPA proves the inner product `<a, b>`). The
//! proof is `2·log₂(n)` points plus two scalars, independent of `n`. This is
//! the core building block of the Bulletproofs range proof and the PLONK
//! verifier.

use tpt_crypto_field::Ed25519Scalar;

use crate::error::ZkError;
use crate::group::Ristretto;
use crate::transcript::Transcript;

/// An inner-product argument proof.
#[derive(Clone, Debug)]
pub struct InnerProductProof {
    /// The `L` points (length `log₂(n)`).
    pub l_vec: alloc::vec::Vec<[u8; 32]>,
    /// The `R` points (length `log₂(n)`).
    pub r_vec: alloc::vec::Vec<[u8; 32]>,
    /// Final `a` scalar.
    pub a: Ed25519Scalar,
    /// Final `b` scalar.
    pub b: Ed25519Scalar,
}

/// Inner product `Σ a_i · b_i`.
fn inner_product(a: &[Ed25519Scalar], b: &[Ed25519Scalar]) -> Ed25519Scalar {
    let mut out = Ed25519Scalar::zero();
    for i in 0..a.len() {
        out = out.add(&a[i].mul(&b[i]));
    }
    out
}

/// Multiscalar multiplication `Σ s_i · P_i`.
fn msm(scalars: &[Ed25519Scalar], points: &[Ristretto]) -> Ristretto {
    let mut acc = Ristretto::identity();
    for i in 0..scalars.len() {
        acc = acc.add(&points[i].scalar_mul(&scalars[i]));
    }
    acc
}

/// Invert each element of `v` in place and return the product of all inverses.
fn batch_invert(v: &mut [Ed25519Scalar]) -> Ed25519Scalar {
    let mut acc = Ed25519Scalar::one();
    for x in v.iter_mut() {
        let inv = x.invert().unwrap();
        *x = inv;
        acc = acc.mul(&inv);
    }
    acc
}

impl InnerProductProof {
    /// Create an inner-product proof for `P = <a, G> + <b, H'> + <a, b>·Q`.
    ///
    /// `transcript` is mutated so the challenges depend on the entire parent
    /// protocol. `G` and `H` are the generator vectors; `H_factors` weights the
    /// `H` vectors (`H'_i = H_factors[i] · H_i`). All vectors must have the same
    /// length, a power of two.
    pub fn create(
        transcript: &mut Transcript,
        q: &Ristretto,
        g_factors: &[Ed25519Scalar],
        h_factors: &[Ed25519Scalar],
        mut g_vec: alloc::vec::Vec<Ristretto>,
        mut h_vec: alloc::vec::Vec<Ristretto>,
        mut a_vec: alloc::vec::Vec<Ed25519Scalar>,
        mut b_vec: alloc::vec::Vec<Ed25519Scalar>,
    ) -> InnerProductProof {
        let n0 = g_vec.len();
        assert_eq!(n0, h_vec.len());
        assert_eq!(n0, a_vec.len());
        assert_eq!(n0, b_vec.len());
        assert_eq!(n0, g_factors.len());
        assert_eq!(n0, h_factors.len());
        assert!(n0.is_power_of_two());

        transcript.append_message(b"dom", b"IPA");

        let lg_n = n0.trailing_zeros() as usize;
        let mut l_vec = alloc::vec::Vec::with_capacity(lg_n);
        let mut r_vec = alloc::vec::Vec::with_capacity(lg_n);

        let mut g = &mut g_vec[..];
        let mut h = &mut h_vec[..];
        let mut a = &mut a_vec[..];
        let mut b = &mut b_vec[..];
        let mut n = n0;

        // First iteration: fold the (constant) G/H factors into the generators.
        if n != 1 {
            n /= 2;
            let (a_l, a_r) = a.split_at_mut(n);
            let (b_l, b_r) = b.split_at_mut(n);
            let (g_l, g_r) = g.split_at_mut(n);
            let (h_l, h_r) = h.split_at_mut(n);

            let c_l = inner_product(a_l, b_r);
            let c_r = inner_product(a_r, b_l);

            let mut l_scalars = alloc::vec::Vec::with_capacity(2 * n + 1);
            let mut l_points = alloc::vec::Vec::with_capacity(2 * n + 1);
            for i in 0..n {
                l_scalars.push(a_l[i].mul(&g_factors[n + i]));
                l_points.push(g_r[i]);
            }
            for i in 0..n {
                l_scalars.push(b_r[i].mul(&h_factors[i]));
                l_points.push(h_l[i]);
            }
            l_scalars.push(c_l);
            l_points.push(*q);

            let mut r_scalars = alloc::vec::Vec::with_capacity(2 * n + 1);
            let mut r_points = alloc::vec::Vec::with_capacity(2 * n + 1);
            for i in 0..n {
                r_scalars.push(a_r[i].mul(&g_factors[i]));
                r_points.push(g_l[i]);
            }
            for i in 0..n {
                r_scalars.push(b_l[i].mul(&h_factors[n + i]));
                r_points.push(h_r[i]);
            }
            r_scalars.push(c_r);
            r_points.push(*q);

            let l = msm(&l_scalars, &l_points);
            let r = msm(&r_scalars, &r_points);
            l_vec.push(l.compress());
            r_vec.push(r.compress());

            transcript.append_point(b"L", &l);
            transcript.append_point(b"R", &r);
            let u = transcript.challenge_scalar(b"u");
            let u_inv = u.invert().unwrap();

            for i in 0..n {
                a_l[i] = a_l[i].mul(&u).add(&u_inv.mul(&a_r[i]));
                b_l[i] = b_l[i].mul(&u_inv).add(&u.mul(&b_r[i]));
                g_l[i] = msm(
                    &[u_inv.mul(&g_factors[i]), u.mul(&g_factors[n + i])],
                    &[g_l[i], g_r[i]],
                );
                h_l[i] = msm(
                    &[u.mul(&h_factors[i]), u_inv.mul(&h_factors[n + i])],
                    &[h_l[i], h_r[i]],
                );
            }
            a = a_l;
            b = b_l;
            g = g_l;
            h = h_l;
        }

        // Remaining iterations: factors are now baked into the folded generators.
        while n != 1 {
            n /= 2;
            let (a_l, a_r) = a.split_at_mut(n);
            let (b_l, b_r) = b.split_at_mut(n);
            let (g_l, g_r) = g.split_at_mut(n);
            let (h_l, h_r) = h.split_at_mut(n);

            let c_l = inner_product(a_l, b_r);
            let c_r = inner_product(a_r, b_l);

            let mut l_scalars = alloc::vec::Vec::with_capacity(2 * n + 1);
            let mut l_points = alloc::vec::Vec::with_capacity(2 * n + 1);
            for i in 0..n {
                l_scalars.push(a_l[i]);
                l_points.push(g_r[i]);
            }
            for i in 0..n {
                l_scalars.push(b_r[i]);
                l_points.push(h_l[i]);
            }
            l_scalars.push(c_l);
            l_points.push(*q);

            let mut r_scalars = alloc::vec::Vec::with_capacity(2 * n + 1);
            let mut r_points = alloc::vec::Vec::with_capacity(2 * n + 1);
            for i in 0..n {
                r_scalars.push(a_r[i]);
                r_points.push(g_l[i]);
            }
            for i in 0..n {
                r_scalars.push(b_l[i]);
                r_points.push(h_r[i]);
            }
            r_scalars.push(c_r);
            r_points.push(*q);

            let l = msm(&l_scalars, &l_points);
            let r = msm(&r_scalars, &r_points);
            l_vec.push(l.compress());
            r_vec.push(r.compress());

            transcript.append_point(b"L", &l);
            transcript.append_point(b"R", &r);
            let u = transcript.challenge_scalar(b"u");
            let u_inv = u.invert().unwrap();

            for i in 0..n {
                a_l[i] = a_l[i].mul(&u).add(&u_inv.mul(&a_r[i]));
                b_l[i] = b_l[i].mul(&u_inv).add(&u.mul(&b_r[i]));
                g_l[i] = msm(&[u_inv, u], &[g_l[i], g_r[i]]);
                h_l[i] = msm(&[u, u_inv], &[h_l[i], h_r[i]]);
            }
            a = a_l;
            b = b_l;
            g = g_l;
            h = h_l;
        }

        InnerProductProof {
            l_vec,
            r_vec,
            a: a[0],
            b: b[0],
        }
    }

    /// Recompute the verification scalars `(u_i²)`, `(u_i^{-2})`, and the `s`
    /// vector for combined multiscalar verification.
    pub fn verification_scalars(
        &self,
        n: usize,
        transcript: &mut Transcript,
    ) -> Result<(alloc::vec::Vec<Ed25519Scalar>, alloc::vec::Vec<Ed25519Scalar>, alloc::vec::Vec<Ed25519Scalar>), ZkError> {
        let lg_n = self.l_vec.len();
        if lg_n >= 32 {
            return Err(ZkError::Verification);
        }
        if n != (1 << lg_n) {
            return Err(ZkError::Verification);
        }

        transcript.append_message(b"dom", b"IPA");

        let mut challenges = alloc::vec::Vec::with_capacity(lg_n);
        for (l, r) in self.l_vec.iter().zip(self.r_vec.iter()) {
            transcript.append_message(b"L", l);
            transcript.append_message(b"R", r);
            challenges.push(transcript.challenge_scalar(b"u"));
        }

        let mut challenges_inv = challenges.clone();
        let allinv = batch_invert(&mut challenges_inv);

        for i in 0..lg_n {
            challenges[i] = challenges[i].mul(&challenges[i]);
            challenges_inv[i] = challenges_inv[i].mul(&challenges_inv[i]);
        }
        let challenges_sq = challenges;
        let challenges_inv_sq = challenges_inv;

        let mut s = alloc::vec::Vec::with_capacity(n);
        s.push(allinv);
        for i in 1..n {
            let lg_i = (32 - 1 - (i as u32).leading_zeros()) as usize;
            let k = 1 << lg_i;
            let u_lg_i_sq = challenges_sq[(lg_n - 1) - lg_i];
            s.push(s[i - k].mul(&u_lg_i_sq));
        }

        Ok((challenges_sq, challenges_inv_sq, s))
    }

    /// Standalone verification of the inner-product relation for a commitment
    /// `p` (used by tests and direct callers).
    pub fn verify(
        &self,
        n: usize,
        transcript: &mut Transcript,
        g_factors: &[Ed25519Scalar],
        h_factors: &[Ed25519Scalar],
        p: &Ristretto,
        q: &Ristretto,
        g: &[Ristretto],
        h: &[Ristretto],
    ) -> Result<(), ZkError> {
        let (u_sq, u_inv_sq, s) = self.verification_scalars(n, transcript)?;

        let mut scalars = alloc::vec::Vec::new();
        let mut points = alloc::vec::Vec::new();

        scalars.push(self.a.mul(&self.b));
        points.push(*q);

        for (gi, si) in g_factors.iter().zip(s.iter()) {
            scalars.push(self.a.mul(si).mul(gi));
        }
        for p_ in g.iter() {
            points.push(*p_);
        }
        let inv_s: alloc::vec::Vec<Ed25519Scalar> = s.iter().rev().copied().collect();
        for (hi, si_inv) in h_factors.iter().zip(inv_s.iter()) {
            scalars.push(self.b.mul(si_inv).mul(hi));
        }
        for p_ in h.iter() {
            points.push(*p_);
        }
        for ui in &u_sq {
            scalars.push(ui.neg());
        }
        for l in &self.l_vec {
            points.push(Ristretto::decompress(l).ok_or(ZkError::Malformed)?);
        }
        for r in &self.r_vec {
            points.push(Ristretto::decompress(r).ok_or(ZkError::Malformed)?);
        }

        let expect_p = msm(&scalars, &points);
        if expect_p.ct_eq(p) {
            Ok(())
        } else {
            Err(ZkError::Verification)
        }
    }

    /// Serialize the proof to `2·log₂(n) + 2` 32-byte elements.
    pub fn to_bytes(&self) -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec::Vec::with_capacity((self.l_vec.len() * 2 + 2) * 32);
        for (l, r) in self.l_vec.iter().zip(self.r_vec.iter()) {
            buf.extend_from_slice(l);
            buf.extend_from_slice(r);
        }
        buf.extend_from_slice(&self.a.to_bytes()[16..48]);
        buf.extend_from_slice(&self.b.to_bytes()[16..48]);
        buf
    }

    /// Deserialize a proof from bytes (length must be a multiple of 32, with at
    /// least `2·log₂(n) + 2` elements).
    pub fn from_bytes(slice: &[u8]) -> Result<InnerProductProof, ZkError> {
        if slice.len() % 32 != 0 {
            return Err(ZkError::InvalidLength);
        }
        let elems = slice.len() / 32;
        if elems < 2 {
            return Err(ZkError::InvalidLength);
        }
        if (elems - 2) % 2 != 0 {
            return Err(ZkError::InvalidLength);
        }
        let lg_n = (elems - 2) / 2;
        if lg_n >= 32 {
            return Err(ZkError::InvalidLength);
        }
        let mut l_vec = alloc::vec::Vec::with_capacity(lg_n);
        let mut r_vec = alloc::vec::Vec::with_capacity(lg_n);
        for i in 0..lg_n {
            let pos = 2 * i * 32;
            let mut l = [0u8; 32];
            let mut r = [0u8; 32];
            l.copy_from_slice(&slice[pos..pos + 32]);
            r.copy_from_slice(&slice[pos + 32..pos + 64]);
            l_vec.push(l);
            r_vec.push(r);
        }
        let pos = 2 * lg_n * 32;
        let mut la = [0u8; 32];
        let mut lb = [0u8; 32];
        la.copy_from_slice(&slice[pos..pos + 32]);
        lb.copy_from_slice(&slice[pos + 32..pos + 64]);
        let a = bytes_to_scalar_checked(&la).ok_or(ZkError::Malformed)?;
        let b = bytes_to_scalar_checked(&lb).ok_or(ZkError::Malformed)?;
        Ok(InnerProductProof { l_vec, r_vec, a, b })
    }
}

/// Reconstruct a scalar from its 32-byte little-endian encoding, rejecting
/// non-canonical values. Exposed for proof deserialization.
pub(crate) fn bytes_to_scalar_checked(bytes: &[u8]) -> Option<Ed25519Scalar> {
    if bytes.len() < 32 {
        return None;
    }
    // Re-encode as the 48-byte big-endian form the field crate expects.
    let mut be = [0u8; 48];
    for i in 0..32 {
        be[16 + (31 - i)] = bytes[i];
    }
    // The field crate's `from_bytes` rejects non-canonical (> p) encodings.
    let opt = Ed25519Scalar::from_bytes(&be);
    if opt.is_some().into_bool() {
        Some(opt.unwrap())
    } else {
        None
    }
}
