//! K-PKE: the IND-CPA core of ML-KEM (FIPS 203 §7.1).
//!
//! [`kpke_keygen`] derives the public key `(ρ, t̂)`; [`kpke_encrypt`] produces a
//! ciphertext `(c1, c2)`; [`kpke_decrypt`] recovers the 32-byte message. All
//! operations are constant-time. The Fujisaki–Okamoto-style transform that turns
//! this into CCA-secure ML-KEM lives in [`crate::ml_kem`].
//!
//! This module stores serialized keys/ciphertexts in `alloc::Vec<u8>` (the ML-KEM
//! payloads are too large for the fixed-array, `no_std` core; the lower layers in
//! [`crate::poly`], [`crate::sampler`], [`crate::encode`] remain heap-free).

use alloc::vec;
use alloc::vec::Vec;

use crate::encode::{pack_poly, unpack_poly};
use crate::params::MlKemParams;
use crate::poly::{
    basemul_polys, freeze, invntt_p, ntt_p, poly_add, poly_frommsg, poly_tomsg, poly_tomont,
    Poly, N,
};
use crate::sampler::{cbd, sample_ntt};
use tpt_crypto_core::Error;
use tpt_crypto_hash::sha3::shake256;

/// A vector of `K` polynomials. Heap-backed because the KEM modules require
/// `alloc`; this keeps the `poly` core heap-free.
#[derive(Clone)]
pub struct PolyVec {
    /// The constituent polynomials.
    pub vec: Vec<Poly>,
}

impl PolyVec {
    /// The all-zero vector of length `k`.
    pub fn zero(k: usize) -> Self {
        PolyVec {
            vec: vec![[0i32; N]; k],
        }
    }
}

/// Derive the K-PKE public key from the 32-byte seed `d`.
pub fn kpke_keygen<P: MlKemParams>(d: &[u8; 32]) -> Vec<u8> {
    // G(d) = SHAKE256(d, 64): ρ ‖ σ
    let mut g = [0u8; 64];
    shake256(d, &mut g);
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&g[..32]);
    let mut sigma = [0u8; 32];
    sigma.copy_from_slice(&g[32..]);

    let mut s = PolyVec::zero(P::K);
    for i in 0..P::K {
        cbd(&mut s.vec[i], &sigma, i as u8, P::ETA1);
    }
    let mut e = PolyVec::zero(P::K);
    for i in 0..P::K {
        cbd(&mut e.vec[i], &sigma, (P::K + i) as u8, P::ETA2);
    }

    let mut t_hat = PolyVec::zero(P::K);
    for j in 0..P::K {
        let s_hat_j = ntt_p(&s.vec[j]);
        for i in 0..P::K {
            let a = sample_ntt(&rho, i as u8, j as u8);
            let a_hat = ntt_p(&a);
            let prod = basemul_polys(&a_hat, &s_hat_j);
            t_hat.vec[i] = poly_add(&t_hat.vec[i], &prod);
        }
        // Lift the accumulated row into Montgomery form (reference `poly_tomont`).
        poly_tomont(&mut t_hat.vec[j]);
    }
    for i in 0..P::K {
        let e_hat = ntt_p(&e.vec[i]);
        t_hat.vec[i] = poly_add(&t_hat.vec[i], &e_hat);
    }
    for i in 0..P::K {
        let mut c = [0i32; N];
        for (k, ck) in c.iter_mut().enumerate() {
            *ck = freeze(t_hat.vec[i][k]);
        }
        t_hat.vec[i] = c;
    }
    encode_pk::<P>(&rho, &t_hat)
}

/// Encode a public key `(ρ ‖ t̂)` with `t̂` packed at 12 bits/coefficient.
pub fn encode_pk<P: MlKemParams>(rho: &[u8; 32], t_hat: &PolyVec) -> Vec<u8> {
    let mut pk = vec![0u8; P::PK_LEN];
    pk[..32].copy_from_slice(rho);
    let mut off = 32;
    for i in 0..P::K {
        let mut buf = [0u8; 384];
        pack_poly(&mut buf, &t_hat.vec[i], 12);
        pk[off..off + 384].copy_from_slice(&buf);
        off += 384;
    }
    pk
}

/// Decode a public key into `(ρ, t̂)` (canonical `t̂`).
pub fn decode_pk<P: MlKemParams>(pk: &[u8]) -> Result<([u8; 32], PolyVec), Error> {
    if pk.len() != P::PK_LEN {
        return Err(Error::InvalidLength);
    }
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&pk[..32]);
    let mut t_hat = PolyVec::zero(P::K);
    let mut off = 32;
    for i in 0..P::K {
        t_hat.vec[i] = unpack_poly(&pk[off..off + 384], 12);
        off += 384;
    }
    Ok((rho, t_hat))
}

/// K-PKE encryption. `m` is the 32-byte message; `r_seed` seeds the ciphertext
/// noise (the FO transform's `r`).
pub fn kpke_encrypt<P: MlKemParams>(
    rho: &[u8; 32],
    t_hat: &PolyVec,
    m: &[u8; 32],
    r_seed: &[u8; 32],
) -> Vec<u8> {
    let mut rv = PolyVec::zero(P::K);
    for i in 0..P::K {
        cbd(&mut rv.vec[i], r_seed, i as u8, P::ETA1);
    }
    let mut e1 = PolyVec::zero(P::K);
    for i in 0..P::K {
        cbd(&mut e1.vec[i], r_seed, (P::K + i) as u8, P::ETA2);
    }
    let mut e2 = [0i32; N];
    cbd(&mut e2, r_seed, (2 * P::K) as u8, P::ETA2);

    // û = Aᵀ · r + e1
    let mut u_hat = PolyVec::zero(P::K);
    for i in 0..P::K {
        let r_hat_i = ntt_p(&rv.vec[i]);
        for j in 0..P::K {
            let a = sample_ntt(rho, j as u8, i as u8);
            let a_hat = ntt_p(&a);
            let prod = basemul_polys(&a_hat, &r_hat_i);
            u_hat.vec[i] = poly_add(&u_hat.vec[i], &prod);
        }
    }

    // v̂ = t̂ · r + e2 + m
    let mut v_hat = [0i32; N];
    for i in 0..P::K {
        let r_hat_i = ntt_p(&rv.vec[i]);
        let prod = basemul_polys(&t_hat.vec[i], &r_hat_i);
        v_hat = poly_add(&v_hat, &prod);
    }

    let mut ct = vec![0u8; P::CT_LEN];
    let c1_len = P::K * 32 * P::DU;
    let mut c1 = [0u8; 352 * 4];
    for i in 0..P::K {
        let u = invntt_p(&u_hat.vec[i]);
        let u = poly_add(&u, &e1.vec[i]);
        let mut u_canon = [0i32; N];
        for k in 0..N {
            u_canon[k] = freeze(u[k] as i32);
        }
        let mut tmp = [0u8; 352];
        pack_poly(&mut tmp, &u_canon, P::DU);
        let n = P::DU * 32;
        c1[i * n..(i + 1) * n].copy_from_slice(&tmp[..n]);
    }
    ct[..c1_len].copy_from_slice(&c1[..c1_len]);

    let mut v = invntt_p(&v_hat);
    v = poly_add(&v, &e2);
    let m_poly = poly_frommsg(m);
    v = poly_add(&v, &m_poly);
    let mut v_canon = [0i32; N];
    for k in 0..N {
        v_canon[k] = freeze(v[k] as i32);
    }
    let mut tmp = [0u8; 352];
    pack_poly(&mut tmp, &v_canon, P::DV);
    let n = P::DV * 32;
    ct[c1_len..c1_len + n].copy_from_slice(&tmp[..n]);

    ct
}

/// K-PKE decryption: recover the 32-byte message from a ciphertext.
pub fn kpke_decrypt<P: MlKemParams>(t_hat: &PolyVec, ct: &[u8]) -> Result<[u8; 32], Error> {
    if ct.len() != P::CT_LEN {
        return Err(Error::InvalidLength);
    }
    let c1_len = P::K * 32 * P::DU;
    let (c1, c2) = ct.split_at(c1_len);

    let mut u = PolyVec::zero(P::K);
    for i in 0..P::K {
        let n = P::DU * 32;
        u.vec[i] = unpack_poly(&c1[i * n..(i + 1) * n], P::DU);
    }
    let v = unpack_poly(c2, P::DV);

    let mut w_hat = [0i32; N];
    for i in 0..P::K {
        let u_hat_i = ntt_p(&u.vec[i]);
        let t_hat_i = ntt_p(&t_hat.vec[i]);
        let prod = basemul_polys(&t_hat_i, &u_hat_i);
        w_hat = poly_add(&w_hat, &prod);
    }
    let w = invntt_p(&w_hat);

    let mut m_poly = [0i32; N];
    for k in 0..N {
        m_poly[k] = freeze((v[k] as i32) - (w[k] as i32));
    }
    Ok(poly_tomsg(&m_poly))
}
