//! Bulletproofs generator vectors, derived deterministically from SHAKE256.
//!
//! The aggregated range proof needs `n·m` independent generator points
//! `G_vec` and `H_vec`. They are derived by hashing a domain label together
//! with the index, so the verifier can reconstruct them from `n` and `m`
//! without any trusted setup beyond the fixed Pedersen generators.

use crate::group::Ristretto;

/// Holder for the vector generators used by Bulletproofs.
pub struct BulletproofGens;

impl BulletproofGens {
    /// `G_vec` of length `n·m` (one generator per bit across `m` values).
    pub fn g_vec(n: usize, m: usize) -> alloc::vec::Vec<Ristretto> {
        let mut out = alloc::vec::Vec::with_capacity(n * m);
        for i in 0..n * m {
            out.push(Ristretto::map_to_point(&gen_label(b"G", i)));
        }
        out
    }

    /// `H_vec` of length `n·m` (one generator per bit across `m` values).
    pub fn h_vec(n: usize, m: usize) -> alloc::vec::Vec<Ristretto> {
        let mut out = alloc::vec::Vec::with_capacity(n * m);
        for i in 0..n * m {
            out.push(Ristretto::map_to_point(&gen_label(b"H", i)));
        }
        out
    }
}

fn gen_label(prefix: &[u8], i: usize) -> alloc::vec::Vec<u8> {
    let mut v = alloc::vec::Vec::new();
    v.extend_from_slice(b"tpt-crypto-zk.Bulletproofs.");
    v.extend_from_slice(prefix);
    v.extend_from_slice(b".");
    v.extend_from_slice(&i.to_le_bytes());
    v
}
