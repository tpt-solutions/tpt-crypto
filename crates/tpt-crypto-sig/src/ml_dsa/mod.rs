//! ML-DSA (FIPS 204) — lattice-based signatures.
//!
//! Implements ML-DSA-44 / -65 / -87 (the FIPS 204 parameter sets derived from
//! Dilithium) in pure Rust, `#![no_std]`, constant-time on secret data.
//!
//! - `keygen::<P>(rng)` derives the verifying/secret key pair from 32 bytes of
//!   seed material.
//! - `sign` (deterministic) and `sign_hedged` (randomized) produce signatures
//!   binding a message and an optional context string `Ctx` (FIPS 204 §5.3).
//! - `verify` accepts a `Signature` only when it is a valid authenticator for
//!   `(pk, msg, ctx)`.
//!
//! The rejection-sampling loop, the `*_chknorm` norm checks, and the hint
//! computation all run in time independent of the secret coefficients; see
//! `crate::constant_time` for the policy.
//!
//! # Note on the message hash
//!
//! Both signing *and* verification compute the message commitment
//! `μ = H(tr ‖ 0x00 ‖ |Ctx| ‖ Ctx ‖ M)` (SHAKE256, 64 bytes), independent of the
//! per-signature randomness `rnd`. The randomness enters only `ρ′`, so hedged
//! and deterministic signatures are both verifiable and the verifier never
//! needs `rnd`.

pub(crate) mod sample;

use alloc::vec;
use alloc::vec::Vec;

use core::marker::PhantomData;

use tpt_crypto_core::CryptoRng;
use tpt_crypto_ct::Choice;
use tpt_crypto_hash::sha3::shake256;

use crate::poly::{
    decompose_impl, make_hint, polyeta_pack, polyeta_unpack, polyt0_pack, polyt0_unpack,
    polyt1_pack, polyt1_unpack, polyw1_pack, use_hint, Poly, Q,
};
use crate::Error;

use super::bytes::PolyArray;

/// Polynomial degree `n = 256`.
pub const N: usize = crate::poly::N;

/// Packed size of one `t₁` polynomial (10 bits/coefficient).
const POLYT1_PACKED: usize = 320;
/// Packed size of one `t₀` polynomial (13 bits/coefficient).
const POLYT0_PACKED: usize = 416;
/// Packed size of one `s₁`/`s₂` polynomial for `η = 2`.
const POLYETA2_PACKED: usize = 96;
/// Packed size of one `s₁`/`s₂` polynomial for `η = 4`.
const POLYETA4_PACKED: usize = 128;
/// Packed size of one `z` polynomial for `γ₁ = 2^17`.
const POLYZ17_PACKED: usize = 576;
/// Packed size of one `z` polynomial for `γ₁ = 2^19`.
const POLYZ19_PACKED: usize = 640;
/// Maximum `w₁` packing length per polynomial (the `(q−1)/88` case).
const POLYW1_PACKED_MAX: usize = 192;
/// Maximum hint packing length for any parameter set (ω + k ≤ 196 + 8).
const MAX_HINT_PACKED: usize = 204;
/// Maximum challenge-seed length for any parameter set (λ/4 ≤ 64).
const MAX_CT_TILDE: usize = 64;

/// An ML-DSA parameter set (one of the FIPS 204 rows).
pub trait MlDsaParams: Copy + Clone {
    /// Rows of the public matrix `Â` (`k`).
    const K: usize;
    /// Columns of the secret `s₁` (`l`).
    const L: usize;
    /// Half-bound on the secret `s₁`/`s₂` coefficients (`η ∈ {2, 4}`).
    const ETA: i32;
    /// Half-bound `γ₁` on the masking vector `y`.
    const GAMMA1: i32;
    /// Decomposition bound `γ₂`.
    const GAMMA2: i32;
    /// Number of ±1 entries in the challenge `c` (`τ`).
    const TAU: usize;
    /// Rejection bound `β`.
    const BETA: i32;
    /// Maximum number of hint 1-bits (`ω`).
    const OMEGA: usize;
    /// Security strength in bits (`λ`).
    const LAMBDA: usize;
    /// Byte length of the challenge seed `c̃` (`λ/4` per FIPS 204 — 32/48/64).
    const CT_TILDE_LEN: usize = Self::LAMBDA / 4;
    /// Maximum context-string length (FIPS 204 §5.3).
    const CTX_MAX: usize = 255;

    /// Byte length of the encoded public key.
    const PUBLICKEYBYTES: usize;
    /// Byte length of the encoded secret key.
    const SECRETKEYBYTES: usize;
    /// Byte length of the encoded signature.
    const SIGNATUREBYTES: usize;

    /// The NTT-domain public matrix `Â` (a `k·l` polynomial array).
    type Mat: PolyArray;
    /// The secret/`y` vector `s₁` (an `l` polynomial array).
    type VecL: PolyArray;
    /// The secret vector `s₂`/`t` (a `k` polynomial array).
    type VecK: PolyArray;
}

macro_rules! ml_dsa_params {
    ($name:ident, $k:expr, $l:expr, $eta:expr, $g1:expr, $g2:expr, $tau:expr, $beta:expr,
     $omega:expr, $lambda:expr, $mat:ty, $vecl:ty, $veck:ty) => {
        #[doc = "An ML-DSA parameter set."]
        #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
        pub struct $name;

        impl MlDsaParams for $name {
            const K: usize = $k;
            const L: usize = $l;
            const ETA: i32 = $eta;
            const GAMMA1: i32 = $g1;
            const GAMMA2: i32 = $g2;
            const TAU: usize = $tau;
            const BETA: i32 = $beta;
            const OMEGA: usize = $omega;
            const LAMBDA: usize = $lambda;
            const PUBLICKEYBYTES: usize = 32 + $k * POLYT1_PACKED;
            const SECRETKEYBYTES: usize = 32
                + 32
                + 64
                + $l * if $eta == 2 {
                    POLYETA2_PACKED
                } else {
                    POLYETA4_PACKED
                }
                + $k * if $eta == 2 {
                    POLYETA2_PACKED
                } else {
                    POLYETA4_PACKED
                }
                + $k * POLYT0_PACKED;
            const SIGNATUREBYTES: usize = $lambda / 4
                + $l * if $g1 == (1 << 17) {
                    POLYZ17_PACKED
                } else {
                    POLYZ19_PACKED
                }
                + $omega
                + $k;
            type Mat = $mat;
            type VecL = $vecl;
            type VecK = $veck;
        }
    };
}

ml_dsa_params!(
    MlDsa44,
    4,
    4,
    2,
    1 << 17,
    (Q - 1) / 88,
    39,
    78,
    80,
    128,
    [Poly; 16],
    [Poly; 4],
    [Poly; 4]
);
ml_dsa_params!(
    MlDsa65,
    6,
    5,
    4,
    1 << 19,
    (Q - 1) / 32,
    49,
    196,
    55,
    192,
    [Poly; 30],
    [Poly; 5],
    [Poly; 6]
);
ml_dsa_params!(
    MlDsa87,
    8,
    7,
    2,
    1 << 19,
    (Q - 1) / 32,
    60,
    120,
    75,
    256,
    [Poly; 56],
    [Poly; 7],
    [Poly; 8]
);

// ── Key / signature types ─────────────────────────────────────────────────────

/// An ML-DSA verifying key (`ρ ‖ t₁` in FIPS 204 wire format).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PublicKey<P: MlDsaParams> {
    /// The encoded public key.
    pub bytes: Vec<u8>,
    _marker: PhantomData<P>,
}

/// An ML-DSA secret (signing) key (`ρ ‖ K ‖ tr ‖ s₁ ‖ s₂ ‖ t₀`).
///
/// Callers should treat the byte buffer as secret and zeroize it after use;
/// see `crate::constant_time`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SecretKey<P: MlDsaParams> {
    /// The encoded secret key.
    pub bytes: Vec<u8>,
    _marker: PhantomData<P>,
}

/// An ML-DSA signature (`c̃ ‖ z ‖ h`).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Signature<P: MlDsaParams> {
    /// The encoded signature.
    pub bytes: Vec<u8>,
    _marker: PhantomData<P>,
}

impl<P: MlDsaParams> PublicKey<P> {
    /// Borrow the key as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Parse a public key from its encoded form.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == P::PUBLICKEYBYTES {
            Some(PublicKey {
                bytes: bytes.to_vec(),
                _marker: PhantomData,
            })
        } else {
            None
        }
    }
}

impl<P: MlDsaParams> SecretKey<P> {
    /// Borrow the key as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Parse a secret key from its encoded form.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == P::SECRETKEYBYTES {
            Some(SecretKey {
                bytes: bytes.to_vec(),
                _marker: PhantomData,
            })
        } else {
            None
        }
    }
}

impl<P: MlDsaParams> Signature<P> {
    /// Borrow the signature as bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Parse a signature from its encoded form.
    #[must_use]
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() == P::SIGNATUREBYTES {
            Some(Signature {
                bytes: bytes.to_vec(),
                _marker: PhantomData,
            })
        } else {
            None
        }
    }
}

// ── Low-level helpers ─────────────────────────────────────────────────────────

/// One-shot SHAKE256 producing `out.len()` bytes from concatenated parts.
fn shake256_concat(parts: &[&[u8]], out: &mut [u8]) {
    let mut buf = Vec::new();
    for p in parts {
        buf.extend_from_slice(p);
    }
    shake256(&buf, out);
}

/// Convert a slice of canonical polynomials into NTT (NTT-domain) form in place.
fn to_ntt(v: &mut [Poly]) {
    for p in v.iter_mut() {
        p.ntt();
    }
}

/// `out = Â · v` where `Â` is `k·l` NTT polynomials and `v` is `l` NTT
/// polynomials; `out` (`k` polynomials) is returned in coefficient form.
fn mat_vec_mul(a: &[Poly], v: &[Poly], out: &mut [Poly]) {
    let l = v.len();
    for i in 0..out.len() {
        let mut acc = Poly::ZERO;
        for j in 0..l {
            // FIPS 204 NTT-domain product: coefficientwise. `a` holds the raw
            // ExpandA coefficients, `v` the Montgomery-NTT form of a canonical
            // vector (`ntt` = to_mont ∘ plain-ζ butterflies).
            acc.pointwise_acc(&a[i * l + j], &v[j]);
        }
        // The accumulated product lacks the Montgomery factor `inv_ntt`
        // strips; lift it so the inverse transform lands on coefficients.
        acc.to_mont_vec();
        acc.inv_ntt();
        acc.canonicalize();
        out[i] = acc;
    }
}

/// Infinity norm (maximum absolute coefficient) of a vector of polynomials.
fn inf_norm(v: &[Poly]) -> i32 {
    let mut m = 0i32;
    for p in v {
        for &c in &p.coeffs {
            let a = c.abs();
            if a > m {
                m = a;
            }
        }
    }
    m
}

/// `Decompose` a polynomial into `(high, low)` parts per coefficient.
fn decompose_poly(gamma2: i32, src: &Poly, hi: &mut Poly, lo: &mut Poly) {
    for j in 0..N {
        let (r1, r0) = decompose_impl(gamma2, src.coeffs[j]);
        hi.coeffs[j] = r1;
        lo.coeffs[j] = r0;
    }
}

/// `w₁` packing length (in bytes) for a given `γ₂`.
#[inline]
fn polyw1_len(gamma2: i32) -> usize {
    if gamma2 == (Q - 1) / 88 {
        192
    } else {
        128
    }
}

/// Pack the hint vector `h` (`k` polynomials, coefficients in `{0, 1}`).
fn pack_hint<P: MlDsaParams>(h: &[Poly], out: &mut [u8]) {
    let mut offset = 0usize;
    for i in 0..P::K {
        for j in 0..N {
            if h[i].coeffs[j] != 0 {
                out[offset] = j as u8;
                offset += 1;
            }
        }
        out[P::OMEGA + i] = offset as u8;
    }
}

/// Unpack the hint vector `h` into `k` polynomials of `{0, 1}` coefficients.
///
/// Returns `None` for a malformed encoding (FIPS 204 `HintBitUnpack` ⊥ cases:
/// non-monotone section counts, count above `ω`, non-increasing indices within a
/// section, or a non-zero unused tail).
fn unpack_hint<P: MlDsaParams>(inp: &[u8], h: &mut [Poly]) -> Option<()> {
    for p in h.iter_mut() {
        *p = Poly::ZERO;
    }
    let mut idx = 0usize;
    for (i, h_poly) in h.iter_mut().enumerate().take(P::K) {
        let end = inp[P::OMEGA + i] as usize;
        if end < idx || end > P::OMEGA {
            return None;
        }
        let mut last: i32 = -1;
        while idx < end {
            let j = inp[idx] as usize;
            if (j as i32) <= last {
                return None;
            }
            last = j as i32;
            if j < N {
                h_poly.coeffs[j] = 1;
            }
            idx += 1;
        }
    }
    // The unused tail of the index section must be all zero.
    for &b in &inp[idx..P::OMEGA] {
        if b != 0 {
            return None;
        }
    }
    Some(())
}

/// Decode the public key into `(ρ, t₁)` where `t₁` is a `k`-vector of polys.
fn parse_public_key<P: MlDsaParams>(pk: &PublicKey<P>) -> ([u8; 32], P::VecK)
where
    P::VecK: PolyArray,
{
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&pk.bytes[..32]);
    let mut t1 = <P::VecK as PolyArray>::zeroed();
    let t1s = t1.as_poly_slice_mut();
    for (idx, t1_poly) in t1s.iter_mut().enumerate().take(P::K) {
        let mut buf = [0u8; POLYT1_PACKED];
        let off = 32 + idx * POLYT1_PACKED;
        buf.copy_from_slice(&pk.bytes[off..off + POLYT1_PACKED]);
        *t1_poly = polyt1_unpack(&buf).expect("t1 unpack");
    }
    (rho, t1)
}

// ── Key generation (FIPS 204 Algorithms 1 & 6) ───────────────────────────────

/// Deterministically derive a key pair from a 32-byte seed `ξ`.
pub fn keygen_from_seed<P: MlDsaParams>(xi: &[u8; 32]) -> (PublicKey<P>, SecretKey<P>)
where
    P::Mat: PolyArray,
    P::VecL: PolyArray,
    P::VecK: PolyArray,
{
    // (ρ, ρ′, K) ← H(ξ ‖ ⟨k⟩ ‖ ⟨ℓ⟩) = SHAKE256(ξ ‖ k ‖ ℓ, 128), split
    // 32/64/32 (FIPS 204 Algorithm 6 — the parameter-set bytes bind the seed
    // to this parameter set).
    let mut expanded = [0u8; 128];
    shake256_concat(&[xi, &[P::K as u8, P::L as u8]], &mut expanded);
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&expanded[..32]);
    let mut rho_prime = [0u8; 64];
    rho_prime.copy_from_slice(&expanded[32..96]);
    let mut k_seed = [0u8; 32];
    k_seed.copy_from_slice(&expanded[96..128]);

    let a = crate::ml_dsa::sample::expand_a::<P>(&rho);
    let (s1, s2) = crate::ml_dsa::sample::expand_s::<P>(&rho_prime);

    // Pack the canonical secret vectors into the secret key *before* they are
    // moved into their NTT/montgomery forms below.
    let mut sk_bytes = vec![0u8; P::SECRETKEYBYTES];
    {
        let mut off = 0;
        sk_bytes[off..off + 32].copy_from_slice(&rho);
        off += 32;
        sk_bytes[off..off + 32].copy_from_slice(&k_seed);
        off += 32;
        sk_bytes[off..off + 64].copy_from_slice(&[0u8; 64]); // tr placeholder
        off += 64;
        let s1_slice = s1.as_poly_slice();
        for s1_poly in s1_slice.iter().take(P::L) {
            let n = if P::ETA == 2 {
                POLYETA2_PACKED
            } else {
                POLYETA4_PACKED
            };
            let mut buf = [0u8; POLYETA4_PACKED];
            polyeta_pack(P::ETA, s1_poly, &mut buf);
            sk_bytes[off..off + n].copy_from_slice(&buf[..n]);
            off += n;
        }
        let s2_slice = s2.as_poly_slice();
        for s2_poly in s2_slice.iter().take(P::K) {
            let n = if P::ETA == 2 {
                POLYETA2_PACKED
            } else {
                POLYETA4_PACKED
            };
            let mut buf = [0u8; POLYETA4_PACKED];
            polyeta_pack(P::ETA, s2_poly, &mut buf);
            sk_bytes[off..off + n].copy_from_slice(&buf[..n]);
            off += n;
        }
        // t₀ is packed after Power2Round below.
    }

    // t = Â · ŝ₁ + s₂ (ŝ₁ in NTT domain; s₂ left in canonical coefficients).
    let mut s1hat = s1;
    to_ntt(s1hat.as_poly_slice_mut());
    let mut t = <P::VecK as PolyArray>::zeroed();
    {
        let a_slice = a.as_poly_slice();
        let s1_slice = s1hat.as_poly_slice();
        let t_slice = t.as_poly_slice_mut();
        mat_vec_mul(a_slice, s1_slice, t_slice);
    }
    {
        let t_slice = t.as_poly_slice_mut();
        let s2_slice = s2.as_poly_slice();
        for (t_poly, s2_poly) in t_slice.iter_mut().zip(s2_slice.iter()).take(P::K) {
            t_poly.add_assign(s2_poly);
            t_poly.reduce();
            // Power2Round needs a canonical (`[0, q)`) input.
            t_poly.canonicalize();
        }
    }

    // (t₁, t₀) = Power2Round(t, 13)
    let mut t1 = <P::VecK as PolyArray>::zeroed();
    let mut t0 = <P::VecK as PolyArray>::zeroed();
    {
        let t_slice = t.as_poly_slice();
        let t1_slice = t1.as_poly_slice_mut();
        let t0_slice = t0.as_poly_slice_mut();
        for ((t_poly, t1_poly), t0_poly) in t_slice
            .iter()
            .zip(t1_slice.iter_mut())
            .zip(t0_slice.iter_mut())
            .take(P::K)
        {
            t_poly.power2round_into(t1_poly, t0_poly);
        }
    }

    // pk = ρ ‖ t₁
    let mut pk_bytes = vec![0u8; P::PUBLICKEYBYTES];
    pk_bytes[..32].copy_from_slice(&rho);
    {
        let t1_slice = t1.as_poly_slice();
        let mut off = 32;
        for t1_poly in t1_slice.iter().take(P::K) {
            let mut buf = [0u8; POLYT1_PACKED];
            polyt1_pack(t1_poly, &mut buf);
            pk_bytes[off..off + POLYT1_PACKED].copy_from_slice(&buf);
            off += POLYT1_PACKED;
        }
    }

    // tr = H(pk)
    let mut tr = [0u8; 64];
    shake256(&pk_bytes, &mut tr);

    // Fill tr into the already-built secret key and append t₀. (s₁, s₂ are
    // already packed before being moved into their NTT forms.)
    {
        let mut off = 64;
        sk_bytes[off..off + 64].copy_from_slice(&tr);
        off += 64;
        let n1 = if P::ETA == 2 {
            POLYETA2_PACKED
        } else {
            POLYETA4_PACKED
        };
        off += P::L * n1 + P::K * n1;
        let t0_slice = t0.as_poly_slice();
        for t0_poly in t0_slice.iter().take(P::K) {
            let mut buf = [0u8; POLYT0_PACKED];
            polyt0_pack(t0_poly, &mut buf);
            sk_bytes[off..off + POLYT0_PACKED].copy_from_slice(&buf);
            off += POLYT0_PACKED;
        }
    }

    (
        PublicKey {
            bytes: pk_bytes,
            _marker: PhantomData,
        },
        SecretKey {
            bytes: sk_bytes,
            _marker: PhantomData,
        },
    )
}

/// Generate a key pair, drawing the 32-byte seed `ξ` from `rng`.
pub fn keygen<P: MlDsaParams, R: CryptoRng>(rng: &mut R) -> (PublicKey<P>, SecretKey<P>)
where
    P::Mat: PolyArray,
    P::VecL: PolyArray,
    P::VecK: PolyArray,
{
    keygen_from_seed::<P>(&rng.gen_array::<32>())
}

// ── Signing (FIPS 204 Algorithms 2 & 7) ──────────────────────────────────────

/// Compute the message commitment `μ` from `tr`, `ctx`, `msg`.
fn compute_mu(tr: &[u8; 64], ctx: &[u8], msg: &[u8], mu: &mut [u8; 64]) {
    // μ = H(tr ‖ 0x00 ‖ IntegerToBytes(|Ctx|, 1) ‖ Ctx ‖ M)   (FIPS 204 §5.2)
    shake256_concat(&[tr, &[0u8, ctx.len() as u8], ctx, msg], mu);
}

/// Compute `ρ′` from `K`, `μ`, and optional `rnd`.
fn compute_rhoprime(k_seed: &[u8; 32], mu: &[u8; 64], rnd: Option<&[u8; 32]>, out: &mut [u8; 64]) {
    match rnd {
        Some(r) => shake256_concat(&[k_seed, mu, r], out),
        None => shake256_concat(&[k_seed, mu, &[0u8]], out),
    }
}

/// Internal signing routine shared by deterministic and hedged entry points.
fn sign_internal<P: MlDsaParams>(
    sk: &SecretKey<P>,
    msg: &[u8],
    ctx: &[u8],
    rnd: Option<&[u8; 32]>,
) -> Result<Signature<P>, Error>
where
    P::Mat: PolyArray,
    P::VecL: PolyArray,
    P::VecK: PolyArray,
{
    if ctx.len() > P::CTX_MAX {
        return Err(Error::InvalidLength);
    }

    // Parse sk: ρ(32) ‖ K(32) ‖ tr(64) ‖ s₁ ‖ s₂ ‖ t₀
    let mut rho = [0u8; 32];
    rho.copy_from_slice(&sk.bytes[..32]);
    let mut k_seed = [0u8; 32];
    k_seed.copy_from_slice(&sk.bytes[32..64]);
    let mut tr = [0u8; 64];
    tr.copy_from_slice(&sk.bytes[64..128]);

    let mut s1 = <P::VecL as PolyArray>::zeroed();
    let mut s2 = <P::VecK as PolyArray>::zeroed();
    let mut t0 = <P::VecK as PolyArray>::zeroed();
    {
        let mut off = 128;
        let s1s = s1.as_poly_slice_mut();
        for s1_poly in s1s.iter_mut().take(P::L) {
            let n = if P::ETA == 2 {
                POLYETA2_PACKED
            } else {
                POLYETA4_PACKED
            };
            let mut buf = [0u8; POLYETA4_PACKED];
            buf[..n].copy_from_slice(&sk.bytes[off..off + n]);
            *s1_poly = polyeta_unpack(P::ETA, &buf[..n]).ok_or(Error::InvalidEncoding)?;
            off += n;
        }
        let s2s = s2.as_poly_slice_mut();
        for s2_poly in s2s.iter_mut().take(P::K) {
            let n = if P::ETA == 2 {
                POLYETA2_PACKED
            } else {
                POLYETA4_PACKED
            };
            let mut buf = [0u8; POLYETA4_PACKED];
            buf[..n].copy_from_slice(&sk.bytes[off..off + n]);
            *s2_poly = polyeta_unpack(P::ETA, &buf[..n]).ok_or(Error::InvalidEncoding)?;
            off += n;
        }
        // t₀ (needed for the hint: h ← MakeHint(−c∘t₀, w − c∘s₂ + c∘t₀)).
        let t0s = t0.as_poly_slice_mut();
        for t0_poly in t0s.iter_mut().take(P::K) {
            let mut buf = [0u8; POLYT0_PACKED];
            buf.copy_from_slice(&sk.bytes[off..off + POLYT0_PACKED]);
            *t0_poly = polyt0_unpack(&buf).ok_or(Error::InvalidEncoding)?;
            off += POLYT0_PACKED;
        }
    }

    let mut mu = [0u8; 64];
    compute_mu(&tr, ctx, msg, &mut mu);

    let mut rhoprime = [0u8; 64];
    compute_rhoprime(&k_seed, &mu, rnd, &mut rhoprime);

    let a = crate::ml_dsa::sample::expand_a::<P>(&rho);

    let mut s1hat = s1;
    to_ntt(s1hat.as_poly_slice_mut());
    let mut s2hat = s2;
    to_ntt(s2hat.as_poly_slice_mut());
    let mut t0hat = t0;
    to_ntt(t0hat.as_poly_slice_mut());

    let mut kappa: u16 = 0;

    // Fixed iteration cap; rejection probability per loop is tiny.
    for _ in 0..256 {
        // y = ExpandMask(ρ′, κ)
        let y = crate::ml_dsa::sample::expand_mask::<P>(&rhoprime, kappa);
        let mut yhat = y.clone();
        to_ntt(yhat.as_poly_slice_mut());

        // w = Â · y
        let mut w = <P::VecK as PolyArray>::zeroed();
        mat_vec_mul(
            a.as_poly_slice(),
            yhat.as_poly_slice(),
            w.as_poly_slice_mut(),
        );

        // (w₁, w₀) = Decompose(w)
        let mut w1 = <P::VecK as PolyArray>::zeroed();
        let mut w0 = <P::VecK as PolyArray>::zeroed();
        {
            let w_slice = w.as_poly_slice();
            let w1_slice = w1.as_poly_slice_mut();
            let w0_slice = w0.as_poly_slice_mut();
            for ((w1_poly, w0_poly), w_poly) in w1_slice
                .iter_mut()
                .zip(w0_slice.iter_mut())
                .zip(w_slice.iter())
                .take(P::K)
            {
                decompose_poly(P::GAMMA2, w_poly, w1_poly, w0_poly);
            }
        }

        // c̃ = H(μ ‖ w₁)
        let mut w1_packed = vec![0u8; P::K * polyw1_len(P::GAMMA2)];
        {
            let w1_slice = w1.as_poly_slice();
            let mut off = 0;
            for w1_poly in w1_slice.iter().take(P::K) {
                let n = polyw1_len(P::GAMMA2);
                let mut buf = [0u8; POLYW1_PACKED_MAX];
                polyw1_pack(P::GAMMA2, w1_poly, &mut buf[..n]);
                w1_packed[off..off + n].copy_from_slice(&buf[..n]);
                off += n;
            }
        }
        let mut c_tilde = [0u8; MAX_CT_TILDE];
        shake256_concat(&[&mu, &w1_packed], &mut c_tilde[..P::CT_TILDE_LEN]);

        // c = SampleInBall(c̃)
        let c = crate::ml_dsa::sample::poly_challenge(&c_tilde[..P::CT_TILDE_LEN], P::TAU);
        let mut chat = c;
        chat.ntt();

        // z = y + c ∘ s₁
        let mut z = y;
        {
            let z_slice = z.as_poly_slice_mut();
            let s1_slice = s1hat.as_poly_slice();
            for i in 0..P::L {
                let mut t = Poly::ZERO;
                t.pointwise(&chat, &s1_slice[i]);
                t.inv_ntt();
                t.reduce();
                t.canonicalize();
                z_slice[i].add_assign(&t);
                z_slice[i].reduce();
            }
        }
        if inf_norm(z.as_poly_slice()) >= P::GAMMA1 - P::BETA {
            kappa = kappa.wrapping_add(1);
            continue;
        }

        // cs2 = c ∘ s₂ (time domain)
        let mut cs2 = <P::VecK as PolyArray>::zeroed();
        {
            let cs2_slice = cs2.as_poly_slice_mut();
            let s2_slice = s2hat.as_poly_slice();
            for (cs2_poly, s2_poly) in cs2_slice.iter_mut().zip(s2_slice.iter()).take(P::K) {
                let mut t = Poly::ZERO;
                t.pointwise(&chat, s2_poly);
                t.inv_ntt();
                t.reduce();
                *cs2_poly = t;
            }
        }

        // r₀ = LowBits(w − c ∘ s₂), approximated by w₀ − c ∘ s₂ (exact under the
        // norm check below).
        let mut r0 = <P::VecK as PolyArray>::zeroed();
        {
            let r0_slice = r0.as_poly_slice_mut();
            let w0_slice = w0.as_poly_slice();
            let cs2_slice = cs2.as_poly_slice();
            for ((r0_poly, w0_poly), cs2_poly) in r0_slice
                .iter_mut()
                .zip(w0_slice.iter())
                .zip(cs2_slice.iter())
                .take(P::K)
            {
                *r0_poly = *w0_poly;
                r0_poly.sub_assign(cs2_poly);
                r0_poly.reduce();
            }
        }
        if inf_norm(r0.as_poly_slice()) >= P::GAMMA2 - P::BETA {
            kappa = kappa.wrapping_add(1);
            continue;
        }

        // ct0 = c ∘ t₀ (time domain)
        let mut ct0 = <P::VecK as PolyArray>::zeroed();
        {
            let ct0_slice = ct0.as_poly_slice_mut();
            let t0_slice = t0hat.as_poly_slice();
            for (ct0_poly, t0_poly) in ct0_slice.iter_mut().zip(t0_slice.iter()).take(P::K) {
                let mut t = Poly::ZERO;
                t.pointwise(&chat, t0_poly);
                t.inv_ntt();
                t.reduce();
                *ct0_poly = t;
            }
        }
        if inf_norm(ct0.as_poly_slice()) >= P::GAMMA2 {
            kappa = kappa.wrapping_add(1);
            continue;
        }

        // h = MakeHint(−c ∘ t₀, w − c ∘ s₂ + c ∘ t₀); reject if popcount > ω.
        let mut h = <P::VecK as PolyArray>::zeroed();
        let mut hint_ones = 0usize;
        {
            let h_slice = h.as_poly_slice_mut();
            let w_slice = w.as_poly_slice();
            let cs2_slice = cs2.as_poly_slice();
            let ct0_slice = ct0.as_poly_slice();
            for (((h_poly, w_poly), cs2_poly), ct0_poly) in h_slice
                .iter_mut()
                .zip(w_slice.iter())
                .zip(cs2_slice.iter())
                .zip(ct0_slice.iter())
                .take(P::K)
            {
                for j in 0..N {
                    let wcs2 = w_poly.coeffs[j] - cs2_poly.coeffs[j];
                    let r_full = wcs2 + ct0_poly.coeffs[j];
                    let hb = make_hint(-ct0_poly.coeffs[j], r_full, P::GAMMA2);
                    let bit = u8::from(bool::from(hb));
                    h_poly.coeffs[j] = i32::from(bit);
                    hint_ones += usize::from(bit);
                }
            }
        }
        if hint_ones > P::OMEGA {
            kappa = kappa.wrapping_add(1);
            continue;
        }

        // Encode: c̃ ‖ z ‖ h
        let mut sig_bytes = vec![0u8; P::SIGNATUREBYTES];
        sig_bytes[..P::CT_TILDE_LEN].copy_from_slice(&c_tilde[..P::CT_TILDE_LEN]);
        {
            let z_slice = z.as_poly_slice();
            let mut off = P::CT_TILDE_LEN;
            for z_poly in z_slice.iter().take(P::L) {
                let n = if P::GAMMA1 == (1 << 17) {
                    POLYZ17_PACKED
                } else {
                    POLYZ19_PACKED
                };
                let mut buf = [0u8; POLYZ19_PACKED];
                crate::poly::polyz_pack(P::GAMMA1, z_poly, &mut buf[..n]);
                sig_bytes[off..off + n].copy_from_slice(&buf[..n]);
                off += n;
            }
            let mut hbuf = [0u8; MAX_HINT_PACKED];
            pack_hint::<P>(h.as_poly_slice(), &mut hbuf[..P::OMEGA + P::K]);
            sig_bytes[off..off + P::OMEGA + P::K].copy_from_slice(&hbuf[..P::OMEGA + P::K]);
        }
        return Ok(Signature {
            bytes: sig_bytes,
            _marker: PhantomData,
        });
    }
    Err(Error::RngFailure)
}

/// Sign `msg` under `sk` (deterministic, FIPS 204 §5.3).
///
/// `ctx` is the context string (≤ 255 bytes). Pass `&[]` for the empty context.
pub fn sign<P: MlDsaParams>(
    sk: &SecretKey<P>,
    msg: &[u8],
    ctx: &[u8],
) -> Result<Signature<P>, Error>
where
    P::Mat: PolyArray,
    P::VecL: PolyArray,
    P::VecK: PolyArray,
{
    sign_internal::<P>(sk, msg, ctx, None)
}

/// Sign `msg` under `sk` with explicit per-signature randomness `rnd` (hedged).
pub fn sign_hedged<P: MlDsaParams>(
    sk: &SecretKey<P>,
    msg: &[u8],
    ctx: &[u8],
    rnd: &[u8; 32],
) -> Result<Signature<P>, Error>
where
    P::Mat: PolyArray,
    P::VecL: PolyArray,
    P::VecK: PolyArray,
{
    sign_internal::<P>(sk, msg, ctx, Some(rnd))
}

// ── Verification (FIPS 204 Algorithms 3 & 8) ──────────────────────────────────

/// Verify that `sig` authenticates `(pk, msg, ctx)`.
pub fn verify<P: MlDsaParams>(
    pk: &PublicKey<P>,
    msg: &[u8],
    sig: &Signature<P>,
    ctx: &[u8],
) -> Result<(), Error>
where
    P::Mat: PolyArray,
    P::VecL: PolyArray,
    P::VecK: PolyArray,
{
    if ctx.len() > P::CTX_MAX {
        return Err(Error::InvalidLength);
    }

    let (rho, t1) = parse_public_key::<P>(pk);
    let mut t1d = t1;
    // t₁ · 2^d (shift by d = 13, then bring into canonical form)
    {
        let s = t1d.as_poly_slice_mut();
        for p in s.iter_mut() {
            p.shift_left_d();
        }
    }

    // Parse signature: c̃(λ/4) ‖ z ‖ h
    let ct_len = P::CT_TILDE_LEN;
    let mut c_tilde = [0u8; MAX_CT_TILDE];
    c_tilde[..ct_len].copy_from_slice(&sig.bytes[..ct_len]);
    let mut z = <P::VecL as PolyArray>::zeroed();
    let mut h = <P::VecK as PolyArray>::zeroed();
    {
        let mut off = P::CT_TILDE_LEN;
        let zs = z.as_poly_slice_mut();
        for z_poly in zs.iter_mut().take(P::L) {
            let n = if P::GAMMA1 == (1 << 17) {
                POLYZ17_PACKED
            } else {
                POLYZ19_PACKED
            };
            let mut buf = [0u8; POLYZ19_PACKED];
            buf[..n].copy_from_slice(&sig.bytes[off..off + n]);
            *z_poly =
                crate::poly::polyz_unpack(P::GAMMA1, &buf[..n]).ok_or(Error::InvalidEncoding)?;
            off += n;
        }
        let hbuf = &sig.bytes[off..off + P::OMEGA + P::K];
        if hbuf.len() != P::OMEGA + P::K {
            return Err(Error::InvalidLength);
        }
        unpack_hint::<P>(hbuf, h.as_poly_slice_mut()).ok_or(Error::InvalidEncoding)?;
    }

    if inf_norm(z.as_poly_slice()) >= P::GAMMA1 - P::BETA {
        return Err(Error::Verification);
    }

    let mut tr = [0u8; 64];
    shake256(&pk.bytes, &mut tr);
    let mut mu = [0u8; 64];
    compute_mu(&tr, ctx, msg, &mut mu);

    let c = crate::ml_dsa::sample::poly_challenge(&c_tilde[..ct_len], P::TAU);
    let mut chat = c;
    chat.ntt();

    let a = crate::ml_dsa::sample::expand_a::<P>(&rho);

    // ŵ = Â · ẑ − ĉ ∘ (2^d · t̂₁)
    let mut w = <P::VecK as PolyArray>::zeroed();
    {
        let mut zhat = z;
        to_ntt(zhat.as_poly_slice_mut());
        mat_vec_mul(
            a.as_poly_slice(),
            zhat.as_poly_slice(),
            w.as_poly_slice_mut(),
        );
    }

    // subtract ĉ ∘ (2^d · t̂₁)
    {
        let w_slice = w.as_poly_slice_mut();
        let mut t1d_ntt = t1d;
        to_ntt(t1d_ntt.as_poly_slice_mut());
        let t1d_slice = t1d_ntt.as_poly_slice();
        for (w_poly, t1d_poly) in w_slice.iter_mut().zip(t1d_slice.iter()).take(P::K) {
            let mut t = Poly::ZERO;
            t.pointwise(&chat, t1d_poly);
            t.inv_ntt();
            t.reduce();
            t.canonicalize();
            w_poly.sub_assign(&t);
            w_poly.reduce();
        }
    }

    // Reconstruct w₁ = UseHint(h, ŵ) for every coefficient, then compare.
    let mut w1_rec = <P::VecK as PolyArray>::zeroed();
    {
        let w_slice = w.as_poly_slice();
        let w1_slice = w1_rec.as_poly_slice_mut();
        let h_slice = h.as_poly_slice();
        for ((w1_poly, w_poly), h_poly) in w1_slice
            .iter_mut()
            .zip(w_slice.iter())
            .zip(h_slice.iter())
            .take(P::K)
        {
            for (j, (w1_c, w_c)) in w1_poly
                .coeffs
                .iter_mut()
                .zip(w_poly.coeffs.iter())
                .enumerate()
            {
                let hb = Choice::from_u8_lsb(h_poly.coeffs[j] as u8);
                *w1_c = use_hint(hb, *w_c, P::GAMMA2);
            }
        }
    }

    // Build the packed w₁ and recompute c̃.

    let mut w1_packed = vec![0u8; P::K * polyw1_len(P::GAMMA2)];
    {
        let w1_slice = w1_rec.as_poly_slice();
        let mut off = 0;
        for w1_poly in w1_slice.iter().take(P::K) {
            let n = polyw1_len(P::GAMMA2);
            let mut buf = [0u8; POLYW1_PACKED_MAX];
            polyw1_pack(P::GAMMA2, w1_poly, &mut buf[..n]);
            w1_packed[off..off + n].copy_from_slice(&buf[..n]);
            off += n;
        }
    }
    let mut c_rec = [0u8; MAX_CT_TILDE];
    shake256_concat(&[&mu, &w1_packed], &mut c_rec[..ct_len]);

    // Constant-time comparison of c̃.
    if bool::from(tpt_crypto_ct::ct_eq_bytes(
        &c_rec[..ct_len],
        &c_tilde[..ct_len],
    )) {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tpt_crypto_core::CryptoRng;

    // A trivial deterministic RNG for tests (NOT cryptographic).
    struct TestRng(u64);
    impl CryptoRng for TestRng {
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), tpt_crypto_core::Error> {
            for d in dest.iter_mut() {
                self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
                *d = (self.0 >> 33) as u8;
            }
            Ok(())
        }
    }

    fn round_trip<P: MlDsaParams>()
    where
        P::Mat: PolyArray,
        P::VecL: PolyArray,
        P::VecK: PolyArray,
    {
        let mut rng = TestRng(0x1234_5678);
        let (pk, sk) = keygen::<P, _>(&mut rng);
        let msg = b"the quick brown fox";
        let sig = sign::<P>(&sk, msg, &[]).expect("sign");
        assert!(verify::<P>(&pk, msg, &sig, &[]).is_ok(), "verify ok");

        // wrong message
        assert!(verify::<P>(&pk, b"wrong", &sig, &[]).is_err());
        // wrong ctx
        assert!(verify::<P>(&pk, msg, &sig, b"ctx").is_err());
        // wrong key
        let (pk2, _) = keygen::<P, _>(&mut rng);
        assert!(verify::<P>(&pk2, msg, &sig, &[]).is_err());
    }

    #[test]
    fn ml_dsa_44_round_trip() {
        round_trip::<MlDsa44>();
    }
    #[test]
    fn ml_dsa_65_round_trip() {
        round_trip::<MlDsa65>();
    }
    #[test]
    fn ml_dsa_87_round_trip() {
        round_trip::<MlDsa87>();
    }

    #[test]
    fn ml_dsa_hedged_round_trip() {
        let mut rng = TestRng(0xABCD);
        let (pk, sk) = keygen::<MlDsa65, _>(&mut rng);
        let msg = b"hedged message";
        let rnd = rng.gen_array::<32>();
        let sig = sign_hedged::<MlDsa65>(&sk, msg, &[], &rnd).expect("sign");
        assert!(verify::<MlDsa65>(&pk, msg, &sig, &[]).is_ok());
    }

    #[test]
    fn ml_dsa_ctx_separation() {
        let mut rng = TestRng(0x9999);
        let (pk, sk) = keygen::<MlDsa65, _>(&mut rng);
        let msg = b"same message, different context";
        let s0 = sign::<MlDsa65>(&sk, msg, &[]).expect("sign");
        let s1 = sign::<MlDsa65>(&sk, msg, b"ctx-a").expect("sign");
        assert_ne!(s0.bytes, s1.bytes, "different ctx -> different sig");
        assert!(verify::<MlDsa65>(&pk, msg, &s0, &[]).is_ok());
        assert!(verify::<MlDsa65>(&pk, msg, &s1, b"ctx-a").is_ok());
        assert!(verify::<MlDsa65>(&pk, msg, &s0, b"ctx-a").is_err());
    }

    #[test]
    fn ml_dsa_decoy_packing() {
        // Re-encoding pk/sk/sig from bytes must round-trip.
        let mut rng = TestRng(0x2222);
        let (pk, sk) = keygen::<MlDsa44, _>(&mut rng);
        let pk2 = PublicKey::<MlDsa44>::from_bytes(&pk.bytes).unwrap();
        let sk2 = SecretKey::<MlDsa44>::from_bytes(&sk.bytes).unwrap();
        let msg = b"packing";
        let sig = sign::<MlDsa44>(&sk2, msg, &[]).unwrap();
        let sig2 = Signature::<MlDsa44>::from_bytes(&sig.bytes).unwrap();
        assert!(verify::<MlDsa44>(&pk2, msg, &sig2, &[]).is_ok());
    }
}
