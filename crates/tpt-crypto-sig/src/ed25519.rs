//! Ed25519 (RFC 8032) signatures.
//!
//! Thin typed layer over [`tpt_crypto_curve::edwards25519`]: the scalar
//! multiplication, point (de)compression and the RFC 8032 sign / verify core
//! all live in `-curve`. This module adds:
//!
//! * key newtypes ([`SigningKey`] / [`VerifyingKey`] / [`Signature`]) with the
//!   seed held in a [`SecretBox`],
//! * strict RFC 8032 §5.1.7 canonical-`S` rejection on verification,
//! * [`verify_batch`], a random linear-combination batch check.
//!
//! Only pure Ed25519 (no context, no pre-hash) is implemented.

use tpt_crypto_core::{CryptoRng, Error, Result, SecretBox};
use tpt_crypto_curve::edwards25519::{scalar, EdwardsPoint};
use tpt_crypto_field::{CtEq, Ed25519Scalar};
use tpt_crypto_hash::sha2::Sha512;
use tpt_crypto_hash::Hasher;

/// Length of an Ed25519 seed / private key.
pub const SEED_LEN: usize = 32;
/// Length of a compressed Ed25519 public key.
pub const PUBLIC_KEY_LEN: usize = 32;
/// Length of an Ed25519 signature.
pub const SIGNATURE_LEN: usize = 64;

/// An Ed25519 signing key — the 32-byte seed, kept in a [`SecretBox`].
pub struct SigningKey {
    seed: SecretBox<[u8; SEED_LEN]>,
}

impl SigningKey {
    /// Construct from a caller-provided 32-byte seed.
    #[must_use]
    pub fn from_seed(seed: [u8; SEED_LEN]) -> Self {
        Self {
            seed: SecretBox::new(seed),
        }
    }

    /// Generate a fresh signing key from `rng`.
    pub fn generate<R: CryptoRng>(rng: &mut R) -> Result<Self> {
        let mut seed = [0u8; SEED_LEN];
        rng.try_fill_bytes(&mut seed)?;
        Ok(Self::from_seed(seed))
    }

    /// The matching public key.
    #[must_use]
    pub fn verifying_key(&self) -> VerifyingKey {
        VerifyingKey(EdwardsPoint::public_key(self.seed.expose_secret()))
    }

    /// Sign `msg` (RFC 8032 pure Ed25519).
    #[must_use]
    pub fn sign(&self, msg: &[u8]) -> Signature {
        Signature(EdwardsPoint::sign(self.seed.expose_secret(), msg))
    }
}

/// An Ed25519 verifying (public) key: a compressed Edwards point.
#[derive(Clone, Copy, Debug)]
pub struct VerifyingKey([u8; PUBLIC_KEY_LEN]);

impl VerifyingKey {
    /// Parse a compressed public key, rejecting points that do not decompress.
    pub fn from_bytes(bytes: &[u8; PUBLIC_KEY_LEN]) -> Result<Self> {
        if EdwardsPoint::decompress(bytes).is_some().into_bool() {
            Ok(Self(*bytes))
        } else {
            Err(Error::InvalidEncoding)
        }
    }

    /// The compressed encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_LEN] {
        self.0
    }

    /// Verify `sig` over `msg`. Rejects a non-canonical `S` (RFC 8032 §5.1.7).
    pub fn verify(&self, msg: &[u8], sig: &Signature) -> Result<()> {
        let s_bytes: [u8; 32] = sig.0[32..].try_into().expect("32 bytes");
        if !scalar::is_canonical_le32(&s_bytes) {
            return Err(Error::Verification);
        }
        if EdwardsPoint::verify(&self.0, msg, &sig.0) {
            Ok(())
        } else {
            Err(Error::Verification)
        }
    }
}

/// An Ed25519 signature (`R || S`, 64 bytes).
#[derive(Clone, Copy, Debug)]
pub struct Signature([u8; SIGNATURE_LEN]);

impl Signature {
    /// Wrap a 64-byte signature.
    #[must_use]
    pub fn from_bytes(bytes: [u8; SIGNATURE_LEN]) -> Self {
        Self(bytes)
    }

    /// The 64-byte encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIGNATURE_LEN] {
        self.0
    }
}

/// One entry for [`verify_batch`]: a public key, its message, and the signature.
pub struct BatchEntry<'a> {
    /// Signer public key.
    pub key: VerifyingKey,
    /// Signed message.
    pub msg: &'a [u8],
    /// Candidate signature.
    pub sig: Signature,
}

/// Batch-verify a slice of `(key, msg, sig)` entries.
///
/// Uses the standard random linear-combination test: for random per-entry
/// weights `z_i` (128-bit), the batch is valid iff
///
/// ```text
/// [8]( [-sum z_i S_i] B  +  sum z_i R_i  +  sum (z_i k_i) A_i ) == O
/// ```
///
/// with `k_i = SHA512(R_i || A_i || msg_i) mod L`. A single invalid signature
/// makes the combined point non-identity with overwhelming probability, so the
/// whole batch is rejected (this call does not identify *which* entry failed —
/// fall back to per-entry [`VerifyingKey::verify`] for that).
///
/// An empty batch verifies vacuously.
pub fn verify_batch<R: CryptoRng>(entries: &[BatchEntry<'_>], rng: &mut R) -> Result<()> {
    if entries.is_empty() {
        return Ok(());
    }

    let mut lhs_s = Ed25519Scalar::zero(); // sum z_i S_i
    let mut acc = EdwardsPoint::identity(); // sum z_i R_i + sum (z_i k_i) A_i

    for e in entries {
        let r_bytes: [u8; 32] = e.sig.0[..32].try_into().expect("32 bytes");
        let s_bytes: [u8; 32] = e.sig.0[32..].try_into().expect("32 bytes");

        if !scalar::is_canonical_le32(&s_bytes) {
            return Err(Error::Verification);
        }
        let a_pt = EdwardsPoint::decompress(&e.key.0);
        let r_pt = EdwardsPoint::decompress(&r_bytes);
        if !(a_pt.is_some().and(r_pt.is_some())).into_bool() {
            return Err(Error::Verification);
        }
        let a_pt = a_pt.unwrap();
        let r_pt = r_pt.unwrap();

        // Random 128-bit weight.
        let mut zb = [0u8; 32];
        rng.try_fill_bytes(&mut zb[..16])?;
        let z = scalar::from_le32(&zb);

        // k_i = SHA512(R || A || msg) mod L.
        let mut h = Sha512::new();
        h.update(&r_bytes);
        h.update(&e.key.0);
        h.update(e.msg);
        let k = scalar::reduce_wide_le(&h.finalize());

        let s = scalar::from_le32(&s_bytes);
        lhs_s = lhs_s.add(&z.mul(&s));

        acc = acc.add(&r_pt.mul(&scalar::to_le32(z)));
        acc = acc.add(&a_pt.mul(&scalar::to_le32(z.mul(&k))));
    }

    // acc + [-lhs_s] B, then clear the cofactor.
    let neg_lhs = Ed25519Scalar::zero().sub(&lhs_s);
    let combined = acc.add(&EdwardsPoint::basepoint().mul(&scalar::to_le32(neg_lhs)));

    if combined
        .mul_by_cofactor()
        .ct_eq(&EdwardsPoint::identity())
        .into_bool()
    {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}
