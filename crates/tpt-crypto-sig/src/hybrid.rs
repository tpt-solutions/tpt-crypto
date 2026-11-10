//! Hybrid signature: Ed25519 + ML-DSA-65, both required.
//!
//! A forgery needs a break of *both* schemes. The Ed25519 half protects against
//! a future lattice break, and the ML-DSA-65 half protects against a quantum
//! attack on the discrete log. Both components sign the same encoded message:
//!
//! ```text
//! M' = LABEL ‖ u8(|ctx|) ‖ ctx ‖ M
//! ```
//!
//! where `LABEL = "tpt-crypto/hybrid-ed25519-mldsa65/v1"` gives domain separation
//! and the length byte makes the `(ctx, M)` split unambiguous. Ed25519 signs `M'`
//! directly. ML-DSA-65 signs `M'` with an empty FIPS 204 context.
//!
//! Wire format (fixed length):
//!
//! * Public key: `ed25519_pk (32) ‖ mldsa65_pk (1952)`.
//! * Signature: `ed25519_sig (64) ‖ mldsa65_sig (3309)`.
//!
//! This is **not** the IETF composite-signature wire format
//! (draft-ietf-lamps-pq-composite-sigs); it is a crate-specific encoding with the
//! same AND-combination. Use it only between parties built from this crate.
//!
//! Verification computes both checks before deciding, so the result does not
//! depend on which component failed.

use crate::ed25519::{
    Signature as EdSignature, SigningKey as EdSigningKey, VerifyingKey as EdVerifyingKey,
};
use crate::ml_dsa::{
    self, MlDsa65, MlDsaParams, PublicKey as MlPublicKey, SecretKey as MlSecretKey,
    Signature as MlSignature,
};
use alloc::vec::Vec;
use tpt_crypto_core::{CryptoRng, Error, Result, SecretBox};

/// Domain-separation label bound into every signed message.
pub const LABEL: &[u8] = b"tpt-crypto/hybrid-ed25519-mldsa65/v1";
/// Ed25519 public-key length.
pub const ED_PUBLIC_LEN: usize = 32;
/// Ed25519 seed length.
pub const ED_SEED_LEN: usize = 32;
/// ML-DSA-65 public-key length.
pub const ML_PUBLIC_LEN: usize = MlDsa65::PUBLICKEYBYTES;
/// Hybrid public-key length.
pub const PUBLIC_KEY_LEN: usize = ED_PUBLIC_LEN + ML_PUBLIC_LEN;
/// Ed25519 signature length.
pub const ED_SIG_LEN: usize = 64;
/// ML-DSA-65 signature length.
pub const ML_SIG_LEN: usize = MlDsa65::SIGNATUREBYTES;
/// Hybrid signature length.
pub const SIGNATURE_LEN: usize = ED_SIG_LEN + ML_SIG_LEN;
/// Maximum context length (matches the FIPS 204 limit).
pub const CTX_MAX: usize = 255;

/// A hybrid verifying key.
#[derive(Clone)]
pub struct VerifyingKey {
    ed: [u8; ED_PUBLIC_LEN],
    ml: MlPublicKey<MlDsa65>,
}

/// A hybrid signing key. Holds the Ed25519 seed (zeroed on drop) and the
/// ML-DSA-65 secret key bytes.
pub struct SigningKey {
    ed_seed: SecretBox<[u8; ED_SEED_LEN]>,
    ml: MlSecretKey<MlDsa65>,
    verifying: VerifyingKey,
}

/// A hybrid signature: `ed25519 ‖ mldsa65`.
#[derive(Clone, PartialEq, Eq)]
pub struct Signature(pub [u8; SIGNATURE_LEN]);

impl VerifyingKey {
    /// Parse a hybrid public key. Returns [`Error::InvalidLength`] on a wrong
    /// length and [`Error::InvalidEncoding`] if the ML-DSA part does not parse.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != PUBLIC_KEY_LEN {
            return Err(Error::InvalidLength);
        }
        let mut ed = [0u8; ED_PUBLIC_LEN];
        ed.copy_from_slice(&bytes[..ED_PUBLIC_LEN]);
        let ml = MlPublicKey::<MlDsa65>::from_bytes(&bytes[ED_PUBLIC_LEN..])
            .ok_or(Error::InvalidEncoding)?;
        Ok(Self { ed, ml })
    }

    /// Encode as `ed25519 ‖ mldsa65`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PUBLIC_KEY_LEN);
        out.extend_from_slice(&self.ed);
        out.extend_from_slice(&self.ml.bytes);
        out
    }
}

impl SigningKey {
    /// The matching verifying key.
    pub fn verifying_key(&self) -> &VerifyingKey {
        &self.verifying
    }
}

/// Map the sig crate's error type onto the core one used by this module.
fn map_sig_error(e: crate::Error) -> Error {
    match e {
        crate::Error::InvalidLength => Error::InvalidLength,
        crate::Error::Verification => Error::Verification,
        crate::Error::RngFailure => Error::RngFailure,
        _ => Error::InvalidEncoding,
    }
}

/// Build the message both components sign (see the module docs).
fn encode_message(ctx: &[u8], msg: &[u8]) -> Result<Vec<u8>> {
    if ctx.len() > CTX_MAX {
        return Err(Error::InvalidLength);
    }
    let mut m = Vec::with_capacity(LABEL.len() + 1 + ctx.len() + msg.len());
    m.extend_from_slice(LABEL);
    m.push(ctx.len() as u8);
    m.extend_from_slice(ctx);
    m.extend_from_slice(msg);
    Ok(m)
}

/// Deterministic key generation from an Ed25519 seed and an ML-DSA seed `xi`.
pub fn keygen_from_seeds(ed_seed: &[u8; ED_SEED_LEN], xi: &[u8; 32]) -> SigningKey {
    let ed_pk = EdSigningKey::from_seed(*ed_seed).verifying_key().to_bytes();
    let (ml_pk, ml_sk) = ml_dsa::keygen_from_seed::<MlDsa65>(xi);
    SigningKey {
        ed_seed: SecretBox::new(*ed_seed),
        ml: ml_sk,
        verifying: VerifyingKey {
            ed: ed_pk,
            ml: ml_pk,
        },
    }
}

/// Generate a hybrid key pair from an RNG.
pub fn keygen(rng: &mut impl CryptoRng) -> SigningKey {
    let ed_seed = rng.gen_array::<ED_SEED_LEN>();
    let xi = rng.gen_array::<32>();
    keygen_from_seeds(&ed_seed, &xi)
}

/// Sign `msg` with context `ctx` (at most [`CTX_MAX`] bytes). Deterministic.
pub fn sign(sk: &SigningKey, ctx: &[u8], msg: &[u8]) -> Result<Signature> {
    let m = encode_message(ctx, msg)?;
    let ed = EdSigningKey::from_seed(*sk.ed_seed.expose_secret())
        .sign(&m)
        .to_bytes();
    let ml = ml_dsa::sign::<MlDsa65>(&sk.ml, &m, &[]).map_err(map_sig_error)?;
    if ml.bytes.len() != ML_SIG_LEN {
        return Err(Error::InvalidLength);
    }
    let mut out = [0u8; SIGNATURE_LEN];
    out[..ED_SIG_LEN].copy_from_slice(&ed);
    out[ED_SIG_LEN..].copy_from_slice(&ml.bytes);
    Ok(Signature(out))
}

/// Verify a hybrid signature. Requires both components to verify.
///
/// Returns [`Error::InvalidLength`] for a wrong-length signature and
/// [`Error::Verification`] when either component fails.
pub fn verify(vk: &VerifyingKey, ctx: &[u8], msg: &[u8], sig: &[u8]) -> Result<()> {
    if sig.len() != SIGNATURE_LEN {
        return Err(Error::InvalidLength);
    }
    let m = encode_message(ctx, msg)?;

    let mut ed_bytes = [0u8; ED_SIG_LEN];
    ed_bytes.copy_from_slice(&sig[..ED_SIG_LEN]);
    let ed_ok = EdVerifyingKey::from_bytes(&vk.ed)
        .and_then(|k| k.verify(&m, &EdSignature::from_bytes(ed_bytes)))
        .is_ok();

    // Parse failure counts as a failed check, but the Ed25519 check still runs.
    let ml_ok = match MlSignature::<MlDsa65>::from_bytes(&sig[ED_SIG_LEN..]) {
        Some(ml_sig) => ml_dsa::verify::<MlDsa65>(&vk.ml, &m, &ml_sig, &[]).is_ok(),
        None => false,
    };

    if ed_ok & ml_ok {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}

impl Signature {
    /// Parse a signature of exact length.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() != SIGNATURE_LEN {
            return Err(Error::InvalidLength);
        }
        let mut out = [0u8; SIGNATURE_LEN];
        out.copy_from_slice(bytes);
        Ok(Signature(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ED_SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];

    /// Python `cryptography`: Ed25519 signature over
    /// `LABEL ‖ 03 ‖ "ctx" ‖ "hello"` with the RFC 8032 test-1 key.
    const ED_SIG_REFERENCE: [u8; 64] = [
        0xdf, 0x1b, 0x37, 0xe5, 0xb1, 0x3b, 0xab, 0xf4, 0x58, 0xed, 0xc6, 0x0c, 0x3c, 0x08, 0xc6,
        0xd6, 0xca, 0x6d, 0x62, 0x57, 0x1f, 0x0f, 0xda, 0xae, 0x84, 0x62, 0x94, 0x5d, 0xea, 0xbc,
        0x60, 0x57, 0xb0, 0x71, 0xfe, 0xa5, 0x66, 0x98, 0x69, 0xf0, 0xe8, 0x83, 0x53, 0x63, 0xf8,
        0xa5, 0x59, 0xaf, 0x6a, 0xd1, 0x3e, 0x6b, 0x0d, 0xe1, 0x41, 0x65, 0x8d, 0xaf, 0x7d, 0x0f,
        0xf0, 0xa9, 0xdb, 0x0c,
    ];

    fn key() -> SigningKey {
        keygen_from_seeds(&ED_SEED, &[0x33; 32])
    }

    #[test]
    fn sizes_match_the_documented_layout() {
        assert_eq!(PUBLIC_KEY_LEN, 32 + 1952);
        assert_eq!(SIGNATURE_LEN, 64 + 3309);
        assert_eq!(key().verifying_key().to_bytes().len(), PUBLIC_KEY_LEN);
    }

    #[test]
    fn ed25519_component_matches_reference() {
        let sk = key();
        let sig = sign(&sk, b"ctx", b"hello").unwrap();
        assert_eq!(sig.0[..64], ED_SIG_REFERENCE);
    }

    #[test]
    fn round_trip_and_serialisation() {
        let sk = key();
        let vk = VerifyingKey::from_bytes(&sk.verifying_key().to_bytes()).unwrap();
        let sig = sign(&sk, b"", b"message").unwrap();
        assert!(verify(&vk, b"", b"message", &sig.0).is_ok());
        let parsed = Signature::from_bytes(&sig.0).unwrap();
        assert!(verify(&vk, b"", b"message", &parsed.0).is_ok());
    }

    #[test]
    fn wrong_message_or_context_fails() {
        let sk = key();
        let vk = sk.verifying_key();
        let sig = sign(&sk, b"ctx", b"hello").unwrap();
        assert!(verify(vk, b"ctx", b"hellO", &sig.0).is_err());
        assert!(verify(vk, b"ctx2", b"hello", &sig.0).is_err());
        // Splitting ctx and msg differently must not verify (length prefix).
        assert!(verify(vk, b"ct", b"xhello", &sig.0).is_err());
    }

    #[test]
    fn tampering_either_component_fails() {
        let sk = key();
        let vk = sk.verifying_key();
        let sig = sign(&sk, b"", b"m").unwrap();

        let mut bad_ed = sig.0;
        bad_ed[10] ^= 1;
        assert!(verify(vk, b"", b"m", &bad_ed).is_err());

        let mut bad_ml = sig.0;
        bad_ml[SIGNATURE_LEN - 5] ^= 1;
        assert!(verify(vk, b"", b"m", &bad_ml).is_err());
    }

    #[test]
    fn signature_from_another_key_fails() {
        let sk = key();
        let other = keygen_from_seeds(&[0x77; 32], &[0x88; 32]);
        let sig = sign(&other, b"", b"m").unwrap();
        assert!(verify(sk.verifying_key(), b"", b"m", &sig.0).is_err());
    }

    #[test]
    fn wrong_lengths_are_rejected() {
        let sk = key();
        let vk = sk.verifying_key();
        let sig = sign(&sk, b"", b"m").unwrap();
        assert_eq!(
            verify(vk, b"", b"m", &sig.0[..SIGNATURE_LEN - 1]).unwrap_err(),
            Error::InvalidLength
        );
        assert_eq!(
            VerifyingKey::from_bytes(&[0u8; PUBLIC_KEY_LEN - 1]).err(),
            Some(Error::InvalidLength)
        );
        let long_ctx = [0u8; CTX_MAX + 1];
        assert_eq!(sign(&sk, &long_ctx, b"m").err(), Some(Error::InvalidLength));
    }
}
