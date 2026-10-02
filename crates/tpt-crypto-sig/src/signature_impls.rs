//! Optional `signature`-crate trait compatibility (behind the `signature`
//! feature).
//!
//! Bridges the schemes in this crate to the ecosystem-standard
//! [`signature::Signer`] / [`signature::Verifier`] traits so they can be used
//! wherever those traits are expected (and vice versa):
//!
//! * **Ed25519** — pure Ed25519 (no context, no pre-hash); [`Signer`] /
//!   [`Verifier`] map 1:1 onto [`crate::ed25519::SigningKey::sign`] /
//!   [`crate::ed25519::VerifyingKey::verify`]. [`TryFrom<&[u8]>`] parses the
//!   64-byte `R ‖ S` encoding.
//! * **ECDSA P-256 / P-384** — [`Signer`] / [`Verifier`] hash the message with
//!   the curve's standard hash (SHA-256 / SHA-384) before signing; the hazmat
//!   [`PrehashSigner`] / [`PrehashVerifier`] map directly onto
//!   `sign_prehash` / `verify_prehash`. [`TryFrom<&[u8]>`] parses the fixed
//!   `r ‖ s` encoding (use `Signature::from_der` for ASN.1 DER).
//! * **ML-DSA-44 / -65 / -87** — signs with the *empty* context string
//!   (deterministic); context-carrying or hedged signing needs
//!   [`crate::ml_dsa::sign`] / [`crate::ml_dsa::sign_hedged`] directly.
//! * **BLS12-381** — [`Signer`] / [`Verifier`] use the default ciphersuite
//!   (POP, Ethereum-compatible); aggregation has no `signature`-crate
//!   equivalent and stays on [`crate::bls::aggregate*`].
//!
//! SLH-DSA is intentionally *not* bridged: its signature length depends on a
//! runtime-chosen parameter set, which [`SignatureEncoding`]'s statically
//! sized `Repr` cannot express — use [`crate::slh_dsa`] directly.

use signature::hazmat::{PrehashSigner, PrehashVerifier};
use signature::{Error as SigError, SignatureEncoding, Signer, Verifier};
use tpt_crypto_hash::Hasher;

/// Map a `tpt-crypto-core` error (Ed25519 / ECDSA) onto the ecosystem error.
/// The ecosystem type is opaque, so no information is lost.
fn sig_err_core(_: tpt_crypto_core::Error) -> SigError {
    SigError::new()
}

/// Map a crate-local error (ML-DSA / BLS) onto the ecosystem error.
fn sig_err_local(_: crate::Error) -> SigError {
    SigError::new()
}

// ── Ed25519 ──────────────────────────────────────────────────────────────────

impl From<crate::ed25519::Signature> for [u8; crate::ed25519::SIGNATURE_LEN] {
    fn from(sig: crate::ed25519::Signature) -> Self {
        sig.to_bytes()
    }
}

impl TryFrom<&[u8]> for crate::ed25519::Signature {
    type Error = SigError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        let arr: [u8; crate::ed25519::SIGNATURE_LEN] =
            bytes.try_into().map_err(|_| SigError::new())?;
        Ok(Self::from_bytes(arr))
    }
}

impl SignatureEncoding for crate::ed25519::Signature {
    type Repr = [u8; crate::ed25519::SIGNATURE_LEN];

    fn to_bytes(&self) -> Self::Repr {
        crate::ed25519::Signature::to_bytes(self)
    }
}

impl Signer<crate::ed25519::Signature> for crate::ed25519::SigningKey {
    fn try_sign(&self, msg: &[u8]) -> Result<crate::ed25519::Signature, SigError> {
        Ok(crate::ed25519::SigningKey::sign(self, msg))
    }
}

impl Verifier<crate::ed25519::Signature> for crate::ed25519::VerifyingKey {
    fn verify(&self, msg: &[u8], signature: &crate::ed25519::Signature) -> Result<(), SigError> {
        crate::ed25519::VerifyingKey::verify(self, msg, signature).map_err(sig_err_core)
    }
}

// ── ECDSA P-256 / P-384 ──────────────────────────────────────────────────────

/// Hazmat prehash surface for every curve instantiation.
impl<C: crate::ecdsa::EcdsaCurve> PrehashSigner<crate::ecdsa::Signature<C>>
    for crate::ecdsa::SigningKey<C>
{
    fn sign_prehash(&self, prehash: &[u8]) -> Result<crate::ecdsa::Signature<C>, SigError> {
        crate::ecdsa::SigningKey::<C>::sign_prehash(self, prehash).map_err(sig_err_core)
    }
}

impl<C: crate::ecdsa::EcdsaCurve> PrehashVerifier<crate::ecdsa::Signature<C>>
    for crate::ecdsa::VerifyingKey<C>
{
    fn verify_prehash(
        &self,
        prehash: &[u8],
        signature: &crate::ecdsa::Signature<C>,
    ) -> Result<(), SigError> {
        crate::ecdsa::VerifyingKey::<C>::verify_prehash(self, prehash, signature)
            .map_err(sig_err_core)
    }
}

macro_rules! impl_ecdsa_message_compat {
    ($curve:ty, $hash:ty) => {
        impl From<crate::ecdsa::Signature<$curve>>
            for [u8; 2 * <$curve as crate::ecdsa::EcdsaCurve>::N_BYTES]
        {
            fn from(sig: crate::ecdsa::Signature<$curve>) -> Self {
                let mut out = [0u8; 2 * <$curve as crate::ecdsa::EcdsaCurve>::N_BYTES];
                out.copy_from_slice(&sig.to_fixed());
                out
            }
        }

        impl TryFrom<&[u8]> for crate::ecdsa::Signature<$curve> {
            type Error = SigError;

            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                crate::ecdsa::Signature::<$curve>::from_fixed(bytes).map_err(sig_err_core)
            }
        }

        impl SignatureEncoding for crate::ecdsa::Signature<$curve> {
            type Repr = [u8; 2 * <$curve as crate::ecdsa::EcdsaCurve>::N_BYTES];

            fn to_bytes(&self) -> Self::Repr {
                let mut out = [0u8; 2 * <$curve as crate::ecdsa::EcdsaCurve>::N_BYTES];
                out.copy_from_slice(&self.to_fixed());
                out
            }
        }

        impl Signer<crate::ecdsa::Signature<$curve>> for crate::ecdsa::SigningKey<$curve> {
            fn try_sign(&self, msg: &[u8]) -> Result<crate::ecdsa::Signature<$curve>, SigError> {
                let mut h = <$hash>::new();
                h.update(msg);
                crate::ecdsa::SigningKey::<$curve>::sign_prehash(self, &h.finalize())
                    .map_err(sig_err_core)
            }
        }

        impl Verifier<crate::ecdsa::Signature<$curve>> for crate::ecdsa::VerifyingKey<$curve> {
            fn verify(
                &self,
                msg: &[u8],
                signature: &crate::ecdsa::Signature<$curve>,
            ) -> Result<(), SigError> {
                let mut h = <$hash>::new();
                h.update(msg);
                crate::ecdsa::VerifyingKey::<$curve>::verify_prehash(self, &h.finalize(), signature)
                    .map_err(sig_err_core)
            }
        }
    };
}

impl_ecdsa_message_compat!(crate::ecdsa::P256, tpt_crypto_hash::sha2::Sha256);
impl_ecdsa_message_compat!(crate::ecdsa::P384, tpt_crypto_hash::sha2::Sha384);

// ── ML-DSA ───────────────────────────────────────────────────────────────────

impl<P: crate::ml_dsa::MlDsaParams> Signer<crate::ml_dsa::Signature<P>>
    for crate::ml_dsa::SecretKey<P>
where
    P::Mat: crate::bytes::PolyArray,
    P::VecL: crate::bytes::PolyArray,
    P::VecK: crate::bytes::PolyArray,
{
    fn try_sign(&self, msg: &[u8]) -> Result<crate::ml_dsa::Signature<P>, SigError> {
        crate::ml_dsa::sign::<P>(self, msg, &[]).map_err(sig_err_local)
    }
}

impl<P: crate::ml_dsa::MlDsaParams> Verifier<crate::ml_dsa::Signature<P>>
    for crate::ml_dsa::PublicKey<P>
where
    P::Mat: crate::bytes::PolyArray,
    P::VecL: crate::bytes::PolyArray,
    P::VecK: crate::bytes::PolyArray,
{
    fn verify(&self, msg: &[u8], signature: &crate::ml_dsa::Signature<P>) -> Result<(), SigError> {
        crate::ml_dsa::verify::<P>(self, msg, signature, &[]).map_err(sig_err_local)
    }
}

macro_rules! impl_ml_dsa_encoding {
    ($set:ty) => {
        impl From<crate::ml_dsa::Signature<$set>>
            for [u8; <$set as crate::ml_dsa::MlDsaParams>::SIGNATUREBYTES]
        {
            fn from(sig: crate::ml_dsa::Signature<$set>) -> Self {
                let mut out = [0u8; <$set as crate::ml_dsa::MlDsaParams>::SIGNATUREBYTES];
                out.copy_from_slice(sig.as_bytes());
                out
            }
        }

        impl TryFrom<&[u8]> for crate::ml_dsa::Signature<$set> {
            type Error = SigError;

            fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
                crate::ml_dsa::Signature::<$set>::from_bytes(bytes).ok_or_else(SigError::new)
            }
        }

        impl SignatureEncoding for crate::ml_dsa::Signature<$set> {
            type Repr = [u8; <$set as crate::ml_dsa::MlDsaParams>::SIGNATUREBYTES];

            fn to_bytes(&self) -> Self::Repr {
                let mut out = [0u8; <$set as crate::ml_dsa::MlDsaParams>::SIGNATUREBYTES];
                out.copy_from_slice(self.as_bytes());
                out
            }
        }
    };
}

impl_ml_dsa_encoding!(crate::ml_dsa::MlDsa44);
impl_ml_dsa_encoding!(crate::ml_dsa::MlDsa65);
impl_ml_dsa_encoding!(crate::ml_dsa::MlDsa87);

// ── BLS12-381 (alloc) ────────────────────────────────────────────────────────

#[cfg(feature = "alloc")]
mod bls_compat {
    use super::{sig_err_local, SigError, SignatureEncoding, Signer, Verifier};
    use crate::bls;

    impl From<bls::Signature> for [u8; bls::SIG_LEN] {
        fn from(sig: bls::Signature) -> Self {
            sig.to_bytes()
        }
    }

    impl TryFrom<&[u8]> for bls::Signature {
        type Error = SigError;

        fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
            let arr: [u8; bls::SIG_LEN] = bytes.try_into().map_err(|_| SigError::new())?;
            bls::Signature::from_bytes(&arr).map_err(sig_err_local)
        }
    }

    impl SignatureEncoding for bls::Signature {
        type Repr = [u8; bls::SIG_LEN];

        fn to_bytes(&self) -> Self::Repr {
            bls::Signature::to_bytes(self)
        }
    }

    impl Signer<bls::Signature> for bls::SecretKey {
        fn try_sign(&self, msg: &[u8]) -> Result<bls::Signature, SigError> {
            Ok(bls::sign(self, msg))
        }
    }

    impl Verifier<bls::Signature> for bls::PublicKey {
        fn verify(&self, msg: &[u8], signature: &bls::Signature) -> Result<(), SigError> {
            bls::verify(self, msg, signature).map_err(sig_err_local)
        }
    }
}
