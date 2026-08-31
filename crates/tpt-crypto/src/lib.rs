//! # tpt-crypto
//!
//! Feature-gated facade crate for the tpt-crypto workspace. Enable the
//! `full` feature to pull in every primitive; pick individual features
//! (`classical`, `pq`, `bls`, `zk`, `mpc`) for a smaller footprint.
//!
//! ## Feature matrix
//!
//! | Feature | Re-exports |
//! |---------|-----------|
//! | `classical` | `hash`, `aead`, `field`, `curve`, `sig` |
//! | `pq` | `kem`, `sig` |
//! | `bls` | `bls` (BLS12-381 signatures, stub until `-curve` lands it) |
//! | `zk` | `bulletproofs` |
//! | `mpc` | `mpc` |
//! | `full` | all of the above |
//! | `std` / `alloc` | propagated to every sub-crate |

#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

#[cfg(feature = "classical")]
#[doc = "Hash functions: BLAKE2b, BLAKE3, SHA-2, SHA-3, K12, HKDF, HMAC."]
#[cfg_attr(docsrs, doc(cfg(feature = "classical")))]
pub mod hash {
    pub use tpt_crypto_hash::*;
}

#[cfg(feature = "classical")]
#[doc = "Authenticated encryption: AES-GCM, AES-GCM-SIV, ChaCha20-Poly1305."]
#[cfg_attr(docsrs, doc(cfg(feature = "classical")))]
pub mod aead {
    pub use tpt_crypto_aead::*;
}

#[cfg(feature = "classical")]
#[doc = "Prime field arithmetic: P-256, P-384, BLS12-381 base, Ed25519 scalar."]
#[cfg_attr(docsrs, doc(cfg(feature = "classical")))]
pub mod field {
    pub use tpt_crypto_field::*;
}

#[cfg(feature = "classical")]
#[doc = "Elliptic curve operations: Ed25519, X25519, P-256, P-384."]
#[cfg_attr(docsrs, doc(cfg(feature = "classical")))]
pub mod curve {
    pub use tpt_crypto_curve::*;
}

#[cfg(any(feature = "classical", feature = "pq"))]
#[doc = "Digital signatures: ML-DSA, Ed25519, ECDSA, SLH-DSA."]
#[cfg_attr(docsrs, doc(cfg(any(feature = "classical", feature = "pq"))))]
pub mod sig {
    pub use tpt_crypto_sig::*;
}

#[cfg(feature = "pq")]
#[doc = "Post-quantum key encapsulation: ML-KEM, FrodoKEM, McEliece."]
#[cfg_attr(docsrs, doc(cfg(feature = "pq")))]
pub mod kem {
    pub use tpt_crypto_kem::*;
}

#[cfg(feature = "bls")]
#[doc = "BLS12-381 signatures (stub until `-curve` lands pairing support)."]
#[cfg_attr(docsrs, doc(cfg(feature = "bls")))]
pub mod bls;

#[cfg(feature = "zk")]
#[doc = "Zero-knowledge proofs: Bulletproofs range proofs, Pedersen commitments."]
#[cfg_attr(docsrs, doc(cfg(feature = "zk")))]
pub mod bulletproofs {
    pub use tpt_crypto_zk::*;
}

#[cfg(feature = "mpc")]
#[doc = "Multi-party computation: Beaver triples, OT extension, secret sharing."]
#[cfg_attr(docsrs, doc(cfg(feature = "mpc")))]
pub mod mpc {
    pub use tpt_crypto_mpc::*;
}

#[doc = "Constant-time selection and comparison utilities."]
pub mod ct;

#[doc = "Common imports for constant-time, `no_std` workflows."]
pub mod prelude;
