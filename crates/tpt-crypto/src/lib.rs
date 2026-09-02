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
//! | `classical` | `hash`, `aead`, `field`, `curve`, `sig`, `ml_dsa` |
//! | `pq` | `kem`, `ml_kem` (with `alloc`), `sig`, `ml_dsa` |
//! | `bls` | `bls` (BLS12-381 signatures, stub until `-curve` lands it) |
//! | `zk` | `bulletproofs` |
//! | `mpc` | `mpc` |
//! | `full` | all of the above |
//! | `std` / `alloc` | propagated to every sub-crate |
//!
//! ## `spec.txt` §4 surface
//!
//! The [`ml_kem`], [`ml_dsa`], [`bulletproofs`], [`bls`] and [`ct`] modules,
//! together with [`prelude`], expose the exact names used in the `spec.txt`
//! §4 target API so downstream code can be written verbatim against it.

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

#[cfg(all(feature = "pq", feature = "alloc"))]
#[doc = "ML-KEM (FIPS 203), `spec.txt` §4 surface: `keygen` / `encapsulate` / `decapsulate` + `MlKem512/768/1024`."]
#[cfg_attr(docsrs, doc(cfg(all(feature = "pq", feature = "alloc"))))]
pub mod ml_kem {
    pub use tpt_crypto_kem::ml_kem::*;
}

#[cfg(any(feature = "classical", feature = "pq"))]
#[doc = "ML-DSA (FIPS 204), `spec.txt` §4 surface: `keygen` / `sign` / `verify` + `MlDsa44/65/87`."]
#[cfg_attr(docsrs, doc(cfg(any(feature = "classical", feature = "pq"))))]
pub mod ml_dsa {
    pub use tpt_crypto_sig::ml_dsa::*;
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
