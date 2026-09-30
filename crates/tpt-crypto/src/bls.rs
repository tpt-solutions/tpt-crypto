//! BLS12-381 aggregatable signatures (for consensus / `tpt-sync`).
//!
//! Thin re-export of [`tpt_crypto_sig::bls`] under the `spec.txt §4` API:
//!
//! ```
//! use tpt_crypto::bls::{self, SecretKey};
//!
//! # let sk1 = SecretKey::keygen(&[7u8; 32]).unwrap();
//! # let sk2 = SecretKey::keygen(&[11u8; 32]).unwrap();
//! # let pk1 = sk1.public_key();
//! # let pk2 = sk2.public_key();
//! let message = b"beacon block root";
//! let sig1 = bls::sign(&sk1, message);
//! let sig2 = bls::sign(&sk2, message);
//! let agg_sig = bls::aggregate(&[sig1, sig2]).unwrap();
//! bls::verify_aggregate(&[pk1, pk2], message, &agg_sig).unwrap();
//! # assert!(bls::verify(&pk1, message, &sig1).is_ok());
//! ```
//!
//! The bare functions use the `…_POP_` ciphersuite (draft-irtf-cfrg-bls-
//! signature-04, minimal-pubkey-size); [`Ciphersuite`] selects Basic / Aug
//! variants, and [`proof_of_possession`] implements key-registration proofs.

pub use tpt_crypto_sig::bls::{
    aggregate, aggregate_verify, aggregate_verify_with, proof_of_possession, sign, sign_with,
    verify, verify_aggregate, verify_aggregate_with, verify_proof_of_possession, verify_with,
    Ciphersuite, PublicKey, SecretKey, Signature, DEFAULT_SUITE, PK_LEN, SIG_LEN, SK_LEN,
};
