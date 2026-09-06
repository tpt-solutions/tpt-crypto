//! # tpt-crypto-kem — constant-time key encapsulation mechanisms
//!
//! This crate implements **ML-KEM** (FIPS 203 / Module-Lattice KEM) as the
//! primary primitive, built on a hand-rolled, constant-time polynomial
//! arithmetic core ([`poly`]): `R_q = Z_q[X]/(X^n + 1)` with `q = 3329`,
//! `n = 256`, compile-time NTT / inverse-NTT / base-multiplication, and
//! Montgomery reduction. All operations are data-flow branch-free so that
//! timing does not depend on secret polynomials.
//!
//! The high-level API lives in [`ml_kem`]:
//!
//! ```
//! use tpt_crypto_kem::ml_kem::{keygen, encapsulate, decapsulate, MlKem768};
//! # use tpt_crypto_core::CryptoRng;
//! # struct DemoRng(u64);
//! # impl CryptoRng for DemoRng {
//! #     fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), tpt_crypto_core::Error> {
//! #         for b in dst { self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1); *b = (self.0 >> 33) as u8; }
//! #         Ok(())
//! #     }
//! # }
//! # let mut rng = DemoRng(42);
//! let (pk, sk) = keygen::<MlKem768>(&mut rng);
//! let (ss, ct) = encapsulate::<MlKem768>(&pk, &mut rng);
//! let ss2 = decapsulate::<MlKem768>(&sk, &ct.bytes).unwrap();
//! assert_eq!(ss, ss2);
//! ```
//!
//! Parameter sets [`MlKem512`], [`MlKem768`], and [`MlKem1024`] are provided.
//!
//! FrodoKEM (`frodo` feature) and Classic McEliece (`mceliece` feature) are
//! gated, larger constructions reserved for a later pass; their modules expose
//! the API surface but currently return [`tpt_crypto_core::Error::Unsupported`].

#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

pub mod encode;
#[cfg(feature = "alloc")]
pub mod ml_kem;
pub mod params;
#[cfg(feature = "alloc")]
pub mod pke;
pub mod poly;
pub mod sampler;

#[cfg(feature = "frodo")]
pub mod frodo;

#[cfg(feature = "mceliece")]
pub mod mceliece;

pub use params::{MlKem1024, MlKem512, MlKem768};
