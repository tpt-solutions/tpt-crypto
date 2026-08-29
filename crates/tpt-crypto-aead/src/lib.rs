//! # tpt-crypto-aead — constant-time AEAD substrate
//!
//! A pure-Rust, `no_std`-first collection of authenticated encryption
//! constructions, all implemented to be constant-time by construction:
//!
//! - **AES-GCM** (NIST SP 800-38D) — [`Aes128Gcm`]/[`Aes256Gcm`]. The portable
//!   AES path is a **table-free, constant-time** S-box (algebraic GF(2⁸)
//!   inversion), and on `x86_64` the dispatcher routes through hardware AES-NI
//!   via [`tpt_crypto_ct::arch`].
//! - **GHASH** over GF(2¹²⁸) — portable carry-less multiply plus a `pclmulqdq`
//!   path routed through `tpt-crypto-ct`.
//! - **ChaCha20 + Poly1305** (RFC 8439) and **XChaCha20-Poly1305**
//!   (draft-irtf-cfrg-xchacha).
//! - **AES-GCM-SIV** (RFC 8452) — nonce-misuse resistant, built on POLYVAL.
//! - **`CtrDrbg`** (SP 800-90A) implementing [`DrbgCore`].
//!
//! The shared API is the [`Aead`] trait with in-place and detached-tag
//! operations, plus constant-time [`Tag::ct_eq`] comparison and the
//! [`Nonce`]/[`Tag`] newtypes. The optional `aead-trait` feature provides
//! implementations of the `aead` crate traits.
//!
//! All tag verification is performed in constant time; on decryption failure the
//! buffer is left unchanged (no plaintext is exposed).

#![no_std]
#![forbid(unsafe_code)]
#![cfg_attr(docsrs, feature(doc_cfg))]
#![warn(missing_docs)]

#[cfg(feature = "alloc")]
extern crate alloc;

mod aes;
mod api;
mod chacha;
mod ctr_drbg;
mod gcm;
mod gcm_siv;

pub use api::{Aead, BlockCipher, Nonce, Tag};

pub use aes::Aes;
pub use chacha::{poly1305_mac, ChaCha20, ChaCha20Poly1305, Poly1305, XChaCha20Poly1305};
pub use ctr_drbg::CtrDrbg;
pub use gcm::{Aes128Gcm, Aes256Gcm};
pub use gcm_siv::{Aes128GcmSiv, Aes256GcmSiv};

#[cfg(feature = "aead-trait")]
mod aead_compat;
