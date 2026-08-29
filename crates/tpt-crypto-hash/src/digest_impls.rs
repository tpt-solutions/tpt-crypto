//! [`digest`] v0.10 trait-compatibility impls, gated behind the `digest`
//! feature.
//!
//! Fixed-output hashes get [`digest::Digest`] (via `Update`, `FixedOutput`,
//! `FixedOutputReset`, `Reset`, `OutputSizeUser`, `HashMarker`); the XOFs get
//! [`digest::Update`] + [`digest::ExtendableOutput`].

use digest::consts::{U28, U32, U48, U64};
use digest::{
    ExtendableOutput, FixedOutput, FixedOutputReset, HashMarker, Output, OutputSizeUser, Reset,
    Update, XofReader,
};

use crate::traits::{Hasher, Xof};

macro_rules! impl_digest_fixed {
    ($ty:path, $size:ty, $out:expr) => {
        impl OutputSizeUser for $ty {
            type OutputSize = $size;
        }
        impl Update for $ty {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                Hasher::update(self, data);
            }
        }
        impl HashMarker for $ty {}
        impl FixedOutput for $ty {
            #[inline]
            fn finalize_into(self, out: &mut Output<Self>) {
                let d = Hasher::<$out>::finalize(self);
                out.copy_from_slice(&d);
            }
        }
        impl FixedOutputReset for $ty {
            #[inline]
            fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
                let d = Hasher::<$out>::finalize_reset(self);
                out.copy_from_slice(&d);
            }
        }
        impl Reset for $ty {
            #[inline]
            fn reset(&mut self) {
                Hasher::reset(self);
            }
        }
    };
}

impl_digest_fixed!(crate::sha2::Sha224, U28, 28);
impl_digest_fixed!(crate::sha2::Sha256, U32, 32);
impl_digest_fixed!(crate::sha2::Sha384, U48, 48);
impl_digest_fixed!(crate::sha2::Sha512, U64, 64);
impl_digest_fixed!(crate::sha3::Sha3_224, U28, 28);
impl_digest_fixed!(crate::sha3::Sha3_256, U32, 32);
impl_digest_fixed!(crate::sha3::Sha3_384, U48, 48);
impl_digest_fixed!(crate::sha3::Sha3_512, U64, 64);

/// A one-shot [`XofReader`] backed by a fully-buffered squeeze.
pub struct BufReader<const N: usize> {
    buf: [u8; N],
    pos: usize,
    len: usize,
}

impl<const N: usize> XofReader for BufReader<N> {
    fn read(&mut self, buffer: &mut [u8]) {
        for b in buffer.iter_mut() {
            *b = if self.pos < self.len {
                let v = self.buf[self.pos];
                self.pos += 1;
                v
            } else {
                0
            };
        }
    }
}

macro_rules! impl_digest_xof {
    ($ty:path) => {
        impl Update for $ty {
            #[inline]
            fn update(&mut self, data: &[u8]) {
                Xof::update(self, data);
            }
        }
        impl ExtendableOutput for $ty {
            type Reader = BufReader<8192>;
            #[inline]
            fn finalize_xof(self) -> Self::Reader {
                let mut buf = [0u8; 8192];
                Xof::finalize_xof(self, &mut buf);
                BufReader {
                    buf,
                    pos: 0,
                    len: 8192,
                }
            }
        }
    };
}

impl_digest_xof!(crate::sha3::Shake128);
impl_digest_xof!(crate::sha3::Shake256);

// --- BLAKE2b (fixed-output `digest::Digest`) ----------------------------

impl_digest_fixed!(crate::blake2b::Blake2b<32>, U32, 32);
impl_digest_fixed!(crate::blake2b::Blake2b<64>, U64, 64);

// --- BLAKE3 / KangarooTwelve (XOF `digest::ExtendableOutput`) -----------

impl_digest_xof!(crate::blake3::Blake3);
impl_digest_xof!(crate::k12::KangarooTwelve);

// --- HMAC -----------------------------------------------------------------
//
// `Hmac` intentionally does **not** implement `digest::Mac`: that trait's
// `new(key: &Key<Self>)` fixes the key length to `Self::KeySize`, whereas
// HMAC accepts arbitrary-length keys (longer keys are hashed internally).
// HMAC instead exposes its own constant-time [`crate::mac::Hmac::verify`]
// method, which is the security-relevant interface.
