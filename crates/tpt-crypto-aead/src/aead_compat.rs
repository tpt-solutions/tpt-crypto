//! Optional `aead`-crate trait implementations (behind the `aead-trait` feature).
//!
//! This bridges our [`Aead`](../api/trait.Aead.html) implementations to the
//! ecosystem `aead` traits so that `tpt-crypto-aead` constructions can be used
//! wherever an `aead::Aead` is expected.

use crate::api::Aead as TptAead;
use crate::{
    Aes128Gcm, Aes256Gcm, ChaCha20Poly1305, Nonce, Tag,
};
use aead::{
    consts::{U0, U12, U16, U32},
    AeadCore, Buffer,
};
use tpt_crypto_core::Error;

macro_rules! impl_aead_compat {
    ($ty:ty, $key:ty) => {
        impl AeadCore for $ty {
            type KeySize = $key;
            type NonceSize = U12;
            type TagSize = U16;
            type CiphertextOverhead = U0;

            fn encrypt_in_place_detached(
                &self,
                nonce: &aead::Nonce<Self>,
                aad: &[u8],
                buffer: &mut impl Buffer,
            ) -> Result<aead::Tag<Self>, aead::Error> {
                let n = Nonce::<12>::from_slice(nonce.as_slice())
                    .map_err(|_| aead::Error::InvalidLength)?;
                let tag = TptAead::encrypt_in_place_detached(self, &n, aad, buffer.as_mut_slice());
                Ok(aead::Tag::from(tag.0))
            }

            fn decrypt_in_place_detached(
                &self,
                nonce: &aead::Nonce<Self>,
                aad: &[u8],
                buffer: &mut impl Buffer,
                tag: &aead::Tag<Self>,
            ) -> Result<(), aead::Error> {
                let n = Nonce::<12>::from_slice(nonce.as_slice())
                    .map_err(|_| aead::Error::InvalidLength)?;
                let t = Tag::<16>::from_slice(tag.as_slice()).map_err(|_| aead::Error::InvalidLength)?;
                TptAead::decrypt_in_place_detached(self, &n, aad, buffer.as_mut_slice(), &t)
                    .map_err(|_| aead::Error::Authentication)
            }
        }

        impl aead::Aead for $ty {}
    };
}

impl_aead_compat!(Aes128Gcm, U16);
impl_aead_compat!(Aes256Gcm, U32);
impl_aead_compat!(ChaCha20Poly1305, U32);

// Silence unused-import warnings for `Error` when only used inside the macro.
#[allow(unused_imports)]
use Error as _Error;
