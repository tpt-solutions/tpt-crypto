//! Optional `aead`-crate trait implementations (behind the `aead-trait` feature).
//!
//! This bridges our [`Aead`](../api/trait.Aead.html) implementations to the
//! ecosystem `aead` traits so that `tpt-crypto-aead` constructions can be used
//! wherever an `aead::Aead` is expected.

use crate::api::Aead as TptAead;
use crate::{Aes128Gcm, Aes256Gcm, ChaCha20Poly1305, Nonce, Tag};
use aead::{
    consts::{U12, U16, U32},
    AeadCore, AeadInOut, KeySizeUser,
};

macro_rules! impl_aead_compat {
    ($ty:ty, $key:ty) => {
        impl AeadCore for $ty {
            type NonceSize = U12;
            type TagSize = U16;
            const TAG_POSITION: aead::TagPosition = aead::TagPosition::Postfix;
        }

        impl KeySizeUser for $ty {
            type KeySize = $key;
        }

        impl AeadInOut for $ty {
            fn encrypt_inout_detached(
                &self,
                nonce: &aead::Nonce<Self>,
                associated_data: &[u8],
                mut buffer: aead::inout::InOutBuf<'_, '_, u8>,
            ) -> Result<aead::Tag<Self>, aead::Error> {
                let n = Nonce::<12>::from_slice(nonce.as_slice()).map_err(|_| aead::Error)?;
                let tag =
                    TptAead::encrypt_in_place_detached(self, &n, associated_data, buffer.get_out());
                Ok(aead::Tag::<Self>::from(tag.0))
            }

            fn decrypt_inout_detached(
                &self,
                nonce: &aead::Nonce<Self>,
                associated_data: &[u8],
                mut buffer: aead::inout::InOutBuf<'_, '_, u8>,
                tag: &aead::Tag<Self>,
            ) -> Result<(), aead::Error> {
                let n = Nonce::<12>::from_slice(nonce.as_slice()).map_err(|_| aead::Error)?;
                let t = Tag::<16>::from_slice(tag.as_slice()).map_err(|_| aead::Error)?;
                TptAead::decrypt_in_place_detached(self, &n, associated_data, buffer.get_out(), &t)
                    .map_err(|_| aead::Error)
            }
        }
    };
}

impl_aead_compat!(Aes128Gcm, U16);
impl_aead_compat!(Aes256Gcm, U32);
impl_aead_compat!(ChaCha20Poly1305, U32);
