//! AEAD API surface: the [`Aead`] trait and the [`Nonce`] / [`Tag`] newtypes.
//!
//! Tag comparison is always performed in constant time through [`Tag::ct_eq`],
//! which uses [`tpt_crypto_ct::ct_eq_bytes`]. There is deliberately no
//! `PartialEq`/`Eq` on [`Tag`]: comparing tags with `==` would be a timing leak.

use tpt_crypto_core::{Error, Result};
use tpt_crypto_ct::ct_eq_bytes;

/// A nonce, fixed to `N` bytes for a given cipher.
///
/// Construct with [`Nonce::new`] (fixed array) or [`Nonce::from_slice`] (checked
/// length). The inner bytes are never interpreted as anything other than opaque
/// nonce material.
pub struct Nonce<const N: usize>(pub [u8; N]);

impl<const N: usize> Nonce<N> {
    /// Build a nonce from a fixed-size byte array.
    pub const fn new(bytes: [u8; N]) -> Self {
        Nonce(bytes)
    }

    /// Parse a nonce from a slice, rejecting wrong-length input.
    pub fn from_slice(s: &[u8]) -> Result<Self> {
        if s.len() != N {
            return Err(Error::InvalidLength);
        }
        let mut b = [0u8; N];
        b.copy_from_slice(s);
        Ok(Nonce(b))
    }

    /// View the nonce as bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
}

/// An authentication tag, fixed to `N` bytes.
///
/// Comparison must go through [`Tag::ct_eq`]; the type omits `PartialEq` so the
/// leaky `==` operator cannot be applied accidentally.
pub struct Tag<const N: usize>(pub [u8; N]);

impl<const N: usize> Tag<N> {
    /// Build a tag from a fixed-size byte array.
    pub const fn new(bytes: [u8; N]) -> Self {
        Tag(bytes)
    }

    /// Parse a tag from a slice, rejecting wrong-length input.
    pub fn from_slice(s: &[u8]) -> Result<Self> {
        if s.len() != N {
            return Err(Error::InvalidLength);
        }
        let mut b = [0u8; N];
        b.copy_from_slice(s);
        Ok(Tag(b))
    }

    /// View the tag as bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }

    /// Constant-time equality test against another tag.
    ///
    /// Returns `true` iff the two tags are byte-equal; the comparison time is
    /// independent of the tag contents.
    pub fn ct_eq(&self, other: &Tag<N>) -> bool {
        bool::from(ct_eq_bytes(&self.0, &other.0))
    }
}

/// A 128-bit block cipher usable as the basis for a counter-mode AEAD.
pub trait BlockCipher {
    /// Block size in bytes (always 16 for the ciphers in this crate).
    const BLOCK_LEN: usize = 16;

    /// Encrypt a single 16-byte block.
    fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16];
}

/// The AEAD interface implemented by every construction in this crate.
///
/// Two flavours are provided:
/// - *detached*: [`encrypt_in_place_detached`] / [`decrypt_in_place_detached`]
///   keep the ciphertext and tag in separate buffers, and the decrypt path
///   verifies the tag in constant time *before* touching the plaintext;
/// - *combined*: [`encrypt`]/[`decrypt`] (gated behind the `alloc` feature)
///   append the tag to the ciphertext.
///
/// Nonce and tag lengths are part of the type-level contract
/// (`NONCE_LEN` / `TAG_LEN`), so a mismatched nonce or truncated tag is a
/// compile-time error where the newtypes are used directly.
pub trait Aead {
    /// Nonce length in bytes.
    const NONCE_LEN: usize;
    /// Authentication tag length in bytes.
    const TAG_LEN: usize;

    /// Encrypt `buf` in place, returning the detached authentication tag.
    ///
    /// `buf` is overwritten with the ciphertext (same length as the plaintext).
    fn encrypt_in_place_detached(
        &self,
        nonce: &Nonce<{ Self::NONCE_LEN }>,
        aad: &[u8],
        buf: &mut [u8],
    ) -> Tag<{ Self::TAG_LEN }>;

    /// Decrypt `buf` in place, verifying `tag` in constant time.
    ///
    /// The tag is checked *before* `buf` is modified, so on failure `buf`
    /// retains the original ciphertext and no plaintext is exposed. On success
    /// `buf` holds the plaintext.
    fn decrypt_in_place_detached(
        &self,
        nonce: &Nonce<{ Self::NONCE_LEN }>,
        aad: &[u8],
        buf: &mut [u8],
        tag: &Tag<{ Self::TAG_LEN }>,
    ) -> Result<()>;

    /// Encrypt `plaintext`, returning `ciphertext || tag`.
    #[cfg(feature = "alloc")]
    fn encrypt(
        &self,
        nonce: &Nonce<{ Self::NONCE_LEN }>,
        aad: &[u8],
        plaintext: &[u8],
    ) -> alloc::vec::Vec<u8> {
        let mut buf = alloc::vec::Vec::with_capacity(plaintext.len() + Self::TAG_LEN);
        buf.extend_from_slice(plaintext);
        let tag = self.encrypt_in_place_detached(nonce, aad, &mut buf);
        buf.extend_from_slice(&tag.0);
        buf
    }

    /// Decrypt `ciphertext` (which must end with the tag), returning the plaintext.
    #[cfg(feature = "alloc")]
    fn decrypt(
        &self,
        nonce: &Nonce<{ Self::NONCE_LEN }>,
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<alloc::vec::Vec<u8>> {
        if ciphertext.len() < Self::TAG_LEN {
            return Err(Error::InvalidLength);
        }
        let (ct, tag_bytes) = ciphertext.split_at(ciphertext.len() - Self::TAG_LEN);
        let mut buf = alloc::vec::Vec::from(ct);
        let tag = Tag::<Self::TAG_LEN>::from_slice(tag_bytes)?;
        self.decrypt_in_place_detached(nonce, aad, &mut buf, &tag)?;
        Ok(buf)
    }
}
