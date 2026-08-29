//! Fixed-size byte and polynomial buffer traits.
//!
//! The ML-DSA / SLH-DSA key, secret-key, signature, and polynomial-vector types
//! are sized entirely at compile time, so they are represented as fixed `[u8; N]`
//! and `[Poly; M]` arrays. These two traits give those arrays a common,
//! dependency-free vocabulary (`from_slice` / `as_ref` / `zeroed`) without
//! requiring the unstable `generic_const_exprs` feature that a `[u8; P::SIG_LEN]`
//! associated type would need.

/// A fixed-size byte buffer.
///
/// Implemented for `[u8; N]`; this lets parameter sets name their key/signature
/// buffers as associated `type PublicKeyBytes = [u8; 1312]` and still offer a
/// uniform `from_slice` / `as_ref` API.
pub trait ByteArray: Sized {
    /// The length of the buffer in bytes.
    const LEN: usize;

    /// Parse a buffer from a slice, or `None` if the length is wrong.
    fn from_slice(bytes: &[u8]) -> Option<Self>;

    /// Borrow the buffer as a byte slice.
    #[inline]
    fn as_byte_slice(&self) -> &[u8] {
        // `[u8; N]` implements `AsRef<[u8]>`; re-use it so callers never depend
        // on the concrete array type.
        <Self as AsRef<[u8]>>::as_ref(self)
    }
}

impl<const N: usize> ByteArray for [u8; N] {
    const LEN: usize = N;

    #[inline]
    fn from_slice(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok()
    }
}

/// A fixed-size vector of [`Poly`] coefficients.
///
/// Implemented for `[Poly; N]`. The NTT matrix and the `s1` / `s2` / `t` vectors
/// are all stored this way, so they can be allocated on the stack and iterated
/// without `alloc`.
pub trait PolyArray: Sized {
    /// A zero-filled vector of the right length.
    fn zeroed() -> Self;

    /// Borrow the vector as a polynomial slice.
    #[inline]
    fn as_poly_slice(&self) -> &[crate::poly::Poly] {
        <Self as AsRef<[crate::poly::Poly]>>::as_ref(self)
    }

    /// Mutably borrow the vector as a polynomial slice.
    #[inline]
    fn as_poly_slice_mut(&mut self) -> &mut [crate::poly::Poly] {
        <Self as AsRef<[crate::poly::Poly]>>::as_ref(self)
    }
}

impl<const N: usize> PolyArray for [crate::poly::Poly; N] {
    fn zeroed() -> Self {
        [crate::poly::Poly::ZERO; N]
    }
}
