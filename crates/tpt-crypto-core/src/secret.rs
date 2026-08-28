//! An owned secret that cannot be observed by accident.
//!
//! [`SecretBox`] owns a value of type `T` and zeroes its memory on `Drop`
//! (provided `T: Zeroize`). Crucially it implements **none** of the leaky
//! traits — no `Debug`, `Display`, `PartialEq`, `Eq`, `Hash`, `Default`,
//! `Clone`, `Copy`, `AsRef`, or `Borrow`. The only way to read the value is the
//! explicit [`SecretBox::expose_secret`] method, which returns a reference; this
//! makes "I am about to touch secret bits" a deliberate, greppable action rather
//! than an implicit conversion.

use crate::zeroize::{Zeroize, Zeroizing};
use core::ops::Deref;

/// An owned, zero-on-drop secret.
///
/// `SecretBox<T>` is the type-system gate that keeps secret material out of logs,
/// equality checks, and hash collections. Construct with [`SecretBox::new`] or
/// [`From`]; read with [`SecretBox::expose_secret`]; move the value out with
/// [`SecretBox::into_inner`] (the caller then owns the wipe responsibility — wrap
/// it in [`Zeroizing`] if you want automatic wiping).
///
/// `T` must implement [`Zeroize`]; the primitive arrays and integer types do, and
/// composite key types can implement it directly.
pub struct SecretBox<T: Zeroize> {
    inner: T,
}

impl<T: Zeroize> SecretBox<T> {
    /// Store `inner` as a secret; it will be wiped when this box is dropped.
    pub fn new(inner: T) -> Self {
        Self { inner }
    }

    /// Irreversibly read the secret. This is the *only* way to observe the value;
    /// it is intentionally named to stand out in code review. The returned
    /// reference must not be logged, compared, or hashed.
    pub fn expose_secret(&self) -> &T {
        &self.inner
    }

    /// Move the secret out of the box *without* wiping it. Ownership of the wipe
    /// now transfers to the caller — prefer returning it inside a [`Zeroizing`]
    /// when the value should still be wiped on scope exit.
    pub fn into_inner(self) -> T {
        // `self` has a `Drop` impl, so we cannot move `self.inner` out directly.
        // Forget the box (skipping its zeroizing `Drop`) and read the field.
        let this = core::mem::ManuallyDrop::new(self);
        unsafe { core::ptr::read(&this.inner) }
    }
}

impl<T: Zeroize> From<T> for SecretBox<T> {
    fn from(inner: T) -> Self {
        Self::new(inner)
    }
}

impl<T: Zeroize> Deref for SecretBox<T> {
    type Target = T;
    /// `Deref` intentionally returns the inner value so the box can be used as the
    /// secret directly in constant-time operations. Prefer [`expose_secret`] in new
    /// code for explicitness.
    fn deref(&self) -> &T {
        &self.inner
    }
}

impl<T: Zeroize> Drop for SecretBox<T> {
    fn drop(&mut self) {
        self.inner.zeroize();
    }
}

// `SecretBox` deliberately implements NO `Debug`, `Display`, `PartialEq`, `Eq`,
// `Hash`, `Default`, `Clone`, `Copy`, `AsRef`, or `Borrow`. The `trybuild`
// compile-fail tests in `tests/trybuild/` pin this contract.

/// Helper used by doctests/examples: wrap a value in [`Zeroizing`] after moving it
/// out of a [`SecretBox`], so the caller gets a self-wiping value.
///
/// This is just `Zeroizing::new(box.into_inner())` spelled out for readability.
pub fn into_zeroizing<T: Zeroize>(secret: SecretBox<T>) -> Zeroizing<T> {
    Zeroizing::new(secret.into_inner())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expose_round_trips_value() {
        let s = SecretBox::new([3u8, 1, 4, 1]);
        assert_eq!(s.expose_secret(), &[3u8, 1, 4, 1]);
    }

    #[test]
    fn deref_reads_value() {
        let s = SecretBox::new(0x1234u64);
        assert_eq!(*s, 0x1234u64);
    }
}
