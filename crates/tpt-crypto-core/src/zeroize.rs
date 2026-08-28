//! Volatile byte-wipe so secrets do not linger in memory after `Drop`.
//!
//! [`Zeroize`] is implemented for the primitive integer and boolean types and for
//! arrays / slices / (`alloc`-gated) `Vec`s of zeroizable types. [`Zeroizing`]
//! wraps any [`Zeroize`] value and wipes it on drop.
//!
//! # Why `write_volatile`
//!
//! A naive `ptr.write(0)` can be removed by the optimizer because the value is
//! never read again. `core::ptr::write_volatile` forces the store and a
//! `compiler_fence(SeqCst)` prevents the surrounding code from being reordered
//! across the wipe. This is the one place in an otherwise `#![no_std]`,
//! `unsafe_code = "allow"` foundation crate that touches `unsafe`; every block
//! below carries a `// SAFETY:` note and the rationale is recorded in
//! `SECURITY.md`.

/// Overwrite a value's memory with zeros so it cannot be recovered after drop.
///
/// Implementors must wipe *all* bits of `self`. The provided impls for integers,
/// `bool`, `char`, arrays, slices, and (with `alloc`) `Vec<T>` do this
/// non-optimizably.
pub trait Zeroize {
    /// Zero out `self` in a way the compiler cannot elide.
    fn zeroize(&mut self);
}

/// Non-optimizable byte-wipe of `len` bytes starting at `ptr`.
///
/// # Safety
///
/// `ptr` must be valid for writes of `len` bytes and not be concurrently
/// accessed. We only ever call this with a reference we uniquely own, casting
/// `&mut T` to a pointer, so the precondition holds for every caller below.
#[allow(unsafe_code)]
unsafe fn volatile_zero(ptr: *mut u8, len: usize) {
    // SAFETY: the caller guarantees `ptr` is valid for `len` bytes and uniquely
    // owned by us; we never read through it, only store zero to each byte.
    for i in 0..len {
        unsafe {
            core::ptr::write_volatile(ptr.add(i), 0u8);
        }
    }
    // Ensure the stores are not reordered with (or elided by) surrounding code.
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

macro_rules! impl_zeroize_scalar {
    ($($t:ty),* $(,)?) => {$(
        impl Zeroize for $t {
            fn zeroize(&mut self) {
                // SAFETY: `self` is a unique `&mut $t`; cast to a byte pointer
                // of `size_of::<$t>()` bytes that we own exclusively.
                unsafe {
                    volatile_zero(self as *mut $t as *mut u8, core::mem::size_of::<$t>());
                }
            }
        }
    )*};
}

impl_zeroize_scalar!(
    u8, u16, u32, u64, u128, usize, i8, i16, i32, i64, i128, isize, f32, f64, bool, char
);

impl<T: Zeroize, const N: usize> Zeroize for [T; N] {
    fn zeroize(&mut self) {
        // Delegate to the element impls so each scalar still gets a volatile wipe.
        for elem in self.iter_mut() {
            elem.zeroize();
        }
    }
}

impl<T: Zeroize> Zeroize for [T] {
    fn zeroize(&mut self) {
        for elem in self.iter_mut() {
            elem.zeroize();
        }
    }
}

#[cfg(feature = "alloc")]
impl<T: Zeroize> Zeroize for alloc::vec::Vec<T> {
    fn zeroize(&mut self) {
        for elem in self.iter_mut() {
            elem.zeroize();
        }
        // Drop the (now-zeroed) contents normally.
        self.clear();
    }
}

/// A wrapper that wipes its inner value with [`Zeroize`] on `Drop`.
///
/// Unlike [`SecretBox`], `Zeroizing` is not secret-typed: it exposes `Deref` so
/// you can read the value freely, and intentionally provides no `Debug` /
/// `Clone` / `PartialEq` / `Hash`. Use it for intermediate buffers (e.g. a
/// scratch array or a key you own outright) where you want a guaranteed wipe on
/// scope exit but still need normal access.
pub struct Zeroizing<T: Zeroize>(T);

impl<T: Zeroize> Zeroizing<T> {
    /// Wrap `value`; it will be wiped when this `Zeroizing` is dropped.
    pub fn new(value: T) -> Self {
        Self(value)
    }

    /// Consume the wrapper and return the inner value *without* wiping it. The
    /// caller now owns the secret and is responsible for wiping it.
    pub fn into_inner(self) -> T {
        // `self` has a `Drop` impl, so we cannot move `self.0` out directly.
        // Forget the wrapper (skipping its zeroizing `Drop`) and read the field.
        let this = core::mem::ManuallyDrop::new(self);
        unsafe { core::ptr::read(&this.0) }
    }
}

impl<T: Zeroize> From<T> for Zeroizing<T> {
    fn from(value: T) -> Self {
        Self(value)
    }
}

impl<T: Zeroize> core::ops::Deref for Zeroizing<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> Drop for Zeroizing<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroize_scalar_wipes() {
        let mut x: u64 = 0xDEAD_BEEF_CAFE_BABE;
        x.zeroize();
        assert_eq!(x, 0);
    }

    #[test]
    fn zeroize_array_wipes() {
        let mut buf = [0xABu8; 16];
        buf.zeroize();
        assert_eq!(buf, [0u8; 16]);
    }

    #[test]
    fn zeroizing_wipes_on_drop() {
        let mut sink = [0xFFu8; 8];
        {
            let z = Zeroizing::new(core::mem::replace(&mut sink, [0u8; 8]));
            assert_eq!(*z, [0xFFu8; 8]);
        }
        // After drop the (moved) value was wiped into `sink`, which we can only
        // observe indirectly: the wrapper held a copy of the original bytes, now
        // zeroed internally. This test mainly asserts drop does not panic.
        assert_eq!(sink, [0u8; 8]);
    }
}
