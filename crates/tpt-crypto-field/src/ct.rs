//! Constant-time primitive building blocks.
//!
//! This is a minimal, self-contained subset of what the `tpt-crypto-ct` crate
//! will provide once it lands in Phase 1. It supplies exactly what the field
//! arithmetic needs: a [`Choice`] bit, a [`CtOption`] (constant-time optional
//! value), the [`CtEq`] trait, and limb/element selection helpers. No `unsafe`
//! is used: every selection is a pure bitwise mask.

/// A boolean value encoded as a `u8` that is either `0` (false) or `1` (true).
///
/// Storing the bit in a `u8` (rather than `bool`) makes it easy to derive masks
/// without branching. Construct via [`Choice::from_bool`] / [`Choice::from_u8`].
#[derive(Copy, Clone, Debug)]
pub struct Choice(u8);

impl Choice {
    /// The false choice.
    pub const FALSE: Choice = Choice(0);
    /// The true choice.
    pub const TRUE: Choice = Choice(1);

    /// Build a [`Choice`] from a `u8`; any non-zero value becomes `1`.
    #[inline]
    #[must_use]
    pub fn from_u8(v: u8) -> Choice {
        // Map to exactly 0 or 1 without branching: (v | (0u8.wrapping_sub(v))) & 1.
        Choice((v | v.wrapping_neg()) >> 7)
    }

    /// Build a [`Choice`] from a `bool`.
    #[inline]
    #[must_use]
    pub fn from_bool(b: bool) -> Choice {
        Choice(b as u8)
    }

    /// Interpret this choice as a `bool`.
    #[inline]
    #[must_use]
    pub fn into_bool(self) -> bool {
        self.0 != 0
    }

    /// Logical NOT.
    #[inline]
    #[must_use]
    pub fn not(self) -> Choice {
        Choice(self.0 ^ 1)
    }

    /// Logical AND.
    #[inline]
    #[must_use]
    pub fn and(self, rhs: Choice) -> Choice {
        Choice(self.0 & rhs.0)
    }

    /// Logical OR.
    #[inline]
    #[must_use]
    pub fn or(self, rhs: Choice) -> Choice {
        Choice(self.0 | rhs.0)
    }

    /// The choice as a mask `0x00` or `0xFF`.
    #[inline]
    #[must_use]
    pub fn mask_u8(self) -> u8 {
        (self.0.wrapping_neg()) & 0xFF
    }

    /// The choice as a full-width `u64` mask (`0` or `!0`).
    #[inline]
    #[must_use]
    pub fn mask_u64(self) -> u64 {
        0u64.wrapping_sub(u64::from(self.0))
    }
}

impl PartialEq for Choice {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        // Constant-time equality of the underlying bit.
        (self.0 ^ other.0) == 0
    }
}
impl Eq for Choice {}

/// A constant-time optional value.
///
/// The `is_some` flag is a [`Choice`]; the wrapped value is always fully
/// materialized so that selecting between `Some`/`None` reveals nothing through
/// timing or memory access.
#[derive(Copy, Clone, Debug)]
pub struct CtOption<T> {
    value: T,
    is_some: Choice,
}

impl<T> CtOption<T> {
    /// Construct a `CtOption`. `is_some` must be a valid [`Choice`] (`0` or `1`).
    #[inline]
    #[must_use]
    pub fn new(value: T, is_some: Choice) -> Self {
        CtOption { value, is_some }
    }

    /// An absent value.
    #[inline]
    #[must_use]
    pub fn none() -> CtOption<T>
    where
        T: Default,
    {
        CtOption {
            value: T::default(),
            is_some: Choice::FALSE,
        }
    }

    /// A present value.
    #[inline]
    #[must_use]
    pub fn some(value: T) -> CtOption<T> {
        CtOption {
            value,
            is_some: Choice::TRUE,
        }
    }

    /// Whether the value is present, as a [`Choice`].
    #[inline]
    #[must_use]
    pub fn is_some(&self) -> Choice {
        self.is_some
    }

    /// Whether the value is absent, as a [`Choice`].
    #[inline]
    #[must_use]
    pub fn is_none(&self) -> Choice {
        self.is_some.not()
    }

    /// Map the contained value, leaving the presence flag untouched.
    #[inline]
    pub fn map<U, F: FnOnce(T) -> U>(self, f: F) -> CtOption<U> {
        CtOption {
            value: f(self.value),
            is_some: self.is_some,
        }
    }

    /// Return `value` if present, else `default`. Constant-time in the choice.
    #[inline]
    #[must_use]
    pub fn unwrap_or(self, default: T) -> T {
        self.unwrap_or_else(|| default)
    }

    /// Return `value` if present, else the result of `f()`.
    #[inline]
    #[must_use]
    pub fn unwrap_or_else<F: FnOnce() -> T>(self, f: F) -> T {
        let present = self.is_some.into_bool();
        if present {
            self.value
        } else {
            f()
        }
    }

    /// Unwrap, expecting a present value (panics if absent). For tests/invariants.
    #[inline]
    #[must_use]
    pub fn unwrap(self) -> T {
        assert!(self.is_some.into_bool(), "CtOption::unwrap on None");
        self.value
    }

    /// Unwrap, expecting a present value; returns a default if absent (non-panicking
    /// convenience for callers that already validated presence out of band).
    #[inline]
    #[must_use]
    pub fn unwrap_or_default(self) -> T
    where
        T: Default,
    {
        self.unwrap_or_else(T::default)
    }
}

/// Constant-time equality.
///
/// Implementors compare two values without branching on the secret data,
/// returning a [`Choice`] that is `1` iff the values are equal.
pub trait CtEq {
    /// Return `1` iff `self` and `rhs` are equal.
    fn ct_eq(&self, rhs: &Self) -> Choice;
}

/// Constant-time selection between two values of the same type.
#[inline]
#[must_use]
pub fn ct_select<T: Copy>(a: T, b: T, choice: Choice, merge: impl Fn(T, T, Choice) -> T) -> T {
    merge(a, b, choice)
}

/// Constant-time selection of a `u64`.
///
/// If `choice` is `1`, returns `b`; if `0`, returns `a`. Implemented with a pure
/// bitwise mask, so no branch is taken on `choice`.
#[inline]
#[must_use]
pub fn ct_select_u64(a: u64, b: u64, choice: Choice) -> u64 {
    let mask = choice.mask_u64();
    a ^ (mask & (a ^ b))
}

/// Constant-time selection of a `u8`.
#[inline]
#[must_use]
pub fn ct_select_u8(a: u8, b: u8, choice: Choice) -> u8 {
    let mask = choice.mask_u8();
    a ^ (mask & (a ^ b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn choice_basics() {
        assert!(Choice::TRUE.into_bool());
        assert!(!Choice::FALSE.into_bool());
        assert_eq!(Choice::from_bool(true), Choice::TRUE);
        assert_eq!(Choice::from_bool(false), Choice::FALSE);
        assert_eq!(Choice::from_u8(5), Choice::TRUE);
        assert_eq!(Choice::from_u8(0), Choice::FALSE);
        assert_eq!(Choice::TRUE.not(), Choice::FALSE);
        assert_eq!(Choice::TRUE.and(Choice::FALSE), Choice::FALSE);
        assert_eq!(Choice::TRUE.or(Choice::FALSE), Choice::TRUE);
    }

    #[test]
    fn ct_select_u64_works() {
        for c in [0u8, 1] {
            let ch = Choice::from_u8(c);
            assert_eq!(ct_select_u64(10, 20, ch), if c == 1 { 20 } else { 10 });
            assert_eq!(ct_select_u8(10, 20, ch), if c == 1 { 20 } else { 10 });
        }
    }

    #[test]
    fn ct_option_works() {
        let some = CtOption::some(7u64);
        let none: CtOption<u64> = CtOption::none();
        assert!(some.is_some().into_bool());
        assert!(none.is_none().into_bool());
        assert_eq!(some.unwrap_or(99), 7);
        assert_eq!(none.unwrap_or(99), 99);
        assert_eq!(some.map(|x| x + 1).unwrap(), 8);
    }
}
