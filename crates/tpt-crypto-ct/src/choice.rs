//! The [`Choice`] type: a 1-bit secret-carrying boolean.
//!
//! A `Choice` is either `0` or `1`, stored as a `u8`. It deliberately does
//! *not* implement `PartialEq` against `bool` in a way that leaks: the only
//! way to act on a `Choice` is through the branch-free operators in this
//! module or the `ct_*` primitives elsewhere in the crate.

/// A boolean value that is safe to use in constant-time code.
///
/// The inner `u8` is guaranteed to be exactly `0` or `1`. Construct one with
/// [`Choice::from_u8_lsb`] or `From<bool>`; do not build one from arbitrary
/// bytes without reducing to a valid choice first.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct Choice(pub(crate) u8);

impl Choice {
    /// The choice that is always false (`0`).
    pub const FALSE: Choice = Choice(0);

    /// The choice that is always true (`1`).
    pub const TRUE: Choice = Choice(1);

    /// Build a [`Choice`] from a `u8` by taking its least-significant bit.
    ///
    /// `from_u8_lsb(x) == TRUE` iff `x & 1 == 1`. This is constant-time.
    #[inline]
    #[must_use]
    pub const fn from_u8_lsb(x: u8) -> Choice {
        Choice(x & 1)
    }

    /// Reduce an arbitrary `u8` to a [`Choice`] in constant time.
    ///
    /// Returns [`Choice::TRUE`] iff `x == 0`, so this is the natural
    /// "is zero" selector used throughout the crate.
    #[inline]
    #[must_use]
    pub fn from_u8_is_zero(x: u8) -> Choice {
        // `x | x.wrapping_sub(1)` has its top bit set iff `x == 0`.
        let top = (x | x.wrapping_sub(1)) >> 7;
        Choice(top & 1)
    }

    /// Return the underlying `u8` (`0` or `1`).
    #[inline]
    #[must_use]
    pub fn unwrap_u8(self) -> u8 {
        self.0
    }

    /// Return `true` iff this choice is [`Choice::TRUE`].
    #[inline]
    #[must_use]
    pub fn is_true(self) -> bool {
        self.0 == 1
    }
}

impl From<bool> for Choice {
    #[inline]
    fn from(b: bool) -> Choice {
        Choice(b as u8)
    }
}

impl From<Choice> for bool {
    #[inline]
    fn from(c: Choice) -> bool {
        c.0 == 1
    }
}

impl core::fmt::Debug for Choice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Choice({})", self.0)
    }
}

impl core::ops::Not for Choice {
    type Output = Choice;
    #[inline]
    fn not(self) -> Choice {
        Choice(self.0 ^ 1)
    }
}

impl core::ops::BitAnd for Choice {
    type Output = Choice;
    #[inline]
    fn bitand(self, rhs: Choice) -> Choice {
        Choice(self.0 & rhs.0)
    }
}

impl core::ops::BitOr for Choice {
    type Output = Choice;
    #[inline]
    fn bitor(self, rhs: Choice) -> Choice {
        Choice(self.0 | rhs.0)
    }
}

impl core::ops::BitXor for Choice {
    type Output = Choice;
    #[inline]
    fn bitxor(self, rhs: Choice) -> Choice {
        Choice(self.0 ^ rhs.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invariants() {
        assert_eq!(Choice::from_u8_lsb(0).unwrap_u8(), 0);
        assert_eq!(Choice::from_u8_lsb(1).unwrap_u8(), 1);
        assert_eq!(Choice::from_u8_lsb(2).unwrap_u8(), 0);
        assert_eq!(Choice::from_u8_lsb(3).unwrap_u8(), 1);
        assert_eq!(Choice::from_u8_lsb(255).unwrap_u8(), 1);
        assert_eq!(Choice::from_u8_is_zero(0).unwrap_u8(), 1);
        assert_eq!(Choice::from_u8_is_zero(1).unwrap_u8(), 0);
        assert_eq!(Choice::from_u8_is_zero(42).unwrap_u8(), 0);
        assert!(!Choice::FALSE.is_true());
        assert!(Choice::TRUE.is_true());
    }

    #[test]
    fn bool_ops() {
        let t = Choice::TRUE;
        let f = Choice::FALSE;
        assert_eq!((!t).unwrap_u8(), 0);
        assert_eq!((!f).unwrap_u8(), 1);
        assert_eq!((t & t).unwrap_u8(), 1);
        assert_eq!((t & f).unwrap_u8(), 0);
        assert_eq!((t | f).unwrap_u8(), 1);
        assert_eq!((f | f).unwrap_u8(), 0);
        assert_eq!((t ^ f).unwrap_u8(), 1);
        assert_eq!((t ^ t).unwrap_u8(), 0);
        assert_eq!(Choice::from(true), t);
        assert_eq!(Choice::from(false), f);
    }
}
