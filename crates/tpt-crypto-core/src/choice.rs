//! A boolean whose internal representation is `0x00` for false and `0x01` for
//! true.
//!
//! The encoding is self-consistent for branch-free arithmetic: `is_true` checks
//! `self.0 == 0x01`, and `ct_select` turns `0x01` into a `0xff` mask via
//! `wrapping_sub`. The concrete comparison/selection algorithms live in
//! `tpt-crypto-ct`; this module only provides the type and its boolean algebra.

/// A constant-time boolean: `0x00` for false, `0x01` for true.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct Choice(pub(crate) u8);

impl Choice {
    /// The `false` choice.
    pub const FALSE: Choice = Choice(0x00);
    /// The `true` choice.
    pub const TRUE: Choice = Choice(0x01);

    /// Build a [`Choice`] from the low bit of `v` (`1` ⇒ true, `0` ⇒ false).
    #[inline]
    #[must_use]
    pub const fn from_u8_lsb(v: u8) -> Choice {
        Choice(v & 1)
    }

    /// Build a [`Choice`] from a `bool`.
    #[inline]
    #[must_use]
    pub const fn from_bool(b: bool) -> Choice {
        Choice(if b { 0x01 } else { 0x00 })
    }

    /// Build a [`Choice`] from a `u8` convention: `0` ⇒ false, any nonzero ⇒ true.
    #[inline]
    #[must_use]
    pub const fn from_u8(v: u8) -> Choice {
        Choice((v != 0) as u8)
    }

    /// Build a [`Choice`] from the integer mask convention `0 == false`,
    /// non-zero == `true`.
    #[inline]
    #[must_use]
    pub const fn from_mask(mask: u8) -> Choice {
        // (mask - 1) & !mask sets bit 7 iff mask == 0. Shift to select 0xff/0x00.
        let is_zero = ((mask.wrapping_sub(1)) & !mask) >> 7;
        Choice(!is_zero)
    }

    /// Constant-time equality of two [`Choice`] values.
    #[inline]
    #[must_use]
    pub fn ct_eq(self, other: Choice) -> Choice {
        let mask = ((self.0 ^ other.0).wrapping_sub(1)) & !(self.0 ^ other.0);
        Choice(!((mask >> 7) ^ 0x01))
    }

    /// Return `true` if this is the `true` choice.
    #[inline]
    #[must_use]
    pub const fn is_true(self) -> bool {
        self.0 == 0x01
    }

    /// Return the underlying byte (`0x00` for false, `0x01` for true).
    #[inline]
    #[must_use]
    pub const fn to_u8(self) -> u8 {
        self.0
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

impl core::ops::Not for Choice {
    type Output = Choice;
    #[inline]
    fn not(self) -> Choice {
        Choice(self.0 ^ 1)
    }
}
