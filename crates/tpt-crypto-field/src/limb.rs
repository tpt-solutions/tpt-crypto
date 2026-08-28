//! Limb type and limb-vector primitives.
//!
//! In the full layout, vectorized limb arithmetic lives in `tpt-math-linalg-fixed`.
//! Until that crate lands, [`Limb`] is a `u64` and the handful of limb-vector
//! helpers required by the Montgomery code are provided here. All operations are
//! implemented with portable wrapping arithmetic and explicit carry/borrow so the
//! code is identical on every target (no secret-dependent branches).

/// A single 64-bit field limb (little-endian digit of the modulus).
pub type Limb = u64;

/// Add with carry: returns `(sum, carry)` where `carry ∈ {0, 1}`.
#[inline]
pub const fn adc(a: Limb, b: Limb, carry: Limb) -> (Limb, Limb) {
    let (s, c1) = a.overflowing_add(b);
    let (s2, c2) = s.overflowing_add(carry);
    (s2, (c1 | c2) as Limb)
}

/// Subtract with borrow: returns `(diff, borrow)` where `borrow ∈ {0, 1}`.
#[inline]
pub const fn sbb(a: Limb, b: Limb, borrow: Limb) -> (Limb, Limb) {
    let (d, b1) = a.overflowing_sub(b);
    let (d2, b2) = d.overflowing_sub(borrow);
    (d2, (b1 | b2) as Limb)
}

/// Multiply two limbs into a 128-bit product, returned as `(lo, hi)`.
#[inline]
pub const fn widening_mul(a: Limb, b: Limb) -> (Limb, Limb) {
    let p = (a as u128) * (b as u128);
    (p as Limb, (p >> 64) as Limb)
}

/// Constant-time selection between two limbs. If `choice == 1` returns `b`,
/// otherwise `a`. Pure bitwise mask — no branch on the secret.
#[inline]
pub const fn select(a: Limb, b: Limb, choice: u8) -> Limb {
    let mask = (choice as Limb).wrapping_neg();
    a ^ (mask & (a ^ b))
}
