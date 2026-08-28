//! Platform conditional-move primitives — **the only `unsafe` in the crate.**
//!
//! Every function here performs a branch-free conditional move on a `u64`
//! limb. Three implementations are provided, selected at compile time:
//!
//! - `x86_64`: a real `cmovne` via inline `asm!`.
//! - `aarch64`: a real `csel` via inline `asm!`.
//! - everything else: a portable bitwise-mask fallback (no `unsafe` needed,
//!   but still wrapped as `unsafe fn` for call-site uniformity).
//!
//! The public, safe API of the crate (`ct_select`, `cmov`, `cswap`, …) routes
//! integer moves through [`cmov_u64`]. The contract is the same on every
//! target: `cmov_u64(c, a, b)` sets `*a = if c != 0 { *b } else { *a }`, with
//! no branch on `c` and no secret-dependent memory access.

/// Conditionally move `*b` into `*a` when `cond != 0`.
///
/// # Safety
///
/// `*a` and `*b` must be valid, aligned, non-overlapping `u64` references.
/// `cond` may be any `u8`; only its zero/non-zero value is significant. No
/// memory other than the two referenced words is touched, and no flags are
/// relied upon by surrounding code after the call.
#[cfg(target_arch = "x86_64")]
#[inline]
pub(crate) unsafe fn cmov_u64(cond: u8, a: &mut u64, b: &u64) {
    // SAFETY: `a` and `b` are valid, aligned `u64` references passed by the
    // caller (see the function-level safety contract). The inline assembly
    // only reads `cond`/`b` and writes `a`; it performs no memory accesses
    // beyond `*a`/`*b`, touches no other registers, and leaves the stack
    // untouched. `cmovne` branches on the zero flag set by `test`, never on a
    // Rust-level branch, so the move is data-flow driven, not control-flow.
    unsafe {
        core::arch::asm!(
            "test {cond}, {cond}",
            "cmovne {a}, {b}",
            cond = in(reg) u64::from(cond),
            a = inout(reg) *a,
            b = in(reg) *b,
            options(nomem, nostack),
        );
    }
}

/// Conditionally move `*b` into `*a` when `cond != 0`.
///
/// # Safety
///
/// See [`cmov_u64`]. On AArch64 this uses the `csel` instruction, which
/// selects a register based on the condition flags and therefore cannot
/// introduce a data-dependent control-flow branch.
#[cfg(target_arch = "aarch64")]
#[inline]
pub(crate) unsafe fn cmov_u64(cond: u8, a: &mut u64, b: &u64) {
    // SAFETY: `a` and `b` are valid, aligned `u64` references. The assembly
    // compares `cond` against zero and uses `csel` to conditionally copy `b`
    // into `a`. No memory outside `*a`/`*b` is accessed and the stack is
    // untouched.
    unsafe {
        core::arch::asm!(
            "cmp {cond}, #0",
            "csel {a}, {b}, {a}, ne",
            cond = in(reg) u64::from(cond),
            a = inout(reg) *a,
            b = in(reg) *b,
            options(nomem, nostack),
        );
    }
}

/// Portable branch-free conditional move via a full-width bitmask.
///
/// # Safety
///
/// See [`cmov_u64`]. This fallback contains no actual `unsafe` operation but
/// is declared `unsafe fn` so that call sites can uniformly invoke it inside
/// an `unsafe` block regardless of target architecture.
#[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
#[inline]
pub(crate) unsafe fn cmov_u64(cond: u8, a: &mut u64, b: &u64) {
    let mask = u64::from(cond).wrapping_neg(); // 0 or 0xFFFF…FFFF
    let av = *a;
    let bv = *b;
    *a = av ^ (mask & (av ^ bv));
}

/// Exposed for documentation/introspection: which backend is compiled in.
#[inline]
#[must_use]
pub const fn backend_name() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        "x86_64 cmov"
    }
    #[cfg(target_arch = "aarch64")]
    {
        "aarch64 csel"
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        "portable bitmask"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmov_semantics() {
        // cond == 0 => a unchanged
        let mut a = 7u64;
        let b = 99u64;
        // SAFETY: stack locals, aligned, non-overlapping.
        unsafe { cmov_u64(0, &mut a, &b) };
        assert_eq!(a, 7);

        // cond != 0 => a takes b's value
        let mut a = 7u64;
        // SAFETY: stack locals, aligned, non-overlapping.
        unsafe { cmov_u64(1, &mut a, &b) };
        assert_eq!(a, 99);

        // any non-zero cond triggers the move
        let mut a = 7u64;
        // SAFETY: stack locals, aligned, non-overlapping.
        unsafe { cmov_u64(255, &mut a, &b) };
        assert_eq!(a, 99);
    }
}
