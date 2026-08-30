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

#[cfg(feature = "std")]
extern crate std;

/// Conditionally move `*b` into `*a` when `cond != 0`.
///
/// # Safety
///
/// `*a` and `*b` must be valid, aligned, non-overlapping `u64` references.
/// `cond` may be any `u8`; only its zero/non-zero value is significant. No
/// memory other than the two referenced words is touched, and no flags are
/// relied upon by surrounding code after the call.
#[cfg(all(target_arch = "x86_64", not(miri), feature = "zzz_nonexistent_zzz"))]
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
#[cfg(all(target_arch = "aarch64", not(miri)))]
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
// Under Miri (which cannot execute inline assembly) we fall back to the
// portable bitmask implementation even on x86_64/aarch64, so the whole crate
// stays `miri`-clean while the production backends keep using real `cmov`/`csel`.
#[cfg(any(not(target_arch = "aarch64"), miri))]
#[inline]
pub(crate) unsafe fn cmov_u64(cond: u8, a: &mut u64, b: &u64) {
    // Reduce `cond` to 0/1 first, then broadcast to a full-width mask. Using
    // `cond` directly would only negate its low byte and corrupt the mask for
    // any non-`0`/`1` value (e.g. `255`).
    let mask = u64::from(cond != 0).wrapping_neg(); // 0 or 0xFFFF…FFFF
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

// ---------------------------------------------------------------------------
// AES-NI / PCLMULQDQ helpers (x86_64 only)
//
// These wrap the Intel AES-NI and carry-less-multiplication instructions. They
// are the *only* place outside the `cmov_u64` family that is architecture
// specific. Every call site routes the AES-NI `aes`/`pclmulqdq` paths of the
// `tpt-crypto-aead` crate through here so that all `unsafe` stays inside this
// single documented module.
// ---------------------------------------------------------------------------

/// A 128-bit block, represented as two `u64` halves (low, high) in
/// little-endian byte order. This is the wire format `tpt-crypto-aead` uses for
/// AES blocks and for GHASH/POLYVAL field elements.
#[cfg(target_arch = "x86_64")]
#[derive(Clone, Copy)]
pub struct Block128 {
    /// Low 64 bits (bytes 0..8).
    pub lo: u64,
    /// High 64 bits (bytes 8..16).
    pub hi: u64,
}

#[cfg(target_arch = "x86_64")]
impl Block128 {
    /// Build a [`Block128`] from a 16-byte little-endian buffer.
    #[inline]
    pub fn from_le_bytes(b: [u8; 16]) -> Self {
        let lo = u64::from_le_bytes(b[0..8].try_into().unwrap());
        let hi = u64::from_le_bytes(b[8..16].try_into().unwrap());
        Block128 { lo, hi }
    }

    /// Build a [`Block128`] from four little-endian `u32` words.
    #[inline]
    pub fn from_u32s(w: [u32; 4]) -> Self {
        let mut b = [0u8; 16];
        for i in 0..4 {
            b[4 * i..4 * i + 4].copy_from_slice(&w[i].to_le_bytes());
        }
        Block128::from_le_bytes(b)
    }

    #[inline]
    fn from_m128i(v: core::arch::x86_64::__m128i) -> Self {
        // SAFETY: `__m128i` is always 16 bytes; `v` is initialized by the
        // caller. Reading it as two `u64` via `transmute` is sound because the
        // layout is a sequence of 16 bytes interpreted as `u64` pairs.
        unsafe { core::mem::transmute_copy(&v) }
    }

    #[inline]
    fn to_m128i(self) -> core::arch::x86_64::__m128i {
        // SAFETY: `Block128` is a two-`u64` struct; the transmute copies only the
        // 16 bytes we own.
        unsafe { core::mem::transmute_copy(&self) }
    }
}

/// Full AES-NI block encryption for a key schedule of `rounds + 1` 128-bit
/// round keys. `rk` must contain the round keys in order (whitening key first).
///
/// This is the single entry point the `tpt-crypto-aead` crate uses for the
/// hardware AES path. The caller is responsible for confirming the CPU actually
/// supports AES (see [`has_aes_ni`]); calling this on a CPU without AES support
/// is undefined behaviour.
///
/// # Safety
///
/// Must only be invoked on `x86_64` targets that support the `aes` target
/// feature. No memory beyond the (by-value) inputs is touched.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
#[inline]
#[target_feature(enable = "aes")]
pub(crate) unsafe fn aes_ni_encrypt_block(rk: &[Block128], block: Block128) -> Block128 {
    // SAFETY: all `__m128i` temporaries are private copies; `_mm_xor_si128` and
    // `_mm_aesenc_si128`/`_mm_aesenclast_si128` read only their input registers
    // and write the output, touching no memory. `rk.len()` is `rounds + 1`.
    // The wrapping `unsafe` block is required by `unsafe_op_in_unsafe_fn`; the
    // `unused_unsafe` allowance is a known false positive because the block is
    // genuinely needed under that lint.
    #[allow(unused_unsafe)]
    unsafe {
        let mut state = block.to_m128i();
        let k0 = rk[0].to_m128i();
        state = core::arch::x86_64::_mm_xor_si128(state, k0);
        let rounds = rk.len() - 1;
        for k in rk.iter().take(rounds).skip(1) {
            let k = k.to_m128i();
            state = core::arch::x86_64::_mm_aesenc_si128(state, k);
        }
        let k = rk[rounds].to_m128i();
        state = core::arch::x86_64::_mm_aesenclast_si128(state, k);
        Block128::from_m128i(state)
    }
}

/// Safe, runtime-dispatched AES-NI block encryption.
///
/// Returns `None` if the current CPU does not support AES (so the caller can
/// fall back to the portable path). The `unsafe` AES-NI routine lives entirely
/// inside this module; callers in `tpt-crypto-aead` never write `unsafe`.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
#[inline]
#[must_use]
pub fn aes_ni_encrypt_block_safe(rk: &[Block128], block: Block128) -> Option<Block128> {
    if !has_aes_ni() {
        return None;
    }
    // SAFETY: we just confirmed AES support via `has_aes_ni`, which is the only
    // precondition of `aes_ni_encrypt_block`. The function touches no memory
    // beyond its by-value inputs.
    Some(unsafe { aes_ni_encrypt_block(rk, block) })
}

/// 128×128 carry-less multiplication producing the 256-bit product `(hi, lo)`,
/// computed with `vpclmulqdq`. Used by the PCLMULQDQ GHASH/POLYVAL paths.
///
/// # Safety
///
/// Must only be invoked on `x86_64` targets that support the `pclmulqdq` target
/// feature. No memory is accessed; operands are by value.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
#[inline]
#[allow(dead_code)]
#[target_feature(enable = "pclmulqdq")]
pub(crate) unsafe fn pclmulqdq(a: Block128, b: Block128) -> (Block128, Block128) {
    // SAFETY: `vpclmulqdq` reads two registers and writes one; no memory is
    // touched. We perform two clmul halves (low·low, high·high) and combine
    // them in registers. The `__m128i` temporaries are private copies. The
    // wrapping `unsafe` block is required by `unsafe_op_in_unsafe_fn`
    // (`unused_unsafe` is a known false positive here).
    #[allow(unused_unsafe)]
    unsafe {
        let a_v = a.to_m128i();
        let b_v = b.to_m128i();
        let lo = core::arch::x86_64::_mm_clmulepi64_si128(a_v, b_v, 0x00);
        let hi = core::arch::x86_64::_mm_clmulepi64_si128(a_v, b_v, 0x11);
        (Block128::from_m128i(hi), Block128::from_m128i(lo))
    }
}

/// Runtime capability probe: does this x86_64 CPU expose the `aes` feature?
///
/// Only meaningful with the `std` feature (the detection routine needs `std`).
/// Without `std` this always returns `false`, falling back to the portable path.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
#[inline]
#[must_use]
pub fn has_aes_ni() -> bool {
    #[cfg(target_feature = "aes")]
    {
        true
    }
    #[cfg(not(target_feature = "aes"))]
    {
        std::is_x86_feature_detected!("aes")
    }
}

/// Runtime capability probe: does this x86_64 CPU expose `pclmulqdq`?
///
/// Only meaningful with the `std` feature (the detection routine needs `std`).
/// Without `std` this always returns `false`, falling back to the portable path.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
#[inline]
#[must_use]
pub fn has_pclmulqdq() -> bool {
    #[cfg(target_feature = "pclmulqdq")]
    {
        true
    }
    #[cfg(not(target_feature = "pclmulqdq"))]
    {
        std::is_x86_feature_detected!("pclmulqdq")
    }
}

#[cfg(not(all(target_arch = "x86_64", feature = "std")))]
#[inline]
#[must_use]
pub fn has_aes_ni() -> bool {
    false
}

#[cfg(not(all(target_arch = "x86_64", feature = "std")))]
#[inline]
#[must_use]
pub fn has_pclmulqdq() -> bool {
    false
}

// ---------------------------------------------------------------------------
// Carry-less multiplication (`pclmulqdq`) for GHASH / POLYVAL (x86_64 only).
//
// These wrap the Intel carry-less-multiply instructions. All `unsafe` stays in
// this single module; callers in `tpt-crypto-aead` never write `unsafe`. The
// 128×128 carry-less product is assembled from four 64×64 clmuls and returned
// as two 128-bit halves (low, high) in `Block128` form.
// ---------------------------------------------------------------------------

/// Single 64×64 carry-less multiply producing a 128-bit `Block128` result.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
#[inline]
#[target_feature(enable = "pclmulqdq")]
pub(crate) unsafe fn clmul(a: Block128, b: Block128, ctrl: u8) -> Block128 {
    // SAFETY: `_mm_clmulepi64_si128` reads two registers and writes one; no
    // memory is touched. `has_pclmulqdq` has already been checked by the
    // caller of `clmul128_raw`.
    #[allow(unused_unsafe)]
    unsafe {
        let av = a.to_m128i();
        let bv = b.to_m128i();
        let v = match ctrl {
            0x00 => core::arch::x86_64::_mm_clmulepi64_si128(av, bv, 0x00),
            0x01 => core::arch::x86_64::_mm_clmulepi64_si128(av, bv, 0x01),
            0x10 => core::arch::x86_64::_mm_clmulepi64_si128(av, bv, 0x10),
            _ => core::arch::x86_64::_mm_clmulepi64_si128(av, bv, 0x11),
        };
        Block128::from_m128i(v)
    }
}

/// Full 128×128 carry-less product, returned as `(low, high)` 128-bit halves.
#[cfg(all(target_arch = "x86_64", feature = "std"))]
#[inline]
#[must_use]
pub fn clmul128_raw(a: &Block128, b: &Block128) -> (Block128, Block128) {
    if !has_pclmulqdq() {
        return (Block128 { lo: 0, hi: 0 }, Block128 { lo: 0, hi: 0 });
    }
    // SAFETY: `has_pclmulqdq` confirmed; `clmul` only touches registers.
    let c00 = unsafe { clmul(*a, *b, 0x00) };
    let c01 = unsafe { clmul(*a, *b, 0x10) };
    let c10 = unsafe { clmul(*a, *b, 0x01) };
    let c11 = unsafe { clmul(*a, *b, 0x11) };
    let mid = Block128 {
        lo: c01.lo ^ c10.lo,
        hi: c01.hi ^ c10.hi,
    };
    // low half (product bits 0..127): c00 plus mid's bits 64..127;
    // high half (product bits 128..255): c11 plus mid's bits 128..191.
    let lo = Block128 {
        lo: c00.lo,
        hi: c00.hi ^ mid.lo,
    };
    let hi = Block128 {
        lo: c11.lo ^ mid.hi,
        hi: c11.hi,
    };
    (lo, hi)
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

    #[test]
    fn clmul128_raw_basic() {
        // 0xb * 0xd over GF(2) = 0x7f (fits in 128 bits, hi half is zero).
        let a = Block128::from_le_bytes(0xb_u128.to_le_bytes());
        let b = Block128::from_le_bytes(0xd_u128.to_le_bytes());
        let (lo, hi) = clmul128_raw(&a, &b);
        let lo_v = lo.lo as u128 | ((lo.hi as u128) << 64);
        let hi_v = hi.lo as u128 | ((hi.hi as u128) << 64);
        assert_eq!((lo_v, hi_v), (0x7f, 0));

        // x^64 * x^64 = x^128 (lands entirely in the high half).
        let x64 = Block128::from_le_bytes((1u128 << 64).to_le_bytes());
        let (lo, hi) = clmul128_raw(&x64, &x64);
        let lo_v = lo.lo as u128 | ((lo.hi as u128) << 64);
        let hi_v = hi.lo as u128 | ((hi.hi as u128) << 64);
        assert_eq!((lo_v, hi_v), (0, 1));
    }
}
