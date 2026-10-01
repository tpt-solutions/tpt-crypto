# Changelog

All notable changes to `tpt-crypto-ct` are documented here.

## 0.1.0 — unreleased

- Initial constant-time substrate:
  - `Choice` (0/1 `u8`) with branch-free `Not`/`BitAnd`/`BitOr`/`BitXor` and
    `from_u8_lsb`.
  - `ct_eq` / `ct_ne` for `u8`, `u16`, `u32`, `u64`, `u128`, `usize`, and
    `&[u8]` / `&[Limb]` slices.
  - `ct_select` / `cmov` / `cswap` / `ct_select_slice` over the same integer
    set, with `u64` routed through `arch::cmov_u64`.
  - `arch` module: the only `unsafe` — `x86_64` `cmov`/`aarch64` `csel` via
    inline `asm!` plus a portable bitmask fallback; every block carries a
    `// SAFETY:` comment and is `#[cfg]`-gated.
  - `Masked<T>`: additive (XOR) sharing with `mask`/`unmask`/`remask` and
    `xor`/`and` (ISW-refreshed) over limbs; `MaskedMul<T>` multiplicative
    sharing with `mask`/`unblind`/`remask`/`mul`.
  - Blinding helpers: `blind_scalar` / `unblind_scalar` (odd-blinded) and
    `BasePointBlinding` scaffold.
  - `ct_lookup` branch-free table selection for window methods.
  - dudect-style Welch t-test leakage harness (`tests/leakage.rs`, run via
    `cargo xtask leakage`) covering `ct_select`, `ct_eq`, `ct_lookup`.
  - `proptest` coverage: `ct_select(c,a,b) == if c {a} else {b}`.
  - `specs/ct_select.spec`: `ensures: execution_trace ⟂ cond`.
