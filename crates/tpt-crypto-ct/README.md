# tpt-crypto-ct

Constant-time arithmetic primitives for the `tpt-crypto` substrate.

This crate is the low-level, side-channel-resistant foundation of `tpt-crypto`.
It is `no_std`-first and provides:

- `Choice` — a 1-bit secret-carrying boolean with branch-free operators.
- `ct_eq` / `ct_ne` — constant-time equality for integer types and byte/limb
  slices.
- `ct_select` / `cmov` / `cswap` / `ct_select_slice` — branch-free selection
  and conditional moves.
- `arch` — the **only** `unsafe` module: platform `cmov`/`csel` with a
  portable bitmask fallback.
- `Masked<T>` — additive (XOR) and multiplicative masking for limbs.
- `blinding` — scalar and base-point blinding scaffolds.
- `ct_lookup` — branch-free table lookup for window methods.

## Guarantees

- No secret-dependent branches or memory accesses in the public API.
- The only `unsafe` is the platform `cmov`/`csel` in `arch` (documented with
  `// SAFETY:` comments). The workspace forbids `unsafe` everywhere else.
- Verified with `cargo xtask leakage` (dudect Welch t-test) and
  `cargo +nightly miri test -p tpt-crypto-ct`.

## License

Licensed under either of MIT or Apache-2.0 at your option.
