# Benchmark budget — `tpt-crypto`

Record of per-primitive performance targets versus the established pure-Rust
reference implementations (`zeroize`, `subtle`, `dalek`, `pqcrypto`, `ring`).
Criterion benchmarks live under each crate's `benches/`; this file is the
human-readable contract that CI's `bench-smoke` keeps honest.

## tpt-crypto-core

| Benchmark          | Target                                   | Status  |
| ------------------ | ---------------------------------------- | ------- |
| `ct_select/u64`    | ≤ 1.2× `subtle::Choice::select_u64`      | pending |
| `ct_eq/slice/64`   | ≤ 1.2× `subtle::ConstantTimeEq`          | pending |
| `zeroize/array/64` | ≤ 1.1× `zeroize::Zeroize`                | pending |

The portable implementations in `core` are the correctness/constant-time
baseline; `tpt-crypto-ct` adds architecture-optimized (`core::arch` / inline
`asm!`) variants and is expected to meet or beat the `subtle` references.
