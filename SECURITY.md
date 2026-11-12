# Security Policy

## Supported Versions

| Version | Supported |
| ------- | --------- |
| 0.1.x   | ✅ (local, pre-publish) |

## Disclosure Policy

This project is developed locally (no GitHub remote yet). To report a
suspected vulnerability, open an issue in the future public repository or
contact the maintainers directly. Do **not** disclose side-channel or memory
issues publicly until a fix is available and coordinated.

## Threat Model

### In scope (what we defend)

- **Microarchitectural side channels** that leak secrets through *timing*,
  *control-flow*, or *memory-access* patterns: cache, branch-prediction, and
  similar observability of `executable trace`.
- The crate provides **constant-time-by-construction** primitives
  (`ct_eq`, `ct_select`, `cmov`, `cswap`, `ct_lookup`, masked arithmetic,
  blinding). The contract is encoded per-primitive in `specs/*.telos` and
  checked with the dudect-style Welch t-test (`cargo xtask leakage`) and Miri
  (`cargo +nightly miri test -p tpt-crypto-ct`).

### Out of scope (v1)

- **Physical attacks**: power analysis requiring lab equipment, EM emanation,
  glitch/fault injection, cold-boot.
- **Cryptanalytic breaks** of the underlying math (those live in the higher
  layers, not `-ct`).
- **Network/transport** and **log-injection** concerns.

## Constant-Time Guarantee

`tpt-crypto-ct` guarantees that, for every public function:

1. There is **no secret-dependent branch** — the program counter path does not
   depend on secret bits.
2. There is **no secret-dependent memory access** — addresses and indices do
   not depend on secret bits.

The *only* `unsafe` code in the entire workspace lives in `tpt-crypto-ct`'s
`arch` module (platform `cmov`/`csel`), and every `unsafe` block carries a
`// SAFETY:` comment. All other modules are ordinary safe Rust.

### The `unsafe` exception

The workspace sets `unsafe_code = "forbid"` via `[workspace.lints]`. This crate
is the single, documented exception: its `Cargo.toml` opts out of the
workspace lints and re-declares only `unsafe_op_in_unsafe_fn = "deny"`, so any
`unsafe` must be wrapped and justified. Rationale: a real machine `cmov` (or
`csel`) is the strongest portable guarantee that the selector cannot be
optimized into a branch by LLVM, and emitting one requires `unsafe` inline
assembly. The portable fallback is also wrapped as `unsafe` for uniform
call-sites. See `crates/tpt-crypto-ct/src/lib.rs` for the header note.

## Proof Boundary

No part of this workspace is machine-checked end to end. The checks that exist are:

- **Exhaustive bounded-domain checks** (`cargo xtask exhaustive`): reductions and
  constant-time helpers over their full small domains, and small-prime field arithmetic.
- **Binary-level constant-time checks** (`cargo xtask ct-asm`): branch scans of the
  compiled probe functions. Some probes are still report-only (see `todo.md` V3).
- **Statistical leakage tests** (`cargo xtask leakage`, Welch t-test): evidence
  against leakage, not a proof of its absence.
- **Known-answer and property tests**, mutation testing (`cargo mutants`) for test strength.

The formal claims stop at the Rust source and LLVM semantics. Anything below that
(the code generated for the target machine, microarchitecture, the compiler's
treatment of `write_volatile`, and cache or power side channels) is outside what
these checks establish. A `specs/*.spec` contract is evidence-linked, not a proof.
Kani, Cryptol/SAW, and Verus/hax proofs are not part of this workspace.
