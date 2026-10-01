# specs/

Contracts for `tpt-crypto` primitives, checked by `cargo xtask verify`.

Each `*.spec` file states a primitive's contract (`description`, `inputs`,
`ensures`, `non_leaks`) and an `evidence:` block binding it to executable
checks:

```
evidence:
  cargo-test: -p tpt-crypto-hash --test kat sha2_      # runs `cargo test <args>`
  pending: reason the contract has no tests yet         # reported, not failed
```

`xtask verify` fails a spec if its header is malformed, it has no `ensures:` /
`evidence:`, any cited test fails, or a filter matches zero tests (stale name).
`pending:` entries are listed; `cargo xtask verify --strict` makes them fail.

What this can and cannot show: functional claims are backed by KATs and property
tests; constant-time claims (`execution_trace ⟂ secret`) are backed by structural
review plus the dudect-style Welch t-test harness (`cargo xtask leakage`), which
is statistical evidence, not a proof.
