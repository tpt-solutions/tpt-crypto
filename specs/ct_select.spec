spec ct_select

description:
  Constant-time selection between two values `a` and `b` under a boolean
  condition `cond`. The defining law is `result == (cond ? a : b)`, but it must
  hold with an execution trace that is independent of the secret condition.

inputs:
  cond : Choice      // 1-bit secret: 0 or 1
  a    : T           // secret-eligible value
  b    : T           // secret-eligible value

outputs:
  result : T

ensures:
  // functional correctness
  result == (if cond { a } else { b })
  // side-channel contract: the observable execution trace (branch pattern,
  // memory-access pattern, micro-op sequence) is independent of `cond`.
  execution_trace ⟂ cond

non_leaks:
  - no conditional branch whose target depends on `cond`
  - no memory access whose address depends on `cond`
  - no secret-dependent division, shift, or table index

verification:
  // discharged structurally: ct_select is implemented via full-width bitmask
  // (or a data-flow `cmov`/`csel` instruction) with no control-flow dependency
  // on `cond`. Re-check under `cargo +nightly miri test -p tpt-crypto-ct`.

evidence:
  cargo-test: -p tpt-crypto-ct --test proptest ct_select
  cargo-test: -p tpt-crypto-ct --features leakage --test leakage leakage_ct_select -- --test-threads=1
