spec secret_no_branch

description:
  Secret-carrying values (`Choice`, `ct_select`/`cmov` operands) must never be
  observable through a branch, memory-access pattern, or index derived from
  their bits. Operations on them have an execution trace independent of value.

inputs:
  s : Secret<T>   // value that must not influence control flow or addresses

ensures:
  // the operation is a pure data-flow function of `s`
  execution_trace ⟂ s

non_leaks:
  - no conditional branch whose target depends on `s`
  - no memory access whose address depends on `s`
  - no secret-dependent division, shift, or table index

verification:
  // the CT primitives obey their functional laws and show no detectable
  // timing dependence under the dudect-style Welch t-test harness.

evidence:
  cargo-test: -p tpt-crypto-ct --test proptest cmov_law
  cargo-test: -p tpt-crypto-ct --test proptest cswap_law
  cargo-test: -p tpt-crypto-ct --features leakage --test leakage leakage_ct_eq -- --test-threads=1
