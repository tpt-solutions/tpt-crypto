spec field_mul

description:
  Multiplication in a prime field `GF(p)`. For every pair of inputs `a, b` that are
  canonical field elements (`0 <= a < p` and `0 <= b < p`), the result is the
  unique field element congruent to `a * b` modulo the prime `p`. The implementation
  uses Montgomery multiplication (CIOS) internally but is observed here through its
  external arithmetic contract.

inputs:
   a : FieldElement<P>   // canonical: 0 <= a < p
   b : FieldElement<P>   // canonical: 0 <= b < p

outputs:
   result : FieldElement<P>

assumes:
   a and b are canonical (already reduced modulo p)

ensures:
   // functional correctness: result is the field product.
   result == (a * b) mod p
   // canonicality: the output is kept in [0, p).
   0 <= result < p
   // constant-time contract: the execution trace (branch pattern, memory-access
   // pattern) is independent of the secret values of `a` and `b`.
   execution_trace ⟂ (a, b)

non_leaks:
   - no conditional branch whose target depends on secret bits of `a` or `b`
   - no memory access whose address depends on secret bits of `a` or `b`
   - reduction is branch-free (no conditional-subtract on a secret value)

verification:
   // discharged by cross-check against the schoolbook `tptmath::mul_mod`
   // big-rational reference over hand-computed and Wycheproof edge-case vectors
   // in `tests/kat/field_mul.json` (see `tests/kat/PROVENANCE.md`).
   // spot-checked exhaustively for the smallest fields under `proptest`.

evidence:
  cargo-test: -p tpt-crypto-field --test field_tests prime_fields_cross_check
  cargo-test: -p tpt-crypto-field --test field_props p256_base_props
  cargo-test: -p tpt-crypto-field --test mul_check mul_basics
