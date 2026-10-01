# ML-DSA KAT vectors — PROVENANCE

## `ml_dsa_acvp.txt` — NIST ACVP (FIPS 204), VERIFIED

Distilled from the official ACVP validation sets:

- Source: <https://github.com/usnistgov/ACVP-Server> `gen-val/json-files/`
  (`ML-DSA-keyGen-FIPS204` prompt+expectedResults, `ML-DSA-sigVer-FIPS204`
  prompt+expectedResults).
- License: NIST material, public domain.
- Distillation: the first 10 keyGen records per parameter set (`seed`/`pk`/`sk`)
  and every `external`-interface `pure` (non-prehash) sigVer record
  (pk/message/context/signature/expected verdict) — 30 kg + 45 sv records.
- Consumed by `tests/ml_dsa_kat.rs`: `keygen_from_seed` must reproduce the
  ACVP key bytes for all three parameter sets, and `verify` must accept
  exactly the ACVP-valid signatures.
- Cross-checked against the `dilithium-py` 1.4.0 reference implementation
  (its `key_derive` reproduces the ACVP key/sk bytes exactly).

**Implementation bugs these vectors exposed and fixed (2026-10-02):**

1. `keygen_from_seed` expanded the seed as `SHAKE256(ξ ‖ 1)` / `SHAKE256(ξ ‖ 2)`
   instead of FIPS 204's `(ρ, ρ′, K) ← H(ξ ‖ ⟨k⟩ ‖ ⟨ℓ⟩)`.
2. `expand_a` applied an extra NTT to the `ExpandA` XOF output, which is
   *already* the NTT-domain polynomial (FIPS 204 Algorithm 32). `mat_vec_mul`
   was adjusted to the matching Montgomery bookkeeping (coefficientwise
   product, one `to_mont` lift before `inv_ntt`).
3. The parameter table's `ω` (max hint count) was wrong for ML-DSA-65
   (120 → 55) and ML-DSA-87 (196 → 75); both pack_hint/unpack_hint agreed with
   each other, so round-trip tests passed while every cross-implementation
   signature verify failed.

Checksums (sha256, relative to `crates/tpt-crypto-sig/tests/kat/`):

| File | Sha256 |
| --- | --- |
| `ml_dsa_acvp.txt` | `98fa5330bfb01236c0daca78dddc931cdbc5400123c81563af9cf3f797c12239` |
