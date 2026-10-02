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


# SLH-DSA KAT vectors — PROVENANCE

## `slh_dsa_acvp.txt` — NIST ACVP (FIPS 205), VERIFIED

Distilled from the official ACVP validation sets:

- Source: <https://github.com/usnistgov/ACVP-Server> `gen-val/json-files/`
  (`SLH-DSA-keyGen-FIPS205`, `SLH-DSA-sigGen-FIPS205`,
  `SLH-DSA-sigVer-FIPS205` — prompt + expectedResults).
- License: NIST material, public domain.
- Distillation: 2 keyGen records per parameter set (`skSeed`/`skPrf`/`pkSeed`
  → `sk`/`pk`), 2 deterministic + 1 hedged `external`/`pure` sigGen records
  per set, and 3 sigVer records per set (2 valid + 1 invalid) — 24 kg +
  24 sg-det + 12 sg-hedged + 36 sv = 96 records over all 12 parameter sets.
- Consumed by `tests/slh_dsa_kat.rs`: `keygen_from_seeds` must reproduce the
  ACVP key bytes, deterministic `sign` must reproduce the ACVP signature
  bytes byte-for-byte, `verify` must accept the hedged reference signatures
  and exactly the ACVP-valid sigVer signatures.

**Implementation bugs these vectors exposed and fixed (2026-10-02):**

1. `wots_pk_gen`/`wots_sign`/`wots_pk_from_sig` lost the keypair field when
   re-typing the ADRS (`with_type` zeroes the trailing 12 bytes), so every
   chain after leaf 0 hashed with keypair = 0.
2. `fors_node`/`fors_sign` lost the FORS keypair the same way — both the
   PRF address and the F-hash address (the reference keeps the keypair
   across FORS type changes and only overwrites height/index).
3. The hypertree signature offset used `1 + fors_len` bytes instead of
   `n + fors_len` (the leading `1` in the length formula is `n` bytes of R),
   overwriting the last 15 bytes of the FORS auth path.
4. `split_digest` masked the tree index with `1 << (h − h_m)` which
   overflows for SLH-DSA-256f (68 − 4 = 64 bits) — saturate to `u64::MAX`.

Checksums (sha256, relative to `crates/tpt-crypto-sig/tests/kat/`):

| File | Sha256 |
| --- | --- |
| `slh_dsa_acvp.txt` | `45b80cd23576067266b845e40dc71a9e501e97af418e3e068a20e1c7638a2362` |


# Wycheproof verify vectors — PROVENANCE

## `wycheproof.txt` — Project Wycheproof (testvectors_v1), VERIFIED

Cross-implementation *verify* vectors for Ed25519 and ECDSA P-256 / P-384
(verify-only: the harness drives `VerifyingKey` with attacker-controlled
public keys, messages, and signatures).

- Source: <https://github.com/google/wycheproof> `testvectors_v1/`
  (`ecdsa_secp256r1_sha256_test.json`, `ecdsa_secp384r1_sha384_test.json`,
  `ed25519_test.json`).
- License: Apache-2.0 (Google LLC).
- Original sha256 (files downloaded 2026-10-03, since removed — re-download
  and re-run `distill_wycheproof.py` to regenerate):
  - `ecdsa_secp256r1_sha256_test.json`
    `182db4f3e230f6f9fa9f800d2a614dede30284b8e8438bbfe1171905402e9332`
  - `ecdsa_secp384r1_sha384_test.json`
    `8a5b3ae1760975143414811f13588c24d951d9d8c904195087ba327591dfe9cc`
  - `ed25519_test.json`
    `752d2ea7d7c6cf4736381b6cbacb61f8182b126ab7cd9b058f00c50084975536`
- Distillation: every test record (pk / msg / sig / expected verdict /
  flags) as flat `key = value` blocks — 484 + 504 + 151 = 1139 records.
  For ECDSA, `high_s = 1` marks signatures with `s > n/2` (exact integer
  comparison against the curve order — a top-byte heuristic is wrong on the
  corpus' `0x00…`/`0x7f…` edge encodings). Regenerate with
  `python distill_wycheproof.py` (needs the three source JSONs in this
  directory).
- Policy (`tests/wycheproof.rs`): accept iff `result = valid` **and**
  `high_s = 0`. The crate canonicalises to low-`S` on sign and rejects
  high-`S` on verify; Wycheproof testvectors_v1 marks high-`S` records
  plain `valid` (the `SignatureMalleability` flag only appears in newer
  generators), so those 384 records are expected to *fail* here. Any
  parse failure counts as a rejection.

**Implementation bugs these vectors exposed and fixed (2026-10-03):**

1. Ed25519 `VerifyingKey::verify` accepted signatures whose `R` decodes to
   the identity point (Wycheproof ed25519 tcId 151): the group equation
   `[8]S·B == 8R + 8[k]A` holds when the forger sets `R = O` and `S = k`,
   so the RFC-literal cofactored check alone cannot reject it. The `-sig`
   wrapper (and `verify_batch`) now reject identity-`R` explicitly —
   matching Wycheproof's `InvalidEncoding` verdict and `verify_strict`
   semantics in `ed25519-dalek`.

Checksums (sha256, relative to `crates/tpt-crypto-sig/tests/kat/`):

| File | Sha256 |
| --- | --- |
| `wycheproof.txt` | `df10efc615edf64c54549c0383aacf4668c587b36b43b00d5032802f3109e61a` |
