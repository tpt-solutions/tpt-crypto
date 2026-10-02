# KAT Provenance — `tpt-crypto-hash`

Generated: 2026-08-29

The known-answer vectors for this crate are embedded as hex literals in
[`../kat.rs`](../kat.rs) (small, fixed set) rather than as a JSON corpus. Each
group is transcribed verbatim from the published source below and cross-checked
against an independent reference implementation while wiring up the tests.

| Test fn | Primitive(s) | Source | Notes |
|---------|--------------|--------|-------|
| `sha2_empty`, `sha2_abc` | SHA-224/256/384/512, SHA-512/256, SHA-512/224 | FIPS 180-4 / NIST CAVP | `""` and `"abc"` digests |
| `sha3_empty`, `sha3_abc` | SHA3-224/256/384/512 | FIPS 202 / NIST CAVP | `""` and `"abc"` digests |
| `shake_empty`, `shake_abc_64` | SHAKE128/256 | FIPS 202 / NIST CAVP | 32- and 64-byte squeezes |
| `blake2b_kat` | BLAKE2b (unkeyed + keyed) | RFC 7693 §B and the BLAKE2 reference test suite | keyed vectors verified against a from-spec Python reference |
| `blake3_kat` | BLAKE3 (unkeyed + keyed) | official BLAKE3 `test_vectors.json` (input lengths 0 and 3) | verified against a from-spec Python reference |
| `hmac_kat` | HMAC-SHA-256 | RFC 4231 test case 1 | plus one self-consistency vector |
| `hkdf_kat` | HKDF-SHA-256 | RFC 5869 test case 1 | 42-byte OKM |
| `cshake_kat` | cSHAKE128 | NIST SP 800-185 Sample #1 (`S = "Email Signature"`) | |
| `kmac_kat` | KMAC128 | NIST SP 800-185 Sample #1 (`K = 0x40..0x5F`, `L = 256`) | standard (non-XOF) KMAC |
| `k12_kat` | KangarooTwelve | RFC 9861 | `(M="", C="")` and `(M=0xFF, C=ptn(41))` |

## Pending

- NIST SP 800-90A CAVP HMAC-DRBG (SHA-256) known-answer vectors — `tests/drbg.rs`
  currently pins behavioural properties only.
- NIST CAVP long-message / Monte-Carlo vectors for SHA-2 / SHA-3.
- RFC 7693 keyed BLAKE2b full vector file; additional BLAKE3 / K12 lengths.


# HMAC-DRBG KAT vectors — PROVENANCE

## `hmac_drbg_acvp.txt` — NIST ACVP (SP 800-90A), VERIFIED

- Source: <https://github.com/usnistgov/ACVP-Server>
  `gen-val/json-files/hmacDRBG-SP800-90Ar1` (prompt + expectedResults),
  downloaded 2026-10-03. NIST material, public domain.
- Distillation: the four SHA2-256 groups (tgIds 5/6 prediction-resistance,
  27/28 non-PR), first 4 tests of each — 16 records (`entropy`/`nonce`/
  `pers` + the ordered `opN_(reseed|generate)` list + `returned`).
- ACVP flow semantics (pinned empirically against the expected results —
  see `tests/drbg_kat.rs`): PR groups reseed with `(op.entropy, op.ai)`
  before every Generate and the Generate call itself takes NO additional
  input; non-PR groups reseed once from the explicit `reSeed` op and every
  Generate carries its OWN `op.ai`; `returned` is the LAST Generate's full
  `ret_len` output.

**Result (2026-10-03):** all 16 records pass with no implementation
changes — the first CAVP-grade cross-check of `HmacDrbg` (the crate's
previous `tests/drbg.rs` only pinned behavioural properties).

Checksums (sha256, relative to `crates/tpt-crypto-hash/tests/kat/`):

| File | Sha256 |
| --- | --- |
| `hmac_drbg_acvp.txt` | `8483d6d501d7e1ef4b287cdb463069abe1764e1e3f5eec485f6e732082f73d74` |
