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
