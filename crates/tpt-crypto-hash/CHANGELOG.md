# Changelog — tpt-crypto-hash

All notable changes to this crate are documented here. Follows the workspace
version `0.1.0` (unreleased) this pass.

## 0.1.0 — unreleased

### Added
- HMAC-DRBG (SP 800-90A) ACVP known-answer corpus (`tests/kat/hmac_drbg_acvp.txt`,
  16 SHA2-256 records with prediction-resistance and non-PR flows) driven by
  `tests/drbg_kat.rs`; all records pass byte-for-byte. First CAVP-grade
  cross-check of `HmacDrbg`.
### Added
- Keccak-f[1600] sponge core (branch-free): SHA3-224/256/384/512,
  SHAKE128/256, cSHAKE, KMAC.
- Merkle–Damgård SHA-2: SHA-224/256/384/512, SHA-512/224, SHA-512/256.
- BLAKE2b (RFC 7693) + keyed mode; BLAKE3 (chunked tree, XOF).
- KangarooTwelve (K12) over Keccak-p[1600, 12].
- HMAC (generic over any `Hasher`); HKDF (extract / expand).
- `HmacDrbg` (NIST SP 800-90A) implementing `DrbgCore`.
- Streaming `Hasher` / `Xof` traits plus one-shot free functions per primitive.
- Optional `digest` feature: `digest` 0.10 crate trait impls.
- `specs/sha256.spec`, `specs/keccak_f.spec`.
