# Changelog — tpt-crypto-sig

All notable changes to this crate are documented here. Follows the workspace
version `0.1.0` (unreleased) this pass.

## 0.1.0 — unreleased

### Fixed
- **FIPS 204 conformance:** the challenge seed `c̃` was packed as a fixed
  32 bytes for every parameter set; the standard length is `λ/4`
  (32 / 48 / 64 bytes), so ML-DSA-65 / -87 signatures were 3293 / 4595
  bytes instead of 3309 / 4627 and did not verify against other
  implementations. The ACVP sigVer harness never asserted its results,
  which is why this survived the vector pass — `tests/ml_dsa_kat.rs` now
  checks `got == want` for every record and passes with the corrected
  layout.

### Security
- Ed25519 `verify` rejects small-order public keys and commitments. With a
  small-order key, the cofactored equation accepts an all-zero `R` with `S = 0`
  for every message.

### Added
- RSA signature verification (`rsa`): PKCS#1 v1.5 and RSASSA-PSS with SHA-256,
  SHA-384 and SHA-512. Moduli from 1024 to 16384 bits; the public-key operation
  uses Montgomery arithmetic. Only the public-key operation is provided.
- Key encodings (`encoding`): strict DER for Ed25519, RSA, P-256 and P-384
  SubjectPublicKeyInfo and PKCS#8, PKCS#1 `RSAPublicKey`, and PEM (RFC 7468).
- JWK public-key encoding (`jwk`) for Ed25519, P-256 and P-384, with strict
  parsing. Private-key members are never accepted.
- ECDSA `verify_prehash_allow_high_s`, a lenient verifier for X.509 and TLS
  signatures that are not low-S normalised. The strict `verify_prehash` is
  unchanged.
- Hybrid Ed25519 + ML-DSA-65 signature (`hybrid`): both components must verify.
  The wire format is crate-defined, not the IETF composite format.
- BLS12-381 signatures (`bls`): draft-irtf-cfrg-bls-signature-04 with Basic,
  Aug and POP ciphersuites, aggregation, and proof of possession.
- Policy profiles `profile-modern` (RSA modulus at least 2048 bits) and
  `profile-cnsa2` (at least 3072 bits). See the README.
- ML-DSA (FIPS 204): ML-DSA-44 / -65 / -87; NTT polynomial core, rejection
  sampling with a data-flow-independent trace, hedged and deterministic
  signing. FIPS 204 KAT coverage.
- SLH-DSA (FIPS 205) behind the `slh-dsa` feature.
- Ed25519 (RFC 8032) sign/verify wrapper over `tpt-crypto-curve`.
- ECDSA over P-256 / P-384 (SEC1 / FIPS 186-5) with constant-time nonce
  generation; `specs/ecdsa_nonce_ct.spec`.
- Optional `signature` feature: `signature`-crate trait impls
  (`Signer` / `Verifier` / `SignatureEncoding` / hazmat prehash) for
  Ed25519, ECDSA P-256 / P-384, ML-DSA-44 / -65 / -87, and BLS12-381
  (default POP suite), covered by `tests/signature_compat.rs`. SLH-DSA is
  intentionally not bridged (runtime parameter-dependent signature
  length).
- `rand_core` RNG bridge feature.
- `cargo-fuzz` signature-verification target.

### Changed
- Facade (`tpt-crypto`) now re-exports `ml_dsa` and the signature wrappers via
  the `classical` / `pq` features.
- The optional `signature` dependency is updated from 2.2.0 to 3.0.0.
