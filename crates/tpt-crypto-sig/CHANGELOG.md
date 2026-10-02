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

### Added
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
