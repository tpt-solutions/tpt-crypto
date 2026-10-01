# Changelog — tpt-crypto-sig

All notable changes to this crate are documented here. Follows the workspace
version `0.1.0` (unreleased) this pass.

## 0.1.0 — unreleased

### Added
- ML-DSA (FIPS 204): ML-DSA-44 / -65 / -87; NTT polynomial core, rejection
  sampling with a data-flow-independent trace, hedged and deterministic
  signing. FIPS 204 KAT coverage.
- SLH-DSA (FIPS 205) behind the `slh-dsa` feature.
- Ed25519 (RFC 8032) sign/verify wrapper over `tpt-crypto-curve`.
- ECDSA over P-256 / P-384 (SEC1 / FIPS 186-5) with constant-time nonce
  generation; `specs/ecdsa_nonce_ct.spec`.
- Optional `signature` feature: `signature` crate trait impls.
- `rand_core` RNG bridge feature.
- `cargo-fuzz` signature-verification target.

### Changed
- Facade (`tpt-crypto`) now re-exports `ml_dsa` and the signature wrappers via
  the `classical` / `pq` features.
