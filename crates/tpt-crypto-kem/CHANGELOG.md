# Changelog — tpt-crypto-kem

All notable changes to this crate are documented here. Follows the workspace
version `0.1.0` (unreleased) this pass.

## 0.1.0 — unreleased

### Added
- ML-KEM (FIPS 203): constant-time polynomial core (`poly`) with compile-time
  NTT / inverse-NTT / base multiplication and Montgomery reduction over
  `R_q = Z_q[X]/(X^256 + 1)`, `q = 3329`.
- K-PKE and the Fujisaki–Okamoto transform; branch-free implicit-reject path.
- Parameter sets `MlKem512`, `MlKem768`, `MlKem1024`.
- Byte encoding / decoding (`encode`), CBD sampler (`sampler`).
- `specs/ml_kem_decapsulate.spec`; `cargo-fuzz` decapsulation target.
- FIPS 203 KAT coverage.

### Removed (pre-release)
- FrodoKEM (`frodo`) and Classic McEliece (`mceliece`) placeholder modules and
  their features. They only returned `Error::Unsupported`, and `--all-features`
  enabled them. Both remain planned work in the workspace `todo.md`.
