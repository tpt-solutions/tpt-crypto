# Changelog — tpt-crypto (facade)

All notable changes to this crate are documented here. Follows the workspace
version `0.1.0` (unreleased) this pass.

## 0.1.0 — unreleased

### Added
- Feature-gated facade over the workspace: `classical`, `pq`, `bls`, `zk`,
  `mpc`, `full`, plus `std` / `alloc` propagated to every enabled sub-crate.
- `spec.txt` §4 surface modules re-exporting names verbatim: `ml_kem`,
  `ml_dsa`, `bulletproofs`, `bls`, `ct`, `prelude`.
- `core` + `ct` are always present so `prelude` / `ct` work regardless of
  which primitive features are enabled.
- `bls` module: BLS12-381 signatures (minimal-pubkey-size, draft-04), with
  aggregation and proof-of-possession.
- `os-rng` feature providing `OsRng` (requires `std`).
- `easy` module (one-call recipes, `os-rng` + `classical`) and `selftest`
  module (power-on known-answer tests, `classical`).
- `signature` feature: `signature`-crate trait impls for the sig types.
- `profile-modern` and `profile-cnsa2` policy features: RSA public keys need
  at least 2048 / 3072-bit moduli.
- `cnsa2` feature and `cnsa2` module: approved-only recipes (AES-256-GCM,
  SHA-384 / SHA-512, ML-KEM-1024, ML-DSA-87). Additive, disables nothing, and is
  not a compliance claim. Requires `std` through `os-rng`.
