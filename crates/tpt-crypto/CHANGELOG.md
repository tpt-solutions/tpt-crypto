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
- `bls` module stub (BLS12-381 signatures) pending pairing support in
  `tpt-crypto-curve`.
