# Changelog — tpt-crypto-zk

All notable changes to this crate are documented here. Follows the workspace
version `0.1.0` (unreleased) this pass.

## 0.1.0 — unreleased

### Added
- `Transcript` — Fiat–Shamir transcript (Merlin-style STROBE-lite) over
  SHAKE256.
- `PedersenGens` / `Ristretto` — Pedersen commitments over the prime-order
  subgroup of Ed25519.
- `InnerProductProof` — inner-product argument.
- Bulletproofs range proofs: `prove_range` / `verify_range`, single and
  aggregated, ranges to `2^64`, with `range_proof_to_bytes` /
  `range_proof_from_bytes`.
- `plonk` — minimal PLONK verifier built on inner-product commitment opening.
- `specs/bulletproofs_verify.telos`.
