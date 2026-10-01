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
- `specs/bulletproofs_verify.spec` and `tests/range_proof.rs`.

### Fixed
- Range proofs never verified: the prover and verifier both started the
  `y⁻ⁱ` generator weights at `y⁻¹` instead of `1`, and aggregated proofs
  committed `T1`/`T2` once per value instead of once in total.
- `range_proof_to_bytes` / `InnerProductProof::to_bytes` wrote scalars
  big-endian while the decoders read little-endian, so no proof round-tripped.
