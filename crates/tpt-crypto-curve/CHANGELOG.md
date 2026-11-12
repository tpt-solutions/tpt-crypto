# Changelog — tpt-crypto-curve

All notable changes to this crate are documented here. Follows the workspace
version `0.1.0` (unreleased) this pass.

## 0.1.0 — unreleased

### Added
- Ed25519 (`EdwardsPoint`, RFC 8032): extended-coordinate add/double, w=4
  fixed-window scalar multiplication via `ct_lookup`, compress/decompress,
  `CtEq`, cofactored sign/verify. RFC 8032 §7.1 test 1 passes.
- X25519 (`X25519`, RFC 7748): clamped Montgomery ladder with `cswap`, final
  inversion. RFC 7748 §5.2 / §6.1 vectors pass.
- P-256 / P-384 (`P256Point`, `P384Point`, generic
  `ProjectivePoint<C: WeierstrassParams>`): complete Renes–Costello–Batina
  formulas (eprint 2015/1060, `a = -3`), exception-free single-path add,
  fixed-length double-and-add, `is_on_curve`, projective `CtEq`, SEC1
  compressed/uncompressed encode + `from_sec1`. RFC 5903 §8.1/§8.2 ECDH
  vectors and `n·G = O` pass.
- `specs/scalarmul_ct.spec` (timing ⟂ scalar).
- BLS12-381 (`bls12_381`, `alloc`): `G1` and `G2` (identity, generator, add, neg,
  constant-time 4-bit fixed-window `mul`, on-curve and subgroup checks,
  compressed encodings), `Gt`, `pairing` and `multi_pairing`. Tests cover subgroup
  structure, bilinearity and non-degeneracy.
- RFC 9380 hash-to-curve (`hash_to_curve`): `expand_message_xmd`, the P-256 and
  P-384 SSWU suites, the edwards25519 ELL2 suite, and the BLS12-381 G1 and G2
  suites (`alloc`). KAT vectors are in `tests/hash_to_curve.rs`.

### Fixed
- X25519 conditional-swap parity bookkeeping (was using an inversion trick that
  desynced from accumulated parity); now plain RFC 7748 §5 form.
