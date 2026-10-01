# Changelog — tpt-crypto-field

All notable changes to this crate are documented here. Follows the workspace
version `0.1.0` (unreleased) this pass.

## 0.1.0 — unreleased

### Added
- `FieldElement<P, LIMBS>` in Montgomery form; per-modulus monomorphized,
  fully-unrolled arithmetic via the `FieldParams` trait.
- Montgomery CIOS multiply/square, Montgomery/Barrett reduction,
  `add` / `sub` / `neg` / `invert` / `sqrt`, canonical `to_bytes` /
  `from_bytes` with constant-time non-canonical rejection.
- Parameter sets: P-256 / P-384 base + scalar, BLS12-381 `Fp` + `Fr`,
  Ed25519 field + scalar.
- BLS12-381 extension towers `Fp2`, `Fp6`, `Fp12`.
- `specs/field_mul.spec`, `specs/field_reduce.spec`.

### Fixed
- Montgomery CIOS overflow-limb bug: for `LIMBS == MAX_LIMBS` (6) the SOS
  reduction can leave an `(n+1)`-th limb (`result ∈ [0, 2p)`); the copy-out
  dropped it. `carry_hi` now feeds the final conditional subtraction.
- `P384BaseParams` limbs 0 and 1 corrected.
- Removed the buggy `const_audit` scratch reference module (raised false
  constant-mismatch failures).
