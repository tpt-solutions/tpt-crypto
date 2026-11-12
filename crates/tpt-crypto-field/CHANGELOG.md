# Changelog — tpt-crypto-field

All notable changes to this crate are documented here. Follows the workspace
version `0.1.0` (unreleased) this pass.

## 0.1.0 — unreleased

### Added
- `FieldElement<P, LIMBS>` in Montgomery form; per-modulus monomorphized,
  fully-unrolled arithmetic via the `FieldParams` trait.
- Montgomery CIOS multiply/square and reduction,
  `add` / `sub` / `neg` / `invert` / `sqrt`, canonical `to_bytes` /
  `from_bytes` with constant-time non-canonical rejection.
- Parameter sets: P-256 / P-384 base + scalar, BLS12-381 `Fp` + `Fr`,
  Ed25519 field + scalar.
- BLS12-381 extension towers `Fp2`, `Fp6`, `Fp12`.
- `bls12381_final_exp_split` and `bls12381_frobenius_exponent` exported from the
  crate root (BLS12-381 final-exponentiation helpers).
- `specs/field_mul.spec`, `specs/field_reduce.spec`.

### Changed
- `sqrt` for `p ≡ 5 (mod 8)` (`S = 2`) uses 2 as the non-residue without a
  runtime search.

### Security
- `pow` multiplies and selects on every exponent bit, so its control flow does
  not depend on the exponent.
- Field add/sub and limb comparisons no longer branch on secret carries or
  comparison results. The `Choice` mask uses `core::hint::black_box` so the
  optimizer cannot turn the masked select back into a branch.

### Fixed
- Montgomery CIOS overflow-limb bug: for `LIMBS == MAX_LIMBS` (6) the SOS
  reduction can leave an `(n+1)`-th limb (`result ∈ [0, 2p)`); the copy-out
  dropped it. `carry_hi` now feeds the final conditional subtraction.
- Regression test `p384_mul_high_limb_regression` (`tests/field_props.rs`) checks
  P-384 products of boundary operands near `2^192`, `2^320` and `p - 1` against
  the reference, including the `2^192 × 2^192` case from the known-issues list.
- `P384BaseParams` limbs 0 and 1 corrected.
- Removed the buggy `const_audit` scratch reference module (raised false
  constant-mismatch failures).
- Tower square roots (`Fp2`, `Fp6`, `Fp12`): the generic non-residue search only
  enumerated base-field elements, which are all squares in these even-degree
  towers, so the search could not terminate. Each tower now overrides `enumerate`
  and uses a fixed non-residue.
