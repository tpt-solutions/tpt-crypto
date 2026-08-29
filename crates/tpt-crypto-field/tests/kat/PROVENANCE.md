# KAT Provenance — `tpt-crypto-field`

Source: `crates/tpt-crypto-field/tests/kat/`
Generated: 2026-08-29

## Source of truth

These known-answer vectors were **hand-computed from the prime definitions**
using Python's arbitrary-precision integers (no dependency on `tpt-math-exact`,
which is not available offline). Each vector is a ground-truth `(a, b, a*b mod p)`
triple derived directly from the canonical prime hex for each field.

## Primes (canonical, big-endian hex)

| Field | Prime |
|-------|-------|
| P-256 | `0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF` |
| P-384 | `0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF` |
| BLS12-381 Fp | `0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab` |

## `field_mul.json`

For each field, the following cases are covered (limbs are **little-endian**
64-bit, matching `FieldElement::to_integer()`):

- `one_one`: `1 * 1 = 1`
- `two_three`: `2 * 3 = 6`
- `max_small`: `(2^62) * (2^62) mod p`
- `p-1_sq`: `(p-1) * (p-1) = 1 mod p`  (the classic sign-of-`-1` check)
- `p-1_times_2`: `(p-1) * 2 = p-2 mod p`
- `zero_times_max`: `0 * (p-1) = 0`
- `one_times_p-1`: `1 * (p-1) = p-1`
- `large_rand`: two large random-ish values multiplied mod p

### Sanity checks applied at generation time

- `(p-1)^2 mod p == 1` for all three fields (verified in the generator script).
- `0 * x == 0` and `1 * x == x` trivially.
- `a * b mod p == b * a mod p` (commutativity) spot-checked.

## `field_reduce.json`

Covers canonical, boundary, and non-canonical inputs for `from_bytes`
(reduction + canonicality rejection):

- `zero`, `one`, `p-1`: canonical, unchanged.
- `p`, `p+1`, `2p-1`: non-canonical (`>= p`), must be rejected by `from_bytes`.
- `large_canonical`: `(p-1)/2`, canonical.

## Cross-check policy

These vectors are a **floor**, not a substitute for the `tpt-math-exact`
big-rational reference called out in the todo. The intended full story:

1. Regenerate with `tpt-math-exact` when online (same JSON schema).
2. Add Wycheproof field edge-case vectors (`tests/kat/wycheproof.json`).
3. `cargo xtask kat-check` verifies every vector against the live impl.

## Reproduce

```sh
python3 tests/kat/generate.py   # regenerates field_mul.json / field_reduce.json
cargo xtask kat-check           # asserts all vectors against FieldElement
```

(`generate.py` is a dev-only helper, not part of the published crate.)
