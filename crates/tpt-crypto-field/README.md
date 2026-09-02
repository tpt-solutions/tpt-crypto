# tpt-crypto-field

Constant-time prime-field and extension-tower arithmetic for the
[`tpt-crypto`](../../README.md) substrate.

Layer: `field` on `ct`. Pure Rust, `#![no_std]`, `unsafe_code = "forbid"`.
Stack-only (no heap on the arithmetic paths). All secret-dependent operations
use bitwise masks and `cmov`, never branches on secret data.

## What's inside

- Core type [`FieldElement<P, LIMBS>`] — elements stored in Montgomery form,
  fully-unrolled arithmetic monomorphized per modulus (`FieldParams` trait).
- Montgomery CIOS multiply/square, Montgomery/Barrett reduction,
  `add` / `sub` / `neg` / `invert` (Fermat), `sqrt`, canonical
  `to_bytes` / `from_bytes` with constant-time non-canonical rejection.
- Parameter sets: P-256 and P-384 base + scalar fields, BLS12-381 `Fp` + `Fr`,
  Ed25519 field + scalar.
- Extension towers for BLS12-381: [`Fp2`], [`Fp6`], [`Fp12`].

## Example

```rust
use tpt_crypto_field::{Field, P256Base};

let a = P256Base::from_u64(7);
let b = P256Base::from_u64(6);
assert_eq!(a.mul(&b), P256Base::from_u64(42));
assert_eq!(a.mul(&a.invert().unwrap()), P256Base::one());
```

## Features

| Feature | Effect |
| --- | --- |
| `alloc` | default; enables the big-integer helpers used by extension-tower setup |

## Status

Not audited. KATs are hand-computed and cross-checked against
`tpt-math-exact` big-rational reference values. The Montgomery CIOS
overflow-limb bug (6-limb moduli) is fixed and regression-tested.

## License

MIT OR Apache-2.0.
