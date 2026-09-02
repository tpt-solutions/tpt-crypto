# tpt-crypto-kem

Constant-time key encapsulation mechanisms for the
[`tpt-crypto`](../../README.md) substrate.

Layer: `kem` on `field + curve + hash` (uses `core + ct + hash`). Pure Rust,
`#![no_std]` (`ml_kem` needs `alloc`), `unsafe_code = "forbid"`.

## What's inside

- **ML-KEM** (FIPS 203 / Module-Lattice KEM) — the primary primitive.
  - Hand-rolled constant-time polynomial core (`poly`):
    `R_q = Z_q[X]/(X^256 + 1)`, `q = 3329`, compile-time NTT / inverse-NTT /
    base multiplication, Montgomery reduction.
  - K-PKE + Fujisaki–Okamoto transform; all data flow is branch-free so
    timing does not depend on secret polynomials or the implicit-reject path.
  - Parameter sets [`MlKem512`], [`MlKem768`], [`MlKem1024`].
- **FrodoKEM** (`frodo`) and **Classic McEliece** (`mceliece`) — gated,
  reserved for a later pass; modules expose the surface but return
  `Error::Unsupported`.

## Example

```rust
use tpt_crypto_kem::ml_kem::{keygen, encapsulate, decapsulate, MlKem768};

let (pk, sk) = keygen::<MlKem768>(&mut rng);
let (ss_a, ct) = encapsulate::<MlKem768>(&pk, &mut rng);
let ss_b = decapsulate::<MlKem768>(&sk, &ct.bytes).unwrap();
assert_eq!(ss_a, ss_b);
```

## Features

| Feature | Effect |
| --- | --- |
| `std` | default |
| `alloc` | enables the `ml_kem` / `pke` high-level API |
| `frodo` / `mceliece` | gated larger lattice / code-based constructions (stubs) |

## Status

Not audited. ML-KEM is checked against FIPS 203 KAT vectors; `specs/` carries
`ml_kem_decapsulate.telos`. A fuzz target exercises decapsulation on
attacker-controlled ciphertexts.

## License

MIT OR Apache-2.0.
