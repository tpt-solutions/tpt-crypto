# tpt-crypto-kem

Constant-time key encapsulation mechanisms for the
[`tpt-crypto`](../../README.md) substrate.

Layer: `kem` on `field + curve + hash` (also `core + ct`; the `hpke` module and
FrodoKEM-AES use `aead`). Pure Rust, `#![no_std]` (`ml_kem` and the other
high-level modules need `alloc`), `unsafe_code = "forbid"`.

## What's inside

- **ML-KEM** (FIPS 203 / Module-Lattice KEM) — the primary primitive.
  - Hand-rolled constant-time polynomial core (`poly`):
    `R_q = Z_q[X]/(X^256 + 1)`, `q = 3329`, compile-time NTT / inverse-NTT /
    base multiplication, Montgomery reduction.
  - K-PKE + Fujisaki–Okamoto transform; all data flow is branch-free so
    timing does not depend on secret polynomials or the implicit-reject path.
  - Parameter sets [`MlKem512`], [`MlKem768`], [`MlKem1024`].
- **FrodoKEM** (`frodo`) — FrodoKEM-640, -976 and -1344, each with a SHAKE and
  an AES matrix variant (`frodo::shake`, `frodo::aes`). Checked byte for byte
  against the first official KAT records (three for 640, one for 976 and 1344).
- **Classic McEliece** (`mceliece`) — parameter sets 348864, 460896, 6688128,
  6960119 and 8192128. Checked against the first three official KAT records of
  each set. The four 13-bit sets are `#[ignore]`d in debug builds.
- **HPKE** (`hpke`, RFC 9180) — `DHKEM(X25519, HKDF-SHA256)` with ChaCha20-Poly1305
  or AES-128-GCM, in base, PSK, auth and auth-PSK modes. Checked against RFC 9180
  test-vector records.
- **X-Wing-style hybrid KEM** (`xwing`) — X25519 + ML-KEM-768, following
  draft-connolly-cfrg-xwing-kem. The draft has no published vectors this crate
  can check against, so the wire format is not stable yet.

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
| `alloc` | enables the `ml_kem`, `pke`, `hpke`, `xwing`, `frodo` and `mceliece` modules |

## Status

Not audited. ML-KEM is checked against FIPS 203 KAT vectors; `specs/` carries
`ml_kem_decapsulate.spec`. Fuzz targets exercise decapsulation on
attacker-controlled ciphertexts for ML-KEM, FrodoKEM, and Classic McEliece
(348864 and 6688128), and the X-Wing decapsulation and public-key
encapsulation paths.

## License

MIT OR Apache-2.0.
