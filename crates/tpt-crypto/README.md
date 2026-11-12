# tpt-crypto

Feature-gated facade for the [`tpt-crypto`](../../README.md) workspace: one
crate that re-exports every primitive behind additive feature gates, and
exposes the `spec.txt` §4 target API verbatim.

Pure Rust, `#![no_std]` (plus `alloc`), `unsafe_code = "forbid"`.

## Features

| Feature | Pulls in |
| --- | --- |
| `classical` | `hash`, `aead`, `field`, `curve`, `sig` (Ed25519 / ECDSA / ML-DSA) |
| `pq` | `kem` + `ml_kem` (needs `alloc`), `sig` + `ml_dsa` |
| `bls` | BLS12-381 signatures (aggregation, proof-of-possession); enables `alloc` |
| `zk` | Bulletproofs, Pedersen commitments |
| `mpc` | secret sharing, Beaver triples, OT |
| `cnsa2` | `cnsa2` module (approved-only recipes, see below); pulls in `classical`, `pq`, `os-rng`, `alloc` |
| `os-rng` | `OsRng`, the operating-system CSPRNG (requires `std`) |
| `signature` | `signature`-crate trait impls for the sig types |
| `profile-modern` / `profile-cnsa2` | policy: RSA public keys need at least 2048 / 3072-bit moduli |
| `full` | all of the above except `cnsa2`, `os-rng`, `signature` and the profiles |
| `std` / `alloc` | propagated to every enabled sub-crate |

With `classical` and `os-rng` enabled, the `easy` module (one-call recipes) is
available. The `selftest` module (power-on known-answer tests) is available
with `classical`.

## `cnsa2` (approved-only recipes)

`tpt_crypto::cnsa2` exposes only the CNSA 2.0 algorithms this crate implements:
AES-256-GCM, SHA-384 / SHA-512, ML-KEM-1024 and ML-DSA-87. Nothing else in the
crate is disabled by the feature, so `--all-features` still builds, and code that
calls the other primitives directly is not checked.

This is not a compliance claim. Using these recipes does not make a system
CNSA 2.0 compliant. LMS and XMSS are listed as approved but are not implemented,
and SHA-3 is not used.

```toml
tpt-crypto = { version = "0.1", features = ["cnsa2"] }
```

## `spec.txt` §4 surface

The [`ml_kem`], [`ml_dsa`], [`bulletproofs`], [`bls`], [`ct`] and [`prelude`]
modules re-export the exact names used in the `spec.txt` §4 snippets, so
downstream code can be written verbatim against the target API.

```toml
[dependencies]
tpt-crypto = { version = "0.1", default-features = false, features = ["pq", "alloc"] }
```

```rust
use tpt_crypto::ml_kem::{keygen, encapsulate, decapsulate, MlKem768};
```

## Status

Not audited — reference material only. See the
[workspace README](../../README.md) for the full picture.

## License

MIT OR Apache-2.0.
