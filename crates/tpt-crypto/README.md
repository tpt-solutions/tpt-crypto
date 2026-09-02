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
| `bls` | BLS12-381 signatures (stub until `-curve` lands pairing) |
| `zk` | Bulletproofs, Pedersen commitments |
| `mpc` | secret sharing, Beaver triples, OT |
| `full` | all of the above |
| `std` / `alloc` | propagated to every enabled sub-crate |

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
