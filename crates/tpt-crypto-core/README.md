# tpt-crypto-core

Shared traits, error types, and secret-handling wrappers for the
[`tpt-crypto`](../README.md) constant-time substrate.

This is the lowest layer of the workspace (`core → ct → field → curve`). It
depends on nothing internal and is `#![no_std]`.

## What's inside

- [`Error`] — the substrate's non-secret error type (no timing/oracle info).
- [`Zeroize`] / [`Zeroizing`] — a volatile byte-wipe so secrets never linger in
  memory after `Drop`.
- [`SecretBox`] — an owned secret that *cannot* be printed, compared, hashed, or
  accidentally observed; reading it requires an explicit
  [`SecretBox::expose_secret`] call.
- [`ct`] — constant-time comparison and selection: [`Choice`], plus the
  [`ct_eq`] / [`ct_ne`] / [`ct_select`] facades.
- [`CryptoRng`] / [`DrbgCore`] — the RNG traits implemented by the DRBGs in
  `tpt-crypto-hash` / `tpt-crypto-aead`.
- [`constant_time`] — a prose module describing exactly what "constant-time"
  guarantees here, the threat model, and how to review a primitive.

## Example

```rust
use tpt_crypto_core::secret::SecretBox;
use tpt_crypto_core::ct::{ct_eq, Choice};

let key = SecretBox::new([0x42u8; 32]);
// Reading the secret is an explicit, greppable action:
assert_eq!(key.expose_secret(), &[0x42u8; 32]);
// No `Debug`/`PartialEq`/`Hash` — this would not compile:
// println!("{:?}", key);
```

## Features

| Feature     | Effect                                                        |
| ----------- | ------------------------------------------------------------- |
| `std`       | `std::error::Error` impl for `Error` (on by default).         |
| `alloc`     | Heap-buffer wipes (`Vec<T>: Zeroize`) and `extern crate alloc`. |
| `serde`     | `Serialize`/`Deserialize` for `Error` and `Choice` (never for `SecretBox`). |
| `rand_core` | Bridge adapters between `CryptoRng` and the `rand_core` ecosystem. |

## License

Licensed under either of [MIT](../LICENSE-MIT) or
[Apache-2.0](../LICENSE-APACHE) at your option.
