# Feature flags

The facade crate `tpt-crypto` gates each family of primitives behind a feature.
Enable only what you use: the build then carries less code and fewer
dependencies.

## Facade features

| Feature | Default | Enables |
| --- | --- | --- |
| `std` | yes | Standard library support. Implies `alloc`. |
| `alloc` | no | Heap-allocating APIs (`Vec`-returning functions, PEM, hybrids, X-Wing). |
| `os-rng` | no | `OsRng`, the operating-system CSPRNG (needs `std`). Required by `easy`. |
| `classical` | no | `hash`, `aead`, `field`, `curve`, `sig`: Ed25519, ECDSA, RSA verify, ML-DSA. Also the `easy` recipes (with `os-rng`) and `selftest`. |
| `pq` | no | `kem` (ML-KEM, X-Wing, HPKE) and `sig` (ML-DSA, SLH-DSA when enabled). |
| `bls` | no | BLS12-381 signatures. |
| `zk` | no | Bulletproofs, Pedersen commitments, the PLONK verifier. |
| `mpc` | no | Secret sharing, Beaver triples, OT primitives. |
| `signature` | no | `signature`-crate trait impls for the sig types. |
| `profile-modern` | no | Policy: RSA public keys need at least 2048-bit moduli. Implies `classical`. |
| `profile-cnsa2` | no | Policy: RSA public keys need at least 3072-bit moduli. Implies `profile-modern`. |
| `cnsa2` | no | Approved-only recipes in `tpt_crypto::cnsa2`: AES-256-GCM, SHA-384/512, ML-KEM-1024, ML-DSA-87. Additive: it disables nothing, so `--all-features` still builds. Not a compliance claim. |
| `full` | no | `classical`, `pq`, `bls`, `zk`, `mpc`. |

A typical setup:

```toml
# Symmetric encryption and hashing only, no heap:
tpt-crypto = { version = "0.1", default-features = false, features = ["classical"] }

# Signatures and recipes on a desktop:
tpt-crypto = { version = "0.1", features = ["classical", "os-rng"] }

# Everything:
tpt-crypto = { version = "0.1", features = ["full", "os-rng"] }
```

## Sub-crate features

Sub-crates can be used directly when you want less than the facade offers.

| Crate | Notable features |
| --- | --- |
| `tpt-crypto-core` | `std`, `alloc`, `os-rng`, `rand_core` |
| `tpt-crypto-hash` | `std`, `alloc`, `digest` (RustCrypto `digest` trait impls) |
| `tpt-crypto-aead` | `std`, `alloc`, `aead-trait` (RustCrypto `aead` trait impls) |
| `tpt-crypto-sig` | `std`, `alloc`, `signature`, `rand_core`, `slh-dsa`, `profile-modern`, `profile-cnsa2` |
| `tpt-crypto-kem` | `std`, `alloc` |

The `profile-*` features are compile-time settings. A binary built with one
cannot accept a weaker RSA key. Under `--all-features` the stricter profile
applies, so `profile-cnsa2` wins over `profile-modern`.

## `no_std` and embedded targets

Every crate is `#![no_std]`. Use `alloc` only where a feature needs a heap.

- CI builds the `no_std` crates for `thumbv6m-none-eabi` (`cargo xtask no-std`).
  `thumbv7em-none-eabihf` and `wasm32-unknown-unknown` are also listed in
  `rust-toolchain.toml`'s notes and CI. Check the target is installed with
  `cargo xtask doctor`.
- The `os-rng` feature needs `std`. On a bare-metal target, supply entropy yourself
  through `tpt_crypto_core::CryptoRng` (or the `rand_core` bridge, where
  available). Do not use `easy::generate_key` there.

## Choosing features for a library you publish

Keep the feature list as small as your own code needs, and document which
facade features your public API depends on. Do not enable `full` in a library.
Let applications choose.
