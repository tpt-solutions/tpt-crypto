# tpt-crypto-sig

Constant-time digital signature schemes for the
[`tpt-crypto`](../../README.md) substrate.

Layer: `sig` on `field + curve + hash` (also `core + ct`). Pure Rust,
`#![no_std]` (plus `alloc`), `unsafe_code = "forbid"`, allocation-free on the
hot paths.

## What's inside

| Scheme | Module | Parameter sets | Reference |
| --- | --- | --- | --- |
| ML-DSA | `ml_dsa` | ML-DSA-44 / -65 / -87 | FIPS 204 |
| SLH-DSA | `slh_dsa` | SLH-DSA (hash-based) | FIPS 205 |
| Ed25519 | `ed25519` | edwards25519 | RFC 8032 |
| ECDSA | `ecdsa` | P-256, P-384 | SEC1 / FIPS 186-5 |

- ML-DSA: lattice-based; NTT polynomial core, rejection sampling with a
  data-flow-independent trace, hedged and deterministic signing.
- ECDSA / Ed25519: nonce generation is constant-time; `specs/ecdsa_nonce_ct.telos`
  pins the "timing ⟂ nonce" contract.

## Example

```rust
use tpt_crypto_sig::ml_dsa::{keygen, sign, verify, MlDsa65};

let (pk, sk) = keygen::<MlDsa65>(&mut rng);
let sig = sign::<MlDsa65>(&sk, b"message", b"" /* context */).unwrap();
assert!(verify::<MlDsa65>(&pk, b"message", &sig, b"").is_ok());
```

## Features

| Feature | Effect |
| --- | --- |
| `std` | default |
| `alloc` | heap support without `std` |
| `slh-dsa` | build the hash-based SLH-DSA module |
| `signature` | implement the [`signature`](https://crates.io/crates/signature) crate traits |
| `rand_core` | `rand_core` RNG bridge |
| `profile-modern` | policy profile: RSA public keys must have a modulus of at least 2048 bits |
| `profile-cnsa2` | policy profile: RSA modulus of at least 3072 bits (implies `profile-modern`) |

### Policy profiles

The profile features tighten what `rsa::PublicKey::from_components` accepts. The
default build keeps the 1024-bit floor. A profile is a compile-time setting, so a
binary built with it cannot accept a weaker key.

`--all-features` enables both profiles, so the stricter one (3072 bits) applies in
that configuration. Under `profile-modern`, the RSA known-answer tests that use
2048-bit vectors are compiled out (`tests/rsa.rs`, `tests/kat_encoding.rs`);
`tests/rsa_profile.rs` checks the length gate directly.

Only RSA size is gated so far. The workspace has no SHA-1 or MD5, so there is
nothing class-level to remove. Excluding other primitives (for example Ed25519 or
ChaCha20 under CNSA 2.0) is a policy decision that is not implemented here.

## Status

Not audited. ML-DSA is checked against FIPS 204 KAT vectors; ECDSA and Ed25519
have RFC / Wycheproof-style vector tests plus property tests. A fuzz target
exercises signature verification on attacker-controlled input.

## License

MIT OR Apache-2.0.
