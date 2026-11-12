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
| RSA (verification only) | `rsa` | PKCS#1 v1.5 and RSASSA-PSS, SHA-256 / 384 / 512 | RFC 8017 |
| BLS12-381 | `bls` | Basic, Aug and POP ciphersuites | draft-irtf-cfrg-bls-signature-04 |
| Hybrid Ed25519 + ML-DSA-65 | `hybrid` | both signatures must verify | crate-defined wire format |

- ML-DSA: lattice-based; NTT polynomial core, rejection sampling with a
  data-flow-independent trace, hedged and deterministic signing.
- ECDSA / Ed25519: nonce generation is constant-time; `specs/ecdsa_nonce_ct.spec`
  pins the "timing ⟂ nonce" contract. ECDSA signing normalises to low-S.
  `verify_prehash` rejects high-S, and `verify_prehash_allow_high_s` accepts it
  for X.509 and TLS inputs that are not normalised.
- Ed25519 verification rejects small-order public keys and commitments.
- Key encodings: `encoding` (strict DER for SubjectPublicKeyInfo and PKCS#8,
  PKCS#1 `RSAPublicKey`, and PEM) and `jwk` (public-key JWK, RFC 7517 / 8037 /
  7518). Private-key members are never accepted by the JWK parser.
- RSA is public-key verification only. It never handles a private key.

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
that configuration. The 2048-bit RSA known-answer tests (`tests/rsa.rs`,
`tests/kat_encoding.rs`) are compiled out under `profile-cnsa2` only, and the 3072-bit
set (`tests/rsa_3072.rs`) runs in every build. `cargo xtask test` also runs the crate
under `profile-modern`, so the 2048-bit set is still exercised. `tests/rsa_profile.rs`
checks the length gate directly.

Only RSA size is gated so far. The workspace has no SHA-1 or MD5, so there is
nothing class-level to remove. Excluding other primitives (for example Ed25519 or
ChaCha20 under CNSA 2.0) is a policy decision that is not implemented here.

## Status

Not audited. ML-DSA is checked against FIPS 204 KAT vectors; ECDSA and Ed25519
have RFC / Wycheproof-style vector tests plus property tests. BLS12-381 is
checked against the Ethereum `bls12-381-tests` vectors (`tests/bls_kat.rs`). A
fuzz target exercises signature verification on attacker-controlled input, and
other targets exercise DER, public-key and hybrid parsing.

## License

MIT OR Apache-2.0.
