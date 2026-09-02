# tpt-crypto-hash

Constant-time hash functions, XOFs, MACs and KDFs for the
[`tpt-crypto`](../../README.md) substrate.

Layer: `hash` on `core + ct`. Pure Rust, `#![no_std]` (plus `alloc`),
`unsafe_code = "forbid"`. Every compression / permutation routine is
fixed-trace: no branch or index on secret data. MAC verification uses
`ct_eq` from `tpt-crypto-ct`.

## What's inside

| Family | Module | Primitives |
| --- | --- | --- |
| SHA-2 (Merkle–Damgård) | `sha2` | SHA-224/256/384/512, SHA-512/224, SHA-512/256 |
| SHA-3 / Keccak | `sha3` | SHA3-224/256/384/512, SHAKE128/256, cSHAKE, KMAC |
| BLAKE | `blake2b`, `blake3` | BLAKE2b (+ keyed), BLAKE3 (chunked tree XOF) |
| KangarooTwelve | `k12` | K12 over Keccak-p[1600, 12] |
| MAC | `mac` | HMAC (generic over any `Hasher`) |
| KDF | `kdf` | HKDF (extract / expand) |
| DRBG | — | `HmacDrbg` (NIST SP 800-90A), implements `DrbgCore` |

## API

- Fixed-output hashes implement [`Hasher`]: `update` / `finalize` /
  `finalize_reset` / `reset`.
- Extendable outputs (SHAKE, cSHAKE, KMAC, BLAKE3, K12) implement [`Xof`]:
  `update` / `finalize_xof` / `finalize_xof_reset` / `reset`.
- Each primitive also has a one-shot free function, e.g. `sha2::sha256`,
  `sha3::shake256`, `mac::hmac_sha256`, `kdf::hkdf_sha256`.

```rust
use tpt_crypto_hash::sha2::sha256;
let digest = sha256(b"abc");
assert_eq!(digest[0], 0xba);
```

## Features

| Feature | Effect |
| --- | --- |
| `std` | default |
| `alloc` | heap support without `std` |
| `digest` | implement the [`digest`](https://crates.io/crates/digest) 0.10 crate traits |

## Status

Not audited. Streaming-vs-one-shot equivalence is property-tested; `specs/`
carries `sha256.telos` and `keccak_f.telos`.

## License

MIT OR Apache-2.0.
