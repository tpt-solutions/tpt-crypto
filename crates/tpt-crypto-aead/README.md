# tpt-crypto-aead

Constant-time authenticated encryption (AEAD) for the
[`tpt-crypto`](../../README.md) substrate.

Layer: `aead` on `core + ct`. Pure Rust, `#![no_std]` (plus `alloc` where
needed), `unsafe_code = "forbid"`.

## What's inside

| Construction | Types | Reference |
| --- | --- | --- |
| AES-GCM | `Aes128Gcm`, `Aes256Gcm` | NIST SP 800-38D |
| ChaCha20-Poly1305 | `ChaCha20Poly1305` | RFC 8439 |
| XChaCha20-Poly1305 | `XChaCha20Poly1305` | draft-irtf-cfrg-xchacha |
| AES-GCM-SIV (nonce-misuse resistant) | `Aes128GcmSiv`, `Aes256GcmSiv` | RFC 8452 |
| AES-256 CTR-DRBG | `CtrDrbg` | NIST SP 800-90A |
| Stream / MAC building blocks | `ChaCha20`, `Poly1305`, `poly1305_mac`, `Aes` | — |

- The portable AES path is a **table-free, constant-time** S-box (algebraic
  GF(2⁸) inversion). On `x86_64` the dispatcher routes through hardware AES-NI
  via `tpt_crypto_ct::arch`; GHASH/POLYVAL use a branch-free carry-less multiply
  with a `pclmulqdq` fast path.
- Tag verification is always constant-time (`Tag::ct_eq`). On decryption
  failure the buffer is left unchanged — no plaintext is released.

## API

All constructions implement the const-generic [`Aead<NONCE_LEN, TAG_LEN>`] trait:
`encrypt_in_place_detached` / `decrypt_in_place_detached`, alloc-gated combined
`encrypt` / `decrypt`, AAD, and the `Nonce` / `Tag` newtypes (`Tag` has no
`PartialEq` — compare via `Tag::ct_eq`).

```rust
use tpt_crypto_aead::{Aead, Aes256Gcm, Nonce};

let cipher = Aes256Gcm::new(&[0x42u8; 32]).unwrap();
let nonce = Nonce::from_slice(&[0u8; 12]).unwrap();
let mut buf = b"attack at dawn".to_vec();
let tag = cipher.encrypt_in_place_detached(&nonce, b"aad", &mut buf);
cipher.decrypt_in_place_detached(&nonce, b"aad", &mut buf, &tag).unwrap();
assert_eq!(buf, b"attack at dawn");
```

## Features

| Feature | Effect |
| --- | --- |
| `std` | default; enables `std`/`alloc` on the core crates |
| `alloc` | combined (non-detached) encrypt/decrypt helpers |
| `aead-trait` | implement the [`aead`](https://crates.io/crates/aead) 0.6 crate traits |

## Status

Not audited. Inline KAT coverage is per-module (FIPS-197, NIST GCM Appendix B,
RFC 8439 §2.5.2, RFC 8452 C.1); the full CAVP / Wycheproof corpora are still
being vendored. `CtrDrbg` is not yet wired to CAVP vectors.

## License

MIT OR Apache-2.0.
