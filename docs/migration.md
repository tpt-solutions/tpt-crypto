# Migrating from other libraries

tpt-crypto is **not a drop-in replacement** for `ring`, RustCrypto or `aws-lc-rs`.
Names, types and some defaults differ, and the library is not yet audited. This
page maps the common operations to their closest equivalent here and notes what
changes. Check every mapping against the API you are replacing before you rely on it.

Byte formats matter more than names. Standard formats (FIPS 203 / 204 keys,
RFC 8032 signatures, RFC 9180 HPKE, RFC 5869 HKDF, RFC 8439 ChaCha20-Poly1305)
interoperate, and this repo checks them against published vectors. The
crate-specific formats (`sig::hybrid`, `kem::xwing`, the `easy::seal` wire format
and the CLI's hex key files) do not interoperate with anything else.

## From `ring`

| `ring` | tpt-crypto | Differences |
| --- | --- | --- |
| `aead::CHACHA20_POLY1305`, `LessSafeKey::seal_in_place_append_tag` | `ChaCha20Poly1305::new(&key)` with `encrypt_in_place_detached` / `decrypt_in_place_detached` | Tag is returned separately, not appended. Nonces are typed (`Nonce<12>`). |
| `aead::AES_256_GCM` | `Aes256Gcm::new(&key)` (`tpt_crypto_aead`) | Same detached-tag shape. 96-bit nonces only. |
| `aead::NonceSequence` (ring trait) | `tpt_crypto_aead::NonceSequence` | Ours is a concrete type that returns `Option` and refuses to wrap. |
| `digest::SHA256` | `tpt_crypto::hash::sha2::sha256`, or `easy::hash` | One-shot functions. Streaming: `Sha256::new()`, `update`, `finalize`. |
| `hmac::Key` / `hmac::sign` | `easy::hmac`, or `hash::mac::hmac_sha256` | Returns a fixed array. |
| `hkdf::Salt` / `Prk::expand` | `easy::hkdf_derive`, or `hash::kdf::hkdf_sha256` | `hkdf_derive` returns an error above 255 × 32 bytes. |
| `signature::Ed25519KeyPair::from_seed_unchecked` | `sig::ed25519::SigningKey::from_seed` | Use `easy::ed25519_generate` for new keys. |
| `signature::UnparsedPublicKey::verify` (Ed25519) | `sig::ed25519::VerifyingKey::verify` | Rejects non-canonical `S` and small-order keys. |
| `signature::EcdsaKeyPair` (P-256 / P-384) | `sig::ecdsa::SigningKey`, `sign_p256_sha256` / `sign_p384_sha384` | Signing is deterministic (RFC 6979). Ring's is randomised. |
| `signature::RsaPublicKeyComponents::verify` | `sig::rsa::PublicKey::from_components` + `verify_pkcs1v15` / `verify_pss` | Verification only. Modulus minimum depends on the profile. |
| `agreement::X25519` | `curve::X25519::diffie_hellman` | Returns raw bytes. Check for an all-zero output (HPKE does this for you). |
| `rand::SystemRandom` | `tpt_crypto::prelude::OsRng` (feature `os-rng`) | Implements `CryptoRng`. |

## From RustCrypto

| RustCrypto | tpt-crypto | Differences |
| --- | --- | --- |
| `sha2::Sha256` / `sha3::Sha3_256` | `hash::sha2::Sha256`, `hash::sha3::Sha3_256` | Enable the `digest` feature of `tpt-crypto-hash` for the trait impls. |
| `aes-gcm::Aes256Gcm` | `tpt_crypto_aead::Aes256Gcm` | Enable `aead-trait` on `tpt-crypto-aead` for the `aead` trait impls. |
| `chacha20poly1305::ChaCha20Poly1305` | `tpt_crypto_aead::ChaCha20Poly1305` | As above. |
| `ed25519-dalek` | `sig::ed25519` | Different type names. Enable `signature` for the `signature`-crate traits. |
| `p256::ecdsa` / `p384::ecdsa` | `sig::ecdsa` | Prehash-based. Use `verify_prehash_allow_high_s` when you must accept high-S signatures from X.509 or TLS. |
| `ml-kem` (FIPS 203) | `kem::ml_kem::{keygen, encapsulate, decapsulate}` | `encapsulate` returns an error on a malformed public key rather than panicking. `EncapsKey` and `DecapsKey` expose their bytes. |
| `ml-dsa` (FIPS 204) | `sig::ml_dsa::{keygen_from_seed, sign, verify}` | `sign` is deterministic; `sign_hedged` takes explicit randomness. |
| `hpke` (RFC 9180) | `kem::hpke` | Covers base, PSK, auth and auth-PSK modes over X25519 with ChaCha20-Poly1305 or AES-128-GCM. Not every ciphersuite. |

## From `aws-lc-rs`

`aws-lc-rs` wraps AWS-LC, a C library. tpt-crypto is pure Rust, so there is no
FFI boundary. Map its functions using the `ring` table above. Two things change:

- Its FIPS-validated build has no equivalent here. Nothing in this repo is
  validated.
- Anything that relies on `aws-lc-rs` for hardware acceleration (for example
  AES-NI) gets whatever the pure-Rust code and the `target-feature` paths give,
  which is slower in most cases.

## Before you switch

1. Port one operation at a time and keep the old implementation running alongside
   for a test run.
2. Replay real inputs through both and compare the bytes, not only the verdicts.
3. Re-check every size limit, nonce rule and error path. Those are where
   libraries differ most.
4. Do not switch a production path until the library's audit status suits you.
   tpt-crypto is not audited.
