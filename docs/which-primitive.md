# Which primitive should I use?

Start from the task. Where a recipe exists, prefer it: it fixes the parameters
so you do not have to.

## Symmetric encryption

| Need | Use | Notes |
| --- | --- | --- |
| Encrypt messages with a key you manage | `tpt_crypto::easy::seal` / `open` | XChaCha20-Poly1305, random 192-bit nonce, nothing for you to manage. |
| Encrypt large files or streams | `tpt_crypto_aead::stream_seal` / `stream_open` | Chunked (age-style) with truncation and reorder protection. Whole-buffer API for now. |
| Explicit counter nonces (protocols) | `tpt_crypto_aead::NonceSequence` | Refuses to wrap. You must keep prefixes unique per sender and key. |
| Interop with AES-GCM systems | `Aes128Gcm` / `Aes256Gcm` | 96-bit nonces only. Do not reuse a nonce under one key. |
| Hardware-friendly or nonce-misuse-tolerant | `Aes128GcmSiv` / `Aes256GcmSiv` | Slower; survives an accidental nonce reuse. |

## Hashing and key derivation

| Need | Use |
| --- | --- |
| General digest | `easy::hash` (SHA-256), or `hash::sha2`, `hash::sha3`, `hash::blake3` |
| Message authentication | `easy::hmac` (HMAC-SHA-256) |
| Derive keys from a shared secret | `easy::hkdf_derive` (HKDF-SHA-256) |
| Hash a password | Argon2id (`hash::argon2`, feature `alloc`). Choose parameters from current guidance; they are your responsibility. |
| Deterministic random bytes | `hash::HmacDrbg` (SP 800-90A). Use the OS RNG for keys. |

## Signatures

| Need | Use | Notes |
| --- | --- | --- |
| Default signatures | Ed25519 (`easy::sign` / `verify`, or `sig::ed25519`) | Deterministic. Use this unless a reason below applies. |
| Post-quantum signatures | ML-DSA-65 (`sig::ml_dsa`) | FIPS 204. Larger keys and signatures. |
| Signatures that must hold against both classical and quantum attackers | `sig::hybrid` (Ed25519 + ML-DSA-65) | Both signatures are required. Crate-specific wire format, not the IETF composite format yet. |
| Interop with existing ECDSA systems | ECDSA P-256 / P-384 (`sig::ecdsa`) | Verify with the high-S-tolerant verifier when accepting X.509 or TLS signatures. |
| Interop with existing RSA systems | RSA verify (`sig::rsa`) | Verification only. Modulus minimum depends on the profile (see feature flags). |
| Stateless hash-based signatures | SLH-DSA (`sig::slh_dsa`, feature `slh-dsa`) | Conservative assumptions, large signatures. |
| Signature aggregation | BLS12-381 (`bls`, feature `bls`) | Aggregation and proofs of possession. |

## Key exchange and encryption

| Need | Use | Notes |
| --- | --- | --- |
| Post-quantum key encapsulation | ML-KEM-768 (`kem::ml_kem`) | FIPS 203. Validates public keys before encapsulating. |
| Classical and post-quantum together | X-Wing-style hybrid (`kem::xwing`) | Secure if either X25519 or ML-KEM-768 is. The wire format follows an unpublished draft. |
| Public-key encryption to a recipient | HPKE, RFC 9180 (`kem::hpke`) | Base, PSK, auth and auth-PSK modes over X25519 with ChaCha20-Poly1305 or AES-128-GCM. |
| Classical Diffie-Hellman | X25519 (`curve::X25519`) | Reject all-zero outputs. HPKE already does. |

## Key storage and interchange

| Need | Use |
| --- | --- |
| Ed25519, P-256/384 or RSA public keys in DER | `sig::encoding` (SPKI, PKCS#8, PEM). |
| Command-line use | `tpt-crypto` binary (`crates/tpt-crypto-cli`). Key files are hex. |

JWK is not implemented yet.

## Zero knowledge and multi-party computation

| Need | Use |
| --- | --- |
| Range proofs for committed values | Bulletproofs (`zk`, feature `zk`) |
| A succinct verifier for a circuit | Minimal PLONK verifier (`zk`). The prover lives in the test suite only. |
| Split a secret between parties | Additive secret sharing and Beaver triples (`mpc`, feature `mpc`) |

## Things this library does not do

- It is not audited. Do not use it in production until it is.
- No TLS, no certificate parsing, no key-agreement protocol beyond the KEM and
  HPKE modes above.
- No FrodoKEM or Classic McEliece yet.
- No formal verification. The verification plan is in `todo.md` (V1–V5), and
  the claims stay at "tested" and "checked against references".
