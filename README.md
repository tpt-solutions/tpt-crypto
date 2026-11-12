# tpt-crypto — the high-assurance, constant-time cryptographic substrate

[![CI](https://github.com/tpt-solutions/tpt-crypto/actions/workflows/ci.yml/badge.svg)](https://github.com/tpt-solutions/tpt-crypto/actions/workflows/ci.yml)

Pure Rust, `no_std`-first, hand-rolled primitives with a 100% MIT/Apache
compatible dependency chain. No OpenSSL, no `ring`, no `*-sys` C-FFI.

> **Status:** pre-release `0.1.0`. Not yet published to crates.io; crates.io
> metadata is prepared so publishing is a one-step follow-up.

> **⚠️ Not audited — reference material only.** This project has **not** been
> independently security-audited or formally verified end-to-end. It is offered
> as a community reference and a starting point for others to learn from, fork,
> and harden — **not** as a production-ready, drop-in cryptographic library. Do
> not ship it in security-critical systems without your own review, testing, and
> professional audit. Use at your own risk.

## Layering (strict — lower never depends on higher)

```
core → ct → field → curve
hash        on core + ct
aead        on core + ct
kem / sig   on field + curve + hash  (kem's hpke module also uses aead)
zk          on curve + hash
mpc         on field + hash
tpt-crypto  (facade) on everything
```

Every crate is `#![no_std]` (plus `alloc` where needed) and opts into the
workspace lints. `unsafe_code = "forbid"` across the workspace **except**
`tpt-crypto-ct` (and the `zeroize` submodule of `tpt-crypto-core`), which
document and localize every `unsafe` block with a `// SAFETY:` comment.

## Crates

| Crate | Purpose |
| --- | --- |
| `tpt-crypto-core` | Shared traits, error types, secret wrappers (`SecretBox<T>`, `Zeroizing<T>`), `CryptoRng`/`DrbgCore`, `CtEq`/`ConstantTimeSelect`. |
| `tpt-crypto-ct` | Constant-time arithmetic: `Choice`, `ct_eq`/`ct_select`, masked ops, `ct_lookup`. |
| `tpt-crypto-hash` | SHA-2, SHA-3/SHAKE, BLAKE2b/BLAKE3, K12, HMAC, HKDF, `HmacDrbg`. |
| `tpt-crypto-field` | Prime field arithmetic over `tpt-math-exact` / `tpt-math-linalg-fixed`. |
| `tpt-crypto-curve` | Ed25519, X25519, P-256/384, BLS12-381 G1/G2 + pairing, RFC 9380 hash-to-curve. |
| `tpt-crypto-aead` | AES-GCM, ChaCha20-Poly1305, AES-GCM-SIV, `CtrDrbg`. |
| `tpt-crypto-kem` | ML-KEM (FIPS 203). FrodoKEM and Classic McEliece are planned. |
| `tpt-crypto-sig` | ML-DSA (FIPS 204), SLH-DSA, Ed25519, ECDSA (P-256/384), RSA verify (PKCS#1 v1.5 / PSS), BLS12-381. |
| `tpt-crypto-zk` | Bulletproofs, minimal PLONK verifier, Pedersen commitments. |
| `tpt-crypto-mpc` | Additive secret sharing, Beaver triples, OT primitives. |
| `tpt-crypto` | Facade re-exporting the substrate behind feature gates. |

### Facade features

Pick a subset or take everything with `full`:

| Feature | Pulls in |
| --- | --- |
| `classical` | `hash`, `aead`, `field`, `curve`, `sig` (Ed25519 / ECDSA / ML-DSA) |
| `pq` | `kem` + `ml_kem` (needs `alloc`), `sig` + `ml_dsa` |
| `bls` | BLS12-381 signatures (aggregation, proof-of-possession) |
| `zk` | Bulletproofs, Pedersen commitments |
| `mpc` | secret sharing, Beaver triples, OT |
| `full` | all of the above |

The `ml_kem`, `ml_dsa`, `bulletproofs`, `bls`, `ct` and `prelude` modules expose
the exact names from `spec.txt` §4 so downstream code compiles verbatim against it.

See [`spec.txt`](./spec.txt) for the full design and target API.

Guides (which primitive to use, feature flags, constant-time claims and their limits,
migration from `ring` / RustCrypto / `aws-lc-rs`) are in [`docs/`](./docs/README.md).

## Guarantees

- **Constant-time by construction.** No secret-dependent branches or indexing.
  Secret-dependent selection goes through `ct_select` / masking, whose
  execution trace is independent of the secret (see
  `tpt-crypto-core::constant_time` and the `*.spec` contracts under `specs/`).
- **`no_std` everywhere** (plus `alloc` where a heap is needed). Builds for
  `thumbv6m-none-eabi`, `thumbv7em-none-eabihf`, `wasm32-unknown-unknown`.
- **100% MIT/Apache dependency chain.** Enforced by `deny.toml` (C-FFI,
  OpenSSL, and `ring` are banned).

## Evidence it works

Correctness is checked against published, independently produced test vectors,
not just self-consistency. Each vector file is pinned by sha256 in the crate's
`tests/kat/PROVENANCE.md`, and `cargo xtask kat-check` fails if one is altered.

| Area | Checked against | Where |
| --- | --- | --- |
| SHA-2, SHA-3, SHAKE | FIPS 180-4 / FIPS 202 (NIST CAVP) | `crates/tpt-crypto-hash/tests/kat.rs` |
| BLAKE2b, BLAKE3, KangarooTwelve | RFC 7693, official BLAKE3 vectors, RFC 9861 | `crates/tpt-crypto-hash/tests/kat.rs` |
| HMAC, HKDF, cSHAKE, KMAC, HMAC-DRBG | RFC 4231, RFC 5869, SP 800-185, NIST ACVP | `crates/tpt-crypto-hash/tests/` |
| AES-GCM, ChaCha20-Poly1305, AES-GCM-SIV | Wycheproof, RFC 8452 | `crates/tpt-crypto-aead/tests/kat/` |
| ML-KEM | NIST FIPS 203 vectors (512/768/1024) | `crates/tpt-crypto-kem/tests/kat/` |
| FrodoKEM, Classic McEliece | official reference KATs (`.rsp`) | `crates/tpt-crypto-kem/tests/kat/` |
| HPKE (X25519) | RFC 9180 vectors | `crates/tpt-crypto-kem/tests/kat/` |
| ML-DSA, SLH-DSA | NIST ACVP | `crates/tpt-crypto-sig/tests/kat/` |
| Signature verification edge cases | Wycheproof | `crates/tpt-crypto-sig/tests/kat/` |

Beyond vectors, the repo also runs property tests, fuzz targets for
attacker-controlled decoders, mutation testing, `miri` on the unsafe crate, a
dudect-style timing-leakage harness, and `no_std` builds for embedded and wasm
targets in CI. See [`todo.md`](./todo.md) for the current status of each.

To reproduce it yourself:

```sh
cargo test --workspace --all-features
cargo test -p tpt-crypto-sig --features alloc,profile-modern  # RSA KATs (see note)
cargo xtask kat-check     # vector files match their recorded sha256
cargo xtask verify        # specs/*.spec contracts bound to test evidence
cargo xtask leakage       # timing-leakage harness
```

Note: `--all-features` enables `profile-cnsa2`, which compiles out the 2048-bit
RSA KATs, so CI runs the sig crate separately under `profile-modern`.

**What this does and does not show.** Passing these checks shows the code agrees
with the published vectors and behaves consistently under the listed tests. It
is not a proof of security, it does not rule out side channels on every
platform, and it is not a substitute for an independent audit (see the warning
above).

## Build & check

```sh
cargo build   --workspace --all-features
cargo test    --workspace --all-features
cargo xtask   check     # fmt --check + clippy -D warnings + cargo deny
cargo xtask   no-std    # builds no_std crates for thumbv6m-none-eabi
cargo xtask   leakage   # dudect-style Welch t-test side-channel harness
cargo xtask   kat-check # verify tests/kat/PROVENANCE.md sha256s
cargo +nightly miri test -p tpt-crypto-ct
cargo +nightly fuzz run <target>   # fuzz/ — attacker-controlled decoder targets
```

## License

Licensed under either of [MIT](./LICENSE-MIT) or
[Apache-2.0](./LICENSE-APACHE) at your option.
