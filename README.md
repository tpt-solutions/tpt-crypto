# tpt-crypto — the high-assurance, constant-time cryptographic substrate

Pure Rust, `no_std`-first, hand-rolled primitives with a 100% MIT/Apache
compatible dependency chain. No OpenSSL, no `ring`, no `*-sys` C-FFI.

> **Status (this pass):** local `git` only — no GitHub remote, no
> `cargo publish`. Metadata is prepped so publishing is a later one-step.

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
kem / sig   on field + curve + hash
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
| `tpt-crypto-curve` | Ed25519, X25519, P-256/384 (complete). BLS12-381 + pairing and RFC 9380 hash-to-curve in progress. |
| `tpt-crypto-aead` | AES-GCM, ChaCha20-Poly1305, AES-GCM-SIV, `CtrDrbg`. |
| `tpt-crypto-kem` | ML-KEM (FIPS 203), FrodoKEM, Classic McEliece. |
| `tpt-crypto-sig` | ML-DSA (FIPS 204), SLH-DSA, Ed25519, ECDSA (P-256/384); BLS12-381 pending pairing. |
| `tpt-crypto-zk` | Bulletproofs, minimal PLONK verifier, Pedersen commitments. |
| `tpt-crypto-mpc` | Additive secret sharing, Beaver triples, OT primitives. |
| `tpt-crypto` | Facade re-exporting the substrate behind feature gates. |

### Facade features

Pick a subset or take everything with `full`:

| Feature | Pulls in |
| --- | --- |
| `classical` | `hash`, `aead`, `field`, `curve`, `sig` (Ed25519 / ECDSA / ML-DSA) |
| `pq` | `kem` + `ml_kem` (needs `alloc`), `sig` + `ml_dsa` |
| `bls` | BLS12-381 signatures (stub until `-curve` lands pairing) |
| `zk` | Bulletproofs, Pedersen commitments |
| `mpc` | secret sharing, Beaver triples, OT |
| `full` | all of the above |

The `ml_kem`, `ml_dsa`, `bulletproofs`, `bls`, `ct` and `prelude` modules expose
the exact names from `spec.txt` §4 so downstream code compiles verbatim against it.

See [`spec.txt`](./spec.txt) for the full design and target API.

## Guarantees

- **Constant-time by construction.** No secret-dependent branches or indexing.
  Secret-dependent selection goes through `ct_select` / masking, whose
  execution trace is independent of the secret (see
  `tpt-crypto-core::constant_time` and the `*.telos` contracts under `specs/`).
- **`no_std` everywhere** (plus `alloc` where a heap is needed). Builds for
  `thumbv6m-none-eabi`, `thumbv7em-none-eabihf`, `wasm32-unknown-unknown`.
- **100% MIT/Apache dependency chain.** Enforced by `deny.toml` (C-FFI,
  OpenSSL, and `ring` are banned).

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
