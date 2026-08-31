# Changelog

All notable changes to `tpt-crypto` are documented in this file.
The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and the project uses [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — unreleased

### Added
- Workspace scaffold: 10 library crates (`core`, `ct`, `hash`, `field`, `aead`,
  `curve`, `kem`, `sig`, `zk`, `mpc`) plus the `tpt-crypto` facade crate.
- `tpt-crypto-core`: `Choice`, `SecretBox`, `Zeroizing`, `CryptoRng`, `DrbgCore`,
  `ConstantTimeSelect`, `CtEq` traits and implementations.
- `tpt-crypto-ct`: architecture-gated constant-time primitives (`cmov`, `cswap`,
  `ct_eq_bytes`, `ct_select_slice`), with SSE4.1 / AVX2 / AVX-512 fast paths.
- `tpt-crypto-hash`: BLAKE2b, BLAKE3, KangarooTwelve, SHA-2, SHA-3, HKDF, HMAC.
- `tpt-crypto-field`: prime-field arithmetic for P-256, P-384, P-381 (BLS12-381
  base), Ed25519 scalar; `FieldElement`, `FieldParams`, `Fp2`/`Fp6`/`Fp12`
  extension types; Montgomery multiplication (`mont_mul`) and reduction.
- `tpt-crypto-aead`: AES-128/256-GCM, AES-128/256-GCM-SIV, ChaCha20,
  XChaCha20-Poly1305, Poly1305, AES-CTR-DRBG.
- `tpt-crypto-curve`: Ed25519 Edwards-point arithmetic, X25519 Montgomery ladder
  (RFC 7748-compliant), P-256/P-384 scalar/point ops.
- `tpt-crypto-kem`: ML-KEM (FIPS 203) with 512/768/1024 parameter sets;
  FrodoKEM-640/976/1344; McEliece.
- `tpt-crypto-sig`: ML-DSA (FIPS 204) with 44/65/87 parameter sets;
  SLH-DSA (SPHINCS+); Ed25519; ECDSA P-256/P-384; BLS12-381 (stub pending
  `-curve` pairing support).
- `tpt-crypto-zk`: Bulletproofs range proofs, Pedersen commitments,
  InnerProductArgument, minimal PLONK verifier.
- `tpt-crypto-mpc`: 1-of-2 OT (IKNP), Beaver triple generation,
  secret-sharing over prime fields.
- `tpt-crypto` facade: feature-gated re-export umbrella (`classical`, `pq`,
  `bls`, `zk`, `mpc`, `full`); `#![forbid(unsafe_code)]` at facade level.
- CI workflow: fmt, clippy, test (nextest + doc tests), no-std cross-target
  (thumbv6m/thumbv7em/wasm32), target-feature matrix, cargo-deny, miri,
  dudect leakage, feature-powerset, bench-smoke, fuzz-smoke, semver-checks.
- `xtask` developer tooling: `check`, `fmt`, `clippy`, `test`, `leakage`,
  `no-std`, `kat-check`, `verify`, `release-dry-run`, `sbom`.
- `deny.toml`: cargo-deny policy (license allow-list, `*-sys`/OpenSSL/ring bans).
- `BUDGET.md`: per-primitive performance targets vs `subtle`/`dalek`/`pqcrypto`.
- `AGENTS.md`: workspace conventions, build commands, layering rules, hard rules.

### Fixed
- X25519 Montgomery ladder: added per-RFC 7748 `swap = bit` reset at the top of
  each ladder step (`crates/tpt-crypto-curve/src/montgomery25519.rs`).
- Removed `crates/tpt-crypto-curve/tests/dbg_trace.rs` (referenced a non-existent
  `dbg_final` helper, blocking `cargo test`).

### Security
- `#![forbid(unsafe_code)]` enforced workspace-wide; `tpt-crypto-core` and
  `tpt-crypto-ct` carry local `unsafe_code = "allow"` overrides with `// SAFETY:`
  annotations limited to `core::ptr::write_volatile` zeroization.
- Constant-time invariants enforced via `CtEq`, `CtSelect`, `ct_select`, `cmov`,
  `cswap` — no secret-dependent branches or indexing in any `no_std` path.

### Known issues
- `tpt-crypto-field::mont_mul` reduction produces incorrect results for products
  whose true value exceeds the limb-width squared (first failure at `2^192 ×
  2^192` for P-384). Under investigation; callers using only sub-`2^32` operands
  (e.g. `prime_fields_cross_check`) are unaffected.
- `tpt-crypto-curve::bls` module is a stub; BLS12-381 pairing operations are
  required before aggregatable signatures are functional.
- `xtask kat-check` and `xtask verify` are stubs pending KAT corpus and
  `tpt-telos` toolchain integration.
- `tpt-crypto-zk::plonk` verifier scaffold exists but is not yet exercised by
  the facade or CI.
