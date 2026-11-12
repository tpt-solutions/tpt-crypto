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
  SLH-DSA (SPHINCS+); Ed25519; ECDSA P-256/P-384; BLS12-381.
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
- `tpt-crypto-zk` KAT suite: `tests/kat/VECTORS.txt` (6 aggregated/single
  Bulletproofs range-proof vectors across `n ∈ {8, 32, 64}` and `m ∈ {1, 2, 4}`,
  plus inner-product-argument, Pedersen, and transcript vectors) with
  `tests/kat/PROVENANCE.md`; the file's SHA-256 is registered with
  `cargo xtask kat-check`. Regenerate with
  `cargo test -p tpt-crypto-zk --test generate_kat`.
- Fuzz targets for the remaining attacker-controlled decoders:
  `ecdsa_der_parse` (P-256/P-384 ASN.1 DER signature parsing),
  `ecdsa_public_key_parse` (SEC1 public-key decoding), and
  `range_proof_parse` (Bulletproofs proof parsing → verification, exercising
  point decompression and scalar canonicality with untrusted input).
- `BUDGET.md`: per-primitive performance targets vs `subtle`/`dalek`/`pqcrypto`.
- `AGENTS.md`: workspace conventions, build commands, layering rules, hard rules.
- `tpt-crypto-sig`: hybrid Ed25519 + ML-DSA-65 signatures (both halves required);
  full SLH-DSA (FIPS 205); RSA PKCS#1 v1.5 and PSS verification (SHA-256/384/512);
  ECDSA verification (lenient: accepts high-S signatures); BLS12-381 signatures
  (draft-irtf-cfrg-bls-signature-04, Basic, Aug and PoP ciphersuites, aggregation).
- `tpt-crypto-sig`: key encoding for Ed25519, RSA, P-256 and P-384 (SPKI, PKCS#8,
  PEM, strict DER) and strict JWK public keys.
- `tpt-crypto-kem`: X-Wing hybrid KEM (X25519 + ML-KEM-768); HPKE (RFC 9180) base,
  PSK, auth and auth-PSK modes; FrodoKEM-640/976/1344 and Classic McEliece (all five
  parameter sets), checked against the official reference KATs.
- `tpt-crypto-hash`: Argon2id (RFC 9106); BLAKE2b with a runtime output length
  (`blake2b_var`).
- `tpt-crypto-aead`: STREAM chunked AEAD (age framing, ChaCha20-Poly1305);
  `NonceSequence` counter nonces that refuse to wrap; Wycheproof AES-GCM and
  ChaCha20-Poly1305 vectors.
- `tpt-crypto-curve`: BLS12-381 pairing (inversion-free Miller loop, cyclotomic
  final exponentiation) and RFC 9380 hash-to-curve for G1 and G2.
- `tpt-crypto-core`: opt-in `os-rng` feature providing `OsRng`.
- `tpt-crypto` facade: `easy` one-call recipes (`seal`/`open` with random
  XChaCha20-Poly1305 nonces, `hash`, `hmac`, `hkdf_derive`, Ed25519 `sign`/`verify`,
  `random_bytes`); `selftest::run()` power-on KATs (SHA-256, HMAC, HKDF, X25519,
  Ed25519); opt-in `cnsa2` feature with an approved-only `tpt_crypto::cnsa2` module
  (AES-256-GCM, SHA-384/512, ML-KEM-1024, ML-DSA-87; not a compliance claim); `signature`,
  `os-rng`, `profile-modern` and `profile-cnsa2` features.
- `tpt-crypto-cli` (new binary crate): `selftest`, `hash`, `random`, Ed25519
  `sign-keygen`/`sign`/`verify` with hex or PEM keys, `pem-export`/`pem-import`
  (PKCS#8 and SPKI, readable by OpenSSL), `seal`/`open`, X-Wing
  `kem-keygen`/`kem-encap`/`kem-decap`, and `bench`.
- `tpt-crypto-wasm` (new crate): wasm-bindgen bindings for the `easy` API (seal/open,
  hash, HMAC, HKDF, Ed25519) for `wasm32-unknown-unknown`, with a Node known-answer
  smoke test. npm packaging is not included.
- `examples`: a minimal TLS 1.3 `rustls::crypto::CryptoProvider` built on the
  substrate (`examples/src/rustls_provider.rs`).
- Fuzz targets for X-Wing encapsulation and decapsulation, hybrid signature
  verification, key-encoding parsers (DER SPKI/PKCS#8, PEM), Argon2id parameters, and
  FrodoKEM and McEliece decapsulation.
- `xtask`: `ct-asm` (binary-level constant-time scan of probe functions), `exhaustive`
  (release-mode bounded-domain checks), `doctor`, `coverage`, `new-primitive` and
  `wycheproof-fetch`. `verify` understands `exhaustive:` and `ct-asm:` evidence.

### Fixed
- X25519 Montgomery ladder: added per-RFC 7748 `swap = bit` reset at the top of
  each ladder step (`crates/tpt-crypto-curve/src/montgomery25519.rs`).
- Removed `crates/tpt-crypto-curve/tests/dbg_trace.rs` (referenced a non-existent
  `dbg_final` helper, blocking `cargo test`).
- `tpt-crypto-ct::ct_eq_slices` reported equal slices as unequal and truncated the
  length difference to 8 bits.
- `tpt-crypto-aead`: the portable AES core was wrong on targets without AES-NI;
  CTR-DRBG increment order corrected.
- `tpt-crypto-sig`: ML-DSA conforms to FIPS 204 (ACVP vectors pass); the challenge
  hash `c~` length is corrected.
- `tpt-crypto-hash`: `hkdf_expand` enforces the 255 × HashLen bound and no longer
  overflows its block counter.

### Changed
- `tpt-crypto-kem`: ML-KEM `encapsulate` validates the public key (FIPS 203 §7.2) and
  returns `Result` instead of panicking on an invalid key.

### Security
- `#![forbid(unsafe_code)]` enforced workspace-wide; `tpt-crypto-core` and
  `tpt-crypto-ct` carry local `unsafe_code = "allow"` overrides with `// SAFETY:`
  annotations limited to `core::ptr::write_volatile` zeroization.
- Constant-time invariants enforced via `CtEq`, `CtSelect`, `ct_select`, `cmov`,
  `cswap` — no secret-dependent branches or indexing in any `no_std` path.
- Secret-dependent branches removed from field add/sub, limb comparisons and `pow`
  (constant in the exponent), McEliece field multiply, decapsulation select and
  key-generation sort, FrodoKEM packing, and ML-KEM `freeze`.
- `tpt-crypto-sig`: Ed25519 verification rejects small-order public keys.

### Known issues
- `tpt-crypto-zk::plonk` verifier scaffold exists but is not yet exercised by
  the facade or CI.
