# Build & Layering — tpt-crypto

Agent-facing quick reference. The authoritative task list is `todo.md`; the
design document is `spec.txt`.

## Build commands

```sh
cargo build --workspace --all-features
cargo test  --workspace --all-features
cargo fmt --check            # cargo xtask fmt  to fix
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo xtask check            # fmt --check + clippy -D warnings + cargo deny
cargo xtask no-std           # builds no_std crates for thumbv6m-none-eabi
cargo xtask leakage          # dudect-style Welch t-test side-channel harness
cargo xtask kat-check        # verify tests/kat/PROVENANCE.md sha256s
cargo +nightly miri test -p tpt-crypto-ct
cargo +nightly fuzz run <target>   # fuzz/ — attacker-controlled decoder targets
```

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

## Hard rules

- Every crate is `#![no_std]` (plus `alloc` where needed) and opts into workspace
  lints (`[lints] workspace = true`).
- `unsafe_code = "forbid"` for the whole workspace **except** `tpt-crypto-ct`,
  which overrides it locally and documents every `unsafe` block with `// SAFETY:`.
- No `*-sys`, OpenSSL, or `ring` dependencies — pure Rust only (enforced by
  `deny.toml`). All deps must be MIT/Apache-compatible.
- Constant-time is a hard requirement: no secret-dependent branches or indexing;
  use `ct_eq`/`ct_select`/`ct_lookup`. New primitives need KAT vectors +
  `PROVENANCE.md`.
- New crates: scaffold under `crates/<name>/`, register in
  `../tpt-rust-map/registry.toml` with `status = "git"`, and never add a
  dependency without a license note.
- Every crate ships its own `README.md` (mirrored as `readme` in `Cargo.toml`)
  and `CHANGELOG.md` (`## 0.1.0 — unreleased`), plus crates.io metadata:
  `description`, `categories` (valid crates.io slugs, e.g. `cryptography`,
  `no-std::no-alloc`), and `keywords` (≤5, lowercase, ≤20 chars).
- The facade (`tpt-crypto`) is feature-gated: `classical`, `pq`, `bls`, `zk`,
  `mpc`, `full`, plus `std` / `alloc` propagated to every sub-crate. The
  `ml_kem` / `ml_dsa` / `bulletproofs` / `bls` / `ct` / `prelude` modules expose
  the `spec.txt` §4 names verbatim.

## Workspace layout

- `crates/*` — the 11 library crates (10 primitives + facade).
- `xtask/` — developer tooling (no-std, kat-check, leakage, verify, release-dry-run, sbom).
- `examples/` — end-to-end usage samples (one per `spec.txt` §4 snippet).
- `fuzz/` — `cargo-fuzz` libfuzzer targets for attacker-controlled decoders
  (AEAD decrypt, ML-KEM decaps, signature verify, point decompress).
- `specs/` — `*.telos` formal contracts, verified by `cargo xtask verify`.
- `benches/` — criterion benches; `BUDGET.md` records perf targets.
