# Contributing to `tpt-crypto`

`tpt-crypto` is the internal high-assurance, constant-time cryptographic
substrate for the TPT Solutions stack. This document describes how to propose
changes.

## Issues only — no external pull requests

`tpt-crypto` follows an **issues-only** workflow. There is no external
pull-request review process:

- To report a bug, request a feature, or propose an API change, **open an
  issue** on the repository's issue tracker.
- For suspected vulnerabilities or soundness bugs, see `SECURITY.md` first (do
  **not** open a public PR for a security fix).
- Maintainers triage issues, make the change on a branch, and land it via the
  internal review process.

Please do not open a pull request from a fork expecting it to be merged; it will
be closed in favour of an issue.

## Per-crate checklist

Every crate in this workspace is built to the same shape (see `todo.md` for the
full template). When adding or modifying a crate, confirm:

- [ ] The crate builds `no_std` where `registry.toml` marks `no_std = true`
      (verified by `cargo xtask no-std`).
- [ ] `cargo fmt --check` is clean (`cargo xtask fmt` to fix).
- [ ] `cargo clippy --workspace --all-targets --all-features -- -D warnings` is
      clean (run via `cargo xtask clippy`).
- [ ] `cargo test --workspace --all-features` passes, including doctests.
- [ ] `cargo-deny` (`cargo xtask deny`) is clean.
- [ ] Public items have rustdoc; panicking operators document `# Panics`.
- [ ] `no_std` crates opt into the workspace lints (`[lints] workspace = true`).
- [ ] Every new primitive ships KAT vectors + `tests/kat/PROVENANCE.md` (source
      URL, license, sha256 of each vector file).
- [ ] Every constant-time primitive has a `specs/<primitive>.telos` contract and
      a `proptest` round-trip; side-channel-sensitive primitives also have a
      `cargo xtask leakage` class.
- [ ] `registry.toml` is updated: a new crate reads `status = "git"`.

The one-stop command is `cargo xtask check`.

## Constant-time / no-leak policy

This substrate's central guarantee is **constant-time execution**: no
secret-dependent branch, memory-access pattern, or index. New primitives must:

- Use `ct_select` / masking from `tpt-crypto-ct` for any secret-dependent
  choice — never `if`, `match`, or indexed access on a secret.
- Add a `tpt-telos` contract under `specs/` stating that the execution trace is
  independent of the secret; `cargo xtask verify` discharges it.
- Add a `leakage` class (Welch t-test) where the primitive is side-channel
  exposed.

## License policy (`deny.toml`)

All workspace crates are `MIT OR Apache-2.0`. `deny.toml` enforces:

- `advisories.yanked = "deny"` — yanked dependency versions are rejected.
- `sources.unknown-registry = "deny"` and `sources.unknown-git = "deny"` —
  every dependency must come from crates.io or a declared git source.
- A curated `licenses` allow-list (permissive licenses only). **No C-FFI
  (`*-sys`), OpenSSL, or `ring`** dependencies (see `[bans]`).
- **No new dependency without a license note.** External deps must be added to
  `registry.toml` and re-checked against the allow-list.

When adding a new external dependency, confirm its license is on the
allow-list before merging, and update the note in `deny.toml` if you add a new
upstream family.

## Adding a new crate

1. Scaffold under `crates/<name>/` following the existing crates' layout.
2. Inherit workspace fields in `Cargo.toml` and add `[lints] workspace = true`.
3. Register the crate in the root `Cargo.toml` `members` array **and** in
   `../tpt-rust-map/registry.toml` with `status = "git"`.
4. Run the per-crate checklist above.
