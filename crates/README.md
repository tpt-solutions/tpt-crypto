# `crates/`

This directory hosts the 11 library crates of the `tpt-crypto` workspace:

```
tpt-crypto-core      tpt-crypto-ct        tpt-crypto-field
tpt-crypto-curve     tpt-crypto-hash      tpt-crypto-aead
tpt-crypto-kem       tpt-crypto-sig       tpt-crypto-zk
tpt-crypto-mpc       tpt-crypto           (facade)
```

It is intentionally **empty in Phase 0** — the crates are scaffolded in
Phase 1 (`-core`, `-ct`, `-hash`), Phase 2 (`-field`, `-curve`, `-aead`),
Phase 3 (`-kem`, `-sig`), and Phase 4 (`-zk`, `-mpc`, and the facade).

Each crate is `#![no_std]`, opts into `[lints] workspace = true`, and follows the
per-crate checklist in `todo.md`. No crate is published yet (`status = "git"` in
`../tpt-rust-map/registry.toml`).
