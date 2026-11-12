# `crates/`

This directory hosts the 11 library crates of the `tpt-crypto` workspace, plus
two application crates that sit on top of them:

```
tpt-crypto-core      tpt-crypto-ct        tpt-crypto-field
tpt-crypto-curve     tpt-crypto-hash      tpt-crypto-aead
tpt-crypto-kem       tpt-crypto-sig       tpt-crypto-zk
tpt-crypto-mpc       tpt-crypto           (facade)
tpt-crypto-cli       tpt-crypto-wasm      (application crates)
```

The primitive crates are `#![no_std]`, opt into `[lints] workspace = true`, and
follow the per-crate checklist in `todo.md`. `tpt-crypto-cli` (a `std` binary)
and `tpt-crypto-wasm` (wasm-bindgen bindings, `std`) are not `no_std`. No crate
is published yet (`status = "git"` in `../tpt-rust-map/registry.toml`).
