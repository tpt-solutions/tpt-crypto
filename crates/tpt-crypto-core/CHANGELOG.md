# Changelog — tpt-crypto-core

All notable changes to this crate are documented here. This crate follows the
workspace version `0.1.0` (unreleased) this pass.

## 0.1.0 — unreleased

### Added
- `Error` enum (non-secret: `Verification`, `InvalidLength`, `InvalidEncoding`,
  `RngFailure`, `NotOnCurve`, …) and a `Result` alias.
- `Zeroize` trait and a portable, `volatile` byte-wipe; `Zeroizing<T>` wrapper
  that wipes on `Drop`.
- `SecretBox<T>` — owns a secret, zeroes on `Drop`, implements none of the leaky
  traits (`Debug`/`Display`/`PartialEq`/`Hash`/`AsRef`/`Borrow`); reading
  requires the explicit `expose_secret` method. The contract is pinned by
  `trybuild` compile-fail tests.
- `ct` module: `Choice`, `CtEq`, `ConstantTimeSelect`, and the `ct_eq` / `ct_ne`
  / `ct_select` facades (portable, constant-time; `tpt-crypto-ct` adds optimized
  variants).
- `CryptoRng` and `DrbgCore` traits.
- `rand_core` feature: `RandCoreRng` / `CoreRng` adapters between `CryptoRng`
  and the `rand_core` ecosystem.
- `constant_time` doc module: guarantees, threat model, review checklist.
- `specs/secret_no_branch.telos`: type-level contract that secret handling
  encodes no secret-dependent branch.
