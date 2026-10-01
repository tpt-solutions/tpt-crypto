# Changelog — tpt-crypto-mpc

All notable changes to this crate are documented here. Follows the workspace
version `0.1.0` (unreleased) this pass.

## 0.1.0 — unreleased

### Added
- Additive secret sharing over any prime field: `Share`, `share_secret`,
  `share_secret_2`, `reconstruct`, constant-time `Share::add` / `Share::scale`,
  `FieldCodec` / `SampleField` traits.
- Beaver triples (`BeaverTriple`): trusted-dealer (`deal`), base-OT
  (`deal_from_base_ot`), and batched IKNP (`deal_many_from_iknp`); `multiply`.
- Oblivious transfer: Chou–Orlandi 1-of-2 base OT over Curve25519 (`ot`),
  1-of-N from 1-of-2 (`transfer_1ofn`), IKNP OT extension (`iknp`,
  `extend_1of2`).
- `specs/secret_share_reconstruct.spec`.
