# tpt-crypto-mpc

Secure multi-party computation primitives for the
[`tpt-crypto`](../../README.md) substrate.

Layer: `mpc` on `field + hash` (also uses `core + ct + curve`). Pure Rust,
`#![no_std]` (plus `alloc`), `unsafe_code = "forbid"`, constant-time by
construction.

## What's inside

- **Additive secret sharing** over any prime field — [`Share`],
  [`share_secret`], [`reconstruct`], [`share_secret_2`]. Share-local ops
  (`Share::add`, `Share::scale`) are constant-time.
- **Beaver triples** — [`BeaverTriple`] for precomputed constant-time
  multiplication of secret-shared values: trusted-dealer (`deal`), base-OT
  (`deal_from_base_ot`), or batched IKNP (`deal_many_from_iknp`).
- **Oblivious transfer** — Chou–Orlandi 1-of-2 base OT over Curve25519
  (`ot`), 1-of-N from 1-of-2 (`ot::transfer_1ofn`), and the IKNP OT extension
  (`iknp`) turning a few base OTs into many.

Protocols are written for an idealized in-process channel: sender and receiver
halves run in the same process and exchange wire messages through typed step
functions. Wiring the messages over a real network is a mechanical drop-in.

## Constant-time contract

Arithmetic, share operations, and the OT key schedule never branch or index on
secret data. Rejection sampling during field-element generation may loop a
variable number of times — this leaks only the public fact that a sample was
reduced, never a value.

## Features

| Feature | Effect |
| --- | --- |
| `std` | default |
| `alloc` | heap support without `std` |

## Status

Not audited, research-grade. Property tests cover share homomorphism, Beaver
multiplication, and OT correctness; `specs/` carries
`secret_share_reconstruct.telos`.

## License

MIT OR Apache-2.0.
