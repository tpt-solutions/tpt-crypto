# KAT Provenance — `tpt-crypto-mpc`

This directory holds the known-answer / reference-run vectors for the MPC
primitives. Vectors are produced by the implementation under test and pinned as
regression checks in `tests/kat.rs`; they are *not* externally sourced RFC
vectors (no standardized test vectors exist for additive secret sharing or for
the in-process OT transcripts used here).

## What is checked

- **`base_ot_kat`** — Chou–Orlandi 1-of-2 base OT over Curve25519. The receiver's
  output is cross-checked against an *independent* re-derivation of the OT key
  schedule (`reference_base_ot` in `tests/kat.rs`, a separate code path over the
  same curve math) and against the chosen message. Both branches (`false`, `true`)
  are pinned.
- **`oneofn_kat`** — 1-of-N OT built from `N` parallel base OTs, checked for
  `N = 4` and every choice index.
- **`share_reconstruct_kat`** — additive secret sharing (`share_secret` /
  `reconstruct`) for party counts 2, 3, 5, 7 and several field elements, including
  an independent check that the final share equals `x - sum(other shares)`.
- **`beaver_from_base_ot_kat`** — Beaver triple offline generation from base OT
  (`deal_from_base_ot`), asserting `a * b == c` and that an online Beaver
  multiplication reconstructs `x * y`.
- **`iknp_kat`** — IKNP OT extension (`extend_1of2`, `κ = 128`) for 8 extended
  OTs, asserting the receiver learns exactly the message for its choice bit.

## Cross-implementation

The strongest cross-checks are the property tests in `tests/props.rs`:

- `reconstruct(share(x)) == x` for `n ∈ [2, 8]` (random `x`).
- Beaver-multiplied shares reconstruct to `x * y` (`multiply` over a dealer
  triple, a base-OT triple, and an IKNP triple batch).
- 1-of-2 / 1-of-N / IKNP: the receiver learns *exactly* the chosen message and
  nothing else.

## Generation

Vectors are generated deterministically from a splitmix64-style `Drng` seeded
with the public inputs, so re-running `cargo test -p tpt-crypto-mpc` reproduces
the pinned values exactly.
