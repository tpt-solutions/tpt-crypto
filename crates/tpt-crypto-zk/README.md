# tpt-crypto-zk

Zero-knowledge proofs over Ed25519 for the
[`tpt-crypto`](../../README.md) substrate.

Layer: `zk` on `curve + hash` (also `core + ct + field`). Pure Rust,
`#![no_std]` + `alloc`, `unsafe_code = "forbid"`. The group is the
prime-order subgroup of Ed25519 (order `L`), so discrete logs are well defined
and the cofactor never introduces ambiguity. All secret-dependent operations
are constant-time.

## What's inside

- [`Transcript`] — Fiat–Shamir transcript (Merlin-style STROBE-lite) over
  SHAKE256: `append_message` / `challenge_scalar`.
- [`PedersenGens`] / [`Ristretto`] — Pedersen commitments over the prime-order
  subgroup (`commit(v, r) = v·G + r·H`).
- [`InnerProductProof`] — the inner-product argument (core building block).
- [`prove_range`] / [`verify_range`] — Bulletproofs range proofs, single and
  aggregated (`n` ∈ {8, 16, 32, 64}, `n·m` a power of two), with
  `range_proof_to_bytes` / `range_proof_from_bytes`.
- [`plonk`] — a minimal PLONK verifier (~500 LoC) built on inner-product
  commitment opening.

## Example

```rust
use tpt_crypto_zk::{prove_range, verify_range, SeedExpander};

let values = [1234u64];
let blindings = [/* Ed25519Scalar per value */];
let mut rng = SeedExpander::new(b"demo-seed");
let (proof, commitments) = prove_range(&values, &blindings, 64, &mut rng);
assert!(verify_range(&commitments, &proof, 64).is_ok());
```

## Features

| Feature | Effect |
| --- | --- |
| `alloc` | default (required — the proofs are heap-backed) |

## Status

Not audited, research-grade. Property tests cover IPA soundness round-trips,
range-proof completeness, and serialization; `specs/` carries
`bulletproofs_verify.telos`.

## License

MIT OR Apache-2.0.
