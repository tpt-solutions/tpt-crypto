# `specs/`

This directory holds the `*.telos` formal contracts for `tpt-crypto` primitives,
verified by `cargo xtask verify` (which shells out to `tpt-telos-cli`).

Each contract encodes the security/functional properties a primitive must hold,
e.g.:

- `secret_no_branch.telos` — types encode "no secret-dependent branch".
- `ct_select.telos` — `ensures: execution_trace ⟂ cond`.
- `sha256.telos`, `keccak_f.telos` — hash correctness contracts.
- `field_mul.telos`, `field_reduce.telos` — field arithmetic contracts.
- `scalarmul_ct.telos` — scalar multiplication timing ⟂ scalar.
- `aead_tag_verify.telos` — accept iff tag valid; timing ⟂ tag.
- `ml_kem_decapsulate.telos`, `ntt_roundtrip.telos`.
- `bls_aggregate.telos`, `ecdsa_nonce_ct.telos`.
- `bulletproofs_verify.telos`, `secret_share_reconstruct.telos`.

Contracts are promoted from non-blocking to blocking in CI as each primitive lands
in `todo.md`.
