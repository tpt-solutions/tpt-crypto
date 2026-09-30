# ML-KEM KAT vectors — PROVENANCE

## `fips203_512.rsp` / `fips203_768.rsp` / `fips203_1024.rsp` — VERIFIED

Official FIPS 203 (ML-KEM) known-answer vectors in the ACVP-style `.rsp`
format: each record carries the seeds `d`/`z`, the encapsulation message
`msg`, the derived keypair (`pk`/`sk`), a valid ciphertext/shared-secret pair
(`ct`/`ss`), and an invalid ciphertext with its implicit-rejection shared
secret (`ct_n`/`ss_n`) — 1000 records per parameter set.

Internal consistency of every record was re-checked (sk embeds
`pk`, `SHA3-256(pk)`, and `z`) and the full harness
(`crates/tpt-crypto-kem/tests/ml_kem_kat.rs`) validates keygen, encapsulation,
decapsulation, and implicit rejection against them; the generator convention
(`G(d ‖ ⟨k⟩)`, `ByteEncode₁₂(t̂) ‖ ρ`, `dk = dk_PKE ‖ ek ‖ H(ek) ‖ z`) matches
final FIPS 203 exactly, cross-checked against the `kyber-py` reference.

**History:** an earlier set of `ml_kem_*.kat` files (commit `b9f910c`) had **no
recorded source and was not trustworthy** — their expected `pk` matched no
standard construction. They were replaced by these files in `1e1d860`. (The
harness failure after that commit was a genuine implementation bug: the K-PKE
encodings used `ρ ‖ t̂` byte order and applied ciphertext compression to the
`t̂`/`ŝ` packing — fixed and re-validated against these vectors.)

Checksums (sha256, relative to `crates/tpt-crypto-kem/tests/kat/`):

| File | Sha256 |
| --- | --- |
| `fips203_512.rsp` | `c4416e2f6c2c5c78bf3e8669adcd132dc6a3cd3cd1a50394f4c4dec6f5253358` |
| `fips203_768.rsp` | `2d408a01b13b1ee4194bd22226298064b563a07c60df08b91a91a193fad338e1` |
| `fips203_1024.rsp` | `4f721bfa19bc00063f48a67c25c65e336ac49bb0e3c4dd94d0b78288d6827c67` |
