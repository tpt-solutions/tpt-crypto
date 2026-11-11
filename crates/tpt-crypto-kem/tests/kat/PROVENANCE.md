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
| `fips203_512.rsp` | `783106e35afb1ab9aba557630f5380f3ffa40b83abfbe75a03059b5986702017` |
| `fips203_768.rsp` | `6ecab47c229a80b85afd8e9b1b76e604317b2505ac35382b0e288116e1ba860a` |
| `fips203_1024.rsp` | `ed23c551c53761649a2dd9573eda2f49f58285675d639fe8c0d585e21f37896c` |
| `hpke_base_x25519.txt` | `702993dd0e57ecd61961a8a33098490fa25a870b7b897f430c52978ec2b7e8e9` |
| `frodokem640_shake_first3.rsp` | `cc76e206a63626230cf9e5f1a1572cb721c5f9bebad9d46aea30bdd7401dfbe4` |

## `hpke_base_x25519.txt` — RFC 9180 HPKE base mode (DHKEM(X25519, HKDF-SHA256))

- Source: `cfrg/draft-irtf-cfrg-hpke`, `test-vectors.json` (the RFC 9180
  vector set), <https://raw.githubusercontent.com/cfrg/draft-irtf-cfrg-hpke/master/test-vectors.json>.
  Downloaded 2026-11-10. The JSON's sha256 is
  `61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6`.
- Selection: records with `mode 0` (base), `kem_id 0x0020` (DHKEM X25519),
  `kdf_id 0x0001` (HKDF-SHA256), and `aead_id` 0x0003 (ChaCha20-Poly1305) and
  0x0001 (AES-128-GCM). For each, the first four `seal` records (sequence 0-3).
  The extraction script is the one-off Python snippet recorded in the commit
  message; the output is the checked-in `.txt`.
- The file's sha256 is in the table above. Changing it requires re-running the
  extraction and updating the row.
- Tests: `src/hpke.rs` (`rfc9180_sender_matches_vectors`,
  `rfc9180_receiver_opens_vectors`) check `enc`, key, base nonce, exporter
  secret, per-sequence nonce, and ciphertext. The source vectors' `exports`
  field is not used.
| `hpke_modes_x25519.txt` | `f6e6f289a09d8d42d16ce57bb972fea5ba898e56cf10866ab65eff0e9b2dcc65` |

## `hpke_modes_x25519.txt` — RFC 9180 PSK, auth and auth-PSK modes

- Source: the same `test-vectors.json` as `hpke_base_x25519.txt` (sha256
  `61fc662f01996cd06d713dacf5e133167bd309a1f329442d53f1e21a47b3ede6`).
- Selection: `mode` 1 (PSK), 2 (auth) and 3 (auth-PSK), each with
  `kem_id 0x0020`, `kdf_id 0x0001`, `aead_id` 0x0003 and 0x0001. The first
  four seal records per vector. Fields absent in a mode are `-`.
- Checked by `src/hpke.rs`: `rfc9180_sender_matches_vectors_all_modes` and
  `rfc9180_receiver_opens_vectors_all_modes`. The static public key is also
  checked against `skSm`.

## `frodokem640_shake_first3.rsp` — FrodoKEM-640-SHAKE (official reference KAT)

- Source: the first three records (`count = 0..2`) of `PQCkemKAT_19888_shake.rsp`
  from the Microsoft reference repository `Microsoft/PQCrypto-LWEKE`, path
  `FrodoKEM/KAT/`. Raw URL:
  <https://raw.githubusercontent.com/Microsoft/PQCrypto-LWEKE/master/FrodoKEM/KAT/PQCkemKAT_19888_shake.rsp>.
  Downloaded 2026-11-11, unmodified apart from truncation after record 2. The
  reference repository is MIT-licensed (its `LICENSE`, Microsoft Corporation).
- Field sizes checked against the reference constants: pk 9616, sk 19888, ct 9752,
  ss 16 bytes.
- Consumed by `crates/tpt-crypto-kem/tests/frodo_kat.rs`. The per-record randomness is
  derived from `seed` with the NIST PQC AES-256 CTR-DRBG, as in the reference
  `PQCgenKAT_kem` harness. The test checks keygen, encapsulation and decapsulation
  byte for byte, and the implementation follows the reference C in `FrodoKEM/src/`.
- Algorithm source: the same repository's `FrodoKEM/src/{kem,noise,util,frodo_macrify_reference}.c`
  (fetched 2026-11-11). `crates/tpt-crypto-kem/src/frodo.rs` is a port of that code.
