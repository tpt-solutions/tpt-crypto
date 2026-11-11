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
| `frodokem640_aes_first3.rsp` | `b4a311a5563d2088092c5d2eff413229852446ababe92fabaaff00cddce0d1da` |
| `frodokem1344_aes_first1.rsp` | `42e3c8dd6da88412a9788ec097a3069df45ce66704baf12e3621c0d3ff2f463e` |
| `frodokem1344_shake_first1.rsp` | `22ca61576c6aa43dfa68d619780c4226b9de52d4140ce44f9f9f5e03c4ee0526` |
| `frodokem976_aes_first1.rsp` | `f7985d57fcf2258e40cdb56aa40cb68aec8f8d119ca7a92d558b3177c64cb6cd` |
| `frodokem976_shake_first1.rsp` | `5deb0a0ac381d61aac5c2059ae5837e27afbcb48101f61530c60fd83151129df` |

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

## `frodokem640_aes_first3.rsp` — FrodoKEM-640-AES (official reference KAT)

- Source: the first three records (`count = 0..2`) of `PQCkemKAT_19888.rsp` from the
  same reference repository, path `FrodoKEM/KAT/`. Raw URL:
  <https://raw.githubusercontent.com/Microsoft/PQCrypto-LWEKE/master/FrodoKEM/KAT/PQCkemKAT_19888.rsp>.
  Downloaded 2026-11-11, truncated after record 2.
- Consumed by `crates/tpt-crypto-kem/tests/frodo_kat.rs` through `frodo::aes`, which
  uses AES-128-ECB for the matrix `A`. The other steps match the SHAKE variant.

## FrodoKEM-976 and FrodoKEM-1344 (official reference KAT, first record only)

- Source: the first record (`count = 0`) of each reference file in `FrodoKEM/KAT/` of
  `Microsoft/PQCrypto-LWEKE`: `PQCkemKAT_31296_shake.rsp`, `PQCkemKAT_31296.rsp`
  (976, SHAKE and AES) and `PQCkemKAT_43088_shake.rsp`, `PQCkemKAT_43088.rsp`
  (1344, SHAKE and AES). Downloaded 2026-11-11, truncated after record 0. Only one record
  per file is kept, to limit the size of the repository.
- Field sizes checked against the reference constants: 976 pk 15632, sk 31296, ct 15792,
  ss 24 bytes; 1344 pk 21520, sk 43088, ct 21696, ss 32 bytes.
- Consumed by `crates/tpt-crypto-kem/tests/frodo_kat.rs` through `frodo::{shake,aes}` with
  `Frodo976` and `Frodo1344`.
