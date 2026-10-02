# Changelog — tpt-crypto-aead

All notable changes to this crate are documented here. Follows the workspace
version `0.1.0` (unreleased) this pass.

## 0.1.0 — unreleased

### Fixed
- **Portable AES core (non-AES-NI targets) produced wrong ciphertext:**
  `shift_rows` rotated rows in the inverse direction (it implemented
  InvShiftRows) and `mix_columns` mixed bits *across* columns (per-row)
  instead of within each column. Every FIPS-197 / SP 800-38A vector failed
  on the portable path, which is the only path on `thumbv6m` and any
  x86_64 CPU without AES-NI (the runtime-dispatched AES-NI path was
  correct, which is why the x86 test suites were green). Fixed both and
  added FIPS-197 C.3 + SP 800-38A F.1.1 AES-256 KATs so the portable path
  is covered by the default test run.
- **CTR-DRBG counter increment order:** SP 800-90A §10.2.1.2 / §10.2.1.5.1
  increment `V` *before* encrypting each keystream block; `CtrDrbg`
  encrypted first. The generator was therefore non-conformant with the
  spec (deterministic, but not interoperable with a reference no-DF
  CTR_DRBG).
### Fixed
- **RFC 8452 conformance:** the POLYVAL hash key was `E(K_mac, 0^16)` (the
  GCM GHASH convention); RFC 8452 §4 uses the raw derived
  message-authentication key directly, with no AES call. Every non-empty
  message encrypted to a non-standard ciphertext/tag (self-consistent, so
  round-trip tests passed — the old inline KAT only covered the
  empty-plaintext vector, where the hash key is never touched). The full
  RFC 8452 Appendix C corpus (`tests/kat/rfc8452.txt`, 50 vectors incl. the
  C.3 counter-wrap tests, driven by `tests/rfc8452.rs`) now passes in both
  directions.

### Added
### Added
- Const-generic `Aead<NONCE_LEN, TAG_LEN>` trait: in-place and detached-tag
  encrypt/decrypt, AAD, constant-time `Tag::ct_eq`, `Nonce` / `Tag` newtypes
  (no `PartialEq` on `Tag`).
- AES-GCM (`Aes128Gcm`, `Aes256Gcm`) — table-free constant-time AES S-box
  (algebraic GF(2⁸) inversion) with an `x86_64` AES-NI dispatch through
  `tpt-crypto-ct::arch`; branch-free GHASH with a `pclmulqdq` path.
- ChaCha20-Poly1305 (RFC 8439) and XChaCha20-Poly1305; standard
  poly1305-donna 5×26-bit arithmetic with cross-call buffering.
- AES-GCM-SIV (RFC 8452) with POLYVAL; authenticates the plaintext, restores
  the buffer on tag mismatch.
- `CtrDrbg` (AES-256 CTR-DRBG, SP 800-90A).
- Optional `aead-trait` feature: `aead` 0.6 crate trait impls.

### Fixed
- Poly1305 limb layout (previously dropped high bits of several message bytes,
  hiding tampering) and multi-slice `update` handling; AEAD length block now
  uses byte counts per RFC 8439.
- GHASH bit order (multiplier now consumed MSB-first).
- GCM-SIV `decrypt` recomputed POLYVAL over ciphertext instead of plaintext.
- XChaCha20-Poly1305 inner-nonce initialization.
