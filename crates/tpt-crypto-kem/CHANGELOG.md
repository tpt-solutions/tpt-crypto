# Changelog — tpt-crypto-kem

All notable changes to this crate are documented here. Follows the workspace
version `0.1.0` (unreleased) this pass.

## 0.1.0 — unreleased

### Added
- ML-KEM (FIPS 203): constant-time polynomial core (`poly`) with compile-time
  NTT / inverse-NTT / base multiplication and Montgomery reduction over
  `R_q = Z_q[X]/(X^256 + 1)`, `q = 3329`.
- K-PKE and the Fujisaki–Okamoto transform; branch-free implicit-reject path.
- Parameter sets `MlKem512`, `MlKem768`, `MlKem1024`.
- Byte encoding / decoding (`encode`), CBD sampler (`sampler`).
- `specs/ml_kem_decapsulate.spec`; `cargo-fuzz` decapsulation target.
- FIPS 203 KAT coverage.
- ML-KEM encapsulation checks the public key (FIPS 203 §7.2, `check_encaps_key`).
  `encapsulate` returns `Result` and rejects a malformed key instead of
  panicking. Freeze and bit packing are branch-free.
- FrodoKEM-640, -976 and -1344 (`frodo`), with SHAKE and AES matrix variants.
  Checked byte for byte against the first official KAT records.
- Classic McEliece 348864, 460896, 6688128, 6960119 and 8192128 (`mceliece`).
  Checked against the first three official KAT records of each set. The field
  multiply, decapsulation select and key-generation sort are constant-time.
- HPKE (`hpke`, RFC 9180): base, PSK, auth and auth-PSK modes with
  `DHKEM(X25519, HKDF-SHA256)` and ChaCha20-Poly1305 or AES-128-GCM.
- X-Wing-style hybrid KEM (`xwing`): X25519 + ML-KEM-768 following
  draft-connolly-cfrg-xwing-kem. The draft has no published vectors, and the
  wire format may change until it is final.

### Removed (pre-release)
- FrodoKEM (`frodo`) and Classic McEliece (`mceliece`) placeholder modules and
  their features. They only returned `Error::Unsupported`, and `--all-features`
  enabled them. Both are implemented later in this release (see Added).
