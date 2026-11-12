# Changelog

## 0.1.0 — unreleased

### Added

- Initial command set: `selftest`, `hash`, `random`, `sign-keygen`, `sign`,
  `verify`, `seal-keygen`, `seal`, `open`.
- `kem-keygen`, `kem-encap`, `kem-decap`: X25519 + ML-KEM-768 hybrid (X-Wing style).
- `bench [iterations]`: quick timings of the main operations.
- PEM support for Ed25519 keys: `sign-keygen --pem` writes PEM, `pem-export` and
  `pem-import` convert between hex and PEM (PKCS#8 private, SPKI public), and
  `sign` / `verify` accept either format. The layouts are the ones OpenSSL emits; no DER. Not tested against OpenSSL in this repo.
