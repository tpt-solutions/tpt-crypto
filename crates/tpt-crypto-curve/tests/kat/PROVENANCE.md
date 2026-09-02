# Curve KAT provenance

## hash_to_curve (RFC 9380)

Vectors in `tests/hash_to_curve.rs` are transcribed from the CFRG
`draft-irtf-cfrg-hash-to-curve` reference proof-of-concept vector set (the
source material for RFC 9380 Appendices J and K):

- `poc/vectors/expand_message_xmd_SHA256_38.json` — `expand_message_xmd`
  (SHA-256), short DST `QUUX-V01-CS02-with-expander-SHA256-128`.
- `poc/vectors/expand_message_xmd_SHA256_256.json` — `expand_message_xmd`
  (SHA-256), 256-byte DST (exercises the `H2C-OVERSIZE-DST-` rule).
- `poc/vectors/P256_XMD:SHA-256_SSWU_RO_.json` — suite
  `QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_`.
- `poc/vectors/P384_XMD:SHA-384_SSWU_RO_.json` — suite
  `QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_RO_`.

Repository: https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve
(`poc/vectors/`), which matches the published RFC 9380 test vectors.
License: CC0 / public-domain test data.

Edwards25519 (Elligator2) and BLS12-381 G1/G2 (isogeny) suites are not yet
implemented; their vectors are not transcribed here.
