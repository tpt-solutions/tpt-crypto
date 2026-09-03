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
- `poc/vectors/expand_message_xmd_SHA512_38.json` — `expand_message_xmd`
  (SHA-512), short DST `QUUX-V01-CS02-with-expander-SHA512-256`.
- `poc/vectors/edwards25519_XMD:SHA-512_ELL2_RO_.json` — suite
  `QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_RO_`.
- `poc/vectors/BLS12381G1_XMD:SHA-256_SSWU_RO_.json` — suite
  `QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_`.

The BLS12-381 G1 11-isogeny coefficient tables in `src/iso11_g1.rs` are the
plain-integer `k_(i,j)` constants of RFC 9380 Appendix E.2, transcribed via
`noble-curves` (`src/bls12-381.ts`, MIT); correctness is gated by the suite
KAT above.

Repository: https://github.com/cfrg/draft-irtf-cfrg-hash-to-curve
(`poc/vectors/`), which matches the published RFC 9380 test vectors.
License: CC0 / public-domain test data.

BLS12-381 G2 (3-isogeny over Fp2 + ψ-based cofactor clear) is not yet
implemented; its vectors are not transcribed here.
