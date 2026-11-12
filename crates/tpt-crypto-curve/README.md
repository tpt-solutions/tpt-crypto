# tpt-crypto-curve

Constant-time elliptic-curve arithmetic for the
[`tpt-crypto`](../../README.md) substrate.

Layer: `curve` on `field + ct + hash + core`. Pure Rust, `#![no_std]`
(plus `alloc`), `unsafe_code = "forbid"`. Every scalar-dependent operation is
branch-free and index-free, using `ct_select` / `ct_lookup` from
`tpt-crypto-ct`.

## What's inside

| Curve | Module | Types | Reference |
| --- | --- | --- | --- |
| Edwards25519 | `edwards25519` | `EdwardsPoint` | RFC 8032 |
| Curve25519 (Montgomery ladder) | `montgomery25519` | `X25519` | RFC 7748 |
| NIST P-256 / P-384 | `weierstrass` | `P256Point`, `P384Point`, `ProjectivePoint<C>` | SEC1 / RFC 5903 |
| BLS12-381 (`alloc`) | `bls12_381` | `G1`, `G2`, `Gt`, `pairing`, `multi_pairing` | BLS12-381 |
| Hash-to-curve | `hash_to_curve` | `hash_to_curve`, `expand_message_xmd`, `hash_to_curve_edwards25519`, `hash_to_curve_bls12381_g1` / `_g2` | RFC 9380 |

- **Ed25519**: extended-coordinate add/double, w=4 fixed-window scalar
  multiplication with `ct_lookup`, point compress/decompress, cofactored verify.
- **X25519**: clamped Montgomery ladder with `cswap`, final inversion.
- **P-256 / P-384**: generic `ProjectivePoint<C: WeierstrassParams>` over the
  `-field` params, complete Renes–Costello–Batina formulas (eprint 2015/1060,
  `a = -3`), exception-free single-path add for the cofactor-1 curves,
  fixed-length double-and-add, SEC1 compressed/uncompressed encoding.
- **BLS12-381**: G1 and G2 group operations with a 4-bit fixed-window scalar
  multiplication, compressed encodings, the optimal ate pairing, and
  `multi_pairing`.
- **Hash-to-curve**: RFC 9380 `expand_message_xmd` and the random-oracle suites for
  P-256, P-384, edwards25519 and BLS12-381 G1/G2.

## Example

```rust
use tpt_crypto_curve::X25519;

let alice_sk = [1u8; 32];
let bob_sk = [2u8; 32];
let alice_pk = X25519::diffie_hellman(&alice_sk, &X25519::BASE);
let bob_pk = X25519::diffie_hellman(&bob_sk, &X25519::BASE);
assert_eq!(
    X25519::diffie_hellman(&alice_sk, &bob_pk),
    X25519::diffie_hellman(&bob_sk, &alice_pk),
);
```

## Features

| Feature | Effect |
| --- | --- |
| `std` | default |
| `alloc` | heap support without `std` |

## Status

Not audited. Ed25519 (RFC 8032 §7.1), X25519 (RFC 7748 §5.2/§6.1) and
P-256/P-384 ECDH (RFC 5903 §8.1/§8.2) KATs pass. RFC 9380 hash-to-curve KATs
pass for the suites listed above. BLS12-381 is covered by subgroup, bilinearity
and non-degeneracy tests; there are no external pairing test vectors yet.

## License

MIT OR Apache-2.0.
