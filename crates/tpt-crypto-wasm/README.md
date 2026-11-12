# tpt-crypto-wasm

WebAssembly bindings for the `tpt-crypto` easy API, built with `wasm-bindgen`.
Byte arrays in and out (`Uint8Array`). Bad key or signature lengths throw.

Exposed: `generateKey`, `randomBytes`, `seal`, `open` (XChaCha20-Poly1305),
`hash` (SHA-256), `hmac`, `hkdfDerive`, `ed25519Generate`, `ed25519PublicKey`,
`ed25519Sign`, `ed25519Verify`.

## Build

```sh
cargo build -p tpt-crypto-wasm --target wasm32-unknown-unknown --release
wasm-bindgen --target web --out-dir pkg target/wasm32-unknown-unknown/release/tpt_crypto_wasm.wasm
```

Use `--target nodejs` for Node. The browser RNG (`getrandom` `wasm_js`) is
enabled automatically for `wasm32-unknown-unknown`.

## Test

```sh
wasm-bindgen --target nodejs --out-dir <dir> target/wasm32-unknown-unknown/release/tpt_crypto_wasm.wasm
node tests/node/smoke.cjs <dir>
```

The smoke test checks known-answer vectors: SHA-256 ("abc"), HMAC-SHA-256
(RFC 4231 #2), Ed25519 (RFC 8032 #1), HKDF-SHA-256 (RFC 5869 #1), and the
AEAD round trip with wrong-AAD and wrong-length rejection.

## Notes

- This crate uses `std`, unlike the other crates, which are `no_std`. It is a
  consumer-facing binding, and `wasm-bindgen` needs `std` for error plumbing.
- No npm package is published from this repo. Packaging and publishing are left
  to the owner.
- Only the easy API is exposed. Use the Rust crates directly for the rest.
