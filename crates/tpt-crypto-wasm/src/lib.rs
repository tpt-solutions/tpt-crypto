//! WebAssembly bindings for the `tpt-crypto` easy API.
//!
//! Every function takes and returns plain byte arrays (`Uint8Array` in
//! JavaScript). Key and signature lengths are checked and rejected with a
//! thrown `Error` rather than panicking.
//!
//! This crate uses `std` (not `#![no_std]`) because `wasm-bindgen` needs it
//! for error and panic plumbing; it is a consumer-facing binding, not a
//! primitive. The underlying crates remain `no_std`.

use tpt_crypto::easy;
use wasm_bindgen::prelude::*;

fn to_array<const N: usize>(bytes: &[u8], what: &str) -> Result<[u8; N], JsError> {
    <[u8; N]>::try_from(bytes)
        .map_err(|_| JsError::new(&format!("{what} must be {N} bytes, got {}", bytes.len())))
}

/// A fresh random 32-byte AEAD key from the OS RNG.
#[wasm_bindgen(js_name = generateKey)]
pub fn generate_key() -> Result<Vec<u8>, JsError> {
    let key = easy::generate_key().map_err(|e| JsError::new(&e.to_string()))?;
    Ok(key.expose_secret().to_vec())
}

/// `len` random bytes from the OS RNG.
#[wasm_bindgen(js_name = randomBytes)]
pub fn random_bytes(len: usize) -> Result<Vec<u8>, JsError> {
    easy::random_bytes(len).map_err(|e| JsError::new(&e.to_string()))
}

/// Encrypt and authenticate `plaintext` under a 32-byte `key`, binding `aad`.
/// Returns `nonce ‖ ciphertext ‖ tag`.
#[wasm_bindgen]
pub fn seal(key: &[u8], plaintext: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsError> {
    let key = to_array::<{ easy::KEY_LEN }>(key, "key")?;
    easy::seal(&key, plaintext, aad).map_err(|e| JsError::new(&e.to_string()))
}

/// Decrypt a value produced by `seal`. Throws if the tag does not verify.
#[wasm_bindgen]
pub fn open(key: &[u8], sealed: &[u8], aad: &[u8]) -> Result<Vec<u8>, JsError> {
    let key = to_array::<{ easy::KEY_LEN }>(key, "key")?;
    easy::open(&key, sealed, aad).map_err(|e| JsError::new(&e.to_string()))
}

/// SHA-256 digest.
#[wasm_bindgen]
pub fn hash(data: &[u8]) -> Vec<u8> {
    easy::hash(data).to_vec()
}

/// HMAC-SHA-256 tag.
#[wasm_bindgen]
pub fn hmac(key: &[u8], msg: &[u8]) -> Vec<u8> {
    easy::hmac(key, msg).to_vec()
}

/// HKDF-SHA-256 derivation of `len` bytes.
#[wasm_bindgen(js_name = hkdfDerive)]
pub fn hkdf_derive(ikm: &[u8], salt: &[u8], info: &[u8], len: usize) -> Result<Vec<u8>, JsError> {
    easy::hkdf_derive(ikm, salt, info, len).map_err(|e| JsError::new(&e.to_string()))
}

/// A fresh random 32-byte Ed25519 seed from the OS RNG.
#[wasm_bindgen(js_name = ed25519Generate)]
pub fn ed25519_generate() -> Result<Vec<u8>, JsError> {
    let seed = easy::ed25519_generate().map_err(|e| JsError::new(&e.to_string()))?;
    Ok(seed.expose_secret().to_vec())
}

/// The 32-byte Ed25519 public key for a 32-byte seed.
#[wasm_bindgen(js_name = ed25519PublicKey)]
pub fn ed25519_public_key(seed: &[u8]) -> Result<Vec<u8>, JsError> {
    let seed = to_array::<{ tpt_crypto::sig::ed25519::SEED_LEN }>(seed, "seed")?;
    Ok(easy::ed25519_public_key(&seed).to_vec())
}

/// Ed25519 signature (64 bytes) over `msg`. Deterministic.
#[wasm_bindgen(js_name = ed25519Sign)]
pub fn ed25519_sign(seed: &[u8], msg: &[u8]) -> Result<Vec<u8>, JsError> {
    let seed = to_array::<{ tpt_crypto::sig::ed25519::SEED_LEN }>(seed, "seed")?;
    Ok(easy::sign(&seed, msg).to_vec())
}

/// Verify an Ed25519 signature. Throws if it does not verify.
#[wasm_bindgen(js_name = ed25519Verify)]
pub fn ed25519_verify(public: &[u8], msg: &[u8], sig: &[u8]) -> Result<(), JsError> {
    let public = to_array::<{ tpt_crypto::sig::ed25519::PUBLIC_KEY_LEN }>(public, "public key")?;
    let sig = to_array::<{ tpt_crypto::sig::ed25519::SIGNATURE_LEN }>(sig, "signature")?;
    easy::verify(&public, msg, &sig).map_err(|e| JsError::new(&e.to_string()))
}
