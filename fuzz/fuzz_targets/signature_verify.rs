//! Fuzz target for Ed25519 `VerifyingKey` parse + `Signature` parse.
//!
//! Every fuzz byte is split into a 32-byte public key and a 64-byte signature;
//! both branches of `decompress`/`verify` are exercised including
//! non-canonical encodings.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tpt_crypto_sig::ed25519::{Signature, VerifyingKey};

fuzz_target!(|data: &[u8]| {
    if data.len() < 96 {
        return;
    }
    let (pk_bytes, sig_bytes) = data.split_at(32);
    let sig_bytes = &sig_bytes[..64];
    let pk_arr: [u8; 32] = pk_bytes.try_into().unwrap();
    let sig_arr: [u8; 64] = sig_bytes.try_into().unwrap();

    let pk = match VerifyingKey::from_bytes(&pk_arr) {
        Ok(p) => p,
        Err(_) => return, // rejected point; nothing further to exercise
    };
    let sig = Signature::from_bytes(sig_arr);
    let _ = pk.verify(b"fuzz message", &sig);
});