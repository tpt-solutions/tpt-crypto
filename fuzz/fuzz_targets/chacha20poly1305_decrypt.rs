//! Fuzz target for `ChaCha20Poly1305`, detached-tag decrypt path.
//!
//! A fixed 32-byte key and 12-byte nonce decrypt arbitrary attacker-controlled
//! `(ciphertext, tag)` buffers.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tpt_crypto_aead::{Aead, ChaCha20Poly1305, Nonce, Tag};

fuzz_target!(|data: &[u8]| {
    if data.len() < 48 {
        return;
    }
    let key = [0x03u8; 32];
    let nonce = Nonce::<12>::new([0x04u8; 12]);
    let cipher = ChaCha20Poly1305::new(&key);
    let aad_len = data.len().saturating_sub(48);
    let (ct_and_tag, aad) = data.split_at(aad_len);
    let (ct, tag_bytes) = ct_and_tag.split_at(ct_and_tag.len() - 16);
    let tag = match Tag::<16>::from_slice(tag_bytes) {
        Ok(t) => t,
        Err(_) => return,
    };
    let mut buf = ct.to_vec();
    let _ = cipher.decrypt_in_place_detached(&nonce, aad, &mut buf, &tag);
});