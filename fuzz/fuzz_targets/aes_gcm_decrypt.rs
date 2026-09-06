//! Fuzz target for `Aes128Gcm`, detached-tag decrypt path.
//!
//! A fixed 16-byte key and 12-byte nonce decrypt arbitrary attacker-controlled
//! `(ciphertext, tag)` buffers; the tag compare runs in constant time.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tpt_crypto_aead::{Aead, Aes128Gcm, Nonce, Tag};

fuzz_target!(|data: &[u8]| {
    if data.len() < 48 {
        return;
    }
    let key = [0x01u8; 16];
    let nonce = Nonce::<12>::new([0x02u8; 12]);
    let cipher = match Aes128Gcm::new(&key) {
        Ok(c) => c,
        Err(_) => return,
    };
    // Split input into ciphertext || tag(16) || aad.
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