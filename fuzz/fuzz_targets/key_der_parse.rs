//! Fuzz target for the key-encoding parsers (DER SPKI / PKCS#8 and PEM).
//!
//! Every fuzz input is fed to each parser. The parsers must return errors on
//! malformed input and never panic. The PEM decoder is driven with the input as
//! text, and with the input wrapped in a valid PEM envelope so the base64 and
//! DER stages are reached too.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tpt_crypto_sig::encoding::{
    ed25519_public_from_spki, ed25519_seed_from_pkcs8, p256_private_from_pkcs8,
    p256_public_from_spki, p384_private_from_pkcs8, p384_public_from_spki, pem_decode,
    rsa_public_from_spki,
};

fuzz_target!(|data: &[u8]| {
    let _ = ed25519_public_from_spki(data);
    let _ = ed25519_seed_from_pkcs8(data);
    let _ = rsa_public_from_spki(data);
    let _ = p256_public_from_spki(data);
    let _ = p256_private_from_pkcs8(data);
    let _ = p384_public_from_spki(data);
    let _ = p384_private_from_pkcs8(data);

    if let Ok(text) = core::str::from_utf8(data) {
        let _ = pem_decode("PUBLIC KEY", text);
    }
    // Valid envelope around arbitrary bytes, so the base64 and DER stages run.
    let mut wrapped = String::from("-----BEGIN PUBLIC KEY-----\n");
    for chunk in data.chunks(48) {
        wrapped.push_str(&base64_encode(chunk));
        wrapped.push('\n');
    }
    wrapped.push_str("-----END PUBLIC KEY-----\n");
    let _ = pem_decode("PUBLIC KEY", &wrapped);
});

fn base64_encode(data: &[u8]) -> String {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in data.chunks(3) {
        let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if c.len() > 1 { B64[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if c.len() > 2 { B64[n as usize & 63] as char } else { '=' });
    }
    out
}
