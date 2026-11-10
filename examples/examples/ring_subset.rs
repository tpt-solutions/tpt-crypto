//! SHA-256 → P-256 ECDSA → AES-128-GCM, end to end through the facade.
//!
//! Run: `cargo run -p tpt-crypto-examples --example ring_subset`

use tpt_crypto::aead::{Aead, Aes128Gcm, Nonce};
use tpt_crypto::hash::sha2::sha256;
use tpt_crypto::prelude::{CryptoRng, OsRng, SecretBox};
use tpt_crypto::sig::ecdsa::{SigningKey, P256};

fn main() {
    // 1) SHA-256 over the message.
    let digest = sha256(b"ring subset demo payload");

    // 2) P-256 ECDSA over the digest (RFC 6979 deterministic signing).
    let secret = SecretBox::new(OsRng.gen_array::<32>());
    let sk = SigningKey::<P256>::from_bytes(secret.expose_secret())
        .expect("random scalar is in [1, n-1]");
    let vk = sk.verifying_key();
    let sig = sk.sign_prehash(&digest).expect("sign");
    vk.verify_prehash(&digest, &sig).expect("verify");
    assert!(vk
        .verify_prehash(&sha256(b"tampered payload"), &sig)
        .is_err());

    // 3) AES-128-GCM keyed from half the digest.
    let key: [u8; 16] = digest[..16].try_into().expect("16 bytes");
    let cipher = Aes128Gcm::new(&key).expect("16-byte key");
    let nonce = Nonce::<12>::new(OsRng.gen_array::<12>());
    let aad = b"tpt-crypto-ring-subset";

    let ct = cipher.encrypt(&nonce, aad, b"secret plaintext");
    let pt = cipher.decrypt(&nonce, aad, &ct).expect("authentication");
    assert_eq!(pt, b"secret plaintext");

    let mut bad = ct.clone();
    bad[0] ^= 0x01;
    assert!(cipher.decrypt(&nonce, aad, &bad).is_err());
    println!("SHA-256 / ECDSA P-256 / AES-128-GCM flow verified");
}
