//! X-Wing-style hybrid KEM (X25519 + ML-KEM-768) with the OS RNG.
//!
//! Run: `cargo run -p tpt-crypto-examples --example hybrid_kem`

use tpt_crypto::kem::xwing;
use tpt_crypto::prelude::OsRng;

fn main() {
    let (pk, sk) = xwing::keygen(&mut OsRng);
    let (sender_secret, ct) = xwing::encapsulate(&pk, &mut OsRng).expect("valid public key");
    let receiver_secret = xwing::decapsulate(&sk, &ct).expect("ciphertext has the right length");

    assert_eq!(sender_secret, receiver_secret);
    println!(
        "X-Wing hybrid shared secret agreed ({} bytes)",
        sender_secret.len()
    );
}
