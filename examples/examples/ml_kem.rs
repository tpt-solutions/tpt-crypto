//! ML-KEM-768 key encapsulation with the OS RNG.
//!
//! Run: `cargo run -p tpt-crypto-examples --example ml_kem`

use tpt_crypto::ml_kem::{decapsulate, encapsulate, keygen, MlKem768};
use tpt_crypto::prelude::OsRng;

fn main() {
    let (pk, sk) = keygen::<MlKem768>(&mut OsRng);
    let (sender_secret, ciphertext) =
        encapsulate::<MlKem768>(&pk, &mut OsRng).expect("valid public key");
    let receiver_secret =
        decapsulate::<MlKem768>(&sk, &ciphertext.bytes).expect("ciphertext has the right length");

    assert_eq!(sender_secret, receiver_secret);
    println!(
        "ML-KEM-768 shared secret agreed ({} bytes)",
        sender_secret.len()
    );
}
