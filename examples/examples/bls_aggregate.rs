//! BLS12-381 same-message aggregation: two signers, one pairing-product check.
//!
//! Run: `cargo run -p tpt-crypto-examples --example bls_aggregate`

use tpt_crypto::bls::{self, SecretKey};
use tpt_crypto::prelude::{CryptoRng, OsRng};

fn main() {
    let mut ikm1 = [0u8; 32];
    let mut ikm2 = [0u8; 32];
    OsRng.try_fill_bytes(&mut ikm1).expect("OS RNG");
    OsRng.try_fill_bytes(&mut ikm2).expect("OS RNG");
    let sk1 = SecretKey::keygen(&ikm1).expect("keygen");
    let sk2 = SecretKey::keygen(&ikm2).expect("keygen");
    let (pk1, pk2) = (sk1.public_key(), sk2.public_key());

    let message = b"beacon attestation";
    let sig1 = bls::sign(&sk1, message);
    let sig2 = bls::sign(&sk2, message);
    let agg = bls::aggregate(&[sig1, sig2]).expect("non-empty aggregate");

    bls::verify_aggregate(&[pk1, pk2], message, &agg).expect("aggregate verifies");
    assert!(bls::verify_aggregate(&[pk1, pk2], b"other", &agg).is_err());
    println!("BLS aggregate of 2 signatures verified");
}
