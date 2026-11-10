//! ML-DSA-65 signing and verification with a domain-separation context.
//!
//! Run: `cargo run -p tpt-crypto-examples --example ml_dsa`

use tpt_crypto::ml_dsa::{keygen, sign, verify, MlDsa65};
use tpt_crypto::prelude::OsRng;

fn main() {
    let (pk, sk) = keygen::<MlDsa65, _>(&mut OsRng);
    let message = b"transfer 10 to alice";
    let ctx = b"tpt-crypto-example-v1";

    let signature = sign::<MlDsa65>(&sk, message, ctx).expect("sign");
    verify::<MlDsa65>(&pk, message, &signature, ctx).expect("honest signature verifies");

    assert!(verify::<MlDsa65>(&pk, b"transfer 10 to eve", &signature, ctx).is_err());
    assert!(verify::<MlDsa65>(&pk, message, &signature, b"other-ctx").is_err());
    println!("ML-DSA-65 signature verified; altered message and context rejected");
}
