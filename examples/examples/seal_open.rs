//! Authenticated encryption with the `easy` recipes (XChaCha20-Poly1305).
//!
//! Run: `cargo run -p tpt-crypto-examples --example seal_open`

use tpt_crypto::easy;

fn main() {
    let key = easy::generate_key().expect("OS RNG");
    let msg = b"meet at the usual place";
    let aad = b"channel-7";

    let sealed = easy::seal(key.expose_secret(), msg, aad).expect("seal");
    let opened = easy::open(key.expose_secret(), &sealed, aad).expect("open");
    assert_eq!(opened, msg);

    assert!(easy::open(key.expose_secret(), &sealed, b"channel-8").is_err());
    println!(
        "sealed {} bytes -> {} bytes; wrong AAD rejected",
        msg.len(),
        sealed.len()
    );
}
