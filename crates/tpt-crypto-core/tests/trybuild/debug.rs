// `SecretBox` must not be `Debug`. This must FAIL to compile.
fn main() {
    let s = tpt_crypto_core::secret::SecretBox::new([1u8; 4]);
    println!("{:?}", s);
}
