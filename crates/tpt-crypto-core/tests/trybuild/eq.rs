// `SecretBox` must not be `PartialEq`. This must FAIL to compile.
fn main() {
    let a = tpt_crypto_core::secret::SecretBox::new([1u8; 4]);
    let b = tpt_crypto_core::secret::SecretBox::new([1u8; 4]);
    let _ = a == b;
}
