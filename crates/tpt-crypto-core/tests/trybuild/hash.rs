// `SecretBox` must not be `Hash`. This must FAIL to compile.
fn main() {
    use std::collections::HashSet;
    let mut set = HashSet::new();
    set.insert(tpt_crypto_core::secret::SecretBox::new([1u8; 4]));
}
