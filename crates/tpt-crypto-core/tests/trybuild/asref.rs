// `SecretBox` must not implement `AsRef`. This must FAIL to compile.
fn main() {
    let s = tpt_crypto_core::secret::SecretBox::new([1u8; 4]);
    let _: &[u8; 4] = s.as_ref();
}
