//! End-to-end usage samples for the `tpt-crypto` substrate.
//!
//! These are compiled and tested as part of the workspace so the documented
//! patterns never rot. Each module mirrors a snippet from `spec.txt` §4 where the
//! relevant primitive has landed; for now it exercises `tpt-crypto-core`.

/// Hold a key in a `SecretBox`, compare secrets in constant time, and wipe on
/// drop. Mirrors the `spec.txt` §4 "Constant-time secret handling" snippet.
///
/// ```
/// use tpt_crypto_core::secret::SecretBox;
/// use tpt_crypto_core::ct::{ct_eq, ct_select, Choice};
/// use tpt_crypto_core::zeroize::Zeroizing;
///
/// // A key we want to keep out of logs and equality checks.
/// let key = SecretBox::new([0x42u8; 32]);
///
/// // Reading the secret is an explicit, greppable action.
/// assert_eq!(key.expose_secret(), &[0x42u8; 32]);
///
/// // Comparing secrets must go through the constant-time primitives — never `==`.
/// let other = SecretBox::new([0x42u8; 32]);
/// assert!(ct_eq(key.expose_secret(), other.expose_secret()).is_set());
///
/// // Constant-time selection: `picked` is `a` when `cond` is set, else `b`.
/// let a = [1u8; 32];
/// let b = [2u8; 32];
/// let cond = Choice::from_u8(1);
/// let picked = ct_select(&cond, &a, &b);
/// assert_eq!(picked, a);
///
/// // Move a secret out with a guaranteed wipe on scope exit.
/// let owned: Zeroizing<[u8; 32]> = Zeroizing::new(*key.expose_secret());
/// assert_eq!(*owned, [0x42u8; 32]);
/// ```
pub fn secret_handling_snippet() {}

#[cfg(test)]
mod tests {
    use tpt_crypto_core::ct::ct_eq;
    use tpt_crypto_core::secret::SecretBox;

    #[test]
    fn secret_box_is_not_observable_by_accident() {
        let key = SecretBox::new([7u8; 16]);
        // The only read path is explicit:
        assert!(ct_eq(key.expose_secret(), &[7u8; 16]).is_set());
    }
}
