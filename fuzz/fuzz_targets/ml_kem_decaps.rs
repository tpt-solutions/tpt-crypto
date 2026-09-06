//! Fuzz target for `ml_kem::decapsulate` (ML-KEM-768).
//!
//! The secret key is fixed (derived from a constant seed); every fuzz byte is
//! treated as a candidate ciphertext. Exercises the full implicit-rejection
//! path: length check, re-encryption, constant-time compare, rejection PRF.

#![no_main]

use libfuzzer_sys::fuzz_target;
use tpt_crypto_kem::ml_kem::{decapsulate, keygen_seed, DecapsKey, MlKem768};
use tpt_crypto_kem::params::MlKemParams;
use std::sync::OnceLock;

fn fixed_sk() -> &'static DecapsKey {
    static SK: OnceLock<DecapsKey> = OnceLock::new();
    SK.get_or_init(|| {
        let (_pk, sk) = keygen_seed::<MlKem768>(&[0xAA; 32], &[0x55; 32]);
        sk
    })
}

fuzz_target!(|data: &[u8]| {
    if data.len() < 32 {
        return;
    }
    let sk = fixed_sk();
    let ct_len = core::cmp::min(data.len(), MlKem768::CT_LEN);
    let _ = decapsulate::<MlKem768>(sk, &data[..ct_len]);
});