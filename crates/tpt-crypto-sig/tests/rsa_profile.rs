//! Minimum RSA modulus size under the policy profiles.
//!
//! `from_components` only checks the bit length and parity of `n`, not primality,
//! so a modulus of the right size with the top bit set is enough to exercise the
//! length gate. The default build accepts 1024 bits and up; `profile-modern`
//! requires 2048; `profile-cnsa2` requires 3072.

#![cfg(feature = "profile-modern")]

use tpt_crypto_sig::rsa::PublicKey;

/// An odd `bits`-bit big-endian modulus (top bit set, low bit set).
fn modulus(bits: usize) -> Vec<u8> {
    let mut n = vec![0x5a_u8; bits / 8];
    n[0] |= 0x80;
    let last = n.len() - 1;
    n[last] |= 0x01;
    n
}

const E: [u8; 3] = [0x01, 0x00, 0x01];

#[cfg(not(feature = "profile-cnsa2"))]
#[test]
fn modern_rejects_1024_bit_modulus() {
    assert!(PublicKey::from_components(&modulus(1024), &E).is_err());
}

#[cfg(not(feature = "profile-cnsa2"))]
#[test]
fn modern_accepts_2048_bit_modulus() {
    assert!(PublicKey::from_components(&modulus(2048), &E).is_ok());
}

#[cfg(feature = "profile-cnsa2")]
#[test]
fn cnsa2_rejects_2048_bit_modulus() {
    assert!(PublicKey::from_components(&modulus(2048), &E).is_err());
}

#[cfg(feature = "profile-cnsa2")]
#[test]
fn cnsa2_accepts_3072_bit_modulus() {
    assert!(PublicKey::from_components(&modulus(3072), &E).is_ok());
}
