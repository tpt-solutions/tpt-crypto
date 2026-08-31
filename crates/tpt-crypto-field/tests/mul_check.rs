//! Integration tests for `tpt-crypto-field`.
//!
//! These tests verify Ed25519 field multiplication and inversion.

use tpt_crypto_field::Ed25519Field;

fn to_int(f: Ed25519Field) -> [u8; 32] {
    let b = f.to_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = b[16 + (31 - i)];
    }
    out
}

fn le32(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[..8].copy_from_slice(&v.to_le_bytes());
    out
}

#[test]
fn mul_basics() {
    let c = Ed25519Field::from_u64(9).mul(&Ed25519Field::from_u64(9));
    assert_eq!(to_int(c), le32(81));
    let c = Ed25519Field::from_u64(2).mul(&Ed25519Field::from_u64(3));
    assert_eq!(to_int(c), le32(6));
    let c = Ed25519Field::from_u64(121665).mul(&Ed25519Field::from_u64(5));
    assert_eq!(to_int(c), le32(608325));
}

#[test]
fn invert_roundtrip() {
    for v in [2u64, 9, 121665, 0xFFFF_FFFF_FFFF_FFFF] {
        let a = Ed25519Field::from_u64(v);
        let inv = a.invert().unwrap();
        let one = a.mul(&inv);
        assert_eq!(to_int(one), le32(1), "invert roundtrip failed for {}", v);
    }
}
