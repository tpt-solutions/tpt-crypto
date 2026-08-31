//! Integration tests for `tpt-crypto-field`.
//!
//! These tests verify field element construction and basic arithmetic
//! operations across the supported field parameter sets.

use tpt_crypto_field::{CtEq, FieldElement, P256BaseParams};

const MAX_LIMBS: usize = 6;

#[test]
fn mul_2_times_3() {
    let two = FieldElement::<P256BaseParams>::from_u64(2);
    let three = FieldElement::<P256BaseParams>::from_u64(3);
    let six = FieldElement::<P256BaseParams>::from_u64(6);
    let prod = two.mul(&three);
    assert!(
        prod.ct_eq(&six).into_bool(),
        "2*3 != 6: prod bytes = {:?}",
        prod.to_bytes()
    );
}

#[test]
fn one_round_trip() {
    let one = FieldElement::<P256BaseParams>::from_u64(1);
    let bytes = one.to_bytes();
    eprintln!("one.to_bytes = {:?}", &bytes[..]);
    let mut expected = [0u8; MAX_LIMBS * 8];
    expected[MAX_LIMBS * 8 - 1] = 1;
    assert_eq!(&bytes[..], &expected[..], "encoding of 1 is wrong");
}
