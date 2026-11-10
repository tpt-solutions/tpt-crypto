//! Direct tests for `ct_eq_slices`, which the mutation run (todo V4) showed had no
//! coverage: equal non-empty slices, unequal contents at each position, and unequal
//! lengths, including lengths that differ only above 255.

use tpt_crypto_ct::cmp::ct_eq_slices;

#[test]
fn equal_slices_compare_equal() {
    let a = [1u8, 2, 3, 4, 5];
    assert!(ct_eq_slices(&a, &a.clone()).is_true());
    assert!(ct_eq_slices::<u8>(&[], &[]).is_true());
    let long = vec![7u8; 1000];
    assert!(ct_eq_slices(&long, &long.clone()).is_true());
}

#[test]
fn any_differing_position_is_detected() {
    let a = [9u8; 40];
    for i in 0..a.len() {
        let mut b = a;
        b[i] ^= 0x01;
        assert!(!ct_eq_slices(&a, &b).is_true(), "difference at {i} missed");
        assert!(
            !ct_eq_slices(&b, &a).is_true(),
            "difference at {i} missed (reversed)"
        );
    }
}

#[test]
fn unequal_lengths_are_unequal() {
    assert!(!ct_eq_slices(&[1u8, 2], &[1u8, 2, 3]).is_true());
    assert!(!ct_eq_slices(&[1u8, 2, 3], &[1u8, 2]).is_true());
    assert!(!ct_eq_slices::<u8>(&[], &[0]).is_true());
}

#[test]
fn lengths_differing_only_above_255_are_unequal() {
    // The length difference must not be truncated to 8 bits: 0 ^ 256 is 256,
    // which `as u8` would turn into 0.
    let empty: Vec<u8> = Vec::new();
    let long = vec![0u8; 256];
    assert!(!ct_eq_slices(&empty, &long).is_true());
    assert!(!ct_eq_slices(&long, &empty).is_true());
    let a = vec![0u8; 512];
    let b = vec![0u8; 256];
    assert!(!ct_eq_slices(&a, &b).is_true());
}
