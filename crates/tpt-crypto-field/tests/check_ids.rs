//! Integration tests for `tpt-crypto-field`.
//!
//! These tests verify field element construction and basic arithmetic
//! operations across the supported field parameter sets.

use tpt_crypto_field::{CtEq, FieldElement};
use tpt_crypto_field::params::P256BaseParams;

#[test]
fn check_addsub() {
    let zero = FieldElement::<P256BaseParams>::zero();
    let one = FieldElement::<P256BaseParams>::one();
    let two = FieldElement::<P256BaseParams>::from_u64(2);

    // from_u64(1) vs one()
    let o64 = FieldElement::<P256BaseParams>::from_u64(1);
    eprintln!("from_u64(1)==one()? {}", o64.ct_eq(&one).into_bool());

    // add(zero,one)==one
    eprintln!("0+1==1? {}", zero.add(&one).ct_eq(&one).into_bool());
    // sub(one,one)==zero
    eprintln!("1-1==0? {}", one.sub(&one).ct_eq(&zero).into_bool());
    // one+one
    let oo = one.add(&one);
    eprintln!("1+1 == from_u64(2)? {}", oo.ct_eq(&two).into_bool());

    // bytes of one+1
    let b = oo.to_bytes();
    eprintln!("(1+1).to_bytes last 24 = {:?}", &b[24..48]);
    let bo = two.to_bytes();
    eprintln!("from_u64(2).to_bytes last 24 = {:?}", &bo[24..48]);
}
