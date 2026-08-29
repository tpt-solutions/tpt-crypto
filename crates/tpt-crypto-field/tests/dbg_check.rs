use tpt_crypto_field::{
    Bls12381Fp, Bls12381FpParams, Bls12381Fr, Bls12381FrParams, CtEq, Field, FieldElement,
    FieldParams, P256Base, P256BaseParams, P256Scalar, P256ScalarParams, P384Base,
    P384BaseParams, P384Scalar, P384ScalarParams,
};

fn check<P: FieldParams>(name: &str)
where
    FieldElement<P>: Field,
{
    let two = FieldElement::<P>::from_u64(2);
    let four = FieldElement::<P>::from_u64(4);
    let inv2 = two.invert();
    println!(
        "{name}: invert(2) is_some={} 2*inv2==1?{}",
        inv2.is_some().into_bool(),
        inv2
            .is_some()
            .into_bool()
            .then(|| two
                .mul(&inv2.unwrap_or_else(FieldElement::<P>::zero))
                .ct_eq(&FieldElement::<P>::one())
                .into_bool())
            .unwrap_or(false)
    );
    let s = four.sqrt();
    println!(
        "{name}: sqrt(4) is_some={} sqrt^2==4?{}",
        s.is_some().into_bool(),
        s.is_some()
            .into_bool()
            .then(|| s.unwrap_or_else(FieldElement::<P>::zero)
                .square()
                .ct_eq(&four)
                .into_bool())
            .unwrap_or(false)
    );
    let zb = FieldElement::<P>::zero().to_bytes();
    let back = FieldElement::<P>::from_bytes(&zb);
    println!(
        "{name}: from_bytes(0).is_some={} eq0?{}",
        back.is_some().into_bool(),
        back.is_some()
            .into_bool()
            .then(|| back
                .unwrap_or_else(FieldElement::<P>::zero)
                .ct_eq(&FieldElement::<P>::zero())
                .into_bool())
            .unwrap_or(false)
    );
    let six = FieldElement::<P>::from_u64(2).mul(&FieldElement::<P>::from_u64(3));
    println!(
        "{name}: 2*3==6? {}",
        six.ct_eq(&FieldElement::<P>::from_u64(6)).into_bool()
    );
}

#[test]
fn dbg_check() {
    check::<P256BaseParams>("P256Base");
    check::<P256ScalarParams>("P256Scalar");
    check::<P384BaseParams>("P384Base");
    check::<P384ScalarParams>("P384Scalar");
    check::<Bls12381FpParams>("BlsFp");
    check::<Bls12381FrParams>("BlsFr");

    // Deep dive on P-384 from_u64.
    let two = P384Base::from_u64(2);
    println!("P384 from_u64(2).is_zero() = {}", two.is_zero().into_bool());
    println!("P384 from_u64(2).to_bytes() = {:?}", two.to_bytes());
    let three = P384Base::from_u64(3);
    println!(
        "P384 from_u64(2).ct_eq(from_u64(3)) = {}",
        two.ct_eq(&three).into_bool()
    );
    println!("P384 from_u64(1).to_bytes() = {:?}", P384Base::from_u64(1).to_bytes());
    println!("P384 one().to_bytes()        = {:?}", P384Base::one().to_bytes());
    println!("P384 one().mont_limbs()      = {:?}", P384Base::one().to_montgomery_limbs());
    println!("BlsFp one().mont_limbs()     = {:?}", Bls12381Fp::one().to_montgomery_limbs());
    println!(
        "P384 from_u64(2).mont_limbs() = {:?}",
        P384Base::from_u64(2).to_montgomery_limbs()
    );
}
