//! Temporary generator for Ed25519 curve constants (Montgomery-form limbs).
use tpt_crypto_field::{CtEq, Ed25519Field, MAX_LIMBS};

fn limbs_to_hex(l: &[u64; MAX_LIMBS]) -> String {
    let mut s = String::new();
    for w in l.iter().rev() {
        s.push_str(&format!("{:016x}", w));
    }
    s
}

#[test]
fn gen_ed25519_consts() {
    // d = -121665 / 121666 mod p
    let d = Ed25519Field::from_u64(121665)
        .mul(&Ed25519Field::from_u64(121666).invert().unwrap())
        .neg();
    let dm = d.to_montgomery_limbs();
    println!("D_MONTS = [{:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}]", dm[0], dm[1], dm[2], dm[3], dm[4], dm[5]);
    println!("D_HEX = {}", limbs_to_hex(&dm));

    // zeta = 2^((p-1)/4)  ; (p-1)/4 = 2^253 - 5
    let e = [0u64, 0, 0, (1u64 << 61) - 5, 0, 0];
    let zeta = Ed25519Field::from_u64(2).pow(&e);
    let z2 = zeta.square();
    let neg1 = Ed25519Field::from_u64(1).neg();
    println!("E = {:?}", e);
    println!("zeta^2 == -1 ? {}", z2.ct_eq(&neg1).into_bool());
    println!("two^(p-1) == 1 ? {}", Ed25519Field::from_u64(2).pow(&[
        0xFFFF_FFFF_FFFF_FFEC, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 0x7FFF_FFFF_FFFF_FFFF, 0, 0,
    ]).ct_eq(&Ed25519Field::one()).into_bool());
    let _ = (d, e);
}

#[test]
fn pow_sanity() {
    let a = Ed25519Field::from_u64(3);
    let sq = a.square();
    let p2 = a.pow(&[2u64, 0, 0, 0, 0, 0]);
    let p3 = a.pow(&[3u64, 0, 0, 0, 0, 0]);
    let lo = |f: Ed25519Field| -> u64 {
        let b = f.to_bytes();
        u64::from_le_bytes([b[24], b[25], b[26], b[27], b[28], b[29], b[30], b[31]])
    };
    println!("sq==pow2? {}", sq.ct_eq(&p2).into_bool());
    println!("sqint={} pow2int={} pow3int={}", lo(sq), lo(p2), lo(p3));
}
