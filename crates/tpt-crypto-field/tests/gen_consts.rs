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
    println!(
        "D_MONTS = [{:#x}, {:#x}, {:#x}, {:#x}, {:#x}, {:#x}]",
        dm[0], dm[1], dm[2], dm[3], dm[4], dm[5]
    );
    println!("D_HEX = {}", limbs_to_hex(&dm));

    // zeta = 2^((p-1)/4)  ; (p-1)/4 = 2^253 - 5
    let e = [0u64, 0, 0, (1u64 << 61) - 5, 0, 0];
    let zeta = Ed25519Field::from_u64(2).pow(&e);
    let z2 = zeta.square();
    let neg1 = Ed25519Field::from_u64(1).neg();
    println!("E = {:?}", e);
    println!("zeta^2 == -1 ? {}", z2.ct_eq(&neg1).into_bool());
    println!(
        "two^(p-1) == 1 ? {}",
        Ed25519Field::from_u64(2)
            .pow(&[
                0xFFFF_FFFF_FFFF_FFEC,
                0xFFFF_FFFF_FFFF_FFFF,
                0xFFFF_FFFF_FFFF_FFFF,
                0x7FFF_FFFF_FFFF_FFFF,
                0,
                0,
            ])
            .ct_eq(&Ed25519Field::one())
            .into_bool()
    );
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

    let one = Ed25519Field::one();
    let zero = Ed25519Field::zero();
    let x = Ed25519Field::from_u64(7);
    println!("mul(1,1)==1? {}", one.mul(&one).ct_eq(&one).into_bool());
    println!("mul(1,x)==x? {}", one.mul(&x).ct_eq(&x).into_bool());
    println!("mul(0,x)==0? {}", zero.mul(&x).ct_eq(&zero).into_bool());
    println!(
        "mul(2,3)==mul(3,2)? {}",
        Ed25519Field::from_u64(2)
            .mul(&Ed25519Field::from_u64(3))
            .ct_eq(&Ed25519Field::from_u64(3).mul(&Ed25519Field::from_u64(2)))
            .into_bool()
    );
    let a = Ed25519Field::from_u64(13);
    println!(
        "a*inv(a)==1? {}",
        a.mul(&a.invert().unwrap()).ct_eq(&one).into_bool()
    );

    // Direct mont_mul vs reference mul_mod for a=7, b=11.
    let am = Ed25519Field::from_u64(7);
    let bm = Ed25519Field::from_u64(11);
    let prod = am.mul(&bm);
    // reference: 7*11 = 77
    println!(
        "7*11==77? {}",
        prod.ct_eq(&Ed25519Field::from_u64(77)).into_bool()
    );
    // 13*17 = 221
    println!(
        "13*17==221? {}",
        Ed25519Field::from_u64(13)
            .mul(&Ed25519Field::from_u64(17))
            .ct_eq(&Ed25519Field::from_u64(221))
            .into_bool()
    );

    // Does to_bytes round-trip a single from_u64 value? to_bytes returns
    // MAX_LIMBS*8 = 48 bytes with the value in the high 32 bytes (big-endian
    // layout, base = (MAX_LIMBS-P::LIMBS)*8 = 16).
    for v in [0u64, 1, 2, 3, 7, 100, 12345] {
        let b = Ed25519Field::from_u64(v).to_bytes();
        let mut expected = [0u8; 32];
        expected[0..8].copy_from_slice(&v.to_le_bytes());
        let ok = b[16..48] == expected[..];
        let decoded = u64::from_le_bytes(b[16..24].try_into().unwrap());
        println!("from_u64({}) roundtrip ok? {} (decoded={})", v, ok, decoded);
    }

    // Compare mul against integer reference for small a,b where a*b < p.
    let mut all_ok = true;
    for a in 1u64..=50u64 {
        for b in 1u64..=50u64 {
            let prod = Ed25519Field::from_u64(a).mul(&Ed25519Field::from_u64(b));
            let pb = prod.to_bytes();
            let decoded = u64::from_le_bytes(pb[16..24].try_into().unwrap());
            if decoded != a * b {
                if all_ok {
                    println!("MISMATCHES:");
                }
                println!("  {} * {} = {} (got {})", a, b, a * b, decoded);
                all_ok = false;
            }
        }
    }
    println!("all small mul correct? {}", all_ok);
}
