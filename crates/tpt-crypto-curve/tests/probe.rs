//! Temporary probe: compare X25519::diffie_hellman against a line-by-line RFC
//! reference ladder to locate the bug.
use tpt_crypto_field::Ed25519Field;
use tpt_crypto_curve::X25519;

fn le_to_fe(bytes: &[u8; 32]) -> Ed25519Field {
    let mut limbs = [0u64; 6];
    for i in 0..4 {
        let mut v = 0u64;
        for j in 0..8 {
            v |= (bytes[i * 8 + j] as u64) << (8 * j);
        }
        limbs[i] = v;
    }
    Ed25519Field::from_limbs(limbs)
}

fn fe_to_le(f: Ed25519Field) -> [u8; 32] {
    let s = f.to_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        out[i] = s[16 + (31 - i)];
    }
    out
}

fn ref_x25519(scalar: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut k = *scalar;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    let x1 = le_to_fe(u);
    let one = Ed25519Field::one();
    let zero = Ed25519Field::zero();
    let a24 = Ed25519Field::from_u64(121665);
    let mut x2 = one;
    let mut z2 = zero;
    let mut x3 = x1;
    let mut z3 = one;
    let mut swap = 0u8;
    for t in (0..255).rev() {
        let bit = ((k[t / 8] >> (t % 8)) & 1) as u8;
        swap ^= bit;
        if swap == 1 {
            core::mem::swap(&mut x2, &mut x3);
            core::mem::swap(&mut z2, &mut z3);
        }
        swap = bit;
        let a = x2.add(&z2);
        let aa = a.square();
        let b = x2.sub(&z2);
        let bb = b.square();
        let e = aa.sub(&bb);
        let c = x3.add(&z3);
        let d = x3.sub(&z3);
        let da = d.mul(&a);
        let cb = c.mul(&b);
        x3 = da.add(&cb).square();
        z3 = x1.mul(&da.sub(&cb).square());
        x2 = aa.mul(&bb);
        z2 = e.mul(&aa.add(&e.mul(&a24)));
    }
    if swap == 1 {
        core::mem::swap(&mut x2, &mut x3);
        core::mem::swap(&mut z2, &mut z3);
    }
    let z2_inv = z2.invert().unwrap_or(zero);
    fe_to_le(x2.mul(&z2_inv))
}

fn hex(b: &[u8]) -> String {
    let mut s = String::new();
    for x in b {
        s.push_str(&format!("{:02x}", x));
    }
    s
}

#[test]
fn compare_ladders() {
    let nine = [9u8; 32];
    let mine = X25519::diffie_hellman(&nine, &nine);
    let reference = ref_x25519(&nine, &nine);
    println!("mine      = {}", hex(&mine));
    println!("reference = {}", hex(&reference));
    println!("rfc       = 422c9bd36bf22d19ba1b740d2c7a6014b871c6dfa4886fba85c9b6d10bd1c7");
    assert_eq!(mine, reference, "ladders disagree");
}
