use tpt_crypto_field::params::P256BaseParams;
use tpt_crypto_field::{CtEq, FieldElement, FieldParams};

const N: usize = 6;

fn to_canon(int: &[u64; N]) -> [u8; N * 8] {
    let mut out = [0u8; N * 8];
    for limb in 0..N {
        let v = int[limb];
        let base = (N - 1 - limb) * 8;
        for b in 0..8 {
            out[base + b] = (v >> (56 - b * 8)) as u8;
        }
    }
    out
}

fn ref_reduce(x: &[u64], m: &[u64; N]) -> [u64; N] {
    let mut r = x.to_vec();
    let mut bit = 0i64;
    for i in (0..r.len()).rev() {
        if r[i] != 0 {
            bit = (i as i64) * 64 + (64 - r[i].leading_zeros() as i64);
            break;
        }
    }
    while bit >= 0 {
        let shift = bit as u32;
        let mut sm = vec![0u64; N];
        let ls = (shift / 64) as usize;
        let bs = (shift % 64) as u32;
        for i in 0..N {
            let v = m[i];
            sm[i + ls] |= v << bs;
            if bs > 0 {
                sm[i + ls + 1] |= v >> (64 - bs);
            }
        }
        let mut ge = false;
        let n = r.len().max(sm.len());
        for i in (0..n).rev() {
            let av = *r.get(i).unwrap_or(&0);
            let bv = *sm.get(i).unwrap_or(&0);
            if av > bv {
                ge = true;
                break;
            }
            if av < bv {
                ge = false;
                break;
            }
        }
        if ge {
            let mut borrow = 0i128;
            let mut out = vec![0u64; r.len().max(sm.len())];
            for i in 0..out.len() {
                let av = *r.get(i).unwrap_or(&0) as i128;
                let bv = *sm.get(i).unwrap_or(&0) as i128;
                let mut d = av - bv - borrow;
                if d < 0 {
                    d += 1i128 << 64;
                    borrow = 1;
                } else {
                    borrow = 0;
                }
                out[i] = d as u64;
            }
            r = out;
        }
        bit -= 1;
    }
    let mut out = [0u64; N];
    for i in 0..N {
        out[i] = *r.get(i).unwrap_or(&0);
    }
    out
}

fn rand_fe<P: FieldParams>(limbs: [u64; N]) -> FieldElement<P> {
    let reduced = ref_reduce(&limbs.to_vec(), &P::MODULUS);
    FieldElement::<P>::from_bytes(&to_canon(&reduced)).unwrap()
}

#[test]
fn debug_rt() {
    for val in [
        0u64,
        1,
        2,
        5,
        12345,
        0xFFFF_FFFF,
        0x1_0000_0000,
        u64::MAX / 2,
    ] {
        let x = FieldElement::<P256BaseParams>::from_u64(val);
        let xb = x.to_bytes();
        let y = FieldElement::<P256BaseParams>::from_bytes(&xb).unwrap();
        let yb = y.to_bytes();
        eprintln!("val={} rt eq: {}", val, x.ct_eq(&y).into_bool());
        eprintln!("  x.to_bytes() = {:?}", &xb[..]);
        eprintln!("  y.to_bytes() = {:?}", &yb[..]);
        assert!(x.ct_eq(&y).into_bool(), "round trip failed for {}", val);
        assert_eq!(xb, yb);
    }
    // random
    let x = rand_fe::<P256BaseParams>([0x1234_5678, 0x9ABC_DEF0, 0x0FED_CBA9, 0x1234_5678, 0, 0]);
    let y = FieldElement::<P256BaseParams>::from_bytes(&x.to_bytes()).unwrap();
    assert!(x.ct_eq(&y).into_bool(), "random round trip failed");
}
