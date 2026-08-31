//! X25519 (RFC 7748 §5.2) known-answer tests against the official vectors.

fn hx(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    for i in 0..32 {
        let hi = match b[2 * i] {
            c @ b'0'..=b'9' => c - b'0',
            c @ b'a'..=b'f' => c - b'a' + 10,
            c @ b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        };
        let lo = match b[2 * i + 1] {
            c @ b'0'..=b'9' => c - b'0',
            c @ b'a'..=b'f' => c - b'a' + 10,
            c @ b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        };
        out[i] = (hi << 4) | lo;
    }
    out
}

#[test]
fn rfc7748_vector_1() {
    let s = hx("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    let u = hx("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    let want = hx("c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552");
    assert_eq!(tpt_crypto_curve::X25519::diffie_hellman(&s, &u), want);
}

#[test]
fn rfc7748_vector_2() {
    let s = hx("4b66e9d4d1b4673c5ad22691957d6af5c11b6421e0ea01d42ca4169e7918ba0d");
    let u = hx("e5210f12786811d3f4b7959d0538ae2c31dbe7106fc03c3efc4cd549c715a493");
    let want = hx("95cbde9476e8907d7aade45cb4b873f88b595a68799fa152e6f8f7647aac7957");
    assert_eq!(tpt_crypto_curve::X25519::diffie_hellman(&s, &u), want);
}

#[test]
fn rfc7748_alice_basepoint() {
    let alice = hx("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let base = [9u8; 32];
    let want = hx("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");
    assert_eq!(tpt_crypto_curve::X25519::diffie_hellman(&alice, &base), want);
}

#[test]
fn rfc7748_reciprocal() {
    // RFC 7748 §5.2: the two vectors compose — X25519(alice, X25519(bob, 9))
    // == X25519(bob, X25519(alice, 9)).
    let alice = hx("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
    let bob = hx("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
    let base = [9u8; 32];
    let ka = tpt_crypto_curve::X25519::diffie_hellman(&alice, &base);
    let kb = tpt_crypto_curve::X25519::diffie_hellman(&bob, &base);
    let s_ab = tpt_crypto_curve::X25519::diffie_hellman(&alice, &kb);
    let s_ba = tpt_crypto_curve::X25519::diffie_hellman(&bob, &ka);
    let want = hx("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    assert_eq!(s_ab, want);
    assert_eq!(s_ba, want);
}

#[test]
fn field_mul_2limb() {
    use tpt_crypto_field::Ed25519Field;
    fn fe_bytes(f: &Ed25519Field) -> [u8; 32] {
        let b = f.to_bytes();
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = b[16 + (31 - i)];
        }
        out
    }
    let a = Ed25519Field::from_limbs({
        let mut l = [0u64; 6];
        l[0] = 0xFFFF_FFFF_FFFF_FFFF;
        l[1] = 1;
        l
    });
    let r = fe_bytes(&a.mul(&a));
    println!("a*a   = {}", hex(&r));
    println!("expect= 0100000000000000fcffffffffffff03000000000000000000000000000000");
}

#[test]
fn field_p_minus_1() {
    use tpt_crypto_field::Ed25519Field;
    fn fe_bytes(f: &Ed25519Field) -> [u8; 32] {
        let b = f.to_bytes();
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = b[16 + (31 - i)];
        }
        out
    }
    let v = Ed25519Field::from_limbs([0xFFFF_FFFF_FFFF_FFEC, 0xFFFF_FFFF_FFFF_FFFF, 0xFFFF_FFFF_FFFF_FFFF, 0x7FFF_FFFF_FFFF_FFFE, 0, 0]);
    let r = fe_bytes(&v.mul(&v));
    println!("(p-1)^2 = {}", hex(&r));
    println!("expect  = 0100000000000000000000000000000000000000000000000000000000000000");
}

#[test]
fn field_raw_mont() {
    use tpt_crypto_field::Ed25519Field;
    let u = hx("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    let fu = Ed25519Field::from_limbs({
        let mut l = [0u64; 6];
        for i in 0..4 {
            let mut v = 0u64;
            for j in 0..8 {
                v |= (u[i * 8 + j] as u64) << (8 * j);
            }
            l[i] = v;
        }
        l
    });
    let raw = fu.to_montgomery_limbs();
    println!("raw Mont(u) limbs LE:");
    for i in 0..4 {
        println!(" limb{} = {:016x}", i, raw[i]);
    }
    println!("expect        :");
    println!(" limb0 = 89272d1f5990a5c6");
    println!(" limb1 = 76344b7074bbfffe");
    println!(" limb2 = c9f897c70d6734fe");
    println!(" limb3 = 4c4180f8a48b1868");
}

#[test]
fn field_small() {
    use tpt_crypto_field::Ed25519Field;
    fn fe_bytes(f: &Ed25519Field) -> [u8; 32] {
        let b = f.to_bytes();
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = b[16 + (31 - i)];
        }
        out
    }
    let two = Ed25519Field::from_u64(2);
    let nine = Ed25519Field::from_u64(9);
    println!("2     = {}", hex(&fe_bytes(&two)));
    println!("2*2   = {}", hex(&fe_bytes(&two.mul(&two))));
    println!("2*9   = {}", hex(&fe_bytes(&two.mul(&nine))));
    println!("9*9   = {}", hex(&fe_bytes(&nine.mul(&nine))));
}

#[test]
fn field_mul_one() {
    use tpt_crypto_field::Ed25519Field;
    fn fe_bytes(f: &Ed25519Field) -> [u8; 32] {
        let b = f.to_bytes();
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = b[16 + (31 - i)];
        }
        out
    }
    let u = hx("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    let fu = Ed25519Field::from_limbs({
        let mut l = [0u64; 6];
        for i in 0..4 {
            let mut v = 0u64;
            for j in 0..8 {
                v |= (u[i * 8 + j] as u64) << (8 * j);
            }
            l[i] = v;
        }
        l
    });
    println!("u*1 = {}", hex(&fe_bytes(&fu.mul(&Ed25519Field::one()))));
    println!("u   = {}", hex(&fe_bytes(&fu)));
    let two = Ed25519Field::from_u64(2);
    println!("u*2 = {}", hex(&fe_bytes(&fu.mul(&two))));
    println!("exp2= 183957a14c075220766b664dd848cce4f8bf62494983286bb66060b0ced1b7df");
}

#[test]
fn field_mul_4limb() {
    use tpt_crypto_field::Ed25519Field;
    fn fe_bytes(f: &Ed25519Field) -> [u8; 32] {
        let b = f.to_bytes();
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = b[16 + (31 - i)];
        }
        out
    }
    let a = Ed25519Field::from_limbs({
        let mut l = [0u64; 6];
        l[0] = 0xFFFF_FFFF_FFFF_FFFF;
        l[1] = 0xFFFF_FFFF_FFFF_FFFF;
        l[2] = 0;
        l[3] = 0;
        l
    });
    let r = fe_bytes(&a.mul(&a));
    println!("a*a   = {}", hex(&r));
    println!("expect= 14000000000000000000000000000000feffffffffffffffffffffffffffff7f");
}

#[test]
fn field_sq_debug() {
    use tpt_crypto_field::Ed25519Field;
    fn fe_bytes(f: &Ed25519Field) -> [u8; 32] {
        let b = f.to_bytes();
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = b[16 + (31 - i)];
        }
        out
    }
    let u = hx("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    let fu = Ed25519Field::from_limbs({
        let mut l = [0u64; 6];
        for i in 0..4 {
            let mut v = 0u64;
            for j in 0..8 {
                v |= (u[i * 8 + j] as u64) << (8 * j);
            }
            l[i] = v;
        }
        l
    });
    let one = Ed25519Field::one();
    let a = fu.add(&one);
    println!("a      = {}", hex(&fe_bytes(&a)));
    let m1 = fe_bytes(&a.mul(&a));
    let m2 = fe_bytes(&a.square());
    println!("a.mul  = {}", hex(&m1));
    println!("a.sq   = {}", hex(&m2));
    println!("u.u    = {}", hex(&fe_bytes(&fu.mul(&fu))));
    println!("expect  = 0197d4f4b83c85006d883203c4f50fa8fc987028a1c3220b8da8cb2958b47f19");
}

#[test]
fn field_sq() {
    use tpt_crypto_field::Ed25519Field;
    fn fe_bytes(f: &Ed25519Field) -> [u8; 32] {
        let b = f.to_bytes();
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = b[16 + (31 - i)];
        }
        out
    }
    let u = hx("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    let fu = Ed25519Field::from_limbs({
        let mut l = [0u64; 6];
        for i in 0..4 {
            let mut v = 0u64;
            for j in 0..8 {
                v |= (u[i * 8 + j] as u64) << (8 * j);
            }
            l[i] = v;
        }
        l
    });
    let one = Ed25519Field::one();
    let ap1 = fe_bytes(&fu.add(&one).square());
    assert_eq!(
        hex(&ap1),
        "0197d4f4b83c85006d883203c4f50fa8fc987028a1c3220b8da8cb2958b47f19",
        "(u+1)^2"
    );
    let am1 = fe_bytes(&fu.sub(&one).square());
    assert_eq!(
        hex(&am1),
        "512525b2202de0bf80b16568146375df0b19ab960ebcd13420e809c7bb110f48",
        "(u-1)^2"
    );
    let prod = fe_bytes(&fu.add(&one).square().mul(&fu.sub(&one).square()));
    assert_eq!(
        hex(&prod),
        "17e7f088963faffa9daa70d488fae76d47c833937f78416e6b21d2f4a130d828",
        "(u^2-1)^2"
    );
}

#[test]
fn field_addsub() {
    use tpt_crypto_field::Ed25519Field;
    fn fe_bytes(f: &Ed25519Field) -> [u8; 32] {
        let b = f.to_bytes();
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = b[16 + (31 - i)];
        }
        out
    }
    let u = hx("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    let fu = Ed25519Field::from_limbs({
        let mut l = [0u64; 6];
        for i in 0..4 {
            let mut v = 0u64;
            for j in 0..8 {
                v |= (u[i * 8 + j] as u64) << (8 * j);
            }
            l[i] = v;
        }
        l
    });
    let one = Ed25519Field::one();
    let ap1 = fe_bytes(&fu.add(&one));
    assert_eq!(
        hex(&ap1),
        "4c1cabd0a603a9103b35b326ec2466727c5fb124a4c19435db3030586768dbe7",
        "u+1"
    );
    let am1 = fe_bytes(&fu.sub(&one));
    assert_eq!(
        hex(&am1),
        "4c1cabd0a603a9103b35b326ec2466727c5fb124a4c19435db3030586768dbe5",
        "u-1"
    );
}

#[test]
fn field_invert() {
    use tpt_crypto_field::Ed25519Field;
    fn fe_bytes(f: &Ed25519Field) -> [u8; 32] {
        let b = f.to_bytes();
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = b[16 + (31 - i)];
        }
        out
    }
    let u = hx("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    let fu = Ed25519Field::from_limbs({
        let mut l = [0u64; 6];
        for i in 0..4 {
            let mut v = 0u64;
            for j in 0..8 {
                v |= (u[i * 8 + j] as u64) << (8 * j);
            }
            l[i] = v;
        }
        l
    });
    let inv = fe_bytes(&fu.invert().unwrap());
    assert_eq!(
        hex(&inv),
        "cbe0fd5aa07abf647d39bdfcedc5ee44bb98b8632d69f0b9058603492416ab99",
        "inv(u)"
    );
}

#[test]
fn field_roundtrip() {
    use tpt_crypto_field::Ed25519Field;
    fn fe_bytes(f: &Ed25519Field) -> [u8; 32] {
        let b = f.to_bytes();
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = b[16 + (31 - i)];
        }
        out
    }
    let u = hx("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    let fu = Ed25519Field::from_limbs({
        let mut l = [0u64; 6];
        for i in 0..4 {
            let mut v = 0u64;
            for j in 0..8 {
                v |= (u[i * 8 + j] as u64) << (8 * j);
            }
            l[i] = v;
        }
        l
    });
    assert_eq!(fe_bytes(&fu), u, "from_limbs/to_bytes round trip");
    // hard multi-limb product: (2^64-1)^2 mod p
    let big = Ed25519Field::from_limbs({
        let mut l = [0u64; 6];
        l[0] = 0xFFFF_FFFF_FFFF_FFFF;
        l
    });
    let bp = fe_bytes(&big.mul(&big));
    assert_eq!(
        hex(&bp),
        "00000000000000000000000000000000fffffffffffffffe0000000000000001",
        "(2^64-1)^2"
    );
}

#[test]
fn field_primitives() {
    use tpt_crypto_field::Ed25519Field;
    fn fe_bytes(f: &Ed25519Field) -> [u8; 32] {
        let b = f.to_bytes();
        let mut out = [0u8; 32];
        for i in 0..32 {
            out[i] = b[16 + (31 - i)];
        }
        out
    }
    fn from_hex(s: &str) -> [u8; 32] {
        hx(s)
    }
    // x = 9, x^2 mod p = 81
    let x = Ed25519Field::from_u64(9);
    let sq = fe_bytes(&x.square());
    println!("9^2 -> {}", hex(&sq));
    assert_eq!(sq[0], 81);
    for i in 1..32 {
        assert_eq!(sq[i], 0);
    }
    // x*y for x=9,y=11 -> 99
    let y = Ed25519Field::from_u64(11);
    let m = fe_bytes(&x.mul(&y));
    assert_eq!(m[0], 99);
    // invert: x * inv(x) == 1
    let inv = x.invert().unwrap();
    let one = fe_bytes(&x.mul(&inv));
    assert_eq!(one[0], 1);
    for i in 1..32 {
        assert_eq!(one[i], 0);
    }
    // add/sub
    let a = Ed25519Field::from_u64(100);
    let b = Ed25519Field::from_u64(40);
    let s = fe_bytes(&a.add(&b));
    assert_eq!(s[0], 140);
    let d = fe_bytes(&a.sub(&b));
    assert_eq!(d[0], 60);
    let _ = from_hex;
}

#[test]
fn trace_dump() {
    let s = hx("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    let u = hx("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c");
    let tr = tpt_crypto_curve::X25519::dbg_trace(&s, &u);
    for (t, swap, x2, z2, x3, z3) in tr.iter() {
        println!(
            "TT t={t} sw={swap} x2={} z2={} x3={} z3={}",
            hex(x2),
            hex(z2),
            hex(x3),
            hex(z3)
        );
    }
}

fn hex(b: &[u8; 32]) -> String {
    let mut s = String::new();
    for byte in b.iter() {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

#[test]
fn x25519_self_consistent() {
    // Any scalar against the basepoint must be deterministic and stable.
    let k = hx("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4");
    let base = [9u8; 32];
    let a = tpt_crypto_curve::X25519::diffie_hellman(&k, &base);
    let b = tpt_crypto_curve::X25519::diffie_hellman(&k, &base);
    assert_eq!(a, b);
}
