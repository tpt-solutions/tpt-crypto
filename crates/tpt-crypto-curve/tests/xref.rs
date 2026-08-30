//! Independent reference X25519 over p = 2^255 - 19, used to validate the
//! library implementation. Not part of the production suite.

type N = [u64; 4]; // little-endian limbs, value < p

const P: N = [
    0xFFFF_FFFF_FFFF_FFED,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0x7FFF_FFFF_FFFF_FFFF,
];

fn cmp_ge(a: &N, b: &N) -> bool {
    let mut i = 4;
    while i > 0 {
        i -= 1;
        if a[i] > b[i] {
            return true;
        }
        if a[i] < b[i] {
            return false;
        }
    }
    true
}

fn subn(a: &N, b: &N) -> N {
    let mut r = [0u64; 4];
    let mut borrow = 0u128;
    for i in 0..4 {
        let s = (a[i] as u128).wrapping_sub(b[i] as u128).wrapping_sub(borrow);
        r[i] = s as u64;
        borrow = if (s >> 64) & 1 == 1 { 1 } else { 0 };
    }
    r
}

fn addmod(a: &N, b: &N) -> N {
    let mut r = [0u64; 4];
    let mut c = 0u128;
    for i in 0..4 {
        let s = (a[i] as u128) + (b[i] as u128) + c;
        r[i] = s as u64;
        c = s >> 64;
    }
    // r < 2p; subtract p at most once.
    if cmp_ge(&r, &P) {
        subn(&r, &P)
    } else {
        r
    }
}

fn submod(a: &N, b: &N) -> N {
    if cmp_ge(a, b) {
        subn(a, b)
    } else {
        addmod(&subn(&P, b), a)
    }
}

/// Reduce a 512-bit little-endian value (8 limbs) modulo p using 2^255 ≡ 19.
fn reduce(w: [u64; 8]) -> N {
    // First pass: v = r + q*2^255, 2^255 ≡ 19 (mod p)  =>  v ≡ r + 19 q.
    let r3 = w[3] & 0x7FFF_FFFF_FFFF_FFFF;
    let r = [w[0], w[1], w[2], r3];
    let mut q = [0u64; 5];
    q[0] = (w[3] >> 63) | (w[4] << 1);
    q[1] = (w[4] >> 63) | (w[5] << 1);
    q[2] = (w[5] >> 63) | (w[6] << 1);
    q[3] = (w[6] >> 63) | (w[7] << 1);
    q[4] = w[7] >> 63;
    let mut t = [0u128; 6];
    for i in 0..5 {
        let p19 = (q[i] as u128) * 19;
        t[i] += p19;
        t[i + 1] += t[i] >> 64;
        t[i] &= 0xFFFF_FFFF_FFFF_FFFF;
    }
    for i in 0..4 {
        let s = t[i] + (r[i] as u128);
        t[i] = s & 0xFFFF_FFFF_FFFF_FFFF;
        t[i + 1] += s >> 64;
    }
    // Second pass on t (< 2^262).
    let r3b = (t[3] as u64) & 0x7FFF_FFFF_FFFF_FFFF;
    let mut q2 = [0u64; 5];
    q2[0] = ((t[3] as u64) >> 63) | ((t[4] as u64) << 1);
    q2[1] = (t[4] as u64) >> 63;
    let mut u = [0u128; 6];
    for i in 0..5 {
        let p19 = (q2[i] as u128) * 19;
        u[i] += p19;
        u[i + 1] += u[i] >> 64;
        u[i] &= 0xFFFF_FFFF_FFFF_FFFF;
    }
    let rr = [t[0] as u64, t[1] as u64, t[2] as u64, r3b];
    for i in 0..4 {
        let s = u[i] + (rr[i] as u128);
        u[i] = s & 0xFFFF_FFFF_FFFF_FFFF;
        u[i + 1] += s >> 64;
    }
    let mut res = [u[0] as u64, u[1] as u64, u[2] as u64, u[3] as u64];
    while cmp_ge(&res, &P) {
        res = subn(&res, &P);
    }
    res
}

fn mul(a: &N, b: &N) -> N {
    let mut w = [0u64; 8];
    for i in 0..4 {
        let mut carry = 0u128;
        for j in 0..4 {
            let s = (w[i + j] as u128) + (a[i] as u128) * (b[j] as u128) + carry;
            w[i + j] = s as u64;
            carry = s >> 64;
        }
        w[i + 4] += carry as u64;
    }
    reduce(w)
}

fn sqr(a: &N) -> N {
    mul(a, a)
}

const EXP: N = [
    0xFFFF_FFFF_FFFF_FFEB,
    0xFFFF_FFFF_FFFF_FFFF,
    0xFFFF_FFFF_FFFF_FFFF,
    0x7FFF_FFFF_FFFF_FFFF,
];

fn inv(a: &N) -> N {
    let mut r = [0u64; 4];
    r[0] = 1;
    for limb in (0..4).rev() {
        for bit in (0..64).rev() {
            r = sqr(&r);
            if (EXP[limb] >> bit) & 1 == 1 {
                r = mul(&r, a);
            }
        }
    }
    r
}

fn bytes_to_fe(b: &[u8; 32]) -> N {
    let mut w = [0u64; 8];
    for i in 0..4 {
        let mut v = 0u64;
        for j in 0..8 {
            v |= (b[i * 8 + j] as u64) << (8 * j);
        }
        w[i] = v;
    }
    reduce(w)
}

fn fe_to_bytes(a: &N) -> [u8; 32] {
    let mut out = [0u8; 32];
    for i in 0..4 {
        for j in 0..8 {
            out[i * 8 + j] = (a[i] >> (8 * j)) as u8;
        }
    }
    out
}

fn swap2(a: &mut N, b: &mut N) {
    core::mem::swap(a, b);
}

fn x25519_ref(k: &[u8; 32], u: &[u8; 32]) -> [u8; 32] {
    let mut k = *k;
    k[0] &= 248;
    k[31] &= 127;
    k[31] |= 64;
    let mut x1 = bytes_to_fe(u);
    let mut x2 = [0u64; 4];
    x2[0] = 1;
    let mut z2 = [0u64; 4];
    let mut x3 = x1;
    let mut z3 = [0u64; 4];
    z3[0] = 1;
    let a24 = {
        let mut v = [0u64; 4];
        v[0] = 121665;
        v
    };
    let mut swap = false;
    let mut iter = 0usize;
    for t in (0..255).rev() {
        let bit = (k[t / 8] >> (t % 8)) & 1;
        swap ^= bit != 0;
        if swap {
            swap2(&mut x2, &mut x3);
            swap2(&mut z2, &mut z3);
        }
        swap = bit != 0;
        let a0 = addmod(&x2, &z2);
        let aa = sqr(&a0);
        let b0 = addmod(&x3, &z3);
        let bb = sqr(&b0);
        let e = submod(&aa, &bb);
        let a1 = submod(&x2, &z2);
        let b1 = submod(&x3, &z3);
        let da = mul(&a1, &b0);
        let cb = mul(&a0, &b1);
        let dacb = submod(&da, &cb);
        x3 = sqr(&addmod(&da, &cb));
        z3 = mul(&x1, &sqr(&dacb));
        x2 = mul(&aa, &bb);
        z2 = mul(&e, &addmod(&aa, &mul(&a24, &e)));
        if iter < 2 {
            eprintln!(
                "iter {} (t={}): x2={:?} z2={:?} x3={:?} z3={:?}",
                iter,
                t,
                fe_to_bytes(&x2),
                fe_to_bytes(&z2),
                fe_to_bytes(&x3),
                fe_to_bytes(&z3)
            );
        }
        iter += 1;
    }
    if swap {
        swap2(&mut x2, &mut x3);
        swap2(&mut z2, &mut z3);
    }
    let z2i = inv(&z2);
    let r = mul(&x2, &z2i);
    fe_to_bytes(&r)
}

#[test]
fn ref_arith_sanity() {
    // 2 * 3 = 6
    assert_eq!(mul(&[2, 0, 0, 0], &[3, 0, 0, 0]), [6, 0, 0, 0]);
    // a * a^-1 = 1
    let av = hex::decode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c").unwrap();
    let mut ab = [0u8; 32];
    ab.copy_from_slice(&av);
    let a = bytes_to_fe(&ab);
    let ai = inv(&a);
    assert_eq!(mul(&a, &ai), [1, 0, 0, 0], "reference inverse broken");
    // a^2 * a^-2 = 1
    let s = sqr(&a);
    let si = inv(&s);
    assert_eq!(mul(&s, &si), [1, 0, 0, 0], "reference square/inverse broken");
}

#[test]
fn ref_field_matches_lib() {
    use tpt_crypto_field::Ed25519Field;
    let pairs: [&[u8]; 8] = [
        b"0000000000000000000000000000000000000000000000000000000000000009",
        b"e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        b"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffed",
        b"7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        b"1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
        b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        b"0000000000000000000000000000000000000000000000000000000000000001",
        b"deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
    ];
    let mut all = Vec::new();
    for h in pairs.iter() {
        let mut v = [0u8; 32];
        let s = h.to_vec();
        // hex decode
        for i in 0..32 {
            let hi = (s[2 * i] as char).to_digit(16).unwrap();
            let lo = (s[2 * i + 1] as char).to_digit(16).unwrap();
            v[i] = (hi * 16 + lo) as u8;
        }
        all.push(v);
    }
    // compare reference mul(a,b) vs library mul(a,b) for all pairs
    for a in &all {
        let ab = bytes_to_fe(a);
        let mut al = [0u64; 6];
        for i in 0..4 {
            let mut w = 0u64;
            for j in 0..8 {
                w |= (a[i * 8 + j] as u64) << (8 * j);
            }
            al[i] = w;
        }
        let la = Ed25519Field::from_limbs(al);
        for b in &all {
            let bb = bytes_to_fe(b);
            let mut bl = [0u64; 6];
            for i in 0..4 {
                let mut w = 0u64;
                for j in 0..8 {
                    w |= (b[i * 8 + j] as u64) << (8 * j);
                }
                bl[i] = w;
            }
            let lb = Ed25519Field::from_limbs(bl);
            let refr = mul(&ab, &bb);
            let libp = la.mul(&lb);
            let lb_bytes = libp.to_bytes();
            // library to_bytes is 48 bytes big-endian, value at 16..48
            let mut lib_le = [0u8; 32];
            for i in 0..32 {
                lib_le[i] = lb_bytes[16 + (31 - i)];
            }
            assert_eq!(
                fe_to_bytes(&refr).to_vec(),
                lib_le.to_vec(),
                "field mul mismatch a={:?} b={:?}",
                a,
                b
            );
        }
    }
}

#[test]
fn x25519_basepoint_alice() {
    let s = hex::decode("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a").unwrap();
    let e = hex::decode("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a").unwrap();
    let mut k = [0u8; 32];
    k.copy_from_slice(&s);
    let u = [9u8; 32];
    let got = x25519_ref(&k, &u);
    assert_eq!(got.to_vec(), e, "X25519(a, 9) wrong: {:?}", got);
}

#[test]
fn x25519_reference_matches_rfc() {
    let vectors = [
        (
            "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
            "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
            "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        ),
        (
            "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742",
        ),
    ];
    for (sc, uc, exp) in vectors {
        let s = hex::decode(sc).unwrap();
        let u = hex::decode(uc).unwrap();
        let e = hex::decode(exp).unwrap();
        let mut k = [0u8; 32];
        k.copy_from_slice(&s);
        let mut uu = [0u8; 32];
        uu.copy_from_slice(&u);
        let got = x25519_ref(&k, &uu);
        assert_eq!(got.to_vec(), e, "reference X25519 wrong for {}", sc);
    }
}

#[test]
fn ladder_first_step_debug() {
    use tpt_crypto_field::Ed25519Field;
    let x1 = Ed25519Field::from_u64(9);
    let mut x2 = Ed25519Field::one();
    let mut z2 = Ed25519Field::zero();
    let mut x3 = x1;
    let mut z3 = Ed25519Field::one();
    let mut swap = false;
    let bit = true;
    swap ^= bit;
    core::mem::swap(&mut x2, &mut x3);
    core::mem::swap(&mut z2, &mut z3);
    swap = bit;
    let a0 = x2.add(&z2);
    let a1 = x2.sub(&z2);
    let b0 = x3.add(&z3);
    let b1 = x3.sub(&z3);
    let aa = a0.square();
    let bb = b0.square();
    let e = aa.sub(&bb);
    let da = a1.mul(&b0);
    let cb = a0.mul(&b1);
    let n_x2 = aa.mul(&bb);
    let n_z2 = e.mul(&aa.add(&e.mul(&Ed25519Field::from_u64(121665))));
    let n_x3 = da.add(&cb).square();
    let n_z3 = x1.mul(&da.sub(&cb).square());
    let bytes = n_x2.to_bytes();
    let mut le = [0u8; 32];
    for i in 0..32 {
        le[i] = bytes[16 + (31 - i)];
    }
    eprintln!(
        "FIRST STEP x2(LE)={:?} z2(LE)={:?} x3(LE)={:?} z3(LE)={:?}",
        le,
        {
            let b = n_z2.to_bytes();
            let mut v = [0u8; 32];
            for i in 0..32 { v[i] = b[16 + (31 - i)]; }
            v
        },
        {
            let b = n_x3.to_bytes();
            let mut v = [0u8; 32];
            for i in 0..32 { v[i] = b[16 + (31 - i)]; }
            v
        },
        {
            let b = n_z3.to_bytes();
            let mut v = [0u8; 32];
            for i in 0..32 { v[i] = b[16 + (31 - i)]; }
            v
        }
    );
}

#[test]
fn x25519_library_matches_reference() {
    use tpt_crypto_curve::X25519;
    let scalar =
        hex::decode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5e1859cb6e918c0c5e1f").unwrap();
    let u_coord =
        hex::decode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c").unwrap();
    let mut k = [0u8; 32];
    k.copy_from_slice(&scalar);
    let mut u = [0u8; 32];
    u.copy_from_slice(&u_coord);

    let lib = X25519::diffie_hellman(&k, &u);
    let refr = x25519_ref(&k, &u);
    assert_eq!(
        lib.to_vec(),
        refr.to_vec(),
        "library != reference\n  lib = {:?}\n  ref = {:?}",
        lib, refr
    );
}

#[test]
fn inline_mul_matches_truth() {
    use tpt_crypto_curve::{EdwardsPoint, X25519};
    use tpt_crypto_ct::lookup::ct_lookup;
    let b = EdwardsPoint::basepoint();
    let scalar = [0u8; 32];
    // inline reimplementation of EdwardsPoint::mul
    let mut table = [EdwardsPoint::identity(); 16];
    let mut p = b;
    for i in 1..16 {
        table[i] = p;
        p = p.add(&b);
    }
    let mut acc = EdwardsPoint::identity();
    for i in (0..64).rev() {
        let byte = scalar[i / 2] as usize;
        let nibble = if (i % 2) == 0 {
            (byte & 0x0F) as usize
        } else {
            ((byte >> 4) & 0x0F) as usize
        };
        for _ in 0..4 {
            acc = acc.double();
        }
        let addend = ct_lookup(&table, nibble, EdwardsPoint::identity());
        acc = acc.add(&addend);
        if i >= 60 {
            println!("INLINE i={} nibble={} acc={:?}", i, nibble, acc.compress());
        }
    }
    let inline = acc.compress();
    // ground truth
    let mut g = EdwardsPoint::basepoint();
    for _ in 0..254 {
        g = g.double();
    }
    let truth = g.compress();
    assert_eq!(inline, truth, "inline mul != 254 doublings");
}

#[test]
fn ct_lookup_on_edwards() {
    use tpt_crypto_curve::EdwardsPoint;
    use tpt_crypto_ct::lookup::ct_lookup;
    let b = EdwardsPoint::basepoint();
    let mut table = [EdwardsPoint::identity(); 16];
    let mut p = b;
    for i in 1..16 {
        table[i] = p;
        p = p.add(&b);
    }
    let four = ct_lookup(&table, 4, EdwardsPoint::identity());
    assert_eq!(four.compress(), b.double().double().compress(), "ct_lookup(table,4) != 4B");
    let zero = ct_lookup(&table, 0, EdwardsPoint::identity());
    assert_eq!(zero.compress(), EdwardsPoint::identity().compress(), "ct_lookup(table,0) != identity");
}

#[test]
fn basepoint_montgomery_u_is_9() {
    use tpt_crypto_curve::EdwardsPoint;
    use tpt_crypto_field::{CtEq, Ed25519Field};
    let u = EdwardsPoint::basepoint().to_montgomery_u();
    let b = u.to_bytes();
    let mut le = [0u8; 32];
    for i in 0..32 {
        le[i] = b[16 + (31 - i)];
    }
    eprintln!("basepoint u(LE) = {:?}", le);
    // Should be 9.
    let nine = Ed25519Field::from_u64(9);
    assert!(u.ct_eq(&nine).into_bool(), "basepoint u != 9: {:?}", le);

    // Does mul([0;32]) (= 2^254 * B) give identity? Print its compress.
    let k = [0u8; 32];
    let q = EdwardsPoint::basepoint().mul(&k);
    eprintln!("2^254 * B compress = {:?}", q.compress());

    // Ground truth for 2^254 * B via repeated doubling.
    let mut acc = EdwardsPoint::basepoint();
    for _ in 0..254 {
        acc = acc.double();
    }
    let truth = acc.compress();
    let m = EdwardsPoint::basepoint().mul(&[0u8; 32]);
    eprintln!("2^254*B truth = {:?}", truth);
    eprintln!("2^254*B mul   = {:?}", m.compress());
    // sanity: doubling loop of identity-ish? just compare
    assert_eq!(truth, m.compress(), "EdwardsPoint::mul high-bit broken");
}

#[test]
fn x25519_matches_edwards_ladder() {
    use tpt_crypto_curve::{EdwardsPoint, X25519};
    use tpt_crypto_field::Ed25519Field;
    fn clamp_k(s: &[u8; 32]) -> [u8; 32] {
        let mut a = *s;
        a[0] &= 248;
        a[31] &= 127;
        a[31] |= 64;
        a
    }
    // u = 9 is the Montgomery u-coordinate of the Ed25519 base point, so
    // X25519(9, k) must equal the u-coordinate of [clamp(k)]·B (birational map
    // u = (1+y)/(1-y)). Edwards scalar mul is an independent code path, so
    // disagreement isolates a Montgomery-ladder group-law bug.
    let base_u = [9u8; 32];
    let scalars: [&[u8]; 2] = [
        b"77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
        b"a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5e1859cb6e918c0c5e1f",
    ];
    for hs in scalars {
        let mut k = [0u8; 32];
        for i in 0..32 {
            k[i] = u8::from_str_radix(core::str::from_utf8(&hs[2 * i..2 * i + 2]).unwrap(), 16)
                .unwrap();
        }
        let kc = clamp_k(&k);
        let mont = X25519::diffie_hellman(&k, &base_u);
        let edw = EdwardsPoint::basepoint().mul(&kc);
        let u_fe: Ed25519Field = edw.to_montgomery_u();
        let ub = u_fe.to_bytes();
        let mut edw_u = [0u8; 32];
        for i in 0..32 {
            edw_u[i] = ub[16 + (31 - i)];
        }
        assert_eq!(
            mont.to_vec(),
            edw_u.to_vec(),
            "X25519 != Edwards-derived u for scalar {:?}",
            k
        );
    }
}

mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        let mut out = Vec::with_capacity(s.len() / 2);
        let b = s.as_bytes();
        let mut i = 0;
        while i < b.len() {
            let hi = v(b[i])?;
            let lo = v(b[i + 1])?;
            out.push((hi << 4) | lo);
            i += 2;
        }
        Ok(out)
    }
    fn v(b: u8) -> Result<u8, ()> {
        match b {
            b'0'..=b'9' => Ok(b - b'0'),
            b'a'..=b'f' => Ok(b - b'a' + 10),
            b'A'..=b'F' => Ok(b - b'A' + 10),
            _ => Err(()),
        }
    }
}
