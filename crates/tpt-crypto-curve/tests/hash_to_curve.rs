//! RFC 9380 hash-to-curve KATs (vectors from the CFRG `draft-irtf-cfrg-hash-to-curve`
//! reference `poc/vectors/` JSON — see `tests/kat/PROVENANCE.md`).

use tpt_crypto_curve::hash_to_curve::{
    expand_message_xmd, hash_to_curve, hash_to_curve_edwards25519, Sswu,
};
use tpt_crypto_curve::weierstrass::{ProjectivePoint, WeierstrassParams, P256, P384};
use tpt_crypto_hash::sha2::{Sha256, Sha512};

#[test]
fn expand_message_xmd_sha512_short_dst() {
    let dst = b"QUUX-V01-CS02-with-expander-SHA512-256";
    let mut out = [0u8; 0x20];
    expand_message_xmd::<64, Sha512>(b"", dst, &mut out, 128);
    assert_eq!(
        hex::encode(out),
        "6b9a7312411d92f921c6f68ca0b6380730a1a4d982c507211a90964c394179ba"
    );
    let mut out = [0u8; 0x20];
    expand_message_xmd::<64, Sha512>(b"abcdef0123456789", dst, &mut out, 128);
    assert_eq!(
        hex::encode(out),
        "087e45a86e2939ee8b91100af1583c4938e0f5fc6c9db4b107b83346bc967f58"
    );
}

#[test]
fn bls12381_g1_xmd_sha256_sswu_ro() {
    use tpt_crypto_curve::hash_to_curve::hash_to_curve_bls12381_g1;
    let dst = b"QUUX-V01-CS02-with-BLS12381G1_XMD:SHA-256_SSWU_RO_";
    let cases: [(&[u8], &str, &str); 3] = [
        (
            b"",
            "052926add2207b76ca4fa57a8734416c8dc95e24501772c814278700eed6d1e4e8cf62d9c09db0fac349612b759e79a1",
            "08ba738453bfed09cb546dbb0783dbb3a5f1f566ed67bb6be0e8c67e2e81a4cc68ee29813bb7994998f3eae0c9c6a265",
        ),
        (
            b"abc",
            "03567bc5ef9c690c2ab2ecdf6a96ef1c139cc0b2f284dca0a9a7943388a49a3aee664ba5379a7655d3c68900be2f6903",
            "0b9c15f3fe6e5cf4211f346271d7b01c8f3b28be689c8429c85b67af215533311f0b8dfaaa154fa6b88176c229f2885d",
        ),
        (
            b"abcdef0123456789",
            "11e0b079dea29a68f0383ee94fed1b940995272407e3bb916bbf268c263ddd57a6a27200a784cbc248e84f357ce82d98",
            "03a87ae2caf14e8ee52e51fa2ed8eefe80f02457004ba4d486d6aa1f517c0889501dc7413753f9599b099ebcbbd2d709",
        ),
    ];
    for (msg, xh, yh) in cases {
        let p = hash_to_curve_bls12381_g1(msg, dst);
        assert!(p.is_on_curve().into_bool(), "off curve");
        assert!(p.is_torsion_free().into_bool(), "not in G1");
        let (x, y) = p.to_affine().expect("identity");
        assert_eq!(
            hex::encode(x.to_bytes()),
            format!("{xh:0>96}"),
            "x for {:?}",
            core::str::from_utf8(msg)
        );
        assert_eq!(hex::encode(y.to_bytes()), format!("{yh:0>96}"));
    }
}

#[test]
fn bls12381_g2_xmd_sha256_sswu_ro() {
    use tpt_crypto_curve::hash_to_curve::hash_to_curve_bls12381_g2;
    let dst = b"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_";
    // (msg, x = x0,x1 ; y = y0,y1) from the CFRG reference vectors.
    let cases: [(&[u8], [&str; 4]); 2] = [
        (
            b"",
            [
                "0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a",
                "05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d",
                "0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92",
                "12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6",
            ],
        ),
        (
            b"abc",
            [
                "02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6",
                "139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8",
                "1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48",
                "00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16",
            ],
        ),
    ];
    for (msg, c) in cases {
        let p = hash_to_curve_bls12381_g2(msg, dst);
        assert!(p.is_on_curve().into_bool(), "off curve");
        assert!(p.is_torsion_free().into_bool(), "not in G2");
        let (x, y) = p.to_affine().expect("identity");
        assert_eq!(hex::encode(x.c0().to_bytes()), format!("{:0>96}", c[0]));
        assert_eq!(hex::encode(x.c1().to_bytes()), format!("{:0>96}", c[1]));
        assert_eq!(hex::encode(y.c0().to_bytes()), format!("{:0>96}", c[2]));
        assert_eq!(hex::encode(y.c1().to_bytes()), format!("{:0>96}", c[3]));
    }
}

fn hex32(s: &str) -> [u8; 32] {
    let v = hex::decode(s).unwrap();
    let mut out = [0u8; 32];
    out[32 - v.len()..].copy_from_slice(&v);
    out
}

#[test]
fn edwards25519_xmd_sha512_ell2_ro() {
    let dst = b"QUUX-V01-CS02-with-edwards25519_XMD:SHA-512_ELL2_RO_";
    // (msg, P.x, P.y) from the CFRG reference vectors.
    let cases: [(&[u8], &str, &str); 3] = [
        (
            b"",
            "3c3da6925a3c3c268448dcabb47ccde5439559d9599646a8260e47b1e4822fc6",
            "09a6c8561a0b22bef63124c588ce4c62ea83a3c899763af26d795302e115dc21",
        ),
        (
            b"abc",
            "608040b42285cc0d72cbb3985c6b04c935370c7361f4b7fbdb1ae7f8c1a8ecad",
            "1a8395b88338f22e435bbd301183e7f20a5f9de643f11882fb237f88268a5531",
        ),
        (
            b"abcdef0123456789",
            "6d7fabf47a2dc03fe7d47f7dddd21082c5fb8f86743cd020f3fb147d57161472",
            "53060a3d140e7fbcda641ed3cf42c88a75411e648a1add71217f70ea8ec561a6",
        ),
    ];
    for (msg, xh, yh) in cases {
        let p = hash_to_curve_edwards25519(msg, dst);
        let x = hex32(xh);
        let mut want = hex32(yh);
        want.reverse(); // big-endian y -> little-endian encoding
        want[31] |= (x[31] & 1) << 7; // sign of x
        assert_eq!(
            hex::encode(p.compress()),
            hex::encode(want),
            "mismatch for {:?}",
            core::str::from_utf8(msg)
        );
    }
}

fn expand256(msg: &[u8], dst: &[u8], n: usize) -> Vec<u8> {
    let mut out = vec![0u8; n];
    expand_message_xmd::<32, Sha256>(msg, dst, &mut out, 64);
    out
}

#[test]
fn expand_message_xmd_sha256_short_dst() {
    let dst = b"QUUX-V01-CS02-with-expander-SHA256-128";
    assert_eq!(
        hex::encode(expand256(b"", dst, 0x20)),
        "68a985b87eb6b46952128911f2a4412bbc302a9d759667f87f7a21d803f07235"
    );
    assert_eq!(
        hex::encode(expand256(b"abcdef0123456789", dst, 0x20)),
        "eff31487c770a893cfb36f912fbfcbff40d5661771ca4b2cb4eafe524333f5c1"
    );
    assert_eq!(
        hex::encode(expand256(b"abc", dst, 0x80)),
        "abba86a6129e366fc877aab32fc4ffc70120d8996c88aee2fe4b32d6c7b6437a\
         647e6c3163d40b76a73cf6a5674ef1d890f95b664ee0afa5359a5c4e07985635\
         bbecbac65d747d3d2da7ec2b8221b17b0ca9dc8a1ac1c07ea6a1e60583e2cb00\
         058e77b7b72a298425cd1b941ad4ec65e8afc50303a22c0f99b0509b4c895f40"
    );
}

#[test]
fn expand_message_xmd_sha256_oversize_dst() {
    // 47-byte prefix + 209 '1' == 256-byte DST, exercises the H2C-OVERSIZE-DST rule.
    let prefix = b"QUUX-V01-CS02-with-expander-SHA256-128-long-DST-";
    let mut dst = prefix.to_vec();
    dst.extend(std::iter::repeat_n(b'1', 256 - prefix.len()));
    assert_eq!(dst.len(), 256);
    assert_eq!(
        hex::encode(expand256(b"", &dst, 0x20)),
        "e8dc0c8b686b7ef2074086fbdd2f30e3f8bfbd3bdf177f73f04b97ce618a3ed3"
    );
    assert_eq!(
        hex::encode(expand256(b"abc", &dst, 0x20)),
        "52dbf4f36cf560fca57dedec2ad924ee9c266341d8f3d6afe5171733b16bbb12"
    );
}

fn affine_hex<C: WeierstrassParams>(p: &ProjectivePoint<C>) -> (String, String) {
    let (x, y) = p.to_affine().expect("not identity");
    let n = C::FIELD_BYTES;
    (
        hex::encode(&x.to_bytes()[48 - n..]),
        hex::encode(&y.to_bytes()[48 - n..]),
    )
}

fn check<C: Sswu>(dst: &[u8], msg: &[u8], x: &str, y: &str) {
    let p = hash_to_curve::<C>(msg, dst);
    assert!(p.is_on_curve().into_bool(), "point off curve");
    let (px, py) = affine_hex(&p);
    assert_eq!(px, x, "x mismatch for {:?}", core::str::from_utf8(msg));
    assert_eq!(py, y, "y mismatch for {:?}", core::str::from_utf8(msg));
}

#[test]
fn p256_xmd_sha256_sswu_ro() {
    let dst = b"QUUX-V01-CS02-with-P256_XMD:SHA-256_SSWU_RO_";
    check::<P256>(
        dst,
        b"",
        "2c15230b26dbc6fc9a37051158c95b79656e17a1a920b11394ca91c44247d3e4",
        "8a7a74985cc5c776cdfe4b1f19884970453912e9d31528c060be9ab5c43e8415",
    );
    check::<P256>(
        dst,
        b"abc",
        "0bb8b87485551aa43ed54f009230450b492fead5f1cc91658775dac4a3388a0f",
        "5c41b3d0731a27a7b14bc0bf0ccded2d8751f83493404c84a88e71ffd424212e",
    );
    check::<P256>(
        dst,
        b"abcdef0123456789",
        "65038ac8f2b1def042a5df0b33b1f4eca6bff7cb0f9c6c1526811864e544ed80",
        "cad44d40a656e7aff4002a8de287abc8ae0482b5ae825822bb870d6df9b56ca3",
    );
}

#[test]
fn p384_xmd_sha384_sswu_ro() {
    let dst = b"QUUX-V01-CS02-with-P384_XMD:SHA-384_SSWU_RO_";
    check::<P384>(
        dst,
        b"",
        "eb9fe1b4f4e14e7140803c1d99d0a93cd823d2b024040f9c067a8eca1f5a2eeac9ad604973527a356f3fa3aeff0e4d83",
        "0c21708cff382b7f4643c07b105c2eaec2cead93a917d825601e63c8f21f6abd9abc22c93c2bed6f235954b25048bb1a",
    );
    check::<P384>(
        dst,
        b"abc",
        "e02fc1a5f44a7519419dd314e29863f30df55a514da2d655775a81d413003c4d4e7fd59af0826dfaad4200ac6f60abe1",
        "01f638d04d98677d65bef99aef1a12a70a4cbb9270ec55248c04530d8bc1f8f90f8a6a859a7c1f1ddccedf8f96d675f6",
    );
}
