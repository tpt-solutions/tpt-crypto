//! RFC 9380 hash-to-curve KATs (vectors from the CFRG `draft-irtf-cfrg-hash-to-curve`
//! reference `poc/vectors/` JSON — see `tests/kat/PROVENANCE.md`).

use tpt_crypto_curve::hash_to_curve::{expand_message_xmd, hash_to_curve, Sswu};
use tpt_crypto_curve::weierstrass::{ProjectivePoint, WeierstrassParams, P256, P384};
use tpt_crypto_hash::sha2::Sha256;

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
