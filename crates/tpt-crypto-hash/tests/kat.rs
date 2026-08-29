//! Known-answer tests for the `tpt-crypto-hash` primitives.
//!
//! Vectors sources:
//! - SHA-2 / SHA-3 / SHAKE: NIST CAVP (empty + `abc`).
//! - BLAKE2b: RFC 7693 reference vectors.
//! - HMAC: RFC 4231 test case 1.
//! - HKDF: RFC 5869 test case 1.
//! - BLAKE3: official test vectors.
//! - KMAC / cSHAKE: NIST SP 800-185 published vectors.
//! - K12: RFC 9861 / draft-irtf-cfrg-kangarootwelve published vectors.

use tpt_crypto_hash::sha2::{sha224, sha256, sha384, sha512, sha512_224, sha512_256};
use tpt_crypto_hash::sha3::{sha3_224, sha3_256, sha3_384, sha3_512};
use tpt_crypto_hash::sha3::{cshake128, kmac128, shake128, shake256};
use tpt_crypto_hash::blake2b::{blake2b, blake2b_keyed};
use tpt_crypto_hash::blake3::{blake3, blake3_keyed};
use tpt_crypto_hash::k12::kangaroo_twelve;
use tpt_crypto_hash::mac::hmac_sha256;
use tpt_crypto_hash::kdf::hkdf_sha256;

fn decode_hex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn assert_eq_hex(label: &str, got: &[u8], expected_hex: &str) {
    let exp = decode_hex(expected_hex);
    assert_eq!(got, &exp[..], "{label} mismatch");
}

#[test]
fn sha2_empty() {
    assert_eq_hex("sha224", &sha224(b""), "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f");
    assert_eq_hex("sha256", &sha256(b""), "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    assert_eq_hex("sha384", &sha384(b""), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
    assert_eq_hex("sha512", &sha512(b""), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    assert_eq_hex("sha512_224", &sha512_224(b""), "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4");
    assert_eq_hex("sha512_256", &sha512_256(b""), "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a");
}

#[test]
fn sha2_abc() {
    assert_eq_hex("sha256(abc)", &sha256(b"abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    assert_eq_hex("sha512(abc)", &sha512(b"abc"), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}

#[test]
fn sha3_empty() {
    assert_eq_hex("sha3_224", &sha3_224(b""), "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7");
    assert_eq_hex("sha3_256", &sha3_256(b""), "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a");
    assert_eq_hex("sha3_384", &sha3_384(b""), "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004");
    assert_eq_hex("sha3_512", &sha3_512(b""), "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
}

#[test]
fn sha3_abc() {
    assert_eq_hex("sha3_256(abc)", &sha3_256(b"abc"), "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532");
}

#[test]
fn shake_empty() {
    let mut out = [0u8; 32];
    shake128(b"", &mut out);
    assert_eq_hex("shake128", &out, "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26");
    shake256(b"", &mut out);
    assert_eq_hex("shake256", &out, "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f");
}

#[test]
fn shake_abc_64() {
    let mut out = [0u8; 64];
    shake128(b"abc", &mut out);
    assert_eq_hex("shake128(abc)64", &out, "5881092dd818bf5cf8a3ddb793fbcba74097d5c526a6d35f97b83351940f2cc844c50af32acd3f2cdd066568706f509bc1bdde58295dae3f891a9a0fca578378");
    let mut out2 = [0u8; 64];
    shake256(b"abc", &mut out2);
    assert_eq_hex("shake256(abc)64", &out2, "483366601360a8771c6863080cc4114d8db44530f8f1e1ee4f94ea37e78b5739d5a15bef186a5386c75744c0527e1faa9f8726e462a12a4feb06bd8801e751e4");
}

#[test]
fn blake2b_kat() {
    assert_eq_hex("blake2b(empty)", &blake2b(b""), "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
    assert_eq_hex("blake2b(abc)", &blake2b(b"abc"), "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
    assert_eq_hex("blake2b_keyed(empty,k=abc)", &blake2b_keyed(b"", b"abc"), "91cc35fc51ce734eae9e57a20725d68062b0bd6de1965a4b5dc5eb4d60402d02d00b5079b0907775e317fd84a149634253c9d1fd01819e202729affbf47b00e5");
    assert_eq_hex("blake2b_keyed(def,k=abc)", &blake2b_keyed(b"def", b"abc"), "c5dc418f6f23a1fb24caae4d5610867f686512c686d730968b7934ac60c82ec86688af4d03e50a2a64a22711dd6d6ba1e0b4766b0e229d212077c43c36f4bc01");
}

#[test]
fn blake3_kat() {
    // Official BLAKE3 test vectors (test_vectors.json), 32-byte output.
    assert_eq_hex("blake3(empty)", &blake3(b""), "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
    // Input = repeating 0,1,..,250 pattern, length 3.
    let d3 = [0u8, 1, 2];
    assert_eq_hex(
        "blake3(len3)",
        &blake3(&d3),
        "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f",
    );
    // Keyed BLAKE3: key = "whats the Elvish word for friend" (32 bytes), empty msg.
    let key = b"whats the Elvish word for friend";
    assert_eq_hex(
        "blake3_keyed(empty)",
        &blake3_keyed(b"", key),
        "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26",
    );
    // Keyed BLAKE3, same key, 3-byte input.
    assert_eq_hex(
        "blake3_keyed(len3)",
        &blake3_keyed(&d3, key),
        "39e67b76b5a007d4921969779fe666da67b5213b096084ab674742f0d5ec62b9",
    );
}

#[test]
fn hmac_kat() {
    // RFC 4231 test case 1: key = 0x0b*20, data = "Hi There", SHA-256.
    let key = b"\x0b".repeat(20);
    assert_eq_hex("hmac_sha256 rfc4231-1", &hmac_sha256(&key, b"Hi There"), "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7");
    assert_eq_hex("hmac_sha256(abc,def)", &hmac_sha256(b"abc", b"def"), "20ebc0f09344470134f35040f63ea98b1d8e414212949ee5c500429d15eab081");
}

#[test]
fn hkdf_kat() {
    // RFC 5869 test case 1 (SHA-256).
    let salt = decode_hex("000102030405060708090a0b0c");
    let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let info = decode_hex("f0f1f2f3f4f5f6f7f8f9");
    let mut okm = [0u8; 42];
    hkdf_sha256(&salt, &ikm, &info, &mut okm);
    assert_eq_hex("hkdf_sha256 rfc5869-1", &okm, "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
}

#[test]
fn cshake_kat() {
    // NIST SP 800-185 cSHAKE128 Sample #1: N="", S="Email Signature",
    // X = 00 01 02 03, L = 256 bits.
    let msg = [0x00u8, 0x01, 0x02, 0x03];
    let mut out = [0u8; 32];
    cshake128(&msg, &mut out, b"", b"Email Signature");
    assert_eq_hex(
        "cshake128",
        &out,
        "c1c36925b6409a04f1b504fcbca9d82b4017277cb5ed2b2065fc1d3814d5aaf5",
    );
}

#[test]
fn kmac_kat() {
    // NIST SP 800-185 KMAC128 Sample #1: K = 0x40..0x5F (32 bytes),
    // X = 00 01 02 03, L = 256 bits, S = "".
    let key: Vec<u8> = (0x40u8..0x60).collect();
    let msg = [0x00u8, 0x01, 0x02, 0x03];
    let mut out = [0u8; 32];
    kmac128(&key, &msg, &mut out, b"");
    assert_eq_hex(
        "kmac128",
        &out,
        "e5780b0d3ea6f7d3a429c5706aa43a00fadbd7d49628839e3187243f456ee14e",
    );
}

#[test]
fn k12_kat() {
    // RFC 9861: KangarooTwelve(M=empty, C=empty, 32).
    let mut out = [0u8; 32];
    kangaroo_twelve(b"", b"", &mut out);
    assert_eq_hex("k12(empty,empty)", &out, "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5");
    // KangarooTwelve(M=0xFF, C=ptn(41), 32) — RFC 9861.
    let mut c = Vec::new();
    let pat: Vec<u8> = (0..0xFBu32).map(|x| x as u8).collect();
    while c.len() < 41 { c.extend(&pat); }
    c.truncate(41);
    let mut out2 = [0u8; 32];
    kangaroo_twelve(b"\xff", &c, &mut out2);
    assert_eq_hex("k12(0xff,ptn41)", &out2, "d848c5068ced736f4462159b9867fd4c20b808acc3d5bc48e0b06ba0a3762ec4");
}
