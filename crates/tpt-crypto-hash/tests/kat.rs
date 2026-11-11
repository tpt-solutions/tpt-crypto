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

use tpt_crypto_hash::blake2b::{blake2b, blake2b_keyed};
use tpt_crypto_hash::blake3::{blake3, blake3_keyed};
use tpt_crypto_hash::k12::kangaroo_twelve;
use tpt_crypto_hash::kdf::hkdf_sha256;
use tpt_crypto_hash::mac::hmac_sha256;
use tpt_crypto_hash::sha2::{sha224, sha256, sha384, sha512, sha512_224, sha512_256};
use tpt_crypto_hash::sha3::{cshake128, kmac128, shake128, shake256};
use tpt_crypto_hash::sha3::{sha3_224, sha3_256, sha3_384, sha3_512};

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
    assert_eq_hex(
        "sha224",
        &sha224(b""),
        "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f",
    );
    assert_eq_hex(
        "sha256",
        &sha256(b""),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    );
    assert_eq_hex("sha384", &sha384(b""), "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b");
    assert_eq_hex("sha512", &sha512(b""), "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e");
    assert_eq_hex(
        "sha512_224",
        &sha512_224(b""),
        "6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4",
    );
    assert_eq_hex(
        "sha512_256",
        &sha512_256(b""),
        "c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a",
    );
}

#[test]
fn sha2_abc() {
    assert_eq_hex(
        "sha256(abc)",
        &sha256(b"abc"),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
    );
    assert_eq_hex("sha512(abc)", &sha512(b"abc"), "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f");
}

#[test]
fn sha3_empty() {
    assert_eq_hex(
        "sha3_224",
        &sha3_224(b""),
        "6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
    );
    assert_eq_hex(
        "sha3_256",
        &sha3_256(b""),
        "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
    );
    assert_eq_hex("sha3_384", &sha3_384(b""), "0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004");
    assert_eq_hex("sha3_512", &sha3_512(b""), "a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26");
}

#[test]
fn sha3_abc() {
    assert_eq_hex(
        "sha3_256(abc)",
        &sha3_256(b"abc"),
        "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
    );
}

#[test]
fn shake_empty() {
    let mut out = [0u8; 32];
    shake128(b"", &mut out);
    assert_eq_hex(
        "shake128",
        &out,
        "7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26",
    );
    shake256(b"", &mut out);
    assert_eq_hex(
        "shake256",
        &out,
        "46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762f",
    );
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
    assert_eq_hex(
        "blake3(empty)",
        &blake3(b""),
        "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    );
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
    assert_eq_hex(
        "hmac_sha256 rfc4231-1",
        &hmac_sha256(&key, b"Hi There"),
        "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7",
    );
    assert_eq_hex(
        "hmac_sha256(abc,def)",
        &hmac_sha256(b"abc", b"def"),
        "20ebc0f09344470134f35040f63ea98b1d8e414212949ee5c500429d15eab081",
    );
}

#[test]
fn hkdf_kat() {
    // RFC 5869 test case 1 (SHA-256).
    let salt = decode_hex("000102030405060708090a0b0c");
    let ikm = decode_hex("0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b");
    let info = decode_hex("f0f1f2f3f4f5f6f7f8f9");
    let mut okm = [0u8; 42];
    hkdf_sha256(&salt, &ikm, &info, &mut okm);
    assert_eq_hex(
        "hkdf_sha256 rfc5869-1",
        &okm,
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
    );
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
    assert_eq_hex(
        "k12(empty,empty)",
        &out,
        "1ac2d450fc3b4205d19da7bfca1b37513c0803577ac7167f06fe2ce1f0ef39e5",
    );
    // KangarooTwelve(M=0xFF, C=ptn(41), 32) — RFC 9861.
    let mut c = Vec::new();
    let pat: Vec<u8> = (0..0xFBu32).map(|x| x as u8).collect();
    while c.len() < 41 {
        c.extend(&pat);
    }
    c.truncate(41);
    let mut out2 = [0u8; 32];
    kangaroo_twelve(b"\xff", &c, &mut out2);
    assert_eq_hex(
        "k12(0xff,ptn41)",
        &out2,
        "d848c5068ced736f4462159b9867fd4c20b808acc3d5bc48e0b06ba0a3762ec4",
    );
}

/// FIPS 180-4 two-block messages (896 bits and 448 bits). The one-block KATs above
/// only put data in the first 12 bytes of a block, so they miss the word loads from
/// bytes 12 onward. These cover them. Both sets are the standard published digests.
#[test]
fn sha2_multi_block() {
    let msg896 = b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu";
    assert_eq_hex(
        "sha512(896-bit)",
        &sha512(msg896),
        "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909",
    );
    assert_eq_hex(
        "sha256(448-bit)",
        &sha256(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
        "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1",
    );
}

/// BLAKE2b with a non-64-byte digest length (`blake2b_var`, used by Argon2). Standard
/// BLAKE2b-256 of "abc", and the 64-byte variant must equal the fixed-size function.
#[test]
fn blake2b_var_known_answers() {
    use tpt_crypto_hash::blake2b::blake2b_var;
    assert_eq_hex(
        "blake2b-256(abc)",
        &blake2b_var(32, &[b"abc"]),
        "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319",
    );
    assert_eq!(blake2b_var(64, &[b"abc"]), blake2b(b"abc").to_vec());
    // Split input must equal the one-shot digest.
    assert_eq!(blake2b_var(32, &[b"a", b"bc"]), blake2b_var(32, &[b"abc"]));
}

/// Streaming BLAKE2b split at every position over every short length. The buffer
/// logic has to hold at each 128-byte boundary, where an exact fit must not flush early.
#[test]
fn blake2b_streaming_at_every_split() {
    use tpt_crypto_hash::blake2b::Blake2b;
    use tpt_crypto_hash::Hasher;
    for len in 0..=260usize {
        let data: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
        let want = blake2b(&data);
        for split in 0..=len {
            let mut h = Blake2b::<64>::new();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finalize_reset(), want, "len {len} split {split}");
        }
    }
}

/// `reset` and `finalize_reset` return the hasher to its initial state, so a reused
/// hasher must match a fresh one.
#[test]
fn blake2b_reuse_matches_fresh() {
    use tpt_crypto_hash::blake2b::Blake2b;
    use tpt_crypto_hash::Hasher;
    let mut h = Blake2b::<64>::new();
    h.update(b"first message");
    let _ = h.finalize_reset();
    h.update(b"abc");
    assert_eq!(h.finalize_reset(), blake2b(b"abc"));
    h.update(b"junk that must be discarded");
    h.reset();
    h.update(b"abc");
    assert_eq!(h.finalize_reset(), blake2b(b"abc"));
}

/// BLAKE3 inputs longer than one 1024-byte chunk, so the chunk-tree code runs. The
/// digests and 64-byte XOF outputs come from the upstream `blake3` crate 1.x, which
/// was run on the same byte pattern (byte i = i mod 251). The four short vectors
/// above never reach the tree logic.
#[test]
fn blake3_multi_chunk_reference() {
    use tpt_crypto_hash::blake3::Blake3;
    use tpt_crypto_hash::Xof;
    let cases: [(usize, &str, &str); 9] = [
        (1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11", "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11a182d27a591b05592b15607500e1e8dd56bc6c7fc063715b7a1d737df5bad333"),
        (1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7", "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af71cf8107265ecdaf8505b95d8fcec83a98a6a96ea5109d2c179c47a387ffbb404"),
        (1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444", "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444f4c4a22b4b399155358a994e52bf255de60035742ec71bd08ac275a1b51cc6bf"),
        (2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a", "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a9a60bf80001410ec9eea6698cd537939fad4749edd484cb541aced55cd9bf547"),
        (3000, "5fade288bf27444bee55ba2babb98c3c922c1e84c2e445e7d1f6da24756f5060", "5fade288bf27444bee55ba2babb98c3c922c1e84c2e445e7d1f6da24756f50604a5137265e81e5154685535a7e45a6cf8fcdd0e47eba71f39401a315734b215b"),
        (4096, "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969", "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e9690289e9409ddb1b99768eafe1623da896faf7e1114bebeadc1be30829b6f8af70"),
        (4097, "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995", "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb99505f91b0b5600a11251652eacfa9497b31cd3c409ce2e45cfe6c0a016967316c4"),
        (8192, "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63", "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a635fe51a27db045a567c1ad51be5aa34c01c6651c4d9b5b5ac5d0fd58cf18dd61a"),
        (10_000, "5f81f9e4ab67627b6b036d5d4e3bc40d9d3daa6fcc2b6dd07ab2bbf0a877da54", "5f81f9e4ab67627b6b036d5d4e3bc40d9d3daa6fcc2b6dd07ab2bbf0a877da5443eae36a6686feb8cf715071b892c67d7e32412dd9ea6afcda419464c146cf1e"),
    ];
    for (len, want_hash, want_xof) in cases {
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        assert_eq_hex(&format!("blake3({len})"), &blake3(&data), want_hash);
        let mut h = Blake3::new();
        h.update(&data);
        let mut out = [0u8; 64];
        h.finalize_xof_reset(&mut out);
        assert_eq_hex(&format!("blake3-xof64({len})"), &out, want_xof);
    }
    let key = b"whats the Elvish word for friend";
    let data: Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();
    assert_eq_hex(
        "blake3_keyed(5000)",
        &blake3_keyed(&data, key),
        "27dc394fb01f055606c3aedde3a8c3694c34a8c514cc61a27279f1417cc385e0",
    );
}

/// BLAKE3 streaming split at chunk boundaries (1023..=1025, 2048, 2049) at every
/// position near each boundary. The buffer flush must not fire early on an exact fit.
#[test]
fn blake3_streaming_at_chunk_boundaries() {
    use tpt_crypto_hash::blake3::Blake3;
    use tpt_crypto_hash::Xof;
    for len in [1023usize, 1024, 1025, 2048, 2049] {
        let data: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let want = blake3(&data);
        for split in (0..=len).step_by(7).chain((len.saturating_sub(3))..=len) {
            let mut h = Blake3::new();
            h.update(&data[..split]);
            h.update(&data[split..]);
            let mut out = [0u8; 32];
            h.finalize_xof_reset(&mut out);
            assert_eq!(out, want, "len {len} split {split}");
        }
    }
}

/// BLAKE3 XOF output longer than one 64-byte block, including lengths that are not a
/// multiple of 64, and the `reset` path. References from the upstream `blake3` crate
/// 1.x: input is the 5000-byte pattern (byte i = i mod 251) or "abc".
#[test]
fn blake3_xof_long_output_and_reset() {
    use tpt_crypto_hash::blake3::Blake3;
    use tpt_crypto_hash::Xof;
    let data: Vec<u8> = (0..5000).map(|i| (i % 251) as u8).collect();

    let mut h = Blake3::new();
    h.update(&data);
    let mut out = [0u8; 65];
    h.finalize_xof_reset(&mut out);
    assert_eq_hex("blake3-xof(65)", &out, "ee78d92070de3df1c57c37002abf0a6b1a6589acdeef4d8ffac7cf3d9e8f2836a995bc68ef4294ff70100b1695e727c159488a2b4d1150044d2525c4b297a23518");

    let mut h = Blake3::new();
    h.update(&data);
    let mut out = [0u8; 100];
    h.finalize_xof_reset(&mut out);
    assert_eq_hex("blake3-xof(100)", &out, "ee78d92070de3df1c57c37002abf0a6b1a6589acdeef4d8ffac7cf3d9e8f2836a995bc68ef4294ff70100b1695e727c159488a2b4d1150044d2525c4b297a23518b7a361552c546c36caec6e7e7f280aebb558291ef28fc4e7569af68c39a4c473877051");

    let mut h = Blake3::new();
    h.update(&data);
    let mut out = [0u8; 200];
    h.finalize_xof_reset(&mut out);
    assert_eq_hex("blake3-xof(200)", &out, "ee78d92070de3df1c57c37002abf0a6b1a6589acdeef4d8ffac7cf3d9e8f2836a995bc68ef4294ff70100b1695e727c159488a2b4d1150044d2525c4b297a23518b7a361552c546c36caec6e7e7f280aebb558291ef28fc4e7569af68c39a4c473877051616caf93e59f6721b9e5bb1bcc73d7db7b77f6222f43b8aa375606badd1d2f96c74c78e0d0b011fd71192c588bf624b6c82fdfb31921fa7c4184304a63c008b73cba0734efcfe94e42dba1fc5ca5e783f8570aa30acba6293744abcd5a527f1a8dfd1f53");

    let mut h = Blake3::new();
    h.update(b"junk that must be discarded");
    h.reset();
    h.update(b"abc");
    let mut out = [0u8; 100];
    h.finalize_xof_reset(&mut out);
    assert_eq_hex("blake3-xof(abc,100) after reset", &out, "6437b3ac38465133ffb63b75273a8db548c558465d79db03fd359c6cd5bd9d851fb250ae7393f5d02813b65d521a0d492d9ba09cf7ce7f4cffd900f23374bf0bc08a1fb0b38ed276181ccbd9f7b7edbddf9f86404ad7929605f6ffa3fb1ac87983105f01");
}

/// KangarooTwelve on inputs past one 8192-byte leaf, so the tree-hashing path runs (the RFC
/// vectors above are short). The digests come from the `tiny-keccak` crate 2.x (its K12),
/// run in a scratch project outside the repository. Input is the byte pattern i mod 251 and
/// the customization is the pattern 0..7.
#[test]
fn k12_long_inputs_reference() {
    let c: Vec<u8> = (0..7u8).collect();
    let cases: [(usize, &str); 8] = [
        (8191, "cd8baf0b2ddc3589006a6dbfe1bf286c88c7e90163a590528bd5154a89246b68"),
        (8192, "248101a4dec830ffcab633a37d16f0633bbff2813a0476828981e06c8f816ded"),
        (8193, "cbbf597e392251dacd3941d091351b43a61aee82588ff52ab7718022d170c4e5"),
        (8200, "b2b38990282320c049edab4eabddbe6efdd7b32ef8ccf78eb765fcb10782608f"),
        (16384, "90bdd4a0ef76d74d8ebd1e32db1d68252e564a43de2c2b0b5644eeda6bb17f08"),
        (16385, "a91c4722c60380ce1bf7c61c9a7f9babcca07570485740ed8749b24d7d7ef291"),
        (20000, "255fdaf49aa83dbd64245832b9cdce8bbf7dbd1cd91909c9b94e1dadd5cab55f"),
        (50000, "125dc18fe1edabc341219db0bdc5fc34c6714f83547940666245f0daf06b8b4a"),
    ];
    for (len, want) in cases {
        let m: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let mut out = [0u8; 32];
        kangaroo_twelve(&m, &c, &mut out);
        assert_eq_hex(&format!("k12(len {len}, c7)"), &out, want);
    }
    // Long output from a short message: 100 bytes.
    let m3: Vec<u8> = (0..3u8).collect();
    let mut out = [0u8; 100];
    kangaroo_twelve(&m3, b"", &mut out);
    assert_eq_hex(
        "k12(len 3, out 100)",
        &out,
        "bb0dc9ebca92864370dd7bebe03ace14a95d377fc3295d721ed188134d8359b35353f103768701e89f1d035ebd3147a9895b00948450ce0e9659fa1ab78fad1d4032a6cf1513a21e98bf25dc668c4cca635dc83cd2a3e717c9a568731e45e39778e529eb",
    );
}

/// KangarooTwelve at the sponge rate boundary (message lengths 167, 168, 169, 335, 336, one
/// byte short of or past a full block), with a 300-byte customization (two-byte length
/// encoding), and with a 500-byte output (more than one rate block). References from the
/// tiny-keccak crate's K12, as in the test above.
#[test]
fn k12_rate_boundaries_and_long_output() {
    use tpt_crypto_hash::k12::KangarooTwelve;
    use tpt_crypto_hash::Xof;
    let c7: Vec<u8> = (0..7u8).collect();
    let cases: [(usize, &str); 5] = [
        (167, "8fba4292095007d349edec415d1f14a6509d62247aee794bb3fc1158e1d833df"),
        (168, "9d22ee29b6e0dbf4bcebf3c1677451971edb9c64fe02edd30e0433bcfb674584"),
        (169, "20a7ebc7362176f93426e147f3c92f9f6445228b9e0282cc391625205d344442"),
        (335, "f93223452769df2df85f63a826c4c93f5529aacb7daff66e35cfb5553d1bc6ba"),
        (336, "19b86a4f4037d985e009d63177e985737d87b9bf1f3fbb2854258da01a0ac195"),    ];
    for (len, want) in cases {
        let m: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
        let mut out = [0u8; 32];
        kangaroo_twelve(&m, &c7, &mut out);
        assert_eq_hex(&format!("k12 rate len {len}"), &out, want);
    }

    let big_c: Vec<u8> = (0..300usize).map(|i| (i % 251) as u8).collect();
    let m5: Vec<u8> = (0..5usize).map(|i| (i % 251) as u8).collect();
    let mut out = [0u8; 32];
    kangaroo_twelve(&m5, &big_c, &mut out);
    assert_eq_hex("k12 customization 300", &out, "3f98988f72fafbac34f42f174de1ab2a06f1ce8eed79bc17c42f92407a37f889");

    let m3: Vec<u8> = (0..3usize).map(|i| (i % 251) as u8).collect();
    let mut k = KangarooTwelve::new(b"");
    Xof::update(&mut k, &m3);
    let mut long = [0u8; 500];
    Xof::finalize_xof_reset(&mut k, &mut long);
    assert_eq_hex("k12 xof 500", &long, "bb0dc9ebca92864370dd7bebe03ace14a95d377fc3295d721ed188134d8359b35353f103768701e89f1d035ebd3147a9895b00948450ce0e9659fa1ab78fad1d4032a6cf1513a21e98bf25dc668c4cca635dc83cd2a3e717c9a568731e45e39778e529eb0095634a8c841e470e67fa7b48fc17fe2d3eba6f8649b53b28576a3dc314ab8115907d691e8df15bd0aa9f52ac179551b4d3925d13c0cbd133cd217c188cd2e245937a07dcb1551ce9bbb95f4a78c4a68863eaf3db0a165f0ac719b9920cb5cf0a252112ef06b4d951af4b75dacede16110d573fd3cad2f3aed636b3630090d28b236d715181e7a78d4ec4b32fec151b88f2b4e7d26175514096bf93454fa47a9f04af279b3bd98f8c9d4eb5e31b8feae07b260d167b78c4738ea6f73c709b9c80fd00ea61a537f9e67e8df37948408e404f7f86ef3bfae426ab9f2dbb7776a4dcc49ce16fe816ab6d5e25530cec9cff870798d320aabb29366100c38b51de732c63750a085a26ddd5194c4e6b16f5a13cb8d5bf58f2584cfa65fd50538593f0a58fc998129149652f6e41ab2c067d190ab12425505f788e94591d9a9756ebaf9a8683bed133a67a1ab4edab641915ab369288db6e41fa36a254cb5d10f56f73e32402b827eb69e669329efa334e8d068f4f7e658608d1ee5add9388b50635579b55a611748e95247ec198e53a1fc6ea");
}

/// KangarooTwelve states the rate-boundary cases that the tests above do not reach. A
/// single-leaf message of 166 bytes with an empty customization absorbs 167 bytes (the
/// one-byte `right_encode(0)` included), so the suffix byte lands on the last rate byte and
/// no extra permutation may run. A 60000-byte message has seven chunk values, so the
/// TurboShake buffer reaches 160 bytes before a 32-byte absorb, which must split at the
/// rate boundary. References from the `tiny-keccak` crate 2.x, as above.
#[test]
fn k12_rate_edge_states_reference() {
    let m: Vec<u8> = (0..166usize).map(|i| (i % 251) as u8).collect();
    let mut out = [0u8; 32];
    kangaroo_twelve(&m, b"", &mut out);
    assert_eq_hex(
        "k12(len 166, empty c)",
        &out,
        "cbbe9dd1e423f20003fba7bb219491c8d1f445fa5c4199d6c6c70c9fdc101964",
    );

    let c7: Vec<u8> = (0..7u8).collect();
    let m: Vec<u8> = (0..60000usize).map(|i| (i % 251) as u8).collect();
    kangaroo_twelve(&m, &c7, &mut out);
    assert_eq_hex(
        "k12(len 60000, c7)",
        &out,
        "1cb0a10d78bd56cf40074743f5eca80b97eb6e69c10e02d2f93d66c07b295acb",
    );
}

/// Streaming KangarooTwelve split at every position over every length up to 400 bytes,
/// so each absorb boundary (partial buffer, exact block fill) is exercised against the
/// one-shot result.
#[test]
fn k12_streaming_at_every_split() {
    use tpt_crypto_hash::k12::KangarooTwelve;
    use tpt_crypto_hash::Xof;
    let c: Vec<u8> = (0..5u8).collect();
    for len in 0..=400usize {
        let m: Vec<u8> = (0..len).map(|i| (i * 13 + 1) as u8).collect();
        let mut one = [0u8; 40];
        kangaroo_twelve(&m, &c, &mut one);
        for split in 0..=len {
            let mut k = KangarooTwelve::new(&c);
            Xof::update(&mut k, &m[..split]);
            Xof::update(&mut k, &m[split..]);
            let mut out = [0u8; 40];
            Xof::finalize_xof_reset(&mut k, &mut out);
            assert_eq!(out, one, "len {len} split {split}");
        }
    }
}

/// The KangarooTwelve `Xof` methods that the streaming test does not call: `finalize_xof`
/// consumes the hasher, and `reset` discards buffered input so a reused hasher matches a fresh one.
#[test]
fn k12_xof_finalize_and_reset() {
    use tpt_crypto_hash::k12::KangarooTwelve;
    use tpt_crypto_hash::Xof;
    let c: Vec<u8> = (0..5u8).collect();
    let m: Vec<u8> = (0..40u8).collect();
    let mut want = [0u8; 40];
    kangaroo_twelve(&m, &c, &mut want);

    let mut k = KangarooTwelve::new(&c);
    Xof::update(&mut k, &m);
    let mut out = [0u8; 40];
    Xof::finalize_xof(k, &mut out);
    assert_eq!(out, want);

    let mut k = KangarooTwelve::new(&c);
    Xof::update(&mut k, b"junk that must be discarded");
    Xof::reset(&mut k);
    Xof::update(&mut k, &m);
    let mut out2 = [0u8; 40];
    Xof::finalize_xof_reset(&mut k, &mut out2);
    assert_eq!(out2, want);
}
