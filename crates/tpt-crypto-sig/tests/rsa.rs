//! RSA verification known-answer tests (OpenSSL-generated vectors).
#![cfg(not(feature = "profile-cnsa2"))] // 2048-bit vectors are below the CNSA 2.0 minimum; the 3072-bit set is in tests/rsa_3072.rs

use tpt_crypto_sig::rsa::{PublicKey, RsaHash};
use tpt_crypto_sig::Error;

const N_HEX: &str = "D19BD5872A55F4389C8BEEA7BF206E4A255C4FA413A8626A4B0A8E5EBAFA9869ABCE391667E9FBA2ED96D399A5E1D145C1807A2E4519091A69F22F3D4B49CC9A11D5B3FBD7CB26B6C610030C314CEB319FB0C98D3CA5CCC7FE7AAAD20CFA0A7E20AD660D11858CC40F69B1416332C5638DB756F5E2584B1F45002314DCBA8260C1D1B46DE621ABC96E73A710165F5164871BB2EB3E74141100285302CCD55D87403EC9B7035D5C3D3139B8E92783DF7E3AB24F878C64A42547F099A2C1E3AFE24E5C90120FB6E280BE7CB4AA26EA96BEF038F1B79015B73C41A9B04FE41E31D0BC65DF2664383041992B9C3559FB4F43647331FADD5DE15CCAE6304D6A6C5F47";
const MSG: &[u8] = b"tpt-crypto RSA vector message";
const SIG_P1_256: &str = "6b21c6e3dcbd45c59279464f2893adc5f49308d518a2440b22fb033bd1a52cb7b4d5054647a698e5e929bba5f4af79d46bc142412b0bf903134b6924fafcf0ea86f076105a8dd3377db05f056a2af2638a7c52f25b00bd041355bdc120672b15b7b23e9fba8af53491665c157963bdf77a82e183b3802271bd05b6634437f5739fac7cd1bfdc4482c0baeb4b7f7a5b0d6fa77e422bc69b7fc53bc3e6fea39254cdf9e7f4a90ae2c78738d640d7cfdcf3ba8e00cbccd2bf5449d321f00ff3be4bbd35512942f68289426063c20997ba2f7330491a58a6a66b8ead82811d5d25c0407bee870feb3016a80489d0062550835946dadf948a2541d2296d12244fc4d9";
const SIG_P1_384: &str = "1d8d1a62ffb7e0d70e9190ca830d8822d7006af530f426e676230c0c74a40a922e3559cad1bde06fe5a9e5528ff84c333bcbe5942c4f4f9a86113a88c128f4e422622898006f4a13c0174fa2e68275dcbfdd249b7049f6aa57b5476a0481f0ca8ee4f0b3555333e23fcdb653e513e61fad08621e67640a0a8aa450f8927293d0ec7d785be4eb3b782268afb2312b957b410ed114f43fa072f57907ebc245b8627578d51ec043349315c5f8e0e57e9e9ab8baed4acbff4e2a966e93d719400a9d4b434a26a12e6ef1111e26755161090b176c7c54dd306b14703cdb56e8d46ceb80f11a2708de27dc385902e5978b540cce98aee03a77365d57efe5e72064c89d";
const SIG_PSS_256: &str = "b63d2936ce6a574d3e7964a08242969038fc01a5bfaa50232babd3a29fae72ac04fe8ea83f55eff00f7e29bb916d1f27ac824bda85939deac31448049b7bc13fcc6cfc7734e047cb2f6e1e80497ecfa96e0beaf7dc9a033dafdef3f9e328bb8257bf753fdf42de0147014168872527d0692d62e4904fa42e024547863f24c59f0a1d09b8ac88417edd93bf03d47b65e9ae5639265bc7b303188c55ce6fe07c124a88d75b73acb892f84a69108393de5371f666d1ce334ddb09398ae67e59d77bf9d8aa4a8cb46af04d1359ead26605cee0d99d764481717cf89076292a89709b11de9d3711e388fd8f03a4bebaa2392b7fd7f8437052dd4cd1d8bd9526bc7d04";
const SIG_PSS_384: &str = "8bfe434339084ee0d11eb0a9285dedcbb617e3f321024cc9177cf75d7b1dbbf86423470ebd97b1ab688f7bfa73417d15a29947a1f324263e88b2aedd5bf90afc0263681a636b2f698dfb61a67471e21f71dac93f7e17825ed54cb33a633e15e3fe723ae141d76023aaea350ec69efc89384f22ea4e8dc371c1dbcdae81b17b729c72ef69ef92420f741515d35cd6231422e5d93fdf5b596934952a3e7984d9777173bb5b86ef6e0e4280200215f6631ca1639334c3e0c0fd10bb042fb60d127daba04e1eec6288061645b55179e17543734d4fb6036e6609140969d25c30fc8dae7fa97db1c8115f27639956bf88b392080690a87e4c33185cc774dac2ae920b";
const SIG_PSS_512: &str = "cb1214fe5c5b4f6513d9e692d411fc901429e27cb015d7b37335cc92736e95b0367c6cb5112310de72a9501c0ed9f151a43727f178005219ae1b3eb2370b86664b3320b3949f04d5fa33cfb5292ff0ac9a064405971a1a3b2a6d9e2ea1a7e5e7a8355c4a7574d8df458b8727b6817e78b5709bd72acdaac296e088d1379c62593d09b3f781c624fc9c091a7cf550083e4646e899e520d1ba0dd4ea3a9e46f7612749920bb92eb3df9a84aeb1568f03835b8a144f0e67891eeccd75542dc709ed32cbfb23292a5135f02a691ce799fe55af7a962e82833d7933416e8ac3489ee9a99dfc041d623d696512ae43be47090913e80027d7e69e219d81994f4d01e30d";

// Vectors generated with OpenSSL 1.1.1t: one RSA-2048 key (e = 65537),
// message `MSG`. PKCS#1 v1.5 signatures use SHA-256 / SHA-384; PSS signatures
// use SHA-256 (salt 32), SHA-384 (salt 48) and SHA-512 (salt 64).

fn hx(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn key() -> PublicKey {
    PublicKey::from_components(&hx(N_HEX), &[0x01, 0x00, 0x01]).unwrap()
}

#[test]
fn pkcs1v15_sha256_and_sha384_verify() {
    let k = key();
    assert_eq!(k.modulus_len(), 256);
    k.verify_pkcs1v15(RsaHash::Sha256, MSG, &hx(SIG_P1_256))
        .unwrap();
    k.verify_pkcs1v15(RsaHash::Sha384, MSG, &hx(SIG_P1_384))
        .unwrap();
}

#[test]
fn pkcs1v15_rejects_wrong_hash_message_and_signature() {
    let k = key();
    let sig = hx(SIG_P1_256);
    assert_eq!(
        k.verify_pkcs1v15(RsaHash::Sha384, MSG, &sig),
        Err(Error::Verification)
    );
    assert_eq!(
        k.verify_pkcs1v15(RsaHash::Sha256, b"tampered", &sig),
        Err(Error::Verification)
    );
    let mut bad = sig.clone();
    bad[100] ^= 0x01;
    assert_eq!(
        k.verify_pkcs1v15(RsaHash::Sha256, MSG, &bad),
        Err(Error::Verification)
    );
    // Wrong length.
    assert_eq!(
        k.verify_pkcs1v15(RsaHash::Sha256, MSG, &sig[1..]),
        Err(Error::Verification)
    );
    // PSS signature is not a valid PKCS#1 v1.5 signature.
    assert_eq!(
        k.verify_pkcs1v15(RsaHash::Sha256, MSG, &hx(SIG_PSS_256)),
        Err(Error::Verification)
    );
}

#[test]
fn pss_verify_all_hashes() {
    let k = key();
    k.verify_pss(RsaHash::Sha256, 32, MSG, &hx(SIG_PSS_256))
        .unwrap();
    k.verify_pss(RsaHash::Sha384, 48, MSG, &hx(SIG_PSS_384))
        .unwrap();
    k.verify_pss(RsaHash::Sha512, 64, MSG, &hx(SIG_PSS_512))
        .unwrap();
}

#[test]
fn pss_rejects_wrong_salt_length_message_and_signature() {
    let k = key();
    let sig = hx(SIG_PSS_256);
    assert_eq!(
        k.verify_pss(RsaHash::Sha256, 20, MSG, &sig),
        Err(Error::Verification)
    );
    assert_eq!(
        k.verify_pss(RsaHash::Sha256, 32, b"tampered", &sig),
        Err(Error::Verification)
    );
    let mut bad = sig.clone();
    bad[0] ^= 0x80;
    assert_eq!(
        k.verify_pss(RsaHash::Sha256, 32, MSG, &bad),
        Err(Error::Verification)
    );
    assert_eq!(
        k.verify_pss(RsaHash::Sha256, 32, MSG, &hx(SIG_P1_256)),
        Err(Error::Verification)
    );
}

#[test]
fn signature_at_or_above_modulus_is_rejected() {
    let k = key();
    // s = n: must be rejected before exponentiation.
    assert_eq!(
        k.verify_pkcs1v15(RsaHash::Sha256, MSG, &hx(N_HEX)),
        Err(Error::Verification)
    );
}

#[test]
fn key_validation() {
    let n = hx(N_HEX);
    // Even modulus.
    let mut even = n.clone();
    *even.last_mut().unwrap() &= 0xfe;
    assert!(PublicKey::from_components(&even, &[1, 0, 1]).is_err());
    // Even exponent, exponent 1, empty exponent.
    assert!(PublicKey::from_components(&n, &[1, 0, 0]).is_err());
    assert!(PublicKey::from_components(&n, &[1]).is_err());
    assert!(PublicKey::from_components(&n, &[]).is_err());
    // Too-small modulus (512 bits).
    assert!(PublicKey::from_components(&n[..64], &[1, 0, 1]).is_err());
    // Leading zeros are tolerated.
    let mut padded = vec![0u8, 0u8];
    padded.extend_from_slice(&n);
    assert!(PublicKey::from_components(&padded, &[0, 1, 0, 1]).is_ok());
}

// ---------------------------------------------------------------------------
// PKCS#1 RSAPublicKey DER (the form TLS certificates carry and rustls passes in).
// ---------------------------------------------------------------------------

fn der_tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    match body.len() {
        0..=127 => out.push(body.len() as u8),
        128..=255 => out.extend_from_slice(&[0x81, body.len() as u8]),
        _ => out.extend_from_slice(&[0x82, (body.len() >> 8) as u8, body.len() as u8]),
    }
    out.extend_from_slice(body);
    out
}

/// A minimal DER INTEGER for a non-negative big-endian value.
fn der_uint(v: &[u8]) -> Vec<u8> {
    let mut body = Vec::new();
    if v[0] & 0x80 != 0 {
        body.push(0);
    }
    body.extend_from_slice(v);
    der_tlv(0x02, &body)
}

fn pkcs1_der(n: &[u8], e: &[u8]) -> Vec<u8> {
    let mut body = der_uint(n);
    body.extend_from_slice(&der_uint(e));
    der_tlv(0x30, &body)
}

#[test]
fn pkcs1_der_key_verifies_existing_signatures() {
    let der = pkcs1_der(&hx(N_HEX), &[0x01, 0x00, 0x01]);
    let k = tpt_crypto_sig::encoding::rsa_public_from_pkcs1(&der).unwrap();
    assert_eq!(k.modulus_be(), &hx(N_HEX)[..]);
    assert_eq!(k.exponent_be(), &[0x01, 0x00, 0x01]);
    k.verify_pkcs1v15(RsaHash::Sha256, MSG, &hx(SIG_P1_256))
        .unwrap();
    k.verify_pss(RsaHash::Sha256, 32, MSG, &hx(SIG_PSS_256))
        .unwrap();
}

#[test]
fn pkcs1_der_rejects_malformed_encodings() {
    let n = hx(N_HEX);
    let e = [0x01u8, 0x00, 0x01];
    let good = pkcs1_der(&n, &e);
    assert!(tpt_crypto_sig::encoding::rsa_public_from_pkcs1(&good).is_ok());

    // Trailing bytes after the sequence.
    let mut trailing = good.clone();
    trailing.push(0);
    assert!(tpt_crypto_sig::encoding::rsa_public_from_pkcs1(&trailing).is_err());

    // Modulus with the high bit set and no 0x00 pad: a negative INTEGER.
    let mut neg_body = der_tlv(0x02, &n);
    neg_body.extend_from_slice(&der_uint(&e));
    let negative = der_tlv(0x30, &neg_body);
    assert!(tpt_crypto_sig::encoding::rsa_public_from_pkcs1(&negative).is_err());

    // Wrong outer tag (SET instead of SEQUENCE).
    let mut set = good.clone();
    set[0] = 0x31;
    assert!(tpt_crypto_sig::encoding::rsa_public_from_pkcs1(&set).is_err());

    // Even modulus is rejected by key validation.
    let mut even = n.clone();
    *even.last_mut().unwrap() &= 0xfe;
    assert!(tpt_crypto_sig::encoding::rsa_public_from_pkcs1(&pkcs1_der(&even, &e)).is_err());
}

// PKCS#1 v1.5 SHA-512 vector: a separate throwaway RSA-2048 key (e = 65537) generated with
// OpenSSL 1.1.1t for this test and re-verified with `openssl dgst -verify`. Public values only.
const N512_HEX: &str = "C7357A80AF11B36A46FC20159F2E5973686E1F1A4ABD56366B28D3853F83C8B776A88C19939D38B799F44BC691AC8AF7A88B3504F686E3AB03391F6A363599C605CDA846B7644FE4690DAF19FC6F383D25D64A892D81AFAFEDC1BFA4086E69FAE6EC2B1331A51106EC7484001EF7258E1E36E029F7CFE06516BBA09985384752FA62F7A798FABA4BD9C576619952539244BDE5D11A716A711DA37D57D3682E38401F718E3DA0C5BB4BE4B3D2B04A7C1270F969362C6A8949D92456D9D9F6A5B867AB23009494D4AF88C5EAE22DDF338FB9F2A37D9C0CA0A7278BFD590EAA128A5DBC4BBA3CAAFB9AE318CDA01AA5867D2549C7A2423E0D71C1849FD179FD8505";
const SIG_P1_512: &str = "839a12418d205354bdbe663bfa98002f3e27db74161f30d6670404225055df34b83dd6a418ffc841712b29ad7bea5fa4af66dde04ac39f5dfdc6aafc6ccbbf887e81d3b6d8f7784798e8cf7550f057aea425cacf19dab089af8d73f3b3a33a3ea84db9754ccb6d55f294f2880b292172d0d2df96c9ef6dd422020f694a5a34629c58239e2325181cf938b5e43c221123bef617caea4dd78289eee949ddc9c04493347e902d7b8244037aa9abdb15ac362f508829bfc61c71ce850f8aca068ad45ed3d081c26d7e25013d7ffecf136059e048c68d5f93959a443531f1f461c6536363c63f93a14a96406890cb90830675e1d512fcfd2f1badc9a967b94552f8c1";

#[test]
fn pkcs1v15_sha512_verifies_and_rejects_tampering() {
    let k = PublicKey::from_components(&hx(N512_HEX), &[0x01, 0x00, 0x01]).unwrap();
    let sig = hx(SIG_P1_512);
    k.verify_pkcs1v15(RsaHash::Sha512, MSG, &sig).unwrap();
    // Wrong hash for this signature.
    assert_eq!(
        k.verify_pkcs1v15(RsaHash::Sha256, MSG, &sig),
        Err(Error::Verification)
    );
    // Tampered message and tampered signature.
    let mut msg = MSG.to_vec();
    msg[0] ^= 1;
    assert_eq!(
        k.verify_pkcs1v15(RsaHash::Sha512, &msg, &sig),
        Err(Error::Verification)
    );
    let mut bad = sig.clone();
    bad[100] ^= 0x10;
    assert_eq!(
        k.verify_pkcs1v15(RsaHash::Sha512, MSG, &bad),
        Err(Error::Verification)
    );
    // Wrong length.
    assert_eq!(
        k.verify_pkcs1v15(RsaHash::Sha512, MSG, &sig[1..]),
        Err(Error::Verification)
    );
}
