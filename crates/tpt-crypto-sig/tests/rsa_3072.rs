//! RSA-3072 verification known-answer tests.
//!
//! The 3072-bit set is the minimum modulus under `profile-cnsa2`, so these run in
//! every build. Vectors were generated with Python `cryptography` (OpenSSL backend)
//! from one fresh RSA-3072 key, e = 65537, over the message in `MSG`. PKCS#1 v1.5
//! uses SHA-256 and SHA-384; PSS uses SHA-256 (salt 32), SHA-384 (salt 48) and
//! SHA-512 (salt 64).

use tpt_crypto_sig::rsa::{PublicKey, RsaHash};
use tpt_crypto_sig::Error;

const N_HEX: &str = "b375ccfd6f93ae6cb25258c05793786b83a363490209818368d4c076096eff4a817b60768ca457f29ebe1d3f90fbf7958f144ba00271c33a62d6d608afdcac6d1295c4818ebfd50ae8c8718f5b26a65f0ca4b711a89e4a255a422671d2115891b76d220b4eee34017740350f42249545e86c19aae58f81aa3a3b6646371de9ecad8af52eede650bcf0817be272f287d8df5143b465a48e4cba9ae8eca4fe0d542e6191bfa57277c33e896ef68f88f7cc2e3a15d6de692172cb36376cd261fc72979dbfbf8099b3a79d169fbcd87b98114f4e499d07eb430b1314814123f27263590dc4035f622ab0e9e0da47c5f689dd7686dc7793468f77d53fbbc6c12600c6cfe1c50f805259a3e6fcf160efe5c469848926b198978c20b11384bdb8e967635d1e722b5c800b3fbdb1077dafc3a734fd9cb3912dd7ed4e44dbabb34dfbc52f75502bcf9f276de9f931db09ebec5bcc2c8a40fd760034a5b0aa04d04581f173a1b47e2283f2e951eff6d998a1e32d1be8cf716118b7f46ffe2eeb8a17e3cc7d";
const MSG: &[u8] = b"tpt-crypto RSA vector message";
const SIG_P1_256: &str = "508dfcd1d718d40f3d52619b8e3c09aeabf93125b316ce4ea920eb1481b4fa9c4193711473aed8a97be38015df0eb1ebf6fb5f6669896174efb6bb95ee2c5def61ab591439db46a45b95cc6c4d252ad78f4415c4f7f275b4af2555a8eef999dc944bcfa5f625b4589cfcefd81b4cc947176a94ac62a29cd8a272edc7399ff95d2858619086b1bc5631e1e4e6f1058a6296bf568689012bdcf79ee5a4128eb4fb0e0532a6cc28687b53f2a6d915ab0539e88cc4411f612f8249ccae6a45f9eb3471da6bc4480546dc90c44227da2e6bf235ab6f07acec1f07cb235f029dd95d40528f240673c8e2f96e0b48993e1884a1f0575b53540e6a69e1b1a2fc2c3fb4da6d86363d46badacd27891bc2b075b40fda4f44b58f877aae7a0e3f5c844981e4d0173de5c5b1fbb0669642f68a062ee065eaab83fe266c1d8f7d81a930f7e5a9855bc3851bae006c3fbf7fe53a21a2a6d04132678bb747babe0d05c3636f847b269b28859550cdcb4a22ea4d6645e2de98c117b149d6f2dc2389129c7c73c57a";
const SIG_P1_384: &str = "a1c12e49f8ef259633cb3c40f7c17140a4cb68db47ac3f1a260b3f0c71433f59360acfdb6dbb857e355fd1ea8a9813ba46cf8b8ff371ef264bf721f88314307197020f564fcf482b154422f9675231ce0d369b833eaf626b21cb22a1b72aa4a11ae22924a6134ead16e6df6fe428d4c1b7d1f75468ecaf3f36b7b7ee456d4d297e5ebaf0b053491c05fbc57e1b208c5a1d0f6714b0f45b1c36b7555010bd332158d160266ee114a40c6889f6fe46c1b6e4b247991331b5d03acb061f0447a83ebf88723e9c72e67f6e1936f51f188b15f23006af4d63d762ae3a1e5cfa4b81892b535dbb37d712438839e1a87c0468ab3149336597792489fc1616adfc52b0e1d2c00792a8f4a28647de2ceccbb93a58e6aca46923da444e8a1c3ed48d514c23beb8a55386905af3432a7fe2c81b46b407718a2bec68ec7ea94200f64e0292f5b9b2449f2332da22e5440cf7cc91a33478607d31b73967cec8a72330eca263be720a7db1b5dd7507effd08f677e27622ce19a515ceb37b4a6bb2d941859d896a";
const SIG_PSS_256: &str = "3b35fe1b191f5a66a65b73718dc14c56f91663799011a93fc79ee869f2a36d7ddd6391926c21cf7f18a2e652487326ad7f11a9f141819414e1081a6dc2246079742bb8dd5fe77db368a3132147c2fe30430d3fd14c0b6aa9ca3eb25c3c79bf2a78c3c479999a67e86eb2ae8d1cc0a4533789f616e52e6a484a84c529293e0363492bb34d28212fa43ef9d8d8e1ded83c2298b5a23226835028593934b75d6af8a65b8829051fe6595cbc64f4975db8bcd393ad88f8395c2911808ffe3e2485b9e538a24bf031921fdc037e5089a750ee92347730b1443596b9a93fdf012c66114f1c13b51e36c428a94a4f320237b718a4b7ff6330bc9de7b9ec89a96e77ce01477aff25055eb0bfbecffb581856e6ac418931252f85100b248d39ba63c26502e380b0816f84bb27d8793b5f66544c919c13adf8e12e091b160a4052cb0a0dab835ba80f146fe521127973c5dd413fc1220bd4d284669b404eb74d440db8f5cf116850102cb0bad51899a5e26a55f52de8e84b721c83017a2988bcb47951776c";
const SIG_PSS_384: &str = "31974800d70c5673801380c3aaad3beca5cd59f90aed555e2deeecebcfce2776b722527464ccdb04d7c7505204a32fec1b116ecae0a4daaab0d528a607968c52f202b621cfff4723e25b8788ecebfda596322400a95049e94b6000d35c245737afc2769c6f4d1e6d71f078ee377650f34c7aaa05a1d4336fa1d112cb7fd3dd09f761fa304f50e8975429f20fae6560aafe7e376bd63356dfcf060cfdfe70753cc12b940b925325170fb9fb1b1dc0fa2c0f9840d2e6faf100f56778e963f1c874586785165994a2d5b2eaa97b8218f99124d9991ff23547a7577a8f893ff1fae225d481030b079a58a51b86a9f4263b7c737982113d3df749c3d792dfa274850ffa52414e11f13e91e026d3cb5e32b1d5eb6c98a5432759ad1e8af2246b6c7699d76b4d6b44be2261d4f0175a0a6e1bdfc250dc3311642678de5e86bd4374bddcf1a550dc633cf9fc207cd435d65930389d57c6f802081b6823f13776a657ffcf9d822f5a04a9b275d13c5942e163169da24dba9ae882845c5f745346709c6052";
const SIG_PSS_512: &str = "afd6885c79aa8155ca29983a0d6b8c5be4d508d9e175b721cecfa4216b8f182896683c94965c7328b47d617f427f00dbf077266224298dc383206e30fa92ce7d285c0354aa4dab3d4ab02f8877f4c5f686216edc2e1c2f9477771e7cc5eb3ee6414e4823a01ba245f3d93e90f8d1fc9ec756459ae9cccd402dd9471564e00ca837fc51eb49f00b86decd648a77aaffc352fb2b3995837ca1e193674355cda45c357a30a88386c1177b8ce8feb9421be02d722af569cfddcf929a4175d5ba842bbb75bcec4b24a0cc58ace6aa4c0c708abe1afbec1f164ae7a2dc1bf499949cde706824437ecf7f536f39d159a8bd901a492cd1f64fbd43c872723c6414fb11b6ec91ce8dba4259f989db13af72f12fb2a1cadb7a4552d2017e0ed258b9e1bd5f8dfc598b72be3642e9042769a2514523dccc8b95cdf2f7035f4c60787fd0a6e64a5e9531f4e24882acc871cf4e31bd853e25eeabaf6f3d2ea4ef4f1f082e3de003bb68de6bbe0252868ddad74f47166e7e84dd6e93f463774558c3831051e4e0";

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
    assert_eq!(k.modulus_len(), 384);
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
    assert_eq!(
        k.verify_pkcs1v15(RsaHash::Sha256, MSG, &sig[1..]),
        Err(Error::Verification)
    );
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
    assert_eq!(
        k.verify_pkcs1v15(RsaHash::Sha256, MSG, &hx(N_HEX)),
        Err(Error::Verification)
    );
}

#[test]
fn key_validation_3072() {
    let n = hx(N_HEX);
    let mut even = n.clone();
    *even.last_mut().unwrap() &= 0xfe;
    assert!(PublicKey::from_components(&even, &[1, 0, 1]).is_err());
    assert!(PublicKey::from_components(&n, &[1, 0, 0]).is_err());
    assert!(PublicKey::from_components(&n, &[1]).is_err());
    assert!(PublicKey::from_components(&n, &[]).is_err());
    assert!(PublicKey::from_components(&n[..64], &[1, 0, 1]).is_err());
    let mut padded = vec![0u8, 0u8];
    padded.extend_from_slice(&n);
    assert!(PublicKey::from_components(&padded, &[0, 1, 0, 1]).is_ok());
}
