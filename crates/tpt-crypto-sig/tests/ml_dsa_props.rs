//! Property tests for ML-DSA (FIPS 204).
//!
//! Rand-based (deterministic `TestRng`) rather than `proptest`, matching the
//! rest of the workspace. Covers, over many random keys / messages / contexts:
//!
//! * `verify(pk, m, ctx, sign(sk, m, ctx))` succeeds.
//! * a wrong message, wrong context, or wrong key yields `Error::Verification`.
//! * `sign_hedged` signatures also verify.
//! * any single-bit mutation of the signature is rejected.

use tpt_crypto_core::CryptoRng;
use tpt_crypto_sig::ml_dsa::{
    keygen, sign, sign_hedged, verify, MlDsa44, MlDsa65, MlDsa87, MlDsaParams,
};
use tpt_crypto_sig::test_rng::TestRng;
use tpt_crypto_sig::Error;

fn rng(tag: u8) -> TestRng {
    let mut seed = [0u8; 32];
    seed[0] = tag;
    seed[1] = 0xA5;
    TestRng::from_seed(&seed)
}

fn roundtrip_and_negatives<P: MlDsaParams>(iters: usize)
where
    P::Mat: tpt_crypto_sig::bytes::PolyArray,
    P::VecL: tpt_crypto_sig::bytes::PolyArray,
    P::VecK: tpt_crypto_sig::bytes::PolyArray,
{
    let mut r = rng(P::K as u8);
    for i in 0..iters {
        let (pk, sk) = keygen::<P, _>(&mut r);
        let mut msg = [0u8; 24];
        r.try_fill_bytes(&mut msg).unwrap();
        let ctx_len = i % 4;
        let mut ctx = [0u8; 4];
        r.try_fill_bytes(&mut ctx).unwrap();
        let ctx = &ctx[..ctx_len];

        let sig = sign::<P>(&sk, &msg, ctx).expect("sign");
        assert!(
            verify::<P>(&pk, &msg, &sig, ctx).is_ok(),
            "honest verify failed"
        );

        // Wrong message.
        let mut bad_msg = msg;
        bad_msg[0] ^= 1;
        assert!(matches!(
            verify::<P>(&pk, &bad_msg, &sig, ctx),
            Err(Error::Verification)
        ));

        // Wrong context.
        let mut bad_ctx = [0u8; 5];
        bad_ctx[..ctx_len].copy_from_slice(ctx);
        bad_ctx[ctx_len] = 0xFF;
        assert!(matches!(
            verify::<P>(&pk, &msg, &sig, &bad_ctx),
            Err(Error::Verification)
        ));

        // Wrong key.
        let (pk2, _) = keygen::<P, _>(&mut r);
        assert!(matches!(
            verify::<P>(&pk2, &msg, &sig, ctx),
            Err(Error::Verification)
        ));

        // Hedged signature also verifies.
        let mut rnd = [0u8; 32];
        r.try_fill_bytes(&mut rnd).unwrap();
        let hsig = sign_hedged::<P>(&sk, &msg, ctx, &rnd).expect("sign_hedged");
        assert!(
            verify::<P>(&pk, &msg, &hsig, ctx).is_ok(),
            "hedged verify failed"
        );
    }
}

fn signature_bitflip_rejected<P: MlDsaParams>()
where
    P::Mat: tpt_crypto_sig::bytes::PolyArray,
    P::VecL: tpt_crypto_sig::bytes::PolyArray,
    P::VecK: tpt_crypto_sig::bytes::PolyArray,
{
    let mut r = rng(100 + P::K as u8);
    let (pk, sk) = keygen::<P, _>(&mut r);
    let msg = b"bit-flip resistance";
    let sig = sign::<P>(&sk, msg, &[]).expect("sign");

    // Sample a spread of bit positions (exhaustive is too slow for the big sets).
    let len = sig.as_bytes().len();
    for &byte in &[0usize, 1, 7, 31, 32, 33, len / 3, len / 2, len - 2, len - 1] {
        for bit in 0..8 {
            let mut bytes = sig.as_bytes().to_vec();
            bytes[byte] ^= 1 << bit;
            // A `None` here just means the mutation broke the length — also fine.
            if let Some(mutated) = tpt_crypto_sig::ml_dsa::Signature::<P>::from_bytes(&bytes) {
                assert!(
                    verify::<P>(&pk, msg, &mutated, &[]).is_err(),
                    "mutated signature verified (byte {byte}, bit {bit})"
                );
            }
        }
    }
}

#[test]
fn ml_dsa_44_props() {
    roundtrip_and_negatives::<MlDsa44>(8);
    signature_bitflip_rejected::<MlDsa44>();
}

#[test]
fn ml_dsa_65_props() {
    roundtrip_and_negatives::<MlDsa65>(5);
    signature_bitflip_rejected::<MlDsa65>();
}

#[test]
fn ml_dsa_87_props() {
    roundtrip_and_negatives::<MlDsa87>(4);
    signature_bitflip_rejected::<MlDsa87>();
}
