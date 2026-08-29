//! Property tests: streaming hashing must equal the one-shot free functions
//! for any chunking of the input, and the XOF stream must be split-invariant.

use proptest::prelude::*;

use tpt_crypto_hash::blake2b::{blake2b, Blake2b};
use tpt_crypto_hash::blake3::{blake3, Blake3};
use tpt_crypto_hash::sha2::{sha256, sha512, Sha256, Sha512};
use tpt_crypto_hash::sha3::{sha3_256, shake128, Sha3_256, Shake128};
use tpt_crypto_hash::{Hasher, Xof};

fn chunked(data: &[u8], sizes: &[usize]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut i = 0;
    let mut s = 0;
    while i < data.len() {
        let take = if sizes.is_empty() {
            data.len() - i
        } else {
            (sizes[s % sizes.len()] % 97 + 1).min(data.len() - i)
        };
        out.push(data[i..i + take].to_vec());
        i += take;
        s += 1;
    }
    out
}

proptest! {
    #[test]
    fn sha256_streaming(data in prop::collection::vec(any::<u8>(), 0..4096),
                        sizes in prop::collection::vec(1usize..96, 0..16)) {
        let mut h = Sha256::new();
        for c in chunked(&data, &sizes) { h.update(&c); }
        prop_assert_eq!(h.finalize(), sha256(&data));
    }

    #[test]
    fn sha512_streaming(data in prop::collection::vec(any::<u8>(), 0..4096),
                        sizes in prop::collection::vec(1usize..96, 0..16)) {
        let mut h = Sha512::new();
        for c in chunked(&data, &sizes) { h.update(&c); }
        prop_assert_eq!(h.finalize(), sha512(&data));
    }

    #[test]
    fn sha3_256_streaming(data in prop::collection::vec(any::<u8>(), 0..4096),
                          sizes in prop::collection::vec(1usize..96, 0..16)) {
        let mut h = Sha3_256::new();
        for c in chunked(&data, &sizes) { h.update(&c); }
        prop_assert_eq!(h.finalize(), sha3_256(&data));
    }

    #[test]
    fn blake2b_streaming(data in prop::collection::vec(any::<u8>(), 0..4096),
                         sizes in prop::collection::vec(1usize..96, 0..16)) {
        let mut h = Blake2b::<64>::new();
        for c in chunked(&data, &sizes) { h.update(&c); }
        prop_assert_eq!(h.finalize(), blake2b(&data));
    }

    #[test]
    fn blake3_streaming(data in prop::collection::vec(any::<u8>(), 0..8192),
                        sizes in prop::collection::vec(1usize..96, 0..32)) {
        let mut h = Blake3::new();
        for c in chunked(&data, &sizes) { h.update(&c); }
        let mut got = [0u8; 32];
        h.finalize_xof(&mut got);
        prop_assert_eq!(got, blake3(&data));
    }

    #[test]
    fn shake128_split(data in prop::collection::vec(any::<u8>(), 0..2048),
                      split in 0usize..128) {
        let total = 200usize;
        let mut whole = [0u8; 200];
        shake128(&data, &mut whole);

        let mut piece = [0u8; 200];
        let mut x = Shake128::new();
        x.update(&data);
        let s = split.min(total);
        x.squeeze(&mut piece[..s]);
        x.squeeze(&mut piece[s..]);
        prop_assert_eq!(piece, whole);
    }
}
