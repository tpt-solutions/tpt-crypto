//! STREAM-style chunked AEAD for large payloads (age-style construction).
//!
//! Plaintext is split into fixed-size chunks, each sealed with ChaCha20-Poly1305
//! under a nonce built from a 12-byte field: an 11-byte big-endian chunk counter
//! followed by a 1-byte last-chunk flag (`0x01` on the final chunk, else `0x00`).
//!
//! * **Reorder / duplication** is caught because each chunk's counter is bound
//!   into its nonce.
//! * **Truncation** (dropping trailing chunks) is caught because the final chunk
//!   is sealed with the last flag set, and only it can be opened that way.
//! * **Extension** is caught because a non-final chunk never opens as final.
//!
//! The caller's `aad` is authenticated with every chunk. An empty plaintext is a
//! single empty final chunk, so every message has at least one chunk.
//!
//! This is a whole-buffer API: [`seal`] and [`open`] take and return `Vec<u8>`.
//! Ciphertext layout is `chunk_0 ‖ chunk_1 ‖ … ‖ chunk_last`, each chunk being
//! `plaintext_chunk.len() + 16` bytes; all chunks but the last are exactly
//! `chunk_size + 16` bytes.

use crate::api::{Aead, Nonce, Tag};
use crate::chacha::ChaCha20Poly1305;
use alloc::vec::Vec;
use tpt_crypto_core::{Error, Result};

/// Authentication tag length per chunk.
pub const TAG_LEN: usize = 16;
/// Default plaintext chunk size (64 KiB, as in age).
pub const DEFAULT_CHUNK_SIZE: usize = 64 * 1024;

const NONCE_LAST: u8 = 0x01;
const NONCE_MID: u8 = 0x00;

fn chunk_nonce(index: u64, last: bool) -> Nonce<12> {
    let mut n = [0u8; 12];
    n[3..11].copy_from_slice(&index.to_be_bytes());
    n[11] = if last { NONCE_LAST } else { NONCE_MID };
    Nonce::new(n)
}

fn check_chunk_size(chunk_size: usize) -> Result<()> {
    if chunk_size == 0 || chunk_size > u32::MAX as usize {
        return Err(Error::InvalidLength);
    }
    Ok(())
}

/// Seal `plaintext` in chunks of `chunk_size` bytes, binding `aad` to every chunk.
///
/// Returns [`Error::InvalidLength`] if `chunk_size` is zero or exceeds `u32::MAX`.
pub fn seal(key: &[u8; 32], plaintext: &[u8], aad: &[u8], chunk_size: usize) -> Result<Vec<u8>> {
    check_chunk_size(chunk_size)?;
    let cipher = ChaCha20Poly1305::new(key);

    // An empty message is one empty final chunk; otherwise the final chunk is the
    // last (possibly full-size) slice of the plaintext.
    let pieces: Vec<&[u8]> = if plaintext.is_empty() {
        alloc::vec![&[][..]]
    } else {
        plaintext.chunks(chunk_size).collect()
    };
    let count = pieces.len();

    let mut out = Vec::with_capacity(plaintext.len() + count * TAG_LEN);
    for (i, piece) in pieces.into_iter().enumerate() {
        let last = i + 1 == count;
        let mut buf = piece.to_vec();
        let tag = cipher.encrypt_in_place_detached(&chunk_nonce(i as u64, last), aad, &mut buf);
        out.extend_from_slice(&buf);
        out.extend_from_slice(&tag.0);
    }
    Ok(out)
}

/// Open a message produced by [`seal`] with the same `key`, `aad` and `chunk_size`.
///
/// No plaintext is returned unless every chunk authenticates, including the
/// final-chunk flag. Returns [`Error::Verification`] on any mismatch and
/// [`Error::InvalidLength`] when the input is too short to hold a chunk.
pub fn open(key: &[u8; 32], sealed: &[u8], aad: &[u8], chunk_size: usize) -> Result<Vec<u8>> {
    check_chunk_size(chunk_size)?;
    if sealed.len() < TAG_LEN {
        return Err(Error::InvalidLength);
    }
    let cipher = ChaCha20Poly1305::new(key);
    let full = chunk_size + TAG_LEN;

    let mut out = Vec::with_capacity(sealed.len());
    let mut rest = sealed;
    let mut index: u64 = 0;
    loop {
        // A chunk is final when no more than one full chunk remains; anything
        // longer must be a non-final chunk.
        let last = rest.len() <= full;
        let take = if last { rest.len() } else { full };
        if take < TAG_LEN {
            return Err(Error::InvalidLength);
        }
        let (chunk, tail) = rest.split_at(take);
        let (ct, tag_bytes) = chunk.split_at(take - TAG_LEN);
        let mut tag = [0u8; TAG_LEN];
        tag.copy_from_slice(tag_bytes);

        let mut buf = ct.to_vec();
        cipher.decrypt_in_place_detached(
            &chunk_nonce(index, last),
            aad,
            &mut buf,
            &Tag::new(tag),
        )?;
        out.extend_from_slice(&buf);

        if last {
            return Ok(out);
        }
        rest = tail;
        index += 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const KEY: [u8; 32] = [0x24; 32];

    #[test]
    fn round_trip_across_chunk_boundaries() {
        for len in [0usize, 1, 15, 16, 17, 99, 100, 101, 250, 1000] {
            let msg: Vec<u8> = (0..len).map(|i| i as u8).collect();
            for chunk in [1usize, 16, 100] {
                let sealed = seal(&KEY, &msg, b"aad", chunk).unwrap();
                let chunks = if len == 0 { 1 } else { len.div_ceil(chunk) };
                assert_eq!(
                    sealed.len(),
                    len + chunks * TAG_LEN,
                    "len {len} chunk {chunk}"
                );
                assert_eq!(open(&KEY, &sealed, b"aad", chunk).unwrap(), msg);
            }
        }
    }

    #[test]
    fn exact_multiple_has_no_trailing_empty_chunk() {
        // 200 bytes at chunk 100 is two chunks, the second being final.
        let msg = [9u8; 200];
        let sealed = seal(&KEY, &msg, b"", 100).unwrap();
        assert_eq!(sealed.len(), 200 + 2 * TAG_LEN);
        assert_eq!(open(&KEY, &sealed, b"", 100).unwrap(), msg);
    }

    #[test]
    fn truncation_at_chunk_boundary_is_rejected() {
        let msg = [1u8; 300];
        let sealed = seal(&KEY, &msg, b"", 100).unwrap();
        let chunk_len = 100 + TAG_LEN;
        // Drop the final chunk: the old middle chunk must not open as final.
        assert!(open(&KEY, &sealed[..2 * chunk_len], b"", 100).is_err());
        // Keep only the first chunk: also rejected.
        assert!(open(&KEY, &sealed[..chunk_len], b"", 100).is_err());
    }

    #[test]
    fn reordering_chunks_is_rejected() {
        let msg = [2u8; 300];
        let sealed = seal(&KEY, &msg, b"", 100).unwrap();
        let c = 100 + TAG_LEN;
        let mut swapped = Vec::new();
        swapped.extend_from_slice(&sealed[c..2 * c]);
        swapped.extend_from_slice(&sealed[..c]);
        swapped.extend_from_slice(&sealed[2 * c..]);
        assert!(open(&KEY, &swapped, b"", 100).is_err());
    }

    #[test]
    fn wrong_aad_key_or_chunk_size_is_rejected() {
        let sealed = seal(&KEY, b"hello stream", b"ctx", 4).unwrap();
        assert!(open(&KEY, &sealed, b"other", 4).is_err());
        assert!(open(&[0u8; 32], &sealed, b"ctx", 4).is_err());
        assert!(open(&KEY, &sealed, b"ctx", 5).is_err());
    }

    #[test]
    fn bit_flips_are_rejected() {
        let sealed = seal(&KEY, b"0123456789", b"", 4).unwrap();
        for byte in 0..sealed.len() {
            let mut bad = sealed.clone();
            bad[byte] ^= 0x80;
            assert!(open(&KEY, &bad, b"", 4).is_err(), "byte {byte}");
        }
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
            .collect()
    }

    /// Reference vector generated independently with Python `cryptography`
    /// (ChaCha20-Poly1305 per chunk, nonce = 3 zero bytes ‖ BE counter ‖ last flag).
    /// Key = 0x00..0x1f, aad = "stream-aad", chunk = 100, plaintext = i mod 256 for 250 bytes.
    #[test]
    fn matches_independent_reference_vector() {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = i as u8;
        }
        let msg: Vec<u8> = (0..250).map(|i| (i % 256) as u8).collect();
        let expected = unhex(
            "18b94032a9e3a0d61b68566aa34e4028e8a0e1e6f5b84d4bf4e1e60936286b4352292a4ef5cb1a7ab5a8720f48232e13ab91c46dea686ff9351370440da864f202b36f9fe30fd49224eec0a465c33c7430722d6513bfe8e0abb9c66b92ddbdbde4c96078390248b62e09c23a28f34d88b76736b6df02a744c64442d8684002a9de4e085c5d83dab481c136e6357a846e6a4d29be76b79f9efeede0a8f1f2ae6756bc568d89f1f40b3bc473089f209a61f520cdb35c41059d858223817bca3a988d2660f3eb2609c974415300a7f61f8b2910299106898749f8b60a190df61840c954e1bdbb44747e8cb1701d5317f65357fef9dd64d3ba10d3f2ec35151f70a60a56eaadcd6e54a6156cb0e1e54358ed7f4a288cef6f9b2724ece1998ac40ac66ad4708b20ad856a9305",
        );
        assert_eq!(expected.len(), 250 + 3 * TAG_LEN);
        assert_eq!(seal(&key, &msg, b"stream-aad", 100).unwrap(), expected);
        assert_eq!(open(&key, &expected, b"stream-aad", 100).unwrap(), msg);
    }

    #[test]
    fn invalid_chunk_sizes_and_short_input() {
        assert_eq!(seal(&KEY, b"x", b"", 0).unwrap_err(), Error::InvalidLength);
        assert_eq!(
            open(&KEY, &[0u8; 15], b"", 16).unwrap_err(),
            Error::InvalidLength
        );
    }
}
