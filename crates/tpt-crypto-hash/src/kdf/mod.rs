//! HKDF (RFC 5869): extract + expand, generic over any [`Hasher`] with a
//! known block size.

use crate::mac::Hmac;
use crate::traits::Hasher;

/// HKDF-Extract: PRK = HMAC-Hash(salt, IKM), written into `prk`. `salt` may be empty.
#[inline]
pub fn hkdf_extract<H: Hasher<OUT> + Default + Clone, const BLOCK: usize, const OUT: usize>(
    salt: &[u8],
    ikm: &[u8],
    prk: &mut [u8],
) {
    let mut h = Hmac::<H, BLOCK, OUT>::new(salt);
    h.update(ikm);
    let d = h.finalize();
    prk[..d.len()].copy_from_slice(&d);
}

/// HKDF-Expand: OKM = output of `okm.len()` bytes from `prk` and `info`.
///
/// # Panics
///
/// Panics if `okm.len() > 255 * OUT` (RFC 5869 §2.3): the block counter is a
/// single octet and cannot address further blocks.
pub fn hkdf_expand<H: Hasher<OUT> + Default + Clone, const BLOCK: usize, const OUT: usize>(
    prk: &[u8],
    info: &[u8],
    okm: &mut [u8],
) {
    assert!(
        okm.len() <= 255 * OUT,
        "HKDF-Expand output exceeds 255 * HashLen"
    );
    let mut prev = [0u8; OUT];
    let mut prev_len = 0usize;
    let mut written = 0;
    let mut counter = 1u8;
    while written < okm.len() {
        let mut h = Hmac::<H, BLOCK, OUT>::new(prk);
        h.update(&prev[..prev_len]);
        h.update(info);
        h.update(&[counter]);
        let blk = h.finalize();
        let need = (okm.len() - written).min(OUT);
        okm[written..written + need].copy_from_slice(&blk[..need]);
        prev.copy_from_slice(&blk);
        prev_len = OUT;
        written += need;
        // After the 255th block the loop exits; wrapping keeps that last step from
        // overflowing (the length assert above guarantees no block 0 is ever used).
        counter = counter.wrapping_add(1);
    }
}

/// One-shot HKDF-SHA-256: extract then expand into `okm`.
#[inline]
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) {
    let mut prk = [0u8; 32];
    hkdf_extract::<crate::sha2::Sha256, 64, 32>(salt, ikm, &mut prk);
    hkdf_expand::<crate::sha2::Sha256, 64, 32>(&prk, info, okm);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha2::Sha256;

    #[test]
    fn hkdf_expand_accepts_maximum_length() {
        let prk = [0x0bu8; 32];
        let mut okm = alloc::vec![0u8; 255 * 32];
        hkdf_expand::<Sha256, 64, 32>(&prk, b"info", &mut okm);
        // The last block must be produced (counter 255), not left zeroed.
        assert!(okm[255 * 32 - 32..].iter().any(|&b| b != 0));
    }

    #[test]
    #[should_panic(expected = "exceeds 255 * HashLen")]
    fn hkdf_expand_rejects_over_maximum_length() {
        let prk = [0x0bu8; 32];
        let mut okm = alloc::vec![0u8; 255 * 32 + 1];
        hkdf_expand::<Sha256, 64, 32>(&prk, b"info", &mut okm);
    }
}
