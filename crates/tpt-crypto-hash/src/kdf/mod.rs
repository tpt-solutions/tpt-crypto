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
pub fn hkdf_expand<H: Hasher<OUT> + Default + Clone, const BLOCK: usize, const OUT: usize>(
    prk: &[u8],
    info: &[u8],
    okm: &mut [u8],
) {
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
        counter += 1;
    }
}

/// One-shot HKDF-SHA-256: extract then expand into `okm`.
#[inline]
pub fn hkdf_sha256(salt: &[u8], ikm: &[u8], info: &[u8], okm: &mut [u8]) {
    let mut prk = [0u8; 32];
    hkdf_extract::<crate::sha2::Sha256, 64, 32>(salt, ikm, &mut prk);
    hkdf_expand::<crate::sha2::Sha256, 64, 32>(&prk, info, okm);
}
