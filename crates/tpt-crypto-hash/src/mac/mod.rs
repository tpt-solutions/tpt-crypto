//! HMAC (RFC 2104), generic over any [`Hasher`] with a known block size.

use crate::traits::Hasher;

/// Constant-time equality of two byte slices (lengths are public metadata).
#[inline]
fn ct_eq_bytes(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    let n = a.len();
    let mut i = 0;
    while i < n {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    diff == 0
}

/// HMAC over hash `H` (`Hasher<OUT>`) with block size `BLOCK` bytes.
#[derive(Clone)]
pub struct Hmac<H: Hasher<OUT> + Default + Clone, const BLOCK: usize, const OUT: usize> {
    inner: H,
    outer: H,
    key_block: [u8; BLOCK],
}

impl<H: Hasher<OUT> + Default + Clone, const BLOCK: usize, const OUT: usize> Hmac<H, BLOCK, OUT> {
    /// Build an HMAC keyed with `key`.
    #[must_use]
    pub fn new(key: &[u8]) -> Self {
        let mut key_block = [0u8; BLOCK];
        if key.len() > BLOCK {
            let mut h = H::default();
            h.update(key);
            let d = h.finalize();
            key_block[..d.len()].copy_from_slice(&d);
        } else {
            key_block[..key.len()].copy_from_slice(key);
        }
        let mut ipad = [0u8; BLOCK];
        let mut opad = [0u8; BLOCK];
        for i in 0..BLOCK {
            ipad[i] = key_block[i] ^ 0x36;
            opad[i] = key_block[i] ^ 0x5c;
        }
        let mut inner = H::default();
        inner.update(&ipad);
        let mut outer = H::default();
        outer.update(&opad);
        Hmac {
            inner,
            outer,
            key_block,
        }
    }

    /// Constant-time verification of a candidate tag.
    #[inline]
    pub fn verify(&self, tag: &[u8]) -> bool {
        let mac = self.clone().finalize_reset();
        ct_eq_bytes(&mac, tag)
    }

    fn rebuild(&mut self) {
        let mut ipad = [0u8; BLOCK];
        let mut opad = [0u8; BLOCK];
        for i in 0..BLOCK {
            ipad[i] = self.key_block[i] ^ 0x36;
            opad[i] = self.key_block[i] ^ 0x5c;
        }
        let mut inner = H::default();
        inner.update(&ipad);
        let mut outer = H::default();
        outer.update(&opad);
        self.inner = inner;
        self.outer = outer;
    }
}

impl<H: Hasher<OUT> + Default + Clone, const BLOCK: usize, const OUT: usize> Hasher<OUT>
    for Hmac<H, BLOCK, OUT>
{
    const OUTPUT_SIZE: usize = OUT;

    #[inline]
    fn update(&mut self, data: &[u8]) {
        self.inner.update(data);
    }

    fn finalize_reset(&mut self) -> [u8; OUT] {
        let inner_out = self.inner.finalize_reset();
        self.outer.update(&inner_out);
        self.outer.finalize_reset()
    }

    #[inline]
    fn finalize(self) -> [u8; OUT] {
        self.clone().finalize_reset()
    }

    fn reset(&mut self) {
        self.rebuild();
    }
}

/// One-shot HMAC-SHA-256.
#[inline]
#[must_use]
pub fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut h = Hmac::<crate::sha2::Sha256, 64, 32>::new(key);
    h.update(msg);
    h.finalize()
}

/// One-shot HMAC-SHA-512.
#[inline]
#[must_use]
pub fn hmac_sha512(key: &[u8], msg: &[u8]) -> [u8; 64] {
    let mut h = Hmac::<crate::sha2::Sha512, 128, 64>::new(key);
    h.update(msg);
    h.finalize()
}
