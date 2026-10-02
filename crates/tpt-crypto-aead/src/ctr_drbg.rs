//! `CtrDrbg` — NIST SP 800-90A deterministic random bit generator based on
//! AES-256 in counter mode, without the optional derivation function.
//!
//! The construction follows SP 800-90A §10.2.1 (no-DF): instantiation and
//! reseed XOR the (zero-padded) seed material into a 48-byte block and feed
//! it through [`CtrDrbg::update`]; [`DrbgCore::generate`] produces keystream
//! by incrementing `V` (§10.2.1.5.1 increments *before* encrypting) and then
//! runs the mandatory post-generation update for backtracking resistance.
//! All operations are constant-time and the secret key is zeroized on drop.

use crate::aes::Aes;
use tpt_crypto_core::{DrbgCore, Result, Zeroizing};

const SEED_LEN: usize = 48; // AES-256 key (32) + counter (16)

/// AES-256 CTR-DRBG (no derivation function).
pub struct CtrDrbg {
    key: Zeroizing<[u8; 32]>,
    v: [u8; 16],
}

impl CtrDrbg {
    /// Instantiate from `seedlen`-bytes of entropy and optional personalization.
    ///
    /// Both inputs are zero-extended/truncated to `seedlen` (48) bytes and XORed
    /// together to form the initial seed material.
    pub fn new(entropy: &[u8], personalization: &[u8]) -> Self {
        let mut seed = [0u8; SEED_LEN];
        xor_into(&mut seed, entropy);
        xor_into(&mut seed, personalization);

        let mut drbg = CtrDrbg {
            key: Zeroizing::new([0u8; 32]),
            v: [0u8; 16],
        };
        drbg.update(&seed);
        drbg
    }

    /// One AES-256-CTR keystream block.
    ///
    /// SP 800-90A §10.2.1.2 / §10.2.1.5.1 increment `V` (rightmost 32 bits,
    /// big-endian) *before* encrypting, so the first keystream block is
    /// `E(K, V+1)`, not `E(K, V)`.
    #[inline]
    fn block(&mut self) -> [u8; 16] {
        inc32(&mut self.v);
        let cipher = Aes::new_256(&self.key[..]);
        cipher.encrypt_block(&self.v)
    }

    /// SP 800-90A `Update`: mix `provided_data` (seedlen bytes) into key and V.
    fn update(&mut self, provided_data: &[u8]) {
        let mut temp = [0u8; SEED_LEN];
        // Generate seedlen bytes of keystream (3 blocks).
        for chunk in temp.chunks_mut(16) {
            let b = self.block();
            chunk.copy_from_slice(&b);
        }
        let mut new_key = [0u8; 32];
        for i in 0..32 {
            new_key[i] = self.key[i] ^ temp[i] ^ provided_data.get(i).copied().unwrap_or(0);
        }
        for i in 0..16 {
            self.v[i] ^= temp[32 + i] ^ provided_data.get(32 + i).copied().unwrap_or(0);
        }
        self.key = Zeroizing::new(new_key);
    }
}

/// XOR `src` (truncated/zero-extended to `dst.len()`) into `dst`.
fn xor_into(dst: &mut [u8], src: &[u8]) {
    for i in 0..dst.len() {
        if i < src.len() {
            dst[i] ^= src[i];
        }
    }
}

#[inline]
fn inc32(block: &mut [u8; 16]) {
    let mut v = u32::from_be_bytes([block[12], block[13], block[14], block[15]]);
    v = v.wrapping_add(1);
    block[12..16].copy_from_slice(&v.to_be_bytes());
}

impl DrbgCore for CtrDrbg {
    fn reseed(&mut self, entropy_input: &[u8], additional_input: &[u8]) {
        let mut seed = [0u8; SEED_LEN];
        xor_into(&mut seed, entropy_input);
        xor_into(&mut seed, additional_input);
        self.update(&seed);
    }

    fn generate(&mut self, out: &mut [u8], additional_input: &[u8]) -> Result<()> {
        if !additional_input.is_empty() {
            self.update(additional_input);
        }
        let mut generated = 0;
        while generated < out.len() {
            let block = self.block();
            let take = (out.len() - generated).min(16);
            out[generated..generated + take].copy_from_slice(&block[..take]);
            generated += take;
        }
        self.update(&[]);
        Ok(())
    }
}

impl Drop for CtrDrbg {
    fn drop(&mut self) {
        // `key` is already zeroized by `Zeroizing`; scrub the counter too.
        self.v = [0u8; 16];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answer_smoke() {
        // CTR-DRBG with a fixed seed should be deterministic.
        let mut a = CtrDrbg::new(&[0x42u8; 48], &[]);
        let mut b = CtrDrbg::new(&[0x42u8; 48], &[]);
        let mut oa = [0u8; 32];
        let mut ob = [0u8; 32];
        a.generate(&mut oa, &[]).unwrap();
        b.generate(&mut ob, &[]).unwrap();
        assert_eq!(oa, ob);
        assert_ne!(oa, [0u8; 32]);
    }

    #[test]
    fn different_entropy_different_output() {
        let mut a = CtrDrbg::new(&[0u8; 48], &[]);
        let mut b = CtrDrbg::new(&[0xffu8; 48], &[]);
        let mut oa = [0u8; 32];
        let mut ob = [0u8; 32];
        a.generate(&mut oa, &[]).unwrap();
        b.generate(&mut ob, &[]).unwrap();
        assert_ne!(oa, ob);
    }

    #[test]
    fn reseed_changes_output() {
        let mut d = CtrDrbg::new(&[1u8; 48], &[]);
        let mut first = [0u8; 16];
        d.generate(&mut first, &[]).unwrap();
        d.reseed(&[9u8; 48], &[]);
        let mut second = [0u8; 16];
        d.generate(&mut second, &[]).unwrap();
        assert_ne!(first, second);
    }
}
