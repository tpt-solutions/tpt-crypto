//! ML-KEM (FIPS 203): the CCA-secure key encapsulation mechanism.
//!
//! This is the Fujisaki–Okamoto transform over [`crate::pke`]:
//!
//! * [`keygen`] derives `(ek, dk)` from a seed and a nonce `z`.
//! * [`encapsulate`] hashes a random message `m` with `H(ek)` to get the shared
//!   secret `K` and the encryption seed `r`, then returns `(K, c)`.
//! * [`decapsulate`] uses implicit rejection: it recomputes the ciphertext from
//!   the decrypted message and, in constant time, returns `K` on a match and
//!   `H(z ‖ c)` otherwise. There is no panic and no secret-dependent branch.
//!
//! Serialized keys/ciphertexts are stored in `alloc::Vec<u8>` (the ML-KEM payloads
//! are too large to keep in fixed arrays under `no_std`); the `alloc` feature is
//! required for this module.

use alloc::vec;
use alloc::vec::Vec;

use crate::params::MlKemParams;
use crate::pke;
use tpt_crypto_core::{CryptoRng, Error};
use tpt_crypto_ct::ct_eq_bytes;
use tpt_crypto_ct::select::ct_select_array;
use tpt_crypto_hash::sha3::{Sha3_256, Sha3_512, Shake256};
use tpt_crypto_hash::{Hasher, Xof};

// Re-expose the parameter-set markers for `ml_kem::MlKem768` style usage.
pub use crate::params::{MlKem512, MlKem768, MlKem1024};

/// The shared secret length (always 32 bytes in ML-KEM).
pub type SharedSecret = [u8; 32];

/// An ML-KEM public key (`ek`).
#[derive(Clone)]
pub struct EncapsKey {
    /// Encoded public key bytes.
    pub bytes: Vec<u8>,
}

/// An ML-KEM secret key (`dk = ek ‖ d ‖ H(ek) ‖ z`).
#[derive(Clone)]
pub struct DecapsKey {
    /// Encoded secret key bytes.
    pub bytes: Vec<u8>,
}

/// An ML-KEM ciphertext (`c = c1 ‖ c2`).
#[derive(Clone)]
pub struct Ciphertext {
    /// Encoded ciphertext bytes.
    pub bytes: Vec<u8>,
}

impl EncapsKey {
    /// Borrow the encoded public key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Parse a public key of parameter set `P` from bytes (constant-time length check).
    pub fn from_bytes<P: MlKemParams>(b: &[u8]) -> Result<Self, Error> {
        if b.len() != P::PK_LEN {
            return Err(Error::InvalidLength);
        }
        Ok(EncapsKey {
            bytes: b.to_vec(),
        })
    }
}

impl DecapsKey {
    /// Borrow the encoded secret key.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Parse a secret key of parameter set `P` from bytes (constant-time length check).
    pub fn from_bytes<P: MlKemParams>(b: &[u8]) -> Result<Self, Error> {
        if b.len() != P::SK_LEN {
            return Err(Error::InvalidLength);
        }
        Ok(DecapsKey {
            bytes: b.to_vec(),
        })
    }
}

impl Ciphertext {
    /// Borrow the encoded ciphertext.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
    /// Parse a ciphertext of parameter set `P` from bytes (constant-time length check).
    pub fn from_bytes<P: MlKemParams>(b: &[u8]) -> Result<Self, Error> {
        if b.len() != P::CT_LEN {
            return Err(Error::InvalidLength);
        }
        Ok(Ciphertext {
            bytes: b.to_vec(),
        })
    }
}

// --- SHAKE256 helpers (streaming, no large temp buffers) ---------------------

/// `G(a ‖ b) = SHA3-512(a ‖ b)` (FIPS 203 §4.1).
fn g_parts(a: &[u8], b: &[u8]) -> [u8; 64] {
    let mut x = Sha3_512::new();
    x.update(a);
    x.update(b);
    x.finalize()
}

/// `H(a ‖ b) = SHA3-256(a ‖ b)` (FIPS 203 §4.1).
fn h_parts(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut x = Sha3_256::new();
    x.update(a);
    x.update(b);
    x.finalize()
}

/// `J(a ‖ b) = SHAKE256(a ‖ b, 32)` — the implicit-rejection PRF (FIPS 203 §4.1).
fn j_parts(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut x = Shake256::new();
    x.update(a);
    x.update(b);
    let mut out = [0u8; 32];
    x.squeeze(&mut out);
    out
}

/// Generate an ML-KEM keypair. `rng` supplies the seed `d` and nonce `z`.
pub fn keygen<P: MlKemParams>(rng: &mut impl CryptoRng) -> (EncapsKey, DecapsKey) {
    let d = rng.gen_array::<32>();
    let z = rng.gen_array::<32>();
    let pk = pke::kpke_keygen::<P>(&d);
    let h = h_parts(&pk, &[]);

    let mut sk = vec![0u8; P::SK_LEN];
    let mut off = 0usize;
    sk[off..off + P::PK_LEN].copy_from_slice(&pk);
    off += P::PK_LEN;
    sk[off..off + 32].copy_from_slice(&d);
    off += 32;
    sk[off..off + 32].copy_from_slice(&h);
    off += 32;
    sk[off..off + 32].copy_from_slice(&z);

    (EncapsKey { bytes: pk }, DecapsKey { bytes: sk })
}

/// Deterministic key generation from explicit seeds.
///
/// `d` seeds the matrix (via `H(d)`), and `z` is the implicit-rejection nonce.
/// Provided for reproducible tests and KAT validation; equivalent to
/// [`keygen`] when `(d, z)` is drawn from an RNG.
pub fn keygen_seed<P: MlKemParams>(d: &[u8; 32], z: &[u8; 32]) -> (EncapsKey, DecapsKey) {
    let pk = pke::kpke_keygen::<P>(d);
    let h = h_parts(&pk, &[]);

    let mut sk = vec![0u8; P::SK_LEN];
    let mut off = 0usize;
    sk[off..off + P::PK_LEN].copy_from_slice(&pk);
    off += P::PK_LEN;
    sk[off..off + 32].copy_from_slice(d);
    off += 32;
    sk[off..off + 32].copy_from_slice(&h);
    off += 32;
    sk[off..off + 32].copy_from_slice(z);

    (EncapsKey { bytes: pk }, DecapsKey { bytes: sk })
}

/// Encapsulate to `pk` with an explicit 32-byte message `m`, returning the shared
/// secret and ciphertext. Equivalent to [`encapsulate`] when `m` is chosen at
/// random; provided for reproducible tests and KAT validation.
pub fn encapsulate_msg<P: MlKemParams>(
    pk: &EncapsKey,
    m: &[u8; 32],
) -> (SharedSecret, Ciphertext) {
    let h_pk = h_parts(&pk.bytes, &[]);
    let g = g_parts(m, &h_pk);
    let mut k = [0u8; 32];
    k.copy_from_slice(&g[..32]);
    let mut r_seed = [0u8; 32];
    r_seed.copy_from_slice(&g[32..]);

    let (rho, t_hat) = pke::decode_pk::<P>(&pk.bytes).expect("own public key is well-formed");
    let ct = pke::kpke_encrypt::<P>(&rho, &t_hat, m, &r_seed);
    (k, Ciphertext { bytes: ct })
}

/// Encapsulate to `pk`, returning the shared secret and ciphertext. `rng`
/// supplies the random message `m`.
pub fn encapsulate<P: MlKemParams>(pk: &EncapsKey, rng: &mut impl CryptoRng) -> (SharedSecret, Ciphertext) {
    let m = rng.gen_array::<32>();
    let h_pk = h_parts(&pk.bytes, &[]);
    let g = g_parts(&m, &h_pk);
    let mut k = [0u8; 32];
    k.copy_from_slice(&g[..32]);
    let mut r_seed = [0u8; 32];
    r_seed.copy_from_slice(&g[32..]);

    let (rho, t_hat) = pke::decode_pk::<P>(&pk.bytes).expect("own public key is well-formed");
    let ct = pke::kpke_encrypt::<P>(&rho, &t_hat, &m, &r_seed);
    (k, Ciphertext { bytes: ct })
}

/// Decapsulate `ct` under `sk`.
///
/// Uses implicit rejection: on a valid ciphertext the real shared secret is
/// returned; on any mismatch the result is `H(z ‖ c)` computed in constant time
/// with respect to the secret key. A ciphertext of the wrong length is rejected
/// with [`Error::InvalidCiphertext`] (a public-input check, not a secret oracle).
pub fn decapsulate<P: MlKemParams>(sk: &DecapsKey, ct: &[u8]) -> Result<SharedSecret, Error> {
    if ct.len() != P::CT_LEN {
        return Err(Error::InvalidCiphertext);
    }
    let (pk, d_slice, h, z) = split_sk::<P>(sk);
    let d: [u8; 32] = d_slice.try_into().map_err(|_| Error::InvalidLength)?;
    let s_hat = pke::derive_s_hat::<P>(&d);

    let (rho, t_hat) = pke::decode_pk::<P>(pk)?;
    let m_prime = pke::kpke_decrypt::<P>(&s_hat, ct)?;

    let g = g_parts(&m_prime, h);
    let mut k_prime = [0u8; 32];
    k_prime.copy_from_slice(&g[..32]);
    let mut r_prime = [0u8; 32];
    r_prime.copy_from_slice(&g[32..]);

    let ct_prime = pke::kpke_encrypt::<P>(&rho, &t_hat, &m_prime, &r_prime);

    // Constant-time comparison of the recomputed ciphertext with the input.
    let eq = ct_eq_bytes(&ct_prime, ct);
    let reject = j_parts(z, ct);

    Ok(ct_select_array(eq, k_prime, reject))
}

/// Split a secret key into its four components (constant-time slicing).
fn split_sk<P: MlKemParams>(sk: &DecapsKey) -> (&[u8], &[u8], &[u8], &[u8]) {
    let b = &sk.bytes;
    let p = P::PK_LEN;
    let pk = &b[..p];
    let d_slice = &b[p..p + 32];
    let h = &b[p + 32..p + 64];
    let z = &b[p + 64..p + 96];
    (pk, d_slice, h, z)
}
