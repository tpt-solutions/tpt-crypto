//! Hybrid KEM: X25519 + ML-KEM-768, combined in the style of X-Wing
//! (draft-connolly-cfrg-xwing-kem).
//!
//! The shared secret is secure if either component is: a break of ML-KEM alone
//! or of X25519 alone does not reveal it. The combiner hashes both component
//! secrets together with the X25519 ciphertext and public key, so the output is
//! bound to the full transcript.
//!
//! Layout (following the draft):
//!
//! * Secret key: a 32-byte seed. Expanded with SHAKE256 into the ML-KEM seeds
//!   `(d, z)` and the X25519 scalar.
//! * Public key: `pk_M ‖ pk_X` (1184 + 32 bytes).
//! * Ciphertext: `ct_M ‖ ct_X` (1088 + 32 bytes).
//! * Shared secret: `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ label)`, with
//!   `label = "\\.//^\\"`.
//!
//! Status: the construction follows the draft at the time of writing, which has
//! no published test vectors this crate can check against. The tests pin the
//! expansion and combiner against an independent Python computation, and check
//! round-trips, tampering and malformed-input handling. Treat the wire format as
//! unstable until the draft is final.
//!
//! Decapsulation regenerates the ML-KEM key from the seed each time, so it costs
//! about one key generation on top of the decapsulation.

use crate::ml_kem::{self, DecapsKey, EncapsKey};
use crate::params::{MlKem768, MlKemParams};
use tpt_crypto_core::{CryptoRng, Error, Result, SecretBox};
use tpt_crypto_curve::X25519;
use tpt_crypto_hash::sha3::{sha3_256, shake256};

/// Seed length (the X-Wing secret key).
pub const SEED_LEN: usize = 32;
/// Public-key length: ML-KEM-768 `ek` followed by the X25519 public key.
pub const PUBLIC_KEY_LEN: usize = MlKem768::PK_LEN + 32;
/// Ciphertext length: ML-KEM-768 `c` followed by the X25519 ephemeral key.
pub const CIPHERTEXT_LEN: usize = MlKem768::CT_LEN + 32;
/// Shared-secret length.
pub const SHARED_SECRET_LEN: usize = 32;

/// Domain-separation label for the combiner (`\.//^\`, six ASCII bytes).
pub const LABEL: [u8; 6] = [0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c];

/// An X-Wing public key.
#[derive(Clone, PartialEq, Eq)]
pub struct PublicKey(pub [u8; PUBLIC_KEY_LEN]);

/// An X-Wing secret key (a 32-byte seed), zeroed on drop.
pub struct SecretKey(SecretBox<[u8; SEED_LEN]>);

impl SecretKey {
    /// Wrap a seed.
    pub fn from_seed(seed: [u8; SEED_LEN]) -> Self {
        SecretKey(SecretBox::new(seed))
    }

    /// The seed bytes.
    pub fn seed(&self) -> &[u8; SEED_LEN] {
        self.0.expose_secret()
    }
}

/// Expand the seed into `(d, z, sk_X)` with SHAKE256 (96 bytes).
fn expand(seed: &[u8; SEED_LEN]) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let mut out = [0u8; 96];
    shake256(seed, &mut out);
    let mut d = [0u8; 32];
    let mut z = [0u8; 32];
    let mut sk_x = [0u8; 32];
    d.copy_from_slice(&out[..32]);
    z.copy_from_slice(&out[32..64]);
    sk_x.copy_from_slice(&out[64..]);
    (d, z, sk_x)
}

/// The combiner: `SHA3-256(ss_M ‖ ss_X ‖ ct_X ‖ pk_X ‖ label)`.
pub fn combine(
    ss_m: &[u8; 32],
    ss_x: &[u8; 32],
    ct_x: &[u8; 32],
    pk_x: &[u8; 32],
) -> [u8; SHARED_SECRET_LEN] {
    let mut input = [0u8; 32 * 4 + LABEL.len()];
    input[..32].copy_from_slice(ss_m);
    input[32..64].copy_from_slice(ss_x);
    input[64..96].copy_from_slice(ct_x);
    input[96..128].copy_from_slice(pk_x);
    input[128..].copy_from_slice(&LABEL);
    sha3_256(&input)
}

/// Deterministic key generation from a 32-byte seed.
pub fn keygen_seed(seed: &[u8; SEED_LEN]) -> (PublicKey, SecretKey) {
    let (d, z, sk_x) = expand(seed);
    let (ek, _dk) = ml_kem::keygen_seed::<MlKem768>(&d, &z);
    let pk_x = X25519::diffie_hellman(&sk_x, &X25519::BASE);
    let mut pk = [0u8; PUBLIC_KEY_LEN];
    pk[..MlKem768::PK_LEN].copy_from_slice(&ek.bytes);
    pk[MlKem768::PK_LEN..].copy_from_slice(&pk_x);
    (PublicKey(pk), SecretKey::from_seed(*seed))
}

/// Generate a key pair from an RNG.
pub fn keygen(rng: &mut impl CryptoRng) -> (PublicKey, SecretKey) {
    let seed = rng.gen_array::<SEED_LEN>();
    keygen_seed(&seed)
}

/// Encapsulate with explicit randomness: `eph` is the X25519 ephemeral scalar and
/// `m` the ML-KEM message. Equivalent to [`encapsulate`] when both are random.
///
/// Returns [`Error::InvalidKey`] if the public key fails the FIPS 203 check or the
/// X25519 component is a low-order point (all-zero shared secret).
pub fn encapsulate_with(
    pk: &PublicKey,
    eph: &[u8; 32],
    m: &[u8; 32],
) -> Result<([u8; SHARED_SECRET_LEN], [u8; CIPHERTEXT_LEN])> {
    let pk_m = &pk.0[..MlKem768::PK_LEN];
    let mut pk_x = [0u8; 32];
    pk_x.copy_from_slice(&pk.0[MlKem768::PK_LEN..]);

    // Untrusted input: check before the ML-KEM encapsulation, which assumes a
    // well-formed key.
    ml_kem::check_encaps_key::<MlKem768>(pk_m)?;
    let ek = EncapsKey {
        bytes: pk_m.to_vec(),
    };
    let (ss_m, ct_m) = ml_kem::encapsulate_msg::<MlKem768>(&ek, m);

    let ss_x = X25519::diffie_hellman(eph, &pk_x);
    if ss_x.iter().all(|&b| b == 0) {
        return Err(Error::InvalidKey);
    }
    let ct_x = X25519::diffie_hellman(eph, &X25519::BASE);

    let ss = combine(&ss_m, &ss_x, &ct_x, &pk_x);
    let mut ct = [0u8; CIPHERTEXT_LEN];
    ct[..MlKem768::CT_LEN].copy_from_slice(ct_m.as_bytes());
    ct[MlKem768::CT_LEN..].copy_from_slice(&ct_x);
    Ok((ss, ct))
}

/// Encapsulate to `pk`, drawing the X25519 ephemeral and the ML-KEM message from `rng`.
pub fn encapsulate(
    pk: &PublicKey,
    rng: &mut impl CryptoRng,
) -> Result<([u8; SHARED_SECRET_LEN], [u8; CIPHERTEXT_LEN])> {
    let eph = rng.gen_array::<32>();
    let m = rng.gen_array::<32>();
    encapsulate_with(pk, &eph, &m)
}

/// Decapsulate `ct` under `sk`.
///
/// Returns [`Error::InvalidCiphertext`] for a wrong length or a low-order X25519
/// ephemeral key. A well-formed but forged ML-KEM component does not error: ML-KEM
/// implicit rejection yields a pseudorandom value, so the final secret differs
/// from the sender's without revealing why.
pub fn decapsulate(sk: &SecretKey, ct: &[u8]) -> Result<[u8; SHARED_SECRET_LEN]> {
    if ct.len() != CIPHERTEXT_LEN {
        return Err(Error::InvalidCiphertext);
    }
    let (d, z, sk_x) = expand(sk.seed());
    let (_ek, dk): (EncapsKey, DecapsKey) = ml_kem::keygen_seed::<MlKem768>(&d, &z);
    let pk_x = X25519::diffie_hellman(&sk_x, &X25519::BASE);

    let ct_m = &ct[..MlKem768::CT_LEN];
    let mut ct_x = [0u8; 32];
    ct_x.copy_from_slice(&ct[MlKem768::CT_LEN..]);

    let ss_m = ml_kem::decapsulate::<MlKem768>(&dk, ct_m)?;
    let ss_x = X25519::diffie_hellman(&sk_x, &ct_x);
    if ss_x.iter().all(|&b| b == 0) {
        return Err(Error::InvalidCiphertext);
    }
    Ok(combine(&ss_m, &ss_x, &ct_x, &pk_x))
}

#[cfg(test)]
mod tests {
    use super::*;

    const SEED: [u8; 32] = [
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24,
        25, 26, 27, 28, 29, 30, 31,
    ];

    /// Python reference (hashlib, cryptography): X25519 public key for the
    /// SHAKE256-expanded scalar of `SEED`.
    const PK_X_REFERENCE: [u8; 32] = [
        0x44, 0xe9, 0xd7, 0xd1, 0x46, 0x64, 0x72, 0x81, 0xfb, 0xba, 0x7b, 0x3c, 0x56, 0xca, 0xfd,
        0x58, 0x33, 0xb7, 0xa9, 0x30, 0xec, 0x42, 0x06, 0xe7, 0xc3, 0xa6, 0xd7, 0x76, 0x4f, 0xe8,
        0x1d, 0x7a,
    ];

    /// Python reference: `SHA3-256(01*32 ‖ 02*32 ‖ 03*32 ‖ 04*32 ‖ label)`.
    const COMBINE_REFERENCE: [u8; 32] = [
        0x5c, 0x6b, 0xfa, 0xf8, 0xc3, 0xec, 0x48, 0xab, 0x3c, 0xee, 0x7c, 0x12, 0x12, 0x9b, 0x39,
        0x91, 0x3b, 0x8a, 0x7f, 0xa1, 0x23, 0x41, 0x15, 0xda, 0x7e, 0x1c, 0x55, 0x60, 0x8a, 0xd1,
        0x9f, 0xb6,
    ];

    #[test]
    fn label_is_draft_value() {
        assert_eq!(&LABEL, b"\\.//^\\");
    }

    #[test]
    fn combiner_matches_reference() {
        let ss = combine(&[1; 32], &[2; 32], &[3; 32], &[4; 32]);
        assert_eq!(ss, COMBINE_REFERENCE);
    }

    #[test]
    fn keygen_x25519_component_matches_reference() {
        let (pk, _) = keygen_seed(&SEED);
        assert_eq!(&pk.0[MlKem768::PK_LEN..], &PK_X_REFERENCE);
        assert_eq!(pk.0.len(), 1216);
    }

    #[test]
    fn round_trip_is_deterministic_per_seed() {
        for i in 0..4u8 {
            let mut seed = SEED;
            seed[0] = i;
            let (pk, sk) = keygen_seed(&seed);
            let eph = [0x40 + i; 32];
            let m = [0x80 + i; 32];
            let (ss_s, ct) = encapsulate_with(&pk, &eph, &m).unwrap();
            let ss_r = decapsulate(&sk, &ct).unwrap();
            assert_eq!(ss_s, ss_r, "seed {i}");
        }
    }

    #[test]
    fn random_encapsulation_round_trips() {
        struct Counter(u8);
        impl CryptoRng for Counter {
            fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<()> {
                for b in dest.iter_mut() {
                    self.0 = self.0.wrapping_mul(37).wrapping_add(11);
                    *b = self.0;
                }
                Ok(())
            }
        }
        let mut rng = Counter(7);
        let (pk, sk) = keygen(&mut rng);
        let (ss_s, ct) = encapsulate(&pk, &mut rng).unwrap();
        assert_eq!(decapsulate(&sk, &ct).unwrap(), ss_s);
    }

    #[test]
    fn tampering_either_component_changes_the_secret() {
        let (pk, sk) = keygen_seed(&SEED);
        let (ss, ct) = encapsulate_with(&pk, &[9; 32], &[7; 32]).unwrap();

        let mut bad_m = ct;
        bad_m[10] ^= 1;
        assert_ne!(decapsulate(&sk, &bad_m).unwrap(), ss);

        let mut bad_x = ct;
        bad_x[CIPHERTEXT_LEN - 1] ^= 1;
        assert_ne!(decapsulate(&sk, &bad_x).unwrap(), ss);
    }

    #[test]
    fn wrong_length_ciphertext_is_rejected() {
        let (_, sk) = keygen_seed(&SEED);
        assert_eq!(
            decapsulate(&sk, &[0u8; CIPHERTEXT_LEN - 1]).unwrap_err(),
            Error::InvalidCiphertext
        );
    }

    #[test]
    fn malformed_ml_kem_key_is_rejected_not_panicked() {
        let (mut pk, _) = keygen_seed(&SEED);
        // Make the first 12-bit coefficient 4095 (>= q = 3329): FIPS 203 §7.2 check.
        pk.0[0] = 0xff;
        pk.0[1] |= 0x0f;
        assert_eq!(
            encapsulate_with(&pk, &[9; 32], &[7; 32]).unwrap_err(),
            Error::InvalidKey
        );
    }

    #[test]
    fn low_order_x25519_public_key_is_rejected() {
        let (mut pk, _) = keygen_seed(&SEED);
        for b in pk.0[MlKem768::PK_LEN..].iter_mut() {
            *b = 0;
        }
        assert_eq!(
            encapsulate_with(&pk, &[9; 32], &[7; 32]).unwrap_err(),
            Error::InvalidKey
        );
    }
}
