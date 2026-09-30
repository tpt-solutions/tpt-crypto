//! BLS12-381 aggregatable signatures
//! (draft-irtf-cfrg-bls-signature-04, minimal-pubkey-size ciphersuites).
//!
//! Signatures live in `G2`, public keys in `G1`; verification is a pairing
//! check `e(P1, H(msg)) == e(pk, σ)` performed with a single
//! [`multi_pairing`] (one final exponentiation regardless of the number of
//! terms). Hashing uses the RFC 9380 suite
//! `BLS12381G2_XMD:SHA-256_SSWU_RO_` with the draft's domain separation tags.
//!
//! Three ciphersuites are provided via [`Ciphersuite`]:
//!
//! * [`Ciphersuite::Basic`] — `…_NUL_`: aggregate verification requires the
//!   messages to be pairwise distinct,
//! * [`Ciphersuite::Aug`] — `…_AUG_`: each message is hashed as `pk ‖ msg`,
//!   so duplicates are safe,
//! * [`Ciphersuite::Pop`] — `…_POP_`: like Basic plus a proof-of-possession
//!   ([`proof_of_possession`]) for key registration.
//!
//! The bare [`sign`]/[`verify`]/[`aggregate`]/[`verify_aggregate`] functions
//! use [`Ciphersuite::Pop`] (the consensus / Ethereum-compatible default,
//! matching the vectors in `tests/kat/`).

use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;

use tpt_crypto_core::SecretBox;
use tpt_crypto_ct::ct_eq_bytes;
use tpt_crypto_curve::bls12_381::{multi_pairing, Gt, G1, G2};
use tpt_crypto_curve::hash_to_curve::hash_to_curve_bls12381_g2;
use tpt_crypto_field::{Bls12381Fr, CtEq};

use crate::{Error, Result};
use tpt_crypto_hash::kdf::hkdf_sha256;

/// Serialized public-key size (compressed `G1`).
pub const PK_LEN: usize = 48;
/// Serialized signature size (compressed `G2`).
pub const SIG_LEN: usize = 96;
/// Secret-key size (big-endian scalar).
pub const SK_LEN: usize = 32;

/// The draft-04 ciphersuite selector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ciphersuite {
    /// `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_` — basic scheme.
    Basic,
    /// `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_` — message augmentation.
    Aug,
    /// `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_` — proof of possession.
    Pop,
}

impl Ciphersuite {
    /// The RFC 9380 domain separation tag for this suite.
    #[must_use]
    pub fn dst(self) -> &'static [u8] {
        match self {
            Ciphersuite::Basic => b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_",
            Ciphersuite::Aug => b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_AUG_",
            Ciphersuite::Pop => b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_POP_",
        }
    }
}

/// The default ciphersuite for the bare [`sign`]/[`verify`]/aggregate
/// functions (Ethereum-compatible).
pub const DEFAULT_SUITE: Ciphersuite = Ciphersuite::Pop;

/// A BLS secret key: a scalar `< r`, zeroized on drop.
pub struct SecretKey {
    sk: SecretBox<[u8; SK_LEN]>,
}

impl core::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("SecretKey(..)")
    }
}

/// A validated BLS public key (compressed `G1`, 48 bytes on the wire).
#[derive(Clone, Copy)]
pub struct PublicKey {
    point: G1,
}

/// A BLS signature (compressed `G2`, 96 bytes on the wire).
#[derive(Clone, Copy)]
pub struct Signature {
    point: G2,
}

impl core::fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "PublicKey({})", hex_str(&self.to_bytes()))
    }
}

impl core::fmt::Debug for Signature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Signature({})", hex_str(&self.to_bytes()[..8]))
    }
}

fn hex_str(b: &[u8]) -> String {
    let mut s = String::new();
    for byte in b {
        s.push_str(&format!("{byte:02x}"));
    }
    s
}

// --- keys --------------------------------------------------------------------

/// Reduce a 48-byte big-endian integer modulo `r` in constant time (one
/// `double-and-add` step per bit, fixed iteration count).
fn os2ip_mod_r(okm: &[u8; 48]) -> [u8; SK_LEN] {
    let mut acc = Bls12381Fr::zero();
    for &byte in okm {
        let mut bit = 8usize;
        while bit > 0 {
            bit -= 1;
            let b = Bls12381Fr::from_u64(((byte >> bit) & 1) as u64);
            acc = acc.double().add(&b);
        }
    }
    // `Bls12381Fr` has 4 limbs: `to_bytes` yields 48 bytes with the value in
    // the low 32.
    let full = acc.to_bytes();
    let mut sk = [0u8; SK_LEN];
    sk.copy_from_slice(&full[full.len() - SK_LEN..]);
    sk
}

impl SecretKey {
    /// Parse a canonical secret key (big-endian scalar `< r`, nonzero).
    pub fn from_bytes(bytes: &[u8; SK_LEN]) -> Result<Self> {
        let is_zero = ct_eq_bytes(bytes, &[0u8; SK_LEN]).is_true();
        if is_zero {
            return Err(Error::InvalidEncoding);
        }
        Ok(SecretKey {
            sk: SecretBox::new(*bytes),
        })
    }

    /// `KeyGen(IKM)` per draft-irtf-cfrg-bls-signature-04 §2.3:
    /// HKDF-SHA-256 with salt `"BLS-SIG-KEYGEN-SALT-"`, 48 output bytes,
    /// reduced modulo the subgroup order. Requires at least 32 bytes of IKM.
    pub fn keygen(ikm: &[u8]) -> Result<Self> {
        if ikm.len() < 32 {
            return Err(Error::InvalidLength);
        }
        let mut salted = Vec::with_capacity(ikm.len() + 1);
        salted.extend_from_slice(ikm);
        salted.push(0u8);
        let mut okm = [0u8; 48];
        hkdf_sha256(b"BLS-SIG-KEYGEN-SALT-", &salted, &info(), &mut okm);
        let sk = os2ip_mod_r(&okm);
        // Probability of a zero scalar is ~2^-255; still, KeyGen must fail.
        if ct_eq_bytes(&sk, &[0u8; SK_LEN]).is_true() {
            return Err(Error::RngFailure);
        }
        Ok(SecretKey {
            sk: SecretBox::new(sk),
        })
    }

    /// Big-endian scalar bytes. Treat the result as secret.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SK_LEN] {
        *self.sk.expose_secret()
    }

    /// `SkToPk`: the compressed public key `[sk]·G1`.
    #[must_use]
    pub fn public_key(&self) -> PublicKey {
        let point = G1::generator().mul(self.sk.expose_secret());
        PublicKey { point }
    }
}

/// HKDF info for `KeyGen`: `I2OSP(48, 2) ‖ "BLS-SIG-KEYGEN-"`.
fn info() -> [u8; 17] {
    let mut info = [0u8; 17];
    info[..2].copy_from_slice(&48u16.to_be_bytes());
    info[2..].copy_from_slice(b"BLS-SIG-KEYGEN-");
    info
}

impl PublicKey {
    /// Parse and validate a compressed public key: canonical encoding, on
    /// curve, in the prime-order subgroup, and not the identity (`KeyValidate`).
    pub fn from_bytes(bytes: &[u8; PK_LEN]) -> Result<Self> {
        let point = G1::from_compressed(bytes).ok_or(Error::InvalidEncoding)?;
        if point.is_identity().into_bool() {
            return Err(Error::InvalidEncoding);
        }
        Ok(PublicKey { point })
    }

    /// Compressed 48-byte serialization.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; PK_LEN] {
        self.point.to_compressed()
    }
}

impl Signature {
    /// Parse a compressed signature (canonical, on curve, in the subgroup).
    /// The identity is accepted at the deserialization layer; verification
    /// rejects it through the pairing equation.
    pub fn from_bytes(bytes: &[u8; SIG_LEN]) -> Result<Self> {
        let point = G2::from_compressed(bytes).ok_or(Error::InvalidEncoding)?;
        Ok(Signature { point })
    }

    /// Compressed 96-byte serialization.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SIG_LEN] {
        self.point.to_compressed()
    }
}

// --- core scheme -------------------------------------------------------------

/// `CoreSign`: `σ = [sk]·H(msg)`.
#[must_use]
pub fn sign(sk: &SecretKey, msg: &[u8]) -> Signature {
    sign_with(sk, msg, DEFAULT_SUITE)
}

/// [`sign`] with an explicit ciphersuite.
#[must_use]
pub fn sign_with(sk: &SecretKey, msg: &[u8], suite: Ciphersuite) -> Signature {
    let m = hash_input(sk, msg, suite);
    let h = hash_to_curve_bls12381_g2(&m, suite.dst());
    Signature {
        point: h.mul(&sk.to_bytes()),
    }
}

/// The message actually hashed: `pk ‖ msg` for the Aug scheme, `msg` otherwise.
fn hash_input(sk: &SecretKey, msg: &[u8], suite: Ciphersuite) -> Vec<u8> {
    if suite == Ciphersuite::Aug {
        let pk = sk.public_key();
        let mut m = Vec::with_capacity(PK_LEN + msg.len());
        m.extend_from_slice(&pk.to_bytes());
        m.extend_from_slice(msg);
        m
    } else {
        Vec::from(msg)
    }
}

/// `CoreVerify`: `e(P1, H(msg)) == e(pk, σ)` as a single product pairing.
pub fn verify(pk: &PublicKey, msg: &[u8], sig: &Signature) -> Result<()> {
    verify_with(pk, msg, sig, DEFAULT_SUITE)
}

/// [`verify`] with an explicit ciphersuite.
pub fn verify_with(pk: &PublicKey, msg: &[u8], sig: &Signature, suite: Ciphersuite) -> Result<()> {
    let m = match suite {
        Ciphersuite::Aug => {
            let mut m = Vec::with_capacity(PK_LEN + msg.len());
            m.extend_from_slice(&pk.to_bytes());
            m.extend_from_slice(msg);
            m
        }
        _ => Vec::from(msg),
    };
    let h = hash_to_curve_bls12381_g2(&m, suite.dst());
    let ok = pairing_check(&[(pk.point, h), (G1::generator().neg(), sig.point)]);
    if ok {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}

/// `∏ e(Pᵢ, Qᵢ) == 1` with one final exponentiation.
fn pairing_check(terms: &[(G1, G2)]) -> bool {
    multi_pairing(terms).ct_eq(&Gt::one()).into_bool()
}

// --- aggregation ---------------------------------------------------------------

/// `Aggregate(σ₁, …, σₙ) = σ₁ + … + σₙ` (at least one signature).
pub fn aggregate(sigs: &[Signature]) -> Result<Signature> {
    let mut it = sigs.iter();
    let first = it.next().ok_or(Error::InvalidLength)?;
    let mut acc = first.point;
    for s in it {
        acc = acc.add(&s.point);
    }
    Ok(Signature { point: acc })
}

/// Same-message aggregate verification (`FastAggregateVerify`):
/// `e(P1, σ_agg) == e(∑pkᵢ, H(msg))`.
///
/// Every public key must be valid ([`PublicKey::from_bytes`] already enforces
/// this) and the aggregate key must not be the identity.
pub fn verify_aggregate(pks: &[PublicKey], msg: &[u8], agg: &Signature) -> Result<()> {
    verify_aggregate_with(pks, msg, agg, DEFAULT_SUITE)
}

/// [`verify_aggregate`] with an explicit ciphersuite.
pub fn verify_aggregate_with(
    pks: &[PublicKey],
    msg: &[u8],
    agg: &Signature,
    suite: Ciphersuite,
) -> Result<()> {
    if pks.is_empty() {
        return Err(Error::InvalidLength);
    }
    let mut sum = pks[0].point;
    for pk in &pks[1..] {
        sum = sum.add(&pk.point);
    }
    if sum.is_identity().into_bool() {
        return Err(Error::Verification);
    }
    let h = hash_to_curve_bls12381_g2(msg, suite.dst());
    let ok = pairing_check(&[(sum, h), (G1::generator().neg(), agg.point)]);
    if ok {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}

/// Distinct-message aggregate verification (`AggregateVerify`):
/// `e(P1, σ_agg) == ∏ e(pkᵢ, H(msgᵢ))`.
///
/// The Basic and Pop schemes require all messages to be pairwise distinct
/// (the draft leaves this to the caller; we enforce it here). The Aug scheme
/// hashes `pk ‖ msg` and imposes no distinctness requirement.
pub fn aggregate_verify(pks: &[PublicKey], msgs: &[&[u8]], agg: &Signature) -> Result<()> {
    aggregate_verify_with(pks, msgs, agg, DEFAULT_SUITE)
}

/// [`aggregate_verify`] with an explicit ciphersuite.
pub fn aggregate_verify_with(
    pks: &[PublicKey],
    msgs: &[&[u8]],
    agg: &Signature,
    suite: Ciphersuite,
) -> Result<()> {
    if pks.is_empty() || pks.len() != msgs.len() {
        return Err(Error::InvalidLength);
    }
    if suite != Ciphersuite::Aug {
        for i in 0..msgs.len() {
            for j in (i + 1)..msgs.len() {
                if msgs[i] == msgs[j] {
                    return Err(Error::InvalidInput);
                }
            }
        }
    }
    let mut terms = Vec::with_capacity(pks.len() + 1);
    terms.push((G1::generator().neg(), agg.point));
    for (pk, msg) in pks.iter().zip(msgs.iter()) {
        let m = if suite == Ciphersuite::Aug {
            let mut m = Vec::with_capacity(PK_LEN + msg.len());
            m.extend_from_slice(&pk.to_bytes());
            m.extend_from_slice(msg);
            m
        } else {
            Vec::from(*msg)
        };
        let h = hash_to_curve_bls12381_g2(&m, suite.dst());
        terms.push((pk.point, h));
    }
    if pairing_check(&terms) {
        Ok(())
    } else {
        Err(Error::Verification)
    }
}

// --- proof of possession -------------------------------------------------------

/// `PopProve`: a signature over the serialized public key itself.
#[must_use]
pub fn proof_of_possession(sk: &SecretKey) -> Signature {
    let pk = sk.public_key();
    sign_with(sk, &pk.to_bytes(), Ciphersuite::Pop)
}

/// `PopVerify`: verify [`proof_of_possession`] against the key it proves.
pub fn verify_proof_of_possession(pk: &PublicKey, pop: &Signature) -> Result<()> {
    verify_with(pk, &pk.to_bytes(), pop, Ciphersuite::Pop)
}
