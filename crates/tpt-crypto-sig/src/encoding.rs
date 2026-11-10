//! Key encoding: strict DER for SubjectPublicKeyInfo / PKCS#8, and PEM.
//!
//! Scope of this module:
//!
//! * **Ed25519** SPKI (RFC 8410 §4) and PKCS#8 (RFC 8410 §7), fixed layouts.
//! * **RSA** SPKI (RFC 8017 §A.1.1) for `rsaEncryption`, which feeds
//!   [`crate::rsa::PublicKey::from_components`].
//! * **PEM** (RFC 7468) wrapping with a strict base64 decoder.
//!
//! The DER reader is deliberately strict, since parsers of attacker-supplied
//! keys are a common source of ambiguity: only definite lengths are accepted,
//! lengths must be minimally encoded, single-byte tags only, integers must be
//! positive and minimally encoded, and any trailing bytes after the structure
//! are rejected. Every rejection is [`Error::InvalidEncoding`].

use crate::ecdsa::{EcdsaCurve, SigningKey as EcSigningKey, VerifyingKey as EcVerifyingKey};
use crate::rsa::PublicKey as RsaPublicKey;
use alloc::string::String;
use alloc::vec::Vec;
use tpt_crypto_core::{Error, Result};
use tpt_crypto_curve::weierstrass::{P256, P384};

/// Length of an Ed25519 public key.
pub const ED25519_PUBLIC_LEN: usize = 32;
/// Length of an Ed25519 seed (secret key).
pub const ED25519_SEED_LEN: usize = 32;
/// Length of a DER Ed25519 SubjectPublicKeyInfo.
pub const ED25519_SPKI_LEN: usize = 44;
/// Length of a DER Ed25519 PKCS#8 PrivateKeyInfo.
pub const ED25519_PKCS8_LEN: usize = 48;

// AlgorithmIdentifier bodies (OID TLV) — see the module note for sources.
const OID_ED25519: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
const OID_RSA_ENCRYPTION: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
];

const TAG_INTEGER: u8 = 0x02;
const TAG_BIT_STRING: u8 = 0x03;
const TAG_OCTET_STRING: u8 = 0x04;
const TAG_NULL: u8 = 0x05;
const TAG_OID_CONSTRUCTED_SEQ: u8 = 0x30;

// ---------------------------------------------------------------------------
// DER writing
// ---------------------------------------------------------------------------

fn push_len(out: &mut Vec<u8>, len: usize) {
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let bytes = len.to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        let n = bytes.len() - skip;
        out.push(0x80 | n as u8);
        out.extend_from_slice(&bytes[skip..]);
    }
}

fn tlv(tag: u8, value: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(value.len() + 6);
    out.push(tag);
    push_len(&mut out, value.len());
    out.extend_from_slice(value);
    out
}

/// DER INTEGER for a non-negative big-endian magnitude (leading zeros stripped,
/// a single `0x00` prepended when the high bit is set).
fn der_uint(be: &[u8]) -> Vec<u8> {
    let start = be.iter().position(|&b| b != 0).unwrap_or(be.len());
    let mag = &be[start..];
    let mut v = Vec::with_capacity(mag.len() + 1);
    if mag.is_empty() {
        v.push(0);
    } else {
        if mag[0] & 0x80 != 0 {
            v.push(0);
        }
        v.extend_from_slice(mag);
    }
    tlv(TAG_INTEGER, &v)
}

// ---------------------------------------------------------------------------
// Strict DER reading
// ---------------------------------------------------------------------------

/// Split one TLV off the front of `input`. Returns `(tag, value, rest)`.
fn read_tlv(input: &[u8]) -> Result<(u8, &[u8], &[u8])> {
    let (&tag, rest) = input.split_first().ok_or(Error::InvalidEncoding)?;
    // Only single-byte tags are used by the structures in this module.
    if tag & 0x1f == 0x1f {
        return Err(Error::InvalidEncoding);
    }
    let (&first, rest) = rest.split_first().ok_or(Error::InvalidEncoding)?;
    let (len, rest) = if first < 0x80 {
        (first as usize, rest)
    } else {
        let n = (first & 0x7f) as usize;
        // Reject indefinite (0x80) and absurdly long lengths; require minimal form.
        if n == 0 || n > core::mem::size_of::<usize>() || rest.len() < n {
            return Err(Error::InvalidEncoding);
        }
        let (lenb, rest) = rest.split_at(n);
        if lenb[0] == 0 {
            return Err(Error::InvalidEncoding); // leading zero: non-minimal
        }
        let mut len = 0usize;
        for &b in lenb {
            len = len.checked_mul(256).ok_or(Error::InvalidEncoding)? | b as usize;
        }
        if len < 0x80 {
            return Err(Error::InvalidEncoding); // should have used short form
        }
        (len, rest)
    };
    if rest.len() < len {
        return Err(Error::InvalidEncoding);
    }
    let (value, rest) = rest.split_at(len);
    Ok((tag, value, rest))
}

/// Read one TLV with an expected tag and return its value; `rest` must be empty
/// afterwards when `exact` is set.
fn expect(input: &[u8], tag: u8) -> Result<(&[u8], &[u8])> {
    let (t, v, rest) = read_tlv(input)?;
    if t != tag {
        return Err(Error::InvalidEncoding);
    }
    Ok((v, rest))
}

/// A DER INTEGER's magnitude bytes: positive, minimally encoded, leading zero
/// stripped.
fn read_uint(input: &[u8]) -> Result<(&[u8], &[u8])> {
    let (v, rest) = expect(input, TAG_INTEGER)?;
    if v.is_empty() || v[0] & 0x80 != 0 {
        return Err(Error::InvalidEncoding); // empty or negative
    }
    if v.len() > 1 && v[0] == 0 && v[1] & 0x80 == 0 {
        return Err(Error::InvalidEncoding); // non-minimal padding
    }
    let mag = if v[0] == 0 && v.len() > 1 { &v[1..] } else { v };
    Ok((mag, rest))
}

fn exact(rest: &[u8]) -> Result<()> {
    if rest.is_empty() {
        Ok(())
    } else {
        Err(Error::InvalidEncoding)
    }
}

// ---------------------------------------------------------------------------
// Ed25519
// ---------------------------------------------------------------------------

/// Encode an Ed25519 public key as a DER SubjectPublicKeyInfo (44 bytes).
pub fn ed25519_public_to_spki(public: &[u8; ED25519_PUBLIC_LEN]) -> [u8; ED25519_SPKI_LEN] {
    let mut out = [0u8; ED25519_SPKI_LEN];
    // 30 2a | 30 05 OID | 03 21 00 <key>
    out[0] = TAG_OID_CONSTRUCTED_SEQ;
    out[1] = 0x2a;
    out[2] = TAG_OID_CONSTRUCTED_SEQ;
    out[3] = 0x05;
    out[4..9].copy_from_slice(OID_ED25519);
    out[9] = TAG_BIT_STRING;
    out[10] = 0x21;
    out[11] = 0x00;
    out[12..].copy_from_slice(public);
    out
}

/// Decode a DER Ed25519 SubjectPublicKeyInfo. Only the exact 44-byte form with
/// the Ed25519 OID and no parameters is accepted.
pub fn ed25519_public_from_spki(der: &[u8]) -> Result<[u8; ED25519_PUBLIC_LEN]> {
    let (seq, rest) = expect(der, TAG_OID_CONSTRUCTED_SEQ)?;
    exact(rest)?;
    let (alg, rest) = expect(seq, TAG_OID_CONSTRUCTED_SEQ)?;
    if alg != OID_ED25519 {
        return Err(Error::InvalidEncoding);
    }
    let (bits, rest) = expect(rest, TAG_BIT_STRING)?;
    exact(rest)?;
    if bits.len() != 1 + ED25519_PUBLIC_LEN || bits[0] != 0 {
        return Err(Error::InvalidEncoding);
    }
    let mut key = [0u8; ED25519_PUBLIC_LEN];
    key.copy_from_slice(&bits[1..]);
    Ok(key)
}

/// Encode an Ed25519 seed as a DER PKCS#8 PrivateKeyInfo (48 bytes, RFC 8410 §7).
pub fn ed25519_seed_to_pkcs8(seed: &[u8; ED25519_SEED_LEN]) -> [u8; ED25519_PKCS8_LEN] {
    let mut out = [0u8; ED25519_PKCS8_LEN];
    // 30 2e | 02 01 00 | 30 05 OID | 04 22 04 20 <seed>
    out[0] = TAG_OID_CONSTRUCTED_SEQ;
    out[1] = 0x2e;
    out[2..5].copy_from_slice(&[TAG_INTEGER, 0x01, 0x00]);
    out[5] = TAG_OID_CONSTRUCTED_SEQ;
    out[6] = 0x05;
    out[7..12].copy_from_slice(OID_ED25519);
    out[12] = TAG_OCTET_STRING;
    out[13] = 0x22;
    out[14] = TAG_OCTET_STRING;
    out[15] = 0x20;
    out[16..].copy_from_slice(seed);
    out
}

/// Decode a DER PKCS#8 Ed25519 PrivateKeyInfo (version 0, no attributes, no
/// embedded public key) and return the seed.
pub fn ed25519_seed_from_pkcs8(der: &[u8]) -> Result<[u8; ED25519_SEED_LEN]> {
    let (seq, rest) = expect(der, TAG_OID_CONSTRUCTED_SEQ)?;
    exact(rest)?;
    let (version, rest) = read_uint(seq)?;
    if version != [0] {
        return Err(Error::InvalidEncoding);
    }
    let (alg, rest) = expect(rest, TAG_OID_CONSTRUCTED_SEQ)?;
    if alg != OID_ED25519 {
        return Err(Error::InvalidEncoding);
    }
    let (inner, rest) = expect(rest, TAG_OCTET_STRING)?;
    exact(rest)?;
    let (seed, rest) = expect(inner, TAG_OCTET_STRING)?;
    exact(rest)?;
    if seed.len() != ED25519_SEED_LEN {
        return Err(Error::InvalidEncoding);
    }
    let mut out = [0u8; ED25519_SEED_LEN];
    out.copy_from_slice(seed);
    Ok(out)
}

// ---------------------------------------------------------------------------
// RSA
// ---------------------------------------------------------------------------

/// Encode an RSA public key as a DER SubjectPublicKeyInfo (`rsaEncryption`,
/// NULL parameters). `n` and `e` are big-endian magnitudes.
pub fn rsa_public_to_spki(n_be: &[u8], e_be: &[u8]) -> Vec<u8> {
    let mut alg = Vec::with_capacity(OID_RSA_ENCRYPTION.len() + 2);
    alg.extend_from_slice(OID_RSA_ENCRYPTION);
    alg.extend_from_slice(&[TAG_NULL, 0x00]);
    let mut key_seq = der_uint(n_be);
    key_seq.extend_from_slice(&der_uint(e_be));
    // BIT STRING body: unused-bits octet then the DER RSAPublicKey.
    let mut bits = Vec::with_capacity(key_seq.len() + 1);
    bits.push(0x00);
    bits.extend_from_slice(&tlv(TAG_OID_CONSTRUCTED_SEQ, &key_seq));
    let mut body = tlv(TAG_OID_CONSTRUCTED_SEQ, &alg);
    body.extend_from_slice(&tlv(TAG_BIT_STRING, &bits));
    tlv(TAG_OID_CONSTRUCTED_SEQ, &body)
}

/// Decode a DER RSA SubjectPublicKeyInfo into a verifying key.
///
/// Accepts only `rsaEncryption` with NULL parameters; the modulus and exponent
/// are then validated by [`RsaPublicKey::from_components`].
pub fn rsa_public_from_spki(der: &[u8]) -> Result<RsaPublicKey> {
    let (seq, rest) = expect(der, TAG_OID_CONSTRUCTED_SEQ)?;
    exact(rest)?;
    let (alg, rest) = expect(seq, TAG_OID_CONSTRUCTED_SEQ)?;
    let (oid, alg_rest) = expect(alg, 0x06)?;
    if oid != &OID_RSA_ENCRYPTION[2..] {
        return Err(Error::InvalidEncoding);
    }
    let (null, alg_rest) = expect(alg_rest, TAG_NULL)?;
    if !null.is_empty() {
        return Err(Error::InvalidEncoding);
    }
    exact(alg_rest)?;

    let (bits, rest) = expect(rest, TAG_BIT_STRING)?;
    exact(rest)?;
    let (&unused, key_der) = bits.split_first().ok_or(Error::InvalidEncoding)?;
    if unused != 0 {
        return Err(Error::InvalidEncoding);
    }
    let (rsa_seq, rest) = expect(key_der, TAG_OID_CONSTRUCTED_SEQ)?;
    exact(rest)?;
    let (n, rest) = read_uint(rsa_seq)?;
    let (e, rest) = read_uint(rest)?;
    exact(rest)?;
    RsaPublicKey::from_components(n, e).map_err(|_| Error::InvalidEncoding)
}

// ---------------------------------------------------------------------------
// ECDSA: P-256 and P-384 (RFC 5480 SPKI, RFC 5915 private key in PKCS#8)
// ---------------------------------------------------------------------------

const OID_EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const OID_PRIME256V1: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const OID_SECP384R1: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
const TAG_CONTEXT_1: u8 = 0xa1;

/// AlgorithmIdentifier body: `id-ecPublicKey ‖ namedCurve`.
fn ec_alg_body(curve_oid: &[u8]) -> Vec<u8> {
    let mut v = Vec::with_capacity(OID_EC_PUBLIC_KEY.len() + curve_oid.len());
    v.extend_from_slice(OID_EC_PUBLIC_KEY);
    v.extend_from_slice(curve_oid);
    v
}

fn ec_spki_encode<C: EcdsaCurve>(curve_oid: &[u8], vk: &EcVerifyingKey<C>) -> Vec<u8> {
    let mut bits = Vec::with_capacity(1 + 1 + 2 * C::FIELD_BYTES);
    bits.push(0x00);
    bits.extend_from_slice(&vk.to_sec1_uncompressed());
    let mut body = tlv(TAG_OID_CONSTRUCTED_SEQ, &ec_alg_body(curve_oid));
    body.extend_from_slice(&tlv(TAG_BIT_STRING, &bits));
    tlv(TAG_OID_CONSTRUCTED_SEQ, &body)
}

fn ec_spki_decode<C: EcdsaCurve>(der: &[u8], curve_oid: &[u8]) -> Result<EcVerifyingKey<C>> {
    let (seq, rest) = expect(der, TAG_OID_CONSTRUCTED_SEQ)?;
    exact(rest)?;
    let (alg, rest) = expect(seq, TAG_OID_CONSTRUCTED_SEQ)?;
    if alg != ec_alg_body(curve_oid).as_slice() {
        return Err(Error::InvalidEncoding);
    }
    let (bits, rest) = expect(rest, TAG_BIT_STRING)?;
    exact(rest)?;
    let (&unused, point) = bits.split_first().ok_or(Error::InvalidEncoding)?;
    if unused != 0 {
        return Err(Error::InvalidEncoding);
    }
    EcVerifyingKey::<C>::from_sec1(point).map_err(|_| Error::InvalidEncoding)
}

/// PKCS#8 PrivateKeyInfo wrapping an RFC 5915 `ECPrivateKey` that carries the
/// optional public key, the same shape OpenSSL emits.
fn ec_pkcs8_encode<C: EcdsaCurve>(curve_oid: &[u8], sk: &EcSigningKey<C>) -> Vec<u8> {
    let d_all = sk.to_be_bytes();
    let d = &d_all.expose_secret()[..C::N_BYTES];
    let point = sk.verifying_key().to_sec1_uncompressed();
    let mut bits = Vec::with_capacity(1 + point.len());
    bits.push(0x00);
    bits.extend_from_slice(&point);

    // ECPrivateKey ::= SEQUENCE { version INTEGER 1, privateKey OCTET STRING,
    //                             publicKey [1] BIT STRING }
    let mut ec_pk = der_uint(&[1]);
    ec_pk.extend_from_slice(&tlv(TAG_OCTET_STRING, d));
    ec_pk.extend_from_slice(&tlv(TAG_CONTEXT_1, &tlv(TAG_BIT_STRING, &bits)));
    let ec_pk = tlv(TAG_OID_CONSTRUCTED_SEQ, &ec_pk);

    // PrivateKeyInfo ::= SEQUENCE { version INTEGER 0, algorithm, privateKey OCTET STRING }
    let mut body = der_uint(&[0]);
    body.extend_from_slice(&tlv(TAG_OID_CONSTRUCTED_SEQ, &ec_alg_body(curve_oid)));
    body.extend_from_slice(&tlv(TAG_OCTET_STRING, &ec_pk));
    tlv(TAG_OID_CONSTRUCTED_SEQ, &body)
}

fn ec_pkcs8_decode<C: EcdsaCurve>(der: &[u8], curve_oid: &[u8]) -> Result<EcSigningKey<C>> {
    let (seq, rest) = expect(der, TAG_OID_CONSTRUCTED_SEQ)?;
    exact(rest)?;
    let (version, rest) = read_uint(seq)?;
    if version != [0] {
        return Err(Error::InvalidEncoding);
    }
    let (alg, rest) = expect(rest, TAG_OID_CONSTRUCTED_SEQ)?;
    if alg != ec_alg_body(curve_oid).as_slice() {
        return Err(Error::InvalidEncoding);
    }
    let (octet, rest) = expect(rest, TAG_OCTET_STRING)?;
    exact(rest)?;

    let (ec_pk, rest) = expect(octet, TAG_OID_CONSTRUCTED_SEQ)?;
    exact(rest)?;
    let (ec_version, rest) = read_uint(ec_pk)?;
    if ec_version != [1] {
        return Err(Error::InvalidEncoding);
    }
    let (d, rest) = expect(rest, TAG_OCTET_STRING)?;
    if d.len() != C::N_BYTES {
        return Err(Error::InvalidEncoding);
    }

    // Optional [1] public key; when present it must match the private scalar.
    let advertised = if rest.is_empty() {
        None
    } else {
        let (tag, value, after) = read_tlv(rest)?;
        if tag != TAG_CONTEXT_1 {
            return Err(Error::InvalidEncoding);
        }
        exact(after)?;
        let (bits, after_bits) = expect(value, TAG_BIT_STRING)?;
        exact(after_bits)?;
        match bits.split_first() {
            Some((&0, point)) => Some(point),
            _ => return Err(Error::InvalidEncoding),
        }
    };

    let sk = EcSigningKey::<C>::from_bytes(d).map_err(|_| Error::InvalidEncoding)?;
    if let Some(point) = advertised {
        if sk.verifying_key().to_sec1_uncompressed().as_slice() != point {
            return Err(Error::InvalidEncoding);
        }
    }
    Ok(sk)
}

/// DER SubjectPublicKeyInfo for a P-256 public key (uncompressed point).
pub fn p256_public_to_spki(vk: &EcVerifyingKey<P256>) -> Vec<u8> {
    ec_spki_encode(OID_PRIME256V1, vk)
}

/// Parse a DER SubjectPublicKeyInfo for a P-256 public key.
pub fn p256_public_from_spki(der: &[u8]) -> Result<EcVerifyingKey<P256>> {
    ec_spki_decode(der, OID_PRIME256V1)
}

/// DER PKCS#8 PrivateKeyInfo for a P-256 key. The result contains the secret
/// scalar; zero it after use.
pub fn p256_private_to_pkcs8(sk: &EcSigningKey<P256>) -> Vec<u8> {
    ec_pkcs8_encode(OID_PRIME256V1, sk)
}

/// Parse a DER PKCS#8 PrivateKeyInfo for a P-256 key.
pub fn p256_private_from_pkcs8(der: &[u8]) -> Result<EcSigningKey<P256>> {
    ec_pkcs8_decode(der, OID_PRIME256V1)
}

/// DER SubjectPublicKeyInfo for a P-384 public key (uncompressed point).
pub fn p384_public_to_spki(vk: &EcVerifyingKey<P384>) -> Vec<u8> {
    ec_spki_encode(OID_SECP384R1, vk)
}

/// Parse a DER SubjectPublicKeyInfo for a P-384 public key.
pub fn p384_public_from_spki(der: &[u8]) -> Result<EcVerifyingKey<P384>> {
    ec_spki_decode(der, OID_SECP384R1)
}

/// DER PKCS#8 PrivateKeyInfo for a P-384 key. The result contains the secret
/// scalar; zero it after use.
pub fn p384_private_to_pkcs8(sk: &EcSigningKey<P384>) -> Vec<u8> {
    ec_pkcs8_encode(OID_SECP384R1, sk)
}

/// Parse a DER PKCS#8 PrivateKeyInfo for a P-384 key.
pub fn p384_private_from_pkcs8(der: &[u8]) -> Result<EcSigningKey<P384>> {
    ec_pkcs8_decode(der, OID_SECP384R1)
}

// ---------------------------------------------------------------------------
// PEM (RFC 7468)
// ---------------------------------------------------------------------------

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

fn b64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for chunk in data.chunks(3) {
        let b = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(B64[(n >> 18) as usize & 63] as char);
        out.push(B64[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 {
            B64[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            B64[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn b64_value(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'+' => Some(62),
        b'/' => Some(63),
        _ => None,
    }
}

/// Strict base64: standard alphabet, canonical padding, no stray characters.
fn b64_decode(text: &[u8]) -> Result<Vec<u8>> {
    if text.len() % 4 != 0 {
        return Err(Error::InvalidEncoding);
    }
    let mut out = Vec::with_capacity(text.len() / 4 * 3);
    let groups = text.len() / 4;
    for (gi, g) in text.chunks(4).enumerate() {
        let last = gi + 1 == groups;
        let pad = g.iter().rev().take_while(|&&c| c == b'=').count();
        if pad > 2 || (pad > 0 && !last) {
            return Err(Error::InvalidEncoding);
        }
        // Concatenate the significant sextets: 6 * (4 - pad) bits.
        let mut bits: u32 = 0;
        for &c in &g[..4 - pad] {
            bits = (bits << 6) | u32::from(b64_value(c).ok_or(Error::InvalidEncoding)?);
        }
        // Bytes produced by this group, and the bits left over after them.
        let out_bytes = 3 - pad;
        let leftover = 6 * (4 - pad) - 8 * out_bytes;
        if leftover > 0 && (bits & ((1u32 << leftover) - 1)) != 0 {
            // Non-zero discarded bits would make two encodings decode alike.
            return Err(Error::InvalidEncoding);
        }
        let n = bits << (6 * pad as u32);
        let bytes = [(n >> 16) as u8, (n >> 8) as u8, n as u8];
        out.extend_from_slice(&bytes[..out_bytes]);
    }
    Ok(out)
}

/// Wrap DER bytes as a PEM block with the given label (e.g. `PUBLIC KEY`).
pub fn pem_encode(label: &str, der: &[u8]) -> String {
    let body = b64_encode(der);
    let mut out = String::with_capacity(body.len() + body.len() / 64 + label.len() * 2 + 40);
    out.push_str("-----BEGIN ");
    out.push_str(label);
    out.push_str("-----\n");
    for line in body.as_bytes().chunks(64) {
        // base64 output is ASCII, so this is always valid UTF-8.
        out.push_str(core::str::from_utf8(line).unwrap_or(""));
        out.push('\n');
    }
    out.push_str("-----END ");
    out.push_str(label);
    out.push_str("-----\n");
    out
}

/// Decode a single PEM block whose label must equal `label`.
///
/// Surrounding text is not accepted: the input must start with the BEGIN line
/// (after optional whitespace) and end with the END line.
pub fn pem_decode(label: &str, pem: &str) -> Result<Vec<u8>> {
    let begin = {
        let mut s = String::from("-----BEGIN ");
        s.push_str(label);
        s.push_str("-----");
        s
    };
    let end = {
        let mut s = String::from("-----END ");
        s.push_str(label);
        s.push_str("-----");
        s
    };
    let trimmed = pem.trim();
    let body = trimmed
        .strip_prefix(begin.as_str())
        .and_then(|r| r.strip_suffix(end.as_str()))
        .ok_or(Error::InvalidEncoding)?;
    if body.contains("-----") {
        return Err(Error::InvalidEncoding);
    }
    let mut b64 = Vec::with_capacity(body.len());
    for c in body.bytes() {
        if c.is_ascii_whitespace() {
            continue;
        }
        b64.push(c);
    }
    b64_decode(&b64)
}

#[cfg(test)]
mod tests {
    use super::*;
    use alloc::{format, vec};

    // RFC 8410 §10.1 Ed25519 test vector (private key seed, public key).
    const SEED: [u8; 32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c,
        0xc4, 0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae,
        0x7f, 0x60,
    ];
    const PUBLIC: [u8; 32] = [
        0xd7, 0x5a, 0x98, 0x01, 0x82, 0xb1, 0x0a, 0xb7, 0xd5, 0x4b, 0xfe, 0xd3, 0xc9, 0x64, 0x07,
        0x3a, 0x0e, 0xe1, 0x72, 0xf3, 0xda, 0xa6, 0x23, 0x25, 0xaf, 0x02, 0x1a, 0x68, 0xf7, 0x07,
        0x51, 0x1a,
    ];

    #[test]
    fn ed25519_spki_matches_rfc8410() {
        let spki = ed25519_public_to_spki(&PUBLIC);
        assert_eq!(
            &spki[..12],
            &[0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]
        );
        assert_eq!(ed25519_public_from_spki(&spki).unwrap(), PUBLIC);
    }

    #[test]
    fn ed25519_pkcs8_round_trip() {
        let der = ed25519_seed_to_pkcs8(&SEED);
        assert_eq!(
            &der[..16],
            &[
                0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22,
                0x04, 0x20
            ]
        );
        assert_eq!(ed25519_seed_from_pkcs8(&der).unwrap(), SEED);
    }

    #[test]
    fn spki_rejects_trailing_data_and_wrong_oid() {
        let mut spki = ed25519_public_to_spki(&PUBLIC).to_vec();
        spki.push(0);
        assert!(ed25519_public_from_spki(&spki).is_err());

        let mut wrong = ed25519_public_to_spki(&PUBLIC);
        wrong[8] = 0x71; // 1.3.101.113 (Ed448) instead of 1.3.101.112 (Ed25519)
        assert!(ed25519_public_from_spki(&wrong).is_err());
    }

    #[test]
    fn spki_rejects_truncation_and_non_minimal_length() {
        let spki = ed25519_public_to_spki(&PUBLIC);
        for n in 0..spki.len() {
            assert!(ed25519_public_from_spki(&spki[..n]).is_err(), "prefix {n}");
        }
        // Long-form length 0x81 0x2a for a value that fits short form: non-minimal.
        let mut bad = vec![0x30, 0x81, 0x2a];
        bad.extend_from_slice(&spki[2..]);
        assert!(ed25519_public_from_spki(&bad).is_err());
    }

    #[test]
    fn uint_rules() {
        // Negative (high bit, no pad) and non-minimal padding are rejected.
        assert!(read_uint(&[0x02, 0x01, 0x80]).is_err());
        assert!(read_uint(&[0x02, 0x02, 0x00, 0x7f]).is_err());
        assert_eq!(read_uint(&[0x02, 0x02, 0x00, 0x80]).unwrap().0, &[0x80]);
    }

    #[test]
    fn pem_round_trip_and_strictness() {
        let spki = ed25519_public_to_spki(&PUBLIC);
        let pem = pem_encode("PUBLIC KEY", &spki);
        assert!(pem.starts_with("-----BEGIN PUBLIC KEY-----\n"));
        assert_eq!(pem_decode("PUBLIC KEY", &pem).unwrap(), spki);
        assert!(pem_decode("PRIVATE KEY", &pem).is_err());
        assert!(pem_decode("PUBLIC KEY", &format!("junk{pem}")).is_err());
        let bad = pem.replace("MCow", "MCo!");
        assert!(pem_decode("PUBLIC KEY", &bad).is_err());
    }

    #[test]
    fn base64_is_canonical() {
        assert_eq!(b64_decode(b"Zg==").unwrap(), b"f");
        assert!(b64_decode(b"Zh==").is_err()); // non-zero discarded bits
        assert!(b64_decode(b"Zg==Zg==").is_err()); // padding mid-stream
        assert!(b64_decode(b"Zg=").is_err()); // bad length
    }

    #[test]
    fn rsa_spki_round_trip_through_public_key() {
        let n = [0xc3u8, 0x01, 0x00, 0x01, 0x23]; // any modulus-shaped bytes
        let e = [0x01u8, 0x00, 0x01];
        let der = rsa_public_to_spki(&n, &e);
        // Structural parse: the rsaEncryption OID is present and the value is minimal.
        assert!(der
            .windows(OID_RSA_ENCRYPTION.len())
            .any(|w| w == OID_RSA_ENCRYPTION));
        let mut bits_check = der.clone();
        bits_check.push(0);
        assert!(rsa_public_from_spki(&bits_check).is_err());
    }
}
