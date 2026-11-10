//! JSON Web Keys (RFC 7517) for public keys: OKP/Ed25519 (RFC 8037) and EC
//! P-256 / P-384 (RFC 7518 §6.2).
//!
//! Output is the canonical form: members in lexicographic order, no whitespace,
//! base64url without padding. Parsing is strict. It accepts exactly the members
//! listed below, with string values and no escape sequences, and it rejects any
//! base64url value that does not re-encode to the same text. Private-key members
//! (`d`) are never accepted, so a JWK parsed here cannot carry a secret.

use crate::ecdsa::{EcdsaCurve, VerifyingKey as EcVerifyingKey, P256, P384};
use crate::ed25519;
use alloc::string::String;
use alloc::vec::Vec;
use tpt_crypto_core::{Error, Result};

const B64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// base64url without padding (RFC 4648 §5).
fn b64url_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 4).div_ceil(3));
    for chunk in data.chunks(3) {
        let b0 = chunk[0];
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let n = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        out.push(B64URL[(n >> 18) as usize & 63] as char);
        out.push(B64URL[(n >> 12) as usize & 63] as char);
        if chunk.len() > 1 {
            out.push(B64URL[(n >> 6) as usize & 63] as char);
        }
        if chunk.len() > 2 {
            out.push(B64URL[n as usize & 63] as char);
        }
    }
    out
}

fn b64url_value(c: u8) -> Option<u32> {
    B64URL.iter().position(|&x| x == c).map(|p| p as u32)
}

/// Decode base64url without padding. Rejects anything that does not re-encode
/// to the same text (bad length, non-zero trailing bits, foreign characters).
fn b64url_decode(text: &str) -> Result<Vec<u8>> {
    let bytes = text.as_bytes();
    if bytes.len() % 4 == 1 {
        return Err(Error::InvalidEncoding);
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let mut n: u32 = 0;
        for (i, &c) in chunk.iter().enumerate() {
            let v = b64url_value(c).ok_or(Error::InvalidEncoding)?;
            n |= v << (18 - 6 * i as u32);
        }
        out.push((n >> 16) as u8);
        if chunk.len() > 2 {
            out.push((n >> 8) as u8);
        }
        if chunk.len() > 3 {
            out.push(n as u8);
        }
    }
    if b64url_encode(&out) != text {
        return Err(Error::InvalidEncoding);
    }
    Ok(out)
}

/// Parse a flat JSON object whose members are all strings without escapes.
/// Returns `(name, value)` pairs; duplicate names are an error.
fn parse_flat_object(text: &str) -> Result<Vec<(&str, &str)>> {
    let s = text.trim();
    let inner = s
        .strip_prefix('{')
        .and_then(|r| r.strip_suffix('}'))
        .ok_or(Error::InvalidEncoding)?;
    let mut members: Vec<(&str, &str)> = Vec::new();
    if inner.trim().is_empty() {
        return Ok(members);
    }
    for part in inner.split(',') {
        let (k, v) = part.split_once(':').ok_or(Error::InvalidEncoding)?;
        let k = unquote(k.trim())?;
        let v = unquote(v.trim())?;
        if members.iter().any(|(name, _)| *name == k) {
            return Err(Error::InvalidEncoding);
        }
        members.push((k, v));
    }
    Ok(members)
}

fn unquote(s: &str) -> Result<&str> {
    let inner = s
        .strip_prefix('"')
        .and_then(|r| r.strip_suffix('"'))
        .ok_or(Error::InvalidEncoding)?;
    if inner.contains(['"', '\\']) {
        return Err(Error::InvalidEncoding);
    }
    Ok(inner)
}

/// Require the member set to be exactly `expected`.
fn members_exactly(members: &[(&str, &str)], expected: &[&str]) -> Result<()> {
    if members.len() != expected.len() {
        return Err(Error::InvalidEncoding);
    }
    for name in expected {
        if !members.iter().any(|(k, _)| k == name) {
            return Err(Error::InvalidEncoding);
        }
    }
    Ok(())
}

fn member<'a>(members: &[(&str, &'a str)], name: &str) -> Result<&'a str> {
    members
        .iter()
        .find(|(k, _)| *k == name)
        .map(|(_, v)| *v)
        .ok_or(Error::InvalidEncoding)
}

/// `{"crv":"Ed25519","kty":"OKP","x":"..."}` for an Ed25519 public key.
#[must_use]
pub fn ed25519_public_to_jwk(vk: &ed25519::VerifyingKey) -> String {
    let x = b64url_encode(&vk.to_bytes());
    let mut s = String::from("{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"");
    s.push_str(&x);
    s.push_str("\"}");
    s
}

/// Parse an Ed25519 public-key JWK (RFC 8037 §2).
///
/// # Errors
///
/// [`Error::InvalidEncoding`] for any member set other than `crv`, `kty`, `x`,
/// wrong values, or a malformed base64url `x`; [`Error::InvalidLength`] for a
/// wrong `x` length; the key-validation error for an invalid point.
pub fn ed25519_public_from_jwk(jwk: &str) -> Result<ed25519::VerifyingKey> {
    let members = parse_flat_object(jwk)?;
    members_exactly(&members, &["crv", "kty", "x"])?;
    if member(&members, "kty")? != "OKP" || member(&members, "crv")? != "Ed25519" {
        return Err(Error::InvalidEncoding);
    }
    let x = b64url_decode(member(&members, "x")?)?;
    let bytes: [u8; 32] = x.try_into().map_err(|_| Error::InvalidLength)?;
    ed25519::VerifyingKey::from_bytes(&bytes)
}

fn ec_to_jwk<C: EcdsaCurve>(crv: &str, vk: &EcVerifyingKey<C>) -> String {
    let sec1 = vk.to_sec1_uncompressed();
    let n = C::N_BYTES;
    let x = b64url_encode(&sec1[1..1 + n]);
    let y = b64url_encode(&sec1[1 + n..1 + 2 * n]);
    let mut s = String::from("{\"crv\":\"");
    s.push_str(crv);
    s.push_str("\",\"kty\":\"EC\",\"x\":\"");
    s.push_str(&x);
    s.push_str("\",\"y\":\"");
    s.push_str(&y);
    s.push_str("\"}");
    s
}

fn ec_from_jwk<C: EcdsaCurve>(crv: &str, jwk: &str) -> Result<EcVerifyingKey<C>> {
    let members = parse_flat_object(jwk)?;
    members_exactly(&members, &["crv", "kty", "x", "y"])?;
    if member(&members, "kty")? != "EC" || member(&members, "crv")? != crv {
        return Err(Error::InvalidEncoding);
    }
    let x = b64url_decode(member(&members, "x")?)?;
    let y = b64url_decode(member(&members, "y")?)?;
    let n = C::N_BYTES;
    if x.len() != n || y.len() != n {
        return Err(Error::InvalidLength);
    }
    let mut sec1 = Vec::with_capacity(1 + 2 * n);
    sec1.push(0x04);
    sec1.extend_from_slice(&x);
    sec1.extend_from_slice(&y);
    EcVerifyingKey::<C>::from_sec1(&sec1)
}

/// `{"crv":"P-256","kty":"EC","x":"...","y":"..."}`.
#[must_use]
pub fn p256_public_to_jwk(vk: &EcVerifyingKey<P256>) -> String {
    ec_to_jwk::<P256>("P-256", vk)
}

/// Parse a P-256 public-key JWK (RFC 7518 §6.2.1).
///
/// # Errors
///
/// As [`ed25519_public_from_jwk`], plus the point checks from `from_sec1`.
pub fn p256_public_from_jwk(jwk: &str) -> Result<EcVerifyingKey<P256>> {
    ec_from_jwk::<P256>("P-256", jwk)
}

/// `{"crv":"P-384","kty":"EC","x":"...","y":"..."}`.
#[must_use]
pub fn p384_public_to_jwk(vk: &EcVerifyingKey<P384>) -> String {
    ec_to_jwk::<P384>("P-384", vk)
}

/// Parse a P-384 public-key JWK (RFC 7518 §6.2.1).
///
/// # Errors
///
/// As [`p256_public_from_jwk`].
pub fn p384_public_from_jwk(jwk: &str) -> Result<EcVerifyingKey<P384>> {
    ec_from_jwk::<P384>("P-384", jwk)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// RFC 8037 Appendix A.1: the Ed25519 public key from RFC 8032 §7.1 test 1.
    const RFC8037_X: &str = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
    const RFC8032_PUB_HEX: &str =
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";

    /// RFC 7517 Appendix A.1: an EC P-256 public key.
    const RFC7517_X: &str = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4";
    const RFC7517_Y: &str = "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM";

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| alloc::format!("{x:02x}")).collect()
    }

    fn okp(x: &str) -> String {
        alloc::format!("{{\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{x}\"}}")
    }

    #[test]
    fn ed25519_matches_rfc8037_example() {
        let vk = ed25519_public_from_jwk(&okp(RFC8037_X)).unwrap();
        assert_eq!(hex(&vk.to_bytes()), RFC8032_PUB_HEX);
        assert_eq!(ed25519_public_to_jwk(&vk), okp(RFC8037_X));
    }

    #[test]
    fn p256_matches_rfc7517_example() {
        let jwk = alloc::format!(
            "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{RFC7517_X}\",\"y\":\"{RFC7517_Y}\"}}"
        );
        let vk = p256_public_from_jwk(&jwk).unwrap();
        assert_eq!(p256_public_to_jwk(&vk), jwk);
    }

    #[test]
    fn rejects_wrong_or_extra_members() {
        let extra = alloc::format!(
            "{{\"crv\":\"Ed25519\",\"d\":\"AAAA\",\"kty\":\"OKP\",\"x\":\"{RFC8037_X}\"}}"
        );
        assert!(ed25519_public_from_jwk(&extra).is_err());
        let wrong_kty =
            alloc::format!("{{\"crv\":\"Ed25519\",\"kty\":\"EC\",\"x\":\"{RFC8037_X}\"}}");
        assert!(ed25519_public_from_jwk(&wrong_kty).is_err());
        let dup = alloc::format!(
            "{{\"crv\":\"Ed25519\",\"crv\":\"Ed25519\",\"kty\":\"OKP\",\"x\":\"{RFC8037_X}\"}}"
        );
        assert!(ed25519_public_from_jwk(&dup).is_err());
    }

    #[test]
    fn rejects_non_canonical_base64url() {
        // Same length as the RFC value, but the final character carries
        // non-zero trailing bits, so it does not re-encode to itself.
        let mut x = RFC8037_X.as_bytes().to_vec();
        *x.last_mut().unwrap() = b'b';
        let x = String::from_utf8(x).unwrap();
        assert!(ed25519_public_from_jwk(&okp(&x)).is_err());
    }

    #[test]
    fn rejects_padding_escapes_and_bad_points() {
        assert!(ed25519_public_from_jwk(&okp(&alloc::format!("{RFC8037_X}="))).is_err());
        assert!(ed25519_public_from_jwk(&okp(&alloc::format!("{RFC8037_X}\\n"))).is_err());
        // An all-zero y-coordinate is not on P-256.
        let zero_y = alloc::format!(
            "{{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"{RFC7517_X}\",\"y\":\"{}\"}}",
            "A".repeat(43)
        );
        assert!(p256_public_from_jwk(&zero_y).is_err());
    }
}
