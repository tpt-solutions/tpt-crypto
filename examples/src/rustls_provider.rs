//! A TLS 1.3 [`rustls::crypto::CryptoProvider`] built entirely from
//! `tpt-crypto` primitives — no `ring`, no `aws-lc-rs`.
//!
//! Wires the substrate into rustls end to end:
//!
//! * **AEAD** — [`tpt::aead::Aes128Gcm`] and [`tpt::aead::ChaCha20Poly1305`]
//!   as `Tls13AeadAlgorithm`s (record sealing/opening per RFC 8446 §5.2).
//! * **HKDF** — the substrate's HMAC-SHA-256 behind rustls'
//!   `HkdfUsingHmac` for the TLS 1.3 key schedule.
//! * **Key exchange** — the substrate's constant-time X25519 (RFC 7748).
//! * **Signatures** — the substrate's Ed25519 (RFC 8032) as the server's
//!   `SigningKey`, with a hand-built self-signed DER certificate.
//!
//! The test at the bottom performs a full in-memory TLS 1.3 handshake
//! (client ⇄ server over duplex buffers) and exchanges application data
//! through each negotiated cipher suite.
//!
//! Demo shortcuts (this is an example, not a production provider): the
//! client accepts any server certificate (`AcceptAny` verifier) and the
//! `KeyProvider` ignores the loaded DER and hands out a fixed demo
//! Ed25519 key.

use std::io::{Read as _, Write as _};
use std::sync::Arc;

#[cfg(test)]
use rustls::crypto::cipher::OutboundChunks;
use rustls::crypto::cipher::{
    make_tls13_aad, AeadKey, InboundOpaqueMessage, Iv, MessageDecrypter, MessageEncrypter,
    Nonce as RustlsNonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls13AeadAlgorithm, UnsupportedOperationError,
};
use rustls::crypto::{
    CipherSuiteCommon, CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom, SharedSecret,
    SupportedKxGroup,
};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, UnixTime};
use rustls::sign::Signer;
use rustls::{
    CipherSuite, NamedGroup, ProtocolVersion, SignatureAlgorithm, SignatureScheme,
    SupportedCipherSuite, Tls13CipherSuite,
};
use tpt_crypto::aead::{Aead, Aes128Gcm, ChaCha20Poly1305, Nonce, Tag};
use tpt_crypto::curve::X25519;
use tpt_crypto::hash::{mac::Hmac, sha2::Sha256, Hasher};
use tpt_crypto::sig::ed25519;

// ── AEAD adapter ─────────────────────────────────────────────────────────────

/// Which substrate AEAD a TLS 1.3 cipher suite uses.
#[derive(Clone, Copy, Debug)]
enum TptAead {
    Aes128Gcm,
    ChaCha20Poly1305,
}

impl TptAead {
    fn new_cipher(&self, key: &[u8]) -> Box<dyn Aead<12, 16>> {
        match self {
            TptAead::Aes128Gcm => Box::new(Aes128Gcm::new(&key[..16]).expect("16-byte key")),
            TptAead::ChaCha20Poly1305 => {
                Box::new(ChaCha20Poly1305::new(key.try_into().expect("32-byte key")))
            }
        }
    }

    fn tag_len(&self) -> usize {
        16
    }
}

/// Per-connection seal key material.
struct TptMessageEncrypter {
    aead: TptAead,
    key: Vec<u8>,
    iv: Iv,
}

impl rustls::crypto::cipher::MessageEncrypter for TptMessageEncrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, rustls::Error> {
        let total_len = msg.payload.len() + 1 + self.aead.tag_len();
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());

        let cipher = self.aead.new_cipher(&self.key);
        let iv = RustlsNonce::new(&self.iv, seq);
        let tag = cipher.encrypt_in_place_detached(
            &Nonce::new(iv.0),
            &make_tls13_aad(total_len),
            payload.as_mut(),
        );
        payload.extend_from_slice(tag.as_slice());

        Ok(OutboundOpaqueMessage::new(
            rustls::ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            payload,
        ))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + self.aead.tag_len()
    }
}

/// Per-connection open key material.
struct TptMessageDecrypter {
    aead: TptAead,
    key: Vec<u8>,
    iv: Iv,
}

impl rustls::crypto::cipher::MessageDecrypter for TptMessageDecrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<rustls::crypto::cipher::InboundPlainMessage<'a>, rustls::Error> {
        let payload = &mut msg.payload;
        if payload.len() < self.aead.tag_len() {
            return Err(rustls::Error::DecryptError);
        }

        let cipher = self.aead.new_cipher(&self.key);
        let iv = RustlsNonce::new(&self.iv, seq);
        let split = payload.len() - self.aead.tag_len();
        let (ct, tag) = payload.split_at_mut(split);
        let tag = Tag::new(tag.try_into().expect("16-byte tag"));
        cipher
            .decrypt_in_place_detached(&Nonce::new(iv.0), &make_tls13_aad(split + 16), ct, &tag)
            .map_err(|_| rustls::Error::DecryptError)?;

        // Drop the tag region so the TLS 1.3 unpadding scan sees only the
        // decrypted inner plaintext (rustls' own decrypters truncate here).
        msg.payload.truncate(split);

        msg.into_tls13_unpadded_message()
    }
}

impl Tls13AeadAlgorithm for TptAead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(TptMessageEncrypter {
            aead: *self,
            key: key.as_ref().to_vec(),
            iv,
        })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(TptMessageDecrypter {
            aead: *self,
            key: key.as_ref().to_vec(),
            iv,
        })
    }

    fn key_len(&self) -> usize {
        match self {
            TptAead::Aes128Gcm => 16,
            TptAead::ChaCha20Poly1305 => 32,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<rustls::ConnectionTrafficSecrets, UnsupportedOperationError> {
        match self {
            TptAead::Aes128Gcm => Ok(rustls::ConnectionTrafficSecrets::Aes128Gcm { key, iv }),
            TptAead::ChaCha20Poly1305 => {
                Ok(rustls::ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv })
            }
        }
    }
}

// ── SHA-256 hash provider (TLS 1.3 transcript) ───────────────────────────────

#[derive(Debug)]
struct TptSha256;

#[derive(Clone)]
struct TptSha256Context(Sha256);

impl rustls::crypto::hash::Hash for TptSha256 {
    fn start(&self) -> Box<dyn rustls::crypto::hash::Context> {
        Box::new(TptSha256Context(Sha256::new()))
    }

    fn hash(&self, data: &[u8]) -> rustls::crypto::hash::Output {
        let mut h = Sha256::new();
        h.update(data);
        rustls::crypto::hash::Output::new(&h.finalize())
    }

    fn output_len(&self) -> usize {
        32
    }

    fn algorithm(&self) -> rustls::crypto::hash::HashAlgorithm {
        rustls::crypto::hash::HashAlgorithm::SHA256
    }
}

impl rustls::crypto::hash::Context for TptSha256Context {
    fn fork_finish(&self) -> rustls::crypto::hash::Output {
        let h = self.0.clone();
        rustls::crypto::hash::Output::new(&h.finalize())
    }

    fn fork(&self) -> Box<dyn rustls::crypto::hash::Context> {
        Box::new(self.clone())
    }

    fn finish(self: Box<Self>) -> rustls::crypto::hash::Output {
        rustls::crypto::hash::Output::new(&self.0.finalize())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

// ── HMAC-SHA-256 adapter (TLS 1.3 key schedule) ──────────────────────────────

struct TptHmacSha256;

#[derive(Clone)]
struct TptHmacKey(Hmac<Sha256, 64, 32>);

impl rustls::crypto::hmac::Hmac for TptHmacSha256 {
    fn with_key(&self, key: &[u8]) -> Box<dyn rustls::crypto::hmac::Key> {
        Box::new(TptHmacKey(Hmac::<Sha256, 64, 32>::new(key)))
    }

    fn hash_output_len(&self) -> usize {
        32
    }
}

impl rustls::crypto::hmac::Key for TptHmacKey {
    fn sign_concat(
        &self,
        first: &[u8],
        middle: &[&[u8]],
        last: &[u8],
    ) -> rustls::crypto::hmac::Tag {
        let mut h = self.0.clone();
        h.update(first);
        for part in middle {
            h.update(part);
        }
        h.update(last);
        rustls::crypto::hmac::Tag::new(&h.finalize())
    }

    fn tag_len(&self) -> usize {
        32
    }
}

// ── X25519 key exchange ──────────────────────────────────────────────────────

#[derive(Debug)]
struct TptX25519;

#[derive(Debug)]
struct TptX25519Active {
    secret: [u8; 32],
    pub_key: [u8; 32],
}

impl SupportedKxGroup for TptX25519 {
    fn start(&self) -> Result<Box<dyn rustls::crypto::ActiveKeyExchange>, rustls::Error> {
        let mut secret = [0u8; 32];
        TptRandom
            .fill(&mut secret)
            .map_err(|_| rustls::Error::General("entropy failure".into()))?;
        let pub_key = X25519::diffie_hellman(&secret, &X25519::BASE);
        Ok(Box::new(TptX25519Active { secret, pub_key }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

impl rustls::crypto::ActiveKeyExchange for TptX25519Active {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, rustls::Error> {
        let peer: [u8; 32] = peer_pub_key
            .try_into()
            .map_err(|_| rustls::Error::PeerMisbehaved(rustls::PeerMisbehaved::InvalidKeyShare))?;
        let shared = X25519::diffie_hellman(&self.secret, &peer);
        // Reject the all-zero shared secret (small-order peer input).
        if shared == [0u8; 32] {
            return Err(rustls::Error::PeerMisbehaved(
                rustls::PeerMisbehaved::InvalidKeyShare,
            ));
        }
        Ok(SharedSecret::from(&shared[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.pub_key
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

// ── Randomness ───────────────────────────────────────────────────────────────

#[derive(Debug)]
struct TptRandom;

impl SecureRandom for TptRandom {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        getrandom::getrandom(buf).map_err(|_| GetRandomFailed)
    }
}

// ── Ed25519 signing key adapter ──────────────────────────────────────────────

/// Demo key pair.
#[derive(Debug)]
struct TptEd25519Key;

struct TptEd25519Signer;

impl std::fmt::Debug for TptEd25519Signer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("TptEd25519Signer")
    }
}

impl Signer for TptEd25519Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
        Ok(ed25519::SigningKey::from_seed(demo_seed())
            .sign(message)
            .to_bytes()
            .to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ED25519
    }
}

impl rustls::sign::SigningKey for TptEd25519Key {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        offered
            .contains(&SignatureScheme::ED25519)
            .then(|| Box::new(TptEd25519Signer) as Box<dyn Signer>)
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ED25519
    }
}

fn demo_seed() -> [u8; 32] {
    // Fixed demo key seed — an example, not a production key.
    let mut seed = [0u8; 32];
    for (i, b) in seed.iter_mut().enumerate() {
        *b = (i as u8) ^ 0x5A;
    }
    seed
}

#[derive(Debug)]
struct TptKeyProvider;

impl KeyProvider for TptKeyProvider {
    fn load_private_key(
        &self,
        _key_der: PrivateKeyDer<'static>,
    ) -> Result<Arc<dyn rustls::sign::SigningKey>, rustls::Error> {
        Ok(Arc::new(TptEd25519Key))
    }
}

// ── Minimal self-signed Ed25519 certificate (hand-built DER) ─────────────────

/// DER helper: length octets (short form suffices for this certificate).
fn der_len(n: usize) -> Vec<u8> {
    if n < 0x80 {
        vec![n as u8]
    } else if n < 0x100 {
        vec![0x81, n as u8]
    } else {
        vec![0x82, (n >> 8) as u8, n as u8]
    }
}

fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend_from_slice(&der_len(body.len()));
    out.extend_from_slice(body);
    out
}

const OID_ED25519: &[u8] = &[0x2b, 0x65, 0x70]; // 1.3.101.112
const OID_CN: &[u8] = &[0x55, 0x04, 0x03]; // 2.5.4.3

/// Build a minimal self-signed Ed25519 certificate for `spki_pub`.
fn self_signed_cert(spki_pub: &[u8; 32]) -> Vec<u8> {
    let sig_alg = tlv(0x30, OID_ED25519);
    let issuer = tlv(
        0x30,
        &tlv(
            0x31,
            &tlv(0x30, &{
                let mut seq = tlv(0x06, OID_CN);
                seq.extend(&tlv(0x0c, b"tpt-demo"));
                tlv(0x30, &seq)
            }),
        ),
    );
    let validity = tlv(0x30, &{
        let mut v = tlv(0x17, b"250101000000Z");
        v.extend(&tlv(0x17, b"351231235959Z"));
        v
    });
    let spki = tlv(0x30, &{
        let mut s = tlv(0x30, OID_ED25519);
        let mut bit = vec![0u8]; // zero unused bits
        bit.extend_from_slice(spki_pub);
        s.extend(&tlv(0x03, &bit));
        s
    });

    let mut tbs = tlv(0xa0, &[0x02, 0x01, 0x03]); // [0] EXPLICIT version v3
    let serial = {
        let s = vec![0x42u8, 0x74, 0x70, 0x74, 0x01, 0x00, 0x00, 0x01];
        s
    };
    tbs.extend(&tlv(0x02, &serial));
    tbs.extend(&sig_alg);
    tbs.extend(&issuer);
    tbs.extend(&validity);
    tbs.extend(&issuer); // subject == issuer
    tbs.extend(&spki);

    let signing = ed25519::SigningKey::from_seed(demo_seed());
    let sig = signing.sign(&tbs);

    let mut cert = tlv(0x30, &tbs);
    let mut bit = vec![0u8];
    bit.extend_from_slice(&sig.to_bytes());
    cert.extend(&tlv(0x03, &bit));
    cert
}

// ── Client verifier (accept-any — demo only!) ────────────────────────────────

#[derive(Debug)]
struct AcceptAny;

impl rustls::client::danger::ServerCertVerifier for AcceptAny {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        // DEMO ONLY: no chain validation.
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Err(rustls::Error::General("TLS 1.2 not supported".into()))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        // Verify the Ed25519 CertificateVerify against the demo key carried
        // in the certificate's SPKI.
        let verifying = ed25519_verifying_key_from_cert(cert)?;
        let scheme_ok = dss.scheme == SignatureScheme::ED25519;
        if !scheme_ok {
            return Err(rustls::Error::General("expected Ed25519".into()));
        }
        let sig: [u8; 64] = dss
            .signature()
            .as_ref()
            .try_into()
            .map_err(|_| rustls::Error::General("bad signature length".into()))?;
        let vk = ed25519::VerifyingKey::from_bytes(&verifying)
            .map_err(|_| rustls::Error::General("bad demo key".into()))?;
        vk.verify(message, &ed25519::Signature::from_bytes(sig))
            .map_err(|_| rustls::Error::General("Ed25519 verify failed".into()))?;
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

/// Extract the 32-byte Ed25519 public key from the hand-built certificate.
fn ed25519_verifying_key_from_cert(cert: &CertificateDer<'_>) -> Result<[u8; 32], rustls::Error> {
    let der = cert.as_ref();
    // The certificate ends with: BIT STRING (0x03 0x42 0x00 || 64-byte sig).
    if der.len() < 2 + 1 + 64 {
        return Err(rustls::Error::General("cert too short".into()));
    }
    let sig_start = der.len() - 64;
    // BIT STRING TLV: 0x03 0x41 0x00 (65 content bytes = 0x00 + 64-byte sig).
    if der[sig_start - 3] != 0x03 || der[sig_start - 2] != 0x41 || der[sig_start - 1] != 0x00 {
        return Err(rustls::Error::General("unexpected cert tail".into()));
    }
    // The SPKI's 32-byte public key directly precedes the signature BIT
    // STRING TLV in the outer SEQUENCE.
    let pk = &der[sig_start - 3 - 32..sig_start - 3];
    Ok(pk.try_into().expect("32-byte key"))
}

// ── Provider assembly ────────────────────────────────────────────────────────

static HMAC_SHA256: TptHmacSha256 = TptHmacSha256;
static AEAD_AES128GCM: TptAead = TptAead::Aes128Gcm;
static AEAD_CHACHA: TptAead = TptAead::ChaCha20Poly1305;
static X25519_GROUP: TptX25519 = TptX25519;
static RANDOM: TptRandom = TptRandom;
static KEY_PROVIDER: TptKeyProvider = TptKeyProvider;

static SHA256_PROVIDER: TptSha256 = TptSha256;

static SUITE_AES128GCM: SupportedCipherSuite = SupportedCipherSuite::Tls13(&Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        hash_provider: &SHA256_PROVIDER,
        confidentiality_limit: 1 << 24,
    },
    hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(&HMAC_SHA256),
    aead_alg: &AEAD_AES128GCM,
    quic: None,
});

static SUITE_CHACHA: SupportedCipherSuite = SupportedCipherSuite::Tls13(&Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
        hash_provider: &SHA256_PROVIDER,
        confidentiality_limit: 1 << 24,
    },
    hkdf_provider: &rustls::crypto::tls13::HkdfUsingHmac(&HMAC_SHA256),
    aead_alg: &AEAD_CHACHA,
    quic: None,
});

/// Build the `tpt-crypto` TLS 1.3 provider (AES-128-GCM + ChaCha20-Poly1305
/// over X25519/Ed25519, SHA-256 key schedule).
#[must_use]
pub fn provider() -> CryptoProvider {
    let ed25519 = rustls::crypto::WebPkiSupportedAlgorithms {
        all: &[],
        mapping: &[],
    };
    CryptoProvider {
        cipher_suites: vec![SUITE_AES128GCM, SUITE_CHACHA],
        kx_groups: vec![&X25519_GROUP],
        signature_verification_algorithms: ed25519,
        secure_random: &RANDOM,
        key_provider: &KEY_PROVIDER,
    }
}

/// The demo server certificate (self-signed Ed25519, hand-built DER).
#[must_use]
pub fn demo_certificate() -> CertificateDer<'static> {
    let seed = demo_seed();
    let signing = ed25519::SigningKey::from_seed(seed);
    let pk = signing.verifying_key().to_bytes();
    CertificateDer::from(self_signed_cert(&pk))
}

// ── In-memory handshake ──────────────────────────────────────────────────────

fn io_err(e: std::io::Error) -> rustls::Error {
    rustls::Error::General(format!("io: {e}"))
}

fn pump(
    client: &mut rustls::ClientConnection,
    server: &mut rustls::ServerConnection,
) -> Result<(), rustls::Error> {
    let mut c2s = Vec::new();
    let mut s2c = Vec::new();
    let mut guard = 0;
    while (client.is_handshaking() || server.is_handshaking()) && guard < 100 {
        guard += 1;
        c2s.clear();
        client
            .write_tls(&mut c2s)
            .map_err(|e| rustls::Error::General(format!("write_tls: {e}")))?;
        // Drain ALL records: read_tls may consume fewer bytes than offered.
        let mut input = &c2s[..];
        while !input.is_empty() {
            match server.read_tls(&mut input) {
                Ok(n) => {
                    if std::env::var("TPT_TLS_DEBUG").is_ok() {
                        eprintln!(
                            "c2s rec {n}B first={:02x} len={}",
                            c2s[0],
                            u16::from_be_bytes([c2s[3], c2s[4]])
                        );
                    }
                    if let Err(e) = server.process_new_packets() {
                        return Err(rustls::Error::General(format!("server process: {e}")));
                    }
                }
                Err(e) => {
                    return Err(rustls::Error::General(format!(
                        "server read_tls: {e}; record head {:02x} {:02x} {:02x} {:02x} {:02x}",
                        input[0], input[1], input[2], input[3], input[4]
                    )));
                }
            }
        }
        s2c.clear();
        server
            .write_tls(&mut s2c)
            .map_err(|e| rustls::Error::General(format!("write_tls: {e}")))?;
        let mut input = &s2c[..];
        while !input.is_empty() {
            match client.read_tls(&mut input) {
                Ok(n) => {
                    if std::env::var("TPT_TLS_DEBUG").is_ok() {
                        eprintln!(
                            "s2c rec {n}B first={:02x} len={}",
                            s2c[0],
                            u16::from_be_bytes([s2c[3], s2c[4]])
                        );
                    }
                    if let Err(e) = client.process_new_packets() {
                        return Err(rustls::Error::General(format!("client process: {e}")));
                    }
                }
                Err(e) => {
                    return Err(rustls::Error::General(format!(
                        "client read_tls: {e}; record head {:02x} {:02x} {:02x} {:02x} {:02x}",
                        input[0], input[1], input[2], input[3], input[4]
                    )));
                }
            }
        }
    }
    Ok(())
}

/// Run one in-memory TLS 1.3 handshake restricted to `suite` and exchange a
/// bidirectional application-data round trip. Returns the negotiated suite.
pub fn demo_handshake(suite: SupportedCipherSuite) -> Result<CipherSuite, rustls::Error> {
    let provider = || {
        let mut p = provider();
        p.cipher_suites = vec![suite];
        Arc::new(p)
    };

    // Server side.
    let cert = demo_certificate();
    let config = rustls::ServerConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("TLS 1.3")
        .with_no_client_auth()
        .with_single_cert(
            vec![cert],
            PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(vec![
                0x30, 0x00,
            ])),
        )
        .expect("server config");
    let mut server = rustls::ServerConnection::new(Arc::new(config))?;

    // Client side: accept-any verifier (demo), host "tpt-demo".
    let verifier = Arc::new(AcceptAny);
    let mut client_config = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()
        .expect("TLS 1.3")
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    client_config.resumption = rustls::client::Resumption::default();
    let client_config = Arc::new(client_config);
    let mut client = rustls::ClientConnection::new(
        client_config,
        rustls::pki_types::ServerName::try_from("tpt-demo".to_string()).expect("valid name"),
    )?;

    pump(&mut client, &mut server)?;
    let negotiated = client
        .negotiated_cipher_suite()
        .expect("negotiated")
        .suite();

    // Bidirectional application data round trip.
    client
        .writer()
        .write(b"hello from tpt-client")
        .map_err(io_err)?;
    pump_data(&mut client, &mut server)?;
    let mut buf = [0u8; 64];
    let n = server.reader().read(&mut buf).map_err(io_err)?;
    assert_eq!(&buf[..n], b"hello from tpt-client");

    server
        .writer()
        .write(b"hello from tpt-server")
        .map_err(io_err)?;
    pump_data(&mut server, &mut client)?;
    let n = client.reader().read(&mut buf).map_err(io_err)?;
    assert_eq!(&buf[..n], b"hello from tpt-server");

    Ok(negotiated)
}

fn pump_data<T1, T2>(
    src: &mut rustls::ConnectionCommon<T1>,
    dst: &mut rustls::ConnectionCommon<T2>,
) -> Result<(), rustls::Error> {
    let mut buf = Vec::new();
    let mut guard = 0;
    while src.wants_write() && guard < 100 {
        guard += 1;
        buf.clear();
        src.write_tls(&mut buf)
            .map_err(|e| rustls::Error::General(format!("write_tls: {e}")))?;
        let mut input = &buf[..];
        while !input.is_empty() {
            dst.read_tls(&mut input)
                .map_err(|e| rustls::Error::General(format!("read_tls: {e}")))?;
            dst.process_new_packets()?;
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aead_adapter_round_trip() {
        let key = AeadKey::from([0x42u8; 32]);
        let iv = Iv::from([0x11u8; 12]);
        let mut enc = TptAead::Aes128Gcm.encrypter(key, iv);
        let chunk = &b"payload bytes"[..];
        let chunks = [chunk];
        let msg = OutboundPlainMessage {
            typ: rustls::ContentType::Handshake,
            version: ProtocolVersion::TLSv1_2,
            payload: OutboundChunks::new(&chunks),
        };
        let sealed = enc.encrypt(msg, 0).expect("seal");
        let mut encoded = sealed.encode();
        println!("sealed {} bytes", encoded.len());

        // Skip the 5-byte record header: `new()` takes only the payload.
        let inbound = InboundOpaqueMessage::new(
            rustls::ContentType::ApplicationData,
            ProtocolVersion::TLSv1_2,
            &mut encoded[5..],
        );
        let mut dec =
            TptAead::Aes128Gcm.decrypter(AeadKey::from([0x42u8; 32]), Iv::from([0x11u8; 12]));
        let plain = dec.decrypt(inbound, 0).expect("open");
        assert_eq!(
            plain
                .payload
                .bytes()
                .collect::<Result<Vec<u8>, _>>()
                .expect("readable"),
            b"payload bytes".to_vec()
        );
        assert_eq!(plain.typ, rustls::ContentType::Handshake);
    }

    #[test]
    fn tls13_handshake_over_tpt_aes128gcm() {
        let suite = demo_handshake(SUITE_AES128GCM).expect("handshake");
        assert_eq!(suite, CipherSuite::TLS13_AES_128_GCM_SHA256);
    }

    #[test]
    fn tls13_handshake_over_tpt_chacha20poly1305() {
        let suite = demo_handshake(SUITE_CHACHA).expect("handshake");
        assert_eq!(suite, CipherSuite::TLS13_CHACHA20_POLY1305_SHA256);
    }
}
