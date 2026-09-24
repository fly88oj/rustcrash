//! Minimal TLS 1.3 client (RFC 8446), hand-rolled.
//!
//! Why not rustls: REALITY's whole authentication lives *inside* the
//! ClientHello (the session id is an AEAD-sealed auth token), and uTLS
//! fingerprinting needs byte-exact extension order. rustls will not let a
//! caller write the hello. So the hello is emitted by
//! [`super::profiles`] and this module drives the rest of the handshake and
//! the record layer.
//!
//! Scope (deliberate):
//!
//! * TLS 1.3 only (`supported_versions` = 0x0304; a 1.2 answer is rejected).
//! * Key exchange X25519 only (curve25519-dalek, clamped scalar).
//! * Cipher suites `TLS_AES_128_GCM_SHA256`, `TLS_AES_256_GCM_SHA384` and
//!   `TLS_CHACHA20_POLY1305_SHA256`. The suite's hash is a *suite* property
//!   and drives the whole key schedule, so `0x1302` runs HKDF-SHA384 with
//!   48-byte secrets (`HashKind` below); `0x1301`/`0x1303` stay HKDF-SHA256.
//!   REALITY needs this: its ServerHello is the camouflage site's own, so the
//!   suite — in practice often `0x1302` — is whatever the `dest` picked.
//! * CertificateVerify: Ed25519, ECDSA P-256/P-384, RSA-PSS (ring). The
//!   scheme is *not* checked against our advertised list — Xray's REALITY
//!   server always signs with Ed25519 even though real Chrome never offers
//!   it, so the reference client cannot be stricter than this either.
//! * No PSK/resumption/0-RTT/client auth/ECH/certificate compression.
//!   `NewSessionTicket` is ignored, `KeyUpdate` is honoured.
//!
//! The key schedule and record layer are pinned against the RFC 8448
//! handshake trace and against a real rustls server (see the tests).

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use hkdf::Hkdf;
use rand::RngCore;
use ring::signature;
use sha2::{Digest, Sha256, Sha384};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::error::{Error, Result};
use crate::proto::aead::{Aead, AeadKind};
use crate::stream::BoxProxyStream;

/// `supported_versions` codepoint for TLS 1.3.
pub const VERSION_TLS13: u16 = 0x0304;
const VERSION_TLS12: u16 = 0x0303;

const RECORD_CCS: u8 = 20;
const RECORD_ALERT: u8 = 21;
const RECORD_HANDSHAKE: u8 = 22;
const RECORD_APP: u8 = 23;

const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const HS_NEW_SESSION_TICKET: u8 = 4;
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_COMPRESSED_CERTIFICATE: u8 = 25;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;
const HS_KEY_UPDATE: u8 = 24;

const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_PRE_SHARED_KEY: u16 = 0x0029;
const GROUP_X25519: u16 = 0x001d;

/// Maximum TLSInnerPlaintext length (RFC 8446 §5.2).
const MAX_PLAINTEXT: usize = 16384;
/// Maximum TLSCiphertext length: plaintext + inner content type + AEAD tag.
const MAX_CIPHERTEXT: usize = MAX_PLAINTEXT + 1 + 16;
/// `KeyUpdate` messages we will process before giving up (RFC 8446 §4.6.3).
const MAX_KEY_UPDATES: u8 = 8;

/// RFC 8446 §4.4.3 context string for the server's CertificateVerify.
const SERVER_SIGNATURE_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";

/// The TLS 1.3 cipher suites this stack implements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    /// 0x1301 (HKDF-SHA256).
    Aes128GcmSha256,
    /// 0x1302 (HKDF-SHA384).
    Aes256GcmSha384,
    /// 0x1303 (HKDF-SHA256).
    Chacha20Poly1305Sha256,
}

impl CipherSuite {
    /// Wire codepoint.
    pub fn id(self) -> u16 {
        match self {
            CipherSuite::Aes128GcmSha256 => 0x1301,
            CipherSuite::Aes256GcmSha384 => 0x1302,
            CipherSuite::Chacha20Poly1305Sha256 => 0x1303,
        }
    }

    /// Map a `cipher_suite` codepoint, or `None` when it is one we do not do.
    pub fn from_id(id: u16) -> Option<Self> {
        match id {
            0x1301 => Some(CipherSuite::Aes128GcmSha256),
            0x1302 => Some(CipherSuite::Aes256GcmSha384),
            0x1303 => Some(CipherSuite::Chacha20Poly1305Sha256),
            _ => None,
        }
    }

    /// Key length of the AEAD.
    pub fn key_len(self) -> usize {
        match self {
            CipherSuite::Aes128GcmSha256 => 16,
            CipherSuite::Aes256GcmSha384 | CipherSuite::Chacha20Poly1305Sha256 => 32,
        }
    }

    fn aead_kind(self) -> AeadKind {
        match self {
            CipherSuite::Aes128GcmSha256 => AeadKind::Aes128Gcm,
            CipherSuite::Aes256GcmSha384 => AeadKind::Aes256Gcm,
            CipherSuite::Chacha20Poly1305Sha256 => AeadKind::Chacha20Poly1305,
        }
    }

    /// Hash of this suite's key schedule (RFC 8446 §7.1).
    fn hash(self) -> HashKind {
        match self {
            CipherSuite::Aes128GcmSha256 | CipherSuite::Chacha20Poly1305Sha256 => HashKind::Sha256,
            CipherSuite::Aes256GcmSha384 => HashKind::Sha384,
        }
    }
}

// --- minimal DER reader (certificates) ---------------------------------

/// Just enough DER to pull a certificate's public key and its outer
/// signature value out. Used for the CertificateVerify key and for REALITY's
/// temp-auth check (which compares the signature field itself).
pub(crate) mod der {
    use crate::error::{Error, Result};

    /// The public key of a server certificate, in the shapes we can verify.
    #[derive(Debug, Clone, PartialEq, Eq)]
    pub(crate) enum PublicKey {
        Ed25519([u8; 32]),
        EcdsaP256(Vec<u8>),
        EcdsaP384(Vec<u8>),
        Rsa { n: Vec<u8>, e: Vec<u8> },
    }

    /// `(tag, content offset, content length)` of one TLV.
    fn tlv(data: &[u8], off: usize) -> Result<(u8, usize, usize)> {
        if off + 2 > data.len() {
            return Err(Error::crypto("der: truncated TLV"));
        }
        let tag = data[off];
        let first = data[off + 1] as usize;
        let (len, hdr) = if first < 0x80 {
            (first, 2usize)
        } else {
            let n = first & 0x7f;
            if n == 0 || n > 4 || off + 2 + n > data.len() {
                return Err(Error::crypto("der: unsupported length form"));
            }
            let mut len = 0usize;
            for i in 0..n {
                len = (len << 8) | data[off + 2 + i] as usize;
            }
            (len, 2 + n)
        };
        let start = off + hdr;
        if start + len > data.len() {
            return Err(Error::crypto("der: TLV runs past the buffer"));
        }
        Ok((tag, start, len))
    }

    fn expect(data: &[u8], off: usize, tag: u8, what: &str) -> Result<(usize, usize)> {
        let (t, start, len) = tlv(data, off)?;
        if t != tag {
            return Err(Error::crypto(format!(
                "der: expected {what} tag {tag:#04x}, got {t:#04x}"
            )));
        }
        Ok((start, len))
    }

    /// Byte range of the certificate's outer `signatureValue` BIT STRING
    /// content (after the unused-bits octet), i.e. the raw signature.
    pub(crate) fn signature_range(cert: &[u8]) -> Result<(usize, usize)> {
        let (body, body_len) = expect(cert, 0, 0x30, "Certificate")?;
        let (tbs_start, tbs_len) = expect(cert, body, 0x30, "tbsCertificate")?;
        let after_tbs = tbs_start + tbs_len;
        let (alg_start, alg_len) = expect(cert, after_tbs, 0x30, "signatureAlgorithm")?;
        let sig_off = alg_start + alg_len;
        let (sig_start, sig_len) = expect(cert, sig_off, 0x03, "signatureValue BIT STRING")?;
        let _ = body_len;
        if sig_len == 0 || cert[sig_start] != 0x00 {
            return Err(Error::crypto("der: signature BIT STRING has unused bits"));
        }
        Ok((sig_start + 1, sig_len - 1))
    }

    /// The certificate's outer signature value (WebPki/Go `Certificate.Signature`).
    pub(crate) fn signature(cert: &[u8]) -> Result<Vec<u8>> {
        let (start, len) = signature_range(cert)?;
        Ok(cert[start..start + len].to_vec())
    }

    /// SubjectPublicKeyInfo of the certificate, decoded to a usable key.
    pub(crate) fn public_key(cert: &[u8]) -> Result<PublicKey> {
        let (body, _) = expect(cert, 0, 0x30, "Certificate")?;
        let (tbs, tbs_len) = expect(cert, body, 0x30, "tbsCertificate")?;
        // TBSCertificate: [0] version?, serialNumber, signature,
        // issuer, validity, subject, subjectPublicKeyInfo, ...
        let mut off = tbs;
        let end = tbs + tbs_len;
        if off < end && cert[off] == 0xa0 {
            let (_, len) = expect(cert, off, 0xa0, "version")?;
            off += 2 + len;
        }
        // serialNumber (INTEGER), then signature, issuer, validity, subject.
        let (start, len) = expect(cert, off, 0x02, "serialNumber")?;
        off = start + len;
        for _ in 0..4 {
            let (start, len) = expect(cert, off, 0x30, "tbs field")?;
            off = start + len;
        }
        let (spki, _) = expect(cert, off, 0x30, "subjectPublicKeyInfo")?;
        let (alg_start, alg_len) = expect(cert, spki, 0x30, "spki.algorithm")?;
        let alg = &cert[alg_start..alg_start + alg_len];
        let key_off = spki + 2 + alg_len;
        let (key_start, key_len) = expect(cert, key_off, 0x03, "spki.subjectPublicKey")?;
        if key_len == 0 || cert[key_start] != 0x00 {
            return Err(Error::crypto("der: SPKI BIT STRING has unused bits"));
        }
        let key = &cert[key_start + 1..key_start + key_len];

        const OID_ED25519: &[u8] = &[0x06, 0x03, 0x2b, 0x65, 0x70];
        const OID_EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
        const OID_P256: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
        const OID_P384: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
        const OID_RSA: &[u8] = &[0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01];

        if alg.starts_with(OID_ED25519) {
            let k: [u8; 32] = key
                .try_into()
                .map_err(|_| Error::crypto("der: Ed25519 key is not 32 bytes"))?;
            return Ok(PublicKey::Ed25519(k));
        }
        if alg.starts_with(OID_EC_PUBLIC_KEY) {
            if alg.len() >= OID_EC_PUBLIC_KEY.len() + OID_P256.len()
                && alg[OID_EC_PUBLIC_KEY.len()..].starts_with(OID_P256)
            {
                return Ok(PublicKey::EcdsaP256(key.to_vec()));
            }
            if alg[OID_EC_PUBLIC_KEY.len()..].starts_with(OID_P384) {
                return Ok(PublicKey::EcdsaP384(key.to_vec()));
            }
            return Err(Error::crypto("der: unsupported EC curve"));
        }
        if alg.starts_with(OID_RSA) {
            // BIT STRING wraps SEQUENCE { INTEGER n, INTEGER e }.
            let (inner, _) = expect(key, 0, 0x30, "RSAPublicKey")?;
            let (n_start, n_len) = expect(key, inner, 0x02, "modulus")?;
            let (e_start, e_len) = expect(key, n_start + n_len, 0x02, "exponent")?;
            let trim = |b: &[u8]| {
                let mut v = b.to_vec();
                while v.len() > 1 && v[0] == 0 {
                    v.remove(0);
                }
                v
            };
            return Ok(PublicKey::Rsa {
                n: trim(&key[n_start..n_start + n_len]),
                e: trim(&key[e_start..e_start + e_len]),
            });
        }
        Err(Error::crypto("der: unsupported certificate public key"))
    }
}

// --- RFC 8446 §7.1 key schedule ----------------------------------------

/// The hash a cipher suite's key schedule is built on (RFC 8446 §7.1).
///
/// In TLS 1.3 the suite's hash drives *everything*: the transcript hash, the
/// HKDF-Extract/Expand calls, Derive-Secret, the Finished HMAC, and the length
/// of every secret (48 bytes instead of 32 for SHA-384). `0x1301`/`0x1303` use
/// SHA-256, `0x1302` uses SHA-384.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashKind {
    Sha256,
    Sha384,
}

impl HashKind {
    /// Secret/HMAC/digest length: 32 for SHA-256, 48 for SHA-384.
    fn digest_len(self) -> usize {
        match self {
            HashKind::Sha256 => 32,
            HashKind::Sha384 => 48,
        }
    }

    /// One-shot digest of `data`.
    fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            HashKind::Sha256 => Sha256::digest(data).to_vec(),
            HashKind::Sha384 => Sha384::digest(data).to_vec(),
        }
    }

    /// HKDF-Expand-Label (RFC 8446 §7.1) with the `tls13 ` label prefix.
    fn hkdf_expand_label(
        self,
        secret: &[u8],
        label: &str,
        context: &[u8],
        out: &mut [u8],
    ) -> Result<()> {
        let full = format!("tls13 {label}");
        if full.len() > u8::MAX as usize
            || context.len() > u8::MAX as usize
            || out.len() > u16::MAX as usize
        {
            return Err(Error::crypto("tls13: label/context too long"));
        }
        let mut info = Vec::with_capacity(2 + 1 + full.len() + 1 + context.len());
        info.extend_from_slice(&(out.len() as u16).to_be_bytes());
        info.push(full.len() as u8);
        info.extend_from_slice(full.as_bytes());
        info.push(context.len() as u8);
        info.extend_from_slice(context);
        match self {
            HashKind::Sha256 => {
                let hk = Hkdf::<Sha256>::from_prk(secret)
                    .map_err(|_| Error::crypto("tls13: bad secret"))?;
                hk.expand(&info, out)
                    .map_err(|_| Error::crypto("tls13: hkdf expand failed"))
            }
            HashKind::Sha384 => {
                let hk = Hkdf::<Sha384>::from_prk(secret)
                    .map_err(|_| Error::crypto("tls13: bad secret"))?;
                hk.expand(&info, out)
                    .map_err(|_| Error::crypto("tls13: hkdf expand failed"))
            }
        }
    }

    /// HMAC of `data` under `key` (the Finished `verify_data`).
    fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        use hmac::{Hmac, Mac};
        match self {
            HashKind::Sha256 => {
                let mut mac =
                    <Hmac<Sha256>>::new_from_slice(key).expect("hmac accepts any key length");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            HashKind::Sha384 => {
                let mut mac =
                    <Hmac<Sha384>>::new_from_slice(key).expect("hmac accepts any key length");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }

    /// Constant-time check that `tag` is `HMAC(key, data)`.
    fn hmac_verify(self, key: &[u8], data: &[u8], tag: &[u8]) -> bool {
        use hmac::{Hmac, Mac};
        match self {
            HashKind::Sha256 => {
                let mut mac =
                    <Hmac<Sha256>>::new_from_slice(key).expect("hmac accepts any key length");
                mac.update(data);
                mac.verify_slice(tag).is_ok()
            }
            HashKind::Sha384 => {
                let mut mac =
                    <Hmac<Sha384>>::new_from_slice(key).expect("hmac accepts any key length");
                mac.update(data);
                mac.verify_slice(tag).is_ok()
            }
        }
    }
}

/// Running handshake transcript hash, using the negotiated suite's hash.
#[derive(Clone)]
enum TranscriptHash {
    Sha256(Sha256),
    Sha384(Sha384),
}

#[derive(Clone)]
struct Transcript {
    inner: TranscriptHash,
}

impl Transcript {
    fn new(hash: HashKind) -> Self {
        Transcript {
            inner: match hash {
                HashKind::Sha256 => TranscriptHash::Sha256(Sha256::new()),
                HashKind::Sha384 => TranscriptHash::Sha384(Sha384::new()),
            },
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        match &mut self.inner {
            TranscriptHash::Sha256(h) => h.update(bytes),
            TranscriptHash::Sha384(h) => h.update(bytes),
        }
    }

    fn hash(&self) -> Vec<u8> {
        match &self.inner {
            TranscriptHash::Sha256(h) => h.clone().finalize().to_vec(),
            TranscriptHash::Sha384(h) => h.clone().finalize().to_vec(),
        }
    }
}

/// HKDF-Extract (RFC 5869) with the suite's hash.
fn hkdf_extract(hash: HashKind, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    match hash {
        HashKind::Sha256 => Hkdf::<Sha256>::extract(Some(salt), ikm).0.to_vec(),
        HashKind::Sha384 => Hkdf::<Sha384>::extract(Some(salt), ikm).0.to_vec(),
    }
}

/// Derive-Secret(secret, label, transcript) — RFC 8446 §7.1.
fn derive_secret(
    hash: HashKind,
    secret: &[u8],
    label: &str,
    transcript_hash: &[u8],
) -> Result<Vec<u8>> {
    let mut out = vec![0u8; hash.digest_len()];
    hash.hkdf_expand_label(secret, label, transcript_hash, &mut out)?;
    Ok(out)
}

/// Finished `verify_data`: HMAC over the transcript with the finished key.
fn finished_verify_data(
    hash: HashKind,
    finished_key: &[u8],
    transcript_hash: &[u8],
) -> Result<Vec<u8>> {
    if finished_key.len() != hash.digest_len() {
        return Err(Error::crypto("tls13: bad finished key"));
    }
    Ok(hash.hmac(finished_key, transcript_hash))
}

fn finished_key(hash: HashKind, secret: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0u8; hash.digest_len()];
    hash.hkdf_expand_label(secret, "finished", &[], &mut out)?;
    Ok(out)
}

/// Per-direction traffic key material.
struct TrafficKeys {
    kind: AeadKind,
    key: Vec<u8>,
    iv: [u8; 12],
}

fn traffic_keys(suite: CipherSuite, secret: &[u8]) -> Result<TrafficKeys> {
    let hash = suite.hash();
    let mut key = vec![0u8; suite.key_len()];
    hash.hkdf_expand_label(secret, "key", &[], &mut key)?;
    let mut iv = [0u8; 12];
    hash.hkdf_expand_label(secret, "iv", &[], &mut iv)?;
    Ok(TrafficKeys {
        kind: suite.aead_kind(),
        key,
        iv,
    })
}

/// Handshake-phase secrets derived from the ECDHE shared secret. All three
/// are `hash.digest_len()` bytes long.
struct HandshakeSecrets {
    c_hs: Vec<u8>,
    s_hs: Vec<u8>,
    master: Vec<u8>,
}

/// RFC 8446 §7.1 up to the master secret.
fn handshake_secrets(
    suite: CipherSuite,
    shared: &[u8; 32],
    transcript: &[u8],
) -> Result<HandshakeSecrets> {
    let hash = suite.hash();
    // "0" in the RFC 8446 §7.1 diagram is Hash.length zero bytes.
    let zeros = vec![0u8; hash.digest_len()];
    let empty_hash = hash.hash(&[]);
    let early_secret = hkdf_extract(hash, &zeros, &zeros);
    let derived = derive_secret(hash, &early_secret, "derived", &empty_hash)?;
    let handshake_secret = hkdf_extract(hash, &derived, shared);
    let c_hs = derive_secret(hash, &handshake_secret, "c hs traffic", transcript)?;
    let s_hs = derive_secret(hash, &handshake_secret, "s hs traffic", transcript)?;
    let derived2 = derive_secret(hash, &handshake_secret, "derived", &empty_hash)?;
    let master = hkdf_extract(hash, &derived2, &zeros);
    Ok(HandshakeSecrets { c_hs, s_hs, master })
}

/// RFC 8446 §7.1 application traffic secrets (after the server Finished).
fn application_secrets(
    hash: HashKind,
    master: &[u8],
    transcript: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    Ok((
        derive_secret(hash, master, "c ap traffic", transcript)?,
        derive_secret(hash, master, "s ap traffic", transcript)?,
    ))
}

/// RFC 8446 §7.2 `traffic upd` secret rotation.
fn next_traffic_secret(hash: HashKind, secret: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0u8; hash.digest_len()];
    hash.hkdf_expand_label(secret, "traffic upd", &[], &mut out)?;
    Ok(out)
}

// --- record layer -------------------------------------------------------

/// One direction of the TLS 1.3 record layer.
struct RecordProtector {
    aead: Aead,
    iv: [u8; 12],
    seq: u64,
}

impl RecordProtector {
    fn new(keys: &TrafficKeys) -> Result<Self> {
        Ok(RecordProtector {
            aead: Aead::new(keys.kind, &keys.key)?,
            iv: keys.iv,
            seq: 0,
        })
    }

    /// Per-record nonce: the static IV XORed with the 64-bit sequence number
    /// (RFC 8446 §5.3).
    fn nonce(&self) -> [u8; 12] {
        let mut nonce = self.iv;
        let seq = self.seq.to_be_bytes();
        for (i, b) in seq.iter().enumerate() {
            nonce[4 + i] ^= b;
        }
        nonce
    }

    /// Seal `plaintext` with an inner content type, returning the whole
    /// TLSCiphertext record (header included; the header is the AAD).
    fn seal(&mut self, inner_type: u8, plaintext: &[u8]) -> Result<Vec<u8>> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(Error::crypto("tls13: record plaintext too large"));
        }
        let mut inner = Vec::with_capacity(plaintext.len() + 1);
        inner.extend_from_slice(plaintext);
        inner.push(inner_type);
        let nonce = self.nonce();
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| Error::crypto("tls13: record sequence overflow"))?;
        let ct_len = inner.len() + 16;
        let header = [
            RECORD_APP,
            (VERSION_TLS12 >> 8) as u8,
            VERSION_TLS12 as u8,
            (ct_len >> 8) as u8,
            ct_len as u8,
        ];
        let mut out = Vec::with_capacity(5 + ct_len);
        out.extend_from_slice(&header);
        self.aead.seal(&nonce, &header, &inner, &mut out)?;
        Ok(out)
    }

    /// Open a TLSCiphertext record (`record` = header + ciphertext).
    /// Returns the inner content type and the plaintext.
    fn open(&mut self, record: &[u8]) -> Result<(u8, Vec<u8>)> {
        if record.len() < 5 + 16 + 1 || record[0] != RECORD_APP {
            return Err(Error::protocol("tls13: malformed encrypted record"));
        }
        let nonce = self.nonce();
        self.seq = self
            .seq
            .checked_add(1)
            .ok_or_else(|| Error::crypto("tls13: record sequence overflow"))?;
        let mut inner = self.aead.open(&nonce, &record[..5], &record[5..])?;
        // RFC 8446 §5.4: zero padding precedes the content type, so the
        // type is the LAST NON-ZERO byte. REALITY servers zero-pad
        // mirrored handshake records (Xray `halfConn.encrypt` mimicry),
        // which a naive `pop()` would misread as content type 0.
        let Some(idx) = inner.iter().rposition(|b| *b != 0) else {
            return Err(Error::protocol("tls13: all-zero inner plaintext"));
        };
        let inner_type = inner[idx];
        inner.truncate(idx);
        Ok((inner_type, inner))
    }
}

// --- server authentication ---------------------------------------------

/// Certificate authentication callback: receives the leaf certificate DER and
/// returns `Ok(true)` when the custom scheme verified it (REALITY's temp-auth).
pub type CertCallback = Box<dyn Fn(&[u8]) -> Result<bool> + Send>;

/// How the client authenticates the server's certificate chain.
pub enum ServerAuth {
    /// Full webpki path validation + name check, via rustls' own verifier
    /// (`rustls::client::WebPkiServerVerifier`, ring provider).
    WebPki {
        /// Trust anchors.
        roots: Arc<rustls::RootCertStore>,
        /// Name the certificate must be valid for (the SNI we sent).
        server_name: String,
    },
    /// REALITY temp-auth: hand the leaf DER to the caller. `Ok(true)` means
    /// the custom scheme verified it; `Ok(false)` still completes the
    /// handshake (upstream Xray does the same, then falls back to the
    /// spider and fails) and is reported by [`Tls13Stream::cert_verified`].
    Callback(CertCallback),
    /// Accept any certificate. Tests and diagnostics only.
    AcceptAny,
}

impl std::fmt::Debug for ServerAuth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServerAuth::WebPki { server_name, .. } => f
                .debug_struct("WebPki")
                .field("server_name", server_name)
                .finish(),
            ServerAuth::Callback(_) => f.write_str("Callback(..)"),
            ServerAuth::AcceptAny => f.write_str("AcceptAny"),
        }
    }
}

// --- server-side message parsing ---------------------------------------

fn u16_at(b: &[u8], i: usize) -> Result<u16> {
    let s = b
        .get(i..i + 2)
        .ok_or_else(|| Error::protocol("tls13: truncated u16"))?;
    Ok(u16::from_be_bytes([s[0], s[1]]))
}

fn u24_at(b: &[u8], i: usize) -> Result<usize> {
    let s = b
        .get(i..i + 3)
        .ok_or_else(|| Error::protocol("tls13: truncated u24"))?;
    Ok(((s[0] as usize) << 16) | ((s[1] as usize) << 8) | s[2] as usize)
}

/// Walk a `u16`-length-prefixed extension block, yielding `(type, body)`.
fn extensions(b: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let total = u16_at(b, 0)? as usize;
    let body = b
        .get(2..2 + total)
        .ok_or_else(|| Error::protocol("tls13: truncated extensions"))?;
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < body.len() {
        let typ = u16_at(body, off)?;
        let len = u16_at(body, off + 2)? as usize;
        let data = body
            .get(off + 4..off + 4 + len)
            .ok_or_else(|| Error::protocol("tls13: truncated extension body"))?;
        out.push((typ, data));
        off += 4 + len;
    }
    Ok(out)
}

const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

struct ServerHello {
    cipher_suite: u16,
    session_id: Vec<u8>,
    share: Vec<u8>,
}

/// Parse a ServerHello handshake message (`msg` includes the 4-byte header).
fn parse_server_hello(msg: &[u8]) -> Result<ServerHello> {
    let b = msg
        .get(4..)
        .ok_or_else(|| Error::protocol("tls13: short ServerHello"))?;
    let random = b
        .get(2..34)
        .ok_or_else(|| Error::protocol("tls13: short ServerHello random"))?;
    if random == HRR_RANDOM.as_slice() {
        return Err(Error::protocol(
            "tls13: server asked for HelloRetryRequest (unsupported; we offer an X25519 key share)",
        ));
    }
    let sid_len = *b
        .get(34)
        .ok_or_else(|| Error::protocol("tls13: short ServerHello"))? as usize;
    let session_id = b
        .get(35..35 + sid_len)
        .ok_or_else(|| Error::protocol("tls13: short ServerHello session id"))?
        .to_vec();
    let mut off = 35 + sid_len;
    let cipher_suite = u16_at(b, off)?;
    off += 2;
    match b.get(off) {
        Some(0x00) => {}
        Some(other) => {
            return Err(Error::protocol(format!(
                "tls13: server selected compression {other:#x}"
            )))
        }
        None => return Err(Error::protocol("tls13: short ServerHello")),
    }
    off += 1;
    let exts = extensions(b.get(off..).unwrap_or_default())?;

    let mut share = None;
    let mut selected_version = None;
    for (typ, body) in exts {
        match typ {
            EXT_SUPPORTED_VERSIONS => {
                selected_version = Some(u16_at(body, 0)?);
            }
            EXT_KEY_SHARE => {
                let group = u16_at(body, 0)?;
                let len = u16_at(body, 2)? as usize;
                if group != GROUP_X25519 {
                    return Err(Error::protocol(format!(
                        "tls13: server selected key exchange group {group:#06x}; only X25519 is implemented"
                    )));
                }
                share = Some(
                    body.get(4..4 + len)
                        .ok_or_else(|| Error::protocol("tls13: short key share"))?
                        .to_vec(),
                );
            }
            EXT_PRE_SHARED_KEY => {
                return Err(Error::protocol(
                    "tls13: server selected a PSK we never offered",
                ))
            }
            _ => {}
        }
    }
    match selected_version {
        Some(v) if v == VERSION_TLS13 => {}
        Some(v) => {
            return Err(Error::protocol(format!(
                "tls13: server negotiated version {v:#06x}, this client is TLS 1.3 only"
            )))
        }
        None => {
            return Err(Error::protocol(
                "tls13: ServerHello has no supported_versions extension",
            ))
        }
    }
    let share = share.ok_or_else(|| Error::protocol("tls13: ServerHello has no key_share"))?;
    if share.len() != 32 {
        return Err(Error::protocol("tls13: X25519 key share is not 32 bytes"));
    }
    Ok(ServerHello {
        cipher_suite,
        session_id,
        share,
    })
}

/// Parse EncryptedExtensions, returning the ALPN protocol if the server set one.
fn parse_encrypted_extensions(msg: &[u8]) -> Result<Option<Vec<u8>>> {
    let body = msg
        .get(4..)
        .ok_or_else(|| Error::protocol("tls13: short EncryptedExtensions"))?;
    let mut alpn = None;
    for (typ, data) in extensions(body)? {
        if typ == EXT_ALPN {
            let total = u16_at(data, 0)? as usize;
            let list = data
                .get(2..2 + total)
                .ok_or_else(|| Error::protocol("tls13: truncated ALPN list"))?;
            if let Some(&len) = list.first() {
                alpn = Some(
                    list.get(1..1 + len as usize)
                        .ok_or_else(|| Error::protocol("tls13: truncated ALPN protocol"))?
                        .to_vec(),
                );
            }
        }
    }
    Ok(alpn)
}

/// Parse a Certificate message into the raw DER chain.
fn parse_certificate(msg: &[u8]) -> Result<Vec<Vec<u8>>> {
    let b = msg
        .get(4..)
        .ok_or_else(|| Error::protocol("tls13: short Certificate"))?;
    let ctx_len = *b
        .first()
        .ok_or_else(|| Error::protocol("tls13: short Certificate"))? as usize;
    let mut off = 1 + ctx_len;
    if ctx_len != 0 {
        return Err(Error::protocol(
            "tls13: Certificate carries a request context we never sent",
        ));
    }
    let list_len = u24_at(b, off)?;
    off += 3;
    let end = off + list_len;
    if end > b.len() {
        return Err(Error::protocol("tls13: truncated certificate list"));
    }
    let mut chain = Vec::new();
    while off < end {
        let len = u24_at(b, off)?;
        off += 3;
        let der = b
            .get(off..off + len)
            .ok_or_else(|| Error::protocol("tls13: truncated certificate"))?;
        chain.push(der.to_vec());
        off += len;
        let ext_len = u16_at(b, off)? as usize;
        off += 2 + ext_len;
    }
    if chain.is_empty() {
        return Err(Error::protocol("tls13: server sent an empty certificate chain"));
    }
    Ok(chain)
}

/// Verify the server's CertificateVerify against the leaf certificate.
fn verify_certificate_verify(body: &[u8], leaf: &[u8], transcript_hash: &[u8]) -> Result<()> {
    let scheme = u16_at(body, 0)?;
    let sig_len = u16_at(body, 2)? as usize;
    let sig = body
        .get(4..4 + sig_len)
        .ok_or_else(|| Error::protocol("tls13: truncated CertificateVerify"))?;

    let mut message =
        Vec::with_capacity(64 + SERVER_SIGNATURE_CONTEXT.len() + 1 + transcript_hash.len());
    message.extend_from_slice(&[0x20u8; 64]);
    message.extend_from_slice(SERVER_SIGNATURE_CONTEXT);
    message.push(0x00);
    message.extend_from_slice(transcript_hash);

    let key = der::public_key(leaf)?;
    let failure = || {
        Error::protocol(format!(
            "tls13: CertificateVerify signature check failed (scheme {scheme:#06x} over a {} key)",
            key_name(&key)
        ))
    };
    let rsa = |n: &Vec<u8>, e: &Vec<u8>, alg: &'static signature::RsaParameters| {
        signature::RsaPublicKeyComponents {
            n: n.as_slice(),
            e: e.as_slice(),
        }
        .verify(alg, &message, sig)
    };
    match (&key, scheme) {
        (der::PublicKey::Ed25519(k), 0x0807) => {
            signature::UnparsedPublicKey::new(&signature::ED25519, k)
                .verify(&message, sig)
                .map_err(|_| failure())?;
        }
        (der::PublicKey::EcdsaP256(k), 0x0403) => {
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, k)
                .verify(&message, sig)
                .map_err(|_| failure())?;
        }
        (der::PublicKey::EcdsaP384(k), 0x0503) => {
            signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_ASN1, k)
                .verify(&message, sig)
                .map_err(|_| failure())?;
        }
        (der::PublicKey::Rsa { n, e }, 0x0804) => {
            rsa(n, e, &signature::RSA_PSS_2048_8192_SHA256).map_err(|_| failure())?;
        }
        (der::PublicKey::Rsa { n, e }, 0x0805) => {
            rsa(n, e, &signature::RSA_PSS_2048_8192_SHA384).map_err(|_| failure())?;
        }
        (der::PublicKey::Rsa { n, e }, 0x0806) => {
            rsa(n, e, &signature::RSA_PSS_2048_8192_SHA512).map_err(|_| failure())?;
        }
        (k, s) => {
            return Err(Error::protocol(format!(
                "tls13: server CertificateVerify scheme {s:#06x} does not match its {} key",
                key_name(k)
            )))
        }
    }
    Ok(())
}

fn key_name(k: &der::PublicKey) -> &'static str {
    match k {
        der::PublicKey::Ed25519(_) => "Ed25519",
        der::PublicKey::EcdsaP256(_) => "ECDSA-P256",
        der::PublicKey::EcdsaP384(_) => "ECDSA-P384",
        der::PublicKey::Rsa { .. } => "RSA",
    }
}

/// Check the server's Finished `verify_data` in constant time.
fn verify_finished(
    hash: HashKind,
    finished_key: &[u8],
    transcript_hash: &[u8],
    body: &[u8],
) -> Result<()> {
    if body.len() != hash.digest_len() {
        return Err(Error::protocol("tls13: Finished has the wrong length"));
    }
    if !hash.hmac_verify(finished_key, transcript_hash, body) {
        return Err(Error::protocol(
            "tls13: server Finished does not verify (wrong key or MITM)",
        ));
    }
    Ok(())
}

/// X25519 with the all-zero (low order) shared-secret check.
pub(crate) fn x25519(secret: &[u8; 32], peer: &[u8]) -> Result<[u8; 32]> {
    let peer: [u8; 32] = peer
        .try_into()
        .map_err(|_| Error::crypto("tls13: X25519 peer key is not 32 bytes"))?;
    let shared = curve25519_dalek::montgomery::MontgomeryPoint(peer)
        .mul_clamped(*secret)
        .0;
    if shared.iter().all(|b| *b == 0) {
        return Err(Error::crypto(
            "tls13: X25519 peer key share is a low-order point",
        ));
    }
    Ok(shared)
}

/// Fresh X25519 keypair; the secret is clamped by `mul_base_clamped`.
pub(crate) fn x25519_keygen() -> ([u8; 32], [u8; 32]) {
    let mut secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut secret);
    let public = curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(secret).0;
    (secret, public)
}

// --- handshake message plumbing ----------------------------------------

fn hs_message(typ: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(typ);
    let len = body.len();
    out.push((len >> 16) as u8);
    out.push((len >> 8) as u8);
    out.push(len as u8);
    out.extend_from_slice(body);
    out
}

/// Pull one complete handshake message out of `buf` (which holds raw
/// handshake bytes); returns `(type, raw message incl. header)`.
fn take_handshake(buf: &mut Vec<u8>) -> Option<(u8, Vec<u8>)> {
    if buf.len() < 4 {
        return None;
    }
    let len = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | buf[3] as usize;
    if buf.len() < 4 + len {
        return None;
    }
    let raw: Vec<u8> = buf.drain(..4 + len).collect();
    Some((raw[0], raw))
}

/// Read one whole TLS record. `Ok(None)` is a clean EOF.
async fn read_record(t: &mut BoxProxyStream) -> Result<Option<Vec<u8>>> {
    let mut header = [0u8; 5];
    let mut filled = 0usize;
    while filled < 5 {
        let n = t.read(&mut header[filled..]).await?;
        if n == 0 {
            return if filled == 0 {
                Ok(None)
            } else {
                Err(Error::protocol("tls13: EOF inside a record header"))
            };
        }
        filled += n;
    }
    let len = u16::from_be_bytes([header[3], header[4]]) as usize;
    if len > MAX_CIPHERTEXT {
        return Err(Error::protocol(format!(
            "tls13: record of {len} bytes exceeds the TLS 1.3 limit"
        )));
    }
    let mut rec = Vec::with_capacity(5 + len);
    rec.extend_from_slice(&header);
    rec.resize(5 + len, 0);
    t.read_exact(&mut rec[5..])
        .await
        .map_err(|e| Error::protocol(format!("tls13: short record: {e}")))?;
    Ok(Some(rec))
}

fn alert_error(record: &[u8]) -> Error {
    let desc = record.get(6).copied().unwrap_or(0);
    let level = record.get(5).copied().unwrap_or(0);
    Error::protocol(format!(
        "tls13: server sent alert level={level} description={desc}"
    ))
}

/// Next handshake message in the *plaintext* phase (the ServerHello).
async fn next_plaintext_handshake(
    t: &mut BoxProxyStream,
    pending: &mut Vec<u8>,
    ccs: &mut u8,
) -> Result<(u8, Vec<u8>)> {
    loop {
        if let Some(msg) = take_handshake(pending) {
            return Ok(msg);
        }
        let rec = read_record(t)
            .await?
            .ok_or_else(|| Error::protocol("tls13: connection closed during the handshake"))?;
        match rec[0] {
            RECORD_HANDSHAKE => pending.extend_from_slice(&rec[5..]),
            RECORD_CCS => {
                *ccs += 1;
                if *ccs > 2 || rec.len() != 6 || rec[5] != 0x01 {
                    return Err(Error::protocol("tls13: unexpected ChangeCipherSpec"));
                }
            }
            RECORD_ALERT => return Err(alert_error(&rec)),
            other => {
                return Err(Error::protocol(format!(
                    "tls13: unexpected record type {other} before the ServerHello"
                )))
            }
        }
    }
}

/// Next handshake message in the *encrypted* phase.
async fn next_encrypted_handshake(
    t: &mut BoxProxyStream,
    key: &mut RecordProtector,
    pending: &mut Vec<u8>,
    ccs: &mut u8,
) -> Result<(u8, Vec<u8>)> {
    loop {
        if let Some(msg) = take_handshake(pending) {
            return Ok(msg);
        }
        let rec = read_record(t)
            .await?
            .ok_or_else(|| Error::protocol("tls13: connection closed during the handshake"))?;
        if rec[0] == RECORD_CCS {
            *ccs += 1;
            if *ccs > 4 {
                return Err(Error::protocol("tls13: too many ChangeCipherSpec records"));
            }
            continue;
        }
        if rec[0] == RECORD_ALERT {
            return Err(alert_error(&rec));
        }
        let (inner_type, plain) = key.open(&rec)?;
        match inner_type {
            RECORD_HANDSHAKE => pending.extend_from_slice(&plain),
            RECORD_ALERT => {
                // Alerts are fatal in the handshake no matter the level.
                let mut rec = vec![0u8; 4];
                rec.extend_from_slice(&plain);
                return Err(alert_error(&rec));
            }
            other => {
                return Err(Error::protocol(format!(
                    "tls13: unexpected inner content type {other} during the handshake"
                )))
            }
        }
    }
}

// --- the client ---------------------------------------------------------

/// Drive a TLS 1.3 handshake over `transport` and return the established
/// stream.
///
/// `client_hello` is the *handshake message* built by
/// [`super::profiles::build_client_hello`] (REALITY must have sealed its
/// session id into it first); `x25519_secret` is the private half of the
/// key share it advertises.
pub async fn connect(
    transport: BoxProxyStream,
    client_hello: &[u8],
    x25519_secret: &[u8; 32],
    auth: ServerAuth,
) -> Result<Tls13Stream> {
    if client_hello.len() < super::profiles::SESSION_ID_OFFSET + 32 || client_hello[0] != HS_CLIENT_HELLO
    {
        return Err(Error::protocol("tls13: malformed ClientHello"));
    }
    let mut expected_session_id = [0u8; 32];
    expected_session_id
        .copy_from_slice(&client_hello[super::profiles::SESSION_ID_OFFSET..][..32]);

    let mut t = transport;
    t.write_all(&super::profiles::client_hello_record(client_hello))
        .await?;

    let mut pending = Vec::new();
    let mut ccs = 0u8;
    let (typ, sh_raw) = next_plaintext_handshake(&mut t, &mut pending, &mut ccs).await?;
    if typ != HS_SERVER_HELLO {
        return Err(Error::protocol(format!(
            "tls13: expected a ServerHello, got handshake type {typ}"
        )));
    }
    let sh = parse_server_hello(&sh_raw)?;
    if sh.session_id != expected_session_id {
        return Err(Error::protocol(
            "tls13: server echoed the wrong legacy session id",
        ));
    }
    let suite = CipherSuite::from_id(sh.cipher_suite).ok_or_else(|| {
        Error::protocol(format!(
            "tls13: server selected unsupported cipher suite {:#06x}",
            sh.cipher_suite
        ))
    })?;
    // The transcript hash is a property of the negotiated suite, so the
    // ClientHello only enters it once the ServerHello has named that suite.
    let mut transcript = Transcript::new(suite.hash());
    transcript.update(client_hello);
    transcript.update(&sh_raw);
    let shared = x25519(x25519_secret, &sh.share)?;
    let secrets = handshake_secrets(suite, &shared, &transcript.hash())?;
    let mut read_key = RecordProtector::new(&traffic_keys(suite, &secrets.s_hs)?)?;
    let mut write_key = RecordProtector::new(&traffic_keys(suite, &secrets.c_hs)?)?;

    // Middlebox compatibility (RFC 8446 §D.4): Go's TLS 1.3 client — which is
    // what the REALITY reference client is — sends a dummy CCS here.
    t.write_all(&[RECORD_CCS, 0x03, 0x03, 0x00, 0x01, 0x01]).await?;

    let (typ, ee_raw) =
        next_encrypted_handshake(&mut t, &mut read_key, &mut pending, &mut ccs).await?;
    if typ != HS_ENCRYPTED_EXTENSIONS {
        return Err(Error::protocol(format!(
            "tls13: expected EncryptedExtensions, got handshake type {typ}"
        )));
    }
    transcript.update(&ee_raw);
    let alpn = parse_encrypted_extensions(&ee_raw)?;

    let (typ, cert_raw) =
        next_encrypted_handshake(&mut t, &mut read_key, &mut pending, &mut ccs).await?;
    if typ == HS_COMPRESSED_CERTIFICATE {
        return Err(Error::protocol(
            "tls13: server sent a compressed certificate (RFC 8879); brotli/zlib \
             decompression is not implemented — drop the compress_certificate \
             extension in the profile to talk to this server",
        ));
    }
    if typ != HS_CERTIFICATE {
        return Err(Error::protocol(format!(
            "tls13: expected Certificate, got handshake type {typ}"
        )));
    }
    transcript.update(&cert_raw);
    let chain = parse_certificate(&cert_raw)?;
    let leaf = chain.first().cloned().unwrap_or_default();

    let (typ, cv_raw) =
        next_encrypted_handshake(&mut t, &mut read_key, &mut pending, &mut ccs).await?;
    if typ != HS_CERTIFICATE_VERIFY {
        return Err(Error::protocol(format!(
            "tls13: expected CertificateVerify, got handshake type {typ}"
        )));
    }
    let hash_at_cert = transcript.hash();
    transcript.update(&cv_raw);
    verify_certificate_verify(cv_raw.get(4..).unwrap_or_default(), &leaf, &hash_at_cert)?;

    // The handshake signature is bound to this certificate; only the chain
    // trust decision is delegated (REALITY's temp-auth replaces it).
    let cert_verified = match &auth {
        ServerAuth::AcceptAny => true,
        ServerAuth::WebPki { roots, server_name } => {
            verify_chain_webpki(roots, server_name, &chain)?;
            true
        }
        ServerAuth::Callback(check) => check(&leaf)?,
    };

    let (typ, fin_raw) =
        next_encrypted_handshake(&mut t, &mut read_key, &mut pending, &mut ccs).await?;
    if typ != HS_FINISHED {
        return Err(Error::protocol(format!(
            "tls13: expected Finished, got handshake type {typ}"
        )));
    }
    let hash_at_cv = transcript.hash();
    verify_finished(
        suite.hash(),
        &finished_key(suite.hash(), &secrets.s_hs)?,
        &hash_at_cv,
        fin_raw.get(4..).unwrap_or_default(),
    )?;
    transcript.update(&fin_raw);

    // Client Finished, encrypted with the client handshake traffic key.
    let verify_data = finished_verify_data(
        suite.hash(),
        &finished_key(suite.hash(), &secrets.c_hs)?,
        &transcript.hash(),
    )?;
    let record = write_key.seal(RECORD_HANDSHAKE, &hs_message(HS_FINISHED, &verify_data))?;
    t.write_all(&record).await?;

    // Application traffic keys, derived from the transcript through the
    // server Finished (RFC 8446 §7.1).
    let hash_at_sfin = transcript.hash();
    let (c_ap, s_ap) = application_secrets(suite.hash(), &secrets.master, &hash_at_sfin)?;
    let read_key = RecordProtector::new(&traffic_keys(suite, &s_ap)?)?;
    let write_key = RecordProtector::new(&traffic_keys(suite, &c_ap)?)?;

    Ok(Tls13Stream {
        inner: t,
        read_secret: s_ap,
        write_secret: c_ap,
        read_key,
        write_key,
        suite,
        alpn,
        cert_verified,
        plain: Vec::new(),
        rec: Vec::new(),
        out: Vec::new(),
        out_plain: 0,
        ctl: Vec::new(),
        peer_ccs: ccs,
        key_updates: 0,
        eof: false,
        close_notify_sent: false,
    })
}

/// Validate the chain with rustls' webpki verifier (the same code rustls
/// itself uses for `WebPkiServerVerifier`); we only supply the messages.
fn verify_chain_webpki(
    roots: &Arc<rustls::RootCertStore>,
    server_name: &str,
    chain: &[Vec<u8>],
) -> Result<()> {
    use rustls::client::danger::ServerCertVerifier;
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier =
        rustls::client::WebPkiServerVerifier::builder_with_provider(roots.clone(), provider)
            .build()
            .map_err(|e| Error::config(format!("tls13: cannot build the webpki verifier: {e}")))?;
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|_| Error::config(format!("tls13: invalid server name {server_name:?}")))?;
    let end_entity = CertificateDer::from(chain[0].clone());
    let intermediates: Vec<CertificateDer<'static>> = chain[1..]
        .iter()
        .map(|c| CertificateDer::from(c.clone()))
        .collect();
    verifier
        .verify_server_cert(
            &end_entity,
            &intermediates,
            &name,
            &[],
            UnixTime::now(),
        )
        .map_err(|e| Error::protocol(format!("tls13: certificate verification failed: {e}")))?;
    Ok(())
}

impl std::fmt::Debug for Tls13Stream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tls13Stream")
            .field("suite", &self.suite)
            .field("alpn", &self.alpn)
            .field("cert_verified", &self.cert_verified)
            .field("eof", &self.eof)
            .finish_non_exhaustive()
    }
}

/// A TLS 1.3 connection: plaintext in, TLS records out.
pub struct Tls13Stream {
    inner: BoxProxyStream,
    suite: CipherSuite,
    read_key: RecordProtector,
    write_key: RecordProtector,
    /// Suite-sized (`digest_len`) traffic secrets, for `KeyUpdate` rotation.
    read_secret: Vec<u8>,
    write_secret: Vec<u8>,
    alpn: Option<Vec<u8>>,
    cert_verified: bool,
    /// Decrypted application data waiting for the caller.
    plain: Vec<u8>,
    /// Raw bytes of the record currently being read.
    rec: Vec<u8>,
    /// Sealed bytes waiting for the transport.
    out: Vec<u8>,
    /// Plaintext byte count `out` corresponds to (poll_write accounting).
    out_plain: usize,
    /// Queued post-handshake control record (KeyUpdate reply).
    ctl: Vec<u8>,
    peer_ccs: u8,
    key_updates: u8,
    /// Read side saw close_notify (or transport EOF).
    eof: bool,
    /// `poll_shutdown` already queued close_notify (write side only — the
    /// read side stays open so a half-closed tunnel can still drain replies).
    close_notify_sent: bool,
}

impl Tls13Stream {
    /// ALPN protocol the server selected, if any.
    pub fn alpn(&self) -> Option<&[u8]> {
        self.alpn.as_deref()
    }

    /// Whether the certificate passed the configured authentication
    /// (`false` only for a [`ServerAuth::Callback`] that returned `Ok(false)`).
    pub fn cert_verified(&self) -> bool {
        self.cert_verified
    }

    /// Cipher suite in use.
    pub fn suite(&self) -> CipherSuite {
        self.suite
    }

    /// `ChangeCipherSpec` records received from the peer. Test-only: it pins
    /// the RFC 8446 §D.4 middlebox-compatibility dance (we send one dummy CCS,
    /// Go's TLS server — the REALITY reference peer — sends one too).
    #[cfg(test)]
    pub(crate) fn peer_ccs(&self) -> u8 {
        self.peer_ccs
    }

    /// Read one whole record into `self.rec`; `Ok(None)` is EOF.
    fn poll_record(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<Option<()>>> {
        loop {
            if self.rec.len() >= 5 {
                let len = u16::from_be_bytes([self.rec[3], self.rec[4]]) as usize;
                if len > MAX_CIPHERTEXT {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "tls13: record too large",
                    )));
                }
                if self.rec.len() >= 5 + len {
                    return Poll::Ready(Ok(Some(())));
                }
            }
            let mut tmp = [0u8; 4096];
            let mut rb = ReadBuf::new(&mut tmp);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
            if rb.filled().is_empty() {
                return Poll::Ready(Ok(None));
            }
            self.rec.extend_from_slice(rb.filled());
        }
    }

    /// Rotate our read key after a peer `KeyUpdate`.
    fn update_read_key(&mut self) -> Result<()> {
        self.read_secret = next_traffic_secret(self.suite.hash(), &self.read_secret)?;
        self.read_key = RecordProtector::new(&traffic_keys(self.suite, &self.read_secret)?)?;
        Ok(())
    }

    /// Queue a `KeyUpdate(update_not_requested)` reply and rotate the write
    /// key after sealing it (RFC 8446 §4.6.3).
    fn queue_key_update_reply(&mut self) -> Result<()> {
        let record = self.write_key.seal(RECORD_HANDSHAKE, &hs_message(HS_KEY_UPDATE, &[0x00]))?;
        self.ctl.extend_from_slice(&record);
        self.write_secret = next_traffic_secret(self.suite.hash(), &self.write_secret)?;
        self.write_key = RecordProtector::new(&traffic_keys(self.suite, &self.write_secret)?)?;
        Ok(())
    }

    /// Best-effort flush of queued control records.
    fn poll_flush_ctl(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.ctl.is_empty() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.ctl))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "tls13: transport accepted zero bytes",
                )));
            }
            self.ctl.drain(..n);
        }
        Poll::Ready(Ok(()))
    }

    /// Decrypt one record into `plain` / flags.
    fn handle_record(&mut self, record: &[u8]) -> Result<()> {
        match record[0] {
            RECORD_CCS => {
                self.peer_ccs += 1;
                if self.peer_ccs > 4 {
                    return Err(Error::protocol("tls13: too many ChangeCipherSpec records"));
                }
            }
            RECORD_ALERT => {
                // Unencrypted alert after the handshake: fatal by definition.
                return Err(alert_error(record));
            }
            RECORD_APP => {
                let (inner_type, mut data) = self.read_key.open(record)?;
                match inner_type {
                    RECORD_APP => self.plain.extend_from_slice(&data),
                    RECORD_HANDSHAKE => {
                        while let Some((typ, raw)) = take_handshake(&mut data) {
                            match typ {
                                HS_NEW_SESSION_TICKET => {
                                    tracing::debug!("engine: tls13: ignoring a session ticket")
                                }
                                HS_KEY_UPDATE => {
                                    let request = raw.get(4).copied().unwrap_or(0);
                                    if self.key_updates >= MAX_KEY_UPDATES {
                                        return Err(Error::protocol(
                                            "tls13: peer sent too many KeyUpdate messages",
                                        ));
                                    }
                                    self.key_updates += 1;
                                    self.update_read_key()?;
                                    if request == 1 {
                                        self.queue_key_update_reply()?;
                                    }
                                }
                                other => {
                                    return Err(Error::protocol(format!(
                                        "tls13: unexpected post-handshake message {other}"
                                    )))
                                }
                            }
                        }
                    }
                    RECORD_ALERT => {
                        let close = data.first().copied() == Some(0) || data.get(1) == Some(&0);
                        if close {
                            self.eof = true;
                        } else {
                            let mut fake = vec![0u8; 4];
                            fake.extend_from_slice(&data);
                            return Err(alert_error(&fake));
                        }
                    }
                    other => {
                        return Err(Error::protocol(format!(
                            "tls13: unexpected inner content type {other}"
                        )))
                    }
                }
            }
            other => {
                return Err(Error::protocol(format!(
                    "tls13: unexpected record type {other}"
                )))
            }
        }
        Ok(())
    }
}

fn io_from(err: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err.to_string())
}

impl AsyncRead for Tls13Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.plain.is_empty() {
                let n = this.plain.len().min(buf.remaining());
                buf.put_slice(&this.plain[..n]);
                this.plain.drain(..n);
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            // Opportunistic flush of a queued KeyUpdate reply.
            let _ = this.poll_flush_ctl(cx);
            match ready!(this.poll_record(cx))? {
                None => {
                    // Transport EOF without close_notify: surface it as EOF.
                    this.eof = true;
                    return Poll::Ready(Ok(()));
                }
                Some(()) => {
                    // `poll_record` guarantees one whole record is buffered,
                    // but a single read can deliver several: peel off exactly
                    // one, or the AEAD (whose AAD is that one header) fails.
                    let len = u16::from_be_bytes([this.rec[3], this.rec[4]]) as usize;
                    let record: Vec<u8> = this.rec.drain(..5 + len).collect();
                    this.handle_record(&record).map_err(io_from)?;
                }
            }
        }
    }
}

impl AsyncWrite for Tls13Stream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.out.is_empty() {
            let take = buf.len().min(MAX_PLAINTEXT);
            this.out = this
                .write_key
                .seal(RECORD_APP, &buf[..take])
                .map_err(io_from)?;
            this.out_plain = take;
        }
        while !this.out.is_empty() {
            let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.out))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "tls13: transport accepted zero bytes",
                )));
            }
            this.out.drain(..n);
        }
        if this.out_plain == 0 {
            return Poll::Ready(Ok(0));
        }
        Poll::Ready(Ok(std::mem::take(&mut this.out_plain)))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_flush_ctl(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.close_notify_sent {
            this.close_notify_sent = true;
            // close_notify (warning, 0) so the peer can distinguish a clean
            // close from a truncated stream. Only the write side ends here:
            // `split` shares this state, and the read half may still be
            // draining replies (a tunnel close is usually half-close).
            if let Ok(record) = this.write_key.seal(RECORD_ALERT, &[0x01, 0x00]) {
                this.ctl.extend_from_slice(&record);
            }
        }
        ready!(this.poll_flush_ctl(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

// --- in-process TLS 1.3 server (tests only) ----------------------------

/// A deliberately small TLS 1.3 *server* used by the hermetic tests: it
/// speaks exactly the subset the client above emits, which lets the REALITY
/// tests exercise the whole handshake (including the auth material) without
/// any network or BoringSSL.
#[cfg(test)]
pub(crate) mod test_server {
    use super::*;
    use std::sync::Arc;

    const EXT_SERVER_NAME: u16 = 0x0000;

    /// What the test server learned from the ClientHello.
    pub(crate) struct ClientHelloInfo {
        pub(crate) raw: Vec<u8>,
        pub(crate) random: [u8; 32],
        pub(crate) session_id: Vec<u8>,
        pub(crate) x25519_share: [u8; 32],
        pub(crate) sni: Option<String>,
        pub(crate) alpn: Vec<String>,
        pub(crate) cipher_suites: Vec<u16>,
    }

    fn parse_client_hello(raw: &[u8]) -> Result<ClientHelloInfo> {
        let b = raw.get(4..).ok_or_else(|| Error::protocol("test server: short hello"))?;
        let random: [u8; 32] = b[2..34].try_into().unwrap();
        let sid_len = b[34] as usize;
        let session_id = b[35..35 + sid_len].to_vec();
        let mut off = 35 + sid_len;
        let cs_len = u16_at(b, off)? as usize;
        off += 2;
        let mut cipher_suites = Vec::new();
        for i in 0..cs_len / 2 {
            cipher_suites.push(u16_at(b, off + i * 2)?);
        }
        off += cs_len;
        let cm_len = b[off] as usize;
        off += 1 + cm_len;
        let mut x25519_share = None;
        let mut sni = None;
        let mut alpn = Vec::new();
        for (typ, body) in extensions(&b[off..])? {
            match typ {
                EXT_KEY_SHARE => {
                    let mut i = 2usize;
                    while i + 4 <= body.len() {
                        let group = u16_at(body, i)?;
                        let len = u16_at(body, i + 2)? as usize;
                        if group == GROUP_X25519 && len == 32 {
                            x25519_share = Some(body[i + 4..i + 36].try_into().unwrap());
                        }
                        i += 4 + len;
                    }
                }
                EXT_SERVER_NAME => {
                    let name_len = u16_at(body, 3)? as usize;
                    sni = Some(String::from_utf8_lossy(&body[5..5 + name_len]).into_owned());
                }
                EXT_ALPN => {
                    let total = u16_at(body, 0)? as usize;
                    let list = &body[2..2 + total];
                    let mut i = 0usize;
                    while i < list.len() {
                        let l = list[i] as usize;
                        alpn.push(String::from_utf8_lossy(&list[i + 1..i + 1 + l]).into_owned());
                        i += 1 + l;
                    }
                }
                _ => {}
            }
        }
        Ok(ClientHelloInfo {
            raw: raw.to_vec(),
            random,
            session_id,
            x25519_share: x25519_share
                .ok_or_else(|| Error::protocol("test server: no X25519 key share"))?,
            sni,
            alpn,
            cipher_suites,
        })
    }

    /// Handshake a test server, yielding the server's `Tls13Stream` and what
    /// it saw in the ClientHello. `choose_cert` decides which certificate to
    /// present after inspecting the hello (REALITY's fake server uses the
    /// client's auth material to build it).
    pub(crate) async fn accept(
        transport: BoxProxyStream,
        suite: CipherSuite,
        choose_cert: impl FnOnce(
            &ClientHelloInfo,
        ) -> Result<(Vec<u8>, Arc<dyn rustls::sign::SigningKey>)>,
    ) -> Result<(Tls13Stream, ClientHelloInfo)> {
        let mut t = transport;
        let mut pending = Vec::new();
        let mut ccs = 0u8;
        let (typ, ch_raw) = next_plaintext_handshake(&mut t, &mut pending, &mut ccs).await?;
        if typ != HS_CLIENT_HELLO {
            return Err(Error::protocol("test server: expected a ClientHello"));
        }
        let hello = parse_client_hello(&ch_raw)?;
        if !hello.cipher_suites.contains(&suite.id()) {
            return Err(Error::protocol("test server: suite not offered"));
        }

        let mut transcript = Transcript::new(suite.hash());
        transcript.update(&ch_raw);

        let server_random: [u8; 32] = {
            let mut r = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut r);
            r
        };
        let (server_secret, server_public) = x25519_keygen();
        let shared = x25519(&server_secret, &hello.x25519_share)?;

        // ServerHello.
        let mut sh_body = Vec::with_capacity(96);
        sh_body.extend_from_slice(&VERSION_TLS12.to_be_bytes());
        sh_body.extend_from_slice(&server_random);
        sh_body.push(hello.session_id.len() as u8);
        sh_body.extend_from_slice(&hello.session_id);
        sh_body.extend_from_slice(&suite.id().to_be_bytes());
        sh_body.push(0x00);
        let mut sh_exts = Vec::new();
        sh_exts.extend_from_slice(&ext(EXT_SUPPORTED_VERSIONS, &VERSION_TLS13.to_be_bytes()));
        let mut ks = Vec::new();
        ks.extend_from_slice(&GROUP_X25519.to_be_bytes());
        ks.extend_from_slice(&32u16.to_be_bytes());
        ks.extend_from_slice(&server_public);
        sh_exts.extend_from_slice(&ext(EXT_KEY_SHARE, &ks));
        if let Some(first) = hello.alpn.first() {
            let mut list = vec![first.len() as u8];
            list.extend_from_slice(first.as_bytes());
            let mut body = Vec::new();
            body.extend_from_slice(&(list.len() as u16).to_be_bytes());
            body.extend_from_slice(&list);
            sh_exts.extend_from_slice(&ext(EXT_ALPN, &body));
        }
        sh_body.extend_from_slice(&(sh_exts.len() as u16).to_be_bytes());
        sh_body.extend_from_slice(&sh_exts);
        let sh_raw = hs_message(HS_SERVER_HELLO, &sh_body);
        transcript.update(&sh_raw);
        t.write_all(&super::super::profiles::client_hello_record(&sh_raw))
            .await?;

        let secrets = handshake_secrets(suite, &shared, &transcript.hash())?;
        let mut read_key = RecordProtector::new(&traffic_keys(suite, &secrets.c_hs)?)?;
        let mut write_key = RecordProtector::new(&traffic_keys(suite, &secrets.s_hs)?)?;

        // EncryptedExtensions: echo the ALPN choice.
        let mut ee_exts = Vec::new();
        if let Some(first) = hello.alpn.first() {
            let mut list = vec![first.len() as u8];
            list.extend_from_slice(first.as_bytes());
            let mut body = Vec::new();
            body.extend_from_slice(&(list.len() as u16).to_be_bytes());
            body.extend_from_slice(&list);
            ee_exts.extend_from_slice(&ext(EXT_ALPN, &body));
        }
        let mut ee_body = Vec::new();
        ee_body.extend_from_slice(&(ee_exts.len() as u16).to_be_bytes());
        ee_body.extend_from_slice(&ee_exts);
        let ee_raw = hs_message(HS_ENCRYPTED_EXTENSIONS, &ee_body);
        transcript.update(&ee_raw);

        // Certificate.
        let (cert_der, signing_key) = choose_cert(&hello)?;
        let mut cert_body = vec![0x00];
        let mut list = Vec::new();
        list.push((cert_der.len() >> 16) as u8);
        list.push((cert_der.len() >> 8) as u8);
        list.push(cert_der.len() as u8);
        list.extend_from_slice(&cert_der);
        list.extend_from_slice(&0u16.to_be_bytes()); // no per-entry extensions
        cert_body.extend_from_slice(&(list.len() as u32).to_be_bytes()[1..]);
        cert_body.extend_from_slice(&list);
        let cert_raw = hs_message(HS_CERTIFICATE, &cert_body);
        transcript.update(&cert_raw);

        // CertificateVerify (Ed25519 or ECDSA, whichever the key supports).
        let signer = signing_key
            .choose_scheme(&[
                rustls::SignatureScheme::ED25519,
                rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            ])
            .ok_or_else(|| Error::protocol("test server: no usable signing scheme"))?;
        let mut message = Vec::new();
        message.extend_from_slice(&[0x20u8; 64]);
        message.extend_from_slice(SERVER_SIGNATURE_CONTEXT);
        message.push(0x00);
        message.extend_from_slice(&transcript.hash());
        let sig = signer
            .sign(&message)
            .map_err(|e| Error::crypto(format!("test server: sign failed: {e}")))?;
        let mut cv_body = Vec::new();
        cv_body.extend_from_slice(&u16::from(signer.scheme()).to_be_bytes());
        cv_body.extend_from_slice(&(sig.len() as u16).to_be_bytes());
        cv_body.extend_from_slice(&sig);
        let cv_raw = hs_message(HS_CERTIFICATE_VERIFY, &cv_body);
        transcript.update(&cv_raw);

        // Finished.
        let server_fin = finished_verify_data(
            suite.hash(),
            &finished_key(suite.hash(), &secrets.s_hs)?,
            &transcript.hash(),
        )?;
        let fin_raw = hs_message(HS_FINISHED, &server_fin);
        transcript.update(&fin_raw);

        let mut flight = Vec::new();
        flight.extend_from_slice(&write_key.seal(RECORD_HANDSHAKE, &ee_raw)?);
        flight.extend_from_slice(&write_key.seal(RECORD_HANDSHAKE, &cert_raw)?);
        flight.extend_from_slice(&write_key.seal(RECORD_HANDSHAKE, &cv_raw)?);
        flight.extend_from_slice(&write_key.seal(RECORD_HANDSHAKE, &fin_raw)?);
        t.write_all(&flight).await?;

        // Client Finished.
        let (typ, cfin_raw) =
            next_encrypted_handshake(&mut t, &mut read_key, &mut pending, &mut ccs).await?;
        if typ != HS_FINISHED {
            return Err(Error::protocol("test server: expected the client Finished"));
        }
        verify_finished(
            suite.hash(),
            &finished_key(suite.hash(), &secrets.c_hs)?,
            &transcript.hash(),
            cfin_raw.get(4..).unwrap_or_default(),
        )?;

        let (c_ap, s_ap) = application_secrets(suite.hash(), &secrets.master, &transcript.hash())?;
        let read_key = RecordProtector::new(&traffic_keys(suite, &c_ap)?)?;
        let write_key = RecordProtector::new(&traffic_keys(suite, &s_ap)?)?;
        Ok((
            Tls13Stream {
                inner: t,
                suite,
                read_secret: c_ap,
                write_secret: s_ap,
                read_key,
                write_key,
                alpn: hello.alpn.first().map(|p| p.as_bytes().to_vec()),
                cert_verified: true,
                plain: Vec::new(),
                rec: Vec::new(),
                out: Vec::new(),
                out_plain: 0,
                ctl: Vec::new(),
                peer_ccs: ccs,
                key_updates: 0,
                eof: false,
                close_notify_sent: false,
            },
            hello,
        ))
    }

    fn ext(typ: u16, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&typ.to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::reality::profiles::{build_client_hello, UtslProfile};
    use std::sync::atomic::{AtomicBool, Ordering};
    use tokio::io::AsyncWriteExt;

    fn hex(s: &str) -> Vec<u8> {
        let cleaned: String = s.chars().filter(|c| !c.is_whitespace()).collect();
        (0..cleaned.len() / 2)
            .map(|i| u8::from_str_radix(&cleaned[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    fn arr32(s: &str) -> [u8; 32] {
        hex(s).try_into().unwrap()
    }

    /// RFC 8448 §3, "derive secret for handshake tls13 derived".
    #[test]
    fn rfc8448_derived_secret_vector() {
        let early = arr32("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a");
        let empty_hash: [u8; 32] = Sha256::digest([]).into();
        assert_eq!(
            empty_hash.to_vec(),
            hex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
        );
        let derived = derive_secret(HashKind::Sha256, &early, "derived", &empty_hash).unwrap();
        assert_eq!(
            derived.to_vec(),
            hex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba")
        );
    }

    /// RFC 8448 §3, "extract secret handshake" + the traffic secrets and
    /// traffic keys derived from it.
    #[test]
    fn rfc8448_handshake_and_application_vectors() {
        let derived = arr32("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba");
        let ecdhe = arr32("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
        let handshake_secret = hkdf_extract(HashKind::Sha256, &derived, &ecdhe);
        assert_eq!(
            handshake_secret.to_vec(),
            hex("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac")
        );

        let c_hs = derive_secret(
            HashKind::Sha256,
            &handshake_secret,
            "c hs traffic",
            &arr32("860c06edc07858ee8e78f0e7428c58edd6b43f2ca3e6e95f02ed063cf0e1cad8"),
        )
        .unwrap();
        assert_eq!(
            c_hs.to_vec(),
            hex("b3eddb126e067f35a780b3abf45e2d8f3b1a950738f52e9600746a0e27a55a21")
        );

        let keys = traffic_keys(CipherSuite::Aes128GcmSha256, &c_hs).unwrap();
        assert_eq!(keys.key, hex("dbfaa693d1762c5b666af5d950258d01"));
        assert_eq!(keys.iv.to_vec(), hex("5bd3c71b836e0b76bb73265f"));

        // The master secret, then the client application traffic secret.
        let empty_hash: [u8; 32] = Sha256::digest([]).into();
        let derived2 = derive_secret(HashKind::Sha256, &handshake_secret, "derived", &empty_hash)
            .unwrap();
        let master = hkdf_extract(HashKind::Sha256, &derived2, &[0u8; 32]);
        assert_eq!(
            master.to_vec(),
            hex("18df06843d13a08bf2a449844c5f8a478001bc4d4c627984d5a41da8d0402919")
        );
        let (c_ap, _) = application_secrets(
            HashKind::Sha256,
            &master,
            &arr32("9608102a0f1ccc6db6250b7b7e417b1a000eaada3daae4777a7686c9ff83df13"),
        )
        .unwrap();
        assert_eq!(
            c_ap.to_vec(),
            hex("9e40646ce79a7f9dc05af8889bce6552875afa0b06df0087f792ebb7c17504a5")
        );
        let keys = traffic_keys(CipherSuite::Aes128GcmSha256, &c_ap).unwrap();
        assert_eq!(keys.key, hex("17422dda596ed5d9acd890e3c63f5051"));
        assert_eq!(keys.iv.to_vec(), hex("5b78923dee08579033e523d9"));
    }

    #[test]
    fn record_nonce_xors_the_sequence_number() {
        let keys = TrafficKeys {
            kind: AeadKind::Aes128Gcm,
            key: vec![0u8; 16],
            iv: [0xa5; 12],
        };
        let mut p = RecordProtector::new(&keys).unwrap();
        assert_eq!(p.nonce(), [0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5]);
        p.seq = 1;
        assert_eq!(p.nonce()[11], 0xa4);
        p.seq = 0x0102_0304_0506_0708;
        let n = p.nonce();
        assert_eq!(&n[4..], &[0xa4, 0xa7, 0xa6, 0xa1, 0xa0, 0xa3, 0xa2, 0xad]);
    }

    // --- rustls as the counterparty ------------------------------------

    fn provider_with(suites: Vec<rustls::SupportedCipherSuite>) -> Arc<rustls::crypto::CryptoProvider> {
        let mut provider = rustls::crypto::ring::default_provider();
        provider.cipher_suites = suites;
        Arc::new(provider)
    }

    struct TestCert {
        der: Vec<u8>,
        key: rustls::pki_types::PrivateKeyDer<'static>,
    }

    fn self_signed(name: &str, alg: &'static rcgen::SignatureAlgorithm) -> TestCert {
        let key_pair = rcgen::KeyPair::generate_for(alg).unwrap();
        let params = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        TestCert {
            der: cert.der().to_vec(),
            key: rustls::pki_types::PrivateKeyDer::Pkcs8(key_pair.serialize_der().into()),
        }
    }

    /// Serve `n` echoes over a real rustls server, then close.
    async fn rustls_echo_server(
        listener: tokio::net::TcpListener,
        config: Arc<rustls::ServerConfig>,
        rounds: usize,
    ) {
        for _ in 0..rounds {
            let (sock, _) = listener.accept().await.unwrap();
            let acceptor = tokio_rustls::TlsAcceptor::from(config.clone());
            let mut tls = acceptor.accept(sock).await.unwrap();
            let mut buf = [0u8; 1024];
            loop {
                let n = tokio::io::AsyncReadExt::read(&mut tls, &mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                // Fragment the reply to exercise record reassembly.
                let mut off = 0;
                while off < n {
                    let take = (n - off).min(7);
                    tls.write_all(&buf[off..off + take]).await.unwrap();
                    off += take;
                }
                tls.flush().await.unwrap();
            }
        }
    }

    /// Drive a real rustls server over loopback TCP. The returned handle is
    /// the echo server task; it ends when the client drops its stream, so
    /// callers must NOT await it while the connection is still open.
    async fn loopback(
        suites: Vec<rustls::SupportedCipherSuite>,
        alg: &'static rcgen::SignatureAlgorithm,
        auth: impl FnOnce(&TestCert) -> ServerAuth,
        profile: UtslProfile,
    ) -> Result<(Tls13Stream, tokio::task::JoinHandle<()>)> {
        let cert = self_signed("localhost", alg);
        let provider = provider_with(suites);
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.der.clone().into()], cert.key.clone_key())
            .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        config.send_tls13_tickets = 2;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(rustls_echo_server(listener, Arc::new(config), 1));

        let sock = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let session_id: [u8; 32] = {
            let mut s = [0u8; 32];
            rand::rngs::OsRng.fill_bytes(&mut s);
            s
        };
        let (secret, public) = x25519_keygen();
        let hello = build_client_hello(profile, "localhost", &random, &session_id, &public);
        let stream = connect(Box::new(sock), &hello, &secret, auth(&cert)).await?;
        Ok((stream, server))
    }

    fn webpki_auth(cert: &TestCert) -> ServerAuth {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert.der.clone().into()).unwrap();
        ServerAuth::WebPki {
            roots: Arc::new(roots),
            server_name: "localhost".to_string(),
        }
    }

    async fn echo_round_trip(mut stream: Tls13Stream) -> Tls13Stream {
        use tokio::io::AsyncReadExt;
        stream.write_all(b"hello tls 1.3").await.unwrap();
        let mut buf = [0u8; 13];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello tls 1.3");
        // A second round with a large payload (multi-record + fragmentation).
        let big: Vec<u8> = (0..8_000u32).map(|i| (i % 251) as u8).collect();
        let expect = big.clone();
        let (mut r, mut w) = tokio::io::split(stream);
        let writer = tokio::spawn(async move {
            w.write_all(&big).await.unwrap();
            w.shutdown().await.unwrap();
            w
        });
        let mut got = Vec::new();
        r.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, expect);
        let w = writer.await.unwrap();
        r.unsplit(w)
    }

    #[tokio::test]
    async fn rustls_loopback_aes128_and_echo() {
        let (stream, server) = loopback(
            vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256],
            &rcgen::PKCS_ECDSA_P256_SHA256,
            webpki_auth,
            UtslProfile::Chrome,
        )
        .await
        .expect("handshake against rustls");
        assert_eq!(stream.suite(), CipherSuite::Aes128GcmSha256);
        assert_eq!(stream.alpn(), Some(&b"h2"[..]));
        assert!(stream.cert_verified());
        let stream = echo_round_trip(stream).await;
        drop(stream);
        let _ = server.await;
    }

    #[tokio::test]
    async fn rustls_loopback_chacha20_and_echo() {
        let (stream, server) = loopback(
            vec![rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256],
            &rcgen::PKCS_ECDSA_P256_SHA256,
            webpki_auth,
            UtslProfile::Firefox,
        )
        .await
        .expect("handshake against rustls");
        assert_eq!(stream.suite(), CipherSuite::Chacha20Poly1305Sha256);
        let stream = echo_round_trip(stream).await;
        drop(stream);
        let _ = server.await;
    }

    #[tokio::test]
    async fn webpki_rejects_an_unknown_ca() {
        // A root store that holds a *different* self-signed CA.
        let other = self_signed("other.test", &rcgen::PKCS_ECDSA_P256_SHA256);
        let err = loopback(
            vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256],
            &rcgen::PKCS_ECDSA_P256_SHA256,
            move |_| {
                let mut roots = rustls::RootCertStore::empty();
                roots.add(other.der.clone().into()).unwrap();
                ServerAuth::WebPki {
                    roots: Arc::new(roots),
                    server_name: "localhost".to_string(),
                }
            },
            UtslProfile::Chrome,
        )
        .await
        .expect_err("an unknown CA must fail");
        assert!(
            err.to_string().contains("certificate verification failed"),
            "{err}"
        );

        // An empty store cannot even build a verifier: that must be a config
        // error, not a silent accept.
        let err = loopback(
            vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256],
            &rcgen::PKCS_ECDSA_P256_SHA256,
            |_| ServerAuth::WebPki {
                roots: Arc::new(rustls::RootCertStore::empty()),
                server_name: "localhost".to_string(),
            },
            UtslProfile::Chrome,
        )
        .await
        .expect_err("an empty root store must fail");
        assert!(!err.to_string().is_empty(), "{err}");
    }

    #[tokio::test]
    async fn webpki_checks_the_name() {
        let err = loopback(
            vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256],
            &rcgen::PKCS_ECDSA_P256_SHA256,
            |cert| {
                let mut roots = rustls::RootCertStore::empty();
                roots.add(cert.der.clone().into()).unwrap();
                ServerAuth::WebPki {
                    roots: Arc::new(roots),
                    server_name: "other.test".to_string(),
                }
            },
            UtslProfile::Chrome,
        )
        .await
        .expect_err("a name mismatch must fail");
        assert!(err.to_string().contains("certificate verification failed"), "{err}");
    }

    #[tokio::test]
    async fn custom_auth_verdict_does_not_abort_the_handshake() {
        let checked = Arc::new(AtomicBool::new(false));
        let flag = checked.clone();
        let stream = loopback(
            vec![rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256],
            &rcgen::PKCS_ECDSA_P256_SHA256,
            move |_| {
                ServerAuth::Callback(Box::new(move |_leaf| {
                    flag.store(true, Ordering::SeqCst);
                    Ok(false) // "this is a real certificate, not a REALITY one"
                }))
            },
            UtslProfile::Chrome,
        )
        .await
        .expect("handshake must complete");
        let (stream, server) = stream;
        assert!(checked.load(Ordering::SeqCst), "callback ran");
        assert!(!stream.cert_verified());
        let stream = echo_round_trip(stream).await;
        drop(stream);
        let _ = server.await;
    }

    /// `0x1302` (`TLS_AES_256_GCM_SHA384`) must work end to end, SHA-384 key
    /// schedule included. REALITY needs it: its ServerHello is the camouflage
    /// site's own, so a `dest` that prefers AES-256-GCM hands the client a
    /// SHA-384 suite (`crypto/tls` prefers it over 0x1301/0x1303). rustls
    /// restricted to that single suite is an independent implementation of
    /// the schedule, so a completed 8 KiB echo is the interop proof.
    #[tokio::test]
    async fn rustls_loopback_aes256gcm_sha384_and_echo() {
        let (stream, server) = loopback(
            vec![rustls::crypto::ring::cipher_suite::TLS13_AES_256_GCM_SHA384],
            &rcgen::PKCS_ECDSA_P256_SHA256,
            webpki_auth,
            UtslProfile::Chrome,
        )
        .await
        .expect("handshake against rustls");
        assert_eq!(stream.suite(), CipherSuite::Aes256GcmSha384);
        assert_eq!(stream.alpn(), Some(&b"h2"[..]));
        assert!(stream.cert_verified());
        let stream = echo_round_trip(stream).await;
        drop(stream);
        let _ = server.await;
    }

    /// Codepoints outside the implemented set are still refused, and the
    /// suite's hash is what decides the schedule.
    #[test]
    fn cipher_suite_ids_and_hashes() {
        assert_eq!(CipherSuite::from_id(0x1301), Some(CipherSuite::Aes128GcmSha256));
        assert_eq!(CipherSuite::from_id(0x1302), Some(CipherSuite::Aes256GcmSha384));
        assert_eq!(
            CipherSuite::from_id(0x1303),
            Some(CipherSuite::Chacha20Poly1305Sha256)
        );
        for id in [0x1304u16, 0x1305, 0xc02f, 0x0000, 0xffff] {
            assert!(
                CipherSuite::from_id(id).is_none(),
                "{id:#06x} must be rejected"
            );
        }
        assert_eq!(CipherSuite::Aes256GcmSha384.id(), 0x1302);
        assert_eq!(CipherSuite::Aes256GcmSha384.key_len(), 32);
        assert_eq!(CipherSuite::Aes256GcmSha384.hash(), HashKind::Sha384);
        assert_eq!(CipherSuite::Aes128GcmSha256.hash(), HashKind::Sha256);
        assert_eq!(CipherSuite::Chacha20Poly1305Sha256.hash(), HashKind::Sha256);
    }

    #[tokio::test]
    async fn our_own_server_path_round_trips_with_ed25519() {
        // Ed25519 CertificateVerify (the scheme REALITY's fake cert uses) is
        // exercised by the in-tree server, since rustls will not pick Ed25519
        // for Chrome's signature_algorithms list.
        let cert = self_signed("localhost", &rcgen::PKCS_ED25519);
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&cert.key).unwrap();
        let der = cert.der.clone();
        let (client, server) = tokio::io::duplex(64 * 1024);

        let server_task = tokio::spawn(async move {
            let (mut tls, hello) = test_server::accept(
                Box::new(server),
                CipherSuite::Aes128GcmSha256,
                move |_| Ok((der.clone(), signing_key.clone())),
            )
            .await
            .unwrap();
            assert_eq!(hello.sni.as_deref(), Some("localhost"));
            assert_eq!(hello.session_id.len(), 32);
            let mut buf = [0u8; 64];
            let n = tokio::io::AsyncReadExt::read(&mut tls, &mut buf).await.unwrap();
            tls.write_all(&buf[..n]).await.unwrap();
            tls.flush().await.unwrap();
            tls
        });

        let mut random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let session_id = [7u8; 32];
        let (secret, public) = x25519_keygen();
        let hello = build_client_hello(UtslProfile::Chrome, "localhost", &random, &session_id, &public);
        let mut stream = connect(
            Box::new(client),
            &hello,
            &secret,
            ServerAuth::AcceptAny,
        )
        .await
        .unwrap();
        assert!(stream.cert_verified());
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 4];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf)
            .await
            .unwrap();
        assert_eq!(&buf, b"ping");
        let server_stream = server_task.await.unwrap();
        assert_eq!(server_stream.alpn(), Some(&b"h2"[..]));
        assert!(
            server_stream.peer_ccs() >= 1,
            "the client sends the middlebox-compat dummy ChangeCipherSpec"
        );
    }
}