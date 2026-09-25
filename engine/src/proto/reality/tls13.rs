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
//! * No PSK/resumption/0-RTT/client auth/certificate compression.
//!   `NewSessionTicket` is ignored, `KeyUpdate` is honoured. ECH (RFC 9460)
//!   lives in a separate entry point, [`connect_ech`], and never touches the
//!   non-ECH path.
//!
//! The key schedule and record layer are pinned against the RFC 8448
//! handshake trace and against a real rustls server (see the tests).

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use hkdf::Hkdf;
use rand::RngCore;
use ring::signature;
use sha2::{Digest, Sha256, Sha384};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::error::{Error, Result};
use crate::proto::aead::{Aead, AeadKind};
use crate::proto::ech;
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
// ECH hello-construction codepoints (metacubex/tls handshake_messages.go
// marshal order; see the ECH client section below).
const EXT_SERVER_NAME: u16 = 0x0000;
const EXT_STATUS_REQUEST: u16 = 0x0005;
const EXT_SUPPORTED_GROUPS: u16 = 0x000a;
const EXT_EC_POINT_FORMATS: u16 = 0x000b;
const EXT_SIGNATURE_ALGORITHMS: u16 = 0x000d;
const EXT_SCTS: u16 = 0x0012;
const EXT_EXTENDED_MASTER_SECRET_ECH: u16 = 0x0017;
const EXT_SESSION_TICKET: u16 = 0x0023;
const EXT_COOKIE: u16 = 0x002c;
const EXT_PSK_KEY_EXCHANGE_MODES_ECH: u16 = 0x002d;
const EXT_RENEGOTIATION_INFO: u16 = 0xff01;
/// `alert_ech_required` (RFC 9460 §7; metacubex/tls `alertECHRequired`).
const ALERT_ECH_REQUIRED: u8 = 121;
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
        const OID_RSA: &[u8] = &[
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
        ];

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
    kind: HashKind,
    inner: TranscriptHash,
}

impl Transcript {
    fn new(hash: HashKind) -> Self {
        Transcript {
            kind: hash,
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

    /// RFC 8446 §4.4.1 message_hash fold for the HelloRetryRequest path: a
    /// fresh transcript holding only `[254, 0, 0, len] ‖ hash(self)`. The
    /// ECH client folds both its inner and outer transcripts this way
    /// (metacubex/tls handshake_client_tls13.go:238-244 and :249-253).
    fn fold_message_hash(&self) -> Transcript {
        let digest = self.hash();
        let mut folded = Transcript::new(self.kind);
        let mut wrap = Vec::with_capacity(4 + digest.len());
        wrap.push(254); // message_hash
        wrap.push(0);
        wrap.push(0);
        wrap.push(digest.len() as u8);
        wrap.extend_from_slice(&digest);
        folded.update(&wrap);
        folded
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
pub type CertCallback = Box<dyn Fn(&[u8]) -> Result<bool> + Send + Sync>;

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
            )));
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
                ));
            }
            _ => {}
        }
    }
    match selected_version {
        Some(v) if v == VERSION_TLS13 => {}
        Some(v) => {
            return Err(Error::protocol(format!(
                "tls13: server negotiated version {v:#06x}, this client is TLS 1.3 only"
            )));
        }
        None => {
            return Err(Error::protocol(
                "tls13: ServerHello has no supported_versions extension",
            ));
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
        return Err(Error::protocol(
            "tls13: server sent an empty certificate chain",
        ));
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
            )));
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
                )));
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
                )));
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
    if client_hello.len() < super::profiles::SESSION_ID_OFFSET + 32
        || client_hello[0] != HS_CLIENT_HELLO
    {
        return Err(Error::protocol("tls13: malformed ClientHello"));
    }
    let mut expected_session_id = [0u8; 32];
    expected_session_id.copy_from_slice(&client_hello[super::profiles::SESSION_ID_OFFSET..][..32]);

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
    t.write_all(&[RECORD_CCS, 0x03, 0x03, 0x00, 0x01, 0x01])
        .await?;

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
        read_spliced: false,
        write_spliced: false,
        splice_prefix: Vec::new(),
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
        .verify_server_cert(&end_entity, &intermediates, &name, &[], UnixTime::now())
        .map_err(|e| Error::protocol(format!("tls13: certificate verification failed: {e}")))?;
    Ok(())
}

// --- ECH client (RFC 9460, ported from metacubex/tls) --------------------
//
// `connect_ech` drives a TLS 1.3 handshake whose ClientHello is split into
// an inner hello (the real SNI/ALPN, HPKE-sealed) and an outer hello (the
// ECHConfig's public_name in the clear). The pieces and their sources:
//
// * inner/outer shaping — `makeClientHello` + the ECH split in
//   `clientHandshake` (handshake_client.go:167-199, :250-275) over the
//   `marshalMsg(echInner)` rules (handshake_messages.go:103-345): the inner
//   drops the four legacy-compat extensions (`ec_point_formats` 0x000b,
//   `session_ticket` 0x0023, `renegotiation_info` 0xff01,
//   `extended_master_secret` 0x0017), carries
//   `encrypted_client_hello = [0x01]`, and is wire-serialized with an EMPTY
//   legacy_session_id; the transcript form restores the OUTER session id.
//   The outer replaces the SNI with the public name, draws a fresh random,
//   and carries the sealed payload. The wire inner is padded per
//   `encodeInnerClientHello` (ech.go:197-216) and sealed with the whole
//   serialized outer body as AAD (`computeAndUpdateOuterECHExtension`,
//   ech.go:418-449 — here `ech::compute_outer_ech_ext`).
//   DELTA vs upstream: the inner does not compress outer-mirrored
//   extensions through `ech_outer_extensions` (0xfd00) — RFC 9460 §6.1
//   makes the compression optional, the ciphertext is only marginally
//   larger, and `ech::decode_inner_client_hello` accepts both forms.
// * accept confirmation — `handshake_client_tls13.go:86-116` (normal
//   ServerHello: the last 8 bytes of the random) and `:255-281` (HRR: the
//   8-byte ECH extension value), both over the inner transcript with the
//   confirmation slot zeroed, PRK = HKDF-Extract(inner random), label
//   `"ech accept confirmation"` / `"hrr ech accept confirmation"`. On
//   acceptance the ACTIVE transcript rebinds to the inner one
//   (`hs.transcript = innerTranscript`, handshake_client_tls13.go:101).
// * rejection — the handshake completes against the OUTER hello, the
//   chain is verified against the PUBLIC name while the peer-certificate
//   callback is skipped (`verifyServerCertificate`'s `echRejected` branch,
//   handshake_client.go:1081-1145), retry configs are captured from the
//   EncryptedExtensions `encrypted_client_hello` extension
//   (handshake_client_tls13.go:577-585), and the connection ends with
//   alert `ech_required` and the `ECHRejectionError` text
//   `"tls: server rejected ECH"` (ech.go:486-492). `connect_ech` retries
//   exactly once when the retry list parses and picks (the dial-closure
//   equivalent of the caller-side retry the upstream error invites).

/// Determinism hooks for [`connect_ech`] tests; every field is `None` in
/// production and the value comes from `OsRng` instead.
#[derive(Debug, Clone)]
pub struct EchHandshakeParams {
    /// The picked ECHConfig + HPKE AEAD (`ech::select_ech_config` on the
    /// configured ECHConfigList wire bytes).
    pub selection: ech::EchConfigSelection,
    /// Fixed inner-hello random.
    pub inner_random: Option<[u8; 32]>,
    /// Fixed outer-hello random.
    pub outer_random: Option<[u8; 32]>,
    /// Fixed legacy session id.
    pub session_id: Option<[u8; 32]>,
    /// Fixed X25519 ECDHE secret (inner and outer share one key share).
    pub x25519_secret: Option<[u8; 32]>,
    /// Fixed HPKE ephemeral secret.
    pub hpke_secret: Option<[u8; 32]>,
}

/// Fingerprint-TLS-with-ECH configuration for [`connect_ech`].
#[derive(Debug, Clone)]
pub struct EchCfg {
    /// The real (inner) server name: the SNI inside the sealed hello and
    /// the name the certificate must verify against once ECH is accepted.
    pub server_name: String,
    /// ClientHello template the inner/outer hellos are shaped from.
    pub profile: super::profiles::UtslProfile,
    /// ALPN list; empty means the profile's own list (h2, http/1.1).
    pub alpn: Vec<String>,
    pub ech: EchHandshakeParams,
}

impl EchCfg {
    /// Config with the profile's default ALPN list.
    pub fn new(
        server_name: impl Into<String>,
        profile: super::profiles::UtslProfile,
        selection: ech::EchConfigSelection,
    ) -> Self {
        EchCfg {
            server_name: server_name.into(),
            profile,
            alpn: Vec::new(),
            ech: EchHandshakeParams {
                selection,
                inner_random: None,
                outer_random: None,
                session_id: None,
                x25519_secret: None,
                hpke_secret: None,
            },
        }
    }
}

/// The outcome of one ECH handshake attempt; `Rejected` carries the
/// server's retry ECHConfigList when it sent one (`ECHRejectionError`,
/// ech.go:486-492).
enum EchAttemptError {
    Fatal(Error),
    Rejected { retry_configs: Vec<u8> },
}

impl From<Error> for EchAttemptError {
    fn from(e: Error) -> Self {
        EchAttemptError::Fatal(e)
    }
}

/// Connect with ECH (RFC 9460) over transports produced by `dial`.
///
/// `dial` is called once per attempt (twice at most: one retry with the
/// server's retry configs, mirroring the caller-side retry upstream's
/// `ECHRejectionError.RetryConfigList` invites). `auth` names the INNER
/// server — on ECH acceptance the certificate is verified against
/// [`EchCfg::server_name`], exactly like upstream's rebind of
/// `c.serverName` to `config.ServerName` (handshake_client_tls13.go:99-100).
/// On rejection the rejected handshake verifies against the ECHConfig's
/// public name instead (handshake_client.go:1081-1104) and the caller sees
/// the upstream error `"tls: server rejected ECH"`; there is no silent
/// outer-mode fallback.
pub async fn connect_ech<D, F>(cfg: &EchCfg, auth: &ServerAuth, mut dial: D) -> Result<Tls13Stream>
where
    D: FnMut() -> F,
    F: Future<Output = Result<BoxProxyStream>> + Send,
{
    let mut selection = cfg.ech.selection.clone();
    for attempt in 0..2 {
        let transport = dial().await?;
        match ech_attempt(cfg, &selection, auth, transport).await {
            Ok(stream) => return Ok(stream),
            Err(EchAttemptError::Fatal(e)) => return Err(e),
            Err(EchAttemptError::Rejected { retry_configs }) => {
                if attempt == 1 {
                    return Err(Error::protocol("tls: server rejected ECH"));
                }
                // Retry once, only when the server's configs are usable.
                match ech::select_ech_config(&retry_configs) {
                    Ok(next) => selection = next,
                    Err(_) => return Err(Error::protocol("tls: server rejected ECH")),
                }
            }
        }
    }
    unreachable!("the retry loop returns on its second rejection")
}

/// `hkdf.Extract(h, innerHello.random, nil)` + `tls13ExpandLabel` for the
/// ECH accept confirmation, generic over the suite hash — the port of
/// handshake_client_tls13.go:86-98. SHA-256 agrees byte for byte with
/// [`ech::server_hello_accept_confirmation`] (pinned by a unit test).
fn ech_accept_confirmation(
    hash: HashKind,
    inner_transcript: &Transcript,
    server_hello_msg: &[u8],
    inner_client_random: &[u8; 32],
) -> Result<[u8; 8]> {
    if server_hello_msg.len() < 38 {
        return Err(Error::protocol(
            "tls: malformed encrypted_client_hello extension",
        ));
    }
    let mut conf = inner_transcript.clone();
    conf.update(&server_hello_msg[..30]);
    conf.update(&[0u8; 8]);
    conf.update(&server_hello_msg[38..]);
    let digest = conf.hash();
    let prk = hkdf_extract(hash, &[], inner_client_random);
    let mut out = [0u8; 8];
    hash.hkdf_expand_label(&prk, "ech accept confirmation", &digest, &mut out)?;
    Ok(out)
}

/// The HRR variant (`handshake_client_tls13.go:261-272`): the whole HRR
/// message with its 8-byte ECH extension value replaced by zeros is hashed
/// onto the (already folded) inner transcript; the label is
/// `"hrr ech accept confirmation"`.
fn ech_hrr_confirmation(
    hash: HashKind,
    inner_transcript: &Transcript,
    hrr_msg: &[u8],
    ech_ext_value: &[u8],
    inner_client_random: &[u8; 32],
) -> Result<[u8; 8]> {
    if ech_ext_value.len() != 8 {
        return Err(Error::protocol(
            "tls: malformed encrypted_client_hello extension",
        ));
    }
    let mut hrr = hrr_msg.to_vec();
    let pos = hrr
        .windows(8)
        .position(|w| w == ech_ext_value)
        .ok_or_else(|| Error::protocol("tls: hrr without the ECH extension value"))?;
    hrr[pos..pos + 8].fill(0);
    let mut conf = inner_transcript.clone();
    conf.update(&hrr);
    let digest = conf.hash();
    let prk = hkdf_extract(hash, &[], inner_client_random);
    let mut out = [0u8; 8];
    hash.hkdf_expand_label(&prk, "hrr ech accept confirmation", &digest, &mut out)?;
    Ok(out)
}

/// A ServerHello-or-HRR as the ECH client needs it. Unlike
/// [`parse_server_hello`] this accepts the HelloRetryRequest random and
/// surfaces the ECH/cookie extensions an HRR may carry.
struct EchServerHello {
    is_hrr: bool,
    cipher_suite: u16,
    session_id: Vec<u8>,
    /// The 8-byte ECH extension value of an HRR (absent in a normal SH).
    ech_ext: Option<Vec<u8>>,
    cookie: Option<Vec<u8>>,
    selected_group: Option<u16>,
    /// Server X25519 share (normal ServerHello only).
    share: Vec<u8>,
}

fn parse_server_hello_ech(msg: &[u8]) -> Result<EchServerHello> {
    let b = msg
        .get(4..)
        .ok_or_else(|| Error::protocol("tls13: short ServerHello"))?;
    let random = b
        .get(2..34)
        .ok_or_else(|| Error::protocol("tls13: short ServerHello random"))?;
    let is_hrr = random == HRR_RANDOM.as_slice();
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
            )));
        }
        None => return Err(Error::protocol("tls13: short ServerHello")),
    }
    off += 1;
    let mut selected_version = None;
    let mut share = None;
    let mut ech_ext = None;
    let mut cookie = None;
    let mut selected_group = None;
    for (typ, body) in extensions(b.get(off..).unwrap_or_default())? {
        match typ {
            EXT_SUPPORTED_VERSIONS => selected_version = Some(u16_at(body, 0)?),
            EXT_KEY_SHARE => {
                if !is_hrr {
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
                } else {
                    selected_group = Some(u16_at(body, 0)?);
                }
            }
            ech::EXTENSION_ENCRYPTED_CLIENT_HELLO => {
                // Only meaningful in an HRR; a normal ServerHello carrying
                // ECH is handled by the caller (the accepted case must not
                // see one at all).
                ech_ext = Some(body.to_vec());
            }
            EXT_COOKIE => cookie = Some(body.to_vec()),
            EXT_PRE_SHARED_KEY => {
                return Err(Error::protocol(
                    "tls13: server selected a PSK we never offered",
                ));
            }
            _ => {}
        }
    }
    match selected_version {
        Some(v) if v == VERSION_TLS13 => {}
        Some(v) => {
            return Err(Error::protocol(format!(
                "tls13: server negotiated version {v:#06x}, this client is TLS 1.3 only"
            )));
        }
        None => {
            return Err(Error::protocol(
                "tls13: ServerHello has no supported_versions extension",
            ));
        }
    }
    if !is_hrr {
        let share = share.ok_or_else(|| Error::protocol("tls13: ServerHello has no key_share"))?;
        if share.len() != 32 {
            return Err(Error::protocol("tls13: X25519 key share is not 32 bytes"));
        }
        Ok(EchServerHello {
            is_hrr: false,
            cipher_suite,
            session_id,
            ech_ext,
            cookie,
            selected_group,
            share,
        })
    } else {
        Ok(EchServerHello {
            is_hrr: true,
            cipher_suite,
            session_id,
            ech_ext,
            cookie,
            selected_group,
            share: Vec::new(),
        })
    }
}

/// The extension block (u16 total included) of a hello handshake message,
/// via the canonical field walk (session id, cipher suites, compression).
fn hello_ext_block(msg: &[u8]) -> Result<&[u8]> {
    let b = msg
        .get(4..)
        .ok_or_else(|| Error::protocol("tls13: short hello"))?;
    let sid_len = *b
        .get(34)
        .ok_or_else(|| Error::protocol("tls13: short hello"))? as usize;
    let mut off = 35 + sid_len;
    let cs_len = u16_at(b, off)? as usize;
    off += 2 + cs_len;
    let comp_len = *b
        .get(off)
        .ok_or_else(|| Error::protocol("tls13: short hello"))? as usize;
    off += 1 + comp_len;
    b.get(off..)
        .ok_or_else(|| Error::protocol("tls13: short hello"))
}

/// Find one extension body in a hello's extension block.
fn find_hello_ext(msg: &[u8], want: u16) -> Result<Option<Vec<u8>>> {
    for (typ, body) in extensions(hello_ext_block(msg)?)? {
        if typ == want {
            return Ok(Some(body.to_vec()));
        }
    }
    Ok(None)
}

/// The retry ECHConfigList out of an EncryptedExtensions message (the
/// `encrypted_client_hello` extension of the EE,
/// handshake_client_tls13.go:577-585 / handshake_messages.go:1039-1042).
fn ee_retry_configs(ee_msg: &[u8]) -> Result<Option<Vec<u8>>> {
    let body = ee_msg
        .get(4..)
        .ok_or_else(|| Error::protocol("tls13: short EncryptedExtensions"))?;
    for (typ, data) in extensions(body)? {
        if typ == ech::EXTENSION_ENCRYPTED_CLIENT_HELLO {
            return Ok(Some(data.to_vec()));
        }
    }
    Ok(None)
}

/// One `(type, body)` extension list serialized into a ClientHello
/// extension block body (everything after the u16 total, which
/// [`serialize_ech_hello`] writes).
fn ech_ext_block(exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (typ, body) in exts {
        out.extend_from_slice(&typ.to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
    }
    out
}

/// Serialize an ECH hello: `legacy_version 0x0303 ‖ random ‖
/// legacy_session_id (empty when None) ‖ cipher_suites ‖ compression ‖
/// extensions` behind the 4-byte handshake header. `None` produces the
/// WIRE (encoded) inner form; `Some` the transcript form — the two differ
/// only in the session id (handshake_messages.go:353-357).
fn serialize_ech_hello(
    random: &[u8; 32],
    session_id: Option<&[u8; 32]>,
    suites_comp: &[u8],
    exts: &[(u16, Vec<u8>)],
) -> Vec<u8> {
    let mut body = Vec::with_capacity(2 + 32 + 1 + suites_comp.len() + 2 + 64);
    body.extend_from_slice(&VERSION_TLS12.to_be_bytes());
    body.extend_from_slice(random);
    match session_id {
        Some(sid) => {
            body.push(sid.len() as u8);
            body.extend_from_slice(sid);
        }
        None => body.push(0),
    }
    body.extend_from_slice(suites_comp);
    let block = ech_ext_block(exts);
    body.extend_from_slice(&(block.len() as u16).to_be_bytes());
    body.extend_from_slice(&block);
    let mut msg = Vec::with_capacity(4 + body.len());
    msg.push(HS_CLIENT_HELLO);
    let len = body.len();
    msg.push((len >> 16) as u8);
    msg.push((len >> 8) as u8);
    msg.push(len as u8);
    msg.extend_from_slice(&body);
    msg
}

/// The `server_name` extension body (RFC 6066 §3, one host_name entry).
fn ech_sni_body(name: &[u8]) -> Vec<u8> {
    let mut entry = Vec::with_capacity(3 + name.len());
    entry.push(0); // name_type = host_name
    entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
    entry.extend_from_slice(name);
    let mut body = Vec::with_capacity(2 + entry.len());
    body.extend_from_slice(&(entry.len() as u16).to_be_bytes());
    body.extend_from_slice(&entry);
    body
}

/// Insert the HRR `cookie` extension at its canonical slot (between
/// `supported_versions` and `key_share`, handshake_messages.go:256-265).
fn ech_insert_cookie(exts: &mut Vec<(u16, Vec<u8>)>, cookie: &[u8]) {
    let pos = exts
        .iter()
        .position(|(t, _)| *t == EXT_KEY_SHARE)
        .unwrap_or(exts.len());
    exts.insert(pos, (EXT_COOKIE, cookie.to_vec()));
}

/// The inner/outer hello pair of one ECH attempt, plus everything the HRR
/// second flight needs to rebuild them.
struct EchHelloSet {
    // fresh material of this attempt
    inner_random: [u8; 32],
    outer_random: [u8; 32],
    session_id: [u8; 32],
    x25519_secret: [u8; 32],
    // template pieces (canonical fork order; ECH ext appended at seal time)
    suites_comp: Vec<u8>,
    inner_exts: Vec<(u16, Vec<u8>)>,
    outer_exts: Vec<(u16, Vec<u8>)>,
    public_name: String,
    /// The real (inner) SNI bytes — the ECH padding input.
    inner_sni_bytes: Vec<u8>,
    max_name_length: usize,
    config_id: u8,
    kdf_id: u16,
    aead_id: u16,
    // built forms
    /// Transcript-form inner (32-byte session id): what the transcript runs
    /// over once ECH is accepted.
    inner_msg: Vec<u8>,
    /// The outer hello as sent (public SNI, sealed payload).
    outer_msg: Vec<u8>,
}

impl EchHelloSet {
    /// Build the pair: the inner from the profile template with the real
    /// SNI minus the four legacy-compat extensions plus the `[0x01]` marker,
    /// the outer with the public SNI, a fresh random and the HPKE-sealed
    /// encoded inner (metacubex/tls handshake_client.go:250-275 over the
    /// `marshalMsg(echInner)` rules).
    #[allow(clippy::too_many_arguments)]
    fn build(
        cfg: &EchCfg,
        selection: &ech::EchConfigSelection,
        inner_random: [u8; 32],
        outer_random: [u8; 32],
        session_id: [u8; 32],
        x25519_secret: [u8; 32],
        hpke_secret: &[u8; 32],
    ) -> Result<(EchHelloSet, ech::HpkeSender)> {
        let config = &selection.config;
        let public: [u8; 32] = config
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| Error::config("tls13: ECH public key is not 32 bytes"))?;
        let public_share =
            curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(x25519_secret).0;

        // Base template: the profile machinery with the REAL server name.
        let alpn = if cfg.alpn.is_empty() {
            None
        } else {
            Some(cfg.alpn.as_slice())
        };
        let base = super::profiles::build_client_hello_alpn(
            cfg.profile,
            &cfg.server_name,
            &inner_random,
            &session_id,
            &public_share,
            alpn,
        );
        let body = &base[4..];
        // vers(2) random(32) sid_len(1)=32 sid(32) suites(u16-pref) comp(u8-pref)
        let suites_len = u16::from_be_bytes([body[67], body[68]]) as usize;
        // cipher_suites (u16-prefixed) plus compression methods
        // (u8-length 1 + the null method) — copied verbatim.
        let suites_comp = body[67..67 + 2 + suites_len + 2].to_vec();
        let base_exts = extensions(&body[67 + 2 + suites_len + 2..])?;
        let find = |want: u16| {
            base_exts
                .iter()
                .find(|(t, _)| *t == want)
                .map(|(_, b)| b.to_vec())
        };

        // supported_versions without anything below TLS 1.3 (the inner must
        // offer 1.3 only — metacubex/tls decodeInnerClientHello rejects a
        // non-GREASE version < 0x0304, ech.go:374-394; GREASE stays).
        let mut versions = Vec::new();
        if let Some(v) = find(EXT_SUPPORTED_VERSIONS) {
            let list = &v[1..];
            let mut i = 0;
            while i + 2 <= list.len() {
                let ver = u16::from_be_bytes([list[i], list[i + 1]]);
                let grease = ver & 0x0f0f == 0x0a0a && ver & 0xff == ver >> 8;
                if grease || ver == VERSION_TLS13 {
                    versions.extend_from_slice(&ver.to_be_bytes());
                }
                i += 2;
            }
        } else {
            versions.extend_from_slice(&VERSION_TLS13.to_be_bytes());
        }
        let versions_body = {
            let mut b = Vec::with_capacity(1 + versions.len());
            b.push(versions.len() as u8);
            b.extend_from_slice(&versions);
            b
        };

        // Inner: real SNI, scts, the [0x01] marker, then the negotiation
        // extensions (canonical fork marshal order).
        let inner_exts: Vec<(u16, Vec<u8>)> = vec![
            (EXT_SERVER_NAME, ech_sni_body(cfg.server_name.as_bytes())),
            (EXT_SCTS, Vec::new()),
            (
                ech::EXTENSION_ENCRYPTED_CLIENT_HELLO,
                vec![1], // inner marker (ech.go:186)
            ),
            (
                EXT_STATUS_REQUEST,
                find(EXT_STATUS_REQUEST).unwrap_or_else(|| vec![0x01, 0x00, 0x00, 0x00, 0x00]),
            ),
            (
                EXT_SUPPORTED_GROUPS,
                find(EXT_SUPPORTED_GROUPS).unwrap_or_else(|| {
                    let mut b = Vec::new();
                    b.extend_from_slice(&2u16.to_be_bytes());
                    b.extend_from_slice(&GROUP_X25519.to_be_bytes());
                    b
                }),
            ),
            (
                EXT_SIGNATURE_ALGORITHMS,
                find(EXT_SIGNATURE_ALGORITHMS)
                    .unwrap_or_else(|| vec![0x00, 0x04, 0x04, 0x03, 0x08, 0x04]),
            ),
            (EXT_ALPN, find(EXT_ALPN).unwrap_or_default()),
            (EXT_SUPPORTED_VERSIONS, versions_body.clone()),
            (EXT_KEY_SHARE, find(EXT_KEY_SHARE).unwrap_or_default()),
            (
                EXT_PSK_KEY_EXCHANGE_MODES_ECH,
                find(EXT_PSK_KEY_EXCHANGE_MODES_ECH).unwrap_or_else(|| vec![0x01, 0x01]),
            ),
        ];
        // Outer: public SNI + the legacy-compat extensions the inner drops,
        // then the same negotiation set (the ECH ext slots in after scts).
        let outer_exts: Vec<(u16, Vec<u8>)> = vec![
            (EXT_SERVER_NAME, ech_sni_body(&config.public_name)),
            (
                EXT_EC_POINT_FORMATS,
                find(EXT_EC_POINT_FORMATS).unwrap_or_else(|| vec![0x01, 0x00]),
            ),
            (EXT_SESSION_TICKET, Vec::new()),
            (EXT_RENEGOTIATION_INFO, vec![0x00]),
            (EXT_EXTENDED_MASTER_SECRET_ECH, Vec::new()),
            (EXT_SCTS, Vec::new()),
            (
                EXT_STATUS_REQUEST,
                find(EXT_STATUS_REQUEST).unwrap_or_else(|| vec![0x01, 0x00, 0x00, 0x00, 0x00]),
            ),
            (
                EXT_SUPPORTED_GROUPS,
                find(EXT_SUPPORTED_GROUPS).unwrap_or_else(|| {
                    let mut b = Vec::new();
                    b.extend_from_slice(&2u16.to_be_bytes());
                    b.extend_from_slice(&GROUP_X25519.to_be_bytes());
                    b
                }),
            ),
            (
                EXT_SIGNATURE_ALGORITHMS,
                find(EXT_SIGNATURE_ALGORITHMS)
                    .unwrap_or_else(|| vec![0x00, 0x04, 0x04, 0x03, 0x08, 0x04]),
            ),
            (EXT_ALPN, find(EXT_ALPN).unwrap_or_default()),
            (EXT_SUPPORTED_VERSIONS, versions_body),
            (EXT_KEY_SHARE, find(EXT_KEY_SHARE).unwrap_or_default()),
            (
                EXT_PSK_KEY_EXCHANGE_MODES_ECH,
                find(EXT_PSK_KEY_EXCHANGE_MODES_ECH).unwrap_or_else(|| vec![0x01, 0x01]),
            ),
        ];

        let public_name = String::from_utf8_lossy(&config.public_name).into_owned();
        let mut set = EchHelloSet {
            inner_random,
            outer_random,
            session_id,
            x25519_secret,
            suites_comp,
            inner_exts,
            outer_exts,
            public_name,
            inner_sni_bytes: cfg.server_name.as_bytes().to_vec(),
            max_name_length: config.max_name_length as usize,
            config_id: config.config_id,
            kdf_id: ech::KDF_HKDF_SHA256,
            aead_id: selection.aead.id(),
            inner_msg: Vec::new(),
            outer_msg: Vec::new(),
        };

        // Wire (encoded) inner: EMPTY session id, then ECH padding.
        let wire = serialize_ech_hello(&inner_random, None, &set.suites_comp, &set.inner_exts);
        let encoded_inner = ech::encode_inner_client_hello(
            &wire[4..],
            Some(cfg.server_name.as_bytes()),
            set.max_name_length,
        );

        // HPKE sender: info = "tls ech\0" ‖ config.raw
        // (handshake_client.go:193-194).
        let (enc, mut sender) = ech::HpkeSender::setup_with(
            &public,
            selection.aead,
            &ech::ech_hpke_info(config),
            hpke_secret,
        )?;

        let ech_ext = set.seal_outer(&mut sender, &enc, &encoded_inner, true, None)?;
        set.inner_msg = serialize_ech_hello(
            &set.inner_random,
            Some(&set.session_id),
            &set.suites_comp,
            &set.inner_exts,
        );
        set.outer_msg = set.serialize_outer_with(&ech_ext, None);
        Ok((set, sender))
    }

    /// `computeAndUpdateOuterECHExtension` (ech.go:418-449): seal the encoded
    /// inner against the placeholder outer serialization. `include_enc`
    /// mirrors upstream's `useKey` — the HRR second flight omits the
    /// encapsulated key.
    fn seal_outer(
        &self,
        sender: &mut ech::HpkeSender,
        enc: &[u8],
        encoded_inner: &[u8],
        include_enc: bool,
        cookie: Option<&[u8]>,
    ) -> Result<Vec<u8>> {
        ech::compute_outer_ech_ext(
            sender,
            self.config_id,
            self.kdf_id,
            self.aead_id,
            enc,
            encoded_inner,
            include_enc,
            |placeholder| self.serialize_outer_with(placeholder, cookie)[4..].to_vec(),
        )
    }

    /// The full outer hello with the given `encrypted_client_hello`
    /// extension body (placeholder or final) at the canonical slot after
    /// `scts`, optionally carrying an HRR cookie.
    fn serialize_outer_with(&self, ech_ext: &[u8], cookie: Option<&[u8]>) -> Vec<u8> {
        let mut exts = self.outer_exts.clone();
        if let Some(cookie) = cookie {
            ech_insert_cookie(&mut exts, cookie);
        }
        // The ECH extension sits right after scts (0x0012), the fork's
        // marshal position (handshake_messages.go:163-170).
        let pos = exts
            .iter()
            .position(|(t, _)| *t == EXT_SCTS)
            .map(|i| i + 1)
            .unwrap_or(exts.len());
        exts.insert(
            pos,
            (ech::EXTENSION_ENCRYPTED_CLIENT_HELLO, ech_ext.to_vec()),
        );
        serialize_ech_hello(
            &self.outer_random,
            Some(&self.session_id),
            &self.suites_comp,
            &exts,
        )
    }

    /// The HRR second flight (`processHelloRetryRequest`,
    /// handshake_client_tls13.go:231-405): on acceptance the inner gains the
    /// cookie, is re-encoded and re-sealed WITHOUT the encapsulated key, and
    /// the transcript gains the second inner; on rejection the second hello
    /// is the outer one with the cookie and the FIRST flight's ciphertext
    /// (upstream re-seals only the accepted path). Returns
    /// `(inner2_transcript_msg, outer2_wire_msg)`.
    fn rebuild_after_hrr(
        &self,
        sender: &mut ech::HpkeSender,
        cookie: &[u8],
        accepted: bool,
    ) -> Result<(Vec<u8>, Vec<u8>)> {
        if accepted {
            let mut inner_exts = self.inner_exts.clone();
            ech_insert_cookie(&mut inner_exts, cookie);
            let inner2 = serialize_ech_hello(
                &self.inner_random,
                Some(&self.session_id),
                &self.suites_comp,
                &inner_exts,
            );
            let wire2 =
                serialize_ech_hello(&self.inner_random, None, &self.suites_comp, &inner_exts);
            let encoded2 = ech::encode_inner_client_hello(
                &wire2[4..],
                Some(&self.inner_sni_bytes),
                self.max_name_length,
            );
            let ech_ext = self.seal_outer(sender, &[], &encoded2, false, None)?;
            let outer2 = self.serialize_outer_with(&ech_ext, None);
            Ok((inner2, outer2))
        } else {
            // The second outer keeps the first flight's sealed payload;
            // upstream only adds the cookie (handshake_client_tls13.go:388).
            let outer2 = self.serialize_outer_with(&self.first_flight_ech_ext(), Some(cookie));
            Ok((Vec::new(), outer2))
        }
    }

    /// The `encrypted_client_hello` body of the first-flight outer hello
    /// (for the rejection second flight).
    fn first_flight_ech_ext(&self) -> Vec<u8> {
        find_hello_ext(&self.outer_msg, ech::EXTENSION_ENCRYPTED_CLIENT_HELLO)
            .ok()
            .flatten()
            .unwrap_or_default()
    }
}

/// Fixed-or-random 32 bytes for the ECH determinism hooks.
fn ech_fixed_or_rng(fixed: Option<[u8; 32]>) -> [u8; 32] {
    fixed.unwrap_or_else(|| {
        let mut v = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut v);
        v
    })
}

/// One full ECH handshake attempt — the TLS 1.3 client handshake of
/// metacubex/tls `handshake_client_tls13.go` with the `echContext`
/// branches: outer hello out, ServerHello/HRR in, accept-confirmation
/// check, transcript rebind on acceptance, outer-mode completion +
/// `ech_required` alert on rejection.
async fn ech_attempt(
    cfg: &EchCfg,
    selection: &ech::EchConfigSelection,
    auth: &ServerAuth,
    transport: BoxProxyStream,
) -> std::result::Result<Tls13Stream, EchAttemptError> {
    let fatal = EchAttemptError::Fatal;
    let mut t = transport;

    let (set, mut hpke) = {
        let inner_random = ech_fixed_or_rng(cfg.ech.inner_random);
        let outer_random = ech_fixed_or_rng(cfg.ech.outer_random);
        let session_id = ech_fixed_or_rng(cfg.ech.session_id);
        let x25519_secret = ech_fixed_or_rng(cfg.ech.x25519_secret);
        let hpke_secret = ech_fixed_or_rng(cfg.ech.hpke_secret);
        match EchHelloSet::build(
            cfg,
            selection,
            inner_random,
            outer_random,
            session_id,
            x25519_secret,
            &hpke_secret,
        ) {
            Ok(v) => v,
            Err(e) => return Err(fatal(e)),
        }
    };

    t.write_all(&super::profiles::client_hello_record(&set.outer_msg))
        .await
        .map_err(|e| fatal(e.into()))?;

    let mut pending = Vec::new();
    let mut ccs = 0u8;
    let mut ccs_sent = false;

    let (typ, sh_raw) = next_plaintext_handshake(&mut t, &mut pending, &mut ccs)
        .await
        .map_err(fatal)?;
    if typ != HS_SERVER_HELLO {
        return Err(fatal(Error::protocol(format!(
            "tls13: expected a ServerHello, got handshake type {typ}"
        ))));
    }
    let mut sh = parse_server_hello_ech(&sh_raw).map_err(fatal)?;
    // `checkServerHelloOrHRR`: the server must echo the outer session id
    // (handshake_client_tls13.go:192-195).
    let suite = match CipherSuite::from_id(sh.cipher_suite) {
        Some(s) => s,
        None => {
            return Err(fatal(Error::protocol(format!(
                "tls: server chose an unconfigured cipher suite {:#06x}",
                sh.cipher_suite
            ))));
        }
    };

    let mut outer_transcript = Transcript::new(suite.hash());
    outer_transcript.update(&set.outer_msg);
    let mut inner_transcript = Transcript::new(suite.hash());
    inner_transcript.update(&set.inner_msg);

    // HelloRetryRequest flight (handshake_client_tls13.go:244-405).
    let mut sh_raw = sh_raw;
    if sh.is_hrr {
        // sendDummyChangeCipherSpec happens right after the HRR.
        t.write_all(&[RECORD_CCS, 0x03, 0x03, 0x00, 0x01, 0x01])
            .await
            .map_err(|e| fatal(e.into()))?;
        ccs_sent = true;

        // Both transcripts fold to a message_hash FIRST
        // (handshake_client_tls13.go:238-253); the HRR confirmation is then
        // computed over the folded inner transcript (cloneHash there, the
        // clone inside `ech_hrr_confirmation` here).
        outer_transcript = outer_transcript.fold_message_hash();
        inner_transcript = inner_transcript.fold_message_hash();

        let mut hrr_accepted = false;
        if let Some(value) = sh.ech_ext.clone() {
            if value.len() != 8 {
                return Err(fatal(Error::protocol(
                    "tls: malformed encrypted client hello extension",
                )));
            }
            let conf = ech_hrr_confirmation(
                suite.hash(),
                &inner_transcript,
                &sh_raw,
                &value,
                &set.inner_random,
            )
            .map_err(fatal)?;
            hrr_accepted =
                ech::confirmation_matches(&conf, value.as_slice().try_into().expect("8 bytes"));
        }

        inner_transcript.update(&sh_raw);
        outer_transcript.update(&sh_raw);

        // The only HRR requests we can honour are cookies: our key share is
        // always X25519 (handshake_client_tls13.go:287-318).
        if sh.selected_group.is_none() && sh.cookie.is_none() {
            return Err(fatal(Error::protocol(
                "tls: server sent an unnecessary HelloRetryRequest message",
            )));
        }
        if let Some(group) = sh.selected_group {
            if group == GROUP_X25519 {
                return Err(fatal(Error::protocol(
                    "tls: server sent an unnecessary HelloRetryRequest key_share",
                )));
            }
            // Only X25519 shares can be generated by this stack.
            return Err(fatal(Error::protocol(
                "tls: server selected unsupported group",
            )));
        }
        let cookie = sh.cookie.clone().unwrap_or_default();
        let (inner2, outer2) = set
            .rebuild_after_hrr(&mut hpke, &cookie, hrr_accepted)
            .map_err(fatal)?;
        if hrr_accepted {
            inner_transcript.update(&inner2);
        }
        t.write_all(&super::profiles::client_hello_record(&outer2))
            .await
            .map_err(|e| fatal(e.into()))?;
        outer_transcript.update(&outer2);

        // The second ServerHello.
        let (typ, second_raw) = next_plaintext_handshake(&mut t, &mut pending, &mut ccs)
            .await
            .map_err(fatal)?;
        if typ != HS_SERVER_HELLO {
            return Err(fatal(Error::protocol(format!(
                "tls13: expected a ServerHello, got handshake type {typ}"
            ))));
        }
        sh = parse_server_hello_ech(&second_raw).map_err(fatal)?;
        if sh.is_hrr {
            return Err(fatal(Error::protocol(
                "tls: server sent two HelloRetryRequest messages",
            )));
        }
        if sh.cipher_suite != suite.id() {
            return Err(fatal(Error::protocol(
                "tls: server changed cipher suite after a HelloRetryRequest",
            )));
        }
        sh_raw = second_raw;
    }
    if sh.session_id != set.session_id {
        return Err(fatal(Error::protocol(
            "tls: server did not echo the legacy session ID",
        )));
    }

    // Accept confirmation: the last 8 bytes of the ServerHello random
    // (handshake_client_tls13.go:86-116). On a match the ACTIVE transcript
    // rebinds to the inner one; otherwise the handshake runs to completion
    // in outer mode and fails as a rejection.
    let random_last8: [u8; 8] = sh_raw[30..38]
        .try_into()
        .map_err(|_| fatal(Error::protocol("tls13: short ServerHello random")))?;
    let conf = ech_accept_confirmation(suite.hash(), &inner_transcript, &sh_raw, &set.inner_random)
        .map_err(fatal)?;
    let accepted = ech::confirmation_matches(&conf, &random_last8);
    let mut transcript = outer_transcript;
    if accepted {
        if sh.ech_ext.is_some() {
            return Err(fatal(Error::protocol(
                "tls: unexpected encrypted client hello extension in server hello despite ECH being accepted",
            )));
        }
        transcript = inner_transcript;
    }
    transcript.update(&sh_raw);

    let shared = x25519(&set.x25519_secret, &sh.share).map_err(fatal)?;
    let secrets = handshake_secrets(suite, &shared, &transcript.hash()).map_err(fatal)?;
    let mut read_key = RecordProtector::new(&traffic_keys(suite, &secrets.s_hs)?).map_err(fatal)?;
    let mut write_key =
        RecordProtector::new(&traffic_keys(suite, &secrets.c_hs)?).map_err(fatal)?;

    if !ccs_sent {
        t.write_all(&[RECORD_CCS, 0x03, 0x03, 0x00, 0x01, 0x01])
            .await
            .map_err(|e| fatal(e.into()))?;
    }

    let (typ, ee_raw) = next_encrypted_handshake(&mut t, &mut read_key, &mut pending, &mut ccs)
        .await
        .map_err(fatal)?;
    if typ != HS_ENCRYPTED_EXTENSIONS {
        return Err(fatal(Error::protocol(format!(
            "tls13: expected EncryptedExtensions, got handshake type {typ}"
        ))));
    }
    let retry_configs = ee_retry_configs(&ee_raw).map_err(fatal)?;
    if retry_configs.is_some() && accepted {
        return Err(fatal(Error::protocol(
            "tls: server sent encrypted client hello retry configs after accepting encrypted client hello",
        )));
    }
    transcript.update(&ee_raw);
    let alpn = parse_encrypted_extensions(&ee_raw).map_err(fatal)?;

    let (typ, cert_raw) = next_encrypted_handshake(&mut t, &mut read_key, &mut pending, &mut ccs)
        .await
        .map_err(fatal)?;
    if typ != HS_CERTIFICATE {
        return Err(fatal(Error::protocol(format!(
            "tls13: expected Certificate, got handshake type {typ}"
        ))));
    }
    transcript.update(&cert_raw);
    let chain = parse_certificate(&cert_raw).map_err(fatal)?;
    let leaf = chain.first().cloned().unwrap_or_default();

    let (typ, cv_raw) = next_encrypted_handshake(&mut t, &mut read_key, &mut pending, &mut ccs)
        .await
        .map_err(fatal)?;
    if typ != HS_CERTIFICATE_VERIFY {
        return Err(fatal(Error::protocol(format!(
            "tls13: expected CertificateVerify, got handshake type {typ}"
        ))));
    }
    let hash_at_cert = transcript.hash();
    transcript.update(&cv_raw);
    verify_certificate_verify(cv_raw.get(4..).unwrap_or_default(), &leaf, &hash_at_cert)
        .map_err(fatal)?;

    // Server authentication: on acceptance the INNER name (the rebind of
    // `c.serverName` to `config.ServerName`,
    // handshake_client_tls13.go:99-100); on rejection the PUBLIC name with
    // the caller's callback skipped — the `echRejected` branch of
    // `verifyServerCertificate` (handshake_client.go:1081-1145).
    let cert_verified = if accepted {
        match auth {
            ServerAuth::AcceptAny => true,
            ServerAuth::WebPki { roots, .. } => {
                verify_chain_webpki(roots, &cfg.server_name, &chain).map_err(fatal)?;
                true
            }
            ServerAuth::Callback(check) => check(&leaf).map_err(fatal)?,
        }
    } else {
        match auth {
            ServerAuth::AcceptAny => true,
            ServerAuth::WebPki { roots, .. } => {
                verify_chain_webpki(roots, &set.public_name, &chain).map_err(fatal)?;
                true
            }
            ServerAuth::Callback(_) => false,
        }
    };

    let (typ, fin_raw) = next_encrypted_handshake(&mut t, &mut read_key, &mut pending, &mut ccs)
        .await
        .map_err(fatal)?;
    if typ != HS_FINISHED {
        return Err(fatal(Error::protocol(format!(
            "tls13: expected Finished, got handshake type {typ}"
        ))));
    }
    let hash_at_cv = transcript.hash();
    verify_finished(
        suite.hash(),
        &finished_key(suite.hash(), &secrets.s_hs).map_err(fatal)?,
        &hash_at_cv,
        fin_raw.get(4..).unwrap_or_default(),
    )
    .map_err(fatal)?;
    transcript.update(&fin_raw);

    // Client Finished over the active (inner-on-accept) transcript.
    let verify_data = finished_verify_data(
        suite.hash(),
        &finished_key(suite.hash(), &secrets.c_hs).map_err(fatal)?,
        &transcript.hash(),
    )
    .map_err(fatal)?;
    let record = write_key
        .seal(RECORD_HANDSHAKE, &hs_message(HS_FINISHED, &verify_data))
        .map_err(fatal)?;
    t.write_all(&record).await.map_err(|e| fatal(e.into()))?;

    let hash_at_sfin = transcript.hash();
    let (c_ap, s_ap) =
        application_secrets(suite.hash(), &secrets.master, &hash_at_sfin).map_err(fatal)?;
    let read_key = RecordProtector::new(&traffic_keys(suite, &s_ap)?).map_err(fatal)?;
    let write_key = RecordProtector::new(&traffic_keys(suite, &c_ap)?).map_err(fatal)?;

    if !accepted {
        // The handshake completed in outer mode; end it the upstream way —
        // alert `ech_required`, then `ECHRejectionError` with the retry
        // configs (handshake_client_tls13.go:151-153, ech.go:486-492).
        let _ = t
            .write_all(&[
                RECORD_ALERT,
                0x03,
                0x03,
                0x00,
                0x02,
                0x02,
                ALERT_ECH_REQUIRED,
            ])
            .await;
        return Err(EchAttemptError::Rejected {
            retry_configs: retry_configs.unwrap_or_default(),
        });
    }

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
        read_spliced: false,
        write_spliced: false,
        splice_prefix: Vec::new(),
    })
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
    // --- Vision direct-copy rebind (XTLS `commandPaddingDirect`) ----------
    // Once the peer announces Vision's direct copy, both peers abandon this
    // record layer and speak raw bytes over the transport (Xray
    // `proxy/proxy.go:248-283`, `proxy.go:334-347`, main 2026-09; mihomo
    // `transport/vless/vision/conn.go:142-179` / `:230-232`). The two flags
    // below allow each *direction* to be abandoned independently: the
    // client's downlink rebinds when the server's `02` frame is parsed while
    // its uplink keeps sealing until its own transition, and vice versa.
    /// Reads bypass the record layer: `splice_prefix` is served first, then
    /// raw transport bytes (upstream re-binds its reader to the raw conn,
    /// Xray `proxy/proxy.go:280-282`).
    read_spliced: bool,
    /// Writes bypass the record layer; sealed bytes still pending from an
    /// in-flight `poll_write` are flushed first (upstream re-binds its
    /// writer after the direct frame went out, mihomo `conn.go:230-232`).
    write_spliced: bool,
    /// Bytes recovered from the record layer at read-splice time: decrypted
    /// read-ahead first (upstream Go `tls.Conn`'s `input`), then any raw
    /// bytes already pulled off the socket (`rawInput`). Served before the
    /// transport.
    splice_prefix: Vec<u8>,
}

/// What [`Tls13Stream::into_raw_transport`] hands back once the record layer
/// is abandoned.
pub struct RawTransport {
    /// The transport that was under the TLS session.
    pub transport: BoxProxyStream,
    /// Bytes the caller must deliver before reading `transport`, in order:
    /// the decrypted-but-unread plaintext first (upstream Go `tls.Conn`'s
    /// `input`), then any transport bytes the record layer had already
    /// pulled off the socket that do not decrypt as records of this session
    /// (upstream `rawInput`).
    pub read_ahead: Vec<u8>,
}

impl std::fmt::Debug for RawTransport {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawTransport")
            .field("read_ahead_len", &self.read_ahead.len())
            .finish_non_exhaustive()
    }
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

    // --- Vision direct-copy rebind -----------------------------------------
    //
    // The XTLS Vision splice needs three things from this layer (Xray steals
    // the first two with reflect+unsafe out of Go's `crypto/tls.Conn`,
    // `proxy/vless/outbound/outbound.go:284-288` main 2026-09; mihomo
    // `transport/vless/vision/vision.go:106-111` does the same): the raw
    // transport under the session, the decrypted-but-unread plaintext
    // (`input`), and the read-ahead already pulled off the socket
    // (`rawInput`). Here they are first-class API.

    /// Take (drain) the decrypted-but-unread application plaintext —
    /// upstream Go `tls.Conn`'s private `input` buffer, which the Vision
    /// reader drains after the server's direct command (Xray
    /// `proxy/proxy.go:259-263`).
    ///
    /// Sequence state is untouched: no record is decrypted or consumed, so a
    /// caller staying in TLS mode keeps a fully consistent stream — the next
    /// `poll_read` decrypts the next record as if nothing happened.
    pub fn take_read_ahead(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.plain)
    }

    /// Whether there is decrypted-but-unread plaintext waiting.
    pub fn has_read_ahead(&self) -> bool {
        !self.plain.is_empty()
    }

    /// Decrypt every *complete* record already buffered in `rec` into
    /// `plain`, without touching the transport. Stops at the first record
    /// that is not a valid application record of this session — a peer that
    /// abandoned the record layer writes raw post-splice traffic, which can
    /// look like a record header; those bytes are left in `rec` so a splice
    /// can treat them as the raw prefix (this mirrors Go's tls.Conn, which
    /// has already decrypted every complete record into `input` by the time
    /// Vision drains it). Only called once reads are being abandoned, so the
    /// sequence-number consumption of a failed open is harmless.
    fn drain_buffered_records(&mut self) {
        loop {
            if self.rec.len() < 5 {
                return;
            }
            let len = u16::from_be_bytes([self.rec[3], self.rec[4]]) as usize;
            if self.rec.len() < 5 + len {
                return;
            }
            let record: Vec<u8> = self.rec.drain(..5 + len).collect();
            if self.handle_record(&record).is_err() {
                // Not one of ours anymore: put it back at the front (bytes
                // still in `rec` arrived after it on the wire); a splice
                // treats it as raw prefix, a TLS-mode caller gets the error
                // from the next `poll_read`.
                self.rec.splice(0..0, record);
                return;
            }
        }
    }

    /// Abandon the record layer for the *read* direction: from now on reads
    /// return, in order, (a) the decrypted read-ahead recovered above
    /// (upstream `input`), (b) any bytes already pulled off the socket that
    /// do not belong to a decryptable record (upstream `rawInput`), then
    /// (c) raw transport bytes. Writes keep being sealed until
    /// [`Tls13Stream::splice_writes`].
    ///
    /// Upstream equivalent: `VisionReader.ReadMultiBuffer` sets
    /// `switchToDirectCopy`, drains `input`/`rawInput` and re-binds its
    /// reader to the raw transport (Xray `proxy/proxy.go:248-250`,
    /// `:259-283`; mihomo `conn.go:142-175`).
    pub fn splice_reads(&mut self) {
        if self.read_spliced {
            return;
        }
        self.read_spliced = true;
        self.drain_buffered_records();
        let mut prefix = std::mem::take(&mut self.plain);
        prefix.append(&mut self.rec);
        self.splice_prefix = prefix;
    }

    /// Abandon the record layer for the *write* direction: subsequent writes
    /// go to the transport raw. Sealed bytes still pending from an in-flight
    /// `poll_write` are flushed first (they are pre-splice data and must stay
    /// ordered ahead of the raw bytes). A queued post-handshake control
    /// record (KeyUpdate reply) is dropped — it cannot be sent once the peer
    /// stopped reading TLS records.
    ///
    /// Upstream equivalent: the Vision writer swaps its writer to the raw
    /// net conn right after the direct frame went out (mihomo
    /// `conn.go:230-232`; Xray `proxy/proxy.go:334-347`).
    pub fn splice_writes(&mut self) {
        if self.write_spliced {
            return;
        }
        self.write_spliced = true;
        if !self.ctl.is_empty() {
            tracing::debug!(
                "engine: tls13: dropping a queued post-handshake control record; \
                 the record layer is abandoned"
            );
            self.ctl.clear();
        }
    }

    /// Whether the read direction was re-bound to the raw transport.
    pub fn reads_spliced(&self) -> bool {
        self.read_spliced
    }

    /// Whether the write direction was re-bound to the raw transport.
    pub fn writes_spliced(&self) -> bool {
        self.write_spliced
    }

    /// Fully unwrap into the raw transport once the record layer can be
    /// abandoned in both directions. The returned `read_ahead` is exactly
    /// what a Vision reader must deliver to its caller before reading the
    /// transport: decrypted-but-unread plaintext first (`input`), then any
    /// transport bytes the record layer had already pulled off the socket
    /// that do not decrypt as records of this session (`rawInput`).
    ///
    /// Fails while a sealed record is still pending in a write (`out`):
    /// flush first. Queued control records are dropped, as in
    /// [`Tls13Stream::splice_writes`]. Once either direction has already
    /// been spliced this still works — it simply returns the transport and
    /// whatever prefix remains.
    pub fn into_raw_transport(mut self) -> Result<RawTransport> {
        if !self.out.is_empty() {
            return Err(Error::protocol(
                "tls13: cannot unwrap while a sealed record is still pending; flush first",
            ));
        }
        self.read_spliced = true;
        self.drain_buffered_records();
        let mut read_ahead = std::mem::take(&mut self.plain);
        read_ahead.append(&mut self.rec);
        read_ahead.append(&mut self.splice_prefix);
        if !self.ctl.is_empty() {
            tracing::debug!(
                "engine: tls13: dropping a queued post-handshake control record; \
                 the record layer is abandoned"
            );
        }
        Ok(RawTransport {
            transport: self.inner,
            read_ahead,
        })
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
        let record = self
            .write_key
            .seal(RECORD_HANDSHAKE, &hs_message(HS_KEY_UPDATE, &[0x00]))?;
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
                                    )));
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
                        )));
                    }
                }
            }
            other => {
                return Err(Error::protocol(format!(
                    "tls13: unexpected record type {other}"
                )));
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
            if this.read_spliced {
                // Vision direct copy: the drained read-ahead (`input` +
                // `rawInput`) is delivered before any raw transport byte,
                // exactly the order upstream's reader merges them
                // (Xray `proxy/proxy.go:259-266`).
                if !this.splice_prefix.is_empty() {
                    let n = this.splice_prefix.len().min(buf.remaining());
                    buf.put_slice(&this.splice_prefix[..n]);
                    this.splice_prefix.drain(..n);
                    return Poll::Ready(Ok(()));
                }
                return Pin::new(&mut this.inner).poll_read(cx, buf);
            }
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
        if this.write_spliced {
            // Vision direct copy: raw passthrough. Sealed bytes still pending
            // from an in-flight pre-splice write go first, in order.
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
            this.out_plain = 0;
            let n = ready!(Pin::new(&mut this.inner).poll_write(cx, buf))?;
            return Poll::Ready(Ok(n));
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
        // Once either direction abandoned the record layer (Vision direct
        // copy), no close_notify is sent — the peer is not reading TLS
        // records anymore; the raw transport is simply shut down (mihomo
        // `vision/conn.go:306-311` closes the raw net conn for exactly this
        // reason, skipping tls.Conn's close_notify).
        if !this.close_notify_sent && !this.read_spliced && !this.write_spliced {
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

    pub(crate) fn parse_client_hello(raw: &[u8]) -> Result<ClientHelloInfo> {
        let b = raw
            .get(4..)
            .ok_or_else(|| Error::protocol("test server: short hello"))?;
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
                read_spliced: false,
                write_spliced: false,
                splice_prefix: Vec::new(),
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

    // ------------------------------------------------ ECH termination ----
    //
    // A test peer that terminates ECH the way metacubex/tls's server does
    // (handshake_server.go + ech.go:550-655): HPKE-open the outer payload
    // with the server's private key, reconstruct the transcript-form inner
    // hello, answer with a confirmation-carrying ServerHello, and complete
    // the handshake against the INNER transcript. The reject/HRR modes
    // cover the other upstream shapes.

    /// A server-side ECH key: the X25519 private half plus the
    /// ECHConfigList wire bytes advertising its public half (mihomo
    /// `component/ech/key.go`).
    pub(crate) struct EchServerKey {
        pub(crate) sk_r: [u8; 32],
        pub(crate) config_list: Vec<u8>,
    }

    /// Deterministic server key: `derive_key_pair_x25519(seed)` for the
    /// private half, one X25519/HKDF-SHA256 config with both AES AEADs.
    pub(crate) fn ech_server_key(seed: &[u8], config_id: u8, public_name: &[u8]) -> EchServerKey {
        let sk = ech::derive_key_pair_x25519(seed);
        let pk = curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(sk).0;
        let mut body = Vec::new();
        body.push(config_id);
        body.extend_from_slice(&ech::KEM_DH_X25519_HKDF_SHA256.to_be_bytes());
        body.extend_from_slice(&32u16.to_be_bytes());
        body.extend_from_slice(&pk);
        let suites = [
            (ech::KDF_HKDF_SHA256, ech::AEAD_AES_128_GCM),
            (ech::KDF_HKDF_SHA256, ech::AEAD_AES_256_GCM),
        ];
        body.extend_from_slice(&((suites.len() * 4) as u16).to_be_bytes());
        for (kdf, aead) in suites {
            body.extend_from_slice(&kdf.to_be_bytes());
            body.extend_from_slice(&aead.to_be_bytes());
        }
        body.push(0x20); // max_name_length
        body.push(public_name.len() as u8);
        body.extend_from_slice(public_name);
        body.extend_from_slice(&0u16.to_be_bytes()); // no config extensions
        let mut list = Vec::with_capacity(6 + body.len());
        list.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
        list.extend_from_slice(&ech::EXTENSION_ENCRYPTED_CLIENT_HELLO.to_be_bytes());
        list.extend_from_slice(&(body.len() as u16).to_be_bytes());
        list.extend_from_slice(&body);
        EchServerKey {
            sk_r: sk,
            config_list: list,
        }
    }

    /// How the ECH test server answers.
    pub(crate) enum EchServerMode {
        /// Terminate ECH: confirmation in the ServerHello random.
        Accept,
        /// Complete the handshake against the OUTER hello; put the retry
        /// ECHConfigList (when given) into EncryptedExtensions.
        Reject { retry_configs: Option<Vec<u8>> },
        /// HelloRetryRequest first (with a cookie): the 8-byte ECH extension
        /// carries a valid hrr confirmation (`accept == true`) or zeros.
        Hrr {
            accept: bool,
            retry_configs: Option<Vec<u8>>,
        },
    }

    /// What the ECH test server saw.
    pub(crate) struct EchServerObserved {
        /// The outer ClientHello (public SNI, ECH payload).
        pub(crate) outer: ClientHelloInfo,
        /// The reconstructed transcript-form inner hello (accept modes).
        pub(crate) inner: Option<ClientHelloInfo>,
    }

    /// Find one extension body in a handshake message's extension block.
    pub(crate) fn find_ext_body(msg: &[u8], want: u16) -> Result<Option<Vec<u8>>> {
        find_hello_ext(msg, want)
    }

    /// The HPKE-open of one outer hello's ECH payload (the trial-decryption
    /// loop of `processECHClientHello`, ech.go:550-620, for one key).
    /// Returns the reconstructed transcript-form inner hello.
    pub(crate) fn open_ech_hello(
        ch_raw: &[u8],
        recipient: &mut ech::HpkeSender,
    ) -> Result<Vec<u8>> {
        let ext_body = find_ext_body(ch_raw, ech::EXTENSION_ENCRYPTED_CLIENT_HELLO)?
            .ok_or_else(|| Error::protocol("test ech server: no ECH extension"))?;
        let payload = match ech::parse_ech_ext(&ext_body)? {
            ech::EchExt::Inner => {
                return Err(Error::protocol("test ech server: inner marker on the wire"));
            }
            ech::EchExt::Outer { payload, .. } => payload,
        };
        // decryptECHPayload (ech.go:401-405): AAD = hello[4..] with the
        // payload's first occurrence zeroed.
        let body = &ch_raw[4..];
        let pos = body
            .windows(payload.len())
            .position(|w| w == payload.as_slice())
            .ok_or_else(|| Error::protocol("test ech server: payload not in hello"))?;
        let mut aad = body.to_vec();
        aad[pos..pos + payload.len()].fill(0);
        let encoded = recipient.open(&aad, &payload)?;
        ech::decode_inner_client_hello(ch_raw, &encoded)
    }

    /// Build the recipient for an outer hello's `enc` (NewRecipient +
    /// decap, ech.go:607-613): decap with the server key and the key
    /// schedule over the config's `info`.
    fn ech_recipient(key: &EchServerKey, enc: &[u8], aead_id: u16) -> Result<ech::HpkeSender> {
        let enc: [u8; 32] = enc
            .try_into()
            .map_err(|_| Error::protocol("test ech server: enc is not 32 bytes"))?;
        let configs = ech::parse_ech_config_list(&key.config_list)?;
        let config = &configs[0];
        let aead = ech::HpkeAead::from_id(aead_id)
            .ok_or_else(|| Error::protocol("test ech server: unsupported aead"))?;
        let shared = ech::hpke_decap(&key.sk_r, &enc)?;
        ech::HpkeSender::from_shared_secret(&shared, aead, &ech::ech_hpke_info(config))
    }

    /// The server flight from the (already CH-seeded) transcript on:
    /// ServerHello (with the accept confirmation patched into random[24..32]
    /// when `inner_random` is given), EncryptedExtensions (echoing ALPN,
    /// plus the retry list when given), Certificate/CertificateVerify/
    /// Finished, then the client Finished — the tail of
    /// `test_server::accept` parameterized on the ECH pieces.
    #[allow(clippy::too_many_arguments)]
    async fn ech_server_flight(
        transport: BoxProxyStream,
        mut pending: Vec<u8>,
        mut ccs: u8,
        suite: CipherSuite,
        transcript: &mut Transcript,
        hello: &ClientHelloInfo,
        inner_random: Option<&[u8; 32]>,
        choose_cert: impl FnOnce(
            &ClientHelloInfo,
        ) -> Result<(Vec<u8>, Arc<dyn rustls::sign::SigningKey>)>,
        retry_configs: Option<Vec<u8>>,
    ) -> Result<Tls13Stream> {
        let mut t = transport;
        let mut server_random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut server_random);
        let (server_secret, server_public) = x25519_keygen();
        let shared = x25519(&server_secret, &hello.x25519_share)?;

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
        let mut sh_raw = hs_message(HS_SERVER_HELLO, &sh_body);

        if let Some(inner_random) = inner_random {
            // Patch the accept confirmation into random[24..32] — the client
            // computes it over this very SH with the slot zeroed
            // (handshake_client_tls13.go:86-98, mirrored on the server side).
            let conf = ech_accept_confirmation(suite.hash(), transcript, &sh_raw, inner_random)?;
            sh_raw[30..38].copy_from_slice(&conf);
        }

        transcript.update(&sh_raw);
        t.write_all(&super::super::profiles::client_hello_record(&sh_raw))
            .await?;

        let secrets = handshake_secrets(suite, &shared, &transcript.hash())?;
        let mut read_key = RecordProtector::new(&traffic_keys(suite, &secrets.c_hs)?)?;
        let mut write_key = RecordProtector::new(&traffic_keys(suite, &secrets.s_hs)?)?;

        // EncryptedExtensions: ALPN echo + the ECH retry list.
        let mut ee_exts = Vec::new();
        if let Some(first) = hello.alpn.first() {
            let mut list = vec![first.len() as u8];
            list.extend_from_slice(first.as_bytes());
            let mut body = Vec::new();
            body.extend_from_slice(&(list.len() as u16).to_be_bytes());
            body.extend_from_slice(&list);
            ee_exts.extend_from_slice(&ext(EXT_ALPN, &body));
        }
        if let Some(retry) = &retry_configs {
            ee_exts.extend_from_slice(&ext(ech::EXTENSION_ENCRYPTED_CLIENT_HELLO, retry));
        }
        let mut ee_body = Vec::new();
        ee_body.extend_from_slice(&(ee_exts.len() as u16).to_be_bytes());
        ee_body.extend_from_slice(&ee_exts);
        let ee_raw = hs_message(HS_ENCRYPTED_EXTENSIONS, &ee_body);
        transcript.update(&ee_raw);

        let (cert_der, signing_key) = choose_cert(hello)?;
        let mut cert_body = vec![0x00];
        let mut list = Vec::new();
        list.push((cert_der.len() >> 16) as u8);
        list.push((cert_der.len() >> 8) as u8);
        list.push(cert_der.len() as u8);
        list.extend_from_slice(&cert_der);
        list.extend_from_slice(&0u16.to_be_bytes());
        cert_body.extend_from_slice(&(list.len() as u32).to_be_bytes()[1..]);
        cert_body.extend_from_slice(&list);
        let cert_raw = hs_message(HS_CERTIFICATE, &cert_body);
        transcript.update(&cert_raw);

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
        drop(pending);
        Ok(Tls13Stream {
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
            read_spliced: false,
            write_spliced: false,
            splice_prefix: Vec::new(),
        })
    }

    /// Terminate (or reject) an ECH handshake as the test peer.
    pub(crate) async fn accept_ech(
        transport: BoxProxyStream,
        suite: CipherSuite,
        key: &EchServerKey,
        mode: EchServerMode,
        choose_cert: impl FnOnce(
            &ClientHelloInfo,
        ) -> Result<(Vec<u8>, Arc<dyn rustls::sign::SigningKey>)>,
    ) -> Result<(Tls13Stream, EchServerObserved)> {
        let mut t = transport;
        let mut pending = Vec::new();
        let mut ccs = 0u8;
        let (typ, ch1_raw) = next_plaintext_handshake(&mut t, &mut pending, &mut ccs).await?;
        if typ != HS_CLIENT_HELLO {
            return Err(Error::protocol("test ech server: expected a ClientHello"));
        }
        let outer = parse_client_hello(&ch1_raw)?;
        if !outer.cipher_suites.contains(&suite.id()) {
            return Err(Error::protocol("test ech server: suite not offered"));
        }

        // Trial-open the ECH payload (ech.go:550-620): a failed open with
        // this key means the reject modes fall back to the outer hello.
        let mut recipient = None;
        if let Some(ext_body) = find_ext_body(&ch1_raw, ech::EXTENSION_ENCRYPTED_CLIENT_HELLO)? {
            if let ech::EchExt::Outer {
                kdf_id: _,
                aead_id,
                config_id: _,
                enc,
                payload: _,
            } = ech::parse_ech_ext(&ext_body)?
            {
                if let Ok(mut r) = ech_recipient(key, &enc, aead_id) {
                    if let Ok(inner_msg) = open_ech_hello(&ch1_raw, &mut r) {
                        recipient = Some((r, inner_msg));
                    }
                }
            }
        }

        match mode {
            EchServerMode::Accept => {
                let (_recipient, inner_msg) = recipient.ok_or_else(|| {
                    Error::protocol("test ech server: could not open the ECH payload")
                })?;
                let inner = parse_client_hello(&inner_msg)?;
                let inner_random = inner.random;
                let mut transcript = Transcript::new(suite.hash());
                transcript.update(&inner_msg);
                let stream = ech_server_flight(
                    t,
                    pending,
                    ccs,
                    suite,
                    &mut transcript,
                    &inner,
                    Some(&inner_random),
                    choose_cert,
                    None,
                )
                .await?;
                Ok((
                    stream,
                    EchServerObserved {
                        outer,
                        inner: Some(inner),
                    },
                ))
            }
            EchServerMode::Reject { retry_configs } => {
                let mut transcript = Transcript::new(suite.hash());
                transcript.update(&ch1_raw);
                let stream = ech_server_flight(
                    t,
                    pending,
                    ccs,
                    suite,
                    &mut transcript,
                    &outer,
                    None,
                    choose_cert,
                    retry_configs,
                )
                .await?;
                Ok((stream, EchServerObserved { outer, inner: None }))
            }
            EchServerMode::Hrr {
                accept,
                retry_configs,
            } => {
                // The HRR needs the inner random for its confirmation, and
                // the accept path needs the recipient context (whose HPKE
                // sequence advanced past the first open) for the second one.
                let (mut recipient, inner1_msg) = recipient.ok_or_else(|| {
                    Error::protocol("test ech server: could not open the ECH payload")
                })?;
                let inner1 = parse_client_hello(&inner1_msg)?;
                let cookie: Vec<u8> = (0..16u8).collect();
                // HRR with the ECH extension value zeroed first, then the
                // confirmation patched in (the mirror of the client's
                // zeroing, handshake_client_tls13.go:262-269).
                let mut hrr_exts = Vec::new();
                hrr_exts
                    .extend_from_slice(&ext(EXT_SUPPORTED_VERSIONS, &VERSION_TLS13.to_be_bytes()));
                hrr_exts.extend_from_slice(&ext(EXT_COOKIE, &cookie));
                hrr_exts.extend_from_slice(&ext(ech::EXTENSION_ENCRYPTED_CLIENT_HELLO, &[0u8; 8]));
                let mut hrr_body = Vec::new();
                hrr_body.extend_from_slice(&VERSION_TLS12.to_be_bytes());
                hrr_body.extend_from_slice(&HRR_RANDOM);
                hrr_body.push(outer.session_id.len() as u8);
                hrr_body.extend_from_slice(&outer.session_id);
                hrr_body.extend_from_slice(&suite.id().to_be_bytes());
                hrr_body.push(0x00);
                hrr_body.extend_from_slice(&(hrr_exts.len() as u16).to_be_bytes());
                hrr_body.extend_from_slice(&hrr_exts);
                let mut hrr_raw = hs_message(HS_SERVER_HELLO, &hrr_body);
                if accept {
                    let mut folded = Transcript::new(suite.hash());
                    folded.update(&inner1_msg);
                    folded = folded.fold_message_hash();
                    folded.update(&hrr_raw);
                    let prk = hkdf_extract(suite.hash(), &[], &inner1.random);
                    let mut conf = [0u8; 8];
                    suite.hash().hkdf_expand_label(
                        &prk,
                        "hrr ech accept confirmation",
                        &folded.hash(),
                        &mut conf,
                    )?;
                    // Patch into the (single) ECH extension slot: the
                    // 8-byte body right after the u16 ext length.
                    let pos = hrr_raw
                        .windows(2)
                        .position(|w| w == ech::EXTENSION_ENCRYPTED_CLIENT_HELLO.to_be_bytes())
                        .expect("the ext was just written");
                    hrr_raw[pos + 4..pos + 4 + 8].copy_from_slice(&conf);
                }
                t.write_all(&super::super::profiles::client_hello_record(&hrr_raw))
                    .await?;

                // The second ClientHello.
                let (typ, ch2_raw) =
                    next_plaintext_handshake(&mut t, &mut pending, &mut ccs).await?;
                if typ != HS_CLIENT_HELLO {
                    return Err(Error::protocol(
                        "test ech server: expected the second ClientHello",
                    ));
                }
                if accept {
                    // Same HPKE context, sequence 1 (the first open consumed 0).
                    let inner2_msg = open_ech_hello(&ch2_raw, &mut recipient)?;
                    let inner2 = parse_client_hello(&inner2_msg)?;
                    let inner_random = inner2.random;
                    let mut transcript = Transcript::new(suite.hash());
                    transcript.update(&inner1_msg);
                    transcript = transcript.fold_message_hash();
                    transcript.update(&hrr_raw);
                    transcript.update(&inner2_msg);
                    let stream = ech_server_flight(
                        t,
                        pending,
                        ccs,
                        suite,
                        &mut transcript,
                        &inner2,
                        Some(&inner_random),
                        choose_cert,
                        None,
                    )
                    .await?;
                    Ok((
                        stream,
                        EchServerObserved {
                            outer,
                            inner: Some(inner2),
                        },
                    ))
                } else {
                    let mut transcript = Transcript::new(suite.hash());
                    transcript.update(&ch1_raw);
                    transcript = transcript.fold_message_hash();
                    transcript.update(&hrr_raw);
                    transcript.update(&ch2_raw);
                    let outer2 = parse_client_hello(&ch2_raw)?;
                    let stream = ech_server_flight(
                        t,
                        pending,
                        ccs,
                        suite,
                        &mut transcript,
                        &outer2,
                        None,
                        choose_cert,
                        retry_configs,
                    )
                    .await?;
                    Ok((stream, EchServerObserved { outer, inner: None }))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::reality::profiles::{UtslProfile, build_client_hello};
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
        let derived2 =
            derive_secret(HashKind::Sha256, &handshake_secret, "derived", &empty_hash).unwrap();
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
        assert_eq!(
            p.nonce(),
            [
                0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5, 0xa5
            ]
        );
        p.seq = 1;
        assert_eq!(p.nonce()[11], 0xa4);
        p.seq = 0x0102_0304_0506_0708;
        let n = p.nonce();
        assert_eq!(&n[4..], &[0xa4, 0xa7, 0xa6, 0xa1, 0xa0, 0xa3, 0xa2, 0xad]);
    }

    // --- rustls as the counterparty ------------------------------------

    fn provider_with(
        suites: Vec<rustls::SupportedCipherSuite>,
    ) -> Arc<rustls::crypto::CryptoProvider> {
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
                let n = tokio::io::AsyncReadExt::read(&mut tls, &mut buf)
                    .await
                    .unwrap();
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
        assert!(
            err.to_string().contains("certificate verification failed"),
            "{err}"
        );
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
        assert_eq!(
            CipherSuite::from_id(0x1301),
            Some(CipherSuite::Aes128GcmSha256)
        );
        assert_eq!(
            CipherSuite::from_id(0x1302),
            Some(CipherSuite::Aes256GcmSha384)
        );
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
            let (mut tls, hello) =
                test_server::accept(Box::new(server), CipherSuite::Aes128GcmSha256, move |_| {
                    Ok((der.clone(), signing_key.clone()))
                })
                .await
                .unwrap();
            assert_eq!(hello.sni.as_deref(), Some("localhost"));
            assert_eq!(hello.session_id.len(), 32);
            let mut buf = [0u8; 64];
            let n = tokio::io::AsyncReadExt::read(&mut tls, &mut buf)
                .await
                .unwrap();
            tls.write_all(&buf[..n]).await.unwrap();
            tls.flush().await.unwrap();
            tls
        });

        let mut random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let session_id = [7u8; 32];
        let (secret, public) = x25519_keygen();
        let hello = build_client_hello(
            UtslProfile::Chrome,
            "localhost",
            &random,
            &session_id,
            &public,
        );
        let mut stream = connect(Box::new(client), &hello, &secret, ServerAuth::AcceptAny)
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

    // --- Vision direct-copy rebind (take/unwrap/splice) --------------------
    //
    // These pin the pieces XTLS Vision's `commandPaddingDirect` splice needs:
    // the decrypted-unread plaintext (`input`), the read-ahead already pulled
    // off the socket (`rawInput`), and the raw transport under the session
    // (Xray `proxy/proxy.go:248-283`, `proxy/vless/outbound/outbound.go:284-288`,
    // main 2026-09).

    /// A connected client/server pair of our own TLS 1.3 implementation over
    /// a loopback duplex.
    async fn rebind_pair() -> (Tls13Stream, Tls13Stream) {
        let cert = self_signed("localhost", &rcgen::PKCS_ED25519);
        let signing_key = rustls::crypto::ring::sign::any_supported_type(&cert.key).unwrap();
        let der = cert.der.clone();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);

        let server_task = tokio::spawn(async move {
            test_server::accept(
                Box::new(server_io),
                CipherSuite::Aes128GcmSha256,
                move |_| Ok((der.clone(), signing_key.clone())),
            )
            .await
            .unwrap()
            .0
        });

        let mut random = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut random);
        let session_id = [9u8; 32];
        let (secret, public) = x25519_keygen();
        let hello = build_client_hello(
            UtslProfile::Chrome,
            "localhost",
            &random,
            &session_id,
            &public,
        );
        let client = connect(Box::new(client_io), &hello, &secret, ServerAuth::AcceptAny)
            .await
            .unwrap();
        let server = server_task.await.unwrap();
        (client, server)
    }

    /// `take_read_ahead` drains exactly the decrypted-unread plaintext and a
    /// TLS-mode caller keeps a fully working stream afterwards (no sequence
    /// state is touched).
    #[tokio::test]
    async fn take_read_ahead_drains_only_unread_plaintext() {
        let (mut client, mut server) = rebind_pair().await;

        server.write_all(b"hello").await.unwrap();
        server.flush().await.unwrap();
        let mut two = [0u8; 2];
        tokio::io::AsyncReadExt::read_exact(&mut client, &mut two)
            .await
            .unwrap();
        assert_eq!(&two, b"he");
        assert!(client.has_read_ahead(), "unread plaintext is buffered");
        assert_eq!(client.take_read_ahead(), b"llo");
        assert!(!client.has_read_ahead());
        assert!(
            client.take_read_ahead().is_empty(),
            "draining is idempotent"
        );

        // The stream keeps working in TLS mode: the next records still
        // decrypt with unbroken sequence numbers.
        server.write_all(b"-more").await.unwrap();
        server.flush().await.unwrap();
        let mut buf = vec![0u8; 5];
        tokio::io::AsyncReadExt::read_exact(&mut client, &mut buf)
            .await
            .unwrap();
        assert_eq!(buf, b"-more");
    }

    /// Full unwrap: the transport comes back with the buffered read-ahead
    /// first, then the raw bytes the peer wrote after abandoning its own
    /// record layer.
    #[tokio::test]
    async fn unwrap_yields_raw_transport_with_read_ahead_first() {
        let (mut client, mut server) = rebind_pair().await;

        client.write_all(b"ping").await.unwrap();
        client.flush().await.unwrap();
        let mut p = [0u8; 4];
        tokio::io::AsyncReadExt::read_exact(&mut server, &mut p)
            .await
            .unwrap();
        assert_eq!(&p, b"ping");

        server.write_all(b"pong").await.unwrap();
        server.flush().await.unwrap();
        let mut two = [0u8; 2];
        tokio::io::AsyncReadExt::read_exact(&mut client, &mut two)
            .await
            .unwrap();
        assert_eq!(&two, b"po");

        // The peer abandons its write record layer; the rest is raw.
        server.splice_writes();
        assert!(server.writes_spliced());
        assert!(!server.reads_spliced());
        server.write_all(b"|raw-tail").await.unwrap();
        server.flush().await.unwrap();

        let mut raw = client.into_raw_transport().unwrap();
        assert_eq!(raw.read_ahead, b"ng", "exactly the buffered bytes first");
        let mut rest = vec![0u8; 9];
        tokio::io::AsyncReadExt::read_exact(&mut raw.transport, &mut rest)
            .await
            .unwrap();
        assert_eq!(rest, b"|raw-tail");
    }

    /// `into_raw_transport` refuses to lose a sealed record that is still
    /// pending in a write: the caller must flush first.
    #[tokio::test]
    async fn unwrap_refuses_a_pending_sealed_write() {
        let (mut client, _server) = rebind_pair().await;
        // Simulate a sealed pending write the way a mid-flight `poll_write`
        // would leave it.
        let sealed = client.write_key.seal(RECORD_APP, b"z").unwrap();
        client.out = sealed;
        client.out_plain = 1;
        let err = client.into_raw_transport().unwrap_err();
        assert!(err.to_string().contains("flush first"), "{err}");
    }

    /// Per-direction splice: after `splice_reads`, reads return the drained
    /// prefix and then raw transport bytes, while writes are still sealed
    /// (the uplink's own transition has not happened — upstream's reader
    /// flag and writer flag are independent, Xray `proxy/proxy.go:248-250`
    /// vs `:334-347`).
    #[tokio::test]
    async fn splice_reads_prefix_then_raw_writes_still_sealed() {
        let (mut client, mut server) = rebind_pair().await;

        // One sealed write; the client reads 3 bytes, leaving read-ahead.
        server.write_all(b"framed-tail").await.unwrap();
        server.flush().await.unwrap();
        let mut three = [0u8; 3];
        tokio::io::AsyncReadExt::read_exact(&mut client, &mut three)
            .await
            .unwrap();
        assert_eq!(&three, b"fra");

        // Ensure the sealed record has fully arrived before the peer goes
        // raw, so the raw bytes are deterministically *not* part of a record.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        server.splice_writes();
        server.write_all(b"rawdata").await.unwrap();
        server.flush().await.unwrap();

        client.splice_reads();
        assert!(client.reads_spliced());
        assert!(!client.writes_spliced());

        // Prefix ("med-tail" = the unread plaintext) then raw ("rawdata").
        let mut got = vec![0u8; 8 + 7];
        tokio::io::AsyncReadExt::read_exact(&mut client, &mut got)
            .await
            .unwrap();
        assert_eq!(got, b"med-tailrawdata".to_vec());

        // The write direction still seals: the server (read side not
        // spliced) decrypts the client's bytes as a normal record.
        client.write_all(b"still-sealed").await.unwrap();
        client.flush().await.unwrap();
        let mut back = vec![0u8; 12];
        tokio::io::AsyncReadExt::read_exact(&mut server, &mut back)
            .await
            .unwrap();
        assert_eq!(back, b"still-sealed".to_vec());
    }

    /// `splice_reads` also recovers *complete but undecrypted* records that
    /// were already pulled off the socket (upstream's Go tls.Conn has them
    /// decrypted into `input` by construction; we decrypt on demand, so the
    /// splice does it) and treats a trailing partial record as raw bytes
    /// (upstream `rawInput`).
    #[tokio::test]
    async fn splice_reads_decrypts_buffered_records_and_keeps_partial_raw() {
        let (mut client, mut server) = rebind_pair().await;

        // Two sealed records, both fully buffered before the client's first
        // read: the one `poll_read` that delivers the first byte pulls both
        // records into `rec` at once.
        server.write_all(b"first-record").await.unwrap();
        server.write_all(b"second-record").await.unwrap();
        server.flush().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;

        let mut one = [0u8; 1];
        tokio::io::AsyncReadExt::read_exact(&mut client, &mut one)
            .await
            .unwrap();
        assert_eq!(&one, b"f");

        // The peer abandons its record layer; the bytes after its last
        // sealed record are raw.
        server.splice_writes();
        server.write_all(b"RAW").await.unwrap();
        server.flush().await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        client.splice_reads();
        let mut got = vec![0u8; 11 + 13 + 3];
        tokio::io::AsyncReadExt::read_exact(&mut client, &mut got)
            .await
            .unwrap();
        assert_eq!(
            got,
            b"irst-recordsecond-recordRAW".to_vec(),
            "the buffered second record decrypts in order, then the raw tail"
        );
    }

    // --- ECH (RFC 9460 / metacubex/tls) ------------------------------------
    //
    // All against the in-tree ECH-terminating test peer: hermetic, fake
    // certs via rcgen, no network.

    use crate::proto::ech as ech_mod;
    use crate::proto::reality::tls13::test_server::{
        EchServerMode, accept_ech, ech_server_key, find_ext_body,
    };

    fn ech_webpki_auth(cert_der: &[u8], name: &str) -> ServerAuth {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der.to_vec().into()).unwrap();
        ServerAuth::WebPki {
            roots: Arc::new(roots),
            server_name: name.to_string(),
        }
    }

    /// A single-attempt dial closure over one duplex end.
    fn once_dial(
        io: tokio::io::DuplexStream,
    ) -> impl FnMut() -> std::future::Ready<Result<BoxProxyStream>> {
        let mut first = Some(Box::new(io) as BoxProxyStream);
        move || {
            std::future::ready(Ok(first
                .take()
                .expect("the test dials at most twice; got a third")))
        }
    }

    /// The happy path: the server terminates ECH (HPKE-open, confirmation
    /// ServerHello, inner-transcript handshake), the client verifies the
    /// certificate against the INNER name, and the relayed session echoes.
    #[tokio::test]
    async fn ech_accept_terminates_inner_and_relays() {
        let cert = self_signed("secret.example", &rcgen::PKCS_ED25519);
        let key = ech_server_key(b"ech-key-a", 0x11, b"public.example");
        let client_list = key.config_list.clone();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let signer = any_ed25519_signer(&cert);
        let der = cert.der.clone();

        let server_task = tokio::spawn(async move {
            let (mut tls, seen) = accept_ech(
                Box::new(server_io),
                CipherSuite::Aes128GcmSha256,
                &key,
                EchServerMode::Accept,
                move |_| Ok((der.clone(), signer.clone())),
            )
            .await
            .unwrap();
            // What the server saw must be the split-hello shapes.
            assert_eq!(seen.outer.sni.as_deref(), Some("public.example"));
            let inner = seen.inner.unwrap();
            assert_eq!(inner.sni.as_deref(), Some("secret.example"));
            assert_eq!(inner.alpn.first().map(String::as_str), Some("h2"));
            // Relay.
            let mut buf = [0u8; 5];
            tokio::io::AsyncReadExt::read_exact(&mut tls, &mut buf)
                .await
                .unwrap();
            tls.write_all(b"pong!").await.unwrap();
            tls.flush().await.unwrap();
            tls
        });

        let selection = ech_mod::select_ech_config(&client_list).unwrap();
        let cfg = EchCfg::new("secret.example", UtslProfile::Chrome, selection);
        let auth = ech_webpki_auth(&cert.der, "secret.example");
        let mut stream = connect_ech(&cfg, &auth, once_dial(client_io))
            .await
            .expect("the ECH handshake must succeed");
        assert_eq!(stream.suite(), CipherSuite::Aes128GcmSha256);
        assert_eq!(stream.alpn(), Some(&b"h2"[..]));
        assert!(stream.cert_verified());
        stream.write_all(b"ping!").await.unwrap();
        let mut buf = [0u8; 5];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf)
            .await
            .unwrap();
        assert_eq!(&buf, b"pong!");
        drop(stream);
        let _ = server_task.await.unwrap();
    }

    fn any_ed25519_signer(cert: &TestCert) -> Arc<dyn rustls::sign::SigningKey> {
        rustls::crypto::ring::sign::any_supported_type(&cert.key).unwrap()
    }

    /// Acceptance verifies against the INNER name: a certificate issued for
    /// the OUTER public name must fail webpki (it would pass if the client
    /// verified the outer name).
    #[tokio::test]
    async fn ech_accept_verifies_against_the_inner_name() {
        // The server presents a cert for the PUBLIC name.
        let cert = self_signed("public.example", &rcgen::PKCS_ECDSA_P256_SHA256);
        let key = ech_server_key(b"ech-key-a", 0x11, b"public.example");
        let client_list = key.config_list.clone();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let signer = any_ecdsa_signer(&cert);
        let der = cert.der.clone();
        let server_task = tokio::spawn(async move {
            // The client aborts at verification; the server's read of the
            // client Finished may or may not complete first.
            let _ = accept_ech(
                Box::new(server_io),
                CipherSuite::Aes128GcmSha256,
                &key,
                EchServerMode::Accept,
                move |_| Ok((der.clone(), signer.clone())),
            )
            .await;
        });

        let selection = ech_mod::select_ech_config(&client_list).unwrap();
        let cfg = EchCfg::new("secret.example", UtslProfile::Chrome, selection);
        // The client trusts the cert but requires the INNER name.
        let auth = ech_webpki_auth(&cert.der, "secret.example");
        let err = connect_ech(&cfg, &auth, once_dial(client_io))
            .await
            .expect_err("a public-name certificate must not pass inner verification");
        assert!(
            err.to_string().contains("certificate verification failed"),
            "{err}"
        );
        let _ = server_task.await;
    }

    fn any_ecdsa_signer(cert: &TestCert) -> Arc<dyn rustls::sign::SigningKey> {
        rustls::crypto::ring::sign::any_supported_type(&cert.key).unwrap()
    }

    /// A server that cannot open the payload (different key: the wrong
    /// config id / key pair) rejects, and the client fails with the exact
    /// upstream `ECHRejectionError` text — no fallback, no retry material.
    #[tokio::test]
    async fn ech_rejection_wrong_key_is_the_upstream_error() {
        let cert = self_signed("public.example", &rcgen::PKCS_ECDSA_P256_SHA256);
        let server_key = ech_server_key(b"server-real-key", 0x22, b"public.example");
        let client_list = ech_server_key(b"client-stale-key", 0x22, b"public.example").config_list;
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let signer = any_ecdsa_signer(&cert);
        let der = cert.der.clone();
        let server_task = tokio::spawn(async move {
            let r = accept_ech(
                Box::new(server_io),
                CipherSuite::Aes128GcmSha256,
                &server_key,
                EchServerMode::Reject {
                    retry_configs: None,
                },
                move |_| Ok((der.clone(), signer.clone())),
            )
            .await;
            // The handshake completes in outer mode; the client then sends
            // the ech_required alert and drops.
            assert!(r.is_ok(), "{:?}", r.err().map(|e| e.to_string()));
        });

        let selection = ech_mod::select_ech_config(&client_list).unwrap();
        let cfg = EchCfg::new("secret.example", UtslProfile::Chrome, selection);
        let auth = ech_webpki_auth(&cert.der, "secret.example");
        let err = connect_ech(&cfg, &auth, once_dial(client_io))
            .await
            .expect_err("the stale key must be rejected");
        // ECHRejectionError.Error() (ech.go:491).
        assert!(
            err.to_string().contains("tls: server rejected ECH"),
            "{err}"
        );
        let _ = server_task.await;
    }

    /// One retry with the server-provided retry configs: the first attempt
    /// is rejected with a usable list, the second (fresh transport, fresh
    /// keys, the retry config) succeeds.
    #[tokio::test]
    async fn ech_retries_once_with_the_retry_configs() {
        // The rejecting server presents the PUBLIC-name certificate (the
        // rejected handshake verifies against it); the accepting retry
        // presents the inner-name one.
        let public_cert = self_signed("public.example", &rcgen::PKCS_ED25519);
        let cert = self_signed("secret.example", &rcgen::PKCS_ED25519);
        let stale = ech_server_key(b"client-stale-key", 0x33, b"public.example");
        let real = ech_server_key(b"server-real-key", 0x44, b"public.example");
        let (io1, srv1) = tokio::io::duplex(64 * 1024);
        let (io2, srv2) = tokio::io::duplex(64 * 1024);
        let signer = any_ed25519_signer(&public_cert);
        let der = public_cert.der.clone();
        let retry_list = real.config_list.clone();

        let server1 = tokio::spawn(async move {
            accept_ech(
                Box::new(srv1),
                CipherSuite::Aes128GcmSha256,
                &real,
                EchServerMode::Reject {
                    retry_configs: Some(retry_list),
                },
                move |_| Ok((der.clone(), signer.clone())),
            )
            .await
            .unwrap();
        });
        let der2 = cert.der.clone();
        let signer2 = any_ed25519_signer(&cert);
        let real2 = ech_server_key(b"server-real-key", 0x44, b"public.example");
        let server2 = tokio::spawn(async move {
            let (mut tls, seen) = accept_ech(
                Box::new(srv2),
                CipherSuite::Aes128GcmSha256,
                &real2,
                EchServerMode::Accept,
                move |_| Ok((der2.clone(), signer2.clone())),
            )
            .await
            .unwrap();
            assert_eq!(seen.inner.unwrap().sni.as_deref(), Some("secret.example"));
            let mut buf = [0u8; 4];
            tokio::io::AsyncReadExt::read_exact(&mut tls, &mut buf)
                .await
                .unwrap();
            assert_eq!(&buf, b"echo");
            tls.write_all(b"back").await.unwrap();
            tls.flush().await.unwrap();
        });

        let selection = ech_mod::select_ech_config(&stale.config_list).unwrap();
        let cfg = EchCfg::new("secret.example", UtslProfile::Firefox, selection);
        // Trust BOTH certificates: the rejected first attempt verifies the
        // public-name one, the accepted retry the inner-name one.
        let mut roots = rustls::RootCertStore::empty();
        roots.add(public_cert.der.clone().into()).unwrap();
        roots.add(cert.der.clone().into()).unwrap();
        let auth = ServerAuth::WebPki {
            roots: Arc::new(roots),
            server_name: "secret.example".to_string(),
        };
        let mut dials = 0usize;
        let mut first = Some(Box::new(io1) as BoxProxyStream);
        let mut second = Some(Box::new(io2) as BoxProxyStream);
        let mut stream = connect_ech(&cfg, &auth, || {
            dials += 1;
            let io = match dials {
                1 => first.take().unwrap(),
                2 => second.take().unwrap(),
                _ => panic!("a third dial must never happen"),
            };
            std::future::ready(Ok(io))
        })
        .await
        .expect("the retry attempt must succeed");
        assert_eq!(dials, 2, "exactly one retry");
        assert!(stream.cert_verified());
        stream.write_all(b"echo").await.unwrap();
        let mut buf = [0u8; 4];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf)
            .await
            .unwrap();
        assert_eq!(&buf, b"back");
        drop(stream);
        server1.await.unwrap();
        server2.await.unwrap();
    }

    /// A second rejection after the retry still ends with the upstream
    /// error (and no third dial).
    #[tokio::test]
    async fn ech_second_rejection_fails_without_more_dials() {
        let cert = self_signed("public.example", &rcgen::PKCS_ECDSA_P256_SHA256);
        let stale = ech_server_key(b"client-stale-key", 0x55, b"public.example");
        let real = ech_server_key(b"server-real-key", 0x66, b"public.example");
        let (io1, srv1) = tokio::io::duplex(64 * 1024);
        let (io2, srv2) = tokio::io::duplex(64 * 1024);
        let signer = any_ecdsa_signer(&cert);
        let der = cert.der.clone();
        let retry_list = real.config_list.clone();
        let server1 = tokio::spawn(async move {
            accept_ech(
                Box::new(srv1),
                CipherSuite::Aes128GcmSha256,
                &real,
                EchServerMode::Reject {
                    retry_configs: Some(retry_list),
                },
                move |_| Ok((der.clone(), signer.clone())),
            )
            .await
            .unwrap();
        });
        let der2 = cert.der.clone();
        let signer2 = any_ecdsa_signer(&cert);
        // The second server also rejects (with nothing usable).
        let server2 = tokio::spawn(async move {
            accept_ech(
                Box::new(srv2),
                CipherSuite::Aes128GcmSha256,
                &ech_server_key(b"server-real-key", 0x66, b"public.example"),
                EchServerMode::Reject {
                    retry_configs: None,
                },
                move |_| Ok((der2.clone(), signer2.clone())),
            )
            .await
            .unwrap();
        });

        let selection = ech_mod::select_ech_config(&stale.config_list).unwrap();
        let cfg = EchCfg::new("secret.example", UtslProfile::Chrome, selection);
        let auth = ech_webpki_auth(&cert.der, "secret.example");
        let mut dials = 0usize;
        let mut first = Some(Box::new(io1) as BoxProxyStream);
        let mut second = Some(Box::new(io2) as BoxProxyStream);
        let err = connect_ech(&cfg, &auth, || {
            dials += 1;
            let io = match dials {
                1 => first.take().unwrap(),
                2 => second.take().unwrap(),
                _ => panic!("a third dial must never happen"),
            };
            std::future::ready(Ok(io))
        })
        .await
        .expect_err("the second rejection must fail");
        assert_eq!(dials, 2);
        assert!(
            err.to_string().contains("tls: server rejected ECH"),
            "{err}"
        );
        server1.await.unwrap();
        server2.await.unwrap();
    }

    /// The HRR accept path: the server HelloRetryRequests with a cookie and
    /// a valid hrr confirmation; the client re-seals the second hello
    /// WITHOUT the encapsulated key (HPKE sequence 1) and completes.
    #[tokio::test]
    async fn ech_hrr_accept_with_cookie_and_reseal() {
        let cert = self_signed("secret.example", &rcgen::PKCS_ED25519);
        let key = ech_server_key(b"ech-hrr-key", 0x77, b"public.example");
        let client_list = key.config_list.clone();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let signer = any_ed25519_signer(&cert);
        let der = cert.der.clone();
        let server_task = tokio::spawn(async move {
            let (mut tls, seen) = accept_ech(
                Box::new(server_io),
                CipherSuite::Aes128GcmSha256,
                &key,
                EchServerMode::Hrr {
                    accept: true,
                    retry_configs: None,
                },
                move |_| Ok((der.clone(), signer.clone())),
            )
            .await
            .expect("the HRR accept handshake must complete");
            // The second inner carried the cookie extension.
            let inner = seen.inner.unwrap();
            let has_cookie = find_ext_body(&inner.raw, 0x002c)
                .expect("cookie ext lookup")
                .is_some();
            assert!(has_cookie, "the second inner hello carries the cookie");
            let mut buf = [0u8; 3];
            tokio::io::AsyncReadExt::read_exact(&mut tls, &mut buf)
                .await
                .unwrap();
            tls.write_all(b"ok!").await.unwrap();
            tls.flush().await.unwrap();
        });

        let selection = ech_mod::select_ech_config(&client_list).unwrap();
        let cfg = EchCfg::new("secret.example", UtslProfile::Chrome, selection);
        let auth = ech_webpki_auth(&cert.der, "secret.example");
        let mut stream = connect_ech(&cfg, &auth, once_dial(client_io))
            .await
            .expect("the HRR accept handshake must succeed");
        stream.write_all(b"hi!").await.unwrap();
        let mut buf = [0u8; 3];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf)
            .await
            .unwrap();
        assert_eq!(&buf, b"ok!");
        drop(stream);
        let _ = server_task.await;
    }

    /// An HRR whose 8-byte ECH extension does NOT confirm (zeros) rejects:
    /// the client completes the second flight in outer mode and fails with
    /// the upstream rejection error.
    #[tokio::test]
    async fn ech_hrr_zero_confirmation_rejects() {
        let cert = self_signed("public.example", &rcgen::PKCS_ECDSA_P256_SHA256);
        let key = ech_server_key(b"ech-hrr-key", 0x88, b"public.example");
        let client_list = key.config_list.clone();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let signer = any_ecdsa_signer(&cert);
        let der = cert.der.clone();
        let server_task = tokio::spawn(async move {
            accept_ech(
                Box::new(server_io),
                CipherSuite::Aes128GcmSha256,
                &key,
                EchServerMode::Hrr {
                    accept: false,
                    retry_configs: None,
                },
                move |_| Ok((der.clone(), signer.clone())),
            )
            .await
            .unwrap();
        });

        let selection = ech_mod::select_ech_config(&client_list).unwrap();
        let cfg = EchCfg::new("secret.example", UtslProfile::Chrome, selection);
        let auth = ech_webpki_auth(&cert.der, "secret.example");
        let err = connect_ech(&cfg, &auth, once_dial(client_io))
            .await
            .expect_err("the zero confirmation must reject");
        assert!(
            err.to_string().contains("tls: server rejected ECH"),
            "{err}"
        );
        let _ = server_task.await;
    }

    /// The SHA-384 suite drives the ECH confirmation and schedule too.
    #[tokio::test]
    async fn ech_accept_sha384_suite() {
        let cert = self_signed("secret.example", &rcgen::PKCS_ECDSA_P256_SHA256);
        let key = ech_server_key(b"ech-key-sha384", 0x99, b"public.example");
        let client_list = key.config_list.clone();
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let signer = any_ecdsa_signer(&cert);
        let der = cert.der.clone();
        let server_task = tokio::spawn(async move {
            let (mut tls, _seen) = accept_ech(
                Box::new(server_io),
                CipherSuite::Aes256GcmSha384,
                &key,
                EchServerMode::Accept,
                move |_| Ok((der.clone(), signer.clone())),
            )
            .await
            .unwrap();
            let mut buf = [0u8; 6];
            tokio::io::AsyncReadExt::read_exact(&mut tls, &mut buf)
                .await
                .unwrap();
            tls.write_all(b"sha384").await.unwrap();
            tls.flush().await.unwrap();
        });

        let selection = ech_mod::select_ech_config(&client_list).unwrap();
        let cfg = EchCfg::new("secret.example", UtslProfile::Chrome, selection);
        let auth = ech_webpki_auth(&cert.der, "secret.example");
        let mut stream = connect_ech(&cfg, &auth, once_dial(client_io))
            .await
            .expect("the SHA-384 ECH handshake");
        assert_eq!(stream.suite(), CipherSuite::Aes256GcmSha384);
        stream.write_all(b"cipher").await.unwrap();
        let mut buf = [0u8; 6];
        tokio::io::AsyncReadExt::read_exact(&mut stream, &mut buf)
            .await
            .unwrap();
        assert_eq!(&buf, b"sha384");
        drop(stream);
        let _ = server_task.await;
    }

    /// Byte-level shape pins on the built hello pair, including the
    /// round-trip invariant the whole transcript correctness rests on: the
    /// server-side reconstruction of the sealed inner equals the client's
    /// transcript-form inner.
    #[test]
    fn ech_hello_shapes_and_roundtrip_reconstruction() {
        let key = ech_server_key(b"ech-shape-key", 0xab, b"public.example");
        let selection = ech_mod::select_ech_config(&key.config_list).unwrap();
        let cfg = EchCfg {
            server_name: "secret.example".into(),
            profile: UtslProfile::Chrome,
            alpn: vec!["h2".into()],
            ech: EchHandshakeParams {
                selection,
                inner_random: Some([0x11; 32]),
                outer_random: Some([0x22; 32]),
                session_id: Some([0x33; 32]),
                x25519_secret: Some([0x44; 32]),
                hpke_secret: Some([0x55; 32]),
            },
        };
        // Rebuild the pair the same way ech_attempt does.
        let (set, _client_sender) = EchHelloSet::build(
            &cfg,
            &cfg.ech.selection,
            [0x11; 32],
            [0x22; 32],
            [0x33; 32],
            [0x44; 32],
            &[0x55; 32],
        )
        .unwrap();
        // Server-side recipient over the same config: decap the `enc` out of
        // the outer's ECH extension and run the key schedule.
        let configs = ech_mod::parse_ech_config_list(&key.config_list).unwrap();
        let ext_body =
            test_server::find_ext_body(&set.outer_msg, ech_mod::EXTENSION_ENCRYPTED_CLIENT_HELLO)
                .unwrap()
                .unwrap();
        let (aead_id, enc) = match ech_mod::parse_ech_ext(&ext_body).unwrap() {
            ech_mod::EchExt::Outer { aead_id, enc, .. } => (aead_id, enc),
            other => panic!("outer ext expected, got {other:?}"),
        };
        assert_eq!(enc.len(), 32);
        let enc: [u8; 32] = enc.try_into().unwrap();
        let shared = ech_mod::hpke_decap(&key.sk_r, &enc).unwrap();
        let mut server_recipient = ech_mod::HpkeSender::from_shared_secret(
            &shared,
            ech_mod::HpkeAead::from_id(aead_id).unwrap(),
            &ech_mod::ech_hpke_info(&configs[0]),
        )
        .unwrap();

        // Outer: public SNI, the sealed ECH ext, and the compat extensions
        // the inner drops; no 1.2-only version in supported_versions.
        let outer_info = test_server::parse_client_hello(&set.outer_msg).unwrap();
        assert_eq!(outer_info.sni.as_deref(), Some("public.example"));
        assert!(find_ext_body(&set.outer_msg, 0x000b).unwrap().is_some());
        assert!(find_ext_body(&set.outer_msg, 0x0023).unwrap().is_some());
        assert!(find_ext_body(&set.outer_msg, 0xff01).unwrap().is_some());
        assert!(find_ext_body(&set.outer_msg, 0x0017).unwrap().is_some());
        let sv = find_ext_body(&set.outer_msg, EXT_SUPPORTED_VERSIONS)
            .unwrap()
            .unwrap();
        assert!(!sv[1..].chunks(2).any(|c| c == [0x03, 0x03]));
        assert!(sv[1..].chunks(2).any(|c| c == [0x03, 0x04]));

        // Inner (transcript form): real SNI, 32-byte session id, marker,
        // and none of the four compat extensions.
        let inner_info = test_server::parse_client_hello(&set.inner_msg).unwrap();
        assert_eq!(inner_info.sni.as_deref(), Some("secret.example"));
        assert_eq!(inner_info.session_id.len(), 32);
        assert!(
            find_ext_body(&set.inner_msg, ech_mod::EXTENSION_ENCRYPTED_CLIENT_HELLO)
                .unwrap()
                .is_some()
        );
        for dropped in [0x000bu16, 0x0023, 0xff01, 0x0017] {
            assert!(
                find_ext_body(&set.inner_msg, dropped).unwrap().is_none(),
                "the inner must not carry {dropped:#06x}"
            );
        }
        // The outer hello in the clear must not leak the inner name.
        assert!(
            !set.outer_msg
                .windows(b"secret.example".len())
                .any(|w| w == b"secret.example")
        );

        // Round-trip: HPKE-open the outer payload and reconstruct — the
        // result must equal the client's transcript-form inner byte for
        // byte (this is the invariant that makes the Finished keys match).
        let opened = test_server::open_ech_hello(&set.outer_msg, &mut server_recipient).unwrap();
        assert_eq!(
            opened, set.inner_msg,
            "server transcript form == client transcript form"
        );
    }

    /// The generic (SHA-256) confirmation must agree byte for byte with the
    /// standalone wave-7 helper in proto::ech.
    #[test]
    fn ech_confirmation_matches_the_ech_module() {
        let inner_random = [0x42u8; 32];
        let sh: Vec<u8> = (0..96u16).map(|i| (i % 251) as u8).collect();
        let mut t = Transcript::new(HashKind::Sha256);
        t.update(&[0x55; 64]);
        let mine = ech_accept_confirmation(HashKind::Sha256, &t, &sh, &inner_random).unwrap();
        let reference = ech_mod::server_hello_accept_confirmation(
            &ech_mod::transcript_context(&[&[0x55; 64]]),
            &sh,
            &inner_random,
        )
        .unwrap();
        assert_eq!(mine, reference);
        // And the HRR variant likewise.
        let mut hrr = vec![2u8, 0, 0, 60];
        hrr.extend_from_slice(&[0u8; 40]);
        let value = [0x99u8; 8];
        hrr.extend_from_slice(&value);
        hrr.extend_from_slice(&[1u8; 12]);
        let mut folded = Transcript::new(HashKind::Sha256);
        folded.update(&[0x55; 64]);
        let mine_hrr =
            ech_hrr_confirmation(HashKind::Sha256, &folded, &hrr, &value, &inner_random).unwrap();
        let reference_hrr = ech_mod::hrr_accept_confirmation(
            &ech_mod::transcript_context(&[&[0x55; 64]]),
            &hrr,
            &value,
            &inner_random,
        )
        .unwrap();
        assert_eq!(mine_hrr, reference_hrr);
    }
}
