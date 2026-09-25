//! A quinn `crypto::ClientConfig` over the engine's OWN TLS 1.3 stack —
//! the seam that carries ECH and JLS into QUIC-based outbounds.
//!
//! ## Why this exists
//!
//! quinn 0.11 performs its QUIC-TLS handshake through the trait-based
//! `quinn::crypto` layer (`quinn_proto` src/crypto.rs:28-121: `Session`,
//! `ClientConfig`, `Keys`, `PacketKey`, `HeaderKey`), whose only in-tree
//! implementation is rustls (`quinn_proto` src/crypto/rustls.rs:38-212).
//! rustls lets no caller write the ClientHello bytes, so everything that
//! lives *inside* the hello — ECH's inner/outer split (RFC 9460), JLS'
//! credential-carrying random (`proto::jls`) — could not ride QUIC. This
//! module implements the quinn crypto traits over the engine's own TLS
//! 1.3 machinery (`proto::reality::tls13`, whose client handshake is a
//! byte-level state machine) and thereby closes that gap:
//!
//! * **JLS-in-QUIC**: the ClientHello random is the JLS-sealed seed
//!   (`jls::build_fake_random` over `jls::hello_auth_data` of the
//!   serialized hello — exactly how the TCP fingerprint path stamps it,
//!   `proto/jls.rs:913-963`; upstream rides the same construction inside
//!   QUIC via jls-quic-go `crypto_setup.go:93` → `tls.QUICClient` of the
//!   metacubex/jls-tls fork) and the ServerHello random is validated with
//!   `jls::check_fake_random` (`jls::ERR_AUTH_FAILED` on failure).
//! * **ECH-on-QUIC**: the first flight is the ECH outer/inner pair of
//!   `reality::tls13::connect_ech` (inner hello HPKE-sealed inside the
//!   outer, `proto::ech.rs` core), with the QUIC transport parameters
//!   embedded in the INNER hello (RFC 9460 §6.1/§8.2 — the real
//!   handshake is the inner one). Accept confirmation, rejection (with
//!   the retry ECHConfigList captured for a one-shot dial-level retry)
//!   and the HelloRetryRequest cookie flight are all ported.
//!
//! ## Design
//!
//! * [`Tls13QuicClientConfig`] implements `quinn_proto::crypto::ClientConfig`
//!   over a hello-builder closure: `start_session(version, server_name,
//!   params)` (quinn_proto src/crypto.rs:113-121) serializes quinn's own
//!   [`TransportParameters`] (`params.write(...)`, the exact `to_vec` of
//!   quinn's rustls glue — quinn_proto src/crypto/rustls.rs:590-594),
//!   hands them to the builder, and queues the produced hello as the
//!   first CRYPTO flight.
//! * [`Tls13QuicSession`] implements `crypto::Session` as a phase machine
//!   over the CRYPTO stream quinn drives: `read_handshake` steps the
//!   byte-level TLS 1.3 handshake (ServerHello → EncryptedExtensions →
//!   Certificate → CertificateVerify → Finished), mirroring the engine's
//!   transport-driven `reality::tls13::connect`
//!   (engine/src/proto/reality/tls13.rs:1155-1312, cited per step);
//!   `write_handshake` drains the Initial-space queue, then surfaces the
//!   handshake-space `Keys`, then drains the Handshake-space queue and
//!   surfaces the 1-RTT keys — the same phase protocol as rustls's
//!   `write_hs` (rustls-0.23.37 src/quic.rs:478-510), which quinn's
//!   `write_crypto`/`upgrade_crypto` consumes by sending a call's bytes
//!   in the CURRENT packet space while the returned keys arm the NEXT
//!   one (quinn_proto src/connection/mod.rs:2149-2208).
//! * Packet keys: initial keys come from rustls's public QUIC API
//!   (`rustls::quic::Suite::keys`, rustls-0.23.37 src/quic.rs:889-970 —
//!   byte-identical with quinn's own `initial_keys`, quinn_proto
//!   src/crypto/rustls.rs:596-613; the returned
//!   `Box<dyn rustls::quic::PacketKey>` boxes already implement quinn's
//!   traits via quinn_proto src/crypto/rustls.rs:228-256/615-648).
//!   Handshake/1-RTT keys derive from the TLS traffic secrets with the
//!   RFC 9001 §5.1 labels (`quic key`/`quic iv`/`quic hp`, rustls-0.23.37
//!   src/quic.rs:1012-1033) into ring-backed [`QuicPacketKey`]/
//!   [`QuicHeaderKey`] mirroring rustls's ring provider (rustls-0.23.37
//!   src/crypto/ring/quic.rs:19-77,97-160).
//! * Certificate verification reuses `reality::tls13::ServerAuth` (the
//!   webpki walk mirrors reality/tls13.rs:1316-1340); the CertificateVerify
//!   *signature* check mirrors reality/tls13.rs:894-955.
//! * A `#[cfg(test)]` quinn SERVER ([`test_server`]) implements
//!   `crypto::ServerConfig` over the same session machinery so JLS and
//!   ECH termination can be exercised hermetically at the QUIC layer.
//!
//! Scope notes / deltas, all deliberate:
//!
//! * TLS 1.3 only, X25519 only, suites 0x1301/0x1302/0x1303 — the surface
//!   of `reality::tls13::CipherSuite`.
//! * No 0-RTT (`early_crypto` returns `None`), no PSK, no client auth,
//!   no certificate compression.
//! * QUIC v1 only (`start_session` rejects other versions; quinn has no
//!   v2 implementation anyway).
//! * ECH rejection surfaces as the upstream error text
//!   `"tls: server rejected ECH"` (metacubex/tls ech.go:486-492), with
//!   the server's retry ECHConfigList appended as
//!   `; retry-configs=<base64>` so [`ech_retry_configs_of`] can perform
//!   the one-shot retry upstream's caller-side loop does
//!   (reality/tls13.rs:1464-1488).

use std::any::Any;
use std::io::Cursor;
use std::sync::Arc;

use bytes::BytesMut;
use hkdf::Hkdf;
use rand::RngCore;
use ring::aead;
use sha2::{Digest, Sha256, Sha384};

use quinn_proto::crypto::{
    ClientConfig as QuinnCryptoClientConfig, CryptoError, ExportKeyingMaterialError, HeaderKey,
    KeyPair, Keys, PacketKey, Session,
};
use quinn_proto::transport_parameters::TransportParameters;
use quinn_proto::{ConnectError, Side as QuinnSide, TransportError, TransportErrorCode};

use crate::error::{Error, Result};
use crate::proto::ech;
use crate::proto::jls;
use crate::proto::reality::profiles::{self, UtslProfile};
use crate::proto::reality::tls13 as engine_tls13;
use crate::proto::reality::tls13::CipherSuite;

/// `quic_transport_parameters` extension codepoint (RFC 9001 §8; rustls
/// carries these bytes into the extension verbatim — rustls-0.23.37
/// src/msgs/handshake.rs:813-827 `TransportParameters::Quic`).
pub const EXT_TRANSPORT_PARAMETERS: u16 = 0x39;

const VERSION_TLS13: u16 = 0x0304;
const VERSION_TLS12: u16 = 0x0303;
/// QUIC v1 wire version.
const QUIC_V1: u32 = 0x0000_0001;

const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;
const HS_NEW_SESSION_TICKET: u8 = 4;
const HS_ENCRYPTED_EXTENSIONS: u8 = 8;
const HS_CERTIFICATE: u8 = 11;
const HS_COMPRESSED_CERTIFICATE: u8 = 25;
const HS_CERTIFICATE_VERIFY: u8 = 15;
const HS_FINISHED: u8 = 20;

const EXT_ALPN: u16 = 0x0010;
const EXT_SUPPORTED_VERSIONS: u16 = 0x002b;
const EXT_KEY_SHARE: u16 = 0x0033;
const EXT_PRE_SHARED_KEY: u16 = 0x0029;
const EXT_COOKIE: u16 = 0x002c;
const EXT_SCTS: u16 = 0x0012;
const EXT_SERVER_NAME: u16 = 0x0000;
const GROUP_X25519: u16 = 0x001d;

/// The HelloRetryRequest random (RFC 8446 §4.1.3), spelled out in
/// reality/tls13.rs:730-733.
const HRR_RANDOM: [u8; 32] = [
    0xcf, 0x21, 0xad, 0x74, 0xe5, 0x9a, 0x61, 0x11, 0xbe, 0x1d, 0x8c, 0x02, 0x1e, 0x65, 0xb8, 0x91,
    0xc2, 0xa2, 0x11, 0x16, 0x7a, 0xbb, 0x8c, 0x5e, 0x07, 0x9e, 0x09, 0xe2, 0xc8, 0xa8, 0x33, 0x9c,
];

/// RFC 8446 §4.4.3 context string for the server's CertificateVerify
/// (reality/tls13.rs:97).
const SERVER_SIGNATURE_CONTEXT: &[u8] = b"TLS 1.3, server CertificateVerify";

/// The upstream ECH rejection sentinel (metacubex/tls ech.go:486-492;
/// `reality::tls13::connect_ech` uses the same text).
pub const ERR_ECH_REJECTED: &str = "tls: server rejected ECH";

// ---------------------------------------------------------------------------
// Key schedule — a mirror of reality/tls13.rs:306-572 (the suite hash
// drives transcript hashes, HKDF-Expand-Label with the "tls13 " prefix,
// the RFC 8446 §7.1 chain, and the Finished HMAC). Duplicated here
// because those items are private to that module; each function cites
// its mirrored line range.
// ---------------------------------------------------------------------------

/// The hash a cipher suite's key schedule is built on
/// (reality/tls13.rs:314-318).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HashKind {
    Sha256,
    Sha384,
}

impl HashKind {
    fn digest_len(self) -> usize {
        match self {
            HashKind::Sha256 => 32,
            HashKind::Sha384 => 48,
        }
    }

    fn hash(self, data: &[u8]) -> Vec<u8> {
        match self {
            HashKind::Sha256 => Sha256::digest(data).to_vec(),
            HashKind::Sha384 => Sha384::digest(data).to_vec(),
        }
    }

    /// HKDF-Expand-Label (reality/tls13.rs:337-372).
    fn hkdf_expand_label(
        self,
        secret: &[u8],
        label: &str,
        context: &[u8],
        out: &mut [u8],
    ) -> Result<()> {
        self.hkdf_expand_label_raw(secret, label.as_bytes(), context, out)
    }

    /// The same with an opaque byte label — RFC 8446 exporter labels are
    /// not constrained to UTF-8 (the TUIC v5 auth token uses the raw
    /// UUID as its label, proto/tuic.rs).
    fn hkdf_expand_label_raw(
        self,
        secret: &[u8],
        label: &[u8],
        context: &[u8],
        out: &mut [u8],
    ) -> Result<()> {
        if 6 + label.len() > u8::MAX as usize || out.len() > u16::MAX as usize {
            return Err(Error::crypto("quic-tls13: label/output too long"));
        }
        let mut info = Vec::with_capacity(2 + 1 + label.len() + 1 + context.len());
        info.extend_from_slice(&(out.len() as u16).to_be_bytes());
        info.push((6 + label.len()) as u8); // "tls13 " + label
        info.extend_from_slice(b"tls13 ");
        info.extend_from_slice(label);
        info.push(context.len() as u8);
        info.extend_from_slice(context);
        match self {
            HashKind::Sha256 => Hkdf::<Sha256>::from_prk(secret)
                .map_err(|_| Error::crypto("quic-tls13: bad secret"))?
                .expand(&info, out)
                .map_err(|_| Error::crypto("quic-tls13: hkdf expand failed")),
            HashKind::Sha384 => Hkdf::<Sha384>::from_prk(secret)
                .map_err(|_| Error::crypto("quic-tls13: bad secret"))?
                .expand(&info, out)
                .map_err(|_| Error::crypto("quic-tls13: hkdf expand failed")),
        }
    }

    /// Finished `verify_data` HMAC (reality/tls13.rs:374-410).
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

    /// Constant-time Finished check (reality/tls13.rs:393-410).
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

impl CipherSuite {
    /// The suite's schedule hash (reality/tls13.rs:147-152).
    fn quic_hash(self) -> HashKind {
        match self {
            CipherSuite::Aes128GcmSha256 | CipherSuite::Chacha20Poly1305Sha256 => HashKind::Sha256,
            CipherSuite::Aes256GcmSha384 => HashKind::Sha384,
        }
    }

    /// ring AEAD for packet protection (reality/tls13.rs:138-144).
    fn ring_aead(self) -> &'static aead::Algorithm {
        match self {
            CipherSuite::Aes128GcmSha256 => &aead::AES_128_GCM,
            CipherSuite::Aes256GcmSha384 => &aead::AES_256_GCM,
            CipherSuite::Chacha20Poly1305Sha256 => &aead::CHACHA20_POLY1305,
        }
    }

    /// ring header-protection algorithm (RFC 9001 §5.4.3: AES suites use
    /// AES-ECB, ChaCha suites ChaCha20; ring's quic module provides
    /// exactly these — ring-0.17.14 src/aead/quic.rs:131-176).
    fn ring_hp(self) -> &'static aead::quic::Algorithm {
        match self {
            CipherSuite::Aes128GcmSha256 => &aead::quic::AES_128,
            CipherSuite::Aes256GcmSha384 => &aead::quic::AES_256,
            CipherSuite::Chacha20Poly1305Sha256 => &aead::quic::CHACHA20,
        }
    }

    /// (confidentiality_limit, integrity_limit) per RFC 9001 §6, as
    /// rustls's ring provider pins them (rustls-0.23.37
    /// src/crypto/ring/tls13.rs:26-80).
    fn quic_limits(self) -> (u64, u64) {
        match self {
            CipherSuite::Aes128GcmSha256 | CipherSuite::Aes256GcmSha384 => (1 << 23, 1 << 52),
            CipherSuite::Chacha20Poly1305Sha256 => (u64::MAX, 1 << 36),
        }
    }
}

/// Running transcript hash (reality/tls13.rs:413-466).
#[derive(Clone)]
struct Transcript {
    kind: HashKind,
    sha256: Sha256,
    sha384: Sha384,
}

impl Transcript {
    fn new(kind: HashKind) -> Self {
        Transcript {
            kind,
            sha256: Sha256::new(),
            sha384: Sha384::new(),
        }
    }

    fn update(&mut self, bytes: &[u8]) {
        match self.kind {
            HashKind::Sha256 => self.sha256.update(bytes),
            HashKind::Sha384 => self.sha384.update(bytes),
        }
    }

    fn hash(&self) -> Vec<u8> {
        match self.kind {
            HashKind::Sha256 => self.sha256.clone().finalize().to_vec(),
            HashKind::Sha384 => self.sha384.clone().finalize().to_vec(),
        }
    }

    /// The RFC 8446 §4.4.1 `message_hash` fold for the HRR path
    /// (reality/tls13.rs:451-466; both ECH transcripts fold first,
    /// metacubex/tls handshake_client_tls13.go:238-253).
    fn fold_message_hash(&self) -> Transcript {
        let digest = self.hash();
        let mut folded = Transcript::new(self.kind);
        let mut wrap = Vec::with_capacity(4 + digest.len());
        wrap.push(254);
        wrap.push(0);
        wrap.push(0);
        wrap.push(digest.len() as u8);
        wrap.extend_from_slice(&digest);
        folded.update(&wrap);
        folded
    }
}

/// HKDF-Extract (reality/tls13.rs:469-475).
fn hkdf_extract(hash: HashKind, salt: &[u8], ikm: &[u8]) -> Vec<u8> {
    match hash {
        HashKind::Sha256 => Hkdf::<Sha256>::extract(Some(salt), ikm).0.to_vec(),
        HashKind::Sha384 => Hkdf::<Sha384>::extract(Some(salt), ikm).0.to_vec(),
    }
}

/// Derive-Secret (reality/tls13.rs:477-487).
fn derive_secret(hash: HashKind, secret: &[u8], label: &str, th: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0u8; hash.digest_len()];
    hash.hkdf_expand_label(secret, label, th, &mut out)?;
    Ok(out)
}

/// The handshake secret triple (reality/tls13.rs:529-553).
#[derive(Clone)]
struct HandshakeSecrets {
    c_hs: Vec<u8>,
    s_hs: Vec<u8>,
    master: Vec<u8>,
}

fn handshake_secrets(
    suite: CipherSuite,
    shared: &[u8; 32],
    transcript_hash: &[u8],
) -> Result<HandshakeSecrets> {
    let hash = suite.quic_hash();
    let zeros = vec![0u8; hash.digest_len()];
    let empty_hash = hash.hash(&[]);
    let early_secret = hkdf_extract(hash, &zeros, &zeros);
    let derived = derive_secret(hash, &early_secret, "derived", &empty_hash)?;
    let handshake_secret = hkdf_extract(hash, &derived, shared);
    let c_hs = derive_secret(hash, &handshake_secret, "c hs traffic", transcript_hash)?;
    let s_hs = derive_secret(hash, &handshake_secret, "s hs traffic", transcript_hash)?;
    let derived2 = derive_secret(hash, &handshake_secret, "derived", &empty_hash)?;
    let master = hkdf_extract(hash, &derived2, &zeros);
    Ok(HandshakeSecrets { c_hs, s_hs, master })
}

/// Application traffic secrets (reality/tls13.rs:555-565).
fn application_secrets(
    hash: HashKind,
    master: &[u8],
    transcript_hash: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    Ok((
        derive_secret(hash, master, "c ap traffic", transcript_hash)?,
        derive_secret(hash, master, "s ap traffic", transcript_hash)?,
    ))
}

/// Finished key + verify_data (reality/tls13.rs:489-505).
fn finished_key(hash: HashKind, secret: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0u8; hash.digest_len()];
    hash.hkdf_expand_label(secret, "finished", &[], &mut out)?;
    Ok(out)
}

fn finished_verify_data(
    hash: HashKind,
    finished_key: &[u8],
    transcript_hash: &[u8],
) -> Result<Vec<u8>> {
    Ok(hash.hmac(finished_key, transcript_hash))
}

// ---------------------------------------------------------------------------
// QUIC packet + header protection keys (RFC 9001 §5) over ring, mirroring
// rustls's ring provider (rustls-0.23.37 src/crypto/ring/quic.rs) and
// satisfying quinn's crypto traits (quinn_proto src/crypto.rs:148-175).
// ---------------------------------------------------------------------------

/// One direction of packet protection: AEAD key + static IV, the nonce
/// formed by XOR with the packet number (RFC 9001 §5.4.1 — the same
/// construction as TLS records, reality/tls13.rs:592-600; rustls
/// crypto/ring/quic.rs:97-160 is the mirrored implementation).
struct QuicPacketKey {
    key: aead::LessSafeKey,
    iv: [u8; 12],
    confidentiality_limit: u64,
    integrity_limit: u64,
}

impl QuicPacketKey {
    fn new(suite: CipherSuite, key: &[u8], iv: [u8; 12]) -> Result<Self> {
        let unbound = aead::UnboundKey::new(suite.ring_aead(), key)
            .map_err(|_| Error::crypto("quic-tls13: packet key rejected"))?;
        let (confidentiality_limit, integrity_limit) = suite.quic_limits();
        Ok(QuicPacketKey {
            key: aead::LessSafeKey::new(unbound),
            iv,
            confidentiality_limit,
            integrity_limit,
        })
    }

    fn nonce(&self, packet: u64) -> [u8; 12] {
        let mut nonce = self.iv;
        let pn = packet.to_be_bytes();
        for (i, b) in pn.iter().enumerate() {
            nonce[4 + i] ^= b;
        }
        nonce
    }
}

impl PacketKey for QuicPacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        // The tail of `buf` is tag storage (quinn's Box impl of this
        // trait, quinn_proto src/crypto/rustls.rs:615-621).
        let (header, payload_tag) = buf.split_at_mut(header_len);
        let (payload, tag_storage) = payload_tag.split_at_mut(payload_tag.len() - self.tag_len());
        let tag = self
            .key
            .seal_in_place_separate_tag(
                aead::Nonce::assume_unique_for_key(self.nonce(packet)),
                aead::Aad::from(&*header),
                payload,
            )
            .expect("payload within AEAD limit");
        tag_storage.copy_from_slice(tag.as_ref());
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> std::result::Result<(), CryptoError> {
        let plain_len = self
            .key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(self.nonce(packet)),
                aead::Aad::from(header),
                payload.as_mut(),
            )
            .map_err(|_| CryptoError)?
            .len();
        payload.truncate(plain_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        16
    }

    fn confidentiality_limit(&self) -> u64 {
        self.confidentiality_limit
    }

    fn integrity_limit(&self) -> u64 {
        self.integrity_limit
    }
}

/// QUIC header protection (RFC 9001 §5.4), the mask application of rustls
/// crypto/ring/quic.rs:19-77 over ring's `aead::quic::HeaderProtectionKey`
/// (ring-0.17.14 src/aead/quic.rs:25-75).
struct QuicHeaderKey {
    key: aead::quic::HeaderProtectionKey,
}

impl QuicHeaderKey {
    fn new(suite: CipherSuite, key: &[u8]) -> Result<Self> {
        let key = aead::quic::HeaderProtectionKey::new(suite.ring_hp(), key)
            .map_err(|_| Error::crypto("quic-tls13: header key rejected"))?;
        Ok(QuicHeaderKey { key })
    }

    /// rustls `xor_in_place` (crypto/ring/quic.rs:24-70), including its
    /// direction subtlety: the packet-number length lives in the
    /// masked length bits, so the SENDER reads them from the plain
    /// first byte and the RECEIVER from the unmasked one (rustls's
    /// `masked` flag).
    fn xor_in_place(
        &self,
        sample: &[u8],
        first: &mut u8,
        packet_number: &mut [u8],
        decrypting: bool,
    ) -> std::result::Result<(), CryptoError> {
        let mask = self.key.new_mask(sample).map_err(|_| CryptoError)?;
        let (first_mask, pn_mask) = mask.split_first().ok_or(CryptoError)?;
        if packet_number.len() > pn_mask.len() {
            return Err(CryptoError);
        }
        const LONG_HEADER_FORM: u8 = 0x80;
        let bits = if *first & LONG_HEADER_FORM == LONG_HEADER_FORM {
            0x0f
        } else {
            0x1f
        };
        let first_plain = if decrypting {
            *first ^ (first_mask & bits)
        } else {
            *first
        };
        let pn_len = (first_plain & 0x03) as usize + 1;
        *first ^= first_mask & bits;
        for (dst, m) in packet_number.iter_mut().zip(pn_mask).take(pn_len) {
            *dst ^= m;
        }
        Ok(())
    }
}

impl HeaderKey for QuicHeaderKey {
    fn decrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        self.xor_in_place(
            &sample[..self.sample_size()],
            &mut first[0],
            &mut rest[pn_offset - 1..pn_end],
            true,
        )
        .expect("sample sized by the caller");
    }

    fn encrypt(&self, pn_offset: usize, packet: &mut [u8]) {
        // The mask application is symmetric; only the packet-number
        // length read differs by direction (see xor_in_place).
        let (header, sample) = packet.split_at_mut(pn_offset + 4);
        let (first, rest) = header.split_at_mut(1);
        let pn_end = Ord::min(pn_offset + 3, rest.len());
        self.xor_in_place(
            &sample[..self.sample_size()],
            &mut first[0],
            &mut rest[pn_offset - 1..pn_end],
            false,
        )
        .expect("sample sized by the caller");
    }

    fn sample_size(&self) -> usize {
        self.key.algorithm().sample_len()
    }
}

/// Per-secret QUIC key material: `quic key` (AEAD key), `quic iv` (static
/// IV) and `quic hp` (header protection) via HKDF-Expand-Label
/// (RFC 9001 §5.1; labels per rustls-0.23.37 src/quic.rs:1012-1033).
fn secret_keys(suite: CipherSuite, secret: &[u8]) -> Result<(QuicPacketKey, QuicHeaderKey)> {
    let hash = suite.quic_hash();
    let mut key = vec![0u8; suite.key_len()];
    hash.hkdf_expand_label(secret, "quic key", &[], &mut key)?;
    let mut iv = [0u8; 12];
    hash.hkdf_expand_label(secret, "quic iv", &[], &mut iv)?;
    let mut hp = vec![0u8; suite.key_len()];
    hash.hkdf_expand_label(secret, "quic hp", &[], &mut hp)?;
    Ok((
        QuicPacketKey::new(suite, &key, iv)?,
        QuicHeaderKey::new(suite, &hp)?,
    ))
}

/// A `crypto::Keys` pair for one packet space from the two traffic
/// secrets (`local` encrypts, `remote` decrypts — quinn_proto
/// src/crypto.rs:96-110).
fn keys_from_secrets(
    suite: CipherSuite,
    client_secret: &[u8],
    server_secret: &[u8],
    side: QuinnSide,
) -> Result<Keys> {
    let (local_secret, remote_secret) = match side {
        QuinnSide::Client => (client_secret, server_secret),
        QuinnSide::Server => (server_secret, client_secret),
    };
    let (local_packet, local_header) = secret_keys(suite, local_secret)?;
    let (remote_packet, remote_header) = secret_keys(suite, remote_secret)?;
    Ok(Keys {
        header: KeyPair {
            local: Box::new(local_header),
            remote: Box::new(remote_header),
        },
        packet: KeyPair {
            local: Box::new(local_packet),
            remote: Box::new(remote_packet),
        },
    })
}

/// The next traffic secret under RFC 9001 §6 key update ("quic ku" — the
/// label of rustls-0.23.37 src/quic.rs:1035-1040, applied to each side).
fn quic_key_update(hash: HashKind, secret: &[u8]) -> Result<Vec<u8>> {
    let mut out = vec![0u8; hash.digest_len()];
    hash.hkdf_expand_label(secret, "quic ku", &[], &mut out)?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Handshake message codecs (mirrors of reality/tls13.rs:694-1033).
// ---------------------------------------------------------------------------

fn u16_at(b: &[u8], i: usize) -> Result<u16> {
    let s = b
        .get(i..i + 2)
        .ok_or_else(|| Error::protocol("quic-tls13: truncated u16"))?;
    Ok(u16::from_be_bytes([s[0], s[1]]))
}

fn u24_at(b: &[u8], i: usize) -> Result<usize> {
    let s = b
        .get(i..i + 3)
        .ok_or_else(|| Error::protocol("quic-tls13: truncated u24"))?;
    Ok(((s[0] as usize) << 16) | ((s[1] as usize) << 8) | s[2] as usize)
}

/// Walk a u16-length-prefixed extension block (reality/tls13.rs:710-728).
fn extensions(b: &[u8]) -> Result<Vec<(u16, &[u8])>> {
    let total = u16_at(b, 0)? as usize;
    let body = b
        .get(2..2 + total)
        .ok_or_else(|| Error::protocol("quic-tls13: truncated extensions"))?;
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < body.len() {
        let typ = u16_at(body, off)?;
        let len = u16_at(body, off + 2)? as usize;
        let data = body
            .get(off + 4..off + 4 + len)
            .ok_or_else(|| Error::protocol("quic-tls13: truncated extension body"))?;
        out.push((typ, data));
        off += 4 + len;
    }
    Ok(out)
}

/// One extension entry serialized (reality test_server's `ext`,
/// tls13.rs:3251-3257).
fn ext_entry(typ: u16, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.extend_from_slice(&typ.to_be_bytes());
    out.extend_from_slice(&(body.len() as u16).to_be_bytes());
    out.extend_from_slice(body);
    out
}

/// Append `type ‖ u24 len ‖ body` (reality/tls13.rs:1010-1019).
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

/// Pull one complete handshake message out of `buf`
/// (reality/tls13.rs:1023-1033).
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

/// The byte offset (into the whole message) of the extension block —
/// including its u16 total length — via the canonical field walk
/// (reality/tls13.rs:1673-1689).
fn hello_ext_block_offset(msg: &[u8]) -> Result<usize> {
    let b = msg
        .get(4..)
        .ok_or_else(|| Error::protocol("quic-tls13: short hello"))?;
    let sid_len = *b
        .get(34)
        .ok_or_else(|| Error::protocol("quic-tls13: short hello"))? as usize;
    let mut off = 35 + sid_len;
    let cs_len = u16_at(b, off)? as usize;
    off += 2 + cs_len;
    let comp_len = *b
        .get(off)
        .ok_or_else(|| Error::protocol("quic-tls13: short hello"))? as usize;
    off += 1 + comp_len;
    Ok(off + 4)
}

/// Insert (or replace) one extension in a serialized hello message,
/// rewriting the block total and the u24 message length. Extension order
/// is not semantic (RFC 8446 §4.1.2); a new extension goes last, after
/// the profile's pinned GREASE/padding entries.
fn insert_extension(msg: &[u8], typ: u16, body: &[u8]) -> Result<Vec<u8>> {
    let block_off = hello_ext_block_offset(msg)?;
    let block = msg
        .get(block_off..)
        .ok_or_else(|| Error::protocol("quic-tls13: short extension block"))?;
    let old_total = u16_at(block, 0)? as usize;
    let mut entries = Vec::with_capacity(old_total + 4 + body.len());
    let mut replaced = false;
    for (t, b) in extensions(block)? {
        if t == typ {
            entries.extend_from_slice(&ext_entry(typ, body));
            replaced = true;
        } else {
            entries.extend_from_slice(&ext_entry(t, b));
        }
    }
    if !replaced {
        entries.extend_from_slice(&ext_entry(typ, body));
    }
    if entries.len() > u16::MAX as usize {
        return Err(Error::protocol("quic-tls13: extension block overflow"));
    }
    let new_body_len = (block_off - 4) + 2 + entries.len();
    if new_body_len > 0x00ff_ffff {
        return Err(Error::protocol("quic-tls13: hello overflow"));
    }
    let mut out = Vec::with_capacity(4 + new_body_len);
    out.push(msg[0]);
    out.push((new_body_len >> 16) as u8);
    out.push((new_body_len >> 8) as u8);
    out.push(new_body_len as u8);
    out.extend_from_slice(&msg[4..block_off]);
    out.extend_from_slice(&(entries.len() as u16).to_be_bytes());
    out.extend_from_slice(&entries);
    Ok(out)
}

/// A ServerHello as the client needs it: the ECH-aware superset of
/// reality/tls13.rs:735-827 and :1550-1669 (the HRR random is surfaced
/// instead of rejected; the HRR's cookie/ECH extensions are kept).
struct ParsedServerHello {
    is_hrr: bool,
    cipher_suite: u16,
    session_id: Vec<u8>,
    share: Vec<u8>,
    /// The 8-byte ECH extension value of an HRR (absent otherwise).
    ech_ext: Option<Vec<u8>>,
    cookie: Option<Vec<u8>>,
}

fn parse_server_hello(msg: &[u8]) -> Result<ParsedServerHello> {
    let b = msg
        .get(4..)
        .ok_or_else(|| Error::protocol("quic-tls13: short ServerHello"))?;
    let random = b
        .get(2..34)
        .ok_or_else(|| Error::protocol("quic-tls13: short ServerHello random"))?;
    let is_hrr = random == HRR_RANDOM.as_slice();
    let sid_len = *b
        .get(34)
        .ok_or_else(|| Error::protocol("quic-tls13: short ServerHello"))? as usize;
    let session_id = b
        .get(35..35 + sid_len)
        .ok_or_else(|| Error::protocol("quic-tls13: short ServerHello session id"))?
        .to_vec();
    let mut off = 35 + sid_len;
    let cipher_suite = u16_at(b, off)?;
    off += 2;
    match b.get(off) {
        Some(0x00) => {}
        Some(other) => {
            return Err(Error::protocol(format!(
                "quic-tls13: server selected compression {other:#x}"
            )));
        }
        None => return Err(Error::protocol("quic-tls13: short ServerHello")),
    }
    off += 1;
    let mut share = None;
    let mut selected_version = None;
    let mut ech_ext = None;
    let mut cookie = None;
    for (typ, body) in extensions(b.get(off..).unwrap_or_default())? {
        match typ {
            EXT_SUPPORTED_VERSIONS => selected_version = Some(u16_at(body, 0)?),
            EXT_KEY_SHARE => {
                let group = u16_at(body, 0)?;
                let len = u16_at(body, 2)? as usize;
                if group != GROUP_X25519 {
                    return Err(Error::protocol(format!(
                        "quic-tls13: server selected key exchange group {group:#06x}; only X25519 is implemented"
                    )));
                }
                share = Some(
                    body.get(4..4 + len)
                        .ok_or_else(|| Error::protocol("quic-tls13: short key share"))?
                        .to_vec(),
                );
            }
            ech::EXTENSION_ENCRYPTED_CLIENT_HELLO => ech_ext = Some(body.to_vec()),
            EXT_COOKIE => cookie = Some(body.to_vec()),
            EXT_PRE_SHARED_KEY => {
                return Err(Error::protocol(
                    "quic-tls13: server selected a PSK we never offered",
                ));
            }
            _ => {}
        }
    }
    match selected_version {
        Some(v) if v == VERSION_TLS13 => {}
        Some(v) => {
            return Err(Error::protocol(format!(
                "quic-tls13: server negotiated version {v:#06x}, this client is TLS 1.3 only"
            )));
        }
        None => {
            return Err(Error::protocol(
                "quic-tls13: ServerHello has no supported_versions extension",
            ));
        }
    }
    if is_hrr {
        return Ok(ParsedServerHello {
            is_hrr: true,
            cipher_suite,
            session_id,
            share: Vec::new(),
            ech_ext,
            cookie,
        });
    }
    let share =
        share.ok_or_else(|| Error::protocol("quic-tls13: ServerHello has no key_share"))?;
    if share.len() != 32 {
        return Err(Error::protocol(
            "quic-tls13: X25519 key share is not 32 bytes",
        ));
    }
    Ok(ParsedServerHello {
        is_hrr: false,
        cipher_suite,
        session_id,
        share,
        ech_ext: None,
        cookie,
    })
}

/// What EncryptedExtensions told us: the negotiated ALPN, the QUIC
/// transport parameters (RFC 9001 §8), and — on ECH rejection — the
/// retry ECHConfigList (metacubex/tls handshake_client_tls13.go:577-585).
struct ParsedEncryptedExtensions {
    alpn: Option<Vec<u8>>,
    transport_parameters: Option<Vec<u8>>,
    ech_retry_configs: Option<Vec<u8>>,
}

fn parse_encrypted_extensions(msg: &[u8]) -> Result<ParsedEncryptedExtensions> {
    let body = msg
        .get(4..)
        .ok_or_else(|| Error::protocol("quic-tls13: short EncryptedExtensions"))?;
    let mut out = ParsedEncryptedExtensions {
        alpn: None,
        transport_parameters: None,
        ech_retry_configs: None,
    };
    for (typ, data) in extensions(body)? {
        match typ {
            EXT_ALPN => {
                // reality/tls13.rs:837-849: one u8-length-prefixed entry.
                let total = u16_at(data, 0)? as usize;
                let list = data
                    .get(2..2 + total)
                    .ok_or_else(|| Error::protocol("quic-tls13: truncated ALPN list"))?;
                if let Some(&len) = list.first() {
                    out.alpn = Some(
                        list.get(1..1 + len as usize)
                            .ok_or_else(|| {
                                Error::protocol("quic-tls13: truncated ALPN protocol")
                            })?
                            .to_vec(),
                    );
                }
            }
            EXT_TRANSPORT_PARAMETERS => out.transport_parameters = Some(data.to_vec()),
            ech::EXTENSION_ENCRYPTED_CLIENT_HELLO => {
                out.ech_retry_configs = Some(data.to_vec())
            }
            _ => {}
        }
    }
    Ok(out)
}

/// Parse a Certificate into the raw DER chain (reality/tls13.rs:854-891).
fn parse_certificate(msg: &[u8]) -> Result<Vec<Vec<u8>>> {
    let b = msg
        .get(4..)
        .ok_or_else(|| Error::protocol("quic-tls13: short Certificate"))?;
    let ctx_len = *b
        .first()
        .ok_or_else(|| Error::protocol("quic-tls13: short Certificate"))? as usize;
    let mut off = 1 + ctx_len;
    if ctx_len != 0 {
        return Err(Error::protocol(
            "quic-tls13: Certificate carries a request context we never sent",
        ));
    }
    let list_len = u24_at(b, off)?;
    off += 3;
    let end = off + list_len;
    if end > b.len() {
        return Err(Error::protocol("quic-tls13: truncated certificate list"));
    }
    let mut chain = Vec::new();
    while off < end {
        let len = u24_at(b, off)?;
        off += 3;
        let der = b
            .get(off..off + len)
            .ok_or_else(|| Error::protocol("quic-tls13: truncated certificate"))?;
        chain.push(der.to_vec());
        off += len;
        let ext_len = u16_at(b, off)? as usize;
        off += 2 + ext_len;
    }
    if chain.is_empty() {
        return Err(Error::protocol(
            "quic-tls13: server sent an empty certificate chain",
        ));
    }
    Ok(chain)
}

/// Verify the server's CertificateVerify against the leaf certificate —
/// a mirror of reality/tls13.rs:894-955 (same schemes, same DER key
/// shapes via `reality::tls13::der`).
fn verify_certificate_verify(body: &[u8], leaf: &[u8], transcript_hash: &[u8]) -> Result<()> {
    use ring::signature;
    let scheme = u16_at(body, 0)?;
    let sig_len = u16_at(body, 2)? as usize;
    let sig = body
        .get(4..4 + sig_len)
        .ok_or_else(|| Error::protocol("quic-tls13: truncated CertificateVerify"))?;
    let mut message = Vec::with_capacity(64 + SERVER_SIGNATURE_CONTEXT.len() + 1 + 32);
    message.extend_from_slice(&[0x20u8; 64]);
    message.extend_from_slice(SERVER_SIGNATURE_CONTEXT);
    message.push(0x00);
    message.extend_from_slice(transcript_hash);

    let key = engine_tls13::der::public_key(leaf)?;
    let failure = || {
        Error::protocol(format!(
            "quic-tls13: CertificateVerify signature check failed (scheme {scheme:#06x})"
        ))
    };
    let rsa = |n: &[u8], e: &[u8], alg: &'static signature::RsaParameters| {
        signature::RsaPublicKeyComponents { n, e }.verify(alg, &message, sig)
    };
    match (&key, scheme) {
        (engine_tls13::der::PublicKey::Ed25519(k), 0x0807) => {
            signature::UnparsedPublicKey::new(&signature::ED25519, k)
                .verify(&message, sig)
                .map_err(|_| failure())?;
        }
        (engine_tls13::der::PublicKey::EcdsaP256(k), 0x0403) => {
            signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_ASN1, k)
                .verify(&message, sig)
                .map_err(|_| failure())?;
        }
        (engine_tls13::der::PublicKey::EcdsaP384(k), 0x0503) => {
            signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_ASN1, k)
                .verify(&message, sig)
                .map_err(|_| failure())?;
        }
        (engine_tls13::der::PublicKey::Rsa { n, e }, 0x0804) => {
            rsa(n, e, &signature::RSA_PSS_2048_8192_SHA256).map_err(|_| failure())?;
        }
        (engine_tls13::der::PublicKey::Rsa { n, e }, 0x0805) => {
            rsa(n, e, &signature::RSA_PSS_2048_8192_SHA384).map_err(|_| failure())?;
        }
        (engine_tls13::der::PublicKey::Rsa { n, e }, 0x0806) => {
            rsa(n, e, &signature::RSA_PSS_2048_8192_SHA512).map_err(|_| failure())?;
        }
        _ => {
            return Err(Error::protocol(format!(
                "quic-tls13: server CertificateVerify scheme {scheme:#06x} does not match its key"
            )));
        }
    }
    Ok(())
}

/// Check the server's Finished (reality/tls13.rs:966-982).
fn verify_finished(
    hash: HashKind,
    finished_key: &[u8],
    transcript_hash: &[u8],
    body: &[u8],
) -> Result<()> {
    if body.len() != hash.digest_len() {
        return Err(Error::protocol("quic-tls13: Finished has the wrong length"));
    }
    if !hash.hmac_verify(finished_key, transcript_hash, body) {
        return Err(Error::protocol(
            "quic-tls13: server Finished does not verify (wrong key or MITM)",
        ));
    }
    Ok(())
}

/// Webpki chain validation — the mirror of reality/tls13.rs:1316-1340
/// (rustls's own `WebPkiServerVerifier` with the ring provider; only the
/// messages are ours).
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
            .map_err(|e| {
                Error::config(format!("quic-tls13: cannot build the webpki verifier: {e}"))
            })?;
    let name = ServerName::try_from(server_name.to_owned())
        .map_err(|_| Error::config(format!("quic-tls13: invalid server name {server_name:?}")))?;
    let end_entity = CertificateDer::from(chain[0].clone());
    let intermediates: Vec<CertificateDer<'static>> = chain[1..]
        .iter()
        .map(|c| CertificateDer::from(c.clone()))
        .collect();
    verifier
        .verify_server_cert(&end_entity, &intermediates, &name, &[], UnixTime::now())
        .map_err(|e| {
            Error::protocol(format!("quic-tls13: certificate verification failed: {e}"))
        })?;
    Ok(())
}

/// System + bundled webpki trust anchors — the engine's shared loader,
/// mirrored from transport.rs:109-126 (private there).
fn root_store() -> Result<Arc<rustls::RootCertStore>> {
    let mut roots = rustls::RootCertStore::empty();
    let mut loaded = 0usize;
    let certs = rustls_native_certs::load_native_certs()
        .map_err(|e| Error::config(format!("native cert store: {e}")))?;
    for cert in certs {
        roots
            .add(cert)
            .map_err(|e| Error::config(format!("bad native cert: {e}")))?;
        loaded += 1;
    }
    if loaded == 0 {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    Ok(Arc::new(roots))
}

// ---------------------------------------------------------------------------
// First flights: plain profile hello, JLS-stamped, ECH outer/inner.
// ---------------------------------------------------------------------------

/// Which cover the QUIC TLS handshake rides.
#[derive(Debug, Clone)]
pub enum QuicTlsCover {
    /// JLS credentials in the hello randoms (`proto::jls`).
    Jls(jls::JlsUser),
    /// ECH (RFC 9460) over the picked ECHConfig (`proto::ech` core).
    Ech(ech::EchConfigSelection),
}

/// Everything the session needs from one constructed first flight.
pub(crate) struct ClientFlight {
    /// The ClientHello handshake message (CRYPTO-stream form).
    pub hello: Vec<u8>,
    /// X25519 private half of the offered key share.
    pub secret: [u8; 32],
    /// The ServerHello authentication/confirmation the session applies.
    pub check: ServerHelloCheck,
}

/// How the session treats the ServerHello beyond the plain TLS checks.
pub(crate) enum ServerHelloCheck {
    /// Nothing beyond the standard handshake.
    None,
    /// JLS: the random must open as the peer's fakeRandom
    /// (`jls::check_fake_random`, `ERR_AUTH_FAILED` on failure).
    Jls(jls::JlsUser),
    /// ECH: accept-confirmation in random[24..32], or a rejected
    /// handshake completed against the OUTER hello
    /// (metacubex/tls handshake_client_tls13.go:86-116).
    Ech(Box<EchClientContext>),
}

/// The ECH client state that survives into the session (the hello-set
/// half of reality/tls13.rs:1786-1811, rebuilt here because that type is
/// private).
pub(crate) struct EchClientContext {
    /// Transcript-form inner hello (32-byte session id) — the transcript
    /// the accepted handshake runs over.
    pub inner_msg: Vec<u8>,
    /// Inner random — the accept-confirmation PRK input.
    pub inner_random: [u8; 32],
    /// The outer hello as sent (the rejected handshake's transcript).
    pub outer_msg: Vec<u8>,
    /// The outer random (re-serialization input for HRR flights).
    pub outer_random: [u8; 32],
    /// The X25519 private half shared by inner and outer key share.
    pub x25519_secret: [u8; 32],
    /// The session id both hellos carry (the server echoes it).
    pub session_id: [u8; 32],
    /// Canonical extension list of the outer hello (cookie slot for HRR).
    pub outer_exts: Vec<(u16, Vec<u8>)>,
    /// Cipher suites ‖ compression bytes shared by both hellos.
    pub suites_comp: Vec<u8>,
    /// The inner extension list (the HRR rebuild adds the cookie).
    pub inner_exts: Vec<(u16, Vec<u8>)>,
    /// The real (inner) SNI — the ECH padding input.
    pub inner_sni_bytes: Vec<u8>,
    pub max_name_length: usize,
    pub config_id: u8,
    pub kdf_id: u16,
    pub aead_id: u16,
    /// The HPKE sender (stateful counter; the HRR re-seal continues it).
    pub hpke: ech::HpkeSender,
    /// The encapsulated key of the first flight (the HRR re-seal omits
    /// it, `useKey == false`).
    #[allow(dead_code)]
    pub enc: [u8; 32],
}

/// One `(type, body)` extension list serialized into a hello extension
/// block body (reality/tls13.rs:1719-1727).
fn ech_ext_block(exts: &[(u16, Vec<u8>)]) -> Vec<u8> {
    let mut out = Vec::new();
    for (typ, body) in exts {
        out.extend_from_slice(&typ.to_be_bytes());
        out.extend_from_slice(&(body.len() as u16).to_be_bytes());
        out.extend_from_slice(body);
    }
    out
}

/// Serialize an ECH hello (reality/tls13.rs:1734-1762): `legacy_version
/// 0x0303 ‖ random ‖ session_id (empty when None) ‖ cipher_suites ‖
/// compression ‖ extensions` behind the handshake header.
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
    hs_message(HS_CLIENT_HELLO, &body)
}

/// The `server_name` extension body (reality/tls13.rs:1764-1774).
fn ech_sni_body(name: &[u8]) -> Vec<u8> {
    let mut entry = Vec::with_capacity(3 + name.len());
    entry.push(0);
    entry.extend_from_slice(&(name.len() as u16).to_be_bytes());
    entry.extend_from_slice(name);
    let mut body = Vec::with_capacity(2 + entry.len());
    body.extend_from_slice(&(entry.len() as u16).to_be_bytes());
    body.extend_from_slice(&entry);
    body
}

/// Insert the `cookie` extension at its canonical slot (between
/// `supported_versions` and `key_share`, handshake_messages.go:256-265;
/// reality/tls13.rs:1776-1784).
fn ech_insert_cookie(exts: &mut Vec<(u16, Vec<u8>)>, cookie: &[u8]) {
    let pos = exts
        .iter()
        .position(|(t, _)| *t == EXT_KEY_SHARE)
        .unwrap_or(exts.len());
    exts.insert(pos, (EXT_COOKIE, cookie.to_vec()));
}

/// Insert the ECH extension at its canonical slot after `scts`
/// (handshake_messages.go:163-170; reality/tls13.rs:2039-2061).
fn ech_insert_ech(exts: &mut Vec<(u16, Vec<u8>)>, body: Vec<u8>) {
    let pos = exts
        .iter()
        .position(|(t, _)| *t == EXT_SCTS)
        .map(|i| i + 1)
        .unwrap_or(exts.len());
    exts.insert(pos, (ech::EXTENSION_ENCRYPTED_CLIENT_HELLO, body));
}

/// Build the plain profile ClientHello with the QUIC transport parameters
/// embedded (the profile machinery of `reality::profiles`, plus the
/// `quic_transport_parameters` extension RFC 9001 §8 requires).
fn build_plain_flight(
    profile: UtslProfile,
    sni: &str,
    alpn: &[String],
    transport_params: &[u8],
) -> Result<ClientFlight> {
    let (secret, public) = engine_tls13::x25519_keygen();
    let mut random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let mut session_id = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut session_id);
    let hello = profiles::build_client_hello_alpn(
        profile,
        sni,
        &random,
        &session_id,
        &public,
        Some(alpn),
    );
    let hello = insert_extension(&hello, EXT_TRANSPORT_PARAMETERS, transport_params)?;
    Ok(ClientFlight {
        hello,
        secret,
        check: ServerHelloCheck::None,
    })
}

/// Build the JLS-stamped flight — the QUIC shape of `build_profile_hello`
/// (proto/jls.rs:913-963, itself the port of utls.go:70-101): pass one
/// builds the hello (with the transport parameters in it, exactly as
/// jls-quic-go's jls-tls fork serializes them inside `tls.QUICClient`),
/// derives authData + fakeRandom from the serialized bytes, pass two
/// re-stamps only the random (`profiles::build_client_hello_opts`'s
/// `structure_seed` pins GREASE and the Chrome shuffle to the first
/// draw).
fn build_jls_flight(
    profile: UtslProfile,
    sni: &str,
    alpn: &[String],
    transport_params: &[u8],
    user: &jls::JlsUser,
) -> Result<ClientFlight> {
    const RANDOM_OFFSET: usize = 6; // header(4) + legacy_version(2)
    const RANDOM_LEN: usize = 32;
    let (secret, public) = engine_tls13::x25519_keygen();
    let mut random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    let mut session_id = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut session_id);
    let alps = alpn.iter().any(|a| a == "h2");
    let hello1 = profiles::build_client_hello_opts(
        profile,
        sni,
        &random,
        &session_id,
        &public,
        Some(alpn),
        None,
        alps,
    );
    let hello1 = insert_extension(&hello1, EXT_TRANSPORT_PARAMETERS, transport_params)?;
    // `jlsClientHelloAuthData` over the serialized hello + the seed =
    // the first half of the drawn random (utls.go:84-94).
    let auth_data = jls::hello_auth_data(&hello1, HS_CLIENT_HELLO)?;
    let fake_random = jls::build_fake_random(user, &random[..16], &auth_data)?;
    let hello2_base = profiles::build_client_hello_opts(
        profile,
        sni,
        &fake_random,
        &session_id,
        &public,
        Some(alpn),
        Some(&random),
        alps,
    );
    let hello2 = insert_extension(&hello2_base, EXT_TRANSPORT_PARAMETERS, transport_params)?;
    // The stamp contract (proto/jls.rs:949-961): the rebuild differs in
    // exactly the 32 random bytes.
    if hello2.len() != hello1.len()
        || hello2[..RANDOM_OFFSET] != hello1[..RANDOM_OFFSET]
        || hello2[RANDOM_OFFSET + RANDOM_LEN..] != hello1[RANDOM_OFFSET + RANDOM_LEN..]
    {
        return Err(Error::crypto(
            "quic-tls13: could not stamp the JLS ClientHello random",
        ));
    }
    Ok(ClientFlight {
        hello: hello2,
        secret,
        check: ServerHelloCheck::Jls(user.clone()),
    })
}

/// Build the ECH outer/inner pair with the transport parameters in the
/// INNER hello — the QUIC port of `EchHelloSet::build`
/// (reality/tls13.rs:1819-2010). The construction rules (inner drops the
/// four legacy-compat extensions, carries the `[0x01]` marker and
/// TLS-1.3-only supported_versions; outer carries the public SNI, a
/// fresh random and the HPKE-sealed encoded inner) are identical; the
/// deltas are the QUIC transport parameters on the inner and assembly
/// through the public `proto::ech` helpers.
fn build_ech_flight(
    profile: UtslProfile,
    server_name: &str,
    alpn: &[String],
    transport_params: &[u8],
    selection: &ech::EchConfigSelection,
) -> Result<ClientFlight> {
    let config = &selection.config;
    let public: [u8; 32] = config
        .public_key
        .as_slice()
        .try_into()
        .map_err(|_| Error::config("quic-tls13: ECH public key is not 32 bytes"))?;
    let mut inner_random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut inner_random);
    let mut outer_random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut outer_random);
    let mut session_id = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut session_id);
    let (x25519_secret, public_share) = engine_tls13::x25519_keygen();
    let mut hpke_secret = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut hpke_secret);

    // Base template under the REAL server name.
    let base = profiles::build_client_hello_alpn(
        profile,
        server_name,
        &inner_random,
        &session_id,
        &public_share,
        Some(alpn),
    );
    let body = &base[4..];
    // vers(2) random(32) sid_len(1)=32 sid(32) suites(u16-pref)
    // comp(u8-pref) — reality/tls13.rs:1852-1858.
    let suites_len = u16::from_be_bytes([body[67], body[68]]) as usize;
    let suites_comp = body[67..67 + 2 + suites_len + 2].to_vec();
    let base_exts = extensions(&body[67 + 2 + suites_len + 2..])?;
    let find = |want: u16| {
        base_exts
            .iter()
            .find(|(t, _)| *t == want)
            .map(|(_, b)| b.to_vec())
    };

    // Inner supported_versions: TLS 1.3 (+GREASE) only
    // (reality/tls13.rs:1866-1889).
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
    let mut versions_body = Vec::with_capacity(1 + versions.len());
    versions_body.push(versions.len() as u8);
    versions_body.extend_from_slice(&versions);

    let default_groups = || {
        let mut b = Vec::new();
        b.extend_from_slice(&2u16.to_be_bytes());
        b.extend_from_slice(&GROUP_X25519.to_be_bytes());
        b
    };
    let default_sigalgs = || vec![0x00u8, 0x04, 0x04, 0x03, 0x08, 0x04];
    let default_status = || vec![0x01u8, 0x00, 0x00, 0x00, 0x00];

    // Inner: real SNI, scts, the [0x01] marker, the negotiation set —
    // and the QUIC transport parameters (RFC 9460 §8.2: the real
    // handshake is the inner one), after `psk_key_exchange_modes`.
    let mut inner_exts: Vec<(u16, Vec<u8>)> = vec![
        (EXT_SERVER_NAME, ech_sni_body(server_name.as_bytes())),
        (EXT_SCTS, Vec::new()),
        (ech::EXTENSION_ENCRYPTED_CLIENT_HELLO, vec![1]), // ech.go:186
        (0x0005, find(0x0005).unwrap_or_else(default_status)),
        (0x000a, find(0x000a).unwrap_or_else(default_groups)),
        (0x000d, find(0x000d).unwrap_or_else(default_sigalgs)),
        (EXT_ALPN, find(EXT_ALPN).unwrap_or_default()),
        (EXT_SUPPORTED_VERSIONS, versions_body.clone()),
        (EXT_KEY_SHARE, find(EXT_KEY_SHARE).unwrap_or_default()),
        (0x002d, find(0x002d).unwrap_or_else(|| vec![0x01, 0x01])),
    ];
    let psk_pos = inner_exts
        .iter()
        .position(|(t, _)| *t == 0x002d)
        .map(|i| i + 1)
        .unwrap_or(inner_exts.len());
    inner_exts.insert(
        psk_pos,
        (EXT_TRANSPORT_PARAMETERS, transport_params.to_vec()),
    );

    // Outer: public SNI, the legacy-compat extensions the inner drops,
    // the same negotiation set. The QUIC transport parameters ride BOTH
    // hellos: the inner because the real handshake is the inner one
    // (RFC 9460 §8.2), the outer because a rejected handshake still has
    // to be a well-formed QUIC ClientHello for the server (Go's ECH-QUIC
    // outer carries them the same way; the parameters are not
    // ECH-sensitive).
    let mut outer_exts: Vec<(u16, Vec<u8>)> = vec![
        (EXT_SERVER_NAME, ech_sni_body(&config.public_name)),
        (0x000b, find(0x000b).unwrap_or_else(|| vec![0x01, 0x00])),
        (0x0023, Vec::new()),
        (0xff01, vec![0x00]),
        (0x0017, Vec::new()),
        (EXT_SCTS, Vec::new()),
        (0x0005, find(0x0005).unwrap_or_else(default_status)),
        (0x000a, find(0x000a).unwrap_or_else(default_groups)),
        (0x000d, find(0x000d).unwrap_or_else(default_sigalgs)),
        (EXT_ALPN, find(EXT_ALPN).unwrap_or_default()),
        (EXT_SUPPORTED_VERSIONS, versions_body),
        (EXT_KEY_SHARE, find(EXT_KEY_SHARE).unwrap_or_default()),
        (0x002d, find(0x002d).unwrap_or_else(|| vec![0x01, 0x01])),
    ];
    let outer_psk_pos = outer_exts
        .iter()
        .position(|(t, _)| *t == 0x002d)
        .map(|i| i + 1)
        .unwrap_or(outer_exts.len());
    outer_exts.insert(
        outer_psk_pos,
        (EXT_TRANSPORT_PARAMETERS, transport_params.to_vec()),
    );

    let serialize_outer_with = |ech_ext: &[u8]| -> Vec<u8> {
        let mut exts = outer_exts.clone();
        ech_insert_ech(&mut exts, ech_ext.to_vec());
        serialize_ech_hello(&outer_random, Some(&session_id), &suites_comp, &exts)
    };

    // Wire (encoded) inner: EMPTY session id + ECH padding
    // (`encodeInnerClientHello`, ech.go:197-216).
    let wire = serialize_ech_hello(&inner_random, None, &suites_comp, &inner_exts);
    let encoded_inner = ech::encode_inner_client_hello(
        &wire[4..],
        Some(server_name.as_bytes()),
        config.max_name_length as usize,
    );

    // HPKE sender: info = "tls ech\0" ‖ config.raw
    // (handshake_client.go:193-194).
    let (enc, mut hpke) =
        ech::HpkeSender::setup_with(&public, selection.aead, &ech::ech_hpke_info(config), &hpke_secret)?;

    // Seal against the placeholder outer serialization
    // (`computeAndUpdateOuterECHExtension`, ech.go:418-449).
    let ech_ext = ech::compute_outer_ech_ext(
        &mut hpke,
        config.config_id,
        ech::KDF_HKDF_SHA256,
        selection.aead.id(),
        &enc,
        &encoded_inner,
        true,
        |placeholder| serialize_outer_with(placeholder)[4..].to_vec(),
    )?;

    let ctx = EchClientContext {
        inner_msg: serialize_ech_hello(
            &inner_random,
            Some(&session_id),
            &suites_comp,
            &inner_exts,
        ),
        inner_random,
        outer_msg: serialize_outer_with(&ech_ext),
        outer_random,
        x25519_secret,
        session_id,
        outer_exts,
        suites_comp,
        inner_exts,
        inner_sni_bytes: server_name.as_bytes().to_vec(),
        max_name_length: config.max_name_length as usize,
        config_id: config.config_id,
        kdf_id: ech::KDF_HKDF_SHA256,
        aead_id: selection.aead.id(),
        hpke,
        enc,
    };

    Ok(ClientFlight {
        hello: ctx.outer_msg.clone(),
        secret: ctx.x25519_secret,
        check: ServerHelloCheck::Ech(Box::new(ctx)),
    })
}

// ---------------------------------------------------------------------------
// The client config (quinn crypto::ClientConfig).
// ---------------------------------------------------------------------------

/// A quinn client crypto configuration over the engine's TLS 1.3 stack.
///
/// The hello is built per connection with the QUIC transport parameters
/// quinn supplies to `start_session` (quinn_proto src/crypto.rs:113-121),
/// covering JLS credentials or ECH per [`QuicTlsCover`]. Certificate
/// verification follows `reality::tls13::ServerAuth` (webpki unless
/// `skip_verify`).
pub struct Tls13QuicClientConfig {
    profile: UtslProfile,
    sni: String,
    alpn: Vec<String>,
    cover: Option<QuicTlsCover>,
    auth: Arc<engine_tls13::ServerAuth>,
}

impl std::fmt::Debug for Tls13QuicClientConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Tls13QuicClientConfig")
            .field("profile", &self.profile.as_str())
            .field("sni", &self.sni)
            .field("alpn", &self.alpn)
            .field("cover", &self.cover.is_some())
            .finish()
    }
}

impl Tls13QuicClientConfig {
    /// A plain (uncovered) config: the engine's fingerprint hello with
    /// the transport parameters embedded. Used by tests and by outbounds
    /// that only want the engine TLS stack under QUIC.
    pub fn new_plain(
        profile: UtslProfile,
        sni: impl Into<String>,
        alpn: Vec<String>,
        skip_verify: bool,
    ) -> Result<Self> {
        let sni = sni.into();
        let auth = if skip_verify {
            Arc::new(engine_tls13::ServerAuth::AcceptAny)
        } else {
            Arc::new(engine_tls13::ServerAuth::WebPki {
                roots: root_store()?,
                server_name: sni.clone(),
            })
        };
        Ok(Tls13QuicClientConfig {
            profile,
            sni,
            alpn,
            cover: None,
            auth,
        })
    }

    /// A JLS-covered config for ShadowQUIC (the engine's equivalent of
    /// mihomo's `tls.Config.JLSConfig` + jls-quic-go,
    /// adapter/outbound/shadowquic.go:104-110). JLS itself authenticates
    /// the peer (utls.go:58-60), so the cover runs `AcceptAny` — exactly
    /// like the TCP fingerprint path.
    pub fn new_jls(
        profile: UtslProfile,
        sni: impl Into<String>,
        alpn: Vec<String>,
        user: jls::JlsUser,
    ) -> Self {
        Tls13QuicClientConfig {
            profile,
            sni: sni.into(),
            alpn,
            cover: Some(QuicTlsCover::Jls(user)),
            auth: Arc::new(engine_tls13::ServerAuth::AcceptAny),
        }
    }

    /// An ECH-covered config for the QUIC outbounds (hy2/tuic/trusttunnel
    /// `ech-opts`): the inner hello carries the real SNI/ALPN and the
    /// certificate is verified against `sni` once ECH is accepted
    /// (handshake_client_tls13.go:99-100).
    pub fn new_ech(
        profile: UtslProfile,
        sni: impl Into<String>,
        alpn: Vec<String>,
        selection: ech::EchConfigSelection,
        skip_verify: bool,
    ) -> Result<Self> {
        let sni = sni.into();
        let auth = if skip_verify {
            Arc::new(engine_tls13::ServerAuth::AcceptAny)
        } else {
            Arc::new(engine_tls13::ServerAuth::WebPki {
                roots: root_store()?,
                server_name: sni.clone(),
            })
        };
        Ok(Tls13QuicClientConfig {
            profile,
            sni,
            alpn,
            cover: Some(QuicTlsCover::Ech(selection)),
            auth,
        })
    }

    /// Build the first flight for one connection.
    fn build_flight(&self, transport_params: &[u8]) -> Result<ClientFlight> {
        match &self.cover {
            None => build_plain_flight(self.profile, &self.sni, &self.alpn, transport_params),
            Some(QuicTlsCover::Jls(user)) => {
                build_jls_flight(self.profile, &self.sni, &self.alpn, transport_params, user)
            }
            Some(QuicTlsCover::Ech(selection)) => {
                build_ech_flight(self.profile, &self.sni, &self.alpn, transport_params, selection)
            }
        }
    }
}

/// The rustls QUIC suite used for initial keys — the same lookup quinn's
/// rustls glue performs (`initial_suite_from_provider`, quinn_proto
/// src/crypto/rustls.rs:567-580): TLS_AES_128_GCM_SHA256's QUIC suite,
/// always present in the ring provider.
fn initial_rustls_suite() -> rustls::quic::Suite {
    let provider = rustls::crypto::ring::default_provider();
    provider
        .cipher_suites
        .iter()
        .find_map(|cs| match (cs.suite(), cs.tls13()) {
            (rustls::CipherSuite::TLS13_AES_128_GCM_SHA256, Some(tls13)) => tls13.quic_suite(),
            _ => None,
        })
        .expect("ring provider ships TLS13_AES_128_GCM_SHA256 with QUIC support")
}

/// Initial packet keys — byte-identical with quinn's own `initial_keys`
/// (quinn_proto src/crypto/rustls.rs:596-613 over rustls-0.23.37
/// src/quic.rs:889-970: RFC 9001 §5.2 "client in"/"server in" secrets
/// from the DCID salt).
fn initial_packet_keys(dst_cid: &quinn_proto::ConnectionId, side: QuinnSide) -> Keys {
    let suite = initial_rustls_suite();
    let rustls_side = match side {
        QuinnSide::Client => rustls::Side::Client,
        QuinnSide::Server => rustls::Side::Server,
    };
    let keys = suite.keys(dst_cid, rustls_side, rustls::quic::Version::V1);
    Keys {
        header: KeyPair {
            local: Box::new(keys.local.header),
            remote: Box::new(keys.remote.header),
        },
        packet: KeyPair {
            local: Box::new(keys.local.packet),
            remote: Box::new(keys.remote.packet),
        },
    }
}

impl QuinnCryptoClientConfig for Tls13QuicClientConfig {
    fn start_session(
        self: Arc<Self>,
        version: u32,
        _server_name: &str,
        params: &TransportParameters,
    ) -> std::result::Result<Box<dyn Session>, ConnectError> {
        if version != QUIC_V1 {
            // QUIC v1 only (the engine's outbounds; quinn has no v2).
            return Err(ConnectError::UnsupportedVersion);
        }
        // quinn's own `to_vec` (quinn_proto src/crypto/rustls.rs:590-594).
        let mut transport_params = Vec::new();
        params.write(&mut transport_params);
        let flight = self
            .build_flight(&transport_params)
            .map_err(|e| ConnectError::InvalidServerName(e.to_string()))?;
        Ok(Box::new(Tls13QuicSession::client(flight, Arc::clone(&self.auth))))
    }
}

// ---------------------------------------------------------------------------
// The session (quinn crypto::Session) — the phase machine.
// ---------------------------------------------------------------------------

/// Where the client is in the TLS 1.3 handshake.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ClientPhase {
    /// ClientHello queued; awaiting the ServerHello (or HRR).
    AwaitServerHello,
    /// ServerHello processed; awaiting EE → Cert → CV → Finished.
    AwaitHandshakeFlight,
    /// Handshake complete (client Finished queued, 1-RTT derived).
    Done,
}

/// Which encrypted-phase message the flight walker expects next.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlightStep {
    EncryptedExtensions,
    Certificate,
    CertificateVerify,
    Finished,
}

/// A server certificate + key (test server).
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct ServerCert {
    pub cert_der: Vec<u8>,
    pub signing_key: Arc<dyn rustls::sign::SigningKey>,
}

impl Clone for ServerCert {
    fn clone(&self) -> Self {
        ServerCert {
            cert_der: self.cert_der.clone(),
            signing_key: Arc::clone(&self.signing_key),
        }
    }
}

/// How the test server answers (declared at module scope because the
/// session struct carries it; only constructed under `cfg(test)`).
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone)]
pub(crate) enum ServerMode {
    /// Plain TLS 1.3 termination.
    Plain,
    /// JLS: validate the client random against `users`, stamp the
    /// ServerHello random (wrong credentials → `ERR_AUTH_FAILED`).
    Jls { users: Vec<jls::JlsUser> },
    /// Terminate ECH (accept-confirmation in the ServerHello random)
    /// with the server private half of `config_list`'s first config.
    EchAccept {
        sk_r: [u8; 32],
        config_list: Vec<u8>,
    },
    /// Complete the handshake against the OUTER hello; put
    /// `retry_configs` (an ECHConfigList) into EncryptedExtensions.
    EchReject { retry_configs: Option<Vec<u8>> },
    /// Stateful: reject the first connection with `config_list` as the
    /// retry ECHConfigList, terminate ECH on every later one (exercises
    /// `quic::dial_ech`'s one-shot retry).
    EchRetryOnce {
        sk_r: [u8; 32],
        config_list: Vec<u8>,
        seen: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    },
}

/// The test server's progress.
#[cfg_attr(not(test), allow(dead_code))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServerState {
    AwaitClientHello,
    AwaitClientFinished,
    Done,
}

pub(crate) struct Tls13QuicSession {
    side: QuinnSide,
    phase: ClientPhase,
    step: FlightStep,
    pending_in: Vec<u8>,
    /// Initial-space outgoing bytes (ClientHello / ServerHello).
    out_initial: Vec<u8>,
    /// Handshake-space outgoing bytes (client/server Finished, server
    /// EE/Cert/CV/Fin). Drained only after the handshake keys surfaced —
    /// the phase split of rustls's `write_hs` queue
    /// (rustls-0.23.37 src/quic.rs:478-492).
    out_handshake: Vec<u8>,
    /// Client cert authentication (client side).
    auth: Option<Arc<engine_tls13::ServerAuth>>,
    /// The X25519 private half of the offered key share.
    x25519_secret: [u8; 32],
    /// The ClientHello as sent (retained for the transcript — the
    /// outgoing queue is drained by `write_handshake`).
    sent_hello: Vec<u8>,
    /// The session id the server must echo.
    expected_session_id: Vec<u8>,
    /// JLS credentials (validated against the ServerHello random).
    jls_user: Option<jls::JlsUser>,
    /// ECH context until the ServerHello decides; kept across an HRR.
    ech_ctx: Option<Box<EchClientContext>>,
    /// True once an HRR accepted ECH (the following ServerHello carries
    /// no second confirmation).
    ech_hrr_accepted: bool,
    suite: Option<CipherSuite>,
    transcript: Option<Transcript>,
    /// ECH dual transcripts before the ServerHello decides.
    inner_transcript: Option<Transcript>,
    outer_transcript: Option<Transcript>,
    /// Handshake secrets once the ServerHello is processed.
    hs: Option<HandshakeSecrets>,
    hs_keys: Option<Keys>,
    /// 1-RTT secrets (rotated in place by key updates).
    ap: Option<(Vec<u8>, Vec<u8>)>,
    /// RFC 8446 §7.1 exporter master secret = Derive-Secret(master,
    /// "exp master", transcript through the server Finished) — the base
    /// of the §7.5 exporter (rustls tls13/key_schedule.rs:386-393,829-
    /// 858).
    exporter_master: Option<Vec<u8>>,
    one_rtt_keys: Option<Keys>,
    /// The negotiated ALPN (set by EncryptedExtensions).
    alpn: Option<Vec<u8>>,
    handshake_data_sent: bool,
    /// The peer's raw transport parameters (from the hello/EE).
    peer_params: Option<Vec<u8>>,
    /// The server's own parameters to advertise (server side; read by
    /// the cfg(test) server only).
    #[cfg_attr(not(test), allow(dead_code))]
    server_params: Vec<u8>,
    chain: Vec<Vec<u8>>,
    ech_rejected: bool,
    ech_retry_configs: Option<Vec<u8>>,
    connected: bool,
    failed: Option<TransportError>,
    // ---- server side (tests only) ----
    #[allow(dead_code)]
    server_mode: ServerMode,
    #[allow(dead_code)]
    server_cert: Option<ServerCert>,
    #[allow(dead_code)]
    server_state: ServerState,
    /// The pre-ServerHello transcript base (the ECH inner hello) for the
    /// accept-confirmation computation.
    #[allow(dead_code)]
    ech_base_hello: Option<Vec<u8>>,
}

/// Map a failure into the transport error quinn expects (a crypto alert
/// code, like quinn_proto src/crypto/rustls.rs:108-117).
fn crypto_te(reason: String) -> TransportError {
    TransportError {
        code: TransportErrorCode::crypto(0x28), // handshake_failure
        frame: None,
        reason,
    }
}

impl Tls13QuicSession {
    fn client(flight: ClientFlight, auth: Arc<engine_tls13::ServerAuth>) -> Self {
        let ClientFlight {
            hello,
            secret,
            check,
        } = flight;
        let mut session = Tls13QuicSession {
            side: QuinnSide::Client,
            phase: ClientPhase::AwaitServerHello,
            step: FlightStep::EncryptedExtensions,
            pending_in: Vec::new(),
            out_initial: hello.clone(),
            out_handshake: Vec::new(),
            auth: Some(auth),
            x25519_secret: secret,
            expected_session_id: hello
                .get(profiles::SESSION_ID_OFFSET..profiles::SESSION_ID_OFFSET + 32)
                .map(|s| s.to_vec())
                .unwrap_or_default(),
            sent_hello: hello,
            jls_user: None,
            ech_ctx: None,
            ech_hrr_accepted: false,
            suite: None,
            transcript: None,
            inner_transcript: None,
            outer_transcript: None,
            hs: None,
            hs_keys: None,
            ap: None,
            exporter_master: None,
            one_rtt_keys: None,
            alpn: None,
            handshake_data_sent: false,
            peer_params: None,
            server_params: Vec::new(),
            chain: Vec::new(),
            ech_rejected: false,
            ech_retry_configs: None,
            connected: false,
            failed: None,
            server_mode: ServerMode::Plain,
            server_cert: None,
            server_state: ServerState::Done,
            ech_base_hello: None,
        };
        match check {
            ServerHelloCheck::None => {}
            ServerHelloCheck::Jls(user) => session.jls_user = Some(user),
            ServerHelloCheck::Ech(ctx) => {
                // Dual transcripts over the inner/outer hellos
                // (reality/tls13.rs:2185-2188).
                let mut inner = Transcript::new(HashKind::Sha256);
                let mut outer = Transcript::new(HashKind::Sha256);
                inner.update(&ctx.inner_msg);
                outer.update(&ctx.outer_msg);
                session.inner_transcript = Some(inner);
                session.outer_transcript = Some(outer);
                session.x25519_secret = ctx.x25519_secret;
                session.expected_session_id = ctx.session_id.to_vec();
                session.ech_ctx = Some(ctx);
            }
        }
        session
    }

    fn fatal(&mut self, reason: String) -> TransportError {
        let te = crypto_te(reason);
        self.failed = Some(te.clone());
        te
    }

    /// The accept-confirmation HKDF over the inner transcript
    /// (`handshakeClientTLS13` accept check, handshake_client_tls13.go:
    /// 86-98; the suite-generic form of reality/tls13.rs:1494-1514 —
    /// SHA-256 agrees byte for byte with
    /// `ech::server_hello_accept_confirmation`).
    fn ech_accept_confirmation(
        hash: HashKind,
        inner_transcript: &Transcript,
        server_hello_msg: &[u8],
        inner_random: &[u8; 32],
    ) -> Result<[u8; 8]> {
        if server_hello_msg.len() < 38 {
            return Err(Error::protocol(
                "quic-tls13: malformed encrypted_client_hello extension",
            ));
        }
        let mut conf = inner_transcript.clone();
        conf.update(&server_hello_msg[..30]);
        conf.update(&[0u8; 8]);
        conf.update(&server_hello_msg[38..]);
        let digest = conf.hash();
        let prk = hkdf_extract(hash, &[], inner_random);
        let mut out = [0u8; 8];
        hash.hkdf_expand_label(&prk, "ech accept confirmation", &digest, &mut out)?;
        Ok(out)
    }

    /// The HRR confirmation (handshake_client_tls13.go:261-272; the
    /// suite-generic form of reality/tls13.rs:1520-1545).
    fn ech_hrr_confirmation(
        hash: HashKind,
        inner_transcript: &Transcript,
        hrr_msg: &[u8],
        ech_ext_value: &[u8],
        inner_random: &[u8; 32],
    ) -> Result<[u8; 8]> {
        if ech_ext_value.len() != 8 {
            return Err(Error::protocol(
                "quic-tls13: malformed encrypted_client_hello extension",
            ));
        }
        let mut hrr = hrr_msg.to_vec();
        let pos = hrr
            .windows(8)
            .position(|w| w == ech_ext_value)
            .ok_or_else(|| Error::protocol("quic-tls13: hrr without the ECH extension value"))?;
        hrr[pos..pos + 8].fill(0);
        let mut conf = inner_transcript.clone();
        conf.update(&hrr);
        let digest = conf.hash();
        let prk = hkdf_extract(hash, &[], inner_random);
        let mut out = [0u8; 8];
        hash.hkdf_expand_label(&prk, "hrr ech accept confirmation", &digest, &mut out)?;
        Ok(out)
    }

    /// Derive the handshake secrets + packet keys once the transcript is
    /// bound (the tail of reality/tls13.rs:1195-1201).
    fn derive_handshake_keys(&mut self, suite: CipherSuite, shared: &[u8; 32]) -> Option<()> {
        let transcript = self.transcript.as_ref()?;
        let hs = handshake_secrets(suite, shared, &transcript.hash()).ok()?;
        let keys = keys_from_secrets(suite, &hs.c_hs, &hs.s_hs, QuinnSide::Client).ok()?;
        self.hs_keys = Some(keys);
        self.hs = Some(hs);
        self.suite = Some(suite);
        self.phase = ClientPhase::AwaitHandshakeFlight;
        self.step = FlightStep::EncryptedExtensions;
        Some(())
    }

    /// Client side: process the ServerHello (the QUIC-CRYPTO form of
    /// reality/tls13.rs:1175-1201, plus the ECH branches of `ech_attempt`
    /// at reality/tls13.rs:2164-2300).
    fn client_server_hello(&mut self, sh_raw: &[u8]) -> std::result::Result<(), TransportError> {
        let sh = match parse_server_hello(sh_raw) {
            Ok(sh) => sh,
            Err(e) => return Err(self.fatal(e.to_string())),
        };

        // JLS: the random must open as the fakeRandom (utls.go:169-188).
        if let Some(user) = self.jls_user.clone() {
            let auth_data = match jls::hello_auth_data(sh_raw, HS_SERVER_HELLO) {
                Ok(a) => a,
                Err(e) => return Err(self.fatal(e.to_string())),
            };
            let random = &sh_raw[6..38];
            if !jls::check_fake_random(&user, random, &auth_data) {
                return Err(self.fatal(jls::ERR_AUTH_FAILED.to_string()));
            }
        }

        let suite = match CipherSuite::from_id(sh.cipher_suite) {
            Some(s) => s,
            None => {
                return Err(self.fatal(format!(
                    "quic-tls13: server selected unsupported cipher suite {:#06x}",
                    sh.cipher_suite
                )))
            }
        };
        if sh.session_id != self.expected_session_id {
            return Err(
                self.fatal("quic-tls13: server echoed the wrong legacy session id".to_string())
            );
        }

        if sh.is_hrr {
            if self.ech_ctx.is_some() {
                return self.client_hrr(suite, sh_raw, sh);
            }
            return Err(self.fatal(
                "quic-tls13: server asked for HelloRetryRequest (we offer an X25519 key share)"
                    .to_string(),
            ));
        }

        // Bind the transcript. ECH decides inner vs outer; after an
        // accepted HRR the running transcript simply continues.
        if self.ech_ctx.is_some() {
            let ctx = self.ech_ctx.take().expect("checked");
            let mut inner = self
                .inner_transcript
                .take()
                .unwrap_or_else(|| Transcript::new(suite.quic_hash()));
            let mut outer = self
                .outer_transcript
                .take()
                .unwrap_or_else(|| Transcript::new(suite.quic_hash()));
            if self.ech_hrr_accepted {
                // The confirmation was carried by the HRR; this is the
                // real ServerHello (reality/tls13.rs:2262+).
                inner.update(sh_raw);
                self.transcript = Some(inner);
            } else {
                let confirmation = match Self::ech_accept_confirmation(
                    suite.quic_hash(),
                    &inner,
                    sh_raw,
                    &ctx.inner_random,
                ) {
                    Ok(c) => c,
                    Err(e) => return Err(self.fatal(e.to_string())),
                };
                let observed: [u8; 8] = match sh_raw[30..38].try_into() {
                    Ok(v) => v,
                    Err(_) => return Err(self.fatal("quic-tls13: short ServerHello".into())),
                };
                if ech::confirmation_matches(&confirmation, &observed) {
                    inner.update(sh_raw);
                    self.transcript = Some(inner);
                } else {
                    // Rejected: the handshake completes against the OUTER
                    // hello and ends with the upstream rejection error
                    // (handshake_client.go:1081-1145; retry configs come
                    // out of the EncryptedExtensions below).
                    outer.update(sh_raw);
                    self.transcript = Some(outer);
                    self.ech_rejected = true;
                }
            }
            self.x25519_secret = ctx.x25519_secret;
        } else if self.ech_hrr_accepted || self.transcript.is_some() {
            // The HRR second-flight path kept a running transcript.
            let mut transcript = self
                .transcript
                .take()
                .or_else(|| self.inner_transcript.take())
                .expect("running transcript");
            transcript.update(sh_raw);
            self.transcript = Some(transcript);
        } else {
            let mut transcript = Transcript::new(suite.quic_hash());
            // The transcript hash is a property of the negotiated suite,
            // so the ClientHello only enters it once the ServerHello has
            // named that suite (reality/tls13.rs:1193-1197).
            transcript.update(&self.sent_hello);
            transcript.update(sh_raw);
            self.transcript = Some(transcript);
        }

        let shared = match engine_tls13::x25519(&self.x25519_secret, &sh.share) {
            Ok(s) => s,
            Err(e) => return Err(self.fatal(e.to_string())),
        };
        if self.derive_handshake_keys(suite, &shared).is_none() {
            return Err(self.fatal("quic-tls13: handshake key derivation failed".into()));
        }
        Ok(())
    }

    /// The HRR second flight (`processHelloRetryRequest`,
    /// handshake_client_tls13.go:231-405; reality/tls13.rs:2190-2300):
    /// fold both transcripts, check the HRR confirmation; on acceptance
    /// the inner gains the cookie and is re-sealed WITHOUT the
    /// encapsulated key; on rejection the second flight is the outer
    /// with the cookie and the FIRST flight's ciphertext.
    fn client_hrr(
        &mut self,
        suite: CipherSuite,
        sh_raw: &[u8],
        sh: ParsedServerHello,
    ) -> std::result::Result<(), TransportError> {
        let mut ctx = self.ech_ctx.take().expect("ech ctx checked by caller");
        let mut inner = self
            .inner_transcript
            .take()
            .unwrap_or_else(|| Transcript::new(suite.quic_hash()));
        let mut outer = self
            .outer_transcript
            .take()
            .unwrap_or_else(|| Transcript::new(suite.quic_hash()));
        // Both transcripts fold to a message_hash FIRST
        // (handshake_client_tls13.go:238-253).
        inner = inner.fold_message_hash();
        outer = outer.fold_message_hash();

        let mut accepted = false;
        if let Some(value) = sh.ech_ext.clone() {
            if value.len() == 8 {
                let conf = match Self::ech_hrr_confirmation(
                    suite.quic_hash(),
                    &inner,
                    sh_raw,
                    &value,
                    &ctx.inner_random,
                ) {
                    Ok(c) => c,
                    Err(e) => return Err(self.fatal(e.to_string())),
                };
                accepted = ech::confirmation_matches(
                    &conf,
                    value.as_slice().try_into().unwrap_or(&[0u8; 8]),
                );
            }
        }

        if !accepted {
            // Rejected HRR: the second flight is the outer with the
            // cookie, keeping the first flight's sealed payload
            // (reality/tls13.rs:2095-2100).
            let mut exts = ctx.outer_exts.clone();
            if let Some(cookie) = sh.cookie.clone() {
                ech_insert_cookie(&mut exts, &cookie);
            }
            if let Some(ech_ext) = first_flight_ech_ext(&ctx.outer_msg) {
                ech_insert_ech(&mut exts, ech_ext);
            } else {
                return Err(self.fatal("quic-tls13: first flight had no ECH payload".into()));
            }
            let outer2 = serialize_ech_hello(
                &ctx.outer_random,
                Some(&ctx.session_id),
                &ctx.suites_comp,
                &exts,
            );
            outer.update(&outer2);
            self.transcript = Some(outer);
            self.ech_rejected = true;
            self.pending_in.clear();
            self.phase = ClientPhase::AwaitServerHello;
            // The ctx is no longer needed on the rejected path.
            self.x25519_secret = ctx.x25519_secret;
            self.ech_hrr_accepted = false;
            self.out_initial = Vec::new();
            self.out_handshake = outer2;
            return Ok(());
        }

        // Accepted HRR: inner gains the cookie, is re-encoded and
        // re-sealed WITHOUT `enc` (reality/tls13.rs:2076-2094).
        let cookie = sh.cookie.clone().unwrap_or_default();
        let mut inner_exts = ctx.inner_exts.clone();
        ech_insert_cookie(&mut inner_exts, &cookie);
        let wire2 = serialize_ech_hello(&ctx.inner_random, None, &ctx.suites_comp, &inner_exts);
        let encoded2 = ech::encode_inner_client_hello(
            &wire2[4..],
            Some(ctx.inner_sni_bytes.as_slice()),
            ctx.max_name_length,
        );
        let EchClientContext {
            hpke,
            outer_exts,
            outer_random,
            session_id,
            suites_comp,
            config_id,
            kdf_id,
            aead_id,
            ..
        } = &mut *ctx;
        let ech_ext = {
            let result = ech::compute_outer_ech_ext(
                hpke,
                *config_id,
                *kdf_id,
                *aead_id,
                &[], // useKey == false (ech.go:441-449)
                &encoded2,
                false,
                |placeholder| {
                    let mut exts = outer_exts.clone();
                    ech_insert_ech(&mut exts, placeholder.to_vec());
                    serialize_ech_hello(outer_random, Some(session_id), suites_comp, &exts)[4..]
                        .to_vec()
                },
            );
            match result {
                Ok(v) => v,
                Err(e) => return Err(self.fatal(e.to_string())),
            }
        };
        let inner2 = serialize_ech_hello(&ctx.inner_random, Some(&ctx.session_id), &ctx.suites_comp, &inner_exts);
        let mut outer2_exts = ctx.outer_exts.clone();
        ech_insert_ech(&mut outer2_exts, ech_ext);
        let outer2 = serialize_ech_hello(
            &ctx.outer_random,
            Some(&ctx.session_id),
            &ctx.suites_comp,
            &outer2_exts,
        );

        // The active transcript is the folded inner + inner2; it becomes
        // the running transcript the real ServerHello continues.
        inner.update(&inner2);
        ctx.inner_msg = inner2;
        self.transcript = Some(inner);
        self.inner_transcript = None;
        self.pending_in.clear();
        self.phase = ClientPhase::AwaitServerHello;
        self.ech_hrr_accepted = true;
        self.out_initial = Vec::new();
        self.out_handshake = outer2;
        Ok(())
    }

    /// Client side: the encrypted flight walker (the QUIC-CRYPTO form of
    /// reality/tls13.rs:1208-1288).
    fn client_flight_step(
        &mut self,
        typ: u8,
        raw: &[u8],
    ) -> std::result::Result<(), TransportError> {
        let Some(suite) = self.suite else {
            return Err(self.fatal("quic-tls13: handshake before the ServerHello".into()));
        };
        let mut transcript = self
            .transcript
            .take()
            .expect("transcript bound at the ServerHello");
        let outcome: std::result::Result<(), String> = (|| {
            let err = |e: Error| e.to_string();
            match (self.step, typ) {
                (FlightStep::EncryptedExtensions, HS_ENCRYPTED_EXTENSIONS) => {
                    let ee = parse_encrypted_extensions(raw).map_err(err)?;
                    transcript.update(raw);
                    self.alpn = ee.alpn;
                    if self.ech_rejected {
                        self.ech_retry_configs = ee.ech_retry_configs;
                    }
                    if self.peer_params.is_none() {
                        self.peer_params = ee.transport_parameters;
                    }
                    self.step = FlightStep::Certificate;
                    Ok(())
                }
                (FlightStep::Certificate, HS_CERTIFICATE) => {
                    let chain = parse_certificate(raw).map_err(err)?;
                    transcript.update(raw);
                    self.chain = chain;
                    self.step = FlightStep::CertificateVerify;
                    Ok(())
                }
                (FlightStep::Certificate, HS_COMPRESSED_CERTIFICATE) => {
                    Err("quic-tls13: server sent a compressed certificate (RFC 8879); \
                         not supported"
                        .to_string())
                }
                (FlightStep::CertificateVerify, HS_CERTIFICATE_VERIFY) => {
                    let hash_at_cert = transcript.hash();
                    transcript.update(raw);
                    let leaf = self.chain.first().cloned().unwrap_or_default();
                    verify_certificate_verify(
                        raw.get(4..).unwrap_or_default(),
                        &leaf,
                        &hash_at_cert,
                    )
                    .map_err(err)?;
                    // The chain trust decision. On ECH rejection upstream
                    // verifies against the PUBLIC name and skips the
                    // peer-certificate callback (handshake_client.go:
                    // 1081-1145); the rejection error is imminent, so the
                    // trust decision is skipped here too.
                    if !self.ech_rejected {
                        let auth = self.auth.clone().expect("client auth");
                        match auth.as_ref() {
                            engine_tls13::ServerAuth::AcceptAny => {}
                            engine_tls13::ServerAuth::WebPki { roots, server_name } => {
                                verify_chain_webpki(roots, server_name.as_str(), &self.chain)
                                    .map_err(err)?;
                            }
                            engine_tls13::ServerAuth::Callback(check) => {
                                check(&leaf).map_err(err)?;
                            }
                        }
                    }
                    self.step = FlightStep::Finished;
                    Ok(())
                }
                (FlightStep::Finished, HS_FINISHED) => {
                    let hs = self.hs.clone().expect("handshake secrets");
                    let hash_at_cv = transcript.hash();
                    verify_finished(
                        suite.quic_hash(),
                        &finished_key(suite.quic_hash(), &hs.s_hs).map_err(err)?,
                        &hash_at_cv,
                        raw.get(4..).unwrap_or_default(),
                    )
                    .map_err(err)?;
                    transcript.update(raw);

                    if self.ech_rejected {
                        // Upstream ends a rejected handshake with alert
                        // `ech_required` + the `ECHRejectionError` text
                        // (ech.go:486-492); the retry list rides the
                        // error text so the dial layer can retry once.
                        let mut reason = ERR_ECH_REJECTED.to_string();
                        if let Some(list) = self.ech_retry_configs.clone() {
                            use base64::Engine as _;
                            reason.push_str("; retry-configs=");
                            reason.push_str(
                                &base64::engine::general_purpose::STANDARD.encode(list),
                            );
                        }
                        return Err(reason);
                    }

                    // Client Finished, protected by quinn with the
                    // handshake keys (the packet space owns the CRYPTO
                    // protection, RFC 9001 §5.7).
                    let verify_data = finished_verify_data(
                        suite.quic_hash(),
                        &finished_key(suite.quic_hash(), &hs.c_hs).map_err(err)?,
                        &transcript.hash(),
                    )
                    .map_err(err)?;
                    self.out_handshake = hs_message(HS_FINISHED, &verify_data);

                    // Application traffic keys, derived from the
                    // transcript through the server Finished
                    // (reality/tls13.rs:1283-1288).
                    let hash_at_sfin = transcript.hash();
                    self.exporter_master = Some(
                        derive_secret(
                            suite.quic_hash(),
                            &hs.master,
                            "exp master",
                            &hash_at_sfin,
                        )
                        .map_err(err)?,
                    );
                    let (c_ap, s_ap) =
                        application_secrets(suite.quic_hash(), &hs.master, &hash_at_sfin)
                            .map_err(err)?;
                    self.one_rtt_keys = Some(
                        keys_from_secrets(suite, &c_ap, &s_ap, QuinnSide::Client).map_err(err)?,
                    );
                    self.ap = Some((c_ap, s_ap));
                    self.phase = ClientPhase::Done;
                    self.connected = true;
                    Ok(())
                }
                (step, typ) => Err(format!(
                    "quic-tls13: unexpected handshake message {typ} at {step:?}"
                )),
            }
        })();
        self.transcript = Some(transcript);
        match outcome {
            Ok(()) => Ok(()),
            Err(reason) => Err(self.fatal(reason)),
        }
    }

    /// Read one CRYPTO chunk (the trait feeds contiguous plaintext, in
    /// stream order — quinn reassembles the spaces).
    fn client_read(&mut self, buf: &[u8]) -> std::result::Result<bool, TransportError> {
        self.pending_in.extend_from_slice(buf);
        while let Some((typ, raw)) = take_handshake(&mut self.pending_in) {
            match self.phase {
                ClientPhase::AwaitServerHello => {
                    if typ != HS_SERVER_HELLO {
                        return Err(self.fatal(format!(
                            "quic-tls13: expected a ServerHello, got handshake type {typ}"
                        )));
                    }
                    self.client_server_hello(&raw)?;
                }
                ClientPhase::AwaitHandshakeFlight => {
                    self.client_flight_step(typ, &raw)?;
                }
                ClientPhase::Done => {
                    // Post-handshake: NewSessionTicket is ignored
                    // (reality/tls13.rs:25).
                    if typ == HS_NEW_SESSION_TICKET {
                        continue;
                    }
                    return Err(self.fatal(format!(
                        "quic-tls13: unexpected post-handshake message {typ}"
                    )));
                }
            }
        }
        // The rustls contract (quinn_proto src/crypto/rustls.rs:118-131):
        // `true` exactly once, when handshake_data became available.
        let ready = self.alpn.is_some() && !self.handshake_data_sent;
        if ready {
            self.handshake_data_sent = true;
        }
        Ok(ready)
    }
}

/// The `encrypted_client_hello` body of the first-flight outer hello (for
/// the rejected-HRR second flight — reality/tls13.rs:2105-2110).
fn first_flight_ech_ext(outer_msg: &[u8]) -> Option<Vec<u8>> {
    let off = hello_ext_block_offset(outer_msg).ok()?;
    for (t, b) in extensions(&outer_msg[off..]).ok()? {
        if t == ech::EXTENSION_ENCRYPTED_CLIENT_HELLO {
            return Some(b.to_vec());
        }
    }
    None
}

impl Session for Tls13QuicSession {
    fn initial_keys(&self, dst_cid: &quinn_proto::ConnectionId, side: QuinnSide) -> Keys {
        initial_packet_keys(dst_cid, side)
    }

    fn handshake_data(&self) -> Option<Box<dyn Any>> {
        self.alpn.as_ref()?;
        // The same HandshakeData type quinn's rustls sessions produce, so
        // downstream downcasts keep working (quinn_proto
        // src/crypto/rustls.rs:60-77).
        Some(Box::new(quinn::crypto::rustls::HandshakeData {
            protocol: self.alpn.clone(),
            server_name: None,
        }))
    }

    fn peer_identity(&self) -> Option<Box<dyn Any>> {
        if self.chain.is_empty() {
            return None;
        }
        Some(Box::new(
            self.chain
                .iter()
                .map(|c| rustls::pki_types::CertificateDer::from(c.clone()))
                .collect::<Vec<rustls::pki_types::CertificateDer<'static>>>(),
        ))
    }

    fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
        None // no 0-RTT
    }

    fn early_data_accepted(&self) -> Option<bool> {
        None
    }

    fn is_handshaking(&self) -> bool {
        !self.connected
    }

    fn read_handshake(&mut self, buf: &[u8]) -> std::result::Result<bool, TransportError> {
        match self.side {
            QuinnSide::Client => self.client_read(buf),
            #[cfg(test)]
            QuinnSide::Server => self.server_read(buf),
            #[cfg(not(test))]
            QuinnSide::Server => Err(crypto_te(
                "quic-tls13: server sessions exist only in tests".to_string(),
            )),
        }
    }

    fn transport_parameters(
        &self,
    ) -> std::result::Result<Option<TransportParameters>, TransportError> {
        // quinn's rustls glue (quinn_proto src/crypto/rustls.rs:134-142).
        let Some(raw) = self.peer_params.as_ref() else {
            return Ok(None);
        };
        let mut cursor = Cursor::new(raw.clone());
        TransportParameters::read(self.side, &mut cursor)
            .map(Some)
            .map_err(Into::into)
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
        // The rustls key-change contract (rustls-0.23.37 src/quic.rs:478-
        // 510): Initial-space bytes drain first; the handshake keys are
        // surfaced at the phase boundary (quinn arms the Handshake space
        // with them); only then do the Handshake-space bytes drain, with
        // the 1-RTT keys closing the sequence. quinn sends a call's bytes
        // in the CURRENT packet space (quinn_proto src/connection/mod.rs:
        // 2149-2208).
        if !self.out_initial.is_empty() {
            buf.append(&mut self.out_initial);
        }
        if let Some(keys) = self.hs_keys.take() {
            return Some(keys);
        }
        if !self.out_handshake.is_empty() {
            buf.append(&mut self.out_handshake);
        }
        if let Some(keys) = self.one_rtt_keys.take() {
            return Some(keys);
        }
        None
    }

    fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
        // RFC 9001 §6: both packet secrets rotate under "quic ku"; header
        // protection keys stay.
        let suite = self.suite?;
        let (c, s) = self.ap.as_ref()?;
        let c_next = quic_key_update(suite.quic_hash(), c).ok()?;
        let s_next = quic_key_update(suite.quic_hash(), s).ok()?;
        self.ap = Some((c_next.clone(), s_next.clone()));
        let (local, _) = secret_keys(suite, &c_next).ok()?;
        let (remote, _) = secret_keys(suite, &s_next).ok()?;
        Some(KeyPair {
            local: Box::new(local),
            remote: Box::new(remote),
        })
    }

    fn is_valid_retry(
        &self,
        orig_dst_cid: &quinn_proto::ConnectionId,
        header: &[u8],
        payload: &[u8],
    ) -> bool {
        // Retry integrity tag (RFC 9001 §5.8) — the mirror of quinn's
        // rustls session (quinn_proto src/crypto/rustls.rs:174-199).
        const RETRY_INTEGRITY_KEY_V1: [u8; 16] = [
            0xbe, 0x0c, 0x69, 0x0b, 0x9f, 0x66, 0x57, 0x5a, 0x1d, 0x76, 0x6b, 0x54, 0xe3, 0x68,
            0xc8, 0x4e,
        ];
        const RETRY_INTEGRITY_NONCE_V1: [u8; 12] = [
            0x46, 0x15, 0x99, 0xd3, 0x5d, 0x63, 0x2b, 0xf2, 0x23, 0x98, 0x25, 0xbb,
        ];
        let tag_start = match payload.len().checked_sub(16) {
            Some(x) => x,
            None => return false,
        };
        let mut pseudo_packet =
            Vec::with_capacity(header.len() + payload.len() + orig_dst_cid.len() + 1);
        pseudo_packet.push(orig_dst_cid.len() as u8);
        pseudo_packet.extend_from_slice(orig_dst_cid);
        pseudo_packet.extend_from_slice(header);
        let tag_start = tag_start + pseudo_packet.len();
        pseudo_packet.extend_from_slice(payload);
        let nonce = aead::Nonce::assume_unique_for_key(RETRY_INTEGRITY_NONCE_V1);
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_128_GCM, &RETRY_INTEGRITY_KEY_V1)
                .expect("static retry key"),
        );
        let (aad, tag) = pseudo_packet.split_at_mut(tag_start);
        key.open_in_place(nonce, aead::Aad::from(&*aad), tag).is_ok()
    }

    fn export_keying_material(
        &self,
        output: &mut [u8],
        label: &[u8],
        context: &[u8],
    ) -> std::result::Result<(), ExportKeyingMaterialError> {
        // RFC 8446 §7.5 over the exporter master secret (§7.1 "exp
        // master" over the transcript through the server Finished):
        // exporter_value = HKDF-Expand-Label(Derive-Secret(
        // exporter_master, label, Hash("")), "exporter", Hash(context),
        // len) — the TUIC v5 auth token rides this (proto/tuic.rs); the
        // exact chain rustls implements (tls13/key_schedule.rs:829-858).
        let Some(suite) = self.suite else {
            return Err(ExportKeyingMaterialError);
        };
        let Some(exporter_master) = self.exporter_master.as_ref() else {
            return Err(ExportKeyingMaterialError);
        };
        let hash = suite.quic_hash();
        let empty_hash = hash.hash(&[]);
        // Derive-Secret with the caller's (opaque) label over the empty
        // transcript hash.
        let mut secret = vec![0u8; hash.digest_len()];
        hash.hkdf_expand_label_raw(exporter_master, label, &empty_hash, &mut secret)
            .map_err(|_| ExportKeyingMaterialError)?;
        let context_hash = hash.hash(context);
        hash.hkdf_expand_label_raw(&secret, b"exporter", &context_hash, output)
            .map_err(|_| ExportKeyingMaterialError)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// ECH dial-level retry: parse the retry-configs a rejected handshake
// surfaced and redial once (the caller-side loop of
// reality/tls13.rs:1464-1488).
// ---------------------------------------------------------------------------

/// If `err` is an ECH rejection carrying retry configs, decode them.
pub fn ech_retry_configs_of(err: &str) -> Option<Vec<u8>> {
    let (_, b64) = err.split_once(&format!("{ERR_ECH_REJECTED}; retry-configs="))?;
    // The list runs to the end of the error text (the transport error
    // carries it as the trailing reason).
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD.decode(b64).ok()
}

// ---------------------------------------------------------------------------
// Test server: a quinn `crypto::ServerConfig` over the same machinery,
// with JLS validation/stamping and ECH termination (the QUIC form of
// reality/tls13.rs's `test_server`, 2992-3266, and its ECH arm 3259+).
// ---------------------------------------------------------------------------

#[cfg(test)]
pub(crate) mod test_server {
    use super::*;

    use std::net::SocketAddr;
    use std::time::Duration;

    use quinn_proto::crypto::ServerConfig as QuinnCryptoServerConfig;
    use quinn_proto::crypto::UnsupportedVersion;

    pub(crate) struct Tls13QuicServerConfig {
        pub mode: ServerMode,
        pub cert: ServerCert,
        /// The suite to answer with (must be offered).
        pub suite: CipherSuite,
    }

    impl QuinnCryptoServerConfig for Tls13QuicServerConfig {
        fn initial_keys(
            &self,
            version: u32,
            dst_cid: &quinn_proto::ConnectionId,
        ) -> std::result::Result<Keys, UnsupportedVersion> {
            if version != QUIC_V1 {
                return Err(UnsupportedVersion);
            }
            Ok(initial_packet_keys(dst_cid, QuinnSide::Server))
        }

        fn retry_tag(
            &self,
            _version: u32,
            _orig_dst_cid: &quinn_proto::ConnectionId,
            _packet: &[u8],
        ) -> [u8; 16] {
            [0u8; 16] // the loopback tests never traverse a retry
        }

        fn start_session(
            self: Arc<Self>,
            version: u32,
            params: &TransportParameters,
        ) -> Box<dyn Session> {
            assert_eq!(version, QUIC_V1);
            let mut transport_params = Vec::new();
            params.write(&mut transport_params);
            let mut session = Tls13QuicSession::server(
                self.mode.clone(),
                ServerCert {
                    cert_der: self.cert.cert_der.clone(),
                    signing_key: Arc::clone(&self.cert.signing_key),
                },
                self.suite,
            );
            session.server_params = transport_params;
            Box::new(session)
        }
    }

    /// What the test server learned from the ClientHello (the shape of
    /// reality/tls13.rs:3000-3070).
    #[derive(Debug, Clone)]
    pub(crate) struct ClientHelloInfo {
        #[allow(dead_code)]
        pub raw: Vec<u8>,
        pub session_id: Vec<u8>,
        pub x25519_share: [u8; 32],
        pub alpn: Vec<String>,
        pub cipher_suites: Vec<u16>,
        pub transport_parameters: Option<Vec<u8>>,
    }

    fn parse_client_hello(raw: &[u8]) -> Result<ClientHelloInfo> {
        let b = raw
            .get(4..)
            .ok_or_else(|| Error::protocol("test server: short hello"))?;
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
        let mut alpn = Vec::new();
        let mut transport_parameters = None;
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
                EXT_TRANSPORT_PARAMETERS => transport_parameters = Some(body.to_vec()),
                _ => {}
            }
        }
        Ok(ClientHelloInfo {
            raw: raw.to_vec(),
            session_id,
            x25519_share: x25519_share
                .ok_or_else(|| Error::protocol("test server: no X25519 key share"))?,
            alpn,
            cipher_suites,
            transport_parameters,
        })
    }

    /// Open the ECH payload of an outer hello and reconstruct the
    /// transcript-form inner — the one-key trial decryption of
    /// `processECHClientHello` (reality/tls13.rs:3341-3386 over the
    /// public `proto::ech` API).
    fn open_ech_hello(ch_raw: &[u8], recipient: &mut ech::HpkeSender) -> Result<Vec<u8>> {
        let off = hello_ext_block_offset(ch_raw)?;
        let mut ext_body = None;
        for (t, b) in extensions(&ch_raw[off..])? {
            if t == ech::EXTENSION_ENCRYPTED_CLIENT_HELLO {
                ext_body = Some(b.to_vec());
            }
        }
        let ext_body =
            ext_body.ok_or_else(|| Error::protocol("test server: no ECH extension"))?;
        let payload = match ech::parse_ech_ext(&ext_body)? {
            ech::EchExt::Inner => {
                return Err(Error::protocol("test server: inner marker on the wire"));
            }
            ech::EchExt::Outer { payload, .. } => payload,
        };
        // AAD = hello[4..] with the payload's first occurrence zeroed
        // (`decryptECHPayload`, ech.go:401-405).
        let body = &ch_raw[4..];
        let pos = body
            .windows(payload.len())
            .position(|w| w == payload.as_slice())
            .ok_or_else(|| Error::protocol("test server: payload not in hello"))?;
        let mut aad = body.to_vec();
        aad[pos..pos + payload.len()].fill(0);
        let encoded = recipient.open(&aad, &payload)?;
        ech::decode_inner_client_hello(ch_raw, &encoded)
    }

    /// A deterministic server ECH key pair advertising `sk_r`'s public
    /// half (the shape of reality/tls13.rs:3278-3316 via the public ech
    /// API). Returns (sk_r, ECHConfigList).
    pub(crate) fn ech_server_key(
        seed: &[u8],
        config_id: u8,
        public_name: &[u8],
    ) -> ([u8; 32], Vec<u8>) {
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
        body.push(0x20);
        body.push(public_name.len() as u8);
        body.extend_from_slice(public_name);
        body.extend_from_slice(&0u16.to_be_bytes());
        let mut list = Vec::with_capacity(6 + body.len());
        list.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
        list.extend_from_slice(&ech::EXTENSION_ENCRYPTED_CLIENT_HELLO.to_be_bytes());
        list.extend_from_slice(&(body.len() as u16).to_be_bytes());
        list.extend_from_slice(&body);
        (sk, list)
    }

    impl Tls13QuicSession {
        pub(crate) fn server(mode: ServerMode, cert: ServerCert, suite: CipherSuite) -> Self {
            Tls13QuicSession {
                side: QuinnSide::Server,
                phase: ClientPhase::AwaitServerHello,
                step: FlightStep::EncryptedExtensions,
                pending_in: Vec::new(),
                out_initial: Vec::new(),
                out_handshake: Vec::new(),
                auth: None,
                x25519_secret: [0u8; 32],
                sent_hello: Vec::new(),
                expected_session_id: Vec::new(),
                jls_user: None,
                ech_ctx: None,
                ech_hrr_accepted: false,
                suite: Some(suite),
                transcript: None,
                inner_transcript: None,
                outer_transcript: None,
                hs: None,
                hs_keys: None,
                ap: None,
                exporter_master: None,
                one_rtt_keys: None,
                alpn: None,
                handshake_data_sent: false,
                peer_params: None,
                server_params: Vec::new(),
                chain: Vec::new(),
                ech_rejected: false,
                ech_retry_configs: None,
                connected: false,
                failed: None,
                server_mode: mode,
                server_cert: Some(cert),
                server_state: ServerState::AwaitClientHello,
                ech_base_hello: None,
            }
        }

        /// Server side: process the ClientHello, build the whole server
        /// flight (the QUIC-CRYPTO form of reality test_server::accept,
        /// tls13.rs:3076-3249, with the ECH arm of `ech_server_flight`).
        fn server_client_hello(
            &mut self,
            ch_raw: &[u8],
        ) -> std::result::Result<(), TransportError> {
            let mode = self.server_mode.clone();
            let cert = self.server_cert.clone().expect("server cert");
            let suite = self.suite.expect("server suite");
            let mut run = || -> Result<ServerFlightBuilt> {
                let hello = parse_client_hello(ch_raw)?;
                if !hello.cipher_suites.contains(&suite.id()) {
                    return Err(Error::protocol("test server: suite not offered"));
                }
                self.peer_params = hello.transport_parameters.clone();

                let mut transcript = Transcript::new(suite.quic_hash());
                // The transcript base: the inner hello when ECH is
                // terminated, the (outer) hello otherwise.
                let mut inner_random = None;
                match &mode {
                    ServerMode::Plain => transcript.update(ch_raw),
                    ServerMode::Jls { users } => {
                        let auth_data = jls::hello_auth_data(ch_raw, HS_CLIENT_HELLO)?;
                        let random = &ch_raw[6..38];
                        let user = users
                            .iter()
                            .find(|u| jls::check_fake_random(u, random, &auth_data));
                        let Some(user) = user else {
                            return Err(Error::crypto(jls::ERR_AUTH_FAILED.to_string()));
                        };
                        self.jls_user = Some(user.clone());
                        transcript.update(ch_raw);
                    }
                    ServerMode::EchAccept { sk_r, config_list } => {
                        // Extract enc + aead id, decap, open the payload,
                        // reconstruct the transcript-form inner hello.
                        let off = hello_ext_block_offset(ch_raw)?;
                        let mut enc = None;
                        let mut aead_id = ech::AEAD_AES_128_GCM;
                        for (t, b) in extensions(&ch_raw[off..])? {
                            if t == ech::EXTENSION_ENCRYPTED_CLIENT_HELLO {
                                if let Ok(ech::EchExt::Outer {
                                    enc: e,
                                    aead_id: a,
                                    ..
                                }) = ech::parse_ech_ext(b)
                                {
                                    enc = Some(e);
                                    aead_id = a;
                                }
                            }
                        }
                        let enc: [u8; 32] = enc
                            .ok_or_else(|| Error::protocol("test server: no ECH extension"))?
                            .try_into()
                            .map_err(|_| Error::protocol("test server: bad enc"))?;
                        let shared = ech::hpke_decap(sk_r, &enc)
                            .map_err(|e| Error::protocol(format!("test server: decap: {e}")))?;
                        let configs = ech::parse_ech_config_list(config_list)?;
                        let mut recipient = ech::HpkeSender::from_shared_secret(
                            &shared,
                            ech::HpkeAead::from_id(aead_id)
                                .ok_or_else(|| Error::protocol("test server: unsupported aead"))?,
                            &ech::ech_hpke_info(&configs[0]),
                        )?;
                        let inner_msg = open_ech_hello(ch_raw, &mut recipient)?;
                        let random: [u8; 32] = inner_msg[6..38].try_into().unwrap();
                        inner_random = Some(random);
                        // The accept confirmation hashes the pre-SH
                        // transcript; keep the base around.
                        self.ech_base_hello = Some(inner_msg.clone());
                        transcript.update(&inner_msg);
                    }
                    ServerMode::EchReject { retry_configs } => {
                        transcript.update(ch_raw);
                        self.ech_retry_configs = retry_configs.clone();
                    }
                    ServerMode::EchRetryOnce {
                        sk_r,
                        config_list,
                        seen,
                    } => {
                        let nth = seen.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if nth == 0 {
                            transcript.update(ch_raw);
                            self.ech_retry_configs = Some(config_list.clone());
                        } else {
                            // The accepted path, inlined from EchAccept.
                            let off = hello_ext_block_offset(ch_raw)?;
                            let mut enc = None;
                            let mut aead_id = ech::AEAD_AES_128_GCM;
                            for (t, b) in extensions(&ch_raw[off..])? {
                                if t == ech::EXTENSION_ENCRYPTED_CLIENT_HELLO {
                                    if let Ok(ech::EchExt::Outer {
                                        enc: e,
                                        aead_id: a,
                                        ..
                                    }) = ech::parse_ech_ext(b)
                                    {
                                        enc = Some(e);
                                        aead_id = a;
                                    }
                                }
                            }
                            let enc: [u8; 32] = enc
                                .ok_or_else(|| Error::protocol("test server: no ECH extension"))?
                                .try_into()
                                .map_err(|_| Error::protocol("test server: bad enc"))?;
                            let shared = ech::hpke_decap(sk_r, &enc)
                                .map_err(|e| Error::protocol(format!("test server: decap: {e}")))?;
                            let configs = ech::parse_ech_config_list(config_list)?;
                            let mut recipient = ech::HpkeSender::from_shared_secret(
                                &shared,
                                ech::HpkeAead::from_id(aead_id)
                                    .ok_or_else(|| Error::protocol("test server: unsupported aead"))?,
                                &ech::ech_hpke_info(&configs[0]),
                            )?;
                            let inner_msg = open_ech_hello(ch_raw, &mut recipient)?;
                            let random: [u8; 32] = inner_msg[6..38].try_into().unwrap();
                            inner_random = Some(random);
                            if let Ok(off) = hello_ext_block_offset(&inner_msg) {
                                if let Ok(exts) = extensions(&inner_msg[off..]) {
                                    for (t, b) in exts {
                                        if t == EXT_TRANSPORT_PARAMETERS {
                                            self.peer_params = Some(b.to_vec());
                                        }
                                    }
                                }
                            }
                            self.ech_base_hello = Some(inner_msg.clone());
                            transcript.update(&inner_msg);
                        }
                    }
                }

                // ServerHello (the shape of reality test_server::accept
                // 3106-3134).
                let mut server_random = [0u8; 32];
                rand::rngs::OsRng.fill_bytes(&mut server_random);
                let (server_secret, server_public) = engine_tls13::x25519_keygen();
                let mut sh_body = Vec::with_capacity(96);
                sh_body.extend_from_slice(&VERSION_TLS12.to_be_bytes());
                sh_body.extend_from_slice(&server_random);
                sh_body.push(hello.session_id.len() as u8);
                sh_body.extend_from_slice(&hello.session_id);
                sh_body.extend_from_slice(&suite.id().to_be_bytes());
                sh_body.push(0x00);
                let mut sh_exts = Vec::new();
                sh_exts.extend_from_slice(&ext_entry(
                    EXT_SUPPORTED_VERSIONS,
                    &VERSION_TLS13.to_be_bytes(),
                ));
                let mut ks = Vec::new();
                ks.extend_from_slice(&GROUP_X25519.to_be_bytes());
                ks.extend_from_slice(&32u16.to_be_bytes());
                ks.extend_from_slice(&server_public);
                sh_exts.extend_from_slice(&ext_entry(EXT_KEY_SHARE, &ks));
                if let Some(first) = hello.alpn.first() {
                    let mut list = vec![first.len() as u8];
                    list.extend_from_slice(first.as_bytes());
                    let mut body = Vec::new();
                    body.extend_from_slice(&(list.len() as u16).to_be_bytes());
                    body.extend_from_slice(&list);
                    sh_exts.extend_from_slice(&ext_entry(EXT_ALPN, &body));
                }
                sh_body.extend_from_slice(&(sh_exts.len() as u16).to_be_bytes());
                sh_body.extend_from_slice(&sh_exts);
                let mut sh_raw = hs_message(HS_SERVER_HELLO, &sh_body);

                // JLS: stamp the ServerHello random in place (the server
                // half of proto/jls.rs:1761-1830: authData over the SH
                // with the random zeroed, seed = the first half of the
                // drawn random; the patch changes only those 32 bytes).
                if let Some(user) = self.jls_user.clone() {
                    let auth_data = jls::hello_auth_data(&sh_raw, HS_SERVER_HELLO)?;
                    let fake = jls::build_fake_random(&user, &server_random[..16], &auth_data)?;
                    sh_raw[6..38].copy_from_slice(&fake);
                }
                transcript.update(&sh_raw);

                // ECH accept confirmation: patch random[24..32] over the
                // zero-slot transcript hash (reality/tls13.rs
                // `ech_server_flight`): build the SH with the slot
                // zeroed, hash base + zeroed SH, expand, patch.
                if let Some(inner_random) = inner_random {
                    let base = self.ech_base_hello.clone().expect("set with inner_random");
                    let mut zeroed = sh_raw.clone();
                    zeroed[30..38].fill(0);
                    let mut conf_tr = Transcript::new(suite.quic_hash());
                    conf_tr.update(&base);
                    conf_tr.update(&zeroed);
                    let prk = hkdf_extract(suite.quic_hash(), &[], &inner_random);
                    let mut conf = [0u8; 8];
                    suite
                        .quic_hash()
                        .hkdf_expand_label(
                            &prk,
                            "ech accept confirmation",
                            &conf_tr.hash(),
                            &mut conf,
                        )?;
                    sh_raw[30..38].copy_from_slice(&conf);
                    // Re-run the transcript over the stamped SH.
                    let mut t = Transcript::new(suite.quic_hash());
                    t.update(&base);
                    t.update(&sh_raw);
                    transcript = t;
                }

                let shared = engine_tls13::x25519(&server_secret, &hello.x25519_share)?;
                let hs = handshake_secrets(suite, &shared, &transcript.hash())?;
                let hs_keys = keys_from_secrets(suite, &hs.c_hs, &hs.s_hs, QuinnSide::Server)?;

                // EncryptedExtensions: echo ALPN + OUR transport
                // parameters (RFC 9001 §8) + the retry list when
                // rejecting ECH.
                let mut ee_exts = Vec::new();
                if let Some(first) = hello.alpn.first() {
                    let mut list = vec![first.len() as u8];
                    list.extend_from_slice(first.as_bytes());
                    let mut body = Vec::new();
                    body.extend_from_slice(&(list.len() as u16).to_be_bytes());
                    body.extend_from_slice(&list);
                    ee_exts.extend_from_slice(&ext_entry(EXT_ALPN, &body));
                }
                ee_exts.extend_from_slice(&ext_entry(
                    EXT_TRANSPORT_PARAMETERS,
                    &self.server_params,
                ));
                if let Some(retry) = self.ech_retry_configs.clone() {
                    ee_exts.extend_from_slice(&ext_entry(
                        ech::EXTENSION_ENCRYPTED_CLIENT_HELLO,
                        &retry,
                    ));
                }
                let mut ee_body = Vec::new();
                ee_body.extend_from_slice(&(ee_exts.len() as u16).to_be_bytes());
                ee_body.extend_from_slice(&ee_exts);
                let ee_raw = hs_message(HS_ENCRYPTED_EXTENSIONS, &ee_body);
                transcript.update(&ee_raw);
                self.alpn = hello.alpn.first().map(|p| p.as_bytes().to_vec());

                // Certificate (reality test_server:3156-3168).
                let cert_der = &cert.cert_der;
                let mut list = Vec::new();
                list.push((cert_der.len() >> 16) as u8);
                list.push((cert_der.len() >> 8) as u8);
                list.push(cert_der.len() as u8);
                list.extend_from_slice(cert_der);
                list.extend_from_slice(&0u16.to_be_bytes());
                let mut cert_body = vec![0x00];
                cert_body.extend_from_slice(&(list.len() as u32).to_be_bytes()[1..]);
                cert_body.extend_from_slice(&list);
                let cert_raw = hs_message(HS_CERTIFICATE, &cert_body);
                transcript.update(&cert_raw);

                // CertificateVerify (reality test_server:3170-3190).
                let signer = cert
                    .signing_key
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
                    .map_err(|e| Error::protocol(format!("test server: sign failed: {e}")))?;
                let mut cv_body = Vec::new();
                cv_body.extend_from_slice(&u16::from(signer.scheme()).to_be_bytes());
                cv_body.extend_from_slice(&(sig.len() as u16).to_be_bytes());
                cv_body.extend_from_slice(&sig);
                let cv_raw = hs_message(HS_CERTIFICATE_VERIFY, &cv_body);
                transcript.update(&cv_raw);

                // Server Finished (reality test_server:3192-3199).
                let server_fin = finished_verify_data(
                    suite.quic_hash(),
                    &finished_key(suite.quic_hash(), &hs.s_hs)?,
                    &transcript.hash(),
                )?;
                let fin_raw = hs_message(HS_FINISHED, &server_fin);
                transcript.update(&fin_raw);
                let hash_at_sfin = transcript.hash();
                let exporter_master =
                    derive_secret(suite.quic_hash(), &hs.master, "exp master", &hash_at_sfin)?;

                // 1-RTT secrets after the server Finished.
                let (c_ap, s_ap) =
                    application_secrets(suite.quic_hash(), &hs.master, &hash_at_sfin)?;
                let one_rtt = keys_from_secrets(suite, &c_ap, &s_ap, QuinnSide::Server)?;

                Ok(ServerFlightBuilt {
                    sh_raw,
                    flight: [ee_raw, cert_raw, cv_raw, fin_raw].concat(),
                    hs,
                    hs_keys,
                    one_rtt,
                    ap: (c_ap, s_ap),
                    exporter_master,
                    transcript,
                })
            };

            match run() {
                Ok(built) => {
                    self.out_initial = built.sh_raw;
                    self.out_handshake = built.flight;
                    self.hs = Some(built.hs);
                    self.hs_keys = Some(built.hs_keys);
                    self.one_rtt_keys = Some(built.one_rtt);
                    self.ap = Some(built.ap);
                    self.exporter_master = Some(built.exporter_master);
                    self.transcript = Some(built.transcript);
                    self.server_state = ServerState::AwaitClientFinished;
                    Ok(())
                }
                Err(reason) => Err(self.fatal(reason.to_string())),
            }
        }

        pub(crate) fn server_read(&mut self, buf: &[u8]) -> std::result::Result<bool, TransportError> {
            self.pending_in.extend_from_slice(buf);
            loop {
                match self.server_state {
                    ServerState::AwaitClientHello => {
                        let Some((typ, raw)) = take_handshake(&mut self.pending_in) else {
                            break;
                        };
                        if typ != HS_CLIENT_HELLO {
                            return Err(
                                self.fatal("test server: expected a ClientHello".to_string())
                            );
                        }
                        self.server_client_hello(&raw)?;
                    }
                    ServerState::AwaitClientFinished => {
                        let Some((typ, raw)) = take_handshake(&mut self.pending_in) else {
                            break;
                        };
                        if typ != HS_FINISHED {
                            return Err(
                                self.fatal("test server: expected the client Finished".to_string())
                            );
                        }
                        let suite = self.suite.expect("suite");
                        let hs = self.hs.clone().expect("secrets");
                        let mut transcript = self.transcript.take().expect("transcript");
                        let outcome: std::result::Result<(), Error> = (|| {
                            let fk = finished_key(suite.quic_hash(), &hs.c_hs)?;
                            verify_finished(
                                suite.quic_hash(),
                                &fk,
                                &transcript.hash(),
                                raw.get(4..).unwrap_or_default(),
                            )?;
                            transcript.update(&raw);
                            Ok(())
                        })();
                        self.transcript = Some(transcript);
                        if let Err(reason) = outcome {
                            return Err(self.fatal(reason.to_string()));
                        }
                        self.connected = true;
                        self.server_state = ServerState::Done;
                    }
                    ServerState::Done => {
                        // Post-handshake server input: ignore.
                        if take_handshake(&mut self.pending_in).is_none() {
                            break;
                        }
                    }
                }
            }
            let ready = self.alpn.is_some() && !self.handshake_data_sent;
            if ready {
                self.handshake_data_sent = true;
            }
            Ok(ready)
        }
    }

    /// The assembled server flight (internal plumbing).
    struct ServerFlightBuilt {
        sh_raw: Vec<u8>,
        flight: Vec<u8>,
        hs: HandshakeSecrets,
        hs_keys: Keys,
        one_rtt: Keys,
        ap: (Vec<u8>, Vec<u8>),
        exporter_master: Vec<u8>,
        transcript: Transcript,
    }

    /// Spawn an in-process quinn server over the custom crypto stack and
    /// return its address + endpoint.
    pub(crate) async fn start_quinn_server(mode: ServerMode) -> Result<quinn::Endpoint> {
        let certified = rcgen::generate_simple_self_signed(vec!["sq.test".to_string()])
            .expect("rcgen self-signed cert");
        let cert_der = certified.cert.der().to_vec();
        let key_der = certified.key_pair.serialize_der();
        let signing_key = rustls::crypto::ring::sign::any_supported_type(
            &rustls::pki_types::PrivateKeyDer::Pkcs8(key_der.into()),
        )
        .expect("signing key");
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_uni_streams(1024u32.into());
        transport.datagram_receive_buffer_size(Some(64 * 1024));
        transport.keep_alive_interval(Some(Duration::from_secs(10)));
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(Tls13QuicServerConfig {
            mode,
            suite: CipherSuite::Aes128GcmSha256,
            cert: ServerCert {
                cert_der,
                signing_key,
            },
        }));
        config.transport_config(Arc::new(transport));
        let endpoint = quinn::Endpoint::server(config, SocketAddr::from(([127, 0, 0, 1], 0)))
            .map_err(|e| Error::network(format!("test quic server bind: {e}")))?;
        Ok(endpoint)
    }
}

// ---------------------------------------------------------------------------
// Tests — hermetic quinn endpoints over the custom crypto stack (loopback
// only, rcgen certs, no network beyond 127.0.0.1).
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::quic::{QuicDial, QuicTlsCover};

    use std::net::SocketAddr;
    use std::time::Duration;


    fn dial_cfg(port: u16, sni: &str, alpn: &[&str]) -> QuicDial {
        QuicDial {
            server: "127.0.0.1".to_string(),
            port,
            sni: sni.to_string(),
            alpn: alpn.iter().map(|s| s.to_string()).collect(),
            skip_verify: true,
            udp_relay: true,
            congestion_brutal_bps: None,
        }
    }

    /// A quinn client config over the plain engine-TLS crypto with a
    /// shared transport (tests build this directly since quinn's
    /// `ClientConfig::transport` field is private).
    fn plain_client_quinn_config(cfg: &QuicDial) -> quinn::ClientConfig {
        let crypto = Tls13QuicClientConfig::new_plain(
            crate::proto::reality::UtslProfile::Chrome,
            &cfg.sni,
            cfg.alpn.clone(),
            true,
        )
        .unwrap();
        let mut quinn_cfg = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_uni_streams(1024u32.into());
        transport.datagram_receive_buffer_size(Some(64 * 1024));
        quinn_cfg.transport_config(Arc::new(transport));
        quinn_cfg
    }

    /// Dial with the plain engine-TLS crypto config.
    async fn dial_plain(addr: SocketAddr, sni: &str, alpn: &[&str]) -> quinn::Connection {
        let cfg = dial_cfg(addr.port(), sni, alpn);
        let mut ep = quinn::Endpoint::client(SocketAddr::from(([127, 0, 0, 1], 0))).unwrap();
        ep.set_default_client_config(plain_client_quinn_config(&cfg));
        let connecting = ep.connect(addr, sni).expect("connect");
        tokio::time::timeout(Duration::from_secs(15), connecting)
            .await
            .expect("connect timed out")
            .expect("handshake failed")
    }

    /// A rustls-based quinn server (the interop target of Task 1).
    async fn rustls_quinn_server(alpn: &[&str]) -> quinn::Endpoint {
        let certified = rcgen::generate_simple_self_signed(vec!["sq.test".to_string()])
            .expect("rcgen self-signed cert");
        let cert = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server config");
        tls.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
        let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls)).unwrap();
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_uni_streams(1024u32.into());
        transport.datagram_receive_buffer_size(Some(64 * 1024));
        config.transport_config(Arc::new(transport));
        quinn::Endpoint::server(config, SocketAddr::from(([127, 0, 0, 1], 0))).unwrap()
    }

    /// Serve echo over every accepted connection of `endpoint`.
    async fn echo_serve(endpoint: quinn::Endpoint) {
        while let Some(incoming) = endpoint.accept().await {
            if let Ok(conn) = incoming.await {
                tokio::spawn(async move {
                    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        tokio::spawn(async move {
                            let mut buf = [0u8; 4096];
                            while let Ok(Some(n)) = recv.read(&mut buf).await {
                                if send.write_all(&buf[..n]).await.is_err() {
                                    break;
                                }
                            }
                            let _ = send.finish();
                        });
                    }
                });
            }
        }
    }

    #[tokio::test]
    async fn plain_config_handshakes_with_a_rustls_quinn_server() {
        // Task 1: the custom crypto stack completes a full QUIC handshake
        // against a rustls quinn server — which requires our ClientHello
        // to carry parseable QUIC transport parameters (quinn rejects a
        // ClientHello without them, connection/mod.rs:2631-2640
        // "transport parameters missing") and requires US to have
        // accepted the server's EE-carried parameters before the
        // connection establishes (connection/mod.rs:2569-2581).
        let endpoint = rustls_quinn_server(&["h3"]).await;
        let addr = endpoint.local_addr().unwrap();
        tokio::spawn(echo_serve(endpoint.clone()));

        let conn = dial_plain(addr, "sq.test", &["h3"]).await;

        // ALPN surfaced through the same HandshakeData type quinn's
        // rustls sessions produce (downcast compatibility).
        let data = conn
            .handshake_data()
            .expect("handshake data")
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .expect("rustls HandshakeData type");
        assert_eq!(data.protocol.as_deref(), Some(&b"h3"[..]));

        // Streams relay across the custom-crypto connection, including a
        // multi-segment payload that exercises the negotiated flow
        // control windows.
        let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
        send.write_all(b"ping over own tls13").await.unwrap();
        let mut buf = vec![0u8; b"ping over own tls13".len()];
        recv.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, b"ping over own tls13");
        let payload: Vec<u8> = (0..9000u32).map(|i| (i % 251) as u8).collect();
        let echo = {
            let payload = payload.clone();
            tokio::spawn(async move {
                let (mut send, mut recv) = conn.open_bi().await.unwrap();
                send.write_all(&payload).await.unwrap();
                let mut got = vec![0u8; payload.len()];
                recv.read_exact(&mut got).await.unwrap();
                got
            })
        };
        let got = tokio::time::timeout(Duration::from_secs(20), echo)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got.len(), payload.len());
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn exporter_agrees_with_rustls_over_the_wire() {
        // RFC 8446 §7.5 exporter: the client runs OUR implementation, the
        // server rustls's; a shared secret over the live connection pins
        // the formula (the TUIC v5 auth token rides this).
        let endpoint = rustls_quinn_server(&["h3"]).await;
        let addr = endpoint.local_addr().unwrap();
        let (tx, rx) = tokio::sync::oneshot::channel();
        tokio::spawn({
            let endpoint = endpoint.clone();
            async move {
                // Accept once: export, then echo the connection's
                // streams (a single accept loop — two loops would race
                // for the one incoming connection).
                while let Some(incoming) = endpoint.accept().await {
                    if let Ok(conn) = incoming.await {
                        let mut out = [0u8; 32];
                        conn.export_keying_material(&mut out, b"tuic v5", b"context")
                            .expect("server export");
                        let _ = tx.send(out);
                        tokio::spawn(async move {
                            while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                                tokio::spawn(async move {
                                    let mut buf = [0u8; 4096];
                                    while let Ok(Some(n)) = recv.read(&mut buf).await {
                                        if send.write_all(&buf[..n]).await.is_err() {
                                            break;
                                        }
                                    }
                                    let _ = send.finish();
                                });
                            }
                        });
                        break;
                    }
                }
            }
        });

        let conn = dial_plain(addr, "sq.test", &["h3"]).await;

        let mut client_out = [0u8; 32];
        conn.export_keying_material(&mut client_out, b"tuic v5", b"context")
            .expect("client export");
        let server_out = tokio::time::timeout(Duration::from_secs(10), rx)
            .await
            .expect("server export timed out")
            .unwrap();
        assert_eq!(client_out, server_out);
    }

    #[test]
    fn insert_extension_roundtrip_and_replacement() {
        // The transport parameters ride extension 0x39: insertion keeps
        // the message parseable, keeps the session id in place, and a
        // second insertion replaces instead of duplicating.
        let (secret, public) = engine_tls13::x25519_keygen();
        let hello = profiles::build_client_hello_alpn(
            UtslProfile::Chrome,
            "example.test",
            &[7u8; 32],
            &[9u8; 32],
            &public,
            Some(&["h3".to_string()]),
        );
        let with_tp = insert_extension(&hello, EXT_TRANSPORT_PARAMETERS, b"params-here").unwrap();
        assert_eq!(
            &with_tp[profiles::SESSION_ID_OFFSET..profiles::SESSION_ID_OFFSET + 32],
            &[9u8; 32]
        );
        let off = hello_ext_block_offset(&with_tp).unwrap();
        let exts = extensions(&with_tp[off..]).unwrap();
        assert_eq!(exts.iter().filter(|(t, _)| *t == EXT_TRANSPORT_PARAMETERS).count(), 1);
        assert_eq!(
            exts.iter()
                .find(|(t, _)| *t == EXT_TRANSPORT_PARAMETERS)
                .map(|(_, b)| b.to_vec()),
            Some(b"params-here".to_vec())
        );
        // Replacement, not duplication.
        let replaced =
            insert_extension(&with_tp, EXT_TRANSPORT_PARAMETERS, b"other").unwrap();
        let off = hello_ext_block_offset(&replaced).unwrap();
        let exts = extensions(&replaced[off..]).unwrap();
        assert_eq!(exts.iter().filter(|(t, _)| *t == EXT_TRANSPORT_PARAMETERS).count(), 1);
        assert_eq!(
            exts.iter()
                .find(|(t, _)| *t == EXT_TRANSPORT_PARAMETERS)
                .map(|(_, b)| b.to_vec()),
            Some(b"other".to_vec())
        );
        let _ = secret;
    }

    #[test]
    fn ech_retry_configs_of_roundtrip() {
        use base64::Engine as _;
        let list = vec![1u8, 2, 3, 4, 5];
        let reason = format!(
            "{ERR_ECH_REJECTED}; retry-configs={}",
            base64::engine::general_purpose::STANDARD.encode(&list)
        );
        assert_eq!(ech_retry_configs_of(&reason).as_deref(), Some(&list[..]));
        assert!(ech_retry_configs_of(ERR_ECH_REJECTED).is_none());
        assert!(ech_retry_configs_of("unrelated").is_none());
    }

    #[tokio::test]
    async fn ech_accepted_full_quic_handshake_and_stream_relay() {
        // Task 3: an ECH-terminating quinn server (HPKE-open of the
        // outer payload, accept confirmation in the ServerHello random —
        // the QUIC form of the wave-8 tls13 test server's accept_ech).
        let (sk_r, list) = test_server::ech_server_key(&[7u8; 32], 0x42, b"public.example");
        let endpoint = test_server::start_quinn_server(ServerMode::EchAccept {
            sk_r,
            config_list: list.clone(),
        })
        .await
        .unwrap();
        let addr = endpoint.local_addr().unwrap();
        tokio::spawn(echo_serve(endpoint.clone()));

        let cfg = dial_cfg(addr.port(), "inner.example", &["h3"]);
        let selection = ech::select_ech_config(&list).unwrap();
        let conn = tokio::time::timeout(
            Duration::from_secs(15),
            crate::quic::dial_custom(&cfg, &QuicTlsCover::Ech(selection)),
        )
        .await
        .expect("ech connect timed out")
        .expect("ech handshake failed");

        let data = conn
            .handshake_data()
            .expect("handshake data")
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .expect("rustls HandshakeData type");
        assert_eq!(data.protocol.as_deref(), Some(&b"h3"[..]));

        let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
        send.write_all(b"ech over quic").await.unwrap();
        let mut buf = [0u8; 13];
        recv.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ech over quic");
    }

    #[tokio::test]
    async fn ech_rejected_is_the_upstream_error_with_retry_configs() {
        // A server that completes the handshake against the OUTER hello:
        // the client surfaces the upstream rejection sentinel and the
        // retry ECHConfigList rides the error text.
        let (_sk_r, other_list) =
            test_server::ech_server_key(&[9u8; 32], 0x07, b"other-public.example");
        let endpoint = test_server::start_quinn_server(ServerMode::EchReject {
            retry_configs: Some(other_list.clone()),
        })
        .await
        .unwrap();
        let addr = endpoint.local_addr().unwrap();
        // quinn drives server handshakes through accept(); the rejected
        // client aborts right after, so draining suffices.
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let _ = incoming.await;
            }
        });

        let cfg = dial_cfg(addr.port(), "inner.example", &["h3"]);
        // The client offers an unrelated config: the server cannot open
        // it, so the handshake completes in outer mode → rejection.
        let (_client_sk, client_list) =
            test_server::ech_server_key(&[3u8; 32], 0x11, b"client-public.example");
        let selection = ech::select_ech_config(&client_list).unwrap();
        let err = crate::quic::dial_custom(&cfg, &QuicTlsCover::Ech(selection))
            .await
            .expect_err("ech rejection must fail the dial");
        let text = err.to_string();
        assert!(text.contains(ERR_ECH_REJECTED), "{text}");
        let retry = ech_retry_configs_of(&text).expect("retry configs ride the error");
        assert_eq!(retry, other_list);
        assert!(ech::select_ech_config(&retry).is_ok());
    }

    #[tokio::test]
    async fn ech_dial_retries_once_with_the_servers_retry_configs() {
        // `quic::dial_ech`: rejection #1 carries the server's real
        // ECHConfigList; the redial with it terminates ECH.
        let (sk_r, list) = test_server::ech_server_key(&[5u8; 32], 0x33, b"retry.example");
        let endpoint = test_server::start_quinn_server(ServerMode::EchRetryOnce {
            sk_r,
            config_list: list.clone(),
            seen: std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        })
        .await
        .unwrap();
        let addr = endpoint.local_addr().unwrap();
        tokio::spawn(echo_serve(endpoint.clone()));

        // First offer a config the server does NOT hold; its retry list
        // names the real one.
        let (_other_sk, other) =
            test_server::ech_server_key(&[4u8; 32], 0x21, b"unrelated.example");
        let wrong = ech::select_ech_config(&other).unwrap();
        let cfg = dial_cfg(addr.port(), "inner.example", &["h3"]);
        let conn = tokio::time::timeout(
            Duration::from_secs(20),
            crate::quic::dial_ech(&cfg, wrong),
        )
        .await
        .expect("ech retry dial timed out")
        .expect("ech retry dial failed");

        let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
        send.write_all(b"after retry").await.unwrap();
        let mut buf = vec![0u8; b"after retry".len()];
        recv.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, b"after retry");
    }

    #[tokio::test]
    async fn jls_cover_handshake_and_wrong_credentials_rejection() {
        // Task 2 at the crypto layer: the cover handshake authenticates
        // through the randoms; wrong credentials are the upstream
        // jls auth error.
        let user = jls::JlsUser::new("quic-user", "quic-pass").unwrap();
        let endpoint =
            test_server::start_quinn_server(ServerMode::Jls { users: vec![user.clone()] })
                .await
                .unwrap();
        let addr = endpoint.local_addr().unwrap();
        tokio::spawn(echo_serve(endpoint.clone()));

        let cfg = dial_cfg(addr.port(), "sq.test", &["h3"]);
        let conn = tokio::time::timeout(
            Duration::from_secs(15),
            crate::quic::dial_custom(&cfg, &QuicTlsCover::Jls(user.clone())),
        )
        .await
        .expect("jls connect timed out")
        .expect("jls handshake failed");
        let (mut send, mut recv) = conn.open_bi().await.expect("open_bi");
        send.write_all(b"jls quic").await.unwrap();
        let mut buf = [0u8; 8];
        recv.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"jls quic");

        // Wrong password: the ServerHello random does not verify.
        let wrong = jls::JlsUser::new("quic-user", "wrong").unwrap();
        let err = crate::quic::dial_custom(&cfg, &QuicTlsCover::Jls(wrong))
            .await
            .expect_err("wrong password must not authenticate");
        assert!(
            err.to_string().contains(jls::ERR_AUTH_FAILED),
            "{}",
            err
        );
    }
}
