//! TLSMirror client (mihomo `transport/tlsmirror`): a hidden channel
//! multiplexed into a real TLS session's record stream. The carrier is
//! a genuine TLS client (rustls, driven manually so every record
//! passes through the mirror); the hidden connection *inserts* extra
//! `application_data` records into the outbound flow and *intercepts*
//! the peer's records, extracting the ones that decrypt under the
//! primary-key-derived AEAD.
//!
//! ## Upstream map
//!
//! * `adapter/outbound/vmess.go` + `transport/vmess/tls.go:92` — the
//!   only consumer: `tlsmirror-opts` on a TLS vmess outbound.
//! * `transport/tlsmirror/client.go` `Dial` — client entry: mirror the
//!   carrier TLS pipe against the raw transport, run the embedded
//!   traffic generator over the carrier, verify connection enrolment.
//! * `transport/tlsmirror/conn.go` — the hidden `Conn`: per-record
//!   XOR-nonce AES-128-GCM (8-byte LE counter nonce from all-ones),
//!   defer-instance-derived first-write, transport-layer padding,
//!   sequence watermarking (raw ChaCha20 over the last 16 bytes of
//!   every app-data/alert record once armed).
//! * `transport/tlsmirror/crypto.go` — HKDF-SHA256 key material from
//!   `primaryKey ‖ clientRandom ‖ serverRandom` under the
//!   `"v2ray-…:tlsmirror-…"` labels; the 8-byte explicit-nonce prefix
//!   for TLS 1.2 AEAD suites (BE counter per direction).
//! * `transport/tlsmirror/mirror.go` — the record pump: capture the
//!   ClientHello/ServerHello randoms, suite-based explicit-nonce
//!   overhead, per-direction insert queues, c2s readiness after the
//!   carrier's first app-data record (the TLS 1.3 Finished), fallback
//!   passthrough when interception fails.
//! * `transport/tlsmirror/record.go` — record framing + the handshake
//!   random/cipher-suite parsers.
//! * `transport/tlsmirror/padding.go` — `payload ‖ pad ‖ len_be32`.
//! * `transport/tlsmirror/traffic.go` — the embedded HTTP traffic
//!   generator with weighted step transitions (HTTP/1.1 here; see
//!   below for h2).
//! * `transport/tlsmirror/enrollment.go` — connection enrolment /
//!   loopback protection (scoped out; see `connect`).
//!
//! ## Wire-visible vs config-carried
//!
//! * Wire-visible: the inserted records (optional 8-byte explicit
//!   nonce + GCM-sealed payload, optionally length-suffixed padding),
//!   the 16-byte ChaCha20 watermark over app-data/alert records, and
//!   the carrier HTTP/1.1 requests the generator issues.
//! * Config-carried: `connection-enrolment` needs the engine's proxy
//!   dialer plus an h2 enrolment control connection — enabling it is
//!   config-rejected precisely. Generator steps over an `h2` carrier
//!   are rejected precisely (no HTTP/2 client in-tree); `http/1.1`
//!   and no-ALPN carriers are implemented.
//! * `client-fingerprint` (uTLS), `fingerprint` (server-cert pinning)
//!   and client certificates are carried but not applied: the plain
//!   rustls hello with standard verification is offered, like the
//!   rest of this crate's TLS transports.
//! * The carrier offers rustls' safe default versions (TLS 1.3 + 1.2);
//!   the explicit-nonce path engages exactly when the negotiated
//!   suite is in the configured list (the TLS 1.2 AEAD case).

use std::io;
use std::io::{Read as _, Write as _};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Buf, BytesMut};
use hkdf::Hkdf;
use rand::{Rng, RngCore};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{ring as ring_provider, CryptoProvider};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::debug;

use crate::error::{Error, Result};
use crate::stream::BoxProxyStream;

/// `record.go recordType*`.
const REC_CCS: u8 = 20;
const REC_ALERT: u8 = 21;
const REC_HANDSHAKE: u8 = 22;
const REC_APP_DATA: u8 = 23;
/// `maxTLSRecordPayload` (record.go:15).
const MAX_RECORD_PAYLOAD: usize = 16384;
const RECORD_HEADER_LEN: usize = 5;

/// `RecommendedExplicitNonceCipherSuites` (config.go:36).
pub const RECOMMENDED_EXPLICIT_NONCE_CIPHER_SUITES: &[u16] = &[
    156, 157, 158, 159, 160, 161, 162, 163, 164, 165, 166, 167, 168, 169, 170, 171, 172, 173,
    49195, 49196, 49197, 49198, 49199, 49200, 49201, 49202, 49290, 49291, 49293, 49316, 49317,
    49318, 49319, 49320, 49321, 49322, 49323, 49324, 49325, 49326, 49327, 52392, 52393, 52394,
    52395, 52396, 52397, 52398,
];

// ---------------------------------------------------------------------------
// Config (adapter/outbound TLSMirrorOptions → transport Config)
// ---------------------------------------------------------------------------

/// `TLSMirrorTimeSpec` / `TimeSpec.Duration()` (config.go:94).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TimeSpec {
    pub base_nanoseconds: u64,
    pub uniform_random_multiplier_nanoseconds: u64,
}

impl TimeSpec {
    fn duration(&self) -> Duration {
        let mut delay = self.base_nanoseconds;
        if self.uniform_random_multiplier_nanoseconds > 0 {
            delay += rand::rngs::OsRng.gen_range(0..self.uniform_random_multiplier_nanoseconds);
        }
        Duration::from_nanos(delay)
    }
}

/// `TrafficTransferCandidate` (config.go:117).
#[derive(Debug, Clone)]
pub struct TrafficTransferCandidate {
    pub weight: i32,
    pub goto_location: i32,
}

/// `TrafficStep` (config.go:70).
#[derive(Debug, Clone)]
pub struct TrafficStep {
    pub name: String,
    pub host: String,
    pub path: String,
    pub method: String,
    /// (name, value) pairs — the YAML `value` and each of `values`.
    pub headers: Vec<(String, String)>,
    pub next_step: Vec<TrafficTransferCandidate>,
    pub connection_ready: bool,
    pub connection_recall_exit: bool,
    pub wait_time: TimeSpec,
    pub h2_do_not_wait_for_download_finish: bool,
}

/// Outbound TLSMirror endpoint — the `tlsmirror-opts` fields plus the
/// carrier TLS knobs vmess passes in (`TLSMirrorOptions.Build` +
/// `tlsmirror.ClientConfig`).
#[derive(Debug, Clone)]
pub struct TlsMirrorOut {
    /// `primary-key` — standard base64, 32 bytes.
    pub primary_key: String,
    /// `explicit-nonce-ciphersuites`.
    pub explicit_nonce_cipher_suites: Vec<u16>,
    /// `defer-instance-derived-write-time`.
    pub defer_instance_derived_write: TimeSpec,
    /// `transport-layer-padding.enabled`.
    pub transport_layer_padding: bool,
    /// `connection-enrolment` (`primary-ingress-outbound`,
    /// `primary-egress-outbound`) — carried; enabling it is rejected.
    pub connection_enrolment: Option<(String, String)>,
    /// `embedded-traffic-generator.steps`.
    pub traffic_generator: Vec<TrafficStep>,
    /// `sequence-watermarking-enabled`.
    pub sequence_watermarking_enabled: bool,
    /// Carrier TLS: server name, verification, ALPN.
    pub server_name: String,
    pub skip_cert_verify: bool,
    pub alpn: Vec<String>,
    /// `client-fingerprint` / `fingerprint` / client cert — carried,
    /// not applied (plain rustls hello, standard verification).
    pub client_fingerprint: String,
    pub fingerprint: String,
    pub certificate: String,
    pub private_key: String,
}

impl TlsMirrorOut {
    pub fn new(primary_key: &str, server_name: &str) -> Self {
        TlsMirrorOut {
            primary_key: primary_key.to_string(),
            explicit_nonce_cipher_suites: Vec::new(),
            defer_instance_derived_write: TimeSpec::default(),
            transport_layer_padding: false,
            connection_enrolment: None,
            traffic_generator: Vec::new(),
            sequence_watermarking_enabled: false,
            server_name: server_name.to_string(),
            skip_cert_verify: true,
            alpn: Vec::new(),
            client_fingerprint: String::new(),
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        }
    }
}

/// `DecodePrimaryKey` (config.go:121).
fn decode_primary_key(value: &str) -> Result<[u8; 32]> {
    use base64::Engine;
    if value.is_empty() {
        return Err(Error::config("tlsmirror: missing tlsmirror primary key"));
    }
    let key = base64::engine::general_purpose::STANDARD
        .decode(value)
        .map_err(|_| {
            Error::config("tlsmirror: primary key must be standard base64 and decode to 32 bytes")
        })?;
    if key.len() == 32 {
        return Ok(key[..32].try_into().expect("32 bytes"));
    }
    Err(Error::config(
        "tlsmirror: primary key must be standard base64 and decode to 32 bytes",
    ))
}

/// `GeneratePrimaryKey` (config.go:115) — for configs/tests.
pub fn generate_primary_key() -> String {
    use base64::Engine;
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    base64::engine::general_purpose::STANDARD.encode(key)
}

// ---------------------------------------------------------------------------
// Raw ChaCha20 (RFC 8439) — the sequence-watermark stream cipher
// (crypto.go uses x/crypto/chacha20's unauthenticated cipher).
// ---------------------------------------------------------------------------

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    fn quarter(s: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        s[a] = s[a].wrapping_add(s[b]);
        s[d] ^= s[a];
        s[d] = s[d].rotate_left(16);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] ^= s[c];
        s[b] = s[b].rotate_left(12);
        s[a] = s[a].wrapping_add(s[b]);
        s[d] ^= s[a];
        s[d] = s[d].rotate_left(8);
        s[c] = s[c].wrapping_add(s[d]);
        s[b] ^= s[c];
        s[b] = s[b].rotate_left(7);
    }
    let mut state = [0u32; 16];
    state[..4].copy_from_slice(&[0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]);
    for (i, w) in key.chunks(4).enumerate() {
        state[4 + i] = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
    }
    state[12] = counter;
    for (i, w) in nonce.chunks(4).enumerate() {
        state[13 + i] = u32::from_le_bytes([w[0], w[1], w[2], w[3]]);
    }
    let mut working = state;
    for _ in 0..10 {
        quarter(&mut working, 0, 4, 8, 12);
        quarter(&mut working, 1, 5, 9, 13);
        quarter(&mut working, 2, 6, 10, 14);
        quarter(&mut working, 3, 7, 11, 15);
        quarter(&mut working, 0, 5, 10, 15);
        quarter(&mut working, 1, 6, 11, 12);
        quarter(&mut working, 2, 7, 8, 13);
        quarter(&mut working, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        out[i * 4..i * 4 + 4].copy_from_slice(&working[i].wrapping_add(state[i]).to_le_bytes());
    }
    out
}

/// A ChaCha20 keystream XOR.
struct ChaCha20Stream {
    key: [u8; 32],
    nonce: [u8; 12],
    counter: u32,
    block: Vec<u8>,
    offset: usize,
}

impl ChaCha20Stream {
    fn new(key: &[u8; 32], nonce: &[u8; 12]) -> Self {
        ChaCha20Stream {
            key: *key,
            nonce: *nonce,
            counter: 0,
            block: Vec::new(),
            offset: 0,
        }
    }

    fn xor(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            if self.offset >= self.block.len() {
                self.block = chacha20_block(&self.key, self.counter, &self.nonce).to_vec();
                self.counter = self.counter.wrapping_add(1);
                self.offset = 0;
            }
            *b ^= self.block[self.offset];
            self.offset += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// Nonce generators + the XOR-nonce AEAD (crypto.go)
// ---------------------------------------------------------------------------

/// `nonceGenerator` (crypto.go:108): LE counter starting from all-ones.
#[derive(Debug, Clone)]
struct NonceGenerator {
    next: [u8; 8],
}

impl NonceGenerator {
    fn new() -> Self {
        NonceGenerator { next: [0xff; 8] }
    }

    fn next(&mut self) -> [u8; 8] {
        for b in self.next.iter_mut() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
        self.next
    }
}

/// `explicitNonceGenerator` (crypto.go:126): BE counter from zero.
#[derive(Debug, Clone)]
struct ExplicitNonceGenerator {
    next: [u8; 8],
}

impl ExplicitNonceGenerator {
    fn new() -> Self {
        ExplicitNonceGenerator { next: [0u8; 8] }
    }

    fn next(&mut self) -> [u8; 8] {
        for b in self.next.iter_mut().rev() {
            *b = b.wrapping_add(1);
            if *b != 0 {
                break;
            }
        }
        self.next
    }
}

/// `xorNonceAEAD` (crypto.go:14): AES-128-GCM under the 12-byte nonce
/// `mask[0..4] ‖ (mask[4..12] ⊕ nonce8)`.
struct XorNonceAead {
    aead: crate::proto::aead::Aead,
    mask: [u8; 12],
}

impl XorNonceAead {
    fn new(key: &[u8; 16], nonce_mask: &[u8; 12]) -> Result<Self> {
        Ok(XorNonceAead {
            aead: crate::proto::aead::Aead::new(crate::proto::aead::AeadKind::Aes128Gcm, key)?,
            mask: *nonce_mask,
        })
    }

    fn full_nonce(&self, nonce8: &[u8; 8]) -> [u8; 12] {
        let mut n = self.mask;
        for i in 0..8 {
            n[4 + i] ^= nonce8[i];
        }
        n
    }

    fn seal(&self, nonce8: &[u8; 8], plain: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(plain.len() + 16);
        let nonce = self.full_nonce(nonce8);
        self.aead.seal(&nonce, b"", plain, &mut out)?;
        Ok(out)
    }

    fn open(&self, nonce8: &[u8; 8], ct: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.full_nonce(nonce8);
        self.aead.open(&nonce, b"", ct)
    }
}

/// `deriveEncryptionKey` (crypto.go:60).
fn derive_encryption_key(
    primary_key: &[u8; 32],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    tag: &str,
) -> Result<([u8; 16], [u8; 12])> {
    let mut combined = Vec::with_capacity(96);
    combined.extend_from_slice(primary_key);
    combined.extend_from_slice(client_random);
    combined.extend_from_slice(server_random);
    let hk = Hkdf::<Sha256>::from_prk(&Sha256::digest(&combined))
        .map_err(|_| Error::crypto("tlsmirror: prk"))?;
    let mut key = [0u8; 16];
    hk.expand(
        format!("v2ray-sp76YMKM-EkGrFUNL-rTJRJMkU:tlsmirror-encryption{tag}").as_bytes(),
        &mut key,
    )
    .map_err(|_| Error::crypto("tlsmirror: hkdf expand encryption"))?;
    let mut mask = [0u8; 12];
    hk.expand(
        format!("v2ray-sp76YMKM-EkGrFUNL-rTJRJMkU:tlsmirror-noncemask{tag}").as_bytes(),
        &mut mask,
    )
    .map_err(|_| Error::crypto("tlsmirror: hkdf expand noncemask"))?;
    Ok((key, mask))
}

/// `deriveSequenceWatermarkingKey` (crypto.go:80).
fn derive_sequence_watermark(
    primary_key: &[u8; 32],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
    tag: &str,
) -> Result<([u8; 32], [u8; 12])> {
    let mut combined = Vec::with_capacity(96);
    combined.extend_from_slice(primary_key);
    combined.extend_from_slice(client_random);
    combined.extend_from_slice(server_random);
    let hk = Hkdf::<Sha256>::from_prk(&Sha256::digest(&combined))
        .map_err(|_| Error::crypto("tlsmirror: prk"))?;
    let mut key = [0u8; 32];
    hk.expand(
        format!(
            "v2ray-xv64FXUU-GxMn8UYz-bTy6UDeE:tlsmirror-sequence-watermark-encryption{tag}"
        )
        .as_bytes(),
        &mut key,
    )
    .map_err(|_| Error::crypto("tlsmirror: hkdf expand watermark key"))?;
    let mut nonce = [0u8; 12];
    hk.expand(
        format!(
            "v2ray-xv64FXUU-GxMn8UYz-bTy6UDeE:tlsmirror-sequence-watermark-noncemask{tag}"
        )
        .as_bytes(),
        &mut nonce,
    )
    .map_err(|_| Error::crypto("tlsmirror: hkdf expand watermark nonce"))?;
    Ok((key, nonce))
}

// ---------------------------------------------------------------------------
// Record helpers (record.go)
// ---------------------------------------------------------------------------

/// `parseClientRandom` (record.go:151).
fn parse_client_random(fragment: &[u8]) -> Option<[u8; 32]> {
    if fragment.len() < 38 || fragment[0] != 1 {
        return None;
    }
    fragment[6..38].try_into().ok()
}

/// `parseServerHello` (record.go:158): random + negotiated suite.
fn parse_server_hello(fragment: &[u8]) -> Option<([u8; 32], u16)> {
    if fragment.len() < 41 || fragment[0] != 2 {
        return None;
    }
    let random: [u8; 32] = fragment[6..38].try_into().ok()?;
    let session_id_len = fragment[38] as usize;
    let off = 39 + session_id_len;
    if fragment.len() < off + 2 {
        return None;
    }
    let suite = u16::from_be_bytes([fragment[off], fragment[off + 1]]);
    Some((random, suite))
}

/// `packPadding` (padding.go:4).
fn pack_padding(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len() + 4);
    out.extend_from_slice(data);
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out
}

/// `unpackPadding` (padding.go:10); `None` = not valid padding.
fn unpack_padding(data: &[u8]) -> Option<&[u8]> {
    if data.len() < 4 {
        return None;
    }
    let n = data.len();
    let payload_len = u32::from_be_bytes([data[n - 4], data[n - 3], data[n - 2], data[n - 1]]) as usize;
    if payload_len > n - 4 {
        return None;
    }
    Some(&data[..payload_len])
}

// ---------------------------------------------------------------------------
// The mirror state (conn.go + mirror.go)
// ---------------------------------------------------------------------------

/// The per-connection hidden-protocol state.
struct Mirror {
    primary_key: [u8; 32],
    explicit_suites: Vec<u16>,
    padding: bool,
    watermarking: bool,
    client_random: Option<[u8; 32]>,
    server_random: Option<[u8; 32]>,
    tls12_explicit: bool,
    encryptor: Option<XorNonceAead>,
    encryptor_nonce: NonceGenerator,
    decryptor: Option<XorNonceAead>,
    decryptor_nonce: NonceGenerator,
    decryptor_next: Option<[u8; 8]>,
    watermark_tx: Option<ChaCha20Stream>,
    watermark_rx: Option<ChaCha20Stream>,
    c2s_explicit: ExplicitNonceGenerator,
    s2c_explicit: ExplicitNonceGenerator,
    /// The in-test server mimic flips every direction tag (conn.go
    /// `isServer`).
    server_side: bool,
}

impl Mirror {
    fn new(cfg: &TlsMirrorOut, primary_key: [u8; 32], server_side: bool) -> Self {
        Mirror {
            primary_key,
            explicit_suites: cfg.explicit_nonce_cipher_suites.clone(),
            padding: cfg.transport_layer_padding,
            watermarking: cfg.sequence_watermarking_enabled,
            client_random: None,
            server_random: None,
            tls12_explicit: false,
            encryptor: None,
            encryptor_nonce: NonceGenerator::new(),
            decryptor: None,
            decryptor_nonce: NonceGenerator::new(),
            decryptor_next: None,
            watermark_tx: None,
            watermark_rx: None,
            c2s_explicit: ExplicitNonceGenerator::new(),
            s2c_explicit: ExplicitNonceGenerator::new(),
            server_side,
        }
    }

    fn encrypt_tag(&self) -> &'static str {
        if self.server_side {
            ":s2c"
        } else {
            ":c2s"
        }
    }

    fn decrypt_tag(&self) -> &'static str {
        if self.server_side {
            ":c2s"
        } else {
            ":s2c"
        }
    }

    /// `explicitNonceOverhead` (mirror.go:104).
    fn overhead(&self) -> usize {
        if self.tls12_explicit {
            8
        } else {
            0
        }
    }

    /// `ensureCryptoLocked` (conn.go:69).
    fn ensure_crypto(&mut self) -> Result<()> {
        if self.encryptor.is_some() && self.decryptor.is_some() {
            return Ok(());
        }
        let (cr, sr) = match (self.client_random, self.server_random) {
            (Some(cr), Some(sr)) => (cr, sr),
            _ => return Err(Error::protocol("tlsmirror: handshake random is not ready")),
        };
        let (enc_key, enc_mask) = derive_encryption_key(&self.primary_key, &cr, &sr, self.encrypt_tag())?;
        let (dec_key, dec_mask) = derive_encryption_key(&self.primary_key, &cr, &sr, self.decrypt_tag())?;
        self.encryptor = Some(XorNonceAead::new(&enc_key, &enc_mask)?);
        self.decryptor = Some(XorNonceAead::new(&dec_key, &dec_mask)?);
        Ok(())
    }

    /// `applySequenceWatermarkRx` (conn.go:362): the last 16 bytes of
    /// every inbound app/alert record, once armed.
    fn apply_watermark_rx(&mut self, fragment: &mut [u8], rec_type: u8) {
        if !self.watermarking {
            return;
        }
        if rec_type != REC_APP_DATA && rec_type != REC_ALERT {
            return;
        }
        let len = fragment.len();
        if len < 16 {
            return;
        }
        if let Some(stream) = self.watermark_rx.as_mut() {
            stream.xor(&mut fragment[len - 16..]);
        }
    }

    /// `handleOutboundRecordTx` (conn.go:377): watermark every outbound
    /// app/alert record once armed; the first *inserted* record arms it
    /// (after itself — the first inserted record is not watermarked).
    fn apply_watermark_tx(&mut self, fragment: &mut [u8], rec_type: u8, inserted: bool) {
        if !self.watermarking {
            return;
        }
        if (rec_type == REC_APP_DATA || rec_type == REC_ALERT) && fragment.len() >= 16 {
            if let Some(stream) = self.watermark_tx.as_mut() {
                let len = fragment.len();
                stream.xor(&mut fragment[len - 16..]);
            }
        }
        if inserted && self.watermark_tx.is_none() {
            // `initSequenceWatermarkTx` (conn.go:395).
            if let (Some(cr), Some(sr)) = (self.client_random, self.server_random) {
                if let Ok((key, nonce)) =
                    derive_sequence_watermark(&self.primary_key, &cr, &sr, self.encrypt_tag())
                {
                    self.watermark_tx = Some(ChaCha20Stream::new(&key, &nonce));
                }
            }
        }
    }

    /// `initSequenceWatermarkRx` (conn.go:408), after the first hidden
    /// record decrypts.
    fn init_watermark_rx(&mut self) {
        if !self.watermarking || self.watermark_rx.is_some() {
            return;
        }
        if let (Some(cr), Some(sr)) = (self.client_random, self.server_random) {
            if let Ok((key, nonce)) =
                derive_sequence_watermark(&self.primary_key, &cr, &sr, self.decrypt_tag())
            {
                self.watermark_rx = Some(ChaCha20Stream::new(&key, &nonce));
            }
        }
    }

    /// `handleInboundRecord` (conn.go:108): `Some(payload)` when the
    /// record carried hidden data (empty payload = padding garbage).
    fn handle_inbound_record(&mut self, fragment: &[u8], rec_type: u8) -> Option<Vec<u8>> {
        if rec_type != REC_APP_DATA {
            return None;
        }
        if self.ensure_crypto().is_err() {
            return None;
        }
        let overhead = self.overhead();
        let decryptor = self.decryptor.as_ref()?;
        if fragment.len() < overhead + 8 {
            return None;
        }
        // `decryptor.Open` (crypto.go:179): peek the next counter
        // nonce and RETRY it across failed opens — the generator only
        // advances once the record actually decrypts.
        let nonce8 = match self.decryptor_next {
            Some(n) => n,
            None => self.decryptor_nonce.next(),
        };
        let plain = match decryptor.open(&nonce8, &fragment[overhead..]) {
            Ok(p) => p,
            Err(_) => {
                self.decryptor_next = Some(nonce8);
                return None;
            }
        };
        self.decryptor_next = None;
        self.init_watermark_rx();
        if self.padding {
            match unpack_padding(&plain) {
                Some(p) => Some(p.to_vec()),
                None => Some(Vec::new()),
            }
        } else {
            Some(plain)
        }
    }

    /// `Conn.Write` (conn.go:170) for one plaintext chunk → the sealed
    /// fragment (before the record header). Returns the plaintext
    /// bytes consumed (the record-size cap).
    fn build_inserted_record(&mut self, plain: &[u8], c2s: bool) -> Result<(Vec<u8>, usize)> {
        self.ensure_crypto()?;
        let encryptor = self
            .encryptor
            .as_ref()
            .ok_or_else(|| Error::protocol("tlsmirror: handshake random is not ready"))?;
        let overhead = self.overhead();
        let max_plain = MAX_RECORD_PAYLOAD - overhead - 16 - if self.padding { 4 } else { 0 };
        let take = plain.len().min(max_plain);
        let body_plain = if self.padding { pack_padding(&plain[..take]) } else { plain[..take].to_vec() };
        let nonce8 = self.encryptor_nonce.next();
        let sealed = encryptor.seal(&nonce8, &body_plain)?;
        let mut fragment = Vec::with_capacity(overhead + sealed.len());
        if overhead > 0 {
            // `fillExplicitNonce` (mirror.go:461): the per-direction BE
            // counter of the writer emitting the record.
            let nonce = if c2s {
                self.c2s_explicit.next()
            } else {
                self.s2c_explicit.next()
            };
            fragment.extend_from_slice(&nonce);
        }
        fragment.extend_from_slice(&sealed);
        Ok((fragment, take))
    }
}

// ---------------------------------------------------------------------------
// The hidden stream (conn.go Conn)
// ---------------------------------------------------------------------------

pub struct TlsMirrorStream {
    hidden_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    insert_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    recall: Arc<tokio::sync::Notify>,
    pending: BytesMut,
    closed: bool,
    alive: Arc<std::sync::atomic::AtomicBool>,
}

impl AsyncRead for TlsMirrorStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if !self.pending.is_empty() {
                let n = self.pending.len().min(buf.remaining());
                buf.put_slice(&self.pending[..n]);
                self.pending.advance(n);
                return Poll::Ready(Ok(()));
            }
            match self.hidden_rx.poll_recv(cx) {
                Poll::Ready(Some(data)) => {
                    if data.is_empty() {
                        continue;
                    }
                    if data.len() > buf.remaining() {
                        let take = buf.remaining();
                        buf.put_slice(&data[..take]);
                        self.pending.extend_from_slice(&data[take..]);
                    } else {
                        buf.put_slice(&data);
                    }
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(None) => return Poll::Ready(Ok(())),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for TlsMirrorStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.closed || !self.alive.load(std::sync::atomic::Ordering::SeqCst) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "tlsmirror: connection closed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Readiness and the first-write defer are enforced in the pump
        // (`waitWriteReady` + `firstWriteDelay`, conn.go:170-195): a
        // write that races the carrier handshake is held until the
        // carrier's first app-data record.
        match self.insert_tx.send(buf.to_vec()) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "tlsmirror: mirror closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // `Conn.Close` (conn.go:289): recall the traffic generator and
        // tear the mirror down.
        self.closed = true;
        self.recall.notify_waiters();
        Poll::Ready(Ok(()))
    }
}

/// The carrier engine: drives rustls and the mirror over the raw
/// transport (mirror.go's two workers + record writers).
#[allow(clippy::too_many_arguments)]
async fn pump(
    mut transport: BoxProxyStream,
    mut tls: ClientConnection,
    mut mirror: Mirror,
    mut insert_rx: tokio::sync::mpsc::UnboundedReceiver<Vec<u8>>,
    hidden_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    mut carrier: Option<tokio::io::DuplexStream>,
    ready: Arc<std::sync::atomic::AtomicBool>,
    ready_notify: Arc<tokio::sync::Notify>,
    defer_write: Duration,
    mut carrier_ready: Option<tokio::sync::oneshot::Sender<()>>,
) {
    let mut rbuf = BytesMut::with_capacity(16 * 1024);
    let mut first_flight = true;
    let mut first_inbound = true;
    let mut ccs_was_last = false;
    let mut first_insert = defer_write;
    let mut pending_inserts = std::collections::VecDeque::new();
    let mut announced_handshake = false;
    let version_hint: [u8; 2] = [0x03, 0x03];
    let mut tmp = [0u8; 16 * 1024];
    loop {
        // ---- outbound rustls flights ----
        while tls.wants_write() {
            let mut flight = Vec::new();
            while tls.wants_write() {
                if tls.write_tls(&mut flight).unwrap_or(0) == 0 {
                    break;
                }
            }
            let mut off = 0usize;
            while off + RECORD_HEADER_LEN <= flight.len() {
                let rlen = u16::from_be_bytes([flight[off + 3], flight[off + 4]]) as usize;
                let end = off + RECORD_HEADER_LEN + rlen;
                if end > flight.len() {
                    break;
                }
                let mut record = flight[off..end].to_vec();
                let rec_type = record[0];
                if first_flight && rec_type == REC_HANDSHAKE {
                    if let Some(random) = parse_client_random(&record[RECORD_HEADER_LEN..]) {
                        mirror.client_random = Some(random);
                    }
                    first_flight = false;
                }
                let is_ccs = rec_type == REC_CCS;
                if rec_type == REC_APP_DATA && !ready.load(std::sync::atomic::Ordering::SeqCst) {
                    // c2sReady (mirror.go:215): the carrier's first
                    // app-data record — the TLS 1.3 Finished.
                    ready.store(true, std::sync::atomic::Ordering::SeqCst);
                    ready_notify.notify_waiters();
                }
                if rec_type == REC_HANDSHAKE
                    && ccs_was_last
                    && !ready.load(std::sync::atomic::Ordering::SeqCst)
                {
                    // The TLS 1.2 Finished after the CCS also readies
                    // the direction (mirror.go:185-219).
                    ready.store(true, std::sync::atomic::Ordering::SeqCst);
                    ready_notify.notify_waiters();
                }
                ccs_was_last = is_ccs && mirror.tls12_explicit;
                mirror.apply_watermark_tx(&mut record[RECORD_HEADER_LEN..], rec_type, false);
                if transport.write_all(&record).await.is_err() {
                    return;
                }
                off = end;
            }
            if off < flight.len() && transport.write_all(&flight[off..]).await.is_err() {
                return;
            }
        }
        if !tls.is_handshaking() && !announced_handshake {
            announced_handshake = true;
            if let Some(tx) = carrier_ready.take() {
                let _ = tx.send(());
            }
        }

        // ---- inbound records ----
        loop {
            if rbuf.len() < RECORD_HEADER_LEN {
                break;
            }
            let rlen = u16::from_be_bytes([rbuf[3], rbuf[4]]) as usize;
            if rbuf.len() < RECORD_HEADER_LEN + rlen {
                break;
            }
            let mut record = rbuf.split_to(RECORD_HEADER_LEN + rlen).to_vec();
            let rec_type = record[0];
            if first_inbound && rec_type == REC_HANDSHAKE {
                if let Some((random, suite)) = parse_server_hello(&record[RECORD_HEADER_LEN..]) {
                    mirror.server_random = Some(random);
                    mirror.tls12_explicit = mirror.explicit_suites.contains(&suite);
                }
                first_inbound = false;
            }
            mirror.apply_watermark_rx(&mut record[RECORD_HEADER_LEN..], rec_type);
            if let Some(payload) = mirror.handle_inbound_record(&record[RECORD_HEADER_LEN..], rec_type) {
                if !payload.is_empty() {
                    let _ = hidden_tx.send(payload);
                }
                continue;
            }
            let mut cursor = &record[..];
            if tls.read_tls(&mut cursor).is_err() {
                return;
            }
            if tls.process_new_packets().is_err() {
                return;
            }
        }
        // Decrypted carrier plaintext → the generator duplex (or
        // dropped, the `io.Copy(io.Discard)` no-generator path).
        if !tls.is_handshaking() && carrier.is_some() {
            let mut plain = [0u8; 16 * 1024];
            loop {
                let n = tls.reader().read(&mut plain).unwrap_or(0);
                if n == 0 {
                    break;
                }
                if carrier
                    .as_mut()
                    .expect("checked")
                    .write_all(&plain[..n])
                    .await
                    .is_err()
                {
                    carrier = None;
                    break;
                }
            }
        } else if !tls.is_handshaking() {
            let mut plain = [0u8; 16 * 1024];
            while tls.reader().read(&mut plain).unwrap_or(0) > 0 {}
        }

        // ---- hidden inserts (waitWriteReady + deferred first write) ----
        while let Ok(chunk) = insert_rx.try_recv() {
            pending_inserts.push_back(chunk);
        }
        if ready.load(std::sync::atomic::Ordering::SeqCst) {
            while !pending_inserts.is_empty() {
                let chunk = pending_inserts.pop_front().expect("non-empty");
                let mut plain: &[u8] = &chunk;
                while !plain.is_empty() {
                    if !first_insert.is_zero() {
                        // `firstWriteDelay` (conn.go:178-195).
                        tokio::time::sleep(first_insert).await;
                        first_insert = Duration::ZERO;
                    }
                    match mirror.build_inserted_record(plain, true) {
                        Ok((fragment, take)) => {
                            let mut record = Vec::with_capacity(RECORD_HEADER_LEN + fragment.len());
                            record.push(REC_APP_DATA);
                            record.extend_from_slice(&version_hint);
                            record.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
                            let mut frag = fragment;
                            mirror.apply_watermark_tx(&mut frag, REC_APP_DATA, true);
                            record.extend_from_slice(&frag);
                            if transport.write_all(&record).await.is_err() {
                                return;
                            }
                            plain = &plain[take..];
                        }
                        Err(_) => return,
                    }
                }
            }
        }

        // ---- wait for work ----
        // Records queued by the inbound pass are flushed before
        // sleeping (the peer may be waiting on them).
        if tls.wants_write() {
            continue;
        }
        let insert_wait = insert_rx.recv();
        tokio::pin!(insert_wait);
        let mut carrier_closed = carrier.is_none();
        let mut carrier_tmp = [0u8; 16 * 1024];
        tokio::select! {
            n = transport.read(&mut tmp) => match n {
                Ok(0) | Err(_) => return,
                Ok(n) => rbuf.extend_from_slice(&tmp[..n]),
            },
            chunk = &mut insert_wait => match chunk {
                Some(chunk) => pending_inserts.push_back(chunk),
                None => {
                    // Hidden stream dropped: mirror closed.
                    let _ = transport.shutdown().await;
                    return;
                }
            },
            n = async {
                carrier
                    .as_mut()
                    .expect("carrier present")
                    .read(&mut carrier_tmp)
                    .await
            }, if !carrier_closed => {
                match n {
                    Ok(0) | Err(_) => {
                        carrier = None;
                        carrier_closed = true;
                    }
                    Ok(n) => {
                        let _ = tls.writer().write_all(&carrier_tmp[..n]);
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The traffic generator (traffic.go), HTTP/1.1 arm
// ---------------------------------------------------------------------------

/// `trafficGeneratorWaitsForReady` (traffic.go:128).
fn traffic_generator_waits_for_ready(steps: &[TrafficStep]) -> bool {
    steps.iter().any(|s| s.connection_ready)
}

/// `chooseNextTrafficStep` (traffic.go:209): weighted pick.
fn choose_next_traffic_step(step: &TrafficStep, current: usize) -> Result<(usize, bool)> {
    if step.next_step.is_empty() {
        return Ok((0, false));
    }
    let total: i32 = step.next_step.iter().map(|c| c.weight).sum();
    if total <= 0 {
        return Err(Error::protocol(format!(
            "tlsmirror: invalid next-step weight total {total}"
        )));
    }
    let selected = if total > 0 {
        rand::rngs::OsRng.gen_range(0..total as u32) as i32
    } else {
        0
    };
    let mut cursor = 0i32;
    for candidate in &step.next_step {
        if cursor >= selected {
            return Ok((candidate.goto_location as usize, true));
        }
        cursor += candidate.weight;
    }
    Ok((current + 1, true))
}

/// One HTTP/1.1 request/response over the carrier (traffic.go
/// `runTrafficStep` for the non-h2 arm).
async fn run_http1_step(
    carrier: &mut tokio::io::DuplexStream,
    step: &TrafficStep,
) -> Result<()> {
    let host = if step.host.is_empty() {
        "localhost".to_string()
    } else {
        step.host.clone()
    };
    let hostname = host.rsplit_once(':').map(|(h, _)| h.to_string()).unwrap_or(host.clone());
    let path = if step.path.is_empty() { "/".to_string() } else { step.path.clone() };
    let method = if step.method.is_empty() { "GET".to_string() } else { step.method.to_uppercase() };
    let mut req = Vec::with_capacity(256);
    req.extend_from_slice(format!("{method} {path} HTTP/1.1\r\n").as_bytes());
    req.extend_from_slice(format!("Host: {hostname}\r\n").as_bytes());
    let mut has_ua = false;
    for (name, value) in &step.headers {
        if name.eq_ignore_ascii_case("user-agent") {
            has_ua = true;
        }
        req.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
    }
    if !has_ua {
        // Go's http client default.
        req.extend_from_slice(b"User-Agent: Go-http-client/1.1\r\n");
    }
    req.extend_from_slice(b"\r\n");
    carrier
        .write_all(&req)
        .await
        .map_err(|e| Error::network(format!("tlsmirror: carrier request: {e}")))?;
    // Drain the response: status line + headers, then the body per
    // Content-Length or chunked framing.
    let mut head = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        carrier
            .read_exact(&mut byte)
            .await
            .map_err(|e| Error::network(format!("tlsmirror: carrier response: {e}")))?;
        head.push(byte[0]);
        if head.ends_with(b"\r\n\r\n") {
            break;
        }
        if head.len() > 16 * 1024 {
            return Err(Error::protocol("tlsmirror: carrier response head too large"));
        }
    }
    let head_str = String::from_utf8_lossy(&head).to_ascii_lowercase();
    let content_length = head_str
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|v| v.trim().parse::<u64>().ok());
    let chunked = head_str.lines().any(|l| l.starts_with("transfer-encoding:") && l.contains("chunked"));
    if let Some(len) = content_length {
        let mut body = vec![0u8; len as usize];
        carrier
            .read_exact(&mut body)
            .await
            .map_err(|e| Error::network(format!("tlsmirror: carrier body: {e}")))?;
    } else if chunked {
        loop {
            let mut line = Vec::new();
            loop {
                carrier.read_exact(&mut byte).await.map_err(Error::from)?;
                line.push(byte[0]);
                if line.ends_with(b"\r\n") {
                    break;
                }
            }
            let size_str = String::from_utf8_lossy(&line[..line.len() - 2]);
            let size = usize::from_str_radix(size_str.trim().split(';').next().unwrap_or("0"), 16)
                .map_err(|_| Error::protocol("tlsmirror: bad chunk size"))?;
            let mut chunk = vec![0u8; size + 2];
            carrier.read_exact(&mut chunk).await.map_err(Error::from)?;
            if size == 0 {
                break;
            }
        }
    }
    Ok(())
}

/// `runTrafficGenerator` (traffic.go:75) for the HTTP/1.1 arm.
async fn run_traffic_generator(
    mut carrier: tokio::io::DuplexStream,
    steps: Vec<TrafficStep>,
    mut ready: Option<tokio::sync::oneshot::Sender<()>>,
    recall: Arc<tokio::sync::Notify>,
) {
    let waits = traffic_generator_waits_for_ready(&steps);
    let mut current = 0usize;
    loop {
        if current >= steps.len() {
            return;
        }
        let step = &steps[current];
        if let Err(e) = run_http1_step(&mut carrier, step).await {
            debug!(target: "engine", "tlsmirror: traffic step ended: {e}");
            return;
        }
        if step.connection_ready {
            if let Some(tx) = ready.take() {
                let _ = tx.send(());
            }
        }
        if step.connection_recall_exit {
            // On recall the generator closes the carrier after this
            // step (traffic.go:105-115); the recall signal itself is
            // honoured at the wait below (and by stream shutdown).
        }
        match choose_next_traffic_step(step, current) {
            Ok((next, ok)) => {
                current = if ok { next } else { current + 1 };
            }
            Err(_) => return,
        }
        if waits && ready.is_none() && steps[current].connection_ready {
            // already marked
        }
        let delay = steps[current].wait_time.duration();
        if !delay.is_zero() {
            let sleep = tokio::time::sleep(delay);
            tokio::pin!(sleep);
            tokio::select! {
                _ = &mut sleep => {}
                _ = recall.notified() => return,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TLS client config + connect (client.go Dial)
// ---------------------------------------------------------------------------

/// Accept-anything verifier for `skip-cert-verify`.
#[derive(Debug)]
struct NoVerify(Arc<CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn tls_config(cfg: &TlsMirrorOut) -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(ring_provider::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::config(format!("tlsmirror: tls: {e}")))?;
    let mut config = if cfg.skip_cert_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth()
    } else {
        let mut roots = RootCertStore::empty();
        let certs = rustls_native_certs::load_native_certs()
            .map_err(|e| Error::config(format!("tlsmirror: native cert store: {e}")))?;
        for cert in certs {
            roots
                .add(cert)
                .map_err(|e| Error::config(format!("tlsmirror: bad native cert: {e}")))?;
        }
        if roots.is_empty() {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        builder.with_root_certificates(roots).with_no_client_auth()
    };
    if !cfg.alpn.is_empty() {
        config.alpn_protocols = cfg.alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
    }
    Ok(Arc::new(config))
}

/// `Dial` (client.go:15): establish the mirrored carrier TLS and
/// return the hidden stream.
pub async fn connect(cfg: &TlsMirrorOut, transport: BoxProxyStream) -> Result<BoxProxyStream> {
    let primary_key = decode_primary_key(&cfg.primary_key)?;
    if cfg.connection_enrolment.is_some() {
        return Err(Error::config(
            "tlsmirror: connection-enrolment is not implemented: it requires the engine proxy \
             dialer (primary-ingress/egress-outbound) and the h2 enrolment control connection \
             (transport/tlsmirror/enrollment.go: deriveEnrollmentRequestKey, \
             marshalEnrollmentConfirmationReq, ServeEnrollmentControlConnection); configure it \
             away for this port",
        ));
    }
    let has_generator = !cfg.traffic_generator.is_empty();
    if has_generator {
        let h2_only = cfg.alpn.iter().any(|a| a == "h2");
        if h2_only {
            return Err(Error::config(
                "tlsmirror: embedded-traffic-generator over an h2 carrier is not implemented: \
                 upstream multiplexes the generator steps over HTTP/2 \
                 (transport/tlsmirror/traffic.go newTrafficHTTP2Transport, unencrypted-h2 prior \
                 knowledge) and this engine has no HTTP/2 client; use an http/1.1 (or empty) \
                 ALPN carrier",
            ));
        }
        for step in &cfg.traffic_generator {
            if step.h2_do_not_wait_for_download_finish {
                // Only meaningful on the h2 arm; carried.
                debug!(target: "engine", "tlsmirror: h2-do-not-wait-for-download-finish applies to the h2 carrier only");
            }
        }
    }
    let server_name = if cfg.server_name.is_empty() {
        return Err(Error::config(
            "tlsmirror: server-name is required when certificate verification is enabled",
        ));
    } else {
        cfg.server_name.clone()
    };
    if cfg.client_fingerprint.is_empty() {
        // plain rustls (see module docs)
    }

    let config = tls_config(cfg)?;
    let name = rustls::pki_types::ServerName::try_from(server_name.to_owned())
        .map_err(|_| Error::config(format!("tlsmirror: invalid SNI {server_name:?}")))?;
    let tls = ClientConnection::new(config, name)
        .map_err(|e| Error::config(format!("tlsmirror: TLS client init: {e}")))?;

    let (hidden_tx, hidden_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (insert_tx, insert_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let ready = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ready_notify = Arc::new(tokio::sync::Notify::new());
    let recall = Arc::new(tokio::sync::Notify::new());
    let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
    // The carrier duplex exists only when a generator runs; otherwise
    // carrier plaintext is discarded (io.Copy(io.Discard), traffic.go:77).
    let (carrier_client, carrier_pump_side) = if has_generator {
        let (a, b) = tokio::io::duplex(64 * 1024);
        (Some(a), Some(b))
    } else {
        (None, None)
    };
    let (carrier_ready_tx, carrier_ready_rx) = tokio::sync::oneshot::channel::<()>();

    let mirror = Mirror::new(cfg, primary_key, false);
    let pump_ready = ready.clone();
    let pump_ready_notify = ready_notify.clone();
    let defer = cfg.defer_instance_derived_write.duration();
    tokio::spawn(async move {
        pump(
            transport,
            tls,
            mirror,
            insert_rx,
            hidden_tx,
            carrier_pump_side,
            pump_ready,
            pump_ready_notify,
            defer,
            Some(carrier_ready_tx),
        )
        .await;
    });

    if has_generator {
        let waits = traffic_generator_waits_for_ready(&cfg.traffic_generator);
        let (gen_ready_tx, gen_ready_rx) = tokio::sync::oneshot::channel::<()>();
        let carrier = carrier_client.expect("has generator");
        let steps = cfg.traffic_generator.clone();
        let gen_recall = recall.clone();
        tokio::spawn(async move {
            run_traffic_generator(carrier, steps, Some(gen_ready_tx), gen_recall).await;
        });
        if waits {
            // Wait until the carrier handshake completed AND a
            // ConnectionReady step finished (client.go:123-135).
            match carrier_ready_rx.await {
                Ok(()) => {}
                Err(_) => {
                    return Err(Error::network(
                        "tlsmirror: carrier traffic generator exited before ready",
                    ))
                }
            }
            match tokio::time::timeout(Duration::from_secs(30), gen_ready_rx).await {
                Ok(Ok(())) => {}
                _ => {
                    return Err(Error::network(
                        "tlsmirror: carrier traffic generator exited before ready",
                    ))
                }
            }
        }
    }

    debug!(target: "engine", "tlsmirror: hidden conn established over carrier {server_name}");
    Ok(Box::new(TlsMirrorStream {
        hidden_rx,
        insert_tx,
        recall,
        pending: BytesMut::new(),
        closed: false,
        alive,
    }))
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use std::time::{Duration, Instant};

    /// RFC 8439 §2.3.2/§A.1: ChaCha20 block for key 0..31, nonce
    /// 000000000000004a00000000, counter 1.
    #[test]
    fn chacha20_block_rfc8439_vector() {
        let key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let nonce = [0u8, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let block = chacha20_block(&key, 1, &nonce);
        assert_eq!(
            block
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect::<String>(),
            "224f51f3401bd9e12fde276fb8631ded\
             8c131f823d2c06e27e4fcaec9ef3cf78\
             8a3b0aa372600a92b57974cded2b9334\
             794cba40c63e34cdea212c4cf07d41b7"
        );
    }

    #[test]
    fn chacha20_stream_xor_is_involutive_and_counters_advance() {
        let key = [7u8; 32];
        let nonce = [9u8; 12];
        let mut stream = ChaCha20Stream::new(&key, &nonce);
        let mut data = vec![0u8; 200];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut data);
        let original = data.clone();
        stream.xor(&mut data);
        assert_ne!(data, original);
        // A fresh stream with the same key restores the data (a
        // continuing stream would XOR with the NEXT keystream bytes).
        let mut stream2 = ChaCha20Stream::new(&[7u8; 32], &[9u8; 12]);
        stream2.xor(&mut data);
        assert_eq!(data, original);
        // Streams with identical keys agree; a different nonce differs.
        let mut a = ChaCha20Stream::new(&key, &nonce);
        let mut b = ChaCha20Stream::new(&key, &nonce);
        let mut x = vec![0u8; 64];
        let mut y = vec![0u8; 64];
        a.xor(&mut x);
        b.xor(&mut y);
        assert_eq!(x, y);
        let mut c = ChaCha20Stream::new(&key, &[1u8; 12]);
        let mut z = vec![0u8; 64];
        c.xor(&mut z);
        assert_ne!(x, z);
    }

    #[test]
    fn nonce_generators_shape() {
        // LE counter from all-ones (crypto.go:108).
        let mut g = NonceGenerator::new();
        // 0xffff…ffff + 1 wraps to zero through every byte.
        assert_eq!(g.next(), [0x00; 8]);
        assert_eq!(g.next(), [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        // BE counter from zero (crypto.go:126).
        let mut e = ExplicitNonceGenerator::new();
        assert_eq!(e.next(), [0, 0, 0, 0, 0, 0, 0, 1]);
        assert_eq!(e.next(), [0, 0, 0, 0, 0, 0, 0, 2]);
    }

    #[test]
    fn xor_nonce_aead_roundtrip() {
        let a = XorNonceAead::new(&[1u8; 16], &[2u8; 12]).unwrap();
        let b = XorNonceAead::new(&[1u8; 16], &[2u8; 12]).unwrap();
        let ct = a.seal(&[0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], b"hidden").unwrap();
        assert_eq!(ct.len(), 6 + 16);
        let pt = b.open(&[0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], &ct).unwrap();
        assert_eq!(pt, b"hidden");
        // Counter mismatch fails.
        assert!(b.open(&[0x01, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], &ct).is_err());
        // Wrong mask fails.
        let c = XorNonceAead::new(&[1u8; 16], &[3u8; 12]).unwrap();
        assert!(c.open(&[0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff], &ct).is_err());
    }

    #[test]
    fn key_derivations_are_directional_and_deterministic() {
        let key = [5u8; 32];
        let cr = [1u8; 32];
        let sr = [2u8; 32];
        let (k1, m1) = derive_encryption_key(&key, &cr, &sr, ":c2s").unwrap();
        let (k2, m2) = derive_encryption_key(&key, &cr, &sr, ":s2c").unwrap();
        assert_ne!(k1, k2);
        assert_ne!(m1, m2);
        assert_eq!(k1, derive_encryption_key(&key, &cr, &sr, ":c2s").unwrap().0);
        let (wk1, wn1) = derive_sequence_watermark(&key, &cr, &sr, ":c2s").unwrap();
        let (wk2, wn2) = derive_sequence_watermark(&key, &cr, &sr, ":s2c").unwrap();
        assert_ne!(wk1, wk2);
        assert_ne!(wn1, wn2);
        assert_eq!(wk1.len(), 32);
        assert_eq!(wn1.len(), 12);
    }

    #[test]
    fn padding_roundtrip() {
        let packed = pack_padding(b"payload");
        assert_eq!(&packed[..7], b"payload");
        assert_eq!(&packed[7..], &7u32.to_be_bytes());
        assert_eq!(unpack_padding(&packed), Some(&b"payload"[..]));
        assert_eq!(unpack_padding(b"ab"), None);
        assert_eq!(unpack_padding(&[0, 0, 0, 9, b'x']), None);
        // Zero-length padding marker.
        assert_eq!(unpack_padding(&0u32.to_be_bytes()), Some(&b""[..]));
    }

    #[test]
    fn handshake_parsers() {
        let mut fragment = vec![0u8; 38];
        fragment[0] = 1;
        for (i, b) in fragment.iter_mut().enumerate().take(38).skip(6) {
            *b = i as u8;
        }
        let random = parse_client_random(&fragment).unwrap();
        assert_eq!(&random[..], &fragment[6..38]);
        assert!(parse_client_random(&fragment[..37]).is_none());
        // ServerHello: random + session-id + suite.
        let mut sh = vec![2u8];
        sh.extend_from_slice(&[0, 0, 36]); // handshake body length
        sh.extend_from_slice(&[0x03, 0x03]); // legacy version
        sh.extend_from_slice(&[0x11u8; 32]); // random
        sh.push(2); // session id len
        sh.extend_from_slice(&[9, 9]);
        sh.extend_from_slice(&0xC02Fu16.to_be_bytes());
        sh.push(0); // compression methods length
        sh.push(0); // null compression
        let (random, suite) = parse_server_hello(&sh).unwrap();
        assert_eq!(random, [0x11u8; 32]);
        assert_eq!(suite, 0xC02F);
    }

    #[test]
    fn next_step_weighted_choice() {
        let step = TrafficStep {
            next_step: vec![
                TrafficTransferCandidate { weight: 0, goto_location: 0 },
            ],
            ..http_step("s", "/")
        };
        assert!(choose_next_traffic_step(&step, 0).is_err());
        let step = TrafficStep {
            next_step: vec![
                TrafficTransferCandidate { weight: 1, goto_location: 4 },
            ],
            ..http_step("s", "/")
        };
        assert_eq!(choose_next_traffic_step(&step, 0).unwrap(), (4, true));
        let no_next = http_step("s", "/");
        assert_eq!(choose_next_traffic_step(&no_next, 3).unwrap(), (0, false));
    }

    #[test]
    fn time_spec_duration_bounds() {
        let t = TimeSpec { base_nanoseconds: 10, uniform_random_multiplier_nanoseconds: 0 };
        assert_eq!(t.duration(), Duration::from_nanos(10));
        let t = TimeSpec { base_nanoseconds: 5, uniform_random_multiplier_nanoseconds: 10 };
        for _ in 0..50 {
            let d = t.duration();
            assert!(d >= Duration::from_nanos(5) && d < Duration::from_nanos(15));
        }
    }

    #[test]
    fn primary_key_validation() {
        let key = generate_primary_key();
        assert_eq!(decode_primary_key(&key).unwrap().len(), 32);
        assert!(decode_primary_key("").unwrap_err().to_string().contains("missing"));
        let err = decode_primary_key("not-base64!!").unwrap_err().to_string();
        assert!(err.contains("base64"), "{err}");
        use base64::Engine;
        let short = base64::engine::general_purpose::STANDARD.encode([0u8; 16]);
        let err = decode_primary_key(&short).unwrap_err().to_string();
        assert!(err.contains("32 bytes"), "{err}");
    }

    // ------------------------------------------------------------ loopback

    fn http_step(name: &str, path: &str) -> TrafficStep {
        TrafficStep {
            name: name.into(),
            host: "carrier.example".into(),
            path: path.into(),
            method: "GET".into(),
            headers: Vec::new(),
            next_step: Vec::new(),
            connection_ready: false,
            connection_recall_exit: false,
            wait_time: TimeSpec::default(),
            h2_do_not_wait_for_download_finish: false,
        }
    }

    fn test_server_config(tls12_only: bool) -> Arc<rustls::ServerConfig> {
        let certified = rcgen::generate_simple_self_signed(vec!["carrier.example".to_string()])
            .expect("rcgen self-signed cert");
        let cert = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let provider = Arc::new(ring_provider::default_provider());
        let versions: &[&'static rustls::SupportedProtocolVersion] = if tls12_only {
            &[&rustls::version::TLS12]
        } else {
            &[&rustls::version::TLS13]
        };
        let builder = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(versions)
            .unwrap()
            .with_no_client_auth();
        let mut config = builder.with_single_cert(vec![cert], key).expect("server config");
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        Arc::new(config)
    }

    /// The camouflage web server behind the mirror: a real rustls
    /// server answering trivial HTTP/1.1 responses. Returns the socket
    /// the mirror forwards to plus a request log.
    fn spawn_forward_server(
        tls12_only: bool,
        requests: Arc<StdMutex<Vec<String>>>,
    ) -> BoxProxyStream {
        let (mirror_side, server_side) = tokio::io::duplex(64 * 1024);
        let config = test_server_config(tls12_only);
        tokio::spawn(async move {
            let mut tls = match rustls::ServerConnection::new(config) {
                Ok(t) => t,
                Err(_) => return,
            };
            let mut io = server_side;
            let mut tls_out = Vec::new();
            loop {
                while tls.wants_write() {
                    if tls.write_tls(&mut tls_out).unwrap_or(0) == 0 {
                        break;
                    }
                }
                if !tls_out.is_empty() && io.write_all(&tls_out).await.is_err() {
                    return;
                }
                tls_out.clear();
                if tls.is_handshaking() {
                    let mut tmp = [0u8; 16 * 1024];
                    let n = match io.read(&mut tmp).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => n,
                    };
                    let mut cursor = &tmp[..n];
                    if tls.read_tls(&mut cursor).is_err() || tls.process_new_packets().is_err() {
                        return;
                    }
                    continue;
                }
                // HTTP/1.1: one request head → one response, read
                // from the DECRYPTED stream (carrier records on the
                // wire stay opaque).
                let mut head = Vec::new();
                loop {
                    let mut plain = [0u8; 4096];
                    let n = {
                        use std::io::Read as _;
                        tls.reader().read(&mut plain).unwrap_or(0)
                    };
                    if n == 0 {
                        // Nothing decrypted yet: pull more records.
                        let mut tmp = [0u8; 16 * 1024];
                        let got = match io.read(&mut tmp).await {
                            Ok(0) | Err(_) => return,
                            Ok(got) => got,
                        };
                        let mut cursor = &tmp[..got];
                        if tls.read_tls(&mut cursor).is_err()
                            || tls.process_new_packets().is_err()
                        {
                            return;
                        }
                        while tls.wants_write() {
                            if tls.write_tls(&mut tls_out).unwrap_or(0) == 0 {
                                break;
                            }
                        }
                        if !tls_out.is_empty() && io.write_all(&tls_out).await.is_err() {
                            return;
                        }
                        tls_out.clear();
                        continue;
                    }
                    head.extend_from_slice(&plain[..n]);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                let head_str = String::from_utf8_lossy(&head).into_owned();
                requests.lock().unwrap().push(head_str);
                let resp = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";
                if tls.writer().write_all(resp).is_err() {
                    return;
                }
            }
        });
        Box::new(mirror_side)
    }

    /// The server-side mirror (`serveConn`, server.go:30): relays
    /// carrier records between the client and the forward target,
    /// extracting hidden records from the client's flow and inserting
    /// hidden records into its own.
    async fn mirror_server_mimic(
        client_io: BoxProxyStream,
        forward_io: BoxProxyStream,
        cfg: &TlsMirrorOut,
        primary_key: [u8; 32],
        hidden_rx_close: tokio::sync::oneshot::Receiver<()>,
    ) {
        let (client_rd, mut client_wr) = tokio::io::split(client_io);
        let (mut forward_rd, mut forward_wr) = tokio::io::split(forward_io);
        let mirror = Arc::new(tokio::sync::Mutex::new(Mirror::new(cfg, primary_key, true)));
        let (hidden_tx, mut hidden_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let (insert_tx, mut insert_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();

        // c2s relay: client → forward, extracting hidden records.
        let c2s_mirror = mirror.clone();
        let c2s = tokio::spawn(async move {
            let mut rd = client_rd;
            let mut first = true;
            let mut rbuf = BytesMut::with_capacity(16 * 1024);
            let mut tmp = [0u8; 16 * 1024];
            loop {
                while rbuf.len() >= RECORD_HEADER_LEN {
                    let rlen = u16::from_be_bytes([rbuf[3], rbuf[4]]) as usize;
                    if rbuf.len() < RECORD_HEADER_LEN + rlen {
                        break;
                    }
                    let mut record = rbuf.split_to(RECORD_HEADER_LEN + rlen).to_vec();
                    let rec_type = record[0];
                    if first && rec_type == REC_HANDSHAKE {
                        if let Some(random) = parse_client_random(&record[RECORD_HEADER_LEN..]) {
                            c2s_mirror.lock().await.client_random = Some(random);
                        }
                        first = false;
                    }
                    let mut m = c2s_mirror.lock().await;
                    m.apply_watermark_rx(&mut record[RECORD_HEADER_LEN..], rec_type);
                    match m.handle_inbound_record(&record[RECORD_HEADER_LEN..], rec_type) {
                        Some(payload) => {
                            if !payload.is_empty() {
                                let _ = hidden_tx.send(payload);
                            }
                        }
                        None => {
                            drop(m);
                            if forward_wr.write_all(&record).await.is_err() {
                                return;
                            }
                        }
                    }
                }
                match rd.read(&mut tmp).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => rbuf.extend_from_slice(&tmp[..n]),
                }
            }
        });

        // s2c relay: forward → client, inserting hidden records
        // (the insert queue is drained whenever the forward side is
        // quiet, so echoes never wait for carrier traffic).
        let s2c_mirror = mirror.clone();
        let s2c = tokio::spawn(async move {
            let mut first = true;
            let mut rbuf = BytesMut::with_capacity(16 * 1024);
            let mut tmp = [0u8; 16 * 1024];
            let mut pending: Vec<Vec<u8>> = Vec::new();
            loop {
                while rbuf.len() >= RECORD_HEADER_LEN {
                    let rlen = u16::from_be_bytes([rbuf[3], rbuf[4]]) as usize;
                    if rbuf.len() < RECORD_HEADER_LEN + rlen {
                        break;
                    }
                    let mut record = rbuf.split_to(RECORD_HEADER_LEN + rlen).to_vec();
                    let rec_type = record[0];
                    if first && rec_type == REC_HANDSHAKE {
                        if let Some((random, suite)) = parse_server_hello(&record[RECORD_HEADER_LEN..]) {
                            let mut m = s2c_mirror.lock().await;
                            m.server_random = Some(random);
                            m.tls12_explicit = m.explicit_suites.contains(&suite);
                        }
                        first = false;
                    }
                    // handleOutboundRecordTx (conn.go:377): outbound
                    // carrier app/alert records are watermarked too once
                    // the tx stream is armed — the client strips every
                    // inbound record after its first hidden decrypt.
                    s2c_mirror
                        .lock()
                        .await
                        .apply_watermark_tx(&mut record[RECORD_HEADER_LEN..], rec_type, false);
                    if client_wr.write_all(&record).await.is_err() {
                        return;
                    }
                }
                // Server hidden inserts (Conn.Write, server side).
                while let Ok(chunk) = insert_rx.try_recv() {
                    pending.push(chunk);
                }
                for chunk in pending.drain(..) {
                    let mut plain: &[u8] = &chunk;
                    while !plain.is_empty() {
                        let (rec, take) = {
                            let mut m = s2c_mirror.lock().await;
                            match m.build_inserted_record(plain, false) {
                                Ok((fragment, take)) => {
                                    let mut rec =
                                        Vec::with_capacity(RECORD_HEADER_LEN + fragment.len());
                                    rec.push(REC_APP_DATA);
                                    rec.extend_from_slice(&[0x03, 0x03]);
                                    rec.extend_from_slice(&(fragment.len() as u16).to_be_bytes());
                                    let mut frag = fragment;
                                    m.apply_watermark_tx(&mut frag, REC_APP_DATA, true);
                                    rec.extend_from_slice(&frag);
                                    (rec, take)
                                }
                                Err(_) => return,
                            }
                        };
                        if client_wr.write_all(&rec).await.is_err() {
                            return;
                        }
                        plain = &plain[take..];
                    }
                }
                let read = tokio::select! {
                    r = forward_rd.read(&mut tmp) => r,
                    chunk = insert_rx.recv() => {
                        match chunk {
                            Some(chunk) => pending.push(chunk),
                            None => return,
                        }
                        continue;
                    }
                };
                match read {
                    Ok(0) | Err(_) => return,
                    Ok(n) => rbuf.extend_from_slice(&tmp[..n]),
                }
            }
        });

        // Hidden echo: extract → re-insert.
        let echo = tokio::spawn(async move {
            while let Some(payload) = hidden_rx.recv().await {
                if insert_tx.send(payload).is_err() {
                    return;
                }
            }
        });
        tokio::select! {
            _ = c2s => {}
            _ = s2c => {}
            _ = echo => {}
            _ = hidden_rx_close => {}
        }
    }

    async fn run_client(cfg: &TlsMirrorOut, requests: Arc<StdMutex<Vec<String>>>) -> Result<BoxProxyStream> {
        let primary_key = decode_primary_key(&cfg.primary_key)?;
        let (client_duplex, server_duplex) = tokio::io::duplex(256 * 1024);
        let forward = spawn_forward_server(false, requests);
        let (close_tx, close_rx) = tokio::sync::oneshot::channel::<()>();
        let cfg2 = cfg.clone();
        tokio::spawn(async move {
            mirror_server_mimic(Box::new(server_duplex), forward, &cfg2, primary_key, close_rx).await;
        });
        // Keep the mimic alive for the test's lifetime.
        std::mem::forget(close_tx);
        connect(cfg, Box::new(client_duplex)).await
    }

    fn base_cfg() -> TlsMirrorOut {
        TlsMirrorOut::new(&generate_primary_key(), "carrier.example")
    }

    async fn echo_roundtrip(stream: &mut BoxProxyStream, payload: &[u8]) {
        stream.write_all(payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(15), stream.read_exact(&mut got))
            .await
            .expect("echo timed out")
            .unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn hidden_echo_roundtrip_tls13() {
        let cfg = base_cfg();
        let mut stream = run_client(&cfg, Arc::new(StdMutex::new(Vec::new())))
            .await
            .unwrap();
        echo_roundtrip(&mut stream, b"hello mirror").await;
        let payload: Vec<u8> = (0..50_000u32).map(|i| (i % 251) as u8).collect();
        echo_roundtrip(&mut stream, &payload).await;
    }

    #[tokio::test]
    async fn hidden_echo_with_padding() {
        let mut cfg = base_cfg();
        cfg.transport_layer_padding = true;
        let mut stream = run_client(&cfg, Arc::new(StdMutex::new(Vec::new())))
            .await
            .unwrap();
        echo_roundtrip(&mut stream, b"padded").await;
        let payload: Vec<u8> = (0..40_000u32).map(|i| (i % 249) as u8).collect();
        echo_roundtrip(&mut stream, &payload).await;
    }

    #[tokio::test]
    async fn hidden_echo_with_watermarking() {
        let mut cfg = base_cfg();
        cfg.sequence_watermarking_enabled = true;
        let mut stream = run_client(&cfg, Arc::new(StdMutex::new(Vec::new())))
            .await
            .unwrap();
        echo_roundtrip(&mut stream, b"watermarked").await;
        let payload: Vec<u8> = (0..20_000u32).map(|i| (i % 253) as u8).collect();
        echo_roundtrip(&mut stream, &payload).await;
    }

    #[tokio::test]
    async fn hidden_echo_padding_and_watermarking() {
        let mut cfg = base_cfg();
        cfg.transport_layer_padding = true;
        cfg.sequence_watermarking_enabled = true;
        let mut stream = run_client(&cfg, Arc::new(StdMutex::new(Vec::new())))
            .await
            .unwrap();
        echo_roundtrip(&mut stream, b"both").await;
    }

    #[tokio::test]
    async fn wrong_primary_key_drops_hidden_channel() {
        // Two keys: the mimic uses the real one; the client another.
        let real = base_cfg();
        let mut bad = real.clone();
        bad.primary_key = generate_primary_key();
        let primary_key = decode_primary_key(&real.primary_key).unwrap();
        let (client_duplex, server_duplex) = tokio::io::duplex(64 * 1024);
        let forward = spawn_forward_server(false, Arc::new(StdMutex::new(Vec::new())));
        let (close_tx, close_rx) = tokio::sync::oneshot::channel::<()>();
        let cfg2 = real.clone();
        tokio::spawn(async move {
            mirror_server_mimic(Box::new(server_duplex), forward, &cfg2, primary_key, close_rx).await;
        });
        std::mem::forget(close_tx);
        let mut stream = connect(&bad, Box::new(client_duplex)).await.unwrap();
        // The client's inserts cannot be decrypted by the server: they
        // are passed through to the camouflage server (TLS junk) which
        // kills the carrier; the hidden channel never echoes.
        stream.write_all(b"secret").await.unwrap();
        let mut buf = [0u8; 6];
        let result = tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf)).await;
        match result {
            Err(_) => {} // no data — fine
            Ok(Err(_)) => {} // carrier died — fine
            Ok(Ok(_)) => panic!("a wrong primary key must not echo hidden data"),
        }
    }

    #[tokio::test]
    async fn defer_instance_derived_write_delays_first_write() {
        let mut cfg = base_cfg();
        cfg.defer_instance_derived_write = TimeSpec {
            base_nanoseconds: 120_000_000, // 120ms
            uniform_random_multiplier_nanoseconds: 0,
        };
        let mut stream = run_client(&cfg, Arc::new(StdMutex::new(Vec::new())))
            .await
            .unwrap();
        let start = Instant::now();
        stream.write_all(b"deferred").await.unwrap();
        let mut buf = [0u8; 8];
        tokio::time::timeout(Duration::from_secs(15), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"deferred");
        assert!(start.elapsed() >= Duration::from_millis(100), "{:?}", start.elapsed());
    }

    #[tokio::test]
    async fn traffic_generator_carries_http11_and_signals_ready() {
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let mut cfg = base_cfg();
        cfg.alpn = vec!["http/1.1".to_string()];
        cfg.traffic_generator = vec![TrafficStep {
            host: "carrier.example".into(),
            path: "/carrier".into(),
            method: "GET".into(),
            headers: vec![("User-Agent".into(), "tlsmirror-test".into())],
            connection_ready: true,
            connection_recall_exit: true,
            wait_time: TimeSpec {
                base_nanoseconds: 10_000_000,
                uniform_random_multiplier_nanoseconds: 0,
            },
            next_step: vec![TrafficTransferCandidate { weight: 1, goto_location: 0 }],
            ..http_step("step", "/carrier")
        }];
        let mut stream = run_client(&cfg, requests.clone()).await.unwrap();
        // Dial returned only after the ConnectionReady step ran.
        let reqs = requests.lock().unwrap().clone();
        assert!(!reqs.is_empty(), "generator produced no carrier requests");
        assert!(
            reqs.iter().any(|r| r.starts_with("GET /carrier HTTP/1.1\r\n")),
            "{reqs:?}"
        );
        assert!(
            reqs.iter().any(|r| r.contains("Host: carrier.example\r\n")),
            "{reqs:?}"
        );
        assert!(
            reqs.iter().any(|r| r.contains("User-Agent: tlsmirror-test\r\n")),
            "{reqs:?}"
        );
        // The hidden channel still works over the generating carrier.
        echo_roundtrip(&mut stream, b"over-generator").await;
    }

    #[tokio::test]
    async fn tls12_explicit_nonce_roundtrip() {
        let mut cfg = base_cfg();
        cfg.explicit_nonce_cipher_suites = RECOMMENDED_EXPLICIT_NONCE_CIPHER_SUITES.to_vec();
        let primary_key = decode_primary_key(&cfg.primary_key).unwrap();
        let (client_duplex, server_duplex) = tokio::io::duplex(256 * 1024);
        // A TLS 1.2-only forward server forces the TLS 1.2 negotiation
        // (rustls picks an ECDHE-ECDSA AES-GCM suite, which is in the
        // recommended explicit list).
        let forward = spawn_forward_server(true, Arc::new(StdMutex::new(Vec::new())));
        let (close_tx, close_rx) = tokio::sync::oneshot::channel::<()>();
        let cfg2 = cfg.clone();
        tokio::spawn(async move {
            mirror_server_mimic(Box::new(server_duplex), forward, &cfg2, primary_key, close_rx).await;
        });
        std::mem::forget(close_tx);
        let mut stream = connect(&cfg, Box::new(client_duplex)).await.unwrap();
        echo_roundtrip(&mut stream, b"tls12-explicit").await;
    }

    #[tokio::test]
    async fn config_rejections() {
        let mut cfg = base_cfg();
        cfg.primary_key.clear();
        let err = connect(&cfg, Box::new(tokio::io::duplex(16).0)).await.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(err.contains("primary key"), "{err}");
        let mut cfg = base_cfg();
        cfg.primary_key = "!!!".into();
        assert!(connect(&cfg, Box::new(tokio::io::duplex(16).0)).await.is_err());
        let mut cfg = base_cfg();
        cfg.connection_enrolment = Some(("ingress".into(), "egress".into()));
        let err = connect(&cfg, Box::new(tokio::io::duplex(16).0)).await.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(err.contains("connection-enrolment"), "{err}");
        assert!(err.contains("enrollment.go"), "{err}");
        let mut cfg = base_cfg();
        cfg.alpn = vec!["h2".to_string()];
        cfg.traffic_generator = vec![http_step("s", "/x")];
        let err = connect(&cfg, Box::new(tokio::io::duplex(16).0)).await.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(err.contains("h2 carrier"), "{err}");
        assert!(err.contains("HTTP/2"), "{err}");
        let mut cfg = base_cfg();
        cfg.server_name.clear();
        assert!(connect(&cfg, Box::new(tokio::io::duplex(16).0)).await.is_err());
        // The recommended suite list is exposed verbatim.
        assert!(RECOMMENDED_EXPLICIT_NONCE_CIPHER_SUITES.contains(&49195));
        assert_eq!(RECOMMENDED_EXPLICIT_NONCE_CIPHER_SUITES.len(), 48);
    }
}
