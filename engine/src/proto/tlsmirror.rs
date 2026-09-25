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
//!   generator with weighted step transitions; the carrier transport is
//!   picked from the NEGOTIATED ALPN (`newTrafficHTTPTransport`,
//!   traffic.go:52): `http/1.1`/none drive plain HTTP/1.1 requests, `h2`
//!   multiplexes the steps over a prior-knowledge h2c connection
//!   (`newTrafficHTTP2Transport`, traffic.go:60-73 — the in-module h2
//!   client below).
//! * `transport/tlsmirror/enrollment.go` — connection enrolment: the
//!   server-identifier host derived from the primary key, the h2c
//!   confirmation protocol on TCP :80, the client verification pass
//!   (needs a dialer — `connect_with`) and the server-side active
//!   table that `ServeConnReady` populates.
//! * `transport/tlsmirror/server.go` — `ServeConnReady`: the server
//!   mirror between a client conn and the pre-dialed forward conn,
//!   activation on the first decrypted hidden record, enrolment
//!   registration on the forward's first handshake record.
//!
//! ## Wire-visible vs config-carried
//!
//! * Wire-visible: the inserted records (optional 8-byte explicit
//!   nonce + GCM-sealed payload, optionally length-suffixed padding),
//!   the 16-byte ChaCha20 watermark over app-data/alert records, and
//!   the carrier HTTP/1.1 requests the generator issues.
//! * Config-carried: `connection-enrolment` needs an enrolment dialer
//!   (the engine's routing) — `connect` rejects it precisely until
//!   `connect_with` supplies one; the h2c control connection itself is
//!   implemented in-module (a minimal RFC 9113 prior-knowledge client
//!   and server — no HTTP/2 dependency). The generator's h2 carrier
//!   rides that same in-module h2 machinery (see the carrier transport
//!   below): `http/1.1`/no-ALPN carriers run HTTP/1.1 steps, an `h2`
//!   carrier runs h2 steps. One deviation: upstream closes the whole
//!   carrier conn when `newTrafficHTTPTransport` rejects the negotiated
//!   ALPN (traffic.go:78-82); this port stops the generator and leaves
//!   the carrier open (the misconfigured-ALPN-only path — see the note
//!   on [`new_traffic_transport`]).
//! * Enrolment loopback prevention (upstream's ctx markers
//!   `WithLoopbackProtection` / `WithSecondaryLoopbackProtection`) is
//!   router plumbing this port does not have: the integrator's dialer
//!   can consult [`is_enrollment_control_target`] to refuse dialing
//!   its own control endpoint.
//! * `client-fingerprint` (uTLS), `fingerprint` (server-cert pinning)
//!   and client certificates are carried but not applied: the plain
//!   rustls hello with standard verification is offered, like the
//!   rest of this crate's TLS transports.
//! * The carrier offers rustls' safe default versions (TLS 1.3 + 1.2);
//!   the explicit-nonce path engages exactly when the negotiated
//!   suite is in the configured list (the TLS 1.2 AEAD case).

use std::collections::HashMap;
use std::io;
use std::io::{Read as _, Write as _};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
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
    // The negotiated carrier ALPN, handed to the traffic generator
    // (`carrierALPN := NegotiatedProtocol`, client.go:96-105).
    mut carrier_alpn: Option<tokio::sync::oneshot::Sender<String>>,
    randoms_tx: tokio::sync::watch::Sender<Option<([u8; 32], [u8; 32])>>,
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
            if let Some(tx) = carrier_alpn.take() {
                let alpn = tls
                    .alpn_protocol()
                    .map(|p| String::from_utf8_lossy(p).into_owned())
                    .unwrap_or_default();
                let _ = tx.send(alpn);
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
            if let (Some(cr), Some(sr)) = (mirror.client_random, mirror.server_random) {
                let _ = randoms_tx.send(Some((cr, sr)));
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

// ---------------------------------------------------------------------------
// The traffic generator (traffic.go), h2 carrier arm
// ---------------------------------------------------------------------------

/// Events one generator h2 stream receives from the connection reader —
/// the demux `http.ClientConn.RoundTrip` provides upstream
/// (`trafficHTTP2Transport`, traffic.go:37-49). The connection reader is
/// modeled on `proto/trusttunnel.rs`'s `h2_reader_task` (private to that
/// module, so duplicated here with this cross-ref) and reuses the
/// in-module RFC 9113 frame/HPACK helpers the enrolment control
/// connection (`h2c_post`) already uses.
enum CarrierH2Event {
    /// Response HEADERS complete (the decoded `:status`).
    Headers(u16),
    /// Response DATA (the payload is discarded at the reader — the
    /// generator drains bodies into `io.Discard`, traffic.go:170-176).
    Data,
    /// END_STREAM on DATA/HEADERS, or RST_STREAM.
    End,
    GoAway,
}

/// One prior-knowledge h2 connection over the carrier duplex
/// (`newTrafficHTTP2Transport`: `SetUnencryptedHTTP2(true)` +
/// `transport.NewClientConn`, traffic.go:60-73): a reader task
/// demultiplexing frames to per-stream channels, plus a serialized
/// writer. Requests carry no body, so only the receive path needs
/// flow-control credit handling.
struct CarrierH2 {
    writer: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<tokio::io::DuplexStream>>>,
    next_stream: AtomicU32,
    streams: Arc<Mutex<HashMap<u32, tokio::sync::mpsc::UnboundedSender<CarrierH2Event>>>>,
    dead: Arc<AtomicBool>,
}

impl CarrierH2 {
    /// Client preface + a generous initial window (mirrors `h2c_post`'s
    /// settings; Go's transport advertises the same large windows).
    async fn handshake(carrier: tokio::io::DuplexStream) -> Result<Arc<Self>> {
        let (read_half, write_half) = tokio::io::split(carrier);
        let conn = Arc::new(CarrierH2 {
            writer: Arc::new(tokio::sync::Mutex::new(write_half)),
            next_stream: AtomicU32::new(1),
            streams: Arc::new(Mutex::new(HashMap::new())),
            dead: Arc::new(AtomicBool::new(false)),
        });
        {
            let mut w = conn.writer.lock().await;
            w.write_all(H2_PREFACE).await?;
            let mut settings = Vec::with_capacity(6);
            // SETTINGS_INITIAL_WINDOW_SIZE (0x4) = 1 MiB.
            settings.extend_from_slice(&0x4u16.to_be_bytes());
            settings.extend_from_slice(&(1u32 << 20).to_be_bytes());
            w.write_all(&h2_frame(H2_SETTINGS, 0, 0, &settings)).await?;
            w.flush().await?;
        }
        let reader = tokio::spawn(carrier_h2_reader(
            read_half,
            conn.streams.clone(),
            conn.writer.clone(),
            conn.dead.clone(),
        ));
        // The reader task owns the demux loop for the connection
        // lifetime; its JoinHandle is deliberately dropped.
        drop(reader);
        Ok(conn)
    }

    /// `ClientConn.RoundTrip` for a bodyless request: HEADERS with
    /// END_STREAM on a fresh odd stream. Returns the stream id and its
    /// event channel.
    async fn open_request(
        self: &Arc<Self>,
        block: &[u8],
    ) -> Result<(
        u32,
        tokio::sync::mpsc::UnboundedReceiver<CarrierH2Event>,
    )> {
        let id = self.next_stream.fetch_add(2, Ordering::SeqCst);
        if id == 0 || id > 0x7FFF_F000 {
            return Err(Error::network("tlsmirror: h2 stream ids exhausted"));
        }
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        self.streams.lock().unwrap().insert(id, tx);
        // END_HEADERS | END_STREAM: the generator's requests have no
        // body (traffic.go builds GET/HEAD-style requests only).
        let out = h2_frame(H2_HEADERS, 0x4 | 0x1, id, block);
        {
            let mut w = self.writer.lock().await;
            w.write_all(&out).await?;
            w.flush().await?;
        }
        Ok((id, rx))
    }

    fn remove_stream(&self, id: u32) {
        self.streams.lock().unwrap().remove(&id);
    }
}

/// The connection reader: dispatch frames to stream channels, answer
/// SETTINGS/PING, return receive credit on DATA (the pattern of
/// trusttunnel's `h2_reader_task`, over the in-module frame codec).
async fn carrier_h2_reader(
    mut read_half: tokio::io::ReadHalf<tokio::io::DuplexStream>,
    streams: Arc<Mutex<HashMap<u32, tokio::sync::mpsc::UnboundedSender<CarrierH2Event>>>>,
    writer: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<tokio::io::DuplexStream>>>,
    dead: Arc<AtomicBool>,
) {
    let mut rbuf = BytesMut::with_capacity(16 * 1024);
    let mut tmp = [0u8; 16 * 1024];
    // Per-stream header-block assembly across CONTINUATION frames.
    let mut header_blocks: HashMap<u32, Vec<u8>> = HashMap::new();
    'conn: loop {
        while rbuf.len() >= 9 {
            let len =
                ((rbuf[0] as usize) << 16) | ((rbuf[1] as usize) << 8) | rbuf[2] as usize;
            if rbuf.len() < 9 + len {
                break;
            }
            let kind = rbuf[3];
            let flags = rbuf[4];
            let stream_id =
                u32::from_be_bytes([rbuf[5], rbuf[6], rbuf[7], rbuf[8]]) & 0x7FFF_FFFF;
            let payload = rbuf[9..9 + len].to_vec();
            rbuf.advance(9 + len);
            match kind {
                H2_SETTINGS => {
                    if flags & 0x1 == 0 {
                        // SETTINGS ACK.
                        let out = h2_frame(H2_SETTINGS, 0x1, 0, &[]);
                        let mut w = writer.lock().await;
                        if w.write_all(&out).await.is_err() {
                            break 'conn;
                        }
                    }
                }
                H2_PING => {
                    if flags & 0x1 == 0 {
                        let out = h2_frame(H2_PING, 0x1, 0, &payload);
                        let mut w = writer.lock().await;
                        if w.write_all(&out).await.is_err() {
                            break 'conn;
                        }
                    }
                }
                H2_WINDOW_UPDATE => {} // requests are bodyless; send-side flow control never binds
                H2_HEADERS | H2_CONTINUATION => {
                    let block = header_blocks.entry(stream_id).or_default();
                    block.extend_from_slice(&payload);
                    if flags & 0x4 != 0 {
                        // END_HEADERS: the response header block is whole.
                        let block = header_blocks.remove(&stream_id).unwrap_or_default();
                        let handle = streams.lock().unwrap().get(&stream_id).cloned();
                        if let Some(tx) = handle {
                            let status = hpack_decode_status(&block).unwrap_or(0);
                            let _ = tx.send(CarrierH2Event::Headers(status));
                            if flags & 0x1 != 0 {
                                let _ = tx.send(CarrierH2Event::End);
                            }
                        }
                    }
                }
                H2_DATA => {
                    let handle = streams.lock().unwrap().get(&stream_id).cloned();
                    if let Some(tx) = handle {
                        if !payload.is_empty() {
                            let _ = tx.send(CarrierH2Event::Data);
                            // Return the flow-control credit (stream and
                            // connection windows).
                            let inc = (payload.len() as u32).to_be_bytes();
                            let mut out = h2_frame(H2_WINDOW_UPDATE, 0, stream_id, &inc);
                            out.extend_from_slice(&h2_frame(H2_WINDOW_UPDATE, 0, 0, &inc));
                            let mut w = writer.lock().await;
                            if w.write_all(&out).await.is_err() {
                                break 'conn;
                            }
                        }
                        if flags & 0x1 != 0 {
                            let _ = tx.send(CarrierH2Event::End);
                        }
                    }
                }
                H2_GOAWAY => {
                    let handles: Vec<_> = streams.lock().unwrap().values().cloned().collect();
                    for tx in handles {
                        let _ = tx.send(CarrierH2Event::GoAway);
                    }
                    break 'conn;
                }
                H2_RST_STREAM => {
                    let handle = streams.lock().unwrap().remove(&stream_id);
                    if let Some(tx) = handle {
                        let _ = tx.send(CarrierH2Event::End);
                    }
                }
                _ => {} // RFC 9113: unknown frames are ignored
            }
        }
        match read_half.read(&mut tmp).await {
            Ok(0) | Err(_) => break 'conn,
            Ok(n) => rbuf.extend_from_slice(&tmp[..n]),
        }
    }
    dead.store(true, Ordering::SeqCst);
    streams.lock().unwrap().clear();
}

/// `newTrafficHTTPTransport` (traffic.go:52-73): pick the carrier
/// transport from the NEGOTIATED ALPN (client.go:96-105 passes
/// `NegotiatedProtocol`; an empty negotiation is the HTTP/1.1 arm).
///
/// Upstream closes the whole conn on an unknown ALPN (traffic.go:78-82);
/// this port stops the generator instead and leaves the carrier to the
/// mirror pump (the hidden channel then hangs rather than erroring) —
/// reachable only with a carrier ALPN that is neither `h2`, `http/1.1`
/// nor empty, i.e. a misconfigured `alpn` list.
async fn new_traffic_transport(
    carrier: tokio::io::DuplexStream,
    alpn: &str,
) -> Result<TrafficCarrier> {
    match alpn {
        "h2" => Ok(TrafficCarrier::H2(CarrierH2::handshake(carrier).await?)),
        "http/1.1" | "" => Ok(TrafficCarrier::Http1(carrier)),
        other => Err(Error::config(format!(
            "tlsmirror: unknown carrier ALPN {other:?}"
        ))),
    }
}

/// The `trafficHTTPTransport` interface (traffic.go:26-50): whichever
/// carrier protocol the generator's `RoundTrip` runs over.
enum TrafficCarrier {
    Http1(tokio::io::DuplexStream),
    H2(Arc<CarrierH2>),
}

/// `runTrafficStep` for the h2 arm (traffic.go:146-199): the request is
/// `:method`/`:scheme https`/`:authority`/`:path` plus the step headers;
/// `finishRequest` drains the body — unless
/// `h2-do-not-wait-for-download-finish` is set, when the drain continues
/// in the background (traffic.go:179-181) and the generator moves on.
async fn run_h2_step(
    transport: &Arc<CarrierH2>,
    step: &TrafficStep,
    do_not_wait: bool,
) -> Result<()> {
    let host = if step.host.is_empty() {
        "localhost".to_string()
    } else {
        step.host.clone()
    };
    let path = if step.path.is_empty() { "/".to_string() } else { step.path.clone() };
    let method = if step.method.is_empty() { "GET".to_string() } else { step.method.to_uppercase() };
    // Go's http2 client maps the URL onto the pseudo-headers and sends
    // `Host` as `:authority`; header names are lowercased on the wire.
    let mut block = Vec::with_capacity(128);
    hpack_literal_header(&mut block, ":method", &method);
    hpack_literal_header(&mut block, ":scheme", "https");
    hpack_literal_header(&mut block, ":authority", &host);
    hpack_literal_header(&mut block, ":path", &path);
    let mut has_ua = false;
    for (name, value) in &step.headers {
        if name.is_empty() {
            continue;
        }
        let name = name.to_ascii_lowercase();
        if name == "user-agent" {
            has_ua = true;
        }
        hpack_literal_header(&mut block, &name, value);
    }
    if !has_ua {
        // Go's http2 transport default.
        hpack_literal_header(&mut block, "user-agent", "Go-http-client/2.0");
    }

    let (id, mut rx) = transport.open_request(&block).await?;
    // RoundTrip resolves on the response HEADERS; a block with no
    // decodable :status is a protocol error (Go's RoundTrip fails the
    // same way).
    let status = loop {
        let event = rx
            .recv()
            .await
            .ok_or_else(|| Error::network("tlsmirror: h2 stream closed before response"))?;
        match event {
            CarrierH2Event::Headers(code) => break code,
            // DATA before HEADERS is out of order; keep draining.
            CarrierH2Event::Data => {}
            CarrierH2Event::End => {
                transport.remove_stream(id);
                return Err(Error::network(
                    "tlsmirror: h2 stream closed before response",
                ));
            }
            CarrierH2Event::GoAway => {
                transport.remove_stream(id);
                return Err(Error::network("tlsmirror: h2 connection gone"));
            }
        }
    };
    if status == 0 {
        transport.remove_stream(id);
        return Err(Error::protocol("tlsmirror: h2 response missing :status"));
    }
    if do_not_wait {
        // `go func() { _ = finishRequest() }()` (traffic.go:179-181): the
        // body drains in the background; errors are dropped.
        let transport = transport.clone();
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if matches!(event, CarrierH2Event::End | CarrierH2Event::GoAway) {
                    break;
                }
            }
            transport.remove_stream(id);
        });
        return Ok(());
    }
    // finishRequest: io.Copy(io.Discard, resp.Body) + Close — consume to
    // END_STREAM (RST/GOAWAY count as ends).
    while let Some(event) = rx.recv().await {
        if matches!(event, CarrierH2Event::End | CarrierH2Event::GoAway) {
            break;
        }
    }
    transport.remove_stream(id);
    Ok(())
}

/// `runTrafficGenerator` (traffic.go:75): the transport is built AFTER
/// the carrier handshake from the negotiated ALPN (client.go:96-105),
/// then the weighted step loop runs over it. HTTP/1.1 steps share this
/// loop with h2 steps — only the per-step transport differs.
async fn run_traffic_generator(
    carrier: tokio::io::DuplexStream,
    steps: Vec<TrafficStep>,
    mut ready: Option<tokio::sync::oneshot::Sender<()>>,
    recall: Arc<tokio::sync::Notify>,
    alpn_rx: tokio::sync::oneshot::Receiver<String>,
) {
    // The pump reports the negotiated protocol once the carrier
    // handshake completes; an error means the carrier died first.
    let alpn = match alpn_rx.await {
        Ok(alpn) => alpn,
        Err(_) => return,
    };
    let mut transport = match new_traffic_transport(carrier, &alpn).await {
        Ok(transport) => transport,
        Err(e) => {
            // Upstream closes the conn here (traffic.go:78-82); see the
            // note on new_traffic_transport for this port's deviation.
            debug!(target: "engine", "tlsmirror: carrier transport ended: {e}");
            return;
        }
    };
    let waits = traffic_generator_waits_for_ready(&steps);
    let mut current = 0usize;
    loop {
        if current >= steps.len() {
            return;
        }
        let step = &steps[current];
        let step_result = match &mut transport {
            TrafficCarrier::Http1(carrier) => run_http1_step(carrier, step).await,
            TrafficCarrier::H2(h2) => {
                run_h2_step(h2, step, step.h2_do_not_wait_for_download_finish).await
            }
        };
        if let Err(e) = step_result {
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
    connect_with(cfg, transport, None).await
}

/// The enrolment control-connection dialer
/// (`ClientConfig.EnrollmentDialer`): routes `controlHost:80` through
/// the primary ingress/egress outbounds. The address is the derived
/// `.tlsmirror-controlconnection.v2fly.arpa` host on port 80.
pub type EnrollmentDialer = std::sync::Arc<
    dyn Fn(
            crate::addr::NetAddr,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<BoxProxyStream>> + Send>>
        + Send
        + Sync,
>;

/// `Dial` with connection enrolment (client.go:136-141 →
/// `verifyConnectionEnrollment`, enrollment.go:119): after the carrier
/// is ready, confirm this (clientRandom, serverRandom) pair against the
/// server's enrolment control endpoint over h2c.
pub async fn connect_with(
    cfg: &TlsMirrorOut,
    transport: BoxProxyStream,
    enrollment_dialer: Option<EnrollmentDialer>,
) -> Result<BoxProxyStream> {
    let primary_key = decode_primary_key(&cfg.primary_key)?;
    if cfg.connection_enrolment.is_some() && enrollment_dialer.is_none() {
        return Err(Error::config(
            "tlsmirror: connection-enrolment requires an enrollment dialer \
             (primary-ingress-outbound / primary-egress-outbound routing); pass one to \
             connect_with (transport/tlsmirror/enrollment.go:119 verifyConnectionEnrollment)",
        ));
    }
    let has_generator = !cfg.traffic_generator.is_empty();
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
    let (carrier_alpn_tx, carrier_alpn_rx) = tokio::sync::oneshot::channel::<String>();

    let mirror = Mirror::new(cfg, primary_key, false);
    let pump_ready = ready.clone();
    let pump_ready_notify = ready_notify.clone();
    let defer = cfg.defer_instance_derived_write.duration();
    let (randoms_tx, randoms_rx) =
        tokio::sync::watch::channel(None::<([u8; 32], [u8; 32])>);
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
            Some(carrier_alpn_tx),
            randoms_tx,
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
            run_traffic_generator(
                carrier,
                steps,
                Some(gen_ready_tx),
                gen_recall,
                carrier_alpn_rx,
            )
            .await;
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

    if cfg.connection_enrolment.is_some() {
        // verifyConnectionEnrollment (client.go:136 → enrollment.go:119).
        let dialer = enrollment_dialer.expect("checked above");
        verify_connection_enrollment(&primary_key, &randoms_rx, &dialer).await?;
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
// Connection enrolment (enrollment.go)
// ---------------------------------------------------------------------------

/// `enrollmentControlConnectionPostfix` (enrollment.go:21).
const ENROLLMENT_CONTROL_POSTFIX: &str = ".tlsmirror-controlconnection.v2fly.arpa";

/// `enrollmentBase32` (enrollment.go:23): RFC 4648 lower alphabet with
/// digits first, no padding.
const ENROLLMENT_BASE32: &[u8; 32] = b"0123456789abcdefghijklmnopqrstuv";

fn enrollment_base32_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() * 8).div_ceil(5));
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    for byte in data {
        buffer = (buffer << 8) | u32::from(*byte);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(ENROLLMENT_BASE32[((buffer >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(ENROLLMENT_BASE32[((buffer << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

/// `deriveSecondaryKey` (enrollment.go:187): HKDF-SHA256 with the
/// primary key as PRK under the v2ray secondary-key namespace.
fn derive_secondary_key(primary_key: &[u8; 32], tag: &str) -> Result<[u8; 16]> {
    let hk = Hkdf::<Sha256>::from_prk(primary_key)
        .map_err(|_| Error::crypto("tlsmirror: prk"))?;
    let mut key = [0u8; 16];
    hk.expand(
        format!("v2ray-sv77RCEY-e8AhYsbD-BmFC7XRK:tlsmirror-secondary{tag}").as_bytes(),
        &mut key,
    )
    .map_err(|_| Error::crypto("tlsmirror: hkdf expand secondary"))?;
    Ok(key)
}

/// `deriveEnrollmentServerIdentifier` (enrollment.go:183).
fn derive_enrollment_server_identifier(primary_key: &[u8; 32]) -> Result<[u8; 16]> {
    derive_secondary_key(
        primary_key,
        ":connection-enrollment-server-identifier-av38NNGF-TJvRw7C3-p8KM8yKd",
    )
}

/// `deriveEnrollmentRequestKey` (enrollment.go:198): the 16-byte
/// encryption key half of `deriveEncryptionKey` under the enrolment tag.
fn derive_enrollment_request_key(
    primary_key: &[u8; 32],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Result<[u8; 16]> {
    let (key, _mask) = derive_encryption_key(
        primary_key,
        client_random,
        server_random,
        ":connection-enrollment-re78HQNM-CmpRnPbr-PNJVRMhu",
    )?;
    Ok(key)
}

/// `ServerIdentifierHost` (enrollment.go:61): the control-connection
/// host the client dials on TCP :80 and the server intercepts.
pub fn server_identifier_host(primary_key: &str) -> Result<String> {
    let key = decode_primary_key(primary_key)?;
    let id = derive_enrollment_server_identifier(&key)?;
    Ok(format!(
        "{}{ENROLLMENT_CONTROL_POSTFIX}",
        enrollment_base32_encode(&id)
    ))
}

/// The active-enrolment table (`enrollmentProcessors`, enrollment.go:203):
/// request keys of served mirrors, per primary key.
fn enrollment_active() -> &'static std::sync::Mutex<std::collections::HashSet<Vec<u8>>> {
    static ACTIVE: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<Vec<u8>>>> =
        std::sync::OnceLock::new();
    ACTIVE.get_or_init(|| std::sync::Mutex::new(std::collections::HashSet::new()))
}

/// `enrollmentProcessor.add` (enrollment.go:220): register a served
/// mirror's handshake randoms; errors on duplicates (replay). Returns a
/// guard that removes the entry (`remove`).
fn enrollment_add(
    primary_key: &[u8; 32],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> Result<EnrollmentGuard> {
    let request_key =
        derive_enrollment_request_key(primary_key, client_random, server_random)?;
    let mut active = enrollment_active().lock().unwrap_or_else(|e| e.into_inner());
    if !active.insert(request_key.to_vec()) {
        return Err(Error::protocol(
            "tlsmirror: enrollment connection already exists",
        ));
    }
    drop(active);
    Ok(EnrollmentGuard { request_key: Some(request_key.to_vec()) })
}

/// Removes the entry on drop (`hidden.setEnrollmentRemove`, server.go:63).
struct EnrollmentGuard {
    request_key: Option<Vec<u8>>,
}

impl Drop for EnrollmentGuard {
    fn drop(&mut self) {
        if let Some(key) = self.request_key.take() {
            enrollment_active()
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .remove(&key);
        }
    }
}

/// `enrollmentProcessor.verify` (enrollment.go:233).
fn enrollment_verify(
    primary_key: &[u8; 32],
    client_random: &[u8; 32],
    server_random: &[u8; 32],
) -> bool {
    match derive_enrollment_request_key(primary_key, client_random, server_random) {
        Ok(request_key) => enrollment_active()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .contains(&request_key.to_vec()),
        Err(_) => false,
    }
}

// -- the enrollment protobuf (enrollment.go:248-432) --------------------------

/// `enrollmentConfirmationReq` (enrollment.go:31). Fields 1-5 are bytes;
/// only 1-3 are populated by either side today.
#[derive(Default, Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentConfirmationReq {
    pub server_identifier: Vec<u8>,
    pub client_random: Vec<u8>,
    pub server_random: Vec<u8>,
    pub client_identifier: Vec<u8>,
    pub reply_address_tag: Vec<u8>,
}

/// `marshalEnrollmentConfirmationReq` (enrollment.go:248).
pub(crate) fn marshal_enrollment_req(req: &EnrollmentConfirmationReq) -> Vec<u8> {
    let mut out = Vec::new();
    append_proto_bytes(&mut out, 1, &req.server_identifier);
    append_proto_bytes(&mut out, 2, &req.client_random);
    append_proto_bytes(&mut out, 3, &req.server_random);
    append_proto_bytes(&mut out, 4, &req.client_identifier);
    append_proto_bytes(&mut out, 5, &req.reply_address_tag);
    out
}

/// `unmarshalEnrollmentConfirmationReq` (enrollment.go:258).
fn unmarshal_enrollment_req(data: &[u8]) -> Result<EnrollmentConfirmationReq> {
    let mut req = EnrollmentConfirmationReq::default();
    let mut data = data;
    while !data.is_empty() {
        let (key, n) = consume_proto_varint(data)?;
        data = &data[n..];
        let field = usize::try_from(key >> 3)
            .map_err(|_| Error::protocol("tlsmirror: invalid protobuf field number"))?;
        let wire_type = key & 0x7;
        if field == 0 {
            return Err(Error::protocol("tlsmirror: invalid protobuf field number"));
        }
        if wire_type == 2 {
            let (size, n) = consume_proto_varint(data)?;
            data = &data[n..];
            let size = usize::try_from(size)
                .map_err(|_| Error::protocol("tlsmirror: protobuf length overflow"))?;
            if data.len() < size {
                return Err(Error::network("tlsmirror: unexpected EOF"));
            }
            let value = data[..size].to_vec();
            data = &data[size..];
            match field {
                1 => req.server_identifier = value,
                2 => req.client_random = value,
                3 => req.server_random = value,
                4 => req.client_identifier = value,
                5 => req.reply_address_tag = value,
                _ => {}
            }
            continue;
        }
        let n = skip_proto_value(data, field, wire_type)?;
        data = &data[n..];
    }
    Ok(req)
}

/// `marshalEnrollmentConfirmationResp` (enrollment.go:305).
fn marshal_enrollment_resp(enrolled: bool) -> Vec<u8> {
    if !enrolled {
        return Vec::new();
    }
    let mut out = Vec::new();
    append_proto_varint(&mut out, (1 << 3) as u64);
    append_proto_varint(&mut out, 1);
    out
}

/// `unmarshalEnrollmentConfirmationResp` (enrollment.go:313).
fn unmarshal_enrollment_resp(data: &[u8]) -> Result<bool> {
    let mut enrolled = false;
    let mut data = data;
    while !data.is_empty() {
        let (key, n) = consume_proto_varint(data)?;
        data = &data[n..];
        let field = usize::try_from(key >> 3)
            .map_err(|_| Error::protocol("tlsmirror: invalid protobuf field number"))?;
        let wire_type = key & 0x7;
        if field == 0 {
            return Err(Error::protocol("tlsmirror: invalid protobuf field number"));
        }
        if field == 1 && wire_type == 0 {
            let (value, n) = consume_proto_varint(data)?;
            data = &data[n..];
            enrolled = value != 0;
            continue;
        }
        let n = skip_proto_value(data, field, wire_type)?;
        data = &data[n..];
    }
    Ok(enrolled)
}

fn append_proto_bytes(out: &mut Vec<u8>, field: usize, value: &[u8]) {
    if value.is_empty() {
        return;
    }
    append_proto_varint(out, ((field << 3) | 2) as u64);
    append_proto_varint(out, value.len() as u64);
    out.extend_from_slice(value);
}

fn append_proto_varint(out: &mut Vec<u8>, mut value: u64) {
    while value >= 0x80 {
        out.push(value as u8 | 0x80);
        value >>= 7;
    }
    out.push(value as u8);
}

fn consume_proto_varint(data: &[u8]) -> Result<(u64, usize)> {
    let mut value: u64 = 0;
    for (i, b) in data.iter().enumerate() {
        if i == 10 {
            return Err(Error::protocol("tlsmirror: invalid protobuf varint"));
        }
        value |= u64::from(b & 0x7f) << (7 * i);
        if b < &0x80 {
            return Ok((value, i + 1));
        }
    }
    Err(Error::network("tlsmirror: unexpected EOF"))
}

fn skip_proto_value(data: &[u8], start_field: usize, wire_type: u64) -> Result<usize> {
    match wire_type {
        0 => Ok(consume_proto_varint(data)?.1),
        1 => {
            if data.len() < 8 {
                return Err(Error::network("tlsmirror: unexpected EOF"));
            }
            Ok(8)
        }
        2 => {
            let (size, n) = consume_proto_varint(data)?;
            let size = usize::try_from(size)
                .map_err(|_| Error::protocol("tlsmirror: protobuf length overflow"))?;
            if data.len() < n + size {
                return Err(Error::network("tlsmirror: unexpected EOF"));
            }
            Ok(n + size)
        }
        3 => {
            // Deprecated group: skip until the matching end-group.
            let mut data = data;
            let mut consumed = 0usize;
            loop {
                let (key, n) = consume_proto_varint(data)?;
                data = &data[n..];
                consumed += n;
                let nested_field = usize::try_from(key >> 3)
                    .map_err(|_| Error::protocol("tlsmirror: invalid protobuf field number"))?;
                let nested_wire = key & 0x7;
                if nested_field == 0 {
                    return Err(Error::protocol("tlsmirror: invalid protobuf field number"));
                }
                if nested_wire == 4 {
                    if nested_field != start_field {
                        return Err(Error::protocol(
                            "tlsmirror: mismatched protobuf end group",
                        ));
                    }
                    return Ok(consumed);
                }
                let n = skip_proto_value(data, nested_field, nested_wire)?;
                data = &data[n..];
                consumed += n;
            }
        }
        4 => Err(Error::protocol("tlsmirror: unexpected protobuf end group")),
        5 => {
            if data.len() < 4 {
                return Err(Error::network("tlsmirror: unexpected EOF"));
            }
            Ok(4)
        }
        other => Err(Error::protocol(format!(
            "tlsmirror: unsupported enrollment protobuf wire type {other}"
        ))),
    }
}

// -- minimal h2c (unencrypted HTTP/2 prior knowledge, RFC 9113) ---------------

/// The connection preface every h2c client sends first.
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const H2_DATA: u8 = 0x0;
const H2_HEADERS: u8 = 0x1;
const H2_SETTINGS: u8 = 0x4;
const H2_PING: u8 = 0x6;
const H2_GOAWAY: u8 = 0x7;
const H2_WINDOW_UPDATE: u8 = 0x8;
const H2_CONTINUATION: u8 = 0x9;
const H2_RST_STREAM: u8 = 0x3;

fn h2_frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(9 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..]);
    out.push(kind);
    out.push(flags);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(payload);
    out
}

async fn h2_read_frame(
    io: &mut BoxProxyStream,
) -> Result<(u8, u8, u32, Vec<u8>)> {
    let mut head = [0u8; 9];
    io.read_exact(&mut head).await?;
    let len = (u32::from(head[0]) << 16 | u32::from(head[1]) << 8 | u32::from(head[2])) as usize;
    let kind = head[3];
    let flags = head[4];
    let stream = u32::from_be_bytes([head[5], head[6], head[7], head[8]]);
    let mut payload = vec![0u8; len];
    io.read_exact(&mut payload).await?;
    Ok((kind, flags, stream, payload))
}

/// HPACK literal-without-indexing string (RFC 7541 §6.2.2, no Huffman).
fn hpack_string(out: &mut Vec<u8>, value: &[u8]) {
    hpack_integer(out, value.len() as u64, 7, 0x00);
    out.extend_from_slice(value);
}

/// HPACK integer encoding with an N-bit prefix (RFC 7541 §5.1).
fn hpack_integer(out: &mut Vec<u8>, value: u64, prefix_bits: u32, first_byte: u8) {
    let max = (1u64 << prefix_bits) - 1;
    if value < max {
        out.push(first_byte | value as u8);
        return;
    }
    out.push(first_byte | max as u8);
    let mut rest = value - max;
    while rest >= 0x80 {
        out.push(rest as u8 | 0x80);
        rest >>= 7;
    }
    out.push(rest as u8);
}

/// One HPACK header field, literal without indexing, new name.
fn hpack_literal_header(out: &mut Vec<u8>, name: &str, value: &str) {
    out.push(0x00);
    hpack_string(out, name.as_bytes());
    hpack_string(out, value.as_bytes());
}

/// Decode `:status` from a header block wedge: indexed static entries
/// and plain literals decode; Huffman literals are refused (the Go h2
/// server emits the standard statuses as static-indexed).
fn hpack_decode_status(block: &[u8]) -> Result<u16> {
    let mut pos = 0usize;
    let mut status: Option<u16> = None;
    while pos < block.len() {
        let b0 = block[pos];
        if b0 & 0x80 != 0 {
            // Indexed header field (static table only here).
            let (idx, n) = hpack_integer_read(block, pos, 7)?;
            pos += n;
            let code = match idx {
                8 => Some(200),
                9 => Some(204),
                10 => Some(206),
                11 => Some(304),
                12 => Some(400),
                13 => Some(404),
                14 => Some(500),
                _ => None,
            };
            if let Some(code) = code {
                status = Some(code);
            }
            continue;
        }
        if b0 & 0xc0 == 0x40 || b0 & 0xf0 == 0x00 || b0 & 0xf0 == 0x10 {
            // Literal (with/without indexing / never indexed): the
            // 6- or 4-bit prefix name index, 0 = literal name.
            let literal_prefix = if b0 & 0xc0 == 0x40 { 6 } else { 4 };
            let (name_idx, n) = hpack_integer_read(block, pos, literal_prefix)?;
            pos += n;
            let name = if name_idx == 0 {
                let (v, n) = hpack_string_read(block, pos)?;
                pos += n;
                v
            } else {
                // Indexed name: never :status in the static table.
                Vec::new()
            };
            let (value, n) = hpack_string_read(block, pos)?;
            pos += n;
            if name_idx == 0 && name == b":status" {
                let text = std::str::from_utf8(&value)
                    .map_err(|_| Error::protocol("tlsmirror: h2 :status not utf-8"))?;
                status = Some(
                    text.parse()
                        .map_err(|_| Error::protocol("tlsmirror: h2 :status not numeric"))?,
                );
            }
            continue;
        }
        if b0 & 0xe0 == 0x20 {
            // Dynamic table size update: skip the integer.
            let (_size, n) = hpack_integer_read(block, pos, 5)?;
            pos += n;
            continue;
        }
        return Err(Error::protocol("tlsmirror: unsupported HPACK entry"));
    }
    status.ok_or_else(|| Error::protocol("tlsmirror: h2 response missing :status"))
}

fn hpack_integer_read(block: &[u8], pos: usize, prefix_bits: u32) -> Result<(u64, usize)> {
    let Some(&first) = block.get(pos) else {
        return Err(Error::network("tlsmirror: hpack truncated"));
    };
    let max = (1u64 << prefix_bits) - 1;
    let mut value = u64::from(first) & max;
    if value < max {
        return Ok((value, 1));
    }
    let mut shift = 0u32;
    let mut n = 1usize;
    loop {
        let Some(&b) = block.get(pos + n) else {
            return Err(Error::network("tlsmirror: hpack truncated"));
        };
        n += 1;
        value += u64::from(b & 0x7f) << shift;
        if b & 0x80 == 0 {
            return Ok((value, n));
        }
        shift += 7;
        if shift > 42 {
            return Err(Error::protocol("tlsmirror: hpack integer overflow"));
        }
    }
}

fn hpack_string_read(block: &[u8], pos: usize) -> Result<(Vec<u8>, usize)> {
    let Some(&first) = block.get(pos) else {
        return Err(Error::network("tlsmirror: hpack truncated"));
    };
    let huffman = first & 0x80 != 0;
    let (len, n) = hpack_integer_read(block, pos, 7)?;
    let len = usize::try_from(len)
        .map_err(|_| Error::protocol("tlsmirror: hpack length overflow"))?;
    let start = pos + n;
    let end = start + len;
    if block.len() < end {
        return Err(Error::network("tlsmirror: hpack truncated"));
    }
    if huffman {
        return Err(Error::protocol(
            "tlsmirror: huffman-coded HPACK string is not supported",
        ));
    }
    Ok((block[start..end].to_vec(), n + len))
}

/// `newTrafficHTTPTransport(conn, "h2")` + `RoundTrip` for the one POST
/// the enrolment handshake issues (enrollment.go:151-165): h2c with
/// prior knowledge over the dialed control connection.
pub(crate) async fn h2c_post(
    mut io: BoxProxyStream,
    host: &str,
    body: &[u8],
) -> Result<(u16, Vec<u8>)> {
    // Preface + a large initial window (the request is small but be
    // generous with the response path).
    io.write_all(H2_PREFACE).await?;
    let mut settings = Vec::new();
    // SETTINGS_INITIAL_WINDOW_SIZE (0x4) = 1 MiB.
    settings.extend_from_slice(&0x4u16.to_be_bytes());
    settings.extend_from_slice(&(1u32 << 20).to_be_bytes());
    io.write_all(&h2_frame(H2_SETTINGS, 0, 0, &settings)).await?;

    // HEADERS on stream 1: literal-without-indexing, no Huffman.
    let mut block = Vec::new();
    hpack_literal_header(&mut block, ":method", "POST");
    hpack_literal_header(&mut block, ":scheme", "http");
    hpack_literal_header(&mut block, ":authority", host);
    hpack_literal_header(&mut block, ":path", "/");
    hpack_literal_header(&mut block, "content-type", "application/octet-stream");
    hpack_literal_header(&mut block, "content-length", &body.len().to_string());
    io.write_all(&h2_frame(H2_HEADERS, 0x4 /* END_HEADERS */, 1, &block))
        .await?;
    io.write_all(&h2_frame(H2_DATA, 0x1 /* END_STREAM */, 1, body))
        .await?;

    let mut status: Option<u16> = None;
    let mut resp_body = Vec::new();
    let mut header_block: Vec<u8> = Vec::new();
    let mut headers_done = false;
    let mut stream_done = false;
    while !stream_done || !headers_done {
        let (kind, flags, stream, payload) = h2_read_frame(&mut io).await?;
        match kind {
            H2_SETTINGS => {
                if flags & 0x1 == 0 {
                    // Best-effort ACK: the one-shot control peer may
                    // return as soon as its response is flushed.
                    let _ = io.write_all(&h2_frame(H2_SETTINGS, 0x1, 0, &[])).await;
                }
            }
            H2_WINDOW_UPDATE => {}
            H2_HEADERS | H2_CONTINUATION => {
                if stream != 1 {
                    continue;
                }
                header_block.extend_from_slice(&payload);
                if flags & 0x4 != 0 {
                    // END_HEADERS
                    status = Some(hpack_decode_status(&header_block)?);
                    headers_done = true;
                }
                if flags & 0x1 != 0 {
                    stream_done = true;
                }
            }
            H2_DATA => {
                if stream != 1 {
                    continue;
                }
                if !payload.is_empty() {
                    resp_body.extend_from_slice(&payload);
                    // Keep the peer's flow-control window healthy
                    // (best-effort, see SETTINGS above).
                    let inc = h2_frame(H2_WINDOW_UPDATE, 0, 0, &payload.len().to_be_bytes());
                    let _ = io.write_all(&inc).await;
                }
                if flags & 0x1 != 0 {
                    stream_done = true;
                }
            }
            H2_PING => {
                if flags & 0x1 == 0 {
                    let _ = io.write_all(&h2_frame(H2_PING, 0x1, 0, &payload)).await;
                }
            }
            H2_GOAWAY => {
                return Err(Error::network("tlsmirror: h2c GOAWAY"));
            }
            _ => {} // unknown frame types are ignored per RFC 9113
        }
    }
    let status = status.ok_or_else(|| Error::protocol("tlsmirror: h2c no :status"))?;
    Ok((status, resp_body))
}

/// `ServeEnrollmentControlConnection` (enrollment.go:69): serve the
/// h2c confirmation endpoint on ONE intercepted TCP connection. The
/// listener (or the integrator's intercept hook) hands the control
/// connection here; it answers exactly the enrollment confirmation.
pub async fn serve_enrollment_control_connection(
    mut io: BoxProxyStream,
    primary_key: &str,
) -> Result<()> {
    let key = decode_primary_key(primary_key)?;
    // Preface, then one request.
    let mut preface = vec![0u8; H2_PREFACE.len()];
    io.read_exact(&mut preface).await?;
    if preface != H2_PREFACE {
        return Err(Error::protocol(
            "tlsmirror: enrollment control connection: not an h2c preface",
        ));
    }
    io.write_all(&h2_frame(H2_SETTINGS, 0, 0, &[])).await?;
    let mut body = Vec::new();
    let mut stream_done = false;
    let mut request_stream: Option<u32> = None;
    while !stream_done {
        let (kind, flags, stream, payload) = h2_read_frame(&mut io).await?;
        match kind {
            H2_SETTINGS => {
                if flags & 0x1 == 0 {
                    let _ = io.write_all(&h2_frame(H2_SETTINGS, 0x1, 0, &[])).await;
                }
            }
            H2_WINDOW_UPDATE | H2_CONTINUATION | H2_HEADERS => {
                // The request headers are not inspected upstream either
                // (the handler reads only the body).
            }
            H2_DATA => {
                if Some(stream) != request_stream && request_stream.is_none() {
                    request_stream = Some(stream);
                }
                if !payload.is_empty() {
                    body.extend_from_slice(&payload);
                    let inc = h2_frame(H2_WINDOW_UPDATE, 0, 0, &payload.len().to_be_bytes());
                    let _ = io.write_all(&inc).await;
                }
                if flags & 0x1 != 0 {
                    stream_done = true;
                }
            }
            H2_PING => {
                if flags & 0x1 == 0 {
                    let _ = io.write_all(&h2_frame(H2_PING, 0x1, 0, &payload)).await;
                }
            }
            H2_GOAWAY => return Ok(()),
            _ => {}
        }
    }
    let stream = request_stream.unwrap_or(1);
    // verify (enrollment.go:233): membership in the active table.
    let req = unmarshal_enrollment_req(&body)?;
    let enrolled = if req.client_random.len() == 32 && req.server_random.len() == 32 {
        let mut cr = [0u8; 32];
        cr.copy_from_slice(&req.client_random);
        let mut sr = [0u8; 32];
        sr.copy_from_slice(&req.server_random);
        enrollment_verify(&key, &cr, &sr)
    } else {
        false
    };
    let resp_body = marshal_enrollment_resp(enrolled);
    let mut block = Vec::new();
    hpack_literal_header(&mut block, ":status", "200");
    hpack_literal_header(&mut block, "content-type", "application/octet-stream");
    hpack_literal_header(&mut block, "content-length", &resp_body.len().to_string());
    io.write_all(&h2_frame(H2_HEADERS, 0x4, stream, &block)).await?;
    io.write_all(&h2_frame(H2_DATA, 0x1, stream, &resp_body)).await?;
    let _ = io.flush().await;
    Ok(())
}

/// `verifyConnectionEnrollment` (enrollment.go:119): the client side of
/// the control protocol — dial `controlHost:80`, POST the confirmation
/// request over h2c, require `enrolled`.
async fn verify_connection_enrollment(
    primary_key: &[u8; 32],
    randoms_rx: &tokio::sync::watch::Receiver<Option<([u8; 32], [u8; 32])>>,
    dialer: &EnrollmentDialer,
) -> Result<()> {
    let mut rx = randoms_rx.clone();
    let (client_random, server_random) = match tokio::time::timeout(
        Duration::from_secs(30),
        rx.wait_for(|r| r.is_some()),
    )
    .await
    {
        Ok(Ok(value)) => value.ok_or_else(|| Error::network("tlsmirror: handshake randoms lost")),
        _ => Err(Error::network(
            "tlsmirror: carrier handshake randoms never became available",
        )),
    }?;
    let server_id = derive_enrollment_server_identifier(primary_key)?;
    let host = format!(
        "{}{ENROLLMENT_CONTROL_POSTFIX}",
        enrollment_base32_encode(&server_id)
    );
    let target = crate::addr::NetAddr::domain(&host, 80)?;
    let control = dialer(target).await?;
    let req = marshal_enrollment_req(&EnrollmentConfirmationReq {
        server_identifier: server_id.to_vec(),
        client_random: client_random.to_vec(),
        server_random: server_random.to_vec(),
        client_identifier: Vec::new(),
        reply_address_tag: Vec::new(),
    });
    let (status, resp_body) = h2c_post(control, &host, &req).await?;
    if status != 200 {
        return Err(Error::protocol(format!(
            "tlsmirror: unexpected enrollment response status {status}"
        )));
    }
    let enrolled = unmarshal_enrollment_resp(&resp_body)?;
    if !enrolled {
        return Err(Error::protocol("tlsmirror: connection enrollment failed"));
    }
    Ok(())
}

/// Is the target the enrolment control endpoint for this primary key?
/// The integrator's intercept hook (upstream `enrollmentTunnel`,
/// listener/tlsmirror/tlsmirror.go:73) matches exactly this: TCP, port
/// 80, host equal to the derived control host (case-insensitive).
pub fn is_enrollment_control_target(target: &crate::addr::NetAddr, primary_key: &str) -> bool {
    if target.port != 80 {
        return false;
    }
    let Some(host) = target.host.as_domain() else {
        return false;
    };
    match server_identifier_host(primary_key) {
        Ok(control_host) => host.eq_ignore_ascii_case(&control_host),
        Err(_) => false,
    }
}

// ---------------------------------------------------------------------------
// The server half (server.go ServeConnReady + serveConn + mirror.go)
// ---------------------------------------------------------------------------

/// `ServerConfig` = `Config` (tlsmirror config.go:53): what the server
/// mirror needs. Built from the listener config.
#[derive(Debug, Clone)]
pub struct TlsMirrorServerConfig {
    pub primary_key: String,
    pub explicit_nonce_cipher_suites: Vec<u16>,
    pub defer_instance_derived_write: TimeSpec,
    pub transport_layer_padding: bool,
    pub connection_enrolment: Option<(String, String)>,
    pub sequence_watermarking_enabled: bool,
}

impl TlsMirrorServerConfig {
    /// The same shape as a client `TlsMirrorOut` minus the carrier knobs.
    pub fn as_out(&self) -> TlsMirrorOut {
        TlsMirrorOut {
            primary_key: self.primary_key.clone(),
            explicit_nonce_cipher_suites: self.explicit_nonce_cipher_suites.clone(),
            defer_instance_derived_write: self.defer_instance_derived_write,
            transport_layer_padding: self.transport_layer_padding,
            connection_enrolment: self.connection_enrolment.clone(),
            traffic_generator: Vec::new(),
            sequence_watermarking_enabled: self.sequence_watermarking_enabled,
            server_name: "tlsmirror-server".to_string(),
            skip_cert_verify: true,
            alpn: Vec::new(),
            client_fingerprint: String::new(),
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
        }
    }
}

/// `ServeConnReady` (server.go:8): the server mirror between the client
/// conn and the pre-dialed forward conn; returns the hidden stream once
/// the FIRST hidden record from the client decrypts (the `activated`
/// transition). Carrier records pass through in both directions; hidden
/// records the server writes are inserted into its s2c flow.
///
/// When the client never activates the hidden channel (a plain TLS
/// client hitting the port — `peekFirstHandshakeRecord` fallback,
/// mirror.go:303) the mirror degenerates into a bidirectional
/// passthrough and this future resolves to an error when either side
/// closes; the camouflage relay has already happened by then.
pub async fn serve_conn_ready(
    client_io: BoxProxyStream,
    forward_io: BoxProxyStream,
    cfg: &TlsMirrorServerConfig,
) -> Result<BoxProxyStream> {
    let key = decode_primary_key(&cfg.primary_key)?;
    let out_cfg = cfg.as_out();
    let mirror = Arc::new(tokio::sync::Mutex::new(Mirror::new(&out_cfg, key, true)));
    let (hidden_tx, hidden_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (insert_tx, insert_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
    let (ready_tx, ready_rx) = tokio::sync::oneshot::channel::<BoxProxyStream>();
    let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let recall = Arc::new(tokio::sync::Notify::new());

    let (client_rd, mut client_wr) = tokio::io::split(client_io);
    let (mut forward_rd, mut forward_wr) = tokio::io::split(forward_io);

    // The hidden stream exists up front; the c2s task holds it until the
    // first hidden record decrypts, then hands it over (serveConn's
    // `activated` → onReady, server.go:41-52).
    let hidden_stream = Box::new(TlsMirrorStream {
        hidden_rx,
        insert_tx: insert_tx.clone(),
        recall: recall.clone(),
        pending: BytesMut::new(),
        closed: false,
        alive: alive.clone(),
    });

    // c2s relay (mirror.go c2sWorker + serveConn's onC2SMessage):
    // extract hidden records, forward the rest, signal ready on the
    // first extraction.
    let c2s_mirror = mirror.clone();
    let c2s_hidden = hidden_tx.clone();
    let c2s = tokio::spawn(async move {
        let mut rd = client_rd;
        let mut first = true;
        let mut rbuf = BytesMut::with_capacity(16 * 1024);
        let mut tmp = [0u8; 16 * 1024];
        let mut hidden_stream = Some(hidden_stream);
        let mut ready_tx = Some(ready_tx);
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
                let extracted =
                    m.handle_inbound_record(&record[RECORD_HEADER_LEN..], rec_type);
                drop(m);
                match extracted {
                    Some(payload) => {
                        if !payload.is_empty() {
                            let _ = c2s_hidden.send(payload);
                        }
                        if let (Some(tx), Some(stream)) = (ready_tx.take(), hidden_stream.take())
                        {
                            let _ = tx.send(stream);
                        }
                    }
                    None => {
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

    // s2c relay (mirror.go s2cWorker + recordWriter): forward carrier
    // records (watermarked), insert the server's hidden records, enrol
    // on the forward's first handshake record (server.go:53-66). The
    // enrolment guard lives here: when this task ends the entry is
    // removed (`mirror.onClose = hidden.removeEnrollment`, server.go:77).
    let s2c_mirror = mirror.clone();
    let s2c_cfg_enrol = cfg.connection_enrolment.is_some();
    let mut defer = cfg.defer_instance_derived_write.duration();
    let mut insert_rx = insert_rx;
    let s2c = tokio::spawn(async move {
        let mut first = true;
        let mut rbuf = BytesMut::with_capacity(16 * 1024);
        let mut tmp = [0u8; 16 * 1024];
        let mut pending: Vec<Vec<u8>> = Vec::new();
        let mut enrolment: Option<EnrollmentGuard> = None;
        loop {
            while rbuf.len() >= RECORD_HEADER_LEN {
                let rlen = u16::from_be_bytes([rbuf[3], rbuf[4]]) as usize;
                if rbuf.len() < RECORD_HEADER_LEN + rlen {
                    break;
                }
                let mut record = rbuf.split_to(RECORD_HEADER_LEN + rlen).to_vec();
                let rec_type = record[0];
                let mut m = s2c_mirror.lock().await;
                if first && rec_type == REC_HANDSHAKE {
                    if let Some((random, suite)) = parse_server_hello(&record[RECORD_HEADER_LEN..])
                    {
                        m.server_random = Some(random);
                        m.tls12_explicit = m.explicit_suites.contains(&suite);
                    }
                    first = false;
                }
                if s2c_cfg_enrol && rec_type == REC_HANDSHAKE && enrolment.is_none() {
                    if let (Some(cr), Some(sr)) = (m.client_random, m.server_random) {
                        if let Ok(guard) = enrollment_add(&key, &cr, &sr) {
                            enrolment = Some(guard);
                        }
                    }
                }
                m.apply_watermark_tx(&mut record[RECORD_HEADER_LEN..], rec_type, false);
                drop(m);
                if client_wr.write_all(&record).await.is_err() {
                    return;
                }
            }
            // Server hidden inserts (Conn.Write server side, with the
            // deferred first write — firstWriteDelay, conn.go:178-195).
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
                    if !defer.is_zero() {
                        tokio::time::sleep(defer).await;
                        defer = Duration::ZERO;
                    }
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
                        // The hidden stream is gone: teardown (the guard
                        // above drops with this task's return).
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

    // Wait for activation (server.go:19-27). The unused sender half of
    // the hidden channel stays here: when serve_conn_ready returns, the
    // extraction sender that remains (c2s task's) keeps it alive.
    let _ = hidden_tx;
    // A finished task means its side of the carrier closed; the select
    // moves the handles (on the ready path the surviving tasks detach
    // and keep serving the mirror).
    let hidden = match tokio::select! {
        ready = ready_rx => ready.map_err(|_| {
            Error::protocol("tlsmirror: mirror ended before the hidden channel activated")
        }),
        _ = c2s => Err(Error::protocol(
            "tlsmirror: client carrier closed before the hidden channel activated",
        )),
        _ = s2c => Err(Error::protocol(
            "tlsmirror: forward carrier closed before the hidden channel activated",
        )),
    } {
        Ok(hidden) => hidden,
        Err(e) => return Err(e),
    };
    Ok(hidden)
}


// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use std::time::{Duration, Instant};

    /// The h2 carrier server's request log: `(stream id, HPACK block)`.
    type H2Requests = Arc<StdMutex<Vec<(u32, Vec<u8>)>>>;

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

    // ------------------------------------------------- h2 carrier generator

    fn h2_carrier_server_config(alpn: &str) -> Arc<rustls::ServerConfig> {
        let certified = rcgen::generate_simple_self_signed(vec!["carrier.example".to_string()])
            .expect("rcgen self-signed cert");
        let cert = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
        let key = rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let provider = Arc::new(ring_provider::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .expect("server config");
        config.alpn_protocols = vec![alpn.as_bytes().to_vec()];
        Arc::new(config)
    }

    /// The camouflage carrier speaking h2 after the TLS handshake: the
    /// in-test h2 server answering every complete request stream with
    /// `:status 200` + a small body. Logs `(stream id, header block)` per
    /// request. `hang_first` leaves stream 1's download dangling (HEADERS
    /// only, no END_STREAM) — the `h2-do-not-wait-for-download-finish`
    /// scenario.
    fn spawn_forward_server_h2(
        alpn: &str,
        hang_first: bool,
        requests: H2Requests,
    ) -> BoxProxyStream {
        let (mirror_side, server_side) = tokio::io::duplex(64 * 1024);
        let config = h2_carrier_server_config(alpn);
        tokio::spawn(async move {
            let mut tls = match rustls::ServerConnection::new(config) {
                Ok(t) => t,
                Err(_) => return,
            };
            let mut io = server_side;
            let mut tls_out = Vec::new();
            // TLS handshake (same drive loop as spawn_forward_server).
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
                if !tls.is_handshaking() {
                    break;
                }
                let mut tmp = [0u8; 16 * 1024];
                let n = match io.read(&mut tmp).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                let mut cursor = &tmp[..n];
                if tls.read_tls(&mut cursor).is_err() || tls.process_new_packets().is_err() {
                    return;
                }
            }

            let mut plain = BytesMut::new();
            let mut tmp = [0u8; 16 * 1024];
            let mut header_blocks: HashMap<u32, Vec<u8>> = HashMap::new();
            let mut preface_done = false;
            loop {
                // Pull decrypted h2 plaintext.
                {
                    use std::io::Read as _;
                    let mut buf = [0u8; 16 * 1024];
                    loop {
                        let n = tls.reader().read(&mut buf).unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        plain.extend_from_slice(&buf[..n]);
                    }
                }
                // The client preface precedes every frame.
                if !preface_done {
                    if plain.len() < H2_PREFACE.len() {
                        // Need more bytes; fall through to the socket read.
                    } else if &plain[..H2_PREFACE.len()] == H2_PREFACE {
                        plain.advance(H2_PREFACE.len());
                        preface_done = true;
                        // Our own SETTINGS, like any real h2 server.
                        let _ = tls.writer().write_all(&h2_frame(H2_SETTINGS, 0, 0, &[]));
                    } else {
                        return; // not an h2c client
                    }
                }
                while plain.len() >= 9 {
                    let len = ((plain[0] as usize) << 16)
                        | ((plain[1] as usize) << 8)
                        | plain[2] as usize;
                    if plain.len() < 9 + len {
                        break;
                    }
                    let kind = plain[3];
                    let flags = plain[4];
                    let stream =
                        u32::from_be_bytes([plain[5], plain[6], plain[7], plain[8]]) & 0x7FFF_FFFF;
                    let payload = plain[9..9 + len].to_vec();
                    plain.advance(9 + len);
                    match kind {
                        H2_SETTINGS => {
                            if flags & 0x1 == 0 {
                                let _ = tls.writer().write_all(&h2_frame(H2_SETTINGS, 0x1, 0, &[]));
                            }
                        }
                        H2_PING => {
                            if flags & 0x1 == 0 {
                                let _ = tls.writer().write_all(&h2_frame(H2_PING, 0x1, 0, &payload));
                            }
                        }
                        H2_HEADERS | H2_CONTINUATION => {
                            let block = header_blocks.entry(stream).or_default();
                            block.extend_from_slice(&payload);
                            if flags & 0x4 != 0 {
                                let block = header_blocks.remove(&stream).unwrap_or_default();
                                requests.lock().unwrap().push((stream, block));
                                // :status 200 (static 0x88); hang_first
                                // leaves stream 1's BODY dangling (no
                                // DATA/END_STREAM) — the download that
                                // never finishes.
                                let _ = tls
                                    .writer()
                                    .write_all(&h2_frame(H2_HEADERS, 0x4, stream, &[0x88]));
                                if !(hang_first && stream == 1) {
                                    let _ = tls
                                        .writer()
                                        .write_all(&h2_frame(H2_DATA, 0x1, stream, b"h2-ok"));
                                }
                            }
                        }
                        _ => {} // DATA (never sent), WINDOW_UPDATE, …: ignored
                    }
                }
                // Flush anything the responses queued.
                while tls.wants_write() {
                    if tls.write_tls(&mut tls_out).unwrap_or(0) == 0 {
                        break;
                    }
                }
                if !tls_out.is_empty() {
                    if io.write_all(&tls_out).await.is_err() {
                        return;
                    }
                    tls_out.clear();
                    continue;
                }
                let n = match io.read(&mut tmp).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => n,
                };
                let mut cursor = &tmp[..n];
                if tls.read_tls(&mut cursor).is_err() || tls.process_new_packets().is_err() {
                    return;
                }
            }
        });
        Box::new(mirror_side)
    }

    /// `run_client` against an h2-speaking carrier.
    async fn run_client_h2(
        cfg: &TlsMirrorOut,
        alpn: &str,
        hang_first: bool,
        requests: H2Requests,
    ) -> Result<BoxProxyStream> {
        let primary_key = decode_primary_key(&cfg.primary_key)?;
        let (client_duplex, server_duplex) = tokio::io::duplex(256 * 1024);
        let forward = spawn_forward_server_h2(alpn, hang_first, requests);
        let (close_tx, close_rx) = tokio::sync::oneshot::channel::<()>();
        let cfg2 = cfg.clone();
        tokio::spawn(async move {
            mirror_server_mimic(Box::new(server_duplex), forward, &cfg2, primary_key, close_rx).await;
        });
        std::mem::forget(close_tx);
        connect(cfg, Box::new(client_duplex)).await
    }

    #[tokio::test]
    async fn traffic_generator_carries_h2_and_signals_ready() {
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let mut cfg = base_cfg();
        cfg.alpn = vec!["h2".to_string()];
        cfg.traffic_generator = vec![TrafficStep {
            host: "carrier.example".into(),
            path: "/h2carrier".into(),
            method: "GET".into(),
            headers: vec![("User-Agent".into(), "tlsmirror-h2-test".into())],
            connection_ready: true,
            connection_recall_exit: true,
            wait_time: TimeSpec {
                base_nanoseconds: 10_000_000,
                uniform_random_multiplier_nanoseconds: 0,
            },
            next_step: vec![TrafficTransferCandidate { weight: 1, goto_location: 0 }],
            ..http_step("step", "/h2carrier")
        }];
        let mut stream = run_client_h2(&cfg, "h2", false, requests.clone())
            .await
            .unwrap();
        // Dial returned only after the ConnectionReady step ran, so at
        // least one h2 request reached the carrier.
        let reqs = requests.lock().unwrap().clone();
        assert!(!reqs.is_empty(), "generator produced no h2 requests");
        // The steps ride one connection: odd stream ids ascending (1, 3, …).
        // The goto-self loop re-runs step 0 every wait_time — wait for the
        // second round before asserting the ids.
        let deadline = Instant::now() + Duration::from_secs(10);
        let reqs = loop {
            let reqs = requests.lock().unwrap().clone();
            if reqs.len() >= 2 || Instant::now() > deadline {
                break reqs;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        };
        assert_eq!(reqs[0].0, 1, "{reqs:?}");
        assert!(reqs.len() >= 2, "the goto-self loop produced one request only: {reqs:?}");
        assert!(reqs.iter().all(|(id, _)| id % 2 == 1), "{reqs:?}");
        // The request is h2-shaped: literal-encoded pseudo-headers plus
        // the step header, lowercased on the wire (run_h2_step).
        let block = &reqs[0].1;
        let contains = |needle: &[u8]| block.windows(needle.len()).any(|w| w == needle);
        assert!(contains(b":method") && contains(b"GET"), "{block:?}");
        assert!(contains(b":scheme") && contains(b"https"), "{block:?}");
        assert!(contains(b":authority") && contains(b"carrier.example"), "{block:?}");
        assert!(contains(b":path") && contains(b"/h2carrier"), "{block:?}");
        assert!(contains(b"user-agent") && contains(b"tlsmirror-h2-test"), "{block:?}");
        // The hidden channel still works over the h2-generating carrier.
        echo_roundtrip(&mut stream, b"over-h2-generator").await;
    }

    #[tokio::test]
    async fn h2_do_not_wait_for_download_finish_moves_on() {
        // Stream 1's download hangs (HEADERS, no END_STREAM); the
        // do-not-wait step hands the drain to the background and the
        // generator proceeds to the next step on stream 3.
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let mut cfg = base_cfg();
        cfg.alpn = vec!["h2".to_string()];
        cfg.traffic_generator = vec![
            TrafficStep {
                path: "/slow".into(),
                connection_ready: true,
                h2_do_not_wait_for_download_finish: true,
                ..http_step("slow", "/slow")
            },
            http_step("next", "/next"),
        ];
        let mut stream = run_client_h2(&cfg, "h2", true, requests.clone())
            .await
            .unwrap();
        // The ready step's round trip resolved on HEADERS (the body still
        // dangling) and the generator moved to step two.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let reqs = requests.lock().unwrap().clone();
            let next_ran = reqs.iter().any(|(id, block)| {
                *id == 3 && block.windows(5).any(|w| w == b"/next")
            });
            if next_ran {
                break;
            }
            assert!(Instant::now() < deadline, "step two never ran: {reqs:?}");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // The hidden channel is unaffected by the dangling download.
        echo_roundtrip(&mut stream, b"not-waiting").await;
    }

    #[tokio::test]
    async fn unknown_carrier_alpn_fails_the_generator_before_ready() {
        // A negotiated ALPN that is neither h2 nor http/1.1 kills the
        // generator (newTrafficHTTPTransport's default arm,
        // traffic.go:74-77); with a ConnectionReady step the dial then
        // fails instead of hanging.
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let mut cfg = base_cfg();
        cfg.alpn = vec!["weird/9".to_string()];
        cfg.traffic_generator = vec![TrafficStep {
            connection_ready: true,
            ..http_step("s", "/x")
        }];
        let err = match run_client_h2(&cfg, "weird/9", false, requests).await {
            Ok(_) => panic!("an unknown carrier ALPN must fail the generator"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("generator exited before ready"),
            "{err}"
        );
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
        // (The h2-carrier generator is no longer rejected at config time:
        // the transport is chosen from the negotiated ALPN — see the
        // traffic_generator_carries_h2_* tests.)
        let mut cfg = base_cfg();
        cfg.server_name.clear();
        assert!(connect(&cfg, Box::new(tokio::io::duplex(16).0)).await.is_err());
        // The recommended suite list is exposed verbatim.
        assert!(RECOMMENDED_EXPLICIT_NONCE_CIPHER_SUITES.contains(&49195));
        assert_eq!(RECOMMENDED_EXPLICIT_NONCE_CIPHER_SUITES.len(), 48);
    }
    // ------------------------------------------------ connection enrolment

    #[test]
    fn server_identifier_host_shape() {
        let key = generate_primary_key();
        let host = server_identifier_host(&key).unwrap();
        assert!(
            host.ends_with(".tlsmirror-controlconnection.v2fly.arpa"),
            "{host}"
        );
        let label = host.strip_suffix(".tlsmirror-controlconnection.v2fly.arpa").unwrap();
        assert!(!label.is_empty());
        assert!(
            label
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'v').contains(&b)),
            "the base32 lower alphabet: {label}"
        );
        // Deterministic for the same key.
        assert_eq!(host, server_identifier_host(&key).unwrap());
        assert_ne!(host, server_identifier_host(&generate_primary_key()).unwrap());
        // The intercept predicate (listener/tlsmirror/tlsmirror.go:82).
        let target = crate::addr::NetAddr::domain(&host, 80).unwrap();
        assert!(is_enrollment_control_target(&target, &key));
        // Case-insensitive host, wrong port, wrong host.
        let upper = crate::addr::NetAddr::domain(&host.to_uppercase(), 80).unwrap();
        assert!(is_enrollment_control_target(&upper, &key));
        let wrong_port = crate::addr::NetAddr::domain(&host, 443).unwrap();
        assert!(!is_enrollment_control_target(&wrong_port, &key));
        let wrong_host = crate::addr::NetAddr::domain("other.example", 80).unwrap();
        assert!(!is_enrollment_control_target(&wrong_host, &key));
        // Bad keys do not derive.
        assert!(server_identifier_host("").is_err());
    }

    #[test]
    fn enrollment_base32_vectors() {
        // RFC 4648 lower alphabet with digits first: encodings of
        // 0x00..: 5-bit groups of 00000 → '0', 00001 → '1' … 11111 → 'v'.
        assert_eq!(enrollment_base32_encode(&[0x00]), "00");
        assert_eq!(enrollment_base32_encode(&[0xff]), "vs");
        assert_eq!(enrollment_base32_encode(&[0xAB, 0xCD]), "lf6g");
        let range: Vec<u8> = (0..16u8).collect();
        assert_eq!(enrollment_base32_encode(&range), "000g40o40k30e209185go38e1s");
        // 16-byte identifiers give 26 chars (80 bits), no padding.
        assert_eq!(enrollment_base32_encode(&[0u8; 16]).len(), 26);
    }

    #[test]
    fn enrollment_protobuf_roundtrip() {
        let req = EnrollmentConfirmationReq {
            server_identifier: vec![1, 2, 3],
            client_random: vec![9; 32],
            server_random: vec![8; 32],
            client_identifier: vec![],
            reply_address_tag: vec![7],
        };
        let bytes = marshal_enrollment_req(&req);
        assert_eq!(unmarshal_enrollment_req(&bytes).unwrap(), req);
        // Empty fields are omitted (marshalEnrollmentConfirmationReq).
        assert!(!bytes.windows(2).any(|w| w == [0x22, 0x00]), "{bytes:?}");
        // Unknown fields are skipped (field 9 varint + field 10 bytes).
        let mut extended = marshal_enrollment_req(&req);
        extended.extend_from_slice(&[0x48, 0x2a]); // field 9, varint 42
        extended.extend_from_slice(&[0x52, 0x02, 0x03, 0x04]); // field 10, bytes
        assert_eq!(unmarshal_enrollment_req(&extended).unwrap(), req);
        // Response forms (enrollment.go:305/313).
        assert_eq!(marshal_enrollment_resp(true), vec![0x08, 0x01]);
        assert!(marshal_enrollment_resp(false).is_empty());
        assert!(unmarshal_enrollment_resp(&[0x08, 0x01]).unwrap());
        assert!(!unmarshal_enrollment_resp(&[]).unwrap());
        // Field-number zero is refused.
        assert!(unmarshal_enrollment_req(&[0x00]).is_err());
        assert!(unmarshal_enrollment_resp(&[0x00]).is_err());
    }

    #[test]
    fn enrollment_request_key_is_directionless_and_random_dependent() {
        let key = [7u8; 32];
        let cr = [1u8; 32];
        let sr = [2u8; 32];
        let k1 = derive_enrollment_request_key(&key, &cr, &sr).unwrap();
        assert_eq!(k1.len(), 16);
        assert_eq!(k1, derive_enrollment_request_key(&key, &cr, &sr).unwrap());
        assert_ne!(k1, derive_enrollment_request_key(&key, &sr, &cr).unwrap());
        assert_ne!(k1, derive_enrollment_request_key(&[8u8; 32], &cr, &sr).unwrap());
        // The server identifier derivation (secondary key namespace).
        let id = derive_enrollment_server_identifier(&key).unwrap();
        assert_eq!(id.len(), 16);
        assert_ne!(id, derive_enrollment_server_identifier(&[8u8; 32]).unwrap());
    }

    #[tokio::test]
    async fn enrollment_active_lifecycle() {
        let key = [3u8; 32];
        let cr = [1u8; 32];
        let sr = [2u8; 32];
        assert!(!enrollment_verify(&key, &cr, &sr));
        let guard = enrollment_add(&key, &cr, &sr).unwrap();
        assert!(enrollment_verify(&key, &cr, &sr));
        // Duplicate registration is a replay error (enrollment.go:225).
        assert!(enrollment_add(&key, &cr, &sr).is_err());
        // A different key has its own table.
        assert!(!enrollment_verify(&[4u8; 32], &cr, &sr));
        drop(guard);
        assert!(!enrollment_verify(&key, &cr, &sr), "guard removal");
    }

    #[test]
    fn hpack_status_decoding() {
        // Indexed static :status 200 → 0x88 (RFC 7541 App. A).
        assert_eq!(hpack_decode_status(&[0x88]).unwrap(), 200);
        assert_eq!(hpack_decode_status(&[0x8c]).unwrap(), 400);
        assert_eq!(hpack_decode_status(&[0x8e]).unwrap(), 500);
        // Literal :status (no huffman).
        let mut block = vec![0x00, 0x07];
        block.extend_from_slice(b":status");
        block.extend_from_slice(&[0x03]);
        block.extend_from_slice(b"404");
        assert_eq!(hpack_decode_status(&block).unwrap(), 404);
        // A dynamic-table size update then an indexed status.
        assert_eq!(hpack_decode_status(&[0x20, 0x88]).unwrap(), 200);
        // Huffman-coded literals are refused.
        let mut huff = vec![0x00, 0x87];
        huff.extend_from_slice(b":status");
        huff.push(0x83);
        huff.extend_from_slice(&[0x1f, 0x9e, 0x9d]);
        assert!(hpack_decode_status(&huff).is_err());
        // Missing :status.
        assert!(hpack_decode_status(&[0x61, 0x02, b'a', b'b', 0x03, b'x', b'y', b'z']).is_err());
    }

    #[tokio::test]
    async fn h2c_enrollment_confirmation_roundtrip() {
        // The control server over one duplex against the h2c client.
        let key = [5u8; 32];
        let key_b64 = {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(key)
        };
        let cr = [1u8; 32];
        let sr = [2u8; 32];
        let host = server_identifier_host(&key_b64).unwrap();
        let req = marshal_enrollment_req(&EnrollmentConfirmationReq {
            server_identifier: derive_enrollment_server_identifier(&key).unwrap().to_vec(),
            client_random: cr.to_vec(),
            server_random: sr.to_vec(),
            ..EnrollmentConfirmationReq::default()
        });

        // Unregistered: enrolled=false (empty response body).
        {
            let (client, server) = tokio::io::duplex(16 * 1024);
            let key_b64 = key_b64.clone();
            let server_task = tokio::spawn(async move {
                serve_enrollment_control_connection(Box::new(server), &key_b64).await
            });
            let (status, body) = h2c_post(Box::new(client), &host, &req).await.unwrap();
            assert_eq!(status, 200);
            assert!(!unmarshal_enrollment_resp(&body).unwrap());
            server_task.await.unwrap().unwrap();
        }
        // Registered: enrolled=true.
        {
            let _guard = enrollment_add(&key, &cr, &sr).unwrap();
            let (client, server) = tokio::io::duplex(16 * 1024);
            let key_b64 = key_b64.clone();
            let server_task = tokio::spawn(async move {
                serve_enrollment_control_connection(Box::new(server), &key_b64).await
            });
            let (status, body) = h2c_post(Box::new(client), &host, &req).await.unwrap();
            assert_eq!(status, 200);
            assert!(unmarshal_enrollment_resp(&body).unwrap());
            server_task.await.unwrap().unwrap();
        }
        // Not an h2c preface: refused precisely.
        {
            let (mut client, server) = tokio::io::duplex(16 * 1024);
            // 28 junk bytes (>= the 24-byte preface) from the client end.
            client
                .write_all(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n")
                .await
                .unwrap();
            let err = serve_enrollment_control_connection(Box::new(server), &key_b64)
                .await
                .unwrap_err()
                .to_string();
            assert!(err.contains("not an h2c preface"), "{err}");
        }
    }

    // ------------------------------------------------ the server half

    fn server_cfg_from(out: &TlsMirrorOut) -> TlsMirrorServerConfig {
        TlsMirrorServerConfig {
            primary_key: out.primary_key.clone(),
            explicit_nonce_cipher_suites: out.explicit_nonce_cipher_suites.clone(),
            defer_instance_derived_write: out.defer_instance_derived_write,
            transport_layer_padding: out.transport_layer_padding,
            connection_enrolment: out.connection_enrolment.clone(),
            sequence_watermarking_enabled: out.sequence_watermarking_enabled,
        }
    }

    /// The engine client ↔ `serve_conn_ready` ↔ a real TLS dest. The
    /// hidden stream echoes inside the server task.
    async fn run_ready_client(
        cfg: &TlsMirrorOut,
        server_cfg: TlsMirrorServerConfig,
    ) -> Result<BoxProxyStream> {
        let (client_duplex, server_duplex) = tokio::io::duplex(256 * 1024);
        let forward = spawn_forward_server(false, Arc::new(StdMutex::new(Vec::new())));
        tokio::spawn(async move {
            if let Ok(mut hidden) =
                serve_conn_ready(Box::new(server_duplex), forward, &server_cfg).await
            {
                // The relay stand-in: echo the hidden plaintext.
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match hidden.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if hidden.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });
        connect(cfg, Box::new(client_duplex)).await
    }

    #[tokio::test]
    async fn serve_conn_ready_hidden_echo() {
        let cfg = base_cfg();
        let mut stream = run_ready_client(&cfg, server_cfg_from(&cfg)).await.unwrap();
        echo_roundtrip(&mut stream, b"ready-mirror").await;
        let payload: Vec<u8> = (0..60_000u32).map(|i| (i % 251) as u8).collect();
        echo_roundtrip(&mut stream, &payload).await;
    }

    #[tokio::test]
    async fn serve_conn_ready_padding_and_watermarking() {
        let mut cfg = base_cfg();
        cfg.transport_layer_padding = true;
        cfg.sequence_watermarking_enabled = true;
        let mut stream = run_ready_client(&cfg, server_cfg_from(&cfg)).await.unwrap();
        echo_roundtrip(&mut stream, b"padded-watermarked").await;
    }

    #[tokio::test]
    async fn serve_conn_ready_never_activates_on_wrong_key() {
        let real = base_cfg();
        let mut bad = real.clone();
        bad.primary_key = generate_primary_key();
        // The client connects against a server configured with another
        // key: its inserts are carrier junk; serve_conn_ready must not
        // return a hidden stream (the camouflage carrier TLS eventually
        // dies because the dest server cannot parse the junk records).
        let mut stream = match tokio::time::timeout(
            Duration::from_secs(15),
            run_ready_client(&bad, server_cfg_from(&real)),
        )
        .await
        {
            // connect() itself can succeed (the carrier handshake is
            // legitimate TLS); the hidden channel must stay dead.
            Ok(Ok(stream)) => stream,
            Ok(Err(_)) => return,
            Err(_) => panic!("connect timed out"),
        };
        stream.write_all(b"secret").await.unwrap();
        let mut buf = [0u8; 6];
        match tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf)).await {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!("a wrong primary key must never echo hidden data ({n} bytes)"),
        }
    }

    #[tokio::test]
    async fn serve_conn_ready_registers_enrolment() {
        // Client WITHOUT enrolment config against a server WITH it: the
        // mirror registers the randoms; an in-test control server (fed
        // by the client-side verify over its own dialer) confirms.
        let cfg = base_cfg();
        let mut server_cfg = server_cfg_from(&cfg);
        server_cfg.connection_enrolment = Some(("ingress".to_string(), "egress".to_string()));

        // The control-connection endpoint: the dialer creates a duplex,
        // serves the control protocol on one end, hands over the other.
        let key_b64 = cfg.primary_key.clone();
        let dialer: EnrollmentDialer = Arc::new(move |_target| {
            let key_b64 = key_b64.clone();
            Box::pin(async move {
                let (client, server) = tokio::io::duplex(16 * 1024);
                tokio::spawn(async move {
                    let _ = serve_enrollment_control_connection(Box::new(server), &key_b64).await;
                });
                Ok(Box::new(client) as BoxProxyStream)
            })
        });

        let (client_duplex, server_duplex) = tokio::io::duplex(256 * 1024);
        let forward = spawn_forward_server(false, Arc::new(StdMutex::new(Vec::new())));
        let server_cfg2 = server_cfg.clone();
        tokio::spawn(async move {
            if let Ok(mut hidden) =
                serve_conn_ready(Box::new(server_duplex), forward, &server_cfg2).await
            {
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match hidden.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if hidden.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            }
        });

        let mut client_cfg = cfg.clone();
        client_cfg.connection_enrolment = Some(("ingress".to_string(), "egress".to_string()));
        let mut stream =
            connect_with(&client_cfg, Box::new(client_duplex), Some(dialer)).await
                .expect("enrolled connect");
        echo_roundtrip(&mut stream, b"enrol-echo").await;
    }

    #[tokio::test]
    async fn enrolment_without_dialer_is_precisely_rejected() {
        let mut cfg = base_cfg();
        cfg.connection_enrolment = Some(("a".into(), "b".into()));
        let err = connect(&cfg, Box::new(tokio::io::duplex(16).0))
            .await
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(err.contains("enrollment dialer"), "{err}");
        assert!(err.contains("connect_with"), "{err}");
        assert!(err.contains("enrollment.go"), "{err}");
    }

}
