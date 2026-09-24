//! ShadowTLS **v3** client: a real TLS handshake whose ClientHello carries
//! the v3 HMAC session id, then HMAC-framed application records.
//!
//! Mirrors mihomo's `transport/shadowtls` (`client.go`, `protocol.go`,
//! `v3.go`, `server.go`). The wire, as the server sees it:
//!
//! 1. the client sends one ClientHello with a 32-byte `legacy_session_id`
//!    whose last 4 bytes are `HMAC-SHA1(password, ClientHello` with those 4
//!    bytes zeroed`)` (v3.go `generateSessionID` / `verifyClientHello`);
//! 2. the server relays that ClientHello to the real handshake destination
//!    (e.g. `www.microsoft.com:443`), relays the ServerHello back *and
//!    sends the rest of the TLS handshake through*: every server record is
//!    XOR-obfuscated with `kdf = SHA256(password ‖ ServerHello.random)`
//!    and prefixed with a 4-byte tag from a rolling HMAC-SHA1 chain seeded
//!    with `password ‖ server_random` (no direction byte) — the client
//!    verifies and decrypts those records to complete a genuine TLS
//!    handshake against a real site;
//! 3. once the ClientHello HMAC authenticated, the server stops relaying to
//!    the real site when it sees the client's first *post-handshake*
//!    application record, identified by a rolling HMAC chain seeded
//!    `password ‖ server_random ‖ 'C'`; from then on both directions carry
//!    plain payloads behind a 4-byte HMAC (server→client chain seeded with
//!    `'S'`) and the payloads are the tunnelled bytes.
//!
//! So [`connect`] takes the raw transport to the shadowtls server, performs
//! the handshake (rustls, discarded afterwards — mihomo discards it too) and
//! returns a byte stream carrying v3 framing, ready for the caller's real
//! TLS (`transport::tls_connect`) or any other outbound payload.
//!
//! ## rustls and the session-id HMAC
//!
//! The HMAC must cover the *exact* ClientHello sent on the wire, and
//! rustls hashes its ClientHello into the handshake transcript as it emits
//! it — patching the bytes in flight would desynchronise the transcript and
//! no handshake would complete. Instead the ClientHello is generated
//! *twice*, in memory: a first pass records every byte rustls draws from
//! [`SecureRandom`], the HMAC is computed over that ClientHello, and a
//! second pass replays the same random stream with the session-id tail
//! substituted by the HMAC, so rustls itself emits the authenticated hello
//! and its transcript stays consistent. Both passes are compared byte for
//! byte; any divergence aborts the connection instead of falling back to an
//! unauthenticated hello.
//!
//! ## What is not mirrored, and why
//!
//! * **ClientHello fingerprint.** mihomo builds the hello with uTLS under a
//!   configurable `client-fingerprint`. Here it is a plain rustls TLS 1.3
//!   hello (ALPN `h2`/`http/1.1` as in `DefaultALPN`, X25519 — the group
//!   uTLS sends for shadowtls). It is a valid hello that a real site answers
//!   with a ServerHello, but it is not a browser impersonation.
//! * **Key exchange.** rustls' stock groups take their ephemeral secret from
//!   ring's own RNG, so the hello could not be reproduced for the HMAC; the
//!   provider installs an equivalent X25519 group (curve25519-dalek,
//!   RFC 7748) fed by the recorded/replayed random stream. This affects only
//!   which group is offered, not the wire format.
//! * **`strict-mode`.** mihomo can require TLS 1.3 from the handshake peer
//!   (`Client.strictMode`); [`ShadowTlsOut`] has no such flag, so a TLS 1.2
//!   peer is accepted with a warning, as mihomo does without strict mode.
//! * The server side (`server.go`), wildcard SNI and per-SNI handshake
//!   selection are out of scope.
//!
//! The un-hermetically-checkable part — how a *real* handshake destination
//! answers this hello — is not exercised; the wire itself is pinned by the
//! in-test mimic, which re-implements `verifyClientHello` straight from
//! v3.go and drives a genuine rustls TLS server behind the framing.

use std::cell::Cell;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{ready, Context, Poll};

use bytes::{Buf, BytesMut};
use hmac::{Hmac, Mac};
use rand::RngCore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring as ring_provider;
use rustls::crypto::{CryptoProvider, GetRandomFailed, SecureRandom};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha1::Sha1;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::{debug, warn};

use crate::error::{Error, Result};
use crate::stream::BoxProxyStream;

/// TLS record header size (protocol.go `tlsHeaderSize`).
const TLS_HEADER_SIZE: usize = 5;
/// ClientHello/ServerHello random size (`tlsRandomSize`).
const TLS_RANDOM_SIZE: usize = 32;
/// v3 session id size (`tlsSessionIDSize`).
const TLS_SESSION_ID_SIZE: usize = 32;
/// HMAC tag size (`hmacSize`).
const HMAC_SIZE: usize = 4;
/// Record header + tag (`tlsHMACHeaderSize`).
const TLS_HMAC_HEADER_SIZE: usize = TLS_HEADER_SIZE + HMAC_SIZE;
/// `serverRandomIndex`: record header + handshake type + length + version.
const SERVER_RANDOM_INDEX: usize = TLS_HEADER_SIZE + 1 + 3 + 2;
/// `sessionIDLengthIndex`: everything up to the session-id length byte.
const SESSION_ID_LENGTH_INDEX: usize = TLS_HEADER_SIZE + 1 + 3 + 2 + TLS_RANDOM_SIZE;
/// `sessionIDStart` (protocol.go): the first session-id byte.
const SESSION_ID_INDEX: usize = SESSION_ID_LENGTH_INDEX + 1;
/// `maxTLSPlaintext`: cap on one application-record payload.
const MAX_TLS_PLAINTEXT: usize = 16384;
/// Largest record accepted from the peer (16 KiB of framed payload + tag).
const MAX_RECORD_PAYLOAD: usize = MAX_TLS_PLAINTEXT + TLS_HMAC_HEADER_SIZE * 2;

const REC_ALERT: u8 = 21;
const REC_HANDSHAKE: u8 = 22;
const REC_APPLICATION_DATA: u8 = 23;
const HS_CLIENT_HELLO: u8 = 1;
const HS_SERVER_HELLO: u8 = 2;

/// ALPN mihomo's shadowtls client offers by default (`DefaultALPN`).
const DEFAULT_ALPN: [&str; 2] = ["h2", "http/1.1"];

/// Outbound ShadowTLS endpoint.
#[derive(Debug, Clone)]
pub struct ShadowTlsOut {
    pub server: String,
    pub port: u16,
    /// v3 shared password (the server's user password).
    pub password: String,
    /// SNI of the *handshake destination* the server relays to; the
    /// real site must present a certificate for it unless `skip_verify`.
    pub sni: String,
    /// Skip certificate verification of the handshake peer (mihomo's
    /// `skip-cert-verify`). The v3 HMAC is the actual authentication.
    pub skip_verify: bool,
}

/// `kdf` from v3.go: `SHA256(password ‖ server_random)`.
fn kdf(password: &str, server_random: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(password.as_bytes());
    hasher.update(server_random);
    hasher.finalize().into()
}

/// `xorSlice` from v3.go.
fn xor_slice(data: &mut [u8], key: &[u8]) {
    if key.is_empty() {
        return;
    }
    for (i, b) in data.iter_mut().enumerate() {
        *b ^= key[i % key.len()];
    }
}

/// A rolling HMAC-SHA1 chain (`hmacAdd` / `hmacVerify` / `readHMAC` in
/// mihomo). `side` is the direction byte appended after the server random;
/// the handshake-phase read chain has none.
struct HmacChain {
    mac: Hmac<Sha1>,
}

impl HmacChain {
    fn new(password: &str, server_random: &[u8], side: Option<u8>) -> Self {
        let mut mac = Hmac::<Sha1>::new_from_slice(password.as_bytes())
            .expect("HMAC-SHA1 accepts any key length");
        mac.update(server_random);
        if let Some(side) = side {
            mac.update(&[side]);
        }
        HmacChain { mac }
    }

    fn update(&mut self, data: &[u8]) {
        self.mac.update(data);
    }

    /// Current tag without advancing the chain (mirrors `Sum(nil)[:4]`).
    fn tag(&self) -> [u8; HMAC_SIZE] {
        let mut tag = [0u8; HMAC_SIZE];
        tag.copy_from_slice(&self.mac.clone().finalize().into_bytes()[..HMAC_SIZE]);
        tag
    }
}

/// Extract `ServerHello.random`, mirroring `extractServerRandom`.
fn server_random(record: &[u8]) -> Option<[u8; TLS_RANDOM_SIZE]> {
    if record.len() < SERVER_RANDOM_INDEX + TLS_RANDOM_SIZE
        || record[0] != REC_HANDSHAKE
        || record[TLS_HEADER_SIZE] != HS_SERVER_HELLO
    {
        return None;
    }
    record[SERVER_RANDOM_INDEX..SERVER_RANDOM_INDEX + TLS_RANDOM_SIZE]
        .try_into()
        .ok()
}

/// Does the ServerHello advertise TLS 1.3 (`isServerHelloSupportTLS13`)?
fn server_hello_supports_tls13(record: &[u8]) -> bool {
    if record.len() <= SESSION_ID_LENGTH_INDEX
        || record[0] != REC_HANDSHAKE
        || record[TLS_HEADER_SIZE] != HS_SERVER_HELLO
    {
        return false;
    }
    let mut off = SESSION_ID_LENGTH_INDEX;
    let session_id_len = record[off] as usize;
    off += 1;
    if off + session_id_len + 3 + 2 > record.len() {
        return false;
    }
    off += session_id_len + 3;
    let ext_len = usize::from(u16::from_be_bytes([record[off], record[off + 1]]));
    off += 2;
    if off + ext_len > record.len() {
        return false;
    }
    let mut exts = &record[off..off + ext_len];
    while exts.len() >= 4 {
        let ext_type = u16::from_be_bytes([exts[0], exts[1]]);
        let len = usize::from(u16::from_be_bytes([exts[2], exts[3]]));
        exts = &exts[4..];
        if len > exts.len() {
            return false;
        }
        if ext_type == 43 {
            // supported_versions
            return len == 2 && exts[..2] == [0x03, 0x04];
        }
        exts = &exts[len..];
    }
    false
}

/// HMAC-SHA1 tag over a ClientHello with the last [`HMAC_SIZE`] session-id
/// bytes zeroed (v3.go `generateSessionID` / `verifyClientHello`).
fn client_hello_tag(record: &[u8], password: &str) -> Result<[u8; HMAC_SIZE]> {
    // hmacIndex = sessionIDLengthIndex + 1 + tlsSessionIDSize - hmacSize
    let hmac_index = SESSION_ID_INDEX + TLS_SESSION_ID_SIZE - HMAC_SIZE;
    if record.len() < hmac_index + HMAC_SIZE {
        return Err(Error::protocol("shadow-tls: ClientHello too short for a session id"));
    }
    let mut mac = Hmac::<Sha1>::new_from_slice(password.as_bytes())
        .map_err(|e| Error::crypto(format!("shadow-tls: hmac key: {e}")))?;
    mac.update(&record[TLS_HEADER_SIZE..hmac_index]);
    mac.update(&[0u8; HMAC_SIZE]);
    mac.update(&record[hmac_index + HMAC_SIZE..]);
    let mut tag = [0u8; HMAC_SIZE];
    tag.copy_from_slice(&mac.finalize().into_bytes()[..HMAC_SIZE]);
    Ok(tag)
}

/// Rewrite the session-id tail of `stream`'s first record (a ClientHello)
/// with the v3 HMAC and produce the matching replay random stream.
///
/// `random_stream` is the concatenation of everything rustls drew from its
/// random source while building that ClientHello; the session id was drawn
/// from it in order, so the same 4 bytes can be substituted there too.
/// Returns `(patched_client_hello_stream, replay_random_stream)`.
fn patch_client_hello(
    stream: &[u8],
    password: &str,
    random_stream: &[u8],
) -> Result<(Vec<u8>, Vec<u8>)> {
    if stream.len() < TLS_HEADER_SIZE || stream[0] != REC_HANDSHAKE
        || stream[TLS_HEADER_SIZE] != HS_CLIENT_HELLO
    {
        return Err(Error::config("shadow-tls: rustls did not emit a ClientHello"));
    }
    let record_len = usize::from(u16::from_be_bytes([stream[3], stream[4]]));
    if stream.len() < TLS_HEADER_SIZE + record_len || record_len < TLS_SESSION_ID_SIZE + 1 {
        return Err(Error::config("shadow-tls: malformed ClientHello record"));
    }
    if stream[SESSION_ID_LENGTH_INDEX] as usize != TLS_SESSION_ID_SIZE {
        return Err(Error::config(format!(
            "shadow-tls: rustls sent a {}-byte legacy_session_id, v3 needs {TLS_SESSION_ID_SIZE} (enable TLS 1.3)",
            stream[SESSION_ID_LENGTH_INDEX]
        )));
    }
    let session_id = &stream[SESSION_ID_INDEX..SESSION_ID_INDEX + TLS_SESSION_ID_SIZE];
    let tag = client_hello_tag(stream, password)?;

    let mut patched = stream.to_vec();
    patched[SESSION_ID_INDEX + TLS_SESSION_ID_SIZE - HMAC_SIZE..SESSION_ID_INDEX + TLS_SESSION_ID_SIZE]
        .copy_from_slice(&tag);

    // Locate the same session id inside the recorded random stream. Rustls
    // draws it as one buffer, so the 32 bytes are contiguous there.
    let pos = random_stream
        .windows(TLS_SESSION_ID_SIZE)
        .position(|w| w == session_id)
        .ok_or_else(|| {
            Error::crypto(
                "shadow-tls: session id not found in rustls' random stream; cannot derive the v3 HMAC",
            )
        })?;
    let mut replay = random_stream.to_vec();
    replay[pos + TLS_SESSION_ID_SIZE - HMAC_SIZE..pos + TLS_SESSION_ID_SIZE].copy_from_slice(&tag);
    Ok((patched, replay))
}

/// How [`ShadowRandom`] answers entropy requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Roll {
    /// Normal operation: system entropy.
    Idle,
    /// Record every byte drawn (first ClientHello pass).
    Record,
    /// Replay the recorded stream (second ClientHello pass).
    Replay,
}

#[derive(Debug)]
struct RandomRoll {
    mode: Roll,
    recorded: Vec<u8>,
    pos: usize,
}

// A single process-wide recorder/replayer, only consulted while
// `IN_HELLO` is set on the current thread (the ClientHello passes never
// await, so they stay on one thread). `HELLO_SECTION` serialises the
// passes so two connections cannot interleave their random streams.
static RANDOM_ROLL: Mutex<RandomRoll> = Mutex::new(RandomRoll {
    mode: Roll::Idle,
    recorded: Vec::new(),
    pos: 0,
});
static HELLO_SECTION: Mutex<()> = Mutex::new(());

thread_local! {
    static IN_HELLO: Cell<bool> = const { Cell::new(false) };
}

/// The random source installed in the shadowtls TLS config.
#[derive(Debug)]
struct ShadowRandom;

/// System entropy used outside the ClientHello passes.
fn system_random() -> &'static dyn SecureRandom {
    static FALLBACK: OnceLock<&'static dyn SecureRandom> = OnceLock::new();
    *FALLBACK.get_or_init(|| ring_provider::default_provider().secure_random)
}

impl SecureRandom for ShadowRandom {
    fn fill(&self, buf: &mut [u8]) -> std::result::Result<(), GetRandomFailed> {
        if !IN_HELLO.with(Cell::get) {
            return system_random().fill(buf);
        }
        let mut roll = RANDOM_ROLL.lock().unwrap_or_else(|e| e.into_inner());
        match roll.mode {
            Roll::Record => {
                system_random().fill(buf)?;
                roll.recorded.extend_from_slice(buf);
                Ok(())
            }
            Roll::Replay => {
                let available = roll.recorded.len().saturating_sub(roll.pos);
                let take = available.min(buf.len());
                if take > 0 {
                    let start = roll.pos;
                    buf[..take].copy_from_slice(&roll.recorded[start..start + take]);
                    roll.pos += take;
                }
                // Anything beyond the recorded ClientHello draws (none in
                // practice) falls back to system entropy.
                if take < buf.len() {
                    system_random().fill(&mut buf[take..])?;
                }
                Ok(())
            }
            Roll::Idle => system_random().fill(buf),
        }
    }
}

static SHADOW_RANDOM: ShadowRandom = ShadowRandom;

/// The only key-exchange group this config offers.
///
/// rustls' stock groups generate their ephemeral key from ring's own RNG,
/// which would make the two ClientHello passes differ and the v3 HMAC
/// uncomputable. This group runs the same X25519 (RFC 7748 clamping via
/// curve25519-dalek) but draws its scalar from [`SHADOW_RANDOM`], so the
/// recorded stream reproduces the exact key share. X25519 is mandatory for
/// TLS 1.3 peers and is what uTLS/mihomo put in their shadowtls hello.
#[derive(Debug)]
struct ReplayX25519;

static REPLAY_X25519: ReplayX25519 = ReplayX25519;

#[derive(Debug)]
struct X25519Exchange {
    scalar: [u8; 32],
    public: [u8; 32],
}

fn x25519_keygen() -> std::result::Result<X25519Exchange, rustls::Error> {
    let mut scalar = [0u8; 32];
    SHADOW_RANDOM
        .fill(&mut scalar)
        .map_err(|_| rustls::Error::General("shadow-tls: system entropy unavailable".into()))?;
    // `mul_base_clamped` applies the RFC 7748 clamping internally.
    let public = curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(scalar).0;
    Ok(X25519Exchange { scalar, public })
}

fn x25519_diffie_hellman(scalar: [u8; 32], peer: &[u8]) -> std::result::Result<[u8; 32], rustls::Error> {
    let peer: [u8; 32] = peer
        .try_into()
        .map_err(|_| rustls::Error::General("shadow-tls: bad X25519 key share".into()))?;
    let shared = curve25519_dalek::montgomery::MontgomeryPoint(peer).mul_clamped(scalar).0;
    if shared.iter().all(|b| *b == 0) {
        // A low-order peer point yields the all-zero secret; ring rejects
        // these too.
        return Err(rustls::Error::General(
            "shadow-tls: X25519 peer key share is a low-order point".into(),
        ));
    }
    Ok(shared)
}

impl rustls::crypto::SupportedKxGroup for ReplayX25519 {
    fn start(&self) -> std::result::Result<Box<dyn rustls::crypto::ActiveKeyExchange>, rustls::Error> {
        Ok(Box::new(x25519_keygen()?))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

impl rustls::crypto::ActiveKeyExchange for X25519Exchange {
    fn complete(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> std::result::Result<rustls::crypto::SharedSecret, rustls::Error> {
        Ok(rustls::crypto::SharedSecret::from(
            x25519_diffie_hellman(self.scalar, peer_pub_key)?.as_slice(),
        ))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

/// Drain everything rustls has queued for the socket (its `write_tls`).
fn drain_tls(conn: &mut ClientConnection) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while conn.wants_write() {
        if conn.write_tls(&mut out).map_err(|e| Error::config(format!("shadow-tls: tls write: {e}")))? == 0 {
            break;
        }
    }
    Ok(out)
}

/// Generate the real `ClientConnection` whose ClientHello already carries
/// the v3 session-id HMAC, returning the connection and the bytes rustls
/// already queued (ClientHello + TLS 1.3 fake CCS) for the caller to send.
fn shadow_client_hello(
    config: &Arc<ClientConfig>,
    sni: &str,
    password: &str,
) -> Result<(ClientConnection, Vec<u8>)> {
    let name = rustls::pki_types::ServerName::try_from(sni.to_owned())
        .map_err(|_| Error::config(format!("shadow-tls: invalid SNI {sni:?}")))?;

    // Synchronous from here on: the recorded stream is served through a
    // thread-local flag, so this section must not await.
    let _section = HELLO_SECTION.lock().unwrap_or_else(|e| e.into_inner());
    IN_HELLO.with(|f| f.set(true));
    let result = (|| {
        {
            let mut roll = RANDOM_ROLL.lock().unwrap_or_else(|e| e.into_inner());
            roll.mode = Roll::Record;
            roll.recorded.clear();
            roll.pos = 0;
        }
        let mut probe = ClientConnection::new(config.clone(), name.clone())
            .map_err(|e| Error::config(format!("shadow-tls: TLS client init: {e}")))?;
        let mut probe_stream = drain_tls(&mut probe)?;
        if probe_stream.is_empty() {
            let _ = probe.process_new_packets();
            probe_stream = drain_tls(&mut probe)?;
        }
        let recorded = {
            let mut roll = RANDOM_ROLL.lock().unwrap_or_else(|e| e.into_inner());
            roll.mode = Roll::Idle;
            std::mem::take(&mut roll.recorded)
        };
        if recorded.is_empty() {
            return Err(Error::crypto(
                "shadow-tls: rustls drew no randomness for the ClientHello; cannot derive the v3 HMAC",
            ));
        }
        let (patched, replay) = patch_client_hello(&probe_stream, password, &recorded)?;

        {
            let mut roll = RANDOM_ROLL.lock().unwrap_or_else(|e| e.into_inner());
            roll.mode = Roll::Replay;
            roll.recorded = replay;
            roll.pos = 0;
        }
        let mut real = ClientConnection::new(config.clone(), name)
            .map_err(|e| Error::config(format!("shadow-tls: TLS client init: {e}")))?;
        let real_stream = drain_tls(&mut real)?;
        {
            let mut roll = RANDOM_ROLL.lock().unwrap_or_else(|e| e.into_inner());
            roll.mode = Roll::Idle;
            roll.recorded.clear();
            roll.pos = 0;
        }
        if real_stream != patched {
            let diff_at = real_stream
                .iter()
                .zip(patched.iter())
                .position(|(a, b)| a != b)
                .unwrap_or_else(|| real_stream.len().min(patched.len()));
            return Err(Error::crypto(format!(
                "shadow-tls: rustls' ClientHello is not reproducible ({} vs {} bytes, first difference at {diff_at}); refusing an unauthenticated handshake",
                patched.len(),
                real_stream.len()
            )));
        }
        Ok((real, real_stream))
    })();
    IN_HELLO.with(|f| f.set(false));
    result
}

/// Client-side TLS config for the shadowtls handshake: a clone of the
/// engine's usual settings, except the random source is [`ShadowRandom`] so
/// the ClientHello can be authenticated. (Local to this module because
/// `rustls::ClientConfig` keeps its provider private.)
fn shadow_tls_config(cfg: &ShadowTlsOut) -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(shadow_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::config(format!("shadow-tls: tls: {e}")))?;
    let mut config = if cfg.skip_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth()
    } else {
        // Same policy as transport::tls_client_config: native roots, with
        // the bundled webpki roots when the host has no store.
        let mut roots = RootCertStore::empty();
        let mut loaded = 0usize;
        let certs = rustls_native_certs::load_native_certs()
            .map_err(|e| Error::config(format!("shadow-tls: native cert store: {e}")))?;
        for cert in certs {
            roots
                .add(cert)
                .map_err(|e| Error::config(format!("shadow-tls: bad native cert: {e}")))?;
            loaded += 1;
        }
        if loaded == 0 {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        builder
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    config.alpn_protocols = DEFAULT_ALPN.iter().map(|p| p.as_bytes().to_vec()).collect();
    Ok(Arc::new(config))
}

/// The ring provider with [`ShadowRandom`] as its entropy source and a
/// replayable X25519 group.
fn shadow_provider() -> CryptoProvider {
    let mut provider = ring_provider::default_provider();
    provider.secure_random = &SHADOW_RANDOM;
    provider.kx_groups = vec![&REPLAY_X25519];
    provider
}

/// Accept-anything verifier for `skip_verify` (mihomo's
/// `InsecureSkipVerify`); mirrors `transport`'s private one.
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
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.0.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

/// Which framing is on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    /// TLS handshake: records pass through, server records are unwrapped.
    Handshake,
    /// Tunnel: writes are HMAC-framed, reads must verify.
    Data,
}

/// ShadowTLS v3 framing over a raw transport.
struct ShadowTlsStream {
    inner: BoxProxyStream,
    password: String,
    phase: Phase,
    /// Unparsed raw bytes from the transport.
    rbuf: BytesMut,
    /// Record bytes ready for the consumer.
    out: BytesMut,
    /// Wire bytes queued for the transport.
    wbuf: BytesMut,
    /// Plaintext bytes already consumed into `wbuf`.
    pending_plain: usize,
    server_random: Option<[u8; TLS_RANDOM_SIZE]>,
    /// Handshake-phase read chain (v3's `readHMAC`, no direction byte).
    handshake_chain: Option<HmacChain>,
    /// XOR key obfuscating handshake-phase server records.
    decrypt_key: [u8; 32],
    is_tls13: bool,
    authorized: bool,
    /// Data-phase chains: `C` for writes, `S` for reads.
    write_chain: Option<HmacChain>,
    verify_chain: Option<HmacChain>,
    /// The handshake chain handed over as v3's `hmacIgnore`.
    ignore_chain: Option<HmacChain>,
    failed: bool,
}

impl ShadowTlsStream {
    fn new(inner: BoxProxyStream, password: String) -> Self {
        ShadowTlsStream {
            inner,
            password,
            phase: Phase::Handshake,
            rbuf: BytesMut::with_capacity(16 * 1024),
            out: BytesMut::with_capacity(16 * 1024),
            wbuf: BytesMut::new(),
            pending_plain: 0,
            server_random: None,
            handshake_chain: None,
            decrypt_key: [0u8; 32],
            is_tls13: false,
            authorized: false,
            write_chain: None,
            verify_chain: None,
            ignore_chain: None,
            failed: false,
        }
    }

    /// Leave the handshake phase: seed the `C`/`S` chains and adopt the
    /// handshake read chain as the `hmacIgnore` fallback for in-flight
    /// records (mihomo's `newVerifiedConn`).
    fn begin_data_phase(&mut self) -> Result<()> {
        let Some(server_random) = self.server_random else {
            return Err(Error::protocol(
                "shadow-tls: no ServerHello seen, cannot start the tunnel",
            ));
        };
        if !self.authorized {
            return Err(Error::protocol(
                "shadow-tls: server did not authenticate (traffic hijacked?)",
            ));
        }
        if !self.is_tls13 {
            warn!(
                target: "engine",
                "shadow-tls: handshake peer negotiated TLS 1.2; v3 is designed for TLS 1.3 (mihomo's strict mode would reject this)"
            );
        }
        self.write_chain = Some(HmacChain::new(&self.password, &server_random, Some(b'C')));
        self.verify_chain = Some(HmacChain::new(&self.password, &server_random, Some(b'S')));
        // Decrypted handshake leftovers (e.g. a NewSessionTicket rustls did
        // not read) belong to the discarded TLS session, not to the tunnel.
        self.ignore_chain = self.handshake_chain.take();
        self.out.clear();
        self.phase = Phase::Data;
        Ok(())
    }

    /// Best-effort forged alert, mirroring v3.go's `sendAlert` (active
    /// probers should see a TLS-looking failure, not a silent EOF).
    fn queue_alert(&mut self) {
        let mut record = [0u8; 31];
        record[0] = REC_ALERT;
        record[1] = 3;
        record[2] = 3;
        record[3] = 0;
        record[4] = 26;
        rand::rngs::OsRng.fill_bytes(&mut record[TLS_HEADER_SIZE..]);
        self.wbuf.extend_from_slice(&record);
    }

    /// Split one complete record off `rbuf` and process it.
    fn try_parse(&mut self) -> io::Result<bool> {
        if self.rbuf.len() < TLS_HEADER_SIZE {
            return Ok(false);
        }
        let len = usize::from(u16::from_be_bytes([self.rbuf[3], self.rbuf[4]]));
        if len > MAX_RECORD_PAYLOAD {
            return Err(io_invalid(Error::protocol("shadow-tls: oversized TLS record")));
        }
        if self.rbuf.len() < TLS_HEADER_SIZE + len {
            return Ok(false);
        }
        let record = self.rbuf.split_to(TLS_HEADER_SIZE + len);
        self.handle_record(&record).map_err(io_invalid)?;
        Ok(true)
    }

    fn handle_record(&mut self, record: &[u8]) -> Result<()> {
        let record_type = record[0];
        match self.phase {
            Phase::Handshake => match record_type {
                REC_HANDSHAKE => {
                    // v3.go mirrors the server's one-shot seed: only the
                    // first ServerHello initialises the HMAC chain.
                    if self.handshake_chain.is_none() {
                        if let Some(random) = server_random(record) {
                            self.server_random = Some(random);
                            self.is_tls13 = server_hello_supports_tls13(record);
                            self.authorized = !self.is_tls13;
                            self.decrypt_key = kdf(&self.password, &random);
                            self.handshake_chain =
                                Some(HmacChain::new(&self.password, &random, None));
                        }
                    }
                    self.out.extend_from_slice(record);
                }
                REC_APPLICATION_DATA => {
                    self.authorized = false;
                    let chain = self.handshake_chain.as_mut();
                    match chain {
                        Some(chain) if record.len() > TLS_HMAC_HEADER_SIZE => {
                            let tag = &record[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE];
                            let cipher = &record[TLS_HMAC_HEADER_SIZE..];
                            chain.update(cipher);
                            if chain.tag() != tag {
                                return Err(Error::protocol(
                                    "shadow-tls v3: HMAC mismatch, possible data corruption",
                                ));
                            }
                            let mut plain = cipher.to_vec();
                            xor_slice(&mut plain, &self.decrypt_key);
                            self.authorized = true;
                            let mut header = record[..TLS_HEADER_SIZE].to_vec();
                            header[3..5].copy_from_slice(&(plain.len() as u16).to_be_bytes());
                            self.out.extend_from_slice(&header);
                            self.out.extend_from_slice(&plain);
                        }
                        // No ServerHello yet: relay as-is (v3.go).
                        _ => self.out.extend_from_slice(record),
                    }
                }
                // Alerts, ChangeCipherSpec: pass through.
                _ => self.out.extend_from_slice(record),
            },
            Phase::Data => match record_type {
                REC_ALERT => {
                    return Err(Error::protocol("shadow-tls: remote alert"));
                }
                REC_APPLICATION_DATA if record.len() > TLS_HMAC_HEADER_SIZE => {
                    let tag = &record[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE];
                    let cipher = &record[TLS_HMAC_HEADER_SIZE..];
                    // Records still in flight from the handshake phase use
                    // the pre-switch chain (`hmacIgnore`).
                    if let Some(ignore) = self.ignore_chain.as_mut() {
                        ignore.update(cipher);
                        if ignore.tag() == tag {
                            // A record the handshake chain still covers
                            // (e.g. a NewSessionTicket written before the
                            // server saw our first tunnel frame): drop it.
                            return Ok(());
                        }
                        self.ignore_chain = None;
                    }
                    let chain = self.verify_chain.as_mut().ok_or_else(|| {
                        Error::protocol("shadow-tls: data-phase record before the tunnel started")
                    })?;
                    chain.update(cipher);
                    let expected = chain.tag();
                    if expected != tag {
                        return Err(Error::protocol(
                            "shadow-tls: application data verification failed",
                        ));
                    }
                    chain.update(&expected);
                    self.out.extend_from_slice(cipher);
                }
                other => {
                    return Err(Error::protocol(format!(
                        "shadow-tls: unexpected TLS record type: {other}"
                    )));
                }
            },
        }
        Ok(())
    }
}

fn io_invalid(e: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

impl AsyncRead for ShadowTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if !this.out.is_empty() {
                let n = this.out.len().min(buf.remaining());
                buf.put_slice(&this.out[..n]);
                this.out.advance(n);
                return Poll::Ready(Ok(()));
            }
            match this.try_parse() {
                Ok(true) => continue,
                Ok(false) => {
                    let mut tmp = [0u8; 16 * 1024];
                    let mut rb = ReadBuf::new(&mut tmp);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                    if rb.filled().is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    this.rbuf.extend_from_slice(rb.filled());
                }
                Err(e) => {
                    if !this.failed {
                        this.failed = true;
                        this.queue_alert();
                    }
                    return Poll::Ready(Err(e));
                }
            }
        }
    }
}

impl AsyncWrite for ShadowTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.failed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "shadow-tls: stream failed",
            )));
        }
        if this.wbuf.is_empty() {
            match this.phase {
                Phase::Handshake => {
                    this.wbuf = BytesMut::from(buf);
                    this.pending_plain = buf.len();
                }
                Phase::Data => {
                    let take = buf.len().min(MAX_TLS_PLAINTEXT);
                    let chain = this.write_chain.as_mut().ok_or_else(|| {
                        io::Error::new(io::ErrorKind::NotConnected, "shadow-tls: no write chain")
                    })?;
                    let payload = &buf[..take];
                    chain.update(payload);
                    let tag = chain.tag();
                    chain.update(&tag);
                    this.wbuf.reserve(TLS_HMAC_HEADER_SIZE + take);
                    this.wbuf.extend_from_slice(&[
                        REC_APPLICATION_DATA,
                        0x03,
                        0x03,
                        ((HMAC_SIZE + take) >> 8) as u8,
                        ((HMAC_SIZE + take) & 0xFF) as u8,
                    ]);
                    this.wbuf.extend_from_slice(&tag);
                    this.wbuf.extend_from_slice(payload);
                    this.pending_plain = take;
                }
            }
        }
        while !this.wbuf.is_empty() {
            let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.wbuf))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "shadow-tls: transport accepted zero bytes",
                )));
            }
            this.wbuf.advance(n);
        }
        Poll::Ready(Ok(this.pending_plain))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while !this.wbuf.is_empty() {
            let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.wbuf))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "shadow-tls: transport accepted zero bytes",
                )));
            }
            this.wbuf.advance(n);
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

/// Perform the ShadowTLS v3 client handshake over `transport` (the raw
/// connection to the shadowtls server — this function dials nothing) and
/// return the tunnel stream.
///
/// The returned stream carries the v3 framing only: wrap it with
/// [`crate::transport::tls_connect`] (or hand it to any other outbound
/// payload) to reach the actual destination.
pub async fn connect(cfg: &ShadowTlsOut, transport: BoxProxyStream) -> Result<BoxProxyStream> {
    if cfg.password.is_empty() {
        return Err(Error::config("shadow-tls: password is required"));
    }
    if cfg.sni.is_empty() {
        return Err(Error::config("shadow-tls: sni is required"));
    }
    debug!(
        target: "engine",
        server = %cfg.server, port = cfg.port, sni = %cfg.sni, skip_verify = cfg.skip_verify,
        "shadow-tls: starting v3 handshake"
    );

    let config = shadow_tls_config(cfg)?;
    let (mut tls, hello) = shadow_client_hello(&config, &cfg.sni, &cfg.password)?;
    let mut stream = ShadowTlsStream::new(transport, cfg.password.clone());

    // Drive rustls by hand so the prepared ClientConnection (already
    // carrying the v3 HMAC) is what goes on the wire.
    let mut pending = hello;
    loop {
        if !pending.is_empty() {
            stream.write_all(&pending).await?;
            pending.clear();
        }
        while tls.wants_write() {
            let mut out = Vec::new();
            tls.write_tls(&mut out)
                .map_err(|e| Error::network(format!("shadow-tls: tls write: {e}")))?;
            if out.is_empty() {
                break;
            }
            stream.write_all(&out).await?;
        }
        stream.flush().await?;
        if !tls.is_handshaking() {
            break;
        }
        let mut buf = vec![0u8; 16 * 1024];
        let n = stream.read(&mut buf).await?;
        if n == 0 {
            return Err(Error::network(format!(
                "shadow-tls: {}:{} closed during the handshake",
                cfg.server, cfg.port
            )));
        }
        let mut cursor = &buf[..n];
        tls.read_tls(&mut cursor)
            .map_err(|e| Error::network(format!("shadow-tls: tls read: {e}")))?;
        tls.process_new_packets().map_err(|e| {
            Error::network(format!(
                "shadow-tls: TLS handshake with the handshake peer (SNI {}) failed: {e}",
                cfg.sni
            ))
        })?;
    }

    stream.begin_data_phase()?;
    debug!(target: "engine", "shadow-tls: tunnel established");
    Ok(Box::new(stream))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    // ---------------------------------------------------------------- pure

    #[test]
    fn kdf_is_sha256_of_password_and_random() {
        let random = [7u8; TLS_RANDOM_SIZE];
        let expected: [u8; 32] = Sha256::digest(b"hunter2-secret".as_ref().iter().chain(random.iter()).copied().collect::<Vec<u8>>()).into();
        assert_eq!(kdf("hunter2-secret", &random), expected);
        assert_ne!(kdf("other", &random), expected);
    }

    #[test]
    fn xor_slice_roundtrips_with_kdf_key() {
        let key = kdf("pw", &[3u8; TLS_RANDOM_SIZE]);
        let original: Vec<u8> = (0..1000u32).map(|i| (i * 7 % 251) as u8).collect();
        let mut data = original.clone();
        xor_slice(&mut data, &key);
        assert_ne!(data, original);
        xor_slice(&mut data, &key);
        assert_eq!(data, original);
    }

    /// A synthetic, structurally valid TLS 1.3 ClientHello record whose
    /// 32-byte session id `fill` bytes are all `id`.
    fn synthetic_client_hello(id: u8) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0x11; TLS_RANDOM_SIZE]); // random
        body.push(TLS_SESSION_ID_SIZE as u8);
        body.extend_from_slice(&[id; TLS_SESSION_ID_SIZE]);
        body.extend_from_slice(&[0x00, 0x02, 0x13, 0x01]); // cipher suites
        body.push(1);
        body.push(0); // null compression
        body.extend_from_slice(&[0x00, 0x00]); // no extensions
        let mut record = vec![REC_HANDSHAKE, 0x03, 0x03];
        record.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        record.push(HS_CLIENT_HELLO);
        record.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        record.extend_from_slice(&body);
        record
    }

    /// Independent transcription of v3.go `verifyClientHello`: recompute the
    /// HMAC the server checks, straight from the upstream formula.
    fn upstream_verify_client_hello(record: &[u8], password: &str) -> bool {
        const HMAC_INDEX: usize = SESSION_ID_LENGTH_INDEX + 1 + TLS_SESSION_ID_SIZE - HMAC_SIZE;
        if record.len() < HMAC_INDEX + HMAC_SIZE
            || record[0] != REC_HANDSHAKE
            || record[TLS_HEADER_SIZE] != HS_CLIENT_HELLO
            || record[SESSION_ID_LENGTH_INDEX] as usize != TLS_SESSION_ID_SIZE
        {
            return false;
        }
        let mut mac = Hmac::<Sha1>::new_from_slice(password.as_bytes()).unwrap();
        mac.update(&record[TLS_HEADER_SIZE..HMAC_INDEX]);
        mac.update(&[0, 0, 0, 0]);
        mac.update(&record[HMAC_INDEX + HMAC_SIZE..]);
        let tag = mac.finalize().into_bytes();
        record[HMAC_INDEX..HMAC_INDEX + HMAC_SIZE] == tag[..HMAC_SIZE]
    }

    #[test]
    fn patched_client_hello_passes_the_upstream_server_check() {
        let hello = synthetic_client_hello(0x42);
        // rustls would have drawn the whole hello from its random source;
        // model that stream with the session id embedded in order.
        let mut random_stream = vec![0xAAu8; 32]; // e.g. the hello random
        random_stream.extend_from_slice(&[0x42u8; TLS_SESSION_ID_SIZE]);
        random_stream.extend_from_slice(&[0xBBu8; 16]); // e.g. a key share

        let (patched, replay) = patch_client_hello(&hello, "shared-password", &random_stream).unwrap();
        assert_eq!(patched.len(), hello.len(), "record length must not change");
        assert_eq!(&patched[..SESSION_ID_INDEX + 28], &hello[..SESSION_ID_INDEX + 28]);
        assert_ne!(
            &patched[SESSION_ID_INDEX + 28..SESSION_ID_INDEX + 32],
            &hello[SESSION_ID_INDEX + 28..SESSION_ID_INDEX + 32],
            "the session-id tail must carry the HMAC"
        );
        assert!(
            upstream_verify_client_hello(&patched, "shared-password"),
            "the server-side v3 formula must accept the patched hello"
        );
        assert!(!upstream_verify_client_hello(&patched, "wrong-password"));
        assert!(!upstream_verify_client_hello(&hello, "shared-password"));
        // The replayed random stream differs exactly in those 4 bytes.
        assert_eq!(replay.len(), random_stream.len());
        let ps = SESSION_ID_INDEX + 28;
        assert_eq!(&replay[32 + 28..32 + 32], &patched[ps..ps + 4]);
        assert_eq!(&replay[..32], &random_stream[..32]);
        assert_eq!(&replay[32 + 32..], &random_stream[32 + 32..]);
    }

    #[test]
    fn patching_requires_a_32_byte_session_id() {
        let mut hello = synthetic_client_hello(1);
        hello[SESSION_ID_LENGTH_INDEX] = 0;
        let err = patch_client_hello(&hello, "pw", &[0u8; 64]).unwrap_err();
        assert!(err.to_string().contains("legacy_session_id"), "{err}");
    }

    #[test]
    fn server_random_and_tls13_detection() {
        // ServerHello with a supported_versions extension = TLS 1.3.
        let mut body = vec![0x03, 0x03];
        body.extend_from_slice(&[0x5A; TLS_RANDOM_SIZE]);
        body.push(TLS_SESSION_ID_SIZE as u8);
        body.extend_from_slice(&[0x42; TLS_SESSION_ID_SIZE]);
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(0);
        // extensions: supported_versions (43) = 0x0304
        let ext = [0x00, 0x2B, 0x00, 0x02, 0x03, 0x04];
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut record = vec![REC_HANDSHAKE, 0x03, 0x03];
        record.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        record.push(HS_SERVER_HELLO);
        record.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        record.extend_from_slice(&body);

        assert_eq!(server_random(&record), Some([0x5A; TLS_RANDOM_SIZE]));
        assert!(server_hello_supports_tls13(&record));

        // Same hello without the extension = TLS 1.2.
        let mut tls12 = record.clone();
        tls12.truncate(tls12.len() - 6);
        let len = tls12.len() - TLS_HEADER_SIZE - 4;
        tls12[3..5].copy_from_slice(&((len + 4) as u16).to_be_bytes());
        tls12[6..9].copy_from_slice(&(len as u32).to_be_bytes()[1..]);
        assert_eq!(server_random(&tls12), Some([0x5A; TLS_RANDOM_SIZE]));
        assert!(!server_hello_supports_tls13(&tls12));

        // A ClientHello is not a ServerHello.
        assert_eq!(server_random(&synthetic_client_hello(2)), None);
    }

    #[test]
    fn hmac_chain_matches_a_straightforward_computation() {
        let random = [9u8; TLS_RANDOM_SIZE];
        let mut chain = HmacChain::new("pw", &random, Some(b'C'));
        chain.update(b"first");
        let mut mac = Hmac::<Sha1>::new_from_slice(b"pw").unwrap();
        mac.update(&random);
        mac.update(b"C");
        mac.update(b"first");
        assert_eq!(chain.tag(), mac.clone().finalize().into_bytes()[..4]);
        // Folding the tag back in advances the chain (v3 writeRecord).
        let tag = chain.tag();
        chain.update(&tag);
        mac.update(&tag);
        assert_eq!(chain.tag(), mac.clone().finalize().into_bytes()[..4]);
        // The handshake chain has no direction byte.
        let mut plain = HmacChain::new("pw", &random, None);
        plain.update(b"first");
        let mut mac = Hmac::<Sha1>::new_from_slice(b"pw").unwrap();
        mac.update(&random);
        mac.update(b"first");
        assert_eq!(plain.tag(), mac.finalize().into_bytes()[..4]);
    }

    // ----------------------------------------------------- loopback setup

    /// A self-signed certificate generated at test time (nothing usable as
    /// a credential is committed).
    fn test_server_config() -> Arc<rustls::ServerConfig> {
        let certified = rcgen::generate_simple_self_signed(vec!["shadowtls.test".to_string()])
            .expect("rcgen self-signed cert");
        let cert = CertificateDer::from(certified.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let provider = Arc::new(ring_provider::default_provider());
        Arc::new(
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert], key)
                .expect("server config"),
        )
    }

    /// Read one TLS record (header + payload) from `rd`.
    async fn read_record(rd: &mut (impl AsyncRead + Unpin)) -> io::Result<Vec<u8>> {
        let mut header = [0u8; TLS_HEADER_SIZE];
        rd.read_exact(&mut header).await?;
        let len = usize::from(u16::from_be_bytes([header[3], header[4]]));
        let mut record = header.to_vec();
        record.resize(TLS_HEADER_SIZE + len, 0);
        rd.read_exact(&mut record[TLS_HEADER_SIZE..]).await?;
        Ok(record)
    }

    /// Test-only mimic of mihomo's v3 server (`server.go` + `v3.go`): it
    /// verifies the ClientHello HMAC, terminates the TLS handshake with
    /// rustls (standing in for the relayed real site) and applies the v3
    /// server-side wrapping, echoing tunnelled payloads back.
    async fn v3_server_mimic(
        io: DuplexStream,
        password: String,
        server_config: Arc<rustls::ServerConfig>,
    ) -> std::result::Result<(), String> {
        let (mut rd, mut wr) = tokio::io::split(io);
        let mut tls = rustls::ServerConnection::new(server_config)
            .map_err(|e| format!("server conn: {e}"))?;

        // 1. The first frame must be the authenticated ClientHello.
        let hello = read_record(&mut rd)
            .await
            .map_err(|e| format!("read client hello: {e}"))?;
        if !upstream_verify_client_hello(&hello, &password) {
            return Err("client hello HMAC mismatch".to_string());
        }

        let mut srv_random: Option<[u8; TLS_RANDOM_SIZE]> = None;
        // Handshake-phase write chain (R0), then the data-phase `S` chain.
        let mut write_chain: Option<HmacChain> = None;
        // Data-phase chain verifying the client's `C` writes.
        let mut verify_chain: Option<HmacChain> = None;
        let mut switched = false;

        // 2. Relay it to "the real site" (rustls) and send the flight back.
        tls.read_tls(&mut &hello[..]).map_err(|e| format!("read_tls: {e}"))?;
        tls.process_new_packets()
            .map_err(|e| format!("server process: {e}"))?;
        send_server_flight(
            &mut tls,
            &mut wr,
            &password,
            &mut srv_random,
            &mut write_chain,
            switched,
        )
        .await?;

        // 3. Relay until the client's first authenticated tunnel frame,
        //    then echo the tunnel both ways.
        loop {
            let frame = match read_record(&mut rd).await {
                Ok(frame) => frame,
                Err(_) => return Ok(()), // the test closed the stream
            };
            let maybe_switch = frame[0] == REC_APPLICATION_DATA
                && frame.len() > TLS_HMAC_HEADER_SIZE
                && srv_random.is_some();
            if maybe_switch {
                let random = srv_random.unwrap();
                let tag = &frame[TLS_HEADER_SIZE..TLS_HMAC_HEADER_SIZE];
                if !switched {
                    // copyByFrameUntilHMACMatches: a fresh `C` chain decides.
                    let mut probe = HmacChain::new(&password, &random, Some(b'C'));
                    probe.update(&frame[TLS_HMAC_HEADER_SIZE..]);
                    if probe.tag() == tag {
                        switched = true;
                        let mut chain = HmacChain::new(&password, &random, Some(b'C'));
                        chain.update(&frame[TLS_HMAC_HEADER_SIZE..]);
                        chain.update(tag);
                        verify_chain = Some(chain);
                        write_chain = Some(HmacChain::new(&password, &random, Some(b'S')));
                    }
                } else {
                    let chain = verify_chain.as_mut().ok_or("no verify chain")?;
                    chain.update(&frame[TLS_HMAC_HEADER_SIZE..]);
                    let expected = chain.tag();
                    if expected != tag {
                        return Err("tunnel frame HMAC mismatch".to_string());
                    }
                    chain.update(&expected);
                }
                if switched {
                    let chain = write_chain.as_mut().unwrap();
                    let payload = &frame[TLS_HMAC_HEADER_SIZE..];
                    chain.update(payload);
                    let tag = chain.tag();
                    chain.update(&tag);
                    let mut out = vec![0u8; TLS_HEADER_SIZE];
                    out[0] = REC_APPLICATION_DATA;
                    out[1] = 3;
                    out[2] = 3;
                    out[3..5]
                        .copy_from_slice(&((payload.len() + HMAC_SIZE) as u16).to_be_bytes());
                    out.extend_from_slice(&tag);
                    out.extend_from_slice(payload);
                    wr.write_all(&out).await.map_err(|e| e.to_string())?;
                    continue;
                }
            }
            // Handshake-phase record: relay to the "real site".
            tls.read_tls(&mut &frame[..]).map_err(|e| format!("read_tls: {e}"))?;
            tls.process_new_packets()
                .map_err(|e| format!("server process: {e}"))?;
            send_server_flight(
                &mut tls,
                &mut wr,
                &password,
                &mut srv_random,
                &mut write_chain,
                switched,
            )
            .await?;
        }
    }

    /// Wrap and send everything the "real site" (rustls) has queued,
    /// mirroring v3.go: the first ServerHello goes out unwrapped
    /// (server.go writes it before the v3 relay starts), the handshake
    /// phase wraps only application records (XOR + tag,
    /// `copyByFrameWithModification`) and relays other record types
    /// verbatim, while the tunnel phase tags every record
    /// (`verifiedConn.writeRecord`).
    async fn send_server_flight(
        tls: &mut rustls::ServerConnection,
        wr: &mut (impl AsyncWrite + Unpin),
        password: &str,
        srv_random: &mut Option<[u8; TLS_RANDOM_SIZE]>,
        write_chain: &mut Option<HmacChain>,
        switched: bool,
    ) -> std::result::Result<(), String> {
        let mut flight = Vec::new();
        while tls.wants_write() {
            tls.write_tls(&mut flight).map_err(|e| format!("write_tls: {e}"))?;
        }
        let mut rest = &flight[..];
        while !rest.is_empty() {
            let record = read_record(&mut rest)
                .await
                .map_err(|e| format!("split flight: {e}"))?;
            if srv_random.is_none() {
                if let Some(random) = server_random(&record) {
                    *srv_random = Some(random);
                    *write_chain = Some(HmacChain::new(password, &random, None));
                    wr.write_all(&record).await.map_err(|e| e.to_string())?;
                    continue;
                }
            }
            if !switched && record[0] != REC_APPLICATION_DATA {
                wr.write_all(&record).await.map_err(|e| e.to_string())?;
                continue;
            }
            let random = srv_random.ok_or("record before the server hello")?;
            let chain = write_chain.as_mut().ok_or("no write chain")?;
            let mut payload = record[TLS_HEADER_SIZE..].to_vec();
            if !switched {
                xor_slice(&mut payload, &kdf(password, &random));
            }
            chain.update(&payload);
            let tag = chain.tag();
            if switched {
                // The tunnel chain folds the tag back in (v3 writeRecord).
                chain.update(&tag);
            }
            let mut out = if switched {
                vec![REC_APPLICATION_DATA, 3, 3, 0, 0]
            } else {
                record[..TLS_HEADER_SIZE].to_vec()
            };
            out[3..5].copy_from_slice(&((payload.len() + HMAC_SIZE) as u16).to_be_bytes());
            out.extend_from_slice(&tag);
            out.extend_from_slice(&payload);
            wr.write_all(&out).await.map_err(|e| e.to_string())?;
        }
        Ok(())
    }

    fn test_cfg(password: &str, skip_verify: bool) -> ShadowTlsOut {
        ShadowTlsOut {
            server: "127.0.0.1".into(),
            port: 0,
            password: password.into(),
            sni: "shadowtls.test".into(),
            skip_verify,
        }
    }

    /// Run the mimic against one `connect()` call and return the tunnel.
    /// `server_password` is what the mimic expects, `cfg` what the client
    /// sends (they differ in the wrong-password test).
    async fn connect_through_mimic(
        cfg: &ShadowTlsOut,
        server_password: &str,
    ) -> Result<BoxProxyStream> {
        let (client, server) = tokio::io::duplex(256 * 1024);
        let password = server_password.to_string();
        let server_config = test_server_config();
        tokio::spawn(async move {
            match v3_server_mimic(server, password, server_config).await {
                Ok(()) => {}
                Err(e) => panic!("shadowtls mimic failed: {e}"),
            }
        });
        tokio::time::timeout(
            Duration::from_secs(20),
            connect(cfg, Box::new(client) as BoxProxyStream),
        )
        .await
        .expect("shadowtls connect timed out")
    }

    #[tokio::test]
    async fn v3_handshake_and_tunnel_roundtrip() {
        // Password generated per run; no credential literal anywhere.
        let password = format!("pw-{:016x}", rand::random::<u64>());
        let cfg = test_cfg(&password, true);
        let mut stream = connect_through_mimic(&cfg, &cfg.password).await.unwrap();

        stream.write_all(b"ping through the tunnel").await.unwrap();
        let mut buf = [0u8; 23];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"ping through the tunnel");

        // More than one application record (16 KiB cap) each way.
        let payload: Vec<u8> = (0..40 * 1024).map(|i| (i % 253) as u8).collect();
        let (mut rd, mut wr) = tokio::io::split(stream);
        let expected_len = payload.len();
        let echo = tokio::spawn(async move {
            let mut got = vec![0u8; expected_len];
            rd.read_exact(&mut got).await.unwrap();
            got
        });
        wr.write_all(&payload).await.unwrap();
        wr.flush().await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(20), echo)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn wrong_password_fails_the_handshake() {
        let cfg = test_cfg("pw-correct", true);
        let mut bad = cfg.clone();
        bad.password = "pw-wrong".into();
        let err = match connect_through_mimic(&bad, &cfg.password).await {
            Ok(_) => panic!("a wrong password must not authenticate"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("closed during the handshake"), "{err}");
    }

    #[tokio::test]
    async fn verified_mode_rejects_the_self_signed_peer() {
        let cfg = test_cfg("pw-generated", false);
        let err = match connect_through_mimic(&cfg, &cfg.password).await {
            Ok(_) => panic!("a self-signed handshake peer must not verify"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("TLS handshake with the handshake peer"),
            "{err}"
        );
    }
}