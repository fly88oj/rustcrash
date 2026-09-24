//! RestLS client (v1.2 of the RestLS protocol, the `restls-client-go`
//! branch mihomo vendors): a genuine TLS handshake to the camouflage SNI
//! whose ClientHello session id carries a password-derived MAC, followed by
//! script-driven `0x17`-record framing for the tunnelled bytes.
//!
//! Upstream: mihomo `adapter/outbound/restls.go` delegates to
//! `github.com/metacubex/restls-client-go` (branch `restls-utls`;
//! `transport/restls/restls.go` builds the config and calls
//! `tls.UClient(conn, config, HelloChrome_Auto)`). The wire, as the restls
//! server sees it:
//!
//! 1. **Key** (`restls_utils.go NewRestlsConfig`):
//!    `key = blake3_derive_key("restls-traffic-key", password)` (32 bytes).
//!    Every MAC below is `RestlsHmac(key)` = BLAKE3 **keyed** hash
//!    (`blake3.New(32, key)`), 32-byte output.
//! 2. **Client authentication** — the TLS 1.3 path
//!    (`handshake_client.go generateSessionIDForTLS13`):
//!    `sessionId[0..16] = MAC(keyShareGroup_be16 ‖ keySharePublicKey)[0..16]`
//!    (`restlsHandshakeMACLength` = 16; the remaining session id bytes stay
//!    random). The server validates this against the key share it actually
//!    decrypts with.
//! 3. **Server authentication** (`conn.go readRecordOrCCS` +
//!    `restlsPlugin.expectServerAuth`): the *first* server record encrypted
//!    under new keys (the first `0x17`-typed record after the ServerHello;
//!    `numCipherChange == 1`) has its body XOR-ed with the first 16 bytes
//!    of `MAC(serverRandom)`. Upstream falls back to the raw record for a
//!    non-restls (plain TLS) peer; an outbound restls client must see the
//!    XOR succeed, so this port XOR-es unconditionally and fails the
//!    handshake otherwise.
//! 4. **Framed application records** (`conn.go writeRestlsApplicationRecord`,
//!    `write0x17AuthHeader`, `extractRestlsAppData`): after the handshake
//!    every record is `[0x17 0x03 0x03 payloadLen_be16] [authMac 8]
//!    [mask⊕(dataLen_be16 ‖ cmd 2)] [data] [padding]` with
//!    `payloadLen = dataLen + paddingLen + 12` (cap 16384 = `maxPlaintext`;
//!    `restlsAppDataAuthHeaderLength = restlsAppDataMACLength(8) +
//!    restlsMaskLength(4)`). Per-direction, per-record counters feed the
//!    hashes (`restlsAuthHeaderHash`):
//!    `MAC(serverRandom ‖ "client-to-server"/"server-to-client" ‖
//!    counter_be64)`; `mask = hash[0..4]` over the first ≤ 32 bytes of
//!    `data ‖ padding`, `authMac = hash[0..8]` over the record header and
//!    everything from the masked length on (padding included).
//! 5. **Script** (`restls_utils.go parseRecordScript`, default
//!    `"250?100<1,350~100<1,600~100,300~200,300~100"`): each comma-separated
//!    line is `target[~range|?range][<N]`. While the to-server counter is
//!    inside the script, a record's target data length is the line's
//!    (`~`: uniform `target + rand(range)`; `?`: fixed at parse time) and
//!    short payloads are padded up to it; `dataLen == 0` records get
//!    `19 + rand(100)` padding. `<N` = `ActResponse(N)`: the record carries
//!    command bytes `[0x01, N]`, asks the peer to emit N random
//!    (`restls-random-response`) records, and interrupts the writer until
//!    the next framed record arrives (`needInterrupt`).
//!
//! ## Scope and deviations
//!
//! * **`version-hint: tls13` is implemented end-to-end.** mihomo also
//!   accepts `tls12` (`handshake_client.go generateSessionIDFromPKnTicket`:
//!   three *eager* ECDHE keys — X25519, P-256, P-384 — whose public keys
//!   are MAC-ed into the session id at fixed offsets
//!   (`restls12ClientAuthLayout3 = [0, 11, 22, 32]`, or `Layout4` with a
//!   session ticket) and then reused in the TLS 1.2 key exchange
//!   (`key_agreement.go keyPtr[curveIDMap[curveID]]`), plus the
//!   CCS/`clientFinishedIsFirst` ordering). rustls' TLS 1.2 client offers
//!   no hook to supply client-chosen ephemeral keys per group and the
//!   engine has no P-256/P-384 provider, so `tls12` is **deferred**;
//!   `connect` rejects it with a pointer to this note.
//! * **ClientHello fingerprint**: uTLS `HelloChrome_Auto` upstream; here a
//!   plain rustls TLS 1.3 hello offering exactly one X25519 key share (the
//!   group whose public key is MAC-ed). The MAC machinery does not depend
//!   on the rest of the fingerprint.
//! * **Post-handshake fallback decrypt**: upstream tries plain-TLS
//!   decryption of records that fail the framing check (NewSessionTicket
//!   records) and drops them; the rustls connection is discarded after the
//!   handshake (mihomo likewise starts from a fresh session), so this port
//!   drops unframable records while still counting the counter — it cannot
//!   distinguish tickets from garbage without the TLS keys.
//! * **Close**: upstream sends an encrypted TLS close_notify; this port
//!   shuts the transport down.
//!
//! The framing is pinned by an in-test mimic that re-implements the server
//! checks (session-id MAC over the key share, the XOR-ed first flight and
//! `extractRestlsAppData`) straight from upstream, behind a real rustls
//! server.

use std::cell::Cell;
use std::io;
use std::pin::Pin;
use std::sync::{Arc, OnceLock};
use std::task::{ready, Context, Poll};

use bytes::{Buf, BytesMut};
use rand::RngCore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring as ring_provider;
use rustls::crypto::{CryptoProvider, GetRandomFailed, SecureRandom};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tracing::debug;

use crate::error::{Error, Result};
use crate::stream::BoxProxyStream;

/// `conn.go restlsAppDataMACLength`.
const AUTH_MAC_LEN: usize = 8;
/// `conn.go restlsCmdLength`.
const CMD_LEN: usize = 2;
/// `conn.go restlsMaskLength = restlsCmdLength + 2`.
const MASK_LEN: usize = CMD_LEN + 2;
/// `conn.go restlsAppDataAuthHeaderLength`.
const AUTH_HEADER_LEN: usize = AUTH_MAC_LEN + MASK_LEN;
/// `conn.go restlsHandshakeMACLength`.
const HANDSHAKE_MAC_LEN: usize = 16;
/// `conn.go recordHeaderLen`.
const RECORD_HEADER_LEN: usize = 5;
/// `common.go maxPlaintext`.
const MAX_PLAINTEXT: usize = 16384;
/// Largest record accepted from the peer.
const MAX_RECORD_LEN: usize = RECORD_HEADER_LEN + MAX_PLAINTEXT + 2048;
/// `generateSessionIDForTLS13` writes 16 MAC bytes into the session id.
const SESSION_ID_MAC_LEN: usize = HANDSHAKE_MAC_LEN;
/// ClientHello offsets: session id length byte at 43, session id at 44
/// (record 5 + handshake header 4 + legacy_version 2 + random 32).
const SESSION_ID_LENGTH_INDEX: usize = RECORD_HEADER_LEN + 1 + 3 + 2 + 32;
const SESSION_ID_INDEX: usize = SESSION_ID_LENGTH_INDEX + 1;
/// ServerHello.random offset.
const SERVER_RANDOM_INDEX: usize = RECORD_HEADER_LEN + 1 + 3 + 2;
/// key_share extension (RFC 8446) and the X25519 group id. The share
/// extraction is the server-side auth check the test mimic re-implements.
#[cfg(test)]
const EXT_KEY_SHARE: u16 = 51;
const GROUP_X25519: u16 = 0x001d;

const REC_ALERT: u8 = 21;
const REC_HANDSHAKE: u8 = 22;
const REC_APP_DATA: u8 = 23;
const HS_SERVER_HELLO: u8 = 2;

/// `restls_utils.go defaultRestlsScript`.
const DEFAULT_SCRIPT: &str = "250?100<1,350~100<1,600~100,300~200,300~100";

/// Outbound RestLS endpoint — mihomo's restls fields: password, SNI,
/// version hint (`tls12`/`tls13`), optional restls script, certificate
/// verification toggle, and the UDP capability flag.
#[derive(Debug, Clone)]
pub struct RestlsOut {
    pub password: String,
    pub sni: String,
    /// mihomo `version-hint`: `"tls12"` or `"tls13"`.
    pub version: String,
    /// mihomo `restls-script`; `None`/empty selects the upstream default.
    pub restls_script: Option<String>,
    pub skip_cert_verify: bool,
    /// Capability flag only — `connect` is a stream handshake.
    pub udp: bool,
}

// ------------------------------------------------------------------ script

/// A restls record command (`restls_utils.go restlsCommand`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Cmd {
    Noop,
    Response(u8),
}

impl Cmd {
    /// `toBytes`: noop `[0x00, 0]`, response `[0x01, n]`.
    fn to_bytes(self) -> [u8; CMD_LEN] {
        match self {
            Cmd::Noop => [0x00, 0x00],
            Cmd::Response(n) => [0x01, n],
        }
    }

    fn need_interrupt(self) -> bool {
        matches!(self, Cmd::Response(_))
    }

    /// `parseCommand`.
    fn parse(b: [u8; CMD_LEN]) -> Result<Self> {
        match b[0] {
            0x00 => Ok(Cmd::Noop),
            0x01 => Ok(Cmd::Response(b[1])),
            _ => Err(Error::protocol("restls: unsupported record command")),
        }
    }
}

/// One script line: a target data length with an optional uniform range.
#[derive(Debug, Clone, Copy)]
struct Line {
    target: i16,
    /// Uniform random extra (`TargetLength[1]`); 0 = fixed.
    range: i16,
}

impl Line {
    /// `TargetLength.Len`.
    fn len(&self) -> usize {
        if self.range != 0 {
            let extra = rand::random::<u32>() % self.range.unsigned_abs() as u32;
            self.target as usize + extra as usize
        } else {
            self.target as usize
        }
    }
}

/// `parseRecordScript`. Commas separate lines; a line is
/// `target`, then optionally `~range` or `?range`, then optionally `<N`.
fn parse_record_script(script: &str) -> Result<Vec<(Line, Cmd)>> {
    let mut lines = Vec::new();
    for raw in script.replace(' ', "").split(',') {
        if raw.is_empty() {
            continue;
        }
        let mut rest = raw.as_bytes();
        let target = get_integer(&mut rest)? as i32;
        if target > 32767 {
            return Err(Error::config(format!(
                "restls: script target len > 32767: {raw:?}"
            )));
        }
        let mut line = Line {
            target: target as i16,
            range: 0,
        };
        if rest.is_empty() {
            lines.push((line, Cmd::Noop));
            continue;
        }
        if rest[0] == b'~' || rest[0] == b'?' {
            let fixed = rest[0] == b'?';
            rest = &rest[1..];
            let range = get_integer(&mut rest)? as i32;
            if range > 32767 || range + target > 32768 {
                return Err(Error::config(format!(
                    "restls: script random target out of range: {raw:?}"
                )));
            }
            line.range = range as i16;
            if fixed {
                // `?` picks once, at parse time.
                line.target = line.len() as i16;
                line.range = 0;
            }
        }
        if rest.is_empty() {
            lines.push((line, Cmd::Noop));
            continue;
        }
        if rest[0] == b'<' {
            rest = &rest[1..];
            let n = get_integer(&mut rest)?;
            if !rest.is_empty() || n >= 255 {
                return Err(Error::config(format!(
                    "restls: invalid response count in script: {raw:?}"
                )));
            }
            lines.push((line, Cmd::Response(n as u8)));
        } else {
            return Err(Error::config(format!(
                "restls: unexpected script content: {raw:?}"
            )));
        }
    }
    Ok(lines)
}

/// `getInteger`: leading decimal digits.
fn get_integer(script: &mut &[u8]) -> Result<u32> {
    let mut res: u32 = 0;
    let mut i = 0;
    while i < script.len() && script[i].is_ascii_digit() {
        res = res
            .checked_mul(10)
            .and_then(|v| v.checked_add((script[i] - b'0') as u32))
            .ok_or_else(|| Error::config("restls: script number overflow"))?;
        if res > 32768 {
            return Err(Error::config("restls: script target len > 32768"));
        }
        i += 1;
    }
    *script = &script[i..];
    Ok(res)
}

// ------------------------------------------------------------------ hashing

/// `restls_utils.go NewRestlsConfig`: `blake3.DeriveKey(32,
/// "restls-traffic-key", password)`.
fn restls_secret(password: &str) -> [u8; 32] {
    blake3::derive_key("restls-traffic-key", password.as_bytes())
}

/// `restls_utils.go RestlsHmac(key)`: BLAKE3 keyed hash, 32-byte digest.
fn restls_hmac(secret: &[u8; 32], parts: &[&[u8]]) -> [u8; 32] {
    let mut h = blake3::Hasher::new_keyed(secret);
    for p in parts {
        h.update(p);
    }
    *h.finalize().as_bytes()
}

/// The direction labels of `Conn.restlsAuthHeaderHash`.
const DIR_TO_CLIENT: &[u8] = b"server-to-client";
const DIR_TO_SERVER: &[u8] = b"client-to-server";

/// A fresh keyed hash seeded with `serverRandom ‖ direction ‖ counter_be64`
/// (`restlsAuthHeaderHash`); callers append the record-specific input.
fn auth_header_hasher(
    secret: &[u8; 32],
    server_random: &[u8; 32],
    dir: &[u8],
    counter: u64,
) -> blake3::Hasher {
    let mut h = blake3::Hasher::new_keyed(secret);
    h.update(server_random);
    h.update(dir);
    h.update(&counter.to_be_bytes());
    h
}

/// The handshake-phase server MAC (`readRecordOrCCS`:
/// `hmac.Write(serverRandom)`, `serverRandomMac[:restlsHandshakeMACLength]`).
fn server_random_mac(secret: &[u8; 32], server_random: &[u8; 32]) -> [u8; HANDSHAKE_MAC_LEN] {
    let digest = restls_hmac(secret, &[server_random]);
    let mut out = [0u8; HANDSHAKE_MAC_LEN];
    out.copy_from_slice(&digest[..HANDSHAKE_MAC_LEN]);
    out
}

/// `conn.go xorWithMac`: XOR `mac` into `data` (length-clamped).
fn xor_with_mac(data: &mut [u8], mac: &[u8]) {
    let n = data.len().min(mac.len());
    for (b, m) in data.iter_mut().zip(mac[..n].iter()) {
        *b ^= *m;
    }
}

/// Extract `ServerHello.random` (same layout as shadowtls' helper).
fn server_random(record: &[u8]) -> Option<[u8; 32]> {
    if record.len() < SERVER_RANDOM_INDEX + 32
        || record[0] != REC_HANDSHAKE
        || record[RECORD_HEADER_LEN] != HS_SERVER_HELLO
    {
        return None;
    }
    record[SERVER_RANDOM_INDEX..SERVER_RANDOM_INDEX + 32]
        .try_into()
        .ok()
}

/// Locate the X25519 key share of a ClientHello record — the value the
/// session-id MAC covers (server-side check; used by the test mimic).
#[cfg(test)]
fn client_hello_x25519_share(record: &[u8]) -> Option<Vec<u8>> {
    if record[0] != REC_HANDSHAKE || record[RECORD_HEADER_LEN] != 0x01 {
        return None;
    }
    // Walk past session id, cipher suites and compression to the extensions.
    let mut off = SESSION_ID_INDEX + record[SESSION_ID_LENGTH_INDEX] as usize;
    let suite_len = usize::from(u16::from_be_bytes([*record.get(off)?, *record.get(off + 1)?]));
    off += 2 + suite_len + 2;
    let ext_len = usize::from(u16::from_be_bytes([*record.get(off)?, *record.get(off + 1)?]));
    off += 2;
    let mut rest = record.get(off..off + ext_len)?;
    while rest.len() >= 4 {
        let ext_type = u16::from_be_bytes([rest[0], rest[1]]);
        let len = usize::from(u16::from_be_bytes([rest[2], rest[3]]));
        rest = &rest[4..];
        if len > rest.len() {
            return None;
        }
        if ext_type == EXT_KEY_SHARE {
            // key_share body: list_len(2), then `group(2) ‖ len(2) ‖ key`.
            let body = &rest[..len];
            if body.len() < 2 {
                return None;
            }
            let list_len = usize::from(u16::from_be_bytes([body[0], body[1]]));
            let mut entry = &body[2..(2 + list_len).min(body.len())];
            while entry.len() >= 4 {
                let group = u16::from_be_bytes([entry[0], entry[1]]);
                let klen = usize::from(u16::from_be_bytes([entry[2], entry[3]]));
                if entry.len() < 4 + klen {
                    break;
                }
                if group == GROUP_X25519 {
                    return Some(entry[4..4 + klen].to_vec());
                }
                entry = &entry[4 + klen..];
            }
        }
        rest = &rest[len..];
    }
    None
}

// ------------------------------------------- fixed X25519 + patched session id

thread_local! {
    /// The per-connection fixed X25519 key pair, installed while the
    /// ClientHello is built (the hello pass never awaits, so it stays on
    /// one thread).
    static FIXED_KEY: Cell<Option<([u8; 32], [u8; 32])>> = const { Cell::new(None) };
    /// The MAC stamped into the ClientHello's random draws while it is
    /// being built. rustls draws the client random and the session id as
    /// separate 32-byte fills whose ORDER is an implementation detail, so
    /// every 32-byte draw is stamped; the post-flight check verifies the
    /// session id carries it (the extra copy inside the client random is
    /// inert — it is random bytes to every observer).
    static HELLO_PATCH: Cell<Option<[u8; SESSION_ID_MAC_LEN]>> = const { Cell::new(None) };
}

fn system_random() -> &'static dyn SecureRandom {
    static FALLBACK: OnceLock<&'static dyn SecureRandom> = OnceLock::new();
    *FALLBACK.get_or_init(|| ring_provider::default_provider().secure_random)
}

/// The random source of the restls TLS config: system entropy, except that
/// the 32-byte draws inside the ClientHello are stamped with the auth MAC
/// (`generateSessionIDForTLS13`). rustls hashes the hello after our fill
/// returns, so its transcript stays consistent and no replay is needed
/// (unlike shadowtls, whose HMAC covers the whole hello).
#[derive(Debug)]
struct RestlsRandom;

static RESTLS_RANDOM: RestlsRandom = RestlsRandom;

impl SecureRandom for RestlsRandom {
    fn fill(&self, buf: &mut [u8]) -> std::result::Result<(), GetRandomFailed> {
        system_random().fill(buf)?;
        if let Some(mac) = HELLO_PATCH.with(Cell::get) {
            if buf.len() == 32 {
                buf[..SESSION_ID_MAC_LEN].copy_from_slice(&mac);
            }
        }
        Ok(())
    }
}

/// A key-exchange group returning a fixed, pre-generated key pair: the
/// session-id MAC covers this public key, so it must be known before the
/// hello is emitted (RFC 7748 clamping via curve25519-dalek, as shadowtls'
/// replayable group).
#[derive(Debug)]
struct FixedX25519;

static FIXED_X25519: FixedX25519 = FixedX25519;

#[derive(Debug)]
struct FixedExchange {
    scalar: [u8; 32],
    public: [u8; 32],
}

impl rustls::crypto::SupportedKxGroup for FixedX25519 {
    fn start(&self) -> std::result::Result<Box<dyn rustls::crypto::ActiveKeyExchange>, rustls::Error> {
        FIXED_KEY.with(Cell::get)
            .map(|(scalar, public)| {
                Box::new(FixedExchange { scalar, public })
                    as Box<dyn rustls::crypto::ActiveKeyExchange>
            })
            .ok_or_else(|| rustls::Error::General("restls: no fixed key installed".into()))
    }

    fn name(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

impl rustls::crypto::ActiveKeyExchange for FixedExchange {
    fn complete(
        self: Box<Self>,
        peer_pub_key: &[u8],
    ) -> std::result::Result<rustls::crypto::SharedSecret, rustls::Error> {
        let peer: [u8; 32] = peer_pub_key
            .try_into()
            .map_err(|_| rustls::Error::General("restls: bad X25519 key share".into()))?;
        let shared = curve25519_dalek::montgomery::MontgomeryPoint(peer).mul_clamped(self.scalar).0;
        if shared.iter().all(|b| *b == 0) {
            return Err(rustls::Error::General(
                "restls: X25519 peer key share is a low-order point".into(),
            ));
        }
        Ok(rustls::crypto::SharedSecret::from(shared.as_slice()))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> rustls::NamedGroup {
        rustls::NamedGroup::X25519
    }
}

/// Accept-anything verifier for `skip-cert-verify` (mihomo's
/// `InsecureSkipVerify` on the restls config).
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

/// TLS 1.3-only client config with the restls crypto provider.
fn restls_config(cfg: &RestlsOut) -> Result<Arc<ClientConfig>> {
    let mut provider = ring_provider::default_provider();
    provider.secure_random = &RESTLS_RANDOM;
    provider.kx_groups = vec![&FIXED_X25519];
    let provider = Arc::new(provider);
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::config(format!("restls: tls: {e}")))?;
    let config = if cfg.skip_cert_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth()
    } else {
        // Same policy as transport::tls_client_config.
        let mut roots = RootCertStore::empty();
        let mut loaded = 0usize;
        let certs = rustls_native_certs::load_native_certs()
            .map_err(|e| Error::config(format!("restls: native cert store: {e}")))?;
        for cert in certs {
            roots
                .add(cert)
                .map_err(|e| Error::config(format!("restls: bad native cert: {e}")))?;
            loaded += 1;
        }
        if loaded == 0 {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        builder
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    Ok(Arc::new(config))
}

/// Drain everything rustls has queued for the socket.
fn drain_tls(conn: &mut ClientConnection) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    while conn.wants_write() {
        if conn
            .write_tls(&mut out)
            .map_err(|e| Error::config(format!("restls: tls write: {e}")))? == 0
        {
            break;
        }
    }
    Ok(out)
}

/// Build the ClientHello whose session id already carries the restls MAC,
/// returning the connection and its initial flight (hello + TLS 1.3 CCS).
fn restls_client_hello(
    config: &Arc<ClientConfig>,
    sni: &str,
    secret: &[u8; 32],
) -> Result<(ClientConnection, Vec<u8>)> {
    // A fixed X25519 pair: its public key is the MAC input, known upfront.
    let mut scalar = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut scalar);
    let public = curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(scalar).0;
    FIXED_KEY.with(|k| k.set(Some((scalar, public))));
    let mut mac_input = GROUP_X25519.to_be_bytes().to_vec();
    mac_input.extend_from_slice(&public);
    let digest = restls_hmac(secret, &[&mac_input]);
    let mut mac = [0u8; SESSION_ID_MAC_LEN];
    mac.copy_from_slice(&digest[..SESSION_ID_MAC_LEN]);
    HELLO_PATCH.with(|p| p.set(Some(mac)));

    let name = rustls::pki_types::ServerName::try_from(sni.to_owned())
        .map_err(|_| Error::config(format!("restls: invalid SNI {sni:?}")))?;
    let result = (|| {
        let mut tls = ClientConnection::new(config.clone(), name)
            .map_err(|e| Error::config(format!("restls: TLS client init: {e}")))?;
        let mut flight = drain_tls(&mut tls)?;
        if flight.is_empty() {
            let _ = tls.process_new_packets();
            flight = drain_tls(&mut tls)?;
        }
        // Fail loudly if the patch did not land where the server reads it.
        if flight.len() < SESSION_ID_INDEX + SESSION_ID_MAC_LEN
            || flight[SESSION_ID_LENGTH_INDEX] != 32
            || flight[SESSION_ID_INDEX..SESSION_ID_INDEX + SESSION_ID_MAC_LEN] != mac
        {
            return Err(Error::crypto(
                "restls: could not stamp the session-id MAC (rustls ClientHello layout changed)",
            ));
        }
        Ok((tls, flight))
    })();
    HELLO_PATCH.with(|p| p.set(None));
    FIXED_KEY.with(|k| k.set(None));
    result
}

/// Read exactly one TLS record from `rbuf`, refilling from `transport`.
async fn read_one_record<R: AsyncRead + Unpin>(
    transport: &mut R,
    rbuf: &mut BytesMut,
) -> Result<Vec<u8>> {
    let want = |rbuf: &BytesMut| -> Option<usize> {
        if rbuf.len() < RECORD_HEADER_LEN {
            return None;
        }
        let len = usize::from(u16::from_be_bytes([rbuf[3], rbuf[4]]));
        if RECORD_HEADER_LEN + len > MAX_RECORD_LEN {
            return Some(usize::MAX);
        }
        Some(RECORD_HEADER_LEN + len)
    };
    loop {
        match want(rbuf) {
            Some(usize::MAX) => return Err(Error::protocol("restls: oversized record")),
            Some(total) if rbuf.len() >= total => return Ok(rbuf.split_to(total).to_vec()),
            _ => {}
        }
        let mut tmp = [0u8; 16 * 1024];
        let n = transport.read(&mut tmp).await?;
        if n == 0 {
            return Err(Error::network("restls: EOF mid-record"));
        }
        rbuf.extend_from_slice(&tmp[..n]);
    }
}

// ------------------------------------------------------------------ stream

/// Post-handshake restls framing over the (now opaque) transport.
struct RestlsStream {
    inner: BoxProxyStream,
    secret: [u8; 32],
    server_random: [u8; 32],
    script: Vec<(Line, Cmd)>,
    /// `restlsToServerCounter`.
    to_server: u64,
    /// `restlsToClientCounter`.
    to_client: u64,
    /// `restlsWritePending`: the script interrupted the writer.
    write_pending: bool,
    /// `restlsSendBuf`: plaintext parked behind an interrupt.
    send_buf: Vec<u8>,
    rbuf: BytesMut,
    out: BytesMut,
    wbuf: BytesMut,
    closed: bool,
}

impl RestlsStream {
    /// `Conn.actAccordingToScript`: returns
    /// `(payloadLen, dataLen, paddingLen, command)` for the record that
    /// will carry `data` starting at the current to-server counter.
    fn act_according_to_script(&self, data_len_in: usize) -> Result<(usize, usize, usize, Cmd)> {
        let mut padding_len = 0usize;
        let mut data_len = data_len_in;
        let mut command = Cmd::Noop;
        if (self.to_server as usize) < self.script.len() {
            let (line, cmd) = self.script[self.to_server as usize];
            data_len = line.len();
            command = cmd;
        }
        if data_len == 0 {
            padding_len = 19 + (rand::random::<u32>() % 100) as usize;
        }
        if data_len_in < data_len {
            padding_len = data_len - data_len_in;
            data_len = data_len_in;
        }
        let payload_len = (data_len + padding_len + AUTH_HEADER_LEN).min(MAX_PLAINTEXT);
        let data_len = payload_len
            .checked_sub(AUTH_HEADER_LEN + padding_len)
            .ok_or_else(|| Error::protocol("restls: script target length is too large"))?;
        Ok((payload_len, data_len, padding_len, command))
    }

    /// `writeRestlsApplicationRecord` + `write0x17AuthHeader` for one
    /// record. `data` is the plaintext to carry (may be empty for a random
    /// response, `fake_response`). Returns the wire record, how many bytes
    /// of `data` it consumed, and whether the writer must now wait for a
    /// peer record (`needInterrupt && !fakeResponse`).
    fn build_record(&self, data: &[u8], fake_response: bool) -> Result<(Vec<u8>, usize, bool)> {
        let (payload_len, data_len, padding_len, command) = self.act_according_to_script(data.len())?;
        if payload_len == 0 {
            return Ok((Vec::new(), 0, false));
        }
        let data = &data[..data_len];
        let mut padding = vec![0u8; padding_len];
        rand::rngs::OsRng.fill_bytes(&mut padding);

        let mut rec = Vec::with_capacity(RECORD_HEADER_LEN + payload_len);
        rec.extend_from_slice(&[REC_APP_DATA, 0x03, 0x03]);
        rec.extend_from_slice(&(payload_len as u16).to_be_bytes());
        let auth_off = rec.len();
        rec.extend_from_slice(&[0u8; AUTH_HEADER_LEN]);
        rec.extend_from_slice(data);
        rec.extend_from_slice(&padding);

        // mask = MAC(base ‖ first ≤ 32 bytes of data ‖ padding)
        let body = &rec[auth_off + AUTH_HEADER_LEN..];
        let sample = &body[..body.len().min(32)];
        let mask_digest = {
            let mut h = auth_header_hasher(&self.secret, &self.server_random, DIR_TO_SERVER, self.to_server);
            h.update(sample);
            *h.finalize().as_bytes()
        };
        let header = rec[..RECORD_HEADER_LEN].to_vec();
        let region = &mut rec[auth_off..];
        region[AUTH_MAC_LEN..AUTH_MAC_LEN + CMD_LEN]
            .copy_from_slice(&(data_len as u16).to_be_bytes());
        region[AUTH_MAC_LEN + CMD_LEN..AUTH_HEADER_LEN].copy_from_slice(&command.to_bytes());
        xor_with_mac(&mut region[AUTH_MAC_LEN..AUTH_HEADER_LEN], &mask_digest[..MASK_LEN]);
        // authMac = MAC(base ‖ record header ‖ region[8:]) — the masked
        // length and command, data and padding, in that order.
        let auth_digest = {
            let mut h = auth_header_hasher(&self.secret, &self.server_random, DIR_TO_SERVER, self.to_server);
            h.update(&header);
            h.update(&region[AUTH_MAC_LEN..]);
            *h.finalize().as_bytes()
        };
        region[..AUTH_MAC_LEN].copy_from_slice(&auth_digest[..AUTH_MAC_LEN]);
        let interrupt = command.need_interrupt() && !fake_response;
        Ok((rec, data_len, interrupt))
    }

    /// `extractRestlsAppData` for a server→client record: verify the
    /// authMac, unmask the length/command, return `(data, command)`.
    /// `counter` is this record's to-client index.
    fn extract_record(&self, record: &[u8], counter: u64) -> Result<(Vec<u8>, Cmd)> {
        if record[0] != REC_APP_DATA {
            return Err(Error::protocol("restls: record is not application data"));
        }
        if record.len() < RECORD_HEADER_LEN + AUTH_HEADER_LEN {
            return Err(Error::protocol("restls: record shorter than the auth header"));
        }
        let header = &record[..RECORD_HEADER_LEN];
        let region = &record[RECORD_HEADER_LEN..];
        let body = &region[AUTH_HEADER_LEN..];
        let sample = &body[..body.len().min(32)];
        let mask_digest = {
            let mut h = auth_header_hasher(&self.secret, &self.server_random, DIR_TO_CLIENT, counter);
            h.update(sample);
            *h.finalize().as_bytes()
        };
        let auth_digest = {
            let mut h = auth_header_hasher(&self.secret, &self.server_random, DIR_TO_CLIENT, counter);
            h.update(header);
            h.update(&region[AUTH_MAC_LEN..]);
            *h.finalize().as_bytes()
        };
        if region[..AUTH_MAC_LEN] != auth_digest[..AUTH_MAC_LEN] {
            return Err(Error::protocol("restls: bad record MAC"));
        }
        let mut lencmd = [0u8; MASK_LEN];
        lencmd.copy_from_slice(&region[AUTH_MAC_LEN..AUTH_HEADER_LEN]);
        xor_with_mac(&mut lencmd, &mask_digest[..MASK_LEN]);
        let data_len = usize::from(u16::from_be_bytes([lencmd[0], lencmd[1]]));
        let cmd = Cmd::parse([lencmd[2], lencmd[3]])?;
        if data_len > body.len() {
            return Err(Error::protocol("restls: data length beyond the record"));
        }
        Ok((body[..data_len].to_vec(), cmd))
    }

    /// The unblock path of `readRecordOrCCS`: a framed server record
    /// arrived while the writer was interrupted; flush the parked bytes
    /// (`c.Write([]byte{})`) into `wbuf`.
    fn flush_pending(&mut self) -> Result<()> {
        let mut data = std::mem::take(&mut self.send_buf);
        while !data.is_empty() {
            let (rec, consumed, interrupt) = self.build_record(&data, false)?;
            self.to_server += 1;
            if !rec.is_empty() {
                self.wbuf.extend_from_slice(&rec);
            }
            let consumed = consumed.max(1).min(data.len().max(1));
            data.drain(..consumed);
            if interrupt {
                self.write_pending = true;
                break;
            }
        }
        if !data.is_empty() {
            self.send_buf = data;
        }
        Ok(())
    }

    /// `handleRestlsCommand` for a received `ActResponse(n)`: emit `n`
    /// random (`restls-random-response`) records.
    fn queue_random_responses(&mut self, n: u8) -> Result<()> {
        for _ in 0..n {
            let (rec, _, _) = self.build_record(&[], true)?;
            self.to_server += 1;
            if !rec.is_empty() {
                self.wbuf.extend_from_slice(&rec);
            }
        }
        Ok(())
    }

    /// Push queued wire bytes out. The read path queues random responses
    /// and unblocked writes, exactly where upstream calls `c.Write`
    /// (`handleRestlsCommand` / the unblock flush), so `poll_read` must
    /// also drive the transport.
    fn drain_wbuf(this: &mut Self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !this.wbuf.is_empty() {
            match Pin::new(&mut this.inner).poll_write(cx, &this.wbuf) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "restls: transport accepted zero bytes",
                    )))
                }
                Poll::Ready(Ok(n)) => this.wbuf.advance(n),
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(()))
    }

    /// Try to consume one complete framed record from `rbuf`.
    /// `Ok(false)` = more bytes needed.
    fn parse_record(&mut self) -> Result<bool> {
        if self.rbuf.len() < RECORD_HEADER_LEN {
            return Ok(false);
        }
        let len = usize::from(u16::from_be_bytes([self.rbuf[3], self.rbuf[4]]));
        if RECORD_HEADER_LEN + len > MAX_RECORD_LEN {
            return Err(Error::protocol("restls: oversized record"));
        }
        if self.rbuf.len() < RECORD_HEADER_LEN + len {
            return Ok(false);
        }
        let record = self.rbuf.split_to(RECORD_HEADER_LEN + len).to_vec();
        if record[0] == REC_ALERT {
            // Upstream maps alerts to a close notification.
            self.closed = true;
            return Ok(true);
        }
        if record[0] != REC_APP_DATA {
            // A non-framed TLS record (e.g. a NewSessionTicket) — dropped,
            // counter advanced (see the fallback note in the module docs).
            self.to_client += 1;
            return Ok(true);
        }
        let counter = self.to_client;
        match self.extract_record(&record, counter) {
            Ok((data, cmd)) => {
                self.to_client += 1;
                self.out.extend_from_slice(&data);
                if self.write_pending {
                    self.write_pending = false;
                    self.flush_pending()?;
                }
                if let Cmd::Response(n) = cmd {
                    self.queue_random_responses(n)?;
                }
            }
            Err(_) => {
                self.to_client += 1;
            }
        }
        Ok(true)
    }
}

fn io_err(e: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

impl AsyncRead for RestlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if !this.out.is_empty() {
                let n = this.out.len().min(buf.remaining());
                buf.put_slice(&this.out[..n]);
                this.out.advance(n);
                return Poll::Ready(Ok(()));
            }
            if this.closed {
                return Poll::Ready(Ok(()));
            }
            match this.parse_record() {
                Ok(true) => {
                    ready!(Self::drain_wbuf(this, cx))?;
                    continue;
                }
                Ok(false) => {
                    let mut tmp = [0u8; 16 * 1024];
                    let mut rb = ReadBuf::new(&mut tmp);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                    if rb.filled().is_empty() {
                        this.closed = true;
                        return Poll::Ready(Ok(()));
                    }
                    this.rbuf.extend_from_slice(rb.filled());
                }
                Err(e) => return Poll::Ready(Err(io_err(e))),
            }
        }
    }
}

impl AsyncWrite for RestlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "restls: connection closed",
            )));
        }
        if this.write_pending {
            // `restlsWritePending`: park the plaintext until a peer record
            // unblocks the writer.
            this.send_buf.extend_from_slice(buf);
            return Poll::Ready(Ok(buf.len()));
        }
        let mut data = std::mem::take(&mut this.send_buf);
        data.extend_from_slice(buf);
        while !data.is_empty() {
            match this.build_record(&data, false) {
                Ok((rec, consumed, interrupt)) => {
                    this.to_server += 1;
                    if !rec.is_empty() {
                        this.wbuf.extend_from_slice(&rec);
                    }
                    let consumed = consumed.clamp(1, data.len());
                    data.drain(..consumed);
                    if interrupt {
                        this.write_pending = true;
                        break;
                    }
                }
                Err(e) => return Poll::Ready(Err(io_err(e))),
            }
        }
        this.send_buf = data;
        // Flush what the script allowed out to the transport.
        while !this.wbuf.is_empty() {
            let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.wbuf))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "restls: transport accepted zero bytes",
                )));
            }
            this.wbuf.advance(n);
        }
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while !this.wbuf.is_empty() {
            let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.wbuf))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "restls: transport accepted zero bytes",
                )));
            }
            this.wbuf.advance(n);
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        // No encrypted close_notify (see the deviations note): flush the
        // queued records and shut the transport down.
        while !this.wbuf.is_empty() {
            let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.wbuf))?;
            if n == 0 {
                break;
            }
            this.wbuf.advance(n);
        }
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// Perform the RestLS client handshake over `transport` (the raw connection
/// to the restls server — this function dials nothing) and return the
/// framed tunnel stream. The camouflage TLS session inside is complete and
/// discarded, as mihomo's client discards its ticket state on fresh dials.
pub async fn connect(cfg: &RestlsOut, transport: BoxProxyStream) -> Result<BoxProxyStream> {
    if cfg.password.is_empty() {
        return Err(Error::config("restls: password is required"));
    }
    if cfg.sni.is_empty() {
        return Err(Error::config("restls: sni is required"));
    }
    let version = cfg.version.trim().to_ascii_lowercase();
    if version != "tls13" {
        if version == "tls12" {
            return Err(Error::config(
                "restls: version-hint tls12 is not implemented (eager X25519/P-256/P-384 keys \
                 MAC-ed into the session id and reused in the TLS 1.2 key exchange — \
                 generateSessionIDFromPKnTicket + key_agreement.go; rustls' TLS 1.2 client \
                 cannot supply client-chosen ephemeral keys)",
            ));
        }
        return Err(Error::config(
            "restls: invalid version hint (want tls12 or tls13)",
        ));
    }
    let script_src = cfg
        .restls_script
        .as_deref()
        .filter(|s| !s.is_empty())
        .unwrap_or(DEFAULT_SCRIPT);
    let script = parse_record_script(script_src)?;
    let secret = restls_secret(&cfg.password);
    let config = restls_config(cfg)?;

    let (mut tls, flight) = restls_client_hello(&config, &cfg.sni, &secret)?;
    let mut transport = transport;
    let mut rbuf = BytesMut::with_capacity(16 * 1024);
    transport.write_all(&flight).await?;
    transport.flush().await?;

    debug!(target: "engine", sni = %cfg.sni, "restls: TLS 1.3 camouflage handshake starting");
    let mut srv_random: Option<[u8; 32]> = None;
    let mut xor_done = false;
    loop {
        if !tls.wants_write() && !tls.is_handshaking() {
            break;
        }
        while tls.wants_write() {
            let out = drain_tls(&mut tls)?;
            if out.is_empty() {
                break;
            }
            transport.write_all(&out).await?;
        }
        transport.flush().await?;
        if !tls.is_handshaking() {
            break;
        }
        let mut record = read_one_record(&mut transport, &mut rbuf).await?;
        if let Some(r) = server_random(&record) {
            srv_random = Some(r);
        }
        if record[0] == REC_APP_DATA && !xor_done {
            // The first encrypted server record is XOR-ed with
            // MAC(serverRandom): the server's restls authentication.
            let sr = srv_random
                .ok_or_else(|| Error::protocol("restls: encrypted record before ServerHello"))?;
            xor_with_mac(
                &mut record[RECORD_HEADER_LEN..],
                &server_random_mac(&secret, &sr),
            );
            xor_done = true;
        }
        let auth = !xor_done;
        let mut cursor = &record[..];
        tls.read_tls(&mut cursor)
            .map_err(|e| Error::network(format!("restls: tls read: {e}")))?;
        tls.process_new_packets().map_err(|e| {
            if auth {
                Error::crypto(format!(
                    "restls: peer failed the server authentication (XOR record did not decrypt): {e}"
                ))
            } else {
                Error::network(format!("restls: TLS handshake with {sni} failed: {e}", sni = cfg.sni))
            }
        })?;
    }
    // The client's Finished flight may still be queued.
    while tls.wants_write() {
        let out = drain_tls(&mut tls)?;
        if out.is_empty() {
            break;
        }
        transport.write_all(&out).await?;
    }
    transport.flush().await?;
    if !xor_done {
        return Err(Error::protocol(
            "restls: handshake completed without the server authentication record",
        ));
    }
    let server_random =
        srv_random.ok_or_else(|| Error::protocol("restls: no ServerHello seen"))?;
    debug!(target: "engine", sni = %cfg.sni, "restls: tunnel established");

    Ok(Box::new(RestlsStream {
        inner: transport,
        secret,
        server_random,
        script,
        to_server: 0,
        to_client: 0,
        write_pending: false,
        send_buf: Vec::new(),
        rbuf,
        out: BytesMut::with_capacity(16 * 1024),
        wbuf: BytesMut::new(),
        closed: false,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::time::Duration;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::crypto::ring as ring_provider;
    use tokio::io::DuplexStream;

    // ------------------------------------------------------------- script

    #[test]
    fn default_script_parses() {
        let lines = parse_record_script(DEFAULT_SCRIPT).unwrap();
        assert_eq!(lines.len(), 5, "{lines:?}");
        // 250?100<1 — `?` fixes the target at parse time in [250, 349].
        let (l0, c0) = lines[0];
        assert!((250..=349).contains(&l0.target), "{}", l0.target);
        assert_eq!(l0.range, 0);
        assert_eq!(c0, Cmd::Response(1));
        // 350~100<1 — a per-record uniform range.
        let (l1, c1) = lines[1];
        assert_eq!(l1.target, 350);
        assert_eq!(l1.range, 100);
        assert_eq!(c1, Cmd::Response(1));
        let (l2, c2) = lines[2];
        assert_eq!((l2.target, l2.range), (600, 100));
        assert_eq!(c2, Cmd::Noop);
        assert_eq!((lines[3].0.target, lines[3].0.range), (300, 200));
        assert_eq!((lines[4].0.target, lines[4].0.range), (300, 100));
        // Line lengths stay inside target..=target+range.
        for _ in 0..50 {
            let n = lines[1].0.len();
            assert!((350..=450).contains(&n), "{n}");
        }
    }

    #[test]
    fn script_errors_and_roundtrip() {
        assert!(parse_record_script("32768").is_err());
        assert!(parse_record_script("100<255").is_err());
        assert!(parse_record_script("100<2x").is_err());
        assert!(parse_record_script("40000~10").is_err());
        assert!(parse_record_script("10 ? 5, 20 ~ 3").is_ok());
        // `cmd` bytes roundtrip.
        assert_eq!(Cmd::Noop.to_bytes(), [0, 0]);
        assert_eq!(Cmd::Response(4).to_bytes(), [1, 4]);
        assert_eq!(Cmd::parse([1, 4]).unwrap(), Cmd::Response(4));
        assert_eq!(Cmd::parse([0, 9]).unwrap(), Cmd::Noop);
        assert!(Cmd::parse([2, 0]).is_err());
    }

    #[test]
    fn secret_is_blake3_derive_key_of_password() {
        let a = restls_secret("hunter2-secret");
        let b = restls_secret("hunter2-secret");
        assert_eq!(a, b);
        assert_ne!(a, restls_secret("other"));
        // Deterministic: BLAKE3 derive-key is a function of context+input.
        assert_eq!(a, blake3::derive_key("restls-traffic-key", b"hunter2-secret"));
    }

    /// Independent transcription of the server-side check on a framed
    /// record (`extractRestlsAppData`), recomputed from scratch. `dir` is
    /// the record's own direction label.
    fn upstream_extract(
        secret: &[u8; 32],
        server_random: &[u8; 32],
        dir: &[u8],
        counter: u64,
        record: &[u8],
    ) -> Result<(Vec<u8>, Cmd)> {
        let region = &record[RECORD_HEADER_LEN..];
        let mut auth = blake3::Hasher::new_keyed(secret);
        auth.update(server_random);
        auth.update(dir);
        auth.update(&counter.to_be_bytes());
        auth.update(&record[..RECORD_HEADER_LEN]);
        auth.update(&region[AUTH_MAC_LEN..]);
        if region[..AUTH_MAC_LEN] != auth.finalize().as_bytes()[..AUTH_MAC_LEN] {
            return Err(Error::protocol("mimic: authMac mismatch"));
        }
        let body = &region[AUTH_HEADER_LEN..];
        let sample = &body[..body.len().min(32)];
        let mut mask = blake3::Hasher::new_keyed(secret);
        mask.update(server_random);
        mask.update(dir);
        mask.update(&counter.to_be_bytes());
        mask.update(sample);
        let mask = mask.finalize();
        let mut lencmd = [0u8; MASK_LEN];
        lencmd.copy_from_slice(&region[AUTH_MAC_LEN..AUTH_HEADER_LEN]);
        for (b, m) in lencmd.iter_mut().zip(mask.as_bytes()[..MASK_LEN].iter()) {
            *b ^= *m;
        }
        let data_len = u16::from_be_bytes([lencmd[0], lencmd[1]]) as usize;
        let cmd = Cmd::parse([lencmd[2], lencmd[3]])?;
        Ok((body[..data_len].to_vec(), cmd))
    }

    #[test]
    fn framed_record_passes_independent_extraction() {
        let secret = restls_secret("shared-test-secret");
        let server_random = [7u8; 32];
        let stream = RestlsStream {
            inner: Box::new(tokio::io::duplex(16).0),
            secret,
            server_random,
            script: parse_record_script("50<1,40,0").unwrap(),
            to_server: 0,
            to_client: 0,
            write_pending: false,
            send_buf: Vec::new(),
            rbuf: BytesMut::new(),
            out: BytesMut::new(),
            wbuf: BytesMut::new(),
            closed: false,
        };
        // Record 0: script line 50<1 — dataLen = 11, padding 39, cmd = <1.
        let (rec, consumed, interrupt) = stream.build_record(b"hello world", false).unwrap();
        assert_eq!(consumed, 11);
        assert!(interrupt);
        assert_eq!(rec[0], REC_APP_DATA);
        let payload_len = u16::from_be_bytes([rec[3], rec[4]]) as usize;
        assert_eq!(payload_len, 11 + 39 + AUTH_HEADER_LEN);
        assert_eq!(rec.len(), RECORD_HEADER_LEN + payload_len);

        // The server-side transcription accepts it.
        let (data, cmd) = upstream_extract(&secret, &server_random, DIR_TO_SERVER, 0, &rec).unwrap();
        assert_eq!(data, b"hello world".to_vec());
        assert_eq!(cmd, Cmd::Response(1));

        // A wrong counter fails the authMac.
        assert!(upstream_extract(&secret, &server_random, DIR_TO_SERVER, 1, &rec).is_err());
        // A wrong secret fails.
        assert!(upstream_extract(&restls_secret("other"), &server_random, DIR_TO_SERVER, 0, &rec).is_err());
        // Flipping one payload bit breaks the authMac (padding is covered).
        let mut tampered = rec.clone();
        let last = tampered.len() - 1;
        tampered[last] ^= 1;
        assert!(upstream_extract(&secret, &server_random, DIR_TO_SERVER, 0, &tampered).is_err());
    }

    #[test]
    fn zero_length_script_line_pads() {
        let secret = restls_secret("pw");
        let stream = RestlsStream {
            inner: Box::new(tokio::io::duplex(16).0),
            secret,
            server_random: [1u8; 32],
            script: parse_record_script("0,5").unwrap(),
            to_server: 0,
            to_client: 0,
            write_pending: false,
            send_buf: Vec::new(),
            rbuf: BytesMut::new(),
            out: BytesMut::new(),
            wbuf: BytesMut::new(),
            closed: false,
        };
        // Line "0": dataLen 0 → padding 19 + rand(100), cmd noop.
        let (rec, consumed, interrupt) = stream.build_record(b"", true).unwrap();
        assert_eq!(consumed, 0);
        assert!(!interrupt);
        let payload_len = u16::from_be_bytes([rec[3], rec[4]]) as usize;
        assert!(((19 + AUTH_HEADER_LEN)..=(118 + AUTH_HEADER_LEN)).contains(&payload_len));
        let (data, cmd) = upstream_extract(&secret, &[1u8; 32], DIR_TO_SERVER, 0, &rec).unwrap();
        assert!(data.is_empty());
        assert_eq!(cmd, Cmd::Noop);
    }

    // ------------------------------------------------------ loopback mimic

    fn test_server_config() -> Arc<rustls::ServerConfig> {
        let certified = rcgen::generate_simple_self_signed(vec!["restls.test".to_string()])
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

    /// One server→client framed record for the mimic (same construction as
    /// the client's, with the direction flipped).
    fn mimic_record(
        secret: &[u8; 32],
        server_random: &[u8; 32],
        script: &[(Line, Cmd)],
        to_client: u64,
        data: &[u8],
        fake_response: bool,
    ) -> Vec<u8> {
        let mut padding_len = 0usize;
        let mut data_len = data.len();
        let mut command = Cmd::Noop;
        if (to_client as usize) < script.len() {
            let (line, cmd) = script[to_client as usize];
            data_len = line.len();
            command = cmd;
        }
        if data_len == 0 {
            padding_len = 19 + (rand::random::<u32>() % 100) as usize;
        }
        if data.len() < data_len {
            padding_len = data_len - data.len();
            data_len = data.len();
        }
        let payload_len = (data_len + padding_len + AUTH_HEADER_LEN).min(MAX_PLAINTEXT);
        let data_len = payload_len - AUTH_HEADER_LEN - padding_len;
        let data = &data[..data_len];
        let mut padding = vec![0u8; padding_len];
        rand::rngs::OsRng.fill_bytes(&mut padding);

        let mut rec = Vec::with_capacity(RECORD_HEADER_LEN + payload_len);
        rec.extend_from_slice(&[REC_APP_DATA, 0x03, 0x03]);
        rec.extend_from_slice(&(payload_len as u16).to_be_bytes());
        let auth_off = rec.len();
        rec.extend_from_slice(&[0u8; AUTH_HEADER_LEN]);
        rec.extend_from_slice(data);
        rec.extend_from_slice(&padding);
        let body = rec[auth_off + AUTH_HEADER_LEN..].to_vec();
        let sample = &body[..body.len().min(32)];
        let mut mask = blake3::Hasher::new_keyed(secret);
        mask.update(server_random);
        mask.update(b"server-to-client");
        mask.update(&to_client.to_be_bytes());
        mask.update(sample);
        let mask = mask.finalize();
        let region_off = auth_off;
        let header = rec[..RECORD_HEADER_LEN].to_vec();
        let mut lencmd = [0u8; MASK_LEN];
        lencmd[..CMD_LEN].copy_from_slice(&(data_len as u16).to_be_bytes());
        lencmd[CMD_LEN..].copy_from_slice(&command.to_bytes());
        for (b, m) in lencmd.iter_mut().zip(mask.as_bytes()[..MASK_LEN].iter()) {
            *b ^= *m;
        }
        rec[region_off + AUTH_MAC_LEN..region_off + AUTH_HEADER_LEN].copy_from_slice(&lencmd);
        let mut auth = blake3::Hasher::new_keyed(secret);
        auth.update(server_random);
        auth.update(b"server-to-client");
        auth.update(&to_client.to_be_bytes());
        auth.update(&header);
        auth.update(&rec[region_off + AUTH_MAC_LEN..]);
        rec[region_off..region_off + AUTH_MAC_LEN]
            .copy_from_slice(&auth.finalize().as_bytes()[..AUTH_MAC_LEN]);
        let _ = fake_response;
        rec
    }

    /// The restls server mimic: verifies the session-id MAC over the X25519
    /// key share (`generateSessionIDForTLS13`), terminates a genuine TLS
    /// 1.3 handshake behind the XOR-ed first encrypted record, then echoes
    /// framed data and honours `ActResponse` commands.
    async fn restls_server_mimic(
        mut io: DuplexStream,
        secret: [u8; 32],
        server_config: Arc<rustls::ServerConfig>,
    ) -> std::result::Result<(), String> {
        let (mut rd, mut wr) = tokio::io::split(&mut io);
        // 1. The ClientHello must carry the authenticated session id.
        let mut hello = Vec::new();
        let mut header = [0u8; RECORD_HEADER_LEN];
        rd.read_exact(&mut header).await.map_err(|e| e.to_string())?;
        let len = u16::from_be_bytes([header[3], header[4]]) as usize;
        hello.extend_from_slice(&header);
        hello.resize(RECORD_HEADER_LEN + len, 0);
        rd.read_exact(&mut hello[RECORD_HEADER_LEN..])
            .await
            .map_err(|e| e.to_string())?;
        let share = client_hello_x25519_share(&hello).ok_or("no X25519 key share")?;
        let mut mac_input = GROUP_X25519.to_be_bytes().to_vec();
        mac_input.extend_from_slice(&share);
        let digest = restls_hmac(&secret, &[&mac_input]);
        if hello[SESSION_ID_INDEX..SESSION_ID_INDEX + SESSION_ID_MAC_LEN]
            != digest[..SESSION_ID_MAC_LEN]
        {
            return Err("session id MAC mismatch (client not authenticated)".into());
        }

        // 2. Real TLS handshake; the first encrypted flight record is
        //    XOR-ed with MAC(serverRandom).
        let mut tls = rustls::ServerConnection::new(server_config).map_err(|e| e.to_string())?;
        let mut input = hello.as_slice();
        tls.read_tls(&mut input).map_err(|e| e.to_string())?;
        tls.process_new_packets().map_err(|e| e.to_string())?;
        let mut xor_done = false;
        let mut srv_random: Option<[u8; 32]> = None;
        // Raw 0x17 records written after the handshake (the rustls
        // NewSessionTicket) — the client's framed reader will drop them and
        // still advance its counter, so the server must count them into its
        // send counter (restls_server.go:539-540 does the same for extra
        // target records).
        let mut extra_raw: u64 = 0;
        while tls.wants_write() || tls.is_handshaking() {
            let mut flight = Vec::new();
            while tls.wants_write() {
                if tls.write_tls(&mut flight).map_err(|e| e.to_string())? == 0 {
                    break;
                }
            }
            if !tls.is_handshaking() && xor_done {
                let mut off = 0usize;
                while off + RECORD_HEADER_LEN <= flight.len() {
                    let rlen = u16::from_be_bytes([flight[off + 3], flight[off + 4]]) as usize;
                    if flight[off] == REC_APP_DATA {
                        extra_raw += 1;
                    }
                    off += RECORD_HEADER_LEN + rlen;
                }
            }
            if !xor_done {
                // Extract the server random from the first ServerHello, and
                // XOR the first 0x17 record of the flight with MAC(random).
                let mut off = 0usize;
                while off + RECORD_HEADER_LEN <= flight.len() {
                    let rlen = u16::from_be_bytes([flight[off + 3], flight[off + 4]]) as usize;
                    let record = &flight[off..off + RECORD_HEADER_LEN + rlen];
                    if let Some(r) = server_random(record) {
                        srv_random = Some(r);
                        break;
                    }
                    off += RECORD_HEADER_LEN + rlen;
                }
                let sr = srv_random.ok_or("flight without ServerHello")?;
                let mac16 = server_random_mac(&secret, &sr);
                let mut out = Vec::with_capacity(flight.len());
                let mut off = 0usize;
                let mut xored = false;
                while off < flight.len() {
                    let rlen = u16::from_be_bytes([flight[off + 3], flight[off + 4]]) as usize;
                    let end = off + RECORD_HEADER_LEN + rlen;
                    let mut record = flight[off..end].to_vec();
                    if !xored && record[0] == REC_APP_DATA {
                        xor_with_mac(&mut record[RECORD_HEADER_LEN..], &mac16);
                        xored = true;
                    }
                    out.extend_from_slice(&record);
                    off = end;
                }
                xor_done = xored;
                flight = out;
            }
            wr.write_all(&flight).await.map_err(|e| e.to_string())?;
            wr.flush().await.map_err(|e| e.to_string())?;
            if !tls.is_handshaking() {
                break;
            }
            let mut record = Vec::new();
            let mut h2 = [0u8; RECORD_HEADER_LEN];
            rd.read_exact(&mut h2).await.map_err(|e| e.to_string())?;
            let l2 = u16::from_be_bytes([h2[3], h2[4]]) as usize;
            record.extend_from_slice(&h2);
            record.resize(RECORD_HEADER_LEN + l2, 0);
            rd.read_exact(&mut record[RECORD_HEADER_LEN..])
                .await
                .map_err(|e| e.to_string())?;
            let mut input = record.as_slice();
            tls.read_tls(&mut input).map_err(|e| e.to_string())?;
            tls.process_new_packets().map_err(|e| e.to_string())?;
        }

        // 3. Framed echo loop.
        let server_random = srv_random.ok_or("no server random")?;
        let script = parse_record_script(DEFAULT_SCRIPT).map_err(|e| e.to_string())?;
        // Two independent per-direction counters, as upstream keeps them:
        // the index of the next client record to verify, and the index of
        // the next server record to send.
        let mut from_client: u64 = 0;
        let mut to_client: u64 = extra_raw;
        let mut rbuf = BytesMut::new();
        loop {
            let record = match read_one_record(&mut rd, &mut rbuf).await {
                Ok(r) => r,
                Err(_) => return Ok(()), // client closed the tunnel
            };
            if record[0] != REC_APP_DATA {
                continue;
            }
            // Server-side extraction mirrors the client's with the
            // direction flipped.
            let region = &record[RECORD_HEADER_LEN..];
            let body = &region[AUTH_HEADER_LEN..];
            let sample = &body[..body.len().min(32)];
            let mut auth = blake3::Hasher::new_keyed(&secret);
            auth.update(&server_random);
            auth.update(b"client-to-server");
            auth.update(&from_client.to_be_bytes());
            auth.update(&record[..RECORD_HEADER_LEN]);
            auth.update(&region[AUTH_MAC_LEN..]);
            if region[..AUTH_MAC_LEN] != auth.finalize().as_bytes()[..AUTH_MAC_LEN] {
                return Err("framed record authMac mismatch".into());
            }
            let mut mask = blake3::Hasher::new_keyed(&secret);
            mask.update(&server_random);
            mask.update(b"client-to-server");
            mask.update(&from_client.to_be_bytes());
            mask.update(sample);
            let mask = mask.finalize();
            let mut lencmd = [0u8; MASK_LEN];
            lencmd.copy_from_slice(&region[AUTH_MAC_LEN..AUTH_HEADER_LEN]);
            for (b, m) in lencmd.iter_mut().zip(mask.as_bytes()[..MASK_LEN].iter()) {
                *b ^= *m;
            }
            let data_len = u16::from_be_bytes([lencmd[0], lencmd[1]]) as usize;
            let cmd = Cmd::parse([lencmd[2], lencmd[3]]).map_err(|e| e.to_string())?;
            from_client += 1;
            let data = &body[..data_len];
            if let Cmd::Response(n) = cmd {
                for _ in 0..n {
                    let rec = mimic_record(&secret, &server_random, &script, to_client, &[], true);
                    to_client += 1;
                    wr.write_all(&rec).await.map_err(|e| e.to_string())?;
                }
            }
            if !data.is_empty() {
                // Echo the whole chunk: like writeRestlsApplicationRecord,
                // a script line shorter than the chunk spans several
                // records.
                let mut rest = data;
                while !rest.is_empty() {
                    let rec = mimic_record(&secret, &server_random, &script, to_client, rest, false);
                    to_client += 1;
                    // How much of `rest` this record carried.
                    let carried = {
                        let region = &rec[RECORD_HEADER_LEN..];
                        let body = &region[AUTH_HEADER_LEN..];
                        let sample = &body[..body.len().min(32)];
                        let mut mask = blake3::Hasher::new_keyed(&secret);
                        mask.update(&server_random);
                        mask.update(b"server-to-client");
                        mask.update(&(to_client - 1).to_be_bytes());
                        mask.update(sample);
                        let mask = mask.finalize();
                        let mut lencmd = [0u8; MASK_LEN];
                        lencmd.copy_from_slice(&region[AUTH_MAC_LEN..AUTH_HEADER_LEN]);
                        for (b, m) in lencmd.iter_mut().zip(mask.as_bytes()[..MASK_LEN].iter()) {
                            *b ^= *m;
                        }
                        u16::from_be_bytes([lencmd[0], lencmd[1]]) as usize
                    };
                    rest = &rest[carried.min(rest.len())..];
                    wr.write_all(&rec).await.map_err(|e| e.to_string())?;
                }
            }
            wr.flush().await.map_err(|e| e.to_string())?;
        }
    }

    fn test_cfg(password: &str) -> RestlsOut {
        RestlsOut {
            password: password.into(),
            sni: "restls.test".into(),
            version: "tls13".into(),
            restls_script: None,
            skip_cert_verify: true,
            udp: true,
        }
    }

    async fn connect_through_mimic(
        cfg: &RestlsOut,
    ) -> Result<BoxProxyStream> {
        let (client, server) = tokio::io::duplex(256 * 1024);
        let secret = restls_secret(&cfg.password);
        let server_config = test_server_config();
        tokio::spawn(async move {
            if let Err(e) = restls_server_mimic(server, secret, server_config).await {
                panic!("restls mimic failed: {e}");
            }
        });
        tokio::time::timeout(
            Duration::from_secs(20),
            connect(cfg, Box::new(client) as BoxProxyStream),
        )
        .await
        .expect("restls connect timed out")
    }

    #[tokio::test]
    async fn restls_handshake_and_echo_roundtrip() {
        // Generated per run; no credential literal committed.
        let password = format!("pw-{:016x}", rand::random::<u64>());
        let cfg = test_cfg(&password);
        let mut stream = connect_through_mimic(&cfg).await.unwrap();

        stream.write_all(b"ping through restls").await.unwrap();
        let mut buf = [0u8; 19];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"ping through restls");

        // Larger payload spanning several script records (> line sizes).
        let payload: Vec<u8> = (0..4096u32).map(|i| (i % 251) as u8).collect();
        let (mut rd, mut wr) = tokio::io::split(stream);
        let expected = payload.clone();
        let echo = tokio::spawn(async move {
            let mut got = vec![0u8; expected.len()];
            rd.read_exact(&mut got).await.unwrap();
            got
        });
        wr.write_all(&payload).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(20), echo)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn wrong_password_fails_authentication() {
        let cfg = test_cfg(&format!("real-{:016x}", rand::random::<u64>()));
        let mut bad = cfg.clone();
        bad.password = format!("wrong-{:016x}", rand::random::<u64>());
        // The mimic rejects the session id; its task ends and the duplex
        // closes. The client must fail, never connect.
        let (client, server) = tokio::io::duplex(64 * 1024);
        let secret = restls_secret(&cfg.password);
        let server_config = test_server_config();
        let mimic = tokio::spawn(async move {
            // Auth failure is expected: return quietly.
            let _ = restls_server_mimic(server, secret, server_config).await;
        });
        let err = match connect(&bad, Box::new(client) as BoxProxyStream).await {
            Ok(_) => panic!("a wrong password must not authenticate"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("session id")
                || err.to_string().contains("authentication")
                || err.to_string().contains("closed")
                || err.to_string().contains("end of file")
                || err.to_string().contains("EOF mid-record"),
            "{err}"
        );
        mimic.abort();
    }

    #[tokio::test]
    async fn tls12_version_hint_reports_deferral() {
        let mut cfg = test_cfg("pw");
        cfg.version = "tls12".into();
        let (client, _server) = tokio::io::duplex(64);
        let err = match connect(&cfg, Box::new(client) as BoxProxyStream).await {
            Ok(_) => panic!("tls12 must report its deferral"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("tls12"), "{err}");
        let mut cfg = test_cfg("pw");
        cfg.version = "tls11".into();
        let (client, _server) = tokio::io::duplex(64);
        assert!(connect(&cfg, Box::new(client) as BoxProxyStream).await.is_err());
    }

    #[tokio::test]
    async fn config_requires_password_and_sni() {
        let mut cfg = test_cfg("");
        let (client, _server) = tokio::io::duplex(64);
        let err = match connect(&cfg, Box::new(client) as BoxProxyStream).await {
            Ok(_) => panic!("an empty password must be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("password"), "{err}");
        cfg.password = "pw".into();
        cfg.sni = String::new();
        let (client, _server) = tokio::io::duplex(64);
        let err = match connect(&cfg, Box::new(client) as BoxProxyStream).await {
            Ok(_) => panic!("an empty SNI must be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("sni"), "{err}");
    }
}
