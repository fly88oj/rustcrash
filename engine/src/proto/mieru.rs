//! Mieru outbound over the **TCP (stream) transport**: one XChaCha20-Poly1305
//! stateful-encrypted underlay connection carrying one session, with a
//! SOCKS5-style connect request tunnelled through the session.
//!
//! Ported from the mieru Go library (`github.com/enfein/mieru/v3`, the
//! protocol mihomo's `adapter/outbound/mieru.go` links) — every wire decision
//! below cites the upstream file:
//!
//! 1. **Keys** (pkg/cipher/keygen.go, cache.go, api.go): the client password
//!    is `SHA256(password ‖ 0x00 ‖ username)`
//!    (`cipher.HashPassword`), the AEAD key is
//!    `PBKDF2-HMAC-SHA256(hashedPassword, salt, iter = 64, 32 bytes)` and the
//!    salt is `SHA256(be64(seconds))` where the seconds are the Unix time
//!    rounded to the nearest multiple of the 2-minute `KeyRefreshInterval`.
//!    The stream client uses the *middle* of the three time-window keys
//!    (`BlockCipherFromPassword` → `cipherList[1]`); the server tries all
//!    three (`serverUsers.Discover`). The AEAD is **XChaCha20-Poly1305**
//!    (24-byte nonce, 16-byte tag — `DefaultNonceSize`/`DefaultOverhead`),
//!    the only supported type.
//! 2. **Stateful implicit-nonce mode** (pkg/cipher/cipher.go): the first
//!    `Encrypt` of a direction generates a random 24-byte nonce, stamps a
//!    *user hint* into its tail — `nonce[20..24] =
//!    SHA256(username ‖ nonce[..16])[..4]` (`addUserHintToNonce`) — and sends
//!    the nonce as a prefix; every later message reuses the nonce
//!    incremented as a 24-byte little-endian counter (`increaseNonce`) with
//!    no prefix. `Decrypt` mirrors this (the first ciphertext carries the
//!    peer's nonce). Each segment does two AEAD operations (metadata,
//!    payload), so the counter advances identically on both ends
//!    (`StreamUnderlay.writeOneSegment` / `readOneSegment`).
//! 3. **Segment framing** (pkg/protocol/underlay_stream.go, metadata.go,
//!    segment.go): every segment starts with a 32-byte plaintext metadata
//!    block (`MetadataLength`), encrypted with the AEAD. A *session*
//!    segment (`sessionStruct`: protocol 2 = open request, 3 = open
//!    response, 4/5 = close request/response) is
//!    `[nonce?] [enc(meta)] [enc(payload ≤ 1024)] [suffix padding]`; a
//!    *data* segment (`dataAckStruct`: protocol 6 = client data, 7 = server
//!    data) is `[nonce?] [enc(meta)] [prefix padding] [enc(payload)]
//!    [suffix padding]`. Metadata layout (big endian): `0` protocol,
//!    `1` reserved, `2..6` timestamp (unix minutes), `6..10` session id,
//!    `10..14` sequence, then session: status `14`, payload len `15..17`,
//!    suffix len `17`; data: un-ack seq `14..18`, window `18..20`,
//!    fragment `20`, prefix len `21`, payload len `22..24`, suffix len `24`.
//!    Padding content is random and discarded by the receiver; only its
//!    length is wire-visible.
//! 4. **Session flow** (pkg/protocol/session.go, underlay_stream.go,
//!    apis/client/client.go, apis/internal/handshake.go): the client creates
//!    a random non-zero session id (`NewSession(mrand.Uint32(), …)`), and
//!    its first `Write` piggybacks up to `MaxSessionOpenPayload = 1024`
//!    bytes on the open request (seq 0); data segments then carry seq 1,
//!    2, … (the stream transport never fragments: `maxFragmentSize` =
//!    `maxPDU` = 32 KiB, and `Write` splits at `maxPDU`). Over the
//!    established session mihomo's adapter performs `PostDialHandshake`: a
//!    SOCKS5 request `[0x05, cmd = 0x01, 0x00, atyp, addr, port_be16]`
//!    (`model.Request.WriteToSocks5`) and the server's reply, whose
//!    trailing address is parsed (`model.Response.ReadFromSocks5`). On the
//!    stream transport no ACK segments are ever sent — `runOutputOnceStream`
//!    has no ACK path and `inputAck` ignores them — so this port sends none
//!    either.
//!
//! ## Scope (what mihomo's adapter exercises, and what is deferred)
//!
//! mihomo delegates the whole client to the mieru library; this port covers
//! the **TCP and UDP transports, port ranges, and client-side
//! multiplexing** — see [`MieruMux`] for the multiplexor (`pkg/protocol/
//! mux.go`) and [`parse_port_range`] for `port-range` ("begin-end", mihomo
//! `adapter/outbound/mieru.go`). The single-session [`connect`] keeps the
//! wave-8 shape: a fresh underlay plus one session per dial
//! (`Mux.DialContext` with `multiplexFactor = 0`). Deferred, with the
//! upstream file that owns them:
//!
//! * Handshake-mode `no-wait` (`apis/internal/early_conn.go`) and
//!   **traffic patterns** — nonce rewriting, TCP fragmentation,
//!   low-entropy payload encoding (`trafficpattern`, `low_entropy.go`).
//! * The underlay **scheduler**'s pending-session gate and idle timer
//!   (`IncPending`/`TryDisableIdle`, mux.go:425-436, 784-806): an
//!   underlay's reusability here is `reader alive && !disabled`, with
//!   zero-session underlays closed at dial time (cleanUnderlay's effect)
//!   and the 512 MiB << factor traffic-volume disable kept.
//! * Server-side JLS-style user quotas, `ExportSessionInfoList`, metrics.
//!
//! ## UDP (packet) transport
//!
//! Ported from `underlay_packet.go`, `session.go` (packet paths),
//! `congestion/{rtt,cubic}.go` and `cipher.go` (stateless mode):
//!
//! * **Stateless cipher mode** (`cipher.go` with
//!   `enableImplicitNonce=false`, chosen by `mux.go newUnderlay` via
//!   `BlockCipherFromPassword(password, stateless=true)`): every datagram
//!   carries a fresh random 24-byte nonce (user hint stamped,
//!   `addUserHintToNonce`) as a prefix of the sealed metadata, and the
//!   sealed payload reuses **the same nonce**
//!   (`writeOneSegment`: `Encrypt(meta)` then
//!   `EncryptWithNonce(dataToSend[offset:], nonce, seg.payload)`).
//! * **Datagram framing** (`writeOneSegment` / `parseSessionSegment` /
//!   `parseDataAckSegment`): session segment `[nonce‖enc(meta)]
//!   [enc_n(nonce, payload)] [suffix padding]`, data/ACK segment
//!   `[nonce‖enc(meta)] [prefix padding] [enc_n(nonce, payload)]
//!   [suffix padding]`; the receiver checks the exact tail length. Padding
//!   length bounds follow `maxPaddingSize` (packet: MTU − payload − 88,
//!   capped at 255; MTU = `common.DefaultMTU` 1400, which is what mihomo's
//!   default profile uses); the ASCII/entropy padding *strategy* of
//!   `buildRecommendedPaddingOpts` is approximated (only the length is
//!   wire-visible).
//! * **Session reliability** (`runOutputOncePacket`, `inputData`,
//!   `inputAck`): sequence-numbered segments, retransmission after
//!   `RTO×1.5^txCount` (RTO from ported RTTStats: initial 2 s, then
//!   smoothed RTT + max(4·mean-dev, 10 ms) + 1 ms × 1.5) capped at 10 s
//!   and 20 transmissions, early retransmission after 3 duplicate ACKs,
//!   delayed ACKs (1 ms), 5 s heartbeats (+≤1 s jitter, suppressed until
//!   the open response lands), in-order delivery through a reorder map,
//!   receive window = 4096 − backlog, send window =
//!   min(CUBIC cwnd, remote window) − unacked, with ported CUBIC
//!   (slow start, ×0.7 on loss, reset on timeout).
//! * **Simplifications** (single session per underlay — the same scope as
//!   the TCP port): no session-map demultiplexing (a datagram for a
//!   foreign session id is dropped), and the receive "queue" is the
//!   bounded pipe to the application (delivery backpressure replaces
//!   `waitForRecvQueueSpace`). A background task per session owns the
//!   socket; the application sees a plain byte stream, so the SOCKS5
//!   handshake and [`MieruUdp`] framing run identically over both
//!   transports.
//!
//! ## UDP datagrams (mihomo `ListenPacketContext`)
//!
//! mihomo relays UDP through a **session dialed to the UDP target** with
//! SOCKS5 command `UDP ASSOCIATE` (0x03, `apis/internal/handshake.go`
//! `PostDialHandshake`), then frames each datagram with
//! `UDPAssociateWrapper(PacketOverStreamTunnel(conn))`
//! (adapter/outbound/mieru.go:92-104): on the session stream every
//! datagram is `0x00 0x00 0x00 ‖ socksaddr(target) ‖ payload` wrapped as
//! `0x00 ‖ be16 len ‖ … ‖ 0xff` (`packet_over_stream.go`,
//! `udp_associate_wrapper.go`). [`connect_udp`] exposes exactly that as
//! `send_to`/`recv_from` (either underlay transport).
//!
//! The wire this module produces is pinned by an in-test mimic of the mieru
//! stream server, which re-implements server-side discovery/decrypt
//! (`StreamUnderlay.readOneSegment` +
//! `serverInitRecvBlockCipherAndDecryptMetadata`) straight from upstream.

use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use bytes::{Buf, BytesMut};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf};
use tokio::net::UdpSocket;
use tokio::time::{sleep_until, Instant};
use tracing::debug;

use crate::addr::{decode_socks_addr, encode_socks_addr, NetAddr};
use crate::error::{Error, Result};
use crate::stream::BoxProxyStream;

/// `pkg/protocol/metadata.go`: plaintext metadata block size.
const METADATA_LENGTH: usize = 32;
/// `metadata.go`: payload that may piggyback on open session request/response.
const MAX_SESSION_OPEN_PAYLOAD: usize = 1024;
/// `pkg/protocol/segment.go maxPDU`: largest single `Write` chunk.
const MAX_PDU: usize = 32 * 1024;
/// `pkg/cipher/api.go DefaultNonceSize` (XChaCha20).
const NONCE_SIZE: usize = 24;
/// `api.go DefaultOverhead` (Poly1305 tag).
const TAG_SIZE: usize = 16;
/// `api.go DefaultKeyLen`.
const KEY_LEN: usize = 32;
/// `pkg/cipher/keygen.go KeyIter`.
const KEY_ITER: u32 = 64;
/// `keygen.go KeyRefreshInterval` = 2 minutes.
const KEY_REFRESH_SECS: i64 = 120;
/// `api.go NoncePrefixLenForUserHint`.
const HINT_PREFIX_LEN: usize = 16;
/// `api.go NonceSuffixLenForUserHint`.
const HINT_SUFFIX_LEN: usize = 4;
/// `session.go segmentTreeCapacity` — the advertised receive window is
/// `max(0, capacity - recvBuf - recvQueue)`.
const SEGMENT_TREE_CAPACITY: usize = 4096;

// protocolType values (pkg/protocol/metadata.go:32-41).
const OPEN_SESSION_REQUEST: u8 = 2;
const OPEN_SESSION_RESPONSE: u8 = 3;
const CLOSE_SESSION_REQUEST: u8 = 4;
const CLOSE_SESSION_RESPONSE: u8 = 5;
const DATA_CLIENT_TO_SERVER: u8 = 6;
const DATA_SERVER_TO_CLIENT: u8 = 7;
const ACK_CLIENT_TO_SERVER: u8 = 8;
const ACK_SERVER_TO_CLIENT: u8 = 9;

/// SOCKS5 constants (apis/constant/socks5.go).
const SOCKS5_VERSION: u8 = 5;
const SOCKS5_CONNECT_CMD: u8 = 1;
/// `Socks5UDPAssociateCmd` — the command `PostDialHandshake` picks for
/// `udp` destinations (apis/internal/handshake.go:37-40).
const SOCKS5_UDP_ASSOCIATE_CMD: u8 = 3;

// Packet transport constants (underlay_packet.go:37-40, session.go:43-95,
// segment.go:39, pkg/common/mtu.go:19).
/// `packetOverhead` = nonce + metadata + two tags.
const PACKET_OVERHEAD: usize = NONCE_SIZE + METADATA_LENGTH + TAG_SIZE * 2;
/// `packetNonHeaderPosition` — minimum datagram size worth decrypting.
const PACKET_NON_HEADER_POSITION: usize = NONCE_SIZE + METADATA_LENGTH + TAG_SIZE;
/// `common.DefaultMTU` — mihomo's default profile sets no MTU.
const DEFAULT_MTU: usize = 1400;
/// `maxFragmentSizeInternal` on the packet transport: MTU − overhead.
const MAX_FRAGMENT: usize = DEFAULT_MTU - PACKET_OVERHEAD;
/// `minWindowSize` (session.go:47).
const MIN_WINDOW: u32 = 16;
/// `sessionHeartbeatInterval` (session.go:55).
const SESSION_HEARTBEAT: Duration = Duration::from_secs(5);
/// `sessionHeartbeatJitterMs` (session.go:56).
const SESSION_HEARTBEAT_JITTER: Duration = Duration::from_millis(1000);
/// `packetAckDelay` (session.go:68-72).
const PACKET_ACK_DELAY: Duration = Duration::from_millis(1);
/// `retransmissionCheckDelay` (session.go:74-77).
const RETRANSMISSION_CHECK_DELAY: Duration = Duration::from_millis(10);
/// `earlyRetransmission` (session.go:79).
const EARLY_RETRANSMISSION: u32 = 3;
/// `earlyRetransmissionLimit` (session.go:81).
const EARLY_RETRANSMISSION_LIMIT: u32 = 1;
/// `txTimeoutBackOff` (session.go:83).
const TX_TIMEOUT_BACKOFF: f64 = 1.5;
/// `maxBackOffDuration` (session.go:85).
const MAX_BACKOFF: Duration = Duration::from_secs(10);
/// `txCountLimit` (segment.go:39).
const TX_COUNT_LIMIT: u32 = 20;
/// `idleSessionTimeout` (underlay_packet.go:40).
const IDLE_SESSION_TIMEOUT: Duration = Duration::from_secs(60);

/// Underlay transport of the mieru profile (mihomo `transport` option).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MieruTransport {
    Tcp,
    Udp,
}

impl MieruTransport {
    /// Parse mihomo's `transport` field exactly as `validateMieruOption`
    /// does ("TCP" / "UDP"; anything else is invalid).
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "TCP" => Ok(MieruTransport::Tcp),
            "UDP" => Ok(MieruTransport::Udp),
            other => Err(Error::config(format!(
                "mieru: transport must be TCP or UDP, got {other:?}"
            ))),
        }
    }
}

/// Outbound mieru endpoint — the subset of mihomo's `MieruOption` the TCP
/// client exercises: server, port (or `port-range`), username, password,
/// transport.
#[derive(Debug, Clone)]
pub struct MieruOut {
    pub server: String,
    pub port: u16,
    /// mihomo `port-range` ("begin-end", `MieruOption.PortRange`,
    /// adapter/outbound/mieru.go:35): when set, every underlay dial picks a
    /// random port from the range (`mux.go newUnderlay` →
    /// `mrand.Intn(len(m.endpoints))` over `FlatPortBindings`' expansion,
    /// appctlcommon/port_binding.go:37-119). Mutually exclusive with a
    /// nonzero `port` ([`validate_ports`]).
    pub port_range: Option<(u16, u16)>,
    pub username: String,
    pub password: String,
    pub transport: MieruTransport,
    /// mihomo `multiplexing` (adapter/outbound/mieru.go:40): off | low
    /// (mieru's default) | middle | high — the level the outbound's mux
    /// pool runs at.
    pub multiplexing: Multiplexing,
}

impl MieruOut {
    /// The endpoint port list a dialer may use — `FlatPortBindings`
    /// (pkg/appctl/appctlcommon/port_binding.go:37-119): a range expands
    /// to one binding per port, a single port to itself.
    pub fn endpoint_ports(&self) -> Vec<u16> {
        endpoint_ports(self.port, self.port_range)
    }
}

/// `beginAndEndPortFromPortRange` + `validateMieruOption`
/// (adapter/outbound/mieru.go:294-361, 357-361) over the strict
/// `^(\d+)-(\d+)$` shape mieru's `validPortRange` regex enforces
/// (appctlcommon/port_binding.go:33, 61-63 — mihomo's looser
/// `fmt.Sscanf("%d-%d")` leaves tails like "1-2-3" unparsed, which the
/// mieru library then rejects at startup, so the strict form is the
/// union of both). Error texts are mihomo's, verbatim.
pub fn parse_port_range(spec: &str) -> Result<(u16, u16)> {
    let invalid = || Error::config(format!("mieru: invalid port-range format: {spec:?}"));
    let Some((begin, end)) = spec.split_once('-') else {
        return Err(invalid());
    };
    // Digits only, both sides, nothing else (the regex anchors).
    if begin.is_empty()
        || end.is_empty()
        || !begin.bytes().all(|b| b.is_ascii_digit())
        || !end.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(invalid());
    }
    let begin: u32 = begin.parse().map_err(|_| invalid())?;
    let end: u32 = end.parse().map_err(|_| invalid())?;
    if !(1..=65535).contains(&begin) {
        return Err(Error::config(
            "mieru: begin port must be between 1 and 65535",
        ));
    }
    if !(1..=65535).contains(&end) {
        return Err(Error::config("mieru: end port must be between 1 and 65535"));
    }
    if begin > end {
        return Err(Error::config(
            "mieru: begin port must be less than or equal to end port",
        ));
    }
    Ok((begin as u16, end as u16))
}

/// The port/port-range cross-checks of `validateMieruOption`
/// (adapter/outbound/mieru.go:301-309): exactly one of `port` or
/// `port_range` must be set, and a bare port must be in 1..=65535.
/// (`port == 0` means "unset" — mihomo's protobuf `Port` default.)
pub fn validate_ports(port: u16, port_range: Option<(u16, u16)>) -> Result<()> {
    if port == 0 && port_range.is_none() {
        return Err(Error::config("mieru: either port or port-range must be set"));
    }
    if port != 0 && port_range.is_some() {
        return Err(Error::config(
            "mieru: port and port-range cannot be set at the same time",
        ));
    }
    if port != 0 && !(1..=65535).contains(&port) {
        // Unreachable for u16; kept for parity with upstream's int check.
        return Err(Error::config("mieru: port must be between 1 and 65535"));
    }
    Ok(())
}

/// The dial-time endpoint list (range expanded, else the single port).
fn endpoint_ports(port: u16, port_range: Option<(u16, u16)>) -> Vec<u16> {
    match port_range {
        Some((begin, end)) => (begin..=end).collect(),
        None => vec![port],
    }
}

/// `mux.go newUnderlay` (663-675): `i := mrand.Intn(len(m.endpoints))` —
/// a uniformly random endpoint port per underlay dial.
fn pick_port(ports: &[u16]) -> Result<u16> {
    if ports.is_empty() {
        return Err(Error::config("mieru: either port or port-range must be set"));
    }
    // rand::random usize; modulo bias is negligible for ≤ 65535 ports.
    Ok(ports[rand::random::<usize>() % ports.len()])
}

/// `cipher.HashPassword` (pkg/cipher/api.go):
/// `SHA256(password ‖ 0x00 ‖ username)`.
fn hash_password(password: &[u8], username: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(password);
    h.update([0x00]);
    h.update(username);
    h.finalize().into()
}

/// PBKDF2-HMAC-SHA256 (RFC 8018; the primitive `pkg/cipher/keygen.go` uses
/// via `golang.org/x/crypto/pbkdf2`). Implemented over `hmac`+`sha2` so no
/// new dependency is introduced.
fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, out_len: usize) -> Vec<u8> {
    use hmac::Mac;
    let prf = |data: &[u8]| -> [u8; 32] {
        let mut mac = <hmac::Hmac<Sha256> as Mac>::new_from_slice(password)
            .expect("HMAC accepts any key length");
        mac.update(data);
        let out: [u8; 32] = mac.finalize().into_bytes().into();
        out
    };
    let mut out = Vec::with_capacity(out_len + 32);
    let mut block: u32 = 1;
    while out.len() < out_len {
        let mut salt_block = salt.to_vec();
        salt_block.extend_from_slice(&block.to_be_bytes());
        let mut u = prf(&salt_block);
        let mut t = u;
        for _ in 1..iterations {
            u = prf(&u);
            for (ti, ui) in t.iter_mut().zip(u.iter()) {
                *ti ^= *ui;
            }
        }
        out.extend_from_slice(&t);
        block += 1;
    }
    out.truncate(out_len);
    out
}

/// The rounded key-refresh boundary: Go's `Time.Round` rounds half away
/// from zero, so for positive Unix seconds the tie goes up.
fn round_to_interval(unix_secs: i64) -> i64 {
    let q = unix_secs.div_euclid(KEY_REFRESH_SECS);
    let r = unix_secs.rem_euclid(KEY_REFRESH_SECS);
    let quotient = if r * 2 >= KEY_REFRESH_SECS { q + 1 } else { q };
    quotient * KEY_REFRESH_SECS
}

fn salt_at(seconds: i64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(seconds.to_be_bytes());
    h.finalize().into()
}

/// `saltFromTime` (pkg/cipher/keygen.go) — the client's middle salt
/// (`salts[1]`) is the rounded time itself.
fn salt_for_time(unix_secs: i64) -> [u8; 32] {
    salt_at(round_to_interval(unix_secs))
}

/// All three discovery salts, in upstream order: past, current, future.
/// (The client needs only the middle one; the trio is what a server's
/// `Discover` iterates and what the test mimic re-implements.)
#[cfg_attr(not(test), allow(dead_code))]
fn salts_for_time(unix_secs: i64) -> [[u8; 32]; 3] {
    let rounded = round_to_interval(unix_secs);
    [
        salt_at(rounded - KEY_REFRESH_SECS),
        salt_at(rounded),
        salt_at(rounded + KEY_REFRESH_SECS),
    ]
}

/// The client key: PBKDF2 over the middle salt (`BlockCipherFromPassword` →
/// `cipherList[1]`).
fn client_key(password: &str, username: &str, unix_secs: i64) -> [u8; KEY_LEN] {
    let hashed = hash_password(password.as_bytes(), username.as_bytes());
    let salt = salt_for_time(unix_secs);
    pbkdf2_hmac_sha256(&hashed, &salt, KEY_ITER, KEY_LEN)
        .try_into()
        .expect("pbkdf2 output length is exact")
}

/// `cipher.addUserHintToNonce` / `CheckUserFromHint`:
/// `nonce[20..24] = SHA256(username ‖ nonce[..16])[..4]`.
fn apply_user_hint(username: &[u8], nonce: &mut [u8; NONCE_SIZE]) {
    let digest = user_hint_digest(username, &nonce[..HINT_PREFIX_LEN]);
    nonce[NONCE_SIZE - HINT_SUFFIX_LEN..].copy_from_slice(&digest[..HINT_SUFFIX_LEN]);
}

/// `CheckUserFromHint` — the server-side companion of the hint stamp (the
/// test mimic verifies it; the client only ever stamps).
#[cfg_attr(not(test), allow(dead_code))]
fn user_hint_matches(username: &[u8], nonce: &[u8; NONCE_SIZE]) -> bool {
    let digest = user_hint_digest(username, &nonce[..HINT_PREFIX_LEN]);
    nonce[NONCE_SIZE - HINT_SUFFIX_LEN..] == digest[..HINT_SUFFIX_LEN]
}

fn user_hint_digest(username: &[u8], prefix: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(username);
    h.update(prefix);
    h.finalize().into()
}

/// `cipher.increaseNonce`: little-endian +1 over the whole 24-byte nonce,
/// carrying from the last byte backwards.
fn increment_nonce(nonce: &mut [u8; NONCE_SIZE]) {
    for b in nonce.iter_mut().rev() {
        let (v, carried) = b.overflowing_add(1);
        *b = v;
        if !carried {
            break;
        }
    }
}

/// A stateful XChaCha20-Poly1305 cipher in implicit-nonce mode
/// (`aeadBlockCipher` with `enableImplicitNonce = true`): the first
/// operation fixes the nonce (generated on encrypt, read from the wire on
/// decrypt) and every later call increments it. The two directions clone
/// the base key independently, exactly like
/// `StreamUnderlay.send = block.Clone()` / `recv = block.Clone()` (and the
/// server's `maybeInitSendBlockCipher`, whose implicit-nonce toggle-off
/// gives it a fresh nonce).
struct StatefulCipher {
    aead: XChaCha20Poly1305,
    nonce: Option<[u8; NONCE_SIZE]>,
    nonce_sent: bool,
    username: String,
}

impl StatefulCipher {
    fn new(key: &[u8; KEY_LEN], username: &str) -> Self {
        StatefulCipher {
            aead: XChaCha20Poly1305::new(Key::from_slice(key)),
            nonce: None,
            nonce_sent: false,
            username: username.to_string(),
        }
    }

    /// `Encrypt` (cipher.go): the first call emits `nonce ‖ ct ‖ tag` (with
    /// the user hint stamped into the generated nonce); later calls emit
    /// `ct ‖ tag` under the incremented nonce.
    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = match self.nonce {
            None => {
                let mut n = [0u8; NONCE_SIZE];
                rand::rngs::OsRng.fill_bytes(&mut n);
                apply_user_hint(self.username.as_bytes(), &mut n);
                self.nonce = Some(n);
                n
            }
            Some(mut n) => {
                increment_nonce(&mut n);
                self.nonce = Some(n);
                n
            }
        };
        let ct = self
            .aead
            .encrypt(XNonce::from_slice(&nonce), Payload::from(plaintext))
            .map_err(|_| Error::crypto("mieru: encryption failed"))?;
        if self.nonce_sent {
            Ok(ct)
        } else {
            self.nonce_sent = true;
            let mut out = nonce.to_vec();
            out.extend_from_slice(&ct);
            Ok(out)
        }
    }

    /// `Decrypt` (cipher.go): the first call consumes the 24-byte nonce
    /// prefix from the ciphertext; later calls drop nothing and use the
    /// incremented nonce.
    fn decrypt(&mut self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        let (nonce, body_offset) = match self.nonce {
            None => {
                if ciphertext.len() < NONCE_SIZE + TAG_SIZE {
                    return Err(Error::protocol("mieru: ciphertext shorter than nonce"));
                }
                let mut n = [0u8; NONCE_SIZE];
                n.copy_from_slice(&ciphertext[..NONCE_SIZE]);
                self.nonce = Some(n);
                (n, NONCE_SIZE)
            }
            Some(mut n) => {
                increment_nonce(&mut n);
                self.nonce = Some(n);
                (n, 0)
            }
        };
        let body = &ciphertext[body_offset..];
        self.aead
            .decrypt(XNonce::from_slice(&nonce), Payload::from(body))
            .map_err(|_| Error::crypto("mieru: decryption failed (wrong key or corrupted data)"))
    }
}

/// A stateless XChaCha20-Poly1305 cipher — `aeadBlockCipher` with
/// `enableImplicitNonce = false`, the mode the packet underlay requires
/// (`NewPacketUnderlay` refuses stateful blocks; `mux.go newUnderlay`
/// builds it with `BlockCipherFromPassword(password, stateless=true)`).
/// `Encrypt` generates a fresh random nonce per call (user hint stamped,
/// cipher.go `addUserHintToNonce`) and prefixes it; the caller reuses that
/// nonce for the payload half of the datagram via
/// [`StatelessCipher::encrypt_with_nonce`]
/// (`writeOneSegment`: `Encrypt(meta)` → `nonce := dataToSend[:NonceSize]`
/// → `EncryptWithNonce(…, nonce, seg.payload)`). All operations take
/// `&self`: there is no per-direction state.
struct StatelessCipher {
    aead: XChaCha20Poly1305,
    username: String,
}

impl StatelessCipher {
    fn new(key: &[u8; KEY_LEN], username: &str) -> Self {
        StatelessCipher {
            aead: XChaCha20Poly1305::new(Key::from_slice(key)),
            username: username.to_string(),
        }
    }

    /// Stateless `Encrypt` (cipher.go:100-134): `nonce ‖ seal(nonce, pt)`.
    fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let nonce = self.new_nonce();
        let mut out = nonce.to_vec();
        self.seal(&nonce, plaintext, &mut out)?;
        Ok(out)
    }

    /// Stateless `EncryptWithNonce` (cipher.go:144-158).
    fn encrypt_with_nonce(&self, nonce: &[u8; NONCE_SIZE], plaintext: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(plaintext.len() + TAG_SIZE);
        self.seal(nonce, plaintext, &mut out)?;
        Ok(out)
    }

    /// Stateless `Decrypt` (cipher.go:160-189): nonce from the prefix.
    fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>> {
        if ciphertext.len() < NONCE_SIZE + TAG_SIZE {
            return Err(Error::protocol("mieru: datagram shorter than a sealed block"));
        }
        let nonce: [u8; NONCE_SIZE] = ciphertext[..NONCE_SIZE].try_into().expect("fixed size");
        self.open(&nonce, &ciphertext[NONCE_SIZE..])
    }

    /// Stateless `DecryptWithNonce` (cipher.go:191-205).
    fn decrypt_with_nonce(&self, nonce: &[u8; NONCE_SIZE], ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.open(nonce, ciphertext)
    }

    fn new_nonce(&self) -> [u8; NONCE_SIZE] {
        let mut nonce = [0u8; NONCE_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        apply_user_hint(self.username.as_bytes(), &mut nonce);
        nonce
    }

    fn seal(&self, nonce: &[u8; NONCE_SIZE], plaintext: &[u8], out: &mut Vec<u8>) -> Result<()> {
        let ct = self
            .aead
            .encrypt(XNonce::from_slice(nonce), Payload::from(plaintext))
            .map_err(|_| Error::crypto("mieru: encryption failed"))?;
        out.extend_from_slice(&ct);
        Ok(())
    }

    fn open(&self, nonce: &[u8; NONCE_SIZE], ciphertext: &[u8]) -> Result<Vec<u8>> {
        self.aead
            .decrypt(XNonce::from_slice(nonce), Payload::from(ciphertext))
            .map_err(|_| Error::crypto("mieru: decryption failed (wrong key or corrupted data)"))
    }
}

/// Current timestamp in unix minutes (`sessionStruct.Marshal`:
/// `time.Now().Unix() / 60`).
fn timestamp_minutes() -> u32 {
    (std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
        / 60) as u32
}

/// `mathext.WithinRange(now, ts, 1)`: timestamps within ±1 minute accepted.
fn timestamp_ok(ts: u32) -> bool {
    let now = timestamp_minutes();
    ts == now || ts == now.wrapping_add(1) || ts == now.wrapping_sub(1)
}

/// `sessionStruct.Marshal` — 32 bytes, big endian, timestamp auto-filled.
fn session_struct(
    protocol: u8,
    session_id: u32,
    seq: u32,
    status: u8,
    payload_len: u16,
    suffix_len: u8,
) -> [u8; METADATA_LENGTH] {
    let mut b = [0u8; METADATA_LENGTH];
    b[0] = protocol;
    b[2..6].copy_from_slice(&timestamp_minutes().to_be_bytes());
    b[6..10].copy_from_slice(&session_id.to_be_bytes());
    b[10..14].copy_from_slice(&seq.to_be_bytes());
    b[14] = status;
    b[15..17].copy_from_slice(&payload_len.to_be_bytes());
    b[17] = suffix_len;
    b
}

/// `dataAckStruct.Marshal` (non-low-entropy path: byte 1 and bytes 25..32
/// stay zero; the protocol byte is the caller's direction). The field count
/// mirrors the fixed upstream layout byte for byte.
#[allow(clippy::too_many_arguments)]
fn data_ack_struct(
    protocol: u8,
    session_id: u32,
    seq: u32,
    un_ack_seq: u32,
    window: u16,
    fragment: u8,
    prefix_len: u8,
    payload_len: u16,
    suffix_len: u8,
) -> [u8; METADATA_LENGTH] {
    let mut b = [0u8; METADATA_LENGTH];
    b[0] = protocol;
    b[2..6].copy_from_slice(&timestamp_minutes().to_be_bytes());
    b[6..10].copy_from_slice(&session_id.to_be_bytes());
    b[10..14].copy_from_slice(&seq.to_be_bytes());
    b[14..18].copy_from_slice(&un_ack_seq.to_be_bytes());
    b[18..20].copy_from_slice(&window.to_be_bytes());
    b[20] = fragment;
    b[21] = prefix_len;
    b[22..24].copy_from_slice(&payload_len.to_be_bytes());
    b[24] = suffix_len;
    b
}

/// `newPadding` + `buildRecommendedPaddingOpts` for session segments: the
/// ASCII strategy pads at least `recommendedConsecutiveASCIILen =
/// 24 + rng.FixedIntVH(17)` bytes (a username-seeded pick). Upstream's exact
/// RNG is not reproduced; a username-derived value in the same `[24, 40]`
/// range selects the minimum and the length is uniform in `[min, 255]`
/// (`maxPaddingSize` for the stream transport is 255). Only the length is
/// wire-visible; the receiver discards the bytes.
fn open_padding_len(username: &str) -> usize {
    let digest: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(username.as_bytes());
        h.finalize().into()
    };
    let min = 24 + (digest[0] % 17) as usize;
    let slack = 255 - min;
    min + (digest[1] as usize) % (slack + 1)
}

/// `newPadding(paddingOpts{maxLen: 255, ascii: &{}})` for data segments:
/// length uniform in `[0, 255]` (content random, discarded by the peer).
fn data_padding_len() -> usize {
    let seed = rand::random::<[u8; 8]>();
    (u16::from_be_bytes([seed[0], seed[1]]) % 256) as usize
}

fn random_bytes(n: usize) -> Vec<u8> {
    let mut v = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut v);
    v
}

/// One parsed inbound metadata block (either struct's fields).
#[derive(Debug, Clone, Copy)]
struct InboundMeta {
    protocol: u8,
    session_id: u32,
    seq: u32,
    status: u8,
    payload_len: u16,
    suffix_len: u8,
    prefix_len: u8,
    /// dataAck-only: `unAckSeq` (bytes 14..18). Zero for session structs.
    un_ack: u32,
    /// dataAck-only: `windowSize` (bytes 18..20). Zero for session structs.
    window: u16,
}

/// `isSessionProtocol` (metadata.go) — the four session-control protocols
/// share the sessionStruct layout; everything else is dataAck.
fn is_session_protocol(p: u8) -> bool {
    matches!(
        p,
        OPEN_SESSION_REQUEST | OPEN_SESSION_RESPONSE | CLOSE_SESSION_REQUEST | CLOSE_SESSION_RESPONSE
    )
}

/// `sessionStruct.Unmarshal` / `dataAckStruct.Unmarshal` field extraction
/// (timestamp window and payload caps enforced as upstream does). The two
/// structs disagree on where the length fields live after byte 14 —
/// `sessionStruct`: status 14, payload len 15..17, suffix len 17;
/// `dataAckStruct`: un-ack seq 14..18, window 18..20, prefix len 21,
/// payload len 22..24, suffix len 24.
fn parse_metadata(b: &[u8]) -> Result<InboundMeta> {
    if b.len() != METADATA_LENGTH {
        return Err(Error::protocol(format!(
            "mieru: metadata length {} != {METADATA_LENGTH}",
            b.len()
        )));
    }
    let ts = u32::from_be_bytes([b[2], b[3], b[4], b[5]]);
    if !timestamp_ok(ts) {
        return Err(Error::protocol(format!(
            "mieru: invalid timestamp {}",
            ts as i64 * 60
        )));
    }
    let is_session = is_session_protocol(b[0]);
    let (payload_len, suffix_len, prefix_len, un_ack, window) = if is_session {
        (
            u16::from_be_bytes([b[15], b[16]]),
            b[17],
            0u8,
            0u32,
            0u16,
        )
    } else {
        (
            u16::from_be_bytes([b[22], b[23]]),
            b[24],
            b[21],
            u32::from_be_bytes([b[14], b[15], b[16], b[17]]),
            u16::from_be_bytes([b[18], b[19]]),
        )
    };
    if is_session && payload_len as usize > MAX_SESSION_OPEN_PAYLOAD {
        return Err(Error::protocol(format!(
            "mieru: session payload {payload_len} exceeds {MAX_SESSION_OPEN_PAYLOAD}"
        )));
    }
    Ok(InboundMeta {
        protocol: b[0],
        session_id: u32::from_be_bytes([b[6], b[7], b[8], b[9]]),
        seq: u32::from_be_bytes([b[10], b[11], b[12], b[13]]),
        status: b[14],
        payload_len,
        suffix_len,
        prefix_len,
        un_ack,
        window,
    })
}

/// The mieru client session over one stream underlay.
struct MieruStream {
    inner: BoxProxyStream,
    send: StatefulCipher,
    recv: StatefulCipher,
    session_id: u32,
    /// Next outbound sequence (session.go `nextSend`).
    next_send: u32,
    /// `openSessionRequest` not yet sent (the first write piggybacks).
    open_pending: bool,
    established: bool,
    /// Decrypted metadata of a segment whose body has not fully arrived.
    pending_meta: Option<InboundMeta>,
    /// Whether the pending segment's prefix padding was already consumed
    /// (a large segment can span several reads; each re-entry must not
    /// skip it twice).
    prefix_done: bool,
    /// Raw underlay bytes not yet parsed.
    rbuf: BytesMut,
    /// Decrypted payload bytes ready for the application.
    out: BytesMut,
    /// Wire bytes waiting for the underlay.
    wbuf: BytesMut,
    /// Plaintext bytes of the current in-flight write.
    pending_plain: usize,
    /// The next inbound segment still carries the peer's nonce prefix.
    first_read: bool,
    /// Close seen or sent; the reader yields the backlog, then EOF.
    closed: bool,
}

impl MieruStream {
    /// `writeOneSegment` — session-struct path (open/close request,
    /// response), piggybacking `payload` (≤ [`MAX_SESSION_OPEN_PAYLOAD`]).
    fn build_session_segment(&mut self, protocol: u8, status: u8, payload: &[u8]) -> Result<Vec<u8>> {
        let suffix = open_padding_len(&self.send.username);
        let meta = session_struct(
            protocol,
            self.session_id,
            self.next_send,
            status,
            payload.len() as u16,
            suffix as u8,
        );
        self.next_send = self.next_send.wrapping_add(1);
        let mut wire = self.send.encrypt(&meta)?;
        if !payload.is_empty() {
            wire.extend_from_slice(&self.send.encrypt(payload)?);
        }
        wire.extend_from_slice(&random_bytes(suffix));
        Ok(wire)
    }

    /// `writeOneSegment` — dataAck path with prefix and suffix padding.
    fn build_data_segment(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
        let prefix = data_padding_len();
        let suffix = data_padding_len();
        let window = SEGMENT_TREE_CAPACITY.min(u16::MAX as usize) as u16;
        let meta = data_ack_struct(
            DATA_CLIENT_TO_SERVER,
            self.session_id,
            self.next_send,
            0, // unAckSeq: `nextRecv` never advances on the stream transport
            window,
            0, // single fragment: stream maxFragmentSize == maxPDU
            prefix as u8,
            payload.len() as u16,
            suffix as u8,
        );
        self.next_send = self.next_send.wrapping_add(1);
        let mut wire = self.send.encrypt(&meta)?;
        wire.extend_from_slice(&random_bytes(prefix));
        wire.extend_from_slice(&self.send.encrypt(payload)?);
        wire.extend_from_slice(&random_bytes(suffix));
        Ok(wire)
    }

    /// Try to consume one complete inbound segment from `rbuf`
    /// (`readOneSegment` + `readSessionSegment` / `readDataAckSegment`).
    /// `Ok(None)` = more bytes needed. The metadata is decrypted exactly
    /// once (each decrypt advances the nonce counter).
    fn parse_segment(&mut self) -> Result<bool> {
        let Some((meta, payload)) = parse_stream_segment(
            &mut self.recv,
            &mut self.rbuf,
            &mut self.pending_meta,
            &mut self.prefix_done,
            &mut self.first_read,
        )?
        else {
            return Ok(false);
        };
        self.out.extend_from_slice(&payload);
        match meta.protocol {
            OPEN_SESSION_RESPONSE => {
                if meta.session_id != self.session_id {
                    return Err(Error::protocol(format!(
                        "mieru: open response for foreign session {}",
                        meta.session_id
                    )));
                }
                self.established = true;
            }
            DATA_SERVER_TO_CLIENT => {
                if meta.session_id != self.session_id {
                    return Err(Error::protocol(
                        "mieru: data segment for a foreign session",
                    ));
                }
            }
            ACK_SERVER_TO_CLIENT => { /* inputAck: no-op on stream */ }
            CLOSE_SESSION_REQUEST => {
                // inputClose: reply closeSessionResponse, then EOF. The
                // response is queued for the next write opportunity.
                if meta.status == 1 {
                    // statusQuotaExhausted: the server closed us for quota.
                    debug!(
                        target: "engine",
                        session = self.session_id, seq = meta.seq,
                        "mieru: remote closed the session (quota exhausted)"
                    );
                }
                let wire = self.build_session_segment(CLOSE_SESSION_RESPONSE, 0, &[])?;
                self.wbuf.extend_from_slice(&wire);
                self.closed = true;
            }
            CLOSE_SESSION_RESPONSE => self.closed = true,
            // The parser rejects client-only protocols already.
            _ => unreachable!("protocols validated by parse_stream_segment"),
        }
        Ok(true)
    }
}

/// The wire half of `StreamUnderlay.readOneSegment`
/// (underlay_stream.go): peel one segment off `rbuf` using the shared
/// (per-direction) implicit-nonce cipher. Used by [`MieruStream`] (single
/// session) and by the multiplexor's reader (any session, demux by
/// metadata session id). `Ok(None)` = more bytes needed.
fn parse_stream_segment(
    recv: &mut StatefulCipher,
    rbuf: &mut BytesMut,
    pending_meta: &mut Option<InboundMeta>,
    prefix_done: &mut bool,
    first_read: &mut bool,
) -> Result<Option<(InboundMeta, Vec<u8>)>> {
    if pending_meta.is_none() {
        let overhead = TAG_SIZE + usize::from(*first_read) * NONCE_SIZE;
        if rbuf.len() < METADATA_LENGTH + overhead {
            return Ok(None);
        }
        let enc = rbuf.split_to(METADATA_LENGTH + overhead).to_vec();
        let plain = recv.decrypt(&enc)?;
        *first_read = false;
        let meta = parse_metadata(&plain)?;
        match meta.protocol {
            OPEN_SESSION_REQUEST | OPEN_SESSION_RESPONSE | CLOSE_SESSION_REQUEST
            | CLOSE_SESSION_RESPONSE | DATA_SERVER_TO_CLIENT | ACK_SERVER_TO_CLIENT => {}
            other => {
                return Err(Error::protocol(format!(
                    "mieru: unknown inbound protocol {other}"
                )))
            }
        }
        *pending_meta = Some(meta);
        *prefix_done = false;
    }
    let meta = (*pending_meta).expect("just set");
    let is_session = is_session_protocol(meta.protocol);
    if !is_session && !*prefix_done {
        if rbuf.len() < meta.prefix_len as usize {
            return Ok(None);
        }
        rbuf.advance(meta.prefix_len as usize);
        *prefix_done = true;
    }
    let mut payload = Vec::new();
    if meta.payload_len > 0 {
        let want = meta.payload_len as usize + TAG_SIZE;
        if rbuf.len() < want {
            return Ok(None);
        }
        let enc = rbuf.split_to(want).to_vec();
        payload = recv.decrypt(&enc)?;
    }
    if meta.suffix_len > 0 {
        if rbuf.len() < meta.suffix_len as usize {
            return Ok(None);
        }
        rbuf.advance(meta.suffix_len as usize);
    }
    *pending_meta = None;
    Ok(Some((meta, payload)))
}

fn io_err(e: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

impl AsyncRead for MieruStream {
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
            if this.closed && this.pending_meta.is_none() {
                // Best-effort flush of a queued close response before EOF.
                while !this.wbuf.is_empty() {
                    let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.wbuf))?;
                    if n == 0 {
                        break;
                    }
                    this.wbuf.advance(n);
                }
                return Poll::Ready(Ok(()));
            }
            match this.parse_segment() {
                Ok(true) => continue,
                Ok(false) => {
                    let mut tmp = [0u8; 16 * 1024];
                    let mut rb = ReadBuf::new(&mut tmp);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                    if rb.filled().is_empty() {
                        if this.rbuf.is_empty() && this.pending_meta.is_none() {
                            // EOF on a segment boundary: a dropped underlay.
                            this.closed = true;
                            return Poll::Ready(Ok(()));
                        }
                        return Poll::Ready(Err(io_err(Error::network(
                            "mieru: underlay closed mid-segment",
                        ))));
                    }
                    this.rbuf.extend_from_slice(rb.filled());
                }
                Err(e) => return Poll::Ready(Err(io_err(e))),
            }
        }
    }
}

impl AsyncWrite for MieruStream {
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
                "mieru: session closed",
            )));
        }
        if this.wbuf.is_empty() {
            // Session.Write: a first write of ≤ 1024 bytes piggybacks on the
            // open request; a larger first write sends it empty and the
            // payload follows as data segments.
            let consumed;
            if this.open_pending {
                if buf.len() <= MAX_SESSION_OPEN_PAYLOAD {
                    let wire = this
                        .build_session_segment(OPEN_SESSION_REQUEST, 0, buf)
                        .map_err(io_err)?;
                    this.wbuf = BytesMut::from(&wire[..]);
                    consumed = buf.len();
                } else {
                    let open = this
                        .build_session_segment(OPEN_SESSION_REQUEST, 0, &[])
                        .map_err(io_err)?;
                    let take = buf.len().min(MAX_PDU);
                    let data = this.build_data_segment(&buf[..take]).map_err(io_err)?;
                    this.wbuf = BytesMut::from(&open[..]);
                    this.wbuf.extend_from_slice(&data);
                    consumed = take;
                }
                this.open_pending = false;
            } else {
                let take = buf.len().min(MAX_PDU);
                let wire = this.build_data_segment(&buf[..take]).map_err(io_err)?;
                this.wbuf = BytesMut::from(&wire[..]);
                consumed = take;
            }
            this.pending_plain = consumed;
        }
        while !this.wbuf.is_empty() {
            let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.wbuf))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "mieru: underlay accepted zero bytes",
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
                    "mieru: underlay accepted zero bytes",
                )));
            }
            this.wbuf.advance(n);
        }
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Session.closeWithError: send closeSessionRequest (seq = nextSend,
        // status 0), without waiting for the response.
        let wire = self
            .as_mut()
            .get_mut()
            .build_session_segment(CLOSE_SESSION_REQUEST, 0, &[]);
        match wire {
            Ok(w) => self.as_mut().get_mut().wbuf.extend_from_slice(&w),
            Err(e) => return Poll::Ready(Err(io_err(e))),
        }
        ready!(self.as_mut().poll_flush(cx))?;
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// UDP (packet) transport — underlay_packet.go + session.go packet paths
// ---------------------------------------------------------------------------

/// `congestion.RTTStats` (pkg/congestion/rtt.go): RFC 6298-style smoothed
/// RTT and mean deviation, an ack-delay term and the 1.5× multiplier the
/// session installs (`SetRTOMultiplier(txTimeoutBackOff)`,
/// `SetMaxAckDelay(packetAckDelay)`).
struct RttStats {
    has_measurement: bool,
    srtt: Duration,
    mean_deviation: Duration,
    max_ack_delay: Duration,
    rto_multiplier: f64,
}

impl RttStats {
    fn new() -> Self {
        RttStats {
            has_measurement: false,
            srtt: Duration::ZERO,
            mean_deviation: Duration::ZERO,
            max_ack_delay: PACKET_ACK_DELAY,
            rto_multiplier: TX_TIMEOUT_BACKOFF,
        }
    }

    /// `RTO()` (rtt.go:74-90): 2 s before any measurement; afterwards
    /// `srtt + max(4·dev, 10ms) + maxAckDelay`, scaled by the multiplier.
    fn rto(&self) -> Duration {
        if self.srtt.is_zero() {
            return Duration::from_secs(2);
        }
        let floor = self.mean_deviation.saturating_mul(4).max(Duration::from_millis(10));
        (self.srtt + floor + self.max_ack_delay).mul_f64(self.rto_multiplier)
    }

    /// `UpdateRTT` (rtt.go:98-119): min/latest bookkeeping and the
    /// α=0.125 / β=0.25 EWMA pair.
    fn update(&mut self, sample: Duration) {
        if sample.is_zero() {
            return;
        }
        if !self.has_measurement {
            self.has_measurement = true;
            self.srtt = sample;
            self.mean_deviation = sample / 2;
        } else {
            let dev = self.srtt.abs_diff(sample);
            self.mean_deviation = self
                .mean_deviation
                .mul_f64(0.75)
                .saturating_add(dev.mul_f64(0.25));
            self.srtt = self.srtt.mul_f64(0.875).saturating_add(sample.mul_f64(0.125));
        }
    }
}

/// `congestion.CubicSendAlgorithm` (pkg/congestion/cubic.go): slow start
/// (+1 per ACK), CUBIC window growth after a loss (β=0.7, C=0.4),
/// reset to the minimum on timeout. Window sizes are segment counts.
struct Cubic {
    min_window: u32,
    max_window: u32,
    slow_start: bool,
    congestion_window: u32,
    window_before_last_reduction: u32,
    last_reduction_time: Option<f64>, // seconds since Unix epoch
    accumulated_acks: u32,
}

impl Cubic {
    fn new() -> Self {
        Cubic {
            min_window: MIN_WINDOW,
            max_window: SEGMENT_TREE_CAPACITY as u32,
            slow_start: true,
            congestion_window: MIN_WINDOW,
            window_before_last_reduction: 0,
            last_reduction_time: None,
            accumulated_acks: 0,
        }
    }

    fn congestion_window_size(&self) -> u32 {
        self.congestion_window
    }

    /// `OnAck` (cubic.go:66-80).
    fn on_ack(&mut self) {
        if self.slow_start {
            self.congestion_window += 1;
            self.in_range();
            return;
        }
        self.accumulated_acks += 1;
        let k = (f64::from(self.window_before_last_reduction) * (1.0 - 0.7) / 0.4).cbrt();
        let t = now_seconds() - self.last_reduction_time.unwrap_or(0.0);
        let w = 0.4 * (t - k) * (t - k) * (t - k) + f64::from(self.window_before_last_reduction);
        self.congestion_window = (w as u32).saturating_add(self.accumulated_acks / 16);
        self.in_range();
    }

    /// `OnLoss` (cubic.go:83-93).
    fn on_loss(&mut self) {
        self.slow_start = false;
        self.last_reduction_time = Some(now_seconds());
        self.window_before_last_reduction = self.congestion_window;
        self.accumulated_acks = 0;
        self.congestion_window = (f64::from(self.congestion_window) * 0.7) as u32;
        self.in_range();
    }

    /// `OnTimeout` (cubic.go:96-106).
    fn on_timeout(&mut self) {
        self.slow_start = true;
        self.congestion_window = self.min_window;
        self.window_before_last_reduction = 0;
        self.last_reduction_time = None;
        self.accumulated_acks = 0;
    }

    fn in_range(&mut self) {
        self.congestion_window = self
            .congestion_window
            .clamp(self.min_window, self.max_window);
    }
}

fn now_seconds() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// `maxPaddingSize` for the packet transport (padding.go:95-106):
/// `clamp(MTU − fragmentSize − packetOverhead − existing, 0, 255)`.
fn packet_max_padding(payload_len: usize, existing: usize) -> usize {
    let res = DEFAULT_MTU as isize
        - payload_len as isize
        - PACKET_OVERHEAD as isize
        - existing as isize;
    res.clamp(0, 255) as usize
}

/// Session-segment suffix padding length: the ASCII strategy's minimum is
/// `recommendedConsecutiveASCIILen = 24 + rng.FixedIntVH(17)` (padding.go:30)
/// — a username-seeded value in `[24, 40]` selects it, as in the stream
/// port — and the length is uniform in `[min, max]` where max is
/// [`packet_max_padding`] (0 if the datagram is already at the MTU).
fn packet_session_padding_len(username: &str, max: usize) -> usize {
    let digest: [u8; 32] = Sha256::digest(username.as_bytes()).into();
    let min = 24 + (digest[0] % 17) as usize;
    if max < min {
        return 0;
    }
    min + (digest[1] as usize) % (max - min + 1)
}

/// dataAck prefix/suffix padding length: uniform in `[0, max]`
/// (`newPadding` with only a max bound; the content is discarded by the
/// receiver, only the length is wire-visible).
fn packet_data_padding_len(max: usize) -> usize {
    if max == 0 {
        return 0;
    }
    rand::random::<u8>() as usize % (max + 1)
}

/// `randomHeartbeatJitter` (session.go:1512-1515).
fn random_heartbeat_jitter() -> Duration {
    Duration::from_nanos(
        rand::random::<u64>() % SESSION_HEARTBEAT_JITTER.as_nanos() as u64,
    )
}

/// One outbound segment awaiting acknowledgement (segment.go:87-95: the
/// metadata is rebuilt on every transmission because `unAckSeq` moves).
#[derive(Clone)]
struct OutSeg {
    seq: u32,
    /// OPEN_SESSION_REQUEST, DATA_CLIENT_TO_SERVER or
    /// CLOSE_SESSION_REQUEST.
    protocol: u8,
    fragment: u8,
    payload: Vec<u8>,
    ack_count: u32,
    tx_count: u32,
    tx_time: Instant,
    tx_timeout: Duration,
}

/// One datagram already decrypted and routed by a multiplexor's demux
/// loop (`PacketUnderlay.readOneSegment` + `deliverToSession`): the
/// metadata block, its wire nonce, and the un-decrypted remainder
/// (padding + sealed payload + padding).
struct DemuxedDgram {
    meta: InboundMeta,
    nonce: [u8; NONCE_SIZE],
    rest: Vec<u8>,
}

/// Where a [`PacketEngine`] gets bytes and puts wire datagrams. The
/// single-session path owns the socket directly; a multiplexed session
/// (`MieruMux`) receives pre-demultiplexed datagrams over a channel and
/// sends through the shared, connected socket.
enum PacketIo {
    /// `Mux.DialContext` without multiplexing: one session, one socket.
    Socket(UdpSocket),
    /// One session of many on a `PacketUnderlay`: the demux loop feeds
    /// datagrams for our session id; sends ride the underlay socket.
    Shared {
        rx: tokio::sync::mpsc::Receiver<DemuxedDgram>,
        sock: std::sync::Arc<UdpSocket>,
    },
}

/// What [`PacketIo::recv`] produced: raw wire bytes (socket path, the
/// engine decrypts with its own cipher) or an already-routed datagram
/// (multiplexed path).
enum PacketRx {
    Raw(usize),
    Demuxed(DemuxedDgram),
    Closed,
}

impl PacketIo {
    async fn recv(&mut self, buf: &mut [u8]) -> Result<PacketRx> {
        match self {
            PacketIo::Socket(s) => match s.recv(buf).await {
                Ok(n) => Ok(PacketRx::Raw(n)),
                Err(e) => Err(Error::network(format!("mieru: udp recv failed: {e}"))),
            },
            PacketIo::Shared { rx, .. } => {
                Ok(rx.recv().await.map_or(PacketRx::Closed, PacketRx::Demuxed))
            }
        }
    }

    async fn send(&mut self, wire: &[u8]) -> Result<()> {
        match self {
            PacketIo::Socket(s) => s
                .send(wire)
                .await
                .map(|_| ())
                .map_err(|e| Error::network(format!("mieru: udp underlay send failed: {e}"))),
            PacketIo::Shared { sock, .. } => sock
                .send(wire)
                .await
                .map(|_| ())
                .map_err(|e| Error::network(format!("mieru: udp underlay send failed: {e}"))),
        }
    }
}

/// Decrypt-and-parse one raw datagram against `cipher`
/// (`PacketUnderlay.readOneSegment`'s metadata half). `None` = not ours
/// (length gate or decrypt failure — silently dropped upstream too).
fn parse_datagram_with(
    cipher: &StatelessCipher,
    dgram: &[u8],
) -> Option<(InboundMeta, [u8; NONCE_SIZE])> {
    if dgram.len() < PACKET_NON_HEADER_POSITION {
        return None;
    }
    let meta_plain = cipher.decrypt(&dgram[..PACKET_NON_HEADER_POSITION]).ok()?;
    let meta = parse_metadata(&meta_plain).ok()?;
    let nonce: [u8; NONCE_SIZE] = dgram[..NONCE_SIZE].try_into().expect("nonce prefix");
    Some((meta, nonce))
}

/// The packet-transport session engine — a faithful single-session port of
/// `PacketUnderlay` (client half) + `Session`'s packet loops, exposed to
/// the application as a byte-stream pipe (`tokio::io::duplex`), so the
/// SOCKS5 handshake and `MieruUdp` framing above are transport-agnostic.
struct PacketEngine {
    io: PacketIo,
    cipher: StatelessCipher,
    /// Application side of the session (the post-handshake byte stream).
    app: DuplexStream,
    session_id: u32,
    /// `nextSend` — sequence of the next outbound segment.
    next_send: u32,
    /// `nextRecv` — next in-order inbound sequence.
    next_recv: u32,
    /// New segments not yet transmitted (sendQueue).
    send_queue: VecDeque<OutSeg>,
    /// Unacknowledged segments (sendBuf).
    send_buf: VecDeque<OutSeg>,
    /// Out-of-order inbound payloads (recvBuf).
    recv_buf: BTreeMap<u32, Vec<u8>>,
    open_sent: bool,
    established: bool,
    close_sent: bool,
    closed: bool,
    app_eof: bool,
    remote_window: u32,
    rtt: RttStats,
    cubic: Cubic,
    ack_pending: bool,
    ack_deadline: Instant,
    last_tx: Instant,
    last_rx: Instant,
    heartbeat_jitter: Duration,
    next_retx_check: Instant,
    /// Fired once the open session response lands, so a multiplexing
    /// caller can await session establishment (`MieruMux::connect`).
    established_tx: Option<tokio::sync::oneshot::Sender<()>>,
}

enum EngineEvent {
    App(Option<usize>),
    Dgram(usize),
    Demuxed(DemuxedDgram),
    SockErr,
    Timer,
}

impl PacketEngine {
    #[allow(clippy::too_many_arguments)]
    fn new(
        io: PacketIo,
        key: &[u8; KEY_LEN],
        username: &str,
        session_id: u32,
        app: DuplexStream,
        established_tx: Option<tokio::sync::oneshot::Sender<()>>,
    ) -> Self {
        let now = Instant::now();
        PacketEngine {
            io,
            cipher: StatelessCipher::new(key, username),
            app,
            session_id,
            next_send: 0,
            next_recv: 0,
            send_queue: VecDeque::new(),
            send_buf: VecDeque::new(),
            recv_buf: BTreeMap::new(),
            open_sent: false,
            established: false,
            close_sent: false,
            closed: false,
            app_eof: false,
            remote_window: MIN_WINDOW,
            rtt: RttStats::new(),
            cubic: Cubic::new(),
            ack_pending: false,
            ack_deadline: now,
            last_tx: now,
            last_rx: now,
            heartbeat_jitter: random_heartbeat_jitter(),
            next_retx_check: now,
            established_tx,
        }
    }

    /// `isClientPacketSessionOpening` (session.go:541-543): between attach
    /// and the open response the client suppresses ACKs and heartbeats and
    /// defers data segments (`shouldDeferNextPacketData`).
    fn opening(&self) -> bool {
        !self.established && !self.closed
    }

    /// `sendWindowSize` (session.go:1410-1412).
    fn send_window_size(&self) -> u32 {
        self.cubic
            .congestion_window_size()
            .saturating_sub(self.send_buf.len() as u32)
            .min(self.remote_window)
    }

    /// `receiveWindowSize` (session.go:1415-1419): the receive queue is the
    /// bounded application pipe, so only the reorder map counts.
    fn receive_window_size(&self) -> usize {
        SEGMENT_TREE_CAPACITY.saturating_sub(self.recv_buf.len())
    }

    /// `nextPacketOutputDelay` (session.go:986-1010) + the underlay idle
    /// timeout as the final bound.
    fn next_deadline(&self) -> Instant {
        let mut next = self.last_rx + IDLE_SESSION_TIMEOUT;
        if !self.send_buf.is_empty() {
            next = next.min(self.next_retx_check);
        }
        if !self.opening() && !self.closed {
            if self.ack_pending {
                next = next.min(self.ack_deadline);
            }
            next = next.min(self.last_tx + SESSION_HEARTBEAT + self.heartbeat_jitter);
        }
        next
    }

    /// `requestPacketAck` (session.go:1021-1031).
    fn request_ack(&mut self) {
        if self.ack_pending {
            return;
        }
        self.ack_deadline = Instant::now() + PACKET_ACK_DELAY;
        self.ack_pending = true;
    }

    /// The engine's event loop: the packet output loop's timer, the
    /// application stream and the socket (runOutputLoop packet arm +
    /// RunEventLoop).
    async fn run(mut self) {
        let mut rbuf = vec![0u8; MAX_PDU];
        let mut dgram = vec![0u8; 1500]; // readOneSegment reads into 1500
        loop {
            let deadline = self.next_deadline();
            let poll_app = !self.app_eof;
            let ev = {
                let PacketEngine { app, io, .. } = &mut self;
                tokio::select! {
                    n = app.read(&mut rbuf), if poll_app => {
                        EngineEvent::App(match n {
                            Ok(0) => None,
                            Ok(n) => Some(n),
                            Err(_) => None,
                        })
                    }
                    rx = io.recv(&mut dgram) => match rx {
                        Ok(PacketRx::Raw(n)) => EngineEvent::Dgram(n),
                        Ok(PacketRx::Demuxed(d)) => EngineEvent::Demuxed(d),
                        Ok(PacketRx::Closed) => EngineEvent::SockErr,
                        Err(_) => EngineEvent::SockErr,
                    },
                    _ = sleep_until(deadline) => EngineEvent::Timer,
                }
            };
            match ev {
                EngineEvent::App(read) => match read {
                    Some(n) => {
                        self.session_write(&rbuf[..n]);
                        self.run_output_once_packet().await;
                    }
                    None => {
                        // The application finished writing: closeWithError
                        // queues closeSessionRequest (session.go:1341+).
                        self.app_eof = true;
                        self.queue_close();
                        self.run_output_once_packet().await;
                    }
                },
                EngineEvent::Dgram(n) => {
                    self.on_datagram(&dgram[..n]).await;
                    self.run_output_once_packet().await;
                }
                EngineEvent::Demuxed(d) => {
                    self.last_rx = Instant::now();
                    self.ingest(d.meta, &d.nonce, &d.rest).await;
                    self.run_output_once_packet().await;
                }
                EngineEvent::SockErr => break,
                EngineEvent::Timer => self.run_output_once_packet().await,
            }
            if (self.closed && self.send_buf.is_empty()) || self.idle_expired() {
                break;
            }
        }
        // Dropping the app half signals EOF to the application reader.
    }

    fn idle_expired(&self) -> bool {
        !self.closed && Instant::now() > self.last_rx + IDLE_SESSION_TIMEOUT
    }

    /// `Session.Write` + `writeChunk` (session.go:323-397, 579-709): the
    /// first ≤1024 bytes piggyback on the open request; the rest is
    /// chunked at maxPDU and fragmented at MTU − packetOverhead, with the
    /// fragment index counting down (`fragment = nFragment-1 … 0`).
    fn session_write(&mut self, b: &[u8]) {
        if self.close_sent || self.closed {
            return;
        }
        let mut rest = b;
        if !self.open_sent {
            self.open_sent = true;
            let piggyback = if rest.len() <= MAX_SESSION_OPEN_PAYLOAD {
                let p = rest.to_vec();
                rest = &[];
                p
            } else {
                Vec::new()
            };
            let seq = self.alloc_seq();
            self.send_queue.push_back(OutSeg {
                seq,
                protocol: OPEN_SESSION_REQUEST,
                fragment: 0,
                payload: piggyback,
                ack_count: 0,
                tx_count: 0,
                tx_time: Instant::now(),
                tx_timeout: Duration::ZERO,
            });
        }
        for chunk in rest.chunks(MAX_PDU) {
            let n_fragment = chunk.len().div_ceil(MAX_FRAGMENT).max(1);
            for (idx, part) in chunk.chunks(MAX_FRAGMENT).enumerate() {
                let seq = self.alloc_seq();
                self.send_queue.push_back(OutSeg {
                    seq,
                    protocol: DATA_CLIENT_TO_SERVER,
                    fragment: (n_fragment - 1 - idx) as u8,
                    payload: part.to_vec(),
                    ack_count: 0,
                    tx_count: 0,
                    tx_time: Instant::now(),
                    tx_timeout: Duration::ZERO,
                });
            }
        }
    }

    fn alloc_seq(&mut self) -> u32 {
        let seq = self.next_send;
        self.next_send = self.next_send.wrapping_add(1);
        seq
    }

    /// `closeWithError` (session.go:1341+): queue closeSessionRequest —
    /// it is retransmitted like any other segment.
    fn queue_close(&mut self) {
        if self.close_sent {
            return;
        }
        self.close_sent = true;
        let seq = self.alloc_seq();
        self.send_queue.push_back(OutSeg {
            seq,
            protocol: CLOSE_SESSION_REQUEST,
            fragment: 0,
            payload: Vec::new(),
            ack_count: 0,
            tx_count: 0,
            tx_time: Instant::now(),
            tx_timeout: Duration::ZERO,
        });
    }

    /// `runOutputOncePacket` (session.go:801-984): retransmission pass,
    /// window-limited transmission of new segments, then delayed ACK or
    /// heartbeat.
    async fn run_output_once_packet(&mut self) {
        let mut has_loss = false;
        let mut has_timeout = false;
        let mut total_transmission_count = 0u32;

        if !self.send_buf.is_empty() && Instant::now() >= self.next_retx_check {
            let now = Instant::now();
            // RTO cannot move during the pass (it only changes on prune),
            // so hoist it to keep the segment borrow disjoint.
            let rto = self.rtt.rto();
            let mut next_tx: Option<Instant> = None;
            let mut fatal = false;
            let mut to_retransmit: Vec<usize> = Vec::new();
            for (i, seg) in self.send_buf.iter_mut().enumerate() {
                if seg.tx_count >= TX_COUNT_LIMIT {
                    fatal = true;
                    break;
                }
                let early = seg.ack_count >= EARLY_RETRANSMISSION
                    && seg.tx_count <= EARLY_RETRANSMISSION_LIMIT;
                if early || now.duration_since(seg.tx_time) >= seg.tx_timeout {
                    if early {
                        has_loss = true;
                    } else {
                        has_timeout = true;
                    }
                    seg.ack_count = 0;
                    seg.tx_count += 1;
                    seg.tx_time = now;
                    seg.tx_timeout = rto
                        .mul_f64(TX_TIMEOUT_BACKOFF.powi(seg.tx_count as i32))
                        .min(MAX_BACKOFF);
                    to_retransmit.push(i);
                }
                next_tx = Some(next_tx.map_or(seg.tx_time + seg.tx_timeout, |t: Instant| {
                    t.min(seg.tx_time + seg.tx_timeout)
                }));
            }
            for i in to_retransmit {
                // Cloned to keep the send path's `&mut self` disjoint from
                // the buffer borrow; the wire form is rebuilt anyway.
                let seg = self.send_buf[i].clone();
                if self.send_seg(&seg).await.is_err() {
                    fatal = true;
                    break;
                }
                total_transmission_count += 1;
            }
            if let Some(next_tx) = next_tx {
                self.next_retx_check = next_tx;
            }
            if fatal {
                // Too many retransmissions (or a dead socket): the session
                // is unhealthy (session.go:830-838).
                self.send_queue.clear();
                self.send_buf.clear();
                self.closed = true;
                return;
            }
            if has_timeout {
                self.cubic.on_timeout();
            } else if has_loss {
                self.cubic.on_loss();
            }
        }

        while !self.send_queue.is_empty() && self.send_window_size() > 0 {
            // sendBuf.Reserving() <= 1 and shouldDeferNextPacketData.
            if self.send_buf.len() + 1 >= SEGMENT_TREE_CAPACITY {
                break;
            }
            if self.opening()
                && self
                    .send_queue
                    .front()
                    .is_some_and(|s| s.protocol == DATA_CLIENT_TO_SERVER)
            {
                break;
            }
            if total_transmission_count >= self.send_window_size() {
                break;
            }
            let mut seg = match self.send_queue.pop_front() {
                Some(seg) => seg,
                None => break,
            };
            let now = Instant::now();
            seg.tx_count = 1;
            seg.tx_time = now;
            seg.tx_timeout = self.tx_timeout(seg.tx_count);
            let deadline = seg.tx_time + seg.tx_timeout;
            if self.send_buf.is_empty() {
                self.next_retx_check = deadline.min(now + RETRANSMISSION_CHECK_DELAY);
            } else if self.next_retx_check > deadline {
                self.next_retx_check = deadline;
            }
            if self.send_seg(&seg).await.is_err() {
                self.closed = true;
                return;
            }
            self.send_buf.push_back(seg);
            total_transmission_count += 1;
        }

        // ACK or heartbeat if needed (not limited by the window).
        let now = Instant::now();
        let ack_due = self.ack_pending && now >= self.ack_deadline;
        let heartbeat_due = now.duration_since(self.last_tx) > SESSION_HEARTBEAT + self.heartbeat_jitter;
        if !self.opening() && !self.closed && (ack_due || heartbeat_due) {
            self.ack_pending = false;
            let seq = self.next_send.saturating_sub(1);
            let ack = self.build_data_wire(
                ACK_CLIENT_TO_SERVER,
                seq,
                self.next_recv,
                self.receive_window_size().min(u16::MAX as usize) as u16,
                0,
                &[],
            );
            if let Ok(wire) = ack {
                if self.io.send(&wire).await.is_ok() {
                    self.last_tx = Instant::now();
                    self.heartbeat_jitter = random_heartbeat_jitter();
                }
            }
        }
    }

    /// `min(rttStat.RTO() * 1.5^txCount, 10s)` (session.go:873, 902).
    fn tx_timeout(&self, tx_count: u32) -> Duration {
        self.rtt
            .rto()
            .mul_f64(TX_TIMEOUT_BACKOFF.powi(tx_count as i32))
            .min(MAX_BACKOFF)
    }

    /// `output(seg, addr)` → `PacketUnderlay.writeOneSegment`
    /// (underlay_packet.go:625-781). Returns Err when the socket refused
    /// the datagram.
    async fn send_seg(&mut self, seg: &OutSeg) -> Result<()> {
        let wire = if is_session_protocol(seg.protocol) {
            self.build_session_wire(seg.protocol, seg.seq, 0, &seg.payload)?
        } else {
            self.build_data_wire(
                seg.protocol,
                seg.seq,
                self.next_recv,
                self.receive_window_size().min(u16::MAX as usize) as u16,
                seg.fragment,
                &seg.payload,
            )?
        };
        self.io.send(&wire).await.map_err(|e| {
            Error::network(format!("mieru: udp underlay send failed: {e}"))
        })?;
        self.last_tx = Instant::now();
        Ok(())
    }

    /// The session-struct wire form (`writeOneSegment` session branch,
    /// underlay_packet.go:669-707): `[nonce‖enc(meta)] [enc_n(nonce,
    /// payload)] [suffix padding]` — metadata and payload share the nonce.
    fn build_session_wire(
        &self,
        protocol: u8,
        seq: u32,
        status: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let max_pad = packet_max_padding(payload.len(), 0);
        let suffix = packet_session_padding_len(&self.cipher.username, max_pad);
        let meta = session_struct(
            protocol,
            self.session_id,
            seq,
            status,
            payload.len() as u16,
            suffix as u8,
        );
        let mut wire = self.cipher.encrypt(&meta)?;
        let nonce: [u8; NONCE_SIZE] = wire[..NONCE_SIZE].try_into().expect("nonce prefix");
        if !payload.is_empty() {
            wire.extend_from_slice(&self.cipher.encrypt_with_nonce(&nonce, payload)?);
        }
        wire.extend_from_slice(&random_bytes(suffix));
        Ok(wire)
    }

    /// The dataAck-struct wire form (`writeOneSegment` dataAck branch,
    /// underlay_packet.go:708-776): `[nonce‖enc(meta)] [prefix padding]
    /// [enc_n(nonce, payload)] [suffix padding]`.
    #[allow(clippy::too_many_arguments)]
    fn build_data_wire(
        &self,
        protocol: u8,
        seq: u32,
        un_ack: u32,
        window: u16,
        fragment: u8,
        payload: &[u8],
    ) -> Result<Vec<u8>> {
        let prefix = packet_data_padding_len(packet_max_padding(payload.len(), 0));
        let suffix = packet_data_padding_len(packet_max_padding(payload.len(), prefix));
        let meta = data_ack_struct(
            protocol,
            self.session_id,
            seq,
            un_ack,
            window,
            fragment,
            prefix as u8,
            payload.len() as u16,
            suffix as u8,
        );
        let mut wire = self.cipher.encrypt(&meta)?;
        let nonce: [u8; NONCE_SIZE] = wire[..NONCE_SIZE].try_into().expect("nonce prefix");
        wire.extend_from_slice(&random_bytes(prefix));
        if !payload.is_empty() {
            wire.extend_from_slice(&self.cipher.encrypt_with_nonce(&nonce, payload)?);
        }
        wire.extend_from_slice(&random_bytes(suffix));
        Ok(wire)
    }

    /// The client half of `readOneSegment` (underlay_packet.go:341-513) +
    /// `Session.input` (session.go:1045-1338). A datagram for a foreign
    /// session is dropped (single-session scope); on a multiplexed
    /// underlay the demux loop routes by session id before this runs.
    async fn on_datagram(&mut self, dgram: &[u8]) {
        self.last_rx = Instant::now();
        let Some((meta, nonce)) = parse_datagram_with(&self.cipher, dgram) else {
            return; // not ours (or corrupted): silently drop
        };
        if meta.session_id != self.session_id {
            return;
        }
        self.ingest(meta, &nonce, &dgram[PACKET_NON_HEADER_POSITION..]).await;
    }

    /// Post-metadata session dispatch — shared by the socket path above
    /// and the multiplexor's pre-decrypted datagrams.
    async fn ingest(&mut self, meta: InboundMeta, nonce: &[u8; NONCE_SIZE], rest: &[u8]) {
        match meta.protocol {
            OPEN_SESSION_RESPONSE | DATA_SERVER_TO_CLIENT => {
                let mut rest = rest;
                if meta.protocol == DATA_SERVER_TO_CLIENT {
                    // parseDataAckSegment: the prefix precedes the payload.
                    if rest.len() < meta.prefix_len as usize {
                        return;
                    }
                    rest = &rest[meta.prefix_len as usize..];
                    // The dataAck fields piggyback acknowledgement state.
                    self.prune_acked(meta.un_ack);
                    self.remote_window = u32::from(meta.window);
                }
                let want = meta.payload_len as usize + TAG_SIZE;
                if rest.len() != want + meta.suffix_len as usize {
                    return; // padding: size not match
                }
                let payload = if want > 0 {
                    match self.cipher.decrypt_with_nonce(nonce, &rest[..want]) {
                        Ok(p) => p,
                        Err(_) => return,
                    }
                } else {
                    Vec::new()
                };
                if self.receive_window_size() == 0 {
                    return; // dropped: receive window size is 0
                }
                self.recv_buf.insert(meta.seq, payload);
                self.deliver_in_order().await;
                self.request_ack();
                if meta.protocol == OPEN_SESSION_RESPONSE {
                    self.established = true;
                    if let Some(tx) = self.established_tx.take() {
                        let _ = tx.send(());
                    }
                }
            }
            ACK_SERVER_TO_CLIENT => {
                // inputAck (session.go:1234-1273).
                self.prune_acked(meta.un_ack);
                self.remote_window = u32::from(meta.window);
                for seg in self.send_buf.iter_mut() {
                    if seg.seq > meta.un_ack {
                        break;
                    }
                    if seg.seq == meta.un_ack {
                        seg.ack_count += 1;
                    }
                }
            }
            CLOSE_SESSION_REQUEST => {
                // inputClose (session.go:1276-1311): reply immediately —
                // the response is not retransmitted.
                if rest.len() != meta.payload_len as usize + TAG_SIZE + meta.suffix_len as usize {
                    return;
                }
                let seq = self.alloc_seq();
                let response =
                    self.build_session_wire(CLOSE_SESSION_RESPONSE, seq, 0, &[]);
                if let Ok(wire) = response {
                    let _ = self.io.send(&wire).await;
                }
                self.closed = true;
                self.send_queue.clear();
                self.send_buf.clear();
            }
            CLOSE_SESSION_RESPONSE => {
                self.closed = true;
                // The peer confirmed: stop retransmitting anything else.
                self.send_queue.clear();
                self.send_buf.clear();
            }
            _ => {}
        }
    }

    /// inputData/inputAck's sendBuf pruning (session.go:1146-1152):
    /// everything strictly below `un_ack` is acknowledged; each removal is
    /// an RTT sample and a CUBIC ack.
    fn prune_acked(&mut self, un_ack: u32) {
        let now = Instant::now();
        while self
            .send_buf
            .front()
            .is_some_and(|seg| seg.seq < un_ack)
        {
            let seg = self.send_buf.pop_front().expect("front checked");
            self.rtt.update(now.duration_since(seg.tx_time));
            self.cubic.on_ack();
        }
    }

    /// `moveRecvBufToRecvQueue` (session.go:1439-1471): deliver exactly the
    /// in-order prefix, one sequence at a time.
    async fn deliver_in_order(&mut self) {
        while let Some(payload) = self.recv_buf.remove(&self.next_recv) {
            self.next_recv = self.next_recv.wrapping_add(1);
            if !payload.is_empty()
                && self.app.write_all(&payload).await.is_err()
            {
                // The application is gone.
                self.closed = true;
                return;
            }
        }
    }
}

/// Dial the packet underlay and spawn its session engine, returning the
/// application side of the session as a byte stream (`Mux.DialContext` →
/// `NewPacketUnderlay` + `NewSession` + `AddSession`, mux.go:393-433,
/// 665-700: one underlay and one session per dial).
async fn dial_packet(cfg: &MieruOut) -> Result<DuplexStream> {
    let port = pick_port(&cfg.endpoint_ports())?;
    let sock = UdpSocket::bind(("0.0.0.0", 0))
        .await
        .map_err(|e| Error::network(format!("mieru: bind udp underlay: {e}")))?;
    sock.connect((cfg.server.as_str(), port))
        .await
        .map_err(|e| {
            Error::network(format!(
                "mieru: udp underlay connect {}:{port}: {e}",
                cfg.server
            ))
        })?;
    debug!(
        target: "engine",
        server = %cfg.server, port,
        "mieru: packet underlay connected"
    );

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let key = client_key(&cfg.password, &cfg.username, now);
    // Session id: `NewSession(mrand.Uint32(), …)`; 0 is reserved.
    let session_id = loop {
        let id = rand::random::<u32>();
        if id != 0 {
            break id;
        }
    };
    let (app, engine_side) = tokio::io::duplex(64 * 1024);
    let username = cfg.username.clone();
    tokio::spawn(async move {
        PacketEngine::new(
            PacketIo::Socket(sock),
            &key,
            &username,
            session_id,
            engine_side,
            None,
        )
        .run()
        .await;
    });
    Ok(app)
}

// ---------------------------------------------------------------------------
// Multiplexing — pkg/protocol/mux.go (client) + appctlcommon multiplexing
// ---------------------------------------------------------------------------

/// mieru's `MultiplexingLevel` (appctlpb) — mihomo's `multiplexing`
/// option. `NewClientMuxFromProfile` maps the levels to the multiplex
/// factor (appctlcommon/client.go:159-171): OFF→0 (a fresh underlay per
/// dial), LOW→1 (upstream's default when the profile leaves the level
/// unset), MIDDLE→2, HIGH→3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Multiplexing {
    Off,
    #[default]
    Low,
    Middle,
    High,
}

impl Multiplexing {
    /// The `SetClientMultiplexFactor` value (appctlcommon/client.go:160-171).
    pub fn factor(self) -> usize {
        match self {
            Multiplexing::Off => 0,
            Multiplexing::Low => 1,
            Multiplexing::Middle => 2,
            Multiplexing::High => 3,
        }
    }

    /// Parse mihomo's `multiplexing` string — the protobuf enum names
    /// `mierupb.MultiplexingLevel_value` accepts
    /// (adapter/outbound/mieru.go:279-283, 335-339). An empty string is
    /// upstream's unset level (LOW); anything else is mihomo's exact
    /// error.
    pub fn parse(level: &str) -> Result<Self> {
        match level {
            "" => Ok(Multiplexing::Low),
            "MULTIPLEXING_OFF" => Ok(Multiplexing::Off),
            "MULTIPLEXING_LOW" => Ok(Multiplexing::Low),
            "MULTIPLEXING_MIDDLE" => Ok(Multiplexing::Middle),
            "MULTIPLEXING_HIGH" => Ok(Multiplexing::High),
            other => Err(Error::config(format!(
                "mieru: invalid multiplexing level: {other}"
            ))),
        }
    }
}

/// Byte counters feeding the traffic-volume disable (mux.go:802-806).
#[derive(Default)]
struct UnderlayCounters {
    in_bytes: std::sync::atomic::AtomicU64,
    out_bytes: std::sync::atomic::AtomicU64,
}

/// One live underlay with its session-routing plumbing — the client half
/// of `Mux`'s underlay bookkeeping (mux.go:46-78, 747-829).
struct UnderlayHandle {
    inner: UnderlayKind,
    /// `underlay.Done()`: the reader loop is still feeding sessions.
    alive: std::sync::Arc<std::sync::atomic::AtomicBool>,
    /// Scheduler disabled (idle or over the traffic volume): never picked
    /// again (mux.go:756-759, 792-806).
    disabled: std::sync::atomic::AtomicBool,
    /// `underlay.SessionCount()`.
    session_count: std::sync::atomic::AtomicUsize,
    counters: std::sync::Arc<UnderlayCounters>,
}

impl UnderlayHandle {
    fn alive(&self) -> bool {
        self.alive.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn disabled(&self) -> bool {
        self.disabled.load(std::sync::atomic::Ordering::Relaxed)
    }

    fn disable(&self) {
        self.disabled.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// `underlay.Close()`: stop scheduling on it and tear the transport
    /// down (the reader loop then ends and clears `alive`). Safe from any
    /// context — the async shutdown is spawned when a runtime exists.
    fn close(&self) {
        self.disable();
        match &self.inner {
            UnderlayKind::Tcp(u) => {
                u.closed.store(true, std::sync::atomic::Ordering::Relaxed);
                if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    let u = u.clone();
                    handle.spawn(async move {
                        let mut wire = u.wire.lock().await;
                        // FIN: the peer closes, our read half sees EOF.
                        let _ = wire.w.shutdown().await;
                    });
                }
            }
            UnderlayKind::Udp(u) => u.closing.notify_waiters(),
        }
    }
}

enum UnderlayKind {
    Tcp(std::sync::Arc<TcpUnderlay>),
    Udp(std::sync::Arc<UdpUnderlay>),
}

// ------------------------------------------------------------ TCP underlay

/// The multiplexed TCP underlay — `StreamUnderlay` (underlay_stream.go)
/// with N sessions: ONE stateful cipher per direction shared by every
/// session on the connection (segments carry their session id in the
/// metadata), the write side locked so a segment's two AEAD operations
/// and its bytes stay adjacent on the wire.
struct TcpUnderlay {
    wire: tokio::sync::Mutex<TcpWire>,
    sessions:
        std::sync::Mutex<std::collections::HashMap<u32, tokio::sync::mpsc::Sender<ToSession>>>,
    closed: std::sync::atomic::AtomicBool,
}

struct TcpWire {
    cipher: StatefulCipher,
    w: tokio::net::tcp::OwnedWriteHalf,
}

/// One routed inbound segment (metadata + decrypted payload).
struct ToSession {
    meta: InboundMeta,
    payload: Vec<u8>,
}

impl TcpUnderlay {
    /// `writeOneSegment` — session-struct path with an explicit sequence
    /// (each session numbers its own segments).
    #[allow(clippy::too_many_arguments)]
    async fn write_session_segment(
        &self,
        protocol: u8,
        session_id: u32,
        seq: u32,
        status: u8,
        payload: &[u8],
        counters: &UnderlayCounters,
    ) -> Result<()> {
        if self.closed.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(Error::network("mieru: underlay closed"));
        }
        let mut wire = self.wire.lock().await;
        let suffix = open_padding_len(&wire.cipher.username);
        let meta = session_struct(
            protocol,
            session_id,
            seq,
            status,
            payload.len() as u16,
            suffix as u8,
        );
        let mut out = wire.cipher.encrypt(&meta)?;
        if !payload.is_empty() {
            out.extend_from_slice(&wire.cipher.encrypt(payload)?);
        }
        out.extend_from_slice(&random_bytes(suffix));
        wire.w.write_all(&out).await?;
        wire.w.flush().await?;
        counters
            .out_bytes
            .fetch_add(out.len() as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }

    /// `writeOneSegment` — dataAck path (prefix + suffix padding).
    async fn write_data_segment(
        &self,
        session_id: u32,
        seq: u32,
        payload: &[u8],
        counters: &UnderlayCounters,
    ) -> Result<()> {
        if self.closed.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(Error::network("mieru: underlay closed"));
        }
        let mut wire = self.wire.lock().await;
        let prefix = data_padding_len();
        let suffix = data_padding_len();
        let window = SEGMENT_TREE_CAPACITY.min(u16::MAX as usize) as u16;
        let meta = data_ack_struct(
            DATA_CLIENT_TO_SERVER,
            session_id,
            seq,
            0,
            window,
            0,
            prefix as u8,
            payload.len() as u16,
            suffix as u8,
        );
        let mut out = wire.cipher.encrypt(&meta)?;
        out.extend_from_slice(&random_bytes(prefix));
        out.extend_from_slice(&wire.cipher.encrypt(payload)?);
        out.extend_from_slice(&random_bytes(suffix));
        wire.w.write_all(&out).await?;
        wire.w.flush().await?;
        counters
            .out_bytes
            .fetch_add(out.len() as u64, std::sync::atomic::Ordering::Relaxed);
        Ok(())
    }
}

/// The underlay read loop — `StreamUnderlay.RunEventLoop` /
/// `readOneSegment` delivering each segment to its session
/// (`deliverToSession`): segments of *any* session on this connection
/// share one receive-nonce counter, and route by metadata session id.
/// A segment for an unknown session is dropped (the single-session port
/// errors instead — there the only possible foreign id is corruption).
async fn run_tcp_underlay_reader(
    mut r: tokio::net::tcp::OwnedReadHalf,
    mut recv: StatefulCipher,
    underlay: std::sync::Arc<TcpUnderlay>,
    counters: std::sync::Arc<UnderlayCounters>,
    alive: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let mut rbuf = BytesMut::with_capacity(16 * 1024);
    let mut pending_meta: Option<InboundMeta> = None;
    let mut prefix_done = false;
    let mut first_read = true;
    loop {
        match parse_stream_segment(&mut recv, &mut rbuf, &mut pending_meta, &mut prefix_done, &mut first_read)
        {
            Ok(Some((meta, payload))) => {
                counters
                    .in_bytes
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let tx = underlay
                    .sessions
                    .lock()
                    .unwrap()
                    .get(&meta.session_id)
                    .cloned();
                match tx {
                    Some(tx) => {
                        if tx.send(ToSession { meta, payload }).await.is_err() {
                            // The session task is gone; late segments for
                            // it are dropped.
                        }
                    }
                    None => debug!(
                        target: "engine",
                        session = meta.session_id,
                        "mieru: segment for unknown session dropped"
                    ),
                }
            }
            Ok(None) => {
                let mut tmp = [0u8; 16 * 1024];
                match r.read(&mut tmp).await {
                    Ok(0) | Err(_) => break, // underlay closed
                    Ok(n) => rbuf.extend_from_slice(&tmp[..n]),
                }
            }
            Err(e) => {
                debug!(target: "engine", error = %e, "mieru: underlay read loop ending");
                break;
            }
        }
    }
    // The underlay is done: disconnect every session so their tasks see
    // the closed channel (upstream drops the sessions in Close,
    // underlay_stream.go) instead of waiting forever.
    underlay.sessions.lock().unwrap().clear();
    alive.store(false, std::sync::atomic::Ordering::Relaxed);
}

/// One multiplexed stream session — `Session` over a shared `StreamUnderlay`
/// (`Session.Write` / `input`, session.go): per-session sequence numbers
/// and open/close state, byte-stream application pipe.
#[allow(clippy::too_many_arguments)]
async fn run_tcp_session(
    underlay: std::sync::Arc<TcpUnderlay>,
    session_id: u32,
    mut app: DuplexStream,
    mut rx: tokio::sync::mpsc::Receiver<ToSession>,
    established_tx: tokio::sync::oneshot::Sender<()>,
    counters: std::sync::Arc<UnderlayCounters>,
    handle: std::sync::Arc<UnderlayHandle>,
) {
    let mut established_tx = Some(established_tx);
    let mut next_send: u32 = 0;
    let mut open_pending = true;
    let mut buf = vec![0u8; MAX_PDU];
    loop {
        tokio::select! {
            read = app.read(&mut buf) => {
                let mut rest: &[u8] = match read {
                    Ok(0) | Err(_) => {
                        // Session.closeWithError: closeSessionRequest (seq =
                        // nextSend, status 0), no response wait.
                        let seq = next_send;
                        let _ = underlay
                            .write_session_segment(
                                CLOSE_SESSION_REQUEST, session_id, seq, 0, &[], &counters,
                            )
                            .await;
                        break;
                    }
                    Ok(n) => &buf[..n],
                };
                // Session.Write: a first write of <= 1024 bytes piggybacks
                // on the open request; a larger one opens empty and the
                // payload follows as data segments.
                if open_pending {
                    open_pending = false;
                    let seq = next_send;
                    next_send = next_send.wrapping_add(1);
                    if rest.len() <= MAX_SESSION_OPEN_PAYLOAD {
                        if underlay
                            .write_session_segment(
                                OPEN_SESSION_REQUEST, session_id, seq, 0, rest, &counters,
                            )
                            .await
                            .is_err()
                        {
                            break;
                        }
                        rest = &[];
                    } else if underlay
                        .write_session_segment(
                            OPEN_SESSION_REQUEST, session_id, seq, 0, &[], &counters,
                        )
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                for chunk in rest.chunks(MAX_PDU) {
                    let seq = next_send;
                    next_send = next_send.wrapping_add(1);
                    if underlay
                        .write_data_segment(session_id, seq, chunk, &counters)
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
            }
            seg = rx.recv() => {
                let Some(ToSession { meta, payload }) = seg else {
                    break; // underlay read loop ended
                };
                match meta.protocol {
                    OPEN_SESSION_RESPONSE => {
                        if meta.session_id != session_id {
                            break;
                        }
                        if let Some(tx) = established_tx.take() {
                            let _ = tx.send(());
                        }
                        if app.write_all(&payload).await.is_err() {
                            break;
                        }
                    }
                    DATA_SERVER_TO_CLIENT => {
                        if app.write_all(&payload).await.is_err() {
                            break;
                        }
                    }
                    CLOSE_SESSION_REQUEST => {
                        // inputClose: reply, then EOF.
                        let seq = next_send;
                        let _ = underlay
                            .write_session_segment(
                                CLOSE_SESSION_RESPONSE, session_id, seq, 0, &[], &counters,
                            )
                            .await;
                        break;
                    }
                    CLOSE_SESSION_RESPONSE => {
                        break;
                    }
                    ACK_SERVER_TO_CLIENT => {} // no-op on stream
                    _ => {}
                }
            }
        }
    }
    handle
        .session_count
        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
}

// ------------------------------------------------------------- UDP underlay

/// The multiplexed UDP underlay — `PacketUnderlay` with N sessions: one
/// connected socket, one stateless cipher (the metadata decryptor for the
/// demux loop; engines clone it for their own outbound seals), datagrams
/// routed by metadata session id.
struct UdpUnderlay {
    sock: std::sync::Arc<UdpSocket>,
    cipher: StatelessCipher,
    sessions:
        std::sync::Mutex<std::collections::HashMap<u32, tokio::sync::mpsc::Sender<DemuxedDgram>>>,
    /// `underlay.Close()`: unblocks the demux loop's recv.
    closing: tokio::sync::Notify,
}

/// `PacketUnderlay.RunEventLoop`'s demux half (underlay_packet.go):
/// the only socket reader; each datagram's metadata decides the session.
async fn run_udp_demux(
    underlay: std::sync::Arc<UdpUnderlay>,
    counters: std::sync::Arc<UnderlayCounters>,
    alive: std::sync::Arc<std::sync::atomic::AtomicBool>,
) {
    let mut buf = vec![0u8; 1500];
    loop {
        let n = tokio::select! {
            n = underlay.sock.recv(&mut buf) => match n {
                Ok(n) => n,
                Err(_) => break,
            },
            _ = underlay.closing.notified() => break,
        };
        counters
            .in_bytes
            .fetch_add(n as u64, std::sync::atomic::Ordering::Relaxed);
        if let Some((meta, nonce)) = parse_datagram_with(&underlay.cipher, &buf[..n]) {
            let dgram = DemuxedDgram {
                meta,
                nonce,
                rest: buf[PACKET_NON_HEADER_POSITION..n].to_vec(),
            };
            let tx = underlay
                .sessions
                .lock()
                .unwrap()
                .get(&dgram.meta.session_id)
                .cloned();
            if let Some(tx) = tx {
                // A closed session's late datagrams are dropped.
                let _ = tx.try_send(dgram);
            }
        }
    }
    alive.store(false, std::sync::atomic::Ordering::Relaxed);
    // Disconnect every session so the engines see the closed channel
    // (their `PacketRx::Closed` unwinds them).
    underlay.sessions.lock().unwrap().clear();
}

// ------------------------------------------------------------------- Mux

/// The client multiplexor — the client half of `pkg/protocol/mux.go`
/// `Mux` (DialContext :391-446, maybePickExistingUnderlay :747-771,
/// newUnderlay :663-730, cleanUnderlay :774-829). One value per mihomo
/// mieru outbound (`ensureClientIsRunning` keeps the client — and its
/// mux — alive across dials); every [`connect`] picks or creates an
/// underlay and adds a fresh session to it, demultiplexed by session id.
///
/// With [`Multiplexing::Off`] the pick always declines, which reproduces
/// the single-session [`connect`] shape (one underlay per dial) on the
/// same machinery.
pub struct MieruMux {
    cfg: MieruOut,
    /// The endpoint ports — `FlatPortBindings`' expansion of
    /// `port-range` (or the single port).
    ports: Vec<u16>,
    multiplex_factor: usize,
    underlays: std::sync::Mutex<Vec<std::sync::Arc<UnderlayHandle>>>,
    /// Test-only: make `maybe_pick_existing` always return the first
    /// active underlay, so the demux machinery is exercised
    /// deterministically (upstream's pick is random).
    #[cfg(test)]
    force_reuse: std::sync::atomic::AtomicBool,
}

impl MieruMux {
    /// `NewClientMuxFromProfile` (appctlcommon/client.go:104-180): wire
    /// the credentials, the multiplex factor and the endpoint list.
    pub fn new(cfg: &MieruOut, multiplexing: Multiplexing) -> Result<Self> {
        if cfg.username.is_empty() || cfg.password.is_empty() {
            return Err(Error::config("mieru: username and password are required"));
        }
        validate_ports(cfg.port, cfg.port_range)?;
        let ports = cfg.endpoint_ports();
        debug!(
            target: "engine",
            server = %cfg.server, endpoints = ports.len(),
            factor = multiplexing.factor(),
            "mieru: client multiplexer initialized"
        );
        Ok(MieruMux {
            cfg: cfg.clone(),
            ports,
            multiplex_factor: multiplexing.factor(),
            underlays: std::sync::Mutex::new(Vec::new()),
            #[cfg(test)]
            force_reuse: std::sync::atomic::AtomicBool::new(false),
        })
    }

    /// Live underlay count (test/introspection).
    pub fn underlay_count(&self) -> usize {
        self.clean_underlays();
        self.underlays.lock().unwrap().len()
    }

    /// Test-only: pin `maybePickExistingUnderlay` to the first active
    /// underlay (upstream's pick is random; tests need determinism).
    #[cfg(test)]
    fn force_reuse(&self) {
        self.force_reuse.store(true, std::sync::atomic::Ordering::Relaxed);
    }

    /// `cleanUnderlay(true)` (mux.go:412, 775-829): drop finished
    /// underlays, stop reusing idle (zero-session) ones — closing them —
    /// and disable any over the traffic volume
    /// `512 MiB << multiplexFactor` (mux.go:802).
    fn clean_underlays(&self) {
        let mut list = self.underlays.lock().unwrap();
        let mut kept = Vec::with_capacity(list.len());
        for h in list.drain(..) {
            if !h.alive() {
                continue; // reader finished: remove
            }
            if h.session_count.load(std::sync::atomic::Ordering::Relaxed) == 0 {
                h.close(); // idle: Close() + never picked again
                continue;
            }
            let limit = 512u64 << self.multiplex_factor;
            if limit > 0
                && (h.counters.in_bytes.load(std::sync::atomic::Ordering::Relaxed) > limit
                    || h.counters.out_bytes.load(std::sync::atomic::Ordering::Relaxed) > limit)
            {
                h.disable();
            }
            kept.push(h);
        }
        *list = kept;
    }

    /// `maybePickExistingUnderlay` (mux.go:747-771): among active
    /// underlays, `n := mrand.Intn(len(active)*factor + 1)` — any draw
    /// below `len(active)*factor` reuses `active[n/factor]`, otherwise a
    /// new underlay is created (so a bigger factor reuses more eagerly).
    fn maybe_pick_existing(&self) -> Option<std::sync::Arc<UnderlayHandle>> {
        let active: Vec<_> = self
            .underlays
            .lock()
            .unwrap()
            .iter()
            .filter(|h| h.alive() && !h.disabled())
            .cloned()
            .collect();
        if self.multiplex_factor == 0 || active.is_empty() {
            return None;
        }
        #[cfg(test)]
        if self.force_reuse.load(std::sync::atomic::Ordering::Relaxed) {
            return Some(active[0].clone());
        }
        let reuse_factor = active.len() * self.multiplex_factor;
        let n = rand::random::<usize>() % (reuse_factor + 1);
        if n < reuse_factor {
            return Some(active[n / self.multiplex_factor].clone());
        }
        None
    }

    /// `newUnderlay` (mux.go:663-730): a random endpoint port, then the
    /// transport's dial. The handle is NOT registered with the underlay
    /// list here — the caller registers it together with its first
    /// session (`AddSession`), so an idle underlay can never be swept by
    /// a concurrent `cleanUnderlay`.
    async fn new_underlay(&self) -> Result<std::sync::Arc<UnderlayHandle>> {
        let port = pick_port(&self.ports)?;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let key = client_key(&self.cfg.password, &self.cfg.username, now);
        let counters = std::sync::Arc::new(UnderlayCounters::default());
        match self.cfg.transport {
            MieruTransport::Tcp => {
                let tcp = tokio::net::TcpStream::connect((self.cfg.server.as_str(), port))
                    .await
                    .map_err(|e| {
                        Error::network(format!("mieru: dial {}:{port}: {e}", self.cfg.server))
                    })?;
                let _ = tcp.set_nodelay(true);
                debug!(
                    target: "engine", server = %self.cfg.server, port,
                    "mieru: new stream underlay"
                );
                let (r, w) = tcp.into_split();
                let underlay = std::sync::Arc::new(TcpUnderlay {
                    wire: tokio::sync::Mutex::new(TcpWire {
                        cipher: StatefulCipher::new(&key, &self.cfg.username),
                        w,
                    }),
                    sessions: std::sync::Mutex::new(std::collections::HashMap::new()),
                    closed: std::sync::atomic::AtomicBool::new(false),
                });
                let handle = std::sync::Arc::new(UnderlayHandle {
                    inner: UnderlayKind::Tcp(underlay.clone()),
                    alive: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
                    disabled: std::sync::atomic::AtomicBool::new(false),
                    session_count: std::sync::atomic::AtomicUsize::new(0),
                    counters: counters.clone(),
                });
                let alive = handle.alive.clone();
                tokio::spawn(run_tcp_underlay_reader(
                    r,
                    StatefulCipher::new(&key, &self.cfg.username),
                    underlay,
                    counters,
                    alive,
                ));
                Ok(handle)
            }
            MieruTransport::Udp => {
                let sock = UdpSocket::bind(("0.0.0.0", 0))
                    .await
                    .map_err(|e| Error::network(format!("mieru: bind udp underlay: {e}")))?;
                sock.connect((self.cfg.server.as_str(), port))
                    .await
                    .map_err(|e| {
                        Error::network(format!(
                            "mieru: udp underlay connect {}:{port}: {e}",
                            self.cfg.server
                        ))
                    })?;
                debug!(
                    target: "engine", server = %self.cfg.server, port,
                    "mieru: new packet underlay"
                );
                let sock = std::sync::Arc::new(sock);
                let underlay = std::sync::Arc::new(UdpUnderlay {
                    cipher: StatelessCipher::new(&key, &self.cfg.username),
                    sock: sock.clone(),
                    sessions: std::sync::Mutex::new(std::collections::HashMap::new()),
                    closing: tokio::sync::Notify::new(),
                });
                let handle = std::sync::Arc::new(UnderlayHandle {
                    inner: UnderlayKind::Udp(underlay.clone()),
                    alive: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(true)),
                    disabled: std::sync::atomic::AtomicBool::new(false),
                    session_count: std::sync::atomic::AtomicUsize::new(0),
                    counters: counters.clone(),
                });
                let alive = handle.alive.clone();
                tokio::spawn(run_udp_demux(underlay, counters, alive));
                Ok(handle)
            }
        }
    }

    /// `Mux.DialContext` (mux.go:391-446) + `PostDialHandshake`
    /// (apis/client/client.go:120-142): pick or create an underlay, add a
    /// fresh session (`NewSession(mrand.Uint32())` — 0 reserved), and run
    /// the SOCKS5 request/reply over it. `cmd` is CONNECT for stream
    /// targets and UDP ASSOCIATE for datagram ones.
    async fn dial(&self, target: &NetAddr, cmd: u8) -> Result<DuplexStream> {
        self.clean_underlays();
        // mux.go:412-423: pick an existing underlay or create one; only a
        // NEW underlay joins the mux list (mux.go:712-714, inside
        // newUnderlay), after its first session is registered so a
        // concurrent cleanUnderlay cannot sweep it as idle.
        let (handle, created) = match self.maybe_pick_existing() {
            Some(h) => {
                debug!(target: "engine", "mieru: reusing existing underlay");
                (h, false)
            }
            None => {
                let h = self.new_underlay().await?;
                debug!(target: "engine", "mieru: created new underlay");
                (h, true)
            }
        };
        // Session id: `NewSession(mrand.Uint32(), …)`; 0 is reserved.
        let session_id = loop {
            let id = rand::random::<u32>();
            if id != 0 {
                break id;
            }
        };
        let (app, engine_side) = tokio::io::duplex(64 * 1024);
        let (etx, erx) = tokio::sync::oneshot::channel();
        handle
            .session_count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        match &handle.inner {
            UnderlayKind::Tcp(u) => {
                let (tx, rx) = tokio::sync::mpsc::channel(64);
                u.sessions.lock().unwrap().insert(session_id, tx);
                tokio::spawn(run_tcp_session(
                    u.clone(),
                    session_id,
                    engine_side,
                    rx,
                    etx,
                    handle.counters.clone(),
                    handle.clone(),
                ));
            }
            UnderlayKind::Udp(u) => {
                let (tx, rx) = tokio::sync::mpsc::channel(64);
                u.sessions.lock().unwrap().insert(session_id, tx);
                let now = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs() as i64)
                    .unwrap_or(0);
                let key = client_key(&self.cfg.password, &self.cfg.username, now);
                let username = self.cfg.username.clone();
                let sock = u.sock.clone();
                let h2 = handle.clone();
                tokio::spawn(async move {
                    PacketEngine::new(
                        PacketIo::Shared { rx, sock },
                        &key,
                        &username,
                        session_id,
                        engine_side,
                        Some(etx),
                    )
                    .run()
                    .await;
                    h2.session_count
                        .fetch_sub(1, std::sync::atomic::Ordering::Relaxed);
                });
            }
        }
        // AddSession (mux.go:442-445); a newly created underlay joins the
        // list only now that it owns a session (mux.go:712-714).
        if created {
            self.underlays.lock().unwrap().push(handle);
        }

        let mut app_stream = app;
        socks5_handshake(&mut app_stream, target, cmd).await?;
        // The SOCKS5 reply rides the open session response (or follows
        // it); require the session to have opened (session.go:441-445 —
        // upstream errors a session that never established).
        match tokio::time::timeout(Duration::from_secs(10), erx).await {
            Ok(Ok(())) => {}
            Ok(Err(_)) => {
                return Err(Error::network(
                    "mieru: session closed before the open response",
                ))
            }
            Err(_) => {
                return Err(Error::network(
                    "mieru: timed out waiting for the open session response",
                ))
            }
        }
        debug!(target: "engine", session = session_id, "mieru: mux session established");
        Ok(app_stream)
    }

    /// mihomo `Mieru.DialContext` (adapter/outbound/mieru.go:74-85) over
    /// the multiplexor: a SOCKS5 CONNECT session for `target`, possibly
    /// sharing an underlay with other sessions.
    pub async fn connect(&self, target: &NetAddr) -> Result<BoxProxyStream> {
        Ok(Box::new(
            self.dial(target, SOCKS5_CONNECT_CMD).await?,
        ))
    }

    /// mihomo `Mieru.ListenPacketContext` (adapter/outbound/mieru.go:88-104)
    /// over the multiplexor: a UDP ASSOCIATE session wrapped in the
    /// packet-over-stream + associate framing ([`MieruUdp`]).
    pub async fn connect_udp(&self, target: &NetAddr) -> Result<MieruUdp> {
        let stream = self.dial(target, SOCKS5_UDP_ASSOCIATE_CMD).await?;
        debug!(target: "engine", target = %target, "mieru: mux udp associate session established");
        Ok(MieruUdp {
            stream: Box::new(stream),
        })
    }
}

/// `PostDialHandshake` (apis/internal/handshake.go:26-54): the SOCKS5
/// request `[ver, cmd, 0x00, atyp, addr, port_be16]` and the reply
/// (`model.Response.ReadFromSocks5`: `[ver, reply, 0x00]` then a bind
/// address). The command is CONNECT for stream destinations and UDP
/// ASSOCIATE for datagram ones.
async fn socks5_handshake(
    stream: &mut (impl AsyncRead + AsyncWrite + Unpin),
    target: &NetAddr,
    cmd: u8,
) -> Result<()> {
    let mut req = Vec::with_capacity(64);
    req.extend_from_slice(&[SOCKS5_VERSION, cmd, 0x00]);
    encode_socks_addr(&mut req, &target.host, target.port);
    stream.write_all(&req).await?;
    stream.flush().await?;

    let mut head = [0u8; 3];
    stream.read_exact(&mut head).await?;
    if head[0] != SOCKS5_VERSION {
        return Err(Error::protocol(format!(
            "mieru: socks5 response version {}",
            head[0]
        )));
    }
    if head[1] != 0 {
        return Err(Error::network(format!(
            "mieru: server returned socks5 error code {}",
            head[1]
        )));
    }
    let mut addr_buf = Vec::with_capacity(19);
    let mut atyp = [0u8; 1];
    stream.read_exact(&mut atyp).await?;
    addr_buf.push(atyp[0]);
    let body = match atyp[0] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            addr_buf.push(len[0]);
            len[0] as usize + 2
        }
        other => {
            return Err(Error::protocol(format!(
                "mieru: socks5 reply address type {other:#x}"
            )))
        }
    };
    let mut rest = vec![0u8; body];
    stream.read_exact(&mut rest).await?;
    addr_buf.extend_from_slice(&rest);
    let _ = decode_socks_addr(&addr_buf)?;
    Ok(())
}

/// Dial a fresh mieru session for `target` over the configured transport
/// and complete the SOCKS5 handshake with `cmd` — `client.DialContext`
/// (apis/client/client.go:120-142) for both transports.
async fn dial_session(
    cfg: &MieruOut,
    target: &NetAddr,
    cmd: u8,
) -> Result<BoxProxyStream> {
    match cfg.transport {
        MieruTransport::Tcp => {
            let port = pick_port(&cfg.endpoint_ports())?;
            let tcp = tokio::net::TcpStream::connect((cfg.server.as_str(), port))
                .await
                .map_err(|e| {
                    Error::network(format!("mieru: dial {}:{port}: {e}", cfg.server))
                })?;
            let _ = tcp.set_nodelay(true);
            debug!(
                target: "engine",
                server = %cfg.server, port, target = %target,
                "mieru: stream underlay connected"
            );

            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0);
            let key = client_key(&cfg.password, &cfg.username, now);
            // Session id: `NewSession(mrand.Uint32(), …)`; 0 is reserved.
            let session_id = loop {
                let id = rand::random::<u32>();
                if id != 0 {
                    break id;
                }
            };
            let mut stream = MieruStream {
                inner: Box::new(tcp),
                send: StatefulCipher::new(&key, &cfg.username),
                recv: StatefulCipher::new(&key, &cfg.username),
                session_id,
                next_send: 0,
                open_pending: true,
                established: false,
                pending_meta: None,
                prefix_done: false,
                rbuf: BytesMut::with_capacity(16 * 1024),
                out: BytesMut::with_capacity(16 * 1024),
                wbuf: BytesMut::new(),
                pending_plain: 0,
                first_read: true,
                closed: false,
            };
            socks5_handshake(&mut stream, target, cmd).await?;
            if !stream.established {
                // The reply always arrives in (or after) the open session response.
                return Err(Error::protocol(
                    "mieru: socks5 reply without an open session response",
                ));
            }
            debug!(target: "engine", session = session_id, "mieru: session established");
            Ok(Box::new(stream))
        }
        MieruTransport::Udp => {
            let mut app = dial_packet(cfg).await?;
            socks5_handshake(&mut app, target, cmd).await?;
            debug!(target: "engine", "mieru: packet session established");
            Ok(Box::new(app))
        }
    }
}

/// Dial `cfg` and tunnel a SOCKS5 connect request for `target` through a
/// fresh mieru session (mihomo `Mieru.DialContext` → client `DialContext` →
/// `PostDialHandshake`). Returns the established byte stream — over the
/// TCP or the UDP (packet) transport.
pub async fn connect(cfg: &MieruOut, target: &NetAddr) -> Result<BoxProxyStream> {
    if cfg.username.is_empty() || cfg.password.is_empty() {
        return Err(Error::config("mieru: username and password are required"));
    }
    dial_session(cfg, target, SOCKS5_CONNECT_CMD).await
}

// ---------------------------------------------------------------------------
// UDP datagram relay (adapter/outbound/mieru.go:92-104 ListenPacketContext)
// ---------------------------------------------------------------------------

/// A mieru UDP relay channel: a mieru session dialed to the UDP target
/// with SOCKS5 command UDP ASSOCIATE, with each datagram framed as
/// `UDPAssociateWrapper(PacketOverStreamTunnel(session))` — on the session
/// stream every datagram is
/// `0x00 ‖ be16 len ‖ 0x00 0x00 0x00 ‖ socksaddr(target) ‖ payload ‖ 0xff`.
/// The transport (`cfg.transport`) only picks the underlay; UDP datagrams
/// ride inside the session either way, exactly as in mihomo.
pub struct MieruUdp {
    stream: BoxProxyStream,
}

impl MieruUdp {
    /// Send one datagram toward `target` (the wrapper adds the associate
    /// header; the tunnel adds the length frame and the 0xff suffix).
    pub async fn send_to(&mut self, target: &NetAddr, payload: &[u8]) -> Result<()> {
        if payload.len() > u16::MAX as usize {
            return Err(Error::protocol(format!(
                "mieru: udp datagram exceeds {} bytes",
                u16::MAX
            )));
        }
        let mut inner = Vec::with_capacity(96 + payload.len());
        inner.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV(2) + FRAG
        encode_socks_addr(&mut inner, &target.host, target.port);
        inner.extend_from_slice(payload);
        let mut frame = Vec::with_capacity(inner.len() + 4);
        frame.push(0x00);
        frame.extend_from_slice(&(inner.len() as u16).to_be_bytes());
        frame.extend_from_slice(&inner);
        frame.push(0xff);
        self.stream.write_all(&frame).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Receive one datagram; returns its origin address and the length
    /// written to `buf`. A buffer shorter than the datagram is an error
    /// (upstream truncates silently).
    pub async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(NetAddr, usize)> {
        // PacketOverStreamTunnel.Read: prefix, length, payload, suffix.
        let mut head = [0u8; 3];
        self.stream.read_exact(&mut head).await?;
        if head[0] != 0x00 {
            return Err(Error::protocol(format!(
                "mieru: packet prefix {:#x} is not 0x00",
                head[0]
            )));
        }
        let len = u16::from_be_bytes([head[1], head[2]]) as usize;
        if len < 7 {
            return Err(Error::protocol(format!(
                "mieru: packet size {len} is too short to hold UDP associate header"
            )));
        }
        let mut inner = vec![0u8; len];
        self.stream.read_exact(&mut inner).await?;
        let mut suffix = [0u8; 1];
        self.stream.read_exact(&mut suffix).await?;
        if suffix[0] != 0xff {
            return Err(Error::protocol(format!(
                "mieru: packet suffix {:#x} is not 0xff",
                suffix[0]
            )));
        }
        // UDPAssociateWrapper.ReadFrom: validate [0, 0, 0], strip the
        // socks address (FQDN is unsupported upstream), keep the payload.
        if inner[0] != 0x00 || inner[1] != 0x00 {
            return Err(Error::protocol("mieru: invalid UDP header"));
        }
        if inner[2] != 0x00 {
            return Err(Error::protocol("mieru: UDP fragment is not supported"));
        }
        let (addr, used) = decode_socks_addr(&inner[3..])?;
        if matches!(addr.host, crate::addr::Host::Domain(_)) {
            return Err(Error::protocol(
                "mieru: peer used FQDN in UDP associate header, which is unsupported",
            ));
        }
        let payload = &inner[3 + used..];
        if buf.len() < payload.len() {
            return Err(Error::protocol(format!(
                "mieru: udp read: {} byte datagram exceeds the {} byte buffer",
                payload.len(),
                buf.len()
            )));
        }
        buf[..payload.len()].copy_from_slice(payload);
        Ok((addr, payload.len()))
    }
}

/// Open a mieru UDP relay to `target` — mihomo's `ListenPacketContext`
/// (adapter/outbound/mieru.go:92-104): `client.DialContext(UDPAddr())`
/// sends the SOCKS5 UDP ASSOCIATE request for the target, and the
/// returned session is wrapped in packet-over-stream + associate framing.
pub async fn connect_udp(cfg: &MieruOut, target: &NetAddr) -> Result<MieruUdp> {
    if cfg.username.is_empty() || cfg.password.is_empty() {
        return Err(Error::config("mieru: username and password are required"));
    }
    let stream = dial_session(cfg, target, SOCKS5_UDP_ASSOCIATE_CMD).await?;
    debug!(target: "engine", target = %target, "mieru: udp associate session established");
    Ok(MieruUdp { stream })
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::atomic::Ordering;
    use std::time::Duration;

    use tokio::net::TcpListener;

    // ------------------------------------------------------------ pure

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    #[test]
    fn pbkdf2_matches_published_vectors() {
        // Widely published PBKDF2-HMAC-SHA256 vectors.
        let out = pbkdf2_hmac_sha256(b"password", b"salt", 1, 32);
        assert_eq!(
            hex(&out),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
        let out = pbkdf2_hmac_sha256(b"password", b"salt", 2, 32);
        assert_eq!(
            hex(&out),
            "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"
        );
        let out = pbkdf2_hmac_sha256(
            b"passwordPASSWORDpassword",
            b"saltSALTsaltSALTsaltSALTsaltSALTsalt",
            4096,
            40,
        );
        assert_eq!(
            hex(&out),
            "348c89dbcbd32b2f32d814b8116e84cf2b17347ebc1800181c4e2a1fb8dd53e1c635518c7dac47e9"
        );
    }

    #[test]
    fn hash_password_is_sha256_of_password_sep_username() {
        // Straight transcription of cipher.HashPassword.
        let mut h = Sha256::new();
        h.update(b"secret-password");
        h.update([0x00]);
        h.update(b"alice");
        let want: [u8; 32] = h.finalize().into();
        assert_eq!(hash_password(b"secret-password", b"alice"), want);
        assert_ne!(hash_password(b"secret-password", b"bob"), want);
    }

    #[test]
    fn salt_rounds_to_two_minute_windows() {
        // 180 = 1.5 × 120: Go rounds half away from zero → 240.
        assert_eq!(salt_for_time(180), salt_at(240));
        assert_eq!(salt_for_time(179), salt_at(120));
        assert_eq!(salt_for_time(240), salt_at(240));
        assert_eq!(salt_for_time(0), salt_at(0));
        // The discovery list is [rounded−120, rounded, rounded+120].
        assert_eq!(
            salts_for_time(180),
            [salt_at(120), salt_at(240), salt_at(360)]
        );
    }

    #[test]
    fn user_hint_and_nonce_increment() {
        let username = b"alice";
        let mut nonce = [7u8; NONCE_SIZE];
        apply_user_hint(username, &mut nonce);
        assert!(user_hint_matches(username, &nonce));
        assert!(!user_hint_matches(b"bob", &nonce));
        assert_eq!(&nonce[..HINT_PREFIX_LEN], &[7u8; HINT_PREFIX_LEN]);

        // Little-endian increment with carry.
        let mut full = [0u8; NONCE_SIZE];
        full[NONCE_SIZE - 1] = 0xFF;
        increment_nonce(&mut full);
        assert_eq!(full[NONCE_SIZE - 1], 0);
        assert_eq!(full[NONCE_SIZE - 2], 1);

        let mut carry = [0xFFu8; NONCE_SIZE];
        increment_nonce(&mut carry);
        assert!(carry.iter().all(|b| *b == 0));
    }

    #[test]
    fn stateful_cipher_roundtrip_both_directions() {
        let key = [3u8; KEY_LEN];
        let mut client_tx = StatefulCipher::new(&key, "alice");
        let mut server_rx = StatefulCipher::new(&key, "alice");
        let mut server_tx = StatefulCipher::new(&key, "alice");
        let mut client_rx = StatefulCipher::new(&key, "alice");

        // First message carries the nonce prefix and the user hint.
        let m1 = client_tx.encrypt(b"metadata one").unwrap();
        assert_eq!(m1.len(), NONCE_SIZE + b"metadata one".len() + TAG_SIZE);
        let nonce: [u8; NONCE_SIZE] = m1[..NONCE_SIZE].try_into().unwrap();
        assert!(user_hint_matches(b"alice", &nonce));
        assert_eq!(server_rx.decrypt(&m1).unwrap(), b"metadata one");

        // Second message: no prefix, counter advanced once.
        let m2 = client_tx.encrypt(b"payload").unwrap();
        assert_eq!(m2.len(), b"payload".len() + TAG_SIZE);
        assert_eq!(server_rx.decrypt(&m2).unwrap(), b"payload");

        // Independent direction: the server's own nonce and hint.
        let s1 = server_tx.encrypt(b"reply-meta").unwrap();
        assert!(user_hint_matches(
            b"alice",
            &s1[..NONCE_SIZE].try_into().unwrap()
        ));
        assert_eq!(client_rx.decrypt(&s1).unwrap(), b"reply-meta");

        // A wrong key cannot open the first message.
        let mut wrong = StatefulCipher::new(&[9u8; KEY_LEN], "alice");
        let msg = client_tx.encrypt(b"x").unwrap();
        assert!(wrong.decrypt(&msg).is_err());
    }

    #[test]
    fn metadata_layouts() {
        let ss = session_struct(OPEN_SESSION_REQUEST, 0x01020304, 7, 1, 0x0102, 3);
        assert_eq!(ss[0], OPEN_SESSION_REQUEST);
        assert_eq!(ss[1], 0);
        assert_eq!(
            u32::from_be_bytes(ss[6..10].try_into().unwrap()),
            0x01020304
        );
        assert_eq!(u32::from_be_bytes(ss[10..14].try_into().unwrap()), 7);
        assert_eq!(ss[14], 1);
        assert_eq!(u16::from_be_bytes(ss[15..17].try_into().unwrap()), 0x0102);
        assert_eq!(ss[17], 3);

        let das = data_ack_struct(DATA_CLIENT_TO_SERVER, 0xAABBCCDD, 5, 0, 4096, 0, 11, 0x0203, 22);
        assert_eq!(das[0], DATA_CLIENT_TO_SERVER);
        assert_eq!(u32::from_be_bytes(das[14..18].try_into().unwrap()), 0);
        assert_eq!(u16::from_be_bytes(das[18..20].try_into().unwrap()), 4096);
        assert_eq!(das[20], 0);
        assert_eq!(das[21], 11);
        assert_eq!(u16::from_be_bytes(das[22..24].try_into().unwrap()), 0x0203);
        assert_eq!(das[24], 22);
        // The low-entropy tail stays zero (metadata.go writes it only for
        // low-entropy protocols).
        assert!(das[25..].iter().all(|b| *b == 0));

        let meta = parse_metadata(&das).unwrap();
        assert_eq!(meta.session_id, 0xAABBCCDD);
        assert_eq!(meta.seq, 5);
        assert_eq!(meta.prefix_len, 11);
        assert_eq!(meta.suffix_len, 22);
        // A stale timestamp is rejected (±1 minute window).
        let mut stale = das;
        let old = timestamp_minutes().wrapping_sub(5);
        stale[2..6].copy_from_slice(&old.to_be_bytes());
        assert!(parse_metadata(&stale).is_err());
    }

    // -------------------------------------------------- server mimic

    /// In-test mieru stream server: a faithful-lite transcription of the
    /// server side of `StreamUnderlay` for one session — user discovery over
    /// the three time-window keys (`serverUsers.Discover`), first-segment
    /// validation (`validateNewServerSessionSegment`), the open response
    /// piggybacking the SOCKS5 reply, data echo, and close handling.
    struct MimicServer {
        username: String,
        password: String,
    }

    struct ServerCtx {
        send: StatefulCipher,
        session_id: u32,
        next_send: u32,
    }

    impl ServerCtx {
        fn session_segment(&mut self, protocol: u8, payload: &[u8]) -> Result<Vec<u8>> {
            let suffix = open_padding_len(&self.send.username);
            let meta = session_struct(
                protocol,
                self.session_id,
                self.next_send,
                0,
                payload.len() as u16,
                suffix as u8,
            );
            self.next_send = self.next_send.wrapping_add(1);
            let mut wire = self.send.encrypt(&meta)?;
            if !payload.is_empty() {
                wire.extend_from_slice(&self.send.encrypt(payload)?);
            }
            wire.extend_from_slice(&random_bytes(suffix));
            Ok(wire)
        }

        fn data_segment(&mut self, payload: &[u8]) -> Result<Vec<u8>> {
            let prefix = data_padding_len();
            let suffix = data_padding_len();
            let meta = data_ack_struct(
                DATA_SERVER_TO_CLIENT,
                self.session_id,
                self.next_send,
                0,
                4096,
                0,
                prefix as u8,
                payload.len() as u16,
                suffix as u8,
            );
            self.next_send = self.next_send.wrapping_add(1);
            let mut wire = self.send.encrypt(&meta)?;
            wire.extend_from_slice(&random_bytes(prefix));
            wire.extend_from_slice(&self.send.encrypt(payload)?);
            wire.extend_from_slice(&random_bytes(suffix));
            Ok(wire)
        }
    }

    impl MimicServer {
        /// Stateless discovery (`serverUsers.Discover` →
        /// `DecryptStatelessTo`): try the three window keys with the nonce
        /// read from the prefix. Returns the winning stateful cipher (which
        /// has captured the client's nonce) and the decrypted metadata.
        fn discover(&self, first: &[u8]) -> Result<(StatefulCipher, Vec<u8>)> {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let hashed = hash_password(self.password.as_bytes(), self.username.as_bytes());
            for salt in salts_for_time(now) {
                let key: [u8; KEY_LEN] = pbkdf2_hmac_sha256(&hashed, &salt, KEY_ITER, KEY_LEN)
                    .try_into()
                    .unwrap();
                let mut probe = StatefulCipher::new(&key, &self.username);
                if let Ok(plain) = probe.decrypt(first) {
                    // The winning probe consumed the prefix and captured the
                    // client's nonce — exactly what the server's re-decrypt
                    // does in serverInitRecvBlockCipherAndDecryptMetadata.
                    return Ok((probe, plain));
                }
            }
            Err(Error::crypto("mimic: discovery failed"))
        }

        async fn run(&self, io: tokio::net::TcpStream) -> Result<()> {
            let (mut rd, mut wr) = tokio::io::split(io);
            let mut recv: Option<StatefulCipher> = None;
            let mut ctx: Option<ServerCtx> = None;
            let mut socks_done = false;

            loop {
                // readOneSegment: the first read includes the nonce.
                let overhead = TAG_SIZE + usize::from(recv.is_none()) * NONCE_SIZE;
                let mut enc_meta = vec![0u8; METADATA_LENGTH + overhead];
                if rd.read_exact(&mut enc_meta).await.is_err() {
                    return Ok(()); // client closed the underlay
                }
                let plain = match &mut recv {
                    None => {
                        let (cipher, p) = self.discover(&enc_meta)?;
                        recv = Some(cipher);
                        p
                    }
                    Some(c) => c.decrypt(&enc_meta)?,
                };
                let meta = parse_metadata(&plain)?;
                if ctx.is_none() {
                    // validateNewServerSessionSegment.
                    assert_eq!(
                        meta.protocol, OPEN_SESSION_REQUEST,
                        "first segment must be an open session request"
                    );
                    assert_ne!(meta.session_id, 0, "reserved session id 0");
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs() as i64;
                    ctx = Some(ServerCtx {
                        // maybeInitSendBlockCipher: a fresh clone (the
                        // implicit-nonce toggle gives the server its own
                        // random nonce + user hint).
                        send: StatefulCipher::new(
                            &client_key(&self.password, &self.username, now),
                            &self.username,
                        ),
                        session_id: meta.session_id,
                        next_send: 0,
                    });
                }

                let mut inbound = Vec::new();
                let is_session = matches!(
                    meta.protocol,
                    OPEN_SESSION_REQUEST | OPEN_SESSION_RESPONSE | CLOSE_SESSION_REQUEST | CLOSE_SESSION_RESPONSE
                );
                if !is_session && meta.prefix_len > 0 {
                    skip(&mut rd, meta.prefix_len as usize).await?;
                }
                if meta.payload_len > 0 {
                    let mut enc = vec![0u8; meta.payload_len as usize + TAG_SIZE];
                    rd.read_exact(&mut enc).await?;
                    inbound = recv.as_mut().unwrap().decrypt(&enc)?;
                }
                if meta.suffix_len > 0 {
                    skip(&mut rd, meta.suffix_len as usize).await?;
                }

                let ctx = ctx.as_mut().unwrap();
                match meta.protocol {
                    OPEN_SESSION_REQUEST => {
                        // The piggybacked bytes are the SOCKS5 request —
                        // CONNECT for stream targets, UDP ASSOCIATE for
                        // datagram ones (PostDialHandshake).
                        assert!(inbound.starts_with(&[SOCKS5_VERSION]));
                        assert!(
                            inbound[1] == SOCKS5_CONNECT_CMD
                                || inbound[1] == SOCKS5_UDP_ASSOCIATE_CMD,
                            "unexpected socks5 command {}",
                            inbound[1]
                        );
                        let (_, used) = decode_socks_addr(&inbound[3..]).unwrap();
                        assert_eq!(used + 3, inbound.len(), "socks request consumed exactly");
                        // The server's first Write piggybacks the SOCKS5
                        // reply on the open response (Session.Write).
                        let reply = [SOCKS5_VERSION, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
                        let wire = ctx.session_segment(OPEN_SESSION_RESPONSE, &reply)?;
                        wr.write_all(&wire).await?;
                        wr.flush().await?;
                        socks_done = true;
                    }
                    DATA_CLIENT_TO_SERVER => {
                        assert!(socks_done, "data before the socks handshake");
                        for chunk in inbound.chunks(MAX_PDU) {
                            let wire = ctx.data_segment(chunk)?;
                            wr.write_all(&wire).await?;
                        }
                        wr.flush().await?;
                    }
                    CLOSE_SESSION_REQUEST => {
                        let wire = ctx.session_segment(CLOSE_SESSION_RESPONSE, &[])?;
                        wr.write_all(&wire).await?;
                        wr.flush().await?;
                        return Ok(());
                    }
                    CLOSE_SESSION_RESPONSE => return Ok(()),
                    other => panic!("mimic: unexpected protocol {other}"),
                }
            }
        }
    }

    async fn skip(rd: &mut (impl AsyncReadExt + Unpin), mut n: usize) -> std::io::Result<()> {
        let mut tmp = [0u8; 256];
        while n > 0 {
            let take = n.min(tmp.len());
            rd.read_exact(&mut tmp[..take]).await?;
            n -= take;
        }
        Ok(())
    }

    fn test_cfg() -> MieruOut {
        MieruOut {
            server: "127.0.0.1".into(),
            port: 0,
            port_range: None,
            username: format!("user-{:016x}", rand::random::<u64>()),
            password: format!("pw-{:016x}", rand::random::<u64>()),
            transport: MieruTransport::Tcp,
            multiplexing: Multiplexing::default(),
        }
    }

    /// Bind a loopback listener and run one mimic connection against it.
    async fn spawn_mimic(cfg: &MieruOut) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = MimicServer {
            username: cfg.username.clone(),
            password: cfg.password.clone(),
        };
        let handle = tokio::spawn(async move {
            let (sock, _) = listener.accept().await.unwrap();
            let _ = sock.set_nodelay(true);
            if let Err(e) = server.run(sock).await {
                if !e.to_string().contains("discovery failed") {
                    // Authentication failure against an unknown key is the
                    // expected outcome of the negative test: drop quietly.
                    panic!("mieru mimic failed: {e}");
                }
            }
        });
        (port, handle)
    }

    #[tokio::test]
    async fn tcp_session_roundtrip_with_socks5_connect() {
        let cfg = test_cfg();
        let (port, mimic) = spawn_mimic(&cfg).await;
        let cfg = MieruOut { port, ..cfg };
        let target = NetAddr::domain("echo.example", 443).unwrap();

        let mut stream = tokio::time::timeout(Duration::from_secs(20), connect(&cfg, &target))
            .await
            .expect("connect timed out")
            .expect("connect failed");

        // Small payload: one data segment each way.
        stream.write_all(b"hello mieru").await.unwrap();
        let mut buf = [0u8; 11];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"hello mieru");

        // Multi-segment payload both ways (> maxPDU = 32 KiB: the client
        // splits, the mimic echoes chunk-for-chunk).
        let payload: Vec<u8> = (0..40 * 1024u32).map(|i| (i % 251) as u8).collect();
        let (mut rd, mut wr) = tokio::io::split(stream);
        let expected = payload.clone();
        let echo = tokio::spawn(async move {
            let mut got = vec![0u8; expected.len()];
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
        drop(wr);
        mimic.abort();
    }

    #[tokio::test]
    async fn first_write_larger_than_piggyback_limit() {
        // A first application write of >1024 bytes: the open request goes
        // out empty (Session.Write fall-through) and the payload follows as
        // data segments.
        let cfg = test_cfg();
        let (port, mimic) = spawn_mimic(&cfg).await;
        let cfg = MieruOut { port, ..cfg };
        let target = NetAddr::domain("bulk.example", 80).unwrap();
        let mut stream = tokio::time::timeout(Duration::from_secs(20), connect(&cfg, &target))
            .await
            .unwrap()
            .unwrap();
        let payload: Vec<u8> = (0..3000u32).map(|i| (i % 253) as u8).collect();
        stream.write_all(&payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut got))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, payload);
        mimic.abort();
    }

    #[tokio::test]
    async fn wrong_password_fails_authentication() {
        let cfg = test_cfg();
        let (port, _mimic) = spawn_mimic(&cfg).await;
        let mut bad = cfg.clone();
        bad.port = port;
        bad.password = format!("wrong-{:016x}", rand::random::<u64>());
        let target = NetAddr::domain("deny.example", 443).unwrap();
        // The mimic drops the connection when discovery fails; the client
        // must surface an authentication/EOF failure, never success.
        let err = match tokio::time::timeout(Duration::from_secs(20), connect(&bad, &target))
            .await
        {
            Ok(Ok(_)) => panic!("a wrong password must not authenticate"),
            Ok(Err(e)) => e,
            Err(_) => panic!("timed out"),
        };
        assert!(
            err.to_string().contains("decryption failed")
                || err.to_string().contains("closed")
                || err.to_string().contains("end of file")
                || err.to_string().contains("Connection reset"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn transport_parsing() {
        // validateMieruOption: "TCP" / "UDP", case-sensitive.
        assert_eq!(MieruTransport::parse("TCP").unwrap(), MieruTransport::Tcp);
        assert_eq!(MieruTransport::parse("UDP").unwrap(), MieruTransport::Udp);
        assert!(MieruTransport::parse("tcp").is_err());
    }

    // ------------------------------------------------ packet transport

    /// Wire helpers mirroring `writeOneSegment` for the test server.
    struct PacketMimicServer {
        username: String,
        password: String,
        /// Drop the very first datagram (the open request) to force the
        /// client's retransmission path.
        drop_first: bool,
        /// Terminate the SOCKS5 UDP-associate framing instead of echoing
        /// raw stream bytes.
        associate: bool,
    }

    impl PacketMimicServer {
        fn session_wire(
            cipher: &StatelessCipher,
            session_id: u32,
            protocol: u8,
            seq: u32,
            payload: &[u8],
        ) -> Result<Vec<u8>> {
            let max_pad = packet_max_padding(payload.len(), 0);
            let suffix = packet_session_padding_len(&cipher.username, max_pad);
            let meta = session_struct(
                protocol,
                session_id,
                seq,
                0,
                payload.len() as u16,
                suffix as u8,
            );
            let mut wire = cipher.encrypt(&meta)?;
            let nonce: [u8; NONCE_SIZE] = wire[..NONCE_SIZE].try_into().unwrap();
            if !payload.is_empty() {
                wire.extend_from_slice(&cipher.encrypt_with_nonce(&nonce, payload)?);
            }
            wire.extend_from_slice(&random_bytes(suffix));
            Ok(wire)
        }

        fn data_wire(
            cipher: &StatelessCipher,
            session_id: u32,
            protocol: u8,
            seq: u32,
            un_ack: u32,
            payload: &[u8],
        ) -> Result<Vec<u8>> {
            let prefix = packet_data_padding_len(packet_max_padding(payload.len(), 0));
            let suffix = packet_data_padding_len(packet_max_padding(payload.len(), prefix));
            let meta = data_ack_struct(
                protocol,
                session_id,
                seq,
                un_ack,
                4096,
                0,
                prefix as u8,
                payload.len() as u16,
                suffix as u8,
            );
            let mut wire = cipher.encrypt(&meta)?;
            let nonce: [u8; NONCE_SIZE] = wire[..NONCE_SIZE].try_into().unwrap();
            wire.extend_from_slice(&random_bytes(prefix));
            if !payload.is_empty() {
                wire.extend_from_slice(&cipher.encrypt_with_nonce(&nonce, payload)?);
            }
            wire.extend_from_slice(&random_bytes(suffix));
            Ok(wire)
        }

        /// The server-side wire parsing half of `readOneSegment` for one
        /// known session (discovery + segment decode).
        fn decode(
            &self,
            key: &[u8; KEY_LEN],
            dgram: &[u8],
        ) -> Option<(InboundMeta, Vec<u8>)> {
            if dgram.len() < PACKET_NON_HEADER_POSITION {
                return None;
            }
            let cipher = StatelessCipher::new(key, &self.username);
            let meta_plain = cipher.decrypt(&dgram[..PACKET_NON_HEADER_POSITION]).ok()?;
            let meta = parse_metadata(&meta_plain).ok()?;
            let nonce: [u8; NONCE_SIZE] = dgram[..NONCE_SIZE].try_into().unwrap();
            let mut rest = &dgram[PACKET_NON_HEADER_POSITION..];
            if !is_session_protocol(meta.protocol) && meta.prefix_len > 0 {
                rest = &rest[meta.prefix_len as usize..];
            }
            let want = meta.payload_len as usize + TAG_SIZE;
            if rest.len() != want + meta.suffix_len as usize {
                return None;
            }
            let payload = if want > 0 {
                cipher.decrypt_with_nonce(&nonce, &rest[..want]).ok()?
            } else {
                Vec::new()
            };
            Some((meta, payload))
        }

        async fn run(self, sock: UdpSocket) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let key = client_key(&self.password, self.username.as_str(), now);
            let cipher = StatelessCipher::new(&key, &self.username);
            let mut session_id = 0u32;
            let mut next_recv = 0u32;
            let mut next_send = 0u32;
            let mut dropped = !self.drop_first;
            let mut backlog: Vec<u8> = Vec::new();
            let socks_reply = [SOCKS5_VERSION, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            loop {
                let mut buf = vec![0u8; 1500];
                let (n, peer) = match sock.recv_from(&mut buf).await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                if !dropped {
                    dropped = true;
                    continue; // simulate one lost datagram
                }
                let Some((meta, payload)) = self.decode(&key, &buf[..n]) else {
                    continue;
                };
                if session_id == 0 {
                    assert_eq!(meta.protocol, OPEN_SESSION_REQUEST);
                    assert_ne!(meta.session_id, 0);
                    session_id = meta.session_id;
                    next_recv = meta.seq + 1;
                    let wire =
                        Self::session_wire(&cipher, session_id, OPEN_SESSION_RESPONSE, next_send, &socks_reply)
                            .unwrap();
                    next_send += 1;
                    let _ = sock.send_to(&wire, peer).await;
                    assert!(payload.starts_with(&[SOCKS5_VERSION]));
                    assert!(
                        payload[1] == SOCKS5_CONNECT_CMD
                            || payload[1] == SOCKS5_UDP_ASSOCIATE_CMD,
                        "unexpected socks5 command {}",
                        payload[1]
                    );
                    continue;
                }
                match meta.protocol {
                    OPEN_SESSION_REQUEST => {
                        // Retransmitted open: re-send the response.
                        let wire =
                            Self::session_wire(&cipher, session_id, OPEN_SESSION_RESPONSE, 0, &socks_reply)
                                .unwrap();
                        let _ = sock.send_to(&wire, peer).await;
                    }
                    DATA_CLIENT_TO_SERVER => {
                        if meta.seq != next_recv {
                            continue; // duplicate or reordered: dropped (recvBuf)
                        }
                        next_recv += 1;
                        if self.associate {
                            backlog.extend_from_slice(&payload);
                            let mut out = Vec::new();
                            // Parse every complete tunnel frame:
                            // 0x00 | be16 len | inner | 0xff.
                            while backlog.len() >= 4 && backlog[0] == 0x00 {
                                let len =
                                    u16::from_be_bytes([backlog[1], backlog[2]]) as usize;
                                if backlog.len() < 3 + len + 1 {
                                    break;
                                }
                                let frame: Vec<u8> = backlog[3..3 + len].to_vec();
                                assert_eq!(backlog[3 + len], 0xff, "tunnel suffix");
                                backlog.drain(..3 + len + 1);
                                // Strip the associate header, re-frame with a
                                // fixed origin (the server's relay behavior).
                                assert_eq!(&frame[..3], &[0, 0, 0]);
                                let (_, used) = decode_socks_addr(&frame[3..]).unwrap();
                                let payload = frame[3 + used..].to_vec();
                                let origin =
                                    NetAddr::ip("127.0.0.1".parse().unwrap(), 5353);
                                let mut inner = vec![0x00, 0x00, 0x00];
                                encode_socks_addr(&mut inner, &origin.host, origin.port);
                                inner.extend_from_slice(&payload);
                                out.push(0x00);
                                out.extend_from_slice(&(inner.len() as u16).to_be_bytes());
                                out.extend_from_slice(&inner);
                                out.push(0xff);
                            }
                            if !out.is_empty() {
                                let wire = Self::data_wire(
                                    &cipher,
                                    session_id,
                                    DATA_SERVER_TO_CLIENT,
                                    next_send,
                                    next_recv,
                                    &out,
                                )
                                .unwrap();
                                next_send += 1;
                                let _ = sock.send_to(&wire, peer).await;
                            }
                        } else {
                            // Echo the stream bytes back.
                            let wire = Self::data_wire(
                                &cipher,
                                session_id,
                                DATA_SERVER_TO_CLIENT,
                                next_send,
                                next_recv,
                                &payload,
                            )
                            .unwrap();
                            next_send += 1;
                            let _ = sock.send_to(&wire, peer).await;
                        }
                    }
                    ACK_CLIENT_TO_SERVER => {}
                    CLOSE_SESSION_REQUEST => {
                        let wire =
                            Self::session_wire(&cipher, session_id, CLOSE_SESSION_RESPONSE, next_send, &[])
                                .unwrap();
                        let _ = sock.send_to(&wire, peer).await;
                        return;
                    }
                    other => panic!("mimic: unexpected protocol {other}"),
                }
            }
        }
    }

    async fn spawn_packet_mimic(
        cfg: &MieruOut,
        drop_first: bool,
        associate: bool,
    ) -> (u16, tokio::task::JoinHandle<()>) {
        let sock = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let port = sock.local_addr().unwrap().port();
        let server = PacketMimicServer {
            username: cfg.username.clone(),
            password: cfg.password.clone(),
            drop_first,
            associate,
        };
        let handle = tokio::spawn(server.run(sock));
        (port, handle)
    }

    fn udp_cfg(port: u16) -> MieruOut {
        MieruOut {
            server: "127.0.0.1".into(),
            port,
            port_range: None,
            username: format!("user-{:016x}", rand::random::<u64>()),
            password: format!("pw-{:016x}", rand::random::<u64>()),
            transport: MieruTransport::Udp,
            multiplexing: Multiplexing::default(),
        }
    }

    #[tokio::test]
    async fn udp_transport_stream_roundtrip() {
        let base = udp_cfg(0);
        let (port, mimic) = spawn_packet_mimic(&base, false, false).await;
        let cfg = MieruOut { port, ..base };
        let target = NetAddr::domain("echo.example", 443).unwrap();

        let mut stream = tokio::time::timeout(Duration::from_secs(20), connect(&cfg, &target))
            .await
            .expect("connect timed out")
            .expect("connect failed");

        // Small payload: piggybacked on the open request, one echo segment.
        stream.write_all(b"hello mieru-udp").await.unwrap();
        let mut buf = [0u8; 15];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"hello mieru-udp");

        // A payload beyond the packet fragment size (1312) forces
        // fragmentation, sequencing and in-order reassembly, plus the
        // ACK-driven send window opening past its initial 16 segments.
        let payload: Vec<u8> = (0..20 * 1024u32).map(|i| (i % 251) as u8).collect();
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
        drop(wr);
        mimic.abort();
    }

    #[tokio::test]
    async fn udp_transport_retransmits_until_delivered() {
        // The mimic drops the very first datagram (the open session
        // request); the client must retransmit it (initial RTO 2 s scaled
        // by the 1.5 backoff) and still establish.
        let base = udp_cfg(0);
        let (port, mimic) = spawn_packet_mimic(&base, true, false).await;
        let cfg = MieruOut { port, ..base };
        let target = NetAddr::domain("retry.example", 80).unwrap();
        let mut stream = tokio::time::timeout(Duration::from_secs(20), connect(&cfg, &target))
            .await
            .expect("connect timed out")
            .expect("connect failed");
        stream.write_all(b"after-loss").await.unwrap();
        let mut buf = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"after-loss");
        mimic.abort();
    }

    #[tokio::test]
    async fn udp_associate_over_packet_transport() {
        let base = udp_cfg(0);
        let (port, mimic) = spawn_packet_mimic(&base, false, true).await;
        let cfg = MieruOut { port, ..base };
        let target = NetAddr::domain("dns.example", 53).unwrap();
        let mut udp = tokio::time::timeout(
            Duration::from_secs(20),
            connect_udp(&cfg, &target),
        )
        .await
        .expect("connect timed out")
        .expect("connect_udp failed");

        // Each datagram keeps its edges through the tunnel + associate
        // framing; the mimic relays with a fixed 127.0.0.1:5353 origin.
        udp.send_to(&target, b"q-one").await.unwrap();
        udp.send_to(&target, b"q-two!!").await.unwrap();
        let mut buf = [0u8; 1500];
        let (addr, n) = tokio::time::timeout(Duration::from_secs(10), udp.recv_from(&mut buf))
            .await
            .expect("recv timed out")
            .unwrap();
        assert_eq!(addr.host, crate::addr::Host::Ip("127.0.0.1".parse().unwrap()));
        assert_eq!(addr.port, 5353);
        assert_eq!(&buf[..n], b"q-one");
        let (_, n) = tokio::time::timeout(Duration::from_secs(10), udp.recv_from(&mut buf))
            .await
            .expect("recv timed out")
            .unwrap();
        assert_eq!(&buf[..n], b"q-two!!");
        mimic.abort();
    }

    #[tokio::test]
    async fn udp_associate_over_tcp_transport() {
        // mihomo's ListenPacketContext is transport-agnostic: the same
        // associate framing must also ride the TCP underlay. The TCP
        // mimic echoes stream bytes, so the client parses back its own
        // datagrams (self-echo semantics pin the framing round-trip).
        let cfg = test_cfg();
        let (port, mimic) = spawn_mimic(&cfg).await;
        let cfg = MieruOut { port, ..cfg };
        // The TCP mimic echoes bytes verbatim, so the echoed associate
        // header carries this IP as the origin (the wrapper refuses FQDN
        // downlink headers, like upstream).
        let target = NetAddr::ip("8.8.8.8".parse().unwrap(), 53);
        let mut udp = tokio::time::timeout(
            Duration::from_secs(20),
            connect_udp(&cfg, &target),
        )
        .await
        .expect("connect timed out")
        .expect("connect_udp failed");

        udp.send_to(&target, b"tcp-udp-assoc").await.unwrap();
        let mut buf = [0u8; 1500];
        let (addr, n) = tokio::time::timeout(Duration::from_secs(10), udp.recv_from(&mut buf))
            .await
            .expect("recv timed out")
            .unwrap();
        assert_eq!(addr.host, crate::addr::Host::Ip("8.8.8.8".parse().unwrap()));
        assert_eq!(addr.port, 53);
        assert_eq!(&buf[..n], b"tcp-udp-assoc");
        mimic.abort();
    }

    #[test]
    fn packet_padding_bounds() {
        // maxPaddingSize: clamp(MTU − payload − 88 − existing, 0, 255).
        assert_eq!(packet_max_padding(0, 0), 255);
        assert_eq!(packet_max_padding(MAX_FRAGMENT, 0), 0);
        assert_eq!(packet_max_padding(1000, 0), 255);
        assert_eq!(packet_max_padding(1250, 0), 62);
        // Session padding stays within [24, 40] ..= max.
        let len = packet_session_padding_len("alice", 255);
        assert!((24..=255).contains(&len), "{len}");
        assert_eq!(packet_session_padding_len("alice", 0), 0);
    }

    #[test]
    fn rtt_and_cubic_evolution() {
        let mut rtt = RttStats::new();
        assert_eq!(rtt.rto(), Duration::from_secs(2)); // no measurement yet
        rtt.update(Duration::from_millis(100));
        assert_eq!(rtt.srtt, Duration::from_millis(100));
        assert_eq!(rtt.mean_deviation, Duration::from_millis(50));
        let rto = rtt.rto(); // 100 + max(200, 10) + 1, ×1.5
        assert_eq!(rto, Duration::from_micros(451_500));
        rtt.update(Duration::from_millis(120));
        // srtt = 0.875·100 + 0.125·120 = 102.5 ms
        assert_eq!(rtt.srtt, Duration::from_micros(102_500));

        let mut cubic = Cubic::new();
        assert_eq!(cubic.congestion_window_size(), MIN_WINDOW);
        for _ in 0..5 {
            cubic.on_ack();
        }
        assert_eq!(cubic.congestion_window_size(), MIN_WINDOW + 5); // slow start
        cubic.on_loss();
        assert!(!cubic.slow_start);
        // 21 × 0.7 = 14.7 → 14, clamped back up to the 16 minimum.
        assert_eq!(cubic.congestion_window_size(), MIN_WINDOW);
        cubic.on_timeout();
        assert_eq!(cubic.congestion_window_size(), MIN_WINDOW);
        assert!(cubic.slow_start);
    }

    #[tokio::test]
    async fn config_requires_credentials() {
        let mut cfg = test_cfg();
        cfg.username.clear();
        let err = match connect(&cfg, &NetAddr::domain("x.test", 1).unwrap()).await {
            Ok(_) => panic!("empty username must be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("username"), "{err}");
    }

    // ------------------------------------------------- port ranges + levels

    #[test]
    fn port_range_parsing_and_validation() {
        // mihomo's exact error strings (adapter/outbound/mieru.go:301-323).
        assert_eq!(parse_port_range("2048-4096").unwrap(), (2048, 4096));
        assert_eq!(parse_port_range("1-65535").unwrap(), (1, 65535));
        assert_eq!(parse_port_range("8080-8080").unwrap(), (8080, 8080));
        for bad in [
            "",
            "8080",
            "-8080",
            "8080-",
            "a-8080",
            "8080-b",
            "0-8080",
            "8080-65536",
            "9080-8080",
            "8080-9080-7080", // FlatPortBindings' regex is anchored
            " 8080-9080",
        ] {
            let err = parse_port_range(bad).unwrap_err();
            assert!(
                err.to_string().contains("invalid port-range format")
                    || err.to_string().contains("begin port must be")
                    || err.to_string().contains("end port must be")
                    || err.to_string().contains("less than or equal"),
                "{bad:?}: {err}"
            );
        }
        // validateMieruOption's cross-checks (mihomo mieru.go:301-309).
        assert!(validate_ports(0, None).is_err());
        let err = validate_ports(0, None).unwrap_err();
        assert!(err.to_string().contains("either port or port-range must be set"));
        let err = validate_ports(8080, Some((8080, 9080))).unwrap_err();
        assert!(err.to_string().contains("cannot be set at the same time"));
        assert!(validate_ports(8080, None).is_ok());
        assert!(validate_ports(0, Some((8080, 9080))).is_ok());
        // FlatPortBindings: a range expands to one binding per port.
        assert_eq!(endpoint_ports(8080, None), vec![8080]);
        assert_eq!(endpoint_ports(0, Some((3, 6))), vec![3, 4, 5, 6]);
    }

    #[test]
    fn port_picker_stays_inside_the_range_and_spreads() {
        let ports = endpoint_ports(0, Some((2000, 2009)));
        // 400 uniform draws: every value inside the range, and with
        // overwhelming probability every port is hit (P(miss one) < 2e-18).
        let mut hits = std::collections::HashSet::new();
        for _ in 0..400 {
            let p = pick_port(&ports).unwrap();
            assert!((2000..=2009).contains(&p));
            hits.insert(p);
        }
        assert!(hits.len() >= 9, "picker is not spreading: {hits:?}");
        assert!(pick_port(&[]).is_err());
    }

    #[test]
    fn multiplexing_levels_parse_and_map_to_factors() {
        // NewClientMuxFromProfile (appctlcommon/client.go:159-171) and
        // mihomo's invalid-level error (adapter/outbound/mieru.go:335-339).
        assert_eq!(Multiplexing::default(), Multiplexing::Low);
        assert_eq!(Multiplexing::parse("").unwrap(), Multiplexing::Low);
        assert_eq!(Multiplexing::parse("MULTIPLEXING_OFF").unwrap().factor(), 0);
        assert_eq!(Multiplexing::parse("MULTIPLEXING_LOW").unwrap().factor(), 1);
        assert_eq!(Multiplexing::parse("MULTIPLEXING_MIDDLE").unwrap().factor(), 2);
        assert_eq!(Multiplexing::parse("MULTIPLEXING_HIGH").unwrap().factor(), 3);
        let err = Multiplexing::parse("max").unwrap_err();
        assert!(err.to_string().contains("invalid multiplexing level: max"));
        assert!(Multiplexing::parse("low").is_err(), "case-sensitive");
    }

    // --------------------------------------------- multiplexing: TCP mimic

    /// In-test mieru server for MANY sessions over ONE TCP underlay — the
    /// demultiplexing half of `StreamUnderlay` the single-session
    /// [`MimicServer`] does not model: one shared recv cipher and one
    /// shared send cipher, segments routed by metadata session id, each
    /// session numbering its own outbound segments.
    #[derive(Clone)]
    struct MultiSessionMimicServer {
        username: String,
        password: String,
    }

    struct SessCtx {
        next_send: u32,
        socks_done: bool,
    }

    impl MultiSessionMimicServer {
        /// The accept loop: one underlay connection at a time, each with
        /// any number of sessions.
        async fn serve(self, listener: TcpListener, conns: std::sync::Arc<AtomicUsize>) {
            loop {
                let (sock, _) = match listener.accept().await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                let _ = sock.set_nodelay(true);
                conns.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let server = self.clone();
                tokio::spawn(async move {
                    if let Err(e) = server.run_connection(sock).await {
                        if !e.to_string().contains("discovery failed") {
                            panic!("multi mimic failed: {e}");
                        }
                    }
                });
            }
        }

        async fn run_connection(&self, io: tokio::net::TcpStream) -> Result<()> {
            let (mut rd, mut wr) = tokio::io::split(io);
            let mut recv: Option<StatefulCipher> = None;
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let mut send = StatefulCipher::new(
                &client_key(&self.password, &self.username, now),
                &self.username,
            );
            let mut sessions: std::collections::HashMap<u32, SessCtx> =
                std::collections::HashMap::new();

            loop {
                let overhead = TAG_SIZE + usize::from(recv.is_none()) * NONCE_SIZE;
                let mut enc_meta = vec![0u8; METADATA_LENGTH + overhead];
                if rd.read_exact(&mut enc_meta).await.is_err() {
                    return Ok(()); // underlay closed
                }
                let plain = match &mut recv {
                    None => {
                        // serverUsers.Discover over the three window keys.
                        let mut found = None;
                        let hashed = hash_password(self.password.as_bytes(), self.username.as_bytes());
                        for salt in salts_for_time(now) {
                            let key: [u8; KEY_LEN] =
                                pbkdf2_hmac_sha256(&hashed, &salt, KEY_ITER, KEY_LEN)
                                    .try_into()
                                    .unwrap();
                            let mut probe = StatefulCipher::new(&key, &self.username);
                            if let Ok(p) = probe.decrypt(&enc_meta) {
                                found = Some((probe, p));
                                break;
                            }
                        }
                        let (cipher, p) =
                            found.ok_or_else(|| Error::crypto("discovery failed"))?;
                        recv = Some(cipher);
                        p
                    }
                    Some(c) => c.decrypt(&enc_meta)?,
                };
                let meta = parse_metadata(&plain)?;
                let mut inbound = Vec::new();
                let is_session = is_session_protocol(meta.protocol);
                if !is_session && meta.prefix_len > 0 {
                    skip(&mut rd, meta.prefix_len as usize).await?;
                }
                if meta.payload_len > 0 {
                    let mut enc = vec![0u8; meta.payload_len as usize + TAG_SIZE];
                    rd.read_exact(&mut enc).await?;
                    inbound = recv.as_mut().unwrap().decrypt(&enc)?;
                }
                if meta.suffix_len > 0 {
                    skip(&mut rd, meta.suffix_len as usize).await?;
                }

                let ctx = sessions
                    .entry(meta.session_id)
                    .or_insert_with(|| SessCtx { next_send: 0, socks_done: false });
                let seq = ctx.next_send;
                ctx.next_send = ctx.next_send.wrapping_add(1);
                match meta.protocol {
                    OPEN_SESSION_REQUEST => {
                        assert!(inbound.starts_with(&[SOCKS5_VERSION]));
                        assert_ne!(meta.session_id, 0, "reserved session id 0");
                        ctx.socks_done = true;
                        let reply = [SOCKS5_VERSION, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
                        let suffix = open_padding_len(&self.username);
                        let sm = session_struct(
                            OPEN_SESSION_RESPONSE,
                            meta.session_id,
                            seq,
                            0,
                            reply.len() as u16,
                            suffix as u8,
                        );
                        let mut wire = send.encrypt(&sm)?;
                        wire.extend_from_slice(&send.encrypt(&reply)?);
                        wire.extend_from_slice(&random_bytes(suffix));
                        wr.write_all(&wire).await?;
                        wr.flush().await?;
                    }
                    DATA_CLIENT_TO_SERVER => {
                        assert!(ctx.socks_done, "data before the socks handshake");
                        for chunk in inbound.chunks(MAX_PDU) {
                            let prefix = data_padding_len();
                            let suffix = data_padding_len();
                            let dm = data_ack_struct(
                                DATA_SERVER_TO_CLIENT,
                                meta.session_id,
                                seq,
                                0,
                                4096,
                                0,
                                prefix as u8,
                                chunk.len() as u16,
                                suffix as u8,
                            );
                            let mut wire = send.encrypt(&dm)?;
                            wire.extend_from_slice(&random_bytes(prefix));
                            wire.extend_from_slice(&send.encrypt(chunk)?);
                            wire.extend_from_slice(&random_bytes(suffix));
                            wr.write_all(&wire).await?;
                        }
                        wr.flush().await?;
                    }
                    CLOSE_SESSION_REQUEST => {
                        let suffix = open_padding_len(&self.username);
                        let sm = session_struct(
                            CLOSE_SESSION_RESPONSE,
                            meta.session_id,
                            seq,
                            0,
                            0,
                            suffix as u8,
                        );
                        let mut wire = send.encrypt(&sm)?;
                        wire.extend_from_slice(&random_bytes(suffix));
                        wr.write_all(&wire).await?;
                        wr.flush().await?;
                        sessions.remove(&meta.session_id);
                    }
                    CLOSE_SESSION_RESPONSE => {
                        sessions.remove(&meta.session_id);
                    }
                    other => panic!("multi mimic: unexpected protocol {other}"),
                }
            }
        }
    }

    type AtomicUsize = std::sync::atomic::AtomicUsize;

    /// A listener accepting any number of underlay connections, each
    /// carrying any number of sessions.
    async fn spawn_multi_tcp_mimic(
        cfg: &MieruOut,
    ) -> (u16, std::sync::Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        spawn_multi_tcp_mimic_on(cfg, 0).await
    }

    /// [`spawn_multi_tcp_mimic`] with an explicit port (0 = ephemeral).
    async fn spawn_multi_tcp_mimic_on(
        cfg: &MieruOut,
        port: u16,
    ) -> (u16, std::sync::Arc<AtomicUsize>, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", port)).await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = MultiSessionMimicServer {
            username: cfg.username.clone(),
            password: cfg.password.clone(),
        };
        let conns = std::sync::Arc::new(AtomicUsize::new(0));
        let handle = tokio::spawn(server.serve(listener, conns.clone()));
        (port, conns, handle)
    }

    fn mux_cfg(port: u16, transport: MieruTransport) -> MieruOut {
        MieruOut {
            server: "127.0.0.1".into(),
            port,
            port_range: None,
            username: format!("user-{:016x}", rand::random::<u64>()),
            password: format!("pw-{:016x}", rand::random::<u64>()),
            transport,
            multiplexing: Multiplexing::default(),
        }
    }

    #[tokio::test]
    async fn mux_tcp_two_sessions_share_one_underlay() {
        // Two concurrent SOCKS5 CONNECT targets over ONE TCP underlay,
        // demultiplexed by session id (mux.go DialContext reusing an
        // underlay via AddSession).
        let cfg = mux_cfg(0, MieruTransport::Tcp);
        let (port, conns, _mimic) = spawn_multi_tcp_mimic(&cfg).await;
        let cfg = MieruOut {
            port,
            ..cfg.clone()
        };
        let mux = MieruMux::new(&cfg, Multiplexing::High).unwrap();
        mux.force_reuse();

        let mut s1 = tokio::time::timeout(
            Duration::from_secs(20),
            mux.connect(&NetAddr::domain("alpha.example", 443).unwrap()),
        )
        .await
        .expect("dial 1 timed out")
        .expect("dial 1 failed");
        let mut s2 = tokio::time::timeout(
            Duration::from_secs(20),
            mux.connect(&NetAddr::domain("beta.example", 80).unwrap()),
        )
        .await
        .expect("dial 2 timed out")
        .expect("dial 2 failed");

        assert_eq!(mux.underlay_count(), 1, "both sessions share the underlay");
        assert_eq!(conns.load(Ordering::Relaxed), 1, "exactly one TCP connection");

        // Independent concurrent echoes over the shared underlay.
        s1.write_all(b"first-session-payload").await.unwrap();
        s2.write_all(b"second").await.unwrap();
        let (mut b1, mut b2) = ([0u8; 21], [0u8; 6]);
        let (r1, r2) = tokio::join!(
            s1.read_exact(&mut b1),
            tokio::time::timeout(Duration::from_secs(10), s2.read_exact(&mut b2)),
        );
        r1.unwrap();
        r2.expect("echo 2 timed out").unwrap();
        assert_eq!(&b1, b"first-session-payload");
        assert_eq!(&b2, b"second");
    }

    #[tokio::test]
    async fn mux_off_creates_one_underlay_per_dial() {
        // MULTIPLEXING_OFF → factor 0 → maybePickExistingUnderlay always
        // declines (mux.go:763): one fresh underlay per session.
        let cfg = mux_cfg(0, MieruTransport::Tcp);
        let (port, conns, _mimic) = spawn_multi_tcp_mimic(&cfg).await;
        let cfg = MieruOut {
            port,
            ..cfg.clone()
        };
        let mux = MieruMux::new(&cfg, Multiplexing::Off).unwrap();
        let target = NetAddr::domain("off.example", 443).unwrap();
        let mut s1 = tokio::time::timeout(Duration::from_secs(20), mux.connect(&target))
            .await
            .unwrap()
            .unwrap();
        let mut s2 = tokio::time::timeout(Duration::from_secs(20), mux.connect(&target))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(mux.underlay_count(), 2);
        assert_eq!(conns.load(Ordering::Relaxed), 2);
        // Both tunnels still work independently.
        s1.write_all(b"one").await.unwrap();
        s2.write_all(b"two!").await.unwrap();
        let (mut b1, mut b2) = ([0u8; 3], [0u8; 4]);
        let (r1, r2) = tokio::join!(s1.read_exact(&mut b1), s2.read_exact(&mut b2));
        r1.unwrap();
        r2.unwrap();
        assert_eq!(&b1, b"one");
        assert_eq!(&b2, b"two!");
    }

    #[tokio::test]
    async fn mux_high_reuses_underlays_statistically() {
        // Without the test pin: every dial creates a new underlay with
        // probability 1/(len(active)*3 + 1) — over 12 dials the odds of
        // never reusing are (1/4)(1/7)(1/10)... ≈ 3e-11.
        let cfg = mux_cfg(0, MieruTransport::Tcp);
        let (port, _conns, _mimic) = spawn_multi_tcp_mimic(&cfg).await;
        let cfg = MieruOut {
            port,
            ..cfg.clone()
        };
        let mux = MieruMux::new(&cfg, Multiplexing::High).unwrap();
        let target = NetAddr::domain("many.example", 443).unwrap();
        let mut streams = Vec::new();
        for _ in 0..12 {
            streams.push(
                tokio::time::timeout(Duration::from_secs(20), mux.connect(&target))
                    .await
                    .unwrap()
                    .unwrap(),
            );
        }
        assert!(
            mux.underlay_count() < 12,
            "expected some underlay reuse, got {}",
            mux.underlay_count()
        );
    }

    // --------------------------------------------- multiplexing: UDP mimic

    /// UDP counterpart of [`MultiSessionMimicServer`]: one socket, many
    /// sessions routed by metadata session id, per-session sequencing.
    struct MultiPacketMimicServer {
        username: String,
        password: String,
    }

    struct UdpSessCtx {
        next_recv: u32,
        next_send: u32,
    }

    impl MultiPacketMimicServer {
        async fn run(self, sock: UdpSocket) {
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs() as i64;
            let key = client_key(&self.password, self.username.as_str(), now);
            let cipher = StatelessCipher::new(&key, &self.username);
            let decode = PacketMimicServer {
                username: self.username.clone(),
                password: self.password.clone(),
                drop_first: false,
                associate: false,
            };
            let mut sessions: std::collections::HashMap<u32, UdpSessCtx> =
                std::collections::HashMap::new();
            let socks_reply = [SOCKS5_VERSION, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
            loop {
                let mut buf = vec![0u8; 1500];
                let (n, peer) = match sock.recv_from(&mut buf).await {
                    Ok(x) => x,
                    Err(_) => return,
                };
                let Some((meta, payload)) = decode.decode(&key, &buf[..n]) else {
                    continue;
                };
                let ctx = sessions
                    .entry(meta.session_id)
                    .or_insert_with(|| UdpSessCtx { next_recv: 0, next_send: 0 });
                match meta.protocol {
                    OPEN_SESSION_REQUEST => {
                        assert_ne!(meta.session_id, 0);
                        assert!(payload.starts_with(&[SOCKS5_VERSION]));
                        assert_eq!(payload[1], SOCKS5_CONNECT_CMD);
                        ctx.next_recv = meta.seq + 1;
                        let wire = PacketMimicServer::session_wire(
                            &cipher,
                            meta.session_id,
                            OPEN_SESSION_RESPONSE,
                            ctx.next_send,
                            &socks_reply,
                        )
                        .unwrap();
                        ctx.next_send += 1;
                        let _ = sock.send_to(&wire, peer).await;
                    }
                    DATA_CLIENT_TO_SERVER => {
                        if meta.seq != ctx.next_recv {
                            continue; // duplicate or reordered
                        }
                        ctx.next_recv += 1;
                        let wire = PacketMimicServer::data_wire(
                            &cipher,
                            meta.session_id,
                            DATA_SERVER_TO_CLIENT,
                            ctx.next_send,
                            ctx.next_recv,
                            &payload,
                        )
                        .unwrap();
                        ctx.next_send += 1;
                        let _ = sock.send_to(&wire, peer).await;
                    }
                    ACK_CLIENT_TO_SERVER => {}
                    CLOSE_SESSION_REQUEST => {
                        let wire = PacketMimicServer::session_wire(
                            &cipher,
                            meta.session_id,
                            CLOSE_SESSION_RESPONSE,
                            ctx.next_send,
                            &[],
                        )
                        .unwrap();
                        let _ = sock.send_to(&wire, peer).await;
                        sessions.remove(&meta.session_id);
                    }
                    CLOSE_SESSION_RESPONSE => {
                        sessions.remove(&meta.session_id);
                    }
                    other => panic!("multi udp mimic: unexpected protocol {other}"),
                }
            }
        }
    }

    #[tokio::test]
    async fn mux_udp_two_sessions_share_one_underlay() {
        // Two sessions over ONE UDP socket (one PacketUnderlay), each with
        // its own reliability engine, demuxed by session id.
        let sock = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let port = sock.local_addr().unwrap().port();
        let username = format!("user-{:016x}", rand::random::<u64>());
        let password = format!("pw-{:016x}", rand::random::<u64>());
        let server = MultiPacketMimicServer {
            username: username.clone(),
            password: password.clone(),
        };
        tokio::spawn(server.run(sock));
        let cfg = MieruOut {
            server: "127.0.0.1".into(),
            port,
            port_range: None,
            username,
            password,
            transport: MieruTransport::Udp,
            multiplexing: Multiplexing::High,
        };
        let mux = MieruMux::new(&cfg, Multiplexing::High).unwrap();
        mux.force_reuse();

        let mut s1 = tokio::time::timeout(
            Duration::from_secs(20),
            mux.connect(&NetAddr::domain("u-one.example", 443).unwrap()),
        )
        .await
        .expect("udp dial 1 timed out")
        .expect("udp dial 1 failed");
        let mut s2 = tokio::time::timeout(
            Duration::from_secs(20),
            mux.connect(&NetAddr::domain("u-two.example", 80).unwrap()),
        )
        .await
        .expect("udp dial 2 timed out")
        .expect("udp dial 2 failed");

        assert_eq!(mux.underlay_count(), 1, "both sessions share the underlay");

        s1.write_all(b"udp-session-one").await.unwrap();
        s2.write_all(b"udp-two").await.unwrap();
        let (mut b1, mut b2) = ([0u8; 15], [0u8; 7]);
        let (r1, r2) = tokio::join!(
            s1.read_exact(&mut b1),
            tokio::time::timeout(Duration::from_secs(10), s2.read_exact(&mut b2)),
        );
        r1.unwrap();
        r2.expect("udp echo 2 timed out").unwrap();
        assert_eq!(&b1, b"udp-session-one");
        assert_eq!(&b2, b"udp-two");
    }

    #[tokio::test]
    async fn port_range_dials_hit_both_range_ports() {
        // A "begin-end" range expands to per-port endpoints
        // (FlatPortBindings); every underlay dial picks one at random
        // (mux.go:670). Over 40 dials across a two-port range both
        // listeners must see traffic (P(one side starved) < 2^-39).
        let mut cfg = mux_cfg(0, MieruTransport::Tcp);
        // Find two adjacent free ports so the range covers exactly the
        // two listeners.
        let (p1, p2) = {
            let mut found = None;
            for _ in 0..1000 {
                let a = TcpListener::bind(("127.0.0.1", 0)).await.unwrap();
                let pa = a.local_addr().unwrap().port();
                if pa != u16::MAX
                    && TcpListener::bind(("127.0.0.1", pa + 1)).await.is_ok()
                {
                    found = Some((pa, pa + 1));
                    break;
                }
            }
            found.expect("two adjacent free loopback ports")
        };
        let (lo, hi) = (p1, p2);
        let (p1, conns1, _m1) = spawn_multi_tcp_mimic_on(&cfg, lo).await;
        let (p2, conns2, _m2) = spawn_multi_tcp_mimic_on(&cfg, hi).await;
        assert_eq!((p1, p2), (lo, hi));
        cfg.port_range = Some((lo, hi));
        assert_eq!(cfg.endpoint_ports(), vec![lo, hi]);
        let mux = MieruMux::new(&cfg, Multiplexing::Off).unwrap();
        let target = NetAddr::domain("range.example", 443).unwrap();
        for _ in 0..40 {
            tokio::time::timeout(Duration::from_secs(20), mux.connect(&target))
                .await
                .expect("dial timed out")
                .expect("dial failed");
        }
        assert!(conns1.load(Ordering::Relaxed) >= 1, "port {lo} never dialed");
        assert!(conns2.load(Ordering::Relaxed) >= 1, "port {hi} never dialed");
        assert_eq!(
            conns1.load(Ordering::Relaxed) + conns2.load(Ordering::Relaxed),
            40
        );
    }
}
