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
//! the **TCP and UDP transports with multiplexing off** — the default
//! profile mihomo builds (a fresh underlay plus one session per dial,
//! `Mux.DialContext` with `multiplexFactor = 0`). Deferred, with the
//! upstream file that owns them:
//!
//! * **Multiplexing** (`mux.go maybePickExistingUnderlay`): reusing one
//!   underlay for several sessions.
//! * **Port ranges** (`PortBindings`; mihomo's `port-range` option), which
//!   belong to the dialer: upstream picks a random endpoint port per
//!   underlay from the configured range (`mux.go newUnderlay` →
//!   `mrand.Intn(len(m.endpoints))`). The config carries a single port.
//! * Handshake-mode `no-wait` (`apis/internal/early_conn.go`) and
//!   **traffic patterns** — nonce rewriting, TCP fragmentation,
//!   low-entropy payload encoding (`trafficpattern`, `low_entropy.go`).
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
/// client exercises: server, port, username, password, transport.
#[derive(Debug, Clone)]
pub struct MieruOut {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub transport: MieruTransport,
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
    /// `Ok(false)` = more bytes needed. The metadata is decrypted exactly
    /// once (each decrypt advances the nonce counter).
    fn parse_segment(&mut self) -> Result<bool> {
        if self.pending_meta.is_none() {
            let overhead = TAG_SIZE + usize::from(self.first_read) * NONCE_SIZE;
            if self.rbuf.len() < METADATA_LENGTH + overhead {
                return Ok(false);
            }
            let enc = self.rbuf.split_to(METADATA_LENGTH + overhead).to_vec();
            let plain = self.recv.decrypt(&enc)?;
            self.first_read = false;
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
            self.pending_meta = Some(meta);
            self.prefix_done = false;
        }
        let meta = self.pending_meta.unwrap();
        let is_session = is_session_protocol(meta.protocol);
        if !is_session && !self.prefix_done {
            if self.rbuf.len() < meta.prefix_len as usize {
                return Ok(false);
            }
            self.rbuf.advance(meta.prefix_len as usize);
            self.prefix_done = true;
        }
        if meta.payload_len > 0 {
            let want = meta.payload_len as usize + TAG_SIZE;
            if self.rbuf.len() < want {
                return Ok(false);
            }
            let enc = self.rbuf.split_to(want).to_vec();
            let payload = self.recv.decrypt(&enc)?;
            self.out.extend_from_slice(&payload);
        }
        if meta.suffix_len > 0 {
            if self.rbuf.len() < meta.suffix_len as usize {
                return Ok(false);
            }
            self.rbuf.advance(meta.suffix_len as usize);
        }
        self.pending_meta = None;

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
            OPEN_SESSION_REQUEST | DATA_CLIENT_TO_SERVER => {
                return Err(Error::protocol(format!(
                    "mieru: unexpected inbound protocol {}",
                    meta.protocol
                )))
            }
            _ => unreachable!("protocols validated above"),
        }
        Ok(true)
    }
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

/// The packet-transport session engine — a faithful single-session port of
/// `PacketUnderlay` (client half) + `Session`'s packet loops, exposed to
/// the application as a byte-stream pipe (`tokio::io::duplex`), so the
/// SOCKS5 handshake and `MieruUdp` framing above are transport-agnostic.
struct PacketEngine {
    sock: UdpSocket,
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
}

enum EngineEvent {
    App(Option<usize>),
    Dgram(usize),
    SockErr,
    Timer,
}

impl PacketEngine {
    fn new(
        sock: UdpSocket,
        key: &[u8; KEY_LEN],
        username: &str,
        session_id: u32,
        app: DuplexStream,
    ) -> Self {
        let now = Instant::now();
        PacketEngine {
            sock,
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
                let PacketEngine { app, sock, .. } = &mut self;
                tokio::select! {
                    n = app.read(&mut rbuf), if poll_app => {
                        EngineEvent::App(match n {
                            Ok(0) => None,
                            Ok(n) => Some(n),
                            Err(_) => None,
                        })
                    }
                    n = sock.recv(&mut dgram) => match n {
                        Ok(n) => EngineEvent::Dgram(n),
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
                if self.sock.send(&wire).await.is_ok() {
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
        self.sock.send(&wire).await.map_err(|e| {
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
    /// session is dropped (single-session scope).
    async fn on_datagram(&mut self, dgram: &[u8]) {
        self.last_rx = Instant::now();
        if dgram.len() < PACKET_NON_HEADER_POSITION {
            return;
        }
        let meta_ct = &dgram[..PACKET_NON_HEADER_POSITION];
        let meta_plain = match self.cipher.decrypt(meta_ct) {
            Ok(p) => p,
            Err(_) => return, // not ours (or corrupted): silently drop
        };
        let meta = match parse_metadata(&meta_plain) {
            Ok(m) => m,
            Err(_) => return,
        };
        if meta.session_id != self.session_id {
            return;
        }
        let nonce: [u8; NONCE_SIZE] = dgram[..NONCE_SIZE].try_into().expect("nonce prefix");
        let rest = &dgram[PACKET_NON_HEADER_POSITION..];
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
                    match self.cipher.decrypt_with_nonce(&nonce, &rest[..want]) {
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
                    let _ = self.sock.send(&wire).await;
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
    let sock = UdpSocket::bind(("0.0.0.0", 0))
        .await
        .map_err(|e| Error::network(format!("mieru: bind udp underlay: {e}")))?;
    sock.connect((cfg.server.as_str(), cfg.port))
        .await
        .map_err(|e| {
            Error::network(format!(
                "mieru: udp underlay connect {}:{}: {e}",
                cfg.server, cfg.port
            ))
        })?;
    debug!(
        target: "engine",
        server = %cfg.server, port = cfg.port,
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
        PacketEngine::new(sock, &key, &username, session_id, engine_side)
            .run()
            .await;
    });
    Ok(app)
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
            let tcp = tokio::net::TcpStream::connect((cfg.server.as_str(), cfg.port))
                .await
                .map_err(|e| {
                    Error::network(format!("mieru: dial {}:{}: {e}", cfg.server, cfg.port))
                })?;
            debug!(
                target: "engine",
                server = %cfg.server, port = cfg.port, target = %target,
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
            username: format!("user-{:016x}", rand::random::<u64>()),
            password: format!("pw-{:016x}", rand::random::<u64>()),
            transport: MieruTransport::Tcp,
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
            username: format!("user-{:016x}", rand::random::<u64>()),
            password: format!("pw-{:016x}", rand::random::<u64>()),
            transport: MieruTransport::Udp,
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
}
