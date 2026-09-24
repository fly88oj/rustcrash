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
//! the **TCP transport with multiplexing off** — the default profile mihomo
//! builds for `transport: TCP` (a fresh underlay plus one session per dial,
//! `Mux.DialContext` with `multiplexFactor = 0`). Deferred, with the
//! upstream file that owns them:
//!
//! * **UDP (packet) transport** (`underlay_packet.go`): stateless
//!   per-datagram framing plus retransmission, ACK scheduling and CUBIC
//!   windowing (`session.go runOutputOncePacket`, `congestion/`).
//! * **Multiplexing** (`mux.go maybePickExistingUnderlay`): reusing one
//!   underlay for several sessions.
//! * **Port ranges** (`PortBindings`), handshake-mode `no-wait`
//!   (`apis/internal/early_conn.go`), and **traffic patterns** — nonce
//!   rewriting, TCP fragmentation, low-entropy payload encoding
//!   (`trafficpattern`, `low_entropy.go`).
//! * Heartbeats: sent only from the packet output loop
//!   (`sessionHeartbeatInterval` is unused by `runOutputOnceStream`).
//!
//! The wire this module produces is pinned by an in-test mimic of the mieru
//! stream server, which re-implements server-side discovery/decrypt
//! (`StreamUnderlay.readOneSegment` +
//! `serverInitRecvBlockCipherAndDecryptMetadata`) straight from upstream.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::{Buf, BytesMut};
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::{Key, XChaCha20Poly1305, XNonce};
use rand::RngCore;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
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

// protocolType values (pkg/protocol/metadata.go).
const OPEN_SESSION_REQUEST: u8 = 2;
const OPEN_SESSION_RESPONSE: u8 = 3;
const CLOSE_SESSION_REQUEST: u8 = 4;
const CLOSE_SESSION_RESPONSE: u8 = 5;
const DATA_CLIENT_TO_SERVER: u8 = 6;
const DATA_SERVER_TO_CLIENT: u8 = 7;
const ACK_SERVER_TO_CLIENT: u8 = 9;

/// SOCKS5 constants (apis/constant/socks5.go).
const SOCKS5_VERSION: u8 = 5;
const SOCKS5_CONNECT_CMD: u8 = 1;

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
}

/// `sessionStruct.Unmarshal` / `dataAckStruct.Unmarshal` field extraction
/// (timestamp window and payload caps enforced as upstream does). The two
/// structs disagree on where the length fields live after byte 14 —
/// `sessionStruct`: status 14, payload len 15..17, suffix len 17;
/// `dataAckStruct`: prefix len 21, payload len 22..24, suffix len 24.
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
    let is_session = matches!(b[0], OPEN_SESSION_REQUEST | OPEN_SESSION_RESPONSE);
    let (payload_len, suffix_len, prefix_len) = if is_session {
        (
            u16::from_be_bytes([b[15], b[16]]),
            b[17],
            0u8,
        )
    } else {
        (
            u16::from_be_bytes([b[22], b[23]]),
            b[24],
            b[21],
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
        let is_session = matches!(
            meta.protocol,
            OPEN_SESSION_REQUEST | OPEN_SESSION_RESPONSE | CLOSE_SESSION_REQUEST | CLOSE_SESSION_RESPONSE
        );
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

/// Dial `cfg` and tunnel a SOCKS5 connect request for `target` through a
/// fresh mieru session (mihomo `Mieru.DialContext` → client `DialContext` →
/// `PostDialHandshake`). Returns the established byte stream.
pub async fn connect(cfg: &MieruOut, target: &NetAddr) -> Result<BoxProxyStream> {
    if cfg.username.is_empty() || cfg.password.is_empty() {
        return Err(Error::config("mieru: username and password are required"));
    }
    if cfg.transport != MieruTransport::Tcp {
        return Err(Error::config(
            "mieru: only the TCP transport is implemented (UDP requires the packet underlay: \
             retransmission, ACK scheduling and CUBIC windowing — underlay_packet.go)",
        ));
    }

    let tcp = tokio::net::TcpStream::connect((cfg.server.as_str(), cfg.port))
        .await
        .map_err(|e| Error::network(format!("mieru: dial {}:{}: {e}", cfg.server, cfg.port)))?;
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

    // PostDialHandshake: SOCKS5 connect request over the session.
    let mut req = Vec::with_capacity(64);
    req.extend_from_slice(&[SOCKS5_VERSION, SOCKS5_CONNECT_CMD, 0x00]);
    encode_socks_addr(&mut req, &target.host, target.port);
    stream.write_all(&req).await?;
    stream.flush().await?;

    // model.Response.ReadFromSocks5: [ver, reply, 0x00] then a bind address.
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

    if !stream.established {
        // The reply always arrives in (or after) the open session response.
        return Err(Error::protocol(
            "mieru: socks5 reply without an open session response",
        ));
    }
    debug!(target: "engine", session = session_id, "mieru: session established");
    Ok(Box::new(stream))
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
                        // The piggybacked bytes are the SOCKS5 request.
                        assert!(inbound.starts_with(&[SOCKS5_VERSION, SOCKS5_CONNECT_CMD, 0x00]));
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
    async fn udp_transport_reports_deferral() {
        let cfg = MieruOut {
            transport: MieruTransport::Udp,
            ..test_cfg()
        };
        let err = match connect(&cfg, &NetAddr::domain("x.test", 1).unwrap()).await {
            Ok(_) => panic!("UDP transport must report its deferral"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("underlay_packet.go"), "{err}");
        assert_eq!(MieruTransport::parse("TCP").unwrap(), MieruTransport::Tcp);
        assert_eq!(MieruTransport::parse("UDP").unwrap(), MieruTransport::Udp);
        assert!(MieruTransport::parse("tcp").is_err());
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
