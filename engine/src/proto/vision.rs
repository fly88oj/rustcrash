//! XTLS Vision (`xtls-rprx-vision`): the client-side framing layer that
//! carries the *inner* TLS session inside the outer VLESS/TLS tunnel.
//!
//! This is a port of the client half of Xray's Vision, cross-checked against
//! mihomo's `transport/vless/vision` (the implementation users' Clash configs
//! actually run) and sing-box's `sing-vmess/vless/vision.go`. Every rule below
//! is cited to the upstream source it was taken from.
//!
//! # What Vision does, on the wire
//!
//! 1. The vless request header carries the flow addon. Xray
//!    `proxy/vless/vless.go:11` defines `XRV = "xtls-rprx-vision"`; the
//!    addons are a protobuf `Addons{ Flow = 1 }` marshalled by
//!    `proxy/vless/encoding/addons.go:17-36`, i.e. the bytes on the wire are
//!    `0a 10 "xtls-rprx-vision"` (18 bytes), preceded by their length `0x12`.
//!    [`vision_request_addons`] returns that whole field.
//!
//! 2. After the request header the client sends *frames* while the inner TLS
//!    handshake is in flight (Xray `XtlsPadding`, `proxy/proxy.go`):
//!
//!    ```text
//!    [ uuid 16 bytes , first frame of the connection only ]
//!    command         1 byte   00 continue / 01 end / 02 direct
//!    contentLen      2 bytes  big endian
//!    paddingLen      2 bytes  big endian
//!    content         contentLen bytes  (inner-TLS record bytes)
//!    padding         paddingLen zero bytes
//!    ```
//!
//!    The 21-byte header (`16 + 1 + 2 + 2`) is `PaddingHeaderLen` in mihomo
//!    (`transport/vless/vision/padding.go:16`); Xray hardcodes the same 21.
//!
//! 3. Padding arithmetic (`XtlsPadding`, v1.8.24 `proxy/proxy.go:282-317`,
//!    v25.9.11 `:425-461`, main `:425-457`; sing-vmess `vless/vision.go:293-303`):
//!
//!    ```text
//!    paddingLen = rand(500) + 900 - contentLen   if contentLen < 900 && longPadding
//!               = rand(256)                     otherwise
//!    paddingLen = min(paddingLen, 8192 - 21 - contentLen)
//!    ```
//!
//!    `longPadding` is `trafficState.IsTLS` (set once the inner ClientHello is
//!    seen) except for the app-data transition frame, where upstream passes a
//!    literal `true` (`proxy/proxy.go:370` v25.9.11 / `:373` main).
//!
//! 4. The padding phase ends at the first piece whose content starts with a
//!    TLS application-data record header, `17 03 03` (`TlsApplicationDataStart`,
//!    main `proxy/proxy.go:41`; mihomo `vision/filter.go:14`); that frame is
//!    sent with command `01` (end) and everything after it is passed through
//!    raw. Upstream sends command `02` (direct) instead when the inner session
//!    negotiated TLS 1.3 (`EnableXtls`, main `:654`, v25.9.11 `:583`), because
//!    both peers then *splice*: the outer TLS layer is abandoned and the inner
//!    records travel raw on the TCP connection (see the direct section below
//!    for the exact upstream mechanics). There is a second, earlier exit for
//!    "earlier vision receiver" compatibility (`proxy/proxy.go:373` v25.9.11):
//!    if no TLS was detected at all and the filter budget is about to run out,
//!    padding ends early with command `01`.
//!
//! 5. The server -> client direction uses exactly the same frame format
//!    (Xray's `TrafficState` and the padding code are direction-agnostic: the
//!    inbound builds `NewTrafficState(userSentID)`, `proxy/vless/inbound/inbound.go:612`,
//!    and uses the same `XtlsPadding`/`XtlsUnpadding`). The client verifies the
//!    16-byte UUID that prefixes the server's first frame; Xray (all versions,
//!    `XtlsUnpadding` initial state, v25.9.11 `proxy/proxy.go:480-483`) simply
//!    treats a non-matching downlink as unframed/raw, while mihomo
//!    (`vision/conn.go:123-130`) errors out. This port takes Xray's behaviour
//!    (raw fallback) and logs a warning.
//!
//! # TLS version scope: TLS 1.3, outer and inner
//!
//! * Outer: upstream *hard-errors* when the outer TLS version is not 1.3
//!   (`proxy/vless/outbound/outbound.go:356-364`, inbound `:573`). Vision is
//!   used with TLS/REALITY, and REALITY is TLS 1.3 only, so this port assumes
//!   the outer stream handed to [`VisionConn::connect`] is a TLS 1.3 session
//!   (this crate's [`crate::proto::reality::tls13`] layer). A `BoxProxyStream`
//!   cannot report its version, so the requirement is documented rather than
//!   enforced.
//! * Inner: the inner session may be TLS 1.2 or 1.3; the version only drives
//!   the padding decisions above.
//!
//! # What the Xray client really does on a server command `02` (direct)
//!
//! It does not merely stop unpadding. The client's downlink is
//! `VisionReader.ReadMultiBuffer` (Xray `proxy/proxy.go`; line numbers below
//! are main as fetched 2026-09 — the branch drifts, the functions do not):
//!
//! * `:246-247` frame command `1`: `*withinPaddingBuffers = false` —
//!   unpadding stops and everything after the frame passes through raw (what
//!   this port has always done for `01`);
//! * `:248-250` frame command `2`: the same, plus `*switchToDirectCopy = true`
//!   (the client's `Outbound.DownlinkReaderDirectCopy`);
//! * `:259-270` still inside that same read, the outer TLS session's
//!   already-decrypted-but-unread buffer (`input`) and its socket read-ahead
//!   (`rawInput`) are drained and appended after the frame's content, so not
//!   one byte is lost at the boundary;
//! * `:280-282` the reader is then *re-bound to the raw transport*:
//!   `UnwrapRawConn` strips the `tls.Conn`/`UConn`/`reality` wrapper and
//!   `w.Reader = buf.NewReader(readerConn)` reads the bare TCP/UDS socket.
//!   From that point the server writes the inner TLS records raw on the
//!   transport, inside no outer TLS record at all (and `:228-233`: once the
//!   switch has fired, later reads return early — no more unpadding, no more
//!   TLS filtering).
//!
//! The uplink is *not* touched by the received `02`: the writer keeps padding
//! until its own transition. `VisionWriter.WriteMultiBuffer` swaps the writer
//! to the raw conn (`:334-347`) only when `Outbound.UplinkWriterDirectCopy`
//! was set by the writer's own decision (`:364-374`, which is what sends
//! command `02` on the wire). The two buffers the reader drains are stolen
//! from the outer TLS object with `reflect` + `unsafe` in the client wiring
//! (`proxy/vless/outbound/outbound.go`, `t.FieldByName("input")` /
//! `("rawInput")` + `unsafe.Pointer`, :285-288 as fetched 2026-09) — in Go
//! this reaches two private fields of `crypto/tls.Conn`. mihomo
//! (`transport/vless/vision/vision.go:87-95`, `:142-175`, `:230-233`) and
//! sing-vmess (`vless/vision.go:88-89`, `:152-167`, `:236-255`) do the same
//! with the same reflection.
//!
//! # What this port implements: the framing half of `02`, exactly
//!
//! * downlink: the `02` frame's content is delivered, its padding skipped,
//!   everything after the frame passes through verbatim (the same visible
//!   bytes as `01`); mirroring upstream's early return (`:228-233`),
//!   passthrough bytes are no longer fed to the TLS filter once direct was
//!   announced. [`VisionConn::direct_mode`] reports the announcement.
//! * uplink: unchanged by the received `02` (upstream's writer flag is
//!   independent). Our own app-data transition still sends command `01`, and
//!   writes after it go out unframed through the outer stream.
//!
//! # Why full splice equivalence is out of reach from this layer
//!
//! The *transport* half of `02` — abandoning the outer TLS records — cannot
//! be expressed here. [`VisionConn`] is handed a [`BoxProxyStream`] (the
//! outbound wiring stacks `VlessStream` over `reality::tls13::Tls13Stream`
//! or utls). A splice would need (a) the raw transport under that outer TLS
//! session, (b) its decrypted-unread plaintext (upstream `input`; our
//! `Tls13Stream` keeps it in a private `plain` buffer) and its read-ahead
//! (upstream `rawInput`; `Tls13Stream::rec`), and (c) the right to stop
//! outer-TLS-encrypting writes. The type-erased box exposes none of that,
//! and no API on the outer layers hands those parts back through the box
//! chain. So, stated rather than faked:
//!
//! * a peer that sends `02` but keeps carrying the post-frame bytes inside
//!   the outer TLS records (framing-level direct, like the loopback server
//!   in the tests) is followed correctly, byte for byte, both directions;
//! * a peer that sends `02` and then writes the inner records raw on the
//!   transport (a current Xray server, whenever the inner session negotiates
//!   TLS 1.3) cannot be followed by this layer: the raw inner records reach
//!   our outer TLS reader, which fails on its own — the failure surfaces
//!   from the transport, not from misparsed framing. A `warn!` log and
//!   [`VisionConn::direct_mode`] make the announced switch observable;
//! * this port never *sends* `02`: it would promise a raw uplink we cannot
//!   provide, and a splicing peer would then read our outer-TLS records as
//!   raw inner bytes.
//!
//! Uplink interop unchanged: vision over this port works with peers that stay
//! in padding-end mode end to end — inner TLS 1.2 sessions, non-splicing
//! `xtls-rprx-vision` peers, framing-level-direct peers, and the loopback
//! servers in this module's tests.
//!
//! # Integration sequence
//!
//! See [`VisionConn::connect`].

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use rand::Rng;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::addr::NetAddr;
use crate::error::{Error, Result};
use crate::stream::BoxProxyStream;

// ------------------------------------------------------------- wire constants

/// The vless `flow` value for Vision (Xray `XRV`, `proxy/vless/vless.go:11`).
pub const FLOW_XTLS_RPRX_VISION: &str = "xtls-rprx-vision";

/// Frame command: keep padding (`CommandPaddingContinue`, Xray `proxy/proxy.go:54`).
pub const COMMAND_CONTINUE: u8 = 0x00;
/// Frame command: this is the last padded frame (Xray `proxy/proxy.go:55`).
pub const COMMAND_END: u8 = 0x01;
/// Frame command: switch to direct copy / splice (Xray `proxy/proxy.go:56`).
pub const COMMAND_DIRECT: u8 = 0x02;

/// Bytes of a frame header: uuid(16) + command(1) + contentLen(2) + paddingLen(2).
/// mihomo `transport/vless/vision/padding.go:16` (`PaddingHeaderLen`).
pub const PADDING_HEADER_LEN: usize = 21;

/// Xray's buffer size (`buf.Size`); mihomo `vision/padding.go:47`
/// (`xrayBufSize = 8192`). All padding/reshape arithmetic is bounded by it.
pub const XRAY_CHUNK_SIZE: usize = 8192;

/// Largest content one frame may carry: `buf.Size - PaddingHeaderLen`
/// (mihomo `vision/padding.go:50`, Xray `ReshapeMultiBuffer`).
pub const FRAME_CONTENT_LIMIT: usize = XRAY_CHUNK_SIZE - PADDING_HEADER_LEN;

/// Padding seeds. Xray main takes them from the account (`testseed`) and
/// defaults to `{900, 500, 900, 256}` (`proxy/proxy.go:303-305`); every
/// version from v1.8.24 through v25.9.11 hardcodes the same numbers inside
/// `XtlsPadding`.
pub const PADDING_SEED_CONTENT: usize = 900;
pub const PADDING_SEED_JITTER: usize = 500;
pub const PADDING_SEED_SHORT: usize = 256;

/// `TlsApplicationDataStart` (Xray `proxy/proxy.go:41`, mihomo `vision/filter.go:14`).
const TLS_APPLICATION_DATA: [u8; 3] = [0x17, 0x03, 0x03];
/// `TlsServerHandShakeStart` (Xray `proxy/proxy.go:39`, mihomo `vision/filter.go:13`).
const TLS_SERVER_HANDSHAKE: [u8; 3] = [0x16, 0x03, 0x03];
/// `TlsClientHandShakeStart` (Xray `proxy/proxy.go:38`, mihomo `vision/filter.go:12`).
const TLS_CLIENT_HANDSHAKE: [u8; 2] = [0x16, 0x03];
/// `Tls13SupportedVersions` = extension `supported_versions` offering 0x0304
/// (Xray `proxy/proxy.go:37`, mihomo `vision/filter.go:11`).
const TLS13_SUPPORTED_VERSIONS: [u8; 6] = [0x00, 0x2b, 0x00, 0x02, 0x03, 0x04];
/// `TlsHandshakeTypeClientHello` (Xray `proxy/proxy.go:52`).
const HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
/// `TlsHandshakeTypeServerHello` (Xray `proxy/proxy.go:53`).
const HANDSHAKE_SERVER_HELLO: u8 = 0x02;
/// The only TLS 1.3 suite upstream refuses to splice with
/// (`TLS_AES_128_CCM_8_SHA256`, Xray `proxy/proxy.go:46`).
const TLS13_CIPHER_CCM8: u16 = 0x1305;

// ------------------------------------------------------------------ addons

/// The vless header addons for Vision: protobuf `Addons { Flow = 1 }`
/// (field 1, string) with `xtls-rprx-vision`.
///
/// Xray `proxy/vless/encoding/addons.go:17-36` marshals exactly this
/// (there is no field-2 seed in the request here), 18 bytes total.
pub fn vision_addons_protobuf() -> [u8; 18] {
    let mut out = [0u8; 18];
    out[0] = 0x0a; // field 1, wire type 2 (length-delimited)
    out[1] = FLOW_XTLS_RPRX_VISION.len() as u8; // 0x10 = 16
    out[2..].copy_from_slice(FLOW_XTLS_RPRX_VISION.as_bytes());
    out
}

/// The complete vless "addons" header field: length byte `0x12` followed by
/// the protobuf message. Write this where the in-tree
/// [`crate::proto::vless::VlessStream::handshake`] currently writes a single
/// `0x00` addons-length byte (the wiring is the integrator's job).
pub fn vision_request_addons() -> [u8; 19] {
    let mut out = [0u8; 19];
    out[0] = 18;
    out[1..].copy_from_slice(&vision_addons_protobuf());
    out
}

// ------------------------------------------------------- TLS record helpers

/// `true` when `prefix` is the start of a TLS application-data record.
///
/// Port of the upstream test `b.Len() >= 6 && bytes.Equal(TlsApplicationDataStart,
/// b.BytesTo(3))` (Xray `proxy/proxy.go:364` main / `:356` v25.9.11; mihomo
/// `vision/conn.go:210`, sing-vmess `vision.go:239`).
pub fn is_application_data(prefix: &[u8]) -> bool {
    prefix.len() >= 6 && prefix[..3] == TLS_APPLICATION_DATA
}

/// Port of Xray main's `IsCompleteRecord` (`proxy/proxy.go:407-455`): the byte
/// string is a whole number of complete `17 03 03 <len>` records, nothing else.
///
/// Upstream main gates the TLS-1.3 -> direct switch on this (to decide that the
/// record it is about to hand to the splice path is complete); the classic
/// clients (v1.8.24..v25.9.11, mihomo, sing-box) do not check it at all.
pub fn is_complete_record(data: &[u8]) -> bool {
    let mut header_len: usize = 5;
    let mut record_len: usize = 0;
    let mut i = 0usize;
    while i < data.len() {
        if header_len > 0 {
            let byte = data[i];
            i += 1;
            match header_len {
                5 => {
                    if byte != 0x17 {
                        return false;
                    }
                }
                4 | 3 => {
                    if byte != 0x03 {
                        return false;
                    }
                }
                2 => record_len = usize::from(byte) << 8,
                1 => record_len |= usize::from(byte),
                _ => unreachable!("record header state"),
            }
            header_len -= 1;
        } else if record_len > 0 {
            let remaining = data.len() - i;
            if remaining < record_len {
                return false;
            }
            i += record_len;
            record_len = 0;
            header_len = 5;
        } else {
            return false;
        }
    }
    header_len == 5 && record_len == 0
}

/// Port of `XtlsPadding`'s length arithmetic with the jitter injected, so it
/// can be asserted byte-exactly in tests. Upstream draws `jitter` uniformly
/// from `0..500` (long) or `0..256` (short) and clamps to
/// `buf.Size - 21 - contentLen`.
pub fn padding_len_from(content_len: usize, long_padding: bool, jitter: usize) -> usize {
    let padding = if content_len < PADDING_SEED_CONTENT && long_padding {
        jitter + PADDING_SEED_CONTENT - content_len
    } else {
        jitter
    };
    padding.min(FRAME_CONTENT_LIMIT.saturating_sub(content_len))
}

/// [`padding_len_from`] with the upstream random draw applied.
pub fn padding_len(content_len: usize, long_padding: bool, rng: &mut impl Rng) -> usize {
    if content_len < PADDING_SEED_CONTENT && long_padding {
        let jitter = rng.gen_range(0..PADDING_SEED_JITTER);
        padding_len_from(content_len, long_padding, jitter)
    } else {
        let jitter = rng.gen_range(0..PADDING_SEED_SHORT);
        padding_len_from(content_len, long_padding, jitter)
    }
}

/// Build one frame exactly as `XtlsPadding` does
/// (Xray v1.8.24 `proxy/proxy.go:282-317` = v25.9.11 `:425-461` = main `:425-457`;
/// mihomo `vision/padding.go:23-45`; sing-vmess `vision.go:325-355`).
///
/// `first_uuid` is the connection's 16-byte VLESS UUID and must be `Some`
/// exactly once per direction — upstream writes it into the first frame only
/// (`writeOnceUserUUID`).
pub fn frame(
    command: FrameCommand,
    content: &[u8],
    padding_len: usize,
    first_uuid: Option<&[u8; 16]>,
) -> Vec<u8> {
    debug_assert!(
        padding_len <= FRAME_CONTENT_LIMIT.saturating_sub(content.len()),
        "vision: frame exceeds the upstream 8192-byte buffer"
    );
    let mut out = Vec::with_capacity(
        content.len() + padding_len + PADDING_HEADER_LEN + if first_uuid.is_some() { 16 } else { 0 },
    );
    if let Some(uuid) = first_uuid {
        out.extend_from_slice(uuid);
    }
    out.push(command.byte());
    out.extend_from_slice(&(content.len() as u16).to_be_bytes());
    out.extend_from_slice(&(padding_len as u16).to_be_bytes());
    out.extend_from_slice(content);
    out.resize(out.len() + padding_len, 0);
    out
}

/// Port of `ReshapeMultiBuffer`'s split points (Xray main `proxy/proxy.go:457-490` /
/// v25.9.11 `:387-415` / v1.8.24 `:247-279`; mihomo `vision/padding.go:49-65`):
/// buffers of `8192 - 21` bytes or more are cut at the *last* `17 03 03` inside
/// `[21, 8192-21]`, or at 4096 when there is none in range.
pub fn reshape(buf: &[u8]) -> Vec<&[u8]> {
    if buf.len() < FRAME_CONTENT_LIMIT {
        return vec![buf];
    }
    let mut pieces = Vec::new();
    let mut rest = buf;
    while rest.len() >= FRAME_CONTENT_LIMIT {
        let cut = match last_index_of(rest, &TLS_APPLICATION_DATA) {
            Some(i) if (21..=FRAME_CONTENT_LIMIT).contains(&i) => i,
            _ => XRAY_CHUNK_SIZE / 2,
        };
        pieces.push(&rest[..cut]);
        rest = &rest[cut..];
    }
    pieces.push(rest);
    pieces
}

fn last_index_of(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || haystack.len() < needle.len() {
        return None;
    }
    (0..=haystack.len() - needle.len())
        .rev()
        .find(|&i| &haystack[i..i + needle.len()] == needle)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    needle.len() <= haystack.len() && haystack.windows(needle.len()).any(|w| w == needle)
}

// ------------------------------------------------------------------ commands

/// A vision frame command byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameCommand {
    /// `0x00`: padding continues.
    Continue,
    /// `0x01`: last padded frame, raw passthrough follows.
    End,
    /// `0x02`: direct — last padded frame, raw passthrough follows, and the
    /// peer announces that *it* stops framing too (upstream additionally
    /// abandons the outer TLS records entirely; this port implements the
    /// framing half — see the module docs' direct section).
    Direct,
}

impl FrameCommand {
    /// The wire byte (Xray `proxy/proxy.go:54-56`).
    pub fn byte(self) -> u8 {
        match self {
            FrameCommand::Continue => COMMAND_CONTINUE,
            FrameCommand::End => COMMAND_END,
            FrameCommand::Direct => COMMAND_DIRECT,
        }
    }

    /// Parse a wire byte.
    pub fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            COMMAND_CONTINUE => Some(FrameCommand::Continue),
            COMMAND_END => Some(FrameCommand::End),
            COMMAND_DIRECT => Some(FrameCommand::Direct),
            _ => None,
        }
    }
}

// -------------------------------------------------------------- TLS filter

/// The inner-TLS detector shared by both directions, ported from `XtlsFilterTls`
/// (Xray v25.9.11 `proxy/proxy.go:548-...`, main `:...`; mihomo
/// `transport/vless/vision/filter.go:29-93`; sing-vmess `vless/vision.go:257-323`).
///
/// Upstream keeps one such state per connection (`TrafficState`): the uplink
/// ClientHello and the downlink ServerHello both feed it, and it is consulted
/// for the padding decisions. `NumberOfPacketToFilter` starts at 8
/// (`proxy/proxy.go:145` main / `:144` v25.9.11) and is decremented once per
/// buffer, not per byte.
#[derive(Debug, Clone)]
pub struct TlsFilter {
    packets_to_filter: u32,
    is_tls: bool,
    is_tls12_or_above: bool,
    cipher: u16,
    remaining_server_hello: i32,
    enable_xtls: bool,
}

impl Default for TlsFilter {
    fn default() -> Self {
        TlsFilter::new()
    }
}

impl TlsFilter {
    /// Fresh state, `NumberOfPacketToFilter = 8`.
    pub fn new() -> Self {
        TlsFilter {
            packets_to_filter: 8,
            is_tls: false,
            is_tls12_or_above: false,
            cipher: 0,
            remaining_server_hello: -1,
            enable_xtls: false,
        }
    }

    /// Feed one buffer of inner-session bytes (either direction).
    pub fn observe(&mut self, buf: &[u8]) {
        if self.packets_to_filter == 0 {
            return;
        }
        self.packets_to_filter -= 1;
        if buf.len() >= 6 {
            if buf[..3] == TLS_SERVER_HANDSHAKE && buf[5] == HANDSHAKE_SERVER_HELLO {
                self.remaining_server_hello =
                    ((i32::from(buf[3])) << 8 | i32::from(buf[4])) + 5;
                self.is_tls12_or_above = true;
                self.is_tls = true;
                // The session id length sits after record(5) + handshake header(4)
                // + legacy_version(2) + random(32) = offset 43; the cipher suite
                // follows it (Xray `proxy/proxy.go:577-585` v25.9.11).
                if buf.len() >= 79 && self.remaining_server_hello >= 79 {
                    let session_id_len = usize::from(buf[43]);
                    let cipher_off = 43 + session_id_len + 1;
                    if cipher_off + 2 <= buf.len() {
                        self.cipher = u16::from_be_bytes([buf[cipher_off], buf[cipher_off + 1]]);
                    }
                } else {
                    tracing::debug!("engine: vision: short server hello, tls 1.2 or older?");
                }
            } else if buf[..2] == TLS_CLIENT_HANDSHAKE && buf[5] == HANDSHAKE_CLIENT_HELLO {
                self.is_tls = true;
                tracing::debug!("engine: vision: found tls client hello");
            }
        }
        if self.remaining_server_hello > 0 {
            // Upstream subtracts the *whole* buffer length, not the clamped
            // `end`, so the counter goes negative at the record's end.
            let end = (self.remaining_server_hello as usize).min(buf.len());
            let len = buf.len() as i32;
            self.remaining_server_hello -= len;
            if contains(&buf[..end], &TLS13_SUPPORTED_VERSIONS) {
                // TLS 1.3 ClientHello echoed in the ServerHello.
                if is_tls13_cipher(self.cipher) && self.cipher != TLS13_CIPHER_CCM8 {
                    self.enable_xtls = true;
                }
                self.packets_to_filter = 0;
                return;
            } else if self.remaining_server_hello <= 0 {
                tracing::debug!("engine: vision: found tls 1.2");
                self.packets_to_filter = 0;
                return;
            }
            tracing::debug!("engine: vision: inconclusive server hello");
        }
    }

    /// `trafficState.IsTLS`: any handshake record seen in the inner session.
    pub fn is_tls(&self) -> bool {
        self.is_tls
    }

    /// `trafficState.IsTLS12orAbove`: a ServerHello was seen.
    pub fn is_tls12_or_above(&self) -> bool {
        self.is_tls12_or_above
    }

    /// `trafficState.EnableXtls`: the inner session is TLS 1.3 with a suite
    /// upstream is willing to splice with. This port logs it but does not
    /// splice (see the module docs).
    pub fn inner_tls13(&self) -> bool {
        self.enable_xtls
    }

    /// Negotiated inner cipher suite as read out of the ServerHello.
    pub fn cipher(&self) -> u16 {
        self.cipher
    }

    /// Remaining detector budget (`NumberOfPacketToFilter`).
    pub fn packets_to_filter(&self) -> u32 {
        self.packets_to_filter
    }
}

fn is_tls13_cipher(cipher: u16) -> bool {
    // Xray's `Tls13CipherSuiteDic` (proxy/proxy.go:43-49): 0x1301..=0x1305.
    (0x1301..=0x1305).contains(&cipher)
}

/// The command that ends the padding phase for this piece of content, if any.
///
/// Port of the two transition branches in `VisionWriter.WriteMultiBuffer`
/// (Xray main `proxy/proxy.go:364-374`, v25.9.11 `:356-368`, v1.8.24 `:212-231`;
/// mihomo `vision/conn.go:210-220`):
///
/// * inner TLS and the piece starts with `17 03 03` -> `End` (upstream would
///   send `Direct` when `EnableXtls`; see the module docs for why this port
///   cannot);
/// * no ServerHello was ever seen and the filter budget is down to its last
///   packet -> `End` ("for compatibility with earlier vision receiver").
pub fn transition_command(
    filter: &TlsFilter,
    content: &[u8],
    require_complete_records: bool,
) -> Option<FrameCommand> {
    // Inner TLS, first application-data record.
    let app_data_end = filter.is_tls()
        && is_application_data(content)
        && (!require_complete_records || is_complete_record(content));
    // "For compatibility with earlier vision receiver, we finish padding 1
    // packet early" (`proxy/proxy.go:373` v25.9.11 / `:377` main).
    let early_end = !filter.is_tls12_or_above() && filter.packets_to_filter() <= 1;
    (app_data_end || early_end).then_some(FrameCommand::End)
}

// ------------------------------------------------------------------ config

/// Vision client knobs.
#[derive(Debug, Clone, Default)]
pub struct VisionConfig {
    /// Send upstream's empty "hide the vless header" frame right away.
    ///
    /// Upstream sends this only when the first payload is more than 500 ms
    /// late (`proxy/vless/outbound/outbound.go:343`, "Insert padding with empty
    /// content to camouflage VLESS header"); when the first payload arrives in
    /// time it is folded into that payload's own frame (mihomo/sing-box do the
    /// latter, always). Default `false`.
    pub initial_padding: bool,
    /// Require a *complete* application-data record (`is_complete_record`)
    /// before ending padding. Upstream main added this together with the
    /// TLS 1.3 direct switch (`proxy/proxy.go:360-364`); the classic clients do
    /// not check it. Default `false` (classic behaviour).
    pub require_complete_records: bool,
}

impl VisionConfig {
    /// Default configuration (no eager padding, classic transition rule).
    pub fn new() -> Self {
        Self::default()
    }
}

// ------------------------------------------------------------- VisionConn

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ReadPhase {
    /// Fewer than 21 downlink bytes seen: framed or unframed is still unknown.
    Init,
    /// Consuming a 5-byte command/contentLen/paddingLen header.
    Header,
    /// Forwarding `remaining_content` bytes to the caller.
    Content,
    /// Discarding `remaining_padding` bytes.
    Padding,
    /// The server did not prefix its frames with our UUID: raw passthrough.
    Unframed,
    /// Padding ended (command `01`): raw passthrough.
    Raw,
    /// Direct (command `02`): raw passthrough too, but — mirroring upstream's
    /// reader, which returns early once the direct switch has fired (Xray
    /// `proxy/proxy.go:228-233`, main 2026-09) — the bytes are no longer fed
    /// to the TLS filter.
    RawDirect,
}

impl ReadPhase {
    fn after_block(command: u8) -> ReadPhase {
        match command {
            COMMAND_CONTINUE => ReadPhase::Header,
            // `*currentCommand == 1` -> `*withinPaddingBuffers = false`
            // (Xray `proxy/proxy.go:246-247`, main 2026-09).
            COMMAND_END => ReadPhase::Raw,
            // `*currentCommand == 2` -> padding over AND the direct switch
            // fired (`proxy/proxy.go:248-250`). The visible passthrough is
            // identical to `01`; upstream then also re-binds its reader to
            // the raw transport (`:280-282`), which this layer cannot do —
            // see the module docs' direct section.
            COMMAND_DIRECT => ReadPhase::RawDirect,
            _ => unreachable!("vision: after_block on a non-terminal command"),
        }
    }
}

/// Client-side Vision connection: an [`AsyncRead`]/[`AsyncWrite`] byte carrier
/// for the inner TLS session.
///
/// Wire rules and limitations: see the module documentation. Both directions
/// of the outer VLESS/TLS stream are in exactly one state machine (like
/// upstream's `TrafficState`); reads and writes may be driven concurrently.
pub struct VisionConn {
    outer: BoxProxyStream,
    target: Option<NetAddr>,
    uuid: [u8; 16],
    cfg: VisionConfig,
    /// Shared inner-TLS detector (upstream's `TrafficState`).
    filter: TlsFilter,

    // uplink
    /// `trafficState.IsPadding`: still framing.
    padding: bool,
    /// `writeOnceUserUUID`: consumed by the first frame of the connection.
    once_uuid: Option<[u8; 16]>,
    /// Framed/queued bytes on their way to `outer`.
    pending: Vec<u8>,

    // downlink
    in_buf: Vec<u8>,
    phase: ReadPhase,
    remaining_content: usize,
    remaining_padding: usize,
    current_command: u8,
    /// The server announced direct copy: a frame with command `02` was
    /// parsed and the downlink switched to unframed passthrough (upstream's
    /// `Outbound.DownlinkReaderDirectCopy`).
    direct_received: bool,
    eof: bool,
}

impl std::fmt::Debug for VisionConn {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VisionConn")
            .field("target", &self.target)
            .field("padding", &self.padding)
            .field("phase", &self.phase)
            .field("direct", &self.direct_received)
            .field("inner_tls13", &self.filter.inner_tls13())
            .finish_non_exhaustive()
    }
}

impl VisionConn {
    /// Wrap an outer stream (post-VLESS-handshake) in the Vision framing.
    ///
    /// # Integration sequence (what the outbound wiring must do)
    ///
    /// ```text
    /// 1. transport = dial(server)                       // BoxProxyStream
    /// 2. outer     = tls / reality handshake over it    // TLS 1.3 (see module docs)
    /// 3. vless request header, WITH the flow addons:
    ///        version(0) || uuid(16) || vision_request_addons() (19 bytes) || cmd || port+addr
    ///    — i.e. the flow replaces the single 0x00 addons-length byte the
    ///      in-tree VlessStream::handshake writes today (that file is the
    ///      integrator's to change).
    /// 4. let conn = VisionConn::connect(outer, &target, uuid, cfg).await?;
    /// 5. run the inner session over `conn`, e.g.
    ///        let inner = tokio_rustls::TlsConnector::from(cfg).connect(name, conn).await?;
    ///    or `crate::proto::reality::tls13::connect(Box::new(conn), ..)`;
    /// 6. proxy application bytes over `inner`.
    /// ```
    ///
    /// Step 3 must happen before step 4 in wall-clock terms, but the in-tree
    /// `VlessStream` writes its header lazily on the first write, so wrapping
    /// it here is fine: the header bytes (already including the flow addons)
    /// go out before the first Vision frame, which is exactly the server's
    /// expectation.
    ///
    /// `target` is recorded for logging only — Vision adds nothing to the
    /// wire for it, the vless request header already carried the destination.
    /// `uuid` is the VLESS account UUID: upstream uses its 16 bytes as the
    /// per-connection padding UUID in both directions
    /// (`NewTrafficState(account.ID.Bytes())`, `proxy/vless/outbound/outbound.go:316`;
    /// server side `proxy/vless/inbound/inbound.go:612`).
    pub async fn connect(
        outer: BoxProxyStream,
        target: &NetAddr,
        uuid: uuid::Uuid,
        cfg: VisionConfig,
    ) -> Result<Self> {
        tracing::debug!(
            dst = %target,
            "engine: vision: framing {} (uplink padding-end; a server direct \
             command is followed as unframed passthrough)",
            FLOW_XTLS_RPRX_VISION
        );
        let mut conn = VisionConn {
            outer,
            target: Some(target.clone()),
            uuid: *uuid.as_bytes(),
            cfg,
            filter: TlsFilter::new(),
            padding: true,
            once_uuid: Some(*uuid.as_bytes()),
            pending: Vec::new(),
            in_buf: Vec::new(),
            phase: ReadPhase::Init,
            remaining_content: 0,
            remaining_padding: 0,
            current_command: COMMAND_CONTINUE,
            direct_received: false,
            eof: false,
        };
        if conn.cfg.initial_padding {
            conn.hide_vless_header().await?;
        }
        Ok(conn)
    }

    /// The destination this connection was created for (informational).
    pub fn target(&self) -> Option<&NetAddr> {
        self.target.as_ref()
    }

    /// The per-connection padding UUID (the VLESS account UUID).
    pub fn uuid(&self) -> [u8; 16] {
        self.uuid
    }

    /// Whether the padding phase is still active on the uplink.
    pub fn padding_active(&self) -> bool {
        self.padding
    }

    /// Whether the server announced XTLS direct copy: a downlink frame with
    /// command `02` (`Direct`) was parsed.
    ///
    /// What "direct" means in *this* layering — upstream's client, on
    /// receiving `02`, stops unpadding **and** abandons the outer TLS
    /// records, draining the outer session's decrypted-unread and read-ahead
    /// buffers and re-binding its reader to the raw transport (Xray
    /// `proxy/proxy.go:248-250`, `:259-283`, main 2026-09). A
    /// [`BoxProxyStream`] cannot reach under the outer TLS session, so this
    /// port implements the framing half only: the `02` frame's content is
    /// delivered, its padding skipped, every later byte passes through
    /// verbatim, and the uplink is untouched (its own transition still sends
    /// `01`). The byte stream is therefore exactly correct with peers that
    /// keep the outer TLS records after announcing direct; with peers that
    /// splice the transport (a real Xray server on inner TLS 1.3), the raw
    /// inner records that follow hit our outer TLS reader and the failure
    /// surfaces there — observable here via this flag and a `warn!` log, not
    /// silently faked. See the module docs' direct section for the full
    /// analysis.
    pub fn direct_mode(&self) -> bool {
        self.direct_received
    }

    /// Whether the inner session was detected as TLS 1.3 (upstream's
    /// `EnableXtls`). When this is `true`, upstream clients would switch to
    /// XTLS direct copy; this port keeps padding-end mode and logs a warning.
    pub fn inner_tls13_detected(&self) -> bool {
        self.filter.inner_tls13()
    }

    /// The shared inner-TLS detector (inspection/tests).
    pub fn filter(&self) -> &TlsFilter {
        &self.filter
    }

    /// Send upstream's empty first frame: UUID + `00 0000 <paddingLen>` + zero
    /// padding, with the long padding rule (`XtlsPadding(nil, CommandPaddingContinue,
    /// &uuid, true)`, Xray `proxy/proxy.go:358` main / `:350` v25.9.11; mihomo
    /// `vision/conn.go:199`).
    ///
    /// Upstream uses it to hide the VLESS header when the first payload is
    /// late; call it before any other write. Returns an error if the first
    /// frame has already gone out.
    pub async fn hide_vless_header(&mut self) -> Result<()> {
        if !self.padding {
            return Err(Error::protocol(
                "vision: hide_vless_header called after the padding phase ended",
            ));
        }
        let uuid = self.once_uuid.take().ok_or_else(|| {
            Error::protocol("vision: hide_vless_header called after the first frame was sent")
        })?;
        let pad = padding_len(0, true, &mut rand::thread_rng());
        self.pending
            .extend_from_slice(&frame(FrameCommand::Continue, &[], pad, Some(&uuid)));
        self.flush().await.map_err(Error::from)
    }

    /// The uplink decision for one piece of content: the command to use and
    /// the `longPadding` flag, mirroring upstream's branch structure.
    fn decide(&self, content: &[u8]) -> (FrameCommand, bool) {
        match transition_command(&self.filter, content, self.cfg.require_complete_records) {
            Some(command) => {
                // Upstream passes a literal `true` for long padding here
                // (proxy/proxy.go:370 v25.9.11 / :373 main).
                (command, true)
            }
            None => (FrameCommand::Continue, self.filter.is_tls()),
        }
    }

    /// Frame `data` into `self.pending` (padding phase only).
    fn frame_into_pending(&mut self, data: &[u8]) {
        self.filter.observe(data);
        for piece in reshape(data) {
            if !self.padding {
                // Upstream leaves the rest of this multi-buffer unpadded once
                // the padding phase ended inside it.
                self.pending.extend_from_slice(piece);
                continue;
            }
            let (command, long_padding) = self.decide(piece);
            let pad = padding_len(piece.len(), long_padding, &mut rand::thread_rng());
            let uuid = self.once_uuid.take();
            self.pending
                .extend_from_slice(&frame(command, piece, pad, uuid.as_ref()));
            if command != FrameCommand::Continue {
                self.padding = false;
                if self.filter.inner_tls13() {
                    tracing::warn!(
                        "engine: vision: inner TLS 1.3 detected; upstream would splice \
                         (command 02) but this port stays double-TLS (command 01)"
                    );
                }
            }
        }
    }

    /// Push queued bytes into `outer` until it blocks.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.pending.is_empty() {
            let n = ready!(Pin::new(&mut self.outer).poll_write(cx, &self.pending))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "vision: transport accepted zero bytes",
                )));
            }
            self.pending.drain(..n);
        }
        Poll::Ready(Ok(()))
    }

    fn poll_read_inner(&mut self, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.phase {
                ReadPhase::Init => {
                    // Upstream only classifies the downlink once it holds 21
                    // bytes and the first 16 match the UUID (`XtlsUnpadding`
                    // initial state, `proxy/proxy.go:480-483`); anything else is
                    // passed through raw. This port decides as soon as it holds
                    // the 16-byte prefix, so an unframed peer is never made to
                    // wait: a framed peer's first 16 bytes are the UUID and a
                    // frame is written whole, so waiting for the 5-byte header
                    // is safe exactly then.
                    if self.in_buf.len() >= 16 {
                        if self.in_buf[..16] == self.uuid {
                            if self.in_buf.len() >= PADDING_HEADER_LEN {
                                self.in_buf.drain(..16);
                                self.phase = ReadPhase::Header;
                                continue;
                            }
                        } else {
                            tracing::warn!(
                                "engine: vision: server downlink is not frame-prefixed with our \
                                 UUID; passing it through unframed (Xray behaviour)"
                            );
                            self.phase = ReadPhase::Unframed;
                            continue;
                        }
                    }
                }
                ReadPhase::Header => {
                    if self.in_buf.len() >= 5 {
                        let command = self.in_buf[0];
                        let content_len =
                            usize::from(u16::from_be_bytes([self.in_buf[1], self.in_buf[2]]));
                        let padding_len =
                            usize::from(u16::from_be_bytes([self.in_buf[3], self.in_buf[4]]));
                        self.in_buf.drain(..5);
                        let Some(command) = FrameCommand::from_byte(command) else {
                            return Poll::Ready(Err(io::Error::new(
                                io::ErrorKind::InvalidData,
                                format!("vision: server sent unknown command {command}"),
                            )));
                        };
                        if command == FrameCommand::Direct {
                            // Server command `02`. Upstream's downlink reader
                            // (VisionReader.ReadMultiBuffer, Xray proxy/proxy.go
                            // :248-250, main 2026-09) sets `withinPaddingBuffers
                            // = false` plus the direct flag, then (in the same
                            // read) drains the outer TLS session's
                            // decrypted-unread `input` and read-ahead
                            // `rawInput` and re-binds its reader to the raw
                            // transport (:259-283). The re-bind is unreachable
                            // through the BoxProxyStream (see the module docs);
                            // the framing half is exact: this frame's content
                            // is delivered, its padding skipped, and everything
                            // after the frame passes through verbatim.
                            self.direct_received = true;
                            tracing::warn!(
                                "engine: vision: server announced XTLS direct copy (command 02); \
                                 framing stopped, passthrough rides the outer stream — this port \
                                 cannot splice the transport (see the module docs)"
                            );
                        }
                        self.current_command = command.byte();
                        self.remaining_content = content_len;
                        self.remaining_padding = padding_len;
                        self.phase = if content_len > 0 {
                            ReadPhase::Content
                        } else if padding_len > 0 {
                            ReadPhase::Padding
                        } else {
                            ReadPhase::after_block(self.current_command)
                        };
                        tracing::debug!(
                            "engine: vision: downlink frame command={} content={} padding={}",
                            self.current_command,
                            content_len,
                            padding_len
                        );
                        continue;
                    }
                }
                ReadPhase::Content => {
                    if !self.in_buf.is_empty() {
                        let n = self
                            .in_buf
                            .len()
                            .min(self.remaining_content)
                            .min(buf.remaining());
                        if n == 0 {
                            return Poll::Ready(Ok(()));
                        }
                        let chunk: Vec<u8> = self.in_buf.drain(..n).collect();
                        self.filter.observe(&chunk);
                        buf.put_slice(&chunk);
                        self.remaining_content -= n;
                        if self.remaining_content == 0 {
                            self.phase = if self.remaining_padding > 0 {
                                ReadPhase::Padding
                            } else {
                                ReadPhase::after_block(self.current_command)
                            };
                        }
                        return Poll::Ready(Ok(()));
                    }
                }
                ReadPhase::Padding => {
                    if !self.in_buf.is_empty() {
                        let n = self.in_buf.len().min(self.remaining_padding);
                        self.in_buf.drain(..n);
                        self.remaining_padding -= n;
                        if self.remaining_padding == 0 {
                            self.phase = ReadPhase::after_block(self.current_command);
                        }
                        continue;
                    }
                }
                ReadPhase::Unframed | ReadPhase::Raw | ReadPhase::RawDirect => {
                    if !self.in_buf.is_empty() {
                        let n = self.in_buf.len().min(buf.remaining());
                        let chunk: Vec<u8> = self.in_buf.drain(..n).collect();
                        if self.phase != ReadPhase::RawDirect {
                            // Upstream keeps filtering while the packet budget
                            // lasts even after padding-end (`withinPaddingBuffers
                            // == false` still runs XtlsFilterTls through the
                            // `|| NumberOfPacketToFilter > 0` gate), but returns
                            // early — no filtering — once the direct switch has
                            // fired (proxy/proxy.go:228-233).
                            self.filter.observe(&chunk);
                        }
                        buf.put_slice(&chunk);
                        return Poll::Ready(Ok(()));
                    }
                    return Pin::new(&mut self.outer).poll_read(cx, buf);
                }
            }
            // The current phase needs more bytes from the transport.
            if self.eof {
                return Poll::Ready(match self.phase {
                    ReadPhase::Init => {
                        if self.in_buf.is_empty() {
                            Ok(())
                        } else {
                            self.phase = ReadPhase::Unframed;
                            continue;
                        }
                    }
                    ReadPhase::Unframed | ReadPhase::Raw | ReadPhase::RawDirect => Ok(()),
                    _ => Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "vision: truncated padded downlink",
                    )),
                });
            }
            ready!(self.poll_fill(cx))?;
        }
    }

    /// Read one chunk from `outer` into `in_buf`.
    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut tmp = [0u8; XRAY_CHUNK_SIZE];
        let n = {
            let mut rb = ReadBuf::new(&mut tmp);
            ready!(Pin::new(&mut self.outer).poll_read(cx, &mut rb))?;
            rb.filled().len()
        };
        if n == 0 {
            self.eof = true;
        } else {
            self.in_buf.extend_from_slice(&tmp[..n]);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for VisionConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.get_mut().poll_read_inner(cx, buf)
    }
}

impl AsyncWrite for VisionConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        data: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        // Bytes queued earlier always go first; the waker is registered by the
        // attempt, and `poll_flush` retries exhaustively.
        let _ = this.poll_drain(cx);
        if !this.padding && this.pending.is_empty() {
            // Padding phase over: upstream writes the buffer through untouched
            // (only the direct/splice mode introduces another layer here).
            return Pin::new(&mut this.outer).poll_write(cx, data);
        }
        if data.is_empty() {
            return Poll::Ready(Ok(0));
        }
        if this.padding {
            this.frame_into_pending(data);
        } else {
            this.pending.extend_from_slice(data);
        }
        let _ = this.poll_drain(cx);
        Poll::Ready(Ok(data.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.outer).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.outer).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use tokio::io::{AsyncReadExt, DuplexStream};

    fn uuid_bytes() -> [u8; 16] {
        *uuid::Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811")
            .unwrap()
            .as_bytes()
    }

    // ------------------------------------------------------- pure decisions

    /// Upstream's command bytes: Xray `proxy/proxy.go:54-56`, mihomo
    /// `vision/padding.go:18-20`.
    #[test]
    fn command_bytes_match_upstream() {
        assert_eq!(COMMAND_CONTINUE, 0x00);
        assert_eq!(COMMAND_END, 0x01);
        assert_eq!(COMMAND_DIRECT, 0x02);
        assert_eq!(FrameCommand::Continue.byte(), 0x00);
        assert_eq!(FrameCommand::End.byte(), 0x01);
        assert_eq!(FrameCommand::Direct.byte(), 0x02);
        assert_eq!(FrameCommand::from_byte(0x00), Some(FrameCommand::Continue));
        assert_eq!(FrameCommand::from_byte(0x01), Some(FrameCommand::End));
        assert_eq!(FrameCommand::from_byte(0x02), Some(FrameCommand::Direct));
        assert_eq!(FrameCommand::from_byte(0x03), None);
    }

    /// The addons field: protobuf `0a 10 "xtls-rprx-vision"`, length-prefixed
    /// (`proxy/vless/encoding/addons.go:17-36`; XRV at `proxy/vless/vless.go:11`).
    #[test]
    fn addons_bytes_match_upstream() {
        assert_eq!(FLOW_XTLS_RPRX_VISION, "xtls-rprx-vision");
        assert_eq!(FLOW_XTLS_RPRX_VISION.len(), 16);
        let protobuf = vision_addons_protobuf();
        assert_eq!(protobuf.len(), 18);
        assert_eq!(&protobuf[..2], &[0x0a, 0x10]);
        assert_eq!(&protobuf[2..], b"xtls-rprx-vision");
        let field = vision_request_addons();
        assert_eq!(field.len(), 19);
        assert_eq!(field[0], 0x12); // 18 bytes of addons follow
        assert_eq!(&field[1..], &protobuf);
    }

    /// `XtlsPadding`'s arithmetic, byte-exact with the jitter pinned
    /// (`proxy/proxy.go:431-448` v25.9.11; sing-vmess `vision.go:293-303`).
    #[test]
    fn padding_arithmetic_matches_upstream() {
        // Long padding: rand(500) + 900 - contentLen.
        assert_eq!(padding_len_from(300, true, 42), 42 + 900 - 300);
        assert_eq!(padding_len_from(0, true, 499), 1399);
        assert_eq!(padding_len_from(899, true, 0), 1);
        // 900 bytes or more: short padding even when longPadding is set.
        assert_eq!(padding_len_from(900, true, 255), 255);
        assert_eq!(padding_len_from(900, false, 255), 255);
        assert_eq!(padding_len_from(100, false, 255), 255);
        // Clamp: paddingLen = min(paddingLen, 8192 - 21 - contentLen).
        assert_eq!(padding_len_from(8100, false, 255), FRAME_CONTENT_LIMIT - 8100);
        assert_eq!(padding_len_from(8171, false, 255), 0);
        assert_eq!(padding_len_from(9000, false, 255), 0, "saturating clamp");
        assert_eq!(FRAME_CONTENT_LIMIT, 8171);
    }

    /// The random draw stays inside upstream's ranges over many samples.
    #[test]
    fn padding_lengths_stay_in_upstream_ranges() {
        let mut rng = rand::thread_rng();
        for _ in 0..2000 {
            let long = padding_len(300, true, &mut rng);
            let total = 300 + long;
            assert!((900..1400).contains(&total), "long padding total {total}");
            let short = padding_len(300, false, &mut rng);
            assert!(short < 256, "short padding {short}");
            let big = padding_len(4000, true, &mut rng);
            assert!(big < 256, "records >= 900 bytes get rand(256): {big}");
        }
    }

    /// Frame layout: `[uuid] command contentLen paddingLen content zeros`
    /// (`XtlsPadding`, all versions; mihomo `padding.go:23-45`).
    #[test]
    fn frame_bytes_are_exact() {
        let uuid = uuid_bytes();
        // First frame of the connection: UUID prefix, content 0, long padding.
        let f = frame(FrameCommand::Continue, &[], 900, Some(&uuid));
        assert_eq!(f.len(), 16 + 5 + 900);
        assert_eq!(&f[..16], &uuid);
        assert_eq!(f[16], COMMAND_CONTINUE);
        assert_eq!(&f[17..21], &[0x00, 0x00, 0x03, 0x84]); // content 0, padding 900
        assert!(f[21..].iter().all(|b| *b == 0));
        // Later frame: no UUID.
        let f = frame(FrameCommand::End, b"abc", 2, None);
        assert_eq!(
            f,
            vec![COMMAND_END, 0x00, 0x03, 0x00, 0x02, b'a', b'b', b'c', 0, 0]
        );
        // contentLen is big-endian and 16-bit saturated at the buffer limit.
        let content = vec![0x5a; FRAME_CONTENT_LIMIT];
        let f = frame(FrameCommand::Continue, &content, 0, None);
        assert_eq!(&f[..5], &[COMMAND_CONTINUE, 0x1f, 0xeb, 0x00, 0x00]);
        assert_eq!(f.len(), 5 + FRAME_CONTENT_LIMIT);
    }

    /// Record classification: `17 03 03` application data needs 6 bytes
    /// (upstream `b.Len() >= 6 && BytesTo(3)`), and `IsCompleteRecord` is a
    /// whole number of complete `17 03 03` records (`proxy/proxy.go:407-455`).
    #[test]
    fn record_classification_matches_upstream() {
        assert!(is_application_data(&[0x17, 0x03, 0x03, 0x00, 0x05, 0x00]));
        assert!(!is_application_data(&[0x17, 0x03, 0x03, 0x00, 0x05]), "short");
        assert!(!is_application_data(&[0x16, 0x03, 0x03, 0x00, 0x05, 0x01]));
        assert!(!is_application_data(&[0x17, 0x03, 0x04, 0x00, 0x05, 0x00]));

        let one = [0x17, 0x03, 0x03, 0x00, 0x03, 1, 2, 3];
        assert!(is_complete_record(&one));
        assert!(is_complete_record(&[]), "empty input is vacuously complete");
        assert!(!is_complete_record(&one[..7]), "truncated payload");
        assert!(!is_complete_record(&one[..5]), "truncated header");
        assert!(!is_complete_record(&[0x16, 0x03, 0x03, 0x00, 0x03, 1, 2, 3]));
        let two = [one.as_slice(), one.as_slice()].concat();
        assert!(is_complete_record(&two));
        let trailing = [one.as_slice(), &[0x17, 0x03, 0x03, 0x00, 0x03, 1, 2]].concat();
        assert!(!is_complete_record(&trailing), "trailing partial record");
    }

    /// `ReshapeMultiBuffer`: split at the last `17 03 03` in `[21, 8171]`,
    /// else at 4096 (`proxy/proxy.go:403-410` v25.9.11).
    #[test]
    fn reshape_cuts_where_upstream_cuts() {
        assert_eq!(reshape(&[0u8; 100]).len(), 1);
        let mut big = vec![0u8; XRAY_CHUNK_SIZE + 841];
        big[5000..5003].copy_from_slice(&TLS_APPLICATION_DATA);
        let pieces = reshape(&big);
        assert_eq!(pieces.len(), 2);
        assert_eq!(pieces[0].len(), 5000);
        assert_eq!(pieces[1].len(), big.len() - 5000);
        // No marker in range: 4096-byte cuts (`buf.Size / 2`).
        let two_buffers = vec![0u8; 2 * XRAY_CHUNK_SIZE];
        let pieces = reshape(&two_buffers);
        assert_eq!(pieces.len(), 4);
        assert!(pieces.iter().all(|p| p.len() == 4096));
        // A marker before offset 21 is ignored.
        let mut low = vec![0u8; XRAY_CHUNK_SIZE + 1];
        low[3..6].copy_from_slice(&TLS_APPLICATION_DATA);
        assert_eq!(reshape(&low)[0].len(), 4096);
    }

    /// A synthetic TLS 1.3 ServerHello (record header + handshake header +
    /// legacy_version + random + session id + cipher + extensions).
    fn server_hello(cipher: u16, with_supported_versions: bool) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // legacy_version
        body.extend_from_slice(&[0xaa; 32]); // random
        body.push(32); // session id length (offset 43 in the record)
        body.extend_from_slice(&[0xbb; 32]);
        body.extend_from_slice(&cipher.to_be_bytes());
        body.push(0); // compression
        let mut ext = Vec::new();
        if with_supported_versions {
            // supported_versions: 0x002b, len 2, TLS 1.3 (0x0304).
            ext.extend_from_slice(&TLS13_SUPPORTED_VERSIONS);
        } else {
            // A TLS 1.2-only extension list.
            ext.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
        }
        body.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext);
        let mut record = Vec::new();
        record.extend_from_slice(&TLS_SERVER_HANDSHAKE);
        record.extend_from_slice(&((body.len() + 4) as u16).to_be_bytes());
        record.push(HANDSHAKE_SERVER_HELLO);
        record.extend_from_slice(&[0x00, 0x00, (body.len()) as u8]); // 3-byte length
        record.extend_from_slice(&body);
        record
    }

    /// Port of `XtlsFilterTls` (`proxy/proxy.go:548-...` v25.9.11;
    /// mihomo `vision/filter.go:29-93`; sing-vmess `vision.go:257-323`).
    #[test]
    fn filter_detects_inner_tls13() {
        let hello = server_hello(0x1301, true);
        assert!(hello.len() >= 79, "the cipher path needs >= 79 bytes");
        let mut filter = TlsFilter::new();
        filter.observe(&hello);
        assert!(filter.is_tls());
        assert!(filter.is_tls12_or_above());
        assert!(filter.inner_tls13());
        assert_eq!(filter.cipher(), 0x1301);
        assert_eq!(filter.packets_to_filter(), 0);

        // Without the supported_versions extension: TLS 1.2, no splice.
        let mut filter = TlsFilter::new();
        filter.observe(&server_hello(0xc02f, false));
        assert!(filter.is_tls12_or_above());
        assert!(!filter.inner_tls13());

        // TLS_AES_128_CCM_8_SHA256 is the one suite upstream refuses to splice.
        let mut filter = TlsFilter::new();
        filter.observe(&server_hello(TLS13_CIPHER_CCM8, true));
        assert!(!filter.inner_tls13());

        // The ServerHello split across two buffers: as long as the split leaves
        // >= 79 bytes in the first buffer, both the cipher (read once, from the
        // record start) and the supported_versions extension are recognised.
        let hello = server_hello(0x1303, true);
        let mut filter = TlsFilter::new();
        filter.observe(&hello[..80]);
        assert_eq!(filter.cipher(), 0x1303);
        assert!(!filter.inner_tls13());
        filter.observe(&hello[80..]);
        assert!(filter.inner_tls13());
        assert_eq!(filter.cipher(), 0x1303);

        // Split earlier than 79 bytes: upstream never gets to read the cipher
        // (`b.Len() >= 79` guard), so even though the TLS 1.3 extension is
        // found later, EnableXtls stays false. Ported as-is.
        let mut filter = TlsFilter::new();
        filter.observe(&hello[..40]);
        filter.observe(&hello[40..]);
        assert!(filter.is_tls12_or_above());
        assert!(!filter.inner_tls13());
        assert_eq!(filter.packets_to_filter(), 0);

        // A ClientHello only sets IsTLS.
        let mut client_hello = Vec::new();
        client_hello.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x40, HANDSHAKE_CLIENT_HELLO]);
        client_hello.resize(6 + 0x40, 0);
        let mut filter = TlsFilter::new();
        filter.observe(&client_hello);
        assert!(filter.is_tls());
        assert!(!filter.is_tls12_or_above());
        assert!(!filter.inner_tls13());
    }

    /// The padding-end rule (`VisionWriter.WriteMultiBuffer`, main
    /// `proxy/proxy.go:364-374` / v25.9.11 `:356-368`).
    #[test]
    fn transition_command_matches_upstream() {
        let mut filter = TlsFilter::new();
        let mut client_hello = Vec::new();
        client_hello.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x10, HANDSHAKE_CLIENT_HELLO]);
        client_hello.resize(6 + 0x10, 0);
        filter.observe(&client_hello);
        assert!(filter.is_tls());
        // Inside the handshake: no transition.
        assert_eq!(transition_command(&filter, &client_hello, false), None);
        // First application-data record: End. (`17 03 03 00 05` + 5 payload
        // bytes = one complete record.)
        let app = [TLS_APPLICATION_DATA.as_slice(), &[0, 5, 1, 2, 3, 4, 5]].concat();
        assert_eq!(
            transition_command(&filter, &app, false),
            Some(FrameCommand::End)
        );
        // With the main-branch completeness rule, a partial record does not
        // end the padding phase.
        assert_eq!(transition_command(&filter, &app[..6], true), None);
        assert_eq!(
            transition_command(&filter, &app, true),
            Some(FrameCommand::End)
        );

        // Non-TLS payload: the early exit fires once the filter budget reaches
        // its last packet (`NumberOfPacketToFilter <= 1`, i.e. the 7th buffer
        // of the 8-packet budget).
        let mut filter = TlsFilter::new();
        for _ in 0..6 {
            filter.observe(b"plain bytes");
        }
        assert_eq!(filter.packets_to_filter(), 2);
        assert_eq!(transition_command(&filter, b"plain bytes", false), None);
        filter.observe(b"plain bytes");
        assert_eq!(filter.packets_to_filter(), 1);
        assert_eq!(
            transition_command(&filter, b"plain bytes", false),
            Some(FrameCommand::End),
            "the early exit fires on the last filter packet"
        );
    }

    // --------------------------------------------------- loopback harness

    /// Wire-level observations the mimic records for assertions.
    #[derive(Default)]
    struct ServerStats {
        frames: AtomicUsize,
        commands: Mutex<Vec<u8>>,
        first_frame_has_uuid: AtomicBool,
        unframed_bytes: AtomicUsize,
    }

    /// Test-only vision server: the server half of the ported rules.
    ///
    /// Deliberately a separate, compact implementation (own frame parser and
    /// builder driven by the upstream constants) so it cross-checks the client
    /// instead of reusing its state machine. `splice` stands in for upstream's
    /// `EnableXtls` decision on the server (which Xray derives from watching the
    /// inner ServerHello): when set, the first application-data frame is sent
    /// with command `02` and what follows is written raw.
    struct VisionServer {
        io: DuplexStream,
        uuid: [u8; 16],
        splice: bool,
        stats: Arc<ServerStats>,
        in_buf: Vec<u8>,
        content_left: usize,
        padding_left: usize,
        /// 0 = not in a frame header, else header bytes still owed.
        header_left: usize,
        command: u8,
        framed: bool,
        raw_read: bool,
        padding: bool,
        sent_uuid: bool,
        out: Vec<u8>,
        /// Content that did not fit the caller's buffer last time.
        carry: Vec<u8>,
    }

    impl VisionServer {
        fn new(io: DuplexStream, uuid: [u8; 16], splice: bool, stats: Arc<ServerStats>) -> Self {
            VisionServer {
                io,
                uuid,
                splice,
                stats,
                in_buf: Vec::new(),
                content_left: 0,
                padding_left: 0,
                header_left: 0,
                command: COMMAND_CONTINUE,
                framed: false,
                raw_read: false,
                padding: true,
                sent_uuid: false,
                out: Vec::new(),
                carry: Vec::new(),
            }
        }

        /// Unpad whatever is buffered; returns the inner-TLS bytes.
        fn take_content(&mut self) -> Vec<u8> {
            let mut out = Vec::new();
            loop {
                if self.content_left > 0 {
                    let n = self.in_buf.len().min(self.content_left);
                    out.extend(self.in_buf.drain(..n));
                    self.content_left -= n;
                    if self.content_left > 0 {
                        break;
                    }
                }
                if self.padding_left > 0 {
                    let n = self.in_buf.len().min(self.padding_left);
                    self.in_buf.drain(..n);
                    self.padding_left -= n;
                    if self.padding_left > 0 {
                        break;
                    }
                }
                if self.header_left > 0 {
                    while self.header_left > 0 && !self.in_buf.is_empty() {
                        let byte = self.in_buf.remove(0);
                        match self.header_left {
                            5 => self.command = byte,
                            4 => self.content_left = usize::from(byte) << 8,
                            3 => self.content_left |= usize::from(byte),
                            2 => self.padding_left = usize::from(byte) << 8,
                            1 => {
                                self.padding_left |= usize::from(byte);
                                self.stats
                                    .commands
                                    .lock()
                                    .unwrap()
                                    .push(self.command);
                                self.stats.frames.fetch_add(1, Ordering::Relaxed);
                                if self.command != COMMAND_CONTINUE {
                                    self.padding = false;
                                }
                            }
                            _ => {}
                        }
                        self.header_left -= 1;
                    }
                    if self.header_left > 0 {
                        break;
                    }
                }
                if self.content_left > 0 || self.padding_left > 0 {
                    continue;
                }
                if !self.framed {
                    if self.in_buf.len() < PADDING_HEADER_LEN {
                        break;
                    }
                    if self.in_buf[..16] != self.uuid {
                        // Not a framed peer: everything is raw.
                        self.raw_read = true;
                        self.stats
                            .unframed_bytes
                            .fetch_add(self.in_buf.len(), Ordering::Relaxed);
                        out.append(&mut self.in_buf);
                        break;
                    }
                    let first_is_uuid = self.stats.frames.load(Ordering::Relaxed) == 0;
                    self.in_buf.drain(..16);
                    self.stats
                        .first_frame_has_uuid
                        .store(first_is_uuid, Ordering::Relaxed);
                    self.framed = true;
                }
                if self.raw_read {
                    out.append(&mut self.in_buf);
                    break;
                }
                if self.command == COMMAND_END {
                    // Padding over on the uplink: the rest is raw.
                    self.raw_read = true;
                    out.append(&mut self.in_buf);
                    break;
                }
                if self.in_buf.len() < 5 {
                    break;
                }
                self.header_left = 5;
            }
            if !out.is_empty() {
                return out;
            }
            if self.raw_read {
                out.append(&mut self.in_buf);
            }
            out
        }

        /// Frame the downlink bytes exactly like upstream's server does.
        fn push_framed(&mut self, data: &[u8]) {
            let (command, long_padding) = if !self.padding {
                (FrameCommand::Continue, false)
            } else if is_application_data(data) {
                let command = if self.splice {
                    FrameCommand::Direct
                } else {
                    FrameCommand::End
                };
                (command, true)
            } else {
                (FrameCommand::Continue, true)
            };
            let pad = padding_len(data.len(), long_padding, &mut rand::thread_rng());
            let uuid = if self.sent_uuid { None } else { Some(self.uuid) };
            self.out
                .extend_from_slice(&frame(command, data, pad, uuid.as_ref()));
            if uuid.is_some() {
                self.sent_uuid = true;
            }
            if command != FrameCommand::Continue {
                self.padding = false;
                if command == FrameCommand::Direct {
                    // Upstream switches its writer to the raw transport here.
                    self.stats
                        .commands
                        .lock()
                        .unwrap()
                        .push(COMMAND_DIRECT);
                }
            }
        }
    }

    impl AsyncRead for VisionServer {
        fn poll_read(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            if this.raw_read {
                return Pin::new(&mut this.io).poll_read(cx, buf);
            }
            if !this.carry.is_empty() {
                let n = this.carry.len().min(buf.remaining());
                buf.put_slice(&this.carry[..n]);
                this.carry.drain(..n);
                return Poll::Ready(Ok(()));
            }
            loop {
                let content = this.take_content();
                if !content.is_empty() {
                    let n = content.len().min(buf.remaining());
                    buf.put_slice(&content[..n]);
                    this.carry.extend_from_slice(&content[n..]);
                    return Poll::Ready(Ok(()));
                }
                if this.raw_read {
                    return Pin::new(&mut this.io).poll_read(cx, buf);
                }
                let mut tmp = [0u8; 4096];
                let n = {
                    let mut rb = ReadBuf::new(&mut tmp);
                    ready!(Pin::new(&mut this.io).poll_read(cx, &mut rb))?;
                    rb.filled().len()
                };
                if n == 0 {
                    return Poll::Ready(Ok(()));
                }
                this.in_buf.extend_from_slice(&tmp[..n]);
            }
        }
    }

    impl AsyncWrite for VisionServer {
        fn poll_write(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<io::Result<usize>> {
            let this = self.get_mut();
            while !this.out.is_empty() {
                let n = ready!(Pin::new(&mut this.io).poll_write(cx, &this.out))?;
                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "vision test server: zero write",
                    )));
                }
                this.out.drain(..n);
            }
            if data.is_empty() {
                return Poll::Ready(Ok(0));
            }
            if this.padding {
                this.push_framed(data);
            } else {
                this.out.extend_from_slice(data);
            }
            while !this.out.is_empty() {
                let n = ready!(Pin::new(&mut this.io).poll_write(cx, &this.out))?;
                this.out.drain(..n);
            }
            Poll::Ready(Ok(data.len()))
        }

        fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            let this = self.get_mut();
            while !this.out.is_empty() {
                let n = ready!(Pin::new(&mut this.io).poll_write(cx, &this.out))?;
                this.out.drain(..n);
            }
            Pin::new(&mut this.io).poll_flush(cx)
        }

        fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
        }
    }

    /// A rustls server config plus its self-signed certificate; the client
    /// config trusts that same certificate (the self-signed-cert-as-root
    /// pattern the tls13 tests use).
    fn test_cert() -> (Arc<rustls::ServerConfig>, rcgen::Certificate) {
        let certified = rcgen::generate_simple_self_signed(vec!["inner.test".to_string()])
            .expect("rcgen self-signed cert");
        let cert_der = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
        let key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let server = Arc::new(
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert_der], key)
                .expect("server config"),
        );
        (server, certified.cert)
    }

    /// A client config trusting the test server's certificate (the same
    /// self-signed-cert-as-root pattern as the tls13 tests).
    fn client_tls_config(cert: &rcgen::Certificate) -> Arc<rustls::ClientConfig> {
        let mut roots = rustls::RootCertStore::empty();
        roots
            .add(rustls::pki_types::CertificateDer::from(cert.der().to_vec()))
            .unwrap();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        Arc::new(
            rustls::ClientConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        )
    }

    /// End to end over a loopback duplex: inner rustls handshake plus an echo,
    /// through the double-TLS stack (vision framing inside, plain duplex
    /// outside), with a test-only vision server implementing the server half.
    #[tokio::test]
    async fn inner_tls_handshake_and_echo_round_trip() {
        let uuid = uuid_bytes();
        let stats = Arc::new(ServerStats::default());
        let (server_config, cert) = test_cert();
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);

        let server_stats = stats.clone();
        let server_task = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            let adapter = VisionServer::new(server_io, uuid, false, server_stats);
            let mut tls = acceptor
                .accept(adapter)
                .await
                .expect("server handshake through vision framing");
            assert_eq!(
                tls.get_ref().1.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3),
                "the inner session must be TLS 1.3"
            );
            let mut buf = [0u8; 4096];
            loop {
                let n = tls.read(&mut buf).await.expect("server read");
                if n == 0 {
                    break;
                }
                tls.write_all(&buf[..n]).await.expect("server echo");
                tls.flush().await.expect("server flush");
            }
        });

        // Client: vision carrier, then a real inner TLS session on top.
        let conn = VisionConn::connect(
            Box::new(client_io),
            &NetAddr::domain("target.test", 443).unwrap(),
            uuid::Uuid::from_bytes(uuid),
            VisionConfig::new(),
        )
        .await
        .unwrap();
        let mut inner = tokio_rustls::TlsConnector::from(client_tls_config(&cert))
            .connect("inner.test".try_into().unwrap(), conn)
            .await
            .expect("client handshake through vision framing");

        inner.write_all(b"vision echo").await.unwrap();
        let mut echoed = [0u8; 11];
        inner.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"vision echo");
        // Multi-record payload: 40 KiB crosses several 16 KiB inner records and
        // several outer frames/reshape cuts, both directions.
        let big: Vec<u8> = (0..40 * 1024).map(|i| (i % 251) as u8).collect();
        inner.write_all(&big).await.unwrap();
        inner.flush().await.unwrap();
        let mut back = vec![0u8; big.len()];
        inner.read_exact(&mut back).await.unwrap();
        assert_eq!(back, big);
        assert!(
            inner.get_ref().0.inner_tls13_detected(),
            "the client must see the inner TLS 1.3 ServerHello"
        );
        inner.shutdown().await.unwrap();
        drop(inner);
        server_task.await.unwrap();

        // The server saw the client's UUID-prefixed first frame, then the
        // padding phase ended with command 01 (never 02: no splice here).
        assert!(stats.first_frame_has_uuid.load(Ordering::Relaxed));
        let commands = stats.commands.lock().unwrap().clone();
        assert!(commands.contains(&COMMAND_CONTINUE), "{commands:?}");
        assert!(commands.contains(&COMMAND_END), "{commands:?}");
        assert!(!commands.contains(&COMMAND_DIRECT), "{commands:?}");
        assert_eq!(stats.unframed_bytes.load(Ordering::Relaxed), 0);
        assert!(stats.frames.load(Ordering::Relaxed) >= 2);
    }

    /// A server that announces direct copy (command `02`) with its first
    /// application-data frame is followed at the framing level: the client
    /// stops unpadding, everything after the frame passes through verbatim,
    /// and the inner TLS 1.3 session plus echo keep working across the
    /// transition, both directions. The client's own uplink transition still
    /// sends command `01` — never `02`, which would promise a raw uplink this
    /// port cannot provide (see the module docs).
    #[tokio::test]
    async fn server_direct_switches_to_raw_passthrough() {
        let uuid = uuid_bytes();
        let stats = Arc::new(ServerStats::default());
        let (server_config, cert) = test_cert();
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);

        let server_stats = stats.clone();
        let server_task = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            let adapter = VisionServer::new(server_io, uuid, true, server_stats);
            let mut tls = acceptor
                .accept(adapter)
                .await
                .expect("the client must follow the direct switch, not abort");
            assert_eq!(
                tls.get_ref().1.protocol_version(),
                Some(rustls::ProtocolVersion::TLSv1_3),
                "the inner session must be TLS 1.3"
            );
            let mut buf = [0u8; 4096];
            loop {
                let n = tls.read(&mut buf).await.expect("server read");
                if n == 0 {
                    break;
                }
                tls.write_all(&buf[..n]).await.expect("server echo");
                tls.flush().await.expect("server flush");
            }
        });

        let conn = VisionConn::connect(
            Box::new(client_io),
            &NetAddr::domain("target.test", 443).unwrap(),
            uuid::Uuid::from_bytes(uuid),
            VisionConfig::new(),
        )
        .await
        .unwrap();
        let mut inner = tokio_rustls::TlsConnector::from(client_tls_config(&cert))
            .connect("inner.test".try_into().unwrap(), conn)
            .await
            .expect("the handshake must survive the server's direct switch");
        assert!(
            inner.get_ref().0.direct_mode(),
            "the server's command 02 must be recorded"
        );
        assert!(
            inner.get_ref().0.inner_tls13_detected(),
            "the client still watches the inner ServerHello"
        );

        // Echo round trip through the transition: these bytes cross in both
        // directions after the server stopped framing.
        inner.write_all(b"after direct").await.unwrap();
        let mut echoed = [0u8; 12];
        inner.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"after direct");
        let big: Vec<u8> = (0..40 * 1024).map(|i| (i % 251) as u8).collect();
        inner.write_all(&big).await.unwrap();
        inner.flush().await.unwrap();
        let mut back = vec![0u8; big.len()];
        inner.read_exact(&mut back).await.unwrap();
        assert_eq!(back, big);
        inner.shutdown().await.unwrap();
        drop(inner);
        server_task.await.unwrap();

        // The server did send command 02 (its own marker, pushed once when it
        // frames the first application-data write). The client's uplink
        // transition shows up as a parsed command 01 — the count pins that the
        // client never emitted a 02 of its own.
        let commands = stats.commands.lock().unwrap().clone();
        assert!(commands.contains(&COMMAND_DIRECT), "{commands:?}");
        assert!(commands.contains(&COMMAND_END), "{commands:?}");
        assert_eq!(
            commands.iter().filter(|c| **c == COMMAND_DIRECT).count(),
            1,
            "exactly one 02 on the wire: the server's own ({commands:?})"
        );
        assert_eq!(stats.unframed_bytes.load(Ordering::Relaxed), 0);
        assert!(stats.frames.load(Ordering::Relaxed) >= 2);
    }

    /// The direct transition boundary, pinned byte-exactly: the `02` frame's
    /// content is delivered, its padding dropped, every byte after the frame
    /// passes through verbatim — including bytes that arrived in the same
    /// transport read as the frame (upstream appends them after the content,
    /// `XtlsUnpadding`'s tail, Xray `proxy/proxy.go`) — and a frame header
    /// split across reads corrupts nothing. Receiving `02` must NOT end the
    /// uplink padding phase (upstream's writer flag is its own), and EOF
    /// after the switch is a clean EOF.
    #[tokio::test]
    async fn direct_frame_boundary_is_exact() {
        let uuid = uuid_bytes();
        let (client_io, mut server_io) = tokio::io::duplex(8192);

        let a = vec![0xa1u8; 48]; // content of a continue frame
        let b = vec![0xb2u8; 64]; // content of the direct frame
        let pad = 37usize; // padding of the direct frame
        let raw1 = vec![0xc3u8; 100]; // raw bytes riding the same write as the frame
        let raw2 = vec![0xd4u8; 77]; // raw bytes in a later write

        let first = {
            let mut w = Vec::new();
            w.extend_from_slice(&uuid);
            w.extend_from_slice(&frame(FrameCommand::Continue, &a, 0, None));
            w
        };
        let direct = frame(FrameCommand::Direct, &b, pad, None);
        assert_eq!(direct[..5], [COMMAND_DIRECT, 0, 64, 0, 37]);
        let expected: Vec<u8> = [a.as_slice(), b.as_slice(), raw1.as_slice(), raw2.as_slice()].concat();

        let server = tokio::spawn(async move {
            server_io.write_all(&first).await.unwrap();
            server_io.flush().await.unwrap();
            // Split header: two bytes now, the rest (content + padding + the
            // first raw chunk that rode along) after a pause.
            server_io.write_all(&direct[..2]).await.unwrap();
            server_io.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            let mut tail = direct[2..].to_vec();
            tail.extend_from_slice(&raw1);
            server_io.write_all(&tail).await.unwrap();
            server_io.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            server_io.write_all(&raw2).await.unwrap();
            server_io.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            server_io.shutdown().await.unwrap();
        });

        let mut conn = VisionConn::connect(
            Box::new(client_io),
            &NetAddr::domain("target.test", 443).unwrap(),
            uuid::Uuid::from_bytes(uuid),
            VisionConfig::new(),
        )
        .await
        .unwrap();
        let mut got = vec![0u8; expected.len()];
        conn.read_exact(&mut got).await.unwrap();
        assert_eq!(got, expected, "content, then raw — never padding bytes");
        assert!(conn.direct_mode(), "the 02 frame was parsed");
        assert!(
            conn.padding_active(),
            "the received 02 must not end the uplink padding phase"
        );
        // Clean EOF after the switch (upstream reads the raw socket's EOF).
        let mut tail = [0u8; 8];
        let n = conn.read(&mut tail).await.unwrap();
        assert_eq!(n, 0, "EOF, not an error");
        drop(conn);
        server.await.unwrap();
    }

    /// The eager hide-the-header frame goes out first, carries the UUID, and
    /// the first data frame then does not repeat it.
    #[tokio::test]
    async fn initial_padding_frame_precedes_the_client_hello() {
        let uuid = uuid_bytes();
        let stats = Arc::new(ServerStats::default());
        let (server_config, cert) = test_cert();
        let (client_io, server_io) = tokio::io::duplex(256 * 1024);

        let server_stats = stats.clone();
        let server_task = tokio::spawn(async move {
            let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
            let adapter = VisionServer::new(server_io, uuid, false, server_stats);
            let mut tls = acceptor.accept(adapter).await.expect("handshake");
            let mut buf = [0u8; 16];
            let n = tls.read(&mut buf).await.expect("read");
            tls.write_all(&buf[..n]).await.expect("echo");
            tls.flush().await.expect("flush");
        });

        let conn = VisionConn::connect(
            Box::new(client_io),
            &NetAddr::domain("target.test", 443).unwrap(),
            uuid::Uuid::from_bytes(uuid),
            VisionConfig {
                initial_padding: true,
                ..VisionConfig::new()
            },
        )
        .await
        .unwrap();
        let mut inner = tokio_rustls::TlsConnector::from(client_tls_config(&cert))
            .connect("inner.test".try_into().unwrap(), conn)
            .await
            .expect("client handshake");
        inner.write_all(b"hi").await.unwrap();
        let mut echoed = [0u8; 2];
        inner.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"hi");
        drop(inner);
        server_task.await.unwrap();

        // The empty frame came first (content == 0), with the UUID, then the
        // ClientHello frame without it.
        let commands = stats.commands.lock().unwrap().clone();
        assert_eq!(commands.first(), Some(&COMMAND_CONTINUE));
        assert!(stats.first_frame_has_uuid.load(Ordering::Relaxed));
        assert!(stats.frames.load(Ordering::Relaxed) >= 2);
    }

    /// A downlink that is not UUID-prefixed is passed through unframed
    /// (Xray `XtlsUnpadding` initial-state behaviour).
    #[tokio::test]
    async fn unframed_downlink_falls_back_to_raw() {
        let uuid = uuid_bytes();
        let (client_io, mut server_io) = tokio::io::duplex(4096);
        let raw = b"\x16\x03\x03\x00\x20unframed downlink bytes here!".to_vec();
        let writer = raw.clone();
        let server = tokio::spawn(async move {
            // Deliver the head of the "record" first: fewer than the 16 bytes
            // the classifier needs, so the client must buffer (not misparse)
            // and still hand the bytes over in order.
            server_io.write_all(&writer[..5]).await.unwrap();
            server_io.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            server_io.write_all(&writer[5..]).await.unwrap();
            server_io.flush().await.unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });
        let mut conn = VisionConn::connect(
            Box::new(client_io),
            &NetAddr::domain("target.test", 443).unwrap(),
            uuid::Uuid::from_bytes(uuid),
            VisionConfig::new(),
        )
        .await
        .unwrap();
        let mut buf = vec![0u8; raw.len()];
        conn.read_exact(&mut buf).await.unwrap();
        assert_eq!(buf, raw);
        drop(conn);
        server.await.unwrap();
    }

    /// `hide_vless_header` is one-shot: the padding UUID goes out once.
    #[tokio::test]
    async fn hide_vless_header_is_one_shot() {
        let uuid = uuid_bytes();
        let (client_io, mut server_io) = tokio::io::duplex(4096);
        let mut conn = VisionConn::connect(
            Box::new(client_io),
            &NetAddr::domain("target.test", 443).unwrap(),
            uuid::Uuid::from_bytes(uuid),
            VisionConfig::new(),
        )
        .await
        .unwrap();
        conn.hide_vless_header().await.unwrap();
        let mut head = vec![0u8; 16 + 5];
        server_io.read_exact(&mut head).await.unwrap();
        assert_eq!(&head[..16], &uuid);
        assert_eq!(head[16], COMMAND_CONTINUE);
        assert_eq!(&head[17..19], &[0, 0], "empty content");
        let pad_len = usize::from(u16::from_be_bytes([head[19], head[20]]));
        // XtlsPadding(nil, .., longPadding=true): rand(500) + 900 - 0.
        assert!((900..1400).contains(&pad_len), "padding {pad_len}");
        let mut pad = vec![0u8; pad_len];
        server_io.read_exact(&mut pad).await.unwrap();
        assert!(pad.iter().all(|b| *b == 0));
        assert!(conn.hide_vless_header().await.is_err(), "UUID sent once");
    }

    /// `connect` records the target and the UUID; `Debug` does not leak bytes.
    #[tokio::test]
    async fn accessors_and_debug() {
        let uuid = uuid_bytes();
        let (client_io, _server_io) = tokio::io::duplex(64);
        let conn = VisionConn::connect(
            Box::new(client_io),
            &NetAddr::domain("target.test", 8443).unwrap(),
            uuid::Uuid::from_bytes(uuid),
            VisionConfig::new(),
        )
        .await
        .unwrap();
        assert_eq!(conn.uuid(), uuid);
        assert_eq!(conn.target().unwrap().port, 8443);
        assert!(conn.padding_active());
        assert!(!conn.inner_tls13_detected());
        assert!(!conn.direct_mode());
        assert!(!conn.filter().is_tls());
        let debug = format!("{conn:?}");
        assert!(debug.contains("VisionConn"), "{debug}");
        assert!(debug.contains("direct"), "{debug}");
    }
}