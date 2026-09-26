//! ShadowQUIC client over quinn, ported source-level from mihomo
//! `transport/shadowquic` (the framing/relay layer) and
//! `adapter/outbound/shadowquic.go` (the option/config surface).
//!
//! ShadowQUIC is Shadowsocks-style relaying over QUIC: a TCP target is a
//! bidirectional stream whose first bytes are `command ‖ socks5.Addr`
//! (`protocol.go:15-22,65-94`); a UDP session ("association") is opened
//! with `CommandAssociateDatagram`/`CommandAssociateStream` plus the
//! unspecified address, after which packets flow either as QUIC datagrams
//! tagged with a per-destination `u16` id (`EncodeDatagram
//! protocol.go:121-129`) or, in `udp-over-stream` mode, over one
//! unidirectional stream per destination carrying
//! `id ‖ [len ‖ payload]...` (`WritePacketStreamHeader/Payload
//! protocol.go:138-156`). The association's control stream carries the
//! server-side binding `socks5.Addr ‖ id_be16` per incoming source
//! (`WriteUDPControl/ReadUDPControl protocol.go:96-119`), and the
//! connection-level demux (`state.go`) routes datagrams and uni streams
//! to the association that owns the id, buffering up to 32 packets for
//! an id whose target is not yet known.
//!
//! ## JLS inside the QUIC handshake — through the engine's own TLS 1.3
//!
//! mihomo ALWAYS enables JLS on a ShadowQUIC outbound
//! (`adapter/outbound/shadowquic.go:104-110`):
//!
//! ```go
//! tlsConfig.JLSConfig = &tls.JLSConfig{ Enable: true,
//!     User: tls.JLSUser{ Username: option.Username, Password: option.Password } }
//! ```
//!
//! and dials with `jls-quic-go`, whose crypto setup runs the metacubex
//! **jls-tls** fork of crypto/tls as the QUIC TLS stack:
//! `jls-quic-go/internal/handshake/crypto_setup.go:93` —
//! `cs.conn = tls.QUICClient(&tls.QUICConfig{TLSConfig: cs.tlsConf})`
//! (import `github.com/metacubex/jls-tls`, crypto_setup.go:7). The JLS
//! credentials are therefore applied INSIDE the QUIC TLS handshake (the
//! ClientHello/ServerHello random replacement of `proto::jls`,
//! jls-tls `jls.go:232-304`) — carried by the QUIC CRYPTO stream and
//! covered by the QUIC transport's own encryption.
//!
//! This port now does the same: when username/password are set,
//! [`connect`] drives the QUIC handshake through
//! [`crate::quic::tls13::Tls13QuicClientConfig`] — a quinn
//! `crypto::ClientConfig` over the engine's own TLS 1.3 stack — with the
//! JLS cover (the fingerprint ClientHello with the fakeRandom stamped in
//! over the serialized hello including the QUIC transport parameters,
//! exactly how the TCP fingerprint path of `proto::jls` stamps it over
//! `jls::hello_auth_data`; the ServerHello random is validated with
//! `jls::check_fake_random` and a failure surfaces the upstream
//! `jls::ERR_AUTH_FAILED` sentinel). With both empty the dial keeps
//! quinn's rustls path unchanged.
//!
//! ## QUIC tuning knobs vs quinn
//!
//! [`ShadowQuicOption`] mirrors every field of upstream
//! `ShadowQuicOption` (`adapter/outbound/shadowquic.go:29-52`). What
//! maps onto `quinn::TransportConfig` (defaults per
//! `NewShadowQuic shadowquic.go:117-158`):
//!
//! * `recv-window-conn` → `stream_receive_window` (upstream ramps
//!   `tuic.DefaultStreamReceiveWindow/10` → full
//!   `tuic.DefaultStreamReceiveWindow` = 15728640, mihomo
//!   `transport/tuic/common/congestion.go:12`; quinn exposes a single
//!   autotuning value, so the /10 ramp is engine-internal).
//! * `recv-window` → `receive_window` (same note;
//!   `DefaultConnectionReceiveWindow` = 67108864).
//! * `max-open-streams` → `max_concurrent_bidi_streams` +
//!   `max_concurrent_uni_streams` (default 1024).
//! * `keep-alive-interval` (ms) → `keep_alive_interval`.
//! * `disable-mtu-discovery` → `mtu_discovery_config(None)`.
//! * datagrams are always enabled (`EnableDatagrams`, shadowquic.go:146)
//!   → `datagram_receive_buffer_size`.
//! * `quic-versions` → endpoint `supported_versions` (default `[v1]`,
//!   `quic_version.go:10-12`); `v2` is rejected — quinn 0.11.12 has no
//!   RFC 9369 support at all (quinn-proto `DEFAULT_SUPPORTED_VERSIONS`
//!   = v1 + drafts only).
//!
//! Knobs quinn does not expose (accepted, never an error, documented
//! here): `cwnd` (no initial-congestion-window setter), `up`/`down`
//! (Brutal rate negotiation — the `extension_brutal.go` frame codecs are
//! ported below but quinn has no `SetCongestionControl` runtime hook, so
//! negotiating Brutal with a server we cannot honour would only degrade
//! the flow), `congestion-controller` and `bbr-profile` (quinn ships
//! CUBIC only; upstream's silent switch-with-no-default matches:
//! unknown values are ignored, congestion.go:21-47), `zero-rtt` (needs a
//! resumption ticket store this client deliberately does not keep),
//! `max-datagram-frame-size` (no per-frame cap knob; the receive buffer
//! covers any `0xffff` datagram).
//!
//! One engine-side addition over the upstream field list:
//! `skip_cert_verify` — upstream always verifies against the CA pool
//! (`shadowquic.go:97`), the engine's shared TLS plumbing carries the
//! flag for every other QUIC outbound and the hermetic loopback tests
//! need it (mihomo's own tests inject their CA into `ca.GetCertPool()`).

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use quinn::VarInt;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};
use tokio::sync::{mpsc, Mutex, Notify};

use crate::addr::{decode_socks_addr, encode_socks_addr, Host, NetAddr};
use crate::error::{Error, Result};
use crate::quic::{self, QuicDial, QuicStream};
use crate::stream::BoxProxyStream;
use crate::transport::{tls_client_config, TlsSettings};

/// `protocol.go:15-22` commands.
pub const COMMAND_CONNECT: u8 = 0x01;
pub const COMMAND_BIND: u8 = 0x02;
pub const COMMAND_ASSOCIATE_DATAGRAM: u8 = 0x03;
pub const COMMAND_ASSOCIATE_STREAM: u8 = 0x04;
pub const COMMAND_AUTHENTICATE: u8 = 0x05;
/// `protocol.go:21 CommandExtension` (private extensions ride it).
pub const COMMAND_EXTENSION: u8 = 0xff;

/// `protocol.go:24 maxUDPPacketSize`.
pub const MAX_UDP_PACKET_SIZE: usize = 0xffff;
/// `state.go:14 maxPendingPacketsPerID`.
const MAX_PENDING_PACKETS_PER_ID: usize = 32;
/// `packet.go:14 packetInputQueue` — per-association packet channel.
const PACKET_INPUT_QUEUE: usize = 128;
/// Default ALPN (`shadowquic.go:101-103`).
const DEFAULT_ALPN: &str = "h3";
/// `transport/tuic/common/congestion.go:12 DefaultStreamReceiveWindow`.
const DEFAULT_STREAM_RECV_WINDOW: u64 = 15_728_640;
/// `transport/tuic/common/congestion.go:13 DefaultConnectionReceiveWindow`.
const DEFAULT_CONNECTION_RECV_WINDOW: u64 = 67_108_864;
/// `shadowquic.go:117-125` zero-value defaults. The datagram frame-size
/// cap has no quinn mapping (accepted, see the module header).
#[allow(dead_code)]
const DEFAULT_MAX_DATAGRAM_FRAME_SIZE: u32 = 1400;
const DEFAULT_MAX_OPEN_STREAMS: u32 = 1024;
/// `shadowquic.go:124-125` — accepted and recorded for parity; quinn
/// exposes no initial-congestion-window knob (module docs).
#[allow(dead_code)]
const DEFAULT_CWND: u32 = 32;

/// `quic_version.go:10-38`: default `[v1]`, parsed aliases for v1/v2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuicVersion {
    V1,
    V2,
}

impl QuicVersion {
    /// The 32-bit wire code used in version negotiation.
    pub fn wire_code(self) -> u32 {
        match self {
            QuicVersion::V1 => 0x0000_0001,
            QuicVersion::V2 => 0x6b33_43cf,
        }
    }
}

/// `ParseQUICVersion` (`quic_version.go:28-38`): normalizes `_`→`-`,
/// lowercases, trims; accepts the RFC spellings.
pub fn parse_quic_version(value: &str) -> Result<QuicVersion> {
    let normalized = value.trim().to_ascii_lowercase().replace('_', "-");
    match normalized.as_str() {
        "v1" | "1" | "rfc9000" | "rfc-9000" => Ok(QuicVersion::V1),
        "v2" | "2" | "rfc9369" | "rfc-9369" => Ok(QuicVersion::V2),
        _ => Err(Error::config(format!(
            "unsupported QUIC version {value:?} (supported: v1, v2)"
        ))),
    }
}

/// `ParseQUICVersions` (`quic_version.go:14-26`): parse each, drop
/// duplicates, preserve order.
pub fn parse_quic_versions(values: &[String]) -> Result<Vec<QuicVersion>> {
    let mut versions = Vec::with_capacity(values.len());
    for value in values {
        let version = parse_quic_version(value)?;
        if !versions.contains(&version) {
            versions.push(version);
        }
    }
    Ok(versions)
}

/// `ShadowQuicOption` (`adapter/outbound/shadowquic.go:29-52`) — every
/// upstream field (plus the engine-side `skip_cert_verify`, see the
/// module docs).
#[derive(Debug, Clone)]
pub struct ShadowQuicOption {
    pub name: String,
    pub server: String,
    pub port: u16,
    /// JLS username (`proxy:"username,omitempty"`).
    pub username: String,
    /// JLS password (`proxy:"password,omitempty"`).
    pub password: String,
    pub sni: String,
    /// Empty selects `["h3"]`.
    pub alpn: Vec<String>,
    /// Empty selects `[v1]` (`DefaultQUICVersions`).
    pub quic_versions: Vec<String>,
    /// UDP-over-stream (`proxy:"udp-over-stream,omitempty"`).
    pub udp_over_stream: bool,
    pub zero_rtt: bool,
    /// Milliseconds (`proxy:"keep-alive-interval,omitempty"`).
    pub keep_alive_interval: u64,
    pub congestion_controller: String,
    /// Upload bandwidth (`proxy:"up,omitempty"`) — Brutal, not applied.
    pub up: String,
    /// Download bandwidth (`proxy:"down,omitempty"`) — Brutal, not applied.
    pub down: String,
    pub cwnd: u32,
    pub bbr_profile: String,
    /// Per-stream receive window (`proxy:"recv-window-conn,omitempty"`).
    pub recv_window_conn: u32,
    /// Connection receive window (`proxy:"recv-window,omitempty"`).
    pub recv_window: u32,
    pub disable_mtu_discovery: bool,
    pub max_datagram_frame_size: u32,
    pub max_open_streams: u32,
    /// Engine-side (upstream verifies against the CA pool unconditionally).
    pub skip_cert_verify: bool,
}

impl ShadowQuicOption {
    /// A zero-value option with the required dial fields, mirroring what
    /// `NewShadowQuic` fills in for unset numerics
    /// (`shadowquic.go:117-125`).
    pub fn new(server: impl Into<String>, port: u16) -> Self {
        ShadowQuicOption {
            name: String::new(),
            server: server.into(),
            port,
            username: String::new(),
            password: String::new(),
            sni: String::new(),
            alpn: Vec::new(),
            quic_versions: Vec::new(),
            udp_over_stream: false,
            zero_rtt: false,
            keep_alive_interval: 0,
            congestion_controller: String::new(),
            up: String::new(),
            down: String::new(),
            cwnd: 0,
            bbr_profile: String::new(),
            recv_window_conn: 0,
            recv_window: 0,
            disable_mtu_discovery: false,
            max_datagram_frame_size: 0,
            max_open_streams: 0,
            skip_cert_verify: false,
        }
    }

    /// Whether JLS credentials are configured (upstream always enables
    /// JLS; here it is the trigger for [`ERR_JLS_IN_QUIC`]).
    pub fn jls_enabled(&self) -> bool {
        !self.username.is_empty() || !self.password.is_empty()
    }

    /// Effective QUIC versions (default `[v1]`).
    pub fn versions(&self) -> Result<Vec<QuicVersion>> {
        if self.quic_versions.is_empty() {
            return Ok(vec![QuicVersion::V1]);
        }
        parse_quic_versions(&self.quic_versions)
    }
}

// ---------------------------------------------------------------- framing

/// `WriteRequest` (`protocol.go:65-74`): `command ‖ socks5.Addr`; `None`
/// writes the unspecified address of `UnspecifiedAddr`
/// (`protocol.go:40-42`, 0.0.0.0:0).
pub fn write_request(buf: &mut Vec<u8>, command: u8, addr: Option<&NetAddr>) -> Result<()> {
    let addr = addr.ok_or_else(|| Error::protocol("shadowquic: invalid address"))?;
    buf.push(command);
    encode_socks_addr(buf, &addr.host, addr.port);
    Ok(())
}

/// The unspecified request address (`UnspecifiedAddr`, `protocol.go:40-42`).
pub fn unspecified_addr() -> NetAddr {
    NetAddr::ip(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0)
}

/// `WriteUDPControl` (`protocol.go:96-107`): `socks5.Addr ‖ id_be16`.
pub fn write_udp_control(buf: &mut Vec<u8>, addr: &NetAddr) {
    encode_socks_addr(buf, &addr.host, addr.port);
}

/// `ReadUDPControl` (`protocol.go:109-119`) over a memory buffer:
/// returns the address, the id and the bytes consumed.
pub fn read_udp_control(data: &[u8]) -> Result<(NetAddr, u16, usize)> {
    let (addr, used) = decode_socks_addr(data)?;
    let id = u16::from_be_bytes(
        data.get(used..used + 2)
            .ok_or_else(|| Error::protocol("shadowquic: short udp control"))?
            .try_into()
            .expect("u16"),
    );
    Ok((addr, id, used + 2))
}

/// `EncodeDatagram` (`protocol.go:121-129`): `id_be16 ‖ payload`.
pub fn encode_datagram(id: u16, payload: &[u8]) -> Result<Bytes> {
    if payload.len() > MAX_UDP_PACKET_SIZE {
        return Err(Error::protocol("shadowquic: packet too large"));
    }
    let mut packet = Vec::with_capacity(2 + payload.len());
    packet.extend_from_slice(&id.to_be_bytes());
    packet.extend_from_slice(payload);
    Ok(Bytes::from(packet))
}

/// `DecodeDatagram` (`protocol.go:131-136`): split `id_be16 ‖ payload`.
pub fn decode_datagram(packet: &[u8]) -> Result<(u16, &[u8])> {
    let id = u16::from_be_bytes(
        packet
            .get(..2)
            .ok_or_else(|| Error::protocol("shadowquic: invalid datagram"))?
            .try_into()
            .expect("u16"),
    );
    Ok((id, &packet[2..]))
}

/// `WritePacketStreamHeader` (`protocol.go:138-143`): `id_be16`.
pub fn write_packet_stream_header(buf: &mut Vec<u8>, id: u16) {
    buf.extend_from_slice(&id.to_be_bytes());
}

/// `WritePacketStreamPayload` (`protocol.go:145-156`):
/// `len_be16 ‖ payload`.
pub fn write_packet_stream_payload(buf: &mut Vec<u8>, payload: &[u8]) -> Result<()> {
    if payload.len() > MAX_UDP_PACKET_SIZE {
        return Err(Error::protocol("shadowquic: packet too large"));
    }
    buf.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    buf.extend_from_slice(payload);
    Ok(())
}

/// `ReadUint16` (`protocol.go:158-164`) from an async reader.
async fn read_u16<R: AsyncRead + Unpin>(r: &mut R) -> Result<u16> {
    let mut buf = [0u8; 2];
    r.read_exact(&mut buf)
        .await
        .map_err(|e| Error::network(format!("shadowquic: short read: {e}")))?;
    Ok(u16::from_be_bytes(buf))
}

/// `socks5.ReadAddr0` over an async reader: one address, byte-at-a-time
/// variable length.
async fn read_socks_addr<R: AsyncRead + Unpin>(r: &mut R) -> Result<NetAddr> {
    let mut atyp = [0u8; 1];
    r.read_exact(&mut atyp)
        .await
        .map_err(|e| Error::network(format!("shadowquic: short addr: {e}")))?;
    let host = match atyp[0] {
        0x01 => {
            let mut octets = [0u8; 4];
            r.read_exact(&mut octets).await.map_err(size_err("ipv4"))?;
            Host::Ip(std::net::IpAddr::V4(octets.into()))
        }
        0x03 => {
            let mut len = [0u8; 1];
            r.read_exact(&mut len)
                .await
                .map_err(|e| Error::network(format!("shadowquic: short domain len: {e}")))?;
            let mut domain = vec![0u8; len[0] as usize];
            r.read_exact(&mut domain).await.map_err(size_err("domain"))?;
            let s = String::from_utf8(domain)
                .map_err(|_| Error::protocol("shadowquic: domain not utf-8"))?;
            Host::Domain(s.to_ascii_lowercase())
        }
        0x04 => {
            let mut octets = [0u8; 16];
            r.read_exact(&mut octets).await.map_err(size_err("ipv6"))?;
            Host::Ip(std::net::IpAddr::V6(octets.into()))
        }
        other => {
            return Err(Error::protocol(format!(
                "shadowquic: bad atyp {other:#x}"
            )))
        }
    };
    let port = read_u16(r).await?;
    Ok(NetAddr::new(host, port))
}

fn size_err(what: &'static str) -> impl Fn(std::io::Error) -> Error {
    move |e| Error::network(format!("shadowquic: short {what}: {e}"))
}

// ------------------------------------------------ brutal extension codec

/// `extension_brutal.go:12 extensionOpcodeMihomoBrutal` — ASCII "mihomo"
/// + extension id 1.
pub const EXTENSION_OPCODE_MIHOMO_BRUTAL: u64 = 0x6d69_686f_6d6f_0001;
/// `extension_brutal.go:14 brutalNegotiationVersion`.
const BRUTAL_VERSION: u8 = 1;
/// `extension_brutal.go:19 brutalNegotiationFlagRxAuto`.
const BRUTAL_FLAG_RX_AUTO: u8 = 1 << 0;
/// `extension_brutal.go:16-18` frame bounds.
const BRUTAL_MIN_PAYLOAD: usize = 8;
const BRUTAL_MAX_PAYLOAD: usize = 64;

/// `WriteBrutalNegotiationRequest` (`extension_brutal.go:39-46`):
/// `CommandExtension ‖ opcode_be64 ‖ version ‖ flags ‖ len ‖ rx`.
/// Ported for wire parity; never sent by this client (see module docs).
pub fn write_brutal_negotiation_request(rx: u64) -> Vec<u8> {
    let mut buf = Vec::with_capacity(1 + 8 + 4 + BRUTAL_MIN_PAYLOAD);
    buf.push(COMMAND_EXTENSION);
    buf.extend_from_slice(&EXTENSION_OPCODE_MIHOMO_BRUTAL.to_be_bytes());
    write_brutal_frame(&mut buf, 0, rx);
    buf
}

/// `WriteBrutalNegotiationResponse` (`extension_brutal.go:53-62`).
pub fn write_brutal_negotiation_response(rx: u64, rx_auto: bool) -> Vec<u8> {
    let mut buf = Vec::with_capacity(4 + BRUTAL_MIN_PAYLOAD);
    let flags = if rx_auto { BRUTAL_FLAG_RX_AUTO } else { 0 };
    write_brutal_frame(&mut buf, flags, rx);
    buf
}

/// `writeBrutalNegotiationFrame` (`extension_brutal.go:72-77`).
fn write_brutal_frame(buf: &mut Vec<u8>, flags: u8, rx: u64) {
    buf.push(BRUTAL_VERSION);
    buf.push(flags);
    buf.extend_from_slice(&(BRUTAL_MIN_PAYLOAD as u16).to_be_bytes());
    buf.extend_from_slice(&rx.to_be_bytes());
}

/// `readBrutalNegotiationFrame` (`extension_brutal.go:79-96`): returns
/// `(rx, rx_auto)` or an error on a malformed/unsupported frame.
pub fn read_brutal_frame(data: &[u8]) -> Result<(u64, bool)> {
    if data.len() < 4 {
        return Err(Error::protocol("shadowquic: invalid brutal negotiation"));
    }
    if data[0] != BRUTAL_VERSION {
        return Err(Error::protocol(
            "shadowquic: unsupported brutal negotiation version",
        ));
    }
    let payload_len = usize::from(u16::from_be_bytes([data[2], data[3]]));
    if !(BRUTAL_MIN_PAYLOAD..=BRUTAL_MAX_PAYLOAD).contains(&payload_len) {
        return Err(Error::protocol("shadowquic: invalid brutal negotiation"));
    }
    let payload = data
        .get(4..4 + payload_len)
        .ok_or_else(|| Error::protocol("shadowquic: invalid brutal negotiation"))?;
    let rx = u64::from_be_bytes(payload[..8].try_into().expect("u64"));
    let rx_auto = data[1] & BRUTAL_FLAG_RX_AUTO != 0;
    Ok((rx, rx_auto))
}

// ------------------------------------------------------------ conn state

/// One delivered UDP packet (the `receivedPacket` of `state.go:23-27`).
#[derive(Debug, Clone)]
pub struct UdpPacket {
    pub addr: NetAddr,
    pub data: Bytes,
}

/// Where packets for a known id go (`recvTarget`, `state.go:46-50`).
#[derive(Debug, Clone)]
struct RecvTarget {
    /// Owning association handle (for `removeRecvIDs` ownership checks).
    assoc: u64,
    tx: mpsc::Sender<UdpPacket>,
    addr: NetAddr,
}

/// `recvSlot` (`state.go:40-44`): the target once the control message
/// arrives, plus packets buffered before that.
#[derive(Default)]
struct RecvSlot {
    target: Option<RecvTarget>,
    pending: Vec<Bytes>,
    ready: Arc<Notify>,
}

/// The connection-level demux of `connState` (`state.go:29-38`),
/// connection-free so the routing table is unit-testable on its own.
struct RecvRouter {
    inner: Mutex<ConnInner>,
}

#[derive(Default)]
struct ConnInner {
    next_id: u16,
    active_send: HashSet<u16>,
    recv: HashMap<u16, RecvSlot>,
}

impl Default for RecvRouter {
    fn default() -> Self {
        RecvRouter {
            inner: Mutex::new(ConnInner::default()),
        }
    }
}

/// `connState`: the router plus the QUIC handle its pumps drive.
struct ConnState {
    conn: quinn::Connection,
    router: RecvRouter,
}

impl ConnState {
    fn new(conn: quinn::Connection) -> Self {
        ConnState {
            conn,
            router: RecvRouter::default(),
        }
    }

    /// `newConnState` spawns the two pumps (`state.go:61-62`).
    fn spawn_pumps(self: Arc<Self>) {
        let datagrams = Arc::clone(&self);
        tokio::spawn(async move {
            // handleDatagrams (state.go:84-97).
            loop {
                match datagrams.conn.read_datagram().await {
                    Ok(message) => {
                        if let Ok((id, payload)) = decode_datagram(&message) {
                            datagrams
                                .router
                                .feed_datagram(id, Bytes::copy_from_slice(payload))
                                .await;
                        }
                    }
                    Err(_) => return,
                }
            }
        });
        let uni = Arc::clone(&self);
        tokio::spawn(async move {
            // handleUniStreams (state.go:99-108).
            loop {
                match uni.conn.accept_uni().await {
                    Ok(stream) => {
                        let uni = Arc::clone(&uni);
                        tokio::spawn(async move {
                            uni.handle_uni_stream(stream).await;
                        });
                    }
                    Err(_) => return,
                }
            }
        });
    }

    /// `handleUniStream` (`state.go:110-137`): `id ‖ [len ‖ payload]...`,
    /// waiting for the id's target before delivering.
    async fn handle_uni_stream(self: Arc<Self>, mut stream: quinn::RecvStream) {
        let id = match read_u16(&mut stream).await {
            Ok(id) => id,
            Err(_) => return,
        };
        let target = match self.router.wait_recv_target(id).await {
            Ok(target) => target,
            Err(_) => return,
        };
        loop {
            let length = match read_u16(&mut stream).await {
                Ok(n) => n as usize,
                Err(_) => return,
            };
            let mut payload = vec![0u8; length];
            if stream.read_exact(&mut payload).await.is_err() {
                return;
            }
            let _ = target.tx.try_send(UdpPacket {
                addr: target.addr.clone(),
                data: Bytes::from(payload),
            });
        }
    }

}

impl RecvRouter {
        /// `feedDatagram` (`state.go:139-162`): deliver to a known target or
    /// buffer (capped at [`MAX_PENDING_PACKETS_PER_ID`]).
    async fn feed_datagram(&self, id: u16, payload: Bytes) {
        let target = {
            let mut inner = self.inner.lock().await;
            if let Some(slot) = inner.recv.get_mut(&id) {
                match &slot.target {
                    Some(target) => Some(target.clone()),
                    None => {
                        if slot.pending.len() < MAX_PENDING_PACKETS_PER_ID {
                            slot.pending.push(payload.clone());
                        }
                        None
                    }
                }
            } else {
                let mut slot = RecvSlot::default();
                slot.pending.push(payload.clone());
                inner.recv.insert(id, slot);
                None
            }
        };
        if let Some(target) = target {
            // Upstream deliver() drops when the queue is full.
            let _ = target.tx.try_send(UdpPacket {
                addr: target.addr.clone(),
                data: payload,
            });
        }
    }

    /// `waitRecvTarget` (`state.go:164-186`).
    async fn wait_recv_target(&self, id: u16) -> Result<RecvTarget> {
        let notified = {
            let mut inner = self.inner.lock().await;
            let slot = inner.recv.entry(id).or_default();
            if let Some(target) = &slot.target {
                return Ok(target.clone());
            }
            Arc::clone(&slot.ready)
        };
        notified.notified().await;
        let inner = self.inner.lock().await;
        inner
            .recv
            .get(&id)
            .and_then(|slot| slot.target.clone())
            .ok_or_else(|| Error::network("shadowquic: recv target vanished"))
    }

    /// `storeRecv` (`state.go:188-213`): bind the id, deliver pending.
    async fn store_recv(&self, id: u16, target: RecvTarget) {
        let pending = {
            let mut inner = self.inner.lock().await;
            let slot = inner.recv.entry(id).or_default();
            let was_pending = slot.target.is_none();
            let pending = std::mem::take(&mut slot.pending);
            slot.target = Some(target.clone());
            if was_pending {
                slot.ready.notify_one();
            }
            pending
        };
        for payload in pending {
            let _ = target.tx.try_send(UdpPacket {
                addr: target.addr.clone(),
                data: payload,
            });
        }
    }

    /// `removeRecvIDs` (`state.go:215-225`): only the owning association
    /// removes a slot.
    async fn remove_recv_ids(&self, assoc: u64, ids: &[u16]) {
        let mut inner = self.inner.lock().await;
        for id in ids {
            if let Some(slot) = inner.recv.get(id) {
                if slot.target.as_ref().map(|t| t.assoc) == Some(assoc) {
                    inner.recv.remove(id);
                }
            }
        }
    }

    /// `allocSendID` (`state.go:227-243`): wrapping allocation skipping
    /// the active set; full wrap = too many contexts.
    async fn alloc_send_id(&self) -> Result<u16> {
        let mut inner = self.inner.lock().await;
        let start = inner.next_id;
        loop {
            let id = inner.next_id;
            inner.next_id = inner.next_id.wrapping_add(1);
            if !inner.active_send.contains(&id) {
                inner.active_send.insert(id);
                return Ok(id);
            }
            if inner.next_id == start {
                return Err(Error::network("shadowquic: too many udp contexts"));
            }
        }
    }

    /// `releaseSendIDs` (`state.go:245-252`).
    async fn release_send_ids(&self, ids: &[u16]) {
        let mut inner = self.inner.lock().await;
        for id in ids {
            inner.active_send.remove(id);
        }
    }
}

// -------------------------------------------------------------- client

/// How UDP packets are relayed (`udpMode`, `state.go:16-21`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UdpMode {
    Datagram,
    Stream,
}

/// The ShadowQUIC client (`shadowquic.Client` over one `connState`).
pub struct Client {
    conn: quinn::Connection,
    state: Arc<ConnState>,
    udp_over_stream: bool,
}

/// Dial the QUIC endpoint and return the relay client. Mirrors
/// `NewShadowQuic` + `DialQuic` (`shadowquic.go:86-193`,
/// `dial.go:24-63`): TLS 1.3 with the configured ALPN and the tuned
/// transport. With JLS credentials set the handshake runs through the
/// engine's own TLS 1.3 stack over quinn's crypto trait
/// ([`crate::quic::tls13`], the engine's equivalent of jls-quic-go's
/// `tls.QUICClient` from metacubex/jls-tls, crypto_setup.go:93); with
/// both empty it keeps quinn's rustls path unchanged.
pub async fn connect(option: &ShadowQuicOption) -> Result<Client> {
    let versions = option.versions()?;
    if versions.contains(&QuicVersion::V2) {
        return Err(Error::config(
            "shadowquic: QUIC v2 (rfc9369) is not supported by this engine's quinn \
             0.11 stack (no v2 implementation exists there)",
        ));
    }

    // shadowquic.go:88-103: SNI falls back to the server; ALPN to "h3".
    let sni = if option.sni.is_empty() {
        option.server.clone()
    } else {
        option.sni.clone()
    };
    let alpn: Vec<String> = if option.alpn.is_empty() {
        vec![DEFAULT_ALPN.to_string()]
    } else {
        option.alpn.clone()
    };
    // `adapter/outbound/jls.go:10-15 JLSOptions.Parse`: both fields
    // required when either is set.
    let jls_user = if option.jls_enabled() {
        Some(crate::proto::jls::JlsUser::new(&option.username, &option.password)?)
    } else {
        None
    };

    let remote = quic::resolve_remote(&option.server, option.port).await?;
    let mut endpoint_config = quinn::EndpointConfig::default();
    endpoint_config.supported_versions(versions.iter().map(|v| v.wire_code()).collect());
    let socket = std::net::UdpSocket::bind(quic::family_bind_addr(remote))
        .map_err(|e| Error::network(format!("shadowquic bind: {e}")))?;
    crate::mark::apply(&socket);
    let mut endpoint = quinn::Endpoint::new(
        endpoint_config,
        None,
        socket,
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| Error::network(format!("shadowquic endpoint: {e}")))?;
    endpoint.set_default_client_config(client_config(option, &sni, &alpn, jls_user.as_ref())?);
    let conn = endpoint
        .connect(remote, &sni)
        .map_err(|e| Error::config(format!("shadowquic connect to {remote}: {e}")))?
        .await
        .map_err(|e| {
            Error::network(format!(
                "shadowquic quic handshake with {remote} (sni {sni}, alpn {alpn:?}): {e}"
            ))
        })?;
    if jls_user.is_some() {
        tracing::debug!(
            target: "engine",
            "shadowquic: JLS-authenticated QUIC tunnel to {remote} (sni {sni})"
        );
    }

    let state = Arc::new(ConnState::new(conn.clone()));
    Arc::clone(&state).spawn_pumps();
    Ok(Client {
        conn,
        state,
        udp_over_stream: option.udp_over_stream,
    })
}

/// The quinn client config: the engine TLS stack (same verification
/// behavior as `quic::client_config`) plus the shadowquic transport
/// knobs (`shadowquic.go:136-158`). With a JLS user the crypto config is
/// the engine's own TLS 1.3 stack carrying the JLS cover
/// (`crate::quic::tls13::Tls13QuicClientConfig::new_jls`).
fn client_config(
    option: &ShadowQuicOption,
    sni: &str,
    alpn: &[String],
    jls_user: Option<&crate::proto::jls::JlsUser>,
) -> Result<quinn::ClientConfig> {
    let mut quic = if let Some(user) = jls_user {
        // The engine's own TLS 1.3 stack carrying the JLS cover — the
        // quinn-crypto equivalent of jls-quic-go's tls.QUICClient.
        quic::client_config_custom(
            &QuicDial {
                server: option.server.clone(),
                port: option.port,
                sni: sni.to_string(),
                alpn: alpn.to_vec(),
                skip_verify: option.skip_cert_verify,
                udp_relay: true,
                congestion_brutal_bps: None,
            },
            &quic::QuicTlsCover::Jls(user.clone()),
        )?
    } else {
        let settings = TlsSettings {
            enabled: true,
            server_name: None,
            skip_cert_verify: option.skip_cert_verify,
            alpn: Vec::new(),
        };
        let mut tls = (*tls_client_config(&settings)?).clone();
        tls.alpn_protocols = alpn.iter().map(|a| a.as_bytes().to_vec()).collect();
        let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))
            .map_err(|e| Error::config(format!("shadowquic quic tls initial suite: {e}")))?;
        quinn::ClientConfig::new(Arc::new(quic_tls))
    };
    apply_transport(option, &mut quic);
    Ok(quic)
}

/// The shadowquic transport knobs (`shadowquic.go:136-158`) applied over
/// whichever TLS stack was picked.
fn apply_transport(option: &ShadowQuicOption, quic: &mut quinn::ClientConfig) {
    let max_open_streams = if option.max_open_streams == 0 {
        DEFAULT_MAX_OPEN_STREAMS
    } else {
        option.max_open_streams
    };
    let stream_window = if option.recv_window_conn == 0 {
        DEFAULT_STREAM_RECV_WINDOW
    } else {
        u64::from(option.recv_window_conn)
    };
    let conn_window = if option.recv_window == 0 {
        DEFAULT_CONNECTION_RECV_WINDOW
    } else {
        u64::from(option.recv_window)
    };
    let clamp = |v: u64| VarInt::from_u64(v).unwrap_or(VarInt::MAX);

    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_bidi_streams(clamp(u64::from(max_open_streams)));
    transport.max_concurrent_uni_streams(clamp(u64::from(max_open_streams)));
    transport.stream_receive_window(clamp(stream_window));
    transport.receive_window(clamp(conn_window));
    transport.datagram_receive_buffer_size(Some(64 * 1024));
    if option.keep_alive_interval > 0 {
        transport.keep_alive_interval(Some(Duration::from_millis(option.keep_alive_interval)));
    }
    if option.disable_mtu_discovery {
        transport.mtu_discovery_config(None);
    }
    quic.transport_config(Arc::new(transport));
}

impl Client {
    /// The live QUIC connection (for `export_keying_material`-style
    /// callers or manual stream work).
    pub fn connection(&self) -> &quinn::Connection {
        &self.conn
    }

    /// `DialContext` (`client.go:97-116`): a bidirectional stream whose
    /// first bytes are `CommandConnect ‖ target` — then raw payload.
    pub async fn dial_tcp(&self, target: &NetAddr) -> Result<BoxProxyStream> {
        let (send, recv) = self
            .conn
            .open_bi()
            .await
            .map_err(|e| Error::network(format!("shadowquic open stream: {e}")))?;
        let mut stream = QuicStream::new(send, recv);
        let mut request = Vec::with_capacity(1 + 19);
        write_request(&mut request, COMMAND_CONNECT, Some(target))?;
        stream
            .write_all(&request)
            .await
            .map_err(|e| Error::network(format!("shadowquic connect request: {e}")))?;
        Ok(Box::new(stream))
    }

    /// `ListenPacket` (`client.go:118-138`): open the control stream,
    /// send the associate command for the configured mode, and return
    /// the association.
    pub async fn listen_packet(&self) -> Result<Association> {
        let (mut control_send, mut control_recv) = self
            .conn
            .open_bi()
            .await
            .map_err(|e| Error::network(format!("shadowquic open udp stream: {e}")))?;
        let mode = if self.udp_over_stream {
            UdpMode::Stream
        } else {
            UdpMode::Datagram
        };
        let command = match mode {
            UdpMode::Datagram => COMMAND_ASSOCIATE_DATAGRAM,
            UdpMode::Stream => COMMAND_ASSOCIATE_STREAM,
        };
        let mut request = Vec::with_capacity(1 + 7);
        write_request(&mut request, command, Some(&unspecified_addr()))?;
        control_send
            .write_all(&request)
            .await
            .map_err(|e| Error::network(format!("shadowquic associate: {e}")))?;
        let assoc_ids = Arc::new(Mutex::new(AssocInner::default()));

        let (tx, rx) = mpsc::channel(PACKET_INPUT_QUEUE);
        let state = Arc::clone(&self.state);
        let assoc = next_assoc_handle();
        let reader_ids = Arc::clone(&assoc_ids);
        // readControl (packet.go:59-72): the server announces each
        // incoming source as `socks5.Addr ‖ id`; the id joins the
        // association's recv set for close-time release.
        tokio::spawn(async move {
            loop {
                match read_socks_addr(&mut control_recv).await {
                    Ok(addr) => match read_u16(&mut control_recv).await {
                        Ok(id) => {
                            reader_ids.lock().await.recv_id_set.insert(id);
                            state
                                .router
                                .store_recv(
                                    id,
                                    RecvTarget {
                                        assoc,
                                        tx: tx.clone(),
                                        addr,
                                    },
                                )
                                .await;
                        }
                        Err(_) => return,
                    },
                    Err(_) => return,
                }
            }
        });

        Ok(Association {
            state: Arc::clone(&self.state),
            mode,
            control: Mutex::new(control_send),
            inner: assoc_ids,
            input: Mutex::new(rx),
            assoc,
        })
    }
}

/// Per-association handle source for `removeRecvIDs` ownership checks.
static NEXT_ASSOC: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);
fn next_assoc_handle() -> u64 {
    NEXT_ASSOC.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
}

#[derive(Default)]
struct AssocInner {
    /// `sendIDs`: destination key → allocated id (packet.go:25).
    send_ids: HashMap<String, u16>,
    /// `sendIDSet`/`recvIDSet` for close-time release (packet.go:26-27).
    send_id_set: HashSet<u16>,
    recv_id_set: HashSet<u16>,
    /// `uniStreams`: destination key → packet stream (packet.go:28).
    uni_streams: HashMap<String, quinn::SendStream>,
}

/// A UDP session (`association`, `packet.go:16-35`).
pub struct Association {
    state: Arc<ConnState>,
    mode: UdpMode,
    control: Mutex<quinn::SendStream>,
    /// Shared with the control-reader task, which records recv ids.
    inner: Arc<Mutex<AssocInner>>,
    input: Mutex<mpsc::Receiver<UdpPacket>>,
    assoc: u64,
}

impl Association {
    /// The relay mode this association negotiated.
    pub fn mode(&self) -> UdpMode {
        self.mode
    }

    /// `WriteTo` (`packet.go:104-167`): allocate (and announce over the
    /// control stream) a destination id on first use, then send — as a
    /// datagram (`EncodeDatagram`) or over the destination's uni stream
    /// (`WritePacketStreamHeader` once, then `WritePacketStreamPayload`).
    pub async fn send_to(&self, payload: &[u8], target: &NetAddr) -> Result<usize> {
        if payload.len() > MAX_UDP_PACKET_SIZE {
            return Err(Error::protocol("shadowquic: packet too large"));
        }
        let key = target.to_string();

        let id = {
            let mut inner = self.inner.lock().await;
            match inner.send_ids.get(&key) {
                Some(id) => *id,
                None => {
                    let id = self.state.router.alloc_send_id().await?;
                    let mut control = Vec::with_capacity(19);
                    write_udp_control(&mut control, target);
                    control.extend_from_slice(&id.to_be_bytes());
                    let mut control_stream = self.control.lock().await;
                    if let Err(e) = control_stream.write_all(&control).await {
                        self.state.router.release_send_ids(&[id]).await;
                        return Err(Error::network(format!(
                            "shadowquic udp control: {e}"
                        )));
                    }
                    inner.send_ids.insert(key.clone(), id);
                    inner.send_id_set.insert(id);
                    id
                }
            }
        };

        match self.mode {
            UdpMode::Stream => {
                let mut packet = Vec::with_capacity(2 + payload.len());
                write_packet_stream_payload(&mut packet, payload)?;
                let mut inner = self.inner.lock().await;
                let stream = match inner.uni_streams.get_mut(&key) {
                    Some(stream) => stream,
                    None => {
                        let mut stream = self
                            .state
                            .conn
                            .open_uni()
                            .await
                            .map_err(|e| Error::network(format!("shadowquic udp stream: {e}")))?;
                        let mut header = Vec::with_capacity(2);
                        write_packet_stream_header(&mut header, id);
                        if let Err(e) = stream.write_all(&header).await {
                            let _ = stream.finish();
                            return Err(Error::network(format!(
                                "shadowquic udp stream header: {e}"
                            )));
                        }
                        inner.uni_streams.insert(key.clone(), stream);
                        inner.uni_streams.get_mut(&key).expect("just inserted")
                    }
                };
                stream
                    .write_all(&packet)
                    .await
                    .map_err(|e| Error::network(format!("shadowquic udp packet: {e}")))?;
            }
            UdpMode::Datagram => {
                let datagram = encode_datagram(id, payload)?;
                self.state
                    .conn
                    .send_datagram(datagram)
                    .map_err(|e| Error::network(format!("shadowquic udp datagram: {e}")))?;
            }
        }
        Ok(payload.len())
    }

    /// `ReadFrom`/`WaitReadFrom` (`packet.go:82-102`): one packet with
    /// its source address (learned from the control stream).
    pub async fn recv_from(&self) -> Result<UdpPacket> {
        let mut input = self.input.lock().await;
        input
            .recv()
            .await
            .ok_or_else(|| Error::network("shadowquic: association closed"))
    }

    /// `Close` (`packet.go:169-198`): release the ids, drop the packet
    /// streams, close the control stream.
    pub async fn close(&self) -> Result<()> {
        let (send_ids, recv_ids, uni_streams) = {
            let mut inner = self.inner.lock().await;
            (
                std::mem::take(&mut inner.send_id_set).into_iter().collect::<Vec<_>>(),
                std::mem::take(&mut inner.recv_id_set).into_iter().collect::<Vec<_>>(),
                std::mem::take(&mut inner.uni_streams),
            )
        };
        self.state.router.release_send_ids(&send_ids).await;
        self.state.router.remove_recv_ids(self.assoc, &recv_ids).await;
        for (_, mut stream) in uni_streams {
            let _ = stream.finish();
        }
        let mut control = self.control.lock().await;
        control
            .finish()
            .map_err(|e| Error::network(format!("shadowquic udp close: {e}")))
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    use std::net::SocketAddr;
    use std::sync::atomic::{AtomicU16, AtomicUsize, Ordering};
    use std::sync::{Arc, OnceLock};
    use std::time::Duration;

    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::crypto::ring as ring_provider;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // ------------------------------------------------------------ framing

    #[test]
    fn quic_version_parsing() {
        // quic_version.go:28-38 aliases, case/underscore normalization.
        for spelling in ["v1", "1", "RFC9000", "rfc-9000", "V1"] {
            assert_eq!(parse_quic_version(spelling).unwrap(), QuicVersion::V1, "{spelling}");
        }
        for spelling in ["v2", "2", "RFC9369", "rfc_9369"] {
            assert_eq!(parse_quic_version(spelling).unwrap(), QuicVersion::V2, "{spelling}");
        }
        assert_eq!(QuicVersion::V1.wire_code(), 0x1);
        assert!(parse_quic_version("v3").is_err());
        // ParseQUICVersions dedups in order.
        let versions = parse_quic_versions(&[
            "v1".to_string(),
            "1".to_string(),
            "rfc9000".to_string(),
        ])
        .unwrap();
        assert_eq!(versions, vec![QuicVersion::V1]);
        assert_eq!(
            parse_quic_versions(&["v2".to_string(), "v1".to_string()]).unwrap(),
            vec![QuicVersion::V2, QuicVersion::V1]
        );
        // The upstream default is [v1] (DefaultQUICVersions).
        assert_eq!(
            ShadowQuicOption::new("127.0.0.1", 1).versions().unwrap(),
            vec![QuicVersion::V1]
        );
    }

    #[test]
    fn option_jls_flag() {
        let mut option = ShadowQuicOption::new("server.example", 8443);
        assert!(!option.jls_enabled());
        option.username = "user1".into();
        assert!(option.jls_enabled());
        option.username.clear();
        option.password = "pass1".into();
        assert!(option.jls_enabled());
    }

    #[test]
    fn request_and_control_frames() {
        // WriteRequest: command ‖ socks5.Addr (protocol.go:65-74).
        let target = NetAddr::domain("example.com", 443).unwrap();
        let mut request = Vec::new();
        write_request(&mut request, COMMAND_CONNECT, Some(&target)).unwrap();
        assert_eq!(request[0], COMMAND_CONNECT);
        let (addr, used) = crate::addr::decode_socks_addr(&request[1..]).unwrap();
        assert_eq!(addr, target);
        assert_eq!(used + 1, request.len());
        // UnspecifiedAddr is 0.0.0.0:0 → atyp 1 (protocol.go:40-42).
        let mut assoc = Vec::new();
        write_request(
            &mut assoc,
            COMMAND_ASSOCIATE_DATAGRAM,
            Some(&unspecified_addr()),
        )
        .unwrap();
        assert_eq!(
            &assoc,
            &[COMMAND_ASSOCIATE_DATAGRAM, 0x01, 0, 0, 0, 0, 0, 0]
        );
        // WriteUDPControl/ReadUDPControl roundtrip (protocol.go:96-119).
        let mut control = Vec::new();
        write_udp_control(&mut control, &target);
        control.extend_from_slice(&0x0102u16.to_be_bytes());
        let (addr, id, used) = read_udp_control(&control).unwrap();
        assert_eq!(addr, target);
        assert_eq!(id, 0x0102);
        assert_eq!(used, control.len());
        assert!(read_udp_control(&control[..3]).is_err());
        // write_request requires an address (errInvalidAddress).
        assert!(write_request(&mut Vec::new(), COMMAND_CONNECT, None).is_err());
    }

    #[test]
    fn datagram_and_stream_packet_codecs() {
        // EncodeDatagram/DecodeDatagram (protocol.go:121-136).
        let datagram = encode_datagram(0x4142, b"payload").unwrap();
        assert_eq!(&datagram[..2], &[0x41, 0x42]);
        let (id, payload) = decode_datagram(&datagram).unwrap();
        assert_eq!((id, payload), (0x4142, &b"payload"[..]));
        assert!(decode_datagram(&[0x01]).is_err());
        let big = vec![0u8; MAX_UDP_PACKET_SIZE + 1];
        assert!(encode_datagram(1, &big).is_err());
        // Packet stream framing (protocol.go:138-156).
        let mut stream = Vec::new();
        write_packet_stream_header(&mut stream, 7);
        write_packet_stream_payload(&mut stream, b"abc").unwrap();
        assert_eq!(stream, vec![0x00, 0x07, 0x00, 0x03, b'a', b'b', b'c']);
        assert!(write_packet_stream_payload(&mut Vec::new(), &big).is_err());
    }

    #[test]
    fn brutal_negotiation_frame_layout() {
        // extension_brutal.go:39-46: Extension command, be64 opcode,
        // version(1) flags(1) len(2) rx(8).
        let request = write_brutal_negotiation_request(0x0102_0304_0506_0708);
        assert_eq!(request[0], COMMAND_EXTENSION);
        assert_eq!(
            u64::from_be_bytes(request[1..9].try_into().unwrap()),
            EXTENSION_OPCODE_MIHOMO_BRUTAL
        );
        assert_eq!(&request[9..13], &[1, 0, 0, 8]);
        assert_eq!(request.len(), 9 + 4 + 8);
        let (rx, auto) = read_brutal_frame(&request[9..]).unwrap();
        assert_eq!(rx, 0x0102_0304_0506_0708);
        assert!(!auto);
        // Response flag (brutalNegotiationFlagRxAuto).
        let response = write_brutal_negotiation_response(42, true);
        let (rx, auto) = read_brutal_frame(&response).unwrap();
        assert_eq!(rx, 42);
        assert!(auto);
        // Malformed frames are rejected (readBrutalNegotiationFrame).
        assert!(read_brutal_frame(&[]).is_err());
        assert!(read_brutal_frame(&[2, 0, 0, 8, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
        assert!(read_brutal_frame(&[1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_err());
    }

    #[tokio::test]
    async fn jls_credentials_rejected_by_a_wrong_password() {
        // The JLS cover rides the QUIC TLS handshake: a server that
        // validates the fakeRandom rejects wrong credentials with the
        // upstream auth sentinel (jls-tls ErrJLSAuthFailed).
        let user = crate::proto::jls::JlsUser::new("user1", "pass1").unwrap();
        let endpoint = crate::quic::tls13::test_server::start_quinn_server(
            crate::quic::tls13::ServerMode::Jls {
                users: vec![user.clone()],
            },
        )
        .await
        .unwrap();
        let addr = endpoint.local_addr().unwrap();
        // quinn drives server handshakes through accept().
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let _ = incoming.await;
            }
        });

        let mut option = ShadowQuicOption::new("127.0.0.1", addr.port());
        option.username = "user1".into();
        option.password = "wrong-password".into();
        let err = match tokio::time::timeout(Duration::from_secs(15), connect(&option)).await {
            Err(_) => panic!("jls handshake timed out"),
            Ok(Err(e)) => e,
            Ok(Ok(_)) => panic!("wrong password must not authenticate"),
        };
        assert!(err.to_string().contains(crate::proto::jls::ERR_AUTH_FAILED), "{err}");
    }

    #[tokio::test]
    async fn jls_incomplete_credentials_are_a_config_error() {
        // JLSOptions.Parse: both fields required when either is set.
        let mut option = ShadowQuicOption::new("server.example", 8443);
        option.username = "user1".into();
        option.password.clear();
        let err = match connect(&option).await {
            Err(e) => e,
            Ok(_) => panic!("incomplete credentials must be a config error"),
        };
        assert!(err.to_string().contains("jls: password is required"), "{err}");
        option.username.clear();
        option.password = "pass1".into();
        let err = match connect(&option).await {
            Err(e) => e,
            Ok(_) => panic!("incomplete credentials must be a config error"),
        };
        assert!(err.to_string().contains("jls: username is required"), "{err}");
    }

    // ------------------------------------------------------ loopback QUIC

    fn server_tls_config() -> Arc<rustls::ServerConfig> {
        let certified = rcgen::generate_simple_self_signed(vec!["sq.test".to_string()])
            .expect("rcgen self-signed cert");
        let cert = CertificateDer::from(certified.cert.der().to_vec());
        let key = PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let mut config = rustls::ServerConfig::builder_with_provider(Arc::new(
            ring_provider::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert], key)
        .expect("server config");
        config.alpn_protocols = vec![DEFAULT_ALPN.as_bytes().to_vec()];
        Arc::new(config)
    }

    fn quinn_server_config() -> quinn::ServerConfig {
        let quic_tls =
            quinn::crypto::rustls::QuicServerConfig::try_from(server_tls_config()).unwrap();
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_uni_streams(1024u32.into());
        transport.datagram_receive_buffer_size(Some(64 * 1024));
        config.transport_config(Arc::new(transport));
        config
    }

    #[derive(Default)]
    struct TestStats {
        tcp_streams: AtomicUsize,
        udp_associations: AtomicUsize,
    }

    /// The server side of one association, transcribed from
    /// `server.go:95-109` + `server.go:187-202` + the shared
    /// `packet.go:104-167` WriteTo: replies (`WriteBack` →
    /// `assoc.WriteTo(b, sourceAddr)`) allocate a send id per source,
    /// announce it over the control stream, and send in the negotiated
    /// mode.
    struct ServerAssoc {
        conn: quinn::Connection,
        control: Mutex<quinn::SendStream>,
        mode: UdpMode,
        send_ids: Mutex<HashMap<String, u16>>,
        uni_streams: Mutex<HashMap<String, quinn::SendStream>>,
        next_id: AtomicU16,
        /// Client registrations: id → destination (its packets' targets).
        targets: Mutex<HashMap<u16, NetAddr>>,
    }

    impl ServerAssoc {
        async fn write_back(&self, payload: &[u8], source: &NetAddr) {
            let key = source.to_string();
            let id = {
                let mut send_ids = self.send_ids.lock().await;
                match send_ids.get(&key) {
                    Some(id) => *id,
                    None => {
                        let id = self
                            .next_id
                            .fetch_add(1, Ordering::Relaxed)
                            .wrapping_add(0x8000);
                        let mut announce = Vec::with_capacity(19);
                        write_udp_control(&mut announce, source);
                        announce.extend_from_slice(&id.to_be_bytes());
                        let mut control = self.control.lock().await;
                        if control.write_all(&announce).await.is_err() {
                            return;
                        }
                        send_ids.insert(key.clone(), id);
                        id
                    }
                }
            };
            match self.mode {
                UdpMode::Datagram => {
                    if let Ok(datagram) = encode_datagram(id, payload) {
                        let _ = self.conn.send_datagram(datagram);
                    }
                }
                UdpMode::Stream => {
                    let mut packet = Vec::with_capacity(2 + payload.len());
                    if write_packet_stream_payload(&mut packet, payload).is_err() {
                        return;
                    }
                    let mut uni = self.uni_streams.lock().await;
                    let stream = match uni.get_mut(&key) {
                        Some(stream) => stream,
                        None => {
                            let Ok(mut stream) = self.conn.open_uni().await else {
                                return;
                            };
                            let mut header = Vec::with_capacity(2);
                            write_packet_stream_header(&mut header, id);
                            if stream.write_all(&header).await.is_err() {
                                return;
                            }
                            uni.insert(key.clone(), stream);
                            uni.get_mut(&key).expect("just inserted")
                        }
                    };
                    let _ = stream.write_all(&packet).await;
                }
            }
        }
    }

    /// Wait (bounded) for a client registration to name id's target —
    /// the tolerant equivalent of `waitRecvTarget` (`state.go:164-186`)
    /// for the mimic.
    async fn wait_for_target(assoc: &Arc<ServerAssoc>, id: u16) -> Option<NetAddr> {
        for _ in 0..2500 {
            if let Some(addr) = assoc.targets.lock().await.get(&id).cloned() {
                return Some(addr);
            }
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
        None
    }

    /// `server.go:63-72 handleConnection` + `handleStream:74-117`: every
    /// bidirectional stream is dispatched on its command byte; TCP
    /// connects echo, associate commands build the server-side
    /// association.
    async fn serve_connection(conn: quinn::Connection, stats: Arc<TestStats>) {
        let assoc: Arc<OnceLock<Arc<ServerAssoc>>> = Arc::new(OnceLock::new());
        // Client uni streams (udp-over-stream sends) route through the
        // association once it exists.
        let uni_state = Arc::clone(&assoc);
        let uni_conn = conn.clone();
        tokio::spawn(async move {
            loop {
                let Ok(mut stream) = uni_conn.accept_uni().await else {
                    return;
                };
                // The associate command precedes any packet stream, but
                // accept order is not guaranteed — wait briefly.
                let server_assoc = {
                    let mut found = None;
                    for _ in 0..500 {
                        if let Some(sa) = uni_state.get() {
                            found = Some(Arc::clone(sa));
                            break;
                        }
                        tokio::time::sleep(Duration::from_millis(2)).await;
                    }
                    match found {
                        Some(sa) => sa,
                        None => continue,
                    }
                };
                let Ok(id) = read_u16(&mut stream).await else {
                    return;
                };
                // handleUniStream (state.go:110-137): [len ‖ payload]...,
                // waiting for the registration (waitRecvTarget) rather
                // than dropping racing packets.
                loop {
                    let Ok(len) = read_u16(&mut stream).await else {
                        return;
                    };
                    let mut payload = vec![0u8; len as usize];
                    if stream.read_exact(&mut payload).await.is_err() {
                        return;
                    }
                    let source = wait_for_target(&server_assoc, id).await;
                    if let Some(source) = source {
                        server_assoc.write_back(&payload, &source).await;
                    }
                }
            }
        });

        while let Ok((send, mut recv)) = conn.accept_bi().await {
            let mut command = [0u8; 1];
            if recv.read_exact(&mut command).await.is_err() {
                break;
            }
            match command[0] {
                COMMAND_CONNECT => {
                    // handleStream:82-94 — relay (echo here).
                    let Ok(_addr) = read_socks_addr(&mut recv).await else {
                        break;
                    };
                    stats.tcp_streams.fetch_add(1, Ordering::Relaxed);
                    tokio::spawn(async move {
                        let (mut send, mut recv) = (send, recv);
                        let mut buf = [0u8; 4096];
                        while let Ok(Some(n)) = recv.read(&mut buf).await {
                            if send.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        let _ = send.finish();
                    });
                }
                COMMAND_ASSOCIATE_DATAGRAM | COMMAND_ASSOCIATE_STREAM => {
                    // handleStream:95-109: unspecified addr, then the
                    // shared association machinery.
                    let Ok(_addr) = read_socks_addr(&mut recv).await else {
                        break;
                    };
                    stats.udp_associations.fetch_add(1, Ordering::Relaxed);
                    let mode = if command[0] == COMMAND_ASSOCIATE_DATAGRAM {
                        UdpMode::Datagram
                    } else {
                        UdpMode::Stream
                    };
                    let server_assoc = Arc::new(ServerAssoc {
                        conn: conn.clone(),
                        control: Mutex::new(send),
                        mode,
                        send_ids: Mutex::new(HashMap::new()),
                        uni_streams: Mutex::new(HashMap::new()),
                        next_id: AtomicU16::new(0),
                        targets: Mutex::new(HashMap::new()),
                    });
                    let _ = assoc.set(Arc::clone(&server_assoc));
                    // The server's readControl (packet.go:59-72) over
                    // the client's registrations.
                    let registration_assoc = Arc::clone(&server_assoc);
                    tokio::spawn(async move {
                        loop {
                            let Ok(addr) = read_socks_addr(&mut recv).await else {
                                return;
                            };
                            let Ok(id) = read_u16(&mut recv).await else {
                                return;
                            };
                            registration_assoc.targets.lock().await.insert(id, addr);
                        }
                    });
                    // handleDatagrams (state.go:84-97) + handleAssociation
                    // echoing back to the source (server.go:187-202).
                    if mode == UdpMode::Datagram {
                        let datagram_assoc = Arc::clone(&server_assoc);
                        tokio::spawn(async move {
                            loop {
                                let Ok(message) = datagram_assoc.conn.read_datagram().await
                                else {
                                    return;
                                };
                                if let Ok((id, payload)) = decode_datagram(&message) {
                                    let source =
                                        datagram_assoc.targets.lock().await.get(&id).cloned();
                                    if let Some(source) = source {
                                        datagram_assoc.write_back(payload, &source).await;
                                    }
                                }
                            }
                        });
                    }
                }
                _ => {
                    // Unknown commands drain (handleStream default).
                    tokio::spawn(async move {
                        let mut buf = [0u8; 512];
                        while let Ok(Some(_)) = recv.read(&mut buf).await {}
                    });
                }
            }
        }
    }

    async fn start_server() -> (Arc<TestStats>, SocketAddr, quinn::Endpoint) {
        serve_forever(quinn::Endpoint::server(
            quinn_server_config(),
            SocketAddr::from(([127, 0, 0, 1], 0)),
        )
        .expect("server endpoint"))
        .await
    }

    /// A JLS-terminating QUIC server: the handshake runs on the engine's
    /// own TLS 1.3 stack (validating + stamping the JLS randoms), the
    /// framing layer above is the same mimic.
    async fn start_jls_server(users: Vec<crate::proto::jls::JlsUser>) -> (Arc<TestStats>, SocketAddr, quinn::Endpoint) {
        serve_forever(
            crate::quic::tls13::test_server::start_quinn_server(
                crate::quic::tls13::ServerMode::Jls { users },
            )
            .await
            .expect("jls server endpoint"),
        )
        .await
    }

    async fn serve_forever(endpoint: quinn::Endpoint) -> (Arc<TestStats>, SocketAddr, quinn::Endpoint) {
        let addr = endpoint.local_addr().expect("local addr");
        let stats = Arc::new(TestStats::default());
        let server_stats = Arc::clone(&stats);
        let server_endpoint = endpoint.clone();
        tokio::spawn(async move {
            // Serve (server.go:46-57).
            while let Some(incoming) = server_endpoint.accept().await {
                if let Ok(conn) = incoming.await {
                    let stats = Arc::clone(&server_stats);
                    tokio::spawn(serve_connection(conn, stats));
                }
            }
        });
        (stats, addr, endpoint)
    }

    fn test_option(port: u16) -> ShadowQuicOption {
        let mut option = ShadowQuicOption::new("127.0.0.1", port);
        option.skip_cert_verify = true;
        option
    }

    #[tokio::test]
    async fn jls_tcp_relay_over_quic() {
        // The JLS cover rides the QUIC TLS handshake (the engine's own
        // TLS 1.3 stack under quinn's crypto trait), then the framing
        // layer relays as usual.
        let user = crate::proto::jls::JlsUser::new("jls-user", "jls-pass").unwrap();
        let (stats, addr, _endpoint) =
            start_jls_server(vec![user.clone()]).await;
        let mut option = test_option(addr.port());
        option.username = user.username.clone();
        option.password = user.password.clone();
        let client = connect(&option).await.unwrap();
        let target = NetAddr::domain("jls.example", 443).unwrap();
        let mut stream = client.dial_tcp(&target).await.unwrap();

        stream.write_all(b"jls over quic").await.unwrap();
        let mut buf = [0u8; 13];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"jls over quic");
        assert_eq!(stats.tcp_streams.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn jls_udp_datagram_mode_roundtrip() {
        let user = crate::proto::jls::JlsUser::new("jls-user", "jls-pass").unwrap();
        let (stats, addr, _endpoint) =
            start_jls_server(vec![user.clone()]).await;
        let mut option = test_option(addr.port());
        option.username = user.username.clone();
        option.password = user.password.clone();
        let client = connect(&option).await.unwrap();
        let assoc = client.listen_packet().await.unwrap();
        assert_eq!(assoc.mode(), UdpMode::Datagram);

        let target = NetAddr::domain("jls-udp.example", 53).unwrap();
        assert_eq!(assoc.send_to(b"jls dns", &target).await.unwrap(), 7);
        let packet = tokio::time::timeout(Duration::from_secs(10), assoc.recv_from())
            .await
            .expect("udp echo timed out")
            .expect("association closed");
        assert_eq!(&packet.data[..], b"jls dns");
        assert_eq!(packet.addr, target);
        assoc.close().await.unwrap();
        assert_eq!(stats.udp_associations.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn tcp_relay_over_quic() {
        let (stats, addr, _endpoint) = start_server().await;
        let client = connect(&test_option(addr.port())).await.unwrap();
        let target = NetAddr::domain("tcp.example", 443).unwrap();
        let mut stream = client.dial_tcp(&target).await.unwrap();

        stream.write_all(b"hello over shadowquic").await.unwrap();
        let mut buf = [0u8; 21];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"hello over shadowquic");

        // A larger payload crosses several QUIC segments.
        let payload: Vec<u8> = (0..6000u32).map(|i| (i % 251) as u8).collect();
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
        assert_eq!(stats.tcp_streams.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn udp_datagram_mode_roundtrip() {
        let (stats, addr, _endpoint) = start_server().await;
        let client = connect(&test_option(addr.port())).await.unwrap();
        let assoc = client.listen_packet().await.unwrap();
        assert_eq!(assoc.mode(), UdpMode::Datagram);

        // Two destinations exercise two send ids + registrations.
        let target = NetAddr::domain("udp.example", 53).unwrap();
        let other = NetAddr::domain("other.example", 123).unwrap();
        assert_eq!(assoc.send_to(b"dns query", &target).await.unwrap(), 9);
        assert_eq!(assoc.send_to(b"second", &target).await.unwrap(), 6);
        assert_eq!(assoc.send_to(b"third", &other).await.unwrap(), 5);

        // The echo returns with the source address the server announced
        // over the control stream (WriteUDPControl) — first the target
        // destination's packets.
        let packet = tokio::time::timeout(Duration::from_secs(10), assoc.recv_from())
            .await
            .expect("udp echo timed out")
            .expect("association closed");
        assert_eq!(&packet.data[..], b"dns query");
        assert_eq!(packet.addr, target);
        let packet = tokio::time::timeout(Duration::from_secs(10), assoc.recv_from())
            .await
            .expect("second echo timed out")
            .expect("association closed");
        assert_eq!(&packet.data[..], b"second");
        assert_eq!(packet.addr, target);
        assoc.close().await.unwrap();
        assert_eq!(stats.udp_associations.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn udp_over_stream_mode_roundtrip() {
        let (_stats, addr, _endpoint) = start_server().await;
        let mut option = test_option(addr.port());
        option.udp_over_stream = true;
        let client = connect(&option).await.unwrap();
        let assoc = client.listen_packet().await.unwrap();
        assert_eq!(assoc.mode(), UdpMode::Stream);

        let target = NetAddr::domain("udp.example", 53).unwrap();
        let other = NetAddr::domain("other.example", 123).unwrap();
        assert_eq!(assoc.send_to(b"stream one", &target).await.unwrap(), 10);
        assert_eq!(assoc.send_to(b"stream two", &target).await.unwrap(), 10);
        assert_eq!(assoc.send_to(b"stream three", &other).await.unwrap(), 12);

        // Replies arrive on server-initiated uni streams carrying the
        // announced id; the demux labels them with the control address.
        let packet = tokio::time::timeout(Duration::from_secs(10), assoc.recv_from())
            .await
            .expect("udp-over-stream echo timed out")
            .expect("association closed");
        assert_eq!(&packet.data[..], b"stream one");
        assert_eq!(packet.addr, target);
        let packet = tokio::time::timeout(Duration::from_secs(10), assoc.recv_from())
            .await
            .expect("second echo timed out")
            .expect("association closed");
        assert_eq!(&packet.data[..], b"stream two");
        assert_eq!(packet.addr, target);
        assoc.close().await.unwrap();
    }

    #[tokio::test]
    async fn udp_packets_before_registration_are_buffered() {
        // state.go:139-162: a datagram whose control registration has not
        // arrived yet waits in the slot (≤ 32) and is delivered once
        // storeRecv runs. Drive it directly through the ConnState.
        let (tx, mut rx) = mpsc::channel(PACKET_INPUT_QUEUE);
        let state = RecvRouter::default();
        state.feed_datagram(9, Bytes::from_static(b"early")).await;
        // Not yet delivered: no target.
        assert!(rx.try_recv().is_err());
        // Multiple early packets buffer up.
        state.feed_datagram(9, Bytes::from_static(b"early2")).await;
        // The registration flushes both, in order.
        state.store_recv(
                9,
                RecvTarget {
                    assoc: 1,
                    tx,
                    addr: NetAddr::domain("src.example", 7).unwrap(),
                },
            )
            .await;
        let first = rx.recv().await.unwrap();
        let second = rx.recv().await.unwrap();
        assert_eq!(&first.data[..], b"early");
        assert_eq!(&second.data[..], b"early2");
        assert_eq!(first.addr, NetAddr::domain("src.example", 7).unwrap());
        // A later datagram with the same id goes straight through.
        state.feed_datagram(9, Bytes::from_static(b"late")).await;
        assert_eq!(&rx.recv().await.unwrap().data[..], b"late");
        // Ownership: only the owning association removes the slot.
        state.remove_recv_ids(999, &[9]).await;
        state.feed_datagram(9, Bytes::from_static(b"still")).await;
        assert_eq!(&rx.recv().await.unwrap().data[..], b"still");
        state.remove_recv_ids(1, &[9]).await;
    }

    #[tokio::test]
    async fn send_id_allocation_wraps_and_reports_exhaustion() {
        // allocSendID skips the active set and wraps (state.go:227-243);
        // a fully occupied id space is "too many udp contexts".
        let state = RecvRouter::default();
        let first = state.alloc_send_id().await.unwrap();
        let second = state.alloc_send_id().await.unwrap();
        assert_ne!(first, second);
        {
            // Occupy every id.
            let mut inner = state.inner.lock().await;
            for id in 0..=u16::MAX {
                inner.active_send.insert(id);
            }
        }
        let err = state.alloc_send_id().await.unwrap_err();
        assert_eq!(err.to_string(), "network: shadowquic: too many udp contexts");
        {
            // Freeing `second` lets the wrap scan find it again.
            let mut inner = state.inner.lock().await;
            inner.active_send.remove(&second);
        }
        assert_eq!(state.alloc_send_id().await.unwrap(), second);
        // And the release API frees in bulk.
        state.release_send_ids(&[first]).await;
        let inner = state.inner.lock().await;
        assert!(!inner.active_send.contains(&first));
    }
}

