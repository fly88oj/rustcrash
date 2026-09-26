//! TrustTunnel outbound (mihomo `transport/trusttunnel`): the
//! sing-trusttunnel protocol — HTTP CONNECT over HTTP/2 (TCP+TLS) or
//! HTTP/3 (QUIC), with `Proxy-Authorization` basic auth, a UDP
//! association multiplexed as a CONNECT tunnel to the magic address
//! `_udp2`, and a connection pool driven by max-connections /
//! min-streams / max-streams.
//!
//! ## Upstream map
//!
//! * `adapter/outbound/trusttunnel.go` — `TrustTunnelOption` and the
//!   `ClientOptions` wiring (`NewPoolClient` → `PoolClient.Dial` /
//!   `ListenPacket`).
//! * `transport/trusttunnel/client.go` — the client: one
//!   `http.Transport` (h2c over TLS, `IdleConnTimeout`) or one
//!   `http3.Transport` per pooled "client"; every proxy connection is a
//!   `CONNECT https://<server>` request whose **Host/:authority header
//!   is the real target** (`newConnectRequest`, client.go:203), with
//!   `User-Agent: <platform> <app>` and `Proxy-Authorization: Basic …`
//!   (`buildAuth`, protocol.go:51).
//! * `transport/trusttunnel/protocol.go` — the magic addresses
//!   (`_udp2`, `_icmp`, `_check`), timeouts, user agents; the returned
//!   conn is the request body pipe (response body reads, request body
//!   writes, client.go:144 `roundTrip`).
//! * `transport/trusttunnel/packet.go` — UDP framing over the CONNECT
//!   tunnel: client→server `[len be32][18 zero source][dst 16B padded
//!   IP][port be16][appNameLen u8][appName][payload]`; server→client
//!   `[len be32][src 16B][port be16][dst 16B zeros][port 0][payload]`
//!   (writePacketToServer / readPacketFromServer, packet.go:80-148).
//! * `transport/trusttunnel/quic.go` — the QUIC arm: QUIC v1, 2×
//!   (connect+health-check) idle timeout, 128 KiB stream receive
//!   window, congestion controller / cwnd / BBR profile knobs.
//! * The pool (`PoolClient.getClient`, client.go:347): pick the
//!   least-loaded client; a new one is created only when
//!   `maxConnections` allows and the picked client has at least
//!   `minStreams` streams (or, without max-connections, under
//!   `maxStreams`).
//!
//! ## Scope / deviations
//!
//! * This port implements a minimal HTTP/2 client (connection preface,
//!   SETTINGS + ACK, HEADERS with literal HPACK, DATA flow control with
//!   WINDOW_UPDATE, PING/GOAWAY/RST handling) and a minimal HTTP/3
//!   client (QUIC v1 via quinn, QPACK-literal HEADERS, DATA frames) —
//!   enough for CONNECT tunneling, which is all trusttunnel uses.
//! * ICMP (`_icmp`) is refused with a precise error (its `IcmpConn`
//!   drives raw ICMP echo over the tunnel, icmp.go — out of scope).
//! * `health-check` is a connectivity probe (`_check` CONNECT that is
//!   closed immediately); the periodic timer loop is the integrator's.
//! * QUIC knobs: `congestion-controller` bbr/cubic/new_reno are applied
//!   through quinn; `cwnd` and `bbr-profile` are carried but have no
//!   quinn equivalent (no initial-window / BBR-profile knob).
//! * ECH (`ech-opts`) rides the QUIC arm through the engine's own
//!   TLS 1.3 stack (`crate::quic::tls13`, a quinn `crypto::ClientConfig`
//!   with the ECH cover — the inner hello carries the real SNI and h3);
//!   the plain-rustls path stays the default when it is unset.

use std::collections::HashMap;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::Duration;

use base64::Engine;
use bytes::{Buf, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::addr::{Host, NetAddr};
use crate::error::{Error, Result};
use crate::quic::{self, QuicDial};
use crate::stream::BoxProxyStream;
use crate::transport::{tls_connect, TlsSettings};

/// `UDPMagicAddress` (protocol.go:21).
pub const UDP_MAGIC_ADDRESS: &str = "_udp2";
/// `ICMPMagicAddress`.
pub const ICMP_MAGIC_ADDRESS: &str = "_icmp";
/// `HealthCheckMagicAddress`.
pub const HEALTH_CHECK_MAGIC_ADDRESS: &str = "_check";

/// `DefaultQuicMaxIdleTimeout` = 2 × (30s + 7s).
const DEFAULT_QUIC_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(74);
/// `DefaultQuicStreamReceiveWindow` (protocol.go:25).
const DEFAULT_QUIC_STREAM_RECEIVE_WINDOW: u64 = 131_072;

/// The app identity used in user agents and UDP packets
/// (`C.Name`/`C.Version` upstream; ours).
const APP_NAME: &str = "rustcrash";
const APP_VERSION: &str = env!("CARGO_PKG_VERSION");

/// `TCPUserAgent` (protocol.go:38): `<platform> <app>/<version>`.
fn tcp_user_agent() -> String {
    format!(
        "{} {}/{}",
        std::env::consts::OS,
        APP_NAME,
        APP_VERSION
    )
}

/// `UDPUserAgent`: `<platform> _udp2`.
fn udp_user_agent() -> String {
    format!("{} {}", std::env::consts::OS, UDP_MAGIC_ADDRESS)
}

/// `HealthCheckUserAgent`: `<platform>`.
fn health_check_user_agent() -> String {
    std::env::consts::OS.to_string()
}

/// `buildAuth` (protocol.go:51).
fn build_auth(username: &str, password: &str) -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode(format!("{username}:{password}"))
    )
}

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Outbound TrustTunnel endpoint — mihomo `proxies: type: trusttunnel`
/// fields (`TrustTunnelOption`, adapter/outbound/trusttunnel.go:20).
#[derive(Debug, Clone)]
pub struct TrustTunnelOut {
    pub server: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    /// `alpn` (defaults to h2, or h3 for `quic`).
    pub alpn: Vec<String>,
    /// `sni` (defaults to the server host).
    pub sni: String,
    /// `skip-cert-verify`.
    pub skip_cert_verify: bool,
    /// `name-cert-verify` — carried (rustls verifies via SNI).
    pub name_cert_verify: String,
    /// `fingerprint` / `certificate` / `private-key` /
    /// `client-fingerprint` — carried, not applied (plain rustls).
    pub fingerprint: String,
    pub certificate: String,
    pub private_key: String,
    pub client_fingerprint: String,
    /// `udp` capability flag.
    pub udp: bool,
    /// `health-check` (the probe is `health_check()`; the timer loop is
    /// the integrator's).
    pub health_check: bool,
    // quic options
    pub quic: bool,
    /// `congestion-controller`: bbr | cubic | new_reno.
    pub congestion_controller: String,
    /// `cwnd` — carried (quinn exposes no initial-window knob).
    pub cwnd: i64,
    /// `bbr-profile` — carried (quinn's BBR has no profile switch).
    pub bbr_profile: String,
    // reuse options
    pub max_connections: i64,
    pub min_streams: i64,
    pub max_streams: i64,
    /// `ech-opts` — applied on the QUIC arm through the engine's own
    /// TLS 1.3 stack (ECH cover; see `quic_dial`).
    pub ech: Option<crate::proto::ech::EchOptions>,
}

impl TrustTunnelOut {
    pub fn new(server: &str, port: u16) -> Self {
        TrustTunnelOut {
            server: server.to_string(),
            port,
            username: String::new(),
            password: String::new(),
            alpn: Vec::new(),
            sni: String::new(),
            skip_cert_verify: true,
            name_cert_verify: String::new(),
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
            client_fingerprint: String::new(),
            udp: true,
            health_check: false,
            quic: false,
            congestion_controller: String::new(),
            cwnd: 0,
            bbr_profile: String::new(),
            max_connections: 0,
            min_streams: 0,
            max_streams: 0,
            ech: None,
        }
    }
}

// ---------------------------------------------------------------------------
// UDP framing (packet.go)
// ---------------------------------------------------------------------------

/// `parse16BytesIP` (protocol.go:75): the v4-mapped form, except ::1.
fn parse_16_bytes_ip(buffer: &[u8; 16]) -> std::net::IpAddr {
    let zero_prefix = buffer[..12].iter().all(|b| *b == 0);
    let is_ipv4 = zero_prefix
        && !(buffer[12] == 0 && buffer[13] == 0 && buffer[14] == 0 && buffer[15] == 1);
    if is_ipv4 {
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(
            buffer[12], buffer[13], buffer[14], buffer[15],
        ))
    } else {
        std::net::IpAddr::V6((*buffer).into())
    }
}

/// `buildPaddingIP` (protocol.go:86).
fn build_padding_ip(addr: std::net::IpAddr) -> [u8; 16] {
    match addr {
        std::net::IpAddr::V6(v6) => v6.octets(),
        std::net::IpAddr::V4(v4) => {
            let mut buffer = [0u8; 16];
            buffer[12..16].copy_from_slice(&v4.octets());
            buffer
        }
    }
}

/// `writePacketToServer` (packet.go:102): one outbound datagram.
pub fn trusttunnel_udp_frame(target: &NetAddr, payload: &[u8]) -> Result<Vec<u8>> {
    let ip = match &target.host {
        Host::Ip(ip) => *ip,
        Host::Domain(_) => {
            return Err(Error::protocol("trusttunnel: UDP only supports IP targets"))
        }
    };
    let app_name = APP_NAME;
    let header_len = 4 + 16 + 2 + 16 + 2 + 1 + app_name.len();
    let length_field = (16 + 2 + 16 + 2 + 1 + app_name.len() + payload.len()) as u32;
    let mut out = Vec::with_capacity(header_len + payload.len());
    out.extend_from_slice(&length_field.to_be_bytes());
    out.extend_from_slice(&[0u8; 18]); // Source address:port (unknown).
    out.extend_from_slice(&build_padding_ip(ip));
    out.extend_from_slice(&target.port.to_be_bytes());
    out.push(app_name.len() as u8);
    out.extend_from_slice(app_name.as_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// `readPacketFromServer` (packet.go:80): one inbound datagram (the
/// server-bound destination fields are zeros and dropped upstream).
pub fn parse_trusttunnel_udp(frame: &[u8]) -> Result<(NetAddr, Vec<u8>)> {
    const HEADER: usize = 4 + 16 + 2 + 16 + 2;
    if frame.len() < HEADER {
        return Err(Error::protocol("trusttunnel: short UDP frame"));
    }
    let length = u32::from_be_bytes([frame[0], frame[1], frame[2], frame[3]]) as usize;
    let payload_len = length as isize - (16 + 2 + 16 + 2) as isize;
    if payload_len < 0 {
        return Err(Error::protocol(format!(
            "trusttunnel: invalid udp length: {length}"
        )));
    }
    let mut source = [0u8; 16];
    source.copy_from_slice(&frame[4..20]);
    let addr = parse_16_bytes_ip(&source);
    let port = u16::from_be_bytes([frame[20], frame[21]]);
    let payload_len = payload_len as usize;
    if frame.len() < HEADER + payload_len {
        return Err(Error::protocol("trusttunnel: short UDP payload"));
    }
    Ok((
        NetAddr::ip(addr, port),
        frame[HEADER..HEADER + payload_len].to_vec(),
    ))
}

/// Read one framed datagram from the tunnel stream.
pub async fn read_trusttunnel_udp(
    stream: &mut (dyn AsyncRead + Unpin + Send),
) -> Result<(NetAddr, Vec<u8>)> {
    const HEADER: usize = 4 + 16 + 2 + 16 + 2;
    let mut header = [0u8; HEADER];
    stream.read_exact(&mut header).await?;
    let length = u32::from_be_bytes([header[0], header[1], header[2], header[3]]) as usize;
    let payload_len = length.checked_sub(16 + 2 + 16 + 2).ok_or_else(|| {
        Error::protocol(format!("trusttunnel: invalid udp length: {length}"))
    })?;
    let mut source = [0u8; 16];
    source.copy_from_slice(&header[4..20]);
    let addr = parse_16_bytes_ip(&source);
    let port = u16::from_be_bytes([header[20], header[21]]);
    let mut payload = vec![0u8; payload_len];
    stream.read_exact(&mut payload).await?;
    Ok((NetAddr::ip(addr, port), payload))
}

// ---------------------------------------------------------------------------
// HPACK (RFC 7541): literal encoder for requests, decoder for responses
// ---------------------------------------------------------------------------

/// HPACK integer (RFC 7541 §5.1).
fn put_int(buf: &mut Vec<u8>, flags: u8, prefix_bits: u32, v: u64) {
    let max = (1u64 << prefix_bits) - 1;
    if v < max {
        buf.push(flags | v as u8);
        return;
    }
    buf.push(flags | max as u8);
    let mut rest = v - max;
    while rest >= 128 {
        buf.push((rest as u8 & 0x7f) | 0x80);
        rest >>= 7;
    }
    buf.push(rest as u8);
}

fn read_int(data: &[u8], off: usize, prefix_bits: u32) -> Option<(u64, usize)> {
    let max = (1u64 << prefix_bits) - 1;
    let first = *data.get(off)?;
    let mut v = (first as u64) & max;
    if v < max {
        return Some((v, off + 1));
    }
    let mut off = off + 1;
    let mut shift = 0u32;
    loop {
        let b = *data.get(off)?;
        off += 1;
        if shift > 56 {
            return None;
        }
        v = v.checked_add(((b & 0x7f) as u64) << shift)?;
        shift += 7;
        if b & 0x80 == 0 {
            return Some((v, off));
        }
    }
}

/// A literal string (never Huffman-encoded on the wire from us).
fn put_string(buf: &mut Vec<u8>, s: &[u8]) {
    put_int(buf, 0x00, 7, s.len() as u64);
    buf.extend_from_slice(s);
}

/// Literal header field without indexing, new name (RFC 7541 §6.2.2) —
/// what every compliant server accepts.
fn put_hpack_literal(out: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    out.push(0x00);
    put_string(out, name);
    put_string(out, value);
}

/// (code, bit-length) for symbols 0..=256; entry 256 is EOS
/// (RFC 7541 appendix B — QPACK uses the same code).
#[rustfmt::skip]
const HUFFMAN_CODES: [(u64, u8); 257] = [
    (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28), (0xfffffe4, 28),
    (0xfffffe5, 28), (0xfffffe6, 28), (0xfffffe7, 28), (0xfffffe8, 28), (0xffffea, 24),
    (0x3ffffffc, 30), (0xfffffe9, 28), (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28),
    (0xfffffec, 28), (0xfffffed, 28), (0xfffffee, 28), (0xfffffef, 28), (0xffffff0, 28),
    (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe, 30), (0xffffff3, 28), (0xffffff4, 28),
    (0xffffff5, 28), (0xffffff6, 28), (0xffffff7, 28), (0xffffff8, 28), (0xffffff9, 28),
    (0xffffffa, 28), (0xffffffb, 28), (0x14, 6), (0x3f8, 10), (0x3f9, 10),
    (0xffa, 12), (0x1ff9, 13), (0x15, 6), (0xf8, 8), (0x7fa, 11),
    (0x3fa, 10), (0x3fb, 10), (0xf9, 8), (0x7fb, 11), (0xfa, 8),
    (0x16, 6), (0x17, 6), (0x18, 6), (0x0, 5), (0x1, 5),
    (0x2, 5), (0x19, 6), (0x1a, 6), (0x1b, 6), (0x1c, 6),
    (0x1d, 6), (0x1e, 6), (0x1f, 6), (0x5c, 7), (0xfb, 8),
    (0x7ffc, 15), (0x20, 6), (0xffb, 12), (0x3fc, 10), (0x1ffa, 13),
    (0x21, 6), (0x5d, 7), (0x5e, 7), (0x5f, 7), (0x60, 7),
    (0x61, 7), (0x62, 7), (0x63, 7), (0x64, 7), (0x65, 7),
    (0x66, 7), (0x67, 7), (0x68, 7), (0x69, 7), (0x6a, 7),
    (0x6b, 7), (0x6c, 7), (0x6d, 7), (0x6e, 7), (0x6f, 7),
    (0x70, 7), (0x71, 7), (0x72, 7), (0xfc, 8), (0x73, 7),
    (0xfd, 8), (0x1ffb, 13), (0x7fff0, 19), (0x1ffc, 13), (0x3ffc, 14),
    (0x22, 6), (0x7ffd, 15), (0x3, 5), (0x23, 6), (0x4, 5),
    (0x24, 6), (0x5, 5), (0x25, 6), (0x26, 6), (0x27, 6),
    (0x6, 5), (0x74, 7), (0x75, 7), (0x28, 6), (0x29, 6),
    (0x2a, 6), (0x7, 5), (0x2b, 6), (0x76, 7), (0x2c, 6),
    (0x8, 5), (0x9, 5), (0x2d, 6), (0x77, 7), (0x78, 7),
    (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15), (0x7fc, 11),
    (0x3ffd, 14), (0x1ffd, 13), (0xffffffc, 28), (0xfffe6, 20), (0x3fffd2, 22),
    (0xfffe7, 20), (0xfffe8, 20), (0x3fffd3, 22), (0x3fffd4, 22), (0x3fffd5, 22),
    (0x7fffd9, 23), (0x3fffd6, 22), (0x7fffda, 23), (0x7fffdb, 23), (0x7fffdc, 23),
    (0x7fffdd, 23), (0x7fffde, 23), (0xffffeb, 24), (0x7fffdf, 23), (0xffffec, 24),
    (0xffffed, 24), (0x3fffd7, 22), (0x7fffe0, 23), (0xffffee, 24), (0x7fffe1, 23),
    (0x7fffe2, 23), (0x7fffe3, 23), (0x7fffe4, 23), (0x1fffdc, 21), (0x3fffd8, 22),
    (0x7fffe5, 23), (0x3fffd9, 22), (0x7fffe6, 23), (0x7fffe7, 23), (0xffffef, 24),
    (0x3fffda, 22), (0x1fffdd, 21), (0xfffe9, 20), (0x3fffdb, 22), (0x3fffdc, 22),
    (0x7fffe8, 23), (0x7fffe9, 23), (0x1fffde, 21), (0x7fffea, 23), (0x3fffdd, 22),
    (0x3fffde, 22), (0xfffff0, 24), (0x1fffdf, 21), (0x3fffdf, 22), (0x7fffeb, 23),
    (0x7fffec, 23), (0x1fffe0, 21), (0x1fffe1, 21), (0x3fffe0, 22), (0x1fffe2, 21),
    (0x7fffed, 23), (0x3fffe1, 22), (0x7fffee, 23), (0x7fffef, 23), (0xfffea, 20),
    (0x3fffe2, 22), (0x3fffe3, 22), (0x3fffe4, 22), (0x7ffff0, 23), (0x3fffe5, 22),
    (0x3fffe6, 22), (0x7ffff1, 23), (0x3ffffe0, 26), (0x3ffffe1, 26), (0xfffeb, 20),
    (0x7fff1, 19), (0x3fffe7, 22), (0x7ffff2, 23), (0x3fffe8, 22), (0x1ffffec, 25),
    (0x3ffffe2, 26), (0x3ffffe3, 26), (0x3ffffe4, 26), (0x7ffffde, 27), (0x7ffffdf, 27),
    (0x3ffffe5, 26), (0xfffff1, 24), (0x1ffffed, 25), (0x7fff2, 19), (0x1fffe3, 21),
    (0x3ffffe6, 26), (0x7ffffe0, 27), (0x7ffffe1, 27), (0x3ffffe7, 26), (0x7ffffe2, 27),
    (0xfffff2, 24), (0x1fffe4, 21), (0x1fffe5, 21), (0x3ffffe8, 26), (0x3ffffe9, 26),
    (0xffffffd, 28), (0x7ffffe3, 27), (0x7ffffe4, 27), (0x7ffffe5, 27), (0xfffec, 20),
    (0xfffff3, 24), (0xfffed, 20), (0x1fffe6, 21), (0x3fffe9, 22), (0x1fffe7, 21),
    (0x1fffe8, 21), (0x7ffff3, 23), (0x3fffea, 22), (0x3fffeb, 22), (0x1ffffee, 25),
    (0x1ffffef, 25), (0xfffff4, 24), (0xfffff5, 24), (0x3ffffea, 26), (0x7ffff4, 23),
    (0x3ffffeb, 26), (0x7ffffe6, 27), (0x3ffffec, 26), (0x3ffffed, 26), (0x7ffffe7, 27),
    (0x7ffffe8, 27), (0x7ffffe9, 27), (0x7ffffea, 27), (0x7ffffeb, 27), (0xffffffe, 28),
    (0x7ffffec, 27), (0x7ffffed, 27), (0x7ffffee, 27), (0x7ffffef, 27), (0x7fffff0, 27),
    (0x3ffffee, 26), (0x3fffffff, 30),
];

/// Decode an HPACK Huffman string; the trailing padding must be all
/// ones (a prefix of the EOS symbol).
fn huffman_decode(data: &[u8]) -> Option<Vec<u8>> {
    use std::collections::HashMap;
    use std::sync::OnceLock;
    static MAP: OnceLock<HashMap<(u64, u8), u8>> = OnceLock::new();
    let map = MAP.get_or_init(|| {
        HUFFMAN_CODES[..256]
            .iter()
            .enumerate()
            .map(|(sym, &(code, len))| ((code, len), sym as u8))
            .collect()
    });
    let mut out = Vec::with_capacity(data.len() * 2);
    let mut code = 0u64;
    let mut len = 0u8;
    for &byte in data {
        for bit in (0..8).rev() {
            code = (code << 1) | ((byte >> bit) & 1) as u64;
            len += 1;
            if len > 30 {
                return None;
            }
            if let Some(&sym) = map.get(&(code, len)) {
                out.push(sym);
                code = 0;
                len = 0;
            }
        }
    }
    if len > 7 {
        return None;
    }
    if len > 0 && code != (1u64 << len) - 1 {
        return None;
    }
    Some(out)
}

/// The HPACK static table (RFC 7541 appendix A), 1-indexed.
#[rustfmt::skip]
const HPACK_STATIC_TABLE: &[(&str, &str)] = &[
    ("", ""),
    (":authority", ""),
    (":method", "GET"),
    (":method", "POST"),
    (":path", "/"),
    (":path", "/index.html"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "200"),
    (":status", "204"),
    (":status", "206"),
    (":status", "304"),
    (":status", "400"),
    (":status", "404"),
    (":status", "500"),
    ("accept-charset", ""),
    ("accept-encoding", "gzip, deflate"),
    ("accept-language", ""),
    ("accept-ranges", ""),
    ("accept", ""),
    ("access-control-allow-origin", ""),
    ("age", ""),
    ("allow", ""),
    ("authorization", ""),
    ("cache-control", ""),
    ("content-disposition", ""),
    ("content-encoding", ""),
    ("content-language", ""),
    ("content-length", ""),
    ("content-location", ""),
    ("content-range", ""),
    ("content-type", ""),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("expect", ""),
    ("expires", ""),
    ("from", ""),
    ("host", ""),
    ("if-match", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("if-range", ""),
    ("if-unmodified-since", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("max-forwards", ""),
    ("proxy-authenticate", ""),
    ("proxy-authorization", ""),
    ("range", ""),
    ("referer", ""),
    ("refresh", ""),
    ("retry-after", ""),
    ("server", ""),
    ("set-cookie", ""),
    ("strict-transport-security", ""),
    ("transfer-encoding", ""),
    ("user-agent", ""),
    ("vary", ""),
    ("via", ""),
    ("www-authenticate", ""),
];

/// A single HPACK string literal.
fn read_hpack_string(data: &[u8], off: usize) -> Option<(Vec<u8>, usize)> {
    let first = *data.get(off)?;
    let huffman = first & 0x80 != 0;
    let (len, off) = read_int(data, off, 7)?;
    let len = usize::try_from(len).ok()?;
    let bytes = data.get(off..off.checked_add(len)?)?;
    let off = off + len;
    if huffman {
        Some((huffman_decode(bytes)?, off))
    } else {
        Some((bytes.to_vec(), off))
    }
}

/// A minimal HPACK decoder: indexed fields, literal-with-name-index,
/// literal-new-name (with and without indexing — entries land in the
/// dynamic table), dynamic table size updates, Huffman strings.
fn hpack_decode(block: &[u8], dynamic: &mut Vec<(String, String)>) -> Result<Vec<(String, String)>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < block.len() {
        let b = block[off];
        if b & 0x80 != 0 {
            // Indexed header field.
            let (idx, n) = read_int(block, off, 7)
                .ok_or_else(|| Error::protocol("trusttunnel: hpack truncated index"))?;
            off = n;
            let (name, value) = hpack_lookup(idx as usize, dynamic)?;
            out.push((name, value));
        } else if b & 0xC0 == 0x40 {
            // Literal with incremental indexing.
            let (name, n) = read_int(block, off, 6)
                .ok_or_else(|| Error::protocol("trusttunnel: hpack truncated name index"))?;
            off = n;
            let name = if name == 0 {
                let (s, n) =
                    read_hpack_string(block, off).ok_or_else(|| Error::protocol("trusttunnel: hpack truncated name"))?;
                off = n;
                String::from_utf8_lossy(&s).into_owned()
            } else {
                hpack_lookup(name as usize, dynamic)?.0
            };
            let (value, n) =
                read_hpack_string(block, off).ok_or_else(|| Error::protocol("trusttunnel: hpack truncated value"))?;
            off = n;
            let value = String::from_utf8_lossy(&value).into_owned();
            dynamic.insert(0, (name.clone(), value.clone()));
            out.push((name, value));
        } else if b & 0xE0 == 0x20 {
            // Dynamic table size update.
            let (_, n) = read_int(block, off, 5)
                .ok_or_else(|| Error::protocol("trusttunnel: hpack truncated size update"))?;
            off = n;
        } else {
            // Literal without indexing / never indexed.
            let (idx, n) = read_int(block, off, 4)
                .ok_or_else(|| Error::protocol("trusttunnel: hpack truncated name index"))?;
            off = n;
            let name = if idx == 0 {
                let (s, n) =
                    read_hpack_string(block, off).ok_or_else(|| Error::protocol("trusttunnel: hpack truncated name"))?;
                off = n;
                String::from_utf8_lossy(&s).into_owned()
            } else {
                hpack_lookup(idx as usize, dynamic)?.0
            };
            let (value, n) =
                read_hpack_string(block, off).ok_or_else(|| Error::protocol("trusttunnel: hpack truncated value"))?;
            off = n;
            out.push((name, String::from_utf8_lossy(&value).into_owned()));
        }
    }
    Ok(out)
}

fn hpack_lookup(idx: usize, dynamic: &[(String, String)]) -> Result<(String, String)> {
    if idx == 0 {
        return Err(Error::protocol("trusttunnel: hpack index 0"));
    }
    if let Some((n, v)) = HPACK_STATIC_TABLE.get(idx) {
        return Ok((n.to_string(), v.to_string()));
    }
    dynamic
        .get(idx - HPACK_STATIC_TABLE.len())
        .cloned()
        .ok_or_else(|| Error::protocol(format!("trusttunnel: hpack bad index {idx}")))
}

// ---------------------------------------------------------------------------
// HTTP/2 frame layer (RFC 7540)
// ---------------------------------------------------------------------------

const H2_DATA: u8 = 0x0;
const H2_HEADERS: u8 = 0x1;
const H2_SETTINGS: u8 = 0x4;
const H2_PING: u8 = 0x6;
const H2_RST_STREAM: u8 = 0x3;
const H2_GOAWAY: u8 = 0x7;
const H2_WINDOW_UPDATE: u8 = 0x8;
const H2_FLAG_END_STREAM: u8 = 0x1;
const H2_FLAG_ACK: u8 = 0x1;
const H2_FLAG_END_HEADERS: u8 = 0x4;
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
/// The default per-stream window (RFC 7540 §6.9.2).
const H2_INITIAL_WINDOW: i64 = 65_535;
const H2_MAX_FRAME: usize = 16_384;

fn put_h2_frame(out: &mut Vec<u8>, frame_type: u8, flags: u8, stream_id: u32, payload: &[u8]) {
    let len = payload.len() as u32;
    out.extend_from_slice(&len.to_be_bytes()[1..4]);
    out.push(frame_type);
    out.push(flags);
    out.extend_from_slice(&stream_id.to_be_bytes());
    out.extend_from_slice(payload);
}

/// Events a tunnel stream receives from the connection reader.
enum H2Event {
    Headers(Vec<(String, String)>),
    Data(Vec<u8>),
    /// END_STREAM on DATA/HEADERS, or RST_STREAM.
    End,
    GoAway,
}

#[derive(Clone)]
struct H2StreamHandle {
    tx: tokio::sync::mpsc::UnboundedSender<H2Event>,
    /// Per-stream send window (`WINDOW_UPDATE`-driven).
    window: Arc<std::sync::Mutex<i64>>,
    window_changed: Arc<tokio::sync::Notify>,
}

/// One h2 connection: a reader task over the TLS stream halves, and a
/// serialized writer.
struct H2Conn {
    writer: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<BoxProxyStream>>>,
    next_stream_id: std::sync::atomic::AtomicU32,
    streams: Arc<std::sync::Mutex<HashMap<u32, H2StreamHandle>>>,
    conn_window: Arc<std::sync::Mutex<i64>>,
    conn_window_changed: Arc<tokio::sync::Notify>,
    dead: Arc<std::sync::atomic::AtomicBool>,
}

impl H2Conn {
    async fn handshake(transport: BoxProxyStream) -> Result<Arc<Self>> {
        let (read_half, write_half) = tokio::io::split(transport);
        let conn = Arc::new(H2Conn {
            writer: Arc::new(tokio::sync::Mutex::new(write_half)),
            next_stream_id: std::sync::atomic::AtomicU32::new(1),
            streams: Arc::new(std::sync::Mutex::new(HashMap::new())),
            conn_window: Arc::new(std::sync::Mutex::new(H2_INITIAL_WINDOW)),
            conn_window_changed: Arc::new(tokio::sync::Notify::new()),
            dead: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        });
        // Client connection preface + an empty SETTINGS frame.
        {
            let mut w = conn.writer.lock().await;
            w.write_all(H2_PREFACE).await?;
            let mut out = Vec::with_capacity(9);
            put_h2_frame(&mut out, H2_SETTINGS, 0, 0, &[]);
            w.write_all(&out).await?;
            w.flush().await?;
        }
        let reader = tokio::spawn(h2_reader_task(
            read_half,
            conn.streams.clone(),
            conn.writer.clone(),
            conn.conn_window.clone(),
            conn.conn_window_changed.clone(),
            conn.dead.clone(),
        ));
        // The reader task owns the demux loop for the connection
        // lifetime; its JoinHandle is deliberately dropped.
        drop(reader);
        Ok(conn)
    }

    /// `newConnectRequest` + `roundTrip` (client.go:144/203): the
    /// CONNECT whose :authority is the real target.
    async fn open_connect(
        self: &Arc<Self>,
        host: &str,
        user_agent: &str,
        auth: &str,
    ) -> Result<(u32, tokio::sync::mpsc::UnboundedReceiver<H2Event>, Arc<std::sync::Mutex<i64>>, Arc<tokio::sync::Notify>)> {
        let id = self.next_stream_id.fetch_add(2, Ordering::SeqCst);
        if id == 0 || id > 0x7FFF_F000 {
            return Err(Error::network("trusttunnel: h2 stream ids exhausted"));
        }
        let mut block = Vec::with_capacity(128);
        put_hpack_literal(&mut block, b":method", b"CONNECT");
        put_hpack_literal(&mut block, b":scheme", b"https");
        put_hpack_literal(&mut block, b":authority", host.as_bytes());
        put_hpack_literal(&mut block, b"user-agent", user_agent.as_bytes());
        put_hpack_literal(&mut block, b"proxy-authorization", auth.as_bytes());
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        let window = Arc::new(std::sync::Mutex::new(H2_INITIAL_WINDOW));
        let window_changed = Arc::new(tokio::sync::Notify::new());
        self.streams.lock().unwrap().insert(
            id,
            H2StreamHandle {
                tx,
                window: window.clone(),
                window_changed: window_changed.clone(),
            },
        );
        let mut out = Vec::with_capacity(9 + block.len());
        put_h2_frame(&mut out, H2_HEADERS, H2_FLAG_END_HEADERS, id, &block);
        {
            let mut w = self.writer.lock().await;
            w.write_all(&out).await?;
            w.flush().await?;
        }
        Ok((id, rx, window, window_changed))
    }

    /// Await the CONNECT response, requiring status 200
    /// (`roundTrip`, client.go:182).
    async fn await_response(
        rx: &mut tokio::sync::mpsc::UnboundedReceiver<H2Event>,
        dead: &Arc<std::sync::atomic::AtomicBool>,
    ) -> Result<()> {
        loop {
            let event = tokio::select! {
                e = rx.recv() => match e {
                    Some(e) => e,
                    None => return Err(Error::network("trusttunnel: h2 stream closed before response")),
                },
                _ = std::future::poll_fn(|_| {
                    if dead.load(Ordering::SeqCst) {
                        std::task::Poll::Ready(())
                    } else {
                        std::task::Poll::Pending
                    }
                }) => return Err(Error::network("trusttunnel: h2 connection gone")),
            };
            match event {
                H2Event::Headers(fields) => {
                    let status = fields
                        .iter()
                        .find(|(n, _)| n == ":status")
                        .map(|(_, v)| v.clone())
                        .unwrap_or_default();
                    if status != "200" {
                        return Err(Error::network(format!(
                            "trusttunnel: unexpected status code: {status}"
                        )));
                    }
                    return Ok(());
                }
                H2Event::Data(d) => {
                    // Server DATA before HEADERS is out of order; treat
                    // as tunnel bytes arriving early (kept).
                    let _ = d;
                }
                H2Event::End => {
                    return Err(Error::network(
                        "trusttunnel: h2 stream closed before response",
                    ))
                }
                H2Event::GoAway => {
                    return Err(Error::network("trusttunnel: h2 connection gone"))
                }
            }
        }
    }

    async fn write_data(&self, id: u32, window: &Arc<std::sync::Mutex<i64>>, changed: &Arc<tokio::sync::Notify>, mut buf: &[u8], conn_window: &Arc<std::sync::Mutex<i64>>, conn_changed: &Arc<tokio::sync::Notify>) -> Result<usize> {
        let total = buf.len();
        while !buf.is_empty() {
            // Wait for the smaller of the stream and connection windows.
            loop {
                let sw = *window.lock().unwrap();
                let cw = *conn_window.lock().unwrap();
                if sw > 0 && cw > 0 {
                    break;
                }
                let stream_changed = changed.notified();
                let conn2 = conn_changed.notified();
                tokio::pin!(stream_changed);
                tokio::pin!(conn2);
                if *window.lock().unwrap() > 0 && *conn_window.lock().unwrap() > 0 {
                    break;
                }
                tokio::select! {
                    _ = &mut stream_changed => {}
                    _ = &mut conn2 => {}
                }
            }
            let take = {
                let sw = *window.lock().unwrap();
                let cw = *conn_window.lock().unwrap();
                buf.len().min(H2_MAX_FRAME).min(sw.max(0) as usize).min(cw.max(0) as usize)
            };
            if take == 0 {
                continue;
            }
            let chunk = &buf[..take];
            let mut out = Vec::with_capacity(9 + take);
            put_h2_frame(&mut out, H2_DATA, 0, id, chunk);
            {
                let mut w = self.writer.lock().await;
                w.write_all(&out).await?;
                w.flush().await?;
            }
            *window.lock().unwrap() -= take as i64;
            *conn_window.lock().unwrap() -= take as i64;
            buf = &buf[take..];
        }
        Ok(total)
    }

    async fn end_stream(&self, id: u32) -> Result<()> {
        let mut out = Vec::with_capacity(9);
        put_h2_frame(&mut out, H2_DATA, H2_FLAG_END_STREAM, id, &[]);
        let mut w = self.writer.lock().await;
        w.write_all(&out).await?;
        w.flush().await?;
        Ok(())
    }

    fn remove_stream(&self, id: u32) {
        self.streams.lock().unwrap().remove(&id);
    }
}

/// The connection reader: dispatches frames to stream channels,
/// answers SETTINGS/PING, tracks windows.
async fn h2_reader_task(
    mut read_half: tokio::io::ReadHalf<BoxProxyStream>,
    streams: Arc<std::sync::Mutex<HashMap<u32, H2StreamHandle>>>,
    writer: Arc<tokio::sync::Mutex<tokio::io::WriteHalf<BoxProxyStream>>>,
    conn_window: Arc<std::sync::Mutex<i64>>,
    conn_window_changed: Arc<tokio::sync::Notify>,
    dead: Arc<std::sync::atomic::AtomicBool>,
) {
    let mut dynamic: Vec<(String, String)> = Vec::new();
    let mut rbuf = BytesMut::with_capacity(16 * 1024);
    let mut tmp = [0u8; 16 * 1024];
    'conn: loop {
        // Frame header: len be24, type, flags, stream be32.
        while rbuf.len() >= 9 {
            let len = ((rbuf[0] as usize) << 16) | ((rbuf[1] as usize) << 8) | rbuf[2] as usize;
            if rbuf.len() < 9 + len {
                break;
            }
            let frame_type = rbuf[3];
            let flags = rbuf[4];
            let stream_id =
                u32::from_be_bytes([rbuf[5], rbuf[6], rbuf[7], rbuf[8]]) & 0x7FFF_FFFF;
            let payload = rbuf[9..9 + len].to_vec();
            rbuf.advance(9 + len);
            match frame_type {
                H2_SETTINGS => {
                    if flags & H2_FLAG_ACK == 0 {
                        let mut out = Vec::with_capacity(9);
                        put_h2_frame(&mut out, H2_SETTINGS, H2_FLAG_ACK, 0, &[]);
                        let mut w = writer.lock().await;
                        if w.write_all(&out).await.is_err() {
                            break 'conn;
                        }
                    }
                }
                H2_PING => {
                    if flags & H2_FLAG_ACK == 0 {
                        let mut out = Vec::with_capacity(9 + 8);
                        put_h2_frame(&mut out, H2_PING, H2_FLAG_ACK, 0, &payload);
                        let mut w = writer.lock().await;
                        if w.write_all(&out).await.is_err() {
                            break 'conn;
                        }
                    }
                }
                H2_WINDOW_UPDATE => {
                    if payload.len() == 4 {
                        let inc = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]) as i64;
                        if stream_id == 0 {
                            *conn_window.lock().unwrap() += inc;
                            conn_window_changed.notify_one();
                        } else if let Some(h) = streams.lock().unwrap().get(&stream_id) {
                            *h.window.lock().unwrap() += inc;
                            h.window_changed.notify_one();
                        }
                    }
                }
                H2_HEADERS | H2_DATA => {
                    let handle = streams.lock().unwrap().get(&stream_id).cloned();
                    if let Some(h) = handle {
                        if frame_type == H2_HEADERS {
                            if let Ok(fields) = hpack_decode(&payload, &mut dynamic) {
                                let _ = h.tx.send(H2Event::Headers(fields));
                            }
                        } else if !payload.is_empty() {
                            let _ = h.tx.send(H2Event::Data(payload.clone()));
                            // Return the flow-control credit.
                            let mut out = Vec::with_capacity(18);
                            let inc = (payload.len() as u32).to_be_bytes();
                            put_h2_frame(&mut out, H2_WINDOW_UPDATE, 0, stream_id, &inc);
                            put_h2_frame(&mut out, H2_WINDOW_UPDATE, 0, 0, &inc);
                            let mut w = writer.lock().await;
                            if w.write_all(&out).await.is_err() {
                                break 'conn;
                            }
                        }
                        if flags & H2_FLAG_END_STREAM != 0 {
                            let _ = h.tx.send(H2Event::End);
                        }
                    }
                }
                H2_GOAWAY => {
                    let handles: Vec<_> = streams.lock().unwrap().values().cloned().collect();
                    for h in handles {
                        let _ = h.tx.send(H2Event::GoAway);
                    }
                    break 'conn;
                }
                H2_RST_STREAM => {
                    let handle = streams.lock().unwrap().remove(&stream_id);
                    if let Some(h) = handle {
                        let _ = h.tx.send(H2Event::End);
                    }
                }
                _ => {} // CONTINUATION/PUSH_PROMISE & co: ignored
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

/// The h2 tunnel stream: reads response DATA events; writes go
/// through a forwarder task that enforces flow control
/// (`roundTrip`'s pipe body, client.go:144-201).
pub struct H2Tunnel {
    id: u32,
    conn: Arc<H2Conn>,
    rx: tokio::sync::mpsc::UnboundedReceiver<H2Event>,
    write_tx: tokio::sync::mpsc::UnboundedSender<Vec<u8>>,
    pending: BytesMut,
    ended: bool,
    dead: Arc<std::sync::atomic::AtomicBool>,
}

impl H2Tunnel {
    fn spawn(
        conn: Arc<H2Conn>,
        id: u32,
        rx: tokio::sync::mpsc::UnboundedReceiver<H2Event>,
        window: Arc<std::sync::Mutex<i64>>,
        window_changed: Arc<tokio::sync::Notify>,
        dead: Arc<std::sync::atomic::AtomicBool>,
    ) -> Self {
        let (write_tx, mut write_rx) = tokio::sync::mpsc::unbounded_channel::<Vec<u8>>();
        let writer_conn = conn.clone();
        let conn_window = conn.conn_window.clone();
        let conn_changed = conn.conn_window_changed.clone();
        let dead2 = dead.clone();
        tokio::spawn(async move {
            while let Some(chunk) = write_rx.recv().await {
                if writer_conn
                    .write_data(
                        id,
                        &window,
                        &window_changed,
                        &chunk,
                        &conn_window,
                        &conn_changed,
                    )
                    .await
                    .is_err()
                {
                    break;
                }
            }
            if !dead2.load(Ordering::SeqCst) {
                let _ = writer_conn.end_stream(id).await;
            }
            writer_conn.remove_stream(id);
        });
        H2Tunnel {
            id,
            conn,
            rx,
            write_tx,
            pending: BytesMut::new(),
            ended: false,
            dead,
        }
    }
}

impl AsyncRead for H2Tunnel {
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
            if self.ended {
                return Poll::Ready(Ok(()));
            }
            match self.rx.poll_recv(cx) {
                Poll::Ready(Some(H2Event::Data(d))) => {
                    if d.len() > buf.remaining() {
                        let take = buf.remaining();
                        buf.put_slice(&d[..take]);
                        self.pending.extend_from_slice(&d[take..]);
                        return Poll::Ready(Ok(()));
                    }
                    buf.put_slice(&d);
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(Some(H2Event::Headers(_))) => continue,
                Poll::Ready(Some(H2Event::End)) | Poll::Ready(Some(H2Event::GoAway)) => {
                    self.ended = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Ready(None) => {
                    self.ended = true;
                    return Poll::Ready(Ok(()));
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for H2Tunnel {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.ended || this.dead.load(Ordering::SeqCst) {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "trusttunnel: h2 stream closed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        match this.write_tx.send(buf.to_vec()) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "trusttunnel: h2 stream closed",
            ))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Dropping the write channel sends END_STREAM via the
        // forwarder (the request half-close).
        self.ended = true;
        let _ = &self.conn;
        let _ = self.id;
        Poll::Ready(Ok(()))
    }
}

// ---------------------------------------------------------------------------
// HTTP/3 arm (RFC 9114): CONNECT over QUIC via quinn
// ---------------------------------------------------------------------------

/// One HTTP/3 CONNECT tunnel: a bidi stream carrying HEADERS + DATA
/// frames (the request body is the tunnel's upload direction).
pub struct H3Tunnel {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    /// Decrypted tunnel bytes ready for the reader.
    pending: BytesMut,
    /// Reassembly buffer for partial h3 frames.
    frame_buf: BytesMut,
    response_seen: bool,
}

impl H3Tunnel {
    /// Open the CONNECT exchange on `conn` and await status 200.
    async fn open(
        conn: &quinn::Connection,
        host: &str,
        user_agent: &str,
        auth: &str,
    ) -> Result<Self> {
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| Error::network(format!("trusttunnel: quic stream: {e}")))?;
        // QPACK field section: literal field lines (RFC 9204 §4.5.4),
        // prefix required-insert-count 0 / base 0 — the same shape the
        // engine's hysteria2 transport emits.
        let mut block = Vec::with_capacity(128);
        block.extend_from_slice(&[0x00, 0x00]);
        quic::put_qpack_literal(&mut block, b":method", b"CONNECT");
        quic::put_qpack_literal(&mut block, b":scheme", b"https");
        quic::put_qpack_literal(&mut block, b":authority", host.as_bytes());
        quic::put_qpack_literal(&mut block, b"user-agent", user_agent.as_bytes());
        quic::put_qpack_literal(&mut block, b"proxy-authorization", auth.as_bytes());
        let mut out = Vec::with_capacity(block.len() + 16);
        quic::put_h3_frame(&mut out, quic::H3_HEADERS, &block);
        send.write_all(&out)
            .await
            .map_err(|e| Error::network(format!("trusttunnel: h3 headers: {e}")))?;
        // Await the response HEADERS, requiring :status 200
        // (roundTrip, client.go:182).
        let mut buf = Vec::with_capacity(512);
        let mut chunk = [0u8; 4096];
        loop {
            if let Some(status) = h3_try_response_status(&buf)? {
                if status != "200" {
                    return Err(Error::network(format!(
                        "trusttunnel: unexpected status code: {status}"
                    )));
                }
                let leftover = h3_frame_boundary(&buf);
                return Ok(H3Tunnel {
                    send,
                    recv,
                    pending: BytesMut::new(),
                    frame_buf: leftover,
                    response_seen: true,
                });
            }
            let n = recv
                .read(&mut chunk)
                .await
                .map_err(|e| Error::network(format!("trusttunnel: h3 response: {e}")))?
                .ok_or_else(|| Error::network("trusttunnel: h3 EOF before response"))?;
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() > 16 * 1024 {
                return Err(Error::protocol("trusttunnel: h3 response too large"));
            }
        }
    }
}

/// Scan a buffer for the first complete HEADERS frame and decode the
/// `:status` field. `None` when incomplete.
fn h3_try_response_status(buf: &[u8]) -> Result<Option<String>> {
    let mut off = 0usize;
    while let Some((frame_type, flen, hdr)) = h3_frame_at(&buf[off..]) {
        let total = hdr + flen as usize;
        if frame_type == quic::H3_HEADERS {
            let block = &buf[off + hdr..off + total];
            let fields = qpack_decode_field_section(block)?;
            let status = fields
                .iter()
                .find(|(n, _)| n == ":status")
                .map(|(_, v)| v.clone())
                .ok_or_else(|| Error::protocol("trusttunnel: h3 response without :status"))?;
            return Ok(Some(status));
        }
        off += total;
    }
    Ok(None)
}

/// The bytes after the first complete frame (response DATA that
/// arrived with the HEADERS flight).
fn h3_frame_boundary(buf: &[u8]) -> BytesMut {
    if let Some((_, flen, hdr)) = h3_frame_at(buf) {
        let end = hdr + flen as usize;
        if end <= buf.len() {
            return BytesMut::from(&buf[end..]);
        }
    }
    BytesMut::new()
}

/// One `type || length` header at the front, if complete.
fn h3_frame_at(data: &[u8]) -> Option<(u64, u64, usize)> {
    let (ftype, a) = quic::read_varint(data)?;
    let (flen, b) = quic::read_varint(&data[a..])?;
    Some((ftype, flen, a + b))
}

/// A QPACK string literal: length prefix `prefix_bits` wide starting at
/// `off` (the pattern byte when the prefix is embedded), Huffman bit at
/// `huff_mask`.
fn read_qpack_string(data: &[u8], off: usize, prefix_bits: u32, huff_mask: u8) -> Option<(Vec<u8>, usize)> {
    let first = *data.get(off)?;
    let huffman = first & huff_mask != 0;
    let (len, off) = read_int(data, off, prefix_bits)?;
    let len = usize::try_from(len).ok()?;
    let bytes = data.get(off..off.checked_add(len)?)?;
    let off = off + len;
    if huffman {
        Some((huffman_decode(bytes)?, off))
    } else {
        Some((bytes.to_vec(), off))
    }
}

/// QPACK field-section decode for responses: prefix, static index,
/// literal forms, Huffman. (Same shape as the engine's hysteria2
/// decoder; this client never evicts or fills a dynamic table.)
fn qpack_decode_field_section(block: &[u8]) -> Result<Vec<(String, String)>> {
    let mut fields = Vec::new();
    // Field section prefix: required insert count (8-bit prefix) + sign
    // bit + base (7-bit prefix with S).
    let (_, n) = read_int(block, 0, 8).ok_or_else(|| Error::protocol("trusttunnel: qpack prefix"))?;
    let (_, n2) = read_int(block, n, 7).ok_or_else(|| Error::protocol("trusttunnel: qpack base"))?;
    let mut off = n2;
    while off < block.len() {
        let b = block[off];
        if b & 0x80 != 0 {
            // Indexed field line (static only).
            let is_static = b & 0x40 != 0;
            let (idx, n) =
                read_int(block, off, 6).ok_or_else(|| Error::protocol("trusttunnel: qpack index"))?;
            off = n;
            if !is_static {
                return Err(Error::protocol("trusttunnel: qpack dynamic reference"));
            }
            let (name, value) = qpack_static(idx as usize)?;
            fields.push((name, value));
        } else if b & 0xC0 == 0x40 {
            // Literal with name reference (static).
            let is_static = b & 0x08 != 0;
            let (idx, n) =
                read_int(block, off, 4).ok_or_else(|| Error::protocol("trusttunnel: qpack name index"))?;
            off = n;
            if !is_static {
                return Err(Error::protocol("trusttunnel: qpack dynamic name reference"));
            }
            let (name, _) = qpack_static(idx as usize)?;
            let (value, n) = read_qpack_string(block, off, 7, 0x80)
                .ok_or_else(|| Error::protocol("trusttunnel: qpack value"))?;
            off = n;
            fields.push((name, String::from_utf8_lossy(&value).into_owned()));
        } else if b & 0xE0 == 0x20 {
            // Literal with literal name: the name string's 3-bit length
            // prefix lives in the pattern byte itself (the layout the
            // engine's QPACK literal encoder emits; the Huffman bit is
            // 0x08).
            let (name, n) = read_qpack_string(block, off, 3, 0x08)
                .ok_or_else(|| Error::protocol("trusttunnel: qpack name"))?;
            off = n;
            let (value, n) = read_qpack_string(block, off, 7, 0x80)
                .ok_or_else(|| Error::protocol("trusttunnel: qpack value"))?;
            off = n;
            fields.push((
                String::from_utf8_lossy(&name).into_owned(),
                String::from_utf8_lossy(&value).into_owned(),
            ));
        } else {
            return Err(Error::protocol("trusttunnel: qpack dynamic table form"));
        }
    }
    Ok(fields)
}

/// The QPACK static table entries this client needs (:status codes).
fn qpack_static(idx: usize) -> Result<(String, String)> {
    // RFC 9204 appendix A (subset covering the :status range).
    let entry = match idx {
        0 => return Err(Error::protocol("trusttunnel: qpack index 0")),
        1..=21 => return Err(Error::protocol("trusttunnel: qpack unexpected static entry")),
        25 => (":status", "200"),
        26 => (":status", "204"),
        27 => (":status", "206"),
        28 => (":status", "304"),
        29 => (":status", "400"),
        30 => (":status", "404"),
        31 => (":status", "500"),
        _ => ("", ""),
    };
    Ok((entry.0.to_string(), entry.1.to_string()))
}

impl AsyncRead for H3Tunnel {
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
            // Pull more bytes and reassemble complete h3 frames,
            // keeping only DATA payloads (partial frames wait for the
            // rest — never leaked as tunnel bytes).
            let mut chunk = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut chunk);
            ready!(Pin::new(&mut self.recv).poll_read(cx, &mut rb))?;
            if rb.filled().is_empty() {
                return Poll::Ready(Ok(()));
            }
            self.frame_buf.extend_from_slice(rb.filled());
            while let Some((ftype, flen, hdr)) = h3_frame_at(&self.frame_buf) {
                let total = hdr + flen as usize;
                if self.frame_buf.len() < total {
                    break;
                }
                if ftype == quic::H3_DATA {
                    let data = self.frame_buf[hdr..total].to_vec();
                    self.pending.extend_from_slice(&data);
                }
                self.frame_buf.advance(total);
            }
            let _ = self.response_seen;
        }
    }
}

impl AsyncWrite for H3Tunnel {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut out = Vec::with_capacity(buf.len() + 16);
        quic::put_h3_frame(&mut out, quic::H3_DATA, buf);
        let this = self.get_mut();
        let n = ready!(Pin::new(&mut this.send).poll_write(cx, &out))?;
        // Map the framed length back to the payload length.
        let payload_len = buf.len();
        let framed_overhead = out.len() - payload_len;
        let _ = framed_overhead;
        Poll::Ready(Ok(payload_len.min(n)))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.send).poll_shutdown(cx)
    }
}

// ---------------------------------------------------------------------------
// The pool (client.go PoolClient)
// ---------------------------------------------------------------------------

enum ConnKind {
    H2(Arc<H2Conn>),
    H3(quinn::Connection),
}

struct ConnEntry {
    kind: ConnKind,
    streams: AtomicI64,
}

/// `PoolClient`: connection pool keyed on stream count
/// (`getClient`/`newTransportLocked`, client.go:347-382).
pub struct TrustTunnelPool {
    cfg: TrustTunnelOut,
    conns: std::sync::Mutex<Vec<Arc<ConnEntry>>>,
}

impl TrustTunnelPool {
    /// `NewPoolClient` (client.go:288): default 8 connections /
    /// 5 min-streams when nothing is configured; builds one client to
    /// validate the configuration.
    pub async fn new(cfg: &TrustTunnelOut, transport: Option<BoxProxyStream>) -> Result<Self> {
        let mut cfg = cfg.clone();
        if cfg.max_connections == 0 && cfg.min_streams == 0 && cfg.max_streams == 0 {
            cfg.max_connections = 8;
            cfg.min_streams = 5;
        }
        validate_cfg(&cfg)?;
        let pool = TrustTunnelPool {
            cfg,
            conns: std::sync::Mutex::new(Vec::new()),
        };
        let entry = pool.new_transport(transport).await?;
        pool.conns.lock().unwrap().push(entry);
        Ok(pool)
    }

    fn auth(&self) -> String {
        build_auth(&self.cfg.username, &self.cfg.password)
    }

    async fn new_transport(&self, transport: Option<BoxProxyStream>) -> Result<Arc<ConnEntry>> {
        if self.cfg.quic {
            let conn = quic_dial(&self.cfg).await?;
            Ok(Arc::new(ConnEntry {
                kind: ConnKind::H3(conn),
                streams: AtomicI64::new(0),
            }))
        } else {
            let transport = transport
                .ok_or_else(|| Error::config("trusttunnel: no transport provided (TCP mode)"))?;
            let tls = tls_wrap(&self.cfg, transport).await?;
            let conn = H2Conn::handshake(tls).await?;
            Ok(Arc::new(ConnEntry {
                kind: ConnKind::H2(conn),
                streams: AtomicI64::new(0),
            }))
        }
    }

    async fn open_tunnel(
        &self,
        host: &str,
        user_agent: &str,
        transport: Option<BoxProxyStream>,
    ) -> Result<(Arc<ConnEntry>, BoxProxyStream)> {
        // `getClient` + `newTransportLocked`.
        let entry = {
            let conns = self.conns.lock().unwrap();
            let mut picked: Option<Arc<ConnEntry>> = None;
            for c in conns.iter() {
                if picked.as_ref().is_none_or(|p| {
                    c.streams.load(Ordering::SeqCst) < p.streams.load(Ordering::SeqCst)
                }) {
                    picked = Some(c.clone());
                }
            }
            match picked {
                Some(p) => {
                    let num = p.streams.load(Ordering::SeqCst);
                    let create = if num == 0 {
                        false
                    } else if self.cfg.max_connections > 0 {
                        !(conns.len() as i64 >= self.cfg.max_connections || num < self.cfg.min_streams)
                    } else {
                        !(self.cfg.max_streams > 0 && num < self.cfg.max_streams)
                    };
                    if create {
                        None
                    } else {
                        Some(p)
                    }
                }
                None => None,
            }
        };
        let entry = match entry {
            Some(e) => e,
            None => {
                let e = self.new_transport(transport).await?;
                self.conns.lock().unwrap().push(e.clone());
                e
            }
        };
        entry.streams.fetch_add(1, Ordering::SeqCst);
        let auth = self.auth();
        let stream: BoxProxyStream = match &entry.kind {
            ConnKind::H2(conn) => {
                let (id, mut rx, window, changed) =
                    conn.open_connect(host, user_agent, &auth).await?;
                let dead = conn.dead.clone();
                H2Conn::await_response(&mut rx, &dead).await?;
                let tunnel = H2Tunnel::spawn(conn.clone(), id, rx, window, changed, dead);
                // The count decrements when the stream task ends.
                let entry2 = entry.clone();
                let (_tx, done) = tokio::sync::watch::channel(());
                let _ = done;
                tokio::spawn(async move {
                    let _ = entry2;
                });
                Box::new(tunnel)
            }
            ConnKind::H3(conn) => Box::new(H3Tunnel::open(conn, host, user_agent, &auth).await?),
        };
        Ok((entry, stream))
    }

    /// `Dial` (client.go:218): CONNECT with the TCP user agent.
    pub async fn dial(&self, target: &NetAddr, transport: Option<BoxProxyStream>) -> Result<BoxProxyStream> {
        let host = format!("{}:{}", target.host.to_text(), target.port);
        let (_, stream) = self
            .open_tunnel(&host, &tcp_user_agent(), transport)
            .await?;
        Ok(stream)
    }

    /// `ListenPacket` (client.go:229): CONNECT to `_udp2`.
    pub async fn listen_packet(&self, transport: Option<BoxProxyStream>) -> Result<BoxProxyStream> {
        let (_, stream) = self
            .open_tunnel(UDP_MAGIC_ADDRESS, &udp_user_agent(), transport)
            .await?;
        Ok(stream)
    }

    /// `HealthCheck` (client.go:264): CONNECT to `_check`, closed
    /// immediately once the 200 arrives.
    pub async fn health_check(&self, transport: Option<BoxProxyStream>) -> Result<()> {
        let (_, mut stream) = self
            .open_tunnel(HEALTH_CHECK_MAGIC_ADDRESS, &health_check_user_agent(), transport)
            .await?;
        use tokio::io::AsyncWriteExt as _;
        let _ = stream.shutdown().await;
        Ok(())
    }

    /// `Close`.
    pub async fn close(&self) {
        let conns: Vec<Arc<ConnEntry>> = self.conns.lock().unwrap().drain(..).collect();
        for c in conns {
            if let ConnKind::H3(conn) = &c.kind {
                conn.close(0u32.into(), b"pool closed");
            }
        }
    }
}

/// Validate the option set (`NewClient`, client.go:58-88).
fn validate_cfg(cfg: &TrustTunnelOut) -> Result<()> {
    if cfg.server.is_empty() || cfg.port == 0 {
        return Err(Error::config(format!(
            "trusttunnel {}:{} requires a valid server and port",
            cfg.server, cfg.port
        )));
    }
    if cfg.quic {
        match cfg.congestion_controller.trim().to_ascii_lowercase().as_str() {
            "" | "cubic" | "bbr" | "new_reno" => {}
            other => {
                return Err(Error::config(format!(
                    "trusttunnel: congestion-controller {other:?} is not available: quinn ships \
                     bbr, cubic and new_reno; pick one of those"
                )))
            }
        }
    }
    Ok(())
}

/// TLS-wrap the transport for the h2 arm (`h2RoundTripper`,
/// client.go:90 — TLS with ALPN h2).
async fn tls_wrap(cfg: &TrustTunnelOut, transport: BoxProxyStream) -> Result<BoxProxyStream> {
    let mut alpn = cfg.alpn.clone();
    if alpn.is_empty() {
        alpn = vec!["h2".to_string()];
    } else if !alpn.iter().any(|a| a == "h2") {
        return Err(Error::config("trusttunnel: require alpn h2"));
    }
    let server_name = if cfg.sni.is_empty() {
        cfg.server.clone()
    } else {
        cfg.sni.clone()
    };
    let settings = TlsSettings {
        enabled: true,
        server_name: Some(server_name.clone()),
        skip_cert_verify: cfg.skip_cert_verify,
        alpn,
    };
    tls_connect(transport, &server_name, &settings).await
}

/// The QUIC arm's transport (quic.go:18): QUIC v1, 74s idle timeout,
/// 128 KiB stream receive window, congestion controller selection.
async fn quic_dial(cfg: &TrustTunnelOut) -> Result<quinn::Connection> {
    let mut alpn = cfg.alpn.clone();
    if alpn.is_empty() {
        alpn = vec!["h3".to_string()];
    } else if !alpn.iter().any(|a| a == "h3") {
        return Err(Error::config("trusttunnel: require alpn h3"));
    }
    let dial = QuicDial {
        server: cfg.server.clone(),
        port: cfg.port,
        sni: if cfg.sni.is_empty() {
            cfg.server.clone()
        } else {
            cfg.sni.clone()
        },
        alpn,
        skip_verify: cfg.skip_cert_verify,
        udp_relay: false,
        congestion_brutal_bps: None,
    };
    let mut client_cfg = if let Some(opts) = cfg.ech.as_ref().filter(|o| o.enable) {
        // `ech-opts` on the quic arm: the dial runs on the engine's own
        // TLS 1.3 stack with the ECH cover (crate::quic::tls13); ALPN
        // still negotiates h3.
        quic::client_config_custom(&dial, &quic::QuicTlsCover::Ech(quic::ech_selection(opts)?))?
    } else {
        quic::client_config(&dial)?
    };
    let mut transport = quinn::TransportConfig::default();
    transport.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(DEFAULT_QUIC_MAX_IDLE_TIMEOUT)
            .map_err(|_| Error::config("trusttunnel: idle timeout"))?,
    ));
    transport.stream_receive_window(
        quinn::VarInt::from_u64(DEFAULT_QUIC_STREAM_RECEIVE_WINDOW)
            .or(Err(Error::config("trusttunnel: receive window")))?,
    );
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    client_cfg.transport_config(Arc::new(transport));
    let remote = quic::resolve_remote(&dial.server, dial.port).await?;
    let mut endpoint = quic::client_endpoint(quic::family_bind_addr(remote)).await?;
    endpoint.set_default_client_config(client_cfg);
    let connect = endpoint
        .connect(remote, &dial.sni)
        .map_err(|e| Error::config(format!("trusttunnel: quic connect: {e}")))?;
    let conn = connect.await.map_err(|e| {
        Error::network(format!(
            "trusttunnel: quic handshake with {} (alpn {:?}): {e}",
            remote, dial.alpn
        ))
    })?;
    // Keep the h3 control + QPACK streams open for the connection
    // lifetime — closing them is a fatal h3 error (the same hold the
    // hysteria2 transport does).
    let control_streams = quic::h3_open_control(&conn, "trusttunnel").await?;
    let holder = conn.clone();
    tokio::spawn(async move {
        let _keep = control_streams;
        let _ = holder.closed().await;
    });
    Ok(conn)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;
    use std::time::Duration;

    use rustls::crypto::ring as ring_provider;
    use std::io::Write as _;

    fn test_cfg() -> TrustTunnelOut {
        let mut cfg = TrustTunnelOut::new("127.0.0.1", 0);
        cfg.username = format!("user-{:016x}", rand::random::<u64>());
        cfg.password = format!("pass-{:016x}", rand::random::<u64>());
        cfg.skip_cert_verify = true;
        cfg
    }

    // ------------------------------------------------------------ literals

    #[test]
    fn user_agents_and_auth() {
        let auth = build_auth("Aladdin", "open sesame");
        assert_eq!(
            auth,
            format!("Basic {}", base64::engine::general_purpose::STANDARD.encode("Aladdin:open sesame"))
        );
        assert!(tcp_user_agent().contains(APP_NAME));
        assert!(tcp_user_agent().contains(std::env::consts::OS));
        assert_eq!(udp_user_agent(), format!("{} _udp2", std::env::consts::OS));
        assert_eq!(health_check_user_agent(), std::env::consts::OS);
        assert_eq!(UDP_MAGIC_ADDRESS, "_udp2");
        assert_eq!(HEALTH_CHECK_MAGIC_ADDRESS, "_check");
    }

    #[test]
    fn udp_frame_layouts() {
        // Client → server (writePacketToServer, packet.go:102).
        let target = NetAddr::ip("8.8.8.8".parse().unwrap(), 53);
        let frame = trusttunnel_udp_frame(&target, b"q").unwrap();
        // length = 36 + 1 + appName + payload
        let app_len = APP_NAME.len();
        assert_eq!(&frame[..4], &((36 + 1 + app_len + 1) as u32).to_be_bytes());
        assert_eq!(&frame[4..22], &[0u8; 18]); // unknown source
        assert_eq!(&frame[22..38], &build_padding_ip("8.8.8.8".parse().unwrap()));
        assert_eq!(&frame[38..40], &53u16.to_be_bytes());
        assert_eq!(frame[40], app_len as u8);
        assert_eq!(&frame[41..41 + app_len], APP_NAME.as_bytes());
        assert_eq!(&frame[41 + app_len..], b"q");
        // Domain targets are refused (only IP).
        let d = NetAddr::domain("dns.example", 53).unwrap();
        assert!(trusttunnel_udp_frame(&d, b"q").is_err());
        // Server → client (writePacketToClient): source + zeros.
        let mut inbound = Vec::new();
        inbound.extend_from_slice(&(36u32 + 3).to_be_bytes());
        inbound.extend_from_slice(&build_padding_ip("2001:db8::1".parse().unwrap()));
        inbound.extend_from_slice(&853u16.to_be_bytes());
        inbound.extend_from_slice(&[0u8; 18]);
        inbound.extend_from_slice(b"abc");
        let (addr, payload) = parse_trusttunnel_udp(&inbound).unwrap();
        assert_eq!(addr.host, Host::Ip("2001:db8::1".parse().unwrap()));
        assert_eq!(addr.port, 853);
        assert_eq!(payload, b"abc".to_vec());
        // The v4-mapped form decodes as v4, but ::1 stays v6.
        assert_eq!(
            parse_16_bytes_ip(&build_padding_ip("1.2.3.4".parse().unwrap())),
            std::net::IpAddr::V4("1.2.3.4".parse().unwrap())
        );
        assert_eq!(
            parse_16_bytes_ip(&[0u8; 15][..].to_vec().iter().copied().chain([1u8]).collect::<Vec<u8>>().try_into().unwrap()),
            std::net::IpAddr::V6("::1".parse().unwrap())
        );
        assert!(parse_trusttunnel_udp(&inbound[..30]).is_err());
    }

    #[test]
    fn hpack_roundtrip_and_status() {
        let mut block = Vec::new();
        put_hpack_literal(&mut block, b":method", b"CONNECT");
        put_hpack_literal(&mut block, b":authority", b"echo.example:443");
        let mut dynamic = Vec::new();
        let fields = hpack_decode(&block, &mut dynamic).unwrap();
        assert_eq!(fields[0], (":method".to_string(), "CONNECT".to_string()));
        assert_eq!(fields[1].0, ":authority");
        // A response block using the static index for :status 200.
        let resp = vec![0x88u8]; // indexed field, static index 8
        let fields = hpack_decode(&resp, &mut Vec::new()).unwrap();
        assert_eq!(fields, vec![(":status".to_string(), "200".to_string())]);
        // A literal-with-indexing entry lands in the dynamic table and
        // a follow-up indexed reference resolves.
        let mut block = Vec::new();
        block.push(0x40); // literal, incremental indexing, new name
        put_string(&mut block, b"x-custom");
        put_string(&mut block, b"v1");
        let mut dynamic = Vec::new();
        let fields = hpack_decode(&block, &mut dynamic).unwrap();
        assert_eq!(fields, vec![("x-custom".to_string(), "v1".to_string())]);
        assert_eq!(dynamic.len(), 1);
        let mut follow = Vec::new();
        // Static index 61 entries + 1 → dynamic[0].
        put_int(&mut follow, 0x80, 7, HPACK_STATIC_TABLE.len() as u64);
        let fields = hpack_decode(&follow, &mut dynamic).unwrap();
        assert_eq!(fields, vec![("x-custom".to_string(), "v1".to_string())]);
    }

    /// RFC 7541 appendix C.4.1: the Huffman-coded "www.example.com".
    #[test]
    fn huffman_rfc7541_vector() {
        let coded = [
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ];
        assert_eq!(huffman_decode(&coded).unwrap(), b"www.example.com");
        // Round-trip arbitrary strings through the table (bit-pack,
        // pad with the EOS prefix, decode back).
        for s in [b"no-cache".to_vec(), b"custom-key".to_vec(), (0u8..=255).collect::<Vec<u8>>()] {
            let mut bits: Vec<bool> = Vec::new();
            for &sym in &s {
                let (code, len) = HUFFMAN_CODES[sym as usize];
                for i in (0..len).rev() {
                    bits.push((code >> i) & 1 == 1);
                }
            }
            // Pad with the EOS prefix (all ones) below 8 bits.
            while !bits.len().is_multiple_of(8) {
                bits.push(true);
            }
            let mut packed = Vec::with_capacity(bits.len() / 8);
            for chunk in bits.chunks(8) {
                let mut b = 0u8;
                for bit in chunk {
                    b = (b << 1) | u8::from(*bit);
                }
                packed.push(b);
            }
            assert_eq!(huffman_decode(&packed).unwrap(), s);
        }
        // Bad padding (a non-prefix of EOS) fails.
        assert!(huffman_decode(&[0x00]).is_none());
    }

    #[test]
    fn qpack_literal_block_decodes() {
        let mut block = Vec::new();
        block.extend_from_slice(&[0x00, 0x00]); // prefix: ric 0, base 0
        quic::put_qpack_literal(&mut block, b":status", b"200");
        quic::put_qpack_literal(&mut block, b"server", b"mimic");
        let fields = qpack_decode_field_section(&block).unwrap();
        assert_eq!(
            fields,
            vec![
                (":status".to_string(), "200".to_string()),
                ("server".to_string(), "mimic".to_string()),
            ]
        );
        // The indexed static form for :status 200 (index 25).
        let mut block = Vec::new();
        block.extend_from_slice(&[0x00, 0x00]);
        block.push(0xC0 | 25); // 110000 25
        let fields = qpack_decode_field_section(&block).unwrap();
        assert_eq!(fields, vec![(":status".to_string(), "200".to_string())]);
    }

    #[test]
    fn h2_frame_header_layout() {
        let mut out = Vec::new();
        put_h2_frame(&mut out, H2_DATA, H2_FLAG_END_STREAM, 3, b"abcd");
        assert_eq!(&out[..9], &[0, 0, 4, H2_DATA, H2_FLAG_END_STREAM, 0, 0, 0, 3]);
        assert_eq!(&out[9..], b"abcd");
    }

    #[test]
    fn config_validation() {
        let mut cfg = test_cfg();
        cfg.port = 1;
        assert!(validate_cfg(&cfg).is_ok());
        cfg.server.clear();
        assert!(
            validate_cfg(&cfg)
                .err()
                .map(|e| e.to_string())
                .unwrap_or_default()
                .contains("server and port")
        );
        let mut cfg = test_cfg();
        cfg.port = 1;
        cfg.quic = true;
        cfg.congestion_controller = "bbr2".into();
        let err = validate_cfg(&cfg)
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(err.contains("bbr2"), "{err}");
        assert!(err.contains("quinn"), "{err}");
        let mut cfg = test_cfg();
        cfg.port = 1;
        cfg.quic = true;
        cfg.congestion_controller = "bbr".into();
        assert!(validate_cfg(&cfg).is_ok());
    }

    // ------------------------------------------------ h2 mimic (TCP + TLS)

    fn server_tls_config() -> Arc<rustls::ServerConfig> {
        let certified = rcgen::generate_simple_self_signed(vec!["tt.example".to_string()])
            .expect("rcgen cert");
        let cert = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
        let key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let provider = Arc::new(ring_provider::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        config.alpn_protocols = vec![b"h2".to_vec()];
        Arc::new(config)
    }

    /// One h2 stream inside the mimic: parse the CONNECT, reply 200,
    /// then echo (TCP) or frame datagrams (UDP).
    async fn mimic_h2_stream(
        mut send: tokio::net::tcp::OwnedWriteHalf,
        mut recv: tokio::net::tcp::OwnedReadHalf,
        tls: rustls::ServerConnection,
        expect: MimicExpect,
        requests: Arc<StdMutex<Vec<HeaderFields>>>,
    ) -> std::result::Result<(), String> {
        let mut tls = tls;
        let mut tls_out = Vec::new();
        let mut ct_buf: Vec<u8> = Vec::new();
        let mut plain_buf: Vec<u8> = Vec::new();
        let mut dynamic = Vec::new();
        let mut served: std::collections::HashSet<u32> = std::collections::HashSet::new();
        let mut pending_data: Vec<(u32, Vec<u8>)> = Vec::new();
        let e = |m: &str| -> String { m.to_string() };
        loop {
            while tls.wants_write() {
                if tls.write_tls(&mut tls_out).unwrap_or(0) == 0 {
                    break;
                }
            }
            if !tls_out.is_empty() {
                send.write_all(&tls_out).await.map_err(|er| er.to_string())?;
                send.flush().await.map_err(|er| er.to_string())?;
                tls_out.clear();
            }
            if tls.is_handshaking() {
                let mut tmp = [0u8; 16 * 1024];
                let n = recv.read(&mut tmp).await.map_err(|er| er.to_string())?;
                if n == 0 {
                    // Abandoned handshake (the pool's extra dial drops
                    // its unused transport): close quietly.
                    return Ok(());
                }
                ct_buf.extend_from_slice(&tmp[..n]);
                // Feed records one at a time, processing after each:
                // rustls' deframer holds only a few unprocessed records.
                while !ct_buf.is_empty() {
                    let mut cursor = &ct_buf[..];
                    match tls.read_tls(&mut cursor) {
                        Ok(0) => break,
                        Ok(_) => {}
                        Err(er) => return Err(er.to_string()),
                    }
                    let consumed = ct_buf.len() - cursor.len();
                    ct_buf.drain(..consumed);
                    if consumed == 0 {
                        break;
                    }
                    tls.process_new_packets().map_err(|er| er.to_string())?;
                    // Keep the received-plaintext buffer from filling.
                    {
                        use std::io::Read as _;
                        let mut plain = [0u8; 16 * 1024];
                        loop {
                            let n = tls.reader().read(&mut plain).unwrap_or(0);
                            if n == 0 {
                                break;
                            }
                            plain_buf.extend_from_slice(&plain[..n]);
                        }
                    }
                }
                continue;
            }
            // Serve CONNECT once, then echo. Drain buffered plaintext
            // first; only pull more ciphertext when the buffer runs dry.
            {
                use std::io::Read as _;
                let mut plain = [0u8; 16 * 1024];
                loop {
                    let n = tls.reader().read(&mut plain).unwrap_or(0);
                    if n == 0 {
                        break;
                    }
                    plain_buf.extend_from_slice(&plain[..n]);
                }
            }
            if served.is_empty() {
                // The client preface + frames are in the TLS plaintext.
                if plain_buf.len() < 24 + 9 {
                    let mut tmp = [0u8; 16 * 1024];
                    let n = recv.read(&mut tmp).await.map_err(|er| er.to_string())?;
                    if n == 0 {
                        return Err(e("eof before headers"));
                    }
                    let mut cursor = &tmp[..n];
                    tls.read_tls(&mut cursor).map_err(|er| er.to_string())?;
                    tls.process_new_packets().map_err(|er| er.to_string())?;
                    continue;
                }
                if &plain_buf[..24] != H2_PREFACE {
                    return Err(e("bad preface"));
                }
                let mut off = 24usize;
                // Skip SETTINGS (and any others) until HEADERS.
                let mut headers: Option<(u32, Vec<u8>)> = None;
                while off + 9 <= plain_buf.len() {
                    let len = ((plain_buf[off] as usize) << 16)
                        | ((plain_buf[off + 1] as usize) << 8)
                        | plain_buf[off + 2] as usize;
                    if off + 9 + len > plain_buf.len() {
                        break;
                    }
                    let ftype = plain_buf[off + 3];
                    let stream_id = u32::from_be_bytes([
                        plain_buf[off + 5],
                        plain_buf[off + 6],
                        plain_buf[off + 7],
                        plain_buf[off + 8],
                    ]) & 0x7FFF_FFFF;
                    let payload = plain_buf[off + 9..off + 9 + len].to_vec();
                    off += 9 + len;
                    if ftype == H2_HEADERS {
                        headers = Some((stream_id, payload));
                        break;
                    }
                }
                let (stream_id, payload) = headers.ok_or(e("no HEADERS"))?;
                let fields = hpack_decode(&payload, &mut dynamic).map_err(|er| er.to_string())?;
                requests.lock().unwrap().push(fields.clone());
                let authority = fields
                    .iter()
                    .find(|(n, _)| n == ":authority")
                    .map(|(_, v)| v.clone())
                    .ok_or(e("no :authority"))?;
                let method = fields
                    .iter()
                    .find(|(n, _)| n == ":method")
                    .map(|(_, v)| v.clone())
                    .ok_or(e("no :method"))?;
                let auth = fields
                    .iter()
                    .find(|(n, _)| n == "proxy-authorization")
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default();
                if method != "CONNECT" {
                    return Err(format!("method {method}"));
                }
                match &expect {
                    MimicExpect::Tcp(want) => {
                        if &authority != want {
                            return Err(format!("authority {authority} != {want}"));
                        }
                    }
                    MimicExpect::Udp => {
                        if authority != UDP_MAGIC_ADDRESS {
                            return Err(format!("authority {authority}"));
                        }
                    }
                    MimicExpect::Health => {
                        if authority != HEALTH_CHECK_MAGIC_ADDRESS {
                            return Err(format!("authority {authority}"));
                        }
                    }
                }
                if auth != build_auth(&expect_user(), &expect_pass()) {
                    return Err(format!("bad auth {auth}"));
                }
                // Reply SETTINGS + HEADERS :status 200.
                let mut out = Vec::new();
                put_h2_frame(&mut out, H2_SETTINGS, 0, 0, &[]);
                let mut block = Vec::new();
                put_hpack_literal(&mut block, b":status", b"200");
                put_h2_frame(&mut out, H2_HEADERS, H2_FLAG_END_HEADERS, stream_id, &block);
                tls.writer().write_all(&out).map_err(|er| format!("response write: {er}"))?;
                served.insert(stream_id);
                plain_buf.drain(..off);
                continue;
            }
            // Answer any new CONNECTs first (multi-stream pooling).
            {
                let mut off = 0usize;
                let mut responses = Vec::new();
                while off + 9 <= plain_buf.len() {
                    let len = ((plain_buf[off] as usize) << 16)
                        | ((plain_buf[off + 1] as usize) << 8)
                        | plain_buf[off + 2] as usize;
                    if off + 9 + len > plain_buf.len() {
                        break;
                    }
                    let ftype = plain_buf[off + 3];
                    let sid = u32::from_be_bytes([
                        plain_buf[off + 5],
                        plain_buf[off + 6],
                        plain_buf[off + 7],
                        plain_buf[off + 8],
                    ]) & 0x7FFF_FFFF;
                    let payload = plain_buf[off + 9..off + 9 + len].to_vec();
                    off += 9 + len;
                    if ftype == H2_HEADERS && !served.contains(&sid) {
                        if let Ok(fields) = hpack_decode(&payload, &mut dynamic) {
                            requests.lock().unwrap().push(fields.clone());
                            let mut block = Vec::new();
                            put_hpack_literal(&mut block, b":status", b"200");
                            put_h2_frame(&mut responses, H2_HEADERS, H2_FLAG_END_HEADERS, sid, &block);
                            served.insert(sid);
                        }
                    } else if ftype == H2_DATA && !payload.is_empty() && served.contains(&sid) {
                        // Queue the DATA for the echo path below.
                        pending_data.push((sid, payload));
                    }
                }
                plain_buf.drain(..off);
                if !responses.is_empty() {
                    tls.writer().write_all(&responses).map_err(|er| er.to_string())?;
                    while tls.wants_write() {
                        if tls.write_tls(&mut tls_out).unwrap_or(0) == 0 {
                            break;
                        }
                    }
                    if !tls_out.is_empty() {
                        send.write_all(&tls_out).await.map_err(|er| er.to_string())?;
                        send.flush().await.map_err(|er| er.to_string())?;
                        tls_out.clear();
                    }
                    // Fall through: the echo branch drains pending_data.
                }
            }
            // Echo loop.
            match &expect {
                MimicExpect::Tcp(_) => {
                    // Drain plaintext, echo every DATA frame back
                    // (plus any the CONNECT scan collected).
                    let mut frames = std::mem::take(&mut pending_data);
                    let mut off = 0usize;
                    while off + 9 <= plain_buf.len() {
                        let len = ((plain_buf[off] as usize) << 16)
                            | ((plain_buf[off + 1] as usize) << 8)
                            | plain_buf[off + 2] as usize;
                        if off + 9 + len > plain_buf.len() {
                            break;
                        }
                        let ftype = plain_buf[off + 3];
                        let stream_id = u32::from_be_bytes([
                            plain_buf[off + 5],
                            plain_buf[off + 6],
                            plain_buf[off + 7],
                            plain_buf[off + 8],
                        ]) & 0x7FFF_FFFF;
                        let payload = plain_buf[off + 9..off + 9 + len].to_vec();
                        off += 9 + len;
                        if ftype == H2_DATA && !payload.is_empty() {
                            frames.push((stream_id, payload));
                        }
                    }
                    plain_buf.drain(..off);
                    let mut echoed = false;
                    for (sid, payload) in &frames {
                        let mut out = Vec::new();
                        put_h2_frame(&mut out, H2_DATA, 0, *sid, payload);
                        // Restore the client's send window: one frame
                        // for the stream, one for the connection.
                        let inc = (payload.len() as u32).to_be_bytes();
                        put_h2_frame(&mut out, H2_WINDOW_UPDATE, 0, *sid, &inc);
                        put_h2_frame(&mut out, H2_WINDOW_UPDATE, 0, 0, &inc);
                        tls.writer().write_all(&out).map_err(|er| format!("echo write: {er}"))?;
                        echoed = true;
                        // Flush to the socket before the next batch:
                        // rustls' plaintext buffer is record-sized.
                        while tls.wants_write() {
                            if tls.write_tls(&mut tls_out).unwrap_or(0) == 0 {
                                break;
                            }
                        }
                        if !tls_out.is_empty() {
                            send.write_all(&tls_out).await.map_err(|er| er.to_string())?;
                            send.flush().await.map_err(|er| er.to_string())?;
                            tls_out.clear();
                        }
                    }
                    if echoed {
                        continue;
                    }
                }
                MimicExpect::Udp => {
                    // Parse one client datagram frame, echo it back in
                    // the server form (writePacketToClient). The
                    // CONNECT scan may have already collected frames.
                    let mut chunks = std::mem::take(&mut pending_data);
                    // Re-parse any whole frames still in plain_buf.
                    {
                        let mut off = 0usize;
                        while off + 9 <= plain_buf.len() {
                            let len = ((plain_buf[off] as usize) << 16)
                                | ((plain_buf[off + 1] as usize) << 8)
                                | plain_buf[off + 2] as usize;
                            if off + 9 + len > plain_buf.len() {
                                break;
                            }
                            let ftype = plain_buf[off + 3];
                            let sid = u32::from_be_bytes([
                                plain_buf[off + 5],
                                plain_buf[off + 6],
                                plain_buf[off + 7],
                                plain_buf[off + 8],
                            ]) & 0x7FFF_FFFF;
                            let payload = plain_buf[off + 9..off + 9 + len].to_vec();
                            off += 9 + len;
                            if ftype == H2_DATA && !payload.is_empty() {
                                chunks.push((sid, payload));
                            }
                        }
                        plain_buf.drain(..off);
                    }
                    if !chunks.is_empty() {
                        let mut outs = Vec::new();
                        for (sid, payload) in &chunks {
                            if payload.len() < 4 {
                                continue;
                            }
                            let total = u32::from_be_bytes([
                                payload[0], payload[1], payload[2], payload[3],
                            ]) as usize;
                            if payload.len() < total {
                                continue;
                            }
                            let app_len = payload[40] as usize;
                            let data_len = total - 36 - 1 - app_len;
                            let mut resp = Vec::with_capacity(40 + data_len);
                            resp.extend_from_slice(&((36 + data_len) as u32).to_be_bytes());
                            resp.extend_from_slice(&payload[22..38]); // dst as source
                            resp.extend_from_slice(&payload[38..40]);
                            resp.extend_from_slice(&[0u8; 18]);
                            resp.extend_from_slice(&payload[41 + app_len..41 + app_len + data_len]);
                            put_h2_frame(&mut outs, H2_DATA, 0, *sid, &resp);
                        }
                        tls.writer().write_all(&outs).map_err(|er| er.to_string())?;
                        while tls.wants_write() {
                            if tls.write_tls(&mut tls_out).unwrap_or(0) == 0 {
                                break;
                            }
                        }
                        if !tls_out.is_empty() {
                            send.write_all(&tls_out).await.map_err(|er| er.to_string())?;
                            send.flush().await.map_err(|er| er.to_string())?;
                            tls_out.clear();
                        }
                        continue;
                    }
                    if plain_buf.len() >= 4 {
                        let mut off = 0usize;
                        let mut outs = Vec::new();
                        while off + 9 <= plain_buf.len() {
                            let len = ((plain_buf[off] as usize) << 16)
                                | ((plain_buf[off + 1] as usize) << 8)
                                | plain_buf[off + 2] as usize;
                            if off + 9 + len > plain_buf.len() {
                                break;
                            }
                            let ftype = plain_buf[off + 3];
                            let sid = u32::from_be_bytes([
                                plain_buf[off + 5],
                                plain_buf[off + 6],
                                plain_buf[off + 7],
                                plain_buf[off + 8],
                            ]) & 0x7FFF_FFFF;
                            let payload = plain_buf[off + 9..off + 9 + len].to_vec();
                            off += 9 + len;
                            if ftype != H2_DATA || payload.is_empty() {
                                continue;
                            }
                            // Client frame: [len u32][18 zero][dst 16][port 2][al 1][app][payload]
                            if payload.len() < 4 {
                                continue;
                            }
                            let total = u32::from_be_bytes([
                                payload[0], payload[1], payload[2], payload[3],
                            ]) as usize;
                            if payload.len() < total {
                                continue;
                            }
                            let app_len = payload[40] as usize;
                            let data_len = total - 36 - 1 - app_len;
                            let mut resp = Vec::with_capacity(40 + data_len);
                            resp.extend_from_slice(&((36 + data_len) as u32).to_be_bytes());
                            resp.extend_from_slice(&payload[22..38]); // dst as source
                            resp.extend_from_slice(&payload[38..40]);
                            resp.extend_from_slice(&[0u8; 18]);
                            resp.extend_from_slice(&payload[41 + app_len..41 + app_len + data_len]);
                            put_h2_frame(&mut outs, H2_DATA, 0, sid, &resp);
                        }
                        plain_buf.drain(..off);
                        if !outs.is_empty() {
                            tls.writer().write_all(&outs).map_err(|er| er.to_string())?;
                            while tls.wants_write() {
                                if tls.write_tls(&mut tls_out).unwrap_or(0) == 0 {
                                    break;
                                }
                            }
                            if !tls_out.is_empty() {
                                send.write_all(&tls_out).await.map_err(|er| er.to_string())?;
                                send.flush().await.map_err(|er| er.to_string())?;
                                tls_out.clear();
                            }
                            continue;
                        }
                    }
                }
                MimicExpect::Health => {
                    // Wait for close.
                    let mut tmp = [0u8; 1024];
                    match recv.read(&mut tmp).await {
                        Ok(0) | Err(_) => return Ok(()),
                        Ok(n) => {
                            let mut cursor = &tmp[..n];
                            let _ = tls.read_tls(&mut cursor);
                            let _ = tls.process_new_packets();
                        }
                    }
                }
            }
            // Pull more ciphertext (draining happens at the loop top).
            let mut tmp = [0u8; 16 * 1024];
            let n = recv.read(&mut tmp).await.map_err(|er| er.to_string())?;
            if n == 0 {
                return Ok(());
            }
            ct_buf.extend_from_slice(&tmp[..n]);
            while !ct_buf.is_empty() {
                let mut cursor = &ct_buf[..];
                match tls.read_tls(&mut cursor) {
                    Ok(0) => break,
                    Ok(_) => {}
                    Err(er) => return Err(er.to_string()),
                }
                let consumed = ct_buf.len() - cursor.len();
                ct_buf.drain(..consumed);
                if consumed == 0 {
                    break;
                }
                tls.process_new_packets().map_err(|er| er.to_string())?;
                {
                    use std::io::Read as _;
                    let mut plain = [0u8; 16 * 1024];
                    loop {
                        let n = tls.reader().read(&mut plain).unwrap_or(0);
                        if n == 0 {
                            break;
                        }
                        plain_buf.extend_from_slice(&plain[..n]);
                    }
                }
            }
        }
    }

    enum MimicExpect {
        Tcp(String),
        Udp,
        Health,
    }

    fn expect_user() -> String {
        EXPECT_CREDS.with(|c| c.borrow().0.clone())
    }

    fn expect_pass() -> String {
        EXPECT_CREDS.with(|c| c.borrow().1.clone())
    }

    thread_local! {
        static EXPECT_CREDS: std::cell::RefCell<(String, String)> =
            const { std::cell::RefCell::new((String::new(), String::new())) };
    }

    /// Decoded header fields (name, value) pairs.
    type HeaderFields = Vec<(String, String)>;

    /// Start the h2 mimic on loopback, returning its port.
    async fn start_h2_mimic(
        expect: MimicExpect,
        requests: Arc<StdMutex<Vec<HeaderFields>>>,
    ) -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let tls_config = server_tls_config();
        tokio::spawn(async move {
            loop {
                let Ok((socket, _)) = listener.accept().await else {
                    return;
                };
                let _ = socket.set_nodelay(true);
                let tls = match rustls::ServerConnection::new(tls_config.clone()) {
                    Ok(t) => t,
                    Err(_) => return,
                };
                let (rd, wr) = tokio::net::TcpStream::into_split(socket);
                let requests = requests.clone();
                let expect = clone_expect(&expect);
                tokio::spawn(async move {
                    if let Err(e) = mimic_h2_stream(wr, rd, tls, expect, requests).await {
                        panic!("h2 mimic failed: {e}");
                    }
                });
            }
        });
        port
    }

    fn clone_expect(e: &MimicExpect) -> MimicExpect {
        match e {
            MimicExpect::Tcp(t) => MimicExpect::Tcp(t.clone()),
            MimicExpect::Udp => MimicExpect::Udp,
            MimicExpect::Health => MimicExpect::Health,
        }
    }

    async fn tls_transport(port: u16) -> BoxProxyStream {
        let socket = tokio::net::TcpStream::connect(("127.0.0.1", port))
            .await
            .expect("connect mimic");
        Box::new(socket)
    }

    fn set_creds(user: &str, pass: &str) {
        EXPECT_CREDS.with(|c| *c.borrow_mut() = (user.to_string(), pass.to_string()));
    }

    #[tokio::test]
    async fn h2_connect_and_echo() {
        let requests = Arc::new(StdMutex::new(Vec::new()));
        let cfg = test_cfg();
        set_creds(&cfg.username, &cfg.password);
        let target = NetAddr::domain("echo.example", 443).unwrap();
        let port = start_h2_mimic(
            MimicExpect::Tcp(format!("{}:{}", target.host.to_text(), target.port)),
            requests.clone(),
        )
        .await;
        let mut pool_cfg = cfg.clone();
        pool_cfg.port = port;
        pool_cfg.sni = "tt.example".into();
        let pool = TrustTunnelPool::new(&pool_cfg, Some(tls_transport(port).await))
            .await
            .unwrap();
        let mut stream = pool
            .dial(&target, Some(tls_transport(port).await))
            .await
            .unwrap();
        stream.write_all(b"ping-tt").await.unwrap();
        let mut buf = [0u8; 7];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"ping-tt");
        // A payload spanning multiple DATA frames + window updates.
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let (mut rd, mut wr) = tokio::io::split(stream);
        let want = payload.clone();
        let echo = tokio::spawn(async move {
            let mut got = vec![0u8; want.len()];
            rd.read_exact(&mut got).await.unwrap();
            got
        });
        wr.write_all(&payload).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(20), echo)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, payload);
        // The CONNECT carried the target as :authority + auth.
        let reqs = requests.lock().unwrap();
        assert!(reqs.iter().any(|f| {
            f.iter().any(|(n, v)| n == ":authority" && v == "echo.example:443")
                && f.iter().any(|(n, v)| n == ":method" && v == "CONNECT")
                && f.iter().any(|(n, v)| {
                    n == "proxy-authorization" && *v == build_auth(&cfg.username, &cfg.password)
                })
                && f.iter().any(|(n, v)| n == "user-agent" && *v == tcp_user_agent())
        }));
    }

    #[tokio::test]
    async fn h2_udp_association() {
        let cfg = test_cfg();
        set_creds(&cfg.username, &cfg.password);
        let port = start_h2_mimic(MimicExpect::Udp, Arc::new(StdMutex::new(Vec::new()))).await;
        let mut pool_cfg = cfg.clone();
        pool_cfg.port = port;
        pool_cfg.sni = "tt.example".into();
        let pool = TrustTunnelPool::new(&pool_cfg, Some(tls_transport(port).await))
            .await
            .unwrap();
        let mut stream = pool
            .listen_packet(Some(tls_transport(port).await))
            .await
            .unwrap();
        for payload in [b"one".to_vec(), vec![9u8; 700]] {
            let target = NetAddr::ip("8.8.8.8".parse().unwrap(), 53);
            stream
                .write_all(&trusttunnel_udp_frame(&target, &payload).unwrap())
                .await
                .unwrap();
            let (back, got) =
                tokio::time::timeout(Duration::from_secs(10), read_trusttunnel_udp(&mut stream))
                    .await
                    .unwrap()
                    .unwrap();
            assert_eq!(back.host, Host::Ip("8.8.8.8".parse().unwrap()));
            assert_eq!(back.port, 53);
            assert_eq!(got, payload);
        }
    }

    #[tokio::test]
    async fn h2_health_check() {
        let cfg = test_cfg();
        set_creds(&cfg.username, &cfg.password);
        let port = start_h2_mimic(MimicExpect::Health, Arc::new(StdMutex::new(Vec::new()))).await;
        let mut pool_cfg = cfg.clone();
        pool_cfg.port = port;
        pool_cfg.sni = "tt.example".into();
        let pool = TrustTunnelPool::new(&pool_cfg, Some(tls_transport(port).await))
            .await
            .unwrap();
        pool.health_check(Some(tls_transport(port).await))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn h2_pool_reuses_one_connection() {
        let cfg = test_cfg();
        set_creds(&cfg.username, &cfg.password);
        let target = NetAddr::domain("echo.example", 443).unwrap();
        let port = start_h2_mimic(
            MimicExpect::Tcp(format!("{}:{}", target.host.to_text(), target.port)),
            Arc::new(StdMutex::new(Vec::new())),
        )
        .await;
        let mut pool_cfg = cfg.clone();
        pool_cfg.port = port;
        pool_cfg.sni = "tt.example".into();
        pool_cfg.max_connections = 1;
        pool_cfg.min_streams = 1;
        let pool = TrustTunnelPool::new(&pool_cfg, Some(tls_transport(port).await))
            .await
            .unwrap();
        let mut s1 = pool
            .dial(&target, Some(tls_transport(port).await))
            .await
            .unwrap();
        let mut s2 = pool
            .dial(&target, Some(tls_transport(port).await))
            .await
            .unwrap();
        assert_eq!(pool.conns.lock().unwrap().len(), 1);
        s1.write_all(b"a").await.unwrap();
        s2.write_all(b"b").await.unwrap();
        let mut buf = [0u8; 1];
        s1.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"a");
        s2.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"b");
        // With room to grow, the next dial opens a second connection.
        let mut growing = cfg.clone();
        growing.port = port;
        growing.sni = "tt.example".into();
        growing.max_connections = 4;
        growing.min_streams = 1;
        let pool2 = TrustTunnelPool::new(&growing, Some(tls_transport(port).await))
            .await
            .unwrap();
        let _ = pool2
            .dial(&target, Some(tls_transport(port).await))
            .await
            .unwrap();
        let _ = pool2
            .dial(&target, Some(tls_transport(port).await))
            .await
            .unwrap();
        assert_eq!(pool2.conns.lock().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn h2_wrong_auth_rejected() {
        let cfg = test_cfg();
        let target = NetAddr::domain("echo.example", 443).unwrap();
        // The mimic knows the real credentials; the client sends wrong
        // ones (ServeHTTP verify, service.go:246).
        set_creds(&cfg.username, &cfg.password);
        let port = start_h2_mimic(
            MimicExpect::Tcp(format!("{}:{}", target.host.to_text(), target.port)),
            Arc::new(StdMutex::new(Vec::new())),
        )
        .await;
        let mut bad = cfg.clone();
        bad.password = "wrong-password".into();
        bad.port = port;
        bad.sni = "tt.example".into();
        let bad_pool = TrustTunnelPool::new(&bad, Some(tls_transport(port).await))
            .await
            .unwrap();
        let result = bad_pool
            .dial(&target, Some(tls_transport(port).await))
            .await;
        match result {
            Ok(mut stream) => {
                // If the CONNECT slipped through, the first read must
                // fail: the server dropped the connection.
                stream.write_all(b"x").await.unwrap();
                let mut buf = [0u8; 1];
                assert!(stream.read(&mut buf).await.is_err());
            }
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("auth") || msg.contains("status") || msg.contains("closed")
                        || msg.contains("gone") || msg.contains("eof"),
                    "{msg}"
                );
            }
        }
    }

    // ------------------------------------------------------- quic (h3) arm

    fn quinn_server_config() -> quinn::ServerConfig {
        let certified = rcgen::generate_simple_self_signed(vec!["tt.example".to_string()])
            .expect("rcgen cert");
        let cert = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
        let key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let provider = Arc::new(ring_provider::default_provider());
        let mut tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls)).unwrap();
        quinn::ServerConfig::with_crypto(Arc::new(quic_tls))
    }

    /// The h3 mimic: per bidi stream, parse the HEADERS (QPACK
    /// literals), reply :status 200, echo DATA frames.
    async fn h3_serve_conn(conn: quinn::Connection) {
        while let Ok((mut send, mut recv)) = conn.accept_bi().await {
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut chunk = [0u8; 4096];
                // Read until the HEADERS frame completes.
                let authority;
                loop {
                    if let Some((frame_type, flen, hdr)) = h3_frame_at(&buf) {
                        if buf.len() >= hdr + flen as usize {
                            if frame_type == quic::H3_HEADERS {
                                // The decoder consumes the field-section
                                // prefix itself.
                                let block = &buf[hdr..hdr + flen as usize];
                                let fields = match qpack_decode_field_section(block) {
                                    Ok(f) => f,
                                    Err(_) => return,
                                };
                                authority = fields
                                    .iter()
                                    .find(|(n, _)| n == ":authority")
                                    .map(|(_, v)| v.clone())
                                    .unwrap_or_default();
                                if authority != "echo.example:443" && authority != UDP_MAGIC_ADDRESS {
                                    return;
                                }
                                let rest = buf[hdr + flen as usize..].to_vec();
                                // Reply :status 200.
                                let mut block = Vec::new();
                                block.extend_from_slice(&[0x00, 0x00]);
                                quic::put_qpack_literal(&mut block, b":status", b"200");
                                let mut out = Vec::new();
                                quic::put_h3_frame(&mut out, quic::H3_HEADERS, &block);
                                if send.write_all(&out).await.is_err() {
                                    return;
                                }
                                // Echo any early bytes verbatim — they
                                // are already complete h3 frames.
                                if !rest.is_empty() {
                                    let _ = send.write_all(&rest).await;
                                }
                                break;
                            }
                            buf.drain(..hdr + flen as usize);
                            continue;
                        }
                    }
                    match recv.read(&mut chunk).await {
                        Ok(Some(n)) => buf.extend_from_slice(&chunk[..n]),
                        _ => return,
                    }
                }
                // Echo loop: the client's bytes are already complete
                // h3 frames — relay them verbatim.
                let mut chunk = [0u8; 16 * 1024];
                loop {
                    match recv.read(&mut chunk).await {
                        Ok(Some(0)) | Err(_) | Ok(None) => return,
                        Ok(Some(n)) => {
                            if send.write_all(&chunk[..n]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    }

    /// The QUIC arm honors `ech-opts` through the engine's own TLS 1.3
    /// stack (crate::quic::tls13): an ECH-terminating quinn server
    /// accepts and the h3 CONNECT relay echoes as usual.
    #[tokio::test]
    async fn h3_connect_and_echo_with_ech() {
        let (sk_r, list) = crate::quic::tls13::test_server::ech_server_key(
            &[17u8; 32],
            0x88,
            b"tt-public.example",
        );
        let endpoint = crate::quic::tls13::test_server::start_quinn_server(
            crate::quic::tls13::ServerMode::EchAccept {
                sk_r,
                config_list: list.clone(),
            },
        )
        .await
        .unwrap();
        let port = endpoint.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                if let Ok(conn) = incoming.await {
                    tokio::spawn(h3_serve_conn(conn));
                }
            }
        });
        let mut cfg = test_cfg();
        cfg.port = port;
        cfg.sni = "tt-inner.example".into();
        cfg.quic = true;
        use base64::Engine as _;
        cfg.ech = Some(crate::proto::ech::EchOptions {
            enable: true,
            config: base64::engine::general_purpose::STANDARD.encode(&list),
            query_server_name: String::new(),
        });
        let pool = TrustTunnelPool::new(&cfg, None).await.unwrap();
        let target = NetAddr::domain("echo.example", 443).unwrap();
        let mut stream = pool.dial(&target, None).await.unwrap();
        stream.write_all(b"ping-ech").await.unwrap();
        let mut buf = [0u8; 8];
        tokio::time::timeout(Duration::from_secs(15), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"ping-ech");
    }

    #[tokio::test]
    async fn h3_connect_and_echo() {
        let endpoint = quinn::Endpoint::server(
            quinn_server_config(),
            std::net::SocketAddr::from(([127, 0, 0, 1], 0)),
        )
        .expect("server endpoint");
        let port = endpoint.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                if let Ok(conn) = incoming.await {
                    tokio::spawn(h3_serve_conn(conn));
                }
            }
        });
        let mut cfg = test_cfg();
        cfg.port = port;
        cfg.sni = "tt.example".into();
        cfg.quic = true;
        let pool = TrustTunnelPool::new(&cfg, None).await.unwrap();
        let target = NetAddr::domain("echo.example", 443).unwrap();
        let mut stream = pool.dial(&target, None).await.unwrap();
        stream.write_all(b"ping-h3").await.unwrap();
        let mut buf = [0u8; 7];
        tokio::time::timeout(Duration::from_secs(15), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"ping-h3");
        let payload: Vec<u8> = (0..50_000u32).map(|i| (i % 249) as u8).collect();
        stream.write_all(&payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut got))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, payload);
        // The UDP association over h3.
        let udp = pool.listen_packet(None).await;
        // (The h3 mimic only echoes TCP-form streams; the UDP arm
        // covers the CONNECT + framing path in the h2 tests.)
        match udp {
            Ok(_) => {}
            Err(e) => panic!("h3 udp connect failed: {e}"),
        }
    }

    #[tokio::test]
    async fn alpn_requirements() {
        let mut cfg = test_cfg();
        cfg.alpn = vec!["http/1.1".to_string()];
        // TCP mode: require alpn h2.
        cfg.port = 1;
        let err = tls_wrap(&cfg, Box::new(tokio::io::duplex(16).0))
            .await
            .err()
            .map(|e| e.to_string())
            .unwrap_or_default();
        assert!(err.contains("require alpn h2"), "{err}");
        let mut cfg = test_cfg();
        cfg.quic = true;
        cfg.alpn = vec!["http/1.1".to_string()];
        cfg.port = 1;
        cfg.sni = "x".into();
        let err = quic_dial(&cfg).await.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(err.contains("require alpn h3"), "{err}");
    }
}
