//! hysteria2 outbound over QUIC, ported from the upstream protocol
//! packages (apernet/hysteria protocol + SagerNet/sing-quic hysteria2):
//! auth is a minimal HTTP/3 POST to `https://hysteria/auth` carrying the
//! password in the `Hysteria-Auth` header (status 233 = ok); TCP relays
//! are bidirectional streams framed with `0x401` varint requests; UDP
//! relays use QUIC datagrams with session/packet/fragment headers. The
//! optional salamander obfuscator (8 random salt bytes, blake2b-256
//! keystream) wraps the UDP socket under QUINN.

use std::collections::{HashMap, VecDeque};
use std::io::{self, IoSliceMut};
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, OnceLock};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use rand::rngs::OsRng;
use rand::{Rng, RngCore};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::addr::NetAddr;
use crate::error::{Error, Result};
use crate::quic::{self, QuicDial, QuicStream};
use crate::stream::BoxProxyStream;

/// Outbound hysteria2 endpoint.
#[derive(Debug, Clone)]
pub struct Hysteria2Cfg {
    pub server: String,
    pub port: u16,
    /// Auth password (sent as the `Hysteria-Auth` header value).
    pub password: String,
    pub sni: String,
    pub skip_verify: bool,
    /// Optional salamander obfuscation key wrapping the QUIC socket.
    pub obfs: Option<String>,
}

// ---------------------------------------------------------------------------
// Auth (HTTP/3 constants from upstream protocol/http.go)
// ---------------------------------------------------------------------------

const URL_HOST: &str = "hysteria";
const URL_PATH: &str = "/auth";
const HDR_AUTH: &str = "hysteria-auth";
const HDR_UDP: &str = "hysteria-udp";
const HDR_CCRX: &str = "hysteria-cc-rx";
const HDR_PADDING: &str = "hysteria-padding";
/// Server status code for successful authentication.
const STATUS_AUTH_OK: u16 = 233;

// HTTP/3 / QPACK frame types (RFC 9114 / RFC 9204).
const H3_FRAME_HEADERS: u64 = 0x1;
const H3_FRAME_SETTINGS: u64 = 0x4;
const H3_STREAM_CONTROL: u8 = 0x0;
const H3_STREAM_QPACK_ENCODER: u8 = 0x2;
const H3_STREAM_QPACK_DECODER: u8 = 0x3;

/// Connect, authenticate and return the live QUIC connection.
pub async fn connect(cfg: &Hysteria2Cfg) -> Result<quinn::Connection> {
    let dial = QuicDial {
        server: cfg.server.clone(),
        port: cfg.port,
        sni: cfg.sni.clone(),
        alpn: vec!["h3".to_string()],
        skip_verify: cfg.skip_verify,
        udp_relay: true,
        congestion_brutal_bps: None,
    };
    let conn = match cfg.obfs.as_deref() {
        Some(key) if !key.is_empty() => dial_obfs(&dial, key.as_bytes(), None).await?,
        _ => quic::dial(&dial).await?,
    };
    authenticate(&conn, cfg).await?;
    Ok(conn)
}

/// [`connect`] with ECH (mihomo `ech-opts` on a hysteria2 outbound): the
/// QUIC dial runs on the engine's own TLS 1.3 stack
/// ([`crate::quic::tls13`]) with the ECH cover — the inner hello carries
/// the real SNI and ALPN `h3`, HPKE-sealed inside the outer. The HTTP/3
/// auth exchange that follows is unchanged. A server that rejects ECH
/// surfaces the upstream `"tls: server rejected ECH"` (with one retry on
/// the server's retry configs, `quic::dial_ech`).
pub async fn connect_ech(
    cfg: &Hysteria2Cfg,
    opts: &crate::proto::ech::EchOptions,
) -> Result<quinn::Connection> {
    let selection = quic::ech_selection(opts)?;
    let dial = QuicDial {
        server: cfg.server.clone(),
        port: cfg.port,
        sni: cfg.sni.clone(),
        alpn: vec!["h3".to_string()],
        skip_verify: cfg.skip_verify,
        udp_relay: true,
        congestion_brutal_bps: None,
    };
    let conn = match cfg.obfs.as_deref() {
        Some(key) if !key.is_empty() => {
            dial_obfs(
                &dial,
                key.as_bytes(),
                Some(quic::QuicTlsCover::Ech(selection)),
            )
            .await?
        }
        _ => quic::dial_ech(&dial, selection).await?,
    };
    authenticate(&conn, cfg).await?;
    Ok(conn)
}

/// QUIC dial through a salamander-obfuscated UDP socket: quinn drives a
/// custom [`quinn::AsyncUdpSocket`] that pads/xors every datagram.
/// `cover` swaps the rustls handshake for the engine's own TLS 1.3
/// stack (ECH).
async fn dial_obfs(
    cfg: &QuicDial,
    password: &[u8],
    cover: Option<quic::QuicTlsCover>,
) -> Result<quinn::Connection> {
    let remote = quic::resolve_remote(&cfg.server, cfg.port).await?;
    let socket = tokio::net::UdpSocket::bind(quic::family_bind_addr(remote))
        .await
        .map_err(|e| Error::network(format!("salamander bind: {e}")))?;
    crate::mark::apply(&socket);
    let mut endpoint = quinn::Endpoint::new_with_abstract_socket(
        quinn::EndpointConfig::default(),
        None,
        Arc::new(SalamanderSocket::new(socket, password.to_vec())),
        Arc::new(quinn::TokioRuntime),
    )
    .map_err(|e| Error::network(format!("salamander endpoint: {e}")))?;
    let client_cfg = match &cover {
        Some(cover) => {
            let mut quic = quic::client_config_custom(cfg, cover)?;
            let mut transport = quinn::TransportConfig::default();
            transport.max_concurrent_uni_streams(1024u32.into());
            if cfg.udp_relay {
                transport.datagram_receive_buffer_size(Some(64 * 1024));
            }
            quic.transport_config(Arc::new(transport));
            quic
        }
        None => quic::client_config(cfg)?,
    };
    endpoint.set_default_client_config(client_cfg);
    let conn = endpoint
        .connect(remote, &cfg.sni)
        .map_err(|e| Error::config(format!("quic connect to {remote}: {e}")))?
        .await
        .map_err(|e| Error::network(format!("salamander quic handshake with {remote}: {e}")))?;
    Ok(conn)
}

/// The response fields the auth exchange cares about.
#[derive(Debug, Default, PartialEq, Eq)]
struct AuthResponse {
    status: u16,
    udp_enabled: bool,
}

/// Authenticate over a minimal HTTP/3 exchange: open the client control
/// and QPACK streams (kept open for the connection lifetime — closing
/// them is a fatal HTTP/3 error), POST to `https://hysteria/auth` and
/// require status 233.
async fn authenticate(conn: &quinn::Connection, cfg: &Hysteria2Cfg) -> Result<()> {
    let mut control = open_uni(conn, "auth control").await?;
    let mut qpack_enc = open_uni(conn, "auth qpack encoder").await?;
    let mut qpack_dec = open_uni(conn, "auth qpack decoder").await?;
    // Control stream type + an empty SETTINGS frame; empty QPACK streams.
    control
        .write_all(&[H3_STREAM_CONTROL, H3_FRAME_SETTINGS as u8, 0])
        .await
        .map_err(|e| Error::network(format!("hysteria2 control stream: {e}")))?;
    qpack_enc
        .write_all(&[H3_STREAM_QPACK_ENCODER])
        .await
        .map_err(|e| Error::network(format!("hysteria2 qpack encoder stream: {e}")))?;
    qpack_dec
        .write_all(&[H3_STREAM_QPACK_DECODER])
        .await
        .map_err(|e| Error::network(format!("hysteria2 qpack decoder stream: {e}")))?;

    let (mut send, mut recv) = conn
        .open_bi()
        .await
        .map_err(|e| Error::network(format!("hysteria2 auth stream: {e}")))?;
    let stream_id = u64::from(send.id());
    let padding = random_padding(256, 2048);
    let request = build_auth_request(&cfg.password, 0, &padding);
    send.write_all(&request)
        .await
        .map_err(|e| Error::network(format!("hysteria2 auth request: {e}")))?;
    // Empty POST body: FIN right after the headers.
    send.finish()
        .map_err(|e| Error::network(format!("hysteria2 auth fin: {e}")))?;

    // RFC 9204 §2: dynamic-table instructions arrive on the server's QPACK
    // encoder stream (uni type 0x02) and must be applied before response
    // field sections reference them. Consume the server's uni streams for
    // the whole connection lifetime.
    let table = Arc::new(Mutex::new(QpackDecoder::default()));
    let table_updated = Arc::new(tokio::sync::Notify::new());
    spawn_qpack_encoder_reader(conn.clone(), table.clone(), table_updated.clone());

    let resp =
        read_auth_response(&mut recv, &mut qpack_dec, stream_id, &table, &table_updated).await?;
    if resp.status != STATUS_AUTH_OK {
        return Err(Error::network(format!(
            "hysteria2 auth failed with status {}",
            resp.status
        )));
    }
    tracing::debug!(target: "engine", "hysteria2 auth ok (server udp: {})", resp.udp_enabled);

    // Dropping quinn SendStreams would FIN (close) them; HTTP/3 marks the
    // control and QPACK streams critical, so hold them open until the
    // connection itself ends.
    let holder = conn.clone();
    tokio::spawn(async move {
        let _keep = (control, qpack_enc, qpack_dec);
        let _ = holder.closed().await;
    });
    Ok(())
}

async fn open_uni(conn: &quinn::Connection, what: &str) -> Result<quinn::SendStream> {
    conn.open_uni()
        .await
        .map_err(|e| Error::network(format!("hysteria2 open {what} stream: {e}")))
}

/// Serialize the auth POST: one HEADERS frame carrying a QPACK field
/// section of literal (never-indexed, new-name) entries.
fn build_auth_request(password: &str, cc_rx: u64, padding: &str) -> Vec<u8> {
    let mut block = Vec::with_capacity(512);
    // QPACK field section prefix: required insert count 0, base 0.
    block.extend_from_slice(&[0x00, 0x00]);
    put_qpack_literal(&mut block, b":method", b"POST");
    put_qpack_literal(&mut block, b":scheme", b"https");
    put_qpack_literal(&mut block, b":authority", URL_HOST.as_bytes());
    put_qpack_literal(&mut block, b":path", URL_PATH.as_bytes());
    put_qpack_literal(&mut block, HDR_AUTH.as_bytes(), password.as_bytes());
    put_qpack_literal(&mut block, HDR_CCRX.as_bytes(), cc_rx.to_string().as_bytes());
    put_qpack_literal(&mut block, HDR_PADDING.as_bytes(), padding.as_bytes());
    let mut out = Vec::with_capacity(block.len() + 16);
    put_h3_frame(&mut out, H3_FRAME_HEADERS, &block);
    out
}

fn put_h3_frame(out: &mut Vec<u8>, frame_type: u64, payload: &[u8]) {
    quic::write_varint(out, frame_type);
    quic::write_varint(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

/// Read one HTTP/3 exchange from the auth stream until its HEADERS frame
/// is complete, then extract `:status` and the hysteria headers. Field
/// sections whose Required Insert Count runs ahead of the inserts applied
/// so far (RFC 9204 §2.1.2) block until the encoder stream delivers the
/// missing instructions — response bytes keep buffering while waiting.
async fn read_auth_response(
    recv: &mut quinn::RecvStream,
    qpack_dec: &mut quinn::SendStream,
    stream_id: u64,
    table: &Arc<Mutex<QpackDecoder>>,
    table_updated: &Arc<tokio::sync::Notify>,
) -> Result<AuthResponse> {
    let mut buf = Vec::with_capacity(512);
    let mut chunk = [0u8; 4096];
    loop {
        // Register for table updates BEFORE re-decoding so a notification
        // that lands between decode and wait still wakes us.
        let notified = table_updated.notified();
        tokio::pin!(notified);
        let decoded = match parse_h3_headers_frame(&buf)? {
            Some(block) => lock_table(table).decode_field_section(block)?,
            None => None,
        };
        let Some(decoded) = decoded else {
            let blocked = parse_h3_headers_frame(&buf)?.is_some();
            // `None` here means "no new response bytes, retry the decode"
            // (a table update arrived); `Some(n)` extends the buffer.
            let n: Option<usize> = if blocked {
                // Blocked section: progress may come from either stream.
                let event = tokio::time::timeout(QPACK_BLOCK_TIMEOUT, async {
                    tokio::select! {
                        () = &mut notified => None,
                        r = recv.read(&mut chunk) => Some(r),
                    }
                })
                .await
                .map_err(|_| Error::protocol("qpack: dynamic table stalled"))?;
                match event {
                    None => None,
                    Some(r) => Some(
                        r.map_err(|e| {
                            Error::network(format!("hysteria2 auth read: {e}"))
                        })?
                        .ok_or_else(|| {
                            Error::protocol("hysteria2 auth: EOF before response")
                        })?,
                    ),
                }
            } else {
                Some(
                    recv.read(&mut chunk)
                        .await
                        .map_err(|e| {
                            Error::network(format!("hysteria2 auth read: {e}"))
                        })?
                        .ok_or_else(|| {
                            Error::protocol("hysteria2 auth: EOF before response")
                        })?,
                )
            };
            if let Some(n) = n {
                buf.extend_from_slice(&chunk[..n]);
                if buf.len() > 16 * 1024 {
                    return Err(Error::protocol("hysteria2 auth: response too large"));
                }
            }
            continue;
        };
        if decoded.required_insert_count > 0 {
            // RFC 9204 §4.4.1: acknowledge sections that used the table.
            let mut ack = Vec::with_capacity(8);
            put_prefixed_int(&mut ack, 0x80, 7, stream_id);
            let _ = qpack_dec.write_all(&ack).await;
        }
        let mut resp = AuthResponse::default();
        for (name, value) in decoded.fields {
            match name.as_str() {
                ":status" => {
                    resp.status = value
                        .parse()
                        .map_err(|_| Error::protocol(format!("h3 bad status {value:?}")))?;
                }
                HDR_UDP => resp.udp_enabled = value == "true",
                _ => {}
            }
        }
        return Ok(resp);
    }
}

/// Lock the shared QPACK decoder, recovering from a poisoned lock (a
/// panicking task must not wedge the connection).
fn lock_table(table: &Arc<Mutex<QpackDecoder>>) -> std::sync::MutexGuard<'_, QpackDecoder> {
    table.lock().unwrap_or_else(|e| e.into_inner())
}

/// Upper bound on buffered encoder-stream bytes awaiting a complete
/// instruction.
const QPACK_ENCODER_BUFFER_MAX: usize = 64 * 1024;

/// Consume the server's unidirectional streams: the QPACK encoder stream
/// (type 0x02) feeds instructions into the shared table, waking blocked
/// decoders (RFC 9204 §4.3); the control (0x00) and QPACK decoder (0x03)
/// streams are drained.
fn spawn_qpack_encoder_reader(
    conn: quinn::Connection,
    table: Arc<Mutex<QpackDecoder>>,
    table_updated: Arc<tokio::sync::Notify>,
) {
    tokio::spawn(async move {
        while let Ok(mut uni) = conn.accept_uni().await {
            // H3 unidirectional stream types are single-byte QUIC varints
            // (< 0x40); anything else is an unknown type to drain.
            let mut head = [0u8; 1];
            let Ok(Some(1)) = uni.read(&mut head).await else {
                continue;
            };
            if head[0] != H3_STREAM_QPACK_ENCODER {
                let mut sink = [0u8; 4096];
                while let Ok(Some(_)) = uni.read(&mut sink).await {}
                continue;
            }
            let mut pending: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match uni.read(&mut chunk).await {
                    Ok(Some(n)) => {
                        pending.extend_from_slice(&chunk[..n]);
                        if pending.len() > QPACK_ENCODER_BUFFER_MAX {
                            lock_table(&table).fatal("qpack: encoder stream overflow");
                            return;
                        }
                        let consumed = lock_table(&table).apply_encoder_instructions(&pending);
                        match consumed {
                            Ok(n) if n > 0 => {
                                pending.drain(..n);
                                table_updated.notify_one();
                            }
                            Ok(_) => {} // partial instruction: await more bytes
                            Err(e) => {
                                lock_table(&table).fatal(&e.to_string());
                                table_updated.notify_one();
                                return;
                            }
                        }
                    }
                    _ => return, // EOF or read error: encoder stream over
                }
            }
        }
    });
}

/// If `buf` holds a complete HEADERS frame (possibly preceded by other
/// frames, which all share the type/length structure and are skipped),
/// return its field section. `None` when more bytes are needed.
fn parse_h3_headers_frame(buf: &[u8]) -> Result<Option<&[u8]>> {
    let mut off = 0usize;
    loop {
        let Some((frame_type, n)) = quic::read_varint(&buf[off..]) else {
            return Ok(None);
        };
        off += n;
        let Some((len, n)) = quic::read_varint(&buf[off..]) else {
            return Ok(None);
        };
        off += n;
        let len =
            usize::try_from(len).map_err(|_| Error::protocol("h3 frame too large"))?;
        let Some(payload) = buf.get(off..off + len) else {
            return Ok(None);
        };
        if frame_type == H3_FRAME_HEADERS {
            return Ok(Some(payload));
        }
        off += len;
    }
}

// ---------------------------------------------------------------------------
// QPACK (RFC 9204): literal-only encoder + full decoder (static AND
// dynamic table). The dynamic half is what mihomo-era quic-go servers
// trip: quic-go's http3 responseWriter auto-adds `Date` to every response
// and its qpack encoder writes that name as a literal-with-name-reference
// to static index 6 — a single 0x56 byte whose 4-bit index prefix the old
// decoder misread as the T bit (T lives at 0x10, RFC 9204 §4.5.4),
// killing every hy2 relay at "qpack: dynamic name reference".
// ---------------------------------------------------------------------------

/// The QPACK static table (RFC 9204 appendix A), 0-indexed.
const QPACK_STATIC_TABLE: &[(&str, &str)] = &[
    (":authority", ""),
    (":path", "/"),
    ("age", "0"),
    ("content-disposition", ""),
    ("content-length", "0"),
    ("cookie", ""),
    ("date", ""),
    ("etag", ""),
    ("if-modified-since", ""),
    ("if-none-match", ""),
    ("last-modified", ""),
    ("link", ""),
    ("location", ""),
    ("referer", ""),
    ("set-cookie", ""),
    (":method", "CONNECT"),
    (":method", "DELETE"),
    (":method", "GET"),
    (":method", "HEAD"),
    (":method", "OPTIONS"),
    (":method", "POST"),
    (":method", "PUT"),
    (":scheme", "http"),
    (":scheme", "https"),
    (":status", "103"),
    (":status", "200"),
    (":status", "304"),
    (":status", "404"),
    (":status", "503"),
    ("accept", "*/*"),
    ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"),
    ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"),
    ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"),
    ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"),
    ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"),
    ("content-encoding", "br"),
    ("content-encoding", "gzip"),
    ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"),
    ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"),
    ("content-type", "image/gif"),
    ("content-type", "image/jpeg"),
    ("content-type", "image/png"),
    ("content-type", "text/css"),
    ("content-type", "text/html;charset=utf-8"),
    ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"),
    ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    ("strict-transport-security", "max-age=31536000;includesubdomains"),
    (
        "strict-transport-security",
        "max-age=31536000;includesubdomains;preload",
    ),
    ("vary", "accept-encoding"),
    ("vary", "origin"),
    ("x-content-type-options", "nosniff"),
    ("x-xss-protection", "1; mode=block"),
    (":status", "100"),
    (":status", "204"),
    (":status", "206"),
    (":status", "302"),
    (":status", "400"),
    (":status", "403"),
    (":status", "421"),
    (":status", "425"),
    (":status", "500"),
    ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"),
    ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"),
    ("alt-svc", "clear"),
    ("authorization", ""),
    (
        "content-security-policy",
        "script-src 'none'; object-src 'none'; base-uri 'none'",
    ),
    ("early-data", "1"),
    ("expect-ct", ""),
    ("forwarded", ""),
    ("if-range", ""),
    ("origin", ""),
    ("purpose", "prefetch"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

/// Append one "literal field line with literal name" (0010 pattern, no
/// Huffman on our side — the values here are short or already random).
fn put_qpack_literal(block: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    put_prefixed_int(block, 0x20, 3, name.len() as u64);
    block.extend_from_slice(name);
    put_prefixed_int(block, 0x00, 7, value.len() as u64);
    block.extend_from_slice(value);
}

/// HPACK/QPACK integer with a `prefix_bits`-wide prefix; `flags` carries
/// the pattern/Huffman bits above the prefix.
fn put_prefixed_int(buf: &mut Vec<u8>, flags: u8, prefix_bits: u32, v: u64) {
    let max = (1u64 << prefix_bits) - 1;
    if v < max {
        buf.push(flags | v as u8);
        return;
    }
    buf.push(flags | max as u8);
    let mut rest = v - max;
    while rest >= 0x80 {
        buf.push(rest as u8 | 0x80);
        rest >>= 7;
    }
    buf.push(rest as u8);
}

/// Read an integer with a `prefix_bits`-wide prefix starting at `off`.
/// Returns the value and the new offset.
fn read_prefixed_int(data: &[u8], off: usize, prefix_bits: u32) -> Option<(u64, usize)> {
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

/// Read a string literal whose length prefix is `prefix_bits` wide;
/// `huff_mask` selects the Huffman bit position for this representation.
fn read_string_literal(
    data: &[u8],
    off: usize,
    prefix_bits: u32,
    huff_mask: u8,
) -> Option<(Vec<u8>, usize)> {
    let first = *data.get(off)?;
    let huffman = first & huff_mask != 0;
    let (len, off) = read_prefixed_int(data, off, prefix_bits)?;
    let len = usize::try_from(len).ok()?;
    let bytes = data.get(off..off.checked_add(len)?)?;
    let off = off + len;
    if huffman {
        Some((huffman_decode(bytes)?, off))
    } else {
        Some((bytes.to_vec(), off))
    }
}

/// Dynamic-table capacity assumed until the encoder sends a Set Dynamic
/// Table Capacity instruction (RFC 9204 §4.3.1). This client advertises
/// SETTINGS_QPACK_MAX_TABLE_CAPACITY = 0 (§5), which forbids a conforming
/// encoder from using the dynamic table at all; the decoder still
/// tolerates encoders that do — bounded by this cap.
const QPACK_LENIENT_CAPACITY: u64 = 64 * 1024;
/// Upper bound accepted for Set Dynamic Table Capacity in lenient mode
/// (a conformant value never exceeds the advertised maximum, which is 0).
const QPACK_LENIENT_MAX_CAPACITY: u64 = 1 << 20;
/// How long a field section may stay blocked (RFC 9204 §2.1.2) waiting
/// for encoder-stream instructions before the exchange fails.
const QPACK_BLOCK_TIMEOUT: Duration = Duration::from_secs(10);

/// One decoded field section.
#[derive(Debug, Default)]
struct DecodedSection {
    fields: Vec<(String, String)>,
    /// Required Insert Count of the section (§4.5.1.1); nonzero sections
    /// must be acknowledged on the decoder stream (§4.4.1).
    required_insert_count: u64,
}

/// The QPACK decoding state: static-table lookups plus the RFC 9204
/// dynamic table (§3.2) driven by encoder-stream instructions (§4.3).
#[derive(Debug)]
struct QpackDecoder {
    /// Dynamic entries, newest first (front = highest absolute index).
    entries: VecDeque<(String, String)>,
    /// Current table size in bytes (§3.2.1: name + value + 32 per entry).
    size: u64,
    /// Capacity last declared via Set Dynamic Table Capacity.
    capacity: u64,
    /// Total inserts ever applied — the absolute index the next entry
    /// will receive (§3.2.4).
    insert_count: u64,
    /// The maximum capacity we advertised in SETTINGS (0: none sent).
    max_table_capacity: u64,
    /// Set when the encoder stream becomes unrecoverable; every decode
    /// then fails instead of mis-decoding.
    fatal: Option<String>,
}

impl Default for QpackDecoder {
    fn default() -> Self {
        QpackDecoder {
            entries: VecDeque::new(),
            size: 0,
            capacity: QPACK_LENIENT_CAPACITY,
            insert_count: 0,
            max_table_capacity: 0,
            fatal: None,
        }
    }
}

impl QpackDecoder {
    /// A decoder advertising a nonzero SETTINGS_QPACK_MAX_TABLE_CAPACITY
    /// (tests; the client itself advertises 0).
    #[cfg(test)]
    fn with_max_capacity(max: u64) -> Self {
        QpackDecoder {
            max_table_capacity: max,
            ..QpackDecoder::default()
        }
    }

    /// Poison the decoder: the encoder stream is broken.
    fn fatal(&mut self, why: &str) {
        if self.fatal.is_none() {
            self.fatal = Some(why.to_string());
        }
    }

    /// §3.2.1 entry size.
    fn entry_size(name: &str, value: &str) -> u64 {
        32 + name.len() as u64 + value.len() as u64
    }

    /// Insert an entry (§3.2.2): entries larger than the capacity are a
    /// protocol error; otherwise the oldest entries are evicted until the
    /// table fits the capacity again.
    fn insert(&mut self, name: String, value: String) -> Result<()> {
        if Self::entry_size(&name, &value) > self.capacity {
            return Err(Error::protocol(
                "qpack: insert exceeds dynamic table capacity",
            ));
        }
        self.size += Self::entry_size(&name, &value);
        self.entries.push_front((name, value));
        self.insert_count += 1;
        while self.size > self.capacity {
            let Some((name, value)) = self.entries.pop_back() else {
                break;
            };
            self.size -= Self::entry_size(&name, &value);
        }
        Ok(())
    }

    /// Evict until the table fits (§3.2.2, after a capacity reduction).
    fn evict_to_capacity(&mut self) {
        while self.size > self.capacity {
            let Some((name, value)) = self.entries.pop_back() else {
                break;
            };
            self.size -= Self::entry_size(&name, &value);
        }
    }

    /// Resolve an absolute dynamic-table index (§3.2.4).
    fn lookup_absolute(&self, abs: u64) -> Result<&(String, String)> {
        let len = self.entries.len() as u64;
        let Some(oldest) = self.insert_count.checked_sub(len) else {
            return Err(Error::protocol("qpack: dynamic table state invalid"));
        };
        if abs < oldest || abs >= self.insert_count {
            return Err(Error::protocol(format!(
                "qpack: dynamic index {abs} out of range"
            )));
        }
        let pos = (self.insert_count - 1 - abs) as usize;
        self.entries
            .get(pos)
            .ok_or_else(|| Error::protocol("qpack: dynamic table state invalid"))
    }

    /// Relative index as used inside encoder instructions (§3.2.5):
    /// relative 0 is the most recently inserted entry.
    fn lookup_encoder_relative(&self, rel: u64) -> Result<&(String, String)> {
        let abs = rel
            .checked_add(1)
            .and_then(|r| self.insert_count.checked_sub(r))
            .ok_or_else(|| Error::protocol(format!("qpack: encoder index {rel} before table")))?;
        self.lookup_absolute(abs)
    }

    /// Apply encoder-stream instructions (§4.3) from `data`, returning
    /// the number of bytes consumed. A truncated instruction at the tail
    /// stays unconsumed until more encoder-stream bytes arrive.
    fn apply_encoder_instructions(&mut self, data: &[u8]) -> Result<usize> {
        if let Some(why) = &self.fatal {
            return Err(Error::protocol(why.clone()));
        }
        let mut off = 0usize;
        while off < data.len() {
            let b = data[off];
            if b & 0x80 != 0 {
                // §4.3.2 insert with name reference: 1T + 6-bit index,
                // then the value as a string literal.
                let is_static = b & 0x40 != 0;
                let Some((idx, n)) = read_prefixed_int(data, off, 6) else {
                    break;
                };
                let Some((value, n2)) = read_string_literal(data, n, 7, 0x80) else {
                    break;
                };
                let name = if is_static {
                    QPACK_STATIC_TABLE
                        .get(idx as usize)
                        .ok_or_else(|| {
                            Error::protocol(format!("qpack: bad static name index {idx}"))
                        })?
                        .0
                        .to_string()
                } else {
                    self.lookup_encoder_relative(idx)?.0.clone()
                };
                self.insert(name, String::from_utf8_lossy(&value).into_owned())?;
                off = n2;
            } else if b & 0xc0 == 0x40 {
                // §4.3.3 insert with literal name: 01H + name string
                // literal, then the value string literal.
                let Some((name, n)) = read_string_literal(data, off, 5, 0x20) else {
                    break;
                };
                let Some((value, n2)) = read_string_literal(data, n, 7, 0x80) else {
                    break;
                };
                self.insert(
                    String::from_utf8_lossy(&name).into_owned(),
                    String::from_utf8_lossy(&value).into_owned(),
                )?;
                off = n2;
            } else if b & 0xe0 == 0x20 {
                // §4.3.1 set dynamic table capacity: 001 + 5-bit integer.
                let Some((cap, n)) = read_prefixed_int(data, off, 5) else {
                    break;
                };
                if self.max_table_capacity > 0 && cap > self.max_table_capacity {
                    return Err(Error::protocol(
                        "qpack: capacity exceeds advertised maximum",
                    ));
                }
                if cap > QPACK_LENIENT_MAX_CAPACITY {
                    return Err(Error::protocol("qpack: dynamic table capacity too large"));
                }
                self.capacity = cap;
                self.evict_to_capacity();
                off = n;
            } else {
                // §4.3.4 duplicate: 000 + 5-bit relative index.
                let Some((rel, n)) = read_prefixed_int(data, off, 5) else {
                    break;
                };
                let (name, value) = self.lookup_encoder_relative(rel)?.clone();
                self.insert(name, value)?;
                off = n;
            }
        }
        Ok(off)
    }

    /// Decode one field section (§4.5). Returns `Ok(None)` while the
    /// section is blocked — its Required Insert Count runs ahead of the
    /// inserts applied so far (§2.1.2); the caller waits for more
    /// encoder-stream bytes and retries on the same buffer.
    fn decode_field_section(&mut self, buf: &[u8]) -> Result<Option<DecodedSection>> {
        if let Some(why) = &self.fatal {
            return Err(Error::protocol(why.clone()));
        }
        let (enc_ric, off) = read_prefixed_int(buf, 0, 8)
            .ok_or_else(|| Error::protocol("qpack: truncated prefix"))?;
        let ric = Self::decode_required_insert_count(
            enc_ric,
            self.insert_count,
            self.max_table_capacity,
        )?;
        if ric > self.insert_count {
            return Ok(None); // blocked until the encoder stream catches up
        }
        // §4.5.1.1 "Base": one Sign bit + 7-bit delta, relative to the
        // Required Insert Count.
        let sign = buf
            .get(off)
            .is_some_and(|b| b & 0x80 != 0);
        let (delta, n) = read_prefixed_int(buf, off, 7)
            .ok_or_else(|| Error::protocol("qpack: truncated base"))?;
        let mut off = n;
        let base = if sign {
            ric.checked_sub(delta)
                .and_then(|v| v.checked_sub(1))
                .ok_or_else(|| Error::protocol("qpack: base precedes table start"))?
        } else {
            ric + delta
        };
        let mut fields = Vec::new();
        while off < buf.len() {
            let b = buf[off];
            if b & 0x80 != 0 {
                // §4.5.2 indexed field line: 1T + 6-bit index.
                let is_static = b & 0x40 != 0;
                let (idx, n) = read_prefixed_int(buf, off, 6)
                    .ok_or_else(|| Error::protocol("qpack: truncated index"))?;
                off = n;
                let (name, value) = if is_static {
                    let (name, value) = QPACK_STATIC_TABLE
                        .get(idx as usize)
                        .ok_or_else(|| {
                            Error::protocol(format!("qpack: bad static index {idx}"))
                        })?;
                    (name.to_string(), value.to_string())
                } else {
                    // §3.2.5: relative 0 is the entry at absolute Base-1.
                    let abs = idx
                        .checked_add(1)
                        .and_then(|r| base.checked_sub(r))
                        .ok_or_else(|| {
                            Error::protocol("qpack: dynamic reference before table start")
                        })?;
                    self.lookup_absolute(abs)?.clone()
                };
                fields.push((name, value));
            } else if b & 0xc0 == 0x40 {
                // §4.5.4 literal with name reference: 01NT + 4-bit index.
                // T is bit 4 (0x10); bit 3 belongs to the index prefix —
                // the old decoder tested 0x08 and misfiled every static
                // name reference with index < 8 (e.g. `date`, 0x56) as a
                // dynamic reference.
                let is_static = b & 0x10 != 0;
                let (idx, n) = read_prefixed_int(buf, off, 4)
                    .ok_or_else(|| Error::protocol("qpack: truncated name index"))?;
                off = n;
                let name = if is_static {
                    QPACK_STATIC_TABLE
                        .get(idx as usize)
                        .ok_or_else(|| {
                            Error::protocol(format!("qpack: bad static name index {idx}"))
                        })?
                        .0
                        .to_string()
                } else {
                    let abs = idx
                        .checked_add(1)
                        .and_then(|r| base.checked_sub(r))
                        .ok_or_else(|| {
                            Error::protocol("qpack: dynamic name reference before table start")
                        })?;
                    self.lookup_absolute(abs)?.0.clone()
                };
                let (value, n) = read_string_literal(buf, off, 7, 0x80)
                    .ok_or_else(|| Error::protocol("qpack: truncated value"))?;
                off = n;
                fields.push((name, String::from_utf8_lossy(&value).into_owned()));
            } else if b & 0xe0 == 0x20 {
                // §4.5.6 literal with literal name: 001NH + 3-bit length.
                let (name, n) = read_string_literal(buf, off, 3, 0x08)
                    .ok_or_else(|| Error::protocol("qpack: truncated name"))?;
                off = n;
                let (value, n) = read_string_literal(buf, off, 7, 0x80)
                    .ok_or_else(|| Error::protocol("qpack: truncated value"))?;
                off = n;
                fields.push((
                    String::from_utf8_lossy(&name).into_owned(),
                    String::from_utf8_lossy(&value).into_owned(),
                ));
            } else if b & 0xf0 == 0x10 {
                // §4.5.3 indexed with post-base index: 0001 + 4-bit.
                let (idx, n) = read_prefixed_int(buf, off, 4)
                    .ok_or_else(|| Error::protocol("qpack: truncated post-base index"))?;
                off = n;
                let (name, value) = self.lookup_absolute(base + idx)?;
                fields.push((name.clone(), value.clone()));
            } else {
                // §4.5.5 literal with post-base name reference: 0000N +
                // 3-bit index, then the value string literal.
                let (idx, n) = read_prefixed_int(buf, off, 3)
                    .ok_or_else(|| Error::protocol("qpack: truncated post-base name index"))?;
                off = n;
                let name = self.lookup_absolute(base + idx)?.0.clone();
                let (value, n) = read_string_literal(buf, off, 7, 0x80)
                    .ok_or_else(|| Error::protocol("qpack: truncated value"))?;
                off = n;
                fields.push((name, String::from_utf8_lossy(&value).into_owned()));
            }
        }
        Ok(Some(DecodedSection {
            fields,
            required_insert_count: ric,
        }))
    }

    /// Decode the Encoded Required Insert Count (§4.5.1.1) — the module
    /// `2 * MaxEntries` winding. With MaxTableCapacity 0 (this client's
    /// advertisement) RFC 9204 leaves no legal nonzero encoding; the
    /// lenient fallback takes the encoded value as the literal count so
    /// encoders that use the dynamic table despite a zero-capacity
    /// advertisement still interoperate.
    fn decode_required_insert_count(
        enc: u64,
        total_inserts: u64,
        max_capacity: u64,
    ) -> Result<u64> {
        if enc == 0 {
            return Ok(0);
        }
        let max_entries = max_capacity / 32;
        if max_entries == 0 {
            return Ok(enc); // lenient: see the doc comment
        }
        let full_range = 2 * max_entries;
        if enc > full_range {
            return Err(Error::protocol("qpack: required insert count out of range"));
        }
        let max_value = total_inserts + max_entries;
        let max_wrapped = (max_value / full_range) * full_range;
        let mut ric = max_wrapped + enc - 1;
        if ric > max_value {
            if ric <= full_range {
                return Err(Error::protocol("qpack: required insert count out of range"));
            }
            ric -= full_range;
        }
        if ric == 0 {
            return Err(Error::protocol("qpack: required insert count encoded as zero"));
        }
        Ok(ric)
    }
}

// ---------------------------------------------------------------------------
// HPACK Huffman decoding (RFC 7541 appendix B — QPACK uses the same code)
// ---------------------------------------------------------------------------

/// (code, bit-length) for symbols 0..=256; entry 256 is EOS.
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

fn huffman_map() -> &'static HashMap<(u64, u8), u8> {
    static MAP: OnceLock<HashMap<(u64, u8), u8>> = OnceLock::new();
    MAP.get_or_init(|| {
        // EOS (symbol 256) is excluded: decoding it is an error.
        HUFFMAN_CODES[..256]
            .iter()
            .enumerate()
            .map(|(sym, &(code, len))| ((code, len), sym as u8))
            .collect()
    })
}

/// Decode an HPACK Huffman string; trailing padding shorter than 8 bits
/// must be all ones (a prefix of the EOS symbol).
fn huffman_decode(data: &[u8]) -> Option<Vec<u8>> {
    let map = huffman_map();
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
        return None; // padding must be shorter than one byte
    }
    if len > 0 && code != (1 << len) - 1 {
        return None; // padding must be EOS-prefix ones
    }
    Some(out)
}

/// Random padding string drawn from the upstream alphabet.
fn random_padding(min: usize, max: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
    let n = OsRng.gen_range(min..max);
    (0..n)
        .map(|_| CHARS[OsRng.gen_range(0..CHARS.len())] as char)
        .collect()
}

// ---------------------------------------------------------------------------
// TCP relay framing (upstream protocol/proxy.go)
// ---------------------------------------------------------------------------

/// TCP request frame type; QUIC varint.
const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;
const MAX_ADDRESS_LENGTH: usize = 2048;
const MAX_MESSAGE_LENGTH: usize = 2048;
const MAX_PADDING_LENGTH: usize = 4096;

/// Open a TCP relay on a new bidirectional stream: send the `0x401`
/// request (address + padding), consume the status response, then hand
/// back the raw relay stream.
pub async fn tcp_stream(conn: &quinn::Connection, target: &NetAddr) -> Result<BoxProxyStream> {
    let (send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| Error::network(format!("hysteria2 open stream: {e}")))?;
    let mut stream = QuicStream::new(send, recv);
    let header = tcp_request_header(&target.to_string(), &random_padding(64, 512));
    stream.write_all(&header).await?;

    // The response frame is consumed lazily on the first read (see
    // Hysteria2Stream::resp_pending) — blocking here deadlocks against
    // the real server's lazy first-write framing.
    Ok(Box::new(Hysteria2Stream {
        inner: Box::new(stream),
        pending: Vec::new(),
        resp_pending: true,
        resp_buf: Vec::new(),
    }))
}

/// A relay stream that replays bytes read past the protocol response
/// before delegating to the wrapped QUIC stream.
pub struct Hysteria2Stream {
    inner: BoxProxyStream,
    pending: Vec<u8>,
    /// The server writes its TCPResponse frame LAZILY, together with
    /// the first data bytes (sing `serverConn.Write` prepends
    /// `WriteTCPResponse(true, ..)` on the first write), so the client
    /// must NOT block on it before forwarding the request — the frame
    /// is consumed on the first READ instead (official client behavior).
    resp_pending: bool,
    /// Accumulator for the partially-received response frame.
    resp_buf: Vec<u8>,
}

impl AsyncWrite for Hysteria2Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for Hysteria2Stream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.resp_pending {
            // Buffer until the response frame parses, then replay the
            // remainder as payload.
            loop {
                match parse_tcp_response(&this.resp_buf) {
                    Ok(Some(used)) => {
                        this.pending.extend_from_slice(&this.resp_buf[used..]);
                        this.resp_pending = false;
                        break;
                    }
                    Ok(None) => {}
                    Err(e) => return Poll::Ready(Err(io::Error::new(io::ErrorKind::InvalidData, e))),
                }
                let mut chunk = [0u8; 4096];
                let mut rb = ReadBuf::new(&mut chunk);
                match Pin::new(&mut this.inner).poll_read(cx, &mut rb) {
                    Poll::Ready(Ok(())) => {}
                    Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                    Poll::Pending => return Poll::Pending,
                }
                if rb.filled().is_empty() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "hysteria2 tcp: EOF before response frame",
                    )));
                }
                this.resp_buf.extend_from_slice(rb.filled());
            }
        }
        if !this.pending.is_empty() {
            let n = this.pending.len().min(buf.remaining());
            buf.put_slice(&this.pending[..n]);
            this.pending.drain(..n);
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

/// `0x401 || varint(len) || addr || varint(len) || padding`, mirroring
/// upstream `WriteTCPRequest` (address is the `host:port` display form,
/// IPv6 bracketed).
pub fn tcp_request_header(addr: &str, padding: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(
        quic::varint_len(FRAME_TYPE_TCP_REQUEST)
            + quic::varint_len(addr.len() as u64)
            + quic::varint_len(padding.len() as u64)
            + addr.len()
            + padding.len(),
    );
    quic::write_varint(&mut buf, FRAME_TYPE_TCP_REQUEST);
    quic::write_varint(&mut buf, addr.len() as u64);
    buf.extend_from_slice(addr.as_bytes());
    quic::write_varint(&mut buf, padding.len() as u64);
    buf.extend_from_slice(padding.as_bytes());
    buf
}

/// Parse a TCP request header; returns the address, the padding length
/// and the offset where the padding starts. Test-side mirror of
/// upstream `ReadTCPRequest` (which runs after the frame-type varint
/// has been consumed).
#[cfg(test)]
fn parse_tcp_request(data: &[u8]) -> Result<(String, usize, usize)> {
    let (addr_len, mut off) = quic::read_varint(data).ok_or_else(|| Error::protocol("tcp req: short"))?;
    if addr_len == 0 || addr_len > MAX_ADDRESS_LENGTH as u64 {
        return Err(Error::protocol("tcp req: invalid address length"));
    }
    let addr = data
        .get(off..off + addr_len as usize)
        .ok_or_else(|| Error::protocol("tcp req: short address"))?;
    off += addr_len as usize;
    let (pad_len, n) = quic::read_varint(&data[off..])
        .ok_or_else(|| Error::protocol("tcp req: short padding len"))?;
    if pad_len > MAX_PADDING_LENGTH as u64 {
        return Err(Error::protocol("tcp req: invalid padding length"));
    }
    let addr = std::str::from_utf8(addr).map_err(|_| Error::protocol("tcp req: bad utf-8"))?;
    let pad_at = off + n;
    let pad_len = pad_len as usize;
    if pad_at + pad_len > data.len() {
        return Err(Error::protocol("tcp req: short padding"));
    }
    Ok((addr.to_string(), pad_len, pad_at))
}

/// Try to parse the server's TCP response: status byte (0 = ok, else the
/// message carries the error), varint message length, message, varint
/// padding length, padding. Returns the offset where the padding ends
/// (relay data follows), `None` when more bytes are needed.
fn parse_tcp_response(data: &[u8]) -> Result<Option<usize>> {
    let Some(&status) = data.first() else {
        return Ok(None);
    };
    let Some((msg_len, mut off)) = quic::read_varint(&data[1..]) else {
        return Ok(None);
    };
    off += 1;
    if msg_len > MAX_MESSAGE_LENGTH as u64 {
        return Err(Error::protocol("tcp resp: invalid message length"));
    }
    let Some(msg) = data.get(off..off + msg_len as usize) else {
        return Ok(None);
    };
    off += msg_len as usize;
    let Some((pad_len, n)) = quic::read_varint(&data[off..]) else {
        return Ok(None);
    };
    if pad_len > MAX_PADDING_LENGTH as u64 {
        return Err(Error::protocol("tcp resp: invalid padding length"));
    }
    off += n + pad_len as usize;
    if off > data.len() {
        return Ok(None);
    }
    if status != 0 {
        let msg = String::from_utf8_lossy(msg).into_owned();
        return Err(Error::network(format!("hysteria2 tcp: remote error: {msg}")));
    }
    Ok(Some(off))
}

// ---------------------------------------------------------------------------
// UDP relay (QUIC datagrams, upstream UDPMessage)
// ---------------------------------------------------------------------------

/// The UDP session id used by [`udp_send`]. Upstream allocates one id
/// per UDP socket; this fire-and-forget helper pins session 0, which the
/// server treats as a single shared association.
const UDP_SESSION_ID: u32 = 0;
/// Upstream MaxUDPSize cap.
const MAX_UDP_SIZE: usize = 4096;

/// Send one UDP payload as a QUIC datagram: session/packet ids and
/// fragment counters (never fragmented here — datagrams above
/// [`MAX_UDP_SIZE`] are rejected), then a varint-prefixed `host:port`
/// string and the data.
pub async fn udp_send(conn: &quinn::Connection, target: &NetAddr, data: &[u8]) -> Result<()> {
    if data.len() > MAX_UDP_SIZE {
        return Err(Error::protocol("hysteria2 udp: packet exceeds MaxUDPSize"));
    }
    let packet_id: u16 = OsRng.gen();
    let mut datagram = udp_message_header(UDP_SESSION_ID, packet_id, 0, 1, &target.to_string());
    datagram.extend_from_slice(data);
    conn.send_datagram(Bytes::from(datagram))
        .map_err(|e| Error::network(format!("hysteria2 udp send: {e}")))
}

/// `session(u32be) || packet(u16be) || frag_id(u8) || frag_count(u8) ||
/// varint(len) || addr`.
fn udp_message_header(session_id: u32, packet_id: u16, frag_id: u8, frag_count: u8, addr: &str) -> Vec<u8> {
    let mut buf = Vec::with_capacity(addr.len() + 16);
    buf.extend_from_slice(&session_id.to_be_bytes());
    buf.extend_from_slice(&packet_id.to_be_bytes());
    buf.push(frag_id);
    buf.push(frag_count);
    quic::write_varint(&mut buf, addr.len() as u64);
    buf.extend_from_slice(addr.as_bytes());
    buf
}

/// A decoded hysteria2 UDP message header (upstream `UDPMessage`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UdpMessage<'a> {
    pub session_id: u32,
    pub packet_id: u16,
    pub frag_id: u8,
    pub frag_count: u8,
    /// `host:port` display form (IPv6 bracketed).
    pub addr: String,
    pub data: &'a [u8],
}

/// Parse a UDP message datagram (the form the server sends back for
/// UDP relays).
pub fn parse_udp_message(msg: &[u8]) -> Result<UdpMessage<'_>> {
    if msg.len() < 8 {
        return Err(Error::protocol("udp msg: short header"));
    }
    let session_id = u32::from_be_bytes([msg[0], msg[1], msg[2], msg[3]]);
    let packet_id = u16::from_be_bytes([msg[4], msg[5]]);
    let frag_id = msg[6];
    let frag_count = msg[7];
    let (addr_len, n) = quic::read_varint(&msg[8..])
        .ok_or_else(|| Error::protocol("udp msg: short addr len"))?;
    if addr_len == 0 || addr_len > MAX_ADDRESS_LENGTH as u64 {
        return Err(Error::protocol("udp msg: invalid address length"));
    }
    let addr_off = 8 + n;
    let addr = msg
        .get(addr_off..addr_off + addr_len as usize)
        .ok_or_else(|| Error::protocol("udp msg: short address"))?;
    let addr = std::str::from_utf8(addr).map_err(|_| Error::protocol("udp msg: bad utf-8"))?;
    let data = &msg[addr_off + addr_len as usize..];
    Ok(UdpMessage {
        session_id,
        packet_id,
        frag_id,
        frag_count,
        addr: addr.to_string(),
        data,
    })
}

// ---------------------------------------------------------------------------
// Salamander obfuscation (upstream hysteria2/salamander.go)
// ---------------------------------------------------------------------------

const SALAMANDER_SALT_LEN: usize = 8;

fn salamander_keystream(password: &[u8], salt: &[u8]) -> [u8; 32] {
    let mut key = Vec::with_capacity(password.len() + salt.len());
    key.extend_from_slice(password);
    key.extend_from_slice(salt);
    blake2b256(&key)
}

/// Obfuscate one packet: 8 random salt bytes, then the payload XORed
/// with the repeating blake2b-256(password || salt) keystream.
fn salamander_pad(password: &[u8], salt: &[u8; SALAMANDER_SALT_LEN], plaintext: &[u8]) -> Vec<u8> {
    let key = salamander_keystream(password, salt);
    let mut out = Vec::with_capacity(SALAMANDER_SALT_LEN + plaintext.len());
    out.extend_from_slice(salt);
    for (i, b) in plaintext.iter().enumerate() {
        out.push(b ^ key[i % 32]);
    }
    out
}

/// De-obfuscate one packet. Upstream silently drops packets no longer
/// than the salt; mirrored as `None`.
fn salamander_unpad(password: &[u8], packet: &[u8]) -> Option<Vec<u8>> {
    if packet.len() <= SALAMANDER_SALT_LEN {
        return None;
    }
    let key = salamander_keystream(password, &packet[..SALAMANDER_SALT_LEN]);
    Some(
        packet[SALAMANDER_SALT_LEN..]
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % 32])
            .collect(),
    )
}

/// A QUIC UDP socket wrapped in salamander obfuscation, adapting the
/// upstream `SalamanderConn` to quinn's abstract socket interface.
#[derive(Debug)]
struct SalamanderSocket {
    socket: Arc<tokio::net::UdpSocket>,
    password: Vec<u8>,
}

impl SalamanderSocket {
    fn new(socket: tokio::net::UdpSocket, password: Vec<u8>) -> Self {
        SalamanderSocket {
            socket: Arc::new(socket),
            password,
        }
    }
}

/// Write-readiness poller for [`SalamanderSocket`].
#[derive(Debug)]
struct SalamanderPoller {
    socket: Arc<tokio::net::UdpSocket>,
}

impl quinn::UdpPoller for SalamanderPoller {
    fn poll_writable(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.socket.poll_send_ready(cx)
    }
}

impl quinn::AsyncUdpSocket for SalamanderSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn quinn::UdpPoller>> {
        Box::pin(SalamanderPoller {
            socket: self.socket.clone(),
        })
    }

    fn try_send(&self, transmit: &quinn::udp::Transmit<'_>) -> io::Result<()> {
        let mut salt = [0u8; SALAMANDER_SALT_LEN];
        OsRng.fill_bytes(&mut salt);
        let packet = salamander_pad(&self.password, &salt, transmit.contents);
        self.socket
            .try_send_to(&packet, transmit.destination)
            .map(|_| ())
    }

    fn poll_recv(
        &self,
        cx: &mut Context<'_>,
        bufs: &mut [IoSliceMut<'_>],
        meta: &mut [quinn::udp::RecvMeta],
    ) -> Poll<io::Result<usize>> {
        let mut raw = [0u8; 65_536];
        loop {
            let mut rb = ReadBuf::new(&mut raw);
            match self.socket.poll_recv_from(cx, &mut rb) {
                Poll::Ready(Ok(addr)) => {
                    let Some(plain) = salamander_unpad(&self.password, rb.filled()) else {
                        continue; // short/garbage packet: dropped like upstream
                    };
                    if plain.len() > bufs[0].len() {
                        continue;
                    }
                    bufs[0][..plain.len()].copy_from_slice(&plain);
                    meta[0] = quinn::udp::RecvMeta {
                        addr,
                        len: plain.len(),
                        stride: plain.len(),
                        ecn: None,
                        dst_ip: None,
                    };
                    return Poll::Ready(Ok(1));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }
}

// ---------------------------------------------------------------------------
// blake2b-256 (RFC 7693), unkeyed — needed for salamander and not
// otherwise present in the dependency tree.
// ---------------------------------------------------------------------------

const BLAKE2B_IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 10] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
];

fn blake2b256(data: &[u8]) -> [u8; 32] {
    let mut h = BLAKE2B_IV;
    // Parameter block word 0: digest 32, key 0, fanout 1, depth 1.
    h[0] ^= 0x0101_0020;
    let mut t: u128 = 0;
    let mut i = 0usize;
    while data.len() - i > 128 {
        let mut block = [0u8; 128];
        block.copy_from_slice(&data[i..i + 128]);
        t += 128;
        blake2b_compress(&mut h, &block, t, false);
        i += 128;
    }
    let mut block = [0u8; 128];
    let rem = &data[i..];
    block[..rem.len()].copy_from_slice(rem);
    t += rem.len() as u128;
    blake2b_compress(&mut h, &block, t, true);
    let mut out = [0u8; 32];
    for (i, w) in h.iter().take(4).enumerate() {
        out[i * 8..(i + 1) * 8].copy_from_slice(&w.to_le_bytes());
    }
    out
}

fn blake2b_compress(h: &mut [u64; 8], block: &[u8; 128], t: u128, last: bool) {
    let mut m = [0u64; 16];
    for (i, w) in m.iter_mut().enumerate() {
        *w = u64::from_le_bytes(block[i * 8..i * 8 + 8].try_into().unwrap());
    }
    let mut v = [0u64; 16];
    v[..8].copy_from_slice(h);
    v[8..].copy_from_slice(&BLAKE2B_IV);
    v[12] ^= t as u64;
    v[13] ^= (t >> 64) as u64;
    if last {
        v[14] ^= u64::MAX;
    }
    for round in 0..12 {
        let s = &SIGMA[round % 10];
        g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
        g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
        g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
        g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
        g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
        g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
        g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
        g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
    }
    for i in 0..8 {
        h[i] ^= v[i] ^ v[i + 8];
    }
}

fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::Host;
    use std::net::IpAddr;

    // ---------------------------------------------------- ECH over QUIC

    /// The hysteria2 HTTP/3 auth answer shaped exactly like the real
    /// mihomo server (metacubex/quic-go `response_writer.go` auto-adds
    /// `Date`; metacubex/qpack emits literal-with-static-name-reference
    /// lines, Huffman values): `:status 233` (name ref 24, multi-byte
    /// index 0x5F 0x09) plus `date` (name ref 6 — the single 0x56 byte
    /// that used to die as "qpack: dynamic name reference").
    fn auth_ok_response() -> Vec<u8> {
        let mut block = vec![0x00, 0x00]; // prefix: ric 0, base 0
        // :status — literal with static name idx 24 (T bit 0x10 set).
        quic::put_prefixed_int(&mut block, 0x50, 4, 24);
        put_test_string(&mut block, b"233", true);
        // date — literal with static name idx 6 (first byte 0x56).
        quic::put_prefixed_int(&mut block, 0x50, 4, 6);
        put_test_string(&mut block, b"Wed, 24 Sep 2026 12:00:00 GMT", true);
        let mut out = Vec::new();
        quic::write_varint(&mut out, 1); // HEADERS
        quic::write_varint(&mut out, block.len() as u64);
        out.extend_from_slice(&block);
        out
    }

    /// HPACK/QPACK Huffman-encode (RFC 7541 appendix B) with EOS padding.
    fn huffman_encode_test(data: &[u8]) -> Vec<u8> {
        let mut bits: Vec<bool> = Vec::new();
        for &b in data {
            let (code, len) = HUFFMAN_CODES[b as usize];
            for i in (0..len).rev() {
                bits.push(((code >> i) & 1) == 1);
            }
        }
        while !bits.len().is_multiple_of(8) {
            bits.push(true); // EOS padding
        }
        bits.chunks(8)
            .map(|c| c.iter().fold(0u8, |acc, b| (acc << 1) | *b as u8))
            .collect()
    }

    /// One 7-bit-prefix string literal (the field-value form, §4.1.2).
    fn put_test_string(block: &mut Vec<u8>, data: &[u8], huffman: bool) {
        let payload = if huffman {
            huffman_encode_test(data)
        } else {
            data.to_vec()
        };
        put_prefixed_int(
            block,
            if huffman { 0x80 } else { 0x00 },
            7,
            payload.len() as u64,
        );
        block.extend_from_slice(&payload);
    }

    /// `connect_ech`: the dial rides the engine's own TLS 1.3 stack with
    /// the ECH cover (inner SNI/ALPN `h3`), an ECH-terminating quinn
    /// server accepts, and the HTTP/3 auth exchange answers 233.
    #[tokio::test]
    async fn ech_connect_authenticates_over_h3() {
        let (sk_r, list) = crate::quic::tls13::test_server::ech_server_key(
            &[13u8; 32],
            0x66,
            b"hy2-public.example",
        );
        let endpoint = crate::quic::tls13::test_server::start_quinn_server(
            crate::quic::tls13::ServerMode::EchAccept {
                sk_r,
                config_list: list.clone(),
            },
        )
        .await
        .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let response = auth_ok_response();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let Ok(conn) = incoming.await else { continue };
                let response = response.clone();
                tokio::spawn(async move {
                    // Drain the client's uni control/QPACK streams and
                    // answer the auth request on the first bi stream;
                    // keep serving streams so the connection (and its
                    // handle) stays alive for the client's reads.
                    let uni_conn = conn.clone();
                    tokio::spawn(async move {
                        while uni_conn.accept_uni().await.is_ok() {}
                    });
                    if let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        let mut buf = [0u8; 1024];
                        // Wait for the request HEADERS to arrive.
                        let _ = recv.read(&mut buf).await;
                        let _ = send.write_all(&response).await;
                        let _ = send.finish();
                    }
                    while conn.accept_bi().await.is_ok() {}
                });
            }
        });

        let cfg = Hysteria2Cfg {
            server: "127.0.0.1".to_string(),
            port: addr.port(),
            password: "ech-pass".to_string(),
            sni: "hy2-inner.example".to_string(),
            skip_verify: true,
            obfs: None,
        };
        use base64::Engine as _;
        let opts = crate::proto::ech::EchOptions {
            enable: true,
            config: base64::engine::general_purpose::STANDARD.encode(&list),
            query_server_name: String::new(),
        };

        let conn = crate::proto::hysteria2::connect_ech(&cfg, &opts)
            .await
            .expect("ech dial + h3 auth");
        // ALPN negotiated through the ECH inner hello.
        let data = conn
            .handshake_data()
            .unwrap()
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .unwrap();
        assert_eq!(data.protocol.as_deref(), Some(&b"h3"[..]));
    }

    /// The QPACK encoder-stream bytes and response HEADERS a hy2 server
    /// with a dynamic-table encoder produces: a Set Dynamic Table
    /// Capacity, insert-with-literal-name, insert-with-static-name-ref
    /// and duplicate instruction on uni stream 0x02, then a HEADERS
    /// frame mixing a dynamic index reference, the mihomo `date` static
    /// name reference (0x56), a post-base index reference, a post-base
    /// literal name reference and a literal name — the exact live-interop
    /// pattern class the static-only decoder died on. The client must
    /// authenticate (status 233, udp enabled).
    fn dynamic_qpack_exchange() -> (Vec<u8>, Vec<u8>) {
        let mut ins = Vec::new();
        put_prefixed_int(&mut ins, 0x20, 5, 512); // capacity 512
        // abs 0: (hysteria-udp, true) — insert with literal name.
        put_prefixed_int(&mut ins, 0x40, 5, 12);
        ins.extend_from_slice(b"hysteria-udp");
        put_prefixed_int(&mut ins, 0x00, 7, 4);
        ins.extend_from_slice(b"true");
        // abs 1: (:status, 233) — insert with static name ref 24.
        put_prefixed_int(&mut ins, 0xC0, 6, 24);
        put_prefixed_int(&mut ins, 0x00, 7, 3);
        ins.extend_from_slice(b"233");
        // abs 2: (hysteria-cc-rx, 0) — insert with literal name.
        put_prefixed_int(&mut ins, 0x40, 5, 14);
        ins.extend_from_slice(b"hysteria-cc-rx");
        put_prefixed_int(&mut ins, 0x00, 7, 1);
        ins.push(b'0');
        // abs 3: duplicate of abs 0 (relative index 2).
        put_prefixed_int(&mut ins, 0x00, 5, 2);

        let mut block = Vec::new();
        put_prefixed_int(&mut block, 0x00, 8, 4); // ric 4 (lenient)
        put_prefixed_int(&mut block, 0x80, 7, 1); // S=1 delta 1 -> base 2
        put_prefixed_int(&mut block, 0x80, 6, 0); // dyn indexed rel 0 -> abs 1 (:status 233)
        put_prefixed_int(&mut block, 0x50, 4, 6); // date static name ref (0x56)
        put_test_string(&mut block, b"Wed, 24 Sep 2026 00:00:00 GMT", true);
        put_prefixed_int(&mut block, 0x80, 6, 1); // dyn indexed rel 1 -> abs 0 (udp true)
        put_prefixed_int(&mut block, 0x10, 4, 0); // post-base idx 0 -> abs 2 (cc-rx 0)
        put_prefixed_int(&mut block, 0x00, 3, 1); // post-base name ref 1 -> abs 3 (dup)
        put_test_string(&mut block, b"true", false);
        put_qpack_literal(&mut block, b"hysteria-padding", b"pp");

        let mut out = Vec::new();
        quic::write_varint(&mut out, 1); // HEADERS
        quic::write_varint(&mut out, block.len() as u64);
        out.extend_from_slice(&block);
        (ins, out)
    }

    /// End-to-end against the in-test hy2 server mimic emitting the
    /// dynamic QPACK exchange above (encoder instructions on the uni
    /// QPACK encoder stream, response HEADERS referencing them).
    #[tokio::test]
    async fn hy2_server_mimic_dynamic_qpack_authenticates() {
        let (sk_r, list) = crate::quic::tls13::test_server::ech_server_key(
            &[21u8; 32],
            0x71,
            b"hy2-dyn.example",
        );
        let endpoint = crate::quic::tls13::test_server::start_quinn_server(
            crate::quic::tls13::ServerMode::EchAccept {
                sk_r,
                config_list: list.clone(),
            },
        )
        .await
        .unwrap();
        let addr = endpoint.local_addr().unwrap();
        let response = dynamic_qpack_exchange();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let Ok(conn) = incoming.await else { continue };
                let (instructions, response) = response.clone();
                tokio::spawn(async move {
                    // Drain the client's uni control/QPACK streams.
                    let uni_conn = conn.clone();
                    tokio::spawn(async move {
                        while uni_conn.accept_uni().await.is_ok() {}
                    });
                    // The server's own critical streams: control with an
                    // empty SETTINGS, QPACK encoder with the dynamic
                    // table instructions, and an (idle) QPACK decoder.
                    if let Ok(mut control) = conn.open_uni().await {
                        let _ = control
                            .write_all(&[H3_STREAM_CONTROL, H3_FRAME_SETTINGS as u8, 0])
                            .await;
                    }
                    if let Ok(mut enc) = conn.open_uni().await {
                        let mut buf = vec![H3_STREAM_QPACK_ENCODER];
                        buf.extend_from_slice(&instructions);
                        let _ = enc.write_all(&buf).await;
                    }
                    if let Ok(mut dec) = conn.open_uni().await {
                        let _ = dec.write_all(&[H3_STREAM_QPACK_DECODER]).await;
                    }
                    if let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        let mut buf = [0u8; 1024];
                        let _ = recv.read(&mut buf).await;
                        let _ = send.write_all(&response).await;
                        let _ = send.finish();
                    }
                    while conn.accept_bi().await.is_ok() {}
                });
            }
        });

        let cfg = Hysteria2Cfg {
            server: "127.0.0.1".to_string(),
            port: addr.port(),
            password: "dyn-pass".to_string(),
            sni: "hy2-inner.example".to_string(),
            skip_verify: true,
            obfs: None,
        };
        use base64::Engine as _;
        let opts = crate::proto::ech::EchOptions {
            enable: true,
            config: base64::engine::general_purpose::STANDARD.encode(&list),
            query_server_name: String::new(),
        };

        let conn = crate::proto::hysteria2::connect_ech(&cfg, &opts)
            .await
            .expect("hy2 auth over dynamic QPACK");
        let data = conn
            .handshake_data()
            .unwrap()
            .downcast::<quinn::crypto::rustls::HandshakeData>()
            .unwrap();
        assert_eq!(data.protocol.as_deref(), Some(&b"h3"[..]));
    }

    /// A server that rejects ECH surfaces the upstream sentinel through
    /// `connect_ech` (precise error, no silent fallback).
    #[tokio::test]
    async fn ech_rejection_is_the_precise_error() {
        let (_other_sk, other) = crate::quic::tls13::test_server::ech_server_key(
            &[14u8; 32],
            0x77,
            b"rejector.example",
        );
        let endpoint = crate::quic::tls13::test_server::start_quinn_server(
            crate::quic::tls13::ServerMode::EchReject {
                retry_configs: Some(other.clone()),
            },
        )
        .await
        .unwrap();
        let addr = endpoint.local_addr().unwrap();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let _ = incoming.await;
            }
        });

        let cfg = Hysteria2Cfg {
            server: "127.0.0.1".to_string(),
            port: addr.port(),
            password: "ech-pass".to_string(),
            sni: "hy2-inner.example".to_string(),
            skip_verify: true,
            obfs: None,
        };
        let (_sk, client_list) = crate::quic::tls13::test_server::ech_server_key(
            &[15u8; 32],
            0x12,
            b"unrelated.example",
        );
        use base64::Engine as _;
        let opts = crate::proto::ech::EchOptions {
            enable: true,
            config: base64::engine::general_purpose::STANDARD.encode(&client_list),
            query_server_name: String::new(),
        };

        let err = crate::proto::hysteria2::connect_ech(&cfg, &opts)
            .await
            .expect_err("rejection must fail");
        // dial_ech already consumed the one retry (with the rejector's
        // list, which names the rejector's own key — the second attempt
        // is rejected again and surfaces the sentinel).
        assert!(
            err.to_string().contains(crate::quic::tls13::ERR_ECH_REJECTED),
            "{err}"
        );
    }


    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    // --- blake2b -----------------------------------------------------

    #[test]
    fn blake2b256_known_vectors() {
        // Cross-checked against Python hashlib.blake2b(digest_size=32).
        assert_eq!(
            hex(&blake2b256(b"")),
            "0e5751c026e543b2e8ab2eb06099daa1d1e5df47778f7787faab45cdf12fe3a8"
        );
        assert_eq!(
            hex(&blake2b256(b"abc")),
            "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
        );
        // Salamander's exact derivation shape: password || salt.
        let mut v = Vec::new();
        v.extend_from_slice(b"test-password");
        v.extend_from_slice(&[0, 1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(
            hex(&blake2b256(&v)),
            "d9a10a59b56c49101e97fae27c7ebc0d45cd988b07524dfc0a5c896b41fc1fab"
        );
        // Multi-block (256 bytes > 128) exercises the counter path.
        assert_eq!(
            hex(&blake2b256(&(0..=255u8).collect::<Vec<u8>>())),
            "39a7eb9fedc19aabc83425c6755dd90e6f9d0c804964a1f4aaeea3b9fb599835"
        );
    }

    // --- salamander --------------------------------------------------

    #[test]
    fn salamander_roundtrip() {
        let pw = b"test-password";
        let salt = [7u8; 8];
        for payload in [&b"a"[..], b"hello salamander", &[0u8; 4096]] {
            let padded = salamander_pad(pw, &salt, payload);
            assert_eq!(&padded[..8], &salt);
            assert_eq!(salamander_unpad(pw, &padded).unwrap(), payload);
        }
        // A zero-length payload is pure salt; readers drop it (upstream
        // returns nothing usable for packets no longer than the salt).
        let empty = salamander_pad(pw, &salt, b"");
        assert_eq!(empty, salt.to_vec());
        assert!(salamander_unpad(pw, &empty).is_none());
    }

    #[test]
    fn salamander_xor_properties() {
        let pw = b"test-password";
        let salt = [9u8; 8];
        let a = salamander_pad(pw, &salt, b"AAAA");
        let b = salamander_pad(pw, &salt, b"AAAB");
        // XOR keystream: a plaintext byte flip changes exactly one byte.
        assert_eq!(a[..11], b[..11]);
        assert_ne!(a[11], b[11]);
        // Different salts hide equal payloads differently.
        let c = salamander_pad(pw, &[1, 2, 3, 4, 5, 6, 7, 8], b"AAAA");
        assert_ne!(a, c);
        // Packets no longer than the salt are dropped, like upstream.
        assert!(salamander_unpad(pw, &salt[..]).is_none());
        assert!(salamander_unpad(pw, &a[..7]).is_none());
    }

    // --- TCP framing -------------------------------------------------

    #[test]
    fn tcp_request_header_known_bytes_and_roundtrip() {
        let header = tcp_request_header("example.com:443", "");
        // varint(0x401) = 44 01, then varint addr len 15
        // ("example.com:443" is 15 bytes).
        assert_eq!(&header[..3], &[0x44, 0x01, 15]);
        // parse_tcp_request mirrors upstream ReadTCPRequest, which runs
        // after the frame-type varint has been consumed.
        let body = &header[2..];
        let (addr, pad_len, pad_at) = parse_tcp_request(body).unwrap();
        assert_eq!(addr, "example.com:443");
        assert_eq!(pad_len, 0);
        assert_eq!(pad_at, body.len());

        let with_pad = tcp_request_header("1.2.3.4:80", "padpad");
        let body = &with_pad[2..];
        let (addr, pad_len, pad_at) = parse_tcp_request(body).unwrap();
        assert_eq!(addr, "1.2.3.4:80");
        assert_eq!(pad_len, 6);
        assert_eq!(pad_at, body.len() - 6);

        // Truncation at every cut must fail.
        for cut in 0..body.len() {
            assert!(parse_tcp_request(&body[..cut]).is_err(), "cut {cut}");
        }
    }

    #[test]
    fn tcp_response_parse() {
        let mut resp = vec![0u8, 0]; // status ok, empty message
        quic::write_varint(&mut resp, 0); // no padding
        let used = parse_tcp_response(&resp).unwrap().unwrap();
        assert_eq!(used, resp.len());

        // Error status carries the message.
        let mut resp = vec![1u8];
        quic::write_varint(&mut resp, 3);
        resp.extend_from_slice(b"denied");
        quic::write_varint(&mut resp, 0);
        assert!(parse_tcp_response(&resp).is_err());

        // With padding: the consumed offset sits after the padding.
        let mut resp = vec![0u8, 0];
        quic::write_varint(&mut resp, 4);
        resp.extend_from_slice(b"pppp");
        let used = parse_tcp_response(&resp).unwrap().unwrap();
        assert_eq!(used, resp.len());
        // Payload bytes following the response are not consumed by it.
        resp.extend_from_slice(b"data");
        let used = parse_tcp_response(&resp).unwrap().unwrap();
        assert_eq!(used, resp.len() - 4);

        // Truncated forms report incomplete rather than error.
        for cut in 0..resp.len() - 4 {
            assert!(matches!(parse_tcp_response(&resp[..cut]), Ok(None)), "cut {cut}");
        }
    }

    // --- UDP framing -------------------------------------------------

    #[test]
    fn udp_message_roundtrip() {
        let header = udp_message_header(7, 513, 0, 1, "[2001:db8::1]:53");
        let mut msg = header.clone();
        msg.extend_from_slice(b"payload");
        let m = parse_udp_message(&msg).unwrap();
        assert_eq!(
            (m.session_id, m.packet_id, m.frag_id, m.frag_count),
            (7, 513, 0, 1)
        );
        assert_eq!(m.addr, "[2001:db8::1]:53");
        assert_eq!(m.data, b"payload");
        // Header layout: u32be || u16be || u8 || u8.
        assert_eq!(&header[..4], &[0, 0, 0, 7]);
        assert_eq!(&header[4..6], &[0x02, 0x01]);
        for cut in 0..header.len() {
            assert!(parse_udp_message(&msg[..cut]).is_err(), "cut {cut}");
        }
    }

    // --- H3 / QPACK --------------------------------------------------

    #[test]
    fn auth_request_layout() {
        let req = build_auth_request("test-password", 0, "pad");
        // One HEADERS frame: varint(1) type, varint length, then block.
        let (ftype, n) = quic::read_varint(&req).unwrap();
        assert_eq!(ftype, H3_FRAME_HEADERS);
        let (len, _) = quic::read_varint(&req[n..]).unwrap();
        assert_eq!(
            len as usize + quic::varint_len(1) + quic::varint_len(len),
            req.len()
        );
        // Block prefix: required-insert-count 0, base 0.
        let block = &req[quic::varint_len(1) + quic::varint_len(len)..];
        assert_eq!(&block[..2], &[0x00, 0x00]);

        let fields = QpackDecoder::default()
            .decode_field_section(block)
            .unwrap()
            .unwrap()
            .fields;
        let get = |k: &str| {
            fields
                .iter()
                .find(|(n, _)| n == k)
                .map(|(_, v)| v.as_str())
                .unwrap()
        };
        assert_eq!(get(":method"), "POST");
        assert_eq!(get(":scheme"), "https");
        assert_eq!(get(":authority"), URL_HOST);
        assert_eq!(get(":path"), URL_PATH);
        assert_eq!(get(HDR_AUTH), "test-password");
        assert_eq!(get(HDR_CCRX), "0");
        assert_eq!(get(HDR_PADDING), "pad");
        assert_eq!(fields.len(), 7);
    }

    #[test]
    fn qpack_decode_static_and_literals() {
        let mut dec = QpackDecoder::default();
        // Indexed static :status 200 (index 25 -> 0xc0|25).
        let mut block = vec![0x00, 0x00, 0xc0 | 25];
        let fields = dec.decode_field_section(&block).unwrap().unwrap().fields;
        assert_eq!(fields, vec![(":status".to_string(), "200".to_string())]);

        // Indexed static with a multi-byte 6-bit index (:status 500 = 71).
        block = vec![0x00, 0x00, 0xff, (71 - 63) as u8];
        let fields = dec.decode_field_section(&block).unwrap().unwrap().fields;
        assert_eq!(fields, vec![(":status".to_string(), "500".to_string())]);

        // Literal with static name reference (:status -> "233"), the
        // shape quic-go emits for the hysteria2 auth response (T is bit
        // 0x10; multi-byte 4-bit index: 0x5F, 24-15).
        let mut block = vec![0x00, 0x00];
        put_prefixed_int(&mut block, 0x50, 4, 24); // T=1 static, name idx 24
        put_prefixed_int(&mut block, 0x00, 7, 3);
        block.extend_from_slice(b"233");
        let fields = dec.decode_field_section(&block).unwrap().unwrap().fields;
        assert_eq!(fields, vec![(":status".to_string(), "233".to_string())]);

        // Literal with literal name (our own encoder's form).
        let mut block = vec![0x00, 0x00];
        put_qpack_literal(&mut block, b"hysteria-udp", b"true");
        let fields = dec.decode_field_section(&block).unwrap().unwrap().fields;
        assert_eq!(fields, vec![("hysteria-udp".to_string(), "true".to_string())]);

        // Dynamic references against an empty table are errors.
        assert!(dec.decode_field_section(&[0x00, 0x00, 0x80]).is_err()); // T=0
        assert!(dec.decode_field_section(&[0x00, 0x00, 0x1f]).is_err()); // post-base
        // A section requiring inserts the table has not seen is blocked
        // (RFC 9204 §2.1.2), not decoded.
        assert!(dec.decode_field_section(&[0x01]).unwrap().is_none());
    }

    #[test]
    fn huffman_decode_rfc7541_vector() {
        // RFC 7541 appendix C.4.1: "www.example.com" -> f1e3 c2e5 f23a
        // 6ba0 ab90 f4ff with the H bit set and a 7-bit length of 12.
        let mut lit = vec![0x80 | 12];
        lit.extend_from_slice(&[
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ]);
        let (decoded, used) = read_string_literal(&lit, 0, 7, 0x80).unwrap();
        assert_eq!(decoded, b"www.example.com");
        assert_eq!(used, lit.len());
        // Bad padding (not all ones) is rejected.
        assert!(huffman_decode(&[0xff, 0x00]).is_none());
        // Round-trip a full string through bit packing with the table.
        let mut bits = Vec::new();
        for &b in b"rustcrash" {
            let (code, len) = HUFFMAN_CODES[b as usize];
            for i in (0..len).rev() {
                bits.push(((code >> i) & 1) == 1);
            }
        }
        while !bits.len().is_multiple_of(8) {
            bits.push(true); // EOS padding
        }
        let packed: Vec<u8> = bits
            .chunks(8)
            .map(|c| c.iter().fold(0u8, |acc, b| (acc << 1) | *b as u8))
            .collect();
        assert_eq!(huffman_decode(&packed).unwrap(), b"rustcrash");
    }

    #[test]
    fn h3_headers_frame_parsing() {
        let mut stream = Vec::new();
        // DATA frame and an unknown frame type (both skipped), then
        // HEADERS.
        put_h3_frame(&mut stream, H3_FRAME_DATA_TEST, b"body");
        put_h3_frame(&mut stream, 0x21, b"future");
        let mut block = vec![0x00, 0x00, 0xc0 | 25];
        block.push(0x20 | 2); // literal name, len 2
        block.extend_from_slice(b"ok");
        put_h3_frame(&mut stream, H3_FRAME_HEADERS, &block);
        let got = parse_h3_headers_frame(&stream).unwrap().unwrap();
        assert_eq!(got, &block[..]);
        // Truncated HEADERS payload waits for more bytes.
        let cut = stream.len() - 1;
        assert!(parse_h3_headers_frame(&stream[..cut]).unwrap().is_none());
        // A DATA frame with a short payload also just waits.
        assert!(parse_h3_headers_frame(&[0x00, 0x04, 0x00]).unwrap().is_none());
    }

    const H3_FRAME_DATA_TEST: u64 = 0x0;

    // --- stream plumbing ----------------------------------------------

    #[tokio::test]
    async fn hysteria2_stream_replays_pending_then_delegates() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (client, mut server) = tokio::io::duplex(64);
        let mut stream = Hysteria2Stream {
            inner: Box::new(client),
            pending: b"replayed!".to_vec(),
            resp_pending: false,
            resp_buf: Vec::new(),
        };
        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"replayed!");
        server.write_all(b"fresh").await.unwrap();
        let mut buf = [0u8; 8];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"fresh");
        stream.write_all(b"x").await.unwrap();
        let mut echo = [0u8; 1];
        server.read_exact(&mut echo).await.unwrap();
        assert_eq!(&echo, b"x");
    }

    #[test]
    fn netaddr_display_matches_go() {
        // The address strings sent on the wire are Go Socksaddr.String()
        // forms: bare v4, bracketed v6.
        let a = NetAddr::new(Host::Domain("example.com".into()), 443);
        assert_eq!(a.to_string(), "example.com:443");
        let b = NetAddr::ip("2001:db8::1".parse::<IpAddr>().unwrap(), 53);
        assert_eq!(b.to_string(), "[2001:db8::1]:53");
    }

    // --- QPACK dynamic table (RFC 9204) -------------------------------

    /// The live-interop repro (fail-before pin): the real mihomo server's
    /// auth-ok HEADERS. quic-go's http3 responseWriter (metacubex/quic-go
    /// aa29579f, response_writer.go "Add Date header") auto-adds `Date`,
    /// and metacubex/qpack v0.6.0's static-only encoder writes it as a
    /// literal with STATIC name reference 6 — the single 0x56 byte
    /// (0101_0110: 01NT, T=1). The old decoder read the T bit at 0x08
    /// (part of the 4-bit index prefix) and rejected it with exactly
    /// "qpack: dynamic name reference".
    #[test]
    fn qpack_decodes_mihomo_date_static_name_ref() {
        let mut dec = QpackDecoder::default();
        let mut block = vec![0x00, 0x00];
        put_prefixed_int(&mut block, 0x50, 4, 24); // :status (static name)
        put_test_string(&mut block, b"233", false);
        put_prefixed_int(&mut block, 0x50, 4, 6); // date (static name) -> 0x56
        put_test_string(&mut block, b"Wed, 24 Sep 2026 00:00:00 GMT", true);
        let section = dec.decode_field_section(&block).unwrap().unwrap();
        assert_eq!(
            section.fields,
            vec![
                (":status".to_string(), "233".to_string()),
                (
                    "date".to_string(),
                    "Wed, 24 Sep 2026 00:00:00 GMT".to_string()
                ),
            ]
        );
        assert_eq!(section.required_insert_count, 0);
    }

    /// Encoder-stream instruction handling (§4.3): set-capacity,
    /// insert-with-literal-name, insert-with-name-ref (static and
    /// dynamic), duplicate, size accounting, eviction on capacity
    /// reduction, and partial-instruction buffering.
    #[test]
    fn qpack_encoder_instructions_build_dynamic_table() {
        let mut dec = QpackDecoder::default();
        let mut ins = Vec::new();
        put_prefixed_int(&mut ins, 0x20, 5, 512); // set capacity 512
        // insert with literal name (hysteria-udp, true) -> abs 0
        put_prefixed_int(&mut ins, 0x40, 5, 12);
        ins.extend_from_slice(b"hysteria-udp");
        put_prefixed_int(&mut ins, 0x00, 7, 4);
        ins.extend_from_slice(b"true");
        // insert with static name ref (:status idx 24), value 233 -> abs 1
        put_prefixed_int(&mut ins, 0xC0, 6, 24);
        put_prefixed_int(&mut ins, 0x00, 7, 3);
        ins.extend_from_slice(b"233");
        // duplicate relative 1 (abs 0) -> abs 2
        put_prefixed_int(&mut ins, 0x00, 5, 1);
        // insert with DYNAMIC name ref: relative 2 (abs 0), value -> abs 3
        put_prefixed_int(&mut ins, 0x80, 6, 2);
        put_prefixed_int(&mut ins, 0x00, 7, 5);
        ins.extend_from_slice(b"false");

        // A truncated final instruction stays unconsumed.
        let cut = ins.len() - 1;
        let consumed = dec.apply_encoder_instructions(&ins[..cut]).unwrap();
        assert!(consumed < cut, "partial instruction must not be applied");
        assert_eq!(dec.insert_count, 3);

        let tail = dec.apply_encoder_instructions(&ins[consumed..]).unwrap();
        assert_eq!(consumed + tail, ins.len());
        assert_eq!(dec.insert_count, 4);
        assert_eq!(dec.entries.len(), 4);
        // Size accounting (§3.2.1: name + value + 32): 48 + 42 + 48 + 49.
        assert_eq!(dec.size, 187);
        // Newest entry first.
        assert_eq!(
            dec.entries[0],
            ("hysteria-udp".to_string(), "false".to_string())
        );
        assert_eq!(
            dec.lookup_absolute(0).unwrap(),
            &("hysteria-udp".to_string(), "true".to_string())
        );
        assert_eq!(
            dec.lookup_absolute(1).unwrap(),
            &(":status".to_string(), "233".to_string())
        );

        // Capacity reduction evicts oldest-first (§3.2.2): 49 bytes keeps
        // only the newest entry (hysteria-udp/false, size 49).
        let mut shrink = Vec::new();
        put_prefixed_int(&mut shrink, 0x20, 5, 49);
        dec.apply_encoder_instructions(&shrink).unwrap();
        assert_eq!(dec.entries.len(), 1);
        assert!(dec.lookup_absolute(2).is_err()); // evicted
        assert!(dec.lookup_absolute(3).is_ok());
        // insert_count survives eviction (absolute indices never reuse).
        assert_eq!(dec.insert_count, 4);

        // An insert larger than the capacity is a protocol error.
        let mut too_big = Vec::new();
        put_prefixed_int(&mut too_big, 0x40, 5, 30);
        too_big.extend_from_slice(&[b'x'; 30]);
        put_prefixed_int(&mut too_big, 0x00, 7, 1);
        too_big.push(b'y');
        assert!(dec.apply_encoder_instructions(&too_big).is_err());
    }

    /// Field sections referencing the dynamic table: relative (pre-base)
    /// indexed, post-base indexed, literal with dynamic name reference
    /// and post-base literal name reference, with a negative base
    /// (S=1) offsetting the Required Insert Count.
    #[test]
    fn qpack_decode_dynamic_references() {
        let mut dec = QpackDecoder::default();
        let mut ins = Vec::new();
        // abs 0: (hysteria-udp, true)
        put_prefixed_int(&mut ins, 0x40, 5, 12);
        ins.extend_from_slice(b"hysteria-udp");
        put_prefixed_int(&mut ins, 0x00, 7, 4);
        ins.extend_from_slice(b"true");
        // abs 1: (:status, 233) via static name ref
        put_prefixed_int(&mut ins, 0xC0, 6, 24);
        put_prefixed_int(&mut ins, 0x00, 7, 3);
        ins.extend_from_slice(b"233");
        // abs 2: duplicate of abs 0
        put_prefixed_int(&mut ins, 0x00, 5, 1);
        dec.apply_encoder_instructions(&ins).unwrap();

        // ric 3 (lenient absolute), S=1 delta 0 -> base = 3-0-1 = 2.
        let mut block = Vec::new();
        put_prefixed_int(&mut block, 0x00, 8, 3);
        put_prefixed_int(&mut block, 0x80, 7, 0);
        put_prefixed_int(&mut block, 0x80, 6, 1); // rel 1 -> abs 0
        put_prefixed_int(&mut block, 0x10, 4, 0); // post-base 0 -> abs 2
        put_prefixed_int(&mut block, 0x40, 4, 0); // dynamic name ref rel 0 -> abs 1
        put_test_string(&mut block, b"233", false);
        put_prefixed_int(&mut block, 0x00, 3, 0); // post-base name ref 0 -> abs 2
        put_test_string(&mut block, b"false", false);
        let section = dec.decode_field_section(&block).unwrap().unwrap();
        assert_eq!(
            section.fields,
            vec![
                ("hysteria-udp".to_string(), "true".to_string()),
                ("hysteria-udp".to_string(), "true".to_string()),
                (":status".to_string(), "233".to_string()),
                ("hysteria-udp".to_string(), "false".to_string()),
            ]
        );
        assert_eq!(section.required_insert_count, 3);

        // A relative reference past the table start is an error.
        let mut bad = Vec::new();
        put_prefixed_int(&mut bad, 0x00, 8, 3);
        put_prefixed_int(&mut bad, 0x80, 7, 0);
        put_prefixed_int(&mut bad, 0x80, 6, 3); // abs 2-1-3 = before start
        assert!(dec.decode_field_section(&bad).is_err());
    }

    /// The requested mixed response: static indexed + dynamic indexed +
    /// static-name literal + dynamic-name literal in one section (base
    /// S=0, base = Required Insert Count).
    #[test]
    fn qpack_decode_mixed_static_and_dynamic() {
        let mut dec = QpackDecoder::default();
        let mut ins = Vec::new();
        // abs 0: (hysteria-udp, true); abs 1: (:status, 233)
        put_prefixed_int(&mut ins, 0x40, 5, 12);
        ins.extend_from_slice(b"hysteria-udp");
        put_prefixed_int(&mut ins, 0x00, 7, 4);
        ins.extend_from_slice(b"true");
        put_prefixed_int(&mut ins, 0xC0, 6, 24);
        put_prefixed_int(&mut ins, 0x00, 7, 3);
        ins.extend_from_slice(b"233");
        dec.apply_encoder_instructions(&ins).unwrap();

        // ric 2, S=0 delta 0 -> base 2.
        let mut block = Vec::new();
        put_prefixed_int(&mut block, 0x00, 8, 2);
        put_prefixed_int(&mut block, 0x00, 7, 0);
        block.push(0xc0 | 25); // static indexed :status 200
        put_prefixed_int(&mut block, 0x80, 6, 1); // dynamic rel 1 -> abs 0
        put_prefixed_int(&mut block, 0x50, 4, 6); // static name ref `date`
        put_test_string(&mut block, b"Mon, 02 Jan 2006 15:04:05 GMT", false);
        put_prefixed_int(&mut block, 0x40, 4, 0); // dynamic name ref rel 0 -> abs 1
        put_test_string(&mut block, b"233", true);
        let section = dec.decode_field_section(&block).unwrap().unwrap();
        assert_eq!(
            section.fields,
            vec![
                (":status".to_string(), "200".to_string()),
                ("hysteria-udp".to_string(), "true".to_string()),
                (
                    "date".to_string(),
                    "Mon, 02 Jan 2006 15:04:05 GMT".to_string()
                ),
                (":status".to_string(), "233".to_string()),
            ]
        );
    }

    /// Blocked decoding (§2.1.2): a section whose Required Insert Count
    /// runs ahead of the applied inserts yields `None` until the
    /// encoder-stream instructions arrive.
    #[test]
    fn qpack_blocked_until_encoder_instructions() {
        let mut dec = QpackDecoder::default();
        // ric 2 (lenient), base = 2: rel 0 -> abs 1.
        let mut block = Vec::new();
        put_prefixed_int(&mut block, 0x00, 8, 2);
        put_prefixed_int(&mut block, 0x00, 7, 0);
        put_prefixed_int(&mut block, 0x80, 6, 0);
        assert!(dec.decode_field_section(&block).unwrap().is_none());

        let mut ins = Vec::new();
        put_prefixed_int(&mut ins, 0x40, 5, 12);
        ins.extend_from_slice(b"hysteria-udp");
        put_prefixed_int(&mut ins, 0x00, 7, 4);
        ins.extend_from_slice(b"true");
        dec.apply_encoder_instructions(&ins).unwrap();
        assert!(dec.decode_field_section(&block).unwrap().is_none());

        ins.clear();
        put_prefixed_int(&mut ins, 0x40, 5, 14);
        ins.extend_from_slice(b"hysteria-cc-rx");
        put_prefixed_int(&mut ins, 0x00, 7, 1);
        ins.extend_from_slice(b"0");
        dec.apply_encoder_instructions(&ins).unwrap();
        let section = dec.decode_field_section(&block).unwrap().unwrap();
        assert_eq!(
            section.fields,
            vec![("hysteria-cc-rx".to_string(), "0".to_string())]
        );
        assert_eq!(section.required_insert_count, 2);
    }

    /// Required Insert Count winding (§4.5.1.1), including the RFC's own
    /// example (100-byte table, 10 inserts, encoded 4 -> 9), plus this
    /// client's lenient zero-capacity mode.
    #[test]
    fn qpack_required_insert_count_winding() {
        let ric = QpackDecoder::decode_required_insert_count;
        assert_eq!(ric(0, 10, 100).unwrap(), 0);
        assert_eq!(ric(4, 10, 100).unwrap(), 9); // RFC 9204 §4.5.1.1 example
        assert!(ric(7, 10, 100).is_err()); // > FullRange (6)
        assert!(ric(1, 0, 100).is_err()); // would decode to 0
        assert_eq!(ric(2, 0, 100).unwrap(), 1);
        // Lenient: no capacity advertised, encoded value taken literally.
        assert_eq!(ric(3, 0, 0).unwrap(), 3);
        assert_eq!(ric(0, 0, 0).unwrap(), 0);

        // End-to-end through a decoder that advertised a 100-byte table:
        // 10 small inserts (only the last two survive the 96-byte
        // capacity the encoder sets), then a section whose encoded count
        // 4 winds to a Required Insert Count of 9.
        let mut dec = QpackDecoder::with_max_capacity(100);
        let mut ins = Vec::new();
        put_prefixed_int(&mut ins, 0x20, 5, 96);
        for i in 0..10u8 {
            ins.push(0x40 | 2); // insert with literal name, len 2, H=0
            ins.extend_from_slice(&[b'n', b'a' + i]);
            ins.push(1); // value len 1
            ins.push(b'v');
        }
        dec.apply_encoder_instructions(&ins).unwrap();
        assert_eq!(dec.insert_count, 10);
        let mut block = Vec::new();
        put_prefixed_int(&mut block, 0x00, 8, 4); // winds to 9
        put_prefixed_int(&mut block, 0x00, 7, 0); // base 9
        put_prefixed_int(&mut block, 0x80, 6, 0); // rel 0 -> abs 8 = ("ni","v")
        let section = dec.decode_field_section(&block).unwrap().unwrap();
        assert_eq!(
            section.fields,
            vec![("ni".to_string(), "v".to_string())] // 9th insert, i=8
        );
        assert_eq!(section.required_insert_count, 9);
    }
}
