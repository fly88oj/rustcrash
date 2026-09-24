//! Hysteria2 SERVER listener: a quinn endpoint (ALPN `h3`) inverting the
//! engine's own outbound client, [`crate::proto::hysteria2`].
//!
//! Wire facts mirrored from the client (and the apernet/hysteria
//! protocol it ports):
//!
//! * Auth (client `connect`/`authenticate`): one HTTP/3-ish exchange on
//!   a bidirectional stream — a HEADERS frame whose QPACK field section
//!   carries `POST https://hysteria/auth` with the password in
//!   `hysteria-auth`. The server answers with a HEADERS frame carrying
//!   `:status 233` (ok) plus `hysteria-udp: true`, or `:status 401`.
//!   The request's `hysteria-cc-rx` (bandwidth) and `hysteria-padding`
//!   headers are accepted but not negotiated: the reply carries
//!   neither, no Brutal rate is enforced and quinn keeps its default
//!   congestion controller — matching the client, which records but
//!   never acts on bandwidth frames.
//! * The client also opens the HTTP/3 control and QPACK uni streams and
//!   never closes them; the server reads their stream type and holds
//!   them open for the connection lifetime.
//! * TCP (client `tcp_stream`): each bidirectional stream begins with
//!   the `0x401` request — varint address length, `host:port` display
//!   string (IPv6 bracketed), varint padding length, padding — and the
//!   server must answer `status(u8) || varint msg len || msg || varint
//!   padding len || padding` (client `parse_tcp_response`) before the
//!   stream turns into a raw relay.
//! * UDP (client `udp_send`/`parse_udp_message`): QUIC datagrams of the
//!   form `session(u32be) || packet(u16be) || frag_id(u8) ||
//!   frag_count(u8) || varint addr len || addr || data`, every fragment
//!   repeating the address. Replies use the same form with the client's
//!   session id. Datagrams are bridged to
//!   [`crate::inbound::RelayHandler::handle_udp`], one relay session
//!   per client session id, reaped after [`UDP_SESSION_TTL`] idle —
//!   the Shadowsocks UDP server's pattern.
//!
//! Traffic is authenticated before it relays: streams and datagrams
//! wait (bounded) for the auth exchange, and a failed auth closes the
//! connection. Salamander obfuscation stays a client-side feature
//! here — a configured `obfs` key is rejected at [`serve`] time with a
//! clear config error (server-side salamander is not implemented).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::addr::{Host, NetAddr};
use crate::error::{Error, Result};
use crate::inbound::proxy_server::{
    ct_eq, hand_off, quic_bind_addr, quic_server_config, ServerConfig, ServerProtocol,
};
use crate::inbound::SharedRelay;
use crate::proto::hysteria2::parse_udp_message;
use crate::quic::{self, QuicStream};

/// The auth password header (client `HDR_AUTH`).
const HDR_AUTH: &str = "hysteria-auth";
/// Successful auth status (client `STATUS_AUTH_OK`).
const STATUS_AUTH_OK: &str = "233";
/// Failed auth status.
const STATUS_AUTH_DENIED: &str = "401";
/// TCP request frame type (client `FRAME_TYPE_TCP_REQUEST`).
const FRAME_TYPE_TCP_REQUEST: u64 = 0x401;
/// The auth stream's first varint: an HTTP/3 HEADERS frame (client
/// `build_auth_request` emits exactly one).
const H3_FRAME_HEADERS: u64 = 0x1;
/// The `status(0) || varint msg len(0) || varint padding len(0)`
/// response that turns a TCP stream into a relay (client
/// `parse_tcp_response` consumes exactly these three bytes).
const TCP_OK_RESPONSE: &[u8; 3] = &[0, 0, 0];
/// Mirrors of the client's framing limits (`MAX_ADDRESS_LENGTH`,
/// `MAX_PADDING_LENGTH`, and the 16 KiB auth-response cap).
const MAX_ADDRESS_LENGTH: usize = 2048;
const MAX_PADDING_LENGTH: usize = 4096;
const MAX_H3_EXCHANGE: usize = 16 * 1024;
/// How long a client's UDP relay session survives without traffic (the
/// ss UDP server's TTL).
const UDP_SESSION_TTL: Duration = Duration::from_secs(60);
/// In-flight fragmented UDP message sets kept per connection.
const MAX_FRAG_SETS: usize = 64;
/// Grace window for the auth exchange to arrive before a relay attempt
/// is dropped.
const AUTH_WINDOW: Duration = Duration::from_secs(5);

/// Session generations, so an idle-reaped session's reply pump only
/// removes the entry it still owns.
static GENERATION: AtomicU64 = AtomicU64::new(1);

/// Serve a Hysteria2 listener; returns the bound address.
///
/// TLS is mandatory (hysteria2 is QUIC-only); the certificate/key PEM
/// files are loaded and validated before the endpoint binds.
pub async fn serve(cfg: &ServerConfig, relay: SharedRelay) -> Result<SocketAddr> {
    let ServerProtocol::Hysteria2 {
        password,
        obfs,
        tls,
    } = &cfg.protocol
    else {
        return Err(Error::config(
            "hysteria2::serve called with a non-hysteria2 protocol",
        ));
    };
    if obfs.as_deref().is_some_and(|k| !k.is_empty()) {
        return Err(Error::config(
            "hysteria2 server: salamander obfs is not implemented server-side; leave `obfs` unset",
        ));
    }
    let Some(tls) = tls else {
        return Err(Error::config(
            "hysteria2 server: TLS is required (set the listener certificate/key PEM paths)",
        ));
    };
    let quinn_config = quic_server_config(tls, b"h3")?;
    let bind = quic_bind_addr(&cfg.bind, cfg.port).await?;
    let endpoint = quinn::Endpoint::server(quinn_config, bind)
        .map_err(|e| Error::network(format!("hysteria2 server bind {bind}: {e}")))?;
    let local = endpoint
        .local_addr()
        .map_err(|e| Error::network(format!("hysteria2 server local addr: {e}")))?;
    let password = password.clone();
    let tag = cfg.tag.clone();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let password = password.clone();
            let tag = tag.clone();
            let relay = relay.clone();
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        let state = Hy2Connection::new(conn, password, tag, local.port(), relay);
                        state.drive().await;
                    }
                    Err(e) => {
                        tracing::debug!(target: "engine", "hysteria2 server handshake: {e}")
                    }
                }
            });
        }
    });
    Ok(local)
}

/// Per-connection state shared with the spawned per-stream tasks (the
/// driver loop itself never awaits a stream handler, so one slow or
/// hostile stream cannot stall authentication or the other relays).
#[derive(Clone)]
struct Hy2Shared {
    conn: quinn::Connection,
    peer: SocketAddr,
    port: u16,
    password: String,
    tag: String,
    relay: SharedRelay,
    auth_rx: tokio::sync::watch::Receiver<bool>,
    sessions: Arc<Mutex<HashMap<u32, UdpSession>>>,
}

/// One client connection: the shared state plus the auth flag the
/// driver owns and the fragment reassembly map only the driver touches.
struct Hy2Connection {
    shared: Hy2Shared,
    auth_tx: tokio::sync::watch::Sender<bool>,
    frags: HashMap<(u32, u16), Fragments>,
}

impl Hy2Connection {
    fn new(
        conn: quinn::Connection,
        password: String,
        tag: String,
        port: u16,
        relay: SharedRelay,
    ) -> Self {
        let peer = conn.remote_address();
        let (auth_tx, auth_rx) = tokio::sync::watch::channel(false);
        Hy2Connection {
            shared: Hy2Shared {
                conn,
                peer,
                port,
                password,
                tag,
                relay,
                auth_rx,
                sessions: Arc::new(Mutex::new(HashMap::new())),
            },
            auth_tx,
            frags: HashMap::new(),
        }
    }

    /// Run the connection until it ends: bidirectional streams are auth
    /// or TCP relays (first varint), uni streams are the client's H3
    /// control/QPACK streams, datagrams are UDP relays. Stream handlers
    /// run as their own tasks; only datagram parsing is inline.
    async fn drive(mut self) {
        loop {
            tokio::select! {
                biased;
                bi = self.shared.conn.accept_bi() => {
                    let (mut send, mut recv) = match bi {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::debug!(target: "engine", "hysteria2 server {}: {e}", self.shared.peer);
                            return;
                        }
                    };
                    let frame_type = match read_varint_stream(&mut recv).await {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::debug!(target: "engine", "hysteria2 stream {}: {e}", self.shared.peer);
                            continue;
                        }
                    };
                    let shared = self.shared.clone();
                    let auth_tx = self.auth_tx.clone();
                    tokio::spawn(async move {
                        let handled = match frame_type {
                            H3_FRAME_HEADERS => handle_auth(&shared, auth_tx, send, recv).await,
                            FRAME_TYPE_TCP_REQUEST => handle_tcp(&shared, send, recv).await,
                            other => {
                                let _ = send.reset(quinn::VarInt::from_u32(0));
                                let _ = recv.stop(quinn::VarInt::from_u32(0));
                                Err(Error::protocol(format!(
                                    "hysteria2 stream: bad frame type {other:#x}"
                                )))
                            }
                        };
                        if let Err(e) = handled {
                            tracing::debug!(target: "engine", "hysteria2 server {}: {e}", shared.peer);
                        }
                    });
                }
                uni = self.shared.conn.accept_uni() => {
                    match uni {
                        Ok(recv) => {
                            // The client pins its H3 control/QPACK
                            // streams open for the connection lifetime;
                            // hold what it sends the same way.
                            let conn = self.shared.conn.clone();
                            tokio::spawn(async move {
                                let mut recv = recv;
                                if read_varint_stream(&mut recv).await.is_ok() {
                                    let _ = conn.closed().await;
                                }
                                // Dropping the stream afterwards is fine:
                                // the connection is over.
                            });
                        }
                        Err(e) => {
                            tracing::debug!(target: "engine", "hysteria2 server {}: {e}", self.shared.peer);
                            return;
                        }
                    }
                }
                dg = self.shared.conn.read_datagram() => {
                    match dg {
                        Ok(msg) => self.handle_datagram(msg).await,
                        Err(e) => {
                            tracing::debug!(target: "engine", "hysteria2 server {}: {e}", self.shared.peer);
                            return;
                        }
                    }
                }
            }
        }
    }

    /// One QUIC datagram: a UDPMessage for a relay session (fragments
    /// reassembled first; the engine client never fragments, upstream
    /// clients do).
    async fn handle_datagram(&mut self, msg: Bytes) {
        if !*self.shared.auth_rx.borrow() {
            tracing::debug!(target: "engine", "hysteria2 udp: datagram before authentication");
            return;
        }
        let m = match parse_udp_message(&msg) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!(target: "engine", "hysteria2 udp {}: {e}", self.shared.peer);
                return;
            }
        };
        if m.frag_count == 0 {
            return;
        }
        let target = match parse_host_port(&m.addr) {
            Ok(t) => t,
            Err(e) => {
                tracing::debug!(target: "engine", "hysteria2 udp {}: {e}", self.shared.peer);
                return;
            }
        };
        let data = if m.frag_count == 1 {
            m.data.to_vec()
        } else {
            let assembled = {
                if self.frags.len() >= MAX_FRAG_SETS {
                    self.frags.clear();
                }
                let entry = self
                    .frags
                    .entry((m.session_id, m.packet_id))
                    .or_insert_with(|| Fragments::new(m.frag_count));
                if entry.total != m.frag_count {
                    *entry = Fragments::new(m.frag_count);
                }
                entry.add(m.frag_id, m.data)
            };
            match assembled {
                Some(data) => data,
                None => return, // waiting for the remaining fragments
            }
        };
        let up = udp_session(&self.shared, m.session_id);
        let _ = up.send((target, data)).await;
    }
}

/// The client's auth POST: decode the HEADERS frame's QPACK field
/// section, compare `hysteria-auth` with the configured password and
/// answer 233/401 (client `read_auth_response`).
async fn handle_auth(
    shared: &Hy2Shared,
    auth_tx: tokio::sync::watch::Sender<bool>,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<()> {
    let payload = read_h3_request_headers(&mut recv).await?;
    let fields = decode_field_section(&payload)?;
    let ok = fields
        .iter()
        .find(|(name, _)| name == HDR_AUTH)
        .map(|(_, value)| ct_eq(value.as_bytes(), shared.password.as_bytes()))
        .unwrap_or(false);

    let mut block = Vec::with_capacity(64);
    // QPACK field section prefix: required insert count 0, base 0.
    block.extend_from_slice(&[0x00, 0x00]);
    let status = if ok { STATUS_AUTH_OK } else { STATUS_AUTH_DENIED };
    quic::put_qpack_literal(&mut block, b":status", status.as_bytes());
    if ok {
        quic::put_qpack_literal(&mut block, b"hysteria-udp", b"true");
    }
    let mut resp = Vec::with_capacity(block.len() + 8);
    quic::put_h3_frame(&mut resp, H3_FRAME_HEADERS, &block);
    send.write_all(&resp)
        .await
        .map_err(|e| Error::network(format!("hysteria2 auth response: {e}")))?;
    let _ = send.finish();

    if !ok {
        // The 401 IS the rejection (the client errors on any status
        // other than 233); the connection itself is left to the
        // client to drop — closing it here would race the response
        // and surface as a transport error instead.
        return Err(Error::protocol("hysteria2: wrong password"));
    }
    let _ = auth_tx.send(true);
    Ok(())
}

/// A TCP relay stream: consume the `0x401` request (address + padding),
/// answer with the status response, then hand the raw stream to the
/// relay.
async fn handle_tcp(
    shared: &Hy2Shared,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<()> {
    wait_auth(&shared.auth_rx).await?;

    let addr_len = read_varint_stream(&mut recv).await?;
    if addr_len == 0 || addr_len > MAX_ADDRESS_LENGTH as u64 {
        return Err(Error::protocol("hysteria2 tcp: invalid address length"));
    }
    let mut addr_bytes = vec![0u8; addr_len as usize];
    recv.read_exact(&mut addr_bytes)
        .await
        .map_err(|e| Error::network(format!("hysteria2 tcp request: {e}")))?;
    let pad_len = read_varint_stream(&mut recv).await?;
    if pad_len > MAX_PADDING_LENGTH as u64 {
        return Err(Error::protocol("hysteria2 tcp: invalid padding length"));
    }
    let mut padding = vec![0u8; pad_len as usize];
    recv.read_exact(&mut padding)
        .await
        .map_err(|e| Error::network(format!("hysteria2 tcp request: {e}")))?;
    let addr = std::str::from_utf8(&addr_bytes)
        .map_err(|_| Error::protocol("hysteria2 tcp: address not utf-8"))?;
    let target = match parse_host_port(addr) {
        Ok(t) => t,
        Err(e) => {
            // Tell the client why (non-zero status + message), like
            // the upstream server, then give up on the stream.
            let _ = send.write_all(&tcp_error_response(&e.to_string())).await;
            let _ = send.finish();
            return Err(Error::protocol(format!("hysteria2 tcp request: {e}")));
        }
    };

    send.write_all(TCP_OK_RESPONSE)
        .await
        .map_err(|e| Error::network(format!("hysteria2 tcp response: {e}")))?;
    hand_off(
        &shared.tag,
        "hysteria2",
        shared.port,
        shared.peer,
        target,
        Box::new(QuicStream::new(send, recv)),
        shared.relay.clone(),
    );
    Ok(())
}

/// The relay session for `session_id`, opening one on first use
/// (mirroring the ss UDP server's per-client-source sessions).
fn udp_session(shared: &Hy2Shared, session_id: u32) -> mpsc::Sender<(NetAddr, Vec<u8>)> {
    let mut sessions = shared.sessions.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(session) = sessions.get(&session_id) {
        return session.up.clone();
    }
    let (up, up_rx) = mpsc::channel(64);
    let (down, down_rx) = mpsc::channel(64);
    shared
        .relay
        .clone()
        .handle_udp(shared.peer, shared.tag.clone(), up_rx, down);
    let generation = GENERATION.fetch_add(1, Ordering::Relaxed);
    sessions.insert(session_id, UdpSession { up: up.clone(), generation });
    drop(sessions);
    tokio::spawn(downlink(
        shared.conn.clone(),
        shared.sessions.clone(),
        session_id,
        generation,
        down_rx,
    ));
    up
}

/// One client UDP relay session (pinned to the QUIC connection and the
/// client's session id).
struct UdpSession {
    up: mpsc::Sender<(NetAddr, Vec<u8>)>,
    generation: u64,
}

/// Reply pump for one session: datagrams from the relay back onto the
/// connection until it closes or the session idles out.
async fn downlink(
    conn: quinn::Connection,
    sessions: Arc<Mutex<HashMap<u32, UdpSession>>>,
    session_id: u32,
    generation: u64,
    mut down_rx: mpsc::Receiver<(NetAddr, Vec<u8>)>,
) {
    let mut packet_id: u16 = rand::random();
    loop {
        let Ok(Some((target, data))) =
            tokio::time::timeout(UDP_SESSION_TTL, down_rx.recv()).await
        else {
            break;
        };
        packet_id = packet_id.wrapping_add(1);
        if let Err(e) = send_udp_reply(&conn, session_id, packet_id, &target, &data) {
            tracing::debug!(target: "engine", "hysteria2 udp reply: {e}");
            break;
        }
    }
    // Retire the session so a later datagram for the same id opens a
    // fresh relay association (only if this pump still owns it).
    let mut sessions = sessions.lock().unwrap_or_else(|e| e.into_inner());
    if sessions
        .get(&session_id)
        .is_some_and(|s| s.generation == generation)
    {
        sessions.remove(&session_id);
    }
}

/// Send one UDP relay reply as (possibly fragmented) QUIC datagrams in
/// the client's UDPMessage form — the address repeats on every fragment
/// because [`parse_udp_message`] requires one. Fragments are sized to
/// quinn's current datagram budget so each actually fits on the wire.
fn send_udp_reply(
    conn: &quinn::Connection,
    session_id: u32,
    packet_id: u16,
    target: &NetAddr,
    data: &[u8],
) -> Result<()> {
    let addr = target.to_string();
    let overhead = 8 + quic::varint_len(addr.len() as u64) + addr.len();
    let budget = conn
        .max_datagram_size()
        .unwrap_or(1200)
        .saturating_sub(overhead);
    let chunks: Vec<&[u8]> = if data.len() <= budget || budget == 0 {
        vec![data]
    } else {
        data.chunks(budget).collect()
    };
    let total = u8::try_from(chunks.len()).unwrap_or(u8::MAX);
    for (i, chunk) in chunks.iter().enumerate() {
        let mut datagram = udp_message_header(session_id, packet_id, i as u8, total, &addr);
        datagram.extend_from_slice(chunk);
        conn.send_datagram(Bytes::from(datagram))
            .map_err(|e| Error::network(format!("hysteria2 udp datagram: {e}")))?;
    }
    Ok(())
}

/// `session(u32be) || packet(u16be) || frag_id(u8) || frag_count(u8) ||
/// varint(len) || addr` — the client's `udp_message_header`, which is
/// private to the proto module, mirrored byte for byte here.
fn udp_message_header(
    session_id: u32,
    packet_id: u16,
    frag_id: u8,
    frag_count: u8,
    addr: &str,
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(addr.len() + 16);
    buf.extend_from_slice(&session_id.to_be_bytes());
    buf.extend_from_slice(&packet_id.to_be_bytes());
    buf.push(frag_id);
    buf.push(frag_count);
    quic::write_varint(&mut buf, addr.len() as u64);
    buf.extend_from_slice(addr.as_bytes());
    buf
}

/// One in-flight fragmented UDP message (upstream clients fragment;
/// the engine's own client always sends `frag_count 1`).
struct Fragments {
    total: u8,
    parts: Vec<Option<Vec<u8>>>,
}

impl Fragments {
    fn new(total: u8) -> Self {
        Fragments {
            total,
            parts: vec![None; total as usize],
        }
    }

    /// Add one fragment; `Some(assembled)` once every slot is filled.
    fn add(&mut self, frag_id: u8, data: &[u8]) -> Option<Vec<u8>> {
        if frag_id >= self.total {
            return None;
        }
        self.parts[frag_id as usize] = Some(data.to_vec());
        if self.parts.iter().all(|p| p.is_some()) {
            return Some(self.parts.drain(..).flat_map(|p| p.unwrap_or_default()).collect());
        }
        None
    }
}

/// Wait (bounded) for the connection's auth exchange to succeed; relay
/// traffic before it is not served.
async fn wait_auth(auth_rx: &tokio::sync::watch::Receiver<bool>) -> Result<()> {
    let mut rx = auth_rx.clone();
    let ok = tokio::time::timeout(AUTH_WINDOW, async {
        loop {
            if *rx.borrow_and_update() {
                return true;
            }
            if rx.changed().await.is_err() {
                return false;
            }
        }
    })
    .await
    .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(Error::protocol(
            "hysteria2: no successful authentication before the stream",
        ))
    }
}

/// Read one QUIC varint (RFC 9000 section 16) from a stream.
async fn read_varint_stream(recv: &mut quinn::RecvStream) -> Result<u64> {
    let mut first = [0u8; 1];
    recv.read_exact(&mut first)
        .await
        .map_err(|e| Error::network(format!("hysteria2 stream read: {e}")))?;
    let len = 1usize << (first[0] >> 6);
    let mut rest = vec![0u8; len - 1];
    if len > 1 {
        recv.read_exact(&mut rest)
            .await
            .map_err(|e| Error::network(format!("hysteria2 stream read: {e}")))?;
    }
    let mut v = (first[0] & 0x3f) as u64;
    for b in rest {
        v = (v << 8) | b as u64;
    }
    Ok(v)
}

/// Read the auth HEADERS frame's field section: the frame-type varint
/// was consumed by the stream dispatcher, so this reads the length
/// varint and the payload (the client's `build_auth_request` emits
/// exactly one HEADERS frame per exchange).
async fn read_h3_request_headers(recv: &mut quinn::RecvStream) -> Result<Vec<u8>> {
    let len = read_varint_stream(recv).await?;
    let len = usize::try_from(len)
        .map_err(|_| Error::protocol("hysteria2 auth: frame too large"))?;
    if len > MAX_H3_EXCHANGE {
        return Err(Error::protocol("hysteria2 auth: frame too large"));
    }
    let mut payload = vec![0u8; len];
    recv.read_exact(&mut payload)
        .await
        .map_err(|e| Error::network(format!("hysteria2 auth request: {e}")))?;
    Ok(payload)
}

/// Parse the `host:port` display string the client puts on the wire
/// (Go `Socksaddr.String()`: bare IPv4/domain, bracketed IPv6 — the
/// exact output of [`NetAddr`]'s `Display`).
fn parse_host_port(s: &str) -> Result<NetAddr> {
    if let Ok(sa) = s.parse::<SocketAddr>() {
        return Ok(NetAddr::ip(sa.ip(), sa.port()));
    }
    let (host, port) = s
        .rsplit_once(':')
        .ok_or_else(|| Error::protocol(format!("missing port in {s:?}")))?;
    if host.starts_with('[') || host.contains(':') {
        return Err(Error::protocol(format!("invalid address {s:?}")));
    }
    let port: u16 = port
        .parse()
        .map_err(|_| Error::protocol(format!("bad port in {s:?}")))?;
    Ok(NetAddr::new(Host::parse(host)?, port))
}

/// A failed TCP request response: `status 1 || varint msg len || msg ||
/// varint 0` — the client's `parse_tcp_response` reports the message.
fn tcp_error_response(msg: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(msg.len() + 8);
    out.push(1u8);
    quic::write_varint(&mut out, msg.len() as u64);
    out.extend_from_slice(msg.as_bytes());
    quic::write_varint(&mut out, 0);
    out
}

// ---------------------------------------------------------------------------
// QPACK (RFC 9204) field-section decoding for the auth request. The
// tables and helpers mirror the engine's own client decoder in
// `proto/hysteria2.rs` (which is private there): literals in every
// representation, static-table references, Huffman-coded strings — so
// the engine client's literal-only encoder and standard HTTP/3 stacks
// (quic-go, hence the official hysteria2 server's clients) both decode.
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
    ("purpose", "preflight"),
    ("server", ""),
    ("timing-allow-origin", "*"),
    ("upgrade-insecure-requests", "1"),
    ("user-agent", ""),
    ("x-forwarded-for", ""),
    ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

/// Read an integer with a `prefix_bits`-wide prefix starting at `off`;
/// returns the value and the new offset.
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
/// `huff_mask` selects the Huffman bit for this representation.
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

/// Decode a QPACK field section: required insert count, base, then
/// indexed-static and literal entries (dynamic references are rejected
/// — a conforming peer never emits them against this server).
fn decode_field_section(buf: &[u8]) -> Result<Vec<(String, String)>> {
    let (required_inserts, off) = read_prefixed_int(buf, 0, 8)
        .ok_or_else(|| Error::protocol("qpack: truncated prefix"))?;
    if required_inserts != 0 {
        return Err(Error::protocol("qpack: dynamic table required"));
    }
    let mut off = read_prefixed_int(buf, off, 7)
        .map(|(_, n)| n)
        .ok_or_else(|| Error::protocol("qpack: truncated base"))?;
    let mut fields = Vec::new();
    while off < buf.len() {
        let b = buf[off];
        if b & 0x80 != 0 {
            // 1T: indexed field line.
            let is_static = b & 0x40 != 0;
            let (idx, n) = read_prefixed_int(buf, off, 6)
                .ok_or_else(|| Error::protocol("qpack: truncated index"))?;
            off = n;
            if !is_static {
                return Err(Error::protocol("qpack: dynamic reference"));
            }
            let (name, value) = QPACK_STATIC_TABLE
                .get(idx as usize)
                .ok_or_else(|| Error::protocol(format!("qpack: bad static index {idx}")))?;
            fields.push((name.to_string(), value.to_string()));
        } else if b & 0xc0 == 0x40 {
            // 01NT: literal with name reference.
            let is_static = b & 0x08 != 0;
            let (idx, n) = read_prefixed_int(buf, off, 4)
                .ok_or_else(|| Error::protocol("qpack: truncated name index"))?;
            off = n;
            if !is_static {
                return Err(Error::protocol("qpack: dynamic name reference"));
            }
            let (name, _) = QPACK_STATIC_TABLE
                .get(idx as usize)
                .ok_or_else(|| Error::protocol(format!("qpack: bad static name index {idx}")))?;
            let (value, n) = read_string_literal(buf, off, 7, 0x80)
                .ok_or_else(|| Error::protocol("qpack: truncated value"))?;
            off = n;
            fields.push((
                name.to_ascii_lowercase(),
                String::from_utf8_lossy(&value).into_owned(),
            ));
        } else if b & 0xe0 == 0x20 {
            // 001NH: literal with literal name.
            let (name, n) = read_string_literal(buf, off, 3, 0x08)
                .ok_or_else(|| Error::protocol("qpack: truncated name"))?;
            off = n;
            let (value, n) = read_string_literal(buf, off, 7, 0x80)
                .ok_or_else(|| Error::protocol("qpack: truncated value"))?;
            off = n;
            fields.push((
                String::from_utf8_lossy(&name).to_ascii_lowercase(),
                String::from_utf8_lossy(&value).into_owned(),
            ));
        } else {
            // 0001 (post-base indexed) / 0000N (post-base name ref).
            return Err(Error::protocol("qpack: dynamic table reference"));
        }
    }
    Ok(fields)
}

/// (code, bit-length) for HPACK/QPACK Huffman symbols 0..=256 (RFC 7541
/// appendix B); entry 256 is EOS.
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

fn huffman_map() -> &'static std::collections::HashMap<(u64, u8), u8> {
    static MAP: OnceLock<std::collections::HashMap<(u64, u8), u8>> = OnceLock::new();
    MAP.get_or_init(|| {
        // EOS (symbol 256) is excluded: decoding it is an error.
        HUFFMAN_CODES[..256]
            .iter()
            .enumerate()
            .map(|(sym, &(code, len))| ((code, len), sym as u8))
            .collect()
    })
}

/// Decode an HPACK/QPACK Huffman string; trailing padding shorter than
/// 8 bits must be all ones (a prefix of the EOS symbol).
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbound::proxy_server::test_support::{self_signed_tls, Capture};
    use crate::proto::hysteria2 as client;
    use crate::proto::hysteria2::Hysteria2Cfg;
    use rand::RngCore;
    use std::net::{IpAddr, Ipv4Addr};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Fresh per-run credential: nothing usable is ever committed.
    fn fresh_password() -> String {
        let mut b = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut b);
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    async fn spawn_server(password: &str) -> (Arc<Capture>, SocketAddr) {
        let (tls, _dir) = self_signed_tls();
        let cfg = ServerConfig {
            tag: "hysteria2-test".into(),
            bind: "127.0.0.1".into(),
            port: 0,
            protocol: ServerProtocol::Hysteria2 {
                password: password.into(),
                obfs: None,
                tls: Some(tls),
            },
        };
        let capture = Capture::new();
        let addr = serve(&cfg, capture.clone()).await.unwrap();
        (capture, addr)
    }

    fn client_cfg(password: &str, port: u16) -> Hysteria2Cfg {
        Hysteria2Cfg {
            server: "127.0.0.1".into(),
            port,
            password: password.into(),
            sni: "localhost".into(),
            skip_verify: true,
            obfs: None,
        }
    }

    /// Handshake + echo one payload through the engine's own client.
    async fn echo(mut stream: crate::stream::BoxProxyStream, payload: &[u8]) {
        stream.write_all(payload).await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = vec![0u8; payload.len()];
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("timeout")
            .unwrap();
        assert_eq!(&buf[..n], payload);
    }

    #[tokio::test]
    async fn tcp_roundtrip_domain_ipv4_and_ipv6_targets() {
        let password = fresh_password();
        let (capture, addr) = spawn_server(&password).await;
        let conn = client::connect(&client_cfg(&password, addr.port()))
            .await
            .unwrap();
        let targets = [
            NetAddr::domain("echo.test", 443).unwrap(),
            NetAddr::ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 80),
            NetAddr::ip(IpAddr::V6("2001:db8::1".parse().unwrap()), 53),
        ];
        for target in &targets {
            let stream = client::tcp_stream(&conn, target).await.unwrap();
            echo(stream, b"ping").await;
        }
        assert_eq!(capture.targets(), targets.to_vec());
        assert_eq!(capture.relayed(), 3);
    }

    #[tokio::test]
    async fn wrong_password_is_rejected_at_auth() {
        let (capture, addr) = spawn_server(&fresh_password()).await;
        // The engine client authenticates before anything else, so a
        // wrong password surfaces at connect with the server's status.
        let err = client::connect(&client_cfg(&fresh_password(), addr.port()))
            .await
            .unwrap_err();
        assert!(err.to_string().contains("401"), "{err}");
        assert_eq!(capture.relayed(), 0);
        assert!(capture.udp_sessions().is_empty());
    }

    #[tokio::test]
    async fn udp_roundtrip() {
        let password = fresh_password();
        let (capture, addr) = spawn_server(&password).await;
        let conn = client::connect(&client_cfg(&password, addr.port()))
            .await
            .unwrap();
        let target = NetAddr::domain("echo.test", 443).unwrap();
        client::udp_send(&conn, &target, b"ping").await.unwrap();

        let datagram = tokio::time::timeout(Duration::from_secs(5), conn.read_datagram())
            .await
            .expect("reply timeout")
            .unwrap();
        let m = client::parse_udp_message(&datagram).unwrap();
        assert_eq!(m.session_id, 0, "the reply echoes the client's session id");
        assert_eq!(m.addr, target.to_string());
        assert_eq!(m.data, b"ping");
        assert_eq!(capture.udp_targets(), vec![target]);
        assert_eq!(capture.udp_sessions().len(), 1);
        assert_eq!(capture.udp_sessions()[0].1, "hysteria2-test");
    }

    /// The engine client never fragments; upstream clients do. Hand-send
    /// two UDPMessage fragments (the client's own wire form, built with
    /// the server-side header encoder) and expect one reassembled relay.
    #[tokio::test]
    async fn udp_fragments_are_reassembled() {
        let password = fresh_password();
        let (capture, addr) = spawn_server(&password).await;
        let conn = client::connect(&client_cfg(&password, addr.port()))
            .await
            .unwrap();
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let addr_str = target.to_string();
        let mut first = udp_message_header(5, 9, 0, 2, &addr_str);
        first.extend_from_slice(b"frag");
        let mut second = udp_message_header(5, 9, 1, 2, &addr_str);
        second.extend_from_slice(b"mented");
        conn.send_datagram(Bytes::from(first)).unwrap();
        conn.send_datagram(Bytes::from(second)).unwrap();

        let datagram = tokio::time::timeout(Duration::from_secs(5), conn.read_datagram())
            .await
            .expect("reply timeout")
            .unwrap();
        let m = client::parse_udp_message(&datagram).unwrap();
        assert_eq!(m.session_id, 5);
        assert_eq!(m.addr, addr_str);
        assert_eq!(m.data, b"fragmented");
        assert_eq!(capture.udp_targets(), vec![target]);
    }

    #[tokio::test]
    async fn missing_tls_and_obfs_are_config_errors() {
        let cfg = ServerConfig {
            tag: "t".into(),
            bind: "127.0.0.1".into(),
            port: 0,
            protocol: ServerProtocol::Hysteria2 {
                password: "x".into(),
                obfs: None,
                tls: None,
            },
        };
        let err = serve(&cfg, Capture::new()).await.unwrap_err().to_string();
        assert!(err.contains("TLS is required"), "{err}");

        let (tls, _dir) = self_signed_tls();
        let cfg = ServerConfig {
            tag: "t".into(),
            bind: "127.0.0.1".into(),
            port: 0,
            protocol: ServerProtocol::Hysteria2 {
                password: "x".into(),
                obfs: Some("key".into()),
                tls: Some(tls),
            },
        };
        let err = serve(&cfg, Capture::new()).await.unwrap_err().to_string();
        assert!(err.contains("salamander"), "{err}");
    }

    #[test]
    fn host_port_display_forms_parse() {
        assert_eq!(
            parse_host_port("example.com:443").unwrap(),
            NetAddr::domain("example.com", 443).unwrap()
        );
        assert_eq!(
            parse_host_port("1.2.3.4:80").unwrap(),
            NetAddr::ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)), 80)
        );
        assert_eq!(
            parse_host_port("[2001:db8::1]:53").unwrap(),
            NetAddr::ip(IpAddr::V6("2001:db8::1".parse().unwrap()), 53)
        );
        // Junk is rejected, not guessed.
        assert!(parse_host_port("no-port").is_err());
        assert!(parse_host_port("host:notaport").is_err());
        assert!(parse_host_port("2001:db8::1").is_err());
        assert!(parse_host_port("").is_err());
    }

    #[test]
    fn tcp_error_response_layout_matches_client_parser() {
        // status 1 || varint msg len || msg || varint 0: three leading
        // bytes and a trailing 0 for a short message.
        let resp = tcp_error_response("denied");
        assert_eq!(&resp[..3], &[0x01, 0x06, b'd']);
        assert_eq!(*resp.last().unwrap(), 0x00);
    }

    #[test]
    fn udp_message_header_layout_matches_client_parser() {
        // u32be || u16be || u8 || u8 || varint len || addr — exactly the
        // bytes `proto::hysteria2::parse_udp_message` consumes.
        let mut msg = udp_message_header(7, 513, 0, 1, "[2001:db8::1]:53");
        msg.extend_from_slice(b"payload");
        let m = parse_udp_message(&msg).unwrap();
        assert_eq!(
            (m.session_id, m.packet_id, m.frag_id, m.frag_count),
            (7, 513, 0, 1)
        );
        assert_eq!(m.addr, "[2001:db8::1]:53");
        assert_eq!(m.data, b"payload");
    }

    #[test]
    fn qpack_decoder_accepts_the_client_and_static_forms() {
        // The engine client's own encoder form: literal field lines with
        // literal names (never indexed).
        let mut block = vec![0x00, 0x00];
        quic::put_qpack_literal(&mut block, b":method", b"POST");
        quic::put_qpack_literal(&mut block, b"hysteria-auth", b"pw");
        let fields = decode_field_section(&block).unwrap();
        assert_eq!(
            fields,
            vec![
                (":method".to_string(), "POST".to_string()),
                ("hysteria-auth".to_string(), "pw".to_string()),
            ]
        );

        // Indexed static :status 200 (index 25 -> 0xc0|25).
        let block = vec![0x00, 0x00, 0xc0 | 25];
        assert_eq!(
            decode_field_section(&block).unwrap(),
            vec![(":status".to_string(), "200".to_string())]
        );

        // Literal with static name reference (:status -> "233"), the
        // shape quic-go emits for the hysteria2 auth response.
        let mut block = vec![0x00, 0x00];
        quic::put_prefixed_int(&mut block, 0x40, 4, 24); // T=1 static, name idx 24
        quic::put_prefixed_int(&mut block, 0x00, 7, 3);
        block.extend_from_slice(b"233");
        assert_eq!(
            decode_field_section(&block).unwrap(),
            vec![(":status".to_string(), "233".to_string())]
        );

        // Dynamic references are rejected.
        assert!(decode_field_section(&[0x00, 0x00, 0x80]).is_err()); // T=0
        assert!(decode_field_section(&[0x00, 0x00, 0x1f]).is_err()); // post-base
        assert!(decode_field_section(&[0x01]).is_err()); // required inserts
    }

    #[test]
    fn huffman_decode_rfc7541_vector() {
        // RFC 7541 appendix C.4.1: "www.example.com" -> f1e3 c2e5 f23a
        // 6ba0 ab90 f4ff, H bit set, 7-bit length 12.
        let mut lit = vec![0x80 | 12];
        lit.extend_from_slice(&[
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ]);
        let (decoded, used) = read_string_literal(&lit, 0, 7, 0x80).unwrap();
        assert_eq!(decoded, b"www.example.com");
        assert_eq!(used, lit.len());
        // Bad padding (not all ones) is rejected.
        assert!(huffman_decode(&[0xff, 0x00]).is_none());
    }
}
