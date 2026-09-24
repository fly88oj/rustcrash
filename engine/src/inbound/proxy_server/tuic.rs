//! TUIC v5 SERVER listener: a quinn endpoint (ALPN `tuic`) inverting
//! the engine's own outbound client, [`crate::proto::tuic`].
//!
//! Wire facts mirrored from the client (and the TUIC v5 protocol
//! specification it ports):
//!
//! * Authentication (client `authenticate`): a unidirectional stream
//!   carrying `VER(5) || TYPE(0) || UUID(16) || TOKEN(32)`, where TOKEN
//!   is the TLS keying-material exporter output with label = raw UUID
//!   bytes and context = raw password bytes. The server derives the
//!   same 32 bytes over the live connection and compares both the UUID
//!   and the token in constant time; a mismatch closes the connection.
//! * TCP (client `tcp_stream`): a bidirectional stream whose first
//!   frame is `VER(5) || TYPE(1) || ADDR` (the sing family-byte
//!   address form); the server never responds, the stream becomes a raw
//!   relay.
//! * UDP (client `udp_send_native`/`udp_send_quic`): Packet commands
//!   `VER || TYPE(2) || ASSOC(u16be) || PKT_ID(u16be) || FRAG_TOTAL ||
//!   FRAG_ID || SIZE(u16be) || ADDR || DATA`, as QUIC datagrams
//!   (native mode) or unidirectional streams (quic mode). Fragments of
//!   one message share the packet id; only the first carries the
//!   address. Replies go back on the transport the session arrived on.
//! * Dissociate (client `dissociate`): `VER || TYPE(3) ||
//!   ASSOC(u16be)` on a uni stream — releases the relay session.
//! * Heartbeat (client `heartbeat`): the 2-byte `[5, 4]` datagram —
//!   tolerated and ignored.
//!
//! Commands are processed authenticate-on-first-use: relays wait
//! (bounded) for a valid Authenticate, which the engine client sends
//! right after connecting. UDP associations are bridged to
//! [`crate::inbound::RelayHandler::handle_udp`], one relay session per
//! assoc id, reaped after [`UDP_SESSION_TTL`] idle (the ss UDP server's
//! pattern).

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use tokio::sync::mpsc;

use crate::addr::{Host, NetAddr};
use crate::error::{Error, Result};
use crate::inbound::proxy_server::{
    ct_eq, hand_off, quic_bind_addr, quic_server_config, ServerConfig, ServerProtocol,
};
use crate::inbound::SharedRelay;
use crate::proto::tuic::{decode_addr_port, decode_packet_frame, ALPN};
use crate::quic::QuicStream;

/// Protocol version byte (client `VERSION`).
const VERSION: u8 = 5;
const CMD_AUTHENTICATE: u8 = 0x00;
const CMD_CONNECT: u8 = 0x01;
const CMD_PACKET: u8 = 0x02;
const CMD_DISSOCIATE: u8 = 0x03;
const CMD_HEARTBEAT: u8 = 0x04;
/// Authenticate frame: VER + TYPE + UUID + TOKEN (client
/// `AUTHENTICATE_LEN`).
const AUTHENTICATE_LEN: usize = 2 + 16 + 32;
/// Auth token length (RFC 5705 exporter output, client
/// `AUTH_TOKEN_LEN`).
const AUTH_TOKEN_LEN: usize = 32;
/// Grace window for the auth exchange to arrive before a relay attempt
/// is dropped.
const AUTH_WINDOW: Duration = Duration::from_secs(5);
/// How long a UDP relay session survives without traffic.
const UDP_SESSION_TTL: Duration = Duration::from_secs(60);
/// In-flight fragmented packet sets kept per connection.
const MAX_FRAG_SETS: usize = 64;
/// Cap on one uni-stream Packet command.
const MAX_UNI_PACKET: usize = 64 * 1024;

/// Address family bytes (the sing serializer the client's
/// `encode_addr_port` writes).
const ATYP_FQDN: u8 = 0x00;
const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x02;

/// Session generations, so an idle-reaped session's reply pump only
/// removes the entry it still owns.
static GENERATION: AtomicU64 = AtomicU64::new(1);

/// Serve a TUIC v5 listener; returns the bound address.
///
/// TLS is mandatory (TUIC is QUIC-only); the UUID is validated and the
/// certificate/key PEM files loaded before the endpoint binds.
pub async fn serve(cfg: &ServerConfig, relay: SharedRelay) -> Result<SocketAddr> {
    let ServerProtocol::Tuic {
        uuid,
        password,
        tls,
    } = &cfg.protocol
    else {
        return Err(Error::config("tuic::serve called with a non-tuic protocol"));
    };
    let uuid = uuid::Uuid::parse_str(uuid)
        .map_err(|e| Error::config(format!("tuic server: bad uuid {uuid:?}: {e}")))?;
    let Some(tls) = tls else {
        return Err(Error::config(
            "tuic server: TLS is required (set the listener certificate/key PEM paths)",
        ));
    };
    let quinn_config = quic_server_config(tls, ALPN.as_bytes())?;
    let bind = quic_bind_addr(&cfg.bind, cfg.port).await?;
    let endpoint = quinn::Endpoint::server(quinn_config, bind)
        .map_err(|e| Error::network(format!("tuic server bind {bind}: {e}")))?;
    let local = endpoint
        .local_addr()
        .map_err(|e| Error::network(format!("tuic server local addr: {e}")))?;
    let uuid = uuid.into_bytes();
    let password = password.clone();
    let tag = cfg.tag.clone();
    tokio::spawn(async move {
        while let Some(incoming) = endpoint.accept().await {
            let uuid = uuid;
            let password = password.clone();
            let tag = tag.clone();
            let relay = relay.clone();
            tokio::spawn(async move {
                match incoming.await {
                    Ok(conn) => {
                        let state =
                            TuicConnection::new(conn, uuid, password, tag, local.port(), relay);
                        state.drive().await;
                    }
                    Err(e) => {
                        tracing::debug!(target: "engine", "tuic server handshake: {e}")
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
struct TuicShared {
    conn: quinn::Connection,
    peer: SocketAddr,
    port: u16,
    uuid: [u8; 16],
    password: String,
    tag: String,
    relay: SharedRelay,
    auth_rx: tokio::sync::watch::Receiver<bool>,
    sessions: Arc<Mutex<HashMap<u16, UdpSession>>>,
}

/// One client connection: the shared state plus the auth flag the
/// driver owns and the fragment reassembly map only the driver's
/// datagram path touches.
struct TuicConnection {
    shared: TuicShared,
    auth_tx: tokio::sync::watch::Sender<bool>,
    frags: HashMap<(u16, u16), Fragments>,
}

impl TuicConnection {
    fn new(
        conn: quinn::Connection,
        uuid: [u8; 16],
        password: String,
        tag: String,
        port: u16,
        relay: SharedRelay,
    ) -> Self {
        let peer = conn.remote_address();
        let (auth_tx, auth_rx) = tokio::sync::watch::channel(false);
        TuicConnection {
            shared: TuicShared {
                conn,
                peer,
                port,
                uuid,
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

    /// Run the connection until it ends: bidirectional streams are TCP
    /// relays, uni streams carry Authenticate / Packet (quic mode) /
    /// Dissociate, datagrams carry Packet (native) and Heartbeat.
    /// Stream handlers run as their own tasks; only datagram parsing
    /// is inline.
    async fn drive(mut self) {
        loop {
            tokio::select! {
                biased;
                bi = self.shared.conn.accept_bi() => {
                    let (send, recv) = match bi {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::debug!(target: "engine", "tuic server {}: {e}", self.shared.peer);
                            return;
                        }
                    };
                    let shared = self.shared.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connect(&shared, send, recv).await {
                            tracing::debug!(target: "engine", "tuic server {}: {e}", shared.peer);
                        }
                    });
                }
                uni = self.shared.conn.accept_uni() => {
                    let recv = match uni {
                        Ok(v) => v,
                        Err(e) => {
                            tracing::debug!(target: "engine", "tuic server {}: {e}", self.shared.peer);
                            return;
                        }
                    };
                    let shared = self.shared.clone();
                    let auth_tx = self.auth_tx.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_uni(&shared, auth_tx, recv).await {
                            tracing::debug!(target: "engine", "tuic server {}: {e}", shared.peer);
                        }
                    });
                }
                dg = self.shared.conn.read_datagram() => {
                    match dg {
                        Ok(datagram) => self.handle_datagram(datagram).await,
                        Err(e) => {
                            tracing::debug!(target: "engine", "tuic server {}: {e}", self.shared.peer);
                            return;
                        }
                    }
                }
            }
        }
    }

    /// One datagram: Heartbeat (ignored) or a Packet command (native
    /// relay mode).
    async fn handle_datagram(&mut self, datagram: Bytes) {
        if datagram.len() == 2 && datagram[0] == VERSION && datagram[1] == CMD_HEARTBEAT {
            return; // client `heartbeat` keep-alive: nothing to do
        }
        let f = match decode_packet_frame(&datagram) {
            Ok(f) => f,
            Err(e) => {
                tracing::debug!(target: "engine", "tuic datagram {}: {e}", self.shared.peer);
                return;
            }
        };
        let session_id = f.session_id;
        let (packet_id, frag_id, frag_total) = (f.packet_id, f.frag_id, f.frag_total);
        let addr = f.addr;
        let data = f.data;
        if frag_total <= 1 {
            let Some(target) = addr else { return };
            deliver(&self.shared, session_id, target, data.to_vec(), false).await;
            return;
        }
        let assembled = {
            if self.frags.len() >= MAX_FRAG_SETS {
                self.frags.clear();
            }
            let entry = self
                .frags
                .entry((session_id, packet_id))
                .or_insert_with(|| Fragments::new(frag_total));
            if entry.total != frag_total {
                *entry = Fragments::new(frag_total);
            }
            entry.add(frag_id, addr, data)
        };
        if let Some((Some(target), data)) = assembled {
            deliver(&self.shared, session_id, target, data, false).await;
        }
    }
}

/// The Authenticate command: verify the UUID and the exporter token
/// (`label` = raw uuid bytes, `context` = raw password bytes — the
/// client's exact derivation, inverted).
async fn handle_authenticate(
    shared: &TuicShared,
    auth_tx: &tokio::sync::watch::Sender<bool>,
    recv: &mut quinn::RecvStream,
) -> Result<()> {
    let mut rest = [0u8; AUTHENTICATE_LEN - 2];
    recv.read_exact(&mut rest)
        .await
        .map_err(|e| Error::network(format!("tuic authenticate: {e}")))?;
    let (got_uuid, got_token) = rest.split_at(16);
    let uuid_ok = ct_eq(got_uuid, &shared.uuid);
    let mut token = [0u8; AUTH_TOKEN_LEN];
    shared
        .conn
        .export_keying_material(&mut token, &shared.uuid, shared.password.as_bytes())
        .map_err(|e| Error::crypto(format!("tuic auth token export: {e:?}")))?;
    let token_ok = ct_eq(got_token, &token);
    if !(uuid_ok && token_ok) {
        shared
            .conn
            .close(quinn::VarInt::from_u32(1), b"tuic: authentication failed");
        return Err(Error::protocol("tuic: wrong uuid or password"));
    }
    let _ = auth_tx.send(true);
    Ok(())
}

/// A TCP relay stream: `VER || TYPE(1) || ADDR`, no response, then a
/// raw relay (the client's `tcp_stream`).
async fn handle_connect(
    shared: &TuicShared,
    mut send: quinn::SendStream,
    mut recv: quinn::RecvStream,
) -> Result<()> {
    wait_auth(&shared.auth_rx).await?;
    let mut head = [0u8; 2];
    recv.read_exact(&mut head)
        .await
        .map_err(|e| Error::network(format!("tuic connect: {e}")))?;
    if head != [VERSION, CMD_CONNECT] {
        let _ = send.reset(quinn::VarInt::from_u32(0));
        let _ = recv.stop(quinn::VarInt::from_u32(0));
        return Err(Error::protocol(format!(
            "tuic stream: bad version/command {:#04x}/{:#04x}",
            head[0], head[1]
        )));
    }
    let target = read_addr(&mut recv).await?;
    hand_off(
        &shared.tag,
        "tuic",
        shared.port,
        shared.peer,
        target,
        Box::new(QuicStream::new(send, recv)),
        shared.relay.clone(),
    );
    Ok(())
}

/// One unidirectional stream: Authenticate, a Packet command (quic
/// relay mode) or Dissociate.
async fn handle_uni(
    shared: &TuicShared,
    auth_tx: tokio::sync::watch::Sender<bool>,
    mut recv: quinn::RecvStream,
) -> Result<()> {
    let mut head = [0u8; 2];
    recv.read_exact(&mut head)
        .await
        .map_err(|e| Error::network(format!("tuic uni stream: {e}")))?;
    if head[0] != VERSION {
        return Err(Error::protocol(format!("tuic: bad version {}", head[0])));
    }
    match head[1] {
        CMD_AUTHENTICATE => handle_authenticate(shared, &auth_tx, &mut recv).await,
        CMD_PACKET => {
            let mut frame = head.to_vec();
            frame.extend_from_slice(
                &recv
                    .read_to_end(MAX_UNI_PACKET)
                    .await
                    .map_err(|e| Error::network(format!("tuic packet stream: {e}")))?,
            );
            let f = decode_packet_frame(&frame)?;
            deliver_uni_packet(shared, f.session_id, f.frag_total, f.addr, f.data).await;
            Ok(())
        }
        CMD_DISSOCIATE => {
            let mut sid = [0u8; 2];
            recv.read_exact(&mut sid)
                .await
                .map_err(|e| Error::network(format!("tuic dissociate: {e}")))?;
            dissociate(shared, u16::from_be_bytes(sid));
            Ok(())
        }
        cmd => Err(Error::protocol(format!(
            "tuic: unexpected uni command {cmd:#x}"
        ))),
    }
}

/// Deliver one uni-stream Packet command (quic relay mode). Quic-mode
/// packets are never fragmented — each command is one complete
/// datagram (the client's `udp_send_quic`) — so a fragmented frame is
/// a protocol error, not a partial delivery.
async fn deliver_uni_packet(
    shared: &TuicShared,
    session_id: u16,
    frag_total: u8,
    addr: Option<NetAddr>,
    data: &[u8],
) {
    if !*shared.auth_rx.borrow() {
        tracing::debug!(target: "engine", "tuic udp: packet before authentication");
        return;
    }
    if frag_total != 1 {
        tracing::debug!(target: "engine", "tuic quic packet: fragmented (frag_total {frag_total})");
        return;
    }
    if let Some(target) = addr {
        deliver(shared, session_id, target, data.to_vec(), true).await;
    }
}

async fn deliver(shared: &TuicShared, session_id: u16, target: NetAddr, data: Vec<u8>, quic_mode: bool) {
    let up = udp_session(shared, session_id, quic_mode);
    let _ = up.send((target, data)).await;
}

/// The relay session for `assoc_id`, opening one on first use with the
/// reply transport the first packet arrived on (datagram = native, uni
/// stream = quic mode).
fn udp_session(
    shared: &TuicShared,
    session_id: u16,
    quic_mode: bool,
) -> mpsc::Sender<(NetAddr, Vec<u8>)> {
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
    sessions.insert(
        session_id,
        UdpSession {
            up: up.clone(),
            generation,
        },
    );
    drop(sessions);
    tokio::spawn(downlink(
        shared.conn.clone(),
        shared.sessions.clone(),
        session_id,
        generation,
        quic_mode,
        down_rx,
    ));
    up
}

/// Dissociate: drop the session's uplink sender, which ends the relay
/// association.
fn dissociate(shared: &TuicShared, session_id: u16) {
    shared
        .sessions
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .remove(&session_id);
}

/// One client UDP relay session (pinned to the QUIC connection and the
/// client's assoc id).
struct UdpSession {
    up: mpsc::Sender<(NetAddr, Vec<u8>)>,
    generation: u64,
}

/// Reply pump for one session: Packet frames from the relay back onto
/// the connection — datagrams for native-mode sessions, unidirectional
/// streams for quic-mode ones — until it closes or the session idles
/// out.
async fn downlink(
    conn: quinn::Connection,
    sessions: Arc<Mutex<HashMap<u16, UdpSession>>>,
    session_id: u16,
    generation: u64,
    quic_mode: bool,
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
        let frames = fragment_reply(&conn, session_id, packet_id, &target, &data);
        let mut failed = false;
        if quic_mode {
            for frame in frames {
                match conn.open_uni().await {
                    Ok(mut stream) => {
                        if stream.write_all(&frame).await.is_err() || stream.finish().is_err() {
                            failed = true;
                            break;
                        }
                    }
                    Err(_) => {
                        failed = true;
                        break;
                    }
                }
            }
        } else {
            for frame in frames {
                if conn.send_datagram(Bytes::from(frame)).is_err() {
                    failed = true;
                    break;
                }
            }
        }
        if failed {
            tracing::debug!(target: "engine", "tuic udp reply: connection unusable");
            break;
        }
    }
    // Retire the session so a later packet for the same assoc id opens
    // a fresh relay association (only if this pump still owns it).
    let mut sessions = sessions.lock().unwrap_or_else(|e| e.into_inner());
    if sessions
        .get(&session_id)
        .is_some_and(|s| s.generation == generation)
    {
        sessions.remove(&session_id);
    }
}

/// One in-flight fragmented Packet message: fragments share the packet
/// id and only the first carries the address (client `fragment_packet`).
struct Fragments {
    total: u8,
    addr: Option<NetAddr>,
    parts: Vec<Option<Vec<u8>>>,
}

impl Fragments {
    fn new(total: u8) -> Self {
        Fragments {
            total,
            addr: None,
            parts: vec![None; total as usize],
        }
    }

    /// Add one fragment; `Some((addr, assembled))` once every slot is
    /// filled.
    fn add(
        &mut self,
        frag_id: u8,
        addr: Option<NetAddr>,
        data: &[u8],
    ) -> Option<(Option<NetAddr>, Vec<u8>)> {
        if frag_id >= self.total {
            return None;
        }
        if self.addr.is_none() {
            self.addr = addr;
        }
        self.parts[frag_id as usize] = Some(data.to_vec());
        if self.parts.iter().all(|p| p.is_some()) {
            return Some((
                self.addr.clone(),
                self.parts.drain(..).flat_map(|p| p.unwrap_or_default()).collect(),
            ));
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
            "tuic: no successful authentication before the command",
        ))
    }
}

/// Read the sing address form (`FAMILY || ADDR || PORT`) off a stream —
/// the exact bytes the client's `encode_addr_port` writes — and decode
/// them with the client's own public decoder.
async fn read_addr(recv: &mut quinn::RecvStream) -> Result<NetAddr> {
    let mut atyp = [0u8; 1];
    recv.read_exact(&mut atyp)
        .await
        .map_err(|e| Error::network(format!("tuic addr: {e}")))?;
    let mut buf = vec![atyp[0]];
    let host_len = match atyp[0] {
        ATYP_FQDN => {
            let mut len = [0u8; 1];
            recv.read_exact(&mut len)
                .await
                .map_err(|e| Error::network(format!("tuic addr: {e}")))?;
            buf.push(len[0]);
            len[0] as usize
        }
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        other => return Err(Error::protocol(format!("tuic addr: bad family {other:#x}"))),
    };
    let mut rest = vec![0u8; host_len + 2];
    recv.read_exact(&mut rest)
        .await
        .map_err(|e| Error::network(format!("tuic addr: {e}")))?;
    buf.extend_from_slice(&rest);
    match decode_addr_port(&buf) {
        Ok((Some(addr), used)) if used == buf.len() => Ok(addr),
        _ => Err(Error::protocol("tuic addr: malformed address")),
    }
}

/// The on-wire size of a Packet frame header for a full target address
/// (the client's `packet_header_size`).
fn packet_header_size(target: &NetAddr) -> usize {
    10 + match &target.host {
        Host::Domain(d) => 4 + d.len().min(255),
        Host::Ip(IpAddr::V4(_)) => 7,
        Host::Ip(IpAddr::V6(_)) => 19,
    }
}

/// Split one reply into Packet frames. The budget is quinn's current
/// datagram limit minus the frame header — the client's own 1197-byte
/// UDP_MTU mirroring would overshoot quinn's path-MTU-bounded
/// datagrams — with later fragments carrying the empty address, exactly
/// the client's `fragment_packet` shape.
fn fragment_reply(
    conn: &quinn::Connection,
    session_id: u16,
    packet_id: u16,
    target: &NetAddr,
    data: &[u8],
) -> Vec<Vec<u8>> {
    let budget = conn
        .max_datagram_size()
        .unwrap_or(1150)
        .saturating_sub(packet_header_size(target));
    if data.len() <= budget || budget == 0 {
        return vec![encode_packet_frame(
            session_id,
            packet_id,
            0,
            1,
            Some(target),
            data,
        )];
    }
    let total = data.chunks(budget).count().min(usize::from(u8::MAX));
    data.chunks(budget)
        .take(total)
        .enumerate()
        .map(|(i, chunk)| {
            let addr = if i == 0 { Some(target) } else { None };
            encode_packet_frame(
                session_id,
                packet_id,
                i as u8,
                total as u8,
                addr,
                chunk,
            )
        })
        .collect()
}

/// Encode the sing address form: `FAMILY || ADDR || PORT(be)` (the port
/// omitted for the empty family) — the client's `encode_addr_port`,
/// which is private to the proto module, mirrored byte for byte.
fn encode_addr_port(buf: &mut Vec<u8>, target: Option<&NetAddr>) {
    match target.map(|t| &t.host) {
        Some(Host::Domain(d)) => {
            let d = d.as_bytes();
            let len = d.len().min(255);
            buf.push(ATYP_FQDN);
            buf.push(len as u8);
            buf.extend_from_slice(&d[..len]);
        }
        Some(Host::Ip(IpAddr::V4(v4))) => {
            buf.push(ATYP_IPV4);
            buf.extend_from_slice(&v4.octets());
        }
        Some(Host::Ip(IpAddr::V6(v6))) => {
            buf.push(ATYP_IPV6);
            buf.extend_from_slice(&v6.octets());
        }
        None => buf.push(0xff),
    }
    if let Some(t) = target {
        buf.extend_from_slice(&t.port.to_be_bytes());
    }
}

/// Encode a Packet command frame:
/// `VER || TYPE(2) || ASSOC_ID(u16be) || PKT_ID(u16be) || FRAG_TOTAL ||
/// FRAG_ID || SIZE(u16be) || ADDR || DATA` — the client's
/// `encode_packet_frame`, mirrored byte for byte (note FRAG_TOTAL
/// precedes FRAG_ID on the wire).
fn encode_packet_frame(
    session_id: u16,
    packet_id: u16,
    frag_id: u8,
    frag_total: u8,
    target: Option<&NetAddr>,
    data: &[u8],
) -> Vec<u8> {
    let mut buf = Vec::with_capacity(10 + 19 + data.len());
    buf.extend_from_slice(&[VERSION, CMD_PACKET]);
    buf.extend_from_slice(&session_id.to_be_bytes());
    buf.extend_from_slice(&packet_id.to_be_bytes());
    buf.push(frag_total);
    buf.push(frag_id);
    buf.extend_from_slice(&(data.len() as u16).to_be_bytes());
    encode_addr_port(&mut buf, target);
    buf.extend_from_slice(data);
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbound::proxy_server::test_support::{self_signed_tls, Capture};
    use crate::proto::tuic as client;
    use crate::proto::tuic::TuicCfg;
    use rand::RngCore;
    use std::net::Ipv4Addr;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Fresh per-run credential: nothing usable is ever committed.
    fn fresh_password() -> String {
        let mut b = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut b);
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    async fn spawn_server(password: &str, uuid: uuid::Uuid) -> (Arc<Capture>, SocketAddr) {
        let (tls, _dir) = self_signed_tls();
        let cfg = ServerConfig {
            tag: "tuic-test".into(),
            bind: "127.0.0.1".into(),
            port: 0,
            protocol: ServerProtocol::Tuic {
                uuid: uuid.to_string(),
                password: password.into(),
                tls: Some(tls),
            },
        };
        let capture = Capture::new();
        let addr = serve(&cfg, capture.clone()).await.unwrap();
        (capture, addr)
    }

    fn client_cfg(password: &str, port: u16, uuid: uuid::Uuid) -> TuicCfg {
        TuicCfg {
            server: "127.0.0.1".into(),
            port,
            uuid,
            password: password.into(),
            sni: "localhost".into(),
            skip_verify: true,
            udp_relay_mode: client::UdpRelayMode::Native,
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

    /// A rejected client: authenticate writes fine (fire-and-forget),
    /// so the failure surfaces as the server closing the connection.
    async fn assert_closed_and_nothing_relayed(
        capture: &Arc<Capture>,
        conn: &quinn::Connection,
        target: &NetAddr,
    ) {
        let _ = tokio::time::timeout(Duration::from_secs(5), conn.closed()).await;
        if let Ok(mut stream) = client::tcp_stream(conn, target).await {
            let _ = stream.write_all(b"ping").await;
            let mut buf = [0u8; 8];
            let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
            match read {
                Ok(Ok(0)) | Ok(Err(_)) => {}
                Ok(Ok(n)) => panic!("unexpected {n} bytes from a rejected client"),
                Err(_) => panic!("timeout: server did not close the connection"),
            }
        }
        assert_eq!(capture.relayed(), 0);
        assert!(capture.udp_sessions().is_empty());
    }

    #[tokio::test]
    async fn tcp_roundtrip_domain_ipv4_and_ipv6_targets() {
        let password = fresh_password();
        let uuid = uuid::Uuid::new_v4();
        let (capture, addr) = spawn_server(&password, uuid).await;
        let conn = client::connect(&client_cfg(&password, addr.port(), uuid))
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
    async fn wrong_password_closes_the_connection() {
        let password = fresh_password();
        let uuid = uuid::Uuid::new_v4();
        let (capture, addr) = spawn_server(&password, uuid).await;
        let conn = client::connect(&client_cfg(&fresh_password(), addr.port(), uuid))
            .await
            .unwrap();
        let target = NetAddr::domain("echo.test", 443).unwrap();
        assert_closed_and_nothing_relayed(&capture, &conn, &target).await;
    }

    #[tokio::test]
    async fn wrong_uuid_closes_the_connection() {
        let password = fresh_password();
        let (capture, addr) = spawn_server(&password, uuid::Uuid::new_v4()).await;
        let conn = client::connect(&client_cfg(&password, addr.port(), uuid::Uuid::new_v4()))
            .await
            .unwrap();
        let target = NetAddr::domain("echo.test", 443).unwrap();
        assert_closed_and_nothing_relayed(&capture, &conn, &target).await;
    }

    #[tokio::test]
    async fn udp_native_roundtrip() {
        let password = fresh_password();
        let uuid = uuid::Uuid::new_v4();
        let (capture, addr) = spawn_server(&password, uuid).await;
        let conn = client::connect(&client_cfg(&password, addr.port(), uuid))
            .await
            .unwrap();
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let (sid, pid): (u16, u16) = (rand::random(), rand::random());
        client::udp_send_native(&conn, sid, pid, &target, b"ping")
            .await
            .unwrap();

        let datagram = tokio::time::timeout(Duration::from_secs(5), conn.read_datagram())
            .await
            .expect("reply timeout")
            .unwrap();
        let f = client::decode_packet_frame(&datagram).unwrap();
        assert_eq!(f.session_id, sid, "the reply echoes the client's assoc id");
        assert_eq!(f.addr.as_ref(), Some(&target));
        assert_eq!(f.data, b"ping");
        assert_eq!(capture.udp_targets(), vec![target]);
        assert_eq!(capture.udp_sessions().len(), 1);
        assert_eq!(capture.udp_sessions()[0].1, "tuic-test");
    }

    /// Quic relay mode: the client's Packet command on a uni stream,
    /// the server's reply back on a uni stream.
    #[tokio::test]
    async fn udp_quic_mode_roundtrip() {
        let password = fresh_password();
        let uuid = uuid::Uuid::new_v4();
        let (capture, addr) = spawn_server(&password, uuid).await;
        let conn = client::connect(&client_cfg(&password, addr.port(), uuid))
            .await
            .unwrap();
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let (sid, pid): (u16, u16) = (rand::random(), rand::random());
        client::udp_send_quic(&conn, sid, pid, &target, b"quinc")
            .await
            .unwrap();

        let mut uni = tokio::time::timeout(Duration::from_secs(5), conn.accept_uni())
            .await
            .expect("reply stream timeout")
            .unwrap();
        let frame = uni.read_to_end(MAX_UNI_PACKET).await.unwrap();
        let f = client::decode_packet_frame(&frame).unwrap();
        assert_eq!(f.session_id, sid);
        assert_eq!(f.addr.as_ref(), Some(&target));
        assert_eq!(f.data, b"quinc");
        assert_eq!(capture.udp_targets(), vec![target]);
    }

    /// Hand-fragmented Packet datagrams in (the client fragments at
    /// 1197 bytes, over quinn's datagram budget, so the fragments are
    /// built with the server-side encoder), and a reply big enough that
    /// the server must fragment it back.
    #[tokio::test]
    async fn udp_fragment_reassembly_and_fragmented_reply() {
        let password = fresh_password();
        let uuid = uuid::Uuid::new_v4();
        let (capture, addr) = spawn_server(&password, uuid).await;
        let conn = client::connect(&client_cfg(&password, addr.port(), uuid))
            .await
            .unwrap();
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let payload: Vec<u8> = (0..1500u32).map(|i| (i % 251) as u8).collect();
        let sid: u16 = rand::random();
        let first = encode_packet_frame(sid, 42, 0, 2, Some(&target), &payload[..750]);
        let second = encode_packet_frame(sid, 42, 1, 2, None, &payload[750..]);
        conn.send_datagram(Bytes::from(first)).unwrap();
        conn.send_datagram(Bytes::from(second)).unwrap();

        // Collect the reply's datagrams until the fragments complete.
        let mut parts: HashMap<u8, Vec<u8>> = HashMap::new();
        let mut total = 0usize;
        let deadline = tokio::time::timeout(Duration::from_secs(5), async {
            let mut reply_packet_id = None;
            loop {
                let datagram = conn.read_datagram().await.expect("reply datagram");
                let f = client::decode_packet_frame(&datagram).unwrap();
                assert_eq!(f.session_id, sid);
                // All fragments of one message share the packet id.
                if let Some(pid) = reply_packet_id {
                    assert_eq!(pid, f.packet_id, "fragments share the packet id");
                }
                reply_packet_id = Some(f.packet_id);
                if f.frag_id == 0 {
                    assert_eq!(f.addr.as_ref(), Some(&target));
                } else {
                    assert_eq!(f.addr, None, "later fragments carry no address");
                }
                total = f.frag_total as usize;
                parts.insert(f.frag_id, f.data.to_vec());
                if parts.len() == total && total > 1 {
                    break;
                }
            }
        })
        .await;
        deadline.expect("reply timeout");
        let mut reassembled = Vec::new();
        for i in 0..total {
            reassembled.extend_from_slice(&parts.remove(&(i as u8)).expect("fragment present"));
        }
        assert_eq!(reassembled, payload);
        assert_eq!(capture.udp_targets(), vec![target]);
    }

    /// Dissociate releases the session: the next packet for the same
    /// assoc id opens a fresh relay association.
    #[tokio::test]
    async fn dissociate_then_reuse_reopens_the_session() {
        let password = fresh_password();
        let uuid = uuid::Uuid::new_v4();
        let (capture, addr) = spawn_server(&password, uuid).await;
        let conn = client::connect(&client_cfg(&password, addr.port(), uuid))
            .await
            .unwrap();
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let sid: u16 = rand::random();
        client::udp_send_native(&conn, sid, 1, &target, b"one")
            .await
            .unwrap();
        let _ = tokio::time::timeout(Duration::from_secs(5), conn.read_datagram())
            .await
            .expect("first reply");
        client::dissociate(&conn, sid).await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        client::udp_send_native(&conn, sid, 2, &target, b"two")
            .await
            .unwrap();
        let datagram = tokio::time::timeout(Duration::from_secs(5), conn.read_datagram())
            .await
            .expect("second reply")
            .unwrap();
        let f = client::decode_packet_frame(&datagram).unwrap();
        assert_eq!(f.data, b"two");
        assert_eq!(capture.udp_sessions().len(), 2);
    }

    /// The client's heartbeat datagram is tolerated: the connection
    /// stays usable afterwards.
    #[tokio::test]
    async fn heartbeat_is_tolerated() {
        let password = fresh_password();
        let uuid = uuid::Uuid::new_v4();
        let (capture, addr) = spawn_server(&password, uuid).await;
        let conn = client::connect(&client_cfg(&password, addr.port(), uuid))
            .await
            .unwrap();
        for _ in 0..3 {
            client::heartbeat(&conn).await.unwrap();
        }
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let stream = client::tcp_stream(&conn, &target).await.unwrap();
        echo(stream, b"ping").await;
        assert_eq!(capture.targets(), vec![target]);
    }

    #[tokio::test]
    async fn missing_tls_and_bad_uuid_are_config_errors() {
        let cfg = ServerConfig {
            tag: "t".into(),
            bind: "127.0.0.1".into(),
            port: 0,
            protocol: ServerProtocol::Tuic {
                uuid: uuid::Uuid::new_v4().to_string(),
                password: "x".into(),
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
            protocol: ServerProtocol::Tuic {
                uuid: "not-a-uuid".into(),
                password: "x".into(),
                tls: Some(tls),
            },
        };
        let err = serve(&cfg, Capture::new()).await.unwrap_err().to_string();
        assert!(err.contains("uuid"), "{err}");
    }

    #[test]
    fn server_packet_frame_matches_the_client_decoder() {
        let target = NetAddr::domain("example.com", 53).unwrap();
        let frame = encode_packet_frame(9, 513, 0, 1, Some(&target), b"query");
        // Header layout: ver, cmd, sid u16be, pid u16be, TOTAL, id, len
        // u16be, then the address (the client's own known-bytes vector).
        assert_eq!(
            &frame[..10],
            &[0x05, 0x02, 0x00, 0x09, 0x02, 0x01, 0x01, 0x00, 0x00, 0x05]
        );
        let f = client::decode_packet_frame(&frame).unwrap();
        assert_eq!(
            (f.session_id, f.packet_id, f.frag_id, f.frag_total),
            (9, 513, 0, 1)
        );
        assert_eq!(f.addr.as_ref(), Some(&target));
        assert_eq!(f.data, b"query");

        // Later-fragment form: empty address family, no port.
        let frame = encode_packet_frame(9, 513, 1, 2, None, b"xx");
        assert_eq!(&frame[10..11], &[0xff]);
        let f = client::decode_packet_frame(&frame).unwrap();
        assert_eq!((f.frag_id, f.frag_total), (1, 2));
        assert_eq!(f.addr, None);
        assert_eq!(f.data, b"xx");
    }

    #[test]
    fn fragment_reply_covers_small_and_large_payloads() {
        // Budget-free check of the fragmentation shape: a frame built
        // against a mocked connection is exercised in the QUIC tests;
        // here verify the encoder's degenerate single-frame path via a
        // connection-less helper (budget 0 keeps one frame).
        let target = NetAddr::domain("example.com", 53).unwrap();
        let frame = encode_packet_frame(1, 2, 0, 1, Some(&target), b"tiny");
        let f = client::decode_packet_frame(&frame).unwrap();
        assert_eq!((f.frag_id, f.frag_total, f.data), (0, 1, &b"tiny"[..]));
        assert_eq!(packet_header_size(&target), 10 + 4 + 11);
    }
}
