//! AnyTLS outbound, ported from mihomo's `transport/anytls`
//! (`client.go`, `session/{frame.go,session.go,stream.go,client.go}`,
//! `padding/padding.go`) and the anytls-go protocol spec
//! (`anytls/anytls-go docs/protocol.md`).
//!
//! The wire, as the server sees it:
//!
//! 1. a TLS handshake (rustls via [`crate::transport::tls_connect`]);
//! 2. **auth** immediately after: `sha256(password) || be16(padding0 len)
//!    || padding0 zeros` (protocol.md "认证"; client.go:77-85) — the
//!    padding0 length is the scheme's `0=` entry. Auth failure makes the
//!    server close (or fall back to a decoy HTTP server);
//! 3. a session of frames `cmd u8 || streamId be32 || len be16 || data`
//!    (frame.go:22-49). The client's first TLS write carries
//!    `cmdSettings(v=2, client=…, padding-md5=…)` + `cmdSYN(sid)` +
//!    `cmdPSH(socks target)` in ONE padded write (session.go `Run` +
//!    `OpenStream` buffering + client.go `CreateProxy`);
//! 4. data as `cmdPSH` frames (≤0xFFFF payload each, session.go:379-420),
//!    close as `cmdFIN`;
//! 5. **padding**: the first `stop` writes are split/padded per the
//!    scheme (`Session.writeConn`, session.go:445-519) so TLS record
//!    sizes look like ordinary HTTPS; the server can push a new scheme
//!    via `cmdUpdatePaddingScheme` when the client's md5 differs.
//!
//! ## Session multiplexing + idle pool
//!
//! A session ([`AnyTlsSession`]) carries any number of streams
//! distinguished by stream id — `OpenStream` assigns `streamId.Add(1)`
//! (session.go:135-169) and the recv loop dispatches `cmdPSH`/`cmdFIN`
//! by id. [`AnyTlsStream`] is one stream handle over the shared session
//! (a `net.Conn` over the session pipe, stream.go:14-38). The
//! [`AnyTlsSessionPool`] ports `session/client.go`: reuse an idle
//! session, open streams on the live session while it has capacity,
//! dial fresh when it is saturated/closed, recycle a session to the
//! idle set when its last stream ends (stream.dieHook,
//! session/client.go:90-109), and expire idle sessions on a timer
//! (`idleCleanup`, session/client.go:171-206) honouring `min-idle`.
//!
//! UDP rides the same sessions as sing-box **udp-over-tcp v2**
//! (adapter/outbound/anytls.go `ListenPacketContext` →
//! `uot.RequestDestination(2)`): the stream target is the magic domain
//! `sp.v2.udp-over-tcp.arpa`, the first packet is prefixed with the uot
//! request `[isConnect=0x00][socksaddr]`, and every datagram is
//! `uot-addr || be16 len || payload` (`uot/{protocol,conn}.go`).
//!
//! ## Deferred (out of scope here)
//!
//! * **Heartbeats**: `cmdHeartRequest` is answered (`cmdHeartResponse`)
//!   but never sent; the v2 SYNACK liveness watchdog (3s
//!   `DeadlineWatcher`, session.go:143-152) is not implemented.
//! * **ALPN / client certs / fingerprint pinning / ECH / shadow-tls and
//!   restls wrappers**: `AnyTlsOut` carries only the fields below;
//!   the integrator layers extra transports before [`connect`] if
//!   needed. `client-metadata` defaults to the empty string, matching
//!   mihomo's default.

use std::collections::{HashMap, VecDeque};
use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{ready, Context, Poll};
use std::time::{Duration, Instant};

use bytes::{Buf, BytesMut};
use md5::Md5;
use rand::Rng;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{mpsc, oneshot, watch};
use tracing::{debug, error, warn};

use crate::addr::{encode_socks_addr, Host, NetAddr};
use crate::error::{Error, Result};
use crate::stream::BoxProxyStream;
use crate::transport::{tls_connect, TlsSettings};

// session/frame.go:7-20 command bytes.
const CMD_WASTE: u8 = 0; // paddings
const CMD_SYN: u8 = 1; // stream open
const CMD_PSH: u8 = 2; // data push
const CMD_FIN: u8 = 3; // stream close
const CMD_SETTINGS: u8 = 4; // client → server settings
const CMD_ALERT: u8 = 5; // server → client alert
const CMD_UPDATE_PADDING: u8 = 6; // padding scheme update
const CMD_SYNACK: u8 = 7; // server reports stream open
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;

/// `headerOverHeadSize` (frame.go:22-24): cmd + sid + len.
const HEADER_SIZE: usize = 1 + 4 + 2;
/// `maxFrameDataLen` (session.go:379): PSH payload cap (u16).
const MAX_FRAME_DATA: usize = 0xFFFF;
/// Padding scheme entries are `min-max` sizes; `-1` is the check mark
/// (`padding.CheckMark`).
const CHECK_MARK: isize = -1;

/// padding.go:16-25 — the exact default scheme mihomo ships.
const DEFAULT_PADDING_SCHEME: &[u8] = b"stop=8\n\
0=30-30\n\
1=100-400\n\
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000\n\
3=9-9,500-1000\n\
4=500-1000\n\
5=500-1000\n\
6=500-1000\n\
7=500-1000";

/// Outbound AnyTLS endpoint (mihomo `proxies: type: anytls`).
#[derive(Debug, Clone)]
pub struct AnyTlsOut {
    pub server: String,
    pub port: u16,
    pub password: String,
    /// SNI for the TLS layer (defaults to `server` when empty, like
    /// mihomo's `tlsConfig.Host` fallback).
    pub sni: String,
    /// `skip-cert-verify`.
    pub skip_verify: bool,
    /// Whether the outbound advertises UDP (via [`udp_stream`]).
    pub udp: bool,
    /// mihomo `jls-opts` on anytls: the JLS cover replaces the plain TLS
    /// handshake (wired in [`open_session`]).
    pub jls: Option<crate::proto::jls::JlsUser>,
    /// mihomo `ech-opts` on anytls — carried; enabling fails at session
    /// open with the precise blocker (see [`open_session`]).
    pub ech: Option<crate::proto::ech::EchOptions>,
}

// ---------------------------------------------------------------------------
// Padding scheme (padding/padding.go)
// ---------------------------------------------------------------------------

/// A parsed padding scheme (`PaddingFactory`). `GenerateRecordPayloadSizes`
/// re-parses the entry on every call, exactly like the Go code — malformed
/// entries are skipped, not fatal.
#[derive(Clone)]
struct PaddingFactory {
    raw: Vec<u8>,
    stop: u32,
    md5: String,
}

impl PaddingFactory {
    /// `NewPaddingFactory` (padding.go:42-58): the map must be non-empty
    /// and `stop` must parse.
    fn new(raw: &[u8]) -> Option<Self> {
        let mut stop: Option<u32> = None;
        let mut entries = 0usize;
        for line in raw.split(|b| *b == b'\n') {
            let line = String::from_utf8_lossy(line);
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            entries += 1;
            if key == "stop" {
                stop = value.trim().parse().ok();
            }
        }
        if entries == 0 {
            return None;
        }
        Some(PaddingFactory {
            raw: raw.to_vec(),
            stop: stop?,
            md5: format!("{:x}", Md5::digest(raw)),
        })
    }

    /// `GenerateRecordPayloadSizes` (padding.go:60-92): per-packet sizes;
    /// `CHECK_MARK` entries come through verbatim.
    fn generate(&self, pkt: u32) -> Vec<isize> {
        let key = pkt.to_string();
        let mut sizes = Vec::new();
        for line in self.raw.split(|b| *b == b'\n') {
            let line = String::from_utf8_lossy(line);
            let Some((k, v)) = line.split_once('=') else {
                continue;
            };
            if k != key {
                continue;
            }
            for range in v.split(',') {
                let Some((min_s, max_s)) = range.split_once('-') else {
                    if range.trim() == "c" {
                        sizes.push(CHECK_MARK);
                    }
                    continue;
                };
                let (Ok(mut min), Ok(mut max)) =
                    (min_s.trim().parse::<i64>(), max_s.trim().parse::<i64>())
                else {
                    continue;
                };
                if min > max {
                    std::mem::swap(&mut min, &mut max);
                }
                if min <= 0 || max <= 0 {
                    continue;
                }
                if min == max {
                    sizes.push(min as isize);
                } else {
                    // Go: rand.Int(reader, max-min) + min — half-open range.
                    let span = (max - min) as u64;
                    let v = rand::rngs::OsRng.gen_range(0..span) + min as u64;
                    sizes.push(v as isize);
                }
            }
        }
        sizes
    }
}

// rand::Rng is imported at the top of the file (needed for gen_range in
// PaddingFactory::generate).

/// One `cmdWaste` frame of `len` zero bytes (session.go:482-486).
fn waste_frame(len: usize) -> Vec<u8> {
    let mut frame = Vec::with_capacity(HEADER_SIZE + len);
    frame.push(CMD_WASTE);
    frame.extend_from_slice(&0u32.to_be_bytes());
    frame.extend_from_slice(&(len as u16).to_be_bytes());
    frame.resize(HEADER_SIZE + len, 0);
    frame
}

/// Append one session frame `cmd || sid be32 || len be16 || data`
/// (session.go:422-443 `writeControlFrame` layout).
fn frame_into(out: &mut Vec<u8>, cmd: u8, sid: u32, data: &[u8]) {
    out.push(cmd);
    out.extend_from_slice(&sid.to_be_bytes());
    out.extend_from_slice(&(data.len() as u16).to_be_bytes());
    out.extend_from_slice(data);
}

/// Append the PSH frames for `data` (session.go:381-420
/// `writeDataFrame`): ≤0xFFFF payload per frame, concatenated for a
/// single writeConn call.
fn psh_frames_into(out: &mut Vec<u8>, sid: u32, data: &[u8]) {
    if data.is_empty() {
        return;
    }
    let mut rest = data;
    while !rest.is_empty() {
        let chunk = rest.split_at(rest.len().min(MAX_FRAME_DATA)).0;
        frame_into(out, CMD_PSH, sid, chunk);
        rest = &rest[chunk.len()..];
    }
}

// ---------------------------------------------------------------------------
// Session multiplexing (transport/anytls/session/{session,stream}.go)
// ---------------------------------------------------------------------------

/// One inbound event for a stream — what Go's session pipe delivers
/// (session.go:171-360 recvLoop → stream.pipeW / closeWithError).
enum StreamEvent {
    Data(Vec<u8>),
    /// cmdFIN — the peer closed the stream (closeLocally → pipe EOF).
    Fin,
    /// cmdSYNACK carrying an error payload
    /// ("remote: …", session.go:233-246).
    RemoteError(String),
}

/// A queued write for the session's writer task — the serialised
/// `writeConn` path under `connLock` (session.go:445-519).
enum WriteCmd {
    /// `writeConn(b)`: PSH/FIN/control frames. While `buffering`, the
    /// bytes append to the session buffer instead of hitting the wire
    /// (session.go:449-451).
    Bytes(Vec<u8>),
    /// `OpenStream`'s first write: the buffered settings + cmdSYN +
    /// first cmdPSH leave as ONE padded writeConn (session.go:93-97,
    /// 135-158); the ack resolves once the transport accepted it.
    Open {
        frames: Vec<u8>,
        ack: oneshot::Sender<io::Result<()>>,
    },
    /// Flush the transport, acking completion (the poll_flush bridge).
    Flush(oneshot::Sender<io::Result<()>>),
    /// Close the transport (Session.Close → conn.Close).
    Shutdown,
}

/// A session returned to the pool's idle set with its idle timestamp
/// (`session.idleSince`, session/client.go:104-105).
type RecycledSession = (Arc<SessionCore>, Instant);

/// The shared state of one live anytls session — mihomo `Session`
/// (session.go:22-54), client side. The recv task, the writer task, the
/// pool and every stream handle hold an `Arc` to this.
struct SessionCore {
    /// Mailbox to the writer task (connLock serialisation).
    tx: mpsc::UnboundedSender<WriteCmd>,
    /// Per-stream event pipes (streams map).
    streams: StdMutex<HashMap<u32, mpsc::UnboundedSender<StreamEvent>>>,
    /// `streamId` — `fetch_add(1) + 1`, so sids start at 1
    /// (session.go:140).
    next_sid: AtomicU32,
    /// Live stream count; zero = the session is idle/recyclable.
    active: AtomicUsize,
    dead: watch::Sender<bool>,
    dead_rx: watch::Receiver<bool>,
    /// The padding factory shared with the writer task (server updates
    /// land here, session.go:315-329).
    padding: Arc<StdMutex<PaddingFactory>>,
    /// Peer version from cmdSettings/cmdServerSettings (v2 sends SYNACK).
    peer_version: AtomicU32,
    die_reason: Arc<StdMutex<String>>,
    /// Recycling hook — stream.dieHook (session/client.go:90-109): set
    /// when the session belongs to a pool; the last stream to close
    /// sends the session back to the idle set.
    recycle: StdMutex<Option<mpsc::UnboundedSender<RecycledSession>>>,
    /// idleSince (session.go:38-39) — set when the last stream ended.
    idle_since: StdMutex<Option<Instant>>,
}

impl SessionCore {
    fn is_dead(&self) -> bool {
        *self.dead_rx.borrow()
    }

    fn death_reason(&self) -> String {
        self.die_reason.lock().unwrap().clone()
    }

    /// `Session.Close` (session.go:110-132): idempotent; every stream is
    /// closed locally (their pipes end) and the transport shuts down.
    fn kill(&self, reason: &str) {
        if self.is_dead() {
            return;
        }
        *self.die_reason.lock().unwrap() = reason.to_string();
        let _ = self.dead.send(true);
        self.streams.lock().unwrap().clear();
        let _ = self.tx.send(WriteCmd::Shutdown);
    }
}

/// The writer task's private state — `sendPadding`, `pktCounter`,
/// `buffering`/`buffer` (session.go:44-49) plus the transport's write
/// half (connLock).
struct WriterState {
    conn: tokio::io::WriteHalf<BoxProxyStream>,
    send_padding: bool,
    pkt_counter: u32,
    buffer: Vec<u8>,
    buffering: bool,
    padding: Arc<StdMutex<PaddingFactory>>,
    dead: watch::Sender<bool>,
    die_reason: Arc<StdMutex<String>>,
}

/// `writeConn`'s padding split (session.go:457-518): the first `stop`
/// writes are segmented per the scheme (each segment its own transport
/// write so TLS record sizes match the scheme); after that, plain
/// writes. `pkt < stop` gates the padding exactly like Go's counter.
fn padded_segments(
    padding: &PaddingFactory,
    send_padding: &mut bool,
    pkt_counter: &mut u32,
    b: &[u8],
) -> Result<Vec<Vec<u8>>> {
    if !*send_padding {
        return Ok(vec![b.to_vec()]);
    }
    *pkt_counter += 1;
    if *pkt_counter >= padding.stop {
        // session.go:513-515: stop padding from now on.
        *send_padding = false;
        return Ok(vec![b.to_vec()]);
    }
    let sizes = padding.generate(*pkt_counter);
    let mut segments = Vec::with_capacity(sizes.len() + 1);
    let mut rest = b;
    for l in sizes {
        if l == CHECK_MARK {
            // session.go:465-471: no payload left → stop; else skip.
            if rest.is_empty() {
                break;
            }
            continue;
        }
        let l = usize::try_from(l).unwrap_or(0);
        if rest.len() > l {
            // This packet is all payload.
            segments.push(rest[..l].to_vec());
            rest = &rest[l..];
        } else if !rest.is_empty() {
            // Last of the payload plus a cmdWaste tail.
            let mut seg = rest.to_vec();
            let padding_len = l.saturating_sub(rest.len() + HEADER_SIZE);
            if padding_len > 0 {
                seg.extend_from_slice(&waste_frame(padding_len));
            }
            segments.push(seg);
            rest = &[];
        } else {
            // This packet is all padding.
            segments.push(waste_frame(l));
            rest = &[];
        }
    }
    if !rest.is_empty() {
        segments.push(rest.to_vec());
    }
    Ok(segments)
}

impl WriterState {
    async fn write_conn(&mut self, b: &[u8]) -> io::Result<()> {
        // Clone the factory out of the lock: the padding scheme can be
        // swapped by the recv task mid-write (upstream reads the atomic
        // pointer per writeConn, session.go:460).
        let padding = self.padding.lock().unwrap().clone();
        let segments =
            padded_segments(&padding, &mut self.send_padding, &mut self.pkt_counter, b)
                .map_err(io_invalid)?;
        for seg in segments {
            self.conn.write_all(&seg).await?;
        }
        self.conn.flush().await
    }

    async fn fail(self, reason: String) {
        *self.die_reason.lock().unwrap() = reason;
        let _ = self.dead.send(true);
        // The recv task observes the flag and finishes Session.Close.
    }
}

/// The writer task: drains [`WriteCmd`]s, one writeConn each. Writer
/// errors mark the session dead (writeControlFrame → s.Close,
/// session.go:431-439). Exits when the mailbox closes (every handle to
/// the session is gone) or on Shutdown.
async fn writer_loop(mut rx: mpsc::UnboundedReceiver<WriteCmd>, mut st: WriterState) {
    while let Some(cmd) = rx.recv().await {
        match cmd {
            WriteCmd::Bytes(frames) => {
                if st.buffering {
                    // session.go:449-451 — hold back until the first
                    // stream write flushes the buffer.
                    st.buffer.extend_from_slice(&frames);
                    continue;
                }
                let mut b = std::mem::take(&mut st.buffer); // 452-455
                b.extend_from_slice(&frames);
                if let Err(e) = st.write_conn(&b).await {
                    st.fail(format!("anytls: session write error: {e}")).await;
                    return;
                }
            }
            WriteCmd::Open { frames, ack } => {
                // session.go:158 — `s.buffering = false` so the proxy's
                // first write flushes settings + SYN + PSH together.
                st.buffering = false;
                let mut b = std::mem::take(&mut st.buffer);
                b.extend_from_slice(&frames);
                match st.write_conn(&b).await {
                    Ok(()) => {
                        let _ = ack.send(Ok(()));
                    }
                    Err(e) => {
                        let _ = ack.send(Err(io::Error::new(
                            io::ErrorKind::BrokenPipe,
                            e.to_string(),
                        )));
                        st.fail(format!("anytls: session write error: {e}")).await;
                        return;
                    }
                }
            }
            WriteCmd::Flush(ack) => {
                let res = st.conn.flush().await;
                let _ = ack.send(res);
            }
            WriteCmd::Shutdown => {
                let _ = st.conn.shutdown().await;
                return;
            }
        }
    }
    // Mailbox closed: the session is gone — close the transport.
    let _ = st.conn.shutdown().await;
}

/// The recv task — recvLoop (session.go:171-360), client side. Reads
/// frames off the transport, dispatches per-stream data, answers
/// heartbeats, adopts padding updates, and closes the session on
/// transport EOF/error or an alert.
async fn recv_loop(
    mut rd: tokio::io::ReadHalf<BoxProxyStream>,
    core: Arc<SessionCore>,
    mut dead_rx: watch::Receiver<bool>,
) {
    let mut rbuf = BytesMut::with_capacity(16 * 1024);
    'session: loop {
        // Dispatch every complete buffered frame first.
        while let Some((cmd, sid, len)) = parse_header(&rbuf) {
            if rbuf.len() < HEADER_SIZE + len {
                break;
            }
            rbuf.advance(HEADER_SIZE);
            let data = rbuf[..len].to_vec();
            rbuf.advance(len);
            match cmd {
                CMD_PSH => {
                    // session.go:190-205 — pipe into the stream if live.
                    if !data.is_empty() {
                        let streams = core.streams.lock().unwrap();
                        if let Some(tx) = streams.get(&sid) {
                            let _ = tx.send(StreamEvent::Data(data));
                        }
                    }
                }
                CMD_FIN => {
                    // session.go:248-255 — remove + closeLocally.
                    let tx = core.streams.lock().unwrap().remove(&sid);
                    if let Some(tx) = tx {
                        let _ = tx.send(StreamEvent::Fin);
                    }
                }
                CMD_SYNACK => {
                    // session.go:226-247 — error payload closes the
                    // stream with "remote: msg".
                    if !data.is_empty() {
                        let streams = core.streams.lock().unwrap();
                        if let Some(tx) = streams.get(&sid) {
                            let _ = tx.send(StreamEvent::RemoteError(format!(
                                "anytls: remote: {}",
                                String::from_utf8_lossy(&data)
                            )));
                        }
                    }
                }
                CMD_WASTE => {}
                CMD_ALERT => {
                    // session.go:302-313 — log and end the session.
                    error!(
                        target: "engine",
                        "anytls: server alert: {}",
                        String::from_utf8_lossy(&data)
                    );
                    core.kill("anytls: server alert");
                    break 'session;
                }
                CMD_UPDATE_PADDING => {
                    // session.go:315-329.
                    match PaddingFactory::new(&data) {
                        Some(p) => {
                            debug!(target: "engine", md5 = %p.md5, "anytls: padding scheme updated");
                            *core.padding.lock().unwrap() = p;
                        }
                        None => {
                            warn!(target: "engine", "anytls: padding scheme update failed to parse");
                        }
                    }
                }
                CMD_HEART_REQUEST => {
                    // session.go:330-332.
                    let mut resp = Vec::with_capacity(HEADER_SIZE);
                    frame_into(&mut resp, CMD_HEART_RESPONSE, sid, &[]);
                    let _ = core.tx.send(WriteCmd::Bytes(resp));
                }
                CMD_SERVER_SETTINGS => {
                    // session.go:337-352 — record the peer version.
                    let text = String::from_utf8_lossy(&data).into_owned();
                    if let Some(v) = text.split('\n').find_map(|l| l.strip_prefix("v=")) {
                        if let Ok(v) = v.trim().parse::<u32>() {
                            core.peer_version.store(v, Ordering::Relaxed);
                        }
                    }
                }
                // cmdSettings is client→server; cmdSYN is server-only
                // reception; cmdHeartResponse is unimplemented upstream
                // too; unknown commands consume their payload (upstream
                // would desync — see the module delta notes).
                _ => {}
            }
        }

        // Pull more wire bytes, or observe a session kill.
        let mut tmp = [0u8; 16 * 1024];
        tokio::select! {
            changed = dead_rx.changed() => {
                if changed.is_ok() && *dead_rx.borrow() {
                    break 'session;
                }
            }
            r = rd.read(&mut tmp) => match r {
                Ok(0) => {
                    core.kill("anytls: server closed the session");
                    break 'session;
                }
                Ok(n) => rbuf.extend_from_slice(&tmp[..n]),
                Err(e) => {
                    core.kill(&format!("anytls: session read error: {e}"));
                    break 'session;
                }
            },
        }
    }
}

/// Frame header off the buffer: `(cmd, sid, data_len)` once buffered.
fn parse_header(rbuf: &BytesMut) -> Option<(u8, u32, usize)> {
    if rbuf.len() < HEADER_SIZE {
        return None;
    }
    let cmd = rbuf[0];
    let sid = u32::from_be_bytes([rbuf[1], rbuf[2], rbuf[3], rbuf[4]]);
    let len = u16::from_be_bytes([rbuf[5], rbuf[6]]) as usize;
    Some((cmd, sid, len))
}

/// A live multiplexed anytls session. Cheap to clone — every clone is
/// another handle to the same session (streams, tasks and all).
#[derive(Clone)]
pub struct AnyTlsSession {
    core: Arc<SessionCore>,
}

impl AnyTlsSession {
    /// `NewClientSession` + `Run` (session.go:56-97): spawn the recv
    /// loop and buffer cmdSettings for the first stream open. `tls` must
    /// already carry the handshake AND the auth write.
    fn start(tls: BoxProxyStream) -> Self {
        let (r, w) = tokio::io::split(tls);
        let (tx, rx) = mpsc::unbounded_channel();
        let (dead, dead_rx) = watch::channel(false);
        let padding = Arc::new(StdMutex::new(
            PaddingFactory::new(DEFAULT_PADDING_SCHEME)
                .expect("the default padding scheme is well-formed"),
        ));
        let core = Arc::new(SessionCore {
            tx: tx.clone(),
            streams: StdMutex::new(HashMap::new()),
            next_sid: AtomicU32::new(0),
            active: AtomicUsize::new(0),
            dead: dead.clone(),
            dead_rx: dead_rx.clone(),
            padding: padding.clone(),
            peer_version: AtomicU32::new(0),
            die_reason: Arc::new(StdMutex::new(String::new())),
            recycle: StdMutex::new(None),
            idle_since: StdMutex::new(None),
        });
        // Run() — the settings frame is buffered (writeConn appends
        // while `buffering`), then the recv loop starts (session.go:80-97).
        let settings = format!("v=2\nclient=\npadding-md5={}", padding.lock().unwrap().md5);
        let mut settings_frame = Vec::with_capacity(HEADER_SIZE + settings.len());
        frame_into(&mut settings_frame, CMD_SETTINGS, 0, settings.as_bytes());
        let _ = tx.send(WriteCmd::Bytes(settings_frame));
        let writer = WriterState {
            conn: w,
            send_padding: true,
            pkt_counter: 0,
            buffer: Vec::new(),
            buffering: true,
            padding,
            dead,
            die_reason: core.die_reason.clone(),
        };
        tokio::spawn(writer_loop(rx, writer));
        tokio::spawn(recv_loop(r, core.clone(), dead_rx));
        AnyTlsSession { core }
    }

    /// `OpenStream` + the CreateProxy target write (session.go:135-169,
    /// client.go:55-66): a fresh stream id, `cmdSYN` + the first
    /// `cmdPSH(target socksaddr)` flushed together with the buffered
    /// settings as one padded write.
    async fn open_stream(&self, target: &NetAddr) -> Result<AnyTlsStream> {
        if self.core.is_dead() {
            return Err(Error::network("anytls: session closed"));
        }
        let sid = self.core.next_sid.fetch_add(1, Ordering::Relaxed) + 1;
        let (ev_tx, ev_rx) = mpsc::unbounded_channel();
        self.core.streams.lock().unwrap().insert(sid, ev_tx);
        let mut wire = Vec::with_capacity(HEADER_SIZE * 2 + 32);
        frame_into(&mut wire, CMD_SYN, sid, &[]);
        let mut addr = Vec::with_capacity(32);
        encode_socks_addr(&mut addr, &target.host, target.port);
        psh_frames_into(&mut wire, sid, &addr);
        let (ack_tx, ack_rx) = oneshot::channel();
        self.core
            .tx
            .send(WriteCmd::Open { frames: wire, ack: ack_tx })
            .map_err(|_| Error::network("anytls: session closed"))?;
        ack_rx
            .await
            .map_err(|_| Error::network("anytls: session closed while opening the stream"))?
            .map_err(Error::from)?;
        self.core.active.fetch_add(1, Ordering::Relaxed);
        debug!(target: "engine", sid, "anytls: stream opened toward {target}");
        Ok(AnyTlsStream {
            core: self.core.clone(),
            sid,
            rx: ev_rx,
            out: BytesMut::with_capacity(16 * 1024),
            fin: false,
            fin_sent: false,
            remote_err: None,
            flush_ack: None,
        })
    }

    /// The padding scheme's md5 currently in force (diagnostics/tests).
    pub fn padding_md5(&self) -> String {
        self.core.padding.lock().unwrap().md5.clone()
    }

    /// Whether the session has died (transport closed / alert).
    pub fn is_dead(&self) -> bool {
        self.core.is_dead()
    }

    /// Live stream count on this session.
    pub fn active_streams(&self) -> usize {
        self.core.active.load(Ordering::Relaxed)
    }

    /// `Session.Close` (session.go:110-132).
    pub fn close(&self) {
        self.core.kill("anytls: session closed locally");
    }
}

/// A client anytls stream: one sid over the shared session — mihomo
/// `Stream` (stream.go:14-38), a net.Conn over the session pipe. Reads
/// dispatch by the recv task; writes are queued to the session's
/// serialised writeConn path; `shutdown()` sends cmdFIN.
pub struct AnyTlsStream {
    core: Arc<SessionCore>,
    sid: u32,
    rx: mpsc::UnboundedReceiver<StreamEvent>,
    out: BytesMut,
    /// cmdFIN seen (or local shutdown) — clean EOF once `out` drains.
    fin: bool,
    /// cmdFIN already queued (Close → closeWithError, stream.go:63-101).
    fin_sent: bool,
    remote_err: Option<String>,
    /// Pending flush ack from the writer task.
    flush_ack: Option<oneshot::Receiver<io::Result<()>>>,
}

fn io_invalid(e: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

impl AnyTlsStream {
    /// Queue a FIN if none was sent — `closeWithError` → `streamClosed`
    /// → `cmdFIN` (stream.go:63-101, session.go:362-371).
    fn send_fin(&mut self) {
        if !self.fin_sent {
            self.fin_sent = true;
            let mut fin = Vec::with_capacity(HEADER_SIZE);
            frame_into(&mut fin, CMD_FIN, self.sid, &[]);
            let _ = self.core.tx.send(WriteCmd::Bytes(fin));
        }
    }

    /// The padding scheme md5 this stream's session currently uses.
    pub fn padding_md5(&self) -> String {
        self.core.padding.lock().unwrap().md5.clone()
    }
}

impl AsyncRead for AnyTlsStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if !this.out.is_empty() {
                let n = this.out.len().min(buf.remaining());
                buf.put_slice(&this.out[..n]);
                this.out.advance(n);
                return Poll::Ready(Ok(()));
            }
            if let Some(err) = this.remote_err.take() {
                return Poll::Ready(Err(io::Error::new(io::ErrorKind::NotConnected, err)));
            }
            if this.fin {
                return Poll::Ready(Ok(()));
            }
            match Pin::new(&mut this.rx).poll_recv(cx) {
                Poll::Ready(Some(StreamEvent::Data(d))) => {
                    this.out.extend_from_slice(&d);
                }
                Poll::Ready(Some(StreamEvent::Fin)) => {
                    this.fin = true;
                }
                Poll::Ready(Some(StreamEvent::RemoteError(m))) => {
                    this.remote_err = Some(m);
                }
                Poll::Ready(None) => {
                    // Every sender is gone: either our FIN was processed
                    // (clean EOF) or the session died (net.ErrClosed in
                    // Go — Stream.Read, stream.go:41-47).
                    if this.core.is_dead() {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::NotConnected,
                            format!("anytls: session closed: {}", this.core.death_reason()),
                        )));
                    }
                    this.fin = true;
                }
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

impl AsyncWrite for AnyTlsStream {
    /// `Stream.Write` (stream.go:50-61): the payload becomes cmdPSH
    /// frames handed to the session's serialised writeConn — one
    /// contiguous frame sequence per write, exactly like Go's
    /// writeDataFrame under connLock.
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.fin_sent {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "anytls: stream closed",
            )));
        }
        if this.core.is_dead() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                format!("anytls: session closed: {}", this.core.death_reason()),
            )));
        }
        if buf.is_empty() {
            // writeDataFrame(0) is a no-op (session.go:383-385).
            return Poll::Ready(Ok(0));
        }
        let mut frames = Vec::with_capacity(buf.len() + HEADER_SIZE);
        psh_frames_into(&mut frames, this.sid, buf);
        if this.core.tx.send(WriteCmd::Bytes(frames)).is_err() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::NotConnected,
                "anytls: session closed",
            )));
        }
        Poll::Ready(Ok(buf.len()))
    }

    /// Flush bridge: hand the writer task a Flush command and resolve
    /// when the transport accepted every queued write.
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.flush_ack.is_none() {
            let (ack_tx, ack_rx) = oneshot::channel();
            if this.core.tx.send(WriteCmd::Flush(ack_tx)).is_err() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "anytls: session closed",
                )));
            }
            this.flush_ack = Some(ack_rx);
        }
        let ack = this.flush_ack.as_mut().expect("set above");
        match ready!(Pin::new(ack).poll(cx)) {
            Ok(res) => {
                this.flush_ack = None;
                Poll::Ready(res)
            }
            Err(_) => {
                // The writer died without acking.
                this.flush_ack = None;
                Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::NotConnected,
                    "anytls: session closed during flush",
                )))
            }
        }
    }

    /// `Stream.Close` → closeWithError → cmdFIN (stream.go:63-101).
    /// Reads still drain what the peer sent before its FIN.
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.send_fin();
        this.fin = true;
        Pin::new(&mut *this).poll_flush(cx)
    }
}

impl Drop for AnyTlsStream {
    /// The stream end-of-life bookkeeping: FIN if unsent, deregister,
    /// and the dieHook — session/client.go:90-109: when the last stream
    /// ends, recycle the session to its pool; a session without a pool
    /// (one-shot) closes instead (`disableReuse` → session.Close,
    /// client.go:93-95).
    fn drop(&mut self) {
        self.send_fin();
        self.core.streams.lock().unwrap().remove(&self.sid);
        if self.core.active.fetch_sub(1, Ordering::AcqRel) == 1 {
            let recycle = self.core.recycle.lock().unwrap().clone();
            match recycle {
                Some(tx) => {
                    let _ = tx.send((self.core.clone(), Instant::now()));
                    // If the pool is gone the send fails silently; the
                    // session is then dropped by the last Arc holder.
                }
                None => self.core.kill("anytls: all streams closed"),
            }
        }
    }
}

/// The auth packet (client.go:77-97): `sha256(password) ||
/// be16(padding0) || padding0` — one TLS write, using the initial
/// scheme's `0=` entry.
fn auth_packet(padding: &PaddingFactory, password: &str) -> Result<Vec<u8>> {
    let padding0 = padding.generate(0).first().copied().unwrap_or(0);
    if padding0 < 0 || padding0 > u16::MAX as isize {
        return Err(Error::protocol("anytls: padding0 out of range"));
    }
    let mut packet = Vec::with_capacity(32 + 2 + padding0 as usize);
    packet.extend_from_slice(&Sha256::digest(password.as_bytes()));
    packet.extend_from_slice(&(padding0 as u16).to_be_bytes());
    packet.resize(32 + 2 + padding0 as usize, 0);
    Ok(packet)
}

/// Open an anytls session over an established transport and open its
/// first stream toward `target`.
///
/// Dial sequence (integrator): TCP → [`connect`] (which performs the TLS
/// handshake via [`tls_connect`], the auth packet, `cmdSettings` +
/// `cmdSYN` + first `cmdPSH(target)`), then relay. The target address is
/// the sing `SocksaddrSerializer` form (`atyp 1/3/4 || addr || port`),
/// i.e. [`crate::addr::encode_socks_addr`]. The session is one-shot:
/// when the returned stream closes, the session closes too (mihomo's
/// `disableReuse` path, session/client.go:93-95).
pub async fn connect(
    cfg: &AnyTlsOut,
    transport: BoxProxyStream,
    target: &NetAddr,
) -> Result<BoxProxyStream> {
    let session = open_session(cfg, transport).await?;
    let stream = session.open_stream(target).await?;
    Ok(Box::new(stream))
}

/// TLS + auth + session start (the parts shared by the TCP, UDP and
/// pooled entry points) — `createOutboundTLSConnection` (client.go:68-99)
/// plus `NewClientSession`/`Run`.
async fn open_session(cfg: &AnyTlsOut, transport: BoxProxyStream) -> Result<AnyTlsSession> {
    if cfg.password.is_empty() {
        return Err(Error::config("anytls: password is required"));
    }
    if cfg.ech.as_ref().is_some_and(|o| o.enable) && cfg.jls.is_some() {
        return Err(Error::config(
            "anytls: jls-opts and ech-opts both replace the TLS handshake and cannot combine",
        ));
    }
    let server_name = if cfg.sni.is_empty() {
        cfg.server.clone()
    } else {
        cfg.sni.clone()
    };
    debug!(
        target: "engine",
        server = %cfg.server, port = %cfg.port, sni = %server_name, skip_verify = cfg.skip_verify,
        "anytls: opening session"
    );
    let mut tls = if let Some(opts) = cfg.ech.as_ref().filter(|o| o.enable) {
        // ECH: the engine's own TLS 1.3 stack carries the outer/inner
        // ClientHello pair (ech-opts on anytls). Self-dialing like the
        // jls/jls-quic split upstream: ECH owns the transport.
        use base64::Engine as _;
        let list = base64::engine::general_purpose::STANDARD
            .decode(opts.config.as_bytes())
            .map_err(|e| {
                Error::config(format!("anytls ech-opts.config is not valid base64: {e}"))
            })?;
        let selection = crate::proto::ech::select_ech_config(&list)?;
        let ech_cfg = crate::proto::reality::tls13::EchCfg::new(
            server_name.clone(),
            crate::proto::reality::UtslProfile::Chrome,
            selection,
        );
        let auth = crate::proto::reality::tls13::ServerAuth::WebPki {
            roots: std::sync::Arc::new(crate::proto::reality::stream::root_store()?),
            server_name: server_name.clone(),
        };
        let dial_server = cfg.server.clone();
        let dial_port = cfg.port;
        Box::new(
            crate::proto::reality::tls13::connect_ech(&ech_cfg, &auth, move || {
                let server = dial_server.clone();
                Box::pin(async move {
                    let tcp = tokio::net::TcpStream::connect((server.as_str(), dial_port))
                        .await
                        .map_err(|e| {
                            Error::network(format!("dial {server}:{dial_port}: {e}"))
                        })?;
                    Ok(Box::new(tcp) as BoxProxyStream)
                })
            })
            .await?,
        )
    } else if let Some(user) = &cfg.jls {
        crate::proto::jls::connect(
            &crate::proto::jls::JlsOut {
                username: user.username.clone(),
                password: user.password.clone(),
                sni: server_name.clone(),
                alpn: Vec::new(),
                skip_cert_verify: cfg.skip_verify,
                fingerprint: None,
            },
            transport,
        )
        .await?
    } else {
        tls_connect(
            transport,
            &server_name,
            &TlsSettings {
                enabled: true,
                server_name: Some(server_name.clone()),
                skip_cert_verify: cfg.skip_verify,
                alpn: Vec::new(),
            },
        )
        .await?
    };

    // Auth (client.go:77-97): one TLS write before anything else.
    let auth = auth_packet(
        &PaddingFactory::new(DEFAULT_PADDING_SCHEME).expect("default scheme is well-formed"),
        &cfg.password,
    )?;
    tls.write_all(&auth).await?;
    tls.flush().await?;
    // NewClientSession + Run: buffer cmdSettings, start the loops.
    Ok(AnyTlsSession::start(tls))
}

// ---------------------------------------------------------------------------
// UDP over anytls (sing uot v2)
// ---------------------------------------------------------------------------

/// The magic uot v2 destination (`uot.MagicAddress`, protocol.go:15).
const UOT_MAGIC_ADDRESS: &str = "sp.v2.udp-over-tcp.arpa";

/// Append a uot packet address (uot `AddrParser`, protocol.go:19-23):
/// atyp `0x00`=IPv4, `0x01`=IPv6, `0x02`=Fqdn, then the port be16.
/// (Note: NOT the SocksaddrSerializer atyp set.)
fn uot_addr_into(out: &mut Vec<u8>, host: &Host, port: u16) {
    match host {
        Host::Domain(d) => {
            out.push(0x02);
            out.push(d.len().min(255) as u8);
            out.extend_from_slice(&d.as_bytes()[..d.len().min(255)]);
        }
        Host::Ip(std::net::IpAddr::V4(v4)) => {
            out.push(0x00);
            out.extend_from_slice(&v4.octets());
        }
        Host::Ip(std::net::IpAddr::V6(v6)) => {
            out.push(0x01);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&port.to_be_bytes());
}

/// A UDP-over-anytls packet stream (uot v2, non-connect mode): the first
/// outbound datagram carries `[isConnect=0x00][socksaddr target]`
/// (uot `EncodeRequest`), then every datagram is
/// `uot-addr || be16 len || payload` (uot conn.go `WritePacket`).
pub struct AnyTlsUdp {
    stream: BoxProxyStream,
    request_written: bool,
}

impl AnyTlsUdp {
    /// Send one datagram toward `target`.
    pub async fn send_to(&mut self, target: &NetAddr, payload: &[u8]) -> Result<()> {
        let len = u16::try_from(payload.len())
            .map_err(|_| Error::protocol("anytls: udp datagram exceeds 65535 bytes"))?;
        let mut packet = Vec::with_capacity(96 + payload.len());
        if !self.request_written {
            // uot.EncodeRequest: isConnect(0x00=false) || Socksaddr target.
            packet.push(0x00);
            encode_socks_addr(&mut packet, &target.host, target.port);
            self.request_written = true;
        }
        uot_addr_into(&mut packet, &target.host, target.port);
        packet.extend_from_slice(&len.to_be_bytes());
        packet.extend_from_slice(payload);
        self.stream.write_all(&packet).await?;
        self.stream.flush().await?;
        Ok(())
    }

    /// Receive one datagram; returns its origin and the length written
    /// to `buf`.
    pub async fn recv_from(&mut self, buf: &mut [u8]) -> Result<(NetAddr, usize)> {
        // Address: 1 atyp (+4/16/+1+len), then port, then len+payload.
        let atyp = self.read_exact_n(1).await?[0];
        let addr: Vec<u8> = match atyp {
            0x00 => self.read_exact_n(4).await?,
            0x01 => self.read_exact_n(16).await?,
            0x02 => {
                let len = self.read_exact_n(1).await?[0] as usize;
                self.read_exact_n(len).await?
            }
            _ => return Err(Error::protocol("anytls: bad uot address type")),
        };
        let port = u16::from_be_bytes(
            self.read_exact_n(2).await?.try_into().expect("two bytes"),
        );
        let len = u16::from_be_bytes(
            self.read_exact_n(2).await?.try_into().expect("two bytes"),
        ) as usize;
        if buf.len() < len {
            return Err(Error::protocol("anytls: uot read: short buffer"));
        }
        let payload = self.read_exact_n(len).await?;
        let host = match atyp {
            0x00 => {
                let mut o = [0u8; 4];
                o.copy_from_slice(&addr);
                Host::Ip(std::net::IpAddr::V4(o.into()))
            }
            0x01 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(&addr);
                Host::Ip(std::net::IpAddr::V6(o.into()))
            }
            _ => Host::Domain(String::from_utf8_lossy(&addr).into_owned()),
        };
        buf[..len].copy_from_slice(&payload);
        Ok((NetAddr::new(host, port), len))
    }

    async fn read_exact_n(&mut self, n: usize) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; n];
        self.stream.read_exact(&mut buf).await?;
        Ok(buf)
    }
}

/// Open a UDP-over-anytls stream: an anytls session whose stream targets
/// the uot v2 magic domain (adapter/outbound/anytls.go
/// `ListenPacketContext` → `uot.RequestDestination(2)`).
pub async fn udp_stream(cfg: &AnyTlsOut, transport: BoxProxyStream) -> Result<AnyTlsUdp> {
    let session = open_session(cfg, transport).await?;
    let target = NetAddr::domain(UOT_MAGIC_ADDRESS, 0)?;
    let stream = session.open_stream(&target).await?;
    Ok(AnyTlsUdp {
        stream: Box::new(stream),
        request_written: false,
    })
}

// ---------------------------------------------------------------------------
// Idle session pool (transport/anytls/session/client.go)
// ---------------------------------------------------------------------------

/// A boxed transport dial — the pool's session factory input. The
/// default dials plain TCP to `(server, port)`; tests and integrators
/// inject obfs/TLS-fronted dialers.
pub type AnyTlsDialFuture =
    Pin<Box<dyn std::future::Future<Output = Result<BoxProxyStream>> + Send>>;
pub type AnyTlsTransportDialer = Arc<dyn Fn() -> AnyTlsDialFuture + Send + Sync>;

async fn dial_tcp(server: &str, port: u16) -> Result<BoxProxyStream> {
    let tcp = tokio::net::TcpStream::connect((server, port))
        .await
        .map_err(|e| Error::network(format!("dial {server}:{port}: {e}")))?;
    Ok(Box::new(tcp))
}

struct AnyTlsPoolCore {
    cfg: AnyTlsOut,
    dialer: AnyTlsTransportDialer,
    /// Every usable session (live or idle), newest first — the
    /// `sessions` map plus the `idleSession` skiplist in one list
    /// ordered like the skiplist (`MaxUint64-seq`, newest first).
    sessions: StdMutex<VecDeque<Arc<SessionCore>>>,
    recycle_tx: mpsc::UnboundedSender<RecycledSession>,
    /// The receiver side, under an async lock (only drained at
    /// connect/cleanup points).
    recycle_rx: tokio::sync::Mutex<mpsc::UnboundedReceiver<RecycledSession>>,
    /// Idle policy as atomics so a constructed pool can still be
    /// retuned (with_idle_policy) while the janitor task runs; the
    /// janitor re-reads them every round.
    idle_timeout_ms: AtomicU64,
    /// Atomic millis so the janitor re-reads the interval every round
    /// (with_idle_policy may retune a constructed-but-unshared pool).
    check_interval_ms: AtomicU64,
    min_idle: AtomicUsize,
    /// Streams a single session may carry before the pool prefers a
    /// fresh one. Upstream's client is strictly one-stream-per-session
    /// (`CreateStream` only takes idle sessions, client.go:75-84);
    /// the engine default allows multiplexing.
    max_streams: AtomicUsize,
}

impl AnyTlsPoolCore {
    /// Fold every recycled session back into the list
    /// (`stream.dieHook` → idleSession.Insert, client.go:103-106).
    async fn drain_recycles(&self) {
        let mut rx = self.recycle_rx.lock().await;
        while let Ok((core, since)) = rx.try_recv() {
            if core.is_dead() {
                continue;
            }
            *core.idle_since.lock().unwrap() = Some(since);
            let mut sessions = self.sessions.lock().unwrap();
            sessions.retain(|s| !Arc::ptr_eq(s, &core));
            sessions.push_front(core); // newest first (MaxUint64-seq)
        }
    }

    /// `idleCleanupExpTime` (client.go:175-206): newest first, keep live
    /// sessions, keep the `min_idle` newest idle ones (refreshing their
    /// idle clock), close the expired rest.
    fn cleanup(&self) {
        let idle_timeout =
            Duration::from_millis(self.idle_timeout_ms.load(Ordering::Relaxed).max(1));
        let min_idle = self.min_idle.load(Ordering::Relaxed);
        let mut sessions = self.sessions.lock().unwrap();
        let mut kept = 0usize; // sessions kept this round (activeCount)
        let mut i = 0;
        while i < sessions.len() {
            let s = &sessions[i];
            if s.active.load(Ordering::Relaxed) > 0 || s.is_dead() {
                i += 1;
                continue;
            }
            let since = *s.idle_since.lock().unwrap();
            let Some(since) = since else {
                i += 1;
                continue;
            };
            if since.elapsed() < idle_timeout {
                kept += 1;
                i += 1;
                continue;
            }
            if kept < min_idle {
                // Keep it around another round (client.go:192-196).
                *s.idle_since.lock().unwrap() = Some(Instant::now());
                kept += 1;
                i += 1;
                continue;
            }
            let s = sessions.remove(i).expect("indexed above");
            debug!(target: "engine", "anytls: closing expired idle session");
            s.kill("anytls: idle session expired");
        }
    }
}

/// The anytls session pool — mihomo `session.Client`
/// (session/client.go): idle-session reuse, per-session stream
/// multiplexing, idle expiry and `min-idle` keep-alive.
///
/// Upstream behaviour notes (all ported):
///
/// * `CreateStream` (client.go:64-112) reuses an idle session before
///   dialing; on stream end the session returns to the idle set
///   (`stream.dieHook`). Where upstream's client strictly takes only
///   *idle* sessions (one active stream each), this pool additionally
///   opens further streams on a live session until `max_streams`
///   (`with_max_streams(1)` restores upstream's exact behaviour).
/// * `idleCleanup` (client.go:171-206) runs every
///   `idle-session-check-interval` (30s default) closing sessions idle
///   longer than `idle-session-timeout` (30s default), always keeping
///   `min-idle-session` (0 default).
/// * A dead/closed session is skipped and the next dial opens a fresh
///   one (`getIdleSession`/`createSession`, client.go:114-151).
#[derive(Clone)]
pub struct AnyTlsSessionPool {
    core: Arc<AnyTlsPoolCore>,
}

impl AnyTlsSessionPool {
    /// A pool dialing plain TCP to `cfg.server:cfg.port` with mihomo's
    /// default idle policy — 30s check interval and 30s timeout (the
    /// clamps of session/client.go:50-55 applied to the config
    /// defaults), min-idle 0.
    pub fn new(cfg: AnyTlsOut) -> Result<Self> {
        let server = cfg.server.clone();
        let port = cfg.port;
        Self::with_dialer(cfg, move || {
            let server = server.clone();
            Box::pin(async move { dial_tcp(&server, port).await })
        })
    }

    /// A pool whose raw transports come from `dialer` (the TLS+auth
    /// layer is applied per session, like `createOutboundTLSConnection`
    /// wrapping `dialer.DialContext`).
    pub fn with_dialer(
        cfg: AnyTlsOut,
        dialer: impl Fn() -> AnyTlsDialFuture + Send + Sync + 'static,
    ) -> Result<Self> {
        if cfg.password.is_empty() {
            return Err(Error::config("anytls: password is required"));
        }
        let (recycle_tx, recycle_rx) = mpsc::unbounded_channel();
        let pool = AnyTlsSessionPool {
            core: Arc::new(AnyTlsPoolCore {
                cfg,
                dialer: Arc::new(dialer),
                sessions: StdMutex::new(VecDeque::new()),
                recycle_tx,
                recycle_rx: tokio::sync::Mutex::new(recycle_rx),
                idle_timeout_ms: AtomicU64::new(30_000),
                check_interval_ms: AtomicU64::new(30_000),
                min_idle: AtomicUsize::new(0),
                max_streams: AtomicUsize::new(usize::MAX),
            }),
        };
        pool.spawn_janitor();
        Ok(pool)
    }

    fn spawn_janitor(&self) {
        if tokio::runtime::Handle::try_current().is_err() {
            // No runtime: cleanup degrades to the lazy drain at every
            // connect (expiry then happens on use, like snell's pool).
            return;
        }
        let weak = Arc::downgrade(&self.core);
        tokio::spawn(async move {
            loop {
                let interval = {
                    // Scope the strong ref: holding it across the sleep
                    // would pin the pool forever.
                    let Some(core) = weak.upgrade() else { break };
                    let interval = Duration::from_millis(
                        core.check_interval_ms.load(Ordering::Relaxed).max(1),
                    );
                    core.drain_recycles().await;
                    core.cleanup();
                    interval
                };
                tokio::time::sleep(interval).await;
            }
        });
    }

    /// Exact idle policy (mihomo clamps values ≤ 5s to 30s inside
    /// `NewClient`, session/client.go:50-55; this builder takes the
    /// values verbatim so embedders and tests can use short timers).
    pub fn with_idle_policy(
        self,
        check_interval: Duration,
        idle_timeout: Duration,
        min_idle: usize,
    ) -> Self {
        self.core
            .check_interval_ms
            .store(check_interval.as_millis() as u64, Ordering::Relaxed);
        self.core
            .idle_timeout_ms
            .store(idle_timeout.as_millis() as u64, Ordering::Relaxed);
        self.core.min_idle.store(min_idle, Ordering::Relaxed);
        self
    }

    /// Cap the streams per session (`1` reproduces upstream's
    /// one-stream-per-session client).
    pub fn with_max_streams(self, max_streams: usize) -> Self {
        self.core
            .max_streams
            .store(max_streams.max(1), Ordering::Relaxed);
        self
    }

    /// Sessions currently held (live + idle), for observability.
    pub fn session_count(&self) -> usize {
        self.core.sessions.lock().unwrap().len()
    }

    /// Open a stream toward `target` — `CreateStream` +
    /// `CreateProxy` (session/client.go:64-112, client.go:55-66).
    /// Reuses an idle session, else a live one under capacity, else
    /// dials a fresh session.
    pub async fn connect(&self, target: &NetAddr) -> Result<BoxProxyStream> {
        self.core.drain_recycles().await;
        let candidate = {
            let sessions = self.core.sessions.lock().unwrap();
            let mut idle: Option<Arc<SessionCore>> = None;
            let mut live: Option<(usize, Arc<SessionCore>)> = None;
            for s in sessions.iter() {
                if s.is_dead() {
                    continue;
                }
                let active = s.active.load(Ordering::Relaxed);
                if active == 0 {
                    // getIdleSession — the newest idle session wins
                    // (skiplist pops the front, client.go:114-123).
                    idle = Some(s.clone());
                    break;
                }
                if active < self.core.max_streams.load(Ordering::Relaxed)
                    && live.as_ref().is_none_or(|(a, _)| active < *a)
                {
                    live = Some((active, s.clone()));
                }
            }
            idle.or(live.map(|(_, s)| s))
        };
        let session = match candidate {
            Some(core) => AnyTlsSession { core },
            None => {
                // createSession (client.go:125-151).
                let transport = (self.core.dialer)().await?;
                let session = open_session(&self.core.cfg, transport).await?;
                let mut sessions = self.core.sessions.lock().unwrap();
                sessions.retain(|s| !s.is_dead());
                sessions.push_front(session.core.clone()); // newest first
                session
            }
        };
        if session.core.is_dead() {
            return Err(Error::network("anytls: session closed before dial"));
        }
        // dieHook registration (client.go:90-109).
        *session.core.recycle.lock().unwrap() = Some(self.core.recycle_tx.clone());
        let stream = session.open_stream(target).await?;
        Ok(Box::new(stream))
    }

    /// `Client.Close` (client.go:153-169): close every session.
    pub async fn close(&self) {
        self.core.drain_recycles().await;
        let sessions: Vec<_> = self.core.sessions.lock().unwrap().drain(..).collect();
        for s in sessions {
            s.kill("anytls: pool closed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    use std::sync::Arc;

    use rustls::crypto::ring as ring_provider;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

    fn test_password() -> String {
        format!("pw-{:016x}", rand::random::<u64>())
    }

    fn test_cfg(password: &str) -> AnyTlsOut {
        AnyTlsOut {
            server: "127.0.0.1".into(),
            port: 0,
            password: password.into(),
            sni: "anytls.test".into(),
            skip_verify: true,
            udp: true,
            jls: None,
            ech: None,
        }
    }

    // ---------------------------------------------------------- padding

    #[test]
    fn default_padding_scheme_sizes() {
        let p = PaddingFactory::new(DEFAULT_PADDING_SCHEME).unwrap();
        assert_eq!(p.stop, 8);
        // "0=30-30" — the fixed auth padding.
        assert_eq!(p.generate(0), vec![30]);
        // "1=100-400" — half-open range.
        let one = p.generate(1);
        assert_eq!(one.len(), 1);
        assert!((100..400).contains(&one[0]), "{one:?}");
        // "2=400-500,c,500-1000,c,..." — sizes interleaved with checks.
        let two = p.generate(2);
        assert_eq!(two.len(), 9);
        assert!((400..500).contains(&two[0]));
        assert_eq!(two[1], CHECK_MARK);
        assert!((500..1000).contains(&two[2]));
        assert_eq!(two[3], CHECK_MARK);
        assert_eq!(two[7], CHECK_MARK);
        assert!((500..1000).contains(&two[8]));
        // "3=9-9,500-1000".
        let three = p.generate(3);
        assert_eq!(three[0], 9);
        assert!((500..1000).contains(&three[1]));
        // "4".."7" each one 500-1000 size; 8+ undefined → empty.
        for pkt in 4..8 {
            assert_eq!(p.generate(pkt).len(), 1);
        }
        assert!(p.generate(8).is_empty());
        // The md5 matches an independent hex digest of the raw scheme.
        assert_eq!(p.md5, format!("{:x}", Md5::digest(DEFAULT_PADDING_SCHEME)));
    }

    #[test]
    fn padding_scheme_update_rules() {
        // A server-pushed scheme replaces the factory (padding.go:34-40).
        let custom = b"stop=2\n0=10-10\n1=77-77".as_slice();
        let p = PaddingFactory::new(custom).unwrap();
        assert_eq!(p.stop, 2);
        assert_eq!(p.generate(0), vec![10]);
        assert_eq!(p.generate(1), vec![77]);
        // No stop line → rejected.
        assert!(PaddingFactory::new(b"0=30-30").is_none());
        // Malformed range entries are skipped, not fatal (padding.go:66-77).
        let sloppy = b"stop=3\n1=5-abc,200-200,x".as_slice();
        let p = PaddingFactory::new(sloppy).unwrap();
        assert_eq!(p.generate(1), vec![200]);
    }

    #[test]
    fn frame_layouts() {
        // Session frame: cmd || sid be32 || len be16 || data (frame.go).
        let mut out = Vec::new();
        frame_into(&mut out, CMD_SETTINGS, 0, b"v=2");
        assert_eq!(
            out,
            vec![CMD_SETTINGS, 0, 0, 0, 0, 0, 3, b'v', b'=', b'2']
        );
        // cmdWaste frame: zeroed payload (session.go:482-486).
        assert_eq!(&waste_frame(3)[..HEADER_SIZE], &[CMD_WASTE, 0, 0, 0, 0, 0, 3]);
        assert_eq!(&waste_frame(3)[HEADER_SIZE..], &[0, 0, 0]);
        // PSH frames split at 0xFFFF.
        let mut out = Vec::new();
        psh_frames_into(&mut out, 1, &vec![7u8; MAX_FRAME_DATA + 5]);
        assert_eq!(out.len(), HEADER_SIZE * 2 + MAX_FRAME_DATA + 5);
        assert_eq!(u16::from_be_bytes([out[5], out[6]]) as usize, MAX_FRAME_DATA);
        let second = HEADER_SIZE + MAX_FRAME_DATA; // start of frame 2
        assert_eq!(out[second], CMD_PSH);
        assert_eq!(u16::from_be_bytes([out[second + 5], out[second + 6]]), 5);
    }

    #[test]
    fn uot_address_encoding() {
        // uot AddrParser atyps: 0x00 IPv4, 0x01 IPv6, 0x02 Fqdn
        // (protocol.go:19-23) — NOT the socks 1/3/4 set.
        let mut out = Vec::new();
        uot_addr_into(&mut out, &Host::Ip("1.2.3.4".parse().unwrap()), 53);
        assert_eq!(out, vec![0x00, 1, 2, 3, 4, 0, 53]);
        let mut out = Vec::new();
        uot_addr_into(&mut out, &Host::Domain("dns.example".into()), 53);
        assert_eq!(
            out,
            vec![0x02, 11, b'd', b'n', b's', b'.', b'e', b'x', b'a', b'm', b'p', b'l', b'e', 0, 53]
        );
    }

    // ------------------------------------------------- server mimic

    fn server_tls_config() -> Arc<rustls::ServerConfig> {
        let certified = rcgen::generate_simple_self_signed(vec!["anytls.test".to_string()])
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

    /// One decrypted session frame off the TLS stream.
    async fn read_frame(tls: &mut tokio_rustls::server::TlsStream<DuplexStream>) -> Result<(u8, u32, Vec<u8>)> {
        let mut header = [0u8; HEADER_SIZE];
        tokio::time::timeout(Duration::from_secs(10), tls.read_exact(&mut header))
            .await
            .expect("frame header timeout")?;
        let len = u16::from_be_bytes([header[5], header[6]]) as usize;
        let mut data = vec![0u8; len];
        tokio::time::timeout(Duration::from_secs(10), tls.read_exact(&mut data))
            .await
            .expect("frame data timeout")?;
        Ok((
            header[0],
            u32::from_be_bytes([header[1], header[2], header[3], header[4]]),
            data,
        ))
    }

    /// The anytls server mimic: auth check, settings/SYN/PSH validation,
    /// optional padding update, then echo behavior.
    struct MimicOptions {
        password: String,
        /// Send cmdUpdatePaddingScheme with this raw scheme (if set).
        push_scheme: Option<&'static [u8]>,
    }

    async fn anytls_server_mimic(io: DuplexStream, opts: MimicOptions) -> Result<()> {
        let acceptor = tokio_rustls::TlsAcceptor::from(server_tls_config());
        let mut tls = acceptor.accept(io).await.map_err(Error::from)?;

        // Auth: sha256(password) || be16(pad0) || pad0 (protocol.md).
        let mut auth = vec![0u8; 32 + 2];
        tokio::time::timeout(Duration::from_secs(10), tls.read_exact(&mut auth))
            .await
            .expect("auth timeout")?;
        let expect: Vec<u8> = Sha256::digest(opts.password.as_bytes()).to_vec();
        if &auth[..32] != expect.as_slice() {
            // Upstream: close (or decoy HTTP) on auth failure.
            return Ok(());
        }
        let padding0 = u16::from_be_bytes([auth[32], auth[33]]) as usize;
        let mut zeros = vec![0u8; padding0];
        if padding0 > 0 {
            tls.read_exact(&mut zeros).await?;
        }

        // Settings — must arrive before SYN (server rejects otherwise).
        let (cmd, sid, data) = read_frame(&mut tls).await?;
        assert_eq!(cmd, CMD_SETTINGS);
        assert_eq!(sid, 0);
        let settings = String::from_utf8_lossy(&data).into_owned();
        assert!(settings.contains("v=2"), "{settings}");
        assert!(settings.contains("padding-md5="), "{settings}");
        let client_md5 = settings
            .split('\n')
            .find_map(|l| l.strip_prefix("padding-md5="))
            .expect("padding-md5 entry");

        if let Some(scheme) = opts.push_scheme {
            let scheme_md5 = format!("{:x}", Md5::digest(scheme));
            if scheme_md5 != client_md5 {
                let mut frame = Vec::new();
                frame_into(&mut frame, CMD_UPDATE_PADDING, 0, scheme);
                tls.write_all(&frame).await?;
            }
        }
        // v2 servers answer with cmdServerSettings.
        let mut frame = Vec::new();
        frame_into(&mut frame, CMD_SERVER_SETTINGS, 0, b"v=2");
        tls.write_all(&frame).await?;

        // SYN + first PSH(target).
        let (cmd, sid, _) = read_frame(&mut tls).await?;
        assert_eq!((cmd, sid), (CMD_SYN, 1));
        let (cmd, sid, data) = read_frame(&mut tls).await?;
        assert_eq!((cmd, sid), (CMD_PSH, 1));
        let target = crate::addr::decode_socks_addr(&data).unwrap().0;

        // SYNACK: success (no data).
        let mut frame = Vec::new();
        frame_into(&mut frame, CMD_SYNACK, 1, &[]);
        tls.write_all(&frame).await?;

        if target.host == Host::Domain("sp.v2.udp-over-tcp.arpa".into()) {
            // UDP mode. Reassemble PSH payloads frame by frame (padding
            // cmdWaste tails are transparent at this layer), then parse
            // the lazy uot request (`[isConnect=0x00][socksaddr]`) and
            // the packet (`uot-addr || be16 len || payload`).
            let mut stream = Vec::new();
            loop {
                let (cmd, sid, data) = read_frame(&mut tls).await?;
                if cmd == CMD_WASTE {
                    continue;
                }
                assert_eq!((cmd, sid), (CMD_PSH, 1), "unexpected frame in udp stream");
                stream.extend_from_slice(&data);
                if let Some(parsed) = parse_uot_stream(&stream) {
                    assert_eq!(parsed.is_connect, 0x00, "anytls uses non-connect uot");
                    assert_eq!(
                        parsed.target,
                        NetAddr::domain("dns.example", 53).unwrap()
                    );
                    assert_eq!(parsed.payload, b"uot-query".to_vec());
                    // Echo one response packet from 8.8.4.4:53.
                    let mut resp = Vec::new();
                    uot_addr_into(&mut resp, &Host::Ip("8.8.4.4".parse().unwrap()), 53);
                    resp.extend_from_slice(&(parsed.payload.len() as u16).to_be_bytes());
                    resp.extend_from_slice(&parsed.payload);
                    let mut frame = Vec::new();
                    psh_frames_into(&mut frame, 1, &resp);
                    tls.write_all(&frame).await?;
                    tls.flush().await?;
                    return Ok(());
                }
            }
        } else {
            assert_eq!(target, NetAddr::domain("echo.example", 443).unwrap());
            // TCP mode: echo every PSH payload, then FIN.
            loop {
                let (cmd, sid, data) = match read_frame(&mut tls).await {
                    Ok(f) => f,
                    Err(_) => return Ok(()),
                };
                match cmd {
                    CMD_PSH if sid == 1 => {
                        let mut frame = Vec::new();
                        psh_frames_into(&mut frame, 1, &data);
                        tls.write_all(&frame).await?;
                        tls.flush().await?;
                    }
                    CMD_FIN if sid == 1 => {
                        let mut frame = Vec::new();
                        frame_into(&mut frame, CMD_FIN, 1, &[]);
                        tls.write_all(&frame).await?;
                        tls.flush().await?;
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }
    }

    /// A fully-buffered uot request + packet (`Some` once complete).
    struct UotPacket {
        is_connect: u8,
        target: NetAddr,
        payload: Vec<u8>,
    }

    fn parse_uot_stream(bytes: &[u8]) -> Option<UotPacket> {
        let (&is_connect, mut rest) = bytes.split_first()?;
        // Socksaddr (sing SocksaddrSerializer: atyp 1/4/3, addr, port).
        let (&atyp, addr_rest) = rest.split_first()?;
        let (host, used) = match atyp {
            0x01 => {
                let o: [u8; 4] = addr_rest.get(..4)?.try_into().ok()?;
                (Host::Ip(std::net::IpAddr::V4(o.into())), 1 + 4)
            }
            0x04 => {
                let o: [u8; 16] = addr_rest.get(..16)?.try_into().ok()?;
                (Host::Ip(std::net::IpAddr::V6(o.into())), 1 + 16)
            }
            0x03 => {
                let &len = addr_rest.first()?;
                let d = addr_rest.get(1..1 + len as usize)?;
                (
                    Host::Domain(String::from_utf8_lossy(d).into_owned()),
                    1 + 1 + len as usize,
                )
            }
            _ => return None,
        };
        rest = rest.get(used..)?;
        let port = u16::from_be_bytes([*rest.first()?, *rest.get(1)?]);
        rest = rest.get(2..)?;
        // uot packet: uot-addr (0x00/0x01/0x02) then port, len, payload.
        let (&uot_atyp, uot_rest) = rest.split_first()?;
        let uot_used = match uot_atyp {
            0x00 => 1 + 4,
            0x01 => 1 + 16,
            0x02 => {
                let &len = uot_rest.first()?;
                1 + 1 + len as usize
            }
            _ => return None,
        };
        rest = rest.get(uot_used + 2..)?; // skip uot addr + port
        let len = u16::from_be_bytes([*rest.first()?, *rest.get(1)?]) as usize;
        let payload = rest.get(2..2 + len)?;
        Some(UotPacket {
            is_connect,
            target: NetAddr::new(host, port),
            payload: payload.to_vec(),
        })
    }

    async fn spawn_mimic(opts: MimicOptions) -> DuplexStream {
        let (client, server) = tokio::io::duplex(256 * 1024);
        tokio::spawn(async move {
            if let Err(e) = anytls_server_mimic(server, opts).await {
                panic!("anytls mimic failed: {e}");
            }
        });
        client
    }

    // ------------------------------------------------------- loopbacks

    #[tokio::test]
    async fn auth_settings_and_echo_loopback() {
        let password = test_password();
        let cfg = test_cfg(&password);
        let transport = spawn_mimic(MimicOptions {
            password: password.clone(),
            push_scheme: None,
        })
        .await;
        let target = NetAddr::domain("echo.example", 443).unwrap();
        let mut stream = connect(&cfg, Box::new(transport), &target).await.unwrap();

        stream.write_all(b"ping-anytls").await.unwrap();
        let mut buf = [0u8; 11];
        read_timeout(&mut stream, &mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-anytls");

        // A larger payload spans multiple PSH frames.
        let payload: Vec<u8> = (0..70 * 1024).map(|i| (i % 251) as u8).collect();
        stream.write_all(&payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(20), stream.read_exact(&mut got))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, payload);

        // Shutdown → cmdFIN → server FIN → clean EOF.
        stream.shutdown().await.unwrap();
        let mut tail = [0u8; 8];
        let n = read_timeout(&mut stream, &mut tail).await.unwrap();
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn padding_scheme_negotiation() {
        let password = test_password();
        let cfg = test_cfg(&password);
        let scheme: &'static [u8] = b"stop=2\n0=10-10\n1=42-42";
        let transport = spawn_mimic(MimicOptions {
            password,
            push_scheme: Some(scheme),
        })
        .await;
        let target = NetAddr::domain("echo.example", 443).unwrap();
        // Drive the session directly so the adopted scheme is observable.
        let session = open_session(&cfg, Box::new(transport)).await.unwrap();
        let mut stream = session.open_stream(&target).await.unwrap();
        // Read something so the cmdUpdatePaddingScheme frame is consumed.
        stream.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        read_timeout(&mut stream, &mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        // The client adopted the server's scheme (session.go:315-329).
        assert_eq!(stream.padding_md5(), format!("{:x}", Md5::digest(scheme)));
    }

    #[tokio::test]
    async fn udp_uot_roundtrip() {
        let password = test_password();
        let cfg = test_cfg(&password);
        let transport = spawn_mimic(MimicOptions {
            password,
            push_scheme: None,
        })
        .await;
        let mut udp = udp_stream(&cfg, Box::new(transport)).await.unwrap();
        let target = NetAddr::domain("dns.example", 53).unwrap();
        udp.send_to(&target, b"uot-query").await.unwrap();
        let mut buf = [0u8; 64];
        let (addr, n) = tokio::time::timeout(Duration::from_secs(10), udp.recv_from(&mut buf))
            .await
            .expect("uot response timeout")
            .unwrap();
        assert_eq!(addr.host, Host::Ip("8.8.4.4".parse().unwrap()));
        assert_eq!(addr.port, 53);
        assert_eq!(&buf[..n], b"uot-query");
    }

    #[tokio::test]
    async fn wrong_password_gets_closed() {
        let password = test_password();
        let cfg = test_cfg(&format!("wrong-{password}"));
        let transport = spawn_mimic(MimicOptions {
            password,
            push_scheme: None,
        })
        .await;
        let target = NetAddr::domain("echo.example", 443).unwrap();
        // The server drops the conn right after the bad hash. The open
        // write may fail eagerly (OpenStream's writeControlFrame errors
        // the same way in Go) — either way, no tunnel data.
        let mut stream = match connect(&cfg, Box::new(transport), &target).await {
            Ok(s) => s,
            Err(e) => {
                assert!(
                    e.to_string().contains("session")
                        || e.to_string().contains("broken pipe")
                        || e.to_string().contains("close_notify"),
                    "unexpected error: {e}"
                );
                return;
            }
        };
        let _ = stream.write_all(b"ping").await; // may fail or buffer
        let mut buf = [0u8; 16];
        match read_timeout(&mut stream, &mut buf).await {
            Ok(0) => {}
            Ok(_) => panic!("a wrong password must not produce data"),
            // The mimic drops the TCP connection; rustls reports the
            // missing TLS close_notify, the session surfaces the death.
            Err(e) => assert!(
                e.to_string().contains("close_notify")
                    || e.to_string().contains("session closed")
                    || e.to_string().contains("broken pipe"),
                "{e}"
            ),
        }
    }

    #[tokio::test]
    async fn empty_password_rejected() {
        let cfg = AnyTlsOut {
            password: String::new(),
            ..test_cfg("x")
        };
        let err = match connect(&cfg, Box::new(tokio::io::duplex(64).0), &NetAddr::domain("a.b", 80).unwrap()).await {
            Ok(_) => panic!("an empty password must be rejected"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("password"), "{err}");
    }

    // ------------------------------------------------------ session pool

    /// Multi-stream anytls server mimic for the pool tests: the TLS +
    /// auth + settings handshake once per session, then any number of
    /// streams — cmdSYN registers the sid (first cmdPSH is the target,
    /// later ones echo), cmdFIN echoes FIN. `close_after_all_streams`
    /// drops the TLS conn once every stream ended (forces the pool's
    /// fresh-dial path).
    async fn anytls_pool_mimic(io: DuplexStream, opts: PoolMimicOptions) -> Result<()> {
        let acceptor = tokio_rustls::TlsAcceptor::from(server_tls_config());
        let mut tls = acceptor.accept(io).await.map_err(Error::from)?;
        let mut auth = vec![0u8; 32 + 2];
        read_frame_timeout(&mut tls, &mut auth).await?;
        if &auth[..32] != Sha256::digest(opts.password.as_bytes()).as_slice() {
            return Ok(());
        }
        let padding0 = u16::from_be_bytes([auth[32], auth[33]]) as usize;
        if padding0 > 0 {
            let mut zeros = vec![0u8; padding0];
            read_frame_timeout(&mut tls, &mut zeros).await?;
        }
        let (cmd, sid, data) = read_frame(&mut tls).await?;
        assert_eq!((cmd, sid), (CMD_SETTINGS, 0));
        let _ = data;
        let mut frame = Vec::new();
        frame_into(&mut frame, CMD_SERVER_SETTINGS, 0, b"v=2");
        tls.write_all(&frame).await?;

        let mut streams: HashMap<u32, Option<NetAddr>> = HashMap::new();
        loop {
            let (cmd, sid, data) = match read_frame(&mut tls).await {
                Ok(f) => f,
                Err(_) => return Ok(()),
            };
            match cmd {
                CMD_SYN => {
                    assert!(streams.insert(sid, None).is_none(), "sid {sid} reused");
                    let mut frame = Vec::new();
                    frame_into(&mut frame, CMD_SYNACK, sid, &[]);
                    tls.write_all(&frame).await?;
                }
                CMD_PSH => {
                    let entry = streams
                        .get_mut(&sid)
                        .unwrap_or_else(|| panic!("PSH for unknown sid {sid}"));
                    if entry.is_none() {
                        let (target, consumed) = crate::addr::decode_socks_addr(&data).unwrap();
                        assert_eq!(consumed, data.len(), "first PSH is the whole target");
                        *entry = Some(target);
                        continue; // the address frame itself is not echoed
                    }
                    let mut frame = Vec::new();
                    psh_frames_into(&mut frame, sid, &data);
                    tls.write_all(&frame).await?;
                    tls.flush().await?;
                }
                CMD_FIN => {
                    assert!(streams.remove(&sid).is_some(), "FIN for unknown sid {sid}");
                    let mut frame = Vec::new();
                    frame_into(&mut frame, CMD_FIN, sid, &[]);
                    tls.write_all(&frame).await?;
                    tls.flush().await?;
                    if opts.close_after_all_streams && streams.is_empty() {
                        return Ok(()); // drop the TLS conn
                    }
                }
                CMD_WASTE => {}
                other => panic!("unexpected frame {other} sid {sid}"),
            }
        }
    }

    struct PoolMimicOptions {
        password: String,
        close_after_all_streams: bool,
    }

    /// read_exact with the suite's timeout (auth reads land in pieces).
    async fn read_frame_timeout(
        tls: &mut tokio_rustls::server::TlsStream<DuplexStream>,
        buf: &mut [u8],
    ) -> Result<()> {
        tokio::time::timeout(Duration::from_secs(10), tls.read_exact(buf))
            .await
            .expect("mimic read timeout")?;
        Ok(())
    }

    /// A pool whose dialer spawns a fresh mimic per session, counting
    /// dials.
    fn pool_with_mimic(
        cfg: &AnyTlsOut,
        close_after_all_streams: bool,
    ) -> (AnyTlsSessionPool, Arc<std::sync::atomic::AtomicUsize>) {
        let counter = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let counter2 = counter.clone();
        let password = cfg.password.clone();
        let pool = AnyTlsSessionPool::with_dialer(cfg.clone(), move || {
            let counter = counter2.clone();
            let password = password.clone();
            let close = close_after_all_streams;
            Box::pin(async move {
                counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                let (client, server) = tokio::io::duplex(256 * 1024);
                let opts = PoolMimicOptions {
                    password,
                    close_after_all_streams: close,
                };
                tokio::spawn(async move {
                    if let Err(e) = anytls_pool_mimic(server, opts).await {
                        panic!("anytls pool mimic failed: {e}");
                    }
                });
                // The pool applies the TLS layer per session
                // (open_session); hand it the raw duplex.
                Ok(Box::new(client) as BoxProxyStream)
            })
        })
        .unwrap();
        (pool, counter)
    }

    fn dial_count(counter: &Arc<std::sync::atomic::AtomicUsize>) -> usize {
        counter.load(std::sync::atomic::Ordering::Relaxed)
    }

    #[tokio::test]
    async fn pool_two_targets_share_one_session() {
        // Both streams multiplex over ONE session: one dial, distinct
        // sids, independent relay (session.go OpenStream/recvLoop).
        let password = test_password();
        let cfg = test_cfg(&password);
        let (pool, counter) = pool_with_mimic(&cfg, false);
        let t1 = NetAddr::domain("one.example", 443).unwrap();
        let t2 = NetAddr::domain("two.example", 80).unwrap();
        let mut s1 = pool.connect(&t1).await.unwrap();
        let mut s2 = pool.connect(&t2).await.unwrap();
        assert_eq!(dial_count(&counter), 1, "one session serves both");
        assert_eq!(pool.session_count(), 1);

        s1.write_all(b"stream-one").await.unwrap();
        s2.write_all(b"stream-two").await.unwrap();
        let mut b1 = [0u8; 10];
        let mut b2 = [0u8; 10];
        s1.flush().await.unwrap();
        s2.flush().await.unwrap();
        read_timeout(&mut s1, &mut b1).await.unwrap();
        read_timeout(&mut s2, &mut b2).await.unwrap();
        assert_eq!(&b1, b"stream-one");
        assert_eq!(&b2, b"stream-two");
        // Concurrent large transfers on both streams stay independent.
        let payload: Vec<u8> = (0..70 * 1024).map(|i| (i % 251) as u8).collect();
        let moved = payload.clone();
        let echo = tokio::spawn(async move {
            let mut got = vec![0u8; moved.len()];
            s2.write_all(&moved).await.unwrap();
            s2.read_exact(&mut got).await.unwrap();
            got
        });
        let mut got1 = vec![0u8; payload.len()];
        s1.write_all(&payload).await.unwrap();
        s1.read_exact(&mut got1).await.unwrap();
        let got2 = tokio::time::timeout(Duration::from_secs(20), echo)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got1, payload);
        assert_eq!(got2, payload);
    }

    #[tokio::test]
    async fn pool_recycles_idle_session() {
        // Stream end → dieHook → the session parks in the idle set;
        // the next connect reuses it (client.go:90-112) with a fresh
        // stream id (no second dial).
        let password = test_password();
        let cfg = test_cfg(&password);
        let (pool, counter) = pool_with_mimic(&cfg, false);
        let target = NetAddr::domain("echo.example", 443).unwrap();
        {
            let mut s = pool.connect(&target).await.unwrap();
            s.write_all(b"first").await.unwrap();
            let mut buf = [0u8; 5];
            read_timeout(&mut s, &mut buf).await.unwrap();
            assert_eq!(&buf, b"first");
        } // drop → FIN → recycle
        tokio::time::sleep(Duration::from_millis(50)).await;
        {
            let mut s = pool.connect(&target).await.unwrap();
            s.write_all(b"secnd").await.unwrap();
            let mut buf = [0u8; 5];
            read_timeout(&mut s, &mut buf).await.unwrap();
            assert_eq!(&buf, b"secnd");
        }
        assert_eq!(dial_count(&counter), 1, "the idle session was reused");
    }

    #[tokio::test]
    async fn pool_dials_fresh_when_session_dies() {
        // The server closes the session after the first stream; the
        // next connect must open a fresh one (getIdleSession skips
        // dead sessions, createSession dials).
        let password = test_password();
        let cfg = test_cfg(&password);
        let (pool, counter) = pool_with_mimic(&cfg, true);
        let target = NetAddr::domain("echo.example", 443).unwrap();
        {
            let mut s = pool.connect(&target).await.unwrap();
            s.write_all(b"only").await.unwrap();
            let mut buf = [0u8; 4];
            let _ = read_timeout(&mut s, &mut buf).await;
            let _ = s.shutdown().await;
        }
        tokio::time::sleep(Duration::from_millis(100)).await; // the mimic drops the TLS conn
        let mut s = pool.connect(&target).await.unwrap();
        s.write_all(b"next").await.unwrap();
        let mut buf = [0u8; 4];
        read_timeout(&mut s, &mut buf).await.unwrap();
        assert_eq!(&buf, b"next");
        assert_eq!(dial_count(&counter), 2, "a fresh session was dialed");
    }

    #[tokio::test]
    async fn pool_idle_expiry_closes_sessions() {
        // idleCleanup (client.go:171-206): an idle session past
        // idle-session-timeout is closed; the next connect dials fresh.
        let password = test_password();
        let cfg = test_cfg(&password);
        let (pool, counter) = pool_with_mimic(&cfg, false);
        let pool = pool.with_idle_policy(Duration::from_millis(60), Duration::from_millis(120), 0);
        let target = NetAddr::domain("echo.example", 443).unwrap();
        {
            let mut s = pool.connect(&target).await.unwrap();
            s.write_all(b"one").await.unwrap();
            let mut buf = [0u8; 3];
            read_timeout(&mut s, &mut buf).await.unwrap();
        }
        tokio::time::sleep(Duration::from_millis(400)).await; // janitor rounds pass
        assert_eq!(pool.session_count(), 0, "the idle session expired");
        let mut s = pool.connect(&target).await.unwrap();
        s.write_all(b"two").await.unwrap();
        let mut buf = [0u8; 3];
        read_timeout(&mut s, &mut buf).await.unwrap();
        assert_eq!(&buf, b"two");
        assert_eq!(dial_count(&counter), 2, "expiry forced a fresh dial");
    }

    #[tokio::test]
    async fn pool_max_streams_one_matches_upstream() {
        // Upstream's client only ever takes IDLE sessions
        // (client.go:75-84), so two concurrent streams mean two
        // sessions; with_max_streams(1) reproduces that exactly.
        let password = test_password();
        let cfg = test_cfg(&password);
        let (pool, counter) = pool_with_mimic(&cfg, false);
        let pool = pool.with_max_streams(1);
        let t1 = NetAddr::domain("one.example", 443).unwrap();
        let t2 = NetAddr::domain("two.example", 80).unwrap();
        let mut s1 = pool.connect(&t1).await.unwrap();
        let mut s2 = pool.connect(&t2).await.unwrap();
        s1.write_all(b"a").await.unwrap();
        s2.write_all(b"b").await.unwrap();
        let mut b1 = [0u8; 1];
        let mut b2 = [0u8; 1];
        read_timeout(&mut s1, &mut b1).await.unwrap();
        read_timeout(&mut s2, &mut b2).await.unwrap();
        assert_eq!(&b1, b"a");
        assert_eq!(&b2, b"b");
        assert_eq!(dial_count(&counter), 2, "one stream per session");
    }

    #[tokio::test]
    async fn pool_close_kills_sessions() {
        // Client.Close (client.go:153-169).
        let password = test_password();
        let cfg = test_cfg(&password);
        let (pool, _counter) = pool_with_mimic(&cfg, false);
        let target = NetAddr::domain("echo.example", 443).unwrap();
        let s = pool.connect(&target).await.unwrap();
        assert_eq!(pool.session_count(), 1);
        pool.close().await;
        assert_eq!(pool.session_count(), 0);
        // The held stream sees the session death on its next read.
        let mut s = s;
        let mut buf = [0u8; 8];
        match read_timeout(&mut s, &mut buf).await {
            Ok(0) => {}
            Ok(_) => panic!("a closed session must not deliver data"),
            Err(e) => assert!(e.to_string().contains("session closed"), "{e}"),
        }
    }

    async fn read_timeout(stream: &mut (impl AsyncRead + Unpin), buf: &mut [u8]) -> io::Result<usize> {
        tokio::time::timeout(Duration::from_secs(10), stream.read(buf))
            .await
            .expect("anytls read timed out")
    }
}
