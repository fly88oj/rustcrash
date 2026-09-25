//! AnyTLS outbound, ported from mihomo's `transport/anytls`
//! (`client.go`, `session/{frame.go,session.go,stream.go}`,
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
//! UDP rides the same sessions as sing-box **udp-over-tcp v2**
//! (adapter/outbound/anytls.go `ListenPacketContext` →
//! `uot.RequestDestination(2)`): the stream target is the magic domain
//! `sp.v2.udp-over-tcp.arpa`, the first packet is prefixed with the uot
//! request `[isConnect=0x00][socksaddr]`, and every datagram is
//! `uot-addr || be16 len || payload` (`uot/{protocol,conn}.go`).
//!
//! ## Deferred (out of scope here)
//!
//! * **Session reuse/multiplexing**: mihomo pools idle sessions and
//!   opens multiple streams (session/client.go). This module opens one
//!   stream (sid 1) per connect — the outbound layer owns any pooling.
//! * **Heartbeats**: `cmdHeartRequest` is answered (`cmdHeartResponse`)
//!   but never sent; the v2 SYNACK liveness watchdog is not implemented.
//! * **ALPN / client certs / fingerprint pinning / ECH / shadow-tls and
//!   restls wrappers**: `AnyTlsOut` carries only the fields below;
//!   the integrator layers extra transports before [`connect`] if
//!   needed. `client-metadata` defaults to the empty string, matching
//!   mihomo's default.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::{Buf, BytesMut};
use md5::Md5;
use rand::Rng;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
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
// The anytls client stream
// ---------------------------------------------------------------------------

/// A client anytls stream carrying one stream (sid 1) over the TLS
/// session. Reads dispatch every session command; writes apply the
/// padding scheme exactly like `Session.writeConn`.
pub struct AnyTlsStream {
    inner: BoxProxyStream,
    padding: PaddingFactory,
    /// `sendPadding` (session.go:46): false once pkt >= stop.
    send_padding: bool,
    /// `pktCounter` — one increment per actual writeConn call.
    pkt_counter: u32,
    sid: u32,
    rbuf: BytesMut,
    /// PSH payloads for our stream, pending the consumer.
    out: BytesMut,
    /// Control frames queued by the read path (heart responses).
    ctrl: VecDeque<Vec<u8>>,
    /// Wire segments pending the transport (one per padding chunk).
    wsegs: VecDeque<Vec<u8>>,
    /// `buffering` (session.go:449-455): the settings frame waits for
    /// the first stream write to flush alongside it.
    settings_buffered: Option<Vec<u8>>,
    pending_plain: usize,
    eof: bool,
    /// `cmdSYNACK` carrying an error — raised after `out` drains.
    synack_err: Option<String>,
    failed: bool,
}

impl AnyTlsStream {
    fn new(inner: BoxProxyStream) -> Self {
        AnyTlsStream {
            inner,
            padding: PaddingFactory::new(DEFAULT_PADDING_SCHEME)
                .expect("the default padding scheme is well-formed"),
            send_padding: true,
            pkt_counter: 0,
            sid: 1,
            rbuf: BytesMut::with_capacity(16 * 1024),
            out: BytesMut::with_capacity(16 * 1024),
            ctrl: VecDeque::new(),
            wsegs: VecDeque::new(),
            settings_buffered: None,
            pending_plain: 0,
            eof: false,
            synack_err: None,
            failed: false,
        }
    }

    /// The auth packet (client.go:68-98): `sha256(password) ||
    /// be16(padding0) || padding0` — one TLS write.
    fn auth_packet(&self, password: &str) -> Result<Vec<u8>> {
        let padding0 = self.padding.generate(0).first().copied().unwrap_or(0);
        if padding0 < 0 || padding0 > u16::MAX as isize {
            return Err(Error::protocol("anytls: padding0 out of range"));
        }
        let mut packet = Vec::with_capacity(32 + 2 + padding0 as usize);
        packet.extend_from_slice(&Sha256::digest(password.as_bytes()));
        packet.extend_from_slice(&(padding0 as u16).to_be_bytes());
        packet.resize(32 + 2 + padding0 as usize, 0);
        Ok(packet)
    }

    /// `writeConn` (session.go:445-519): split/pad one write into wire
    /// segments. Padding applies to the first `stop` writes only, and
    /// each segment is a separate transport write so the TLS layer sees
    /// the intended record sizes.
    fn pad_write(&mut self, b: &[u8]) -> Result<Vec<Vec<u8>>> {
        if !self.send_padding {
            return Ok(vec![b.to_vec()]);
        }
        self.pkt_counter += 1;
        if self.pkt_counter >= self.padding.stop {
            // session.go:513-515: stop padding from now on.
            self.send_padding = false;
            return Ok(vec![b.to_vec()]);
        }
        let sizes = self.padding.generate(self.pkt_counter);
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

    /// Dispatch one decrypted session frame (session.go:171-360,
    /// client side).
    fn handle_frame(&mut self, cmd: u8, sid: u32, data: &[u8]) {
        match cmd {
            CMD_PSH => {
                if sid == self.sid {
                    self.out.extend_from_slice(data);
                }
            }
            CMD_FIN => {
                if sid == self.sid {
                    self.eof = true;
                }
            }
            CMD_WASTE => {}
            CMD_SYNACK => {
                if !data.is_empty() && sid == self.sid {
                    let msg = String::from_utf8_lossy(data).into_owned();
                    self.synack_err = Some(format!("anytls: remote: {msg}"));
                }
            }
            CMD_ALERT => {
                error!(
                    target: "engine",
                    "anytls: server alert: {}",
                    String::from_utf8_lossy(data)
                );
                self.eof = true;
            }
            CMD_UPDATE_PADDING => {
                match PaddingFactory::new(data) {
                    Some(p) => {
                        debug!(target: "engine", md5 = %p.md5, "anytls: padding scheme updated");
                        self.padding = p;
                    }
                    None => {
                        warn!(target: "engine", "anytls: padding scheme update failed to parse");
                    }
                }
            }
            CMD_SERVER_SETTINGS => {
                debug!(
                    target: "engine",
                    "anytls: server settings: {}",
                    String::from_utf8_lossy(data)
                );
            }
            CMD_HEART_REQUEST => {
                let mut resp = Vec::with_capacity(HEADER_SIZE);
                frame_into(&mut resp, CMD_HEART_RESPONSE, sid, &[]);
                self.ctrl.push_back(resp);
            }
            _ => {}
        }
    }

    /// Parse every complete frame out of `rbuf`; false on a malformed
    /// header.
    fn try_parse(&mut self) -> Result<bool> {
        let mut progress = false;
        while self.rbuf.len() >= HEADER_SIZE {
            let cmd = self.rbuf[0];
            let sid = u32::from_be_bytes([self.rbuf[1], self.rbuf[2], self.rbuf[3], self.rbuf[4]]);
            let len = u16::from_be_bytes([self.rbuf[5], self.rbuf[6]]) as usize;
            if self.rbuf.len() < HEADER_SIZE + len {
                break;
            }
            self.rbuf.advance(HEADER_SIZE);
            let data = self.rbuf[..len].to_vec();
            self.rbuf.advance(len);
            self.handle_frame(cmd, sid, &data);
            progress = true;
        }
        Ok(progress)
    }
}

fn io_invalid(e: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
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
            if this.synack_err.is_some() {
                this.failed = true;
                let msg = this.synack_err.take().unwrap_or_default();
                return Poll::Ready(Err(io_invalid(Error::protocol(msg))));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            match this.try_parse().map_err(io_invalid) {
                Ok(true) => continue,
                Ok(false) => {
                    let mut tmp = [0u8; 16 * 1024];
                    let mut rb = ReadBuf::new(&mut tmp);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                    if rb.filled().is_empty() {
                        // Server closed the session (auth failure, alert,
                        // or transport death) — a clean EOF upstream.
                        this.eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    this.rbuf.extend_from_slice(rb.filled());
                }
                Err(e) => {
                    this.failed = true;
                    return Poll::Ready(Err(e));
                }
            }
        }
    }
}

impl AnyTlsStream {
    /// Drain pending wire segments (and queued control frames) to the
    /// transport.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while let Some(seg) = self.wsegs.front_mut() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, seg))?;
            if n == 0 {
                self.failed = true;
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "anytls: transport accepted zero bytes",
                )));
            }
            seg.drain(..n);
            if seg.is_empty() {
                self.wsegs.pop_front();
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for AnyTlsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.failed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "anytls: stream failed",
            )));
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        // Queued heart responses go out first (their own writeConn).
        while let Some(ctrl) = this.ctrl.pop_front() {
            let segs = this.pad_write(&ctrl).map_err(io_invalid)?;
            this.wsegs.extend(segs);
        }
        if this.wsegs.is_empty() {
            let mut frames = Vec::with_capacity(buf.len() + HEADER_SIZE);
            psh_frames_into(&mut frames, this.sid, buf);
            let segs = this.pad_write(&frames).map_err(io_invalid)?;
            this.wsegs.extend(segs);
            this.pending_plain = buf.len();
        }
        ready!(this.poll_drain(cx))?;
        Poll::Ready(Ok(this.pending_plain))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while let Some(ctrl) = this.ctrl.pop_front() {
            let segs = this.pad_write(&ctrl).map_err(io_invalid)?;
            this.wsegs.extend(segs);
        }
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.eof {
            // Stream.Close → cmdFIN (session.go:362-371).
            let mut fin = Vec::with_capacity(HEADER_SIZE);
            frame_into(&mut fin, CMD_FIN, this.sid, &[]);
            let segs = this.pad_write(&fin).map_err(io_invalid)?;
            this.wsegs.extend(segs);
            this.eof = true;
        }
        // Same drain as poll_flush, without re-borrowing self.
        while let Some(ctrl) = this.ctrl.pop_front() {
            let segs = this.pad_write(&ctrl).map_err(io_invalid)?;
            this.wsegs.extend(segs);
        }
        ready!(this.poll_drain(cx))?;
        ready!(Pin::new(&mut this.inner).poll_flush(cx))?;
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

/// Open an anytls session over an established transport and open its
/// first stream toward `target`.
///
/// Dial sequence (integrator): TCP → [`connect`] (which performs the TLS
/// handshake via [`tls_connect`], the auth packet, `cmdSettings` +
/// `cmdSYN` + first `cmdPSH(target)`), then relay. The target address is
/// the sing `SocksaddrSerializer` form (`atyp 1/3/4 || addr || port`),
/// i.e. [`crate::addr::encode_socks_addr`].
pub async fn connect(
    cfg: &AnyTlsOut,
    transport: BoxProxyStream,
    target: &NetAddr,
) -> Result<BoxProxyStream> {
    let stream = open_session(cfg, transport).await?;
    let stream = stream.open_stream(target).await?;
    Ok(Box::new(stream))
}

/// TLS + auth + buffered settings (the parts shared by the TCP and UDP
/// entry points).
async fn open_session(cfg: &AnyTlsOut, transport: BoxProxyStream) -> Result<AnyTlsStream> {
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
    let tls = if let Some(opts) = cfg.ech.as_ref().filter(|o| o.enable) {
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

    let mut stream = AnyTlsStream::new(tls);
    // 1. Auth (client.go:77-97): one TLS write.
    let auth = stream.auth_packet(&cfg.password)?;
    stream.inner.write_all(&auth).await?;
    stream.inner.flush().await?;
    // 2. cmdSettings, buffered until the first stream write (Session.Run,
    //    session.go:80-97 + the buffering flag from NewClientSession).
    let settings = format!("v=2\nclient=\npadding-md5={}", stream.padding.md5);
    let mut settings_frame = Vec::with_capacity(HEADER_SIZE + settings.len());
    frame_into(&mut settings_frame, CMD_SETTINGS, 0, settings.as_bytes());
    stream.settings_buffered = Some(settings_frame);
    Ok(stream)
}

impl AnyTlsStream {
    /// Flush the buffered settings + SYN + first PSH in one padded write
    /// (OpenStream + CreateProxy: session.go:135-169, client.go:55-66 —
    /// `s.buffering = false` only after the SYN, so the three frames
    /// share one writeConn).
    async fn open_stream(mut self, target: &NetAddr) -> Result<Self> {
        let mut wire = self.settings_buffered.take().unwrap_or_default();
        frame_into(&mut wire, CMD_SYN, self.sid, &[]);
        let mut addr = Vec::with_capacity(32);
        encode_socks_addr(&mut addr, &target.host, target.port);
        psh_frames_into(&mut wire, self.sid, &addr);
        let segs = self.pad_write(&wire)?;
        for seg in segs {
            self.inner.write_all(&seg).await?;
        }
        self.inner.flush().await?;
        debug!(target: "engine", "anytls: stream opened toward {target}");
        Ok(self)
    }
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
    let stream = open_session(cfg, transport).await?;
    let target = NetAddr::domain(UOT_MAGIC_ADDRESS, 0)?;
    let stream = stream.open_stream(&target).await?;
    Ok(AnyTlsUdp {
        stream: Box::new(stream),
        request_written: false,
    })
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
        let stream = open_session(&cfg, Box::new(transport)).await.unwrap();
        let mut stream = stream.open_stream(&target).await.unwrap();
        // Read something so the cmdUpdatePaddingScheme frame is consumed.
        stream.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        read_timeout(&mut stream, &mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        // The client adopted the server's scheme (session.go:315-329).
        assert_eq!(stream.padding.md5, format!("{:x}", Md5::digest(scheme)));
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
        // connect() itself succeeds (mihomo too — auth failure surfaces at
        // relay time): the server simply closes after the bad hash.
        let mut stream = connect(&cfg, Box::new(transport), &target)
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 16];
        match read_timeout(&mut stream, &mut buf).await {
            Ok(0) => {}
            Ok(_) => panic!("a wrong password must not produce data"),
            // The mimic drops the TCP connection; rustls reports the
            // missing TLS close_notify as an error. Either way: no data.
            Err(e) => assert!(e.to_string().contains("close_notify"), "{e}"),
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

    async fn read_timeout(stream: &mut (impl AsyncRead + Unpin), buf: &mut [u8]) -> io::Result<usize> {
        tokio::time::timeout(Duration::from_secs(10), stream.read(buf))
            .await
            .expect("anytls read timed out")
    }
}
