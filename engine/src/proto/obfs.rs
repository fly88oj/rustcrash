//! simple-obfs client wrappers (http/tls obfuscation for Shadowsocks).
//!
//! Faithful port of mihomo's `transport/simple-obfs` client:
//! `http.go` (request head, response head stripping), `http_server.go`
//! (response head shape), `tls.go` (fake ClientHello, record framing,
//! response parsing) and `tls_server.go` (fake ServerHello +
//! ChangeCipherSpec prefix the client has to skip).
//!
//! # Layering
//!
//! mihomo wraps the transport in
//! `adapter/outbound/shadowsocks.go::StreamConnContext` *before*
//! `StreamConn` applies the Shadowsocks cipher, so both constructors here
//! take the dialed TCP (or TLS) stream and return a stream the SS layer is
//! built on top of: the first Shadowsocks write — salt plus encrypted
//! address header — is what rides the fake request / fake ClientHello.
//!
//! # Wire behaviour
//!
//! - `http`: the first payload write emits
//!   `GET <uri> HTTP/1.1` with `Host`, a `curl/7.x.y` user agent,
//!   `Connection: Upgrade` / `Upgrade: websocket`, a random
//!   `Sec-Websocket-Key` and `Content-Length`, then the payload as the
//!   request body; later writes go out raw. The first response read strips
//!   everything through the terminating `\r\n\r\n` (the head may span
//!   reads) and passes the remaining bytes through.
//! - `tls`: the first payload chunk (at most [`TLS_CHUNK_SIZE`], upstream's
//!   `chunkSize = 1 << 14`) is embedded in a fake ClientHello whose SNI is
//!   `settings.host`; later chunks are wrapped in `17 03 03 <len16>`
//!   records (upstream `tls.go::write`). The first response read skips the
//!   102-byte fake ServerHello + ChangeCipherSpec prefix and parses the
//!   record framing of every server record; upstream's `read()` discards
//!   105 bytes then a 2-byte big-endian length on the first read and 3
//!   bytes then a 2-byte length afterwards — de-framing the same wire
//!   layout.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use base64::Engine;
use bytes::{Buf, BytesMut};
use rand::{Rng, RngCore};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::{Error, Result};
use crate::stream::BoxProxyStream;

/// Upstream `tls.go` `chunkSize = 1 << 14`: the window of the first payload
/// that rides inside the fake ClientHello, and the per-record cap after it.
const TLS_CHUNK_SIZE: usize = 1 << 14;

/// Fake ServerHello record (5 + 91 bytes) + ChangeCipherSpec record (6
/// bytes) that the obfs server writes before its first data record.
const TLS_RESPONSE_PREFIX: usize = 102;

/// Sanity cap while accumulating a response head in `http` mode.
const MAX_HTTP_HEAD: usize = 16 * 1024;

/// Path shapes used when `ObfsSettings::path` is unset. Upstream mihomo
/// always sends `/` (its URL is `http://<host>/`) and the C simple-obfs
/// defaults `obfs-uri` to `/`; we keep the same shape while randomizing.
const REQUEST_PATHS: [&str; 4] = ["/", "/index.html", "/index.php", "/search"];

/// simple-obfs client settings (`plugin: obfs`, `plugin-opts: {mode, host}`).
#[derive(Debug, Clone)]
pub struct ObfsSettings {
    /// `obfs-host`: the HTTP `Host:` header / TLS-SNI-looking name. mihomo
    /// defaults this to `bing.com`; must be non-empty, at most 255 bytes and
    /// free of CR/LF.
    pub host: String,
    /// Shadowsocks server port, used for the HTTP `Host:` header (`:80` is
    /// dropped), mirroring mihomo's `NewHTTPObfs(conn, host, port)`.
    pub port: u16,
    /// Explicit request path (the C client's `obfs-uri`, default `/`).
    /// `None` picks a random path from the same shapes.
    pub path: Option<String>,
}

impl ObfsSettings {
    /// Settings with the upstream defaults for `path` (random).
    pub fn new(host: impl Into<String>, port: u16) -> Self {
        ObfsSettings {
            host: host.into(),
            port,
            path: None,
        }
    }

    fn validate(&self) -> Result<()> {
        if self.host.is_empty() {
            return Err(Error::config(
                "obfs: host must not be empty (mihomo defaults to bing.com)",
            ));
        }
        if self.host.len() > 255 {
            return Err(Error::config("obfs: host must be at most 255 bytes"));
        }
        let injects = |s: &str| s.contains('\r') || s.contains('\n');
        if injects(&self.host) || self.path.as_deref().is_some_and(injects) {
            return Err(Error::config("obfs: host/path must not contain CR or LF"));
        }
        Ok(())
    }

    /// The `Host:` header value: `host` plus `:port` unless the port is 80.
    fn host_header(&self) -> String {
        if self.port == 80 {
            self.host.clone()
        } else {
            format!("{}:{}", self.host, self.port)
        }
    }

    /// Request path for the fake request line.
    fn request_uri(&self) -> String {
        match &self.path {
            Some(p) if p.starts_with('/') => p.clone(),
            Some(p) => format!("/{p}"),
            None => random_request_uri(),
        }
    }
}

/// `/` plus a short random alphanumeric token, or one of the common root
/// paths — the shapes upstream uses in the request line.
fn random_request_uri() -> String {
    const ALNUM: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
    let mut rng = rand::rngs::OsRng;
    if rng.gen_ratio(1, 2) {
        let len = rng.gen_range(4..=8);
        let mut uri = String::with_capacity(1 + len);
        uri.push('/');
        for _ in 0..len {
            uri.push(ALNUM[rng.gen_range(0..ALNUM.len())] as char);
        }
        uri
    } else {
        REQUEST_PATHS[rng.gen_range(0..REQUEST_PATHS.len())].to_string()
    }
}

// ---------------------------------------------------------------------------
// http
// ---------------------------------------------------------------------------

/// Build the fake request head (upstream `http.go::Write`). Go emits the
/// request line, `Host`, `User-Agent`, `Content-Length`, then the remaining
/// headers sorted, so `Connection` precedes `Sec-Websocket-Key` (Go's
/// canonical spelling) and `Upgrade`. The first payload write is the body.
fn http_request_head(settings: &ObfsSettings, body_len: usize) -> String {
    let mut key = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut key);
    let key = base64::engine::general_purpose::URL_SAFE.encode(key);
    let (major, minor) = {
        let mut rng = rand::rngs::OsRng;
        (rng.gen_range(0..54), rng.gen_range(0..2))
    };
    format!(
        "GET {uri} HTTP/1.1\r\n\
         Host: {host}\r\n\
         User-Agent: curl/7.{major}.{minor}\r\n\
         Content-Length: {body_len}\r\n\
         Connection: Upgrade\r\n\
         Sec-Websocket-Key: {key}\r\n\
         Upgrade: websocket\r\n\
         \r\n",
        uri = settings.request_uri(),
        host = settings.host_header(),
    )
}

/// http obfs write state (upstream `http.go`): the head rides the first
/// payload write, later writes are raw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HttpWriteState {
    /// No head on the wire yet: the next non-empty write carries it.
    PreHead,
    /// Head (plus its body) queued for the transport.
    Emitting,
    /// Head sent: later writes pass straight through.
    Raw,
}

/// Client-side http obfs stream over the dialed transport.
struct HttpObfsStream {
    inner: BoxProxyStream,
    settings: ObfsSettings,
    wbuf: BytesMut,
    /// Caller bytes currently baked into `wbuf`.
    pending: usize,
    wstate: HttpWriteState,
    /// Leftover payload after the stripped response head.
    rbuf: BytesMut,
    head_done: bool,
}

impl HttpObfsStream {
    fn poll_read_inner(
        &mut self,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if self.head_done {
                if !self.rbuf.is_empty() {
                    let n = self.rbuf.len().min(dst.remaining());
                    dst.put_slice(&self.rbuf[..n]);
                    self.rbuf.advance(n);
                    return Poll::Ready(Ok(()));
                }
                return Pin::new(&mut self.inner).poll_read(cx, dst);
            }

            // The response head may span reads; accumulate until the blank
            // line that ends it (upstream only inspects its first read).
            let mut tmp = [0u8; 8 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
            if rb.filled().is_empty() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "obfs http: transport closed inside the response head",
                )));
            }
            self.rbuf.extend_from_slice(rb.filled());

            if let Some(pos) = self.rbuf.windows(4).position(|w| w == b"\r\n\r\n") {
                if !self.rbuf.starts_with(b"HTTP/") {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "obfs http: malformed response head",
                    )));
                }
                self.rbuf.advance(pos + 4);
                self.head_done = true;
                continue;
            }
            if self.rbuf.len() > MAX_HTTP_HEAD {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "obfs http: response head exceeds 16 KiB without a terminator",
                )));
            }
        }
    }
}

impl AsyncWrite for HttpObfsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.wbuf.is_empty() {
            match this.wstate {
                HttpWriteState::Raw => return Pin::new(&mut this.inner).poll_write(cx, buf),
                HttpWriteState::PreHead => {
                    if buf.is_empty() {
                        return Poll::Ready(Ok(0));
                    }
                    let take = buf.len().min(TLS_CHUNK_SIZE);
                    let head = http_request_head(&this.settings, take);
                    let mut out = Vec::with_capacity(head.len() + take);
                    out.extend_from_slice(head.as_bytes());
                    out.extend_from_slice(&buf[..take]);
                    this.wbuf = BytesMut::from(&out[..]);
                    this.pending = take;
                    this.wstate = HttpWriteState::Emitting;
                }
                // Pending retry: the framed unit is already queued.
                HttpWriteState::Emitting => {}
            }
        }
        while !this.wbuf.is_empty() {
            let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.wbuf))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "obfs http: transport accepted zero bytes",
                )));
            }
            this.wbuf.advance(n);
        }
        this.wstate = HttpWriteState::Raw;
        Poll::Ready(Ok(std::mem::take(&mut this.pending)))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let _ = this.poll_drain(cx);
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl HttpObfsStream {
    /// Flush any queued head bytes to the transport.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.wbuf.is_empty() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.wbuf))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "obfs http: transport accepted zero bytes",
                )));
            }
            self.wbuf.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncRead for HttpObfsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_read_inner(cx, buf)
    }
}

/// Wrap a dialed transport with the http obfs client (mihomo
/// `NewHTTPObfs`), for use *below* the Shadowsocks stream.
pub async fn http_obfs_client(
    transport: BoxProxyStream,
    settings: &ObfsSettings,
) -> Result<BoxProxyStream> {
    settings.validate()?;
    tracing::debug!(
        target: "engine",
        "obfs http client wrapping transport (host {})",
        settings.host_header()
    );
    Ok(Box::new(HttpObfsStream {
        inner: transport,
        settings: settings.clone(),
        wbuf: BytesMut::new(),
        pending: 0,
        wstate: HttpWriteState::PreHead,
        rbuf: BytesMut::with_capacity(16 * 1024),
        head_done: false,
    }))
}

// ---------------------------------------------------------------------------
// tls
// ---------------------------------------------------------------------------

/// Seconds since the Unix epoch for the fake hello's random timestamp.
/// Upstream stamps it from NTP-adjusted time (`ntp.Now()`); the local clock
/// is used here.
fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Fake ClientHello carrying `data` (the first payload window) in a fake
/// `session_ticket` extension, with `host` as SNI. Byte-for-byte port of
/// upstream `tls.go::makeClientHelloMsg`; the three length fields are
/// derived from the buffered window, exactly as upstream computes them only
/// once the first payload is known.
fn client_hello(data: &[u8], host: &str) -> Vec<u8> {
    const CIPHER_SUITES: [u8; 56] = [
        0xc0, 0x2c, 0xc0, 0x30, 0x00, 0x9f, 0xcc, 0xa9, 0xcc, 0xa8, 0xcc, 0xaa, 0xc0, 0x2b, 0xc0,
        0x2f, 0x00, 0x9e, 0xc0, 0x24, 0xc0, 0x28, 0x00, 0x6b, 0xc0, 0x23, 0xc0, 0x27, 0x00, 0x67,
        0xc0, 0x0a, 0xc0, 0x14, 0x00, 0x39, 0xc0, 0x09, 0xc0, 0x13, 0x00, 0x33, 0x00, 0x9d, 0x00,
        0x9c, 0x00, 0x3d, 0x00, 0x3c, 0x00, 0x35, 0x00, 0x2f, 0x00, 0xff,
    ];
    const SIGNATURE_ALGORITHMS: [u8; 30] = [
        0x06, 0x01, 0x06, 0x02, 0x06, 0x03, 0x05, 0x01, 0x05, 0x02, 0x05, 0x03, 0x04, 0x01, 0x04,
        0x02, 0x04, 0x03, 0x03, 0x01, 0x03, 0x02, 0x03, 0x03, 0x02, 0x01, 0x02, 0x02, 0x02, 0x03,
    ];

    let mut random = [0u8; 28];
    let mut session_id = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    rand::rngs::OsRng.fill_bytes(&mut session_id);

    let data_len = data.len() as u16;
    let host_len = host.len() as u16;
    let mut hello = Vec::with_capacity(216 + data.len() + host.len());

    // handshake record: TLS 1.0 version, length
    hello.extend_from_slice(&[0x16, 0x03, 0x01]);
    hello.extend_from_slice(&(212 + data_len + host_len).to_be_bytes());
    // ClientHello, length, TLS 1.2 version
    hello.extend_from_slice(&[0x01, 0x00]);
    hello.extend_from_slice(&(208 + data_len + host_len).to_be_bytes());
    hello.extend_from_slice(&[0x03, 0x03]);
    // random with timestamp, session id
    hello.extend_from_slice(&(now_secs() as u32).to_be_bytes());
    hello.extend_from_slice(&random);
    hello.push(32);
    hello.extend_from_slice(&session_id);
    // cipher suites
    hello.extend_from_slice(&[0x00, 0x38]);
    hello.extend_from_slice(&CIPHER_SUITES);
    // compression
    hello.extend_from_slice(&[0x01, 0x00]);
    // extension length
    hello.extend_from_slice(&(79 + data_len + host_len).to_be_bytes());
    // fake session ticket extension: the buffered payload window
    hello.extend_from_slice(&[0x00, 0x23]);
    hello.extend_from_slice(&data_len.to_be_bytes());
    hello.extend_from_slice(data);
    // server name (SNI)
    hello.extend_from_slice(&[0x00, 0x00]);
    hello.extend_from_slice(&(host_len + 5).to_be_bytes());
    hello.extend_from_slice(&(host_len + 3).to_be_bytes());
    hello.push(0);
    hello.extend_from_slice(&host_len.to_be_bytes());
    hello.extend_from_slice(host.as_bytes());
    // ec_point, groups, signature algorithms, encrypt-then-mac, ext master secret
    hello.extend_from_slice(&[0x00, 0x0b, 0x00, 0x04, 0x03, 0x01, 0x00, 0x02]);
    hello.extend_from_slice(&[
        0x00, 0x0a, 0x00, 0x0a, 0x00, 0x08, 0x00, 0x1d, 0x00, 0x17, 0x00, 0x19, 0x00, 0x18,
    ]);
    hello.extend_from_slice(&[0x00, 0x0d, 0x00, 0x20, 0x00, 0x1e]);
    hello.extend_from_slice(&SIGNATURE_ALGORITHMS);
    hello.extend_from_slice(&[0x00, 0x16, 0x00, 0x00]);
    hello.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
    hello
}

/// tls obfs write state (upstream `tls.go`): the first payload window is
/// embedded in the fake ClientHello, later chunks become records.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsWriteState {
    /// No ClientHello yet: the next non-empty chunk rides the hello.
    PreHead,
    /// ClientHello queued for the transport.
    Emitting,
    /// Hello sent: chunks become `17 03 03 <len16>` records.
    Framed,
}

/// Read-side framing phase, mirroring upstream `tls.go::read`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TlsReadPhase {
    /// Fake ServerHello + ChangeCipherSpec prefix of the first response.
    ServerHello,
    /// 3-byte record prefix (content type, version) before each length.
    RecordPrefix,
    /// 2-byte big-endian record payload length.
    RecordLen,
}

/// Client-side tls obfs stream over the dialed transport.
struct TlsObfsStream {
    inner: BoxProxyStream,
    settings: ObfsSettings,
    wbuf: BytesMut,
    /// Caller bytes currently baked into `wbuf`.
    pending: usize,
    wstate: TlsWriteState,
    rbuf: BytesMut,
    phase: TlsReadPhase,
    /// Payload bytes of the current record still to hand to the caller.
    remain: usize,
}

impl TlsObfsStream {
    /// True when the stream sits exactly on a record boundary.
    fn at_frame_boundary(&self) -> bool {
        self.remain == 0
            && self.rbuf.is_empty()
            && matches!(self.phase, TlsReadPhase::ServerHello | TlsReadPhase::RecordPrefix)
    }

    /// Read more transport bytes into `rbuf`; `Ok(false)` means clean EOF.
    fn poll_fill(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<bool>> {
        let mut tmp = [0u8; 8 * 1024];
        let mut rb = ReadBuf::new(&mut tmp);
        ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
        if rb.filled().is_empty() {
            if self.at_frame_boundary() {
                return Poll::Ready(Ok(false));
            }
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "obfs tls: truncated record",
            )));
        }
        self.rbuf.extend_from_slice(rb.filled());
        Poll::Ready(Ok(true))
    }

    fn poll_read_inner(
        &mut self,
        cx: &mut Context<'_>,
        dst: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        loop {
            if dst.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            if self.remain > 0 {
                if !self.rbuf.is_empty() {
                    let n = self.remain.min(self.rbuf.len()).min(dst.remaining());
                    dst.put_slice(&self.rbuf[..n]);
                    self.rbuf.advance(n);
                    self.remain -= n;
                    return Poll::Ready(Ok(()));
                }
            } else {
                match self.phase {
                    TlsReadPhase::ServerHello => {
                        if self.rbuf.len() >= TLS_RESPONSE_PREFIX {
                            if self.rbuf[0] != 0x16 {
                                return Poll::Ready(Err(io::Error::new(
                                    io::ErrorKind::InvalidData,
                                    "obfs tls: server did not open with a hello record",
                                )));
                            }
                            self.rbuf.advance(TLS_RESPONSE_PREFIX);
                            self.phase = TlsReadPhase::RecordPrefix;
                            continue;
                        }
                    }
                    TlsReadPhase::RecordPrefix => {
                        if self.rbuf.len() >= 3 {
                            self.rbuf.advance(3);
                            self.phase = TlsReadPhase::RecordLen;
                            continue;
                        }
                    }
                    TlsReadPhase::RecordLen => {
                        if self.rbuf.len() >= 2 {
                            self.remain =
                                u16::from_be_bytes([self.rbuf[0], self.rbuf[1]]) as usize;
                            self.rbuf.advance(2);
                            self.phase = TlsReadPhase::RecordPrefix;
                            continue;
                        }
                    }
                }
            }
            if !ready!(self.poll_fill(cx))? {
                return Poll::Ready(Ok(()));
            }
        }
    }

    /// Flush any queued record bytes to the transport.
    fn poll_drain(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.wbuf.is_empty() {
            let n = ready!(Pin::new(&mut self.inner).poll_write(cx, &self.wbuf))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "obfs tls: transport accepted zero bytes",
                )));
            }
            self.wbuf.advance(n);
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for TlsObfsStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.wbuf.is_empty() {
            if buf.is_empty() {
                return Poll::Ready(Ok(0));
            }
            // Upstream chunks every write at 16384; the first window is the
            // payload the ClientHello lengths are computed from.
            let take = buf.len().min(TLS_CHUNK_SIZE);
            let mut out = Vec::with_capacity(take + 512);
            if this.wstate == TlsWriteState::PreHead {
                out.extend_from_slice(&client_hello(&buf[..take], &this.settings.host));
                this.wstate = TlsWriteState::Emitting;
            } else {
                out.extend_from_slice(&[0x17, 0x03, 0x03]);
                out.extend_from_slice(&(take as u16).to_be_bytes());
                out.extend_from_slice(&buf[..take]);
            }
            this.wbuf = BytesMut::from(&out[..]);
            this.pending = take;
        }
        while !this.wbuf.is_empty() {
            let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.wbuf))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "obfs tls: transport accepted zero bytes",
                )));
            }
            this.wbuf.advance(n);
        }
        this.wstate = TlsWriteState::Framed;
        Poll::Ready(Ok(std::mem::take(&mut this.pending)))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drain(cx))?;
        Pin::new(&mut this.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let _ = this.poll_drain(cx);
        Pin::new(&mut this.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for TlsObfsStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.poll_read_inner(cx, buf)
    }
}

/// Wrap a dialed transport with the tls obfs client (mihomo `NewTLSObfs`),
/// for use *below* the Shadowsocks stream. The tls obfs server does send a
/// fake ServerHello prefix, so the read side here skips it and de-frames
/// the server's records.
pub async fn tls_obfs_client(
    transport: BoxProxyStream,
    settings: &ObfsSettings,
) -> Result<BoxProxyStream> {
    settings.validate()?;
    tracing::debug!(
        target: "engine",
        "obfs tls client wrapping transport (sni {})",
        settings.host
    );
    Ok(Box::new(TlsObfsStream {
        inner: transport,
        settings: settings.clone(),
        wbuf: BytesMut::new(),
        pending: 0,
        wstate: TlsWriteState::PreHead,
        rbuf: BytesMut::with_capacity(16 * 1024),
        phase: TlsReadPhase::ServerHello,
        remain: 0,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
    use tokio::sync::oneshot;

    const HOST: &str = "obfs.example";

    fn settings(host: &str, port: u16) -> ObfsSettings {
        ObfsSettings::new(host, port)
    }

    fn payload(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    /// Split a captured client stream at the end of the request head.
    fn split_head(wire: &[u8]) -> (&str, &[u8]) {
        let pos = wire
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .expect("request head terminator");
        (
            std::str::from_utf8(&wire[..pos + 4]).unwrap(),
            &wire[pos + 4..],
        )
    }

    fn count(wire: &[u8], needle: &[u8]) -> usize {
        wire.windows(needle.len()).filter(|w| *w == needle).count()
    }

    /// The 102-byte fake ServerHello + ChangeCipherSpec prefix written by
    /// upstream `tls_server.go::makeServerHello` before its first record.
    fn server_hello_prefix() -> Vec<u8> {
        let mut v = Vec::with_capacity(TLS_RESPONSE_PREFIX);
        v.extend_from_slice(&[0x16, 0x03, 0x01, 0x00, 0x5b]);
        v.extend_from_slice(&[0x02, 0x00, 0x00, 0x57, 0x03, 0x03]);
        v.extend_from_slice(&7u32.to_be_bytes());
        v.extend_from_slice(&[0x11; 28]);
        v.push(32);
        v.extend_from_slice(&[0x22; 32]);
        v.extend_from_slice(&[0xcc, 0xa8, 0x00, 0x00, 0x00]);
        v.extend_from_slice(&[0xff, 0x01, 0x00, 0x01, 0x00]);
        v.extend_from_slice(&[0x00, 0x17, 0x00, 0x00]);
        v.extend_from_slice(&[0x00, 0x0b, 0x00, 0x02, 0x01, 0x00]);
        v.extend_from_slice(&[0x14, 0x03, 0x03, 0x00, 0x01, 0x01]);
        assert_eq!(v.len(), TLS_RESPONSE_PREFIX);
        v
    }

    fn record(content_type: u8, body: &[u8]) -> Vec<u8> {
        let mut v = Vec::with_capacity(body.len() + 5);
        v.extend_from_slice(&[content_type, 0x03, 0x03]);
        v.extend_from_slice(&(body.len() as u16).to_be_bytes());
        v.extend_from_slice(body);
        v
    }

    #[tokio::test]
    async fn http_first_write_carries_the_request_head_once() {
        let (client_io, mut server_io) = tokio::io::duplex(16 * 1024);
        let mut stream = http_obfs_client(Box::new(client_io), &settings(HOST, 8388))
            .await
            .unwrap();
        stream.write_all(b"hello-obfs").await.unwrap();
        stream.write_all(b"tail").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut wire = Vec::new();
        server_io.read_to_end(&mut wire).await.unwrap();

        let (head, body) = split_head(&wire);
        assert!(head.starts_with("GET /"), "request line: {head:?}");
        assert!(head.contains(" HTTP/1.1\r\n"));
        assert!(head.contains("Host: obfs.example:8388\r\n"));
        assert!(head.contains("User-Agent: curl/7."));
        assert!(head.contains("Content-Length: 10\r\n"));
        assert!(head.contains("Connection: Upgrade\r\n"));
        assert!(head.contains("Upgrade: websocket\r\n"));
        assert!(head.contains("Sec-Websocket-Key: "));
        // The first payload rides the body, later writes are raw.
        assert_eq!(body, b"hello-obfstail");
        assert_eq!(count(&wire, b"GET "), 1, "request head must be sent once");
        assert_eq!(count(&wire, b"\r\n\r\n"), 1);
    }

    #[tokio::test]
    async fn http_head_uses_settings_and_omits_port_80() {
        let (client_io, mut server_io) = tokio::io::duplex(4096);
        let mut cfg = settings(HOST, 80);
        cfg.path = Some("/assets/app.js".into());
        let mut stream = http_obfs_client(Box::new(client_io), &cfg).await.unwrap();
        stream.write_all(b"x").await.unwrap();
        stream.shutdown().await.unwrap();
        let mut wire = Vec::new();
        server_io.read_to_end(&mut wire).await.unwrap();
        let (head, _) = split_head(&wire);
        assert!(head.starts_with("GET /assets/app.js HTTP/1.1\r\n"), "{head:?}");
        assert!(head.contains("Host: obfs.example\r\n"));
        assert!(!head.contains("Host: obfs.example:80"));
    }

    #[tokio::test]
    async fn http_response_head_split_across_reads_is_stripped() {
        let (client_io, mut server_io) = tokio::io::duplex(16 * 1024);
        let mut stream = http_obfs_client(Box::new(client_io), &settings(HOST, 8388))
            .await
            .unwrap();
        // part 1 ends inside the final CRLF terminator.
        let part1: &[u8] = b"HTTP/1.1 101 Switching Protocols\r\n\
            Server: nginx/1.1.1\r\n\
            Upgrade: websocket\r\n\
            Connection: Upgrade\r\n\
            Sec-WebSocket-Accept: c29tZS1rZXk9\r\n\r";
        let part2: &[u8] = b"\npong-head-tail";
        let (ack_tx, ack_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            server_io.write_all(part1).await.unwrap();
            ack_rx.await.unwrap();
            server_io.write_all(part2).await.unwrap();
        });

        let mut out = [0u8; 14];
        let early = tokio::time::timeout(Duration::from_millis(100), stream.read_exact(&mut out));
        assert!(early.await.is_err(), "no payload before the head completes");
        ack_tx.send(()).unwrap();
        stream.read_exact(&mut out).await.unwrap();
        assert_eq!(&out, b"pong-head-tail");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn http_read_rejects_malformed_and_truncated_heads() {
        // A terminated but non-HTTP head is garbage.
        let (client_io, mut server_io) = tokio::io::duplex(4096);
        let mut stream = http_obfs_client(Box::new(client_io), &settings(HOST, 8388))
            .await
            .unwrap();
        server_io
            .write_all(b"NOT-HTTP/1.1 200 OK\r\n\r\npayload")
            .await
            .unwrap();
        let mut out = [0u8; 7];
        let err = stream.read_exact(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // A transport that closes before the head terminates is truncated.
        let (client_io, mut server_io) = tokio::io::duplex(4096);
        let mut stream = http_obfs_client(Box::new(client_io), &settings(HOST, 8388))
            .await
            .unwrap();
        server_io.write_all(b"HTTP/1.1 200 OK\r\nServer: nginx").await.unwrap();
        drop(server_io);
        let err = stream.read_exact(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn http_roundtrip_through_mimic_server() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(mimic_http_server(server_io));
        let mut stream = http_obfs_client(Box::new(client_io), &settings(HOST, 8388))
            .await
            .unwrap();

        let data = payload(20_000, 3);
        stream.write_all(&data).await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = vec![0u8; data.len()];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, data);
        drop(stream);
        server.await.unwrap();
    }

    /// Minimal server-side mimic of upstream `http_server.go`: read the
    /// request head (validating the upstream shape), read `Content-Length`
    /// body bytes, answer with a canned response head, then echo the rest
    /// of the client stream raw.
    async fn mimic_http_server(mut sock: DuplexStream) {
        let mut head = Vec::new();
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            sock.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
            assert!(head.len() <= 1024, "client sent no request head");
        }
        let head = String::from_utf8(head.clone()).unwrap();
        assert!(head.starts_with("GET /"), "{head:?}");
        assert!(head.contains(&format!("Host: {HOST}:8388\r\n")), "{head:?}");
        assert!(head.contains("Connection: Upgrade\r\n"), "{head:?}");
        assert!(head.contains("Upgrade: websocket\r\n"), "{head:?}");
        let key = head
            .lines()
            .find_map(|l| l.strip_prefix("Sec-Websocket-Key: "))
            .expect("websocket key");
        assert_eq!(key.len(), 24, "base64url of 16 bytes: {key:?}");
        let body_len: usize = head
            .lines()
            .find_map(|l| l.strip_prefix("Content-Length: "))
            .expect("content length")
            .parse()
            .unwrap();
        // The first write is capped at the upstream chunk size, so the head's
        // Content-Length is the window, not the whole 20 KiB payload.
        assert_eq!(body_len, TLS_CHUNK_SIZE);
        let mut first = vec![0u8; body_len];
        sock.read_exact(&mut first).await.unwrap();

        // The upstream server answers with a 101 head, then raw payload.
        sock.write_all(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Server: nginx/1.1.1\r\n\
              Upgrade: websocket\r\n\
              Connection: Upgrade\r\n\
              Sec-WebSocket-Accept: c29tZS1rZXk9\r\n\r\n",
        )
        .await
        .unwrap();
        sock.write_all(&first).await.unwrap();

        // Later client writes are raw: echo them unchanged.
        let mut buf = [0u8; 4096];
        loop {
            match sock.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if sock.write_all(&buf[..n]).await.is_err() {
                        break;
                    }
                }
            }
        }
    }

    #[tokio::test]
    async fn tls_client_hello_layout_matches_upstream() {
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let mut stream = tls_obfs_client(Box::new(client_io), &settings(HOST, 443))
            .await
            .unwrap();
        let data = payload(TLS_CHUNK_SIZE + 3616, 9);
        stream.write_all(&data).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut wire = Vec::new();
        server_io.read_to_end(&mut wire).await.unwrap();

        let host_len = HOST.len() as u16;
        let window = TLS_CHUNK_SIZE as u16;
        // record / handshake / extensions lengths are back-computed from the
        // buffered window (upstream emits the hello only once it is known).
        assert_eq!(&wire[..3], &[0x16, 0x03, 0x01]);
        assert_eq!(u16::from_be_bytes([wire[3], wire[4]]), 212 + window + host_len);
        assert_eq!(u16::from_be_bytes([wire[7], wire[8]]), 208 + window + host_len);
        assert_eq!(u16::from_be_bytes([wire[136], wire[137]]), 79 + window + host_len);
        // fake session ticket carries the buffered window
        assert_eq!(&wire[138..140], &[0x00, 0x23]);
        assert_eq!(u16::from_be_bytes([wire[140], wire[141]]), window);
        assert_eq!(&wire[142..142 + TLS_CHUNK_SIZE], &data[..TLS_CHUNK_SIZE]);
        // SNI = settings.host
        let sni = 142 + TLS_CHUNK_SIZE;
        assert_eq!(&wire[sni..sni + 2], &[0x00, 0x00]);
        assert_eq!(u16::from_be_bytes([wire[sni + 2], wire[sni + 3]]), host_len + 5);
        assert_eq!(u16::from_be_bytes([wire[sni + 4], wire[sni + 5]]), host_len + 3);
        assert_eq!(wire[sni + 6], 0);
        assert_eq!(u16::from_be_bytes([wire[sni + 7], wire[sni + 8]]), host_len);
        assert_eq!(&wire[sni + 9..sni + 9 + HOST.len()], HOST.as_bytes());
        // the overflow becomes one `17 03 03 <len16>` record
        let hello_len = 9 + 208 + TLS_CHUNK_SIZE + HOST.len();
        assert_eq!(&wire[hello_len..hello_len + 3], &[0x17, 0x03, 0x03]);
        assert_eq!(
            u16::from_be_bytes([wire[hello_len + 3], wire[hello_len + 4]]) as usize,
            3616
        );
        assert_eq!(&wire[hello_len + 5..], &data[TLS_CHUNK_SIZE..]);
        assert_eq!(wire.len(), hello_len + 5 + 3616);
    }

    #[tokio::test]
    async fn tls_read_strips_server_hello_and_record_framing() {
        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let mut stream = tls_obfs_client(Box::new(client_io), &settings(HOST, 443))
            .await
            .unwrap();
        let prefix = server_hello_prefix();
        let rec1 = record(0x16, b"first-record-payload");
        let rec2 = record(0x17, b"second");
        let (ack_tx, ack_rx) = oneshot::channel();
        let server = tokio::spawn(async move {
            // Split inside the fake hello, and inside a record's length field.
            server_io.write_all(&prefix[..61]).await.unwrap();
            ack_rx.await.unwrap();
            server_io.write_all(&prefix[61..]).await.unwrap();
            server_io.write_all(&rec1[..6]).await.unwrap();
            server_io.write_all(&rec1[6..]).await.unwrap();
            server_io.write_all(&rec2).await.unwrap();
        });

        let mut out = [0u8; 8];
        let early = tokio::time::timeout(Duration::from_millis(100), stream.read(&mut out));
        assert!(early.await.is_err(), "hello prefix is not payload");
        ack_tx.send(()).unwrap();
        let mut got = vec![0u8; 26];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"first-record-payloadsecond");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn tls_roundtrip_through_mimic_server() {
        let (client_io, server_io) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(mimic_tls_server(server_io, HOST));
        let mut stream = tls_obfs_client(Box::new(client_io), &settings(HOST, 443))
            .await
            .unwrap();

        let data = payload(20_000, 17);
        stream.write_all(&data).await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = vec![0u8; data.len()];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, data);
        drop(stream);
        server.await.unwrap();
    }

    /// Minimal server-side mimic of upstream `tls_server.go`: parse the
    /// fake ClientHello (payload in the session ticket extension, SNI),
    /// de-frame client records, answer with a fake ServerHello prefix plus
    /// a first record, then echo later records.
    async fn mimic_tls_server(mut sock: DuplexStream, host: &str) {
        let mut head = [0u8; 5];
        sock.read_exact(&mut head).await.unwrap();
        assert_eq!(&head[..3], &[0x16, 0x03, 0x01]);
        let record_len = u16::from_be_bytes([head[3], head[4]]) as usize;
        let mut hello = vec![0u8; record_len];
        sock.read_exact(&mut hello).await.unwrap();
        assert_eq!(u16::from_be_bytes([hello[2], hello[3]]) as usize, record_len - 4);
        assert_eq!(&hello[4..6], &[0x03, 0x03]);
        // fixed ClientHello prefix: extensions length at 131, ticket type at
        // 133, ticket (payload window) length at 135.
        assert_eq!(&hello[133..135], &[0x00, 0x23]);
        let ticket_len = u16::from_be_bytes([hello[135], hello[136]]) as usize;
        assert_eq!(
            u16::from_be_bytes([hello[131], hello[132]]) as usize,
            79 + ticket_len + host.len()
        );
        let payload = &hello[137..137 + ticket_len];
        let sni = 137 + ticket_len;
        assert_eq!(&hello[sni..sni + 2], &[0x00, 0x00]);
        let name_len = u16::from_be_bytes([hello[sni + 7], hello[sni + 8]]) as usize;
        assert_eq!(name_len, host.len());
        assert_eq!(&hello[sni + 9..sni + 9 + name_len], host.as_bytes());

        // First response: fake ServerHello prefix + the first data record.
        let mut first = server_hello_prefix();
        first.extend_from_slice(&record(0x16, payload));
        sock.write_all(&first).await.unwrap();

        // Later client chunks are `17 03 03 <len16>` records; echo each one.
        loop {
            let mut hdr = [0u8; 5];
            match sock.read_exact(&mut hdr).await {
                Ok(_) => {}
                Err(_) => break,
            }
            assert_eq!(&hdr[..3], &[0x17, 0x03, 0x03]);
            let len = u16::from_be_bytes([hdr[3], hdr[4]]) as usize;
            let mut body = vec![0u8; len];
            sock.read_exact(&mut body).await.unwrap();
            sock.write_all(&record(0x17, &body)).await.unwrap();
        }
    }

    #[tokio::test]
    async fn tls_read_rejects_non_hello_and_truncated_records() {
        // A non-TLS first byte: the "server" sent an error page.
        let (client_io, mut server_io) = tokio::io::duplex(4096);
        let mut stream = tls_obfs_client(Box::new(client_io), &settings(HOST, 443))
            .await
            .unwrap();
        server_io.write_all(&[b'H'; 512]).await.unwrap();
        let mut out = [0u8; 4];
        let err = stream.read_exact(&mut out).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);

        // Truncation in the middle of a record payload.
        let (client_io, mut server_io) = tokio::io::duplex(4096);
        let mut stream = tls_obfs_client(Box::new(client_io), &settings(HOST, 443))
            .await
            .unwrap();
        let mut wire = server_hello_prefix();
        wire.extend_from_slice(&record(0x17, b"a"));
        wire.extend_from_slice(&[0x17, 0x03, 0x03, 0x00, 0x05]); // promises 5 bytes
        server_io.write_all(&wire).await.unwrap();
        drop(server_io);
        let mut got = [0u8; 8];
        let mut read = 0;
        loop {
            match stream.read(&mut got[read..]).await {
                Ok(0) => panic!("clean EOF inside a record"),
                Ok(n) => {
                    read += n;
                    assert_eq!(read, 1, "only the single available byte arrives");
                }
                Err(e) => {
                    assert_eq!(e.kind(), io::ErrorKind::UnexpectedEof);
                    break;
                }
            }
        }
        assert_eq!(read, 1);
    }

    #[tokio::test]
    async fn settings_are_validated() {
        let (client_io, _server_io) = tokio::io::duplex(64);
        assert!(http_obfs_client(Box::new(client_io), &settings("", 80))
            .await
            .is_err());
        let (client_io, _server_io) = tokio::io::duplex(64);
        assert!(tls_obfs_client(Box::new(client_io), &settings("bad\r\nhost", 443))
            .await
            .is_err());
    }
}