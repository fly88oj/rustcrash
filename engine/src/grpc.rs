//! Minimal HTTP/2 client carrying gRPC for the v2ray "gun" transport.
//!
//! One connection carries exactly one gRPC stream: `POST /{service}/Tun`,
//! the method xray/v2ray gun servers and sing-box's v2raygrpc client dial.
//! The caller performs TCP and TLS themselves (ALPN must negotiate "h2");
//! this module speaks the HTTP/2 framing, HPACK (with huffman decoding on
//! the receive side) and the length-prefixed gRPC message envelope, and
//! exposes the tunnel as a plain [`AsyncRead`] + [`AsyncWrite`] byte
//! stream, mirroring the WebSocket transport in `transport.rs`.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use bytes::{Buf, BufMut, BytesMut};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::error::{Error, Result};
use crate::stream::BoxProxyStream;

/// v2ray gRPC (gun) transport settings.
#[derive(Debug, Clone)]
pub struct GrpcSettings {
    /// gRPC service name (`TunService` by convention); requests target
    /// `/{service_name}/Tun`.
    pub service_name: String,
    /// `:authority` override (defaults to the dial host).
    pub host: Option<String>,
}

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const FT_DATA: u8 = 0x0;
const FT_HEADERS: u8 = 0x1;
const FT_RST_STREAM: u8 = 0x3;
const FT_SETTINGS: u8 = 0x4;
const FT_PUSH_PROMISE: u8 = 0x5;
const FT_PING: u8 = 0x6;
const FT_GOAWAY: u8 = 0x7;
const FT_WINDOW_UPDATE: u8 = 0x8;
const FT_CONTINUATION: u8 = 0x9;

const FLAG_END_STREAM: u8 = 0x1;
const FLAG_ACK: u8 = 0x1;
const FLAG_END_HEADERS: u8 = 0x4;
const FLAG_PADDED: u8 = 0x8;
const FLAG_PRIORITY: u8 = 0x20;

/// The single h2 stream this transport opens.
const STREAM_ID: u32 = 1;
const DEFAULT_WINDOW: i64 = 65_535;
/// Connection-level receive window we maintain (stream window stays at the
/// 64 KiB default and is replenished per ~32 KiB consumed).
const CONN_WINDOW: i64 = 1 << 20;
/// Frames we send never exceed the default max frame size (16384), which is
/// the minimum every server must accept.
const MAX_FRAME: usize = 16_384;
/// Cap on a reassembled header block (HEADERS + CONTINUATIONs).
const MAX_HEADER_BLOCK: usize = 64 * 1024;
/// Send backlog bound: beyond this, `poll_write` awaits flow-control credit.
const MAX_SEND_BACKLOG: usize = 1 << 20;
/// One gRPC message per `poll_write` chunk, kept small like the ws frame cap.
const WRITE_CHUNK: usize = 16 * 1024;
/// Guard against malicious inbound message lengths.
const MAX_MESSAGE: usize = 16 << 20;

/// Perform the HTTP/2 + gRPC handshake over an already-established transport
/// (TCP + TLS with ALPN "h2" is the caller's job) and return a bidirectional
/// byte stream tunneled inside the gRPC `Tun` RPC.
///
/// Fails if the server answers with a non-200 `:status`.
pub async fn grpc_connect(
    transport: BoxProxyStream,
    settings: &GrpcSettings,
    default_host: &str,
) -> Result<BoxProxyStream> {
    let service = settings.service_name.trim_matches('/');
    if service.is_empty() {
        return Err(Error::config("grpc: empty service name"));
    }
    let host = settings
        .host
        .clone()
        .unwrap_or_else(|| default_host.to_string());
    let path = format!("/{service}/Tun");
    let block = hpack::encode(&[
        (":method", "POST"),
        (":scheme", "https"),
        (":authority", host.as_str()),
        (":path", path.as_str()),
        ("content-type", "application/grpc"),
        ("te", "trailers"),
        ("user-agent", "rustcrash-grpc"),
    ]);

    let mut conn = H2Conn::new(transport);
    conn.out.put_slice(PREFACE);
    put_frame(&mut conn.out, FT_SETTINGS, 0, 0, &[]);
    let conn_bump = (CONN_WINDOW - DEFAULT_WINDOW) as u32;
    put_frame(
        &mut conn.out,
        FT_WINDOW_UPDATE,
        0,
        0,
        &conn_bump.to_be_bytes(),
    );
    put_frame(
        &mut conn.out,
        FT_HEADERS,
        FLAG_END_HEADERS,
        STREAM_ID,
        &block,
    );
    conn.flush_out().await?;

    while !conn.got_response {
        conn.drain_frames()?;
        if conn.got_response {
            break;
        }
        if conn.fill().await? == 0 {
            return Err(Error::protocol("grpc: EOF before response headers"));
        }
    }
    // Push acks (SETTINGS/PING) queued while we were waiting.
    conn.flush_out().await?;

    Ok(Box::new(GrpcStream {
        conn,
        sendq: BytesMut::new(),
        close_after_drain: false,
        end_stream_sent: false,
    }))
}

/// Append one HTTP/2 frame to `out`.
fn put_frame(out: &mut BytesMut, kind: u8, flags: u8, stream: u32, payload: &[u8]) {
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes()[1..4]);
    out.put_u8(kind);
    out.put_u8(flags);
    out.put_u32(stream);
    out.put_slice(payload);
}

/// A parsed HTTP/2 frame: (type, flags, stream id, payload).
type RawFrame = (u8, u8, u32, Vec<u8>);

/// Strip HTTP/2 padding from a DATA/HEADERS payload (RFC 7540 §6.1).
fn strip_padding(flags: u8, payload: &[u8]) -> Result<&[u8]> {
    if flags & FLAG_PADDED == 0 {
        return Ok(payload);
    }
    let Some((&pad, rest)) = payload.split_first() else {
        return Err(Error::protocol("grpc: empty padded frame"));
    };
    let pad = pad as usize;
    if pad > rest.len() {
        return Err(Error::protocol("grpc: padding longer than frame"));
    }
    Ok(&rest[..rest.len() - pad])
}

/// Connection-level HTTP/2 state machine plus the tunnel payload buffers.
struct H2Conn {
    inner: BoxProxyStream,
    rbuf: BytesMut,
    /// Encoded frames waiting for the socket (control frames + DATA).
    out: BytesMut,
    /// Send-side flow control (connection + our single stream).
    conn_send_window: i64,
    stream_send_window: i64,
    peer_initial_window: i64,
    /// Receive-side accounting used to emit WINDOW_UPDATEs.
    conn_recv_window: i64,
    stream_recv_window: i64,
    /// Header block reassembly (HEADERS + CONTINUATION).
    header_frag: BytesMut,
    header_end_stream: bool,
    in_headers: bool,
    hpack_dec: hpack::Decoder,
    // Stream state.
    got_response: bool,
    remote_end: bool,
    conn_eof: bool,
    stream_error: Option<String>,
    trailer_error: Option<String>,
    /// De-framed tunnel payload waiting for the reader.
    plain: BytesMut,
    deframer: GrpcDeframer,
}

impl H2Conn {
    fn new(inner: BoxProxyStream) -> Self {
        H2Conn {
            inner,
            rbuf: BytesMut::with_capacity(16 * 1024),
            out: BytesMut::new(),
            conn_send_window: DEFAULT_WINDOW,
            stream_send_window: DEFAULT_WINDOW,
            peer_initial_window: DEFAULT_WINDOW,
            conn_recv_window: CONN_WINDOW,
            stream_recv_window: DEFAULT_WINDOW,
            header_frag: BytesMut::new(),
            header_end_stream: false,
            in_headers: false,
            hpack_dec: hpack::Decoder::new(),
            got_response: false,
            remote_end: false,
            conn_eof: false,
            stream_error: None,
            trailer_error: None,
            plain: BytesMut::with_capacity(16 * 1024),
            deframer: GrpcDeframer::default(),
        }
    }

    async fn flush_out(&mut self) -> Result<()> {
        while !self.out.is_empty() {
            let n = self.inner.write(&self.out).await?;
            if n == 0 {
                return Err(Error::network("grpc: transport accepted zero bytes"));
            }
            self.out.advance(n);
        }
        self.inner.flush().await?;
        Ok(())
    }

    /// Read once from the socket into `rbuf`; 0 means EOF.
    async fn fill(&mut self) -> Result<usize> {
        let mut tmp = [0u8; 16 * 1024];
        let n = self.inner.read(&mut tmp).await?;
        self.rbuf.extend_from_slice(&tmp[..n]);
        Ok(n)
    }

    /// Parse and handle every complete frame buffered in `rbuf`.
    fn drain_frames(&mut self) -> Result<()> {
        while let Some((kind, flags, stream, payload)) = self.take_frame()? {
            self.on_frame(kind, flags, stream, &payload)?;
        }
        Ok(())
    }

    fn take_frame(&mut self) -> Result<Option<RawFrame>> {
        if self.rbuf.len() < 9 {
            return Ok(None);
        }
        let len = ((self.rbuf[0] as usize) << 16)
            | ((self.rbuf[1] as usize) << 8)
            | self.rbuf[2] as usize;
        if len > MAX_FRAME {
            // We never advertise a larger SETTINGS_MAX_FRAME_SIZE, so a
            // conformant peer cannot legitimately exceed the default.
            return Err(Error::protocol(format!(
                "grpc: frame of {len} bytes exceeds our max frame size"
            )));
        }
        if self.rbuf.len() < 9 + len {
            return Ok(None);
        }
        let kind = self.rbuf[3];
        let flags = self.rbuf[4];
        let stream = (((self.rbuf[5] as u32) & 0x7f) << 24)
            | ((self.rbuf[6] as u32) << 16)
            | ((self.rbuf[7] as u32) << 8)
            | self.rbuf[8] as u32;
        let payload = self.rbuf[9..9 + len].to_vec();
        self.rbuf.advance(9 + len);
        Ok(Some((kind, flags, stream, payload)))
    }

    fn on_frame(&mut self, kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Result<()> {
        if self.in_headers && kind != FT_CONTINUATION {
            return Err(Error::protocol("grpc: expected CONTINUATION frame"));
        }
        match kind {
            FT_DATA if stream == STREAM_ID => self.on_data(flags, payload),
            FT_DATA if stream == 0 => Err(Error::protocol("grpc: DATA on stream 0")),
            FT_HEADERS if stream == STREAM_ID => self.on_headers(flags, payload),
            FT_CONTINUATION if stream == STREAM_ID => self.on_continuation(flags, payload),
            FT_SETTINGS if flags & FLAG_ACK != 0 => Ok(()),
            FT_SETTINGS => self.on_settings(payload),
            FT_PING if flags & FLAG_ACK != 0 => Ok(()),
            FT_PING if payload.len() != 8 => Err(Error::protocol("grpc: PING with bad length")),
            FT_PING => {
                put_frame(&mut self.out, FT_PING, FLAG_ACK, 0, payload);
                Ok(())
            }
            FT_WINDOW_UPDATE if payload.len() != 4 => {
                Err(Error::protocol("grpc: WINDOW_UPDATE with bad length"))
            }
            FT_WINDOW_UPDATE => self.on_window_update(stream, payload),
            FT_RST_STREAM if stream == STREAM_ID => {
                let code = if payload.len() == 4 {
                    u32::from_be_bytes(payload[..4].try_into().unwrap())
                } else {
                    0
                };
                self.stream_error = Some(format!("grpc: stream reset by server (code {code})"));
                self.remote_end = true;
                Ok(())
            }
            FT_GOAWAY => {
                tracing::debug!("grpc: server sent GOAWAY");
                Ok(())
            }
            FT_PUSH_PROMISE => Err(Error::protocol("grpc: unexpected PUSH_PROMISE")),
            // PRIORITY and frames for other streams are ignored.
            _ => Ok(()),
        }
    }

    fn on_data(&mut self, flags: u8, payload: &[u8]) -> Result<()> {
        let data = strip_padding(flags, payload)?;
        self.account_recv(payload.len() as i64);
        self.deframer.push(data, &mut self.plain)?;
        if flags & FLAG_END_STREAM != 0 {
            self.remote_end = true;
        }
        Ok(())
    }

    /// Consume receive-window budget, replenishing windows once they drop
    /// below half so the server never stalls.
    fn account_recv(&mut self, len: i64) {
        if self.remote_end {
            return; // peer is done; no point replenishing windows
        }
        self.conn_recv_window -= len;
        self.stream_recv_window -= len;
        if self.stream_recv_window <= DEFAULT_WINDOW / 2 {
            let inc = DEFAULT_WINDOW - self.stream_recv_window;
            put_frame(
                &mut self.out,
                FT_WINDOW_UPDATE,
                0,
                STREAM_ID,
                &(inc as u32).to_be_bytes(),
            );
            self.stream_recv_window = DEFAULT_WINDOW;
        }
        if self.conn_recv_window <= CONN_WINDOW / 2 {
            let inc = CONN_WINDOW - self.conn_recv_window;
            put_frame(
                &mut self.out,
                FT_WINDOW_UPDATE,
                0,
                0,
                &(inc as u32).to_be_bytes(),
            );
            self.conn_recv_window = CONN_WINDOW;
        }
    }

    fn on_headers(&mut self, flags: u8, payload: &[u8]) -> Result<()> {
        let body = strip_padding(flags, payload)?;
        let body = if flags & FLAG_PRIORITY != 0 {
            body.get(5..)
                .ok_or_else(|| Error::protocol("grpc: short HEADERS frame"))?
        } else {
            body
        };
        if self.header_frag.len() + body.len() > MAX_HEADER_BLOCK {
            return Err(Error::protocol("grpc: header block too large"));
        }
        self.header_frag.extend_from_slice(body);
        self.header_end_stream = flags & FLAG_END_STREAM != 0;
        if flags & FLAG_END_HEADERS != 0 {
            self.finish_header_block()?;
        } else {
            self.in_headers = true;
        }
        Ok(())
    }

    fn on_continuation(&mut self, flags: u8, payload: &[u8]) -> Result<()> {
        if !self.in_headers {
            return Err(Error::protocol("grpc: unexpected CONTINUATION frame"));
        }
        if self.header_frag.len() + payload.len() > MAX_HEADER_BLOCK {
            return Err(Error::protocol("grpc: header block too large"));
        }
        self.header_frag.extend_from_slice(payload);
        if flags & FLAG_END_HEADERS != 0 {
            self.in_headers = false;
            self.finish_header_block()?;
        }
        Ok(())
    }

    /// Decode a complete header block: the response HEADERS first (must be
    /// 200), trailers (grpc-status) afterwards.
    fn finish_header_block(&mut self) -> Result<()> {
        let block = std::mem::take(&mut self.header_frag);
        let end_stream = self.header_end_stream;
        let headers = self.hpack_dec.decode(&block)?;
        if !self.got_response {
            let status = headers
                .iter()
                .find(|(n, _)| n == b":status")
                .and_then(|(_, v)| std::str::from_utf8(v).ok())
                .and_then(|v| v.parse::<u16>().ok())
                .ok_or_else(|| Error::protocol("grpc: response missing :status"))?;
            self.got_response = true;
            if status != 200 {
                return Err(Error::protocol(format!(
                    "grpc: unexpected HTTP status {status}"
                )));
            }
        }
        if end_stream {
            self.remote_end = true;
            if let Some((_, v)) = headers.iter().find(|(n, _)| n == b"grpc-status") {
                let s = String::from_utf8_lossy(v).trim().to_string();
                if !s.trim().is_empty() && s.parse::<i32>() != Ok(0) {
                    self.trailer_error = Some(format!("grpc: server returned grpc-status {s}"));
                }
            }
        }
        Ok(())
    }

    fn on_settings(&mut self, payload: &[u8]) -> Result<()> {
        if !payload.len().is_multiple_of(6) {
            return Err(Error::protocol("grpc: bad SETTINGS length"));
        }
        for pair in payload.as_chunks::<6>().0 {
            let id = u16::from_be_bytes([pair[0], pair[1]]);
            let val = u32::from_be_bytes([pair[2], pair[3], pair[4], pair[5]]);
            if id == 0x4 && val > 0x7fff_ffff {
                return Err(Error::protocol("grpc: initial window above 2^31-1"));
            }
            // SETTINGS_INITIAL_WINDOW_SIZE changes the window of open
            // streams too; everything else we can ignore (we never open a
            // second stream and always send 16 KiB frames).
            if id == 0x4 {
                let val = val as i64;
                self.stream_send_window += val - self.peer_initial_window;
                self.peer_initial_window = val;
            }
        }
        put_frame(&mut self.out, FT_SETTINGS, FLAG_ACK, 0, &[]);
        Ok(())
    }

    fn on_window_update(&mut self, stream: u32, payload: &[u8]) -> Result<()> {
        let inc = u32::from_be_bytes(payload[..4].try_into().unwrap()) & 0x7fff_ffff;
        if inc == 0 {
            return Err(Error::protocol("grpc: zero WINDOW_UPDATE increment"));
        }
        let inc = inc as i64;
        match stream {
            0 => {
                if self.conn_send_window + inc > 0x7fff_ffff {
                    return Err(Error::protocol("grpc: connection window overflow"));
                }
                self.conn_send_window += inc;
            }
            STREAM_ID => {
                if self.stream_send_window + inc > 0x7fff_ffff {
                    return Err(Error::protocol("grpc: stream window overflow"));
                }
                self.stream_send_window += inc;
            }
            _ => {}
        }
        Ok(())
    }

    /// Poll-based variant of `drain_frames` + `fill`: processes buffered
    /// frames, then reads more from the socket. Returns `Pending` with the
    /// socket read waker armed, or `Ready` once the socket hit EOF.
    fn poll_process(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            match self.take_frame() {
                Ok(Some((kind, flags, stream, payload))) => {
                    if let Err(e) = self.on_frame(kind, flags, stream, &payload) {
                        return Poll::Ready(Err(io::Error::new(
                            io::ErrorKind::InvalidData,
                            e.to_string(),
                        )));
                    }
                }
                Ok(None) => {
                    let mut tmp = [0u8; 16 * 1024];
                    let mut rb = ReadBuf::new(&mut tmp);
                    ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
                    if rb.filled().is_empty() {
                        self.conn_eof = true;
                        return Poll::Ready(Ok(()));
                    }
                    self.rbuf.extend_from_slice(rb.filled());
                }
                Err(e) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        e.to_string(),
                    )))
                }
            }
        }
    }
}

/// The gRPC-tunneled byte stream returned by [`grpc_connect`].
struct GrpcStream {
    conn: H2Conn,
    /// gRPC messages accepted from the caller (5-byte prefix + payload)
    /// that have not yet been moved into flow-controlled DATA frames.
    sendq: BytesMut,
    close_after_drain: bool,
    end_stream_sent: bool,
}

impl GrpcStream {
    /// Process inbound frames, move `sendq` into DATA frames as the send
    /// window allows, and push queued bytes to the socket.
    fn poll_drive(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        loop {
            if let Poll::Ready(r) = self.conn.poll_process(cx) {
                r?;
            }
            if !self.conn.out.is_empty() {
                let n = ready!(Pin::new(&mut self.conn.inner).poll_write(cx, &self.conn.out))?;
                if n == 0 {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "grpc: transport accepted zero bytes",
                    )));
                }
                self.conn.out.advance(n);
                continue;
            }
            let allowed = self.conn.conn_send_window.min(self.conn.stream_send_window);
            if allowed > 0 && !self.sendq.is_empty() {
                let take = (allowed as usize).min(MAX_FRAME).min(self.sendq.len());
                put_frame(
                    &mut self.conn.out,
                    FT_DATA,
                    0,
                    STREAM_ID,
                    &self.sendq[..take],
                );
                self.conn.conn_send_window -= take as i64;
                self.conn.stream_send_window -= take as i64;
                self.sendq.advance(take);
                continue;
            }
            // Half-close only after all queued data is on the wire.
            if self.close_after_drain && !self.end_stream_sent && self.sendq.is_empty() {
                self.end_stream_sent = true;
                put_frame(&mut self.conn.out, FT_DATA, FLAG_END_STREAM, STREAM_ID, &[]);
                continue;
            }
            return Poll::Ready(Ok(()));
        }
    }
}

impl AsyncWrite for GrpcStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        let mut accepted = 0usize;
        loop {
            match this.poll_drive(cx) {
                Poll::Ready(r) => r?,
                Poll::Pending => {
                    return if accepted > 0 {
                        Poll::Ready(Ok(accepted))
                    } else {
                        Poll::Pending
                    };
                }
            }
            let space = MAX_SEND_BACKLOG.saturating_sub(this.sendq.len());
            if accepted < buf.len() && space > 0 {
                let take = (buf.len() - accepted).min(WRITE_CHUNK).min(space);
                this.sendq.reserve(take + 5);
                this.sendq.put_u8(0); // uncompressed-flag
                this.sendq.put_u32(take as u32); // big-endian length
                this.sendq.put_slice(&buf[accepted..accepted + take]);
                accepted += take;
                continue;
            }
            if accepted > 0 {
                return Poll::Ready(Ok(accepted));
            }
            // Backlog full and the send window is closed; the waker was
            // armed by poll_drive (socket read for WINDOW_UPDATEs, or the
            // socket write side while flushing).
            return Poll::Pending;
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        ready!(this.poll_drive(cx))?;
        Pin::new(&mut this.conn.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        this.close_after_drain = true;
        ready!(this.poll_drive(cx))?;
        if !this.end_stream_sent {
            // Still draining the send backlog (window exhausted); the waker
            // is armed on the socket (WINDOW_UPDATE arrival or flush
            // completion). Closing now would drop queued tunnel bytes.
            return Poll::Pending;
        }
        Pin::new(&mut this.conn.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for GrpcStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        fn frame_err(e: Error) -> io::Error {
            io::Error::new(io::ErrorKind::InvalidData, e.to_string())
        }
        let this = self.get_mut();
        loop {
            // Deliver whatever is already de-framed.
            if !this.conn.plain.is_empty() {
                let n = this.conn.plain.len().min(buf.remaining());
                buf.put_slice(&this.conn.plain[..n]);
                this.conn.plain.advance(n);
                return Poll::Ready(Ok(()));
            }
            // Terminal states.
            if let Some(e) = &this.conn.stream_error {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::ConnectionReset,
                    e.clone(),
                )));
            }
            if this.conn.remote_end {
                if let Some(e) = &this.conn.trailer_error {
                    return Poll::Ready(Err(io::Error::other(e.clone())));
                }
                return Poll::Ready(Ok(())); // clean EOF after trailers
            }
            if this.conn.conn_eof {
                // TCP EOF without trailers: lenient, like the ws transport.
                return Poll::Ready(Ok(()));
            }
            // Best-effort pump of the outbound side (acks, window updates,
            // queued DATA). Write-side closure errors (peer vanished while
            // we still owed acks) must not abort the read direction: keep
            // draining inbound data instead.
            if let Poll::Ready(Err(e)) = this.poll_drive(cx) {
                match e.kind() {
                    io::ErrorKind::BrokenPipe | io::ErrorKind::WriteZero => {}
                    _ => return Poll::Ready(Err(e)),
                }
            }
            // Parse one buffered frame, if any (drive may have read and
            // buffered several; on_frame feeds `plain` / sets state).
            match this.conn.take_frame() {
                Ok(Some((kind, flags, stream, payload))) => {
                    this.conn
                        .on_frame(kind, flags, stream, &payload)
                        .map_err(frame_err)?;
                    continue;
                }
                Ok(None) => {}
                Err(e) => return Poll::Ready(Err(frame_err(e))),
            }
            // No complete frame buffered: read more from the socket. This
            // is the only Pending exit, so buffered bytes are never lost.
            let mut tmp = [0u8; 16 * 1024];
            let mut rb = ReadBuf::new(&mut tmp);
            match Pin::new(&mut this.conn.inner).poll_read(cx, &mut rb) {
                Poll::Ready(Ok(())) if rb.filled().is_empty() => {
                    this.conn.conn_eof = true;
                }
                Poll::Ready(Ok(())) => {
                    this.conn.rbuf.extend_from_slice(rb.filled());
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
    }
}

/// Reassembles length-prefixed gRPC messages back into a byte stream
/// (`flag(1) | len-be32(4) | data`), tolerating messages split across DATA
/// frame boundaries and several messages per frame.
#[derive(Default)]
struct GrpcDeframer {
    carry: BytesMut,
}

impl GrpcDeframer {
    fn push(&mut self, chunk: &[u8], out: &mut BytesMut) -> Result<()> {
        self.carry.extend_from_slice(chunk);
        loop {
            if self.carry.len() < 5 {
                return Ok(());
            }
            if self.carry[0] != 0 {
                return Err(Error::protocol("grpc: compressed message (flag != 0)"));
            }
            let len =
                u32::from_be_bytes([self.carry[1], self.carry[2], self.carry[3], self.carry[4]])
                    as usize;
            if len > MAX_MESSAGE {
                return Err(Error::protocol(format!(
                    "grpc: message of {len} bytes exceeds limit"
                )));
            }
            if self.carry.len() < 5 + len {
                return Ok(());
            }
            out.extend_from_slice(&self.carry[5..5 + len]);
            self.carry.advance(5 + len);
        }
    }
}

/// HPACK (RFC 7541): a sender that only emits literal-without-indexing
/// with huffman disabled (legal against any server) and a complete
/// receiver — static table, dynamic table with size updates, integer and
/// string primitives, huffman decoding.
mod hpack {
    use std::collections::{HashMap, VecDeque};
    use std::sync::OnceLock;

    use super::*;

    /// RFC 7541 Appendix A: the 61-entry static table.
    const STATIC_TABLE: &[(&[u8], &[u8])] = &[
        (b":authority", b""),
        (b":method", b"GET"),
        (b":method", b"POST"),
        (b":path", b"/"),
        (b":path", b"/index.html"),
        (b":scheme", b"http"),
        (b":scheme", b"https"),
        (b":status", b"200"),
        (b":status", b"204"),
        (b":status", b"206"),
        (b":status", b"304"),
        (b":status", b"400"),
        (b":status", b"404"),
        (b":status", b"500"),
        (b"accept-charset", b""),
        (b"accept-encoding", b"gzip, deflate"),
        (b"accept-language", b""),
        (b"accept-ranges", b""),
        (b"accept", b""),
        (b"access-control-allow-origin", b""),
        (b"age", b""),
        (b"allow", b""),
        (b"authorization", b""),
        (b"cache-control", b""),
        (b"content-disposition", b""),
        (b"content-encoding", b""),
        (b"content-language", b""),
        (b"content-length", b""),
        (b"content-location", b""),
        (b"content-range", b""),
        (b"content-type", b""),
        (b"cookie", b""),
        (b"date", b""),
        (b"etag", b""),
        (b"expect", b""),
        (b"expires", b""),
        (b"from", b""),
        (b"host", b""),
        (b"if-match", b""),
        (b"if-modified-since", b""),
        (b"if-none-match", b""),
        (b"if-range", b""),
        (b"if-unmodified-since", b""),
        (b"last-modified", b""),
        (b"link", b""),
        (b"location", b""),
        (b"max-forwards", b""),
        (b"proxy-authenticate", b""),
        (b"proxy-authorization", b""),
        (b"range", b""),
        (b"referer", b""),
        (b"refresh", b""),
        (b"retry-after", b""),
        (b"server", b""),
        (b"set-cookie", b""),
        (b"strict-transport-security", b""),
        (b"transfer-encoding", b""),
        (b"user-agent", b""),
        (b"vary", b""),
        (b"via", b""),
        (b"www-authenticate", b""),
    ];

    /// Encode `headers` as HPACK. Every field is a literal-without-indexing
    /// with a new name (never touches either dynamic table); names must
    /// already be lowercase.
    pub(super) fn encode(headers: &[(&str, &str)]) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        for (name, value) in headers {
            out.push(0x00);
            encode_str(name.as_bytes(), &mut out);
            encode_str(value.as_bytes(), &mut out);
        }
        out
    }

    fn encode_str(s: &[u8], out: &mut Vec<u8>) {
        encode_int(s.len() as u64, 7, out);
        out.extend_from_slice(s);
    }

    /// HPACK integer with a `prefix`-bit prefix (RFC 7541 §5.1).
    fn encode_int(mut value: u64, prefix: u8, out: &mut Vec<u8>) {
        let max = (1u64 << prefix) - 1;
        if value < max {
            out.push(value as u8);
            return;
        }
        out.push(max as u8);
        value -= max;
        while value >= 128 {
            out.push((value % 128 + 128) as u8);
            value /= 128;
        }
        out.push(value as u8);
    }

    pub(super) fn read_int(data: &[u8], pos: usize, prefix: u8) -> Result<(u64, usize)> {
        if pos >= data.len() {
            return Err(Error::protocol("hpack: truncated integer"));
        }
        let mask = (1u64 << prefix) - 1;
        let mut value = (data[pos] as u64) & mask;
        let mut n = 1usize;
        if value < mask {
            return Ok((value, n));
        }
        let mut shift = 0u32;
        loop {
            let Some(&b) = data.get(pos + n) else {
                return Err(Error::protocol("hpack: truncated integer"));
            };
            value = value
                .checked_add(((b & 0x7f) as u64) << shift)
                .ok_or_else(|| Error::protocol("hpack: integer overflow"))?;
            n += 1;
            if shift > 28 {
                return Err(Error::protocol("hpack: integer overflow"));
            }
            shift += 7;
            if b & 0x80 == 0 {
                return Ok((value, n));
            }
        }
    }

    fn read_string(data: &[u8], pos: usize) -> Result<(Vec<u8>, usize)> {
        if pos >= data.len() {
            return Err(Error::protocol("hpack: truncated string"));
        }
        let huff = data[pos] & 0x80 != 0;
        let (len, n) = read_int(data, pos, 7)?;
        if len > data.len() as u64 {
            return Err(Error::protocol("hpack: string length out of range"));
        }
        let len = len as usize;
        let bytes = data
            .get(pos + n..pos + n + len)
            .ok_or_else(|| Error::protocol("hpack: truncated string"))?;
        let value = if huff {
            huffman_decode(bytes)?
        } else {
            bytes.to_vec()
        };
        Ok((value, n + len))
    }

    pub(super) struct Decoder {
        dynamic: VecDeque<(Vec<u8>, Vec<u8>)>,
        size: usize,
        max_size: usize,
    }

    impl Decoder {
        pub(super) fn new() -> Self {
            Decoder {
                dynamic: VecDeque::new(),
                size: 0,
                max_size: 4096,
            }
        }

        pub(super) fn decode(&mut self, block: &[u8]) -> Result<Vec<(Vec<u8>, Vec<u8>)>> {
            let mut out = Vec::new();
            let mut i = 0usize;
            while i < block.len() {
                let b = block[i];
                if b & 0x80 != 0 {
                    // Indexed header field.
                    let (idx, n) = read_int(block, i, 7)?;
                    if idx == 0 {
                        return Err(Error::protocol("hpack: index 0"));
                    }
                    out.push(self.lookup(idx)?);
                    i += n;
                } else if b & 0xc0 == 0x40 {
                    // Literal with incremental indexing.
                    let (idx, n) = read_int(block, i, 6)?;
                    i += n;
                    let name = self.name_at(idx, block, &mut i)?;
                    let (value, n) = read_string(block, i)?;
                    i += n;
                    self.insert(name.clone(), value.clone());
                    out.push((name, value));
                } else if b & 0xe0 == 0x20 {
                    // Dynamic table size update (must not exceed our cap).
                    let (size, n) = read_int(block, i, 5)?;
                    if size > 4096 {
                        return Err(Error::protocol("hpack: table size update above cap"));
                    }
                    self.max_size = size as usize;
                    self.evict();
                    i += n;
                } else {
                    // Literal without indexing / never indexed.
                    let (idx, n) = read_int(block, i, 4)?;
                    i += n;
                    let name = self.name_at(idx, block, &mut i)?;
                    let (value, n) = read_string(block, i)?;
                    i += n;
                    out.push((name, value));
                }
            }
            Ok(out)
        }

        fn name_at(&self, idx: u64, block: &[u8], i: &mut usize) -> Result<Vec<u8>> {
            if idx == 0 {
                let (s, n) = read_string(block, *i)?;
                *i += n;
                Ok(s)
            } else {
                Ok(self.lookup(idx)?.0)
            }
        }

        fn lookup(&self, idx: u64) -> Result<(Vec<u8>, Vec<u8>)> {
            if idx as usize <= STATIC_TABLE.len() {
                let (n, v) = STATIC_TABLE[idx as usize - 1];
                return Ok((n.to_vec(), v.to_vec()));
            }
            let dyn_idx = idx as usize - STATIC_TABLE.len() - 1;
            self.dynamic
                .get(dyn_idx)
                .cloned()
                .ok_or_else(|| Error::protocol(format!("hpack: bad index {idx}")))
        }

        fn insert(&mut self, name: Vec<u8>, value: Vec<u8>) {
            self.size += 32 + name.len() + value.len();
            self.dynamic.push_front((name, value));
            self.evict();
        }

        fn evict(&mut self) {
            while self.size > self.max_size {
                match self.dynamic.pop_back() {
                    Some((n, v)) => self.size -= 32 + n.len() + v.len(),
                    None => break,
                }
            }
        }
    }

    /// RFC 7541 Appendix B: canonical Huffman code `(code, bit-length)` for
    /// symbols 0..=255, then EOS (256).
    const HUFFMAN: [(u32, u8); 257] = [
        (0x1ff8, 13),
        (0x7fffd8, 23),
        (0xfffffe2, 28),
        (0xfffffe3, 28),
        (0xfffffe4, 28),
        (0xfffffe5, 28),
        (0xfffffe6, 28),
        (0xfffffe7, 28),
        (0xfffffe8, 28),
        (0xffffea, 24),
        (0x3ffffffc, 30),
        (0xfffffe9, 28),
        (0xfffffea, 28),
        (0x3ffffffd, 30),
        (0xfffffeb, 28),
        (0xfffffec, 28),
        (0xfffffed, 28),
        (0xfffffee, 28),
        (0xfffffef, 28),
        (0xffffff0, 28),
        (0xffffff1, 28),
        (0xffffff2, 28),
        (0x3ffffffe, 30),
        (0xffffff3, 28),
        (0xffffff4, 28),
        (0xffffff5, 28),
        (0xffffff6, 28),
        (0xffffff7, 28),
        (0xffffff8, 28),
        (0xffffff9, 28),
        (0xffffffa, 28),
        (0xffffffb, 28),
        (0x14, 6),
        (0x3f8, 10),
        (0x3f9, 10),
        (0xffa, 12),
        (0x1ff9, 13),
        (0x15, 6),
        (0xf8, 8),
        (0x7fa, 11),
        (0x3fa, 10),
        (0x3fb, 10),
        (0xf9, 8),
        (0x7fb, 11),
        (0xfa, 8),
        (0x16, 6),
        (0x17, 6),
        (0x18, 6),
        (0x0, 5),
        (0x1, 5),
        (0x2, 5),
        (0x19, 6),
        (0x1a, 6),
        (0x1b, 6),
        (0x1c, 6),
        (0x1d, 6),
        (0x1e, 6),
        (0x1f, 6),
        (0x5c, 7),
        (0xfb, 8),
        (0x7ffc, 15),
        (0x20, 6),
        (0xffb, 12),
        (0x3fc, 10),
        (0x1ffa, 13),
        (0x21, 6),
        (0x5d, 7),
        (0x5e, 7),
        (0x5f, 7),
        (0x60, 7),
        (0x61, 7),
        (0x62, 7),
        (0x63, 7),
        (0x64, 7),
        (0x65, 7),
        (0x66, 7),
        (0x67, 7),
        (0x68, 7),
        (0x69, 7),
        (0x6a, 7),
        (0x6b, 7),
        (0x6c, 7),
        (0x6d, 7),
        (0x6e, 7),
        (0x6f, 7),
        (0x70, 7),
        (0x71, 7),
        (0x72, 7),
        (0xfc, 8),
        (0x73, 7),
        (0xfd, 8),
        (0x1ffb, 13),
        (0x7fff0, 19),
        (0x1ffc, 13),
        (0x3ffc, 14),
        (0x22, 6),
        (0x7ffd, 15),
        (0x3, 5),
        (0x23, 6),
        (0x4, 5),
        (0x24, 6),
        (0x5, 5),
        (0x25, 6),
        (0x26, 6),
        (0x27, 6),
        (0x6, 5),
        (0x74, 7),
        (0x75, 7),
        (0x28, 6),
        (0x29, 6),
        (0x2a, 6),
        (0x7, 5),
        (0x2b, 6),
        (0x76, 7),
        (0x2c, 6),
        (0x8, 5),
        (0x9, 5),
        (0x2d, 6),
        (0x77, 7),
        (0x78, 7),
        (0x79, 7),
        (0x7a, 7),
        (0x7b, 7),
        (0x7ffe, 15),
        (0x7fc, 11),
        (0x3ffd, 14),
        (0x1ffd, 13),
        (0xffffffc, 28),
        (0xfffe6, 20),
        (0x3fffd2, 22),
        (0xfffe7, 20),
        (0xfffe8, 20),
        (0x3fffd3, 22),
        (0x3fffd4, 22),
        (0x3fffd5, 22),
        (0x7fffd9, 23),
        (0x3fffd6, 22),
        (0x7fffda, 23),
        (0x7fffdb, 23),
        (0x7fffdc, 23),
        (0x7fffdd, 23),
        (0x7fffde, 23),
        (0xffffeb, 24),
        (0x7fffdf, 23),
        (0xffffec, 24),
        (0xffffed, 24),
        (0x3fffd7, 22),
        (0x7fffe0, 23),
        (0xffffee, 24),
        (0x7fffe1, 23),
        (0x7fffe2, 23),
        (0x7fffe3, 23),
        (0x7fffe4, 23),
        (0x1fffdc, 21),
        (0x3fffd8, 22),
        (0x7fffe5, 23),
        (0x3fffd9, 22),
        (0x7fffe6, 23),
        (0x7fffe7, 23),
        (0xffffef, 24),
        (0x3fffda, 22),
        (0x1fffdd, 21),
        (0xfffe9, 20),
        (0x3fffdb, 22),
        (0x3fffdc, 22),
        (0x7fffe8, 23),
        (0x7fffe9, 23),
        (0x1fffde, 21),
        (0x7fffea, 23),
        (0x3fffdd, 22),
        (0x3fffde, 22),
        (0xfffff0, 24),
        (0x1fffdf, 21),
        (0x3fffdf, 22),
        (0x7fffeb, 23),
        (0x7fffec, 23),
        (0x1fffe0, 21),
        (0x1fffe1, 21),
        (0x3fffe0, 22),
        (0x1fffe2, 21),
        (0x7fffed, 23),
        (0x3fffe1, 22),
        (0x7fffee, 23),
        (0x7fffef, 23),
        (0xfffea, 20),
        (0x3fffe2, 22),
        (0x3fffe3, 22),
        (0x3fffe4, 22),
        (0x7ffff0, 23),
        (0x3fffe5, 22),
        (0x3fffe6, 22),
        (0x7ffff1, 23),
        (0x3ffffe0, 26),
        (0x3ffffe1, 26),
        (0xfffeb, 20),
        (0x7fff1, 19),
        (0x3fffe7, 22),
        (0x7ffff2, 23),
        (0x3fffe8, 22),
        (0x1ffffec, 25),
        (0x3ffffe2, 26),
        (0x3ffffe3, 26),
        (0x3ffffe4, 26),
        (0x7ffffde, 27),
        (0x7ffffdf, 27),
        (0x3ffffe5, 26),
        (0xfffff1, 24),
        (0x1ffffed, 25),
        (0x7fff2, 19),
        (0x1fffe3, 21),
        (0x3ffffe6, 26),
        (0x7ffffe0, 27),
        (0x7ffffe1, 27),
        (0x3ffffe7, 26),
        (0x7ffffe2, 27),
        (0xfffff2, 24),
        (0x1fffe4, 21),
        (0x1fffe5, 21),
        (0x3ffffe8, 26),
        (0x3ffffe9, 26),
        (0xffffffd, 28),
        (0x7ffffe3, 27),
        (0x7ffffe4, 27),
        (0x7ffffe5, 27),
        (0xfffec, 20),
        (0xfffff3, 24),
        (0xfffed, 20),
        (0x1fffe6, 21),
        (0x3fffe9, 22),
        (0x1fffe7, 21),
        (0x1fffe8, 21),
        (0x7ffff3, 23),
        (0x3fffea, 22),
        (0x3fffeb, 22),
        (0x1ffffee, 25),
        (0x1ffffef, 25),
        (0xfffff4, 24),
        (0xfffff5, 24),
        (0x3ffffea, 26),
        (0x7ffff4, 23),
        (0x3ffffeb, 26),
        (0x7ffffe6, 27),
        (0x3ffffec, 26),
        (0x3ffffed, 26),
        (0x7ffffe7, 27),
        (0x7ffffe8, 27),
        (0x7ffffe9, 27),
        (0x7ffffea, 27),
        (0x7ffffeb, 27),
        (0xffffffe, 28),
        (0x7ffffec, 27),
        (0x7ffffed, 27),
        (0x7ffffee, 27),
        (0x7ffffef, 27),
        (0x7fffff0, 27),
        (0x3ffffee, 26),
        (0x3fffffff, 30), // EOS
    ];

    fn huffman_table() -> &'static HashMap<(u8, u32), u16> {
        static MAP: OnceLock<HashMap<(u8, u32), u16>> = OnceLock::new();
        MAP.get_or_init(|| {
            HUFFMAN
                .iter()
                .enumerate()
                .map(|(sym, &(code, bits))| ((bits, code), sym as u16))
                .collect()
        })
    }

    /// Decode an HPACK huffman string (RFC 7541 §5.2): bit-by-bit canonical
    /// decode; trailing bits must be the MSBs of EOS (all ones, < 8 bits).
    pub(super) fn huffman_decode(input: &[u8]) -> Result<Vec<u8>> {
        let table = huffman_table();
        let mut acc = 0u32;
        let mut len = 0u8;
        let mut out = Vec::with_capacity(input.len() * 2);
        for &byte in input {
            for shift in (0..8).rev() {
                acc = (acc << 1) | u32::from((byte >> shift) & 1);
                len += 1;
                if let Some(&sym) = table.get(&(len, acc)) {
                    if sym == 256 {
                        return Err(Error::protocol("hpack: EOS inside string"));
                    }
                    out.push(sym as u8);
                    acc = 0;
                    len = 0;
                } else if len > 30 {
                    return Err(Error::protocol("hpack: invalid huffman code"));
                }
            }
        }
        if len > 0 && (len >= 8 || acc != (1 << len) - 1) {
            return Err(Error::protocol("hpack: invalid huffman padding"));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;
    use tokio::io::AsyncReadExt;

    const VECTORS: &[(&str, &[u8])] = &[
        // RFC 7541 Appendix C.4.1
        (
            "www.example.com",
            &[
                0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
            ],
        ),
        ("no-cache", &[0xa8, 0xeb, 0x10, 0x64, 0x9c, 0xbf]),
        // RFC 7541 Appendix C.4.2
        (
            "custom-key",
            &[0x25, 0xa8, 0x49, 0xe9, 0x5b, 0xa9, 0x7d, 0x7f],
        ),
        ("302", &[0x64, 0x02]),
    ];

    #[test]
    fn huffman_decode_rfc_vectors() {
        for (want, bytes) in VECTORS {
            assert_eq!(&hpack::huffman_decode(bytes).unwrap(), want.as_bytes());
        }
    }

    #[test]
    fn huffman_decode_rejects_bad_input() {
        // '0' (5 bits of zeros) + 3 zero padding bits: padding must be 1s.
        assert!(hpack::huffman_decode(&[0x00]).is_err());
        // 8+ one bits: EOS prefix longer than legal padding.
        assert!(hpack::huffman_decode(&[0xff]).is_err());
        // Empty string is legal.
        assert_eq!(&hpack::huffman_decode(&[]).unwrap(), b"");
    }

    #[test]
    fn hpack_roundtrip_literal_without_indexing() {
        let headers = [
            (":method", "POST"),
            (":scheme", "https"),
            (":authority", "grpc.example.com"),
            (":path", "/TunService/Tun"),
            ("content-type", "application/grpc"),
            ("te", "trailers"),
        ];
        let block = hpack::encode(&headers);
        let mut dec = hpack::Decoder::new();
        let decoded = dec.decode(&block).unwrap();
        let decoded: Vec<(String, String)> = decoded
            .iter()
            .map(|(n, v)| {
                (
                    String::from_utf8_lossy(n).into_owned(),
                    String::from_utf8_lossy(v).into_owned(),
                )
            })
            .collect();
        let expect: Vec<_> = headers
            .iter()
            .map(|(n, v)| (n.to_string(), v.to_string()))
            .collect();
        assert_eq!(decoded, expect);
    }

    #[test]
    fn hpack_static_table_indexed() {
        let mut dec = hpack::Decoder::new();
        // 0x88 = indexed field 8 = :status: 200.
        assert_eq!(
            dec.decode(&[0x88]).unwrap(),
            vec![(b":status".to_vec(), b"200".to_vec())]
        );
    }

    #[test]
    fn hpack_dynamic_table_insert_and_reference() {
        let mut dec = hpack::Decoder::new();
        // 0x40 literal-with-incremental-indexing "x-custom: 1", then 0xbe
        // (indexed 62) referencing the just-inserted dynamic entry.
        let mut block = vec![0x40, 8];
        block.extend_from_slice(b"x-custom");
        block.push(1);
        block.extend_from_slice(b"1");
        block.push(0xbe);
        let out = dec.decode(&block).unwrap();
        assert_eq!(
            out,
            vec![
                (b"x-custom".to_vec(), b"1".to_vec()),
                (b"x-custom".to_vec(), b"1".to_vec()),
            ]
        );
    }

    #[test]
    fn hpack_size_update_evicts() {
        let mut dec = hpack::Decoder::new();
        // Size update to 0, insert "a: 1" (immediately evicted), then try to
        // reference it: must fail.
        let mut block = vec![0x20];
        block.push(0x40);
        block.push(1);
        block.push(b'a');
        block.push(1);
        block.push(b'1');
        block.push(0xbe);
        assert!(dec.decode(&block).is_err());
    }

    #[test]
    fn hpack_integer_roundtrip_multibyte() {
        assert_eq!(hpack::read_int(&[0x05], 0, 7).unwrap(), (5, 1));
        // 1337 with a 7-bit prefix: 127 | continuation bytes 186, 9.
        assert_eq!(hpack::read_int(&[0x7f, 186, 9], 0, 7).unwrap(), (1337, 3));
        assert!(hpack::read_int(&[0x7f], 0, 7).is_err());
    }

    #[test]
    fn grpc_deframer_reassembles_at_every_split() {
        let pattern: Vec<u8> = (0..300u32).map(|i| (i % 251) as u8).collect();
        let msgs: Vec<Vec<u8>> = vec![b"hello".to_vec(), pattern, b"x".to_vec()];
        let mut wire = Vec::new();
        for m in &msgs {
            wire.push(0u8);
            wire.extend_from_slice(&(m.len() as u32).to_be_bytes());
            wire.extend_from_slice(m);
        }
        let want: Vec<u8> = msgs.concat();
        for split in 1..=wire.len() {
            let mut d = GrpcDeframer::default();
            let mut out = BytesMut::new();
            for chunk in wire.chunks(split) {
                d.push(chunk, &mut out).unwrap();
            }
            assert_eq!(&out[..], &want[..], "split {split}");
        }
    }

    #[test]
    fn grpc_deframer_rejects_compressed_and_oversize() {
        let mut out = BytesMut::new();
        let mut d = GrpcDeframer::default();
        let compressed = [1u8, 0, 0, 0, 1, b'x'];
        assert!(d.push(&compressed, &mut out).is_err());
        let mut d = GrpcDeframer::default();
        let oversize = [0u8, 0xff, 0xff, 0xff, 0xff, b'x'];
        assert!(d.push(&oversize, &mut out).is_err());
    }

    #[test]
    fn frame_encoding_layout() {
        let mut out = BytesMut::new();
        put_frame(&mut out, FT_HEADERS, FLAG_END_HEADERS, 1, b"abc");
        let expect: &[u8] = &[
            0,
            0,
            3,
            FT_HEADERS,
            FLAG_END_HEADERS,
            0,
            0,
            0,
            1,
            b'a',
            b'b',
            b'c',
        ];
        assert_eq!(&out[..], expect);
    }

    // ---- hermetic loopback integration ----

    fn frame_bytes(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut out = BytesMut::new();
        put_frame(&mut out, kind, flags, stream, payload);
        out.to_vec()
    }

    async fn read_frame<S: AsyncRead + Unpin>(io: &mut S) -> io::Result<(u8, u8, u32, Vec<u8>)> {
        let mut head = [0u8; 9];
        io.read_exact(&mut head).await?;
        let len = ((head[0] as usize) << 16) | ((head[1] as usize) << 8) | head[2] as usize;
        let kind = head[3];
        let flags = head[4];
        let stream = (((head[5] as u32) & 0x7f) << 24)
            | ((head[6] as u32) << 16)
            | ((head[7] as u32) << 8)
            | head[8] as u32;
        let mut payload = vec![0u8; len];
        io.read_exact(&mut payload).await?;
        Ok((kind, flags, stream, payload))
    }

    /// Minimal in-test HTTP/2 server: handshakes, verifies the request
    /// headers, replies with `reply_status`, replenishes the client's
    /// windows, echoes every gRPC message payload, and closes with a
    /// grpc-status 0 trailer on the client's half-close. Returns the
    /// observed :path.
    async fn fake_gun_server(mut io: tokio::io::DuplexStream, reply_status: u16) -> String {
        let mut preface = [0u8; 24];
        io.read_exact(&mut preface).await.unwrap();
        assert_eq!(&preface, PREFACE);
        io.write_all(&frame_bytes(FT_SETTINGS, 0, 0, &[]))
            .await
            .unwrap();

        let mut seen_path = String::new();
        let mut responded = false;
        let mut deframer = GrpcDeframer::default();
        let mut echo = BytesMut::new();
        let mut done = false;
        while !done {
            let (kind, flags, stream, payload) = read_frame(&mut io).await.unwrap();
            match kind {
                FT_SETTINGS if flags & FLAG_ACK == 0 => {
                    io.write_all(&frame_bytes(FT_SETTINGS, FLAG_ACK, 0, &[]))
                        .await
                        .unwrap();
                }
                FT_PING if flags & FLAG_ACK == 0 => {
                    io.write_all(&frame_bytes(FT_PING, FLAG_ACK, 0, &payload))
                        .await
                        .unwrap();
                }
                FT_WINDOW_UPDATE => {}
                // SETTINGS/PING acks for frames we initiated.
                FT_SETTINGS | FT_PING => {}
                FT_HEADERS if stream == 1 && !responded => {
                    assert!(
                        flags & FLAG_END_HEADERS != 0,
                        "test server: CONTINUATION not supported"
                    );
                    let mut dec = hpack::Decoder::new();
                    for (n, v) in dec.decode(&payload).unwrap() {
                        match n.as_slice() {
                            b":path" => seen_path = String::from_utf8(v).unwrap(),
                            b":method" => assert_eq!(v, b"POST"),
                            b":scheme" => assert_eq!(v, b"https"),
                            b":authority" => assert_eq!(v, b"grpc.example.com"),
                            b"content-type" => assert_eq!(v, b"application/grpc"),
                            b"te" => assert_eq!(v, b"trailers"),
                            _ => {}
                        }
                    }
                    responded = true;
                    let block = hpack::encode(&[
                        (":status", &reply_status.to_string()),
                        ("content-type", "application/grpc"),
                    ]);
                    io.write_all(&frame_bytes(FT_HEADERS, FLAG_END_HEADERS, 1, &block))
                        .await
                        .unwrap();
                    if reply_status != 200 {
                        break;
                    }
                }
                FT_DATA if stream == 1 => {
                    if !payload.is_empty() {
                        let inc = (payload.len() as u32).to_be_bytes();
                        io.write_all(&frame_bytes(FT_WINDOW_UPDATE, 0, 0, &inc))
                            .await
                            .unwrap();
                        io.write_all(&frame_bytes(FT_WINDOW_UPDATE, 0, 1, &inc))
                            .await
                            .unwrap();
                    }
                    deframer.push(&payload, &mut echo).unwrap();
                    if flags & FLAG_END_STREAM != 0 {
                        done = true;
                    }
                }
                FT_RST_STREAM | FT_GOAWAY => break,
                other => panic!(
                    "test server: unexpected frame type {other} flags {flags:#x} stream {stream}"
                ),
            }
            if !echo.is_empty() {
                let mut msg = Vec::with_capacity(echo.len() + 5);
                msg.push(0u8);
                msg.extend_from_slice(&(echo.len() as u32).to_be_bytes());
                msg.extend_from_slice(&echo);
                echo.clear();
                for chunk in msg.chunks(MAX_FRAME) {
                    io.write_all(&frame_bytes(FT_DATA, 0, 1, chunk))
                        .await
                        .unwrap();
                }
            }
            if done {
                let trailers = hpack::encode(&[("grpc-status", "0")]);
                io.write_all(&frame_bytes(
                    FT_HEADERS,
                    FLAG_END_HEADERS | FLAG_END_STREAM,
                    1,
                    &trailers,
                ))
                .await
                .unwrap();
            }
        }
        seen_path
    }

    #[tokio::test]
    async fn grpc_tunnel_echo_and_clean_eof() {
        let (client, server) = tokio::io::duplex(64 * 1024);
        let server = tokio::spawn(fake_gun_server(server, 200));
        let settings = GrpcSettings {
            service_name: "TunService".into(),
            host: Some("grpc.example.com".into()),
        };
        let mut stream = grpc_connect(Box::new(client), &settings, "fallback.example.com")
            .await
            .unwrap();

        stream.write_all(b"hello gun").await.unwrap();
        let mut buf = [0u8; 9];
        tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"hello gun");

        // Half-close; the server answers with a grpc-status 0 trailer,
        // which the client surfaces as a clean EOF.
        stream.shutdown().await.unwrap();
        let mut buf = [0u8; 4];
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0);
        assert_eq!(server.await.unwrap(), "/TunService/Tun");
    }

    #[tokio::test]
    async fn grpc_tunnel_large_echo_through_flow_control() {
        // A small duplex buffer forces real backpressure in both
        // directions; the payload exceeds every initial window (64 KiB).
        let (client, server) = tokio::io::duplex(8 * 1024);
        let server = tokio::spawn(fake_gun_server(server, 200));
        let settings = GrpcSettings {
            service_name: "TunService".into(),
            host: Some("grpc.example.com".into()),
        };
        let mut stream = grpc_connect(Box::new(client), &settings, "fallback.example.com")
            .await
            .unwrap();

        let payload: Vec<u8> = (0..300_000u32).map(|i| (i % 253) as u8).collect();
        let want = payload.clone();
        // Single task drives both directions (the copy_bidirectional
        // pattern): write everything, then read the echo back. The reader's
        // poll continues pumping the flow-controlled send backlog.
        stream.write_all(&payload).await.unwrap();
        stream.shutdown().await.unwrap();

        let mut got = vec![0u8; want.len()];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut got))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, want);
        assert_eq!(server.await.unwrap(), "/TunService/Tun");
    }

    #[tokio::test]
    async fn grpc_connect_rejects_non_200() {
        let (client, server) = tokio::io::duplex(4096);
        let server = tokio::spawn(fake_gun_server(server, 404));
        let settings = GrpcSettings {
            service_name: "svc".into(),
            host: Some("grpc.example.com".into()),
        };
        let err = match grpc_connect(Box::new(client), &settings, "h.example.com").await {
            Ok(_) => panic!("grpc: expected the 404 response to fail the handshake"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("404"), "{err}");
        assert_eq!(server.await.unwrap(), "/svc/Tun");
    }

    #[tokio::test]
    async fn grpc_trailer_error_surfaces() {
        let (client, mut server) = tokio::io::duplex(4096);
        let settings = GrpcSettings {
            service_name: "svc".into(),
            host: Some("grpc.example.com".into()),
        };
        // The server half must speak while grpc_connect is still waiting
        // for its response headers, so run it as a task.
        let responder = tokio::spawn(async move {
            let ok = hpack::encode(&[(":status", "200"), ("content-type", "application/grpc")]);
            server
                .write_all(&frame_bytes(FT_HEADERS, FLAG_END_HEADERS, 1, &ok))
                .await
                .unwrap();
            let bad = hpack::encode(&[("grpc-status", "7")]);
            server
                .write_all(&frame_bytes(
                    FT_HEADERS,
                    FLAG_END_HEADERS | FLAG_END_STREAM,
                    1,
                    &bad,
                ))
                .await
                .unwrap();
        });
        let mut stream = grpc_connect(Box::new(client), &settings, "h.example.com")
            .await
            .unwrap();

        let mut buf = [0u8; 4];
        let err = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap_err();
        assert!(err.to_string().contains("grpc-status 7"), "{err}");
        responder.await.unwrap();
    }
}
