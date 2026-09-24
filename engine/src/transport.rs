//! Transport upgrades for outbound connections: TLS (rustls) and
//! WebSocket (RFC 6455 client side).

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use base64::Engine;
use bytes::{Buf, BytesMut};
use rand::RngCore;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::ring as ring_provider;
use rustls::{ClientConfig, DigitallySignedStruct, RootCertStore, SignatureScheme};
use sha1::{Digest, Sha1};
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::addr::Host;
use crate::error::{Error, Result};
use crate::stream::BoxProxyStream;

/// TLS settings for one outbound.
#[derive(Debug, Clone, Default)]
pub struct TlsSettings {
    pub enabled: bool,
    pub server_name: Option<String>,
    pub skip_cert_verify: bool,
    /// ALPN protocol list (e.g. ["h2"] for the gRPC transport).
    pub alpn: Vec<String>,
}

impl TlsSettings {
    /// Verified client TLS for `name` (DoT/DoH internal clients).
    pub fn client(name: &str) -> Self {
        TlsSettings {
            enabled: true,
            server_name: Some(name.to_string()),
            skip_cert_verify: false,
            alpn: Vec::new(),
        }
    }
}

/// Read one HTTP head (through `\r\n\r\n`, capped at 16 KiB) from a
/// boxed stream. Shared by the ws, httpupgrade and http-in paths.
pub async fn read_head(
    transport: &mut BoxProxyStream,
    what: &str,
) -> Result<String> {
    use tokio::io::AsyncReadExt;
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        let n = transport.read(&mut byte).await?;
        if n == 0 {
            return Err(Error::protocol(format!("{what}: EOF before headers")));
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            return Err(Error::protocol(format!("{what}: head too large")));
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Accept-anything verifier used when `skip-cert-verify` is set (mirrors
/// mihomo's behaviour; loudly logged by the engine when active).
#[derive(Debug)]
struct NoVerify(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &rustls::pki_types::CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.0.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

fn root_store() -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    let mut loaded = 0usize;
    let certs = rustls_native_certs::load_native_certs()
        .map_err(|e| Error::config(format!("native cert store: {e}")))?;
    for cert in certs {
        roots
            .add(cert)
            .map_err(|e| Error::config(format!("bad native cert: {e}")))?;
        loaded += 1;
    }
    if loaded == 0 {
        // Containers without a system store: fall back to the bundled
        // webpki roots so TLS still works out of the box.
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    Ok(roots)
}

/// Build a rustls ClientConfig honoring the settings.
pub fn tls_client_config(settings: &TlsSettings) -> Result<Arc<ClientConfig>> {
    let provider = Arc::new(ring_provider::default_provider());
    let builder = ClientConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::config(format!("tls: {e}")))?;
    let mut config = if settings.skip_cert_verify {
        builder
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify(provider)))
            .with_no_client_auth()
    } else {
        let roots = root_store()?;
        builder
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    if !settings.alpn.is_empty() {
        config.alpn_protocols = settings
            .alpn
            .iter()
            .map(|p| p.as_bytes().to_vec())
            .collect();
    }
    Ok(Arc::new(config))
}

/// A boxed stream wrapped so tokio-rustls can drive it (rustls requires
/// a concrete AsyncRead + AsyncWrite).
struct UnpinAdapter(BoxProxyStream);

impl AsyncRead for UnpinAdapter {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl AsyncWrite for UnpinAdapter {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// Perform a TLS handshake over an existing stream.
pub async fn tls_connect(
    transport: BoxProxyStream,
    server_name: &str,
    settings: &TlsSettings,
) -> Result<BoxProxyStream> {
    let config = tls_client_config(settings)?;
    let name = rustls::pki_types::ServerName::try_from(server_name.to_owned())
        .map_err(|_| Error::config(format!("invalid TLS server name {server_name:?}")))?;
    let connector = tokio_rustls::TlsConnector::from(config);
    let stream = connector
        .connect(name, UnpinAdapter(transport))
        .await
        .map_err(|e| Error::network(format!("tls handshake with {server_name}: {e}")))?;
    Ok(Box::new(stream))
}

/// v2ray httpupgrade transport: an HTTP/1.1 Upgrade handshake that
/// leaves a RAW byte stream (no WebSocket framing) after the 101.
pub async fn httpupgrade_connect(
    mut transport: BoxProxyStream,
    path: &str,
    host: &str,
) -> Result<BoxProxyStream> {
    let path = if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    };
    let req = format!(
        "GET {path} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nUser-Agent: rustcrash\r\n\r\n"
    );
    transport.write_all(req.as_bytes()).await?;

    let head = read_head(&mut transport, "httpupgrade").await?;
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    if !status.contains(" 101") {
        return Err(Error::protocol(format!("httpupgrade: unexpected status {status:?}")));
    }
    let mut ok_connection = false;
    let mut ok_upgrade = false;
    for line in lines {
        let Some((k, v)) = line.split_once(':') else { continue };
        let v = v.trim();
        if k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("upgrade") {
            ok_connection = true;
        }
        if k.eq_ignore_ascii_case("upgrade") && v.eq_ignore_ascii_case("websocket") {
            ok_upgrade = true;
        }
    }
    if !ok_connection || !ok_upgrade {
        return Err(Error::protocol("httpupgrade: missing Upgrade headers in 101"));
    }
    // The byte-at-a-time head read never crosses into the body, so the
    // stream resumes exactly at the tunnel's first byte.
    Ok(transport)
}

/// WebSocket client settings.
#[derive(Debug, Clone)]
pub struct WsSettings {
    pub path: String,
    pub host: Option<String>,
}

impl Default for WsSettings {
    fn default() -> Self {
        WsSettings {
            path: "/".to_string(),
            host: None,
        }
    }
}

/// Maximum payload bytes that can ride the ws handshake as early data
/// (v2ray/Xray 0-RTT convention: base64url of 757 bytes stays well
/// under header-size limits).
pub const WS_MAX_EARLY_DATA: usize = 757;

/// Perform a WebSocket client handshake and return a framed binary stream.
pub async fn ws_connect(
    transport: BoxProxyStream,
    settings: &WsSettings,
    default_host: &str,
) -> Result<BoxProxyStream> {
    ws_connect_early(transport, settings, default_host, &[]).await
}

/// `ws_connect` with 0-RTT early data (v2ray/Xray ws convention): the
/// caller supplies the first relayed bytes in `early` (at most
/// [`WS_MAX_EARLY_DATA`]); they ride the handshake as
/// `Sec-WebSocket-Protocol: <base64url, no padding>` instead of a data
/// frame. The returned stream never replays them — its first write
/// carries whatever follows `early`. Only a server that understands the
/// convention (early-data-header ws) will treat the header as payload;
/// a plain ws server would ignore the subprotocol, so callers gate
/// this on their remote configuration.
pub async fn ws_connect_early(
    mut transport: BoxProxyStream,
    settings: &WsSettings,
    default_host: &str,
    early: &[u8],
) -> Result<BoxProxyStream> {
    if early.len() > WS_MAX_EARLY_DATA {
        return Err(Error::protocol(format!(
            "ws: early data exceeds {WS_MAX_EARLY_DATA} bytes"
        )));
    }
    let host = settings.host.clone().unwrap_or_else(|| default_host.to_string());
    let mut key_bytes = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut key_bytes);
    let key = base64::engine::general_purpose::STANDARD.encode(key_bytes);
    let early_header = if early.is_empty() {
        String::new()
    } else {
        format!(
            "Sec-WebSocket-Protocol: {}\r\n",
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(early)
        )
    };

    let req = format!(
        "GET {} HTTP/1.1\r\nHost: {host}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n{early_header}\r\n",
        settings.path
    );
    transport.write_all(req.as_bytes()).await?;

    let head = read_head(&mut transport, "ws").await?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| Error::protocol("ws: empty handshake response"))?;
    let code = status_line
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| Error::protocol(format!("ws: malformed status line {status_line:?}")))?;
    if code != 101 {
        return Err(Error::protocol(format!("ws: upgrade rejected with {code}")));
    }
    let expected_accept = {
        let mut h = Sha1::new();
        h.update(key.as_bytes());
        h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        base64::engine::general_purpose::STANDARD.encode(h.finalize())
    };
    let accept = lines.find_map(|l| {
        let (name, value) = l.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("sec-websocket-accept")
            .then(|| value.trim().to_string())
    });
    match accept {
        Some(a) if a == expected_accept => {}
        Some(_) => return Err(Error::protocol("ws: Sec-WebSocket-Accept mismatch")),
        None => return Err(Error::protocol("ws: missing Sec-WebSocket-Accept")),
    }
    Ok(Box::new(WsStream {
        inner: transport,
        rbuf: BytesMut::with_capacity(16 * 1024),
        plain: BytesMut::with_capacity(16 * 1024),
        wbuf: BytesMut::new(),
        pending_plain: 0,
        ctrl_buf: BytesMut::new(),
        closed: false,
    }))
}

/// A client-side WebSocket binary stream (client→server frames masked).
pub struct WsStream {
    inner: BoxProxyStream,
    rbuf: BytesMut,
    plain: BytesMut,
    wbuf: BytesMut,
    pending_plain: usize,
    /// Queued control frames (pong/close) pending a write opportunity.
    ctrl_buf: BytesMut,
    closed: bool,
}

const OP_CONT: u8 = 0x0;
const OP_TEXT: u8 = 0x1;
const OP_BINARY: u8 = 0x2;
const OP_CLOSE: u8 = 0x8;
const OP_PING: u8 = 0x9;
const OP_PONG: u8 = 0xA;

impl WsStream {
    fn build_frame(opcode: u8, payload: &[u8], out: &mut Vec<u8>) {
        out.push(0x80 | opcode); // FIN + opcode
        let mask_bit = 0x80;
        match payload.len() {
            n if n < 126 => out.push(mask_bit | n as u8),
            n if n <= 0xFFFF => {
                out.push(mask_bit | 126);
                out.extend_from_slice(&(n as u16).to_be_bytes());
            }
            n => {
                out.push(mask_bit | 127);
                out.extend_from_slice(&(n as u64).to_be_bytes());
            }
        }
        let mut mask = [0u8; 4];
        rand::rngs::OsRng.fill_bytes(&mut mask);
        out.extend_from_slice(&mask);
        for (i, b) in payload.iter().enumerate() {
            out.push(b ^ mask[i % 4]);
        }
    }

    /// Try to parse one complete frame from `rbuf`; returns payload bytes
    /// (or None when incomplete). Control frames are handled inline.
    fn parse_frame(&mut self) -> Result<Option<(u8, Vec<u8>)>> {
        if self.rbuf.len() < 2 {
            return Ok(None);
        }
        let b0 = self.rbuf[0];
        let b1 = self.rbuf[1];
        let opcode = b0 & 0x0F;
        let masked = b1 & 0x80 != 0;
        let len = (b1 & 0x7F) as u64;
        let mut off = 2usize;
        let len = match len {
            126 => {
                if self.rbuf.len() < 4 {
                    return Ok(None);
                }
                let v = u16::from_be_bytes([self.rbuf[2], self.rbuf[3]]) as u64;
                off = 4;
                v
            }
            127 => {
                if self.rbuf.len() < 10 {
                    return Ok(None);
                }
                let mut b = [0u8; 8];
                b.copy_from_slice(&self.rbuf[2..10]);
                off = 10;
                u64::from_be_bytes(b)
            }
            v => v,
        };
        let mask_len = if masked { 4 } else { 0 };
        let total = off + mask_len + len as usize;
        if self.rbuf.len() < total {
            return Ok(None);
        }
        let mask = if masked {
            let mut m = [0u8; 4];
            m.copy_from_slice(&self.rbuf[off..off + 4]);
            m
        } else {
            [0u8; 4]
        };
        let mut payload = self.rbuf[off + mask_len..total].to_vec();
        if masked {
            for (i, b) in payload.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }
        self.rbuf.advance(total);
        Ok(Some((opcode, payload)))
    }
}

impl AsyncWrite for WsStream {
    fn poll_write(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let this = self.get_mut();
        if this.wbuf.is_empty() {
            let mut frame = Vec::with_capacity(buf.len() + 14);
            // Cap chunk at 16 KiB to bound memory.
            let take = buf.len().min(16 * 1024);
            Self::build_frame(OP_BINARY, &buf[..take], &mut frame);
            this.wbuf = BytesMut::from(&frame[..]);
            this.pending_plain = take;
        }
        while !this.wbuf.is_empty() {
            let n = ready!(Pin::new(&mut this.inner).poll_write(cx, &this.wbuf))?;
            if n == 0 {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "ws: transport accepted zero bytes",
                )));
            }
            this.wbuf.advance(n);
        }
        Poll::Ready(Ok(this.pending_plain))
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        // Best-effort close frame, then TCP shutdown.
        let this = self.get_mut();
        if !this.closed {
            this.closed = true;
            let mut frame = Vec::new();
            Self::build_frame(OP_CLOSE, &1000u16.to_be_bytes(), &mut frame);
            this.ctrl_buf.extend_from_slice(&frame);
        }
        if this.flush_ctrl(cx).is_ok() {
            return Pin::new(&mut this.inner).poll_shutdown(cx);
        }
        Poll::Pending
    }
}

impl AsyncRead for WsStream {
    fn poll_read(self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            // Drain queued control frames when the transport is writable.
            let _ = this.flush_ctrl(cx);
            if !this.plain.is_empty() {
                let n = this.plain.len().min(buf.remaining());
                buf.put_slice(&this.plain[..n]);
                this.plain.advance(n);
                return Poll::Ready(Ok(()));
            }
            match this.parse_frame().map_err(io_invalid)? {
                Some((opcode, payload)) => match opcode {
                    OP_BINARY | OP_TEXT | OP_CONT => {
                        this.plain.extend_from_slice(&payload);
                    }
                    OP_PING => {
                        let mut frame = Vec::new();
                        Self::build_frame(OP_PONG, &payload, &mut frame);
                        this.ctrl_buf.extend_from_slice(&frame);
                    }
                    OP_CLOSE => {
                        if !this.closed {
                            this.closed = true;
                            let mut frame = Vec::new();
                            Self::build_frame(OP_CLOSE, &payload, &mut frame);
                            this.ctrl_buf.extend_from_slice(&frame);
                        }
                        if this.flush_ctrl(cx)? {
                            return Poll::Ready(Ok(()));
                        }
                    }
                    _ => {}
                },
                None => {
                    let mut tmp = [0u8; 16 * 1024];
                    let mut rb = ReadBuf::new(&mut tmp);
                    ready!(Pin::new(&mut this.inner).poll_read(cx, &mut rb))?;
                    if rb.filled().is_empty() {
                        return Poll::Ready(Ok(()));
                    }
                    this.rbuf.extend_from_slice(rb.filled());
                }
            }
        }
    }
}

impl WsStream {
    /// Best-effort drain of queued control frames; returns true when the
    /// queue is empty.
    fn flush_ctrl(&mut self, cx: &mut Context<'_>) -> io::Result<bool> {
        while !self.ctrl_buf.is_empty() {
            match Pin::new(&mut self.inner).poll_write(cx, &self.ctrl_buf) {
                Poll::Ready(Ok(0)) => {
                    return Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "ws: transport accepted zero bytes",
                    ))
                }
                Poll::Ready(Ok(n)) => {
                    self.ctrl_buf.advance(n);
                }
                Poll::Ready(Err(e)) => return Err(e),
                Poll::Pending => return Ok(false),
            }
        }
        Ok(true)
    }
}

fn io_invalid(e: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

/// Resolve which server name to use for TLS (explicit SNI wins, else the
/// target host when it is a domain, else the server address string).
pub fn effective_sni(settings: &TlsSettings, server: &str, target: Option<&Host>) -> String {
    settings
        .server_name
        .clone()
        .or_else(|| {
            target
                .and_then(|h| h.as_domain().map(|d| d.to_string()))
        })
        .unwrap_or_else(|| server.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncReadExt;

    #[tokio::test]
    async fn ws_handshake_and_echo() {
        let (client, mut server) = tokio::io::duplex(1024);
        // Minimal ws server: validate key, reply accept, echo frames.
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                server.read_exact(&mut byte).await.unwrap();
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let req = String::from_utf8_lossy(&buf).to_string();
            let key = req
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("sec-websocket-key:"))
                .unwrap()
                .split_once(':')
                .unwrap()
                .1
                .trim()
                .to_string();
            let mut h = Sha1::new();
            h.update(key.as_bytes());
            h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
            let accept = base64::engine::general_purpose::STANDARD.encode(h.finalize());
            server
                .write_all(
                    format!(
                        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                         Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            // Read one masked binary frame, reply with an unmasked one.
            let mut head = [0u8; 2];
            server.read_exact(&mut head).await.unwrap();
            assert_eq!(head[0] & 0x0F, OP_BINARY);
            let len = head[1] & 0x7F;
            assert_eq!(len, 4);
            let mut rest = [0u8; 8]; // 4 mask + 4 payload
            server.read_exact(&mut rest).await.unwrap();
            let mut plain = Vec::new();
            for (i, b) in rest[4..].iter().enumerate() {
                plain.push(b ^ rest[i % 4]);
            }
            assert_eq!(&plain, b"ping");
            let mut frame = vec![0x82, 4];
            frame.extend_from_slice(b"pong");
            server.write_all(&frame).await.unwrap();
        });
        let settings = WsSettings {
            path: "/ws".into(),
            host: Some("ws.test".into()),
        };
        let mut stream = ws_connect(Box::new(client), &settings, "fallback").await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"pong");
    }

    /// Fake ws server: read the request head, hand it to `inspect`, then
    /// answer 101 with a valid accept.
    async fn ws_fake_server(
        mut server: tokio::io::DuplexStream,
        inspect: impl FnOnce(&str) + Send + 'static,
    ) {
        use tokio::io::AsyncWriteExt;
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = server.read(&mut byte).await.unwrap();
            if n == 0 {
                panic!("ws server: EOF before request head");
            }
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let req = String::from_utf8_lossy(&buf).to_string();
        inspect(&req);
        let key = req
            .lines()
            .find(|l| l.to_ascii_lowercase().starts_with("sec-websocket-key:"))
            .unwrap()
            .split_once(':')
            .unwrap()
            .1
            .trim()
            .to_string();
        let mut h = Sha1::new();
        h.update(key.as_bytes());
        h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        let accept = base64::engine::general_purpose::STANDARD.encode(h.finalize());
        server
            .write_all(
                format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                     Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn ws_early_data_rides_handshake() {
        let (client, server) = tokio::io::duplex(1024);
        // Bytes whose standard base64 would contain +/ and padding: the
        // wire value proves the URL-safe no-pad alphabet.
        let early: [u8; 7] = [0xfb, 0xef, 0xbe, 0xff, 0x00, 0x42, 0x7f];
        let handle = tokio::spawn(async move {
            let mut server = server;
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                server.read_exact(&mut byte).await.unwrap();
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let req = String::from_utf8_lossy(&buf).to_string();
            let protocol = req
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("sec-websocket-protocol:"));
            assert_eq!(protocol, Some("Sec-WebSocket-Protocol: ----_wBCfw"));
            let key = req
                .lines()
                .find(|l| l.to_ascii_lowercase().starts_with("sec-websocket-key:"))
                .unwrap()
                .split_once(':')
                .unwrap()
                .1
                .trim()
                .to_string();
            let mut h = Sha1::new();
            h.update(key.as_bytes());
            h.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
            let accept = base64::engine::general_purpose::STANDARD.encode(h.finalize());
            server
                .write_all(
                    format!(
                        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                         Connection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
            // The stream must NOT replay the early bytes: the first
            // frame carries only what was written after the handshake.
            let mut head = [0u8; 2];
            server.read_exact(&mut head).await.unwrap();
            assert_eq!(head[0] & 0x0F, OP_BINARY);
            assert_eq!(head[1] & 0x7F, 4); // "tail", no early prefix
            let mut rest = [0u8; 8]; // 4 mask + 4 payload
            server.read_exact(&mut rest).await.unwrap();
            let plain: Vec<u8> = rest[4..]
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ rest[i % 4])
                .collect();
            assert_eq!(plain, b"tail".to_vec());
            // First client read yields only bytes sent after the
            // handshake.
            server.write_all(&[0x81, 2, b'o', b'k']).await.unwrap();
        });
        let settings = WsSettings::default();
        let mut stream = ws_connect_early(Box::new(client), &settings, "ed.test", &early)
            .await
            .unwrap();
        stream.write_all(b"tail").await.unwrap();
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"ok");
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn ws_plain_connect_omits_subprotocol() {
        let (client, server) = tokio::io::duplex(1024);
        let handle = tokio::spawn(ws_fake_server(server, |req| {
            assert!(!req.to_ascii_lowercase().contains("sec-websocket-protocol"));
        }));
        let settings = WsSettings::default();
        let _stream = ws_connect(Box::new(client), &settings, "plain.test")
            .await
            .unwrap();
        handle.await.unwrap();
    }

    #[tokio::test]
    async fn ws_early_data_over_limit_rejected() {
        let (client, mut server) = tokio::io::duplex(64);
        let too_big = [0u8; WS_MAX_EARLY_DATA + 1];
        let err = match ws_connect_early(
            Box::new(client),
            &WsSettings::default(),
            "cap.test",
            &too_big,
        )
        .await
        {
            Err(e) => e,
            Ok(_) => panic!("expected the early-data cap to reject the payload"),
        };
        assert!(err.to_string().contains("757"), "{err}");
        // The oversized payload never reaches the transport.
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(std::time::Duration::from_secs(2), server.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn frame_layout_known_bytes() {
        // Small masked binary frame: header 0x82, mask bit + len, 4 mask
        // bytes, then payload XOR mask.
        let mut out = Vec::new();
        WsStream::build_frame(OP_BINARY, b"abcd", &mut out);
        assert_eq!(out[0], 0x82);
        assert_eq!(out[1], 0x80 | 4);
        let mask = [out[2], out[3], out[4], out[5]];
        for (i, b) in b"abcd".iter().enumerate() {
            assert_eq!(out[6 + i], b ^ mask[i % 4]);
        }
    }

    #[test]
    fn effective_sni_priority() {
        let tls = TlsSettings {
            enabled: true,
            server_name: Some("sni.example".into()),
            skip_cert_verify: false,
            alpn: Vec::new(),
        };
        assert_eq!(
            effective_sni(&tls, "1.2.3.4", Some(&Host::Domain("target.example".into()))),
            "sni.example"
        );
        let tls = TlsSettings::default();
        assert_eq!(
            effective_sni(&tls, "1.2.3.4", Some(&Host::Domain("target.example".into()))),
            "target.example"
        );
        assert_eq!(effective_sni(&tls, "5.6.7.8", None), "5.6.7.8");
    }
}
