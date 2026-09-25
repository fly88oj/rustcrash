//! QUIC client plumbing (quinn) shared by the hysteria2 and TUIC v5
//! outbounds: endpoint construction on top of the engine's rustls TLS
//! stack (same verification behavior as the TCP transports), a boxed
//! stream adapter over a quinn stream pair, and the QUIC varint codec
//! used by the hysteria2 framing.

use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::error::{Error, Result};
use crate::transport::{tls_client_config, TlsSettings};

pub mod tls13;

/// Settings for one outbound QUIC connection.
#[derive(Debug, Clone)]
pub struct QuicDial {
    pub server: String,
    pub port: u16,
    /// TLS server name (SNI) used for the handshake.
    pub sni: String,
    /// ALPN protocol list offered to the server (e.g. `h3`, `tuic`).
    pub alpn: Vec<String>,
    /// Trust any server certificate (mirrors `skip-cert-verify`).
    pub skip_verify: bool,
    /// Whether QUIC datagrams are exchanged (UDP relay).
    pub udp_relay: bool,
    /// Requested Brutal congestion-control rate in bits/s. Recorded for
    /// parity with upstream configs, but quinn ships no Brutal
    /// implementation, so the transport keeps its default controller and
    /// simply accepts any bandwidth frames the server sends.
    pub congestion_brutal_bps: Option<u64>,
}

/// Resolve `server:port` to the first socket address, for the QUIC
/// handshake (UDP) and to pick the bind address family.
pub async fn resolve_remote(server: &str, port: u16) -> Result<SocketAddr> {
    let mut addrs = tokio::net::lookup_host((server, port))
        .await
        .map_err(|e| Error::dns(format!("resolve {server}:{port}: {e}")))?;
    addrs
        .next()
        .ok_or_else(|| Error::dns(format!("no address for {server}:{port}")))
}

/// A UDP bind address matching the remote's family, so IPv6 servers are
/// reached over IPv6 sockets.
pub(crate) fn family_bind_addr(remote: SocketAddr) -> SocketAddr {
    if remote.is_ipv6() {
        SocketAddr::from(([0u8; 16], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0], 0))
    }
}

/// Build the quinn client config: rustls (reusing the engine TLS
/// verification paths) with the ALPN list, plus transport settings
/// mirrored from the sing-quic defaults (datagrams for UDP relay, uni
/// streams, keep-alive).
pub fn client_config(cfg: &QuicDial) -> Result<quinn::ClientConfig> {
    let settings = TlsSettings {
        enabled: true,
        server_name: None,
        skip_cert_verify: cfg.skip_verify,
        alpn: Vec::new(),
    };
    let mut tls = (*tls_client_config(&settings)?).clone();
    tls.alpn_protocols = cfg.alpn.iter().map(|a| a.as_bytes().to_vec()).collect();

    let mut transport = quinn::TransportConfig::default();
    // TUIC (UDP-over-stream) and QPACK control streams arrive on uni
    // streams; 1024 is far above the traffic shape of these protocols.
    transport.max_concurrent_uni_streams(1024u32.into());
    if cfg.udp_relay {
        transport.datagram_receive_buffer_size(Some(64 * 1024));
    }
    transport.keep_alive_interval(Some(Duration::from_secs(10)));
    let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(Arc::new(tls))
        .map_err(|e| Error::config(format!("quic tls initial suite: {e}")))?;
    let mut quic = quinn::ClientConfig::new(Arc::new(quic_tls));
    quic.transport_config(Arc::new(transport));
    Ok(quic)
}

/// Open a client endpoint (UDP socket bound per address family) and
/// connect to the configured server.
pub async fn dial(cfg: &QuicDial) -> Result<quinn::Connection> {
    let remote = resolve_remote(&cfg.server, cfg.port).await?;
    let mut endpoint = quinn::Endpoint::client(family_bind_addr(remote))
        .map_err(|e| Error::network(format!("quic bind: {e}")))?;
    endpoint.set_default_client_config(client_config(cfg)?);
    let connect = endpoint
        .connect(remote, &cfg.sni)
        .map_err(|e| Error::config(format!("quic connect to {}: {e}", remote)))?;
    let conn = connect.await.map_err(|e| {
        Error::network(format!(
            "quic handshake with {} (sni {}, alpn {:?}): {e}",
            remote, cfg.sni, cfg.alpn
        ))
    })?;
    tracing::debug!(target: "engine", "quic connected to {remote} (sni {})", cfg.sni);
    Ok(conn)
}

/// A bidirectional QUIC stream pair exposed as a tokio duplex stream, so
/// `Box::new(QuicStream)` satisfies [`crate::stream::BoxProxyStream`].
pub struct QuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
}

impl QuicStream {
    pub fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        QuicStream { send, recv }
    }
}

impl AsyncRead for QuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for QuicStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

/// Append a QUIC varint (RFC 9000 section 16) to `buf`.
pub(crate) fn write_varint(buf: &mut Vec<u8>, v: u64) {
    if v <= 0x3f {
        buf.push(v as u8);
    } else if v <= 0x3fff {
        buf.push((v >> 8) as u8 | 0x40);
        buf.push(v as u8);
    } else if v <= 0x3fff_ffff {
        buf.extend_from_slice(&[(v >> 24) as u8 | 0x80, (v >> 16) as u8, (v >> 8) as u8, v as u8]);
    } else {
        buf.extend_from_slice(&[
            (v >> 56) as u8 | 0xc0,
            (v >> 48) as u8,
            (v >> 40) as u8,
            (v >> 32) as u8,
            (v >> 24) as u8,
            (v >> 16) as u8,
            (v >> 8) as u8,
            v as u8,
        ]);
    }
}

/// Length in bytes of `v` in QUIC varint form.
pub(crate) fn varint_len(v: u64) -> usize {
    if v <= 0x3f {
        1
    } else if v <= 0x3fff {
        2
    } else if v <= 0x3fff_ffff {
        4
    } else {
        8
    }
}

/// Try to read one QUIC varint from the front of `data`. Returns the
/// value and the number of bytes consumed.
pub(crate) fn read_varint(data: &[u8]) -> Option<(u64, usize)> {
    let first = *data.first()?;
    let len = 1usize << (first >> 6);
    if data.len() < len {
        return None;
    }
    let mut v = (first & 0x3f) as u64;
    for &b in &data[1..len] {
        v = (v << 8) | b as u64;
    }
    Some((v, len))
}

// ---------------------------------------------------------------------------
// Minimal HTTP/3 client helpers (RFC 9114 / RFC 9204), shared by the
// hysteria2 auth handshake and the DoH3 DNS upstream. Deliberately
// literal-only: QPACK fields use literal names/values (no dynamic table,
// no Huffman), which every compliant server accepts.
// ---------------------------------------------------------------------------

/// HTTP/3 frame types.
pub(crate) const H3_DATA: u64 = 0x0;
pub(crate) const H3_HEADERS: u64 = 0x1;
pub(crate) const H3_SETTINGS: u64 = 0x4;
/// Uni-stream types: control, QPACK encoder instructions, decoder.
pub(crate) const H3_STREAM_CONTROL: u64 = 0x0;
pub(crate) const H3_STREAM_QPACK_ENCODER: u64 = 0x2;
pub(crate) const H3_STREAM_QPACK_DECODER: u64 = 0x3;

/// Append `type || length || payload` (the HTTP/3 frame layout).
pub(crate) fn put_h3_frame(out: &mut Vec<u8>, frame_type: u64, payload: &[u8]) {
    write_varint(out, frame_type);
    write_varint(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

/// QPACK literal-field-line, literal name (RFC 9204 §4.5.4; never
/// indexed, no Huffman).
pub(crate) fn put_qpack_literal(block: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    put_prefixed_int(block, 0x20, 3, name.len() as u64);
    block.extend_from_slice(name);
    put_prefixed_int(block, 0x00, 7, value.len() as u64);
    block.extend_from_slice(value);
}

/// HPACK/QPACK integer (RFC 7541 §5.1) with a `prefix_bits`-wide prefix.
pub(crate) fn put_prefixed_int(buf: &mut Vec<u8>, flags: u8, prefix_bits: u32, v: u64) {
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

/// Open the three HTTP/3 connection-level uni streams (control + QPACK
/// encoder/decoder). The caller MUST keep the returned streams alive for
/// the connection lifetime — closing them is a fatal HTTP/3 error.
pub(crate) async fn h3_open_control(
    conn: &quinn::Connection,
    what: &str,
) -> Result<Vec<quinn::SendStream>> {
    let mut control = conn
        .open_uni()
        .await
        .map_err(|e| Error::network(format!("{what}: control stream: {e}")))?;
    let mut encoder = conn
        .open_uni()
        .await
        .map_err(|e| Error::network(format!("{what}: qpack encoder stream: {e}")))?;
    let mut decoder = conn
        .open_uni()
        .await
        .map_err(|e| Error::network(format!("{what}: qpack decoder stream: {e}")))?;
    let mut head = Vec::with_capacity(8);
    write_varint(&mut head, H3_STREAM_CONTROL);
    put_h3_frame(&mut head, H3_SETTINGS, &[]);
    control
        .write_all(&head)
        .await
        .map_err(|e| Error::network(format!("{what}: settings: {e}")))?;
    let mut t = Vec::with_capacity(8);
    write_varint(&mut t, H3_STREAM_QPACK_ENCODER);
    encoder
        .write_all(&t)
        .await
        .map_err(|e| Error::network(format!("{what}: qpack encoder type: {e}")))?;
    t.clear();
    write_varint(&mut t, H3_STREAM_QPACK_DECODER);
    decoder
        .write_all(&t)
        .await
        .map_err(|e| Error::network(format!("{what}: qpack decoder type: {e}")))?;
    Ok(vec![control, encoder, decoder])
}

/// Read an HTTP/3 response until FIN, returning the concatenated DATA
/// payloads. HEADERS/SETTINGS/padding frames are skipped (the caller
/// cares about the body).
pub(crate) async fn h3_read_data(recv: &mut quinn::RecvStream, what: &str) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut chunk = [0u8; 4096];
    let mut out = Vec::new();
    loop {
        // Try to parse one frame from the buffered bytes.
        if let Some((ftype, flen, hdr)) = read_frame_header(&buf) {
            let total = hdr + flen as usize;
            if buf.len() >= total {
                if ftype == H3_DATA {
                    out.extend_from_slice(&buf[hdr..total]);
                }
                buf.drain(..total);
                continue;
            }
        }
        match recv.read(&mut chunk).await {
            Ok(Some(n)) => buf.extend_from_slice(&chunk[..n]),
            Ok(None) => break,
            Err(e) => return Err(Error::network(format!("{what}: stream read: {e}"))),
        }
    }
    Ok(out)
}

/// Parse `frame_type || length` at the front of `data`; returns
/// (type, length, header_bytes).
fn read_frame_header(data: &[u8]) -> Option<(u64, u64, usize)> {
    let (ftype, a) = read_varint(data)?;
    let (flen, b) = read_varint(data.get(a..)?)?;
    Some((ftype, flen, a + b))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn varint_known_encodings() {
        // Vectors from RFC 9000 section 16.
        let cases: &[(u64, &[u8])] = &[
            (0, &[0x00]),
            (63, &[0x3f]),
            (64, &[0x40, 0x40]),
            (16383, &[0x7f, 0xff]),
            (16384, &[0x80, 0x00, 0x40, 0x00]),
            (1073741823, &[0xbf, 0xff, 0xff, 0xff]),
            (1073741824, &[0xc0, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00]),
            (151288809941952652, &[0xc2, 0x19, 0x7c, 0x5e, 0xff, 0x14, 0xe8, 0x8c]),
        ];
        for (v, bytes) in cases {
            let mut buf = Vec::new();
            write_varint(&mut buf, *v);
            assert_eq!(&buf, *bytes, "encode {v}");
            assert_eq!(varint_len(*v), bytes.len(), "len {v}");
            assert_eq!(read_varint(bytes).unwrap(), (*v, bytes.len()), "decode {v}");
        }
        // The hysteria2 TCP request frame type 0x401 uses the 2-byte form.
        let mut buf = Vec::new();
        write_varint(&mut buf, 0x401);
        assert_eq!(buf, vec![0x44, 0x01]);
    }

    #[test]
    fn varint_roundtrip_all_lengths() {
        let samples = [
            0u64, 1, 0x3f, 0x40, 0x1234, 0x3fff, 0x4000, 0xdead_beef, 0x3fff_ffff, 0x4000_0000,
            u64::MAX >> 2,
        ];
        for v in samples {
            let mut buf = Vec::new();
            write_varint(&mut buf, v);
            let (got, used) = read_varint(&buf).expect("parses");
            assert_eq!(got, v);
            assert_eq!(used, buf.len());
            // A trailing byte must not be consumed.
            buf.push(0xff);
            assert_eq!(read_varint(&buf).unwrap(), (v, used));
        }
    }

    #[test]
    fn varint_rejects_truncated() {
        let mut buf = Vec::new();
        write_varint(&mut buf, 0x3fff_ffff);
        for cut in 0..buf.len() {
            assert!(read_varint(&buf[..cut]).is_none(), "cut {cut}");
        }
        assert!(read_varint(&[]).is_none());
    }

    #[test]
    fn quic_stream_is_boxable() {
        // Compile-time check that QuicStream satisfies the proxy stream
        // bounds once boxed.
        fn assert_boxed(_: Box<dyn crate::stream::ProxyStream>) {}
        fn make(send: quinn::SendStream, recv: quinn::RecvStream) {
            assert_boxed(Box::new(QuicStream::new(send, recv)));
        }
        // Never executed: only the bounds above must compile.
        let _ = make;
    }
}
