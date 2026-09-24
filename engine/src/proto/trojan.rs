//! Trojan outbound: SHA-224 password hex, command byte, socks-style
//! target, CRLF; UDP associate uses length-prefixed addressed frames.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use sha2::{Digest, Sha224};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::addr::{encode_socks_addr, NetAddr};
use crate::error::Result;
use crate::stream::BoxProxyStream;

const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x03;

/// Outbound Trojan endpoint.
#[derive(Debug, Clone)]
pub struct TrojanOut {
    pub server: String,
    pub port: u16,
    pub password: String,
}

/// The hex(SHA-224(password)) sent on the wire.
pub fn trojan_password_hex(password: &str) -> String {
    let digest = Sha224::digest(password.as_bytes());
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

/// A Trojan client stream.
pub struct TrojanStream {
    inner: BoxProxyStream,
    /// Request header, flushed before the first payload byte.
    pending: Option<Vec<u8>>,
}

impl TrojanStream {
    pub async fn handshake(
        transport: BoxProxyStream,
        cfg: &TrojanOut,
        target: &NetAddr,
        is_udp: bool,
    ) -> Result<Self> {
        let mut hdr = Vec::with_capacity(96);
        hdr.extend_from_slice(trojan_password_hex(&cfg.password).as_bytes());
        hdr.extend_from_slice(b"\r\n");
        hdr.push(if is_udp { CMD_UDP } else { CMD_TCP });
        encode_socks_addr(&mut hdr, &target.host, target.port);
        hdr.extend_from_slice(b"\r\n");
        Ok(TrojanStream {
            inner: transport,
            pending: Some(hdr),
        })
    }
}

impl AsyncWrite for TrojanStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if let Some(hdr) = self.pending.take() {
            ready!(write_all_pin(&mut self.inner, cx, &hdr))?;
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for TrojanStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        // Trojan responses carry no header — data starts immediately.
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

fn write_all_pin(inner: &mut BoxProxyStream, cx: &mut Context<'_>, mut data: &[u8]) -> Poll<io::Result<()>> {
    while !data.is_empty() {
        let n = ready!(Pin::new(&mut *inner).poll_write(cx, data))?;
        if n == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "trojan: transport accepted zero bytes",
            )));
        }
        data = &data[n..];
    }
    Poll::Ready(Ok(()))
}


/// Encode a trojan UDP datagram: `socks-addr || len-be16 || CRLF ||
/// payload` (upstream: mihomo transport/trojan writePacket, Xray
/// trojan/protocol.go).
pub fn trojan_udp_frame(target: &crate::addr::NetAddr, data: &[u8]) -> Result<Vec<u8>> {
    let len = u16::try_from(data.len())
        .map_err(|_| crate::error::Error::protocol("trojan udp datagram exceeds 65535 bytes"))?;
    let mut out = Vec::with_capacity(data.len() + 32);
    crate::addr::encode_socks_addr(&mut out, &target.host, target.port);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(data);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::decode_socks_addr;
    use crate::addr::Host;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn password_hash_known_vector() {
        // SHA-224("password"), cross-checked against Python hashlib.
        assert_eq!(
            trojan_password_hex("password"),
            "d63dc919e201d7bc4c825630d2cf25fdc93d4b2f0d46706d29038d01"
        );
    }

    #[tokio::test]
    async fn handshake_header_bytes() {
        let (client, mut server) = tokio::io::duplex(128);
        let out = TrojanOut {
            server: "x".into(),
            port: 1,
            password: "password".into(),
        };
        let target = NetAddr::domain("t.test", 443).unwrap();
        let mut stream = TrojanStream::handshake(Box::new(client), &out, &target, false)
            .await
            .unwrap();
        stream.write_all(b"data").await.unwrap();
        stream.flush().await.unwrap();
        drop(stream);
        let mut seen = Vec::new();
        server.read_to_end(&mut seen).await.unwrap();
        let hash = trojan_password_hex("password");
        assert_eq!(&seen[..56], hash.as_bytes());
        assert_eq!(&seen[56..58], b"\r\n");
        assert_eq!(seen[58], CMD_TCP);
        let (addr, used) = decode_socks_addr(&seen[59..]).unwrap();
        assert_eq!(addr.host, Host::Domain("t.test".into()));
        assert_eq!(&seen[59 + used..59 + used + 2], b"\r\n");
        assert_eq!(&seen[59 + used + 2..], b"data");
    }

}
