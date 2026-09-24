//! VLESS outbound (XTLS spec, plain form): version 0 header, UUID, command,
//! address. `flow` variants (Vision/XTLS) are rejected at config load.

use std::io;
use std::pin::Pin;
use std::task::{ready, Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use crate::addr::{encode_socks_addr, NetAddr};
use crate::error::{Error, Result};
use crate::stream::BoxProxyStream;

const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x02;

/// Outbound VLESS endpoint.
#[derive(Debug, Clone)]
pub struct VlessOut {
    pub server: String,
    pub port: u16,
    pub uuid: uuid::Uuid,
}

/// A VLESS stream: the header rides the first write; afterwards the
/// connection is a plain pass-through.
pub struct VlessStream {
    inner: BoxProxyStream,
    /// First payload to prepend (header + optional initial data).
    pending: Vec<u8>,
    /// Response header (version + addons-length + addons) consumption state.
    consumed_resp_header: bool,
    resp_hdr_buf: Vec<u8>,
}

impl VlessStream {
    pub async fn handshake(
        transport: BoxProxyStream,
        cfg: &VlessOut,
        target: &NetAddr,
        is_udp: bool,
    ) -> Result<Self> {
        Self::handshake_with_addons(transport, cfg, target, is_udp, None).await
    }

    /// Handshake with a custom request-addons field. `addons` replaces the
    /// whole field (length byte INCLUDED) — the vision flow passes
    /// [`crate::proto::vision::vision_request_addons`] here.
    pub async fn handshake_with_addons(
        transport: BoxProxyStream,
        cfg: &VlessOut,
        target: &NetAddr,
        is_udp: bool,
        addons: Option<&[u8]>,
    ) -> Result<Self> {
        let mut hdr = Vec::with_capacity(48);
        hdr.push(0x00); // version
        hdr.extend_from_slice(cfg.uuid.as_bytes());
        match addons {
            Some(bytes) => hdr.extend_from_slice(bytes),
            None => hdr.push(0x00), // empty addons
        }
        hdr.push(if is_udp { CMD_UDP } else { CMD_TCP });
        // mihomo's vless shares sing-vmess's AddressSerializer: port first.
        crate::addr::encode_port_first_addr(&mut hdr, &target.host, target.port);
        Ok(VlessStream {
            inner: transport,
            pending: hdr,
            consumed_resp_header: false,
            resp_hdr_buf: Vec::new(),
        })
    }
}

impl AsyncWrite for VlessStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        if !self.pending.is_empty() {
            let hdr = std::mem::take(&mut self.pending);
            ready!(ready_write_all(&mut self.inner, cx, &hdr))?;
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

impl AsyncRead for VlessStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        // Response: version(1) + addons-length(1) then data.
        if !self.consumed_resp_header {
            // Read exactly two bytes using the pending buffer.
            while self.resp_hdr_buf.len() < 2 {
                let mut tmp = [0u8; 2];
                let want = 2 - self.resp_hdr_buf.len();
                let mut rb = ReadBuf::new(&mut tmp[..want]);
                ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
                if rb.filled().is_empty() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "vless: truncated response header",
                    )));
                }
                self.resp_hdr_buf.extend_from_slice(rb.filled());
            }
            let addons_len = self.resp_hdr_buf[1] as usize;
            // addons are rare; skip them.
            while self.resp_hdr_buf.len() < 2 + addons_len {
                let mut tmp = [0u8; 64];
                let mut rb = ReadBuf::new(&mut tmp);
                ready!(Pin::new(&mut self.inner).poll_read(cx, &mut rb))?;
                if rb.filled().is_empty() {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "vless: truncated response addons",
                    )));
                }
                self.resp_hdr_buf.extend_from_slice(rb.filled());
            }
            self.consumed_resp_header = true;
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

fn ready_write_all(
    inner: &mut BoxProxyStream,
    cx: &mut Context<'_>,
    mut data: &[u8],
) -> Poll<io::Result<()>> {
    while !data.is_empty() {
        let n = ready!(Pin::new(&mut *inner).poll_write(cx, data))?;
        if n == 0 {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "vless: transport accepted zero bytes",
            )));
        }
        data = &data[n..];
    }
    Poll::Ready(Ok(()))
}

/// Frame one UDP datagram in the VLESS UDP-over-TCP form:
/// `socks-addr || len-be16 || payload`.
pub fn vless_udp_frame(target: &NetAddr, data: &[u8]) -> Result<Vec<u8>> {
    let len = u16::try_from(data.len())
        .map_err(|_| Error::protocol("vless udp datagram exceeds 65535 bytes"))?;
    let mut out = Vec::with_capacity(data.len() + 32);
    encode_socks_addr(&mut out, &target.host, target.port);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::Host;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};



    #[tokio::test]
    async fn handshake_header_bytes() {
        // Pipe the stream into a duplex and inspect the first bytes written.
        let (client, mut server) = tokio::io::duplex(64);
        let out = VlessOut {
            server: "x".into(),
            port: 1,
            uuid: uuid::Uuid::parse_str("b831381d-6324-4d53-ad4f-8cda48b30811").unwrap(),
        };
        let target = NetAddr::domain("hdr.test", 8080).unwrap();
        let mut stream = VlessStream::handshake(Box::new(client), &out, &target, false)
            .await
            .unwrap();
        stream.write_all(b"zz").await.unwrap();
        stream.flush().await.unwrap();
        drop(stream);
        let mut seen = Vec::new();
        server.read_to_end(&mut seen).await.unwrap();
        // version(0) uuid(16) addons-len(0) cmd(1) port-atyp-addr
        assert_eq!(seen[0], 0);
        assert_eq!(&seen[1..17], out.uuid.as_bytes());
        assert_eq!(seen[17], 0);
        assert_eq!(seen[18], CMD_TCP);
        let (addr, used) = crate::addr::decode_port_first_addr(&seen[19..]).unwrap();
        assert_eq!(addr.host, Host::Domain("hdr.test".into()));
        assert_eq!(addr.port, 8080);
        assert_eq!(&seen[19 + used..], b"zz");
    }
}
