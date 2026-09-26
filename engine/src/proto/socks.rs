//! SOCKS5 outbound client (RFC 1928): CONNECT and UDP ASSOCIATE.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::addr::{decode_socks_addr, encode_socks_addr, Host, NetAddr};
use crate::error::{Error, Result};
use crate::stream::BoxProxyStream;

/// Outbound SOCKS5 endpoint.
#[derive(Debug, Clone)]
pub struct SocksOut {
    pub server: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
}

/// A connected SOCKS5 TCP tunnel (handshake complete).
pub struct SocksStream {
    inner: BoxProxyStream,
}

impl SocksStream {
    pub async fn handshake(
        transport: BoxProxyStream,
        cfg: &SocksOut,
        target: &NetAddr,
    ) -> Result<Self> {
        let mut transport = transport;
        negotiate(&mut transport, cfg).await?;
        let mut req = vec![0x05, 0x01, 0x00];
        encode_socks_addr(&mut req, &target.host, target.port);
        transport.write_all(&req).await?;
        let (code, _bind) = read_socks_reply(&mut transport).await?;
        if code != 0x00 {
            return Err(Error::protocol(format!(
                "socks5: connect failed, code {code:#04x}"
            )));
        }
        Ok(SocksStream { inner: transport })
    }
}

impl AsyncWrite for SocksStream {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for SocksStream {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

/// Read a SOCKS5 reply: `VER REP RSV ATYP ADDR PORT`.
async fn read_socks_reply<S: AsyncRead + AsyncWrite + Unpin>(
    io: &mut S,
) -> Result<(u8, NetAddr)> {
    let mut head = [0u8; 4];
    io.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(Error::protocol("socks5: reply version mismatch"));
    }
    let tail_len = match head[3] {
        0x01 => 4 + 2,
        0x03 => 255, // read length byte first
        0x04 => 16 + 2,
        other => return Err(Error::protocol(format!("socks5: bad reply atyp {other:#x}"))),
    };
    let mut tail = vec![0u8; tail_len.max(1)];
    if head[3] == 0x03 {
        io.read_exact(&mut tail[..1]).await?;
        let n = tail[0] as usize + 2;
        tail.resize(n, 0);
        io.read_exact(&mut tail[1..]).await?;
    } else {
        io.read_exact(&mut tail).await?;
    }
    let port = tail.len()
        .checked_sub(2)
        .map(|p| u16::from_be_bytes([tail[p], tail[p + 1]]))
        .unwrap_or(0);
    let host = match head[3] {
        0x01 => Host::Ip(format!("{}.{}.{}.{}", tail[0], tail[1], tail[2], tail[3])
            .parse()
            .map_err(|_| Error::protocol("socks5: bad ipv4 in reply"))?),
        0x03 => Host::Domain(String::from_utf8_lossy(&tail[..tail.len() - 2]).to_string()),
        _ => {
            let mut b = [0u8; 16];
            b.copy_from_slice(&tail[..16]);
            Host::Ip(std::net::IpAddr::V6(b.into()))
        }
    };
    Ok((head[1], NetAddr::new(host, port)))
}

/// Method negotiation (greeting + optional user/pass subnegotiation).
async fn negotiate<S: AsyncRead + AsyncWrite + Unpin>(io: &mut S, cfg: &SocksOut) -> Result<()> {
    let has_auth = cfg
        .username
        .as_deref()
        .map(|u| !u.is_empty())
        .unwrap_or(false);
    let mut greet = vec![0x05, if has_auth { 2 } else { 1 }, 0x00];
    if has_auth {
        greet.push(0x02);
    }
    io.write_all(&greet).await?;
    let mut resp = [0u8; 2];
    io.read_exact(&mut resp).await?;
    if resp[0] != 0x05 {
        return Err(Error::protocol(format!("socks5: bad version {:#x}", resp[0])));
    }
    match resp[1] {
        0x00 => Ok(()),
        0x02 if has_auth => {
            let user = cfg.username.as_deref().unwrap_or("");
            let pass = cfg.password.as_deref().unwrap_or("");
            let mut req = Vec::with_capacity(3 + user.len() + pass.len());
            req.push(0x01);
            req.push(user.len() as u8);
            req.extend_from_slice(user.as_bytes());
            req.push(pass.len() as u8);
            req.extend_from_slice(pass.as_bytes());
            io.write_all(&req).await?;
            let mut status = [0u8; 2];
            io.read_exact(&mut status).await?;
            if status[1] != 0x00 {
                return Err(Error::protocol("socks5: authentication failed"));
            }
            Ok(())
        }
        0xFF => Err(Error::protocol(
            "socks5: server refuses all offered auth methods",
        )),
        other => Err(Error::protocol(format!(
            "socks5: server chose unoffered method {other:#x}"
        ))),
    }
}

/// A SOCKS5 UDP association: the TCP control connection plus the relay's
/// UDP endpoint.
pub struct SocksUdp {
    #[allow(dead_code)]
    control: SocksStream,
    /// Relay UDP endpoint from the associate reply.
    pub relay: std::net::SocketAddr,
    /// Local socket bound from the same address family as the TCP link.
    pub socket: tokio::net::UdpSocket,
}

impl SocksUdp {
    /// Negotiate a UDP ASSOCIATE over an established TCP connection. The
    /// TCP stream is kept concrete so the UDP socket can bind to the same
    /// address family (servers key the association by source address).
    pub async fn associate(mut tcp: tokio::net::TcpStream, cfg: &SocksOut) -> Result<Self> {
        negotiate(&mut tcp, cfg).await?;

        // UDP ASSOCIATE with the zero target; the reply carries the relay
        // endpoint.
        let mut req = vec![0x05, 0x03, 0x00];
        encode_socks_addr(
            &mut req,
            &Host::Ip(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)),
            0,
        );
        tcp.write_all(&req).await?;
        let (rep, bind) = read_socks_reply(&mut tcp).await?;
        if rep != 0x00 {
            return Err(Error::protocol(format!(
                "socks5: udp associate failed, code {rep:#04x}"
            )));
        }
        let Host::Ip(relay_ip) = bind.host else {
            return Err(Error::protocol("socks5: udp associate reply is not an IP"));
        };
        let relay = std::net::SocketAddr::new(relay_ip, bind.port);
        if relay.port() == 0 {
            return Err(Error::protocol("socks5: udp associate returned port 0"));
        }
        let local_tcp = tcp.local_addr().map_err(|e| Error::network(e.to_string()))?;
        let socket = tokio::net::UdpSocket::bind(if local_tcp.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await?;
        crate::mark::apply(&socket);
        Ok(SocksUdp {
            control: SocksStream {
                inner: Box::new(tcp),
            },
            relay,
            socket,
        })
    }

    /// Wrap a datagram in the SOCKS5 UDP header.
    pub fn encode_datagram(target: &NetAddr, data: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(data.len() + 32);
        out.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV RSV FRAG
        encode_socks_addr(&mut out, &target.host, target.port);
        out.extend_from_slice(data);
        out
    }

    /// Strip the SOCKS5 UDP header from a datagram.
    pub fn decode_datagram(buf: &[u8]) -> Result<(NetAddr, &[u8])> {
        if buf.len() < 4 {
            return Err(Error::protocol("socks5 udp: runt datagram"));
        }
        let (addr, used) = decode_socks_addr(&buf[3..])?;
        Ok((addr, &buf[3 + used..]))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[test]
    fn datagram_roundtrip() {
        let target = NetAddr::domain("d.test", 53).unwrap();
        let wire = SocksUdp::encode_datagram(&target, b"hello");
        let (addr, data) = SocksUdp::decode_datagram(&wire).unwrap();
        assert_eq!(addr.host, Host::Domain("d.test".into()));
        assert_eq!(addr.port, 53);
        assert_eq!(data, b"hello");
    }

    /// Minimal in-process SOCKS5 server for CONNECT: greets, echoes reply,
    /// then relays.
    #[tokio::test]
    async fn connect_handshake_no_auth() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut b = [0u8; 3];
            sock.read_exact(&mut b).await.unwrap();
            assert_eq!(&b, &[0x05, 0x01, 0x00]);
            sock.write_all(&[0x05, 0x00]).await.unwrap();
            let mut head = [0u8; 4];
            sock.read_exact(&mut head).await.unwrap();
            assert_eq!(head[1], 0x01);
            // domain target (RFC 1928 ATYP 3)
            assert_eq!(head[3], 0x03);
            let mut lenb = [0u8; 1];
            sock.read_exact(&mut lenb).await.unwrap();
            let mut rest = vec![0u8; lenb[0] as usize + 2];
            sock.read_exact(&mut rest).await.unwrap();
            let port = u16::from_be_bytes([rest[rest.len() - 2], rest[rest.len() - 1]]);
            assert_eq!(port, 443);
            // Reply: success with 127.0.0.1:1080.
            sock.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x04, 0x38])
                .await
                .unwrap();
            // Relay one exchange.
            let mut buf = [0u8; 16];
            let n = sock.read(&mut buf).await.unwrap();
            assert_eq!(&buf[..n], b"ping");
            sock.write_all(b"pong").await.unwrap();
        });

        let cfg = SocksOut {
            server: "127.0.0.1".into(),
            port: addr.port(),
            username: None,
            password: None,
        };
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut stream = SocksStream::handshake(Box::new(tcp), &cfg, &NetAddr::domain("s.test", 443).unwrap())
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"pong");
    }

    #[tokio::test]
    async fn connect_handshake_rejects_bad_reply_code() {
        use tokio::net::TcpListener;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut b = [0u8; 3];
            sock.read_exact(&mut b).await.unwrap();
            sock.write_all(&[0x05, 0x00]).await.unwrap();
            let mut head = [0u8; 4];
            sock.read_exact(&mut head).await.unwrap();
            let mut lenb = [0u8; 1];
            sock.read_exact(&mut lenb).await.unwrap();
            let mut rest = vec![0u8; lenb[0] as usize + 2];
            sock.read_exact(&mut rest).await.unwrap();
            // General failure.
            sock.write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        });
        let cfg = SocksOut {
            server: "127.0.0.1".into(),
            port: addr.port(),
            username: None,
            password: None,
        };
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let err = SocksStream::handshake(Box::new(tcp), &cfg, &NetAddr::domain("x.test", 80).unwrap())
            .await
            .err()
            .expect("handshake should fail");
        assert!(err.to_string().contains("connect failed"));
    }
}
