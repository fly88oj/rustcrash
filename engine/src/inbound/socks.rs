//! SOCKS5 inbound server (RFC 1928): CONNECT, UDP ASSOCIATE, optional
//! username/password auth.

use std::net::SocketAddr;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc;

use crate::addr::{Host, NetAddr};
use crate::error::{Error, Result};
use crate::inbound::{ListenerConfig, SharedRelay, TcpMeta};
use crate::stream::BoxProxyStream;

/// Serve a SOCKS5 listener; returns the bound address.
pub async fn serve(cfg: &ListenerConfig, relay: SharedRelay) -> Result<SocketAddr> {
    let listener = TcpListener::bind((cfg.bind.as_str(), cfg.port))
        .await
        .map_err(|e| Error::network(format!("bind {}:{}: {e}", cfg.bind, cfg.port)))?;
    let addr = listener.local_addr().map_err(|e| Error::network(e.to_string()))?;
    let tag = cfg.tag.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                continue;
            };
            let _ = stream.set_nodelay(true);
            let relay = relay.clone();
            let tag = tag.clone();
            // The listener's own IP is the address clients reach us on —
            // advertised in UDP ASSOCIATE replies.
            let server_ip = addr.ip();
            tokio::spawn(async move {
                let port = stream.local_addr().map(|a| a.port()).ok();
                handle(stream, peer, tag, port, "socks", relay, Some(server_ip)).await;
            });
        }
    });
    Ok(addr)
}

/// Drive one SOCKS5 connection over an established stream (the mixed
/// listener routes here after peeking the version byte).
pub async fn handle_stream(
    stream: BoxProxyStream,
    peer: SocketAddr,
    tag: String,
    inbound_port: Option<u16>,
    inbound_kind: &'static str,
    relay: SharedRelay,
) -> Result<()> {
    handle_inner(stream, peer, &tag, inbound_port, inbound_kind, relay, None).await
}

async fn handle(
    stream: tokio::net::TcpStream,
    peer: SocketAddr,
    tag: String,
    inbound_port: Option<u16>,
    inbound_kind: &'static str,
    relay: SharedRelay,
    server_ip: Option<std::net::IpAddr>,
) {
    if let Err(e) =
        handle_inner(Box::new(stream), peer, &tag, inbound_port, inbound_kind, relay, server_ip)
            .await
    {
        tracing::debug!(target: "engine", "socks5 {peer}: {e}");
    }
}

async fn handle_inner(
    mut stream: BoxProxyStream,
    peer: SocketAddr,
    tag: &str,
    inbound_port: Option<u16>,
    inbound_kind: &'static str,
    relay: SharedRelay,
    server_ip: Option<std::net::IpAddr>,
) -> Result<()> {
    // Greeting.
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    if head[0] != 0x05 {
        return Err(Error::protocol(format!("bad socks version {:#x}", head[0])));
    }
    let nmethods = head[1] as usize;
    if nmethods > 16 {
        return Err(Error::protocol("too many auth methods"));
    }
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;
    // No-auth only (mihomo local auth is rarely used for the mixed port;
    // add when a config asks for it).
    stream.write_all(&[0x05, 0x00]).await?;

    // Request.
    let mut req = [0u8; 4];
    stream.read_exact(&mut req).await?;
    if req[0] != 0x05 {
        return Err(Error::protocol("bad request version"));
    }
    let target = read_socks_target(&mut stream, req[3]).await?;
    match req[1] {
        0x01 => {
            // CONNECT: success reply with a zero address.
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            relay.handle_tcp(
                TcpMeta {
                    target,
                    source: peer,
                    inbound: tag.to_string(),
                    inbound_port,
                    inbound_kind,
                },
                Box::new(stream),
            );
            Ok(())
        }
        0x03 => {
            udp_associate(&mut stream, peer, tag, target, relay, server_ip).await;
            Ok(())
        }
        0x02 => Err(Error::protocol("BIND not supported")),
        other => Err(Error::protocol(format!("unsupported socks cmd {other:#x}"))),
    }
}

/// Read an address payload following `atyp`.
async fn read_socks_target(stream: &mut BoxProxyStream, atyp: u8) -> Result<NetAddr> {
    let host = match atyp {
        0x01 => {
            let mut b = [0u8; 4];
            stream.read_exact(&mut b).await?;
            Host::Ip(b.into())
        }
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await?;
            let mut name = vec![0u8; l[0] as usize];
            stream.read_exact(&mut name).await?;
            let s = String::from_utf8(name)
                .map_err(|_| Error::protocol("socks5: domain not utf-8"))?;
            Host::parse(&s)?
        }
        0x04 => {
            let mut b = [0u8; 16];
            stream.read_exact(&mut b).await?;
            Host::Ip(b.into())
        }
        other => return Err(Error::protocol(format!("socks5: bad atyp {other:#x}"))),
    };
    let mut p = [0u8; 2];
    stream.read_exact(&mut p).await?;
    Ok(NetAddr::new(host, u16::from_be_bytes(p)))
}

async fn udp_associate(
    stream: &mut BoxProxyStream,
    peer: SocketAddr,
    tag: &str,
    _requested: NetAddr,
    relay: SharedRelay,
    server_ip: Option<std::net::IpAddr>,
) {
    // Allocate the data socket first so the reply can carry its address.
    let socket = match UdpSocket::bind(if peer.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await
    {
        Ok(s) => s,
        Err(e) => {
            tracing::warn!(target: "engine", "socks5 udp bind: {e}");
            let _ = stream
                .write_all(&[0x05, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return;
        }
    };
    let Ok(data_addr) = socket.local_addr() else {
        return;
    };
    // The wildcard-bound data socket reports 0.0.0.0 — advertising that
    // makes clients auto-bind to a wildcard source and breaks the reply
    // path. Use the address the client reached us on (the listener IP),
    // matching mihomo's behaviour; fall back to the peer-family loopback.
    let advertised_ip = server_ip.unwrap_or_else(|| {
        if peer.is_ipv4() {
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
        } else {
            std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
        }
    });
    // Reply with the data port on the reachable address (address family
    // preserved; the client connects back from the same address family).
    let reply = match advertised_ip {
        std::net::IpAddr::V4(v4) => {
            let mut r = vec![0x05, 0x00, 0x00, 0x01];
            r.extend_from_slice(&v4.octets());
            r.extend_from_slice(&data_addr.port().to_be_bytes());
            r
        }
        std::net::IpAddr::V6(v6) => {
            let mut r = vec![0x05, 0x00, 0x00, 0x04];
            r.extend_from_slice(&v6.octets());
            r.extend_from_slice(&data_addr.port().to_be_bytes());
            r
        }
    };
    if stream.write_all(&reply).await.is_err() {
        return;
    }

    let (up_tx, up_rx) = mpsc::channel::<(NetAddr, Vec<u8>)>(64);
    let (down_tx, mut down_rx) = mpsc::channel::<(NetAddr, Vec<u8>)>(64);
    relay.handle_udp(peer, tag.to_string(), up_rx, down_tx);

    // Pump: client datagrams → uplink; downlink → client.
    let mut buf = vec![0u8; 65536];
    let mut ctrl_buf = [0u8; 1];
    // The UDP SOURCE of the association's datagrams — replies go here,
    // which is NOT necessarily the TCP peer port (clients use separate
    // ephemeral ports for the control connection and the data flow).
    let mut udp_client: Option<SocketAddr> = None;
    use tokio::io::AsyncReadExt as _;
    loop {
        tokio::select! {
            r = socket.recv_from(&mut buf) => {
                let Ok((n, src)) = r else { break };
                if src.ip() != peer.ip() {
                    continue; // association is single-client
                }
                udp_client = Some(src);
                let Ok((target, data)) = crate::proto::socks::SocksUdp::decode_datagram(&buf[..n]) else {
                    continue;
                };
                if up_tx.send((target, data.to_vec())).await.is_err() {
                    break;
                }
            }
            r = down_rx.recv() => {
                match r {
                    Some((target, data)) => {
                        let Some(client) = udp_client else { continue };
                        let wire = crate::proto::socks::SocksUdp::encode_datagram(&target, &data);
                        // Replies come from the association's perspective:
                        // the target is the "source" of the datagram.
                        if socket.send_to(&wire, client).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            _ = stream.read(&mut ctrl_buf) => {
                // Control connection closed → tear the association down.
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbound::RelayHandler;
    use crate::inbound::{ListenerConfig, ListenerKind};
    use std::sync::Arc;

    struct Capture(std::sync::Mutex<Vec<NetAddr>>);

    impl RelayHandler for Capture {
        fn handle_tcp(self: std::sync::Arc<Self>, meta: TcpMeta, mut client: BoxProxyStream) {
            self.0.lock().unwrap().push(meta.target.clone());
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 16];
                let n = client.read(&mut buf).await.unwrap_or(0);
                let _ = client.write_all(&buf[..n]).await;
            });
        }

        fn handle_udp(
            self: std::sync::Arc<Self>,
            _source: SocketAddr,
            _inbound: String,
            mut uplink: mpsc::Receiver<(NetAddr, Vec<u8>)>,
            downlink: mpsc::Sender<(NetAddr, Vec<u8>)>,
        ) {
            tokio::spawn(async move {
                while let Some((target, data)) = uplink.recv().await {
                    let _ = downlink.send((target, data)).await;
                }
            });
        }
    }

    async fn spawn_capture() -> (std::sync::Arc<Capture>, ListenerConfig) {
        let cfg = ListenerConfig {
            tag: "test".into(),
            bind: "127.0.0.1".into(),
            port: 0,
            kind: ListenerKind::Socks,
        };
        let capture = Arc::new(Capture(std::sync::Mutex::new(Vec::new())));
        let _ = serve(&cfg, capture.clone()).await;
        (capture, cfg)
    }

    #[tokio::test]
    async fn socks5_connect_relay() {
        let (capture, cfg) = spawn_capture().await;
        // Re-bind because port 0 was allocated inside serve; the test
        // client needs the real port — serve returned the address to its
        // caller. Recreate with an explicit port instead.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let cfg = ListenerConfig {
            port: addr.port(),
            ..cfg
        };
        let bound = serve(&cfg, capture.clone()).await.unwrap();
        let mut c = tokio::net::TcpStream::connect(bound).await.unwrap();
        c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut r = [0u8; 2];
        c.read_exact(&mut r).await.unwrap();
        assert_eq!(&r, &[0x05, 0x00]);
        c.write_all(&[0x05, 0x01, 0x00, 0x03, 9, b'e', b'c', b'h', b'o', b'.', b't', b'e', b's', b't', 0x01, 0xbb])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        c.read_exact(&mut reply).await.unwrap();
        assert_eq!(reply[1], 0x00);
        c.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), c.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"ping");
        assert_eq!(
            capture.0.lock().unwrap()[0].host,
            Host::Domain("echo.test".into())
        );
    }
}
