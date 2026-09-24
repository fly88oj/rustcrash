//! VLESS server (plain form): version 0 header, UUID, command, port-first
//! address, then a raw byte relay or a UDP association.
//!
//! Inverts [`crate::proto::vless::VlessStream`]. The server sends the
//! response header ([version, addons-length = 0]) before relaying, which
//! the engine client — and real clients — consume transparently.
//! `flow` addons (XTLS/Vision) are rejected: this server is plain VLESS.
//!
//! The UDP command (cmd 2) turns the connection into the engine client's
//! datagram framing, `socks-addr || len-be16 || payload`, bridged to the
//! relay; the header's target is ignored because every datagram carries
//! its own. Upstream VLESS UDP framing differs (sing-box's standalone UOT
//! numbers the address families 0x00/0x01/0x02, mihomo's sing-vmess client
//! pins a single destination and sends bare length-prefixed payloads), so
//! this server tracks the engine's own outbound codec.

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::{Error, Result};
use crate::inbound::proxy_server::{
    build_tls_config, ct_eq, hand_off, read_port_first_addr, serve_with, spawn_framed_udp,
    ServerConfig, ServerProtocol, ServerTls,
};
use crate::inbound::SharedRelay;
use crate::stream::BoxProxyStream;

const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x02;

/// A VLESS server: validated UUID and optional TLS.
#[derive(Clone)]
pub struct VlessServer {
    uuid: [u8; 16],
    tls: Option<Arc<rustls::ServerConfig>>,
}

impl VlessServer {
    /// Validate the UUID and load TLS material once, before binding.
    pub fn new(uuid: &str, tls: Option<&ServerTls>) -> Result<Self> {
        let uuid = uuid::Uuid::parse_str(uuid.trim())
            .map_err(|e| Error::config(format!("vless uuid {uuid:?}: {e}")))?;
        let tls = tls.map(build_tls_config).transpose()?;
        Ok(VlessServer {
            uuid: *uuid.as_bytes(),
            tls,
        })
    }

    /// Run the server handshake on an accepted connection and hand the
    /// (plain, post-header) stream to the relay.
    pub async fn handle(
        &self,
        stream: BoxProxyStream,
        peer: SocketAddr,
        port: u16,
        tag: &str,
        relay: SharedRelay,
    ) -> Result<()> {
        let mut stream = match &self.tls {
            Some(config) => crate::inbound::proxy_server::tls_accept(config.clone(), stream).await?,
            None => stream,
        };

        // version(1) uuid(16) addons-length(1)
        let mut head = [0u8; 18];
        stream.read_exact(&mut head).await?;
        if head[0] != 0 {
            return Err(Error::protocol(format!(
                "vless: unsupported version {:#x}",
                head[0]
            )));
        }
        if !ct_eq(&head[1..17], &self.uuid) {
            return Err(Error::protocol("vless: unknown uuid"));
        }
        if head[17] != 0 {
            return Err(Error::protocol(
                "vless: flow/addons are not supported by this server",
            ));
        }

        let mut cmd = [0u8; 1];
        stream.read_exact(&mut cmd).await?;
        let udp = match cmd[0] {
            CMD_TCP => false,
            CMD_UDP => true,
            other => return Err(Error::protocol(format!("vless: bad command {other:#x}"))),
        };

        let target = read_port_first_addr(&mut stream).await?;

        // Response header: version + no addons; data follows immediately.
        stream.write_all(&[0x00, 0x00]).await?;
        if udp {
            spawn_framed_udp(stream, peer, tag.to_string(), relay, false);
        } else {
            hand_off(tag, "vless", port, peer, target, stream, relay);
        }
        Ok(())
    }
}

/// Serve a VLESS listener; returns the bound address.
pub async fn serve(cfg: &ServerConfig, relay: SharedRelay) -> Result<SocketAddr> {
    let ServerProtocol::Vless { uuid, tls } = &cfg.protocol else {
        return Err(Error::config("vless::serve called with a non-vless protocol"));
    };
    let server = VlessServer::new(uuid, tls.as_ref())?;
    let tag = cfg.tag.clone();
    serve_with(cfg, move |stream, peer, port| {
        let server = server.clone();
        let relay = relay.clone();
        let tag = tag.clone();
        async move { server.handle(stream, peer, port, &tag, relay).await }
    })
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::NetAddr;
    use crate::inbound::proxy_server::test_support::{
        read_client_udp_frame, self_signed_tls, Capture,
    };
    use crate::proto::vless::VlessOut;
    use crate::transport::{tls_connect, TlsSettings};
    use std::time::Duration;
    use tokio::net::TcpStream;

    fn fresh_uuid() -> String {
        uuid::Uuid::new_v4().to_string()
    }

    async fn spawn_server(uuid: &str, tls: Option<ServerTls>) -> (Arc<Capture>, SocketAddr) {
        let cfg = ServerConfig {
            tag: "vless-test".into(),
            bind: "127.0.0.1".into(),
            port: 0,
            protocol: ServerProtocol::Vless {
                uuid: uuid.into(),
                tls,
            },
        };
        let capture = Capture::new();
        let addr = serve(&cfg, capture.clone()).await.unwrap();
        (capture, addr)
    }

    fn client(uuid: &str, port: u16) -> VlessOut {
        VlessOut {
            server: "127.0.0.1".into(),
            port,
            uuid: uuid::Uuid::parse_str(uuid).unwrap(),
        }
    }

    async fn roundtrip_over(
        transport: BoxProxyStream,
        uuid: &str,
        port: u16,
    ) -> (Vec<u8>, NetAddr) {
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let mut stream = crate::proto::vless::VlessStream::handshake(
            transport,
            &client(uuid, port),
            &target,
            false,
        )
        .await
        .unwrap();
        stream.write_all(b"ping").await.unwrap();
        stream.flush().await.unwrap();
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
            .await
            .expect("timeout")
            .unwrap();
        (buf[..n].to_vec(), target)
    }

    #[tokio::test]
    async fn plain_tcp_roundtrip() {
        let uuid = fresh_uuid();
        let (capture, addr) = spawn_server(&uuid, None).await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let (echo, target) = roundtrip_over(Box::new(tcp), &uuid, addr.port()).await;
        assert_eq!(echo, b"ping");
        assert_eq!(capture.targets(), vec![target]);
    }

    #[tokio::test]
    async fn tls_tcp_roundtrip() {
        let uuid = fresh_uuid();
        let (tls, _dir) = self_signed_tls();
        let (capture, addr) = spawn_server(&uuid, Some(tls)).await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let tls_stream = tls_connect(
            Box::new(tcp),
            "localhost",
            &TlsSettings {
                enabled: true,
                server_name: Some("localhost".into()),
                skip_cert_verify: true,
                alpn: Vec::new(),
            },
        )
        .await
        .unwrap();
        let (echo, target) = roundtrip_over(tls_stream, &uuid, addr.port()).await;
        assert_eq!(echo, b"ping");
        assert_eq!(capture.targets(), vec![target]);
    }

    #[tokio::test]
    async fn unknown_uuid_relays_nothing() {
        let (capture, addr) = spawn_server(&fresh_uuid(), None).await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let mut stream = crate::proto::vless::VlessStream::handshake(
            Box::new(tcp),
            &client(&fresh_uuid(), addr.port()),
            &target,
            false,
        )
        .await
        .unwrap();
        let _ = stream.write_all(b"ping").await;
        let mut buf = [0u8; 8];
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
        match read {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!("unexpected {n} bytes from a rejected client"),
            Err(_) => panic!("timeout: server did not close the connection"),
        }
        assert_eq!(capture.relayed(), 0);
    }

    /// UDP command (cmd 2) roundtrip through the engine's own client:
    /// `VlessStream` for the handshake and `vless_udp_frame` for the
    /// datagram, which is exactly what `UdpChannel::Framed` writes.
    #[tokio::test]
    async fn udp_command_roundtrip() {
        let uuid = fresh_uuid();
        let (capture, addr) = spawn_server(&uuid, None).await;
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        // Like the outbound, the association header carries no real target.
        let placeholder =
            NetAddr::ip(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
        let mut stream = crate::proto::vless::VlessStream::handshake(
            Box::new(tcp),
            &client(&uuid, addr.port()),
            &placeholder,
            true,
        )
        .await
        .unwrap();
        let frame = crate::proto::vless::vless_udp_frame(&target, b"ping").unwrap();
        stream.write_all(&frame).await.unwrap();
        stream.flush().await.unwrap();

        let (from, data) = read_client_udp_frame(&mut stream).await;
        assert_eq!(data, b"ping");
        assert_eq!(from, target);
        assert_eq!(capture.udp_targets(), vec![target]);
        assert_eq!(capture.relayed(), 0);
        assert_eq!(capture.udp_sessions().len(), 1);
        assert_eq!(capture.udp_sessions()[0].1, "vless-test");
    }
}