//! Trojan server: TLS (when configured), SHA-224 password hex, command
//! byte, SOCKS address, CRLF — then a raw TCP relay or a UDP association.
//!
//! The wire form is the exact inverse of
//! [`crate::proto::trojan::TrojanStream`]. `CONNECT` (cmd 1) relays raw
//! bytes; the UDP command (cmd 3) turns the connection into a sequence of
//! `socks-addr || len-be16 || payload` datagrams bridged to the relay
//! (the engine's own UDP framing — see the module-level notes in
//! [`crate::inbound::proxy_server`]; upstream trojan inserts a CRLF
//! between the length and the payload).

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::AsyncReadExt;

use crate::error::{Error, Result};
use crate::inbound::proxy_server::{
    build_tls_config, ct_eq, hand_off, read_socks_addr, serve_with, spawn_framed_udp,
    ServerConfig, ServerProtocol, ServerTls,
};
use crate::inbound::SharedRelay;
use crate::proto::trojan::trojan_password_hex;
use crate::stream::BoxProxyStream;

const CMD_TCP: u8 = 0x01;
const CMD_UDP: u8 = 0x03;

/// A Trojan server: validated password hash and optional TLS.
#[derive(Clone)]
pub struct TrojanServer {
    password_hex: String,
    tls: Option<Arc<rustls::ServerConfig>>,
}

impl TrojanServer {
    /// Validate the password and load TLS material once, before binding.
    pub fn new(password: &str, tls: Option<&ServerTls>) -> Result<Self> {
        let tls = tls.map(build_tls_config).transpose()?;
        Ok(TrojanServer {
            password_hex: trojan_password_hex(password),
            tls,
        })
    }

    /// Run the server handshake on an accepted connection and hand the
    /// stream to the relay (trojan responses carry no header).
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

        let mut password = [0u8; 56];
        stream.read_exact(&mut password).await?;
        if !ct_eq(&password, self.password_hex.as_bytes()) {
            return Err(Error::protocol("trojan: wrong password"));
        }
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).await?;
        if &crlf != b"\r\n" {
            return Err(Error::protocol("trojan: missing CRLF after password"));
        }

        let mut cmd = [0u8; 1];
        stream.read_exact(&mut cmd).await?;
        let udp = match cmd[0] {
            CMD_TCP => false,
            CMD_UDP => true,
            other => {
                return Err(Error::protocol(format!("trojan: bad command {other:#x}")));
            }
        };

        // For TCP this is the relay target; for UDP the header address is
        // unused (every datagram carries its own).
        let target = read_socks_addr(&mut stream).await?;
        let mut crlf = [0u8; 2];
        stream.read_exact(&mut crlf).await?;
        if &crlf != b"\r\n" {
            return Err(Error::protocol("trojan: missing CRLF after address"));
        }

        if udp {
            spawn_framed_udp(stream, peer, tag.to_string(), relay, true);
        } else {
            hand_off(tag, "trojan", port, peer, target, stream, relay);
        }
        Ok(())
    }
}

/// Serve a Trojan listener; returns the bound address.
pub async fn serve(cfg: &ServerConfig, relay: SharedRelay) -> Result<SocketAddr> {
    let ServerProtocol::Trojan { password, tls } = &cfg.protocol else {
        return Err(Error::config("trojan::serve called with a non-trojan protocol"));
    };
    let server = TrojanServer::new(password, tls.as_ref())?;
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
        read_client_trojan_udp_frame, self_signed_tls, Capture,
    };
    use crate::proto::trojan::TrojanOut;
    use crate::transport::{tls_connect, TlsSettings};
    use rand::RngCore;
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    fn fresh_password() -> String {
        let mut b = [0u8; 12];
        rand::rngs::OsRng.fill_bytes(&mut b);
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    async fn spawn_server(password: &str, tls: Option<ServerTls>) -> (Arc<Capture>, SocketAddr) {
        let cfg = ServerConfig {
            tag: "trojan-test".into(),
            bind: "127.0.0.1".into(),
            port: 0,
            protocol: ServerProtocol::Trojan {
                password: password.into(),
                tls,
            },
        };
        let capture = Capture::new();
        let addr = serve(&cfg, capture.clone()).await.unwrap();
        (capture, addr)
    }

    fn client(password: &str, port: u16) -> TrojanOut {
        TrojanOut {
            server: "127.0.0.1".into(),
            port,
            password: password.into(),
        }
    }

    /// Handshake + echo one payload over an established transport.
    async fn roundtrip_over(transport: BoxProxyStream, password: &str, port: u16) -> (Vec<u8>, NetAddr) {
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let mut stream = crate::proto::trojan::TrojanStream::handshake(
            transport,
            &client(password, port),
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
        let password = fresh_password();
        let (capture, addr) = spawn_server(&password, None).await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let (echo, target) = roundtrip_over(Box::new(tcp), &password, addr.port()).await;
        assert_eq!(echo, b"ping");
        assert_eq!(capture.targets(), vec![target]);
    }

    #[tokio::test]
    async fn tls_tcp_roundtrip() {
        let password = fresh_password();
        let (tls, _dir) = self_signed_tls();
        let (capture, addr) = spawn_server(&password, Some(tls)).await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        // The outbound-facing client verifier skips the self-signed cert:
        // this loop only checks the protocol over a real rustls handshake.
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
        let (echo, target) = roundtrip_over(tls_stream, &password, addr.port()).await;
        assert_eq!(echo, b"ping");
        assert_eq!(capture.targets(), vec![target]);
    }

    #[tokio::test]
    async fn wrong_password_relays_nothing() {
        let (capture, addr) = spawn_server(&fresh_password(), None).await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let mut stream = crate::proto::trojan::TrojanStream::handshake(
            Box::new(tcp),
            &client(&fresh_password(), addr.port()),
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

    /// UDP command (cmd 3) roundtrip through the engine's own client:
    /// `TrojanStream` for the handshake and `proto::trojan::trojan_udp_frame`
    /// for the datagram, which is exactly what `UdpChannel::Trojan` writes
    /// (upstream framing: addr || len || CRLF || payload).
    #[tokio::test]
    async fn udp_associate_roundtrip() {
        let password = fresh_password();
        let (capture, addr) = spawn_server(&password, None).await;
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        // Like the outbound, the association header carries no real target.
        let placeholder =
            NetAddr::ip(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
        let mut stream = crate::proto::trojan::TrojanStream::handshake(
            Box::new(tcp),
            &client(&password, addr.port()),
            &placeholder,
            true,
        )
        .await
        .unwrap();
        let frame = crate::proto::trojan::trojan_udp_frame(&target, b"ping").unwrap();
        stream.write_all(&frame).await.unwrap();
        stream.flush().await.unwrap();

        let (from, data) = read_client_trojan_udp_frame(&mut stream).await;
        assert_eq!(data, b"ping");
        assert_eq!(from, target);
        // UDP went through the relay's UDP side, not a TCP hand-off.
        assert_eq!(capture.udp_targets(), vec![target]);
        assert_eq!(capture.relayed(), 0);
        assert_eq!(capture.udp_sessions().len(), 1);
        assert_eq!(capture.udp_sessions()[0].1, "trojan-test");
    }

    #[tokio::test]
    async fn udp_command_wrong_password_relays_nothing() {
        let (capture, addr) = spawn_server(&fresh_password(), None).await;
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        let mut hdr = Vec::new();
        hdr.extend_from_slice(trojan_password_hex(&fresh_password()).as_bytes());
        hdr.extend_from_slice(b"\r\n");
        hdr.push(CMD_UDP);
        crate::addr::encode_socks_addr(
            &mut hdr,
            &crate::addr::Host::Domain("echo.test".into()),
            443,
        );
        hdr.extend_from_slice(b"\r\n");
        tcp.write_all(&hdr).await.unwrap();
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), tcp.read(&mut buf)).await;
        match read {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!("unexpected {n} bytes from a rejected client"),
            Err(_) => panic!("timeout: server did not close the connection"),
        }
        assert_eq!(capture.udp_sessions().len(), 0);
    }
}