//! Snell server listener: mihomo `listener/snell/server.go`.
//!
//! Every accepted connection is (optionally) wrapped in http obfs, then
//! runs the server half of the wire codecs in
//! [`crate::proto::snell`]: the request header carries the target
//! (relay like trojan), the first relay write prefixes the tunnel reply,
//! and a request that negotiated `CommandConnectV2` keeps the conn
//! alive for the next request (the zero-chunk half-close +
//! [`crate::proto::snell::SnellServerNext`] continuation).
//!
//! Config gate parity with upstream `New`
//! (listener/snell/server.go:37-52): version `0` defaults to v4 (the
//! *server* default — the client's is v1), `1..=5` pass, anything else
//! is `snell inbound version %d is not supported`; an empty psk is
//! `snell inbound requires psk`; `obfs-mode` accepts `""`/`http` (the
//! `tls` mode needs the TLS-record camouflage server from
//! `transport/simple-obfs/tls_server.go`, which the engine does not
//! carry — a precise error at serve time, see [`OBFS_TLS_UNSUPPORTED`]).
//!
//! Integrator deltas (fields upstream's `LC.SnellServer` carries that
//! [`ServerProtocol::Snell`] lacks — parse-time errors are the
//! integrator's once the enum grows them):
//!
//! * `UDP` — upstream gates the UDP command on it
//!   (server.go:202-204, "snell UDP is disabled"); this listener always
//!   serves UDP (the engine's client advertises it per outbound).
//! * `ShadowTLS` / `ResTLS` / `JLSConfig` — stacked frontings wrapping
//!   the raw listener before the snell codec (server.go:56-89,
//!   100-106); mutually exclusive upstream
//!   ("security modes are mutually exclusive: …"). Nothing to wire
//!   until the enum carries the configs.
//! * `obfs-host` is accepted but unused server-side: mihomo's
//!   `NewHTTPObfsServer` echoes no Host (the client-side wrapper is the
//!   one that needs it).

use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::error::{Error, Result};
use crate::inbound::proxy_server::{
    hand_off, serve_with, ServerConfig, ServerProtocol, SharedRelay,
};
use crate::proto::snell::{
    http_obfs_server, parse_server_version, parse_snell_udp_request, snell_udp_response_frame,
    SnellServerConn, SnellServerNext, SnellServerRequest, SnellServerUdp,
};
use crate::stream::BoxProxyStream;

/// `maxPacketLength` (listener/snell/server.go:28).
const MAX_PACKET_LENGTH: usize = crate::proto::snell::MAX_LENGTH;

/// The precise error for `obfs-mode: tls`: the TLS-record camouflage
/// server half lives upstream at
/// `transport/simple-obfs/tls_server.go` (`NewTLSObfsServer`,
/// listener/snell/server.go:159-160) and the engine's
/// `proto::obfs` carries only the client wrapper.
pub const OBFS_TLS_UNSUPPORTED: &str = concat!(
    "snell inbound obfs mode tls is not implemented server-side: it needs the ",
    "TLS-record camouflage server from mihomo transport/simple-obfs/tls_server.go ",
    "(NewTLSObfsServer); the engine's proto::obfs ships only the client half. ",
    "Use obfs-mode http or plain"
);

/// Per-listener context shared by every accepted conn.
#[derive(Clone)]
struct SnellListenCtx {
    psk: Vec<u8>,
    version: u8,
    http_obfs: bool,
    relay: SharedRelay,
    tag: Arc<str>,
}

/// Serve a snell listener; returns the bound address.
pub async fn serve(cfg: &ServerConfig, relay: SharedRelay) -> Result<SocketAddr> {
    let ServerProtocol::Snell {
        psk,
        version,
        obfs_mode,
        obfs_host: _,
    } = &cfg.protocol
    else {
        return Err(Error::config("snell::serve called with a non-snell protocol"));
    };
    // New()'s gate (listener/snell/server.go:37-52), verbatim messages.
    let version = parse_server_version(*version)?;
    if psk.is_empty() {
        return Err(Error::config("snell inbound requires psk"));
    }
    let http_obfs = match obfs_mode.as_str() {
        "" => false,
        "http" => true,
        "tls" => return Err(Error::config(OBFS_TLS_UNSUPPORTED)),
        other => {
            return Err(Error::config(format!(
                "snell inbound obfs mode error: {other}"
            )));
        }
    };
    let ctx = SnellListenCtx {
        psk: psk.as_bytes().to_vec(),
        version,
        http_obfs,
        relay,
        tag: Arc::from(cfg.tag.as_str()),
    };
    serve_with(cfg, move |stream, peer, port| {
        let ctx = ctx.clone();
        async move { handle_conn(stream, peer, port, ctx).await }
    })
    .await
}

/// HandleConn (listener/snell/server.go:146-172): obfs wrap, then the
/// request loop.
async fn handle_conn(
    stream: BoxProxyStream,
    peer: SocketAddr,
    port: u16,
    ctx: SnellListenCtx,
) -> Result<()> {
    let stream = if ctx.http_obfs {
        http_obfs_server(stream).await?
    } else {
        stream
    };
    let conn = SnellServerConn::new(stream, &ctx.psk, ctx.version)?;
    serve_loop(conn, peer, port, ctx).await;
    Ok(())
}

/// Boxed request-loop continuation — the recursion breaker: the
/// continuation closure hands back an erased future instead of an
/// inline async block, so the loop's own generator type never has to
/// prove its own `Send`.
fn continue_serve_loop(
    conn: SnellServerConn,
    peer: SocketAddr,
    port: u16,
    ctx: SnellListenCtx,
) -> Pin<Box<dyn std::future::Future<Output = ()> + Send>> {
    Box::pin(serve_loop(conn, peer, port, ctx))
}

/// The request loop — `for { handleRequest }` (server.go:166-171). A
/// reusable request returns into this loop from the relay stream's Drop
/// continuation instead of straight through.
async fn serve_loop(conn: SnellServerConn, peer: SocketAddr, port: u16, ctx: SnellListenCtx) {
    if let Err(e) = serve_loop_inner(conn, peer, port, ctx).await {
        tracing::debug!(target: "engine", "snell server {peer}: {e}");
    }
}

async fn serve_loop_inner(
    conn: SnellServerConn,
    peer: SocketAddr,
    port: u16,
    ctx: SnellListenCtx,
) -> Result<()> {
    // One request per entry: the loop-back for reusable requests comes
    // from the Drop continuation re-entering serve_loop, not from a
    // literal loop here (the relay owns the conn between requests).
    let mut conn = conn;
    match conn.read_request().await? {
        // Answered inline with a pong frame; the conn closes
        // (server.go:188-191).
        SnellServerRequest::Ping => Ok(()),
        SnellServerRequest::Udp { .. } => {
            // handleUDP (server.go:257-294): the tunnel reply first,
            // then the datagram pumps own the conn to the end (UDP
            // sessions never reuse).
            conn.write_tunnel_reply().await?;
            udp_relay(conn.into_udp(), peer, port, ctx).await;
            Ok(())
        }
        SnellServerRequest::Connect { target, reuse, .. } => {
            // handleTCP (server.go:226-255): the relay owns the
            // stream; when it finishes, Drop performs the close
            // semantics and — on the reuse path — re-enters this loop
            // through the continuation.
            let next_ctx = ctx.clone();
            let next_peer = peer;
            let next_port = port;
            let next: SnellServerNext = Arc::new(move |conn| {
                continue_serve_loop(conn, next_peer, next_port, next_ctx.clone())
            });
            let stream = conn.into_tcp(reuse, Some(next));
            hand_off(
                &ctx.tag,
                "snell",
                port,
                peer,
                target,
                Box::new(stream),
                ctx.relay.clone(),
            );
            Ok(())
        }
    }
}

/// The UDP relay — handleUDP + udpPacket.WriteBack
/// (listener/snell/server.go:257-294, 387-410): one AEAD frame per
/// datagram both ways, bridged to [`crate::inbound::RelayHandler::handle_udp`].
///
/// Response addresses must be IPs (`WritePacketResponse` has no domain
/// form — upstream resolves domain targets before replying); a domain
/// downlink datagram is dropped, mirroring a lossy link.
async fn udp_relay(io: SnellServerUdp, peer: SocketAddr, _port: u16, ctx: SnellListenCtx) {
    let (up_tx, up_rx) = tokio::sync::mpsc::channel::<(crate::addr::NetAddr, Vec<u8>)>(64);
    let (down_tx, mut down_rx) = tokio::sync::mpsc::channel::<(crate::addr::NetAddr, Vec<u8>)>(64);
    ctx.relay.handle_udp(peer, ctx.tag.to_string(), up_rx, down_tx);

    let (mut rd, mut wr) = tokio::io::split(io);
    // Uplink: one AEAD frame per datagram, parsed and forwarded until
    // the session ends (server.go:266-293).
    let uplink = tokio::spawn(async move {
        let mut buf = vec![0u8; MAX_PACKET_LENGTH + 32];
        loop {
            let n = match rd.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            let (target, payload) = match parse_snell_udp_request(&buf[..n]) {
                Ok(p) => p,
                Err(e) => {
                    tracing::debug!(target: "engine", "snell udp frame from {peer}: {e}");
                    break;
                }
            };
            if up_tx.send((target, payload)).await.is_err() {
                break;
            }
        }
    });
    // Downlink: relay replies sealed one frame per datagram
    // (udpPacket.WriteBack → WritePacketResponse, server.go:399-410).
    while let Some((from, data)) = down_rx.recv().await {
        match snell_udp_response_frame(&from, &data) {
            Ok(frame) => {
                if wr.write_all(&frame).await.is_err() {
                    break;
                }
                let _ = wr.flush().await;
            }
            Err(_) => {
                tracing::debug!(target: "engine", "snell udp: dropping domain downlink datagram")
            }
        }
    }
    let _ = uplink.await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::{Host, NetAddr};
    use crate::inbound::proxy_server::test_support::Capture;
    use crate::proto::snell::{handshake, udp_session, SnellOut};
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    fn fresh_psk() -> String {
        format!("psk-{:016x}", rand::random::<u64>())
    }

    fn cfg(version: u8, psk: &str, obfs_mode: &str) -> ServerConfig {
        ServerConfig {
            tag: "snell-test".into(),
            bind: "127.0.0.1".into(),
            port: 0,
            protocol: ServerProtocol::Snell {
                psk: psk.into(),
                version,
                obfs_mode: obfs_mode.into(),
                obfs_host: "cdn.example".into(),
            },
        }
    }

    async fn spawn_server(version: u8, psk: &str) -> (Arc<Capture>, SocketAddr) {
        spawn_server_obfs(version, psk, "").await
    }

    async fn spawn_server_obfs(
        version: u8,
        psk: &str,
        obfs_mode: &str,
    ) -> (Arc<Capture>, SocketAddr) {
        let capture = Capture::new();
        let addr = serve(&cfg(version, psk, obfs_mode), capture.clone())
            .await
            .unwrap();
        (capture, addr)
    }

    fn client(psk: &str, port: u16, version: u8) -> SnellOut {
        SnellOut {
            server: "127.0.0.1".into(),
            port,
            psk: psk.into(),
            version,
            udp: false,
        }
    }

    /// Connect + handshake + one echo exchange through the listener.
    async fn roundtrip(psk: &str, addr: SocketAddr, version: u8) -> NetAddr {
        let tcp = TcpStream::connect(addr).await.unwrap();
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let mut stream = handshake(Box::new(tcp), &client(psk, addr.port(), version), &target, false)
            .await
            .unwrap();
        stream.write_all(b"ping-snell").await.unwrap();
        let mut buf = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
            .await
            .expect("echo timeout")
            .unwrap();
        assert_eq!(&buf, b"ping-snell");
        target
    }

    #[tokio::test]
    async fn tcp_roundtrip_all_versions() {
        // The engine's own snell client (every wire version, plus v5
        // riding v4) connects through the listener end to end.
        for version in [1u8, 2, 3, 4, 5] {
            let psk = fresh_psk();
            let (capture, addr) = spawn_server(version, &psk).await;
            let target = roundtrip(&psk, addr, version).await;
            assert_eq!(capture.targets(), vec![target], "version {version}");
        }
    }

    #[tokio::test]
    async fn default_version_is_v4_on_the_server() {
        // version 0 → v4 (listener/snell/server.go:37-39): a v4 client
        // interops with a version-0 listener.
        let psk = fresh_psk();
        let (capture, addr) = spawn_server(0, &psk).await;
        let target = roundtrip(&psk, addr, 4).await;
        assert_eq!(capture.targets(), vec![target]);
    }

    #[tokio::test]
    async fn wrong_psk_relays_nothing() {
        let (capture, addr) = spawn_server(4, &fresh_psk()).await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let mut stream =
            handshake(Box::new(tcp), &client(&fresh_psk(), addr.port(), 4), &target, false)
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

    #[tokio::test]
    async fn udp_session_roundtrip_v3_v4() {
        // The engine's UDP client (udp_session) through the listener's
        // UDP command: request frames parsed, responses IP-framed.
        for version in [3u8, 4] {
            let psk = fresh_psk();
            let (capture, addr) = spawn_server(version, &psk).await;
            let tcp = TcpStream::connect(addr).await.unwrap();
            let mut cfg = client(&psk, addr.port(), version);
            cfg.udp = true;
            let mut udp = udp_session(&cfg, Box::new(tcp)).await.unwrap();
            // An IP target keeps the echo on the IP-only response wire.
            let target = NetAddr::ip("8.8.8.8".parse().unwrap(), 53);
            udp.send_to(&target, b"dgram").await.unwrap();
            let mut buf = [0u8; 1500];
            let (from, n) =
                tokio::time::timeout(Duration::from_secs(10), udp.recv_from(&mut buf))
                    .await
                    .expect("udp response timeout")
                    .unwrap();
            assert_eq!(&buf[..n], b"dgram");
            assert_eq!(from, target, "the echo comes from the requested host");
            // The datagram went through the relay's UDP side.
            assert_eq!(capture.udp_targets(), vec![target]);
            assert_eq!(capture.udp_sessions().len(), 1);
            assert_eq!(capture.udp_sessions()[0].1, "snell-test");
            assert_eq!(capture.relayed(), 0);
        }
    }

    #[tokio::test]
    async fn udp_domain_target_reaches_relay() {
        // A domain request datagram is forwarded to the relay (the
        // Capture echoes it back as a domain, which the response codec
        // drops — upstream resolves before replying).
        let psk = fresh_psk();
        let (capture, addr) = spawn_server(4, &psk).await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut cfg = client(&psk, addr.port(), 4);
        cfg.udp = true;
        let mut udp = udp_session(&cfg, Box::new(tcp)).await.unwrap();
        let target = NetAddr::domain("dns.example", 53).unwrap();
        udp.send_to(&target, b"q").await.unwrap();
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(capture.udp_targets(), vec![target]);
    }

    #[tokio::test]
    async fn http_obfs_roundtrip() {
        // obfs-mode http: the engine's http-obfs client below the snell
        // client, the server-side wrapper above the snell server.
        let psk = fresh_psk();
        let (capture, addr) = spawn_server_obfs(4, &psk, "http").await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let settings = crate::proto::obfs::ObfsSettings::new("cdn.example", addr.port());
        let transport = crate::proto::obfs::http_obfs_client(Box::new(tcp), &settings)
            .await
            .unwrap();
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let mut stream =
            handshake(transport, &client(&psk, addr.port(), 4), &target, false)
                .await
                .unwrap();
        stream.write_all(b"obfs-ping").await.unwrap();
        let mut buf = [0u8; 9];
        tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
            .await
            .expect("echo timeout")
            .unwrap();
        assert_eq!(&buf, b"obfs-ping");
        assert_eq!(capture.targets(), vec![target]);
    }

    #[tokio::test]
    async fn pooled_client_reuses_one_listener_conn() {
        // The engine's snell pool through the listener: two requests,
        // one TCP conn (the server's reuse loop + zero-chunk dance).
        let psk = fresh_psk();
        let (_capture, addr) = spawn_server(4, &psk).await;
        let addr_str = addr.to_string();
        let dials = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let dials2 = dials.clone();
        let pool = crate::proto::snell::SnellPool::with_dialer(
            client(&psk, addr.port(), 4),
            move || {
                let addr_str = addr_str.clone();
                let dials = dials2.clone();
                Box::pin(async move {
                    dials.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let tcp = TcpStream::connect(addr_str.as_str())
                        .await
                        .map_err(|e| Error::network(e.to_string()))?;
                    Ok(Box::new(tcp) as BoxProxyStream)
                })
            },
        )
        .unwrap();
        let target = NetAddr::domain("echo.test", 443).unwrap();
        {
            let mut conn = pool.dial(&target).await.unwrap();
            conn.write_all(b"first").await.unwrap();
            conn.flush().await.unwrap();
            let mut buf = [0u8; 5];
            tokio::time::timeout(Duration::from_secs(10), conn.read_exact(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buf, b"first");
            conn.shutdown().await.unwrap();
            let mut tail = [0u8; 4];
            let n = tokio::time::timeout(Duration::from_secs(10), conn.read(&mut tail))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(n, 0, "the server's zero chunk ends the request");
        }
        tokio::time::sleep(Duration::from_millis(150)).await;
        assert_eq!(pool.idle_len().await, 1);
        {
            let mut conn = pool.dial(&target).await.unwrap();
            conn.write_all(b"seco").await.unwrap();
            conn.flush().await.unwrap();
            let mut buf = [0u8; 4];
            tokio::time::timeout(Duration::from_secs(10), conn.read_exact(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buf, b"seco");
        }
        assert_eq!(
            dials.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "one listener conn served both requests"
        );
    }

    #[tokio::test]
    async fn config_gates_match_upstream() {
        let capture = Capture::new();
        // Version gate (server.go:43).
        let err = serve(&cfg(6, "p", ""), capture.clone()).await.unwrap_err();
        assert!(
            err.to_string().contains("snell inbound version 6 is not supported"),
            "{err}"
        );
        // PSK gate (server.go:45-47).
        let err = serve(&cfg(4, "", ""), capture.clone()).await.unwrap_err();
        assert!(err.to_string().contains("snell inbound requires psk"), "{err}");
        // obfs mode gate (server.go:48-52) + the tls precise error.
        let err = serve(&cfg(4, "p", "weird"), capture.clone()).await.unwrap_err();
        assert!(
            err.to_string().contains("snell inbound obfs mode error: weird"),
            "{err}"
        );
        let err = serve(&cfg(4, "p", "tls"), capture.clone()).await.unwrap_err();
        assert!(err.to_string().contains("tls_server.go"), "{err}");
        assert!(err.to_string().contains("obfs mode tls"), "{err}");
    }

    #[tokio::test]
    async fn version_byte_gate_rejects_bad_header() {
        // A conn whose first decrypted byte is not the protocol version
        // is dropped with no relay (handleRequest's version check,
        // server.go:180-182). Simulated with a wrong psk — same wire
        // effect (undecryptable header).
        let (capture, addr) = spawn_server(3, &fresh_psk()).await;
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        // Raw garbage: never decrypts to a valid header.
        tcp.write_all(&[0u8; 64]).await.unwrap();
        let mut buf = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(5), tcp.read(&mut buf)).await;
        match read {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!("unexpected {n} bytes from a rejected client"),
            Err(_) => panic!("timeout: server did not close the connection"),
        }
        assert_eq!(capture.relayed(), 0);
    }

    #[test]
    fn host_parse_matches_metadata_rules() {
        // metadata() (server.go:296-313): parseable IPs become IP hosts.
        let t = NetAddr::ip("10.0.0.1".parse::<std::net::IpAddr>().unwrap(), 80);
        assert!(matches!(t.host, Host::Ip(_)));
    }
}
