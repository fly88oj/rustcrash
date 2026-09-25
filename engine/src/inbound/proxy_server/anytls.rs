//! AnyTLS server listener: mihomo `listener/anytls/server.go`.
//!
//! Every accepted connection runs the auth check (`sha256(password)`
//! against the user map — single `password` or the `users` pairs), then
//! the server session from [`crate::proto::anytls`]: each client-opened
//! stream reads its target off the first PSH, gets its SYNACK, and is
//! handed to the relay with `inbound_kind` "anytls". Streams targeting
//! the uot v2 magic domain (`sp.v2.udp-over-tcp.arpa`) are bridged to
//! the UDP relay instead — the engine-side equivalent of upstream's
//! "sing handler can automatically handle UoT" (server.go:135-140).
//!
//! TLS: upstream REFUSES to serve without a fronting —
//! `disallow using AnyTLS without certificates/shadow-tls/res-tls/jls/
//! allow-insecure config` (listener/anytls/server.go:159-163) — via
//! certificate / ECH key / client-auth / shadow-tls / restls / jls
//! fields on `LC.AnyTLSServer`. Our [`crate::inbound::proxy_server::ServerProtocol::AnyTls`]
//! carries only `{password, users}`, so this listener serves PLAIN
//! TCP + auth (the trojan `tls: None` position): safe for tests and
//! for transports fronted elsewhere. See [`TLS_REQUIRED_NOTE`] for the
//! integrator note.
//!
//! Integrator deltas (upstream `LC.AnyTLSServer` fields our enum
//! lacks): `certificate`/`private-key` (+ `ServerTls`), `client-auth-*`,
//! `ech-key`, `shadow-tls`/`res-tls`/`jls` stacking, and
//! `padding-scheme` (this listener pins the default scheme;
//! [`crate::proto::anytls::run_server_session`] already accepts a raw
//! scheme for when the enum grows the field).

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::addr::{Host, NetAddr};
use crate::error::{Error, Result};
use crate::inbound::proxy_server::{
    hand_off, serve_with, ServerConfig, ServerProtocol, SharedRelay,
};
use crate::proto::anytls::{
    parse_uot_packet, parse_uot_request, read_auth, run_server_session, uot_packet_frame,
    AnyTlsOnStream, AnyTlsServerStream, AnyTlsUserMap, DEFAULT_PADDING_SCHEME, UOT_MAGIC_ADDRESS,
};
use crate::stream::BoxProxyStream;

/// The upstream gate this listener cannot express: production anytls is
/// TLS-fronted. Verbatim upstream error (server.go:162) cited for the
/// integrator adding `tls`/stacking fields to `ServerProtocol::AnyTls`.
pub const TLS_REQUIRED_NOTE: &str = concat!(
    "anytls upstream refuses plaintext listeners: 'disallow using AnyTLS ",
    "without certificates/shadow-tls/res-tls/jls/allow-insecure config' ",
    "(listener/anytls/server.go:159-163); this engine listener serves ",
    "plain TCP + auth until ServerProtocol::AnyTls grows tls/stacking fields"
);

/// Serve an anytls listener; returns the bound address.
pub async fn serve(cfg: &ServerConfig, relay: SharedRelay) -> Result<SocketAddr> {
    let ServerProtocol::AnyTls { password, users } = &cfg.protocol else {
        return Err(Error::config(
            "anytls::serve called with a non-anytls protocol",
        ));
    };
    let user_map = AnyTlsUserMap::new(password, users);
    if user_map.is_empty() {
        // Nothing would ever authenticate (upstream's empty-Users map
        // rejects every conn); refuse at serve time instead.
        return Err(Error::config(
            "anytls listener requires a password or users",
        ));
    }
    tracing::debug!(target: "engine", "{TLS_REQUIRED_NOTE}");
    let tag: Arc<str> = Arc::from(cfg.tag.as_str());
    let user_map = Arc::new(user_map);
    serve_with(cfg, move |stream, peer, port| {
        let user_map = user_map.clone();
        let relay = relay.clone();
        let tag = tag.clone();
        async move { handle_conn(stream, peer, port, &user_map, tag, relay).await }
    })
    .await
}

/// HandleConn (listener/anytls/server.go:206-263): auth, then the
/// session.
async fn handle_conn(
    stream: BoxProxyStream,
    peer: SocketAddr,
    port: u16,
    user_map: &AnyTlsUserMap,
    tag: Arc<str>,
    relay: SharedRelay,
) -> Result<()> {
    let mut stream = stream;
    // Auth (server.go:210-240): an unknown hash closes silently — no
    // oracle, nothing relayed.
    let Some(user) = read_auth(&mut stream, user_map).await? else {
        return Ok(());
    };
    let on_stream: AnyTlsOnStream = {
        let relay = relay.clone();
        let tag = tag.clone();
        Arc::new(move |stream| {
            let relay = relay.clone();
            let tag = tag.clone();
            tokio::spawn(async move {
                handle_stream(stream, peer, port, tag, relay).await;
            });
        })
    };
    // NewServerSession + Run + Close (server.go:242-262).
    run_server_session(stream, DEFAULT_PADDING_SCHEME, user, on_stream).await;
    Ok(())
}

/// One client-opened stream — the `onNewStream` callback
/// (listener/anytls/server.go:242-260): read the destination, report
/// success, relay; the uot magic destination becomes a UDP association.
async fn handle_stream(
    mut stream: AnyTlsServerStream,
    peer: SocketAddr,
    port: u16,
    tag: Arc<str>,
    relay: SharedRelay,
) {
    let target = match stream.read_target().await {
        Ok(t) => t,
        Err(e) => {
            tracing::debug!(target: "engine", "anytls stream from {peer}: {e}");
            stream.handshake_failure(&e.to_string());
            return;
        }
    };
    if target.host == Host::Domain(UOT_MAGIC_ADDRESS.to_string()) {
        // UDP over uot: the sing handler's UoT conversion
        // (server.go:135-140, "Using sing handler can automatically
        // handle UoT").
        stream.handshake_success();
        uot_relay(stream, peer, tag, relay).await;
        return;
    }
    // h.NewConnection — "we report success directly" (server.go:250-252).
    stream.handshake_success();
    hand_off(
        &tag,
        "anytls",
        port,
        peer,
        target,
        Box::new(stream),
        relay,
    );
}

/// Bridge a uot v2 stream to [`crate::inbound::RelayHandler::handle_udp`]:
/// the lazy request prefix (`[isConnect][socksaddr]`) is consumed, then
/// each `uot-addr || be16 len || payload` datagram flows uplink and
/// each relay reply is framed back down — the wire the engine's own
/// [`crate::proto::anytls::AnyTlsUdp`] speaks.
async fn uot_relay(stream: AnyTlsServerStream, peer: SocketAddr, tag: Arc<str>, relay: SharedRelay) {
    let (up_tx, up_rx) = tokio::sync::mpsc::channel::<(NetAddr, Vec<u8>)>(64);
    let (down_tx, mut down_rx) = tokio::sync::mpsc::channel::<(NetAddr, Vec<u8>)>(64);
    relay.handle_udp(peer, tag.to_string(), up_rx, down_tx);

    let (mut rd, mut wr) = tokio::io::split(stream);
    let uplink = tokio::spawn(async move {
        let mut buf: Vec<u8> = Vec::with_capacity(16 * 1024);
        let mut request_consumed = false;
        let mut chunk = [0u8; 16 * 1024];
        loop {
            let n = match rd.read(&mut chunk).await {
                Ok(0) | Err(_) => break,
                Ok(n) => n,
            };
            buf.extend_from_slice(&chunk[..n]);
            loop {
                if !request_consumed {
                    match parse_uot_request(&buf) {
                        Ok(Some((_is_connect, _target, consumed))) => {
                            buf.drain(..consumed);
                            request_consumed = true;
                            continue;
                        }
                        Ok(None) => break,
                        Err(e) => {
                            tracing::debug!(target: "engine", "anytls uot request: {e}");
                            return;
                        }
                    }
                }
                match parse_uot_packet(&buf) {
                    Ok(Some((from, payload, consumed))) => {
                        buf.drain(..consumed);
                        if up_tx.send((from, payload)).await.is_err() {
                            return;
                        }
                    }
                    Ok(None) => break,
                    Err(e) => {
                        tracing::debug!(target: "engine", "anytls uot packet: {e}");
                        return;
                    }
                }
            }
        }
    });
    while let Some((from, data)) = down_rx.recv().await {
        let frame = match uot_packet_frame(&from, &data) {
            Ok(f) => f,
            Err(_) => {
                tracing::debug!(target: "engine", "anytls uot: dropping oversize datagram");
                continue;
            }
        };
        if wr.write_all(&frame).await.is_err() {
            break;
        }
        let _ = wr.flush().await;
    }
    let _ = uplink.await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbound::proxy_server::test_support::Capture;
    use crate::proto::anytls::{connect_plain, udp_stream_plain, AnyTlsOut};
    use std::time::Duration;
    use tokio::io::AsyncWriteExt;
    use tokio::net::TcpStream;

    fn fresh_password() -> String {
        format!("pw-{:016x}", rand::random::<u64>())
    }

    fn cfg(password: &str, users: Vec<(String, String)>) -> ServerConfig {
        ServerConfig {
            tag: "anytls-test".into(),
            bind: "127.0.0.1".into(),
            port: 0,
            protocol: ServerProtocol::AnyTls {
                password: password.into(),
                users,
            },
        }
    }

    async fn spawn_server(password: &str) -> (Arc<Capture>, SocketAddr) {
        let capture = Capture::new();
        let addr = serve(&cfg(password, Vec::new()), capture.clone())
            .await
            .unwrap();
        (capture, addr)
    }

    fn client(password: &str, port: u16) -> AnyTlsOut {
        AnyTlsOut {
            server: "127.0.0.1".into(),
            port,
            password: password.into(),
            sni: String::new(),
            skip_verify: true,
            udp: true,
            jls: None,
            ech: None,
        }
    }

    #[tokio::test]
    async fn tcp_roundtrip_single_password() {
        // The engine's own anytls client (plain-transport path) through
        // the listener: auth, stream open, echo.
        let password = fresh_password();
        let (capture, addr) = spawn_server(&password).await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let mut stream = connect_plain(&client(&password, addr.port()), Box::new(tcp), &target)
            .await
            .unwrap();
        stream.write_all(b"ping-anytls").await.unwrap();
        let mut buf = [0u8; 11];
        tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
            .await
            .expect("echo timeout")
            .unwrap();
        assert_eq!(&buf, b"ping-anytls");
        assert_eq!(capture.targets(), vec![target]);
    }

    // The wrong-credential tests below observe the server's close
    // THROUGH the client's session tasks (channel-mediated reads); on a
    // current-thread test runtime the channel wakeups around the
    // socket close starve, so they run on a small multi-thread runtime
    // — the relay assertions are identical either way.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multi_user_roundtrip_and_wrong_user_rejected() {
        // users-mode: a listed user's password works, an unlisted one is
        // closed silently.
        let users = vec![("alice".to_string(), "pw-a".to_string())];
        let capture = Capture::new();
        let addr = serve(&cfg("", users), capture.clone()).await.unwrap();
        let tcp = TcpStream::connect(addr).await.unwrap();
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let mut stream = connect_plain(&client("pw-a", addr.port()), Box::new(tcp), &target)
            .await
            .unwrap();
        stream.write_all(b"alice-ping").await.unwrap();
        let mut buf = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(10), stream.read(&mut buf))
            .await
            .expect("echo timeout")
            .unwrap();
        assert_eq!(&buf, b"alice-ping");
        assert_eq!(capture.targets(), vec![target.clone()]);

        // An unknown password never relays.
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut stream = match connect_plain(
            &client(&fresh_password(), addr.port()),
            Box::new(tcp),
            &target,
        )
        .await
        {
            Ok(s) => s,
            Err(_) => {
                assert_eq!(capture.relayed(), 1, "only alice's stream relayed");
                return;
            }
        };
        let _ = stream.write_all(b"x").await;
        let mut buf = [0u8; 8];
        let read = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
        match read {
            Ok(Ok(0)) | Ok(Err(_)) => {}
            Ok(Ok(n)) => panic!("unexpected {n} bytes from a rejected client"),
            Err(_) => panic!("timeout: server did not close the connection"),
        }
        assert_eq!(capture.relayed(), 1, "only alice's stream relayed");
    }

    // See the note on multi_user_roundtrip_and_wrong_user_rejected.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn wrong_password_relays_nothing() {
        let (capture, addr) = spawn_server(&fresh_password()).await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let target = NetAddr::domain("echo.test", 443).unwrap();
        let mut stream = match connect_plain(
            &client(&fresh_password(), addr.port()),
            Box::new(tcp),
            &target,
        )
        .await
        {
            Ok(s) => s,
            Err(_) => {
                assert_eq!(capture.relayed(), 0);
                return;
            }
        };
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
    async fn udp_uot_roundtrip() {
        // The engine's uot v2 client through the listener's magic-domain
        // bridge: datagrams in, uot-framed replies out (domains allowed
        // on the uot wire, unlike snell's response form).
        let password = fresh_password();
        let (capture, addr) = spawn_server(&password).await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let mut udp = udp_stream_plain(&client(&password, addr.port()), Box::new(tcp))
            .await
            .unwrap();
        let target = NetAddr::domain("dns.example", 53).unwrap();
        udp.send_to(&target, b"uot-ping").await.unwrap();
        let mut buf = [0u8; 64];
        let (from, n) =
            tokio::time::timeout(Duration::from_secs(10), udp.recv_from(&mut buf))
                .await
                .expect("uot response timeout")
                .unwrap();
        assert_eq!(from, target, "the echo comes from the requested host");
        assert_eq!(&buf[..n], b"uot-ping");
        assert_eq!(capture.udp_targets(), vec![target]);
        assert_eq!(capture.udp_sessions().len(), 1);
        assert_eq!(capture.udp_sessions()[0].1, "anytls-test");
        assert_eq!(capture.relayed(), 0, "uot never touches the TCP relay");
    }

    #[tokio::test]
    async fn two_streams_share_one_session() {
        // The session muxes: two connect_plain clients... one session
        // carries both streams (distinct sids), each handed to the relay
        // independently.
        let password = fresh_password();
        let (capture, addr) = spawn_server(&password).await;
        let tcp = TcpStream::connect(addr).await.unwrap();
        let cfg = client(&password, addr.port());
        let session = crate::proto::anytls::open_session_plain(&cfg, Box::new(tcp))
            .await
            .unwrap();
        let t1 = NetAddr::domain("one.test", 443).unwrap();
        let t2 = NetAddr::domain("two.test", 80).unwrap();
        let mut s1 = session.open_stream(&t1).await.unwrap();
        let mut s2 = session.open_stream(&t2).await.unwrap();
        s1.write_all(b"one").await.unwrap();
        s2.write_all(b"two").await.unwrap();
        let mut b1 = [0u8; 3];
        let mut b2 = [0u8; 3];
        tokio::time::timeout(Duration::from_secs(10), s1.read(&mut b1))
            .await
            .expect("s1 echo timeout")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(10), s2.read(&mut b2))
            .await
            .expect("s2 echo timeout")
            .unwrap();
        assert_eq!(&b1, b"one");
        assert_eq!(&b2, b"two");
        let mut targets = capture.targets();
        targets.sort_by_key(|t| t.host.to_text());
        assert_eq!(targets, vec![t1, t2]);
    }

    #[tokio::test]
    async fn empty_credentials_fail_before_binding() {
        let capture = Capture::new();
        let err = serve(&cfg("", Vec::new()), capture).await.unwrap_err();
        assert!(
            err.to_string().contains("anytls listener requires a password or users"),
            "{err}"
        );
    }

    #[test]
    fn tls_note_cites_upstream() {
        assert!(TLS_REQUIRED_NOTE.contains("listener/anytls/server.go:159-163"));
        assert!(TLS_REQUIRED_NOTE.contains("disallow using AnyTLS"));
    }
}
