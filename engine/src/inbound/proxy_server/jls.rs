//! JLS server listener (mihomo `listener/jls`): multi-user JLS
//! termination over every accepted TCP conn, with the dest fallback
//! relay for non-JLS traffic.
//!
//! ## The relay model, from the sources
//!
//! Upstream `jls.Server` (`transport/jls/jls.go:176-197`) returns the
//! authenticated plaintext conn and parses no target — the target lives
//! in the proxied protocol the listener is composed with. The only
//! upstream composition is anytls under JLS
//! (`listener/anytls/server.go:117-119`, where every inner stream's
//! destination is read out of the conn,
//! `M.SocksaddrSerializer.ReadAddrPort`); `dest` is used exclusively by
//! the fallback (`relayFallback`, `transport/jls/jls.go:199-212`). So
//! the JLS listener tunnels arbitrary targets like trojan — this port
//! reads an RFC 1928 socks-addr from the head of the decrypted stream
//! and relays there — and non-JLS conns are relayed toward `dest`
//! (rate-limited per `rate-limit`). The engine's
//! [`crate::inbound::RelayHandler`] is receive-only, so the fallback
//! dials `dest` directly, the same adaptation as the
//! restls/tlsmirror listeners.
//!
//! The authenticated username upstream recovers via
//! `jls.UserFromConn` (`listener/jls/jls.go:45-47`) for rules has no
//! field on the engine's [`crate::inbound::TcpMeta`] — it is logged at
//! debug level here (note for the integrator: add a `user` field to
//! `TcpMeta` to route on it).

use std::net::SocketAddr;

use crate::addr::{Host, NetAddr};
use crate::error::{Error, Result};
use crate::inbound::proxy_server::{
    hand_off, read_socks_addr, serve_with, ServerConfig, ServerProtocol,
};
use crate::inbound::SharedRelay;
use crate::proto::jls::{self, JlsServerConfig, JlsServerHandshake, JlsUser};
use crate::stream::BoxProxyStream;
use tracing::debug;

/// Serve a JLS listener; returns the bound address.
pub async fn serve(cfg: &ServerConfig, relay: SharedRelay) -> Result<SocketAddr> {
    let ServerProtocol::Jls {
        sni,
        dest,
        users,
        alpn,
        rate_limit,
    } = &cfg.protocol
    else {
        return Err(Error::config("jls::serve called with a non-jls protocol"));
    };
    // NewServerConfig (transport/jls/jls.go:121-134): dest is required
    // and must be host:port (net.SplitHostPort); an empty SNI defaults
    // to the dest host.
    let (dest_host, dest_port) = split_dest(dest)?;
    let sni = if sni.is_empty() {
        dest_host.clone()
    } else {
        sni.clone()
    };
    let users: Vec<JlsUser> = users
        .iter()
        .map(|(username, password)| JlsUser {
            username: username.clone(),
            password: password.clone(),
        })
        .collect();
    let server_cfg = JlsServerConfig::new(&sni, users, alpn.clone())?;
    let dest_addr = NetAddr {
        host: parse_host(&dest_host)?,
        port: dest_port,
    };
    let rate_limit = *rate_limit as u64;
    let tag = cfg.tag.clone();

    serve_with(cfg, move |stream, peer, port| {
        let server_cfg = server_cfg.clone();
        let relay = relay.clone();
        let tag = tag.clone();
        let dest_addr = dest_addr.clone();
        async move {
            handle_conn(&server_cfg, stream, peer, port, &tag, &relay, dest_addr, rate_limit).await
        }
    })
    .await
}

/// One accepted conn: the JLS server handshake, then either the
/// authenticated relay (target inside the stream) or the dest fallback.
/// A completed fallback is upstream's `ErrFallbackCompleted` — the
/// plain `Ok(())` here (logged at debug by `serve_with`).
#[allow(clippy::too_many_arguments)]
async fn handle_conn(
    server_cfg: &JlsServerConfig,
    stream: BoxProxyStream,
    peer: SocketAddr,
    port: u16,
    tag: &str,
    relay: &SharedRelay,
    dest_addr: NetAddr,
    rate_limit: u64,
) -> Result<()> {
    match jls::server(server_cfg, stream).await {
        Ok(JlsServerHandshake::Authenticated { mut stream, user }) => {
            // The target is inside the stream (see the module docs).
            let target = read_socks_addr(&mut stream).await?;
            // UserFromConn semantics: the authenticated user rides the
            // connection for rules; TcpMeta has no field yet — log it.
            debug!(
                target: "engine",
                user = %user,
                "jls listener {tag}: user {user} relayed to {target}"
            );
            hand_off(tag, "jls", port, peer, target, stream, relay.clone());
            Ok(())
        }
        Ok(JlsServerHandshake::Fallback { conn, prefix }) => {
            // relayFallback (transport/jls/jls.go:199-212): toward dest,
            // the upstream side rate-limited.
            jls::relay_fallback(conn, prefix, dest_addr.clone(), rate_limit).await?;
            debug!(
                target: "engine",
                "jls listener {tag}: non-JLS conn from {peer} relayed to {dest_addr}"
            );
            Ok(())
        }
        // A flight already reached the client (recorder.wroteToClient,
        // jls.go:183-186): close, relay nothing.
        Err(e) => Err(e),
    }
}

/// `dest` must carry a port (`net.SplitHostPort`, jls.go:127-130).
fn split_dest(dest: &str) -> Result<(String, u16)> {
    let (host, port) = dest
        .rsplit_once(':')
        .ok_or_else(|| Error::config(format!("jls: invalid dest address: {dest:?}")))?;
    if host.is_empty() || port.is_empty() || !port.chars().all(|c| c.is_ascii_digit()) {
        return Err(Error::config(format!("jls: invalid dest address: {dest:?}")));
    }
    let port = port
        .parse::<u16>()
        .map_err(|_| Error::config(format!("jls: invalid dest address: {dest:?}")))?;
    Ok((host.to_string(), port))
}

fn parse_host(host: &str) -> Result<Host> {
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        Ok(Host::Ip(ip))
    } else {
        Ok(Host::Domain(host.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbound::proxy_server::test_support::Capture;
    use crate::proto::jls::JlsOut;
    use crate::proto::reality::profiles::UtslProfile;
    use std::time::{Duration, Instant};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    fn listener_cfg(users: &[(&str, &str)], dest: &str) -> ServerConfig {
        ServerConfig {
            tag: "jls-test".into(),
            bind: "127.0.0.1".into(),
            port: 0,
            protocol: ServerProtocol::Jls {
                sni: "jls.test".into(),
                dest: dest.into(),
                users: users
                    .iter()
                    .map(|(u, p)| (u.to_string(), p.to_string()))
                    .collect(),
                alpn: Vec::new(),
                rate_limit: 0,
            },
        }
    }

    /// A plain TCP recorder/echo standing in for the camouflage `dest`.
    async fn spawn_dest_echo() -> (SocketAddr, std::sync::Arc<std::sync::Mutex<Vec<u8>>>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let seen = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let seen2 = seen.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    continue;
                };
                let seen = seen2.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    loop {
                        match sock.read(&mut buf).await {
                            Ok(0) | Err(_) => break,
                            Ok(n) => {
                                seen.lock().unwrap().extend_from_slice(&buf[..n]);
                                let _ = sock.write_all(&buf[..n]).await;
                            }
                        }
                    }
                });
            }
        });
        (addr, seen)
    }

    /// The engine's own JLS client dialing the listener, then sending the
    /// in-stream socks-addr target the listener relays toward.
    async fn client_conn(
        addr: SocketAddr,
        username: &str,
        password: &str,
        fingerprint: Option<UtslProfile>,
        target: &NetAddr,
    ) -> Result<BoxProxyStream> {
        let cfg = JlsOut {
            username: username.into(),
            password: password.into(),
            sni: "jls.test".into(),
            alpn: Vec::new(),
            skip_cert_verify: true,
            fingerprint,
        };
        let tcp = TcpStream::connect(addr).await.expect("connect listener");
        let mut stream = crate::proto::jls::connect(&cfg, Box::new(tcp)).await?;
        let mut head = Vec::new();
        crate::addr::encode_socks_addr(&mut head, &target.host, target.port);
        stream.write_all(&head).await?;
        Ok(stream)
    }

    #[tokio::test]
    async fn engine_client_roundtrips_through_the_listener_both_users() {
        // Fake credentials only (loopback, never real secrets).
        let (dest_addr, _seen) = spawn_dest_echo().await;
        let capture = Capture::new();
        let cfg = listener_cfg(
            &[("user1", "pass1"), ("user2", "pass2")],
            &dest_addr.to_string(),
        );
        let addr = serve(&cfg, capture.clone()).await.expect("serve");
        let target = NetAddr::domain("target.example", 443).unwrap();

        for (user, pass) in [("user1", "pass1"), ("user2", "pass2")] {
            let mut stream = tokio::time::timeout(
                Duration::from_secs(20),
                client_conn(addr, user, pass, None, &target),
            )
            .await
            .expect("client handshake timeout")
            .expect("client handshake failed");

            let payload = format!("through jls listener as {user}");
            stream.write_all(payload.as_bytes()).await.unwrap();
            let mut buf = vec![0u8; payload.len()];
            tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
                .await
                .expect("echo timeout")
                .unwrap();
            assert_eq!(buf, payload.as_bytes());
            let _ = stream.shutdown().await;
        }

        // Both authenticated conns reached the relay with the in-stream
        // target (the trojan-like model; see the module docs).
        assert_eq!(capture.relayed(), 2);
        let targets = capture.targets();
        assert_eq!(targets.len(), 2);
        for t in &targets {
            assert_eq!(t.to_string(), "target.example:443");
        }
    }

    #[tokio::test]
    async fn fingerprint_client_roundtrips_through_the_listener() {
        let (dest_addr, _seen) = spawn_dest_echo().await;
        let capture = Capture::new();
        let cfg = listener_cfg(&[("user1", "pass1")], &dest_addr.to_string());
        let addr = serve(&cfg, capture.clone()).await.expect("serve");
        let target = NetAddr::domain("fp.example", 443).unwrap();

        let mut stream = tokio::time::timeout(
            Duration::from_secs(20),
            client_conn(
                addr,
                "user1",
                "pass1",
                Some(UtslProfile::parse("chrome").unwrap()),
                &target,
            ),
        )
        .await
        .expect("client handshake timeout")
        .expect("client handshake failed");

        stream.write_all(b"chrome through jls listener").await.unwrap();
        let mut buf = vec![0u8; b"chrome through jls listener".len()];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
            .await
            .expect("echo timeout")
            .unwrap();
        assert_eq!(buf, b"chrome through jls listener");
        assert_eq!(capture.relayed(), 1);
        assert_eq!(capture.targets()[0].to_string(), "fp.example:443");
    }

    #[tokio::test]
    async fn plain_tls_client_lands_on_the_dest_fallback() {
        // A genuine TLS client (no JLS stamp) hitting the port: the
        // listener relays its bytes toward dest — the camouflage site.
        let (dest_addr, seen) = spawn_dest_echo().await;
        let capture = Capture::new();
        let cfg = listener_cfg(&[("user1", "pass1")], &dest_addr.to_string());
        let addr = serve(&cfg, capture.clone()).await.expect("serve");

        // A minimal TLS client: send a ClientHello-shaped record and see
        // it arrive at dest through the fallback relay. The record is
        // self-consistent (header length == payload, len24 == body) so
        // the whole flight lands in the fallback prefix.
        let mut tcp = TcpStream::connect(addr).await.unwrap();
        let mut hello = vec![0x16, 0x03, 0x01, 0x00, 0x2b]; // record, len 43
        hello.push(0x01); // ClientHello
        hello.extend_from_slice(&[0x00, 0x00, 0x27]); // len24 = 39
        hello.extend_from_slice(&[0x03, 0x03]); // legacy_version
        hello.extend_from_slice(&[0xab; 32]); // random
        hello.extend_from_slice(&[0x00]); // empty session id
        hello.extend_from_slice(&[0x00, 0x00]); // empty cipher list
        hello.push(0x01); // compression methods length
        hello.push(0x00); // null
        assert_eq!(hello.len(), 5 + 43);
        assert_eq!(4 + 39, 43);
        tcp.write_all(&hello).await.unwrap();

        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let got = seen.lock().unwrap().clone();
            if got.len() >= hello.len() {
                assert_eq!(&got[..hello.len()], &hello[..], "prefix replayed to dest");
                break;
            }
            assert!(Instant::now() < deadline, "dest never saw the ClientHello");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        // Nothing reached the proxy relay for a plain TLS client.
        assert_eq!(capture.relayed(), 0);
    }

    #[tokio::test]
    async fn wrong_password_falls_back_instead_of_hard_closing() {
        // A JLS client with the wrong password is NOT rejected with a
        // hard close: the handshake failed with nothing written, so the
        // listener relays the conn toward dest (canFallbackJLS /
        // relayFallback) — the client's own TLS flight reaches the
        // camouflage site and the dial then fails client-side.
        let (dest_addr, seen) = spawn_dest_echo().await;
        let capture = Capture::new();
        let cfg = listener_cfg(&[("user1", "pass1")], &dest_addr.to_string());
        let addr = serve(&cfg, capture.clone()).await.expect("serve");
        let target = NetAddr::domain("target.example", 443).unwrap();

        let result = tokio::time::timeout(
            Duration::from_secs(20),
            client_conn(addr, "user1", "wrong-pass", None, &target),
        )
        .await
        .expect("timeout");

        // The echoed-back flight cannot verify — the dial fails.
        assert!(
            result.is_err(),
            "a wrong password must not authenticate"
        );
        // The fallback relay delivered the client's hello to dest.
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let len = seen.lock().unwrap().len();
            if len > 0 {
                break;
            }
            assert!(Instant::now() < deadline, "dest never saw the fallback bytes");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert_eq!(capture.relayed(), 0);
    }

    #[tokio::test]
    async fn fallback_rate_limit_kicks_in() {
        // The fallback relay is rate-limited per `rate-limit`
        // (newRateLimitedConn): pushing a blob through a 64 kbps
        // listener takes ~1.5 s for 12 KB where the unlimited listener
        // finishes immediately.
        let (dest_addr, seen) = spawn_dest_echo().await;
        let capture = Capture::new();
        let mut cfg = listener_cfg(&[("user1", "pass1")], &dest_addr.to_string());
        let addr = serve(&cfg, capture.clone()).await.expect("serve");

        let push = |addr: SocketAddr| async move {
            let mut tcp = TcpStream::connect(addr).await.unwrap();
            let payload = vec![0x61u8; 12_000];
            let start = Instant::now();
            // Write, then read the echo back to completion.
            tcp.write_all(&payload).await.unwrap();
            let mut got = 0usize;
            let mut buf = vec![0u8; 16 * 1024];
            while got < payload.len() {
                let n = tcp.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                got += n;
            }
            start.elapsed()
        };
        let unlimited = push(addr).await;
        assert_eq!(seen.lock().unwrap().len(), 12_000);

        // Now with the limiter armed (a fresh listener + dest).
        let (dest_addr2, _seen2) = spawn_dest_echo().await;
        cfg.protocol = ServerProtocol::Jls {
            sni: "jls.test".into(),
            dest: dest_addr2.to_string(),
            users: vec![("user1".into(), "pass1".into())],
            alpn: Vec::new(),
            rate_limit: 64_000,
        };
        let addr2 = serve(&cfg, capture.clone()).await.expect("serve 2");
        let limited = push(addr2).await;
        assert!(
            limited >= Duration::from_millis(1_000),
            "rate limit did not pace the fallback: {limited:?} (unlimited {unlimited:?})"
        );
    }

    #[tokio::test]
    async fn config_errors_surface_before_binding() {
        let capture = Capture::new();
        // dest without a port (net.SplitHostPort fails, jls.go:127-130).
        let err = serve(&listener_cfg(&[("u", "p")], "camo.example"), capture.clone())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid dest"), "{err}");
        // No users (NewServerConfig).
        let err = serve(&listener_cfg(&[], "127.0.0.1:1"), capture.clone())
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("user"), "{err}");
    }

    #[test]
    fn dest_splitting() {
        assert_eq!(split_dest("example.com:8443").unwrap(), ("example.com".into(), 8443));
        assert_eq!(split_dest("127.0.0.1:443").unwrap(), ("127.0.0.1".into(), 443));
        for bad in ["example.com", ":443", "example.com:", "example.com:http"] {
            assert!(split_dest(bad).is_err(), "{bad}");
        }
    }
}
