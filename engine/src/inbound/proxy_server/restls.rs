//! RestLS camouflage listener (mihomo `listeners` type `restls`): the
//! server half of the restls handshake over every accepted TCP conn,
//! then a plain relay of the hidden stream to `dest` (the camouflage
//! target) through the engine — upstream `listener/restls/restls.go`
//! wraps every accepted conn with `restls.Server` and hands the
//! decrypted conn to the tunnel with the listener's fixed dest, because
//! restls carries no in-protocol target.
//!
//! Upstream's `DialContext` routes the camouflage conn through
//! `inner.HandleTcp`; the engine's [`crate::inbound::RelayHandler`] is
//! receive-only (no dial-back), so [`crate::proto::restls::server`]
//! dials `dest` directly for the camouflage session while the hidden
//! plaintext stream rides the router as usual via
//! [`hand_off`] with `target = dest` and `inbound_kind "restls"`.

use std::net::SocketAddr;

use crate::addr::NetAddr;
use crate::error::{Error, Result};
use crate::inbound::proxy_server::{hand_off, serve_with, ServerConfig, ServerProtocol};
use crate::inbound::SharedRelay;

/// Serve a restls listener; returns the bound address.
pub async fn serve(cfg: &ServerConfig, relay: SharedRelay) -> Result<SocketAddr> {
    let ServerProtocol::Restls {
        password,
        restls_script,
        min_record_len,
        rate_limit,
        dest,
    } = &cfg.protocol
    else {
        return Err(Error::config("restls::serve called with a non-restls protocol"));
    };
    if password.is_empty() {
        return Err(Error::config("restls: password is required"));
    }
    if dest.trim().is_empty() {
        return Err(Error::config(
            "restls listener requires a dest (the camouflage destination)",
        ));
    }
    // Fail a bad script before binding (upstream parses it per state).
    if let Some(script) = restls_script.as_deref() {
        if !script.is_empty() {
            crate::proto::restls::validate_script(script)?;
        }
    }
    // `restlsHostPort`: no port → 443.
    let target = parse_dest(dest)?;

    let server_cfg = crate::proto::restls::RestlsServerConfig {
        server_hostname: dest.clone(),
        password: password.clone(),
        restls_script: restls_script.clone(),
        min_record_len: *min_record_len,
        rate_limit: *rate_limit as u64,
    };
    let tag = cfg.tag.clone();

    serve_with(cfg, move |stream, peer, port| {
        let server_cfg = server_cfg.clone();
        let relay = relay.clone();
        let tag = tag.clone();
        let target = target.clone();
        async move {
            // restls.Server: camouflage TLS toward dest + the hidden
            // stream. A completed raw fallback surfaces upstream's
            // sentinel error (logged at debug by serve_with); nothing is
            // relayed through the engine for a non-restls client.
            let hidden = crate::proto::restls::server(&server_cfg, stream).await?;
            // The listener model needs a target from the handshake, and
            // restls has none in-protocol: the dest IS the target.
            hand_off(&tag, "restls", port, peer, target, hidden, relay);
            Ok(())
        }
    })
    .await
}

/// `dest` (`host` or `host:port`, default 443) as a relay target.
fn parse_dest(dest: &str) -> Result<NetAddr> {
    let (host, port) = if let Some((h, p)) = dest.rsplit_once(':') {
        if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) {
            (h, p.parse::<u16>().map_err(|_| Error::config(format!("restls: bad dest port {p:?}")))?)
        } else {
            (dest, 443)
        }
    } else {
        (dest, 443)
    };
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        Ok(NetAddr::ip(ip, port))
    } else {
        NetAddr::domain(host, port)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::Host;
    use crate::inbound::proxy_server::test_support::Capture;
    use crate::proto::restls::RestlsOut;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;

    /// The camouflage `dest`: a real rustls TLS server (the "site" being
    /// mimicked). The listener dials it for the camouflage session.
    async fn spawn_dest() -> (rustls::pki_types::CertificateDer<'static>, SocketAddr) {
        let certified =
            rcgen::generate_simple_self_signed(vec!["restls.test".to_string()]).expect("rcgen");
        let cert = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
        let key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
        let config = std::sync::Arc::new(
            rustls::ServerConfig::builder_with_provider(provider)
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_no_client_auth()
                .with_single_cert(vec![cert.clone()], key)
                .expect("dest server config"),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { continue };
                let config = config.clone();
                tokio::spawn(async move {
                    let _ = tokio_rustls::TlsAcceptor::from(config)
                        .accept(stream)
                        .await;
                });
            }
        });
        (cert, addr)
    }

    fn listener_cfg(password: &str, dest: &str) -> ServerConfig {
        ServerConfig {
            tag: "restls-test".into(),
            bind: "127.0.0.1".into(),
            port: 0,
            protocol: ServerProtocol::Restls {
                password: password.into(),
                restls_script: None,
                min_record_len: 15,
                rate_limit: 0,
                dest: dest.into(),
            },
        }
    }

    /// The engine's own restls CLIENT, driven through the listener and
    /// out to the real dest (the camouflage handshake rides the
    /// listener's relay toward dest, exactly like a deployed client).
    async fn client_conn(addr: SocketAddr, password: &str) -> crate::stream::BoxProxyStream {
        let cfg = RestlsOut {
            password: password.into(),
            sni: "restls.test".into(),
            version: "tls13".into(),
            restls_script: None,
            skip_cert_verify: true,
            udp: false,
        };
        let tcp = TcpStream::connect(addr).await.expect("connect listener");
        crate::proto::restls::connect(&cfg, Box::new(tcp))
            .await
            .expect("restls client handshake")
    }

    #[tokio::test]
    async fn engine_client_roundtrips_through_the_listener() {
        let password = format!("pw-{:016x}", rand::random::<u64>());
        let (_cert, dest_addr) = spawn_dest().await;
        let capture = Capture::new();
        let cfg = listener_cfg(&password, &dest_addr.to_string());
        let addr = serve(&cfg, capture.clone()).await.expect("serve");

        let mut stream = tokio::time::timeout(
            Duration::from_secs(20),
            client_conn(addr, &password),
        )
        .await
        .expect("client handshake timeout");

        stream.write_all(b"ping through restls listener").await.unwrap();
        let mut buf = vec![0u8; b"ping through restls listener".len()];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
            .await
            .expect("echo timeout")
            .unwrap();
        assert_eq!(buf, b"ping through restls listener");

        // A second exchange keeps the counters aligned.
        stream.write_all(b"second").await.unwrap();
        let mut more = [0u8; 6];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut more))
            .await
            .expect("echo timeout 2")
            .unwrap();
        assert_eq!(&more, b"second");

        // The hidden stream was relayed with target = dest.
        assert_eq!(capture.relayed(), 1);
        let targets = capture.targets();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].to_string(), dest_addr.to_string());

        let _ = stream.shutdown().await;
    }

    #[tokio::test]
    async fn wrong_password_is_rejected() {
        let password = format!("real-{:016x}", rand::random::<u64>());
        let (_cert, dest_addr) = spawn_dest().await;
        let capture = Capture::new();
        let cfg = listener_cfg(&password, &dest_addr.to_string());
        let addr = serve(&cfg, capture.clone()).await.expect("serve");

        // The session-id MAC does not verify: the server falls back to
        // the raw relay, which ends with the sentinel error and closes —
        // the client must fail, never connect.
        let bad = RestlsOut {
            password: format!("wrong-{:016x}", rand::random::<u64>()),
            sni: "restls.test".into(),
            version: "tls13".into(),
            restls_script: None,
            skip_cert_verify: true,
            udp: false,
        };
        let tcp = TcpStream::connect(addr).await.expect("connect listener");
        match tokio::time::timeout(
            Duration::from_secs(20),
            crate::proto::restls::connect(&bad, Box::new(tcp)),
        )
        .await
        {
            Ok(Ok(_)) => panic!("a wrong password must not authenticate"),
            Ok(Err(_)) => {}
            Err(_) => panic!("timeout"),
        }
        // Nothing reached the relay.
        assert_eq!(capture.relayed(), 0);
    }

    #[tokio::test]
    async fn config_errors_surface_before_binding() {
        let capture = Capture::new();
        let mut cfg = listener_cfg("", "127.0.0.1:1");
        let err = serve(&cfg, capture.clone()).await.unwrap_err().to_string();
        assert!(err.contains("password is required"), "{err}");

        cfg = listener_cfg("pw", "  ");
        let err = serve(&cfg, capture.clone()).await.unwrap_err().to_string();
        assert!(err.contains("dest"), "{err}");

        let bad_script = ServerConfig {
            protocol: ServerProtocol::Restls {
                password: "pw".into(),
                restls_script: Some("40000~10".into()),
                min_record_len: 15,
                rate_limit: 0,
                dest: "127.0.0.1:1".into(),
            },
            ..listener_cfg("pw", "127.0.0.1:1")
        };
        let err = serve(&bad_script, capture).await.unwrap_err().to_string();
        assert!(err.contains("script"), "{err}");
    }

    #[test]
    fn dest_parsing() {
        assert_eq!(
            parse_dest("example.com").unwrap(),
            NetAddr::domain("example.com", 443).unwrap()
        );
        assert_eq!(
            parse_dest("example.com:8443").unwrap(),
            NetAddr::domain("example.com", 8443).unwrap()
        );
        assert_eq!(
            parse_dest("127.0.0.1:9443").unwrap(),
            NetAddr::ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST), 9443)
        );
        let net = parse_dest("127.0.0.1").unwrap();
        assert!(matches!(net.host, Host::Ip(_)));
        assert_eq!(net.port, 443);
    }
}
