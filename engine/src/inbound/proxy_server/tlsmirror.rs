//! TLSMirror camouflage listener (mihomo `listeners` type `tlsmirror`):
//! per accepted connection, dial `dest` through the engine relay FIRST
//! (upstream `inner.HandleTcp`), run the mirror server handshake
//! (`ServeConnReady`) between the client conn and the forward conn,
//! then hand the hidden stream to the relay with `dest` as target.
//!
//! Enrolment control connections (upstream `enrollmentTunnel`,
//! listener/tlsmirror/tlsmirror.go:73-86) intercept TCP conns to
//! `controlHost:80` wherever they enter the engine. This listener model
//! sees only its own port, so the practical equivalent is:
//!
//! * a conn whose first bytes are the h2c preface (`PRI * HTTP/2.0`) is
//!   served by [`proto::tlsmirror::serve_enrollment_control_connection`]
//!   — a TLS ClientHello never starts with `P`, so the split is
//!   wire-sound;
//! * integrators routing such conns elsewhere (TUN/other inbounds)
//!   must intercept by host themselves:
//!   [`proto::tlsmirror::is_enrollment_control_target`] matches the
//!   target, [`proto::tlsmirror::server_identifier_host`] derives the
//!   control host, and the control connection is then served with
//!   `serve_enrollment_control_connection`. Conns that are NOT served
//!   are never silently dropped: without an enrolment config the
//!   handler fails loudly (logged) instead of relaying junk.

use std::net::SocketAddr;

use tokio::io::AsyncReadExt;

use crate::addr::NetAddr;
use crate::error::{Error, Result};
use crate::inbound::proxy_server::{hand_off, serve_with, ServerConfig, ServerProtocol};
use crate::inbound::{SharedRelay, TcpMeta};
use crate::proto::tlsmirror::{
    serve_conn_ready, serve_enrollment_control_connection, TlsMirrorServerConfig, TimeSpec,
};
use crate::stream::BoxProxyStream;

/// The h2c connection preface an enrolment control connection starts
/// with (RFC 9113 §3.4); a TLS record always starts with 0x16.
const H2C_PREFACE_PREFIX: &[u8] = b"PRI * HTTP/2.0";

/// Serve a TLSMirror listener; returns the bound address.
pub async fn serve(cfg: &ServerConfig, relay: SharedRelay) -> Result<SocketAddr> {
    let ServerProtocol::TlsMirror {
        primary_key,
        explicit_nonce_cipher_suites,
        defer_write_time,
        transport_padding,
        enrolment,
        sequence_watermarking,
        dest,
    } = &cfg.protocol
    else {
        return Err(Error::config(
            "tlsmirror::serve called with a non-tlsmirror protocol",
        ));
    };
    // Validate credentials before binding: the primary key must decode
    // and the control host must derive.
    crate::proto::tlsmirror::server_identifier_host(primary_key)?;
    let dest_addr = parse_dest(dest)?;
    let server_cfg = TlsMirrorServerConfig {
        primary_key: primary_key.clone(),
        explicit_nonce_cipher_suites: explicit_nonce_cipher_suites.clone(),
        defer_instance_derived_write: TimeSpec {
            base_nanoseconds: defer_write_time.0,
            uniform_random_multiplier_nanoseconds: defer_write_time.1,
        },
        transport_layer_padding: *transport_padding,
        connection_enrolment: enrolment.clone(),
        sequence_watermarking_enabled: *sequence_watermarking,
    };
    let tag = cfg.tag.clone();
    let primary_key = primary_key.clone();
    let enrolment_on = enrolment.is_some();
    serve_with(cfg, move |stream, peer, port| {
        let relay = relay.clone();
        let tag = tag.clone();
        let primary_key = primary_key.clone();
        let server_cfg = server_cfg.clone();
        let dest_addr = dest_addr.clone();
        let enrolment_on = enrolment_on;
        async move {
            handle(
                stream,
                peer,
                port,
                tag,
                relay,
                primary_key,
                server_cfg,
                dest_addr,
                enrolment_on,
            )
            .await
        }
    })
    .await
}

/// Parse `dest` (`host:port`, the camouflage carrier target).
fn parse_dest(dest: &str) -> Result<NetAddr> {
    let (host, port) = dest
        .rsplit_once(':')
        .ok_or_else(|| Error::config(format!("tlsmirror listener: invalid dest {dest:?}")))?;
    let port: u16 = port
        .parse()
        .map_err(|_| Error::config(format!("tlsmirror listener: invalid dest port {port:?}")))?;
    Ok(NetAddr::new(crate::addr::Host::parse(host)?, port))
}

/// One accepted connection: control-conn detection, then the mirror.
#[allow(clippy::too_many_arguments)]
async fn handle(
    stream: BoxProxyStream,
    peer: SocketAddr,
    port: u16,
    tag: String,
    relay: SharedRelay,
    primary_key: String,
    server_cfg: TlsMirrorServerConfig,
    dest_addr: NetAddr,
    enrolment_on: bool,
) -> Result<()> {
    // Peek the first bytes: h2c preface = enrolment control connection.
    let (stream, peeked) = peek_preface(stream).await?;
    let is_control = peeked.len() >= H2C_PREFACE_PREFIX.len()
        && &peeked[..H2C_PREFACE_PREFIX.len()] == H2C_PREFACE_PREFIX;
    if is_control {
        if !enrolment_on {
            // Never silently dropped: the failure is logged by serve_with.
            return Err(Error::protocol(format!(
                "tlsmirror: enrolment control connection from {peer} but this listener has \
                 no connection-enrolment configured",
            )));
        }
        return serve_enrollment_control_connection(stream, &primary_key).await;
    }

    // inner.HandleTcp (listener/tlsmirror/tlsmirror.go:82): dial dest
    // through the engine relay first. The relay owns the routing; a
    // duplex pair turns the relayed session back into a stream handle.
    let (ours, relay_side) = tokio::io::duplex(64 * 1024);
    relay.clone().handle_tcp(
        TcpMeta {
            target: dest_addr.clone(),
            source: peer,
            inbound: tag.clone(),
            inbound_port: Some(port),
            inbound_kind: "tlsmirror",
        },
        Box::new(relay_side),
    );

    // ServeConnReady between the client conn and the forward conn.
    let hidden = serve_conn_ready(stream, Box::new(ours), &server_cfg).await?;
    // The hidden plaintext is relayed with dest as target.
    hand_off(&tag, "tlsmirror", port, peer, dest_addr, hidden, relay);
    Ok(())
}

/// Read exactly the preface prefix length (aborting early on
/// divergence or EOF), returning the stream with the peeked bytes
/// prepended (crate::inbound::PrependStream) plus the peeked bytes.
async fn peek_preface(stream: BoxProxyStream) -> Result<(BoxProxyStream, Vec<u8>)> {
    let mut stream = stream;
    let mut peeked = Vec::with_capacity(H2C_PREFACE_PREFIX.len());
    let mut byte = [0u8; 1];
    while peeked.len() < H2C_PREFACE_PREFIX.len() {
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            stream.read(&mut byte),
        )
        .await
        .map_err(|_| Error::network("tlsmirror: client sent nothing"))??;
        if n == 0 {
            break;
        }
        peeked.push(byte[0]);
        // Early divergence: not the preface.
        if H2C_PREFACE_PREFIX[peeked.len() - 1] != byte[0] {
            break;
        }
    }
    let peeked_out = peeked.clone();
    Ok((
        Box::new(crate::inbound::PrependStream::new(stream, peeked)),
        peeked_out,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbound::proxy_server::test_support::Capture;
    use crate::proto::tlsmirror::{
        connect_with, generate_primary_key, h2c_post, is_enrollment_control_target,
        marshal_enrollment_req, server_identifier_host, EnrollmentConfirmationReq,
        EnrollmentConfirmationReq as Req, TlsMirrorOut,
    };
    use std::sync::Arc;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A test relay that dials the real dest port (the engine router's
    /// job) and records the TcpMeta of every connection.
    struct DialRelay {
        dest_port: std::sync::atomic::AtomicU16,
        metas: std::sync::Mutex<Vec<NetAddr>>,
    }

    impl DialRelay {
        fn new() -> Arc<Self> {
            Arc::new(DialRelay {
                dest_port: std::sync::atomic::AtomicU16::new(0),
                metas: std::sync::Mutex::new(Vec::new()),
            })
        }

        fn targets(&self) -> Vec<NetAddr> {
            self.metas.lock().unwrap().clone()
        }
    }

    impl crate::inbound::RelayHandler for DialRelay {
        fn handle_tcp(self: Arc<Self>, meta: TcpMeta, client: BoxProxyStream) {
            self.metas.lock().unwrap().push(meta.target.clone());
            let port = self.dest_port.load(std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                let mut client = client;
                if let Ok(mut tcp) = tokio::net::TcpStream::connect(("127.0.0.1", port)).await {
                let _ = tokio::io::copy_bidirectional(&mut client, &mut tcp).await;
            }
            });
        }

        fn handle_udp(
            self: Arc<Self>,
            _source: SocketAddr,
            _inbound: String,
            _uplink: tokio::sync::mpsc::Receiver<(NetAddr, Vec<u8>)>,
            _downlink: tokio::sync::mpsc::Sender<(NetAddr, Vec<u8>)>,
        ) {
        }
    }

    fn listener_cfg(
        primary_key: &str,
        dest: &str,
        enrolment: Option<(String, String)>,
    ) -> ServerConfig {
        ServerConfig {
            tag: "tl-mirror".into(),
            bind: "127.0.0.1".into(),
            port: 0,
            protocol: ServerProtocol::TlsMirror {
                primary_key: primary_key.to_string(),
                explicit_nonce_cipher_suites: Vec::new(),
                defer_write_time: (0, 0),
                transport_padding: false,
                enrolment,
                sequence_watermarking: false,
                dest: dest.to_string(),
            },
        }
    }

    /// The engine's own tlsmirror client against the listener: the
    /// hidden bytes are echoed by the Capture relay. The client conn is
    /// bridged from a duplex to the listener's TCP port.
    async fn client_against_listener(
        primary_key: &str,
        relay: Arc<DialRelay>,
        enrollment_dialer: Option<crate::proto::tlsmirror::EnrollmentDialer>,
        key_override: Option<&str>,
    ) -> Result<(BoxProxyStream, std::net::SocketAddr)> {
        let dest_port = spawn_tls_dest().await;
        relay
            .dest_port
            .store(dest_port, std::sync::atomic::Ordering::SeqCst);
        let enrolment = enrollment_dialer.is_some().then(|| {
            ("primary-ingress".to_string(), "primary-egress".to_string())
        });
        let cfg = listener_cfg(
            primary_key,
            &format!("dest.example:{dest_port}"),
            enrolment,
        );
        let addr = serve(&cfg, relay).await.unwrap();
        let mut out = TlsMirrorOut::new(key_override.unwrap_or(primary_key), "dest.example");
        out.alpn = vec!["http/1.1".to_string()];
        out.connection_enrolment = enrollment_dialer.as_ref().map(|_| {
            ("primary-ingress".to_string(), "primary-egress".to_string())
        });
        let (client, server) = tokio::io::duplex(256 * 1024);
        tokio::spawn(async move {
            let mut server = server;
            let mut tcp = match tokio::net::TcpStream::connect(addr).await {
                Ok(t) => t,
                Err(_) => return,
            };
            let _ = tokio::io::copy_bidirectional(&mut server, &mut tcp).await;
        });
        let stream = connect_with(&out, Box::new(client), enrollment_dialer).await?;
        Ok((stream, addr))
    }

    /// The camouflage dest: TLS when the first byte is a ClientHello
    /// (the mirror's carrier), plain HTTP for the hidden stream the
    /// relay proxies to the same `dest`.
    async fn spawn_tls_dest() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let certified =
            rcgen::generate_simple_self_signed(vec!["dest.example".to_string()]).unwrap();
        let cert = rustls::pki_types::CertificateDer::from(certified.cert.der().to_vec());
        let key =
            rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut config = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let config = Arc::new(config);
        tokio::spawn(async move {
            loop {
                let (stream, _) = match listener.accept().await {
                    Ok(v) => v,
                    Err(_) => continue,
                };
                let config = config.clone();
                tokio::spawn(async move {
                    let mut stream = stream;
                    let mut first = [0u8; 1];
                    if tokio::time::timeout(
                        std::time::Duration::from_secs(10),
                        stream.read_exact(&mut first),
                    )
                    .await
                    .is_err()
                    {
                        return;
                    }
                    let io: BoxProxyStream = Box::new(crate::inbound::PrependStream::new(
                        Box::new(stream),
                        first.to_vec(),
                    ));
                    if first[0] == 0x16 {
                        serve_dest_tls(config, io).await;
                    } else {
                        serve_dest_plain_http(io).await;
                    }
                });
            }
        });
        port
    }

    /// The TLS carrier service: one trivial HTTP/1.1 response.
    async fn serve_dest_tls(config: Arc<rustls::ServerConfig>, io: BoxProxyStream) {
        let acceptor = tokio_rustls::TlsAcceptor::from(config);
        let mut tls = match acceptor.accept(crate::inbound::proxy_server::BoxedIo(io)).await {
            Ok(t) => t,
            Err(_) => return,
        };
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match tls.read(&mut byte).await {
                Ok(0) | Err(_) => return,
                Ok(_) => {
                    head.push(byte[0]);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
            }
        }
        let _ = tls
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await;
    }

    /// The hidden plaintext service: echo one HTTP response.
    async fn serve_dest_plain_http(mut io: BoxProxyStream) {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            match io.read_exact(&mut byte).await {
                Ok(_) => {
                    head.push(byte[0]);
                    if head.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                Err(_) => return,
            }
        }
        let _ = io
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
            .await;
    }

    #[tokio::test]
    async fn listener_serves_own_client() {
        let primary_key = generate_primary_key();
        let relay = DialRelay::new();
        let (mut stream, _addr) =
            client_against_listener(&primary_key, relay.clone(), None, None)
                .await
                .expect("connect");
        // The hidden channel speaks to the camouflage dest's plaintext
        // service: one HTTP request, one response.
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: dest.example\r\n\r\n")
            .await
            .unwrap();
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            stream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let text = String::from_utf8_lossy(&head).into_owned();
        assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
        let mut body = [0u8; 2];
        stream.read_exact(&mut body).await.unwrap();
        assert_eq!(&body, b"ok");
        // The relay dialed dest for the mirror's forward conn and the
        // hidden stream's relay.
        let targets = relay.targets();
        assert!(
            targets
                .iter()
                .all(|t| t.host.as_domain() == Some("dest.example")),
            "{targets:?}"
        );
        assert!(targets.len() >= 2, "forward + hidden relays: {targets:?}");
    }

    #[tokio::test]
    async fn listener_rejects_wrong_primary_key() {
        let real = generate_primary_key();
        let relay = DialRelay::new();
        let bad = generate_primary_key();
        let (mut stream, _addr) = client_against_listener(&real, relay, None, Some(&bad))
            .await
            .unwrap();
        stream.write_all(b"secret").await.unwrap();
        let mut buf = [0u8; 6];
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            stream.read_exact(&mut buf),
        )
        .await;
        match result {
            Err(_) => {}
            Ok(Err(_)) => {}
            Ok(Ok(read)) => panic!("a wrong primary key must not echo hidden data ({read} bytes)"),
        }
    }

    #[tokio::test]
    async fn listener_enrollment_control_roundtrip() {
        // Full enrolment e2e: the client's control connection dials a
        // listener serving the same primary key (the dialer asserts the
        // control host:80 target shape); the mirror registered its
        // randoms when the dest TLS handshake flowed (the registry is
        // process-global, exactly upstream's `enrollmentProcessors`),
        // so the confirmation comes back enrolled and connect succeeds.
        let primary_key = generate_primary_key();
        let dest_port = spawn_tls_dest().await;
        let control_cfg = listener_cfg(
            &primary_key,
            &format!("dest.example:{dest_port}"),
            Some(("ingress".to_string(), "egress".to_string())),
        );
        let control_addr = serve(&control_cfg, DialRelay::new()).await.unwrap();
        let key_for_dialer = primary_key.clone();
        let dialer: crate::proto::tlsmirror::EnrollmentDialer = Arc::new(move |target| {
            assert!(
                is_enrollment_control_target(&target, &key_for_dialer),
                "the dialer must see the control host:80 target, got {target}"
            );
            Box::pin(async move {
                let stream = tokio::net::TcpStream::connect(control_addr)
                    .await
                    .map_err(|e| Error::network(format!("control dial: {e}")))?;
                Ok(Box::new(stream) as BoxProxyStream)
            })
        });
        let relay = DialRelay::new();
        let (mut stream, _addr) = client_against_listener(&primary_key, relay, Some(dialer), None)
            .await
            .expect("enrolled connect");
        // The hidden channel works after enrolment.
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: dest.example\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 100];
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(20),
            stream.read(&mut buf),
        )
        .await
        .unwrap()
        .unwrap();
        let text = String::from_utf8_lossy(&buf[..n]).into_owned();
        assert!(text.starts_with("HTTP/1.1 200 OK"), "{text}");
    }

    #[tokio::test]
    async fn listener_control_conn_without_enrolment_fails_loudly() {
        let primary_key = generate_primary_key();
        let dest_port = spawn_tls_dest().await;
        let cfg = listener_cfg(&primary_key, &format!("dest.example:{dest_port}"), None);
        let addr = serve(&cfg, Capture::new()).await.unwrap();
        // A control-shaped conn: not silently dropped — the h2c POST
        // gets no enrollment answer (the handler errors), the conn dies.
        let tcp = tokio::net::TcpStream::connect(addr).await.unwrap();
        let host = server_identifier_host(&primary_key).unwrap();
        let req = marshal_enrollment_req(&Req {
            server_identifier: vec![1, 2],
            client_random: vec![3; 32],
            server_random: vec![4; 32],
            ..EnrollmentConfirmationReq::default()
        });
        let result = h2c_post(Box::new(tcp), &host, &req).await;
        assert!(result.is_err(), "no enrolment configured: {result:?}");
    }
}

