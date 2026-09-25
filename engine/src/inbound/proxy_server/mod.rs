//! Server-side proxy protocols: the engine acting as a proxy SERVER
//! (mihomo `listeners:` / sing-box server inbounds), inverting the client
//! codecs in [`crate::proto`].
//!
//! [`serve`] binds one listener, runs the protocol handshake on every
//! accepted connection, recovers the client's requested target and hands
//! the decrypted stream to [`crate::inbound::RelayHandler`] with a
//! [`TcpMeta`] whose `inbound_kind` is the protocol name — from there the
//! connection rides the normal router (rules, outbounds, statistics),
//! exactly like a client-side inbound.
//!
//! Served protocols:
//!
//! * Shadowsocks: legacy AEAD (`aes-128-gcm`, `aes-256-gcm`,
//!   `chacha20-ietf-poly1305`) and 2022 (`2022-blake3-aes-128-gcm`,
//!   `2022-blake3-aes-256-gcm`) streams, including the SIP022 timestamp,
//!   replay and padding-length checks — plus a UDP relay socket
//!   ([`ss::SsUdpServer`]) on the listener port for the same methods.
//!   2022 listeners additionally support SIP023 multi-user: per-user PSKs
//!   selected through the Extended Identity Header on both TCP and UDP
//!   (see [`ss`] for the wire details).
//! * Trojan: TLS (when configured) then SHA-224 password hex, command and
//!   the SOCKS address; plain TCP relay for `CONNECT`, and for the UDP
//!   command a `socks-addr || len-be16 || payload` frame relay.
//! * VMess: AEAD only (`aes-128-gcm`, `chacha20-poly1305`). Security
//!   `none`, alter-id and the legacy MD5 header are rejected. The UDP
//!   command rides the AEAD body, one `port-first addr || payload` chunk
//!   per datagram.
//! * VLESS: plain header (version 0, no addons/flow) then raw relay,
//!   optionally TLS-fronted; the UDP command uses the engine's
//!   `socks-addr || len-be16 || payload` frames.
//! * Hysteria2: QUIC (ALPN `h3`). Auth is the protocol's minimal
//!   HTTP/3 POST to `https://hysteria/auth` with the password in the
//!   `hysteria-auth` header (status 233 = ok); TCP relays are
//!   `0x401`-framed bidirectional streams and UDP relays are QUIC
//!   datagrams with the session/packet/fragment header, one relay
//!   session per client session id.
//! * TUIC v5: QUIC (ALPN `tuic`). Authentication rides a
//!   unidirectional stream (`VER 5 TYPE 0 uuid token`, the token from
//!   the TLS exporter); TCP is addressed bidirectional streams, UDP is
//!   Packet frames as QUIC datagrams (native mode) or uni streams
//!   (quic mode), with Dissociate and Heartbeat handled.
//!
//! UDP transport notes (wire forms verified against upstream):
//!
//! * Shadowsocks UDP is connectionless: [`ss::serve`] binds one extra UDP
//!   socket on the listener port, so a datagram may arrive before any TCP
//!   session exists. Legacy AEAD packets are self-contained
//!   (`salt || AEAD-block`); 2022 packets use the SIP022 separate header
//!   and per-client session keys, with replay rejection on the
//!   (session id, packet id) pair.
//! * Trojan / VLESS / VMess UDP arrives as a command on the TCP
//!   connection (`trojan cmd 3`, `vless cmd 2`, `vmess cmd 2`) and needs
//!   no extra socket: the connection turns into an addressed-datagram
//!   stream bridged to [`RelayHandler::handle_udp`].
//! * Hysteria2 / TUIC UDP rides QUIC datagrams on the QUIC listener
//!   itself (TUIC also accepts uni-stream Packet commands in `quic`
//!   mode and replies on the transport the session arrived on), one
//!   relay session per client session id, reaped when idle.
//!
//! Framing deviations from upstream that are currently forced by the
//! engine's own outbound codecs (see [`crate::outbound::UdpChannel`]):
//!
//! * Trojan UDP frames are `socks-addr || len-be16 || payload` with no
//!   CRLF — exactly what the engine's trojan client writes via
//!   [`crate::proto::vless::vless_udp_frame`]. Xray-Core
//!   (`proxy/trojan/protocol.go`, `PacketWriter`/`PacketReader`) and
//!   mihomo (`transport/trojan/trojan.go`, `writePacket`/`ReadPacket`)
//!   insert a CRLF between the length and the payload; the server accepts
//!   and emits the engine client's CRLF-free form, so real trojan clients
//!   need the outbound side fixed to interop (out of scope here).
//! * The engine's ss2022 UDP client derives its session subkey and AEAD
//!   nonce from the ENCRYPTED separate header (see
//!   [`crate::proto::shadowsocks::SsUdp`]), while SIP022 §3.2.1 and
//!   sing-shadowsocks use the DECRYPTED one. [`ss::SsUdpServer`] accepts
//!   both constructions and replies with whichever the client used, so
//!   spec-conformant peers (mihomo/sing-box) and the engine's own client
//!   are both served.

pub mod hysteria2;
pub mod restls;
pub mod ss;
pub mod tlsmirror;
pub mod trojan;
pub mod tuic;
pub mod vless;
pub mod vmess;

use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;

use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

use crate::addr::NetAddr;
use crate::error::{Error, Result};
use crate::inbound::{SharedRelay, TcpMeta};
use crate::stream::BoxProxyStream;

/// PEM files for a TLS-fronted server protocol (file paths, as mihomo /
/// sing-box configs give them).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServerTls {
    /// Certificate chain (one or more `CERTIFICATE` blocks).
    pub cert_pem: String,
    /// Private key (PKCS#8, PKCS#1 or SEC1 PEM block).
    pub key_pem: String,
}

/// One server-protocol listener from the config.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    pub tag: String,
    pub bind: String,
    pub port: u16,
    pub protocol: ServerProtocol,
}

/// The protocol a listener serves and its credentials.
#[derive(Debug, Clone)]
pub enum ServerProtocol {
    /// Shadowsocks: `method` is any supported [`crate::proto::shadowsocks::SsMethod`]
    /// name; the legacy methods derive the key from `password`, the 2022
    /// methods expect the base64 PSK in `password`.
    ///
    /// `users` enables SIP023 multi-user (EIH) on a 2022 listener:
    /// `(username, base64 user PSK)` pairs in addition to the server-level
    /// PSK in `password` (mihomo `listeners[].users` / sing-box inbound
    /// `users`). Empty keeps the single-user path unchanged; the dialect
    /// layer fills it from config, never the wire.
    Shadowsocks {
        method: String,
        password: String,
        users: Vec<(String, String)>,
    },
    /// Trojan with SHA-224 password hex auth. `tls: None` serves plain
    /// (`trojanc://`) and is intended for tests and trusted transports.
    Trojan {
        password: String,
        tls: Option<ServerTls>,
    },
    /// VMess, AEAD only. `security` is the config string (`auto`,
    /// `aes-128-gcm`, `chacha20-poly1305`); `auto` accepts whatever the
    /// client requests, a concrete value must match the request.
    ///
    /// There is no alter-id on the AEAD wire: configs asking for
    /// `alterId > 0` must be rejected by the integrator (the legacy
    /// MD5 auth path is not implemented).
    Vmess { uuid: String, security: String },
    /// VLESS plain form; `flow`/addons requests are rejected.
    Vless {
        uuid: String,
        tls: Option<ServerTls>,
    },
    /// Hysteria2: the `hysteria-auth` password. TLS is mandatory on
    /// the wire (`None` is a config error at serve time). `obfs` is a
    /// salamander key; the server side does not implement salamander,
    /// so a non-empty key is rejected at serve time.
    Hysteria2 {
        password: String,
        obfs: Option<String>,
        tls: Option<ServerTls>,
    },
    /// TUIC v5: the UUID/password pair checked against the
    /// Authenticate command's TLS-exporter token. TLS is mandatory
    /// (`None` is a config error at serve time).
    Tuic {
        uuid: String,
        password: String,
        tls: Option<ServerTls>,
    },
    /// RestLS camouflage listener (mihomo `listeners` type `restls`):
    /// the server half of the restls handshake over every accepted TCP
    /// conn, then a plain relay to `dest` (the camouflage site) —
    /// unlike the proxy protocols above there is no target inside the
    /// protocol; the client speaks to `dest` through the tunnel.
    Restls {
        password: String,
        restls_script: Option<String>,
        min_record_len: u32,
        rate_limit: u32,
        /// The camouflage destination the hidden session relays to.
        dest: String,
    },
    /// TLSMirror camouflage listener (mihomo `listeners` type
    /// `tlsmirror`): dial `dest` first, then the mirror server
    /// handshake (`ServeConnReady`) between the client conn and the
    /// forward conn. Enrolment is the (ingress, egress) outbound pair.
    TlsMirror {
        primary_key: String,
        explicit_nonce_cipher_suites: Vec<u16>,
        defer_write_time: (u64, u64),
        transport_padding: bool,
        enrolment: Option<(String, String)>,
        sequence_watermarking: bool,
        /// The carrier destination the hidden session relays to.
        dest: String,
    },
}

impl ServerProtocol {
    /// Protocol name, used as `TcpMeta::inbound_kind` for IN-TYPE rules
    /// and logged with connection errors.
    pub fn name(&self) -> &'static str {
        match self {
            ServerProtocol::Shadowsocks { .. } => "shadowsocks",
            ServerProtocol::Trojan { .. } => "trojan",
            ServerProtocol::Vmess { .. } => "vmess",
            ServerProtocol::Vless { .. } => "vless",
            ServerProtocol::Hysteria2 { .. } => "hysteria2",
            ServerProtocol::Tuic { .. } => "tuic",
            ServerProtocol::Restls { .. } => "restls",
            ServerProtocol::TlsMirror { .. } => "tlsmirror",
        }
    }

    /// UDP relay support: every served protocol has a UDP path.
    ///
    /// * Shadowsocks: [`ss::serve`] binds a UDP socket on the listener
    ///   port (legacy AEAD and 2022 datagrams).
    /// * Trojan / VLESS / VMess: UDP is a command on the TCP connection,
    ///   so nothing extra is bound and a config never needs a separate
    ///   UDP port.
    /// * Hysteria2 / TUIC: UDP rides the QUIC listener itself (QUIC
    ///   datagrams, and TUIC uni streams in `quic` mode).
    /// * RestLS / TLSMirror: camouflage TCP relays — TCP only.
    pub fn supports_udp(&self) -> bool {
        !matches!(self, ServerProtocol::Restls { .. } | ServerProtocol::TlsMirror { .. })
    }
}

impl ServerConfig {
    /// The served protocol's short name (see [`ServerProtocol::name`]).
    pub fn protocol_name(&self) -> &'static str {
        self.protocol.name()
    }
}

/// Serve one server-protocol listener; returns the bound address.
///
/// Binds `cfg.bind:cfg.port` (port 0 picks an ephemeral port), validates
/// the protocol credentials/TLS material up front and spawns the accept
/// loop. Shadowsocks also binds its UDP relay socket on the same port
/// (see [`ss::serve`]); the other protocols carry UDP on the TCP
/// connection and bind nothing extra.
pub async fn serve(cfg: &ServerConfig, relay: SharedRelay) -> Result<SocketAddr> {
    match &cfg.protocol {
        ServerProtocol::Shadowsocks { .. } => ss::serve(cfg, relay).await,
        ServerProtocol::Trojan { .. } => trojan::serve(cfg, relay).await,
        ServerProtocol::Vmess { .. } => vmess::serve(cfg, relay).await,
        ServerProtocol::Vless { .. } => vless::serve(cfg, relay).await,
        ServerProtocol::Hysteria2 { .. } => hysteria2::serve(cfg, relay).await,
        ServerProtocol::Tuic { .. } => tuic::serve(cfg, relay).await,
        ServerProtocol::Restls { .. } => restls::serve(cfg, relay).await,
        ServerProtocol::TlsMirror { .. } => tlsmirror::serve(cfg, relay).await,
    }
}

/// Bind `cfg` and run the accept loop: one task per connection drives
/// `handler`, which performs the handshake and hands the stream to the
/// relay. Handler errors are logged at debug level and close the
/// connection (nothing is relayed).
pub(crate) async fn serve_with<F, Fut>(cfg: &ServerConfig, handler: F) -> Result<SocketAddr>
where
    F: Fn(BoxProxyStream, SocketAddr, u16) -> Fut + Clone + Send + Sync + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    let listener = TcpListener::bind((cfg.bind.as_str(), cfg.port))
        .await
        .map_err(|e| Error::network(format!("bind {}:{}: {e}", cfg.bind, cfg.port)))?;
    let addr = listener
        .local_addr()
        .map_err(|e| Error::network(e.to_string()))?;
    let kind = cfg.protocol.name();
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                continue;
            };
            let _ = stream.set_nodelay(true);
            let port = stream.local_addr().map(|a| a.port()).unwrap_or_else(|_| addr.port());
            let handler = handler.clone();
            tokio::spawn(async move {
                if let Err(e) = handler(Box::new(stream), peer, port).await {
                    tracing::debug!(target: "engine", "{kind} server {peer}: {e}");
                }
            });
        }
    });
    Ok(addr)
}

/// Hand a decrypted stream and its recovered target to the relay.
pub(crate) fn hand_off(
    tag: &str,
    kind: &'static str,
    port: u16,
    peer: SocketAddr,
    target: NetAddr,
    stream: BoxProxyStream,
    relay: SharedRelay,
) {
    relay.handle_tcp(
        TcpMeta {
            target,
            source: peer,
            inbound: tag.to_string(),
            inbound_port: Some(port),
            inbound_kind: kind,
        },
        stream,
    );
}

/// Read exactly `n` bytes from a boxed stream.
pub(crate) async fn read_exact_vec(stream: &mut BoxProxyStream, n: usize) -> Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    stream.read_exact(&mut buf).await?;
    Ok(buf)
}

/// Bridge a UDP-over-TCP stream to [`crate::inbound::RelayHandler::handle_udp`].
/// Two spawned pumps own the stream from here on: it carries a sequence of
/// `socks-addr || len-be16 || payload` datagrams in both directions.
///
/// This is the dialect the engine's own UDP clients write
/// ([`crate::proto::vless::vless_udp_frame`], shared by the VLESS and
/// Trojan outbounds): an RFC 1928 address, a big-endian length and no CRLF.
/// Upstream peers differ in detail (trojan puts a CRLF before the payload,
/// and sing's standalone UOT numbers the address families 0x00/0x01/0x02),
/// so the outbound codec is what these servers track — see the module docs.
pub(crate) fn spawn_framed_udp(
    stream: BoxProxyStream,
    source: SocketAddr,
    tag: String,
    relay: SharedRelay,
    crlf: bool,
) {
    let (up_tx, up_rx) = tokio::sync::mpsc::channel::<(NetAddr, Vec<u8>)>(64);
    let (down_tx, mut down_rx) = tokio::sync::mpsc::channel::<(NetAddr, Vec<u8>)>(64);
    relay.handle_udp(source, tag, up_rx, down_tx);

    let (mut reader, mut writer) = tokio::io::split(stream);
    // Uplink: frames off the stream, into the relay.
    tokio::spawn(async move {
        loop {
            match read_framed_datagram(&mut reader, crlf).await {
                Ok(Some((target, data))) => {
                    if up_tx.send((target, data)).await.is_err() {
                        break;
                    }
                }
                // Clean EOF: the client closed the association.
                Ok(None) => break,
                Err(e) => {
                    tracing::debug!(target: "engine", "udp frame from {source}: {e}");
                    break;
                }
            }
        }
    });
    // Downlink: relay replies back onto the stream.
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        while let Some((target, data)) = down_rx.recv().await {
            let frame = if crlf {
                // trojan: addr || len-be16 || CRLF || payload
                match crate::proto::trojan::trojan_udp_frame(&target, &data) {
                    Ok(f) => f,
                    Err(_) => continue, // oversize: drop like a lossy link
                }
            } else {
                let Ok(f) = crate::proto::vless::vless_udp_frame(&target, &data) else {
                    continue; // oversize datagram: drop, mirroring a lossy link
                };
                f
            };
            if writer.write_all(&frame).await.is_err() {
                break;
            }
            let _ = writer.flush().await;
        }
    });
}

/// Read one `socks-addr || len-be16 || payload` datagram; `Ok(None)` at a
/// clean EOF between frames.
async fn read_framed_datagram<R>(
    reader: &mut R,
    crlf: bool,
) -> Result<Option<(NetAddr, Vec<u8>)>>
where
    R: tokio::io::AsyncRead + Unpin,
{
    use crate::addr::Atyp;
    let mut atyp = [0u8; 1];
    if reader.read(&mut atyp).await? == 0 {
        return Ok(None);
    }
    let mut addr = vec![atyp[0]];
    let host_len = match atyp[0] {
        v if v == Atyp::Ipv4 as u8 => 4,
        v if v == Atyp::Ipv6 as u8 => 16,
        v if v == Atyp::Domain as u8 => {
            let mut len = [0u8; 1];
            reader.read_exact(&mut len).await?;
            addr.push(len[0]);
            len[0] as usize
        }
        other => {
            return Err(Error::protocol(format!("udp frame: bad atyp {other:#x}")));
        }
    };
    let mut body = vec![0u8; host_len + 2];
    reader.read_exact(&mut body).await?;
    addr.extend_from_slice(&body);

    let mut len = [0u8; 2];
    reader.read_exact(&mut len).await?;
    if crlf {
        // Trojan frames carry a CRLF between the length and the payload.
        let mut crlf_b = [0u8; 2];
        reader.read_exact(&mut crlf_b).await?;
    }
    let mut payload = vec![0u8; u16::from_be_bytes(len) as usize];
    reader.read_exact(&mut payload).await?;

    let (target, _) = crate::addr::decode_socks_addr(&addr)?;
    Ok(Some((target, payload)))
}

/// Read one RFC 1928 SOCKS address (`ATYP | addr | port`) from a stream.
/// Used by the trojan/shadowsocks-style protocols.
pub(crate) async fn read_socks_addr(stream: &mut BoxProxyStream) -> Result<NetAddr> {
    let mut head = [0u8; 1];
    stream.read_exact(&mut head).await?;
    let mut buf = Vec::with_capacity(19);
    buf.push(head[0]);
    match head[0] {
        0x01 => buf.extend_from_slice(&read_exact_vec(stream, 4).await?),
        0x03 => {
            let len = read_exact_vec(stream, 1).await?;
            buf.push(len[0]);
            buf.extend_from_slice(&read_exact_vec(stream, len[0] as usize).await?);
        }
        0x04 => buf.extend_from_slice(&read_exact_vec(stream, 16).await?),
        other => {
            return Err(Error::protocol(format!("socks address: bad atyp {other:#x}")));
        }
    }
    buf.extend_from_slice(&read_exact_vec(stream, 2).await?);
    let (addr, _) = crate::addr::decode_socks_addr(&buf)?;
    Ok(addr)
}

/// Read one sing/mihomo port-first address (`port-be16 | atyp | addr`) from
/// a stream — the VMess/VLESS destination form.
pub(crate) async fn read_port_first_addr(stream: &mut BoxProxyStream) -> Result<NetAddr> {
    let head = read_exact_vec(stream, 3).await?;
    let mut buf = head.to_vec();
    match head[2] {
        0x01 => buf.extend_from_slice(&read_exact_vec(stream, 4).await?),
        0x02 => {
            let len = read_exact_vec(stream, 1).await?;
            buf.push(len[0]);
            buf.extend_from_slice(&read_exact_vec(stream, len[0] as usize).await?);
        }
        0x03 => buf.extend_from_slice(&read_exact_vec(stream, 16).await?),
        other => {
            return Err(Error::protocol(format!("port-first address: bad atyp {other:#x}")));
        }
    }
    let (addr, _) = crate::addr::decode_port_first_addr(&buf)?;
    Ok(addr)
}

/// Load a PEM certificate chain and key into a rustls server config using
/// the ring provider (the engine's TLS backend).
pub(crate) fn build_tls_config(tls: &ServerTls) -> Result<Arc<rustls::ServerConfig>> {
    let certs = load_certs(&tls.cert_pem)?;
    let key = load_key(&tls.key_pem)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = rustls::ServerConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::config(format!("server tls: {e}")))?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| Error::config(format!("server tls cert/key ({}): {e}", tls.cert_pem)))?;
    Ok(Arc::new(config))
}

fn load_certs(path: &str) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let file = std::fs::File::open(path)
        .map_err(|e| Error::config(format!("server tls cert {path}: {e}")))?;
    let mut reader = std::io::BufReader::new(file);
    let certs: std::result::Result<Vec<_>, _> = rustls_pemfile::certs(&mut reader).collect();
    let certs = certs.map_err(|e| Error::config(format!("server tls cert {path}: {e}")))?;
    if certs.is_empty() {
        return Err(Error::config(format!(
            "server tls cert {path}: no CERTIFICATE block"
        )));
    }
    Ok(certs)
}

fn load_key(path: &str) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let file = std::fs::File::open(path)
        .map_err(|e| Error::config(format!("server tls key {path}: {e}")))?;
    let mut reader = std::io::BufReader::new(file);
    rustls_pemfile::private_key(&mut reader)
        .map_err(|e| Error::config(format!("server tls key {path}: {e}")))?
        .ok_or_else(|| Error::config(format!("server tls key {path}: no PRIVATE KEY block")))
}

/// Build a quinn server config for a TLS-fronted QUIC server protocol
/// (hysteria2, TUIC): rustls material via [`build_tls_config`] with the
/// protocol's ALPN, plus the transport settings the engine's own QUIC
/// clients offer (datagrams for UDP relay, generous uni-stream limits —
/// see [`crate::quic::client_config`]).
pub(crate) fn quic_server_config(tls: &ServerTls, alpn: &[u8]) -> Result<quinn::ServerConfig> {
    let mut rustls_config = (*build_tls_config(tls)?).clone();
    rustls_config.alpn_protocols = vec![alpn.to_vec()];
    let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(rustls_config))
        .map_err(|e| Error::config(format!("quic server tls: {e}")))?;
    let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
    let mut transport = quinn::TransportConfig::default();
    transport.max_concurrent_uni_streams(1024u32.into());
    transport.datagram_receive_buffer_size(Some(64 * 1024));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

/// Resolve `bind:port` to the first socket address, for binding a QUIC
/// (UDP) server endpoint (port 0 picks an ephemeral port).
pub(crate) async fn quic_bind_addr(bind: &str, port: u16) -> Result<SocketAddr> {
    tokio::net::lookup_host((bind, port))
        .await
        .map_err(|e| Error::config(format!("resolve bind {bind}:{port}: {e}")))?
        .next()
        .ok_or_else(|| Error::config(format!("no address for bind {bind}:{port}")))
}

/// A boxed stream adapted for `tokio-rustls`, which needs a concrete
/// `AsyncRead + AsyncWrite + Unpin` type.
pub(crate) struct BoxedIo(BoxProxyStream);

impl tokio::io::AsyncRead for BoxedIo {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for BoxedIo {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.0).poll_shutdown(cx)
    }
}

/// Terminate TLS on an accepted connection.
pub(crate) async fn tls_accept(
    config: Arc<rustls::ServerConfig>,
    stream: BoxProxyStream,
) -> Result<BoxProxyStream> {
    let acceptor = tokio_rustls::TlsAcceptor::from(config);
    let stream = acceptor
        .accept(BoxedIo(stream))
        .await
        .map_err(|e| Error::protocol(format!("server tls handshake: {e}")))?;
    Ok(Box::new(stream))
}

/// Constant-time byte comparison (password / UUID checks).
pub(crate) fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Current unix time in seconds.
pub(crate) fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Test relay that records the [`TcpMeta`] of every relayed connection and
/// the sessions/targets of every UDP association, and echoes payload back
/// to the client on both.
#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::sync::Mutex;

    #[derive(Default)]
    pub(crate) struct Capture {
        metas: Mutex<Vec<TcpMeta>>,
        udp_sessions: Mutex<Vec<(SocketAddr, String)>>,
        udp_targets: Mutex<Vec<NetAddr>>,
    }

    impl Capture {
        pub(crate) fn new() -> Arc<Self> {
            Arc::new(Capture::default())
        }

        /// Targets relayed so far (empty = nothing reached the relay).
        pub(crate) fn targets(&self) -> Vec<NetAddr> {
            self.metas
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .iter()
                .map(|m| m.target.clone())
                .collect()
        }

        pub(crate) fn relayed(&self) -> usize {
            self.metas.lock().unwrap_or_else(|e| e.into_inner()).len()
        }

        /// UDP associations opened, as `(source, inbound)`.
        pub(crate) fn udp_sessions(&self) -> Vec<(SocketAddr, String)> {
            self.udp_sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }

        /// Datagram targets that reached the relay.
        pub(crate) fn udp_targets(&self) -> Vec<NetAddr> {
            self.udp_targets
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .clone()
        }
    }

    impl crate::inbound::RelayHandler for Capture {
        fn handle_tcp(self: Arc<Self>, meta: TcpMeta, mut client: BoxProxyStream) {
            self.metas.lock().unwrap_or_else(|e| e.into_inner()).push(meta);
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = vec![0u8; 16 * 1024];
                loop {
                    match client.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if client.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }

        /// Records the association, then echoes every datagram back as if a
        /// remote host had answered from the requested target.
        fn handle_udp(
            self: Arc<Self>,
            source: SocketAddr,
            inbound: String,
            mut uplink: tokio::sync::mpsc::Receiver<(NetAddr, Vec<u8>)>,
            downlink: tokio::sync::mpsc::Sender<(NetAddr, Vec<u8>)>,
        ) {
            self.udp_sessions
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push((source, inbound));
            tokio::spawn(async move {
                while let Some((target, data)) = uplink.recv().await {
                    self.udp_targets
                        .lock()
                        .unwrap_or_else(|e| e.into_inner())
                        .push(target.clone());
                    if downlink.send((target, data)).await.is_err() {
                        break;
                    }
                }
            });
        }
    }

    /// Read one trojan datagram the way `UdpChannel::Trojan::recv` does:
    /// `socks-addr || len-be16 || CRLF || payload`.
    pub(crate) async fn read_client_trojan_udp_frame<R>(reader: &mut R) -> (NetAddr, Vec<u8>)
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        use tokio::io::AsyncReadExt;
        let mut atyp = [0u8; 1];
        reader.read_exact(&mut atyp).await.expect("frame atyp");
        let mut addr = vec![atyp[0]];
        let host_len = match atyp[0] {
            0x01 => 4,
            0x04 => 16,
            0x03 => {
                let mut len = [0u8; 1];
                reader.read_exact(&mut len).await.expect("domain length");
                addr.push(len[0]);
                len[0] as usize
            }
            other => panic!("client udp frame: bad atyp {other:#x}"),
        };
        let mut host = vec![0u8; host_len + 2];
        reader.read_exact(&mut host).await.expect("frame address");
        addr.extend_from_slice(&host);
        let mut len = [0u8; 2];
        reader.read_exact(&mut len).await.expect("frame length");
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).await.expect("frame crlf");
        assert_eq!(&crlf, b"\r\n", "trojan frames carry CRLF before the payload");
        let mut payload = vec![0u8; u16::from_be_bytes(len) as usize];
        reader.read_exact(&mut payload).await.expect("frame payload");
        let (target, _) = crate::addr::decode_socks_addr(&addr).expect("frame address decodes");
        (target, payload)
    }

    /// Read one datagram from a server the way the engine's UDP clients
    /// read it (`crate::outbound::UdpChannel::Framed::recv`):
    /// `socks-addr || len-be16 || payload`, RFC 1928 address form.
    pub(crate) async fn read_client_udp_frame<R>(reader: &mut R) -> (NetAddr, Vec<u8>)
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        use tokio::io::AsyncReadExt;
        let mut atyp = [0u8; 1];
        reader.read_exact(&mut atyp).await.expect("frame atyp");
        let mut addr = vec![atyp[0]];
        let host_len = match atyp[0] {
            0x01 => 4,
            0x04 => 16,
            0x03 => {
                let mut len = [0u8; 1];
                reader.read_exact(&mut len).await.expect("domain length");
                addr.push(len[0]);
                len[0] as usize
            }
            other => panic!("client udp frame: bad atyp {other:#x}"),
        };
        let mut host = vec![0u8; host_len + 2];
        reader.read_exact(&mut host).await.expect("frame address");
        addr.extend_from_slice(&host);
        let mut len = [0u8; 2];
        reader.read_exact(&mut len).await.expect("frame length");
        let mut payload = vec![0u8; u16::from_be_bytes(len) as usize];
        reader.read_exact(&mut payload).await.expect("frame payload");
        let (target, _) = crate::addr::decode_socks_addr(&addr).expect("frame address decodes");
        (target, payload)
    }

    /// Self-signed certificate + key written to temporary PEM files for
    /// the TLS tests (nothing committed, nothing leaves loopback).
    pub(crate) fn self_signed_tls() -> (ServerTls, tempfile::TempDir) {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("generate self-signed cert");
        let dir = tempfile::tempdir().expect("tempdir");
        let cert_path = dir.path().join("cert.pem");
        let key_path = dir.path().join("key.pem");
        std::fs::write(&cert_path, cert.cert.pem()).expect("write cert");
        std::fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");
        (
            ServerTls {
                cert_pem: cert_path.to_string_lossy().into_owned(),
                key_pem: key_path.to_string_lossy().into_owned(),
            },
            dir,
        )
    }

    #[test]
    fn constant_time_compare() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::Capture;
    use super::*;

    fn cfg(protocol: ServerProtocol) -> ServerConfig {
        ServerConfig {
            tag: "t".into(),
            bind: "127.0.0.1".into(),
            port: 0,
            protocol,
        }
    }

    #[test]
    fn protocol_names_and_udp_flag() {
        let ss = cfg(ServerProtocol::Shadowsocks {
            method: "aes-128-gcm".into(),
            password: "x".into(),
            users: Vec::new(),
        });
        let trojan = cfg(ServerProtocol::Trojan {
            password: "x".into(),
            tls: None,
        });
        let vmess = cfg(ServerProtocol::Vmess {
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            security: "auto".into(),
        });
        let vless = cfg(ServerProtocol::Vless {
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            tls: None,
        });
        let hysteria2 = cfg(ServerProtocol::Hysteria2 {
            password: "x".into(),
            obfs: None,
            tls: None,
        });
        let tuic = cfg(ServerProtocol::Tuic {
            uuid: "b831381d-6324-4d53-ad4f-8cda48b30811".into(),
            password: "x".into(),
            tls: None,
        });
        assert_eq!(ss.protocol_name(), "shadowsocks");
        assert_eq!(trojan.protocol_name(), "trojan");
        assert_eq!(vmess.protocol_name(), "vmess");
        assert_eq!(vless.protocol_name(), "vless");
        assert_eq!(hysteria2.protocol_name(), "hysteria2");
        assert_eq!(tuic.protocol_name(), "tuic");
        // Every served protocol now has a UDP path.
        for c in [&ss, &trojan, &vmess, &vless, &hysteria2, &tuic] {
            assert!(c.protocol.supports_udp(), "{} must serve UDP", c.protocol_name());
        }
    }

    #[tokio::test]
    async fn invalid_credentials_fail_before_binding() {
        let capture = Capture::new();
        let bad_method = cfg(ServerProtocol::Shadowsocks {
            method: "rc4-md5".into(),
            password: "x".into(),
            users: Vec::new(),
        });
        assert!(serve(&bad_method, capture.clone()).await.is_err());

        let bad_uuid = cfg(ServerProtocol::Vmess {
            uuid: "nope".into(),
            security: "auto".into(),
        });
        assert!(serve(&bad_uuid, capture.clone()).await.is_err());

        // A missing TLS PEM file is a config error, not a late handshake
        // failure.
        let bad_tls = cfg(ServerProtocol::Trojan {
            password: "x".into(),
            tls: Some(ServerTls {
                cert_pem: "/nonexistent/cert.pem".into(),
                key_pem: "/nonexistent/key.pem".into(),
            }),
        });
        let err = serve(&bad_tls, capture).await.unwrap_err().to_string();
        assert!(err.contains("server tls cert"), "{err}");
    }
}