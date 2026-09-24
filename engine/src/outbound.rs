//! Outbound assembly: leaf proxies (enum-dispatched), transport
//! composition (TCP → TLS → WS → protocol), UDP channels, and the
//! registry that resolves names through groups.

use std::collections::HashMap;

use tokio::io::AsyncReadExt;
use tokio::sync::RwLock;

use crate::addr::{decode_socks_addr, NetAddr};
use crate::error::{Error, Result};
use crate::proto::httpx::{HttpOut, HttpStream};
use crate::proto::shadowsocks::{SsOut, SsStream, SsUdp};
use crate::proto::socks::{SocksOut, SocksStream, SocksUdp};
use crate::proto::trojan::{TrojanOut, TrojanStream};
use crate::proto::vless::{vless_udp_frame, VlessOut, VlessStream};
use crate::proto::vmess::{VmessOut, VmessStream};
use crate::stream::BoxProxyStream;
use crate::transport::{effective_sni, tls_connect, ws_connect, TlsSettings, WsSettings};

/// Transport between the TCP dial and the protocol handshake.
#[derive(Debug, Clone, Default)]
pub enum TransportKind {
    #[default]
    Tcp,
    Ws {
        path: String,
        host: Option<String>,
    },
    /// v2ray httpupgrade: Upgrade handshake, then a raw stream.
    HttpUpgrade {
        path: String,
        host: Option<String>,
    },
    /// v2ray gRPC (gun): TLS with ALPN h2, one gRPC stream per connection.
    Grpc {
        service_name: String,
        host: Option<String>,
    },
}

/// simple-obfs mode for a Shadowsocks outbound.
#[derive(Debug, Clone)]
pub struct ObfsMode {
    pub http: bool,
    pub host: String,
}

impl ObfsMode {
    /// Wrap a dialed stream in the obfs layer (before the ss cipher).
    async fn wrap(&self, stream: BoxProxyStream) -> Result<BoxProxyStream> {
        let settings = crate::proto::obfs::ObfsSettings::new(&self.host, 80);
        if self.http {
            crate::proto::obfs::http_obfs_client(stream, &settings).await
        } else {
            crate::proto::obfs::tls_obfs_client(stream, &settings).await
        }
    }
}

/// Leaf outbound configuration (dialect-independent).
#[derive(Debug, Clone)]
pub struct OutboundConfig {
    pub name: String,
    pub udp: bool,
    pub kind: OutboundKind,
}

#[derive(Debug, Clone)]
pub enum OutboundKind {
    Direct,
    Reject,
    Http {
        server: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    },
    Socks {
        server: String,
        port: u16,
        username: Option<String>,
        password: Option<String>,
    },
    Shadowsocks {
        server: String,
        port: u16,
        method: crate::proto::shadowsocks::SsMethod,
        password: String,
        /// simple-obfs wrapper (mihomo `plugin: obfs`).
        obfs: Option<ObfsMode>,
    },
    Vmess {
        server: String,
        port: u16,
        uuid: uuid::Uuid,
        security: crate::proto::vmess::VmessSecurity,
        transport: TransportKind,
        tls: TlsSettings,
    },
    Vless {
        server: String,
        port: u16,
        uuid: uuid::Uuid,
        transport: TransportKind,
        tls: TlsSettings,
        /// REALITY: wraps raw TCP before the vless handshake.
        reality: Option<crate::proto::reality::RealityCfg>,
        /// uTLS-style ClientHello fingerprint (chrome/firefox), used
        /// instead of rustls when set.
        fingerprint: Option<crate::proto::reality::UtslProfile>,
        /// `flow: xtls-rprx-vision`: XTLS Vision framing after the
        /// vless handshake.
        vision: bool,
    },
    Trojan {
        server: String,
        port: u16,
        password: String,
        transport: TransportKind,
        tls: TlsSettings,
    },
    Hysteria2 {
        server: String,
        port: u16,
        password: String,
        sni: Option<String>,
        skip_verify: bool,
        obfs: Option<String>,
    },
    Tuic {
        server: String,
        port: u16,
        uuid: uuid::Uuid,
        password: String,
        sni: Option<String>,
        skip_verify: bool,
        udp_relay_mode: crate::proto::tuic::UdpRelayMode,
    },
    Ssh {
        server: String,
        port: u16,
        user: String,
        password: Option<String>,
        private_key: Option<String>,
        private_key_passphrase: Option<String>,
        host_key: Vec<String>,
    },
    /// ShadowTLS v3 wrapping an inner protocol (mihomo `proxy:` nesting):
    /// dial → shadowtls handshake → real TLS → the inner protocol's
    /// handshake over that stream.
    ShadowTls {
        server: String,
        port: u16,
        password: String,
        sni: String,
        skip_verify: bool,
        inner: Box<OutboundKind>,
    },
    Wireguard(crate::proto::wireguard::WgOut),
    Snell(crate::proto::snell::SnellOut),
    AnyTls(crate::proto::anytls::AnyTlsOut),
    Mieru(crate::proto::mieru::MieruOut),
    Restls {
        server: String,
        port: u16,
        cfg: crate::proto::restls::RestlsOut,
    },
}

/// Shared, lazily-dialed QUIC connection for the hysteria2/tuic outbounds
/// (one connection per outbound; streams open per TCP relay).
#[derive(Default)]
struct QuicConnCache(tokio::sync::Mutex<Option<std::sync::Arc<quinn::Connection>>>);

/// A runtime leaf outbound.
pub struct Outbound {
    pub name: String,
    pub udp: bool,
    kind: OutboundKind,
    quic: QuicConnCache,
}

impl Outbound {
    pub fn from_config(cfg: &OutboundConfig) -> Result<Self> {
        Ok(Outbound {
            name: cfg.name.clone(),
            udp: cfg.udp,
            kind: cfg.kind.clone(),
            quic: QuicConnCache::default(),
        })
    }

    /// The shared QUIC connection for hy2/tuic outbounds, dialed on
    /// first use and reused until the server closes it.
    async fn quic_conn<F, Fut>(&self, dial: F) -> Result<std::sync::Arc<quinn::Connection>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<quinn::Connection>>,
    {
        let mut slot = self.quic.0.lock().await;
        if let Some(conn) = slot.as_ref() {
            if conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
        }
        let conn = std::sync::Arc::new(dial().await?);
        *slot = Some(conn.clone());
        Ok(conn)
    }

    pub fn kind_name(&self) -> &'static str {
        match &self.kind {
            OutboundKind::Direct => "Direct",
            OutboundKind::Reject => "Reject",
            OutboundKind::Http { .. } => "Http",
            OutboundKind::Socks { .. } => "Socks",
            OutboundKind::Shadowsocks { .. } => "Shadowsocks",
            OutboundKind::Vmess { .. } => "Vmess",
            OutboundKind::Vless { .. } => "Vless",
            OutboundKind::Trojan { .. } => "Trojan",
            OutboundKind::Hysteria2 { .. } => "Hysteria2",
            OutboundKind::Tuic { .. } => "Tuic",
            OutboundKind::Ssh { .. } => "Ssh",
            OutboundKind::ShadowTls { .. } => "ShadowTls",
            OutboundKind::Wireguard(_) => "Wireguard",
            OutboundKind::Snell(_) => "Snell",
            OutboundKind::AnyTls(_) => "AnyTls",
            OutboundKind::Mieru(_) => "Mieru",
            OutboundKind::Restls { .. } => "Restls",
        }
    }

    /// Whether this outbound drops traffic (REJECT) — callers decide
    /// between a silent close (TCP) and refusing the session (UDP).
    pub fn is_reject(&self) -> bool {
        matches!(self.kind, OutboundKind::Reject)
    }

    /// Dial the proxy server and compose TLS/WS transports.
    async fn dial_transport(
        server: &str,
        port: u16,
        transport: &TransportKind,
        tls: &TlsSettings,
    ) -> Result<BoxProxyStream> {
        let tcp = tokio::net::TcpStream::connect((server, port))
            .await
            .map_err(|e| Error::network(format!("dial {server}:{port}: {e}")))?;
        let _ = tcp.set_nodelay(true);
        let mut stream: BoxProxyStream = Box::new(tcp);
        // gRPC (gun) rides TLS with ALPN h2 — the one transport that
        // REQUIRES TLS and augments the TLS settings.
        let mut tls = tls.clone();
        if let TransportKind::Grpc { .. } = transport {
            if !tls.enabled {
                return Err(Error::config("grpc transport requires tls: true"));
            }
            if tls.alpn.is_empty() {
                tls.alpn = vec!["h2".to_string()];
            }
        }
        if tls.enabled {
            let sni = effective_sni(&tls, server, None);
            stream = tls_connect(stream, &sni, &tls).await?;
        }
        let host_header = |host: &Option<String>| {
            host.clone().unwrap_or_else(|| format!("{server}:{port}"))
        };
        if let TransportKind::Ws { path, host } = transport {
            let settings = WsSettings {
                path: path.clone(),
                host: host.clone(),
            };
            stream = ws_connect(stream, &settings, &host_header(host)).await?;
        }
        if let TransportKind::HttpUpgrade { path, host } = transport {
            stream =
                crate::transport::httpupgrade_connect(stream, path, &host_header(host)).await?;
        }
        if let TransportKind::Grpc {
            service_name,
            host,
        } = transport
        {
            let settings = crate::grpc::GrpcSettings {
                service_name: service_name.clone(),
                host: host.clone(),
            };
            stream = crate::grpc::grpc_connect(stream, &settings, &host_header(host)).await?;
        }
        Ok(stream)
    }

    /// Compose the vless front end: REALITY or a uTLS fingerprint replaces
/// the rustls handshake; the resulting stream goes straight into the
/// vless protocol (both are raw-TCP shapes, so ws/grpc underneath are
/// refused loudly rather than silently mis-layered).
async fn vless_front(
    server: &str,
    port: u16,
    transport: &TransportKind,
    tls: &TlsSettings,
    reality: &Option<crate::proto::reality::RealityCfg>,
    fingerprint: &Option<crate::proto::reality::UtslProfile>,
) -> Result<BoxProxyStream> {
    if reality.is_none() && fingerprint.is_none() {
        return Self::dial_transport(server, port, transport, tls).await;
    }
    if !matches!(transport, TransportKind::Tcp) {
        return Err(Error::config(
            "reality / client-fingerprint cannot be combined with a layered transport \
             (ws/httpupgrade/grpc) yet",
        ));
    }
    let tcp = tokio::net::TcpStream::connect((server, port))
        .await
        .map_err(|e| Error::network(format!("dial {server}:{port}: {e}")))?;
    let _ = tcp.set_nodelay(true);
    let tcp: BoxProxyStream = Box::new(tcp);
    if let Some(cfg) = reality {
        return crate::proto::reality::reality_connect(cfg, tcp).await;
    }
    let profile = fingerprint.expect("fingerprint checked above");
    let utls = crate::proto::reality::UtlsCfg {
        server_name: effective_sni(tls, server, None),
        profile,
        alpn: vec!["h2".to_string(), "http/1.1".to_string()],
    };
    crate::proto::reality::utls_connect(&utls, tcp).await
}

/// Run an inner leaf protocol's handshake over an already-wrapped
    /// stream (shadowtls nesting). The inner outbound never dials.
    async fn shadowtls_inner(
        inner: &OutboundKind,
        stream: BoxProxyStream,
        target: &NetAddr,
    ) -> Result<BoxProxyStream> {
        match inner {
            OutboundKind::Shadowsocks {
                method, password, ..
            } => {
                let cfg = SsOut {
                    server: String::new(),
                    port: 0,
                    method: *method,
                    password: password.clone(),
                };
                let s = SsStream::handshake(stream, &cfg, target, &[]).await?;
                Ok(Box::new(s))
            }
            OutboundKind::Trojan { password, .. } => {
                let cfg = TrojanOut {
                    server: String::new(),
                    port: 0,
                    password: password.clone(),
                };
                let s = TrojanStream::handshake(stream, &cfg, target, false).await?;
                Ok(Box::new(s))
            }
            OutboundKind::Vmess {
                uuid, security, ..
            } => {
                let cfg = VmessOut {
                    server: String::new(),
                    port: 0,
                    uuid: *uuid,
                    security: *security,
                };
                let s = VmessStream::handshake(stream, &cfg, target, false).await?;
                Ok(Box::new(s))
            }
            OutboundKind::Vless { uuid, .. } => {
                let cfg = VlessOut {
                    server: String::new(),
                    port: 0,
                    uuid: *uuid,
                };
                let s = VlessStream::handshake(stream, &cfg, target, false).await?;
                Ok(Box::new(s))
            }
            other => Err(Error::config(format!(
                "shadowtls inner protocol {} is not supported (shadowsocks, trojan, vmess, vless)",
                other_kind_name(other)
            ))),
        }
    }

    /// Open a proxied TCP connection to `target`.
    pub async fn connect(&self, target: &NetAddr) -> Result<BoxProxyStream> {
        match &self.kind {
            OutboundKind::Direct => {
                let host = target.host.to_text();
                let tcp = tokio::net::TcpStream::connect((host.as_str(), target.port))
                    .await
                    .map_err(|e| Error::network(format!("direct dial {target}: {e}")))?;
                let _ = tcp.set_nodelay(true);
                Ok(Box::new(tcp))
            }
            OutboundKind::Reject => Err(Error::Rejected),
            OutboundKind::Http {
                server,
                port,
                username,
                password,
            } => {
                let cfg = HttpOut {
                    server: server.clone(),
                    port: *port,
                    username: username.clone(),
                    password: password.clone(),
                };
                let tcp = Self::dial_transport(server, *port, &TransportKind::Tcp, &TlsSettings::default())
                    .await?;
                let s = HttpStream::handshake(tcp, &cfg, target).await?;
                Ok(Box::new(s))
            }
            OutboundKind::Socks {
                server,
                port,
                username,
                password,
            } => {
                let cfg = SocksOut {
                    server: server.clone(),
                    port: *port,
                    username: username.clone(),
                    password: password.clone(),
                };
                let tcp = Self::dial_transport(server, *port, &TransportKind::Tcp, &TlsSettings::default())
                    .await?;
                let s = SocksStream::handshake(tcp, &cfg, target).await?;
                Ok(Box::new(s))
            }
            OutboundKind::Shadowsocks {
                server,
                port,
                method,
                password,
                obfs,
            } => {
                let cfg = SsOut {
                    server: server.clone(),
                    port: *port,
                    method: *method,
                    password: password.clone(),
                };
                let mut tcp = Self::dial_transport(server, *port, &TransportKind::Tcp, &TlsSettings::default())
                    .await?;
                // simple-obfs wraps the RAW stream, below the cipher
                // (mihomo: obfs(conn) then StreamConn).
                if let Some(mode) = obfs {
                    tcp = mode.wrap(tcp).await?;
                }
                let s = SsStream::handshake(tcp, &cfg, target, &[]).await?;
                Ok(Box::new(s))
            }
            OutboundKind::Vmess {
                server,
                port,
                uuid,
                security,
                transport,
                tls,
            } => {
                let cfg = VmessOut {
                    server: server.clone(),
                    port: *port,
                    uuid: *uuid,
                    security: *security,
                };
                let stream = Self::dial_transport(server, *port, transport, tls).await?;
                let s = VmessStream::handshake(stream, &cfg, target, false).await?;
                Ok(Box::new(s))
            }
            OutboundKind::Vless {
                server,
                port,
                uuid,
                transport,
                tls,
                reality,
                fingerprint,
                vision,
            } => {
                let cfg = VlessOut {
                    server: server.clone(),
                    port: *port,
                    uuid: *uuid,
                };
                let stream =
                    Self::vless_front(server, *port, transport, tls, reality, fingerprint).await?;
                if *vision {
                    // Vision: the request header carries the flow addons,
                    // then the framing wraps everything after the
                    // handshake (the app's TLS records ride inside).
                    let addons = crate::proto::vision::vision_request_addons();
                    let vs = VlessStream::handshake_with_addons(
                        stream,
                        &cfg,
                        target,
                        false,
                        Some(&addons),
                    )
                    .await?;
                    let conn = crate::proto::vision::VisionConn::connect(
                        Box::new(vs),
                        target,
                        *uuid,
                        crate::proto::vision::VisionConfig::default(),
                    )
                    .await?;
                    return Ok(Box::new(conn));
                }
                let s = VlessStream::handshake(stream, &cfg, target, false).await?;
                Ok(Box::new(s))
            }
            OutboundKind::Trojan {
                server,
                port,
                password,
                transport,
                tls,
            } => {
                let cfg = TrojanOut {
                    server: server.clone(),
                    port: *port,
                    password: password.clone(),
                };
                let stream = Self::dial_transport(server, *port, transport, tls).await?;
                let s = TrojanStream::handshake(stream, &cfg, target, false).await?;
                Ok(Box::new(s))
            }
            OutboundKind::Hysteria2 {
                server,
                port,
                password,
                sni,
                skip_verify,
                obfs,
            } => {
                let cfg = crate::proto::hysteria2::Hysteria2Cfg {
                    server: server.clone(),
                    port: *port,
                    password: password.clone(),
                    sni: sni.clone().unwrap_or_else(|| server.clone()),
                    skip_verify: *skip_verify,
                    obfs: obfs.clone(),
                };
                let conn = self
                    .quic_conn(|| async { crate::proto::hysteria2::connect(&cfg).await })
                    .await?;
                crate::proto::hysteria2::tcp_stream(&conn, target).await
            }
            OutboundKind::Tuic {
                server,
                port,
                uuid,
                password,
                sni,
                skip_verify,
                ..
            } => {
                let cfg = crate::proto::tuic::TuicCfg {
                    server: server.clone(),
                    port: *port,
                    uuid: *uuid,
                    password: password.clone(),
                    sni: sni.clone().unwrap_or_else(|| server.clone()),
                    skip_verify: *skip_verify,
                    udp_relay_mode: crate::proto::tuic::UdpRelayMode::default(),
                };
                let conn = self
                    .quic_conn(|| async { crate::proto::tuic::connect(&cfg).await })
                    .await?;
                crate::proto::tuic::tcp_stream(&conn, target).await
            }
            OutboundKind::Ssh {
                server,
                port,
                user,
                password,
                private_key,
                private_key_passphrase,
                host_key,
            } => {
                let cfg = crate::proto::ssh::SshOut {
                    server: server.clone(),
                    port: *port,
                    user: user.clone(),
                    password: password.clone(),
                    private_key: private_key.clone(),
                    private_key_passphrase: private_key_passphrase.clone(),
                    host_key: host_key.clone(),
                };
                crate::proto::ssh::connect(&cfg, target).await
            }
            OutboundKind::ShadowTls {
                server,
                port,
                password,
                sni,
                skip_verify,
                inner,
            } => {
                // Layering: raw TCP → shadowtls v3 → real TLS → inner
                // protocol handshake. The inner outbound never dials.
                let raw = tokio::net::TcpStream::connect((server.as_str(), *port))
                    .await
                    .map_err(|e| Error::network(format!("dial {server}:{port}: {e}")))?;
                let _ = raw.set_nodelay(true);
                let cfg = crate::proto::shadowtls::ShadowTlsOut {
                    server: server.clone(),
                    port: *port,
                    password: password.clone(),
                    sni: sni.clone(),
                    skip_verify: *skip_verify,
                };
                let st = crate::proto::shadowtls::connect(&cfg, Box::new(raw)).await?;
                let tls = TlsSettings {
                    enabled: true,
                    server_name: Some(sni.clone()),
                    skip_cert_verify: *skip_verify,
                    alpn: Vec::new(),
                };
                let stream = tls_connect(st, sni, &tls).await?;
                // The inner protocol's handshake over the wrapped stream.
                Self::shadowtls_inner(inner, stream, target).await
            }
            OutboundKind::Wireguard(cfg) => {
                crate::proto::wireguard::connect(cfg, target).await
            }
            OutboundKind::Snell(cfg) => {
                let tcp = Self::dial_transport(&cfg.server, cfg.port, &TransportKind::Tcp, &TlsSettings::default()).await?;
                let s = crate::proto::snell::handshake(tcp, cfg, target, false).await?;
                Ok(s)
            }
            OutboundKind::AnyTls(cfg) => {
                let tcp = Self::dial_transport(&cfg.server, cfg.port, &TransportKind::Tcp, &TlsSettings::default()).await?;
                crate::proto::anytls::connect(cfg, tcp, target).await
            }
            OutboundKind::Mieru(cfg) => {
                crate::proto::mieru::connect(cfg, target).await
            }
            OutboundKind::Restls { server, port, cfg } => {
                let tcp = Self::dial_transport(server, *port, &TransportKind::Tcp, &TlsSettings::default()).await?;
                crate::proto::restls::connect(cfg, tcp).await
            }
        }
    }

    /// Open a UDP channel through this outbound.
    /// Open a UDP channel. `initial` is the session's first destination —
    /// trojan writes it into the association header (upstream
    /// `WriteHeader(.., CommandUDP, serializesSocksAddr(metadata))`); other
    /// protocols ignore it.
    pub async fn udp(&self, initial: &NetAddr) -> Result<UdpChannel> {
        if !self.udp {
            return Err(Error::protocol(format!(
                "outbound {} does not support UDP",
                self.name
            )));
        }
        match &self.kind {
            OutboundKind::Direct => {
                let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
                Ok(UdpChannel::Direct(socket))
            }
            OutboundKind::Socks {
                server,
                port,
                username,
                password,
            } => {
                let cfg = SocksOut {
                    server: server.clone(),
                    port: *port,
                    username: username.clone(),
                    password: password.clone(),
                };
                let tcp = tokio::net::TcpStream::connect((server.as_str(), *port))
                    .await
                    .map_err(|e| Error::network(format!("dial {server}:{port}: {e}")))?;
                let socks_udp = SocksUdp::associate(tcp, &cfg).await?;
                Ok(UdpChannel::Socks(Box::new(socks_udp)))
            }
            OutboundKind::Shadowsocks {
                server,
                port,
                method,
                password,
                obfs,
            } => {
                if obfs.is_some() {
                    // simple-obfs is TCP-only upstream too.
                    return Err(Error::protocol(
                        "shadowsocks UDP is not available under simple-obfs",
                    ));
                }
                let cfg = SsOut {
                    server: server.clone(),
                    port: *port,
                    method: *method,
                    password: password.clone(),
                };
                Ok(UdpChannel::Ss(Box::new(SsUdp::bind(&cfg).await?)))
            }
            OutboundKind::Vmess {
                server,
                port,
                uuid,
                security,
                transport,
                tls,
            } => {
                let cfg = VmessOut {
                    server: server.clone(),
                    port: *port,
                    uuid: *uuid,
                    security: *security,
                };
                let stream = Self::dial_transport(server, *port, transport, tls).await?;
                // The header target is ignored for UDP commands; each
                // chunk carries its own addressed packet.
                let target = NetAddr::ip(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
                let s = VmessStream::handshake(stream, &cfg, &target, true).await?;
                Ok(UdpChannel::Vmess(tokio::sync::Mutex::new(Box::new(s))))
            }
            OutboundKind::Vless {
                server,
                port,
                uuid,
                transport,
                tls,
                reality,
                fingerprint,
                vision,
            } => {
                if *vision {
                    return Err(Error::protocol(
                        "vless UDP is not available under xtls-rprx-vision",
                    ));
                }
                let cfg = VlessOut {
                    server: server.clone(),
                    port: *port,
                    uuid: *uuid,
                };
                let stream =
                    Self::vless_front(server, *port, transport, tls, reality, fingerprint).await?;
                let target = NetAddr::ip(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);
                let s = VlessStream::handshake(stream, &cfg, &target, true).await?;
                Ok(UdpChannel::Framed(tokio::sync::Mutex::new(Box::new(s))))
            }
            OutboundKind::Trojan {
                server,
                port,
                password,
                transport,
                tls,
            } => {
                let cfg = TrojanOut {
                    server: server.clone(),
                    port: *port,
                    password: password.clone(),
                };
                let stream = Self::dial_transport(server, *port, transport, tls).await?;
                // Upstream trojan writes the REAL session target into the
                // UDP association header (mihomo trojan.go writeHeaderContext).
                let s = TrojanStream::handshake(stream, &cfg, initial, true).await?;
                Ok(UdpChannel::Trojan(tokio::sync::Mutex::new(Box::new(s))))
            }
            // QUIC UDP relays dial a DEDICATED connection per channel: the
            // datagram reader is exclusive, and UDP sessions are
            // long-lived, so the shared TCP cache is bypassed.
            OutboundKind::Hysteria2 {
                server,
                port,
                password,
                sni,
                skip_verify,
                obfs,
            } => {
                let cfg = crate::proto::hysteria2::Hysteria2Cfg {
                    server: server.clone(),
                    port: *port,
                    password: password.clone(),
                    sni: sni.clone().unwrap_or_else(|| server.clone()),
                    skip_verify: *skip_verify,
                    obfs: obfs.clone(),
                };
                let conn = std::sync::Arc::new(crate::proto::hysteria2::connect(&cfg).await?);
                let (tx, rx) = tokio::sync::mpsc::channel(64);
                let pump = conn.clone();
                tokio::spawn(async move {
                    while let Ok(dg) = pump.read_datagram().await {
                        let Ok(msg) = crate::proto::hysteria2::parse_udp_message(&dg) else {
                            continue;
                        };
                        let Some(target) = parse_hostport(&msg.addr) else {
                            continue;
                        };
                        if tx.send((target, msg.data.to_vec())).await.is_err() {
                            break;
                        }
                    }
                });
                Ok(UdpChannel::Quic(QuicUdp {
                    conn,
                    kind: QuicUdpKind::Hysteria2,
                    rx,
                    session_id: 0,
                    packet_seq: 0,
                }))
            }
            OutboundKind::Tuic {
                server,
                port,
                uuid,
                password,
                sni,
                skip_verify,
                udp_relay_mode,
            } => {
                let cfg = crate::proto::tuic::TuicCfg {
                    server: server.clone(),
                    port: *port,
                    uuid: *uuid,
                    password: password.clone(),
                    sni: sni.clone().unwrap_or_else(|| server.clone()),
                    skip_verify: *skip_verify,
                    udp_relay_mode: *udp_relay_mode,
                };
                let conn = std::sync::Arc::new(crate::proto::tuic::connect(&cfg).await?);
                let session_id = (std::process::id() % 0xffff) as u16;
                let (tx, rx) = tokio::sync::mpsc::channel(64);
                let pump = conn.clone();
                tokio::spawn(async move {
                    // v5 servers time sessions out without heartbeats.
                    let mut tick = tokio::time::interval(std::time::Duration::from_secs(10));
                    loop {
                        tokio::select! {
                            _ = tick.tick() => {
                                if crate::proto::tuic::heartbeat(&pump).await.is_err() {
                                    break;
                                }
                            }
                            dg = pump.read_datagram() => {
                                let Ok(dg) = dg else { break };
                                let Ok(frame) = crate::proto::tuic::decode_packet_frame(&dg)
                                else {
                                    continue;
                                };
                                let Some(addr) = frame.addr.clone() else {
                                    continue;
                                };
                                let data = frame.data.to_vec();
                                if tx.send((addr, data)).await.is_err() {
                                    break;
                                }
                            }
                        }
                    }
                });
                Ok(UdpChannel::Quic(QuicUdp {
                    conn,
                    kind: QuicUdpKind::Tuic(*udp_relay_mode),
                    rx,
                    session_id,
                    packet_seq: 0,
                }))
            }
            OutboundKind::Wireguard(cfg) => {
                if !cfg.udp {
                    return Err(Error::protocol("wireguard outbound has udp disabled"));
                }
                let wg = crate::proto::wireguard::WgUdp::bind(cfg).await?;
                Ok(UdpChannel::Wg(wg))
            }
            // Snell UDP: the session stream merges decrypted AEAD
            // frames, so packet edges are not recoverable through
            // BoxProxyStream yet — refused loudly (tracked in the
            // audit) rather than corrupting datagrams.
            OutboundKind::AnyTls(cfg) if cfg.udp => {
                let tcp = Self::dial_transport(&cfg.server, cfg.port, &TransportKind::Tcp, &TlsSettings::default()).await?;
                let udp = crate::proto::anytls::udp_stream(cfg, tcp).await?;
                Ok(UdpChannel::AnyTls(udp))
            }
            OutboundKind::Snell(_) => Err(Error::protocol(
                "snell UDP is not wired yet (frame-boundary reader pending)",
            )),
            OutboundKind::AnyTls(_) | OutboundKind::Mieru(_)
            | OutboundKind::Restls { .. } => Err(Error::protocol(format!(
                "{} does not support UDP",
                self.kind_name()
            ))),
            OutboundKind::Reject
            | OutboundKind::Http { .. }
            | OutboundKind::Ssh { .. }
            | OutboundKind::ShadowTls { .. } => Err(Error::protocol(format!(
                "{} does not support UDP",
                self.kind_name()
            ))),
        }
    }
}

/// Read a framed UDP downlink prefix: RFC 1928 address, then the
/// big-endian u16 payload length. Returns (addr, payload_len).
async fn read_framed_addr(
    stream: &mut BoxProxyStream,
) -> Result<(NetAddr, usize)> {
    use tokio::io::AsyncReadExt;
    let mut atyp = [0u8; 1];
    stream.read_exact(&mut atyp).await?;
    let mut frame = vec![atyp[0]];
    match atyp[0] {
        0x01 => {
            let mut b = [0u8; 4 + 2];
            stream.read_exact(&mut b).await?;
            frame.extend_from_slice(&b);
        }
        0x03 => {
            let mut l = [0u8; 1];
            stream.read_exact(&mut l).await?;
            frame.push(l[0]);
            let mut b = vec![0u8; l[0] as usize + 2];
            stream.read_exact(&mut b).await?;
            frame.extend_from_slice(&b);
        }
        0x04 => {
            let mut b = [0u8; 16 + 2];
            stream.read_exact(&mut b).await?;
            frame.extend_from_slice(&b);
        }
        other => {
            return Err(Error::protocol(format!(
                "udp tunnel frame: bad atyp {other:#x}"
            )))
        }
    }
    let (addr, used) = decode_socks_addr(&frame)?;
    if used != frame.len() {
        return Err(Error::protocol("udp tunnel frame: trailing address bytes"));
    }
    let mut lenb = [0u8; 2];
    stream.read_exact(&mut lenb).await?;
    Ok((addr, u16::from_be_bytes(lenb) as usize))
}

/// `host:port` display form (IPv6 bracketed) back into a NetAddr.
fn parse_hostport(s: &str) -> Option<NetAddr> {
    let (host, port) = s.rsplit_once(':')?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port: u16 = port.parse().ok()?;
    Some(NetAddr::new(crate::addr::Host::parse(host).ok()?, port))
}

/// kind_name for a raw OutboundKind (no Outbound wrapper).
fn other_kind_name(kind: &OutboundKind) -> &'static str {
    match kind {
        OutboundKind::Direct => "Direct",
        OutboundKind::Reject => "Reject",
        OutboundKind::Http { .. } => "Http",
        OutboundKind::Socks { .. } => "Socks",
        OutboundKind::Shadowsocks { .. } => "Shadowsocks",
        OutboundKind::Vmess { .. } => "Vmess",
        OutboundKind::Vless { .. } => "Vless",
        OutboundKind::Trojan { .. } => "Trojan",
        OutboundKind::Hysteria2 { .. } => "Hysteria2",
        OutboundKind::Tuic { .. } => "Tuic",
        OutboundKind::Ssh { .. } => "Ssh",
        OutboundKind::ShadowTls { .. } => "ShadowTls",
        OutboundKind::Wireguard(_) => "Wireguard",
        OutboundKind::Snell(_) => "Snell",
        OutboundKind::AnyTls(_) => "AnyTls",
        OutboundKind::Mieru(_) => "Mieru",
        OutboundKind::Restls { .. } => "Restls",
    }
}

/// A UDP channel over QUIC (hysteria2 datagrams / TUIC v5).
pub struct QuicUdp {
    conn: std::sync::Arc<quinn::Connection>,
    kind: QuicUdpKind,
    rx: tokio::sync::mpsc::Receiver<(NetAddr, Vec<u8>)>,
    session_id: u16,
    packet_seq: u16,
}

#[derive(Clone, Copy)]
enum QuicUdpKind {
    Hysteria2,
    Tuic(crate::proto::tuic::UdpRelayMode),
}

impl Drop for QuicUdp {
    fn drop(&mut self) {
        // TUIC sessions are released on the wire; hy2 just closes with
        // the channel. Best-effort — the connection drops anyway.
        if let QuicUdpKind::Tuic(_) = self.kind {
            let conn = self.conn.clone();
            let sid = self.session_id;
            tokio::spawn(async move {
                let _ = crate::proto::tuic::dissociate(&conn, sid).await;
            });
        }
    }
}

/// A UDP channel through any UDP-capable outbound.
pub enum UdpChannel {
    Direct(tokio::net::UdpSocket),
    Socks(Box<SocksUdp>),
    Ss(Box<SsUdp>),
    /// vmess tunnel: one body chunk per packet, `socks-addr || data`.
    Vmess(tokio::sync::Mutex<Box<VmessStream>>),
    /// vless tunnel: `socks-addr || len-be16 || data` frames.
    Framed(tokio::sync::Mutex<BoxProxyStream>),
    /// trojan tunnel: the same frame with a CRLF between the length and
    /// the payload (upstream transport/trojan framing).
    Trojan(tokio::sync::Mutex<BoxProxyStream>),
    /// hysteria2 / TUIC v5 datagram relays.
    Quic(QuicUdp),
    /// WireGuard userspace-stack UDP.
    Wg(crate::proto::wireguard::WgUdp),
    /// AnyTLS UDP-over-TCP (uot v2).
    AnyTls(crate::proto::anytls::AnyTlsUdp),
}

impl UdpChannel {
    pub async fn send(&mut self, target: &NetAddr, data: &[u8]) -> Result<()> {
        match self {
            UdpChannel::Direct(socket) => {
                let host = target.host.to_text();
                socket
                    .send_to(data, (host.as_str(), target.port))
                    .await
                    .map_err(|e| Error::network(format!("udp send: {e}")))?;
                Ok(())
            }
            UdpChannel::Socks(socks) => {
                let wire = SocksUdp::encode_datagram(target, data);
                socks
                    .socket
                    .send_to(&wire, socks.relay)
                    .await
                    .map_err(|e| Error::network(format!("socks5 udp send: {e}")))?;
                Ok(())
            }
            UdpChannel::Ss(ss) => ss.send(target, data).await,
            UdpChannel::Wg(w) => w.send(target, data).await,
            UdpChannel::AnyTls(a) => a.send_to(target, data).await,
            UdpChannel::Quic(q) => {
                q.packet_seq = q.packet_seq.wrapping_add(1);
                match q.kind {
                    QuicUdpKind::Hysteria2 => {
                        crate::proto::hysteria2::udp_send(&q.conn, target, data).await
                    }
                    QuicUdpKind::Tuic(crate::proto::tuic::UdpRelayMode::Native) => {
                        crate::proto::tuic::udp_send_native(
                            &q.conn,
                            q.session_id,
                            q.packet_seq,
                            target,
                            data,
                        )
                        .await
                    }
                    QuicUdpKind::Tuic(crate::proto::tuic::UdpRelayMode::Quic) => {
                        crate::proto::tuic::udp_send_quic(
                            &q.conn,
                            q.session_id,
                            q.packet_seq,
                            target,
                            data,
                        )
                        .await
                    }
                }
            }
            UdpChannel::Vmess(stream) => {
                let mut frame = Vec::with_capacity(data.len() + 32);
                crate::addr::encode_port_first_addr(&mut frame, &target.host, target.port);
                frame.extend_from_slice(data);
                use tokio::io::AsyncWriteExt;
                stream
                    .lock()
                    .await
                    .write_all(&frame)
                    .await
                    .map_err(|e| Error::network(format!("vmess udp send: {e}")))?;
                Ok(())
            }
            UdpChannel::Framed(stream) => {
                let frame = vless_udp_frame(target, data)?;
                use tokio::io::AsyncWriteExt;
                stream
                    .lock()
                    .await
                    .write_all(&frame)
                    .await
                    .map_err(|e| Error::network(format!("udp tunnel send: {e}")))?;
                Ok(())
            }
            UdpChannel::Trojan(stream) => {
                let frame = crate::proto::trojan::trojan_udp_frame(target, data)?;
                use tokio::io::AsyncWriteExt;
                stream
                    .lock()
                    .await
                    .write_all(&frame)
                    .await
                    .map_err(|e| Error::network(format!("trojan udp send: {e}")))?;
                Ok(())
            }
        }
    }

    pub async fn recv(&mut self) -> Result<(NetAddr, Vec<u8>)> {
        match self {
            UdpChannel::Direct(socket) => {
                let mut buf = vec![0u8; 65536];
                // The reply source only decides the address family; the
                // dummy target is what the socks encoder writes back.
                let (n, peer) = socket
                    .recv_from(&mut buf)
                    .await
                    .map_err(|e| Error::network(format!("udp recv: {e}")))?;
                let peer_ip = match peer.ip() {
                    std::net::IpAddr::V4(_) => "0.0.0.0".parse().unwrap(),
                    std::net::IpAddr::V6(_) => "::".parse().unwrap(),
                };
                Ok((NetAddr::ip(peer_ip, 0), buf[..n].to_vec()))
            }
            UdpChannel::Socks(socks) => {
                let mut buf = vec![0u8; 65536];
                let (n, _) = socks
                    .socket
                    .recv_from(&mut buf)
                    .await
                    .map_err(|e| Error::network(format!("socks5 udp recv: {e}")))?;
                let (addr, data) = SocksUdp::decode_datagram(&buf[..n])?;
                Ok((addr, data.to_vec()))
            }
            UdpChannel::Ss(ss) => ss.recv().await,
            UdpChannel::Vmess(stream) => {
                let mut stream = stream.lock().await;
                let packet = stream.read_packet().await?;
                let (addr, used) = crate::addr::decode_port_first_addr(&packet)?;
                Ok((addr, packet[used..].to_vec()))
            }
            UdpChannel::Framed(stream) => {
                let mut stream = stream.lock().await;
                let (addr, len) = read_framed_addr(&mut stream).await?;
                let mut data = vec![0u8; len];
                stream.read_exact(&mut data).await?;
                Ok((addr, data))
            }
            UdpChannel::Trojan(stream) => {
                // Trojan UDP frames carry a CRLF between the length and
                // the payload (upstream transport/trojan writePacket) —
                // both directions.
                let mut stream = stream.lock().await;
                let (addr, len) = read_framed_addr(&mut stream).await?;
                let mut crlf = [0u8; 2];
                stream.read_exact(&mut crlf).await?;
                let mut data = vec![0u8; len];
                stream.read_exact(&mut data).await?;
                Ok((addr, data))
            }
            UdpChannel::Quic(q) => {
                q.rx
                    .recv()
                    .await
                    .ok_or_else(|| Error::network("quic udp channel closed"))
            }
            UdpChannel::Wg(w) => w.recv().await,
            UdpChannel::AnyTls(a) => {
                let mut buf = vec![0u8; 65536];
                let (addr, n) = a.recv_from(&mut buf).await?;
                Ok((addr, buf[..n].to_vec()))
            }
        }
    }
}

/// Registry of outbounds and groups; resolves a name to a leaf outbound,
/// following group selections with a cycle guard.
pub struct Registry {
    outbounds: Vec<Outbound>,
    index: HashMap<String, usize>,
    groups: Vec<GroupState>,
    group_index: HashMap<String, usize>,
}

/// A proxy group.
#[derive(Debug, Clone)]
pub struct GroupConfig {
    pub name: String,
    pub members: Vec<String>,
    pub policy: GroupPolicy,
    pub url: Option<String>,
    pub interval: u64,
    pub tolerance: u16,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupPolicy {
    Select,
    UrlTest,
    Fallback,
    LoadBalance,
}

pub struct GroupState {
    pub cfg: GroupConfig,
    selected: RwLock<Option<usize>>,
    /// Latest latency per member (ms). None = untested, Some(0) = failed.
    latencies: RwLock<HashMap<String, Option<u32>>>,
}

impl Registry {
    pub fn build(outbounds: Vec<OutboundConfig>, groups: Vec<GroupConfig>) -> Result<Self> {
        let mut index = HashMap::new();
        let mut runtime = Vec::with_capacity(outbounds.len());
        for cfg in &outbounds {
            if cfg.name.is_empty() {
                return Err(Error::config("outbound with empty name"));
            }
            if index.contains_key(&cfg.name) {
                return Err(Error::config(format!("duplicate outbound {}", cfg.name)));
            }
            index.insert(cfg.name.clone(), runtime.len());
            runtime.push(Outbound::from_config(cfg)?);
        }
        let mut group_index = HashMap::new();
        let mut group_states = Vec::with_capacity(groups.len());
        for cfg in groups {
            if index.contains_key(&cfg.name) || group_index.contains_key(&cfg.name) {
                return Err(Error::config(format!("duplicate group {}", cfg.name)));
            }
            if cfg.members.is_empty() {
                return Err(Error::config(format!("group {} has no members", cfg.name)));
            }
            group_index.insert(cfg.name.clone(), group_states.len());
            group_states.push(GroupState {
                cfg,
                selected: RwLock::new(None),
                latencies: RwLock::new(HashMap::new()),
            });
        }
        // Validate references.
        for g in &group_states {
            for m in &g.cfg.members {
                if !index.contains_key(m) && !group_index.contains_key(m) {
                    return Err(Error::config(format!(
                        "group {} references unknown proxy {m:?}",
                        g.cfg.name
                    )));
                }
            }
        }
        Ok(Registry {
            outbounds: runtime,
            index,
            groups: group_states,
            group_index,
        })
    }

    pub fn leaf_names(&self) -> Vec<String> {
        self.outbounds.iter().map(|o| o.name.clone()).collect()
    }

    pub fn group_names(&self) -> Vec<String> {
        self.groups.iter().map(|g| g.cfg.name.clone()).collect()
    }

    pub fn group(&self, name: &str) -> Option<&GroupState> {
        self.group_index.get(name).map(|i| &self.groups[*i])
    }

    /// Resolve a name to a leaf outbound following selections.
    pub async fn resolve(&self, name: &str) -> Result<&Outbound> {
        let mut current: std::borrow::Cow<'_, str> = std::borrow::Cow::Borrowed(name);
        for _ in 0..16 {
            if let Some(i) = self.index.get(current.as_ref()) {
                return Ok(&self.outbounds[*i]);
            }
            let Some(gi) = self.group_index.get(current.as_ref()).copied() else {
                return Err(Error::config(format!("unknown proxy {current:?}")));
            };
            let group = &self.groups[gi];
            current = std::borrow::Cow::Owned(self.pick_member(group).await?);
        }
        Err(Error::config(format!("proxy group cycle at {current:?}")))
    }

    /// Select the active member for a group per its policy.
    async fn pick_member(&self, group: &GroupState) -> Result<String> {
        let members = &group.cfg.members;
        match group.cfg.policy {
            GroupPolicy::Select => {
                let selected = group.selected.read().await;
                let idx = selected.unwrap_or(0);
                members
                    .get(idx)
                    .cloned()
                    .ok_or_else(|| Error::config(format!("group {} selection out of range", group.cfg.name)))
            }
            GroupPolicy::UrlTest => {
                // Lowest latency wins, but only by more than `tolerance`:
                // mihomo keeps the incumbent unless a challenger beats it
                // by the configured margin (avoids flapping).
                let latencies = group.latencies.read().await;
                let mut best: Option<(usize, u32)> = None;
                for (i, m) in members.iter().enumerate() {
                    if let Some(Some(lat)) = latencies.get(m) {
                        if *lat == 0 {
                            continue; // failed probe
                        }
                        match best {
                            None => best = Some((i, *lat)),
                            Some((_, bl)) if (*lat + u32::from(group.cfg.tolerance)) < bl => {
                                best = Some((i, *lat))
                            }
                            _ => {}
                        }
                    }
                }
                Ok(best
                    .map(|(i, _)| members[i].clone())
                    .unwrap_or_else(|| members[0].clone()))
            }
            GroupPolicy::Fallback => {
                // First ALIVE member in config order — fallback preserves
                // priority order, it does not hunt for the fastest.
                let latencies = group.latencies.read().await;
                for m in members.iter() {
                    if matches!(latencies.get(m), Some(Some(lat)) if *lat > 0) {
                        return Ok(m.clone());
                    }
                }
                Ok(members[0].clone())
            }
            GroupPolicy::LoadBalance => {
                let count = members.len() as u64;
                let tick = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_secs())
                    .unwrap_or(0);
                let idx = (tick % count.max(1)) as usize;
                Ok(members[idx].clone())
            }
        }
    }

    /// Explicit selection (Clash API PUT /proxies/:name).
    pub async fn set_selected(&self, group: &str, member: &str) -> Result<()> {
        let gi = self
            .group_index
            .get(group)
            .copied()
            .ok_or_else(|| Error::config(format!("unknown group {group:?}")))?;
        let g = &self.groups[gi];
        let idx = g
            .cfg
            .members
            .iter()
            .position(|m| m == member)
            .ok_or_else(|| {
                Error::config(format!("group {group:?} has no member {member:?}"))
            })?;
        // Only Select groups honor manual choice.
        if !matches!(g.cfg.policy, GroupPolicy::Select) {
            return Err(Error::protocol(format!(
                "group {group:?} is not manually selectable"
            )));
        }
        *self.groups[gi].selected.write().await = Some(idx);
        Ok(())
    }

    /// Record a latency sample (health checks and the API delay test).
    pub async fn record_latency(&self, name: &str, latency: Option<u32>) {
        for g in &self.groups {
            if g.cfg.members.iter().any(|m| m == name) {
                g.latencies.write().await.insert(name.to_string(), latency);
            }
        }
    }

    /// Snapshot of latencies for the API.
    pub async fn latency_snapshot(&self) -> HashMap<String, Option<u32>> {
        let mut out = HashMap::new();
        for g in &self.groups {
            for (k, v) in g.latencies.read().await.iter() {
                out.insert(k.clone(), *v);
            }
        }
        out
    }

    /// Run one URL-test round for every url-test/fallback group member
    /// that has no fresh sample yet.
    pub async fn health_round(&self) {
        for g in &self.groups {
            if !matches!(g.cfg.policy, GroupPolicy::UrlTest | GroupPolicy::Fallback) {
                continue;
            }
            let url = g.cfg.url.clone().unwrap_or_else(|| {
                "http://www.gstatic.com/generate_204".to_string()
            });
            for m in &g.cfg.members {
                let Ok(outbound) = self.resolve(m).await else {
                    continue;
                };
                if matches!(outbound.kind_name(), "Direct" | "Reject") {
                    continue;
                }
                let started = std::time::Instant::now();
                let probe = probe(&url, outbound).await;
                let sample = probe.ok().map(|_| started.elapsed().as_millis() as u32);
                self.record_latency(m, sample).await;
            }
        }
    }
}

/// Fetch a URL through an outbound (GET via a minimal HTTP/1.1 request).
pub async fn probe(url: &str, outbound: &Outbound) -> Result<()> {
    let (host, port, path) = parse_probe_url(url)?;
    let target = NetAddr::domain(&host, port)?;
    let mut stream = outbound.connect(&target).await?;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let req = format!("GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: rustcrash-engine\r\nConnection: close\r\n\r\n");
    stream.write_all(req.as_bytes()).await?;
    let mut buf = [0u8; 128];
    let n = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
        .await
        .map_err(|_| Error::network("probe timeout"))?
        .map_err(|e| Error::network(e.to_string()))?;
    if n == 0 {
        return Err(Error::network("probe: empty response"));
    }
    let head = String::from_utf8_lossy(&buf[..n]);
    let code = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .unwrap_or(0);
    if (200..400).contains(&code) {
        Ok(())
    } else {
        Err(Error::network(format!("probe status {code}")))
    }
}

fn parse_probe_url(url: &str) -> Result<(String, u16, String)> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| Error::config(format!("probe URL must be http: {url:?}")))?;
    let (hostport, path) = match rest.split_once('/') {
        Some((hp, p)) => (hp, format!("/{p}")),
        None => (rest, "/".to_string()),
    };
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => (h.to_string(), p.parse().unwrap_or(80)),
        None => (hostport.to_string(), 80),
    };
    Ok((host, port, path))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::shadowsocks::SsMethod;

    fn direct(name: &str) -> OutboundConfig {
        OutboundConfig {
            name: name.into(),
            udp: true,
            kind: OutboundKind::Direct,
        }
    }

    fn reject(name: &str) -> OutboundConfig {
        OutboundConfig {
            name: name.into(),
            udp: false,
            kind: OutboundKind::Reject,
        }
    }

    #[tokio::test]
    async fn registry_resolves_groups_and_selection() {
        let groups = vec![GroupConfig {
            name: "G".into(),
            members: vec!["A".into(), "B".into()],
            policy: GroupPolicy::Select,
            url: None,
            interval: 0,
            tolerance: 0,
        }];
        let reg = Registry::build(vec![direct("A"), direct("B"), reject("R")], groups).unwrap();
        assert_eq!(reg.resolve("G").await.unwrap().name, "A");
        assert_eq!(reg.resolve("A").await.unwrap().name, "A");
        reg.set_selected("G", "B").await.unwrap();
        assert_eq!(reg.resolve("G").await.unwrap().name, "B");
        assert!(reg.set_selected("G", "R").await.is_err());
        assert!(reg.set_selected("A", "A").await.is_err());
    }

    #[tokio::test]
    async fn registry_rejects_unknown_refs_and_cycles() {
        let groups = vec![GroupConfig {
            name: "G".into(),
            members: vec!["missing".into()],
            policy: GroupPolicy::Select,
            url: None,
            interval: 0,
            tolerance: 0,
        }];
        assert!(Registry::build(vec![direct("A")], groups).is_err());

        let groups = vec![
            GroupConfig {
                name: "G1".into(),
                members: vec!["G2".into()],
                policy: GroupPolicy::Select,
                url: None,
                interval: 0,
                tolerance: 0,
            },
            GroupConfig {
                name: "G2".into(),
                members: vec!["G1".into()],
                policy: GroupPolicy::Select,
                url: None,
                interval: 0,
                tolerance: 0,
            },
        ];
        let reg = Registry::build(vec![], groups).unwrap();
        assert!(reg.resolve("G1").await.is_err());
    }

    #[tokio::test]
    async fn reject_outbound_fails_connect() {
        let out = Outbound::from_config(&reject("R")).unwrap();
        let err = out
            .connect(&NetAddr::domain("x.test", 80).unwrap())
            .await
            .err()
            .expect("reject must fail");
        assert!(matches!(err, Error::Rejected));
    }

    #[tokio::test]
    async fn direct_roundtrip() {
        // Echo server on loopback, reached through the Direct outbound.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let (mut sock, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 16];
            let n = sock.read(&mut buf).await.unwrap();
            sock.write_all(&buf[..n]).await.unwrap();
        });
        let out = Outbound::from_config(&direct("D")).unwrap();
        let mut stream = out
            .connect(&NetAddr::ip(addr.ip(), addr.port()))
            .await
            .unwrap();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 16];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    #[tokio::test]
    async fn udp_unsupported_errors() {
        let out = Outbound::from_config(&reject("R")).unwrap();
        assert!(out
            .udp(&NetAddr::ip(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0))
            .await
            .is_err());
    }

    #[test]
    fn probe_url_parsing() {
        let (h, p, path) = parse_probe_url("http://www.gstatic.com/generate_204").unwrap();
        assert_eq!(h, "www.gstatic.com");
        assert_eq!(p, 80);
        assert_eq!(path, "/generate_204");
        let (h, p, path) = parse_probe_url("http://cp.cloudflare.com:8080/").unwrap();
        assert_eq!(h, "cp.cloudflare.com");
        assert_eq!(p, 8080);
        assert_eq!(path, "/");
        assert!(parse_probe_url("https://x").is_err());
    }

    #[test]
    fn outbound_kinds_named() {
        let out = Outbound::from_config(&OutboundConfig {
            name: "ss".into(),
            udp: true,
            kind: OutboundKind::Shadowsocks {
                server: "s".into(),
                port: 1,
                method: SsMethod::Aes256Gcm,
                password: "p".into(),
                obfs: None,
            },
        })
        .unwrap();
        assert_eq!(out.kind_name(), "Shadowsocks");
    }
}
