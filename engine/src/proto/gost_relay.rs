//! gost-relay outbound (mihomo `transport/gost/relay.go`): the go-gost
//! relay protocol client — a feature-framed CONNECT over TCP (with
//! optional TLS), plus the UDP association that reuses the same
//! framing with `relayFlagUDP`.
//!
//! ## Upstream map
//!
//! * `adapter/outbound/gost_relay.go` — `GostRelayOption`, dialer
//!   wiring (`NewRelayDialer` → `relayDialer.DialContext` /
//!   `ListenPacket`).
//! * `transport/gost/relay.go` — the whole wire protocol:
//!   * Request (`writeRelayRequest`, relay.go:231):
//!     `version=0x01 || command || featuresLen be16 || features…`
//!     with feature entries `type u8 || len be16 || payload`:
//!     userauth (0x01: `ulen u8 || user || plen u8 || pass`),
//!     addr (0x02: SOCKS-style `atyp || addr || port`, port LAST),
//!     network (0x04: `be16`, TCP=0/UDP=1). With `forward`, the addr
//!     feature is omitted (the server uses its configured forward).
//!   * Response (`readRelayConnectResponse`, relay.go:354):
//!     `version u8 || status u8 || featuresLen be16` (features
//!     discarded); non-zero status is fatal.
//!   * TCP (`DialContext`, relay.go:85): dial the relay server (its own
//!     server:port, or the target itself under `forward`), optionally
//!     wrap with TLS, send CONNECT, await status, tunnel.
//!   * UDP (`ListenPacket`, relay.go:117): CONNECT|0x80 with the
//!     network feature = UDP and the raddr as target; datagrams are
//!     `len be16 || payload` frames bound to the connect-time peer.
//!
//! ## Scope
//!
//! * `mux: true` wraps each dial in an smux session
//!   (`dialRelayServer`, relay.go:192 — github.com/metacubex/smux).
//!   smux is a full session protocol (SYN/FIN/PSH/NPN/UPD frames with
//!   per-stream windows) not present anywhere in this engine, so the
//!   option is config-rejected with a precise reason.
//! * TLS uses the engine's rustls client stack (same verification
//!   paths as every other TCP transport) instead of Go's
//!   `vmess.StreamTLSConn` fingerprint zoo; `client-fingerprint`,
//!   `fingerprint`, `certificate`/`private-key` (client-cert auth) are
//!   carried but not applied — the plain rustls hello is offered.
//!   `name-cert-verify` is likewise carried: rustls verifies against
//!   the system/webpki stores with the SNI as the name.

use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

use crate::addr::{Host, NetAddr};
use crate::error::{Error, Result};
use crate::stream::BoxProxyStream;
use crate::transport::{tls_connect, TlsSettings};

/// `relayVersion1`.
const RELAY_VERSION: u8 = 0x01;
/// `relayCmdConnect`.
const RELAY_CMD_CONNECT: u8 = 0x01;
/// `relayFlagUDP`.
const RELAY_FLAG_UDP: u8 = 0x80;

/// Status codes (`relayStatus*`, relay.go:28-37).
const RELAY_STATUS_OK: u8 = 0x00;

/// `relayFeatureUserAuth/Addr/Network`.
const RELAY_FEATURE_USER_AUTH: u8 = 0x01;
const RELAY_FEATURE_ADDR: u8 = 0x02;
const RELAY_FEATURE_NETWORK: u8 = 0x04;

/// `relayNetworkTCP/UDP`.
const RELAY_NETWORK_TCP: u16 = 0x0000;
const RELAY_NETWORK_UDP: u16 = 0x0001;

/// Outbound gost-relay endpoint — mihomo `proxies: type: gost-relay`
/// fields (`GostRelayOption`, adapter/outbound/gost_relay.go:19).
#[derive(Debug, Clone)]
pub struct GostRelayOut {
    pub server: String,
    pub port: u16,
    /// `forward`: omit the target address feature (server-side forward).
    pub forward: bool,
    /// UDP capability flag.
    pub udp: bool,
    /// `tls`: wrap the relay connection in TLS.
    pub tls: bool,
    /// `mux`: smux session per dial — rejected (see module docs).
    pub mux: bool,
    /// `sni` (defaults to the relay server host).
    pub sni: String,
    pub username: String,
    pub password: String,
    /// `skip-cert-verify`.
    pub skip_cert_verify: bool,
    /// `name-cert-verify` — carried (rustls verifies via SNI).
    pub name_cert_verify: String,
    /// `fingerprint` (server cert pinning) — carried, not applied.
    pub fingerprint: String,
    /// `certificate` / `private-key` (client cert) — carried, not applied.
    pub certificate: String,
    pub private_key: String,
    /// `client-fingerprint` (uTLS hello) — carried, not applied.
    pub client_fingerprint: String,
}

impl GostRelayOut {
    pub fn new(server: &str, port: u16) -> Self {
        GostRelayOut {
            server: server.to_string(),
            port,
            forward: false,
            udp: false,
            tls: false,
            mux: false,
            sni: String::new(),
            username: String::new(),
            password: String::new(),
            skip_cert_verify: false,
            name_cert_verify: String::new(),
            fingerprint: String::new(),
            certificate: String::new(),
            private_key: String::new(),
            client_fingerprint: String::new(),
        }
    }
}

/// `relayStatusText` (relay.go:429).
fn relay_status_text(status: u8) -> &'static str {
    match status {
        RELAY_STATUS_OK => "ok",
        0x01 => "bad request",
        0x02 => "unauthorized",
        0x03 => "forbidden",
        0x04 => "timeout",
        0x05 => "service unavailable",
        0x06 => "host unreachable",
        0x07 => "network unreachable",
        0x08 => "internal server error",
        _ => "unknown",
    }
}

/// `encodeRelayFeature` (relay.go:375).
fn encode_relay_feature(feature_type: u8, payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > 0xFFFF {
        return Err(Error::protocol(
            "gost-relay: feature payload too large",
        ));
    }
    let mut out = Vec::with_capacity(3 + payload.len());
    out.push(feature_type);
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// `encodeRelayUserAuth` (relay.go:388).
fn encode_relay_user_auth(username: &str, password: &str) -> Result<Vec<u8>> {
    if username.len() > 0xFF || password.len() > 0xFF {
        return Err(Error::protocol(
            "gost-relay: username or password too long",
        ));
    }
    let mut out = Vec::with_capacity(2 + username.len() + password.len());
    out.push(username.len() as u8);
    out.extend_from_slice(username.as_bytes());
    out.push(password.len() as u8);
    out.extend_from_slice(password.as_bytes());
    Ok(out)
}

/// `encodeRelayAddr` (relay.go:397): SOCKS-style address, port LAST.
fn encode_relay_addr(target: &NetAddr) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(1 + 16 + 2);
    match &target.host {
        Host::Domain(d) => {
            if d.len() > 0xFF {
                return Err(Error::protocol(
                    "gost-relay: target host too long",
                ));
            }
            out.push(0x03);
            out.push(d.len() as u8);
            out.extend_from_slice(d.as_bytes());
        }
        Host::Ip(std::net::IpAddr::V4(v4)) => {
            out.push(0x01);
            out.extend_from_slice(&v4.octets());
        }
        Host::Ip(std::net::IpAddr::V6(v6)) => {
            out.push(0x04);
            out.extend_from_slice(&v6.octets());
        }
    }
    out.extend_from_slice(&target.port.to_be_bytes());
    Ok(out)
}

/// `writeRelayRequest` (relay.go:231).
fn build_relay_request(
    command: u8,
    target: Option<&NetAddr>,
    network: u16,
    username: &str,
    password: &str,
) -> Result<Vec<u8>> {
    let mut features = Vec::with_capacity(3);
    if !username.is_empty() || !password.is_empty() {
        features.push(encode_relay_feature(
            RELAY_FEATURE_USER_AUTH,
            &encode_relay_user_auth(username, password)?,
        )?);
    }
    if let Some(target) = target {
        features.push(encode_relay_feature(
            RELAY_FEATURE_ADDR,
            &encode_relay_addr(target)?,
        )?);
    }
    features.push(encode_relay_feature(
        RELAY_FEATURE_NETWORK,
        &network.to_be_bytes(),
    )?);
    let payload_len: usize = features.iter().map(|f| f.len()).sum();
    if payload_len > 0xFFFF {
        return Err(Error::protocol(
            "gost-relay: feature list too large",
        ));
    }
    let mut out = Vec::with_capacity(4 + payload_len);
    out.push(RELAY_VERSION);
    out.push(command);
    out.extend_from_slice(&(payload_len as u16).to_be_bytes());
    for f in features {
        out.extend_from_slice(&f);
    }
    Ok(out)
}

/// The parsed relay request: (command, target, network, user, pass).
#[cfg(test)]
type ParsedRelayRequest = (u8, Option<NetAddr>, u16, (String, String));

/// The server-side mirror of the request parser (test mimic).
#[cfg(test)]
fn parse_relay_request(data: &[u8]) -> Result<ParsedRelayRequest> {
    if data.len() < 4 || data[0] != RELAY_VERSION {
        return Err(Error::protocol("gost-relay: bad version"));
    }
    let command = data[1];
    let flen = u16::from_be_bytes([data[2], data[3]]) as usize;
    if data.len() < 4 + flen {
        return Err(Error::protocol("gost-relay: short feature list"));
    }
    let mut target = None;
    let mut network = RELAY_NETWORK_TCP;
    let mut auth = (String::new(), String::new());
    let mut off = 4usize;
    while off + 3 <= 4 + flen {
        let ftype = data[off];
        let plen = u16::from_be_bytes([data[off + 1], data[off + 2]]) as usize;
        if off + 3 + plen > 4 + flen {
            return Err(Error::protocol("gost-relay: short feature"));
        }
        let payload = &data[off + 3..off + 3 + plen];
        match ftype {
            RELAY_FEATURE_USER_AUTH => {
                if payload.len() < 2 {
                    return Err(Error::protocol("gost-relay: short auth"));
                }
                let ul = payload[0] as usize;
                if payload.len() < 1 + ul + 1 {
                    return Err(Error::protocol("gost-relay: short auth user"));
                }
                let user = String::from_utf8_lossy(&payload[1..1 + ul]).into_owned();
                let pl = payload[1 + ul] as usize;
                if payload.len() < 1 + ul + 1 + pl {
                    return Err(Error::protocol("gost-relay: short auth pass"));
                }
                let pass = String::from_utf8_lossy(&payload[2 + ul..2 + ul + pl]).into_owned();
                auth = (user, pass);
            }
            RELAY_FEATURE_ADDR => {
                let atyp = *payload.first().ok_or_else(|| Error::protocol("gost-relay: empty addr"))?;
                let (host, used) = match atyp {
                    0x01 => {
                        let o = payload.get(1..5).ok_or_else(|| Error::protocol("gost-relay: short ipv4"))?;
                        (
                            Host::Ip(std::net::IpAddr::V4(std::net::Ipv4Addr::new(
                                o[0], o[1], o[2], o[3],
                            ))),
                            4usize,
                        )
                    }
                    0x04 => {
                        let o = payload.get(1..17).ok_or_else(|| Error::protocol("gost-relay: short ipv6"))?;
                        let mut b = [0u8; 16];
                        b.copy_from_slice(o);
                        (Host::Ip(std::net::IpAddr::V6(b.into())), 16usize)
                    }
                    0x03 => {
                        let l = *payload.get(1).ok_or_else(|| Error::protocol("gost-relay: short domain"))?
                            as usize;
                        let d = payload
                            .get(2..2 + l)
                            .ok_or_else(|| Error::protocol("gost-relay: short domain bytes"))?;
                        // 1 length byte + the domain.
                        (
                            Host::Domain(String::from_utf8_lossy(d).into_owned()),
                            1 + l,
                        )
                    }
                    other => return Err(Error::protocol(format!("gost-relay: bad atyp {other:#x}"))),
                };
                let port = payload
                    .get(1 + used..1 + used + 2)
                    .map(|p| u16::from_be_bytes([p[0], p[1]]))
                    .ok_or_else(|| Error::protocol("gost-relay: short port"))?;
                target = Some(NetAddr::new(host, port));
            }
            RELAY_FEATURE_NETWORK => {
                if payload.len() != 2 {
                    return Err(Error::protocol("gost-relay: bad network feature"));
                }
                network = u16::from_be_bytes([payload[0], payload[1]]);
            }
            _ => {} // unknown features are skipped
        }
        off += 3 + plen;
    }
    Ok((command, target, network, auth))
}

/// `readRelayConnectResponse` (relay.go:354).
async fn read_relay_connect_response<S: AsyncRead + Unpin>(r: &mut S) -> Result<()> {
    let mut header = [0u8; 4];
    r.read_exact(&mut header).await?;
    if header[0] != RELAY_VERSION {
        return Err(Error::protocol(format!(
            "gost-relay: bad version: {}",
            header[0]
        )));
    }
    if header[1] != RELAY_STATUS_OK {
        return Err(Error::protocol(format!(
            "gost-relay: connect failed with status {:#04x} ({})",
            header[1],
            relay_status_text(header[1])
        )));
    }
    let feature_len = (usize::from(header[2]) << 8) | usize::from(header[3]);
    if feature_len == 0 {
        return Ok(());
    }
    let mut discard = vec![0u8; feature_len];
    r.read_exact(&mut discard).await?;
    Ok(())
}

/// `dialRelayServer` (relay.go:156): connect to the relay server (the
/// configured one, or the target address itself under `forward`),
/// optionally TLS.
async fn dial_relay_server(
    cfg: &GostRelayOut,
    transport: Option<BoxProxyStream>,
    fallback_target: Option<&NetAddr>,
) -> Result<BoxProxyStream> {
    // The integrator supplies the established TCP connection; when it
    // does not, this function has nothing to dial from.
    let mut conn = transport
        .ok_or_else(|| Error::config("gost-relay: no transport provided to the relay dialer"))?;
    if cfg.tls {
        let server_name = if !cfg.sni.is_empty() {
            cfg.sni.clone()
        } else if !cfg.server.is_empty() {
            cfg.server.clone()
        } else {
            fallback_target
                .map(|t| t.host.to_text())
                .unwrap_or_default()
        };
        if server_name.is_empty() {
            return Err(Error::config(
                "gost-relay: server-name is required when TLS is enabled",
            ));
        }
        let settings = TlsSettings {
            enabled: true,
            server_name: Some(server_name.clone()),
            skip_cert_verify: cfg.skip_cert_verify,
            alpn: Vec::new(),
        };
        conn = tls_connect(conn, &server_name, &settings).await?;
    }
    Ok(conn)
}

fn validate_cfg(cfg: &GostRelayOut) -> Result<()> {
    if cfg.server.is_empty() || cfg.port == 0 {
        return Err(Error::config(format!(
            "gost-relay {} requires a valid server and port",
            cfg.server
        )));
    }
    if cfg.mux {
        return Err(Error::config(
            "gost-relay: mux is not implemented: it wraps each dial in an smux session \
             (github.com/metacubex/smux — relay.go dialRelayServer: SYN/FIN/PSH/NPN/UPD \
             frames with per-stream receive windows), and no smux implementation exists \
             in this engine yet; configure mux: false",
        ));
    }
    Ok(())
}

/// `relayDialer.DialContext` (relay.go:85): CONNECT for TCP.
pub async fn connect(
    cfg: &GostRelayOut,
    transport: BoxProxyStream,
    target: &NetAddr,
) -> Result<BoxProxyStream> {
    validate_cfg(cfg)?;
    let mut conn = dial_relay_server(cfg, Some(transport), Some(target)).await?;
    let request_target = if cfg.forward { None } else { Some(target) };
    let request = build_relay_request(
        RELAY_CMD_CONNECT,
        request_target,
        RELAY_NETWORK_TCP,
        &cfg.username,
        &cfg.password,
    )?;
    conn.write_all(&request).await?;
    read_relay_connect_response(&mut conn).await?;
    Ok(conn)
}

/// The UDP association (`ListenPacket`, relay.go:117): CONNECT|0x80
/// with the network feature = UDP and the fixed peer as target.
/// Datagrams over the returned stream use [`relay_udp_frame`] /
/// [`read_relay_udp`]; the association is bound to `target` (the
/// server rejects writes to other destinations, relay.go:316).
pub async fn connect_udp(
    cfg: &GostRelayOut,
    transport: BoxProxyStream,
    target: &NetAddr,
) -> Result<BoxProxyStream> {
    validate_cfg(cfg)?;
    let mut conn = dial_relay_server(cfg, Some(transport), Some(target)).await?;
    let request_target = if cfg.forward { None } else { Some(target) };
    let request = build_relay_request(
        RELAY_CMD_CONNECT | RELAY_FLAG_UDP,
        request_target,
        RELAY_NETWORK_UDP,
        &cfg.username,
        &cfg.password,
    )?;
    conn.write_all(&request).await?;
    read_relay_connect_response(&mut conn).await?;
    Ok(conn)
}

/// `relayPacketConn.WriteTo` (relay.go:312): `len be16 || payload`.
pub fn relay_udp_frame(payload: &[u8]) -> Result<Vec<u8>> {
    if payload.len() > 0xFFFF {
        return Err(Error::protocol(format!(
            "gost-relay: udp packet too large: {}",
            payload.len()
        )));
    }
    let mut out = Vec::with_capacity(2 + payload.len());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// `relayPacketConn.ReadFrom` (relay.go:293): one framed datagram; the
/// sender is the association peer (no per-packet address on the wire).
pub async fn read_relay_udp<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    let packet_len = u16::from_be_bytes(header) as usize;
    let mut payload = vec![0u8; packet_len];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::DuplexStream;

    fn test_cfg(tls: bool) -> GostRelayOut {
        let mut cfg = GostRelayOut::new("relay.example", 8443);
        cfg.username = format!("user-{:016x}", rand::random::<u64>());
        cfg.password = format!("pass-{:016x}", rand::random::<u64>());
        cfg.tls = tls;
        cfg.skip_cert_verify = true;
        cfg.sni = "relay.example".into();
        cfg
    }

    #[test]
    fn request_layout_tcp_with_auth() {
        let target = NetAddr::domain("echo.example", 443).unwrap();
        let req = build_relay_request(RELAY_CMD_CONNECT, Some(&target), RELAY_NETWORK_TCP, "u", "p").unwrap();
        // Feature list: userauth (3+4) + addr (3+16, "echo.example") +
        // network (3+2) = 31.
        assert_eq!(&req[..4], &[0x01, 0x01, 0x00, 31]);
        // userauth feature payload: ulen u8 || user || plen u8 || pass.
        assert_eq!(&req[4..7], &[RELAY_FEATURE_USER_AUTH, 0x00, 4]);
        assert_eq!(&req[7..11], &[1, b'u', 1, b'p']);
        // The addr feature follows: type 0x02, payload length be16.
        assert_eq!(&req[11..14], &[RELAY_FEATURE_ADDR, 0x00, 16]);
        let (cmd, parsed_target, network, (user, pass)) = parse_relay_request(&req).unwrap();
        assert_eq!(cmd, RELAY_CMD_CONNECT);
        assert_eq!(parsed_target.as_ref().unwrap(), &target);
        assert_eq!(network, RELAY_NETWORK_TCP);
        assert_eq!((user.as_str(), pass.as_str()), ("u", "p"));
    }

    #[test]
    fn request_layout_udp_and_forward() {
        let target = NetAddr::ip("8.8.8.8".parse().unwrap(), 53);
        let req = build_relay_request(
            RELAY_CMD_CONNECT | RELAY_FLAG_UDP,
            Some(&target),
            RELAY_NETWORK_UDP,
            "",
            "",
        ).unwrap();
        let (cmd, parsed, network, auth) = parse_relay_request(&req).unwrap();
        assert_eq!(cmd, RELAY_CMD_CONNECT | RELAY_FLAG_UDP);
        assert_eq!(parsed.as_ref().unwrap(), &target);
        assert_eq!(network, RELAY_NETWORK_UDP);
        assert_eq!(auth, (String::new(), String::new()));
        // forward: no addr feature.
        let req = build_relay_request(RELAY_CMD_CONNECT, None, RELAY_NETWORK_TCP, "u", "p").unwrap();
        let (_, parsed, _, _) = parse_relay_request(&req).unwrap();
        assert!(parsed.is_none());
        // IPv6 target roundtrip.
        let v6 = NetAddr::ip("2001:db8::1".parse().unwrap(), 853);
        let req = build_relay_request(RELAY_CMD_CONNECT, Some(&v6), RELAY_NETWORK_TCP, "", "").unwrap();
        let (_, parsed, _, _) = parse_relay_request(&req).unwrap();
        assert_eq!(parsed.unwrap(), v6);
    }

    #[test]
    fn auth_length_limits() {
        let long = "x".repeat(256);
        assert!(encode_relay_user_auth(&long, "p").is_err());
        assert!(encode_relay_user_auth("u", &long).is_err());
        let long_host = NetAddr::new(Host::Domain("d".repeat(256)), 80);
        assert!(encode_relay_addr(&long_host).is_err());
        assert!(relay_udp_frame(&vec![0u8; 0x10000]).is_err());
        assert!(relay_udp_frame(&vec![0u8; 0xFFFF]).is_ok());
    }

    #[test]
    fn status_text_mapping() {
        assert_eq!(relay_status_text(0x00), "ok");
        assert_eq!(relay_status_text(0x02), "unauthorized");
        assert_eq!(relay_status_text(0x08), "internal server error");
        assert_eq!(relay_status_text(0x7f), "unknown");
    }

    /// The relay server mimic: parse the CONNECT, verify auth + target,
    /// reply status, then echo.
    async fn relay_server_mimic(
        mut io: DuplexStream,
        username: String,
        password: String,
        expect: Expect,
        status: u8,
    ) -> std::result::Result<(), String> {
        let mut head = [0u8; 4];
        io.read_exact(&mut head).await.map_err(|e| e.to_string())?;
        let flen = u16::from_be_bytes([head[2], head[3]]) as usize;
        let mut rest = vec![0u8; flen];
        io.read_exact(&mut rest).await.map_err(|e| e.to_string())?;
        let mut request = head.to_vec();
        request.extend_from_slice(&rest);
        let (cmd, target, network, (user, pass)) =
            parse_relay_request(&request).map_err(|e| e.to_string())?;
        if user != username || pass != password {
            let resp = [RELAY_VERSION, 0x02, 0, 0];
            io.write_all(&resp).await.map_err(|e| e.to_string())?;
            return Err("auth mismatch".into());
        }
        let udp = matches!(expect, Expect::Udp(_));
        match expect {
            Expect::Tcp(want) => {
                if cmd != RELAY_CMD_CONNECT || network != RELAY_NETWORK_TCP {
                    return Err(format!("bad command/network {cmd:#x}/{network}"));
                }
                if target.as_ref() != Some(&want) {
                    return Err(format!("target mismatch {target:?}"));
                }
            }
            Expect::Udp(want) => {
                if cmd != (RELAY_CMD_CONNECT | RELAY_FLAG_UDP) || network != RELAY_NETWORK_UDP {
                    return Err(format!("bad udp command/network {cmd:#x}/{network}"));
                }
                if target.as_ref() != Some(&want) {
                    return Err(format!("udp target mismatch {target:?}"));
                }
            }
        }
        let resp = [RELAY_VERSION, status, 0, 0];
        io.write_all(&resp).await.map_err(|e| e.to_string())?;
        if status != RELAY_STATUS_OK {
            return Ok(());
        }
        if udp {
            // Datagrams: echo three frames back.
            for _ in 0..3 {
                let payload = read_relay_udp(&mut io).await.map_err(|e| e.to_string())?;
                io.write_all(&relay_udp_frame(&payload).unwrap())
                    .await
                    .map_err(|e| e.to_string())?;
            }
            Ok(())
        } else {
            // TCP echo loop.
            let mut buf = [0u8; 4096];
            loop {
                let n = io.read(&mut buf).await.map_err(|e| e.to_string())?;
                if n == 0 {
                    return Ok(());
                }
                io.write_all(&buf[..n]).await.map_err(|e| e.to_string())?;
            }
        }
    }

    enum Expect {
        Tcp(NetAddr),
        Udp(NetAddr),
    }

    #[tokio::test]
    async fn tcp_connect_and_echo() {
        let cfg = test_cfg(false);
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (user, pass) = (cfg.username.clone(), cfg.password.clone());
        tokio::spawn(async move {
            if let Err(e) = relay_server_mimic(
                server,
                user,
                pass,
                Expect::Tcp(NetAddr::domain("echo.example", 443).unwrap()),
                RELAY_STATUS_OK,
            )
            .await
            {
                panic!("relay mimic failed: {e}");
            }
        });
        let target = NetAddr::domain("echo.example", 443).unwrap();
        let mut stream = connect(&cfg, Box::new(client), &target).await.unwrap();
        stream.write_all(b"ping-relay").await.unwrap();
        let mut buf = [0u8; 10];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"ping-relay");
    }

    #[tokio::test]
    async fn wrong_password_gets_unauthorized() {
        let cfg = test_cfg(false);
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (user, pass) = (cfg.username.clone(), format!("wrong-{}", cfg.password));
        tokio::spawn(async move {
            let _ = relay_server_mimic(
                server,
                user,
                pass,
                Expect::Tcp(NetAddr::domain("echo.example", 443).unwrap()),
                0x02,
            )
            .await;
        });
        let target = NetAddr::domain("echo.example", 443).unwrap();
        let err = match connect(&cfg, Box::new(client), &target).await {
            Ok(_) => panic!("a wrong password must fail"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("status 0x02"), "{err}");
        assert!(err.to_string().contains("unauthorized"), "{err}");
    }

    #[tokio::test]
    async fn server_error_status_surfaces() {
        let cfg = test_cfg(false);
        let (client, server) = tokio::io::duplex(16 * 1024);
        let (user, pass) = (cfg.username.clone(), cfg.password.clone());
        tokio::spawn(async move {
            let _ = relay_server_mimic(
                server,
                user,
                pass,
                Expect::Tcp(NetAddr::domain("echo.example", 443).unwrap()),
                0x05,
            )
            .await;
        });
        let target = NetAddr::domain("echo.example", 443).unwrap();
        let err = match connect(&cfg, Box::new(client), &target).await {
            Ok(_) => panic!("status 5 must fail"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("service unavailable"), "{err}");
    }

    #[tokio::test]
    async fn udp_association_datagrams() {
        let cfg = test_cfg(false);
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (user, pass) = (cfg.username.clone(), cfg.password.clone());
        tokio::spawn(async move {
            if let Err(e) = relay_server_mimic(
                server,
                user,
                pass,
                Expect::Udp(NetAddr::ip("8.8.8.8".parse().unwrap(), 53)),
                RELAY_STATUS_OK,
            )
            .await
            {
                panic!("udp mimic failed: {e}");
            }
        });
        let target = NetAddr::ip("8.8.8.8".parse().unwrap(), 53);
        let mut stream = connect_udp(&cfg, Box::new(client), &target).await.unwrap();
        for payload in [b"q1".to_vec(), b"query22".to_vec(), vec![7u8; 300]] {
            stream
                .write_all(&relay_udp_frame(&payload).unwrap())
                .await
                .unwrap();
            let got = read_relay_udp(&mut stream).await.unwrap();
            assert_eq!(got, payload);
        }
    }

    #[test]
    fn config_validation() {
        let mut cfg = test_cfg(false);
        assert!(validate_cfg(&cfg).is_ok());
        cfg.server.clear();
        assert!(validate_cfg(&cfg).unwrap_err().to_string().contains("server"));
        let mut cfg = test_cfg(false);
        cfg.port = 0;
        assert!(validate_cfg(&cfg).is_err());
        let mut cfg = test_cfg(false);
        cfg.mux = true;
        let err = validate_cfg(&cfg).unwrap_err().to_string();
        assert!(err.contains("smux"), "{err}");
        assert!(err.contains("mux: false"), "{err}");
    }
}
