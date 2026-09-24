//! DNS upstream transports: UDP, TCP, DoT (`tls://`), DoH (`https://`,
//! RFC 8484 over HTTP/1.1+TLS), DoQ (`quic://`, RFC 9250) and DoH3
//! (`h3://`). Each upstream is an enum value; the exchange loop tries
//! them in order with per-upstream timeouts.

use std::net::{IpAddr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpStream, UdpSocket};

use crate::error::{Error, Result};
use crate::transport::TlsSettings;

/// One configured upstream.
#[derive(Debug, Clone)]
pub enum Upstream {
    /// Plain UDP (the classic resolver).
    Udp(SocketAddr),
    /// DNS-over-TCP (length-framed wireformat).
    Tcp(SocketAddr),
    /// DNS-over-TLS: `tls://1.1.1.1[:853]` (RFC 7858).
    Tls { addr: SocketAddr, name: String },
    /// DNS-over-HTTPS: `https://host[:443]/path` (RFC 8484, HTTP/1.1).
    Https { addr: SocketAddr, name: String, path: String },
    /// DNS-over-QUIC: `quic://host[:853]` (RFC 9250, one stream/query).
    Doq { addr: SocketAddr, name: String },
    /// DNS-over-HTTP/3: `h3://host[:443]/path` (RFC 8484 over HTTP/3).
    H3 { addr: SocketAddr, name: String, path: String },
    /// The platform resolver: `/etc/resolv.conf` nameservers read at
    /// load (mihomo `system`, sing-box `local`).
    System { servers: Vec<SocketAddr> },
    /// DHCP-provided resolvers for an interface (mihomo `dhcp://en0`):
    /// parsed from dhclient/systemd-networkd lease files at load.
    Dhcp { servers: Vec<SocketAddr>, iface: String },
}

impl std::fmt::Display for Upstream {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Upstream::Udp(a) => write!(f, "udp://{a}"),
            Upstream::Tcp(a) => write!(f, "tcp://{a}"),
            Upstream::Tls { addr, .. } => write!(f, "tls://{addr}"),
            Upstream::Https { addr, .. } => write!(f, "https://{addr}"),
            Upstream::Doq { addr, .. } => write!(f, "quic://{addr}"),
            Upstream::H3 { addr, .. } => write!(f, "h3://{addr}"),
            Upstream::System { servers } => write!(f, "system://{}", servers.len()),
            Upstream::Dhcp { iface, .. } => write!(f, "dhcp://{iface}"),
        }
    }
}

const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(3);

impl Upstream {
    /// Exchange one wire-format query for one response. The caller has
    /// already synced the query id.
    pub async fn exchange(&self, query: &[u8]) -> Result<Vec<u8>> {
        match self {
            Upstream::Udp(addr) => Self::exchange_udp(*addr, query).await,
            Upstream::Tcp(addr) => Self::exchange_tcp_stream(*addr, query).await,
            Upstream::Tls { addr, name } => {
                let tcp = TcpStream::connect(addr)
                    .await
                    .map_err(|e| Error::dns(format!("dot connect: {e}")))?;
                let tls = crate::transport::tls_connect(
                    Box::new(tcp),
                    name,
                    &TlsSettings::client(name),
                )
                .await?;
                Self::exchange_tls_stream(tls, query).await
            }
            Upstream::Https { addr, name, path } => {
                Self::exchange_https(*addr, name, path, query).await
            }
            Upstream::Doq { addr, name } => Self::exchange_doq(*addr, name, query).await,
            Upstream::H3 { addr, name, path } => {
                Self::exchange_h3(*addr, name, path, query).await
            }
            Upstream::System { servers } | Upstream::Dhcp { servers, .. } => {
                // The platform/DHCP resolvers are plain UDP servers.
                let mut last = Err(Error::dns("no platform resolvers configured"));
                for addr in servers {
                    match Self::exchange_udp(*addr, query).await {
                        Ok(resp) => return Ok(resp),
                        Err(e) => last = Err(e),
                    }
                }
                last
            }
        }
    }

    /// RFC 9250: one bidirectional stream per query, 2-byte length
    /// framing identical to DoT, message id 0 on the wire.
    async fn exchange_doq(addr: SocketAddr, name: &str, query: &[u8]) -> Result<Vec<u8>> {
        let conn = crate::quic::dial(&crate::quic::QuicDial {
            server: addr.ip().to_string(),
            port: addr.port(),
            sni: name.to_string(),
            alpn: vec!["doq".to_string()],
            skip_verify: false,
            udp_relay: false,
            congestion_brutal_bps: None,
        })
        .await?;
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| Error::dns(format!("doq open stream: {e}")))?;
        let mut framed = Vec::with_capacity(query.len() + 2);
        let len = u16::try_from(query.len()).map_err(|_| Error::dns("doq query too large"))?;
        framed.extend_from_slice(&len.to_be_bytes());
        framed.extend_from_slice(query);
        send.write_all(&framed)
            .await
            .map_err(|e| Error::dns(format!("doq write: {e}")))?;
        send.finish()
            .map_err(|e| Error::dns(format!("doq finish: {e}")))?;

        let res = tokio::time::timeout(EXCHANGE_TIMEOUT, async {
            let mut len_buf = [0u8; 2];
            recv.read_exact(&mut len_buf)
                .await
                .map_err(|e| Error::dns(format!("doq read len: {e}")))?;
            let n = u16::from_be_bytes(len_buf) as usize;
            if !(12..=65535).contains(&n) {
                return Err(Error::dns("doq: bad framed length"));
            }
            let mut resp = vec![0u8; n];
            recv.read_exact(&mut resp)
                .await
                .map_err(|e| Error::dns(format!("doq read body: {e}")))?;
            Ok(resp)
        })
        .await
        .map_err(|_| Error::dns("doq timeout"))?;
        conn.close(0u32.into(), b"done");
        res
    }

    /// RFC 8484 over HTTP/3: control/QPACK streams, then a POST with the
    /// wire query as the body; the response DATA frames carry the answer.
    async fn exchange_h3(
        addr: SocketAddr,
        name: &str,
        path: &str,
        query: &[u8],
    ) -> Result<Vec<u8>> {
        let conn = crate::quic::dial(&crate::quic::QuicDial {
            server: addr.ip().to_string(),
            port: addr.port(),
            sni: name.to_string(),
            alpn: vec!["h3".to_string()],
            skip_verify: false,
            udp_relay: false,
            congestion_brutal_bps: None,
        })
        .await?;
        // Control + QPACK streams must stay open for the connection's
        // lifetime (closing them is a fatal HTTP/3 error).
        let control = crate::quic::h3_open_control(&conn, "doh3").await?;

        let mut head = Vec::with_capacity(256);
        {
            let mut fields = Vec::with_capacity(192);
            // QPACK field section prefix: required insert count 0, base 0.
            fields.extend_from_slice(&[0x00, 0x00]);
            let authority = if addr.port() == 443 {
                name.to_string()
            } else {
                format!("{name}:{}", addr.port())
            };
            crate::quic::put_qpack_literal(&mut fields, b":method", b"POST");
            crate::quic::put_qpack_literal(&mut fields, b":scheme", b"https");
            crate::quic::put_qpack_literal(&mut fields, b":authority", authority.as_bytes());
            crate::quic::put_qpack_literal(&mut fields, b":path", path.as_bytes());
            crate::quic::put_qpack_literal(
                &mut fields,
                b"content-type",
                b"application/dns-message",
            );
            crate::quic::put_qpack_literal(&mut fields, b"accept", b"application/dns-message");
            crate::quic::put_h3_frame(&mut head, crate::quic::H3_HEADERS, &fields);
            crate::quic::put_h3_frame(&mut head, crate::quic::H3_DATA, query);
        }
        let (mut send, mut recv) = conn
            .open_bi()
            .await
            .map_err(|e| Error::dns(format!("doh3 open stream: {e}")))?;
        send.write_all(&head)
            .await
            .map_err(|e| Error::dns(format!("doh3 write: {e}")))?;
        send.finish()
            .map_err(|e| Error::dns(format!("doh3 finish: {e}")))?;

        let res = tokio::time::timeout(EXCHANGE_TIMEOUT, async {
            let body = crate::quic::h3_read_data(&mut recv, "doh3").await?;
            if body.len() < 12 {
                return Err(Error::dns("doh3: short or missing body"));
            }
            Ok(body)
        })
        .await
        .map_err(|_| Error::dns("doh3 timeout"))?;
        drop(control);
        conn.close(0u32.into(), b"done");
        res
    }

    async fn exchange_udp(addr: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
        let bind = if addr.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
        let socket = UdpSocket::bind(bind).await.map_err(|e| Error::dns(e.to_string()))?;
        socket.send_to(query, addr).await.map_err(|e| Error::dns(e.to_string()))?;
        let mut buf = vec![0u8; 4096];
        let (n, _) = tokio::time::timeout(EXCHANGE_TIMEOUT, socket.recv_from(&mut buf))
            .await
            .map_err(|_| Error::dns("timeout"))?
            .map_err(|e| Error::dns(e.to_string()))?;
        if n < 12 {
            return Err(Error::dns("short response"));
        }
        if buf[0..2] != query[0..2] {
            return Err(Error::dns("id mismatch"));
        }
        Ok(buf[..n].to_vec())
    }

    /// Length-framed wireformat over a plain TCP stream.
    async fn exchange_tcp_stream(addr: SocketAddr, query: &[u8]) -> Result<Vec<u8>> {
        let mut stream = TcpStream::connect(addr)
            .await
            .map_err(|e| Error::dns(format!("dns-tcp connect: {e}")))?;
        Self::write_framed(&mut stream, query).await?;
        Self::read_framed(&mut stream).await
    }

    async fn exchange_tls_stream(mut stream: crate::stream::BoxProxyStream, query: &[u8]) -> Result<Vec<u8>> {
        Self::write_framed(&mut stream, query).await?;
        Self::read_framed(&mut stream).await
    }

    async fn write_framed<S: AsyncWriteExt + Unpin>(stream: &mut S, query: &[u8]) -> Result<()> {
        let len = u16::try_from(query.len()).map_err(|_| Error::dns("query too large"))?;
        stream
            .write_all(&len.to_be_bytes())
            .await
            .map_err(|e| Error::dns(e.to_string()))?;
        stream
            .write_all(query)
            .await
            .map_err(|e| Error::dns(e.to_string()))?;
        Ok(())
    }

    async fn read_framed<S: AsyncReadExt + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
        let mut len = [0u8; 2];
        tokio::time::timeout(EXCHANGE_TIMEOUT, stream.read_exact(&mut len))
            .await
            .map_err(|_| Error::dns("timeout"))?
            .map_err(|e| Error::dns(e.to_string()))?;
        let n = u16::from_be_bytes(len) as usize;
        if !(12..=65535).contains(&n) {
            return Err(Error::dns("bad framed length"));
        }
        let mut resp = vec![0u8; n];
        tokio::time::timeout(EXCHANGE_TIMEOUT, stream.read_exact(&mut resp))
            .await
            .map_err(|_| Error::dns("timeout"))?
            .map_err(|e| Error::dns(e.to_string()))?;
        Ok(resp)
    }

    /// RFC 8484 over HTTP/1.1: POST application/dns-message, same TLS
    /// stack as the proxy outbounds (rustls). One connection per exchange
    /// (HTTP/1.1 keep-alive pooling is future work).
    async fn exchange_https(
        addr: SocketAddr,
        name: &str,
        path: &str,
        query: &[u8],
    ) -> Result<Vec<u8>> {
        let tcp = TcpStream::connect(addr)
            .await
            .map_err(|e| Error::dns(format!("doh connect: {e}")))?;
        let mut tls = crate::transport::tls_connect(Box::new(tcp), name, &TlsSettings::client(name)).await?;
        let path = if path.starts_with('/') {
            path.to_string()
        } else {
            format!("/{path}")
        };
        let req = format!(
            "POST {path} HTTP/1.1\r\nHost: {name}\r\nContent-Type: application/dns-message\r\n\
             Accept: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            query.len()
        );
        tls.write_all(req.as_bytes()).await.map_err(|e| Error::dns(e.to_string()))?;
        tls.write_all(query).await.map_err(|e| Error::dns(e.to_string()))?;
        tls.flush().await.map_err(|e| Error::dns(e.to_string()))?;

        // Read the whole response, then split headers/body.
        let mut raw = Vec::with_capacity(1024);
        let mut chunk = [0u8; 4096];
        loop {
            let n = tokio::time::timeout(EXCHANGE_TIMEOUT, tls.read(&mut chunk))
                .await
                .map_err(|_| Error::dns("doh timeout"))?
                .map_err(|e| Error::dns(e.to_string()))?;
            if n == 0 {
                break;
            }
            raw.extend_from_slice(&chunk[..n]);
            if raw.len() > 64 * 1024 {
                return Err(Error::dns("doh response too large"));
            }
        }
        Self::extract_http_body(&raw)
    }

    /// Minimal HTTP/1.1 response split: find the blank line, then the
    /// body (Content-Length or to-EOF; chunked is rejected).
    fn extract_http_body(raw: &[u8]) -> Result<Vec<u8>> {
        let split = raw
            .windows(4)
            .position(|w| w == b"\r\n\r\n")
            .ok_or_else(|| Error::dns("doh: no header terminator"))?;
        let head = String::from_utf8_lossy(&raw[..split]);
        let status = head
            .lines()
            .next()
            .and_then(|l| l.split_whitespace().nth(1))
            .and_then(|c| c.parse::<u16>().ok())
            .unwrap_or(0);
        if !(200..300).contains(&status) {
            return Err(Error::dns(format!("doh: HTTP {status}")));
        }
        let body = &raw[split + 4..];
        let chunked = head
            .lines()
            .any(|l| l.to_ascii_lowercase().starts_with("transfer-encoding: chunked"));
        if chunked {
            return Self::dechunk(body);
        }
        Ok(body.to_vec())
    }

    /// Decode a chunked body: repeat (hex-size CRLF data CRLF) until the
    /// zero-size terminator chunk.
    fn dechunk(body: &[u8]) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        let mut rest = body;
        loop {
            let line_end = rest
                .windows(2)
                .position(|w| w == b"\r\n")
                .ok_or_else(|| Error::dns("doh: bad chunk header"))?;
            let size_line = std::str::from_utf8(&rest[..line_end])
                .map_err(|_| Error::dns("doh: chunk size"))?;
            // Chunk extensions after ';' are legal and ignored.
            let hex = size_line.split(';').next().unwrap_or("").trim();
            let size = usize::from_str_radix(hex, 16)
                .map_err(|_| Error::dns("doh: chunk size"))?;
            if size == 0 {
                return Ok(out);
            }
            rest = &rest[line_end + 2..];
            if rest.len() < size {
                return Err(Error::dns("doh: short chunk"));
            }
            out.extend_from_slice(&rest[..size]);
            rest = &rest[size..];
            if rest.starts_with(b"\r\n") {
                rest = &rest[2..];
            }
        }
    }
}

/// Parse a nameserver spec into an upstream.
///
/// Accepted: `1.1.1.1`, `udp://1.1.1.1[:53]`, `tcp://1.1.1.1[:53]`,
/// `tls://1.1.1.1[:853]` (name defaults to the IP), `tls://dns.google`,
/// `https://1.1.1.1/dns-query`, `https://dns.google/dns-query`.
pub fn parse_upstream(ns: &str) -> Option<Upstream> {
    // Scheme-less platform keywords (mihomo `system`, sing-box `local`).
    match ns {
        "system" | "local" => {
            let servers = resolv_conf_nameservers();
            return (!servers.is_empty()).then_some(Upstream::System { servers });
        }
        _ => {}
    }
    let (scheme, rest) = ns.split_once("://").unwrap_or(("", ns));
    match scheme {
        // Hostnames resolve once at load, like mihomo's defaults.
        "" | "udp" => {
            let (_host, addr) = parse_host_addr(rest, 53)?;
            Some(Upstream::Udp(addr))
        }
        "tcp" => {
            let (_host, addr) = parse_host_addr(rest, 53)?;
            Some(Upstream::Tcp(addr))
        }
        "tls" => {
            let (host, addr) = parse_host_addr(rest, 853)?;
            Some(Upstream::Tls {
                addr,
                name: host,
            })
        }
        "https" => {
            // Strip an optional port, then take the path.
            let (authority, path) = match rest.find('/') {
                Some(i) => (&rest[..i], &rest[i..]),
                None => (rest, "/dns-query"),
            };
            let (host, addr) = parse_host_addr(authority, 443)?;
            Some(Upstream::Https {
                addr,
                name: host,
                path: path.to_string(),
            })
        }
        // DNS-over-QUIC (RFC 9250) — mihomo/sing-box also spell it `doq`.
        "quic" | "doq" => {
            let (host, addr) = parse_host_addr(rest, 853)?;
            Some(Upstream::Doq { addr, name: host })
        }
        // DNS-over-HTTP/3 (RFC 8484 over HTTP/3).
        "h3" => {
            let (authority, path) = match rest.find('/') {
                Some(i) => (&rest[..i], &rest[i..]),
                None => (rest, "/dns-query"),
            };
            let (host, addr) = parse_host_addr(authority, 443)?;
            Some(Upstream::H3 {
                addr,
                name: host,
                path: path.to_string(),
            })
        }
        // The platform resolver (mihomo `system`, sing-box `local`).
        "system" | "local" => {
            let servers = resolv_conf_nameservers();
            if servers.is_empty() {
                return None;
            }
            Some(Upstream::System { servers })
        }
        // DHCP-provided resolvers for an interface (mihomo `dhcp://en0`;
        // an empty interface auto-detects the default-route one).
        "dhcp" => {
            let iface = if rest.is_empty() || rest == "auto" {
                default_route_iface()?
            } else {
                rest.to_string()
            };
            let servers = dhcp_lease_nameservers(&iface);
            if servers.is_empty() {
                return None;
            }
            Some(Upstream::Dhcp { servers, iface })
        }
        _ => None,
    }
}

/// `1.2.3.4[:port]` or `[v6][:port]` with a default port.
/// Nameservers from `/etc/resolv.conf` (system/local upstreams).
fn resolv_conf_nameservers() -> Vec<SocketAddr> {
    let Ok(text) = std::fs::read_to_string("/etc/resolv.conf") else {
        return Vec::new();
    };
    parse_resolv_conf(&text)
}

fn parse_resolv_conf(text: &str) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        let Some(rest) = line.strip_prefix("nameserver") else {
            continue;
        };
        let token = rest.trim();
        if let Ok(ip) = token.parse::<IpAddr>() {
            out.push(SocketAddr::new(ip, 53));
        }
    }
    out
}

/// Default-route interface from /proc/net/route (iface autodetect).
fn default_route_iface() -> Option<String> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    parse_default_route_iface(&text)
}

fn parse_default_route_iface(text: &str) -> Option<String> {
    for line in text.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        // iface destination gateway flags ... — destination 00000000 with
        // the RTF_UP+RTF_GATEWAY flags marks the default route.
        if cols.len() < 4 || cols[1] != "00000000" {
            continue;
        }
        let flags = u32::from_str_radix(cols[3], 16).unwrap_or(0);
        if flags & 0x3 == 0x3 {
            return Some(cols[0].to_string());
        }
    }
    None
}

/// DHCP-provided resolvers for an interface: dhclient lease files and
/// systemd-networkd leases (mihomo's `dhcp://` behavior).
fn dhcp_lease_nameservers(iface: &str) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    // systemd-networkd: /run/systemd/netif/leases/<idx> with a DNS= line.
    if let Ok(entries) = std::fs::read_dir("/run/systemd/netif/leases") {
        for e in entries.flatten() {
            let Ok(text) = std::fs::read_to_string(e.path()) else {
                continue;
            };
            out.extend(parse_systemd_lease_dns(&text, iface));
        }
    }
    // dhclient: /var/lib/dhcp/dhclient.<iface>.leases (+ the generic one).
    for path in [
        format!("/var/lib/dhcp/dhclient.{iface}.leases"),
        "/var/lib/dhcp/dhclient.leases".to_string(),
    ] {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        out.extend(parse_dhclient_lease_dns(&text));
    }
    out.dedup();
    out
}

/// `DNS=` lines from a systemd-networkd lease for `iface` (the file
/// carries an `IFACE=` key).
fn parse_systemd_lease_dns(text: &str, iface: &str) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    if !text.lines().any(|l| l.trim() == format!("IFACE={iface}")) {
        return out;
    }
    for line in text.lines() {
        if let Some(rest) = line.trim().strip_prefix("DNS=") {
            for tok in rest.split_whitespace() {
                if let Ok(ip) = tok.parse::<IpAddr>() {
                    out.push(SocketAddr::new(ip, 53));
                }
            }
        }
    }
    out
}

/// `option domain-name-servers a.b.c.d[, e.f.g.h];` from a dhclient lease.
fn parse_dhclient_lease_dns(text: &str) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("option domain-name-servers") else {
            continue;
        };
        for tok in rest.trim_end_matches(';').split(',') {
            if let Ok(ip) = tok.trim().parse::<IpAddr>() {
                out.push(SocketAddr::new(ip, 53));
            }
        }
    }
    out
}

/// A host (IP or name) plus the resolved socket address; IPs skip DNS
/// bootstrapping, names resolve via the system resolver at parse time
/// (once — mihomo does the same for its default resolvers).
fn parse_host_addr(s: &str, default_port: u16) -> Option<(String, SocketAddr)> {
    // Bracketed v6.
    if let Some(rest) = s.strip_prefix('[') {
        let (v6, port) = rest.split_once(']')?;
        let port = port
            .strip_prefix(':')
            .map(|p| p.parse().ok())
            .unwrap_or(Some(default_port))?;
        let ip: IpAddr = v6.parse().ok()?;
        return Some((v6.to_string(), SocketAddr::new(ip, port)));
    }
    // Bare IP literal (IPv6 has colons — must precede the port split).
    if let Ok(ip) = s.parse::<IpAddr>() {
        return Some((s.to_string(), SocketAddr::new(ip, default_port)));
    }
    if let Some((host, port)) = s.rsplit_once(':') {
        if let Ok(port) = port.parse::<u16>() {
            return resolve_once(host, port);
        }
    }
    resolve_once(s, default_port)
}

fn resolve_once(host: &str, port: u16) -> Option<(String, SocketAddr)> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some((host.to_string(), SocketAddr::new(ip, port)));
    }
    // Blocking resolve is acceptable at config load (parse_upstream runs
    // once per nameserver, before the async engine starts).
    let addr = std::net::ToSocketAddrs::to_socket_addrs(&(host, port)).ok()?.next()?;
    Some((host.to_string(), addr))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn upstream_parsing() {
        assert!(matches!(
            parse_upstream("1.1.1.1"),
            Some(Upstream::Udp(a)) if a.port() == 53
        ));
        assert!(matches!(
            parse_upstream("udp://1.1.1.1:5353"),
            Some(Upstream::Udp(a)) if a.port() == 5353
        ));
        assert!(matches!(
            parse_upstream("tcp://1.1.1.1"),
            Some(Upstream::Tcp(a)) if a.port() == 53
        ));
        match parse_upstream("tls://1.1.1.1") {
            Some(Upstream::Tls { addr, name }) => {
                assert_eq!(addr.port(), 853);
                assert_eq!(name, "1.1.1.1");
            }
            other => panic!("bad tls parse: {other:?}"),
        }
        match parse_upstream("https://1.1.1.1/dns-query") {
            Some(Upstream::Https { addr, name, path }) => {
                assert_eq!(addr.port(), 443);
                assert_eq!(name, "1.1.1.1");
                assert_eq!(path, "/dns-query");
            }
            other => panic!("bad https parse: {other:?}"),
        }
        // Path defaults to /dns-query.
        match parse_upstream("https://1.1.1.1") {
            Some(Upstream::Https { path, .. }) => assert_eq!(path, "/dns-query"),
            other => panic!("bad https parse: {other:?}"),
        }
        // DoQ: quic:// (mihomo/sing-box spelling) and doq://.
        match parse_upstream("quic://1.1.1.1") {
            Some(Upstream::Doq { addr, name }) => {
                assert_eq!(addr.port(), 853);
                assert_eq!(name, "1.1.1.1");
            }
            other => panic!("bad quic parse: {other:?}"),
        }
        match parse_upstream("doq://dns.adguard-dns.com:8853") {
            Some(Upstream::Doq { addr, name }) => {
                assert_eq!(addr.port(), 8853);
                assert_eq!(name, "dns.adguard-dns.com");
            }
            other => panic!("bad doq parse: {other:?}"),
        }
        // DoH3.
        match parse_upstream("h3://1.1.1.1/dns-query") {
            Some(Upstream::H3 { addr, name, path }) => {
                assert_eq!(addr.port(), 443);
                assert_eq!(name, "1.1.1.1");
                assert_eq!(path, "/dns-query");
            }
            other => panic!("bad h3 parse: {other:?}"),
        }
        match parse_upstream("h3://1.1.1.1") {
            Some(Upstream::H3 { path, .. }) => assert_eq!(path, "/dns-query"),
            other => panic!("bad h3 parse: {other:?}"),
        }
        // Platform keywords parse only when the platform provides
        // resolvers/leases (environment-dependent outside tests, so only
        // the scheme-less bare-host path is asserted here).
        assert!(parse_upstream("frobnicate://x").is_none());
    }

    #[test]
    fn platform_resolver_parsers() {
        // resolv.conf: nameserver lines, comments and other keys ignored.
        let rc = "# generated\nnameserver 127.0.0.53\nsearch lan\nnameserver 192.0.2.1 # up\n";
        let ns = parse_resolv_conf(rc);
        assert_eq!(ns.len(), 2);
        assert_eq!(ns[0].to_string(), "127.0.0.53:53");
        assert_eq!(ns[1].to_string(), "192.0.2.1:53");

        // /proc/net/route: the default route is dest 00000000 with
        // UP|GATEWAY flags (0x3).
        let routes = "Iface\tDestination\tGateway\t\tFlags\tRefCnt\tUse\tMetric\tMask\n\
eth0\t00000000\t0102A8C0\t\t0003\t\t0\t0\t100\t00000000\n\
eth1\t0002A8C0\t00000000\t\t0001\t\t0\t0\t0\t00FFFFFF\n";
        assert_eq!(parse_default_route_iface(routes).as_deref(), Some("eth0"));

        // systemd-networkd lease: DNS= only for the matching IFACE.
        let lease = "IFACE=eth0\nADDRESS=192.0.2.10\nDNS=192.0.2.53 192.0.2.54\n";
        let dns = parse_systemd_lease_dns(lease, "eth0");
        assert_eq!(dns.len(), 2);
        assert!(parse_systemd_lease_dns(lease, "eth1").is_empty());

        // dhclient lease.
        let dh = "lease {\n  option domain-name-servers 192.0.2.1, 192.0.2.2;\n}\n";
        assert_eq!(parse_dhclient_lease_dns(dh).len(), 2);
    }

    #[test]
    fn h3_request_frame_layout() {
        // Build a minimal DoH3 request and re-parse the frames by hand.
        let mut head = Vec::new();
        let mut fields = Vec::new();
        fields.extend_from_slice(&[0x00, 0x00]);
        crate::quic::put_qpack_literal(&mut fields, b":method", b"POST");
        crate::quic::put_h3_frame(&mut head, crate::quic::H3_HEADERS, &fields);
        crate::quic::put_h3_frame(&mut head, crate::quic::H3_DATA, b"DNSQUERY");
        // HEADERS: type 0x01, length = fields.len().
        assert_eq!(head[0], 0x01);
        assert_eq!(head[1] as usize, fields.len());
        let data_off = 2 + fields.len();
        assert_eq!(head[data_off], 0x00);
        assert_eq!(head[data_off + 1] as usize, 8);
        assert_eq!(&head[data_off + 2..], b"DNSQUERY");
        // QPACK literal name len 7 == the 3-bit prefix max, so RFC 7541
        // §5.1 needs the two-byte form: 0x27 then remainder 0x00.
        assert_eq!(fields[2], 0x27);
        assert_eq!(fields[3], 0x00);
        assert_eq!(&fields[4..11], b":method");
        assert_eq!(fields[11], 0x04); // value length 4, no Huffman
        assert_eq!(&fields[12..16], b"POST");
    }

    #[test]
    fn doh_body_extraction() {
        let resp = b"HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\n\r\nDNSBODY";
        assert_eq!(
            Upstream::extract_http_body(resp).unwrap(),
            b"DNSBODY".to_vec()
        );
        let chunked = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nDNSBODY1\r\n0\r\n\r\n";
        assert_eq!(
            Upstream::extract_http_body(chunked).unwrap(),
            b"DNSBODY1".to_vec()
        );
        let err = Upstream::extract_http_body(b"HTTP/1.1 500 Oops\r\n\r\nx").unwrap_err();
        assert!(err.to_string().contains("500"));
    }
}
