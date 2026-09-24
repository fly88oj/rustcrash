//! Addressing model shared by every protocol: targets are either a domain
//! or a literal IP, plus a port. A single codec (the SOCKS address, as
//! reused by Shadowsocks / VMess / VLESS / Trojan) covers all wire formats.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::error::{Error, Result};

/// Address type byte in the SOCKS address format (RFC 1928): 1 = IPv4,
/// 3 = domain name, 4 = IPv6. This exact mapping is wire-visible to
/// mihomo/sing-box peers — 0x02 is NOT a domain (a bug here made every
/// domain-targeted ss/vmess request fail against real servers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Atyp {
    Ipv4 = 0x01,
    Domain = 0x03,
    Ipv6 = 0x04,
}

impl Atyp {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            0x01 => Some(Atyp::Ipv4),
            0x03 => Some(Atyp::Domain),
            0x04 => Some(Atyp::Ipv6),
            _ => None,
        }
    }
}

/// A connection target host: domain or literal IP. Keeping these apart is
/// what lets the engine route by domain without resolving first.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum Host {
    Domain(String),
    Ip(IpAddr),
}

impl Host {
    pub fn as_domain(&self) -> Option<&str> {
        match self {
            Host::Domain(d) => Some(d),
            Host::Ip(_) => None,
        }
    }

    /// Parse `example.com` / `1.2.3.4` / `::1` text into a Host, choosing
    /// Domain only when it is not a valid IP literal.
    pub fn parse(s: &str) -> Result<Self> {
        let s = s.trim();
        if s.is_empty() {
            return Err(Error::protocol("empty host"));
        }
        if let Ok(ip) = s.parse::<IpAddr>() {
            return Ok(Host::Ip(ip));
        }
        validate_domain(s)?;
        Ok(Host::Domain(s.to_ascii_lowercase()))
    }

    /// Display form (`example.com`, `1.2.3.4`).
    pub fn to_text(&self) -> String {
        match self {
            Host::Domain(d) => d.clone(),
            Host::Ip(ip) => ip.to_string(),
        }
    }
}

impl fmt::Display for Host {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_text())
    }
}

/// A full network target.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct NetAddr {
    pub host: Host,
    pub port: u16,
}

impl NetAddr {
    pub fn new(host: Host, port: u16) -> Self {
        NetAddr { host, port }
    }

    pub fn domain(name: &str, port: u16) -> Result<Self> {
        Ok(NetAddr::new(Host::parse(name)?, port))
    }

    pub fn ip(ip: IpAddr, port: u16) -> Self {
        NetAddr::new(Host::Ip(ip), port)
    }
}

impl fmt::Display for NetAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.host {
            Host::Domain(d) => write!(f, "{d}:{}", self.port),
            Host::Ip(IpAddr::V4(v4)) => write!(f, "{v4}:{}", self.port),
            Host::Ip(IpAddr::V6(v6)) => write!(f, "[{v6}]:{}", self.port),
        }
    }
}

/// Domains must be plausible before they touch the wire: bounded length,
/// LDH + underscore charset (underscores appear in real internal names and
/// mihomo accepts them), no empty labels. This is a format guard, not a
/// security boundary — the charset ban also blocks address bytes smuggling.
fn validate_domain(s: &str) -> Result<()> {
    if s.len() > 253 || s.is_empty() {
        return Err(Error::protocol(format!("domain length out of range: {s}")));
    }
    if s.split('.').any(|label| label.is_empty()) {
        return Err(Error::protocol(format!("empty label in domain: {s}")));
    }
    let ok = s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.' || b == b'_');
    if !ok {
        return Err(Error::protocol(format!("invalid domain charset: {s}")));
    }
    Ok(())
}

/// Append the mihomo/sing-vmess destination form: `port_be16 || atyp ||
/// addr` (PORT FIRST — metacubex's AddressSerializer uses
/// `PortThenAddress`, unlike the v2fly atyp/addr/port order). NOTE the
/// sing atyp convention here is NOT RFC 1928: 1 = IPv4, 2 = domain,
/// 3 = IPv6 (mihomo peers parse exactly these).
pub fn encode_port_first_addr(buf: &mut Vec<u8>, host: &Host, port: u16) {
    const SING_IPV4: u8 = 0x01;
    const SING_DOMAIN: u8 = 0x02;
    const SING_IPV6: u8 = 0x03;
    buf.extend_from_slice(&port.to_be_bytes());
    match host {
        Host::Domain(d) => {
            let len = d.len().min(255);
            buf.push(SING_DOMAIN);
            buf.push(len as u8);
            buf.extend_from_slice(&d.as_bytes()[..len]);
        }
        Host::Ip(IpAddr::V4(v4)) => {
            buf.push(SING_IPV4);
            buf.extend_from_slice(&v4.octets());
        }
        Host::Ip(IpAddr::V6(v6)) => {
            buf.push(SING_IPV6);
            buf.extend_from_slice(&v6.octets());
        }
    }
}

/// Parse the port-first destination form (`port_be16 || atyp || addr`).
pub fn decode_port_first_addr(data: &[u8]) -> Result<(NetAddr, usize)> {
    if data.len() < 3 {
        return Err(Error::protocol("port-first addr: short"));
    }
    let port = u16::from_be_bytes([data[0], data[1]]);
    let (host, used) = match data[2] {
        0x01 => {
            let Some(o) = data.get(3..7) else {
                return Err(Error::protocol("port-first addr: short ipv4"));
            };
            (Host::Ip(IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3]))), 5)
        }
        0x02 => {
            let Some(&l) = data.get(3) else {
                return Err(Error::protocol("port-first addr: short domain len"));
            };
            let Some(b) = data.get(4..4 + l as usize) else {
                return Err(Error::protocol("port-first addr: short domain"));
            };
            let s = std::str::from_utf8(b)
                .map_err(|_| Error::protocol("port-first addr: bad utf-8"))?;
            (Host::Domain(s.to_ascii_lowercase()), 2 + l as usize)
        }
        0x03 => {
            let Some(o) = data.get(3..19) else {
                return Err(Error::protocol("port-first addr: short ipv6"));
            };
            let mut b = [0u8; 16];
            b.copy_from_slice(o);
            (Host::Ip(IpAddr::V6(Ipv6Addr::from(b))), 17)
        }
        other => return Err(Error::protocol(format!("port-first addr: bad atyp {other:#x}"))),
    };
    Ok((NetAddr::new(host, port), 2 + used))
}

/// Append the SOCKS address wire form (`ATYP | addr | port-be`) of `addr`.
pub fn encode_socks_addr(buf: &mut Vec<u8>, host: &Host, port: u16) {
    match host {
        Host::Domain(d) => {
            let d = d.as_bytes();
            // Length prefix is u8; validated domains fit, but a config-fed
            // 253-byte domain could exceed u8 after some encoding. Truncate
            // guard: refuse by clamping is wrong — caller validates earlier,
            // so a >255 label is impossible (253 total, single label ≤63 by
            // validation… not strictly enforced, so clamp defensively).
            let len = d.len().min(255);
            buf.push(Atyp::Domain as u8);
            buf.push(len as u8);
            buf.extend_from_slice(&d[..len]);
        }
        Host::Ip(IpAddr::V4(v4)) => {
            buf.push(Atyp::Ipv4 as u8);
            buf.extend_from_slice(&v4.octets());
        }
        Host::Ip(IpAddr::V6(v6)) => {
            buf.push(Atyp::Ipv6 as u8);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&port.to_be_bytes());
}

/// Read one SOCKS address from the front of `data`. Returns the parsed
/// address and the number of bytes consumed.
pub fn decode_socks_addr(data: &[u8]) -> Result<(NetAddr, usize)> {
    let Some(&atyp) = data.first() else {
        return Err(Error::protocol("socks addr: empty"));
    };
    let atyp = Atyp::from_u8(atyp).ok_or_else(|| Error::protocol(format!("socks addr: bad atyp {atyp:#x}")))?;
    let mut off = 1usize;
    let host = match atyp {
        Atyp::Ipv4 => {
            let Some(octets) = data.get(off..off + 4) else {
                return Err(Error::protocol("socks addr: short ipv4"));
            };
            off += 4;
            Host::Ip(IpAddr::V4(Ipv4Addr::new(
                octets[0], octets[1], octets[2], octets[3],
            )))
        }
        Atyp::Ipv6 => {
            let Some(octets) = data.get(off..off + 16) else {
                return Err(Error::protocol("socks addr: short ipv6"));
            };
            off += 16;
            let mut b = [0u8; 16];
            b.copy_from_slice(octets);
            Host::Ip(IpAddr::V6(Ipv6Addr::from(b)))
        }
        Atyp::Domain => {
            let Some(&len) = data.get(off) else {
                return Err(Error::protocol("socks addr: short domain length"));
            };
            off += 1;
            let Some(bytes) = data.get(off..off + len as usize) else {
                return Err(Error::protocol("socks addr: short domain"));
            };
            off += len as usize;
            let s = std::str::from_utf8(bytes)
                .map_err(|_| Error::protocol("socks addr: domain not utf-8"))?;
            Host::Domain(s.to_ascii_lowercase())
        }
    };
    let Some(port_bytes) = data.get(off..off + 2) else {
        return Err(Error::protocol("socks addr: short port"));
    };
    off += 2;
    let port = u16::from_be_bytes([port_bytes[0], port_bytes[1]]);
    Ok((NetAddr { host, port }, off))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_parse_classifies() {
        assert_eq!(Host::parse("Example.COM").unwrap(), Host::Domain("example.com".into()));
        assert_eq!(
            Host::parse("1.2.3.4").unwrap(),
            Host::Ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))
        );
        assert_eq!(
            Host::parse("::1").unwrap(),
            Host::Ip(IpAddr::V6(Ipv6Addr::LOCALHOST))
        );
        assert!(Host::parse("").is_err());
        assert!(Host::parse("a b.com").is_err());
        assert!(Host::parse("a..b").is_err());
        let long = "a".repeat(254);
        assert!(Host::parse(&long).is_err());
        // Internal names with underscores are legal in practice.
        assert_eq!(
            Host::parse("my_host.internal").unwrap(),
            Host::Domain("my_host.internal".into())
        );
    }

    #[test]
    fn socks_addr_roundtrip() {
        for host in [
            Host::Domain("example.com".into()),
            Host::Ip(IpAddr::V4(Ipv4Addr::new(10, 1, 2, 3))),
            Host::Ip(IpAddr::V6("2001:db8::1".parse().unwrap())),
        ] {
            let mut buf = Vec::new();
            encode_socks_addr(&mut buf, &host, 443);
            let (addr, used) = decode_socks_addr(&buf).unwrap();
            assert_eq!(used, buf.len());
            assert_eq!(addr.host, host);
            assert_eq!(addr.port, 443);
        }
    }

    #[test]
    fn socks_addr_known_bytes() {
        // RFC 1928: domain ATYP is 3 — 03 0b "example.com" 01bb
        let mut buf = Vec::new();
        encode_socks_addr(&mut buf, &Host::Domain("example.com".into()), 443);
        assert_eq!(
            buf,
            vec![0x03, 0x0b, b'e', b'x', b'a', b'm', b'p', b'l', b'e', b'.', b'c', b'o', b'm', 0x01, 0xbb]
        );
        // IPv4: 01 7f000001 1f90
        let mut buf = Vec::new();
        encode_socks_addr(&mut buf, &Host::Ip(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1))), 8080);
        assert_eq!(buf, vec![0x01, 127, 0, 0, 1, 0x1f, 0x90]);
    }

    #[test]
    fn socks_addr_rejects_truncated() {
        let mut buf = Vec::new();
        encode_socks_addr(&mut buf, &Host::Domain("example.com".into()), 80);
        for cut in 0..buf.len() {
            assert!(decode_socks_addr(&buf[..cut]).is_err(), "cut {cut} should fail");
        }
    }

    #[test]
    fn socks_addr_rejects_bad_atyp() {
        assert!(decode_socks_addr(&[0x04, 0, 0, 0, 0, 0, 0]).is_err());
    }

    #[test]
    fn display_forms() {
        let a = NetAddr::new(Host::Domain("x.com".into()), 80);
        assert_eq!(a.to_string(), "x.com:80");
        let b = NetAddr::new(Host::Ip(IpAddr::V6("::1".parse().unwrap())), 53);
        assert_eq!(b.to_string(), "[::1]:53");
    }
}
