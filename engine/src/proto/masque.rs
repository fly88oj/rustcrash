//! MASQUE outbound (the mihomo `masque` proxy type): a Cloudflare
//! Access / WARP-flavoured client — HTTP/3 over QUIC with **ECDSA client
//! certificate authentication** (the enrolled `private-key` signs a
//! fresh self-signed certificate) and **server public-key pinning** (the
//! `public-key` must equal the peer certificate's ECDSA public key).
//!
//! Upstream sources (mihomo Alpha):
//! * `adapter/outbound/masque.go` — `MasqueOption` fields, key parsing,
//!   mode selection, the run/start loops and the TUN device plumbing.
//! * `transport/masque/masque.go` — `ConnectSNI`/`ConnectURI`,
//!   `PrepareTlsConfig` (client cert + pin), `GenerateCert`,
//!   `ConnectTunnel` (extended CONNECT `:protocol cf-connect-ip`,
//!   SETTINGS 0x276, `Capsule-Protocol: ?1`) and `dialEx`.
//! * `transport/masque/l4proxy.go` — the L4 client: one shared H3
//!   connection, per-target **plain** CONNECT (no `:protocol`),
//!   `L4ConnectSNI`.
//! * `transport/masque/client_h2.go` — the h2 capsule DATAGRAM codec
//!   (capsule type 0 over a byte stream) and the IPv4 TTL/checksum
//!   datagram composition; the TCP+HTTP/2 transport itself is out of
//!   scope (rejected with a precise error in [`MasqueClient::connect`]).
//! * `github.com/metacubex/connect-ip-go` (`conn.go`, `capsule.go`) —
//!   the CONNECT-IP session: capsules ADDRESS_ASSIGN(1)/
//!   ADDRESS_REQUEST(2)/ROUTE_ADVERTISEMENT(3) on the request stream,
//!   IP packets as QUIC datagrams prefixed with context id 0, inbound
//!   source/destination validation, close via stream cancel with
//!   `H3_NO_ERROR` (0x100).
//!
//! # What the upstream wire actually is (read before changing anything)
//!
//! * **ALPN**: `h3` (`http3.NextProtoH3`, transport/masque/masque.go:71).
//!   There is no `masque` ALPN. The `h2` network mode uses ALPN `h2`
//!   over TCP (masque.go:181).
//! * **TCP**: in `network: h3-l4proxy` mode, upstream opens one H3
//!   request stream per target and sends a **plain CONNECT**
//!   (`:method CONNECT` + `:authority host:port`, no `:path`, no
//!   `:scheme`, no `:protocol` — quic-go `http3/request_writer.go:85,
//!   123-131`), then relays DATA frames. This port implements exactly
//!   that ([`MasqueClient::dial_tcp`]).
//! * **The L3 tunnel is CONNECT-IP, not CONNECT-UDP**: upstream dials an
//!   extended CONNECT with `:protocol` = **`cf-connect-ip`** —
//!   Cloudflare's non-RFC-compliant variant of RFC 9484 CONNECT-IP
//!   (masque.go:129) — and **ignores** the server's
//!   `SETTINGS_ENABLE_CONNECT_PROTOCOL` (`ignoreExtendedConnect=true`,
//!   masque.go:129/189) while still requiring the datagram setting
//!   (masque.go:192). RFC 9298 CONNECT-udp contexts / REGISTER / CLOSE
//!   capsules are **not** used anywhere in upstream mihomo masque; the
//!   only CLOSE on the wire is the QUIC stream cancel with
//!   `H3_NO_ERROR` (connect-ip-go conn.go:420-430).
//! * **SETTINGS/capsule negotiation**: the client sends HTTP/3 SETTINGS
//!   `0x276 = 1` (draft-ietf-masque-h3-datagram-00, deprecated but what
//!   the official client still sends, masque.go:110-118) — this port
//!   also sends `0x33 = 1` (RFC 9220 `SETTINGS_H3_DATAGRAM`) — plus the
//!   `Capsule-Protocol: ?1` request header (RFC 9297 structured field
//!   boolean). UDP payloads are proxied as whole **IP packets** inside
//!   context-0 QUIC datagrams.
//! * **The ECDSA keypair's role**: TLS client-certificate authentication
//!   (Cloudflare Access device enrollment). `private-key` (base64 SEC1
//!   EC private key, `x509.ParseECPrivateKey`, masque.go:136-143) signs
//!   a generated self-signed X.509 certificate (`GenerateCert`,
//!   masque.go:93-104: empty subject, serial 0, 24h validity) presented
//!   as the client cert; `public-key` (base64 PKIX SPKI ECDSA,
//!   masque.go:145-156) pins the server: every peer certificate's
//!   public key must equal it (`PrepareTlsConfig`'s `verfiyCert`,
//!   masque.go:38-91, chain validation skipped via InsecureSkipVerify).
//!   `skip-cert-verify` drops the pin entirely (masque.go:86-88).
//!
//! # Scope of this port
//!
//! * TCP: the `h3-l4proxy` data plane (plain H3 CONNECT per target).
//!   The default (`Tun`) mode tunnels TCP through a local TUN device +
//!   userspace IP stack (`newIPStack`, masque.go:239); that device is
//!   not wired into the engine, so `dial_tcp` there rejects with a
//!   precise error (see [`MasqueClient::dial_tcp`]).
//! * UDP: the CONNECT-IP tunnel with **in-process IP/UDP synthesis** —
//!   the exact datagram format upstream's TUN device produces (context-0
//!   datagrams, TTL decrement, checksum fixup), minus the kernel
//!   interface. Requires `ip`/`ipv6` config ([`prefixes`]).
//! * `network: h2` (HTTP/2 CONNECT-IP over TLS) is rejected: it needs a
//!   full HTTP/2 client; only its capsule codec is ported
//!   ([`h2_datagram_capsule`]).
//! * `ip-stack: gvisor` is rejected like a non-with_gvisor build
//!   (wireguard.go:159-162); `congestion-controller`/`cwnd`/
//!   `bbr-profile` are carried but quinn has no Brutal/BBR3 — the
//!   transport keeps its default controller (same note as
//!   [`crate::quic::QuicDial::congestion_brutal_bps`]).
//! * `remote-dns-resolve`/`dns` are carried for the integrator: upstream
//!   builds a resolver routed through this proxy (masque.go:252-264);
//!   the engine's DNS wiring happens at the outbound/config layer.
//! * The ICMP-too-large return of `WritePacket` (conn.go:366-374) needs
//!   the TUN device — a too-large datagram surfaces as a send error.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};
use std::time::{Duration, SystemTime};

use bytes::{Buf, Bytes, BytesMut};
use ring::signature::KeyPair as _;
use rand::Rng;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::Mutex;
use tracing::{debug, warn};

use crate::addr::{Host, NetAddr};
use crate::error::{Error, Result};
use crate::quic::{self, read_varint, write_varint};
use crate::stream::BoxProxyStream;

// ---------------------------------------------------------------------------
// Upstream constants
// ---------------------------------------------------------------------------

/// `ConnectSNI` (transport/masque/masque.go:26).
pub const CONNECT_SNI: &str = "consumer-masque.cloudflareclient.com";
/// `L4ConnectSNI` (transport/masque/l4proxy.go:18).
pub const L4_CONNECT_SNI: &str = "consumer-masque-proxy.cloudflareclient.com";
/// `ConnectURI` (transport/masque/masque.go:27).
pub const CONNECT_URI: &str = "https://cloudflareaccess.com";
/// The extended-CONNECT `:protocol` (masque.go:129 — Cloudflare's
/// variant, not the RFC 9484 `connect-ip` token).
pub const CONNECT_IP_PROTOCOL: &str = "cf-connect-ip";
/// `http3.NextProtoH3`.
pub const ALPN_H3: &str = "h3";
/// The `Capsule-Protocol` header name; its value is `?1` (masque.go:196).
pub const CAPSULE_PROTOCOL_HEADER: &str = "capsule-protocol";

/// HTTP/3 frame types (RFC 9114 §7.2).
const H3_FRAME_DATA: u64 = 0x0;
const H3_FRAME_HEADERS: u64 = 0x1;
const H3_FRAME_SETTINGS: u64 = 0x4;
/// Uni-stream types (RFC 9114 §6.2).
const H3_STREAM_CONTROL: u8 = 0x0;
const H3_STREAM_QPACK_ENCODER: u8 = 0x2;
const H3_STREAM_QPACK_DECODER: u8 = 0x3;
/// `SETTINGS_H3_DATAGRAM_00` = 0x276 (draft-ietf-masque-h3-datagram-00;
/// sent as an AdditionalSetting by upstream, masque.go:110-118).
pub const SETTINGS_H3_DATAGRAM_DRAFT00: u64 = 0x276;
/// RFC 9220 `SETTINGS_H3_DATAGRAM` = 0x33.
pub const SETTINGS_H3_DATAGRAM: u64 = 0x33;
/// `http3.ErrCodeNoError` — the stream error code of `Conn.Close`
/// (connect-ip-go conn.go:427).
pub const H3_NO_ERROR: u64 = 0x100;

/// CONNECT-IP capsule types (connect-ip-go capsule.go:15-17).
pub const CAPSULE_ADDRESS_ASSIGN: u64 = 1;
pub const CAPSULE_ADDRESS_REQUEST: u64 = 2;
pub const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 3;
/// The h2 capsule DATAGRAM type (client_h2.go:24).
pub const H2_DATAGRAM_CAPSULE: u64 = 0;

/// Upstream `mtu` default (adapter/outbound/masque.go:218-221).
pub const DEFAULT_MTU: u32 = 1280;
/// `ipv4HeaderLen` / `ipv6HeaderLen` (client_h2.go:27-29).
const IPV4_HEADER_LEN: usize = 20;
const IPV6_HEADER_LEN: usize = 40;
/// IP protocol numbers (conn.go:38-40 and the UDP data plane).
const IP_PROTO_ICMP: u8 = 1;
const IP_PROTO_ICMPV6: u8 = 58;
const IP_PROTO_UDP: u8 = 17;

// ---------------------------------------------------------------------------
// Configuration (adapter/outbound/masque.go:53-79 MasqueOption)
// ---------------------------------------------------------------------------

/// `IPStackOption` (adapter/outbound/wireguard.go:143-172): YAML map with
/// `mode` (`auto`/`gvisor`/`mips`) and `congestion-controller`
/// (`cubic`/`reno`/`bbr`/`bbr3`).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IpStackOption {
    pub mode: String,
    pub congestion_controller: String,
}

impl IpStackOption {
    /// `normalize` (wireguard.go:148-154): lowercase + default `auto`.
    pub fn normalize(&mut self) {
        self.mode = self.mode.to_lowercase();
        if self.mode.is_empty() {
            self.mode = "auto".into();
        }
        self.congestion_controller = self.congestion_controller.to_lowercase();
    }

    /// `validate` (wireguard.go:156-172) with the exact upstream error
    /// strings. `gvisor` additionally needs the (Go-only) gVisor
    /// netstack, so it is rejected here like a non-with_gvisor build.
    pub fn validate(&self) -> Result<()> {
        match self.mode.as_str() {
            "auto" | "mips" => {}
            "gvisor" => {
                return Err(Error::config(
                    "gVisor IP stack requires the with_gvisor build tag",
                ))
            }
            other => {
                return Err(Error::config(format!(
                    "invalid IP stack mode {other:?}; expected auto, gvisor, or mips"
                )))
            }
        }
        match self.congestion_controller.as_str() {
            "" | "cubic" | "reno" | "bbr" | "bbr3" => Ok(()),
            other => Err(Error::config(format!(
                "invalid IP stack congestion controller {other:?}; expected cubic, reno, bbr, or bbr3"
            ))),
        }
    }
}

/// The runtime mode selected by `network` (masque.go:158,180,231).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MasqueMode {
    /// `network` empty (upstream default): the TUN/CONNECT-IP path.
    Tun,
    /// `network: h3-l4proxy`: the per-target plain-CONNECT client.
    L4Proxy,
}

/// mihomo `MasqueOption` (adapter/outbound/masque.go:53-79). Every
/// upstream field is carried; the YAML tag names are in the doc
/// comments for the config integrator.
#[derive(Debug, Clone, Default)]
pub struct MasqueOption {
    /// `server`
    pub server: String,
    /// `port`
    pub port: u16,
    /// `private-key`: base64 (std) DER of a SEC1 EC private key
    /// (`x509.ParseECPrivateKey`).
    pub private_key: String,
    /// `public-key`: base64 (std) DER of a PKIX SubjectPublicKeyInfo
    /// holding an ECDSA public key (`x509.ParsePKIXPublicKey`).
    pub public_key: String,
    /// `ip`: local IPv4 (optionally `addr/prefix`); defaults to /32.
    pub ip: String,
    /// `ipv6`: local IPv6 (optionally `addr/prefix`); defaults to /128.
    pub ipv6: String,
    /// `uri`: the CONNECT target (default `https://cloudflareaccess.com`).
    pub uri: String,
    /// `sni`
    pub sni: String,
    /// `mtu` (0 → 1280)
    pub mtu: u32,
    /// `udp`
    pub udp: bool,
    /// `handshake-timeout` in seconds (non-negative; the YAML layer must
    /// reject negatives with "masque handshake timeout must be
    /// non-negative", masque.go:110-112).
    pub handshake_timeout: u64,
    /// `skip-cert-verify`
    pub skip_cert_verify: bool,
    /// `name-cert-verify`: placeholder — upstream never verifies
    /// certificate names for MASQUE (masque.go:68 comment).
    pub name_cert_verify: String,
    /// `network`: "" | "h3-l4proxy" | "h2"
    pub network: String,
    /// `congestion-controller` (carried; see the module scope notes)
    pub congestion_controller: String,
    /// `cwnd`
    pub cwnd: i64,
    /// `bbr-profile`
    pub bbr_profile: String,
    /// `ip-stack` map
    pub ip_stack: IpStackOption,
    /// `remote-dns-resolve`: integrator hook (see module scope notes)
    pub remote_dns_resolve: bool,
    /// `dns`: nameserver URLs for that resolver
    pub dns: Vec<String>,
}

/// A parsed `ip`/`ipv6` prefix (`netip.Prefix`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpPrefix {
    pub addr: IpAddr,
    pub bits: u8,
}

impl IpPrefix {
    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                let bits = u32::from(self.bits).min(32);
                let mask = if bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - bits)
                };
                (u32::from(net) & mask) == (u32::from(addr) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                let bits = u32::from(self.bits).min(128);
                let mask = if bits == 0 {
                    0
                } else {
                    u128::MAX << (128 - bits)
                };
                (u128::from(net) & mask) == (u128::from(addr) & mask)
            }
            _ => false,
        }
    }
}

/// `MasqueOption.Prefixes` (masque.go:81-107): bare addresses get /32
/// (v4) or /128 (v6); upstream error strings preserved.
pub fn prefixes(option: &MasqueOption) -> Result<Vec<IpPrefix>> {
    let mut local_prefixes = Vec::new();
    let mut parse = |s: &str, what: &str| -> Result<()> {
        if s.is_empty() {
            return Ok(());
        }
        let s = if s.contains('/') {
            s.to_string()
        } else {
            format!("{s}/{}", if what == "ipv6" { 128 } else { 32 })
        };
        let (addr, bits) = s
            .split_once('/')
            .ok_or_else(|| Error::config(format!("{what} address parse error: no prefix")))?;
        let addr: IpAddr = addr
            .parse()
            .map_err(|e| Error::config(format!("{what} address parse error: {e}")))?;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        let bits: u8 = bits
            .parse()
            .map_err(|e| Error::config(format!("{what} address parse error: {e}")))?;
        if bits > max {
            return Err(Error::config(format!(
                "{what} address parse error: prefix length out of range"
            )));
        }
        local_prefixes.push(IpPrefix { addr, bits });
        Ok(())
    };
    parse(&option.ip, "ip")?;
    parse(&option.ipv6, "ipv6")?;
    if local_prefixes.is_empty() {
        return Err(Error::config("missing local address"));
    }
    Ok(local_prefixes)
}

impl MasqueOption {
    /// `IPStack.normalize()` + `validate()` (masque.go:113-116).
    pub fn validate_ip_stack(&mut self) -> Result<()> {
        self.ip_stack.normalize();
        self.ip_stack.validate()
    }

    /// The effective SNI (masque.go:166-172).
    pub fn effective_sni(&self, mode: MasqueMode) -> String {
        if !self.sni.is_empty() {
            return self.sni.clone();
        }
        match mode {
            MasqueMode::Tun => CONNECT_SNI.to_string(),
            MasqueMode::L4Proxy => L4_CONNECT_SNI.to_string(),
        }
    }

    /// The effective URI (masque.go:160-164).
    pub fn effective_uri(&self) -> String {
        if self.uri.is_empty() {
            CONNECT_URI.to_string()
        } else {
            self.uri.clone()
        }
    }

    /// The effective MTU (masque.go:218-221).
    pub fn effective_mtu(&self) -> u32 {
        if self.mtu == 0 {
            DEFAULT_MTU
        } else {
            self.mtu
        }
    }
}

/// Split the connect URI into `(authority, path)` — the pieces quic-go
/// puts in `:authority` and `:path` (an empty path becomes "/", matching
/// `http3/request_writer.go`'s default; the port-less authority stays
/// port-less, unlike the h2 transport's `:443` append, client_h2.go:128).
pub fn uri_authority_path(uri: &str) -> Result<(String, String)> {
    let rest = uri.split_once("://").map(|(_, rest)| rest).unwrap_or(uri);
    let (authority, path) = match rest.find(['/', '?', '#']) {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, ""),
    };
    if authority.is_empty() {
        return Err(Error::config(format!(
            "connect-ip: failed to parse URI: {uri}"
        )));
    }
    let path = if path.is_empty() { "/" } else { path };
    Ok((authority.to_string(), path.to_string()))
}

// ---------------------------------------------------------------------------
// Minimal DER (the SEC1/PKIX/X.509 pieces GenerateCert and the pin need)
// ---------------------------------------------------------------------------

mod der {
    //! Tiny DER TLV reader/writer — just enough for SEC1 EC keys, PKIX
    //! SPKI walks and the self-signed certificate of `GenerateCert`
    //! (masque.go:93-104). The engine carries no ASN.1 dependency.

    /// Read one TLV at the front of `data`; returns `(tag, content)`.
    pub fn tlv(data: &[u8]) -> Option<(u8, &[u8])> {
        let (&tag, rest) = data.split_first()?;
        let (len, header_len): (usize, usize) = match rest.first()? {
            &l if l < 0x80 => (l as usize, 1),
            0x81 => (usize::from(*rest.get(1)?), 2),
            0x82 => {
                let b1 = *rest.get(1)?;
                let b2 = *rest.get(2)?;
                (usize::from(u16::from_be_bytes([b1, b2])), 3)
            }
            _ => return None,
        };
        let content = rest.get(header_len..header_len + len)?;
        Some((tag, content))
    }

    /// Total bytes of a TLV with a `content_len`-byte payload.
    pub fn tlv_len(content_len: usize) -> usize {
        if content_len < 0x80 {
            content_len + 2
        } else if content_len <= 0xff {
            content_len + 3
        } else {
            content_len + 4
        }
    }

    /// Wrap `content` in a TLV with DER length encoding.
    pub fn put_tlv(out: &mut Vec<u8>, tag: u8, content: &[u8]) {
        out.push(tag);
        if content.len() < 0x80 {
            out.push(content.len() as u8);
        } else if content.len() <= 0xff {
            out.push(0x81);
            out.push(content.len() as u8);
        } else {
            out.push(0x82);
            out.extend_from_slice(&(content.len() as u16).to_be_bytes());
        }
        out.extend_from_slice(content);
    }

    pub fn seq(parts: &[&[u8]]) -> Vec<u8> {
        let mut body = Vec::new();
        for p in parts {
            body.extend_from_slice(p);
        }
        let mut out = Vec::new();
        put_tlv(&mut out, 0x30, &body);
        out
    }

    /// DER INTEGER from a non-negative magnitude (adds the sign byte).
    pub fn uint(mut v: Vec<u8>) -> Vec<u8> {
        while v.len() > 1 && v[0] == 0 {
            v.remove(0);
        }
        if v.first().is_some_and(|&b| b & 0x80 != 0) {
            v.insert(0, 0);
        }
        let mut out = Vec::new();
        if v.is_empty() {
            out.extend_from_slice(&[0x02, 0x01, 0x00]);
        } else {
            put_tlv(&mut out, 0x02, &v);
        }
        out
    }

    /// OID from dotted decimals (X.690 §8.19 base-128 big-endian per
    /// component; the first two arcs are combined as `arc0*40 + arc1`).
    pub fn oid(parts: &[u64]) -> Vec<u8> {
        let mut body = Vec::new();
        push_base128(&mut body, parts[0] * 40 + parts[1]);
        for &p in &parts[2..] {
            push_base128(&mut body, p);
        }
        let mut out = Vec::new();
        put_tlv(&mut out, 0x06, &body);
        out
    }

    /// One base-128 component: 7-bit groups, most significant first, with
    /// the continuation bit set on every byte except the last.
    fn push_base128(out: &mut Vec<u8>, mut v: u64) {
        let mut stack = [0u8; 10];
        let mut n = 0;
        loop {
            stack[n] = (v & 0x7f) as u8;
            n += 1;
            v >>= 7;
            if v == 0 {
                break;
            }
        }
        for i in (0..n).rev() {
            out.push(if i == 0 { stack[i] } else { stack[i] | 0x80 });
        }
    }

    /// BIT STRING with zero unused bits.
    pub fn bitstring(content: &[u8]) -> Vec<u8> {
        let mut body = vec![0u8];
        body.extend_from_slice(content);
        let mut out = Vec::new();
        put_tlv(&mut out, 0x03, &body);
        out
    }

    /// UTCTime `YYMMDDHHMMSSZ` (Go's pre-2050 format).
    pub fn utctime(t: std::time::SystemTime) -> Vec<u8> {
        // days since epoch → civil date (Howard Hinnant's algorithm).
        let secs = t
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let days = (secs / 86_400) as i64;
        let rem = secs % 86_400;
        let (h, mi, s) = (rem / 3600, (rem / 60) % 60, rem % 60);
        let z = days + 719_468;
        let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
        let doe = z - era * 146_097;
        let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
        let y = yoe + era * 400;
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
        let mp = (5 * doy + 2) / 153;
        let d = doy - (153 * mp + 2) / 5 + 1;
        let m = if mp < 10 { mp + 3 } else { mp - 9 };
        let y = if m <= 2 { y + 1 } else { y };
        let text = format!("{:02}{:02}{:02}{:02}{:02}{:02}Z", y % 100, m, d, h, mi, s);
        let mut out = Vec::new();
        put_tlv(&mut out, 0x17, text.as_bytes());
        out
    }
}

// ---------------------------------------------------------------------------
// Key parsing + certificate generation (masque.go:93-156)
// ---------------------------------------------------------------------------

/// A parsed PKIX ECDSA public key: curve OID bytes + uncompressed point.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EcdsaPublicKey {
    pub curve_oid: Vec<u8>,
    /// The BIT STRING content (uncompressed EC point, leading 0x04).
    pub point: Vec<u8>,
}

fn bad_key(msg: &str) -> Error {
    Error::config(format!("failed to parse public key: {msg}"))
}

/// `x509.ParsePKIXPublicKey` restricted to ECDSA: SPKI =
/// `SEQ{ SEQ{ OID ecPublicKey, OID curve }, BIT STRING point }`
/// (masque.go:145-156).
pub fn parse_spki_ecdsa_public_key(der: &[u8]) -> Result<EcdsaPublicKey> {
    let (tag, spki) = der::tlv(der).ok_or_else(|| bad_key("malformed SPKI"))?;
    if tag != 0x30 {
        return Err(bad_key("SPKI is not a SEQUENCE"));
    }
    let (tag, alg) = der::tlv(spki).ok_or_else(|| bad_key("malformed SPKI algorithm"))?;
    if tag != 0x30 {
        return Err(bad_key("SPKI algorithm is not a SEQUENCE"));
    }
    // 1.2.840.10045.2.1 id-ecPublicKey
    const EC_OID: [u8; 7] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
    let (tag, ec_oid) = der::tlv(alg).ok_or_else(|| bad_key("malformed SPKI algorithm"))?;
    if tag != 0x06 || ec_oid != EC_OID {
        return Err(Error::config("failed to assert public key as ECDSA"));
    }
    let rest = &alg[der::tlv_len(ec_oid.len())..];
    let (tag, curve_oid) = der::tlv(rest).ok_or_else(|| bad_key("malformed SPKI curve"))?;
    if tag != 0x06 {
        return Err(bad_key("malformed SPKI curve"));
    }
    let rest = &spki[der::tlv_len(alg.len())..];
    let (tag, point) = der::tlv(rest).ok_or_else(|| bad_key("malformed SPKI point"))?;
    if tag != 0x03 || point.first() != Some(&0) {
        return Err(bad_key("malformed SPKI point"));
    }
    Ok(EcdsaPublicKey {
        curve_oid: curve_oid.to_vec(),
        point: point[1..].to_vec(),
    })
}

/// A parsed SEC1 EC private key (`x509.ParseECPrivateKey`): P-256 only
/// (the ring backend has no P-384/521 signing), rewrapped as PKCS#8 for
/// rustls/ring.
#[derive(Debug, Clone)]
pub struct EcPrivateKey {
    /// PKCS#8 PrivateKeyInfo DER wrapping the original SEC1 blob.
    pub pkcs8: Vec<u8>,
}

/// `x509.ParseECPrivateKey` (masque.go:140): the SEC1 struct is
/// `SEQ{ INTEGER 1, OCTET STRING scalar, [0] OID curve, [1] pub (opt) }`;
/// the curve OID must be prime256v1 for this port.
pub fn parse_ec_private_key(der: &[u8]) -> Result<EcPrivateKey> {
    let (_, body) = der::tlv(der)
        .filter(|(t, _)| *t == 0x30)
        .ok_or_else(|| Error::config("failed to parse private key: not a SEQUENCE"))?;
    let mut rest = body;
    let (t, v) = der::tlv(rest).ok_or_else(|| bad_priv("version"))?;
    if t != 0x02 || v != [1] {
        return Err(bad_priv("version"));
    }
    rest = &rest[der::tlv_len(v.len())..];
    let (t, scalar) = der::tlv(rest).ok_or_else(|| bad_priv("private key"))?;
    if t != 0x04 || scalar.len() != 32 {
        return Err(bad_priv("private key"));
    }
    rest = &rest[der::tlv_len(scalar.len())..];
    // optional [0] curve OID — must be prime256v1 (1.2.840.10045.3.1.7).
    const P256_OID: [u8; 8] = [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
    let curve_ok = match der::tlv(rest) {
        Some((0xa0, inner)) => match der::tlv(inner) {
            Some((0x06, oid)) => oid == P256_OID,
            _ => false,
        },
        _ => false,
    };
    if !curve_ok {
        return Err(Error::config(
            "failed to parse private key: only P-256 EC keys are supported",
        ));
    }
    // PKCS#8 wrap: SEQ{ INTEGER 0, SEQ{ ecPublicKey, prime256v1 },
    // OCTET STRING <original SEC1 DER> } — the inner blob is reused
    // verbatim so any [1] public-key element survives.
    let alg = der::seq(&[
        &der::oid(&[1, 2, 840, 10045, 2, 1]),
        &der::oid(&[1, 2, 840, 10045, 3, 1, 7]),
    ]);
    let mut octet = Vec::new();
    der::put_tlv(&mut octet, 0x04, der);
    let pkcs8 = der::seq(&[&der::uint(vec![0]), &alg, &octet]);
    Ok(EcPrivateKey { pkcs8 })
}

fn bad_priv(field: &str) -> Error {
    Error::config(format!("failed to parse private key: malformed {field}"))
}

/// OID 1.2.840.10045.4.3.2 (ecdsa-with-SHA256) — the algorithm Go picks
/// for a P-256 key in `CreateCertificate`.
fn algid_ecdsa_sha256() -> Vec<u8> {
    der::seq(&[&der::oid(&[1, 2, 840, 10045, 4, 3, 2]), &[0x05, 0x00]])
}

/// `GenerateCert` (masque.go:93-104): a self-signed certificate with
/// serial 0, empty subject/issuer, 24h validity, signed by the given key.
/// Go's `x509.Certificate.Version` zero value means **v3**, so the TBS
/// carries the explicit `[0] INTEGER 2` version element. Returns the
/// certificate DER.
pub fn generate_client_cert(key: &EcPrivateKey) -> Result<Vec<u8>> {
    let rng = ring::rand::SystemRandom::new();
    let pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
        &key.pkcs8,
        &rng,
    )
    .map_err(|e| Error::config(format!("failed to generate cert: {e}")))?;
    let public = pair.public_key().as_ref().to_vec(); // 0x04 ‖ X ‖ Y

    let spki = der::seq(&[
        &der::seq(&[
            &der::oid(&[1, 2, 840, 10045, 2, 1]),
            &der::oid(&[1, 2, 840, 10045, 3, 1, 7]),
        ]),
        &der::bitstring(&public),
    ]);
    let now = SystemTime::now();
    let validity = der::seq(&[
        &der::utctime(now),
        &der::utctime(now + Duration::from_secs(86_400)),
    ]);
    let sig_alg = algid_ecdsa_sha256();
    // tbsCertificate version [0] EXPLICIT INTEGER 2 (v3, RFC 5280 §4.1).
    let mut version = Vec::new();
    der::put_tlv(&mut version, 0xa0, &der::uint(vec![2]));
    let tbs = der::seq(&[
        &version,
        &der::uint(vec![0]), // serial 0 (template big.NewInt(0))
        &sig_alg,
        &der::seq(&[]), // issuer: empty Name
        &validity,
        &der::seq(&[]), // subject: empty Name
        &spki,
    ]);
    let sig = pair
        .sign(&rng, &tbs)
        .map_err(|e| Error::config(format!("failed to generate cert: {e}")))?;
    // ring gives 64 fixed R‖S; X.509 wants ASN.1 SEQUENCE{r,s}.
    let (r, s) = sig.as_ref().split_at(32);
    let sig_der = der::seq(&[&der::uint(r.to_vec()), &der::uint(s.to_vec())]);
    Ok(der::seq(&[&tbs, &sig_alg, &der::bitstring(&sig_der)]))
}

// ---------------------------------------------------------------------------
// TLS: client cert + server public key pin (masque.go:38-91)
// ---------------------------------------------------------------------------

/// Extract the ECDSA SPKI from a certificate DER: walk the TBS
/// top-level elements and return the first SEQUENCE that parses as an
/// EC SPKI (the walk is structural — versions/extensions tolerated).
pub fn cert_spki(cert: &[u8]) -> Result<EcdsaPublicKey> {
    let (_, cert_body) = der::tlv(cert)
        .filter(|(t, _)| *t == 0x30)
        .ok_or_else(|| Error::protocol("malformed certificate"))?;
    let (_, tbs) = der::tlv(cert_body)
        .filter(|(t, _)| *t == 0x30)
        .ok_or_else(|| Error::protocol("malformed certificate TBS"))?;
    let mut rest = tbs;
    while !rest.is_empty() {
        let Some((t, field)) = der::tlv(rest) else {
            break;
        };
        if t == 0x30 {
            let mut candidate = Vec::new();
            der::put_tlv(&mut candidate, 0x30, field);
            if let Ok(key) = parse_spki_ecdsa_public_key(&candidate) {
                return Ok(key);
            }
        }
        rest = &rest[der::tlv_len(field.len())..];
    }
    Err(Error::protocol("no SubjectPublicKeyInfo in certificate"))
}

/// `PrepareTlsConfig`'s pin verifier (masque.go:38-91): chain validation
/// is skipped entirely (upstream runs with InsecureSkipVerify), and the
/// peer's certificate public key must ECDSA-equal the configured
/// `public-key` (Go compares `ecdsa.PublicKey.Equal` — curve + point).
#[derive(Debug)]
struct PinnedKeyVerifier {
    provider: Arc<CryptoProvider>,
    pinned: Option<EcdsaPublicKey>,
}

impl ServerCertVerifier for PinnedKeyVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let Some(pinned) = &self.pinned else {
            // skip-cert-verify: the pin is dropped (masque.go:86-88).
            return Ok(ServerCertVerified::assertion());
        };
        match cert_spki(end_entity.as_ref()) {
            Ok(spki) if spki.curve_oid == pinned.curve_oid && spki.point == pinned.point => {
                Ok(ServerCertVerified::assertion())
            }
            Ok(_) => Err(rustls::Error::General(
                "remote endpoint has a different public key than what we trust".into(),
            )),
            Err(_) => Err(rustls::Error::General(
                "x509: unsupported public key (only ECDSA is supported)".into(),
            )),
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &self.provider.signature_verification_algorithms)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// `PrepareTlsConfig` (masque.go:38-91) over rustls/quinn: the client
/// certificate generated from `private-key`, the `public-key` pin (none
/// when `skip_cert_verify`), SNI, ALPN `h3`, TLS 1.3.
pub fn masque_client_tls_config(
    private_key: &EcPrivateKey,
    pinned: Option<&EcdsaPublicKey>,
    skip_cert_verify: bool,
) -> Result<Arc<ClientConfig>> {
    // The SNI itself is applied at the QUIC connect call (PrepareTlsConfig
    // only stores ServerName; masque.go:70).
    let cert = generate_client_cert(private_key)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let verifier = PinnedKeyVerifier {
        provider: provider.clone(),
        pinned: if skip_cert_verify {
            None
        } else {
            pinned.cloned()
        },
    };
    let mut config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::config(format!("failed to prepare TLS config: {e}")))?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(verifier))
        .with_client_auth_cert(
            vec![CertificateDer::from(cert)],
            rustls::pki_types::PrivateKeyDer::Pkcs8(private_key.pkcs8.clone().into()),
        )
        .map_err(|e| Error::config(format!("failed to prepare TLS config: {e}")))?;
    config.alpn_protocols = vec![ALPN_H3.as_bytes().to_vec()];
    Ok(Arc::new(config))
}

// ---------------------------------------------------------------------------
// H3 wire helpers: frames, QPACK (RFC 9114 / RFC 9204)
// ---------------------------------------------------------------------------

/// Append one HTTP/3 frame (`type ‖ length ‖ payload`).
fn put_h3_frame(out: &mut Vec<u8>, frame_type: u64, payload: &[u8]) {
    write_varint(out, frame_type);
    write_varint(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

/// The QPACK static table (RFC 9204 appendix A), 0-indexed — the same
/// table the engine's hysteria2 decoder carries.
#[rustfmt::skip]
const QPACK_STATIC_TABLE: &[(&str, &str)] = &[
    (":authority", ""), (":path", "/"), ("age", "0"), ("content-disposition", ""),
    ("content-length", "0"), ("cookie", ""), ("date", ""), ("etag", ""),
    ("if-modified-since", ""), ("if-none-match", ""), ("last-modified", ""), ("link", ""),
    ("location", ""), ("referer", ""), ("set-cookie", ""), (":method", "CONNECT"),
    (":method", "DELETE"), (":method", "GET"), (":method", "HEAD"), (":method", "OPTIONS"),
    (":method", "POST"), (":method", "PUT"), (":scheme", "http"), (":scheme", "https"),
    (":status", "103"), (":status", "200"), (":status", "304"), (":status", "404"),
    (":status", "503"), ("accept", "*/*"), ("accept", "application/dns-message"),
    ("accept-encoding", "gzip, deflate, br"), ("accept-ranges", "bytes"),
    ("access-control-allow-headers", "cache-control"),
    ("access-control-allow-headers", "content-type"),
    ("access-control-allow-origin", "*"), ("cache-control", "max-age=0"),
    ("cache-control", "max-age=2592000"), ("cache-control", "max-age=604800"),
    ("cache-control", "no-cache"), ("cache-control", "no-store"),
    ("cache-control", "public, max-age=31536000"), ("content-encoding", "br"),
    ("content-encoding", "gzip"), ("content-type", "application/dns-message"),
    ("content-type", "application/javascript"), ("content-type", "application/json"),
    ("content-type", "application/x-www-form-urlencoded"), ("content-type", "image/gif"),
    ("content-type", "image/jpeg"), ("content-type", "image/png"), ("content-type", "text/css"),
    ("content-type", "text/html;charset=utf-8"), ("content-type", "text/plain"),
    ("content-type", "text/plain;charset=utf-8"), ("range", "bytes=0-"),
    ("strict-transport-security", "max-age=31536000"),
    ("strict-transport-security", "max-age=2592000;includesubdomains"),
    ("strict-transport-security", "max-age=31536000;includesubdomains;preload"),
    ("vary", "accept-encoding"), ("vary", "origin"),
    ("x-content-type-options", "nosniff"), ("x-xss-protection", "1; mode=block"),
    (":status", "100"), (":status", "204"), (":status", "206"), (":status", "302"),
    (":status", "400"), (":status", "403"), (":status", "421"), (":status", "425"),
    (":status", "500"), ("accept-language", ""),
    ("access-control-allow-credentials", "FALSE"),
    ("access-control-allow-credentials", "TRUE"),
    ("access-control-allow-headers", "*"), ("access-control-allow-methods", "get"),
    ("access-control-allow-methods", "get, post, options"),
    ("access-control-allow-methods", "options"),
    ("access-control-expose-headers", "content-length"),
    ("access-control-request-headers", "content-type"),
    ("access-control-request-method", "get"),
    ("access-control-request-method", "post"), ("alt-svc", "clear"),
    ("authorization", ""),
    ("content-security-policy", "script-src 'none'; object-src 'none'; base-uri 'none'"),
    ("early-data", "1"), ("expect-ct", ""), ("forwarded", ""), ("if-range", ""),
    ("origin", ""), ("purpose", "prefetch"), ("server", ""),
    ("timing-allow-origin", "*"), ("upgrade-insecure-requests", "1"), ("user-agent", ""),
    ("x-forwarded-for", ""), ("x-frame-options", "deny"),
    ("x-frame-options", "sameorigin"),
];

/// Literal field line, literal name, never indexed (RFC 9204 §4.5.4) —
/// the same encoder the engine's other H3 clients use.
fn put_qpack_literal(block: &mut Vec<u8>, name: &[u8], value: &[u8]) {
    quic::put_prefixed_int(block, 0x20, 3, name.len() as u64);
    block.extend_from_slice(name);
    quic::put_prefixed_int(block, 0x00, 7, value.len() as u64);
    block.extend_from_slice(value);
}

fn read_prefixed_int(data: &[u8], off: usize, prefix_bits: u32) -> Option<(u64, usize)> {
    let max = (1u64 << prefix_bits) - 1;
    let first = *data.get(off)?;
    let mut v = first as u64 & max;
    if v < max {
        return Some((v, off + 1));
    }
    let mut off = off + 1;
    let mut shift = 0u32;
    loop {
        let b = *data.get(off)?;
        off += 1;
        if shift > 56 {
            return None;
        }
        v = v.checked_add(((b & 0x7f) as u64) << shift)?;
        shift += 7;
        if b & 0x80 == 0 {
            return Some((v, off));
        }
    }
}

/// HPACK Huffman code table (RFC 7541 appendix B); QPACK uses the same
/// codes. (code, length) for symbols 0..=256.
#[rustfmt::skip]
const HUFFMAN_CODES: [(u64, u8); 257] = [
    (0x1ff8, 13), (0x7fffd8, 23), (0xfffffe2, 28), (0xfffffe3, 28), (0xfffffe4, 28),
    (0xfffffe5, 28), (0xfffffe6, 28), (0xfffffe7, 28), (0xfffffe8, 28), (0xffffea, 24),
    (0x3ffffffc, 30), (0xfffffe9, 28), (0xfffffea, 28), (0x3ffffffd, 30), (0xfffffeb, 28),
    (0xfffffec, 28), (0xfffffed, 28), (0xfffffee, 28), (0xfffffef, 28), (0xffffff0, 28),
    (0xffffff1, 28), (0xffffff2, 28), (0x3ffffffe, 30), (0xffffff3, 28), (0xffffff4, 28),
    (0xffffff5, 28), (0xffffff6, 28), (0xffffff7, 28), (0xffffff8, 28), (0xffffff9, 28),
    (0xffffffa, 28), (0xffffffb, 28), (0x14, 6), (0x3f8, 10), (0x3f9, 10),
    (0xffa, 12), (0x1ff9, 13), (0x15, 6), (0xf8, 8), (0x7fa, 11),
    (0x3fa, 10), (0x3fb, 10), (0xf9, 8), (0x7fb, 11), (0xfa, 8),
    (0x16, 6), (0x17, 6), (0x18, 6), (0x0, 5), (0x1, 5),
    (0x2, 5), (0x19, 6), (0x1a, 6), (0x1b, 6), (0x1c, 6),
    (0x1d, 6), (0x1e, 6), (0x1f, 6), (0x5c, 7), (0xfb, 8),
    (0x7ffc, 15), (0x20, 6), (0xffb, 12), (0x3fc, 10), (0x1ffa, 13),
    (0x21, 6), (0x5d, 7), (0x5e, 7), (0x5f, 7), (0x60, 7),
    (0x61, 7), (0x62, 7), (0x63, 7), (0x64, 7), (0x65, 7),
    (0x66, 7), (0x67, 7), (0x68, 7), (0x69, 7), (0x6a, 7),
    (0x6b, 7), (0x6c, 7), (0x6d, 7), (0x6e, 7), (0x6f, 7),
    (0x70, 7), (0x71, 7), (0x72, 7), (0xfc, 8), (0x73, 7),
    (0xfd, 8), (0x1ffb, 13), (0x7fff0, 19), (0x1ffc, 13), (0x3ffc, 14),
    (0x22, 6), (0x7ffd, 15), (0x3, 5), (0x23, 6), (0x4, 5),
    (0x24, 6), (0x5, 5), (0x25, 6), (0x26, 6), (0x27, 6),
    (0x6, 5), (0x74, 7), (0x75, 7), (0x28, 6), (0x29, 6),
    (0x2a, 6), (0x7, 5), (0x2b, 6), (0x76, 7), (0x2c, 6),
    (0x8, 5), (0x9, 5), (0x2d, 6), (0x77, 7), (0x78, 7),
    (0x79, 7), (0x7a, 7), (0x7b, 7), (0x7ffe, 15), (0x7fc, 11),
    (0x3ffd, 14), (0x1ffd, 13), (0xffffffc, 28), (0xfffe6, 20), (0x3fffd2, 22),
    (0xfffe7, 20), (0xfffe8, 20), (0x3fffd3, 22), (0x3fffd4, 22), (0x3fffd5, 22),
    (0x7fffd9, 23), (0x3fffd6, 22), (0x7fffda, 23), (0x7fffdb, 23), (0x7fffdc, 23),
    (0x7fffdd, 23), (0x7fffde, 23), (0xffffeb, 24), (0x7fffdf, 23), (0xffffec, 24),
    (0xffffed, 24), (0x3fffd7, 22), (0x7fffe0, 23), (0xffffee, 24), (0x7fffe1, 23),
    (0x7fffe2, 23), (0x7fffe3, 23), (0x7fffe4, 23), (0x1fffdc, 21), (0x3fffd8, 22),
    (0x7fffe5, 23), (0x3fffd9, 22), (0x7fffe6, 23), (0x7fffe7, 23), (0xffffef, 24),
    (0x3fffda, 22), (0x1fffdd, 21), (0xfffe9, 20), (0x3fffdb, 22), (0x3fffdc, 22),
    (0x7fffe8, 23), (0x7fffe9, 23), (0x1fffde, 21), (0x7fffea, 23), (0x3fffdd, 22),
    (0x3fffde, 22), (0xfffff0, 24), (0x1fffdf, 21), (0x3fffdf, 22), (0x7fffeb, 23),
    (0x7fffec, 23), (0x1fffe0, 21), (0x1fffe1, 21), (0x3fffe0, 22), (0x1fffe2, 21),
    (0x7fffed, 23), (0x3fffe1, 22), (0x7fffee, 23), (0x7fffef, 23), (0xfffea, 20),
    (0x3fffe2, 22), (0x3fffe3, 22), (0x3fffe4, 22), (0x7ffff0, 23), (0x3fffe5, 22),
    (0x3fffe6, 22), (0x7ffff1, 23), (0x3ffffe0, 26), (0x3ffffe1, 26), (0xfffeb, 20),
    (0x7fff1, 19), (0x3fffe7, 22), (0x7ffff2, 23), (0x3fffe8, 22), (0x1ffffec, 25),
    (0x3ffffe2, 26), (0x3ffffe3, 26), (0x3ffffe4, 26), (0x7ffffde, 27), (0x7ffffdf, 27),
    (0x3ffffe5, 26), (0xfffff1, 24), (0x1ffffed, 25), (0x7fff2, 19), (0x1fffe3, 21),
    (0x3ffffe6, 26), (0x7ffffe0, 27), (0x7ffffe1, 27), (0x3ffffe7, 26), (0x7ffffe2, 27),
    (0xfffff2, 24), (0x1fffe4, 21), (0x1fffe5, 21), (0x3ffffe8, 26), (0x3ffffe9, 26),
    (0xffffffd, 28), (0x7ffffe3, 27), (0x7ffffe4, 27), (0x7ffffe5, 27), (0xfffec, 20),
    (0xfffff3, 24), (0xfffed, 20), (0x1fffe6, 21), (0x3fffe9, 22), (0x1fffe7, 21),
    (0x1fffe8, 21), (0x7ffff3, 23), (0x3fffea, 22), (0x3fffeb, 22), (0x1ffffee, 25),
    (0x1ffffef, 25), (0xfffff4, 24), (0xfffff5, 24), (0x3ffffea, 26), (0x7ffff4, 23),
    (0x3ffffeb, 26), (0x7ffffe6, 27), (0x3ffffec, 26), (0x3ffffed, 26), (0x7ffffe7, 27),
    (0x7ffffe8, 27), (0x7ffffe9, 27), (0x7ffffea, 27), (0x7ffffeb, 27), (0xffffffe, 28),
    (0x7ffffec, 27), (0x7ffffed, 27), (0x7ffffee, 27), (0x7ffffef, 27), (0x7fffff0, 27),
    (0x3ffffee, 26), (0x3fffffff, 30),
];

fn huffman_map() -> &'static HashMap<(u64, u8), u8> {
    use std::sync::OnceLock;
    static MAP: OnceLock<HashMap<(u64, u8), u8>> = OnceLock::new();
    MAP.get_or_init(|| {
        HUFFMAN_CODES[..256]
            .iter()
            .enumerate()
            .map(|(sym, &(code, len))| ((code, len), sym as u8))
            .collect()
    })
}

fn huffman_decode(data: &[u8]) -> Option<Vec<u8>> {
    let map = huffman_map();
    let mut out = Vec::with_capacity(data.len() * 2);
    let mut code = 0u64;
    let mut len = 0u8;
    for &byte in data {
        for bit in (0..8).rev() {
            code = (code << 1) | ((byte >> bit) & 1) as u64;
            len += 1;
            if len > 30 {
                return None;
            }
            if let Some(&sym) = map.get(&(code, len)) {
                out.push(sym);
                code = 0;
                len = 0;
            }
        }
    }
    if len > 7 {
        return None;
    }
    if len > 0 && code != (1 << len) - 1 {
        return None;
    }
    Some(out)
}

fn read_string_literal(
    data: &[u8],
    off: usize,
    prefix_bits: u32,
    huff_mask: u8,
) -> Option<(Vec<u8>, usize)> {
    let first = *data.get(off)?;
    let huffman = first & huff_mask != 0;
    let (len, off) = read_prefixed_int(data, off, prefix_bits)?;
    let len = usize::try_from(len).ok()?;
    let bytes = data.get(off..off.checked_add(len)?)?;
    let off = off + len;
    if huffman {
        Some((huffman_decode(bytes)?, off))
    } else {
        Some((bytes.to_vec(), off))
    }
}

/// Decode a QPACK field section (static table + literals, Huffman
/// accepted, dynamic references rejected — this client never sets a
/// dynamic table capacity, mirroring `DisableCompression: true`,
/// masque.go:119).
fn decode_field_section(buf: &[u8]) -> Result<Vec<(String, String)>> {
    let (required_inserts, mut off) = read_prefixed_int(buf, 0, 8)
        .ok_or_else(|| Error::protocol("qpack: truncated prefix"))?;
    if required_inserts != 0 {
        return Err(Error::protocol("qpack: dynamic table required"));
    }
    off = read_prefixed_int(buf, off, 7)
        .map(|(_, n)| n)
        .ok_or_else(|| Error::protocol("qpack: truncated base"))?;
    let mut fields = Vec::new();
    while off < buf.len() {
        let b = buf[off];
        if b & 0x80 != 0 {
            let is_static = b & 0x40 != 0;
            let (idx, n) = read_prefixed_int(buf, off, 6)
                .ok_or_else(|| Error::protocol("qpack: truncated index"))?;
            off = n;
            if !is_static {
                return Err(Error::protocol("qpack: dynamic reference"));
            }
            let (name, value) = QPACK_STATIC_TABLE
                .get(idx as usize)
                .ok_or_else(|| Error::protocol(format!("qpack: bad static index {idx}")))?;
            fields.push((name.to_string(), value.to_string()));
        } else if b & 0xc0 == 0x40 {
            let is_static = b & 0x08 != 0;
            let (idx, n) = read_prefixed_int(buf, off, 4)
                .ok_or_else(|| Error::protocol("qpack: truncated name index"))?;
            off = n;
            if !is_static {
                return Err(Error::protocol("qpack: dynamic name reference"));
            }
            let (name, _) = QPACK_STATIC_TABLE
                .get(idx as usize)
                .ok_or_else(|| Error::protocol(format!("qpack: bad static name index {idx}")))?;
            let (value, n) = read_string_literal(buf, off, 7, 0x80)
                .ok_or_else(|| Error::protocol("qpack: truncated value"))?;
            off = n;
            fields.push((name.to_string(), String::from_utf8_lossy(&value).into_owned()));
        } else if b & 0xe0 == 0x20 {
            let (name, n) = read_string_literal(buf, off, 3, 0x08)
                .ok_or_else(|| Error::protocol("qpack: truncated name"))?;
            off = n;
            let (value, n) = read_string_literal(buf, off, 7, 0x80)
                .ok_or_else(|| Error::protocol("qpack: truncated value"))?;
            off = n;
            fields.push((
                String::from_utf8_lossy(&name).into_owned(),
                String::from_utf8_lossy(&value).into_owned(),
            ));
        } else {
            return Err(Error::protocol("qpack: dynamic table reference"));
        }
    }
    Ok(fields)
}

// ---------------------------------------------------------------------------
// Capsules (RFC 9297 framing + connect-ip-go capsule.go)
// ---------------------------------------------------------------------------

/// Append `type ‖ length ‖ payload` (RFC 9297 §3).
fn put_capsule(out: &mut Vec<u8>, capsule_type: u64, payload: &[u8]) {
    write_varint(out, capsule_type);
    write_varint(out, payload.len() as u64);
    out.extend_from_slice(payload);
}

/// An `IPRoute` (capsule.go:171-177).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpRoute {
    pub start: IpAddr,
    pub end: IpAddr,
    /// 0 = all protocols allowed.
    pub ip_protocol: u8,
}

fn put_ip(out: &mut Vec<u8>, ip: &IpAddr) {
    match ip {
        IpAddr::V4(v4) => {
            out.push(4);
            out.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            out.push(6);
            out.extend_from_slice(&v6.octets());
        }
    }
}

/// Just the address octets, no version byte (`netip.Addr.AsSlice`).
fn put_ip_octets(out: &mut Vec<u8>, ip: &IpAddr) {
    match ip {
        IpAddr::V4(v4) => out.extend_from_slice(&v4.octets()),
        IpAddr::V6(v6) => out.extend_from_slice(&v6.octets()),
    }
}

/// `routeAdvertisementCapsule.append` (capsule.go:203-221): per route
/// ONE `ip_version` byte (from the start address's family), then start,
/// end (raw octets each) and `ip_protocol`.
pub fn route_advertisement_capsule(routes: &[IpRoute]) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    for r in routes {
        body.push(match r.start {
            IpAddr::V4(_) => 4,
            IpAddr::V6(_) => 6,
        });
        put_ip_octets(&mut body, &r.start);
        put_ip_octets(&mut body, &r.end);
        body.push(r.ip_protocol);
    }
    let mut out = Vec::new();
    put_capsule(&mut out, CAPSULE_ROUTE_ADVERTISEMENT, &body);
    Ok(out)
}

fn ip_family_mismatch(a: &IpAddr, b: &IpAddr) -> bool {
    a.is_ipv4() != b.is_ipv4()
}

fn read_capsule_ip(data: &[u8], off: usize) -> Result<(IpAddr, usize)> {
    let &v = data
        .get(off)
        .ok_or_else(|| Error::protocol("connect-ip: truncated ip version"))?;
    let (len, mk): (usize, fn([u8; 16]) -> IpAddr) = match v {
        4 => (4, |o: [u8; 16]| IpAddr::V4(Ipv4Addr::new(o[0], o[1], o[2], o[3]))),
        6 => (16, |o: [u8; 16]| IpAddr::V6(o.into())),
        other => {
            return Err(Error::protocol(format!(
                "connect-ip: invalid IP version: {other}"
            )))
        }
    };
    let bytes = data
        .get(off + 1..off + 1 + len)
        .ok_or_else(|| Error::protocol("connect-ip: truncated ip"))?;
    let mut o = [0u8; 16];
    o[..len].copy_from_slice(bytes);
    Ok((mk(o), off + 1 + len))
}

/// `parseRouteAdvertisementCapsule` / `parseIPAddressRange`
/// (capsule.go:186-199 + 223-268): per route ONE `ip_version` byte
/// governs both endpoints — `ip_version ‖ start ‖ end ‖ ip_protocol`.
fn parse_route_advertisement(payload: &[u8]) -> Result<Vec<IpRoute>> {
    let mut routes = Vec::new();
    let mut off = 0usize;
    while off < payload.len() {
        let &v = payload
            .get(off)
            .ok_or_else(|| Error::protocol("connect-ip: truncated ip version"))?;
        let len = match v {
            4 => 4usize,
            6 => 16,
            other => {
                return Err(Error::protocol(format!(
                    "connect-ip: invalid IP version: {other}"
                )))
            }
        };
        let start = read_capsule_octets(payload, off + 1, v, len)?;
        let end = read_capsule_octets(payload, off + 1 + len, v, len)?;
        off += 1 + 2 * len;
        let proto = *payload
            .get(off)
            .ok_or_else(|| Error::protocol("connect-ip: truncated route"))?;
        off += 1;
        routes.push(IpRoute {
            start,
            end,
            ip_protocol: proto,
        });
    }
    Ok(routes)
}

/// Read `len` address octets (no version byte) and build the IP.
fn read_capsule_octets(data: &[u8], off: usize, version: u8, len: usize) -> Result<IpAddr> {
    let bytes = data
        .get(off..off + len)
        .ok_or_else(|| Error::protocol("connect-ip: truncated ip"))?;
    if version == 4 {
        Ok(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        )))
    } else {
        let mut o = [0u8; 16];
        o.copy_from_slice(bytes);
        Ok(IpAddr::V6(o.into()))
    }
}

/// An `AssignedAddress` (capsule.go:25-33).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AssignedAddress {
    pub request_id: u64,
    pub prefix: IpPrefix,
}

/// `addressAssignCapsule.append` (capsule.go:65-85):
/// per address `request_id varint ‖ ip ‖ prefix_len u8`.
pub fn address_assign_capsule(addresses: &[AssignedAddress]) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    for a in addresses {
        write_varint(&mut body, a.request_id);
        put_ip(&mut body, &a.prefix.addr);
        body.push(a.prefix.bits);
    }
    let mut out = Vec::new();
    put_capsule(&mut out, CAPSULE_ADDRESS_ASSIGN, &body);
    Ok(out)
}

/// `parseAddressAssignCapsule` (capsule.go:50-63 + parseAddress 124-163).
fn parse_address_assign(payload: &[u8]) -> Result<Vec<AssignedAddress>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off < payload.len() {
        let (request_id, n) = read_varint(&payload[off..])
            .ok_or_else(|| Error::protocol("connect-ip: truncated request id"))?;
        off += n;
        let (addr, n) = read_capsule_ip(payload, off)?;
        off = n;
        let &bits = payload
            .get(off)
            .ok_or_else(|| Error::protocol("connect-ip: truncated prefix length"))?;
        off += 1;
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if bits > max {
            return Err(Error::protocol(format!(
                "connect-ip: prefix length {bits} exceeds IP address length ({max})"
            )));
        }
        // capsule.go:158-161: `prefix != prefix.Masked()` — the host bits
        // not covered by the prefix length must all be zero.
        let host_bits_zero = match addr {
            IpAddr::V4(a) => {
                let mask = if bits == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(bits))
                };
                u32::from(a) & !mask == 0
            }
            IpAddr::V6(a) => {
                let mask = if bits == 0 {
                    0
                } else {
                    u128::MAX << (128 - u128::from(bits))
                };
                u128::from(a) & !mask == 0
            }
        };
        if !host_bits_zero {
            return Err(Error::protocol(
                "connect-ip: lower bits not covered by prefix length are not all zero",
            ));
        }
        out.push(AssignedAddress {
            request_id,
            prefix: IpPrefix { addr, bits },
        });
    }
    Ok(out)
}

/// The h2 capsule DATAGRAM codec (`h2DatagramStream.SendDatagram`,
/// client_h2.go:305-318): capsule type 0 over a plain byte stream.
pub fn h2_datagram_capsule(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(payload.len() + 9);
    put_capsule(&mut out, H2_DATAGRAM_CAPSULE, payload);
    out
}

/// Parse one capsule from the front of `data`; returns
/// `(type, payload, consumed)`. `Ok(None)` = need more bytes.
pub fn parse_capsule(data: &[u8]) -> Result<Option<(u64, &[u8], usize)>> {
    let Some((ctype, a)) = read_varint(data) else {
        return Ok(None);
    };
    let Some(rest) = data.get(a..) else {
        return Ok(None);
    };
    let Some((len, b)) = read_varint(rest) else {
        return Ok(None);
    };
    let len = usize::try_from(len)
        .map_err(|_| Error::protocol("connect-ip: capsule length out of range"))?;
    let start = a + b;
    let payload = match data.get(start..start.saturating_add(len)) {
        Some(payload) => payload,
        // The declared length exceeds what is buffered: wait for more
        // bytes (quicvarint + io.ReadFull semantics, capsule.go / RFC
        // 9297 stream reading) instead of failing the stream.
        None => return Ok(None),
    };
    Ok(Some((ctype, payload, start + len)))
}

// ---------------------------------------------------------------------------
// IP datagram composition (connect-ip-go conn.go:385-418, client_h2.go)
// ---------------------------------------------------------------------------

/// `ipVersion` (client_h2.go:253).
pub fn ip_version(b: &[u8]) -> Option<u8> {
    b.first().map(|v| v >> 4)
}

/// `calculateIPv4Checksum` (client_h2.go:255-267).
pub fn ipv4_header_checksum(header: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for i in (0..IPV4_HEADER_LEN).step_by(2) {
        if i == 10 {
            continue; // skip the checksum field itself
        }
        sum += u32::from(u16::from_be_bytes([header[i], header[i + 1]]));
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// `composeDatagram` (conn.go:385-418): validate + decrement TTL / hop
/// limit + recompute the IPv4 checksum. `Err` = unproxyable packet
/// (upstream drops it with a log line; [`ConnectIpTunnel::write_packet`]
/// does the same).
pub fn compose_datagram(b: &mut [u8]) -> Result<()> {
    if b.is_empty() {
        return Err(Error::protocol("connect-ip: empty packet"));
    }
    match ip_version(b) {
        Some(4) => {
            if b.len() < IPV4_HEADER_LEN {
                return Err(Error::protocol("connect-ip: IPv4 packet too short"));
            }
            let ttl = b[8];
            if ttl <= 1 {
                return Err(Error::protocol(format!(
                    "connect-ip: datagram TTL too small: {ttl}"
                )));
            }
            b[8] -= 1;
            let checksum = ipv4_header_checksum(&b[..IPV4_HEADER_LEN]);
            b[10..12].copy_from_slice(&checksum.to_be_bytes());
        }
        Some(6) => {
            if b.len() < IPV6_HEADER_LEN {
                return Err(Error::protocol("connect-ip: IPv6 packet too short"));
            }
            let hop_limit = b[7];
            if hop_limit <= 1 {
                return Err(Error::protocol(format!(
                    "connect-ip: datagram Hop Limit too small: {hop_limit}"
                )));
            }
            b[7] -= 1;
        }
        other => {
            return Err(Error::protocol(format!(
                "connect-ip: unknown IP versions: {}",
                other.unwrap_or(0)
            )))
        }
    }
    Ok(())
}

/// The destination half of `handleIncomingProxiedPacket` (conn.go:288-355):
/// the packet must land in an assigned prefix or one of our advertised
/// routes (protocol 0 = any, ICMP always allowed). The peer-source check
/// is omitted — this client never assigns peer addresses (upstream only
/// checks it when `peerAddresses != nil`, conn.go:322).
fn incoming_packet_allowed(
    packet: &[u8],
    assigned: &[IpPrefix],
    local_routes: &[IpRoute],
) -> Result<bool> {
    if packet.is_empty() {
        return Err(Error::protocol("connect-ip: empty packet"));
    }
    let (dst, version, ip_proto) = match ip_version(packet) {
        Some(4) if packet.len() >= IPV4_HEADER_LEN => (
            IpAddr::V4(Ipv4Addr::new(
                packet[16], packet[17], packet[18], packet[19],
            )),
            4,
            packet[9],
        ),
        Some(6) if packet.len() >= IPV6_HEADER_LEN => {
            let mut d = [0u8; 16];
            d.copy_from_slice(&packet[24..40]);
            (IpAddr::V6(d.into()), 6, packet[6])
        }
        Some(v) => return Err(Error::protocol(format!("connect-ip: unknown IP versions: {v}"))),
        None => return Err(Error::protocol("connect-ip: empty packet")),
    };
    if assigned.iter().any(|p| p.contains(dst)) {
        return Ok(true);
    }
    let icmp = (version, ip_proto) == (4, IP_PROTO_ICMP) || (version, ip_proto) == (6, IP_PROTO_ICMPV6);
    Ok(local_routes.iter().any(|r| {
        !ip_family_mismatch(&r.start, &dst)
            && addr_ge(&dst, &r.start)
            && addr_ge(&r.end, &dst)
            && (icmp || r.ip_protocol == 0 || r.ip_protocol == ip_proto)
    }))
}

fn addr_ge(a: &IpAddr, b: &IpAddr) -> bool {
    match (a, b) {
        (IpAddr::V4(x), IpAddr::V4(y)) => u32::from(*x) >= u32::from(*y),
        (IpAddr::V6(x), IpAddr::V6(y)) => u128::from(*x) >= u128::from(*y),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// UDP over the tunnel: IP/UDP packet synthesis (the TUN data plane)
// ---------------------------------------------------------------------------

/// Build an IPv4 UDP packet (src → dst). UDP checksum 0 (legal for IPv4).
pub fn build_udp4_packet(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let total = IPV4_HEADER_LEN + 8 + payload.len();
    let mut pkt = Vec::with_capacity(total);
    pkt.extend_from_slice(&[0x45, 0x00]);
    pkt.extend_from_slice(&(total as u16).to_be_bytes());
    pkt.extend_from_slice(&[0, 0, 0, 0]); // id, flags/frag
    pkt.push(64); // TTL
    pkt.push(IP_PROTO_UDP);
    pkt.extend_from_slice(&[0, 0]); // checksum placeholder
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&dst.octets());
    let checksum = ipv4_header_checksum(&pkt[..IPV4_HEADER_LEN]);
    pkt[10..12].copy_from_slice(&checksum.to_be_bytes());
    put_udp_header(&mut pkt, sport, dport, payload);
    pkt
}

/// Build an IPv6 UDP packet; the UDP checksum is mandatory and computed
/// over the IPv6 pseudo-header (RFC 8200 §8.1).
pub fn build_udp6_packet(
    src: Ipv6Addr,
    dst: Ipv6Addr,
    sport: u16,
    dport: u16,
    payload: &[u8],
) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(IPV6_HEADER_LEN + 8 + payload.len());
    pkt.extend_from_slice(&[0x60, 0, 0, 0]);
    pkt.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    pkt.push(IP_PROTO_UDP);
    pkt.push(64); // hop limit
    pkt.extend_from_slice(&src.octets());
    pkt.extend_from_slice(&dst.octets());
    put_udp_header(&mut pkt, sport, dport, payload);
    let checksum = udp_checksum_v6(src, dst, &pkt[IPV6_HEADER_LEN..]);
    let off = pkt.len() - payload.len() - 2;
    pkt[off..off + 2].copy_from_slice(&checksum.to_be_bytes());
    pkt
}

fn put_udp_header(pkt: &mut Vec<u8>, sport: u16, dport: u16, payload: &[u8]) {
    pkt.extend_from_slice(&sport.to_be_bytes());
    pkt.extend_from_slice(&dport.to_be_bytes());
    pkt.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    pkt.extend_from_slice(&[0, 0]); // checksum (0 for v4; filled for v6)
    pkt.extend_from_slice(payload);
}

/// One's-complement checksum over the IPv6 pseudo-header + UDP header +
/// payload (RFC 8200 §8.1 / RFC 1071).
fn udp_checksum_v6(src: Ipv6Addr, dst: Ipv6Addr, udp: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut add_bytes = |bytes: &[u8]| {
        for chunk in bytes.chunks(2) {
            let hi = chunk[0] as u32;
            let lo = *chunk.get(1).unwrap_or(&0) as u32;
            sum += (hi << 8) | lo;
        }
    };
    add_bytes(&src.octets());
    add_bytes(&dst.octets());
    sum += (udp.len() >> 16) as u32 & 0xffff;
    sum += udp.len() as u32 & 0xffff;
    sum += IP_PROTO_UDP as u32;
    // UDP header + payload with the checksum field (bytes 6..8) skipped.
    for (i, chunk) in udp.chunks(2).enumerate() {
        if i == 3 {
            continue;
        }
        let hi = chunk[0] as u32;
        let lo = *chunk.get(1).unwrap_or(&0) as u32;
        sum += (hi << 8) | lo;
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    let csum = !(sum as u16);
    if csum == 0 {
        0xffff
    } else {
        csum
    }
}

/// Parse an IP packet into `(source, dest_port, payload)` when it
/// carries UDP (protocol 17); `Ok(None)` = not a UDP packet.
pub fn parse_udp_ip_packet(packet: &[u8]) -> Result<Option<(NetAddr, u16, Vec<u8>)>> {
    let Some(v) = ip_version(packet) else {
        return Ok(None);
    };
    let (src, dport, udp) = match v {
        4 => {
            if packet.len() < IPV4_HEADER_LEN + 8 || packet[9] != IP_PROTO_UDP {
                return Ok(None);
            }
            (
                IpAddr::V4(Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15])),
                u16::from_be_bytes([packet[IPV4_HEADER_LEN + 2], packet[IPV4_HEADER_LEN + 3]]),
                &packet[IPV4_HEADER_LEN..],
            )
        }
        6 => {
            if packet.len() < IPV6_HEADER_LEN + 8 || packet[6] != IP_PROTO_UDP {
                return Ok(None);
            }
            let mut a = [0u8; 16];
            a.copy_from_slice(&packet[8..24]);
            (
                IpAddr::V6(a.into()),
                u16::from_be_bytes([packet[IPV6_HEADER_LEN + 2], packet[IPV6_HEADER_LEN + 3]]),
                &packet[IPV6_HEADER_LEN..],
            )
        }
        _ => return Ok(None),
    };
    let len = u16::from_be_bytes([udp[4], udp[5]]) as usize;
    if len < 8 || udp.len() < len {
        return Err(Error::protocol("connect-ip: UDP length mismatch"));
    }
    let src = NetAddr::ip(src, u16::from_be_bytes([udp[0], udp[1]]));
    Ok(Some((src, dport, udp[8..len].to_vec())))
}

// ---------------------------------------------------------------------------
// The H3 client connection
// ---------------------------------------------------------------------------

/// One HTTP/3 client connection: control + QPACK streams opened once and
/// held for the connection lifetime (closing them is a fatal HTTP/3
/// error, RFC 9114 §6.2.1), SETTINGS sent upstream-style.
struct H3Client {
    conn: quinn::Connection,
    #[allow(dead_code)]
    control: Vec<quinn::SendStream>,
}

impl H3Client {
    /// Open the client control/QPACK uni streams and send SETTINGS
    /// (`0x276 = 1` per upstream masque.go:110-118, plus RFC 9220
    /// `0x33 = 1`).
    async fn open(conn: quinn::Connection) -> Result<Self> {
        let mut control = conn
            .open_uni()
            .await
            .map_err(|e| Error::network(format!("masque: control stream: {e}")))?;
        let mut encoder = conn
            .open_uni()
            .await
            .map_err(|e| Error::network(format!("masque: qpack encoder stream: {e}")))?;
        let mut decoder = conn
            .open_uni()
            .await
            .map_err(|e| Error::network(format!("masque: qpack decoder stream: {e}")))?;
        let mut payload = Vec::with_capacity(8);
        write_varint(&mut payload, SETTINGS_H3_DATAGRAM_DRAFT00);
        write_varint(&mut payload, 1);
        write_varint(&mut payload, SETTINGS_H3_DATAGRAM);
        write_varint(&mut payload, 1);
        let mut head = Vec::with_capacity(16);
        write_varint(&mut head, H3_STREAM_CONTROL as u64);
        put_h3_frame(&mut head, H3_FRAME_SETTINGS, &payload);
        control
            .write_all(&head)
            .await
            .map_err(|e| Error::network(format!("masque: settings: {e}")))?;
        let mut t = Vec::with_capacity(4);
        write_varint(&mut t, H3_STREAM_QPACK_ENCODER as u64);
        encoder
            .write_all(&t)
            .await
            .map_err(|e| Error::network(format!("masque: qpack encoder type: {e}")))?;
        t.clear();
        write_varint(&mut t, H3_STREAM_QPACK_DECODER as u64);
        decoder
            .write_all(&t)
            .await
            .map_err(|e| Error::network(format!("masque: qpack decoder type: {e}")))?;
        Ok(H3Client {
            conn,
            control: vec![control, encoder, decoder],
        })
    }

    /// `dialEx`'s settings wait (masque.go:186-194): the server's control
    /// SETTINGS must enable datagrams (the RFC 9220 id or the deprecated
    /// draft-00 id Cloudflare also sends). The EnableExtendedConnect
    /// check is skipped — upstream passes `ignoreExtendedConnect=true`
    /// for Cloudflare's benefit.
    async fn require_datagram_setting(&self) -> Result<()> {
        let found = tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                let mut uni = match self.conn.accept_uni().await {
                    Ok(s) => s,
                    Err(_) => return false,
                };
                let mut head = [0u8; 1];
                if uni.read_exact(&mut head).await.is_err() {
                    continue;
                }
                if head[0] != H3_STREAM_CONTROL {
                    continue; // server QPACK streams: not interesting
                }
                let mut buf = Vec::with_capacity(256);
                let mut chunk = [0u8; 1024];
                loop {
                    match uni.read(&mut chunk).await {
                        Ok(Some(n)) => {
                            buf.extend_from_slice(&chunk[..n]);
                            if let Some(found) = scan_settings_datagram(&buf) {
                                return found;
                            }
                            if buf.len() > 4096 {
                                return false;
                            }
                        }
                        _ => return scan_settings_datagram(&buf).unwrap_or(false),
                    }
                }
            }
        })
        .await;
        match found {
            Ok(true) => Ok(()),
            _ => Err(Error::protocol(
                "connect-ip: server didn't enable datagrams",
            )),
        }
    }

    /// Encode a QPACK field block (prefix: required insert count 0,
    /// base 0; RFC 9204 §4.5.1) of literal never-indexed fields.
    fn encode_headers(fields: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut block = Vec::with_capacity(128);
        block.extend_from_slice(&[0x00, 0x00]);
        for (name, value) in fields {
            put_qpack_literal(&mut block, name, value);
        }
        block
    }

    /// `l4proxy.go DialContext` (89-115): one request stream, a plain
    /// CONNECT to `https://<address>` — `:authority host:port`, no
    /// `:path`/`:scheme`/`:protocol` — 2xx means tunnel; payload rides
    /// DATA frames. Returns the stream halves plus any bytes already
    /// read past the response HEADERS frame.
    async fn connect_l4(
        &self,
        target: &NetAddr,
    ) -> Result<(quinn::SendStream, quinn::RecvStream, BytesMut)> {
        let (mut send, mut recv) = self
            .conn
            .open_bi()
            .await
            .map_err(|e| Error::network(format!("masque: open stream: {e}")))?;
        let authority = target.to_string();
        let block = Self::encode_headers(&[
            (b":authority", authority.as_bytes()),
            (b":method", b"CONNECT"),
        ]);
        let mut frame = Vec::with_capacity(block.len() + 8);
        put_h3_frame(&mut frame, H3_FRAME_HEADERS, &block);
        send.write_all(&frame)
            .await
            .map_err(|e| Error::network(format!("masque: send request: {e}")))?;
        let (status, leftover) = read_response(&mut recv).await?;
        if !(200..=299).contains(&status) {
            return Err(Error::network(format!(
                "CONNECT rejected with status {status}"
            )));
        }
        Ok((send, recv, leftover))
    }

    /// `dialEx` (masque.go:171-224): extended CONNECT with
    /// `:protocol cf-connect-ip`, `:scheme https`, `:path` from the URI
    /// (URI-template variables — IP flow forwarding — are rejected,
    /// masque.go:172-174), `Capsule-Protocol: ?1`, empty `User-Agent`.
    async fn connect_ip(
        &self,
        uri: &str,
    ) -> Result<(quinn::SendStream, quinn::RecvStream, BytesMut)> {
        if uri.contains(['{', '}']) {
            return Err(Error::protocol(
                "connect-ip: IP flow forwarding not supported",
            ));
        }
        let (authority, path) = uri_authority_path(uri)?;
        let (mut send, mut recv) = self
            .conn
            .open_bi()
            .await
            .map_err(|e| Error::network(format!("connect-ip: failed to open request stream: {e}")))?;
        let block = Self::encode_headers(&[
            (b":authority", authority.as_bytes()),
            (b":method", b"CONNECT"),
            (b":path", path.as_bytes()),
            (b":scheme", b"https"),
            (b":protocol", CONNECT_IP_PROTOCOL.as_bytes()),
            (CAPSULE_PROTOCOL_HEADER.as_bytes(), b"?1"),
            (b"user-agent", b""),
        ]);
        let mut frame = Vec::with_capacity(block.len() + 8);
        put_h3_frame(&mut frame, H3_FRAME_HEADERS, &block);
        send.write_all(&frame)
            .await
            .map_err(|e| Error::network(format!("connect-ip: failed to send request: {e}")))?;
        let (status, leftover) = read_response(&mut recv).await?;
        if !(200..=299).contains(&status) {
            return Err(Error::network(format!(
                "connect-ip: server responded with {status}"
            )));
        }
        Ok((send, recv, leftover))
    }
}

/// Scan a buffer for a SETTINGS frame and whether it enables datagrams.
fn scan_settings_datagram(buf: &[u8]) -> Option<bool> {
    let mut off = 0usize;
    loop {
        let (ftype, a) = read_varint(&buf[off..])?;
        let (len, b) = read_varint(buf.get(off + a..)?)?;
        let start = off + a + b;
        let len = usize::try_from(len).ok()?;
        let payload = buf.get(start..start + len)?;
        if ftype == H3_FRAME_SETTINGS {
            let mut p = 0usize;
            while p < payload.len() {
                let (id, n) = read_varint(&payload[p..])?;
                let (value, m) = read_varint(&payload[p + n..])?;
                p += n + m;
                if (id == SETTINGS_H3_DATAGRAM || id == SETTINGS_H3_DATAGRAM_DRAFT00) && value == 1
                {
                    return Some(true);
                }
            }
            return Some(false);
        }
        off = start + len;
    }
}

/// Read H3 frames from the stream until the response HEADERS frame.
/// Returns `(:status, leftover)` — `leftover` holds any bytes read past
/// that frame (`rstr.ReadResponse` + the 2xx checks of masque.go:220-222
/// / l4proxy.go:111-113).
async fn read_response(recv: &mut quinn::RecvStream) -> Result<(u16, BytesMut)> {
    let mut buf = BytesMut::with_capacity(512);
    let mut chunk = [0u8; 2048];
    loop {
        if let Some(block) = find_headers_frame(&buf)? {
            let fields = decode_field_section(block)?;
            let status = fields
                .iter()
                .find(|(n, _)| n == ":status")
                .map(|(_, v)| v.clone())
                .ok_or_else(|| Error::protocol("masque: response without :status"))?;
            let status: u16 = status
                .parse()
                .map_err(|_| Error::protocol(format!("masque: bad status {status:?}")))?;
            let consumed = headers_frame_consumed(&buf)
                .ok_or_else(|| Error::protocol("masque: headers frame accounting"))?;
            buf.advance(consumed);
            return Ok((status, buf));
        }
        let n = recv
            .read(&mut chunk)
            .await
            .map_err(|e| Error::network(format!("connect-ip: failed to read response: {e}")))?
            .ok_or_else(|| Error::protocol("connect-ip: EOF before response"))?;
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 16 * 1024 {
            return Err(Error::protocol("masque: response head too large"));
        }
    }
}

/// If `buf` starts a complete HEADERS frame (skipping any whole frames
/// before it), return its field block. `Ok(None)` = need more bytes.
fn find_headers_frame(buf: &[u8]) -> Result<Option<&[u8]>> {
    let mut off = 0usize;
    loop {
        let Some((ftype, a)) = read_varint(&buf[off..]) else {
            return Ok(None);
        };
        let Some(rest) = buf.get(off + a..) else {
            return Ok(None);
        };
        let Some((len, b)) = read_varint(rest) else {
            return Ok(None);
        };
        let start = off + a + b;
        let len = usize::try_from(len)
            .map_err(|_| Error::protocol("masque: frame length out of range"))?;
        let Some(payload) = buf.get(start..start + len) else {
            return Ok(None);
        };
        if ftype == H3_FRAME_HEADERS {
            return Ok(Some(payload));
        }
        off = start + len;
    }
}

/// Total bytes occupied by the HEADERS frame and any whole frames before
/// it — to step a stream buffer into capsule/DATA territory.
fn headers_frame_consumed(buf: &[u8]) -> Option<usize> {
    let mut off = 0usize;
    loop {
        let (ftype, a) = read_varint(&buf[off..])?;
        let rest = buf.get(off + a..)?;
        let (len, b) = read_varint(rest)?;
        let start = off + a + b;
        let len = usize::try_from(len).ok()?;
        buf.get(start..start + len)?;
        if ftype == H3_FRAME_HEADERS {
            return Some(start + len);
        }
        off = start + len;
    }
}

// ---------------------------------------------------------------------------
// The CONNECT-IP tunnel (connect-ip-go Conn)
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct TunnelState {
    /// From the server's ADDRESS_ASSIGN capsules (conn.go:209-215).
    assigned_addresses: Vec<IpPrefix>,
    /// From the server's ROUTE_ADVERTISEMENT capsules (conn.go:226-232).
    available_routes: Vec<IpRoute>,
    /// The routes this client advertised (`localRoutes`, conn.go:120-122).
    local_routes: Vec<IpRoute>,
    closed: bool,
}

impl TunnelState {
    /// The capsule switch of `readFromStream` (conn.go:199-237).
    fn handle_capsule(&mut self, ctype: u64, payload: &[u8]) -> Result<()> {
        match ctype {
            CAPSULE_ADDRESS_ASSIGN => {
                let assigned = parse_address_assign(payload)?;
                self.assigned_addresses = assigned.into_iter().map(|a| a.prefix).collect();
            }
            CAPSULE_ADDRESS_REQUEST => {
                return Err(Error::protocol(
                    "connect-ip: address request not yet supported",
                ))
            }
            CAPSULE_ROUTE_ADVERTISEMENT => {
                self.available_routes = parse_route_advertisement(payload)?;
            }
            _ => {} // cr.Discard()
        }
        Ok(())
    }
}

/// The routes this client advertises at connect (masque.go:138-153): all
/// of IPv4 and IPv6 with IPProtocol 0 — reused by the inbound check.
fn advertised_routes() -> Vec<IpRoute> {
    vec![
        IpRoute {
            start: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            end: IpAddr::V4(Ipv4Addr::BROADCAST),
            ip_protocol: 0,
        },
        IpRoute {
            start: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            end: IpAddr::V6(Ipv6Addr::from(u128::MAX)),
            ip_protocol: 0,
        },
    ]
}

/// A CONNECT-IP session over one extended-CONNECT request stream
/// (connect-ip-go `Conn`): capsules on the stream, IP packets in
/// context-0 QUIC datagrams.
pub struct ConnectIpTunnel {
    conn: quinn::Connection,
    send: Mutex<quinn::SendStream>,
    state: Arc<std::sync::Mutex<TunnelState>>,
    closed_rx: tokio::sync::watch::Receiver<bool>,
}

impl ConnectIpTunnel {
    /// `ConnectTunnel` + `AdvertiseRoute` (masque.go:109-168): establish
    /// the extended CONNECT, then advertise the catch-all routes. The
    /// capsule reader runs as a task (`readFromStream`'s goroutine).
    async fn connect(h3: &H3Client, conn: quinn::Connection, uri: &str) -> Result<Arc<Self>> {
        h3.require_datagram_setting().await?;
        let (mut send, mut recv, leftover) = h3.connect_ip(uri).await?;
        let routes = advertised_routes();
        let state = Arc::new(std::sync::Mutex::new(TunnelState {
            local_routes: routes.clone(),
            ..Default::default()
        }));
        let (closed_tx, closed_rx) = tokio::sync::watch::channel(false);
        send.write_all(&route_advertisement_capsule(&routes)?)
            .await
            .map_err(|e| Error::network(format!("connect-ip: route advertisement: {e}")))?;

        let st = state.clone();
        tokio::spawn(async move {
            let mut buf = leftover;
            let mut chunk = [0u8; 4096];
            loop {
                match parse_capsule(&buf) {
                    Ok(Some((ctype, payload, consumed))) => {
                        if let Err(e) = st.lock().unwrap().handle_capsule(ctype, payload) {
                            debug!(target: "engine", "connect-ip: capsule error: {e}");
                            break;
                        }
                        buf.advance(consumed);
                        continue;
                    }
                    Ok(None) => {}
                    Err(e) => {
                        debug!(target: "engine", "connect-ip capsule read failed: {e}");
                        break;
                    }
                }
                match recv.read(&mut chunk).await {
                    Ok(Some(n)) => buf.extend_from_slice(&chunk[..n]),
                    Ok(None) | Err(_) => break, // stream FIN/reset
                }
            }
            st.lock().unwrap().closed = true;
            let _ = closed_tx.send(true);
        });
        Ok(Arc::new(ConnectIpTunnel {
            conn,
            send: Mutex::new(send),
            state,
            closed_rx,
        }))
    }

    /// `LocalPrefixes` snapshot (conn.go:159-173).
    pub fn local_prefixes(&self) -> Vec<IpPrefix> {
        self.state.lock().unwrap().assigned_addresses.clone()
    }

    /// `Routes` snapshot (conn.go:175-189).
    pub fn routes(&self) -> Vec<IpRoute> {
        self.state.lock().unwrap().available_routes.clone()
    }

    /// `ReadPacket` (conn.go:261-286): receive a datagram, strip the
    /// context id (non-zero contexts are dropped), validate the packet
    /// against assignments and our advertised routes.
    pub async fn read_packet(&self) -> Result<Vec<u8>> {
        let mut closed = self.closed_rx.clone();
        loop {
            if self.state.lock().unwrap().closed {
                return Err(Error::network("connect-ip: connection closed"));
            }
            let data = tokio::select! {
                dg = self.conn.read_datagram() => dg,
                _ = closed.changed() => {
                    return Err(Error::network("connect-ip: connection closed"));
                }
            }
            .map_err(|e| Error::network(format!("connect-ip: datagram receive: {e}")))?;
            let (context_id, n) = read_varint(&data)
                .ok_or_else(|| Error::protocol("connect-ip: malformed datagram"))?;
            if context_id != 0 {
                continue; // only IP payload proxying is supported
            }
            let packet = data[n..].to_vec();
            let (assigned, local_routes) = {
                let st = self.state.lock().unwrap();
                (st.assigned_addresses.clone(), st.local_routes.clone())
            };
            match incoming_packet_allowed(&packet, &assigned, &local_routes) {
                Ok(true) => return Ok(packet),
                Ok(false) => {
                    debug!(target: "engine", "connect-ip: dropping proxied packet (destination not allowed)");
                    continue;
                }
                Err(e) => {
                    debug!(target: "engine", "dropping proxied packet: {e}");
                    continue;
                }
            }
        }
    }

    /// `WritePacket` (conn.go:357-418): compose (TTL decrement +
    /// checksum), prefix context id 0, send as a QUIC datagram.
    /// Unproxyable packets are dropped silently, like upstream (the
    /// ICMP-too-large return needs the TUN device).
    pub async fn write_packet(&self, packet: &mut [u8]) -> Result<()> {
        if let Err(e) = compose_datagram(packet) {
            debug!(target: "engine", "dropping proxied packet ({} bytes): {e}", packet.len());
            return Ok(());
        }
        let mut datagram = Vec::with_capacity(packet.len() + 1);
        write_varint(&mut datagram, 0); // contextIDZero (conn.go:414-417)
        datagram.extend_from_slice(packet);
        self.conn
            .send_datagram(Bytes::from(datagram))
            .map_err(|e| Error::network(format!("connect-ip: send datagram: {e}")))
    }

    /// `Close` (conn.go:420-430): cancel the stream with
    /// `H3_NO_ERROR` (0x100). Upstream sends CancelRead + Close (a
    /// STOP_SENDING plus stream close); quinn's `reset` sends the
    /// equivalent RESET_STREAM with the same code.
    pub async fn close(&self) -> Result<()> {
        {
            let mut st = self.state.lock().unwrap();
            if st.closed {
                return Ok(());
            }
            st.closed = true;
        }
        let mut send = self.send.lock().await;
        let code = quinn::VarInt::from_u64(H3_NO_ERROR)
            .map_err(|_| Error::protocol("masque: bad error code"))?;
        let _ = send.reset(code);
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// UDP session over the tunnel
// ---------------------------------------------------------------------------

/// A UDP relay session over the CONNECT-IP tunnel: datagrams are
/// synthesized as full IP/UDP packets with the configured local `ip` /
/// `ipv6` as source (the job of upstream's TUN device, done in-process),
/// in exactly the datagram format `WritePacket`/`ReadPacket` exchange.
pub struct MasqueUdpSession {
    tunnel: Arc<ConnectIpTunnel>,
    local4: Option<Ipv4Addr>,
    local6: Option<Ipv6Addr>,
    src_port: u16,
}

impl MasqueUdpSession {
    /// Send one datagram to `target` (packets with no matching local
    /// address family are dropped, like a TUN stack would).
    pub async fn send_to(&self, target: &NetAddr, data: &[u8]) -> Result<()> {
        let packet = match (&self.local4, &target.host) {
            (Some(src), Host::Ip(IpAddr::V4(dst))) => {
                build_udp4_packet(*src, *dst, self.src_port, target.port, data)
            }
            (None, Host::Ip(IpAddr::V4(_))) => {
                debug!(target: "engine", "masque: dropping UDP packet: no local ipv4");
                return Ok(());
            }
            _ => match (&self.local6, &target.host) {
                (Some(src), Host::Ip(IpAddr::V6(dst))) => {
                    build_udp6_packet(*src, *dst, self.src_port, target.port, data)
                }
                _ => {
                    debug!(target: "engine", "masque: dropping UDP packet: no matching local address family");
                    return Ok(());
                }
            },
        };
        let mut packet = packet;
        self.tunnel.write_packet(&mut packet).await
    }

    /// Receive the next UDP datagram addressed to this session's port.
    pub async fn recv_from(&self) -> Result<(NetAddr, Vec<u8>)> {
        loop {
            let packet = self.tunnel.read_packet().await?;
            if let Some((src, dport, payload)) = parse_udp_ip_packet(&packet)? {
                if dport == self.src_port {
                    return Ok((src, payload));
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The outbound client
// ---------------------------------------------------------------------------

/// A connected MASQUE outbound: one H3/QUIC connection with the client
/// certificate and (unless `skip-cert-verify`) the server key pin.
pub struct MasqueClient {
    cfg: MasqueOption,
    mode: MasqueMode,
    conn: quinn::Connection,
    h3: Arc<H3Client>,
    tunnel: Mutex<Option<Arc<ConnectIpTunnel>>>,
}

/// The TUN-mode TCP rejection (`MasqueClient::dial_tcp`, Tun arm).
fn tun_tcp_unimplemented(mode: &str) -> Error {
    Error::config(format!(
        "masque: TUN/ip-stack mode {mode:?} TCP is not implemented — the L3 data plane needs \
         a local TUN device plus a userspace IP stack (upstream adapter/outbound/masque.go \
         newIPStack + the tunDevice read/write loops); use network: h3-l4proxy for the \
         CONNECT-based TCP path"
    ))
}

/// The L4-mode UDP refusal (masque.go:493-495 `ListenPacketContext`).
const L4_UDP_UNSUPPORTED: &str = "masque L4 proxy mode is not supported for UDP";

impl MasqueClient {
    /// `NewMasque` + `L4Client.dialConn` + `ConnectTunnel`: validate the
    /// config, dial QUIC with the masque TLS config, set up H3. The QUIC
    /// transport mirrors `crate::quic::client_config` (datagrams enabled,
    /// generous uni-stream limits, 30s keep-alive — upstream
    /// masque.go:210-214) — quinn manages its own connection ids, so
    /// upstream's `ConnectionIDLength: 20` has no equivalent knob.
    pub async fn connect(mut cfg: MasqueOption) -> Result<Self> {
        cfg.validate_ip_stack()?;
        let mode = match cfg.network.as_str() {
            "h3-l4proxy" => MasqueMode::L4Proxy,
            "h2" => {
                return Err(Error::config(
                    "masque: network h2 is not implemented (HTTP/2 CONNECT-IP over TLS requires \
                     a full HTTP/2 client; transport/masque client_h2.go)",
                ))
            }
            _ => MasqueMode::Tun,
        };
        if mode == MasqueMode::L4Proxy && cfg.udp {
            // masque.go:226-229 — "L4 proxy mode is not supported for UDP"
            warn!(target: "engine", "L4 proxy mode is not supported for UDP");
            cfg.udp = false;
        }
        let private = base64_decode(&cfg.private_key, "private key")?;
        let private = parse_ec_private_key(&private)?;
        let public = base64_decode(&cfg.public_key, "public key")?;
        let public = parse_spki_ecdsa_public_key(&public)?;
        let sni = cfg.effective_sni(mode);
        let tls = masque_client_tls_config(&private, Some(&public), cfg.skip_cert_verify)?;
        let quic_tls = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
            .map_err(|e| Error::config(format!("failed to prepare TLS config: {e}")))?;
        let mut quic_cfg = quinn::ClientConfig::new(Arc::new(quic_tls));
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_uni_streams(1024u32.into());
        transport.datagram_receive_buffer_size(Some(64 * 1024));
        transport.keep_alive_interval(Some(Duration::from_secs(30)));
        quic_cfg.transport_config(Arc::new(transport));

        let remote = quic::resolve_remote(&cfg.server, cfg.port).await?;
        let mut endpoint = quinn::Endpoint::client(quic::family_bind_addr(remote))
            .map_err(|e| Error::network(format!("quic bind: {e}")))?;
        endpoint.set_default_client_config(quic_cfg);
        let connect = endpoint
            .connect(remote, &sni)
            .map_err(|e| Error::config(format!("quic connect to {remote}: {e}")))?;
        let conn = if cfg.handshake_timeout > 0 {
            tokio::time::timeout(Duration::from_secs(cfg.handshake_timeout), connect)
                .await
                .map_err(|_| Error::network("masque: handshake timed out"))?
        } else {
            connect.await
        }
        .map_err(|e| {
            if e.to_string().contains("tls: access denied") {
                Error::network(
                    "login failed! Please double-check if your tls key and cert is enrolled in \
                     the Cloudflare Access service",
                )
            } else {
                Error::network(format!(
                    "quic handshake with {remote} (sni {sni}, alpn h3): {e}"
                ))
            }
        })?;
        debug!(target: "engine", "masque: connected to {remote} (sni {sni})");
        let h3 = Arc::new(H3Client::open(conn.clone()).await?);
        Ok(MasqueClient {
            cfg,
            mode,
            conn,
            h3,
            tunnel: Mutex::new(None),
        })
    }

    /// TCP relay. `h3-l4proxy` mode: the upstream plain-CONNECT L4
    /// client. Default (`Tun`) mode: upstream tunnels TCP through the
    /// local TUN device, which this port does not wire — precise reject.
    pub async fn dial_tcp(&self, target: &NetAddr) -> Result<BoxProxyStream> {
        match self.mode {
            MasqueMode::L4Proxy => {
                let (send, recv, leftover) = self.h3.connect_l4(target).await?;
                Ok(Box::new(H3DataStream::new(send, recv, leftover)))
            }
            MasqueMode::Tun => Err(tun_tcp_unimplemented(&self.cfg.ip_stack.mode)),
        }
    }

    /// Open (or reuse) the CONNECT-IP tunnel and return a UDP session.
    /// L4 proxy mode refuses UDP (upstream forces it off,
    /// masque.go:226-229 / 493-495).
    pub async fn open_udp(&self) -> Result<MasqueUdpSession> {
        if self.mode == MasqueMode::L4Proxy {
            return Err(Error::config(L4_UDP_UNSUPPORTED));
        }
        let mut guard = self.tunnel.lock().await;
        if guard.is_none() {
            let uri = self.cfg.effective_uri();
            let tunnel = ConnectIpTunnel::connect(&self.h3, self.conn.clone(), &uri).await?;
            *guard = Some(tunnel);
        }
        let tunnel = guard.as_ref().expect("just set").clone();
        let local = prefixes(&self.cfg)?;
        let local4 = local.iter().find_map(|p| match p.addr {
            IpAddr::V4(v4) if !v4.is_unspecified() => Some(v4),
            _ => None,
        });
        let local6 = local.iter().find_map(|p| match p.addr {
            IpAddr::V6(v6) if !v6.is_unspecified() => Some(v6),
            _ => None,
        });
        Ok(MasqueUdpSession {
            tunnel,
            local4,
            local6,
            src_port: rand::rngs::OsRng.gen_range(32768..=60999),
        })
    }
}

fn base64_decode(s: &str, what: &str) -> Result<Vec<u8>> {
    use base64::Engine as _;
    base64::engine::general_purpose::STANDARD
        .decode(s.as_bytes())
        .map_err(|e| Error::config(format!("failed to decode {what}: {e}")))
}

// ---------------------------------------------------------------------------
// The L4 tunnel stream (DATA frames, RFC 9114 §4.4)
// ---------------------------------------------------------------------------

/// A bidirectional HTTP/3 tunnel stream: writes become DATA frames, reads
/// deframe DATA (other frame types are skipped).
pub struct H3DataStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    rbuf: BytesMut,
    out: BytesMut,
    wbuf: BytesMut,
    eof: bool,
}

impl H3DataStream {
    fn new(send: quinn::SendStream, recv: quinn::RecvStream, leftover: BytesMut) -> Self {
        H3DataStream {
            send,
            recv,
            rbuf: leftover,
            out: BytesMut::with_capacity(16 * 1024),
            wbuf: BytesMut::new(),
            eof: false,
        }
    }

    /// Consume one complete DATA frame if buffered; `Ok(false)` = need
    /// more bytes. Non-DATA frames are skipped.
    fn try_parse(&mut self) -> Result<bool> {
        loop {
            let Some((ftype, a)) = read_varint(&self.rbuf) else {
                return Ok(false);
            };
            let Some(rest) = self.rbuf.get(a..) else {
                return Ok(false);
            };
            let Some((len, b)) = read_varint(rest) else {
                return Ok(false);
            };
            let len = usize::try_from(len)
                .map_err(|_| Error::protocol("masque: frame length out of range"))?;
            let start = a + b;
            let Some(payload) = self.rbuf.get(start..start + len) else {
                return Ok(false);
            };
            let is_data = ftype == H3_FRAME_DATA;
            if is_data {
                self.out.extend_from_slice(payload);
            }
            self.rbuf.advance(start + len);
            if is_data {
                return Ok(true);
            }
        }
    }
}

impl AsyncWrite for H3DataStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = &mut *self;
        if !this.wbuf.is_empty() {
            // Flush the previous frame first.
            match AsyncWrite::poll_write(Pin::new(&mut this.send), cx, &this.wbuf) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::WriteZero,
                        "masque: transport accepted zero bytes",
                    )))
                }
                Poll::Ready(Ok(n)) => {
                    this.wbuf.advance(n);
                    if !this.wbuf.is_empty() {
                        return Poll::Pending;
                    }
                }
                other => return other,
            }
        }
        let mut frame = Vec::with_capacity(buf.len() + 9);
        put_h3_frame(&mut frame, H3_FRAME_DATA, buf);
        this.wbuf.extend_from_slice(&frame);
        match AsyncWrite::poll_write(Pin::new(&mut this.send), cx, &this.wbuf) {
            Poll::Ready(Ok(0)) => Poll::Ready(Ok(buf.len())), // stays buffered
            Poll::Ready(Ok(n)) => {
                this.wbuf.advance(n);
                Poll::Ready(Ok(buf.len()))
            }
            other => other,
        }
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        while !this.wbuf.is_empty() {
            let n = ready!(AsyncWrite::poll_write(
                Pin::new(&mut this.send),
                cx,
                &this.wbuf
            ))?;
            if n == 0 {
                return Poll::Ready(Err(std::io::Error::new(
                    std::io::ErrorKind::WriteZero,
                    "masque: transport accepted zero bytes",
                )));
            }
            this.wbuf.advance(n);
        }
        AsyncWrite::poll_flush(Pin::new(&mut this.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        ready!(self.as_mut().poll_flush(cx))?;
        let this = &mut *self;
        AsyncWrite::poll_shutdown(Pin::new(&mut this.send), cx)
    }
}

impl AsyncRead for H3DataStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = &mut *self;
        loop {
            if !this.out.is_empty() {
                let n = this.out.len().min(buf.remaining());
                buf.put_slice(&this.out[..n]);
                this.out.advance(n);
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            match this.try_parse() {
                Ok(true) => continue,
                Ok(false) => {
                    let mut tmp = [0u8; 16 * 1024];
                    let mut rb = ReadBuf::new(&mut tmp);
                    match AsyncRead::poll_read(Pin::new(&mut this.recv), cx, &mut rb) {
                        Poll::Ready(Ok(())) => {
                            if rb.filled().is_empty() {
                                this.eof = true;
                                return Poll::Ready(Ok(()));
                            }
                            this.rbuf.extend_from_slice(rb.filled());
                        }
                        other => return other,
                    }
                }
                Err(e) => {
                    return Poll::Ready(Err(std::io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        e.to_string(),
                    )))
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ------------------------------------------------------------ DER/cert

    /// A fresh P-256 key pair via ring (rcgen's generator is Ed25519
    /// only): returns (pkcs8, public point).
    fn generate_p256() -> (Vec<u8>, Vec<u8>) {
        let rng = ring::rand::SystemRandom::new();
        let doc = ring::signature::EcdsaKeyPair::generate_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &rng,
        )
        .unwrap();
        let pkcs8 = doc.as_ref().to_vec();
        let pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &pkcs8,
            &rng,
        )
        .unwrap();
        (pkcs8, pair.public_key().as_ref().to_vec())
    }

    /// (SEC1 DER, public point) for the client's `private-key` config.
    /// ring's PKCS#8 inner ECPrivateKey omits the optional `[0]` curve OID
    /// (RFC 5915 §3; PKCS#11-compatible), while Go's
    /// `x509.MarshalECPrivateKey` — the shape Cloudflare enrollment keys
    /// and `x509.ParseECPrivateKey` (masque.go:136-143) use — always
    /// writes `[0] OID prime256v1` and `[1] BIT STRING public`. Rebuild
    /// that Go-style SEC1 from the ring fields.
    fn test_ec_key_material() -> (Vec<u8>, Vec<u8>) {
        let (pkcs8, point) = generate_p256();
        // PKCS#8 → the inner (ring-shaped) ECPrivateKey: the last OCTET
        // STRING element of the PrivateKeyInfo.
        let (_, body) = der::tlv(&pkcs8).unwrap();
        let mut rest = body;
        let (_, v) = der::tlv(rest).unwrap();
        rest = &rest[der::tlv_len(v.len())..];
        let (_, a) = der::tlv(rest).unwrap();
        rest = &rest[der::tlv_len(a.len())..];
        let (_, o) = der::tlv(rest).unwrap();
        // ECPrivateKey content: INTEGER 1, OCTET STRING scalar, [1] pub.
        let (_, inner) = der::tlv(o).unwrap();
        let mut irest = inner;
        let (_, ver) = der::tlv(irest).unwrap();
        irest = &irest[der::tlv_len(ver.len())..];
        let (_, scalar) = der::tlv(irest).unwrap();
        let mut scalar_tlv = Vec::new();
        der::put_tlv(&mut scalar_tlv, 0x04, scalar);
        // Splice in the mandatory-for-Go [0] curve OID.
        let mut zero_oid = Vec::new();
        der::put_tlv(&mut zero_oid, 0xa0, &der::oid(&[1, 2, 840, 10045, 3, 1, 7]));
        let mut one = Vec::new();
        der::put_tlv(&mut one, 0xa1, &der::bitstring(&point));
        (
            der::seq(&[&der::uint(vec![1]), &scalar_tlv, &zero_oid, &one]),
            point,
        )
    }

    #[test]
    fn der_helpers_roundtrip() {
        // Known OID encodings.
        assert_eq!(der::oid(&[1, 2, 840, 10045, 3, 1, 7])[2..], [
            0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07
        ]);
        // 2.100.3: the combined first arcs 2*40+100 = 180 needs two
        // base-128 bytes — 180 = 1*128 + 52 → (0x81, 0x34).
        assert_eq!(der::oid(&[2, 100, 3])[2..], [0x81, 0x34, 0x03]);
        // INTEGER sign byte and minimal form.
        assert_eq!(der::uint(vec![0]), vec![0x02, 0x01, 0x00]);
        assert_eq!(der::uint(vec![0x00, 0x80]), vec![0x02, 0x02, 0x00, 0x80]);
        assert_eq!(der::uint(vec![0x01, 0x02]), vec![0x02, 0x02, 0x01, 0x02]);
        // Long-form lengths roundtrip through tlv.
        let long = vec![7u8; 300];
        let mut t = Vec::new();
        der::put_tlv(&mut t, 0x04, &long);
        assert_eq!(der::tlv(&t).unwrap(), (0x04, long.as_slice()));
    }

    #[test]
    fn sec1_key_parses_and_rewraps() {
        let (sec1, point) = test_ec_key_material();
        let key = parse_ec_private_key(&sec1).unwrap();
        let pair = ring::signature::EcdsaKeyPair::from_pkcs8(
            &ring::signature::ECDSA_P256_SHA256_FIXED_SIGNING,
            &key.pkcs8,
            &ring::rand::SystemRandom::new(),
        )
        .unwrap();
        assert_eq!(pair.public_key().as_ref(), point.as_slice());
        // Rejects junk and missing fields.
        assert!(parse_ec_private_key(&[0x30, 0x00]).is_err());
        assert!(parse_ec_private_key(&der::seq(&[&der::uint(vec![1])])).is_err());
    }

    #[test]
    fn generated_cert_is_valid_x509() {
        let (sec1, point) = test_ec_key_material();
        let key = parse_ec_private_key(&sec1).unwrap();
        let cert = generate_client_cert(&key).unwrap();
        // Certificate DER walk: SEQ{ tbs, algid, BIT STRING sig }.
        let (_, body) = der::tlv(&cert).unwrap();
        let (t_tbs, tbs) = der::tlv(body).unwrap();
        assert_eq!(t_tbs, 0x30);
        // The signature covers the FULL marshaled tbsCertificate TLV
        // (tag + length + content), like x509.CreateCertificate.
        let tbs_len = der::tlv_len(tbs.len());
        let tbs_full = &body[..tbs_len];
        let rest = &body[tbs_len..];
        let (_, algid) = der::tlv(rest).unwrap();
        let rest = &rest[der::tlv_len(algid.len())..];
        let (t_sig, sig_body) = der::tlv(rest).unwrap();
        assert_eq!(t_sig, 0x03);
        // SPKI inside the cert matches the key's public point.
        let spki = cert_spki(&cert).unwrap();
        assert_eq!(spki.point, point);
        assert_eq!(
            spki.curve_oid,
            der::oid(&[1, 2, 840, 10045, 3, 1, 7])[2..].to_vec()
        );
        // The signature verifies; tampering fails.
        let verifier = ring::signature::UnparsedPublicKey::new(
            &ring::signature::ECDSA_P256_SHA256_ASN1,
            &point,
        );
        verifier.verify(tbs_full, &sig_body[1..]).unwrap();
        let mut bad_sig = sig_body.to_vec();
        let last = bad_sig.len() - 1;
        bad_sig[last] ^= 1;
        assert!(verifier.verify(tbs_full, &bad_sig[1..]).is_err());
    }

    #[test]
    fn spki_parse_and_pin_semantics() {
        let (_, point) = test_ec_key_material();
        let spki = der::seq(&[
            &der::seq(&[
                &der::oid(&[1, 2, 840, 10045, 2, 1]),
                &der::oid(&[1, 2, 840, 10045, 3, 1, 7]),
            ]),
            &der::bitstring(&point),
        ]);
        let parsed = parse_spki_ecdsa_public_key(&spki).unwrap();
        assert_eq!(parsed.point, point);
        // Non-EC algorithms rejected with the upstream message.
        let rsa_spki = der::seq(&[
            &der::seq(&[&der::oid(&[1, 2, 840, 113549, 1, 1, 1])]),
            &der::bitstring(&[0x01]),
        ]);
        let err = parse_spki_ecdsa_public_key(&rsa_spki)
            .unwrap_err()
            .to_string();
        assert!(err.contains("failed to assert public key as ECDSA"), "{err}");
    }

    // ------------------------------------------------------------ capsules

    #[test]
    fn route_capsule_roundtrip() {
        let routes = vec![
            IpRoute {
                start: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                end: IpAddr::V4(Ipv4Addr::BROADCAST),
                ip_protocol: 0,
            },
            IpRoute {
                start: "2001:db8::".parse().unwrap(),
                end: "2001:db8::ffff".parse().unwrap(),
                ip_protocol: IP_PROTO_UDP,
            },
        ];
        let capsule = route_advertisement_capsule(&routes).unwrap();
        let (ctype, payload, consumed) = parse_capsule(&capsule).unwrap().unwrap();
        assert_eq!(ctype, CAPSULE_ROUTE_ADVERTISEMENT);
        assert_eq!(consumed, capsule.len());
        assert_eq!(parse_route_advertisement(payload).unwrap(), routes);
        // The upstream wire bytes for the v4 catch-all range — ONE
        // version byte per route, 1+4+4+1 = 10 bytes (capsule.go:203-213):
        // 04 00000000 ffffffff 00 (masque.go:140-144).
        assert_eq!(
            &payload[..10],
            &[0x04, 0, 0, 0, 0, 0xff, 0xff, 0xff, 0xff, 0x00]
        );
        // The v6 catch-all (masque.go:145-153): 06 + 16 zeros + 16 x ff
        // + 00, following the 10-byte v4 route.
        let all = advertised_routes();
        let capsule = route_advertisement_capsule(&all).unwrap();
        let (_, payload, _) = parse_capsule(&capsule).unwrap().unwrap();
        let mut expect = vec![0x06u8];
        expect.extend_from_slice(&[0u8; 16]);
        expect.extend_from_slice(&[0xffu8; 16]);
        expect.push(0);
        assert_eq!(&payload[10..], &expect[..]);
        // Truncation of the final route errors.
        assert!(parse_route_advertisement(&payload[..payload.len() - 1]).is_err());
    }

    #[test]
    fn address_assign_capsule_roundtrip() {
        let addrs = vec![
            AssignedAddress {
                request_id: 7,
                prefix: IpPrefix {
                    addr: IpAddr::V4(Ipv4Addr::new(100, 64, 0, 2)),
                    bits: 32,
                },
            },
            AssignedAddress {
                request_id: 0x4041, // exercises the 2-byte varint
                prefix: IpPrefix {
                    addr: "fd00:2021:1111::2".parse().unwrap(),
                    bits: 128,
                },
            },
        ];
        let capsule = address_assign_capsule(&addrs).unwrap();
        let (ctype, payload, _) = parse_capsule(&capsule).unwrap().unwrap();
        assert_eq!(ctype, CAPSULE_ADDRESS_ASSIGN);
        assert_eq!(parse_address_assign(payload).unwrap(), addrs);
        // An out-of-range or unmasked prefix is rejected (capsule.go:155-161).
        let mut bad = payload.to_vec();
        let last = bad.len() - 1;
        bad[last] = 33;
        assert!(parse_address_assign(&bad).is_err());
    }

    #[test]
    fn h2_datagram_capsule_shape() {
        let frame = h2_datagram_capsule(b"packet-bytes");
        // Capsule type 0, varint length, payload (client_h2.go:305-318).
        assert_eq!(frame[0], 0);
        let (ctype, payload, consumed) = parse_capsule(&frame).unwrap().unwrap();
        assert_eq!((ctype, payload, consumed), (0, &b"packet-bytes"[..], frame.len()));
        // Incomplete input waits rather than erroring.
        assert!(parse_capsule(&frame[..frame.len() - 1]).unwrap().is_none());
    }

    // ------------------------------------------------------------ IP datagrams

    #[test]
    fn compose_datagram_decrements_ttl_and_fixes_checksum() {
        let mut pkt = build_udp4_packet(
            "100.64.0.2".parse().unwrap(),
            "1.1.1.1".parse().unwrap(),
            5353,
            53,
            b"abc",
        );
        let before = pkt[10..12].to_vec();
        compose_datagram(&mut pkt).unwrap();
        assert_eq!(pkt[8], 63); // TTL 64 → 63
        assert_ne!(pkt[10..12], before);
        // The recomputed checksum is internally consistent: upstream's
        // calculateIPv4Checksum SKIPS the checksum field (client_h2.go:255-267),
        // so recomputing over the finished header reproduces the stored
        // value rather than summing to zero.
        assert_eq!(
            ipv4_header_checksum(&pkt[..IPV4_HEADER_LEN]),
            u16::from_be_bytes([pkt[10], pkt[11]])
        );
        // TTL 1 → dropped with the upstream message.
        let mut dropme = pkt.clone();
        dropme[8] = 1;
        let err = compose_datagram(&mut dropme).unwrap_err().to_string();
        assert!(err.contains("TTL too small"), "{err}");
        // IPv6 hop limit.
        let mut v6 = build_udp6_packet(
            "fd00::2".parse().unwrap(),
            "fd00::1".parse().unwrap(),
            5353,
            53,
            b"x",
        );
        compose_datagram(&mut v6).unwrap();
        assert_eq!(v6[7], 63);
        // Unknown version dropped with the upstream message.
        let mut junk = vec![0x50u8, 1];
        let err = compose_datagram(&mut junk).unwrap_err().to_string();
        assert!(err.contains("unknown IP versions"), "{err}");
        assert!(compose_datagram(&mut []).is_err());
    }

    #[test]
    fn udp_ip_packet_roundtrip() {
        let payload = b"udp-payload-bytes";
        let pkt4 = build_udp4_packet(
            "100.64.0.2".parse().unwrap(),
            "8.8.8.8".parse().unwrap(),
            40000,
            53,
            payload,
        );
        let (src, dport, got) = parse_udp_ip_packet(&pkt4).unwrap().unwrap();
        // (source, dest_port): the packet was built
        // 100.64.0.2:40000 → 8.8.8.8:53.
        assert_eq!(src.host.to_text(), "100.64.0.2");
        assert_eq!(src.port, 40000);
        assert_eq!(dport, 53);
        assert_eq!(got, payload);
        // IPv4 header checksum correct by construction (the skip-style
        // recompute returns the stored value).
        assert_eq!(
            ipv4_header_checksum(&pkt4[..IPV4_HEADER_LEN]),
            u16::from_be_bytes([pkt4[10], pkt4[11]])
        );
        // IPv6: the written checksum verifies against a recompute.
        let (s6, d6): (Ipv6Addr, Ipv6Addr) =
            ("fd00::2".parse().unwrap(), "fd00::1".parse().unwrap());
        let pkt6 = build_udp6_packet(s6, d6, 40000, 53, payload);
        let udp = &pkt6[IPV6_HEADER_LEN..];
        assert_eq!(
            udp_checksum_v6(s6, d6, udp),
            u16::from_be_bytes([udp[6], udp[7]])
        );
        let (src, dport, got) = parse_udp_ip_packet(&pkt6).unwrap().unwrap();
        assert_eq!(src.host.to_text(), "fd00::2");
        assert_eq!(src.port, 40000);
        assert_eq!(dport, 53);
        assert_eq!(got, payload);
        // Non-UDP protocol and truncated packets are skipped.
        let mut tcp = pkt4.clone();
        tcp[9] = 6;
        assert!(parse_udp_ip_packet(&tcp).unwrap().is_none());
        assert!(parse_udp_ip_packet(&pkt4[..IPV4_HEADER_LEN + 4])
            .unwrap()
            .is_none());
        // A lying UDP length field errors.
        let mut lying = pkt4.clone();
        lying[IPV4_HEADER_LEN + 4] = 0xff;
        assert!(parse_udp_ip_packet(&lying).is_err());
    }

    #[test]
    fn inbound_packet_destination_validation() {
        let routes = advertised_routes();
        let pkt = build_udp4_packet(
            "8.8.8.8".parse().unwrap(),
            "100.64.0.2".parse().unwrap(),
            53,
            5353,
            b"q",
        );
        assert!(incoming_packet_allowed(&pkt, &[], &routes).unwrap());
        // A destination outside the routes is refused.
        let alien = build_udp4_packet(
            "8.8.8.8".parse().unwrap(),
            "203.0.113.9".parse().unwrap(),
            53,
            5353,
            b"q",
        );
        assert!(!incoming_packet_allowed(&alien, &[], &[]).unwrap());
        // ...unless an assigned prefix covers it (conn.go:332-335).
        let assigned = [IpPrefix {
            addr: "203.0.113.0".parse().unwrap(),
            bits: 24,
        }];
        assert!(incoming_packet_allowed(&alien, &assigned, &[]).unwrap());
        // Protocol-restricted routes allow only their protocol + ICMP.
        let udp_only = [IpRoute {
            start: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            end: IpAddr::V4(Ipv4Addr::BROADCAST),
            ip_protocol: IP_PROTO_UDP,
        }];
        assert!(incoming_packet_allowed(&pkt, &[], &udp_only).unwrap());
        let mut tcp = pkt.clone();
        tcp[9] = 6;
        assert!(!incoming_packet_allowed(&tcp, &[], &udp_only).unwrap());
        let mut icmp = pkt.clone();
        icmp[9] = IP_PROTO_ICMP;
        assert!(incoming_packet_allowed(&icmp, &[], &udp_only).unwrap());
    }

    // ------------------------------------------------------------ QPACK

    #[test]
    fn qpack_decode_static_literals_huffman() {
        // Our encoder's own form.
        let mut block = vec![0x00, 0x00];
        put_qpack_literal(&mut block, b":status", b"200");
        put_qpack_literal(&mut block, b"x-custom", b"v");
        let fields = decode_field_section(&block).unwrap();
        assert_eq!(fields.len(), 2);
        assert_eq!(fields[0], (":status".to_string(), "200".to_string()));

        // Indexed static :status 200 (index 25 → 0xd9).
        let fields = decode_field_section(&[0x00, 0x00, 0xc0 | 25]).unwrap();
        assert_eq!(fields, vec![(":status".to_string(), "200".to_string())]);
        // Multi-byte static index (:status 500 = 71).
        let fields = decode_field_section(&[0x00, 0x00, 0xff, (71 - 63) as u8]).unwrap();
        assert_eq!(fields[0].1, "500");
        // Literal with static name index + Huffman value (the RFC 7541
        // C.4.1 huffman string is "www.example.com").
        let mut block = vec![0x00, 0x00];
        quic::put_prefixed_int(&mut block, 0x40, 4, 24); // :status name idx
        quic::put_prefixed_int(&mut block, 0x80, 7, 12); // Huffman flag set
        block.extend_from_slice(&[
            0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
        ]);
        let fields = decode_field_section(&block).unwrap();
        assert_eq!(fields[0].0, ":status");
        assert_eq!(fields[0].1, "www.example.com");
        // Dynamic references rejected (we advertise no dynamic table).
        assert!(decode_field_section(&[0x00, 0x00, 0x80]).is_err());
        assert!(decode_field_section(&[0x00, 0x00, 0x1f]).is_err());
    }

    // ------------------------------------------------------------ config

    #[test]
    fn prefixes_parse_upstream_semantics() {
        let mut o = MasqueOption::default();
        let err = prefixes(&o).unwrap_err().to_string();
        assert!(err.contains("missing local address"), "{err}");
        o.ip = "100.64.0.2".into();
        let p = prefixes(&o).unwrap();
        assert_eq!(
            p,
            vec![IpPrefix {
                addr: "100.64.0.2".parse().unwrap(),
                bits: 32
            }]
        );
        o.ipv6 = "fd00:2021:1111::2/64".into();
        let p = prefixes(&o).unwrap();
        assert_eq!(p[1].bits, 64);
        o.ip = "not-an-ip".into();
        let err = prefixes(&o).unwrap_err().to_string();
        // Error::config's Display carries the "config: " prefix.
        assert!(err.contains("ip address parse error"), "{err}");
        o.ip = "1.2.3.4/33".into();
        assert!(prefixes(&o).is_err());
    }

    #[test]
    fn ip_stack_validate_upstream_strings() {
        let mut s = IpStackOption::default();
        s.normalize();
        assert_eq!(s.mode, "auto");
        s.validate().unwrap();
        s.mode = "gvisor".into();
        let err = s.validate().unwrap_err().to_string();
        assert!(err.contains("with_gvisor"), "{err}");
        s.mode = "bogus".into();
        let err = s.validate().unwrap_err().to_string();
        assert!(err.contains("invalid IP stack mode"), "{err}");
        s.mode = "mips".into();
        s.congestion_controller = "bbr3".into();
        s.validate().unwrap();
        s.congestion_controller = "ls".into();
        let err = s.validate().unwrap_err().to_string();
        assert!(err.contains("invalid IP stack congestion controller"), "{err}");
    }

    #[test]
    fn uri_split_matches_quic_go() {
        assert_eq!(
            uri_authority_path("https://cloudflareaccess.com").unwrap(),
            ("cloudflareaccess.com".to_string(), "/".to_string())
        );
        assert_eq!(
            uri_authority_path("https://example.org:8443/masque?x=1").unwrap(),
            ("example.org:8443".to_string(), "/masque?x=1".to_string())
        );
        assert!(uri_authority_path("https://").is_err());
    }

    #[test]
    fn effective_defaults() {
        let mut o = MasqueOption::default();
        assert_eq!(o.effective_uri(), CONNECT_URI);
        assert_eq!(
            o.effective_sni(MasqueMode::Tun),
            CONNECT_SNI,
        );
        assert_eq!(o.effective_sni(MasqueMode::L4Proxy), L4_CONNECT_SNI);
        assert_eq!(o.effective_mtu(), DEFAULT_MTU);
        o.sni = "custom.example".into();
        o.uri = "https://cf.example/masque".into();
        o.mtu = 1400;
        assert_eq!(o.effective_sni(MasqueMode::Tun), "custom.example");
        assert_eq!(o.effective_uri(), "https://cf.example/masque");
        assert_eq!(o.effective_mtu(), 1400);
    }

    #[test]
    fn settings_scan_accepts_both_datagram_ids() {
        let settings = |id: u64| {
            let mut p = Vec::new();
            write_varint(&mut p, id);
            write_varint(&mut p, 1);
            let mut f = Vec::new();
            put_h3_frame(&mut f, H3_FRAME_SETTINGS, &p);
            f
        };
        assert_eq!(scan_settings_datagram(&settings(0x33)), Some(true));
        assert_eq!(scan_settings_datagram(&settings(0x276)), Some(true));
        // Disabled / absent.
        let mut empty = Vec::new();
        put_h3_frame(&mut empty, H3_FRAME_SETTINGS, &[]);
        assert_eq!(scan_settings_datagram(&empty), Some(false));
        // Incomplete input waits; other frames are stepped over.
        assert_eq!(scan_settings_datagram(&[0x04]), None);
        let mut mixed = Vec::new();
        put_h3_frame(&mut mixed, H3_FRAME_DATA, b"skip");
        mixed.extend_from_slice(&settings(0x33));
        assert_eq!(scan_settings_datagram(&mixed), Some(true));
    }

    #[test]
    fn headers_frame_find_and_skip() {
        let block = vec![0x00, 0x00];
        let mut stream = Vec::new();
        put_h3_frame(&mut stream, H3_FRAME_DATA, b"skip");
        put_h3_frame(&mut stream, H3_FRAME_HEADERS, &block);
        put_h3_frame(&mut stream, H3_FRAME_DATA, b"after");
        assert_eq!(find_headers_frame(&stream).unwrap().unwrap(), &block[..]);
        let consumed = headers_frame_consumed(&stream).unwrap();
        // `after` rides in its own DATA frame: skip its 2-byte header.
        assert_eq!(&stream[consumed..][2..], b"after");
        // Truncation inside the HEADERS frame (and inside a leading DATA
        // frame) waits for more bytes.
        assert!(find_headers_frame(&stream[..9]).unwrap().is_none());
        assert!(find_headers_frame(&stream[..4]).unwrap().is_none());
    }

    // -------------------------------------------------- quinn loopback peers
    //
    // A hand-rolled H3 server behind a real rustls/quinn endpoint: it
    // requires the client certificate (pinning the expected public
    // point), reads the client control SETTINGS, sends its own with
    // datagrams enabled, then speaks the exact masque frames (plain
    // CONNECT echo / extended CONNECT-IP with capsules and datagrams).

    use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
    use tokio::io::AsyncWriteExt as _; // quinn SendStream flush()

    #[derive(Debug)]
    struct TestClientCertVerifier {
        expected_point: Vec<u8>,
        provider: Arc<CryptoProvider>,
    }

    impl ClientCertVerifier for TestClientCertVerifier {
        fn root_hint_subjects(&self) -> &[rustls::DistinguishedName] {
            &[]
        }

        fn verify_client_cert(
            &self,
            end_entity: &CertificateDer<'_>,
            _intermediates: &[CertificateDer<'_>],
            _now: rustls::pki_types::UnixTime,
        ) -> std::result::Result<ClientCertVerified, rustls::Error> {
            match cert_spki(end_entity.as_ref()) {
                Ok(spki) if spki.point == self.expected_point => {
                    Ok(ClientCertVerified::assertion())
                }
                _ => Err(rustls::Error::General("unrecognized client cert".into())),
            }
        }

        fn verify_tls12_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls12_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn verify_tls13_signature(
            &self,
            message: &[u8],
            cert: &CertificateDer<'_>,
            dss: &DigitallySignedStruct,
        ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
            verify_tls13_signature(
                message,
                cert,
                dss,
                &self.provider.signature_verification_algorithms,
            )
        }

        fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
            self.provider
                .signature_verification_algorithms
                .supported_schemes()
        }
    }

    #[derive(Debug)]
    enum SrvEvent {
        ClientCertOk,
        Settings { datagram: bool },
        L4Connect { authority: String },
        L4Rejected { authority: String },
        IpConnect {
            authority: String,
            path: String,
            protocol: String,
            capsule_protocol: Option<String>,
            user_agent: Option<String>,
        },
        RouteAdvertisement(Vec<IpRoute>),
        AddressAssignSent,
        StreamReset(quinn::VarInt),
    }

    struct TestServer {
        addr: std::net::SocketAddr,
        /// The server certificate's EC point — what the client pins.
        public_point: Vec<u8>,
        events: tokio::sync::mpsc::UnboundedReceiver<SrvEvent>,
    }

    fn ecdsa_cert() -> (CertificateDer<'static>, rustls::pki_types::PrivateKeyDer<'static>, Vec<u8>)
    {
        let (pkcs8, point) = generate_p256();
        let pair = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
            &rustls::pki_types::PrivatePkcs8KeyDer::from(pkcs8.as_slice()),
            &rcgen::PKCS_ECDSA_P256_SHA256,
        )
        .unwrap();
        let params = rcgen::CertificateParams::new(vec!["masque.test".to_string()]).unwrap();
        let cert = params.self_signed(&pair).unwrap();
        (
            CertificateDer::from(cert.der().to_vec()),
            rustls::pki_types::PrivateKeyDer::Pkcs8(pkcs8.into()),
            point,
        )
    }

    fn spki_der_of_point(point: &[u8]) -> Vec<u8> {
        der::seq(&[
            &der::seq(&[
                &der::oid(&[1, 2, 840, 10045, 2, 1]),
                &der::oid(&[1, 2, 840, 10045, 3, 1, 7]),
            ]),
            &der::bitstring(point),
        ])
    }

    async fn read_stream_request(
        recv: &mut quinn::RecvStream,
        buf: &mut BytesMut,
    ) -> Result<Vec<(String, String)>> {
        let mut chunk = [0u8; 2048];
        loop {
            if let Some(block) = find_headers_frame(buf)? {
                let fields = decode_field_section(block)?;
                let consumed = headers_frame_consumed(buf).unwrap();
                buf.advance(consumed);
                return Ok(fields);
            }
            let n = recv
                .read(&mut chunk)
                .await
                .map_err(|e| Error::network(format!("srv read: {e}")))?
                .ok_or_else(|| Error::protocol("srv: EOF before request"))?;
            buf.extend_from_slice(&chunk[..n]);
        }
    }

    fn response_headers_frame(status: u16) -> Vec<u8> {
        let mut block = vec![0x00, 0x00];
        put_qpack_literal(&mut block, b":status", status.to_string().as_bytes());
        let mut frame = Vec::new();
        put_h3_frame(&mut frame, H3_FRAME_HEADERS, &block);
        frame
    }

    /// Echo the PAYLOADS of received DATA frames (a real HTTP/3 peer
    /// deframes before answering; re-framing raw stream chunks would
    /// double-encapsulate). `leftover` carries bytes already read past
    /// the request HEADERS frame.
    async fn echo_data_frames(
        recv: &mut quinn::RecvStream,
        send: &mut quinn::SendStream,
        mut leftover: BytesMut,
    ) {
        let mut chunk = [0u8; 4096];
        loop {
            while let Some((ftype, a)) = read_varint(&leftover) {
                let Some(rest) = leftover.get(a..) else {
                    break;
                };
                let Some((len, b)) = read_varint(rest) else {
                    break;
                };
                let Ok(len) = usize::try_from(len) else {
                    return;
                };
                let start = a + b;
                if leftover.get(start..start + len).is_none() {
                    break;
                }
                if ftype == H3_FRAME_DATA {
                    let payload = leftover[start..start + len].to_vec();
                    let mut frame = Vec::with_capacity(payload.len() + 9);
                    put_h3_frame(&mut frame, H3_FRAME_DATA, &payload);
                    if send.write_all(&frame).await.is_err() {
                        return;
                    }
                    let _ = send.flush().await;
                }
                leftover.advance(start + len);
            }
            match recv.read(&mut chunk).await {
                Ok(Some(n)) => leftover.extend_from_slice(&chunk[..n]),
                _ => return,
            }
        }
    }

    /// Echo a context-0 IP datagram back with src/dst swapped: rebuild
    /// the UDP packet with addresses (and ports) reversed — the relay's
    /// answer form.
    fn echo_ip_packet(packet: &[u8]) -> Option<Vec<u8>> {
        let (src, dport, payload) = parse_udp_ip_packet(packet).ok()??;
        let src_ip = match src.host {
            Host::Ip(ip) => ip,
            _ => return None,
        };
        let dst_ip = match ip_version(packet)? {
            4 => IpAddr::V4(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19])),
            _ => {
                let mut o = [0u8; 16];
                o.copy_from_slice(&packet[24..40]);
                IpAddr::V6(o.into())
            }
        };
        Some(match (src_ip, dst_ip) {
            (IpAddr::V4(s), IpAddr::V4(d)) => build_udp4_packet(d, s, dport, src.port, &payload),
            (IpAddr::V6(s), IpAddr::V6(d)) => build_udp6_packet(d, s, dport, src.port, &payload),
            _ => return None,
        })
    }

    async fn spawn_masque_server(client_point: Vec<u8>) -> TestServer {
        let (cert, key, public_point) = ecdsa_cert();
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let mut tls = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(Arc::new(TestClientCertVerifier {
                expected_point: client_point,
                provider,
            }))
            .with_single_cert(vec![cert], key)
            .unwrap();
        tls.alpn_protocols = vec![ALPN_H3.as_bytes().to_vec()];
        let quic_tls = quinn::crypto::rustls::QuicServerConfig::try_from(Arc::new(tls)).unwrap();
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(quic_tls));
        let mut transport = quinn::TransportConfig::default();
        transport.max_concurrent_uni_streams(1024u32.into());
        transport.datagram_receive_buffer_size(Some(64 * 1024));
        config.transport_config(Arc::new(transport));
        let endpoint = quinn::Endpoint::server(config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = endpoint.local_addr().unwrap();
        let (tx, events) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Some(incoming) = endpoint.accept().await {
                let tx = tx.clone();
                tokio::spawn(async move {
                    let conn = match incoming.await {
                        Ok(c) => c,
                        Err(_) => return,
                    };
                    tx.send(SrvEvent::ClientCertOk).ok();
                    // Drain client uni streams; send our own SETTINGS with
                    // datagrams enabled (RFC 9220 id) on the control stream.
                    let conn2 = conn.clone();
                    let uni = tokio::spawn(async move {
                        while let Ok(mut s) = conn2.accept_uni().await {
                            let mut head = [0u8; 1];
                            if s.read_exact(&mut head).await.is_err() {
                                continue;
                            }
                            if head[0] == H3_STREAM_CONTROL {
                                let mut buf = Vec::new();
                                let mut chunk = [0u8; 1024];
                                while let Ok(Some(n)) = s.read(&mut chunk).await {
                                    buf.extend_from_slice(&chunk[..n]);
                                    if scan_settings_datagram(&buf).is_some() {
                                        break;
                                    }
                                }
                            }
                        }
                    });
                    let mut control = conn.open_uni().await.unwrap();
                    let mut settings = Vec::new();
                    write_varint(&mut settings, H3_STREAM_CONTROL as u64);
                    let mut payload = Vec::new();
                    write_varint(&mut payload, SETTINGS_H3_DATAGRAM);
                    write_varint(&mut payload, 1);
                    put_h3_frame(&mut settings, H3_FRAME_SETTINGS, &payload);
                    control.write_all(&settings).await.unwrap();
                    tx.send(SrvEvent::Settings { datagram: true }).ok();

                    // Bi-stream request loop.
                    while let Ok((mut send, mut recv)) = conn.accept_bi().await {
                        let tx = tx.clone();
                        let conn = conn.clone();
                        tokio::spawn(async move {
                            let mut buf = BytesMut::with_capacity(2048);
                            let fields = match read_stream_request(&mut recv, &mut buf).await {
                                Ok(f) => f,
                                Err(_) => return,
                            };
                            let get = |k: &str| {
                                fields
                                    .iter()
                                    .find(|(n, _)| n == k)
                                    .map(|(_, v)| v.clone())
                            };
                            let Some(protocol) = get(":protocol") else {
                                // Plain CONNECT (l4proxy.go).
                                let authority = get(":authority").unwrap_or_default();
                                assert_eq!(get(":method").as_deref(), Some("CONNECT"));
                                assert_eq!(get(":path"), None);
                                assert_eq!(get(":scheme"), None);
                                if authority.starts_with("forbidden") {
                                    tx.send(SrvEvent::L4Rejected { authority }).ok();
                                    send.write_all(&response_headers_frame(403))
                                        .await
                                        .ok();
                                    let _ = send.flush().await;
                                    return;
                                }
                                tx.send(SrvEvent::L4Connect { authority }).ok();
                                send.write_all(&response_headers_frame(200))
                                    .await
                                    .ok();
                                let _ = send.flush().await;
                                // Echo DATA frame payloads until EOF.
                                echo_data_frames(&mut recv, &mut send, buf).await;
                                return;
                            };
                            // Extended CONNECT (cf-connect-ip).
                            tx.send(SrvEvent::IpConnect {
                                authority: get(":authority").unwrap_or_default(),
                                path: get(":path").unwrap_or_default(),
                                protocol,
                                capsule_protocol: get(CAPSULE_PROTOCOL_HEADER),
                                user_agent: get("user-agent"),
                            })
                            .ok();
                            send.write_all(&response_headers_frame(200))
                                .await
                                .ok();
                            let _ = send.flush().await;
                            // Expect the ROUTE_ADVERTISEMENT capsule next.
                            let mut chunk = [0u8; 2048];
                            loop {
                                if let Ok(Some((ctype, payload, consumed))) = parse_capsule(&buf) {
                                    if ctype == CAPSULE_ROUTE_ADVERTISEMENT {
                                        let routes = parse_route_advertisement(payload).unwrap();
                                        tx.send(SrvEvent::RouteAdvertisement(routes)).ok();
                                        let assign = address_assign_capsule(&[
                                            AssignedAddress {
                                                request_id: 0,
                                                prefix: IpPrefix {
                                                    addr: "100.96.0.2".parse().unwrap(),
                                                    bits: 32,
                                                },
                                            },
                                            AssignedAddress {
                                                request_id: 0,
                                                prefix: IpPrefix {
                                                    addr: "fd00:cafe::2".parse().unwrap(),
                                                    bits: 128,
                                                },
                                            },
                                        ])
                                        .unwrap();
                                        send.write_all(&assign).await.ok();
                                        let _ = send.flush().await;
                                        tx.send(SrvEvent::AddressAssignSent).ok();
                                        buf.advance(consumed);
                                        break;
                                    }
                                    buf.advance(consumed);
                                    continue;
                                }
                                match recv.read(&mut chunk).await {
                                    Ok(Some(n)) => buf.extend_from_slice(&chunk[..n]),
                                    _ => return,
                                }
                            }
                            // Reset watcher + context-0 datagram echo.
                            let mut read_task = Box::pin(async {
                                let mut chunk = [0u8; 2048];
                                loop {
                                    match recv.read(&mut chunk).await {
                                        Ok(Some(n)) => buf.extend_from_slice(&chunk[..n]),
                                        Ok(None) => break,
                                        Err(quinn::ReadError::Reset(code)) => {
                                            tx.send(SrvEvent::StreamReset(code)).ok();
                                            break;
                                        }
                                        Err(_) => break,
                                    }
                                }
                            });
                            let dg_conn = conn.clone();
                            loop {
                                tokio::select! {
                                    _ = &mut read_task => {
                                        break;
                                    }
                                    dg = dg_conn.read_datagram() => match dg {
                                        Ok(data) => {
                                            if let Some((ctx, n)) = read_varint(&data) {
                                                if ctx == 0 {
                                                    if let Some(reply) = echo_ip_packet(&data[n..]) {
                                                        let mut out = Vec::new();
                                                        write_varint(&mut out, 0);
                                                        out.extend_from_slice(&reply);
                                                        dg_conn.send_datagram(Bytes::from(out)).ok();
                                                    }
                                                }
                                            }
                                        }
                                        Err(_) => break,
                                    },
                                }
                            }
                        });
                    }
                    uni.abort();
                });
            }
        });
        TestServer {
            addr,
            public_point,
            events,
        }
    }

    fn b64(data: &[u8]) -> String {
        use base64::Engine as _;
        base64::engine::general_purpose::STANDARD.encode(data)
    }

    fn test_option(port: u16, network: &str, server_point: &[u8], client_sec1: &[u8]) -> MasqueOption {
        let mut o = MasqueOption {
            server: "127.0.0.1".into(),
            port,
            private_key: b64(client_sec1),
            public_key: b64(&spki_der_of_point(server_point)),
            ip: "100.64.0.2".into(),
            ipv6: "fd00:2021:1111::2".into(),
            handshake_timeout: 15,
            network: network.into(),
            sni: "masque.test".into(),
            ..Default::default()
        };
        if network == "h3-l4proxy" {
            o.sni = L4_CONNECT_SNI.into();
        }
        o
    }

    async fn next_event(srv: &mut TestServer) -> SrvEvent {
        tokio::time::timeout(Duration::from_secs(10), srv.events.recv())
            .await
            .expect("server event timeout")
            .expect("server channel closed")
    }

    async fn connect_err(o: MasqueOption) -> String {
        match MasqueClient::connect(o).await {
            Ok(_) => panic!("masque connect unexpectedly succeeded"),
            Err(e) => e.to_string(),
        }
    }

    #[tokio::test]
    async fn l4_tcp_relay_over_h3_connect() {
        // One client keypair shared by the server's cert pin and the
        // client's own enrollment material.
        let (sec1, client_point) = test_ec_key_material();
        let mut srv = spawn_masque_server(client_point).await;
        let mut o = test_option(srv.addr.port(), "h3-l4proxy", &srv.public_point, &sec1);
        o.sni = "masque.test".into();
        let client = MasqueClient::connect(o).await.unwrap();
        // The server saw the client cert (pin verified) and SETTINGS.
        assert!(matches!(next_event(&mut srv).await, SrvEvent::ClientCertOk));
        assert!(matches!(
            next_event(&mut srv).await,
            SrvEvent::Settings { datagram: true }
        ));

        let target = NetAddr::domain("echo.example", 443).unwrap();
        let mut stream = client.dial_tcp(&target).await.unwrap();
        match next_event(&mut srv).await {
            SrvEvent::L4Connect { authority } => assert_eq!(authority, "echo.example:443"),
            other => panic!("wrong event {other:?}"),
        }
        use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
        stream.write_all(b"ping-masque").await.unwrap();
        let mut buf = [0u8; 11];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"ping-masque");
        // A multi-frame payload round-trips through DATA framing.
        let payload: Vec<u8> = (0..9000u32).map(|i| (i % 251) as u8).collect();
        stream.write_all(&payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(15), stream.read_exact(&mut got))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, payload);

        // A non-2xx CONNECT surfaces upstream's status error string.
        let err = match client
            .dial_tcp(&NetAddr::domain("forbidden.test", 80).unwrap())
            .await
        {
            Ok(_) => panic!("403 CONNECT must fail"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("CONNECT rejected with status 403"), "{err}");
        // The server saw (and rejected) the forbidden authority.
        match next_event(&mut srv).await {
            SrvEvent::L4Rejected { authority } => assert_eq!(authority, "forbidden.test:80"),
            other => panic!("wrong event {other:?}"),
        }
    }

    #[tokio::test]
    async fn tun_mode_tcp_and_l4_udp_are_rejected_with_precise_errors() {
        // Tun TCP: precise TUN-device rejection, upstream pointers inside.
        let err = tun_tcp_unimplemented("auto").to_string();
        assert!(
            err.contains("TUN/ip-stack mode \"auto\" TCP is not implemented"),
            "{err}"
        );
        assert!(err.contains("TUN device"), "{err}");
        assert!(err.contains("h3-l4proxy"), "{err}");
        // L4 UDP: the exact upstream error string.
        assert_eq!(
            Error::config(L4_UDP_UNSUPPORTED).to_string(),
            "config: masque L4 proxy mode is not supported for UDP"
        );
        // h2 network: rejected before any dial.
        let (sec1, _) = test_ec_key_material();
        let mut o = test_option(1, "h2", &[0x04, 0x02], &sec1);
        o.port = 1;
        let err = connect_err(o).await;
        assert!(err.contains("network h2 is not implemented"), "{err}");
        assert!(err.contains("HTTP/2 CONNECT-IP"), "{err}");
        // gVisor ip-stack rejected with the upstream build-tag error.
        let (sec1, _) = test_ec_key_material();
        let mut o = test_option(1, "", &[0x04, 0x02], &sec1);
        o.ip_stack.mode = "gvisor".into();
        o.port = 1;
        let err = connect_err(o).await;
        assert!(err.contains("with_gvisor"), "{err}");
    }

    #[tokio::test]
    async fn connect_ip_udp_roundtrip_and_capsule_close() {
        let (sec1, client_point) = test_ec_key_material();
        let mut srv = spawn_masque_server(client_point).await;
        let mut o = test_option(srv.addr.port(), "", &srv.public_point, &sec1);
        o.sni = "masque.test".into();
        let client = MasqueClient::connect(o).await.unwrap();
        let udp = client.open_udp().await.unwrap();

        // ClientCertOk, Settings, then the exact extended-CONNECT shape.
        assert!(matches!(next_event(&mut srv).await, SrvEvent::ClientCertOk));
        assert!(matches!(
            next_event(&mut srv).await,
            SrvEvent::Settings { datagram: true }
        ));
        match next_event(&mut srv).await {
            SrvEvent::IpConnect {
                authority,
                path,
                protocol,
                capsule_protocol,
                user_agent,
            } => {
                assert_eq!(authority, "cloudflareaccess.com");
                assert_eq!(path, "/");
                assert_eq!(protocol, CONNECT_IP_PROTOCOL);
                assert_eq!(capsule_protocol.as_deref(), Some("?1"));
                assert_eq!(user_agent.as_deref(), Some(""));
            }
            other => panic!("wrong event {other:?}"),
        }
        match next_event(&mut srv).await {
            SrvEvent::RouteAdvertisement(routes) => {
                assert_eq!(routes.len(), 2);
                assert_eq!(routes[0].ip_protocol, 0);
                assert_eq!(routes[0].start, IpAddr::V4(Ipv4Addr::UNSPECIFIED));
                assert_eq!(routes[0].end, IpAddr::V4(Ipv4Addr::BROADCAST));
            }
            other => panic!("wrong event {other:?}"),
        }
        assert!(matches!(next_event(&mut srv).await, SrvEvent::AddressAssignSent));
        // The client picked up the ADDRESS_ASSIGN prefixes.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            udp.tunnel.local_prefixes(),
            vec![
                IpPrefix {
                    addr: "100.96.0.2".parse().unwrap(),
                    bits: 32
                },
                IpPrefix {
                    addr: "fd00:cafe::2".parse().unwrap(),
                    bits: 128
                },
            ]
        );

        // UDP capsule roundtrip through the datagram path.
        let target = NetAddr::ip("8.8.8.8".parse().unwrap(), 53);
        udp.send_to(&target, b"masque-udp-query").await.unwrap();
        let (from, payload) = tokio::time::timeout(Duration::from_secs(10), udp.recv_from())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(from.host.to_text(), "8.8.8.8");
        assert_eq!(from.port, 53);
        assert_eq!(payload, b"masque-udp-query".to_vec());

        // Capsule close: the tunnel resets the stream with H3_NO_ERROR.
        udp.tunnel.close().await.unwrap();
        match next_event(&mut srv).await {
            SrvEvent::StreamReset(code) => {
                assert_eq!(code, quinn::VarInt::from_u64(0x100).unwrap())
            }
            other => panic!("expected reset, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn pinned_public_key_mismatch_fails_handshake() {
        let (sec1, client_point) = test_ec_key_material();
        let srv = spawn_masque_server(client_point).await;
        let mut o = test_option(srv.addr.port(), "h3-l4proxy", &[0x04, 0x02], &sec1); // wrong pin
        o.sni = "masque.test".into();
        let err = connect_err(o).await;
        assert!(
            err.contains("different public key than what we trust")
                || err.contains("handshake")
                || err.contains("alert")
                || err.contains("peer"),
            "{err}"
        );
    }
}
