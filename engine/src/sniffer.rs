//! Traffic sniffer: extracts the TLS ClientHello server_name, the HTTP
//! request Host, or the QUIC Initial ClientHello server_name from the
//! first bytes of a connection, so transparent inbounds
//! (redir/tproxy with IP destinations) can still route by domain —
//! mirroring mihomo's `sniffer` config.

use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit as _};
use aes_gcm::aead::{Aead as _, Payload};
use aes_gcm::Aes128Gcm;
use hkdf::Hkdf;
use sha2::Sha256;

use crate::addr::{Host, NetAddr};

/// What the sniffer learned from a stream's first bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SniffResult {
    /// TLS ClientHello server_name.
    Tls(String),
    /// HTTP/1.1 request Host header.
    Http(String),
    /// QUIC v1 Initial CRYPTO stream ClientHello server_name.
    Quic(String),
    /// Not enough bytes / unrecognized.
    Unknown,
}

/// Sniff configuration: which protocols to sniff.
#[derive(Debug, Clone, Default)]
pub struct SniffConfig {
    pub tls: bool,
    pub http: bool,
    /// Sniff QUIC v1 Initial packets (UDP-carried TLS 1.3).
    pub quic: bool,
    /// Override the destination with the sniffed domain (mihomo's
    /// override-destination; sing-box always overrides for routing).
    pub override_destination: bool,
    /// Domains to skip (sniff-skip / force-domain exclusions).
    pub skip_domains: Vec<String>,
    /// Domains that always apply the sniffed result, even without
    /// override_destination (mihomo's force-domain). Skip wins over
    /// force.
    pub force_domains: Vec<String>,
    /// Destination-port gates per protocol (mihomo
    /// `sniff: {TLS: {ports: [...]}}`); empty = every port.
    pub tls_ports: Vec<u16>,
    pub http_ports: Vec<u16>,
    pub quic_ports: Vec<u16>,
}

impl SniffConfig {
    pub fn enabled(&self) -> bool {
        self.tls || self.http || self.quic
    }

    fn skips(&self, domain: &str) -> bool {
        self.skip_domains
            .iter()
            .any(|p| crate::rule::domain_matches_suffix(domain, p))
    }

    fn forces(&self, domain: &str) -> bool {
        self.force_domains
            .iter()
            .any(|p| crate::rule::domain_matches_suffix(domain, p))
    }

    fn port_allowed(ports: &[u16], port: u16) -> bool {
        ports.is_empty() || ports.contains(&port)
    }
}

/// The maximum prefix examined: a full ClientHello first flight fits well
/// under 4 KiB (certificates come later).
pub const MAX_SNIFF: usize = 4096;

/// Sniff the first `n` bytes of a stream destined for `port`.
///
/// The parser is deliberately total: malformed input yields `Unknown`,
/// never an error, so the relay can proceed with the original
/// destination. Per-protocol `*_ports` gates mirror mihomo's
/// `sniff: {TLS: {ports: [...]}}`.
pub fn sniff(buf: &[u8], cfg: &SniffConfig, port: u16) -> SniffResult {
    if buf.is_empty() {
        return SniffResult::Unknown;
    }
    if cfg.tls && SniffConfig::port_allowed(&cfg.tls_ports, port) {
        if let Some(sni) = sniff_tls(buf) {
            if !cfg.skips(&sni) {
                return SniffResult::Tls(sni);
            }
        }
    }
    if cfg.http && SniffConfig::port_allowed(&cfg.http_ports, port) {
        if let Some(host) = sniff_http(buf) {
            if !cfg.skips(&host) {
                return SniffResult::Http(host);
            }
        }
    }
    if cfg.quic && SniffConfig::port_allowed(&cfg.quic_ports, port) {
        if let Some(sni) = sniff_quic(buf) {
            if !cfg.skips(&sni) {
                return SniffResult::Quic(sni);
            }
        }
    }
    SniffResult::Unknown
}

/// Decide whether a sniffed domain replaces the connection target —
/// the one place the override policy lives (mihomo: IP targets,
/// `override-destination` or a force-domain match). Skip-domains keeps
/// precedence over force-domains. Returns the replacement target on
/// apply.
pub fn apply_sniffed(target: &NetAddr, sniffed: &SniffResult, cfg: &SniffConfig) -> Option<NetAddr> {
    let domain = match sniffed {
        SniffResult::Tls(d) | SniffResult::Http(d) | SniffResult::Quic(d) => d.as_str(),
        SniffResult::Unknown => return None,
    };
    if cfg.skips(domain) {
        return None;
    }
    let host = Host::parse(domain).ok()?;
    let apply = cfg.forces(domain)
        || match target.host {
            Host::Ip(_) => true,
            Host::Domain(_) => cfg.override_destination,
        };
    if !apply {
        return None;
    }
    Some(NetAddr::new(host, target.port))
}

/// TLS record 0x16 (handshake) → ClientHello → SNI extension.
/// Byte-walked without allocation beyond the returned String.
fn sniff_tls(buf: &[u8]) -> Option<String> {
    if buf.len() < 43 || buf[0] != 0x16 {
        return None;
    }
    // Record header: type(1) version(2) length(2); parse what we have
    // even from a partial record.
    clienthello_sni(&buf[5..])
}

/// ClientHello handshake message → SNI extension, shared by the TLS
/// record walk and the QUIC CRYPTO stream walk. `body` starts at the
/// 4-byte handshake header (type 0x01 + 3-byte length); parsing works
/// on truncated input. Byte-walked without allocation beyond the
/// returned String.
fn clienthello_sni(body: &[u8]) -> Option<String> {
    if body.is_empty() || body[0] != 0x01 {
        return None; // not a ClientHello
    }
    // Handshake header: type(1) len(3); then ClientHello:
    // legacy_version(2) random(32) session_id_len(1) session_id
    let mut off = 4usize;
    if body.len() < off + 34 {
        return None;
    }
    off += 2 + 32;
    let sid_len = body.get(off).copied()? as usize;
    off += 1 + sid_len;
    // cipher_suites_len(2) cipher_suites comp_len(1) legacy_compression
    let cs_len = u16::from_be_bytes([*body.get(off)?, *body.get(off + 1)?]) as usize;
    off += 2 + cs_len;
    let cm_len = *body.get(off)? as usize;
    off += 1 + cm_len;
    // extensions_len(2) then extensions
    let ext_total = u16::from_be_bytes([*body.get(off)?, *body.get(off + 1)?]) as usize;
    off += 2;
    let ext_end = (off + ext_total).min(body.len());
    while off + 4 <= ext_end {
        let etype = u16::from_be_bytes([body[off], body[off + 1]]);
        let elen = u16::from_be_bytes([body[off + 2], body[off + 3]]) as usize;
        off += 4;
        let ext = body.get(off..off + elen)?;
        if etype == 0x0000 {
            // server_name extension: list_len(2) type(1)==0 name_len(2) name
            if ext.len() < 5 {
                return None;
            }
            let name_type = ext[2];
            if name_type != 0 {
                return None;
            }
            let name_len = u16::from_be_bytes([ext[3], ext[4]]) as usize;
            if ext.len() < 5 + name_len {
                return None;
            }
            let name = std::str::from_utf8(&ext[5..5 + name_len]).ok()?;
            let name = name.to_ascii_lowercase();
            // Sanity: SNI must be a plausible hostname.
            if name.is_empty() || name.len() > 253 || name.contains(char::is_whitespace) {
                return None;
            }
            return Some(name);
        }
        off += elen;
    }
    None
}

/// HTTP/1.1 request-line + Host header from the request head.
fn sniff_http(buf: &[u8]) -> Option<String> {
    let head_end = buf
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        // Not a complete head; sniff anyway if we see a method + Host line.
        .unwrap_or(buf.len().min(1024));
    let head = std::str::from_utf8(&buf[..head_end]).ok()?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next()?;
    // METHOD SP TARGET SP VERSION — methods mihomo sniffs.
    let method = request_line.split(' ').next()?;
    if !matches!(
        method,
        "GET" | "POST" | "PUT" | "DELETE" | "HEAD" | "OPTIONS" | "PATCH" | "CONNECT" | "TRACE"
    ) {
        return None;
    }
    for line in lines {
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("host:") {
            let host = rest.trim();
            // Strip a trailing :port only when the tail is all digits
            // (bracketed v6 hosts are rare in sniffing).
            let bare = host
                .rsplit_once(':')
                .filter(|(_, p)| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
                .map(|(h, _)| h)
                .unwrap_or(host);
            if bare.is_empty() {
                return None;
            }
            return Some(bare.to_ascii_lowercase());
        }
    }
    None
}

// -------------------------------------------------------------------------
// QUIC v1 Initial sniffing (RFC 9000/9001), porting sing-box's
// `common/sniff` QUICClientHello: derive the client Initial keys from
// the DCID, strip header protection, AEAD-decrypt the payload, walk the
// frames and reassemble the CRYPTO stream's ClientHello.

/// RFC 9001 §5.2: HKDF salt for QUIC v1 Initial packets.
const QUIC_V1_SALT: [u8; 20] = [
    0x38, 0x76, 0x2c, 0xf7, 0xf5, 0x59, 0x34, 0xb3, 0x4d, 0x17, 0x9a, 0xe6, 0xa4, 0xc8, 0x0c, 0xad,
    0xcc, 0xbb, 0x7f, 0x0a,
];

/// Client Initial protection keys (RFC 9001 §5.1: Initial always uses
/// AEAD_AES_128_GCM).
struct QuicInitialKeys {
    key: [u8; 16],
    iv: [u8; 12],
    hp: [u8; 16],
}

/// HKDF-Expand-Label info (RFC 8446 §7.1): the `tls13 ` prefix is
/// shared by TLS 1.3 and QUIC's "quic key/iv/hp" labels.
fn quic_label_info(label: &str, len: u16) -> Vec<u8> {
    let full = format!("tls13 {label}");
    let mut info = Vec::with_capacity(4 + full.len());
    info.extend_from_slice(&len.to_be_bytes());
    info.push(full.len() as u8);
    info.extend_from_slice(full.as_bytes());
    info.push(0); // empty context
    info
}

/// client_initial_secret = HKDF-Expand-Label(
///     HKDF-Extract(salt, dcid), "client in", "", 32).
fn quic_client_initial_secret(dcid: &[u8]) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(Some(&QUIC_V1_SALT), dcid);
    let mut secret = [0u8; 32];
    hk.expand(&quic_label_info("client in", 32), &mut secret)
        .expect("32-byte SHA-256 output");
    secret
}

fn quic_initial_keys(dcid: &[u8]) -> QuicInitialKeys {
    let secret = quic_client_initial_secret(dcid);
    let hk = Hkdf::<Sha256>::from_prk(&secret).expect("32-byte PRK");
    let mut keys = QuicInitialKeys {
        key: [0u8; 16],
        iv: [0u8; 12],
        hp: [0u8; 16],
    };
    hk.expand(&quic_label_info("quic key", 16), &mut keys.key)
        .expect("16-byte okm");
    hk.expand(&quic_label_info("quic iv", 12), &mut keys.iv)
        .expect("12-byte okm");
    hk.expand(&quic_label_info("quic hp", 16), &mut keys.hp)
        .expect("16-byte okm");
    keys
}

/// Header-protection mask: one raw AES-128 block encryption of the
/// sample (RFC 9001 §5.4.3).
fn quic_hp_mask(hp: &[u8; 16], sample: &[u8]) -> Option<[u8; 16]> {
    let cipher = aes::Aes128::new(GenericArray::from_slice(hp));
    let mut block = *GenericArray::from_slice(sample.get(..16)?);
    cipher.encrypt_block(&mut block);
    Some(block.into())
}

/// Read one QUIC varint (RFC 9000 §16) at `off`, if present.
fn quic_varint(buf: &[u8], off: usize) -> Option<(u64, usize)> {
    crate::quic::read_varint(buf.get(off..)?)
}

fn quic_skip_varints(buf: &[u8], off: &mut usize, count: usize) -> Option<()> {
    for _ in 0..count {
        let (_, n) = quic_varint(buf, *off)?;
        *off += n;
    }
    Some(())
}

/// QUIC v1 long-header client Initial → decrypted CRYPTO stream →
/// ClientHello SNI. Total parser: any malformation yields `None`.
fn sniff_quic(buf: &[u8]) -> Option<String> {
    // Long header (0b11xxxxxx), Initial packet type (bits 4-5 clear)
    // and version 1. Those bits are unprotected.
    if buf.len() < 6 {
        return None;
    }
    let first = buf[0];
    if first & 0xc0 != 0xc0 || first & 0x30 != 0 {
        return None;
    }
    let version = u32::from_be_bytes([buf[1], buf[2], buf[3], buf[4]]);
    if version != 1 {
        return None;
    }
    let mut off = 5usize;
    let dcid_len = *buf.get(off)? as usize;
    off += 1;
    if dcid_len == 0 || dcid_len > 20 {
        return None;
    }
    let dcid = buf.get(off..off + dcid_len)?;
    off += dcid_len;
    let scid_len = (*buf.get(off)? as usize).min(20);
    off += 1 + scid_len;
    let (token_len, n) = quic_varint(buf, off)?;
    off = off
        .checked_add(n)?
        .checked_add(usize::try_from(token_len).ok()?)?;
    let (payload_len, n) = quic_varint(buf, off)?;
    off += n;
    // The packet-number field ends the header; the payload-length
    // varint covers packet number + ciphertext (incl. 16-byte tag).
    let pn_off = off;
    let end = pn_off.checked_add(usize::try_from(payload_len).ok()?)?;
    if end > buf.len() {
        return None;
    }
    // Remove header protection (RFC 9001 §5.4.1): the sample sits 4
    // bytes past the packet number, inside the ciphertext.
    let keys = quic_initial_keys(dcid);
    let sample = buf.get(pn_off + 4..pn_off + 20)?;
    let mask = quic_hp_mask(&keys.hp, sample)?;
    let first_clear = first ^ (mask[0] & 0x0f);
    let pn_len = (first_clear & 0x03) as usize + 1;
    if pn_off + pn_len > end {
        return None;
    }
    let mut pn_be = [0u8; 4];
    for (i, b) in buf[pn_off..pn_off + pn_len].iter().enumerate() {
        pn_be[4 - pn_len + i] = b ^ mask[1 + i];
    }
    // AEAD: nonce = iv XOR packet number, AAD = unprotected header.
    let mut nonce = keys.iv;
    for i in 0..4 {
        nonce[8 + i] ^= pn_be[i];
    }
    let mut header = buf[..pn_off + pn_len].to_vec();
    header[0] = first_clear;
    header[pn_off..pn_off + pn_len].copy_from_slice(&pn_be[4 - pn_len..]);
    let ciphertext = buf.get(pn_off + pn_len..end)?;
    let aead = Aes128Gcm::new(GenericArray::from_slice(&keys.key));
    let plain = aead
        .decrypt(
            GenericArray::from_slice(&nonce),
            Payload {
                msg: ciphertext,
                aad: &header,
            },
        )
        .ok()?;
    // Walk frames, collecting CRYPTO fragments (offset, data).
    let mut crypto: Vec<(u64, &[u8])> = Vec::new();
    let mut off = 0usize;
    while off < plain.len() {
        let (ftype, n) = quic_varint(&plain, off)?;
        off += n;
        match ftype {
            0x00 | 0x01 => {} // PADDING | PING
            0x02 | 0x03 => {
                // ACK (+ECN): largest acked, ack delay, range count,
                // first range, then (gap, range) pairs.
                quic_skip_varints(&plain, &mut off, 3)?;
                let (ranges, n) = quic_varint(&plain, off)?;
                off += n;
                quic_skip_varints(&plain, &mut off, 1 + 2 * usize::try_from(ranges).ok()?)?;
                if ftype == 0x03 {
                    quic_skip_varints(&plain, &mut off, 3)?;
                }
            }
            0x06 => {
                // CRYPTO: offset varint, length varint, data.
                let (foff, n) = quic_varint(&plain, off)?;
                off += n;
                let (flen, n) = quic_varint(&plain, off)?;
                off += n;
                let flen = usize::try_from(flen).ok()?;
                let fend = off.checked_add(flen)?;
                crypto.push((foff, plain.get(off..fend)?));
                off = fend;
            }
            0x1c | 0x1d => {
                // CONNECTION_CLOSE (transport adds a frame-type field),
                // then a length-prefixed reason phrase.
                quic_skip_varints(&plain, &mut off, if ftype == 0x1c { 2 } else { 1 })?;
                let (rlen, n) = quic_varint(&plain, off)?;
                off = off
                    .checked_add(n)?
                    .checked_add(usize::try_from(rlen).ok()?)?;
            }
            _ => return None, // unrecognized frame: not an Initial hello
        }
    }
    // Reassemble CRYPTO fragments in stream order (starting at offset
    // 0, the ClientHello) and reuse the TLS SNI walk.
    let mut stream = Vec::new();
    let mut index: u64 = 0;
    while let Some(i) = crypto.iter().position(|(foff, _)| *foff == index) {
        let (foff, data) = crypto.remove(i);
        index = foff.saturating_add(data.len() as u64);
        stream.extend_from_slice(data);
    }
    clienthello_sni(&stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cfg() -> SniffConfig {
        SniffConfig {
            tls: true,
            http: true,
            quic: false,
            override_destination: true,
            skip_domains: vec![],
            force_domains: vec![],
            tls_ports: vec![],
            http_ports: vec![],
            quic_ports: vec![],
        }
    }

    fn quic_cfg() -> SniffConfig {
        SniffConfig {
            quic: true,
            ..cfg()
        }
    }

    fn client_hello(sni: &str) -> Vec<u8> {
        // Hand-build a minimal ClientHello with an SNI extension.
        let name = sni.as_bytes();
        let mut ext = Vec::new();
        ext.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes()); // server list len
        ext.push(0x00); // host_name type
        ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        ext.extend_from_slice(name);
        let mut ext_block = Vec::new();
        ext_block.extend_from_slice(&0u16.to_be_bytes()); // extension type = server_name
        ext_block.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        ext_block.extend_from_slice(&ext);

        let mut body = Vec::new();
        body.push(0x01); // handshake type = ClientHello
        body.extend_from_slice(&[0, 0, 0]); // length (patched below)
        body.extend_from_slice(&0x0303u16.to_be_bytes()); // legacy_version
        body.extend(&[0x42u8; 32]); // random
        body.push(0); // session_id_len
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites len
        body.extend_from_slice(&0x1301u16.to_be_bytes()); // one suite
        body.push(1); // compression methods len
        body.push(0); // null compression
        body.extend_from_slice(&(ext_block.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext_block);
        let handshake_len = (body.len() - 4) as u32;
        body[1..4].copy_from_slice(&handshake_len.to_be_bytes()[1..4]);

        let mut rec = Vec::new();
        rec.push(0x16); // handshake record
        rec.extend_from_slice(&0x0301u16.to_be_bytes()); // version
        rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
        rec.extend_from_slice(&body);
        rec
    }

    #[test]
    fn sniffs_tls_sni() {
        let hello = client_hello("Example.COM");
        assert_eq!(
            sniff(&hello, &cfg(), 443),
            SniffResult::Tls("example.com".into())
        );
    }

    #[test]
    fn sniffs_partial_tls() {
        let hello = client_hello("tls.partial.test");
        // Truncate mid-record: the walk stays in bounds or returns Unknown.
        let cut = &hello[..hello.len() - 20];
        match sniff(cut, &cfg(), 443) {
            SniffResult::Tls(d) => assert_eq!(d, "tls.partial.test"),
            SniffResult::Unknown => {} // truncation before SNI is legal
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn sniffs_http_host() {
        let req = b"GET /path HTTP/1.1\r\nHost: Example.com:443\r\nUser-Agent: x\r\n\r\nbody";
        assert_eq!(
            sniff(req, &cfg(), 443),
            SniffResult::Http("example.com".into())
        );
        // Host without port.
        let req2 = b"POST /x HTTP/1.1\r\nHost: plain.test\r\n\r\n";
        assert_eq!(sniff(req2, &cfg(), 443), SniffResult::Http("plain.test".into()));
    }

    #[test]
    fn http_without_host_is_unknown() {
        let req = b"GET / HTTP/1.1\r\nUser-Agent: x\r\n\r\n";
        assert_eq!(sniff(req, &cfg(), 443), SniffResult::Unknown);
    }

    #[test]
    fn junk_is_unknown() {
        assert_eq!(sniff(b"\x00\x01\x02", &cfg(), 443), SniffResult::Unknown);
        assert_eq!(sniff(b"", &cfg(), 443), SniffResult::Unknown);
        // Non-TLS record type.
        assert_eq!(sniff(b"\x17\x03\x03\x00\x01\x00", &cfg(), 443), SniffResult::Unknown);
    }

    #[test]
    fn protocol_gates_respected() {
        let hello = client_hello("gated.test");
        let tls_off = SniffConfig {
            tls: false,
            http: true,
            ..cfg()
        };
        assert_eq!(sniff(&hello, &tls_off, 443), SniffResult::Unknown);
        let http_off = SniffConfig {
            tls: true,
            http: false,
            ..cfg()
        };
        assert_eq!(
            sniff(b"GET / HTTP/1.1\r\nHost: h.test\r\n\r\n", &http_off, 443),
            SniffResult::Unknown
        );
    }

    #[test]
    fn port_gates_respected() {
        let hello = client_hello("gated.test");
        // TLS only on 443 → a hello to 8443 stays unknown.
        let tls_443 = SniffConfig {
            tls_ports: vec![443],
            ..cfg()
        };
        assert!(matches!(
            sniff(&hello, &tls_443, 443),
            SniffResult::Tls(_)
        ));
        assert_eq!(sniff(&hello, &tls_443, 8443), SniffResult::Unknown);
        // HTTP gate.
        let http_80 = SniffConfig {
            http_ports: vec![80, 8080],
            ..cfg()
        };
        let req = b"GET / HTTP/1.1\r\nHost: gated.test\r\n\r\n";
        assert_eq!(
            sniff(req, &http_80, 8080),
            SniffResult::Http("gated.test".into())
        );
        assert_eq!(sniff(req, &http_80, 3128), SniffResult::Unknown);
        // QUIC gate.
        let quic_443 = SniffConfig {
            quic_ports: vec![443],
            ..quic_cfg()
        };
        assert!(matches!(
            sniff(RFC_A2_PACKET, &quic_443, 443),
            SniffResult::Quic(_)
        ));
        assert_eq!(
            sniff(RFC_A2_PACKET, &quic_443, 8443),
            SniffResult::Unknown
        );
    }

    #[test]
    fn skip_domains_suppress() {
        let hello = client_hello("skip.me");
        let c = SniffConfig {
            skip_domains: vec!["skip.me".into()],
            ..cfg()
        };
        assert_eq!(sniff(&hello, &c, 443), SniffResult::Unknown);
    }

    #[test]
    fn garbage_sni_rejected() {
        // Hand-built hello with SNI containing a space → rejected.
        let hello = client_hello("bad host.test");
        assert_eq!(sniff(&hello, &cfg(), 443), SniffResult::Unknown);
    }

    // --- QUIC ------------------------------------------------------------

    // RFC 9001 Appendix A.2 protected client Initial (SNI example.com).
    const RFC_A2_PACKET: &[u8] = &[
        0xc0, 0x00, 0x00, 0x00, 0x01, 0x08, 0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08, 0x00, 0x00,
        0x44, 0x9e, 0x7b, 0x9a, 0xec, 0x34, 0xd1, 0xb1, 0xc9, 0x8d, 0xd7, 0x68, 0x9f, 0xb8, 0xec, 0x11,
        0xd2, 0x42, 0xb1, 0x23, 0xdc, 0x9b, 0xd8, 0xba, 0xb9, 0x36, 0xb4, 0x7d, 0x92, 0xec, 0x35, 0x6c,
        0x0b, 0xab, 0x7d, 0xf5, 0x97, 0x6d, 0x27, 0xcd, 0x44, 0x9f, 0x63, 0x30, 0x00, 0x99, 0xf3, 0x99,
        0x1c, 0x26, 0x0e, 0xc4, 0xc6, 0x0d, 0x17, 0xb3, 0x1f, 0x84, 0x29, 0x15, 0x7b, 0xb3, 0x5a, 0x12,
        0x82, 0xa6, 0x43, 0xa8, 0xd2, 0x26, 0x2c, 0xad, 0x67, 0x50, 0x0c, 0xad, 0xb8, 0xe7, 0x37, 0x8c,
        0x8e, 0xb7, 0x53, 0x9e, 0xc4, 0xd4, 0x90, 0x5f, 0xed, 0x1b, 0xee, 0x1f, 0xc8, 0xaa, 0xfb, 0xa1,
        0x7c, 0x75, 0x0e, 0x2c, 0x7a, 0xce, 0x01, 0xe6, 0x00, 0x5f, 0x80, 0xfc, 0xb7, 0xdf, 0x62, 0x12,
        0x30, 0xc8, 0x37, 0x11, 0xb3, 0x93, 0x43, 0xfa, 0x02, 0x8c, 0xea, 0x7f, 0x7f, 0xb5, 0xff, 0x89,
        0xea, 0xc2, 0x30, 0x82, 0x49, 0xa0, 0x22, 0x52, 0x15, 0x5e, 0x23, 0x47, 0xb6, 0x3d, 0x58, 0xc5,
        0x45, 0x7a, 0xfd, 0x84, 0xd0, 0x5d, 0xff, 0xfd, 0xb2, 0x03, 0x92, 0x84, 0x4a, 0xe8, 0x12, 0x15,
        0x46, 0x82, 0xe9, 0xcf, 0x01, 0x2f, 0x90, 0x21, 0xa6, 0xf0, 0xbe, 0x17, 0xdd, 0xd0, 0xc2, 0x08,
        0x4d, 0xce, 0x25, 0xff, 0x9b, 0x06, 0xcd, 0xe5, 0x35, 0xd0, 0xf9, 0x20, 0xa2, 0xdb, 0x1b, 0xf3,
        0x62, 0xc2, 0x3e, 0x59, 0x6d, 0x11, 0xa4, 0xf5, 0xa6, 0xcf, 0x39, 0x48, 0x83, 0x8a, 0x3a, 0xec,
        0x4e, 0x15, 0xda, 0xf8, 0x50, 0x0a, 0x6e, 0xf6, 0x9e, 0xc4, 0xe3, 0xfe, 0xb6, 0xb1, 0xd9, 0x8e,
        0x61, 0x0a, 0xc8, 0xb7, 0xec, 0x3f, 0xaf, 0x6a, 0xd7, 0x60, 0xb7, 0xba, 0xd1, 0xdb, 0x4b, 0xa3,
        0x48, 0x5e, 0x8a, 0x94, 0xdc, 0x25, 0x0a, 0xe3, 0xfd, 0xb4, 0x1e, 0xd1, 0x5f, 0xb6, 0xa8, 0xe5,
        0xeb, 0xa0, 0xfc, 0x3d, 0xd6, 0x0b, 0xc8, 0xe3, 0x0c, 0x5c, 0x42, 0x87, 0xe5, 0x38, 0x05, 0xdb,
        0x05, 0x9a, 0xe0, 0x64, 0x8d, 0xb2, 0xf6, 0x42, 0x64, 0xed, 0x5e, 0x39, 0xbe, 0x2e, 0x20, 0xd8,
        0x2d, 0xf5, 0x66, 0xda, 0x8d, 0xd5, 0x99, 0x8c, 0xca, 0xbd, 0xae, 0x05, 0x30, 0x60, 0xae, 0x6c,
        0x7b, 0x43, 0x78, 0xe8, 0x46, 0xd2, 0x9f, 0x37, 0xed, 0x7b, 0x4e, 0xa9, 0xec, 0x5d, 0x82, 0xe7,
        0x96, 0x1b, 0x7f, 0x25, 0xa9, 0x32, 0x38, 0x51, 0xf6, 0x81, 0xd5, 0x82, 0x36, 0x3a, 0xa5, 0xf8,
        0x99, 0x37, 0xf5, 0xa6, 0x72, 0x58, 0xbf, 0x63, 0xad, 0x6f, 0x1a, 0x0b, 0x1d, 0x96, 0xdb, 0xd4,
        0xfa, 0xdd, 0xfc, 0xef, 0xc5, 0x26, 0x6b, 0xa6, 0x61, 0x17, 0x22, 0x39, 0x5c, 0x90, 0x65, 0x56,
        0xbe, 0x52, 0xaf, 0xe3, 0xf5, 0x65, 0x63, 0x6a, 0xd1, 0xb1, 0x7d, 0x50, 0x8b, 0x73, 0xd8, 0x74,
        0x3e, 0xeb, 0x52, 0x4b, 0xe2, 0x2b, 0x3d, 0xcb, 0xc2, 0xc7, 0x46, 0x8d, 0x54, 0x11, 0x9c, 0x74,
        0x68, 0x44, 0x9a, 0x13, 0xd8, 0xe3, 0xb9, 0x58, 0x11, 0xa1, 0x98, 0xf3, 0x49, 0x1d, 0xe3, 0xe7,
        0xfe, 0x94, 0x2b, 0x33, 0x04, 0x07, 0xab, 0xf8, 0x2a, 0x4e, 0xd7, 0xc1, 0xb3, 0x11, 0x66, 0x3a,
        0xc6, 0x98, 0x90, 0xf4, 0x15, 0x70, 0x15, 0x85, 0x3d, 0x91, 0xe9, 0x23, 0x03, 0x7c, 0x22, 0x7a,
        0x33, 0xcd, 0xd5, 0xec, 0x28, 0x1c, 0xa3, 0xf7, 0x9c, 0x44, 0x54, 0x6b, 0x9d, 0x90, 0xca, 0x00,
        0xf0, 0x64, 0xc9, 0x9e, 0x3d, 0xd9, 0x79, 0x11, 0xd3, 0x9f, 0xe9, 0xc5, 0xd0, 0xb2, 0x3a, 0x22,
        0x9a, 0x23, 0x4c, 0xb3, 0x61, 0x86, 0xc4, 0x81, 0x9e, 0x8b, 0x9c, 0x59, 0x27, 0x72, 0x66, 0x32,
        0x29, 0x1d, 0x6a, 0x41, 0x82, 0x11, 0xcc, 0x29, 0x62, 0xe2, 0x0f, 0xe4, 0x7f, 0xeb, 0x3e, 0xdf,
        0x33, 0x0f, 0x2c, 0x60, 0x3a, 0x9d, 0x48, 0xc0, 0xfc, 0xb5, 0x69, 0x9d, 0xbf, 0xe5, 0x89, 0x64,
        0x25, 0xc5, 0xba, 0xc4, 0xae, 0xe8, 0x2e, 0x57, 0xa8, 0x5a, 0xaf, 0x4e, 0x25, 0x13, 0xe4, 0xf0,
        0x57, 0x96, 0xb0, 0x7b, 0xa2, 0xee, 0x47, 0xd8, 0x05, 0x06, 0xf8, 0xd2, 0xc2, 0x5e, 0x50, 0xfd,
        0x14, 0xde, 0x71, 0xe6, 0xc4, 0x18, 0x55, 0x93, 0x02, 0xf9, 0x39, 0xb0, 0xe1, 0xab, 0xd5, 0x76,
        0xf2, 0x79, 0xc4, 0xb2, 0xe0, 0xfe, 0xb8, 0x5c, 0x1f, 0x28, 0xff, 0x18, 0xf5, 0x88, 0x91, 0xff,
        0xef, 0x13, 0x2e, 0xef, 0x2f, 0xa0, 0x93, 0x46, 0xae, 0xe3, 0x3c, 0x28, 0xeb, 0x13, 0x0f, 0xf2,
        0x8f, 0x5b, 0x76, 0x69, 0x53, 0x33, 0x41, 0x13, 0x21, 0x19, 0x96, 0xd2, 0x00, 0x11, 0xa1, 0x98,
        0xe3, 0xfc, 0x43, 0x3f, 0x9f, 0x25, 0x41, 0x01, 0x0a, 0xe1, 0x7c, 0x1b, 0xf2, 0x02, 0x58, 0x0f,
        0x60, 0x47, 0x47, 0x2f, 0xb3, 0x68, 0x57, 0xfe, 0x84, 0x3b, 0x19, 0xf5, 0x98, 0x40, 0x09, 0xdd,
        0xc3, 0x24, 0x04, 0x4e, 0x84, 0x7a, 0x4f, 0x4a, 0x0a, 0xb3, 0x4f, 0x71, 0x95, 0x95, 0xde, 0x37,
        0x25, 0x2d, 0x62, 0x35, 0x36, 0x5e, 0x9b, 0x84, 0x39, 0x2b, 0x06, 0x10, 0x85, 0x34, 0x9d, 0x73,
        0x20, 0x3a, 0x4a, 0x13, 0xe9, 0x6f, 0x54, 0x32, 0xec, 0x0f, 0xd4, 0xa1, 0xee, 0x65, 0xac, 0xcd,
        0xd5, 0xe3, 0x90, 0x4d, 0xf5, 0x4c, 0x1d, 0xa5, 0x10, 0xb0, 0xff, 0x20, 0xdc, 0xc0, 0xc7, 0x7f,
        0xcb, 0x2c, 0x0e, 0x0e, 0xb6, 0x05, 0xcb, 0x05, 0x04, 0xdb, 0x87, 0x63, 0x2c, 0xf3, 0xd8, 0xb4,
        0xda, 0xe6, 0xe7, 0x05, 0x76, 0x9d, 0x1d, 0xe3, 0x54, 0x27, 0x01, 0x23, 0xcb, 0x11, 0x45, 0x0e,
        0xfc, 0x60, 0xac, 0x47, 0x68, 0x3d, 0x7b, 0x8d, 0x0f, 0x81, 0x13, 0x65, 0x56, 0x5f, 0xd9, 0x8c,
        0x4c, 0x8e, 0xb9, 0x36, 0xbc, 0xab, 0x8d, 0x06, 0x9f, 0xc3, 0x3b, 0xd8, 0x01, 0xb0, 0x3a, 0xde,
        0xa2, 0xe1, 0xfb, 0xc5, 0xaa, 0x46, 0x3d, 0x08, 0xca, 0x19, 0x89, 0x6d, 0x2b, 0xf5, 0x9a, 0x07,
        0x1b, 0x85, 0x1e, 0x6c, 0x23, 0x90, 0x52, 0x17, 0x2f, 0x29, 0x6b, 0xfb, 0x5e, 0x72, 0x40, 0x47,
        0x90, 0xa2, 0x18, 0x10, 0x14, 0xf3, 0xb9, 0x4a, 0x4e, 0x97, 0xd1, 0x17, 0xb4, 0x38, 0x13, 0x03,
        0x68, 0xcc, 0x39, 0xdb, 0xb2, 0xd1, 0x98, 0x06, 0x5a, 0xe3, 0x98, 0x65, 0x47, 0x92, 0x6c, 0xd2,
        0x16, 0x2f, 0x40, 0xa2, 0x9f, 0x0c, 0x3c, 0x87, 0x45, 0xc0, 0xf5, 0x0f, 0xba, 0x38, 0x52, 0xe5,
        0x66, 0xd4, 0x45, 0x75, 0xc2, 0x9d, 0x39, 0xa0, 0x3f, 0x0c, 0xda, 0x72, 0x19, 0x84, 0xb6, 0xf4,
        0x40, 0x59, 0x1f, 0x35, 0x5e, 0x12, 0xd4, 0x39, 0xff, 0x15, 0x0a, 0xab, 0x76, 0x13, 0x49, 0x9d,
        0xbd, 0x49, 0xad, 0xab, 0xc8, 0x67, 0x6e, 0xef, 0x02, 0x3b, 0x15, 0xb6, 0x5b, 0xfc, 0x5c, 0xa0,
        0x69, 0x48, 0x10, 0x9f, 0x23, 0xf3, 0x50, 0xdb, 0x82, 0x12, 0x35, 0x35, 0xeb, 0x8a, 0x74, 0x33,
        0xbd, 0xab, 0xcb, 0x90, 0x92, 0x71, 0xa6, 0xec, 0xbc, 0xb5, 0x8b, 0x93, 0x6a, 0x88, 0xcd, 0x4e,
        0x8f, 0x2e, 0x6f, 0xf5, 0x80, 0x01, 0x75, 0xf1, 0x13, 0x25, 0x3d, 0x8f, 0xa9, 0xca, 0x88, 0x85,
        0xc2, 0xf5, 0x52, 0xe6, 0x57, 0xdc, 0x60, 0x3f, 0x25, 0x2e, 0x1a, 0x8e, 0x30, 0x8f, 0x76, 0xf0,
        0xbe, 0x79, 0xe2, 0xfb, 0x8f, 0x5d, 0x5f, 0xbb, 0xe2, 0xe3, 0x0e, 0xca, 0xdd, 0x22, 0x07, 0x23,
        0xc8, 0xc0, 0xae, 0xa8, 0x07, 0x8c, 0xdf, 0xcb, 0x38, 0x68, 0x26, 0x3f, 0xf8, 0xf0, 0x94, 0x00,
        0x54, 0xda, 0x48, 0x78, 0x18, 0x93, 0xa7, 0xe4, 0x9a, 0xd5, 0xaf, 0xf4, 0xaf, 0x30, 0x0c, 0xd8,
        0x04, 0xa6, 0xb6, 0x27, 0x9a, 0xb3, 0xff, 0x3a, 0xfb, 0x64, 0x49, 0x1c, 0x85, 0x19, 0x4a, 0xab,
        0x76, 0x0d, 0x58, 0xa6, 0x06, 0x65, 0x4f, 0x9f, 0x44, 0x00, 0xe8, 0xb3, 0x85, 0x91, 0x35, 0x6f,
        0xbf, 0x64, 0x25, 0xac, 0xa2, 0x6d, 0xc8, 0x52, 0x44, 0x25, 0x9f, 0xf2, 0xb1, 0x9c, 0x41, 0xb9,
        0xf9, 0x6f, 0x3c, 0xa9, 0xec, 0x1d, 0xde, 0x43, 0x4d, 0xa7, 0xd2, 0xd3, 0x92, 0xb9, 0x05, 0xdd,
        0xf3, 0xd1, 0xf9, 0xaf, 0x93, 0xd1, 0xaf, 0x59, 0x50, 0xbd, 0x49, 0x3f, 0x5a, 0xa7, 0x31, 0xb4,
        0x05, 0x6d, 0xf3, 0x1b, 0xd2, 0x67, 0xb6, 0xb9, 0x0a, 0x07, 0x98, 0x31, 0xaa, 0xf5, 0x79, 0xbe,
        0x0a, 0x39, 0x01, 0x31, 0x37, 0xaa, 0xc6, 0xd4, 0x04, 0xf5, 0x18, 0xcf, 0xd4, 0x68, 0x40, 0x64,
        0x7e, 0x78, 0xbf, 0xe7, 0x06, 0xca, 0x4c, 0xf5, 0xe9, 0xc5, 0x45, 0x3e, 0x9f, 0x7c, 0xfd, 0x2b,
        0x8b, 0x4c, 0x8d, 0x16, 0x9a, 0x44, 0xe5, 0x5c, 0x88, 0xd4, 0xa9, 0xa7, 0xf9, 0x47, 0x42, 0x41,
        0xe2, 0x21, 0xaf, 0x44, 0x86, 0x00, 0x18, 0xab, 0x08, 0x56, 0x97, 0x2e, 0x19, 0x4c, 0xd9, 0x34,
    ];

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[test]
    fn quic_initial_secrets_rfc9001_vector() {
        // Appendix A.1 pins the HKDF derivation against the standard:
        // DCID 8394c8f03e515708.
        let dcid = [0x83, 0x94, 0xc8, 0xf0, 0x3e, 0x51, 0x57, 0x08];
        let secret = quic_client_initial_secret(&dcid);
        assert_eq!(
            hex(&secret),
            "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea"
        );
        let keys = quic_initial_keys(&dcid);
        assert_eq!(hex(&keys.key), "1f369613dd76d5467730efcbe3b1a22d");
        assert_eq!(hex(&keys.iv), "fa044b2f42a3fd3b46fb255c");
        assert_eq!(hex(&keys.hp), "9f50449e04a0e810283a1e9933adedd2");
    }

    #[test]
    fn quic_rfc9001_a2_initial_sniffs_sni() {
        // Full pipeline against the standard's sample client Initial:
        // header protection, AEAD, frame walk, CRYPTO → SNI.
        assert_eq!(
            sniff(RFC_A2_PACKET, &quic_cfg(), 443),
            SniffResult::Quic("example.com".into())
        );
    }

    /// Protect a QUIC v1 client Initial with the same key schedule the
    /// sniffer derives — encrypting here is the round-trip proof.
    fn quic_protect(dcid: &[u8], pn: u32, pn_len: usize, frames: &[u8]) -> Vec<u8> {
        use aes::cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit as _};
        use aes_gcm::aead::{Aead as _, Payload};
        use aes_gcm::Aes128Gcm;

        let keys = quic_initial_keys(dcid);
        let pn_bytes = pn.to_be_bytes();
        let pn_field = &pn_bytes[4 - pn_len..];
        let mut header = Vec::new();
        header.push(0xc0 | (pn_len as u8 - 1));
        header.extend_from_slice(&1u32.to_be_bytes()); // version
        header.push(dcid.len() as u8);
        header.extend_from_slice(dcid);
        header.push(0); // SCID length
        header.push(0); // token length varint
        crate::quic::write_varint(&mut header, (pn_len + frames.len() + 16) as u64);
        header.extend_from_slice(pn_field);

        let mut nonce = keys.iv;
        for i in 0..4 {
            nonce[8 + i] ^= pn_bytes[i];
        }
        let aead = Aes128Gcm::new(GenericArray::from_slice(&keys.key));
        let ciphertext = aead
            .encrypt(
                GenericArray::from_slice(&nonce),
                Payload {
                    msg: frames,
                    aad: &header,
                },
            )
            .unwrap();
        let mut packet = header.clone();
        packet.extend_from_slice(&ciphertext);

        let pn_off = header.len() - pn_len;
        let cipher = aes::Aes128::new(GenericArray::from_slice(&keys.hp));
        let mut block = *GenericArray::from_slice(&packet[pn_off + 4..pn_off + 20]);
        cipher.encrypt_block(&mut block);
        let mask: [u8; 16] = block.into();
        packet[0] ^= mask[0] & 0x0f;
        for i in 0..pn_len {
            packet[pn_off + i] ^= mask[1 + i];
        }
        packet
    }

    /// CRYPTO(offset 0) + padding carrying `hs` as the crypto stream.
    fn quic_frames_with_crypto(hs: &[u8]) -> Vec<u8> {
        let mut frames = vec![0x06];
        crate::quic::write_varint(&mut frames, 0);
        crate::quic::write_varint(&mut frames, hs.len() as u64);
        frames.extend_from_slice(hs);
        frames.push(0x01); // PING
        frames.extend([0u8; 24]); // PADDING
        frames
    }

    #[test]
    fn quic_synthetic_round_trip() {
        // client_hello returns a TLS record; the QUIC crypto stream is
        // the handshake message itself (strip the 5-byte record header).
        let hs = client_hello("quic.roundtrip.test")[5..].to_vec();
        let packet = quic_protect(&[0xaa; 8], 0x1234, 2, &quic_frames_with_crypto(&hs));
        assert_eq!(
            sniff(&packet, &quic_cfg(), 443),
            SniffResult::Quic("quic.roundtrip.test".into())
        );
    }

    #[test]
    fn quic_gates_and_negatives() {
        let hs = client_hello("gated.quic.test")[5..].to_vec();
        let packet = quic_protect(&[0x11; 8], 1, 1, &quic_frames_with_crypto(&hs));

        let quic_off = SniffConfig {
            quic: false,
            ..quic_cfg()
        };
        assert_eq!(sniff(&packet, &quic_off, 443), SniffResult::Unknown);

        let skip = SniffConfig {
            skip_domains: vec!["gated.quic.test".into()],
            ..quic_cfg()
        };
        assert_eq!(sniff(&packet, &skip, 443), SniffResult::Unknown);

        // QUIC v2 (0x6b3343cf) is not sniffed.
        let mut v2 = packet.clone();
        v2[1..5].copy_from_slice(&0x6b3343cfu32.to_be_bytes());
        assert_eq!(sniff(&v2, &quic_cfg(), 443), SniffResult::Unknown);

        // Corrupted ciphertext fails the AEAD tag check.
        let mut bad = packet.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0xff;
        assert_eq!(sniff(&bad, &quic_cfg(), 443), SniffResult::Unknown);

        // Truncation never panics and stays Unknown.
        for cut in 1..packet.len() {
            assert_eq!(sniff(&packet[..cut], &quic_cfg(), 443), SniffResult::Unknown);
        }
    }

    // --- apply_sniffed force-domain semantics -----------------------------

    #[test]
    fn force_domains_apply_without_override() {
        let target = NetAddr::new(Host::parse("orig.test").unwrap(), 443);
        let sniffed = SniffResult::Tls("cdn.force.test".into());
        let base = SniffConfig {
            override_destination: false,
            ..quic_cfg()
        };
        // Domain target without override: not applied.
        assert_eq!(apply_sniffed(&target, &sniffed, &base), None);
        // A force-domain (suffix) match applies regardless.
        let forced = SniffConfig {
            force_domains: vec!["force.test".into()],
            ..base.clone()
        };
        let applied = apply_sniffed(&target, &sniffed, &forced).unwrap();
        assert_eq!(applied.host, Host::Domain("cdn.force.test".into()));
        assert_eq!(applied.port, 443);
        // Non-matching force entries change nothing.
        let other = SniffConfig {
            force_domains: vec!["other.test".into()],
            ..base
        };
        assert_eq!(apply_sniffed(&target, &sniffed, &other), None);
    }

    #[test]
    fn skip_domains_win_over_force() {
        // Even an IP target (normally always overridden) is left alone
        // when the sniffed domain is skip-listed.
        let target = NetAddr::new(Host::parse("93.184.216.34").unwrap(), 443);
        let sniffed = SniffResult::Quic("blocked.quic.test".into());
        let cfg = SniffConfig {
            skip_domains: vec!["blocked.quic.test".into()],
            force_domains: vec!["blocked.quic.test".into()],
            ..quic_cfg()
        };
        assert_eq!(apply_sniffed(&target, &sniffed, &cfg), None);
    }

    #[test]
    fn quic_result_applies_like_tls() {
        let target = NetAddr::new(Host::parse("10.0.0.1").unwrap(), 443);
        let applied =
            apply_sniffed(&target, &SniffResult::Quic("q.test".into()), &quic_cfg()).unwrap();
        assert_eq!(applied.host, Host::Domain("q.test".into()));
        assert_eq!(applied.port, 443);
    }
}
