//! DNS wire-format codec (RFC 1035 subset): parse queries and responses
//! (with compression pointers), build replies. The engine only ever needs
//! to read the question section, rewrite A/AAAA answers, and forward the
//! rest verbatim.

use crate::error::{Error, Result};

/// A parsed DNS message (question + answer records, best-effort).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsMessage {
    pub id: u16,
    pub flags: u16,
    pub opcode: u8,
    pub rcode: u8,
    pub questions: Vec<Question>,
    pub answers: Vec<ResourceRecord>,
    /// Whole original message (for opaque forwarding).
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Question {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResourceRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub rdata: Vec<u8>,
}

pub const TYPE_A: u16 = 1;
pub const TYPE_AAAA: u16 = 28;
pub const RCODE_NOERROR: u8 = 0;
pub const RCODE_FORMERR: u8 = 1;
pub const RCODE_SERVFAIL: u8 = 2;
pub const RCODE_NXDOMAIN: u8 = 3;
pub const RCODE_NOTIMP: u8 = 4;
pub const RCODE_REFUSED: u8 = 5;

/// Parse an mihomo `rcode://<token>` name into its RFC 1035 code
/// (mihomo `dns/rcode.go` `newRCodeClient`, validated with the same
/// token set in `config/config.go`'s `rcode` scheme arm). Tokens are
/// matched exactly like upstream (lowercase, no aliases) so an
/// unknown name returns `None` and the caller can fail loudly.
pub fn parse_rcode_token(token: &str) -> Option<u8> {
    match token {
        "success" => Some(RCODE_NOERROR),
        "format_error" => Some(RCODE_FORMERR),
        "server_failure" => Some(RCODE_SERVFAIL),
        "name_error" => Some(RCODE_NXDOMAIN),
        "not_implemented" => Some(RCODE_NOTIMP),
        "refused" => Some(RCODE_REFUSED),
        _ => None,
    }
}

/// The mihomo token for a code, or `"unknown"` — used for logs and the
/// API surface. Inverse of [`parse_rcode_token`] over the six tokens
/// mihomo defines (extended rcodes 6–15 have no upstream token).
pub fn rcode_token(rcode: u8) -> &'static str {
    match rcode {
        RCODE_NOERROR => "success",
        RCODE_FORMERR => "format_error",
        RCODE_SERVFAIL => "server_failure",
        RCODE_NXDOMAIN => "name_error",
        RCODE_NOTIMP => "not_implemented",
        RCODE_REFUSED => "refused",
        _ => "unknown",
    }
}

impl DnsMessage {
    pub fn is_response(&self) -> bool {
        self.flags & 0x8000 != 0
    }

    pub fn recursion_desired(&self) -> bool {
        self.flags & 0x0100 != 0
    }

    /// The first question's lowercase name, if any.
    pub fn first_question(&self) -> Option<&Question> {
        self.questions.first()
    }
}

/// Parse a DNS message; `raw` is copied into the result.
pub fn parse(raw: &[u8]) -> Result<DnsMessage> {
    if raw.len() < 12 {
        return Err(Error::dns("message shorter than header"));
    }
    let id = u16::from_be_bytes([raw[0], raw[1]]);
    let flags = u16::from_be_bytes([raw[2], raw[3]]);
    let qd = u16::from_be_bytes([raw[4], raw[5]]);
    let an = u16::from_be_bytes([raw[6], raw[7]]);
    let ns = u16::from_be_bytes([raw[8], raw[9]]);
    let ar = u16::from_be_bytes([raw[10], raw[11]]);

    let mut off = 12usize;
    let mut questions = Vec::new();
    for _ in 0..qd {
        let (name, used) = read_name(raw, off)?;
        off += used;
        if raw.len() < off + 4 {
            return Err(Error::dns("truncated question"));
        }
        let qtype = u16::from_be_bytes([raw[off], raw[off + 1]]);
        let qclass = u16::from_be_bytes([raw[off + 2], raw[off + 3]]);
        off += 4;
        questions.push(Question {
            name,
            qtype,
            qclass,
        });
    }

    let mut answers = Vec::new();
    let total_rr = an + ns + ar;
    for _ in 0..total_rr {
        let (name, used) = read_name(raw, off)?;
        off += used;
        if raw.len() < off + 10 {
            return Err(Error::dns("truncated record"));
        }
        let rtype = u16::from_be_bytes([raw[off], raw[off + 1]]);
        let rclass = u16::from_be_bytes([raw[off + 2], raw[off + 3]]);
        let ttl = u32::from_be_bytes([raw[off + 4], raw[off + 5], raw[off + 6], raw[off + 7]]);
        let rdlen = u16::from_be_bytes([raw[off + 8], raw[off + 9]]) as usize;
        off += 10;
        if raw.len() < off + rdlen {
            return Err(Error::dns("truncated rdata"));
        }
        answers.push(ResourceRecord {
            name,
            rtype,
            rclass,
            ttl,
            rdata: raw[off..off + rdlen].to_vec(),
        });
        off += rdlen;
    }

    Ok(DnsMessage {
        id,
        flags,
        opcode: ((flags >> 11) & 0xF) as u8,
        rcode: (flags & 0xF) as u8,
        questions,
        answers,
        raw: raw.to_vec(),
    })
}

/// Read a (possibly compressed) domain name; returns the name and the
/// number of bytes consumed in the ORIGINAL range. Bytes reached through
/// a compression pointer belong to an earlier name and do not count.
/// `pub(crate)`: the Clash API's `/dns/query` renderer decodes
/// name-rdata records (CNAME/NS/PTR) with it.
pub(crate) fn read_name(raw: &[u8], offset: usize) -> Result<(String, usize)> {
    let mut labels: Vec<String> = Vec::new();
    let mut pos = offset;
    let mut consumed = 0usize;
    let mut followed_pointer = false;
    let mut jumps = 0;
    loop {
        if pos >= raw.len() {
            return Err(Error::dns("name runs past end"));
        }
        let len = raw[pos] as usize;
        match len & 0xC0 {
            0x00 => {
                pos += 1;
                if !followed_pointer {
                    consumed += 1;
                }
                if len == 0 {
                    break;
                }
                if pos + len > raw.len() {
                    return Err(Error::dns("label runs past end"));
                }
                labels.push(
                    String::from_utf8_lossy(&raw[pos..pos + len])
                        .to_ascii_lowercase(),
                );
                pos += len;
                if !followed_pointer {
                    consumed += len;
                }
            }
            0xC0 => {
                if pos + 1 >= raw.len() {
                    return Err(Error::dns("truncated pointer"));
                }
                let ptr = ((len & 0x3F) << 8) | raw[pos + 1] as usize;
                // Pointers must point strictly backwards (from the
                // pointer's own position) — forward or self pointers
                // would loop.
                if ptr >= pos {
                    return Err(Error::dns("bad compression pointer"));
                }
                // The first pointer fixes the caller's consumed count;
                // everything after it lives in an earlier name.
                if !followed_pointer {
                    consumed = pos + 2 - offset;
                    followed_pointer = true;
                }
                pos = ptr;
                jumps += 1;
                if jumps > 32 {
                    return Err(Error::dns("compression loop"));
                }
            }
            _ => return Err(Error::dns("reserved label type")),
        }
    }
    Ok((labels.join("."), consumed))
}

/// Append a dotted name as uncompressed labels.
fn write_name(out: &mut Vec<u8>, name: &str) {
    if name.is_empty() || name == "." {
        out.push(0);
        return;
    }
    for label in name.trim_end_matches('.').split('.') {
        // Names from the wire/config are bounded; clamp defensively.
        let bytes = label.as_bytes();
        let len = bytes.len().min(63);
        out.push(len as u8);
        out.extend_from_slice(&bytes[..len]);
    }
    out.push(0);
}

/// Build a response for `query` carrying `answers` (A/AAAA rdata).
/// TTL is small: fake-ip mappings are volatile.
pub fn build_response(query: &DnsMessage, rcode: u8, answers: &[(std::net::IpAddr, u32)]) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + answers.len() * 16);
    let id = query.id;
    out.extend_from_slice(&id.to_be_bytes());
    // QR=1, opcode copied, AA=0, TC=0, RD copied, RA=1, Z=0, rcode.
    let opcode = (query.opcode as u16) << 11;
    let rd = if query.recursion_desired() { 0x0100 } else { 0 };
    let flags = 0x8000 | opcode | rd | 0x0080 | (rcode as u16 & 0xF);
    out.extend_from_slice(&flags.to_be_bytes());
    let qd = query.questions.len() as u16;
    out.extend_from_slice(&qd.to_be_bytes());
    out.extend_from_slice(&(answers.len() as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    for q in &query.questions {
        write_name(&mut out, &q.name);
        out.extend_from_slice(&q.qtype.to_be_bytes());
        out.extend_from_slice(&q.qclass.to_be_bytes());
    }
    let Some(_q) = query.questions.first() else {
        return out;
    };
    for (ip, ttl) in answers {
        // Compressed name pointer to the question at offset 12.
        out.push(0xC0);
        out.push(0x0C);
        let rtype = if ip.is_ipv4() { TYPE_A } else { TYPE_AAAA };
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&0x0001u16.to_be_bytes()); // IN
        out.extend_from_slice(&ttl.to_be_bytes());
        match ip {
            std::net::IpAddr::V4(v4) => {
                out.extend_from_slice(&4u16.to_be_bytes());
                out.extend_from_slice(&v4.octets());
            }
            std::net::IpAddr::V6(v6) => {
                out.extend_from_slice(&16u16.to_be_bytes());
                out.extend_from_slice(&v6.octets());
            }
        }
    }
    out
}

/// Build a UDP-forwardable query (new ID, RD set).
pub fn build_query(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(32 + name.len());
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&0x0100u16.to_be_bytes()); // standard query, RD
    out.extend_from_slice(&1u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes());
    write_name(&mut out, name);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // IN
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn query_build_parse_roundtrip() {
        let wire = build_query(0x1234, "Example.COM", TYPE_A);
        let msg = parse(&wire).unwrap();
        assert_eq!(msg.id, 0x1234);
        assert!(!msg.is_response());
        assert!(msg.recursion_desired());
        assert_eq!(msg.questions.len(), 1);
        assert_eq!(msg.questions[0].name, "example.com");
        assert_eq!(msg.questions[0].qtype, TYPE_A);
        assert_eq!(msg.questions[0].qclass, 1);
    }

    #[test]
    fn response_builds_and_parses() {
        let query = parse(&build_query(7, "ok.test", TYPE_A)).unwrap();
        let ip: std::net::IpAddr = "198.18.0.5".parse().unwrap();
        let resp = build_response(&query, RCODE_NOERROR, &[(ip, 1)]);
        let msg = parse(&resp).unwrap();
        assert!(msg.is_response());
        assert_eq!(msg.id, 7);
        assert_eq!(msg.rcode, 0);
        assert_eq!(msg.answers.len(), 1);
        assert_eq!(msg.answers[0].name, "ok.test");
        assert_eq!(msg.answers[0].rtype, TYPE_A);
        assert_eq!(msg.answers[0].rdata, vec![198, 18, 0, 5]);
    }

    #[test]
    fn compression_pointer_parse() {
        // Build a response with a compressed answer name by hand:
        // header + question + answer whose name is a pointer to offset 12.
        let mut q = build_query(9, "cp.test", TYPE_A);
        q[2] = 0x81; // make it a response for realism
        let mut msg = q.clone();
        // Answer record: pointer(0xC00C) TYPE_A IN TTL 60 RDLEN 4 1.2.3.4
        msg.extend_from_slice(&[0xC0, 0x0C]);
        msg.extend_from_slice(&TYPE_A.to_be_bytes());
        msg.extend_from_slice(&1u16.to_be_bytes());
        msg.extend_from_slice(&60u32.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&[1, 2, 3, 4]);
        msg[6] = 0; // ANCOUNT hi
        msg[7] = 1; // ANCOUNT lo
        let parsed = parse(&msg).unwrap();
        assert_eq!(parsed.answers.len(), 1);
        assert_eq!(parsed.answers[0].name, "cp.test");
        assert_eq!(parsed.answers[0].rdata, vec![1, 2, 3, 4]);
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse(&[]).is_err());
        assert!(parse(&[0u8; 11]).is_err());
        // QDCOUNT 1 but no question body.
        let mut m = vec![0u8; 12];
        m[5] = 1;
        assert!(parse(&m).is_err());
    }

    #[test]
    fn name_reader_handles_root() {
        let (name, used) = read_name(&[0x00], 0).unwrap();
        assert_eq!(name, "");
        assert_eq!(used, 1);
    }

    /// The mihomo `rcode://` token table (dns/rcode.go newRCodeClient):
    /// every token maps to its RFC 1035 code and back.
    #[test]
    fn rcode_token_table_roundtrips() {
        let table = [
            ("success", RCODE_NOERROR),
            ("format_error", RCODE_FORMERR),
            ("server_failure", RCODE_SERVFAIL),
            ("name_error", RCODE_NXDOMAIN),
            ("not_implemented", RCODE_NOTIMP),
            ("refused", RCODE_REFUSED),
        ];
        for (token, code) in table {
            assert_eq!(parse_rcode_token(token), Some(code), "token {token}");
            assert_eq!(rcode_token(code), token, "code {code}");
        }
        // Unknown / malformed tokens are refused, not defaulted — the
        // caller fails loudly like config.go's "unsupported RCode type".
        assert_eq!(parse_rcode_token("SUCCESS"), None);
        assert_eq!(parse_rcode_token("servfail"), None);
        assert_eq!(parse_rcode_token(""), None);
        assert_eq!(rcode_token(9), "unknown");
    }

    /// One response per rcode: the code survives the wire round-trip
    /// and the question is echoed (mihomo's rcodeClient returns the
    /// query message with Response+Rcode set).
    #[test]
    fn every_rcode_builds_and_roundtrips() {
        let codes = [
            (RCODE_NOERROR, "success"),
            (RCODE_FORMERR, "format_error"),
            (RCODE_SERVFAIL, "server_failure"),
            (RCODE_NXDOMAIN, "name_error"),
            (RCODE_NOTIMP, "not_implemented"),
            (RCODE_REFUSED, "refused"),
        ];
        for (code, token) in codes {
            let query = parse(&build_query(0x0BAD, "blocked.ad.test", TYPE_A)).unwrap();
            let resp = build_response(&query, code, &[]);
            let msg = parse(&resp).unwrap();
            assert!(msg.is_response(), "{token}: QR set");
            assert_eq!(msg.id, 0x0BAD, "{token}: id echoed");
            assert_eq!(msg.rcode, code, "{token}: rcode on the wire");
            assert_eq!(rcode_token(msg.rcode), token, "{token}: token back");
            assert_eq!(msg.questions.len(), 1, "{token}: question echoed");
            assert_eq!(msg.questions[0].name, "blocked.ad.test");
            assert!(msg.answers.is_empty(), "{token}: no answers");
            // The rcode rides in the low nibble of the flags word.
            assert_eq!((msg.flags & 0xF) as u8, code, "{token}: flags nibble");
        }
    }
}
