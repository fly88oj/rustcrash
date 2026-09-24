//! EDNS0 (RFC 6891) OPT pseudo-RR encoding plus the EDNS client-subnet
//! option (RFC 7871): build the OPT RR for outgoing queries with an
//! optional truncated client subnet, and best-effort parse the ECS
//! option back out of responses for the scope the upstream chose.

use std::net::IpAddr;

/// Payload size advertised in OPT RRs built by [`append_to_query`]
/// (1232 bytes, the DNS flag-day 2020 recommendation: fits common
/// IPv6-minimum MTUs without fragmentation).
pub const DEFAULT_PAYLOAD_SIZE: u16 = 1232;

/// EDNS client-subnet option payload (RFC 7871). `source_prefix` is the
/// significant prefix length of `addr`; `scope_prefix` is the network
/// scope the answer covers — 0 in queries, set by the resolver in
/// answers.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientSubnet {
    pub addr: IpAddr,
    pub source_prefix: u8,
    pub scope_prefix: u8,
}

/// ECS option code (RFC 7871 §6).
const ECS_OPTION_CODE: u16 = 8;
/// OPT RR TYPE (RFC 6891 §6.1).
const TYPE_OPT: u16 = 41;

/// Encode one OPT RR (RFC 6891 §6.1) with an optional client-subnet
/// option (RFC 7871 §6). Returns just the record bytes (owner name
/// through rdata); the caller splices them into a message and bumps
/// ARCOUNT — see [`append_to_query`].
///
/// Wire layout: root name (0x00), TYPE 41, CLASS = `udpsize` (the
/// requester's payload size), TTL = ext-rcode(8) << 24 | version(8) <<
/// 16 | DO(1) << 15 | z(15) — ext-rcode and version are always 0 here —
/// then RDLENGTH and rdata. With a subnet the rdata is one option:
/// code 8, option length, family (1 = IPv4, 2 = IPv6), source prefix,
/// scope prefix, and the address truncated to `source_prefix` bits
/// rounded up to whole bytes, network byte order, with the trailing
/// non-significant bits of the last byte zeroed (RFC 7871 §6).
///
/// A `source_prefix` wider than the address family is clamped to the
/// full address.
pub fn encode_opt_rr(subnet: Option<&ClientSubnet>, udpsize: u16, dnssec: bool) -> Vec<u8> {
    let rdata = subnet.map(encode_ecs_rdata).unwrap_or_default();
    let mut out = Vec::with_capacity(11 + rdata.len());
    out.push(0x00); // owner name: root
    out.extend_from_slice(&TYPE_OPT.to_be_bytes());
    out.extend_from_slice(&udpsize.to_be_bytes()); // CLASS = payload size
    let ttl: u32 = if dnssec { 0x8000 } else { 0 }; // DO bit, else 0
    out.extend_from_slice(&ttl.to_be_bytes());
    out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    out.extend_from_slice(&rdata);
    out
}

/// The ECS option bytes (code, length, family/prefixes/address).
fn encode_ecs_rdata(cs: &ClientSubnet) -> Vec<u8> {
    let family = if cs.addr.is_ipv4() { 1u16 } else { 2u16 };
    let octets = match cs.addr {
        IpAddr::V4(v4) => v4.octets().to_vec(),
        IpAddr::V6(v6) => v6.octets().to_vec(),
    };
    // Truncate the address to the source prefix, whole bytes, and zero
    // the trailing non-significant bits of the last byte.
    let bits = (cs.source_prefix as usize).min(octets.len() * 8);
    let nbytes = bits.div_ceil(8);
    let mut addr = octets[..nbytes].to_vec();
    let rem = bits % 8;
    if rem != 0 {
        if let Some(last) = addr.last_mut() {
            *last &= 0xFFu8 << (8 - rem);
        }
    }
    let mut out = Vec::with_capacity(4 + addr.len());
    out.extend_from_slice(&ECS_OPTION_CODE.to_be_bytes());
    // option length = family(2) + source(1) + scope(1) + address
    out.extend_from_slice(&((4 + addr.len()) as u16).to_be_bytes());
    out.extend_from_slice(&family.to_be_bytes());
    out.push(cs.source_prefix);
    out.push(cs.scope_prefix); // 0 on queries per RFC 7871
    out.extend_from_slice(&addr);
    out
}

/// Best-effort parse of one OPT RR from the tail of a message (the
/// record must start at `msg_tail[0]`, i.e. owner name = root). Returns
/// `(payload size, DO bit, client subnet)`. The subnet is `None` when
/// the RR carries no ECS option or the option is malformed; `None` for
/// the whole tuple when the record is not an OPT RR or is truncated
/// before the RDLENGTH field.
pub fn parse_opt_rr(msg_tail: &[u8]) -> Option<(u16, bool, Option<ClientSubnet>)> {
    if msg_tail.len() < 11 || msg_tail[0] != 0x00 {
        return None;
    }
    let rtype = u16::from_be_bytes([msg_tail[1], msg_tail[2]]);
    if rtype != TYPE_OPT {
        return None;
    }
    let udpsize = u16::from_be_bytes([msg_tail[3], msg_tail[4]]);
    let ttl = u32::from_be_bytes([msg_tail[5], msg_tail[6], msg_tail[7], msg_tail[8]]);
    let dnssec = ttl & 0x8000 != 0;
    let rdlen = u16::from_be_bytes([msg_tail[9], msg_tail[10]]) as usize;
    // Best-effort: honor the shorter of RDLENGTH and what is present.
    let rdata = &msg_tail[11..][..rdlen.min(msg_tail.len() - 11)];

    // Walk the options in rdata looking for the first well-formed ECS.
    let mut subnet = None;
    let mut off = 0usize;
    while off + 4 <= rdata.len() {
        let code = u16::from_be_bytes([rdata[off], rdata[off + 1]]);
        let olen = u16::from_be_bytes([rdata[off + 2], rdata[off + 3]]) as usize;
        off += 4;
        if rdata.len() < off + olen {
            break;
        }
        if code == ECS_OPTION_CODE && subnet.is_none() {
            subnet = parse_ecs_option(&rdata[off..off + olen]);
        }
        off += olen;
    }
    Some((udpsize, dnssec, subnet))
}

/// Decode one ECS option body (family/prefixes/address); `None` when
/// the family is unknown or the fixed fields are missing.
fn parse_ecs_option(opt: &[u8]) -> Option<ClientSubnet> {
    if opt.len() < 4 {
        return None;
    }
    let family = u16::from_be_bytes([opt[0], opt[1]]);
    let source_prefix = opt[2];
    let scope_prefix = opt[3];
    let addr_bytes = &opt[4..];
    // The address is truncated to the source prefix; pad back to the
    // full family width (missing octets are zero).
    let addr = match family {
        1 => {
            let mut o = [0u8; 4];
            let n = addr_bytes.len().min(4);
            o[..n].copy_from_slice(&addr_bytes[..n]);
            IpAddr::from(o)
        }
        2 => {
            let mut o = [0u8; 16];
            let n = addr_bytes.len().min(16);
            o[..n].copy_from_slice(&addr_bytes[..n]);
            IpAddr::from(o)
        }
        _ => return None,
    };
    Some(ClientSubnet {
        addr,
        source_prefix,
        scope_prefix,
    })
}

/// Append an OPT RR (client subnet optional) to an already-built query
/// and bump the header's ARCOUNT (bytes 10..12). Uses
/// [`DEFAULT_PAYLOAD_SIZE`] and no DO bit. A no-op on a buffer shorter
/// than a DNS header or when ARCOUNT is already saturated.
pub fn append_to_query(query: &mut Vec<u8>, subnet: Option<&ClientSubnet>) {
    if query.len() < 12 {
        return;
    }
    let arcount = u16::from_be_bytes([query[10], query[11]]);
    let Some(arcount) = arcount.checked_add(1) else {
        return;
    };
    query.extend_from_slice(&encode_opt_rr(subnet, DEFAULT_PAYLOAD_SIZE, false));
    query[10..12].copy_from_slice(&arcount.to_be_bytes());
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::wire;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn rfc7871_ipv4_example_query() {
        // RFC 7871: client 192.0.2.0/24 in a query — family 1, source 24,
        // scope 0, address truncated to 3 bytes.
        let cs = ClientSubnet {
            addr: ip("192.0.2.0"),
            source_prefix: 24,
            scope_prefix: 0,
        };
        let rr = encode_opt_rr(Some(&cs), 1232, false);
        assert_eq!(
            rr,
            [
                0x00, 0x00, 0x29, 0x04, 0xD0, // root, TYPE 41, class=1232
                0x00, 0x00, 0x00, 0x00, // TTL: ext-rcode 0, version 0, DO 0
                0x00, 0x0B, // rdlength 11
                0x00, 0x08, 0x00, 0x07, // ECS option, length 7
                0x00, 0x01, 0x18, 0x00, // family 1, source /24, scope 0
                0xC0, 0x00, 0x02, // 192.0.2
            ]
        );
    }

    #[test]
    fn address_truncated_and_masked() {
        // /25 on 192.0.2.207: 4 bytes, last one masked to its top bit.
        let cs = ClientSubnet {
            addr: ip("192.0.2.207"),
            source_prefix: 25,
            scope_prefix: 0,
        };
        let rr = encode_opt_rr(Some(&cs), 1232, false);
        assert_eq!(&rr[rr.len() - 4..], &[0xC0, 0x00, 0x02, 0x80]);
        // A /24 keeps the first three bytes verbatim, dropping .207.
        let cs = ClientSubnet {
            addr: ip("192.0.2.207"),
            source_prefix: 24,
            scope_prefix: 0,
        };
        let rr = encode_opt_rr(Some(&cs), 1232, false);
        assert_eq!(&rr[rr.len() - 3..], &[0xC0, 0x00, 0x02]);
        // Prefix wider than the family clamps to the full address.
        let cs = ClientSubnet {
            addr: ip("192.0.2.1"),
            source_prefix: 120,
            scope_prefix: 0,
        };
        let rr = encode_opt_rr(Some(&cs), 1232, false);
        assert_eq!(&rr[rr.len() - 4..], &[0xC0, 0x00, 0x02, 0x01]);
    }

    #[test]
    fn ipv6_subnet() {
        // 2001:db8::/32: family 2, address truncated to 4 bytes.
        let cs = ClientSubnet {
            addr: ip("2001:db8::1"),
            source_prefix: 32,
            scope_prefix: 0,
        };
        assert!(cs.addr.is_ipv6());
        let rr = encode_opt_rr(Some(&cs), 4096, false);
        assert_eq!(
            rr,
            [
                0x00, 0x00, 0x29, 0x10, 0x00, // root, TYPE 41, class=4096
                0x00, 0x00, 0x00, 0x00, 0x00, 0x0C, // TTL 0, rdlength 12
                0x00, 0x08, 0x00, 0x08, // ECS option, length 8
                0x00, 0x02, 0x20, 0x00, // family 2, source /32, scope 0
                0x20, 0x01, 0x0D, 0xB8, // 2001:0db8
            ]
        );
    }

    #[test]
    fn no_subnet_is_bare_opt() {
        let rr = encode_opt_rr(None, 4096, false);
        assert_eq!(
            rr,
            [0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
        );
        assert_eq!(rr.len(), 11);
    }

    #[test]
    fn do_bit_in_ttl() {
        let cs = ClientSubnet {
            addr: ip("192.0.2.0"),
            source_prefix: 24,
            scope_prefix: 0,
        };
        let rr = encode_opt_rr(Some(&cs), 1232, true);
        assert_eq!(&rr[5..9], &[0x00, 0x00, 0x80, 0x00]); // DO set
        let rr = encode_opt_rr(Some(&cs), 1232, false);
        assert_eq!(&rr[5..9], &[0x00, 0x00, 0x00, 0x00]); // DO clear
    }

    #[test]
    fn parse_roundtrip_query_and_scope() {
        let cs = ClientSubnet {
            addr: ip("192.0.2.33"),
            source_prefix: 24,
            scope_prefix: 0,
        };
        let rr = encode_opt_rr(Some(&cs), 1232, false);
        let (size, do_bit, got) = parse_opt_rr(&rr).unwrap();
        assert_eq!(size, 1232);
        assert!(!do_bit);
        // The address comes back zero-extended to full width.
        assert_eq!(
            got,
            Some(ClientSubnet {
                addr: ip("192.0.2.0"),
                source_prefix: 24,
                scope_prefix: 0,
            })
        );

        // Response side: the resolver answers with a scope prefix.
        let resp = ClientSubnet {
            addr: ip("192.0.2.0"),
            source_prefix: 24,
            scope_prefix: 24,
        };
        let rr = encode_opt_rr(Some(&resp), 4096, true);
        let (size, do_bit, got) = parse_opt_rr(&rr).unwrap();
        assert_eq!(size, 4096);
        assert!(do_bit);
        let got = got.unwrap();
        assert_eq!(got.scope_prefix, 24);
        assert_eq!(got.source_prefix, 24);
        assert_eq!(got.addr, ip("192.0.2.0"));

        // IPv6 round-trip: 4-byte truncated address pads to 2001:db8::.
        let cs = ClientSubnet {
            addr: ip("2001:db8::1"),
            source_prefix: 32,
            scope_prefix: 0,
        };
        let (.., got) = parse_opt_rr(&encode_opt_rr(Some(&cs), 1232, false)).unwrap();
        assert_eq!(
            got,
            Some(ClientSubnet {
                addr: ip("2001:db8::"),
                source_prefix: 32,
                scope_prefix: 0,
            })
        );
    }

    #[test]
    fn parse_skips_other_options_and_tolerates_junk() {
        // OPT with an unknown option (code 10) before the ECS option.
        let ecs = [
            0x00, 0x01, 0x18, 0x00, 0xC0, 0x00, 0x02, // family/src/scope/addr
        ];
        let mut rdata = vec![0x00, 0x0A, 0x00, 0x01, 0xAB]; // code 10, len 1
        rdata.extend_from_slice(&[0x00, 0x08, 0x00, 0x07]); // ECS header
        rdata.extend_from_slice(&ecs);
        let mut rr = vec![0x00, 0x00, 0x29, 0x04, 0xD0, 0x00, 0x00, 0x00, 0x00];
        rr.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        rr.extend_from_slice(&rdata);
        let (size, do_bit, got) = parse_opt_rr(&rr).unwrap();
        assert_eq!(size, 1232);
        assert!(!do_bit);
        let got = got.unwrap();
        assert_eq!(got.addr, ip("192.0.2.0"));
        assert_eq!(got.source_prefix, 24);

        // Malformed / non-OPT inputs give None.
        assert!(parse_opt_rr(&[]).is_none());
        assert!(parse_opt_rr(&[0u8; 10]).is_none());
        // Owner name is not the root label.
        assert!(parse_opt_rr(&[0x01, 0x61, 0x00, 0x00, 0x29, 0, 0, 0, 0, 0, 0, 0]).is_none());
        // TYPE != 41.
        let not_opt = [
            0x00, 0x00, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0x00, 0x04, 1, 2, 3, 4,
        ];
        assert!(parse_opt_rr(&not_opt).is_none());
        // OPT header parses but rdata is junk: no subnet, no panic.
        let mut junk = vec![
            0x00, 0x00, 0x29, 0x04, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
        ];
        junk.extend_from_slice(&[0x00, 0x08, 0xFF]); // option length runs past
        assert_eq!(parse_opt_rr(&junk), Some((1232, false, None)));
        // ECS with a truncated fixed part yields no subnet.
        let mut short = vec![
            0x00, 0x00, 0x29, 0x04, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
        ];
        short.extend_from_slice(&[0x00, 0x08, 0x00, 0x01, 0x00]);
        assert_eq!(parse_opt_rr(&short), Some((1232, false, None)));
    }

    #[test]
    fn append_bumps_arcount_and_keeps_question() {
        let cs = ClientSubnet {
            addr: ip("192.0.2.0"),
            source_prefix: 24,
            scope_prefix: 0,
        };
        let mut q = wire::build_query(0x1234, "example.test", wire::TYPE_A);
        let question = q.clone();
        let len_before = q.len();
        append_to_query(&mut q, Some(&cs));

        // ARCOUNT 0 -> 1; everything except bytes 10..12 is untouched.
        assert_eq!(u16::from_be_bytes([q[10], q[11]]), 1);
        assert_eq!(&q[..10], &question[..10]);
        assert_eq!(&q[12..len_before], &question[12..]);
        // The appended bytes are exactly the OPT RR with the defaults.
        let expected = encode_opt_rr(Some(&cs), DEFAULT_PAYLOAD_SIZE, false);
        assert_eq!(&q[len_before..], expected.as_slice());
        // The whole message still parses with the wire codec, and the
        // tail round-trips through parse_opt_rr.
        assert!(wire::parse(&q).is_ok());
        assert_eq!(
            parse_opt_rr(&q[len_before..]),
            Some((
                DEFAULT_PAYLOAD_SIZE,
                false,
                Some(ClientSubnet {
                    addr: ip("192.0.2.0"),
                    source_prefix: 24,
                    scope_prefix: 0
                })
            ))
        );
    }

    #[test]
    fn append_without_subnet_and_repeated() {
        let mut q = wire::build_query(7, "no-ecs.test", wire::TYPE_A);
        let len_before = q.len();
        append_to_query(&mut q, None);
        assert_eq!(u16::from_be_bytes([q[10], q[11]]), 1);
        assert_eq!(q.len(), len_before + 11);
        // A second append (e.g. adding ECS after a plain one was added)
        // bumps ARCOUNT again.
        append_to_query(&mut q, None);
        assert_eq!(u16::from_be_bytes([q[10], q[11]]), 2);
        // Short buffers are left alone instead of panicking.
        let mut tiny = vec![0u8; 8];
        append_to_query(&mut tiny, None);
        assert_eq!(tiny, vec![0u8; 8]);
    }
}
