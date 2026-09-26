//! smoltcp netstack over the TUN device: the far side of the tunnel.
//!
//! Both IP families are in play: the stack is built `proto-ipv4` +
//! `proto-ipv6` (when the config carries an `inet6_address`), TCP listeners
//! and UDP sockets match by destination port across both families, and ICMP
//! echo requests ("ping") are answered locally for v4 and v6.
//!
//! # Shape
//!
//! One task owns the `Interface`, the `SocketSet` and the device shim; every
//! socket operation happens there, because smoltcp sockets are `!Sync` and
//! share one mutable socket set. The outside world only touches handles:
//!
//! * **TCP**: each accepted connection becomes a [`TunStream`], an
//!   `AsyncRead + AsyncWrite` bridge backed by two bounded queues plus wakers
//!   (`StreamShared`). The relay drives it exactly like a socket; the
//!   netstack task moves bytes between the stream and the smoltcp socket.
//! * **UDP**: smoltcp UDP sockets are keyed by *destination port* (that is
//!   what smoltcp's `accepts()` matches — it has no wildcard-port socket),
//!   while relay sessions are keyed by *client source address*: one
//!   `relay.handle_udp` association per client, mirroring the socks
//!   UDP-ASSOCIATE lifecycle including the idle timeout.
//! * **DNS**: destinations listed in `TunConfig::dns_hijack` are answered by
//!   the engine's own resolver and never reach the relay or an upstream.
//! * **ICMP**: echo requests (v4 type 8, v6 type 128) are answered directly
//!   onto the device — never staged for smoltcp, which would otherwise also
//!   answer echoes addressed to the interface itself and duplicate the reply.
//!   Every other ICMP type is dropped with a debug log, as before.
//! * **TCP SYN → listener**: smoltcp cannot listen on "any port" (`listen()`
//!   rejects port 0, `accepts()` requires an exact port), so a listener
//!   socket is created for a destination port *before* the SYN that needs it
//!   is handed to the stack. That peek is the only packet the netstack
//!   parses itself; everything else is smoltcp's business.
//!
//! # IPv6 extension headers
//!
//! The classifier follows the extension-header chain (hop-by-hop, routing,
//! destination options, fragment, AH, mobility — see [`ipv6_upper_layer`],
//! the gvisor/Linux walker) so UDP port 53 is hijacked, UDP datagrams are
//! relayed and ICMPv6 echoes are answered even behind a chain. What is *not*
//! done is feeding a chained packet to smoltcp: the stack only consumes
//! hop-by-hop itself (smoltcp `iface/interface/ipv6.rs:204`) and answers
//! every other unrecognized next-header with an ICMPv6 Parameter Problem
//! (`ipv6.rs:352-367`), so a staged chain would only earn the client that
//! error. Locally handled paths (DNS hijack, UDP relay, ICMP echo) are
//! complete without smoltcp; chained TCP is dropped with a debug log —
//! upstream sing-tun tolerates it because gvisor parses chains in-stack.
//!
//! # Wakeups
//!
//! The task sleeps in a `select!` over three things: packets from the reader
//! pump ([`io::DeviceReader`] — a dedicated thread blocking on the device,
//! the wireguard-go `RoutineReadFromTUN` shape), a [`tokio::sync::Notify`]
//! pinged by stream writes and UDP downlinks, and the timer
//! `Interface::poll_delay` asks for (TCP retransmits, TIME-WAIT, session
//! GC). A stream reader's waker is stored under the same mutex that guards
//! its queues, so a push can never race the park and no wakeup is lost.

use std::collections::{HashMap, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{mpsc, Notify};

use crate::addr::NetAddr;
use crate::dns::resolver::DnsEngine;
use crate::error::{Error, Result};
use crate::inbound::tun::io::{DeviceReader, TunIo};
use crate::inbound::tun::{DnsHijack, TunConfig, TunHooks};
use crate::inbound::{SharedRelay, TcpMeta};

/// Read buffer per smoltcp TCP socket (also the advertised receive window).
const TCP_RX_BYTES: usize = 64 * 1024;
/// Write buffer per smoltcp TCP socket (how far the peer may run ahead).
const TCP_TX_BYTES: usize = 64 * 1024;
/// Buffers per smoltcp UDP socket — shared by every client using that port.
const UDP_RX_BYTES: usize = 32 * 1024;
const UDP_TX_BYTES: usize = 32 * 1024;
/// Packet slots per smoltcp UDP socket.
const UDP_PACKETS: usize = 64;

/// Per-direction cap on a bridged TCP stream. Reaching it stops the stack
/// from draining the socket, which closes the TCP window — real backpressure.
const STREAM_QUEUE_MAX: usize = 128 * 1024;

/// Cap on TCP listener + connection sockets. With `TCP_RX_BYTES +
/// TCP_TX_BYTES` per socket this bounds the stack's TCP memory (~32 MiB at
/// the cap); listeners count too, so a SYN flood cannot grow it further.
const MAX_TCP_CONNS: usize = 256;
/// Cap on smoltcp UDP sockets (one per destination port in use).
const MAX_UDP_SOCKETS: usize = 256;
/// Cap on UDP relay sessions (one per client source address). Each holds a
/// pump task, so a source-port flood must not create tasks without bound.
const MAX_UDP_SESSIONS: usize = 1024;
/// Cap on packets waiting to be handed to the stack in one batch.
const MAX_STAGED_PACKETS: usize = 2048;
/// Cap on replies waiting to be injected from off-task producers.
const MAX_PENDING_REPLIES: usize = 1024;
/// Packets the reader pump may queue between the device thread and this
/// task. Beyond it the thread parks in `blocking_send` and the kernel's
/// device queue absorbs the burst — the overload behavior of a NIC.
const READER_CHANNEL: usize = 1024;

/// Idle UDP sessions are reaped this long after the last datagram, matching
/// the socks association's lazy teardown.
const UDP_SESSION_IDLE: Duration = Duration::from_secs(120);
/// How often the session reaper runs.
const UDP_GC_INTERVAL: Duration = Duration::from_secs(10);

/// Bounds on the netstack's sleep; `MAX_TICK` is also the "nothing to do" tick.
const MIN_TICK: Duration = Duration::from_millis(1);
const MAX_TICK: Duration = Duration::from_secs(1);

/// Chunk size for moving bytes between a smoltcp socket and a stream.
const PUMP_CHUNK: usize = 32 * 1024;

// ---------------------------------------------------------------------------
// Packet classification (pure; unit-tested over hand-built headers)
// ---------------------------------------------------------------------------

/// What one raw TUN packet is, from the inbound's point of view. Both IP
/// families are parsed: the stack runs `proto-ipv4` + `proto-ipv6`, and TCP
/// listeners / UDP sockets match by port across families.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Classified<'a> {
    Tcp {
        src: SocketAddr,
        dst: SocketAddr,
        /// SYN set — the only trigger that may need a new listener.
        syn: bool,
        /// The transport header sat behind IPv6 extension headers (true only
        /// for v6; see [`stage`](Netstack::stage) for what that changes).
        ext: bool,
    },
    Udp {
        src: SocketAddr,
        dst: SocketAddr,
        payload: &'a [u8],
        /// Arrived behind IPv6 extension headers.
        ext: bool,
    },
    /// ICMP echo request — v4 type 8 / v6 type 128 (possibly behind an
    /// extension-header chain). Answered locally by [`icmpv4_echo_reply`] /
    /// [`icmpv6_echo_reply`], never staged.
    IcmpEchoRequest {
        src: IpAddr,
        dst: IpAddr,
        v6: bool,
    },
    /// IP but not TCP/UDP/echo-request: every other ICMP type (errors,
    /// echoes of our own pings, IGMP, ...), IPv6 chains that end without a
    /// parseable transport (non-initial fragments, ESP, "no next header",
    /// unknown headers), and non-ICMP protocols.
    Other {
        version: u8,
        proto: u8,
    },
    /// Neither IPv4 nor IPv6.
    Unsupported {
        version: u8,
    },
    Malformed,
}

const FLAG_SYN: u8 = 0x02;
/// ICMP message types answered locally.
const ICMPV4_ECHO_REQUEST: u8 = 8;
const ICMPV6_ECHO_REQUEST: u8 = 128;
/// IP protocol / next-header numbers.
const IPPROTO_ICMPV4: u8 = 1;
const IPPROTO_ICMPV6: u8 = 58;

/// Parse just enough of an IPv4 or IPv6 packet to route it. Never panics on
/// garbage: every slice is length-checked and the header's length field is
/// clamped to what was actually read.
pub(crate) fn classify_packet(pkt: &[u8]) -> Classified<'_> {
    let Some(&vihl) = pkt.first() else {
        return Classified::Malformed;
    };
    match vihl >> 4 {
        4 => classify_v4(pkt),
        6 => classify_v6(pkt),
        version => Classified::Unsupported { version },
    }
}

fn classify_v4(pkt: &[u8]) -> Classified<'_> {
    let vihl = pkt[0];
    let ihl = (vihl & 0x0f) as usize * 4;
    if ihl < 20 || pkt.len() < 20 {
        return Classified::Malformed;
    }
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    if total_len < ihl {
        return Classified::Malformed;
    }
    let end = total_len.min(pkt.len());
    let proto = pkt[9];
    let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
    match proto {
        6 => {
            if end < ihl + 20 {
                return Classified::Malformed;
            }
            let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
            let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
            let flags = pkt[ihl + 13];
            Classified::Tcp {
                src: SocketAddr::new(IpAddr::V4(src), src_port),
                dst: SocketAddr::new(IpAddr::V4(dst), dst_port),
                syn: flags & FLAG_SYN != 0,
                ext: false,
            }
        }
        17 => {
            if end < ihl + 8 {
                return Classified::Malformed;
            }
            let src_port = u16::from_be_bytes([pkt[ihl], pkt[ihl + 1]]);
            let dst_port = u16::from_be_bytes([pkt[ihl + 2], pkt[ihl + 3]]);
            let udp_len = u16::from_be_bytes([pkt[ihl + 4], pkt[ihl + 5]]) as usize;
            let payload_start = ihl + 8;
            let payload_end = payload_start
                .saturating_add(udp_len.saturating_sub(8))
                .min(end)
                .max(payload_start);
            Classified::Udp {
                src: SocketAddr::new(IpAddr::V4(src), src_port),
                dst: SocketAddr::new(IpAddr::V4(dst), dst_port),
                payload: &pkt[payload_start..payload_end],
                ext: false,
            }
        }
        IPPROTO_ICMPV4 => {
            // Only a full 8-byte echo-request header is answered here;
            // everything else (errors, replies, truncated) falls through.
            if end >= ihl + 8 && pkt[ihl] == ICMPV4_ECHO_REQUEST {
                Classified::IcmpEchoRequest {
                    src: IpAddr::V4(src),
                    dst: IpAddr::V4(dst),
                    v6: false,
                }
            } else {
                Classified::Other { version: 4, proto }
            }
        }
        other => Classified::Other {
            version: 4,
            proto: other,
        },
    }
}

/// IPv6 next-header numbers that continue the extension-header chain
/// (RFC 8200 §4's table).
const IPV6_HOPOPTS: u8 = 0;
const IPV6_ROUTING: u8 = 43;
const IPV6_FRAGMENT: u8 = 44;
const IPV6_AUTH_HDR: u8 = 51;
const IPV6_NO_NEXT_HDR: u8 = 59;
const IPV6_DEST_OPTS: u8 = 60;
const IPV6_MOBILITY: u8 = 135;

/// Where an IPv6 extension-header chain ends up.
#[derive(Debug, PartialEq, Eq)]
enum UpperLayer {
    /// A parseable upper-layer header: its protocol and byte offset.
    Upper(u8, usize),
    /// The chain ends without one; the value is what the last next-header
    /// field named (what gvisor's `TryParseTransportProtocol` returns with
    /// ok=false — the "maybe protocol" it could not confirm).
    None(u8),
    /// A header claims more bytes than the packet carries (or is too short
    /// to even read its length).
    Malformed,
}

/// Walk an IPv6 packet's extension-header chain to the upper layer.
///
/// Ported from gvisor netstack's `TryParseTransportProtocol`
/// (pkg/tcpip/header/ipv6.go:234-273, which itself cites Linux
/// `net/ipv6/exthdrs_core.c:ipv6_skip_exthdr`) with the one addition the
/// task asked for: mobility (135) is walked too, its length rule identical
/// to hop-by-hop/routing/destination-options (RFC 6275 §6.1 — 8-octet units
/// not counting the first 8; gvisor and the kernel stop there instead).
///
/// * hop-by-hop/routing/destination-options/mobility skip
///   `(hdr-ext-len + 1) * 8` bytes;
/// * fragment is a fixed 8 bytes, and only an offset-0 fragment carries the
///   upper-layer header — a non-zero offset ends the walk with the
///   fragment's own next-header value (gvisor ipv6.go:246-254; its
///   atomic-fragment fast path at network/ipv6/ipv6.go:1610-1618 per
///   RFC 6946 is exactly the offset-0 case that keeps walking);
/// * AH skips `(hdr-ext-len + 2) * 4` bytes (RFC 4302 §2.2; gvisor
///   ipv6.go:261-262) — the walk continues past it;
/// * ESP, "no next header" and any unrecognized header end the walk with
///   `None` (gvisor `IsExtensionHeader` ipv6.go:219-227 + the default arm);
/// * hop-by-hop anywhere but immediately after the IPv6 header is invalid
///   (RFC 8200 §4.1; gvisor rejects it in
///   `processIPv6HopByHopOptionsExtHdr`, network/ipv6/ipv6.go:1589-1596).
///
/// Offsets strictly grow and every skip is bounds-checked against `limit`,
/// so the walk always terminates.
fn ipv6_upper_layer(pkt: &[u8], limit: usize) -> UpperLayer {
    let mut nh = pkt[6];
    let mut off = 40usize;
    loop {
        if off >= limit {
            // The chain consumed the whole payload; no upper-layer bytes
            // remain (gvisor: "if len(data) == 0 ... return ok=false"). For
            // a transport that was promised but is not present that is a
            // malformed packet (the pre-ext-header classifier's label for a
            // truncated TCP/UDP); for anything else it stays `None` — an
            // unknown protocol is unparseable, not broken.
            return match nh {
                6 | 17 | IPPROTO_ICMPV6 => UpperLayer::Malformed,
                _ => UpperLayer::None(nh),
            };
        }
        let len = match nh {
            6 | 17 | IPPROTO_ICMPV6 => return UpperLayer::Upper(nh, off),
            IPV6_HOPOPTS if off != 40 => {
                return UpperLayer::None(IPV6_HOPOPTS);
            }
            IPV6_HOPOPTS | IPV6_ROUTING | IPV6_DEST_OPTS | IPV6_MOBILITY => {
                if off + 2 > limit {
                    return UpperLayer::Malformed;
                }
                8 * (pkt[off + 1] as usize + 1)
            }
            IPV6_FRAGMENT => {
                if off + 8 > limit {
                    return UpperLayer::Malformed;
                }
                if u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]) >> 3 != 0 {
                    // Non-initial fragment: the transport is in another
                    // fragment; report what the fragment header says
                    // follows it, unconfirmed (gvisor's shape).
                    return UpperLayer::None(pkt[off]);
                }
                8
            }
            IPV6_AUTH_HDR => {
                if off + 2 > limit {
                    return UpperLayer::Malformed;
                }
                4 * (pkt[off + 1] as usize + 2)
            }
            // ESP, "no next header" and any unrecognized header: the chain
            // ends here, unconfirmed (gvisor ipv6.go:265-267).
            IPV6_NO_NEXT_HDR => return UpperLayer::None(IPV6_NO_NEXT_HDR),
            other => return UpperLayer::None(other),
        };
        if off + len > limit {
            return UpperLayer::Malformed;
        }
        nh = pkt[off];
        off += len;
    }
}

/// IPv6 base header (RFC 8200 §3: fixed 40 bytes) plus, since the ext-header
/// pass, whatever chain follows it: the transport is found by
/// [`ipv6_upper_layer`], and packets that arrive through a chain carry
/// `ext = true` (which keeps them out of smoltcp — see the module docs).
fn classify_v6(pkt: &[u8]) -> Classified<'_> {
    if pkt.len() < 40 {
        return Classified::Malformed;
    }
    let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let end = 40 + payload_len.min(pkt.len() - 40);
    let src_bytes: [u8; 16] = pkt[8..24].try_into().expect("24-8 is the address length");
    let dst_bytes: [u8; 16] = pkt[24..40].try_into().expect("40-24 is the address length");
    let src = IpAddr::V6(Ipv6Addr::from(src_bytes));
    let dst = IpAddr::V6(Ipv6Addr::from(dst_bytes));
    let (next_header, off) = match ipv6_upper_layer(pkt, end) {
        UpperLayer::Upper(nh, off) => (nh, off),
        UpperLayer::None(proto) => return Classified::Other { version: 6, proto },
        UpperLayer::Malformed => return Classified::Malformed,
    };
    let ext = off > 40;
    match next_header {
        6 => {
            if end < off + 20 {
                return Classified::Malformed;
            }
            let src_port = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
            let dst_port = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]);
            let flags = pkt[off + 13];
            Classified::Tcp {
                src: SocketAddr::new(src, src_port),
                dst: SocketAddr::new(dst, dst_port),
                syn: flags & FLAG_SYN != 0,
                ext,
            }
        }
        17 => {
            if end < off + 8 {
                return Classified::Malformed;
            }
            let src_port = u16::from_be_bytes([pkt[off], pkt[off + 1]]);
            let dst_port = u16::from_be_bytes([pkt[off + 2], pkt[off + 3]]);
            let udp_len = u16::from_be_bytes([pkt[off + 4], pkt[off + 5]]) as usize;
            let payload_start = off + 8;
            let payload_end = payload_start
                .saturating_add(udp_len.saturating_sub(8))
                .min(end)
                .max(payload_start);
            Classified::Udp {
                src: SocketAddr::new(src, src_port),
                dst: SocketAddr::new(dst, dst_port),
                payload: &pkt[payload_start..payload_end],
                ext,
            }
        }
        IPPROTO_ICMPV6 => {
            if end >= off + 8 && pkt[off] == ICMPV6_ECHO_REQUEST {
                Classified::IcmpEchoRequest { src, dst, v6: true }
            } else {
                Classified::Other {
                    version: 6,
                    proto: next_header,
                }
            }
        }
        _ => unreachable!("ipv6_upper_layer only confirms TCP, UDP or ICMPv6"),
    }
}

// ---------------------------------------------------------------------------
// ICMP echo responder (pure; unit-tested over hand-built requests)
// ---------------------------------------------------------------------------

/// One's-complement internet checksum (RFC 1071) over the concatenation of
/// `parts`. `!inet_sum(parts)` is the checksum field; summing a valid message
/// *including* its checksum field yields 0, which is how the tests verify
/// replies. Shared by the production responder and nothing else — the test
/// module keeps its own independent copy so a bug here cannot hide itself.
fn inet_sum(parts: &[&[u8]]) -> u16 {
    let mut sum: u32 = 0;
    for part in parts {
        let mut i = 0;
        while i + 1 < part.len() {
            sum += u16::from_be_bytes([part[i], part[i + 1]]) as u32;
            i += 2;
        }
        if i < part.len() {
            sum += (part[i] as u32) << 8;
        }
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum as u16
}

fn checksum(parts: &[&[u8]]) -> u16 {
    !inet_sum(parts)
}

/// Build the echo reply for one IPv4 echo-request packet.
///
/// The reply swaps source and destination, answers with type 0, keeps
/// id/seq/data verbatim (that is what `ping` matches on) and recomputes both
/// checksums: the ICMP checksum covers only the ICMP message, the header
/// checksum only the IPv4 header. `None` when the packet is not a
/// well-formed echo request.
pub(crate) fn icmpv4_echo_reply(pkt: &[u8]) -> Option<Vec<u8>> {
    let vihl = *pkt.first()?;
    let ihl = (vihl & 0x0f) as usize * 4;
    if ihl < 20 || pkt.len() < ihl + 8 {
        return None;
    }
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    let end = total_len.clamp(ihl + 8, pkt.len());
    let icmp = &pkt[ihl..end];
    if icmp[0] != ICMPV4_ECHO_REQUEST {
        return None;
    }
    let mut icmp_out = icmp.to_vec();
    icmp_out[0] = 0; // echo reply
    icmp_out[1] = 0;
    icmp_out[2..4].copy_from_slice(&[0, 0]);
    let ck = checksum(&[&icmp_out]);
    icmp_out[2..4].copy_from_slice(&ck.to_be_bytes());

    let mut out = pkt[..ihl].to_vec();
    out[8] = 64; // a fresh hop limit for a locally generated reply
    out[12..16].copy_from_slice(&pkt[16..20]); // src <- request dst
    out[16..20].copy_from_slice(&pkt[12..16]); // dst <- request src
    out[10..12].copy_from_slice(&[0, 0]);
    let ck = checksum(&[&out]);
    out[10..12].copy_from_slice(&ck.to_be_bytes());

    out.extend_from_slice(&icmp_out);
    Some(out)
}

/// Build the echo reply for one IPv6 echo-request packet: type 129, swapped
/// addresses, id/seq/data verbatim. The ICMPv6 checksum covers the message
/// *plus* the IPv6 pseudo-header (src, dst, upper-layer packet length, next
/// header 58), computed over the reply's own (swapped) addresses — RFC 4443
/// §2.1 with RFC 8200 §8.1. `None` when the packet is not a well-formed
/// echo request.
///
/// The echo request may sit behind an extension-header chain (found with the
/// same [`ipv6_upper_layer`] walk the classifier uses); the chain is copied
/// verbatim into the reply, and per RFC 8200 §8.1 the pseudo-header carries
/// the *upper-layer* length and protocol — extension headers count in
/// neither, so the checksum is over the ICMP message alone either way.
pub(crate) fn icmpv6_echo_reply(pkt: &[u8]) -> Option<Vec<u8>> {
    if pkt.len() < 48 {
        return None;
    }
    let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let end = 40 + payload_len.clamp(8, pkt.len() - 40);
    let off = match ipv6_upper_layer(pkt, end) {
        UpperLayer::Upper(IPPROTO_ICMPV6, off) => off,
        _ => return None,
    };
    if end < off + 8 {
        return None;
    }
    let icmp = &pkt[off..end];
    if icmp[0] != ICMPV6_ECHO_REQUEST {
        return None;
    }
    let mut icmp_out = icmp.to_vec();
    icmp_out[0] = 129; // echo reply
    icmp_out[1] = 0;
    icmp_out[2..4].copy_from_slice(&[0, 0]);

    // Base header + any extension chain, copied verbatim up to the message.
    let mut out = pkt[..off].to_vec();
    out[7] = 64; // hop limit of a locally generated reply
    out[8..24].copy_from_slice(&pkt[24..40]); // src <- request dst
    out[24..40].copy_from_slice(&pkt[8..24]); // dst <- request src

    // Pseudo-header over the reply's addresses (RFC 8200 §8.1): the length
    // is the upper-layer packet length (payload minus extension headers),
    // so `icmp_out.len()` — not the on-wire payload length — and next header
    // 58, never the chain's first header type.
    let mut pseudo = [0u8; 40];
    pseudo[..16].copy_from_slice(&out[8..24]);
    pseudo[16..32].copy_from_slice(&out[24..40]);
    pseudo[32..36].copy_from_slice(&(icmp_out.len() as u32).to_be_bytes());
    pseudo[39] = IPPROTO_ICMPV6;
    let ck = checksum(&[&pseudo, &icmp_out]);
    icmp_out[2..4].copy_from_slice(&ck.to_be_bytes());

    out.extend_from_slice(&icmp_out);
    Some(out)
}

/// Relay session key for TUN UDP: one association per client source address,
/// however many destinations that client talks to — the same identity the
/// socks inbound gives a UDP association.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) struct UdpSessionKey(pub SocketAddr);

impl UdpSessionKey {
    pub(crate) fn for_packet(src: SocketAddr) -> Self {
        UdpSessionKey(src)
    }
}

/// Is this destination answered by the engine's resolver instead of the
/// relay? Matched by address AND port (mihomo #1689: `any:53` is the
/// address wildcard on port 53 only — matching by address alone captured
/// non-DNS traffic to a hijack address), in either family.
pub(crate) fn is_dns_hijack(dst: SocketAddr, hijack: &[DnsHijack]) -> bool {
    hijack.iter().any(|h| {
        h.port == dst.port() && h.ip.is_none_or(|ip| ip == dst.ip())
    })
}

/// Facts about one live TCP socket that decide whether an arriving SYN needs
/// a brand-new listener. Pure so the policy is testable without a stack:
/// smoltcp matches a listening socket by destination port and a connected one
/// by its exact 4-tuple, so a SYN is already covered when either exists.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct SocketFacts {
    pub port: u16,
    pub listening: bool,
    pub local: Option<(IpAddr, u16)>,
    pub remote: Option<(IpAddr, u16)>,
}

pub(crate) fn needs_new_listener(facts: &[SocketFacts], src: SocketAddr, dst: SocketAddr) -> bool {
    let covered = facts.iter().any(|f| {
        f.port == dst.port()
            && (f.listening
                || (f.local == Some((dst.ip(), dst.port()))
                    && f.remote == Some((src.ip(), src.port()))))
    });
    !covered
}

// ---------------------------------------------------------------------------
// TCP bridge: StreamShared + TunStream
// ---------------------------------------------------------------------------

/// Queues and wakers of one bridged TCP connection. Everything lives under a
/// single mutex: pushing bytes and taking the waker happen in one critical
/// section, which is what makes the hand-off race-free.
struct StreamBufs {
    /// stack -> proxy (read off the smoltcp socket, waiting to be read).
    to_proxy: VecDeque<u8>,
    /// proxy -> stack (waiting for the smoltcp send buffer / window).
    to_stack: VecDeque<u8>,
    /// The peer finished sending and the socket's rx is drained: read EOF.
    read_eof: bool,
    /// The proxy half-closed; FIN once `to_stack` drains.
    write_closed: bool,
    /// The proxy dropped the stream: abort the connection.
    aborted: bool,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

struct StreamShared {
    bufs: Mutex<StreamBufs>,
    /// Pings the netstack task: "queues changed, come and move bytes".
    wake: Arc<Notify>,
}

impl StreamShared {
    fn new(wake: Arc<Notify>) -> Self {
        StreamShared {
            bufs: Mutex::new(StreamBufs {
                to_proxy: VecDeque::new(),
                to_stack: VecDeque::new(),
                read_eof: false,
                write_closed: false,
                aborted: false,
                read_waker: None,
                write_waker: None,
            }),
            wake,
        }
    }

    fn lock(&self) -> MutexGuard<'_, StreamBufs> {
        // A panicking relay task must not wedge the inbound.
        self.bufs.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// One accepted TCP connection as a byte stream.
///
/// Reads drain `to_proxy` and park the reader's waker; writes append to
/// `to_stack` and notify the netstack task, which pushes them into the
/// smoltcp socket as window space allows. Both directions are bounded, so a
/// slow peer slows the other side down instead of growing memory.
pub struct TunStream {
    shared: Arc<StreamShared>,
}

impl Drop for TunStream {
    fn drop(&mut self) {
        let mut g = self.shared.lock();
        g.aborted = true;
        g.read_eof = true;
        g.write_closed = true;
        drop(g);
        self.shared.wake.notify_one();
    }
}

impl AsyncRead for TunStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut g = self.shared.lock();
        if !g.to_proxy.is_empty() {
            let n = g.to_proxy.len().min(buf.remaining());
            let (front, back) = g.to_proxy.as_slices();
            let take_front = n.min(front.len());
            buf.put_slice(&front[..take_front]);
            if take_front < n {
                buf.put_slice(&back[..n - take_front]);
            }
            g.to_proxy.drain(..n);
            return Poll::Ready(Ok(()));
        }
        if g.read_eof {
            // EOF: a successful read that fills nothing.
            return Poll::Ready(Ok(()));
        }
        g.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for TunStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut g = self.shared.lock();
        if g.aborted || g.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "tun: stream is closed",
            )));
        }
        let space = STREAM_QUEUE_MAX.saturating_sub(g.to_stack.len());
        if space == 0 {
            g.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = space.min(buf.len());
        g.to_stack.extend(buf[..n].iter().copied());
        drop(g);
        self.shared.wake.notify_one();
        Poll::Ready(Ok(n))
    }

    /// No-op: every accepted byte is already queued for the stack, and
    /// "flush" has no further meaning on a socket (`tokio::net::TcpStream`
    /// behaves the same).
    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    /// Half-close: the FIN goes out once the queued bytes have been sent.
    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<io::Result<()>> {
        self.shared.lock().write_closed = true;
        self.shared.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

// ---------------------------------------------------------------------------
// Packet sink + smoltcp device shim
// ---------------------------------------------------------------------------

/// Where the stack's egress goes. Production is the device (through
/// [`TunIoSink`]); tests capture the packets so the identical path runs
/// without privileges.
pub(crate) trait PacketSink: Send + Sync + 'static {
    fn send(&self, pkt: &[u8]) -> io::Result<()>;
}

/// The device as the stack's egress sink: one nonblocking write per packet
/// (`WouldBlock` drops — see `TxTok::consume`), exactly the write half every
/// platform backend already provides.
struct TunIoSink(Arc<dyn TunIo>);

impl PacketSink for TunIoSink {
    fn send(&self, pkt: &[u8]) -> io::Result<()> {
        self.0.send(pkt)
    }
}

/// The smoltcp `Device` over the TUN: ingress packets are staged by the
/// netstack loop (which peeks at SYNs first), egress goes straight to the
/// sink. One scratch buffer is reused for every transmit.
struct DeviceShim {
    sink: Arc<dyn PacketSink>,
    ingress: VecDeque<Vec<u8>>,
    scratch: Vec<u8>,
    mtu: usize,
    dropped: u64,
}

impl DeviceShim {
    fn new(sink: Arc<dyn PacketSink>, mtu: usize) -> Self {
        DeviceShim {
            sink,
            ingress: VecDeque::new(),
            scratch: Vec::new(),
            mtu,
            dropped: 0,
        }
    }

    /// Stage one packet for the next poll. Returns false when the staging
    /// queue is full — under overload we drop, which is what a NIC does.
    fn stage(&mut self, pkt: &[u8]) -> bool {
        if self.ingress.len() >= MAX_STAGED_PACKETS {
            self.dropped += 1;
            if self.dropped == 1 || self.dropped.is_multiple_of(1000) {
                tracing::debug!(
                    target: "engine",
                    "tun: ingress queue full, dropped {} packets",
                    self.dropped
                );
            }
            return false;
        }
        self.ingress.push_back(pkt.to_vec());
        true
    }
}

impl Device for DeviceShim {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok<'a>;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(RxTok, TxTok<'_>)> {
        let pkt = self.ingress.pop_front()?;
        Some((
            RxTok { pkt },
            TxTok {
                sink: &*self.sink,
                scratch: &mut self.scratch,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<TxTok<'_>> {
        Some(TxTok {
            sink: &*self.sink,
            scratch: &mut self.scratch,
        })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        // Checksums stay in software (`caps.checksum` default): a TUN does
        // no offload, so the stack must compute them.
        caps
    }
}

/// Owns the staged packet: an `RxToken` borrows nothing from the device.
struct RxTok {
    pkt: Vec<u8>,
}

impl RxToken for RxTok {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.pkt)
    }
}

struct TxTok<'a> {
    sink: &'a dyn PacketSink,
    scratch: &'a mut Vec<u8>,
}

impl TxToken for TxTok<'_> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        self.scratch.clear();
        self.scratch.resize(len, 0);
        let out = {
            let buf = &mut self.scratch[..len];
            f(buf)
        };
        if let Err(e) = self.sink.send(&self.scratch[..len]) {
            // WouldBlock is normal under load: the device queue is full and
            // the packet is dropped (TCP retransmits, UDP is lossy anyway).
            if e.kind() != io::ErrorKind::WouldBlock {
                tracing::debug!(target: "engine", "tun: egress write failed: {e}");
            }
        }
        out
    }
}

// ---------------------------------------------------------------------------
// Netstack
// ---------------------------------------------------------------------------

/// A bridged TCP connection: the smoltcp socket handle plus its stream half.
struct Conn {
    handle: SocketHandle,
    shared: Arc<StreamShared>,
    /// FIN already pushed to the stack after the proxy half-closed.
    fin_sent: bool,
}

/// One UDP relay association (per client source address).
struct UdpSession {
    uplink: mpsc::Sender<(NetAddr, Vec<u8>)>,
    last_activity: std::time::Instant,
    /// Downlink pump; aborted when the session is dropped.
    pump: tokio::task::JoinHandle<()>,
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        self.pump.abort();
    }
}

/// A datagram to hand back to the TUN, from the resolver or a relay session.
struct UdpReply {
    /// Where it goes: the client's source address.
    client: SocketAddr,
    /// Where it appears to come from: the destination the client dialled.
    local: SocketAddr,
    data: Vec<u8>,
}

struct Netstack {
    iface: Interface,
    sockets: SocketSet<'static>,
    shim: DeviceShim,
    /// Where locally generated packets (ICMP echo replies) go, the same sink
    /// the device shim transmits through.
    sink: Arc<dyn PacketSink>,
    relay: SharedRelay,
    tag: String,
    dns: Option<Arc<DnsEngine>>,
    dns_hijack: Vec<DnsHijack>,
    /// Listening sockets: (handle, destination port). A socket leaves this
    /// list and becomes a `Conn` once its handshake completes.
    listeners: Vec<(SocketHandle, u16)>,
    conns: Vec<Conn>,
    /// smoltcp UDP sockets by destination port (what `accepts()` matches).
    udp_sockets: HashMap<u16, SocketHandle>,
    sessions: HashMap<UdpSessionKey, UdpSession>,
    /// Replies produced off-task (resolver, relay downlinks), drained in step().
    replies: Arc<Mutex<VecDeque<UdpReply>>>,
    /// Wakes the task when a stream or a downlink has work.
    wake: Arc<Notify>,
    start: std::time::Instant,
    next_gc: std::time::Instant,
    pump_buf: Vec<u8>,
}

impl Netstack {
    fn new(
        sink: Arc<dyn PacketSink>,
        cfg: &TunConfig,
        relay: SharedRelay,
        hooks: TunHooks,
    ) -> Result<Self> {
        let mtu = cfg.mtu.max(576) as usize;
        let mut shim = DeviceShim::new(sink.clone(), mtu);
        let mut iface_cfg = IfaceConfig::new(HardwareAddress::Ip);
        // Randomised ISNs and ephemeral ports: two engines on one host must
        // not pick colliding sequence numbers.
        iface_cfg.random_seed = rand::random();
        let mut iface = Interface::new(iface_cfg, &mut shim, SmolInstant::ZERO);
        iface.update_ip_addrs(|addrs| {
            // One address per family is enough: any_ip accepts every
            // destination, and each one exists so the default routes below
            // have a gateway.
            let _ = addrs.push(IpCidr::new(
                IpAddress::Ipv4(cfg.address),
                cfg.netmask.min(32),
            ));
            if let Some((inet6, prefix)) = cfg.inet6_address {
                let _ = addrs.push(IpCidr::new(IpAddress::Ipv6(inet6), prefix.min(128)));
            }
        });
        // any_ip only accepts a packet when a route lookup succeeds, so a
        // default route is required per family in use (smoltcp documents that
        // coupling).
        iface
            .routes_mut()
            .add_default_ipv4_route(cfg.address)
            .map_err(|_| Error::network("tun: route table full"))?;
        if let Some((inet6, _)) = cfg.inet6_address {
            iface
                .routes_mut()
                .add_default_ipv6_route(inet6)
                .map_err(|_| Error::network("tun: route table full"))?;
        }
        iface.set_any_ip(true);

        let now = std::time::Instant::now();
        Ok(Netstack {
            iface,
            sockets: SocketSet::new(Vec::new()),
            shim,
            sink,
            relay,
            tag: cfg.tag.clone(),
            dns: hooks.dns,
            dns_hijack: cfg.dns_hijack.clone(),
            listeners: Vec::new(),
            conns: Vec::new(),
            udp_sockets: HashMap::new(),
            sessions: HashMap::new(),
            replies: Arc::new(Mutex::new(VecDeque::new())),
            wake: Arc::new(Notify::new()),
            start: now,
            next_gc: now + UDP_GC_INTERVAL,
            pump_buf: vec![0u8; PUMP_CHUNK],
        })
    }

    fn now(&self) -> SmolInstant {
        SmolInstant::from_micros(self.start.elapsed().as_micros() as i64)
    }

    /// Hand one raw TUN packet to the stack, after the peeks the stack cannot
    /// do itself: smoltcp has no listen-on-any-port socket, so a SYN's
    /// destination port must have a listener *before* the packet is polled;
    /// and ICMP echo requests are answered by us, not staged (staging one
    /// addressed to the interface would make smoltcp answer it too).
    fn stage(&mut self, pkt: &[u8]) {
        match classify_packet(pkt) {
            Classified::Tcp { src, dst, syn, ext } => {
                if ext {
                    // The classifier followed the chain, but smoltcp does
                    // not: only hop-by-hop is consumed before dispatch
                    // (smoltcp iface/interface/ipv6.rs:204-210) and any other
                    // chain reaches process_nxt_hdr as an unrecognized
                    // next-header, which it answers with an ICMPv6 Parameter
                    // Problem (ipv6.rs:352-367). Staging the SYN would only
                    // earn the client that error, so it is dropped here —
                    // upstream sing-tun tolerates chains because gvisor
                    // parses them in-stack before demux.
                    tracing::debug!(target: "engine",
                        "tun: dropping IPv6 TCP behind extension headers ({src} -> {dst})");
                    return;
                }
                if syn && needs_new_listener(&self.socket_facts(), src, dst) {
                    self.add_listener(dst.port());
                }
                self.shim.stage(pkt);
            }
            Classified::Udp { src, dst, payload, ext } => {
                // The stack needs a UDP socket bound to this port even though
                // the payload is handled here: without one smoltcp answers
                // every relayed datagram with an ICMP port-unreachable, which
                // would tell the client the destination is dead. At the
                // socket cap the datagram is dropped instead — a silent drop
                // is the honest failure, a false ICMP is not. The socket is
                // also the reply path for hijacked answers and relay
                // downlinks, so it is bound for ext-headered datagrams too.
                if self.ensure_udp_socket(dst.port()).is_none() {
                    return;
                }
                if is_dns_hijack(dst, &self.dns_hijack) {
                    // Answered by the engine's resolver, never relayed.
                    self.spawn_dns(payload.to_vec(), src, dst);
                } else {
                    self.udp_uplink(src, dst, payload.to_vec());
                }
                if ext {
                    // Same smoltcp limitation as the TCP arm: the datagram
                    // itself is fully handled above (resolver or relay), and
                    // only the redundant staging copy — which would draw an
                    // ICMPv6 Parameter Problem — is skipped.
                    return;
                }
                self.shim.stage(pkt);
            }
            Classified::IcmpEchoRequest { v6, .. } => {
                // Answer the ping ourselves, straight onto the device: the
                // reply is sourced from the pinged address (which for the
                // tunnel's own address is the tunnel itself) and carries the
                // request's id/seq/data back, so every `ping` through the
                // tunnel succeeds — mihomo parity.
                let reply = if v6 {
                    icmpv6_echo_reply(pkt)
                } else {
                    icmpv4_echo_reply(pkt)
                };
                match reply {
                    Some(reply) => {
                        if let Err(e) = self.sink.send(&reply) {
                            if e.kind() != io::ErrorKind::WouldBlock {
                                tracing::debug!(target: "engine", "tun: echo reply write failed: {e}");
                            }
                        }
                    }
                    None => tracing::debug!(
                        target: "engine",
                        "tun: dropping malformed ICMP{} echo request",
                        if v6 { "v6" } else { "" }
                    ),
                }
            }
            Classified::Other { version, proto } => {
                if proto == IPPROTO_ICMPV4 || proto == IPPROTO_ICMPV6 {
                    tracing::debug!(target: "engine",
                        "tun: dropping IPv{version} ICMP (only echo requests are answered)");
                } else {
                    tracing::debug!(target: "engine",
                        "tun: dropping IPv{version} proto {proto}");
                }
            }
            Classified::Unsupported { version } => {
                tracing::debug!(target: "engine",
                    "tun: dropping IP version {version} packet (only IPv4/IPv6 are handled)");
            }
            Classified::Malformed => {
                tracing::debug!(target: "engine", "tun: dropping malformed packet ({} bytes)", pkt.len());
            }
        }
    }

    /// Current view of every TCP socket, for `needs_new_listener`.
    fn socket_facts(&self) -> Vec<SocketFacts> {
        fn facts(s: &tcp::Socket<'_>, port: u16) -> SocketFacts {
            SocketFacts {
                port,
                listening: s.state() == tcp::State::Listen,
                local: ep_addr(s.local_endpoint()),
                remote: ep_addr(s.remote_endpoint()),
            }
        }
        let mut out = Vec::with_capacity(self.listeners.len() + self.conns.len());
        for (handle, port) in &self.listeners {
            out.push(facts(self.sockets.get::<tcp::Socket>(*handle), *port));
        }
        for c in &self.conns {
            let s = self.sockets.get::<tcp::Socket>(c.handle);
            out.push(facts(s, s.local_endpoint().map(|e| e.port).unwrap_or(0)));
        }
        out
    }

    fn add_listener(&mut self, port: u16) {
        if self.listeners.len() + self.conns.len() >= MAX_TCP_CONNS {
            tracing::debug!(target: "engine", "tun: connection limit reached, refusing port {port}");
            return;
        }
        let mut sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_RX_BYTES]),
            tcp::SocketBuffer::new(vec![0; TCP_TX_BYTES]),
        );
        // Any address, this exact port: `accepts()` compares dst_port only.
        if let Err(e) = sock.listen(IpListenEndpoint { addr: None, port }) {
            tracing::debug!(target: "engine", "tun: cannot listen on port {port}: {e:?}");
            return;
        }
        let handle = self.sockets.add(sock);
        self.listeners.push((handle, port));
    }

    fn ensure_udp_socket(&mut self, port: u16) -> Option<SocketHandle> {
        if let Some(handle) = self.udp_sockets.get(&port) {
            return Some(*handle);
        }
        if self.udp_sockets.len() >= MAX_UDP_SOCKETS {
            tracing::debug!(target: "engine", "tun: too many UDP destination ports, dropping port {port}");
            return None;
        }
        let mut sock = udp::Socket::new(
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_PACKETS],
                vec![0; UDP_RX_BYTES],
            ),
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_PACKETS],
                vec![0; UDP_TX_BYTES],
            ),
        );
        if let Err(e) = sock.bind(IpListenEndpoint { addr: None, port }) {
            tracing::debug!(target: "engine", "tun: cannot bind UDP port {port}: {e:?}");
            return None;
        }
        let handle = self.sockets.add(sock);
        self.udp_sockets.insert(port, handle);
        Some(handle)
    }

    /// Datagram from the tunnel: feed the client's relay session, opening it
    /// on first use (mirrors socks UDP_ASSOCIATE — one association per client
    /// source address, torn down after `UDP_SESSION_IDLE`).
    fn udp_uplink(&mut self, src: SocketAddr, dst: SocketAddr, payload: Vec<u8>) {
        let key = UdpSessionKey::for_packet(src);
        let uplink = match self.sessions.get_mut(&key) {
            Some(s) => {
                s.last_activity = std::time::Instant::now();
                s.uplink.clone()
            }
            None => {
                if self.sessions.len() >= MAX_UDP_SESSIONS {
                    tracing::debug!(target: "engine", "tun: {MAX_UDP_SESSIONS} udp sessions active, datagram from {src} dropped");
                    return;
                }
                self.open_session(key)
            }
        };
        // UDP is lossy; a full session queue drops rather than blocks.
        if uplink
            .try_send((NetAddr::ip(dst.ip(), dst.port()), payload))
            .is_err()
        {
            tracing::debug!(target: "engine", "tun: udp uplink queue full for {src}, datagram dropped");
        }
    }

    fn open_session(&mut self, key: UdpSessionKey) -> mpsc::Sender<(NetAddr, Vec<u8>)> {
        let (up_tx, up_rx) = mpsc::channel::<(NetAddr, Vec<u8>)>(64);
        let (down_tx, mut down_rx) = mpsc::channel::<(NetAddr, Vec<u8>)>(64);
        self.relay
            .clone()
            .handle_udp(key.0, self.tag.clone(), up_rx, down_tx);

        let replies = self.replies.clone();
        let wake = self.wake.clone();
        let client = key.0;
        // Downlink pump: relay replies become packets for the TUN. It ends
        // when the engine closes its side, or when the session is dropped
        // (the task handle is aborted).
        let pump = tokio::spawn(async move {
            while let Some((from, data)) = down_rx.recv().await {
                let Some(local) = netaddr_to_socketaddr(&from) else {
                    tracing::debug!(target: "engine", "tun: udp reply to {client} for non-IP target {from}, dropped");
                    continue;
                };
                let mut q = replies.lock().unwrap_or_else(|e| e.into_inner());
                if q.len() >= MAX_PENDING_REPLIES {
                    continue;
                }
                q.push_back(UdpReply {
                    client,
                    local,
                    data,
                });
                drop(q);
                wake.notify_one();
            }
        });
        self.sessions.insert(
            key,
            UdpSession {
                uplink: up_tx.clone(),
                last_activity: std::time::Instant::now(),
                pump,
            },
        );
        up_tx
    }

    /// Hijacked DNS: answer through the engine's own resolver, off-task so a
    /// slow upstream cannot stall the stack.
    fn spawn_dns(&self, query: Vec<u8>, client: SocketAddr, local: SocketAddr) {
        let Some(dns) = self.dns.clone() else {
            tracing::debug!(target: "engine", "tun: DNS hijack destination {local} with no resolver configured, dropped");
            return;
        };
        let replies = self.replies.clone();
        let wake = self.wake.clone();
        tokio::spawn(async move {
            let resp = dns.handle(&query).await;
            if resp.is_empty() {
                return;
            }
            let mut q = replies.lock().unwrap_or_else(|e| e.into_inner());
            if q.len() < MAX_PENDING_REPLIES {
                q.push_back(UdpReply {
                    client,
                    local,
                    data: resp,
                });
            }
            drop(q);
            wake.notify_one();
        });
    }

    /// One pass of the stack: poll, bridge, flush, reap. Runs whenever
    /// something happened and on the stack's own timer.
    fn step(&mut self) {
        let now = self.now();
        self.iface.poll(now, &mut self.shim, &mut self.sockets);

        self.convert_listeners();
        self.drain_replies();
        self.service_conns();
        self.drain_udp_rx();

        // Flush whatever the two steps above queued in the sockets.
        let now = self.now();
        self.iface.poll(now, &mut self.shim, &mut self.sockets);
        self.gc_sessions();
    }

    /// Listeners whose handshake completed become relayed connections; dead
    /// ones are discarded (the next SYN re-creates a listener).
    fn convert_listeners(&mut self) {
        let mut keep = Vec::with_capacity(self.listeners.len());
        let mut established = Vec::new();
        let mut dead: Vec<SocketHandle> = Vec::new();
        for (handle, port) in self.listeners.drain(..) {
            let sock = self.sockets.get_mut::<tcp::Socket>(handle);
            match sock.state() {
                tcp::State::Listen | tcp::State::SynReceived => keep.push((handle, port)),
                tcp::State::Established => {
                    match (
                        ep_addr(sock.local_endpoint()),
                        ep_addr(sock.remote_endpoint()),
                    ) {
                        (Some((local_ip, local_port)), Some((remote_ip, remote_port))) => {
                            established.push((
                                handle,
                                SocketAddr::new(remote_ip, remote_port),
                                NetAddr::ip(local_ip, local_port),
                            ))
                        }
                        _ => dead.push(handle),
                    }
                }
                _ => dead.push(handle),
            }
        }
        self.listeners = keep;
        for handle in dead {
            self.sockets.remove(handle);
        }
        for (handle, source, target) in established {
            tracing::debug!(target: "engine", "tun: new tcp {source} -> {target}");
            let shared = Arc::new(StreamShared::new(self.wake.clone()));
            // TCP DNS hijack (mihomo `tcp://any:53` / sing-box #3878):
            // a connection whose ORIGINAL destination is a hijack entry
            // is answered by the engine's resolver over the same stream
            // (length-framed wireformat), never relayed — otherwise a
            // systemd-resolved falling back to TCP DNS (its standard
            // reaction to UDP loss) would be relayed right back into the
            // routing path that lost the UDP.
            let hijacked = self
                .dns
                .as_ref()
                .and_then(|_| netaddr_to_socketaddr(&target))
                .is_some_and(|dst| is_dns_hijack(dst, &self.dns_hijack));
            if hijacked {
                tracing::debug!(target: "engine",
                    "tun: hijacking tcp dns {source} -> {target}");
                let dns = self.dns.clone().expect("checked above");
                let mut stream: crate::stream::BoxProxyStream = Box::new(TunStream {
                    shared: shared.clone(),
                });
                tokio::spawn(async move {
                    crate::app::serve_dns_tcp(&mut stream, dns).await;
                });
            } else {
                self.relay.clone().handle_tcp(
                    TcpMeta {
                        target,
                        source,
                        inbound: self.tag.clone(),
                        inbound_port: None,
                        inbound_kind: "tun",
                    },
                    Box::new(TunStream {
                        shared: shared.clone(),
                    }),
                );
            }
            self.conns.push(Conn {
                handle,
                shared,
                fin_sent: false,
            });
        }
    }

    /// Replies produced off-task (resolver answers, relay downlinks) are sent
    /// from the smoltcp socket bound to the destination port, with the
    /// original destination as the source address — the client must see the
    /// answer come from where it sent. Works for either family: the smoltcp
    /// sockets listen on `addr: None`, so the same socket carries v4 and v6.
    fn drain_replies(&mut self) {
        let items: Vec<UdpReply> = {
            let mut q = self.replies.lock().unwrap_or_else(|e| e.into_inner());
            q.drain(..).collect()
        };
        for r in items {
            let Some(handle) = self.ensure_udp_socket(r.local.port()) else {
                continue;
            };
            let sock = self.sockets.get_mut::<udp::Socket>(handle);
            let mut meta =
                udp::UdpMetadata::from(IpEndpoint::new(smol_ip(r.client.ip()), r.client.port()));
            meta.local_address = Some(smol_ip(r.local.ip()));
            if let Err(e) = sock.send_slice(&r.data, meta) {
                tracing::debug!(target: "engine", "tun: udp reply to {}: {e:?}", r.client);
            }
        }
    }

    /// Move bytes between the smoltcp sockets and the stream queues. This is
    /// the only place the two are connected, and it never blocks: a queue
    /// that is full simply stops being drained (window backpressure).
    fn service_conns(&mut self) {
        let mut dead: Vec<SocketHandle> = Vec::new();
        for c in self.conns.iter_mut() {
            let sock = self.sockets.get_mut::<tcp::Socket>(c.handle);
            let mut g = c.shared.lock();

            // stack -> proxy
            while g.to_proxy.len() < STREAM_QUEUE_MAX && sock.can_recv() {
                let n = match sock.recv_slice(&mut self.pump_buf) {
                    Ok(n) => n,
                    Err(_) => break,
                };
                g.to_proxy.extend(self.pump_buf[..n].iter().copied());
            }
            if !sock.may_recv() && sock.recv_queue() == 0 {
                g.read_eof = true;
            }

            // proxy -> stack
            while !g.to_stack.is_empty() && sock.can_send() {
                let n = match sock.send_slice(g.to_stack.make_contiguous()) {
                    Ok(n) => n,
                    Err(_) => break,
                };
                g.to_stack.drain(..n);
            }
            if g.write_closed && g.to_stack.is_empty() && !c.fin_sent {
                sock.close();
                c.fin_sent = true;
            }
            if g.aborted {
                sock.abort();
            }
            let gone = sock.state() == tcp::State::Closed;
            if gone {
                g.read_eof = true;
            }

            // Wake both halves while still holding the lock: a reader that
            // parked before the push was impossible, and one that parks now
            // sees the state above.
            if (!g.to_proxy.is_empty() || g.read_eof) && g.read_waker.is_some() {
                if let Some(w) = g.read_waker.take() {
                    w.wake();
                }
            }
            if (gone || g.to_stack.len() < STREAM_QUEUE_MAX) && g.write_waker.is_some() {
                if let Some(w) = g.write_waker.take() {
                    w.wake();
                }
            }
            drop(g);
            if gone {
                dead.push(c.handle);
            }
        }
        if !dead.is_empty() {
            self.conns.retain(|c| !dead.contains(&c.handle));
            for handle in dead {
                self.sockets.remove(handle);
            }
        }
    }

    /// Relayed datagrams are also buffered by the smoltcp socket that exists
    /// only to keep the stack from answering them with ICMP; discard those
    /// copies so the buffers stay empty.
    fn drain_udp_rx(&mut self) {
        for handle in self.udp_sockets.values() {
            let sock = self.sockets.get_mut::<udp::Socket>(*handle);
            while sock.can_recv() {
                if sock.recv_slice(&mut self.pump_buf).is_err() {
                    break;
                }
            }
        }
    }

    /// Reap idle UDP sessions (their pump task goes with them).
    fn gc_sessions(&mut self) {
        let now = std::time::Instant::now();
        if now < self.next_gc {
            return;
        }
        self.next_gc = now + UDP_GC_INTERVAL;
        let before = self.sessions.len();
        self.sessions.retain(|key, s| {
            let idle = now.duration_since(s.last_activity) >= UDP_SESSION_IDLE;
            if idle {
                tracing::debug!(target: "engine", "tun: udp session {} idle, closing", key.0);
            }
            !idle
        });
        if before != self.sessions.len() {
            tracing::debug!(target: "engine", "tun: {} udp sessions active", self.sessions.len());
        }
    }

    /// How long until the stack needs attention again (retransmits, TIME-WAIT
    /// expiry, session GC), clamped so the loop always makes progress.
    fn poll_delay(&mut self) -> Duration {
        let now = self.now();
        let stack = self
            .iface
            .poll_delay(now, &self.sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(MAX_TICK);
        let gc = self
            .next_gc
            .saturating_duration_since(std::time::Instant::now());
        stack.min(gc).clamp(MIN_TICK, MAX_TICK)
    }
}

/// Drive the stack until the device dies. One task owns everything; the relay
/// only ever sees `TunStream`s and UDP sessions.
///
/// Ingress is the reader pump ([`io::DeviceReader`], a dedicated thread
/// blocking on the device — the wireguard-go `RoutineReadFromTUN` shape);
/// this task consumes its channel, stages each packet after the peeks above,
/// and never touches device readiness itself. Egress is the same device
/// through [`TunIoSink`]: a nonblocking write per transmitted packet.
pub(crate) async fn run(
    dev: Arc<dyn TunIo>,
    cfg: TunConfig,
    relay: SharedRelay,
    hooks: TunHooks,
) -> Result<()> {
    // Room for the largest packet the interface can deliver, plus headroom
    // for the utun 4-byte family header macOS recv strips in place.
    let mut reader = DeviceReader::spawn(dev.clone(), cfg.mtu.max(576) as usize + 64, READER_CHANNEL)
        .map_err(|e| Error::network(e.to_string()))?;
    let mut rx = reader
        .take_receiver()
        .expect("the receiver is taken exactly once");
    let mut net = Netstack::new(Arc::new(TunIoSink(dev)), &cfg, relay, hooks)?;
    let wake = net.wake.clone();

    loop {
        net.step();
        let delay = net.poll_delay();
        tokio::select! {
            biased;
            pkt = rx.recv() => match pkt {
                Some(pkt) => {
                    net.stage(&pkt);
                    // Drain what arrived behind it: the reader thread batches
                    // (it keeps reading while packets are there), and one
                    // step per burst is the old AsyncFd drain loop's
                    // discipline.
                    while let Ok(pkt) = rx.try_recv() {
                        net.stage(&pkt);
                    }
                }
                None => {
                    // The reader stopped. The channel only closes when the
                    // thread exits, so the liveness query must agree (the
                    // unconditional read also keeps it out of dead-code
                    // pruning in release builds).
                    let finished = reader.is_finished();
                    debug_assert!(
                        finished,
                        "reader channel closed before the thread exited"
                    );
                    // Either the device died — surface the error the thread
                    // recorded — or the pump was dropped, which cannot
                    // happen while this future lives.
                    return match reader.take_error() {
                        Some(e) => Err(Error::network(format!("tun: device read: {e}"))),
                        None => Ok(()),
                    };
                }
            },
            _ = wake.notified() => {}
            _ = tokio::time::sleep(delay) => {}
        }
    }
}

/// `IpEndpoint` -> `(IpAddr, port)`, either family.
fn ep_addr(ep: Option<IpEndpoint>) -> Option<(IpAddr, u16)> {
    let ep = ep?;
    Some((std_ip(ep.addr), ep.port))
}

/// smoltcp `IpAddress` (which *is* `core::net::{Ipv4Addr, Ipv6Addr}`) ->
/// `std::net::IpAddr`.
fn std_ip(ip: IpAddress) -> IpAddr {
    match ip {
        IpAddress::Ipv4(v4) => IpAddr::V4(v4),
        IpAddress::Ipv6(v6) => IpAddr::V6(v6),
    }
}

/// The other direction, for building smoltcp endpoints and routes.
fn smol_ip(ip: IpAddr) -> IpAddress {
    match ip {
        IpAddr::V4(v4) => IpAddress::Ipv4(v4),
        IpAddr::V6(v6) => IpAddress::Ipv6(v6),
    }
}

fn netaddr_to_socketaddr(a: &NetAddr) -> Option<SocketAddr> {
    match &a.host {
        crate::addr::Host::Ip(ip) => Some(SocketAddr::new(*ip, a.port)),
        crate::addr::Host::Domain(_) => None,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddrV4;
    use std::sync::atomic::{AtomicBool, Ordering};

    // -- packet builders ----------------------------------------------------
    //
    // Everything below is hand-built (no smoltcp emitters) so the tests pin
    // the exact bytes the stack has to accept, including checksums.

    /// One's-complement checksum over the concatenation of `chunks`.
    fn checksum(chunks: &[&[u8]]) -> u16 {
        let mut sum: u32 = 0;
        for c in chunks {
            let mut i = 0;
            while i + 1 < c.len() {
                sum += u16::from_be_bytes([c[i], c[i + 1]]) as u32;
                i += 2;
            }
            if i < c.len() {
                sum += (c[i] as u32) << 8;
            }
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }

    fn ipv4_packet(proto: u8, src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut pkt = vec![
            0x45,
            0,
            (total >> 8) as u8,
            total as u8,
            0,
            0,
            0,
            0,
            64,
            proto,
            0,
            0,
        ];
        pkt.extend_from_slice(&src.octets());
        pkt.extend_from_slice(&dst.octets());
        pkt.extend_from_slice(payload);
        let ck = checksum(&[&pkt[..20]]);
        pkt[10..12].copy_from_slice(&ck.to_be_bytes());
        pkt
    }

    fn udp_packet(src: SocketAddrV4, dst: SocketAddrV4, payload: &[u8]) -> Vec<u8> {
        let len = 8 + payload.len();
        let mut seg = vec![
            (src.port() >> 8) as u8,
            src.port() as u8,
            (dst.port() >> 8) as u8,
            dst.port() as u8,
            (len >> 8) as u8,
            len as u8,
            0,
            0,
        ];
        seg.extend_from_slice(payload);
        let pseudo = pseudo_header(*src.ip(), *dst.ip(), 17, len);
        let ck = checksum(&[&pseudo, &seg]);
        seg[6..8].copy_from_slice(&ck.to_be_bytes());
        ipv4_packet(17, *src.ip(), *dst.ip(), &seg)
    }

    /// `ack` = None means no ACK flag (a bare SYN); Some(seq) sets both seq and
    /// the ACK flag/ack number.
    #[allow(clippy::too_many_arguments)]
    fn tcp_packet(
        src: SocketAddrV4,
        dst: SocketAddrV4,
        seq: u32,
        ack: Option<u32>,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut seg = Vec::with_capacity(20 + payload.len());
        seg.extend_from_slice(&src.port().to_be_bytes());
        seg.extend_from_slice(&dst.port().to_be_bytes());
        seg.extend_from_slice(&seq.to_be_bytes());
        seg.extend_from_slice(&ack.unwrap_or(0).to_be_bytes());
        seg.push(5 << 4); // data offset 5, no options
        let flags = if ack.is_some() { flags | 0x10 } else { flags };
        seg.push(flags);
        seg.extend_from_slice(&65535u16.to_be_bytes());
        seg.extend_from_slice(&[0, 0, 0, 0]); // checksum placeholder, urgent
        seg.extend_from_slice(payload);
        let pseudo = pseudo_header(*src.ip(), *dst.ip(), 6, seg.len());
        let ck = checksum(&[&pseudo, &seg]);
        seg[16..18].copy_from_slice(&ck.to_be_bytes());
        ipv4_packet(6, *src.ip(), *dst.ip(), &seg)
    }

    fn pseudo_header(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, len: usize) -> Vec<u8> {
        let mut p = Vec::with_capacity(12);
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        p.push(0);
        p.push(proto);
        p.extend_from_slice(&(len as u16).to_be_bytes());
        p
    }

    /// IPv6 base header (fixed 40 bytes) + payload; no checksum in the
    /// header itself — transport checksums carry the pseudo-header.
    fn ipv6_packet(next_header: u8, src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
        let mut pkt = Vec::with_capacity(40 + payload.len());
        pkt.extend_from_slice(&[0x60, 0, 0, 0]);
        pkt.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        pkt.push(next_header);
        pkt.push(64); // hop limit
        pkt.extend_from_slice(&src.octets());
        pkt.extend_from_slice(&dst.octets());
        pkt.extend_from_slice(payload);
        pkt
    }

    fn pseudo_header_v6(src: Ipv6Addr, dst: Ipv6Addr, nh: u8, len: usize) -> Vec<u8> {
        let mut p = Vec::with_capacity(40);
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(&(len as u32).to_be_bytes());
        p.extend_from_slice(&[0, 0, 0]);
        p.push(nh);
        p
    }

    fn udp6_packet(src: SocketAddr, dst: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) = (src.ip(), dst.ip()) else {
            panic!("udp6_packet wants v6 addresses");
        };
        let len = 8 + payload.len();
        let mut seg = vec![
            (src.port() >> 8) as u8,
            src.port() as u8,
            (dst.port() >> 8) as u8,
            dst.port() as u8,
            (len >> 8) as u8,
            len as u8,
            0,
            0,
        ];
        seg.extend_from_slice(payload);
        let pseudo = pseudo_header_v6(src_ip, dst_ip, 17, len);
        let ck = checksum(&[&pseudo, &seg]);
        seg[6..8].copy_from_slice(&ck.to_be_bytes());
        ipv6_packet(17, src_ip, dst_ip, &seg)
    }

    /// TCP segment over IPv6; `ack` = None means a bare SYN.
    fn tcp6_packet(
        src: SocketAddr,
        dst: SocketAddr,
        seq: u32,
        ack: Option<u32>,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) = (src.ip(), dst.ip()) else {
            panic!("tcp6_packet wants v6 addresses");
        };
        let mut seg = Vec::with_capacity(20 + payload.len());
        seg.extend_from_slice(&src.port().to_be_bytes());
        seg.extend_from_slice(&dst.port().to_be_bytes());
        seg.extend_from_slice(&seq.to_be_bytes());
        seg.extend_from_slice(&ack.unwrap_or(0).to_be_bytes());
        seg.push(5 << 4);
        let flags = if ack.is_some() { flags | 0x10 } else { flags };
        seg.push(flags);
        seg.extend_from_slice(&65535u16.to_be_bytes());
        seg.extend_from_slice(&[0, 0, 0, 0]);
        seg.extend_from_slice(payload);
        let pseudo = pseudo_header_v6(src_ip, dst_ip, 6, seg.len());
        let ck = checksum(&[&pseudo, &seg]);
        seg[16..18].copy_from_slice(&ck.to_be_bytes());
        ipv6_packet(6, src_ip, dst_ip, &seg)
    }

    /// ICMPv4 echo request (type 8): id, seq, payload bytes.
    fn icmpv4_echo_request(
        src: Ipv4Addr,
        dst: Ipv4Addr,
        id: u16,
        seq: u16,
        data: &[u8],
    ) -> Vec<u8> {
        let mut msg = vec![8, 0, 0, 0];
        msg.extend_from_slice(&id.to_be_bytes());
        msg.extend_from_slice(&seq.to_be_bytes());
        msg.extend_from_slice(data);
        let ck = checksum(&[&msg]);
        msg[2..4].copy_from_slice(&ck.to_be_bytes());
        ipv4_packet(1, src, dst, &msg)
    }

    /// ICMPv6 echo request (type 128): checksum over the v6 pseudo-header.
    fn icmpv6_echo_request(
        src: Ipv6Addr,
        dst: Ipv6Addr,
        id: u16,
        seq: u16,
        data: &[u8],
    ) -> Vec<u8> {
        let mut msg = vec![128, 0, 0, 0];
        msg.extend_from_slice(&id.to_be_bytes());
        msg.extend_from_slice(&seq.to_be_bytes());
        msg.extend_from_slice(data);
        let pseudo = pseudo_header_v6(src, dst, 58, msg.len());
        let ck = checksum(&[&pseudo, &msg]);
        msg[2..4].copy_from_slice(&ck.to_be_bytes());
        ipv6_packet(58, src, dst, &msg)
    }

    // -- IPv6 extension-header builders --------------------------------------
    //
    // Hand-built chains, byte for byte: every length rule the walker
    // implements is pinned by these constructors (and the assertions below).

    /// One 8-octet-unit extension header (hop-by-hop / routing /
    /// destination options / mobility): `[next header, hdr ext len, data..]`
    /// padded so the *total* is `8 * (hdr ext len + 1)` (RFC 8200 §4.3;
    /// mobility RFC 6275 §6.1) — with the 2 fixed bytes, `data` lands on
    /// `6 mod 8` bytes.
    fn ext8(next: u8, data: &[u8]) -> Vec<u8> {
        let mut d = data.to_vec();
        while d.len() < 6 || !(d.len() + 2).is_multiple_of(8) {
            d.push(0);
        }
        let hdrlen = (d.len() + 2) / 8 - 1;
        let mut h = Vec::with_capacity(d.len() + 2);
        h.push(next);
        h.push(hdrlen as u8);
        h.extend_from_slice(&d);
        h
    }

    /// Fragment header (fixed 8 bytes, RFC 8200 §4.5): the 13-bit offset in
    /// 8-octet units occupies the high bits of bytes 2..4; the low bit is M.
    fn frag_hdr(next: u8, offset_units: u16, more: bool) -> Vec<u8> {
        let v = (offset_units << 3) | u16::from(more);
        let mut h = vec![next, 0];
        h.extend_from_slice(&v.to_be_bytes());
        h.extend_from_slice(&[0x2a, 0, 0, 1]); // identification (arbitrary)
        h
    }

    /// Authentication Header (RFC 4302 §2.2): the *total* is
    /// `4 * (hdr ext len + 2)` — 4-octet units, unlike everything else.
    fn ah_hdr(next: u8, data: &[u8]) -> Vec<u8> {
        let mut d = data.to_vec();
        while d.len() < 6 || !(d.len() + 2).is_multiple_of(4) {
            d.push(0);
        }
        let hdrlen = (d.len() + 2) / 4 - 2;
        let mut h = Vec::with_capacity(d.len() + 2);
        h.push(next);
        h.push(hdrlen as u8);
        h.extend_from_slice(&d);
        h
    }

    /// An IPv6 packet whose payload starts with an extension-header chain.
    /// `first_nh` is the *type* of the first extension header (0/43/44/51/
    /// 60/135) — the type itself is not written inside the header, only in
    /// the preceding next-header field, so it cannot be derived from `chain`.
    fn ipv6_chained(
        first_nh: u8,
        chain: &[&[u8]],
        src: Ipv6Addr,
        dst: Ipv6Addr,
        transport: &[u8],
    ) -> Vec<u8> {
        let plen = chain.iter().map(|c| c.len()).sum::<usize>() + transport.len();
        let mut pkt = Vec::with_capacity(40 + plen);
        pkt.extend_from_slice(&[0x60, 0, 0, 0]);
        pkt.extend_from_slice(&(plen as u16).to_be_bytes());
        pkt.push(first_nh);
        pkt.push(64);
        pkt.extend_from_slice(&src.octets());
        pkt.extend_from_slice(&dst.octets());
        for c in chain {
            pkt.extend_from_slice(c);
        }
        pkt.extend_from_slice(transport);
        pkt
    }

    /// UDP over a chain: the checksum's pseudo-header carries the
    /// *upper-layer* length (RFC 8200 §8.1 — extension headers are excluded),
    /// which is why the segment is checksummed before the chain is prepended.
    fn udp6_chained(
        first_nh: u8,
        chain: &[&[u8]],
        src: SocketAddr,
        dst: SocketAddr,
        payload: &[u8],
    ) -> Vec<u8> {
        let (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) = (src.ip(), dst.ip()) else {
            panic!("udp6_chained wants v6 addresses");
        };
        let len = 8 + payload.len();
        let mut seg = vec![
            (src.port() >> 8) as u8,
            src.port() as u8,
            (dst.port() >> 8) as u8,
            dst.port() as u8,
            (len >> 8) as u8,
            len as u8,
            0,
            0,
        ];
        seg.extend_from_slice(payload);
        let pseudo = pseudo_header_v6(src_ip, dst_ip, 17, len);
        let ck = checksum(&[&pseudo, &seg]);
        seg[6..8].copy_from_slice(&ck.to_be_bytes());
        ipv6_chained(first_nh, chain, src_ip, dst_ip, &seg)
    }

    /// TCP over a chain (`ack` = None means a bare SYN).
    #[allow(clippy::too_many_arguments)]
    fn tcp6_chained(
        first_nh: u8,
        chain: &[&[u8]],
        src: SocketAddr,
        dst: SocketAddr,
        seq: u32,
        ack: Option<u32>,
        flags: u8,
        payload: &[u8],
    ) -> Vec<u8> {
        let (IpAddr::V6(src_ip), IpAddr::V6(dst_ip)) = (src.ip(), dst.ip()) else {
            panic!("tcp6_chained wants v6 addresses");
        };
        let mut seg = Vec::with_capacity(20 + payload.len());
        seg.extend_from_slice(&src.port().to_be_bytes());
        seg.extend_from_slice(&dst.port().to_be_bytes());
        seg.extend_from_slice(&seq.to_be_bytes());
        seg.extend_from_slice(&ack.unwrap_or(0).to_be_bytes());
        seg.push(5 << 4);
        let flags = if ack.is_some() { flags | 0x10 } else { flags };
        seg.push(flags);
        seg.extend_from_slice(&65535u16.to_be_bytes());
        seg.extend_from_slice(&[0, 0, 0, 0]);
        seg.extend_from_slice(payload);
        let pseudo = pseudo_header_v6(src_ip, dst_ip, 6, seg.len());
        let ck = checksum(&[&pseudo, &seg]);
        seg[16..18].copy_from_slice(&ck.to_be_bytes());
        ipv6_chained(first_nh, chain, src_ip, dst_ip, &seg)
    }

    /// ICMPv6 echo request over a chain; the pseudo-header length is the
    /// ICMP message length (RFC 8200 §8.1 again).
    fn icmpv6_echo_request_chained(
        first_nh: u8,
        chain: &[&[u8]],
        src: Ipv6Addr,
        dst: Ipv6Addr,
        id: u16,
        seq: u16,
        data: &[u8],
    ) -> Vec<u8> {
        let mut msg = vec![128, 0, 0, 0];
        msg.extend_from_slice(&id.to_be_bytes());
        msg.extend_from_slice(&seq.to_be_bytes());
        msg.extend_from_slice(data);
        let pseudo = pseudo_header_v6(src, dst, 58, msg.len());
        let ck = checksum(&[&pseudo, &msg]);
        msg[2..4].copy_from_slice(&ck.to_be_bytes());
        ipv6_chained(first_nh, chain, src, dst, &msg)
    }

    /// ICMP message bytes from a raw IPv4 packet.
    fn icmpv4_msg(pkt: &[u8]) -> &[u8] {
        let ihl = (pkt[0] & 0x0f) as usize * 4;
        &pkt[ihl..]
    }

    /// TCP fields from a raw IPv4 packet: (src_port, dst_port, seq, ack, flags).
    fn tcp_fields(pkt: &[u8]) -> (u16, u16, u32, u32, u8) {
        let ihl = (pkt[0] & 0x0f) as usize * 4;
        let s = &pkt[ihl..];
        (
            u16::from_be_bytes([s[0], s[1]]),
            u16::from_be_bytes([s[2], s[3]]),
            u32::from_be_bytes([s[4], s[5], s[6], s[7]]),
            u32::from_be_bytes([s[8], s[9], s[10], s[11]]),
            s[13],
        )
    }

    /// TCP fields from a raw IPv6 packet (transport starts at 40).
    fn tcp6_fields(pkt: &[u8]) -> (u16, u16, u32, u32, u8) {
        let s = &pkt[40..];
        (
            u16::from_be_bytes([s[0], s[1]]),
            u16::from_be_bytes([s[2], s[3]]),
            u32::from_be_bytes([s[4], s[5], s[6], s[7]]),
            u32::from_be_bytes([s[8], s[9], s[10], s[11]]),
            s[13],
        )
    }

    /// UDP payload + addresses from a raw IPv4 packet.
    fn udp_fields(pkt: &[u8]) -> (SocketAddr, SocketAddr, Vec<u8>) {
        let ihl = (pkt[0] & 0x0f) as usize * 4;
        let dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);
        let src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
        let s = &pkt[ihl..];
        (
            SocketAddr::new(IpAddr::V4(src), u16::from_be_bytes([s[0], s[1]])),
            SocketAddr::new(IpAddr::V4(dst), u16::from_be_bytes([s[2], s[3]])),
            s[8..].to_vec(),
        )
    }

    /// UDP payload + addresses from a raw IPv6 packet.
    fn udp6_fields(pkt: &[u8]) -> (SocketAddr, SocketAddr, Vec<u8>) {
        let src: [u8; 16] = pkt[8..24].try_into().unwrap();
        let dst: [u8; 16] = pkt[24..40].try_into().unwrap();
        (
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(src)),
                u16::from_be_bytes([pkt[40], pkt[41]]),
            ),
            SocketAddr::new(
                IpAddr::V6(Ipv6Addr::from(dst)),
                u16::from_be_bytes([pkt[42], pkt[43]]),
            ),
            pkt[48..].to_vec(),
        )
    }

    fn dns_query(name: &str, id: u16) -> Vec<u8> {
        let mut q = id.to_be_bytes().to_vec();
        q.extend_from_slice(&[0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A, IN
        q
    }

    // -- test doubles -------------------------------------------------------

    struct TestSink(Mutex<Vec<Vec<u8>>>);

    impl PacketSink for TestSink {
        fn send(&self, pkt: &[u8]) -> io::Result<()> {
            self.0.lock().unwrap().push(pkt.to_vec());
            Ok(())
        }
    }

    /// Relay that records metadata and keeps the streams / UDP datagrams.
    #[derive(Default)]
    struct CaptureRelay {
        tcp: Mutex<Vec<TcpMeta>>,
        streams: Mutex<Vec<crate::stream::BoxProxyStream>>,
        udp: Mutex<Vec<(SocketAddr, NetAddr, Vec<u8>)>>,
    }

    impl CaptureRelay {
        fn take_stream(&self) -> Option<crate::stream::BoxProxyStream> {
            self.streams.lock().unwrap().pop()
        }
    }

    impl crate::inbound::RelayHandler for CaptureRelay {
        fn handle_tcp(self: Arc<Self>, meta: TcpMeta, client: crate::stream::BoxProxyStream) {
            self.tcp.lock().unwrap().push(meta);
            self.streams.lock().unwrap().push(client);
        }

        fn handle_udp(
            self: Arc<Self>,
            source: SocketAddr,
            _inbound: String,
            mut uplink: mpsc::Receiver<(NetAddr, Vec<u8>)>,
            downlink: mpsc::Sender<(NetAddr, Vec<u8>)>,
        ) {
            tokio::spawn(async move {
                while let Some((target, data)) = uplink.recv().await {
                    self.udp
                        .lock()
                        .unwrap()
                        .push((source, target.clone(), data.clone()));
                    // Echo straight back: exercises the downlink path.
                    let _ = downlink.send((target, data)).await;
                }
            });
        }
    }

    fn test_cfg() -> TunConfig {
        TunConfig {
            tag: "tun-test".into(),
            name: "rc-tun-test".into(),
            address: Ipv4Addr::new(10, 7, 0, 1),
            netmask: 30,
            mtu: 1500,
            dns_hijack: Vec::new(),
            inet6_address: None,
        }
    }

    /// `test_cfg` with the v6 half enabled (the stack gets a v6 address and
    /// a default v6 route, like `inet6-address: fd00::1/64`).
    fn test_cfg_v6() -> TunConfig {
        TunConfig {
            inet6_address: Some((Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1), 64)),
            ..test_cfg()
        }
    }

    fn stack(
        cfg: &TunConfig,
        relay: Arc<CaptureRelay>,
        dns: Option<Arc<DnsEngine>>,
    ) -> (Netstack, Arc<TestSink>) {
        let sink = Arc::new(TestSink(Mutex::new(Vec::new())));
        let net = Netstack::new(sink.clone(), cfg, relay, TunHooks { dns }).unwrap();
        (net, sink)
    }

    // -- classification -----------------------------------------------------

    #[test]
    fn classify_tcp_and_udp_headers() {
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 7, 0, 2), 40000);
        let dst = SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443);

        // Bare SYN: recognised, and it is the SYN that triggers a listener.
        let pkt = tcp_packet(src, dst, 1000, None, FLAG_SYN, &[]);
        assert_eq!(
            classify_packet(&pkt),
            Classified::Tcp {
                src: SocketAddr::V4(src),
                dst: SocketAddr::V4(dst),
                syn: true,
                ext: false
            }
        );
        // ACK-only: same tuple, no SYN.
        let pkt = tcp_packet(src, dst, 1001, Some(2000), 0, b"x");
        assert_eq!(
            classify_packet(&pkt),
            Classified::Tcp {
                src: SocketAddr::V4(src),
                dst: SocketAddr::V4(dst),
                syn: false,
                ext: false
            }
        );

        let pkt = udp_packet(src, dst, b"payload");
        match classify_packet(&pkt) {
            Classified::Udp {
                src: s,
                dst: d,
                payload,
                ..
            } => {
                assert_eq!((s, d), (SocketAddr::V4(src), SocketAddr::V4(dst)));
                assert_eq!(payload, b"payload");
            }
            other => panic!("expected udp, got {other:?}"),
        }
    }

    #[test]
    fn classify_ipv6_tcp_udp_and_echo() {
        let src_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let dst_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x443);
        let src = SocketAddr::new(IpAddr::V6(src_ip), 40000);
        let dst = SocketAddr::new(IpAddr::V6(dst_ip), 443);

        let pkt = tcp6_packet(src, dst, 500, None, FLAG_SYN, &[]);
        assert_eq!(
            classify_packet(&pkt),
            Classified::Tcp {
                src,
                dst,
                syn: true,
                ext: false
            }
        );

        let pkt = udp6_packet(src, dst, b"v6-payload");
        match classify_packet(&pkt) {
            Classified::Udp {
                src: s,
                dst: d,
                payload,
                ..
            } => {
                assert_eq!((s, d), (src, dst));
                assert_eq!(payload, b"v6-payload");
            }
            other => panic!("expected udp, got {other:?}"),
        }

        // Echo request: answered locally, never handed to the stack. The
        // destination here is the tunnel's own v6 address.
        let gateway = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let pkt = icmpv6_echo_request(src_ip, gateway, 7, 1, b"probe");
        assert_eq!(
            classify_packet(&pkt),
            Classified::IcmpEchoRequest {
                src: IpAddr::V6(src_ip),
                dst: IpAddr::V6(gateway),
                v6: true
            }
        );
        // An echo *reply* (type 129) is not ours to answer.
        let pkt = icmpv6_echo_request(src_ip, gateway, 7, 1, b"probe");
        let mut reply_shaped = pkt.clone();
        reply_shaped[40] = 129;
        assert_eq!(
            classify_packet(&reply_shaped),
            Classified::Other {
                version: 6,
                proto: 58
            }
        );

        // A non-initial fragment (offset 8 units, M set) carries no
        // upper-layer header: gvisor's walker returns ok=false with the
        // fragment's own next-header value as the maybe-proto.
        let frag = ipv6_packet(44, src_ip, dst_ip, &[6, 0, 0, 8, 0, 0, 0, 0]);
        assert_eq!(
            classify_packet(&frag),
            Classified::Other {
                version: 6,
                proto: 6
            }
        );

        // Truncated v6 TCP: payload length says 20 more bytes, packet ends.
        let mut truncated = ipv6_packet(6, src_ip, dst_ip, &[]);
        truncated[4] = 0;
        truncated[5] = 20;
        assert_eq!(classify_packet(&truncated), Classified::Malformed);
        // And a header shorter than 40 bytes.
        assert_eq!(classify_packet(&[0x6f; 39]), Classified::Malformed);
    }

    #[test]
    fn classify_drops_everything_else() {
        // An ICMPv4 echo *reply* (type 0) is IPv4 but not ours to handle;
        // requests (type 8) classify as IcmpEchoRequest instead.
        let reply = ipv4_packet(
            1,
            Ipv4Addr::new(10, 7, 0, 2),
            Ipv4Addr::new(10, 7, 0, 1),
            &[0, 0, 0, 0],
        );
        assert_eq!(
            classify_packet(&reply),
            Classified::Other {
                version: 4,
                proto: 1
            }
        );

        // IPv6 with an unhandled next-header (96): parsed, not relayed.
        let v6 = [0x60u8; 40];
        assert_eq!(
            classify_packet(&v6),
            Classified::Other {
                version: 6,
                proto: 96
            }
        );
        // IP version 5 is nothing we speak.
        assert_eq!(
            classify_packet(&[0x50; 40]),
            Classified::Unsupported { version: 5 }
        );

        assert_eq!(classify_packet(&[]), Classified::Malformed);
        assert_eq!(classify_packet(&[0x45]), Classified::Malformed);
        // IHL < 5 (0x44) is malformed, not "IPv4 without options".
        assert_eq!(classify_packet(&[0x44; 20]), Classified::Malformed);
        // Truncated TCP: header says 40 bytes, we only have 20.
        let mut truncated = ipv4_packet(6, Ipv4Addr::LOCALHOST, Ipv4Addr::LOCALHOST, &[]);
        truncated[2] = 0;
        truncated[3] = 40;
        assert_eq!(classify_packet(&truncated), Classified::Malformed);
        // UDP whose length field overruns the packet: payload is clamped.
        let mut pkt = udp_packet(
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 1), 1234),
            SocketAddrV4::new(Ipv4Addr::new(10, 0, 0, 2), 53),
            b"abc",
        );
        let ihl = 20;
        pkt[ihl + 4] = 0xff;
        pkt[ihl + 5] = 0xff;
        match classify_packet(&pkt) {
            Classified::Udp { payload, .. } => assert_eq!(payload, b"abc"),
            other => panic!("expected udp, got {other:?}"),
        }
    }

    // -- UDP session identity + DNS hijack decision -------------------------

    #[test]
    fn udp_sessions_are_keyed_by_client_source() {
        let client = SocketAddrV4::new(Ipv4Addr::new(10, 7, 0, 2), 5353);
        let other_port = SocketAddrV4::new(Ipv4Addr::new(10, 7, 0, 2), 5354);
        let other_host = SocketAddrV4::new(Ipv4Addr::new(10, 7, 0, 3), 5353);
        let v6_same_port =
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)), 5353);

        let key = UdpSessionKey::for_packet(SocketAddr::V4(client));
        assert_eq!(key, UdpSessionKey(SocketAddr::V4(client)));
        // Same client, two destinations: one association (the destination is
        // carried per datagram on the uplink, not in the key).
        assert_eq!(key, UdpSessionKey::for_packet(SocketAddr::V4(client)));
        assert_ne!(key, UdpSessionKey::for_packet(SocketAddr::V4(other_port)));
        assert_ne!(key, UdpSessionKey::for_packet(SocketAddr::V4(other_host)));
        // A v6 client is a different client even on the same port.
        assert_ne!(key, UdpSessionKey::for_packet(v6_same_port));
        assert_eq!(
            UdpSessionKey::for_packet(v6_same_port),
            UdpSessionKey(SocketAddr::new(
                IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
                5353
            ))
        );
    }

    #[test]
    fn dns_hijack_matches_address_and_port() {
        use crate::inbound::tun::DnsHijack;
        let ip_a = IpAddr::V4(Ipv4Addr::new(10, 7, 0, 1));
        let hijack_v4 = vec![
            DnsHijack { ip: Some(ip_a), port: 53 },
            DnsHijack { ip: Some(IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))), port: 53 },
        ];
        // The configured destination matches on BOTH address and port...
        assert!(is_dns_hijack(SocketAddr::new(ip_a, 53), &hijack_v4));
        // ...and a non-DNS port on the same address is NOT captured —
        // the mihomo #1689 over-hijack this engine used to have.
        assert!(!is_dns_hijack(SocketAddr::new(ip_a, 5353), &hijack_v4));
        assert!(!is_dns_hijack(SocketAddr::new(ip_a, 1), &hijack_v4));
        // Different address, same port: no match.
        assert!(!is_dns_hijack(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 7, 0, 2)), 53),
            &hijack_v4
        ));

        // `any:53`: every address, port 53 only.
        let any53 = vec![DnsHijack { ip: None, port: 53 }];
        assert!(is_dns_hijack(SocketAddr::new(ip_a, 53), &any53));
        assert!(!is_dns_hijack(SocketAddr::new(ip_a, 5353), &any53));
        assert!(is_dns_hijack(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)), 53),
            &any53
        ));

        // v6 works symmetrically, and families never cross-match.
        let fd00_1 = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        let hijack_v6 = vec![DnsHijack { ip: Some(fd00_1), port: 53 }];
        assert!(is_dns_hijack(SocketAddr::new(fd00_1, 53), &hijack_v6));
        assert!(!is_dns_hijack(SocketAddr::new(fd00_1, 5353), &hijack_v6));
        assert!(!is_dns_hijack(
            SocketAddr::new(IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)), 53),
            &hijack_v6
        ));
        assert!(!is_dns_hijack(SocketAddr::new(fd00_1, 53), &hijack_v4));
        assert!(!is_dns_hijack(SocketAddr::new(ip_a, 53), &hijack_v6));
        assert!(!is_dns_hijack(SocketAddr::new(ip_a, 53), &[]));
    }

    #[test]
    fn listener_policy_for_arriving_syns() {
        let src = SocketAddrV4::new(Ipv4Addr::new(10, 7, 0, 2), 40000);
        let dst = SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443);
        let src = SocketAddr::V4(src);
        let dst = SocketAddr::V4(dst);
        let listening = SocketFacts {
            port: 443,
            listening: true,
            local: None,
            remote: None,
        };
        // A free listener on the port covers the SYN — for a v6 client too,
        // since listeners match by port across families.
        assert!(!needs_new_listener(&[listening], src, dst));
        let v6_src = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
            40000,
        );
        assert!(!needs_new_listener(&[listening], v6_src, dst));
        // A socket that already owns this 4-tuple covers it too (this is the
        // SYN-retransmit case: no second listener, no port churn).
        let owning = SocketFacts {
            port: 443,
            listening: false,
            local: Some((dst.ip(), dst.port())),
            remote: Some((src.ip(), src.port())),
        };
        assert!(!needs_new_listener(&[owning], src, dst));
        // A connection from a *different* client does not cover a new SYN.
        let other_client = SocketFacts {
            remote: Some((IpAddr::V4(Ipv4Addr::new(10, 7, 0, 3)), 40001)),
            ..owning
        };
        assert!(needs_new_listener(&[other_client], src, dst));
        // Nor does a listener on a different port.
        assert!(needs_new_listener(
            &[SocketFacts {
                port: 8443,
                ..listening
            }],
            src,
            dst
        ));
        assert!(needs_new_listener(&[], src, dst));
    }

    // -- the TCP bridge itself ---------------------------------------------

    struct FlagWaker(AtomicBool);

    impl std::task::Wake for FlagWaker {
        fn wake(self: Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
        fn wake_by_ref(self: &Arc<Self>) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn waker() -> (Waker, Arc<FlagWaker>) {
        let flag = Arc::new(FlagWaker(AtomicBool::new(false)));
        (Waker::from(flag.clone()), flag)
    }

    #[test]
    fn tun_stream_reads_queued_bytes_then_eof() {
        let shared = Arc::new(StreamShared::new(Arc::new(Notify::new())));
        let mut stream = TunStream {
            shared: shared.clone(),
        };
        let (w, flag) = waker();
        let mut cx = Context::from_waker(&w);

        // Empty and open: parks the reader with its waker.
        let mut buf = [0u8; 8];
        {
            let mut rb = ReadBuf::new(&mut buf);
            assert!(std::pin::Pin::new(&mut stream)
                .poll_read(&mut cx, &mut rb)
                .is_pending());
        }
        assert!(shared.lock().read_waker.is_some());

        // The netstack pushed bytes: the parked reader is woken and reads.
        shared.lock().to_proxy.extend(b"hello".iter().copied());
        shared.lock().read_waker.take().unwrap().wake();
        assert!(flag.0.load(Ordering::SeqCst));
        let mut rb = ReadBuf::new(&mut buf);
        assert!(std::pin::Pin::new(&mut stream)
            .poll_read(&mut cx, &mut rb)
            .is_ready());
        assert_eq!(rb.filled(), b"hello");

        // EOF is a successful read that fills nothing.
        shared.lock().read_eof = true;
        let mut rb = ReadBuf::new(&mut buf);
        assert!(std::pin::Pin::new(&mut stream)
            .poll_read(&mut cx, &mut rb)
            .is_ready());
        assert!(rb.filled().is_empty());
    }

    #[test]
    fn tun_stream_write_backpressure_and_half_close() {
        let wake = Arc::new(Notify::new());
        let shared = Arc::new(StreamShared::new(wake.clone()));
        let mut stream = TunStream {
            shared: shared.clone(),
        };
        let (w, _flag) = waker();
        let mut cx = Context::from_waker(&w);

        let chunk = vec![0xabu8; 1024];
        loop {
            match std::pin::Pin::new(&mut stream).poll_write(&mut cx, &chunk) {
                Poll::Ready(Ok(_)) => {}
                Poll::Pending => break,
                Poll::Ready(Err(e)) => panic!("unexpected write error: {e}"),
            }
        }
        // Queue full: the writer parked instead of growing memory.
        assert_eq!(shared.lock().to_stack.len(), STREAM_QUEUE_MAX);
        assert!(shared.lock().write_waker.is_some());

        // Draining space wakes the writer.
        shared.lock().to_stack.clear();
        shared.lock().write_waker.take().unwrap().wake();
        assert!(std::pin::Pin::new(&mut stream)
            .poll_write(&mut cx, b"after")
            .is_ready());

        // Shutdown queues the FIN and refuses later writes.
        assert!(std::pin::Pin::new(&mut stream)
            .poll_shutdown(&mut cx)
            .is_ready());
        assert!(shared.lock().write_closed);
        match std::pin::Pin::new(&mut stream).poll_write(&mut cx, b"x") {
            Poll::Ready(Err(e)) => assert_eq!(e.kind(), io::ErrorKind::BrokenPipe),
            other => panic!("expected BrokenPipe, got {other:?}"),
        }
    }

    // -- full netstack, hermetic: no TUN, no privileges ---------------------

    #[tokio::test]
    async fn tcp_handshake_is_relayed_and_bridged() {
        let cfg = test_cfg();
        let relay = Arc::new(CaptureRelay::default());
        let (mut net, sink) = stack(&cfg, relay.clone(), None);

        let client = SocketAddrV4::new(Ipv4Addr::new(10, 7, 0, 2), 40000);
        let server = SocketAddrV4::new(Ipv4Addr::new(93, 184, 216, 34), 443);

        // 1. SYN -> a listener is created behind the scenes, SYN-ACK goes out.
        net.stage(&tcp_packet(client, server, 1000, None, FLAG_SYN, &[]));
        net.step();
        let synack = sink
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|p| tcp_fields(p).4 & 0x12 == 0x12)
            .cloned()
            .expect("stack must answer the SYN with a SYN-ACK");
        let (stack_port, peer_port, stack_seq, ack_no, _) = tcp_fields(&synack);
        assert_eq!(stack_port, 443, "SYN-ACK must come from the dialled port");
        assert_eq!(peer_port, 40000);
        assert_eq!(ack_no, 1001, "SYN-ACK must acknowledge our SYN");

        // 2. Final ACK -> the connection is handed to the relay.
        net.stage(&tcp_packet(
            client,
            server,
            ack_no,
            Some(stack_seq + 1),
            0,
            &[],
        ));
        net.step();
        {
            let metas = relay.tcp.lock().unwrap();
            assert_eq!(metas.len(), 1, "one relayed connection");
            let m = &metas[0];
            assert_eq!(m.inbound, "tun-test");
            assert_eq!(m.inbound_kind, "tun");
            assert_eq!(m.inbound_port, None);
            assert_eq!(m.target.to_string(), "93.184.216.34:443");
            assert_eq!(m.source, SocketAddr::V4(client));
        }
        let mut stream = relay.take_stream().expect("stream handed to the relay");

        // 3. Proxy -> stack: bytes appear in a TCP segment for the client.
        use tokio::io::AsyncWriteExt;
        stream.write_all(b"GET / HTTP/1.1\r\n").await.unwrap();
        net.step();
        let egress: Vec<Vec<u8>> = sink.0.lock().unwrap().clone();
        let carried = egress.iter().any(|p| {
            let (sp, dp, _s, _a, _f) = tcp_fields(p);
            let ihl = (p[0] & 0x0f) as usize * 4;
            sp == 443
                && dp == 40000
                && p[ihl + 20..].starts_with(b"GET / HTTP/1.1\r\n")
                && p[ihl + 20..].len() >= 16
        });
        assert!(carried, "written bytes must reach the wire");

        // 4. Stack -> proxy: a data segment from the client is readable.
        net.stage(&tcp_packet(
            client,
            server,
            ack_no,
            Some(stack_seq + 1),
            0x18,
            b"pong",
        ));
        net.step();
        use tokio::io::AsyncReadExt;
        let mut buf = [0u8; 4];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pong");

        // 5. Dropping the stream tears the connection down (the stack sees a
        //    FIN/RST and stops holding a socket for it).
        stream.shutdown().await.unwrap();
        net.step();
        assert_eq!(net.conns.len(), 1);
        drop(stream);
        net.step();
        assert!(
            net.conns.is_empty(),
            "aborted stream must release the socket"
        );
    }

    #[tokio::test]
    async fn udp_datagram_is_relayed_and_reply_injected() {
        let cfg = test_cfg();
        let relay = Arc::new(CaptureRelay::default());
        let (mut net, sink) = stack(&cfg, relay.clone(), None);

        let client = SocketAddrV4::new(Ipv4Addr::new(10, 7, 0, 2), 40000);
        let server = SocketAddrV4::new(Ipv4Addr::new(8, 8, 8, 8), 53);
        net.stage(&udp_packet(client, server, b"query"));
        net.step();

        // The relay got one association for this client, with the datagram.
        // (handle_udp spawns its pump, so let it run.)
        for _ in 0..100 {
            if !relay.udp.lock().unwrap().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        {
            let up = relay.udp.lock().unwrap();
            assert_eq!(up.len(), 1);
            assert_eq!(up[0].0, SocketAddr::V4(client));
            assert_eq!(up[0].1.to_string(), "8.8.8.8:53");
            assert_eq!(up[0].2, b"query");
        }

        // The echo reply comes back out with the *server* as the source.
        for _ in 0..100 {
            let has_reply = sink
                .0
                .lock()
                .unwrap()
                .iter()
                .any(|p| p[9] == 17 && p[16..20] == [10, 7, 0, 2]);
            if has_reply {
                break;
            }
            net.step();
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let reply = sink
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|p| p[9] == 17 && p[16..20] == [10, 7, 0, 2])
            .cloned()
            .expect("relay reply must be injected back into the tunnel");
        let (src, dst, payload) = udp_fields(&reply);
        assert_eq!(
            src,
            SocketAddr::V4(server),
            "reply source must be the dialled destination"
        );
        assert_eq!(dst, SocketAddr::V4(client));
        assert_eq!(payload, b"query");
    }

    #[tokio::test]
    async fn dns_hijack_is_answered_by_the_engine_resolver() {
        let mut cfg = test_cfg();
        cfg.dns_hijack = vec![IpAddr::V4(Ipv4Addr::new(10, 7, 0, 1)).into()];
        // A resolver with a static hosts entry: answering needs no upstream,
        // so this stays hermetic.
        let mut dns_cfg = crate::config::DnsConfig::default();
        dns_cfg.hosts.insert(
            "probe.test".to_string(),
            vec![Ipv4Addr::new(203, 0, 113, 5).into()],
        );
        let dns = DnsEngine::new(dns_cfg, crate::rule::DomainMatcher::default()).unwrap();

        let relay = Arc::new(CaptureRelay::default());
        let (mut net, sink) = stack(&cfg, relay.clone(), Some(dns));

        let client = SocketAddrV4::new(Ipv4Addr::new(10, 7, 0, 2), 40000);
        let hijack = SocketAddrV4::new(Ipv4Addr::new(10, 7, 0, 1), 53);
        net.stage(&udp_packet(client, hijack, &dns_query("probe.test", 7)));
        net.step();

        let mut answer_pkt = None;
        for _ in 0..200 {
            net.step();
            answer_pkt = sink
                .0
                .lock()
                .unwrap()
                .iter()
                .find(|p| p[9] == 17 && p[16..20] == [10, 7, 0, 2])
                .cloned();
            if answer_pkt.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let answer = answer_pkt.expect("hijacked query must be answered");
        let (src, dst, payload) = udp_fields(&answer);
        assert_eq!(
            src,
            SocketAddr::V4(hijack),
            "answer must come from the hijacked address"
        );
        assert_eq!(dst, SocketAddr::V4(client));
        assert_eq!(&payload[..2], &7u16.to_be_bytes(), "transaction id");
        assert!(payload.ends_with(&[203, 0, 113, 5]), "A record answer");
        // Nothing was relayed: a hijacked query never reaches an outbound.
        assert!(relay.udp.lock().unwrap().is_empty());
        assert!(relay.tcp.lock().unwrap().is_empty());
    }

    // -- ICMP echo: byte-level responder ------------------------------------

    /// A correct checksum sums (with itself included) to 0: `checksum(...)`
    /// over the full header/message must therefore return 0.
    #[test]
    fn icmpv4_echo_reply_bytes_and_checksums() {
        let client = Ipv4Addr::new(10, 7, 0, 2);
        let gateway = Ipv4Addr::new(10, 7, 0, 1);
        let req = icmpv4_echo_request(client, gateway, 0x1234, 5, b"rustcrash-probe");

        let reply = icmpv4_echo_reply(&req).expect("echo request must be answered");
        // Type 0 / code 0, addresses swapped, id/seq/data carried verbatim,
        // fresh TTL, and the request's header length / total length are kept.
        assert_eq!(reply[0], req[0], "header bytes kept");
        assert_eq!(&reply[2..4], &req[2..4], "total length unchanged");
        assert_eq!(reply[9], 1, "still ICMP");
        assert_eq!(reply[8], 64, "fresh hop limit");
        assert_eq!(
            &reply[12..16],
            &gateway.octets()[..],
            "src = pinged address"
        );
        assert_eq!(&reply[16..20], &client.octets()[..], "dst = pinger");
        let icmp = icmpv4_msg(&reply);
        assert_eq!(icmp[0], 0, "echo reply type");
        assert_eq!(icmp[1], 0, "code");
        assert_eq!(&icmp[4..6], 0x1234u16.to_be_bytes().as_slice(), "id kept");
        assert_eq!(&icmp[6..8], 5u16.to_be_bytes().as_slice(), "seq kept");
        assert_eq!(&icmp[8..], b"rustcrash-probe");
        // Checksums verify: header checksum and ICMP checksum both sum to 0.
        assert_eq!(checksum(&[&reply[..20]]), 0, "IPv4 header checksum");
        assert_eq!(checksum(&[icmp]), 0, "ICMP checksum");

        // Non-echo input and truncation are refused, not mis-answered.
        assert_eq!(icmpv4_echo_reply(&reply), None, "a reply is not a request");
        assert_eq!(icmpv4_echo_reply(&req[..24]), None, "truncated request");
    }

    #[test]
    fn icmpv6_echo_reply_bytes_and_checksums() {
        let client = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let remote = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 9);
        let req = icmpv6_echo_request(client, remote, 0xbeef, 42, b"v6-probe");

        let reply = icmpv6_echo_reply(&req).expect("echo request must be answered");
        assert_eq!(reply[6], 58, "next header unchanged");
        assert_eq!(reply[7], 64, "fresh hop limit");
        assert_eq!(&reply[8..24], &remote.octets()[..], "src = pinged address");
        assert_eq!(&reply[24..40], &client.octets()[..], "dst = pinger");
        let icmp = &reply[40..];
        assert_eq!(icmp[0], 129, "ICMPv6 echo reply type");
        assert_eq!(icmp[1], 0, "code");
        assert_eq!(&icmp[4..6], 0xbeefu16.to_be_bytes().as_slice(), "id kept");
        assert_eq!(&icmp[6..8], 42u16.to_be_bytes().as_slice(), "seq kept");
        assert_eq!(&icmp[8..], b"v6-probe");
        // The ICMPv6 checksum covers the reply's own (swapped) addresses via
        // the pseudo-header; verifying it there proves the swap was included.
        let pseudo = pseudo_header_v6(remote, client, 58, icmp.len());
        assert_eq!(checksum(&[&pseudo, icmp]), 0, "pseudo-header checksum");

        assert_eq!(icmpv6_echo_reply(&reply), None, "a reply is not a request");
        assert_eq!(icmpv6_echo_reply(&req[..44]), None, "truncated request");
    }

    /// The stack answers pings on the device without any socket or relay
    /// involvement; other ICMP types stay dropped.
    #[tokio::test]
    async fn icmp_echo_is_answered_on_both_families() {
        let cfg = test_cfg_v6();
        let relay = Arc::new(CaptureRelay::default());
        let (mut net, sink) = stack(&cfg, relay.clone(), None);

        let v4_req = icmpv4_echo_request(
            Ipv4Addr::new(10, 7, 0, 2),
            Ipv4Addr::new(10, 7, 0, 1),
            1,
            1,
            b"ping4",
        );
        net.stage(&v4_req);
        let v6_req = icmpv6_echo_request(
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2),
            Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
            2,
            2,
            b"ping6",
        );
        net.stage(&v6_req);
        // Non-echo ICMP stays dropped: a dest-unreachable (type 3) and a v6
        // echo *reply* produce nothing.
        net.stage(&ipv4_packet(
            1,
            Ipv4Addr::new(10, 7, 0, 2),
            Ipv4Addr::new(10, 7, 0, 1),
            &[3, 1, 0, 0, 0, 0, 0, 0],
        ));
        let mut v6_reply_shaped = v6_req.clone();
        v6_reply_shaped[40] = 129;
        net.stage(&v6_reply_shaped);
        net.step();

        let out = sink.0.lock().unwrap().clone();
        assert_eq!(out.len(), 2, "exactly the two echo replies, nothing else");
        assert_eq!(icmpv4_msg(&out[0])[0], 0, "v4 reply first");
        assert_eq!(icmpv4_msg(&out[0])[4..6], 1u16.to_be_bytes());
        assert_eq!(out[1][40], 129, "v6 reply second");
        assert!(
            icmpv4_echo_reply(&out[0]).is_none(),
            "our own reply is not a request"
        );
        assert!(relay.tcp.lock().unwrap().is_empty());
        assert!(relay.udp.lock().unwrap().is_empty());
        assert!(net.conns.is_empty());
    }

    // -- IPv6 data plane -----------------------------------------------------

    #[tokio::test]
    async fn ipv6_udp_is_relayed_and_reply_injected() {
        let cfg = test_cfg_v6();
        let relay = Arc::new(CaptureRelay::default());
        let (mut net, sink) = stack(&cfg, relay.clone(), None);

        let client_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let client = SocketAddr::new(IpAddr::V6(client_ip), 40000);
        let server = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
            53,
        );
        net.stage(&udp6_packet(client, server, b"v6-query"));
        net.step();

        for _ in 0..100 {
            if !relay.udp.lock().unwrap().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        {
            let up = relay.udp.lock().unwrap();
            assert_eq!(up.len(), 1);
            assert_eq!(up[0].0, client, "v6 session keyed by the v6 source");
            assert_eq!(up[0].1.to_string(), "[2001:4860:4860::8888]:53");
            assert_eq!(up[0].2, b"v6-query");
        }

        // The echo reply comes back out as an IPv6 packet sourced from the
        // dialled server.
        let is_reply = |p: &[u8]| p[0] >> 4 == 6 && p[6] == 17 && p[24..40] == client_ip.octets();
        for _ in 0..100 {
            if sink.0.lock().unwrap().iter().any(|p| is_reply(p)) {
                break;
            }
            net.step();
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let reply = sink
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|p| is_reply(p))
            .cloned()
            .expect("relay reply must be injected back into the tunnel");
        let (src, dst, payload) = udp6_fields(&reply);
        assert_eq!(src, server, "reply source must be the dialled destination");
        assert_eq!(dst, client);
        assert_eq!(payload, b"v6-query");
    }

    #[tokio::test]
    async fn ipv6_tcp_handshake_is_relayed() {
        let cfg = test_cfg_v6();
        let relay = Arc::new(CaptureRelay::default());
        let (mut net, sink) = stack(&cfg, relay.clone(), None);

        let client = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
            40000,
        );
        let server = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111)),
            443,
        );

        net.stage(&tcp6_packet(client, server, 700, None, FLAG_SYN, &[]));
        net.step();
        let synack = sink
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|p| p[0] >> 4 == 6 && p[6] == 6 && tcp6_fields(p).4 & 0x12 == 0x12)
            .cloned()
            .expect("stack must answer the v6 SYN with a SYN-ACK");
        let (stack_port, peer_port, stack_seq, ack_no, _) = tcp6_fields(&synack);
        assert_eq!(stack_port, 443);
        assert_eq!(peer_port, 40000);
        assert_eq!(ack_no, 701, "SYN-ACK must acknowledge our SYN");

        net.stage(&tcp6_packet(
            client,
            server,
            ack_no,
            Some(stack_seq + 1),
            0,
            &[],
        ));
        net.step();
        {
            let metas = relay.tcp.lock().unwrap();
            assert_eq!(metas.len(), 1, "one relayed v6 connection");
            assert_eq!(metas[0].target.to_string(), "[2606:4700::1111]:443");
            assert_eq!(metas[0].source, client);
            assert_eq!(metas[0].inbound_kind, "tun");
        }
    }

    #[tokio::test]
    async fn ipv6_dns_hijack_is_answered_by_the_engine_resolver() {
        let mut cfg = test_cfg_v6();
        let gateway_v6 = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        cfg.dns_hijack = vec![gateway_v6.into()];
        let mut dns_cfg = crate::config::DnsConfig::default();
        let answer_v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 5);
        dns_cfg
            .hosts
            .insert("probe6.test".to_string(), vec![answer_v6.into()]);
        let dns = DnsEngine::new(dns_cfg, crate::rule::DomainMatcher::default()).unwrap();

        let relay = Arc::new(CaptureRelay::default());
        let (mut net, sink) = stack(&cfg, relay.clone(), Some(dns));

        let client_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let client = SocketAddr::new(IpAddr::V6(client_ip), 40000);
        let hijack = SocketAddr::new(gateway_v6, 53);
        // AAAA query (type 28) so the hosts entry's v6 address answers it.
        let mut q = dns_query("probe6.test", 11);
        let q_len = q.len();
        q[q_len - 4] = 0x00;
        q[q_len - 3] = 0x1c;
        net.stage(&udp6_packet(client, hijack, &q));
        net.step();

        let is_answer = |p: &[u8]| p[0] >> 4 == 6 && p[6] == 17 && p[24..40] == client_ip.octets();
        let mut answer_pkt = None;
        for _ in 0..200 {
            net.step();
            answer_pkt = sink
                .0
                .lock()
                .unwrap()
                .iter()
                .find(|p| is_answer(p))
                .cloned();
            if answer_pkt.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let answer = answer_pkt.expect("hijacked v6 query must be answered");
        let (src, dst, payload) = udp6_fields(&answer);
        assert_eq!(src, hijack, "answer must come from the hijacked v6 address");
        assert_eq!(dst, client);
        assert_eq!(&payload[..2], &11u16.to_be_bytes(), "transaction id");
        assert!(payload.ends_with(&answer_v6.octets()), "AAAA record answer");
        assert!(relay.udp.lock().unwrap().is_empty(), "nothing relayed");
        assert!(relay.tcp.lock().unwrap().is_empty());
    }

    // -- IPv6 extension-header classification ----------------------------------

    /// The chains the classifier must see through, per gvisor's
    /// `TryParseTransportProtocol` (header/ipv6.go:234) — the walker this
    /// port follows.
    #[test]
    fn classify_ipv6_ext_header_chains_to_the_transport() {
        let src_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let dst_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x443);
        let client = SocketAddr::new(IpAddr::V6(src_ip), 40000);
        let dns = SocketAddr::new(IpAddr::V6(dst_ip), 53);
        let https = SocketAddr::new(IpAddr::V6(dst_ip), 443);

        // hop-by-hop -> UDP: as classify-able as a bare UDP datagram.
        let hbh = ext8(17, &[0x05, 0x02, 0, 0, 0, 0]); // a PadN option, content irrelevant
        let pkt = udp6_chained(0, &[&hbh], client, dns, b"q");
        assert_eq!(
            classify_packet(&pkt),
            Classified::Udp {
                src: client,
                dst: dns,
                payload: b"q",
                ext: true
            }
        );

        // hop-by-hop + routing -> UDP (the headline chain).
        let hbh_r = ext8(43, &[0x05, 0x02, 0, 0, 0, 0]);
        let routing = ext8(17, &[0u8; 8]); // type 0, segments-left 0
        let pkt = udp6_chained(0, &[&hbh_r, &routing], client, dns, b"chain");
        assert_eq!(
            classify_packet(&pkt),
            Classified::Udp {
                src: client,
                dst: dns,
                payload: b"chain",
                ext: true
            }
        );

        // destination options -> TCP SYN.
        let dst_opts = ext8(6, &[]);
        let pkt = tcp6_chained(60, &[&dst_opts], client, https, 1000, None, FLAG_SYN, &[]);
        assert_eq!(
            classify_packet(&pkt),
            Classified::Tcp {
                src: client,
                dst: https,
                syn: true,
                ext: true
            }
        );

        // A fragment at offset 0 (atomic, RFC 6946) carries the transport.
        let frag0 = frag_hdr(17, 0, false);
        let pkt = udp6_chained(44, &[&frag0], client, dns, b"atomic");
        assert_eq!(
            classify_packet(&pkt),
            Classified::Udp {
                src: client,
                dst: dns,
                payload: b"atomic",
                ext: true
            }
        );

        // AH (4-octet units, RFC 4302) and mobility (RFC 6275) are walked
        // with their own length rules.
        let ah = ah_hdr(6, &[0u8; 8]);
        let pkt = tcp6_chained(51, &[&ah], client, https, 7, None, FLAG_SYN, &[]);
        assert_eq!(
            classify_packet(&pkt),
            Classified::Tcp {
                src: client,
                dst: https,
                syn: true,
                ext: true
            }
        );
        let mob = ext8(17, &[0u8; 8]);
        let pkt = udp6_chained(135, &[&mob], client, dns, b"mipv6");
        assert_eq!(
            classify_packet(&pkt),
            Classified::Udp {
                src: client,
                dst: dns,
                payload: b"mipv6",
                ext: true
            }
        );
    }

    /// Chains that end without a transport, and chains that are broken.
    #[test]
    fn classify_ipv6_ext_header_terminators_and_bounds() {
        let src_ip = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let dst_ip = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x443);

        // ESP (50): opaque, ends the walk.
        let pkt = ipv6_packet(50, src_ip, dst_ip, &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(
            classify_packet(&pkt),
            Classified::Other {
                version: 6,
                proto: 50
            }
        );
        // No next header (59): nothing follows.
        let pkt = ipv6_packet(59, src_ip, dst_ip, &[0u8; 4]);
        assert_eq!(
            classify_packet(&pkt),
            Classified::Other {
                version: 6,
                proto: 59
            }
        );
        // Unrecognized (139 = Host Identity Protocol): same shape.
        let pkt = ipv6_packet(139, src_ip, dst_ip, &[0u8; 4]);
        assert_eq!(
            classify_packet(&pkt),
            Classified::Other {
                version: 6,
                proto: 139
            }
        );

        // Hop-by-hop must be first (RFC 8200 §4.1): routing -> hbh is a
        // malformed chain per gvisor; it reports the hbh value.
        let hbh = ext8(17, &[0x05, 0x02, 0, 0, 0, 0]);
        let routing = ext8(0, &[0u8; 8]);
        let client = SocketAddr::new(IpAddr::V6(src_ip), 40000);
        let dns = SocketAddr::new(IpAddr::V6(dst_ip), 53);
        let pkt = udp6_chained(43, &[&routing, &hbh], client, dns, b"late-hbh");
        assert_eq!(
            classify_packet(&pkt),
            Classified::Other {
                version: 6,
                proto: 0
            }
        );

        // A header claiming more bytes than the packet carries is malformed.
        let mut pkt = udp6_chained(0, &[&ext8(17, &[0u8; 8])], client, dns, b"cut");
        pkt.truncate(pkt.len() - 12);
        assert_eq!(classify_packet(&pkt), Classified::Malformed);

        // A chain that consumes the whole payload while promising a
        // transport: the transport is absent, so the packet is malformed
        // (the pre-ext-header label for a truncated TCP/UDP).
        let pkt = ipv6_chained(0, &[&ext8(17, &[0u8; 8])], src_ip, dst_ip, &[]);
        assert_eq!(classify_packet(&pkt), Classified::Malformed);
    }

    /// The echo responder answers a request that arrived through a chain,
    /// carrying the chain verbatim and checksumming only the ICMP message
    /// (RFC 8200 §8.1: the pseudo-header excludes extension headers).
    #[test]
    fn icmpv6_echo_reply_behind_ext_headers_keeps_chain_and_checksum() {
        let client = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let gateway = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let hbh = ext8(58, &[0x05, 0x02, 0, 0, 0, 0]);
        let req = icmpv6_echo_request_chained(0, &[&hbh], client, gateway, 0xcafe, 3, b"ext-ping");
        assert_eq!(
            classify_packet(&req),
            Classified::IcmpEchoRequest {
                src: IpAddr::V6(client),
                dst: IpAddr::V6(gateway),
                v6: true
            }
        );

        let reply = icmpv6_echo_reply(&req).expect("chained echo request is answered");
        assert_eq!(reply[6], 0, "the chain is still the first next header");
        assert_eq!(reply[40], 58, "the chain's last header names ICMPv6");
        assert_eq!(&reply[40..48], &hbh[..], "chain bytes carried verbatim");
        assert_eq!(&reply[8..24], &gateway.octets()[..], "src = pinged address");
        assert_eq!(&reply[24..40], &client.octets()[..], "dst = pinger");
        let icmp = &reply[48..];
        assert_eq!(icmp[0], 129, "echo reply type");
        assert_eq!(&icmp[4..6], &0xcafeu16.to_be_bytes(), "id kept");
        assert_eq!(&icmp[6..8], &3u16.to_be_bytes(), "seq kept");
        assert_eq!(&icmp[8..], b"ext-ping");
        // The pseudo-header checksum verifies over the upper-layer length
        // (the ICMP message, not chain+message).
        let pseudo = pseudo_header_v6(gateway, client, 58, icmp.len());
        assert_eq!(checksum(&[&pseudo, icmp]), 0, "pseudo-header checksum");
    }

    /// The whole classification stage() policy for chained packets: handled
    /// locally, never handed to smoltcp (which cannot follow a chain and
    /// would answer with an ICMPv6 Parameter Problem instead).
    #[tokio::test]
    async fn ipv6_dns_hijack_survives_extension_headers() {
        let mut cfg = test_cfg_v6();
        let gateway = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        cfg.dns_hijack = vec![gateway.into()];
        let mut dns_cfg = crate::config::DnsConfig::default();
        let answer_v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x55);
        dns_cfg
            .hosts
            .insert("probe-xh.test".to_string(), vec![answer_v6.into()]);
        let dns = DnsEngine::new(dns_cfg, crate::rule::DomainMatcher::default()).unwrap();

        let relay = Arc::new(CaptureRelay::default());
        let (mut net, sink) = stack(&cfg, relay.clone(), Some(dns));

        let client = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
            40000,
        );
        let hijack = SocketAddr::new(gateway, 53);
        let hbh = ext8(43, &[0x05, 0x02, 0, 0, 0, 0]); // -> routing follows
        let routing = ext8(17, &[0u8; 8]); // -> UDP follows
        // AAAA query so the hosts entry's v6 address answers it.
        let mut q = dns_query("probe-xh.test", 0x0a0b);
        let q_len = q.len();
        q[q_len - 4] = 0x00;
        q[q_len - 3] = 0x1c;
        net.stage(&udp6_chained(0, &[&hbh, &routing], client, hijack, &q));
        net.step();

        let client_ip = match client.ip() {
            IpAddr::V6(ip) => ip,
            _ => unreachable!(),
        };
        let is_answer =
            |p: &[u8]| p[0] >> 4 == 6 && p[6] == 17 && p[24..40] == client_ip.octets();
        let mut answer_pkt = None;
        for _ in 0..200 {
            net.step();
            answer_pkt = sink.0.lock().unwrap().iter().find(|p| is_answer(p)).cloned();
            if answer_pkt.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        let answer = answer_pkt.expect("hijacked chained query must be answered");
        let (src, dst, payload) = udp6_fields(&answer);
        assert_eq!(src, hijack, "answer must come from the hijacked v6 address");
        assert_eq!(dst, client);
        assert_eq!(&payload[..2], &0x0a0bu16.to_be_bytes(), "transaction id");
        assert!(payload.ends_with(&answer_v6.octets()), "AAAA record answer");
        // Nothing relayed, and nothing entered smoltcp.
        assert!(relay.udp.lock().unwrap().is_empty(), "nothing relayed");
        assert!(relay.tcp.lock().unwrap().is_empty());
        assert!(
            net.shim.ingress.is_empty(),
            "chained packets must not be handed to smoltcp"
        );
    }

    /// A chained UDP datagram to a non-hijacked destination is relayed like
    /// a bare one; only the staging copy into smoltcp is skipped.
    #[tokio::test]
    async fn ipv6_udp_behind_ext_headers_is_relayed_not_staged() {
        let cfg = test_cfg_v6();
        let relay = Arc::new(CaptureRelay::default());
        let (mut net, sink) = stack(&cfg, relay.clone(), None);

        let client = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
            40000,
        );
        let server = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
            53,
        );
        let hbh = ext8(17, &[0x05, 0x02, 0, 0, 0, 0]);
        net.stage(&udp6_chained(0, &[&hbh], client, server, b"ext-query"));
        net.step();

        for _ in 0..100 {
            if !relay.udp.lock().unwrap().is_empty() {
                break;
            }
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        {
            let up = relay.udp.lock().unwrap();
            assert_eq!(up.len(), 1, "the chained datagram is relayed");
            assert_eq!(up[0].0, client);
            assert_eq!(up[0].1.to_string(), "[2001:4860:4860::8888]:53");
            assert_eq!(up[0].2, b"ext-query");
        }
        assert!(
            net.shim.ingress.is_empty(),
            "the chained packet is not staged for smoltcp"
        );
        assert!(
            net.udp_sockets.contains_key(&53),
            "the reply socket is bound despite the chain"
        );

        // The relay's echo reply still comes back through the bound socket.
        let client_ip = match client.ip() {
            IpAddr::V6(ip) => ip,
            _ => unreachable!(),
        };
        let is_reply = |p: &[u8]| p[0] >> 4 == 6 && p[6] == 17 && p[24..40] == client_ip.octets();
        for _ in 0..100 {
            if sink.0.lock().unwrap().iter().any(|p| is_reply(p)) {
                break;
            }
            net.step();
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        let reply = sink
            .0
            .lock()
            .unwrap()
            .iter()
            .find(|p| is_reply(p))
            .cloned()
            .expect("the reply rides the bound smoltcp socket");
        let (src, dst, payload) = udp6_fields(&reply);
        assert_eq!(src, server);
        assert_eq!(dst, client);
        assert_eq!(payload, b"ext-query");
    }

    /// Chained ICMPv6 echoes are answered on the device, chain preserved.
    #[tokio::test]
    async fn ipv6_icmp_echo_behind_ext_headers_is_answered() {
        let cfg = test_cfg_v6();
        let relay = Arc::new(CaptureRelay::default());
        let (mut net, sink) = stack(&cfg, relay.clone(), None);

        let client = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2);
        let gateway = Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1);
        let hbh = ext8(58, &[0x05, 0x02, 0, 0, 0, 0]);
        net.stage(&icmpv6_echo_request_chained(
            0,
            &[&hbh],
            client,
            gateway,
            9,
            9,
            b"ping6-xh",
        ));
        net.step();

        let out = sink.0.lock().unwrap().clone();
        assert_eq!(out.len(), 1, "exactly the chained echo reply");
        let reply = &out[0];
        assert_eq!(reply[6], 0, "chain still first");
        assert_eq!(&reply[40..48], &hbh[..], "chain carried verbatim");
        assert_eq!(reply[48], 129, "echo reply type");
        let icmp = &reply[48..];
        let pseudo = pseudo_header_v6(gateway, client, 58, icmp.len());
        assert_eq!(checksum(&[&pseudo, icmp]), 0, "checksum verifies");
        assert!(relay.tcp.lock().unwrap().is_empty());
        assert!(relay.udp.lock().unwrap().is_empty());
    }

    // -- the full inbound over the in-memory device -----------------------------

    use crate::inbound::tun::testdev::LoopbackTun;
    use std::time::Instant;

    /// Wait for `cond` (polled on a fresh clone of the closure's captures
    /// each round) up to 10s, tokio-yielding between rounds. Returns the
    /// value or panics with `what`.
    async fn wait_until<T>(what: &str, mut cond: impl FnMut() -> Option<T>) -> T {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            if let Some(v) = cond() {
                return v;
            }
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    /// The same discipline for the device's egress: tokio yields between
    /// rounds so the spawned netstack task keeps being polled — a
    /// `std::thread::sleep` loop would starve a current-thread runtime and
    /// the packets this waits for would never be produced.
    async fn wait_egress(
        dev: &LoopbackTun,
        what: &str,
        mut pred: impl FnMut(&[u8]) -> bool,
        spill: &mut Vec<Vec<u8>>,
    ) -> Vec<u8> {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            for pkt in dev.take_egress() {
                if pred(&pkt) {
                    return pkt;
                }
                spill.push(pkt);
            }
            assert!(Instant::now() < deadline, "timed out waiting for {what}");
            tokio::task::yield_now().await;
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
    }

    /// UDP relay + ICMP echo through the real `run()` loop: in-memory device
    /// -> reader pump thread -> select loop -> classifier -> relay/ICMP
    /// responder -> sink -> device egress. No kernel TUN anywhere.
    #[tokio::test]
    async fn run_serves_udp_and_icmp_over_the_in_memory_device() {
        let dev = LoopbackTun::new();
        let relay = Arc::new(CaptureRelay::default());
        let cfg = test_cfg_v6();
        let io_dev: Arc<dyn TunIo> = dev.clone();
        let task = tokio::spawn(run(
            io_dev,
            cfg,
            relay.clone(),
            TunHooks { dns: None },
        ));

        let client = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
            40000,
        );
        let server = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888)),
            53,
        );
        dev.inject(&udp6_packet(client, server, b"pumpme"));
        let up = wait_until("relay uplink", || relay.udp.lock().unwrap().first().cloned()).await;
        assert_eq!(up.0, client, "session keyed by the v6 source");
        assert_eq!(up.1.to_string(), "[2001:4860:4860::8888]:53");
        assert_eq!(up.2, b"pumpme");

        let client_ip = match client.ip() {
            IpAddr::V6(ip) => ip,
            _ => unreachable!(),
        };
        let mut spill = Vec::new();
        let reply = wait_egress(
            &dev,
            "the relay echo must come back out of the device",
            |p| p[0] >> 4 == 6 && p[6] == 17 && p[24..40] == client_ip.octets(),
            &mut spill,
        )
        .await;
        let (src, dst, payload) = udp6_fields(&reply);
        assert_eq!(src, server, "reply sourced from the dialled peer");
        assert_eq!(dst, client);
        assert_eq!(payload, b"pumpme");

        // ICMPv4 echo through the same pump (the stack answers it itself).
        let ping = icmpv4_echo_request(
            Ipv4Addr::new(10, 7, 0, 2),
            Ipv4Addr::new(10, 7, 0, 1),
            5,
            5,
            b"via-pump",
        );
        dev.inject(&ping);
        let pong = wait_egress(
            &dev,
            "the echo reply must come back out of the device",
            |p| p.len() > 28 && p[0] >> 4 == 4 && p[9] == 1 && icmpv4_msg(p)[0] == 0,
            &mut spill,
        )
        .await;
        assert_eq!(icmpv4_msg(&pong)[0], 0, "echo reply type");
        assert_eq!(&icmpv4_msg(&pong)[8..], b"via-pump", "data carried");

        task.abort();
    }

    /// A full TCP handshake + data over the in-memory device: proves the
    /// SYN-peek/listener path and the stream bridge ride the pump too.
    #[tokio::test]
    async fn run_relays_a_tcp_handshake_over_the_in_memory_device() {
        let dev = LoopbackTun::new();
        let relay = Arc::new(CaptureRelay::default());
        let cfg = test_cfg_v6();
        let io_dev: Arc<dyn TunIo> = dev.clone();
        let task = tokio::spawn(run(
            io_dev,
            cfg,
            relay.clone(),
            TunHooks { dns: None },
        ));

        let client = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
            40000,
        );
        let server = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0x2606, 0x4700, 0, 0, 0, 0, 0, 0x1111)),
            443,
        );
        dev.inject(&tcp6_packet(client, server, 1000, None, FLAG_SYN, &[]));
        let mut spill = Vec::new();
        let synack = wait_egress(
            &dev,
            "SYN-ACK through the pump",
            |p| p[0] >> 4 == 6 && p[6] == 6 && tcp6_fields(p).4 & 0x12 == 0x12,
            &mut spill,
        )
        .await;
        let (_sp, _dp, stack_seq, ack_no, _f) = tcp6_fields(&synack);
        assert_eq!(ack_no, 1001, "SYN-ACK acknowledges the SYN");

        dev.inject(&tcp6_packet(
            client,
            server,
            ack_no,
            Some(stack_seq + 1),
            0,
            &[],
        ));
        let _meta = wait_until("relay accept", || {
            relay.tcp.lock().unwrap().first().cloned()
        })
        .await;
        let mut stream = relay.take_stream().expect("stream handed to the relay");

        use tokio::io::AsyncWriteExt;
        stream.write_all(b"over-the-pump").await.unwrap();
        let data = wait_egress(
            &dev,
            "stream bytes must reach the wire",
            |p| p[0] >> 4 == 6 && p[6] == 6 && p.len() > 60 && p[60..].ends_with(b"over-the-pump"),
            &mut spill,
        )
        .await;
        assert!(data.len() >= 60 + b"over-the-pump".len());

        drop(stream);
        task.abort();
    }

    /// TCP DNS hijack end to end over the in-memory device (sing-box
    /// #3878's shape: a resolver falling back to TCP DNS must be answered
    /// by the engine, never relayed back into the routing path): a
    /// completed handshake to a hijacked destination serves length-framed
    /// DNS from the engine resolver over the bridged stream.
    #[tokio::test]
    async fn run_hijacks_tcp_dns_over_the_in_memory_device() {
        let dev = LoopbackTun::new();
        let relay = Arc::new(CaptureRelay::default());
        let mut cfg = test_cfg_v6();
        let gateway = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        cfg.dns_hijack = vec![gateway.into()];
        let mut dns_cfg = crate::config::DnsConfig::default();
        let answer_v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x77);
        dns_cfg
            .hosts
            .insert("probe-tcp.test".to_string(), vec![answer_v6.into()]);
        let dns = DnsEngine::new(dns_cfg, crate::rule::DomainMatcher::default()).unwrap();

        let io_dev: Arc<dyn TunIo> = dev.clone();
        let task = tokio::spawn(run(
            io_dev,
            cfg,
            relay.clone(),
            TunHooks { dns: Some(dns) },
        ));

        let client = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
            40001,
        );
        let hijack_dst = SocketAddr::new(gateway, 53);

        // Handshake to the hijacked destination.
        dev.inject(&tcp6_packet(client, hijack_dst, 1000, None, FLAG_SYN, &[]));
        let mut spill = Vec::new();
        let synack = wait_egress(
            &dev,
            "SYN-ACK from the hijack listener",
            |p| p[0] >> 4 == 6 && p[6] == 6 && tcp6_fields(p).4 & 0x12 == 0x12,
            &mut spill,
        )
        .await;
        let (_sp, _dp, stack_seq, ack_no, _f) = tcp6_fields(&synack);
        assert_eq!(ack_no, 1001);
        dev.inject(&tcp6_packet(
            client,
            hijack_dst,
            ack_no,
            Some(stack_seq + 1),
            0,
            &[],
        ));

        // One length-framed AAAA query for a hosts-mapped name.
        let mut q = dns_query("probe-tcp.test", 0x0e0f);
        let qlen = q.len();
        q[qlen - 4] = 0x00;
        q[qlen - 3] = 0x1c; // AAAA — matches the v6 hosts entry
        let mut framed = (q.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&q);
        dev.inject(&tcp6_packet(
            client,
            hijack_dst,
            1001,
            Some(stack_seq + 1),
            0x08, // PSH
            &framed,
        ));

        // The framed answer comes back with the resolver's data.
        let answer = wait_egress(
            &dev,
            "the framed DNS answer must come back over the stream",
            |p| {
                p[0] >> 4 == 6 && p[6] == 6 && p.len() > 60 && p[60..].ends_with(&answer_v6.octets())
            },
            &mut spill,
        )
        .await;
        let tcp_payload = &answer[60..];
        let frame_len = u16::from_be_bytes([tcp_payload[0], tcp_payload[1]]) as usize;
        let msg = crate::dns::wire::parse(&tcp_payload[2..2 + frame_len]).unwrap();
        assert_eq!(msg.id, 0x0e0f, "transaction id echoed");
        assert!(
            relay.tcp.lock().unwrap().is_empty(),
            "a hijacked TCP DNS connection must never reach the relay"
        );

        task.abort();
    }

    /// DNS hijack end to end over the in-memory device, including a chained
    /// query: the reader pump, classifier, resolver and reply socket in one
    /// path — the platform-independence proof for the whole inbound.
    #[tokio::test]
    async fn run_hijacks_dns_over_the_in_memory_device() {
        let dev = LoopbackTun::new();
        let relay = Arc::new(CaptureRelay::default());
        let mut cfg = test_cfg_v6();
        let gateway = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        cfg.dns_hijack = vec![gateway.into()];
        let mut dns_cfg = crate::config::DnsConfig::default();
        let answer_v6 = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x66);
        dns_cfg
            .hosts
            .insert("pump-dns.test".to_string(), vec![answer_v6.into()]);
        let dns = DnsEngine::new(dns_cfg, crate::rule::DomainMatcher::default()).unwrap();

        let io_dev: Arc<dyn TunIo> = dev.clone();
        let task = tokio::spawn(run(
            io_dev,
            cfg,
            relay.clone(),
            TunHooks { dns: Some(dns) },
        ));

        let client = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 2)),
            40000,
        );
        let hijack = SocketAddr::new(gateway, 53);
        // A chained query: hop-by-hop -> routing -> UDP 53 to the hijack
        // address.
        let hbh_then_routing = ext8(43, &[0x05, 0x02, 0, 0, 0, 0]);
        let routing = ext8(17, &[0u8; 8]);
        let mut q = dns_query("pump-dns.test", 0x0c0d);
        let q_len = q.len();
        q[q_len - 4] = 0x00;
        q[q_len - 3] = 0x1c; // AAAA
        dev.inject(&udp6_chained(
            0,
            &[&hbh_then_routing, &routing],
            client,
            hijack,
            &q,
        ));

        let client_ip = match client.ip() {
            IpAddr::V6(ip) => ip,
            _ => unreachable!(),
        };
        let mut spill = Vec::new();
        let answer = wait_egress(
            &dev,
            "the resolver's answer must come back out of the device",
            |p| p[0] >> 4 == 6 && p[6] == 17 && p[24..40] == client_ip.octets(),
            &mut spill,
        )
        .await;
        let (src, dst, payload) = udp6_fields(&answer);
        assert_eq!(src, hijack, "answer from the hijacked address");
        assert_eq!(dst, client);
        assert_eq!(&payload[..2], &0x0c0du16.to_be_bytes(), "transaction id");
        assert!(payload.ends_with(&answer_v6.octets()), "AAAA answer");
        assert!(relay.udp.lock().unwrap().is_empty(), "nothing relayed");

        task.abort();
    }

    /// A device that dies takes `run()` down with the reader's error — the
    /// pump's error slot reaches the caller.
    #[tokio::test]
    async fn run_returns_the_device_error() {
        let dev = LoopbackTun::new();
        let relay = Arc::new(CaptureRelay::default());
        let io_dev: Arc<dyn TunIo> = dev.clone();
        let task = tokio::spawn(run(
            io_dev,
            test_cfg(),
            relay,
            TunHooks { dns: None },
        ));
        dev.kill("device vanished");
        let outcome = tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("run must return when the device dies")
            .expect("task must not panic");
        let err = outcome.expect_err("the device error must surface");
        let text = err.to_string();
        assert!(text.contains("device read"), "{text}");
        assert!(text.contains("device vanished"), "{text}");
    }
}
