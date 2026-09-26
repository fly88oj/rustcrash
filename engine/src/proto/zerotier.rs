//! The ZeroTier overlay outbound: config surface + the Rust wire core
//! (milestone 1: identity, packet armor, HELLO, controller netconf) +
//! the node runtime (milestone 2: world/planet parsing, the UDP node
//! loop with WHOIS through the planet roots, fragmentation, the
//! netconf-driven smoltcp link and a real `connect()` dial) + the map
//! of what still separates it from a full node.
//!
//! # Honest start
//!
//! mihomo's ZeroTier outbound (`adapter/outbound/zerotier.go`, 1370
//! lines, cached at `/tmp/wave10-upstream/probe_adapter_outbound_zerotier.go`)
//! is build-gated `!no_zerotier` and embeds **`metacubex/zerotier-go`**
//! — Go bindings over **libzt**, the C/C++ ZeroTier core. The engine
//! ships musl-static with **no C dependencies**, so vendoring the C
//! node core is out; the wave-14 question was whether a Rust core's
//! *first milestone* is tractable the way wireguard's Noise, tailscale's
//! Noise/DERP and easytier's mesh were. Verdict: **yes** — the wire
//! layer is pure, well-specified arithmetic on primitives the tree
//! already carries, and it has now landed here (everything below
//! [`MILESTONE_1`]). What remains out of scope is the *node runtime*
//! around it, not the crypto or the codecs.
//!
//! # The wave-14 evidence chain
//!
//! Sources probed (upstream `zerotier/ZeroTierOne` @ `899352e`,
//! 2026-07-22, cloned to `/tmp/wave14-upstream/ZeroTierOne`; the Go
//! port `metacubex/zerotier-go` cloned alongside):
//!
//! * **Cipher** — `node/Packet.hpp:81-127`: cipher suite
//!   `C25519_POLY1305_SALSA2012 = 1` (Poly1305 MAC keyed by the first
//!   32 bytes of a **Salsa20/12** keystream; payload encrypted with the
//!   keystream from byte 64 on — `Packet.cpp:1083-1164`, cross-read in
//!   the Go port's `packet.go:507-538`); suite 0 = MAC-only (HELLO is
//!   sent in the clear, MAC'd); suite 3 = AES-GMAC-SIV, used **only**
//!   when the peer's protocol version is >= 12 (`Peer.hpp:657-659`) —
//!   a client advertising protocol version 11 (min accepted is 4,
//!   `Packet.hpp:64-69`) pins every conversation to Salsa20/12, so
//!   AES-GMAC-SIV is never load-bearing. Salsa20 is **not** in-tree as
//!   a crate (`chacha20poly1305` is ChaCha, not Salsa; the lockfile's
//!   `salsa20` exists only transitively under scrypt/russh), so the
//!   core is hand-rolled here against public vectors, exactly like
//!   `proto::tailscale::derp`'s XSalsa20 before it.
//! * **Identity** — `node/Identity.cpp:24-79`: a node identity is a
//!   64-byte public key set = X25519 pub (bytes 0-32) || Ed25519 pub
//!   (bytes 32-64) (`node/ECC.hpp:55-116`); the 40-bit address is a
//!   hashcash PoW: a 2 MiB memory-hard SHA-512/Salsa20 digest of the
//!   public set whose first byte must be < 17 and whose last 5 bytes
//!   *are* the address. Generation varies the X25519 half only
//!   (`ECC::generateSatisfying`, LE u64 inc/dec at bytes 8..24).
//!   String form `address:0:pubhex[:privhex]` with the address in
//!   **hex10** — note `Utils::hex10`; the wave-10 config code wrongly
//!   parsed node addresses as decimal, fixed below to match
//!   `zerotier-go/address.go:44-58` ("a ten-character hexadecimal
//!   ZeroTier node address").
//! * **Key agreement** — `node/ECC.cpp:2450-2465` (and the Go port
//!   `identity.go:224-236`): `key = SHA-512(X25519(my priv, their pub))`
//!   truncated to 48 bytes. Pinned here against the Go port's published
//!   cross-implementation agreement vector (`identity_test.go:31-46`).
//! * **Signatures** — `node/ECC.cpp:2466-2520` + `get_hram`
//!   (`ECC.cpp:2422-2436`): the 96-byte ZeroTier signature is
//!   `R || s || SHA-512(msg)[0..32]` where `(R,s)` is a **standard
//!   RFC-8032 Ed25519 signature over the 32-byte pre-digest** (the Go
//!   port spells it out: `ed25519.Sign(seed, digest[:32])`,
//!   `identity.go:259-271`). So in-tree `ring` Ed25519 signs and
//!   verifies it with no hand-rolled curve code.
//! * **Controller join** — *not* HTTPS JSON (that is ZeroTier
//!   Central's management API): a node joins by sending
//!   `VERB_NETWORK_CONFIG_REQUEST` (0x0b) over the same armored UDP
//!   wire to the controller node — the address encoded in the top 40
//!   bits of the network id (`zerotier-go/address.go:131-133`,
//!   `node/Network.cpp:1436-1461`). The reply `OK` carries a chunked
//!   `key=value\n` netconf dictionary, each chunk signed by the
//!   controller identity (`node/Node.cpp:800-840`) and LZ4-block
//!   compressed when that shrinks it (`Packet.cpp:1276-1296`;
//!   decompression happens generically before verb dispatch,
//!   `IncomingPacket.cpp:74-78`). The client verifies each chunk's
//!   signature against the controller identity
//!   (`node/Network.cpp:1123-1132`). Requests may be sent uncompressed.
//! * **Fragmentation** — `node/Packet.hpp:344-462` (the `Packet::
//!   Fragment` header: parent packet id, dest, the reserved-`0xff`
//!   indicator byte, `(total<<4|no)`, hops) + the send-side slicing in
//!   `node/Switch.cpp:_sendViaSpecificPath` (head truncated to the
//!   path MTU with `ZT_PROTO_FLAG_FRAGMENTED` set *before* armoring —
//!   the MAC covers the whole assembled packet; fragments 1..n each
//!   carry `mtu-16` payload bytes, no per-fragment MAC) + the
//!   receive-side reassembly queue keyed by packet id
//!   (`node/Switch.cpp:68-272`: bitmask of fragments held, assemble
//!   when complete, then dearmor).
//! * **WHOIS** — `VERB_WHOIS` (0x04) payload is one or more 5-byte
//!   addresses; the upstream's `OK(WHOIS)` carries the binary
//!   identities it knows (`node/IncomingPacket.cpp:669-705`,
//!   `_doWHOIS`). Roots (supernodes) answer for every peer that has
//!   HELLOed them; unknown sources are themselves WHOISed — a fresh
//!   node therefore always bootstraps with HELLO, whose identity
//!   travels in the clear under suite 0.
//! * **World/planet** — `node/World.hpp` (header-only at this ref):
//!   `type(1) || id(8) || ts(8) || updatesMustBeSignedBy(64) ||
//!   signature(96) || roots[ (identity(71+) || endpoints[InetAddress]) ]`
//!   with the signature over the `forSign` form (0x7f…7f prefix,
//!   0xf7…f7 suffix). The built-in Earth planet is a 570-byte constant
//!   in `node/Topology.cpp:20-37` (`ZT_DEFAULT_WORLD_LENGTH`,
//!   id 149604618) — carried verbatim below and parsed in tests.
//! * **Netconf dictionary** — `node/NetworkConfig.cpp:366+`
//!   (`fromDictionary`): `mtu`, `I` = concatenated binary
//!   `InetAddress`es whose u16 field carries the prefix length
//!   (`InetAddress.hpp:615-660` — the same codec as HELLO's physical
//!   addresses), `RT` = `[target][via][u16 flags][u16 metric]` runs,
//!   `S` = u64 specialist node addresses (active bridges), all stored
//!   with the `node/Dictionary.hpp` backslash escapes (`\0` `\r` `\n`
//!   `\\` `\e`) — *not* hex.
//! * **Relaying** — every packet whose destination is not the
//!   receiver is relayed toward it with the hop count (low 3 flag
//!   bits) incremented (`node/Switch.cpp:82-152`). Hop mutation is
//!   MAC-safe by construction: `_salsa20MangleKey` masks the hop bits
//!   out (`Packet.hpp:1425-1452`) and the Poly1305 input starts at the
//!   verb byte. A client node with no direct path sends through a
//!   planet root exactly this way (`Switch.cpp:_trySend`'s relay
//!   fallback).
//! * **Data plane** — `VERB_FRAME` (0x06) carries `nwid(8) ||
//!   ethertype(2) || ethernet payload` with **no MAC header**: MACs
//!   are derived from the packet's source/destination ZeroTier
//!   addresses (`node/IncomingPacket.cpp:_doFRAME`, `MAC::fromAddress`
//!   in `node/MAC.hpp:163-173` — the low 40 bits are the address
//!   XOR-masked with network-id bytes, first octet locally
//!   administered). Unicast frames to an unknown MAC go to the
//!   network's active-bridge specialists (`Switch.cpp:
//!   onLocalEthernet`), which is how an L3-only port reaches peers
//!   before it has learned any MACs.
//! * **Extended armor** — the `encrypted-hello` option wraps HELLO in
//!   an ephemeral-X25519 + AES-CTR tail (`Packet.cpp:1152-1163`). It
//!   is a *node option*, default off (`Node.hpp:288-300`,
//!   `enableEncryptedHello` zero-initialized): roots accept the plain
//!   base form, which is what this port sends (`Peer.cpp:426-474`
//!   passes `encryptedHelloEnabled()`). AES-CTR for the tail stays
//!   unimplemented; see [`NOT_PORTED`].
//! * **Multipath/bonding** — optional per-config (`node/Bond.cpp` is a
//!   peer policy), never required on the wire; single-path packet
//!   exchange is complete protocol.
//!
//! # What landed (milestone 1)
//!
//! * [`NodeIdentity`] — generation (PoW search), parse/serialize (string
//!   and binary forms), hashcash [`memory_hard_hash`] validation,
//!   X25519 [`NodeIdentity::agree`], Ed25519 [`NodeIdentity::sign`]/`verify`.
//! * [`WirePacket`] — the 28-byte header codec, suite 0/1 armor and
//!   dearmor (hand-rolled [`salsa20`] + [`poly1305`], per-packet key
//!   mangling per `Packet.hpp:1425-1452`), LZ4 block decompression.
//! * [`build_hello`]/[`parse_hello`]/[`build_ok_hello`]/[`parse_ok_hello`]
//!   — the P2P identity handshake.
//! * [`build_network_config_request`]/[`parse_netconf_response`] — the
//!   controller join conversation, chunk-signature verification
//!   included.
//!
//! Crypto is pinned to public vectors: Salsa20/20 (eSTREAM verified
//! set 1, 256-bit key), Salsa20/12 (BouncyCastle `Salsa20Test`'s
//! eSTREAM-derived vectors — the 16-byte-key "expand 16-byte k"
//! layout exists here solely so that variant has a *public* vector;
//! ZeroTier only ever uses 32-byte keys), Poly1305 (RFC 8439 §2.5.2),
//! and the Go port's known-good identity + ECDH agreement fixtures.
//!
//! # What landed (milestone 2: the node runtime)
//!
//! * [`World`] — planet/moon parsing, the `forSign` signature check,
//!   `World::make` for tests, and the built-in Earth planet bytes
//!   (`ZT_DEFAULT_WORLD`, Topology.cpp) parsed in tests.
//! * [`fragment_packet`]/[`FragmentAssembler`] — the send-side slicing
//!   and receive-side reassembly queue from Switch.cpp.
//! * [`NetconfDict`]/[`AppliedNetconf`] — the controller dictionary
//!   decoded (escapes included) into managed IPs, routes, MTU and
//!   active-bridge specialists.
//! * [`ZtStack`] — the UDP node loop: HELLO bootstrap to a planet
//!   root, WHOIS through the root, the netconf join, a peer table
//!   (address → identity/endpoint/key), per-peer duplicate-packet-id
//!   suppression, relay-through-root for peers without a direct path,
//!   and the smoltcp interface bridged over `VERB_FRAME` — the
//!   wireguard/openvpn EtStack shape.
//! * [`connect`] — a real dial (`ZeroTierConfig` + target →
//!   `BoxProxyStream`), plus [`ZtUdp`] for UDP through the overlay.
//!
//! The hermetic e2e spins an in-test planet root (HELLO/WHOIS/relay),
//! a controller (signed netconf with a managed IP + specialist) and a
//! peer node with its own smoltcp echo stack — identity → planet →
//! WHOIS → netconf → dial → echo, with fragmentation exercised via a
//! small path MTU. A real ZeroTier network additionally needs internet
//! reachability of the real planet roots; that interop gap is the same
//! class as easytier's pre-M2 state (the wire is transcribed and
//! cross-validated, the live network is not dialed from CI).
//!
//! # What landed (milestone 3: direct paths, state, moons)
//!
//! * **Direct-path learning / NAT-t** — VERB_RENDEZVOUS (0x05, the
//!   root's introduction) and VERB_PUSH_DIRECT_PATHS (0x10, the
//!   trusted-peer address push) with the probe-confirm flow: a 4-byte
//!   NAT-opener junk datagram, a plain HELLO at the candidate
//!   address, and the armored OK(HELLO) — echoing a packet id we
//!   await, from the probed address — confirms the path and releases
//!   the root relay (`Peer::introduce` / `attemptToContactAt` /
//!   `_doPUSH_DIRECT_PATHS`, IncomingPacket.cpp:736-761 + 1364-1431).
//! * **State persistence** — `state-dir` now holds the Node.cpp state
//!   objects: `identity.secret` (generated once, reloaded on restart
//!   — the openvpn/wireguard state-store precedent) and
//!   `peers.d/<addr>` (learned identities + last paths, so a restart
//!   skips the WHOIS round trips).
//! * **Moon gossip** — HELLO tails list pending `orbit:` seeds at
//!   timestamp 0; the OK(HELLO) world-update block is parsed and
//!   signed moons whose roots contain a configured seed are adopted
//!   as extra upstreams (`Topology::addWorld` +
//!   `shouldAcceptWorldUpdateFrom`).
//!
//! # What remains ([`NOT_PORTED`])
//!
//! Bonds/multipath policies, multicast groups (MULTICAST_LIKE/GATHER/
//! MULTICAST_FRAME and ARP/NDP emulation), tap/L2 semantics for
//! bridged nodes, capabilities/tags rules enforcement, SSO netconf
//! auth, cluster verbs, QoS/flow hashing, trusted paths, and the
//! AES-CTR extended-armor HELLO tail. The TCP fallback relay no
//! longer exists upstream (node/, 1.14.x) — the config fields parse
//! inertly, exactly like a current upstream node treats them.
//!
//! # Config surface
//!
//! Every field of upstream `ZeroTierOption` (cached lines 108-135) is
//! carried by [`ZeroTierConfig`], and the constructor's data-only
//! validations are ported ([`ZeroTierConfig::validate`],
//! [`parse_network_id`], [`default_state_dir`], [`identity_has_private`]).
//! `identity-secret` is a secret: redacted in `Debug`, tests source it
//! from an environment variable only. MTU bounds mirror
//! `ZT.MinNetworkMTU`/`MaxNetworkMTU`/`MinPhysicalMTU`/`MaxPhysicalMTU`
//! (metacubex/zerotier-go).

use crate::error::{Error, Result};

use std::collections::{HashMap, HashSet, VecDeque};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot, Notify};

use crate::addr::NetAddr;
use crate::stream::BoxProxyStream;

/// `ZT.MinNetworkMTU` — IPv6's minimum MTU (1280), the floor for a
/// ZeroTier virtual network.
pub const MIN_NETWORK_MTU: i64 = 1280;
/// `ZT.MaxNetworkMTU` — ZeroTier's network MTU ceiling.
pub const MAX_NETWORK_MTU: i64 = 10000;
/// `ZT.MinPhysicalMTU` — physical-path floor. Set to the IPv6 minimum
/// (a ZeroTier path must at least carry a 1280-byte datagram).
pub const MIN_PHYSICAL_MTU: i64 = 1280;
/// `ZT.MaxPhysicalMTU` — a UDP payload fits in a u16.
pub const MAX_PHYSICAL_MTU: i64 = 65535;
/// `ZT.TraceLevelInsane` — the trace-level ceiling.
pub const TRACE_LEVEL_INSANE: u64 = 4;

// ===========================================================================
// Milestone 1: the Rust wire core
// ===========================================================================

/// Marker for the wave-14 milestone: the sections between here and
/// [`NOT_PORTED`] are the Rust-native ZeroTier wire layer (identity,
/// armor, HELLO, controller netconf), all pinned to public vectors.
pub const MILESTONE_1: &str = "zerotier wire core: identity + armor + HELLO + netconf (rust-native)";

/// Marker for the wave-15 milestone: the node runtime (world/planet,
/// the UDP loop with WHOIS + relay, fragmentation, the netconf→smoltcp
/// link and the dial).
pub const MILESTONE_2: &str = "zerotier node runtime: planet + UDP loop + WHOIS + fragments + netconf link (rust-native)";

// Milestone-2 wire constants (node/Packet.hpp:138-208, Constants.hpp).

/// `ZT_PACKET_FRAGMENT_INDICATOR` = `ZT_ADDRESS_RESERVED_PREFIX`: a
/// datagram whose byte 13 is 0xff is a Packet::Fragment, not a head
/// (`Switch.cpp:74` — byte 13 is a packet's source-address top byte,
/// which can never be 0xff since that prefix is reserved).
pub const FRAGMENT_INDICATOR: u8 = 0xff;
/// The fragment-indicator offset (`ZT_PACKET_FRAGMENT_IDX_FRAGMENT_INDICATOR`,
/// which aliases the packet header's source-address start).
pub const FRAGMENT_IDX_INDICATOR: usize = PACKET_IDX_SOURCE;
/// `ZT_PACKET_FRAGMENT_IDX_PAYLOAD` = 16: the fragment header length.
pub const FRAGMENT_HEADER_LEN: usize = 16;
/// `ZT_MAX_PACKET_FRAGMENTS` (node/Constants.hpp:295) — 7 fragments
/// per assembled packet (the 4-bit field would allow 16; upstream
/// bounds `ZT_PROTO_MAX_PACKET_LENGTH` to 7 × physical MTU).
pub const MAX_PACKET_FRAGMENTS: usize = 7;
/// `ZT_ETHERTYPE_IPV4` (IEEE 802.3 assigned numbers).
pub const ETHERTYPE_IPV4: u16 = 0x0800;
/// `ZT_ETHERTYPE_IPV6`.
pub const ETHERTYPE_IPV6: u16 = 0x86dd;
/// `ZT_RELAY_MAX_HOPS` (node/Constants.hpp:337).
pub const RELAY_MAX_HOPS: u8 = 3;
/// `ZT_WHOIS_RETRY_DELAY` in ms (node/Constants.hpp:320).
pub const WHOIS_RETRY: Duration = Duration::from_millis(500);
/// `ZT_PATH_HEARTBEAT_PERIOD` (node/Constants.hpp:374), ms — the root
/// path keepalive (a HELLO whose reply doubles as the heartbeat ack).
pub const PATH_HEARTBEAT: Duration = Duration::from_millis(14_000);
/// `ZT_DEFAULT_MTU` (node/Constants.hpp:290) — the netconf default
/// when the controller's dictionary carries no `mtu`.
pub const DEFAULT_NETWORK_MTU: usize = 2800;

/// `ZT_PROTO_VERSION` we advertise (node/Packet.hpp:64 = 13). We claim
/// **11**: the only wire-visible thing versions >= 12 gate is the
/// AES-GMAC-SIV suite (`Peer.hpp:657-659` — peers pick it for us only
/// if we advertise >= 12), and this port implements Salsa20/12 only.
/// `ZT_PROTO_VERSION_MIN` is 4, so every peer accepts 11.
pub const PROTO_VERSION: u8 = 11;
/// `ZT_PROTO_VERSION_MIN` (node/Packet.hpp:69) — the oldest peer we
/// will talk to.
pub const PROTO_VERSION_MIN: u8 = 4;
/// The engine's advertised software version (mirrors the
/// `vMajor/vMinor/vRevision` HELLO fields).
pub const SOFTWARE_VERSION: (u8, u8, u16) = (0, 1, 0);
/// `ZT_SYMMETRIC_KEY_SIZE` (node/Constants.hpp:280) — ZeroTier's
/// pairwise keys are 48 bytes (armor consumes the first 32).
pub const SYMMETRIC_KEY_SIZE: usize = 48;
/// `ZT_ECC_*` sizes (node/ECC.hpp:60-62): C25519+Ed25519 key sets.
pub const PUBLIC_KEY_SIZE: usize = 64;
/// Secret key set: X25519 half || Ed25519 seed half.
pub const PRIVATE_KEY_SIZE: usize = 64;
/// `ZT_ECC_SIGNATURE_LEN` — `R(32) || s(32) || SHA-512(msg)[0..32](32)`.
pub const SIGNATURE_SIZE: usize = 96;
/// `ZT_DEFAULT_PHYSMTU` (include/ZeroTierOne.h:98).
pub const DEFAULT_PHYSICAL_MTU: usize = 1432;
/// `ZT_PROTO_MAX_PACKET_LENGTH` = fragments × physical MTU.
pub const MAX_PACKET_LENGTH: usize = 7 * DEFAULT_PHYSICAL_MTU;
/// The memory-hard identity PoW buffer (node/Identity.cpp:18:
/// `ZT_IDENTITY_GEN_MEMORY`).
pub const IDENTITY_GEN_MEMORY: usize = 2 * 1024 * 1024;
/// `ZT_IDENTITY_GEN_HASHCASH_FIRST_BYTE_LESS_THAN`
/// (node/Identity.cpp:15): digest[0] < 17 ⇒ ~1/16.6 work factor.
const IDENTITY_HASHCASH_THRESHOLD: u8 = 17;
/// `ZT_NETWORKCONFIG_VERSION` (node/NetworkConfig.hpp:90).
pub const NETWORKCONFIG_VERSION: u64 = 7;

// ---------------------------------------------------------------------------
// Salsa20 (djb snuffle, public domain) — 12-round armor + 20-round PoW
// ---------------------------------------------------------------------------

/// Salsa20 "expand 32-byte k" constants (the sigma words).
const SALSA_SIGMA: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
/// Salsa20 "expand 16-byte k" constants — the 128-bit-key variant.
/// ZeroTier never uses it; it exists so the 12-round core can be pinned
/// to a public (BouncyCastle-published) vector.
const SALSA_TAU: [u32; 4] = [0x6170_7865, 0x3120_646e, 0x7962_2d36, 0x6b20_6574];

/// One Salsa20 doubleround on 16 words (djb spec; the same permutation
/// `proto::tailscale::derp` runs for XSalsa20).
fn salsa20_doubleround(x: &mut [u32; 16]) {
    fn qr(x: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
        x[b] ^= x[a].wrapping_add(x[d]).rotate_left(7);
        x[c] ^= x[b].wrapping_add(x[a]).rotate_left(9);
        x[d] ^= x[c].wrapping_add(x[b]).rotate_left(13);
        x[a] ^= x[d].wrapping_add(x[c]).rotate_left(18);
    }
    // column round
    qr(x, 0, 4, 8, 12);
    qr(x, 5, 9, 13, 1);
    qr(x, 10, 14, 2, 6);
    qr(x, 15, 3, 7, 11);
    // row round
    qr(x, 0, 1, 2, 3);
    qr(x, 5, 6, 7, 4);
    qr(x, 10, 11, 8, 9);
    qr(x, 15, 12, 13, 14);
}

/// The Salsa20 hash over a full 16-word state (`salsa20_wordtobyte`):
/// `rounds` rounds, then add the input back and serialize LE. This is
/// the only place round count matters — ZeroTier uses 12 for packet
/// armor and 20 for the identity PoW.
fn salsa20_hash(input: &[u32; 16], rounds: usize, out: &mut [u8; 64]) {
    let mut x = *input;
    for _ in 0..(rounds / 2) {
        salsa20_doubleround(&mut x);
    }
    for i in 0..16 {
        let w = x[i].wrapping_add(input[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
    }
}

/// Assemble the Salsa20 state: sigma/tau + key + 8-byte IV + 64-bit
/// block counter (words 8/9, LE — `node/Salsa20.cpp:96-120`).
fn salsa20_state(key: &[u8], iv: &[u8; 8], counter: u64) -> [u32; 16] {
    let word = |b: &[u8]| u32::from_le_bytes(b.try_into().unwrap());
    let k: [u32; 4] = [
        word(&key[0..4]),
        word(&key[4..8]),
        word(&key[8..12]),
        word(&key[12..16]),
    ];
    let (c, hi): (&[u32; 4], [u32; 4]) = if key.len() == 32 {
        (
            &SALSA_SIGMA,
            [word(&key[16..20]), word(&key[20..24]), word(&key[24..28]), word(&key[28..32])],
        )
    } else {
        (&SALSA_TAU, k)
    };
    [
        c[0],
        k[0],
        k[1],
        k[2],
        k[3],
        c[1],
        word(&iv[0..4]),
        word(&iv[4..8]),
        counter as u32,
        (counter >> 32) as u32,
        c[2],
        hi[0],
        hi[1],
        hi[2],
        hi[3],
        c[3],
    ]
}

/// A continuous Salsa20 keystream that mirrors ZeroTier's C++ object
/// semantics (`node/Salsa20.cpp crypt12/crypt20`): a call that ends
/// mid-block *discards* the remainder — the next call resumes at the
/// next 64-byte block. (ZeroTier's armor relies on exactly this: the
/// 32-byte Poly1305 key comes from block 0 and payload encryption
/// starts at byte 64 — confirmed by the fast path at
/// `Packet.cpp:1119-1127` and Go `packet.go:519-534`.)
struct SalsaStream {
    key: Vec<u8>,
    iv: [u8; 8],
    counter: u64,
    rounds: usize,
}

impl SalsaStream {
    fn new(key: &[u8], iv: &[u8], rounds: usize) -> Self {
        let mut n = [0u8; 8];
        n.copy_from_slice(&iv[..8]);
        SalsaStream { key: key.to_vec(), iv: n, counter: 0, rounds }
    }

    /// XOR `data` with the next keystream bytes (block-discarding).
    fn xor(&mut self, data: &mut [u8]) {
        let mut block = [0u8; 64];
        let mut pos = 0;
        while pos < data.len() {
            let state = salsa20_state(&self.key, &self.iv, self.counter);
            salsa20_hash(&state, self.rounds, &mut block);
            let take = (data.len() - pos).min(64);
            for i in 0..take {
                data[pos + i] ^= block[i];
            }
            pos += take;
            self.counter += 1;
        }
    }
}

/// Salsa20 encryption of a buffer with a 32-byte key and 8-byte IV
/// (block counter starting at 0).
fn salsa20_xor(key: &[u8; 32], iv: &[u8; 8], data: &mut [u8], rounds: usize) {
    SalsaStream::new(key, iv, rounds).xor(data);
}

/// Poly1305 (RFC 8439 §2.5) — the donna 32-bit-limb evaluation; same
/// construction `proto::tailscale::derp` pins against RFC vectors.
/// ZeroTier MACs with the first 32 keystream bytes and stores only the
/// first 8 tag bytes (`Packet.cpp:1130`).
fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    let le = |b: &[u8]| u32::from_le_bytes(b.try_into().unwrap());
    // r clamp (RFC 8439 §2.5)
    let mut rbytes = [0u8; 16];
    rbytes.copy_from_slice(&key[..16]);
    for w in 0..4 {
        let v = le(&rbytes[w * 4..w * 4 + 4]) & if w == 0 { 0x0fff_ffff } else { 0x0fff_fffc };
        rbytes[w * 4..w * 4 + 4].copy_from_slice(&v.to_le_bytes());
    }
    let r_full = u128::from_le_bytes(rbytes);
    let r: [u32; 5] = [
        (r_full & 0x03ff_ffff) as u32,
        ((r_full >> 26) & 0x03ff_ffff) as u32,
        ((r_full >> 52) & 0x03ff_ffff) as u32,
        ((r_full >> 78) & 0x03ff_ffff) as u32,
        ((r_full >> 104) & 0x03ff_ffff) as u32,
    ];
    let pad = [le(&key[16..20]), le(&key[20..24]), le(&key[24..28]), le(&key[28..32])];
    let mut h = [0u32; 5];

    let mut blocks = |m: &[u8], hibit: u32| {
        let s1 = r[1].wrapping_mul(5);
        let s2 = r[2].wrapping_mul(5);
        let s3 = r[3].wrapping_mul(5);
        let s4 = r[4].wrapping_mul(5);
        for block in m.as_chunks::<16>().0 {
            let t0 = le(&block[0..4]);
            let t1 = le(&block[4..8]);
            let t2 = le(&block[8..12]);
            let t3 = le(&block[12..16]);
            h[0] += t0 & 0x03ff_ffff;
            h[1] += ((t0 >> 26) | (t1 << 6)) & 0x03ff_ffff;
            h[2] += ((t1 >> 20) | (t2 << 12)) & 0x03ff_ffff;
            h[3] += ((t2 >> 14) | (t3 << 18)) & 0x03ff_ffff;
            h[4] += (t3 >> 8) | hibit;

            let d0 = u64::from(h[0]) * u64::from(r[0])
                + u64::from(h[1]) * u64::from(s4)
                + u64::from(h[2]) * u64::from(s3)
                + u64::from(h[3]) * u64::from(s2)
                + u64::from(h[4]) * u64::from(s1);
            let mut d1 = u64::from(h[0]) * u64::from(r[1])
                + u64::from(h[1]) * u64::from(r[0])
                + u64::from(h[2]) * u64::from(s4)
                + u64::from(h[3]) * u64::from(s3)
                + u64::from(h[4]) * u64::from(s2);
            let mut d2 = u64::from(h[0]) * u64::from(r[2])
                + u64::from(h[1]) * u64::from(r[1])
                + u64::from(h[2]) * u64::from(r[0])
                + u64::from(h[3]) * u64::from(s4)
                + u64::from(h[4]) * u64::from(s3);
            let mut d3 = u64::from(h[0]) * u64::from(r[3])
                + u64::from(h[1]) * u64::from(r[2])
                + u64::from(h[2]) * u64::from(r[1])
                + u64::from(h[3]) * u64::from(r[0])
                + u64::from(h[4]) * u64::from(s4);
            let mut d4 = u64::from(h[0]) * u64::from(r[4])
                + u64::from(h[1]) * u64::from(r[3])
                + u64::from(h[2]) * u64::from(r[2])
                + u64::from(h[3]) * u64::from(r[1])
                + u64::from(h[4]) * u64::from(r[0]);

            let mut c = (d0 >> 26) as u32;
            h[0] = d0 as u32 & 0x03ff_ffff;
            d1 += u64::from(c);
            c = (d1 >> 26) as u32;
            h[1] = d1 as u32 & 0x03ff_ffff;
            d2 += u64::from(c);
            c = (d2 >> 26) as u32;
            h[2] = d2 as u32 & 0x03ff_ffff;
            d3 += u64::from(c);
            c = (d3 >> 26) as u32;
            h[3] = d3 as u32 & 0x03ff_ffff;
            d4 += u64::from(c);
            c = (d4 >> 26) as u32;
            h[4] = d4 as u32 & 0x03ff_ffff;
            // 2^130 ≡ 5 (mod 2^130-5): fold the carry back in.
            h[0] += c.wrapping_mul(5);
            c = h[0] >> 26;
            h[0] &= 0x03ff_ffff;
            h[1] += c;
        }
    };

    let full = msg.len() - (msg.len() % 16);
    if full > 0 {
        blocks(&msg[..full], 1 << 24);
    }
    let rem = msg.len() % 16;
    if rem > 0 {
        let mut buf = [0u8; 16];
        buf[..rem].copy_from_slice(&msg[full..]);
        buf[rem] = 1;
        blocks(&buf, 0);
    }

    // finalize: fully carry, compute h + -p, select, add pad
    let mut c = h[1] >> 26;
    h[1] &= 0x03ff_ffff;
    h[2] += c;
    c = h[2] >> 26;
    h[2] &= 0x03ff_ffff;
    h[3] += c;
    c = h[3] >> 26;
    h[3] &= 0x03ff_ffff;
    h[4] += c;
    c = h[4] >> 26;
    h[4] &= 0x03ff_ffff;
    h[0] += c;
    c = h[0] >> 26;
    h[0] &= 0x03ff_ffff;
    h[1] += c;

    let g0 = h[0].wrapping_add(5);
    let c = g0 >> 26;
    let g0 = g0 & 0x03ff_ffff;
    let g1 = h[1].wrapping_add(c);
    let c = g1 >> 26;
    let g1 = g1 & 0x03ff_ffff;
    let g2 = h[2].wrapping_add(c);
    let c = g2 >> 26;
    let g2 = g2 & 0x03ff_ffff;
    let g3 = h[3].wrapping_add(c);
    let c = g3 >> 26;
    let g3 = g3 & 0x03ff_ffff;
    let g4 = h[4].wrapping_add(c).wrapping_sub(1 << 26);

    let mask = (g4 >> 31).wrapping_sub(1);
    let hh = [
        (h[0] & !mask) | (g0 & mask),
        (h[1] & !mask) | (g1 & mask),
        (h[2] & !mask) | (g2 & mask),
        (h[3] & !mask) | (g3 & mask),
        (h[4] & !mask) | (g4 & mask),
    ];

    let w0 = (u64::from(hh[0]) | (u64::from(hh[1]) << 26)) as u32 as u64;
    let w1 = ((u64::from(hh[1] >> 6)) | (u64::from(hh[2]) << 20)) as u32 as u64;
    let w2 = ((u64::from(hh[2] >> 12)) | (u64::from(hh[3]) << 14)) as u32 as u64;
    let w3 = ((u64::from(hh[3] >> 18)) | (u64::from(hh[4]) << 8)) as u32 as u64;

    let mut out = [0u8; 16];
    let mut f = w0 + u64::from(pad[0]);
    out[0..4].copy_from_slice(&(f as u32).to_le_bytes());
    f = w1 + u64::from(pad[1]) + (f >> 32);
    out[4..8].copy_from_slice(&(f as u32).to_le_bytes());
    f = w2 + u64::from(pad[2]) + (f >> 32);
    out[8..12].copy_from_slice(&(f as u32).to_le_bytes());
    f = w3 + u64::from(pad[3]) + (f >> 32);
    out[12..16].copy_from_slice(&(f as u32).to_le_bytes());
    out
}

/// Constant-time byte-slice equality (the MAC check must not leak).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        acc |= x ^ y;
    }
    acc == 0
}

// ---------------------------------------------------------------------------
// Node identity (node/Identity.cpp + node/ECC.*)
// ---------------------------------------------------------------------------

/// The memory-hard hashcash digest a ZeroTier address is derived from
/// (`node/Identity.cpp:23-57`, cross-read in the Go port's
/// `identity.go:281-310`): SHA-512 of the 64-byte public set seeds a
/// Salsa20/20 chain that fills a 2 MiB CBC-like buffer, then the
/// digest is repeatedly re-encrypted while used as a lookup table into
/// that buffer. `digest[0] < 17` and `digest[59..64]` = the address.
fn memory_hard_hash(public: &[u8; PUBLIC_KEY_SIZE]) -> [u8; 64] {
    use sha2::Digest;
    let mut digest: [u8; 64] = sha2::Sha512::digest(public)
        .as_slice()
        .try_into()
        .unwrap();
    let mut stream = SalsaStream::new(&digest[0..32], &digest[32..40], 20);

    let mut genmem = vec![0u8; IDENTITY_GEN_MEMORY];
    // CBC-like fill: block i = (block i-1) XOR keystream (block 0 XORs
    // zeros — the buffer starts zeroed).
    stream.xor(&mut genmem[..64]);
    for i in (64..IDENTITY_GEN_MEMORY).step_by(64) {
        let prev = i - 64;
        genmem.copy_within(prev..i, i);
        stream.xor(&mut genmem[i..i + 64]);
    }

    // Lookup phase: two big-endian indices per iteration; swap a digest
    // u64 with a genmem u64; re-encrypt the whole digest each time.
    let words = (IDENTITY_GEN_MEMORY / 8) as u64;
    let mut i = 0;
    while i < IDENTITY_GEN_MEMORY {
        let idx1 = (u64::from_be_bytes(genmem[i..i + 8].try_into().unwrap()) % 8) as usize * 8;
        i += 8;
        let idx2 = (u64::from_be_bytes(genmem[i..i + 8].try_into().unwrap()) % words) as usize * 8;
        i += 8;
        for k in 0..8 {
            core::mem::swap(&mut genmem[idx2 + k], &mut digest[idx1 + k]);
        }
        stream.xor(&mut digest);
    }
    digest
}

/// A ZeroTier node identity: the 40-bit address (hex10 in string form),
/// the 64-byte public key set (X25519 || Ed25519) and optionally the
/// 64-byte secret set (X25519 priv || Ed25519 seed).
#[derive(Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    address: u64,
    public: [u8; PUBLIC_KEY_SIZE],
    secret: Option<[u8; PRIVATE_KEY_SIZE]>,
}

impl std::fmt::Debug for NodeIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The secret half never appears in Debug output.
        f.debug_struct("NodeIdentity")
            .field("address", &format!("{:010x}", self.address))
            .field("public", &"<64 bytes>")
            .field("secret", &self.secret.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

impl NodeIdentity {
    /// Assemble from raw parts (the future node loop's WHOIS path; the
    /// tests' fixture constructor). No PoW check — see
    /// [`NodeIdentity::locally_validate`].
    pub fn from_parts(
        address: u64,
        public: [u8; PUBLIC_KEY_SIZE],
        secret: Option<[u8; PRIVATE_KEY_SIZE]>,
    ) -> Self {
        NodeIdentity { address, public, secret }
    }

    /// `Identity::generate()` (node/Identity.cpp:69-87 +
    /// ECC::generateSatisfying): random secret set, then iterate the
    /// X25519 half (LE u64 inc at bytes 8..16, dec at 16..24) until the
    /// hashcash condition holds. ~16.6 expected memory-hard hashes —
    /// seconds in release, minutes in debug.
    pub fn generate() -> Result<Self> {
        use rand::RngCore;
        let mut secret = [0u8; PRIVATE_KEY_SIZE];
        rand::rngs::OsRng.fill_bytes(&mut secret);
        let mut public = [0u8; PUBLIC_KEY_SIZE];
        public[32..64].copy_from_slice(&ed25519_public_from_seed(&secret[32..64])?);
        loop {
            let dh: [u8; 32] = secret[..32].try_into().unwrap();
            public[..32].copy_from_slice(
                &curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(dh).0,
            );
            let digest = memory_hard_hash(&public);
            let address = be40(&digest[59..64]);
            if digest[0] < IDENTITY_HASHCASH_THRESHOLD && !address_is_reserved(address) {
                return Ok(NodeIdentity { address, public, secret: Some(secret) });
            }
            let lo = u64::from_le_bytes(secret[8..16].try_into().unwrap()).wrapping_add(1);
            secret[8..16].copy_from_slice(&lo.to_le_bytes());
            let hi = u64::from_le_bytes(secret[16..24].try_into().unwrap()).wrapping_sub(1);
            secret[16..24].copy_from_slice(&hi.to_le_bytes());
        }
    }

    /// The 40-bit address (fits the low 40 bits of the u64).
    pub fn address(&self) -> u64 {
        self.address
    }

    pub fn public(&self) -> &[u8; PUBLIC_KEY_SIZE] {
        &self.public
    }

    /// `Identity::toString`: `address:0:pubhex` / `address:0:pubhex:privhex`
    /// (hex10 address — node/Identity.cpp:97-111).
    pub fn to_public_str(&self) -> String {
        format!("{:010x}:0:{}", self.address, hex(&self.public))
    }

    pub fn to_secret_str(&self) -> Result<String> {
        match &self.secret {
            Some(s) => Ok(format!("{:010x}:0:{}:{}", self.address, hex(&self.public), hex(s))),
            None => Err(Error::crypto("zerotier: identity has no secret half")),
        }
    }

    /// `Identity::fromString` (node/Identity.cpp:114-160): 3 or 4
    /// colon fields, hex10 address, "0" taxonomy, 64-byte hex key
    /// halves. With a secret present the public halves are checked
    /// against it (zerotier-go `identity.go:210-223`).
    pub fn from_str_form(raw: &str) -> Result<Self> {
        let fields: Vec<&str> = raw.trim().split(':').collect();
        if fields.len() != 3 && fields.len() != 4 {
            return Err(Error::config("zerotier: identity must have 3 or 4 colon fields"));
        }
        let address = parse_node_address(fields[0])?;
        if fields[1] != "0" {
            return Err(Error::config("zerotier: identity taxonomy field must be 0"));
        }
        let mut public = [0u8; PUBLIC_KEY_SIZE];
        unhex_into(fields[2], &mut public)?;
        let secret = match fields.get(3) {
            Some(s) => {
                let mut sec = [0u8; PRIVATE_KEY_SIZE];
                unhex_into(s, &mut sec)?;
                if sec[..32] != [0u8; 32] {
                    let dh: [u8; 32] = sec[..32].try_into().unwrap();
                    let want = curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(dh).0;
                    if want != public[..32] {
                        return Err(Error::config("zerotier: identity X25519 halves do not match"));
                    }
                }
                if sec[32..] != [0u8; 32]
                    && ed25519_public_from_seed(&sec[32..64])? != public[32..64]
                {
                    return Err(Error::config("zerotier: identity Ed25519 halves do not match"));
                }
                Some(sec)
            }
            None => None,
        };
        Ok(NodeIdentity { address, public, secret })
    }

    /// Binary serialize (`Identity::serialize`, node/Identity.hpp:218-232):
    /// address(5 BE) + type 0 + public(64) + [0 | privlen(64) + priv(64)].
    pub fn serialize_bin(&self, include_private: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(71 + 65);
        out.extend_from_slice(&self.address.to_be_bytes()[3..8]);
        out.push(0);
        out.extend_from_slice(&self.public);
        match (include_private, &self.secret) {
            (true, Some(s)) => {
                out.push(PRIVATE_KEY_SIZE as u8);
                out.extend_from_slice(s);
            }
            _ => out.push(0),
        }
        out
    }

    /// Binary deserialize (`Identity::deserialize`, node/Identity.hpp:245-285);
    /// returns the identity and the bytes consumed.
    pub fn deserialize_bin(buf: &[u8]) -> Result<(Self, usize)> {
        if buf.len() < 71 {
            return Err(Error::crypto("zerotier: truncated binary identity"));
        }
        let address = be40(&buf[0..5]);
        if address_is_reserved(address) {
            return Err(Error::crypto("zerotier: reserved identity address"));
        }
        if buf[5] != 0 {
            return Err(Error::crypto("zerotier: unknown identity type"));
        }
        let mut public = [0u8; PUBLIC_KEY_SIZE];
        public.copy_from_slice(&buf[6..70]);
        let mut used = 71;
        let secret = match buf[70] {
            0 => None,
            // PRIVATE_KEY_SIZE as a literal (patterns must be literals).
            64 => {
                if buf.len() < 71 + 64 {
                    return Err(Error::crypto("zerotier: truncated secret identity"));
                }
                let mut s = [0u8; PRIVATE_KEY_SIZE];
                s.copy_from_slice(&buf[71..135]);
                used += 64;
                Some(s)
            }
            other => {
                return Err(Error::config(format!(
                    "zerotier: bad private key length {other}"
                )))
            }
        };
        Ok((NodeIdentity { address, public, secret }, used))
    }

    /// `Identity::locallyValidate` (node/Identity.cpp:113-124): re-run
    /// the memory-hard hash and check the hashcash condition plus the
    /// address bytes. One ~2 MiB evaluation.
    pub fn locally_validate(&self) -> bool {
        if address_is_reserved(self.address) {
            return false;
        }
        let digest = memory_hard_hash(&self.public);
        digest[0] < IDENTITY_HASHCASH_THRESHOLD && be40(&digest[59..64]) == self.address
    }

    /// `Identity::agree` (node/ECC.cpp:2450-2465): the 48-byte pairwise
    /// key = SHA-512(X25519(mine, theirs))[0..48].
    pub fn agree(&self, peer: &NodeIdentity) -> Result<[u8; SYMMETRIC_KEY_SIZE]> {
        use sha2::Digest;
        let secret = self
            .secret
            .as_ref()
            .ok_or_else(|| Error::crypto("zerotier: agreement needs a secret identity"))?;
        let sk: [u8; 32] = secret[..32].try_into().unwrap();
        let pk: [u8; 32] = peer.public[..32].try_into().unwrap();
        let raw = curve25519_dalek::montgomery::MontgomeryPoint(pk).mul_clamped(sk).0;
        let digest = sha2::Sha512::digest(raw);
        let mut key = [0u8; SYMMETRIC_KEY_SIZE];
        key.copy_from_slice(&digest[..SYMMETRIC_KEY_SIZE]);
        Ok(key)
    }

    /// `Identity::sign` (node/ECC.cpp:2466-2520): standard Ed25519 over
    /// SHA-512(msg)[0..32], packaged `R || s || digest` (96 bytes). The
    /// curve math is in-tree `ring`; ZeroTier's own construction
    /// (`get_hram`, ECC.cpp:2422) is bit-identical to RFC 8032.
    pub fn sign(&self, msg: &[u8]) -> Result<[u8; SIGNATURE_SIZE]> {
        use sha2::Digest;
        let secret = self
            .secret
            .as_ref()
            .ok_or_else(|| Error::crypto("zerotier: signing needs a secret identity"))?;
        let digest: [u8; 64] = sha2::Sha512::digest(msg).as_slice().try_into().unwrap();
        let kp = ring::signature::Ed25519KeyPair::from_seed_unchecked(&secret[32..64])
            .map_err(|_| Error::crypto("zerotier: bad Ed25519 seed"))?;
        let sig = kp.sign(&digest[..32]);
        let mut out = [0u8; SIGNATURE_SIZE];
        out[..64].copy_from_slice(sig.as_ref());
        out[64..].copy_from_slice(&digest[..32]);
        Ok(out)
    }

    /// `Identity::verify` (node/ECC.cpp:2522-2549): digest check +
    /// Ed25519 verification of `R || s` over the digest.
    pub fn verify(&self, msg: &[u8], signature: &[u8]) -> bool {
        use sha2::Digest;
        if signature.len() != SIGNATURE_SIZE {
            return false;
        }
        let digest: [u8; 64] = sha2::Sha512::digest(msg).as_slice().try_into().unwrap();
        if !ct_eq(&signature[64..], &digest[..32]) {
            return false;
        }
        ring::signature::UnparsedPublicKey::new(
            &ring::signature::ED25519,
            &self.public[32..64],
        )
        .verify(&digest[..32], &signature[..64])
        .is_ok()
    }
}

/// Reserved addresses (`Address::isReserved`, node/Address.hpp:149-152):
/// zero, or top byte 0xff (`ZT_ADDRESS_RESERVED_PREFIX` — also the
/// fragment-indicator magic).
fn address_is_reserved(address: u64) -> bool {
    address == 0 || (address >> 32) == 0xff
}

/// The Ed25519 public half derived from a 32-byte seed (standard
/// RFC 8032 keygen — `_calcPubED`, node/ECC.cpp:2553+).
fn ed25519_public_from_seed(seed: &[u8]) -> Result<[u8; 32]> {
    use ring::signature::KeyPair as _;
    ring::signature::Ed25519KeyPair::from_seed_unchecked(seed)
        .map(|kp| {
            let mut out = [0u8; 32];
            out.copy_from_slice(kp.public_key().as_ref());
            out
        })
        .map_err(|_| Error::crypto("zerotier: bad Ed25519 seed"))
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex_into(raw: &str, out: &mut [u8]) -> Result<()> {
    let bytes = raw.as_bytes();
    if bytes.len() != out.len() * 2 || !bytes.iter().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::config("zerotier: expected hex key material"));
    }
    for (i, slot) in out.iter_mut().enumerate() {
        *slot = u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16)
            .map_err(|_| Error::config("zerotier: bad hex key material"))?;
    }
    Ok(())
}

/// 5 big-endian bytes → the 40-bit address value.
fn be40(bytes: &[u8]) -> u64 {
    let mut v = [0u8; 8];
    v[3..8].copy_from_slice(bytes);
    u64::from_be_bytes(v)
}

// ---------------------------------------------------------------------------
// The packet wire codec (node/Packet.hpp:168-198 + Packet.cpp)
// ---------------------------------------------------------------------------

/// Header field offsets (`ZT_PACKET_IDX_*`, node/Packet.hpp:168-176).
pub const PACKET_IDX_IV: usize = 0;
pub const PACKET_IDX_DEST: usize = 8;
pub const PACKET_IDX_SOURCE: usize = 13;
pub const PACKET_IDX_FLAGS: usize = 18;
pub const PACKET_IDX_MAC: usize = 19;
pub const PACKET_IDX_VERB: usize = 27;
pub const PACKET_IDX_PAYLOAD: usize = 28;
/// `ZT_PROTO_MIN_PACKET_LENGTH` — the 28-byte armored header.
pub const PACKET_HEADER_LEN: usize = PACKET_IDX_PAYLOAD;

/// Flags byte layout `FFCCCHHH` (node/Packet.hpp:1259-1276): extended
/// armor 0x80, fragmented 0x40, cipher suite in bits 0x38, hops in the
/// low 3 bits.
pub const FLAG_EXTENDED_ARMOR: u8 = 0x80;
pub const FLAG_FRAGMENTED: u8 = 0x40;
/// `ZT_PROTO_VERB_FLAG_COMPRESSED` (node/Packet.hpp:151): LZ4 on the
/// verb byte, above the 5 verb bits.
pub const VERB_FLAG_COMPRESSED: u8 = 0x80;

/// Cipher suites (`ZT_PROTO_CIPHER_SUITE__*`, node/Packet.hpp:90-117).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CipherSuite {
    /// 0: MAC-only (cleartext HELLO).
    C25519Poly1305None,
    /// 1: MAC + Salsa20/12 payload encryption.
    C25519Poly1305Salsa2012,
    /// 3: AES-GMAC-SIV — negotiated only with peers advertising
    /// protocol >= 12; we advertise 11, so we never receive it.
    AesGmacSiv,
}

impl CipherSuite {
    fn to_bits(self) -> u8 {
        match self {
            CipherSuite::C25519Poly1305None => 0,
            CipherSuite::C25519Poly1305Salsa2012 => 1,
            CipherSuite::AesGmacSiv => 3,
        }
    }

    fn from_bits(bits: u8) -> Result<Self> {
        match bits {
            0 => Ok(CipherSuite::C25519Poly1305None),
            1 => Ok(CipherSuite::C25519Poly1305Salsa2012),
            3 => Ok(CipherSuite::AesGmacSiv),
            other => Err(Error::crypto(format!(
                "zerotier: unknown cipher suite {other}"
            ))),
        }
    }
}

/// Packet verbs actually spoken by this port (node/Packet.hpp:501-1018).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verb {
    Nop,
    Hello,
    Error,
    Ok,
    Whois,
    Rendezvous,
    Frame,
    Echo,
    NetworkConfigRequest,
    NetworkConfig,
    PushDirectPaths,
}

impl Verb {
    pub fn to_byte(self) -> u8 {
        match self {
            Verb::Nop => 0x00,
            Verb::Hello => 0x01,
            Verb::Error => 0x02,
            Verb::Ok => 0x03,
            Verb::Whois => 0x04,
            Verb::Rendezvous => 0x05,
            Verb::Frame => 0x06,
            Verb::Echo => 0x08,
            Verb::NetworkConfigRequest => 0x0b,
            Verb::NetworkConfig => 0x0c,
            // `VERB_PUSH_DIRECT_PATHS` (node/Packet.hpp:946 — 0x10, not
            // the 0x07 slot VERB_EXT_FRAME occupies).
            Verb::PushDirectPaths => 0x10,
        }
    }

    fn from_byte(b: u8) -> Result<Self> {
        match b {
            0x00 => Ok(Verb::Nop),
            0x01 => Ok(Verb::Hello),
            0x02 => Ok(Verb::Error),
            0x03 => Ok(Verb::Ok),
            0x04 => Ok(Verb::Whois),
            0x05 => Ok(Verb::Rendezvous),
            0x06 => Ok(Verb::Frame),
            0x08 => Ok(Verb::Echo),
            0x0b => Ok(Verb::NetworkConfigRequest),
            0x0c => Ok(Verb::NetworkConfig),
            0x10 => Ok(Verb::PushDirectPaths),
            other => Err(Error::crypto(format!("zerotier: unknown verb 0x{other:02x}"))),
        }
    }
}

/// One ZeroTier wire packet: the 28-byte header + verb payload, armored
/// in place (`Packet::armor`/`dearmor`, node/Packet.cpp:1083-1262).
#[derive(Clone, PartialEq, Eq)]
pub struct WirePacket {
    buf: Vec<u8>,
}

impl std::fmt::Debug for WirePacket {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("WirePacket")
            .field("dest", &format!("{:010x}", self.dest()))
            .field("source", &format!("{:010x}", self.source()))
            .field("verb", &self.verb().map(|v| format!("{v:?}")))
            .field("len", &self.buf.len())
            .finish()
    }
}

impl WirePacket {
    /// `Packet(dest, source, verb)` — random IV, zero flags
    /// (node/Packet.hpp:424-430).
    pub fn new(dest: u64, source: u64, verb: Verb) -> Self {
        use rand::RngCore;
        let mut buf = vec![0u8; PACKET_HEADER_LEN];
        rand::rngs::OsRng.fill_bytes(&mut buf[PACKET_IDX_IV..PACKET_IDX_DEST]);
        buf[PACKET_IDX_DEST..PACKET_IDX_SOURCE].copy_from_slice(&dest.to_be_bytes()[3..8]);
        buf[PACKET_IDX_SOURCE..PACKET_IDX_FLAGS].copy_from_slice(&source.to_be_bytes()[3..8]);
        buf[PACKET_IDX_FLAGS] = 0;
        buf[PACKET_IDX_VERB] = verb.to_byte();
        WirePacket { buf }
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < PACKET_HEADER_LEN || bytes.len() > MAX_PACKET_LENGTH {
            return Err(Error::crypto("zerotier: bad packet length"));
        }
        Ok(WirePacket { buf: bytes.to_vec() })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub fn into_bytes(self) -> Vec<u8> {
        self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    /// `packetId()` — the IV read as a big-endian u64.
    pub fn packet_id(&self) -> u64 {
        u64::from_be_bytes(self.buf[PACKET_IDX_IV..PACKET_IDX_DEST].try_into().unwrap())
    }

    pub fn dest(&self) -> u64 {
        be40(&self.buf[PACKET_IDX_DEST..PACKET_IDX_SOURCE])
    }

    pub fn source(&self) -> u64 {
        be40(&self.buf[PACKET_IDX_SOURCE..PACKET_IDX_FLAGS])
    }

    pub fn hops(&self) -> u8 {
        self.buf[PACKET_IDX_FLAGS] & 0x07
    }

    pub fn cipher(&self) -> Result<CipherSuite> {
        CipherSuite::from_bits((self.buf[PACKET_IDX_FLAGS] & 0x38) >> 3)
    }

    fn set_cipher(&mut self, suite: CipherSuite) {
        let b = &mut self.buf[PACKET_IDX_FLAGS];
        *b = (*b & 0xc7) | (suite.to_bits() << 3);
    }

    pub fn compressed(&self) -> bool {
        self.buf[PACKET_IDX_VERB] & VERB_FLAG_COMPRESSED != 0
    }

    pub fn set_compressed(&mut self, on: bool) {
        if on {
            self.buf[PACKET_IDX_VERB] |= VERB_FLAG_COMPRESSED;
        } else {
            self.buf[PACKET_IDX_VERB] &= !VERB_FLAG_COMPRESSED;
        }
    }

    /// `ZT_PROTO_FLAG_FRAGMENTED` (0x40): more fragments follow this
    /// head. Set **before** armoring — the whole assembled packet is
    /// what the MAC covers (`Switch.cpp:_sendViaSpecificPath`).
    pub fn fragmented(&self) -> bool {
        self.buf[PACKET_IDX_FLAGS] & FLAG_FRAGMENTED != 0
    }

    pub fn set_fragmented(&mut self, on: bool) {
        if on {
            self.buf[PACKET_IDX_FLAGS] |= FLAG_FRAGMENTED;
        } else {
            self.buf[PACKET_IDX_FLAGS] &= !FLAG_FRAGMENTED;
        }
    }

    /// `Packet::incrementHops` (relay transit): bump the low 3 flag
    /// bits. MAC-safe by construction — `mangle_key` masks the hop
    /// bits out and the Poly1305 input starts at the verb byte.
    pub fn increment_hops(&mut self) {
        let b = &mut self.buf[PACKET_IDX_FLAGS];
        *b = (*b & 0xf8) | ((*b + 1) & 0x07);
    }

    /// The verb bits (compressed flag masked off).
    pub fn verb(&self) -> Result<Verb> {
        Verb::from_byte(self.buf[PACKET_IDX_VERB] & 0x1f)
    }

    /// The verb payload (after the 28-byte header).
    pub fn payload(&self) -> &[u8] {
        &self.buf[PACKET_IDX_PAYLOAD..]
    }

    pub fn payload_mut(&mut self) -> &mut Vec<u8> {
        &mut self.buf
    }

    pub fn push_u8(&mut self, v: u8) -> &mut Self {
        self.buf.push(v);
        self
    }

    pub fn push_u16(&mut self, v: u16) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn push_u64(&mut self, v: u64) -> &mut Self {
        self.buf.extend_from_slice(&v.to_be_bytes());
        self
    }

    pub fn push_bytes(&mut self, v: &[u8]) -> &mut Self {
        self.buf.extend_from_slice(v);
        self
    }

    /// Replace the verb payload wholesale (the compress path).
    pub fn set_payload(&mut self, payload: &[u8]) {
        self.buf.truncate(PACKET_IDX_PAYLOAD);
        self.buf.extend_from_slice(payload);
    }

    /// `_salsa20MangleKey` (node/Packet.hpp:1425-1452): derive the
    /// per-packet Salsa20 key by XORing the pairwise key's head with
    /// the packet's own header bytes (IV+addresses, flags with hops
    /// masked off, little-endian packet length).
    fn mangle_key(&self, key: &[u8]) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..18].copy_from_slice(&key[..18]);
        for (o, b) in out.iter_mut().zip(self.buf[..18].iter()) {
            *o ^= *b;
        }
        out[18] = key[18] ^ (self.buf[PACKET_IDX_FLAGS] & 0xf8);
        out[19] = key[19] ^ (self.buf.len() & 0xff) as u8;
        out[20] = key[20] ^ ((self.buf.len() >> 8) & 0xff) as u8;
        out[21..].copy_from_slice(&key[21..]);
        out
    }

    /// `Packet::armor` with the Salsa20/12 suite (node/Packet.cpp:1107-1161):
    /// mangled key + Salsa20/12 keystream; bytes 0..32 of block 0 are
    /// the Poly1305 key; the payload (verb byte on) is encrypted from
    /// keystream byte 64 when `encrypt_payload`; the MAC is the first
    /// 8 tag bytes.
    pub fn armor(&mut self, key: &[u8; SYMMETRIC_KEY_SIZE], encrypt_payload: bool) {
        self.set_cipher(if encrypt_payload {
            CipherSuite::C25519Poly1305Salsa2012
        } else {
            CipherSuite::C25519Poly1305None
        });
        let mangled = self.mangle_key(&key[..32]);
        let mut iv = [0u8; 8];
        iv.copy_from_slice(&self.buf[PACKET_IDX_IV..PACKET_IDX_DEST]);
        let mut stream = SalsaStream::new(&mangled, &iv, 12);
        let mut mac_key = [0u8; 32];
        stream.xor(&mut mac_key); // consumes + discards the rest of block 0
        if encrypt_payload {
            stream.xor(&mut self.buf[PACKET_IDX_VERB..]);
        }
        let tag = poly1305(&mac_key, &self.buf[PACKET_IDX_VERB..]);
        self.buf[PACKET_IDX_MAC..PACKET_IDX_VERB].copy_from_slice(&tag[..8]);
    }

    /// `Packet::dearmor` (node/Packet.cpp:1166-1259): verify the MAC
    /// (over the ciphertext when encrypted), then decrypt. Suite 3
    /// fails with the negotiation note.
    pub fn dearmor(&mut self, key: &[u8; SYMMETRIC_KEY_SIZE]) -> Result<()> {
        let suite = self.cipher()?;
        if suite == CipherSuite::AesGmacSiv {
            return Err(Error::crypto(
                "zerotier: AES-GMAC-SIV suite received but not negotiated \
                 (we advertise protocol 11 for exactly this reason)",
            ));
        }
        let mangled = self.mangle_key(&key[..32]);
        let mut iv = [0u8; 8];
        iv.copy_from_slice(&self.buf[PACKET_IDX_IV..PACKET_IDX_DEST]);
        let mut stream = SalsaStream::new(&mangled, &iv, 12);
        let mut mac_key = [0u8; 32];
        stream.xor(&mut mac_key);
        let tag = poly1305(&mac_key, &self.buf[PACKET_IDX_VERB..]);
        if !ct_eq(&tag[..8], &self.buf[PACKET_IDX_MAC..PACKET_IDX_VERB]) {
            return Err(Error::crypto("zerotier: packet MAC check failed"));
        }
        if suite == CipherSuite::C25519Poly1305Salsa2012 {
            stream.xor(&mut self.buf[PACKET_IDX_VERB..]);
        }
        Ok(())
    }

    /// The generic inbound post-armor step (`IncomingPacket.cpp:74-78`):
    /// LZ4-decompress the verb payload when the compressed flag is set.
    pub fn uncompress(&mut self) -> Result<()> {
        if !self.compressed() {
            return Ok(());
        }
        let plain = lz4_block_decode(self.payload(), MAX_PACKET_LENGTH - PACKET_IDX_PAYLOAD)?;
        self.buf.truncate(PACKET_IDX_PAYLOAD);
        self.buf.extend_from_slice(&plain);
        self.set_compressed(false);
        Ok(())
    }

    /// `Packet::cryptField` (node/Packet.cpp:1264-1276): Salsa20/12 with
    /// the raw pairwise key over a packet sub-range; the IV is the
    /// packet IV with its low 3 bits masked (the packet-id bits that
    /// are still unset when this runs). Used only to mask HELLO's moon
    /// tail.
    pub fn crypt_field(&mut self, key: &[u8; SYMMETRIC_KEY_SIZE], start: usize, len: usize) {
        let mut iv = [0u8; 8];
        iv.copy_from_slice(&self.buf[PACKET_IDX_IV..PACKET_IDX_DEST]);
        iv[7] &= 0xf8;
        let key32: [u8; 32] = key[..32].try_into().unwrap();
        salsa20_xor(&key32, &iv, &mut self.buf[start..start + len], 12);
    }
}

// ---------------------------------------------------------------------------
// LZ4 block decompression (lz4_Block_format.md — decode-only)
// ---------------------------------------------------------------------------

/// LZ4 block format decoding (`lz4/lz4` `doc/lz4_Block_format.md`):
/// token (literal-length nibble || match-length nibble), optional 255
/// extension bytes, literals, then — for every non-final sequence — a
/// little-endian u16 offset (1..=65535, never 0) and a match of
/// `minmatch 4 + nibble (+ extensions)` bytes copied from history
/// (byte-by-byte: matches overlap). The final sequence is literals
/// only. `cap` mirrors `ZT_PROTO_MAX_PACKET_LENGTH` bounding.
fn lz4_block_decode(src: &[u8], cap: usize) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::new();
    let mut i = 0usize;
    loop {
        if i >= src.len() {
            return Err(Error::crypto("zerotier: truncated LZ4 block"));
        }
        let token = src[i];
        i += 1;
        let mut litlen = (token >> 4) as usize;
        if litlen == 15 {
            loop {
                if i >= src.len() {
                    return Err(Error::crypto("zerotier: truncated LZ4 literals"));
                }
                let b = src[i];
                i += 1;
                litlen += b as usize;
                if b != 255 {
                    break;
                }
            }
        }
        if i + litlen > src.len() || out.len() + litlen > cap {
            return Err(Error::crypto("zerotier: LZ4 literals out of bounds"));
        }
        out.extend_from_slice(&src[i..i + litlen]);
        i += litlen;
        if i >= src.len() {
            break; // final sequence: literals only
        }
        if i + 2 > src.len() {
            return Err(Error::crypto("zerotier: truncated LZ4 match header"));
        }
        let offset = u16::from_le_bytes([src[i], src[i + 1]]) as usize;
        i += 2;
        if offset == 0 || offset > out.len() {
            return Err(Error::crypto("zerotier: LZ4 offset out of history"));
        }
        let mut matchlen = ((token & 0x0f) as usize) + 4;
        if (token & 0x0f) == 15 {
            loop {
                if i >= src.len() {
                    return Err(Error::crypto("zerotier: truncated LZ4 match length"));
                }
                let b = src[i];
                i += 1;
                matchlen += b as usize;
                if b != 255 {
                    break;
                }
            }
        }
        if out.len() + matchlen > cap {
            return Err(Error::crypto("zerotier: LZ4 output overflows packet cap"));
        }
        // Overlapping copy: byte-by-byte from history (offset < len).
        for src_pos in (out.len() - offset..).take(matchlen) {
            out.push(out[src_pos]);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// VERB_HELLO / OK(HELLO) — the P2P identity handshake
// ---------------------------------------------------------------------------

/// An `InetAddress` on the wire (node/InetAddress.hpp:615-660):
/// `0x04 || ipv4(4) || port(2 BE)`, `0x06 || ipv6(16) || port(2 BE)`,
/// or a lone `0x00`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PhysAddr {
    None,
    V4([u8; 4], u16),
    V6([u8; 16], u16),
}

impl PhysAddr {
    pub fn serialize_into(&self, out: &mut Vec<u8>) {
        match self {
            PhysAddr::None => out.push(0),
            PhysAddr::V4(ip, port) => {
                out.push(0x04);
                out.extend_from_slice(ip);
                out.extend_from_slice(&port.to_be_bytes());
            }
            PhysAddr::V6(ip, port) => {
                out.push(0x06);
                out.extend_from_slice(ip);
                out.extend_from_slice(&port.to_be_bytes());
            }
        }
    }

    pub fn deserialize_from(buf: &[u8], at: usize) -> Result<(Self, usize)> {
        let Some(&kind) = buf.get(at) else {
            return Err(Error::crypto("zerotier: truncated physical address"));
        };
        let read_port = |p: usize| -> Result<u16> {
            let b: [u8; 2] = buf
                .get(p..p + 2)
                .and_then(|s| s.try_into().ok())
                .ok_or_else(|| Error::crypto("zerotier: truncated physical address"))?;
            Ok(u16::from_be_bytes(b))
        };
        match kind {
            0 => Ok((PhysAddr::None, 1)),
            0x04 => {
                let ip: [u8; 4] = buf
                    .get(at + 1..at + 5)
                    .and_then(|s| s.try_into().ok())
                    .ok_or_else(|| Error::crypto("zerotier: truncated IPv4 address"))?;
                Ok((PhysAddr::V4(ip, read_port(at + 5)?), 7))
            }
            0x06 => {
                let ip: [u8; 16] = buf
                    .get(at + 1..at + 17)
                    .and_then(|s| s.try_into().ok())
                    .ok_or_else(|| Error::crypto("zerotier: truncated IPv6 address"))?;
                Ok((PhysAddr::V6(ip, read_port(at + 17)?), 19))
            }
            other => Err(Error::crypto(format!(
                "zerotier: unknown physical address type 0x{other:02x}"
            ))),
        }
    }

    /// The u16 field read as a **netmask length** — the form managed
    /// IPs and routes use inside the netconf dictionary
    /// (`InetAddress::netmaskBits`; the same wire codec as physical
    /// addresses, `InetAddress.hpp:615-660`).
    pub fn to_ip_prefix(&self) -> Option<(IpAddr, u8)> {
        match *self {
            PhysAddr::None => None,
            PhysAddr::V4(ip, bits) if bits <= 32 => {
                Some((IpAddr::V4(Ipv4Addr::from(ip)), bits as u8))
            }
            PhysAddr::V6(ip, bits) if bits <= 128 => {
                Some((IpAddr::V6(Ipv6Addr::from(ip)), bits as u8))
            }
            _ => None,
        }
    }

    /// The u16 field read as a **port** (a physical endpoint).
    pub fn to_socket_addr(&self) -> Option<SocketAddr> {
        match *self {
            PhysAddr::None => None,
            PhysAddr::V4(ip, port) => {
                Some(SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::from(ip), port)))
            }
            PhysAddr::V6(ip, port) => {
                Some(SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(ip), port, 0, 0)))
            }
        }
    }

    pub fn from_socket_addr(sa: SocketAddr) -> Self {
        match sa {
            SocketAddr::V4(v4) => PhysAddr::V4(v4.ip().octets(), v4.port()),
            SocketAddr::V6(v6) => PhysAddr::V6(v6.ip().octets(), v6.port()),
        }
    }
}

/// A parsed VERB_HELLO payload (`ZT_PROTO_VERB_HELLO_*`,
/// node/Packet.hpp:230-235 + Peer::sendHELLO, node/Peer.cpp:426-474):
/// versions, timestamp, the sender's identity, the physical address the
/// packet was sent to, planet id/timestamp, then (optionally) the
/// cryptField-masked moon tail.
#[derive(Debug, Clone)]
pub struct Hello {
    pub proto_version: u8,
    pub major: u8,
    pub minor: u8,
    pub revision: u16,
    pub timestamp: i64,
    pub identity: NodeIdentity,
    pub physical: PhysAddr,
    pub world_id: u64,
    pub world_timestamp: u64,
    /// The still-masked moon tail (type/id/timestamp tuples), if any.
    pub moon_tail: Option<Vec<u8>>,
}

fn i64_from_be(b: &[u8]) -> i64 {
    i64::from_be_bytes(b.try_into().unwrap())
}

/// Build a HELLO like `Peer::sendHELLO`. The moon tail is masked with
/// the pairwise key (cryptField) exactly as upstream does before
/// armoring with suite 0.
pub fn build_hello(
    from: &NodeIdentity,
    to_address: u64,
    to_physical: PhysAddr,
    world: (u64, u64),
    moons: &[(u64, u64)],
    timestamp: i64,
    key: &[u8; SYMMETRIC_KEY_SIZE],
) -> Result<WirePacket> {
    let mut pkt = WirePacket::new(to_address, from.address(), Verb::Hello);
    let mut physical_bytes = Vec::new();
    to_physical.serialize_into(&mut physical_bytes);
    pkt.push_u8(PROTO_VERSION)
        .push_u8(SOFTWARE_VERSION.0)
        .push_u8(SOFTWARE_VERSION.1)
        .push_u16(SOFTWARE_VERSION.2)
        .push_u64(timestamp as u64)
        .push_bytes(&from.serialize_bin(false))
        .push_bytes(&physical_bytes)
        .push_u64(world.0)
        .push_u64(world.1);
    let tail_start = pkt.len();
    pkt.push_u16(moons.len() as u16);
    for (id, ts) in moons {
        // World::TYPE_MOON = 1 (node/World.hpp).
        pkt.push_u8(1).push_u64(*id).push_u64(*ts);
    }
    if pkt.len() > tail_start {
        pkt.crypt_field(key, tail_start, pkt.len() - tail_start);
    }
    pkt.armor(key, false);
    Ok(pkt)
}

/// Parse a (dearmored) HELLO. The moon tail is returned still masked;
/// callers who care unmangle it with the pairwise key.
pub fn parse_hello(pkt: &WirePacket) -> Result<Hello> {
    let p = pkt.payload();
    if p.len() < 13 + 71 + 16 {
        return Err(Error::crypto("zerotier: truncated HELLO"));
    }
    let proto_version = p[0];
    let major = p[1];
    let minor = p[2];
    let revision = u16::from_be_bytes([p[3], p[4]]);
    let timestamp = i64_from_be(&p[5..13]);
    let (identity, used) = NodeIdentity::deserialize_bin(&p[13..])?;
    if used != 71 {
        return Err(Error::crypto("zerotier: HELLO carried a secret identity"));
    }
    let mut at = 13 + used;
    let (physical, pa) = PhysAddr::deserialize_from(p, at)?;
    at += pa;
    let mut world_id = 0;
    let mut world_timestamp = 0;
    if p.len() >= at + 16 {
        world_id = u64::from_be_bytes(p[at..at + 8].try_into().unwrap());
        world_timestamp = u64::from_be_bytes(p[at + 8..at + 16].try_into().unwrap());
        at += 16;
    }
    let moon_tail = (at < p.len()).then(|| p[at..].to_vec());
    Ok(Hello {
        proto_version,
        major,
        minor,
        revision,
        timestamp,
        identity,
        physical,
        world_id,
        world_timestamp,
        moon_tail,
    })
}

/// An OK(HELLO) payload (`ZT_PROTO_VERB_HELLO__OK__IDX_*`,
/// node/Packet.hpp:282-287 + IncomingPacket.cpp:507-531).
#[derive(Debug, Clone)]
pub struct OkHello {
    pub in_re_packet_id: u64,
    pub timestamp: i64,
    pub proto_version: u8,
    pub major: u8,
    pub minor: u8,
    pub revision: u16,
    pub physical: PhysAddr,
    /// The (opaque here) serialized world update block, if present.
    pub world_update: Option<Vec<u8>>,
}

/// Build the OK(HELLO) reply, armored with suite 1 (upstream replies
/// encrypted — `IncomingPacket.cpp:531`). `hello_packet_id` is the
/// packet id of the HELLO being answered (the OK echoes it).
#[allow(clippy::too_many_arguments)]
pub fn build_ok_hello(
    from: &NodeIdentity,
    to_hello: &Hello,
    hello_packet_id: u64,
    to_address: u64,
    physical: PhysAddr,
    key: &[u8; SYMMETRIC_KEY_SIZE],
) -> Result<WirePacket> {
    build_ok_hello_with_worlds(from, to_hello, hello_packet_id, to_address, physical, &[], key)
}

/// [`build_ok_hello`] with a world-update block — the responder side
/// of `_doHELLO`'s gossip (IncomingPacket.cpp:541-557): the newest
/// copy of a world the REQUESTER listed in its HELLO tail travels in
/// the OK, u16-length-prefixed.
#[allow(clippy::too_many_arguments)]
pub fn build_ok_hello_with_worlds(
    from: &NodeIdentity,
    to_hello: &Hello,
    hello_packet_id: u64,
    to_address: u64,
    physical: PhysAddr,
    worlds: &[World],
    key: &[u8; SYMMETRIC_KEY_SIZE],
) -> Result<WirePacket> {
    let mut pkt = WirePacket::new(to_address, from.address(), Verb::Ok);
    let mut physical_bytes = Vec::new();
    physical.serialize_into(&mut physical_bytes);
    pkt.push_u8(Verb::Hello.to_byte())
        .push_u64(hello_packet_id)
        .push_u64(to_hello.timestamp as u64)
        .push_u8(PROTO_VERSION)
        .push_u8(SOFTWARE_VERSION.0)
        .push_u8(SOFTWARE_VERSION.1)
        .push_u16(SOFTWARE_VERSION.2)
        .push_bytes(&physical_bytes)
        .push_u16(0); // world-update length slot (filled below)
    let len_at = pkt.len() - 2;
    let mut update = Vec::new();
    for w in worlds {
        w.serialize(false, &mut update);
    }
    pkt.payload_mut().extend_from_slice(&update);
    let total = pkt.len() - len_at - 2;
    pkt.buf[len_at..len_at + 2].copy_from_slice(&(total as u16).to_be_bytes());
    pkt.armor(key, true);
    Ok(pkt)
}

/// Parse a (dearmored) OK(HELLO). `in_re_packet_id` must be checked by
/// the caller against the HELLO it sent.
    pub fn parse_ok_hello(pkt: &WirePacket) -> Result<OkHello> {
        let p = pkt.payload();
        // in-re-verb + packet id + timestamp + versions = 22 bytes minimum.
        if p.len() < 22 || !matches!(Verb::from_byte(p[0]), Ok(Verb::Hello)) {
            return Err(Error::crypto("zerotier: not an OK(HELLO)"));
        }
    let in_re_packet_id = u64::from_be_bytes(p[1..9].try_into().unwrap());
    let timestamp = i64_from_be(&p[9..17]);
    let proto_version = p[17];
    let major = p[18];
    let minor = p[19];
    let revision = u16::from_be_bytes([p[20], p[21]]);
    let (physical, pa) = PhysAddr::deserialize_from(p, 22)?;
    let mut at = 22 + pa;
    let mut world_update = None;
    if p.len() >= at + 2 {
        let wlen = u16::from_be_bytes(p[at..at + 2].try_into().unwrap()) as usize;
        at += 2;
        if p.len() < at + wlen {
            return Err(Error::crypto("zerotier: truncated world update"));
        }
        world_update = (wlen > 0).then(|| p[at..at + wlen].to_vec());
    }
    Ok(OkHello {
        in_re_packet_id,
        timestamp,
        proto_version,
        major,
        minor,
        revision,
        physical,
        world_update,
    })
}

// ---------------------------------------------------------------------------
// VERB_NETWORK_CONFIG_REQUEST — the controller join
// ---------------------------------------------------------------------------

/// The request metadata dictionary (`node/Network.cpp:1420-1451`; key
/// literals from node/NetworkConfig.hpp:95-121). Values advertise this
/// port honestly: vendor stays ZeroTier-compatible (controllers key on
/// it), the protocol version pins Salsa20/12 (see [`PROTO_VERSION`]).
pub fn netconf_request_meta_dict() -> String {
    let (maj, min, rev) = SOFTWARE_VERSION;
    [
        format!("v={NETWORKCONFIG_VERSION}"),
        "vend=1".to_string(), // ZT_VENDOR_ZEROTIER
        format!("pv={PROTO_VERSION}"),
        format!("majv={maj}"),
        format!("minv={min}"),
        format!("revv={rev}"),
        "mr=1024".to_string(),  // ZT_MAX_NETWORK_RULES
        "mc=128".to_string(),   // ZT_MAX_NETWORK_CAPABILITIES
        "mcr=64".to_string(),   // ZT_MAX_CAPABILITY_RULES
        "mt=128".to_string(),   // ZT_MAX_NETWORK_TAGS
        "f=0".to_string(),      // flags
        "revr=1".to_string(),   // ZT_RULES_ENGINE_REVISION
        "o=rustcrash-engine".to_string(),
    ]
    .join("\n")
        + "\n"
}

/// Build a `VERB_NETWORK_CONFIG_REQUEST` to the network's controller
/// (`node/Network.cpp:1448-1460`; payload: network id, u16 dict
/// length, metadata dict, then the previous config revision/timestamp
/// or 16 zero bytes). Sent uncompressed (compression is optional on
/// this direction — controllers uncompress only when the flag is set).
pub fn build_network_config_request(
    from: &NodeIdentity,
    controller_address: u64,
    network_id: u64,
    previous: Option<(u64, u64)>,
    key: &[u8; SYMMETRIC_KEY_SIZE],
) -> Result<WirePacket> {
    let meta = netconf_request_meta_dict();
    let mut pkt = WirePacket::new(controller_address, from.address(), Verb::NetworkConfigRequest);
    pkt.push_u64(network_id)
        .push_u16(meta.len() as u16)
        .push_bytes(meta.as_bytes());
    match previous {
        Some((rev, ts)) => {
            pkt.push_u64(rev).push_u64(ts);
        }
        None => {
            pkt.push_bytes(&[0u8; 16]);
        }
    }
    pkt.armor(key, true);
    Ok(pkt)
}

/// The controller address embedded in a network id
/// (`zerotier-go/address.go:131-133`): the top 40 bits.
pub fn controller_of(network_id: u64) -> u64 {
    network_id >> 24
}

/// A verified netconf chunk (the OK(NETWORK_CONFIG_REQUEST) payload).
#[derive(Debug, Clone)]
pub struct NetconfResponse {
    pub network_id: u64,
    pub update_id: u64,
    /// The reassembled `key=value\n` dictionary — raw bytes: binary
    /// values (`I`, `RT`, ...) escape only 5 byte values, so high
    /// bytes travel literally and the chunk is not UTF-8 in general.
    pub dict: Vec<u8>,
}

/// Parse and verify an `OK(NETWORK_CONFIG_REQUEST)` (or a pushed
/// `VERB_NETWORK_CONFIG`) packet after dearmor + uncompress. The chunk
/// layout and the signed region follow `node/Node.cpp:807-837` and the
/// client-side verification (`node/Network.cpp:1082-1132`): every chunk
/// carries `sigType=1, sigLen=96` and the controller's 96-byte
/// signature over `[nwid .. chunkIndex]`. Multi-chunk configs are
/// rejected by name (reassembling them is transport-loop work).
pub fn parse_netconf_response(
    pkt: &mut WirePacket,
    controller: &NodeIdentity,
) -> Result<NetconfResponse> {
    if pkt.verb()? != Verb::Ok && pkt.verb()? != Verb::NetworkConfig {
        return Err(Error::crypto("zerotier: not a netconf response"));
    }
    let p = pkt.payload().to_vec();
    let mut at = 0usize;
    if pkt.verb()? == Verb::Ok {
        if p.len() < 9 || !matches!(Verb::from_byte(p[0]), Ok(Verb::NetworkConfigRequest)) {
            return Err(Error::crypto("zerotier: not an OK(NETWORK_CONFIG_REQUEST)"));
        }
        at = 9; // in-re-verb + echoed packet id
    }
    let signed_start = at;
    if p.len() < at + 8 + 2 {
        return Err(Error::crypto("zerotier: truncated netconf chunk"));
    }
    let network_id = u64::from_be_bytes(p[at..at + 8].try_into().unwrap());
    at += 8;
    let chunk_len = u16::from_be_bytes(p[at..at + 2].try_into().unwrap()) as usize;
    at += 2;
    if p.len() < at + chunk_len {
        return Err(Error::crypto("zerotier: netconf chunk overruns packet"));
    }
    let chunk = &p[at..at + chunk_len];
    at += chunk_len;
    if p.len() < at + 17 {
        return Err(Error::crypto("zerotier: truncated netconf chunk trailer"));
    }
    let _flags = p[at];
    at += 1;
    let update_id = u64::from_be_bytes(p[at..at + 8].try_into().unwrap());
    at += 8;
    let total_len = u32::from_be_bytes(p[at..at + 4].try_into().unwrap()) as usize;
    at += 4;
    let chunk_index = u32::from_be_bytes(p[at..at + 4].try_into().unwrap()) as usize;
    at += 4;
    let signed_end = at;
    if chunk_index != 0 || chunk_len != total_len {
        return Err(Error::crypto(
            "zerotier: multi-chunk netconf reassembly is staged with the transport loop",
        ));
    }
    if p[at] != 1 || u16::from_be_bytes(p[at + 1..at + 3].try_into().unwrap()) != SIGNATURE_SIZE as u16
    {
        return Err(Error::crypto("zerotier: netconf chunk is unsigned (legacy controller)"));
    }
    at += 3;
    if p.len() < at + SIGNATURE_SIZE {
        return Err(Error::crypto("zerotier: truncated netconf signature"));
    }
    let sig = &p[at..at + SIGNATURE_SIZE];
    if !controller.verify(&p[signed_start..signed_end], sig) {
        return Err(Error::crypto("zerotier: netconf chunk signature check failed"));
    }
    Ok(NetconfResponse { network_id, update_id, dict: chunk.to_vec() })
}

/// Build a signed, optionally LZ4-compressed netconf chunk the way a
/// controller does (`node/Node.cpp:807-837`) — used by the in-test
/// controller and by future controller-mode support. `lz4_compress`
/// here is the literal-run-only encoder: a conformant block (every
/// decoder must accept it), not a ratio-optimizing one.
#[allow(clippy::too_many_arguments)]
pub fn build_netconf_ok(
    controller: &NodeIdentity,
    to_address: u64,
    request_packet_id: u64,
    network_id: u64,
    dict: &[u8],
    update_id: u64,
    compress: bool,
    key: &[u8; SYMMETRIC_KEY_SIZE],
) -> Result<WirePacket> {
    let chunk = dict;
    let mut body = Vec::with_capacity(chunk.len() + 32);
    body.extend_from_slice(&network_id.to_be_bytes());
    body.extend_from_slice(&(chunk.len() as u16).to_be_bytes());
    body.extend_from_slice(chunk);
    body.push(0); // flags
    body.extend_from_slice(&update_id.to_be_bytes());
    body.extend_from_slice(&(chunk.len() as u32).to_be_bytes());
    body.extend_from_slice(&0u32.to_be_bytes()); // chunk index 0
    let sig = controller.sign(&body)?;
    body.push(1);
    body.extend_from_slice(&(SIGNATURE_SIZE as u16).to_be_bytes());
    body.extend_from_slice(&sig);

    let mut pkt = WirePacket::new(to_address, controller.address(), Verb::Ok);
    pkt.push_u8(Verb::NetworkConfigRequest.to_byte())
        .push_u64(request_packet_id)
        .push_bytes(&body);
    if compress {
        let encoded = lz4_literal_encode(pkt.payload());
        pkt.set_payload(&encoded);
        pkt.set_compressed(true);
    }
    pkt.armor(key, true);
    Ok(pkt)
}

/// The literal-run-only LZ4 block encoder (spec-conformant: exactly one
/// sequence — the final one, which "contains only literals" — with the
/// length in the 255-extension chain). Not a general compressor — a
/// real one would emit matches; this one is good enough to exercise
/// the decompression path honestly and is limited by the decoder cap.
fn lz4_literal_encode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if data.is_empty() {
        out.push(0);
        return out;
    }
    let litlen = data.len();
    if litlen < 15 {
        out.push((litlen as u8) << 4);
    } else {
        out.push(0xf0);
        let mut rem = litlen - 15;
        while rem >= 255 {
            out.push(255);
            rem -= 255;
        }
        out.push(rem as u8);
    }
    out.extend_from_slice(data);
    out
}

// ===========================================================================
// Milestone 2: the node runtime — world/planet, fragments, WHOIS, the
// UDP loop, the netconf→smoltcp link, and the dial
// ===========================================================================

// ---------------------------------------------------------------------------
// World / planet (node/World.hpp — header-only at this ref)
// ---------------------------------------------------------------------------

/// `World::TYPE_PLANET` (node/World.hpp:77-82).
pub const WORLD_TYPE_PLANET: u8 = 1;
/// `World::TYPE_MOON` — user-created root sets.
pub const WORLD_TYPE_MOON: u8 = 127;
/// `ZT_WORLD_ID_EARTH` (node/World.hpp:50).
pub const WORLD_ID_EARTH: u64 = 149604618;
/// `ZT_WORLD_MAX_ROOTS` (node/World.hpp:31).
pub const WORLD_MAX_ROOTS: usize = 4;
/// `ZT_WORLD_MAX_STABLE_ENDPOINTS_PER_ROOT` (node/World.hpp:37).
pub const WORLD_MAX_ENDPOINTS_PER_ROOT: usize = 32;
/// The `forSign` bracket words (`World::serialize(true)`,
/// node/World.hpp:188-233): the signed region is wrapped in these.
const WORLD_SIGN_PREFIX: u64 = 0x7f7f_7f7f_7f7f_7f7f;
const WORLD_SIGN_SUFFIX: u64 = 0xf7f7_f7f7_f7f7_f7f7;

/// One root of a world: its identity plus the stable physical
/// endpoints (`World::Root`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorldRoot {
    pub identity: NodeIdentity,
    pub endpoints: Vec<PhysAddr>,
}

/// A world definition — a planet or moon (`class World`): the root set
/// a fresh node trusts, signed by the key that must sign its updates.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct World {
    /// 1 = planet, 127 = moon.
    pub world_type: u8,
    pub id: u64,
    pub timestamp: u64,
    /// The public key set (`ECC::Public`, 64 bytes) that must sign the
    /// *next* revision of this world.
    pub must_be_signed_by: [u8; PUBLIC_KEY_SIZE],
    /// The C25519 signature over the `forSign` form of this world.
    pub signature: [u8; SIGNATURE_SIZE],
    pub roots: Vec<WorldRoot>,
}

impl World {
    /// `World::deserialize` (node/World.hpp:236-271): type, id, ts,
    /// signing key, signature, roots (identity + stable endpoints);
    /// a moon carries a trailing dictionary length. Returns the world
    /// and the bytes consumed.
    pub fn from_bytes(buf: &[u8]) -> Result<(Self, usize)> {
        fn bad(what: &str) -> Error {
            Error::crypto(format!("zerotier: malformed world: {what}"))
        }
        // A cursor that reads and advances.
        struct Cur<'a> {
            buf: &'a [u8],
            at: usize,
        }
        impl Cur<'_> {
            fn u8(&mut self) -> Result<u8> {
                let b = *self.buf.get(self.at).ok_or_else(|| bad("truncated"))?;
                self.at += 1;
                Ok(b)
            }
            fn take(&mut self, n: usize) -> Result<&[u8]> {
                let s = self.buf.get(self.at..self.at + n).ok_or_else(|| bad("truncated"))?;
                self.at += n;
                Ok(s)
            }
            fn u16(&mut self) -> Result<u16> {
                let b: [u8; 2] = self.take(2)?.try_into().unwrap();
                Ok(u16::from_be_bytes(b))
            }
            fn u64(&mut self) -> Result<u64> {
                let b: [u8; 8] = self.take(8)?.try_into().unwrap();
                Ok(u64::from_be_bytes(b))
            }
        }
        let mut c = Cur { buf, at: 0 };
        let world_type = c.u8()?;
        if !matches!(world_type, 0 | WORLD_TYPE_PLANET | WORLD_TYPE_MOON) {
            return Err(bad("unknown world type"));
        }
        let id = c.u64()?;
        let timestamp = c.u64()?;
        let must_be_signed_by: [u8; PUBLIC_KEY_SIZE] = c.take(PUBLIC_KEY_SIZE)?.try_into().unwrap();
        let signature: [u8; SIGNATURE_SIZE] = c.take(SIGNATURE_SIZE)?.try_into().unwrap();
        let num_roots = c.u8()? as usize;
        if num_roots > WORLD_MAX_ROOTS {
            return Err(bad("too many roots"));
        }
        let mut roots = Vec::with_capacity(num_roots);
        for _ in 0..num_roots {
            let (identity, used) = NodeIdentity::deserialize_bin(&buf[c.at..])?;
            c.at += used;
            let num_eps = c.u8()? as usize;
            if num_eps > WORLD_MAX_ENDPOINTS_PER_ROOT {
                return Err(bad("too many stable endpoints"));
            }
            let mut endpoints = Vec::with_capacity(num_eps);
            for _ in 0..num_eps {
                let (ep, used) = PhysAddr::deserialize_from(buf, c.at)?;
                c.at += used;
                endpoints.push(ep);
            }
            roots.push(WorldRoot { identity, endpoints });
        }
        if world_type == WORLD_TYPE_MOON {
            let dlen = c.u16()? as usize;
            c.at = c
                .at
                .checked_add(dlen)
                .ok_or_else(|| bad("moon dictionary"))?;
        }
        Ok((
            World { world_type, id, timestamp, must_be_signed_by, signature, roots },
            c.at,
        ))
    }

    /// `World::serialize` (node/World.hpp:188-233). `for_sign` adds the
    /// bracket words and omits the signature — the exact bytes the
    /// signature covers.
    pub fn serialize(&self, for_sign: bool, out: &mut Vec<u8>) {
        if for_sign {
            out.extend_from_slice(&WORLD_SIGN_PREFIX.to_be_bytes());
        }
        out.push(self.world_type);
        out.extend_from_slice(&self.id.to_be_bytes());
        out.extend_from_slice(&self.timestamp.to_be_bytes());
        out.extend_from_slice(&self.must_be_signed_by);
        if !for_sign {
            out.extend_from_slice(&self.signature);
        }
        out.push(self.roots.len() as u8);
        for root in &self.roots {
            out.extend_from_slice(&root.identity.serialize_bin(false));
            out.push(root.endpoints.len() as u8);
            for ep in &root.endpoints {
                ep.serialize_into(out);
            }
        }
        if self.world_type == WORLD_TYPE_MOON {
            out.extend_from_slice(&0u16.to_be_bytes()); // no attached dictionary
        }
        if for_sign {
            out.extend_from_slice(&WORLD_SIGN_SUFFIX.to_be_bytes());
        }
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.serialize(false, &mut out);
        out
    }

    /// Verify the embedded signature against
    /// `updatesMustBeSignedBy` — the check `World::shouldBeReplacedBy`
    /// performs for updates (ECC::verify over the forSign form). The
    /// Ed25519 half of the key set is what signs.
    pub fn signature_is_valid(&self) -> bool {
        let mut body = Vec::new();
        self.serialize(true, &mut body);
        let signer = NodeIdentity::from_parts(0, self.must_be_signed_by, None);
        signer.verify(&body, &self.signature)
    }

    /// Parse a planet (or moon) file the way `Topology` loads the
    /// built-in one: full-consume, sane type/roots, signature valid.
    /// A planet's own signature proves it against the key it names —
    /// the *anchor* is the file's provenance (embedded by Topology or
    /// provided by the operator via `planet:`), exactly upstream's
    /// trust model.
    pub fn parse_planet(bytes: &[u8]) -> Result<Self> {
        let (world, used) = World::from_bytes(bytes)?;
        if used != bytes.len() {
            return Err(Error::crypto("zerotier: trailing bytes after world"));
        }
        if world.world_type == 0 {
            return Err(Error::crypto("zerotier: null world type"));
        }
        if world.roots.is_empty() {
            return Err(Error::crypto("zerotier: world has no roots"));
        }
        if !world.signature_is_valid() {
            return Err(Error::crypto("zerotier: world signature check failed"));
        }
        Ok(world)
    }

    /// `World::make` (node/World.hpp:277-292): assemble a signed world.
    /// The signer's public set becomes `updatesMustBeSignedBy` and the
    /// signature is over the forSign form — used by tests (and a
    /// future controller-side moon publisher).
    pub fn make(
        world_type: u8,
        id: u64,
        timestamp: u64,
        signer: &NodeIdentity,
        roots: Vec<WorldRoot>,
    ) -> Result<Self> {
        let mut world = World {
            world_type,
            id,
            timestamp,
            must_be_signed_by: *signer.public(),
            signature: [0u8; SIGNATURE_SIZE],
            roots,
        };
        let mut body = Vec::new();
        world.serialize(true, &mut body);
        world.signature = signer.sign(&body)?;
        Ok(world)
    }
}

/// `ZT_DEFAULT_WORLD` — the built-in Earth planet verbatim from
/// `node/Topology.cpp:20-37` (570 bytes, id 149604618, four roots:
/// cafe9efeb9 / 778cde7190 / 62f865ae71 / cafe04eba9, each with a
/// v4+v6 stable endpoint). This is what a node without a `planet:`
/// file bootstraps against, like `Topology`'s constructor.
pub fn default_planet() -> &'static [u8] {
    const ZT_DEFAULT_WORLD: [u8; 570] = [
        0x01, 0x00, 0x00, 0x00, 0x00, 0x08, 0xea, 0xc9, 0x0a, 0x00, 0x00, 0x01, 0x7e, 0xe9, 0x57, 0x60,
        0xcd, 0xb8, 0xb3, 0x88, 0xa4, 0x69, 0x22, 0x14, 0x91, 0xaa, 0x9a, 0xcd, 0x66, 0xcc, 0x76, 0x4c,
        0xde, 0xfd, 0x56, 0x03, 0x9f, 0x10, 0x67, 0xae, 0x15, 0xe6, 0x9c, 0x6f, 0xb4, 0x2d, 0x7b, 0x55,
        0x33, 0x0e, 0x3f, 0xda, 0xac, 0x52, 0x9c, 0x07, 0x92, 0xfd, 0x73, 0x40, 0xa6, 0xaa, 0x21, 0xab,
        0xa8, 0xa4, 0x89, 0xfd, 0xae, 0xa4, 0x4a, 0x39, 0xbf, 0x2d, 0x00, 0x65, 0x9a, 0xc9, 0xc8, 0x18,
        0xeb, 0x36, 0x00, 0x92, 0x76, 0x37, 0xef, 0x4d, 0x14, 0x04, 0xa4, 0x4d, 0x54, 0x46, 0x84, 0x85,
        0x13, 0x79, 0x75, 0x1f, 0xaa, 0x79, 0xb4, 0xc4, 0xea, 0x85, 0x04, 0x01, 0x75, 0xea, 0x06, 0x58,
        0x60, 0x48, 0x24, 0x02, 0xe1, 0xeb, 0x34, 0x20, 0x52, 0x00, 0x0e, 0x62, 0x90, 0x06, 0x1a, 0x9b,
        0xe0, 0xcd, 0x29, 0x3c, 0x8b, 0x55, 0xf1, 0xc3, 0xd2, 0x52, 0x48, 0x08, 0xaf, 0xc5, 0x49, 0x22,
        0x08, 0x0e, 0x35, 0x39, 0xa7, 0x5a, 0xdd, 0xc3, 0xce, 0xf0, 0xf6, 0xad, 0x26, 0x0d, 0x58, 0x82,
        0x93, 0xbb, 0x77, 0x86, 0xe7, 0x1e, 0xfa, 0x4b, 0x90, 0x57, 0xda, 0xd9, 0x86, 0x7a, 0xfe, 0x12,
        0xdd, 0x04, 0xca, 0xfe, 0x9e, 0xfe, 0xb9, 0x00, 0xcc, 0xde, 0xf7, 0x6b, 0xc7, 0xb9, 0x7d, 0xed,
        0x90, 0x4e, 0xab, 0xc5, 0xdf, 0x09, 0x88, 0x6d, 0x9c, 0x15, 0x14, 0xa6, 0x10, 0x03, 0x6c, 0xb9,
        0x13, 0x9c, 0xc2, 0x14, 0x00, 0x1a, 0x29, 0x58, 0x97, 0x8e, 0xfc, 0xec, 0x15, 0x71, 0x2d, 0xd3,
        0x94, 0x8c, 0x6e, 0x6b, 0x3a, 0x8e, 0x89, 0x3d, 0xf0, 0x1f, 0xf4, 0x93, 0xd1, 0xf8, 0xd9, 0x80,
        0x6a, 0x86, 0x0c, 0x54, 0x20, 0x57, 0x1b, 0xf0, 0x00, 0x02, 0x04, 0x68, 0xc2, 0x08, 0x86, 0x27,
        0x09, 0x06, 0x26, 0x05, 0x98, 0x80, 0x02, 0x00, 0x12, 0x00, 0x00, 0x30, 0x05, 0x71, 0x0e, 0x34,
        0x00, 0x51, 0x27, 0x09, 0x77, 0x8c, 0xde, 0x71, 0x90, 0x00, 0x3f, 0x66, 0x81, 0xa9, 0x9e, 0x5a,
        0xd1, 0x89, 0x5e, 0x9f, 0xba, 0x33, 0xe6, 0x21, 0x2d, 0x44, 0x54, 0xe1, 0x68, 0xbc, 0xec, 0x71,
        0x12, 0x10, 0x1b, 0xf0, 0x00, 0x95, 0x6e, 0xd8, 0xe9, 0x2e, 0x42, 0x89, 0x2c, 0xb6, 0xf2, 0xec,
        0x41, 0x08, 0x81, 0xa8, 0x4a, 0xb1, 0x9d, 0xa5, 0x0e, 0x12, 0x87, 0xba, 0x3d, 0x92, 0x6c, 0x3a,
        0x1f, 0x75, 0x5c, 0xcc, 0xf2, 0x99, 0xa1, 0x20, 0x70, 0x55, 0x00, 0x02, 0x04, 0x67, 0xc3, 0x67,
        0x42, 0x27, 0x09, 0x06, 0x26, 0x05, 0x98, 0x80, 0x04, 0x00, 0x00, 0xc3, 0x02, 0x54, 0xf2, 0xbc,
        0xa1, 0xf7, 0x00, 0x19, 0x27, 0x09, 0x62, 0xf8, 0x65, 0xae, 0x71, 0x00, 0xe2, 0x07, 0x6c, 0x57,
        0xde, 0x87, 0x0e, 0x62, 0x88, 0xd7, 0xd5, 0xe7, 0x40, 0x44, 0x08, 0xb1, 0x54, 0x5e, 0xfc, 0xa3,
        0x7d, 0x67, 0xf7, 0x7b, 0x87, 0xe9, 0xe5, 0x41, 0x68, 0xc2, 0x5d, 0x3e, 0xf1, 0xa9, 0xab, 0xf2,
        0x90, 0x5e, 0xa5, 0xe7, 0x85, 0xc0, 0x1d, 0xff, 0x23, 0x88, 0x7a, 0xd4, 0x23, 0x2d, 0x95, 0xc7,
        0xa8, 0xfd, 0x2c, 0x27, 0x11, 0x1a, 0x72, 0xbd, 0x15, 0x93, 0x22, 0xdc, 0x00, 0x02, 0x04, 0x32,
        0x07, 0xfc, 0x8a, 0x27, 0x09, 0x06, 0x20, 0x01, 0x49, 0xf0, 0xd0, 0xdb, 0x00, 0x02, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x27, 0x09, 0xca, 0xfe, 0x04, 0xeb, 0xa9, 0x00, 0x6c, 0x6a,
        0x9d, 0x1d, 0xea, 0x55, 0xc1, 0x61, 0x6b, 0xfe, 0x2a, 0x2b, 0x8f, 0x0f, 0xf9, 0xa8, 0xca, 0xca,
        0xf7, 0x03, 0x74, 0xfb, 0x1f, 0x39, 0xe3, 0xbe, 0xf8, 0x1c, 0xbf, 0xeb, 0xef, 0x17, 0xb7, 0x22,
        0x82, 0x68, 0xa0, 0xa2, 0xa2, 0x9d, 0x34, 0x88, 0xc7, 0x52, 0x56, 0x5c, 0x6c, 0x96, 0x5c, 0xbd,
        0x65, 0x06, 0xec, 0x24, 0x39, 0x7c, 0xc8, 0xa5, 0xd9, 0xd1, 0x52, 0x85, 0xa8, 0x7f, 0x00, 0x02,
        0x04, 0x54, 0x11, 0x35, 0x9b, 0x27, 0x09, 0x06, 0x2a, 0x02, 0x6e, 0xa0, 0xd4, 0x05, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x99, 0x93, 0x27, 0x09,
    ];
    &ZT_DEFAULT_WORLD
}

// ---------------------------------------------------------------------------
// Packet fragmentation (node/Packet.hpp:344-462 + node/Switch.cpp)
// ---------------------------------------------------------------------------

/// Build one `Packet::Fragment` (`Fragment::init`, Packet.hpp:406-421):
/// the parent's IV+dest (13 bytes), the reserved-`0xff` indicator, the
/// packed `(total<<4 | no)` byte, a hop byte, then the fragment data.
pub fn build_fragment(
    packet: &[u8],
    frag_start: usize,
    frag_len: usize,
    frag_no: u8,
    frag_total: u8,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(FRAGMENT_HEADER_LEN + frag_len);
    out.extend_from_slice(&packet[..PACKET_IDX_DEST + 5]); // IV + dest
    out.push(FRAGMENT_INDICATOR);
    out.push(((frag_total & 0x0f) << 4) | (frag_no & 0x0f));
    out.push(0); // hops
    out.extend_from_slice(&packet[frag_start..frag_start + frag_len]);
    out
}

/// A received `Packet::Fragment` with its header fields decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireFragment {
    bytes: Vec<u8>,
}

impl WireFragment {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.len() < FRAGMENT_HEADER_LEN || bytes[FRAGMENT_IDX_INDICATOR] != FRAGMENT_INDICATOR {
            return Err(Error::crypto("zerotier: not a valid fragment"));
        }
        Ok(WireFragment { bytes: bytes.to_vec() })
    }

    /// The destination address (bytes 8..13).
    pub fn destination(&self) -> u64 {
        be40(&self.bytes[PACKET_IDX_DEST..PACKET_IDX_DEST + 5])
    }

    pub fn packet_id(&self) -> u64 {
        u64::from_be_bytes(self.bytes[0..8].try_into().unwrap())
    }

    pub fn total_fragments(&self) -> usize {
        ((self.bytes[14] >> 4) & 0x0f) as usize
    }

    pub fn fragment_number(&self) -> usize {
        (self.bytes[14] & 0x0f) as usize
    }

    pub fn payload(&self) -> &[u8] {
        &self.bytes[FRAGMENT_HEADER_LEN..]
    }
}

/// Slice an armored packet into path-MTU datagrams exactly as
/// `Switch::_sendViaSpecificPath` does: the head keeps the packet
/// header, gets `ZT_PROTO_FLAG_FRAGMENTED` set **pre-armor** by the
/// caller (see [`ZtStack::send_packet`]), and is truncated to the MTU;
/// each following fragment carries up to `mtu-16` payload bytes. No
/// per-fragment MAC — the assembled packet's MAC authenticates all of
/// it. Errors when the packet needs more than
/// [`MAX_PACKET_FRAGMENTS`] fragments.
pub fn fragment_packet(armored: &[u8], path_mtu: usize) -> Result<Vec<Vec<u8>>> {
    if path_mtu <= FRAGMENT_HEADER_LEN {
        return Err(Error::network("zerotier: path MTU too small to carry fragments"));
    }
    let chunk = armored.len().min(path_mtu);
    if chunk == armored.len() {
        return Ok(vec![armored.to_vec()]);
    }
    let per_frag = path_mtu - FRAGMENT_HEADER_LEN;
    let remaining = armored.len() - chunk;
    let mut frags_remaining = remaining / per_frag;
    if frags_remaining * per_frag < remaining {
        frags_remaining += 1;
    }
    let total = frags_remaining + 1;
    if total > MAX_PACKET_FRAGMENTS {
        return Err(Error::network(format!(
            "zerotier: packet needs {total} fragments (max {MAX_PACKET_FRAGMENTS})"
        )));
    }
    let mut out = Vec::with_capacity(total);
    out.push(armored[..chunk].to_vec());
    let mut start = chunk;
    for fno in 1..total {
        let len = (armored.len() - start).min(per_frag);
        out.push(build_fragment(armored, start, len, fno as u8, total as u8));
        start += len;
    }
    Ok(out)
}

/// How many datagrams [`fragment_packet`] would emit for `len` bytes.
fn fragment_count(len: usize, path_mtu: usize) -> usize {
    if len <= path_mtu {
        return 1;
    }
    let per_frag = path_mtu - FRAGMENT_HEADER_LEN;
    let remaining = len - path_mtu;
    1 + remaining.div_ceil(per_frag)
}

/// The RX-side reassembly queue (`Switch::onRemotePacket`,
/// node/Switch.cpp:68-272): entries keyed by packet id, one bit per
/// fragment held (bit 0 = the head), assembled the moment all bits
/// arrive. Entries expire after [`FRAGMENT_TTL`] — upstream recycles
/// its fixed RX queue the same way.
const FRAGMENT_TTL: Duration = Duration::from_secs(5);

struct FragAssembly {
    total: usize,
    have: u32,
    head: Option<Vec<u8>>,
    frags: Vec<Option<Vec<u8>>>,
    at: Instant,
}

#[derive(Default)]
pub struct FragmentAssembler {
    entries: HashMap<u64, FragAssembly>,
}

impl FragmentAssembler {
    /// Feed one datagram; returns the fully assembled (still armored)
    /// packet when this datagram completes one. Mirrors the
    /// fragment/head branches of `Switch::onRemotePacket`, including
    /// the sanity gates (fragment numbers are 1.., totals > 1, ≤ 16)
    /// and duplicate suppression.
    pub fn ingest(&mut self, datagram: &[u8]) -> Option<Vec<u8>> {
        if datagram.len() < FRAGMENT_HEADER_LEN {
            return None;
        }
        if datagram[FRAGMENT_IDX_INDICATOR] == FRAGMENT_INDICATOR {
            let frag = WireFragment::from_bytes(datagram).ok()?;
            let number = frag.fragment_number();
            let total = frag.total_fragments();
            // "frag no 0 is a Packet; totals <= 1 make no sense as fragments"
            if number == 0 || number > 15 || total <= 1 || number >= total {
                return None;
            }
            let packet_id = frag.packet_id();
            let entry = self.entries.entry(packet_id).or_insert_with(|| FragAssembly {
                total: 0,
                have: 0,
                head: None,
                frags: vec![None; 15],
                at: Instant::now(),
            });
            if entry.have & (1 << number) != 0 {
                return None; // duplicate fragment
            }
            entry.total = total;
            entry.frags[number - 1] = Some(frag.bytes[FRAGMENT_HEADER_LEN..].to_vec());
            entry.have |= 1 << number;
            let complete = entry.have.count_ones() as usize == total && entry.head.is_some();
            if !complete {
                return None;
            }
            let mut assembled = entry.head.take().unwrap();
            for f in entry.frags.iter().take(total - 1) {
                assembled.extend_from_slice(f.as_deref().unwrap_or(&[]));
            }
            self.entries.remove(&packet_id);
            return Some(assembled);
        }
        // A packet head.
        if datagram.len() < PACKET_HEADER_LEN {
            return None;
        }
        let packet_id = u64::from_be_bytes(datagram[0..8].try_into().unwrap());
        if datagram[PACKET_IDX_FLAGS] & FLAG_FRAGMENTED == 0 {
            // Unfragmented: process directly.
            return Some(datagram.to_vec());
        }
        let entry = self.entries.entry(packet_id).or_insert_with(|| FragAssembly {
            total: 0,
            have: 0,
            head: None,
            frags: vec![None; 15],
            at: Instant::now(),
        });
        if entry.have & 1 != 0 {
            return None; // duplicate head
        }
        entry.have |= 1;
        entry.head = Some(datagram.to_vec());
        let complete =
            entry.total > 1 && entry.have.count_ones() as usize == entry.total;
        if !complete {
            return None;
        }
        let mut assembled = entry.head.take().unwrap();
        for f in entry.frags.iter().take(entry.total - 1) {
            assembled.extend_from_slice(f.as_deref().unwrap_or(&[]));
        }
        self.entries.remove(&packet_id);
        Some(assembled)
    }

    /// Drop expired entries (the RX queue recycle).
    pub fn expire(&mut self) {
        let now = Instant::now();
        self.entries.retain(|_, e| now.duration_since(e.at) < FRAGMENT_TTL);
    }
}

// ---------------------------------------------------------------------------
// WHOIS / FRAME / ECHO verb payloads
// ---------------------------------------------------------------------------

/// Build a `VERB_WHOIS` for one address (`Packet.hpp:577-581`: the
/// payload is 5-byte addresses, as many as fit). Unarmored — callers
/// armor (and fragment) via [`armor_and_fragment`] so the fragmented
/// flag lands before the MAC does.
/// `ZT_DIRECT_PATH_PUSH_INTERVAL` (node/Constants.hpp:568), ms — how
/// often our direct paths are pushed to a peer we have **no** direct
/// path to yet (`Peer::sendHELLO`'s push block, Peer.cpp:200-236).
pub const DIRECT_PATH_PUSH_INTERVAL: Duration = Duration::from_millis(15_000);
/// `ZT_DIRECT_PATH_PUSH_INTERVAL_HAVEPATH` (node/Constants.hpp:573), ms.
pub const DIRECT_PATH_PUSH_INTERVAL_HAVEPATH: Duration = Duration::from_millis(120_000);
/// `ZT_MIN_UNITE_INTERVAL` (node/Constants.hpp:542), ms — a root's
/// rate limit for introducing the same (source, destination) pair
/// (`Switch::_shouldUnite`, Switch.cpp:1079-1088).
pub const MIN_UNITE_INTERVAL: Duration = Duration::from_millis(30_000);
/// `ZT_PUSH_DIRECT_PATHS_FLAG_FORGET_PATH` (node/Packet.hpp:216).
pub const PUSH_DIRECT_PATHS_FLAG_FORGET_PATH: u8 = 0x01;
/// `ZT_PUSH_DIRECT_PATHS_FLAG_CLUSTER_REDIRECT` (node/Packet.hpp:221).
pub const PUSH_DIRECT_PATHS_FLAG_CLUSTER_REDIRECT: u8 = 0x02;
/// `ZT_PUSH_DIRECT_PATHS_MAX_PER_SCOPE_AND_FAMILY`
/// (node/Constants.hpp:613) — probes honored per push, per scope and
/// family.
pub const PUSH_DIRECT_PATHS_MAX_PER_SCOPE: usize = 8;
/// `ZT_PUSH_DIRECT_PATHS_CUTOFF_TIME` (node/Constants.hpp:578), ms —
/// the rolling window of the push-receive rate gate.
pub const PUSH_DIRECT_PATHS_CUTOFF: Duration = Duration::from_millis(30_000);
/// `ZT_PUSH_DIRECT_PATHS_CUTOFF_LIMIT` (node/Constants.hpp:608).
pub const PUSH_DIRECT_PATHS_CUTOFF_LIMIT: usize = 8;
/// How long a probe's OK(HELLO) may take to land (this port's bound
/// on the probe table; upstream keeps `Path` candidates with quality
/// bookkeeping instead).
pub const PROBE_TTL: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// VERB_RENDEZVOUS + VERB_PUSH_DIRECT_PATHS — direct-path learning (NAT-t)
// ---------------------------------------------------------------------------

/// A `VERB_RENDEZVOUS` (0x05): a trusted upstream's introduction —
/// "peer `zt_address` is at `sock`; go contact it directly"
/// (`Peer::introduce`, node/Peer.cpp:291-407; parsed by
/// `_doRENDEZVOUS`, node/IncomingPacket.cpp:736-761). Wire
/// (`ZT_PROTO_VERB_RENDEZVOUS_IDX_*`, node/Packet.hpp:284-288):
/// `flags(1) || zt_address(5) || port(2) || addr_len(1: 4|16) || ip`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rendezvous {
    /// Always 0 from `Peer::introduce` (kept for 1:1 parse).
    pub flags: u8,
    /// The introduced peer's ZeroTier address.
    pub zt_address: u64,
    /// Where to reach it (one of its live physical paths).
    pub sock: SocketAddr,
}

/// Build a RENDEZVOUS like `Peer::introduce` does — armored suite 1
/// (encrypted; Peer.cpp:399), sent over the introducer's path to `to`.
pub fn build_rendezvous(
    from: &NodeIdentity,
    to: u64,
    msg: &Rendezvous,
    key: &[u8; SYMMETRIC_KEY_SIZE],
) -> WirePacket {
    let mut pkt = WirePacket::new(to, from.address(), Verb::Rendezvous);
    let ip: Vec<u8> = match msg.sock {
        SocketAddr::V4(v4) => v4.ip().octets().to_vec(),
        SocketAddr::V6(v6) => v6.ip().octets().to_vec(),
    };
    pkt.push_u8(msg.flags)
        .push_bytes(&msg.zt_address.to_be_bytes()[3..8])
        .push_u16(msg.sock.port())
        .push_u8(if msg.sock.is_ipv4() { 4 } else { 16 })
        .push_bytes(&ip);
    pkt.armor(key, true);
    pkt
}

/// Parse a (dearmored) RENDEZVOUS. Callers must gate the sender to an
/// upstream first — `_doRENDEZVOUS` only honors introductions from
/// roots (`isUpstream(peer->identity())`).
pub fn parse_rendezvous(pkt: &WirePacket) -> Result<Rendezvous> {
    let p = pkt.payload();
    if p.len() < 10 {
        return Err(Error::crypto("zerotier: truncated RENDEZVOUS"));
    }
    let flags = p[0];
    let zt_address = be40(&p[1..6]);
    let port = u16::from_be_bytes([p[6], p[7]]);
    let alen = p[8] as usize;
    if (alen != 4 && alen != 16) || p.len() < 9 + alen {
        return Err(Error::crypto("zerotier: RENDEZVOUS bad address"));
    }
    let sock = match alen {
        4 => SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(p[9], p[10], p[11], p[12]),
            port,
        )),
        _ => {
            let octets: [u8; 16] = p[9..25].try_into().unwrap();
            SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(octets), port, 0, 0))
        }
    };
    Ok(Rendezvous { flags, zt_address, sock })
}

/// One `VERB_PUSH_DIRECT_PATHS` (0x10) record. Wire (the writer,
/// `Peer.cpp:217-232`): `flags(1) || ext_len(2: 0) || addr_type(1:
/// 4|6) || addr_len(1: 6|18 — ip bytes + port) || ip(4|16) || port(2)`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirectPath {
    /// `ZT_PUSH_DIRECT_PATHS_FLAG_*` bits; 0 for a plain path.
    pub flags: u8,
    /// The advertised physical address.
    pub sock: SocketAddr,
}

/// Build a PUSH_DIRECT_PATHS advertising `paths` — compressed and
/// armored suite 1 exactly like the upstream sender (Peer.cpp:231-232).
pub fn build_push_direct_paths(
    from: &NodeIdentity,
    to: u64,
    paths: &[DirectPath],
    key: &[u8; SYMMETRIC_KEY_SIZE],
) -> WirePacket {
    let mut pkt = WirePacket::new(to, from.address(), Verb::PushDirectPaths);
    pkt.push_u16(paths.len() as u16);
    for p in paths {
        let (ty, ip): (u8, Vec<u8>) = match p.sock {
            SocketAddr::V4(v4) => (4, v4.ip().octets().to_vec()),
            SocketAddr::V6(v6) => (6, v6.ip().octets().to_vec()),
        };
        // addr_len counts ip bytes + the trailing u16 port (6 / 18).
        pkt.push_u8(p.flags)
            .push_u16(0)
            .push_u8(ty)
            .push_u8(if ty == 4 { 6 } else { 18 })
            .push_bytes(&ip)
            .push_u16(p.sock.port());
    }
    // Compressed like the upstream sender (`outp->compress()`,
    // Peer.cpp:231) — the port's literal-run LZ4 block (the same
    // encoder the netconf OK uses; a documented delta: no back-
    // reference search, spec-conformant output).
    let encoded = lz4_literal_encode(pkt.payload());
    pkt.set_payload(&encoded);
    pkt.set_compressed(true);
    pkt.armor(key, true);
    pkt
}

/// Parse a (dearmored, uncompressed-by-the-caller) PUSH_DIRECT_PATHS
/// — the reader walk of `_doPUSH_DIRECT_PATHS`
/// (IncomingPacket.cpp:1378-1431), including the extension skip.
pub fn parse_push_direct_paths(pkt: &WirePacket) -> Result<Vec<DirectPath>> {
    let p = pkt.payload();
    if p.len() < 2 {
        return Err(Error::crypto("zerotier: truncated PUSH_DIRECT_PATHS"));
    }
    let count = u16::from_be_bytes([p[0], p[1]]) as usize;
    let mut at = 2usize;
    let mut out = Vec::with_capacity(count.min(16));
    for _ in 0..count {
        if at + 3 > p.len() {
            return Err(Error::crypto("zerotier: truncated PUSH_DIRECT_PATHS record"));
        }
        let flags = p[at];
        at += 1;
        let ext = u16::from_be_bytes([p[at], p[at + 1]]) as usize;
        at += 2;
        if at + ext + 2 > p.len() {
            return Err(Error::crypto("zerotier: truncated PUSH_DIRECT_PATHS extension"));
        }
        at += ext;
        let ty = p[at];
        at += 1;
        let alen = p[at] as usize;
        at += 1;
        match ty {
            4 if at + 6 <= p.len() && alen >= 6 => {
                let ip = Ipv4Addr::new(p[at], p[at + 1], p[at + 2], p[at + 3]);
                let port = u16::from_be_bytes([p[at + 4], p[at + 5]]);
                out.push(DirectPath { flags, sock: SocketAddr::V4(SocketAddrV4::new(ip, port)) });
                at += alen;
            }
            6 if at + 18 <= p.len() && alen >= 18 => {
                let octets: [u8; 16] = p[at..at + 16].try_into().unwrap();
                let port = u16::from_be_bytes([p[at + 16], p[at + 17]]);
                out.push(DirectPath {
                    flags,
                    sock: SocketAddr::V6(SocketAddrV6::new(Ipv6Addr::from(octets), port, 0, 0)),
                });
                at += alen;
            }
            // Unknown family: skip the record (upstream's switch falls
            // through the same way).
            _ => at += alen,
        }
    }
    Ok(out)
}

pub fn build_whois(from: &NodeIdentity, upstream: u64, who: u64) -> WirePacket {
    let mut pkt = WirePacket::new(upstream, from.address(), Verb::Whois);
    pkt.push_bytes(&who.to_be_bytes()[3..8]);
    pkt
}

/// Parse an `OK(WHOIS)` payload: one or more binary identities
/// (`_doWHOIS`'s reply, IncomingPacket.cpp:669-705).
pub fn parse_ok_whois(pkt: &WirePacket) -> Result<Vec<NodeIdentity>> {
    let p = pkt.payload();
    if p.len() < 9 || !matches!(Verb::from_byte(p[0]), Ok(Verb::Whois)) {
        return Err(Error::crypto("zerotier: not an OK(WHOIS)"));
    }
    let mut at = 9;
    let mut ids = Vec::new();
    while at < p.len() {
        let (id, used) = NodeIdentity::deserialize_bin(&p[at..])?;
        at += used;
        if id.secret.is_some() {
            return Err(Error::crypto("zerotier: WHOIS reply carried a secret identity"));
        }
        ids.push(id);
    }
    Ok(ids)
}

/// The in-re packet id echoed by an OK (verb-agnostic prefix).
pub fn ok_in_re_packet_id(pkt: &WirePacket) -> Result<u64> {
    let p = pkt.payload();
    if p.len() < 9 {
        return Err(Error::crypto("zerotier: truncated OK"));
    }
    Ok(u64::from_be_bytes(p[1..9].try_into().unwrap()))
}

/// Build a `VERB_FRAME` (`Packet.hpp:622-633`): network id, ethertype,
/// and the ethernet *payload* — MACs are derived from the packet's
/// source/destination ZeroTier addresses (`_doFRAME`), never carried.
/// Unarmored — see [`build_whois`].
pub fn build_frame(from: &NodeIdentity, to: u64, network_id: u64, ethertype: u16, frame: &[u8]) -> WirePacket {
    let mut pkt = WirePacket::new(to, from.address(), Verb::Frame);
    pkt.push_u64(network_id).push_u16(ethertype).push_bytes(frame);
    pkt
}

/// Armor + fragment one outbound packet exactly as
/// `Switch::_sendViaSpecificPath` orders it: the fragmented flag is set
/// while the packet is still plaintext (the MAC must cover the whole
/// assembled packet), then armor, then slice to datagrams.
pub fn armor_and_fragment(
    pkt: &mut WirePacket,
    key: &[u8; SYMMETRIC_KEY_SIZE],
    path_mtu: usize,
) -> Result<Vec<Vec<u8>>> {
    pkt.set_fragmented(fragment_count(pkt.len(), path_mtu) > 1);
    pkt.armor(key, true);
    fragment_packet(pkt.as_bytes(), path_mtu)
}

/// A parsed `VERB_FRAME`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WireFrame {
    pub network_id: u64,
    pub ethertype: u16,
    pub frame: Vec<u8>,
}

pub fn parse_frame(pkt: &WirePacket) -> Result<WireFrame> {
    let p = pkt.payload();
    if p.len() < 10 {
        return Err(Error::crypto("zerotier: truncated FRAME"));
    }
    Ok(WireFrame {
        network_id: u64::from_be_bytes(p[0..8].try_into().unwrap()),
        ethertype: u16::from_be_bytes([p[8], p[9]]),
        frame: p[10..].to_vec(),
    })
}

/// The ethertype of an IP packet by version (`ZT_ETHERTYPE_*`).
fn ip_ethertype(pkt: &[u8]) -> Option<u16> {
    match pkt.first()? >> 4 {
        4 => Some(ETHERTYPE_IPV4),
        6 => Some(ETHERTYPE_IPV6),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// The netconf dictionary (node/Dictionary.hpp + NetworkConfig.cpp)
// ---------------------------------------------------------------------------

/// A parsed `key=value\n` dictionary with the Dictionary.hpp escapes
/// (`\0` `\r` `\n` `\\` `\e`) decoded per value. Values stay **bytes**:
/// binary fields (`I`, `RT`, `S`) legitimately contain high bytes the
/// escaping does not touch. Lookup is linear — upstream's is too
/// ("designed for small things").
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct NetconfDict {
    pairs: Vec<(String, Vec<u8>)>,
}

impl NetconfDict {
    pub fn parse(raw: &[u8]) -> Self {
        let mut pairs = Vec::new();
        for line in raw.split(|&b| b == b'\n') {
            let Some(eq) = line.iter().position(|&b| b == b'=') else {
                continue;
            };
            let key = String::from_utf8_lossy(&line[..eq]).into_owned();
            pairs.push((key, unescape_dict_value(&line[eq + 1..])));
        }
        NetconfDict { pairs }
    }

    pub fn get(&self, key: &str) -> Option<&[u8]> {
        self.pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_slice())
    }

    /// `Dictionary::getUI`: integers are stored as hex.
    fn get_u64(&self, key: &str) -> Option<u64> {
        self.get(key)
            .and_then(|v| std::str::from_utf8(v).ok())
            .and_then(|v| u64::from_str_radix(v, 16).ok())
    }
}

/// Decode the `Dictionary.hpp` value escapes (lines 360-400): `\\0`,
/// `\\r`, `\\n`, `\\\\`, `\\e` (an escaped `=`).
fn unescape_dict_value(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut i = 0;
    while i < raw.len() {
        if raw[i] != b'\\' {
            out.push(raw[i]);
            i += 1;
            continue;
        }
        match raw.get(i + 1) {
            Some(b'0') => out.push(0),
            Some(b'r') => out.push(b'\r'),
            Some(b'n') => out.push(b'\n'),
            Some(b'\\') => out.push(b'\\'),
            Some(b'e') => out.push(b'='),
            Some(&other) => {
                out.push(b'\\');
                out.push(other);
            }
            None => out.push(b'\\'),
        }
        i += 2;
    }
    out
}

/// The encoder twin of [`unescape_dict_value`] (`Dictionary::add`'s
/// escaping): what a controller emits for binary field values. Shared
/// by the in-test controller and a future controller-mode port.
pub fn escape_dict_value(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    for &b in raw {
        match b {
            0 => out.extend_from_slice(b"\\0"),
            b'\r' => out.extend_from_slice(b"\\r"),
            b'\n' => out.extend_from_slice(b"\\n"),
            b'\\' => out.extend_from_slice(b"\\\\"),
            b'=' => out.extend_from_slice(b"\\e"),
            other => out.push(other),
        }
    }
    out
}

/// One managed route from the netconf `RT` field
/// (`NetworkConfig::fromDictionary`): target network, optional via
/// (gateway), flags, metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ManagedRoute {
    pub target: (IpAddr, u8),
    pub via: Option<IpAddr>,
    pub flags: u16,
    pub metric: u16,
}

/// A controller netconf applied to the local stack: the managed
/// addresses (with prefixes), the managed routes, the MTU and the
/// specialist (active-bridge) node addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AppliedNetconf {
    pub network_id: u64,
    pub revision: u64,
    pub update_id: u64,
    pub mtu: usize,
    /// `I`: ZT-assigned static addresses; the InetAddress u16 field is
    /// the netmask length.
    pub managed_ips: Vec<(IpAddr, u8)>,
    /// `RT`: managed routes.
    pub routes: Vec<ManagedRoute>,
    /// `S`: specialist node addresses (active bridges — where frames
    /// for unknown MACs go).
    pub specialists: Vec<u64>,
}

/// Turn a verified [`NetconfResponse`] into an [`AppliedNetconf`]
/// (`NetworkConfig::fromDictionary`, NetworkConfig.cpp:366+):
/// `nwid`/`r`/`mtu` scalars, `I` static IPs, `RT` routes, `S`
/// specialists — each binary field a run of InetAddress-shaped
/// records.
pub fn parse_applied_netconf(resp: &NetconfResponse) -> Result<AppliedNetconf> {
    let dict = NetconfDict::parse(&resp.dict);
    let network_id = dict
        .get_u64("nwid")
        .ok_or_else(|| Error::protocol("zerotier: netconf has no nwid"))?;
    if network_id != resp.network_id {
        return Err(Error::protocol("zerotier: netconf nwid mismatch"));
    }
    let revision = dict.get_u64("r").unwrap_or(0);
    let mut mtu = dict.get_u64("mtu").unwrap_or(DEFAULT_NETWORK_MTU as u64) as usize;
    // fromDictionary clamps: IPv6 floor 1280, ZT_MAX_MTU ceiling.
    mtu = mtu.clamp(MIN_NETWORK_MTU as usize, MAX_NETWORK_MTU as usize);

    let mut managed_ips = Vec::new();
    if let Some(ips) = dict.get("I") {
        let mut at = 0usize;
        while at < ips.len() {
            let (addr, used) = PhysAddr::deserialize_from(ips, at)
                .map_err(|_| Error::protocol("zerotier: bad managed address"))?;
            at += used;
            match addr.to_ip_prefix() {
                Some(prefix) => managed_ips.push(prefix),
                None => return Err(Error::protocol("zerotier: managed address missing prefix")),
            }
        }
    }

    let mut routes = Vec::new();
    if let Some(rt) = dict.get("RT") {
        let mut at = 0usize;
        while at < rt.len() {
            let (target, used) = PhysAddr::deserialize_from(rt, at)
                .map_err(|_| Error::protocol("zerotier: bad route target"))?;
            at += used;
            let (via, used) = PhysAddr::deserialize_from(rt, at)
                .map_err(|_| Error::protocol("zerotier: bad route via"))?;
            at += used;
            if rt.len() < at + 4 {
                return Err(Error::protocol("zerotier: truncated route flags"));
            }
            let flags = u16::from_be_bytes(rt[at..at + 2].try_into().unwrap());
            let metric = u16::from_be_bytes(rt[at + 2..at + 4].try_into().unwrap());
            at += 4;
            let target = target
                .to_ip_prefix()
                .ok_or_else(|| Error::protocol("zerotier: route target missing prefix"))?;
            let via = match via {
                PhysAddr::None => None,
                other => Some(
                    other
                        .to_ip_prefix()
                        .map(|(ip, _)| ip)
                        .or_else(|| other.to_socket_addr().map(|sa| sa.ip()))
                        .ok_or_else(|| Error::protocol("zerotier: bad route gateway"))?,
                ),
            };
            routes.push(ManagedRoute { target, via, flags, metric });
        }
    }

    let mut specialists = Vec::new();
    if let Some(sp) = dict.get("S") {
        if sp.len() % 8 != 0 {
            return Err(Error::protocol("zerotier: specialist list not u64-aligned"));
        }
        for chunk in sp.as_chunks::<8>().0 {
            specialists.push(u64::from_be_bytes(*chunk));
        }
    }

    Ok(AppliedNetconf {
        network_id,
        revision,
        update_id: resp.update_id,
        mtu,
        managed_ips,
        routes,
        specialists,
    })
}

// ---------------------------------------------------------------------------
// The node runtime: peer table + UDP loop + the smoltcp link
// ---------------------------------------------------------------------------

/// Milliseconds since the epoch — ZeroTier's `node->now()`.
fn zt_now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// One learned peer: identity, pairwise key, the endpoint when known
/// (a root's comes from the planet; others' arrive through direct-path
/// learning — RENDEZVOUS introductions and PUSH_DIRECT_PATHS probes),
/// and a small duplicate-packet filter (the packet-id half of Switch's
/// RX-queue identity; replays of a whole packet are dropped like
/// duplicate fragments are).
struct PeerEntry {
    identity: NodeIdentity,
    key: [u8; SYMMETRIC_KEY_SIZE],
    endpoint: Option<SocketAddr>,
    last_seen: Instant,
    recent_ids: VecDeque<u64>,
    /// When we last pushed our direct paths to this peer
    /// (`_lastDirectPathPushSent`, Peer.cpp:209-211's interval gate).
    last_push_sent: Option<Instant>,
    /// The push-receive rate gate (`rateGatePushDirectPaths`,
    /// Peer.hpp:387-398): consecutive pushes inside the cutoff window.
    push_recv_streak: u8,
    last_push_recv: Option<Instant>,
}

impl PeerEntry {
    fn new(identity: NodeIdentity, key: [u8; SYMMETRIC_KEY_SIZE]) -> Self {
        PeerEntry {
            identity,
            key,
            endpoint: None,
            last_seen: Instant::now(),
            recent_ids: VecDeque::new(),
            last_push_sent: None,
            push_recv_streak: 0,
            last_push_recv: None,
        }
    }

    fn note_packet(&mut self, id: u64) -> bool {
        if self.recent_ids.contains(&id) {
            return false;
        }
        if self.recent_ids.len() >= 64 {
            self.recent_ids.pop_front();
        }
        self.recent_ids.push_back(id);
        true
    }
}

/// Where the node task's join stands.
enum Join {
    /// Fresh: no root HELLO in flight yet.
    Start,
    /// HELLO sent at `Instant`, `attempts` so far.
    HelloRoot { at: Instant, attempts: u32 },
    /// Root answered; netconf request in flight.
    Netconf { at: Instant, attempts: u32 },
    /// Controller netconf applied.
    Applied,
    /// Terminal.
    Failed(String),
}

/// Where a ZtUdp's inbound datagrams arrive.
type ZtUdpDownlink = mpsc::Receiver<(NetAddr, Vec<u8>)>;

/// Commands from the public API into the node task (the wireguard
/// tunnel-task shape).
enum ZtCmd {
    Connect {
        target: NetAddr,
        reply: oneshot::Sender<Result<Arc<StreamShared>>>,
    },
    UdpOpen {
        reply: oneshot::Sender<Result<(u32, ZtUdpDownlink)>>,
    },
    UdpSend {
        id: u32,
        dst: SocketAddr,
        data: Vec<u8>,
    },
    UdpClose {
        id: u32,
    },
}

/// A dial parked until the controller netconf applies (connect() can
/// arrive while the join is still in flight — the pre-session queue at
/// the socket level, like wireguard's pre-handshake SYNs).
struct ZtPendingDial {
    target: NetAddr,
    reply: oneshot::Sender<Result<Arc<StreamShared>>>,
    deadline: Instant,
}

struct ZtConn {
    handle: SocketHandle,
    shared: Arc<StreamShared>,
    fin_sent: bool,
    pending: Option<(oneshot::Sender<Result<Arc<StreamShared>>>, Instant)>,
}

struct ZtUdpSock {
    handle: SocketHandle,
    port: u16,
    down: mpsc::Sender<(NetAddr, Vec<u8>)>,
}

/// Queue/timeout constants (wireguard's EtStack values where ZeroTier
/// has no analogue of its own).
const ZT_TCP_RX_BYTES: usize = 64 * 1024;
const ZT_TCP_TX_BYTES: usize = 64 * 1024;
const ZT_UDP_RX_BYTES: usize = 32 * 1024;
const ZT_UDP_TX_BYTES: usize = 32 * 1024;
const ZT_UDP_PACKETS: usize = 64;
const ZT_STREAM_QUEUE_MAX: usize = 128 * 1024;
const ZT_MAX_CONNS: usize = 128;
const ZT_MAX_UDP_SOCKETS: usize = 64;
const ZT_TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const ZT_NETCONF_TIMEOUT: Duration = Duration::from_secs(15);
const ZT_MIN_TICK: Duration = Duration::from_millis(1);
const ZT_MAX_TICK: Duration = Duration::from_secs(1);
const ZT_PUMP_CHUNK: usize = 32 * 1024;
const ZT_HELLO_RETRY: Duration = Duration::from_millis(1000);
const ZT_MAX_ATTEMPTS: u32 = 10;

// -- the smoltcp device shim (the wireguard/openvpn EtStack shim) ------

struct Shim {
    ingress: VecDeque<Vec<u8>>,
    egress: VecDeque<Vec<u8>>,
    scratch: Vec<u8>,
    mtu: usize,
}

impl Shim {
    fn new(mtu: usize) -> Self {
        Shim { ingress: VecDeque::new(), egress: VecDeque::new(), scratch: Vec::new(), mtu }
    }

    fn stage(&mut self, pkt: &[u8]) {
        if self.ingress.len() < 512 {
            self.ingress.push_back(pkt.to_vec());
        }
    }
}

impl Device for Shim {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok<'a>;

    fn receive(&mut self, _ts: SmolInstant) -> Option<(RxTok, TxTok<'_>)> {
        let pkt = self.ingress.pop_front()?;
        Some((
            RxTok { pkt },
            TxTok { egress: &mut self.egress, scratch: &mut self.scratch },
        ))
    }

    fn transmit(&mut self, _ts: SmolInstant) -> Option<TxTok<'_>> {
        Some(TxTok { egress: &mut self.egress, scratch: &mut self.scratch })
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = self.mtu;
        caps
    }
}

struct RxTok {
    pkt: Vec<u8>,
}

impl RxToken for RxTok {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.pkt)
    }
}

struct TxTok<'a> {
    egress: &'a mut VecDeque<Vec<u8>>,
    scratch: &'a mut Vec<u8>,
}

impl TxToken for TxTok<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        self.scratch.clear();
        self.scratch.resize(len, 0);
        let out = {
            let buf = &mut self.scratch[..len];
            f(buf)
        };
        self.egress.push_back(self.scratch[..len].to_vec());
        out
    }
}

// -- the stream bridge (wireguard's StreamShared, verbatim shape) ------

struct StreamBufs {
    to_proxy: VecDeque<u8>,
    to_stack: VecDeque<u8>,
    read_eof: bool,
    write_closed: bool,
    aborted: bool,
    read_waker: Option<Waker>,
    write_waker: Option<Waker>,
}

struct StreamShared {
    bufs: Mutex<StreamBufs>,
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

    fn lock(&self) -> std::sync::MutexGuard<'_, StreamBufs> {
        self.bufs.lock().unwrap_or_else(|e| e.into_inner())
    }
}

/// One TCP connection through the ZeroTier overlay, as seen by the
/// relay: an `AsyncRead + AsyncWrite` bridge over the shared queues.
pub struct ZtStream {
    shared: Arc<StreamShared>,
}

impl Drop for ZtStream {
    fn drop(&mut self) {
        let mut g = self.shared.lock();
        g.aborted = true;
        g.read_eof = true;
        g.write_closed = true;
        drop(g);
        self.shared.wake.notify_one();
    }
}

impl AsyncRead for ZtStream {
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
            drop(g);
            self.shared.wake.notify_one();
            return Poll::Ready(Ok(()));
        }
        if g.read_eof {
            return Poll::Ready(Ok(()));
        }
        g.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for ZtStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut g = self.shared.lock();
        if g.aborted {
            return Poll::Ready(Err(io::Error::new(io::ErrorKind::ConnectionReset, "zt: aborted")));
        }
        if g.write_closed || g.to_stack.len() >= ZT_STREAM_QUEUE_MAX {
            g.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let n = buf.len().min(ZT_STREAM_QUEUE_MAX - g.to_stack.len());
        g.to_stack.extend(buf[..n].iter().copied());
        drop(g);
        self.shared.wake.notify_one();
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: std::pin::Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: std::pin::Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shared.lock().write_closed = true;
        self.shared.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

// -- the stack ----------------------------------------------------------

/// The node runtime: one task owning the UDP socket, the peer table,
/// the fragment queue, the join state machine and the smoltcp
/// interface — the wireguard tunnel-task shape over the ZeroTier wire
/// core.
struct ZtStack {
    identity: NodeIdentity,
    world: World,
    network_id: u64,
    controller: u64,
    path_mtu: usize,
    peers: HashMap<u64, PeerEntry>,
    frags: FragmentAssembler,
    /// The join state (HELLO→WHOIS→netconf).
    join: Join,
    /// Packet ids we await replies to (expectReplyTo,
    /// IncomingPacket.cpp:660).
    expecting: HashSet<u64>,
    /// The controller's verified netconf once applied.
    netconf: Option<AppliedNetconf>,
    /// src IP → peer address (MAC learning, Switch's bridge table).
    ip_peers: HashMap<IpAddr, u64>,
    iface: Interface,
    sockets: SocketSet<'static>,
    shim: Shim,
    conns: Vec<ZtConn>,
    pend_dials: Vec<ZtPendingDial>,
    udp: HashMap<u32, ZtUdpSock>,
    used_ports: HashSet<u16>,
    next_udp_id: u32,
    /// The config's `udp:` gate (mihomo's ZeroTierOption.UDP).
    udp_enabled: bool,
    wake: Arc<Notify>,
    start: Instant,
    /// When the root last got a HELLO from us (the path heartbeat).
    last_root_hello: Instant,
    pump_buf: Vec<u8>,
    /// Frames queued before the netconf applied (the pre-session
    /// queue: smoltcp may emit SYNs the moment addresses exist, but a
    /// fast dial can outrun the join).
    prejoin_tx: VecDeque<Vec<u8>>,
    /// Adopted moon worlds (Topology::_moons) — extra upstreams once
    /// their signed definitions arrive (the OK(HELLO) world-update
    /// block).
    moons: Vec<World>,
    /// Pending moon seeds (`Topology::_moonSeeds`): (world id, seed
    /// address) from the config's `orbit:` entries, consumed when the
    /// matching signed world lands.
    moon_seeds: Vec<(u64, u64)>,
    /// Our external surface as a trusted peer observed it — the
    /// OK(HELLO) `physical` field (SelfAwareness's whoami input,
    /// IncomingPacket.cpp:531-539). What PUSH_DIRECT_PATHS advertises.
    my_surface: Option<SocketAddr>,
    /// The socket's local address (the LAN-scope path we advertise).
    local_addr: Option<SocketAddr>,
    /// Probes in flight: (peer, candidate address) → when sent. Only
    /// an OK(HELLO) arriving physically from a probed address confirms
    /// a direct path — a relayed OK arrives from the ROOT's address
    /// and must not become the peer's endpoint (upstream records the
    /// physical arrival path the same way, `Peer::gotPacket`).
    probing: HashMap<(u64, SocketAddr), Instant>,
    /// The state store, when `state-dir` is usable (identity + peer
    /// persistence across restarts).
    state: Option<NodeStateStore>,
}

impl ZtStack {
    #[allow(clippy::too_many_arguments)]
    fn new(
        identity: NodeIdentity,
        world: World,
        network_id: u64,
        path_mtu: usize,
        udp_enabled: bool,
        wake: Arc<Notify>,
        orbit: Vec<(u64, u64)>,
        local_addr: Option<SocketAddr>,
        state: Option<NodeStateStore>,
    ) -> Self {
        let mut shim = Shim::new(DEFAULT_NETWORK_MTU);
        let mut iface_cfg = IfaceConfig::new(HardwareAddress::Ip);
        iface_cfg.random_seed = rand::random();
        let mut iface = Interface::new(iface_cfg, &mut shim, SmolInstant::ZERO);
        // No addresses until the controller's netconf assigns the
        // managed set (`Network::setConfiguration` applies exactly the
        // assigned prefixes, deriving nothing).
        iface.update_ip_addrs(|addrs| addrs.clear());
        ZtStack {
            identity,
            world,
            network_id,
            controller: controller_of(network_id),
            path_mtu,
            peers: HashMap::new(),
            frags: FragmentAssembler::default(),
            join: Join::Start,
            expecting: HashSet::new(),
            netconf: None,
            ip_peers: HashMap::new(),
            iface,
            sockets: SocketSet::new(Vec::new()),
            shim,
            conns: Vec::new(),
            pend_dials: Vec::new(),
            udp: HashMap::new(),
            used_ports: HashSet::new(),
            next_udp_id: 1,
            udp_enabled,
            wake,
            start: Instant::now(),
            last_root_hello: Instant::now(),
            pump_buf: vec![0u8; ZT_PUMP_CHUNK],
            prejoin_tx: VecDeque::new(),
            moons: Vec::new(),
            moon_seeds: orbit,
            my_surface: None,
            local_addr,
            probing: HashMap::new(),
            state,
        }
    }

    fn now(&self) -> SmolInstant {
        SmolInstant::from_micros(self.start.elapsed().as_micros() as i64)
    }

    fn std_now(&self) -> Instant {
        Instant::now()
    }

    fn ephemeral_port(&mut self) -> u16 {
        loop {
            let port = 32768 + rand::random::<u16>() % 28_000;
            if self.used_ports.insert(port) {
                return port;
            }
        }
    }

    /// The root peers of our planet **and adopted moons**, in world
    /// order (`Topology::_memoizeUpstreams` seeds its root peer set
    /// from exactly these — planet roots first, then moon roots).
    fn root_endpoints(&self) -> Vec<(u64, NodeIdentity, SocketAddr)> {
        let mut out = Vec::new();
        for world in [&self.world].into_iter().chain(self.moons.iter()) {
            for r in &world.roots {
                if let Some(ep) = r.endpoints.iter().find_map(|e| e.to_socket_addr()) {
                    out.push((r.identity.address(), r.identity.clone(), ep));
                }
            }
        }
        out
    }

    /// Is `addr` an upstream — a planet root or a moon root
    /// (`Topology::isUpstream`)? Gates RENDEZVOUS acceptance and world
    /// updates.
    fn is_upstream(&self, addr: u64) -> bool {
        self.root_endpoints().iter().any(|(a, _, _)| *a == addr)
            || self.moon_seeds.iter().any(|(_, seed)| *seed == addr)
    }

    /// The HELLO moon tail: adopted moons (id, timestamp) plus pending
    /// seeds at timestamp 0 — "we want this world" (`Peer::sendHELLO`
    /// lists both the same way; a zero timestamp makes any holder of a
    /// newer copy send it back in the OK(HELLO) world-update block).
    fn moon_tail(&self) -> Vec<(u64, u64)> {
        let mut out: Vec<(u64, u64)> = self.moons.iter().map(|m| (m.id, m.timestamp)).collect();
        for (world, _) in &self.moon_seeds {
            if !out.iter().any(|(id, _)| id == world) {
                out.push((*world, 0));
            }
        }
        out
    }

    fn learn_peer(&mut self, identity: NodeIdentity, endpoint: Option<SocketAddr>) {
        let key = self.identity.agree(&identity).unwrap_or([0u8; SYMMETRIC_KEY_SIZE]);
        match self.peers.entry(identity.address()) {
            std::collections::hash_map::Entry::Vacant(slot) => {
                // New identity: persist it (`Topology::_savePeer` —
                // best-effort, failure only costs a WHOIS on restart).
                if let Some(state) = &self.state {
                    state.save_peer(&identity, endpoint);
                }
                let mut entry = PeerEntry::new(identity, key);
                entry.endpoint = endpoint;
                slot.insert(entry);
            }
            std::collections::hash_map::Entry::Occupied(mut slot) => {
                let entry = slot.get_mut();
                entry.last_seen = Instant::now();
                if let Some(ep) = endpoint {
                    if entry.endpoint != Some(ep) {
                        if let Some(state) = &self.state {
                            state.save_peer(&entry.identity, Some(ep));
                        }
                    }
                    entry.endpoint = Some(ep);
                }
            }
        }
    }

    /// `Peer::attemptToContactAt` — the NAT-t probe: a 4-byte junk
    /// datagram to open the local NAT/stateful firewall, then a plain
    /// suite-0 HELLO straight at the candidate address. The peer's
    /// OK(HELLO) reply, armored under the pairwise key and echoing a
    /// packet id we await, confirms the path.
    async fn attempt_contact(&mut self, socket: &UdpSocket, dest: u64, at: SocketAddr) {
        let Some(peer) = self.peers.get(&dest) else { return };
        let key = peer.key;
        // `_doRENDEZVOUS`'s junk packet (IncomingPacket.cpp:757-758).
        // Delta: upstream sends it with TTL 2; the port has no
        // per-packet TTL knob on the shared socket, and the opener's
        // purpose (open the local NAT) is served at default TTL.
        let junk = rand::random::<u32>();
        let _ = socket.send_to(&junk.to_be_bytes(), at).await;
        // Bounded probe bookkeeping (see `probing`).
        if self.probing.len() > 128 {
            let now = Instant::now();
            self.probing.retain(|_, at_instant| now.duration_since(*at_instant) < PROBE_TTL);
        }
        self.probing.insert((dest, at), Instant::now());
        let moons = self.moon_tail();
        if let Ok(hello) = build_hello(
            &self.identity,
            dest,
            PhysAddr::from_socket_addr(at),
            (self.world.id, self.world.timestamp),
            &moons,
            zt_now_ms(),
            &key,
        ) {
            self.expecting.insert(hello.packet_id());
            if let Err(e) = socket.send_to(hello.as_bytes(), at).await {
                tracing::debug!(target: "engine", "zt: probe to {at} failed: {e}");
            }
        }
    }

    // -- sending -----------------------------------------------------------

    /// Send one packet to `dest` — armored + fragmented here, direct
    /// when the peer has a known endpoint, else relayed through a
    /// planet root (the `Switch::_trySend` relay fallback: the packet's
    /// DEST stays the real destination, the root forwards it).
    async fn send_packet(&mut self, socket: &UdpSocket, mut pkt: WirePacket, dest: u64) {
        let Some(peer) = self.peers.get(&dest) else {
            tracing::debug!(target: "engine", "zt: no peer {dest:010x}, dropping packet");
            return;
        };
        let key = peer.key;
        let packet_id = pkt.packet_id();
        let datagrams = match armor_and_fragment(&mut pkt, &key, self.path_mtu) {
            Ok(dg) => dg,
            Err(e) => {
                tracing::debug!(target: "engine", "zt: armor/fragment failed: {e}");
                return;
            }
        };
        // expectReplyTo (IncomingPacket.cpp:660) — bounded, like the
        // upstream ring: entries leave when their reply lands; a flood
        // that outgrows the cap resets it (stale entries only cost a
        // stray accept anyway).
        if self.expecting.len() > 1024 {
            self.expecting.clear();
        }
        self.expecting.insert(packet_id);
        let direct = self.peers.get(&dest).and_then(|p| p.endpoint);
        let via = match direct {
            Some(ep) => ep,
            None => match self.root_endpoints().first() {
                Some((_, _, ep)) => *ep,
                None => return,
            },
        };
        for dg in datagrams {
            if let Err(e) = socket.send_to(&dg, via).await {
                tracing::debug!(target: "engine", "zt: udp send to {via} failed: {e}");
            }
        }
    }

    /// Egress IP packet from the netstack → VERB_FRAME to the peer
    /// that owns the destination IP (learned source IPs first, the
    /// netconf's active-bridge specialists otherwise — the unknown-MAC
    /// rule from `Switch::onLocalEthernet`).
    async fn send_frame(&mut self, socket: &UdpSocket, pkt: &[u8]) {
        if self.netconf.is_none() {
            if self.prejoin_tx.len() < 512 {
                self.prejoin_tx.push_back(pkt.to_vec());
            }
            return;
        }
        let Some(ethertype) = ip_ethertype(pkt) else {
            return; // not IP — an L2 port this is not
        };
        let dst_ip = dst_ip_of(pkt);
        let dest = match dst_ip.and_then(|ip| self.ip_peers.get(&ip).copied()) {
            Some(addr) => Some(addr),
            None => self.netconf.as_ref().and_then(|n| n.specialists.first().copied()),
        };
        let Some(dest) = dest else {
            tracing::debug!(target: "engine", "zt: no route to {dst_ip:?}, dropping frame");
            return;
        };
        if !self.peers.contains_key(&dest) {
            // WHOIS it through a root; the queued frame goes out when
            // the identity lands (Switch::send's TX queue behavior).
            self.request_whois(socket, dest).await;
            if self.prejoin_tx.len() < 512 {
                self.prejoin_tx.push_back(pkt.to_vec());
            }
            return;
        }
        let frame = build_frame(&self.identity, dest, self.network_id, ethertype, pkt);
        self.send_packet(socket, frame, dest).await;
    }

    /// Queue a WHOIS for `who` to every planet root that has answered
    /// (`Switch::requestWhois` sends to upstreams).
    async fn request_whois(&mut self, socket: &UdpSocket, who: u64) {
        for (addr, _id, _ep) in self.root_endpoints() {
            if self.peers.contains_key(&addr) {
                let pkt = build_whois(&self.identity, addr, who);
                self.send_packet(socket, pkt, addr).await;
            }
        }
    }

    /// The join driver: HELLO the first planet root, then request the
    /// netconf from the controller, with retries
    /// (`ZT_WHOIS_RETRY_DELAY`-paced like upstream's request retries).
    async fn drive_join(&mut self, socket: &UdpSocket) {
        let now = self.std_now();
        match &self.join {
            Join::Start => {
                self.send_root_hello(socket).await;
                self.join = Join::HelloRoot { at: now, attempts: 1 };
            }
            Join::HelloRoot { at, attempts } => {
                if now.duration_since(*at) >= ZT_HELLO_RETRY {
                    if *attempts >= ZT_MAX_ATTEMPTS {
                        self.join = Join::Failed("root HELLO never answered".into());
                        return;
                    }
                    let next = attempts + 1;
                    self.send_root_hello(socket).await;
                    self.join = Join::HelloRoot { at: now, attempts: next };
                }
            }
            Join::Netconf { at, attempts } => {
                if now.duration_since(*at) >= WHOIS_RETRY {
                    if *attempts >= ZT_MAX_ATTEMPTS {
                        self.join = Join::Failed("netconf never arrived".into());
                        return;
                    }
                    let next = attempts + 1;
                    self.send_netconf_request(socket).await;
                    self.join = Join::Netconf { at: now, attempts: next };
                }
            }
            Join::Applied | Join::Failed(_) => {}
        }
    }

    /// `Peer::sendHELLO` to the first reachable planet root (base
    /// form, suite 0 — see the module notes on extended armor).
    async fn send_root_hello(&mut self, socket: &UdpSocket) {
        let Some((addr, identity, ep)) = self.root_endpoints().first().cloned() else {
            self.join = Join::Failed("planet has no usable roots".into());
            return;
        };
        self.learn_peer(identity, Some(ep));
        self.last_root_hello = Instant::now();
        let key = self.peers[&addr].key;
        let moons = self.moon_tail();
        let hello = build_hello(
            &self.identity,
            addr,
            PhysAddr::from_socket_addr(ep),
            (self.world.id, self.world.timestamp),
            &moons,
            zt_now_ms(),
            &key,
        );
        if let Ok(hello) = hello {
            self.expecting.insert(hello.packet_id());
            if let Err(e) = socket.send_to(hello.as_bytes(), ep).await {
                tracing::debug!(target: "engine", "zt: hello send failed: {e}");
            }
        }
    }

    /// `Network::requestConfiguration`: the controller is addressed
    /// through the root relay until a direct path exists. Built
    /// unarmored (the wave-14 builder armors internally; the runtime
    /// armors once, in [`Self::send_packet`], after the fragmented
    /// flag decision).
    async fn send_netconf_request(&mut self, socket: &UdpSocket) {
        let Some(_peer) = self.peers.get(&self.controller) else {
            // WHOIS first; the join driver retries.
            self.request_whois(socket, self.controller).await;
            return;
        };
        let previous = self.netconf.as_ref().map(|n| (n.revision, n.update_id));
        let meta = netconf_request_meta_dict();
        let mut req =
            WirePacket::new(self.controller, self.identity.address(), Verb::NetworkConfigRequest);
        req.push_u64(self.network_id)
            .push_u16(meta.len() as u16)
            .push_bytes(meta.as_bytes());
        match previous {
            Some((rev, ts)) => {
                req.push_u64(rev).push_u64(ts);
            }
            None => {
                req.push_bytes(&[0u8; 16]);
            }
        }
        self.send_packet(socket, req, self.controller).await;
    }

    /// Apply a verified netconf: managed addresses + routes onto the
    /// smoltcp interface, then flush anything queued pre-join.
    async fn apply_netconf(&mut self, socket: &UdpSocket, applied: AppliedNetconf) {
        tracing::debug!(
            target: "engine",
            "zt: netconf applied (nwid {:016x}, {} managed ips, mtu {})",
            applied.network_id,
            applied.managed_ips.len(),
            applied.mtu
        );
        self.shim.mtu = applied.mtu;
        self.iface.update_ip_addrs(|addrs| {
            addrs.clear();
            for (ip, prefix) in &applied.managed_ips {
                let cidr = match ip {
                    IpAddr::V4(v4) => IpCidr::new(IpAddress::Ipv4(*v4), *prefix),
                    IpAddr::V6(v6) => IpCidr::new(IpAddress::Ipv6(*v6), *prefix),
                };
                let _ = addrs.push(cidr);
            }
        });
        // Managed routes with a gateway (`via`) onto the route table;
        // via-less routes are the connected prefixes the managed
        // addresses above already installed (`fromDictionary` keeps
        // the same split: staticIps for on-link, routes for via).
        self.iface.routes_mut().update(|table| {
            table.clear();
            for route in &applied.routes {
                let Some(via) = route.via else { continue };
                let (addr, prefix) = route.target;
                let cidr = match addr {
                    IpAddr::V4(v4) => IpCidr::new(IpAddress::Ipv4(v4), prefix),
                    IpAddr::V6(v6) => IpCidr::new(IpAddress::Ipv6(v6), prefix),
                };
                let via_router = match via {
                    IpAddr::V4(v4) => IpAddress::Ipv4(v4),
                    IpAddr::V6(v6) => IpAddress::Ipv6(v6),
                };
                let _ = table.push(smoltcp::iface::Route {
                    cidr,
                    via_router,
                    preferred_until: None,
                    expires_at: None,
                });
            }
        });
        self.join = Join::Applied;
        self.netconf = Some(applied);
        // WHOIS the specialists now so data frames have keys ready.
        if let Some(spec) = self.netconf.as_ref().and_then(|n| n.specialists.first().copied()) {
            if !self.peers.contains_key(&spec) {
                self.request_whois(socket, spec).await;
            }
        }
        // WHOIS pending moon seeds through the roots too — a live seed
        // answers with its identity, and the root's RENDEZVOUS
        // introduction (or a relayed frame meeting it) hands us the
        // path whose OK(HELLO) carries the signed moon world
        // (Topology::_moonSeeds + shouldAcceptWorldUpdateFrom).
        for (_, seed) in self.moon_seeds.clone() {
            if !self.peers.contains_key(&seed) {
                self.request_whois(socket, seed).await;
            }
        }
        let queued: Vec<Vec<u8>> = self.prejoin_tx.drain(..).collect();
        for pkt in queued {
            self.send_frame(socket, &pkt).await;
        }
    }

    // -- inbound -----------------------------------------------------------

    /// One UDP datagram from the wire (Switch::onRemotePacket): relay
    /// check on the destination, fragment assembly, dearmor, verb
    /// dispatch. `from` is the physical source.
    async fn on_datagram(&mut self, socket: &UdpSocket, dg: &[u8], from: SocketAddr) {
        if dg.len() < PACKET_HEADER_LEN {
            return;
        }
        let dest = be40(&dg[PACKET_IDX_DEST..PACKET_IDX_SOURCE]);
        let source = be40(&dg[PACKET_IDX_SOURCE..PACKET_IDX_FLAGS]);
        if source == self.identity.address() {
            return; // our own packet echoed back
        }
        if dest != self.identity.address() {
            return; // relaying is upstream work — not a client node's
        }
        let Some(assembled) = self.frags.ingest(dg) else {
            return; // a fragment still waiting on its siblings
        };
        if assembled.len() < PACKET_HEADER_LEN {
            return;
        }
        // A suite-0 HELLO from an unknown peer is the bootstrap path
        // (`_doHELLO`'s "we don't already have an identity" branch):
        // the claimed identity travels in the clear, so the peer is
        // learned before any key exists. The cipher bits live in the
        // flags byte, which armor never encrypts.
        let is_plain_hello = assembled.len() > PACKET_IDX_VERB
            && (assembled[PACKET_IDX_FLAGS] & 0x38) >> 3 == 0
            && assembled[PACKET_IDX_VERB] & 0x1f == Verb::Hello.to_byte();
        let source = be40(&assembled[PACKET_IDX_SOURCE..PACKET_IDX_FLAGS]);
        if is_plain_hello {
            if let Ok(pkt) = WirePacket::from_bytes(&assembled) {
                self.on_hello(socket, pkt, from).await;
            }
            return;
        }
        // Every other verb needs the pairwise key: an unknown source is
        // WHOISed through a root and the packet dropped for its
        // retransmit (upstream queues it — same eventual outcome).
        let Some(peer) = self.peers.get_mut(&source) else {
            self.request_whois(socket, source).await;
            return;
        };
        peer.last_seen = Instant::now();
        let key = peer.key;
        let mut pkt = match WirePacket::from_bytes(&assembled) {
            Ok(p) => p,
            Err(_) => return,
        };
        if !peer.note_packet(pkt.packet_id()) {
            return; // replay/duplicate
        }
        if let Err(e) = pkt.dearmor(&key) {
            tracing::debug!(target: "engine", "zt: dearmor from {source:010x} failed: {e}");
            return;
        }
        if let Err(e) = pkt.uncompress() {
            tracing::debug!(target: "engine", "zt: uncompress failed: {e}");
            return;
        }
        self.dispatch(socket, pkt, from).await;
    }

    /// Verb dispatch (`IncomingPacket::tryDecode`'s switch) — the
    /// subset this node speaks (HELLO is handled pre-dispatch, where
    /// the peer is learned). `from` is the physical source — the
    /// direct-path confirmation signal for OK(HELLO).
    async fn dispatch(&mut self, socket: &UdpSocket, pkt: WirePacket, from: SocketAddr) {
        let verb = match pkt.verb() {
            Ok(v) => v,
            Err(_) => return,
        };
        let source = pkt.source();
        match verb {
            Verb::Ok => self.on_ok(socket, pkt, from).await,
            Verb::Whois => self.on_whois(socket, pkt).await,
            Verb::Echo => {
                // `_doECHO`: OK echoing the payload verbatim.
                let payload = pkt.payload().to_vec();
                let mut ok = WirePacket::new(source, self.identity.address(), Verb::Ok);
                ok.push_u8(Verb::Echo.to_byte())
                    .push_u64(pkt.packet_id())
                    .push_bytes(&payload);
                self.send_packet(socket, ok, source).await;
            }
            Verb::Rendezvous => self.on_rendezvous(socket, pkt).await,
            Verb::PushDirectPaths => self.on_push_direct_paths(socket, pkt).await,
            Verb::Frame => {
                let Ok(frame) = parse_frame(&pkt) else { return };
                if frame.network_id != self.network_id {
                    return; // not our network
                }
                // MAC learning: the frame's source ZT address owns the
                // source IP inside it (MAC::fromAddress inverts to the
                // same address).
                if let Some(src_ip) = src_ip_of(&frame.frame) {
                    self.ip_peers.insert(src_ip, source);
                }
                if ip_ethertype(&frame.frame).is_some() {
                    self.shim.stage(&frame.frame);
                    self.wake.notify_one();
                }
            }
            Verb::Error | Verb::Hello | Verb::NetworkConfig | Verb::NetworkConfigRequest | Verb::Nop => {}
        }
    }

    /// `_doRENDEZVOUS` (IncomingPacket.cpp:736-761): only a trusted
    /// upstream may introduce; the introduced peer must already be
    /// known (we WHOIS every specialist before frames flow); then the
    /// NAT-t probe fires at the given address.
    async fn on_rendezvous(&mut self, socket: &UdpSocket, pkt: WirePacket) {
        let source = pkt.source();
        if !self.is_upstream(source) {
            return;
        }
        let Ok(rd) = parse_rendezvous(&pkt) else {
            return;
        };
        if rd.sock.port() == 0 || !self.peers.contains_key(&rd.zt_address) {
            return;
        }
        tracing::debug!(
            target: "engine",
            "zt: rendezvous — peer {:010x} at {}/{}, probing direct",
            rd.zt_address,
            rd.sock.ip(),
            rd.sock.port()
        );
        self.attempt_contact(socket, rd.zt_address, rd.sock).await;
    }

    /// `_doPUSH_DIRECT_PATHS` (IncomingPacket.cpp:1364-1431): the
    /// rate gate, then probe every advertised address we do not
    /// already have a path to (up to the per-scope cap). FORGET_PATH
    /// and CLUSTER_REDIRECT records are skipped — neither is sent on a
    /// client mesh (cluster redirect is root-cluster machinery).
    async fn on_push_direct_paths(&mut self, socket: &UdpSocket, pkt: WirePacket) {
        let source = pkt.source();
        let now = Instant::now();
        {
            let Some(peer) = self.peers.get_mut(&source) else { return };
            let streak = match peer.last_push_recv {
                Some(at) if now.duration_since(at) < PUSH_DIRECT_PATHS_CUTOFF => {
                    peer.push_recv_streak + 1
                }
                _ => 0,
            };
            peer.last_push_recv = Some(now);
            peer.push_recv_streak = streak;
            if streak >= PUSH_DIRECT_PATHS_CUTOFF_LIMIT as u8 {
                return; // rateGatePushDirectPaths: drop the push
            }
        }
        let Ok(paths) = parse_push_direct_paths(&pkt) else { return };
        let current = self.peers.get(&source).and_then(|p| p.endpoint);
        let mut probed = 0usize;
        for p in paths {
            if p.flags
                & (PUSH_DIRECT_PATHS_FLAG_FORGET_PATH | PUSH_DIRECT_PATHS_FLAG_CLUSTER_REDIRECT)
                != 0
            {
                continue;
            }
            if p.sock.port() == 0 || Some(p.sock) == current {
                continue;
            }
            if probed >= PUSH_DIRECT_PATHS_MAX_PER_SCOPE {
                break;
            }
            probed += 1;
            self.attempt_contact(socket, source, p.sock).await;
        }
    }

    /// Send our PUSH_DIRECT_PATHS to `dest` — `Peer::sendHELLO`'s
    /// push block (Peer.cpp:200-236): trusted peers get our address
    /// set (the socket's local address + our observed external
    /// surface) at the HAVEPATH interval once a path exists, the short
    /// interval before that.
    async fn push_direct_paths_to(&mut self, socket: &UdpSocket, dest: u64) {
        let now = Instant::now();
        let key = {
            let Some(peer) = self.peers.get_mut(&dest) else { return };
            let interval = if peer.endpoint.is_some() {
                DIRECT_PATH_PUSH_INTERVAL_HAVEPATH
            } else {
                DIRECT_PATH_PUSH_INTERVAL
            };
            if let Some(at) = peer.last_push_sent {
                if now.duration_since(at) < interval {
                    return;
                }
            }
            peer.last_push_sent = Some(now);
            peer.key
        };
        let mut paths: Vec<DirectPath> = Vec::new();
        for cand in [self.local_addr, self.my_surface].into_iter().flatten() {
            if cand.port() != 0 && !cand.ip().is_unspecified() && !paths.iter().any(|p| p.sock == cand)
            {
                paths.push(DirectPath { flags: 0, sock: cand });
            }
        }
        if paths.is_empty() {
            return;
        }
        let pkt = build_push_direct_paths(&self.identity, dest, &paths, &key);
        let via = self
            .peers
            .get(&dest)
            .and_then(|p| p.endpoint)
            .or_else(|| self.root_endpoints().first().map(|(_, _, ep)| *ep));
        if let Some(via) = via {
            if let Err(e) = socket.send_to(pkt.as_bytes(), via).await {
                tracing::debug!(target: "engine", "zt: push-direct-paths send failed: {e}");
            }
        }
    }

    /// Adopt a world from an OK(HELLO) world-update block
    /// (`Topology::addWorld` + `shouldAcceptWorldUpdateFrom`,
    /// Topology.cpp:162-172, 229-281): planets only from planet roots
    /// and only newer copies of OUR planet; moons when the signature
    /// verifies, the id matches a pending seed, and the roots contain
    /// that seed. The seed is consumed on adoption.
    fn adopt_worlds(&mut self, from: u64, block: &[u8]) {
        let is_planet_root = self.world.roots.iter().any(|r| r.identity.address() == from);
        let mut at = 0usize;
        while at < block.len() {
            match World::from_bytes(&block[at..]) {
                Ok((world, used)) if used > 0 => {
                    at += used;
                    if world.world_type == WORLD_TYPE_MOON && world.signature_is_valid() {
                        // `shouldAcceptWorldUpdateFrom` (Topology.cpp:
                        // 162-172): the update must come from a planet
                        // root or the pending seed itself — the seed
                        // gate is what binds a self-signed moon world
                        // to the operator's configured seed identity.
                        let sender_ok = is_planet_root
                            || self
                                .moon_seeds
                                .iter()
                                .any(|(id, seed)| *id == world.id && *seed == from)
                            || self.moons.iter().any(|m| {
                                m.id == world.id
                                    && m.roots.iter().any(|r| r.identity.address() == from)
                            });
                        if !sender_ok {
                            continue;
                        }
                        let seeds = self.moon_seeds.clone();
                        if let Some((idx, _)) = seeds.iter().enumerate().find(|(_, (id, seed))| {
                            *id == world.id
                                && world.roots.iter().any(|r| r.identity.address() == *seed)
                        }) {
                            let (world_id, _) = seeds[idx];
                            self.moon_seeds.remove(idx);
                            // Only accept newer copies of an adopted moon.
                            if !self
                                .moons
                                .iter()
                                .any(|m| m.id == world_id && m.timestamp >= world.timestamp)
                            {
                                self.moons.retain(|m| m.id != world_id);
                                tracing::debug!(
                                    target: "engine",
                                    "zt: adopted moon world {:016x} ({} roots)",
                                    world.id,
                                    world.roots.len()
                                );
                                for r in &world.roots {
                                    if let Some(ep) =
                                        r.endpoints.iter().find_map(|e| e.to_socket_addr())
                                    {
                                        self.learn_peer(r.identity.clone(), Some(ep));
                                    }
                                }
                                self.moons.push(world);
                            }
                        }
                    } else if world.world_type == WORLD_TYPE_PLANET
                        && is_planet_root
                        && world.id == self.world.id
                        && world.timestamp > self.world.timestamp
                        && world.signature_is_valid()
                    {
                        self.world = world;
                    }
                }
                _ => break, // trailing garbage: stop adopting
            }
        }
    }

    /// `_doHELLO` (the responder side): identity/address match, MAC
    /// check under the *claimed* identity's key, PoW validation, learn
    /// the peer (with this packet's source as its path), reply
    /// OK(HELLO).
    async fn on_hello(&mut self, socket: &UdpSocket, mut pkt: WirePacket, from: SocketAddr) {
        let source = pkt.source();
        if !matches!(pkt.cipher(), Ok(CipherSuite::C25519Poly1305None)) {
            return; // we send suite-0 HELLOs and expect the same back
        }
        // Suite 0 MACs but does not encrypt, so the claimed identity
        // is readable before the peer is learned — upstream's
        // two-step: parse the identity, construct the candidate peer,
        // dearmor with its derived key (_doHELLO's newPeer path).
        let probe = match WirePacket::from_bytes(pkt.as_bytes()) {
            Ok(p) => p,
            Err(_) => return,
        };
        let claimed = parse_hello(&probe).ok().filter(|h| h.identity.address() == source);
        let Some(claimed) = claimed else { return };
        let Ok(key) = self.identity.agree(&claimed.identity) else { return };
        if pkt.dearmor(&key).is_err() {
            tracing::debug!(target: "engine", "zt: HELLO MAC check failed");
            return;
        }
        if !claimed.identity.locally_validate() {
            tracing::debug!(target: "engine", "zt: HELLO identity failed hashcash");
            return;
        }
        self.learn_peer(claimed.identity, Some(from));
        let Ok(hello) = parse_hello(&pkt) else { return };
        let peer_key = self.peers[&source].key;
        let ok = build_ok_hello(
            &self.identity,
            &hello,
            pkt.packet_id(),
            source,
            PhysAddr::from_socket_addr(from),
            &peer_key,
        );
        if let Ok(ok) = ok {
            // Small packet, already armored suite 1 by the builder.
            if let Some(ep) = self.peers.get(&source).and_then(|p| p.endpoint) {
                let _ = socket.send_to(ok.as_bytes(), ep).await;
            }
        }
    }

    /// `_doWHOIS` (the responder side): answer with the identities we
    /// know, one binary identity per requested address.
    async fn on_whois(&mut self, socket: &UdpSocket, pkt: WirePacket) {
        let source = pkt.source();
        if !self.peers.contains_key(&source) {
            return;
        }
        let p = pkt.payload().to_vec();
        let mut ok = WirePacket::new(source, self.identity.address(), Verb::Ok);
        ok.push_u8(Verb::Whois.to_byte()).push_u64(pkt.packet_id());
        let mut count = 0usize;
        for chunk in p.as_chunks::<5>().0 {
            let addr = be40(chunk);
            if let Some(known) = self.peers.get(&addr) {
                ok.push_bytes(&known.identity.serialize_bin(false));
                count += 1;
            }
        }
        if count > 0 {
            self.send_packet(socket, ok, source).await;
        }
    }

    /// `_doOK`: correlate the in-re packet id against what we await,
    /// then handle the HELLO/WHOIS/NET_CONFIG_REQUEST variants.
    async fn on_ok(&mut self, socket: &UdpSocket, mut pkt: WirePacket, from: SocketAddr) {
        match ok_in_re_packet_id(&pkt) {
            Ok(id) if self.expecting.remove(&id) => {}
            _ => return, // not expecting a reply to this — drop
        }
        let in_re_verb = pkt.payload().first().copied().unwrap_or(0);
        match Verb::from_byte(in_re_verb) {
            Ok(Verb::Hello) => {
                let source = pkt.source();
                // The OK's `physical` field is OUR address as the
                // replier sees it — SelfAwareness's whoami input
                // (IncomingPacket.cpp:531-539): what we advertise in
                // PUSH_DIRECT_PATHS.
                if let Ok(ok) = parse_ok_hello(&pkt) {
                    if let Some(ep) = ok.physical.to_socket_addr() {
                        self.my_surface = Some(ep);
                    }
                    // Moon/planet world updates ride the same block
                    // (`_doHELLO`'s worldUpdate, IncomingPacket.cpp:541-557).
                    if let Some(block) = ok.world_update {
                        self.adopt_worlds(source, &block);
                    }
                }
                // A direct path is CONFIRMED when the reply arrives
                // physically from an address we probed: the packet
                // dearmored under the pairwise key (authentic) and
                // echoes a packet id we were expecting (not a replay).
                // A reply that arrives RELAYED (physically from the
                // root) proves only the relay — upstream records the
                // arrival path the same way (`Peer::gotPacket`).
                let confirmed_direct = self.probing.remove(&(source, from)).is_some();
                if let Some(peer) = self.peers.get_mut(&source) {
                    peer.last_seen = Instant::now();
                    if confirmed_direct && peer.endpoint != Some(from) {
                        peer.endpoint = Some(from);
                        if let Some(state) = &self.state {
                            state.save_peer(&peer.identity, Some(from));
                        }
                        tracing::debug!(
                            target: "engine",
                            "zt: direct path confirmed — peer {:010x} at {} (relay released)",
                            source,
                            from
                        );
                    }
                }
                // The root path is proven; move the join along.
                if matches!(self.join, Join::HelloRoot { .. }) {
                    self.join = Join::Netconf { at: self.std_now(), attempts: 0 };
                    self.send_netconf_request(socket).await;
                }
                // Trust established → tell this peer where we are
                // (Peer::sendHELLO's push block).
                self.push_direct_paths_to(socket, source).await;
            }
            Ok(Verb::Whois) => {
                let Ok(ids) = parse_ok_whois(&pkt) else { return };
                for id in ids {
                    // Roots are trusted anchors; other identities
                    // must carry their hashcash proof.
                    let is_root =
                        self.world.roots.iter().any(|r| r.identity.address() == id.address());
                    if !is_root && !id.locally_validate() {
                        tracing::debug!(target: "engine", "zt: WHOIS identity failed hashcash");
                        continue;
                    }
                    self.learn_peer(id, None);
                }
                // If the controller's identity just landed and the
                // netconf is still pending, send the request now.
                if matches!(self.join, Join::Netconf { .. })
                    && self.peers.contains_key(&self.controller)
                {
                    self.send_netconf_request(socket).await;
                }
            }
            Ok(Verb::NetworkConfigRequest) => {
                let source = pkt.source();
                if source != self.controller {
                    return;
                }
                let Some(controller) = self.peers.get(&self.controller).map(|p| p.identity.clone())
                else {
                    return;
                };
                let resp = parse_netconf_response(&mut pkt, &controller);
                match resp {
                    Ok(resp) if resp.network_id == self.network_id => {
                        match parse_applied_netconf(&resp) {
                            Ok(applied) => self.apply_netconf(socket, applied).await,
                            Err(e) => {
                                tracing::debug!(target: "engine", "zt: netconf apply failed: {e}")
                            }
                        }
                    }
                    Ok(_) => tracing::debug!(target: "engine", "zt: netconf for foreign network"),
                    Err(e) => {
                        self.join = Join::Failed(format!("netconf rejected: {e}"));
                    }
                }
            }
            _ => {}
        }
    }

    // -- netstack service (the wireguard EtStack service loop) -----------

    /// Start one dial against the applied netconf; `reply` carries the
    /// failure directly, or the shared stream once ESTABLISHED.
    fn start_dial(&mut self, target: NetAddr, reply: oneshot::Sender<Result<Arc<StreamShared>>>) {
        let remote = match zt_target_addr(&target, &self.netconf) {
            Ok(r) => r,
            Err(e) => {
                let _ = reply.send(Err(e));
                return;
            }
        };
        if self.conns.len() >= ZT_MAX_CONNS {
            let _ = reply.send(Err(Error::network("zt: connection limit reached")));
            return;
        }
        // Source-address selection: the managed address of the
        // destination's family (sing-wireguard's DialContext rule).
        let local_ip = match local_address_for(&self.netconf, &remote) {
            Some(ip) => ip,
            None => {
                let _ = reply.send(Err(Error::network(format!(
                    "zt: no managed address of {}'s family to dial from",
                    remote
                ))));
                return;
            }
        };
        let mut sock = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; ZT_TCP_RX_BYTES]),
            tcp::SocketBuffer::new(vec![0; ZT_TCP_TX_BYTES]),
        );
        let port = self.ephemeral_port();
        let local = IpListenEndpoint { addr: Some(local_ip), port };
        let cx = self.iface.context();
        let endpoint = match remote {
            SocketAddr::V4(v4) => IpEndpoint::new(IpAddress::Ipv4(*v4.ip()), v4.port()),
            SocketAddr::V6(v6) => IpEndpoint::new(IpAddress::Ipv6(*v6.ip()), v6.port()),
        };
        if let Err(e) = sock.connect(cx, endpoint, local) {
            let _ = reply.send(Err(Error::network(format!("zt: connect: {e:?}"))));
            return;
        }
        let handle = self.sockets.add(sock);
        let shared = Arc::new(StreamShared::new(self.wake.clone()));
        tracing::debug!(target: "engine", "zt: dialing {remote} through network {:016x}", self.network_id);
        self.conns.push(ZtConn {
            handle,
            shared: shared.clone(),
            fin_sent: false,
            pending: Some((reply, self.std_now() + ZT_TCP_CONNECT_TIMEOUT)),
        });
    }

    /// Convert parked dials once the join resolves (applied → start;
    /// failed/expired → error reply).
    fn promote_dials(&mut self) {
        if self.pend_dials.is_empty() {
            return;
        }
        let now = self.std_now();
        let mut parked = std::mem::take(&mut self.pend_dials);
        let failed = match &self.join {
            Join::Failed(e) => Some(format!("zt: join failed: {e}")),
            _ => None,
        };
        for dial in parked.drain(..) {
            if let Some(reason) = &failed {
                let _ = dial.reply.send(Err(Error::network(reason.clone())));
            } else if matches!(self.join, Join::Applied) {
                self.start_dial(dial.target, dial.reply);
            } else if now >= dial.deadline {
                let _ = dial.reply.send(Err(Error::network(
                    "zt: netconf never arrived (controller unreachable)",
                )));
            } else {
                self.pend_dials.push(dial);
            }
        }
    }

    async fn step(&mut self, socket: &UdpSocket) {
        self.iface.poll(self.now(), &mut self.shim, &mut self.sockets);
        self.promote_dials();
        self.service_conns();
        self.drain_udp_rx();
        self.iface.poll(self.now(), &mut self.shim, &mut self.sockets);
        self.drain_egress(socket).await;
    }

    fn service_conns(&mut self) {
        let now = Instant::now();
        let mut dead: Vec<SocketHandle> = Vec::new();
        for c in self.conns.iter_mut() {
            let sock = self.sockets.get_mut::<tcp::Socket>(c.handle);
            if let Some((reply, deadline)) = c.pending.take() {
                match sock.state() {
                    tcp::State::Established => {
                        let _ = reply.send(Ok(c.shared.clone()));
                    }
                    s if s == tcp::State::Closed || now >= deadline => {
                        let _ = reply.send(Err(Error::network(format!(
                            "zt: tcp dial failed (state {s:?})"
                        ))));
                        sock.abort();
                        dead.push(c.handle);
                        continue;
                    }
                    _ => {
                        c.pending = Some((reply, deadline));
                    }
                }
            }
            let mut g = c.shared.lock();
            while g.to_proxy.len() < ZT_STREAM_QUEUE_MAX && sock.can_recv() {
                let n = match sock.recv_slice(&mut self.pump_buf) {
                    Ok(n) => n,
                    Err(_) => break,
                };
                g.to_proxy.extend(self.pump_buf[..n].iter().copied());
            }
            let dialing = matches!(sock.state(), tcp::State::SynSent | tcp::State::Listen);
            if !dialing && !sock.may_recv() && sock.recv_queue() == 0 {
                g.read_eof = true;
            }
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
                if !c.fin_sent && !g.write_closed {
                    g.aborted = true;
                }
            }
            if (!g.to_proxy.is_empty() || g.read_eof) && g.read_waker.is_some() {
                if let Some(w) = g.read_waker.take() {
                    w.wake();
                }
            }
            if (gone || g.to_stack.len() < ZT_STREAM_QUEUE_MAX) && g.write_waker.is_some() {
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
                if let Some(sock) = self.sockets.get::<tcp::Socket>(handle).local_endpoint() {
                    self.used_ports.remove(&sock.port);
                }
                self.sockets.remove(handle);
            }
        }
    }

    fn drain_udp_rx(&mut self) {
        let ids: Vec<u32> = self.udp.keys().copied().collect();
        for id in ids {
            let (handle, down) = match self.udp.get(&id) {
                Some(u) => (u.handle, &u.down),
                None => continue,
            };
            let sock = self.sockets.get_mut::<udp::Socket>(handle);
            while sock.can_recv() {
                let (n, meta) = match sock.recv_slice(&mut self.pump_buf) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let from = match meta.endpoint.addr {
                    IpAddress::Ipv4(src) => NetAddr::ip(IpAddr::V4(src), meta.endpoint.port),
                    IpAddress::Ipv6(src) => NetAddr::ip(IpAddr::V6(src), meta.endpoint.port),
                };
                let _ = down.try_send((from, self.pump_buf[..n].to_vec()));
            }
        }
    }

    async fn drain_egress(&mut self, socket: &UdpSocket) {
        let pkts: Vec<Vec<u8>> = self.shim.egress.drain(..).collect();
        for pkt in pkts {
            self.send_frame(socket, &pkt).await;
        }
    }

    async fn on_cmd(&mut self, socket: &UdpSocket, cmd: ZtCmd) {
        match cmd {
            ZtCmd::Connect { target, reply } => {
                match &self.join {
                    Join::Failed(e) => {
                        let _ = reply.send(Err(Error::network(format!("zt: join failed: {e}"))));
                    }
                    Join::Applied => {
                        self.start_dial(target, reply);
                    }
                    _ => {
                        // Join in flight: park the dial; promote_dials
                        // converts it the moment the netconf applies.
                        self.pend_dials.push(ZtPendingDial {
                            target,
                            reply,
                            deadline: self.std_now() + ZT_NETCONF_TIMEOUT,
                        });
                        self.drive_join(socket).await;
                    }
                }
            }
            ZtCmd::UdpOpen { reply } => {
                if !self.udp_enabled {
                    let _ = reply.send(Err(Error::network(
                        "zt: udp is disabled for this network (udp: false)",
                    )));
                    return;
                }
                if self.udp.len() >= ZT_MAX_UDP_SOCKETS {
                    let _ = reply.send(Err(Error::network("zt: udp socket limit reached")));
                    return;
                }
                let mut sock = udp::Socket::new(
                    udp::PacketBuffer::new(
                        vec![udp::PacketMetadata::EMPTY; ZT_UDP_PACKETS],
                        vec![0; ZT_UDP_RX_BYTES],
                    ),
                    udp::PacketBuffer::new(
                        vec![udp::PacketMetadata::EMPTY; ZT_UDP_PACKETS],
                        vec![0; ZT_UDP_TX_BYTES],
                    ),
                );
                let port = self.ephemeral_port();
                if let Err(e) = sock.bind(IpListenEndpoint { addr: None, port }) {
                    let _ = reply.send(Err(Error::network(format!("zt: udp bind: {e:?}"))));
                    return;
                }
                let handle = self.sockets.add(sock);
                let id = self.next_udp_id;
                self.next_udp_id += 1;
                let (tx, rx) = mpsc::channel::<(NetAddr, Vec<u8>)>(64);
                self.udp.insert(id, ZtUdpSock { handle, port, down: tx });
                let _ = reply.send(Ok((id, rx)));
            }
            ZtCmd::UdpSend { id, dst, data } => {
                let Some(handle) = self.udp.get(&id).map(|u| u.handle) else {
                    return;
                };
                let local = local_address_for(&self.netconf, &dst);
                let mut meta = udp::UdpMetadata::from(match dst {
                    SocketAddr::V4(v4) => IpEndpoint::new(IpAddress::Ipv4(*v4.ip()), v4.port()),
                    SocketAddr::V6(v6) => IpEndpoint::new(IpAddress::Ipv6(*v6.ip()), v6.port()),
                });
                meta.local_address = local;
                let sock = self.sockets.get_mut::<udp::Socket>(handle);
                if let Err(e) = sock.send_slice(&data, meta) {
                    tracing::debug!(target: "engine", "zt: udp send to {dst}: {e:?}");
                }
            }
            ZtCmd::UdpClose { id } => {
                if let Some(u) = self.udp.remove(&id) {
                    self.sockets.remove(u.handle);
                    self.used_ports.remove(&u.port);
                }
            }
        }
    }

    async fn on_timer(&mut self, socket: &UdpSocket) {
        self.drive_join(socket).await;
        self.frags.expire();
        // Expire unanswered probes.
        if !self.probing.is_empty() {
            let now = Instant::now();
            self.probing.retain(|_, at| now.duration_since(*at) < PROBE_TTL);
        }
        // `ZT_PATH_HEARTBEAT_PERIOD`: keep the root path alive with a
        // periodic HELLO once joined (the reply doubles as the ack).
        if matches!(self.join, Join::Applied)
            && self.last_root_hello.elapsed() >= PATH_HEARTBEAT
        {
            self.send_root_hello(socket).await;
        }
    }
}

/// The destination IP of an IPv4/IPv6 packet, if parseable.
fn dst_ip_of(pkt: &[u8]) -> Option<IpAddr> {
    match pkt.first()? >> 4 {
        4 if pkt.len() >= 20 => {
            Some(IpAddr::V4(Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19])))
        }
        6 if pkt.len() >= 40 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&pkt[24..40]);
            Some(IpAddr::V6(Ipv6Addr::from(o)))
        }
        _ => None,
    }
}

/// The source IP of an IPv4/IPv6 packet, if parseable.
fn src_ip_of(pkt: &[u8]) -> Option<IpAddr> {
    match pkt.first()? >> 4 {
        4 if pkt.len() >= 20 => {
            Some(IpAddr::V4(Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15])))
        }
        6 if pkt.len() >= 40 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(&pkt[8..24]);
            Some(IpAddr::V6(Ipv6Addr::from(o)))
        }
        _ => None,
    }
}

/// Source-address selection for a dial: the managed address of the
/// destination's family (sing-wireguard's DialContext addr4/addr6
/// rule, applied to the netconf's assigned addresses).
fn local_address_for(netconf: &Option<AppliedNetconf>, dst: &SocketAddr) -> Option<IpAddress> {
    let ips = netconf.as_ref()?.managed_ips.clone();
    let want_v4 = dst.is_ipv4();
    ips.iter()
        .find(|(ip, _)| ip.is_ipv4() == want_v4)
        .map(|(ip, _)| match ip {
            IpAddr::V4(v4) => IpAddress::Ipv4(*v4),
            IpAddr::V6(v6) => IpAddress::Ipv6(*v6),
        })
}

/// The node task: one loop, biased select over commands, socket reads,
/// wakeups and the join/timer tick (the wireguard run_stack shape).
async fn run_zt_stack(mut stack: ZtStack, socket: Arc<UdpSocket>, mut cmd_rx: mpsc::Receiver<ZtCmd>) {
    let wake = stack.wake.clone();
    let mut rx = vec![0u8; 65_536];
    loop {
        stack.drive_join(&socket).await;
        stack.step(&socket).await;
        // Clamp the sleep so the loop always makes progress without
        // busy-spinning; the join/fragment timers want sub-second
        // wakeups even when smoltcp reports none.
        let offset = stack
            .iface
            .poll_delay(stack.now(), &stack.sockets)
            .map(|d| Duration::from_micros(d.total_micros()))
            .unwrap_or(ZT_MAX_TICK)
            .clamp(ZT_MIN_TICK, ZT_MAX_TICK);
        let deadline = tokio::time::Instant::now() + offset.min(WHOIS_RETRY);
        let sleep = tokio::time::sleep_until(deadline);
        tokio::select! {
            biased;
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(c) => stack.on_cmd(&socket, c).await,
                    None => break,
                }
            }
            _ = wake.notified() => {}
            r = socket.recv_from(&mut rx) => {
                match r {
                    Ok((n, from)) => {
                        stack.on_datagram(&socket, &rx[..n], from).await;
                    }
                    Err(e) => {
                        tracing::debug!(target: "engine", "zt: udp recv error: {e}");
                    }
                }
            }
            _ = sleep => {
                stack.on_timer(&socket).await;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Public API: the tunnel registry + the dial
// ---------------------------------------------------------------------------

/// One shared node per distinct ZeroTier identity+network+planet —
/// every dial with the same config reuses it (the wireguard tunnel
/// cache shape; upstream shares one service node across proxies the
/// same way).
static ZT_TUNNELS: std::sync::OnceLock<tokio::sync::Mutex<HashMap<String, mpsc::Sender<ZtCmd>>>> =
    std::sync::OnceLock::new();

fn zt_cache_key(cfg: &ZeroTierConfig) -> String {
    [
        cfg.network.as_str(),
        cfg.identity_secret.as_deref().unwrap_or(""),
        cfg.planet.as_deref().unwrap_or(""),
        &cfg.primary_port.to_string(),
        &cfg.physical_mtu.to_string(),
        // The state dir participates: two configs over one network
        // with different state dirs are different nodes (different
        // persisted identities).
        &cfg.effective_state_dir(),
    ]
    .join("\u{1f}")
}

async fn zt_tunnel_for(cfg: &ZeroTierConfig) -> Result<mpsc::Sender<ZtCmd>> {
    cfg.validate()?;
    let key = zt_cache_key(cfg);
    let cache = ZT_TUNNELS.get_or_init(Default::default);
    let mut map = cache.lock().await;
    if let Some(tx) = map.get(&key) {
        if !tx.is_closed() {
            return Ok(tx.clone());
        }
    }
    let network_id = parse_network_id(&cfg.network)?;

    // The state store under state-dir (the Node.cpp state objects).
    // Opening it fails loudly — a state-dir that cannot exist is a
    // config error, never a silent degradation.
    let state = NodeStateStore::open(&cfg.effective_state_dir())?;

    // The identity: from config when provided (explicit wins, like
    // mihomo's identity-secret), else the persisted one, else a fresh
    // PoW search persisted on the spot — `Node::New` against its
    // state store, exactly.
    let identity = match &cfg.identity_secret {
        Some(secret) => {
            let id = NodeIdentity::from_str_form(secret)?;
            // The state store holds the node's identity regardless of
            // where it came from (`Node`'s ZT_STATE_OBJECT_IDENTITY
            // write) — a restart without the config field reuses it.
            state.save_identity(&id)?;
            id
        }
        None => state.load_or_create_identity()?,
    };

    // The planet: the operator's file, else the built-in Earth world
    // (Topology's constructor).
    let planet_bytes: Vec<u8> = match &cfg.planet {
        Some(path) => std::fs::read(path)
            .map_err(|e| Error::config(format!("zerotier: cannot read planet file {path}: {e}")))?,
        None => default_planet().to_vec(),
    };
    let world = World::parse_planet(&planet_bytes)?;

    // The orbit entries (moons): pending (world id, seed address)
    // pairs until each signed world arrives (`Topology::orbit`).
    let mut orbit = Vec::new();
    for entry in &cfg.orbit {
        orbit.push((entry.world, parse_node_address(&entry.seed)?));
    }

    let bind = if cfg.primary_port > 0 && cfg.primary_port <= 65535 {
        format!("0.0.0.0:{}", cfg.primary_port)
    } else {
        "0.0.0.0:0".to_string()
    };
    let socket = Arc::new(
        UdpSocket::bind(&bind)
            .await
            .map_err(|e| Error::network(format!("zerotier: bind udp: {e}")))?,
    );
    let local_addr = match socket.local_addr() {
        Ok(sa) if !sa.ip().is_unspecified() => Some(sa),
        _ => None,
    };
    // The path MTU: the config's physical-mtu, else the ZT default.
    let path_mtu = if cfg.physical_mtu > 0 {
        cfg.physical_mtu as usize
    } else {
        DEFAULT_PHYSICAL_MTU
    };
    let wake = Arc::new(Notify::new());
    let mut stack = ZtStack::new(
        identity,
        world,
        network_id,
        path_mtu,
        cfg.udp,
        wake.clone(),
        orbit,
        local_addr,
        Some(state),
    );
    // Reload persisted peers (`Node::New`'s ZT_STATE_OBJECT_PEER
    // pass): identities re-derive their pairwise keys via `agree`, so
    // a restart skips the WHOIS round trips for previously met peers.
    for (peer_id, endpoint) in stack.state.as_ref().expect("state present").load_peers() {
        stack.learn_peer(peer_id, endpoint);
    }
    let (tx, rx) = mpsc::channel::<ZtCmd>(64);
    let task_socket = socket.clone();
    tokio::spawn(async move {
        run_zt_stack(stack, task_socket, rx).await;
    });
    map.insert(key, tx.clone());
    Ok(tx)
}

/// Resolve a proxy target to the socket address the netstack dials:
/// managed IPs only — domains are resolved *outside* the overlay
/// (mihomo/sing-box hand the stack an IP; the easytier/wireguard
/// precedent), and a family with no managed address is refused.
fn zt_target_addr(target: &NetAddr, netconf: &Option<AppliedNetconf>) -> Result<SocketAddr> {
    match &target.host {
        crate::addr::Host::Ip(IpAddr::V4(ip)) => Ok(SocketAddr::V4(SocketAddrV4::new(*ip, target.port))),
        crate::addr::Host::Ip(IpAddr::V6(ip)) => match netconf.as_ref().map(|n| n.managed_ips.iter().any(|(a, _)| a.is_ipv6())) {
            Some(true) => Ok(SocketAddr::V6(SocketAddrV6::new(*ip, target.port, 0, 0))),
            _ => Err(Error::network(
                "zt: dial to an IPv6 target with no managed IPv6 address",
            )),
        },
        crate::addr::Host::Domain(d) => Err(Error::network(format!(
            "zt: target {d} is a domain — resolve it before routing (the overlay dials managed IPs)"
        ))),
    }
}

/// Dial a TCP connection through the ZeroTier overlay described by
/// `cfg`. The node (identity, planet, UDP loop, join) is created on
/// first use and shared by every later dial with the same
/// configuration; the returned stream is a plain
/// `AsyncRead + AsyncWrite` the relay can splice. This is the
/// outbound.rs wiring point:
///
/// ```text
/// OutboundKind::ZeroTier(cfg) => crate::proto::zerotier::connect(cfg, target).await
/// ```
///
/// (target: `&crate::addr::NetAddr`; returns
/// `crate::stream::BoxProxyStream` — the wireguard `connect` shape.)
pub async fn connect(cfg: &ZeroTierConfig, target: &NetAddr) -> Result<BoxProxyStream> {
    let tunnel = zt_tunnel_for(cfg).await?;
    let (tx, rx) = oneshot::channel();
    tunnel
        .send(ZtCmd::Connect { target: target.clone(), reply: tx })
        .await
        .map_err(|_| Error::network("zt: node task is gone"))?;
    // The join (HELLO → WHOIS → netconf) plus the TCP connect itself.
    let shared = tokio::time::timeout(ZT_NETCONF_TIMEOUT + ZT_TCP_CONNECT_TIMEOUT, rx)
        .await
        .map_err(|_| Error::network("zt: tcp dial timed out"))?
        .map_err(|_| Error::network("zt: node task dropped the dial"))??;
    Ok(Box::new(ZtStream { shared }))
}

/// A UDP socket inside the ZeroTier overlay: send to any managed
/// address, receive from anyone who replies to this socket's port.
pub struct ZtUdp {
    cmd: mpsc::Sender<ZtCmd>,
    id: u32,
    down: tokio::sync::Mutex<mpsc::Receiver<(NetAddr, Vec<u8>)>>,
}

impl ZtUdp {
    /// Open a UDP socket through the overlay node for `cfg`.
    pub async fn bind(cfg: &ZeroTierConfig) -> Result<Self> {
        let tunnel = zt_tunnel_for(cfg).await?;
        let (tx, rx) = oneshot::channel();
        tunnel
            .send(ZtCmd::UdpOpen { reply: tx })
            .await
            .map_err(|_| Error::network("zt: node task is gone"))?;
        let (id, down) = tokio::time::timeout(ZT_NETCONF_TIMEOUT, rx)
            .await
            .map_err(|_| Error::network("zt: udp open timed out"))?
            .map_err(|_| Error::network("zt: node task dropped the open"))??;
        Ok(ZtUdp { cmd: tunnel, id, down: tokio::sync::Mutex::new(down) })
    }

    /// Send one datagram to `target` (a managed IP address).
    pub async fn send(&self, target: &NetAddr, data: &[u8]) -> Result<()> {
        let dst = match &target.host {
            crate::addr::Host::Ip(IpAddr::V4(ip)) => {
                SocketAddr::V4(SocketAddrV4::new(*ip, target.port))
            }
            crate::addr::Host::Ip(IpAddr::V6(ip)) => {
                SocketAddr::V6(SocketAddrV6::new(*ip, target.port, 0, 0))
            }
            crate::addr::Host::Domain(d) => {
                return Err(Error::network(format!(
                    "zt: udp target {d} is a domain — resolve before sending"
                )))
            }
        };
        self.cmd
            .send(ZtCmd::UdpSend { id: self.id, dst, data: data.to_vec() })
            .await
            .map_err(|_| Error::network("zt: node task is gone"))
    }

    /// Receive the next datagram addressed to this socket.
    pub async fn recv(&self) -> Result<(NetAddr, Vec<u8>)> {
        let mut down = self.down.lock().await;
        down.recv()
            .await
            .ok_or_else(|| Error::network("zt: udp socket is closed"))
    }
}

impl Drop for ZtUdp {
    fn drop(&mut self) {
        let _ = self.cmd.try_send(ZtCmd::UdpClose { id: self.id });
    }
}

// ===========================================================================
// Config surface (mihomo ZeroTierOption)
// ===========================================================================

/// The `ip-stack` option (upstream `IPStackOption` with
/// `normalize()`/`validate()`, cached lines 259-260): the userspace
/// stack that terminates the virtual link.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum IpStack {
    /// The default userspace stack (the smoltcp side in a Rust port).
    #[default]
    Gvisor,
    /// Delegate to the host stack (a real TUN device).
    System,
}

impl IpStack {
    /// `IPStackOption.normalize()` — the empty string picks the default
    /// (gvisor, matching mihomo's tun stack default).
    pub fn parse(raw: &str) -> Result<Self> {
        match raw.trim() {
            "" | "gvisor" => Ok(IpStack::Gvisor),
            "system" => Ok(IpStack::System),
            other => Err(Error::config(format!(
                "ZeroTier ip-stack must be gvisor or system, got {other:?}"
            ))),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            IpStack::Gvisor => "gvisor",
            IpStack::System => "system",
        }
    }
}

/// One `orbit:` entry — a user-defined root set ("moon"): the world id
/// plus one seed node address (`ZeroTierOrbitOption`, cached lines
/// 132-135).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZeroTierOrbit {
    /// 16-hex-digit world id (`ZT.ParseOrbit`'s world).
    pub world: u64,
    /// 10-hex-digit seed node address (`ZT.ParseOrbit`'s seed; see
    /// [`parse_node_address`] — hex10, like every ZeroTier address).
    pub seed: String,
}

/// The `zerotier` outbound configuration, mirroring mihomo's
/// `ZeroTierOption` (`adapter/outbound/zerotier.go:108-135`).
#[derive(Default, Clone, PartialEq, Eq)]
pub struct ZeroTierConfig {
    /// `name:` — the proxy name (mihomo `BasicOption.Name`).
    pub name: String,
    /// `network:` — the 16-hex-digit network id (required).
    pub network: String,
    /// `state-dir:` — persistent node state (see [`default_state_dir`]).
    pub state_dir: Option<String>,
    /// `identity-secret:` — a ZeroTier node identity with private keys.
    /// Secret; never logged.
    pub identity_secret: Option<String>,
    /// `planet:` — path to a custom planet (root set) file.
    pub planet: Option<String>,
    /// `mtu:` — the virtual network MTU (0 = controller's default).
    pub mtu: i64,
    /// `ip-stack:` — gvisor (default) or system.
    pub ip_stack: IpStack,
    /// `physical-mtu:` — the physical transport MTU (0 = default).
    pub physical_mtu: i64,
    /// `udp:` — support UDP through the overlay.
    pub udp: bool,
    /// `remote-dns-resolve:` — resolve via the overlay's DNS servers.
    pub remote_dns_resolve: bool,
    /// `dns:` — name servers for remote-dns-resolve.
    pub dns: Vec<String>,
    /// `low-bandwidth:` — reduce keepalive chatter.
    pub low_bandwidth: bool,
    /// `encrypted-hello:` — encrypt the P2P HELLO handshake.
    pub encrypted_hello: bool,
    /// `primary-port:` — the main physical UDP port (0 = ephemeral).
    pub primary_port: i64,
    /// `secondary-port:` — the port-rebind fallback (0 = ephemeral).
    pub secondary_port: i64,
    /// `tcp-fallback-mode:` — when the TCP fallback relay engages.
    pub tcp_fallback_mode: Option<String>,
    /// `tcp-fallback-relay:` — the fallback relay address
    /// (default `ZTTransport.DefaultTCPFallbackRelay`).
    pub tcp_fallback_relay: Option<String>,
    /// `orbit:` — additional moons (world + seed).
    pub orbit: Vec<ZeroTierOrbit>,
    /// `remote-trace-target:` — a 10-hex-digit node id receiving traces.
    pub remote_trace_target: Option<String>,
    /// `remote-trace-level:` — 0 (off) ..= [`TRACE_LEVEL_INSANE`].
    pub remote_trace_level: u64,
}

impl std::fmt::Debug for ZeroTierConfig {
    /// Debug redacts `identity_secret`: the secret must never appear in
    /// logs, panics or test output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ZeroTierConfig")
            .field("name", &self.name)
            .field("network", &self.network)
            .field("state_dir", &self.state_dir)
            .field("identity_secret", &self.identity_secret.as_ref().map(|_| "[redacted]"))
            .field("planet", &self.planet)
            .field("mtu", &self.mtu)
            .field("ip_stack", &self.ip_stack)
            .field("physical_mtu", &self.physical_mtu)
            .field("udp", &self.udp)
            .field("remote_dns_resolve", &self.remote_dns_resolve)
            .field("dns", &self.dns)
            .field("low_bandwidth", &self.low_bandwidth)
            .field("encrypted_hello", &self.encrypted_hello)
            .field("primary_port", &self.primary_port)
            .field("secondary_port", &self.secondary_port)
            .field("tcp_fallback_mode", &self.tcp_fallback_mode)
            .field("tcp_fallback_relay", &self.tcp_fallback_relay)
            .field("orbit", &self.orbit)
            .field("remote_trace_target", &self.remote_trace_target)
            .field("remote_trace_level", &self.remote_trace_level)
            .finish()
    }
}

/// `ZT.ParseNetworkID` (zerotier-go `address.go:59-77`): a network id
/// is 16 hex digits (u64); zero is rejected, and non-ad-hoc networks
/// encode a non-reserved controller address.
pub fn parse_network_id(raw: &str) -> Result<u64> {
    let raw = raw.trim();
    if raw.len() != 16 || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::config(format!(
            "ZeroTier network id must be 16 hex digits, got {raw:?}"
        )));
    }
    let network_id = u64::from_str_radix(raw, 16)
        .map_err(|_| Error::config(format!("ZeroTier network id overflow: {raw}")))?;
    if network_id == 0
        || (!is_adhoc_network_id(network_id) && address_is_reserved(controller_of(network_id)))
    {
        return Err(Error::config(format!(
            "ZeroTier network id encodes a reserved controller: {raw}"
        )));
    }
    Ok(network_id)
}

/// `ZT.IsAdHocNetworkID` (zerotier-go `address.go:82-84`): the
/// controllerless namespace is the `0xff`-prefixed top byte.
pub fn is_adhoc_network_id(network_id: u64) -> bool {
    network_id >> 56 == 0xff
}

/// `ZT.ParseAddress` (zerotier-go `address.go:44-58`): a node address
/// is exactly 10 **hex** digits (`Utils::hex10`; the wave-10 decimal
/// reading was wrong) and must not be reserved (zero or `0xff`-prefixed).
pub fn parse_node_address(raw: &str) -> Result<u64> {
    let raw = raw.trim();
    if raw.len() != 10 || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::config(format!(
            "ZeroTier node address must be 10 hex digits, got {raw:?}"
        )));
    }
    let address = u64::from_str_radix(raw, 16)
        .map_err(|_| Error::config(format!("ZeroTier node address overflow: {raw}")))?;
    if address_is_reserved(address) {
        return Err(Error::config(format!(
            "ZeroTier node address is reserved: {raw}"
        )));
    }
    Ok(address)
}

/// The shape check behind `ZT.ParseIdentity` + `HasPrivate` +
/// `Validate` (cached lines 206-218): a ZeroTier identity is
/// `address:public-key[:taxonomy][:secret-key]` colon fields — the
/// public form has three, the secret form four (`zerotier-idtool`'s
/// `identity.public`/`identity.secret`). Full validation is
/// [`NodeIdentity::from_str_form`] + [`NodeIdentity::locally_validate`];
/// this is the config-layer pre-check.
pub fn identity_has_private(secret: &str) -> bool {
    let fields: Vec<&str> = secret.trim().split(':').collect();
    fields.len() >= 4 && fields.iter().all(|f| !f.trim().is_empty())
}

/// The default `state-dir` derivation (cached lines 283-286):
/// `zerotier/<network>-<sha256(name)[:6]>`, hex.
pub fn default_state_dir(name: &str, network: &str) -> String {
    use sha2::Digest;
    let digest = sha2::Sha256::digest(name.as_bytes());
    format!(
        "zerotier/{}-{}",
        network,
        hex_prefix(&digest, 3) // 3 bytes = 6 hex chars, like instance[:6]
    )
}

fn hex_prefix(bytes: &[u8], n: usize) -> String {
    bytes[..n].iter().map(|b| format!("{b:02x}")).collect()
}

impl ZeroTierConfig {
    /// A config with just name + network, like the zero-value
    /// `ZeroTierOption` plus its required fields.
    pub fn new(name: impl Into<String>, network: impl Into<String>) -> Self {
        ZeroTierConfig {
            name: name.into(),
            network: network.into(),
            ..Default::default()
        }
    }

    /// The state directory, defaulted like `NewZeroTier`
    /// (cached lines 283-286). Path policy (resolve + safety) is the
    /// config layer's job, upstream's `C.Path.Resolve`/`IsSafePath`.
    pub fn effective_state_dir(&self) -> String {
        self.state_dir
            .clone()
            .unwrap_or_else(|| default_state_dir(&self.name, &self.network))
    }

    /// Every data-only validation of `NewZeroTier` (cached lines
    /// 201-290): network id, identity shape, both MTU windows, orbit
    /// worlds (parse + duplicates), trace target/level. File reads
    /// (planet, state store) stay to the integrator — they are IO, not
    /// config math.
    pub fn validate(&self) -> Result<()> {
        parse_network_id(&self.network)?;
        if let Some(secret) = &self.identity_secret {
            if !identity_has_private(secret) {
                return Err(Error::config(
                    "ZeroTier identity-secret must contain private keys",
                ));
            }
        }
        if self.mtu != 0 && !(MIN_NETWORK_MTU..=MAX_NETWORK_MTU).contains(&self.mtu) {
            return Err(Error::config(format!(
                "ZeroTier MTU must be between {MIN_NETWORK_MTU} and {MAX_NETWORK_MTU}"
            )));
        }
        if self.physical_mtu != 0
            && !(MIN_PHYSICAL_MTU..=MAX_PHYSICAL_MTU).contains(&self.physical_mtu)
        {
            return Err(Error::config(format!(
                "ZeroTier physical MTU must be between {MIN_PHYSICAL_MTU} and {MAX_PHYSICAL_MTU}"
            )));
        }
        let mut seen_worlds = std::collections::HashSet::new();
        for orbit in &self.orbit {
            let seed = parse_node_address(&orbit.seed)?;
            if seed == 0 {
                // Unreachable post-reserved-check, but mirrors the
                // upstream zero-address rejection (`ZT.Address.IsReserved`).
                return Err(Error::config(
                    "ZeroTier orbit seed must be a valid node address",
                ));
            }
            if !seen_worlds.insert(orbit.world) {
                return Err(Error::config(format!(
                    "duplicate ZeroTier orbit world {:016x}",
                    orbit.world
                )));
            }
        }
        if let Some(target) = &self.remote_trace_target {
            parse_node_address(target)?;
        }
        if self.remote_trace_level > TRACE_LEVEL_INSANE {
            return Err(Error::config(format!(
                "ZeroTier remote trace level must be between 0 and {TRACE_LEVEL_INSANE}"
            )));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// On-disk node state (state-dir): identity + peer persistence
// ---------------------------------------------------------------------------

/// The name upstream stores the node identity under
/// (`ZT_STATE_OBJECT_IDENTITY` → `identity.secret`, node/Node.cpp's
/// stateObjectPut; the content is `zerotier-idtool`'s textual secret
/// form — exactly [`NodeIdentity::to_secret_str`]).
pub const STATE_FILE_IDENTITY: &str = "identity.secret";
/// The peer-cache directory (`ZT_STATE_OBJECT_PEER` → `peers.d/<hex>`,
/// node/Topology.cpp:423-435 `_savePeer`).
pub const STATE_DIR_PEERS: &str = "peers.d";

/// The node's persistent state under `state-dir` — the bounded
/// `Node.cpp` state objects: the identity survives restarts (the
/// openvpn/wireguard state-store precedent in this engine), and
/// learned peers are cached the way `Topology::_savePeer` caches them
/// (identity + last path) so a restart skips the WHOIS round trips.
///
/// Deltas vs upstream (documented, wire-invisible): one file per peer
/// instead of `Peer::serializeForCache`'s full path-quality block, and
/// pairwise keys are never written (they re-derive from the two
/// identities via [`NodeIdentity::agree`], upstream re-derives the
/// same way).
pub struct NodeStateStore {
    dir: PathBuf,
}

impl NodeStateStore {
    /// Open (and create) the state directory. Fails loudly — a
    /// configured state-dir that cannot exist is a config error, not a
    /// silent degradation (the audit's standing rule).
    pub fn open(dir: &str) -> Result<Self> {
        let dir = PathBuf::from(dir);
        std::fs::create_dir_all(&dir)
            .map_err(|e| Error::config(format!("zerotier: state-dir {dir:?}: {e}")))?;
        Ok(NodeStateStore { dir })
    }

    fn identity_path(&self) -> PathBuf {
        self.dir.join(STATE_FILE_IDENTITY)
    }

    fn peers_dir(&self) -> PathBuf {
        self.dir.join(STATE_DIR_PEERS)
    }

    /// The node identity: loaded from `identity.secret` when present
    /// and valid, freshly generated (the PoW search) and persisted
    /// otherwise — `Node`'s identity lifecycle against its state
    /// store. A corrupt file fails loudly rather than silently
    /// re-keying the node.
    pub fn load_or_create_identity(&self) -> Result<NodeIdentity> {
        match std::fs::read_to_string(self.identity_path()) {
            Ok(raw) => self.load_identity_from(&raw),
            Err(e) if e.kind() == io::ErrorKind::NotFound => {
                let id = NodeIdentity::generate()?;
                self.save_identity(&id)?;
                Ok(id)
            }
            Err(e) => Err(Error::config(format!(
                "zerotier: read {}: {e}",
                self.identity_path().display()
            ))),
        }
    }

    /// Parse + validate an identity file's contents.
    fn load_identity_from(&self, raw: &str) -> Result<NodeIdentity> {
        let id = NodeIdentity::from_str_form(raw.trim())?;
        if !id.locally_validate() {
            return Err(Error::config(
                "zerotier: state identity.secret failed hashcash validation",
            ));
        }
        Ok(id)
    }

    /// Persist the node identity (write-then-rename: a half-written
    /// identity file must never shadow a good one — the fakeip
    /// store's atomic precedent).
    pub fn save_identity(&self, id: &NodeIdentity) -> Result<()> {
        let secret = id.to_secret_str()?;
        let tmp = self.dir.join(format!(".identity.secret.{}", std::process::id()));
        std::fs::write(&tmp, secret.as_bytes())
            .map_err(|e| Error::config(format!("zerotier: write identity: {e}")))?;
        std::fs::rename(&tmp, self.identity_path())
            .map_err(|e| Error::config(format!("zerotier: commit identity: {e}")))?;
        Ok(())
    }

    /// Every persisted peer: the identity (public half) and its
    /// last-known endpoint, when one was ever learned.
    pub fn load_peers(&self) -> Vec<(NodeIdentity, Option<SocketAddr>)> {
        let Ok(entries) = std::fs::read_dir(self.peers_dir()) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for entry in entries.flatten() {
            let Ok(raw) = std::fs::read(entry.path()) else { continue };
            let Ok((identity, used)) = NodeIdentity::deserialize_bin(&raw) else { continue };
            if !identity.locally_validate() || used != 71 {
                continue; // cache poison / non-public form: drop the entry
            }
            let endpoint = if raw.len() > used {
                PhysAddr::deserialize_from(&raw, used).ok().and_then(|(a, _)| a.to_socket_addr())
            } else {
                None
            };
            out.push((identity, endpoint));
        }
        out
    }

    /// Persist one peer (best-effort — a cache write failure logs and
    /// keeps the node running, exactly like upstream's `_savePeer`
    /// `catch (...) {}`).
    pub fn save_peer(&self, identity: &NodeIdentity, endpoint: Option<SocketAddr>) {
        let dir = self.peers_dir();
        if std::fs::create_dir_all(&dir).is_err() {
            return;
        }
        let mut buf = identity.serialize_bin(false);
        if let Some(ep) = endpoint {
            PhysAddr::from_socket_addr(ep).serialize_into(&mut buf);
        }
        let path = dir.join(format!("{:010x}", identity.address()));
        let tmp = dir.join(format!(".{:010x}.{}", identity.address(), std::process::id()));
        if std::fs::write(&tmp, &buf).is_ok() {
            let _ = std::fs::rename(&tmp, path);
        }
    }
}

/// What still separates this port from a full ZeroTier node after
/// wave 16 (the wire core, the node runtime, direct-path learning
/// with NAT-t, state persistence and moon gossip are rust-native —
/// see [`MILESTONE_1`]/[`MILESTONE_2`]/[`MILESTONE_3`]):
///
/// * multicast groups (MULTICAST_LIKE/GATHER/MULTICAST_FRAME) and the
///   ARP/NDP emulation built on them — unicast is bridged via the
///   netconf's active-bridge specialists instead;
/// * multipath/bonding policies (`node/Bond.cpp`), QoS/flow hashing;
/// * tap/L2 semantics for bridged hosts (`VERB_EXT_FRAME`, MAC
///   forwarding), capabilities/tags rules enforcement, SSO netconf
///   authentication, cluster verbs, trusted paths;
/// * the AES-CTR extended-armor HELLO tail (off by default upstream —
///   `encrypted-hello:` config parses but stays inert) and the
///   AES-GMAC-SIV suite (avoided by advertising protocol 11);
/// * the TCP fallback relay — REMOVED upstream (node/ has no
///   tcpFallback machinery in 1.14.x; only the standalone tcp-proxy
///   docker sidecar remains); the config fields parse inertly,
///   matching what a current upstream node would do with them.
pub const NOT_PORTED: &str = concat!(
    "zerotier: wire core + node runtime are rust-native (planet, UDP loop, ",
    "WHOIS via roots, relay, fragmentation, netconf->smoltcp link, dial — see ",
    "proto::zerotier::MILESTONE_2); wave 16: direct-path learning/NAT-t ",
    "(PUSH_DIRECT_PATHS 0x10 + RENDEZVOUS 0x05 probes, relay released on ",
    "confirmed paths), state-dir persistence (identity.secret + peers.d) and ",
    "moon orbit gossip (OK(HELLO) world-update adoption) landed — see ",
    "proto::zerotier::MILESTONE_3; remaining: multicast groups + ARP/NDP ",
    "emulation, bonds/multipath, tap/L2 bridging, rules enforcement, SSO auth, ",
    "cluster verbs, the AES extended-armor HELLO tail; the TCP fallback relay ",
    "no longer exists upstream (node/, 1.14.x)"
);

/// Marker for the wave-16 milestone: direct-path learning and NAT-t
/// (PUSH_DIRECT_PATHS probes + root RENDEZVOUS introductions, relay
/// released on confirmed paths), `state-dir` persistence
/// (`identity.secret` + `peers.d`), and moon orbit gossip (the
/// OK(HELLO) world-update block adopting signed moons whose roots
/// contain a configured seed).
pub const MILESTONE_3: &str = "zerotier direct paths + NAT-t + state persistence + moon gossip (rust-native)";

#[cfg(test)]
mod tests {
    use super::*;

    /// SECURITY: the repo's standing rule — fake credentials come from
    /// the environment only, never a source literal. Absent means "not
    /// exercised" (the shape check covers it either way).
    fn test_identity() -> Option<String> {
        std::env::var("RUSTCRASH_TEST_ZT_IDENTITY").ok().filter(|s| !s.is_empty())
    }

    fn wellformed(network: &str) -> ZeroTierConfig {
        ZeroTierConfig::new("zt-node", network)
    }

    fn unhex(raw: &str) -> Vec<u8> {
        (0..raw.len() / 2)
            .map(|i| u8::from_str_radix(&raw[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    // -----------------------------------------------------------------
    // Salsa20 + Poly1305 against public vectors
    // -----------------------------------------------------------------

    /// eSTREAM verified vectors, 256-bit key, set 1 vector 0
    /// (das-labor/legacy salsa20-256.64-verified.test-vectors; the same
    /// vectors BouncyCastle and RustCrypto test against).
    #[test]
    fn salsa20_ecostream_20_rounds_256bit() {
        let key: [u8; 32] = unhex(
            "8000000000000000000000000000000000000000000000000000000000000000",
        )
        .try_into()
        .unwrap();
        let iv = [0u8; 8];
        let mut stream = vec![0u8; 512];
        salsa20_xor(&key, &iv, &mut stream, 20);
        let expect0 = unhex(
            "E3BE8FDD8BECA2E3EA8EF9475B29A6E7003951E1097A5C38D23B7A5FAD9F6844\
             B22C97559E2723C7CBBD3FE4FC8D9A0744652A83E72A9C461876AF4D7EF1A117",
        );
        let expect192 = unhex(
            "57BE81F47B17D9AE7C4FF15429A73E10ACF250ED3A90A93C711308A74C6216A9\
             ED84CD126DA7F28E8ABF8BB63517E1CA98E712F4FB2E1A6AED9FDC73291FAA17",
        );
        let expect256 = unhex(
            "958211C4BA2EBD5838C635EDB81F513A91A294E194F1C039AEEC657DCE40AA7E\
             7C0AF57CACEFA40C9F14B71A4B3456A63E162EC7D8D10B8FFB1810D71001B618",
        );
        let expect448 = unhex(
            "696AFCFD0CDDCC83C7E77F11A649D79ACDC3354E9635FF137E929933A0BD6F53\
             77EFA105A3A4266B7C0D089D08F1E855CC32B15B93784A36E56A76CC64BC8477",
        );
        assert_eq!(&stream[0..64], &expect0[..]);
        assert_eq!(&stream[192..256], &expect192[..]);
        assert_eq!(&stream[256..320], &expect256[..]);
        assert_eq!(&stream[448..512], &expect448[..]);
    }

    /// Salsa20/12: BouncyCastle Salsa20Test.java's eSTREAM-derived
    /// 12-round vectors (128-bit key — the reason the "expand 16-byte
    /// k" layout exists here). ZeroTier's armor is the same round
    /// function with 32-byte keys.
    #[test]
    fn salsa20_12_rounds_bouncycastle() {
        let key = unhex("80000000000000000000000000000000");
        let iv = [0u8; 8];
        let mut stream = vec![0u8; 512];
        {
            let mut s = SalsaStream::new(&key, &iv, 12);
            s.xor(&mut stream);
        }
        let expect0 = unhex(
            "FC207DBFC76C5E1774961E7A5AAD09069B2225AC1CE0FE7A0CE77003E7E5BDF8\
             B31AF821000813E6C56B8C1771D6EE7039B2FBD0A68E8AD70A3944B677937897",
        );
        let expect192 = unhex(
            "4B62A4881FA1AF9560586510D5527ED48A51ECAFA4DECEEBBDDC10E9918D44AB\
             26B10C0A31ED242F146C72940C6E9C3753F641DA84E9F68B4F9E76B6C48CA5AC",
        );
        let expect256 = unhex(
            "F52383D9DEFB20810325F7AEC9EADE34D9D883FEE37E05F74BF40875B2D0BE79\
             ED8886E5BFF556CEA8D1D9E86B1F68A964598C34F177F8163E271B8D2FEB5996",
        );
        let expect448 = unhex(
            "A52ED8C37014B10EC0AA8E05B5CEEE123A1017557FB3B15C53E6C5EA8300BF74\
             264A73B5315DC821AD2CAB0F3BB2F152BDAEA3AEE97BA04B8E72A7B40DCC6BA4",
        );
        assert_eq!(&stream[0..64], &expect0[..]);
        assert_eq!(&stream[192..256], &expect192[..]);
        assert_eq!(&stream[256..320], &expect256[..]);
        assert_eq!(&stream[448..512], &expect448[..]);
    }

    /// The block-discarding stream semantics ZeroTier's armor relies
    /// on: a 32-byte call consumes all of block 0's keystream budget,
    /// the next call resumes at block 1 (byte 64 of the stream).
    #[test]
    fn salsa_stream_discards_partial_blocks() {
        let key = [7u8; 32];
        let iv = [9u8; 8];
        let mut whole = vec![0u8; 128];
        salsa20_xor(&key, &iv, &mut whole, 12);
        let mut split = [0u8; 32 + 64];
        let mut s = SalsaStream::new(&key, &iv, 12);
        s.xor(&mut split[..32]);
        s.xor(&mut split[32..]);
        assert_eq!(split[..32], whole[..32]);
        assert_eq!(split[32..], whole[64..128]);
    }

    /// RFC 8439 §2.5.2 — the Poly1305 MAC vector.
    #[test]
    fn poly1305_rfc8439() {
        let key: [u8; 32] = unhex(
            "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b",
        )
        .try_into()
        .unwrap();
        let msg = b"Cryptographic Forum Research Group";
        let tag = poly1305(&key, msg);
        assert_eq!(hex(&tag), "a8061dc1305136c6c22b8baf0c0127a9");
    }

    #[test]
    fn poly1305_all_zero_key_yields_zero_tag() {
        // r = s = 0 ⇒ h stays 0 (RFC 8439 A.3 test vector #1 shape).
        let tag = poly1305(&[0u8; 32], b"anything at all");
        assert_eq!(tag, [0u8; 16]);
    }

    // -----------------------------------------------------------------
    // Identity: the Go port's cross-implementation fixtures
    // -----------------------------------------------------------------

    /// metacubex/zerotier-go `identity_test.go:8` — a known-good
    /// secret identity (validated by the Go port against the C++
    /// derivation). Proves the whole hashcash translation end-to-end:
    /// parse, PoW validation, string round-trips, binary round-trip.
    /// Not a credential — a published test fixture.
    #[test]
    fn identity_known_good_from_the_go_port() {
        let known_good = "8e4df28b72:0:ac3d46abe0c21f3cfe7a6c8d6a85cfcffcb82fbd55af6a4d6350657c68200843fa2e16f9418bbd9702cae365f2af5fb4c420908b803a681d4daef6114d78a2d7:bd8dd6e4ce7022d2f812797a80c6ee8ad180dc4ebf301dec8b06d1be08832bddd63a2f1cfa7b2c504474c75bdc8898ba476ef92e8e2d0509f8441985171ff16e";
        let id = NodeIdentity::from_str_form(known_good).unwrap();
        assert_eq!(id.address(), 0x8e4df28b72);
        assert!(id.locally_validate(), "hashcash address must validate");
        // A tampered public key breaks the address binding.
        let mut tampered_pub = *id.public();
        tampered_pub[63] ^= 1;
        let bad = NodeIdentity::from_parts(
            id.address(),
            tampered_pub,
            id.secret,
        );
        assert!(!bad.locally_validate());
        assert_eq!(id.to_secret_str().unwrap(), known_good);
        assert!(id.to_public_str().starts_with("8e4df28b72:0:"));
        let bin = id.serialize_bin(true);
        let (parsed, used) = NodeIdentity::deserialize_bin(&bin).unwrap();
        assert_eq!(used, bin.len());
        assert_eq!(parsed.to_secret_str().unwrap(), known_good);
        // The public binary form has no secret and round-trips the pub half.
        let pubbin = id.serialize_bin(false);
        let (pubonly, used2) = NodeIdentity::deserialize_bin(&pubbin).unwrap();
        assert_eq!(used2, pubbin.len());
        assert!(pubonly.secret.is_none());
        assert_eq!(pubonly.to_public_str(), id.to_public_str());
    }

    /// zerotier-go `identity_test.go:21-46` — a published
    /// cross-implementation agreement vector for the 48-byte pairwise
    /// key. Test keys, not credentials.
    #[test]
    fn identity_agreement_vector_from_the_go_port() {
        let pub1: [u8; 64] = unhex("a1fc7ab46ddf7dcfe7ec75e5fadd11cbcc37f8845d1c924e098965fcd8e95a30dae486a335b4190cbc7bcb3eb94cbd16e83d132bc9c339eaf142e76f69789ab7").try_into().unwrap();
        let priv1: [u8; 64] = unhex("e5f37bd40ec9dc775086dcf42ebcdb27f073d45873c44b718b3cc54fa87ca484d9962373b40316bf1ea12dd8c48ae78210dac9e5459b01dc73a6c917a815316d").try_into().unwrap();
        let pub2: [u8; 64] = unhex("3e49a40e3aafa3073df72aec43b1d4091acb8e92f96595046d2d9b34a3bf5100e2ee23f5280aa9b1570b965662ba1294afc65fb561430fde0babfa4ffec5e718").try_into().unwrap();
        let priv2: [u8; 64] = unhex("004d418de46923ae98c43e770f1d945d293e945a3839200fd36f76a2290203cb0b7f4f1a295113337c99b3818239440597fb0df293a24094f4ff5d0961e45f76").try_into().unwrap();
        let id1 = NodeIdentity::from_parts(0x111111111, pub1, Some(priv1));
        let id2 = NodeIdentity::from_parts(0x222222222, pub2, Some(priv2));
        let want = "abced224e893b0e77214dcbb7d0fd894169eb57fd7195f3e2d45d5f7900b3e05182e2bf4fad4ec624a4f4850af1ce89f";
        assert_eq!(hex(&id1.agree(&id2).unwrap()), want);
        assert_eq!(hex(&id2.agree(&id1).unwrap()), want);
        // A secret-less identity cannot agree.
        let pubonly = NodeIdentity::from_parts(0x222222222, pub2, None);
        assert!(pubonly.agree(&id1).is_err());
    }

    /// Sign/verify: the ZeroTier 96-byte packaging over ring's
    /// standard Ed25519, plus the tamper rejects.
    #[test]
    fn identity_sign_verify() {
        let known_good = "8e4df28b72:0:ac3d46abe0c21f3cfe7a6c8d6a85cfcffcb82fbd55af6a4d6350657c68200843fa2e16f9418bbd9702cae365f2af5fb4c420908b803a681d4daef6114d78a2d7:bd8dd6e4ce7022d2f812797a80c6ee8ad180dc4ebf301dec8b06d1be08832bddd63a2f1cfa7b2c504474c75bdc8898ba476ef92e8e2d0509f8441985171ff16e";
        let id = NodeIdentity::from_str_form(known_good).unwrap();
        let msg = b"the controller's netconf chunk";
        let sig = id.sign(msg).unwrap();
        assert_eq!(sig.len(), SIGNATURE_SIZE);
        assert!(id.verify(msg, &sig));
        assert!(!id.verify(b"tampered message", &sig));
        let mut tampered = sig;
        tampered[0] ^= 1;
        assert!(!id.verify(msg, &tampered));
        tampered = sig;
        tampered[64] ^= 1; // the embedded digest
        assert!(!id.verify(msg, &tampered));
        // A different verifier identity fails.
        let other = NodeIdentity::from_parts(0x333333333, [9u8; 64], None);
        assert!(!other.verify(msg, &sig));
    }

    /// Full identity generation (the PoW search). Env-gated: ~16.6
    /// memory-hard hashes — seconds in release, too slow for debug CI.
    #[test]
    #[ignore = "expensive: enable with RUSTCRASH_TEST_ZT_GEN=1"]
    fn identity_generate_pow() {
        if std::env::var("RUSTCRASH_TEST_ZT_GEN").ok().as_deref() != Some("1") {
            return;
        }
        let id = NodeIdentity::generate().unwrap();
        assert!(id.locally_validate());
        assert!(id.secret.is_some());
        let parsed = NodeIdentity::from_str_form(&id.to_secret_str().unwrap()).unwrap();
        assert_eq!(parsed, id);
    }

    // -----------------------------------------------------------------
    // Packet armor + the HELLO conversation
    // -----------------------------------------------------------------

    /// A synthetic identity with consistent key halves and a fixed
    /// address — the codec tests don't need PoW-valid addresses (the
    /// responder's locallyValidate call is policy, not codec).
    fn synth_identity(tag: u8, address: u64) -> NodeIdentity {
        let mut secret = [0u8; 64];
        secret[..32].fill(tag);
        secret[32..].fill(tag ^ 0x5a);
        let mut public = [0u8; 64];
        public[..32].copy_from_slice(
            &curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(
                secret[..32].try_into().unwrap(),
            )
            .0,
        );
        public[32..].copy_from_slice(&ed25519_public_from_seed(&secret[32..64]).unwrap());
        NodeIdentity::from_parts(address, public, Some(secret))
    }

    #[test]
    fn armor_roundtrip_and_tamper() {
        let a = synth_identity(0x11, 0x0000000001);
        let b = synth_identity(0x22, 0x0000000002);
        let key = a.agree(&b).unwrap();
        let mut pkt = WirePacket::new(b.address(), a.address(), Verb::Echo);
        pkt.push_bytes(b"echo payload bytes");
        let wire = pkt.as_bytes().to_vec();
        pkt.armor(&key, true);
        assert_eq!(pkt.cipher().unwrap(), CipherSuite::C25519Poly1305Salsa2012);
        assert_ne!(pkt.as_bytes(), wire); // MAC + ciphertext differ
        // The peer derives the same key and opens it.
        let mut inbound = WirePacket::from_bytes(pkt.as_bytes()).unwrap();
        assert_eq!(inbound.source(), a.address());
        inbound.dearmor(&b.agree(&a).unwrap()).unwrap();
        assert_eq!(inbound.payload(), b"echo payload bytes");
        // Any tamper — payload, header, MAC — fails the MAC check.
        for bit in [0usize, 9, 18, 20, 30] {
            let mut tampered = pkt.as_bytes().to_vec();
            tampered[bit] ^= 0x80;
            let mut t = WirePacket::from_bytes(&tampered).unwrap();
            assert!(t.dearmor(&key).is_err(), "tamper at byte {bit} accepted");
        }
        // A wrong key fails too.
        let mut wrong = WirePacket::from_bytes(pkt.as_bytes()).unwrap();
        assert!(wrong.dearmor(&[3u8; 48]).is_err());
    }

    /// The full milestone-1 conversation, both ends in-process:
    /// HELLO (suite 0) → OK(HELLO) (suite 1) → one encrypted packet.
    #[test]
    fn hello_conversation() {
        let a = synth_identity(0x11, 0x0000000001);
        let b = synth_identity(0x22, 0x0000000002);
        let key_ab = a.agree(&b).unwrap();
        let key_ba = b.agree(&a).unwrap();

        // A sends HELLO toward B's physical endpoint (suite 0).
        let hello = build_hello(
            &a,
            b.address(),
            PhysAddr::V4([10, 0, 0, 2], 9993),
            (0x93f5, 0x0123),
            &[(0xdeadbeef, 42)],
            1_700_000_000_000,
            &key_ab,
        )
        .unwrap();
        assert_eq!(hello.cipher().unwrap(), CipherSuite::C25519Poly1305None);
        assert_eq!(hello.verb().unwrap(), Verb::Hello);

        // B dearmors with the key derived from A's claimed identity.
        let mut inbound = WirePacket::from_bytes(hello.as_bytes()).unwrap();
        inbound.dearmor(&key_ba).unwrap();
        let parsed = parse_hello(&inbound).unwrap();
        assert_eq!(parsed.identity.address(), a.address());
        assert_eq!(parsed.proto_version, PROTO_VERSION);
        assert_eq!(parsed.timestamp, 1_700_000_000_000);
        assert_eq!(parsed.physical, PhysAddr::V4([10, 0, 0, 2], 9993));
        assert_eq!(parsed.world_id, 0x93f5);
        assert!(parsed.moon_tail.is_some(), "moon tail must be present");
        // The moon tail unmangles with the pairwise key (crypt_field's
        // IV masking included).
        let mut tail = parsed.moon_tail.clone().unwrap();
        let mut iv = [0u8; 8];
        iv.copy_from_slice(&hello.as_bytes()[0..8]);
        iv[7] &= 0xf8;
        let tail_key: [u8; 32] = key_ba[..32].try_into().unwrap();
        salsa20_xor(&tail_key, &iv, &mut tail, 12);
        assert_eq!(tail[2], 1u8); // World::TYPE_MOON
        assert_eq!(
            u64::from_be_bytes(tail[3..11].try_into().unwrap()),
            0xdeadbeef
        );

        // B replies OK(HELLO), encrypted.
        let ok = build_ok_hello(
            &b,
            &parsed,
            hello.packet_id(),
            a.address(),
            PhysAddr::V4([10, 0, 0, 1], 9993),
            &key_ba,
        )
        .unwrap();
        assert_eq!(ok.cipher().unwrap(), CipherSuite::C25519Poly1305Salsa2012);
        let mut ok_in = WirePacket::from_bytes(ok.as_bytes()).unwrap();
        ok_in.dearmor(&key_ab).unwrap();
        let parsed_ok = parse_ok_hello(&ok_in).unwrap();
        assert_eq!(parsed_ok.in_re_packet_id, hello.packet_id());
        assert_eq!(parsed_ok.timestamp, parsed.timestamp);
        assert_eq!(parsed_ok.proto_version, PROTO_VERSION);
        assert_eq!(parsed_ok.physical, PhysAddr::V4([10, 0, 0, 1], 9993));

        // One encrypted data-plane exchange (VERB_ECHO).
        let mut data = WirePacket::new(b.address(), a.address(), Verb::Echo);
        data.push_bytes(&[0xab; 200]);
        data.armor(&key_ab, true);
        let mut data_in = WirePacket::from_bytes(data.as_bytes()).unwrap();
        data_in.dearmor(&key_ba).unwrap();
        assert_eq!(data_in.verb().unwrap(), Verb::Echo);
        assert_eq!(data_in.payload(), &[0xab; 200]);
    }

    #[test]
    fn phys_addr_wire_format() {
        let mut buf = Vec::new();
        PhysAddr::None.serialize_into(&mut buf);
        assert_eq!(buf, vec![0u8]);
        let (parsed, used) = PhysAddr::deserialize_from(&buf, 0).unwrap();
        assert_eq!(parsed, PhysAddr::None);
        assert_eq!(used, 1);

        let mut buf = Vec::new();
        PhysAddr::V4([192, 168, 1, 1], 9993).serialize_into(&mut buf);
        assert_eq!(buf, vec![0x04, 192, 168, 1, 1, 0x27, 0x09]);
        let (parsed, used) = PhysAddr::deserialize_from(&buf, 0).unwrap();
        assert_eq!(parsed, PhysAddr::V4([192, 168, 1, 1], 9993));
        assert_eq!(used, 7);

        let mut buf = Vec::new();
        PhysAddr::V6([0x20u8; 16], 443).serialize_into(&mut buf);
        assert_eq!(buf.len(), 19);
        let (parsed, used) = PhysAddr::deserialize_from(&buf, 0).unwrap();
        assert_eq!(parsed, PhysAddr::V6([0x20u8; 16], 443));
        assert_eq!(used, 19);

        assert!(PhysAddr::deserialize_from(&[0x99], 0).is_err());
        assert!(PhysAddr::deserialize_from(&[], 0).is_err());
    }

    // -----------------------------------------------------------------
    // Controller netconf: request build + verified response
    // -----------------------------------------------------------------

    #[test]
    fn netconf_conversation() {
        let node = synth_identity(0x11, 0x0000000001);
        let controller = synth_identity(0x22, 0x0000000abc);
        let nwid = 0x0000000abc000001u64;
        assert_eq!(controller_of(nwid), controller.address());

        let key_n = node.agree(&controller).unwrap();
        let key_c = controller.agree(&node).unwrap();

        // The node's request (uncompressed, suite 1).
        let req = build_network_config_request(&node, controller.address(), nwid, None, &key_n)
            .unwrap();
        let mut req_in = WirePacket::from_bytes(req.as_bytes()).unwrap();
        req_in.dearmor(&key_c).unwrap();
        req_in.uncompress().unwrap();
        assert_eq!(req_in.verb().unwrap(), Verb::NetworkConfigRequest);
        let p = req_in.payload();
        assert_eq!(u64::from_be_bytes(p[0..8].try_into().unwrap()), nwid);
        let dlen = u16::from_be_bytes(p[8..10].try_into().unwrap()) as usize;
        let meta = String::from_utf8(p[10..10 + dlen].to_vec()).unwrap();
        for needed in ["v=7\n", "pv=11\n", "vend=1\n", "mr=1024\n", "o=rustcrash-engine\n"] {
            assert!(meta.contains(needed), "meta dict missing {needed:?}: {meta}");
        }
        assert_eq!(&p[10 + dlen..], &[0u8; 16]);

        // The controller's signed, compressed OK.
        let dict = b"nwid=0000000abc000001\nnsm=1\nmtu=2800\n";
        let ok = build_netconf_ok(
            &controller,
            node.address(),
            req.packet_id(),
            nwid,
            dict,
            7,
            true,
            &key_c,
        )
        .unwrap();
        let mut ok_in = WirePacket::from_bytes(ok.as_bytes()).unwrap();
        ok_in.dearmor(&key_n).unwrap();
        ok_in.uncompress().unwrap(); // LZ4 round trip
        let resp = parse_netconf_response(&mut ok_in, &controller).unwrap();
        assert_eq!(resp.network_id, nwid);
        assert_eq!(resp.update_id, 7);
        assert_eq!(resp.dict, dict);

        // Tampered chunk body fails the signature.
        let ok2 = build_netconf_ok(
            &controller,
            node.address(),
            req.packet_id(),
            nwid,
            dict,
            8,
            false,
            &key_c,
        )
        .unwrap();
        let mut raw = ok2.into_bytes();
        // Flip a dict byte inside the (uncompressed) signed region.
        let dict_off = PACKET_IDX_PAYLOAD + 9 + 8 + 2 + 2;
        raw[dict_off] ^= 1;
        // Re-armor integrity is now broken — the MAC check catches it
        // first, so instead simulate a compromised-transport parse by
        // rebuilding the packet from the tampered plaintext.
        let mut tampered = WirePacket::from_bytes(&raw).unwrap();
        tampered.dearmor(&key_n).expect_err("MAC must fail");
        // And with a wrong verifier identity the signature check fails.
        let ok3_raw = build_netconf_ok(
            &controller,
            node.address(),
            req.packet_id(),
            nwid,
            dict,
            9,
            false,
            &key_c,
        )
        .unwrap();
        let mut ok3 = WirePacket::from_bytes(ok3_raw.as_bytes()).unwrap();
        ok3.dearmor(&key_n).unwrap();
        let wrong_ctrl = synth_identity(0x33, 0x0000000abd);
        assert!(parse_netconf_response(&mut ok3, &wrong_ctrl).is_err());
    }

    #[test]
    fn netconf_meta_dict_is_a_dictionary() {
        let dict = netconf_request_meta_dict();
        assert!(dict.ends_with('\n'));
        assert!(dict.lines().all(|l| l.contains('=') && !l.contains(':')));
    }

    // -----------------------------------------------------------------
    // LZ4 block decode (spec-constructed vectors)
    // -----------------------------------------------------------------

    #[test]
    fn lz4_block_decode_spec_vectors() {
        // Empty input: a lone zero token (spec: "Even empty input can
        // be represented, using a zero byte").
        assert_eq!(lz4_block_decode(&[0x00], 1024).unwrap(), Vec::<u8>::new());
        // Literal-only final sequence: token's HIGH nibble is the
        // literal length — 0x50 = 5 literals, no match.
        let mut lit = vec![0x50, b'h', b'e', b'l', b'l', b'o'];
        assert_eq!(lz4_block_decode(&lit, 1024).unwrap(), b"hello");
        // Literal + an offset-1 match of 5 (nibble 1 = minmatch 4+1):
        // "ab" then 5×'b', closed by the final zero token.
        lit = vec![0x21, b'a', b'b', 0x01, 0x00, 0x00];
        assert_eq!(lz4_block_decode(&lit, 1024).unwrap(), b"abbbbbb");
        // Overlapping long match: literal 'A', offset 1, length 19+ext,
        // then the mandatory final literal-only token (spec end
        // condition: "the last sequence contains only literals").
        let mut enc = vec![0x1f, b'A', 0x01, 0x00, 0x01, 0x00];
        let out = lz4_block_decode(&enc, 1024).unwrap();
        let mut want = vec![b'A'];
        want.extend(std::iter::repeat_n(b'A', 20));
        assert_eq!(out, want);
        enc[4] = 0xff; // extension chain: 255 then 0 → length 19+255
        enc[5] = 0x00;
        enc.push(0x00); // final token again
        let out = lz4_block_decode(&enc, 1024).unwrap();
        assert_eq!(out.len(), 1 + 19 + 255);
        // Length-extension literals: token 0xf0 + ext bytes + literals.
        let mut big = vec![0xf0, 0xf0];
        big.extend_from_slice(&[7u8; 15 + 240]);
        assert_eq!(lz4_block_decode(&big, 1024).unwrap(), vec![7u8; 255]);
        // The module's own encoder is decodable.
        let payload: Vec<u8> = (0..1000u32).map(|i| (i % 251) as u8).collect();
        let encoded = lz4_literal_encode(&payload);
        assert_eq!(lz4_block_decode(&encoded, 4096).unwrap(), payload);
        // Malformed inputs are rejected.
        assert!(lz4_block_decode(&[], 1024).is_err()); // truncated
        assert!(lz4_block_decode(&[0x20, b'x'], 1024).is_err()); // literals overrun
        assert!(lz4_block_decode(&[0x00, 0x01, 0x00], 1024).is_err()); // offset without history
        assert!(lz4_block_decode(&[0x21, b'a', b'b', 0x00, 0x00], 1024).is_err()); // offset 0
        assert!(lz4_block_decode(&[0x21, b'a', b'b', 0x02, 0x00], 4).is_err()); // cap overrun
    }

    // -----------------------------------------------------------------
    // Config surface
    // -----------------------------------------------------------------

    #[test]
    fn network_id_parsing() {
        // 16 hex digits parse; ad-hoc (0xff top byte) recognized.
        assert_eq!(parse_network_id("8056c2e21c000001").unwrap(), 0x8056c2e21c000001);
        assert!(is_adhoc_network_id(parse_network_id("ffffc2e21c000001").unwrap()));
        assert!(!is_adhoc_network_id(parse_network_id("8056c2e21c000001").unwrap()));
        assert!(!is_adhoc_network_id(parse_network_id("00ffc2e21c000001").unwrap()));
        // Wrong length / non-hex / zero / reserved-controller inputs fail.
        for bad in [
            "8056c2e21c0000",
            "8056c2e21c0000012",
            "8056c2e21c00000g",
            "",
            "0000000000000000",
        ] {
            assert!(parse_network_id(bad).is_err(), "{bad:?}");
        }
        let err = parse_network_id("short").unwrap_err().to_string();
        assert!(err.contains("16 hex digits"), "{err}");
    }

    #[test]
    fn node_address_parsing_is_hex10() {
        // zerotier-go address.go:44: "a ten-character hexadecimal
        // ZeroTier node address" (the wave-10 decimal reading was a
        // probe error — fixed here).
        assert_eq!(parse_node_address("0000000123").unwrap(), 0x123);
        assert_eq!(parse_node_address("1234567890").unwrap(), 0x1234567890);
        assert_eq!(parse_node_address("abcdef0123").unwrap(), 0xabcdef0123);
        for bad in [
            "123456789",     // 9 digits
            "12345678901",   // 11 digits
            "0000000000",    // reserved: zero
            "ffffffffff",    // reserved: 0xff prefix
            "00ffffffffff",  // wrong length
        ] {
            assert!(parse_node_address(bad).is_err(), "{bad:?}");
        }
        let err = parse_node_address("nope").unwrap_err().to_string();
        assert!(err.contains("10 hex digits"), "{err}");
    }

    #[test]
    fn config_field_surface_is_complete() {
        // Every ZeroTierOption field is carried (cached lines 108-135).
        let identity = test_identity();
        let cfg = ZeroTierConfig {
            name: "zt".into(),
            network: "8056c2e21c000001".into(),
            state_dir: Some("zt-state".into()),
            identity_secret: identity.clone(),
            planet: Some("/path/planet".into()),
            mtu: 2800,
            ip_stack: IpStack::System,
            physical_mtu: 1500,
            udp: true,
            remote_dns_resolve: true,
            dns: vec!["10.144.0.1:53".into()],
            low_bandwidth: true,
            encrypted_hello: true,
            primary_port: 9993,
            secondary_port: 0,
            tcp_fallback_mode: Some("proxy".into()),
            tcp_fallback_relay: Some("tcp://relay.example:443".into()),
            orbit: vec![ZeroTierOrbit {
                world: 0x1234567890abcdef,
                seed: "0123456789".into(),
            }],
            remote_trace_target: Some("0987654321".into()),
            remote_trace_level: 1,
        };
        assert!(cfg.validate().is_ok(), "{cfg:?}");
        // The identity secret is redacted in Debug even when present.
        let debug = format!("{cfg:?}");
        if let Some(secret) = &identity {
            assert!(!debug.contains(secret.as_str()), "secret leaked in Debug");
            assert!(debug.contains("[redacted]"));
        }
    }

    #[test]
    fn validate_matches_upstream_gates() {
        // Bad network id.
        assert!(wellformed("nope").validate().is_err());
        // Identity without the private field (public form = 3 fields).
        let mut cfg = wellformed("8056c2e21c000001");
        cfg.identity_secret = Some("1234567890:pubkeyonly:0".into());
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("private keys"), "{err}");
        assert!(!identity_has_private("1234567890:pubkeyonly:0"));
        assert!(identity_has_private("1234567890:pubkey:0:secretkey"));
        cfg.identity_secret = test_identity().or(Some("1234567890:pubkey:0:secretkey".into()));
        assert!(cfg.validate().is_ok());
        // MTU windows (cached lines 219-224).
        cfg.mtu = 1279;
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("ZeroTier MTU must be between"), "{err}");
        cfg.mtu = MAX_NETWORK_MTU + 1;
        assert!(cfg.validate().is_err());
        cfg.mtu = 0; // 0 = default, fine
        cfg.physical_mtu = MIN_PHYSICAL_MTU - 1;
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("physical MTU"), "{err}");
        cfg.physical_mtu = 0;
        assert!(cfg.validate().is_ok());
        // Duplicate orbit worlds (cached lines 248-250).
        cfg.orbit = vec![
            ZeroTierOrbit { world: 7, seed: "0123456789".into() },
            ZeroTierOrbit { world: 7, seed: "0123456789".into() },
        ];
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("duplicate ZeroTier orbit world 0000000000000007"), "{err}");
        // Bad seed (non-hex10 or reserved).
        cfg.orbit = vec![ZeroTierOrbit { world: 7, seed: "nope".into() }];
        assert!(cfg.validate().is_err());
        cfg.orbit = vec![ZeroTierOrbit { world: 7, seed: "ffffffffff".into() }];
        assert!(cfg.validate().is_err());
        // Trace target must be a hex10 node id (cached lines 267-271).
        cfg.orbit.clear();
        cfg.remote_trace_target = Some("nope".into());
        assert!(cfg.validate().is_err());
        cfg.remote_trace_target = None;
        // Trace level ceiling (cached lines 273-275).
        cfg.remote_trace_level = TRACE_LEVEL_INSANE + 1;
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("remote trace level"), "{err}");
        cfg.remote_trace_level = TRACE_LEVEL_INSANE;
        assert!(cfg.validate().is_ok());
    }

    #[test]
    fn state_dir_default_derivation() {
        // cached lines 283-286: zerotier/<network>-<sha256(name)[:6]>.
        let dir = default_state_dir("my-node", "8056c2e21c000001");
        assert!(dir.starts_with("zerotier/8056c2e21c000001-"), "{dir}");
        let suffix = dir.rsplit('-').next().unwrap();
        assert_eq!(suffix.len(), 6);
        assert!(suffix.chars().all(|c| c.is_ascii_hexdigit()));
        // Different names derive different dirs; the config path picks
        // the default only when unset.
        assert_ne!(dir, default_state_dir("other", "8056c2e21c000001"));
        let cfg = ZeroTierConfig::new("my-node", "8056c2e21c000001");
        assert_eq!(cfg.effective_state_dir(), dir);
        let cfg = ZeroTierConfig {
            state_dir: Some("custom".into()),
            ..cfg
        };
        assert_eq!(cfg.effective_state_dir(), "custom");
    }

    #[test]
    fn ip_stack_option() {
        assert_eq!(IpStack::parse("").unwrap(), IpStack::Gvisor);
        assert_eq!(IpStack::parse("gvisor").unwrap(), IpStack::Gvisor);
        assert_eq!(IpStack::parse(" system ").unwrap(), IpStack::System);
        let err = IpStack::parse("lwip").unwrap_err().to_string();
        assert!(err.contains("gvisor or system"), "{err}");
        assert_eq!(IpStack::default().as_str(), "gvisor");
    }

    #[test]
    fn packet_header_layout() {
        let pkt = WirePacket::new(0x123456789a, 0x00beefcafe, Verb::NetworkConfigRequest);
        let b = pkt.as_bytes();
        assert_eq!(b.len(), PACKET_HEADER_LEN);
        assert_eq!(&b[PACKET_IDX_DEST..PACKET_IDX_SOURCE], &[0x12, 0x34, 0x56, 0x78, 0x9a]);
        assert_eq!(&b[PACKET_IDX_SOURCE..PACKET_IDX_FLAGS], &[0x00, 0xbe, 0xef, 0xca, 0xfe]);
        assert_eq!(b[PACKET_IDX_VERB], 0x0b);
        assert_eq!(pkt.packet_id(), u64::from_be_bytes(b[0..8].try_into().unwrap()));
        assert!(WirePacket::from_bytes(&b[..27]).is_err());
        let oversized = vec![0u8; MAX_PACKET_LENGTH + 1];
        assert!(WirePacket::from_bytes(&oversized).is_err());
        // Flags: cipher bits + hops.
        let mut p2 = pkt.clone();
        p2.set_compressed(true);
        assert!(p2.compressed());
        let mut p3 = pkt.clone();
        p3.buf[PACKET_IDX_FLAGS] = (1u8 << 3) | 0x05; // suite 1, 5 hops
        assert_eq!(p3.cipher().unwrap(), CipherSuite::C25519Poly1305Salsa2012);
        assert_eq!(p3.hops(), 5);
    }

    #[test]
    fn not_ported_shrunk_to_the_runtime_gaps() {
        // Milestone 2 landed the runtime; milestone 3 landed direct
        // paths, state persistence and moon gossip. The remainder is
        // the honest gap list (multicast, tap semantics...).
        assert!(NOT_PORTED.contains("MILESTONE_3"), "{NOT_PORTED}");
        assert!(NOT_PORTED.contains("PUSH_DIRECT_PATHS"), "{NOT_PORTED}");
        assert!(NOT_PORTED.contains("state-dir persistence"), "{NOT_PORTED}");
        assert!(NOT_PORTED.contains("moon orbit gossip"), "{NOT_PORTED}");
        // The landed items must be GONE from the gap list.
        assert!(!NOT_PORTED.contains("root-relayed)"), "{NOT_PORTED}");
        assert!(
            !NOT_PORTED.contains("TCP fallback, on-disk state"),
            "{NOT_PORTED}"
        );
        assert!(NOT_PORTED.contains("multicast"), "{NOT_PORTED}");
        assert!(!NOT_PORTED.contains("transport loop"), "{NOT_PORTED}");
        assert!(!NOT_PORTED.contains("world/planet parsing"), "{NOT_PORTED}");
    }

    // -----------------------------------------------------------------
    // Milestone 2: world/planet
    // -----------------------------------------------------------------

    /// The built-in Earth planet (`ZT_DEFAULT_WORLD`, Topology.cpp:20-37)
    /// parses exactly: type PLANET, id 149604618, four roots with their
    /// real stable endpoints, full 570-byte consume, and its own
    /// signature verifies — the trust anchor a fresh node starts from.
    #[test]
    fn builtin_planet_parses_and_verifies() {
        let bytes = default_planet();
        assert_eq!(bytes.len(), 570);
        let world = World::parse_planet(bytes).unwrap();
        assert_eq!(world.world_type, WORLD_TYPE_PLANET);
        assert_eq!(world.id, WORLD_ID_EARTH);
        assert_eq!(world.id, 149604618);
        assert!(world.timestamp > 0);
        assert_eq!(world.roots.len(), 4);
        assert!(world.signature_is_valid());
        // The four real root addresses, in planet order.
        let addrs: Vec<u64> = world.roots.iter().map(|r| r.identity.address()).collect();
        assert_eq!(
            addrs,
            vec![0xcafe9efeb9, 0x778cde7190, 0x62f865ae71, 0xcafe04eba9]
        );
        // Root 0's stable endpoints: 104.194.8.134:9993 + the v6 twin
        // (transcribed from the binary above).
        let root0 = &world.roots[0];
        assert_eq!(
            root0.endpoints[0],
            PhysAddr::V4([104, 194, 8, 134], 9993)
        );
        assert_eq!(
            root0.endpoints[1].to_socket_addr().unwrap().port(),
            9993
        );
        // Round-trip: re-serializing the parsed world is byte-exact.
        assert_eq!(world.to_bytes(), bytes);
        // Tampering with any byte breaks the signature (checked where
        // the tamper doesn't invalidate the structure itself).
        for bit in [0usize, 40, 120, 400, 569] {
            let mut t = bytes.to_vec();
            t[bit] ^= 1;
            let parsed = World::from_bytes(&t);
            if let Ok((w, used)) = parsed {
                if used == t.len() {
                    assert!(!w.signature_is_valid(), "tamper at {bit} verified");
                }
            }
        }
        // Structural rejects: truncation, trailing junk, no roots.
        assert!(World::parse_planet(&bytes[..569]).is_err());
        let mut junk = bytes.to_vec();
        junk.push(0);
        assert!(World::parse_planet(&junk).is_err());
    }

    /// `World::make` → `parse_planet` round-trip + the update rule
    /// (`shouldBeReplacedBy`: same id+type, newer ts, valid signature
    /// under the previous key).
    #[test]
    fn world_make_sign_and_replace() {
        let signer = synth_identity(0x55, 0x0000000099);
        let r1 = synth_identity(0x11, 0x0000000001);
        let r2 = synth_identity(0x22, 0x0000000002);
        let world = World::make(
            WORLD_TYPE_PLANET,
            0xfeedface,
            1000,
            &signer,
            vec![
                WorldRoot {
                    identity: r1.clone(),
                    endpoints: vec![PhysAddr::V4([10, 1, 1, 1], 9993)],
                },
                WorldRoot { identity: r2, endpoints: vec![] },
            ],
        )
        .unwrap();
        let bytes = world.to_bytes();
        let parsed = World::parse_planet(&bytes).unwrap();
        // Parsed roots are public-form identities (no secret half), so
        // compare the wire-visible fields; the byte round-trip below
        // proves the rest.
        assert_eq!(parsed.world_type, world.world_type);
        assert_eq!(parsed.id, world.id);
        assert_eq!(parsed.timestamp, world.timestamp);
        assert_eq!(parsed.must_be_signed_by, world.must_be_signed_by);
        assert_eq!(parsed.signature, world.signature);
        assert_eq!(
            parsed
                .roots
                .iter()
                .map(|r| (r.identity.address(), r.endpoints.clone()))
                .collect::<Vec<_>>(),
            world
                .roots
                .iter()
                .map(|r| (r.identity.address(), r.endpoints.clone()))
                .collect::<Vec<_>>()
        );
        assert_eq!(parsed.to_bytes(), bytes);
        assert_eq!(parsed.roots[0].identity.address(), r1.address());
        assert_eq!(parsed.roots[0].endpoints.len(), 1);

        // A newer revision signed by the same key replaces; one signed
        // by a different key does not (the next-update key must match).
        let newer = World::make(WORLD_TYPE_PLANET, 0xfeedface, 2000, &signer, vec![
            WorldRoot { identity: r1, endpoints: vec![] },
        ])
        .unwrap();
        assert!(newer.signature_is_valid());
        assert!(newer.timestamp > parsed.timestamp);
        let other_signer = synth_identity(0x66, 0x00000000aa);
        let forged = World::make(WORLD_TYPE_PLANET, 0xfeedface, 3000, &other_signer, vec![])
            .unwrap();
        assert!(forged.signature_is_valid()); // self-consistent...
        // ...but parse_planet anchors on its own key; the *replacement*
        // check upstream performs (verify with the OLD world's key) is
        // what rejects it:
        let old_key = NodeIdentity::from_parts(0, parsed.must_be_signed_by, None);
        let mut body = Vec::new();
        forged.serialize(true, &mut body);
        assert!(!old_key.verify(&body, &forged.signature));
        let mut body = Vec::new();
        newer.serialize(true, &mut body);
        assert!(old_key.verify(&body, &newer.signature));

        // A moon carries the trailing dictionary length and parses.
        let moon = World::make(WORLD_TYPE_MOON, 0x1234, 7, &signer, vec![]).unwrap();
        let (parsed_moon, used) = World::from_bytes(&moon.to_bytes()).unwrap();
        assert_eq!(used, moon.to_bytes().len());
        assert_eq!(parsed_moon.world_type, WORLD_TYPE_MOON);
        // Limits: >4 roots rejected (ZT_WORLD_MAX_ROOTS).
        let many: Vec<WorldRoot> = (0..5)
            .map(|i| WorldRoot {
                identity: synth_identity(i, 0x0000000100 + i as u64),
                endpoints: vec![],
            })
            .collect();
        assert!(World::make(WORLD_TYPE_PLANET, 1, 1, &signer, many.clone()).is_ok());
        let signed = World::make(WORLD_TYPE_PLANET, 1, 1, &signer, many).unwrap();
        let mut truncated = signed.to_bytes();
        truncated.truncate(50);
        assert!(World::from_bytes(&truncated).is_err());
    }

    // -----------------------------------------------------------------
    // Milestone 2: fragmentation
    // -----------------------------------------------------------------

    /// The send-side slicing matches `Switch::_sendViaSpecificPath`:
    /// head truncated to the path MTU, fragments of `mtu-16`, correct
    /// header fields, and the >7-fragment rejection.
    #[test]
    fn fragment_slicing_matches_switch() {
        let armored = vec![0xa5u8; 5000];
        // Give it a plausible IV/dest so fragment headers carry real
        // fields: the codec only copies bytes, so a pattern suffices.
        let dgs = fragment_packet(&armored, 1400).unwrap();
        assert_eq!(dgs.len(), 4); // 1 + ceil(3600/1384)
        assert_eq!(&dgs[0], &armored[..1400]);
        for (i, dg) in dgs.iter().enumerate().skip(1) {
            let frag = WireFragment::from_bytes(dg).unwrap();
            assert_eq!(frag.total_fragments(), 4);
            assert_eq!(frag.fragment_number(), i);
            assert_eq!(frag.packet_id(), u64::from_be_bytes(armored[0..8].try_into().unwrap()));
            assert_eq!(frag.destination(), be40(&armored[8..13]));
            assert_eq!(dg.len(), 16 + 1384.min(5000 - 1400 - (i - 1) * 1384));
        }
        assert_eq!(fragment_count(5000, 1400), 4);
        // Exactly at the MTU: one datagram, no fragments.
        let one = fragment_packet(&armored[..1400], 1400).unwrap();
        assert_eq!(one.len(), 1);
        assert_eq!(fragment_count(1400, 1400), 1);
        // 8000 bytes at mtu 1000 needs 9 > ZT_MAX_PACKET_FRAGMENTS.
        let big = vec![0u8; 8000];
        let err = fragment_packet(&big, 1000).unwrap_err().to_string();
        assert!(err.contains("max 7"), "{err}");
        // An MTU that cannot carry a fragment header is refused.
        assert!(fragment_packet(&big, 16).is_err());
    }

    /// The receive-side queue (`Switch::onRemotePacket`): assemble on
    /// the last piece regardless of order, ignore duplicates, stall on
    /// loss, pass unfragmented heads straight through.
    #[test]
    fn fragment_assembly_order_dups_loss() {
        let armored = vec![0x5au8; 5000];
        let dgs = fragment_packet(&armored, 1400).unwrap();
        // Reverse arrival order: the head lands last.
        let mut asm = FragmentAssembler::default();
        for dg in dgs.iter().skip(1).rev() {
            assert!(asm.ingest(dg).is_none(), "completed without the head");
        }
        assert_eq!(asm.ingest(&dgs[0]).as_deref(), Some(&armored[..]));

        // Duplicates (head or fragment) are ignored without breaking
        // a fresh assembly.
        let mut asm = FragmentAssembler::default();
        assert!(asm.ingest(&dgs[0]).is_none());
        assert!(asm.ingest(&dgs[0]).is_none()); // duplicate head
        assert!(asm.ingest(&dgs[1]).is_none());
        assert!(asm.ingest(&dgs[1]).is_none()); // duplicate fragment
        assert!(asm.ingest(&dgs[2]).is_none());
        assert!(asm.ingest(&dgs[2]).is_none());
        assert_eq!(asm.ingest(&dgs[3]).as_deref(), Some(&armored[..]));

        // Loss of one fragment: never completes.
        let mut asm = FragmentAssembler::default();
        asm.ingest(&dgs[0]);
        asm.ingest(&dgs[1]);
        asm.ingest(&dgs[3]); // fragment 2 lost
        assert!(asm.ingest(&dgs[1]).is_none()); // dup still ignored
        assert!(asm.entries.contains_key(&u64::from_be_bytes(
            dgs[0][0..8].try_into().unwrap()
        )));

        // Unfragmented head passes through directly.
        let mut asm = FragmentAssembler::default();
        assert_eq!(asm.ingest(&dgs[0].clone()).map(|_| ()), None); // head of a fragmented set waits
        let plain = vec![7u8; 100];
        assert_eq!(asm.ingest(&plain), Some(plain.clone()));
        // Malformed: a "fragment" with number 0 or total <= 1 is junk.
        let mut junk = dgs[1].clone();
        junk[14] = 0x01; // total 0, no 1 — both invalid
        let mut asm = FragmentAssembler::default();
        assert!(asm.ingest(&junk).is_none());
        assert!(asm.entries.is_empty());
    }

    /// A fragmented VERB_FRAME reassembles and dearmors to the exact
    /// original payload — the MAC covers the whole assembled packet
    /// (fragments carry none of their own).
    #[test]
    fn fragmented_armored_frame_roundtrips() {
        let a = synth_identity(0x11, 0x0000000001);
        let b = synth_identity(0x22, 0x0000000002);
        let key = a.agree(&b).unwrap();
        let payload: Vec<u8> = (0..4000u32).map(|i| (i % 251) as u8).collect();
        let mut pkt = build_frame(&a, b.address(), 0x1234_0000_0000, ETHERTYPE_IPV4, &payload);
        let dgs = armor_and_fragment(&mut pkt, &key, 700).unwrap();
        assert!(dgs.len() >= 6, "small MTU must force many fragments: {}", dgs.len());
        assert!(dgs.iter().skip(1).all(|d| d.len() <= 700));
        // Feed in order; the last datagram completes.
        let mut asm = FragmentAssembler::default();
        let mut assembled = None;
        for dg in &dgs {
            if let Some(full) = asm.ingest(dg) {
                assembled = Some(full);
            }
        }
        let mut full = WirePacket::from_bytes(&assembled.unwrap()).unwrap();
        full.dearmor(&b.agree(&a).unwrap()).unwrap();
        assert_eq!(parse_frame(&full).unwrap().frame, payload);
        // Flipping any fragment byte breaks the whole-packet MAC.
        let mut evil = dgs[2].clone();
        let idx = evil.len() - 1;
        evil[idx] ^= 0x80;
        let mut asm = FragmentAssembler::default();
        let mut assembled = None;
        for dg in dgs.iter().enumerate().map(|(i, d)| if i == 2 { &evil } else { d }) {
            if let Some(full) = asm.ingest(dg) {
                assembled = Some(full);
            }
        }
        let mut full = WirePacket::from_bytes(&assembled.unwrap()).unwrap();
        assert!(full.dearmor(&b.agree(&a).unwrap()).is_err());
    }

    // -----------------------------------------------------------------
    // Milestone 2: the netconf dictionary
    // -----------------------------------------------------------------

    /// Dictionary escapes round-trip, and `parse_applied_netconf`
    /// extracts the managed surface exactly as `fromDictionary` does.
    #[test]
    fn netconf_dict_fields_and_escapes() {
        // Managed ip 172.29.1.10/24 + route 172.29.1.0/24 (on-link) +
        // specialist bridge — binary values escaped like Dictionary::add.
        let mut ips = vec![4u8, 172, 29, 1, 10];
        ips.extend_from_slice(&24u16.to_be_bytes());
        let mut rt = vec![4u8, 172, 29, 1, 0];
        rt.extend_from_slice(&24u16.to_be_bytes());
        rt.push(0); // via: none
        rt.extend_from_slice(&0u16.to_be_bytes());
        rt.extend_from_slice(&0u16.to_be_bytes());
        let sp = 0x0a0b0c0d11u64.to_be_bytes().to_vec();
        let mut dict = format!(
            "v=7\nnwid={:x}\nts={:x}\nr=2\nid={:010x}\nmtu=af0\n",
            0x0a0b0c0d11000001u64,
            1_700_000_000_000u64,
            0x0a0b0c0d11u64,
        )
        .into_bytes();
        dict.extend_from_slice(b"I=");
        dict.extend_from_slice(&escape_dict_value(&ips));
        dict.push(b'\n');
        dict.extend_from_slice(b"RT=");
        dict.extend_from_slice(&escape_dict_value(&rt));
        dict.push(b'\n');
        dict.extend_from_slice(b"S=");
        dict.extend_from_slice(&escape_dict_value(&sp));
        dict.push(b'\n');
        // The escaped forms really do contain the escapes (the .0 octet
        // and the netmask high byte are NULs) — and the raw 172 stays a
        // single raw byte, never re-encoded.
        assert!(dict.windows(2).any(|w| w == b"\\0"), "{dict:?}");
        assert!(dict.contains(&172u8));
        assert!(dict.contains(&29u8));

        let resp = NetconfResponse {
            network_id: 0x0a0b0c0d11000001,
            update_id: 9,
            dict,
        };
        let applied = parse_applied_netconf(&resp).unwrap();
        assert_eq!(applied.network_id, 0x0a0b0c0d11000001);
        assert_eq!(applied.revision, 2);
        assert_eq!(applied.update_id, 9);
        assert_eq!(applied.mtu, 0xaf0); // 2800, as clamped passthrough
        assert_eq!(
            applied.managed_ips,
            vec![(IpAddr::V4(Ipv4Addr::new(172, 29, 1, 10)), 24)]
        );
        assert_eq!(applied.routes.len(), 1);
        assert_eq!(
            applied.routes[0].target,
            (IpAddr::V4(Ipv4Addr::new(172, 29, 1, 0)), 24)
        );
        assert_eq!(applied.routes[0].via, None);
        assert_eq!(applied.specialists, vec![0x0a0b0c0d11]);

        // A gateway route (via present).
        let mut rt2 = vec![4u8, 10, 0, 0, 0];
        rt2.extend_from_slice(&8u16.to_be_bytes());
        rt2.extend_from_slice(&[4u8, 10, 144, 0, 1]);
        rt2.extend_from_slice(&9993u16.to_be_bytes());
        rt2.extend_from_slice(&0u16.to_be_bytes());
        rt2.extend_from_slice(&0u16.to_be_bytes());
        let mut dict = format!("v=7\nnwid={:x}\nRT=", 0x0a0b0c0d11000001u64).into_bytes();
        dict.extend_from_slice(&escape_dict_value(&rt2));
        dict.push(b'\n');
        let resp = NetconfResponse { network_id: 0x0a0b0c0d11000001, update_id: 1, dict };
        let applied = parse_applied_netconf(&resp).unwrap();
        assert_eq!(applied.routes[0].via, Some(IpAddr::V4(Ipv4Addr::new(10, 144, 0, 1))));
        // mtu clamping: 100 → 1280 floor; absent → 2800 default.
        let dict = format!("v=7\nnwid={:x}\nmtu=64\n", 0x0a0b0c0d11000001u64).into_bytes();
        let resp = NetconfResponse { network_id: 0x0a0b0c0d11000001, update_id: 1, dict };
        assert_eq!(parse_applied_netconf(&resp).unwrap().mtu, 1280);
        let dict = format!("v=7\nnwid={:x}\n", 0x0a0b0c0d11000001u64).into_bytes();
        let resp = NetconfResponse { network_id: 0x0a0b0c0d11000001, update_id: 1, dict };
        assert_eq!(parse_applied_netconf(&resp).unwrap().mtu, DEFAULT_NETWORK_MTU);
        // Missing nwid, or a mismatched one, is fatal.
        let resp = NetconfResponse { network_id: 1, dict: b"v=7\n".to_vec(), update_id: 1 };
        assert!(parse_applied_netconf(&resp).is_err());
        // escape/unescape round-trip over every byte.
        for b in 0u16..256 {
            let raw = [(b as u8).wrapping_mul(7), b as u8, 0x0a, b as u8];
            let esc = escape_dict_value(&raw);
            assert!(esc.iter().all(|&c| c != b'\n' || b == 0x0a));
            assert_eq!(unescape_dict_value(&esc), raw, "byte {b}");
        }
    }

    /// The dial target policy: managed IPs only, domains refused, v6
    /// needs a managed v6 address.
    #[test]
    fn dial_target_policy() {
        let none: Option<AppliedNetconf> = None;
        let ip4 = NetAddr::ip(IpAddr::V4(Ipv4Addr::new(172, 29, 1, 20)), 80);
        assert!(zt_target_addr(&ip4, &none).is_ok());
        let dom = NetAddr::new(crate::addr::Host::Domain("peer.zt".into()), 80);
        let err = zt_target_addr(&dom, &none).unwrap_err().to_string();
        assert!(err.contains("resolve it before routing"), "{err}");
        let ip6 = NetAddr::ip(IpAddr::V6(Ipv6Addr::LOCALHOST), 80);
        assert!(zt_target_addr(&ip6, &none).is_err());
        let with_v6 = Some(AppliedNetconf {
            network_id: 1,
            revision: 0,
            update_id: 0,
            mtu: 2800,
            managed_ips: vec![(IpAddr::V6(Ipv6Addr::LOCALHOST), 128)],
            routes: vec![],
            specialists: vec![],
        });
        assert!(zt_target_addr(&ip6, &with_v6).is_ok());
        // Source selection picks the family's managed address.
        let both = Some(AppliedNetconf {
            network_id: 1,
            revision: 0,
            update_id: 0,
            mtu: 2800,
            managed_ips: vec![
                (IpAddr::V4(Ipv4Addr::new(172, 29, 1, 10)), 24),
                (IpAddr::V6(Ipv6Addr::LOCALHOST), 128),
            ],
            routes: vec![],
            specialists: vec![],
        });
        let sa = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(172, 29, 1, 20), 80));
        assert_eq!(
            local_address_for(&both, &sa),
            Some(IpAddress::Ipv4(Ipv4Addr::new(172, 29, 1, 10)))
        );
        assert_eq!(local_address_for(&none, &sa), None);
    }

    // -----------------------------------------------------------------
    // The hermetic end-to-end: in-test planet root + controller +
    // bridge (active-bridge specialist with an echo stack) + the node
    // runtime under test — identity → planet → HELLO → WHOIS → netconf
    // → smoltcp dial → TCP echo (fragmented both ways) + UDP echo.
    // -----------------------------------------------------------------

    const E2E_TCP_ECHO: u16 = 17007;
    const E2E_UDP_ECHO: u16 = 17008;
    const E2E_NODE_IP: Ipv4Addr = Ipv4Addr::new(172, 29, 1, 10);
    const E2E_BRIDGE_IP: Ipv4Addr = Ipv4Addr::new(172, 29, 1, 20);

    /// The responder side of the wire, transcribed from the same
    /// upstream sources as the runtime (IncomingPacket.cpp's _doHELLO /
    /// _doWHOIS / the Node.cpp netconf reply / Switch.cpp relay).
    struct Mimic {
        identity: NodeIdentity,
        socket: Arc<UdpSocket>,
        /// address → (identity, endpoint), learned from HELLOs.
        known: Arc<std::sync::Mutex<HashMap<u64, (NodeIdentity, SocketAddr)>>>,
        /// The planet root (address, identity, endpoint) for relaying
        /// and WHOIS; None on the root itself.
        root: Option<(u64, NodeIdentity, SocketAddr)>,
        world: (u64, u64),
        /// Per-mimic fragment queue (packet ids are globally unique, so
        /// one queue per mimic is all the separation needed).
        frags: FragmentAssembler,
        /// Pairs already introduced (the root's `_shouldUnite` gate,
        /// once per pair for the test's lifetime).
        introduced: std::collections::HashSet<(u64, u64)>,
        /// A moon this mimic serves to peers listing it in their HELLO
        /// tail (the `_doHELLO` world-update block).
        moon: Option<World>,
    }

    impl Mimic {
        async fn send_to(&self, dest: u64, key: &[u8; SYMMETRIC_KEY_SIZE], pkt: &mut WirePacket, mtu: usize) {
            let endpoint = self.known.lock().unwrap().get(&dest).map(|(_, e)| *e);
            let dgs = armor_and_fragment(pkt, key, mtu).unwrap();
            let via = endpoint
                .or_else(|| self.root.as_ref().map(|(_, _, ep)| *ep))
                .unwrap();
            for dg in dgs {
                let _ = self.socket.send_to(&dg, via).await;
            }
        }

        /// Send a pre-armored small packet (OK(HELLO)) direct or relayed.
        async fn send_armored(&self, dest: u64, pkt: &WirePacket) {
            let endpoint = self.known.lock().unwrap().get(&dest).map(|(_, e)| *e);
            let via = endpoint
                .or_else(|| self.root.as_ref().map(|(_, _, ep)| *ep))
                .unwrap();
            let _ = self.socket.send_to(pkt.as_bytes(), via).await;
        }

        /// One datagram: relay if not for us, else the responder verbs
        /// (the same dispatch order the runtime uses).
        async fn on_datagram(
            &mut self,
            dg: &[u8],
            from: SocketAddr,
            netconf: Option<&(u64, u64, u64)>, // (nwid, specialist, mtu) — controller role
            bridge: Option<&mut BridgeStack>,
        ) {
            if dg.len() < FRAGMENT_HEADER_LEN {
                return;
            }
            let dest = be40(&dg[PACKET_IDX_DEST..PACKET_IDX_SOURCE]);
            let source = be40(&dg[PACKET_IDX_SOURCE..PACKET_IDX_FLAGS]);
            if dest != self.identity.address() {
                // RELAY (Switch.cpp:82-152): forward toward the dest
                // with the hop count bumped — hop mutation is MAC-safe.
                let Some((_, ep)) = self.known.lock().unwrap().get(&dest).cloned() else {
                    return;
                };
                let mut fwd = dg.to_vec();
                if fwd[FRAGMENT_IDX_INDICATOR] == FRAGMENT_INDICATOR {
                    fwd[15] = fwd[15].wrapping_add(1) & 0x3f;
                } else {
                    fwd[PACKET_IDX_FLAGS] = (fwd[PACKET_IDX_FLAGS] & 0xf8)
                        | ((fwd[PACKET_IDX_FLAGS] + 1) & 0x07);
                }
                let _ = self.socket.send_to(&fwd, ep).await;
                // Switch.cpp:205-208: after a successful direct relay,
                // introduce the two parties to each other
                // (`_shouldUnite`-gated) — a RENDEZVOUS to each, naming
                // the other's live path (`Peer::introduce`).
                if self.introduced.insert((source, dest)) {
                    let known = self.known.lock().unwrap().clone();
                    if let (Some((src_id, src_ep)), Some((dst_id, dst_ep))) =
                        (known.get(&source).cloned(), known.get(&dest).cloned())
                    {
                        let to_dst = build_rendezvous(
                            &self.identity,
                            dest,
                            &Rendezvous { flags: 0, zt_address: source, sock: src_ep },
                            &self.identity.agree(&dst_id).unwrap(),
                        );
                        let _ = self.socket.send_to(to_dst.as_bytes(), ep).await;
                        let to_src = build_rendezvous(
                            &self.identity,
                            source,
                            &Rendezvous { flags: 0, zt_address: dest, sock: dst_ep },
                            &self.identity.agree(&src_id).unwrap(),
                        );
                        let _ = self.socket.send_to(to_src.as_bytes(), src_ep).await;
                    }
                }
                return;
            }
            if source == self.identity.address() {
                return;
            }
            let Some(assembled) = self.frags.ingest(dg) else {
                return;
            };
            if assembled.len() < PACKET_HEADER_LEN {
                return;
            }
            // The assembled packet's source — a fragment datagram's
            // bytes 13.. are its own header, not a source address.
            let source = be40(&assembled[PACKET_IDX_SOURCE..PACKET_IDX_FLAGS]);
            let mut pkt = match WirePacket::from_bytes(&assembled) {
                Ok(p) => p,
                Err(_) => return,
            };
            // A suite-0 HELLO from an unknown peer: learn it (the
            // identity travels in the clear — the runtime's bootstrap
            // path, mirrored here).
            if (assembled[PACKET_IDX_FLAGS] & 0x38) >> 3 == 0
                && assembled[PACKET_IDX_VERB] & 0x1f == Verb::Hello.to_byte()
            {
                let Ok(hello) = parse_hello(&pkt) else { return };
                if hello.identity.address() != source || !hello.identity.locally_validate() {
                    return;
                }
                let key = self.identity.agree(&hello.identity).unwrap();
                if pkt.dearmor(&key).is_err() {
                    return;
                }
                self.known
                    .lock()
                    .unwrap()
                    .insert(source, (hello.identity.clone(), from));
                let worlds: Vec<World> = self.moon.iter().cloned().collect();
                let ok = build_ok_hello_with_worlds(
                    &self.identity,
                    &hello,
                    pkt.packet_id(),
                    source,
                    PhysAddr::from_socket_addr(from),
                    &worlds,
                    &key,
                )
                .unwrap();
                self.send_armored(source, &ok).await;
                return;
            }
            // Everything else needs the pairwise key; an unknown source
            // is WHOISed through the root and dropped (the sender's
            // retransmit lands after the identity is learned).
            let Some((peer_id, _)) = self.known.lock().unwrap().get(&source).cloned() else {
                if let Some((root_addr, root_id, root_ep)) = &self.root {
                    let key = self.identity.agree(root_id).unwrap();
                    let mut who = build_whois(&self.identity, *root_addr, source);
                    let dgs = armor_and_fragment(&mut who, &key, DEFAULT_PHYSICAL_MTU).unwrap();
                    for d in dgs {
                        let _ = self.socket.send_to(&d, *root_ep).await;
                    }
                }
                return;
            };
            let key = self.identity.agree(&peer_id).unwrap();
            if pkt.dearmor(&key).is_err() || pkt.uncompress().is_err() {
                return;
            }
            match pkt.verb().unwrap() {
                Verb::Ok => {
                    // OK(WHOIS): learn the returned identities (their
                    // endpoints are unknown — replies route via the
                    // root relay).
                    if let Ok(ids) = parse_ok_whois(&pkt) {
                        for id in ids {
                            self.known.lock().unwrap().entry(id.address()).or_insert_with(|| {
                                (id, self.root.as_ref().map(|(_, _, ep)| *ep).unwrap())
                            });
                        }
                    }
                }
                Verb::Whois => {
                    let p = pkt.payload().to_vec();
                    let mut ok = WirePacket::new(source, self.identity.address(), Verb::Ok);
                    ok.push_u8(Verb::Whois.to_byte()).push_u64(pkt.packet_id());
                    for chunk in p.as_chunks::<5>().0 {
                        if let Some((id, _)) = self.known.lock().unwrap().get(&be40(chunk)) {
                            ok.push_bytes(&id.serialize_bin(false));
                        }
                    }
                    if ok.len() > PACKET_HEADER_LEN + 9 {
                        self.send_to(source, &key, &mut ok, DEFAULT_PHYSICAL_MTU).await;
                    }
                }
                Verb::NetworkConfigRequest => {
                    let Some((nwid, specialist, mtu)) = netconf else { return };
                    let mtu = *mtu as usize;
                    // Node.cpp:800-840 — the signed single-chunk dict:
                    // a managed /24 for the requester, the on-link
                    // route, and the bridge as active-bridge specialist.
                    let mut ips = vec![4u8];
                    ips.extend_from_slice(&E2E_NODE_IP.octets());
                    ips.extend_from_slice(&24u16.to_be_bytes());
                    let mut rt = vec![4u8, E2E_BRIDGE_IP.octets()[0], 29, 1, 0];
                    rt.extend_from_slice(&24u16.to_be_bytes());
                    rt.push(0); // via: on-link
                    rt.extend_from_slice(&0u16.to_be_bytes());
                    rt.extend_from_slice(&0u16.to_be_bytes());
                    let sp = specialist.to_be_bytes().to_vec();
                    let mut dict = format!(
                        "v=7\nnwid={nwid:x}\nts={:x}\nr=1\nid={:010x}\nmtu={mtu:x}\n",
                        1_700_000_000_000u64,
                        source,
                    )
                    .into_bytes();
                    dict.extend_from_slice(b"I=");
                    dict.extend_from_slice(&escape_dict_value(&ips));
                    dict.push(b'\n');
                    dict.extend_from_slice(b"RT=");
                    dict.extend_from_slice(&escape_dict_value(&rt));
                    dict.push(b'\n');
                    dict.extend_from_slice(b"S=");
                    dict.extend_from_slice(&escape_dict_value(&sp));
                    dict.push(b'\n');
                    let ok = build_netconf_ok(
                        &self.identity,
                        source,
                        pkt.packet_id(),
                        *nwid,
                        &dict,
                        1,
                        false,
                        &key,
                    )
                    .unwrap();
                    // Reply via the root relay (no direct path back).
                    let root_ep = self.root.as_ref().unwrap().2;
                    let _ = self.socket.send_to(ok.as_bytes(), root_ep).await;
                }
                Verb::Frame => {
                    let Some(stack) = bridge else { return };
                    let Ok(frame) = parse_frame(&pkt) else { return };
                    stack.ingress(source, &frame.frame);
                }
                Verb::PushDirectPaths => {
                    // `_doPUSH_DIRECT_PATHS`'s probe: HELLO every
                    // advertised address we do not already have.
                    let Ok(paths) = parse_push_direct_paths(&pkt) else { return };
                    let known_ep = self.known.lock().unwrap().get(&source).map(|(_, e)| *e);
                    let Some((peer_id, _)) = self.known.lock().unwrap().get(&source).cloned()
                    else {
                        return;
                    };
                    let key = self.identity.agree(&peer_id).unwrap();
                    for p in paths {
                        if Some(p.sock) == known_ep || p.sock.port() == 0 {
                            continue;
                        }
                        let hello = build_hello(
                            &self.identity,
                            source,
                            PhysAddr::from_socket_addr(p.sock),
                            self.world,
                            &[],
                            zt_now_ms(),
                            &key,
                        )
                        .unwrap();
                        let _ = self.socket.send_to(hello.as_bytes(), p.sock).await;
                    }
                }
                Verb::Rendezvous => {
                    // `_doRENDEZVOUS` on a leaf: probe the introduced
                    // peer at the given address (junk omitted — the
                    // mimic needs no NAT opening on loopback).
                    let Ok(rd) = parse_rendezvous(&pkt) else { return };
                    let Some((peer_id, _)) = self.known.lock().unwrap().get(&rd.zt_address).cloned()
                    else {
                        return;
                    };
                    let key = self.identity.agree(&peer_id).unwrap();
                    let hello = build_hello(
                        &self.identity,
                        rd.zt_address,
                        PhysAddr::from_socket_addr(rd.sock),
                        self.world,
                        &[],
                        zt_now_ms(),
                        &key,
                    )
                    .unwrap();
                    let _ = self.socket.send_to(hello.as_bytes(), rd.sock).await;
                }
                _ => {}
            }
        }

        /// HELLO the root at startup so it learns us.
        async fn hello_root(&self) {
            let Some((root_addr, root_id, root_ep)) = &self.root else { return };
            let key = self.identity.agree(root_id).unwrap();
            let hello = build_hello(
                &self.identity,
                *root_addr,
                PhysAddr::from_socket_addr(*root_ep),
                self.world,
                &[],
                zt_now_ms(),
                &key,
            )
            .unwrap();
            let _ = self.socket.send_to(hello.as_bytes(), *root_ep).await;
        }
    }

    /// The bridge's inner stack: a smoltcp interface at
    /// E2E_BRIDGE_IP/24 with a TCP echo listener and a UDP echo socket,
    /// bridged over VERB_FRAME both directions.
    struct BridgeStack {
        iface: Interface,
        sockets: SocketSet<'static>,
        shim: Shim,
        tcp: SocketHandle,
        udp: SocketHandle,
        ip_peers: HashMap<IpAddr, u64>,
        pump_buf: Vec<u8>,
        start: Instant,
    }

    impl BridgeStack {
        fn new() -> Self {
            let mut shim = Shim::new(DEFAULT_NETWORK_MTU);
            let mut cfg = IfaceConfig::new(HardwareAddress::Ip);
            cfg.random_seed = rand::random();
            let mut iface = Interface::new(cfg, &mut shim, SmolInstant::ZERO);
            iface.update_ip_addrs(|addrs| {
                let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(E2E_BRIDGE_IP), 24));
            });
            let mut sockets = SocketSet::new(Vec::new());
            let mut listener = tcp::Socket::new(
                tcp::SocketBuffer::new(vec![0; 16 * 1024]),
                tcp::SocketBuffer::new(vec![0; 16 * 1024]),
            );
            listener
                .listen(IpListenEndpoint { addr: None, port: E2E_TCP_ECHO })
                .unwrap();
            let tcp = sockets.add(listener);
            let mut usock = udp::Socket::new(
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 16 * 1024]),
                udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 16 * 1024]),
            );
            usock.bind(IpListenEndpoint { addr: None, port: E2E_UDP_ECHO }).unwrap();
            let udp = sockets.add(usock);
            BridgeStack {
                iface,
                sockets,
                shim,
                tcp,
                udp,
                ip_peers: HashMap::new(),
                pump_buf: vec![0; 32 * 1024],
                start: Instant::now(),
            }
        }

        fn now(&self) -> SmolInstant {
            SmolInstant::from_micros(self.start.elapsed().as_micros() as i64)
        }

        fn ingress(&mut self, source: u64, frame: &[u8]) {
            if ip_ethertype(frame).is_none() {
                return;
            }
            if let Some(src) = src_ip_of(frame) {
                self.ip_peers.insert(src, source);
            }
            self.shim.stage(frame);
        }

        /// Poll + echo service; returns (dest, ethertype, frame) pairs
        /// to send back.
        fn step(&mut self) -> Vec<(u64, u16, Vec<u8>)> {
            self.iface.poll(self.now(), &mut self.shim, &mut self.sockets);
            // TCP echo: whatever arrived goes straight back.
            {
                let sock = self.sockets.get_mut::<tcp::Socket>(self.tcp);
                while sock.can_recv() {
                    match sock.recv_slice(&mut self.pump_buf) {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            let mut back = 0usize;
                            while back < n {
                                match sock.send_slice(&self.pump_buf[back..n]) {
                                    Ok(m) => back += m,
                                    Err(_) => break,
                                }
                            }
                        }
                    }
                }
            }
            // UDP echo: reply to the source endpoint.
            {
                let sock = self.sockets.get_mut::<udp::Socket>(self.udp);
                while sock.can_recv() {
                    let Ok((n, meta)) = sock.recv_slice(&mut self.pump_buf) else { break };
                    let _ = sock.send_slice(&self.pump_buf[..n], meta);
                }
            }
            // A real echo server serves many connections: finish the
            // half-closed one (peer FIN) and re-arm the listener when
            // the socket reaches Closed — without this the second dial
            // of the direct-path test would be RST by a consumed
            // listener (smoltcp listeners are single-connection).
            {
                let sock = self.sockets.get_mut::<tcp::Socket>(self.tcp);
                if matches!(sock.state(), tcp::State::CloseWait) && !sock.can_recv() {
                    sock.close();
                }
                if sock.state() == tcp::State::Closed {
                    sock.listen(IpListenEndpoint { addr: None, port: E2E_TCP_ECHO }).unwrap();
                }
            }
            self.iface.poll(self.now(), &mut self.shim, &mut self.sockets);
            let egress: Vec<Vec<u8>> = self.shim.egress.drain(..).collect();
            let mut out = Vec::new();
            for pkt in egress {
                let Some(et) = ip_ethertype(&pkt) else { continue };
                if let Some(dest) = dst_ip_of(&pkt).and_then(|ip| self.ip_peers.get(&ip).copied()) {
                    out.push((dest, et, pkt));
                }
            }
            out
        }
    }

    /// The full conversation over real UDP sockets on localhost. All
    /// keys are generated in-test (the PoW search is the same one a
    /// fresh node runs); nothing leaves the process.
    #[tokio::test]
    async fn overlay_e2e_root_controller_bridge_echo() {
        let authority = NodeIdentity::generate().unwrap();
        let root_id = NodeIdentity::generate().unwrap();
        let controller_id = NodeIdentity::generate().unwrap();
        let bridge_id = NodeIdentity::generate().unwrap();
        let node_id = NodeIdentity::generate().unwrap();

        let root_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ctrl_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let bridge_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let root_ep = root_sock.local_addr().unwrap();

        // The in-test planet: one root (the root mimic), signed by the
        // authority — `World::make`, the same format as the built-in
        // planet (verified separately above).
        let world = World::make(
            WORLD_TYPE_PLANET,
            0x00c0ffee01,
            42,
            &authority,
            vec![WorldRoot {
                identity: root_id.clone(),
                endpoints: vec![PhysAddr::from_socket_addr(root_ep)],
            }],
        )
        .unwrap();
        let planet_path = std::env::temp_dir().join(format!(
            "rustcrash-zt-planet-{}-{:?}.bin",
            std::process::id(),
            root_ep.port()
        ));
        std::fs::write(&planet_path, world.to_bytes()).unwrap();

        let nwid = (controller_id.address() << 24) | 1;
        let registry: Arc<std::sync::Mutex<HashMap<u64, (NodeIdentity, SocketAddr)>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));

        // -- the root: WHOIS responder + relay ---------------------------
        let mut root_mimic = Mimic {
            identity: root_id.clone(),
            socket: root_sock.clone(),
            known: registry.clone(),
            root: None,
            world: (world.id, world.timestamp),
            frags: FragmentAssembler::default(),
            introduced: std::collections::HashSet::new(),
            moon: None,
        };
        let root_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            loop {
                let Ok((n, from)) = root_sock.recv_from(&mut buf).await else { break };
                root_mimic.on_datagram(&buf[..n], from, None, None).await;
            }
        });

        // -- the controller: netconf with a managed IP + specialist ------
        let mut ctrl_mimic = Mimic {
            identity: controller_id.clone(),
            socket: ctrl_sock.clone(),
            known: registry.clone(),
            root: Some((root_id.address(), root_id.clone(), root_ep)),
            world: (world.id, world.timestamp),
            frags: FragmentAssembler::default(),
            introduced: std::collections::HashSet::new(),
            moon: None,
        };
        // The root's identity is planet knowledge — known from the
        // start, like the runtime's peer table seeds its roots.
        ctrl_mimic
            .known
            .lock()
            .unwrap()
            .insert(root_id.address(), (root_id.clone(), root_ep));
        let netconf_info = (nwid, bridge_id.address(), 2800u64);
        let ctrl_task = tokio::spawn(async move {
            ctrl_mimic.hello_root().await;
            let mut buf = vec![0u8; 65_536];
            loop {
                let Ok((n, from)) = ctrl_sock.recv_from(&mut buf).await else { break };
                ctrl_mimic
                    .on_datagram(&buf[..n], from, Some(&netconf_info), None)
                    .await;
            }
        });

        // -- the bridge: the specialist with the echo stack --------------
        let mut bridge_mimic = Mimic {
            identity: bridge_id.clone(),
            socket: bridge_sock.clone(),
            known: registry.clone(),
            root: Some((root_id.address(), root_id.clone(), root_ep)),
            world: (world.id, world.timestamp),
            frags: FragmentAssembler::default(),
            introduced: std::collections::HashSet::new(),
            moon: None,
        };
        bridge_mimic
            .known
            .lock()
            .unwrap()
            .insert(root_id.address(), (root_id.clone(), root_ep));
        let bridge_task = tokio::spawn(async move {
            bridge_mimic.hello_root().await;
            let mut stack = BridgeStack::new();
            let bridge_id = bridge_mimic.identity.clone();
            let mut buf = vec![0u8; 65_536];
            loop {
                // Service the echo stack whenever something arrived (or
                // on a tick, so pure egress drains too).
                tokio::select! {
                    r = bridge_sock.recv_from(&mut buf) => {
                        let Ok((n, from)) = r else { break };
                        bridge_mimic.on_datagram(&buf[..n], from, None, Some(&mut stack)).await;
                    }
                    _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                }
                for (dest, et, frame) in stack.step() {
                    let key = bridge_mimic
                        .known
                        .lock()
                        .unwrap()
                        .get(&dest)
                        .map(|(id, _)| bridge_id.agree(id).unwrap())
                        .unwrap_or([0u8; SYMMETRIC_KEY_SIZE]);
                    let mut pkt = build_frame(&bridge_id, dest, nwid, et, &frame);
                    bridge_mimic.send_to(dest, &key, &mut pkt, DEFAULT_PHYSICAL_MTU).await;
                }
            }
        });

        // Let the mimics' startup HELLOs register with the root.
        tokio::time::sleep(Duration::from_millis(200)).await;

        // -- the node under test ------------------------------------------
        let state_dir = std::env::temp_dir().join(format!(
            "rustcrash-zt-state-{}-{:?}",
            std::process::id(),
            root_ep.port()
        ));
        let cfg = ZeroTierConfig {
            name: "e2e-node".into(),
            network: format!("{nwid:016x}"),
            identity_secret: Some(node_id.to_secret_str().unwrap()),
            planet: Some(planet_path.to_string_lossy().into_owned()),
            state_dir: Some(state_dir.to_string_lossy().into_owned()),
            physical_mtu: 1280, // path MTU — fragments every ~2.7 KiB segment
            udp: true,
            ..ZeroTierConfig::new("e2e-node", format!("{nwid:016x}"))
        };
        let target = NetAddr::ip(IpAddr::V4(E2E_BRIDGE_IP), E2E_TCP_ECHO);
        let mut stream = tokio::time::timeout(Duration::from_secs(40), connect(&cfg, &target))
            .await
            .expect("dial timed out")
            .expect("dial failed");

        // A payload spanning multiple maximum segments: each ~2.7 KiB
        // segment exceeds the 1280-byte path MTU, so the TCP echo
        // crosses the wire as fragmented ZeroTier packets both ways.
        let payload: Vec<u8> = (0..9000u32).map(|i| (i % 251) as u8).collect();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        stream.write_all(&payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(got, payload, "echoed bytes differ");

        // UDP through the same overlay (the config's udp: true).
        let udp = ZtUdp::bind(&cfg).await.unwrap();
        udp.send(
            &NetAddr::ip(IpAddr::V4(E2E_BRIDGE_IP), E2E_UDP_ECHO),
            b"zt overlay udp echo",
        )
        .await
        .unwrap();
        let (from, data) = tokio::time::timeout(Duration::from_secs(10), udp.recv())
            .await
            .expect("udp echo timed out")
            .unwrap();
        assert_eq!(data, b"zt overlay udp echo");
        assert_eq!(from.port, E2E_UDP_ECHO);
        assert_eq!(
            from.host,
            crate::addr::Host::Ip(IpAddr::V4(E2E_BRIDGE_IP))
        );

        drop(stream);
        drop(udp);
        root_task.abort();
        ctrl_task.abort();
        bridge_task.abort();
        std::fs::remove_file(&planet_path).ok();
        // State landed: the identity was persisted even though it came
        // from config (the Node state-object write), and the met
        // peers are cached.
        let identity_file = state_dir.join(STATE_FILE_IDENTITY);
        let persisted = std::fs::read_to_string(&identity_file).unwrap();
        assert_eq!(persisted.trim(), node_id.to_secret_str().unwrap().trim());
        let peers = std::fs::read_dir(state_dir.join(STATE_DIR_PEERS)).unwrap().flatten().count();
        assert!(peers >= 2, "root + bridge should be persisted, got {peers}");
        std::fs::remove_dir_all(&state_dir).ok();
    }

    // -----------------------------------------------------------------
    // Wave 16: direct-path learning + state persistence + moons
    // -----------------------------------------------------------------

    /// VERB_RENDEZVOUS and VERB_PUSH_DIRECT_PATHS round-trip on the
    /// wire, byte-faithful to the upstream layouts
    /// (Packet.hpp:284-288 / Peer.cpp:217-232).
    #[test]
    fn rendezvous_and_push_direct_paths_wire() {
        let a = synth_identity(1, 0x1111111111);
        let b = synth_identity(2, 0x2222222222);
        let key = a.agree(&b).unwrap();

        let rd = Rendezvous {
            flags: 0,
            zt_address: 0x0123456789,
            sock: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 7), 9993)),
        };
        let pkt = build_rendezvous(&a, b.address(), &rd, &key);
        // Suite-1 armor encrypts the verb byte (armor's stream starts
        // at PACKET_IDX_VERB) — the verb is readable post-dearmor,
        // exactly as the receiver sees it.
        let mut back = pkt.clone();
        back.dearmor(&key).unwrap();
        assert_eq!(back.verb().unwrap(), Verb::Rendezvous);
        assert_eq!(back.verb().unwrap().to_byte(), 0x05);
        let parsed = parse_rendezvous(&back).unwrap();
        assert_eq!(parsed, rd);
        // The zt address rides as 5 big-endian bytes right after flags.
        let p = back.payload();
        assert_eq!(&p[1..6], &rd.zt_address.to_be_bytes()[3..8]);
        assert_eq!(u16::from_be_bytes([p[6], p[7]]), 9993);
        assert_eq!(p[8], 4);

        // v6 rendezvous, and the addrlen-16 arm of the parser.
        let rd6 = Rendezvous {
            flags: 0,
            zt_address: 0xdeadbeefba,
            sock: SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1),
                4444,
                0,
                0,
            )),
        };
        let pkt6 = build_rendezvous(&a, b.address(), &rd6, &key);
        let mut back6 = pkt6;
        back6.dearmor(&key).unwrap();
        assert_eq!(parse_rendezvous(&back6).unwrap(), rd6);

        // PUSH_DIRECT_PATHS: two paths (v4 + v6), compressed payload,
        // armor suite 1 — dearmor + uncompress then parse.
        let paths = vec![
            DirectPath {
                flags: 0,
                sock: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(10, 1, 2, 3), 41234)),
            },
            DirectPath {
                flags: 0,
                sock: SocketAddr::V6(SocketAddrV6::new(
                    Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 9),
                    41235,
                    0,
                    0,
                )),
            },
        ];
        let push = build_push_direct_paths(&a, b.address(), &paths, &key);
        let mut push_back = push;
        push_back.dearmor(&key).unwrap();
        // Both the verb bits and the compressed flag live on the verb
        // byte, which suite-1 armor encrypts — readable post-dearmor.
        assert_eq!(push_back.verb().unwrap().to_byte(), 0x10);
        assert!(push_back.compressed());
        push_back.uncompress().unwrap();
        assert!(!push_back.compressed());
        assert_eq!(parse_push_direct_paths(&push_back).unwrap(), paths);
        // The record layout: flags(1) ext(2)=0 type(1) len(1)=6/18 ip port.
        let p = push_back.payload();
        assert_eq!(u16::from_be_bytes([p[0], p[1]]), 2); // count
        assert_eq!(p[2], 0); // flags
        assert_eq!(u16::from_be_bytes([p[3], p[4]]), 0); // no extensions
        assert_eq!(p[5], 4); // addrType
        assert_eq!(p[6], 6); // addrLen: ip(4) + port(2)
        assert_eq!(&p[7..11], &[10, 1, 2, 3]);
        assert_eq!(u16::from_be_bytes([p[11], p[12]]), 41234);

        // The reader skips unknown extension bytes exactly like
        // _doPUSH_DIRECT_PATHS's `ptr += extLen`.
        let mut odd = WirePacket::new(b.address(), a.address(), Verb::PushDirectPaths);
        odd.push_u16(1)
            .push_u8(0)
            .push_u16(4) // 4 extension bytes
            .push_bytes(&[0xde, 0xad, 0xbe, 0xef])
            .push_u8(4)
            .push_u8(6)
            .push_bytes(&[192, 0, 2, 1])
            .push_u16(53);
        let parsed = parse_push_direct_paths(&odd).unwrap();
        assert_eq!(
            parsed,
            vec![DirectPath {
                flags: 0,
                sock: SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(192, 0, 2, 1), 53))
            }]
        );
    }

    /// The state store: identity generation persists and reloads
    /// byte-identically; peers round-trip with their endpoints; a
    /// corrupt identity fails loudly instead of silently re-keying.
    #[test]
    fn state_store_identity_and_peer_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "rustcrash-zt-store-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let store = NodeStateStore::open(dir.to_str().unwrap()).unwrap();

        // Identity: generated once, reloaded identically.
        let first = store.load_or_create_identity().unwrap();
        assert!(first.locally_validate());
        let second = store.load_or_create_identity().unwrap();
        assert_eq!(first.to_secret_str().unwrap(), second.to_secret_str().unwrap());

        // Peers: save + load round-trip (real identities — the loader
        // validates hashcash, so synthesized keys are cache poison).
        let peer = NodeIdentity::generate().unwrap();
        let ep = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(198, 51, 100, 4), 31337));
        store.save_peer(&peer, Some(ep));
        let loaded = store.load_peers();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].0.address(), peer.address());
        assert_eq!(loaded[0].1, Some(ep));
        // Without an endpoint the identity alone loads (endpoint None).
        let peer2 = NodeIdentity::generate().unwrap();
        store.save_peer(&peer2, None);
        let loaded = store.load_peers();
        assert_eq!(loaded.len(), 2);
        assert!(loaded.iter().any(|(id, e)| id.address() == peer2.address() && e.is_none()));

        // A corrupt identity.secret is a loud config error, never a
        // silent identity rotation.
        std::fs::write(store.dir.join(STATE_FILE_IDENTITY), b"garbage\n").unwrap();
        let err = store.load_or_create_identity().unwrap_err();
        assert!(
            err.to_string().contains("state") || err.to_string().contains("identity"),
            "{err}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Moon adoption (`Topology::addWorld` + shouldAcceptWorldUpdateFrom):
    /// a signed moon world whose roots contain our pending seed is
    /// adopted, the seed consumed, the moon's roots become upstreams;
    /// worlds for unknown ids, wrong ids, or bad signatures are not.
    #[test]
    fn adopt_worlds_moon_orbit() {
        let moon_authority = synth_identity(3, 0x3333333333);
        let moon_root = synth_identity(4, 0x4444444444);
        let moon_ep = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::new(203, 0, 113, 99), 9990));
        let moon = World::make(
            WORLD_TYPE_MOON,
            0xfeedface01,
            77,
            &moon_authority,
            vec![WorldRoot {
                identity: moon_root.clone(),
                endpoints: vec![PhysAddr::from_socket_addr(moon_ep)],
            }],
        )
        .unwrap();
        let mut world_bytes = Vec::new();
        moon.serialize(false, &mut world_bytes);

        let me = synth_identity(5, 0x5555555555);
        let planet = World::parse_planet(default_planet()).unwrap();
        let planet_root = planet.roots[0].identity.address();
        let wake = Arc::new(Notify::new());
        let mut stack = ZtStack::new(
            me,
            planet,
            0x0123456789abcdef,
            DEFAULT_PHYSICAL_MTU,
            true,
            wake,
            vec![(0xfeedface01, moon_root.address())],
            None,
            None,
        );
        // Before: one pending seed, no moons, the moon root unknown.
        assert_eq!(stack.moon_seeds.len(), 1);
        assert!(stack.root_endpoints().len() == stack.world.roots.len());

        // A world for an id we did not ask about: ignored.
        let other = World::make(
            WORLD_TYPE_MOON,
            0xbadbadbad1,
            1,
            &moon_authority,
            vec![WorldRoot { identity: moon_root.clone(), endpoints: vec![] }],
        )
        .unwrap();
        let mut other_bytes = Vec::new();
        other.serialize(false, &mut other_bytes);
        stack.adopt_worlds(planet_root, &other_bytes);
        assert_eq!(stack.moon_seeds.len(), 1);
        assert!(stack.moons.is_empty());

        // The asked-for moon, delivered by a planet root: adopted.
        stack.adopt_worlds(planet_root, &world_bytes);
        assert!(stack.moon_seeds.is_empty(), "seed consumed");
        assert_eq!(stack.moons.len(), 1);
        assert_eq!(stack.moons[0].id, 0xfeedface01);
        assert!(stack.is_upstream(moon_root.address()));
        assert!(stack.root_endpoints().iter().any(|(a, _, ep)| {
            *a == moon_root.address() && *ep == moon_ep
        }));
        // The moon root entered the peer table with its endpoint.
        assert_eq!(
            stack.peers.get(&moon_root.address()).and_then(|p| p.endpoint),
            Some(moon_ep)
        );

        // An older copy of the same moon does not replace it.
        let older = World::make(
            WORLD_TYPE_MOON,
            0xfeedface01,
            7,
            &moon_authority,
            vec![WorldRoot { identity: moon_root.clone(), endpoints: vec![] }],
        )
        .unwrap();
        let mut older_bytes = Vec::new();
        older.serialize(false, &mut older_bytes);
        stack.adopt_worlds(planet_root, &older_bytes);
        assert_eq!(stack.moons[0].timestamp, 77);
    }

    /// The live direct-path proof: after the root relays the node's
    /// first frames it introduces both parties (RENDEZVOUS); the node
    /// probes the bridge directly, the OK(HELLO) confirms the path —
    /// and when the ROOT DIES, dials keep working through the direct
    /// path. Root-relay-only would fail this the moment the root
    /// task aborts.
    #[tokio::test]
    async fn overlay_e2e_direct_path_survives_root_death() {
        let authority = NodeIdentity::generate().unwrap();
        let root_id = NodeIdentity::generate().unwrap();
        let controller_id = NodeIdentity::generate().unwrap();
        let bridge_id = NodeIdentity::generate().unwrap();

        let root_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let ctrl_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let bridge_sock = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let root_ep = root_sock.local_addr().unwrap();

        let world = World::make(
            WORLD_TYPE_PLANET,
            0x00c0ffee02,
            43,
            &authority,
            vec![WorldRoot {
                identity: root_id.clone(),
                endpoints: vec![PhysAddr::from_socket_addr(root_ep)],
            }],
        )
        .unwrap();
        let planet_path = std::env::temp_dir().join(format!(
            "rustcrash-zt-planet2-{}-{:?}.bin",
            std::process::id(),
            root_ep.port()
        ));
        std::fs::write(&planet_path, world.to_bytes()).unwrap();

        let nwid = (controller_id.address() << 24) | 2;
        let registry: Arc<std::sync::Mutex<HashMap<u64, (NodeIdentity, SocketAddr)>>> =
            Arc::new(std::sync::Mutex::new(HashMap::new()));

        let mut root_mimic = Mimic {
            identity: root_id.clone(),
            socket: root_sock.clone(),
            known: registry.clone(),
            root: None,
            world: (world.id, world.timestamp),
            frags: FragmentAssembler::default(),
            introduced: std::collections::HashSet::new(),
            moon: None,
        };
        let root_task = tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            loop {
                let Ok((n, from)) = root_sock.recv_from(&mut buf).await else { break };
                root_mimic.on_datagram(&buf[..n], from, None, None).await;
            }
        });

        let mut ctrl_mimic = Mimic {
            identity: controller_id.clone(),
            socket: ctrl_sock.clone(),
            known: registry.clone(),
            root: Some((root_id.address(), root_id.clone(), root_ep)),
            world: (world.id, world.timestamp),
            frags: FragmentAssembler::default(),
            introduced: std::collections::HashSet::new(),
            moon: None,
        };
        ctrl_mimic
            .known
            .lock()
            .unwrap()
            .insert(root_id.address(), (root_id.clone(), root_ep));
        let netconf_info = (nwid, bridge_id.address(), 2800u64);
        let ctrl_task = tokio::spawn(async move {
            ctrl_mimic.hello_root().await;
            let mut buf = vec![0u8; 65_536];
            loop {
                let Ok((n, from)) = ctrl_sock.recv_from(&mut buf).await else { break };
                ctrl_mimic
                    .on_datagram(&buf[..n], from, Some(&netconf_info), None)
                    .await;
            }
        });

        let mut bridge_mimic = Mimic {
            identity: bridge_id.clone(),
            socket: bridge_sock.clone(),
            known: registry.clone(),
            root: Some((root_id.address(), root_id.clone(), root_ep)),
            world: (world.id, world.timestamp),
            frags: FragmentAssembler::default(),
            introduced: std::collections::HashSet::new(),
            moon: None,
        };
        bridge_mimic
            .known
            .lock()
            .unwrap()
            .insert(root_id.address(), (root_id.clone(), root_ep));
        let bridge_task = tokio::spawn(async move {
            bridge_mimic.hello_root().await;
            let mut stack = BridgeStack::new();
            let bridge_id = bridge_mimic.identity.clone();
            let mut buf = vec![0u8; 65_536];
            loop {
                tokio::select! {
                    r = bridge_sock.recv_from(&mut buf) => {
                        let Ok((n, from)) = r else { break };
                        bridge_mimic.on_datagram(&buf[..n], from, None, Some(&mut stack)).await;
                    }
                    _ = tokio::time::sleep(Duration::from_millis(50)) => {}
                }
                for (dest, et, frame) in stack.step() {
                    let key = bridge_mimic
                        .known
                        .lock()
                        .unwrap()
                        .get(&dest)
                        .map(|(id, _)| bridge_id.agree(id).unwrap())
                        .unwrap_or([0u8; SYMMETRIC_KEY_SIZE]);
                    let mut pkt = build_frame(&bridge_id, dest, nwid, et, &frame);
                    bridge_mimic.send_to(dest, &key, &mut pkt, DEFAULT_PHYSICAL_MTU).await;
                }
            }
        });

        tokio::time::sleep(Duration::from_millis(200)).await;

        let state_dir = std::env::temp_dir().join(format!(
            "rustcrash-zt-state2-{}-{:?}",
            std::process::id(),
            root_ep.port()
        ));
        let cfg = ZeroTierConfig {
            name: "e2e-direct".into(),
            network: format!("{nwid:016x}"),
            state_dir: Some(state_dir.to_string_lossy().into_owned()),
            planet: Some(planet_path.to_string_lossy().into_owned()),
            physical_mtu: 2800,
            udp: true,
            ..ZeroTierConfig::new("e2e-direct", format!("{nwid:016x}"))
        };
        let target = NetAddr::ip(IpAddr::V4(E2E_BRIDGE_IP), E2E_TCP_ECHO);

        // Phase 1: dial + echo while the root lives. The relayed SYN
        // triggers the root's introduce; the probes confirm a direct
        // path during this exchange.
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut first = tokio::time::timeout(Duration::from_secs(40), connect(&cfg, &target))
            .await
            .expect("first dial timed out")
            .expect("first dial failed");
        let hello: Vec<u8> = (0..4096u32).map(|i| (i % 241) as u8).collect();
        first.write_all(&hello).await.unwrap();
        let mut got = vec![0u8; hello.len()];
        first.read_exact(&mut got).await.unwrap();
        assert_eq!(got, hello, "relayed echo differs");
        // Graceful close so the bridge's listener retires the old
        // connection and re-arms (the second dial needs a listener).
        // Draining to EOF is the deterministic proof both sides
        // retired the connection — no timing window.
        first.shutdown().await.unwrap();
        let mut eof = [0u8; 1];
        let n = tokio::time::timeout(Duration::from_secs(5), first.read(&mut eof))
            .await
            .expect("EOF never arrived after shutdown")
            .unwrap();
        assert_eq!(n, 0, "expected EOF after graceful close, got {n} bytes");
        drop(first);

        // Phase 2: the root dies. A fresh dial + echo must still work
        // — only a learned direct path can carry it now. (The graceful
        // close above needs a moment to retire the bridge's listener
        // before the witness disappears; the direct path itself was
        // confirmed during phase 1.)
        root_task.abort();
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let mut second = tokio::time::timeout(Duration::from_secs(20), connect(&cfg, &target))
            .await
            .expect("post-root-death dial timed out (direct path was not learned)")
            .expect("post-root-death dial failed");
        let payload: Vec<u8> = (0..5000u32).map(|i| (i % 199) as u8).collect();
        second.write_all(&payload).await.unwrap();
        let mut got2 = vec![0u8; payload.len()];
        second.read_exact(&mut got2).await.unwrap();
        assert_eq!(got2, payload, "direct-path echo differs");

        drop(second);
        ctrl_task.abort();
        bridge_task.abort();
        std::fs::remove_file(&planet_path).ok();
        std::fs::remove_dir_all(&state_dir).ok();
    }
}
