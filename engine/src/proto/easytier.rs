//! The EasyTier overlay outbound: the full config surface, the complete
//! port of mihomo's `component/easytier` (the pure-data layer the
//! adapter drives — TOML rendering, peer-URI parsing, the overlay-DNS
//! helpers), and the wire-level assessment of what bringing the actual
//! mesh online takes.
//!
//! # The split: what is Rust, what is not in-tree
//!
//! mihomo's EasyTier outbound (`adapter/outbound/easytier.go`, 614
//! lines, cached at `/tmp/wave10-upstream/probe_adapter_outbound_easytier.go`)
//! is build-gated `!no_easytier` and embeds **`easytier-go`** — the
//! bindings over the **EasyTier core, which is Rust**
//! (`github.com/EasyTier/EasyTier`). Unlike ZeroTier's libzt there is
//! no C wall: pieces ARE portable in principle. What the adapter
//! actually uses from the core (cached lines 23, 292-318, 341-357):
//!
//! * `corehost.Host` + `CreateInstanceTOML(name, id, configTOML)` — a
//!   full mesh node fed the TOML this module now renders;
//! * `instance.Start/Wait/Close`, `instance.Events()` — the lifecycle
//!   + `peer_added`/`peer_removed` event stream;
//! * `instance.ShowNodeInfo` / `ListRoute` — the overlay node table
//!   behind the MagicDNS resolver;
//! * `instance.Dial(ctx, "tcp4", addr)` / `ListenPacket("udp4", ":0")`
//!   — flows onto the overlay's virtual network (IPv4-only in the
//!   adapter, cached lines 407-408).
//!
//! Those map onto EasyTier's Rust crates: the peer/peer-manager (mesh
//! membership, gossip), the tcp/udp/quic/ws tunnels (direct
//! transports — all four ported, see the milestone sections), the KCP
//! proxy behind the `enable-*-proxy` flags, and the rpc layer feeding
//! ShowNodeInfo/ListRoute. The core is not vendored; the **direct TCP
//! peer tunnel** (the first milestone) is ported natively into this
//! file — see the milestone section below — and everything pure-Go
//! around the core is ported below and is the load-bearing config path
//! (the rendered TOML is byte-compatible with upstream's `RenderTOML` +
//! `ApplyRequiredFlags`).
//!
//! # Ported this wave (component/easytier, verbatim behaviour)
//!
//! * `toml.go` — [`EasyTierTomlConfig::validate`]
//!   (`ValidateStructured`), [`EasyTierTomlConfig::render_toml`]
//!   (`RenderTOML`), [`apply_required_flags`] (`ApplyRequiredFlags`),
//!   [`parse_peer_uri`] (`parsePeerURI`, the `peer-public-key` query
//!   extraction) and the TOML/JSON string quoting (Go's
//!   `encoding/json` HTML escaping included).
//! * `overlay.go` — [`DEFAULT_TLD_DNS_ZONE`], [`normalize_dns_name`],
//!   [`normalize_zone`], [`overlay_names`], [`is_magic_dns`],
//!   [`lookup_overlay_host`], [`lookup_overlay_ptr`],
//!   [`parse_node_ipv4`], [`ipv4_from_u32`], [`parse_ptr_ipv4`].
//!
//! # First portable milestone — LANDED (the direct TCP peer tunnel)
//!
//! The wire protocol a node speaks to a `tcp://host:port` peer is now
//! in-tree, ported from EasyTier's Rust core (commit main@2026-09, the
//! `easytier-core` crate; sources cached under
//! `/tmp/wave11-upstream/easytier/`):
//!
//! * **Framing** — `easytier-core/src/tunnel/framed.rs` + `tunnel/tcp.rs`:
//!   one TCP frame is `[u32 LE body_len][PeerManagerHeader (16B)][payload]`
//!   with `body_len = 16 + payload_len` and a 2000-byte MTU
//!   ([`PeerPacket`], [`read_frame`], [`write_frame`]).
//! * **Handshake** — the plain (non-secure-mode) branch of
//!   `peers/conn/peer_conn.rs`: both ends exchange a proto3
//!   `HandshakeRequest` (magic `0xd1e1a5e1`, version 1, the
//!   `liveness-echo-v1` feature, network name, 32-byte
//!   `network_secret_digest` = std `DefaultHasher` over name+secret,
//!   `config/mod.rs:207-218`) inside a `PacketType::HandShake` packet;
//!   then the `add_new_peer_conn` identity check
//!   (`peers/peer_manager.rs:395-412`) ([`connect_peer`],
//!   [`handshake_as_client`]).
//! * **Packet encryption** — `tunnel/encrypt/` with the core default
//!   `enable_encryption = true` (`config/toml.rs:34`): `Data` payloads
//!   are AEAD-sealed (default `aes-gcm` = AES-128-GCM keyed by
//!   `derive_key_128(network_secret)`; also `aes-256-gcm`,
//!   `chacha20[-poly1305]`, `xor`) and carry the 28-byte
//!   `StandardAeadTail { tag, nonce }` after the ciphertext
//!   ([`PacketEncryptor`], [`create_encryptor`]).
//! * **Keepalive** — the `peer_conn_ping.rs` ping/pong: 4-byte LE seq in
//!   a `Ping` packet, echoed as `Pong`, 2s timeout, 1s logic clock with
//!   the exponential backoff controller and the 5-loss connection
//!   teardown ([`EasyTierNode::ping`], the in-connection keepalive).
//! * **Data seam** — [`EasyTierNode::send_ip_frame`]/[`recv_ip_frame`]:
//!   the `PacketType::Data` packets that carry the virtual network's IP
//!   frames (the TUN payload), encrypted per the flags. This is the
//!   attach point for the next milestone.
//!
//! Secure mode WAS the follow-up and is now in-tree (M6): the Noise_XX
//! `PeerConnNoiseMsg1/2/3` handshake (`Noise_XX_25519_ChaChaPoly_SHA256`,
//! prologue `easytier-peerconn-noise`, hand-rolled after snow —
//! [`NoiseXxHandshake`]) plus the per-peer session AEAD that replaces
//! the network-secret encryption afterwards (see the M6 section below).
//!
//! # Second milestone — LANDED (route gossip + the userspace stack)
//!
//! M2 wires the M1 tunnel into a dialable overlay (sources cached under
//! `/tmp/wave12-upstream/easytier/`):
//!
//! * **The peer RPC framework subset** — the `RpcReq`/`RpcResp` framing
//!   of `rpc/packet.rs` + `client.rs` + `server.rs`: the proto3
//!   `RpcPacket`/`RpcDescriptor`/`RpcRequest`/`RpcResponse` wire
//!   messages, the transaction-id table, the `PacketMerger`, and the
//!   descriptor-keyed dispatch (method indexes start at 1). RpcReq/
//!   RpcResp payloads ride the same AEAD packet encryption as Data —
//!   the real core's `RpcTransport::send` encrypts them
//!   (peers/peer_manager.rs:153-169).
//! * **Route gossip** — the two-node subset of the 234 KB
//!   `peers/route/peer_ospf_route.rs`: announce our `RoutePeerInfo`
//!   (overlay IPv4, hostname, version, peer_route_id) plus the
//!   two-node `RouteConnBitmap` adjacency via
//!   `OspfRouteRpc.SyncRouteInfo` (domain = network name, method index
//!   1), learn the peer's routes back (the strictly-greater-version
//!   LSDB merge), the session admission rules of
//!   `admit_inbound_locked`, and the 10s periodic re-sync.
//! * **The smoltcp userspace stack** — the engine's openvpn.rs/
//!   wireguard.rs L3 pattern on `send_ip_frame`/`recv_ip_frame`: static
//!   `ipv4` from the config (a /32 + default route through it) or the
//!   modern easytier dhcp behaviour — a local first-fit allocation out
//!   of the peer's gossiped subnet (`DhcpIpv4Allocator::evaluate`,
//!   gateway/dhcp.rs:51-78; there is no DHCP protocol on the wire).
//! * **The dial API** — [`connect_tcp`] + [`EasyTierUdp`] over a
//!   process-global node cache keyed by config identity (the
//!   wireguard.rs/openvpn.rs tunnel registry pattern).
//!
//! # Third milestone — LANDED (the UDP transport + the listener)
//!
//! M3 (sources cached under `/tmp/wave13-upstream/`, the v2.6.4 tag
//! clone `et264/` — the line the released binaries speak):
//!
//! * **The UDP peer transport** — `tunnel/udp.rs` + the
//!   `UDPTunnelHeader` of `tunnel/packet_def.rs`: a `udp://host:port`
//!   peer URI dials a datagram virtual circuit (SYN/SACK exchange with
//!   a random conn id + echoed magic, `try_connect_with_socket`,
//!   tunnel/udp.rs:844-873); every write becomes one
//!   `[hdr{Data, conn_id, len}][payload]` datagram and the same
//!   M1 framing rides inside ([`connect_udp_tunnel`],
//!   [`UdpVtStream`], [`parse_peer_endpoint`]). Reached from the peer
//!   connector via `IpScheme::Udp => UdpTunnelConnector`
//!   (connector/mod.rs:248).
//! * **The listener** — the `create_listener_by_url` dispatch +
//!   `ListenerManager` accept loop of `instance/listeners.rs`:
//!   [`serve`] binds every configured listener (`tcp://` and `udp://`),
//!   dials the first supported peer when one is configured, and feeds
//!   every accepted tunnel through the SAME server handshake, crypto
//!   and keepalive the client side speaks; inbound peers join the one
//!   overlay node (shared peer id, shared overlay address, one gossip
//!   session per edge) and relays dial both ways
//!   ([`EasyTierServer`]).
//! * **The multi-peer node** — [`EtStack`] grew a peer table: each
//!   attached session carries its own `RouteGossip`/`RpcRouter`, egress
//!   frames route by longest-prefix over the union LSDB (two-node
//!   default: the first live peer), and the dhcp allocation is
//!   node-wide.
//! * **Secure mode — assessed then landed in M6** — after the Noise_XX
//!   handshake every payload switches from the network-secret AEAD to
//!   the per-peer session AEAD (`PeerSessionStore` +
//!   `SecureDatagramSession`); the fast-fail gate is gone.
//!
//! # Fourth milestone — LANDED (the QUIC + WebSocket transports)
//!
//! M4 (sources cached under `/tmp/wave14-upstream/`, the v2.6.4 tag
//! clone `et264/`) adds the two remaining real-binary transports:
//!
//! * **QUIC** — `tunnel/quic.rs`: one QUIC connection per peer carrying
//!   EXACTLY ONE bidirectional stream with the M1 TCP framing on it,
//!   connected with the server name `localhost`. The crypto is NOT TLS:
//!   easytier builds on the `quinn-plaintext` crate — no encryption, no
//!   header protection, an 8-byte SeaHash checksum tag per packet and
//!   the QUIC transport parameters exchanged as the raw CRYPTO-stream
//!   content. The crate is re-implemented in-tree ([`quic_plaintext`],
//!   after quinn-plaintext-0.3.0/src/lib.rs) against the engine's
//!   quinn/quinn-proto, verified against digests produced by the real
//!   crate. Transport settings mirror upstream (BBR, 5s keep-alive,
//!   MTU 1200) ([`connect_quic_tunnel`], [`QuicVtListener`]).
//! * **WebSocket** — `tunnel/websocket.rs`: `ws://`/`wss://` peers ride
//!   a hand-rolled RFC 6455 client (the sudoku precedent) with an
//!   insecure-TLS `wss` (SNI `localhost` for IPs); every binary message
//!   is one `[PeerManagerHeader][payload]` frame — NO length prefix
//!   (the message is self-delimiting) — which [`WsPeerStream`] adapts
//!   to/from the byte framing the session machinery speaks. The
//!   listener serves the upgrade (101 + computed accept) behind a
//!   process-global self-signed `wss` cert ([`connect_ws_tunnel`],
//!   [`WsVtListener`]).
//!
//! # Fifth milestone — LANDED (the WireGuard transport)
//!
//! M5 (sources cached under `/tmp/wave15-upstream/`, the v2.6.4 tag)
//! adds the last direct transport, `wg://` — WireGuard-as-transport
//! (`tunnel/wireguard.rs`):
//!
//! * **Keys** — the SHARED static keypair: every node of a network
//!   derives the same X25519 pair from
//!   `generate_digest_from_str(network_name, network_secret)` and
//!   configures `peer_public == my_public`, so the Noise ss step is
//!   X25519(sk, sk·G) = sk²·G on both ends — deterministic, no exchange
//!   ([`wg_static_keys`], upstream `WgConfig::new_from_network_identity`,
//!   wireguard.rs:62-79).
//! * **The pump** — [`WgEtPump`], the boringtun `Tunn` equivalent over
//!   the engine's own Noise_IKpsk2 machinery (proto/wireguard.rs,
//!   reached through its additive `et_pump` facade): encapsulate/decaps
//!   -ulate/update_timers with boringtun's exact timers (5s handshake
//!   retry, 90s attempt budget, 120s initiator rekey, 180s session
//!   death, 10s keepalive, 540s hard expiry), the responder's TAI64N
//!   replay guard and its my-static-equals-peer-static check, the
//!   pre-session queue, cookie-reply consumption, and a session ring
//!   for in-flight packets across a rekey.
//! * **Framing** — one `[PMH][payload]` datagram per WG IP packet with
//!   a 20-byte synthetic IPv4 header (total length = 20 + datagram,
//!   TTL 64, all else zero; [`wg_ip_packet`]/[`wg_strip_ip_header`]) —
//!   the same datagram contract as the UDP transport, so the wg tunnel
//!   reuses [`UdpVtStream`] verbatim.
//! * **Connector/listener** — the handshake-initiation-first dial
//!   ([`connect_wg_tunnel`]) and the per-address peer-table listener
//!   with the 250ms routine tick and the 61s idle sweep
//!   ([`WgVtListener`]).
//!
//! The engine's wg transport is thus wire-compatible with the real
//! core's boringtun — verified by the ignored real-binary interop test
//! (`real_easytier_binary_serving_wg`).
//!
//! # Sixth milestone — LANDED (secure mode)
//!
//! M6 (v2.6.4 sources, `/tmp/wave16-upstream/et264/`) ports the payload
//! layer a `[secure_mode]` config turns on:
//!
//! * **The handshake** — `Noise_XX_25519_ChaChaPoly_SHA256` with the
//!   prologue `easytier-peerconn-noise`, hand-rolled after snow
//!   ([`NoiseXxHandshake`]; the engine's third hand-rolled Noise pattern
//!   after wireguard's IKpsk2 and tailscale's IK): msg1 (ephemeral +
//!   clear payload), msg2 (ephemeral, ee, the sealed static, es, the
//!   sealed payload), msg3 (the sealed static, se, the sealed payload).
//!   The `PeerConnNoiseMsg1/2/3Pb` protobufs ride peer packets 13/14/15
//!   with the conn-id echo checks, the same/foreign `role_hint` rule and
//!   the HMAC network-secret proofs over the handshake hash.
//! * **The session AEAD** — [`SecureDatagramSession`]
//!   (secure_datagram.rs, 1020 lines; the load-bearing subset): traffic
//!   keys are epoch-keyed (`HMAC(prk, "et-traffic" || epoch || dir ||
//!   0x01)` over `HMAC(0^32, root_key)`), the send nonce is
//!   `epoch_be || seq_be` in the AEAD tail, replay is a 256-bit window
//!   per direction with two live epochs + a far-future bound, epochs
//!   rotate after 1M packets / 10 min, and a root-key sync keeps the
//!   pre-sync rx epochs valid for a 5s grace window.
//! * **The session store** — [`PeerSessionStore`] (peer_session.rs, 422
//!   lines; the two-node subset): per-peer sessions keyed by
//!   `(network_name, peer_id)` with the Join/Sync/Create generation
//!   election (the responder decides) and pinned remote static keys.
//! * **The auth subset** — `verify_remote_auth`'s proof and pinned-key
//!   paths; the trusted-key store (credential file + OSPF key
//!   propagation) and the foreign-network identity roles are not ported
//!   ([`SECURE_MODE_PORTED_NOTE`]).
//!
//! # Remaining milestones
//!
//! 1. The relay path, foreign networks, and the exit-node/proxy-network
//!    pieces.
//! 2. Multi-hop OSPF (SPF over `graph_algo.rs`) — the node table and
//!    forwarding are multi-peer now, but adjacency is still the
//!    direct-neighbor bitmap.
//! 3. IPv6 overlay addressing (see the M5 verdict in [`NOT_PORTED`])
//!    and the hole-punch connector paths.
//!
//! # Config surface
//!
//! Every field of upstream `EasyTierOption` (cached lines 56-89) is
//! carried by [`EasyTierConfig`] and projected into
//! [`EasyTierTomlConfig`] (`structuredConfig`, cached lines 91-126 —
//! instance-name defaults to the proxy name). `network-secret`,
//! `local-private-key` and peer public keys are secrets: redacted in
//! `Debug`, tests source them from an environment variable only.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet, VecDeque};
use std::hash::Hasher;
use std::io;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};
use std::pin::Pin;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex as StdMutex};
use std::task::{Context, Poll, Waker};
use std::time::{Duration, Instant};

use aes_gcm::aead::{Aead as _, AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use base64::Engine as _;
use chacha20poly1305::ChaCha20Poly1305;
use hmac::Mac as _;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex, Notify};

use crate::error::{Error, Result};
use crate::proto::wireguard::{et_pump, parse_wg_msg, WgMsg};
use crate::stream::BoxProxyStream;

/// `defaultListener` (toml.go:10).
pub const DEFAULT_LISTENER: &str = "tcp://0.0.0.0:11010";
/// `DefaultTLDDNSZone` (overlay.go:11).
pub const DEFAULT_TLD_DNS_ZONE: &str = "et.net.";

// ---------------------------------------------------------------------------
// Overlay DNS helpers (component/easytier/overlay.go) — the portable piece
// ---------------------------------------------------------------------------

/// One overlay IPv4 hostname mapping (`overlay.go:13-17`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OverlayNode {
    pub hostname: String,
    pub ipv4: Ipv4Addr,
}

/// `NormalizeDNSName` (overlay.go:20-22): lowercase, strip one trailing
/// dot, trim whitespace.
pub fn normalize_dns_name(name: &str) -> String {
    name.trim().trim_end_matches('.').to_lowercase()
}

/// `NormalizeZone` (overlay.go:24-30): a MagicDNS zone without a
/// trailing dot, defaulting to `et.net.`.
pub fn normalize_zone(zone: &str) -> String {
    let zone = normalize_dns_name(zone);
    if zone.is_empty() {
        normalize_dns_name(DEFAULT_TLD_DNS_ZONE)
    } else {
        zone
    }
}

/// `OverlayNames` (overlay.go:33-45): the hostname forms MagicDNS may
/// use — the bare hostname plus `<hostname>.<zone>` unless it already
/// is a zone name.
pub fn overlay_names(hostname: &str, zone: &str) -> Vec<String> {
    let hostname = normalize_dns_name(hostname);
    if hostname.is_empty() {
        return Vec::new();
    }
    let zone = normalize_zone(zone);
    let mut names = vec![hostname.clone()];
    if hostname != zone && !hostname.ends_with(&format!(".{zone}")) {
        names.push(format!("{hostname}.{zone}"));
    }
    names
}

/// `IsMagicDNS` (overlay.go:47-55): names inside the zone stay on the
/// overlay resolver.
pub fn is_magic_dns(host: &str, zone: &str) -> bool {
    let host = normalize_dns_name(host);
    if host.is_empty() {
        return false;
    }
    let zone = normalize_zone(zone);
    host == zone || host.ends_with(&format!(".{zone}"))
}

/// `LookupOverlayHost` (overlay.go:57-74): the overlay IPv4 for a host
/// name, by any of its MagicDNS forms.
pub fn lookup_overlay_host(host: &str, zone: &str, nodes: &[OverlayNode]) -> Option<Ipv4Addr> {
    let host = normalize_dns_name(host);
    if host.is_empty() {
        return None;
    }
    for node in nodes {
        for name in overlay_names(&node.hostname, zone) {
            if host == name {
                return Some(node.ipv4);
            }
        }
    }
    None
}

/// `LookupOverlayPTR` (overlay.go:76-93): the MagicDNS name (zone form,
/// trailing dot) for an overlay IPv4.
pub fn lookup_overlay_ptr(ip: Ipv4Addr, zone: &str, nodes: &[OverlayNode]) -> Option<String> {
    let zone = normalize_zone(zone);
    for node in nodes {
        if node.ipv4 != ip {
            continue;
        }
        let names = overlay_names(&node.hostname, &zone);
        let last = names.last()?;
        return Some(format!("{last}."));
    }
    None
}

/// `ParseNodeIPv4` (overlay.go:95-109): an address or CIDR — the
/// prefix length is dropped (`10.144.0.1/24` → `10.144.0.1`).
pub fn parse_node_ipv4(value: &str) -> Result<Ipv4Addr> {
    let value = value.trim();
    if value.is_empty() {
        return Err(Error::config("easytier: empty overlay IPv4 address"));
    }
    let addr = value.split('/').next().unwrap_or(value);
    addr.parse::<Ipv4Addr>()
        .map_err(|e| Error::config(format!("easytier: invalid overlay IPv4 {value:?}: {e}")))
}

/// `IPv4FromUint32` (overlay.go:111-116): big-endian u32 → address.
pub fn ipv4_from_u32(addr: u32) -> Ipv4Addr {
    Ipv4Addr::from(addr.to_be_bytes())
}

/// `ParsePTRIPv4` (overlay.go:118-138): `2.0.144.10.in-addr.arpa.` →
/// `10.144.0.2`.
pub fn parse_ptr_ipv4(name: &str) -> Option<Ipv4Addr> {
    let name = normalize_dns_name(name);
    let stripped = name.strip_suffix(".in-addr.arpa")?;
    let labels: Vec<&str> = stripped.split('.').collect();
    if labels.len() != 4 {
        return None;
    }
    let mut octets = [0u8; 4];
    for (i, label) in labels.iter().rev().enumerate() {
        let Ok(part) = label.parse::<u8>() else {
            return None;
        };
        octets[i] = part;
    }
    Some(Ipv4Addr::from(octets))
}

// ---------------------------------------------------------------------------
// Config surface (adapter/outbound/easytier.go EasyTierOption)
// ---------------------------------------------------------------------------

/// The `easytier` outbound configuration, mirroring mihomo's
/// `EasyTierOption` (cached lines 56-89).
#[derive(Default, Clone, PartialEq, Eq)]
pub struct EasyTierConfig {
    /// `name:` — the proxy name; also the default instance name and
    /// the default state-dir component.
    pub name: String,
    /// `network-name:` — the mesh to join (required).
    pub network_name: String,
    /// `network-secret:` the mesh passphrase. Secret; never logged.
    pub network_secret: String,
    /// `hostname:` — this node's MagicDNS hostname.
    pub hostname: Option<String>,
    /// `ipv4:` — static overlay address (address or CIDR).
    pub ipv4: Option<String>,
    /// `dhcp:` — take an address from the mesh (default when `ipv4` is
    /// unset, enforced at render time like upstream).
    pub dhcp: bool,
    /// `peers:` — peer URIs (`tcp://`, `udp://`, `quic://`, `ws://`…,
    /// optionally `?peer-public-key=`).
    pub peers: Vec<String>,
    /// `listeners:` — local listener URIs.
    pub listeners: Vec<String>,
    /// `no-listener:` — bind nothing (cannot combine with listeners).
    pub no_listener: Option<bool>,
    /// `mapped-listeners:` — advertised listener URIs (NAT).
    pub mapped_listeners: Vec<String>,
    /// `exit-nodes:` — overlay nodes acting as default route.
    pub exit_nodes: Vec<String>,
    /// `proxy-networks:` — CIDRs exported into the mesh.
    pub proxy_networks: Vec<String>,
    /// `instance-name:` — the easytier instance name.
    pub instance_name: Option<String>,
    /// `state-dir:` — instance state (default `easytier/<name>`).
    pub state_dir: Option<String>,
    /// `udp:` — support UDP through the overlay.
    pub udp: bool,
    /// `accept-dns:` — take DNS from the mesh.
    pub accept_dns: Option<bool>,
    /// `enable-exit-node:`
    pub enable_exit_node: Option<bool>,
    /// `enable-encryption:`
    pub enable_encryption: Option<bool>,
    /// `encryption-algorithm:`
    pub encryption_algorithm: Option<String>,
    /// `private-mode:`
    pub private_mode: Option<bool>,
    /// `latency-first:` — prefer low latency over minimum hops.
    pub latency_first: Option<bool>,
    /// `disable-p2p:`
    pub disable_p2p: Option<bool>,
    /// `enable-kcp-proxy:`
    pub enable_kcp_proxy: Option<bool>,
    /// `disable-kcp-input:`
    pub disable_kcp_input: Option<bool>,
    /// `enable-quic-proxy:`
    pub enable_quic_proxy: Option<bool>,
    /// `disable-quic-input:`
    pub disable_quic_input: Option<bool>,
    /// `mtu:`
    pub mtu: i64,
    /// `tld-dns-zone:` — the MagicDNS zone (default `et.net.`).
    pub tld_dns_zone: Option<String>,
    /// `secure-mode:` — key-pinned mesh (implied by key material).
    pub secure_mode: Option<bool>,
    /// `local-private-key:` Secret; never logged.
    pub local_private_key: Option<String>,
    /// `local-public-key:`
    pub local_public_key: Option<String>,
}

impl std::fmt::Debug for EasyTierConfig {
    /// Debug redacts `network_secret`, `local_private_key` and
    /// `local_public_key`: secrets must never appear in output.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EasyTierConfig")
            .field("name", &self.name)
            .field("network_name", &self.network_name)
            .field("network_secret", &(!self.network_secret.is_empty()).then_some("[redacted]"))
            .field("hostname", &self.hostname)
            .field("ipv4", &self.ipv4)
            .field("dhcp", &self.dhcp)
            .field("peers", &self.peers)
            .field("listeners", &self.listeners)
            .field("no_listener", &self.no_listener)
            .field("mapped_listeners", &self.mapped_listeners)
            .field("exit_nodes", &self.exit_nodes)
            .field("proxy_networks", &self.proxy_networks)
            .field("instance_name", &self.instance_name)
            .field("state_dir", &self.state_dir)
            .field("udp", &self.udp)
            .field("accept_dns", &self.accept_dns)
            .field("enable_exit_node", &self.enable_exit_node)
            .field("enable_encryption", &self.enable_encryption)
            .field("encryption_algorithm", &self.encryption_algorithm)
            .field("private_mode", &self.private_mode)
            .field("latency_first", &self.latency_first)
            .field("disable_p2p", &self.disable_p2p)
            .field("enable_kcp_proxy", &self.enable_kcp_proxy)
            .field("disable_kcp_input", &self.disable_kcp_input)
            .field("enable_quic_proxy", &self.enable_quic_proxy)
            .field("disable_quic_input", &self.disable_quic_input)
            .field("mtu", &self.mtu)
            .field("tld_dns_zone", &self.tld_dns_zone)
            .field("secure_mode", &self.secure_mode)
            .field("local_private_key", &self.local_private_key.as_ref().map(|_| "[redacted]"))
            .field("local_public_key", &self.local_public_key.as_ref().map(|_| "[redacted]"))
            .finish()
    }
}

impl EasyTierConfig {
    /// A minimal config with name + network, like the zero-value
    /// `EasyTierOption` plus its required field.
    pub fn new(name: impl Into<String>, network_name: impl Into<String>) -> Self {
        EasyTierConfig {
            name: name.into(),
            network_name: network_name.into(),
            ..Default::default()
        }
    }

    /// `structuredConfig` (cached lines 91-126): project the proxy
    /// options into the TOML-layer config; instance-name defaults to
    /// the proxy name.
    pub fn structured_config(&self) -> EasyTierTomlConfig {
        EasyTierTomlConfig {
            network_name: self.network_name.clone(),
            network_secret: self.network_secret.clone(),
            hostname: self.hostname.clone().unwrap_or_default(),
            ipv4: self.ipv4.clone().unwrap_or_default(),
            dhcp: self.dhcp,
            peers: self.peers.clone(),
            listeners: self.listeners.clone(),
            no_listener: self.no_listener,
            mapped_listeners: self.mapped_listeners.clone(),
            exit_nodes: self.exit_nodes.clone(),
            proxy_networks: self.proxy_networks.clone(),
            instance_name: self
                .instance_name
                .clone()
                .unwrap_or_else(|| self.name.clone()),
            accept_dns: self.accept_dns,
            enable_exit_node: self.enable_exit_node,
            enable_encryption: self.enable_encryption,
            encryption_algorithm: self.encryption_algorithm.clone().unwrap_or_default(),
            private_mode: self.private_mode,
            latency_first: self.latency_first,
            disable_p2p: self.disable_p2p,
            enable_kcp_proxy: self.enable_kcp_proxy,
            disable_kcp_input: self.disable_kcp_input,
            enable_quic_proxy: self.enable_quic_proxy,
            disable_quic_input: self.disable_quic_input,
            mtu: self.mtu,
            tld_dns_zone: self.tld_dns_zone.clone().unwrap_or_default(),
            secure_mode: self.secure_mode,
            local_private_key: self.local_private_key.clone().unwrap_or_default(),
            local_public_key: self.local_public_key.clone().unwrap_or_default(),
        }
    }

    /// The default state-dir (cached lines 135-138):
    /// `easytier/<name>`.
    pub fn effective_state_dir(&self) -> String {
        self.state_dir
            .clone()
            .unwrap_or_else(|| format!("easytier/{}", self.name))
    }

    /// `NormalizeZone(option.TLDDNSZone)` (cached line 163).
    pub fn zone(&self) -> String {
        normalize_zone(self.tld_dns_zone.as_deref().unwrap_or(""))
    }

    /// Render the instance TOML: `structuredConfig().RenderTOML()` +
    /// `ApplyRequiredFlags` (cached lines 128-134).
    pub fn render_instance_toml(&self) -> Result<String> {
        let toml = self.structured_config().render_toml()?;
        Ok(apply_required_flags(&toml))
    }
}

// ---------------------------------------------------------------------------
// TOML layer (component/easytier/toml.go) — the ported portable piece
// ---------------------------------------------------------------------------

/// The structured EasyTier instance configuration rendered to TOML
/// (`easytier.Config`, toml.go:18-47).
#[derive(Default, Clone, PartialEq, Eq, Debug)]
pub struct EasyTierTomlConfig {
    pub network_name: String,
    pub network_secret: String,
    pub hostname: String,
    pub ipv4: String,
    pub dhcp: bool,
    pub peers: Vec<String>,
    pub listeners: Vec<String>,
    pub no_listener: Option<bool>,
    pub mapped_listeners: Vec<String>,
    pub exit_nodes: Vec<String>,
    pub proxy_networks: Vec<String>,
    pub instance_name: String,
    pub accept_dns: Option<bool>,
    pub enable_exit_node: Option<bool>,
    pub enable_encryption: Option<bool>,
    pub encryption_algorithm: String,
    pub private_mode: Option<bool>,
    pub latency_first: Option<bool>,
    pub disable_p2p: Option<bool>,
    pub enable_kcp_proxy: Option<bool>,
    pub disable_kcp_input: Option<bool>,
    pub enable_quic_proxy: Option<bool>,
    pub disable_quic_input: Option<bool>,
    pub mtu: i64,
    pub tld_dns_zone: String,
    pub secure_mode: Option<bool>,
    pub local_private_key: String,
    pub local_public_key: String,
}

/// One `[[peer]]` table after URI query extraction (toml.go:49-53).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Peer {
    pub uri: String,
    pub peer_public_key: String,
}

impl EasyTierTomlConfig {
    /// `listeners()` (toml.go:55-66): no-listener wins, then the
    /// configured list, then the default listener when no-listener is
    /// explicitly false.
    pub fn listeners(&self) -> Vec<String> {
        if self.no_listener == Some(true) {
            return Vec::new();
        }
        if !self.listeners.is_empty() {
            return self.listeners.clone();
        }
        if self.no_listener == Some(false) {
            return vec![DEFAULT_LISTENER.to_string()];
        }
        Vec::new()
    }

    /// `parsedPeers()` (toml.go:91-100).
    pub fn parsed_peers(&self) -> Result<Vec<Peer>> {
        self.peers
            .iter()
            .enumerate()
            .map(|(i, raw)| {
                parse_peer_uri(raw)
                    .map_err(|e| Error::config(format!("easytier: peers[{i}]: {e}")))
            })
            .collect()
    }

    fn has_secure_mode_material(&self) -> bool {
        if !self.local_private_key.is_empty() || !self.local_public_key.is_empty() {
            return true;
        }
        self.parsed_peers()
            .map(|peers| peers.iter().any(|p| !p.peer_public_key.is_empty()))
            .unwrap_or(false)
    }

    /// `secureModeEnabled()` (toml.go:162-167).
    fn secure_mode_enabled(&self) -> bool {
        self.secure_mode.unwrap_or_else(|| self.has_secure_mode_material())
    }

    /// `ValidateStructured()` (toml.go:68-89) — the exact upstream
    /// error strings.
    pub fn validate(&self) -> Result<()> {
        if self.network_name.trim().is_empty() {
            return Err(Error::config("easytier: network-name is required"));
        }
        if self.no_listener == Some(true) && !self.listeners.is_empty() {
            return Err(Error::config(
                "easytier: no-listener cannot be combined with listeners",
            ));
        }
        if self.peers.is_empty() && self.listeners().is_empty() {
            return Err(Error::config(
                "easytier: peers is required when listeners are empty; implicit public.easytier.top is disabled",
            ));
        }
        self.parsed_peers()?;
        if !self.local_public_key.is_empty() && self.local_private_key.is_empty() {
            return Err(Error::config(
                "easytier: local-public-key requires local-private-key",
            ));
        }
        if self.secure_mode == Some(false) && self.has_secure_mode_material() {
            return Err(Error::config(
                "easytier: local keys and peer-public-key require secure-mode",
            ));
        }
        Ok(())
    }

    /// `RenderTOML()` (toml.go:169-250).
    pub fn render_toml(&self) -> Result<String> {
        self.validate()?;
        let mut out = String::new();
        if !self.instance_name.is_empty() {
            write_toml_string_field(&mut out, "instance_name", &self.instance_name);
        }
        if !self.hostname.is_empty() {
            write_toml_string_field(&mut out, "hostname", &self.hostname);
        }
        if !self.ipv4.trim().is_empty() {
            write_toml_string_field(&mut out, "ipv4", &self.ipv4);
        }
        if self.dhcp || self.ipv4.trim().is_empty() {
            write_toml_bool_field(&mut out, "dhcp", true);
        }
        write_toml_string_array_field(&mut out, "listeners", &self.listeners());
        if !self.mapped_listeners.is_empty() {
            write_toml_string_array_field(&mut out, "mapped_listeners", &self.mapped_listeners);
        }
        if !self.exit_nodes.is_empty() {
            write_toml_string_array_field(&mut out, "exit_nodes", &self.exit_nodes);
        }
        out.push('\n');
        out.push_str("[network_identity]\n");
        write_toml_string_field(&mut out, "network_name", &self.network_name);
        write_toml_string_field(&mut out, "network_secret", &self.network_secret);

        let peers = self.parsed_peers()?;
        if self.secure_mode_enabled() {
            out.push_str("\n[secure_mode]\n");
            write_toml_bool_field(&mut out, "enabled", true);
            if !self.local_private_key.is_empty() {
                write_toml_string_field(&mut out, "local_private_key", &self.local_private_key);
            }
            if !self.local_public_key.is_empty() {
                write_toml_string_field(&mut out, "local_public_key", &self.local_public_key);
            }
        }
        for peer in &peers {
            out.push_str("\n[[peer]]\n");
            write_toml_string_field(&mut out, "uri", &peer.uri);
            if !peer.peer_public_key.is_empty() {
                write_toml_string_field(&mut out, "peer_public_key", &peer.peer_public_key);
            }
        }
        for network in &self.proxy_networks {
            out.push_str("\n[[proxy_network]]\n");
            write_toml_string_field(&mut out, "cidr", network);
        }
        out.push_str("\n[flags]\n");
        write_toml_bool_field(&mut out, "no_tun", true);
        write_toml_bool_field(&mut out, "bind_device", false);
        write_optional_bool_field(&mut out, "accept_dns", self.accept_dns);
        write_optional_bool_field(&mut out, "enable_exit_node", self.enable_exit_node);
        write_optional_bool_field(&mut out, "enable_encryption", self.enable_encryption);
        if !self.encryption_algorithm.is_empty() {
            write_toml_string_field(&mut out, "encryption_algorithm", &self.encryption_algorithm);
        }
        write_optional_bool_field(&mut out, "private_mode", self.private_mode);
        write_optional_bool_field(&mut out, "latency_first", self.latency_first);
        write_optional_bool_field(&mut out, "disable_p2p", self.disable_p2p);
        write_optional_bool_field(&mut out, "enable_kcp_proxy", self.enable_kcp_proxy);
        write_optional_bool_field(&mut out, "disable_kcp_input", self.disable_kcp_input);
        write_optional_bool_field(&mut out, "enable_quic_proxy", self.enable_quic_proxy);
        write_optional_bool_field(&mut out, "disable_quic_input", self.disable_quic_input);
        if self.mtu > 0 {
            out.push_str(&format!("mtu = {}\n", self.mtu));
        }
        if !self.tld_dns_zone.is_empty() {
            write_toml_string_field(&mut out, "tld_dns_zone", &self.tld_dns_zone);
        }
        Ok(out)
    }
}

/// `url.PathUnescape` (the subset the peer URIs need): `%XX` decoding,
/// `+` stays literal.
fn path_unescape(raw: &str) -> Result<String> {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = raw
                .get(i + 1..i + 3)
                .ok_or_else(|| Error::config(format!("invalid URL escape in {raw:?}")))?;
            let v = u8::from_str_radix(hex, 16)
                .map_err(|_| Error::config(format!("invalid URL escape %{hex} in {raw:?}")))?;
            out.push(v);
            i += 3;
            continue;
        }
        out.push(bytes[i]);
        i += 1;
    }
    Ok(String::from_utf8_lossy(&out).into_owned())
}

/// `parsePeerURI` (toml.go:103-144): extract `peer-public-key` (or the
/// snake_case form) from the URI query, keep every other parameter,
/// and rebuild the URI without it. URIs without a query pass through
/// untouched.
pub fn parse_peer_uri(raw: &str) -> Result<Peer> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err(Error::config("uri is required"));
    }
    let Some((base, query)) = raw.split_once('?') else {
        return Ok(Peer {
            uri: raw.to_string(),
            peer_public_key: String::new(),
        });
    };
    let mut kept: Vec<&str> = Vec::new();
    let mut key = String::new();
    for pair in query.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (name, value) = pair.split_once('=').unwrap_or((pair, ""));
        let decoded_name = path_unescape(name)?;
        match decoded_name.as_str() {
            "peer-public-key" | "peer_public_key" => {
                key = path_unescape(value)?;
            }
            _ => kept.push(pair),
        }
    }
    if key.is_empty() {
        return Ok(Peer {
            uri: raw.to_string(),
            peer_public_key: String::new(),
        });
    }
    let uri = if kept.is_empty() {
        base.to_string()
    } else {
        format!("{base}?{}", kept.join("&"))
    };
    Ok(Peer {
        uri,
        peer_public_key: key,
    })
}

/// `isTOMLSection` (toml.go:314-324): `[name]` / `[[name]]`, optionally
/// followed by a comment.
fn is_toml_section(trimmed: &str) -> bool {
    if !trimmed.starts_with('[') {
        return false;
    }
    let Some(end) = trimmed.find(']') else {
        return false;
    };
    let rest = trimmed[end + 1..].trim();
    rest.is_empty() || rest.starts_with('#')
}

/// `sectionName` (toml.go:326-337).
fn section_name(trimmed: &str) -> &str {
    let end = trimmed.find(']').unwrap_or(0);
    let mut name = trimmed[..end + 1].trim();
    name = name.strip_prefix("[[").unwrap_or(name);
    let name = name.strip_prefix('[').unwrap_or(name);
    let name = name.strip_suffix("]]").unwrap_or(name);
    let name = name.strip_suffix(']').unwrap_or(name);
    name.trim_matches(['"', '\''])
}

/// `flagKey` (toml.go:339-344).
fn flag_key(trimmed: &str) -> &str {
    match trimmed.find('=') {
        Some(idx) => trimmed[..idx].trim().trim_matches(['"', '\'']),
        None => "",
    }
}

/// `ApplyRequiredFlags` (toml.go:252-312): force `no_tun = true` and
/// `bind_device = false` in the `[flags]` section (injecting the
/// section when absent) — the embedded core must not touch the host's
/// TUN or bind devices for a proxy-outbound use.
pub fn apply_required_flags(config_toml: &str) -> String {
    const FLAGS: [(&str, &str); 2] = [("no_tun", "true"), ("bind_device", "false")];
    let mut out: Vec<String> = Vec::new();
    let mut section = String::new();
    let mut seen: Vec<String> = Vec::new();
    let mut wrote_flags = false;

    fn flush(
        out: &mut Vec<String>,
        seen: &mut Vec<String>,
        section: &str,
        wrote_flags: &mut bool,
    ) {
        if section != "flags" {
            return;
        }
        const FLAGS: [(&str, &str); 2] = [("no_tun", "true"), ("bind_device", "false")];
        for (key, value) in FLAGS {
            if !seen.iter().any(|k| k == key) {
                out.push(format!("{key} = {value}"));
            }
        }
        *wrote_flags = true;
        seen.clear();
    }

    for line in config_toml.split('\n') {
        let trimmed = line.trim();
        if is_toml_section(trimmed) {
            flush(&mut out, &mut seen, &section, &mut wrote_flags);
            section = section_name(trimmed).to_string();
            out.push(line.to_string());
            continue;
        }
        if section == "flags" {
            let key = flag_key(trimmed);
            if let Some((required_key, required_value)) =
                FLAGS.iter().find(|(k, _)| *k == key)
            {
                out.push(format!("{key} = {required_value}"));
                seen.push(required_key.to_string());
                continue;
            }
        }
        out.push(line.to_string());
    }
    flush(&mut out, &mut seen, &section, &mut wrote_flags);
    if !wrote_flags {
        if let Some(last) = out.last() {
            if !last.trim().is_empty() {
                out.push(String::new());
            }
        }
        out.push("[flags]".to_string());
        for (key, value) in FLAGS {
            out.push(format!("{key} = {value}"));
        }
    }
    let joined = out.join("\n");
    format!("{}\n", joined.trim_end().trim_end_matches('\n'))
}

fn write_optional_bool_field(out: &mut String, name: &str, value: Option<bool>) {
    if let Some(value) = value {
        write_toml_bool_field(out, name, value);
    }
}

fn write_toml_string_field(out: &mut String, name: &str, value: &str) {
    out.push_str(&format!("{name} = {}\n", quote_toml_string(value)));
}

fn write_toml_bool_field(out: &mut String, name: &str, value: bool) {
    out.push_str(&format!("{name} = {value}\n"));
}

fn write_toml_string_array_field(out: &mut String, name: &str, values: &[String]) {
    let quoted: Vec<String> = values.iter().map(|v| quote_toml_string(v)).collect();
    out.push_str(&format!("{name} = [{}]\n", quoted.join(", ")));
}

/// `quoteTOMLString` (toml.go:371-377): Go's `json.Marshal` — including
/// its default HTML escaping of `<`, `>` and `&`.
pub fn quote_toml_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for c in value.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '<' => out.push_str("\\u003c"),
            '>' => out.push_str("\\u003e"),
            '&' => out.push_str("\\u0026"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

// ---------------------------------------------------------------------------
// Wire layer (EasyTier core: easytier-core/src/packet/mod.rs +
// tunnel/framed.rs + tunnel/tcp.rs), commit main@2026-09
// ---------------------------------------------------------------------------

/// `PeerId` — `easytier-core/src/config/mod.rs:55` (`pub type PeerId = u32`).
pub type PeerId = u32;

/// `TCP_TUNNEL_HEADER_SIZE` (packet/mod.rs:30): the 4-byte LE frame length.
pub const TCP_TUNNEL_HEADER_SIZE: usize = 4;
/// `PEER_MANAGER_HEADER_SIZE` (packet/mod.rs:136): 16.
pub const PEER_MANAGER_HEADER_SIZE: usize = 16;
/// `TCP_MTU_BYTES` (tunnel/framed.rs:23): the max framed body a TCP peer
/// tunnel accepts (`body too long` beyond it).
pub const TCP_MTU_BYTES: usize = 2000;

/// `PacketType` (packet/mod.rs:80-107) — the values this port speaks.
pub mod packet_type {
    pub const DATA: u8 = 1;
    pub const HANDSHAKE: u8 = 2;
    pub const PING: u8 = 4;
    pub const PONG: u8 = 5;
    pub const RPC_REQ: u8 = 8;
    pub const RPC_RESP: u8 = 9;
    /// `PacketType::NoiseHandshakeMsg1` (packet_def.rs:86) — the first
    /// message of the secure-mode handshake (msg2/msg3 live in
    /// [`noise_packet_type`], colocated with the secure-mode port).
    pub const NOISE_HANDSHAKE_MSG1: u8 = 13;
}

/// `PeerManagerHeaderFlags` (packet/mod.rs:110-123) — the bits this port
/// reads or writes.
pub mod pm_flag {
    pub const ENCRYPTED: u8 = 0b0000_0001;
    pub const LATENCY_FIRST: u8 = 0b0000_0010;
    pub const EXIT_NODE: u8 = 0b0000_0100;
}

/// `PeerManagerHeader` (packet/mod.rs:125-136): `#[repr(C, packed)]`
/// little-endian — from_peer_id, to_peer_id, packet_type, flags,
/// forward_counter, reserved, len.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PeerManagerHeader {
    pub from_peer_id: PeerId,
    pub to_peer_id: PeerId,
    pub packet_type: u8,
    pub flags: u8,
    pub forward_counter: u8,
    pub reserved: u8,
    /// The payload length after this header (`fill_peer_manager_hdr`,
    /// packet/mod.rs:718-728).
    pub len: u32,
}

impl PeerManagerHeader {
    fn to_bytes(self) -> [u8; PEER_MANAGER_HEADER_SIZE] {
        let mut out = [0u8; PEER_MANAGER_HEADER_SIZE];
        out[0..4].copy_from_slice(&self.from_peer_id.to_le_bytes());
        out[4..8].copy_from_slice(&self.to_peer_id.to_le_bytes());
        out[8] = self.packet_type;
        out[9] = self.flags;
        out[10] = self.forward_counter;
        out[11] = self.reserved;
        out[12..16].copy_from_slice(&self.len.to_le_bytes());
        out
    }

    fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < PEER_MANAGER_HEADER_SIZE {
            return None;
        }
        Some(Self {
            from_peer_id: u32::from_le_bytes(buf[0..4].try_into().ok()?),
            to_peer_id: u32::from_le_bytes(buf[4..8].try_into().ok()?),
            packet_type: buf[8],
            flags: buf[9],
            forward_counter: buf[10],
            reserved: buf[11],
            len: u32::from_le_bytes(buf[12..16].try_into().ok()?),
        })
    }

    /// `is_encrypted` (packet/mod.rs:139-143).
    pub fn is_encrypted(&self) -> bool {
        self.flags & pm_flag::ENCRYPTED != 0
    }

    /// `set_encrypted` (packet/mod.rs:145-153).
    pub fn set_encrypted(&mut self, encrypted: bool) {
        if encrypted {
            self.flags |= pm_flag::ENCRYPTED;
        } else {
            self.flags &= !pm_flag::ENCRYPTED;
        }
    }

    /// `is_latency_first` (packet/mod.rs:155-159).
    pub fn is_latency_first(&self) -> bool {
        self.flags & pm_flag::LATENCY_FIRST != 0
    }

    /// `set_latency_first` (packet/mod.rs:179-188).
    pub fn set_latency_first(&mut self, latency_first: bool) -> &mut Self {
        if latency_first {
            self.flags |= pm_flag::LATENCY_FIRST;
        } else {
            self.flags &= !pm_flag::LATENCY_FIRST;
        }
        self
    }

    /// `set_exit_node` (packet/mod.rs:190-199).
    pub fn set_exit_node(&mut self, exit_node: bool) -> &mut Self {
        if exit_node {
            self.flags |= pm_flag::EXIT_NODE;
        } else {
            self.flags &= !pm_flag::EXIT_NODE;
        }
        self
    }
}

/// The `ZCPacket` as it crosses the TCP peer tunnel: one peer-manager
/// header plus its payload (`fill_peer_manager_hdr` semantics:
/// `flags = 0`, `forward_counter = 1`, `reserved = 0`, `len = payload
/// length`, packet/mod.rs:718-728).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerPacket {
    pub hdr: PeerManagerHeader,
    pub payload: Vec<u8>,
}

impl PeerPacket {
    /// `ZCPacket::new_with_payload` + `fill_peer_manager_hdr`.
    pub fn new(from: PeerId, to: PeerId, packet_type: u8, payload: &[u8]) -> Self {
        PeerPacket {
            hdr: PeerManagerHeader {
                from_peer_id: from,
                to_peer_id: to,
                packet_type,
                flags: 0,
                forward_counter: 1,
                reserved: 0,
                len: payload.len() as u32,
            },
            payload: payload.to_vec(),
        }
    }

    /// `TcpZCPacketToBytes::zcpacket_into_bytes` (tunnel/framed.rs:137-151):
    /// the TCP frame is `[u32 LE = PEER_MANAGER_HEADER_SIZE + payload_len]
    /// [PeerManagerHeader] [payload]`.
    pub fn to_tcp_frame(&self) -> Result<Vec<u8>> {
        let tcp_len = PEER_MANAGER_HEADER_SIZE + self.payload.len();
        if tcp_len > TCP_MTU_BYTES {
            return Err(Error::protocol(format!(
                "easytier: packet exceeds TCP tunnel MTU. max: {TCP_MTU_BYTES}, input: {tcp_len}"
            )));
        }
        let mut out = Vec::with_capacity(TCP_TUNNEL_HEADER_SIZE + tcp_len);
        out.extend_from_slice(&(tcp_len as u32).to_le_bytes());
        let mut hdr = self.hdr;
        hdr.len = self.payload.len() as u32;
        out.extend_from_slice(&hdr.to_bytes());
        out.extend_from_slice(&self.payload);
        Ok(out)
    }

    /// Parse the body of one TCP frame (`FramedReader::extract_one_packet`,
    /// tunnel/framed.rs:61-85: the body is the peer-manager header +
    /// payload).
    pub fn from_frame_body(body: &[u8]) -> Result<Self> {
        let hdr = PeerManagerHeader::from_bytes(body)
            .ok_or_else(|| Error::protocol("easytier: body too short"))?;
        Ok(PeerPacket {
            hdr,
            payload: body[PEER_MANAGER_HEADER_SIZE..].to_vec(),
        })
    }
}

/// Write one TCP peer-tunnel frame (`FramedWriter`, tunnel/framed.rs:232+).
pub async fn write_frame<W: AsyncWrite + Unpin>(writer: &mut W, packet: &PeerPacket) -> Result<()> {
    writer.write_all(&packet.to_tcp_frame()?).await?;
    writer.flush().await?;
    Ok(())
}

/// Read one TCP peer-tunnel frame. `Ok(None)` is the clean stream end at
/// a frame boundary; the length validation mirrors
/// `FramedReader::extract_one_packet` (tunnel/framed.rs:61-85).
pub async fn read_frame<R: AsyncRead + Unpin>(reader: &mut R) -> Result<Option<PeerPacket>> {
    let mut len_buf = [0u8; TCP_TUNNEL_HEADER_SIZE];
    match reader.read_exact(&mut len_buf).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let body_len = u32::from_le_bytes(len_buf) as usize;
    if body_len > TCP_MTU_BYTES {
        return Err(Error::protocol("easytier: invalid packet. msg: body too long"));
    }
    if body_len < PEER_MANAGER_HEADER_SIZE {
        return Err(Error::protocol("easytier: invalid packet. msg: body too short"));
    }
    let mut body = vec![0u8; body_len];
    reader.read_exact(&mut body).await?;
    PeerPacket::from_frame_body(&body).map(Some)
}

// ---------------------------------------------------------------------------
// The UDP peer tunnel (easytier-core/src/tunnel/udp.rs + the
// `UDPTunnelHeader` of tunnel/packet_def.rs:22-59 — v2.6.4, the line the
// released binaries speak; reached from the peer connector via
// `IpScheme::Udp => UdpTunnelConnector::new(url)`, connector/mod.rs:248
// and connector/direct.rs:234)
// ---------------------------------------------------------------------------
//
// The UDP tunnel is a **datagram virtual circuit**: each write of one
// peer frame becomes one UDP datagram carrying `[PeerManagerHeader]
// [payload]` — the SAME peer-manager header as the TCP side but WITHOUT
// the u32 length prefix (the datagram bounds the frame; the
// `ZCPacketType::UDP` offsets of packet_def.rs:393-400), wrapped in an
// 8-byte session header. The circuit is established with a SYN/SACK
// exchange (`try_connect_with_socket` / `handle_new_connect`,
// tunnel/udp.rs:844-873, 417-477):
//
// * client: random `conn_id` (u32) + random `magic` (u64); sends
//   `[hdr{Syn, conn_id, len:8}][magic LE]`, then waits (3s budget,
//   `wait_sack_loop` tunnel/udp.rs:747-762) for the SACK echoing both;
// * server: on a Syn from an address, replies `[hdr{Sack, conn_id,
//   len:8}][magic LE]` and keys a connection by that remote address
//   (`sock_map`, tunnel/udp.rs:455) — the conn id of both directions is
//   the one the client chose;
// * data: every write becomes `[hdr{Data, conn_id, len=payload}]
//   [payload]`; the receiver keeps only Data packets whose conn id
//   matches (`UdpConnection::handle_packet_from_remote`,
//   tunnel/udp.rs:372-390).
//
// Upstream shuttles the payloads through a ring-buffer stream pair
// (`RingTunnel`, tunnel/ring.rs); this port collapses that into one
// duplex stream with datagram-sized queues (the engine's EtStream
// pattern). The STUN responder and the loopback hole-punch forwards of
// the listener's forward task (tunnel/udp.rs:182-241, 479-545) stay
// out — a hermetic mesh never sends them (see NOT_PORTED).

/// `UDP_TUNNEL_HEADER_SIZE` (packet_def.rs:59).
pub const UDP_TUNNEL_HEADER_SIZE: usize = 8;
/// `UDP_DATA_MTU` (tunnel/udp.rs:41): the datagram budget the tunnel is
/// sized for.
pub const UDP_DATA_MTU: usize = 2000;
/// The SACK wait budget (`Duration::from_secs(3)`, tunnel/udp.rs:862).
const UDP_SACK_TIMEOUT: Duration = Duration::from_secs(3);
/// How many datagrams may sit in one direction's queue (the ring is 128
/// slots, tunnel/udp.rs:439-440).
const UDP_CHAN_DATAGRAMS: usize = 128;
/// The receive buffer: generous over `UDP_DATA_MTU` so a reassembled
/// oversized datagram is never truncated (tokio's `recv_buf_from` grows
/// to 4x MTU upstream, tunnel/udp.rs:310).
const UDP_RECV_BUF: usize = 16 * 1024;

/// `UdpPacketType` (packet_def.rs:22-35).
pub mod udp_packet_type {
    pub const INVALID: u8 = 0;
    pub const SYN: u8 = 1;
    pub const SACK: u8 = 2;
    pub const DATA: u8 = 3;
    pub const FIN: u8 = 4;
    pub const HOLE_PUNCH: u8 = 5;
    pub const V4_HOLE_PUNCH: u8 = 6;
    pub const V6_HOLE_PUNCH: u8 = 7;
}

/// The 8-byte packed little-endian `UDPTunnelHeader`
/// `{ conn_id: U32, msg_type: u8, padding: u8, len: U16 }`
/// (packet_def.rs:51-58).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct UdpTunnelHeader {
    conn_id: u32,
    msg_type: u8,
    len: u16,
}

impl UdpTunnelHeader {
    fn to_bytes(self) -> [u8; UDP_TUNNEL_HEADER_SIZE] {
        let mut out = [0u8; UDP_TUNNEL_HEADER_SIZE];
        out[0..4].copy_from_slice(&self.conn_id.to_le_bytes());
        out[4] = self.msg_type;
        // out[5] is padding, always zero.
        out[6..8].copy_from_slice(&self.len.to_le_bytes());
        out
    }

    fn from_bytes(buf: &[u8]) -> Option<Self> {
        if buf.len() < UDP_TUNNEL_HEADER_SIZE {
            return None;
        }
        Some(UdpTunnelHeader {
            conn_id: u32::from_le_bytes(buf[0..4].try_into().ok()?),
            msg_type: buf[4],
            len: u16::from_le_bytes(buf[6..8].try_into().ok()?),
        })
    }

    /// `new_udp_packet` (tunnel/udp.rs:46-61): header plus body, `len`
    /// the body length.
    fn datagram(msg_type: u8, conn_id: u32, body: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(UDP_TUNNEL_HEADER_SIZE + body.len());
        out.extend_from_slice(
            &UdpTunnelHeader {
                conn_id,
                msg_type,
                len: body.len() as u16,
            }
            .to_bytes(),
        );
        out.extend_from_slice(body);
        out
    }
}

/// `get_zcpacket_from_buf` (tunnel/udp.rs:243-267) without the STUN
/// branch: a datagram must carry the 8-byte header and its `len` must
/// equal the body length, else it is not tunnel traffic.
fn parse_udp_datagram(buf: &[u8]) -> Option<(UdpTunnelHeader, &[u8])> {
    let header = UdpTunnelHeader::from_bytes(buf)?;
    let body = &buf[UDP_TUNNEL_HEADER_SIZE..];
    if header.len as usize != body.len() {
        return None;
    }
    Some((header, body))
}

/// The tunnel payload a UDP datagram carries: `[PeerManagerHeader]
/// [payload]` — NO length prefix (the datagram bounds the frame), the
/// `ZCPacketType::UDP` offsets of packet_def.rs:393-400. The peer
/// framing layer writes `[u32 len][PMH][payload]` byte streams; this
/// strips the prefix when segmenting a stream frame into its datagram.
fn udp_wire_datagram(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < TCP_TUNNEL_HEADER_SIZE + PEER_MANAGER_HEADER_SIZE {
        return None;
    }
    let len = u32::from_le_bytes(frame[..TCP_TUNNEL_HEADER_SIZE].try_into().ok()?) as usize;
    let end = TCP_TUNNEL_HEADER_SIZE.checked_add(len)?;
    if len < PEER_MANAGER_HEADER_SIZE || len > u16::MAX as usize || end != frame.len() {
        return None;
    }
    Some(&frame[TCP_TUNNEL_HEADER_SIZE..end])
}

/// One queued-datagram duplex end (`UdpVtShared`): the read side serves
/// bytes out of received datagrams (each datagram is re-prefixed with
/// its u32 length so the framing reader sees a normal byte stream; a
/// partially-consumed datagram is retained — the framing reader pulls
/// its frame in several small reads); the write side stages the framed
/// byte stream, cutting one `[PMH][payload]` datagram per complete
/// stream frame for the sender task.
struct UdpVtHalf {
    rx_queue: VecDeque<Vec<u8>>,
    partial: Vec<u8>,
    partial_pos: usize,
    read_waker: Option<Waker>,
    tx_stage: Vec<u8>,
    tx_queue: VecDeque<Vec<u8>>,
    write_waker: Option<Waker>,
    write_closed: bool,
    write_error: bool,
    read_closed: bool,
}

impl UdpVtHalf {
    fn new() -> Self {
        UdpVtHalf {
            rx_queue: VecDeque::new(),
            partial: Vec::new(),
            partial_pos: 0,
            read_waker: None,
            tx_stage: Vec::new(),
            tx_queue: VecDeque::new(),
            write_waker: None,
            write_closed: false,
            write_error: false,
            read_closed: false,
        }
    }

    /// One received `[PMH][payload]` datagram becomes a `[u32 len]
    /// [PMH][payload]` byte-stream chunk (the inverse of the write-side
    /// segmentation).
    fn push_datagram(&mut self, data: &[u8]) {
        if self.rx_queue.len() >= UDP_CHAN_DATAGRAMS {
            return;
        }
        let mut framed = Vec::with_capacity(TCP_TUNNEL_HEADER_SIZE + data.len());
        framed.extend_from_slice(&(data.len() as u32).to_le_bytes());
        framed.extend_from_slice(data);
        self.rx_queue.push_back(framed);
    }

    /// Cut every complete stream frame staged in `tx_stage` into its
    /// datagram. Returns false on a malformed stage.
    fn segment_staged(&mut self) -> bool {
        loop {
            if self.tx_stage.len() < TCP_TUNNEL_HEADER_SIZE {
                return true;
            }
            let Some(datagram) = udp_wire_datagram(&self.tx_stage) else {
                self.write_error = true;
                return false;
            };
            if self.tx_queue.len() >= UDP_CHAN_DATAGRAMS {
                return true;
            }
            self.tx_queue.push_back(datagram.to_vec());
            self.tx_stage.drain(..TCP_TUNNEL_HEADER_SIZE + datagram.len());
        }
    }
}

/// The client/accepted UDP tunnel stream: `AsyncRead` + `AsyncWrite`
/// over the shared half, the sender task woken through `Notify`.
pub struct UdpVtStream {
    half: Arc<StdMutex<UdpVtHalf>>,
    send_wake: Arc<Notify>,
}

impl AsyncRead for UdpVtStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let mut half = self.half.lock().unwrap_or_else(|e| e.into_inner());
        if half.partial_pos < half.partial.len() {
            let n = (half.partial.len() - half.partial_pos).min(buf.remaining());
            buf.put_slice(&half.partial[half.partial_pos..half.partial_pos + n]);
            half.partial_pos += n;
            if half.partial_pos == half.partial.len() {
                half.partial.clear();
                half.partial_pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        if let Some(next) = half.rx_queue.pop_front() {
            half.partial = next;
            half.partial_pos = 0;
            drop(half);
            return self.poll_read(cx, buf);
        }
        if half.read_closed {
            return Poll::Ready(Ok(()));
        }
        half.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for UdpVtStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut half = self.half.lock().unwrap_or_else(|e| e.into_inner());
        if half.write_error {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "easytier: udp tunnel send failed",
            )));
        }
        if half.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "easytier: udp tunnel is closed",
            )));
        }
        if half.tx_queue.len() >= UDP_CHAN_DATAGRAMS {
            half.write_waker = Some(cx.waker().clone());
            return Poll::Pending;
        }
        // Stage the framed byte stream, then cut every complete frame
        // into its `[PMH][payload]` datagram (the ring carries whole
        // ZCPackets upstream — one frame per datagram).
        half.tx_stage.extend_from_slice(buf);
        if !half.segment_staged() {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "easytier: udp datagram stream is not frame-aligned",
            )));
        }
        drop(half);
        self.send_wake.notify_one();
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut half = self.half.lock().unwrap_or_else(|e| e.into_inner());
        // `UdpPacketType::Fin` exists but is never sent by the v2.6.4
        // tunnel; closing is simply going silent (the peer's ping losses
        // tear the circuit down).
        half.write_closed = true;
        Poll::Ready(Ok(()))
    }
}

/// Wake a waiting reader/writer after external state changed.
fn wake_udp_half(half: &Arc<StdMutex<UdpVtHalf>>) {
    let mut half = half.lock().unwrap_or_else(|e| e.into_inner());
    if let Some(w) = half.read_waker.take() {
        w.wake();
    }
    if let Some(w) = half.write_waker.take() {
        w.wake();
    }
}

/// The sender task (`forward_from_ring_to_udp`, tunnel/udp.rs:269-302):
/// drain the write queue into Data datagrams for `dst`.
async fn run_udp_sender(
    socket: Arc<tokio::net::UdpSocket>,
    dst: SocketAddr,
    conn_id: u32,
    half: Arc<StdMutex<UdpVtHalf>>,
    wake: Arc<Notify>,
) {
    loop {
        wake.notified().await;
        loop {
            let next = {
                let mut guard = half.lock().unwrap_or_else(|e| e.into_inner());
                guard.tx_queue.pop_front()
            };
            let Some(body) = next else { break };
            if let Some(w) = half
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .write_waker
                .take()
            {
                w.wake();
            }
            let datagram = UdpTunnelHeader::datagram(udp_packet_type::DATA, conn_id, &body);
            if socket.send_to(&datagram, dst).await.is_err() {
                let mut guard = half.lock().unwrap_or_else(|e| e.into_inner());
                guard.write_error = true;
                guard.read_closed = true;
                drop(guard);
                wake_udp_half(&half);
                return;
            }
        }
    }
}

/// The client connect (`UdpTunnelConnector::connect` →
/// `try_connect_with_socket`, tunnel/udp.rs:844-873): bind an ephemeral
/// socket, SYN/SACK, then run the receiver task (`build_tunnel`'s
/// recv_loop, tunnel/udp.rs:793-809 — Data packets are matched by conn
/// id only).
pub async fn connect_udp_tunnel(dst: SocketAddr) -> Result<UdpVtStream> {
    let bind_addr: &str = if dst.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = tokio::net::UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| Error::network(format!("easytier: udp bind: {e}")))?;
    let socket = Arc::new(socket);
    let conn_id: u32 = rand::random();
    let magic: u64 = rand::random();
    let syn = UdpTunnelHeader::datagram(udp_packet_type::SYN, conn_id, &magic.to_le_bytes());
    socket
        .send_to(&syn, dst)
        .await
        .map_err(|e| Error::network(format!("easytier: udp send syn: {e}")))?;

    // `wait_sack_loop`: retry on any invalid packet, bounded by the 3s
    // outer timeout (tunnel/udp.rs:862-866).
    let deadline = tokio::time::Instant::now() + UDP_SACK_TIMEOUT;
    let mut buf = vec![0u8; UDP_RECV_BUF];
    loop {
        let recv = match tokio::time::timeout_at(deadline, socket.recv_from(&mut buf)).await {
            Err(_) => {
                return Err(Error::network("easytier: udp connect timeout (no sack)"));
            }
            Ok(Err(e)) => return Err(Error::network(format!("easytier: udp recv: {e}"))),
            Ok(Ok((n, _addr))) => &buf[..n],
        };
        if let Some((header, body)) = parse_udp_datagram(recv) {
            if header.msg_type == udp_packet_type::SACK
                && header.conn_id == conn_id
                && body == magic.to_le_bytes()
            {
                break;
            }
        }
    }

    let half = Arc::new(StdMutex::new(UdpVtHalf::new()));
    let wake = Arc::new(Notify::new());
    let recv_socket = socket.clone();
    let recv_half = half.clone();
    tokio::spawn(async move {
        let mut buf = vec![0u8; UDP_RECV_BUF];
        loop {
            match recv_socket.recv_from(&mut buf).await {
                Ok((n, _)) => {
                    if let Some((header, body)) = parse_udp_datagram(&buf[..n]) {
                        if header.msg_type == udp_packet_type::DATA && header.conn_id == conn_id {
                            let mut guard = recv_half.lock().unwrap_or_else(|e| e.into_inner());
                            guard.push_datagram(body);
                            drop(guard);
                            wake_udp_half(&recv_half);
                        }
                    }
                }
                Err(_) => {
                    let mut guard = recv_half.lock().unwrap_or_else(|e| e.into_inner());
                    guard.read_closed = true;
                    drop(guard);
                    wake_udp_half(&recv_half);
                    break;
                }
            }
        }
    });
    tokio::spawn(run_udp_sender(socket, dst, conn_id, half.clone(), wake.clone()));
    Ok(UdpVtStream { half, send_wake: wake })
}

/// One accepted server-side circuit (`UdpConnection` keyed by remote
/// address, tunnel/udp.rs:337-391).
struct UdpAcceptedConn {
    conn_id: u32,
    half: Arc<StdMutex<UdpVtHalf>>,
}

/// The UDP tunnel listener (`UdpTunnelListener`, tunnel/udp.rs:562-678):
/// one socket; a Syn from an address establishes a circuit (SACK back,
/// connection keyed by the remote address); Data datagrams are routed to
/// that circuit by address and conn id. Hole-punch and STUN datagrams
/// are ignored (upstream answers them, tunnel/udp.rs:483-492).
pub struct UdpVtListener {
    local: SocketAddr,
    accept_rx: mpsc::Receiver<UdpVtStream>,
    task: tokio::task::JoinHandle<()>,
}

impl UdpVtListener {
    /// `UdpTunnelListener::listen` (tunnel/udp.rs:599-639).
    pub async fn bind(local: SocketAddr) -> Result<Self> {
        let bind_addr: std::net::SocketAddr = match local {
            SocketAddr::V4(v4) => {
                std::net::SocketAddr::V4(std::net::SocketAddrV4::new(v4.ip().to_owned(), v4.port()))
            }
            SocketAddr::V6(_) => local,
        };
        let socket = tokio::net::UdpSocket::bind(bind_addr)
            .await
            .map_err(|e| Error::network(format!("easytier: udp listen {local}: {e}")))?;
        let local = socket
            .local_addr()
            .map_err(|e| Error::network(format!("easytier: udp local addr: {e}")))?;
        let socket = Arc::new(socket);
        let (accept_tx, accept_rx) = mpsc::channel(16);
        let conns: Arc<StdMutex<HashMap<SocketAddr, UdpAcceptedConn>>> =
            Arc::new(StdMutex::new(HashMap::new()));
        let task = tokio::spawn(run_udp_listener(socket, conns, accept_tx));
        Ok(UdpVtListener {
            local,
            accept_rx,
            task,
        })
    }

    /// The bound address (port 0 resolves, `local_url`, tunnel/udp.rs:613).
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// `accept` (tunnel/udp.rs:641-649): the next established circuit.
    pub async fn accept(&mut self) -> Result<UdpVtStream> {
        self.accept_rx
            .recv()
            .await
            .ok_or_else(|| Error::network("easytier: udp listener closed"))
    }
}

impl Drop for UdpVtListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The listener forward task (`do_forward_task` +
/// `do_forward_one_packet_to_conn`, tunnel/udp.rs:479-559): Syn →
/// `handle_new_connect`; Data → the circuit for that address.
async fn run_udp_listener(
    socket: Arc<tokio::net::UdpSocket>,
    conns: Arc<StdMutex<HashMap<SocketAddr, UdpAcceptedConn>>>,
    accept_tx: mpsc::Sender<UdpVtStream>,
) {
    let mut buf = vec![0u8; UDP_RECV_BUF];
    loop {
        let (n, addr) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => break,
        };
        let Some((header, body)) = parse_udp_datagram(&buf[..n]) else {
            continue;
        };
        match header.msg_type {
            udp_packet_type::SYN => {
                // `handle_new_connect`: an 8-byte magic payload, SACK it
                // back, then the circuit joins the map (a reconnect from
                // the same address replaces, tunnel/udp.rs:455).
                if body.len() != 8 {
                    continue;
                }
                let sack =
                    UdpTunnelHeader::datagram(udp_packet_type::SACK, header.conn_id, body);
                if socket.send_to(&sack, addr).await.is_err() {
                    continue;
                }
                let half = Arc::new(StdMutex::new(UdpVtHalf::new()));
                conns.lock().unwrap_or_else(|e| e.into_inner()).insert(
                    addr,
                    UdpAcceptedConn {
                        conn_id: header.conn_id,
                        half: half.clone(),
                    },
                );
                let stream_socket = socket.clone();
                let send_wake = Arc::new(Notify::new());
                tokio::spawn(run_udp_sender(
                    stream_socket,
                    addr,
                    header.conn_id,
                    half.clone(),
                    send_wake.clone(),
                ));
                let stream = UdpVtStream {
                    half,
                    send_wake,
                };
                if accept_tx.send(stream).await.is_err() {
                    return;
                }
            }
            udp_packet_type::DATA => {
                // Route by address, then conn id
                // (`UdpConnection::handle_packet_from_remote`).
                let conns = conns.clone();
                let Some(conn) = conns
                    .lock()
                    .unwrap_or_else(|e| e.into_inner())
                    .get(&addr)
                    .map(|c| (c.conn_id, c.half.clone()))
                else {
                    continue;
                };
                if conn.0 != header.conn_id {
                    continue;
                }
                let mut half = conn.1.lock().unwrap_or_else(|e| e.into_inner());
                half.push_datagram(body);
                drop(half);
                wake_udp_half(&conn.1);
            }
            // Fin/HolePunch/V4/V6HolePunch/Invalid: ignored (the punch
            // forwards live behind the hole-punch connector, not the
            // plain listener port).
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// The QUIC peer transport (easytier-core/src/tunnel/quic.rs, v2.6.4)
// ---------------------------------------------------------------------------
//
// A `quic://host:port` peer URI rides **one QUIC connection per peer
// connection**: the client `connect`s with the server name `localhost`
// (QuicTunnelConnector::connect, quic.rs:583, `endpoint.connect(addr,
// "localhost")`), opens EXACTLY ONE bidirectional stream (`open_bi`,
// quic.rs:587-590), and the plain TCP framing of M1 — `[u32 LE body_len]
// [PeerManagerHeader][payload]` — rides that stream untouched
// (`FramedReader::new_with_associate_data(r, 4500, ...)` +
// `FramedWriter::new_with_associate_data(w, ...)`, quic.rs:606-608). The
// listener is the mirror: accept the connection, `accept_bi`
// (quic.rs:482-493 — the CLIENT opens the stream, the server waits for
// it), wrap the pair with the same framing (max packet size 2000
// server-side, quic.rs:509). Dropping the tunnel closes the connection
// with error code 0 / reason `done` (`ConnWrapper::drop`, quic.rs:461-465).
//
// **The crypto is the special part**: easytier's QUIC is NOT TLS. Both
// `server_config()` and `client_config()` (quic.rs:41-51) are built on
// the `quinn-plaintext` crate (easytier Cargo.toml:84, quinn-plaintext
// 0.3.0) — a quinn crypto provider with NO encryption and NO header
// protection whose only wire presence is an 8-byte **SeaHash checksum
// tag** appended to every packet (`PlaintextPacketKey`, tag_len 8):
//
// * the tag = SeaHash (seahash 4.1.0, default seeds) of
//   `Hash for [u8]`-hashed header then payload — i.e. per member
//   `write_usize(len)` followed by `write(bytes)` (std's slice Hash
//   writes the length prefix first), digest big-endian in the last 8
//   bytes of the datagram;
// * the QUIC transport parameters are exchanged as the CRYPTO-stream
//   content directly (`PlaintextSession::write_handshake` /
//   `read_handshake`: `TransportParameters::write` / `::read` — no
//   TLS records at all), Initial keys are the same plaintext keys as
//   1-RTT keys, and `next_1rtt_keys` hands out fresh plaintext keys
//   forever (quinn-plaintext src/lib.rs:38-341).
//
// The engine cannot take the crate (no new dependencies), so the provider
// is re-implemented in-tree below ([`quic_plaintext`]) after the crate's
// published source (MIT OR Apache-2.0,
// quinn-plaintext-0.3.0/src/lib.rs), against the engine's quinn-proto
// 0.11.18 trait surface — the same seam the engine's own TLS 1.3 QUIC
// stack implements (`quic::tls13`). The transport settings mirror
// `transport_config` (quic.rs:26-39): 255 concurrent bidi streams, NO
// uni streams, 5s keep-alive, `initial_mtu(1200)`/`min_mtu(1200)`,
// segmentation offload, and the BBR congestion controller.
//
// DELTA vs upstream: `QuicEndpointManager`'s process-global endpoint
// pools (quic.rs:222-455, one shared client endpoint per IP family,
// stopped-endpoint recycling) are collapsed into one endpoint per dial
// and one per listener — a fresh `0.0.0.0:0`/`[::]:0` bind per
// connection, no pooling. On the wire both are QUIC v1 endpoints; only
// local socket usage differs.

/// The in-tree `quinn-plaintext` port: the null QUIC crypto easytier's
/// `quic://` tunnel speaks (quinn-plaintext-0.3.0/src/lib.rs, cited per
/// item). Wire-visible behaviour only — the SeaHash tag and the
/// transport-parameter CRYPTO choreography — is load-bearing; the rest
/// is the quinn `crypto` trait plumbing.
mod quic_plaintext {
    use std::any::Any;
    use std::sync::Arc;
    use std::time::Duration;

    use bytes::BytesMut;

    use quinn_proto::crypto::{
        ClientConfig as QuinnClientConfig, CryptoError, ExportKeyingMaterialError, HeaderKey,
        KeyPair, Keys, PacketKey, ServerConfig as QuinnServerConfig, Session,
    };
    use quinn_proto::congestion::BbrConfig;
    use quinn_proto::transport_parameters::TransportParameters;
    use quinn_proto::{ConnectError, Side, TransportError};

    // -- SeaHash (seahash-4.1.0 src/stream.rs + src/helper.rs) ------------
    //
    // The streaming hash whose digest is every packet's integrity tag.
    // Implemented byte-at-a-time (gather 8 LE bytes into `tail`, push),
    // which is mathematically identical to the crate's block-unrolled
    // `push_bytes` — the reference test `chunked_equiv` asserts exactly
    // this streaming equivalence — and verified against digests produced
    // by the real crate (see `quic_plaintext_seahash_reference_vectors`).

    /// `diffuse` (helper.rs:79-92): the PCG-round bijection.
    fn diffuse(mut x: u64) -> u64 {
        x = x.wrapping_mul(0x6eed0e9da4d94a4f);
        let a = x >> 32;
        let b = x >> 60;
        x ^= a >> b;
        x.wrapping_mul(0x6eed0e9da4d94a4f)
    }

    /// The streaming SeaHasher (`SeaHasher::default` seeds, stream.rs:19-28).
    struct SeaHasher {
        state: [u64; 4],
        written: u64,
        tail: u64,
        ntail: usize,
    }

    impl SeaHasher {
        fn new() -> Self {
            SeaHasher {
                state: [
                    0x16f11fe89b0d677c,
                    0xb480a793d8e6c86c,
                    0x6fe2e5aaf078ebc9,
                    0x14f994a4c5259381,
                ],
                written: 0,
                tail: 0,
                ntail: 0,
            }
        }

        /// `SeaHasher::push` (stream.rs:48-56).
        fn push(&mut self, x: u64) {
            let a = diffuse(self.state[0] ^ x);
            self.state[0] = self.state[1];
            self.state[1] = self.state[2];
            self.state[2] = self.state[3];
            self.state[3] = a;
            self.written += 8;
        }

        /// `Hasher::write` (stream.rs:178-180).
        fn write(&mut self, bytes: &[u8]) {
            for &b in bytes {
                self.tail |= (b as u64) << (8 * self.ntail);
                self.ntail += 1;
                if self.ntail == 8 {
                    let x = self.tail;
                    self.push(x);
                    self.tail = 0;
                    self.ntail = 0;
                }
            }
        }

        /// `Hasher::write_usize` (stream.rs:198-200): 8 LE bytes on
        /// 64-bit — what std's `write_length_prefix` default emits, i.e.
        /// the length prefix of `Hash for [u8]`.
        fn write_usize(&mut self, n: usize) {
            self.write(&(n as u64).to_le_bytes());
        }

        /// `Hasher::finish` (stream.rs:166-176): note the reference's
        /// `a ^ ... ^ written + ntail` parses as `^ (written + ntail)`.
        fn finish(&self) -> u64 {
            let a = if self.ntail > 0 {
                diffuse(self.state[0] ^ self.tail)
            } else {
                self.state[0]
            };
            diffuse(a ^ self.state[1] ^ self.state[2] ^ self.state[3] ^ (self.written + self.ntail as u64))
        }
    }

    /// The packet integrity tag: `SeaHasher` over the `Hash for [u8]`
    /// sequence of header then payload (`PlaintextPacketKey::encrypt`,
    /// quinn-plaintext src/lib.rs:281-297 — `header.hash(&mut hasher);
    /// payload.hash(&mut hasher)`).
    pub(super) fn packet_tag(header: &[u8], payload: &[u8]) -> u64 {
        let mut hasher = SeaHasher::new();
        hasher.write_usize(header.len());
        hasher.write(header);
        hasher.write_usize(payload.len());
        hasher.write(payload);
        hasher.finish()
    }

    /// `PlaintextHeaderKey` (quinn-plaintext src/lib.rs:38-65): no header
    /// protection at all.
    struct PlaintextHeaderKey;

    impl HeaderKey for PlaintextHeaderKey {
        fn decrypt(&self, _pn_offset: usize, _packet: &mut [u8]) {}
        fn encrypt(&self, _pn_offset: usize, _packet: &mut [u8]) {}
        fn sample_size(&self) -> usize {
            0
        }
    }

    /// `PlaintextPacketKey` (quinn-plaintext src/lib.rs:280-341): the
    /// 8-byte SeaHash tag, nothing else.
    pub(super) struct PlaintextPacketKey;

    impl PacketKey for PlaintextPacketKey {
        fn encrypt(&self, _packet: u64, buf: &mut [u8], header_len: usize) {
            let (header, payload_tag) = buf.split_at_mut(header_len);
            let (payload, tag_storage) = payload_tag.split_at_mut(payload_tag.len() - self.tag_len());
            let checksum = packet_tag(header, payload);
            tag_storage.copy_from_slice(&checksum.to_be_bytes());
        }

        fn decrypt(
            &self,
            _packet: u64,
            header: &[u8],
            payload: &mut BytesMut,
        ) -> Result<(), CryptoError> {
            let tag_start = payload
                .len()
                .checked_sub(self.tag_len())
                .ok_or(CryptoError)?;
            let tag_storage = payload.split_off(tag_start);
            let expected =
                u64::from_be_bytes(tag_storage.as_ref().try_into().map_err(|_| CryptoError)?);
            let checksum = packet_tag(header, payload);
            if checksum != expected {
                return Err(CryptoError);
            }
            Ok(())
        }

        fn tag_len(&self) -> usize {
            8
        }

        fn confidentiality_limit(&self) -> u64 {
            u64::MAX
        }

        fn integrity_limit(&self) -> u64 {
            1 << 36
        }
    }

    fn header_keypair() -> KeyPair<Box<dyn HeaderKey>> {
        KeyPair {
            local: Box::new(PlaintextHeaderKey),
            remote: Box::new(PlaintextHeaderKey),
        }
    }

    fn packet_keypair() -> KeyPair<Box<dyn PacketKey>> {
        KeyPair {
            local: Box::new(PlaintextPacketKey),
            remote: Box::new(PlaintextPacketKey),
        }
    }

    /// `crypto_keys` (quinn-plaintext src/lib.rs:95-100): identical
    /// plaintext keys for every packet space and both directions.
    fn crypto_keys() -> Keys {
        Keys {
            header: header_keypair(),
            packet: packet_keypair(),
        }
    }

    /// `PlaintextSession` (quinn-plaintext src/lib.rs:117-240): the QUIC
    /// transport parameters ARE the handshake — written to / read from
    /// the CRYPTO stream verbatim, with two key-phase transitions
    /// (initial keys, then handshake keys) that carry the same plaintext
    /// keys.
    struct PlaintextSession {
        side: Side,
        params: TransportParameters,
        peer_params: Option<TransportParameters>,
        wrote_transporter_params: bool,
        initial_keys: Option<Keys>,
        handshake_keys: Option<Keys>,
    }

    impl PlaintextSession {
        fn new(side: Side, params: TransportParameters) -> Self {
            PlaintextSession {
                side,
                params,
                peer_params: None,
                wrote_transporter_params: false,
                initial_keys: Some(crypto_keys()),
                handshake_keys: Some(crypto_keys()),
            }
        }
    }

    impl Session for PlaintextSession {
        fn initial_keys(&self, _dst_cid: &quinn_proto::ConnectionId, _side: Side) -> Keys {
            crypto_keys()
        }

        fn handshake_data(&self) -> Option<Box<dyn Any>> {
            self.peer_params.map(|tp| Box::new(tp) as Box<dyn Any>)
        }

        fn peer_identity(&self) -> Option<Box<dyn Any>> {
            None
        }

        fn early_crypto(&self) -> Option<(Box<dyn HeaderKey>, Box<dyn PacketKey>)> {
            None
        }

        fn early_data_accepted(&self) -> Option<bool> {
            Some(false)
        }

        /// `is_handshaking` (lib.rs:167-172): until the peer's parameters
        /// arrived AND our own were written AND both key phases were
        /// handed over.
        fn is_handshaking(&self) -> bool {
            self.peer_params.is_none()
                || !self.wrote_transporter_params
                    && (self.initial_keys.is_some() || self.handshake_keys.is_some())
        }

        fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
            if self.peer_params.is_none() {
                let mut cursor = buf;
                self.peer_params = Some(
                    TransportParameters::read(self.side, &mut cursor).map_err(|e| {
                        TransportError {
                            code: quinn_proto::TransportErrorCode::crypto(0x28),
                            frame: None,
                            reason: format!("easytier quic: bad transport parameters: {e}"),
                        }
                    })?,
                );
            }
            Ok(true)
        }

        fn transport_parameters(&self) -> Result<Option<TransportParameters>, TransportError> {
            Ok(self.peer_params)
        }

        /// `write_handshake` (lib.rs:193-219): the client emits its
        /// parameters on the FIRST call (Initial space) and returns the
        /// initial keys; the second call returns the handshake keys. The
        /// server writes its parameters when the handshake keys are taken
        /// (its first flight has nothing to send — it answers).
        fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<Keys> {
            if self.side.is_client() && !self.wrote_transporter_params {
                self.params.write(buf);
                self.wrote_transporter_params = true;
            }
            match self.initial_keys.take() {
                Some(k) => Some(k),
                None => match self.handshake_keys.take() {
                    Some(k) => {
                        if self.side.is_server() && !self.wrote_transporter_params {
                            self.params.write(buf);
                            self.wrote_transporter_params = true;
                        }
                        Some(k)
                    }
                    None => None,
                },
            }
        }

        fn next_1rtt_keys(&mut self) -> Option<KeyPair<Box<dyn PacketKey>>> {
            Some(packet_keypair())
        }

        fn is_valid_retry(
            &self,
            _orig_dst_cid: &quinn_proto::ConnectionId,
            _header: &[u8],
            _payload: &[u8],
        ) -> bool {
            // The listener never issues retries (ServerConfig default),
            // so nothing to verify.
            true
        }

        fn export_keying_material(
            &self,
            _output: &mut [u8],
            _label: &[u8],
            _context: &[u8],
        ) -> Result<(), ExportKeyingMaterialError> {
            Ok(())
        }
    }

    /// `PlaintextClientConfig` (lib.rs:242-252).
    #[derive(Default)]
    struct PlaintextClientConfig;

    impl QuinnClientConfig for PlaintextClientConfig {
        fn start_session(
            self: Arc<Self>,
            _version: u32,
            _server_name: &str,
            params: &TransportParameters,
        ) -> Result<Box<dyn Session>, ConnectError> {
            Ok(Box::new(PlaintextSession::new(Side::Client, *params)))
        }
    }

    /// `PlaintextServerConfig` (lib.rs:254-278).
    #[derive(Default)]
    struct PlaintextServerConfig;

    impl QuinnServerConfig for PlaintextServerConfig {
        fn initial_keys(
            &self,
            _version: u32,
            _dst_cid: &quinn_proto::ConnectionId,
        ) -> Result<Keys, quinn_proto::crypto::UnsupportedVersion> {
            Ok(crypto_keys())
        }

        fn retry_tag(&self, _version: u32, _orig_dst_cid: &quinn_proto::ConnectionId, _packet: &[u8]) -> [u8; 16] {
            [0u8; 16]
        }

        fn start_session(
            self: Arc<Self>,
            _version: u32,
            params: &TransportParameters,
        ) -> Box<dyn Session> {
            Box::new(PlaintextSession::new(Side::Server, *params))
        }
    }

    // -- The easytier configs on top (tunnel/quic.rs:26-57) ---------------

    /// `transport_config` (quic.rs:26-39).
    fn transport_config() -> Arc<quinn::TransportConfig> {
        let mut config = quinn::TransportConfig::default();
        config
            .max_concurrent_bidi_streams(u8::MAX.into())
            .max_concurrent_uni_streams(0u8.into())
            .keep_alive_interval(Some(Duration::from_secs(5)))
            .initial_mtu(1200)
            .min_mtu(1200)
            .enable_segmentation_offload(true)
            .congestion_controller_factory(Arc::new(BbrConfig::default()));
        Arc::new(config)
    }

    /// `server_config` (quic.rs:41-45).
    pub(super) fn server_config() -> quinn::ServerConfig {
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(PlaintextServerConfig));
        config.transport_config(transport_config());
        config
    }

    /// `client_config` (quic.rs:47-51).
    pub(super) fn client_config() -> quinn::ClientConfig {
        let mut config = quinn::ClientConfig::new(Arc::new(PlaintextClientConfig));
        config.transport_config(transport_config());
        config
    }

    /// `endpoint_config` (quic.rs:53-57).
    pub(super) fn endpoint_config() -> quinn::EndpointConfig {
        let mut config = quinn::EndpointConfig::default();
        config.max_udp_payload_size(1200).unwrap();
        config
    }
}

/// One `quic://` peer tunnel stream: the single bi-stream of one QUIC
/// connection plus the connection itself (kept alive for the stream's
/// lifetime; dropped streams close it with code 0 / `done`, the
/// `ConnWrapper` of quic.rs:457-465).
pub struct EtQuicStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    conn: Option<quinn::Connection>,
}

impl EtQuicStream {
    fn pair(send: quinn::SendStream, recv: quinn::RecvStream, conn: quinn::Connection) -> Self {
        EtQuicStream {
            send,
            recv,
            conn: Some(conn),
        }
    }
}

impl Drop for EtQuicStream {
    fn drop(&mut self) {
        if let Some(conn) = self.conn.take() {
            conn.close(0u32.into(), b"done");
        }
    }
}

impl AsyncRead for EtQuicStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        AsyncRead::poll_read(Pin::new(&mut self.recv), cx, buf)
    }
}

impl AsyncWrite for EtQuicStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

/// The quinn endpoint boot shared by both roles: a bound UDP socket
/// wrapped by the tokio runtime's UDP stack (upstream:
/// `QuicEndpointManager::try_create`, quic.rs:233-249).
fn quic_endpoint(
    bind: SocketAddr,
    server: Option<quinn::ServerConfig>,
) -> Result<quinn::Endpoint> {
    let socket = std::net::UdpSocket::bind(bind)
        .map_err(|e| Error::network(format!("easytier: quic bind {bind}: {e}")))?;
    let runtime = quinn::default_runtime()
        .ok_or_else(|| Error::network("easytier: quic: no async runtime found"))?;
    let wrapped = runtime
        .wrap_udp_socket(socket)
        .map_err(|e| Error::network(format!("easytier: quic socket: {e}")))?;
    quinn::Endpoint::new_with_abstract_socket(
        quic_plaintext::endpoint_config(),
        server,
        wrapped,
        runtime,
    )
    .map_err(|e| Error::network(format!("easytier: quic endpoint: {e}")))
}

/// `QuicTunnelConnector::connect` (quic.rs:578-610): connect with the
/// server name `localhost`, open the one bi-stream, return it under the
/// M1 framing. The caller owns the 3s direct-connect budget.
pub async fn connect_quic_tunnel(addr: SocketAddr) -> Result<EtQuicStream> {
    let bind = if addr.is_ipv6() {
        SocketAddr::from(([0u8; 16], 0))
    } else {
        SocketAddr::from(([0, 0, 0, 0], 0))
    };
    let mut endpoint = quic_endpoint(bind, None)?;
    endpoint.set_default_client_config(quic_plaintext::client_config());
    let connecting = endpoint
        .connect(addr, "localhost")
        .map_err(|e| Error::network(format!("easytier: quic connect to {addr}: {e}")))?;
    let conn = connecting
        .await
        .map_err(|e| Error::network(format!("easytier: quic connect to {addr}: {e}")))?;
    let (send, recv) = conn
        .open_bi()
        .await
        .map_err(|e| Error::network(format!("easytier: quic open_bi: {e}")))?;
    Ok(EtQuicStream::pair(send, recv, conn))
}

/// `QuicTunnelListener` (quic.rs:467-556): a bound QUIC endpoint whose
/// `accept` completes a connection and takes the client's first
/// bi-stream.
pub struct QuicVtListener {
    endpoint: quinn::Endpoint,
    local: SocketAddr,
}

impl QuicVtListener {
    /// `QuicTunnelListener::listen` (quic.rs:530-539).
    pub fn bind(addr: SocketAddr) -> Result<Self> {
        let endpoint = quic_endpoint(addr, Some(quic_plaintext::server_config()))?;
        let local = endpoint
            .local_addr()
            .map_err(|e| Error::network(format!("easytier: quic local addr: {e}")))?;
        Ok(QuicVtListener { endpoint, local })
    }

    /// The bound address (port 0 resolves, `local_url`, quic.rs:553-556).
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// `QuicTunnelListener::accept` (quic.rs:482-551): accept, await the
    /// connection, take the client-opened bi-stream; a failed inbound
    /// retries after 1ms instead of failing the listener.
    pub async fn accept(&mut self) -> Result<EtQuicStream> {
        loop {
            let incoming = match self.endpoint.accept().await {
                Some(incoming) => incoming,
                None => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    continue;
                }
            };
            let conn = match incoming.await {
                Ok(conn) => conn,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    continue;
                }
            };
            match conn.accept_bi().await {
                Ok((send, recv)) => return Ok(EtQuicStream::pair(send, recv, conn)),
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    continue;
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// The WebSocket peer transport (easytier-core/src/tunnel/websocket.rs, v2.6.4)
// ---------------------------------------------------------------------------
//
// A `ws://`/`wss://` peer URI is the SAME peer protocol over a WebSocket:
// the connector dials TCP (`TcpSocket::connect` + nodelay,
// websocket.rs:217-225), optionally wraps it in TLS for `wss` — an
// INSECURE rustls client config with SNI `localhost` when the URI has no
// domain (`get_insecure_tls_client_config` + the SNI comment,
// websocket.rs:244-256) — then runs the RFC 6455 client upgrade
// (`ClientBuilder::from_uri` of the `ws://` URI: `GET <path> HTTP/1.1`
// with Host/Upgrade/Connection/Sec-WebSocket-Key/Sec-WebSocket-Version,
// websocket.rs:243,261) and maps the stream: **every WebSocket BINARY
// message is one tunnel payload** — `[PeerManagerHeader][payload]` with
// NO length prefix, because the message is self-delimiting
// (`sink_from_zc_packet` sends `msg.tunnel_payload_bytes()` and
// `map_from_ws_message` re-buffers each binary message as one ZCPacket,
// websocket.rs:36-64). A close message ends the stream; non-binary
// messages are an error; `Limits::unlimited()` server-side
// (websocket.rs:114). The listener is the TCP (or TLS) mirror: upstream
// serves `wss` with a process-global self-signed cert
// (`get_insecure_tls_cert`) and completes the upgrade with the computed
// `Sec-WebSocket-Accept`, then hands the same message mapping to the
// peer manager (websocket.rs:94-158, accept retries after failures with
// a 3s per-accept budget, websocket.rs:177-191).
//
// The engine has no websocket dependency; per the sudoku precedent
// (proto/sudoku.rs `ws_build_frame`/`ws_read_frame` + transport.rs's
// `ws_connect`), the handshake and framing are hand-rolled here. The
// session machinery of M1 speaks the TCP byte framing
// (`[u32][PeerManagerHeader][payload]`, `write_frame`/`read_frame`), so
// [`WsPeerStream`] is the adapter: outgoing it STRIPS the u32 length
// prefix and sends the body as one binary message; incoming it re-adds
// the prefix in front of each message body — the byte stream the peer
// machinery reads is byte-identical to the TCP tunnel while the WIRE
// carries upstream's message mapping.
//
// DELTA vs upstream: the `Forwarded`/`X-Forwarded-For` remote-address
// rewrite for trusted proxies (websocket.rs:66-78, 118-141 — TunnelInfo
// bookkeeping only, nothing on the peer wire) is not carried; the wss
// certificate is generated once per process (upstream's global
// `LazyLock` cert) but roles and ciphers are identical.

/// The largest inbound WS message accepted (upstream: `Limits::unlimited()`
/// on the listener; a peer frame never legitimately exceeds the ~2 KB
/// packet budget, so 1 MiB is generous headroom against garbage).
const WS_MAX_MESSAGE: usize = 1 << 20;

/// RFC 6455 opcodes this transport cares about.
const WS_OP_CONT: u8 = 0x0;
const WS_OP_TEXT: u8 = 0x1;
const WS_OP_BINARY: u8 = 0x2;
const WS_OP_CLOSE: u8 = 0x8;
const WS_OP_PING: u8 = 0x9;
const WS_OP_PONG: u8 = 0xa;
/// The RFC 6455 GUID folded into `Sec-WebSocket-Accept`.
const WS_GUID: &[u8] = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

/// `Sec-WebSocket-Accept` = base64(SHA-1(key || GUID)) (RFC 6455 §4.2.2).
fn ws_accept_key(key: &str) -> String {
    use base64::Engine as _;
    use sha1::{Digest as _, Sha1};
    let mut h = Sha1::new();
    h.update(key.as_bytes());
    h.update(WS_GUID);
    base64::engine::general_purpose::STANDARD.encode(h.finalize())
}

/// Read one CRLF-terminated HTTP/1.1 head (up to the blank line) from a
/// fresh stream, bounded by `cap` bytes.
async fn ws_read_http_head<S>(io: &mut S, cap: usize) -> Result<String>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        match io.read(&mut byte).await {
            Ok(0) => break,
            Ok(_) => {
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    buf.truncate(buf.len() - 4);
                    break;
                }
                if buf.len() > cap {
                    return Err(Error::protocol("easytier: ws handshake head too long"));
                }
            }
            Err(e) => return Err(e.into()),
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Case-insensitive header lookup over a parsed head.
fn ws_header<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.split("\r\n").find_map(|line| {
        let (k, v) = line.split_once(':')?;
        k.trim()
            .eq_ignore_ascii_case(name)
            .then(|| v.trim())
    })
}

/// Serialize one RFC 6455 frame; `mask` per the client role (clients mask,
/// servers do not). Mirrors the engine's sudoku/transport.rs builders.
fn ws_frame(opcode: u8, payload: &[u8], mask: bool) -> Vec<u8> {
    let mut frame = Vec::with_capacity(payload.len() + 14);
    frame.push(0x80 | opcode); // FIN + opcode (easytier never fragments)
    match payload.len() {
        n if n < 126 => frame.push(if mask { 0x80 | n as u8 } else { n as u8 }),
        n if n <= 0xffff => {
            frame.push(if mask { 0x80 | 126 } else { 126 });
            frame.extend_from_slice(&(n as u16).to_be_bytes());
        }
        n => {
            frame.push(if mask { 0x80 | 127 } else { 127 });
            frame.extend_from_slice(&(n as u64).to_be_bytes());
        }
    }
    if mask {
        let mask = rand::random::<u32>().to_le_bytes();
        frame.extend_from_slice(&mask);
        for (i, b) in payload.iter().enumerate() {
            frame.push(b ^ mask[i % 4]);
        }
    } else {
        frame.extend_from_slice(payload);
    }
    frame
}

/// One parsed inbound frame (both maskings accepted, RFC §5.1 enforced
/// only on our own client).
struct WsParsedFrame {
    fin: bool,
    opcode: u8,
    payload: Vec<u8>,
    /// Bytes consumed from the front of `buf`.
    used: usize,
}

/// Try to parse one frame off the front of `buf`.
fn ws_parse_frame(buf: &[u8]) -> Result<Option<WsParsedFrame>> {
    if buf.len() < 2 {
        return Ok(None);
    }
    let b0 = buf[0];
    let b1 = buf[1];
    if b0 & 0x70 != 0 {
        return Err(Error::protocol("easytier: ws frame with RSV bits"));
    }
    let fin = b0 & 0x80 != 0;
    let opcode = b0 & 0x0f;
    let masked = b1 & 0x80 != 0;
    let mut off = 2usize;
    let len = match b1 & 0x7f {
        126 => {
            if buf.len() < 4 {
                return Ok(None);
            }
            off = 4;
            u16::from_be_bytes([buf[2], buf[3]]) as usize
        }
        127 => {
            if buf.len() < 10 {
                return Ok(None);
            }
            let mut b = [0u8; 8];
            b.copy_from_slice(&buf[2..10]);
            off = 10;
            u64::from_be_bytes(b) as usize
        }
        n => n as usize,
    };
    if len > WS_MAX_MESSAGE {
        return Err(Error::protocol("easytier: ws message too long"));
    }
    let mask_len = if masked { 4 } else { 0 };
    let total = off + mask_len + len;
    if buf.len() < total {
        return Ok(None);
    }
    let mask = if masked {
        let mut m = [0u8; 4];
        m.copy_from_slice(&buf[off..off + 4]);
        m
    } else {
        [0u8; 4]
    };
    let mut payload = buf[off + mask_len..total].to_vec();
    if masked {
        for (i, b) in payload.iter_mut().enumerate() {
            *b ^= mask[i % 4];
        }
    }
    Ok(Some(WsParsedFrame {
        fin,
        opcode,
        payload,
        used: total,
    }))
}

/// The WS peer stream: the engine-side byte framing in, RFC 6455 binary
/// messages out (and the reverse on read). See the section header for
/// the mapping.
pub struct WsPeerStream {
    io: BoxProxyStream,
    /// The client role masks its frames (RFC 6455 §5.1).
    client: bool,
    // Receive side: raw socket bytes → frames → assembled messages →
    // the reconstructed [u32 len][body] byte stream.
    rbuf: Vec<u8>,
    pending: Vec<u8>,
    pending_pos: usize,
    msg_buf: Vec<u8>,
    eof: bool,
    // Send side.
    tx_buf: Vec<u8>,
    tx_pos: usize,
    /// The plain length the in-flight `tx_buf` frame stands for (what
    /// `poll_write` must report once the frame is handed off).
    tx_plain: usize,
    ctrl: Vec<u8>,
    /// How much of `ctrl` already reached the socket (control-frame
    /// writes may interleave with pending data-frame writes).
    ctrl_pos: usize,
    closed: bool,
}

impl WsPeerStream {
    fn new(io: BoxProxyStream, client: bool) -> Self {
        WsPeerStream {
            io,
            client,
            rbuf: Vec::new(),
            pending: Vec::new(),
            pending_pos: 0,
            msg_buf: Vec::new(),
            eof: false,
            tx_buf: Vec::new(),
            tx_pos: 0,
            tx_plain: 0,
            ctrl: Vec::new(),
            ctrl_pos: 0,
            closed: false,
        }
    }

    /// Read-side: fold one newly completed message into `pending`,
    /// re-adding the u32 length prefix the WS mapping drops.
    fn message_done(&mut self) {
        let mut framed = Vec::with_capacity(4 + self.msg_buf.len());
        framed.extend_from_slice(&(self.msg_buf.len() as u32).to_le_bytes());
        framed.append(&mut self.msg_buf);
        self.pending = framed;
        self.pending_pos = 0;
    }

    /// Build the outgoing frame for `buf`, stripping the u32 length
    /// prefix when `buf` is exactly one engine frame (always the case
    /// from `write_frame`'s `write_all`).
    fn outgoing_frame(&self, buf: &[u8]) -> Vec<u8> {
        let body = if buf.len() >= 4 {
            let declared = u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
            if declared + 4 == buf.len() {
                &buf[4..]
            } else {
                buf
            }
        } else {
            buf
        };
        ws_frame(WS_OP_BINARY, body, self.client)
    }

    /// Push as much of the buffer at `pos` through the socket as it
    /// accepts right now.
    fn pump_write(
        io: &mut BoxProxyStream,
        buf: &mut [u8],
        pos: &mut usize,
        cx: &mut Context<'_>,
    ) -> Poll<io::Result<usize>> {
        while *pos < buf.len() {
            match Pin::new(&mut **io).poll_write(cx, &buf[*pos..]) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "easytier: ws transport accepted zero bytes",
                    )))
                }
                Poll::Ready(Ok(n)) => *pos += n,
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        Poll::Ready(Ok(0))
    }

    /// Flush the queued control frames; `Ok(true)` when the queue is
    /// fully drained (`ctrl_pos` keeps the progress across Pending).
    fn pump_ctrl(&mut self, cx: &mut Context<'_>) -> io::Result<bool> {
        let mut pos = self.ctrl_pos;
        match Self::pump_write(&mut self.io, &mut self.ctrl, &mut pos, cx) {
            Poll::Ready(Ok(_)) => {
                self.ctrl.clear();
                self.ctrl_pos = 0;
                Ok(true)
            }
            Poll::Ready(Err(e)) => Err(e),
            Poll::Pending => {
                self.ctrl_pos = pos;
                Ok(false)
            }
        }
    }
}

impl AsyncRead for WsPeerStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        loop {
            // Serve the reconstructed byte stream first.
            if this.pending_pos < this.pending.len() {
                let n = (this.pending.len() - this.pending_pos).min(buf.remaining());
                buf.put_slice(&this.pending[this.pending_pos..this.pending_pos + n]);
                this.pending_pos += n;
                return Poll::Ready(Ok(()));
            }
            if this.eof {
                return Poll::Ready(Ok(()));
            }
            if buf.remaining() == 0 {
                return Poll::Ready(Ok(()));
            }
            // Opportunistically flush queued control frames.
            if !this.ctrl.is_empty() {
                if let Err(e) = this.pump_ctrl(cx) {
                    return Poll::Ready(Err(e));
                }
            }
            match ws_parse_frame(&this.rbuf).map_err(ws_io_err)? {
                Some(frame) => {
                    this.rbuf.drain(..frame.used);
                    match frame.opcode {
                        WS_OP_BINARY | WS_OP_TEXT | WS_OP_CONT => {
                            this.msg_buf.extend_from_slice(&frame.payload);
                            if frame.fin {
                                if frame.opcode == WS_OP_TEXT {
                                    // `map_from_ws_message`: only binary
                                    // messages are peer packets.
                                    return Poll::Ready(Err(ws_io_err(Error::protocol(
                                        "easytier: ws: non-binary message",
                                    ))));
                                }
                                this.message_done();
                            }
                        }
                        WS_OP_PING => {
                            this.ctrl
                                .extend_from_slice(&ws_frame(WS_OP_PONG, &frame.payload, this.client));
                        }
                        WS_OP_PONG => {}
                        WS_OP_CLOSE => {
                            // `recv close message from websocket` ends the
                            // stream (websocket.rs:49-52).
                            if !this.closed {
                                this.closed = true;
                                this.ctrl
                                    .extend_from_slice(&ws_frame(WS_OP_CLOSE, &frame.payload, this.client));
                            }
                            this.eof = true;
                        }
                        _ => {}
                    }
                    continue;
                }
                None => {
                    let mut tmp = [0u8; 16 * 1024];
                    let mut rb = ReadBuf::new(&mut tmp);
                    match Pin::new(&mut this.io).poll_read(cx, &mut rb) {
                        Poll::Ready(Ok(())) => {
                            if rb.filled().is_empty() {
                                this.eof = true;
                                return Poll::Ready(Ok(()));
                            }
                            this.rbuf.extend_from_slice(rb.filled());
                        }
                        Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                        Poll::Pending => return Poll::Pending,
                    }
                }
            }
        }
    }
}

impl AsyncWrite for WsPeerStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.closed || this.eof {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionAborted,
                "easytier: ws tunnel closed",
            )));
        }
        // Finish the in-flight frame first (`write_all` re-polls with the
        // same slice until its full plain length is acknowledged).
        if this.tx_pos < this.tx_buf.len() {
            match Self::pump_write(&mut this.io, &mut this.tx_buf, &mut this.tx_pos, cx) {
                Poll::Ready(Ok(_)) => {
                    let n = this.tx_plain;
                    this.tx_buf.clear();
                    this.tx_pos = 0;
                    this.tx_plain = 0;
                    return Poll::Ready(Ok(n));
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }
        // Queued control frames go out before the next data frame.
        if !this.ctrl.is_empty() {
            match this.pump_ctrl(cx) {
                Ok(true) => {}
                Ok(false) => return Poll::Pending,
                Err(e) => return Poll::Ready(Err(e)),
            }
        }
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        this.tx_buf = this.outgoing_frame(buf);
        this.tx_pos = 0;
        this.tx_plain = buf.len();
        match Self::pump_write(&mut this.io, &mut this.tx_buf, &mut this.tx_pos, cx) {
            Poll::Ready(Ok(_)) => {
                let n = this.tx_plain;
                this.tx_buf.clear();
                this.tx_pos = 0;
                this.tx_plain = 0;
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        while this.tx_pos < this.tx_buf.len() || this.ctrl_pos < this.ctrl.len() {
            if this.tx_pos < this.tx_buf.len() {
                match Self::pump_write(&mut this.io, &mut this.tx_buf, &mut this.tx_pos, cx) {
                    Poll::Ready(Ok(_)) => {
                        this.tx_buf.clear();
                        this.tx_pos = 0;
                        this.tx_plain = 0;
                    }
                    other => return other.map(|r| r.map(|_| ())),
                }
            }
            if this.ctrl_pos < this.ctrl.len() {
                match this.pump_ctrl(cx) {
                    Ok(_) => {}
                    Err(e) => return Poll::Ready(Err(e)),
                }
            }
        }
        Pin::new(&mut this.io).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if !this.closed {
            this.closed = true;
            let frame = ws_frame(WS_OP_CLOSE, &1000u16.to_be_bytes(), this.client);
            this.ctrl.extend_from_slice(&frame);
        }
        // Best-effort close frame, then the transport shutdown.
        match this.pump_ctrl(cx) {
            Ok(true) => Pin::new(&mut this.io).poll_shutdown(cx),
            Ok(false) => Poll::Pending,
            Err(_) => Pin::new(&mut this.io).poll_shutdown(cx),
        }
    }
}

fn ws_io_err(e: Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e.to_string())
}

/// `WsTunnelConnector::connect` (websocket.rs:198-266): TCP connect,
/// optional insecure TLS for `wss` (SNI = the URI's domain, else
/// `localhost`), then the client upgrade. The caller owns the connect
/// budget.
pub async fn connect_ws_tunnel(endpoint: &PeerEndpoint) -> Result<WsPeerStream> {
    let addr = resolve_peer_addr(endpoint).await?;
    let stream = tokio::net::TcpStream::connect(addr)
        .await
        .map_err(|e| Error::network(format!("easytier: ws connect {addr}: {e}")))?;
    let _ = stream.set_nodelay(true);
    let mut io: BoxProxyStream = Box::new(stream);
    if endpoint.transport == PeerTransport::Wss {
        let sni = if endpoint.host.parse::<std::net::IpAddr>().is_ok() {
            // "use localhost as SNI for url without domain" (websocket.rs:248-252)
            "localhost".to_owned()
        } else {
            endpoint.host.clone()
        };
        let settings = crate::transport::TlsSettings {
            enabled: true,
            server_name: None,
            skip_cert_verify: true,
            alpn: Vec::new(),
        };
        io = crate::transport::tls_connect(io, &sni, &settings).await?;
    }
    // The upgrade (ClientBuilder::from_uri over the ws:// URI — the easytier
    // peer URI carries no path, so `GET /`).
    use base64::Engine as _;
    let mut key_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key_bytes);
    let key = base64::engine::general_purpose::STANDARD.encode(key_bytes);
    let host_header = format!("{}:{}", endpoint.host, endpoint.port);
    let req = format!(
        "GET / HTTP/1.1\r\nHost: {host_header}\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    );
    io.write_all(req.as_bytes()).await?;
    let head = ws_read_http_head(&mut io, 16 * 1024).await?;
    let status = head
        .split_whitespace()
        .nth(1)
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| Error::protocol(format!("easytier: ws bad status line {head:?}")))?;
    if status != 101 {
        return Err(Error::network(format!(
            "easytier: ws upgrade rejected with {status}"
        )));
    }
    let accept = ws_header(&head, "sec-websocket-accept").unwrap_or_default();
    if accept != ws_accept_key(&key) {
        return Err(Error::protocol("easytier: ws Sec-WebSocket-Accept mismatch"));
    }
    Ok(WsPeerStream::new(io, true))
}

/// The process-global self-signed `wss` server certificate
/// (`get_insecure_tls_cert`, a LazyLock upstream — one key per process).
/// The engine has no cert generator in its library dependencies, so this
/// is the minimal self-signed ECDSA P-256 DER builder of the JLS
/// camouflage path (`proto/jls.rs::generate_camouflage_cert`): random
/// serial + CN, ~8y validity, `ecdsa-with-SHA256`. Nothing verifies it
/// (every easytier `wss` client is insecure by design), so the minimal
/// shape suffices.
static WSS_INSECURE_SERVER: std::sync::OnceLock<Option<Arc<rustls::ServerConfig>>> =
    std::sync::OnceLock::new();

/// One DER TLV (`der_put` of proto/jls.rs).
fn ws_der_put(out: &mut Vec<u8>, tag: u8, body: &[u8]) {
    out.push(tag);
    if body.len() < 0x80 {
        out.push(body.len() as u8);
    } else if body.len() <= 0xff {
        out.push(0x81);
        out.push(body.len() as u8);
    } else {
        out.push(0x82);
        out.push((body.len() >> 8) as u8);
        out.push(body.len() as u8);
    }
    out.extend_from_slice(body);
}

/// One DER UTCTime (Hinnant's civil-from-days, as in proto/jls.rs).
fn ws_der_utctime(unix_secs: i64) -> Vec<u8> {
    let days = unix_secs.div_euclid(86_400);
    let secs = unix_secs.rem_euclid(86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 146_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let (h, mi, s) = (secs / 3600, (secs % 3600) / 60, secs % 60);
    format!("{:02}{m:02}{d:02}{h:02}{mi:02}{s:02}Z", y.rem_euclid(100)).into_bytes()
}

/// Build the (cert, key) pair rustls serves for `wss`.
fn ws_self_signed_pair(
) -> Result<(
    rustls::pki_types::CertificateDer<'static>,
    rustls::pki_types::PrivateKeyDer<'static>,
)> {
    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = ring::signature::EcdsaKeyPair::generate_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        &rng,
    )
    .map_err(|_| Error::crypto("easytier: wss key generation failed"))?;
    let pair = ring::signature::EcdsaKeyPair::from_pkcs8(
        &ring::signature::ECDSA_P256_SHA256_ASN1_SIGNING,
        pkcs8.as_ref(),
        &rng,
    )
    .map_err(|_| Error::crypto("easytier: wss key parse failed"))?;

    // SubjectPublicKeyInfo: ecPublicKey + prime256v1, uncompressed point.
    let mut alg = Vec::new();
    ws_der_put(&mut alg, 0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]);
    ws_der_put(&mut alg, 0x06, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07]);
    let mut alg_id = Vec::new();
    ws_der_put(&mut alg_id, 0x30, &alg);
    let mut spki_bitstring = Vec::new();
    spki_bitstring.push(0x00);
    spki_bitstring.extend_from_slice(ring::signature::KeyPair::public_key(&pair).as_ref());
    let mut spki_body = alg_id;
    let mut bit = Vec::new();
    ws_der_put(&mut bit, 0x03, &spki_bitstring);
    spki_body.extend_from_slice(&bit);
    let mut spki = Vec::new();
    ws_der_put(&mut spki, 0x30, &spki_body);

    // ecdsa-with-SHA256 (1.2.840.10045.4.3.2).
    let mut sig_alg = Vec::new();
    ws_der_put(
        &mut sig_alg,
        0x30,
        &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02],
    );

    // Random CN, positive minimal serial.
    let mut cn_bytes = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut cn_bytes);
    let cn: String = cn_bytes.iter().map(|b| format!("{b:02x}")).collect();
    let mut cn_body = Vec::new();
    ws_der_put(&mut cn_body, 0x0c, cn.as_bytes()); // UTF8String
    let mut rdn = Vec::new();
    ws_der_put(&mut rdn, 0x31, &cn_body); // RDNSequence set
    let mut name = Vec::new();
    ws_der_put(&mut name, 0x30, &rdn);
    let mut serial_bytes = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut serial_bytes);
    let mut serial: Vec<u8> = serial_bytes.to_vec();
    while serial.first() == Some(&0) {
        serial.remove(0);
    }
    if serial.is_empty() || serial[0] & 0x80 != 0 {
        serial.insert(0, 0x00);
    }

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let mut validity = Vec::new();
    ws_der_put(&mut validity, 0x17, &ws_der_utctime(now - 86_400));
    ws_der_put(&mut validity, 0x17, &ws_der_utctime(now + 8 * 365 * 86_400));

    let mut tbs = Vec::with_capacity(512);
    ws_der_put(&mut tbs, 0xa0, &[0x02, 0x01, 0x02]); // v3
    ws_der_put(&mut tbs, 0x02, &serial);
    tbs.extend_from_slice(&sig_alg);
    tbs.extend_from_slice(&name); // issuer (self-signed)
    let mut validity_seq = Vec::new();
    ws_der_put(&mut validity_seq, 0x30, &validity);
    tbs.extend_from_slice(&validity_seq);
    tbs.extend_from_slice(&name); // subject
    tbs.extend_from_slice(&spki);

    let signature = pair
        .sign(&rng, &tbs)
        .map_err(|_| Error::crypto("easytier: wss cert signing failed"))?;
    // Certificate ::= SEQUENCE { tbsCertificate SEQUENCE,
    // signatureAlgorithm, signatureValue BIT STRING } — the TBS gets its
    // own wrapper and the signature covers exactly its content.
    let mut tbs_seq = Vec::with_capacity(tbs.len() + 4);
    ws_der_put(&mut tbs_seq, 0x30, &tbs);
    let mut body = tbs_seq;
    body.extend_from_slice(&sig_alg);
    let mut sig_bits = Vec::new();
    sig_bits.push(0x00);
    sig_bits.extend_from_slice(signature.as_ref());
    ws_der_put(&mut body, 0x03, &sig_bits);
    let mut cert = Vec::with_capacity(body.len() + 4);
    ws_der_put(&mut cert, 0x30, &body);
    Ok((
        rustls::pki_types::CertificateDer::from(cert),
        rustls::pki_types::PrivateKeyDer::Pkcs8(pkcs8.as_ref().to_vec().into()),
    ))
}

fn wss_insecure_server() -> Option<&'static Arc<rustls::ServerConfig>> {
    WSS_INSECURE_SERVER.get_or_init(|| {
        let (cert, key) = ws_self_signed_pair().ok()?;
        rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert], key)
            .ok()
            .map(Arc::new)
    })
    .as_ref()
}

/// `WsTunnelListener` (websocket.rs:81-196): a TCP listener whose accept
/// completes the server upgrade (optionally behind the insecure `wss`
/// TLS) and returns the message-mapped stream.
pub struct WsVtListener {
    listener: tokio::net::TcpListener,
    tls: Option<Arc<rustls::ServerConfig>>,
    local: SocketAddr,
}

impl WsVtListener {
    /// `WsTunnelListener::listen` (websocket.rs:163-175).
    pub async fn bind(endpoint: &PeerEndpoint) -> Result<Self> {
        let addr = resolve_peer_addr(endpoint).await?;
        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .map_err(|e| Error::network(format!("easytier: ws listen {addr}: {e}")))?;
        let local = listener
            .local_addr()
            .map_err(|e| Error::network(format!("easytier: ws local addr: {e}")))?;
        let tls = if endpoint.transport == PeerTransport::Wss {
            Some(
                wss_insecure_server().cloned().ok_or_else(|| {
                    Error::crypto("easytier: wss listener: self-signed cert generation failed")
                })?,
            )
        } else {
            None
        };
        Ok(WsVtListener {
            listener,
            tls,
            local,
        })
    }

    /// The bound address (port 0 resolves, `local_url`).
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// `WsTunnelListener::accept` (websocket.rs:177-196): each inbound
    /// gets 3s to complete the upgrade; failures are logged and the
    /// listener lives on.
    pub async fn accept(&mut self) -> Result<WsPeerStream> {
        loop {
            let (stream, _peer) = self
                .listener
                .accept()
                .await
                .map_err(|e| Error::network(format!("easytier: ws accept: {e}")))?;
            let _ = stream.set_nodelay(true);
            match tokio::time::timeout(
                Duration::from_secs(3),
                self.try_accept(stream),
            )
            .await
            {
                Ok(Ok(stream)) => return Ok(stream),
                Ok(Err(e)) => {
                    tracing::debug!(target: "engine", "easytier: ws accept: {e}");
                }
                Err(_) => {
                    tracing::debug!(target: "engine", "easytier: ws accept: upgrade timed out");
                }
            }
        }
    }

    /// `try_accept` (websocket.rs:94-158) minus the Forwarded rewrite.
    async fn try_accept(&self, stream: tokio::net::TcpStream) -> Result<WsPeerStream> {
        let mut io: BoxProxyStream = Box::new(stream);
        if let Some(config) = &self.tls {
            let acceptor = tokio_rustls::TlsAcceptor::from(config.clone());
            let tls = acceptor
                .accept(io)
                .await
                .map_err(|e| Error::network(format!("easytier: wss accept: {e}")))?;
            io = Box::new(tls);
        }
        // The server upgrade (`ServerBuilder::accept`): validate the
        // request, answer 101 with the computed accept key.
        let head = ws_read_http_head(&mut io, 16 * 1024).await?;
        let upgrade = ws_header(&head, "upgrade").unwrap_or_default();
        if !upgrade.eq_ignore_ascii_case("websocket") {
            return Err(Error::protocol("easytier: ws: not a websocket upgrade"));
        }
        if ws_header(&head, "sec-websocket-version").map(|v| v.trim()) != Some("13") {
            return Err(Error::protocol("easytier: ws: unsupported Sec-WebSocket-Version"));
        }
        let key = ws_header(&head, "sec-websocket-key")
            .ok_or_else(|| Error::protocol("easytier: ws: missing Sec-WebSocket-Key"))?
            .to_owned();
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
             Connection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
            ws_accept_key(&key)
        );
        io.write_all(response.as_bytes()).await?;
        Ok(WsPeerStream::new(io, false))
    }
}

// ---------------------------------------------------------------------------
// The wg:// peer transport (M5, easytier-core/src/tunnel/wireguard.rs @
// v2.6.4, cached at /tmp/wave15-upstream/wireguard.rs)
// ---------------------------------------------------------------------------
//
// WireGuard-as-transport. Upstream drives cloudflare/boringtun's `Tunn`
// as a datagram pump per peer; this port drives the engine's own
// Noise_IKpsk2 machinery (proto/wireguard.rs, exposed through its
// additive `et_pump` facade) through the same shape:
//
// * **Keys** — `WgConfig::new_from_network_identity`
//   (wireguard.rs:62-79): `my_secret = generate_digest_from_str(name,
//   secret)` and `peer_secret = my_secret`, `peer_public = my_public`.
//   EVERY node of a network runs the SAME static keypair, so the Noise
//   `ss` step is X25519(my_priv, my_pub) = sk²·G on both ends —
//   deterministic, no exchange. Nothing in the handshake rejects a peer
//   whose static equals ours: the initiator seals its static under
//   es = DH(e_i, peer_pub) and the responder verifies it equals the
//   configured `peer_static_public` (boringtun handshake.rs:527-532) —
//   with the shared pair that check is self-consistent by construction.
// * **Framing** (`InternalUse`, wireguard.rs:131-179 + 318-335) — one
//   peer frame per WG IP packet: `[20-byte synthetic IPv4 header (0x45,
//   total len = 20 + PMH + payload, TTL 64, everything else zero)]
//   [PeerManagerHeader][payload]`, sealed as an ordinary WG transport
//   datagram. Receive trims AEAD padding by the IPv4 total length, then
//   strips the synthetic header (20B v4 / 40B v6) before the
//   `[PMH][payload]` datagram enters the session machinery — the exact
//   datagram contract of [`UdpVtStream`], so the wg pump reuses it.
// * **Connector** (`connect_with_socket`, wireguard.rs:626-691) — the
//   handshake-initiation-first dial: send an initiation, wait for the
//   first datagram (the response), and only then start the tunnel
//   tasks. A cookie reply is consumed and the initiation retried with
//   MAC2 immediately (the engine wg client's `initiate(force)` mirror).
// * **Listener** (`handle_udp_incoming`, wireguard.rs:489-551) — one
//   socket, a peer table keyed by remote address (every first datagram
//   creates a peer and yields a tunnel to accept), a 1s sweep dropping
//   peers silent > 61s.
// * **Routine** (`routine_task` + `handle_routine_tun_result`,
//   wireguard.rs:261-316) — a 250ms tick of boringtun's `update_timers`
//   (noise/timers.rs:168+, values identical to the engine's
//   wireguard.rs): retry the initiation every REKEY_TIMEOUT (5s), give
//   it up after REKEY_ATTEMPT_TIME (90s) and start over, rekey the
//   session at REKEY_AFTER_TIME (120s, initiator side only), keepalive
//   after KEEPALIVE_TIMEOUT (10s) of transmit silence, drop everything
//   at REJECT_AFTER_TIME * 3 (540s).
//
// DELTA vs upstream: the responder never answers initiations with
// cookie replies under load (boringtun's rate limiter trips at 64/s;
// a two-node mesh never gets there), and crossed simultaneous
// initiations converge through the retry timers (boringtun keeps two
// handshakes in flight — `Handshake::previous` — where this port keeps
// one; both recover the same way).

/// `MAX_PACKET` (tunnel/wireguard.rs:40): the WG packet budget.
pub const WG_MAX_PACKET: usize = 2048;
/// The routine tick (`sleep(Duration::from_millis(250))`,
/// tunnel/wireguard.rs:300-305).
const WG_TICK: Duration = Duration::from_millis(250);
/// The listener's idle-peer cutoff (`elapsed().as_secs() < 61`,
/// tunnel/wireguard.rs:500-502).
const WG_PEER_IDLE: Duration = Duration::from_secs(61);
/// boringtun `REKEY_TIMEOUT` (noise/timers.rs:22) — handshake retry.
const WG_REKEY_TIMEOUT: Duration = Duration::from_secs(5);
/// boringtun `REKEY_AFTER_TIME` (noise/timers.rs:19) — initiator rekey.
const WG_REKEY_AFTER_TIME: Duration = Duration::from_secs(120);
/// boringtun `REJECT_AFTER_TIME` (noise/timers.rs:20) — a session this
/// old may not receive anymore.
const WG_REJECT_AFTER_TIME: Duration = Duration::from_secs(180);
/// boringtun `REKEY_ATTEMPT_TIME` (noise/timers.rs:21) — the overall
/// handshake attempt budget before the connection expires and a fresh
/// handshake starts over.
const WG_REKEY_ATTEMPT_TIME: Duration = Duration::from_secs(90);
/// boringtun `KEEPALIVE_TIMEOUT` (noise/timers.rs:23).
const WG_KEEPALIVE_TIMEOUT: Duration = Duration::from_secs(10);
/// How long a superseded session still decrypts in-flight packets
/// (boringtun keeps `N_SESSIONS = 8` sessions alive; the whitepaper's
/// grace is 3 * REKEY_TIMEOUT — 15s is the in-flight window that
/// matters, entries also die at REJECT_AFTER_TIME).
const WG_OLD_SESSION_GRACE: Duration = Duration::from_secs(15);
/// The packets `encapsulate` queues while no session exists (boringtun
/// `queue_packet`; upstream has no bound but the M1 ping loop keeps it
/// near-empty).
const WG_QUEUED_PACKETS: usize = 256;

/// The shared static keypair of the network (`new_from_network_identity`
/// over the same `generate_digest_from_str` as the handshake digest —
/// config/mod.rs:207-218).
fn wg_static_keys(network_name: &str, network_secret: &str) -> et_pump::EtStatic {
    et_pump::static_from_secret(network_secret_digest(network_name, network_secret))
}

/// The synthetic IPv4 header of one outgoing WG IP packet
/// (`fill_ip_header`, tunnel/wireguard.rs:318-331): version 0x45, total
/// length = 20 + datagram, TTL 64, everything else zero (protocol 0 —
/// nothing parses past the total length).
fn wg_ip_packet(datagram: &[u8]) -> Vec<u8> {
    let total = (datagram.len() + 20) as u16;
    let mut pkt = Vec::with_capacity(datagram.len() + 20);
    pkt.push(0x45);
    pkt.push(0);
    pkt.extend_from_slice(&total.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.push(64);
    pkt.push(0);
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u32.to_be_bytes());
    pkt.extend_from_slice(&0u32.to_be_bytes());
    pkt.extend_from_slice(datagram);
    pkt
}

/// Strip the synthetic IP header off one decrypted inner packet
/// (`remove_ip_header`, tunnel/wireguard.rs:333-335): 20 bytes for a
/// v4 packet (the only form this port sends), 40 for v6.
fn wg_strip_ip_header(ip_packet: &[u8]) -> &[u8] {
    if ip_packet.first().is_some_and(|b| b >> 4 == 6) {
        &ip_packet[40.min(ip_packet.len())..]
    } else {
        &ip_packet[20.min(ip_packet.len())..]
    }
}

/// One established transport session plus its boringtun bookkeeping.
struct WgEtSession {
    session: et_pump::EtSession,
    established: Instant,
    /// We initiated this handshake (only the initiator rekeys — boringtun
    /// timers.rs:237-247).
    initiator: bool,
}

/// The per-peer `boringtun::noise::Tunn` equivalent: one static pair
/// (the shared digest keys), at most one outbound handshake in flight,
/// the session ring and the pre-session queue. All methods are
/// synchronous and non-blocking — callers serialize through a mutex and
/// do the UDP I/O on the returned vectors.
struct WgEtPump {
    statics: et_pump::EtStatic,
    peer_pk: [u8; 32],
    /// The outbound initiation awaiting its response.
    pending: Option<et_pump::EtPending>,
    last_initiation: Option<Instant>,
    /// When the current attempt window started (the 90s budget).
    handshake_started: Option<Instant>,
    cookie: Option<([u8; 16], Instant)>,
    /// Sessions newest-last; the last one is the send session. boringtun
    /// keeps a ring of `N_SESSIONS = 8` keyed by receiver index.
    sessions: VecDeque<WgEtSession>,
    /// Inner IP packets queued while no session exists (boringtun
    /// `queue_packet`, mod.rs `encapsulate`).
    queue: VecDeque<Vec<u8>>,
    /// The responder's replay guard: the strictly-greatest TAI64N
    /// accepted (boringtun handshake.rs:543-547).
    last_peer_timestamp: Option<[u8; 12]>,
    last_tx: Instant,
    last_rx: Instant,
    /// Whether this pump ever initiated (the connector re-initiates on
    /// expiry; a pure listener peer waits — easytier's routine only
    /// formats a fresh initiation after `ConnectionExpired`).
    ever_initiated: bool,
}

/// What one pump step wants the socket to do.
struct WgEtOut {
    to_network: Vec<Vec<u8>>,
    /// `[PMH][payload]` datagrams for the session machinery.
    to_tunnel: Vec<Vec<u8>>,
}

impl WgEtPump {
    fn new(network_name: &str, network_secret: &str) -> Self {
        let statics = wg_static_keys(network_name, network_secret);
        // `peer_public = my_public` — the shared pair
        // (new_from_network_identity, wireguard.rs:69).
        let peer_pk = statics.public();
        WgEtPump {
            statics,
            peer_pk,
            pending: None,
            last_initiation: None,
            handshake_started: None,
            cookie: None,
            sessions: VecDeque::new(),
            queue: VecDeque::new(),
            last_peer_timestamp: None,
            last_tx: Instant::now(),
            last_rx: Instant::now(),
            ever_initiated: false,
        }
    }

    /// A live send session exists.
    fn has_session(&self) -> bool {
        !self.sessions.is_empty()
    }

    /// Start (or restart) an outbound handshake: a fresh initiation with
    /// a fresh ephemeral and TAI64N, MAC2 keyed with the learned cookie
    /// when one is live (`format_handshake_initiation`).
    fn start_handshake(&mut self) -> Option<Vec<u8>> {
        if self.handshake_started.is_none() {
            self.handshake_started = Some(Instant::now());
        }
        self.ever_initiated = true;
        let cookie = self
            .cookie
            .filter(|(_, at)| at.elapsed() < WG_REJECT_AFTER_TIME)
            .map(|(c, _)| c);
        let index = rand::random();
        match et_pump::build_initiation(&self.statics, &self.peer_pk, cookie, index) {
            Ok((msg, pending)) => {
                self.pending = Some(pending);
                self.last_initiation = Some(Instant::now());
                Some(msg)
            }
            Err(e) => {
                tracing::debug!(target: "engine", "easytier wg: cannot build initiation: {e}");
                None
            }
        }
    }

    /// Install a finished handshake as the send session, keeping the
    /// superseded one receive-alive for the grace window.
    fn push_session(&mut self, session: et_pump::EtSession, initiator: bool) {
        let now = Instant::now();
        self.sessions
            .retain(|s| now.duration_since(s.established) < WG_OLD_SESSION_GRACE);
        self.sessions.push_back(WgEtSession {
            session,
            established: now,
            initiator,
        });
        while self.sessions.len() > 8 {
            self.sessions.pop_front();
        }
        self.pending = None;
        self.handshake_started = None;
    }

    /// Seal one inner IP packet, or queue it and kick a handshake
    /// (`Tunn::encapsulate`, boringtun mod.rs — no session: queue +
    /// initiate). Returns the datagrams to send.
    fn encapsulate(&mut self, inner_ip: &[u8]) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if inner_ip.len() + 20 > WG_MAX_PACKET {
            // boringtun `WireGuardError::LargePacket`; upstream logs and
            // carries on.
            tracing::debug!(
                target: "engine",
                "easytier wg: dropping {}-byte packet (max {})",
                inner_ip.len() + 20,
                WG_MAX_PACKET
            );
            return out;
        }
        if let Some(sess) = self.sessions.back_mut() {
            match sess.session.seal(inner_ip) {
                Ok(msg) => {
                    self.last_tx = Instant::now();
                    out.push(msg);
                }
                Err(e) => {
                    tracing::debug!(target: "engine", "easytier wg: seal failed: {e}");
                }
            }
            return out;
        }
        if self.queue.len() < WG_QUEUED_PACKETS {
            self.queue.push_back(inner_ip.to_vec());
        }
        if self.pending.is_none() {
            out.extend(self.start_handshake());
        }
        out
    }

    /// Feed one UDP datagram from the peer (`Tunn::decapsulate`):
    /// handshakes advance, transport packets decrypt into inner IP
    /// packets. Returns what to send / deliver.
    fn decapsulate(&mut self, datagram: &[u8]) -> WgEtOut {
        let mut out = WgEtOut {
            to_network: Vec::new(),
            to_tunnel: Vec::new(),
        };
        self.last_rx = Instant::now();
        let Some(msg) = parse_wg_msg(datagram) else {
            return out; // boringtun drops malformed datagrams silently
        };
        match msg {
            WgMsg::Initiation { .. } => {
                // Responder role. boringtun verifies MAC1 (inside
                // `open_initiation`), unseals the static and REQUIRES it
                // to equal the configured peer key (handshake.rs:527-532)
                // — with the shared digest pair, our own public.
                let opened = match et_pump::open_initiation(&self.statics, &msg) {
                    Ok(opened) => opened,
                    Err(e) => {
                        tracing::debug!(target: "engine", "easytier wg: initiation rejected: {e}");
                        return out;
                    }
                };
                if opened.initiator_static() != self.peer_pk {
                    tracing::debug!(target: "engine", "easytier wg: initiation from wrong key");
                    return out;
                }
                let timestamp = opened.timestamp();
                if self
                    .last_peer_timestamp
                    .is_some_and(|last| timestamp <= last)
                {
                    // Possibly a replay — boringtun WrongTai64nTimestamp.
                    return out;
                }
                self.last_peer_timestamp = Some(timestamp);
                match et_pump::respond_initiation(opened, rand::random()) {
                    Ok((resp, done)) => {
                        // The responder sends with the initiator's
                        // receive key and vice versa.
                        let session = et_pump::EtSession::from_responder(
                            done.local_index,
                            done.peer_index,
                            done.send_key,
                            done.recv_key,
                        );
                        self.push_session(session, false);
                        out.to_network.push(resp);
                    }
                    Err(e) => {
                        tracing::debug!(target: "engine", "easytier wg: respond failed: {e}")
                    }
                }
            }
            WgMsg::Response { .. } => {
                // Initiator role: consume against the pending initiation
                // (a stale response for a dropped handshake is ignored —
                // `receiver` must match our index).
                let Some(mut pending) = self.pending.take() else {
                    return out;
                };
                match et_pump::consume_response(&self.statics, &mut pending, &msg) {
                    Ok(done) => {
                        let session = et_pump::EtSession::from_initiator(done);
                        self.push_session(session, true);
                        // Confirmation + everything queued while the
                        // handshake was in flight (boringtun flushes the
                        // queue on `set_finished`; the empty packet is
                        // the key confirmation the responder waits for).
                        let queued: Vec<Vec<u8>> = self.queue.drain(..).collect();
                        for inner in queued {
                            out.to_network.extend(self.encapsulate(&inner));
                        }
                        if let Some(sess) = self.sessions.back_mut() {
                            if let Ok(keepalive) = sess.session.seal(&[]) {
                                self.last_tx = Instant::now();
                                out.to_network.push(keepalive);
                            }
                        }
                    }
                    Err(e) => {
                        // Put the initiation back and wait for the retry
                        // timer (boringtun keeps it until REKEY_TIMEOUT).
                        self.pending = Some(pending);
                        tracing::debug!(target: "engine", "easytier wg: response rejected: {e}");
                    }
                }
            }
            WgMsg::Cookie { .. } => {
                // Under-load reply: learn the cookie and retry the
                // initiation with MAC2 right away (the engine wg client's
                // `initiate(socket, true)` mirror).
                if let Some(pending) = &self.pending {
                    if let Ok(cookie) =
                        et_pump::consume_cookie_reply(&self.peer_pk, pending, &msg)
                    {
                        self.cookie = Some((cookie, Instant::now()));
                        self.pending = None;
                        out.to_network.extend(self.start_handshake());
                    }
                }
            }
            WgMsg::Transport { receiver, counter, data } => {
                // Find the session by receiver index (boringtun's
                // N_SESSIONS ring); tag first, replay window after.
                let now = Instant::now();
                self.sessions
                    .retain(|s| now.duration_since(s.established) < WG_REJECT_AFTER_TIME);
                for sess in self.sessions.iter_mut() {
                    if sess.session.local_index() != receiver {
                        continue;
                    }
                    match sess.session.open(counter, &data) {
                        Ok(mut inner) => {
                            if inner.is_empty() {
                                return out; // keepalive
                            }
                            et_pump::trim_ip_packet(&mut inner);
                            if inner.len() >= 20 {
                                let datagram = wg_strip_ip_header(&inner).to_vec();
                                if !datagram.is_empty() {
                                    out.to_tunnel.push(datagram);
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!(target: "engine", "easytier wg: transport open: {e}");
                        }
                    }
                    break;
                }
            }
        }
        out
    }

    /// The 250ms routine tick (`update_timers`, boringtun timers.rs:
    /// 168-299, driven by easytier's `routine_task`).
    fn update_timers(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let now = Instant::now();
        if let Some(started) = self.handshake_started {
            // An outbound handshake is in flight.
            if now.duration_since(started) >= WG_REKEY_ATTEMPT_TIME {
                // CONNECTION_EXPIRED(REKEY_ATTEMPT_TIME): the retries
                // give up, the queue is cleared, and easytier's routine
                // formats a FRESH initiation (wireguard.rs:280-291).
                self.pending = None;
                self.queue.clear();
                self.handshake_started = None;
                return out;
            }
            if self
                .last_initiation
                .is_some_and(|at| now.duration_since(at) >= WG_REKEY_TIMEOUT)
            {
                // HANDSHAKE(REKEY_TIMEOUT): retransmit with a fresh
                // ephemeral and timestamp.
                self.pending = None;
                out.extend(self.start_handshake());
            }
            return out;
        }
        // No handshake in flight.
        self.sessions
            .retain(|s| now.duration_since(s.established) < WG_REJECT_AFTER_TIME * 3);
        if self.sessions.is_empty() {
            // Either data is queued with no session (boringtun's
            // encapsulate triggers a handshake) or the connection
            // expired out from under a dial — easytier's routine
            // formats a FRESH initiation on ConnectionExpired
            // (wireguard.rs:280-291). A pure listener peer (never
            // initiated, nothing queued) waits for the peer instead.
            if !self.queue.is_empty() || self.ever_initiated {
                out.extend(self.start_handshake());
            }
            return out;
        }
        let established = self.sessions.back().unwrap().established;
        let initiator = self.sessions.back().unwrap().initiator;
        // HANDSHAKE(REKEY_AFTER_TIME): the ORIGINAL initiator rekeys
        // under a live session (the responder does not).
        if initiator && now.duration_since(established) >= WG_REKEY_AFTER_TIME {
            out.extend(self.start_handshake());
            return out;
        }
        // KEEPALIVE(KEEPALIVE_TIMEOUT): we received since our last send
        // but have been transmit-silent.
        if self.last_rx > self.last_tx && now.duration_since(self.last_tx) >= WG_KEEPALIVE_TIMEOUT
        {
            if let Some(sess) = self.sessions.back_mut() {
                if let Ok(keepalive) = sess.session.seal(&[]) {
                    self.last_tx = Instant::now();
                    out.push(keepalive);
                }
            }
        }
        out
    }
}

/// The sender task (`handle_packet_from_me` — the ring side of
/// upstream's stream pair): each complete `[PMH][payload]` datagram the
/// session machinery writes becomes one WG IP packet; with no session
/// the packet queues and a handshake starts.
async fn run_wg_sender(
    socket: Arc<tokio::net::UdpSocket>,
    dst: SocketAddr,
    pump: Arc<StdMutex<WgEtPump>>,
    half: Arc<StdMutex<UdpVtHalf>>,
    wake: Arc<Notify>,
) {
    loop {
        wake.notified().await;
        loop {
            let next = {
                let mut guard = half.lock().unwrap_or_else(|e| e.into_inner());
                guard.tx_queue.pop_front()
            };
            let Some(datagram) = next else { break };
            if let Some(w) = half
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .write_waker
                .take()
            {
                w.wake();
            }
            let to_network = {
                let mut pump = pump.lock().unwrap_or_else(|e| e.into_inner());
                pump.encapsulate(&wg_ip_packet(&datagram))
            };
            for packet in to_network {
                if socket.send_to(&packet, dst).await.is_err() {
                    let mut guard = half.lock().unwrap_or_else(|e| e.into_inner());
                    guard.write_error = true;
                    guard.read_closed = true;
                    drop(guard);
                    wake_udp_half(&half);
                    return;
                }
            }
        }
    }
}

/// The routine task (`routine_task`, wireguard.rs:310-316): tick
/// `update_timers` every 250ms and send what it produces.
async fn run_wg_routine(
    socket: Arc<tokio::net::UdpSocket>,
    dst: SocketAddr,
    pump: Arc<StdMutex<WgEtPump>>,
) {
    loop {
        tokio::time::sleep(WG_TICK).await;
        let to_network = pump
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .update_timers();
        for packet in to_network {
            let _ = socket.send_to(&packet, dst).await;
        }
    }
}

/// The receiver task (the spawned `handle_one_packet_from_peer` loop of
/// the connector, wireguard.rs:660-673).
async fn run_wg_receiver(
    socket: Arc<tokio::net::UdpSocket>,
    dst: SocketAddr,
    pump: Arc<StdMutex<WgEtPump>>,
    half: Arc<StdMutex<UdpVtHalf>>,
) {
    let mut buf = vec![0u8; WG_MAX_PACKET + 128];
    loop {
        match socket.recv_from(&mut buf).await {
            Ok((n, addr)) => {
                // `Received packet from changed address` is a warning
                // upstream (wireguard.rs:653-655); the peer table is
                // address-keyed and never roams, so foreign datagrams
                // are dropped.
                if addr != dst {
                    continue;
                }
                let out = pump.lock().unwrap_or_else(|e| e.into_inner()).decapsulate(&buf[..n]);
                for packet in out.to_network {
                    let _ = socket.send_to(&packet, dst).await;
                }
                if !out.to_tunnel.is_empty() {
                    let mut guard = half.lock().unwrap_or_else(|e| e.into_inner());
                    for datagram in out.to_tunnel {
                        guard.push_datagram(&datagram);
                    }
                    drop(guard);
                    wake_udp_half(&half);
                }
            }
            Err(_) => {
                let mut guard = half.lock().unwrap_or_else(|e| e.into_inner());
                guard.read_closed = true;
                drop(guard);
                wake_udp_half(&half);
                break;
            }
        }
    }
}

/// The wg:// peer dial (`WgTunnelConnector::connect` →
/// `connect_with_socket`, tunnel/wireguard.rs:626-691): an ephemeral
/// socket, the handshake-initiation-first exchange — send an initiation,
/// wait for the first datagram back (the response, or a cookie reply
/// which retries immediately) — then the tunnel tasks around the same
/// datagram half the UDP transport uses.
pub async fn connect_wg_tunnel(
    dst: SocketAddr,
    network_name: &str,
    network_secret: &str,
) -> Result<UdpVtStream> {
    let bind_addr: &str = if dst.is_ipv4() { "0.0.0.0:0" } else { "[::]:0" };
    let socket = tokio::net::UdpSocket::bind(bind_addr)
        .await
        .map_err(|e| Error::network(format!("easytier: wg bind: {e}")))?;
    let socket = Arc::new(socket);
    let pump = Arc::new(StdMutex::new(WgEtPump::new(network_name, network_secret)));

    // "do handshake here so we will return after receive first packet"
    // (wireguard.rs:641-643).
    let initiation = {
        let mut pump = pump.lock().unwrap_or_else(|e| e.into_inner());
        pump.start_handshake()
    };
    if let Some(initiation) = initiation {
        socket
            .send_to(&initiation, dst)
            .await
            .map_err(|e| Error::network(format!("easytier: wg send initiation: {e}")))?;
    }
    let mut buf = vec![0u8; WG_MAX_PACKET + 128];
    let mut pending_tunnel: Vec<Vec<u8>> = Vec::new();
    loop {
        let (n, addr) = tokio::time::timeout(WG_HANDSHAKE_WAIT, socket.recv_from(&mut buf))
            .await
            .map_err(|_| Error::network("easytier: wg connect timeout (no handshake response)"))?
            .map_err(|e| Error::network(format!("easytier: wg recv: {e}")))?;
        if addr != dst {
            continue;
        }
        let out = pump.lock().unwrap_or_else(|e| e.into_inner()).decapsulate(&buf[..n]);
        for packet in out.to_network {
            let _ = socket.send_to(&packet, dst).await;
        }
        pending_tunnel.extend(out.to_tunnel);
        if pump
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .has_session()
        {
            break;
        }
        // A cookie reply already retried the initiation; keep waiting
        // for the response within the outer budget.
    }

    let half = Arc::new(StdMutex::new(UdpVtHalf::new()));
    let wake = Arc::new(Notify::new());
    if !pending_tunnel.is_empty() {
        let mut guard = half.lock().unwrap_or_else(|e| e.into_inner());
        for datagram in pending_tunnel {
            guard.push_datagram(&datagram);
        }
        drop(guard);
        wake_udp_half(&half);
    }
    tokio::spawn(run_wg_receiver(socket.clone(), dst, pump.clone(), half.clone()));
    tokio::spawn(run_wg_sender(
        socket.clone(),
        dst,
        pump.clone(),
        half.clone(),
        wake.clone(),
    ));
    tokio::spawn(run_wg_routine(socket, dst, pump));
    Ok(UdpVtStream {
        half,
        send_wake: wake,
    })
}

/// How long the synchronous handshake exchange may take (the direct
/// connector's 3s budget, connectivity/direct/mod.rs:64 — upstream waits
/// unbounded; the dial wrapper enforces the same ceiling).
const WG_HANDSHAKE_WAIT: Duration = Duration::from_secs(3);

/// One listener peer-table entry (`WgPeer` + its tasks).
struct WgListenerPeer {
    pump: Arc<StdMutex<WgEtPump>>,
    half: Arc<StdMutex<UdpVtHalf>>,
    last_seen: Instant,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl WgListenerPeer {
    fn shutdown(self) {
        for task in self.tasks {
            task.abort();
        }
        let mut guard = self.half.lock().unwrap_or_else(|e| e.into_inner());
        guard.read_closed = true;
        guard.write_error = true;
        drop(guard);
        wake_udp_half(&self.half);
    }
}

/// The wg:// listener (`WgTunnelListener`, tunnel/wireguard.rs:455-591):
/// one UDP socket; every first datagram from an address creates a peer
/// (whose tunnel is yielded to `accept`), later datagrams feed that
/// peer's pump; a sweep drops peers silent > 61s.
pub struct WgVtListener {
    local: SocketAddr,
    accept_rx: mpsc::Receiver<UdpVtStream>,
    task: tokio::task::JoinHandle<()>,
}

impl WgVtListener {
    /// `WgTunnelListener::listen` (wireguard.rs:556-578): bind, then the
    /// `handle_udp_incoming` task.
    pub async fn bind(
        local: SocketAddr,
        network_name: &str,
        network_secret: &str,
    ) -> Result<Self> {
        let socket = tokio::net::UdpSocket::bind(local)
            .await
            .map_err(|e| Error::network(format!("easytier: wg listen {local}: {e}")))?;
        let local = socket
            .local_addr()
            .map_err(|e| Error::network(format!("easytier: wg local addr: {e}")))?;
        let socket = Arc::new(socket);
        let (accept_tx, accept_rx) = mpsc::channel(16);
        let task = tokio::spawn(run_wg_listener(
            socket,
            network_name.to_owned(),
            network_secret.to_owned(),
            accept_tx,
        ));
        Ok(WgVtListener {
            local,
            accept_rx,
            task,
        })
    }

    /// The bound address (port 0 resolves, `local_url`).
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// `accept` (wireguard.rs:580-587): the next peer tunnel.
    pub async fn accept(&mut self) -> Result<UdpVtStream> {
        self.accept_rx
            .recv()
            .await
            .ok_or_else(|| Error::network("easytier: wg listener closed"))
    }
}

impl Drop for WgVtListener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

/// The listener forward task (`handle_udp_incoming`,
/// tunnel/wireguard.rs:489-551): the peer table + the 1s retain sweep
/// (wireguard.rs:498-506).
async fn run_wg_listener(
    socket: Arc<tokio::net::UdpSocket>,
    network_name: String,
    network_secret: String,
    accept_tx: mpsc::Sender<UdpVtStream>,
) {
    let peers: Arc<StdMutex<HashMap<SocketAddr, WgListenerPeer>>> =
        Arc::new(StdMutex::new(HashMap::new()));
    {
        // The retain sweep: `access_time.elapsed() < 61s && !stopped`.
        let peers = peers.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let mut guard = peers.lock().unwrap_or_else(|e| e.into_inner());
                    let now_idle = |peer: &WgListenerPeer| peer.last_seen.elapsed() >= WG_PEER_IDLE;
                let dead: Vec<SocketAddr> = guard
                    .iter()
                    .filter(|(_, peer)| now_idle(peer))
                    .map(|(addr, _)| *addr)
                    .collect();
                for addr in dead {
                    if let Some(peer) = guard.remove(&addr) {
                        peer.shutdown();
                    }
                }
            }
        });
    }
    let mut buf = vec![0u8; WG_MAX_PACKET + 128];
    loop {
        let (n, addr) = match socket.recv_from(&mut buf).await {
            Ok(v) => v,
            Err(_) => break,
        };
        // "New peer: {}" — the first datagram creates the tunnel no
        // matter its type; a transport packet for a session nobody has
        // is then dropped by the pump (upstream behaves identically —
        // the peer exists before decapsulate sees the packet).
        {
            let mut guard = peers.lock().unwrap_or_else(|e| e.into_inner());
            match guard.get_mut(&addr) {
                Some(peer) => peer.last_seen = Instant::now(),
                None => {
                    let pump =
                        Arc::new(StdMutex::new(WgEtPump::new(&network_name, &network_secret)));
                    let half = Arc::new(StdMutex::new(UdpVtHalf::new()));
                    let wake = Arc::new(Notify::new());
                    // The connector spawns a dedicated receive task (it
                    // owns its socket); the LISTENER's datagrams arrive
                    // through this central loop, so a peer entry only
                    // runs the sender + routine tasks.
                    let tasks = vec![
                        tokio::spawn(run_wg_sender(
                            socket.clone(),
                            addr,
                            pump.clone(),
                            half.clone(),
                            wake.clone(),
                        )),
                        tokio::spawn(run_wg_routine(socket.clone(), addr, pump.clone())),
                    ];
                    guard.insert(
                        addr,
                        WgListenerPeer {
                            pump,
                            half: half.clone(),
                            last_seen: Instant::now(),
                            tasks,
                        },
                    );
                    let stream = UdpVtStream {
                        half,
                        send_wake: wake,
                    };
                    let _ = accept_tx.try_send(stream);
                }
            }
        }
        let (out, half) = {
            let mut guard = peers.lock().unwrap_or_else(|e| e.into_inner());
            let Some(peer) = guard.get_mut(&addr) else {
                continue;
            };
            let out = peer
                .pump
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .decapsulate(&buf[..n]);
            (out, peer.half.clone())
        };
        for packet in out.to_network {
            let _ = socket.send_to(&packet, addr).await;
        }
        if !out.to_tunnel.is_empty() {
            let mut guard = half.lock().unwrap_or_else(|e| e.into_inner());
            for datagram in out.to_tunnel {
                guard.push_datagram(&datagram);
            }
            drop(guard);
            wake_udp_half(&half);
        }
    }
}

// ---------------------------------------------------------------------------
// Network identity (easytier-core/src/config/mod.rs:135-233)
// ---------------------------------------------------------------------------

/// `NetworkSecretDigest = [u8; 32]` (config/mod.rs:56).
pub type NetworkSecretDigest = [u8; 32];

/// `generate_digest_from_str` (config/mod.rs:207-218): std
/// `DefaultHasher` (SipHash-1-3, zero keys) over the name then the
/// secret, the 8-byte big-endian shards fed back between rounds.
fn generate_digest_from_str(name: &str, secret: &str, digest: &mut [u8]) {
    let mut hasher = DefaultHasher::new();
    hasher.write(name.as_bytes());
    hasher.write(secret.as_bytes());

    let shard_count = digest.len() / 8;
    for i in 0..shard_count {
        digest[i * 8..(i + 1) * 8].copy_from_slice(&hasher.finish().to_be_bytes());
        hasher.write(&digest[..(i + 1) * 8]);
    }
}

/// `network_secret_digest` (config/mod.rs:220-225).
pub fn network_secret_digest(network_name: &str, network_secret: &str) -> NetworkSecretDigest {
    let mut digest = [0u8; 32];
    generate_digest_from_str(network_name, network_secret, &mut digest);
    digest
}

/// `network_secret_digest_is_empty` (peer_conn.rs:1417-1422): the
/// all-zero digest a secret-less (credential) peer sends.
fn digest_is_empty(digest: &[u8]) -> bool {
    digest.iter().all(|byte| *byte == 0)
}

// ---------------------------------------------------------------------------
// HandshakeRequest — hand-rolled proto3 (peer_rpc.proto:315-322)
// ---------------------------------------------------------------------------

/// The plain (non-secure-mode) peer handshake message
/// (`HandshakeRequest`, easytier-proto/proto/peer_rpc.proto:315-322),
/// carried in a `PacketType::HandShake` peer packet
/// (`send_handshake`, peers/conn/peer_conn.rs:529-573).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HandshakeRequest {
    pub magic: u32,
    pub my_peer_id: PeerId,
    pub version: u32,
    pub features: Vec<String>,
    pub network_name: String,
    pub network_secret_digest: Vec<u8>,
}

/// `MAGIC` (peers/conn/peer_conn.rs:65).
pub const HANDSHAKE_MAGIC: u32 = 0xd1e1a5e1;
/// `VERSION` (peers/conn/peer_conn.rs:66).
pub const HANDSHAKE_VERSION: u32 = 1;
/// `LIVENESS_ECHO_FEATURE` (peers/conn/peer_conn_liveness.rs:10).
pub const LIVENESS_ECHO_FEATURE: &str = "liveness-echo-v1";

fn proto_put_varint(out: &mut Vec<u8>, mut value: u64) {
    loop {
        let byte = (value & 0x7f) as u8;
        value >>= 7;
        if value == 0 {
            out.push(byte);
            return;
        }
        out.push(byte | 0x80);
    }
}

fn proto_put_len_field(out: &mut Vec<u8>, field: u32, bytes: &[u8]) {
    proto_put_varint(out, (field << 3 | 2) as u64);
    proto_put_varint(out, bytes.len() as u64);
    out.extend_from_slice(bytes);
}

struct ProtoReader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> ProtoReader<'a> {
    fn varint(&mut self) -> Result<u64> {
        let mut value = 0u64;
        let mut shift = 0;
        loop {
            let byte = *self.buf.get(self.pos).ok_or_else(|| {
                Error::protocol("easytier: truncated protobuf varint")
            })?;
            self.pos += 1;
            value |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
            if shift >= 64 {
                return Err(Error::protocol("easytier: protobuf varint overflow"));
            }
        }
    }

    fn len_bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.varint()? as usize;
        let end = self
            .pos
            .checked_add(len)
            .filter(|end| *end <= self.buf.len())
            .ok_or_else(|| Error::protocol("easytier: truncated protobuf field"))?;
        let bytes = &self.buf[self.pos..end];
        self.pos = end;
        Ok(bytes)
    }

    fn skip(&mut self, wire_type: u64) -> Result<()> {
        match wire_type {
            0 => {
                self.varint()?;
            }
            1 => {
                self.pos = self.pos.checked_add(8).filter(|p| *p <= self.buf.len()).ok_or_else(
                    || Error::protocol("easytier: truncated fixed64"),
                )?;
            }
            2 => {
                self.len_bytes()?;
            }
            5 => {
                self.pos = self.pos.checked_add(4).filter(|p| *p <= self.buf.len()).ok_or_else(
                    || Error::protocol("easytier: truncated fixed32"),
                )?;
            }
            _ => return Err(Error::protocol("easytier: unknown protobuf wire type")),
        }
        Ok(())
    }
}

impl HandshakeRequest {
    /// proto3 encoding: default (zero/empty) fields are omitted, exactly
    /// as prost does for this message.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        if self.magic != 0 {
            proto_put_varint(&mut out, 0x08);
            proto_put_varint(&mut out, self.magic as u64);
        }
        if self.my_peer_id != 0 {
            proto_put_varint(&mut out, 0x10);
            proto_put_varint(&mut out, self.my_peer_id as u64);
        }
        if self.version != 0 {
            proto_put_varint(&mut out, 0x18);
            proto_put_varint(&mut out, self.version as u64);
        }
        for feature in &self.features {
            proto_put_len_field(&mut out, 4, feature.as_bytes());
        }
        if !self.network_name.is_empty() {
            proto_put_len_field(&mut out, 5, self.network_name.as_bytes());
        }
        if !self.network_secret_digest.is_empty() {
            proto_put_len_field(&mut out, 6, &self.network_secret_digest);
        }
        out
    }

    /// Decode, skipping unknown fields and accepting any field order;
    /// proto3 defaults fill the gaps.
    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut req = HandshakeRequest::default();
        let mut reader = ProtoReader { buf, pos: 0 };
        while reader.pos < buf.len() {
            let tag = reader.varint()?;
            let field = (tag >> 3) as u32;
            let wire_type = tag & 7;
            match (field, wire_type) {
                (1, 0) => req.magic = reader.varint()? as u32,
                (2, 0) => req.my_peer_id = reader.varint()? as u32,
                (3, 0) => req.version = reader.varint()? as u32,
                (4, 2) => {
                    let bytes = reader.len_bytes()?;
                    let text = String::from_utf8_lossy(bytes).into_owned();
                    req.features.push(text);
                }
                (5, 2) => {
                    let bytes = reader.len_bytes()?;
                    req.network_name = String::from_utf8_lossy(bytes).into_owned();
                }
                (6, 2) => {
                    let bytes = reader.len_bytes()?;
                    req.network_secret_digest = bytes.to_vec();
                }
                _ => reader.skip(wire_type)?,
            }
        }
        Ok(req)
    }
}

// ---------------------------------------------------------------------------
// Packet encryption (easytier-core/src/tunnel/encrypt/ — mod.rs, aes_gcm.rs,
// chacha20.rs, xor.rs; keys from config/encryption.rs + encrypt/mod.rs)
// ---------------------------------------------------------------------------

/// `EncryptionAlgorithm` (easytier-core/src/config/encryption.rs:6-11) with
/// its exact alias table (`FromStr`, encryption.rs:29-41).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EncryptionAlgorithm {
    Xor,
    #[default]
    AesGcm,
    Aes256Gcm,
    ChaCha20,
}

impl EncryptionAlgorithm {
    /// `as_str` (encryption.rs:14-22).
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Xor => "xor",
            Self::AesGcm => "aes-gcm",
            Self::Aes256Gcm => "aes-256-gcm",
            Self::ChaCha20 => "chacha20",
        }
    }
}

impl std::str::FromStr for EncryptionAlgorithm {
    type Err = ();

    fn from_str(value: &str) -> std::result::Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "xor" => Ok(Self::Xor),
            "aes-gcm" | "openssl-aes-gcm" => Ok(Self::AesGcm),
            "aes-256-gcm" | "openssl-aes-256-gcm" => Ok(Self::Aes256Gcm),
            "chacha20" | "chacha20-poly1305" | "openssl-chacha20" => Ok(Self::ChaCha20),
            _ => Err(()),
        }
    }
}

/// `derive_key_128` (tunnel/encrypt/mod.rs:62-71).
pub fn derive_key_128(secret: &str) -> [u8; 16] {
    let mut key = [0u8; 16];
    let mut hasher = DefaultHasher::new();
    hasher.write(secret.as_bytes());
    key[0..8].copy_from_slice(&hasher.finish().to_be_bytes());
    hasher.write(&key[0..8]);
    key[8..16].copy_from_slice(&hasher.finish().to_be_bytes());
    hasher.write(&key);
    key
}

/// `derive_key_256` (tunnel/encrypt/mod.rs:73-84).
pub fn derive_key_256(secret: &str) -> [u8; 32] {
    let mut key = [0u8; 32];
    let mut hasher = DefaultHasher::new();
    hasher.write(secret.as_bytes());
    hasher.write(b"easytier-256bit-key");
    for i in 0..4 {
        let chunk_start = i * 8;
        let chunk_end = chunk_start + 8;
        hasher.write(&key[0..chunk_start]);
        hasher.write(&[i as u8]);
        key[chunk_start..chunk_end].copy_from_slice(&hasher.finish().to_be_bytes());
    }
    key
}

enum Cipher {
    /// `NullCipher` (encrypt/mod.rs:65-78).
    Null,
    /// `XorCipher` (encrypt/xor.rs:8-11).
    Xor(Vec<u8>),
    Aes128Gcm(Box<Aes128Gcm>),
    Aes256Gcm(Box<Aes256Gcm>),
    ChaCha20(Box<ChaCha20Poly1305>),
}

/// The `Encryptor` port (tunnel/encrypt/mod.rs:39-51): AEAD packets grow by
/// the `StandardAeadTail { tag: 16, nonce: 12 }` (packet/mod.rs:331-346)
/// appended after the ciphertext and are flagged `ENCRYPTED` in the
/// peer-manager header.
pub struct PacketEncryptor {
    cipher: Cipher,
}



/// `AEAD_TAIL_SIZE` = `StandardAeadTail::SIZE` (packet/mod.rs:339-346).
pub const AEAD_TAIL_SIZE: usize = 28;

// The packet methods below take &mut Vec<u8> because the AEAD tail
// changes the payload length (clippy::ptr_arg).
#[allow(clippy::ptr_arg)]
impl PacketEncryptor {
    fn aead_seal_detached(
        &self,
        nonce: &[u8; 12],
        payload: &mut Vec<u8>,
    ) -> Result<[u8; 16]> {
        let nonce = Nonce::from_slice(nonce);
        let tag = match &self.cipher {
            Cipher::Aes128Gcm(cipher) => cipher.encrypt_in_place_detached(nonce, b"", payload),
            Cipher::Aes256Gcm(cipher) => cipher.encrypt_in_place_detached(nonce, b"", payload),
            Cipher::ChaCha20(cipher) => cipher.encrypt_in_place_detached(nonce, b"", payload),
            Cipher::Null | Cipher::Xor(_) => {
                return Err(Error::crypto("easytier: cipher is not an AEAD"))
            }
        }
        .map_err(|_| Error::crypto("easytier: encryption failed"))?;
        let mut tag_out = [0u8; 16];
        tag_out.copy_from_slice(tag.as_ref());
        Ok(tag_out)
    }

    fn aead_open_detached(
        &self,
        nonce: &[u8; 12],
        text_and_tag: &mut [u8],
        tag: &[u8; 16],
    ) -> Result<()> {
        let nonce = Nonce::from_slice(nonce);
        let result = match &self.cipher {
            Cipher::Aes128Gcm(cipher) => {
                cipher.decrypt_in_place_detached(nonce, b"", text_and_tag, tag.as_ref().into())
            }
            Cipher::Aes256Gcm(cipher) => {
                cipher.decrypt_in_place_detached(nonce, b"", text_and_tag, tag.as_ref().into())
            }
            Cipher::ChaCha20(cipher) => {
                cipher.decrypt_in_place_detached(nonce, b"", text_and_tag, tag.as_ref().into())
            }
            Cipher::Null | Cipher::Xor(_) => {
                return Err(Error::crypto("easytier: cipher is not an AEAD"))
            }
        };
        result.map_err(|_| Error::crypto("easytier: decryption failed"))
    }

    /// `encrypt_with_nonce` (encrypt/ring.rs:121-146 with a chosen nonce —
    /// `seal_in_place_separate_tag(nonce, Aad::empty(), payload)`, then
    /// append `AeadTail { tag, nonce }` and set the ENCRYPTED flag).
    pub fn encrypt_packet_with_nonce(
        &self,
        hdr: &mut PeerManagerHeader,
        payload: &mut Vec<u8>,
        nonce: &[u8; 12],
    ) -> Result<()> {
        if hdr.is_encrypted() {
            // already encrypted — upstream warns and returns Ok.
            return Ok(());
        }
        match &self.cipher {
            Cipher::Null => return Ok(()),
            Cipher::Xor(key) => {
                for (i, byte) in payload.iter_mut().enumerate() {
                    *byte ^= key[i % key.len()];
                }
            }
            _ => {
                let tag = self.aead_seal_detached(nonce, payload)?;
                payload.extend_from_slice(&tag);
                payload.extend_from_slice(nonce);
            }
        }
        hdr.set_encrypted(true);
        Ok(())
    }

    /// `encrypt` (encrypt/ring.rs:110-113): random nonce from the OS.
    pub fn encrypt_packet(
        &self,
        hdr: &mut PeerManagerHeader,
        payload: &mut Vec<u8>,
    ) -> Result<()> {
        let mut nonce = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut nonce);
        self.encrypt_packet_with_nonce(hdr, payload, &nonce)
    }

    /// `decrypt` (encrypt/ring.rs:72-108): unencrypted packets pass; the
    /// AEAD tail is the last 28 bytes, the tag sits directly after the
    /// ciphertext, and the 28 tail bytes are truncated after opening.
    pub fn decrypt_packet(
        &self,
        hdr: &mut PeerManagerHeader,
        payload: &mut Vec<u8>,
    ) -> Result<()> {
        if !hdr.is_encrypted() {
            return Ok(());
        }
        match &self.cipher {
            Cipher::Null => return Err(Error::crypto("easytier: decryption failed")),
            Cipher::Xor(key) => {
                for (i, byte) in payload.iter_mut().enumerate() {
                    *byte ^= key[i % key.len()];
                }
                hdr.set_encrypted(false);
                return Ok(());
            }
            _ => {}
        }
        let payload_len = payload.len();
        if payload_len < AEAD_TAIL_SIZE {
            return Err(Error::crypto(format!(
                "easytier: packet is too short. len: {payload_len}"
            )));
        }
        // Upstream feeds ring `open_in_place` the ciphertext followed by
        // the tag (ring.rs:88-101, `text_and_tag_len`); the RustCrypto
        // API wants the ciphertext and the tag apart.
        let text_len = payload_len - AEAD_TAIL_SIZE;
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&payload[payload_len - 12..]);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&payload[text_len..text_len + 16]);
        let text = &mut payload[..text_len];
        self.aead_open_detached(&nonce, text, &tag)?;
        payload.truncate(text_len);
        hdr.set_encrypted(false);
        Ok(())
    }
}

/// `create_encryptor` (tunnel/encrypt/mod.rs:297-312) with the key choice
/// of `PeerManager::new` (peers/peer_manager.rs:902-908): the keys derive
/// from the network secret. `enable_encryption` defaults to **true**
/// (`gen_default_flags`, config/toml.rs:34) — a real peer drops plaintext
/// data packets when the flag is on.
pub fn create_encryptor(algorithm: &str, enable: bool, network_secret: &str) -> Result<PacketEncryptor> {
    if !enable {
        return Ok(PacketEncryptor { cipher: Cipher::Null });
    }
    let Ok(algorithm) = algorithm.parse::<EncryptionAlgorithm>() else {
        return Err(Error::config(format!(
            "easytier: invalid encryption algorithm: {algorithm}"
        )));
    };
    let key_128 = derive_key_128(network_secret);
    let key_256 = derive_key_256(network_secret);
    let cipher = match algorithm {
        EncryptionAlgorithm::Xor => Cipher::Xor(key_128.to_vec()),
        EncryptionAlgorithm::AesGcm => Cipher::Aes128Gcm(Box::new(
            Aes128Gcm::new_from_slice(&key_128).expect("128-bit key"),
        )),
        EncryptionAlgorithm::Aes256Gcm => Cipher::Aes256Gcm(Box::new(
            Aes256Gcm::new_from_slice(&key_256).expect("256-bit key"),
        )),
        EncryptionAlgorithm::ChaCha20 => Cipher::ChaCha20(Box::new(
            ChaCha20Poly1305::new_from_slice(&key_256).expect("256-bit key"),
        )),
    };
    Ok(PacketEncryptor { cipher })
}

// ---------------------------------------------------------------------------
// Secure mode (M6) — the Noise_XX handshake + the per-peer session AEAD
// (easytier-core v2.6.4: peers/peer_conn.rs:793-1218,
// peers/secure_datagram.rs, peers/peer_session.rs, peer_rpc.proto:343-386)
// ---------------------------------------------------------------------------
//
// Secure mode REPLACES the network-secret AEAD of plain mode: after the
// three Noise_XX messages every payload packet (Data/RpcReq/RpcResp —
// everything except the handshake itself and Ping/Pong,
// `PeerSessionTunnelFilter::should_skip_encrypt`, peer_conn.rs:136-144) is
// sealed by a per-peer session AEAD keyed from a root key the responder
// generates (`SecureModeConfig` keys are static X25519 identities; the
// network-secret proof still authenticates same-network peers).
//
// What the handshake exchanges (`do_noise_handshake_as_client/_as_server`,
// peer_conn.rs:793-1218, snow `Noise_XX_25519_ChaChaPoly_SHA256`, prologue
// `easytier-peerconn-noise`):
//
// * msg1 `PeerConnNoiseMsg1Pb { version, a_network_name,
//   a_session_generation?, a_conn_id, client_encryption_algorithm }` —
//   rides IN THE CLEAR after the 32-byte ephemeral (the first Noise_XX
//   message has no DH, so the payload is not yet encrypted);
// * msg2 `PeerConnNoiseMsg2Pb { b_network_name, role_hint, action
//   (Join/Sync/Create), b_session_generation, root_key_32?, initial_epoch,
//   b_conn_id, a_conn_id_echo, secret_proof_32?,
//   server_encryption_algorithm }` — carries the responder's session
//   verdict: `Create` (no prior session: fresh root key, generation 1),
//   `Sync` (known peer, resync: the stored root key + the next epoch) or
//   `Join` (the client's generation matches: no key material at all);
// * msg3 `PeerConnNoiseMsg3Pb { a_conn_id_echo, b_conn_id_echo,
//   secret_proof_32?, secret_digest }` — the client's proof and the
//   plain-mode digest for the compat identity check.
//
// The two-node subset ported: the full handshake with proofs and pinned
// keys, the `SecureDatagramSession` payload layer (epoch-keyed AEAD,
// per-direction replay windows, epoch rotation, root-key sync with the rx
// grace window, the decrypt-failure invalidation) and the
// `PeerSessionStore` Join/Sync/Create state machine. NOT ported: the
// trusted-key store behind `is_pubkey_trusted` (the credential file +
// OSPF key propagation — a pinned config key is the trust anchor here),
// the Relay* packet types (the relay path is not ported) and the
// foreign-network identity machinery (`classify_remote_identity` is
// reduced to logging the auth level).

/// `PacketType::NoiseHandshakeMsg2/3` (packet_def.rs:87-88).
pub mod noise_packet_type {
    pub const NOISE_HANDSHAKE_MSG2: u8 = 14;
    pub const NOISE_HANDSHAKE_MSG3: u8 = 15;
}

/// The prologue binding the handshake to the peer-conn protocol
/// (`do_noise_handshake_as_client`, peer_conn.rs:794).
const NOISE_PROLOGUE: &[u8] = b"easytier-peerconn-noise";
/// `VERSION` (peer_conn.rs:66) — carried in msg1 for future protocol bumps.
const NOISE_VERSION: u32 = 1;
/// The 5s budget on every noise message exchange (`timeout(Duration::
/// from_secs(5), ...)`, peer_conn.rs:842-846, 1136-1140).
const NOISE_MSG_TIMEOUT: Duration = Duration::from_secs(5);
/// `PeerSession::SYNC_RX_GRACE_AFTER_MS` (secure_datagram.rs:252): how
/// long a root-key sync keeps accepting the pre-sync rx epochs.
const SYNC_RX_GRACE_AFTER_MS: u64 = 5_000;
/// `EVICT_IDLE_AFTER_MS` (secure_datagram.rs:251).
const RX_SLOT_EVICT_AFTER_MS: u64 = 30_000;
/// `ROTATE_AFTER_PACKETS` / `ROTATE_AFTER_MS` (secure_datagram.rs:253-254):
/// the send epoch rotates after a million packets or ten minutes.
const EPOCH_ROTATE_AFTER_PACKETS: u64 = 1_000_000;
const EPOCH_ROTATE_AFTER_MS: u64 = 10 * 60 * 1000;
/// `MAX_ACCEPTED_RX_EPOCH_AHEAD` (secure_datagram.rs:255): an rx epoch
/// more than this ahead of the baseline is rejected without touching the
/// replay window.
const MAX_ACCEPTED_RX_EPOCH_AHEAD: u32 = 3;
/// `DECRYPT_FAIL_THRESHOLD` (secure_datagram.rs:256): ten consecutive
/// decrypt failures invalidate the session (which closes the connection —
/// the peer re-handshakes).
const DECRYPT_FAIL_THRESHOLD: u32 = 10;

// -- X25519 (curve25519-dalek, the wireguard.rs pattern) ---------------------

/// A static (or ephemeral) X25519 keypair (`get_keypair` over
/// `x25519_dalek::StaticSecret`, peer_conn.rs:604-638).
struct SecureStaticKeys {
    sk: [u8; 32],
    pk: [u8; 32],
}

impl SecureStaticKeys {
    fn from_secret(sk: [u8; 32]) -> Self {
        let pk = curve25519_dalek::montgomery::MontgomeryPoint::mul_base_clamped(sk).0;
        SecureStaticKeys { sk, pk }
    }

    fn random() -> Self {
        let mut sk = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut sk);
        Self::from_secret(sk)
    }
}

fn secure_x25519_dh(sk: &[u8; 32], peer: &[u8; 32]) -> Result<[u8; 32]> {
    let shared = curve25519_dalek::montgomery::MontgomeryPoint(*peer)
        .mul_clamped(*sk)
        .0;
    if shared.iter().all(|&b| b == 0) {
        return Err(Error::crypto(
            "easytier: X25519 peer key is a low-order point",
        ));
    }
    Ok(shared)
}

// -- HMAC-SHA256 + the Noise HKDF --------------------------------------------

type SecureHmac = hmac::Hmac<sha2::Sha256>;

fn hmac_sha256(key: &[u8], msg_parts: &[&[u8]]) -> [u8; 32] {
    let mut mac = <SecureHmac as hmac::Mac>::new_from_slice(key).expect("hmac accepts any key");
    for part in msg_parts {
        mac.update(part);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// `SHA256(a || b)` — the Noise `MixHash` primitive.
fn sha256_concat(a: &[u8], b: &[u8]) -> [u8; 32] {
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(a);
    hasher.update(b);
    hasher.finalize().into()
}

/// The Noise `HKDF(chaining_key, ikm, 2)` of `MixKey` (snow's
/// `hkdf` helper, RFC 5869 with the ck as the key): `temp = HMAC(ck, ikm)`,
/// `out1 = HMAC(temp, 0x01)` (the new ck), `out2 = HMAC(temp, out1 || 0x02)`
/// (the new k).
fn noise_hkdf2(ck: &[u8; 32], ikm: &[u8]) -> ([u8; 32], [u8; 32]) {
    let temp = hmac_sha256(ck, &[ikm]);
    let out1 = hmac_sha256(&temp, &[&[0x01]]);
    let out2 = hmac_sha256(&temp, &[&out1, &[0x02]]);
    (out1, out2)
}

/// `get_secret_proof` (global_ctx.rs:476-483): the network-secret proof is
/// `HMAC-SHA256(network_secret, "easytier secret proof" || challenge)` —
/// the challenge is the Noise handshake hash at the point each side
/// captured it.
fn secret_proof(network_secret: &str, challenge: &[u8]) -> [u8; 32] {
    hmac_sha256(
        network_secret.as_bytes(),
        &[b"easytier secret proof", challenge],
    )
}

// -- Noise_XX_25519_ChaChaPoly_SHA256 ----------------------------------------

/// One side of the `Noise_XX` handshake, hand-rolled after snow's
/// `HandshakeState` (the engine's second hand-rolled Noise pattern —
/// wireguard.rs owns IKpsk2). The XX pattern is:
///
/// ```text
/// -> e
/// <- e, ee, s, es
/// -> s, se
/// ```
///
/// msg1 carries its payload in the clear (no DH yet, so the cipherstate
/// has no key); from msg2 on every static and payload is ChaChaPoly-sealed
/// with the running chain key, AAD = the handshake hash before the token.
struct NoiseXxHandshake {
    /// `h` — the running handshake hash.
    h: [u8; 32],
    /// `ck` — the chaining key.
    ck: [u8; 32],
    /// `k` — the current message key (`None` until the first DH).
    k: Option<[u8; 32]>,
    /// `n` — the nonce counter of `k` (Noise uses 32 zero bits || u64 LE).
    n: u64,
    /// Our static (`s`).
    s: SecureStaticKeys,
    /// Our ephemeral (`e`), generated when the first message is written.
    e: Option<SecureStaticKeys>,
    /// Their ephemeral (`re`).
    re: Option<[u8; 32]>,
    /// Their static (`rs`) — learned in msg2 (initiator) / msg3 (responder).
    rs: Option<[u8; 32]>,
}

impl NoiseXxHandshake {
    /// `Initialize` for "Noise_XX_25519_ChaChaPoly_SHA256" with our static:
    /// the protocol name is exactly 32 bytes, then the (empty for XX) DH
    /// prelude and the prologue are mixed in.
    fn new(static_keys: SecureStaticKeys) -> Self {
        let name = b"Noise_XX_25519_ChaChaPoly_SHA256";
        let mut h = [0u8; 32];
        h[..name.len()].copy_from_slice(name);
        let mut hs = NoiseXxHandshake {
            h,
            ck: h,
            k: None,
            n: 0,
            s: static_keys,
            e: None,
            re: None,
            rs: None,
        };
        hs.mix_hash(NOISE_PROLOGUE);
        hs
    }

    fn mix_hash(&mut self, data: &[u8]) {
        self.h = sha256_concat(&self.h, data);
    }

    fn mix_key(&mut self, ikim: &[u8]) {
        let (ck, k) = noise_hkdf2(&self.ck, ikim);
        self.ck = ck;
        self.k = Some(k);
        self.n = 0;
    }

    /// `EncryptAndHash` with an explicit key slot: ChaCha20-Poly1305,
    /// nonce `0^4 || u64 LE counter`, AAD = `h` before this step, then
    /// `MixHash(ciphertext)`. With no key yet the payload is appended in
    /// the clear (Noise spec 5.2, `EncryptWithAd` with `HasKey() ==
    /// false`).
    fn encrypt_and_hash(&mut self, plaintext: &[u8]) -> Vec<u8> {
        if let Some(key) = self.k {
            let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("32-byte key");
            let mut nonce = [0u8; 12];
            nonce[4..].copy_from_slice(&self.n.to_le_bytes());
            self.n += 1;
            let ct = cipher
                .encrypt(
                    (&nonce).into(),
                    aes_gcm::aead::Payload {
                        msg: plaintext,
                        aad: &self.h,
                    },
                )
                .expect("chacha20poly1305 seal");
            self.mix_hash(&ct);
            ct
        } else {
            let ct = plaintext.to_vec();
            self.mix_hash(&ct);
            ct
        }
    }

    /// `DecryptAndHash` — the inverse; `None` maps the empty-key clear
    /// payload, `Some` a sealed one.
    fn decrypt_and_hash(&mut self, ciphertext: &[u8]) -> Result<Option<Vec<u8>>> {
        let Some(key) = self.k else {
            self.mix_hash(ciphertext);
            return Ok(None);
        };
        let cipher = ChaCha20Poly1305::new_from_slice(&key).expect("32-byte key");
        let mut nonce = [0u8; 12];
        nonce[4..].copy_from_slice(&self.n.to_le_bytes());
        self.n += 1;
        let pt = cipher
            .decrypt(
                (&nonce).into(),
                aes_gcm::aead::Payload {
                    msg: ciphertext,
                    aad: &self.h,
                },
            )
            .map_err(|_| Error::crypto("easytier: noise read msg failed: decrypt failed"))?;
        self.mix_hash(ciphertext);
        Ok(Some(pt))
    }

    /// msg1 `-> e`: 32-byte ephemeral + the clear payload.
    fn write_msg1(&mut self, payload: &[u8]) -> Vec<u8> {
        let e = SecureStaticKeys::random();
        self.mix_hash(&e.pk);
        let e_pk = e.pk;
        self.e = Some(e);
        let mut out = Vec::with_capacity(32 + payload.len());
        out.extend_from_slice(&e_pk);
        out.extend_from_slice(&self.encrypt_and_hash(payload));
        out
    }

    /// msg1 read: the ephemeral + the clear payload.
    fn read_msg1(&mut self, wire: &[u8]) -> Result<Vec<u8>> {
        if wire.len() < 32 {
            return Err(Error::protocol("easytier: noise msg1 too short"));
        }
        let (e, rest) = wire.split_at(32);
        let mut re = [0u8; 32];
        re.copy_from_slice(e);
        self.mix_hash(&re);
        self.re = Some(re);
        match self.decrypt_and_hash(rest)? {
            // No key in msg1: `None` means the payload was clear.
            None => Ok(rest.to_vec()),
            Some(pt) => Ok(pt),
        }
    }

    /// msg2 `<- e, ee, s, es` (responder writes, initiator reads).
    fn write_msg2(&mut self, payload: &[u8]) -> Vec<u8> {
        let e = SecureStaticKeys::random();
        self.mix_hash(&e.pk);
        let re = self.re.expect("msg2 needs the peer ephemeral");
        let e_pk = e.pk;
        let e_sk = e.sk;
        self.e = Some(e);
        let ee = secure_x25519_dh(&e_sk, &re).expect("fresh ephemeral");
        self.mix_key(&ee);
        let mut out = Vec::with_capacity(32 + 48 + 16 + payload.len());
        out.extend_from_slice(&e_pk);
        let s_pk = self.s.pk;
        out.extend_from_slice(&self.encrypt_and_hash(&s_pk)); // s (48B)
        let s_sk = self.s.sk;
        let se = secure_x25519_dh(&s_sk, &re).expect("static dh");
        self.mix_key(&se); // es (responder: DH(s, re))
        out.extend_from_slice(&self.encrypt_and_hash(payload));
        out
    }

    /// The msg2 read side: the sealed payload.
    fn read_msg2(&mut self, wire: &[u8]) -> Result<Vec<u8>> {
        if wire.len() < 32 + 48 {
            return Err(Error::protocol("easytier: noise msg2 too short"));
        }
        let (e, rest) = wire.split_at(32);
        let mut re = [0u8; 32];
        re.copy_from_slice(e);
        self.mix_hash(&re);
        self.re = Some(re);
        // ee: DH(our msg1 ephemeral, their msg2 ephemeral).
        let e_sk = self.e.as_ref().expect("initiator wrote msg1").sk;
        let ee = secure_x25519_dh(&e_sk, &re)?;
        self.mix_key(&ee);
        let (s_ct, payload_ct) = rest.split_at(48);
        let s_pt = self
            .decrypt_and_hash(s_ct)?
            .ok_or_else(|| Error::protocol("easytier: noise msg2 static was not sealed"))?;
        let mut rs = [0u8; 32];
        rs.copy_from_slice(&s_pt);
        self.rs = Some(rs);
        // es (responder wrote DH(s_responder, e_initiator); we compute
        // DH(s_theirs, e_ours)) — same shared secret.
        let se = secure_x25519_dh(&e_sk, &rs)?;
        self.mix_key(&se);
        self.decrypt_and_hash(payload_ct)?
            .ok_or_else(|| Error::protocol("easytier: noise msg2 payload was not sealed"))
    }

    /// msg3 `-> s, se` (initiator writes, responder reads).
    fn write_msg3(&mut self, payload: &[u8]) -> Vec<u8> {
        let re = self.re.expect("msg3 needs the peer ephemeral");
        let mut out = Vec::with_capacity(48 + 16 + payload.len());
        let s_pk = self.s.pk;
        out.extend_from_slice(&self.encrypt_and_hash(&s_pk)); // s (48B)
        let s_sk = self.s.sk;
        let se = secure_x25519_dh(&s_sk, &re).expect("static dh"); // se (initiator: DH(s, re))
        self.mix_key(&se);
        out.extend_from_slice(&self.encrypt_and_hash(payload));
        out
    }

    fn read_msg3(&mut self, wire: &[u8]) -> Result<Vec<u8>> {
        if wire.len() < 48 {
            return Err(Error::protocol("easytier: noise msg3 too short"));
        }
        let (s_ct, payload_ct) = wire.split_at(48);
        let s_pt = self
            .decrypt_and_hash(s_ct)?
            .ok_or_else(|| Error::protocol("easytier: noise msg3 static was not sealed"))?;
        let mut rs = [0u8; 32];
        rs.copy_from_slice(&s_pt);
        self.rs = Some(rs);
        // se (initiator wrote DH(s_initiator, e_responder)); we compute
        // DH(s_theirs, e_ours).
        let e_sk = self.e.as_ref().expect("responder wrote msg2").sk;
        let se = secure_x25519_dh(&e_sk, &rs)?;
        self.mix_key(&se);
        self.decrypt_and_hash(payload_ct)?
            .ok_or_else(|| Error::protocol("easytier: noise msg3 payload was not sealed"))
    }

    /// `get_handshake_hash()` — the challenge domain of the secret proofs.
    fn handshake_hash(&self) -> [u8; 32] {
        self.h
    }

    /// `get_remote_static()`.
    fn remote_static(&self) -> Option<[u8; 32]> {
        self.rs
    }
}

// -- The noise wire messages (peer_rpc.proto:328-386) -------------------------

/// `PeerConnSessionActionPb` (peer_rpc.proto:334-338).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerConnSessionAction {
    Join,
    Sync,
    Create,
}

impl PeerConnSessionAction {
    fn from_wire(value: u32) -> Result<Self> {
        match value {
            0 => Ok(Self::Join),
            1 => Ok(Self::Sync),
            2 => Ok(Self::Create),
            _ => Err(Error::protocol("easytier: invalid session action")),
        }
    }

    fn to_wire(self) -> u32 {
        match self {
            Self::Join => 0,
            Self::Sync => 1,
            Self::Create => 2,
        }
    }
}

/// `common.UUID` (common.proto:139-144): four u32 varint fields holding
/// the 128 bits big-endian (`From<uuid::Uuid>`, common.rs:14-24).
fn uuid_wire_parts(id: uuid::Uuid) -> [u32; 4] {
    let (high, low) = id.as_u64_pair();
    [
        (high >> 32) as u32,
        (high & 0xFFFF_FFFF) as u32,
        (low >> 32) as u32,
        (low & 0xFFFF_FFFF) as u32,
    ]
}

fn uuid_from_wire_parts(parts: [u32; 4]) -> uuid::Uuid {
    uuid::Uuid::from_u64_pair(
        (u64::from(parts[0]) << 32) | u64::from(parts[1]),
        (u64::from(parts[2]) << 32) | u64::from(parts[3]),
    )
}

fn proto_put_u32_field(out: &mut Vec<u8>, field: u32, value: u32) {
    proto_put_varint(out, (field << 3) as u64);
    proto_put_varint(out, value as u64);
}

fn proto_put_message_field(out: &mut Vec<u8>, field: u32, body: &[u8]) {
    proto_put_varint(out, ((field << 3) | 2) as u64);
    proto_put_varint(out, body.len() as u64);
    out.extend_from_slice(body);
}

fn proto_encode_uuid(id: uuid::Uuid) -> Vec<u8> {
    let mut out = Vec::with_capacity(20);
    for (i, part) in uuid_wire_parts(id).into_iter().enumerate() {
        proto_put_u32_field(&mut out, i as u32 + 1, part);
    }
    out
}

/// Decode four u32 varint fields (part1..part4) out of a nested UUID
/// message; unknown fields are skipped.
fn proto_decode_uuid(buf: &[u8]) -> Result<uuid::Uuid> {
    let mut reader = ProtoReader { buf, pos: 0 };
    let mut parts = [0u32; 4];
    while reader.pos < buf.len() {
        let tag = reader.varint()?;
        let field = (tag >> 3) as u32;
        let wire_type = tag & 7;
        match (field, wire_type) {
            (1..=4, 0) => {
                let value = reader.varint()? as u32;
                parts[(field - 1) as usize] = value;
            }
            _ => reader.skip(wire_type)?,
        }
    }
    Ok(uuid_from_wire_parts(parts))
}

/// `PeerConnNoiseMsg1Pb` (peer_rpc.proto:343-349).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoiseMsg1 {
    pub version: u32,
    pub a_network_name: String,
    pub a_session_generation: Option<u32>,
    pub a_conn_id: uuid::Uuid,
    pub client_encryption_algorithm: String,
}

impl NoiseMsg1 {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        proto_put_u32_field(&mut out, 1, self.version);
        proto_put_len_field(&mut out, 2, self.a_network_name.as_bytes());
        if let Some(gen) = self.a_session_generation {
            proto_put_u32_field(&mut out, 3, gen);
        }
        proto_put_message_field(&mut out, 4, &proto_encode_uuid(self.a_conn_id));
        proto_put_len_field(&mut out, 5, self.client_encryption_algorithm.as_bytes());
        out
    }

    fn decode(buf: &[u8]) -> Result<Self> {
        let mut reader = ProtoReader { buf, pos: 0 };
        let mut msg = NoiseMsg1 {
            version: 0,
            a_network_name: String::new(),
            a_session_generation: None,
            a_conn_id: uuid::Uuid::default(),
            client_encryption_algorithm: String::new(),
        };
        while reader.pos < buf.len() {
            let tag = reader.varint()?;
            let field = (tag >> 3) as u32;
            let wire_type = tag & 7;
            match (field, wire_type) {
                (1, 0) => msg.version = reader.varint()? as u32,
                (2, 2) => {
                    msg.a_network_name = String::from_utf8_lossy(reader.len_bytes()?).into_owned()
                }
                (3, 0) => msg.a_session_generation = Some(reader.varint()? as u32),
                (4, 2) => msg.a_conn_id = proto_decode_uuid(reader.len_bytes()?)?,
                (5, 2) => {
                    msg.client_encryption_algorithm =
                        String::from_utf8_lossy(reader.len_bytes()?).into_owned()
                }
                _ => reader.skip(wire_type)?,
            }
        }
        Ok(msg)
    }
}

/// `PeerConnNoiseMsg2Pb` (peer_rpc.proto:351-362).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoiseMsg2 {
    pub b_network_name: String,
    pub role_hint: u32,
    pub action: PeerConnSessionAction,
    pub b_session_generation: u32,
    pub root_key_32: Option<[u8; 32]>,
    pub initial_epoch: u32,
    pub b_conn_id: uuid::Uuid,
    pub a_conn_id_echo: Option<uuid::Uuid>,
    pub secret_proof_32: Option<Vec<u8>>,
    pub server_encryption_algorithm: String,
}

impl NoiseMsg2 {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(160);
        proto_put_len_field(&mut out, 1, self.b_network_name.as_bytes());
        proto_put_u32_field(&mut out, 2, self.role_hint);
        proto_put_u32_field(&mut out, 3, self.action.to_wire());
        proto_put_u32_field(&mut out, 4, self.b_session_generation);
        if let Some(root) = &self.root_key_32 {
            proto_put_len_field(&mut out, 5, root);
        }
        proto_put_u32_field(&mut out, 6, self.initial_epoch);
        proto_put_message_field(&mut out, 7, &proto_encode_uuid(self.b_conn_id));
        if let Some(echo) = self.a_conn_id_echo {
            proto_put_message_field(&mut out, 8, &proto_encode_uuid(echo));
        }
        if let Some(proof) = &self.secret_proof_32 {
            proto_put_len_field(&mut out, 9, proof);
        }
        proto_put_len_field(&mut out, 10, self.server_encryption_algorithm.as_bytes());
        out
    }

    fn decode(buf: &[u8]) -> Result<Self> {
        let mut reader = ProtoReader { buf, pos: 0 };
        let mut msg = NoiseMsg2 {
            b_network_name: String::new(),
            role_hint: 0,
            action: PeerConnSessionAction::Join,
            b_session_generation: 0,
            root_key_32: None,
            initial_epoch: 0,
            b_conn_id: uuid::Uuid::default(),
            a_conn_id_echo: None,
            secret_proof_32: None,
            server_encryption_algorithm: String::new(),
        };
        while reader.pos < buf.len() {
            let tag = reader.varint()?;
            let field = (tag >> 3) as u32;
            let wire_type = tag & 7;
            match (field, wire_type) {
                (1, 2) => {
                    msg.b_network_name = String::from_utf8_lossy(reader.len_bytes()?).into_owned()
                }
                (2, 0) => msg.role_hint = reader.varint()? as u32,
                (3, 0) => msg.action = PeerConnSessionAction::from_wire(reader.varint()? as u32)?,
                (4, 0) => msg.b_session_generation = reader.varint()? as u32,
                (5, 2) => {
                    let bytes = reader.len_bytes()?;
                    if bytes.len() == 32 {
                        let mut key = [0u8; 32];
                        key.copy_from_slice(bytes);
                        msg.root_key_32 = Some(key);
                    }
                }
                (6, 0) => msg.initial_epoch = reader.varint()? as u32,
                (7, 2) => msg.b_conn_id = proto_decode_uuid(reader.len_bytes()?)?,
                (8, 2) => msg.a_conn_id_echo = Some(proto_decode_uuid(reader.len_bytes()?)?),
                (9, 2) => msg.secret_proof_32 = Some(reader.len_bytes()?.to_vec()),
                (10, 2) => {
                    msg.server_encryption_algorithm =
                        String::from_utf8_lossy(reader.len_bytes()?).into_owned()
                }
                _ => reader.skip(wire_type)?,
            }
        }
        Ok(msg)
    }
}

/// `PeerConnNoiseMsg3Pb` (peer_rpc.proto:381-386).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NoiseMsg3 {
    pub a_conn_id_echo: uuid::Uuid,
    pub b_conn_id_echo: uuid::Uuid,
    pub secret_proof_32: Option<Vec<u8>>,
    pub secret_digest: Vec<u8>,
}

impl NoiseMsg3 {
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(120);
        proto_put_message_field(&mut out, 1, &proto_encode_uuid(self.a_conn_id_echo));
        proto_put_message_field(&mut out, 2, &proto_encode_uuid(self.b_conn_id_echo));
        if let Some(proof) = &self.secret_proof_32 {
            proto_put_len_field(&mut out, 3, proof);
        }
        proto_put_len_field(&mut out, 4, &self.secret_digest);
        out
    }

    fn decode(buf: &[u8]) -> Result<Self> {
        let mut reader = ProtoReader { buf, pos: 0 };
        let mut msg = NoiseMsg3 {
            a_conn_id_echo: uuid::Uuid::default(),
            b_conn_id_echo: uuid::Uuid::default(),
            secret_proof_32: None,
            secret_digest: Vec::new(),
        };
        while reader.pos < buf.len() {
            let tag = reader.varint()?;
            let field = (tag >> 3) as u32;
            let wire_type = tag & 7;
            match (field, wire_type) {
                (1, 2) => msg.a_conn_id_echo = proto_decode_uuid(reader.len_bytes()?)?,
                (2, 2) => msg.b_conn_id_echo = proto_decode_uuid(reader.len_bytes()?)?,
                (3, 2) => msg.secret_proof_32 = Some(reader.len_bytes()?.to_vec()),
                (4, 2) => msg.secret_digest = reader.len_bytes()?.to_vec(),
                _ => reader.skip(wire_type)?,
            }
        }
        Ok(msg)
    }
}

// -- The session AEAD (secure_datagram.rs, the load-bearing subset) ----------

/// `SecureDatagramDirection` (secure_datagram.rs:23-36): the traffic
/// direction of one packet, agreed by both sides from the peer-id order
/// (`PeerSession::dir_for_sender`: sender < receiver -> AToB).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureDirection {
    AToB,
    BToA,
}

impl SecureDirection {
    fn idx(self) -> usize {
        match self {
            Self::AToB => 0,
            Self::BToA => 1,
        }
    }
}

/// `ReplayWindow256` (secure_datagram.rs:67-161): a sliding 256-bit
/// bitmap over sequence numbers below `max_seq`; new maxima shift the
/// window, old duplicates are rejected.
#[derive(Debug, Clone, Copy, Default)]
struct ReplayWindow256 {
    max_seq: u64,
    bitmap: [u8; 32],
    valid: bool,
}

impl ReplayWindow256 {
    fn test_bit(&self, idx: usize) -> bool {
        (self.bitmap[idx / 8] >> (idx % 8)) & 1 == 1
    }

    fn set_bit(&mut self, idx: usize) {
        self.bitmap[idx / 8] |= 1u8 << (idx % 8);
    }

    fn shift_right(&mut self, shift: usize) {
        if shift == 0 {
            return;
        }
        if shift >= 256 {
            self.bitmap.fill(0);
            return;
        }
        let byte_shift = shift / 8;
        let bit_shift = shift % 8;
        if byte_shift > 0 {
            for i in (0..self.bitmap.len()).rev() {
                self.bitmap[i] = if i >= byte_shift {
                    self.bitmap[i - byte_shift]
                } else {
                    0
                };
            }
        }
        if bit_shift > 0 {
            let mut carry = 0u8;
            for b in self.bitmap.iter_mut() {
                let new_carry = *b >> (8 - bit_shift);
                *b = (*b << bit_shift) | carry;
                carry = new_carry;
            }
        }
    }

    fn accept(&mut self, seq: u64) -> bool {
        if !self.valid {
            self.valid = true;
            self.max_seq = seq;
            self.set_bit(0);
            return true;
        }
        if seq > self.max_seq {
            let shift = (seq - self.max_seq) as usize;
            self.shift_right(shift);
            self.max_seq = seq;
            self.set_bit(0);
            return true;
        }
        let delta = (self.max_seq - seq) as usize;
        if delta >= 256 || self.test_bit(delta) {
            return false;
        }
        self.set_bit(delta);
        true
    }

    fn can_accept(&self, seq: u64) -> bool {
        if !self.valid || seq > self.max_seq {
            return true;
        }
        let delta = (self.max_seq - seq) as usize;
        delta < 256 && !self.test_bit(delta)
    }
}

/// `EpochRxSlot` (secure_datagram.rs:163-178): one direction's replay
/// state for one epoch, with the idle-eviction timestamp.
#[derive(Debug, Clone, Copy, Default)]
struct EpochRxSlot {
    epoch: u32,
    window: ReplayWindow256,
    last_rx_ms: u64,
    valid: bool,
}

impl EpochRxSlot {
    fn clear(&mut self) {
        *self = Self::default();
    }
}

/// `SyncRxGrace` (secure_datagram.rs:180-205): a snapshot of the rx
/// slots kept valid for five seconds across a root-key sync, so in-flight
/// packets from the pre-sync epochs still decrypt.
#[derive(Debug, Clone, Copy, Default)]
struct SyncRxGrace {
    slots: [[EpochRxSlot; 2]; 2],
    expires_at_ms: u64,
    valid: bool,
}

impl SyncRxGrace {
    fn clear(&mut self) {
        *self = Self::default();
    }

    fn refresh(&mut self, slots: [[EpochRxSlot; 2]; 2], expires_at_ms: u64) {
        self.slots = slots;
        self.expires_at_ms = expires_at_ms;
        self.valid = true;
    }

    fn maybe_expire(&mut self, now_ms: u64) {
        if self.valid && now_ms >= self.expires_at_ms {
            self.clear();
        }
    }
}

fn secure_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// One cached (epoch, generation) cipher pair of a direction
/// (`EpochKeySlot`, secure_datagram.rs:38-65).
struct EpochKeySlot {
    epoch: u32,
    generation: u32,
    valid: bool,
    send_cipher: Arc<PacketEncryptor>,
    recv_cipher: Arc<PacketEncryptor>,
}

/// `SecureDatagramSession` (secure_datagram.rs:207-771) — the payload
/// layer every post-handshake packet crosses:
///
/// * **Traffic keys** are epoch-keyed: `hkdf_traffic_key` extracts
///   `HMAC-SHA256(0^32, root_key)` then expands
///   `HMAC(prk, "et-traffic" || epoch_be || dir || 0x01)` — one 32-byte
///   key per (epoch, direction); the send nonce is `epoch_be(4) ||
///   seq_be(8)`, so the receiver reads the epoch straight out of the
///   AEAD tail and never needs a counter sync.
/// * **Replay** is a `ReplayWindow256` per direction, at most two recent
///   rx epochs live (`MAX_ACCEPTED_RX_EPOCH_AHEAD` bounds far-future
///   epochs without poisoning the window); a root-key sync snapshots the
///   rx slots for the 5s grace window.
/// * **Rotation** bumps the send epoch after a million packets or ten
///   minutes; the receive side accepts any epoch within the ahead bound.
/// * **Failure containment**: ten consecutive decrypt failures
///   invalidate the session — the connection closes and re-handshakes.
pub struct SecureDatagramSession {
    root_key: StdMutex<[u8; 32]>,
    session_generation: AtomicU32,
    send_epoch: AtomicU32,
    send_seq: [AtomicU64; 2],
    send_epoch_started_ms: AtomicU64,
    send_packets_since_epoch: AtomicU64,
    rx_slots: StdMutex<[[EpochRxSlot; 2]; 2]>,
    key_cache: StdMutex<[[Option<EpochKeySlot>; 2]; 2]>,
    sync_rx_grace: StdMutex<SyncRxGrace>,
    sync_rx_grace_expires_at_ms: AtomicU64,
    send_cipher_algorithm: String,
    recv_cipher_algorithm: String,
    invalidated: AtomicU32,
    decrypt_fail_count: AtomicU32,
}

impl SecureDatagramSession {
    /// `SecureDatagramSession::new` (secure_datagram.rs:258-290).
    pub fn new(
        root_key: [u8; 32],
        session_generation: u32,
        initial_epoch: u32,
        send_cipher_algorithm: String,
        recv_cipher_algorithm: String,
    ) -> Self {
        Self {
            root_key: StdMutex::new(root_key),
            session_generation: AtomicU32::new(session_generation),
            send_epoch: AtomicU32::new(initial_epoch),
            send_seq: [AtomicU64::new(0), AtomicU64::new(0)],
            send_epoch_started_ms: AtomicU64::new(secure_now_ms()),
            send_packets_since_epoch: AtomicU64::new(0),
            rx_slots: StdMutex::new([[EpochRxSlot::default(), EpochRxSlot::default()]; 2]),
            key_cache: StdMutex::new([[None, None], [None, None]]),
            sync_rx_grace: StdMutex::new(SyncRxGrace::default()),
            sync_rx_grace_expires_at_ms: AtomicU64::new(0),
            send_cipher_algorithm,
            recv_cipher_algorithm,
            invalidated: AtomicU32::new(0),
            decrypt_fail_count: AtomicU32::new(0),
        }
    }

    pub fn invalidate(&self) {
        self.invalidated.store(1, Ordering::Relaxed);
    }

    pub fn is_valid(&self) -> bool {
        self.invalidated.load(Ordering::Relaxed) == 0
    }

    pub fn session_generation(&self) -> u32 {
        self.session_generation.load(Ordering::Relaxed)
    }

    fn root_key(&self) -> [u8; 32] {
        *self.root_key.lock().unwrap()
    }

    /// `new_root_key` (secure_datagram.rs:308-312): 32 random bytes.
    pub fn new_root_key() -> [u8; 32] {
        let mut out = [0u8; 32];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut out);
        out
    }

    /// `next_sync_epoch` (secure_datagram.rs:314-329): the epoch a Sync
    /// resync restarts at — one past everything seen or sent.
    pub fn next_sync_epoch(&self) -> u32 {
        let send_epoch = self.send_epoch.load(Ordering::Relaxed);
        let rx = self.rx_slots.lock().unwrap();
        let mut max_epoch = send_epoch;
        for dir in 0..2 {
            for slot in &rx[dir] {
                if slot.valid {
                    max_epoch = max_epoch.max(slot.epoch);
                }
            }
        }
        max_epoch.wrapping_add(1)
    }

    /// `check_encrypt_algo_same` (secure_datagram.rs:331-342).
    pub fn check_encrypt_algo_same(&self, send: &str, recv: &str) -> Result<()> {
        if self.send_cipher_algorithm != send || self.recv_cipher_algorithm != recv {
            return Err(Error::protocol("easytier: encrypt algorithm not same"));
        }
        Ok(())
    }

    /// `sync_root_key` (secure_datagram.rs:344-389): install a new
    /// (root key, generation, initial epoch), reset the send side, clear
    /// the rx slots — keeping the pre-sync rx epochs valid for the grace
    /// window when the key itself did not change
    /// (`preserve_rx_grace && old == new`).
    pub fn sync_root_key(
        &self,
        root_key: [u8; 32],
        session_generation: u32,
        initial_epoch: u32,
        preserve_rx_grace: bool,
    ) {
        let old_root_key = self.root_key();
        let can_preserve_rx_grace = preserve_rx_grace && old_root_key == root_key;
        *self.root_key.lock().unwrap() = root_key;
        self.session_generation
            .store(session_generation, Ordering::Relaxed);
        self.send_epoch.store(initial_epoch, Ordering::Relaxed);
        self.send_seq[0].store(0, Ordering::Relaxed);
        self.send_seq[1].store(0, Ordering::Relaxed);
        self.send_epoch_started_ms
            .store(secure_now_ms(), Ordering::Relaxed);
        self.send_packets_since_epoch.store(0, Ordering::Relaxed);
        {
            let mut rx = self.rx_slots.lock().unwrap();
            let mut sync_rx_grace = self.sync_rx_grace.lock().unwrap();
            if can_preserve_rx_grace {
                let expires_at_ms = secure_now_ms().saturating_add(SYNC_RX_GRACE_AFTER_MS);
                sync_rx_grace.refresh(*rx, expires_at_ms);
                self.sync_rx_grace_expires_at_ms
                    .store(expires_at_ms, Ordering::Relaxed);
            } else {
                sync_rx_grace.clear();
                self.sync_rx_grace_expires_at_ms.store(0, Ordering::Relaxed);
            }
            for dir in 0..2 {
                rx[dir][0].clear();
                rx[dir][1].clear();
            }
        }
        for dir_slots in self.key_cache.lock().unwrap().iter_mut() {
            *dir_slots = [None, None];
        }
    }

    /// `hkdf_traffic_key` (secure_datagram.rs:391-410).
    fn hkdf_traffic_key(&self, epoch: u32, dir: SecureDirection) -> [u8; 32] {
        let root_key = self.root_key();
        let prk = hmac_sha256(&[0u8; 32], &[&root_key]);
        let mut info = Vec::with_capacity(13);
        info.extend_from_slice(b"et-traffic");
        info.extend_from_slice(&epoch.to_be_bytes());
        info.push(dir.idx() as u8);
        hmac_sha256(&prk, &[&info, &[1u8]])
    }

    /// `create_encryptor` keyed from the HKDF output (the raw-key arm of
    /// peers/encrypt/mod.rs:60-107: aes-gcm takes key[..16],
    /// aes-256-gcm/chacha20 the full 32 bytes).
    fn cipher_for(algorithm: &str, key: &[u8; 32]) -> Result<PacketEncryptor> {
        let mut key_128 = [0u8; 16];
        key_128.copy_from_slice(&key[..16]);
        let Ok(algorithm) = algorithm.parse::<EncryptionAlgorithm>() else {
            return Err(Error::config(format!(
                "easytier: invalid encryption algorithm: {algorithm}"
            )));
        };
        let cipher = match algorithm {
            EncryptionAlgorithm::Xor => Cipher::Xor(key_128.to_vec()),
            EncryptionAlgorithm::AesGcm => Cipher::Aes128Gcm(Box::new(
                Aes128Gcm::new_from_slice(&key_128).expect("128-bit key"),
            )),
            EncryptionAlgorithm::Aes256Gcm => Cipher::Aes256Gcm(Box::new(
                Aes256Gcm::new_from_slice(key).expect("256-bit key"),
            )),
            EncryptionAlgorithm::ChaCha20 => Cipher::ChaCha20(Box::new(
                ChaCha20Poly1305::new_from_slice(key).expect("256-bit key"),
            )),
        };
        Ok(PacketEncryptor { cipher })
    }

    /// `get_or_create_encryptor` (secure_datagram.rs:412-447): a two-slot
    /// cache per direction (current + previous epoch).
    fn get_or_create_cipher(
        &self,
        epoch: u32,
        dir: SecureDirection,
        generation: u32,
        is_send: bool,
    ) -> Result<Arc<PacketEncryptor>> {
        let dir_idx = dir.idx();
        let mut guard = self.key_cache.lock().unwrap();
        for slot in guard[dir_idx].iter_mut().flatten() {
            if slot.valid && slot.epoch == epoch && slot.generation == generation {
                return Ok(if is_send {
                    slot.send_cipher.clone()
                } else {
                    slot.recv_cipher.clone()
                });
            }
        }
        let key = self.hkdf_traffic_key(epoch, dir);
        let slot = EpochKeySlot {
            epoch,
            generation,
            valid: true,
            send_cipher: Arc::new(Self::cipher_for(&self.send_cipher_algorithm, &key)?),
            recv_cipher: Arc::new(Self::cipher_for(&self.recv_cipher_algorithm, &key)?),
        };
        let ret = if is_send {
            slot.send_cipher.clone()
        } else {
            slot.recv_cipher.clone()
        };
        if guard[dir_idx][0].as_ref().is_none_or(|s| s.epoch == epoch) {
            guard[dir_idx][0] = Some(slot);
        } else {
            guard[dir_idx][1] = Some(slot);
        }
        Ok(ret)
    }

    /// `maybe_rotate_epoch` (secure_datagram.rs:449-471).
    fn maybe_rotate_epoch(&self, now_ms: u64) {
        let packets = self
            .send_packets_since_epoch
            .fetch_add(1, Ordering::Relaxed)
            + 1;
        let started = self.send_epoch_started_ms.load(Ordering::Relaxed);
        if packets < EPOCH_ROTATE_AFTER_PACKETS
            && now_ms.saturating_sub(started) < EPOCH_ROTATE_AFTER_MS
        {
            return;
        }
        let cur = self.send_epoch.load(Ordering::Relaxed);
        let next = cur.wrapping_add(1);
        if self
            .send_epoch
            .compare_exchange(cur, next, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            self.send_epoch_started_ms.store(now_ms, Ordering::Relaxed);
            self.send_packets_since_epoch.store(0, Ordering::Relaxed);
        }
    }

    /// `next_nonce` (secure_datagram.rs:473-482): the epoch goes to the
    /// nonce AND to the derived key, so the receiver can address the
    /// right cipher without any sync.
    fn next_nonce(&self, dir: SecureDirection) -> (u32, u64, [u8; 12]) {
        let now_ms = secure_now_ms();
        self.maybe_rotate_epoch(now_ms);
        let epoch = self.send_epoch.load(Ordering::Relaxed);
        let seq = self.send_seq[dir.idx()].fetch_add(1, Ordering::Relaxed);
        let mut nonce = [0u8; 12];
        nonce[..4].copy_from_slice(&epoch.to_be_bytes());
        nonce[4..].copy_from_slice(&seq.to_be_bytes());
        (epoch, seq, nonce)
    }

    fn evict_old_rx_slots(rx: &mut [[EpochRxSlot; 2]; 2], now_ms: u64) {
        for dir_slots in rx.iter_mut() {
            for slot in dir_slots.iter_mut() {
                if slot.valid
                    && slot.last_rx_ms != 0
                    && now_ms.saturating_sub(slot.last_rx_ms) > RX_SLOT_EVICT_AFTER_MS
                {
                    slot.clear();
                }
            }
        }
    }

    fn epoch_in_slots(slots: &[EpochRxSlot; 2], epoch: u32) -> bool {
        slots[0].valid && slots[0].epoch == epoch || slots[1].valid && slots[1].epoch == epoch
    }

    fn sync_rx_grace_active(&self, now_ms: u64) -> bool {
        let expires_at_ms = self.sync_rx_grace_expires_at_ms.load(Ordering::Relaxed);
        if expires_at_ms == 0 {
            return false;
        }
        if now_ms < expires_at_ms {
            return true;
        }
        self.sync_rx_grace_expires_at_ms.store(0, Ordering::Relaxed);
        false
    }

    fn take_sync_rx_grace(&self, now_ms: u64) -> Option<SyncRxGrace> {
        if !self.sync_rx_grace_active(now_ms) {
            return None;
        }
        let mut grace = self.sync_rx_grace.lock().unwrap();
        grace.maybe_expire(now_ms);
        if grace.valid {
            Self::evict_old_rx_slots(&mut grace.slots, now_ms);
            Some(*grace)
        } else {
            self.sync_rx_grace_expires_at_ms.store(0, Ordering::Relaxed);
            None
        }
    }

    /// `prune_key_cache` (secure_datagram.rs:519-537): keep only the
    /// ciphers of the send epoch, the live rx epochs and the grace
    /// window's epochs.
    fn prune_key_cache(&self, rx: &[[EpochRxSlot; 2]; 2], grace: Option<&SyncRxGrace>) {
        let send_epoch = self.send_epoch.load(Ordering::Relaxed);
        let mut key_cache = self.key_cache.lock().unwrap();
        for d in 0..2 {
            for s in 0..2 {
                let Some(slot) = key_cache[d][s].as_mut() else {
                    continue;
                };
                let e = slot.epoch;
                let allowed = e == send_epoch
                    || rx[d][0].valid && rx[d][0].epoch == e
                    || rx[d][1].valid && rx[d][1].epoch == e
                    || grace.is_some_and(|g| Self::epoch_in_slots(&g.slots[d], e));
                if !allowed {
                    slot.valid = false;
                }
            }
        }
    }

    /// `precheck_replay` (secure_datagram.rs:539-604) — the lock-free
    /// pre-check that decides whether commit has a chance, so a decrypt
    /// failure never consumes a sequence number
    /// (`failed_decrypt_does_not_poison_replay_window`).
    fn precheck_replay(&self, epoch: u32, seq: u64, dir: SecureDirection, now_ms: u64) -> bool {
        let dir_idx = dir.idx();
        let mut rx = self.rx_slots.lock().unwrap();
        Self::evict_old_rx_slots(&mut rx, now_ms);
        let grace = self.take_sync_rx_grace(now_ms);
        if grace
            .as_ref()
            .is_some_and(|g| Self::epoch_in_slots(&g.slots[dir_idx], epoch))
        {
            for slot in &grace.expect("checked").slots[dir_idx] {
                if slot.valid && slot.epoch == epoch {
                    return slot.window.can_accept(seq);
                }
            }
        }
        if !rx[dir_idx][0].valid {
            return true;
        }
        if rx[dir_idx][0].valid && epoch == rx[dir_idx][0].epoch {
            return rx[dir_idx][0].window.can_accept(seq);
        }
        if rx[dir_idx][1].valid && epoch == rx[dir_idx][1].epoch {
            return rx[dir_idx][1].window.can_accept(seq);
        }
        if rx[dir_idx][0].valid && epoch > rx[dir_idx][0].epoch {
            let mut baseline_epoch = self.send_epoch.load(Ordering::Relaxed);
            if rx[dir_idx][0].valid {
                baseline_epoch = baseline_epoch.max(rx[dir_idx][0].epoch);
            }
            if rx[dir_idx][1].valid {
                baseline_epoch = baseline_epoch.max(rx[dir_idx][1].epoch);
            }
            let max_allowed_epoch = baseline_epoch.saturating_add(MAX_ACCEPTED_RX_EPOCH_AHEAD);
            if epoch > max_allowed_epoch {
                return false;
            }
            return true;
        }
        false
    }

    /// `commit_replay` (secure_datagram.rs:606-688) — the state-changing
    /// half, run only after the packet decrypted.
    fn commit_replay(&self, epoch: u32, seq: u64, dir: SecureDirection, now_ms: u64) -> bool {
        let dir_idx = dir.idx();
        let mut rx = self.rx_slots.lock().unwrap();
        Self::evict_old_rx_slots(&mut rx, now_ms);
        let mut grace = self.take_sync_rx_grace(now_ms);
        let accepted = if grace
            .as_ref()
            .is_some_and(|g| Self::epoch_in_slots(&g.slots[dir_idx], epoch))
        {
            let mut accepted = false;
            for slot in grace.as_mut().expect("checked").slots[dir_idx].iter_mut() {
                if slot.valid && slot.epoch == epoch {
                    slot.last_rx_ms = now_ms;
                    accepted = slot.window.accept(seq);
                    break;
                }
            }
            accepted
        } else if !rx[dir_idx][0].valid {
            rx[dir_idx][0] = EpochRxSlot {
                epoch,
                window: ReplayWindow256::default(),
                last_rx_ms: now_ms,
                valid: true,
            };
            rx[dir_idx][0].window.accept(seq)
        } else if rx[dir_idx][0].valid && epoch == rx[dir_idx][0].epoch {
            rx[dir_idx][0].last_rx_ms = now_ms;
            rx[dir_idx][0].window.accept(seq)
        } else if rx[dir_idx][1].valid && epoch == rx[dir_idx][1].epoch {
            rx[dir_idx][1].last_rx_ms = now_ms;
            rx[dir_idx][1].window.accept(seq)
        } else if rx[dir_idx][0].valid && epoch > rx[dir_idx][0].epoch {
            let mut baseline_epoch = self.send_epoch.load(Ordering::Relaxed);
            if rx[dir_idx][0].valid {
                baseline_epoch = baseline_epoch.max(rx[dir_idx][0].epoch);
            }
            if rx[dir_idx][1].valid {
                baseline_epoch = baseline_epoch.max(rx[dir_idx][1].epoch);
            }
            let max_allowed_epoch = baseline_epoch.saturating_add(MAX_ACCEPTED_RX_EPOCH_AHEAD);
            if epoch > max_allowed_epoch {
                false
            } else {
                rx[dir_idx][1] = rx[dir_idx][0];
                rx[dir_idx][0] = EpochRxSlot {
                    epoch,
                    window: ReplayWindow256::default(),
                    last_rx_ms: now_ms,
                    valid: true,
                };
                rx[dir_idx][0].window.accept(seq)
            }
        } else {
            false
        };
        self.prune_key_cache(&rx, grace.as_ref());
        accepted
    }

    /// `encrypt_payload` (secure_datagram.rs:704-720) over the engine's
    /// header+payload shape: the chosen nonce rides the AEAD tail.
    pub fn encrypt_payload(
        &self,
        dir: SecureDirection,
        hdr: &mut PeerManagerHeader,
        payload: &mut Vec<u8>,
    ) -> Result<()> {
        if !self.is_valid() {
            return Err(Error::crypto("easytier: session invalidated"));
        }
        let (epoch, _seq, nonce) = self.next_nonce(dir);
        let cipher = self.get_or_create_cipher(epoch, dir, self.session_generation(), true)?;
        cipher.encrypt_packet_with_nonce(hdr, payload, &nonce)
    }

    /// `decrypt_payload` (secure_datagram.rs:722-759): the epoch and
    /// sequence come from the tail nonce; the replay window is committed
    /// only after the tag verified.
    pub fn decrypt_payload(
        &self,
        dir: SecureDirection,
        hdr: &mut PeerManagerHeader,
        payload: &mut Vec<u8>,
    ) -> Result<()> {
        if !self.is_valid() {
            return Err(Error::crypto("easytier: session invalidated"));
        }
        let payload_len = payload.len();
        if payload_len < AEAD_TAIL_SIZE {
            return Err(Error::crypto(format!(
                "easytier: packet is too short. len: {payload_len}"
            )));
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&payload[payload_len - 12..]);
        let epoch = u32::from_be_bytes(nonce[..4].try_into().expect("4 bytes"));
        let seq = u64::from_be_bytes(nonce[4..].try_into().expect("8 bytes"));
        let now_ms = secure_now_ms();
        if !self.precheck_replay(epoch, seq, dir, now_ms) {
            return Err(Error::crypto("easytier: replay rejected"));
        }
        let cipher = self.get_or_create_cipher(epoch, dir, self.session_generation(), false)?;
        if let Err(e) = cipher.decrypt_packet(hdr, payload) {
            let count = self.decrypt_fail_count.fetch_add(1, Ordering::Relaxed) + 1;
            if count >= DECRYPT_FAIL_THRESHOLD {
                self.invalidate();
                tracing::warn!(
                    target: "engine",
                    count,
                    "easytier: secure session auto-invalidated after consecutive decrypt failures"
                );
            }
            return Err(e);
        }
        self.decrypt_fail_count.store(0, Ordering::Relaxed);
        if !self.commit_replay(epoch, seq, dir, now_ms) {
            return Err(Error::crypto("easytier: replay rejected"));
        }
        Ok(())
    }

    #[cfg(test)]
    fn check_replay_for_test(
        &self,
        epoch: u32,
        seq: u64,
        dir: SecureDirection,
        now_ms: u64,
    ) -> bool {
        self.precheck_replay(epoch, seq, dir, now_ms)
            && self.commit_replay(epoch, seq, dir, now_ms)
    }
}

// -- The peer session + store (peer_session.rs, two-node subset) -------------

impl std::fmt::Debug for PeerSecureSession {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PeerSecureSession")
            .field("generation", &self.session_generation())
            .field("valid", &self.is_valid())
            .finish()
    }
}

/// Upstream `PeerSession` (peer_session.rs:215-367): the per-peer session
/// (static-key pinning + the datagram layer). Named `PeerSecureSession`
/// here because the engine's gossip side already owns `PeerSession`.
pub struct PeerSecureSession {
    peer_static_pubkey: StdMutex<Option<[u8; 32]>>,
    datagram: SecureDatagramSession,
}

impl PeerSecureSession {
    /// `PeerSession::new` (peer_session.rs:235-256).
    pub fn new(
        root_key: [u8; 32],
        session_generation: u32,
        initial_epoch: u32,
        send_cipher_algorithm: String,
        recv_cipher_algorithm: String,
        peer_static_pubkey: Option<[u8; 32]>,
    ) -> Self {
        Self {
            peer_static_pubkey: StdMutex::new(peer_static_pubkey),
            datagram: SecureDatagramSession::new(
                root_key,
                session_generation,
                initial_epoch,
                send_cipher_algorithm,
                recv_cipher_algorithm,
            ),
        }
    }

    pub fn is_valid(&self) -> bool {
        self.datagram.is_valid()
    }

    pub fn invalidate(&self) {
        self.datagram.invalidate();
    }

    pub fn session_generation(&self) -> u32 {
        self.datagram.session_generation()
    }

    pub fn root_key(&self) -> [u8; 32] {
        self.datagram.root_key()
    }

    pub fn new_root_key() -> [u8; 32] {
        SecureDatagramSession::new_root_key()
    }

    pub fn next_sync_epoch(&self) -> u32 {
        self.datagram.next_sync_epoch()
    }

    pub fn check_encrypt_algo_same(&self, send: &str, recv: &str) -> Result<()> {
        self.datagram.check_encrypt_algo_same(send, recv)
    }

    /// `check_or_set_peer_static_pubkey` (peer_session.rs:296-312): the
    /// first observed static pins; a different one later is an error.
    pub fn check_or_set_peer_static_pubkey(&self, pubkey: Option<[u8; 32]>) -> Result<()> {
        let Some(pubkey) = pubkey else {
            return Ok(());
        };
        let mut guard = self.peer_static_pubkey.lock().unwrap();
        if let Some(existing) = *guard {
            if existing != pubkey {
                return Err(Error::protocol("easytier: peer static pubkey mismatch"));
            }
            return Ok(());
        }
        *guard = Some(pubkey);
        Ok(())
    }

    /// `sync_root_key` (peer_session.rs:314-327).
    pub fn sync_root_key(
        &self,
        root_key: [u8; 32],
        session_generation: u32,
        initial_epoch: u32,
        preserve_rx_grace: bool,
    ) {
        self.datagram
            .sync_root_key(root_key, session_generation, initial_epoch, preserve_rx_grace);
    }

    /// `dir_for_sender` (peer_session.rs:329-338): the peer-id order
    /// decides which side is "A".
    fn dir_for_sender(sender_peer_id: PeerId, receiver_peer_id: PeerId) -> SecureDirection {
        if sender_peer_id < receiver_peer_id {
            SecureDirection::AToB
        } else {
            SecureDirection::BToA
        }
    }

    /// `encrypt_payload` (peer_session.rs:340-351).
    pub fn encrypt_payload(
        &self,
        sender_peer_id: PeerId,
        receiver_peer_id: PeerId,
        hdr: &mut PeerManagerHeader,
        payload: &mut Vec<u8>,
    ) -> Result<()> {
        if !self.is_valid() {
            return Err(Error::crypto("easytier: session invalidated"));
        }
        self.datagram.encrypt_payload(
            Self::dir_for_sender(sender_peer_id, receiver_peer_id),
            hdr,
            payload,
        )
    }

    /// `decrypt_payload` (peer_session.rs:353-366).
    pub fn decrypt_payload(
        &self,
        sender_peer_id: PeerId,
        receiver_peer_id: PeerId,
        hdr: &mut PeerManagerHeader,
        payload: &mut Vec<u8>,
    ) -> Result<()> {
        if !self.is_valid() {
            return Err(Error::crypto("easytier: session invalidated"));
        }
        self.datagram.decrypt_payload(
            Self::dir_for_sender(sender_peer_id, receiver_peer_id),
            hdr,
            payload,
        )
    }
}

/// The result of `upsert_responder_session` (peer_session.rs:15-21).
pub struct UpsertResponderSessionReturn {
    pub session: Arc<PeerSecureSession>,
    pub action: PeerConnSessionAction,
    pub session_generation: u32,
    pub root_key: Option<[u8; 32]>,
    pub initial_epoch: u32,
}

/// The store's session table: `(network_name, peer_id)` -> session.
type SecureSessionMap = HashMap<(String, PeerId), Arc<PeerSecureSession>>;

/// `PeerSessionStore` (peer_session.rs:46-213) — the per-node session
/// table keyed by `(network_name, peer_id)`; the Join/Sync/Create
/// generations live here. Shared by every connection of one node (the
/// acceptors in `serve`, the dialer in `node_for`), so a reconnecting
/// peer resumes its session instead of restarting at Create.
#[derive(Clone, Default)]
pub struct PeerSessionStore {
    sessions: Arc<StdMutex<SecureSessionMap>>,
}

impl PeerSessionStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn get(&self, key: &(String, PeerId)) -> Option<Arc<PeerSecureSession>> {
        let session = self.sessions.lock().unwrap().get(key).cloned()?;
        if session.is_valid() {
            Some(session)
        } else {
            self.sessions.lock().unwrap().remove(key);
            None
        }
    }

    /// `upsert_responder_session` (peer_session.rs:88-150): the
    /// responder's verdict for a connecting peer — Create a fresh session
    /// (generation 1, epoch 0, a new root key it must send), answer Join
    /// when the client's generation matches ours (nothing to send), or
    /// Sync our stored key at the next epoch.
    pub fn upsert_responder_session(
        &self,
        key: (String, PeerId),
        a_session_generation: Option<u32>,
        send_algorithm: &str,
        recv_algorithm: &str,
        peer_static_pubkey: Option<[u8; 32]>,
    ) -> Result<UpsertResponderSessionReturn> {
        let existing = self.get(&key);
        match existing {
            None => {
                let root_key = PeerSecureSession::new_root_key();
                let session_generation = 1u32;
                let initial_epoch = 0u32;
                let session = Arc::new(PeerSecureSession::new(
                    root_key,
                    session_generation,
                    initial_epoch,
                    send_algorithm.to_owned(),
                    recv_algorithm.to_owned(),
                    peer_static_pubkey,
                ));
                self.sessions.lock().unwrap().insert(key, session.clone());
                Ok(UpsertResponderSessionReturn {
                    session,
                    action: PeerConnSessionAction::Create,
                    session_generation,
                    root_key: Some(root_key),
                    initial_epoch,
                })
            }
            Some(session) => {
                session.check_encrypt_algo_same(send_algorithm, recv_algorithm)?;
                session.check_or_set_peer_static_pubkey(peer_static_pubkey)?;
                let local_gen = session.session_generation();
                if a_session_generation.is_some_and(|g| g == local_gen) {
                    Ok(UpsertResponderSessionReturn {
                        session,
                        action: PeerConnSessionAction::Join,
                        session_generation: local_gen,
                        root_key: None,
                        initial_epoch: 0,
                    })
                } else {
                    let initial_epoch = session.next_sync_epoch();
                    let root_key = session.root_key();
                    Ok(UpsertResponderSessionReturn {
                        session,
                        action: PeerConnSessionAction::Sync,
                        session_generation: local_gen,
                        root_key: Some(root_key),
                        initial_epoch,
                    })
                }
            }
        }
    }

    /// `apply_initiator_action` (peer_session.rs:154-212): the client
    /// installs the responder's verdict.
    #[allow(clippy::too_many_arguments)] // upstream parity (peer_session.rs:152-164)
    pub fn apply_initiator_action(
        &self,
        key: (String, PeerId),
        action: PeerConnSessionAction,
        b_session_generation: u32,
        root_key_32: Option<[u8; 32]>,
        initial_epoch: u32,
        send_algorithm: &str,
        recv_algorithm: &str,
        peer_static_pubkey: Option<[u8; 32]>,
    ) -> Result<Arc<PeerSecureSession>> {
        match action {
            PeerConnSessionAction::Join => {
                let Some(session) = self.get(&key) else {
                    return Err(Error::protocol("easytier: no local session for JOIN"));
                };
                session.check_encrypt_algo_same(send_algorithm, recv_algorithm)?;
                session.check_or_set_peer_static_pubkey(peer_static_pubkey)?;
                if session.session_generation() != b_session_generation {
                    return Err(Error::protocol("easytier: JOIN generation mismatch"));
                }
                Ok(session)
            }
            PeerConnSessionAction::Sync | PeerConnSessionAction::Create => {
                let root_key = root_key_32
                    .ok_or_else(|| Error::protocol("easytier: missing root_key"))?;
                if self.sessions.lock().unwrap().get(&key).is_some_and(|s| !s.is_valid()) {
                    self.sessions.lock().unwrap().remove(&key);
                }
                let mut guard = self.sessions.lock().unwrap();
                let session = guard
                    .entry(key)
                    .or_insert_with(|| {
                        Arc::new(PeerSecureSession::new(
                            root_key,
                            b_session_generation,
                            initial_epoch,
                            send_algorithm.to_owned(),
                            recv_algorithm.to_owned(),
                            peer_static_pubkey,
                        ))
                    })
                    .clone();
                drop(guard);
                session.check_encrypt_algo_same(send_algorithm, recv_algorithm)?;
                session.check_or_set_peer_static_pubkey(peer_static_pubkey)?;
                session.sync_root_key(
                    root_key,
                    b_session_generation,
                    initial_epoch,
                    matches!(action, PeerConnSessionAction::Sync),
                );
                Ok(session)
            }
        }
    }
}

// -- The auth subset + the handshake flows ------------------------------------

/// `SecureAuthLevel` (peer_rpc.proto:322-328).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecureAuthLevel {
    None,
    EncryptedUnauthenticated,
    PeerVerified,
    NetworkSecretConfirmed,
}

/// The per-node secure-mode context: the static identity, the proof
/// secret and the session store every handshake of the node shares
/// (`SecureModeConfig` + the peer manager's `PeerSessionStore`).
pub struct SecureModeCtx {
    /// The network name proofs are checked against.
    pub network_name: String,
    /// The network secret (`None` when the config carries none — proofs
    /// are skipped and only pinned keys can authenticate).
    pub network_secret: Option<String>,
    /// `local_private_key` (base64 X25519) or a fresh random identity
    /// (`process_secure_mode_cfg`, config.rs:489-521).
    static_keys: SecureStaticKeys,
    /// The negotiated payload algorithm (`my_encrypt_algo` = the flags'
    /// `encryption_algorithm`, default `aes-gcm`).
    pub algorithm: String,
    /// The dialed peer's `peer-public-key` pin, when the config has one.
    pub pinned_peer_pubkey: Option<[u8; 32]>,
    /// The node-wide session table (Join/Sync/Create generations).
    pub store: PeerSessionStore,
}

impl SecureModeCtx {
    /// Build the context from a validated config. `pinned_peer_pubkey`
    /// comes from the first peer URI's `peer-public-key` query param (the
    /// dial-side pin; `get_pinned_remote_static_pubkey_b64`,
    /// peer_conn.rs:641-655).
    pub fn new(
        network_name: &str,
        network_secret: &str,
        local_private_key: &str,
        algorithm: &str,
        pinned_peer_pubkey_b64: Option<&str>,
    ) -> Result<Self> {
        let static_keys = if local_private_key.trim().is_empty() {
            SecureStaticKeys::random()
        } else {
            let raw = base64::engine::general_purpose::STANDARD
                .decode(local_private_key.trim())
                .map_err(|e| Error::config(format!("easytier: local-private-key: {e}")))?;
            let sk: [u8; 32] = raw.try_into().map_err(|_| {
                Error::config("easytier: local-private-key must be 32 bytes base64")
            })?;
            SecureStaticKeys::from_secret(sk)
        };
        let pinned_peer_pubkey = pinned_peer_pubkey_b64
            .filter(|s| !s.trim().is_empty())
            .map(|s| {
                let raw = base64::engine::general_purpose::STANDARD
                    .decode(s.trim())
                    .map_err(|e| Error::config(format!("easytier: peer-public-key: {e}")))?;
                raw.try_into().map_err(|_| {
                    Error::config("easytier: peer-public-key must be 32 bytes base64")
                })
            })
            .transpose()?;
        Ok(SecureModeCtx {
            network_name: network_name.to_owned(),
            network_secret: (!network_secret.is_empty()).then(|| network_secret.to_owned()),
            static_keys,
            algorithm: algorithm.to_owned(),
            pinned_peer_pubkey,
            store: PeerSessionStore::new(),
        })
    }

    fn has_network_secret(&self) -> bool {
        self.network_secret.is_some()
    }

    fn proof(&self, challenge: &[u8]) -> Option<[u8; 32]> {
        self.network_secret
            .as_ref()
            .map(|secret| secret_proof(secret, challenge))
    }

    /// `verify_remote_auth` (peer_conn.rs:707-762), the two-node subset:
    /// (1) a valid proof is `NetworkSecretConfirmed`; (2) a pinned key
    /// must match — and without a network secret the pinned config key IS
    /// the trust anchor (upstream consults the trusted-key store here,
    /// which is not ported); (3) an initiator without a secret keeps the
    /// encrypted channel (`EncryptedUnauthenticated`); (4) anything else
    /// is rejected.
    fn verify_remote_auth(
        &self,
        proof: Option<&[u8]>,
        handshake_hash: &[u8],
        remote_pubkey: &[u8],
        is_initiator: bool,
    ) -> Result<SecureAuthLevel> {
        if let (Some(proof), Some(expected)) = (proof, self.proof(handshake_hash)) {
            if expected.as_slice() == proof {
                return Ok(SecureAuthLevel::NetworkSecretConfirmed);
            }
        }
        if let (Some(pinned), true) = (&self.pinned_peer_pubkey, is_initiator) {
            if pinned.as_slice() != remote_pubkey {
                return Err(Error::protocol(
                    "easytier: pinned remote static pubkey mismatch",
                ));
            }
            return Ok(SecureAuthLevel::PeerVerified);
        }
        if is_initiator && !self.has_network_secret() {
            return Ok(SecureAuthLevel::EncryptedUnauthenticated);
        }
        Err(Error::protocol(
            "easytier: authentication failed: invalid proof and unknown credential",
        ))
    }
}

/// Send one noise message as a peer packet (`send_noise_msg`,
/// peer_conn.rs:657-683).
async fn send_noise_msg<W: AsyncWrite + Unpin>(
    writer: &mut W,
    from: PeerId,
    to: PeerId,
    packet_type: u8,
    wire: &[u8],
) -> Result<()> {
    write_frame(writer, &PeerPacket::new(from, to, packet_type, wire)).await
}

/// Read the next noise message frame with the 5s budget
/// (`recv_next_peer_manager_packet` + the timeout, peer_conn.rs:842-846).
async fn recv_noise_frame<R: AsyncRead + Unpin>(
    reader: &mut R,
    expected: u8,
) -> Result<PeerPacket> {
    let packet = tokio::time::timeout(NOISE_MSG_TIMEOUT, async {
        loop {
            let packet = read_frame(reader)
                .await?
                .ok_or_else(|| Error::network("easytier: conn closed during noise handshake"))?;
            if packet.hdr.packet_type == expected {
                break Ok::<PeerPacket, Error>(packet);
            }
        }
    })
    .await
    .map_err(|_| Error::network("easytier: wait noise handshake response timeout"))??;
    Ok(packet)
}

/// The noise handshake result mapped into the plain-mode peer info plus
/// the live session (the `NoiseHandshakeResult` fields the engine uses).
#[derive(Debug)]
struct NoiseHandshakeOutcome {
    peer: PeerInfo,
    session: Arc<PeerSecureSession>,
    auth_level: SecureAuthLevel,
}

/// `do_noise_handshake_as_client` (peer_conn.rs:793-983).
async fn noise_handshake_as_client<I>(
    io: &mut I,
    my_peer_id: PeerId,
    ctx: &SecureModeCtx,
) -> Result<NoiseHandshakeOutcome>
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(io);
    let mut hs = NoiseXxHandshake::new(SecureStaticKeys {
        sk: ctx.static_keys.sk,
        pk: ctx.static_keys.pk,
    });
    let a_conn_id = uuid::Uuid::new_v4();
    let msg1 = NoiseMsg1 {
        version: NOISE_VERSION,
        a_network_name: ctx.network_name.clone(),
        // `peer_id_hint` is None on the direct dial path, so no
        // generation is claimed (peer_conn.rs:809-815).
        a_session_generation: None,
        a_conn_id,
        client_encryption_algorithm: ctx.algorithm.clone(),
    };
    let wire1 = hs.write_msg1(&msg1.encode());
    send_noise_msg(
        &mut writer,
        my_peer_id,
        0,
        packet_type::NOISE_HANDSHAKE_MSG1,
        &wire1,
    )
    .await?;
    // The challenge the server's msg2 proof is checked against: the hash
    // as of OUR msg1 (peer_conn.rs:840).
    let server_handshake_hash = hs.handshake_hash();

    let msg2_packet = recv_noise_frame(&mut reader, noise_packet_type::NOISE_HANDSHAKE_MSG2).await?;
    let remote_peer_id = msg2_packet.hdr.from_peer_id;
    if remote_peer_id == 0 {
        return Err(Error::protocol("easytier: noise msg2 missing src peer id"));
    }
    let payload2 = hs.read_msg2(&msg2_packet.payload)?;
    let msg2 = NoiseMsg2::decode(&payload2)?;
    if msg2.a_conn_id_echo != Some(a_conn_id) {
        return Err(Error::protocol("easytier: noise msg2 conn_id_echo mismatch"));
    }
    let remote_network_name = msg2.b_network_name.clone();
    if remote_network_name == ctx.network_name && msg2.role_hint != 1 {
        return Err(Error::protocol(
            "easytier: role_hint must be 1 when network_name is same",
        ));
    }
    // Our msg3 proof is computed over the hash as of THEIR msg2
    // (peer_conn.rs:875-879).
    let handshake_hash_for_proof = hs.handshake_hash();
    let msg3 = NoiseMsg3 {
        a_conn_id_echo: a_conn_id,
        b_conn_id_echo: msg2.b_conn_id,
        secret_proof_32: ctx.proof(&handshake_hash_for_proof).map(|p| p.to_vec()),
        secret_digest: network_secret_digest(
            &ctx.network_name,
            ctx.network_secret.as_deref().unwrap_or(""),
        )
        .to_vec(),
    };
    let wire3 = hs.write_msg3(&msg3.encode());
    send_noise_msg(
        &mut writer,
        my_peer_id,
        remote_peer_id,
        noise_packet_type::NOISE_HANDSHAKE_MSG3,
        &wire3,
    )
    .await?;

    let remote_static = hs.remote_static().unwrap_or_default();
    // The initiator saw the server's static in msg2; the pin and the
    // proof both authenticate it. The no-pin EncryptedUnauthenticated
    // fast path (peer_conn.rs:918-920) only applies to cross-network
    // servers, which the two-node mesh never sees.
    let auth_level = ctx.verify_remote_auth(
        msg2.secret_proof_32.as_deref(),
        &server_handshake_hash,
        &remote_static,
        true,
    )?;
    let session = ctx.store.apply_initiator_action(
        (ctx.network_name.clone(), remote_peer_id),
        msg2.action,
        msg2.b_session_generation,
        msg2.root_key_32,
        msg2.initial_epoch,
        &ctx.algorithm,
        &msg2.server_encryption_algorithm,
        hs.remote_static(),
    )?;
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&msg3.secret_digest);
    Ok(NoiseHandshakeOutcome {
        peer: PeerInfo {
            peer_id: remote_peer_id,
            network_name: remote_network_name,
            // `we have authorized the peer with noise handshake, so just
            // set secret digest same as us` (peer_conn.rs:976-977).
            network_secret_digest: digest,
            features: Vec::new(),
            version: NOISE_VERSION,
        },
        session,
        auth_level,
    })
}

/// `do_noise_handshake_as_server` (peer_conn.rs:1043-1218): the first
/// frame (already read by the caller's handshake dispatch) is the
/// client's msg1.
async fn noise_handshake_as_server<I>(
    io: &mut I,
    my_peer_id: PeerId,
    ctx: &SecureModeCtx,
    first_msg1: PeerPacket,
) -> Result<NoiseHandshakeOutcome>
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(io);
    let mut hs = NoiseXxHandshake::new(SecureStaticKeys {
        sk: ctx.static_keys.sk,
        pk: ctx.static_keys.pk,
    });
    let remote_peer_id = first_msg1.hdr.from_peer_id;
    if remote_peer_id == 0 {
        return Err(Error::protocol("easytier: noise msg1 must have src peer id"));
    }
    let payload1 = hs.read_msg1(&first_msg1.payload)?;
    let msg1 = NoiseMsg1::decode(&payload1)?;
    let remote_network_name = msg1.a_network_name.clone();
    // `role_hint` 1 = same network (with proof), 2 = foreign
    // (peer_conn.rs:1082-1091).
    let (role_hint, secret_proof_32) = if msg1.a_network_name == ctx.network_name {
        (1, ctx.proof(&hs.handshake_hash()).map(|p| p.to_vec()))
    } else {
        (2, None)
    };
    let upsert = ctx.store.upsert_responder_session(
        (remote_network_name.clone(), remote_peer_id),
        msg1.a_session_generation,
        &ctx.algorithm,
        &msg1.client_encryption_algorithm,
        None,
    )?;
    let b_conn_id = uuid::Uuid::new_v4();
    let msg2 = NoiseMsg2 {
        b_network_name: ctx.network_name.clone(),
        role_hint,
        action: upsert.action,
        b_session_generation: upsert.session_generation,
        root_key_32: upsert.root_key,
        initial_epoch: upsert.initial_epoch,
        b_conn_id,
        a_conn_id_echo: Some(msg1.a_conn_id),
        secret_proof_32,
        server_encryption_algorithm: ctx.algorithm.clone(),
    };
    let wire2 = hs.write_msg2(&msg2.encode());
    send_noise_msg(
        &mut writer,
        my_peer_id,
        remote_peer_id,
        noise_packet_type::NOISE_HANDSHAKE_MSG2,
        &wire2,
    )
    .await?;
    // The challenge the client's msg3 proof is checked against: the hash
    // as of OUR msg2 (peer_conn.rs:1134).
    let handshake_hash_for_proof = hs.handshake_hash();

    let msg3_packet = recv_noise_frame(&mut reader, noise_packet_type::NOISE_HANDSHAKE_MSG3).await?;
    let payload3 = hs.read_msg3(&msg3_packet.payload)?;
    let msg3 = NoiseMsg3::decode(&payload3)?;
    if msg3.a_conn_id_echo != msg1.a_conn_id {
        return Err(Error::protocol("easytier: noise msg3 a_conn_id mismatch"));
    }
    if msg3.b_conn_id_echo != b_conn_id {
        return Err(Error::protocol("easytier: noise msg3 b_conn_id mismatch"));
    }
    let remote_static = hs.remote_static();
    upsert
        .session
        .check_or_set_peer_static_pubkey(remote_static)?;
    let auth_level = if role_hint == 1 {
        ctx.verify_remote_auth(
            msg3.secret_proof_32.as_deref(),
            &handshake_hash_for_proof,
            &remote_static.unwrap_or_default(),
            false,
        )?
    } else {
        SecureAuthLevel::EncryptedUnauthenticated
    };
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&msg3.secret_digest);
    Ok(NoiseHandshakeOutcome {
        peer: PeerInfo {
            peer_id: remote_peer_id,
            network_name: remote_network_name,
            network_secret_digest: digest,
            features: Vec::new(),
            version: msg1.version,
        },
        session: upsert.session,
        auth_level,
    })
}
// ---------------------------------------------------------------------------
// The peer RPC framework — the minimal client+server subset
// (easytier-core/src/rpc/packet.rs + client.rs + server.rs +
// service_registry.rs + peers/peer_rpc.rs; the wire messages are
// easytier-proto/proto/common.proto:93-165), commit main@2026-09
// ---------------------------------------------------------------------------
//
// What a route-gossip RPC looks like on the peer channel, and what this
// port keeps:
//
// * One `RpcReq` peer packet carries an encoded `RpcPacket` (common.proto:
//   149-163): transaction id, `RpcDescriptor` (the service/method being
//   called), an `is_request` flag, piece counters and compression info;
//   its `body` is an encoded `RpcRequest { request, timeout_ms }`. The
//   response comes back as an `RpcResp` peer packet with the same
//   transaction id and an `RpcResponse { response, error, runtime_us }`
//   body (client.rs:261-407, server.rs:210-308).
// * The transaction id is a process-global random-start `AtomicI64`
//   counter (client.rs:40 `CUR_TID`); responses are matched to callers
//   by `(from_peer, to_peer, transaction_id)` (client.rs:45-50,
//   185-190).
// * Multi-piece packets exist so a datagram-sized UDP transport can
//   carry big RPC bodies (packet.rs:14, 163-250); over TCP the pieces
//   would only ever be split by the same UDP budget. The merger is
//   ported (`PacketMerger`, packet.rs:57-150) so a real peer's split
//   packets reassemble, but this side always emits single-piece
//   requests (`total_pieces = 0 && piece_idx = 0` is the pass-through
//   fast path, packet.rs:106-108).
// * Compression: zstd is negotiated when both sides have the feature
//   (packet.rs:16-22). This build has no zstd, so every packet carries
//   `CompressionAlgoPb::None` (= 1, common.proto:134-138) — the peer's
//   `decompress_packet` maps None to the identity compressor
//   (packet.rs:46-55). Omitting the compression info entirely would
//   also interop (server.rs:216-224); we send it to mirror upstream.
// * Server dispatch is by `RpcDescriptor { domain_name, proto_name,
//   service_name, method_index }` (service_registry.rs:42-47,
//   166-200): domain = the network name the service registered under,
//   and method indexes start at 1 (the codegen's `(i + 1) as u8`
//   discriminants, easytier-proto/build/rpc.rs:70-72, 277-287).
// * Timeouts ride inside `RpcRequest.timeout_ms` (dispatch.rs:20-36);
//   the route gossip uses 3s (peer_ospf_route.rs:3529-3531).
//
// Skipped from the ~65 KB framework: the bidirect manager's ring-tunnel
// plumbing and `MpscTunnel` fan-in (bidirect.rs — an in-process
// performance shim), the standalone/HTTP transports (standalone.rs), the
// metrics wrappers, the dashmap-based peer-info table, and the generic
// codegen'd client factories (`__rt.rs`); this port has exactly one
// service (`OspfRouteRpc.SyncRouteInfo`), so the registry collapses to
// an `if` on the descriptor constants below.

/// The RPC method indexes this port speaks (`method_index` on the wire;
/// the codegen enumerates `SyncRouteInfo = 1`, build/rpc.rs:70-72).
pub mod rpc_method {
    /// `OspfRouteRpc::SyncRouteInfo` — the only method of the only
    /// service in the subset (peer_rpc.proto:137-140).
    pub const OSPF_SYNC_ROUTE_INFO: u32 = 1;
}

/// The `RpcDescriptor` a route-gossip call carries: registered with
/// `domain_name = network_name` (the `scoped_client` + `register` calls,
/// peer_ospf_route.rs:3513-3517, 4511-4513) and the prost names of
/// `service OspfRouteRpc` (proto_name and Rust name are both
/// `OspfRouteRpc`, so both fields carry it).
pub fn ospf_route_descriptor(network_name: &str) -> RpcDescriptor {
    RpcDescriptor {
        domain_name: network_name.to_owned(),
        proto_name: "OspfRouteRpc".to_owned(),
        service_name: "OspfRouteRpc".to_owned(),
        method_index: rpc_method::OSPF_SYNC_ROUTE_INFO,
    }
}

/// `RpcDescriptor` (common.proto:93-101).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RpcDescriptor {
    pub domain_name: String,
    pub proto_name: String,
    pub service_name: String,
    pub method_index: u32,
}

impl RpcDescriptor {
    pub fn encode(&self, out: &mut Vec<u8>) {
        if !self.domain_name.is_empty() {
            proto_put_len_field(out, 1, self.domain_name.as_bytes());
        }
        if !self.proto_name.is_empty() {
            proto_put_len_field(out, 2, self.proto_name.as_bytes());
        }
        if !self.service_name.is_empty() {
            proto_put_len_field(out, 3, self.service_name.as_bytes());
        }
        if self.method_index != 0 {
            proto_put_varint(out, 0x20);
            proto_put_varint(out, self.method_index as u64);
        }
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut desc = RpcDescriptor::default();
        let mut reader = ProtoReader { buf, pos: 0 };
        while reader.pos < buf.len() {
            let tag = reader.varint()?;
            match (tag >> 3, tag & 7) {
                (1, 2) => {
                    desc.domain_name = String::from_utf8_lossy(reader.len_bytes()?).into_owned()
                }
                (2, 2) => {
                    desc.proto_name = String::from_utf8_lossy(reader.len_bytes()?).into_owned()
                }
                (3, 2) => {
                    desc.service_name = String::from_utf8_lossy(reader.len_bytes()?).into_owned()
                }
                (4, 0) => desc.method_index = reader.varint()? as u32,
                _ => reader.skip(tag & 7)?,
            }
        }
        Ok(desc)
    }
}

/// `CompressionAlgoPb` (common.proto:134-138). Only `None` is emitted;
/// anything else decodes for diagnostics.
pub const COMPRESSION_ALGO_NONE: u32 = 1;

/// `RpcPacket` (common.proto:149-163). `compression_info` is flattened
/// to its two enum fields (fields 10.1 / 10.2).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RpcPacket {
    pub from_peer: PeerId,
    pub to_peer: PeerId,
    pub transaction_id: i64,
    pub descriptor: Option<RpcDescriptor>,
    pub body: Vec<u8>,
    pub is_request: bool,
    pub total_pieces: u32,
    pub piece_idx: u32,
    pub trace_id: i32,
    pub compression_algo: Option<u32>,
    pub compression_accepted: Option<u32>,
}

impl RpcPacket {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.body.len());
        if self.from_peer != 0 {
            proto_put_varint(&mut out, 0x08);
            proto_put_varint(&mut out, self.from_peer as u64);
        }
        if self.to_peer != 0 {
            proto_put_varint(&mut out, 0x10);
            proto_put_varint(&mut out, self.to_peer as u64);
        }
        if self.transaction_id != 0 {
            proto_put_varint(&mut out, 0x18);
            // int64 on the wire: the two's-complement 10-byte form.
            proto_put_varint(&mut out, self.transaction_id as u64);
        }
        if let Some(desc) = &self.descriptor {
            let mut inner = Vec::new();
            desc.encode(&mut inner);
            proto_put_len_field(&mut out, 4, &inner);
        }
        if !self.body.is_empty() {
            proto_put_len_field(&mut out, 5, &self.body);
        }
        if self.is_request {
            proto_put_varint(&mut out, 0x30);
            proto_put_varint(&mut out, 1);
        }
        if self.total_pieces != 0 {
            proto_put_varint(&mut out, 0x38);
            proto_put_varint(&mut out, self.total_pieces as u64);
        }
        if self.piece_idx != 0 {
            proto_put_varint(&mut out, 0x40);
            proto_put_varint(&mut out, self.piece_idx as u64);
        }
        if self.trace_id != 0 {
            proto_put_varint(&mut out, 0x48);
            proto_put_varint(&mut out, self.trace_id as u32 as u64);
        }
        if self.compression_algo.is_some() || self.compression_accepted.is_some() {
            let mut inner = Vec::new();
            if let Some(algo) = self.compression_algo {
                proto_put_varint(&mut inner, 0x08);
                proto_put_varint(&mut inner, algo as u64);
            }
            if let Some(accepted) = self.compression_accepted {
                proto_put_varint(&mut inner, 0x10);
                proto_put_varint(&mut inner, accepted as u64);
            }
            proto_put_len_field(&mut out, 10, &inner);
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut packet = RpcPacket::default();
        let mut reader = ProtoReader { buf, pos: 0 };
        while reader.pos < buf.len() {
            let tag = reader.varint()?;
            match (tag >> 3, tag & 7) {
                (1, 0) => packet.from_peer = reader.varint()? as PeerId,
                (2, 0) => packet.to_peer = reader.varint()? as PeerId,
                (3, 0) => packet.transaction_id = reader.varint()? as i64,
                (4, 2) => packet.descriptor = Some(RpcDescriptor::decode(reader.len_bytes()?)?),
                (5, 2) => packet.body = reader.len_bytes()?.to_vec(),
                (6, 0) => packet.is_request = reader.varint()? != 0,
                (7, 0) => packet.total_pieces = reader.varint()? as u32,
                (8, 0) => packet.piece_idx = reader.varint()? as u32,
                (9, 0) => packet.trace_id = reader.varint()? as u32 as i32,
                (10, 2) => {
                    let inner = reader.len_bytes()?;
                    let mut sub = ProtoReader { buf: inner, pos: 0 };
                    while sub.pos < inner.len() {
                        let sub_tag = sub.varint()?;
                        match (sub_tag >> 3, sub_tag & 7) {
                            (1, 0) => packet.compression_algo = Some(sub.varint()? as u32),
                            (2, 0) => packet.compression_accepted = Some(sub.varint()? as u32),
                            _ => sub.skip(sub_tag & 7)?,
                        }
                    }
                }
                _ => reader.skip(tag & 7)?,
            }
        }
        Ok(packet)
    }
}

/// `PacketMerger` (rpc/packet.rs:57-150): reassembles split RPC packets
/// by `(transaction_id, from_peer)`; `total_pieces == 0 && piece_idx ==
/// 0` passes straight through (the single-piece form this port emits).
#[derive(Default)]
pub struct PacketMerger {
    first_piece: Option<RpcPacket>,
    pieces: Vec<Option<RpcPacket>>,
}

impl PacketMerger {
    pub fn new() -> Self {
        Self::default()
    }

    fn try_merge_pieces(&self) -> Option<RpcPacket> {
        self.first_piece.as_ref()?;
        if self.pieces.is_empty() {
            return None;
        }
        if self
            .pieces
            .iter()
            .any(|p| p.as_ref().is_none_or(|p| p.total_pieces == 0))
        {
            return None;
        }
        let mut body = Vec::new();
        for piece in &self.pieces {
            body.extend_from_slice(&piece.as_ref().expect("checked piece").body);
        }
        let mut merged = self.pieces[0].as_ref().expect("checked piece").clone();
        merged.total_pieces = 1;
        merged.piece_idx = 0;
        merged.body = body;
        Some(merged)
    }

    pub fn feed(&mut self, rpc_packet: RpcPacket) -> Result<Option<RpcPacket>> {
        let total_pieces = rpc_packet.total_pieces;
        let piece_idx = rpc_packet.piece_idx;
        if total_pieces == 0 && piece_idx == 0 {
            return Ok(Some(rpc_packet));
        }
        if rpc_packet.piece_idx == 0 && rpc_packet.descriptor.is_none() {
            return Err(Error::protocol(
                "easytier: malformat rpc packet: descriptor is missing",
            ));
        }
        if total_pieces > 32 * 1024 || total_pieces == 0 {
            return Err(Error::protocol(format!(
                "easytier: malformat rpc packet: total_pieces is invalid: {total_pieces}"
            )));
        }
        if piece_idx >= total_pieces {
            return Err(Error::protocol(
                "easytier: malformat rpc packet: piece_idx >= total_pieces",
            ));
        }
        let start_new = match &self.first_piece {
            None => true,
            Some(first) => {
                first.transaction_id != rpc_packet.transaction_id
                    || first.from_peer != rpc_packet.from_peer
            }
        };
        if start_new {
            self.first_piece = Some(rpc_packet.clone());
            self.pieces.clear();
        }
        self.pieces.resize_with(total_pieces as usize, || None);
        self.pieces[piece_idx as usize] = Some(rpc_packet);
        Ok(self.try_merge_pieces())
    }
}

/// `RpcRequest` (common.proto:110-114): the deprecated `descriptor`
/// rides field 1, the payload `request` is field **2**, `timeout_ms`
/// field 3.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RpcRequestBody {
    pub request: Vec<u8>,
    pub timeout_ms: i32,
}

impl RpcRequestBody {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.request.len() + 8);
        if !self.request.is_empty() {
            proto_put_len_field(&mut out, 2, &self.request);
        }
        if self.timeout_ms != 0 {
            proto_put_varint(&mut out, 0x18);
            proto_put_varint(&mut out, self.timeout_ms as u32 as u64);
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut req = RpcRequestBody::default();
        let mut reader = ProtoReader { buf, pos: 0 };
        while reader.pos < buf.len() {
            let tag = reader.varint()?;
            match (tag >> 3, tag & 7) {
                (1, 2) => {
                    // The deprecated descriptor (field 1): present in
                    // legacy packets, unused by the dispatch.
                    let _ = reader.len_bytes()?;
                }
                (2, 2) => req.request = reader.len_bytes()?.to_vec(),
                (3, 0) => req.timeout_ms = reader.varint()? as u32 as i32,
                _ => reader.skip(tag & 7)?,
            }
        }
        Ok(req)
    }
}

/// `RpcResponse` (common.proto:129-133). The `error` oneof
/// (error.proto:23-34) is captured by its field tag so failures surface
/// with a reason instead of being silently dropped.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RpcResponseBody {
    pub response: Vec<u8>,
    /// The `error_kind` oneof tag of `common.Error`, when the call failed
    /// (`1..=8`, error.proto:24-33).
    pub error_tag: Option<u32>,
    pub runtime_us: u64,
}

impl RpcResponseBody {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.response.len() + 16);
        if !self.response.is_empty() {
            proto_put_len_field(&mut out, 1, &self.response);
        }
        if self.runtime_us != 0 {
            proto_put_varint(&mut out, 0x18);
            proto_put_varint(&mut out, self.runtime_us);
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut resp = RpcResponseBody::default();
        let mut reader = ProtoReader { buf, pos: 0 };
        while reader.pos < buf.len() {
            let tag = reader.varint()?;
            match (tag >> 3, tag & 7) {
                (1, 2) => resp.response = reader.len_bytes()?.to_vec(),
                (2, 2) => {
                    // Record which oneof arm fired (the arm's own message
                    // body is not needed to report the failure).
                    let _ = reader.len_bytes()?;
                    resp.error_tag = Some((tag >> 3) as u32);
                }
                (3, 0) => resp.runtime_us = reader.varint()?,
                _ => reader.skip(tag & 7)?,
            }
        }
        Ok(resp)
    }
}

/// The process-global transaction-id counter (`CUR_TID`, client.rs:40):
/// random start, incrementing.
static RPC_TRANSACTION_ID: AtomicU64 = AtomicU64::new(0);

fn next_transaction_id() -> i64 {
    let current = RPC_TRANSACTION_ID.load(Ordering::Relaxed);
    if current == 0 {
        // First use: install the random seed like `LazyLock<AtomicI64>`'s
        // `rand::random()` initializer (client.rs:40).
        let seed: i64 = rand::random();
        let _ = RPC_TRANSACTION_ID.compare_exchange(0, seed as u64, Ordering::Relaxed, Ordering::Relaxed);
        return seed;
    }
    RPC_TRANSACTION_ID.fetch_add(1, Ordering::Relaxed) as i64
}

/// The RPC routing table of one overlay node: the outstanding-call
/// table (the client's `inflight_requests`, client.rs:45-99, with the
/// per-call `PacketMerger`) plus the server's per-request mergers
/// (server.rs:42-57, 163-196). The single-call route-gossip client
/// reads completed calls back out of `merged` instead of holding the
/// oneshot receivers across the node loop's select.
#[derive(Default)]
struct RpcRouter {
    /// transaction id → the per-call response merger + waiter.
    inflight: HashMap<i64, PacketMerger>,
    /// transaction id → a fully merged response not yet consumed.
    merged: HashMap<i64, RpcPacket>,
    /// (transaction id →) the server-side request mergers.
    request_mergers: HashMap<i64, PacketMerger>,
}

impl RpcRouter {
    /// `Client::scoped_client`'s `call` (client.rs:261-344), specialized
    /// to one method: build the request packet and return the wire
    /// bytes to send.
    fn begin_call(
        &mut self,
        from_peer: PeerId,
        to_peer: PeerId,
        desc: RpcDescriptor,
        request: &[u8],
        timeout_ms: i32,
    ) -> (i64, Vec<u8>) {
        let transaction_id = next_transaction_id();
        let inner = RpcRequestBody {
            request: request.to_vec(),
            timeout_ms,
        };
        let packet = RpcPacket {
            from_peer,
            to_peer,
            transaction_id,
            descriptor: Some(desc),
            body: inner.encode(),
            is_request: true,
            compression_algo: Some(COMPRESSION_ALGO_NONE),
            compression_accepted: Some(COMPRESSION_ALGO_NONE),
            ..Default::default()
        };
        self.inflight.insert(transaction_id, PacketMerger::new());
        (transaction_id, packet.encode())
    }

    /// The client's response pump (client.rs:161-221): merge pieces of
    /// the call's responses; a complete packet lands in `merged`.
    fn on_response(&mut self, packet: RpcPacket) {
        let Some(merger) = self.inflight.get_mut(&packet.transaction_id) else {
            return;
        };
        if let Ok(Some(merged)) = merger.feed(packet) {
            self.merged.insert(merged.transaction_id, merged);
        }
    }

    /// Take a completed response (`rx.recv().await` in the generic
    /// client; the single-call variant polls it from the node loop).
    fn take_merged(&mut self, transaction_id: i64) -> Option<RpcPacket> {
        self.merged.remove(&transaction_id)
    }

    /// Drop a timed-out call (`InflightCleanup`, client.rs:67-79).
    fn cancel(&mut self, transaction_id: i64) {
        self.inflight.remove(&transaction_id);
        self.merged.remove(&transaction_id);
    }

    /// The server's request pump (server.rs:138-197): merge pieces of
    /// one `(from_peer, transaction_id)` request, yielding the whole
    /// packet once complete.
    fn on_request(&mut self, packet: RpcPacket) -> Result<Option<RpcPacket>> {
        let key = packet.transaction_id;
        let merger = self.request_mergers.entry(key).or_default();
        let out = merger.feed(packet)?;
        if out.is_some() {
            self.request_mergers.remove(&key);
        }
        Ok(out)
    }
}

/// Build one response `RpcPacket` (server.rs:290-302): the descriptor
/// echoes the request's, `from`/`to` swap, the body is the encoded
/// `RpcResponse`.
fn build_rpc_response(req: &RpcPacket, response: &[u8]) -> RpcPacket {
    let body = RpcResponseBody {
        response: response.to_vec(),
        ..Default::default()
    };
    RpcPacket {
        from_peer: req.to_peer,
        to_peer: req.from_peer,
        transaction_id: req.transaction_id,
        descriptor: req.descriptor.clone(),
        body: body.encode(),
        is_request: false,
        compression_algo: Some(COMPRESSION_ALGO_NONE),
        compression_accepted: Some(COMPRESSION_ALGO_NONE),
        ..Default::default()
    }
}

// ---------------------------------------------------------------------------
// Route gossip — the two-node OSPF subset
// (easytier-core/src/peers/route/peer_ospf_route.rs, 234 KB upstream;
// the wire messages are easytier-proto/proto/peer_rpc.proto:22-140)
// ---------------------------------------------------------------------------
//
// What a real peer needs to route IP frames to us, and what this subset
// ports from the 234 KB module:
//
// * **Our `RoutePeerInfo`** (peer_rpc.proto:22-53) — built like
//   `new_updated_self_route_peer_info` (peer_ospf_route.rs:774-816):
//   our peer id, a random instance UUID, cost 0, our overlay IPv4 (as
//   `common.Ipv4Addr { addr = u32::from_be_bytes(octets) }`, the From
//   impl in easytier-proto/src/common.rs:68-74), the hostname, a
//   monotonically increasing `version` (starts at 1), a random
//   `peer_route_id`, `network_length`, and the feature flag. `last_update`
//   is rewritten by the receiver anyway (update_peer_infos,
//   peer_ospf_route.rs:1396-1398) but is sent like upstream sends it.
// * **The adjacency** — `SyncRouteInfoRequest.conn_info` as a
//   `RouteConnBitmap` (peer_rpc.proto:60-63): the sorted `peer_ids`
//   vector plus an n×n row-major bit matrix (build code at
//   peer_ospf_route.rs:2900-2967; the parse side `get_connected_peers`
//   at 1196-1203 + graph consumption). For two nodes the matrix says
//   exactly `us ↔ peer`, which is all the SPF graph needs for a direct
//   neighbor.
// * **The session** — one random non-zero `my_session_id` per
//   connection; the connector side is the initiator (`is_initiator =
//   true` on its requests, the election at peer_ospf_route.rs:3900-3966
//   electing one initiator per edge). The responder's requests carry
//   `is_initiator = false` and are admitted by the
//   `admit_inbound_locked` rules (peer_ospf_route.rs:2233-2254) ported
//   below.
// * **The exchange** — client: `sync_route_with_peer`
//   (peer_ospf_route.rs:3467-3620) builds the request, calls the RPC,
//   and on success records the peer's session id + initiator role
//   (`update_remote_state_locked`, 2203-2231). Server:
//   `do_sync_route_info` (4047-4227) admits the session, merges
//   `peer_infos` into the LSDB with the strictly-greater-version rule
//   (`update_peer_infos`, 1364-1400), folds the conn bitmap into the
//   conn map (1407-1460), and answers `{ is_initiator, session_id }`.
// * **Periodic refresh** — upstream re-initiates every 10s while a
//   session lives (peer_ospf_route.rs:3763-3769) and clears an
//   initiator whose RPCs stop for 45s
//   (`INITIATOR_SESSION_LIVENESS_TIMEOUT`, 1985); this port re-syncs on
//   a 10s tick.
//
// What is consciously SKIPPED, and why the subset still routes for a
// DIRECT peer:
//
// * **SPF / the graph algorithms** (`graph_algo.rs`, and the
//   `RouteTable::build_from_snapshot` calls): with exactly two nodes
//   the only path to the peer is the direct connection and the only
//   path back is the adjacency we announce; there is nothing to
//   compute. The peer runs its own SPF over our announced info.
// * **Foreign networks** (`RouteForeignNetworkInfos`, the relay path):
//   only multi-network meshes need it; a direct same-network peer
//   exchanges an empty list.
// * **Credentials / ACL groups / trusted pubkeys** (Step 9b in
//   `do_sync_route_info`, `TrustedCredentialPubkey*`): admin nodes with
//   a network secret (our case) skip every branch —
//   `get_peer_identity_type_from_interface` defaults to `Admin` for an
//   unknown direct peer.
// * **`missing_peer_ids` chasing** (`collect_missing_peer_ids`,
//   `request_missing_peer_infos`): the peer asks for infos of peers we
//   referenced but did not send. In a two-node mesh we only ever
//   reference ourselves, so the lists come back empty; a non-empty list
//   is logged and retried by the next periodic sync.
// * **The `RouteConnPeerList` conn-info form** (the `support_conn_list_
//   sync` feature, peer_ospf_route.rs:3364-3379): we send the bitmap
//   form, which every version accepts; our feature flag does not
//   advertise the list feature so peers answer in bitmap form too.
// * **Stale-session rejection subtleties**
//   (`sync_request_is_current_locked`, `state_revision`): the two-node
//   session never changes generation without a reconnect, on which this
//   side starts a fresh session id anyway.
// * **Route expiration sweeps** (`clear_expired_peer`, 3610s): a
//   61-minute dead-peer GC with no effect on a live two-node mesh.

/// `common.UUID` (common.proto:127-131) — four random u32s, one per
/// node incarnation (`uuid::Uuid::new_v4`, peer_manager.rs:895-899).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OverlayUuid {
    pub part1: u32,
    pub part2: u32,
    pub part3: u32,
    pub part4: u32,
}

impl OverlayUuid {
    pub fn random() -> Self {
        OverlayUuid {
            part1: rand::random(),
            part2: rand::random(),
            part3: rand::random(),
            part4: rand::random(),
        }
    }

    fn encode(&self, out: &mut Vec<u8>) {
        proto_put_varint(out, 0x08);
        proto_put_varint(out, self.part1 as u64);
        proto_put_varint(out, 0x10);
        proto_put_varint(out, self.part2 as u64);
        proto_put_varint(out, 0x18);
        proto_put_varint(out, self.part3 as u64);
        proto_put_varint(out, 0x20);
        proto_put_varint(out, self.part4 as u64);
    }
}

/// The decoded subset of `RoutePeerInfo` (peer_rpc.proto:22-53) this
/// port reads back: identity, the overlay IPv4 (+ its prefix length),
/// hostname, version, and the proxied CIDRs. Unknown fields are skipped
/// on decode (they are never re-encoded — this side only ever announces
/// its own info, so upstream's raw-bytes preservation for multi-hop
/// propagation does not apply).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoutePeerInfo {
    pub peer_id: PeerId,
    pub inst_id: Option<OverlayUuid>,
    pub cost: u32,
    /// `common.Ipv4Addr.addr` — `u32::from_be_bytes(octets)`.
    pub ipv4_addr: Option<u32>,
    pub network_length: u32,
    pub proxy_cidrs: Vec<String>,
    pub hostname: Option<String>,
    pub last_update_secs: i64,
    pub version: u32,
    pub easytier_version: String,
    pub peer_route_id: u64,
    pub is_public_server: bool,
    pub support_conn_list_sync: bool,
}

impl RoutePeerInfo {
    /// The overlay address as an `Ipv4Addr` (`From<Ipv4Addr> for
    /// common::Ipv4Addr`, easytier-proto/src/common.rs:68-74: `addr =
    /// u32::from_be_bytes(octets)`, which equals `u32::from(ip)`).
    pub fn ipv4(&self) -> Option<Ipv4Addr> {
        self.ipv4_addr.map(Ipv4Addr::from)
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        if self.peer_id != 0 {
            proto_put_varint(&mut out, 0x08);
            proto_put_varint(&mut out, self.peer_id as u64);
        }
        if let Some(inst) = &self.inst_id {
            let mut inner = Vec::new();
            inst.encode(&mut inner);
            proto_put_len_field(&mut out, 2, &inner);
        }
        if self.cost != 0 {
            proto_put_varint(&mut out, 0x18);
            proto_put_varint(&mut out, self.cost as u64);
        }
        if let Some(addr) = self.ipv4_addr {
            let mut inner = Vec::new();
            proto_put_varint(&mut inner, 0x08);
            proto_put_varint(&mut inner, addr as u64);
            proto_put_len_field(&mut out, 4, &inner);
        }
        for cidr in &self.proxy_cidrs {
            proto_put_len_field(&mut out, 5, cidr.as_bytes());
        }
        if let Some(hostname) = &self.hostname {
            if !hostname.is_empty() {
                proto_put_len_field(&mut out, 6, hostname.as_bytes());
            }
        }
        if self.last_update_secs != 0 {
            let mut inner = Vec::new();
            proto_put_varint(&mut inner, 0x08);
            proto_put_varint(&mut inner, self.last_update_secs as u64);
            proto_put_len_field(&mut out, 8, &inner);
        }
        if self.version != 0 {
            proto_put_varint(&mut out, 0x48);
            proto_put_varint(&mut out, self.version as u64);
        }
        if !self.easytier_version.is_empty() {
            proto_put_len_field(&mut out, 10, self.easytier_version.as_bytes());
        }
        if self.is_public_server || self.support_conn_list_sync {
            let mut inner = Vec::new();
            if self.is_public_server {
                proto_put_varint(&mut inner, 0x08);
                proto_put_varint(&mut inner, 1);
            }
            if self.support_conn_list_sync {
                proto_put_varint(&mut inner, 0x28);
                proto_put_varint(&mut inner, 1);
            }
            proto_put_len_field(&mut out, 11, &inner);
        }
        if self.peer_route_id != 0 {
            proto_put_varint(&mut out, 0x60);
            proto_put_varint(&mut out, self.peer_route_id);
        }
        if self.network_length != 0 {
            proto_put_varint(&mut out, 0x68);
            proto_put_varint(&mut out, self.network_length as u64);
        }
        out
    }

    fn decode(buf: &[u8]) -> Result<Self> {
        let mut info = RoutePeerInfo::default();
        let mut reader = ProtoReader { buf, pos: 0 };
        while reader.pos < buf.len() {
            let tag = reader.varint()?;
            match (tag >> 3, tag & 7) {
                (1, 0) => info.peer_id = reader.varint()? as PeerId,
                (2, 2) => {
                    let inner = reader.len_bytes()?;
                    let mut uuid = OverlayUuid {
                        part1: 0,
                        part2: 0,
                        part3: 0,
                        part4: 0,
                    };
                    let mut sub = ProtoReader { buf: inner, pos: 0 };
                    while sub.pos < inner.len() {
                        let sub_tag = sub.varint()?;
                        match (sub_tag >> 3, sub_tag & 7) {
                            (1, 0) => uuid.part1 = sub.varint()? as u32,
                            (2, 0) => uuid.part2 = sub.varint()? as u32,
                            (3, 0) => uuid.part3 = sub.varint()? as u32,
                            (4, 0) => uuid.part4 = sub.varint()? as u32,
                            _ => sub.skip(sub_tag & 7)?,
                        }
                    }
                    info.inst_id = Some(uuid);
                }
                (3, 0) => info.cost = reader.varint()? as u32,
                (4, 2) => {
                    let inner = reader.len_bytes()?;
                    let mut sub = ProtoReader { buf: inner, pos: 0 };
                    while sub.pos < inner.len() {
                        let sub_tag = sub.varint()?;
                        match (sub_tag >> 3, sub_tag & 7) {
                            (1, 0) => info.ipv4_addr = Some(sub.varint()? as u32),
                            _ => sub.skip(sub_tag & 7)?,
                        }
                    }
                }
                (5, 2) => info
                    .proxy_cidrs
                    .push(String::from_utf8_lossy(reader.len_bytes()?).into_owned()),
                (6, 2) => {
                    info.hostname =
                        Some(String::from_utf8_lossy(reader.len_bytes()?).into_owned())
                }
                (8, 2) => {
                    let inner = reader.len_bytes()?;
                    let mut sub = ProtoReader { buf: inner, pos: 0 };
                    while sub.pos < inner.len() {
                        let sub_tag = sub.varint()?;
                        match (sub_tag >> 3, sub_tag & 7) {
                            (1, 0) => info.last_update_secs = sub.varint()? as i64,
                            _ => sub.skip(sub_tag & 7)?,
                        }
                    }
                }
                (9, 0) => info.version = reader.varint()? as u32,
                (10, 2) => {
                    info.easytier_version =
                        String::from_utf8_lossy(reader.len_bytes()?).into_owned()
                }
                (11, 2) => {
                    let inner = reader.len_bytes()?;
                    let mut sub = ProtoReader { buf: inner, pos: 0 };
                    while sub.pos < inner.len() {
                        let sub_tag = sub.varint()?;
                        match (sub_tag >> 3, sub_tag & 7) {
                            (1, 0) => info.is_public_server = sub.varint()? != 0,
                            (5, 0) => info.support_conn_list_sync = sub.varint()? != 0,
                            _ => sub.skip(sub_tag & 7)?,
                        }
                    }
                }
                (12, 0) => info.peer_route_id = reader.varint()?,
                (13, 0) => info.network_length = reader.varint()? as u32,
                _ => reader.skip(tag & 7)?,
            }
        }
        Ok(info)
    }
}

/// `PeerIdVersion` (peer_rpc.proto:55-58).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PeerIdVersion {
    pub peer_id: PeerId,
    pub version: u32,
}

/// `RouteConnBitmap` (peer_rpc.proto:60-63): the sorted peer-id rows and
/// the row-major adjacency bits — bit `(row * n + col)` of `bitmap` says
/// `peer_ids[row]` is directly connected to `peer_ids[col]`
/// (peer_ospf_route.rs:2952-2967).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RouteConnBitmap {
    pub peer_ids: Vec<PeerIdVersion>,
    pub bitmap: Vec<u8>,
}

impl RouteConnBitmap {
    /// The two-node adjacency (the cached bitmap a direct mesh always
    /// rebuilds to, peer_ospf_route.rs:2900-2967 with one conn-map
    /// entry per side).
    pub fn two_node(us: PeerId, them: PeerId) -> Self {
        let mut ids = [us, them];
        ids.sort_unstable();
        let mut bitmap = vec![0u8; (4usize).div_ceil(8)];
        if us != them {
            let row = ids.iter().position(|id| *id == us).expect("us in ids");
            let col = ids.iter().position(|id| *id == them).expect("them in ids");
            let n = ids.len();
            let bit = row * n + col;
            bitmap[bit / 8] |= 1 << (bit % 8);
            let bit = col * n + row;
            bitmap[bit / 8] |= 1 << (bit % 8);
        }
        RouteConnBitmap {
            peer_ids: ids
                .iter()
                .map(|id| PeerIdVersion {
                    peer_id: *id,
                    version: 1,
                })
                .collect(),
            bitmap,
        }
    }

    /// `get_connected_peers` (peer_ospf_route.rs:1196-1203) — the peers
    /// directly connected to `peer_id`.
    pub fn connected_peers(&self, peer_id: PeerId) -> Option<Vec<PeerId>> {
        let idx = self.peer_ids.iter().position(|p| p.peer_id == peer_id)?;
        let n = self.peer_ids.len();
        if self.bitmap.len() < (n * n).div_ceil(8) {
            return None;
        }
        let mut out = Vec::new();
        for (col, other) in self.peer_ids.iter().enumerate() {
            let bit = idx * n + col;
            if self.bitmap[bit / 8] & (1 << (bit % 8)) != 0 {
                out.push(other.peer_id);
            }
        }
        Some(out)
    }

    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for p in &self.peer_ids {
            let mut inner = Vec::new();
            proto_put_varint(&mut inner, 0x08);
            proto_put_varint(&mut inner, p.peer_id as u64);
            if p.version != 0 {
                proto_put_varint(&mut inner, 0x10);
                proto_put_varint(&mut inner, p.version as u64);
            }
            proto_put_len_field(&mut out, 1, &inner);
        }
        if !self.bitmap.is_empty() {
            proto_put_len_field(&mut out, 2, &self.bitmap);
        }
        out
    }

    fn decode(buf: &[u8]) -> Result<Self> {
        let mut bm = RouteConnBitmap::default();
        let mut reader = ProtoReader { buf, pos: 0 };
        while reader.pos < buf.len() {
            let tag = reader.varint()?;
            match (tag >> 3, tag & 7) {
                (1, 2) => {
                    let inner = reader.len_bytes()?;
                    let mut entry = PeerIdVersion::default();
                    let mut sub = ProtoReader { buf: inner, pos: 0 };
                    while sub.pos < inner.len() {
                        let sub_tag = sub.varint()?;
                        match (sub_tag >> 3, sub_tag & 7) {
                            (1, 0) => entry.peer_id = sub.varint()? as PeerId,
                            (2, 0) => entry.version = sub.varint()? as u32,
                            _ => sub.skip(sub_tag & 7)?,
                        }
                    }
                    bm.peer_ids.push(entry);
                }
                (2, 2) => bm.bitmap = reader.len_bytes()?.to_vec(),
                _ => reader.skip(tag & 7)?,
            }
        }
        Ok(bm)
    }
}

/// `SyncRouteInfoRequest` (peer_rpc.proto:111-121). Only the bitmap
/// conn-info arm (field 5) is carried; the `conn_peer_list` arm (7) is
/// the skipped optional form.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncRouteInfoRequest {
    pub my_peer_id: PeerId,
    pub my_session_id: u64,
    pub is_initiator: bool,
    pub peer_infos: Vec<RoutePeerInfo>,
    pub conn_bitmap: Option<RouteConnBitmap>,
}

impl SyncRouteInfoRequest {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.my_peer_id != 0 {
            proto_put_varint(&mut out, 0x08);
            proto_put_varint(&mut out, self.my_peer_id as u64);
        }
        if self.my_session_id != 0 {
            proto_put_varint(&mut out, 0x10);
            proto_put_varint(&mut out, self.my_session_id);
        }
        if self.is_initiator {
            proto_put_varint(&mut out, 0x18);
            proto_put_varint(&mut out, 1);
        }
        if !self.peer_infos.is_empty() {
            let mut inner = Vec::new();
            for info in &self.peer_infos {
                let encoded = info.encode();
                proto_put_len_field(&mut inner, 1, &encoded);
            }
            proto_put_len_field(&mut out, 4, &inner);
        }
        if let Some(bitmap) = &self.conn_bitmap {
            let encoded = bitmap.encode();
            proto_put_len_field(&mut out, 5, &encoded);
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut req = SyncRouteInfoRequest::default();
        let mut reader = ProtoReader { buf, pos: 0 };
        while reader.pos < buf.len() {
            let tag = reader.varint()?;
            match (tag >> 3, tag & 7) {
                (1, 0) => req.my_peer_id = reader.varint()? as PeerId,
                (2, 0) => req.my_session_id = reader.varint()?,
                (3, 0) => req.is_initiator = reader.varint()? != 0,
                (4, 2) => {
                    let inner = reader.len_bytes()?;
                    let mut sub = ProtoReader { buf: inner, pos: 0 };
                    while sub.pos < inner.len() {
                        let sub_tag = sub.varint()?;
                        match (sub_tag >> 3, sub_tag & 7) {
                            (1, 2) => req
                                .peer_infos
                                .push(RoutePeerInfo::decode(sub.len_bytes()?)?),
                            _ => sub.skip(sub_tag & 7)?,
                        }
                    }
                }
                (5, 2) => req.conn_bitmap = Some(RouteConnBitmap::decode(reader.len_bytes()?)?),
                _ => reader.skip(tag & 7)?,
            }
        }
        Ok(req)
    }
}

/// `SyncRouteInfoResponse` (peer_rpc.proto:128-135). `error` is the
/// optional `SyncRouteInfoError` (123-126: DuplicatePeerId = 0,
/// Stopped = 1).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SyncRouteInfoResponse {
    pub is_initiator: bool,
    pub session_id: u64,
    pub error: Option<u32>,
    pub missing_peer_ids: Vec<PeerId>,
}

impl SyncRouteInfoResponse {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        if self.is_initiator {
            proto_put_varint(&mut out, 0x08);
            proto_put_varint(&mut out, 1);
        }
        if self.session_id != 0 {
            proto_put_varint(&mut out, 0x10);
            proto_put_varint(&mut out, self.session_id);
        }
        if let Some(err) = self.error {
            proto_put_varint(&mut out, 0x18);
            proto_put_varint(&mut out, err as u64);
        }
        for id in &self.missing_peer_ids {
            proto_put_varint(&mut out, 0x20);
            proto_put_varint(&mut out, *id as u64);
        }
        out
    }

    pub fn decode(buf: &[u8]) -> Result<Self> {
        let mut resp = SyncRouteInfoResponse::default();
        let mut reader = ProtoReader { buf, pos: 0 };
        while reader.pos < buf.len() {
            let tag = reader.varint()?;
            match (tag >> 3, tag & 7) {
                (1, 0) => resp.is_initiator = reader.varint()? != 0,
                (2, 0) => resp.session_id = reader.varint()?,
                (3, 0) => resp.error = Some(reader.varint()? as u32),
                (4, 0) => resp.missing_peer_ids.push(reader.varint()? as PeerId),
                _ => reader.skip(tag & 7)?,
            }
        }
        Ok(resp)
    }
}

/// `DhcpIpv4Allocator::evaluate` (gateway/dhcp.rs:51-78): pick the first
/// address of the subnet that no known route uses, skipping the network
/// and broadcast addresses. Modern EasyTier's `dhcp = true` is exactly
/// this local allocation from the gossiped route table — there is no
/// DHCP server protocol on the wire.
pub fn allocate_overlay_ipv4(used: &[Ipv4Addr], subnet: Ipv4Addr, prefix: u8) -> Option<Ipv4Addr> {
    let mask = if prefix == 0 {
        return None;
    } else if prefix >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - prefix)
    };
    let network = u32::from(subnet) & mask;
    let broadcast = network | !mask;
    // `subnet.iter()` walks host order (network + 1 .. broadcast - 1 like
    // upstream's `network().iter()` with the first/last excluded).
    for host in (network + 1)..broadcast {
        let candidate = Ipv4Addr::from(host);
        if !used.contains(&candidate) {
            return Some(candidate);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// The peer node (peers/conn/peer_conn.rs + peer_conn_ping.rs + the
// add_new_peer_conn identity check of peers/peer_manager.rs:379-416)
// ---------------------------------------------------------------------------

/// `DIRECT_CONNECT_TIMEOUT` (connectivity/direct/mod.rs:64).
const DIRECT_CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// The handshake wait (peer_conn.rs:511 `Duration::from_secs(5)`).
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
/// `do_pingpong_once` pong timeout (peer_conn_ping.rs:220).
const PONG_TIMEOUT: Duration = Duration::from_secs(2);
/// The controller tick (peer_conn_ping.rs:73 `Duration::from_secs(1)`).
const PING_TICK: Duration = Duration::from_secs(1);
/// `too many consecutive pingpong failures` threshold
/// (peer_conn_ping.rs:309).
const MAX_CONSECUTIVE_PING_LOSS: u32 = 5;
/// The `PacketRecvChan` capacity (peers/mod.rs:115).
const PACKET_CHAN_CAPACITY: usize = 128;

/// The peer's handshake answer as the client sees it.
#[derive(Debug, Clone)]
pub struct PeerInfo {
    pub peer_id: PeerId,
    pub network_name: String,
    pub network_secret_digest: NetworkSecretDigest,
    pub features: Vec<String>,
    pub version: u32,
}

struct ConnState {
    my_peer_id: PeerId,
    peer_id: PeerId,
    encryptor: PacketEncryptor,
    /// The secure-mode session: when set, every payload-bearing packet
    /// crosses THIS AEAD instead of the network-secret `encryptor`
    /// (`PeerSessionTunnelFilter` with `enabled = true`, peer_conn.rs:
    /// 147-248 — the peer manager skips its own encryptor in secure
    /// mode, peer_manager.rs:103-104).
    secure: Option<Arc<PeerSecureSession>>,
    sink: mpsc::Sender<PeerPacket>,
    pong_tx: broadcast::Sender<PeerPacket>,
    data_tx: mpsc::Sender<Vec<u8>>,
    ctrl_tx: mpsc::Sender<PeerPacket>,
    latency_us: AtomicU64,
    tx_packets: AtomicU64,
    rx_packets: AtomicU64,
    closed: Notify,
    close_flag: AtomicU32,
}

impl ConnState {
    fn notify_closed_once(&self) {
        if self.close_flag.swap(1, Ordering::AcqRel) == 0 {
            self.closed.notify_waiters();
            self.closed.notify_one();
        }
    }

    /// Seal one outbound payload packet — the secure-mode session AEAD
    /// when the connection has one, the network-secret AEAD otherwise
    /// (`PeerSessionTunnelFilter::before_send` vs the peer manager's
    /// `encryptor.encrypt`, gated by `!is_secure_mode_enabled`).
    fn seal_outgoing(&self, hdr: &mut PeerManagerHeader, payload: &mut Vec<u8>) -> Result<()> {
        if let Some(session) = &self.secure {
            // The filter skips the handshake/relay/ping/pong types; every
            // packet reaching this seam is a payload type.
            return session.encrypt_payload(self.my_peer_id, self.peer_id, hdr, payload);
        }
        self.encryptor.encrypt_packet(hdr, payload)
    }
}

/// The recv loop (`start_recv_loop`, peer_conn.rs:1286-1366): Ping →
/// flip the header to Pong and echo (peer_conn.rs:1334-1341), Pong →
/// the control broadcast, Data → decrypt and hand the IP frame up,
/// everything else → the control channel for the route/RPC layer.
///
/// DELTA vs M1: `PacketType::RpcReq`/`RpcResp` payloads are decrypted
/// with the same network-secret encryptor as `Data` before delivery —
/// in the real core the peer manager's `RpcTransport::send` calls
/// `encryptor.encrypt` for every RPC packet to a non-public-server
/// peer (peers/peer_manager.rs:153-169) and `handle_packet` decrypts
/// them on the self-destined receive path (peers/peer_manager.rs:
/// 3170-3192); Ping/Pong stay plaintext (`should_skip_encrypt`,
/// peers/conn/peer_conn.rs:125-133). In secure mode the session AEAD
/// replaces the network-secret one on BOTH seams
/// (`PeerSessionTunnelFilter::after_received`, peer_conn.rs:190-245):
/// a transient failure drops the packet, an invalidated session (ten
/// consecutive decrypt failures) closes the connection so the peer
/// re-handshakes.
async fn run_recv_loop<R: AsyncRead + Unpin>(mut reader: R, state: Arc<ConnState>) {
    loop {
        let packet = match read_frame(&mut reader).await {
            Ok(Some(packet)) => packet,
            Ok(None) | Err(_) => break,
        };
        state.rx_packets.fetch_add(1, Ordering::Relaxed);
        let mut packet = packet;
        if packet.hdr.packet_type == packet_type::PING {
            packet.hdr.packet_type = packet_type::PONG;
            let _ = state.sink.send(packet).await;
            continue;
        }
        if packet.hdr.packet_type == packet_type::PONG {
            let _ = state.pong_tx.send(packet);
            continue;
        }
        if packet.hdr.packet_type == packet_type::DATA
            || packet.hdr.packet_type == packet_type::RPC_REQ
            || packet.hdr.packet_type == packet_type::RPC_RESP
        {
            // Direct two-node mesh: only frames addressed to us from the
            // joined peer carry our data (the peer manager would forward
            // anything else; there is nothing to forward to yet).
            if packet.hdr.from_peer_id != state.peer_id
                || packet.hdr.to_peer_id != state.my_peer_id
            {
                continue;
            }
            let decrypted = match &state.secure {
                Some(session) => session.decrypt_payload(
                    state.peer_id,
                    state.my_peer_id,
                    &mut packet.hdr,
                    &mut packet.payload,
                ),
                None => state
                    .encryptor
                    .decrypt_packet(&mut packet.hdr, &mut packet.payload),
            };
            if let Err(e) = decrypted {
                if state.secure.as_ref().is_some_and(|s| !s.is_valid()) {
                    tracing::warn!(target: "engine", "easytier: session invalidated, closing connection: {e}");
                    break;
                }
                continue;
            }
            if packet.hdr.packet_type == packet_type::DATA {
                if state.data_tx.send(packet.payload).await.is_err() {
                    break;
                }
            } else if state.ctrl_tx.send(packet).await.is_err() {
                break;
            }
            continue;
        }
        if state.ctrl_tx.send(packet).await.is_err() {
            break;
        }
    }
    state.notify_closed_once();
}

/// The writer half: drains the outbound channel to the socket.
async fn run_writer_loop<W: AsyncWrite + Unpin>(mut writer: W, state: Arc<ConnState>, mut rx: mpsc::Receiver<PeerPacket>) {
    while let Some(packet) = rx.recv().await {
        state.tx_packets.fetch_add(1, Ordering::Relaxed);
        if write_frame(&mut writer, &packet).await.is_err() {
            break;
        }
    }
    state.notify_closed_once();
}

/// `PingIntervalController` (peer_conn_ping.rs:57-133): a 1-second logic
/// clock; a ping is due when `logic_time - last_send >= 1 << backoff`,
/// where the backoff grows up to 5 and resets while traffic flows one way
/// or pings are being lost.
struct PingIntervalController {
    logic_time: u64,
    last_send_logic_time: u64,
    backoff_idx: i32,
    max_backoff_idx: i32,
    last_tx_packets: u64,
    last_rx_packets: u64,
}

impl PingIntervalController {
    fn new() -> Self {
        Self {
            logic_time: 0,
            last_send_logic_time: 0,
            backoff_idx: 0,
            max_backoff_idx: 5,
            last_tx_packets: 0,
            last_rx_packets: 0,
        }
    }

    /// `should_send_ping` (peer_conn_ping.rs:94-125) with the loss counter
    /// and throughput signals of `ConnState`.
    fn should_send_ping(&mut self, state: &ConnState, loss_counter: u32) -> bool {
        let tx = state.tx_packets.load(Ordering::Relaxed);
        let rx = state.rx_packets.load(Ordering::Relaxed);
        let tx_increase = tx > self.last_tx_packets;
        let rx_increase = rx > self.last_rx_packets;
        self.last_tx_packets = tx;
        self.last_rx_packets = rx;

        // Losses, or one-way traffic, pin the backoff at zero
        // (peer_conn_ping.rs:95-100; both branches reset identically).
        if loss_counter > 0 || (tx_increase && !rx_increase) {
            self.backoff_idx = 0;
        }

        if (self.logic_time - self.last_send_logic_time) < (1u64 << self.backoff_idx) {
            return false;
        }

        self.backoff_idx = std::cmp::min(self.backoff_idx + 1, self.max_backoff_idx);
        // `use this makes two peers not pingpong at the same time`
        // (peer_conn_ping.rs:120-122).
        if self.backoff_idx > self.max_backoff_idx - 2
            && rand::Rng::gen_bool(&mut rand::thread_rng(), 0.2)
        {
            self.backoff_idx -= 1;
        }
        self.last_send_logic_time = self.logic_time;
        true
    }
}

/// `pingpong` (peer_conn_ping.rs:240-319): the controller fires
/// `do_pingpong_once`; five consecutive losses close the connection.
async fn run_ping_loop(state: Arc<ConnState>) {
    let mut controller = PingIntervalController::new();
    let mut loss_counter: u32 = 0;
    let mut req_seq: u32 = 0;
    let mut tick = tokio::time::interval(PING_TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            _ = tick.tick() => {
                controller.logic_time += 1;
                if !controller.should_send_ping(&state, loss_counter) {
                    continue;
                }
                let ping = PeerPacket::new(
                    state.my_peer_id,
                    state.peer_id,
                    packet_type::PING,
                    &req_seq.to_le_bytes(),
                );
                if state.sink.send(ping).await.is_err() {
                    break;
                }
                // `do_pingpong_once` (peer_conn_ping.rs:167-236): await the
                // pong carrying our seq, 2s timeout.
                let mut receiver = state.pong_tx.subscribe();
                let got_pong = tokio::time::timeout(PONG_TIMEOUT, async {
                    loop {
                        match receiver.recv().await {
                            Ok(p) if p.payload.len() >= 4
                                && u32::from_le_bytes(p.payload[0..4].try_into().unwrap())
                                    == req_seq =>
                            {
                                return true;
                            }
                            Ok(_) => continue,
                            Err(broadcast::error::RecvError::Lagged(_)) => continue,
                            Err(broadcast::error::RecvError::Closed) => return false,
                        }
                    }
                })
                .await
                .unwrap_or(false);
                req_seq = req_seq.wrapping_add(1);
                if got_pong {
                    // The latency is measured by the caller of `ping`;
                    // the keepalive only clears the loss counter
                    // (peer_conn_ping.rs:279-286).
                    loss_counter = 0;
                } else {
                    loss_counter += 1;
                    if loss_counter >= MAX_CONSECUTIVE_PING_LOSS {
                        break;
                    }
                }
            }
            _ = state.closed.notified() => break,
        }
    }
    state.notify_closed_once();
}

/// A live direct-TCP EasyTier peer connection: one joined mesh neighbor.
pub struct EasyTierNode {
    my_peer_id: PeerId,
    peer_id: PeerId,
    network_name: String,
    state: Arc<ConnState>,
    data_rx: Mutex<mpsc::Receiver<Vec<u8>>>,
    ctrl_rx: Mutex<mpsc::Receiver<PeerPacket>>,
    tasks: Mutex<Vec<tokio::task::JoinHandle<()>>>,
}

impl std::fmt::Debug for EasyTierNode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EasyTierNode")
            .field("my_peer_id", &self.my_peer_id)
            .field("peer_id", &self.peer_id)
            .field("network_name", &self.network_name)
            .finish()
    }
}

impl EasyTierNode {
    /// Our `PeerId` (`random_peer_id`, peers/peer_manager.rs:192-198).
    pub fn my_peer_id(&self) -> PeerId {
        self.my_peer_id
    }

    /// The joined peer's id (its handshake `my_peer_id`).
    pub fn peer_id(&self) -> PeerId {
        self.peer_id
    }

    /// The mesh network name we validated against.
    pub fn network_name(&self) -> &str {
        &self.network_name
    }

    /// Whether the underlying connection has closed.
    pub fn is_closed(&self) -> bool {
        self.state.close_flag.load(Ordering::Acquire) == 1
    }

    /// The last explicit `ping()` round trip in microseconds.
    pub fn latency_us(&self) -> u64 {
        self.state.latency_us.load(Ordering::Relaxed)
    }

    /// Send one IP frame onto the mesh for this peer (`send_msg_by_ip`,
    /// peers/peer_manager.rs:2793-2855: `fill_peer_manager_hdr(my_peer_id,
    /// dst, Data)` then `try_compress_and_encrypt` — compression stays
    /// off, matching the default `data_compress_algo = None`).
    pub async fn send_ip_frame(&self, frame: &[u8]) -> Result<()> {
        self.send_packet(packet_type::DATA, frame).await
    }

    /// The shared encrypting sender for every payload-bearing packet type:
    /// `Data` (`send_msg_by_ip` → `try_compress_and_encrypt`,
    /// peer_manager.rs:2641-2660) and `RpcReq`/`RpcResp`
    /// (`RpcTransport::send` → `encryptor.encrypt`, peer_manager.rs:
    /// 153-169) both leave the node sealed by the network-secret
    /// encryptor in plain (non-secure) mode, or by the per-peer session
    /// AEAD in secure mode.
    async fn send_packet(&self, packet_type: u8, payload: &[u8]) -> Result<()> {
        let mut hdr = PeerManagerHeader {
            from_peer_id: self.my_peer_id,
            to_peer_id: self.peer_id,
            packet_type,
            flags: 0,
            forward_counter: 1,
            reserved: 0,
            len: payload.len() as u32,
        };
        let mut payload = payload.to_vec();
        self.state.seal_outgoing(&mut hdr, &mut payload)?;
        self.state
            .sink
            .send(PeerPacket { hdr, payload })
            .await
            .map_err(|_| Error::network("easytier: peer connection closed"))
    }

    /// Send one control payload as an `RpcReq`/`RpcResp` peer packet (the
    /// client and server halves of the route-gossip RPC layer; the
    /// `PeerRpcManager` send path, peers/peer_rpc.rs:63-84).
    pub async fn send_rpc_packet(&self, is_request: bool, payload: &[u8]) -> Result<()> {
        self.send_packet(
            if is_request {
                packet_type::RPC_REQ
            } else {
                packet_type::RPC_RESP
            },
            payload,
        )
        .await
    }

    /// Receive the next IP frame the peer sent us (the Data-packet
    /// delivery of the recv loop, already decrypted).
    pub async fn recv_ip_frame(&self) -> Option<Vec<u8>> {
        self.data_rx.lock().await.recv().await
    }

    /// Non-route control packets (RpcReq/RpcResp/…) — the seam the route
    /// gossip milestone consumes.
    pub async fn recv_ctrl_packet(&self) -> Option<PeerPacket> {
        self.ctrl_rx.lock().await.recv().await
    }

    /// One explicit ping/pong round trip (`do_pingpong_once`,
    /// peer_conn_ping.rs:167-236): returns the latency.
    pub async fn ping(&self) -> Result<Duration> {
        let latency = conn_ping(&self.state).await?;
        self.state
            .latency_us
            .store(latency.as_micros() as u64, Ordering::Relaxed);
        Ok(latency)
    }

    /// Wait for the connection to close (the `PeerConnCloseNotify`
    /// waiter, peer_conn.rs:238-271).
    pub async fn wait_closed(&self) {
        if self.is_closed() {
            return;
        }
        self.state.closed.notified().await;
    }

    /// Shut the connection down (drop the sink and join the tasks).
    pub async fn close(self) {
        self.state.notify_closed_once();
        let mut tasks = self.tasks.lock().await;
        for task in tasks.iter() {
            task.abort();
        }
        for task in tasks.drain(..) {
            let _ = task.await;
        }
    }
}

/// The consumed halves of one connected stream: the shared connection
/// state (the send path — everything an overlay node needs to emit
/// packets to this peer) plus the receive channels its event pump
/// drains, and the tasks to abort when the session ends.
pub struct SessionHalves {
    state: Arc<ConnState>,
    data_rx: mpsc::Receiver<Vec<u8>>,
    ctrl_rx: mpsc::Receiver<PeerPacket>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
}

impl SessionHalves {
    /// Wrap back into the standalone per-connection node object (the
    /// shape the plain `connect_peer`/`serve_peer` APIs return).
    fn into_node(self, network_name: String) -> EasyTierNode {
        EasyTierNode {
            my_peer_id: self.state.my_peer_id,
            peer_id: self.state.peer_id,
            network_name,
            state: self.state,
            data_rx: Mutex::new(self.data_rx),
            ctrl_rx: Mutex::new(self.ctrl_rx),
            tasks: Mutex::new(self.tasks),
        }
    }
}

/// One ping/pong round trip over a live connection state — the shared
/// body of [`EasyTierNode::ping`] and the post-dial liveness check.
async fn conn_ping(state: &Arc<ConnState>) -> Result<Duration> {
    let seq: u32 = rand::random();
    let ping = PeerPacket::new(
        state.my_peer_id,
        state.peer_id,
        packet_type::PING,
        &seq.to_le_bytes(),
    );
    let mut receiver = state.pong_tx.subscribe();
    state
        .sink
        .send(ping)
        .await
        .map_err(|_| Error::network("easytier: peer connection closed"))?;
    let start = std::time::Instant::now();
    tokio::time::timeout(PONG_TIMEOUT, async {
        loop {
            match receiver.recv().await {
                Ok(p) if p.payload.len() >= 4
                    && u32::from_le_bytes(p.payload[0..4].try_into().unwrap()) == seq =>
                {
                    return Ok(())
                }
                Ok(_) => continue,
                Err(broadcast::error::RecvError::Lagged(_)) => continue,
                Err(broadcast::error::RecvError::Closed) => {
                    return Err(Error::network("easytier: peer connection closed"))
                }
            }
        }
    })
    .await
    .map_err(|_| Error::network("easytier: wait ping response timeout"))??;
    Ok(start.elapsed())
}

/// Spawn the shared post-handshake machinery around a connected stream
/// (the `start_recv_loop` + `start_pingpong` + MpscTunnel wiring of
/// `PeerConn::new_with_peer_id_hint_and_origin`, peer_conn.rs:340-413),
/// returning the raw halves — what the multi-peer overlay node attaches
/// to its peer table (the standalone per-connection object is
/// `SessionHalves::into_node`).
async fn spawn_connection_halves<I>(
    io: I,
    my_peer_id: PeerId,
    peer: &PeerInfo,
    encryptor: PacketEncryptor,
    secure: Option<Arc<PeerSecureSession>>,
) -> SessionHalves
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (sink, sink_rx) = mpsc::channel::<PeerPacket>(PACKET_CHAN_CAPACITY);
    let (pong_tx, _) = broadcast::channel(8);
    let (data_tx, data_rx) = mpsc::channel::<Vec<u8>>(PACKET_CHAN_CAPACITY);
    let (ctrl_tx, ctrl_rx) = mpsc::channel::<PeerPacket>(PACKET_CHAN_CAPACITY);
    let state = Arc::new(ConnState {
        my_peer_id,
        peer_id: peer.peer_id,
        encryptor,
        secure,
        sink,
        pong_tx,
        data_tx,
        ctrl_tx,
        latency_us: AtomicU64::new(0),
        tx_packets: AtomicU64::new(0),
        rx_packets: AtomicU64::new(0),
        closed: Notify::new(),
        close_flag: AtomicU32::new(0),
    });
    let (reader, writer) = tokio::io::split(io);
    let tasks = vec![
        tokio::spawn(run_recv_loop(reader, state.clone())),
        tokio::spawn(run_writer_loop(writer, state.clone(), sink_rx)),
        tokio::spawn(run_ping_loop(state.clone())),
    ];
    SessionHalves {
        state,
        data_rx,
        ctrl_rx,
        tasks,
    }
}


/// Build the plain-mode handshake message (`send_handshake`,
/// peer_conn.rs:529-573): magic, our peer id, version, the
/// liveness-echo feature, the network name and the 32-byte digest (zeros
/// when we have no secret to prove).
fn build_handshake(my_peer_id: PeerId, network_name: &str, digest: Option<&NetworkSecretDigest>) -> PeerPacket {
    let mut req = HandshakeRequest {
        magic: HANDSHAKE_MAGIC,
        my_peer_id,
        version: HANDSHAKE_VERSION,
        features: vec![LIVENESS_ECHO_FEATURE.to_owned()],
        network_name: network_name.to_owned(),
        ..Default::default()
    };
    match digest {
        Some(digest) => req.network_secret_digest.extend_from_slice(digest),
        None => req.network_secret_digest.extend_from_slice(&[0u8; 32]),
    }
    PeerPacket::new(my_peer_id, 0, packet_type::HANDSHAKE, &req.encode())
}

/// `wait_handshake` + `decode_handshake_packet` (peer_conn.rs:458-508,
/// 575-600): a `HandShake`-typed packet whose payload decodes and whose
/// digest is exactly 32 bytes.
async fn wait_handshake<R: AsyncRead + Unpin>(reader: &mut R) -> Result<HandshakeRequest> {
    let deadline = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        loop {
            let packet = read_frame(reader)
                .await?
                .ok_or_else(|| Error::network("easytier: conn closed during wait handshake response"))?;
            if packet.hdr.packet_type != packet_type::HANDSHAKE {
                // `wait_handshake` sets need_retry=true and loops until
                // the 5s timeout (peer_conn.rs:478, 510-527).
                continue;
            }
            let rsp = HandshakeRequest::decode(&packet.payload).map_err(|e| {
                Error::protocol(format!("easytier: decode handshake response error: {e}"))
            })?;
            if rsp.network_secret_digest.len() != std::mem::size_of::<NetworkSecretDigest>() {
                return Err(Error::protocol("easytier: invalid network secret digest"));
            }
            return Ok(rsp);
        }
    })
    .await;
    match deadline {
        Ok(inner) => inner,
        Err(_) => Err(Error::network("easytier: wait handshake timeout")),
    }
}

/// The identity check of `add_new_peer_conn` (peers/peer_manager.rs:
/// 395-412): same network name, and digests compared only when both
/// sides sent a non-zero one (a secret-less peer sends zeros and is
/// checked by name alone).
fn check_network_identity(local_name: &str, local_digest: &NetworkSecretDigest, peer: &PeerInfo) -> Result<()> {
    if peer.network_name != local_name {
        return Err(Error::config("easytier: network identity not match"));
    }
    let my_digest_empty = digest_is_empty(local_digest);
    let peer_digest_empty = digest_is_empty(&peer.network_secret_digest);
    if !my_digest_empty && !peer_digest_empty && *local_digest != peer.network_secret_digest {
        return Err(Error::config("easytier: network identity not match"));
    }
    Ok(())
}

/// `do_handshake_as_client` (peer_conn.rs:1246-1264), plain mode: send
/// our handshake, read the peer's, reject self-connections.
async fn handshake_as_client<I>(
    io: &mut I,
    my_peer_id: PeerId,
    network_name: &str,
    digest: &NetworkSecretDigest,
) -> Result<PeerInfo>
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut writer) = tokio::io::split(io);
    let packet = build_handshake(my_peer_id, network_name, Some(digest));
    write_frame(&mut writer, &packet)
        .await
        .map_err(|_| Error::network("easytier: send handshake request error"))?;
    let rsp = wait_handshake(&mut reader).await?;
    drop(writer);
    drop(reader);
    if rsp.my_peer_id == my_peer_id {
        return Err(Error::protocol(
            "easytier: peer id conflict, are you connecting to yourself?",
        ));
    }
    let mut peer_digest = [0u8; 32];
    peer_digest.copy_from_slice(&rsp.network_secret_digest);
    Ok(PeerInfo {
        peer_id: rsp.my_peer_id,
        network_name: rsp.network_name,
        network_secret_digest: peer_digest,
        features: rsp.features,
        version: rsp.version,
    })
}

/// `do_handshake_as_server_ext` (peer_conn.rs:1234-1281): read the first
/// packet under the 5s timeout and dispatch on its type — a
/// `NoiseHandshakeMsg1` first packet routes into the secure-mode
/// handshake when (and only when) this node runs secure mode
/// (peer_conn.rs:1252-1264); a plain `HandShake` runs the plain reply
/// either way; anything else is `unexpected packet type during
/// handshake` (peer_conn.rs:1277-1281). Returns the peer info plus the
/// live secure session when the noise path ran.
async fn handshake_as_server<I>(
    io: &mut I,
    my_peer_id: PeerId,
    network_name: &str,
    digest: &NetworkSecretDigest,
    secure: Option<&SecureModeCtx>,
) -> Result<(PeerInfo, Option<Arc<PeerSecureSession>>)>
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    let packet = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let packet = read_frame(io)
            .await?
            .ok_or_else(|| Error::network("easytier: conn closed during wait handshake"))?;
        if packet.hdr.packet_type == packet_type::HANDSHAKE
            || (packet.hdr.packet_type == packet_type::NOISE_HANDSHAKE_MSG1
                && secure.is_some())
        {
            Ok(packet)
        } else if packet.hdr.packet_type == packet_type::NOISE_HANDSHAKE_MSG1 {
            // A secure-mode client opened with the Noise_XX msg1 but this
            // node is not configured for secure mode — the generic
            // unexpected-type error of peer_conn.rs:1277-1281, with the
            // cause named.
            Err(Error::protocol(
                "easytier: unexpected packet type during handshake: 13 (NoiseHandshakeMsg1 — the peer runs secure mode, this node does not)",
            ))
        } else {
            Err(Error::protocol(format!(
                "easytier: unexpected packet type during handshake: {}",
                packet.hdr.packet_type
            )))
        }
    })
    .await
    .map_err(|_| Error::network("easytier: wait handshake timeout"))??;

    if packet.hdr.packet_type == packet_type::NOISE_HANDSHAKE_MSG1 {
        let ctx = secure.expect("dispatch checked");
        let outcome = noise_handshake_as_server(io, my_peer_id, ctx, packet).await?;
        tracing::debug!(
            target: "engine",
            "easytier: secure-mode peer {} authenticated at {:?}",
            outcome.peer.peer_id,
            outcome.auth_level
        );
        return Ok((outcome.peer, Some(outcome.session)));
    }

    let req = HandshakeRequest::decode(&packet.payload)
        .map_err(|e| Error::protocol(format!("easytier: decode handshake response error: {e}")))?;
    if req.network_secret_digest.len() != std::mem::size_of::<NetworkSecretDigest>() {
        return Err(Error::protocol("easytier: invalid network secret digest"));
    }
    if req.my_peer_id == my_peer_id {
        return Err(Error::protocol("easytier: peer id conflict"));
    }
    let mut client_digest = [0u8; 32];
    client_digest.copy_from_slice(&req.network_secret_digest);
    // `send_digest = self.get_network_identity() == self.context.network_identity()`
    // (peer_conn.rs:1225): name and digest both equal.
    let same_identity = req.network_name == network_name && client_digest == *digest;
    let reply = build_handshake(my_peer_id, network_name, same_identity.then_some(digest));
    write_frame(io, &reply)
        .await
        .map_err(|_| Error::network("easytier: send handshake request error"))?;
    Ok((
        PeerInfo {
            peer_id: req.my_peer_id,
            network_name: req.network_name,
            network_secret_digest: client_digest,
            features: req.features,
            version: req.version,
        },
        None,
    ))
}

/// The transport of one parsed peer URI (the `IpScheme` arms the peer
/// connector dispatches on, connector/mod.rs:247-268: `Tcp`, `Udp`,
/// `Quic`, `Wg`, `Ws | Wss`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerTransport {
    Tcp,
    Udp,
    Quic,
    Wg,
    Ws,
    Wss,
}

/// One parsed `tcp://`/`udp://`/`quic://`/`wg://`/`ws://`/`wss://` peer
/// endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEndpoint {
    pub transport: PeerTransport,
    pub host: String,
    pub port: u16,
}

/// `protocol_default_port("tcp")` (connectivity/protocol/mod.rs:55-64)
/// via `protocol_port_offset`: 11010 + 0.
pub const DEFAULT_PEER_PORT: u16 = 11010;

/// The per-scheme default port (`IpScheme::default_port`, tunnel/mod.rs:334-342):
/// `ws` 80, `wss` 443, everything else `11010 + port_offset` with the
/// offsets `tcp` 0 / `udp` 0 / `wg` 1 / `quic` 2 / `ws` 1 / `wss` 2
/// (tunnel/mod.rs:306-328 — only `ws`/`wss` special-case the well-known
/// ports).
pub fn transport_default_port(transport: PeerTransport) -> u16 {
    match transport {
        PeerTransport::Tcp | PeerTransport::Udp => DEFAULT_PEER_PORT,
        PeerTransport::Wg => DEFAULT_PEER_PORT + 1,
        PeerTransport::Quic => DEFAULT_PEER_PORT + 2,
        PeerTransport::Ws => 80,
        PeerTransport::Wss => 443,
    }
}

/// Parse a peer URI down to transport + host + port. The TCP, UDP, QUIC,
/// WireGuard and WebSocket schemes are live; anything else names the
/// unported transports.
pub fn parse_peer_endpoint(uri: &str) -> Result<PeerEndpoint> {
    let (transport, rest) = if let Some(rest) = uri.strip_prefix("tcp://") {
        (PeerTransport::Tcp, rest)
    } else if let Some(rest) = uri.strip_prefix("udp://") {
        (PeerTransport::Udp, rest)
    } else if let Some(rest) = uri.strip_prefix("quic://") {
        (PeerTransport::Quic, rest)
    } else if let Some(rest) = uri.strip_prefix("wg://") {
        (PeerTransport::Wg, rest)
    } else if let Some(rest) = uri.strip_prefix("ws://") {
        (PeerTransport::Ws, rest)
    } else if let Some(rest) = uri.strip_prefix("wss://") {
        (PeerTransport::Wss, rest)
    } else {
        let scheme = uri.split("://").next().unwrap_or(uri);
        return Err(Error::config(format!(
            "easytier: unsupported peer transport scheme {scheme:?} in {uri:?} (the faketcp/hole-punch transports are not ported)"
        )));
    };
    let default_port = transport_default_port(transport);
    let rest = rest.split('/').next().unwrap_or(rest);
    let (host, port) = if let Some(rest) = rest.strip_prefix('[') {
        // IPv6 literal: `[::1]:port`.
        let (host, tail) = rest
            .split_once(']')
            .ok_or_else(|| Error::config(format!("easytier: invalid IPv6 peer URI {uri:?}")))?;
        let port = tail
            .strip_prefix(':')
            .map(|p| {
                p.parse::<u16>().map_err(|_| {
                    Error::config(format!("easytier: invalid port in peer URI {uri:?}"))
                })
            })
            .transpose()?
            .unwrap_or(default_port);
        (host.to_string(), port)
    } else {
        match rest.rsplit_once(':') {
            Some((host, port)) => {
                let port = port.parse::<u16>().map_err(|_| {
                    Error::config(format!("easytier: invalid port in peer URI {uri:?}"))
                })?;
                (host.to_string(), port)
            }
            None => (rest.to_string(), default_port),
        }
    };
    if host.is_empty() {
        return Err(Error::config(format!("easytier: peer URI has no host: {uri:?}")));
    }
    Ok(PeerEndpoint {
        transport,
        host,
        port,
    })
}

/// Resolve a peer endpoint's host to the first socket address
/// (`SocketAddr::from_url`, tunnel/common.rs — both families accepted).
async fn resolve_peer_addr(endpoint: &PeerEndpoint) -> Result<SocketAddr> {
    let target = (endpoint.host.as_str(), endpoint.port);
    let addr = tokio::net::lookup_host(target)
        .await
        .map_err(|e| Error::network(format!("easytier: resolve peer {}: {e}", endpoint.host)))?
        .next()
        .ok_or_else(|| Error::network(format!("easytier: peer host resolved to nothing: {}", endpoint.host)))?;
    Ok(addr)
}

/// Dial one `tcp://`/`udp://`/`quic://`/`wg://`/`ws://` peer and run the
/// plain-mode client handshake — the `PeerManager::add_tunnel_as_client`
/// path (peers/peer_manager.rs:1990-2021): TCP over `TcpStream::connect`,
/// UDP over the datagram virtual circuit (`UdpTunnelConnector`, the
/// connector's `IpScheme::Udp` arm, connector/mod.rs:248), QUIC over the
/// plaintext quinn tunnel (`IpScheme::Quic`, connector/mod.rs:250-253),
/// WG over the shared-keypair WireGuard tunnel (`IpScheme::Wg`,
/// connector/mod.rs:254-262), WS/WSS over the websocket tunnel
/// (`IpScheme::Ws | Wss`, connector/mod.rs:264-267), all with the direct
/// connector's 3s budget (connectivity/direct/mod.rs:64). DELTA:
/// after the channel is up, one explicit ping confirms liveness —
/// upstream's `ensureStarted` equivalent — which also fails the dial
/// fast when the peer rejects our identity right after its handshake
/// reply.
pub async fn connect_peer(
    endpoint: &PeerEndpoint,
    network_name: &str,
    network_secret: &str,
    encryptor: PacketEncryptor,
) -> Result<EasyTierNode> {
    connect_peer_as(
        endpoint,
        random_peer_id(),
        network_name,
        network_secret,
        encryptor,
        None,
    )
    .await
}

/// [`connect_peer`] under a caller-chosen `my_peer_id` — every
/// connection of ONE overlay node shares the node's peer id (upstream:
/// one `PeerId` per node, all its `PeerConn`s carry it), so the
/// multi-peer node and the listener pass theirs here. `secure` switches
/// the handshake to the Noise_XX flow.
pub async fn connect_peer_as(
    endpoint: &PeerEndpoint,
    my_peer_id: PeerId,
    network_name: &str,
    network_secret: &str,
    encryptor: PacketEncryptor,
    secure: Option<&SecureModeCtx>,
) -> Result<EasyTierNode> {
    let halves =
        dial_session(endpoint, my_peer_id, network_name, network_secret, encryptor, secure)
            .await?;
    Ok(halves.into_node(network_name.to_owned()))
}

/// The [`connect_peer_as`] path returning the raw session halves — what
/// the multi-peer overlay node attaches. `secure` switches the client
/// handshake to the Noise_XX flow (`add_tunnel_as_client` on a
/// secure-mode node).
async fn dial_session(
    endpoint: &PeerEndpoint,
    my_peer_id: PeerId,
    network_name: &str,
    network_secret: &str,
    encryptor: PacketEncryptor,
    secure: Option<&SecureModeCtx>,
) -> Result<SessionHalves> {
    let digest = network_secret_digest(network_name, network_secret);
    match endpoint.transport {
        PeerTransport::Tcp => {
            let stream = tokio::time::timeout(
                DIRECT_CONNECT_TIMEOUT,
                tokio::net::TcpStream::connect((endpoint.host.as_str(), endpoint.port)),
            )
            .await
            .map_err(|_| Error::network("easytier: direct connect timeout"))??;
            client_session(stream, my_peer_id, network_name, &digest, encryptor, secure).await
        }
        PeerTransport::Udp => {
            let addr = resolve_peer_addr(endpoint).await?;
            let stream = tokio::time::timeout(DIRECT_CONNECT_TIMEOUT, connect_udp_tunnel(addr))
                .await
                .map_err(|_| Error::network("easytier: udp connect timeout"))??;
            client_session(stream, my_peer_id, network_name, &digest, encryptor, secure).await
        }
        PeerTransport::Quic => {
            let addr = resolve_peer_addr(endpoint).await?;
            let stream = tokio::time::timeout(DIRECT_CONNECT_TIMEOUT, connect_quic_tunnel(addr))
                .await
                .map_err(|_| Error::network("easytier: quic connect timeout"))??;
            client_session(stream, my_peer_id, network_name, &digest, encryptor, secure).await
        }
        PeerTransport::Wg => {
            let addr = resolve_peer_addr(endpoint).await?;
            let stream = tokio::time::timeout(
                DIRECT_CONNECT_TIMEOUT,
                connect_wg_tunnel(addr, network_name, network_secret),
            )
            .await
            .map_err(|_| Error::network("easytier: wg connect timeout"))??;
            client_session(stream, my_peer_id, network_name, &digest, encryptor, secure).await
        }
        PeerTransport::Ws | PeerTransport::Wss => {
            let stream = tokio::time::timeout(DIRECT_CONNECT_TIMEOUT, connect_ws_tunnel(endpoint))
                .await
                .map_err(|_| Error::network("easytier: ws connect timeout"))??;
            client_session(stream, my_peer_id, network_name, &digest, encryptor, secure).await
        }
    }
}

/// Handshake + identity check + machinery for one dialed stream.
async fn client_session<I>(
    io: I,
    my_peer_id: PeerId,
    network_name: &str,
    digest: &NetworkSecretDigest,
    encryptor: PacketEncryptor,
    secure: Option<&SecureModeCtx>,
) -> Result<SessionHalves>
where
    I: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let mut stream = io;
    let (peer, session) = match secure {
        Some(ctx) => {
            let outcome = noise_handshake_as_client(&mut stream, my_peer_id, ctx).await?;
            tracing::debug!(
                target: "engine",
                "easytier: secure-mode peer {} authenticated at {:?}",
                outcome.peer.peer_id,
                outcome.auth_level
            );
            (outcome.peer, Some(outcome.session))
        }
        None => (handshake_as_client(&mut stream, my_peer_id, network_name, digest).await?, None),
    };
    check_network_identity(network_name, digest, &peer)?;
    let halves = spawn_connection_halves(stream, my_peer_id, &peer, encryptor, session).await;
    // The liveness ping (`do_pingpong_once` via the client connect path).
    conn_ping(&halves.state).await?;
    Ok(halves)
}

/// The server side of one accepted stream: run the plain-mode handshake
/// and the same post-handshake machinery. This is the peer side the
/// listener productionizes below (`PeerManager::add_tunnel_as_server`,
/// peers/peer_manager.rs:2042+).
pub async fn serve_peer(
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    network_name: &str,
    network_secret: &str,
    encryptor: PacketEncryptor,
) -> Result<(EasyTierNode, PeerInfo)> {
    let my_peer_id = random_peer_id();
    let (halves, peer) = serve_peer_as(
        stream,
        my_peer_id,
        network_name,
        network_secret,
        encryptor,
        None,
    )
    .await?;
    Ok((halves.into_node(network_name.to_owned()), peer))
}

/// [`serve_peer`] under a caller-chosen `my_peer_id` (the shared node
/// identity of the listener), returning the raw halves. `secure` enables
/// the Noise_XX server handshake for secure-mode clients (plain clients
/// are still accepted, peer_conn.rs:1252-1275).
pub async fn serve_peer_as(
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    my_peer_id: PeerId,
    network_name: &str,
    network_secret: &str,
    encryptor: PacketEncryptor,
    secure: Option<&SecureModeCtx>,
) -> Result<(SessionHalves, PeerInfo)> {
    let digest = network_secret_digest(network_name, network_secret);
    let mut stream = stream;
    let (peer, session) =
        handshake_as_server(&mut stream, my_peer_id, network_name, &digest, secure).await?;
    check_network_identity(network_name, &digest, &peer)?;
    let halves =
        spawn_connection_halves(stream, my_peer_id, &peer, encryptor, session).await;
    Ok((halves, peer))
}

/// `random_peer_id` (peers/peer_manager.rs:192-198): any non-zero u32.
fn random_peer_id() -> PeerId {
    loop {
        let peer_id = rand::random();
        if peer_id != 0 {
            return peer_id;
        }
    }
}

/// Secure mode — LANDED (M6, v2.6.4 sources). The Noise_XX
/// `PeerConnNoiseMsg1/2/3` handshake (snow
/// `Noise_XX_25519_ChaChaPoly_SHA256`, prologue
/// `easytier-peerconn-noise`, hand-rolled in [`NoiseXxHandshake`]) plus
/// the per-peer session AEAD that replaces the network-secret encryption
/// afterwards ([`SecureDatagramSession`] + [`PeerSessionStore`]). What
/// the two-node subset keeps and skips:
///
/// * **Kept** — the full three-message handshake with the conn-id echo
///   checks, the `role_hint` same/foreign-network rule, the
///   network-secret HMAC proofs over the handshake hash
///   (`NetworkSecretConfirmed`), the `peer-public-key` pin
///   (`PeerVerified`), the Join/Sync/Create generation state machine
///   with static-key pinning, the epoch-keyed traffic-key HKDF, the
///   256-bit per-direction replay windows (two live epochs + the
///   far-future bound), epoch rotation (1M packets / 10 min), root-key
///   sync with the 5s rx grace window, and the decrypt-failure
///   invalidation that closes the connection.
/// * **Skipped** — the trusted-key store behind `is_pubkey_trusted`
///   (the credential-file + OSPF key propagation: a pinned config key is
///   the trust anchor), the foreign-network identity machinery
///   (`classify_remote_identity`'s Admin/Credential/SharedNode roles —
///   the auth level is logged instead), the relay noise messages
///   (`RelayNoiseMsg1/2Pb` — the relay path is not ported) and the
///   `HMAC_SECRET_DIGEST` global-var branch (msg3 carries the
///   plain-mode digest, the default).
pub const SECURE_MODE_PORTED_NOTE: &str = concat!(
    "easytier: secure mode is ported: the Noise_XX handshake ",
    "(Noise_XX_25519_ChaChaPoly_SHA256, prologue easytier-peerconn-noise) ",
    "plus the per-peer session AEAD (epoch-keyed HKDF traffic keys, ",
    "per-direction 256-bit replay windows, root-key sync with rx grace, ",
    "Join/Sync/Create generations). Not ported within it: the trusted-key ",
    "store (credential file + OSPF key propagation — a pinned config key ",
    "is the trust anchor) and the foreign-network identity roles"
);

/// What is still missing after secure mode landed (M6): the mesh roles
/// beyond the direct neighborhood. The message names the next milestones
/// precisely.
pub const NOT_PORTED: &str = concat!(
    "easytier: the direct TCP peer tunnel (M1: handshake + framing + ",
    "AEAD packet encryption + ping/pong), the route layer (M2: the ",
    "peer RPC framework subset + OspfRouteRpc.SyncRouteInfo gossip + the ",
    "smoltcp userspace stack + connect_tcp/EasyTierUdp dials), the ",
    "M3 listener + UDP transport (serve(cfg) accepting tcp:// and udp:// ",
    "peers into the same node, the udp:// peer dial over the SYN/SACK ",
    "datagram circuit), the M4 QUIC + WebSocket transports (the ",
    "quic:// peer dial and listener over the in-tree port of ",
    "quinn-plaintext — SeaHash-tagged plaintext QUIC, one bi-stream per ",
    "peer — and the ws:// wss:// peer dial and listener, one binary ",
    "message per peer frame), and the M5 WireGuard transport (the wg:// ",
    "peer dial and listener: the shared digest-derived static keypair ",
    "with my_public == peer_public, boringtun-Tunn-equivalent ",
    "encapsulate/decapsulate/update_timers over the engine's own ",
    "Noise_IKpsk2 machinery, [20-byte synthetic IPv4 header][PMH]",
    "[payload] framing, the connector's handshake-initiation-first ",
    "connect and the listener's per-address peer table; DELTAs: no ",
    "cookie replies under load, one in-flight handshake vs boringtun's ",
    "two), and the M6 secure mode (the Noise_XX handshake with proofs ",
    "and pinned keys + the per-peer session AEAD + the Join/Sync/Create ",
    "session store; see SECURE_MODE_PORTED_NOTE for the subset) are ",
    "in-tree; NOT ported: the trusted-key store (credential file + ",
    "OSPF-propagated keys) and the foreign-network identity roles of ",
    "secure mode, the relay path + foreign networks ",
    "(RouteForeignNetworkInfos), multi-hop OSPF convergence (graph_algo.rs ",
    "SPF beyond the direct-neighbor adjacency), IPv6 overlay addressing ",
    "(RoutePeerInfo.ipv6_addr field 15, peer_rpc.proto, through the same ",
    "SyncRouteInfo gossip + the v6 dhcp allocator + a dual-stack EtStack ",
    "with v6 source selection — NOT ported because the adapter surface ",
    "driving this module is IPv4-only end to end: mihomo's EasyTierOption ",
    "carries no ipv6 field and ListRoute/ParseNodeIPv4 resolve v4 only; ",
    "the wg/udp/tcp transports themselves are dual-stack already), ",
    "exit-node/proxy-network policy (proxy_networks are ",
    "announced but not routed), MagicDNS serving (the resolver helpers ",
    "are ported; the dns server is not), and the hole-punch/punch-client ",
    "connector paths (the udp listener's STUN and loopback forwards, ",
    "tunnel/udp.rs:182-241)"
);

/// Bring the mesh up against the first `tcp://`/`udp://` peer and
/// return the joined peer connection — the counterpart of upstream
/// `NewEasyTier` + `ensureStarted` + the direct connector's first task
/// (adapter cached lines 172-209; connectivity/direct/mod.rs). The
/// config is validated exactly like the rendered TOML demands, and the
/// packet encryption follows the core defaults (`enable_encryption:
/// true`, `aes-gcm`, config/toml.rs:34,64).
/// Build the secure-mode context of a config (`process_secure_mode_cfg`:
/// a missing `local_private_key` becomes a fresh random identity) — the
/// dial-side pin comes from the first supported peer URI's
/// `peer-public-key` query (`get_pinned_remote_static_pubkey_b64`).
fn secure_mode_ctx(
    config: &EasyTierConfig,
    structured: &EasyTierTomlConfig,
) -> Result<Option<SecureModeCtx>> {
    if !structured.secure_mode_enabled() {
        return Ok(None);
    }
    let algorithm = config
        .encryption_algorithm
        .clone()
        .unwrap_or_else(|| EncryptionAlgorithm::default().as_str().to_owned());
    let peers = structured.parsed_peers()?;
    let pinned = peers
        .iter()
        .find(|p| parse_peer_endpoint(p.uri.trim()).is_ok())
        .map(|p| p.peer_public_key.as_str());
    Ok(Some(SecureModeCtx::new(
        &config.network_name,
        &config.network_secret,
        &structured.local_private_key,
        &algorithm,
        pinned,
    )?))
}

/// Bring the mesh up against the first `tcp://`/`udp://` peer and
/// return the joined peer connection — the counterpart of upstream
/// `NewEasyTier` + `ensureStarted` + the direct connector's first task
/// (adapter cached lines 172-209; connectivity/direct/mod.rs). The
/// config is validated exactly like the rendered TOML demands, and the
/// packet encryption follows the core defaults (`enable_encryption:
/// true`, `aes-gcm`, config/toml.rs:34,64); a `secure-mode` config runs
/// the Noise_XX handshake and the session AEAD instead.
pub async fn connect(config: &EasyTierConfig) -> Result<EasyTierNode> {
    let structured = config.structured_config();
    structured.validate()?;
    let secure = secure_mode_ctx(config, &structured)?;
    let peers = structured.parsed_peers()?;
    let peer = peers
        .iter()
        .find(|p| parse_peer_endpoint(p.uri.trim()).is_ok())
        .ok_or_else(|| {
            Error::config(
                "easytier: no tcp://, udp://, quic://, wg://, ws:// or wss:// peer to dial for the direct tunnel",
            )
        })?;
    let algorithm = config
        .encryption_algorithm
        .clone()
        .unwrap_or_else(|| EncryptionAlgorithm::default().as_str().to_owned());
    let encryptor = create_encryptor(
        &algorithm,
        config.enable_encryption.unwrap_or(true),
        &config.network_secret,
    )?;
    let endpoint = parse_peer_endpoint(&peer.uri)?;
    connect_peer_as(
        &endpoint,
        random_peer_id(),
        &config.network_name,
        &config.network_secret,
        encryptor,
        secure.as_ref(),
    )
    .await
}

// ---------------------------------------------------------------------------
// The gossip state machine (the two-node slice of PeerRouteServiceImpl +
// SyncRouteSession + SyncedRouteInfo, peer_ospf_route.rs)
// ---------------------------------------------------------------------------

/// `SyncRouteInfoError` (peer_rpc.proto:123-126).
pub mod sync_route_error {
    pub const DUPLICATE_PEER_ID: u32 = 0;
    pub const STOPPED: u32 = 1;
}

/// How often a live session re-initiates (`last_sync.elapsed() > 10`,
/// peer_ospf_route.rs:3763-3769; also comfortably inside the 45s
/// `INITIATOR_SESSION_LIVENESS_TIMEOUT`, 1985).
const ROUTE_SYNC_PERIOD: Duration = Duration::from_secs(10);
/// The route-sync RPC budget (`ctrl.set_timeout_ms(3000)`,
/// peer_ospf_route.rs:3529-3531).
const ROUTE_SYNC_TIMEOUT: Duration = Duration::from_secs(3);
/// The easytier default MTU (`config/toml.rs:36 mtu: 1380`).
pub const DEFAULT_MTU: usize = 1380;
/// The retry backoff between failed route syncs (upstream's session task
/// retries with 50ms..5s backoff, peer_ospf_route.rs:3744-3746).
const SYNC_RETRY_BACKOFF: Duration = Duration::from_millis(500);

/// One side of the two-node OSPF session. Owns our announced
/// `RoutePeerInfo` (the self side of `SyncedRouteInfo`), the learned
/// LSDB subset, and the session bookkeeping `SyncRouteSession` carries
/// (`my_session_id` / `dst_session_id` / initiator roles,
/// peer_ospf_route.rs:2000-2340).
#[allow(clippy::too_many_arguments)]
pub struct RouteGossip {
    network_name: String,
    my_peer_id: PeerId,
    peer_id: PeerId,
    /// Random non-zero per connection (`SessionId`).
    my_session_id: u64,
    /// The peer's session id once learned; 0 = unknown.
    dst_session_id: u64,
    dst_is_initiator: bool,
    /// The connector of a two-node edge is the initiator (the election
    /// at peer_ospf_route.rs:3900-3966 picks one side; ours is us).
    we_are_initiator: bool,
    inst_id: OverlayUuid,
    /// `peer_route_id`: random per incarnation, the duplicate-peer-id
    /// detector's nonce (peer_ospf_route.rs:1330-1360).
    my_route_id: u64,
    hostname: String,
    /// Our overlay IPv4: static from the config, or DHCP-allocated once
    /// the peer's subnet is known (`context.ipv4()`).
    my_ipv4: Option<Ipv4Addr>,
    my_network_length: u32,
    want_dhcp: bool,
    dhcp_allocated: bool,
    proxy_cidrs: Vec<String>,
    /// Bumped on every change of our announced info (`version`,
    /// peer_ospf_route.rs:1516-1536).
    my_version: u32,
    /// The learned LSDB (`SyncedRouteInfo::peer_infos`).
    lsdb: HashMap<PeerId, RoutePeerInfo>,
    /// `update_peer_infos`' strictly-greater-version acceptance
    /// (peer_ospf_route.rs:1399-1404).
    conn_map: HashMap<PeerId, Vec<PeerId>>,
    last_sync_ok: Option<std::time::Instant>,
    successful_syncs: u32,
    /// Our announced info changed and must (re-)reach the peer even
    /// between periodic syncs (the dhcp allocation bumps it).
    need_announce: bool,
    /// When the last request left (the retry backoff base — a main-line
    /// peer rejects an initiator request until it learned our session
    /// from our responses, so retries must not spin).
    last_sync_start: Option<std::time::Instant>,
}

impl RouteGossip {
    #[allow(clippy::too_many_arguments)]
    fn new(
        network_name: &str,
        my_peer_id: PeerId,
        peer_id: PeerId,
        hostname: &str,
        ipv4: Option<Ipv4Addr>,
        network_length: u32,
        want_dhcp: bool,
        proxy_cidrs: Vec<String>,
        initiator: bool,
    ) -> Self {
        RouteGossip {
            network_name: network_name.to_owned(),
            my_peer_id,
            peer_id,
            my_session_id: rand::random::<u64>().max(1),
            dst_session_id: 0,
            dst_is_initiator: false,
            we_are_initiator: initiator,
            inst_id: OverlayUuid::random(),
            my_route_id: rand::random::<u64>().max(1),
            hostname: hostname.to_owned(),
            my_ipv4: ipv4,
            my_network_length: network_length,
            want_dhcp,
            dhcp_allocated: false,
            proxy_cidrs,
            my_version: 1,
            lsdb: HashMap::new(),
            conn_map: HashMap::new(),
            last_sync_ok: None,
            successful_syncs: 0,
            need_announce: true,
            last_sync_start: None,
        }
    }

    /// `new_updated_self_route_peer_info` (peer_ospf_route.rs:774-816) for
    /// the fields a two-node announcement carries.
    pub fn my_peer_info(&self) -> RoutePeerInfo {
        RoutePeerInfo {
            peer_id: self.my_peer_id,
            inst_id: Some(self.inst_id),
            cost: 0,
            ipv4_addr: self.my_ipv4.map(u32::from),
            proxy_cidrs: self.proxy_cidrs.clone(),
            hostname: Some(self.hostname.clone()).filter(|h| !h.is_empty()),
            last_update_secs: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            version: self.my_version,
            easytier_version: String::new(),
            peer_route_id: self.my_route_id,
            network_length: if self.my_ipv4.is_some() {
                if self.my_network_length == 0 {
                    32
                } else {
                    self.my_network_length
                }
            } else {
                24
            },
            is_public_server: false,
            support_conn_list_sync: false,
        }
    }

    /// `build_sync_request` (peer_ospf_route.rs:3357-3373) reduced to the
    /// two-node shape: our info plus the adjacency bitmap.
    pub fn build_request(&self) -> SyncRouteInfoRequest {
        SyncRouteInfoRequest {
            my_peer_id: self.my_peer_id,
            my_session_id: self.my_session_id,
            is_initiator: self.we_are_initiator,
            peer_infos: vec![self.my_peer_info()],
            conn_bitmap: Some(RouteConnBitmap::two_node(self.my_peer_id, self.peer_id)),
        }
    }

    /// Whether the periodic tick should fire a new sync
    /// (`sync_as_initiator` when 10s passed, peer_ospf_route.rs:3763-3769;
    /// an unsynced session syncs immediately; a changed announcement
    /// syncs as soon as the line is free and the 500ms retry backoff
    /// elapsed).
    pub fn sync_due(&self) -> bool {
        let backoff_elapsed = self
            .last_sync_start
            .is_none_or(|t| std::time::Instant::now().duration_since(t) >= SYNC_RETRY_BACKOFF);
        if self.need_announce && backoff_elapsed {
            return true;
        }
        match self.last_sync_ok {
            None => backoff_elapsed,
            Some(last) => std::time::Instant::now().duration_since(last) >= ROUTE_SYNC_PERIOD,
        }
    }

    /// The client's response handling (`update_remote_state_locked` +
    /// the success branch, peer_ospf_route.rs:3605-3637): record the
    /// peer's session id and initiator role; a `Stopped` error from a
    /// stale generation is retried by the next tick.
    pub fn apply_response(&mut self, resp: &SyncRouteInfoResponse) {
        if let Some(err) = resp.error {
            tracing::debug!(target: "engine", "easytier: sync_route_info error code {err}");
            return;
        }
        self.dst_session_id = resp.session_id;
        self.dst_is_initiator = resp.is_initiator;
        self.last_sync_ok = Some(std::time::Instant::now());
        self.successful_syncs += 1;
        self.need_announce = false;
        if !resp.missing_peer_ids.is_empty() {
            // `collect_missing_peer_ids`: the peer wants infos we did not
            // send. In a two-node mesh this is unexpected; the next
            // periodic sync re-sends everything we know.
            tracing::debug!(target: "engine", "easytier: route sync missing peer ids: {:?}", resp.missing_peer_ids);
        }
    }

    /// The responder's session acceptance. DELTA: upstream main adds a
    /// stale-generation admission filter (`admit_inbound_locked`,
    /// peer_ospf_route.rs:2233-2254) that rejects an initiator request
    /// unless the previous initiator relinquished; the v2.6.x line every
    /// released binary speaks accepts every request unconditionally
    /// (`do_sync_route_info`: `get_or_start_session` + `update_dst_
    /// session_id` + `dst_is_initiator.store`, peer_ospf_route.rs:
    /// 3484-3514 of the v2.6.4 tag). Two nodes that both elect
    /// themselves initiator (the fresh-mesh case: both sides' elections
    /// pick each other) deadlock under the strict rules — each rejects
    /// the other's first request — so this port takes the permissive
    /// released-binary behaviour: always admit, record the peer's
    /// session id and initiator role. A main-line peer still converges:
    /// it learns our session + initiator flag from our responses, and
    /// our next request then matches its recorded session.
    pub fn admit_inbound(&mut self, session_id: u64, is_initiator: bool) -> bool {
        self.dst_session_id = session_id;
        self.dst_is_initiator = is_initiator;
        true
    }

    /// `update_peer_infos` (peer_ospf_route.rs:1364-1400): merge the
    /// announced infos into the LSDB, keeping the strictly-greater
    /// version (`route_info.version > old.version`), and fold the conn
    /// bitmap into the adjacency map (`update_conn_info_with_bitmap`,
    /// 1407-1437). Returns the infos actually stored.
    pub fn merge_sync_request(&mut self, infos: &[RoutePeerInfo], bitmap: Option<&RouteConnBitmap>) {
        for info in infos {
            if info.peer_id == 0 {
                continue;
            }
            let newer = self
                .lsdb
                .get(&info.peer_id)
                .is_none_or(|old| info.version > old.version);
            if newer {
                self.lsdb.insert(info.peer_id, info.clone());
            }
        }
        if let Some(bitmap) = bitmap {
            for entry in &bitmap.peer_ids {
                if let Some(connected) = bitmap.connected_peers(entry.peer_id) {
                    self.conn_map.insert(entry.peer_id, connected);
                }
            }
        }
    }

    /// The server half of `do_sync_route_info` (peer_ospf_route.rs:
    /// 3473-3645 on the v2.6.4 tag) for a direct admin peer: admit,
    /// merge, answer.
    pub fn handle_sync_request(&mut self, req: &SyncRouteInfoRequest) -> SyncRouteInfoResponse {
        self.admit_inbound(req.my_session_id, req.is_initiator);
        self.merge_sync_request(&req.peer_infos, req.conn_bitmap.as_ref());
        SyncRouteInfoResponse {
            is_initiator: self.we_are_initiator,
            session_id: self.my_session_id,
            error: None,
            missing_peer_ids: Vec::new(),
        }
    }

    /// The mesh network name we validated against.
    pub fn network_name(&self) -> &str {
        &self.network_name
    }

    /// The learned route for a peer id.
    pub fn peer_route(&self, peer_id: PeerId) -> Option<&RoutePeerInfo> {
        self.lsdb.get(&peer_id)
    }

    /// All overlay addresses in the LSDB (our own included) — the dhcp
    /// allocator's `used_ipv4` (`DhcpIpv4RouteSnapshot`,
    /// gateway/dhcp.rs:83-108).
    pub fn used_ipv4(&self) -> Vec<Ipv4Addr> {
        let mut used: Vec<Ipv4Addr> = self.lsdb.values().filter_map(|i| i.ipv4()).collect();
        if let Some(mine) = self.my_ipv4 {
            used.push(mine);
        }
        used
    }

    /// The overlay address we announce.
    pub fn my_ipv4(&self) -> Option<Ipv4Addr> {
        self.my_ipv4
    }

    /// Stamp a request's departure (the retry-backoff clock).
    fn mark_sync_started(&mut self) {
        self.last_sync_start = Some(std::time::Instant::now());
    }

    /// `DhcpIpv4Allocator::evaluate` (gateway/dhcp.rs:51-78) over the
    /// learned routes: pick the first free host of the peer's subnet.
    /// Returns true when our announced info changed (version bump).
    pub fn allocate_dhcp_ipv4(&mut self) -> bool {
        if !self.want_dhcp || self.dhcp_allocated || self.my_ipv4.is_some() {
            return false;
        }
        // `has_routes`: at least one learned address to allocate against.
        let Some(peer_addr) = self
            .lsdb
            .values()
            .filter_map(|i| i.ipv4().map(|a| (a, i.network_length)))
            .min_by_key(|(addr, _)| u32::from(*addr))
        else {
            return false;
        };
        let (subnet, length) = peer_addr;
        let prefix = if length == 0 { 24 } else { length.min(32) };
        let Some(picked) = allocate_overlay_ipv4(&self.used_ipv4(), subnet, prefix as u8) else {
            return false;
        };
        self.my_ipv4 = Some(picked);
        self.my_network_length = prefix;
        self.dhcp_allocated = true;
        self.my_version += 1;
        self.need_announce = true;
        tracing::debug!(target: "engine", "easytier: dhcp allocated overlay address {picked}");
        true
    }

    /// Adopt an address the owning overlay node allocated (or carried
    /// statically) — the multi-peer node allocates once and announces the
    /// same address over every edge. Idempotent; bumps the announcement
    /// version only on change.
    pub fn set_announced_ipv4(&mut self, addr: Ipv4Addr, network_length: u32) {
        if self.my_ipv4 == Some(addr) {
            return;
        }
        self.my_ipv4 = Some(addr);
        self.my_network_length = network_length;
        self.dhcp_allocated = true;
        self.my_version += 1;
        self.need_announce = true;
    }

    /// Whether the route exchange has done its job for dialing: our
    /// address is known and at least one sync succeeded.
    pub fn is_ready(&self) -> bool {
        self.my_ipv4.is_some() && self.successful_syncs > 0
    }

    /// The MagicDNS node table of the learned routes (`ShowNodeInfo` /
    /// `ListRoute` behind the overlay resolver).
    pub fn overlay_nodes(&self) -> Vec<crate::proto::easytier::OverlayNode> {
        let mut nodes = Vec::new();
        for info in self.lsdb.values() {
            if let (Some(ipv4), true) = (info.ipv4(), info.peer_id != self.my_peer_id) {
                nodes.push(OverlayNode {
                    hostname: info.hostname.clone().unwrap_or_default(),
                    ipv4,
                });
            }
        }
        if let Some(ipv4) = self.my_ipv4 {
            nodes.push(OverlayNode {
                hostname: self.hostname.clone(),
                ipv4,
            });
        }
        nodes
    }
}

// ---------------------------------------------------------------------------
// The smoltcp userspace stack (the engine's openvpn.rs/wireguard.rs L3
// pattern, fed by the EasyTier IP-frame seam)
// ---------------------------------------------------------------------------

// netstack buffer sizes (wireguard.rs/openvpn.rs parity).
const TCP_RX_BYTES: usize = 64 * 1024;
const TCP_TX_BYTES: usize = 64 * 1024;
const UDP_RX_BYTES: usize = 32 * 1024;
const UDP_TX_BYTES: usize = 32 * 1024;
const UDP_PACKETS: usize = 64;
const PRE_SESSION_QUEUE_MAX: usize = 512;
const MAX_CONNS: usize = 128;
const MAX_UDP_SOCKETS: usize = 64;
const TCP_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MIN_TICK: Duration = Duration::from_millis(1);
const MAX_TICK: Duration = Duration::from_secs(1);
const PUMP_CHUNK: usize = 32 * 1024;
const STREAM_QUEUE_MAX: usize = 256 * 1024;
/// How long the first dial waits for the route exchange + optional dhcp
/// allocation before failing the node (mirrors the connector-side
/// liveness budget of M1's explicit ping).
const ROUTE_READY_TIMEOUT: Duration = Duration::from_secs(10);

struct Shim {
    ingress: VecDeque<Vec<u8>>,
    egress: VecDeque<Vec<u8>>,
    scratch: Vec<u8>,
    mtu: usize,
}

impl Shim {
    fn new(mtu: usize) -> Self {
        Shim {
            ingress: VecDeque::new(),
            egress: VecDeque::new(),
            scratch: Vec::new(),
            mtu,
        }
    }

    fn stage(&mut self, pkt: &[u8]) {
        if self.ingress.len() < PRE_SESSION_QUEUE_MAX {
            self.ingress.push_back(pkt.to_vec());
        }
    }
}

impl Device for Shim {
    type RxToken<'a> = RxTok;
    type TxToken<'a> = TxTok<'a>;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(RxTok, TxTok<'_>)> {
        let pkt = self.ingress.pop_front()?;
        Some((
            RxTok { pkt },
            TxTok {
                egress: &mut self.egress,
                scratch: &mut self.scratch,
            },
        ))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<TxTok<'_>> {
        Some(TxTok {
            egress: &mut self.egress,
            scratch: &mut self.scratch,
        })
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
    bufs: StdMutex<StreamBufs>,
    wake: Arc<Notify>,
}

impl StreamShared {
    fn new(wake: Arc<Notify>) -> Self {
        StreamShared {
            bufs: StdMutex::new(StreamBufs {
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

/// One TCP connection through the EasyTier overlay, as seen by the relay.
pub struct EtStream {
    shared: Arc<StreamShared>,
}

impl Drop for EtStream {
    fn drop(&mut self) {
        let mut g = self.shared.lock();
        g.aborted = true;
        g.read_eof = true;
        g.write_closed = true;
        drop(g);
        self.shared.wake.notify_one();
    }
}

impl AsyncRead for EtStream {
    fn poll_read(
        self: Pin<&mut Self>,
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
            return Poll::Ready(Ok(()));
        }
        g.read_waker = Some(cx.waker().clone());
        Poll::Pending
    }
}

impl AsyncWrite for EtStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut g = self.shared.lock();
        if g.aborted || g.write_closed {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "easytier: stream is closed",
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

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.shared.lock().write_closed = true;
        self.shared.wake.notify_one();
        Poll::Ready(Ok(()))
    }
}

struct Conn {
    handle: SocketHandle,
    shared: Arc<StreamShared>,
    fin_sent: bool,
    pending: Option<(oneshot::Sender<Result<Arc<StreamShared>>>, std::time::Instant)>,
}

type UdpDownlink = mpsc::Receiver<(SocketAddr, Vec<u8>)>;

struct UdpSock {
    handle: SocketHandle,
    port: u16,
    down: mpsc::Sender<(SocketAddr, Vec<u8>)>,
}

enum Cmd {
    /// Park the dial until the route exchange completed (the handshake
    /// gate of the tunnel: first use waits for the session).
    WaitReady {
        reply: oneshot::Sender<()>,
    },
    Connect {
        remote: SocketAddr,
        reply: oneshot::Sender<Result<Arc<StreamShared>>>,
    },
    UdpOpen {
        reply: oneshot::Sender<Result<(u32, UdpDownlink)>>,
    },
    UdpSend {
        id: u32,
        dst: SocketAddr,
        data: Vec<u8>,
    },
    UdpClose {
        id: u32,
    },
    /// Hand one freshly handshaked inbound peer (the listener's accept
    /// loop) to the running node so it joins the peer table
    /// (`ListenerManager`'s `peer_manager.handle_tunnel`,
    /// instance/listeners.rs:239-253).
    AttachPeer {
        session: Box<SessionHalves>,
    },
    /// The MagicDNS node table of the whole node (`ShowNodeInfo` /
    /// `ListRoute` behind the overlay resolver).
    ListNodes {
        reply: oneshot::Sender<Vec<OverlayNode>>,
    },
    /// The node's peer id (accepted peers must announce THEMSELVES as
    /// that same node identity).
    MyPeerId {
        reply: oneshot::Sender<PeerId>,
    },
    /// Deterministic teardown of the node task (`EasyTierServer::
    /// shutdown`).
    Shutdown {
        reply: oneshot::Sender<()>,
    },
}

/// One attached mesh neighbor of the overlay node: the connection's
/// send-side state plus its OWN route-gossip session (each edge carries
/// its own `SyncRouteSession` — my/dst session ids and initiator role
/// are per-connection, peer_ospf_route.rs:2000-2340).
struct PeerSession {
    state: Arc<ConnState>,
    peer_id: PeerId,
    gossip: RouteGossip,
    router: RpcRouter,
    descriptor: RpcDescriptor,
    /// The outstanding route-sync call of this session's single-call
    /// client (the transaction id of the in-flight request, if any).
    outstanding_sync: Option<i64>,
    sync_deadline: Option<std::time::Instant>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    closed: bool,
}

impl PeerSession {
    /// The shared encrypting sender for every payload-bearing packet
    /// type: `Data` (`send_msg_by_ip` → `try_compress_and_encrypt`,
    /// peer_manager.rs:2641-2660) and `RpcReq`/`RpcResp`
    /// (`RpcTransport::send` → `encryptor.encrypt`, peer_manager.rs:
    /// 153-169) both leave the node sealed by the network-secret
    /// encryptor in plain (non-secure) mode, or by the per-peer session
    /// AEAD in secure mode.
    async fn send_packet(&self, packet_type: u8, payload: &[u8]) -> Result<()> {
        let mut hdr = PeerManagerHeader {
            from_peer_id: self.state.my_peer_id,
            to_peer_id: self.peer_id,
            packet_type,
            flags: 0,
            forward_counter: 1,
            reserved: 0,
            len: payload.len() as u32,
        };
        let mut payload = payload.to_vec();
        self.state.seal_outgoing(&mut hdr, &mut payload)?;
        self.state
            .sink
            .send(PeerPacket { hdr, payload })
            .await
            .map_err(|_| Error::network("easytier: peer connection closed"))
    }

    async fn send_ip_frame(&self, frame: &[u8]) -> Result<()> {
        self.send_packet(packet_type::DATA, frame).await
    }

    async fn send_rpc_packet(&self, is_request: bool, payload: &[u8]) -> Result<()> {
        self.send_packet(
            if is_request {
                packet_type::RPC_REQ
            } else {
                packet_type::RPC_RESP
            },
            payload,
        )
        .await
    }

    fn is_closed(&self) -> bool {
        self.closed || self.state.close_flag.load(Ordering::Acquire) == 1
    }
}

/// One event off one attached peer, multiplexed into the node loop (the
/// per-connection packet channels the upstream `PeerManager` fans in).
enum PeerEvent {
    Ctrl(usize, PeerPacket),
    Data(usize, Vec<u8>),
    Closed(usize),
}

/// Pump one session's two receive channels into the node's event
/// channel; `Closed` fires when the connection's recv loop ended.
async fn run_peer_events(
    mut data_rx: mpsc::Receiver<Vec<u8>>,
    mut ctrl_rx: mpsc::Receiver<PeerPacket>,
    idx: usize,
    tx: mpsc::Sender<PeerEvent>,
) {
    loop {
        tokio::select! {
            ctrl = ctrl_rx.recv() => match ctrl {
                Some(p) => {
                    if tx.send(PeerEvent::Ctrl(idx, p)).await.is_err() {
                        break;
                    }
                }
                None => break,
            },
            data = data_rx.recv() => match data {
                Some(f) => {
                    if tx.send(PeerEvent::Data(idx, f)).await.is_err() {
                        break;
                    }
                }
                None => break,
            },
        }
    }
    let _ = tx.send(PeerEvent::Closed(idx)).await;
}

/// One overlay node task: the attached peer sessions (dialed and
/// accepted — every one joins the same node identity and address), the
/// route gossip riding each session's RPC seam, and the smoltcp stack
/// bridging the IP-frame seam to TCP/UDP sessions — the userspace
/// counterpart of the core's `PeerManager` + `gateway`.
struct EtStack {
    /// The ONE peer id this node announces on every edge (upstream: one
    /// `PeerId` per node; all its `PeerConn`s share it).
    my_peer_id: PeerId,
    network_name: String,
    hostname: String,
    /// The overlay address of the node: static from the config, or
    /// allocated once from the learned routes and announced everywhere.
    my_ipv4: Option<Ipv4Addr>,
    my_network_length: u32,
    want_dhcp: bool,
    proxy_cidrs: Vec<String>,
    peers: Vec<PeerSession>,
    iface: Interface,
    sockets: SocketSet<'static>,
    shim: Shim,
    conns: Vec<Conn>,
    udp: HashMap<u32, UdpSock>,
    used_ports: HashSet<u16>,
    next_udp_id: u32,
    wake: Arc<Notify>,
    start: std::time::Instant,
    pump_buf: Vec<u8>,
    /// The overlay address already installed on the interface.
    installed_addr: Option<Ipv4Addr>,
    /// Dials parked until the route exchange completes (the handshake
    /// gate of openvpn's `Cmd::Connect` — first use waits for the
    /// session, with the same 10s budget the dial timeout carries).
    wait_ready: Vec<(Instant, oneshot::Sender<()>)>,
    fail: Option<Error>,
}

impl EtStack {
    #[allow(clippy::too_many_arguments)]
    fn new(
        my_peer_id: PeerId,
        network_name: &str,
        hostname: &str,
        mtu: usize,
        static_addr: Option<Ipv4Addr>,
        static_prefix: u32,
        want_dhcp: bool,
        proxy_cidrs: Vec<String>,
    ) -> Self {
        let wake = Arc::new(Notify::new());
        let mut shim = Shim::new(mtu);
        let mut iface_cfg = IfaceConfig::new(HardwareAddress::Ip);
        iface_cfg.random_seed = rand::random();
        let mut iface = Interface::new(iface_cfg, &mut shim, SmolInstant::ZERO);
        if let Some(addr) = static_addr {
            // The static overlay address is known before the loop starts;
            // the dhcp path installs inside the loop once allocated.
            iface.update_ip_addrs(|addrs| {
                let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(addr), 32));
            });
            let _ = iface.routes_mut().add_default_ipv4_route(addr);
        }
        EtStack {
            my_peer_id,
            network_name: network_name.to_owned(),
            hostname: hostname.to_owned(),
            my_ipv4: static_addr,
            my_network_length: if static_addr.is_some() && static_prefix == 0 {
                32
            } else {
                static_prefix
            },
            want_dhcp,
            proxy_cidrs,
            peers: Vec::new(),
            iface,
            sockets: SocketSet::new(Vec::new()),
            shim,
            conns: Vec::new(),
            udp: HashMap::new(),
            used_ports: HashSet::new(),
            next_udp_id: 1,
            wake,
            start: std::time::Instant::now(),
            pump_buf: vec![0u8; PUMP_CHUNK],
            installed_addr: static_addr,
            wait_ready: Vec::new(),
            fail: None,
        }
    }

    /// Attach one handshaked session (dialed or accepted) and start its
    /// event pump. Returns the session's index. The gossip starts from
    /// the node's current announcement; the initiator flag marks which
    /// side dialed (`we_are_initiator` — the connector of an edge is
    /// the initiator).
    fn attach_session(
        &mut self,
        halves: SessionHalves,
        initiator: bool,
        events: &mpsc::Sender<PeerEvent>,
    ) -> usize {
        let idx = self.peers.len();
        let gossip = RouteGossip::new(
            &self.network_name,
            self.my_peer_id,
            halves.state.peer_id,
            &self.hostname,
            self.my_ipv4,
            self.my_network_length,
            false,
            self.proxy_cidrs.clone(),
            initiator,
        );
        let peer_id = halves.state.peer_id;
        let (data_rx, ctrl_rx) = (halves.data_rx, halves.ctrl_rx);
        tokio::spawn(run_peer_events(data_rx, ctrl_rx, idx, events.clone()));
        self.peers.push(PeerSession {
            state: halves.state,
            peer_id,
            gossip,
            router: RpcRouter::default(),
            descriptor: ospf_route_descriptor(&self.network_name),
            outstanding_sync: None,
            sync_deadline: None,
            tasks: halves.tasks,
            closed: false,
        });
        idx
    }

    /// The mutable session at `idx`, when it exists.
    fn sess(&mut self, idx: usize) -> Option<&mut PeerSession> {
        self.peers.get_mut(idx)
    }

    /// Whether any live session finished a route exchange with our
    /// address known — the dial gate.
    fn ready(&self) -> bool {
        self.peers
            .iter()
            .any(|s| !s.is_closed() && s.gossip.is_ready())
    }

    /// The node's DHCP allocation (`DhcpIpv4Allocator::evaluate`,
    /// gateway/dhcp.rs:51-78) over the UNION of every session's LSDB —
    /// one address for the whole node, then announced on every edge.
    /// Returns true when a fresh address was picked.
    fn maybe_allocate_dhcp(&mut self) -> bool {
        if !self.want_dhcp || self.my_ipv4.is_some() {
            return false;
        }
        let Some((subnet, length)) = self
            .peers
            .iter()
            .flat_map(|s| s.gossip.lsdb.values())
            .filter_map(|i| i.ipv4().map(|a| (a, i.network_length)))
            .min_by_key(|(addr, _)| u32::from(*addr))
        else {
            return false;
        };
        let prefix = if length == 0 { 24 } else { length.min(32) };
        let used: Vec<Ipv4Addr> = self
            .peers
            .iter()
            .flat_map(|s| s.gossip.used_ipv4())
            .collect();
        let Some(picked) = allocate_overlay_ipv4(&used, subnet, prefix as u8) else {
            return false;
        };
        tracing::debug!(target: "engine", "easytier: dhcp allocated overlay address {picked}");
        self.my_ipv4 = Some(picked);
        self.my_network_length = prefix;
        for s in &mut self.peers {
            s.gossip.set_announced_ipv4(picked, prefix);
        }
        true
    }

    /// Complete or expire the dials parked on route readiness.
    fn service_ready(&mut self) {
        let ready = self.ready();
        let now = Instant::now();
        let mut parked = std::mem::take(&mut self.wait_ready);
        self.wait_ready = parked
            .drain(..)
            .filter_map(|(deadline, tx)| {
                if ready {
                    let _ = tx.send(());
                    None
                } else {
                    (now < deadline).then_some((deadline, tx))
                }
            })
            .collect();
        self.maybe_allocate_dhcp();
        if let Some(addr) = self.my_ipv4 {
            self.install_address(addr);
        }
    }

    fn now(&self) -> SmolInstant {
        SmolInstant::from_micros(self.start.elapsed().as_micros() as i64)
    }

    /// Install the overlay address once known (the TUN `update_addr`
    /// path; a /32 plus the default route through it, wireguard.rs
    /// parity — every overlay destination is reached via a peer).
    /// Idempotent: a repeat sync announcing the same address leaves the
    /// interface untouched.
    fn install_address(&mut self, addr: Ipv4Addr) {
        if self.installed_addr == Some(addr) {
            return;
        }
        self.iface.update_ip_addrs(|addrs| {
            addrs.clear();
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(addr), 32));
        });
        let _ = self.iface.routes_mut().add_default_ipv4_route(addr);
        self.installed_addr = Some(addr);
        tracing::debug!(target: "engine", "easytier: overlay address {addr} installed");
    }

    // -- gossip driver ------------------------------------------------------

    /// Fire the route sync RPC of one session
    /// (`sync_route_with_peer`'s send half, peer_ospf_route.rs:3507-3553).
    async fn start_sync(&mut self, idx: usize) {
        let my_peer_id = self.my_peer_id;
        let Some(session) = self.sess(idx) else {
            return;
        };
        if session.is_closed() || session.outstanding_sync.is_some() {
            return;
        }
        let request = session.gossip.build_request().encode();
        let (transaction_id, wire) = session.router.begin_call(
            my_peer_id,
            session.peer_id,
            session.descriptor.clone(),
            &request,
            ROUTE_SYNC_TIMEOUT.as_millis().min(i32::MAX as u128) as i32,
        );
        session.outstanding_sync = Some(transaction_id);
        session.sync_deadline = Some(std::time::Instant::now() + ROUTE_SYNC_TIMEOUT);
        session.gossip.mark_sync_started();
        if let Err(e) = session.send_rpc_packet(true, &wire).await {
            self.fail_route_sync(idx, transaction_id, &e);
        }
    }

    fn fail_route_sync(&mut self, idx: usize, transaction_id: i64, e: &Error) {
        tracing::debug!(target: "engine", "easytier: sync_route_info failed: {e}");
        if let Some(session) = self.sess(idx) {
            session.router.cancel(transaction_id);
            if session.outstanding_sync == Some(transaction_id) {
                session.outstanding_sync = None;
                session.sync_deadline = None;
            }
        }
    }

    /// The client's response pump (client.rs:161-221) for the single
    /// outstanding route-sync call of one session.
    fn on_rpc_response(&mut self, idx: usize, packet: RpcPacket) {
        let Some(transaction_id) = self
            .sess(idx)
            .and_then(|s| s.outstanding_sync)
        else {
            return;
        };
        if packet.transaction_id != transaction_id {
            // Not our call (a late response to a cancelled sync).
            return;
        }
        let session = self.sess(idx).unwrap();
        session.outstanding_sync = None;
        session.sync_deadline = None;
        let body = match RpcResponseBody::decode(&packet.body) {
            Ok(body) => body,
            Err(e) => {
                tracing::debug!(target: "engine", "easytier: decode rpc response: {e}");
                return;
            }
        };
        if let Some(tag) = body.error_tag {
            tracing::debug!(target: "engine", "easytier: rpc error tag {tag}");
            return;
        }
        match SyncRouteInfoResponse::decode(&body.response) {
            Ok(resp) => session.gossip.apply_response(&resp),
            Err(e) => tracing::debug!(target: "engine", "easytier: decode sync response: {e}"),
        }
    }

    /// The server dispatch (`dispatch_request` + the registered
    /// `OspfRouteRpcServer`, service_registry.rs:166-200 collapsed to
    /// the one service).
    async fn on_rpc_request(&mut self, idx: usize, packet: RpcPacket) {
        let request = {
            let Some(session) = self.sess(idx) else {
                return;
            };
            let Some(desc) = packet.descriptor.clone() else {
                tracing::debug!(target: "engine", "easytier: rpc request without a descriptor");
                return;
            };
            if desc != session.descriptor {
                tracing::debug!(target: "engine", "easytier: rpc request for unknown service {}", desc.service_name);
                return;
            }
            if desc.method_index != rpc_method::OSPF_SYNC_ROUTE_INFO {
                // `Error::InvalidMethodIndex` upstream; answered by silence
                // here — the subset speaks one method.
                tracing::debug!(target: "engine", "easytier: rpc method index {} is not SyncRouteInfo", desc.method_index);
                return;
            }
            let body = match RpcRequestBody::decode(&packet.body) {
                Ok(body) => body,
                Err(e) => {
                    tracing::debug!(target: "engine", "easytier: decode rpc request: {e}");
                    return;
                }
            };
            match SyncRouteInfoRequest::decode(&body.request) {
                Ok(req) => req,
                Err(e) => {
                    tracing::debug!(target: "engine", "easytier: decode route request: {e}");
                    return;
                }
            }
        };
        let response = {
            let Some(session) = self.sess(idx) else {
                return;
            };
            session.gossip.handle_sync_request(&request)
        };
        let resp_packet = build_rpc_response(&packet, &response.encode());
        if let Some(session) = self.sess(idx) {
            if let Err(e) = session.send_rpc_packet(false, &resp_packet.encode()).await {
                tracing::debug!(target: "engine", "easytier: send sync response: {e}");
            }
        }
        // Serving a request may have taught us the subnet we still need
        // for the dhcp allocation.
        if self.maybe_allocate_dhcp() {
            self.start_sync(idx).await;
        }
    }

    /// One decrypted control packet off one session's channel.
    async fn on_ctrl(&mut self, idx: usize, packet: PeerPacket) {
        if packet.hdr.packet_type != packet_type::RPC_REQ && packet.hdr.packet_type != packet_type::RPC_RESP
        {
            return;
        }
        let rpc = match RpcPacket::decode(&packet.payload) {
            Ok(rpc) => rpc,
            Err(e) => {
                tracing::debug!(target: "engine", "easytier: decode rpc packet: {e}");
                return;
            }
        };
        if rpc.is_request {
            let merged = {
                let Some(session) = self.sess(idx) else {
                    return;
                };
                match session.router.on_request(rpc) {
                    Ok(whole) => whole,
                    Err(e) => {
                        tracing::debug!(target: "engine", "easytier: merge rpc pieces: {e}");
                        return;
                    }
                }
            };
            if let Some(whole) = merged {
                self.on_rpc_request(idx, whole).await;
            }
        } else {
            // Response pieces merge inside the router's per-call merger;
            // a complete packet is read back by the outstanding call.
            let transaction_id = rpc.transaction_id;
            let merged = {
                let Some(session) = self.sess(idx) else {
                    return;
                };
                session.router.on_response(rpc);
                (session.outstanding_sync == Some(transaction_id))
                    .then(|| session.router.take_merged(transaction_id))
                    .flatten()
            };
            if let Some(merged) = merged {
                self.on_rpc_response(idx, merged);
            }
        }
    }

    /// The gossip tick of every session: fire the periodic sync, time
    /// out a stuck one, and retry the dhcp allocation as routes arrive.
    async fn gossip_tick(&mut self) {
        let mut due: Vec<usize> = Vec::new();
        for idx in 0..self.peers.len() {
            let Some(session) = self.peers.get_mut(idx) else {
                continue;
            };
            if session.is_closed() {
                continue;
            }
            if let Some(deadline) = session.sync_deadline {
                if std::time::Instant::now() >= deadline {
                    if let Some(transaction_id) = session.outstanding_sync.take() {
                        session.router.cancel(transaction_id);
                        tracing::debug!(target: "engine", "easytier: sync_route_info timed out");
                    }
                    session.sync_deadline = None;
                }
            }
            if session.gossip.sync_due() && session.outstanding_sync.is_none() {
                due.push(idx);
            }
        }
        for idx in due {
            self.start_sync(idx).await;
        }
        if self.maybe_allocate_dhcp() {
            let live: Vec<usize> = (0..self.peers.len())
                .filter(|&i| self.peers.get(i).is_some_and(|s| !s.is_closed()))
                .collect();
            for idx in live {
                self.start_sync(idx).await;
            }
        }
    }

    // -- netstack service (openvpn.rs/wireguard.rs parity) ------------------

    async fn step(&mut self) {
        let now = self.now();
        self.iface.poll(now, &mut self.shim, &mut self.sockets);
        self.service_conns();
        self.drain_udp_rx();
        self.service_ready();
        let now = self.now();
        self.iface.poll(now, &mut self.shim, &mut self.sockets);
        self.drain_egress().await;
    }

    fn service_conns(&mut self) {
        let now = std::time::Instant::now();
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
                            "easytier: tcp dial failed (state {s:?})"
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
            while g.to_proxy.len() < STREAM_QUEUE_MAX && sock.can_recv() {
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
            }
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
            let Some((handle, down)) = self.udp.get(&id).map(|u| (u.handle, &u.down)) else {
                continue;
            };
            let sock = self.sockets.get_mut::<udp::Socket>(handle);
            while sock.can_recv() {
                let (n, meta) = match sock.recv_slice(&mut self.pump_buf) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let from = match meta.endpoint.addr {
                    IpAddress::Ipv4(src) => SocketAddr::V4(SocketAddrV4::new(src, meta.endpoint.port)),
                    // The overlay interface is IPv4-only (the adapter
                    // dials tcp4/udp4); a v6 endpoint cannot occur.
                    IpAddress::Ipv6(_) => continue,
                };
                let _ = down.try_send((from, self.pump_buf[..n].to_vec()));
            }
        }
    }

    /// Route one egress frame to the session whose LSDB announces the
    /// destination (longest prefix over the learned `RoutePeerInfo`
    /// addresses and `proxy_cidrs`); the two-node default falls back to
    /// the first live peer (the /32 + default-route interface sends
    /// everything to a peer when nothing matches — `send_msg_by_ip`
    /// looks the route up in the OSPF table, peer_manager.rs:2793-2855).
    fn route_frame(&self, dst: Ipv4Addr) -> Option<usize> {
        let mut best: Option<(u32, usize)> = None;
        for (idx, session) in self.peers.iter().enumerate() {
            if session.is_closed() {
                continue;
            }
            for info in session.gossip.lsdb.values() {
                if info.peer_id == self.my_peer_id {
                    continue;
                }
                if let Some(addr) = info.ipv4() {
                    let len = if info.network_length == 0 {
                        24
                    } else {
                        info.network_length.min(32)
                    };
                    if ipv4_in_subnet(dst, addr, len as u8) && best.is_none_or(|(b, _)| len > b) {
                        best = Some((len, idx));
                    }
                }
                for cidr in &info.proxy_cidrs {
                    if let Some((addr, len)) = parse_cidr(cidr) {
                        let len = len as u32;
                        if ipv4_in_subnet(dst, addr, len as u8) && best.is_none_or(|(b, _)| len > b)
                        {
                            best = Some((len, idx));
                        }
                    }
                }
            }
        }
        best.map(|(_, idx)| idx)
            .or_else(|| self.peers.iter().position(|s| !s.is_closed()))
    }

    async fn drain_egress(&mut self) {
        let pkts: Vec<Vec<u8>> = self.shim.egress.drain(..).collect();
        for pkt in pkts {
            let dst = ipv4_destination(&pkt);
            let Some(idx) = dst.and_then(|dst| self.route_frame(dst)) else {
                // No live peer to forward through: drop (upstream queues
                // into the peer manager's route miss counter).
                continue;
            };
            if let Some(session) = self.peers.get(idx) {
                if let Err(e) = session.send_ip_frame(&pkt).await {
                    tracing::debug!(target: "engine", "easytier: send ip frame: {e}");
                    if let Some(session) = self.peers.get_mut(idx) {
                        session.closed = true;
                    }
                    if !self.peers.iter().any(|s| !s.is_closed()) {
                        self.fail = Some(e);
                        return;
                    }
                }
            }
        }
    }

    fn ephemeral_port(&mut self) -> u16 {
        loop {
            let port = 32768 + rand::random::<u16>() % 28_000;
            if self.used_ports.insert(port) {
                return port;
            }
        }
    }

    /// Source-address selection: the overlay address (IPv4-only, like
    /// the mihomo adapter's `Dial(ctx, "tcp4", …)`).
    fn local_address_for(&self) -> Result<IpAddress> {
        self.my_ipv4
            .map(IpAddress::Ipv4)
            .ok_or_else(|| Error::network("easytier: no overlay IPv4 address yet"))
    }

    async fn on_cmd(&mut self, cmd: Cmd, events: &mpsc::Sender<PeerEvent>) {
        match cmd {
            Cmd::WaitReady { reply } => {
                if self.ready() {
                    let _ = reply.send(());
                } else {
                    self.wait_ready.push((Instant::now() + ROUTE_READY_TIMEOUT, reply));
                }
            }
            Cmd::Connect { remote, reply } => {
                if let Some(e) = &self.fail {
                    let _ = reply.send(Err(Error::network(e.to_string())));
                    return;
                }
                if !self.ready() {
                    let _ = reply.send(Err(Error::network(
                        "easytier: route exchange not complete yet",
                    )));
                    return;
                }
                if self.conns.len() >= MAX_CONNS {
                    let _ = reply.send(Err(Error::network("easytier: connection limit reached")));
                    return;
                }
                let SocketAddr::V4(remote) = remote else {
                    let _ = reply.send(Err(Error::network(
                        "easytier: the overlay is IPv4-only (the adapter dials tcp4/udp4)",
                    )));
                    return;
                };
                let mut sock = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0; TCP_RX_BYTES]),
                    tcp::SocketBuffer::new(vec![0; TCP_TX_BYTES]),
                );
                let port = self.ephemeral_port();
                let Ok(local_addr) = self.local_address_for() else {
                    let _ = reply.send(Err(Error::network(
                        "easytier: no overlay address for the target family",
                    )));
                    return;
                };
                let local = IpListenEndpoint {
                    addr: Some(local_addr),
                    port,
                };
                let endpoint = IpEndpoint::new(IpAddress::Ipv4(*remote.ip()), remote.port());
                let cx = self.iface.context();
                if let Err(e) = sock.connect(cx, endpoint, local) {
                    let _ = reply.send(Err(Error::network(format!(
                        "easytier: connect: {e:?}"
                    ))));
                    return;
                }
                let handle = self.sockets.add(sock);
                let shared = Arc::new(StreamShared::new(self.wake.clone()));
                tracing::debug!(target: "engine", "easytier: dialing {remote} through the overlay");
                self.conns.push(Conn {
                    handle,
                    shared: shared.clone(),
                    fin_sent: false,
                    pending: Some((reply, std::time::Instant::now() + TCP_CONNECT_TIMEOUT)),
                });
            }
            Cmd::UdpOpen { reply } => {
                if let Some(e) = &self.fail {
                    let _ = reply.send(Err(Error::network(e.to_string())));
                    return;
                }
                if !self.ready() {
                    let _ = reply.send(Err(Error::network(
                        "easytier: route exchange not complete yet",
                    )));
                    return;
                }
                if self.udp.len() >= MAX_UDP_SOCKETS {
                    let _ = reply.send(Err(Error::network("easytier: udp socket limit reached")));
                    return;
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
                let port = self.ephemeral_port();
                if let Err(e) = sock.bind(IpListenEndpoint { addr: None, port }) {
                    let _ = reply.send(Err(Error::network(format!("easytier: udp bind: {e:?}"))));
                    return;
                }
                let handle = self.sockets.add(sock);
                let id = self.next_udp_id;
                self.next_udp_id += 1;
                let (tx, rx) = mpsc::channel(64);
                self.udp.insert(id, UdpSock { handle, port, down: tx });
                let _ = reply.send(Ok((id, rx)));
            }
            Cmd::UdpSend { id, dst, data } => {
                let Some(handle) = self.udp.get(&id).map(|u| u.handle) else {
                    return;
                };
                let Ok(local_addr) = self.local_address_for() else {
                    return;
                };
                let SocketAddr::V4(dst) = dst else {
                    return;
                };
                let mut meta = udp::UdpMetadata::from(IpEndpoint::new(
                    IpAddress::Ipv4(*dst.ip()),
                    dst.port(),
                ));
                meta.local_address = Some(local_addr);
                let sock = self.sockets.get_mut::<udp::Socket>(handle);
                if let Err(e) = sock.send_slice(&data, meta) {
                    tracing::debug!(target: "engine", "easytier: udp send to {dst}: {e:?}");
                }
            }
            Cmd::UdpClose { id } => {
                if let Some(u) = self.udp.remove(&id) {
                    self.sockets.remove(u.handle);
                    self.used_ports.remove(&u.port);
                }
            }
            Cmd::AttachPeer { session } => {
                let peer_id = session.state.peer_id;
                self.attach_session(*session, false, events);
                tracing::debug!(target: "engine", "easytier: inbound peer {peer_id} joined the node");
            }
            Cmd::ListNodes { reply } => {
                let _ = reply.send(self.overlay_nodes());
            }
            Cmd::MyPeerId { reply } => {
                let _ = reply.send(self.my_peer_id);
            }
            Cmd::Shutdown { .. } => {
                // Handled by the driver loop (it must break out of the
                // select, not just the command dispatch).
            }
        }
    }

    fn next_deadline(&mut self) -> std::time::Instant {
        let mut until = std::time::Instant::now()
            + self
                .iface
                .poll_delay(self.now(), &self.sockets)
                .map(|d| Duration::from_micros(d.total_micros()))
                .unwrap_or(MAX_TICK)
                .clamp(MIN_TICK, MAX_TICK);
        for session in &self.peers {
            if let Some(deadline) = session.sync_deadline {
                until = until.min(deadline);
            }
            if session.gossip.sync_due() {
                until = until.min(std::time::Instant::now() + Duration::from_millis(50));
            }
        }
        until
    }

    /// The MagicDNS node table of the whole node: every address learned
    /// over any session (`ShowNodeInfo` / `ListRoute` behind the overlay
    /// resolver — the merged LSDB view).
    fn overlay_nodes(&self) -> Vec<OverlayNode> {
        let mut nodes = Vec::new();
        for session in &self.peers {
            for info in session.gossip.lsdb.values() {
                if let (Some(ipv4), true) = (info.ipv4(), info.peer_id != self.my_peer_id) {
                    nodes.push(OverlayNode {
                        hostname: info.hostname.clone().unwrap_or_default(),
                        ipv4,
                    });
                }
            }
        }
        if let Some(ipv4) = self.my_ipv4 {
            nodes.push(OverlayNode {
                hostname: self.hostname.clone(),
                ipv4,
            });
        }
        nodes
    }
}

/// The IPv4 destination of one overlay frame (`version == 4`, dst at
/// bytes 16..20) — None for anything else (the overlay is IPv4-only).
fn ipv4_destination(frame: &[u8]) -> Option<Ipv4Addr> {
    if frame.len() < 20 || frame[0] >> 4 != 4 {
        return None;
    }
    Some(Ipv4Addr::new(
        frame[16],
        frame[17],
        frame[18],
        frame[19],
    ))
}

/// `addr` inside `subnet/len` (the route lookup of `send_msg_by_ip`).
fn ipv4_in_subnet(addr: Ipv4Addr, subnet: Ipv4Addr, len: u8) -> bool {
    if len == 0 {
        return true;
    }
    let mask = if len >= 32 {
        u32::MAX
    } else {
        u32::MAX << (32 - len)
    };
    (u32::from(addr) & mask) == (u32::from(subnet) & mask)
}

/// Parse one `a.b.c.d/len` proxy CIDR.
fn parse_cidr(cidr: &str) -> Option<(Ipv4Addr, u8)> {
    let (addr, len) = cidr.trim().split_once('/')?;
    Some((addr.parse().ok()?, len.parse().ok()?))
        .filter(|(_, len)| *len <= 32)
}

/// Drive one overlay node: the per-session gossip timers, every peer's
/// channel (IP frames + control, multiplexed through [`PeerEvent`]), the
/// command queue and the netstack all make progress in one loop. The
/// loop runs until a `Shutdown` command or the last command sender
/// drops (listener acceptors hold senders, so a serving node outlives
/// its peers).
async fn run_overlay(
    mut stack: EtStack,
    mut cmd_rx: mpsc::Receiver<Cmd>,
    events_tx: mpsc::Sender<PeerEvent>,
    mut events_rx: mpsc::Receiver<PeerEvent>,
) {
    let wake = stack.wake.clone();
    // The first sync fires immediately (an unsynced session syncs on the
    // first tick).
    stack.gossip_tick().await;
    loop {
        stack.step().await;
        stack.gossip_tick().await;
        let deadline = stack.next_deadline();
        let sleep = tokio::time::sleep_until(tokio::time::Instant::from_std(deadline));
        enum Event {
            Cmd(Cmd),
            Peer(Option<PeerEvent>),
            Wake,
            Tick,
        }
        // The select borrows `stack` immutably in its channel branches;
        // handling happens after the statement, once those futures are
        // dropped, so the handlers can take the stack mutably.
        let event = tokio::select! {
            biased;
            cmd = cmd_rx.recv() => match cmd {
                Some(c) => Event::Cmd(c),
                None => break,
            },
            ev = events_rx.recv() => Event::Peer(ev),
            _ = wake.notified() => Event::Wake,
            _ = sleep => Event::Tick,
        };
        match event {
            Event::Cmd(Cmd::Shutdown { reply }) => {
                // Tear the sessions' tasks down deterministically (the
                // standalone node does this in `EasyTierNode::close`).
                for session in &stack.peers {
                    for task in &session.tasks {
                        task.abort();
                    }
                }
                let _ = reply.send(());
                break;
            }
            Event::Cmd(c) => stack.on_cmd(c, &events_tx).await,
            Event::Peer(Some(PeerEvent::Ctrl(idx, p))) => stack.on_ctrl(idx, p).await,
            Event::Peer(Some(PeerEvent::Data(_idx, f))) => {
                stack.shim.stage(&f);
                stack.wake.notify_one();
            }
            Event::Peer(Some(PeerEvent::Closed(idx))) => {
                if let Some(session) = stack.peers.get_mut(idx) {
                    session.closed = true;
                    tracing::debug!(target: "engine", "easytier: peer {} left", session.peer_id);
                }
            }
            Event::Peer(None) => {
                // Unreachable while this loop holds its own sender; treat
                // as a tick.
            }
            Event::Wake | Event::Tick => {}
        }
        if stack.fail.is_some() {
            break;
        }
    }
}

// ---------------------------------------------------------------------------
// Public API: one shared overlay node per config identity (the
// wireguard.rs/openvpn.rs tunnel registry pattern)
// ---------------------------------------------------------------------------

static NODES: std::sync::OnceLock<tokio::sync::Mutex<HashMap<String, mpsc::Sender<Cmd>>>> =
    std::sync::OnceLock::new();

/// The config identity a node is cached by: everything that changes the
/// peer session or the announced routes — plus the listener set (a
/// serving node is a different animal than a dial-only one).
fn node_cache_key(cfg: &EasyTierConfig) -> String {
    [
        cfg.name.as_str(),
        &cfg.network_name,
        &cfg.network_secret,
        &cfg.peers.join(","),
        cfg.ipv4.as_deref().unwrap_or(""),
        &cfg.dhcp.to_string(),
        cfg.hostname.as_deref().unwrap_or(""),
        cfg.instance_name.as_deref().unwrap_or(""),
        cfg.encryption_algorithm.as_deref().unwrap_or(""),
        &cfg.enable_encryption.map(|b| b.to_string()).unwrap_or_default(),
        &cfg.mtu.to_string(),
        &cfg.proxy_networks.join(","),
        &cfg.no_listener.map(|b| b.to_string()).unwrap_or_default(),
        &cfg.listeners.join(","),
    ]
    .join("\u{1f}")
}

/// The parsed static overlay address + prefix (the `ipv4` config field;
/// a bare address carries /32 — DELTA: upstream's CIDR parser requires
/// an explicit prefix for anything else).
fn static_overlay_address(cfg: &EasyTierConfig) -> Result<Option<(Ipv4Addr, u32)>> {
    let Some(raw) = cfg.ipv4.as_deref().filter(|s| !s.trim().is_empty()) else {
        return Ok(None);
    };
    let (addr, prefix) = match raw.trim().split_once('/') {
        Some((addr, prefix)) => {
            let prefix = prefix.parse::<u32>().map_err(|_| {
                Error::config(format!("easytier: invalid overlay IPv4 prefix in {raw:?}"))
            })?;
            if prefix > 32 {
                return Err(Error::config(format!(
                    "easytier: invalid overlay IPv4 prefix in {raw:?}"
                )));
            }
            (addr, prefix)
        }
        None => (raw.trim(), 32),
    };
    let addr: Ipv4Addr = addr
        .parse()
        .map_err(|e| Error::config(format!("easytier: invalid overlay IPv4 {raw:?}: {e}")))?;
    Ok(Some((addr, prefix)))
}

/// Bring the mesh up for `cfg` (or reuse the live one): the direct
/// peer connection over the first supported transport, the route
/// exchange, and the overlay address — then hand back the command
/// channel every dial shares. DELTA: the dial-only registry path binds
/// no listeners even when the config carries them (the adapter use
/// case never serves); `serve` is the listener entry.
async fn node_for(cfg: &EasyTierConfig) -> Result<mpsc::Sender<Cmd>> {
    let structured = cfg.structured_config();
    structured.validate()?;
    let secure = secure_mode_ctx(cfg, &structured)?;
    let key = node_cache_key(cfg);
    let cache = NODES.get_or_init(Default::default);
    let mut map = cache.lock().await;
    if let Some(tx) = map.get(&key) {
        if !tx.is_closed() {
            return Ok(tx.clone());
        }
    }
    let algorithm = cfg
        .encryption_algorithm
        .clone()
        .unwrap_or_else(|| EncryptionAlgorithm::default().as_str().to_owned());
    let encryptor = create_encryptor(
        &algorithm,
        cfg.enable_encryption.unwrap_or(true),
        &cfg.network_secret,
    )?;
    let my_peer_id = random_peer_id();
    let hostname = cfg
        .hostname
        .clone()
        .unwrap_or_else(|| format!("rustcrash-{}", my_peer_id & 0xffff));
    let static_addr = static_overlay_address(cfg)?;
    let (addr, prefix) = static_addr.unzip();
    let want_dhcp = addr.is_none() && (cfg.dhcp || cfg.ipv4.as_deref().unwrap_or("").trim().is_empty());
    let mtu = if cfg.mtu > 0 {
        cfg.mtu as usize
    } else {
        DEFAULT_MTU
    };
    let mut stack = EtStack::new(
        my_peer_id,
        &cfg.network_name,
        &hostname,
        mtu,
        addr,
        prefix.unwrap_or(32),
        want_dhcp,
        cfg.proxy_networks.clone(),
    );
    let (events_tx, events_rx) = mpsc::channel::<PeerEvent>(64);
    // The outbound session: dial the first supported peer (the direct
    // connector's first task).
    let peers = structured.parsed_peers()?;
    let supported = peers
        .iter()
        .find(|p| parse_peer_endpoint(p.uri.trim()).is_ok())
        .map(|p| p.uri.clone());
    if let Some(uri) = supported {
        let endpoint = parse_peer_endpoint(&uri)?;
        let halves = dial_session(
            &endpoint,
            my_peer_id,
            &cfg.network_name,
            &cfg.network_secret,
            encryptor,
            secure.as_ref(),
        )
        .await?;
        stack.attach_session(halves, true, &events_tx);
    }
    let (tx, rx) = mpsc::channel::<Cmd>(64);
    tokio::spawn(run_overlay(stack, rx, events_tx, events_rx));
    map.insert(key, tx.clone());
    Ok(tx)
}

/// Dial a TCP connection through the EasyTier overlay described by
/// `cfg`. The overlay node (peer connection + route exchange + netstack)
/// is created on first use and shared by every later dial with the same
/// configuration; `target` must be an overlay IPv4 address (the peer's,
/// or any address the peer routes — proxied networks, exit nodes).
pub async fn connect_tcp(cfg: &EasyTierConfig, target: &SocketAddr) -> Result<BoxProxyStream> {
    let tunnel = node_for(cfg).await?;
    wait_ready(&tunnel).await?;
    let (tx, rx) = oneshot::channel();
    tunnel
        .send(Cmd::Connect {
            remote: *target,
            reply: tx,
        })
        .await
        .map_err(|_| Error::network("easytier: overlay node task is gone"))?;
    let shared = tokio::time::timeout(TCP_CONNECT_TIMEOUT, rx)
        .await
        .map_err(|_| Error::network("easytier: tcp dial timed out"))?
        .map_err(|_| Error::network("easytier: overlay node task dropped the dial"))??;
    Ok(Box::new(EtStream { shared }))
}

/// The readiness gate: one signal when the route exchange completed
/// (our address known + one successful sync), bounded by the node's
/// route budget.
async fn wait_ready(tunnel: &mpsc::Sender<Cmd>) -> Result<()> {
    let (tx, rx) = oneshot::channel();
    tunnel
        .send(Cmd::WaitReady { reply: tx })
        .await
        .map_err(|_| Error::network("easytier: overlay node task is gone"))?;
    tokio::time::timeout(ROUTE_READY_TIMEOUT, rx)
        .await
        .map_err(|_| Error::network("easytier: route exchange did not complete in time"))?
        .map_err(|_| Error::network("easytier: route exchange failed"))
}

// ---------------------------------------------------------------------------
// The listener side (instance/listeners.rs of the v2.6.4 core: the
// `create_listener_by_url` dispatch — `IpScheme::Tcp =>
// TcpTunnelListener`, `IpScheme::Udp => UdpTunnelListener`,
// `IpScheme::Quic => QuicTunnelListener`, `IpScheme::Ws | Wss =>
// WsTunnelListener`, listeners.rs:26-59 — plus
// `ListenerManager::run_listener`'s accept loop feeding every accepted
// tunnel to the SAME peer manager, listeners.rs:179-256)
// ---------------------------------------------------------------------------

/// One bound listener of the serving node.
enum BoundListener {
    Tcp(tokio::net::TcpListener),
    Udp(UdpVtListener),
    Quic(QuicVtListener),
    Wg(WgVtListener),
    Ws(WsVtListener),
}

/// The inbound stream of one accepted peer: a TCP connection, an
/// established UDP circuit, the bi-stream of one QUIC connection, a
/// WireGuard peer tunnel, or an upgraded WebSocket (`Box<dyn Tunnel>`
/// upstream — the tunnel trait's stream side).
pub enum InboundPeerStream {
    Tcp(tokio::net::TcpStream),
    Udp(UdpVtStream),
    Quic(EtQuicStream),
    Wg(UdpVtStream),
    Ws(WsPeerStream),
}

impl AsyncRead for InboundPeerStream {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.get_mut() {
            InboundPeerStream::Tcp(stream) => Pin::new(stream).poll_read(cx, buf),
            InboundPeerStream::Udp(stream) => Pin::new(stream).poll_read(cx, buf),
            InboundPeerStream::Quic(stream) => Pin::new(stream).poll_read(cx, buf),
            InboundPeerStream::Wg(stream) => Pin::new(stream).poll_read(cx, buf),
            InboundPeerStream::Ws(stream) => Pin::new(stream).poll_read(cx, buf),
        }
    }
}

impl AsyncWrite for InboundPeerStream {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        match self.get_mut() {
            InboundPeerStream::Tcp(stream) => Pin::new(stream).poll_write(cx, buf),
            InboundPeerStream::Udp(stream) => Pin::new(stream).poll_write(cx, buf),
            InboundPeerStream::Quic(stream) => Pin::new(stream).poll_write(cx, buf),
            InboundPeerStream::Wg(stream) => Pin::new(stream).poll_write(cx, buf),
            InboundPeerStream::Ws(stream) => Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            InboundPeerStream::Tcp(stream) => Pin::new(stream).poll_flush(cx),
            InboundPeerStream::Udp(stream) => Pin::new(stream).poll_flush(cx),
            InboundPeerStream::Quic(stream) => Pin::new(stream).poll_flush(cx),
            InboundPeerStream::Wg(stream) => Pin::new(stream).poll_flush(cx),
            InboundPeerStream::Ws(stream) => Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        match self.get_mut() {
            InboundPeerStream::Tcp(stream) => Pin::new(stream).poll_shutdown(cx),
            InboundPeerStream::Udp(stream) => Pin::new(stream).poll_shutdown(cx),
            InboundPeerStream::Quic(stream) => Pin::new(stream).poll_shutdown(cx),
            InboundPeerStream::Wg(stream) => Pin::new(stream).poll_shutdown(cx),
            InboundPeerStream::Ws(stream) => Pin::new(stream).poll_shutdown(cx),
        }
    }
}

impl BoundListener {
    /// `TunnelListener::accept` — the next inbound tunnel.
    async fn accept(&mut self) -> Result<InboundPeerStream> {
        match self {
            BoundListener::Tcp(listener) => {
                let (stream, _addr) = listener
                    .accept()
                    .await
                    .map_err(|e| Error::network(format!("easytier: tcp accept: {e}")))?;
                Ok(InboundPeerStream::Tcp(stream))
            }
            BoundListener::Udp(listener) => {
                let stream = listener.accept().await?;
                Ok(InboundPeerStream::Udp(stream))
            }
            BoundListener::Quic(listener) => {
                let stream = listener.accept().await?;
                Ok(InboundPeerStream::Quic(stream))
            }
            BoundListener::Wg(listener) => {
                let stream = listener.accept().await?;
                Ok(InboundPeerStream::Wg(stream))
            }
            BoundListener::Ws(listener) => {
                let stream = listener.accept().await?;
                Ok(InboundPeerStream::Ws(stream))
            }
        }
    }
}

/// A serving EasyTier node: the process-global overlay node of `cfg`
/// (shared with `connect_tcp`/`EasyTierUdp` through the registry) plus
/// its listener tasks. Dropping the handle does NOT stop the node (the
/// registry keeps it); [`EasyTierServer::shutdown`] does.
pub struct EasyTierServer {
    cmd: mpsc::Sender<Cmd>,
    local_addrs: Vec<SocketAddr>,
    acceptors: Vec<tokio::task::JoinHandle<()>>,
}

impl std::fmt::Debug for EasyTierServer {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EasyTierServer")
            .field("local_addrs", &self.local_addrs)
            .finish()
    }
}

impl EasyTierServer {
    /// The addresses the listeners actually bound (port 0 resolved).
    pub fn local_addrs(&self) -> &[SocketAddr] {
        &self.local_addrs
    }

    /// Block until the node has an overlay address and at least one
    /// finished route exchange (an inbound peer must have joined and
    /// synced).
    pub async fn wait_ready(&self) -> Result<()> {
        wait_ready(&self.cmd).await
    }

    /// The node table of the mesh as this node sees it (the
    /// `ShowNodeInfo`/`ListRoute` view behind the overlay resolver).
    pub async fn overlay_nodes(&self) -> Result<Vec<OverlayNode>> {
        let (tx, rx) = oneshot::channel();
        self.cmd
            .send(Cmd::ListNodes { reply: tx })
            .await
            .map_err(|_| Error::network("easytier: overlay node task is gone"))?;
        rx.await
            .map_err(|_| Error::network("easytier: overlay node task is gone"))
    }

    /// Stop the node deterministically: abort the acceptors, tear the
    /// node task down, leave the registry entry dead (the next dial
    /// with this config creates a fresh node).
    pub async fn shutdown(self) {
        for acceptor in &self.acceptors {
            acceptor.abort();
        }
        let (tx, rx) = oneshot::channel();
        if self.cmd.send(Cmd::Shutdown { reply: tx }).await.is_ok() {
            let _ = tokio::time::timeout(Duration::from_secs(2), rx).await;
        }
    }
}

/// `create_listener_by_url` (listeners.rs:26-59) over the five direct
/// transports: parse the URI, bind it (the `wg://` listener derives its
/// keypair from the network identity — `WgConfig::
/// new_from_network_identity`, listeners.rs:36-42). Unhandled schemes
/// name the unported transports.
async fn bind_listener_uri(
    uri: &str,
    network_name: &str,
    network_secret: &str,
) -> Result<BoundListener> {
    let endpoint = parse_peer_endpoint(uri)?;
    match endpoint.transport {
        PeerTransport::Tcp => {
            let listener = tokio::net::TcpListener::bind((endpoint.host.as_str(), endpoint.port))
                .await
                .map_err(|e| {
                    Error::network(format!("easytier: listen on {uri}: {e}"))
                })?;
            Ok(BoundListener::Tcp(listener))
        }
        PeerTransport::Udp => {
            let addr = resolve_peer_addr(&endpoint).await?;
            Ok(BoundListener::Udp(UdpVtListener::bind(addr).await?))
        }
        PeerTransport::Quic => {
            let addr = resolve_peer_addr(&endpoint).await?;
            Ok(BoundListener::Quic(QuicVtListener::bind(addr)?))
        }
        PeerTransport::Wg => {
            let addr = resolve_peer_addr(&endpoint).await?;
            Ok(BoundListener::Wg(
                WgVtListener::bind(addr, network_name, network_secret).await?,
            ))
        }
        PeerTransport::Ws | PeerTransport::Wss => {
            Ok(BoundListener::Ws(WsVtListener::bind(&endpoint).await?))
        }
    }
}

/// The local address a bound listener reports.
async fn listener_local_addr(listener: &mut BoundListener) -> Result<SocketAddr> {
    match listener {
        BoundListener::Tcp(l) => l
            .local_addr()
            .map_err(|e| Error::network(format!("easytier: tcp local addr: {e}"))),
        BoundListener::Udp(l) => Ok(l.local_addr()),
        BoundListener::Quic(l) => Ok(l.local_addr()),
        BoundListener::Wg(l) => Ok(l.local_addr()),
        BoundListener::Ws(l) => Ok(l.local_addr()),
    }
}

/// Serve the mesh described by `cfg`: bind every configured listener
/// (`listeners:`; the default `tcp://0.0.0.0:11010` when unset), dial
/// the first supported peer when one is configured, and run the shared
/// overlay node — every inbound peer joins it through the SAME
/// handshake, crypto and keepalive the client side speaks
/// (`serve_peer_as`), then gossips routes and relays overlay traffic
/// like any attached session.
///
/// This is the productionized counterpart of upstream's
/// `ListenerManager::run` + the peer manager's `add_tunnel_as_server`
/// (instance/listeners.rs:258-277, peers/peer_manager.rs:703+); the
/// returned handle controls the acceptors. DELTA vs upstream: no
/// listen-retry loop (a bind failure fails `serve` — the caller
/// retries), and the IPv6 dual-stack mirror listener
/// (listeners.rs:145-161, gated by `enable-ipv6`) is opened best-effort
/// only for `tcp://0.0.0.0:port` since the config surface carries no
/// IPv6 flag.
pub async fn serve(cfg: &EasyTierConfig) -> Result<EasyTierServer> {
    let structured = cfg.structured_config();
    structured.validate()?;
    // One shared context per node: the same static identity and the same
    // session store for the outbound dial and every acceptor, so a
    // reconnecting secure-mode peer resumes its session.
    let secure = secure_mode_ctx(cfg, &structured)?.map(Arc::new);
    let listener_uris = structured.listeners();
    if listener_uris.is_empty() {
        return Err(Error::config(
            "easytier: serve: no-listener is set and no listeners configured; nothing to accept on",
        ));
    }

    // `ListenerManager::run`: every must-succeed listener binds before
    // the node starts (listeners.rs:258-277).
    let mut bound_listeners: Vec<BoundListener> = Vec::new();
    for uri in &listener_uris {
        bound_listeners
            .push(bind_listener_uri(uri, &cfg.network_name, &cfg.network_secret).await?);
    }
    // The IPv6 dual-stack mirror (listeners.rs:145-161): an unspecified
    // v4 host additionally gets a `[::]` listener on the same port,
    // best-effort (`must_succ = false`; on Linux the v4 listener usually
    // owns the port already unless v6-only).
    for uri in &listener_uris {
        if uri.starts_with("tcp://0.0.0.0:") {
            let v6 = uri.replacen("tcp://0.0.0.0:", "tcp://[::]:", 1);
            if let Ok(listener) =
                bind_listener_uri(&v6, &cfg.network_name, &cfg.network_secret).await
            {
                bound_listeners.push(listener);
            }
        }
    }

    // The shared node: reuse a live registry entry (a previous serve or
    // dial of the identical config) or create it.
    let key = node_cache_key(cfg);
    let cache = NODES.get_or_init(Default::default);
    let mut map = cache.lock().await;
    let cmd = if let Some(tx) = map.get(&key).filter(|tx| !tx.is_closed()) {
        tx.clone()
    } else {
        let my_peer_id = random_peer_id();
        let hostname = cfg
            .hostname
            .clone()
            .unwrap_or_else(|| format!("rustcrash-{}", my_peer_id & 0xffff));
        let static_addr = static_overlay_address(cfg)?;
        let (addr, prefix) = static_addr.unzip();
        let want_dhcp =
            addr.is_none() && (cfg.dhcp || cfg.ipv4.as_deref().unwrap_or("").trim().is_empty());
        let mtu = if cfg.mtu > 0 {
            cfg.mtu as usize
        } else {
            DEFAULT_MTU
        };
        let mut stack = EtStack::new(
            my_peer_id,
            &cfg.network_name,
            &hostname,
            mtu,
            addr,
            prefix.unwrap_or(32),
            want_dhcp,
            cfg.proxy_networks.clone(),
        );
        let (events_tx, events_rx) = mpsc::channel::<PeerEvent>(64);
        // The outbound side: dial the first supported peer when one is
        // configured (the direct connector's first task). A serving node
        // with no reachable peer stays up — its job is to accept.
        let peers = structured.parsed_peers()?;
        let supported = peers
            .iter()
            .find(|p| parse_peer_endpoint(p.uri.trim()).is_ok())
            .map(|p| p.uri.clone());
        if let Some(uri) = supported {
            let dial = parse_peer_endpoint(&uri).and_then(|endpoint| {
                let algorithm = cfg
                    .encryption_algorithm
                    .clone()
                    .unwrap_or_else(|| EncryptionAlgorithm::default().as_str().to_owned());
                let encryptor =
                    create_encryptor(&algorithm, cfg.enable_encryption.unwrap_or(true), &cfg.network_secret)?;
                Ok((endpoint, encryptor))
            });
            match dial {
                Ok((endpoint, peer_encryptor)) => {
                    match dial_session(
                        &endpoint,
                        my_peer_id,
                        &cfg.network_name,
                        &cfg.network_secret,
                        peer_encryptor,
                        secure.as_deref(),
                    )
                    .await
                    {
                        Ok(halves) => {
                            stack.attach_session(halves, true, &events_tx);
                        }
                        Err(e) => {
                            // DELTA: no connector retry loop — the
                            // listener is the point; log and serve.
                            tracing::debug!(target: "engine", "easytier: outbound peer {uri} unreachable: {e}");
                        }
                    }
                }
                Err(e) => {
                    tracing::debug!(target: "engine", "easytier: outbound peer {uri}: {e}");
                }
            }
        }
        let (tx, rx) = mpsc::channel::<Cmd>(64);
        tokio::spawn(run_overlay(stack, rx, events_tx, events_rx));
        map.insert(key.clone(), tx.clone());
        tx
    };
    drop(map);

    // The accept loops (listeners.rs:209-256): every accepted tunnel is
    // handshaked as the server and joins the running node.
    let mut local_addrs = Vec::new();
    let mut acceptors = Vec::new();
    for mut listener in bound_listeners {
        local_addrs.push(listener_local_addr(&mut listener).await?);
        let cmd = cmd.clone();
        let network_name = cfg.network_name.clone();
        let network_secret = cfg.network_secret.clone();
        let algorithm = cfg
            .encryption_algorithm
            .clone()
            .unwrap_or_else(|| EncryptionAlgorithm::default().as_str().to_owned());
        let enable_encryption = cfg.enable_encryption.unwrap_or(true);
        let secure = secure.clone();
        let my_peer_id = cmd_my_peer_id(&cmd).await;
        let acceptor = tokio::spawn(async move {
            loop {
                let stream = match listener.accept().await {
                    Ok(stream) => stream,
                    Err(e) => {
                        // Accept errors break to the outer retry loop
                        // upstream (listeners.rs:210-220); here the
                        // acceptor just ends — the node survives.
                        tracing::debug!(target: "engine", "easytier: accept: {e}");
                        break;
                    }
                };
                // A fresh encryptor per connection (deterministic from
                // the network secret).
                let encryptor = match create_encryptor(&algorithm, enable_encryption, &network_secret)
                {
                    Ok(encryptor) => encryptor,
                    Err(e) => {
                        tracing::debug!(target: "engine", "easytier: encryptor: {e}");
                        continue;
                    }
                };
                match serve_peer_as(
                    stream,
                    my_peer_id,
                    &network_name,
                    &network_secret,
                    encryptor,
                    secure.as_deref(),
                )
                .await
                {
                    Ok((halves, peer)) => {
                        tracing::debug!(
                            target: "engine",
                            "easytier: accepted peer {} ({})",
                            peer.peer_id,
                            peer.network_name
                        );
                        if cmd
                            .send(Cmd::AttachPeer {
                                session: Box::new(halves),
                            })
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                    Err(e) => {
                        // `handle conn error` — one bad peer never stops
                        // the listener (listeners.rs:244-252).
                        tracing::debug!(target: "engine", "easytier: inbound handshake: {e}");
                    }
                }
            }
        });
        acceptors.push(acceptor);
    }

    Ok(EasyTierServer {
        cmd,
        local_addrs,
        acceptors,
    })
}

/// Ask a running node for its peer id (used so every accepted peer sees
/// the SAME node identity). A node that never answers gets a fresh id —
/// the handshake only needs non-zero.
async fn cmd_my_peer_id(cmd: &mpsc::Sender<Cmd>) -> PeerId {
    let (tx, rx) = oneshot::channel();
    if cmd.send(Cmd::MyPeerId { reply: tx }).await.is_ok() {
        if let Ok(id) = rx.await {
            return id;
        }
    }
    random_peer_id()
}

/// A UDP socket inside the EasyTier overlay: send to any overlay target,
/// receive from anyone who replies to this socket's port.
pub struct EasyTierUdp {
    cmd: mpsc::Sender<Cmd>,
    id: u32,
    down: tokio::sync::Mutex<UdpDownlink>,
}

impl Drop for EasyTierUdp {
    fn drop(&mut self) {
        let _ = self.cmd.try_send(Cmd::UdpClose { id: self.id });
    }
}

impl EasyTierUdp {
    /// Open a UDP socket through the overlay described by `cfg` (the
    /// counterpart of upstream's `ListenPacket("udp4", ":0")`).
    pub async fn bind(cfg: &EasyTierConfig) -> Result<Self> {
        let tunnel = node_for(cfg).await?;
        wait_ready(&tunnel).await?;
        let (tx, rx) = oneshot::channel();
        tunnel
            .send(Cmd::UdpOpen { reply: tx })
            .await
            .map_err(|_| Error::network("easytier: overlay node task is gone"))?;
        let (id, down) = tokio::time::timeout(Duration::from_secs(10), rx)
            .await
            .map_err(|_| Error::network("easytier: udp open timed out"))?
            .map_err(|_| Error::network("easytier: overlay node task dropped the open"))??;
        Ok(EasyTierUdp {
            cmd: tunnel,
            id,
            down: tokio::sync::Mutex::new(down),
        })
    }

    /// Send one datagram to `target` (an overlay IPv4 address).
    pub async fn send(&self, target: &SocketAddr, data: &[u8]) -> Result<()> {
        self.cmd
            .send(Cmd::UdpSend {
                id: self.id,
                dst: *target,
                data: data.to_vec(),
            })
            .await
            .map_err(|_| Error::network("easytier: overlay node task is gone"))
    }

    /// Receive the next datagram (and its sender) from the overlay.
    pub async fn recv(&self) -> Result<(SocketAddr, Vec<u8>)> {
        let mut rx = self.down.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| Error::network("easytier: udp session closed"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// SECURITY: fake credentials from the environment only.
    fn test_secret() -> String {
        std::env::var("RUSTCRASH_TEST_ET_SECRET")
            .ok()
            .filter(|s| !s.is_empty())
            .unwrap_or_else(|| "et-unit-secret".to_string())
    }

    fn minimal_config(peers: &[&str]) -> EasyTierTomlConfig {
        EasyTierTomlConfig {
            network_name: "example".into(),
            network_secret: test_secret(),
            peers: peers.iter().map(|p| p.to_string()).collect(),
            ..Default::default()
        }
    }

    // ------------------------------------------------------- overlay.go

    #[test]
    fn overlay_lookup_forms() {
        // TestLookupOverlayHost (overlay_test.go:8-18).
        let ip: Ipv4Addr = "10.144.0.2".parse().unwrap();
        let nodes = [OverlayNode {
            hostname: "peer".into(),
            ipv4: ip,
        }];
        assert_eq!(lookup_overlay_host("peer.et.net.", "et.net.", &nodes), Some(ip));
        assert_eq!(lookup_overlay_host("peer", "et.net.", &nodes), Some(ip));
        assert_eq!(lookup_overlay_host("missing", "et.net.", &nodes), None);
        // PTR + node IPv4 (overlay_test.go:20-29).
        assert_eq!(parse_ptr_ipv4("2.0.144.10.in-addr.arpa."), Some(ip));
        assert_eq!(parse_ptr_ipv4("2.0.144.10.in-addr.arpa"), Some(ip));
        assert_eq!(parse_ptr_ipv4("x.example.com."), None);
        assert_eq!(parse_ptr_ipv4("1.2.3.4.5.in-addr.arpa."), None);
        assert_eq!(parse_ptr_ipv4("a.0.144.10.in-addr.arpa."), None);
        assert_eq!(
            parse_node_ipv4("10.144.0.1/24").unwrap(),
            "10.144.0.1".parse::<Ipv4Addr>().unwrap()
        );
        assert_eq!(parse_node_ipv4("10.144.0.1").unwrap().to_string(), "10.144.0.1");
        assert!(parse_node_ipv4("").is_err());
        assert!(parse_node_ipv4("not-an-ip").is_err());
        assert_eq!(ipv4_from_u32(0x0a900002), "10.144.0.2".parse::<Ipv4Addr>().unwrap());
        // MagicDNS membership (overlay_test.go:31-41).
        assert!(!is_magic_dns("peer", "et.net."));
        assert!(is_magic_dns("peer.et.net", ""));
        assert!(!is_magic_dns("example.com", "et.net."));
        assert!(is_magic_dns("et.net", "et.net."));
        // PTR name lookup (LookupOverlayPTR).
        assert_eq!(
            lookup_overlay_ptr(ip, "et.net.", &nodes),
            Some("peer.et.net.".to_string())
        );
        assert_eq!(lookup_overlay_ptr(ip, "", &nodes), Some("peer.et.net.".to_string()));
        let other: Ipv4Addr = "10.1.2.3".parse().unwrap();
        assert_eq!(lookup_overlay_ptr(other, "et.net.", &nodes), None);
        // Normalization.
        assert_eq!(normalize_dns_name("  Peer.ET.net. "), "peer.et.net");
        assert_eq!(normalize_zone(""), "et.net");
        assert_eq!(normalize_zone(" Overlay.Example. "), "overlay.example");
    }

    // ---------------------------------------------------------- toml.go

    #[test]
    fn render_requires_peers_without_listeners() {
        // TestRenderTOMLDefaultNoListenerRequiresPeers (toml_test.go:12-17).
        let err = EasyTierTomlConfig {
            network_name: "example".into(),
            ..Default::default()
        }
        .render_toml()
        .unwrap_err()
        .to_string();
        assert!(err.contains("peers is required when listeners are empty"), "{err}");
        // network-name required.
        let err = EasyTierTomlConfig::default().validate().unwrap_err().to_string();
        assert!(err.contains("network-name is required"), "{err}");
    }

    #[test]
    fn no_listener_false_yields_default_listener() {
        // TestRenderTOMLNoListenerFalseDefaultListener (toml_test.go:19-33).
        let toml = EasyTierTomlConfig {
            network_name: "example".into(),
            no_listener: Some(false),
            ..Default::default()
        }
        .render_toml()
        .unwrap();
        assert!(
            toml.contains(&format!("listeners = [\"{DEFAULT_LISTENER}\"]")),
            "{toml}"
        );
        assert!(toml.contains("no_tun = true"));
        assert!(toml.contains("bind_device = false"));
    }

    #[test]
    fn explicit_empty_listeners_with_peers() {
        // TestRenderTOMLExplicitEmptyListenersWithPeers (toml_test.go:35-52).
        let toml = minimal_config(&["tcp://192.0.2.10:11010"])
            .render_toml()
            .unwrap();
        assert!(toml.contains("listeners = []"), "{toml}");
        assert!(toml.contains("[[peer]]"));
        assert!(toml.contains("uri = \"tcp://192.0.2.10:11010\""));
        // DHCP defaults on when ipv4 omitted (toml_test.go:146-161).
        assert!(toml.contains("dhcp = true"));
        assert!(!toml.contains("ipv4"));
    }

    #[test]
    fn static_ipv4_omits_dhcp_and_keeps_prefix() {
        // TestRenderTOMLStaticIPv4OmitsDHCP + ManualIPv4WithoutPrefix
        // (toml_test.go:88-104, 163-176).
        let cfg = EasyTierTomlConfig {
            ipv4: "10.144.0.10".into(),
            ..minimal_config(&["tcp://192.0.2.10:11010"])
        };
        let toml = cfg.render_toml().unwrap();
        assert!(toml.contains("ipv4 = \"10.144.0.10\""), "{toml}");
        assert!(!toml.contains("dhcp = true"));
        let cfg = EasyTierTomlConfig {
            ipv4: "10.144.0.1/24".into(),
            hostname: "node-a".into(),
            ..minimal_config(&["tcp://192.0.2.10:11010"])
        };
        let toml = cfg.render_toml().unwrap();
        assert!(toml.contains("ipv4 = \"10.144.0.1/24\""), "{toml}");
        assert!(toml.contains("hostname = \"node-a\""));
    }

    #[test]
    fn multiple_peers_render_distinct_tables() {
        // TestRenderTOMLMultiplePeers (toml_test.go:106-124).
        let cfg = minimal_config(&["tcp://192.0.2.10:11010", "udp://192.0.2.11:11010"]);
        let toml = cfg.render_toml().unwrap();
        assert_eq!(toml.matches("[[peer]]").count(), 2);
        assert!(toml.contains("uri = \"tcp://192.0.2.10:11010\""));
        assert!(toml.contains("uri = \"udp://192.0.2.11:11010\""));
    }

    #[test]
    fn tld_dns_zone_and_optional_flags_render() {
        // TestRenderTOMLWritesTLDDNSZone (toml_test.go:178-191).
        let cfg = EasyTierTomlConfig {
            tld_dns_zone: "overlay.example.".into(),
            mtu: 1200,
            accept_dns: Some(true),
            encryption_algorithm: "aes-256-gcm".into(),
            ..minimal_config(&["tcp://192.0.2.10:11010"])
        };
        let toml = cfg.render_toml().unwrap();
        assert!(toml.contains("tld_dns_zone = \"overlay.example.\""), "{toml}");
        assert!(toml.contains("mtu = 1200"));
        assert!(toml.contains("accept_dns = true"));
        assert!(toml.contains("encryption_algorithm = \"aes-256-gcm\""));
        // Unset optional flags render nothing.
        assert!(!toml.contains("latency_first"));
    }

    #[test]
    fn secure_mode_from_local_keys() {
        // TestRenderTOMLSecureMode (toml_test.go:193-214) — secrets via
        // env-shaped plumbing, plain sentinels for the shape test.
        let cfg = EasyTierTomlConfig {
            secure_mode: Some(true),
            local_private_key: "privkey-sentinel".into(),
            local_public_key: "pubkey-sentinel".into(),
            ..minimal_config(&["tcp://192.0.2.10:11010"])
        };
        let toml = cfg.render_toml().unwrap();
        assert!(toml.contains("[secure_mode]"), "{toml}");
        assert!(toml.contains("enabled = true"));
        assert!(toml.contains("local_private_key = \"privkey-sentinel\""));
        assert!(toml.contains("local_public_key = \"pubkey-sentinel\""));
        // Public key alone is a config error
        // (toml_test.go:251-261).
        let err = EasyTierTomlConfig {
            local_public_key: "pubkey".into(),
            ..minimal_config(&["tcp://192.0.2.10:11010"])
        }
        .validate()
        .unwrap_err()
        .to_string();
        assert!(
            err.contains("local-public-key requires local-private-key"),
            "{err}"
        );
    }

    #[test]
    fn peer_public_key_extraction() {
        // TestRenderTOMLPeerPublicKeyEnablesSecureMode
        // (toml_test.go:216-237): pinning a peer key both strips it from
        // the URI and implies [secure_mode].
        let key = "CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=";
        let cfg = minimal_config(&[&format!(
            "tcp://relay.example.com:11010?peer-public-key={key}"
        )]);
        let toml = cfg.render_toml().unwrap();
        assert!(toml.contains("[secure_mode]"), "{toml}");
        assert!(toml.contains("enabled = true"));
        assert!(toml.contains("uri = \"tcp://relay.example.com:11010\""));
        assert!(!toml.contains("peer-public-key="), "{toml}");
        assert!(toml.contains(&format!("peer_public_key = \"{key}\"")));
        // secure-mode: false + pinned peer fails
        // (toml_test.go:239-249).
        let err = EasyTierTomlConfig {
            secure_mode: Some(false),
            ..cfg
        }
        .validate()
        .unwrap_err()
        .to_string();
        assert!(err.contains("require secure-mode"), "{err}");
        // Empty peer URI fails (toml_test.go:263-272).
        assert!(minimal_config(&[""]).validate().is_err());
        // no-listener + listeners conflict (toml_test.go:77-86).
        let err = EasyTierTomlConfig {
            no_listener: Some(true),
            listeners: vec!["tcp://0.0.0.0:11010".into()],
            ..minimal_config(&["tcp://192.0.2.10:11010"])
        }
        .validate()
        .unwrap_err()
        .to_string();
        assert!(err.contains("no-listener cannot be combined with listeners"), "{err}");
    }

    #[test]
    fn parse_peer_uri_query_forms() {
        // TestParsePeerURIQuery (toml_test.go:274-301).
        let peer = parse_peer_uri(
            " tcp://relay.example.com:11010?foo=1&peer-public-key=CC%2BCC/CC=&bar=2 ",
        )
        .unwrap();
        assert_eq!(peer.uri, "tcp://relay.example.com:11010?foo=1&bar=2");
        assert_eq!(peer.peer_public_key, "CC+CC/CC=");

        let peer = parse_peer_uri(
            "tcp://relay.example.com:11010?peer_public_key=CCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCCC=",
        )
        .unwrap();
        assert_eq!(peer.uri, "tcp://relay.example.com:11010");
        assert!(!peer.peer_public_key.is_empty());

        let peer = parse_peer_uri("tcp://192.0.2.10:11010?foo=1").unwrap();
        assert_eq!(peer.uri, "tcp://192.0.2.10:11010?foo=1");
        assert_eq!(peer.peer_public_key, "");

        assert!(parse_peer_uri("  ").is_err());
        // Bad escapes error where Go decodes: in a parameter NAME and in
        // a peer-public-key VALUE (plain other values pass through
        // verbatim, exactly like upstream).
        assert!(parse_peer_uri("tcp://x?%zz=1").is_err(), "bad name escape");
        assert!(
            parse_peer_uri("tcp://x?peer-public-key=%zz").is_err(),
            "bad key escape"
        );
        assert!(parse_peer_uri("tcp://x?k=%zz").is_ok(), "other values pass through");
    }

    #[test]
    fn apply_required_flags_injects_and_replaces() {
        // TestApplyRequiredFlagsInjectsNoTun (toml_test.go:54-62).
        let got = apply_required_flags("[network_identity]\nnetwork_name = \"n\"\n");
        assert!(got.contains("[flags]") && got.contains("no_tun = true"), "{got}");
        assert!(got.contains("bind_device = false"));
        // TestApplyRequiredFlagsReplacesNoTun (toml_test.go:64-75).
        let got = apply_required_flags("[flags]\nno_tun = false\nmtu = 1200\n");
        assert!(got.contains("no_tun = true"), "{got}");
        assert!(got.contains("bind_device = false"));
        assert!(got.contains("mtu = 1200"), "lost existing flag");
        // Section comment keeps one table (toml_test.go:126-134).
        let got = apply_required_flags("[flags] # tun flags\nno_tun = false\nmtu = 1200\n");
        assert_eq!(got.matches("[flags]").count(), 1, "{got}");
        assert!(got.contains("no_tun = true") && got.contains("mtu = 1200"));
        // Quoted key replaced, not duplicated (toml_test.go:136-144).
        let got = apply_required_flags("[flags]\n\"no_tun\" = false\n");
        assert_eq!(got.matches("no_tun").count(), 1, "{got}");
        assert!(got.contains("no_tun = true"));
        // Array-of-table sections are recognized as sections.
        let got = apply_required_flags("[[peer]]\nuri = \"tcp://x\"\n");
        assert!(got.contains("[flags]"), "{got}");
        assert!(got.contains("[[peer]]"));
    }

    #[test]
    fn toml_string_quoting_matches_go_json() {
        // Go's json.Marshal HTML-escapes <, >, & and control chars.
        assert_eq!(quote_toml_string("plain"), "\"plain\"");
        assert_eq!(quote_toml_string("a\"b\\c"), "\"a\\\"b\\\\c\"");
        assert_eq!(quote_toml_string("a<b>&c"), "\"a\\u003cb\\u003e\\u0026c\"");
        assert_eq!(quote_toml_string("nl\n"), "\"nl\\n\"");
        assert_eq!(quote_toml_string("\u{1}"), "\"\\u0001\"");
    }

    // ------------------------------------------------- adapter-level glue

    #[test]
    fn config_projection_and_defaults() {
        // structuredConfig (adapter cached lines 91-126) + state-dir
        // default (lines 135-138) + zone normalization (line 163).
        let cfg = EasyTierConfig::new("my-et", "mymesh");
        assert_eq!(cfg.effective_state_dir(), "easytier/my-et");
        assert_eq!(cfg.zone(), "et.net");
        let structured = cfg.structured_config();
        assert_eq!(structured.instance_name, "my-et");
        assert_eq!(structured.network_name, "mymesh");
        let cfg = EasyTierConfig {
            instance_name: Some("inst".into()),
            state_dir: Some("s".into()),
            tld_dns_zone: Some("z.example.".into()),
            ..EasyTierConfig::new("n", "net")
        };
        assert_eq!(cfg.structured_config().instance_name, "inst");
        assert_eq!(cfg.effective_state_dir(), "s");
        assert_eq!(cfg.zone(), "z.example");
        // render_instance_toml = RenderTOML + ApplyRequiredFlags
        // (adapter cached lines 128-134).
        let cfg = EasyTierConfig {
            peers: vec!["tcp://192.0.2.10:11010".into()],
            ..EasyTierConfig::new("et", "net")
        };
        let toml = cfg.render_instance_toml().unwrap();
        assert!(toml.contains("[flags]"));
        assert!(toml.contains("no_tun = true"));
        assert!(toml.contains("network_name = \"net\""));
    }

    #[test]
    fn secrets_are_redacted_in_debug() {
        let cfg = EasyTierConfig {
            network_secret: "super-secret".into(),
            local_private_key: Some("priv".into()),
            local_public_key: Some("pub".into()),
            ..EasyTierConfig::new("et", "net")
        };
        let debug = format!("{cfg:?}");
        assert!(!debug.contains("super-secret"), "{debug}");
        assert!(!debug.contains("\"priv\""), "{debug}");
        assert!(!debug.contains("\"pub\""), "{debug}");
        assert_eq!(debug.matches("[redacted]").count(), 3);
    }

    #[tokio::test]
    async fn connect_config_errors_name_the_next_step() {
        // No peers + no listeners fails validation exactly like the TOML
        // layer (toml.go ValidateStructured).
        let err = connect(&EasyTierConfig::new("et", "net"))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("peers is required when listeners are empty"), "{err}");
        // An unsupported-scheme peer names the missing transports; the
        // five direct transports (wg:// included) dial now.
        let cfg = EasyTierConfig {
            peers: vec!["faketcp://192.0.2.10:11010".into()],
            ..EasyTierConfig::new("et", "net")
        };
        let err = connect(&cfg).await.unwrap_err().to_string();
        assert!(err.contains("no tcp://, udp://, quic://, wg://, ws:// or wss:// peer"), "{err}");
        // Secure mode runs the Noise_XX handshake now (its hermetic
        // round-trip tests are below); an invalid key still fails the
        // config before the dial.
        let cfg = EasyTierConfig {
            peers: vec!["tcp://192.0.2.10:11010".into()],
            secure_mode: Some(true),
            local_private_key: Some("not-base64!!".to_owned()),
            ..EasyTierConfig::new("et", "net")
        };
        let err = connect(&cfg).await.unwrap_err().to_string();
        assert!(err.contains("local-private-key"), "{err}");
        // An unknown encryption algorithm fails the dial (peer_manager.rs:
        // 902-908 validate_algorithm).
        let cfg = EasyTierConfig {
            peers: vec!["tcp://192.0.2.10:11010".into()],
            encryption_algorithm: Some("aes-512-gcm".into()),
            ..EasyTierConfig::new("et", "net")
        };
        let err = connect(&cfg).await.unwrap_err().to_string();
        assert!(err.contains("invalid encryption algorithm"), "{err}");
    }

    // ------------------------------------------------ wire: header + framing

    #[test]
    fn peer_manager_header_golden_bytes() {
        // packet/mod.rs:125-136 — packed, little-endian.
        let hdr = PeerManagerHeader {
            from_peer_id: 0x01020304,
            to_peer_id: 0x0a0b0c0d,
            packet_type: packet_type::DATA,
            flags: pm_flag::ENCRYPTED | pm_flag::LATENCY_FIRST,
            forward_counter: 1,
            reserved: 0,
            len: 1500,
        };
        let bytes = hdr.to_bytes();
        assert_eq!(
            bytes,
            [
                0x04, 0x03, 0x02, 0x01, // from_peer_id LE
                0x0d, 0x0c, 0x0b, 0x0a, // to_peer_id LE
                packet_type::DATA, 0x03, 0x01, 0x00, // type, flags, fwd, reserved
                0xdc, 0x05, 0x00, 0x00, // len = 1500 LE
            ]
        );
        assert_eq!(PeerManagerHeader::from_bytes(&bytes).unwrap(), hdr);
        assert!(PeerManagerHeader::from_bytes(&bytes[..15]).is_none());
        // Flag accessors (packet/mod.rs:139-163).
        let mut h = hdr;
        assert!(h.is_encrypted() && h.is_latency_first());
        h.set_encrypted(false);
        assert!(!h.is_encrypted() && h.is_latency_first());
        h.set_latency_first(false).set_exit_node(true);
        assert!(!h.is_latency_first() && h.flags & pm_flag::EXIT_NODE != 0);
    }

    #[tokio::test]
    async fn tcp_frame_round_trip_and_length_limits() {
        // FramedReader::extract_one_packet (framed.rs:61-85) +
        // TcpZCPacketToBytes (framed.rs:137-151).
        let (mut client, mut server) = tokio::io::duplex(4096);
        let packet = PeerPacket::new(7, 9, packet_type::HANDSHAKE, b"payload-bytes");
        write_frame(&mut client, &packet).await.unwrap();
        let readback = read_frame(&mut server).await.unwrap().unwrap();
        assert_eq!(readback, packet);
        assert_eq!(readback.hdr.len as usize, b"payload-bytes".len());
        // Two frames coalesced in one segment still split cleanly.
        write_frame(&mut client, &packet).await.unwrap();
        write_frame(&mut client, &packet).await.unwrap();
        assert_eq!(read_frame(&mut server).await.unwrap().unwrap(), packet);
        assert_eq!(read_frame(&mut server).await.unwrap().unwrap(), packet);
        // Clean EOF at a frame boundary is Ok(None).
        drop(client);
        assert!(read_frame(&mut server).await.unwrap().is_none());

        // `body too short`: len < PEER_MANAGER_HEADER_SIZE
        // (framed.rs:75-77, framed.rs:349-360 test parity).
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&15u32.to_le_bytes()).await.unwrap();
        a.write_all(&[0u8; 15]).await.unwrap();
        let err = read_frame(&mut b).await.unwrap_err().to_string();
        assert!(err.contains("body too short"), "{err}");
        // `body too long`: len > TCP_MTU_BYTES (framed.rs:71-73).
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&(TCP_MTU_BYTES as u32 + 1).to_le_bytes()).await.unwrap();
        let err = read_frame(&mut b).await.unwrap_err().to_string();
        assert!(err.contains("body too long"), "{err}");
        // Writing a packet beyond the MTU fails before the socket
        // (TunnelError::ExceedMaxPacketSize semantics).
        let big = PeerPacket::new(1, 2, packet_type::DATA, &vec![0u8; TCP_MTU_BYTES]);
        assert!(big.to_tcp_frame().is_err());
        // The frame length prefix counts header + payload
        // (tcp.rs:148-155 set_tcp_tunnel_len).
        let pkt = PeerPacket::new(1, 2, packet_type::DATA, &[0u8; 100]);
        let frame = pkt.to_tcp_frame().unwrap();
        assert_eq!(
            u32::from_le_bytes(frame[0..4].try_into().unwrap()) as usize,
            PEER_MANAGER_HEADER_SIZE + 100
        );
        assert_eq!(frame.len(), TCP_TUNNEL_HEADER_SIZE + PEER_MANAGER_HEADER_SIZE + 100);
    }

    // --------------------------------------------- handshake proto3 codec

    #[test]
    fn handshake_protobuf_golden_bytes() {
        // HandshakeRequest field numbers: magic=1, my_peer_id=2,
        // version=3, features=4, network_name=5,
        // network_secret_digest=6 (peer_rpc.proto:315-322).
        let digest = network_secret_digest("et-net", "s3cret");
        let req = HandshakeRequest {
            magic: HANDSHAKE_MAGIC,
            my_peer_id: 0x1234,
            version: HANDSHAKE_VERSION,
            features: vec!["liveness-echo-v1".to_owned()],
            network_name: "et-net".into(),
            network_secret_digest: digest.to_vec(),
        };
        let mut expected = Vec::new();
        expected.push(0x08); // field 1 varint
        expected.extend_from_slice(&[0xe1, 0xcb, 0x86, 0x8f, 0x0d]); // 0xd1e1a5e1
        expected.push(0x10); // field 2 varint
        expected.extend_from_slice(&[0xb4, 0x24]); // 0x1234 varint
        expected.push(0x18); // field 3 varint
        expected.push(0x01); // version 1
        expected.push(0x22); // field 4 LEN
        expected.push(0x10); // len 16
        expected.extend_from_slice(b"liveness-echo-v1");
        expected.push(0x2a); // field 5 LEN
        expected.push(0x06);
        expected.extend_from_slice(b"et-net");
        expected.push(0x32); // field 6 LEN
        expected.push(0x20); // len 32
        expected.extend_from_slice(&digest);
        assert_eq!(req.encode(), expected);
        assert_eq!(HandshakeRequest::decode(&expected).unwrap(), req);
        // Zero-valued fields are omitted (proto3 default encoding).
        assert_eq!(HandshakeRequest::default().encode(), Vec::<u8>::new());
    }

    #[test]
    fn handshake_protobuf_decode_is_lenient() {
        // Unknown fields are skipped, any order accepted, repeated
        // features accumulate — prost's decoding contract.
        let digest = [7u8; 32];
        let mut buf = Vec::new();
        // unknown field 15, varint
        buf.extend_from_slice(&[0x78, 0x2a]);
        // features (4) twice
        buf.extend_from_slice(&[0x22, 0x01, b'a', 0x22, 0x01, b'b']);
        // digest (6) first, network_name (5) after
        buf.extend_from_slice(&[0x32, 0x20]); // field 6 (digest), LEN
        buf.extend_from_slice(&digest);
        buf.extend_from_slice(&[0x2a, 0x02, b'o', b'k']);
        // unknown field 16, LEN
        buf.extend_from_slice(&[0x82, 0x01, 0x02, 0xde, 0xad]);
        let req = HandshakeRequest::decode(&buf).unwrap();
        assert_eq!(req.features, vec!["a".to_string(), "b".to_string()]);
        assert_eq!(req.network_name, "ok");
        assert_eq!(req.network_secret_digest, digest);
        assert_eq!(req.magic, 0);
        // Truncated input errors instead of panicking.
        assert!(HandshakeRequest::decode(&[0x3a, 0x20, 0x01]).is_err());
        assert!(HandshakeRequest::decode(&[0x0f]).is_err()); // wire type 7 unknown
    }

    // ------------------------------------------------------ crypto port

    #[test]
    fn aes128_gcm_matches_upstream_standard_vector() {
        // The upstream ring-backend vector (tunnel/encrypt/ring.rs:158-176
        // aes128_gcm_matches_standard_vector): zero key, zero nonce,
        // 16 zero bytes of plaintext → NIST ciphertext+tag, then the
        // 28-byte AEAD tail. Passing this proves the tail layout AND the
        // cipher choice match the upstream ring backend byte for byte.
        let encryptor = PacketEncryptor {
            cipher: Cipher::Aes128Gcm(Box::new(
                Aes128Gcm::new_from_slice(&[0u8; 16]).unwrap(),
            )),
        };
        let mut hdr = PeerPacket::new(0, 0, packet_type::DATA, &[0u8; 16]).hdr;
        let mut payload = vec![0u8; 16];
        encryptor
            .encrypt_packet_with_nonce(&mut hdr, &mut payload, &[0u8; 12])
            .unwrap();
        assert!(hdr.is_encrypted());
        assert_eq!(
            payload,
            [
                0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92, 0xf3, 0x28, 0xc2, 0xb9, 0x71,
                0xb2, 0xfe, 0x78, // ciphertext
                0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd, 0xf5, 0x3a, 0x67, 0xb2, 0x12,
                0x57, 0xbd, 0xdf, // tag
                0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // nonce echoed in the tail
            ]
        );
        encryptor.decrypt_packet(&mut hdr, &mut payload).unwrap();
        assert_eq!(payload, vec![0u8; 16]);
        assert!(!hdr.is_encrypted());
    }

    #[test]
    fn encryptor_round_trips_every_algorithm() {
        let plaintext = b"an overlay ip frame";
        for name in ["xor", "aes-gcm", "aes-256-gcm", "chacha20", "chacha20-poly1305", "openssl-aes-gcm"] {
            let encryptor = create_encryptor(name, true, test_secret().as_str()).unwrap();
            let mut hdr = PeerPacket::new(1, 2, packet_type::DATA, plaintext).hdr;
            let mut payload = plaintext.to_vec();
            encryptor.encrypt_packet(&mut hdr, &mut payload).unwrap();
            assert!(hdr.is_encrypted(), "{name} must set the ENCRYPTED flag");
            assert_ne!(payload, plaintext);
            if name != "xor" {
                // AEAD packets grow by the 28-byte StandardAeadTail
                // (packet/mod.rs:331-346); xor only toggles the flag.
                assert_eq!(payload.len(), plaintext.len() + AEAD_TAIL_SIZE, "{name}");
            }
            encryptor.decrypt_packet(&mut hdr, &mut payload).unwrap();
            assert_eq!(payload, plaintext, "{name} round trip");
            assert!(!hdr.is_encrypted());
            // Decrypting an unencrypted packet is a pass-through
            // (NullCipher::decrypt / ring.rs:72-75).
            encryptor.decrypt_packet(&mut hdr, &mut payload).unwrap();
            assert_eq!(payload, plaintext);
        }
        // Disabled encryption is the NullCipher: nothing changes, and a
        // peer's ENCRYPTED flag becomes a decryption failure
        // (encrypt/mod.rs:65-78).
        let null = create_encryptor("aes-gcm", false, test_secret().as_str()).unwrap();
        let mut hdr = PeerPacket::new(1, 2, packet_type::DATA, plaintext).hdr;
        let mut payload = plaintext.to_vec();
        null.encrypt_packet(&mut hdr, &mut payload).unwrap();
        assert!(!hdr.is_encrypted() && payload == plaintext);
        hdr.set_encrypted(true);
        assert!(null.decrypt_packet(&mut hdr, &mut payload).is_err());
        // Wrong secret cannot decrypt (the identity the digest guards).
        let other = create_encryptor("aes-gcm", true, "another-secret").unwrap();
        let mut hdr = PeerPacket::new(1, 2, packet_type::DATA, plaintext).hdr;
        let mut payload = plaintext.to_vec();
        other.encrypt_packet(&mut hdr, &mut payload).unwrap();
        let encryptor = create_encryptor("aes-gcm", true, test_secret().as_str()).unwrap();
        assert!(encryptor.decrypt_packet(&mut hdr, &mut payload).is_err());
        // EncryptionAlgorithm alias table (config/encryption.rs:29-41).
        assert_eq!("chacha20-poly1305".parse::<EncryptionAlgorithm>().unwrap(), EncryptionAlgorithm::ChaCha20);
        assert_eq!("openssl-aes-256-gcm".parse::<EncryptionAlgorithm>().unwrap(), EncryptionAlgorithm::Aes256Gcm);
        assert!("nope".parse::<EncryptionAlgorithm>().is_err());
        assert_eq!(EncryptionAlgorithm::default().as_str(), "aes-gcm");
    }

    #[test]
    fn key_derivation_is_the_upstream_shape() {
        // derive_key_128/256 (tunnel/encrypt/mod.rs:62-84): std
        // DefaultHasher over the secret, shards fed back between rounds.
        let k128 = derive_key_128("secret-one");
        let k256 = derive_key_256("secret-one");
        assert_eq!(k128, derive_key_128("secret-one"));
        assert_ne!(k128, derive_key_128("secret-two"));
        assert_ne!(k256, derive_key_256("secret-two"));
        assert_ne!(&k128[..], &k256[..16]);
        // The digest (config/mod.rs:207-218) is deterministic and covers
        // both name and secret.
        let d1 = network_secret_digest("net", "secret");
        assert_eq!(d1, network_secret_digest("net", "secret"));
        assert_ne!(d1, network_secret_digest("net", "other"));
        assert_ne!(d1, network_secret_digest("other-net", "secret"));
        assert!(!digest_is_empty(&d1));
        assert!(digest_is_empty(&[0u8; 32]));
    }

    // ------------------------------------------------------- peer URI

    #[test]
    fn parse_peer_endpoint_forms() {
        assert_eq!(
            parse_peer_endpoint("tcp://192.0.2.10:11010").unwrap(),
            PeerEndpoint { transport: PeerTransport::Tcp, host: "192.0.2.10".into(), port: 11010 }
        );
        // protocol_default_port("tcp") = 11010
        // (connectivity/protocol/mod.rs:55-64).
        assert_eq!(
            parse_peer_endpoint("tcp://node.example.com").unwrap(),
            PeerEndpoint {
                transport: PeerTransport::Tcp,
                host: "node.example.com".into(),
                port: DEFAULT_PEER_PORT
            }
        );
        assert_eq!(
            parse_peer_endpoint("tcp://[2001:db8::1]:11011").unwrap(),
            PeerEndpoint {
                transport: PeerTransport::Tcp,
                host: "2001:db8::1".into(),
                port: 11011
            }
        );
        assert_eq!(
            parse_peer_endpoint("udp://192.0.2.10:11010").unwrap(),
            PeerEndpoint {
                transport: PeerTransport::Udp,
                host: "192.0.2.10".into(),
                port: 11010
            }
        );
        // A path component is ignored (host[:port] is what remains).
        assert_eq!(
            parse_peer_endpoint("tcp://example.com:11010/some/path").unwrap(),
            PeerEndpoint {
                transport: PeerTransport::Tcp,
                host: "example.com".into(),
                port: 11010
            }
        );
        // `IpScheme::default_port` (tunnel/mod.rs:334-342): quic 11012
        // (offset 2), ws 80 / wss 443 (the well-known ports).
        assert_eq!(
            parse_peer_endpoint("quic://192.0.2.10").unwrap(),
            PeerEndpoint {
                transport: PeerTransport::Quic,
                host: "192.0.2.10".into(),
                port: 11012
            }
        );
        assert_eq!(
            parse_peer_endpoint("quic://[2001:db8::2]:11020").unwrap(),
            PeerEndpoint {
                transport: PeerTransport::Quic,
                host: "2001:db8::2".into(),
                port: 11020
            }
        );
        assert_eq!(
            parse_peer_endpoint("ws://node.example.com").unwrap(),
            PeerEndpoint {
                transport: PeerTransport::Ws,
                host: "node.example.com".into(),
                port: 80
            }
        );
        assert_eq!(
            parse_peer_endpoint("wss://192.0.2.10").unwrap(),
            PeerEndpoint {
                transport: PeerTransport::Wss,
                host: "192.0.2.10".into(),
                port: 443
            }
        );
        assert_eq!(
            parse_peer_endpoint("ws://192.0.2.10:11011/some/path").unwrap(),
            PeerEndpoint {
                transport: PeerTransport::Ws,
                host: "192.0.2.10".into(),
                port: 11011
            }
        );
        // wg:// parses with its own default port (11010 + offset 1).
        assert_eq!(
            parse_peer_endpoint("wg://192.0.2.10").unwrap(),
            PeerEndpoint {
                transport: PeerTransport::Wg,
                host: "192.0.2.10".into(),
                port: 11011
            }
        );
        let err = parse_peer_endpoint("faketcp://192.0.2.10").unwrap_err().to_string();
        assert!(err.contains("faketcp"), "{err}");
        assert!(parse_peer_endpoint("tcp://:11010").is_err());
        assert!(parse_peer_endpoint("tcp://host:notaport").is_err());
        assert!(parse_peer_endpoint("tcp://[::1:11010").is_err());
    }

    // ------------------------------------------------- the handshake pair

    #[tokio::test]
    async fn handshake_pair_over_duplex() {
        // do_handshake_as_client (peer_conn.rs:1246-1264) against
        // do_handshake_as_server_ext (peer_conn.rs:1186-1243), both in
        // plain mode, over an in-memory stream.
        let secret = test_secret();
        let digest = network_secret_digest("mesh", &secret);
        let (client_io, server_io) = tokio::io::duplex(4096);
        let mut client_io = client_io;
        let mut server_io = server_io;
        let server = tokio::spawn(async move {
            handshake_as_server(&mut server_io, 0xdead_beef, "mesh", &digest, None).await
        });
        let client_peer =
            handshake_as_client(&mut client_io, 0x0000_0042, "mesh", &digest).await.unwrap();
        let (server_peer, secure) = server.await.unwrap().unwrap();
        assert!(secure.is_none());
        // Each side sees the other's id and the shared identity.
        assert_eq!(client_peer.peer_id, 0xdead_beef);
        assert_eq!(server_peer.peer_id, 0x0000_0042);
        assert_eq!(client_peer.network_name, "mesh");
        assert_eq!(server_peer.network_secret_digest, digest);
        assert!(client_peer.features.iter().any(|f| f == LIVENESS_ECHO_FEATURE));
        assert_eq!(client_peer.version, HANDSHAKE_VERSION);
        // A peer answering with OUR peer id is a self-connection
        // (peer_conn.rs:1238-1242, 1269-1275).
        let (mut client_io, mut server_io) = tokio::io::duplex(4096);
        let echo_conflict = tokio::spawn(async move {
            let _packet = read_frame(&mut server_io).await.unwrap().unwrap();
            let reply = build_handshake(0x42, "mesh", Some(&digest));
            write_frame(&mut server_io, &reply).await.unwrap();
        });
        let err = handshake_as_client(&mut client_io, 0x42, "mesh", &digest)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("peer id conflict"), "{err}");
        echo_conflict.await.unwrap();
        // The server-side twin check rejects the client instead of
        // answering (peer_conn.rs:1238-1242): the client then sees the
        // connection close.
        let (mut client_io, mut server_io) = tokio::io::duplex(4096);
        let server = tokio::spawn(async move {
            handshake_as_server(&mut server_io, 0x42, "mesh", &digest, None).await
        });
        let err = handshake_as_client(&mut client_io, 0x42, "mesh", &digest)
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("peer id conflict") || err.contains("conn closed"),
            "{err}"
        );
        let server_err = server.await.unwrap().unwrap_err().to_string();
        assert!(server_err.contains("peer id conflict"), "{server_err}");
    }

    // ----------------------------------------------- the in-test mesh peer

    /// The full in-test EasyTier peer node, transcribed from the server
    /// path of the same upstream sources `serve_peer` ports: the plain
    /// handshake responder + the shared post-handshake machinery + an IP
    /// frame echo. Fresh fake secrets per run; loopback only.
    struct MimicPeer {
        addr: std::net::SocketAddr,
        seen: mpsc::Receiver<(String, NetworkSecretDigest)>,
        error: mpsc::Receiver<String>,
    }

    async fn spawn_mimic_peer(network_name: &str, secret: &str, encrypt: bool) -> MimicPeer {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (seen_tx, seen) = mpsc::channel(4);
        let (err_tx, error) = mpsc::channel(4);
        let network_name = network_name.to_owned();
        let secret = secret.to_owned();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { break };
                let seen_tx = seen_tx.clone();
                let err_tx = err_tx.clone();
                let network_name = network_name.clone();
                let secret = secret.clone();
                tokio::spawn(async move {
                    let encryptor = create_encryptor("aes-gcm", encrypt, &secret).unwrap();
                    match serve_peer(stream, &network_name, &secret, encryptor).await {
                        Ok((node, peer_info)) => {
                            let _ = seen_tx
                                .send((peer_info.network_name.clone(), peer_info.network_secret_digest))
                                .await;
                            // Echo every IP frame back (the data-plane
                            // round trip).
                            while let Some(frame) = node.recv_ip_frame().await {
                                if node.send_ip_frame(&frame).await.is_err() {
                                    break;
                                }
                            }
                        }
                        Err(e) => {
                            let _ = err_tx.send(e.to_string()).await;
                        }
                    }
                });
            }
        });
        MimicPeer { addr, seen, error }
    }

    fn e2e_config(addr: &std::net::SocketAddr, name: &str, secret: &str) -> EasyTierConfig {
        EasyTierConfig {
            peers: vec![format!("tcp://{addr}")],
            network_secret: secret.to_owned(),
            ..EasyTierConfig::new("et-e2e", name)
        }
    }

    #[tokio::test]
    async fn connect_handshake_ping_and_encrypted_data_round_trip() {
        // The milestone proof: dial, join the mesh (handshake + identity
        // check), keepalive ping/pong, and IP frames both ways with the
        // core-default encryption (enable_encryption defaults true).
        let secret = format!("et-{}", rand::random::<u64>());
        let mut mimic = spawn_mimic_peer("et-e2e-net", &secret, true).await;
        let node = connect(&e2e_config(&mimic.addr, "et-e2e-net", &secret))
            .await
            .unwrap();
        assert_eq!(node.network_name(), "et-e2e-net");
        assert_ne!(node.peer_id(), node.my_peer_id());
        // The peer saw exactly our handshake identity.
        let (seen_name, seen_digest) = mimic.seen.recv().await.unwrap();
        assert_eq!(seen_name, "et-e2e-net");
        assert_eq!(seen_digest, network_secret_digest("et-e2e-net", &secret));
        // Explicit ping measures a real round trip.
        let latency = node.ping().await.unwrap();
        assert!(node.latency_us() > 0);
        assert!(!latency.is_zero());
        // IP frames flow both ways (echo) under encryption.
        let frame: Vec<u8> = (0..64).map(|i| i as u8).collect();
        node.send_ip_frame(&frame).await.unwrap();
        let echoed = node.recv_ip_frame().await.unwrap();
        assert_eq!(echoed, frame);
        // The background keepalive (both directions) keeps the mesh up.
        tokio::time::sleep(Duration::from_millis(2300)).await;
        assert!(!node.is_closed());
        node.close().await;
    }

    #[tokio::test]
    async fn connect_without_encryption_carries_plaintext_data() {
        // enable_encryption: false is the NullCipher — same handshake,
        // unencrypted Data packets.
        let secret = format!("et-{}", rand::random::<u64>());
        let mimic = spawn_mimic_peer("plain-net", &secret, false).await;
        let cfg = EasyTierConfig {
            enable_encryption: Some(false),
            ..e2e_config(&mimic.addr, "plain-net", &secret)
        };
        let node = connect(&cfg).await.unwrap();
        node.send_ip_frame(b"plaintext overlay frame").await.unwrap();
        let echoed = node.recv_ip_frame().await.unwrap();
        assert_eq!(echoed, b"plaintext overlay frame");
        node.close().await;
    }

    #[tokio::test]
    async fn wrong_network_name_fails_the_dial() {
        // add_new_peer_conn (peer_manager.rs:395-412): a name mismatch
        // is rejected by the client immediately.
        let secret = format!("et-{}", rand::random::<u64>());
        let mimic = spawn_mimic_peer("other-net", &secret, true).await;
        let err = connect(&e2e_config(&mimic.addr, "my-net", &secret))
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("network identity not match"), "{err}");
    }

    #[tokio::test]
    async fn wrong_secret_is_rejected_by_the_peer() {
        // Same name, different secret: the client's digest is real, the
        // peer answers with zeros (send_digest logic, peer_conn.rs:
        // 1225-1227), so the client passes the name check — and the
        // PEER rejects us (its add_new_peer_conn) and closes; the
        // post-handshake liveness ping turns that into a dial failure.
        let secret = format!("et-{}", rand::random::<u64>());
        let mut mimic = spawn_mimic_peer("net", &secret, true).await;
        let err = connect(&e2e_config(&mimic.addr, "net", "wrong-secret"))
            .await
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("timeout") || err.contains("closed"),
            "expected liveness failure, got: {err}"
        );
        let peer_err = tokio::time::timeout(Duration::from_secs(3), mimic.error.recv())
            .await
            .unwrap()
            .unwrap();
        assert!(peer_err.contains("network identity not match"), "{peer_err}");
    }

    #[tokio::test]
    async fn hand_rolled_mimic_validates_client_handshake_bytes() {
        // An independent mimic (no serve_peer): reads the client's first
        // frame straight off the socket, decodes the wire bytes itself,
        // and answers — proving what we put on the wire against a
        // transcription of the upstream expectations.
        let secret = format!("et-{}", rand::random::<u64>());
        let network = "hand-rolled-net";
        let digest = network_secret_digest(network, &secret);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let checker = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let packet = read_frame(&mut stream).await.unwrap().unwrap();
            // The frame is a HandShake packet from a non-zero peer id to
            // peer id 0 (fill_peer_manager_hdr semantics).
            assert_eq!(packet.hdr.packet_type, packet_type::HANDSHAKE);
            assert_eq!(packet.hdr.to_peer_id, 0);
            assert!(packet.hdr.from_peer_id != 0);
            assert_eq!(packet.hdr.forward_counter, 1);
            assert_eq!(packet.hdr.len as usize, packet.payload.len());
            let req = HandshakeRequest::decode(&packet.payload).unwrap();
            assert_eq!(req.magic, 0xd1e1a5e1); // peer_conn.rs:65
            assert_eq!(req.version, 1); // peer_conn.rs:66
            assert_eq!(req.network_name, network);
            assert_eq!(req.network_secret_digest, digest);
            assert_eq!(req.features, vec!["liveness-echo-v1".to_owned()]); // liveness.rs:10
            // Answer with our own handshake (server sends its digest
            // only on identity match — here it matches).
            let reply = build_handshake(0xfeed_face, network, Some(&digest));
            write_frame(&mut stream, &reply).await.unwrap();
            // Echo pings as pongs (peer_conn.rs:1334-1341).
            while let Some(p) = read_frame(&mut stream).await.unwrap() {
                if p.hdr.packet_type != packet_type::PING {
                    continue;
                }
                let mut pong = p;
                pong.hdr.packet_type = packet_type::PONG;
                write_frame(&mut stream, &pong).await.unwrap();
            }
        });
        let endpoint = parse_peer_endpoint(&format!("tcp://{addr}")).unwrap();
        let encryptor = create_encryptor("aes-gcm", true, &secret).unwrap();
        let node = connect_peer(&endpoint, network, &secret, encryptor)
            .await
            .unwrap();
        assert_eq!(node.peer_id(), 0xfeed_face);
        assert!(node.ping().await.is_ok());
        node.close().await;
        checker.await.unwrap();
    }

    // -------------------------------------------- ping interval controller

    #[test]
    fn ping_backoff_controller_matches_upstream_toggles() {
        // PingIntervalController::should_send_ping (peer_conn_ping.rs:
        // 94-125): losses and one-way traffic pin the backoff at zero
        // (a ping every tick); idle time grows the gap exponentially.
        let (sink, _rx) = mpsc::channel(8);
        let state = ConnState {
            my_peer_id: 1,
            peer_id: 2,
            encryptor: create_encryptor("aes-gcm", true, "s").unwrap(),
            secure: None,
            sink,
            pong_tx: broadcast::channel(8).0,
            data_tx: mpsc::channel(8).0,
            ctrl_tx: mpsc::channel(8).0,
            latency_us: AtomicU64::new(0),
            tx_packets: AtomicU64::new(0),
            rx_packets: AtomicU64::new(0),
            closed: Notify::new(),
            close_flag: AtomicU32::new(0),
        };
        let mut controller = PingIntervalController::new();
        // Loss path: a ping every tick.
        controller.logic_time += 1;
        assert!(controller.should_send_ping(&state, 1));
        controller.logic_time += 1;
        assert!(controller.should_send_ping(&state, 1));
        // Idle path: t=1 sent, then backoff grows (2, 4, 8… ticks).
        let mut controller = PingIntervalController::new();
        controller.logic_time = 1;
        assert!(controller.should_send_ping(&state, 0)); // backoff -> 1
        controller.logic_time = 2;
        assert!(!controller.should_send_ping(&state, 0)); // 2-1 < 2
        controller.logic_time = 3;
        assert!(controller.should_send_ping(&state, 0)); // 3-1 >= 2, backoff -> 2
        controller.logic_time = 4;
        assert!(!controller.should_send_ping(&state, 0)); // 4-3 < 4
        controller.logic_time = 6;
        assert!(!controller.should_send_ping(&state, 0)); // 6-3 < 4
    }

    #[tokio::test]
    async fn five_lost_pings_close_the_connection() {
        // peer_conn_ping.rs:309-317: the peer stops answering; the
        // keepalive tears the connection down after 5 consecutive
        // losses.
        let secret = format!("et-{}", rand::random::<u64>());
        let network = "silent-net";
        let digest = network_secret_digest(network, &secret);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            // Handshake, then keep the socket open while swallowing
            // every ping without answering (the connection stays alive;
            // only the keepalive can tear it down).
            let (peer, secure) =
                handshake_as_server(&mut stream, 0xaa, network, &digest, None)
                    .await
                    .unwrap();
            assert!(secure.is_none());
            drop(peer);
            while matches!(read_frame(&mut stream).await, Ok(Some(_))) {}
        });
        // connect_peer's explicit ping would fail immediately here, so
        // drive the pieces: handshake + spawn, then let the keepalive
        // run against the silent peer.
        let my_peer_id = random_peer_id();
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let peer_info = handshake_as_client(&mut stream, my_peer_id, network, &digest)
            .await
            .unwrap();
        let node = spawn_connection_halves(
            stream,
            my_peer_id,
            &peer_info,
            create_encryptor("aes-gcm", true, &secret).unwrap(),
            None,
        )
        .await
        .into_node(peer_info.network_name.clone());
        // The keepalive pings at t=1s (backoff 0 grows each success), a
        // missed pong costs 2s; five losses close well under 15s.
        tokio::time::timeout(Duration::from_secs(15), node.wait_closed())
            .await
            .expect("connection should close after 5 lost pings");
        assert!(node.is_closed());
    }

    // ========================================================================
    // M2: the peer RPC framework + route gossip + the smoltcp overlay
    // ========================================================================

    use std::net::SocketAddrV4;

    // ------------------------------------------------- wire codecs (golden)

    #[test]
    fn rpc_packet_golden_bytes() {
        // RpcPacket field numbers: from_peer=1, to_peer=2,
        // transaction_id=3, descriptor=4, body=5, is_request=6,
        // total_pieces=7, piece_idx=8, trace_id=9, compression_info=10
        // (common.proto:149-163); RpcDescriptor 1..4 (93-101).
        let desc = RpcDescriptor {
            domain_name: "mesh".into(),
            proto_name: "OspfRouteRpc".into(),
            service_name: "OspfRouteRpc".into(),
            method_index: 1,
        };
        let packet = RpcPacket {
            from_peer: 0x1111,
            to_peer: 0x2222,
            transaction_id: 300,
            descriptor: Some(desc.clone()),
            body: b"req-body".to_vec(),
            is_request: true,
            compression_algo: Some(COMPRESSION_ALGO_NONE),
            compression_accepted: Some(COMPRESSION_ALGO_NONE),
            ..Default::default()
        };
        let bytes = packet.encode();
        assert_eq!(RpcPacket::decode(&bytes).unwrap(), packet);
        // from_peer = 0x1111 = 4369 → varint 0x91 0x22 (field tag 0x08).
        assert_eq!(&bytes[..3], &[0x08, 0x91, 0x22]);
        // method_index = 1 is the codegen's `(i + 1)` ordinal.
        let decoded = RpcPacket::decode(&bytes).unwrap();
        let decoded_desc = decoded.descriptor.clone().unwrap();
        assert_eq!(decoded_desc.method_index, rpc_method::OSPF_SYNC_ROUTE_INFO);
        assert_eq!(decoded_desc, desc);
        // Negative transaction ids encode as 10-byte varints (int64).
        let packet = RpcPacket {
            transaction_id: -1,
            ..RpcPacket::default()
        };
        let bytes = packet.encode();
        // int64 -1 → the 10-byte two's-complement varint (9×0xff, 0x01).
        let mut expected = vec![0x18u8];
        expected.extend([0xffu8; 9]);
        expected.push(0x01);
        assert_eq!(bytes, expected);
        assert_eq!(RpcPacket::decode(&bytes).unwrap().transaction_id, -1);
        // The descriptor the route gossip must carry to interop.
        let ospf = ospf_route_descriptor("mymesh");
        assert_eq!(ospf.domain_name, "mymesh");
        assert_eq!(ospf.proto_name, "OspfRouteRpc");
        assert_eq!(ospf.service_name, "OspfRouteRpc");
        assert_eq!(ospf.method_index, 1);
    }

    #[test]
    fn sync_route_wire_golden_bytes() {
        // SyncRouteInfoRequest fields: my_peer_id=1, my_session_id=2,
        // is_initiator=3, peer_infos=4 (repeated RoutePeerInfo at 1),
        // conn_bitmap=5 (peer_ids=1, bitmap=2) — peer_rpc.proto:111-121.
        let us: Ipv4Addr = "10.144.0.2".parse().unwrap();
        let them: Ipv4Addr = "10.144.0.1".parse().unwrap();
        let gossip = RouteGossip::new(
            "mesh",
            0x1111,
            0x2222,
            "node-b",
            Some(us),
            32,
            false,
            vec![],
            true,
        );
        let req = gossip.build_request();
        let bytes = req.encode();
        assert_eq!(SyncRouteInfoRequest::decode(&bytes).unwrap(), req);
        // The first field on the wire is my_peer_id (field 1, varint).
        assert_eq!(bytes[0], 0x08);
        assert!(req.is_initiator);
        assert_eq!(req.my_session_id, gossip.my_session_id);
        // The RoutePeerInfo inside carries our address in the
        // u32::from_be_bytes form of common.Ipv4Addr.
        let info = &req.peer_infos[0];
        assert_eq!(info.ipv4().unwrap(), us);
        assert_eq!(info.ipv4_addr.unwrap(), u32::from(us));
        assert_eq!(info.version, 1);
        assert_eq!(info.peer_id, 0x1111);
        // The adjacency is symmetric for both orderings of peer ids.
        let bm = req.conn_bitmap.as_ref().unwrap();
        assert_eq!(bm.connected_peers(0x1111).unwrap(), vec![0x2222]);
        assert_eq!(bm.connected_peers(0x2222).unwrap(), vec![0x1111]);
        let _ = them;
        // The response round-trips with the session fields the client
        // records (peer_rpc.proto:128-135).
        let resp = SyncRouteInfoResponse {
            is_initiator: false,
            session_id: 0xfeed_beef_cafe,
            error: None,
            missing_peer_ids: vec![7, 9],
        };
        let bytes = resp.encode();
        assert_eq!(SyncRouteInfoResponse::decode(&bytes).unwrap(), resp);
        let err_resp = SyncRouteInfoResponse {
            error: Some(sync_route_error::STOPPED),
            ..Default::default()
        };
        assert_eq!(
            SyncRouteInfoResponse::decode(&err_resp.encode()).unwrap().error,
            Some(1)
        );
    }

    #[test]
    fn packet_merger_reassembles_and_validates() {
        // PacketMerger (rpc/packet.rs:57-150): single-piece fast path,
        // ordered and out-of-order reassembly, the malformed guards.
        let mut merger = PacketMerger::new();
        let whole = RpcPacket {
            transaction_id: 5,
            body: b"whole".to_vec(),
            ..Default::default()
        };
        assert!(merger.feed(whole.clone()).unwrap().unwrap() == whole);
        let make = |idx: u32, total: u32, body: &[u8]| RpcPacket {
            transaction_id: 9,
            total_pieces: total,
            piece_idx: idx,
            descriptor: (idx == 0).then(|| RpcDescriptor {
                service_name: "OspfRouteRpc".into(),
                ..Default::default()
            }),
            body: body.to_vec(),
            ..Default::default()
        };
        let mut merger = PacketMerger::new();
        assert!(merger.feed(make(1, 2, b"tail")).unwrap().is_none());
        let merged = merger.feed(make(0, 2, b"head")).unwrap().unwrap();
        assert_eq!(merged.body, b"headtail");
        assert_eq!(merged.total_pieces, 1);
        assert_eq!(merged.piece_idx, 0);
        // Guards: piece 0 without a descriptor, bad totals, idx range.
        let mut merger = PacketMerger::new();
        let no_desc = RpcPacket {
            transaction_id: 1,
            total_pieces: 2,
            piece_idx: 0,
            ..Default::default()
        };
        assert!(merger.feed(no_desc).is_err());
        assert!(merger
            .feed(RpcPacket {
                transaction_id: 1,
                total_pieces: 0,
                piece_idx: 3,
                ..Default::default()
            })
            .is_err());
        assert!(merger
            .feed(RpcPacket {
                transaction_id: 1,
                total_pieces: 2,
                piece_idx: 2,
                ..Default::default()
            })
            .is_err());
    }

    #[test]
    fn conn_bitmap_two_node_adjacency() {
        // build: sorted ids, row-major bits (peer_ospf_route.rs:2900-2967).
        let bm = RouteConnBitmap::two_node(9, 3);
        assert_eq!(bm.peer_ids[0].peer_id, 3);
        assert_eq!(bm.peer_ids[1].peer_id, 9);
        assert_eq!(bm.connected_peers(3).unwrap(), vec![9]);
        assert_eq!(bm.connected_peers(9).unwrap(), vec![3]);
        // The encoding round-trips (peer_ids=1, bitmap=2).
        let bytes = bm.encode();
        assert_eq!(RouteConnBitmap::decode(&bytes).unwrap(), bm);
        // A self-bit is never set (the conn map excludes self).
        let bm2 = RouteConnBitmap::two_node(9, 9);
        assert!(bm2.connected_peers(9).unwrap().is_empty());
    }

    #[test]
    fn dhcp_allocator_first_fit_free_address() {
        // DhcpIpv4Allocator::evaluate (gateway/dhcp.rs:51-78): first
        // free host, skipping network + broadcast + used.
        let used = ["10.126.126.1".parse::<Ipv4Addr>().unwrap()];
        let picked = allocate_overlay_ipv4(&used, "10.126.126.1".parse().unwrap(), 24).unwrap();
        assert_eq!(picked.to_string(), "10.126.126.2");
        let used: Vec<Ipv4Addr> = ["10.126.126.1", "10.126.126.2"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let picked = allocate_overlay_ipv4(&used, "10.126.126.1".parse().unwrap(), 24).unwrap();
        assert_eq!(picked.to_string(), "10.126.126.3");
        // A full /30 (network .0, hosts .1/.2, broadcast .3) has nothing
        // free once both hosts are used.
        let used: Vec<Ipv4Addr> = vec!["10.0.0.1".parse().unwrap(), "10.0.0.2".parse().unwrap()];
        assert!(allocate_overlay_ipv4(&used, "10.0.0.1".parse().unwrap(), 30).is_none());
        // /32 and /31 never allocate (no host range).
        assert!(allocate_overlay_ipv4(&[], "10.0.0.1".parse().unwrap(), 32).is_none());
    }

    #[test]
    fn route_gossip_session_and_lsdb_rules() {
        // admit_inbound_locked (peer_ospf_route.rs:2233-2254) and the
        // strictly-greater-version LSDB merge (1364-1400), as units.
        let mut client = RouteGossip::new(
            "mesh",
            1,
            2,
            "a",
            Some("10.0.0.1".parse().unwrap()),
            24,
            false,
            vec![],
            true,
        );
        assert!(client.we_are_initiator);
        // The responder's acceptance is permissive (the v2.6.x released
        // behaviour): every request updates the session bookkeeping.
        assert!(client.admit_inbound(0xaaa, false));
        assert_eq!(client.dst_session_id, 0xaaa);
        assert!(!client.dst_is_initiator);
        assert!(client.admit_inbound(0xbbb, true));
        assert_eq!(client.dst_session_id, 0xbbb);
        assert!(client.dst_is_initiator);
        assert!(client.admit_inbound(0xbbb, false));
        assert!(!client.dst_is_initiator);

        // The LSDB merge keeps strictly greater versions.
        let mut server = RouteGossip::new(
            "mesh",
            2,
            1,
            "b",
            Some("10.0.0.2".parse().unwrap()),
            24,
            false,
            vec![],
            false,
        );
        let req = client.build_request();
        server.merge_sync_request(&req.peer_infos, req.conn_bitmap.as_ref());
        assert_eq!(
            server.peer_route(1).unwrap().ipv4().unwrap(),
            "10.0.0.1".parse::<Ipv4Addr>().unwrap()
        );
        // An equal-version re-announcement changes nothing.
        let before = server.peer_route(1).unwrap().clone();
        server.merge_sync_request(&req.peer_infos, None);
        assert_eq!(server.peer_route(1).unwrap(), &before);
        // A higher version replaces.
        let mut newer = req.peer_infos[0].clone();
        newer.version += 1;
        newer.ipv4_addr = Some(u32::from("10.0.0.9".parse::<Ipv4Addr>().unwrap()));
        server.merge_sync_request(&[newer], None);
        assert_eq!(
            server.peer_route(1).unwrap().ipv4().unwrap(),
            "10.0.0.9".parse::<Ipv4Addr>().unwrap()
        );
        // The response of a responder: our initiator flag is false, our
        // session id non-zero (do_sync_route_info's tail, 3611-3618).
        let resp = server.handle_sync_request(&req);
        assert!(!resp.is_initiator);
        assert_eq!(resp.session_id, server.my_session_id);
        assert!(resp.error.is_none());
        // apply_response: readiness needs one successful sync + address.
        assert!(!client.is_ready());
        client.apply_response(&SyncRouteInfoResponse {
            is_initiator: false,
            session_id: 0xaaa,
            ..Default::default()
        });
        assert!(client.is_ready());
        assert_eq!(client.successful_syncs, 1);
        assert!(!client.sync_due());
        // The dhcp allocation picks from the learned subnet.
        let mut dhcp_node = RouteGossip::new("mesh", 3, 2, "c", None, 24, true, vec![], true);
        assert!(!dhcp_node.is_ready());
        assert!(!dhcp_node.allocate_dhcp_ipv4()); // no routes yet
        let peer_info = RoutePeerInfo {
            peer_id: 2,
            ipv4_addr: Some(u32::from("10.126.126.1".parse::<Ipv4Addr>().unwrap())),
            network_length: 24,
            version: 1,
            ..Default::default()
        };
        dhcp_node.merge_sync_request(&[peer_info], None);
        assert!(dhcp_node.allocate_dhcp_ipv4());
        assert_eq!(
            dhcp_node.my_ipv4().unwrap().to_string(),
            "10.126.126.2"
        );
        // Allocation is once; the announced version bumped.
        assert!(!dhcp_node.allocate_dhcp_ipv4());
        assert_eq!(dhcp_node.my_peer_info().version, 2);
        assert_eq!(dhcp_node.my_peer_info().network_length, 24);
        // The MagicDNS table includes ourselves and the learned peer.
        let nodes = dhcp_node.overlay_nodes();
        assert!(nodes.iter().any(|n| n.ipv4 == "10.126.126.1".parse::<Ipv4Addr>().unwrap()));
        assert!(nodes.iter().any(|n| n.ipv4 == "10.126.126.2".parse::<Ipv4Addr>().unwrap()));
    }

    // ------------------------------------------------- the in-test mesh

    /// The learned-route snapshot the mimic publishes (its LSDB's
    /// peer_id → announced ipv4).
    type LearnedRoutes = Arc<StdMutex<HashMap<PeerId, Option<Ipv4Addr>>>>;

    /// The full in-test EasyTier peer: the M1 `serve_peer` handshake
    /// responder wrapped in the same `EtStack` this module ships — it
    /// answers route syncs with the server half, reverse-syncs with the
    /// client half, and echoes TCP/UDP on its overlay address. Every
    /// credential is generated per run; loopback only.
    struct MimicMesh {
        underlay: std::net::SocketAddr,
        overlay_ip: Ipv4Addr,
        learned: LearnedRoutes,
        accepted: Arc<AtomicU32>,
        /// Underlay peer connections accepted (one per registry entry on
        /// the dialing side — the reuse proof).
        underlay_conns: Arc<AtomicU32>,
        echo_tcp_port: u16,
        echo_udp_port: u16,
    }

    impl MimicMesh {
        async fn spawn(network: &str, secret: &str, overlay_ip: &str, prefix: u32) -> Self {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let underlay = listener.local_addr().unwrap();
            let overlay_ip: Ipv4Addr = overlay_ip.parse().unwrap();
            let learned: LearnedRoutes = Arc::new(StdMutex::new(HashMap::new()));
            let accepted = Arc::new(AtomicU32::new(0));
            let underlay_conns = Arc::new(AtomicU32::new(0));
            let network = network.to_owned();
            let secret = secret.to_owned();
            let learned_task = learned.clone();
            let accepted_task = accepted.clone();
            let underlay_task = underlay_conns.clone();
            tokio::spawn(async move {
                loop {
                    let Ok((stream, _)) = listener.accept().await else { break };
                    let network = network.clone();
                    let secret = secret.clone();
                    let learned = learned_task.clone();
                    let accepted = accepted_task.clone();
                    underlay_task.fetch_add(1, Ordering::Relaxed);
                    tokio::spawn(async move {
                        let encryptor = create_encryptor("aes-gcm", true, &secret).unwrap();
                        let Ok((halves, _peer_info)) =
                            serve_peer_as(stream, random_peer_id(), &network, &secret, encryptor, None)
                                .await
                        else {
                            return;
                        };
                        // The responder side of the gossip: static
                        // address, never the initiator.
                        let mut stack = EtStack::new(
                            halves.state.my_peer_id,
                            &network,
                            "mimic",
                            DEFAULT_MTU,
                            Some(overlay_ip),
                            prefix,
                            false,
                            vec![],
                        );
                        let (events_tx, events_rx) = mpsc::channel::<PeerEvent>(64);
                        stack.attach_session(halves, false, &events_tx);
                        run_mimic(stack, events_rx, learned, accepted, 9041, 9042).await;
                    });
                }
            });
            MimicMesh {
                underlay,
                overlay_ip,
                learned,
                accepted,
                underlay_conns,
                echo_tcp_port: 9041,
                echo_udp_port: 9042,
            }
        }

        fn config(&self, network: &str, secret: &str, ipv4: Option<&str>) -> EasyTierConfig {
            EasyTierConfig {
                peers: vec![format!("tcp://{}", self.underlay)],
                network_secret: secret.to_owned(),
                ipv4: ipv4.map(|s| s.to_owned()),
                dhcp: ipv4.is_none(),
                ..EasyTierConfig::new("et-m2", network)
            }
        }
    }

    /// The mimic's loop: the EtStack drives the gossip over the ctrl
    /// seam while a listening TCP socket and a UDP socket echo traffic
    /// on the mimic's overlay address.
    async fn run_mimic(
        mut stack: EtStack,
        mut events: mpsc::Receiver<PeerEvent>,
        learned: LearnedRoutes,
        accepted: Arc<AtomicU32>,
        echo_tcp_port: u16,
        echo_udp_port: u16,
    ) {
        let mut listener = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; TCP_RX_BYTES]),
            tcp::SocketBuffer::new(vec![0; TCP_TX_BYTES]),
        );
        if listener
            .listen(IpListenEndpoint {
                addr: None,
                port: echo_tcp_port,
            })
            .is_err()
        {
            return;
        }
        let mut listener_handle = stack.sockets.add(listener);
        let mut udp_echo = udp::Socket::new(
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_PACKETS],
                vec![0; UDP_RX_BYTES],
            ),
            udp::PacketBuffer::new(
                vec![udp::PacketMetadata::EMPTY; UDP_PACKETS],
                vec![0; UDP_TX_BYTES],
            ),
        );
        if udp_echo
            .bind(IpListenEndpoint {
                addr: None,
                port: echo_udp_port,
            })
            .is_err()
        {
            return;
        }
        let udp_handle = stack.sockets.add(udp_echo);
        let mut echo_conns: Vec<SocketHandle> = Vec::new();
        let mut pump = vec![0u8; PUMP_CHUNK];
        let mut tick = tokio::time::interval(Duration::from_millis(200));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            stack.step().await;
            stack.gossip_tick().await;
            // Publish the learned routes (the LSDB view the tests
            // assert against).
            {
                let mut out = learned.lock().unwrap();
                out.clear();
                if let Some(session) = stack.peers.first() {
                    for (peer_id, info) in &session.gossip.lsdb {
                        out.insert(*peer_id, info.ipv4());
                    }
                }
            }
            // Accept: an Established listener becomes one echo socket,
            // and a fresh listener takes its place.
            if matches!(
                stack.sockets.get::<tcp::Socket>(listener_handle).state(),
                tcp::State::Established
            ) {
                // The established socket keeps its handle and joins the
                // echo set; a fresh listener takes over the port.
                echo_conns.push(listener_handle);
                accepted.fetch_add(1, Ordering::Relaxed);
                let mut fresh = tcp::Socket::new(
                    tcp::SocketBuffer::new(vec![0; TCP_RX_BYTES]),
                    tcp::SocketBuffer::new(vec![0; TCP_TX_BYTES]),
                );
                let _ = fresh.listen(IpListenEndpoint {
                    addr: None,
                    port: echo_tcp_port,
                });
                listener_handle = stack.sockets.add(fresh);
            }
            // Echo every established connection both ways.
            let mut closed: Vec<SocketHandle> = Vec::new();
            for handle in &echo_conns {
                let sock = stack.sockets.get_mut::<tcp::Socket>(*handle);
                while sock.can_recv() {
                    let n = match sock.recv_slice(&mut pump) {
                        Ok(n) => n,
                        Err(_) => break,
                    };
                    let mut sent = 0;
                    while sent < n {
                        match sock.send_slice(&pump[sent..n]) {
                            Ok(m) => sent += m,
                            Err(_) => break,
                        }
                    }
                }
                if sock.state() == tcp::State::Closed {
                    closed.push(*handle);
                }
            }
            echo_conns.retain(|h| !closed.contains(h));
            for handle in closed {
                stack.sockets.remove(handle);
            }
            // UDP echo: bounce each datagram back to its sender.
            let udp_sock = stack.sockets.get_mut::<udp::Socket>(udp_handle);
            while udp_sock.can_recv() {
                let (n, meta) = match udp_sock.recv_slice(&mut pump) {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let _ = udp_sock.send_slice(&pump[..n], meta);
            }
            enum Event {
                Peer(Option<PeerEvent>),
                Tick,
            }
            let event = tokio::select! {
                biased;
                ev = events.recv() => Event::Peer(ev),
                _ = tick.tick() => Event::Tick,
            };
            match event {
                Event::Peer(Some(PeerEvent::Ctrl(_idx, p))) => stack.on_ctrl(0, p).await,
                Event::Peer(Some(PeerEvent::Data(_idx, f))) => {
                    stack.shim.stage(&f);
                    stack.wake.notify_one();
                }
                Event::Peer(Some(PeerEvent::Closed(_idx))) => break,
                Event::Peer(None) => break,
                Event::Tick => {}
            }
            if stack.peers.first().is_none_or(|s| s.is_closed()) {
                break;
            }
        }
        // Tear the session tasks down like the driver loop does.
        if let Some(session) = stack.peers.first_mut() {
            for task in &session.tasks {
                task.abort();
            }
        }
    }

    async fn wait_for_routes(learned: &LearnedRoutes, peer_id: PeerId) -> Option<Ipv4Addr> {
        for _ in 0..200 {
            let addr = learned.lock().unwrap().get(&peer_id).copied().flatten();
            if addr.is_some() {
                return addr;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        None
    }

    #[tokio::test]
    async fn route_exchange_teaches_the_peer_our_address() {
        // The gossip proof: dial, exchange SyncRouteInfo both ways, and
        // the peer's LSDB holds our announced static overlay address.
        let secret = format!("et-{}", rand::random::<u64>());
        let mimic = MimicMesh::spawn("route-net", &secret, "10.144.0.1", 24).await;
        let cfg = mimic.config("route-net", &secret, Some("10.144.0.2"));
        // connect_tcp drives the full node (registry + gossip + stack);
        // a dial to the mimic's echo port proves the routes work.
        let target = SocketAddr::V4(SocketAddrV4::new(mimic.overlay_ip, mimic.echo_tcp_port));
        let mut stream = connect_tcp(&cfg, &target).await.unwrap();
        stream.write_all(b"route-probe").await.unwrap();
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"route-probe");
        // The peer learned exactly our announced address (our peer id is
        // random; everything it learned is us).
        for _ in 0..100 {
            let learned_snapshot: Vec<Option<Ipv4Addr>> =
                mimic.learned.lock().unwrap().values().copied().collect();
            if !learned_snapshot.is_empty() {
                assert!(
                    learned_snapshot
                        .iter()
                        .all(|v| *v == Some("10.144.0.2".parse::<Ipv4Addr>().unwrap())),
                    "learned {learned_snapshot:?}"
                );
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(
            !mimic.learned.lock().unwrap().is_empty(),
            "peer learned nothing"
        );
    }

    #[tokio::test]
    async fn tcp_relay_through_the_overlay_and_registry_reuse() {
        // THE M2 proof: a TCP connection relayed end-to-end through two
        // smoltcp stacks over the encrypted peer tunnel, with the node
        // registry sharing one peer session across dials.
        let secret = format!("et-{}", rand::random::<u64>());
        let mimic = MimicMesh::spawn("relay-net", &secret, "10.144.0.1", 24).await;
        let cfg = mimic.config("relay-net", &secret, Some("10.144.0.2"));
        let target = SocketAddr::V4(SocketAddrV4::new(mimic.overlay_ip, mimic.echo_tcp_port));
        let mut first = connect_tcp(&cfg, &target).await.unwrap();
        let mut second = connect_tcp(&cfg, &target).await.unwrap();
        // Both streams echo independently.
        first.write_all(b"first-stream").await.unwrap();
        second.write_all(b"second-stream").await.unwrap();
        let mut buf = vec![0u8; 64];
        let n = first.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"first-stream");
        let n = second.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"second-stream");
        // A bigger transfer exercises segmentation through the 1380 MTU.
        let payload: Vec<u8> = (0..20_000u32).map(|i| i as u8).collect();
        first.write_all(&payload).await.unwrap();
        let mut got = Vec::new();
        while got.len() < payload.len() {
            let n = first.read(&mut buf).await.unwrap();
            assert!(n > 0, "echo stream ended early at {}", got.len());
            got.extend_from_slice(&buf[..n]);
        }
        assert_eq!(got, payload);
        drop(first);
        drop(second);
        // The registry proof: both dials shared ONE underlay peer
        // connection while two overlay TCP connections were served.
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert_eq!(
            mimic.underlay_conns.load(Ordering::Relaxed),
            1,
            "registry must reuse the peer session"
        );
        assert_eq!(
            mimic.accepted.load(Ordering::Relaxed),
            2,
            "two overlay TCP connections"
        );
    }

    #[tokio::test]
    async fn udp_session_through_the_overlay() {
        let secret = format!("et-{}", rand::random::<u64>());
        let mimic = MimicMesh::spawn("udp-net", &secret, "10.144.0.1", 24).await;
        let cfg = mimic.config("udp-net", &secret, Some("10.144.0.2"));
        let udp = EasyTierUdp::bind(&cfg).await.unwrap();
        let target = SocketAddr::V4(SocketAddrV4::new(mimic.overlay_ip, mimic.echo_udp_port));
        udp.send(&target, b"udp-over-mesh").await.unwrap();
        let (from, data) = tokio::time::timeout(Duration::from_secs(10), udp.recv())
            .await
            .expect("udp echo timeout")
            .unwrap();
        assert_eq!(data, b"udp-over-mesh");
        assert_eq!(from.ip(), mimic.overlay_ip);
        assert_eq!(from.port(), mimic.echo_udp_port);
    }

    #[tokio::test]
    async fn dhcp_allocates_from_the_peer_subnet_and_routes() {
        // dhcp: true (the default without ipv4) — the node announces
        // nothing first, learns the peer's subnet from the reverse sync,
        // allocates the first free address exactly like
        // DhcpIpv4Allocator::evaluate, re-announces, and then dials.
        let secret = format!("et-{}", rand::random::<u64>());
        let mimic = MimicMesh::spawn("dhcp-net", &secret, "10.126.126.1", 24).await;
        let cfg = mimic.config("dhcp-net", &secret, None);
        let target = SocketAddr::V4(SocketAddrV4::new(mimic.overlay_ip, mimic.echo_tcp_port));
        let mut stream = tokio::time::timeout(Duration::from_secs(20), connect_tcp(&cfg, &target))
            .await
            .expect("dhcp-assisted dial timed out")
            .unwrap();
        stream.write_all(b"dhcp-probe").await.unwrap();
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"dhcp-probe");
        // The peer saw the allocated address in our re-announcement (the
        // second sync fires as soon as the allocation lands).
        let mut saw_allocation = false;
        for _ in 0..200 {
            let learned_snapshot: Vec<Option<Ipv4Addr>> =
                mimic.learned.lock().unwrap().values().copied().collect();
            if learned_snapshot
                .iter()
                .any(|v| *v == Some("10.126.126.2".parse::<Ipv4Addr>().unwrap()))
            {
                saw_allocation = true;
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
        assert!(saw_allocation, "no allocation learned");
    }

    #[tokio::test]
    async fn wrong_route_dial_is_rejected() {
        // An overlay address nobody owns: the mimic's stack drops the
        // frame (no local address matches), so the TCP dial times out
        // instead of connecting — the route table's rejection.
        let secret = format!("et-{}", rand::random::<u64>());
        let mimic = MimicMesh::spawn("wrong-net", &secret, "10.144.0.1", 24).await;
        let cfg = mimic.config("wrong-net", &secret, Some("10.144.0.2"));
        let ghost = SocketAddr::V4(SocketAddrV4::new(
            "10.144.0.99".parse::<Ipv4Addr>().unwrap(),
            mimic.echo_tcp_port,
        ));
        let err = match connect_tcp(&cfg, &ghost).await {
            Err(e) => e.to_string(),
            Ok(_) => panic!("a dial to an unowned overlay address must not connect"),
        };
        assert!(err.contains("timed out") || err.contains("failed"), "{err}");
    }

    #[tokio::test]
    async fn hand_rolled_wire_validates_the_gossip_request() {
        // An independent transcription (nothing from this module's
        // codecs on the checking side): the test hand-builds the exact
        // proto3 bytes of a SyncRouteInfo RPC, sends it through the
        // real node seam, and hand-parses the response the server sends.
        fn hv(out: &mut Vec<u8>, mut value: u64) {
            loop {
                let byte = (value & 0x7f) as u8;
                value >>= 7;
                if value == 0 {
                    out.push(byte);
                    return;
                }
                out.push(byte | 0x80);
            }
        }
        fn hfield_varint(out: &mut Vec<u8>, field: u32, value: u64) {
            hv(out, (field << 3) as u64);
            hv(out, value);
        }
        fn hfield_len(out: &mut Vec<u8>, field: u32, body: &[u8]) {
            hv(out, (field << 3 | 2) as u64);
            hv(out, body.len() as u64);
            out.extend_from_slice(body);
        }
        // A hand-rolled reader walking (tag, wire-type) pairs.
        fn hparse(buf: &[u8]) -> Vec<(u32, u8, Vec<u8>)> {
            let mut out = Vec::new();
            let mut pos = 0usize;
            while pos < buf.len() {
                let mut tag = 0u64;
                let mut shift = 0;
                loop {
                    let b = buf[pos];
                    pos += 1;
                    tag |= ((b & 0x7f) as u64) << shift;
                    if b & 0x80 == 0 {
                        break;
                    }
                    shift += 7;
                }
                let field = (tag >> 3) as u32;
                let wire = tag & 7;
                let mut value = Vec::new();
                match wire {
                    0 => loop {
                        let b = buf[pos];
                        pos += 1;
                        value.push(b);
                        if b & 0x80 == 0 {
                            break;
                        }
                    },
                    2 => {
                        let mut len = 0usize;
                        let mut shift = 0;
                        loop {
                            let b = buf[pos];
                            pos += 1;
                            len |= ((b & 0x7f) as usize) << shift;
                            if b & 0x80 == 0 {
                                break;
                            }
                            shift += 7;
                        }
                        value.extend_from_slice(&buf[pos..pos + len]);
                        pos += len;
                    }
                    _ => panic!("unexpected wire type {wire}"),
                }
                out.push((field, wire as u8, value));
            }
            out
        }

        let secret = format!("et-{}", rand::random::<u64>());
        let network = "hand-rolled-net";
        let learned: LearnedRoutes = Arc::new(StdMutex::new(HashMap::new()));
        let accepted = Arc::new(AtomicU32::new(0));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server_secret = secret.clone();
        let server_learned = learned.clone();
        let server_accepted = accepted.clone();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let encryptor = create_encryptor("aes-gcm", true, &server_secret).unwrap();
            let (halves, _peer_info) =
                serve_peer_as(stream, random_peer_id(), network, &server_secret, encryptor, None)
                    .await
                    .unwrap();
            let mut stack = EtStack::new(
                halves.state.my_peer_id,
                network,
                "mimic",
                DEFAULT_MTU,
                Some("10.200.0.1".parse().unwrap()),
                24,
                false,
                vec![],
            );
            let (events_tx, events_rx) = mpsc::channel::<PeerEvent>(64);
            stack.attach_session(halves, false, &events_tx);
            run_mimic(stack, events_rx, server_learned, server_accepted, 9051, 9052).await;
        });

        // The client: a raw M1 node, hand-built gossip bytes.
        let endpoint = parse_peer_endpoint(&format!("tcp://{addr}")).unwrap();
        let encryptor = create_encryptor("aes-gcm", true, &secret).unwrap();
        let node = connect_peer(&endpoint, network, &secret, encryptor)
            .await
            .unwrap();
        // Hand-build SyncRouteInfoRequest { my_peer_id = 0x1111,
        // my_session_id = 0x9876543210, is_initiator = true,
        // peer_infos = [RoutePeerInfo { peer_id = 0x1111, ipv4 =
        // 10.200.0.7, version = 1 }] }.
        let mut rpi = Vec::new();
        hfield_varint(&mut rpi, 1, 0x1111);
        let mut ipv4 = Vec::new();
        hfield_varint(&mut ipv4, 1, u32::from("10.200.0.7".parse::<Ipv4Addr>().unwrap()) as u64);
        hfield_len(&mut rpi, 4, &ipv4);
        hfield_varint(&mut rpi, 9, 1);
        let mut infos = Vec::new();
        hfield_len(&mut infos, 1, &rpi);
        let mut sync_req = Vec::new();
        hfield_varint(&mut sync_req, 1, 0x1111);
        hfield_varint(&mut sync_req, 2, 0x0098_7654_3210);
        hfield_varint(&mut sync_req, 3, 1);
        hfield_len(&mut sync_req, 4, &infos);
        // RpcRequest { request (field 2), timeout_ms = 3000 }.
        let mut rpc_req = Vec::new();
        hfield_len(&mut rpc_req, 2, &sync_req);
        hfield_varint(&mut rpc_req, 3, 3000);
        // RpcPacket { from = us, to = peer, transaction_id = 7777,
        // descriptor = OspfRouteRpc@1, body, is_request }.
        let mut desc = Vec::new();
        hfield_len(&mut desc, 1, network.as_bytes());
        hfield_len(&mut desc, 2, b"OspfRouteRpc");
        hfield_len(&mut desc, 3, b"OspfRouteRpc");
        hfield_varint(&mut desc, 4, 1);
        let mut packet = Vec::new();
        hfield_varint(&mut packet, 1, 0x1111);
        hfield_varint(&mut packet, 2, node.peer_id() as u64);
        hfield_varint(&mut packet, 3, 7777);
        hfield_len(&mut packet, 4, &desc);
        hfield_len(&mut packet, 5, &rpc_req);
        hfield_varint(&mut packet, 6, 1);
        node.send_rpc_packet(true, &packet).await.unwrap();
        // Hand-parse the response: the mimic's own reverse sync may
        // arrive first, so read until the RpcResp for our transaction.
        let ctrl = tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                let ctrl = node
                    .recv_ctrl_packet()
                    .await
                    .expect("ctrl packet");
                if ctrl.hdr.packet_type == packet_type::RPC_RESP {
                    return ctrl;
                }
            }
        })
        .await
        .expect("response timeout");
        let rpc_fields = hparse(&ctrl.payload);
        let mut body = None;
        for (field, wire, value) in &rpc_fields {
            if *field == 5 && *wire == 2 {
                body = Some(value.clone());
            }
        }
        let body = body.expect("rpc body");
        let mut response = None;
        for (field, wire, value) in hparse(&body) {
            if field == 1 && wire == 2 {
                response = Some(value);
            }
        }
        let response = response.expect("rpc response body");
        let mut is_initiator: Option<u64> = None;
        let mut session_id: Option<u64> = None;
        let mut error: Option<u64> = None;
        for (field, wire, value) in hparse(&response) {
            let num = || {
                let mut v = 0u64;
                let mut shift = 0;
                for b in &value {
                    v |= ((b & 0x7f) as u64) << shift;
                    shift += 7;
                }
                v
            };
            if wire == 0 {
                match field {
                    1 => is_initiator = Some(num()),
                    2 => session_id = Some(num()),
                    3 => error = Some(num()),
                    _ => {}
                }
            }
        }
        assert_eq!(error, None, "route sync refused: {response:?}");
        // A false is_initiator is the proto3 default and is omitted.
        assert_ne!(is_initiator, Some(1), "responder is not the initiator");
        let session_id = session_id.expect("session id");
        assert_ne!(session_id, 0);
        assert_ne!(session_id, 0x0098_7654_3210, "session id must be the peer's");
        // The mimic learned our hand-announced address.
        let learned_addr = wait_for_routes(&learned, 0x1111).await;
        assert_eq!(
            learned_addr,
            Some("10.200.0.7".parse::<Ipv4Addr>().unwrap()),
            "hand-rolled announcement not learned: {:?}",
            learned.lock().unwrap()
        );
        node.close().await;
        server.abort();
    }

    /// A guard that kills the spawned real node on drop.
    struct KillChild(std::process::Child);
    impl Drop for KillChild {
        fn drop(&mut self) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }

    /// OPTIONAL real-binary interop (hermetic tests remain the gate):
    /// spawns a real `easytier-core` (verified against the v2.6.4
    /// release) with a SOCKS5 server on its overlay address and proves
    /// the full M2 chain — the plain handshake, the AEAD packet
    /// encryption on both the Data and the RpcReq/RpcResp channels, the
    /// `OspfRouteRpc.SyncRouteInfo` exchange in both directions (the
    /// node answers ours; we answer its reverse sync), and a TCP relay
    /// through both stacks (the SOCKS5 greeting). With
    /// `EASYTIER_VERBOSE=1` set, the test instead drives one raw route
    /// sync by hand and prints the decoded response. Run with:
    /// `EASYTIER_BIN=/path/to/easytier-core cargo test ... -- --ignored`
    #[tokio::test]
    #[ignore = "needs a real easytier-core binary; set EASYTIER_BIN to enable"]
    async fn real_easytier_binary_interop() {
        let Ok(bin) = std::env::var("EASYTIER_BIN") else {
            eprintln!("skipping: EASYTIER_BIN is not set");
            return;
        };
        let network = format!("itnet-{}", rand::random::<u32>());
        let secret = format!("itsec-{}", rand::random::<u64>());
        let port = 31000 + rand::random::<u16>() % 20000;
        let verbose = std::env::var("EASYTIER_VERBOSE").is_ok();
        let mut command = std::process::Command::new(&bin);
        command.args([
            "--network-name",
            &network,
            "--network-secret",
            &secret,
            "-l",
            &format!("tcp://127.0.0.1:{port}"),
            "--no-tun",
            "-i",
            "10.126.126.1",
            "--hostname",
            "real-node",
            "--socks5",
            "1080",
        ]);
        if verbose {
            command
                .arg("--console-log-level")
                .arg("trace")
                .stderr(std::process::Stdio::inherit());
        } else {
            command.stderr(std::process::Stdio::null());
        }
        let _child = KillChild(command.spawn().expect("spawn easytier-core"));
        // Give the node time to bind its listener.
        tokio::time::sleep(Duration::from_secs(2)).await;

        let cfg = EasyTierConfig {
            peers: vec![format!("tcp://127.0.0.1:{port}")],
            network_secret: secret,
            ipv4: Some("10.126.126.2/24".to_owned()),
            dhcp: false,
            hostname: Some("rustcrash-m2".to_owned()),
            ..EasyTierConfig::new("et-real", &network)
        };
        // Debug path (EASYTIER_VERBOSE): one raw route sync against the
        // real node, printing what comes back.
        if verbose {
            let endpoint = parse_peer_endpoint(&format!("tcp://127.0.0.1:{port}")).unwrap();
            let encryptor = create_encryptor("aes-gcm", true, &cfg.network_secret).unwrap();
            let node = connect_peer(&endpoint, &cfg.network_name, &cfg.network_secret, encryptor)
                .await
                .unwrap();
            let mut gossip = RouteGossip::new(
                &cfg.network_name,
                node.my_peer_id(),
                node.peer_id(),
                "rustcrash-m2",
                Some("10.126.126.2".parse().unwrap()),
                24,
                false,
                vec![],
                true,
            );
            let mut router = RpcRouter::default();
            let request = gossip.build_request().encode();
            let (transaction_id, wire) = router.begin_call(
                node.my_peer_id(),
                node.peer_id(),
                ospf_route_descriptor(&cfg.network_name),
                &request,
                3000,
            );
            node.send_rpc_packet(true, &wire).await.unwrap();
            let deadline = Duration::from_secs(6);
            let reported = tokio::time::timeout(deadline, async {
                loop {
                    let Some(packet) = node.recv_ctrl_packet().await else {
                        return "ctrl channel closed".to_string();
                    };
                    let Ok(rpc) = RpcPacket::decode(&packet.payload) else {
                        continue;
                    };
                    if rpc.is_request {
                        let body = RpcRequestBody::decode(&rpc.body).unwrap();
                        let req = SyncRouteInfoRequest::decode(&body.request).unwrap();
                        let resp = gossip.handle_sync_request(&req);
                        let resp_packet = build_rpc_response(&rpc, &resp.encode());
                        let _ = node.send_rpc_packet(false, &resp_packet.encode()).await;
                        eprintln!("probe: answered the node's reverse sync");
                        continue;
                    }
                    if rpc.transaction_id != transaction_id {
                        eprintln!("probe: stray response tid {}", rpc.transaction_id);
                        continue;
                    }
                    let body = RpcResponseBody::decode(&rpc.body).unwrap();
                    return format!(
                        "probe response: error_tag={:?} decoded={:?}",
                        body.error_tag,
                        SyncRouteInfoResponse::decode(&body.response)
                    );
                }
            })
            .await;
            eprintln!("probe: {reported:?}");
            node.close().await;
            return;
        }
        // The dial parks on route readiness first: a real node must
        // accept our SyncRouteInfo (and answer its own) before any
        // overlay traffic flows back to us.
        let socks5: SocketAddr = "10.126.126.1:1080".parse().unwrap();
        let mut stream = tokio::time::timeout(Duration::from_secs(20), connect_tcp(&cfg, &socks5))
            .await
            .expect("dial through the real node timed out")
            .expect("dial through the real node");
        // SOCKS5 greeting: no-auth method.
        stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greeting = [0u8; 2];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(&greeting, &[0x05, 0x00], "socks5 greeting");
    }

    // ========================================================================
    // M3: the UDP transport + the listener
    // ========================================================================

    #[test]
    fn udp_tunnel_wire_format() {
        // `UDPTunnelHeader` (packet_def.rs:51-58): packed little-endian
        // { conn_id: U32, msg_type: u8, padding: u8, len: U16 }.
        let header = UdpTunnelHeader {
            conn_id: 0x1122_3344,
            msg_type: udp_packet_type::SYN,
            len: 8,
        };
        assert_eq!(
            header.to_bytes(),
            [0x44, 0x33, 0x22, 0x11, 0x01, 0x00, 0x08, 0x00]
        );
        assert_eq!(UdpTunnelHeader::from_bytes(&header.to_bytes()), Some(header));
        assert_eq!(UDP_TUNNEL_HEADER_SIZE, 8);
        // The SYN/SACK datagram: 8 header bytes + the magic, LE
        // (`new_syn_packet`, tunnel/udp.rs:63-72).
        let magic: u64 = 0x0102_0304_0506_0708;
        let syn = UdpTunnelHeader::datagram(udp_packet_type::SYN, 7, &magic.to_le_bytes());
        assert_eq!(syn.len(), 16);
        assert_eq!(&syn[..8], &[0x07, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00]);
        assert_eq!(&syn[8..], &magic.to_le_bytes());
        // `get_zcpacket_from_buf`: the len field must match the body
        // (tunnel/udp.rs:258-264) — a mismatched datagram is not tunnel
        // traffic.
        let (parsed, body) = parse_udp_datagram(&syn).unwrap();
        assert_eq!(parsed.msg_type, udp_packet_type::SYN);
        assert_eq!(parsed.conn_id, 7);
        assert_eq!(body, &magic.to_le_bytes()[..]);
        let mut bogus = syn.clone();
        bogus[7] = 0x09; // len 9 vs the 8-byte body
        assert!(parse_udp_datagram(&bogus).is_none());
        assert!(parse_udp_datagram(&syn[..7]).is_none());
    }

    #[tokio::test]
    async fn udp_tunnel_connect_accept_and_framed_round_trip() {
        // The virtual circuit end to end: listener + connector, the
        // SYN/SACK exchange, then framed peer packets in both directions
        // (the `udp_pingpong` of tunnel/udp.rs:958-963, over the M1
        // framing instead of raw bytes).
        let mut listener = UdpVtListener::bind("127.0.0.1:0".parse().unwrap())
            .await
            .unwrap();
        let addr = listener.local_addr();
        let mut client = connect_udp_tunnel(addr).await.unwrap();
        let mut server = tokio::time::timeout(Duration::from_secs(3), listener.accept())
            .await
            .expect("accept the syn")
            .unwrap();
        // Client -> server through the datagram circuit.
        let out = PeerPacket::new(1, 2, packet_type::DATA, b"over-udp");
        write_frame(&mut client, &out).await.unwrap();
        let back = tokio::time::timeout(Duration::from_secs(3), read_frame(&mut server))
            .await
            .expect("server read")
            .unwrap()
            .expect("frame");
        assert_eq!(back.hdr, out.hdr);
        assert_eq!(back.payload, b"over-udp");
        // Server -> client (the circuit's conn id is the client's; both
        // directions share it, tunnel/udp.rs:289).
        let reply = PeerPacket::new(2, 1, packet_type::PONG, &[9, 0, 0, 0]);
        write_frame(&mut server, &reply).await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(3), read_frame(&mut client))
            .await
            .expect("client read")
            .unwrap()
            .expect("frame");
        assert_eq!(got.payload, reply.payload);
    }

    #[tokio::test]
    async fn udp_wire_payload_is_pmh_framed() {
        // The datagram payload on the wire is `[PeerManagerHeader]
        // [payload]` with NO length prefix (packet_def.rs:393-400),
        // found live against the real binary. A fake server socket
        // answers the SYN/SACK and observes the actual datagrams.
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        let client =
            tokio::spawn(async move { connect_udp_tunnel(addr).await.unwrap() });
        let mut buf = vec![0u8; 1600];
        let (n, from) = sock.recv_from(&mut buf).await.unwrap();
        let (syn, body) = parse_udp_datagram(&buf[..n]).unwrap();
        assert_eq!(syn.msg_type, udp_packet_type::SYN);
        assert_eq!(body.len(), 8);
        sock.send_to(
            &UdpTunnelHeader::datagram(udp_packet_type::SACK, syn.conn_id, body),
            from,
        )
        .await
        .unwrap();
        let mut client = client.await.unwrap();
        // One peer frame write → one datagram whose body is PMH+payload.
        let frame =
            PeerPacket::new(9, 8, packet_type::HANDSHAKE, b"pmh-only").to_tcp_frame().unwrap();
        client.write_all(&frame).await.unwrap();
        client.flush().await.unwrap();
        let (n, _) = sock.recv_from(&mut buf).await.unwrap();
        let (data_hdr, data_body) = parse_udp_datagram(&buf[..n]).unwrap();
        assert_eq!(data_hdr.msg_type, udp_packet_type::DATA);
        assert_eq!(data_hdr.conn_id, syn.conn_id);
        assert_eq!(data_hdr.len as usize, data_body.len());
        assert_eq!(
            data_body.len(),
            PEER_MANAGER_HEADER_SIZE + b"pmh-only".len(),
            "no u32 length prefix on the wire"
        );
        assert_eq!(data_body[8], packet_type::HANDSHAKE);
        assert_eq!(&data_body[PEER_MANAGER_HEADER_SIZE..], b"pmh-only");
        // And the inverse: a [PMH][payload] datagram reads back as one
        // framed peer packet.
        let inbound =
            PeerPacket::new(8, 9, packet_type::PONG, &[1, 0, 0, 0]).to_tcp_frame().unwrap();
        let wire = udp_wire_datagram(&inbound).unwrap();
        sock.send_to(
            &UdpTunnelHeader::datagram(udp_packet_type::DATA, syn.conn_id, wire),
            from,
        )
        .await
        .unwrap();
        let got = tokio::time::timeout(Duration::from_secs(3), read_frame(&mut client))
            .await
            .expect("frame back")
            .unwrap()
            .expect("frame");
        assert_eq!(got.hdr.packet_type, packet_type::PONG);
        assert_eq!(got.payload, &[1, 0, 0, 0]);
    }

    impl MimicMesh {
        /// The UDP flavour: a mimic mesh whose underlay is the UDP
        /// tunnel listener (`UdpTunnelListener` + `add_tunnel_as_server`).
        async fn spawn_udp(network: &str, secret: &str, overlay_ip: &str, prefix: u32) -> Self {
            let mut listener = UdpVtListener::bind("127.0.0.1:0".parse().unwrap())
                .await
                .unwrap();
            let underlay = listener.local_addr();
            let overlay_ip: Ipv4Addr = overlay_ip.parse().unwrap();
            let learned: LearnedRoutes = Arc::new(StdMutex::new(HashMap::new()));
            let accepted = Arc::new(AtomicU32::new(0));
            let underlay_conns = Arc::new(AtomicU32::new(0));
            let network = network.to_owned();
            let secret = secret.to_owned();
            let learned_task = learned.clone();
            let accepted_task = accepted.clone();
            let underlay_task = underlay_conns.clone();
            tokio::spawn(async move {
                loop {
                    let Ok(stream) = listener.accept().await else { break };
                    let network = network.clone();
                    let secret = secret.clone();
                    let learned = learned_task.clone();
                    let accepted = accepted_task.clone();
                    underlay_task.fetch_add(1, Ordering::Relaxed);
                    tokio::spawn(async move {
                        let encryptor = create_encryptor("aes-gcm", true, &secret).unwrap();
                        let Ok((halves, _peer_info)) =
                            serve_peer_as(stream, random_peer_id(), &network, &secret, encryptor, None)
                                .await
                        else {
                            return;
                        };
                        let mut stack = EtStack::new(
                            halves.state.my_peer_id,
                            &network,
                            "mimic",
                            DEFAULT_MTU,
                            Some(overlay_ip),
                            prefix,
                            false,
                            vec![],
                        );
                        let (events_tx, events_rx) = mpsc::channel::<PeerEvent>(64);
                        stack.attach_session(halves, false, &events_tx);
                        run_mimic(stack, events_rx, learned, accepted, 9041, 9042).await;
                    });
                }
            });
            MimicMesh {
                underlay,
                overlay_ip,
                learned,
                accepted,
                underlay_conns,
                echo_tcp_port: 9041,
                echo_udp_port: 9042,
            }
        }

        fn config_udp(&self, network: &str, secret: &str, ipv4: Option<&str>) -> EasyTierConfig {
            EasyTierConfig {
                peers: vec![format!("udp://{}", self.underlay)],
                network_secret: secret.to_owned(),
                ipv4: ipv4.map(|s| s.to_owned()),
                dhcp: ipv4.is_none(),
                ..EasyTierConfig::new("et-m3-udp", network)
            }
        }
    }

    #[tokio::test]
    async fn udp_peer_uri_drives_the_full_stack() {
        // THE UDP proof: a `udp://` peer URI dials the datagram circuit,
        // the plain handshake + gossip ride it, and overlay TCP relays
        // through both smoltcp stacks — everything the TCP path does,
        // over UDP.
        let secret = format!("et-{}", rand::random::<u64>());
        let mimic = MimicMesh::spawn_udp("udp-net", &secret, "10.144.30.1", 24).await;
        let cfg = mimic.config_udp("udp-net", &secret, Some("10.144.30.2"));
        let target = SocketAddr::V4(SocketAddrV4::new(mimic.overlay_ip, mimic.echo_tcp_port));
        let mut stream = tokio::time::timeout(Duration::from_secs(15), connect_tcp(&cfg, &target))
            .await
            .expect("udp dial through the overlay")
            .expect("connect_tcp over the udp transport");
        stream.write_all(b"udp-carried").await.unwrap();
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"udp-carried");
    }

    /// One mesh node driven by THIS test suite as a client: dial the
    /// given underlay, run the echo service of `run_mimic` behind the
    /// client-side stack (the role the real easytier binary plays in the
    /// listener interop test).
    async fn spawn_mimic_client(
        addr: SocketAddr,
        network: &str,
        secret: &str,
        overlay_ip: &str,
        prefix: u32,
    ) -> (Ipv4Addr, u16) {
        let overlay: Ipv4Addr = overlay_ip.parse().unwrap();
        let network = network.to_owned();
        let secret = secret.to_owned();
        let learned: LearnedRoutes = Arc::new(StdMutex::new(HashMap::new()));
        let accepted = Arc::new(AtomicU32::new(0));
        tokio::spawn(async move {
            let endpoint = PeerEndpoint {
                transport: PeerTransport::Tcp,
                host: "127.0.0.1".to_owned(),
                port: addr.port(),
            };
            let encryptor = create_encryptor("aes-gcm", true, &secret).unwrap();
            let Ok(halves) =
                dial_session(&endpoint, random_peer_id(), &network, &secret, encryptor, None).await
            else {
                return;
            };
            let mut stack = EtStack::new(
                halves.state.my_peer_id,
                &network,
                "mimic-client",
                DEFAULT_MTU,
                Some(overlay),
                prefix,
                false,
                vec![],
            );
            let (events_tx, events_rx) = mpsc::channel::<PeerEvent>(64);
            stack.attach_session(halves, true, &events_tx);
            run_mimic(stack, events_rx, learned, accepted, 9061, 9062).await;
        });
        (overlay, 9061)
    }

    #[tokio::test]
    async fn serve_accepts_inbound_peer_and_relays_overlay_tcp() {
        // THE listener proof: `serve` binds, our own client (the binary's
        // stand-in) dials in, joins the node through the same handshake,
        // gossip converges both ways, and overlay traffic relays through
        // the INBOUND session.
        let secret = format!("et-{}", rand::random::<u64>());
        let network = "srv-net";
        let port = 31000 + rand::random::<u16>() % 20000;
        let cfg = EasyTierConfig {
            listeners: vec![format!("tcp://127.0.0.1:{port}")],
            network_secret: secret.clone(),
            ipv4: Some("10.144.20.1/24".to_owned()),
            dhcp: false,
            hostname: Some("serve-node".to_owned()),
            ..EasyTierConfig::new("et-m3-serve", network)
        };
        let server = serve(&cfg).await.unwrap();
        assert_eq!(server.local_addrs()[0].port(), port);

        let (mimic_ip, echo_port) = spawn_mimic_client(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
            network,
            &secret,
            "10.144.20.2",
            24,
        )
        .await;
        // The inbound peer must join and sync before the node is ready.
        tokio::time::timeout(Duration::from_secs(15), server.wait_ready())
            .await
            .expect("inbound peer did not sync in time")
            .unwrap();
        let nodes = server.overlay_nodes().await.unwrap();
        assert!(
            nodes.iter().any(|n| n.ipv4 == mimic_ip),
            "node table {nodes:?} lacks the inbound peer {mimic_ip}"
        );
        // Route through the inbound session: the registry reuses the
        // served node for the dial.
        let target = SocketAddr::V4(SocketAddrV4::new(mimic_ip, echo_port));
        let mut stream = tokio::time::timeout(Duration::from_secs(15), connect_tcp(&cfg, &target))
            .await
            .expect("dial through the inbound peer")
            .expect("connect_tcp via the listener");
        stream.write_all(b"through-the-listener").await.unwrap();
        let mut buf = [0u8; 32];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"through-the-listener");
        server.shutdown().await;
    }

    #[tokio::test]
    async fn serve_udp_listener_accepts_inbound_udp_peer() {
        // The udp:// listener flavour end to end: the inbound peer rides
        // the datagram circuit into the same node.
        let secret = format!("et-{}", rand::random::<u64>());
        let network = "srv-udp-net";
        let port = 31000 + rand::random::<u16>() % 20000;
        let cfg = EasyTierConfig {
            listeners: vec![format!("udp://127.0.0.1:{port}")],
            network_secret: secret.clone(),
            ipv4: Some("10.144.40.1/24".to_owned()),
            dhcp: false,
            hostname: Some("serve-udp-node".to_owned()),
            ..EasyTierConfig::new("et-m3-serve-udp", network)
        };
        let server = serve(&cfg).await.unwrap();
        assert_eq!(server.local_addrs()[0].port(), port);
        // The stand-in client over the UDP transport.
        let (mimic_ip, echo_port) = {
            let overlay: Ipv4Addr = "10.144.40.2".parse().unwrap();
            let network = network.to_owned();
            let secret = secret.clone();
            let learned: LearnedRoutes = Arc::new(StdMutex::new(HashMap::new()));
            let accepted = Arc::new(AtomicU32::new(0));
            tokio::spawn(async move {
                let endpoint = PeerEndpoint {
                    transport: PeerTransport::Udp,
                    host: "127.0.0.1".to_owned(),
                    port,
                };
                let encryptor = create_encryptor("aes-gcm", true, &secret).unwrap();
                let Ok(halves) =
                    dial_session(&endpoint, random_peer_id(), &network, &secret, encryptor, None).await
                else {
                    return;
                };
                let mut stack = EtStack::new(
                    halves.state.my_peer_id,
                    &network,
                    "mimic-udp-client",
                    DEFAULT_MTU,
                    Some(overlay),
                    24,
                    false,
                    vec![],
                );
                let (events_tx, events_rx) = mpsc::channel::<PeerEvent>(64);
                stack.attach_session(halves, true, &events_tx);
                run_mimic(stack, events_rx, learned, accepted, 9071, 9072).await;
            });
            (overlay, 9071)
        };
        tokio::time::timeout(Duration::from_secs(15), server.wait_ready())
            .await
            .expect("inbound udp peer did not sync in time")
            .unwrap();
        let target = SocketAddr::V4(SocketAddrV4::new(mimic_ip, echo_port));
        let mut stream = tokio::time::timeout(Duration::from_secs(15), connect_tcp(&cfg, &target))
            .await
            .expect("dial through the inbound udp peer")
            .expect("connect_tcp via the udp listener");
        stream.write_all(b"udp-inbound").await.unwrap();
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"udp-inbound");
        server.shutdown().await;
    }

    #[tokio::test]
    async fn serve_config_errors() {
        // no-listener refuses to serve (a peer must be present or the
        // TOML validation fires first).
        let cfg = EasyTierConfig {
            peers: vec!["tcp://127.0.0.1:1".into()],
            no_listener: Some(true),
            ..EasyTierConfig::new("et-m3-none", "net")
        };
        let err = serve(&cfg).await.unwrap_err().to_string();
        assert!(err.contains("nothing to accept on"), "{err}");
        // A bad secure-mode key still fails the config.
        let cfg = EasyTierConfig {
            listeners: vec!["tcp://127.0.0.1:0".into()],
            secure_mode: Some(true),
            local_private_key: Some("not-base64!!".to_owned()),
            ..EasyTierConfig::new("et-m3-secure", "net")
        };
        let err = serve(&cfg).await.unwrap_err().to_string();
        assert!(err.contains("local-private-key"), "{err}");
        // An unhandled listener scheme names the missing transports
        // (wg:// binds now — its hermetic listener test is below).
        let cfg = EasyTierConfig {
            listeners: vec!["faketcp://127.0.0.1:0".into()],
            ..EasyTierConfig::new("et-m3-wg", "net")
        };
        let err = serve(&cfg).await.unwrap_err().to_string();
        assert!(err.contains("faketcp"), "{err}");
    }

    #[tokio::test]
    async fn secure_mode_noise_first_packet_is_named() {
        // A secure-mode client opens with NoiseHandshakeMsg1; a PLAIN-mode
        // server answers the generic unexpected-type error with the cause
        // named (upstream's `unexpected packet type during handshake`,
        // peer_conn.rs:1277-1281 — the noise path only runs when this node
        // is itself in secure mode, peer_conn.rs:1252).
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let noise = PeerPacket::new(1, 0, packet_type::NOISE_HANDSHAKE_MSG1, &[0u8; 48]);
            write_frame(&mut stream, &noise).await.unwrap();
            let _ = tokio::time::timeout(Duration::from_secs(2), read_frame(&mut stream)).await;
        });
        let mut stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let digest = network_secret_digest("net", "secret");
        let err = handshake_as_server(&mut stream, 7, "net", &digest, None)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("unexpected packet type during handshake: 13"), "{err}");
        assert!(err.contains("secure mode"), "{err}");
    }

    // ------------------------------------------------ M6: secure mode

    fn secure_test_ctx(network: &str, secret: &str, pinned: Option<&str>) -> SecureModeCtx {
        SecureModeCtx::new(network, secret, "", "aes-gcm", pinned).unwrap()
    }

    #[test]
    fn noise_wire_messages_proto_roundtrip() {
        // The three protobufs round-trip through the engine codec,
        // optional fields included (peer_rpc.proto:343-386).
        let a_conn_id = uuid::Uuid::new_v4();
        let msg1 = NoiseMsg1 {
            version: 1,
            a_network_name: "net-1".to_owned(),
            a_session_generation: Some(7),
            a_conn_id,
            client_encryption_algorithm: "aes-gcm".to_owned(),
        };
        let decoded1 = NoiseMsg1::decode(&msg1.encode()).unwrap();
        assert_eq!(decoded1, msg1);
        assert!(decoded1.encode().len() >= 32 + 4 + 8, "uuid + varints");

        let root_key: [u8; 32] = core::array::from_fn(|i| i as u8);
        let b_conn_id = uuid::Uuid::new_v4();
        let msg2 = NoiseMsg2 {
            b_network_name: "net-1".to_owned(),
            role_hint: 1,
            action: PeerConnSessionAction::Create,
            b_session_generation: 1,
            root_key_32: Some(root_key),
            initial_epoch: 0,
            b_conn_id,
            a_conn_id_echo: Some(a_conn_id),
            secret_proof_32: Some(vec![0xab; 32]),
            server_encryption_algorithm: "aes-gcm".to_owned(),
        };
        assert_eq!(NoiseMsg2::decode(&msg2.encode()).unwrap(), msg2);
        // Omitted optionals decode as None (proto3).
        let bare = NoiseMsg2 {
            root_key_32: None,
            secret_proof_32: None,
            a_conn_id_echo: None,
            ..msg2.clone()
        };
        let decoded = NoiseMsg2::decode(&bare.encode()).unwrap();
        assert_eq!(decoded.root_key_32, None);
        assert_eq!(decoded.secret_proof_32, None);

        let msg3 = NoiseMsg3 {
            a_conn_id_echo: a_conn_id,
            b_conn_id_echo: b_conn_id,
            secret_proof_32: Some(vec![1u8; 32]),
            secret_digest: vec![2u8; 32],
        };
        assert_eq!(NoiseMsg3::decode(&msg3.encode()).unwrap(), msg3);
        // The UUID wire form is four BE u32 varints (common.rs:14-24).
        let parts = uuid_wire_parts(a_conn_id);
        assert_eq!(uuid_from_wire_parts(parts), a_conn_id);
    }

    #[test]
    fn secure_hkdf_traffic_key_matches_upstream_shape() {
        // secure_datagram.rs:391-410: prk = HMAC-SHA256(0^32, root_key);
        // key = HMAC(prk, "et-traffic" || epoch_be || dir || 0x01).
        let root_key: [u8; 32] = core::array::from_fn(|i| (i * 7) as u8);
        let session = SecureDatagramSession::new(
            root_key,
            1,
            0,
            "aes-gcm".to_owned(),
            "aes-gcm".to_owned(),
        );
        // Direction 0, epoch 0x0102_0304.
        session.sync_root_key(root_key, 1, 0x0102_0304, false);
        let got = session.hkdf_traffic_key(0x0102_0304, SecureDirection::AToB);
        let prk = hmac_sha256(&[0u8; 32], &[&root_key]);
        let mut info = Vec::new();
        info.extend_from_slice(b"et-traffic");
        info.extend_from_slice(&0x0102_0304u32.to_be_bytes());
        info.push(0);
        let expected = hmac_sha256(&prk, &[&info, &[1u8]]);
        assert_eq!(got, expected, "the HKDF info string must stay stable");
        // Different direction derives a different key.
        assert_ne!(
            session.hkdf_traffic_key(0x0102_0304, SecureDirection::BToA),
            expected
        );
    }

    #[test]
    fn replay_window_shift_preserves_bits() {
        // secure_datagram.rs:906-918.
        let mut w = ReplayWindow256::default();
        for i in 0..10u64 {
            assert!(w.accept(i), "seq {i} should be accepted");
        }
        assert_eq!(w.max_seq, 9);
        for i in 0..10u64 {
            assert!(!w.accept(i), "seq {i} should be rejected as replay");
        }
        assert!(w.accept(10));
    }

    #[test]
    fn replay_window_out_of_order_within_window() {
        // secure_datagram.rs:920-932.
        let mut w = ReplayWindow256::default();
        for i in (0..=20u64).step_by(2) {
            assert!(w.accept(i));
        }
        for i in (1..=19u64).step_by(2) {
            assert!(w.accept(i), "out-of-order within 256 must pass");
        }
        for i in 0..=20u64 {
            assert!(!w.accept(i));
        }
    }

    #[test]
    fn secure_session_roundtrip_replay_and_tamper() {
        // The two halves of one session exchange traffic both ways, a
        // replayed ciphertext is rejected, and a tampered tail fails
        // without poisoning the window (secure_datagram.rs:846-903).
        let root_key = PeerSecureSession::new_root_key();
        let a = PeerSecureSession::new(
            root_key,
            1,
            0,
            "aes-gcm".to_owned(),
            "aes-gcm".to_owned(),
            None,
        );
        let b = PeerSecureSession::new(
            root_key,
            1,
            0,
            "aes-gcm".to_owned(),
            "aes-gcm".to_owned(),
            None,
        );
        let a_id: PeerId = 10;
        let b_id: PeerId = 20;

        let plaintext = b"secure payload over the mesh";
        let mut hdr = PeerManagerHeader {
            from_peer_id: a_id,
            to_peer_id: b_id,
            packet_type: packet_type::DATA,
            flags: 0,
            forward_counter: 1,
            reserved: 0,
            len: plaintext.len() as u32,
        };
        let mut payload = plaintext.to_vec();
        a.encrypt_payload(a_id, b_id, &mut hdr, &mut payload).unwrap();
        assert!(hdr.is_encrypted());
        assert_eq!(payload.len(), plaintext.len() + AEAD_TAIL_SIZE);
        let mut decrypted_hdr = hdr;
        let mut decrypted = payload.clone();
        b.decrypt_payload(a_id, b_id, &mut decrypted_hdr, &mut decrypted)
            .unwrap();
        assert_eq!(decrypted, plaintext);
        assert!(!decrypted_hdr.is_encrypted());

        // Replaying the same ciphertext is rejected (same epoch+seq).
        let mut replay_hdr = hdr;
        let mut replay = payload.clone();
        assert!(
            b.decrypt_payload(a_id, b_id, &mut replay_hdr, &mut replay)
                .is_err()
        );

        // A tampered nonce (far-future epoch) fails without poisoning:
        // the next honest packet still decrypts.
        let mut forged_hdr = hdr;
        let mut forged = plaintext.to_vec();
        a.encrypt_payload(a_id, b_id, &mut forged_hdr, &mut forged).unwrap();
        let len = forged.len();
        forged[len - 12..len - 8].copy_from_slice(&1000u32.to_be_bytes());
        assert!(
            b.decrypt_payload(a_id, b_id, &mut forged_hdr, &mut forged)
                .is_err()
        );
        let mut next_hdr = PeerManagerHeader {
            from_peer_id: a_id,
            to_peer_id: b_id,
            packet_type: packet_type::DATA,
            flags: 0,
            forward_counter: 1,
            reserved: 0,
            len: plaintext.len() as u32,
        };
        let mut next = plaintext.to_vec();
        a.encrypt_payload(a_id, b_id, &mut next_hdr, &mut next).unwrap();
        b.decrypt_payload(a_id, b_id, &mut next_hdr, &mut next).unwrap();
        assert_eq!(next, plaintext);

        // The reverse direction derives the BToA keys.
        let mut back_hdr = PeerManagerHeader {
            from_peer_id: b_id,
            to_peer_id: a_id,
            packet_type: packet_type::RPC_REQ,
            flags: 0,
            forward_counter: 1,
            reserved: 0,
            len: 4,
        };
        let mut back = b"ping?".to_vec();
        b.encrypt_payload(b_id, a_id, &mut back_hdr, &mut back).unwrap();
        a.decrypt_payload(b_id, a_id, &mut back_hdr, &mut back).unwrap();
        assert_eq!(back, b"ping?");
    }

    #[test]
    fn sync_root_key_grace_keeps_then_expires_old_epochs() {
        // secure_datagram.rs:954-1000: after a same-key sync the
        // pre-sync rx epochs stay acceptable for the 5s grace window,
        // then expire; a CHANGED root key gets no grace.
        let s = SecureDatagramSession::new(
            PeerSecureSession::new_root_key(),
            1,
            0,
            "aes-gcm".to_owned(),
            "aes-gcm".to_owned(),
        );
        let now = secure_now_ms();
        assert!(s.check_replay_for_test(0, 0, SecureDirection::AToB, now));
        assert!(s.check_replay_for_test(1, 0, SecureDirection::AToB, now + 1));

        let root_key = s.root_key();
        s.sync_root_key(root_key, 2, 2, true);
        assert!(s.check_replay_for_test(2, 0, SecureDirection::AToB, now + 2));
        // Grace: the old epochs still accept NEW sequences.
        assert!(s.check_replay_for_test(1, 1, SecureDirection::AToB, now + 3));
        assert!(s.check_replay_for_test(0, 1, SecureDirection::AToB, now + 4));
        // After the window they are gone.
        assert!(!s.check_replay_for_test(
            0,
            2,
            SecureDirection::AToB,
            now + SYNC_RX_GRACE_AFTER_MS + 3,
        ));

        // A different root key never gets the grace window.
        s.sync_root_key(PeerSecureSession::new_root_key(), 3, 5, true);
        assert!(s.check_replay_for_test(5, 0, SecureDirection::AToB, now + 10));
        assert!(!s.check_replay_for_test(2, 0, SecureDirection::AToB, now + 11));
    }

    #[test]
    fn far_future_epoch_rejected_without_poisoning() {
        // secure_datagram.rs:826-844.
        let s = SecureDatagramSession::new(
            PeerSecureSession::new_root_key(),
            1,
            0,
            "aes-gcm".to_owned(),
            "aes-gcm".to_owned(),
        );
        let now = secure_now_ms();
        assert!(s.check_replay_for_test(0, 1, SecureDirection::AToB, now));
        assert!(s.check_replay_for_test(0, 2, SecureDirection::AToB, now));
        assert!(!s.check_replay_for_test(1000, 1, SecureDirection::AToB, now));
        // The far-future packet did not shift the window.
        assert!(s.check_replay_for_test(1, 1, SecureDirection::AToB, now + 1));
        assert!(s.check_replay_for_test(1, 2, SecureDirection::AToB, now + 2));
    }

    #[test]
    fn session_store_join_sync_create_election() {
        // peer_session.rs:88-212: a first responder contact Creates with
        // a fresh root key; a matching generation Joins (no key); a
        // mismatched generation Syncs the stored key at the next epoch.
        let store = PeerSessionStore::new();
        let key = ("net".to_owned(), 42u32);

        let first = store
            .upsert_responder_session(key.clone(), None, "aes-gcm", "aes-gcm", None)
            .unwrap();
        assert_eq!(first.action, PeerConnSessionAction::Create);
        assert_eq!(first.session_generation, 1);
        let created_root_key = first.root_key;
        assert!(created_root_key.is_some());

        // The client installs the Create verdict.
        let client_session = store
            .apply_initiator_action(
                key.clone(),
                PeerConnSessionAction::Create,
                first.session_generation,
                created_root_key,
                first.initial_epoch,
                "aes-gcm",
                "aes-gcm",
                None,
            )
            .unwrap();
        assert_eq!(client_session.root_key(), created_root_key.unwrap());

        // Same generation claimed by the client → Join, no key material.
        let second = store
            .upsert_responder_session(key.clone(), Some(1), "aes-gcm", "aes-gcm", None)
            .unwrap();
        assert_eq!(second.action, PeerConnSessionAction::Join);
        assert_eq!(second.root_key, None);

        // Join with the wrong generation on the client side is fatal.
        assert!(
            store
                .apply_initiator_action(
                    key.clone(),
                    PeerConnSessionAction::Join,
                    99,
                    None,
                    0,
                    "aes-gcm",
                    "aes-gcm",
                    None,
                )
                .is_err()
        );

        // A client without a generation hint (the engine's dial path)
        // gets a Sync of the stored key.
        let third = store
            .upsert_responder_session(key.clone(), None, "aes-gcm", "aes-gcm", None)
            .unwrap();
        assert_eq!(third.action, PeerConnSessionAction::Sync);
        assert_eq!(third.root_key, created_root_key);

        // Static-key pinning: the first key sticks, a different one is
        // rejected (peer_session.rs:296-312).
        let pinned: [u8; 32] = core::array::from_fn(|i| i as u8);
        store
            .upsert_responder_session(key.clone(), Some(1), "aes-gcm", "aes-gcm", Some(pinned))
            .unwrap();
        let clash = store.upsert_responder_session(
            key.clone(),
            Some(1),
            "aes-gcm",
            "aes-gcm",
            Some([9u8; 32]),
        );
        assert!(clash.is_err());
    }

    #[tokio::test]
    async fn noise_handshake_roundtrip_over_duplex() {
        // The full three-message exchange between our own client and
        // server halves over a memory duplex: proofs verified both ways
        // (NetworkSecretConfirmed), the responder's Create verdict
        // installed by the client, and BOTH sides end on the same
        // session (same root key, same generation).
        let (client_io, server_io) = tokio::io::duplex(8192);
        let mut client_io = client_io;
        let mut server_io = server_io;
        let client_ctx = secure_test_ctx("sec-net", "sec-secret", None);
        let server_ctx = secure_test_ctx("sec-net", "sec-secret", None);
        let server_peer_id: PeerId = 0xfeed_face;
        let client_peer_id: PeerId = 0x1234_5678;

        let server = tokio::spawn(async move {
            let first = recv_noise_frame(&mut server_io, packet_type::NOISE_HANDSHAKE_MSG1)
                .await
                .unwrap();
            noise_handshake_as_server(&mut server_io, server_peer_id, &server_ctx, first).await
        });
        let client =
            noise_handshake_as_client(&mut client_io, client_peer_id, &client_ctx).await.unwrap();
        let server = server.await.unwrap().unwrap();

        assert_eq!(client.peer.peer_id, server_peer_id);
        assert_eq!(server.peer.peer_id, client_peer_id);
        assert_eq!(client.auth_level, SecureAuthLevel::NetworkSecretConfirmed);
        assert_eq!(server.auth_level, SecureAuthLevel::NetworkSecretConfirmed);
        // The Create verdict gave both sides the same root key.
        assert_eq!(client.session.root_key(), server.session.root_key());
        assert_eq!(
            client.session.session_generation(),
            server.session.session_generation()
        );
        // The identity digest carried in msg3 matches the plain-mode
        // digest of the shared secret.
        assert_eq!(
            client.peer.network_secret_digest,
            network_secret_digest("sec-net", "sec-secret")
        );

        // The sessions carry traffic for each other immediately.
        let mut hdr = PeerManagerHeader {
            from_peer_id: client_peer_id,
            to_peer_id: server_peer_id,
            packet_type: packet_type::DATA,
            flags: 0,
            forward_counter: 1,
            reserved: 0,
            len: 5,
        };
        let mut payload = b"hello".to_vec();
        client
            .session
            .encrypt_payload(client_peer_id, server_peer_id, &mut hdr, &mut payload)
            .unwrap();
        server
            .session
            .decrypt_payload(client_peer_id, server_peer_id, &mut hdr, &mut payload)
            .unwrap();
        assert_eq!(payload, b"hello");
    }

    #[tokio::test]
    async fn noise_handshake_rejects_wrong_secret() {
        // A client holding a DIFFERENT network secret fails the
        // server's proof check (verify_remote_auth rule 5).
        let (client_io, server_io) = tokio::io::duplex(8192);
        let mut client_io = client_io;
        let mut server_io = server_io;
        let client_ctx = secure_test_ctx("sec-net", "client-secret", None);
        let server_ctx = secure_test_ctx("sec-net", "server-secret", None);

        let server = tokio::spawn(async move {
            let first = recv_noise_frame(&mut server_io, packet_type::NOISE_HANDSHAKE_MSG1)
                .await
                .unwrap();
            noise_handshake_as_server(&mut server_io, 0xfeed_face, &server_ctx, first).await
        });
        let err = noise_handshake_as_client(&mut client_io, 0x42, &client_ctx)
            .await
            .unwrap_err()
            .to_string();
        let server_result = server.await.unwrap();
        // Either side rejects: the client cannot verify the server's
        // msg2 proof, the server cannot verify the client's msg3 proof.
        assert!(
            err.contains("authentication failed") || err.contains("proof"),
            "client error: {err}"
        );
        if let Err(server_err) = server_result {
            assert!(
                server_err.to_string().contains("authentication failed"),
                "server error: {server_err}"
            );
        }
    }

    #[tokio::test]
    async fn noise_handshake_pinned_key_mismatch_is_rejected() {
        // The dial-side pin (`peer-public-key`): with no network secret
        // the proof path cannot fire, so a pinned remote static that does
        // not match fails the handshake (verify_remote_auth rule 2,
        // peer_conn.rs:726-731). With a shared secret the proof wins
        // first — upstream checks in that order (peer_conn.rs:717-743).
        let (client_io, server_io) = tokio::io::duplex(8192);
        let mut client_io = client_io;
        let mut server_io = server_io;
        let wrong_pin = base64::engine::general_purpose::STANDARD.encode([7u8; 32]);
        let client_ctx = secure_test_ctx("sec-net", "", Some(&wrong_pin));
        let server_ctx = secure_test_ctx("sec-net", "", None);

        let server = tokio::spawn(async move {
            let first = recv_noise_frame(&mut server_io, packet_type::NOISE_HANDSHAKE_MSG1)
                .await
                .unwrap();
            let _ = noise_handshake_as_server(&mut server_io, 0x99, &server_ctx, first).await;
        });
        let err = noise_handshake_as_client(&mut client_io, 0x42, &client_ctx)
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("pinned remote static pubkey mismatch"), "{err}");
        let _ = server.await;
    }

    #[tokio::test]
    async fn serve_secure_mode_two_node_relay() {
        // THE secure-mode listener proof: `serve` with secure-mode
        // enabled, our own client dialing with a secure context — the
        // Noise_XX handshake, the session AEAD carrying the route RPC
        // gossip AND overlay data, ping/pong in the clear, all end to
        // end.
        let secret = format!("sec-{}", rand::random::<u64>());
        let network = "sec-relay";
        let port = 31000 + rand::random::<u16>() % 20000;
        let cfg = EasyTierConfig {
            listeners: vec![format!("tcp://127.0.0.1:{port}")],
            network_secret: secret.clone(),
            ipv4: Some("10.155.10.1/24".to_owned()),
            dhcp: false,
            hostname: Some("secure-serve".to_owned()),
            secure_mode: Some(true),
            ..EasyTierConfig::new("et-m6-secure-serve", network)
        };
        let server = serve(&cfg).await.unwrap();

        // The secure-mode mimic client (spawn_mimic_client's secure
        // sibling): same shape, dial_session with a SecureModeCtx.
        let overlay: Ipv4Addr = "10.155.10.2".parse().unwrap();
        let network_owned = network.to_owned();
        let secret_clone = secret.clone();
        let learned: LearnedRoutes = Arc::new(StdMutex::new(HashMap::new()));
        let accepted = Arc::new(AtomicU32::new(0));
        let echo_port = 9081u16;
        tokio::spawn(async move {
            let endpoint = PeerEndpoint {
                transport: PeerTransport::Tcp,
                host: "127.0.0.1".to_owned(),
                port,
            };
            let ctx = SecureModeCtx::new(&network_owned, &secret_clone, "", "aes-gcm", None)
                .unwrap();
            let encryptor = create_encryptor("aes-gcm", true, &secret_clone).unwrap();
            let Ok(halves) = dial_session(
                &endpoint,
                random_peer_id(),
                &network_owned,
                &secret_clone,
                encryptor,
                Some(&ctx),
            )
            .await
            else {
                return;
            };
            let mut stack = EtStack::new(
                halves.state.my_peer_id,
                &network_owned,
                "secure-mimic",
                DEFAULT_MTU,
                Some(overlay),
                24,
                false,
                vec![],
            );
            let (events_tx, events_rx) = mpsc::channel::<PeerEvent>(64);
            stack.attach_session(halves, true, &events_tx);
            run_mimic(stack, events_rx, learned, accepted, echo_port, echo_port + 1).await;
        });

        tokio::time::timeout(Duration::from_secs(15), server.wait_ready())
            .await
            .expect("secure-mode inbound peer did not sync in time")
            .unwrap();
        let nodes = server.overlay_nodes().await.unwrap();
        assert!(
            nodes.iter().any(|n| n.ipv4 == overlay),
            "node table {nodes:?} lacks the secure peer {overlay}"
        );
        // Overlay traffic through the session AEAD both ways.
        let target = SocketAddr::V4(SocketAddrV4::new(overlay, echo_port));
        let mut stream =
            tokio::time::timeout(Duration::from_secs(15), connect_tcp(&cfg, &target))
                .await
                .expect("dial through the secure peer")
                .expect("connect_tcp via the secure listener");
        stream.write_all(b"secure-relay").await.unwrap();
        let mut buf = [0u8; 16];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"secure-relay");
        server.shutdown().await;
    }

    #[tokio::test]
    async fn serve_secure_mode_accepts_plain_peer_too() {
        // A secure-enabled server still accepts a PLAIN handshake
        // (peer_conn.rs:1252-1275: the noise path only claims a msg1
        // first packet).
        let secret = format!("secmix-{}", rand::random::<u64>());
        let network = "sec-mixed";
        let port = 31000 + rand::random::<u16>() % 20000;
        let cfg = EasyTierConfig {
            listeners: vec![format!("tcp://127.0.0.1:{port}")],
            network_secret: secret.clone(),
            ipv4: Some("10.156.10.1/24".to_owned()),
            dhcp: false,
            hostname: Some("mixed-serve".to_owned()),
            secure_mode: Some(true),
            ..EasyTierConfig::new("et-m6-mixed", network)
        };
        let server = serve(&cfg).await.unwrap();
        let (mimic_ip, echo_port) = spawn_mimic_client(
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port)),
            network,
            &secret,
            "10.156.10.2",
            24,
        )
        .await;
        tokio::time::timeout(Duration::from_secs(15), server.wait_ready())
            .await
            .expect("plain peer did not sync in time")
            .unwrap();
        let target = SocketAddr::V4(SocketAddrV4::new(mimic_ip, echo_port));
        let mut stream =
            tokio::time::timeout(Duration::from_secs(15), connect_tcp(&cfg, &target))
                .await
                .expect("dial through the plain peer")
                .expect("connect_tcp via the mixed listener");
        stream.write_all(b"plain-still-works").await.unwrap();
        let mut buf = [0u8; 24];
        let n = stream.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"plain-still-works");
        server.shutdown().await;
    }

    /// Run the real binary with the common interop flags; returns the
    /// child (killed on drop).
    fn spawn_real_binary(
        bin: &str,
        network: &str,
        secret: &str,
        extra: &[&str],
    ) -> KillChild {
        let mut command = std::process::Command::new(bin);
        command.args(["--network-name", network, "--network-secret", secret]);
        for arg in extra {
            command.arg(arg);
        }
        if std::env::var("EASYTIER_VERBOSE").is_ok() {
            command
                .arg("--console-log-level")
                .arg("trace")
                .stderr(std::process::Stdio::inherit());
        } else {
            command.stderr(std::process::Stdio::null());
        }
        KillChild(command.spawn().expect("spawn easytier-core"))
    }

    /// The SOCKS5-greeting proof used by every real-binary test: dial
    /// the binary's socks5 port through the overlay and read the
    /// no-auth method selection.
    async fn assert_socks5_on_overlay(cfg: &EasyTierConfig, socks5_port: u16) {
        let socks5: SocketAddr = format!("10.126.126.1:{socks5_port}").parse().unwrap();
        let mut stream =
            tokio::time::timeout(Duration::from_secs(25), connect_tcp(cfg, &socks5))
                .await
                .expect("dial through the real node timed out")
                .expect("dial through the real node");
        stream.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greeting = [0u8; 2];
        stream.read_exact(&mut greeting).await.unwrap();
        assert_eq!(&greeting, &[0x05, 0x00], "socks5 greeting");
    }

    /// [`assert_socks5_through_overlay`] at the conventional socks5 port
    /// (the secure-mode interops bind distinct ports so their binaries
    /// may run concurrently).
    async fn assert_socks5_through_overlay(cfg: &EasyTierConfig) {
        assert_socks5_on_overlay(cfg, 1080).await;
    }

    /// A local non-loopback IPv4 the real binary can dial. Its v2.6.4
    /// connector binds one socket per local interface IP
    /// (`set_bind_addrs`, connector/mod.rs:70-77) and races them —
    /// loopback targets never answer from those LAN sources, so the
    /// inbound interop listens on 0.0.0.0 and is dialed on the LAN
    /// address (the UDP-connect routing trick; no packet leaves).
    fn dialable_lan_ip() -> Option<Ipv4Addr> {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
        socket.connect("8.8.8.8:80").ok()?;
        match socket.local_addr().ok()? {
            SocketAddr::V4(v4) if !v4.ip().is_loopback() => Some(*v4.ip()),
            _ => None,
        }
    }

    #[tokio::test]
    #[ignore = "needs a real easytier-core binary; set EASYTIER_BIN to enable"]
    async fn real_easytier_binary_dials_our_listener() {
        // THE M3 interop: the real binary connects to OUR listener as an
        // inbound peer, joins our node, gossips routes, and we relay
        // overlay TCP through it.
        let Ok(bin) = std::env::var("EASYTIER_BIN") else {
            eprintln!("skipping: EASYTIER_BIN is not set");
            return;
        };
        let Some(lan_ip) = dialable_lan_ip() else {
            eprintln!("skipping: no dialable non-loopback local IP");
            return;
        };
        let network = format!("itnet-{}", rand::random::<u32>());
        let secret = format!("itsec-{}", rand::random::<u64>());
        let port = 31000 + rand::random::<u16>() % 20000;
        let _child = spawn_real_binary(
            &bin,
            &network,
            &secret,
            &[
                "-p",
                &format!("tcp://{lan_ip}:{port}"),
                "--no-listener",
                "--no-tun",
                "-i",
                "10.126.126.1",
                "--hostname",
                "real-node",
                "--socks5",
                "1080",
            ],
        );
        let cfg = EasyTierConfig {
            listeners: vec![format!("tcp://0.0.0.0:{port}")],
            network_secret: secret,
            ipv4: Some("10.126.126.2/24".to_owned()),
            dhcp: false,
            hostname: Some("rustcrash-m3".to_owned()),
            ..EasyTierConfig::new("et-real-listener", &network)
        };
        let server = serve(&cfg).await.unwrap();
        tokio::time::timeout(Duration::from_secs(25), server.wait_ready())
            .await
            .expect("the real node did not sync in time")
            .unwrap();
        assert_socks5_through_overlay(&cfg).await;
        server.shutdown().await;
    }

    #[tokio::test]
    #[ignore = "needs a real easytier-core binary; set EASYTIER_BIN to enable"]
    async fn real_easytier_binary_serving_udp() {
        // The real binary's UDP listener: our `udp://` peer dial rides
        // the datagram circuit into the real core.
        let Ok(bin) = std::env::var("EASYTIER_BIN") else {
            eprintln!("skipping: EASYTIER_BIN is not set");
            return;
        };
        let network = format!("itnet-{}", rand::random::<u32>());
        let secret = format!("itsec-{}", rand::random::<u64>());
        let port = 31000 + rand::random::<u16>() % 20000;
        let _child = spawn_real_binary(
            &bin,
            &network,
            &secret,
            &[
                "-l",
                &format!("udp://127.0.0.1:{port}"),
                "--no-tun",
                "-i",
                "10.126.126.1",
                "--hostname",
                "real-udp-node",
                "--socks5",
                "1080",
            ],
        );
        // Give the node time to bind its listener.
        tokio::time::sleep(Duration::from_secs(2)).await;
        let cfg = EasyTierConfig {
            peers: vec![format!("udp://127.0.0.1:{port}")],
            network_secret: secret,
            ipv4: Some("10.126.126.2/24".to_owned()),
            dhcp: false,
            hostname: Some("rustcrash-m3-udp".to_owned()),
            ..EasyTierConfig::new("et-real-udp", &network)
        };
        assert_socks5_through_overlay(&cfg).await;
    }

    #[tokio::test]
    #[ignore = "needs a real easytier-core binary; set EASYTIER_BIN to enable"]
    async fn real_easytier_binary_secure_mode_serving() {
        // THE M6 interop (client direction): the real binary runs a
        // secure-mode network (`--secure-mode`); our node dials it with
        // the Noise_XX handshake, the session AEAD carries the route RPC
        // gossip and the overlay traffic end to end.
        let Ok(bin) = std::env::var("EASYTIER_BIN") else {
            eprintln!("skipping: EASYTIER_BIN is not set");
            return;
        };
        let network = format!("itnet-{}", rand::random::<u32>());
        let secret = format!("itsec-{}", rand::random::<u64>());
        let port = 31000 + rand::random::<u16>() % 20000;
        // A random socks5 port: the interops may run concurrently and the
        // conventional 1080 (plus any fixed port) can be taken by another
        // test's binary or an unrelated local service.
        let socks5_port: u16 = 21000 + rand::random::<u16>() % 20000;
        let _child = spawn_real_binary(
            &bin,
            &network,
            &secret,
            &[
                "-l",
                &format!("tcp://127.0.0.1:{port}"),
                "--secure-mode",
                "--no-tun",
                "-i",
                "10.126.126.1",
                "--hostname",
                "real-sec-node",
                "--socks5",
                &socks5_port.to_string(),
            ],
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
        let cfg = EasyTierConfig {
            peers: vec![format!("tcp://127.0.0.1:{port}")],
            network_secret: secret,
            ipv4: Some("10.126.126.2/24".to_owned()),
            dhcp: false,
            hostname: Some("rustcrash-m6-sec".to_owned()),
            secure_mode: Some(true),
            ..EasyTierConfig::new("et-real-secure", &network)
        };
        assert_socks5_on_overlay(&cfg, socks5_port).await;
    }

    #[tokio::test]
    #[ignore = "needs a real easytier-core binary; set EASYTIER_BIN to enable"]
    async fn real_easytier_binary_secure_mode_dials_our_listener() {
        // THE M6 interop (server direction): WE serve a secure-mode
        // network; the real binary connects with `--secure-mode` and its
        // msg1 goes through our responder handshake (Create verdict, the
        // session AEAD from the store).
        let Ok(bin) = std::env::var("EASYTIER_BIN") else {
            eprintln!("skipping: EASYTIER_BIN is not set");
            return;
        };
        let Some(lan_ip) = dialable_lan_ip() else {
            eprintln!("skipping: no dialable non-loopback local IP");
            return;
        };
        let network = format!("itnet-{}", rand::random::<u32>());
        let secret = format!("itsec-{}", rand::random::<u64>());
        let port = 31000 + rand::random::<u16>() % 20000;
        let _child = spawn_real_binary(
            &bin,
            &network,
            &secret,
            &[
                "-p",
                &format!("tcp://{lan_ip}:{port}"),
                "--secure-mode",
                "--no-listener",
                "--no-tun",
                "-i",
                "10.126.126.1",
                "--hostname",
                "real-sec-node",
                "--socks5",
                "1080",
            ],
        );
        let cfg = EasyTierConfig {
            listeners: vec![format!("tcp://0.0.0.0:{port}")],
            network_secret: secret,
            ipv4: Some("10.126.126.2/24".to_owned()),
            dhcp: false,
            hostname: Some("rustcrash-m6-serve".to_owned()),
            secure_mode: Some(true),
            ..EasyTierConfig::new("et-real-secure-serve", &network)
        };
        let server = serve(&cfg).await.unwrap();
        tokio::time::timeout(Duration::from_secs(25), server.wait_ready())
            .await
            .expect("the real secure node did not sync in time")
            .unwrap();
        assert_socks5_through_overlay(&cfg).await;
        server.shutdown().await;
    }

    #[tokio::test]
    #[ignore = "needs a real easytier-core binary; set EASYTIER_BIN to enable"]
    async fn real_easytier_binary_dials_our_udp_listener() {
        // The reverse: the real binary connects INTO our udp:// listener
        // (dialed on the LAN address — see `dialable_lan_ip`).
        let Ok(bin) = std::env::var("EASYTIER_BIN") else {
            eprintln!("skipping: EASYTIER_BIN is not set");
            return;
        };
        let Some(lan_ip) = dialable_lan_ip() else {
            eprintln!("skipping: no dialable non-loopback local IP");
            return;
        };
        let network = format!("itnet-{}", rand::random::<u32>());
        let secret = format!("itsec-{}", rand::random::<u64>());
        let port = 31000 + rand::random::<u16>() % 20000;
        let _child = spawn_real_binary(
            &bin,
            &network,
            &secret,
            &[
                "-p",
                &format!("udp://{lan_ip}:{port}"),
                "--no-listener",
                "--no-tun",
                "-i",
                "10.126.126.1",
                "--hostname",
                "real-node",
                "--socks5",
                "1080",
            ],
        );
        let cfg = EasyTierConfig {
            listeners: vec![format!("udp://0.0.0.0:{port}")],
            network_secret: secret,
            ipv4: Some("10.126.126.2/24".to_owned()),
            dhcp: false,
            hostname: Some("rustcrash-m3".to_owned()),
            ..EasyTierConfig::new("et-real-udp-listener", &network)
        };
        let server = serve(&cfg).await.unwrap();
        tokio::time::timeout(Duration::from_secs(25), server.wait_ready())
            .await
            .expect("the real node did not sync in time")
            .unwrap();
        assert_socks5_through_overlay(&cfg).await;
        server.shutdown().await;
    }

    // ========================================================================
    // M4: the QUIC + WebSocket transports
    // ========================================================================
    // (The four interop tests below each spawn the real binary with
    // `--socks5 1080` — the shared assertion port — so the ignored set
    // must run with `--test-threads=1` when more than one is enabled.)

    #[test]
    fn quic_plaintext_seahash_matches_reference_crate() {
        // Digests produced by the REAL seahash 4.1.0 driven exactly the
        // way quinn-plaintext 0.3.0 drives it (`header.hash(&mut hasher);
        // payload.hash(&mut hasher)` over std's `Hash for [u8]`, i.e.
        // write_usize(len) + write(bytes) per member): the in-tree
        // SeaHasher must reproduce them bit for bit or every packet the
        // real binary sends fails its integrity check.
        let cases: &[(&[u8], &[u8], u64)] = &[
            (&[], &[], 15605663169668837975),
            (&[0x45, 0, 0, 10], &[1, 2, 3, 4, 5, 6], 14432687309312439075),
            (
                &0u64.to_le_bytes(),
                b"abcdefgh",
                2896981824816784093,
            ),
            (&[0x11u8; 3], &0u64.to_le_bytes(), 4620115072304201297),
            (&1200u64.to_le_bytes(), &[0xabu8; 1200], 15336253554449442413),
            (&8u64.to_le_bytes(), &[0u8; 8], 4785788110206384021),
            (&16u64.to_le_bytes(), &[0xffu8; 16], 681446427028685233),
            (&5u64.to_le_bytes(), &[9, 8, 7, 6, 5], 11526691439214515923),
            (&0u64.to_le_bytes(), &[], 11560770652361694180),
            (
                &[1, 2, 3, 4, 5, 6, 7],
                &[
                    8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
                    27, 28, 29, 30, 31, 32, 33, 34, 35,
                ],
                1067341436300427410,
            ),
        ];
        for (header, payload, expected) in cases {
            let got = quic_plaintext::packet_tag(header, payload);
            assert_eq!(got, *expected, "header {header:?} payload len {}", payload.len());
        }
    }

    #[test]
    fn quic_plaintext_encrypt_decrypt_roundtrip() {
        // One packet: header || payload || tag, like quinn hands it to
        // PacketKey::encrypt — and the decrypt mirror strips and checks
        // the tag (`PlaintextPacketKey`, quinn-plaintext lib.rs:281-325).
        use quinn_proto::crypto::PacketKey as _;
        let key = quic_plaintext::PlaintextPacketKey;
        assert_eq!(key.tag_len(), 8);
        let header = [0x40u8, 0x01, 0x02, 0x03, 0x04];
        let payload = b"easytier plaintext quic".to_vec();
        let mut buf = header.to_vec();
        buf.extend_from_slice(&payload);
        buf.extend_from_slice(&[0u8; 8]); // tag space
        // encrypt writes only the tag into the tail (payload untouched).
        key.encrypt(0, &mut buf, header.len());
        assert_eq!(&buf[..header.len()], &header);
        assert_eq!(&buf[header.len()..header.len() + payload.len()], &payload);
        let tag = &buf[buf.len() - 8..];
        assert_eq!(
            u64::from_be_bytes(tag.try_into().unwrap()),
            quic_plaintext::packet_tag(&header, &payload)
        );
        // The decrypt mirror strips and verifies the tag (quinn hands
        // PacketKey::decrypt the payload WITHOUT the header).
        let mut bytes = bytes::BytesMut::from(&buf[header.len()..]);
        key.decrypt(0, &header, &mut bytes).unwrap();
        assert_eq!(&bytes[..], &payload[..]);
        let mut bad = bytes::BytesMut::from(&buf[header.len()..]);
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert!(key.decrypt(0, &header, &mut bad).is_err());
    }

    #[tokio::test]
    async fn quic_tunnel_pingpong() {
        // QuicTunnelListener + QuicTunnelConnector over the in-tree
        // plaintext crypto: both directions of the M1 framing over the
        // one bi-stream (upstream `quic_pingpong`, quic.rs:661-669).
        let mut listener = QuicVtListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr();
        let server = tokio::spawn(async move {
            let mut tunnel = listener.accept().await.unwrap();
            let packet = read_frame(&mut tunnel).await.unwrap().unwrap();
            write_frame(&mut tunnel, &packet).await.unwrap();
            // Hold the connection until the client is done reading
            // (dropping closes it with 0/"done", which discards
            // unacknowledged stream data — the ConnWrapper semantics).
            let _ = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut tunnel)).await;
        });
        let mut client = tokio::time::timeout(Duration::from_secs(5), connect_quic_tunnel(addr))
            .await
            .expect("quic connect timeout")
            .unwrap();
        let original = PeerPacket::new(0x1111, 0x2222, packet_type::DATA, b"quic-echo");
        write_frame(&mut client, &original).await.unwrap();
        let echoed = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut client))
            .await
            .expect("quic echo timeout")
            .unwrap()
            .unwrap();
        assert_eq!(echoed, original);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn quic_transport_peer_session() {
        // The full client/server peer session over quic:// — handshake,
        // identity check, the post-dial liveness ping and a Data packet
        // through the AEAD packet encryption (the `add_tunnel_as_client`
        // / `add_tunnel_as_server` pair on the QUIC transport).
        let mut listener = QuicVtListener::bind("127.0.0.1:0".parse().unwrap()).unwrap();
        let addr = listener.local_addr();
        let secret = test_secret();
        let encryptor = create_encryptor("aes-gcm", true, &secret).unwrap();
        let server_secret = secret.clone();
        let server = tokio::spawn(async move {
            let tunnel = listener.accept().await.unwrap();
            let (mut halves, peer) =
                serve_peer_as(tunnel, 0xdead_beef, "mesh", &server_secret, encryptor, None)
                    .await
                    .unwrap();
            assert_eq!(peer.peer_id, 0x0000_0042);
            let frame = halves.data_rx.recv().await.unwrap();
            (peer, frame)
        });
        let endpoint = PeerEndpoint {
            transport: PeerTransport::Quic,
            host: "127.0.0.1".into(),
            port: addr.port(),
        };
        let node = connect_peer_as(
            &endpoint,
            0x0000_0042,
            "mesh",
            &secret,
            create_encryptor("aes-gcm", true, &secret).unwrap(),
            None,
        )
        .await
        .unwrap();
        let latency = node.ping().await.unwrap();
        assert!(latency < Duration::from_secs(2));
        node.send_packet(packet_type::DATA, b"quic-ip-frame")
            .await
            .unwrap();
        let (peer, frame) = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("server session timed out")
            .unwrap();
        assert_eq!(peer.network_name, "mesh");
        assert_eq!(frame, b"quic-ip-frame");
        node.close().await;
    }

    #[test]
    fn ws_accept_key_rfc6455_vector() {
        // The RFC 6455 §4.2.2 sample: the same computation the listener
        // answers upgrades with (and the client validates).
        assert_eq!(
            ws_accept_key("dGhlIHNhbXBsZSBub25jZQ=="),
            "s3pPLMBiTxaQ9kYGzzhZRbK+xOo="
        );
    }

    #[test]
    fn ws_frame_build_parse_roundtrip() {
        // Masked (client) and unmasked (server) forms, both lengths forms
        // the peer frames can use.
        let payloads: [Vec<u8>; 3] = [Vec::new(), b"x".to_vec(), vec![7u8; 200]];
        for payload in &payloads {
            let masked = ws_frame(WS_OP_BINARY, payload, true);
            assert_eq!(masked[1] & 0x80, 0x80, "client frame is masked");
            let parsed = ws_parse_frame(&masked).unwrap().unwrap();
            assert_eq!(parsed.opcode, WS_OP_BINARY);
            assert!(parsed.fin);
            assert_eq!(parsed.payload, *payload);
            let plain = ws_frame(WS_OP_BINARY, payload, false);
            assert_eq!(plain[1] & 0x80, 0, "server frame is unmasked");
            let parsed = ws_parse_frame(&plain).unwrap().unwrap();
            assert_eq!(parsed.payload, *payload);
        }
        // Truncated frames wait for more bytes.
        let frame = ws_frame(WS_OP_BINARY, &vec![1u8; 300], false);
        assert!(ws_parse_frame(&frame[..frame.len() - 1]).unwrap().is_none());
        // RSV bits are refused (no extensions negotiated).
        let mut bad = ws_frame(WS_OP_BINARY, b"x", false);
        bad[0] |= 0x40;
        assert!(ws_parse_frame(&bad).is_err());
    }

    #[tokio::test]
    async fn ws_wire_message_has_no_length_prefix() {
        // THE ws mapping (`sink_from_zc_packet`): one binary message per
        // peer frame, WITHOUT the u32 length prefix the TCP tunnel
        // carries — asserted on the raw wire by a hand-rolled server
        // that answers the upgrade itself and inspects the first frame.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tap_addr = listener.local_addr().unwrap();
        let observed = tokio::spawn(async move {
            use tokio::io::AsyncReadExt as _;
            let (mut raw, _) = listener.accept().await.unwrap();
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            // The upgrade request.
            loop {
                raw.read_exact(&mut byte).await.unwrap();
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&buf).into_owned();
            let key = ws_header(&head, "sec-websocket-key").unwrap().to_owned();
            raw.write_all(
                format!(
                    "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\
                     Connection: Upgrade\r\nSec-WebSocket-Accept: {}\r\n\r\n",
                    ws_accept_key(&key)
                )
                .as_bytes(),
            )
            .await
            .unwrap();
            // First frame header: opcode + masked length.
            let mut hdr = [0u8; 2];
            raw.read_exact(&mut hdr).await.unwrap();
            (hdr[0] & 0x0f, hdr[1] & 0x7f)
        });
        let mut client = tokio::time::timeout(
            Duration::from_secs(5),
            connect_ws_tunnel(&PeerEndpoint {
                transport: PeerTransport::Ws,
                host: "127.0.0.1".into(),
                port: tap_addr.port(),
            }),
        )
        .await
        .expect("ws connect timeout")
        .unwrap();
        let packet = PeerPacket::new(1, 2, packet_type::DATA, b"abcd");
        write_frame(&mut client, &packet).await.unwrap();
        let (opcode, len) = tokio::time::timeout(Duration::from_secs(5), observed)
            .await
            .expect("tap timed out")
            .unwrap();
        assert_eq!(opcode, WS_OP_BINARY);
        // 16-byte PeerManagerHeader + 4 payload, NO 4-byte length prefix.
        assert_eq!(len as usize, PEER_MANAGER_HEADER_SIZE + 4);
    }

    #[tokio::test]
    async fn ws_tunnel_pingpong() {
        // WsVtListener + connect_ws_tunnel: both directions of the peer
        // framing through the message adapter (upstream `ws_pingpong`,
        // websocket.rs:341-346).
        let mut listener = WsVtListener::bind(&PeerEndpoint {
            transport: PeerTransport::Ws,
            host: "127.0.0.1".into(),
            port: 0,
        })
        .await
        .unwrap();
        let endpoint = PeerEndpoint {
            transport: PeerTransport::Ws,
            host: "127.0.0.1".into(),
            port: listener.local_addr().port(),
        };
        let server = tokio::spawn(async move {
            let mut tunnel = listener.accept().await.unwrap();
            let packet = read_frame(&mut tunnel).await.unwrap().unwrap();
            write_frame(&mut tunnel, &packet).await.unwrap();
        });
        let mut client = tokio::time::timeout(Duration::from_secs(5), connect_ws_tunnel(&endpoint))
            .await
            .expect("ws connect timeout")
            .unwrap();
        let original = PeerPacket::new(0x1111, 0x2222, packet_type::DATA, b"ws-echo");
        write_frame(&mut client, &original).await.unwrap();
        let echoed = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut client))
            .await
            .expect("ws echo timeout")
            .unwrap()
            .unwrap();
        assert_eq!(echoed, original);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn ws_transport_peer_session() {
        // The full peer session over ws:// — the quic session test's
        // twin.
        let mut listener = WsVtListener::bind(&PeerEndpoint {
            transport: PeerTransport::Ws,
            host: "127.0.0.1".into(),
            port: 0,
        })
        .await
        .unwrap();
        let endpoint = PeerEndpoint {
            transport: PeerTransport::Ws,
            host: "127.0.0.1".into(),
            port: listener.local_addr().port(),
        };
        let secret = test_secret();
        let server_secret = secret.clone();
        let server = tokio::spawn(async move {
            let tunnel = listener.accept().await.unwrap();
            let (mut halves, peer) = serve_peer_as(
                tunnel,
                0xdead_beef,
                "mesh",
                &server_secret,
                create_encryptor("aes-gcm", true, &server_secret).unwrap(),
                None,
            )
            .await
            .unwrap();
            let frame = halves.data_rx.recv().await.unwrap();
            (peer, frame)
        });
        let node = connect_peer_as(
            &endpoint,
            0x0000_0042,
            "mesh",
            &secret,
            create_encryptor("aes-gcm", true, &secret).unwrap(),
            None,
        )
        .await
        .unwrap();
        node.ping().await.unwrap();
        node.send_packet(packet_type::DATA, b"ws-ip-frame")
            .await
            .unwrap();
        let (peer, frame) = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("server session timed out")
            .unwrap();
        assert_eq!(peer.peer_id, 0x0000_0042);
        assert_eq!(frame, b"ws-ip-frame");
        node.close().await;
    }

    #[tokio::test]
    async fn wss_transport_client_to_our_listener() {
        // wss end to end against the in-tree self-signed cert: rustls
        // client (insecure, like every easytier wss peer) over the
        // hand-rolled DER certificate, then the message-mapped frames.
        let mut listener = WsVtListener::bind(&PeerEndpoint {
            transport: PeerTransport::Wss,
            host: "127.0.0.1".into(),
            port: 0,
        })
        .await
        .unwrap();
        let endpoint = PeerEndpoint {
            transport: PeerTransport::Wss,
            host: "127.0.0.1".into(),
            port: listener.local_addr().port(),
        };
        let server = tokio::spawn(async move {
            let mut tunnel = listener.accept().await.unwrap();
            let packet = read_frame(&mut tunnel).await.unwrap().unwrap();
            write_frame(&mut tunnel, &packet).await.unwrap();
        });
        let mut client = tokio::time::timeout(Duration::from_secs(5), connect_ws_tunnel(&endpoint))
            .await
            .expect("wss connect timeout")
            .unwrap();
        let original = PeerPacket::new(1, 2, packet_type::PING, &[1, 2, 3, 4]);
        write_frame(&mut client, &original).await.unwrap();
        let echoed = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut client))
            .await
            .expect("wss echo timeout")
            .unwrap()
            .unwrap();
        assert_eq!(echoed, original);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn serve_quic_listener_two_node_mesh() {
        // The M3 mesh pattern on the QUIC transport: serve() binds
        // quic://, the client comes up through the registry path
        // (`EasyTierUdp::bind` — the node that attaches the route
        // gossip), dials it, the inbound peer joins the node and the
        // route exchange completes on BOTH ends.
        let network = format!("mesh-{}", rand::random::<u32>());
        let secret = test_secret();
        let server_cfg = EasyTierConfig {
            listeners: vec!["quic://127.0.0.1:0".into()],
            network_secret: secret.clone(),
            ipv4: Some("10.144.144.1/24".to_owned()),
            dhcp: false,
            hostname: Some("rustcrash-m4-quic".to_owned()),
            ..EasyTierConfig::new("et-m4-quic", &network)
        };
        let server = serve(&server_cfg).await.unwrap();
        let port = server.local_addrs()[0].port();
        let client_cfg = EasyTierConfig {
            peers: vec![format!("quic://127.0.0.1:{port}")],
            network_secret: secret,
            ipv4: Some("10.144.144.2/24".to_owned()),
            dhcp: false,
            hostname: Some("rustcrash-m4-quic-b".to_owned()),
            ..EasyTierConfig::new("et-m4-quic-b", &network)
        };
        // The client's own readiness IS the route-exchange proof (it
        // waits for a finished gossip round against the server).
        let _udp = tokio::time::timeout(Duration::from_secs(20), EasyTierUdp::bind(&client_cfg))
            .await
            .expect("quic mesh route exchange timed out")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(20), server.wait_ready())
            .await
            .expect("server route exchange timed out")
            .unwrap();
        let nodes = server.overlay_nodes().await.unwrap();
        assert_eq!(nodes.len(), 2, "both overlay nodes gossiped");
        server.shutdown().await;
    }

    #[tokio::test]
    async fn serve_ws_listener_two_node_mesh() {
        // The same proof over ws://.
        let network = format!("mesh-{}", rand::random::<u32>());
        let secret = test_secret();
        let server_cfg = EasyTierConfig {
            listeners: vec!["ws://127.0.0.1:0".into()],
            network_secret: secret.clone(),
            ipv4: Some("10.144.145.1/24".to_owned()),
            dhcp: false,
            hostname: Some("rustcrash-m4-ws".to_owned()),
            ..EasyTierConfig::new("et-m4-ws", &network)
        };
        let server = serve(&server_cfg).await.unwrap();
        let port = server.local_addrs()[0].port();
        let client_cfg = EasyTierConfig {
            peers: vec![format!("ws://127.0.0.1:{port}")],
            network_secret: secret,
            ipv4: Some("10.144.145.2/24".to_owned()),
            dhcp: false,
            hostname: Some("rustcrash-m4-ws-b".to_owned()),
            ..EasyTierConfig::new("et-m4-ws-b", &network)
        };
        let _udp = tokio::time::timeout(Duration::from_secs(20), EasyTierUdp::bind(&client_cfg))
            .await
            .expect("ws mesh route exchange timed out")
            .unwrap();
        tokio::time::timeout(Duration::from_secs(20), server.wait_ready())
            .await
            .expect("server route exchange timed out")
            .unwrap();
        let nodes = server.overlay_nodes().await.unwrap();
        assert_eq!(nodes.len(), 2, "both overlay nodes gossiped");
        server.shutdown().await;
    }

    #[tokio::test]
    #[ignore = "needs a real easytier-core binary; set EASYTIER_BIN to enable"]
    async fn real_easytier_binary_serving_quic() {
        // The real binary's QUIC listener: our quic:// peer dial rides
        // the plaintext-QUIC tunnel into the real core — the proof the
        // in-tree quinn-plaintext port is wire-identical.
        let Ok(bin) = std::env::var("EASYTIER_BIN") else {
            eprintln!("skipping: EASYTIER_BIN is not set");
            return;
        };
        let network = format!("itnet-{}", rand::random::<u32>());
        let secret = format!("itsec-{}", rand::random::<u64>());
        let port = 31000 + rand::random::<u16>() % 20000;
        let _child = spawn_real_binary(
            &bin,
            &network,
            &secret,
            &[
                "-l",
                &format!("quic://127.0.0.1:{port}"),
                "--no-tun",
                "-i",
                "10.126.126.1",
                "--hostname",
                "real-quic-node",
                "--socks5",
                "1080",
            ],
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
        let cfg = EasyTierConfig {
            peers: vec![format!("quic://127.0.0.1:{port}")],
            network_secret: secret,
            ipv4: Some("10.126.126.2/24".to_owned()),
            dhcp: false,
            hostname: Some("rustcrash-m4-quic".to_owned()),
            ..EasyTierConfig::new("et-real-quic", &network)
        };
        assert_socks5_through_overlay(&cfg).await;
    }

    #[tokio::test]
    #[ignore = "needs a real easytier-core binary; set EASYTIER_BIN to enable"]
    async fn real_easytier_binary_serving_ws() {
        // The real binary's WebSocket listener: our ws:// peer dial
        // through the hand-rolled RFC 6455 client.
        let Ok(bin) = std::env::var("EASYTIER_BIN") else {
            eprintln!("skipping: EASYTIER_BIN is not set");
            return;
        };
        let network = format!("itnet-{}", rand::random::<u32>());
        let secret = format!("itsec-{}", rand::random::<u64>());
        let port = 31000 + rand::random::<u16>() % 20000;
        let _child = spawn_real_binary(
            &bin,
            &network,
            &secret,
            &[
                "-l",
                &format!("ws://127.0.0.1:{port}"),
                "--no-tun",
                "-i",
                "10.126.126.1",
                "--hostname",
                "real-ws-node",
                "--socks5",
                "1080",
            ],
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
        let cfg = EasyTierConfig {
            peers: vec![format!("ws://127.0.0.1:{port}")],
            network_secret: secret,
            ipv4: Some("10.126.126.2/24".to_owned()),
            dhcp: false,
            hostname: Some("rustcrash-m4-ws".to_owned()),
            ..EasyTierConfig::new("et-real-ws", &network)
        };
        assert_socks5_through_overlay(&cfg).await;
    }

    #[tokio::test]
    #[ignore = "needs a real easytier-core binary; set EASYTIER_BIN to enable"]
    async fn real_easytier_binary_dials_our_quic_listener() {
        // The reverse: the real binary's QUIC connector into OUR
        // quic:// listener (dialed on the LAN address — the v2.6.4
        // connector's bind-addrs racing, see `dialable_lan_ip`).
        let Ok(bin) = std::env::var("EASYTIER_BIN") else {
            eprintln!("skipping: EASYTIER_BIN is not set");
            return;
        };
        let Some(lan_ip) = dialable_lan_ip() else {
            eprintln!("skipping: no dialable non-loopback local IP");
            return;
        };
        let network = format!("itnet-{}", rand::random::<u32>());
        let secret = format!("itsec-{}", rand::random::<u64>());
        let port = 31000 + rand::random::<u16>() % 20000;
        let _child = spawn_real_binary(
            &bin,
            &network,
            &secret,
            &[
                "-p",
                &format!("quic://{lan_ip}:{port}"),
                "--no-listener",
                "--no-tun",
                "-i",
                "10.126.126.1",
                "--hostname",
                "real-node",
                "--socks5",
                "1080",
            ],
        );
        let cfg = EasyTierConfig {
            listeners: vec![format!("quic://0.0.0.0:{port}")],
            network_secret: secret,
            ipv4: Some("10.126.126.2/24".to_owned()),
            dhcp: false,
            hostname: Some("rustcrash-m4".to_owned()),
            ..EasyTierConfig::new("et-real-quic-listener", &network)
        };
        let server = serve(&cfg).await.unwrap();
        tokio::time::timeout(Duration::from_secs(25), server.wait_ready())
            .await
            .expect("the real node did not sync in time")
            .unwrap();
        assert_socks5_through_overlay(&cfg).await;
        server.shutdown().await;
    }

    #[tokio::test]
    #[ignore = "needs a real easytier-core binary; set EASYTIER_BIN to enable"]
    async fn real_easytier_binary_dials_our_ws_listener() {
        // The real binary's WebSocket connector into OUR ws:// listener.
        let Ok(bin) = std::env::var("EASYTIER_BIN") else {
            eprintln!("skipping: EASYTIER_BIN is not set");
            return;
        };
        let Some(lan_ip) = dialable_lan_ip() else {
            eprintln!("skipping: no dialable non-loopback local IP");
            return;
        };
        let network = format!("itnet-{}", rand::random::<u32>());
        let secret = format!("itsec-{}", rand::random::<u64>());
        let port = 31000 + rand::random::<u16>() % 20000;
        let _child = spawn_real_binary(
            &bin,
            &network,
            &secret,
            &[
                "-p",
                &format!("ws://{lan_ip}:{port}"),
                "--no-listener",
                "--no-tun",
                "-i",
                "10.126.126.1",
                "--hostname",
                "real-node",
                "--socks5",
                "1080",
            ],
        );
        let cfg = EasyTierConfig {
            listeners: vec![format!("ws://0.0.0.0:{port}")],
            network_secret: secret,
            ipv4: Some("10.126.126.2/24".to_owned()),
            dhcp: false,
            hostname: Some("rustcrash-m4".to_owned()),
            ..EasyTierConfig::new("et-real-ws-listener", &network)
        };
        let server = serve(&cfg).await.unwrap();
        tokio::time::timeout(Duration::from_secs(25), server.wait_ready())
            .await
            .expect("the real node did not sync in time")
            .unwrap();
        assert_socks5_through_overlay(&cfg).await;
        server.shutdown().await;
    }

    // ========================================================================
    // M5: the WireGuard transport
    // ========================================================================

    #[test]
    fn wg_synthetic_ip_header_roundtrip() {
        // fill_ip_header (wireguard.rs:318-331): 0x45, big-endian total
        // length = 20 + datagram, TTL 64, protocol/checksum/addresses zero.
        let datagram = [7u8; 32];
        let ip = wg_ip_packet(&datagram);
        assert_eq!(ip.len(), 52);
        assert_eq!(ip[0], 0x45);
        assert_eq!(&ip[2..4], &52u16.to_be_bytes());
        assert_eq!(ip[8], 64);
        assert!(ip[1..2].iter().all(|b| *b == 0));
        assert!(ip[9..12].iter().all(|b| *b == 0));
        assert!(ip[12..20].iter().all(|b| *b == 0));
        // remove_ip_header (wireguard.rs:333-335): 20 bytes off a v4
        // packet, 40 off a v6 one.
        assert_eq!(wg_strip_ip_header(&ip), &datagram[..]);
        let mut v6 = vec![0x60u8];
        v6.extend_from_slice(&[0u8; 39]);
        v6.extend_from_slice(&datagram);
        assert_eq!(wg_strip_ip_header(&v6), &datagram[..]);
    }

    #[test]
    fn wg_static_keys_are_shared_and_identity_bound() {
        // new_from_network_identity (wireguard.rs:62-79): both nodes of a
        // network derive the SAME pair (my_public == peer_public on both
        // ends), and the pair is bound to name+secret exactly like the
        // handshake digest (generate_digest_from_str).
        let a = wg_static_keys("net-x", "secret-y");
        let b = wg_static_keys("net-x", "secret-y");
        assert_eq!(a.public(), b.public());
        assert_ne!(wg_static_keys("net-x", "secret-z").public(), a.public());
        assert_ne!(wg_static_keys("net-w", "secret-y").public(), a.public());
        // The secret key IS the 32-byte network digest.
        assert_eq!(network_secret_digest("net-x", "secret-y").len(), 32);
    }

    #[tokio::test]
    async fn wg_tunnel_pingpong() {
        // WgTunnelListener + WgTunnelConnector over the engine's own
        // Noise_IKpsk2 machinery with the SHARED digest keys (upstream
        // `wg_pingpong`, wireguard.rs:793-799): one peer frame each way
        // through the synthetic-IPv4-header WG encapsulation.
        let secret = test_secret();
        let mut listener = WgVtListener::bind("127.0.0.1:0".parse().unwrap(), "net", &secret)
            .await
            .unwrap();
        let addr = listener.local_addr();
        let server = tokio::spawn(async move {
            let mut tunnel = listener.accept().await.unwrap();
            let packet = read_frame(&mut tunnel).await.unwrap().unwrap();
            write_frame(&mut tunnel, &packet).await.unwrap();
            // Hold the tunnel so the client's echo is not racing a drop.
            let _ = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut tunnel)).await;
        });
        let mut client = tokio::time::timeout(
            Duration::from_secs(5),
            connect_wg_tunnel(addr, "net", &secret),
        )
        .await
        .expect("wg connect timeout")
        .unwrap();
        let original = PeerPacket::new(0x1111, 0x2222, packet_type::DATA, b"wg-echo");
        write_frame(&mut client, &original).await.unwrap();
        let echoed = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut client))
            .await
            .expect("wg echo timeout")
            .unwrap()
            .unwrap();
        assert_eq!(echoed, original);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn wg_transport_peer_session() {
        // The full client/server peer session over wg:// — the M1
        // handshake, the identity check, the post-dial liveness ping and
        // a Data packet through the AEAD packet encryption, all riding
        // the WG transport (the `add_tunnel_as_client` /
        // `add_tunnel_as_server` pair, upstream `wg_pingpong`'s session
        // flavour).
        let secret = test_secret();
        let mut listener = WgVtListener::bind("127.0.0.1:0".parse().unwrap(), "mesh", &secret)
            .await
            .unwrap();
        let addr = listener.local_addr();
        let encryptor = create_encryptor("aes-gcm", true, &secret).unwrap();
        let server_secret = secret.clone();
        let server = tokio::spawn(async move {
            let tunnel = listener.accept().await.unwrap();
            let (mut halves, peer) =
                serve_peer_as(tunnel, 0xdead_beef, "mesh", &server_secret, encryptor, None)
                    .await
                    .unwrap();
            assert_eq!(peer.peer_id, 0x0000_0042);
            let frame = halves.data_rx.recv().await.unwrap();
            (peer, frame)
        });
        let endpoint = PeerEndpoint {
            transport: PeerTransport::Wg,
            host: "127.0.0.1".into(),
            port: addr.port(),
        };
        let node = connect_peer_as(
            &endpoint,
            0x0000_0042,
            "mesh",
            &secret,
            create_encryptor("aes-gcm", true, &secret).unwrap(),
            None,
        )
        .await
        .unwrap();
        let latency = node.ping().await.unwrap();
        assert!(latency < Duration::from_secs(2));
        node.send_packet(packet_type::DATA, b"wg-ip-frame")
            .await
            .unwrap();
        let (peer, frame) = tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("server session timed out")
            .unwrap();
        assert_eq!(peer.network_name, "mesh");
        assert_eq!(frame, b"wg-ip-frame");
        node.close().await;
    }

    #[tokio::test]
    async fn wg_listener_accepts_multiple_peers() {
        // The listener's per-address peer table (handle_udp_incoming,
        // wireguard.rs:509-551): two connectors from different source
        // ports are two independent tunnels off one socket.
        let secret = test_secret();
        let mut listener = WgVtListener::bind("127.0.0.1:0".parse().unwrap(), "net", &secret)
            .await
            .unwrap();
        let addr = listener.local_addr();
        let server = tokio::spawn(async move {
            for expected in ["first", "second"] {
                let mut tunnel = listener.accept().await.unwrap();
                let packet = read_frame(&mut tunnel).await.unwrap().unwrap();
                assert_eq!(&packet.payload, expected.as_bytes());
            }
        });
        for payload in ["first", "second"] {
            let mut client = connect_wg_tunnel(addr, "net", &secret).await.unwrap();
            write_frame(
                &mut client,
                &PeerPacket::new(1, 2, packet_type::DATA, payload.as_bytes()),
            )
            .await
            .unwrap();
        }
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .expect("both peers accepted")
            .unwrap();
    }

    #[tokio::test]
    async fn wg_wrong_network_secret_never_connects() {
        // A different secret means a different static pair: the peer's
        // boringtun equivalent rejects our initiation at MAC1 (keyed by
        // ITS static), so the dial exhausts its budget instead of ever
        // establishing (the shared-key design has no downgrade).
        let secret = test_secret();
        let listener = WgVtListener::bind("127.0.0.1:0".parse().unwrap(), "net", &secret)
            .await
            .unwrap();
        let addr = listener.local_addr();
        let err = connect_wg_tunnel(addr, "net", "a-totally-different-secret")
            .await
            .err()
            .expect("the dial must fail")
            .to_string();
        assert!(err.contains("wg connect timeout"), "{err}");
    }

    #[tokio::test]
    #[ignore = "needs a real easytier-core binary; set EASYTIER_BIN to enable"]
    async fn real_easytier_binary_serving_wg() {
        // THE M5 interop: the real binary's boringtun wg:// listener and
        // our wg:// peer dial — the shared digest keypair + the Noise
        // IK math + the synthetic-IP-header framing against the real
        // core, byte for byte.
        let Ok(bin) = std::env::var("EASYTIER_BIN") else {
            eprintln!("skipping: EASYTIER_BIN is not set");
            return;
        };
        let network = format!("itnet-{}", rand::random::<u32>());
        let secret = format!("itsec-{}", rand::random::<u64>());
        let port = 31000 + rand::random::<u16>() % 20000;
        let _child = spawn_real_binary(
            &bin,
            &network,
            &secret,
            &[
                "-l",
                &format!("wg://127.0.0.1:{port}"),
                "--no-tun",
                "-i",
                "10.126.126.1",
                "--hostname",
                "real-wg-node",
                "--socks5",
                "1080",
            ],
        );
        tokio::time::sleep(Duration::from_secs(2)).await;
        let cfg = EasyTierConfig {
            peers: vec![format!("wg://127.0.0.1:{port}")],
            network_secret: secret,
            ipv4: Some("10.126.126.2/24".to_owned()),
            dhcp: false,
            hostname: Some("rustcrash-m5-wg".to_owned()),
            ..EasyTierConfig::new("et-real-wg", &network)
        };
        assert_socks5_through_overlay(&cfg).await;
    }

    #[tokio::test]
    #[ignore = "needs a real easytier-core binary; set EASYTIER_BIN to enable"]
    async fn real_easytier_binary_dials_our_wg_listener() {
        // The reverse: the real binary's wg:// connector (boringtun
        // initiating) into OUR listener — its initiation must pass our
        // responder's MAC1/static/timestamp checks (dialed on the LAN
        // address; see `dialable_lan_ip`).
        let Ok(bin) = std::env::var("EASYTIER_BIN") else {
            eprintln!("skipping: EASYTIER_BIN is not set");
            return;
        };
        let Some(lan_ip) = dialable_lan_ip() else {
            eprintln!("skipping: no dialable non-loopback local IP");
            return;
        };
        let network = format!("itnet-{}", rand::random::<u32>());
        let secret = format!("itsec-{}", rand::random::<u64>());
        let port = 31000 + rand::random::<u16>() % 20000;
        let _child = spawn_real_binary(
            &bin,
            &network,
            &secret,
            &[
                "-p",
                &format!("wg://{lan_ip}:{port}"),
                "--no-listener",
                "--no-tun",
                "-i",
                "10.126.126.1",
                "--hostname",
                "real-wg-node",
                "--socks5",
                "1080",
            ],
        );
        let cfg = EasyTierConfig {
            listeners: vec![format!("wg://0.0.0.0:{port}")],
            network_secret: secret,
            ipv4: Some("10.126.126.2/24".to_owned()),
            dhcp: false,
            hostname: Some("rustcrash-m5".to_owned()),
            ..EasyTierConfig::new("et-real-wg-listener", &network)
        };
        let server = serve(&cfg).await.unwrap();
        tokio::time::timeout(Duration::from_secs(25), server.wait_ready())
            .await
            .expect("the real node did not sync in time")
            .unwrap();
        assert_socks5_through_overlay(&cfg).await;
        server.shutdown().await;
    }
}
