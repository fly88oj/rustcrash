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
//! membership, gossip), the tcp/udp tunnels (direct transports), the
//! quinn-based QUIC tunnel + KCP/WS proxies behind the
//! `enable-*-proxy` flags, and the rpc layer feeding ShowNodeInfo/
//! ListRoute. The core is not vendored; the **direct TCP peer tunnel**
//! (the first milestone) is now ported natively into this file — see
//! the milestone section below — and everything pure-Go around the
//! core is ported below and is the load-bearing config path (the
//! rendered TOML is byte-compatible with upstream's `RenderTOML` +
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
//! Secure mode (the Noise_XX `PeerConnNoiseMsg1/2/3` handshake of
//! `peer_conn.rs:779-1170`) is NOT ported: hand-rolling snow's
//! `Noise_XX_25519_ChaChaPoly_SHA256` is its own follow-up and only
//! `[secure_mode]` configs need it.
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
//! # Remaining milestones
//!
//! 1. **The listener side** (`listener/{mod,transport}.rs` — accepting
//!    our own peers) and the remaining transports (`udp`/`wg`/`quic`/
//!    `ws`, `socket/udp/` + the quinn QUIC tunnel + the websocket
//!    upgrader behind `enable-kcp/quic-proxy`).
//! 2. Secure mode (the Noise_XX `PeerConnNoiseMsg1/2/3` handshake of
//!    `peer_conn.rs:779-1170` + peer sessions), the relay path, foreign
//!    networks, and the exit-node/proxy-network pieces.
//! 3. Multi-hop OSPF (SPF over `graph_algo.rs`) once a listener lets
//!    this node sit inside a larger mesh.
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

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use smoltcp::iface::{Config as IfaceConfig, Interface, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{HardwareAddress, IpAddress, IpCidr, IpEndpoint, IpListenEndpoint};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::sync::{broadcast, mpsc, oneshot, Mutex, Notify};

use crate::error::{Error, Result};
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
/// peers/conn/peer_conn.rs:125-133).
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
            if state
                .encryptor
                .decrypt_packet(&mut packet.hdr, &mut packet.payload)
                .is_err()
            {
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
    /// encryptor in plain (non-secure) mode.
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
        self.state
            .encryptor
            .encrypt_packet(&mut hdr, &mut payload)?;
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
        let seq: u32 = rand::random();
        let ping = PeerPacket::new(
            self.my_peer_id,
            self.peer_id,
            packet_type::PING,
            &seq.to_le_bytes(),
        );
        let mut receiver = self.state.pong_tx.subscribe();
        self.state
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
        let latency = start.elapsed();
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

/// Spawn the shared post-handshake machinery around a connected stream
/// (the `start_recv_loop` + `start_pingpong` + MpscTunnel wiring of
/// `PeerConn::new_with_peer_id_hint_and_origin`, peer_conn.rs:340-413).
async fn spawn_connection<I>(io: I, my_peer_id: PeerId, peer: &PeerInfo, encryptor: PacketEncryptor) -> EasyTierNode
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
    EasyTierNode {
        my_peer_id,
        peer_id: peer.peer_id,
        network_name: peer.network_name.clone(),
        state,
        data_rx: Mutex::new(data_rx),
        ctrl_rx: Mutex::new(ctrl_rx),
        tasks: Mutex::new(tasks),
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

/// `do_handshake_as_server_ext` (peer_conn.rs:1186-1243), plain mode: the
/// first packet must be a handshake; the reply carries our real digest
/// only when the client's identity equals ours (`send_handshake`'s
/// `send_secret_digest`, peer_conn.rs:1225-1227).
async fn handshake_as_server<I>(
    io: &mut I,
    my_peer_id: PeerId,
    network_name: &str,
    digest: &NetworkSecretDigest,
) -> Result<PeerInfo>
where
    I: AsyncRead + AsyncWrite + Unpin,
{
    // `recv_next_peer_manager_packet` reads exactly once under the 5s
    // timeout (peer_conn.rs:1193-1196); a non-handshake first packet is
    // `unexpected packet type during handshake` (peer_conn.rs:1228-1233).
    let packet = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        let packet = read_frame(io)
            .await?
            .ok_or_else(|| Error::network("easytier: conn closed during wait handshake"))?;
        if packet.hdr.packet_type == packet_type::HANDSHAKE {
            Ok(packet)
        } else {
            Err(Error::protocol(format!(
                "easytier: unexpected packet type during handshake: {}",
                packet.hdr.packet_type
            )))
        }
    })
    .await
    .map_err(|_| Error::network("easytier: wait handshake timeout"))??;

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
    Ok(PeerInfo {
        peer_id: req.my_peer_id,
        network_name: req.network_name,
        network_secret_digest: client_digest,
        features: req.features,
        version: req.version,
    })
}

/// One parsed `tcp://` peer endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerEndpoint {
    pub host: String,
    pub port: u16,
}

/// `protocol_default_port("tcp")` (connectivity/protocol/mod.rs:55-64)
/// via `protocol_port_offset`: 11010 + 0.
pub const DEFAULT_PEER_PORT: u16 = 11010;

/// Parse a peer URI down to host + port. Only the plain TCP scheme is
/// live (`protocol_transport`, connectivity/protocol/mod.rs:23-36):
/// `ws`/`wss` ride TCP too but behind the websocket upgrader.
pub fn parse_tcp_peer_uri(uri: &str) -> Result<PeerEndpoint> {
    let rest = uri
        .strip_prefix("tcp://")
        .ok_or_else(|| Error::config(format!("easytier: unsupported peer transport scheme in {uri:?}")))?;
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
            .unwrap_or(DEFAULT_PEER_PORT);
        (host.to_string(), port)
    } else {
        match rest.rsplit_once(':') {
            Some((host, port)) => {
                let port = port.parse::<u16>().map_err(|_| {
                    Error::config(format!("easytier: invalid port in peer URI {uri:?}"))
                })?;
                (host.to_string(), port)
            }
            None => (rest.to_string(), DEFAULT_PEER_PORT),
        }
    };
    if host.is_empty() {
        return Err(Error::config(format!("easytier: peer URI has no host: {uri:?}")));
    }
    Ok(PeerEndpoint { host, port })
}

/// Dial one `tcp://` peer and run the plain-mode client handshake —
/// the `PeerManager::add_tunnel_as_client` path
/// (peers/peer_manager.rs:1990-2021) over `TcpStream::connect` with the
/// connector's 3s budget (connectivity/direct/mod.rs:64). DELTA: after
/// the channel is up, one explicit ping confirms liveness — upstream's
/// `ensureStarted` equivalent — which also fails the dial fast when the
/// peer rejects our identity right after its handshake reply.
pub async fn connect_peer(
    endpoint: &PeerEndpoint,
    network_name: &str,
    network_secret: &str,
    encryptor: PacketEncryptor,
) -> Result<EasyTierNode> {
    let digest = network_secret_digest(network_name, network_secret);
    let my_peer_id = random_peer_id();
    let stream = tokio::time::timeout(
        DIRECT_CONNECT_TIMEOUT,
        tokio::net::TcpStream::connect((endpoint.host.as_str(), endpoint.port)),
    )
    .await
    .map_err(|_| Error::network("easytier: direct connect timeout"))??;
    let mut stream = stream;
    let peer = handshake_as_client(&mut stream, my_peer_id, network_name, &digest).await?;
    check_network_identity(network_name, &digest, &peer)?;
    let node = spawn_connection(stream, my_peer_id, &peer, encryptor).await;
    node.ping().await?;
    Ok(node)
}

/// The server side of one accepted stream: run the plain-mode handshake
/// and the same post-handshake machinery. This is the peer side the
/// hermetic tests drive, and the seam for the future listener
/// (`PeerManager::add_tunnel_as_server`, peers/peer_manager.rs:2042+).
pub async fn serve_peer(
    stream: impl AsyncRead + AsyncWrite + Unpin + Send + 'static,
    network_name: &str,
    network_secret: &str,
    encryptor: PacketEncryptor,
) -> Result<(EasyTierNode, PeerInfo)> {
    let digest = network_secret_digest(network_name, network_secret);
    let my_peer_id = random_peer_id();
    let mut stream = stream;
    let peer = handshake_as_server(&mut stream, my_peer_id, network_name, &digest).await?;
    check_network_identity(network_name, &digest, &peer)?;
    let node = spawn_connection(stream, my_peer_id, &peer, encryptor).await;
    Ok((node, peer))
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

/// What is still missing after the route gossip + userspace stack
/// landed (M2): the transports and roles a full mesh node carries. The
/// message names the next milestones precisely.
pub const NOT_PORTED: &str = concat!(
    "easytier: the direct TCP peer tunnel (M1: handshake + framing + ",
    "AEAD packet encryption + ping/pong) and the route layer (M2: the ",
    "peer RPC framework subset + OspfRouteRpc.SyncRouteInfo gossip + the ",
    "smoltcp userspace stack + connect_tcp/EasyTierUdp dials) are ",
    "in-tree; NOT ported: the udp/quic/ws/wg peer transports (socket/udp/",
    " + the quinn QUIC tunnel + the websocket upgrader), the listener ",
    "side (listener/{mod,transport}.rs — accepting our own peers), ",
    "secure mode (the Noise_XX PeerConnNoiseMsg1/2/3 handshake of ",
    "peers/conn/peer_conn.rs:779-1170), the relay path + foreign ",
    "networks (RouteForeignNetworkInfos), multi-hop OSPF convergence ",
    "(graph_algo.rs SPF beyond the direct-neighbor adjacency), IPv6 ",
    "overlay addressing, exit-node/proxy-network policy, and MagicDNS ",
    "serving (the resolver helpers are ported; the dns server is not)"
);

/// Bring the mesh up against the first `tcp://` peer and return the
/// joined peer connection — the counterpart of upstream `NewEasyTier` +
/// `ensureStarted` + the direct connector's first task (adapter cached
/// lines 172-209; connectivity/direct/mod.rs). The config is validated
/// exactly like the rendered TOML demands, and the packet encryption
/// follows the core defaults (`enable_encryption: true`, `aes-gcm`,
/// config/toml.rs:34,64).
pub async fn connect(config: &EasyTierConfig) -> Result<EasyTierNode> {
    let structured = config.structured_config();
    structured.validate()?;
    let peers = structured.parsed_peers()?;
    let peer = peers
        .iter()
        .find(|p| p.uri.trim().to_ascii_lowercase().starts_with("tcp://"))
        .ok_or_else(|| {
            Error::config(
                "easytier: no tcp:// peer to dial for the direct TCP tunnel; the udp/quic/ws transports are not ported yet",
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
    let endpoint = parse_tcp_peer_uri(&peer.uri)?;
    connect_peer(&endpoint, &config.network_name, &config.network_secret, encryptor).await
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
}

/// One overlay node task: the joined peer connection, the route gossip
/// riding its RPC seam, and the smoltcp stack bridging the IP-frame seam
/// to TCP/UDP sessions — the userspace counterpart of the core's
/// `PeerManager` + `gateway` for a direct two-node mesh.
struct EtStack {
    node: EasyTierNode,
    gossip: RouteGossip,
    router: RpcRouter,
    descriptor: RpcDescriptor,
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
    /// The outstanding route-sync call (single-call client; the
    /// transaction id of the in-flight request, if any).
    outstanding_sync: Option<i64>,
    sync_deadline: Option<std::time::Instant>,
    /// The overlay address already installed on the interface.
    installed_addr: Option<Ipv4Addr>,
    /// Dials parked until the route exchange completes (the handshake
    /// gate of openvpn's `Cmd::Connect` — first use waits for the
    /// session, with the same 10s budget the dial timeout carries).
    wait_ready: Vec<(Instant, oneshot::Sender<()>)>,
    fail: Option<Error>,
}

impl EtStack {
    fn new(node: EasyTierNode, gossip: RouteGossip, mtu: usize, static_addr: Option<Ipv4Addr>) -> Self {
        let descriptor = ospf_route_descriptor(gossip.network_name());
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
            node,
            gossip,
            router: RpcRouter::default(),
            descriptor,
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
            outstanding_sync: None,
            sync_deadline: None,
            installed_addr: static_addr,
            wait_ready: Vec::new(),
            fail: None,
        }
    }

    /// Complete or expire the dials parked on route readiness.
    fn service_ready(&mut self) {
        let ready = self.gossip.is_ready();
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
        if ready {
            if let Some(addr) = self.gossip.my_ipv4() {
                self.install_address(addr);
            }
        }
    }

    fn now(&self) -> SmolInstant {
        SmolInstant::from_micros(self.start.elapsed().as_micros() as i64)
    }

    /// Install the overlay address once known (the TUN `update_addr`
    /// path; a /32 plus the default route through it, wireguard.rs
    /// parity — every overlay destination is reached via the peer).
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

    /// Fire the route sync RPC (`sync_route_with_peer`'s send half,
    /// peer_ospf_route.rs:3507-3553).
    async fn start_sync(&mut self) {
        if self.outstanding_sync.is_some() {
            return;
        }
        let request = self.gossip.build_request().encode();
        let (transaction_id, wire) = self.router.begin_call(
            self.node.my_peer_id(),
            self.node.peer_id(),
            self.descriptor.clone(),
            &request,
            ROUTE_SYNC_TIMEOUT.as_millis().min(i32::MAX as u128) as i32,
        );
        self.outstanding_sync = Some(transaction_id);
        self.sync_deadline = Some(std::time::Instant::now() + ROUTE_SYNC_TIMEOUT);
        self.gossip.mark_sync_started();
        if let Err(e) = self.node.send_rpc_packet(true, &wire).await {
            self.fail_route_sync(transaction_id, &e);
        }
    }

    fn fail_route_sync(&mut self, transaction_id: i64, e: &Error) {
        tracing::debug!(target: "engine", "easytier: sync_route_info failed: {e}");
        self.router.cancel(transaction_id);
        if self.outstanding_sync == Some(transaction_id) {
            self.outstanding_sync = None;
            self.sync_deadline = None;
        }
    }

    /// The client's response pump (client.rs:161-221) for the single
    /// outstanding route-sync call.
    fn on_rpc_response(&mut self, packet: RpcPacket) {
        let Some(transaction_id) = self.outstanding_sync else {
            return;
        };
        if packet.transaction_id != transaction_id {
            // Not our call (a late response to a cancelled sync).
            return;
        }
        self.outstanding_sync = None;
        self.sync_deadline = None;
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
            Ok(resp) => self.gossip.apply_response(&resp),
            Err(e) => tracing::debug!(target: "engine", "easytier: decode sync response: {e}"),
        }
        if self.gossip.is_ready() {
            if let Some(addr) = self.gossip.my_ipv4() {
                self.install_address(addr);
            }
        }
    }

    /// The server dispatch (`dispatch_request` + the registered
    /// `OspfRouteRpcServer`, service_registry.rs:166-200 collapsed to
    /// the one service).
    async fn on_rpc_request(&mut self, packet: RpcPacket) {
        let Some(desc) = packet.descriptor.clone() else {
            tracing::debug!(target: "engine", "easytier: rpc request without a descriptor");
            return;
        };
        if desc != self.descriptor {
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
        let request = match SyncRouteInfoRequest::decode(&body.request) {
            Ok(req) => req,
            Err(e) => {
                tracing::debug!(target: "engine", "easytier: decode route request: {e}");
                return;
            }
        };
        let response = self.gossip.handle_sync_request(&request);
        let resp_packet = build_rpc_response(&packet, &response.encode());
        if let Err(e) = self.node.send_rpc_packet(false, &resp_packet.encode()).await {
            tracing::debug!(target: "engine", "easytier: send sync response: {e}");
        }
        // Serving a request may have taught us the subnet we still need
        // for the dhcp allocation.
        if self.gossip.allocate_dhcp_ipv4() {
            self.start_sync().await;
        }
    }

    /// One decrypted control packet off the peer channel.
    async fn on_ctrl(&mut self, packet: PeerPacket) {
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
            match self.router.on_request(rpc) {
                Ok(Some(whole)) => self.on_rpc_request(whole).await,
                Ok(None) => {}
                Err(e) => tracing::debug!(target: "engine", "easytier: merge rpc pieces: {e}"),
            }
        } else {
            // Response pieces merge inside the router's per-call merger;
            // a complete packet is read back by the outstanding call.
            let transaction_id = rpc.transaction_id;
            self.router.on_response(rpc);
            if self.outstanding_sync == Some(transaction_id) {
                if let Some(merged) = self.router.take_merged(transaction_id) {
                    self.on_rpc_response(merged);
                }
            }
        }
    }

    /// The gossip tick: fire the periodic sync, time out a stuck one,
    /// and retry the dhcp allocation as routes arrive.
    async fn gossip_tick(&mut self) {
        if let Some(deadline) = self.sync_deadline {
            if std::time::Instant::now() >= deadline {
                if let Some(transaction_id) = self.outstanding_sync.take() {
                    self.router.cancel(transaction_id);
                    tracing::debug!(target: "engine", "easytier: sync_route_info timed out");
                }
                self.sync_deadline = None;
            }
        }
        if self.gossip.sync_due() && self.outstanding_sync.is_none() {
            self.start_sync().await;
        }
        if self.gossip.allocate_dhcp_ipv4() {
            self.start_sync().await;
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

    async fn drain_egress(&mut self) {
        let pkts: Vec<Vec<u8>> = self.shim.egress.drain(..).collect();
        for pkt in pkts {
            if let Err(e) = self.node.send_ip_frame(&pkt).await {
                tracing::debug!(target: "engine", "easytier: send ip frame: {e}");
                self.fail = Some(e);
                return;
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
        self.gossip
            .my_ipv4()
            .map(IpAddress::Ipv4)
            .ok_or_else(|| Error::network("easytier: no overlay IPv4 address yet"))
    }

    async fn on_cmd(&mut self, cmd: Cmd) {
        match cmd {
            Cmd::WaitReady { reply } => {
                if self.gossip.is_ready() {
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
                if !self.gossip.is_ready() {
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
                if !self.gossip.is_ready() {
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
        if let Some(deadline) = self.sync_deadline {
            until = until.min(deadline);
        }
        if self.gossip.sync_due() {
            until = until.min(std::time::Instant::now() + Duration::from_millis(50));
        }
        until
    }
}

/// Drive one overlay node until the last command sender is gone: the
/// gossip timer, the peer channel (IP frames + control), the command
/// queue and the netstack all make progress in one loop.
async fn run_overlay(mut stack: EtStack, mut cmd_rx: mpsc::Receiver<Cmd>) {
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
            Ctrl(PeerPacket),
            Data(Vec<u8>),
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
            ctrl = stack.node.recv_ctrl_packet() => match ctrl {
                Some(p) => Event::Ctrl(p),
                None => break,
            },
            frame = stack.node.recv_ip_frame() => match frame {
                Some(f) => Event::Data(f),
                None => break,
            },
            _ = wake.notified() => Event::Wake,
            _ = sleep => Event::Tick,
        };
        match event {
            Event::Cmd(c) => stack.on_cmd(c).await,
            Event::Ctrl(p) => stack.on_ctrl(p).await,
            Event::Data(f) => {
                stack.shim.stage(&f);
                stack.wake.notify_one();
            }
            Event::Wake | Event::Tick => {}
        }
        if stack.fail.is_some() || stack.node.is_closed() {
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
/// peer session or the announced routes.
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

/// Bring the mesh up for `cfg` (or reuse the live one): the direct TCP
/// peer connection, the route exchange, and the overlay address — then
/// hand back the command channel every dial shares.
async fn node_for(cfg: &EasyTierConfig) -> Result<mpsc::Sender<Cmd>> {
    let structured = cfg.structured_config();
    structured.validate()?;
    let key = node_cache_key(cfg);
    let cache = NODES.get_or_init(Default::default);
    let mut map = cache.lock().await;
    if let Some(tx) = map.get(&key) {
        if !tx.is_closed() {
            return Ok(tx.clone());
        }
    }
    let node = connect(cfg).await?;
    let static_addr = static_overlay_address(cfg)?;
    let hostname = cfg
        .hostname
        .clone()
        .unwrap_or_else(|| format!("rustcrash-{}", node.my_peer_id() & 0xffff));
    let (addr, prefix) = static_addr.unzip();
    let gossip = RouteGossip::new(
        &cfg.network_name,
        node.my_peer_id(),
        node.peer_id(),
        &hostname,
        addr,
        prefix.unwrap_or(32),
        addr.is_none() && (cfg.dhcp || cfg.ipv4.as_deref().unwrap_or("").trim().is_empty()),
        cfg.proxy_networks.clone(),
        true,
    );
    let mtu = if cfg.mtu > 0 {
        cfg.mtu as usize
    } else {
        DEFAULT_MTU
    };
    let stack = EtStack::new(node, gossip, mtu, addr);
    let (tx, rx) = mpsc::channel::<Cmd>(64);
    tokio::spawn(run_overlay(stack, rx));
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
        // A non-TCP peer names the not-yet-ported transports.
        let cfg = EasyTierConfig {
            peers: vec!["udp://192.0.2.10:11010".into()],
            ..EasyTierConfig::new("et", "net")
        };
        let err = connect(&cfg).await.unwrap_err().to_string();
        assert!(err.contains("no tcp:// peer"), "{err}");
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
    fn parse_tcp_peer_uri_forms() {
        assert_eq!(
            parse_tcp_peer_uri("tcp://192.0.2.10:11010").unwrap(),
            PeerEndpoint { host: "192.0.2.10".into(), port: 11010 }
        );
        // protocol_default_port("tcp") = 11010
        // (connectivity/protocol/mod.rs:55-64).
        assert_eq!(
            parse_tcp_peer_uri("tcp://node.example.com").unwrap(),
            PeerEndpoint { host: "node.example.com".into(), port: DEFAULT_PEER_PORT }
        );
        assert_eq!(
            parse_tcp_peer_uri("tcp://[2001:db8::1]:11011").unwrap(),
            PeerEndpoint { host: "2001:db8::1".into(), port: 11011 }
        );
        // A path component is ignored (host[:port] is what remains).
        assert_eq!(
            parse_tcp_peer_uri("tcp://example.com:11010/some/path").unwrap(),
            PeerEndpoint { host: "example.com".into(), port: 11010 }
        );
        assert!(parse_tcp_peer_uri("udp://192.0.2.10:11010").is_err());
        assert!(parse_tcp_peer_uri("quic://192.0.2.10").is_err());
        assert!(parse_tcp_peer_uri("tcp://:11010").is_err());
        assert!(parse_tcp_peer_uri("tcp://host:notaport").is_err());
        assert!(parse_tcp_peer_uri("tcp://[::1:11010").is_err());
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
            handshake_as_server(&mut server_io, 0xdead_beef, "mesh", &digest).await
        });
        let client_peer =
            handshake_as_client(&mut client_io, 0x0000_0042, "mesh", &digest).await.unwrap();
        let server_peer = server.await.unwrap().unwrap();
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
            handshake_as_server(&mut server_io, 0x42, "mesh", &digest).await
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
        let endpoint = parse_tcp_peer_uri(&format!("tcp://{addr}")).unwrap();
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
            let peer = handshake_as_server(&mut stream, 0xaa, network, &digest)
                .await
                .unwrap();
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
        let node = spawn_connection(
            stream,
            my_peer_id,
            &peer_info,
            create_encryptor("aes-gcm", true, &secret).unwrap(),
        )
        .await;
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
                        let Ok((node, _peer_info)) =
                            serve_peer(stream, &network, &secret, encryptor).await
                        else {
                            return;
                        };
                        // The responder side of the gossip: static
                        // address, never the initiator.
                        let gossip = RouteGossip::new(
                            &network,
                            node.my_peer_id(),
                            node.peer_id(),
                            "mimic",
                            Some(overlay_ip),
                            prefix,
                            false,
                            vec![],
                            false,
                        );
                        let stack = EtStack::new(node, gossip, DEFAULT_MTU, Some(overlay_ip));
                        run_mimic(stack, learned, accepted, 9041, 9042).await;
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
                for (peer_id, info) in &stack.gossip.lsdb {
                    out.insert(*peer_id, info.ipv4());
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
                Ctrl(PeerPacket),
                Data(Vec<u8>),
                Tick,
            }
            let event = tokio::select! {
                biased;
                ctrl = stack.node.recv_ctrl_packet() => match ctrl {
                    Some(p) => Event::Ctrl(p),
                    None => break,
                },
                frame = stack.node.recv_ip_frame() => match frame {
                    Some(f) => Event::Data(f),
                    None => break,
                },
                _ = tick.tick() => Event::Tick,
            };
            match event {
                Event::Ctrl(p) => stack.on_ctrl(p).await,
                Event::Data(f) => {
                    stack.shim.stage(&f);
                    stack.wake.notify_one();
                }
                Event::Tick => {}
            }
            if stack.node.is_closed() {
                break;
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
            let (node, _peer_info) =
                serve_peer(stream, network, &server_secret, encryptor).await.unwrap();
            let gossip = RouteGossip::new(
                network,
                node.my_peer_id(),
                node.peer_id(),
                "mimic",
                Some("10.200.0.1".parse().unwrap()),
                24,
                false,
                vec![],
                false,
            );
            let stack = EtStack::new(
                node,
                gossip,
                DEFAULT_MTU,
                Some("10.200.0.1".parse().unwrap()),
            );
            run_mimic(stack, server_learned, server_accepted, 9051, 9052).await;
        });

        // The client: a raw M1 node, hand-built gossip bytes.
        let endpoint = parse_tcp_peer_uri(&format!("tcp://{addr}")).unwrap();
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
            let endpoint = parse_tcp_peer_uri(&format!("tcp://127.0.0.1:{port}")).unwrap();
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
}
