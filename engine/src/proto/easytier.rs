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
//! # Next milestones (the expanded map)
//!
//! 1. **The route layer** so a real peer knows our overlay IPv4:
//!    EasyTier gossips `RoutePeerInfo` (ipv4_addr, cost, hostname…) via
//!    the `OspfRouteRpc.SyncRouteInfo` service — `peers/route/
//!    peer_ospf_route.rs` (234 KB), `route_peer_wire.rs`, `graph_algo.rs`
//!    — carried by the peer RPC framework (`peers/peer_rpc.rs` over
//!    `src/rpc/{client,server,packet,operation}.rs`, ~65 KB total) in
//!    `PacketType::RpcReq/RpcResp` packets. The first cut needs only the
//!    two-node `SyncRouteInfo` exchange, not the full OSPF convergence.
//! 2. **The userspace stack** (`Dial`/`ListenPacket` over the overlay):
//!    the engine's own smoltcp pattern (openvpn.rs/wireguard.rs) fed by
//!    `send_ip_frame`/`recv_ip_frame`, plus the overlay IPv4 assignment
//!    (`gateway/dhcp.rs` for dhcp, static `ipv4` straight from config).
//! 3. **The listener side** (`listener/{mod,transport}.rs` — accepting
//!    our own peers) and the remaining transports (`udp`/`wg`/`quic`/
//!    `ws`, `socket/udp/` + the quinn QUIC tunnel + the websocket
//!    upgrader behind `enable-kcp/quic-proxy`).
//! 4. Secure mode (Noise_XX handshake + peer sessions), the relay path,
//!    and the exit-node/proxy-network pieces.
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
use std::hash::Hasher;
use std::net::Ipv4Addr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce};
use chacha20poly1305::ChaCha20Poly1305;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{broadcast, mpsc, Mutex, Notify};

use crate::error::{Error, Result};

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
                Error::protocol("easytier: truncated protobuf varint in handshake")
            })?;
            self.pos += 1;
            value |= ((byte & 0x7f) as u64) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
            shift += 7;
            if shift >= 64 {
                return Err(Error::protocol("easytier: protobuf varint overflow in handshake"));
            }
        }
    }

    fn len_bytes(&mut self) -> Result<&'a [u8]> {
        let len = self.varint()? as usize;
        let end = self
            .pos
            .checked_add(len)
            .filter(|end| *end <= self.buf.len())
            .ok_or_else(|| Error::protocol("easytier: truncated protobuf field in handshake"))?;
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
                    || Error::protocol("easytier: truncated fixed64 in handshake"),
                )?;
            }
            2 => {
                self.len_bytes()?;
            }
            5 => {
                self.pos = self.pos.checked_add(4).filter(|p| *p <= self.buf.len()).ok_or_else(
                    || Error::protocol("easytier: truncated fixed32 in handshake"),
                )?;
            }
            _ => return Err(Error::protocol("easytier: unknown protobuf wire type in handshake")),
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
        if packet.hdr.packet_type == packet_type::DATA {
                // Direct two-node mesh: only frames addressed to us from the
            // joined peer carry our data (the peer manager would forward
            // anything else; there is nothing to forward to yet).
            if packet.hdr.from_peer_id != state.peer_id
                || packet.hdr.to_peer_id != state.my_peer_id
            {
                continue;
            }
            if let Err(_e) = state.encryptor.decrypt_packet(&mut packet.hdr, &mut packet.payload) {
                continue;
            }
            if state.data_tx.send(packet.payload).await.is_err() {
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
        let mut hdr = PeerManagerHeader {
            from_peer_id: self.my_peer_id,
            to_peer_id: self.peer_id,
            packet_type: packet_type::DATA,
            flags: 0,
            forward_counter: 1,
            reserved: 0,
            len: frame.len() as u32,
        };
        let mut payload = frame.to_vec();
        self.state
            .encryptor
            .encrypt_packet(&mut hdr, &mut payload)?;
        self.state
            .sink
            .send(PeerPacket { hdr, payload })
            .await
            .map_err(|_| Error::network("easytier: peer connection closed"))
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

/// What is still missing after the direct TCP tunnel landed: the
/// peer-manager route layer and the userspace IP stack. The message
/// names the next milestone precisely.
pub const NOT_PORTED: &str = concat!(
    "easytier: the direct TCP peer tunnel is in-tree (handshake + framing ",
    "+ AEAD packet encryption + ping/pong); next milestone = the ",
    "peer-manager route layer so the peer routes our overlay IPv4: the ",
    "SyncRouteInfo OSPF gossip (easytier-core/src/peers/route/peer_ospf_route.rs ",
    "+ route_peer_wire.rs) over the peer RPC framework ",
    "(easytier-core/src/peers/peer_rpc.rs + easytier-core/src/rpc/), then ",
    "the smoltcp userspace stack on the overlay IPv4 ",
    "(gateway/smoltcp/, the wireguard.rs/openvpn.rs engine pattern) and ",
    "DHCP/static assignment (gateway/dhcp.rs); udp/quic/ws transports and ",
    "the listener side follow"
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
}
