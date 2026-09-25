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
//! ListRoute. None are vendored in-tree yet, so [`connect`] fails with
//! the staged milestone error; everything pure-Go around the core is
//! ported below and is the load-bearing config path (the rendered TOML
//! is byte-compatible with upstream's `RenderTOML` + `ApplyRequiredFlags`).
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
//! # First portable milestone (the staged error's scope)
//!
//! 1. Bring the direct **TCP tunnel** up against one peer URI:
//!    the engine's own transport dials `tcp://host:port`, speaks
//!    EasyTier's peer handshake, and registers the peer — no gossip,
//!    no NAT traversal. `Peers: ["tcp://…"]` + `listeners = []`
//!    (the config this module renders for exactly that shape).
//! 2. The **peer-manager gossip** over the direct tunnel (network
//!    name/secret join, route table) → `ListRoute`-equivalent.
//! 3. The userspace stack (smoltcp, the tailscale/zerotier stand-in)
//!    on the overlay's IPv4 → `Dial`/`ListenPacket`.
//! 4. The remaining transports (udp/wg/quic/ws tunnels behind the
//!    `enable-kcp/quic-proxy` flags) and the exit-node/proxy-network
//!    pieces.
//!
//! # Config surface
//!
//! Every field of upstream `EasyTierOption` (cached lines 56-89) is
//! carried by [`EasyTierConfig`] and projected into
//! [`EasyTierTomlConfig`] (`structuredConfig`, cached lines 91-126 —
//! instance-name defaults to the proxy name). `network-secret`,
//! `local-private-key` and peer public keys are secrets: redacted in
//! `Debug`, tests source them from an environment variable only.

use std::net::Ipv4Addr;

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

/// The error every dial returns today: the mesh core is Rust but not
/// in-tree. The message names the first milestone.
pub const NOT_PORTED: &str = concat!(
    "easytier: the mesh core (EasyTier's Rust crates: peer/peer-manager, ",
    "tcp/udp tunnels, quinn-based QUIC transport, rpc) is not in-tree; ",
    "first portable milestone = the direct TCP tunnel for one peer URI ",
    "behind the already-ported TOML config surface ",
    "(EasyTierConfig::render_instance_toml) — see the proto::easytier ",
    "module map for the staged plan"
);

/// Bring up the mesh instance and return a dial-capable connection —
/// the counterpart of upstream `NewEasyTier` + `ensureStarted`
/// (cached lines 172-209). Fails with [`NOT_PORTED`] until the first
/// milestone lands; the config path ([`EasyTierConfig::render_instance_toml`],
/// [`parse_peer_uri`], the overlay-DNS helpers) is the ported logic
/// the dial path will call.
pub async fn connect(_config: &EasyTierConfig) -> Result<()> {
    Err(Error::config(NOT_PORTED))
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
    async fn connect_fails_with_the_staged_milestone_error() {
        let cfg = EasyTierConfig::new("et", "net");
        let err = connect(&cfg).await.unwrap_err().to_string();
        assert!(err.contains("easytier"), "{err}");
        assert!(err.contains("not in-tree"), "{err}");
        assert!(err.contains("first portable milestone"), "{err}");
        assert!(err.contains("TCP tunnel"), "{err}");
    }
}
