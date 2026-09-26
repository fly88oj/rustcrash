//! The tailscale overlay outbound: config surface, the ipn control
//! session (login + map poll), and the data plane.
//!
//! # Status after wave 13
//!
//! The full control path of a tsnet node now exists in this module:
//!
//! * wave 10 (each a `tailscale/` submodule, a 1:1 port of the Go
//!   sources cached at `/tmp/wave10-upstream/`): [`noise`] — the
//!   controlbase **Noise IK** transport; [`controlhttp`] — the
//!   `/ts2021` HTTP upgrade; [`derp`] — the DERP relay client.
//! * wave 11 (sources cached at `/tmp/wave11-upstream/`):
//!   [`tailcfg`] — the JSON control messages (RegisterRequest,
//!   MapRequest/Response, Node, DERPMap) with Go's exact wire shapes;
//!   [`state`] — the ipn `FileStore` state file and the machine/node
//!   key lifecycle; [`control`] — the control session inside the noise
//!   records (the `/key` bootstrap, the auth-key register flow, the
//!   `StreamMap` long-poll with delta application); [`wg`] — the
//!   data-plane session: a WireGuard initiator whose datagrams ride a
//!   direct UDP path or the peer's home DERP relay, over a smoltcp
//!   netstack (the stand-in for tsnet's `Netstack`).
//! * wave 12: **the outbound dial API** — [`dial_tcp`]/[`dial_udp`] on
//!   a process-global overlay cache ([`overlay_for`], the openvpn
//!   `TUNNELS` registry shape), plus:
//!   * MagicDNS resolution ([`TailscaleOverlay::resolve`]: the map's
//!     DNSConfig search domains and the peers' FQDNs);
//!   * subnet-route and exit-node enforcement
//!     ([`NetMap::route_peer_enforced`]: the AllowSubnetRoutes prefs of
//!     ipnlocal's authReconfig);
//!   * the map-poll reconnect/backoff loop (auto.go's mapRoutine shape,
//!     capped);
//!   * UDP through the overlay ([`TsUdpSocket`], routed per
//!     destination).
//! * wave 13 (sources cached at `/tmp/wave13-upstream/`):
//!   * [`disco`] — the disco overlay codec (magic + key + nacl box,
//!     Ping/Pong/CallMeMaybe, disco/disco.go) and the data plane's
//!     bounded disco loop ([`wg`]'s tunnel: ping on handshake, pong
//!     confirms the direct path, CallMeMaybe via DERP opens one);
//!   * **key-expiry renewal** — the poll task watches the self node's
//!     `KeyExpiry` (ipnlocal.go:1906), and on expiry re-registers
//!     with a freshly generated node key under
//!     `RegisterRequest{NodeKey: fresh, OldNodeKey: current}`
//!     (direct.go:706-713, 761), resets the map session and drops the
//!     peer tunnels so the next dial re-keys under the new identity
//!     ([`TailscaleOverlay::node_public`] tracks the rotation).
//!
//! [`start_overlay`] runs that whole path and returns a
//! [`TailscaleOverlay`] whose dials reach peers: directly through the
//! engine's existing `proto::wireguard` client (netmap-derived
//! `WgOut`), or — when the peer has no reachable UDP endpoint —
//! through the DERP-relayed [`wg`] session. [`connect`] drives
//! [`start_overlay`] as far as it goes and then stops with the precise
//! remaining-gap error (the outbound integration itself belongs to the
//! integrator's wave).
//!
//! # Honest start (unchanged)
//!
//! mihomo's tailscale outbound (`adapter/outbound/tailscale.go`, 479
//! lines, cached at `/tmp/wave7-upstream/mihomo_outbound_tailscale.go`)
//! is build-gated on `with_gvisor && !no_tailscale` and embeds the whole
//! `metacubex/tailscale` tsnet userspace stack. This module ports the
//! protocol stack natively instead; the config surface is complete
//! ([`TailscaleConfig::masked_prefs`],
//! [`TailscaleConfig::exit_node_needs_status`]) and the control + data
//! planes now work against a Go-parity control server.
//!
//! # Ported deltas (vs upstream Go)
//!
//! * HTTP/1.1 inside the noise records instead of unencrypted HTTP/2
//!   (see [`control`]'s module docs for the reasoning); one noise
//!   connection per request instead of a pooled h2 connection.
//! * Map responses are requested UNcompressed (`Compress: ""`); zstd-
//!   compressed messages are still decoded when a server sends them
//!   ([`control::decode_map_message`]).
//! * The interactive login branch (RegisterResponse.AuthURL) is staged:
//!   surfaced as [`control::RegisterOutcome::NeedsBrowserAuth`] instead
//!   of parking a `LoginGoal{url}` (auto.go:386-405); a headless proxy
//!   cannot visit the URL.
//! * Disco is the bounded core (see [`wg`]'s module docs for the full
//!   simplification list vs magicsock: no heartbeat, first-pong-wins,
//!   no MTU probes / UDP-relay messages / DERP-carried pings).
//! * The key-expiry renewal re-registers with the configured auth key
//!   (upstream's expired-key relogin is interactive — NeedsLogin,
//!   ipnlocal.go:6938-6940 — while an auth-key proxy can rotate
//!   headlessly); rotation is one round per detected expiry, not
//!   upstream's unbounded regen loop.
//! * The auto exit-node pick is lowest-Node-ID of the reachable
//!   advertising peers, not lowest DERP latency — a headless proxy has
//!   no netcheck measurements (upstream `suggestExitNodeUsingDERP`
//!   ranks by region latency; see `NetMap::pick_auto_exit_node`).
//! * The map poll's reconnect loop caps consecutive failed attempts
//!   (upstream's mapRoutine retries forever under its backoff; a proxy
//!   keeps the last netmap and stops after the cap — see
//!   [`POLL_RETRY`]).
//! * controlhttp dials HTTP then HTTPS sequentially (upstream races
//!   them, client.go:288-305); TLS verification stays on; derphttp has
//!   no websocket fallback / fast-start / dial-plan; the DERP send rate
//!   limiter is not ported (wave-10 deltas, kept).
//!
//! # Config surface
//!
//! Every field of upstream `TailscaleOption` (cached lines 54-67) is
//! carried by [`TailscaleConfig`]. `auth_key` is a secret: redacted in
//! `Debug`, sourced from configuration or the environment in tests,
//! never a source literal. `state_dir` defaults to `"tailscale"`
//! resolved by the config layer (upstream: `C.Path.Resolve` +
//! `C.Path.IsSafePath`, cached lines 118-124 — path policy belongs to
//! the engine's config, not the protocol module).

mod control;
mod controlhttp;
mod derp;
mod disco;
mod noise;
mod state;
mod tailcfg;
mod wg;

pub use control::{
    build_map_request, build_register_request, decode_map_message, fetch_control_key, register,
    stream_map, ControlSession, MapSession, NetMap, RegisterOutcome,
};
pub use controlhttp::{
    upgrade_over as controlhttp_upgrade_over, ControlHttpDialer, HANDSHAKE_HEADER_NAME,
    SERVER_UPGRADE_PATH, UPGRADE_HEADER_VALUE,
};
pub use derp::{
    derp_connect, derp_upgrade_over, DerpClient, DerpClientOptions, DerpHttpOptions, DerpMessage,
    NodePrivateKey, NodePublicKey, ServerInfo, ServerInfoMessage, DERP_PATH,
};
pub use disco::{
    looks_like_disco, DiscoMessage, DiscoPrivateKey, DiscoPublicKey, MAGIC as DISCO_MAGIC,
};
pub use noise::{
    client_deferred, client_handshake, server_handshake, MachinePrivateKey, MachinePublicKey,
    NoiseConn, CURRENT_PROTOCOL_VERSION,
};
pub use state::{
    persist_rotated_node_key, FileStore, NodeIdentity, Persist, STATE_FILE_NAME,
};
pub use tailcfg::{
    AddrPort, DerpMap, DerpNode, DerpRegion, DiscoKeyText, DnsConfig, FilterRule, Hostinfo,
    MachineKeyText, MapRequest, MapResponse, NetPortRange, Node, NodeKey, OverTlsPublicKeyResponse,
    PeerChange, Prefix, RegisterRequest, RegisterResponse, RegisterResponseAuth, UserProfile,
    CURRENT_CAPABILITY_VERSION,
};
pub use wg::{DerpRoute, DiscoKeys, TsTcpStream, TsTunnel, TsTunnelConfig, TsUdp};

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use base64::Engine;
use tokio::sync::Notify;

use crate::error::{Error, Result};

/// tsnet's default control server (`Server.getControlURL`'s fallback).
pub const DEFAULT_CONTROL_URL: &str = "https://controlplane.tailscale.com";

/// The `tailscale` outbound configuration, mirroring mihomo's
/// `TailscaleOption` (`adapter/outbound/tailscale.go:54-67`).
///
/// `Option<bool>` fields mean "unset" the way Go's `*bool` fields do:
/// `accept-routes` and `exit-node-allow-lan-access` only mask a pref when
/// explicitly configured (see [`TailscaleConfig::masked_prefs`]).
#[derive(Default, Clone, PartialEq, Eq)]
pub struct TailscaleConfig {
    /// `name:` — the proxy name (mihomo `BasicOption.Name`).
    pub name: String,
    /// `hostname:` — the node hostname tsnet registers as.
    pub hostname: Option<String>,
    /// `auth-key:` — the tailnet auth key. Secret; never logged.
    pub auth_key: Option<String>,
    /// `control-url:` — control server (default: the public one).
    pub control_url: Option<String>,
    /// `state-dir:` — tsnet state store directory (default "tailscale").
    pub state_dir: Option<String>,
    /// `ephemeral:` — register as an ephemeral node.
    pub ephemeral: bool,
    /// `udp:` — support UDP through the overlay.
    pub udp: bool,
    /// `accept-routes:` — RouteAll pref.
    pub accept_routes: Option<bool>,
    /// `exit-node:` — an exit node IP/hostname, or an `auto:<expr>` pick.
    pub exit_node: Option<String>,
    /// `exit-node-allow-lan-access:` — LAN bypass while using an exit node.
    pub exit_node_allow_lan_access: Option<bool>,
}

/// Debug redacts the auth key: the secret must never appear in logs,
/// panics or test output.
impl std::fmt::Debug for TailscaleConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TailscaleConfig")
            .field("name", &self.name)
            .field("hostname", &self.hostname)
            .field("auth_key", &self.auth_key.as_ref().map(|_| "[redacted]"))
            .field("control_url", &self.control_url)
            .field("state_dir", &self.state_dir)
            .field("ephemeral", &self.ephemeral)
            .field("udp", &self.udp)
            .field("accept_routes", &self.accept_routes)
            .field("exit_node", &self.exit_node)
            .field("exit_node_allow_lan_access", &self.exit_node_allow_lan_access)
            .finish()
    }
}

impl TailscaleConfig {
    /// A config with just the proxy name set, like the zero-value
    /// `TailscaleOption` plus the required `name` field.
    pub fn new(name: impl Into<String>) -> Self {
        TailscaleConfig {
            name: name.into(),
            ..Default::default()
        }
    }

    /// Port of `tailscaleExitNodeNeedsStatus`
    /// (`adapter/outbound/tailscale.go:341-347`): a literal exit node
    /// (IP or hostname) needs a `LocalClient.Status()` lookup to resolve
    /// it to an IP before prefs can be applied; an `auto:<expr>` pick
    /// does not.
    pub fn exit_node_needs_status(&self) -> bool {
        match &self.exit_node {
            Some(node) if !node.is_empty() => !parse_auto_exit_node(node),
            _ => false,
        }
    }

    /// Port of `buildTailscaleMaskedPrefs` (cached lines 314-339): the
    /// `ipn.MaskedPrefs` this config would push via `EditPrefs`. `None`
    /// means "nothing to edit" exactly like upstream's `nil, nil` return.
    pub fn masked_prefs(&self) -> Option<MaskedPrefs> {
        let mut changed = false;
        let mut prefs = MaskedPrefs::default();
        if let Some(route_all) = self.accept_routes {
            prefs.route_all = Some(route_all);
            changed = true;
        }
        if let Some(node) = self.exit_node.as_deref().filter(|n| !n.is_empty()) {
            if let Some(expr) = parse_auto_exit_node_str(node) {
                prefs.auto_exit_node = Some(expr.to_string());
                changed = true;
            }
        }
        if self.exit_node_allow_lan_access.is_some() && !self.exit_node_needs_status() {
            prefs.exit_node_allow_lan_access = self.exit_node_allow_lan_access;
            changed = true;
        }
        if changed {
            Some(prefs)
        } else {
            None
        }
    }
}

/// The subset of `ipn.MaskedPrefs` the outbound ever sets
/// (`buildTailscaleMaskedPrefs`).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct MaskedPrefs {
    /// `RouteAll` (accept-routes).
    pub route_all: Option<bool>,
    /// `AutoExitNode` (the `auto:<expr>` form).
    pub auto_exit_node: Option<String>,
    /// `ExitNodeAllowLANAccess`.
    pub exit_node_allow_lan_access: Option<bool>,
}

/// Port of `ipn.ParseAutoExitNodeString`
/// (`metacubex/tailscale` `ipn/prefs.go:1187-1192`): a string is an
/// auto-exit-node expression iff it starts with `AutoExitNodePrefix`
/// (`"auto:"`, prefs.go:1175) and has a non-empty remainder.
pub fn parse_auto_exit_node(s: &str) -> bool {
    match s.strip_prefix("auto:") {
        Some(expr) => !expr.is_empty(),
        None => false,
    }
}

/// The slicing twin used by [`TailscaleConfig::masked_prefs`], returning
/// the expression.
fn parse_auto_exit_node_str(s: &str) -> Option<&str> {
    s.strip_prefix("auto:").filter(|expr| !expr.is_empty())
}

/// The error `connect` still ends with after wave 13. Everything up
/// through the data plane is ported (login, the reconnecting netmap
/// poll, direct-UDP + DERP peer paths with the disco overlay informing
/// carrier selection, MagicDNS, route enforcement, UDP, key-expiry
/// renewal) and [`dial_tcp`]/[`dial_udp`] hand the integrator real
/// streams; the two remaining gaps are enumerated precisely in the
/// constant below.
pub const NOT_IMPLEMENTED: &str = concat!(
    "tailscale: login, the netmap poll (with reconnect/backoff), the peer ",
    "data plane (direct UDP + DERP relay, disco-informed: ping/pong path ",
    "confirmation and call-me-maybe), MagicDNS, subnet-route and ",
    "exit-node enforcement, UDP, key-expiry renewal and the tailnet packet ",
    "filter (parsed from the map, carried on the netmap, queryable via ",
    "packet_filter_allows — an inbound ACL has nothing to reject on an ",
    "outbound; enforcement belongs to a listener/TUN surface) are ported, ",
    "and dial_tcp/dial_udp return live streams — still missing: ",
    "interactive (browser) login — headless out of scope, staged as ",
    "RegisterOutcome::NeedsBrowserAuth"
);

// ---------------------------------------------------------------------------
// The overlay: login + map poll + data plane
// ---------------------------------------------------------------------------

/// The routing prefs an overlay enforces — the subset of
/// [`TailscaleConfig`] that changes routing decisions (ipnlocal's
/// authReconfig reads exactly these from ipn.Prefs: RouteAll,
/// ExitNodeID/ExitNodeIP, ExitNodeAllowLANAccess, ipnlocal.go:6111-6152).
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct OverlayPrefs {
    /// `accept-routes` (RouteAll → netmap.AllowSubnetRoutes).
    pub accept_routes: bool,
    /// `exit-node` (IP, MagicDNS name, or `auto:<expr>`), resolved
    /// against every netmap the poll delivers.
    pub exit_node: Option<String>,
    /// `exit-node-allow-lan-access`.
    pub exit_node_allow_lan_access: bool,
    /// `udp` — whether UDP sockets may traverse the overlay.
    pub udp: bool,
}

impl OverlayPrefs {
    fn from_config(cfg: &TailscaleConfig) -> Self {
        OverlayPrefs {
            accept_routes: cfg.accept_routes.unwrap_or(false),
            exit_node: cfg
                .exit_node
                .clone()
                .filter(|n| !n.is_empty())
                .map(|n| n.trim().to_string()),
            exit_node_allow_lan_access: cfg.exit_node_allow_lan_access.unwrap_or(false),
            udp: cfg.udp,
        }
    }
}

/// The retry policy of the map-poll task — auto.go's mapRoutine
/// (controlclient_auto.go:582-650, cached at
/// `/tmp/wave10-upstream/controlclient_auto.go`): a
/// `backoff.NewBackoff("mapRoutine", ..., 30*time.Second)` (line 588)
/// that `BackOff(ctx, err)`s after every failed poll and `Reset`s when
/// a netmap arrives (lines 482-486, "Reset the backoff timer if we got
/// a netmap"). This port's deltas: deterministic (upstream jitters the
/// delay), and capped — upstream retries forever, a proxy keeps the
/// last netmap and parks the poll after `max_attempts` consecutive
/// failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PollRetry {
    /// The first delay.
    pub initial: std::time::Duration,
    /// The growth ceiling (`NewBackoff`'s maxWait, auto.go:588).
    pub max: std::time::Duration,
    /// Consecutive failed polls before the task gives up.
    pub max_attempts: u32,
}

/// The production policy: 100ms doubling to 30s, 16 consecutive
/// failures (~1.8h of retrying) before the poll parks.
pub const POLL_RETRY: PollRetry = PollRetry {
    initial: std::time::Duration::from_millis(100),
    max: std::time::Duration::from_secs(30),
    max_attempts: 16,
};

impl PollRetry {
    /// The delay after `attempt` consecutive failures
    /// (min(initial·2^attempt, max)).
    fn delay(&self, attempt: u32) -> std::time::Duration {
        let shift = attempt.min(31);
        let grow = self
            .initial
            .saturating_mul(1u32.checked_shl(shift).unwrap_or(u32::MAX));
        grow.min(self.max)
    }
}

/// A live tailscale overlay: the login has completed, the map poll is
/// running (reconnecting with backoff), and dials route through the
/// netmap under the config's prefs.
pub struct TailscaleOverlay {
    /// The current node private key — swapped by the key-expiry
    /// renewal (the poll task rotates it; dials read it fresh).
    node_key: Arc<Mutex<NodePrivateKey>>,
    /// This overlay's disco keypair (magicsock.Conn's per-start key,
    /// `RotateDiscoKey`); peers learn the public half from
    /// `MapRequest.DiscoKey`.
    disco_key: DiscoPrivateKey,
    /// The latest netmap, fed by the map-poll task.
    netmap: Arc<Mutex<Option<NetMap>>>,
    netmap_changed: Arc<Notify>,
    /// The node key of the peer selected as exit node, re-resolved on
    /// every netmap (select_exit_node over the fresh map).
    selected_exit_node: Arc<Mutex<Option<NodeKey>>>,
    /// The prefs every routing decision enforces.
    prefs: OverlayPrefs,
    /// The poll task's terminal state, once it gives up (netmap stays).
    poll_error: Arc<Mutex<Option<String>>>,
    /// Why key-expiry renewal failed, when it did (the overlay keeps
    /// serving off the old identity; see [`Self::renewal_error`]).
    renewal_error: Arc<Mutex<Option<String>>>,
    /// One tunnel per routed peer (by node key hex) — cleared when the
    /// node key rotates so tunnels respawn under the new identity.
    tunnels: Arc<tokio::sync::Mutex<HashMap<String, TsTunnel>>>,
    /// The host:port authority for control requests.
    control_authority: String,
}

impl TailscaleOverlay {
    /// Our CURRENT node public key (rotates on key-expiry renewal —
    /// the peers' WireGuard sessions re-key against it).
    pub fn node_public(&self) -> [u8; 32] {
        *self
            .node_key
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .public()
            .as_bytes()
    }

    /// Why the last key-expiry renewal failed, when it did. The old
    /// identity keeps serving dials off the last netmap until its
    /// sessions die; upstream surfaces the same condition as the
    /// NeedsLogin state (ipnlocal.go:6938-6940, "The node key expired,
    /// need to relogin").
    pub fn renewal_error(&self) -> Option<String> {
        self.renewal_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
    /// The latest netmap (the last one the poll delivered).
    pub fn netmap(&self) -> Option<NetMap> {
        self.netmap.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The prefs this overlay enforces (from the config it started
    /// with).
    pub fn prefs(&self) -> &OverlayPrefs {
        &self.prefs
    }

    /// Why the map poll gave up, when it did (the last netmap stays
    /// usable for dials).
    pub fn poll_error(&self) -> Option<String> {
        self.poll_error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }

    /// Wait for the first netmap (already delivered by
    /// [`start_overlay`], so this returns immediately in practice).
    pub async fn wait_netmap(&self) -> Result<NetMap> {
        loop {
            if let Some(nm) = self.netmap() {
                return Ok(nm);
            }
            self.netmap_changed.notified().await;
        }
    }

    /// The self node's tailnet addresses (tsnet's `TailscaleIPs()`).
    pub fn tailscale_ips(&self) -> Vec<std::net::IpAddr> {
        self.netmap()
            .map(|nm| {
                nm.self_node
                    .addresses
                    .iter()
                    .map(|p| p.addr)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default()
    }

    /// MagicDNS resolution against the live netmap (see
    /// [`NetMap::resolve`]): an FQDN with or without the trailing dot,
    /// or a bare name expanded through the map's search domains.
    pub fn resolve(&self, name: &str) -> Option<std::net::IpAddr> {
        self.netmap().and_then(|nm| nm.resolve(name))
    }

    /// The search domains of the live netmap (the MagicDNS suffix plus
    /// `DNSConfig.Domains`).
    pub fn search_domains(&self) -> Vec<String> {
        self.netmap().map(|nm| nm.search_domains()).unwrap_or_default()
    }

    /// The peer currently selected as exit node (the config's
    /// `exit-node` resolved against the latest netmap), when any.
    pub fn selected_exit_node(&self) -> Option<Node> {
        let key = self
            .selected_exit_node
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()?;
        self.netmap().and_then(|nm| {
            nm.peers
                .into_iter()
                .find(|p| p.key == key)
        })
    }

    /// The peer `ip` routes to under this overlay's prefs — the
    /// enforced routing decision ([`NetMap::route_peer_enforced`]),
    /// with the precise refusal surfaced on error.
    pub fn routed_peer<'a>(&self, nm: &'a NetMap, ip: std::net::IpAddr) -> Result<&'a Node> {
        let exit = self
            .selected_exit_node
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        match nm.route_peer_enforced(
            ip,
            self.prefs.accept_routes,
            exit.as_ref(),
            self.prefs.exit_node_allow_lan_access,
        ) {
            Ok(Some(peer)) => Ok(peer),
            Ok(None) => Err(Error::network(format!(
                "tailscale: no peer routes {ip} (cryptokey routing found no match)"
            ))),
            Err(reason) => Err(Error::network(format!("tailscale: {ip} not routed: {reason}"))),
        }
    }

    /// Dial TCP through the engine's EXISTING WireGuard client
    /// (`proto::wireguard::connect`) configured from the netmap: this is
    /// the direct path, usable when the routed peer advertises a UDP
    /// endpoint. The `reserved` bytes stay zero (no mihomo provider
    /// quirk applies to a tailnet peer).
    pub async fn dial_direct(&self, target: SocketAddr) -> Result<crate::stream::BoxProxyStream> {
        let nm = self.netmap().ok_or_else(|| {
            Error::network("tailscale: no netmap yet (the map poll has not delivered one)")
        })?;
        let peer = self.routed_peer(&nm, target.ip())?;
        let endpoint = peer
            .endpoints
            .iter()
            .find(|ep| ep.0.is_ipv4())
            .or_else(|| peer.endpoints.first())
            .map(|ep| ep.0)
            .ok_or_else(|| {
                Error::network("tailscale: peer advertises no UDP endpoint (use the DERP path)")
            })?;
        let local_ipv4 = nm
            .self_node
            .addresses
            .iter()
            .find_map(|p| match p.addr {
                std::net::IpAddr::V4(v4) => Some(v4),
                _ => None,
            })
            .ok_or_else(|| Error::network("tailscale: self node has no IPv4 tailnet address"))?;
        let local_ipv6 = nm.self_node.addresses.iter().find_map(|p| match p.addr {
            std::net::IpAddr::V6(v6) => Some(v6),
            _ => None,
        });
        let node_key = self
            .node_key
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone();
        let b64 = base64::engine::general_purpose::STANDARD;
        let cfg = crate::proto::wireguard::WgOut {
            server: endpoint.ip().to_string(),
            port: endpoint.port(),
            private_key: b64.encode(node_key.secret()),
            peer_public_key: b64.encode(peer.key.as_bytes()),
            pre_shared_key: None,
            local_ip: local_ipv4,
            local_ipv6,
            mtu: 1280,
            reserved: [0, 0, 0],
            udp: true,
        };
        let target = crate::addr::NetAddr::ip(target.ip(), target.port());
        crate::proto::wireguard::connect(&cfg, &target).await
    }

    /// The peer's tunnel, spawned or reused (one per peer, keyed by
    /// node key hex — the same cache `dial_relay` rides).
    async fn tunnel_for_peer(&self, nm: &NetMap, peer: &Node) -> Result<TsTunnel> {
        let peer_hex: String = peer.key.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let mut tunnels = self.tunnels.lock().await;
        // Reuse the peer's tunnel when it exists and lives.
        if let Some(t) = tunnels.get(&peer_hex) {
            return Ok(t.clone());
        }
        let endpoint = peer
            .endpoints
            .iter()
            .find(|ep| ep.0.is_ipv4())
            .or_else(|| peer.endpoints.first())
            .map(|ep| ep.0);
        let derp = if peer.home_derp != 0 {
            nm.derp_map
                .region_url(peer.home_derp)
                .map(|url| DerpRoute {
                    url,
                    peer_key: *peer.key.as_bytes(),
                })
        } else {
            None
        };
        if endpoint.is_none() && derp.is_none() {
            return Err(Error::network(format!(
                "tailscale: peer {} has neither a UDP endpoint nor a home DERP",
                peer.name
            )));
        }
        let local_ipv4 = nm
            .self_node
            .addresses
            .iter()
            .find_map(|p| match p.addr {
                std::net::IpAddr::V4(v4) => Some(v4),
                _ => None,
            })
            .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED);
        let local_ipv6 = nm.self_node.addresses.iter().find_map(|p| match p.addr {
            std::net::IpAddr::V6(v6) => Some(v6),
            _ => None,
        });
        // The peer's disco key (Node.DiscoKey): non-zero means the peer
        // speaks disco and the tunnel pings/confirms the direct path
        // (updateFromNode's key handling, endpoint.go:1706-1721).
        let disco = peer
            .disco_key
            .as_ref()
            .filter(|dk| dk.0 != [0u8; 32])
            .map(|dk| DiscoKeys {
                our_private: self.disco_key.clone(),
                peer_public: dk.0,
            });
        let cfg = TsTunnelConfig {
            private_key: *self
                .node_key
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .secret(),
            peer_public: *peer.key.as_bytes(),
            local_ipv4,
            local_ipv6,
            mtu: 1280,
            endpoint,
            derp,
            udp_enabled: self.prefs.udp,
            disco,
        };
        let tunnel = TsTunnel::spawn(cfg).await?;
        tunnels.insert(peer_hex, tunnel.clone());
        Ok(tunnel)
    }

    /// Dial TCP through the tailscale-side session ([`wg`]): direct UDP
    /// when the peer advertises an endpoint, DERP-relayed through the
    /// peer's home relay otherwise (and both while the path is being
    /// learned). One tunnel per peer is cached.
    pub async fn dial_relay(&self, target: SocketAddr) -> Result<TsTcpStream> {
        let nm = self.netmap().ok_or_else(|| {
            Error::network("tailscale: no netmap yet (the map poll has not delivered one)")
        })?;
        let peer = self.routed_peer(&nm, target.ip())?;
        let tunnel = self.tunnel_for_peer(&nm, peer).await?;
        tunnel.connect_tcp(target).await
    }

    /// Dial TCP through the overlay, preferring the direct path and
    /// falling back to DERP (magicsock's behavior, sequential here).
    /// The routing decision enforces the overlay's prefs (accept-routes
    /// / exit-node).
    pub async fn dial(&self, target: SocketAddr) -> Result<crate::stream::BoxProxyStream> {
        match self.dial_direct(target).await {
            Ok(stream) => Ok(stream),
            Err(direct_err) => {
                let relayed = self
                    .dial_relay(target)
                    .await
                    .map(|s| Box::new(s) as crate::stream::BoxProxyStream);
                relayed.map_err(|relay_err| {
                    Error::network(format!(
                        "tailscale: both paths failed (direct: {direct_err}; relay: {relay_err})"
                    ))
                })
            }
        }
    }

    /// Open the overlay-wide UDP socket: send to any destination the
    /// netmap routes (each packet picks its peer's tunnel), receive
    /// every reply. Requires the config's `udp: true` (mihomo's UDP
    /// support flag), enforced per tunnel.
    pub async fn udp_socket(self: &Arc<Self>) -> Result<TsUdpSocket> {
        if !self.prefs.udp {
            return Err(Error::config(
                "tailscale: udp is disabled (the outbound's udp: flag is off)",
            ));
        }
        // Eagerly validate a netmap exists (send() re-checks per packet).
        if self.netmap().is_none() {
            return Err(Error::network(
                "tailscale: no netmap yet (the map poll has not delivered one)",
            ));
        }
        let (down_tx, down_rx) = tokio::sync::mpsc::channel::<(crate::addr::NetAddr, Vec<u8>)>(256);
        Ok(TsUdpSocket {
            overlay: self.clone(),
            sessions: tokio::sync::Mutex::new(HashMap::new()),
            down_tx,
            down_rx: tokio::sync::Mutex::new(down_rx),
        })
    }

    /// The control authority (host:port) — for the map poll task.
    pub fn control_authority(&self) -> &str {
        &self.control_authority
    }
}

/// A UDP socket through the whole overlay — the engine's UDP-outbound
/// shape: every datagram carries its own destination, replies come
/// back with their source. Internally one [`TsUdp`] per destination's
/// routed peer (a tunnel is bound to a single peer's cryptokey), with
/// each socket's replies funneled into one channel.
pub struct TsUdpSocket {
    overlay: Arc<TailscaleOverlay>,
    /// Per-peer inner sockets, keyed by node key hex.
    sessions: tokio::sync::Mutex<HashMap<String, TsUdp>>,
    down_tx: tokio::sync::mpsc::Sender<(crate::addr::NetAddr, Vec<u8>)>,
    down_rx: tokio::sync::Mutex<tokio::sync::mpsc::Receiver<(crate::addr::NetAddr, Vec<u8>)>>,
}

impl TsUdpSocket {
    /// Send one datagram to `target` (an IP, or a MagicDNS name the
    /// netmap resolves).
    pub async fn send(&self, target: &crate::addr::NetAddr, data: &[u8]) -> Result<()> {
        let ip = match &target.host {
            crate::addr::Host::Ip(ip) => *ip,
            crate::addr::Host::Domain(name) => self.overlay.resolve(name).ok_or_else(|| {
                Error::dns(format!(
                    "tailscale: {name} is not a MagicDNS name in the tailnet",
                ))
            })?,
        };
        let nm = self.overlay.netmap().ok_or_else(|| {
            Error::network("tailscale: no netmap yet (the map poll has not delivered one)")
        })?;
        let peer = self.overlay.routed_peer(&nm, ip)?;
        let peer_hex: String =
            peer.key.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let mut sessions = self.sessions.lock().await;
        if !sessions.contains_key(&peer_hex) {
            let tunnel = self.overlay.tunnel_for_peer(&nm, peer).await?;
            let udp = tunnel.udp_socket(nm.self_node.addresses.iter().find_map(|p| match p.addr {
                std::net::IpAddr::V6(v6) => Some(v6),
                _ => None,
            })).await?;
            // Funnel this peer's replies into the shared channel.
            let forward = udp.clone();
            let down = self.down_tx.clone();
            tokio::spawn(async move {
                while let Ok(pkt) = forward.recv().await {
                    if down.send(pkt).await.is_err() {
                        break;
                    }
                }
            });
            sessions.insert(peer_hex.clone(), udp);
        }
        // Safe: the key was just inserted; send through the stored one.
        let sock = sessions.get(&peer_hex).expect("inserted above");
        sock.send(&crate::addr::NetAddr::ip(ip, target.port), data)
            .await
    }

    /// Receive the next datagram from any destination this socket has
    /// written to.
    pub async fn recv(&self) -> Result<(crate::addr::NetAddr, Vec<u8>)> {
        let mut rx = self.down_rx.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| Error::network("tailscale: udp socket is closed"))
    }
}

/// One register round over a fresh noise connection — TryLogin's
/// single-exchange shape (one connection per request; see control's
/// module docs).
async fn register_round(
    control_url: &str,
    machine_key: &MachinePrivateKey,
    control_key: &MachinePublicKey,
    authority: &str,
    request: &RegisterRequest,
) -> Result<RegisterOutcome> {
    let dialer = ControlHttpDialer::from_url(control_url, machine_key.clone(), control_key.clone())?;
    let mut session = ControlSession::dial(&dialer).await?;
    register(&mut session, authority, request).await
}

/// Bring the overlay up: state keys, the control `/key` bootstrap, the
/// auth-key register, then the map long-poll (spawned; it feeds
/// [`TailscaleOverlay::netmap`] and reconnects with backoff until it
/// delivers). Returns once the first netmap has arrived — the
/// `watchBackendState` gate of the mihomo outbound (cached lines
/// 213-252) equivalent for "Running".
pub async fn start_overlay(config: &TailscaleConfig) -> Result<TailscaleOverlay> {
    start_overlay_with(config, POLL_RETRY).await
}

/// [`start_overlay`] with an injectable poll-retry policy (the
/// production policy is [`POLL_RETRY`]; tests shrink the delays).
pub async fn start_overlay_with(
    config: &TailscaleConfig,
    poll_retry: PollRetry,
) -> Result<TailscaleOverlay> {
    let control_url = config
        .control_url
        .clone()
        .filter(|u| !u.is_empty())
        .unwrap_or_else(|| DEFAULT_CONTROL_URL.to_string());
    let auth_key = config.auth_key.clone().unwrap_or_default();
    if auth_key.is_empty() {
        return Err(Error::config(
            "tailscale: auth-key is required this wave (interactive browser login is staged, \
             see RegisterOutcome::NeedsBrowserAuth)",
        ));
    }

    // 1. Identity: machine + node keys from the state dir, or ephemeral
    //    (tsnet's Store init + initMachineKeyLocked, state module docs).
    let state_dir: Option<PathBuf> = config
        .state_dir
        .as_deref()
        .filter(|d| !d.is_empty())
        .map(PathBuf::from);
    let identity = NodeIdentity::load_or_generate(state_dir.as_deref(), config.ephemeral)
        .map_err(|e| Error::config(format!("tailscale: state: {e}")))?;
    let mut node_key = identity.node_key;

    // 2. The control server's noise key (loadServerPubKeys) + the
    //    host:port authority requests are addressed to.
    let control_key = fetch_control_key(&control_url).await?;
    let control_authority = format!("{}:{}", host_of(&control_url), port_of(&control_url));

    let hostinfo = Hostinfo {
        backend_log_id: backend_log_id(),
        os: std::env::consts::OS.to_string(),
        app: "rustcrash".into(),
        hostname: config
            .hostname
            .clone()
            .unwrap_or_else(|| "rustcrash".into()),
        userspace: Some(true),
        userspace_router: Some(true),
        ..Default::default()
    };

    // 3. Register (TryLogin's auth-key leg), rotating the node key once
    //    if the server reports the current one expired — doLoginOrRegen's
    //    regen loop (direct.go:697-713 + 861-866: "Generating a new
    //    nodekey", OldPrivateNodeKey = PrivateNodeKey), bounded at one
    //    regen like upstream's regen flag (a second expired answer after
    //    a rotation is the "weird" hard error, direct.go:863).
    let mut old_node_key: Option<NodePrivateKey> = None;
    let mut registered = false;
    for round in 0..2 {
        let request = build_register_request(
            &NodeKey(*node_key.public().as_bytes()),
            old_node_key
                .as_ref()
                .map(|k| NodeKey(*k.public().as_bytes()))
                .as_ref(),
            &auth_key,
            hostinfo.clone(),
            config.ephemeral,
        );
        match register_round(
            &control_url,
            &identity.machine_key,
            &control_key,
            &control_authority,
            &request,
        )
        .await?
        {
            RegisterOutcome::Registered(_) => {
                if round > 0 {
                    // "key rotation is complete" (direct.go:876-879):
                    // commit the new key to the state store.
                    persist_rotated_node_key(
                        state_dir.as_deref(),
                        &node_key,
                        old_node_key.as_ref(),
                    )
                    .map_err(|e| {
                        Error::config(format!("tailscale: state: persist rotated key: {e}"))
                    })?;
                }
                registered = true;
                break;
            }
            RegisterOutcome::NeedsBrowserAuth(url) => {
                return Err(Error::config(format!(
                    "tailscale: interactive login required (visit {url}); browser auth is staged"
                )))
            }
            RegisterOutcome::NodeKeyExpired => {
                if round > 0 {
                    return Err(Error::protocol(
                        "register request: weird: regen=true but server says NodeKeyExpired",
                    ));
                }
                old_node_key = Some(node_key.clone());
                node_key = NodePrivateKey::generate();
            }
        }
    }
    if !registered {
        return Err(Error::protocol(
            "register request: node key expired twice (rotation refused by control)",
        ));
    }
    let node_key_pub = *node_key.public().as_bytes();
    // The overlay's disco keypair (magicsock.Conn's per-start key).
    let disco_key = DiscoPrivateKey::generate();
    let disco_wire = DiscoKeyText(*disco_key.public().as_bytes());

    // 4. The map long-poll (StreamMap) as auto.go's mapRoutine runs it
    //    (controlclient_auto.go:582-650): one poll at a time, a fresh
    //    noise connection each, backoff between failures reset by every
    //    delivered netmap — capped (see PollRetry's deltas). The same
    //    task owns the key-expiry renewal: when a netmap reports the
    //    self key expired (ipnlocal.go:1906's check), the stream is
    //    interrupted, the node key rotates through the OldNodeKey
    //    register round, and the poll restarts under the new identity
    //    (auto.go's restartMap-after-relogin shape).
    let netmap_slot: Arc<Mutex<Option<NetMap>>> = Arc::new(Mutex::new(None));
    let changed = Arc::new(Notify::new());
    let selected_exit: Arc<Mutex<Option<NodeKey>>> = Arc::new(Mutex::new(None));
    let poll_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let renewal_error: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let shared_node_key: Arc<Mutex<NodePrivateKey>> = Arc::new(Mutex::new(node_key.clone()));
    let tunnels: Arc<tokio::sync::Mutex<HashMap<String, TsTunnel>>> =
        Arc::new(tokio::sync::Mutex::new(HashMap::new()));
    {
        let slot = netmap_slot.clone();
        let changed = changed.clone();
        let selected_exit = selected_exit.clone();
        let poll_error = poll_error.clone();
        let renewal_error = renewal_error.clone();
        let shared_node_key = shared_node_key.clone();
        let tunnels = tunnels.clone();
        let authority = control_authority.clone();
        let machine_key = identity.machine_key.clone();
        let prefs = OverlayPrefs::from_config(config);
        let auth_key = auth_key.clone();
        let state_dir = state_dir.clone();
        let disco_wire = disco_wire.clone();
        let ephemeral = config.ephemeral;
        // The renewal interrupt: a netmap that reports an expired self
        // key bumps the generation, and the select! below drops the
        // held-open stream so the rotation can run promptly.
        let (interrupt_tx, mut interrupt_rx) = tokio::sync::watch::channel(0u64);
        let expired_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        tokio::spawn(async move {
            let mut attempt: u32 = 0;
            // One MapSession across reconnects: deltas accumulate, and a
            // full Peers list (what a fresh stream starts with) replaces
            // the set (map.go:556-570). A rotation REPLACES it: the new
            // identity's map starts fresh (upstream's restartMap).
            let mut map_session = MapSession::new(NodeKey(node_key_pub));
            let mut node_key = node_key;
            loop {
                let map_dialer = match ControlHttpDialer::from_url(
                    &control_url,
                    machine_key.clone(),
                    control_key.clone(),
                ) {
                    Ok(d) => d,
                    Err(e) => {
                        tracing::debug!(target: "engine", "tailscale: map dialer: {e}");
                        return;
                    }
                };
                let Ok(mut s) = ControlSession::dial(&map_dialer).await else {
                    // Back off and retry (below).
                    attempt += 1;
                    if attempt >= poll_retry.max_attempts {
                        *poll_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(format!(
                            "map poll gave up after {attempt} attempts (no netmap from control)"
                        ));
                        return;
                    }
                    tokio::time::sleep(poll_retry.delay(attempt - 1)).await;
                    continue;
                };
                let req = build_map_request(
                    &NodeKey(*node_key.public().as_bytes()),
                    hostinfo.clone(),
                    true,
                    &disco_wire,
                );
                let delivered = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let on_map = {
                    let slot = slot.clone();
                    let selected_exit = selected_exit.clone();
                    let changed = changed.clone();
                    let interrupt = interrupt_tx.clone();
                    let expired_flag = expired_flag.clone();
                    let delivered = delivered.clone();
                    let prefs = prefs.clone();
                    move |nm: &NetMap| {
                        *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(nm.clone());
                        // Re-resolve the exit node against the fresh map
                        // (the "old and new exit node when the selection
                        // changes" reconfiguration, ipnlocal.go:6145-6152).
                        *selected_exit.lock().unwrap_or_else(|e| e.into_inner()) = nm
                            .select_exit_node(prefs.exit_node.as_deref())
                            .map(|p| p.key.clone());
                        delivered.store(true, std::sync::atomic::Ordering::SeqCst);
                        changed.notify_one();
                        // ipnlocal.go:1906: isExpired = !SelfKeyExpiry()
                        // .IsZero() && SelfKeyExpiry().Before(now).
                        if nm.self_key_expired(control::unix_now()) {
                            expired_flag.store(true, std::sync::atomic::Ordering::SeqCst);
                            let next = interrupt.borrow().wrapping_add(1);
                            let _ = interrupt.send(next);
                        }
                    }
                };
                let res = tokio::select! {
                    r = stream_map(&mut s, &authority, &req, &mut map_session, on_map) => r,
                    _ = interrupt_rx.changed() => {
                        Err(Error::network("self node key expired; rotating"))
                    }
                };
                // Key-expiry renewal (direct.go:697-713, 861-879): one
                // rotation per detected expiry, with the OldNodeKey flow.
                if expired_flag.swap(false, std::sync::atomic::Ordering::SeqCst) {
                    let old_pub = *node_key.public().as_bytes();
                    let new_key = NodePrivateKey::generate();
                    let request = build_register_request(
                        &NodeKey(*new_key.public().as_bytes()),
                        Some(&NodeKey(old_pub)),
                        &auth_key,
                        hostinfo.clone(),
                        ephemeral,
                    );
                    match register_round(
                        &control_url,
                        &machine_key,
                        &control_key,
                        &authority,
                        &request,
                    )
                    .await
                    {
                        Ok(RegisterOutcome::Registered(_)) => {
                            if let Err(e) = persist_rotated_node_key(
                                state_dir.as_deref(),
                                &new_key,
                                Some(&node_key),
                            ) {
                                tracing::warn!(target: "engine",
                                    "tailscale: persisting the rotated node key failed: {e}");
                            }
                            tracing::info!(target: "engine",
                                "tailscale: node key renewed (OldNodeKey rotation accepted)");
                            *renewal_error
                                .lock()
                                .unwrap_or_else(|e| e.into_inner()) = None;
                            node_key = new_key.clone();
                            *shared_node_key.lock().unwrap_or_else(|e| e.into_inner()) = new_key;
                            // Fresh map session under the new identity
                            // (restartMap after relogin), and the peer
                            // tunnels must re-key against the new node
                            // key — drop the cache so the next dial
                            // respawns them.
                            map_session = MapSession::new(NodeKey(*node_key.public().as_bytes()));
                            tunnels.lock().await.clear();
                            attempt = 0;
                            tokio::time::sleep(poll_retry.initial).await;
                            continue;
                        }
                        Ok(RegisterOutcome::NodeKeyExpired) => {
                            *renewal_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(
                                "weird: regen=true but server says NodeKeyExpired".into(),
                            );
                        }
                        Ok(RegisterOutcome::NeedsBrowserAuth(url)) => {
                            *renewal_error.lock().unwrap_or_else(|e| e.into_inner()) =
                                Some(format!("renewal needs interactive login ({url})"));
                        }
                        Err(e) => {
                            *renewal_error.lock().unwrap_or_else(|e| e.into_inner()) =
                                Some(format!("renewal register failed: {e}"));
                        }
                    }
                    // The rotation failed: keep serving under the old
                    // identity (the last netmap stays) and let the poll's
                    // ordinary backoff retry the stream; the next netmap
                    // that still reports expiry bumps the interrupt again.
                }
                if delivered.load(std::sync::atomic::Ordering::SeqCst) {
                    // "Reset the backoff timer if we got a netmap"
                    // (auto.go:482-486). A cleanly closed stream re-polls
                    // after a floor pause (upstream goes through its
                    // backoff too; hot-dialing a closing server helps
                    // nobody); an ended-with-error poll backs off below.
                    attempt = 0;
                    if res.is_ok() {
                        tokio::time::sleep(poll_retry.initial).await;
                    }
                    continue;
                }
                attempt += 1;
                if let Err(e) = res {
                    tracing::debug!(target: "engine", "tailscale: map poll ended: {e}");
                }
                if attempt >= poll_retry.max_attempts {
                    *poll_error.lock().unwrap_or_else(|e| e.into_inner()) = Some(format!(
                        "map poll gave up after {attempt} attempts (last netmap stays)"
                    ));
                    return;
                }
                tokio::time::sleep(poll_retry.delay(attempt - 1)).await;
            }
        });
    }

    let overlay = TailscaleOverlay {
        node_key: shared_node_key,
        disco_key,
        netmap: netmap_slot,
        netmap_changed: changed,
        selected_exit_node: selected_exit,
        prefs: OverlayPrefs::from_config(config),
        poll_error,
        renewal_error,
        tunnels,
        control_authority,
    };

    // 5. Wait for the first netmap (bounded; beyond that the poll's own
    //    backoff governs).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while overlay.netmap().is_none() {
        if std::time::Instant::now() >= deadline {
            return Err(Error::network(
                "tailscale: no netmap arrived from the map poll within 15s",
            ));
        }
        if let Some(err) = overlay.poll_error() {
            return Err(Error::network(format!(
                "tailscale: the map poll gave up before a netmap arrived ({err})"
            )));
        }
        let changed = overlay.netmap_changed.clone();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), changed.notified()).await;
    }
    Ok(overlay)
}

// ---------------------------------------------------------------------------
// The outbound dial API: a process-global overlay cache + entry points
// ---------------------------------------------------------------------------

/// The process-global overlay registry — the openvpn `TUNNELS` shape
/// (proto/openvpn.rs:4651-4652): repeated dials with the same config
/// reuse the same login, netmap and peer tunnels instead of
/// re-registering a node per connection (which control servers rate
/// limit and ephemeral re-registration would churn the tailnet).
static OVERLAYS: std::sync::OnceLock<tokio::sync::Mutex<HashMap<String, Arc<TailscaleOverlay>>>> =
    std::sync::OnceLock::new();

/// The cache key: every field that changes what the overlay IS. The
/// auth key is deliberately excluded — it authenticates the same
/// identity either way and must not live in a map key (secret hygiene:
/// keys never appear in logs or panics).
fn overlay_cache_key(cfg: &TailscaleConfig) -> String {
    [
        cfg.name.as_str(),
        cfg.control_url.as_deref().unwrap_or(""),
        cfg.state_dir.as_deref().unwrap_or(""),
        cfg.hostname.as_deref().unwrap_or(""),
        if cfg.ephemeral { "1" } else { "0" },
        match cfg.accept_routes {
            Some(true) => "ar:1",
            Some(false) => "ar:0",
            None => "ar:",
        },
        cfg.exit_node.as_deref().unwrap_or(""),
        match cfg.exit_node_allow_lan_access {
            Some(true) => "lan:1",
            Some(false) => "lan:0",
            None => "lan:",
        },
        if cfg.udp { "udp:1" } else { "udp:0" },
    ]
    .join("\u{1f}")
}

/// The live overlay for `cfg`, logged in once and reused — the outbound
/// dial entry point below and the integrator's wave share one node
/// identity per config. The cache holds the overlay for the process
/// lifetime; an overlay whose poll gave up still serves dials off its
/// last netmap (see [`TailscaleOverlay::poll_error`]).
pub async fn overlay_for(config: &TailscaleConfig) -> Result<Arc<TailscaleOverlay>> {
    let key = overlay_cache_key(config);
    let cache = OVERLAYS.get_or_init(Default::default);
    {
        let map = cache.lock().await;
        if let Some(overlay) = map.get(&key) {
            return Ok(overlay.clone());
        }
    }
    // Bring the overlay up OUTSIDE the lock so concurrent dials with the
    // same config don't serialize behind a login; the second one to
    // finish inserts, the other's slot is dropped (same as its state).
    let overlay = Arc::new(start_overlay(config).await?);
    let mut map = cache.lock().await;
    Ok(map.entry(key).or_insert(overlay).clone())
}

/// Dial TCP through the tailscale overlay — the outbound entry: starts
/// (or reuses) the overlay for `config` and connects to `target`
/// through the netmap's routing decision (accept-routes / exit-node
/// enforced, MagicDNS irrelevant for a literal IP).
pub async fn dial_tcp(
    config: &TailscaleConfig,
    target: &SocketAddr,
) -> Result<crate::stream::BoxProxyStream> {
    let overlay = overlay_for(config).await?;
    overlay.dial(*target).await
}

/// [`dial_tcp`] for an engine target: a literal IP dials straight, a
/// domain resolves through MagicDNS first ([`TailscaleOverlay::resolve`]
/// — names outside the tailnet map are refused, they are not the
/// overlay's to answer).
pub async fn dial_tcp_addr(
    config: &TailscaleConfig,
    target: &crate::addr::NetAddr,
) -> Result<crate::stream::BoxProxyStream> {
    let ip = match &target.host {
        crate::addr::Host::Ip(ip) => *ip,
        crate::addr::Host::Domain(name) => {
            let overlay = overlay_for(config).await?;
            let ip = overlay.resolve(name).ok_or_else(|| {
                Error::dns(format!("tailscale: {name} is not a MagicDNS name in the tailnet"))
            })?;
            return overlay.dial(SocketAddr::new(ip, target.port)).await;
        }
    };
    dial_tcp(config, &SocketAddr::new(ip, target.port)).await
}

/// Open the overlay's UDP socket (see [`TailscaleOverlay::udp_socket`])
/// — requires `udp: true` in the config.
pub async fn dial_udp(config: &TailscaleConfig) -> Result<TsUdpSocket> {
    let overlay = overlay_for(config).await?;
    overlay.udp_socket().await
}

fn host_of(url: &str) -> String {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or(rest);
    let host = match authority.rsplit_once(':') {
        Some((h, p)) if !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()) => h,
        _ => authority,
    };
    host.trim_start_matches('[').trim_end_matches(']').to_string()
}

fn port_of(url: &str) -> u16 {
    let rest = url.split("://").nth(1).unwrap_or(url);
    let authority = rest.split('/').next().unwrap_or(rest);
    let has_port = authority
        .rsplit_once(':')
        .map(|(_, p)| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        .unwrap_or(false);
    if has_port {
        authority
            .rsplit_once(':')
            .and_then(|(_, p)| p.parse().ok())
            .unwrap_or(80)
    } else if url.starts_with("https") {
        443
    } else {
        80
    }
}

fn backend_log_id() -> String {
    // direct.go:755-757 refuses an empty BackendLogID; a random opaque
    // id serves the same purpose (log correlation) without dragging in
    // logtail.
    let mut b = [0u8; 8];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
    b.iter().map(|x| format!("{x:02x}")).collect()
}

/// Bring up the overlay and prove it is dial-ready — the counterpart
/// of upstream `NewTailscale` + `start`/`ensureStarted` (cached lines
/// 114-211). Wave 13 runs the real control path (login + netmap +
/// peer reachability + the routing prefs + the disco-informed data
/// plane) and then stops with the precise remaining-gap error: the
/// outbound wiring itself is [`dial_tcp`]/[`dial_udp`] (real streams —
/// the integrator's step to splice into the relay), and the two
/// enumerated gaps stand.
pub async fn connect(config: &TailscaleConfig) -> Result<()> {
    // Everything that can be brought up, is (and fails loudly).
    let overlay = start_overlay(config).await?;
    let nm = overlay.netmap().ok_or_else(|| {
        Error::network("tailscale: start_overlay returned without a netmap")
    })?;
    if nm.peers.is_empty() {
        return Err(Error::config(
            "tailscale: logged in and netmap present, but the tailnet has no peers to dial",
        ));
    }
    let reachable = nm
        .peers
        .iter()
        .any(|p| !p.endpoints.is_empty() || p.home_derp != 0);
    if !reachable {
        return Err(Error::config(
            "tailscale: logged in, netmap present, but no peer has a UDP endpoint or a home \
             DERP relay to reach it through",
        ));
    }
    // Logged in, netmap present, peer reachable — stop here with the
    // precise remaining-gap list.
    Err(Error::config(NOT_IMPLEMENTED))
}

/// Bootstrap material for the wire-level bring-up — the pieces the
/// wave-10 progress path owns: the machine identity and the control
/// server's noise public key, plus an optional explicit DERP server.
///
/// Keys are never literals: callers generate them
/// ([`MachinePrivateKey::generate`]) or load them from state.
#[derive(Debug, Clone)]
pub struct ControlBootstrap {
    /// The machine's noise identity.
    pub machine_key: MachinePrivateKey,
    /// The control server's expected static key.
    pub control_key: MachinePublicKey,
    /// An explicit DERP server URL to register against (normally the
    /// netmap's DERPMap picks this; pre-netmap tests pass one).
    pub derp_url: Option<String>,
}

/// The progress ledger of a wire-level bring-up — what came up before
/// the (still missing) ipn layer takes over.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct BringUpReport {
    /// The control dial completed: TCP + `/ts2021` upgrade + the Noise
    /// IK handshake authenticated against the pinned control key.
    pub control_reachable: bool,
    /// The protocol version negotiated with control.
    pub control_protocol_version: Option<u16>,
    /// A DERP registration completed: HTTP upgrade + server-key
    /// exchange + naclboxed ClientInfo accepted.
    pub derp_registered: bool,
}

/// Bring the control-plane wires up: dial control over the `/ts2021`
/// upgrade, authenticate with Noise IK, and (when `bootstrap.derp_url`
/// is set) register with a DERP server. This is the progress half of
/// [`connect`] — everything below the ipn layer that a tsnet node
/// would do first. Fails with the dial error if a configured wire
/// cannot come up.
pub async fn connect_with_bootstrap(
    config: &TailscaleConfig,
    bootstrap: &ControlBootstrap,
) -> Result<BringUpReport> {
    let url = config
        .control_url
        .as_deref()
        .filter(|u| !u.is_empty())
        .ok_or_else(|| {
            Error::config("tailscale: control-url is required to bring up the control plane")
        })?;
    let mut report = BringUpReport::default();

    // Control: /ts2021 upgrade + Noise IK (controlhttp client.go:346-363).
    let dialer = ControlHttpDialer::from_url(
        url,
        bootstrap.machine_key.clone(),
        bootstrap.control_key.clone(),
    )?;
    let mut control = dialer.dial().await?;
    // One encrypted round trip proves the record layer (conn.go Write/Read).
    let probe: &[u8] = b"tailscale.wave10.probe";
    control.send(probe).await?;
    let echoed = control.recv().await?;
    if echoed != probe {
        return Err(Error::protocol(
            "tailscale: control echo mismatch after noise handshake",
        ));
    }
    report.control_protocol_version = Some(control.protocol_version());
    report.control_reachable = true;

    // DERP: register when an explicit server is provided (pre-netmap;
    // upstream gets the DERPMap from the control netmap).
    if let Some(derp_url) = bootstrap.derp_url.as_deref().filter(|u| !u.is_empty()) {
        let node_key = NodePrivateKey::generate();
        let mut derp = derp_connect(derp_url, &node_key, &DerpHttpOptions::default()).await?;
        match derp.recv().await? {
            DerpMessage::ServerInfo(_) => {}
            other => {
                return Err(Error::protocol(format!(
                    "tailscale: unexpected first DERP message: {other:?}"
                )))
            }
        }
        report.derp_registered = true;
    }

    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbound::RelayHandler;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn test_auth_key() -> Option<String> {
        // SECURITY: the repo's standing rule — fake credentials come from
        // the environment only, never a source literal. Absent means "not
        // exercised".
        std::env::var("RUSTCRASH_TEST_TS_AUTH_KEY").ok().filter(|k| !k.is_empty())
    }

    /// A generated-in-test fake auth key (never a literal; the mimic
    /// echoes it back for comparison).
    fn generated_auth_key() -> String {
        let mut b = [0u8; 12];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut b);
        format!("tskey-auth-{}", b.iter().map(|x| format!("{x:02x}")).collect::<String>())
    }

    #[test]
    fn config_field_surface_is_complete() {
        // Every TailscaleOption field must be carried (cached
        // adapter/outbound/tailscale.go:54-67). Setting each one proves
        // the surface; new upstream fields should extend this test.
        let cfg = TailscaleConfig {
            name: "ts0".into(),
            hostname: Some("rustcrash-node".into()),
            auth_key: test_auth_key(),
            control_url: Some("https://control.example".into()),
            state_dir: Some("ts-state".into()),
            ephemeral: true,
            udp: true,
            accept_routes: Some(true),
            exit_node: Some("auto:any".into()),
            exit_node_allow_lan_access: Some(false),
        };
        assert_eq!(cfg.name, "ts0");
        assert_eq!(cfg.hostname.as_deref(), Some("rustcrash-node"));
        assert_eq!(cfg.control_url.as_deref(), Some("https://control.example"));
        assert_eq!(cfg.state_dir.as_deref(), Some("ts-state"));
        assert!(cfg.ephemeral && cfg.udp);
        assert_eq!(cfg.accept_routes, Some(true));
        assert_eq!(cfg.exit_node.as_deref(), Some("auto:any"));
        assert_eq!(cfg.exit_node_allow_lan_access, Some(false));
    }

    #[test]
    fn config_defaults_and_named_constructor() {
        let cfg = TailscaleConfig::new("ts");
        assert_eq!(cfg.name, "ts");
        let TailscaleConfig {
            name,
            hostname,
            auth_key,
            control_url,
            state_dir,
            ephemeral,
            udp,
            accept_routes,
            exit_node,
            exit_node_allow_lan_access,
        } = TailscaleConfig::default();
        assert_eq!(name, "");
        assert!(hostname.is_none());
        assert!(auth_key.is_none());
        assert!(control_url.is_none());
        assert!(state_dir.is_none());
        assert!(!ephemeral);
        assert!(!udp);
        assert!(accept_routes.is_none());
        assert!(exit_node.is_none());
        assert!(exit_node_allow_lan_access.is_none());
    }

    #[test]
    fn auto_exit_node_parsing_matches_ipn() {
        // ipn.ParseAutoExitNodeString: "auto:" prefix + non-empty rest.
        assert!(parse_auto_exit_node("auto:any"));
        assert!(parse_auto_exit_node("auto:bye"));
        assert!(!parse_auto_exit_node("auto:"));
        assert!(!parse_auto_exit_node("auto"));
        assert!(!parse_auto_exit_node(""));
        assert!(!parse_auto_exit_node("100.101.102.103"));
        assert!(!parse_auto_exit_node("exit.example.com"));
    }

    #[test]
    fn exit_node_needs_status_matches_upstream() {
        // tailscaleExitNodeNeedsStatus (cached:341-347): only literal
        // exit nodes need the Status() lookup.
        let mut cfg = TailscaleConfig::new("ts");
        assert!(!cfg.exit_node_needs_status());
        cfg.exit_node = Some("auto:any".into());
        assert!(!cfg.exit_node_needs_status());
        cfg.exit_node = Some("".into());
        assert!(!cfg.exit_node_needs_status());
        cfg.exit_node = Some("100.101.102.103".into());
        assert!(cfg.exit_node_needs_status());
        cfg.exit_node = Some("exit.example.com".into());
        assert!(cfg.exit_node_needs_status());
    }

    #[test]
    fn masked_prefs_match_build_tailscale_masked_prefs() {
        // Nothing configured -> nothing to edit (upstream nil, nil).
        assert_eq!(TailscaleConfig::new("ts").masked_prefs(), None);

        // accept-routes -> RouteAll.
        let cfg = TailscaleConfig::new("ts").with_accept_routes(true);
        assert_eq!(
            cfg.masked_prefs(),
            Some(MaskedPrefs {
                route_all: Some(true),
                auto_exit_node: None,
                exit_node_allow_lan_access: None,
            })
        );

        // auto exit node -> AutoExitNode, no status needed.
        let cfg = TailscaleConfig::new("ts").with_exit_node("auto:bye");
        assert_eq!(
            cfg.masked_prefs(),
            Some(MaskedPrefs {
                route_all: None,
                auto_exit_node: Some("bye".into()),
                exit_node_allow_lan_access: None,
            })
        );

        // Literal exit node: nothing is masked up front (cached:318-334
        // only RouteAll / auto exit / status-free LAN access apply here);
        // the exit node and its LAN pref go through applyExitNodePrefs
        // after a Status() lookup, so masked_prefs() stays None.
        let cfg = TailscaleConfig::new("ts")
            .with_exit_node("100.101.102.103")
            .with_exit_node_allow_lan_access(true);
        assert_eq!(cfg.masked_prefs(), None);
        assert!(cfg.exit_node_needs_status());

        // auto exit node + LAN access: both applied up front.
        let cfg = TailscaleConfig::new("ts")
            .with_exit_node("auto:any")
            .with_exit_node_allow_lan_access(true);
        assert_eq!(
            cfg.masked_prefs(),
            Some(MaskedPrefs {
                route_all: None,
                auto_exit_node: Some("any".into()),
                exit_node_allow_lan_access: Some(true),
            })
        );
    }

    #[test]
    fn auth_key_never_prints_in_debug() {
        // Only env-sourced fake credentials are ever attached; Debug must
        // not expose them.
        let cfg = TailscaleConfig::new("ts").with_auth_key(Some("env-sourced-secret".into()));
        let printed = format!("{cfg:?}");
        assert!(!printed.contains("env-sourced-secret"), "{printed}");
        assert!(printed.contains("[redacted]"), "{printed}");
    }

    #[tokio::test]
    async fn connect_without_control_url_fails_early() {
        // No control-url and no auth-key: the first config gate trips.
        let err = connect(&TailscaleConfig::new("ts")).await.unwrap_err();
        assert!(err.to_string().contains("auth-key"), "{err}");
    }

    #[tokio::test]
    async fn connect_fails_with_the_precise_cited_error() {
        // With a control-url pointing at a closed port, the login leg
        // fails with the network error (never NOT_IMPLEMENTED — the gap
        // error only comes after real progress).
        let cfg = TailscaleConfig::new("ts")
            .with_auth_key(Some(generated_auth_key()))
            .with_control_url("http://127.0.0.1:1".to_string());
        let err = connect(&cfg).await.unwrap_err();
        assert!(err.to_string().contains("/key"), "{err}");
        assert!(!err.to_string().contains(NOT_IMPLEMENTED), "{err}");
    }

    // -------------------------------------------------------------------
    // Hermetic end-to-end: a Go-parity control mimic (key fetch +
    // register + map poll), a DERP mimic, and the engine's own
    // WireGuard endpoint as the peer — proving login, netmap, and TCP
    // relay through BOTH data-plane paths.
    // -------------------------------------------------------------------

    struct EchoRelay;
    impl RelayHandler for EchoRelay {
        fn handle_tcp(
            self: Arc<Self>,
            _meta: crate::inbound::TcpMeta,
            client: crate::stream::BoxProxyStream,
        ) {
            tokio::spawn(async move {
                let mut client = client;
                let mut buf = vec![0u8; 4096];
                loop {
                    match client.read(&mut buf).await {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if client.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                    }
                }
            });
        }
        fn handle_udp(
            self: Arc<Self>,
            _source: SocketAddr,
            _inbound: String,
            mut uplink: tokio::sync::mpsc::Receiver<(crate::addr::NetAddr, Vec<u8>)>,
            downlink: tokio::sync::mpsc::Sender<(crate::addr::NetAddr, Vec<u8>)>,
        ) {
            tokio::spawn(async move {
                while let Some((target, data)) = uplink.recv().await {
                    let _ = downlink.send((target, data)).await;
                }
            });
        }
    }

    /// A per-round mutation of the map message the mimic is about to
    /// frame (tests vary the netmap across reconnects).
    type MapTweak = std::sync::Arc<dyn Fn(usize, &mut serde_json::Value) + Send + Sync>;

    /// The control-side state one test run needs: keys, the peer's
    /// netmap entry, and the endpoint address to advertise.
    struct ControlFixture {
        control_key: MachinePrivateKey,
        /// The peer node key (hex) the netmap will advertise.
        peer_key_hex: String,
        /// The peer's advertised UDP endpoint.
        peer_endpoint: Option<SocketAddr>,
        /// The DERP URL of the peer's home region.
        derp_url: Option<String>,
        auth_key: String,
        /// The RegisterRequest.Ephemeral flag the mimic must see.
        ephemeral: bool,
        /// `DNSConfig.Domains` the map carries (search domains).
        dns_domains: Vec<String>,
        /// Per-map-connection mutation of the map message: (round index,
        /// 1-based, the JSON). Applied just before framing.
        map_tweak: Option<MapTweak>,
        /// Close each map connection after delivering (the client's poll
        /// reconnects); false = hold the long-poll open.
        map_close_after_deliver: bool,
        /// Answer HTTP 500 for map connections whose round is >= this.
        map_fail_from_round: Option<usize>,
        /// The peer's disco key (hex) — `Node.DiscoKey` in the map.
        peer_disco_hex: Option<String>,
        /// Where the mimic captures the client's `MapRequest.DiscoKey`
        /// (the in-test peer fronts learn our disco public from it).
        disco_capture: Option<Arc<Mutex<Option<[u8; 32]>>>>,
        /// Where the mimic records the register rounds: the first node
        /// key seen, and the (old, new) pair of the OldNodeKey renewal.
        register_capture: Option<Arc<RegisterCapture>>,
    }

    /// The register-round ledger a renewal test asserts on.
    #[derive(Default)]
    struct RegisterCapture {
        /// The node key of the FIRST register.
        first: Mutex<Option<[u8; 32]>>,
        /// (OldNodeKey, NodeKey) of the register that carried a
        /// non-zero OldNodeKey — the key-expiry renewal round.
        renewal: Mutex<Option<([u8; 32], [u8; 32])>>,
    }

    impl ControlFixture {
        /// The per-connection clone: the tweak closure is shared (Arc),
        /// everything else is cheap state.
        fn clone_for_conn(&self) -> Self {
            ControlFixture {
                control_key: self.control_key.clone(),
                peer_key_hex: self.peer_key_hex.clone(),
                peer_endpoint: self.peer_endpoint,
                derp_url: self.derp_url.clone(),
                auth_key: self.auth_key.clone(),
                ephemeral: self.ephemeral,
                dns_domains: self.dns_domains.clone(),
                map_tweak: self.map_tweak.clone(),
                map_close_after_deliver: self.map_close_after_deliver,
                map_fail_from_round: self.map_fail_from_round,
                peer_disco_hex: self.peer_disco_hex.clone(),
                disco_capture: self.disco_capture.clone(),
                register_capture: self.register_capture.clone(),
            }
        }

        fn new(
            control_key: MachinePrivateKey,
            peer_key_hex: String,
            peer_endpoint: Option<SocketAddr>,
            derp_url: Option<String>,
            auth_key: String,
        ) -> Self {
            ControlFixture {
                control_key,
                peer_key_hex,
                peer_endpoint,
                derp_url,
                auth_key,
                ephemeral: false,
                dns_domains: Vec::new(),
                map_tweak: None,
                map_close_after_deliver: false,
                map_fail_from_round: None,
                peer_disco_hex: None,
                disco_capture: None,
                register_capture: None,
            }
        }
    }

    /// Run the control mimic: serves the /key fetch, the register, and
    /// the map poll(s), one task per connection — a real control server
    /// is concurrent, and the overlay's poll + a fresh login (the dial
    /// API's cache miss) overlap. Assertions validate every request
    /// shape.
    async fn control_server(listener: tokio::net::TcpListener, fx: ControlFixture) {
        let map_round = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        loop {
            let (sock, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => return,
            };
            let fx = fx.clone_for_conn();
            let map_round = map_round.clone();
            tokio::spawn(async move {
                control_conn(sock, fx, map_round).await;
            });
        }
    }

    #[allow(clippy::too_many_lines)]
    async fn control_conn(
        mut sock: tokio::net::TcpStream,
        fx: ControlFixture,
        map_round: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use base64::Engine;
        let mut head = Vec::new();
            let mut b = [0u8; 1];
            loop {
                if sock.read_exact(&mut b).await.is_err() {
                    break;
                }
                head.push(b[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let text = String::from_utf8_lossy(&head).into_owned();
            if text.starts_with("GET /key") {
                // loadServerPubKeys' endpoint (over TLS in production).
                assert!(text.contains("GET /key?v=148"), "{text}");
                let hexs: String = fx
                    .control_key
                    .public()
                    .as_bytes()
                    .iter()
                    .map(|x| format!("{x:02x}"))
                    .collect();
                let body = format!(r#"{{"publicKey":"mkey:{hexs}"}}"#);
                sock.write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                        body.len()
                    )
                    .as_bytes(),
                )
                .await
                .unwrap();
                return;
            }
            if !text.starts_with("POST /ts2021") {
                panic!("unexpected request: {text}");
            }
            let b64 = text
                .lines()
                .find_map(|l| l.strip_prefix("X-Tailscale-Handshake: "))
                .expect("handshake header");
            let init = base64::engine::general_purpose::STANDARD.decode(b64).unwrap();
            sock.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Upgrade: tailscale-control-protocol\r\n\
                  Connection: upgrade\r\n\r\n",
            )
            .await
            .unwrap();
            let mut conn = server_handshake(sock, &fx.control_key, Some(init))
                .await
                .unwrap();

            // One HTTP/1.1 request inside the noise records.
            let mut buf = Vec::new();
            let (path, body) = loop {
                let rec = conn.recv().await.unwrap();
                buf.extend_from_slice(&rec);
                let t = String::from_utf8_lossy(&buf).into_owned();
                if let Some(pos) = t.find("\r\n\r\n") {
                    if let Some(cl) = t
                        .lines()
                        .find_map(|l| l.strip_prefix("Content-Length: "))
                        .and_then(|v| v.trim().parse::<usize>().ok())
                    {
                        if buf.len() >= pos + 4 + cl {
                            let path = t
                                .lines()
                                .next()
                                .unwrap()
                                .split_ascii_whitespace()
                                .nth(1)
                                .unwrap()
                                .to_string();
                            break (path, buf[pos + 4..pos + 4 + cl].to_vec());
                        }
                    }
                }
            };

            match path.as_str() {
                "/machine/register" => {
                    let req: RegisterRequest = serde_json::from_slice(&body).unwrap();
                    assert_eq!(req.version, CURRENT_CAPABILITY_VERSION);
                    assert_eq!(req.auth.as_ref().unwrap().auth_key, fx.auth_key);
                    assert_eq!(
                        req.ephemeral, fx.ephemeral,
                        "the ephemeral login flag (direct.go:766) round-trips"
                    );
                    // The register ledger: the first round's key, and the
                    // OldNodeKey renewal round (direct.go:761).
                    if let Some(cap) = &fx.register_capture {
                        let nk = *req.node_key.as_bytes();
                        let old = *req.old_node_key.as_bytes();
                        let mut first = cap.first.lock().unwrap_or_else(|e| e.into_inner());
                        if first.is_none() {
                            *first = Some(nk);
                        } else if old != [0u8; 32] {
                            *cap.renewal.lock().unwrap_or_else(|e| e.into_inner()) = Some((old, nk));
                        }
                    }
                    let resp = br#"{"MachineAuthorized":true}"#.to_vec();
                    let head = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        resp.len()
                    );
                    let mut wire = head.into_bytes();
                    wire.extend_from_slice(&resp);
                    conn.send(&wire).await.unwrap();
                }
                "/machine/map" => {
                    let req: MapRequest = serde_json::from_slice(&body).unwrap();
                    assert!(req.stream);
                    assert!(req.keep_alive);
                    if let Some(slot) = &fx.disco_capture {
                        *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(req.disco_key.0);
                    }
                    let round = map_round
                        .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                        + 1;
                    if let Some(from) = fx.map_fail_from_round {
                        if round >= from {
                            let resp = br#"{"Error":"map rejected"}"#.to_vec();
                            let head = format!(
                                "HTTP/1.1 500 nope\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                resp.len()
                            );
                            let mut wire = head.into_bytes();
                            wire.extend_from_slice(&resp);
                            conn.send(&wire).await.unwrap();
                            return;
                        }
                    }
                    // The netmap: self + one peer (+ DERPMap when the
                    // peer has a home relay). Built with serde_json so
                    // the Go field names are asserted by construction.
                    let self_hex: String = req
                        .node_key
                        .as_bytes()
                        .iter()
                        .map(|b| format!("{b:02x}"))
                        .collect();
                    let mut peer = serde_json::json!({
                        "ID": 2,
                        "Name": "peer.tail-scale.ts.net.",
                        "User": 10,
                        "Key": format!("nodekey:{}", fx.peer_key_hex),
                        "Addresses": ["100.64.0.2/32"],
                        "AllowedIPs": ["100.64.0.2/32"],
                        "HomeDERP": 1,
                        "Online": true,
                        "MachineAuthorized": true,
                    });
                    if let Some(ep) = fx.peer_endpoint {
                        peer["Endpoints"] = serde_json::json!([ep.to_string()]);
                    }
                    if let Some(dk) = &fx.peer_disco_hex {
                        peer["DiscoKey"] = serde_json::json!(format!("discokey:{dk}"));
                    }
                    let mut msg = serde_json::json!({
                        "Node": {
                            "ID": 1,
                            "Name": "self-node.tail-scale.ts.net.",
                            "Key": format!("nodekey:{self_hex}"),
                            "Addresses": ["100.64.0.1/32"],
                            "AllowedIPs": ["100.64.0.1/32"],
                        },
                        "Peers": [peer],
                        "Domain": "tail-scale.ts.net",
                    });
                    if !fx.dns_domains.is_empty() {
                        msg["DNSConfig"] = serde_json::json!({
                            "Domains": fx.dns_domains,
                            "Proxied": true,
                        });
                    }
                    if let Some(tweak) = &fx.map_tweak {
                        tweak(round, &mut msg);
                    }
                    if let Some(url) = &fx.derp_url {
                        let authority = url
                            .trim_start_matches("http://")
                            .trim_start_matches("https://");
                        let port: u16 = authority
                            .rsplit_once(':')
                            .and_then(|(_, p)| p.parse().ok())
                            .unwrap_or(80);
                        let host = authority
                            .rsplit_once(':')
                            .map(|(h, _)| h)
                            .unwrap_or(authority);
                        msg["DERPMap"] = serde_json::json!({
                            "Regions": {
                                "1": {
                                    "RegionID": 1,
                                    "RegionCode": "tst",
                                    "RegionName": "Test",
                                    "Nodes": [{
                                        "Name": "1a",
                                        "RegionID": 1,
                                        "HostName": host,
                                        "IPv4": host,
                                        "DERPPort": port,
                                        "InsecureForTests": true,
                                    }],
                                }
                            }
                        });
                    }
                    let msg = serde_json::to_vec(&msg).unwrap();
                    conn.send(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n")
                        .await
                        .unwrap();
                    let mut framed = Vec::with_capacity(4 + msg.len());
                    framed.extend_from_slice(&(msg.len() as u32).to_le_bytes());
                    framed.extend_from_slice(&msg);
                    let mut chunk = format!("{:x}\r\n", framed.len()).into_bytes();
                    chunk.extend_from_slice(&framed);
                    chunk.extend_from_slice(b"\r\n");
                    conn.send(&chunk).await.unwrap();
                    if fx.map_close_after_deliver {
                        // Drop the connection: the poll's read sees EOF,
                        // reconnects per the backoff loop.
                        return;
                    }
                    // Hold the long-poll open.
                    loop {
                        if conn.recv().await.is_err() {
                            break;
                        }
                    }
                }
                other => panic!("unexpected control path: {other}"),
            }
    }

    /// A DERP mimic that relays frames between the overlay client and
    /// the peer's UDP socket — the peer's magicsock DERP leg: a real
    /// peer connected to the same relay would receive SendPacket frames
    /// addressed to its node key and reply over the same relay.
    async fn derp_bridge(listener: tokio::net::TcpListener, peer_endpoint: SocketAddr) {
        use super::derp::{
            box_open, box_seal, read_frame, write_frame, NodePrivateKey as _NodePriv,
            FRAME_CLIENT_INFO, FRAME_RECV_PACKET,
            FRAME_SEND_PACKET, FRAME_SERVER_INFO, FRAME_SERVER_KEY, KEY_LEN, MAGIC,
        };
        let (mut sock, _) = listener.accept().await.expect("derp accept");
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        loop {
            sock.read_exact(&mut b).await.unwrap();
            head.push(b[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        assert!(head.starts_with(b"GET /derp HTTP/1.1"));
        sock.write_all(
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n",
        )
        .await
        .unwrap();

        let server_key = _NodePriv::generate();
        let mut greeting = MAGIC.to_vec();
        greeting.extend_from_slice(server_key.public().as_bytes());
        write_frame(&mut sock, FRAME_SERVER_KEY, &greeting).await.unwrap();
        let (t, payload) = read_frame(&mut sock).await.unwrap();
        assert_eq!(t, FRAME_CLIENT_INFO);
        let mut peer = [0u8; 32];
        peer.copy_from_slice(&payload[..KEY_LEN]);
        let boxed = box_seal(server_key.secret(), &peer, br#"{"version":2}"#).unwrap();
        write_frame(&mut sock, FRAME_SERVER_INFO, &boxed).await.unwrap();
        let _ = box_open(server_key.secret(), &peer, &payload[KEY_LEN..]).unwrap();

        // The bridge socket the peer's replies come back on.
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp.connect(peer_endpoint).await.unwrap();
        let mut buf = vec![0u8; 65_536];
        loop {
            tokio::select! {
                frame = read_frame(&mut sock) => {
                    match frame {
                        // FRAME_SEND_PACKET: dst key (32) + packet.
                        Ok((t, payload)) if t == FRAME_SEND_PACKET => {
                            let _ = udp.send(&payload[KEY_LEN..]).await;
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
                r = udp.recv(&mut buf) => {
                    match r {
                        Ok(n) => {
                            let mut out = Vec::with_capacity(KEY_LEN + n);
                            out.extend_from_slice(&peer);
                            out.extend_from_slice(&buf[..n]);
                            if write_frame(&mut sock, FRAME_RECV_PACKET, &out)
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    }

    /// What one in-test disco peer front observed.
    #[derive(Default)]
    struct DiscoFrontCounters {
        /// Disco pings answered with a Pong.
        pings: std::sync::atomic::AtomicUsize,
        /// WireGuard datagrams relayed toward the peer's WG endpoint
        /// (the direct path carrying data).
        wg_relays: std::sync::atomic::AtomicUsize,
    }

    /// An in-test disco-capable peer front: one UDP socket speaking
    /// BOTH protocols the way a real tailscale peer's magicsock does —
    /// disco Pings are answered with Pongs (sealed under the peer's
    /// disco key, handlePingLocked's reply), and WireGuard datagrams
    /// are relayed to/from the engine's WG endpoint (magicsock's
    /// socket feeding wireguard-go). `our_disco_pub` is the CLIENT's
    /// disco public, captured from its MapRequest.DiscoKey by the
    /// control mimic. Returns the front's socket address.
    async fn disco_peer_front(
        wg_addr: SocketAddr,
        disco: super::disco::DiscoPrivateKey,
        our_disco_pub: Arc<Mutex<Option<[u8; 32]>>>,
        counters: Arc<DiscoFrontCounters>,
    ) -> SocketAddr {
        let sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let addr = sock.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65_536];
            // The most recent direct sender (where WG responses go).
            let mut last_client: Option<SocketAddr> = None;
            loop {
                let (n, from) = match sock.recv_from(&mut buf).await {
                    Ok(v) => v,
                    Err(_) => break,
                };
                let pkt = &buf[..n];
                if from == wg_addr {
                    // A WG response from the peer's endpoint: relay it
                    // to the last direct sender.
                    if let Some(client) = last_client {
                        let _ = sock.send_to(pkt, client).await;
                    }
                    continue;
                }
                if super::disco::looks_like_disco(pkt) {
                    let captured = *our_disco_pub.lock().unwrap_or_else(|e| e.into_inner());
                    let Some(our_pub) = captured else {
                        continue;
                    };
                    let Ok((_sender, msg)) =
                        super::disco::open(&disco, pkt)
                    else {
                        continue;
                    };
                    if let super::disco::DiscoMessage::Ping(ping) = msg {
                        let pong = super::disco::Pong {
                            txid: ping.txid,
                            src: from,
                        };
                        if let Ok(reply) = super::disco::seal(
                            &disco,
                            &super::disco::DiscoPublicKey::from_bytes(our_pub),
                            &super::disco::DiscoMessage::Pong(pong),
                        ) {
                            let _ = sock.send_to(&reply, from).await;
                            counters
                                .pings
                                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        }
                    }
                    continue;
                }
                // WireGuard from the client: relay to the peer's WG
                // endpoint (and remember the direct sender).
                last_client = Some(from);
                counters
                    .wg_relays
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                let _ = sock.send_to(pkt, wg_addr).await;
            }
        });
        addr
    }

    /// [`derp_bridge`] counting the WireGuard frames it relays toward
    /// the peer (the client's DERP-carried WG traffic).
    async fn derp_bridge_counting(
        listener: tokio::net::TcpListener,
        peer_endpoint: SocketAddr,
        wg_via_derp: Arc<std::sync::atomic::AtomicUsize>,
    ) {
        use super::derp::{
            box_open, box_seal, read_frame, write_frame, NodePrivateKey as _NodePriv,
            FRAME_CLIENT_INFO, FRAME_RECV_PACKET, FRAME_SEND_PACKET, FRAME_SERVER_INFO,
            FRAME_SERVER_KEY, KEY_LEN, MAGIC,
        };
        let (mut sock, _) = listener.accept().await.expect("derp accept");
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        loop {
            sock.read_exact(&mut b).await.unwrap();
            head.push(b[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        assert!(head.starts_with(b"GET /derp HTTP/1.1"));
        sock.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n")
            .await
            .unwrap();

        let server_key = _NodePriv::generate();
        let mut greeting = MAGIC.to_vec();
        greeting.extend_from_slice(server_key.public().as_bytes());
        write_frame(&mut sock, FRAME_SERVER_KEY, &greeting).await.unwrap();
        let (t, payload) = read_frame(&mut sock).await.unwrap();
        assert_eq!(t, FRAME_CLIENT_INFO);
        let mut peer = [0u8; 32];
        peer.copy_from_slice(&payload[..KEY_LEN]);
        let boxed = box_seal(server_key.secret(), &peer, br#"{"version":2}"#).unwrap();
        write_frame(&mut sock, FRAME_SERVER_INFO, &boxed).await.unwrap();
        let _ = box_open(server_key.secret(), &peer, &payload[KEY_LEN..]).unwrap();

        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp.connect(peer_endpoint).await.unwrap();
        let mut buf = vec![0u8; 65_536];
        loop {
            tokio::select! {
                frame = read_frame(&mut sock) => {
                    match frame {
                        // FRAME_SEND_PACKET: dst key (32) + packet.
                        Ok((t, payload)) if t == FRAME_SEND_PACKET => {
                            let data = &payload[KEY_LEN..];
                            if !super::disco::looks_like_disco(data) {
                                wg_via_derp.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                            }
                            let _ = udp.send(data).await;
                        }
                        Ok(_) => {}
                        Err(_) => break,
                    }
                }
                r = udp.recv(&mut buf) => {
                    match r {
                        Ok(n) => {
                            let mut out = Vec::with_capacity(KEY_LEN + n);
                            out.extend_from_slice(&peer);
                            out.extend_from_slice(&buf[..n]);
                            if write_frame(&mut sock, FRAME_RECV_PACKET, &out)
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
    }

    /// The CallMeMaybe DERP leg: a one-connection DERP mimic that NEVER
    /// relays WireGuard frames (the peer's WG leg is the direct front),
    /// and answers the client's first WG SendPacket with a
    /// CallMeMaybe carrying `my_number` — "the peer has already sent to
    /// us via UDP, so their stateful firewall should be open"
    /// (disco.go:191-199). Proves the direct path opens through
    /// disco rather than the relay.
    async fn derp_call_me_maybe(
        listener: tokio::net::TcpListener,
        peer_disco: super::disco::DiscoPrivateKey,
        our_disco_pub: Arc<Mutex<Option<[u8; 32]>>>,
        our_node_pub: [u8; 32],
        my_number: SocketAddr,
    ) {
        use super::derp::{
            box_open, box_seal, read_frame, write_frame, NodePrivateKey as _NodePriv,
            FRAME_CLIENT_INFO, FRAME_RECV_PACKET, FRAME_SEND_PACKET, FRAME_SERVER_INFO,
            FRAME_SERVER_KEY, KEY_LEN, MAGIC,
        };
        let (mut sock, _) = listener.accept().await.expect("derp accept");
        let mut head = Vec::new();
        let mut b = [0u8; 1];
        loop {
            sock.read_exact(&mut b).await.unwrap();
            head.push(b[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        assert!(head.starts_with(b"GET /derp HTTP/1.1"));
        sock.write_all(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n")
            .await
            .unwrap();
        let server_key = _NodePriv::generate();
        let mut greeting = MAGIC.to_vec();
        greeting.extend_from_slice(server_key.public().as_bytes());
        write_frame(&mut sock, FRAME_SERVER_KEY, &greeting).await.unwrap();
        let (t, payload) = read_frame(&mut sock).await.unwrap();
        assert_eq!(t, FRAME_CLIENT_INFO);
        let mut client = [0u8; 32];
        client.copy_from_slice(&payload[..KEY_LEN]);
        assert_eq!(client, our_node_pub, "the DERP registration is our node key");
        let boxed = box_seal(server_key.secret(), &client, br#"{"version":2}"#).unwrap();
        write_frame(&mut sock, FRAME_SERVER_INFO, &boxed).await.unwrap();
        let _ = box_open(server_key.secret(), &client, &payload[KEY_LEN..]).unwrap();

        loop {
            match read_frame(&mut sock).await {
                Ok((t, payload)) if t == FRAME_SEND_PACKET => {
                    let data = &payload[KEY_LEN..];
                    if super::disco::looks_like_disco(data) || data.first() == Some(&4) {
                        // The client's disco ping or WG initiation via
                        // DERP: dropped — the CallMeMaybe path is the
                        // ONLY way this peer comes up. (A real peer
                        // would bridge; this mimic isolates the
                        // mechanism under test.)
                    } else if data.first() == Some(&1) {
                        // The first WG initiation triggers the
                        // CallMeMaybe (upstream: a peer receiving
                        // DERP-relayed traffic answers with one when it
                        // wants the direct path, endpoint.go:2138+).
                        let our_pub = (*our_disco_pub
                            .lock()
                            .unwrap_or_else(|e| e.into_inner()))
                        .expect("the client's disco key was captured");
                        let cmm = super::disco::CallMeMaybe {
                            my_number: vec![my_number],
                        };
                        let pkt = super::disco::seal(
                            &peer_disco,
                            &super::disco::DiscoPublicKey::from_bytes(our_pub),
                            &super::disco::DiscoMessage::CallMeMaybe(cmm),
                        )
                        .unwrap();
                        // RECV_PACKET: source key + payload (the frame
                        // the client's DerpClient yields as
                        // ReceivedPacket).
                        let mut frame = Vec::with_capacity(KEY_LEN + pkt.len());
                        frame.extend_from_slice(&our_node_pub);
                        frame.extend_from_slice(&pkt);
                        write_frame(&mut sock, FRAME_RECV_PACKET, &frame)
                            .await
                            .unwrap();
                    }
                }
                Ok(_) => {}
                Err(_) => break,
            }
        }
    }


    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    /// The peer: the engine's own WireGuard endpoint (the production
    /// responder + netstack + relay), returning (wg_addr, peer static
    /// public key hex) and allowing our node key + tailnet IP.
    async fn spawn_peer_wg_endpoint(our_node_pub: [u8; 32]) -> (SocketAddr, String) {
        spawn_peer_wg_endpoint_at(our_node_pub, "100.64.0.2").await
    }

    /// [`spawn_peer_wg_endpoint`] at a chosen inner address (an exit
    /// node peer owns a different tailnet IP than the plain peer).
    async fn spawn_peer_wg_endpoint_at(
        our_node_pub: [u8; 32],
        addr: &str,
    ) -> (SocketAddr, String) {
        // SECURITY: the peer's static key is generated in-test.
        let peer_static = NodePrivateKey::generate();
        let cfg = crate::proto::wireguard::WgEndpointCfg {
            tag: "ts-peer".into(),
            private_key: b64(peer_static.secret()),
            listen_port: 0,
            mtu: 0,
            // /24 like the wireguard endpoint tests' SERVER_TUNNEL_IP
            // (a /32 on the server stack's own address breaks nothing in
            // theory; the tests keep the tested shape).
            address: Some((addr.parse().unwrap(), 24)),
            inet6_address: None,
            udp_timeout: None,
            peers: vec![crate::proto::wireguard::WgEndpointPeer {
                public_key: b64(&our_node_pub),
                pre_shared_key: None,
                allowed_ips: vec![("100.64.0.1".parse::<std::net::IpAddr>().unwrap(), 32)],
                persistent_keepalive: None,
            }],
        };
        let sa = crate::proto::wireguard::serve_endpoint(&cfg, Arc::new(EchoRelay))
            .await
            .unwrap();
        // The endpoint binds [::] dual-stack and reports the v6 wildcard;
        // address it over v4 loopback (the wireguard.rs tests' v4_ep
        // rewrites the same way).
        let addr = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            sa.port(),
        );
        let hexs: String = peer_static
            .public()
            .as_bytes()
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();
        (addr, hexs)
    }

    #[tokio::test]
    async fn login_netmap_and_direct_data_plane_through_existing_wg_client() {
        // SECURITY: all key material generated in-test. The identity is
        // PERSISTED in a state dir and reloaded by start_overlay — the
        // real restart flow — so the endpoint can allow the exact node
        // key the overlay will present.
        let dir = tempfile::tempdir().unwrap();
        let identity = NodeIdentity::load_or_generate(Some(dir.path()), false).unwrap();
        let our_node_pub = *identity.node_key.public().as_bytes();
        let (wg_addr, peer_key_hex) = spawn_peer_wg_endpoint(our_node_pub).await;
        let auth_key = generated_auth_key();

        let control_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_addr = control_listener.local_addr().unwrap();
        tokio::spawn(control_server(
            control_listener,
            ControlFixture::new(
                MachinePrivateKey::generate(),
                peer_key_hex.clone(),
                Some(wg_addr),
                None,
                auth_key.clone(),
            ),
        ));

        let cfg = TailscaleConfig {
            auth_key: Some(auth_key),
            control_url: Some(format!("http://{control_addr}")),
            state_dir: Some(dir.path().to_string_lossy().into_owned()),
            ephemeral: false,
            ..TailscaleConfig::new("ts-e2e")
        };
        let overlay = start_overlay(&cfg).await.unwrap_or_else(|e| panic!("login + netmap: {e}"));

        // The netmap: self address + one peer with the endpoint's real
        // UDP address.
        let nm = overlay.netmap().unwrap();
        assert_eq!(
            overlay.tailscale_ips(),
            vec![std::net::IpAddr::V4("100.64.0.1".parse().unwrap())]
        );
        assert_eq!(nm.peers.len(), 1);
        assert_eq!(nm.peers[0].endpoints[0].0, wg_addr);

        // Direct path via the EXISTING wireguard client machinery,
        // configured purely from the netmap: a TCP echo through the
        // endpoint's relay proves login -> netmap -> WireGuard ->
        // netstack -> engine relay end to end. (Payload kept within one
        // segment: multi-segment bursts over this path have a
        // scheduling-dependent stall inside proto/wireguard.rs's stack —
        // pre-existing, out of this wave's files — so the full-size
        // echo proof rides the tailscale-owned session below.)
        let mut stream = overlay
            .dial_direct("100.64.0.2:8080".parse().unwrap())
            .await
            .unwrap_or_else(|e| panic!("direct dial: {e}"));
        let payload: Vec<u8> = (0..1024u32).map(|i| (i % 251) as u8).collect();
        stream.write_all(&payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        let mut off = 0;
        while off < payload.len() {
            let n = tokio::time::timeout(
                std::time::Duration::from_secs(10),
                stream.read(&mut got[off..]),
            )
            .await
            .unwrap_or_else(|_| panic!("direct echo stalled at {off}/{}", payload.len()))
            .unwrap();
            assert!(n > 0, "eof at {off}/{}", payload.len());
            off += n;
        }
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn login_netmap_and_derp_relayed_data_plane() {
        let dir = tempfile::tempdir().unwrap();
        let identity = NodeIdentity::load_or_generate(Some(dir.path()), false).unwrap();
        let our_node_pub = *identity.node_key.public().as_bytes();
        let (wg_addr, peer_key_hex) = spawn_peer_wg_endpoint(our_node_pub).await;

        let derp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let derp_addr = derp_listener.local_addr().unwrap();
        tokio::spawn(derp_bridge(derp_listener, wg_addr));

        let control_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_addr = control_listener.local_addr().unwrap();
        let auth_key = generated_auth_key();
        tokio::spawn(control_server(
            control_listener,
            ControlFixture::new(
                MachinePrivateKey::generate(),
                peer_key_hex,
                // NO endpoints: the peer is only reachable through its
                // home DERP relay.
                None,
                Some(format!("http://{derp_addr}")),
                auth_key.clone(),
            ),
        ));

        let cfg = TailscaleConfig {
            auth_key: Some(auth_key),
            control_url: Some(format!("http://{control_addr}")),
            state_dir: Some(dir.path().to_string_lossy().into_owned()),
            ephemeral: false,
            ..TailscaleConfig::new("ts-derp")
        };
        let overlay = start_overlay(&cfg).await.unwrap_or_else(|e| panic!("login + netmap: {e}"));
        let nm = overlay.netmap().unwrap();
        assert!(nm.peers[0].endpoints.is_empty(), "peer is DERP-only");
        assert_eq!(nm.peers[0].home_derp, 1);
        assert_eq!(
            nm.derp_map.region_url(1).as_deref(),
            Some(format!("http://{derp_addr}").as_str())
        );

        // The relay path: the handshake AND transport packets flow
        // through the DERP client to the peer's home relay.
        let mut stream = overlay
            .dial_relay("100.64.0.2:8081".parse().unwrap())
            .await
            .unwrap_or_else(|e| panic!("derp-relayed dial: {e}"));
        let payload: Vec<u8> = (0..8192u32).map(|i| (i % 241) as u8).collect();
        stream.write_all(&payload).await.unwrap();
        let mut got = vec![0u8; 512];
        let n = stream.read(&mut got).await.unwrap();
        assert_eq!(&got[..n], &payload[..n]);
        // Read the rest to prove the full echo.
        let mut rest = vec![0u8; payload.len() - n];
        stream.read_exact(&mut rest).await.unwrap();
        assert_eq!(rest, payload[n..]);
    }

    // -------------------------------------------------------------------
    // Wave 13: the disco overlay (ping/pong path confirmation,
    // call-me-maybe) and the key-expiry renewal.
    // -------------------------------------------------------------------

    fn hex32(bytes: &[u8; 32]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    #[tokio::test]
    async fn disco_pong_confirms_the_direct_path() {
        // A disco-capable peer (front answering pings with pongs, WG
        // relayed to the engine's endpoint) with a home DERP. The Pong
        // for our Ping confirms the direct address; the established
        // session then carries data direct-only — a peer that never
        // ponged would stay on DERP (next test).
        let dir = tempfile::tempdir().unwrap();
        let identity = NodeIdentity::load_or_generate(Some(dir.path()), false).unwrap();
        let our_node_pub = *identity.node_key.public().as_bytes();
        let (wg_addr, peer_key_hex) = spawn_peer_wg_endpoint(our_node_pub).await;

        let peer_disco = super::disco::DiscoPrivateKey::generate();
        let our_disco = Arc::new(Mutex::new(None::<[u8; 32]>));
        let counters = Arc::new(DiscoFrontCounters::default());
        let front = disco_peer_front(
            wg_addr,
            peer_disco.clone(),
            our_disco.clone(),
            counters.clone(),
        )
        .await;

        let derp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let derp_addr = derp_listener.local_addr().unwrap();
        let wg_via_derp = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        tokio::spawn(derp_bridge_counting(
            derp_listener,
            wg_addr,
            wg_via_derp.clone(),
        ));

        let control_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_addr = control_listener.local_addr().unwrap();
        let auth_key = generated_auth_key();
        let mut fx = ControlFixture::new(
            MachinePrivateKey::generate(),
            peer_key_hex,
            Some(front),
            Some(format!("http://{derp_addr}")),
            auth_key.clone(),
        );
        fx.peer_disco_hex = Some(hex32(peer_disco.public().as_bytes()));
        fx.disco_capture = Some(our_disco.clone());
        tokio::spawn(control_server(control_listener, fx));

        let cfg = TailscaleConfig {
            auth_key: Some(auth_key),
            control_url: Some(format!("http://{control_addr}")),
            state_dir: Some(dir.path().to_string_lossy().into_owned()),
            ..TailscaleConfig::new("ts-disco")
        };
        let overlay = Arc::new(start_overlay(&cfg).await.unwrap());
        // The map carried the peer's disco key — the tunnel speaks disco.
        assert!(overlay.netmap().unwrap().peers[0].disco_key.is_some());

        // Echo through the tailscale-side session.
        let mut stream = overlay
            .dial_relay("100.64.0.2:8082".parse().unwrap())
            .await
            .unwrap_or_else(|e| panic!("disco dial: {e}"));
        stream.write_all(b"disco-probe").await.unwrap();
        let mut got = [0u8; 11];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"disco-probe");

        // The front answered at least one Ping with a Pong and relayed
        // WireGuard datagrams: the direct path exists AND carried data.
        assert!(
            counters.pings.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "the peer ponged our ping"
        );
        assert!(
            counters.wg_relays.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "the direct path carried WireGuard"
        );

        // Disco-informed carrier selection: once pong-confirmed (the
        // 6.5s trustUDPAddrDuration window), an established session
        // sends direct-only — a second echo round must not grow the
        // DERP relay's WG counter at all.
        let via_derp_before = wg_via_derp.load(std::sync::atomic::Ordering::SeqCst);
        stream.write_all(b"second-round").await.unwrap();
        let mut got2 = [0u8; 12];
        stream.read_exact(&mut got2).await.unwrap();
        assert_eq!(&got2, b"second-round");
        assert_eq!(
            wg_via_derp.load(std::sync::atomic::Ordering::SeqCst),
            via_derp_before,
            "the pong-confirmed direct path carries the session exclusively"
        );
    }

    #[tokio::test]
    async fn disco_ignored_falls_back_to_derp() {
        // The peer advertises a disco key and an endpoint that DROPS
        // everything (the pings go unanswered): no Pong ever confirms a
        // direct path, so the session falls back to — and stays on —
        // the DERP relay. The wave-11 behavior, preserved exactly.
        let dir = tempfile::tempdir().unwrap();
        let identity = NodeIdentity::load_or_generate(Some(dir.path()), false).unwrap();
        let our_node_pub = *identity.node_key.public().as_bytes();
        let (wg_addr, peer_key_hex) = spawn_peer_wg_endpoint(our_node_pub).await;

        // The dead direct path: binds, counts, drops.
        let dead = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dead_addr = dead.local_addr().unwrap();
        let dropped = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        {
            let dropped = dropped.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65_536];
                while dead.recv_from(&mut buf).await.is_ok() {
                    dropped.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            });
        }

        let derp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let derp_addr = derp_listener.local_addr().unwrap();
        let wg_via_derp = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        tokio::spawn(derp_bridge_counting(
            derp_listener,
            wg_addr,
            wg_via_derp.clone(),
        ));

        let control_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_addr = control_listener.local_addr().unwrap();
        let auth_key = generated_auth_key();
        let mut fx = ControlFixture::new(
            MachinePrivateKey::generate(),
            peer_key_hex,
            Some(dead_addr),
            Some(format!("http://{derp_addr}")),
            auth_key.clone(),
        );
        let peer_disco = super::disco::DiscoPrivateKey::generate();
        fx.peer_disco_hex = Some(hex32(peer_disco.public().as_bytes()));
        fx.disco_capture = Some(Arc::new(Mutex::new(None::<[u8; 32]>)));
        tokio::spawn(control_server(control_listener, fx));

        let cfg = TailscaleConfig {
            auth_key: Some(auth_key),
            control_url: Some(format!("http://{control_addr}")),
            state_dir: Some(dir.path().to_string_lossy().into_owned()),
            ..TailscaleConfig::new("ts-disco-dead")
        };
        let overlay = Arc::new(start_overlay(&cfg).await.unwrap());
        assert!(overlay.netmap().unwrap().peers[0].disco_key.is_some());

        // The echo still works — over DERP.
        let mut stream = overlay
            .dial_relay("100.64.0.2:8083".parse().unwrap())
            .await
            .unwrap_or_else(|e| panic!("derp-fallback dial: {e}"));
        stream.write_all(b"via-derp").await.unwrap();
        let mut got = [0u8; 8];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"via-derp");

        // The pings WERE sent (the dead endpoint saw them) and ignored;
        // the WG session rode the relay.
        assert!(
            dropped.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "the disco pings were sent to the advertised endpoint"
        );
        assert!(
            wg_via_derp.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "the never-ponged peer fell back to DERP"
        );
    }

    #[tokio::test]
    async fn call_me_maybe_opens_the_direct_path() {
        // A DERP-ONLY peer (no advertised endpoints) whose relay answers
        // our first WG frame with a CallMeMaybe instead of relaying it:
        // the only way the session can come up is the direct path the
        // CallMeMaybe requested — we ping the advertised number, the
        // Pong confirms it, and the handshake + data flow direct.
        let dir = tempfile::tempdir().unwrap();
        let identity = NodeIdentity::load_or_generate(Some(dir.path()), false).unwrap();
        let our_node_pub = *identity.node_key.public().as_bytes();
        let (wg_addr, peer_key_hex) = spawn_peer_wg_endpoint(our_node_pub).await;

        let peer_disco = super::disco::DiscoPrivateKey::generate();
        let our_disco = Arc::new(Mutex::new(None::<[u8; 32]>));
        let counters = Arc::new(DiscoFrontCounters::default());
        let front = disco_peer_front(
            wg_addr,
            peer_disco.clone(),
            our_disco.clone(),
            counters.clone(),
        )
        .await;

        let derp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let derp_addr = derp_listener.local_addr().unwrap();
        tokio::spawn(derp_call_me_maybe(
            derp_listener,
            peer_disco.clone(),
            our_disco.clone(),
            our_node_pub,
            front,
        ));

        let control_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_addr = control_listener.local_addr().unwrap();
        let auth_key = generated_auth_key();
        let mut fx = ControlFixture::new(
            MachinePrivateKey::generate(),
            peer_key_hex,
            // NO endpoints: the peer is only reachable through its home
            // DERP relay — and the direct path the CallMeMaybe opens.
            None,
            Some(format!("http://{derp_addr}")),
            auth_key.clone(),
        );
        fx.peer_disco_hex = Some(hex32(peer_disco.public().as_bytes()));
        fx.disco_capture = Some(our_disco.clone());
        tokio::spawn(control_server(control_listener, fx));

        let cfg = TailscaleConfig {
            auth_key: Some(auth_key),
            control_url: Some(format!("http://{control_addr}")),
            state_dir: Some(dir.path().to_string_lossy().into_owned()),
            ..TailscaleConfig::new("ts-cmm")
        };
        let overlay = Arc::new(start_overlay(&cfg).await.unwrap());
        assert!(overlay.netmap().unwrap().peers[0].endpoints.is_empty());

        // The echo comes up through the direct path the CallMeMaybe
        // opened (the relay refused to carry WG at all).
        let mut stream = overlay
            .dial_relay("100.64.0.2:8084".parse().unwrap())
            .await
            .unwrap_or_else(|e| panic!("call-me-maybe dial: {e}"));
        stream.write_all(b"cmm-probe").await.unwrap();
        let mut got = [0u8; 9];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"cmm-probe");

        // We pinged the advertised number and the WG datagrams flowed
        // through the front — the direct path, opened by disco.
        assert!(
            counters.pings.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "the CallMeMaybe numbers were pinged"
        );
        assert!(
            counters.wg_relays.load(std::sync::atomic::Ordering::SeqCst) >= 1,
            "the WireGuard session came up over the direct path"
        );
    }

    #[tokio::test]
    async fn expired_node_key_rotates_via_old_node_key_and_dials_keep_working() {
        // Round 1's netmap carries a past-dated self KeyExpiry: the
        // poll detects it (ipnlocal.go:1906), interrupts the stream,
        // and re-registers with a FRESH node key under
        // RegisterRequest{NodeKey: fresh, OldNodeKey: current}
        // (direct.go:697-713). The mimic asserts the OldNodeKey flow;
        // the next netmap carries the new self key; and a dial under
        // the rotated identity re-keys (a peer allowing the NEW key
        // takes over the map entry).
        let dir = tempfile::tempdir().unwrap();
        let identity = NodeIdentity::load_or_generate(Some(dir.path()), false).unwrap();
        let initial_pub = *identity.node_key.public().as_bytes();
        let (wg_addr, peer_key_hex) = spawn_peer_wg_endpoint(initial_pub).await;

        let capture = Arc::new(RegisterCapture::default());
        // The post-rotation peer, swapped into the map by the test once
        // the rotated key is known: (endpoint, peer node key hex).
        let peer2: Arc<Mutex<Option<(SocketAddr, String)>>> = Arc::new(Mutex::new(None));
        let tweak_peer2 = peer2.clone();
        let tweak = std::sync::Arc::new(move |round: usize, msg: &mut serde_json::Value| {
            if round == 1 {
                // ipnlocal's expiry check reads exactly this field.
                msg["Node"]["KeyExpiry"] = serde_json::json!("2020-01-01T00:00:00Z");
            } else {
                // Post-rotation rounds carry no expiry; and the swapped
                // peer (allowing the rotated key) once the test sets it.
                if let Some((ep, hex)) =
                    (*tweak_peer2.lock().unwrap_or_else(|e| e.into_inner())).clone()
                {
                    msg["Peers"][0]["Key"] = serde_json::json!(format!("nodekey:{hex}"));
                    msg["Peers"][0]["Endpoints"] = serde_json::json!([ep.to_string()]);
                }
            }
        });
        let control_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_addr = control_listener.local_addr().unwrap();
        let auth_key = generated_auth_key();
        let mut fx = ControlFixture::new(
            MachinePrivateKey::generate(),
            peer_key_hex,
            Some(wg_addr),
            None,
            auth_key.clone(),
        );
        fx.map_close_after_deliver = true;
        fx.map_tweak = Some(tweak);
        fx.register_capture = Some(capture.clone());
        tokio::spawn(control_server(control_listener, fx));

        let cfg = TailscaleConfig {
            auth_key: Some(auth_key),
            control_url: Some(format!("http://{control_addr}")),
            state_dir: Some(dir.path().to_string_lossy().into_owned()),
            ..TailscaleConfig::new("ts-renew")
        };
        let overlay = Arc::new(start_overlay_with(
            &cfg,
            PollRetry {
                initial: std::time::Duration::from_millis(20),
                max: std::time::Duration::from_millis(50),
                max_attempts: 500,
            },
        )
        .await
        .unwrap());

        // The rotation lands: our node public changes...
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while overlay.node_public() == initial_pub {
            assert!(
                std::time::Instant::now() < deadline,
                "the expired key was never renewed: {:?}",
                overlay.renewal_error()
            );
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }
        let rotated_pub = overlay.node_public();
        assert_ne!(rotated_pub, initial_pub);
        assert!(overlay.renewal_error().is_none());

        // ...the mimic saw the OldNodeKey register round exactly
        // (direct.go:761: OldNodeKey = the current key, NodeKey = fresh).
        let renewal = *capture
            .renewal
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        assert_eq!(renewal, Some((initial_pub, rotated_pub)), "the OldNodeKey flow");

        // ...and the next netmap carries the rotated self key with the
        // expiry gone.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let nm = overlay.netmap().unwrap();
            if *nm.self_node.key.as_bytes() == rotated_pub {
                assert!(
                    nm.self_node.key_expiry.is_none(),
                    "the renewed map carries no expiry"
                );
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the renewed netmap never landed: self={}",
                hex32(nm.self_node.key.as_bytes())
            );
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }

        // Dials keep working under the rotated identity: the WG
        // sessions re-key on next use — a peer allowing the NEW node
        // key takes over the map entry, and the tunnel cache was
        // cleared so the dial spawns a fresh session.
        let (wg2, peer2_hex) = spawn_peer_wg_endpoint(rotated_pub).await;
        *peer2.lock().unwrap_or_else(|e| e.into_inner()) = Some((wg2, peer2_hex.clone()));
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let nm = overlay.netmap().unwrap();
            let got_hex = hex32(nm.peers[0].key.as_bytes());
            if got_hex == peer2_hex {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "the rotated peer never landed in the map: {got_hex}"
            );
            tokio::time::sleep(std::time::Duration::from_millis(25)).await;
        }

        let mut stream = overlay
            .dial_relay("100.64.0.2:8085".parse().unwrap())
            .await
            .unwrap_or_else(|e| panic!("post-rotation dial: {e}"));
        stream.write_all(b"after-rotation").await.unwrap();
        let mut got = [0u8; 14];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"after-rotation");
    }

    #[tokio::test]
    async fn connect_reaches_logged_in_netmap_peer_and_stops_at_the_gap_error() {
        // connect() drives the whole control path against the mimic and
        // then stops with the precise remaining-gap error.
        let dir = tempfile::tempdir().unwrap();
        let identity = NodeIdentity::load_or_generate(Some(dir.path()), false).unwrap();
        let our_node_pub = *identity.node_key.public().as_bytes();
        let (wg_addr, peer_key_hex) = spawn_peer_wg_endpoint(our_node_pub).await;
        let control_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_addr = control_listener.local_addr().unwrap();
        let auth_key = generated_auth_key();
        tokio::spawn(control_server(
            control_listener,
            ControlFixture::new(
                MachinePrivateKey::generate(),
                peer_key_hex.clone(),
                Some(wg_addr),
                None,
                auth_key.clone(),
            ),
        ));
        let cfg = TailscaleConfig {
            auth_key: Some(auth_key),
            control_url: Some(format!("http://{control_addr}")),
            state_dir: Some(dir.path().to_string_lossy().into_owned()),
            ephemeral: false,
            ..TailscaleConfig::new("ts-connect")
        };
        let err = connect(&cfg).await.unwrap_err();
        let msg = err.to_string();
        // The filter is now parsed/carried/queryable — named as PORTED
        // in the preamble, not in the "still missing" list.
        assert!(msg.contains("packet filter"), "{msg}");
        assert!(msg.contains("browser"), "{msg}");
        // What landed must not be listed as MISSING anymore (the
        // preamble names them as ported; the "still missing" list
        // must not).
        let missing = msg.split("still missing:").nth(1).unwrap_or_default();
        assert!(!missing.contains("disco"), "{missing}");
        assert!(!missing.contains("key-expiry"), "{missing}");
        assert!(!missing.contains("renewal"), "{missing}");
        assert!(!missing.contains("packet filter"), "{missing}");
        assert!(!missing.contains("MagicDNS"), "{msg}");
        assert!(!missing.contains("reconnect"), "{missing}");
        assert!(!missing.contains("subnet-route"), "{missing}");
        assert!(!missing.contains("UDP"), "{missing}");
        // And it never leaks secrets.
        assert!(!msg.contains("tskey-"), "{msg}");
    }

    /// An in-test control server: `/ts2021` POST + 101 + the
    /// controlbase server half, echoing one record (the wire-exact
    /// behavior of control/controlhttp/controlhttpserver).
    async fn control_echo_mimic(listener: tokio::net::TcpListener, control_key: MachinePrivateKey) {
        use base64::Engine;
        let (socket, _) = listener.accept().await.expect("control mimic accept");
        let (mut r, mut w) = tokio::io::split(socket);
        let mut head = Vec::new();
        loop {
            let mut b = [0u8; 1];
            r.read_exact(&mut b).await.unwrap();
            head.push(b[0]);
            if head.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        let head = String::from_utf8_lossy(&head).into_owned();
        assert!(head.starts_with("POST /ts2021 HTTP/1.1"), "{head}");
        assert!(head.contains("Upgrade: tailscale-control-protocol"));
        let b64 = head
            .lines()
            .find_map(|l| l.strip_prefix("X-Tailscale-Handshake: "))
            .expect("handshake header");
        let init = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap();
        w.write_all(
            b"HTTP/1.1 101 Switching Protocols\r\n\
              Upgrade: tailscale-control-protocol\r\n\
              Connection: upgrade\r\n\r\n",
        )
        .await
        .unwrap();
        w.flush().await.unwrap();
        let socket = r.unsplit(w);
        let mut conn = server_handshake(socket, &control_key, Some(init)).await.unwrap();
        let got = conn.recv().await.unwrap();
        conn.send(&got).await.unwrap();
    }

    #[tokio::test]
    async fn connect_with_bootstrap_reports_control_and_derp_progress() {
        // End-to-end over loopback mimics: the /ts2021 upgrade, the
        // Noise IK handshake, one encrypted record echo, and a full
        // DERP registration — the progress ledger the ipn layer will
        // sit on top of. All keys generated in-test.
        let control_key = MachinePrivateKey::generate();
        let control_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_addr = control_listener.local_addr().unwrap();
        {
            let key = control_key.clone();
            tokio::spawn(control_echo_mimic(control_listener, key));
        }

        // A one-peer DERP mimic: upgrade + greeting + ClientInfo +
        // ServerInfo (see the derp module tests for the relay path).
        let derp_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let derp_addr = derp_listener.local_addr().unwrap();
        tokio::spawn(async move {
            use super::derp::{
                box_open, box_seal, read_frame, write_frame, NodePrivateKey, FRAME_CLIENT_INFO,
                FRAME_SERVER_INFO, FRAME_SERVER_KEY, MAGIC,
            };
            let (mut sock, _) = derp_listener.accept().await.expect("derp mimic accept");
            let mut head = Vec::new();
            loop {
                let mut b = [0u8; 1];
                sock.read_exact(&mut b).await.unwrap();
                head.push(b[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&head).into_owned();
            assert!(head.starts_with("GET /derp HTTP/1.1"), "{head}");
            assert!(head.contains("Upgrade: DERP"));
            sock.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: DERP\r\nConnection: Upgrade\r\n\r\n",
            )
            .await
            .unwrap();
            let server_key = NodePrivateKey::generate();
            let mut greeting = MAGIC.to_vec();
            greeting.extend_from_slice(server_key.public().as_bytes());
            write_frame(&mut sock, FRAME_SERVER_KEY, &greeting).await.unwrap();
            let (t, payload) = read_frame(&mut sock).await.unwrap();
            assert_eq!(t, FRAME_CLIENT_INFO);
            let mut peer = [0u8; 32];
            peer.copy_from_slice(&payload[..32]);
            let json = box_open(server_key.secret(), &peer, &payload[32..]).unwrap();
            let needle = br#""version":2"#;
            assert!(
                json.windows(needle.len()).any(|w| w == needle),
                "ClientInfo carries DERP protocol version 2: {}",
                String::from_utf8_lossy(&json)
            );
            let boxed = box_seal(server_key.secret(), &peer, br#"{"version":2}"#).unwrap();
            write_frame(&mut sock, FRAME_SERVER_INFO, &boxed).await.unwrap();
        });

        // SECURITY: machine key generated in-test, never a literal.
        let config = TailscaleConfig::new("ts").with_control_url(format!("http://{control_addr}"));
        let bootstrap = ControlBootstrap {
            machine_key: MachinePrivateKey::generate(),
            control_key: control_key.public(),
            derp_url: Some(format!("http://{derp_addr}")),
        };

        let report = connect_with_bootstrap(&config, &bootstrap).await.expect("wires up");
        assert!(report.control_reachable);
        assert_eq!(report.control_protocol_version, Some(CURRENT_PROTOCOL_VERSION));
        assert!(report.derp_registered);
    }

    #[tokio::test]
    async fn connect_with_bootstrap_requires_a_control_url() {
        let bootstrap = ControlBootstrap {
            machine_key: MachinePrivateKey::generate(),
            control_key: MachinePublicKey::from_bytes([0u8; 32]),
            derp_url: None,
        };
        let err = connect_with_bootstrap(&TailscaleConfig::new("ts"), &bootstrap)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("control-url"));
    }

    #[tokio::test]
    async fn start_overlay_requires_an_auth_key_this_wave() {
        let err = match start_overlay(&TailscaleConfig::new("ts")).await {
            Err(e) => e,
            Ok(_) => panic!("expected the missing auth-key to fail"),
        };
        assert!(err.to_string().contains("auth-key"), "{err}");
    }

    #[test]
    fn poll_retry_delays_double_up_to_the_cap() {
        // auto.go:588: NewBackoff("mapRoutine", ..., 30s) — the delay
        // doubles per consecutive failure and never exceeds the cap.
        let fast = PollRetry {
            initial: std::time::Duration::from_millis(10),
            max: std::time::Duration::from_millis(40),
            max_attempts: 3,
        };
        assert_eq!(fast.delay(0), std::time::Duration::from_millis(10));
        assert_eq!(fast.delay(1), std::time::Duration::from_millis(20));
        assert_eq!(fast.delay(2), std::time::Duration::from_millis(40));
        assert_eq!(fast.delay(9), std::time::Duration::from_millis(40), "capped");
        assert_eq!(POLL_RETRY.delay(0), std::time::Duration::from_millis(100));
        assert_eq!(POLL_RETRY.delay(9), std::time::Duration::from_secs(30));
        // No overflow even at absurd attempt counts.
        assert_eq!(POLL_RETRY.delay(63), std::time::Duration::from_secs(30));
    }

    #[test]
    fn overlay_cache_key_covers_identity_but_not_the_secret() {
        let base = TailscaleConfig::new("ts")
            .with_control_url("http://127.0.0.1:1".into())
            .with_auth_key(Some("tskey-env-sourced".into()));
        let same_but_other_key = TailscaleConfig::new("ts")
            .with_control_url("http://127.0.0.1:1".into())
            .with_auth_key(Some("tskey-env-sourced-2".into()));
        assert_eq!(overlay_cache_key(&base), overlay_cache_key(&same_but_other_key));
        assert!(!overlay_cache_key(&base).contains("tskey-"));
        // Every routing-relevant field changes the key.
        for changed in [
            TailscaleConfig {
                name: "other".into(),
                ..base.clone()
            },
            TailscaleConfig {
                accept_routes: Some(true),
                ..base.clone()
            },
            TailscaleConfig {
                exit_node: Some("auto:any".into()),
                ..base.clone()
            },
            TailscaleConfig {
                exit_node_allow_lan_access: Some(true),
                ..base.clone()
            },
            TailscaleConfig {
                udp: true,
                ..base.clone()
            },
        ] {
            assert_ne!(overlay_cache_key(&base), overlay_cache_key(&changed));
        }
    }

    /// Shared plumbing for the wave-12 e2e tests: a live peer WG
    /// endpoint + a control mimic, returning the config to dial with.
    /// The tempdir is held for the test's lifetime (the overlay reloads
    /// its identity from it on every start).
    struct LiveTailnet {
        cfg: TailscaleConfig,
        _state: tempfile::TempDir,
    }

    async fn live_tailnet(name: &str, udp: bool) -> LiveTailnet {
        let dir = tempfile::tempdir().unwrap();
        let identity = NodeIdentity::load_or_generate(Some(dir.path()), false).unwrap();
        let our_node_pub = *identity.node_key.public().as_bytes();
        let (wg_addr, peer_key_hex) = spawn_peer_wg_endpoint(our_node_pub).await;
        let control_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_addr = control_listener.local_addr().unwrap();
        let auth_key = generated_auth_key();
        tokio::spawn(control_server(
            control_listener,
            ControlFixture::new(
                MachinePrivateKey::generate(),
                peer_key_hex,
                Some(wg_addr),
                None,
                auth_key.clone(),
            ),
        ));
        LiveTailnet {
            cfg: TailscaleConfig {
                auth_key: Some(auth_key),
                control_url: Some(format!("http://{control_addr}")),
                state_dir: Some(dir.path().to_string_lossy().into_owned()),
                udp,
                ..TailscaleConfig::new(name)
            },
            _state: dir,
        }
    }

    #[tokio::test]
    async fn dial_tcp_uses_the_cached_overlay_and_echoes() {
        let lt = live_tailnet("ts-cache", false).await;
        // Two overlay_for calls, one login: Arc identity is the cache's
        // whole point (the openvpn TUNNELS registry shape).
        let a = overlay_for(&lt.cfg).await.unwrap();
        let b = overlay_for(&lt.cfg).await.unwrap();
        assert!(Arc::ptr_eq(&a, &b), "the overlay is reused, not re-registered");
        // A different config identity is a different overlay.
        let mut other = lt.cfg.clone();
        other.name = "ts-cache-2".into();
        let c = overlay_for(&other).await.unwrap();
        assert!(!Arc::ptr_eq(&a, &c));

        // And the cached overlay dials: a TCP echo through the peer.
        let mut stream = dial_tcp(&lt.cfg, &"100.64.0.2:8090".parse().unwrap())
            .await
            .unwrap_or_else(|e| panic!("dial_tcp: {e}"));
        let payload: Vec<u8> = (0..768u32).map(|i| (i % 251) as u8).collect();
        stream.write_all(&payload).await.unwrap();
        let mut got = vec![0u8; payload.len()];
        let mut off = 0;
        while off < payload.len() {
            let n = tokio::time::timeout(std::time::Duration::from_secs(10), stream.read(&mut got[off..]))
                .await
                .unwrap_or_else(|_| panic!("echo stalled at {off}"))
                .unwrap();
            assert!(n > 0);
            off += n;
        }
        assert_eq!(got, payload);
    }

    #[tokio::test]
    async fn dial_tcp_addr_resolves_magicdns_names() {
        let lt = live_tailnet("ts-dns", false).await;
        // The mimic's peer Name is peer.tail-scale.ts.net. — an FQDN and
        // its bare label both resolve, and both dial.
        for name in ["peer.tail-scale.ts.net", "peer"] {
            let target = crate::addr::NetAddr::domain(name, 8091).unwrap();
            let mut stream = dial_tcp_addr(&lt.cfg, &target)
                .await
                .unwrap_or_else(|e| panic!("dial_tcp_addr({name}): {e}"));
            stream.write_all(b"magicdns-probe").await.unwrap();
            let mut got = [0u8; 14];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(&got, b"magicdns-probe");
        }
        // A name outside the tailnet map is not ours to answer.
        let err = match dial_tcp_addr(
            &lt.cfg,
            &crate::addr::NetAddr::domain("public.example.com", 443).unwrap(),
        )
        .await
        {
            Err(e) => e,
            Ok(_) => panic!("a non-tailnet name must not dial"),
        };
        assert!(err.to_string().contains("not a MagicDNS name"), "{err}");
    }

    #[tokio::test]
    async fn udp_through_the_overlay_echoes() {
        let lt = live_tailnet("ts-udp", true).await;
        let overlay = Arc::new(start_overlay(&lt.cfg).await.unwrap());
        let udp = overlay.udp_socket().await.unwrap_or_else(|e| panic!("udp: {e}"));
        let target = crate::addr::NetAddr::ip(
            "100.64.0.2".parse().unwrap(),
            7700,
        );
        let payload: Vec<u8> = (0..512u32).map(|i| (i % 251) as u8).collect();
        udp.send(&target, &payload).await.unwrap();
        let (from, data) = tokio::time::timeout(std::time::Duration::from_secs(10), udp.recv())
            .await
            .expect("udp echo timed out")
            .unwrap();
        assert_eq!(from, target, "the reply carries its source");
        assert_eq!(data, payload);
    }

    #[tokio::test]
    async fn udp_disabled_by_config_is_refused() {
        let lt = live_tailnet("ts-udp-off", false).await;
        let overlay = Arc::new(start_overlay(&lt.cfg).await.unwrap());
        let err = match overlay.udp_socket().await {
            Err(e) => e,
            Ok(_) => panic!("udp must be refused"),
        };
        assert!(err.to_string().contains("udp"), "{err}");
        let err = match dial_udp(&lt.cfg).await {
            Err(e) => e,
            Ok(_) => panic!("dial_udp must be refused"),
        };
        assert!(err.to_string().contains("udp is disabled"), "{err}");
    }

    #[tokio::test]
    async fn map_poll_reconnects_and_delivers_the_next_netmap() {
        // The mimic closes every map stream right after delivering: the
        // poll must reconnect (auto.go's mapRoutine loop) and the SECOND
        // map — which adds a peer — must land in the overlay's netmap.
        let dir = tempfile::tempdir().unwrap();
        let identity = NodeIdentity::load_or_generate(Some(dir.path()), false).unwrap();
        let our_node_pub = *identity.node_key.public().as_bytes();
        let (wg_addr, peer_key_hex) = spawn_peer_wg_endpoint(our_node_pub).await;
        let control_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_addr = control_listener.local_addr().unwrap();
        let auth_key = generated_auth_key();
        // Round >= 2 adds a second, DERP-only peer (its key is generated
        // in-test; it is never dialed, only present in the map).
        let extra_hex: String = {
            let k = NodePrivateKey::generate();
            k.public().as_bytes().iter().map(|b| format!("{b:02x}")).collect()
        };
        let tweak = std::sync::Arc::new(move |round: usize, msg: &mut serde_json::Value| {
            if round >= 2 {
                msg["Peers"]
                    .as_array_mut()
                    .unwrap()
                    .push(serde_json::json!({
                        "ID": 9,
                        "Name": "late.tail-scale.ts.net.",
                        "Key": format!("nodekey:{extra_hex}"),
                        "Addresses": ["100.64.0.9/32"],
                        "AllowedIPs": ["100.64.0.9/32"],
                        "HomeDERP": 1,
                    }));
            }
        });
        let mut fx = ControlFixture::new(
            MachinePrivateKey::generate(),
            peer_key_hex,
            Some(wg_addr),
            None,
            auth_key.clone(),
        );
        fx.map_close_after_deliver = true;
        fx.map_tweak = Some(tweak);
        tokio::spawn(control_server(control_listener, fx));

        let cfg = TailscaleConfig {
            auth_key: Some(auth_key),
            control_url: Some(format!("http://{control_addr}")),
            state_dir: Some(dir.path().to_string_lossy().into_owned()),
            ..TailscaleConfig::new("ts-reconnect")
        };
        let overlay = start_overlay_with(
            &cfg,
            PollRetry {
                initial: std::time::Duration::from_millis(20),
                max: std::time::Duration::from_millis(50),
                max_attempts: 50,
            },
        )
        .await
        .unwrap();
        assert_eq!(overlay.netmap().unwrap().peers.len(), 1);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while overlay.netmap().unwrap().peers.len() < 2 {
            assert!(
                std::time::Instant::now() < deadline,
                "the reconnected poll never delivered the second netmap: {:?}",
                overlay.netmap().map(|nm| nm.peers.len())
            );
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        assert!(overlay.poll_error().is_none(), "still polling");
        assert_eq!(overlay.netmap().unwrap().peers[1].name, "late.tail-scale.ts.net.");
    }

    #[tokio::test]
    async fn map_poll_gives_up_after_capped_retries_and_keeps_the_last_netmap() {
        // Round 1 delivers a netmap then closes; every later map request
        // answers 500. The poll backs off, hits the cap, records why —
        // and the delivered netmap keeps serving routing decisions.
        let dir = tempfile::tempdir().unwrap();
        let identity = NodeIdentity::load_or_generate(Some(dir.path()), false).unwrap();
        let our_node_pub = *identity.node_key.public().as_bytes();
        let (wg_addr, peer_key_hex) = spawn_peer_wg_endpoint(our_node_pub).await;
        let control_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_addr = control_listener.local_addr().unwrap();
        let auth_key = generated_auth_key();
        let mut fx = ControlFixture::new(
            MachinePrivateKey::generate(),
            peer_key_hex,
            Some(wg_addr),
            None,
            auth_key.clone(),
        );
        fx.map_close_after_deliver = true;
        fx.map_fail_from_round = Some(2);
        tokio::spawn(control_server(control_listener, fx));
        let cfg = TailscaleConfig {
            auth_key: Some(auth_key),
            control_url: Some(format!("http://{control_addr}")),
            state_dir: Some(dir.path().to_string_lossy().into_owned()),
            ..TailscaleConfig::new("ts-cap")
        };
        let overlay = start_overlay_with(
            &cfg,
            PollRetry {
                initial: std::time::Duration::from_millis(10),
                max: std::time::Duration::from_millis(20),
                max_attempts: 3,
            },
        )
        .await
        .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while overlay.poll_error().is_none() {
            assert!(
                std::time::Instant::now() < deadline,
                "the poll never gave up (map_fail_from_round not hit)"
            );
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        let err = overlay.poll_error().unwrap();
        assert!(err.contains("gave up"), "{err}");
        // The last netmap stays: the routing decision still answers.
        assert_eq!(overlay.netmap().unwrap().peers.len(), 1);
        let nm = overlay.netmap().unwrap();
        let peer = overlay.routed_peer(&nm, "100.64.0.2".parse().unwrap()).unwrap();
        assert_eq!(peer.name, "peer.tail-scale.ts.net.");
    }

    #[tokio::test]
    async fn exit_node_selection_and_dial() {
        // Two live peers: the fixture's plain peer plus an exit peer
        // (advertises 0.0.0.0/0) added by the map tweak. With
        // exit-node "auto:any", internet destinations route to the exit
        // peer and dials through its tailnet address echo.
        let dir = tempfile::tempdir().unwrap();
        let identity = NodeIdentity::load_or_generate(Some(dir.path()), false).unwrap();
        let our_node_pub = *identity.node_key.public().as_bytes();
        let (plain_addr, plain_hex) = spawn_peer_wg_endpoint(our_node_pub).await;
        let (exit_addr, exit_hex) = spawn_peer_wg_endpoint_at(our_node_pub, "100.64.0.3").await;
        let control_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let control_addr = control_listener.local_addr().unwrap();
        let auth_key = generated_auth_key();
        let tweak = std::sync::Arc::new(move |_round: usize, msg: &mut serde_json::Value| {
            msg["Peers"].as_array_mut().unwrap().push(serde_json::json!({
                "ID": 3,
                "Name": "exit.tail-scale.ts.net.",
                "User": 10,
                "Key": format!("nodekey:{exit_hex}"),
                "Addresses": ["100.64.0.3/32"],
                "AllowedIPs": ["100.64.0.3/32", "0.0.0.0/0"],
                "Endpoints": [exit_addr.to_string()],
                "Online": true,
            }));
        });
        let mut fx = ControlFixture::new(
            MachinePrivateKey::generate(),
            plain_hex,
            Some(plain_addr),
            None,
            auth_key.clone(),
        );
        fx.map_tweak = Some(tweak);
        tokio::spawn(control_server(control_listener, fx));

        let cfg = TailscaleConfig {
            auth_key: Some(auth_key),
            control_url: Some(format!("http://{control_addr}")),
            state_dir: Some(dir.path().to_string_lossy().into_owned()),
            exit_node: Some("auto:any".into()),
            ..TailscaleConfig::new("ts-exit")
        };
        let overlay = Arc::new(start_overlay(&cfg).await.unwrap());
        // The auto pick resolved the exit peer from the map.
        assert_eq!(
            overlay.selected_exit_node().as_ref().map(|n| n.name.as_str()),
            Some("exit.tail-scale.ts.net.")
        );
        // Internet destinations now route to the exit peer...
        let nm = overlay.netmap().unwrap();
        let routed = overlay
            .routed_peer(&nm, "8.8.8.8".parse().unwrap())
            .unwrap();
        assert_eq!(routed.name, "exit.tail-scale.ts.net.");
        // ...LAN ones are refused without allow-lan-access...
        let err = overlay
            .routed_peer(&nm, "192.168.0.10".parse().unwrap())
            .unwrap_err();
        assert!(err.to_string().contains("exit-node-allow-lan-access"), "{err}");
        // ...and tailnet addresses still route to their owning peer.
        let routed = overlay
            .routed_peer(&nm, "100.64.0.2".parse().unwrap())
            .unwrap();
        assert_eq!(routed.name, "peer.tail-scale.ts.net.");

        // A dial through the exit peer's own tailnet address echoes
        // (the exit peer is a normal peer for its own /32).
        let mut stream = overlay
            .dial("100.64.0.3:8095".parse().unwrap())
            .await
            .unwrap_or_else(|e| panic!("exit-peer dial: {e}"));
        stream.write_all(b"via-exit-node").await.unwrap();
        let mut got = [0u8; 13];
        stream.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"via-exit-node");
    }

    #[test]
    fn default_control_url_is_the_public_one() {
        assert_eq!(DEFAULT_CONTROL_URL, "https://controlplane.tailscale.com");
    }

    /// Small builder helpers used by the tests above (and handy for the
    /// integrator's config layer).
    impl TailscaleConfig {
        fn with_accept_routes(mut self, v: bool) -> Self {
            self.accept_routes = Some(v);
            self
        }
        fn with_exit_node(mut self, v: &str) -> Self {
            self.exit_node = Some(v.to_string());
            self
        }
        fn with_exit_node_allow_lan_access(mut self, v: bool) -> Self {
            self.exit_node_allow_lan_access = Some(v);
            self
        }
        fn with_auth_key(mut self, v: Option<String>) -> Self {
            self.auth_key = v;
            self
        }
        fn with_control_url(mut self, v: String) -> Self {
            self.control_url = Some(v);
            self
        }
    }
}
