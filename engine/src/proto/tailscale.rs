//! The tailscale overlay outbound: config surface, the ipn control
//! session (login + map poll), and the first data-plane wiring.
//!
//! # Status after wave 11
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
//! * No disco: peers that require the disco overlay before accepting
//!   transport will not come up (see [`wg`]'s module docs).
//! * The map poll runs once per [`start_overlay`]; auto.go's
//!   `mapRoutine` backoff/restart loop (map.go:584-650) is trimmed to a
//!   single long-poll task.
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
pub use noise::{
    client_deferred, client_handshake, server_handshake, MachinePrivateKey, MachinePublicKey,
    NoiseConn, CURRENT_PROTOCOL_VERSION,
};
pub use state::{FileStore, NodeIdentity, Persist, STATE_FILE_NAME};
pub use tailcfg::{
    AddrPort, DerpMap, DerpNode, DerpRegion, DiscoKeyText, Hostinfo, MachineKeyText, MapRequest,
    MapResponse, Node, NodeKey, OverTlsPublicKeyResponse, PeerChange, Prefix, RegisterRequest,
    RegisterResponse, RegisterResponseAuth, UserProfile, CURRENT_CAPABILITY_VERSION,
};
pub use wg::{DerpRoute, TsTcpStream, TsTunnel, TsTunnelConfig};

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

/// The error every `connect` still ends with after wave 11: login,
/// netmap and peer reachability now work; what remains is enumerated
/// precisely (and the outbound integration itself is the integrator's).
pub const NOT_IMPLEMENTED: &str = concat!(
    "tailscale: login (auth-key RegisterRequest), the netmap long-poll and ",
    "peer data-plane paths (direct UDP + DERP relay) are ported, but the ",
    "outbound is not integrated yet and these pieces are missing: ",
    "MagicDNS resolution (names still need pre-resolved tailnet IPs), ",
    "subnet-route and exit-node enforcement (prefs are parsed, never ",
    "applied to routing), key-expiry renewal / node key rotation, the ",
    "disco overlay peers may require before accepting transport, UDP ",
    "through the overlay, the tailnet packet filter, interactive ",
    "(browser) login, and the map-poll reconnect/backoff loop — ",
    "P3 continuation"
);

// ---------------------------------------------------------------------------
// The overlay: login + map poll + data plane
// ---------------------------------------------------------------------------

/// A live tailscale overlay: the login has completed, the map poll is
/// running, and dials route through the netmap.
pub struct TailscaleOverlay {
    node_key: NodePrivateKey,
    /// The latest netmap, fed by the map-poll task.
    netmap: Arc<Mutex<Option<NetMap>>>,
    netmap_changed: Arc<Notify>,
    /// One tunnel per routed peer (by node key hex).
    tunnels: tokio::sync::Mutex<HashMap<String, TsTunnel>>,
    /// The host:port authority for control requests.
    control_authority: String,
}

impl TailscaleOverlay {
    /// The latest netmap (the last one the poll delivered).
    pub fn netmap(&self) -> Option<NetMap> {
        self.netmap.lock().unwrap_or_else(|e| e.into_inner()).clone()
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

    /// Dial TCP through the engine's EXISTING WireGuard client
    /// (`proto::wireguard::connect`) configured from the netmap: this is
    /// the direct path, usable when the routed peer advertises a UDP
    /// endpoint. The `reserved` bytes stay zero (no mihomo provider
    /// quirk applies to a tailnet peer).
    pub async fn dial_direct(&self, target: SocketAddr) -> Result<crate::stream::BoxProxyStream> {
        let nm = self.netmap().ok_or_else(|| {
            Error::network("tailscale: no netmap yet (the map poll has not delivered one)")
        })?;
        let peer = nm.route_peer(target.ip()).ok_or_else(|| {
            Error::network(format!(
                "tailscale: no peer routes {} (cryptokey routing found no match)",
                target.ip()
            ))
        })?;
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
        let b64 = base64::engine::general_purpose::STANDARD;
        let cfg = crate::proto::wireguard::WgOut {
            server: endpoint.ip().to_string(),
            port: endpoint.port(),
            private_key: b64.encode(self.node_key.secret()),
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

    /// Dial TCP through the tailscale-side session ([`wg`]): direct UDP
    /// when the peer advertises an endpoint, DERP-relayed through the
    /// peer's home relay otherwise (and both while the path is being
    /// learned). One tunnel per peer is cached.
    pub async fn dial_relay(&self, target: SocketAddr) -> Result<TsTcpStream> {
        let nm = self.netmap().ok_or_else(|| {
            Error::network("tailscale: no netmap yet (the map poll has not delivered one)")
        })?;
        let peer = nm.route_peer(target.ip()).ok_or_else(|| {
            Error::network(format!(
                "tailscale: no peer routes {} (cryptokey routing found no match)",
                target.ip()
            ))
        })?;
        let peer_hex: String =
            peer.key.as_bytes().iter().map(|b| format!("{b:02x}")).collect();
        let mut tunnels = self.tunnels.lock().await;
        // Reuse the peer's tunnel when it exists and lives.
        if let Some(t) = tunnels.get(&peer_hex) {
            if let Ok(stream) = t.connect_tcp(target).await {
                return Ok(stream);
            }
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
        let cfg = TsTunnelConfig {
            private_key: *self.node_key.secret(),
            peer_public: *peer.key.as_bytes(),
            local_ipv4: nm
                .self_node
                .addresses
                .iter()
                .find_map(|p| match p.addr {
                    std::net::IpAddr::V4(v4) => Some(v4),
                    _ => None,
                })
                .unwrap_or(std::net::Ipv4Addr::UNSPECIFIED),
            local_ipv6: nm.self_node.addresses.iter().find_map(|p| match p.addr {
                std::net::IpAddr::V6(v6) => Some(v6),
                _ => None,
            }),
            mtu: 1280,
            endpoint,
            derp,
        };
        let tunnel = TsTunnel::spawn(cfg).await?;
        tunnels.insert(peer_hex, tunnel.clone());
        tunnel.connect_tcp(target).await
    }

    /// Dial TCP through the overlay, preferring the direct path and
    /// falling back to DERP (magicsock's behavior, sequential here).
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

    /// The control authority (host:port) — for the map poll task.
    pub fn control_authority(&self) -> &str {
        &self.control_authority
    }
}

/// Bring the overlay up: state keys, the control `/key` bootstrap, the
/// auth-key register, then the map long-poll (spawned; it feeds
/// [`TailscaleOverlay::netmap`]). Returns once the first netmap has
/// arrived — the `watchBackendState` gate of the mihomo outbound
/// (cached lines 213-252) equivalent for "Running".
pub async fn start_overlay(config: &TailscaleConfig) -> Result<TailscaleOverlay> {
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
    let node_key_pub = *identity.node_key.public().as_bytes();

    // 2. The control server's noise key (loadServerPubKeys) + the
    //    host:port authority requests are addressed to.
    let control_key = fetch_control_key(&control_url).await?;
    let control_authority = format!("{}:{}", host_of(&control_url), port_of(&control_url));

    // 3. Register (TryLogin's auth-key leg). One noise connection per
    //    request (see control's module docs).
    let dialer = ControlHttpDialer::from_url(
        &control_url,
        identity.machine_key.clone(),
        control_key.clone(),
    )?;
    let mut session = ControlSession::dial(&dialer).await?;
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
    let request = build_register_request(
        &NodeKey(node_key_pub),
        None,
        &auth_key,
        hostinfo.clone(),
        config.ephemeral,
    );
    match register(&mut session, &control_authority, &request).await? {
        RegisterOutcome::Registered(_) => {}
        RegisterOutcome::NeedsBrowserAuth(url) => {
            return Err(Error::config(format!(
                "tailscale: interactive login required (visit {url}); browser auth is staged"
            )))
        }
    }
    drop(session);

    // 4. The map long-poll (StreamMap), in the background, feeding the
    //    overlay's netmap slot. auto.go's authRoutine/mapRoutine pair is
    //    trimmed to: register once, then one long-poll task (the
    //    reconnect/backoff loop is a documented gap).
    let netmap_slot: Arc<Mutex<Option<NetMap>>> = Arc::new(Mutex::new(None));
    let changed = Arc::new(Notify::new());
    {
        let slot = netmap_slot.clone();
        let changed = changed.clone();
        let authority = control_authority.clone();
        let machine_key = identity.machine_key.clone();
        tokio::spawn(async move {
            let map_dialer = match ControlHttpDialer::from_url(&control_url, machine_key, control_key) {
                Ok(d) => d,
                Err(e) => {
                    tracing::debug!(target: "engine", "tailscale: map dialer: {e}");
                    return;
                }
            };
            let mut map_session = MapSession::new(NodeKey(node_key_pub));
            let Ok(mut s) = ControlSession::dial(&map_dialer).await else {
                return;
            };
            let req = build_map_request(&NodeKey(node_key_pub), hostinfo, true);
            let res = stream_map(&mut s, &authority, &req, &mut map_session, |nm| {
                *slot.lock().unwrap_or_else(|e| e.into_inner()) = Some(nm.clone());
                changed.notify_one();
            })
            .await;
            if let Err(e) = res {
                tracing::debug!(target: "engine", "tailscale: map poll ended: {e}");
            }
        });
    }

    let overlay = TailscaleOverlay {
        node_key: identity.node_key,
        netmap: netmap_slot,
        netmap_changed: changed,
        tunnels: tokio::sync::Mutex::new(HashMap::new()),
        control_authority,
    };

    // 5. Wait for the first netmap (bounded; the poll reconnect loop is
    //    a documented gap).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
    while overlay.netmap().is_none() {
        if std::time::Instant::now() >= deadline {
            return Err(Error::network(
                "tailscale: no netmap arrived from the map poll within 15s",
            ));
        }
        let changed = overlay.netmap_changed.clone();
        let _ = tokio::time::timeout(std::time::Duration::from_secs(2), changed.notified()).await;
    }
    Ok(overlay)
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

/// Bring up the overlay and return a dial-capable connection — the
/// counterpart of upstream `NewTailscale` + `start`/`ensureStarted`
/// (cached lines 114-211). Wave 11 runs the real control path (login +
/// netmap + peer reachability) and then stops with the precise
/// remaining-gap error: the outbound wiring itself (a `connect` that
/// returns a stream the engine's relay can splice) is the integrator's
/// step, and the enumerated gaps (MagicDNS, exit-node/subnet-route
/// enforcement, key expiry renewal, disco, UDP, packet filter,
/// interactive login, poll reconnect) stand.
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
    }

    /// Run the control mimic: sequentially serves the /key fetch, the
    /// register, and the map poll on one listener (the client's calls
    /// are sequential). Assertions validate every request shape.
    async fn control_server(listener: tokio::net::TcpListener, fx: ControlFixture) {
        use base64::Engine;
        loop {
            let (mut sock, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => return,
            };
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
                continue;
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
                    let mut msg = serde_json::json!({
                        "Node": {
                            "ID": 1,
                            "Key": format!("nodekey:{self_hex}"),
                            "Addresses": ["100.64.0.1/32"],
                            "AllowedIPs": ["100.64.0.1/32"],
                        },
                        "Peers": [peer],
                        "Domain": "tail-scale.ts.net",
                    });
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

    fn b64(bytes: &[u8]) -> String {
        base64::engine::general_purpose::STANDARD.encode(bytes)
    }

    /// The peer: the engine's own WireGuard endpoint (the production
    /// responder + netstack + relay), returning (wg_addr, peer static
    /// public key hex) and allowing our node key + tailnet IP.
    async fn spawn_peer_wg_endpoint(our_node_pub: [u8; 32]) -> (SocketAddr, String) {
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
            address: Some(("100.64.0.2".parse().unwrap(), 24)),
            inet6_address: None,
            udp_timeout: None,
            peers: vec![crate::proto::wireguard::WgEndpointPeer {
                public_key: b64(&our_node_pub),
                pre_shared_key: None,
                allowed_ips: vec![("100.64.0.1".parse::<std::net::IpAddr>().unwrap(), 32)],
                persistent_keepalive: None,
            }],
        };
        let addr = crate::proto::wireguard::serve_endpoint(&cfg, Arc::new(EchoRelay))
            .await
            .unwrap();
        // The endpoint binds [::] dual-stack and reports the v6 wildcard;
        // address it over v4 loopback (the wireguard.rs tests' v4_ep
        // rewrites the same way).
        let addr = SocketAddr::new(
            std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
            addr.port(),
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
            ControlFixture {
                control_key: MachinePrivateKey::generate(),
                peer_key_hex: peer_key_hex.clone(),
                peer_endpoint: Some(wg_addr),
                derp_url: None,
                auth_key: auth_key.clone(),
                ephemeral: false,
            },
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
            ControlFixture {
                control_key: MachinePrivateKey::generate(),
                peer_key_hex,
                // NO endpoints: the peer is only reachable through its
                // home DERP relay.
                peer_endpoint: None,
                derp_url: Some(format!("http://{derp_addr}")),
                auth_key: auth_key.clone(),
                ephemeral: false,
            },
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
            ControlFixture {
                control_key: MachinePrivateKey::generate(),
                peer_key_hex: peer_key_hex.clone(),
                peer_endpoint: Some(wg_addr),
                derp_url: None,
                auth_key: auth_key.clone(),
                ephemeral: false,
            },
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
        assert!(msg.contains("MagicDNS"), "{msg}");
        assert!(msg.contains("exit-node"), "{msg}");
        assert!(msg.contains("key-expiry"), "{msg}");
        assert!(msg.contains("disco"), "{msg}");
        assert!(msg.contains("P3 continuation"), "{msg}");
        assert!(msg.contains("DERP relay"), "{msg}");
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
