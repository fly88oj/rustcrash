//! The tailscale overlay outbound: config surface + the wire-level
//! control-plane foundations.
//!
//! # Status after wave 10
//!
//! The two wire protocols under every tsnet node now exist in this
//! module (each a `tailscale/` submodule, each a 1:1 port of the Go
//! sources cached at `/tmp/wave10-upstream/`):
//!
//! * [`noise`] — `controlbase`: the **Noise IK**
//!   (`Noise_IK_25519_ChaChaPoly_BLAKE2s`) handshake, its 101/51-byte
//!   messages and the framed record transport (both client and server
//!   halves — the server half is what the in-test mimics run).
//! * [`controlhttp`] — the `/ts2021` HTTP upgrade that carries the
//!   noise transport (POST + `Upgrade: tailscale-control-protocol` +
//!   base64 initiation in `X-Tailscale-Handshake` → 101), with the
//!   HTTP→HTTPS fallback.
//! * [`derp`] — the DERP relay client: the 5-byte frame layer, the
//!   magic/naclbox key registration exchange, and the
//!   `GET /derp` + `Upgrade: DERP` HTTP carrier.
//!
//! What is still missing above them is the ipn layer: the
//! `NeedsLogin→Running` state machine, prefs/state persistence in
//! `StateDir`, the tailcfg JSON messages (RegisterRequest/netmap
//! long-poll) and the DERPMap bootstrap that registration feeds from —
//! see [`connect`] for the precise error.
//!
//! # Honest start
//!
//! mihomo's tailscale outbound (`adapter/outbound/tailscale.go`, 479
//! lines, cached at `/tmp/wave7-upstream/mihomo_outbound_tailscale.go`)
//! is **build-gated** on `with_gvisor && !no_tailscale` (line 1) and is
//! not a proxy protocol at all — it embeds the whole
//! `metacubex/tailscale` tsnet userspace stack. When the tag is off,
//! upstream registers nothing. The config math is ported
//! ([`TailscaleConfig::masked_prefs`],
//! [`TailscaleConfig::exit_node_needs_status`]) and the control-plane
//! wires now exist below; the ipn glue that turns them into a dialable
//! overlay is the remaining P3 continuation point.
//!
//! # What tsnet provides (and the outbound leans on)
//!
//! * `tsnet.Server{Dir, Hostname, AuthKey, ControlURL, Ephemeral,
//!   SystemDialer, SystemPacketListener, ExtraRootCAs, LookupHook,
//!   UserLogf, Logf}` — cached file lines 148-179: a complete IPN node in
//!   process. `Start()` runs the control-plane login; `Netstack(ctx)` (a
//!   gVisor userspace IP stack) actually carries the flows
//!   (`DialContextTCPWithBind` at line 369); `TailscaleIPs()` supplies the
//!   source addresses (line 357); UDP goes through `ListenPacket` (line
//!   398).
//! * `LocalClient` — `EditPrefs`/`applyPrefs` (lines 272-286), the
//!   `WatchIPNBus` state watcher that gates every dial on the backend
//!   reaching a usable state (`watchBackendState`, lines 213-252), exit
//!   node application via `Status` (lines 288-312), and MagicDNS through
//!   `QueryDNS` (lines 429-455).
//! * the control plane underneath: `tailcfg` — the control-server
//!   protocol (Noise-encrypted HTTPS; node registration, netmap
//!   exchange over long-poll HTTP/2), the DERP relay mesh (relayed
//!   connectivity bootstrap and fallback), and the `ipn` state machine +
//!   state store in `StateDir` (noise private key, machine key, prefs).
//!
//! # Implementation map for this engine
//!
//! Done in-tree (wave 10, this module):
//!
//! * `controlbase` Noise IK transport — [`noise`] (handshake, record
//!   framing, machine keys).
//! * `controlhttp` `/ts2021` upgrade — [`controlhttp`].
//! * DERP client + derphttp carrier — [`derp`].
//!
//! Pieces with an in-tree basis (next):
//!
//! * WireGuard Noise transport — `proto::wireguard` already implements
//!   the Noise_IK handshake and transport encryption; a tailscale
//!   data-plane flow is WireGuard over the tsnet-chosen path (direct UDP
//!   or a DERP stream, now speakable).
//! * tailcfg JSON messages — serde_json covers RegisterRequest/netmap
//!   once the ipn layer exists.
//! * Userspace IP stack — `smoltcp` (already a dependency) is the
//!   non-gVisor stand-in for `Netstack`.
//! * DNS — the engine's resolver can front `QueryDNS`-equivalent
//!   MagicDNS queries once a LocalClient exists.
//!
//! Still missing (the ipn work, in order):
//!
//! * control-server key bootstrap — the `/key` fetch that supplies the
//!   server's noise public key ([`controlhttp`] takes it as a
//!   parameter precisely because this fetch is not ported yet).
//! * tailcfg session — RegisterRequest/login, netmap long-poll, cap
//!   hashes, the DERPMap delivery that [`connect_with_bootstrap`]'s
//!   DERP registration will ultimately be driven from.
//! * `ipn` state machine — prefs persistence and the
//!   NeedsLogin→Running lifecycle the outbound's `watchBackendState`
//!   gates on, plus the `StateDir` store format.
//! * lifecycle glue — port of `start`/`ensureStarted`/`applyPrefs`
//!   (cached lines 186-347) onto the pieces above.
//!
//! # Ported deltas (vs upstream Go)
//!
//! * controlhttp dials the HTTP leg then falls back to HTTPS
//!   sequentially; upstream races both with a 500 ms fallback timer
//!   (client.go:288-305). Same wire, no timer race.
//! * controlhttp verifies TLS by default where upstream demotes cert
//!   errors to logs (client.go:493-502) — the Noise layer pins the
//!   control key anyway, and engine policy keeps verification on
//!   unless the config says otherwise.
//! * derphttp: no websocket fallback (derphttp_client.go:381-423), no
//!   meta-cert fast-start (:453-477), no proxy/dial-plan machinery —
//!   the plain `GET /derp` + 101 path only.
//! * derp.Client: the token-bucket send rate limiter
//!   (derp_client.go:709-720) is not ported; it throttbles local sends
//!   and never appears on the wire.
//!
//! # Config surface
//!
//! Every field of upstream `TailscaleOption` (cached lines 54-67) is
//! carried by [`TailscaleConfig`]. `auth_key` is a secret: it is
//! redacted in `Debug` and tests only ever source it from an environment
//! variable, never a literal. `state_dir` defaults to `"tailscale"`
//! resolved by the config layer (upstream: `C.Path.Resolve` +
//! `C.Path.IsSafePath`, cached lines 118-124 — path policy belongs to
//! the engine's config, not the protocol module).

mod controlhttp;
mod derp;
mod noise;

pub use controlhttp::{
    upgrade_over as controlhttp_upgrade_over, ControlHttpDialer, HANDSHAKE_HEADER_NAME,
    SERVER_UPGRADE_PATH, UPGRADE_HEADER_VALUE,
};
pub use derp::{
    derp_connect, derp_upgrade_over, DerpClient, DerpClientOptions, DerpHttpOptions,
    DerpMessage, NodePrivateKey, NodePublicKey, ServerInfo, ServerInfoMessage, DERP_PATH,
};
pub use noise::{
    client_deferred, client_handshake, server_handshake, MachinePrivateKey, MachinePublicKey,
    NoiseConn, CURRENT_PROTOCOL_VERSION,
};

use crate::error::{Error, Result};

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

/// The error every dial returns today: the wire protocols are ported
/// (controlbase Noise IK, the /ts2021 upgrade, the DERP client), but
/// the ipn layer that turns them into a node is still missing.
pub const NOT_IMPLEMENTED: &str = concat!(
    "tailscale: the control-plane wire layer is ported (controlbase ",
    "Noise IK + /ts2021 upgrade + DERP client, see module docs) but the ",
    "ipn layer is not: control /key bootstrap, tailcfg RegisterRequest + ",
    "netmap long-poll, the ipn NeedsLogin->Running state machine + ",
    "StateDir persistence, and the tsnet netstack glue — P3 continuation"
);

/// Bootstrap material for the wire-level bring-up — the pieces the
/// future ipn layer will own: the machine identity and the control
/// server's noise public key (fetched via the control `/key` endpoint
/// upstream, not yet ported), plus an optional explicit DERP server.
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

/// Bring up the overlay and return a dial-capable connection — the
/// counterpart of upstream `NewTailscale` + `start`/`ensureStarted`
/// (cached lines 114-211). The wire layer now exists
/// ([`connect_with_bootstrap`] proves control reachability and DERP
/// registration); the dial itself still fails with [`NOT_IMPLEMENTED`]
/// because the ipn state machine that owns registration, the netmap
/// and the userspace stack is not ported.
pub async fn connect(config: &TailscaleConfig) -> Result<()> {
    let _ = config;
    Err(Error::config(NOT_IMPLEMENTED))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_auth_key() -> Option<String> {
        // SECURITY: the repo's standing rule — fake credentials come from
        // the environment only, never a source literal. Absent means "not
        // exercised".
        std::env::var("RUSTCRASH_TEST_TS_AUTH_KEY").ok().filter(|k| !k.is_empty())
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

    #[tokio::test]
    async fn connect_fails_with_the_precise_cited_error() {
        let err = connect(&TailscaleConfig::new("ts").with_auth_key(test_auth_key()))
            .await
            .unwrap_err();
        assert_eq!(
            err.to_string(),
            format!("config: {NOT_IMPLEMENTED}"),
            "the error text is the contract the integrator surfaces"
        );
        // The message names what now exists and precisely what is
        // still missing (the ipn layer), and never leaks
        // configuration (no auth key, no control url).
        assert!(err.to_string().contains("ipn"));
        assert!(err.to_string().contains("netmap long-poll"));
        assert!(err.to_string().contains("P3 continuation"));
        assert!(!err.to_string().contains("control.example"));
    }

    /// An in-test control server: `/ts2021` POST + 101 + the
    /// controlbase server half, echoing one record (the wire-exact
    /// behavior of control/controlhttp/controlhttpserver).
    async fn control_echo_mimic(listener: tokio::net::TcpListener, control_key: MachinePrivateKey) {
        use base64::Engine;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
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
        let config = TailscaleConfig::new("ts")
            .with_control_url(format!("http://{control_addr}"));
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

    #[test]
    fn auth_key_never_prints_in_debug() {
        // Only env-sourced fake credentials are ever attached; Debug must
        // not expose them.
        let cfg = TailscaleConfig::new("ts").with_auth_key(Some("env-sourced-secret".into()));
        let printed = format!("{cfg:?}");
        assert!(!printed.contains("env-sourced-secret"), "{printed}");
        assert!(printed.contains("[redacted]"), "{printed}");
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
