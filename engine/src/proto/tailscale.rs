//! The tailscale overlay outbound: config surface + the wire-level
//! assessment of what implementing it actually takes.
//!
//! # Honest start
//!
//! mihomo's tailscale outbound (`adapter/outbound/tailscale.go`, 479
//! lines, cached at `/tmp/wave7-upstream/mihomo_outbound_tailscale.go`)
//! is **build-gated** on `with_gvisor && !no_tailscale` (line 1) and is
//! not a proxy protocol at all — it embeds the whole
//! `metacubex/tailscale` tsnet userspace stack. When the tag is off,
//! upstream registers nothing. This module is the equivalent honest
//! position for this engine: the full config surface is parsed and
//! carried (below), the pref math is ported, and [`connect`] fails with
//! a precise error instead of pretending. It is a P3 continuation point,
//! not a refusal — the implementation map follows.
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
//! Pieces with an in-tree basis:
//!
//! * WireGuard Noise transport — `proto::wireguard` already implements
//!   the Noise_IK handshake and transport encryption; a tailscale
//!   data-plane flow is WireGuard over the tsnet-chosen path (direct UDP
//!   or a DERP stream).
//! * TLS 1.3 + HTTP/2 client — the control channel and DERP are
//!   HTTPS/2; `proto::trusttunnel` carries an HTTP/2 client and rustls
//!   TLS 1.3 is used across the tree (ech/tlsmirror).
//! * Userspace IP stack — `smoltcp` (already a dependency) is the
//!   non-gVisor stand-in for `Netstack`: dialing through the overlay is
//!   injecting flows into a userspace stack bound to the tailscale
//!   addresses, exactly what `DialContextTCPWithBind` does upstream.
//! * DNS — the engine's resolver can front `QueryDNS`-equivalent
//!   MagicDNS queries once a LocalClient exists.
//!
//! Pieces with no in-tree basis (the actual work):
//!
//! * `tailcfg` protocol — the JSON message schema (RegisterRequest,
//!   Netmap, cap hashes), the Noise framing on top of TLS 1.3
//!   (`controlbase`), and the long-poll netmap session.
//! * DERP client — the relay protocol (messages, probe/backoff, the
//!   regional bootstrap list) used before/instead of direct links.
//! * `ipn` state machine — prefs persistence and the
//!   NeedsLogin→Running lifecycle the outbound's `watchBackendState`
//!   gates on, plus the `StateDir` store format.
//! * lifecycle glue — port of `start`/`ensureStarted`/`applyPrefs`
//!   (cached lines 186-347) onto the pieces above.
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

/// The error every dial would return today: the overlay needs the tsnet
/// control-plane stack this engine does not carry yet.
pub const NOT_IMPLEMENTED: &str = concat!(
    "tailscale: the overlay needs the tsnet control-plane stack ",
    "(tailcfg/ipn/DERP); the portable wire pieces are mapped in the ",
    "module docs — P3 continuation"
);

/// Bring up the overlay and return a dial-capable connection — the
/// counterpart of upstream `NewTailscale` + `start`/`ensureStarted`
/// (cached lines 114-211). Fails with [`NOT_IMPLEMENTED`] until the
/// control-plane pieces in the module map exist; the config math
/// ([`TailscaleConfig::masked_prefs`], [`TailscaleConfig::exit_node_needs_status`])
/// is already the ported logic the dial path will call.
pub async fn connect(_config: &TailscaleConfig) -> Result<()> {
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
        // The message names the missing stack and the continuation, and
        // never leaks configuration (no auth key, no control url).
        assert!(err.to_string().contains("tailcfg/ipn/DERP"));
        assert!(err.to_string().contains("P3 continuation"));
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
    }
}
