//! The ZeroTier overlay outbound: config surface + the wire-level
//! assessment of why it cannot be ported under the engine's no-C
//! shipping policy, and what a Rust replacement would need.
//!
//! # Honest start
//!
//! mihomo's ZeroTier outbound (`adapter/outbound/zerotier.go`, 1370
//! lines, cached at `/tmp/wave10-upstream/probe_adapter_outbound_zerotier.go`)
//! is build-gated `!no_zerotier` and embeds **`metacubex/zerotier-go`**
//! — cgo bindings over **libzt** (`github.com/zerotier/libzt`), the
//! C/C++ ZeroTier core (ZeroTierOne service + libzt socket shim). The
//! engine ships musl-static with **no C dependencies**; vendoring a C
//! node core is exactly what that policy forbids. This module therefore
//! ports the pure-Go surface that is portable — the full option struct
//! and every validation the adapter's constructor performs on plain
//! data (network id, orbit worlds, MTU bounds, trace settings, the
//! state-dir derivation, the identity shape check) — and [`connect`]
//! fails with the precise error naming the C dependency instead of
//! pretending.
//!
//! # What libzt provides (and the adapter leans on)
//!
//! From the adapter's own usage (cached lines 492-576, 533-546):
//!
//! * `ZT.NewNode(NodeConfig{ Identity, Store, Sender, Planet, OnEvent,
//!   PhysicalMTU, RemoteTrace*, LowBandwidth, EncryptedHello,
//!   OnNetworkConfig, OnFrame, DirectPaths })` — a complete ZeroTier
//!   node in process: the identity (Ed25519 keypair → 10-digit node
//!   address), the persistent state store (`ZT.NewFileStore`, the
//!   `zeroTierStateFS` directory), the planet/world root set
//!   (`ZT.ParsePlanet`), `node.Join(networkID)` / `node.Orbit(world,
//!   seed)`, and background tasks.
//! * Events — `EventNodeUp/Online/Offline`, `EventPeerPathLearned`,
//!   `EventPeerRouteChanged` (direct vs relayed), the network lifecycle
//!   (`EventNetworkConfigPending/Ready/Changed/AccessDenied/NotFound/
//!   AuthenticationRequired/Left`), identity collisions — the adapter's
//!   `handleNodeEvent` maps every one of these to listener state
//!   (cached lines 657-757).
//! * `ZTTransport.New(Config{ Dialer, Interfaces, SharedUDP,
//!   PrimaryPort/SecondaryPort, TCPFallbackMode/Relay })` — the
//!   physical wire: UDP multipath with a TCP fallback relay.
//! * `ZTIP.New(networkID, node)` — the virtual L2/L3 link:
//!   `HandleFrame`/`WritePacket` (Ethernet frames ↔ IP packets) and
//!   `ApplyNetworkConfig` (managed addresses, routes, MTU).
//! * An IP stack on top (`newIPStack(ipStackOption, assigned, mtu)`) —
//!   gVisor or system — turning the link into `DialTCP`/`ListenUDP`
//!   (cached lines 1088-1135, 1237-1251).
//!
//! # What a Rust replacement needs
//!
//! The ZeroTier wire protocol is public and documentable (ZeroTier's
//! own docs and protocol paper describe it; libzt is the reference
//! implementation):
//!
//! * **Control plane** — join a network by id (the 16-hex-digit u64
//!   this module validates): fetch a `NetworkConfig` (netconf) from
//!   the network's controller via the planet root servers (moons/
//!   orbits are user-defined roots — what the `orbit` option adds).
//!   Transport: ZeroTier's UDP control protocol over the root set.
//! * **Identity** — Ed25519 keypair; the 10-digit node address is a
//!   derivative. Rust side exists (`ed25519-dalek` is not in-tree, but
//!   `ring`'s signature primitive is; `curve25519-dalek` is already a
//!   dependency for other overlays).
//! * **Data plane** — P2P UDP: HELLO/OK handshake proving identity,
//!   path learning/verification (the `EventPeerPathLearned` surface),
//!   NAT traversal, and relayed fallback through roots; packets are
//!   Ethernet frames encrypted with Salsa20 (per the ZeroTier
//!   protocol; the `encrypted-hello` option toggles the handshake's
//!   confidentiality). In-tree Rust equivalents for the symmetric
//!   crypto exist (`chacha20poly1305` covers the Salsa20/ChaCha
//!   family; the exact Salsa20 stream cipher would need a small
//!   in-module implementation like `snell::argon2id`).
//! * **Link + stack** — the virtual NIC: parse/emit Ethernet + ARP +
//!   the managed-IP math (`ZTIP`), then a userspace IP stack. The
//!   engine already carries **smoltcp** (the tailscale assessment's
//!   gVisor stand-in) — that is the natural `ip-stack: gvisor` side.
//!
//! First milestones, in dependency order: (1) identity + state store
//! files, (2) planet/moon world parsing, (3) the root-server control
//! conversation to obtain a netconf, (4) the UDP data plane for one
//! direct peer, (5) smoltcp on the virtual link. Steps 3-4 are the
//! real work; nothing else in-tree implements the ZeroTier control
//! protocol today (tailscale's DERP/Noise control is the analogous,
//! equally absent, piece).
//!
//! # Config surface
//!
//! Every field of upstream `ZeroTierOption` (cached lines 108-135) is
//! carried by [`ZeroTierConfig`], and the constructor's data-only
//! validations are ported ([`ZeroTierConfig::validate`],
//! [`parse_network_id`], [`default_state_dir`], [`identity_has_private`]).
//! `identity-secret` is a secret: redacted in `Debug`, tests source it
//! from an environment variable only. Numeric bounds mirror
//! `ZT.MinNetworkMTU`/`MaxNetworkMTU`/`MinPhysicalMTU`/`MaxPhysicalMTU`
//! (metacubex/zerotier-go) — the constants below use libzt's
//! documented network-MTU window and are called out for re-checking
//! when a Rust core lands.

use crate::error::{Error, Result};

/// `ZT.MinNetworkMTU` — IPv6's minimum MTU (1280), the floor for a
/// ZeroTier virtual network.
pub const MIN_NETWORK_MTU: i64 = 1280;
/// `ZT.MaxNetworkMTU` — ZeroTier's network MTU ceiling.
pub const MAX_NETWORK_MTU: i64 = 10000;
/// `ZT.MinPhysicalMTU` — physical-path floor. Set to the IPv6 minimum
/// (a ZeroTier path must at least carry a 1280-byte datagram); the
/// exact zerotier-go constant should be re-checked when a Rust core is
/// vendored.
pub const MIN_PHYSICAL_MTU: i64 = 1280;
/// `ZT.MaxPhysicalMTU` — a UDP payload fits in a u16.
pub const MAX_PHYSICAL_MTU: i64 = 65535;
/// `ZT.TraceLevelInsane` — the trace-level ceiling.
pub const TRACE_LEVEL_INSANE: u64 = 4;

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
    /// 10-digit seed node address (`ZT.ParseOrbit`'s seed).
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
    /// `remote-trace-target:` — a 10-digit node id receiving traces.
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

/// `ZT.ParseNetworkID` — a network id is 16 hex digits (u64). Ad-hoc
/// networks (`ff` prefix, `ZT.IsAdHocNetworkID`) parse like any other.
pub fn parse_network_id(raw: &str) -> Result<u64> {
    let raw = raw.trim();
    if raw.len() != 16 || !raw.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(Error::config(format!(
            "ZeroTier network id must be 16 hex digits, got {raw:?}"
        )));
    }
    u64::from_str_radix(raw, 16)
        .map_err(|_| Error::config(format!("ZeroTier network id overflow: {raw}")))
}

/// `ZT.IsAdHocNetworkID` — the `ff...` prefix marks controller-less
/// ad-hoc networks (handled specially in the event loop, cached lines
/// 665-713).
pub fn is_adhoc_network_id(network_id: u64) -> bool {
    network_id >> 48 == 0xffff
}

/// `ZT.ParseAddress` — a node address is exactly 10 decimal digits.
pub fn parse_node_address(raw: &str) -> Result<u64> {
    let raw = raw.trim();
    if raw.len() != 10 || !raw.chars().all(|c| c.is_ascii_digit()) {
        return Err(Error::config(format!(
            "ZeroTier node address must be 10 decimal digits, got {raw:?}"
        )));
    }
    raw.parse::<u64>()
        .map_err(|_| Error::config(format!("ZeroTier node address overflow: {raw}")))
}

/// The shape check behind `ZT.ParseIdentity` + `HasPrivate` +
/// `Validate` (cached lines 206-218): a ZeroTier identity is
/// `address:public-key[:taxonomy][:secret-key]` colon fields — the
/// public form has three, the secret form four (`zerotier-idtool`'s
/// `identity.public`/`identity.secret`). Cryptographic validation is
/// libzt's; this is the portable pre-check.
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
                // The zero address is reserved (`ZT.Address.IsReserved`,
                // the same rule the trace target hits).
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
            let address = parse_node_address(target)?;
            // Reserved addresses (0 and friends) are rejected upstream
            // (cached lines 267-271); the zero address is the portable
            // case.
            if address == 0 {
                return Err(Error::config(
                    "ZeroTier remote trace target must be a 10-digit node ID",
                ));
            }
        }
        if self.remote_trace_level > TRACE_LEVEL_INSANE {
            return Err(Error::config(format!(
                "ZeroTier remote trace level must be between 0 and {TRACE_LEVEL_INSANE}"
            )));
        }
        Ok(())
    }
}

/// The error every dial returns today: the overlay needs the ZeroTier
/// node core, which is C.
pub const NOT_PORTED: &str = concat!(
    "zerotier: the overlay needs the ZeroTier node core (libzt, C/C++ — ",
    "via metacubex/zerotier-go), which the engine's musl-static no-C ",
    "policy forbids; a Rust replacement needs the control plane ",
    "(identity/planet/moon worlds, controller netconf) plus the P2P wire ",
    "(HELLO multipath UDP, Salsa20 frames, relay fallback) — see the ",
    "proto::zerotier module map for the staged milestones"
);

/// Bring up the overlay and return a dial-capable connection — the
/// counterpart of upstream `NewZeroTier` + `start`/`ensureStarted`
/// (cached lines 448-626). Fails with [`NOT_PORTED`] until a Rust node
/// core exists; the config math ([`ZeroTierConfig::validate`],
/// [`parse_network_id`], [`default_state_dir`]) is the ported logic
/// the dial path will call.
pub async fn connect(_config: &ZeroTierConfig) -> Result<()> {
    Err(Error::config(NOT_PORTED))
}

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

    #[test]
    fn network_id_parsing() {
        // 16 hex digits parse; ad-hoc (ff...) recognized.
        assert_eq!(parse_network_id("8056c2e21c000001").unwrap(), 0x8056c2e21c000001);
        assert!(is_adhoc_network_id(parse_network_id("ffffc2e21c000001").unwrap()));
        assert!(!is_adhoc_network_id(parse_network_id("8056c2e21c000001").unwrap()));
        // Wrong length / non-hex / overflow-ish inputs fail.
        for bad in ["8056c2e21c0000", "8056c2e21c0000012", "8056c2e21c00000g", ""] {
            assert!(parse_network_id(bad).is_err(), "{bad:?}");
        }
        let err = parse_network_id("short").unwrap_err().to_string();
        assert!(err.contains("16 hex digits"), "{err}");
    }

    #[test]
    fn node_address_parsing() {
        assert_eq!(parse_node_address("0000000123").unwrap(), 123);
        assert_eq!(parse_node_address("1234567890").unwrap(), 1_234_567_890);
        for bad in ["123456789", "12345678901", "12345678a", "abcdef", "0000000abc"] {
            assert!(parse_node_address(bad).is_err(), "{bad:?}");
        }
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
        // Bad seed.
        cfg.orbit = vec![ZeroTierOrbit { world: 7, seed: "nope".into() }];
        assert!(cfg.validate().is_err());
        // Trace target must be a 10-digit node id (cached lines 267-271).
        cfg.orbit.clear();
        cfg.remote_trace_target = Some("nope".into());
        let err = cfg.validate().unwrap_err().to_string();
        assert!(err.contains("10 decimal digits"), "{err}");
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

    #[tokio::test]
    async fn connect_fails_with_the_c_dependency_error() {
        let cfg = wellformed("8056c2e21c000001");
        let err = connect(&cfg).await.unwrap_err().to_string();
        assert!(err.contains("libzt"), "{err}");
        assert!(err.contains("no-C"), "{err}");
        assert!(err.contains("control plane"), "{err}");
        assert!(err.contains("P2P"), "{err}");
    }
}
