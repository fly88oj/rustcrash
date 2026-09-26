//! Normalized engine configuration (dialect-independent): both the Clash
//! YAML and sing-box JSON loaders produce this shape.

use crate::error::{Error, Result};
use crate::inbound::ListenerConfig;
use crate::outbound::{GroupConfig, GroupPolicy, OutboundConfig};
use crate::rule::Rule;

/// Routing mode (mihomo semantics).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuleMode {
    #[default]
    Rule,
    Global,
    Direct,
}

impl RuleMode {
    /// mihomo lowercases the value before matching (config/config.go
    /// `parseMode` receives the lowercased string), and ShellCrash's
    /// set.yaml hardcodes the capitalized `mode: Rule` — accept any
    /// casing like upstream instead of rejecting the config.
    pub fn parse(s: &str) -> Result<Self> {
        let lower = s.trim().to_ascii_lowercase();
        match lower.as_str() {
            "rule" => Ok(RuleMode::Rule),
            "global" => Ok(RuleMode::Global),
            "direct" => Ok(RuleMode::Direct),
            _ => Err(Error::config(format!("bad mode {s:?}"))),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            RuleMode::Rule => "rule",
            RuleMode::Global => "global",
            RuleMode::Direct => "direct",
        }
    }
}

/// DNS enhanced mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum EnhancedMode {
    #[default]
    FakeIp,
    RedirHost,
}

/// DNS configuration.
#[derive(Debug, Clone)]
pub struct DnsConfig {
    pub enable: bool,
    /// `host:port` to listen on (e.g. `0.0.0.0:7892`).
    pub listen: Option<String>,
    pub enhanced_mode: EnhancedMode,
    pub ipv6: bool,
    pub nameservers: Vec<String>,
    pub fallback: Vec<String>,
    pub fakeip_range: String,
    /// fake-ip store path (mihomo `profile.store-fake-ip` semantics; a
    /// JSON file the pool loads at start and persists to on shutdown).
    pub fakeip_store: Option<std::path::PathBuf>,
    /// fake-ip-filter entries: `geosite:xxx` or domain patterns.
    pub fakeip_filter: Vec<String>,
    /// Static hosts overrides (mihomo `hosts:`, sing-box `hosts`):
    /// domain → addresses; answered before any other resolution path.
    pub hosts: std::collections::HashMap<String, Vec<std::net::IpAddr>>,
    /// mihomo `nameserver-policy`: (domain pattern, nameserver URLs) —
    /// matched domains exchange against these upstreams instead of the
    /// default list.
    pub nameserver_policy: Vec<(String, Vec<String>)>,
    /// EDNS0 client subnet (RFC 7871) attached to outgoing queries
    /// (sing-box dns server `client_subnet`).
    pub client_subnet: Option<crate::dns::edns::ClientSubnet>,
    /// sing-box `dns.rules`: per-rule upstream/ttl/cache behavior.
    pub rules: Vec<crate::dns::rules::RuleSpec>,
}

impl Default for DnsConfig {
    fn default() -> Self {
        DnsConfig {
            fakeip_store: None,
            enable: false,
            listen: None,
            enhanced_mode: EnhancedMode::FakeIp,
            ipv6: false,
            nameservers: vec![
                "udp://223.5.5.5".to_string(),
                "udp://8.8.8.8".to_string(),
            ],
            fallback: Vec::new(),
            fakeip_range: "198.18.0.1/15".to_string(),
            fakeip_filter: vec!["*.lan".to_string(), "*.local".to_string()],
            hosts: std::collections::HashMap::new(),
            nameserver_policy: Vec::new(),
            client_subnet: None,
            rules: Vec::new(),
        }
    }
}

/// Clash RESTful API (external-controller).
#[derive(Debug, Clone)]
pub struct ApiConfig {
    pub bind: String,
    pub port: u16,
    pub secret: Option<String>,
}

/// A file-based rule provider referenced by the config.
#[derive(Debug, Clone)]
pub struct RuleProviderSpec {
    pub name: String,
    pub path: String,
    pub behavior: ProviderBehavior,
    pub format: ProviderFormat,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderBehavior {
    Domain,
    IpCidr,
    Classical,
}

impl ProviderBehavior {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "domain" => Ok(ProviderBehavior::Domain),
            "ipcidr" | "ipcidr6" => Ok(ProviderBehavior::IpCidr),
            "classical" => Ok(ProviderBehavior::Classical),
            other => Err(Error::config(format!("bad provider behavior {other:?}"))),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProviderFormat {
    Text,
    Yaml,
    Mrs,
}

impl ProviderFormat {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "text" => Ok(ProviderFormat::Text),
            "yaml" | "yml" => Ok(ProviderFormat::Yaml),
            // .mrs and sing-box .srs (declared "binary"): the loader
            // sniffs the magic from the file itself.
            "mrs" | "srs" | "binary" => Ok(ProviderFormat::Mrs),
            other => Err(Error::config(format!("bad provider format {other:?}"))),
        }
    }
}

/// Geo database paths (wired by the crash integration).
#[derive(Debug, Clone, Default)]
pub struct GeoPaths {
    pub geoip_mmdb: Option<String>,
    pub geosite_dat: Option<String>,
    /// Optional dedicated ASN mmdb; when absent, IP-ASN reads the
    /// geoip database (mihomo's single-metadb behavior).
    pub asn_mmdb: Option<String>,
}

/// The whole normalized engine config.
#[derive(Debug, Clone, Default)]
pub struct EngineConfig {
    pub mode: RuleMode,
    pub ipv6: bool,
    pub listeners: Vec<ListenerConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub groups: Vec<GroupConfig>,
    pub rules: Vec<String>,
    pub dns: Option<DnsConfig>,
    pub api: Option<ApiConfig>,
    pub rule_providers: Vec<RuleProviderSpec>,
    pub geo: GeoPaths,
    /// Traffic sniffer (TLS SNI / HTTP Host) for the TCP relay.
    pub sniff: crate::sniffer::SniffConfig,
    /// Server-side proxy listeners (mihomo `listeners:` / sing-box server
    /// inbounds): the engine ACTS AS the proxy server for these.
    pub proxy_servers: Vec<crate::inbound::proxy_server::ServerConfig>,
    /// TUN device inbound (mihomo `tun:` / sing-box tun inbound).
    pub tun: Option<crate::inbound::tun::TunConfig>,
    /// sing-box `endpoints` of type wireguard (the WG SERVER mode:
    /// handshake responder + cryptokey routing into the engine).
    pub wg_endpoints: Vec<crate::proto::wireguard::WgEndpointCfg>,
    /// Per-group health-check options (mihomo `lazy` /
    /// `expected-status`), keyed by group name. The mihomo loader fills
    /// an entry for EVERY group; the sing-box loader leaves it empty —
    /// see [`EngineConfig::group_health`].
    pub group_health: std::collections::HashMap<String, GroupHealth>,
    /// sing-box route rule actions, keyed by index into `rules`
    /// (attached by [`EngineConfig::compile_rules`]). mihomo rule lines
    /// carry no actions upstream, so that loader never fills this.
    pub rule_actions: std::collections::HashMap<usize, crate::rule::RuleAction>,
    /// mihomo `authentication`: `user:pass` pairs enforced on the
    /// http/socks/mixed inbound listeners (HTTP 407 challenge, SOCKS5
    /// RFC 1929 auth). Empty = open proxy, mihomo's default.
    pub authentication: Vec<(String, String)>,
    /// mihomo `routing-mark`: SO_MARK stamped on every socket the
    /// engine dials so a transparent-proxy firewall can exempt the
    /// engine's own traffic (`meta mark <mark> return` loop-guards —
    /// without it each relay dials straight back into the tproxy/redir
    /// port and self-relays until FD exhaustion). None = unmarked.
    pub routing_mark: Option<u32>,
}

impl EngineConfig {
    /// Parse the raw rule lines; errors on the first malformed rule.
    pub fn parse_rules(&self) -> Result<Vec<Rule>> {
        self.rules.iter().map(|r| Rule::parse(r)).collect()
    }

    /// Parse the rule lines AND attach the per-index sing-box rule
    /// actions — the action-aware parse result the router walks
    /// ([`crate::rule::RuleTable::walk`]).
    pub fn compile_rules(&self) -> Result<crate::rule::RuleTable> {
        Ok(crate::rule::RuleTable::from_parts(
            self.parse_rules()?,
            self.rule_actions.clone(),
        ))
    }

    /// Health-check options for one group. Absent entry (sing-box
    /// dialect, which has no lazy/expected-status surface): never skip
    /// a check, accept any status.
    pub fn group_health(&self, name: &str) -> GroupHealth {
        self.group_health.get(name).cloned().unwrap_or(GroupHealth {
            lazy: false,
            expected_status: ExpectedStatus::default(),
        })
    }

    /// Ensure built-in outbounds exist (DIRECT/REJECT/PASS, mihomo names).
    pub fn with_builtin_outbounds(mut self) -> Self {
        for (name, udp) in [("DIRECT", true), ("REJECT", false), ("REJECT-DROP", false), ("PASS", true), ("COMPATIBLE", true)] {
            if !self.outbounds.iter().any(|o| o.name == name)
                && !self.groups.iter().any(|g| g.name == name)
            {
                self.outbounds.push(builtin_outbound(name, udp));
            }
        }
        self
    }
}

fn builtin_outbound(name: &str, udp: bool) -> OutboundConfig {
    use crate::outbound::OutboundKind;
    OutboundConfig {
        name: name.to_string(),
        udp,
        kind: match name {
            "DIRECT" | "PASS" | "COMPATIBLE" => OutboundKind::Direct,
            _ => OutboundKind::Reject,
        },
    }
}

impl GroupPolicy {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "select" => Ok(GroupPolicy::Select),
            "url-test" => Ok(GroupPolicy::UrlTest),
            "fallback" => Ok(GroupPolicy::Fallback),
            "load-balance" => Ok(GroupPolicy::LoadBalance),
            other => Err(Error::config(format!(
                "unsupported group type {other:?} (supported: select, url-test, fallback, load-balance)"
            ))),
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            GroupPolicy::Select => "Selector",
            GroupPolicy::UrlTest => "URLTest",
            GroupPolicy::Fallback => "Fallback",
            GroupPolicy::LoadBalance => "LoadBalance",
        }
    }
}

/// Split an external-controller address (`host:port`, `[v6]:port`, or
/// bare port-less host) into bind host and port — shared by both config
/// dialects. The leading-colon form (`:9999`, mihomo's all-interfaces
/// default) and `*:port` bind every interface: an empty host would fail
/// address lookup at bind time.
pub fn split_controller(controller: &str) -> (String, u16) {
    let controller = controller.trim();
    match controller.rsplit_once(':') {
        Some((host, port)) => {
            let host = host.trim_start_matches('[').trim_end_matches(']');
            let bind = match host {
                "" | "*" => "0.0.0.0".to_string(),
                other => other.to_string(),
            };
            (bind, port.parse().unwrap_or(9090))
        }
        None => ("127.0.0.1".to_string(), 9090),
    }
}

/// Normalize a listen address for parsing: mihomo's leading-colon
/// shorthand (`listen: :1053`, the form ShellCrash's dns.yaml emits)
/// means all interfaces, i.e. `0.0.0.0:port` (`SocketAddr::parse`
/// would reject the bare `:port` form outright).
pub fn normalize_listen(listen: &str) -> String {
    let listen = listen.trim();
    if let Some(port) = listen.strip_prefix(':') {
        format!("0.0.0.0:{port}")
    } else {
        listen.to_string()
    }
}

/// A mihomo group `expected-status` list (adapter/outboundgroup/
/// parser.go `ExpectedStatus`, parsed with common/utils/ranges.go
/// `NewUnsignedRanges[uint16]`): `200`, `200/204`, `200-400`,
/// `200/204/401-429/501-503`. `,` is equivalent to `/`; a range's
/// bounds are swapped rather than rejected (`NewRange` normalizes);
/// empty entries drop out; empty or `*` means ANY status. The health
/// check only counts a probe whose HTTP status matches.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ExpectedStatus {
    /// Inclusive `lo-hi` bounds; empty = any status (upstream: nil
    /// IntRanges, where `Check` returns true).
    ranges: Vec<(u16, u16)>,
}

impl ExpectedStatus {
    /// Parse an `expected-status` payload. Errors on a non-numeric or
    /// overlong bound (`lo-hi-x`), a value above `u16::MAX`, or more
    /// than 28 ranges — mirroring upstream's "too many ranges to use,
    /// maximum support 28 ranges" (Go's unsigned parse would silently
    /// truncate out-of-range values; erroring is stricter and safer).
    pub fn parse(payload: &str) -> Result<Self> {
        let payload = payload.trim();
        if payload.is_empty() || payload == "*" {
            return Ok(ExpectedStatus::default());
        }
        let joined = payload.replace(',', "/");
        let list: Vec<&str> = joined.split('/').collect();
        if list.len() > 28 {
            return Err(Error::config(format!(
                "expected-status {payload:?}: too many ranges to use, \
                 maximum support 28 ranges"
            )));
        }
        let mut ranges = Vec::with_capacity(list.len());
        for entry in list {
            if entry.is_empty() {
                continue;
            }
            let one = |s: &str| -> Result<u16> {
                s.trim_matches(['[', ']', ' '])
                    .parse::<u16>()
                    .map_err(|_| Error::config(format!("invalid range: {entry}")))
            };
            let (lo, hi) = match entry.split_once('-') {
                None => {
                    let v = one(entry)?;
                    (v, v)
                }
                Some((lo, hi)) => {
                    // `NewRange` swaps inverted bounds instead of failing.
                    let (lo, hi) = (one(lo)?, one(hi)?);
                    (lo.min(hi), lo.max(hi))
                }
            };
            ranges.push((lo, hi));
        }
        Ok(ExpectedStatus { ranges })
    }

    /// Whether a probe response status counts as healthy
    /// (utils.IntRanges.Check): an empty list accepts everything.
    pub fn matches(&self, status: u16) -> bool {
        self.ranges.is_empty() || self.ranges.iter().any(|&(lo, hi)| lo <= status && status <= hi)
    }

    /// True when no filter was configured (any status accepted).
    pub fn is_any(&self) -> bool {
        self.ranges.is_empty()
    }
}

/// Per-group health-check options (mihomo groupbase surface; sing-box
/// urltest carries neither upstream — option/group.go URLTestOutbound
/// has only url/interval/tolerance/idle_timeout).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupHealth {
    /// mihomo `lazy` (adapter/outboundgroup/parser.go:35): a lazy group
    /// skips its periodic health check when it has not been touched
    /// (used for routing) within the check interval. Defaults to TRUE
    /// upstream (parser.go:51-53).
    pub lazy: bool,
    /// mihomo `expected-status`: only statuses in the list count as
    /// healthy probes.
    pub expected_status: ExpectedStatus,
}

impl Default for GroupHealth {
    fn default() -> Self {
        GroupHealth {
            lazy: true,
            expected_status: ExpectedStatus::default(),
        }
    }
}

impl GroupHealth {
    /// Whether this group's periodic check should run NOW — mihomo
    /// adapter/provider/healthcheck.go `process()`: on every interval
    /// tick, `if !hc.lazy || since < hc.interval { check() } else {
    /// skip }`, where `since` is time since the last touch (never
    /// touched = the zero time = skip, matching the huge `since`).
    pub fn due(
        &self,
        interval: std::time::Duration,
        last_touch: Option<std::time::Instant>,
        now: std::time::Instant,
    ) -> bool {
        if !self.lazy {
            return true;
        }
        match last_touch {
            Some(t) => now.duration_since(t) < interval,
            None => false,
        }
    }
}


/// Validate a normalized config the way `engine test` does.
pub fn validate(cfg: &EngineConfig) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    if cfg.outbounds.is_empty() && cfg.groups.is_empty() {
        return Err(Error::config("no outbounds configured"));
    }
    let names: std::collections::HashSet<&str> = cfg
        .outbounds
        .iter()
        .map(|o| o.name.as_str())
        .chain(cfg.groups.iter().map(|g| g.name.as_str()))
        .collect();
    for p in &cfg.rule_providers {
        if !std::path::Path::new(&p.path).exists() {
            warnings.push(format!("rule provider {} file missing: {}", p.name, p.path));
        }
    }
    for (i, r) in cfg.parse_rules()?.iter().enumerate() {
        match &r.matcher {
            crate::rule::RuleMatcher::RuleSet { name, .. } => {
                if !cfg.rule_providers.iter().any(|p| &p.name == name) {
                    return Err(Error::config(format!("rule references unknown rule-set {name:?}")));
                }
            }
            // Geosite names resolve at build; unknown ones warn there.
            crate::rule::RuleMatcher::Geosite { .. } => {}
            _ => {}
        }
        // A rule carrying an action routes through the action, not an
        // outbound (sing-box action rules have no `outbound` field; the
        // converted line's target is only a placeholder).
        if cfg.rule_actions.contains_key(&i) {
            continue;
        }
        if !names.contains(r.outbound.as_str()) {
            return Err(Error::config(format!(
                "rule target {} is not a configured proxy or group",
                r.outbound
            )));
        }
    }
    for g in &cfg.groups {
        for m in &g.members {
            if !names.contains(m.as_str()) {
                return Err(Error::config(format!(
                    "group {} references unknown proxy {m:?}",
                    g.name
                )));
            }
        }
    }
    if let Some(dns) = &cfg.dns {
        if dns.enable && dns.listen.is_none() {
            warnings.push("dns enabled without a listen address".to_string());
        }
    }
    Ok(warnings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_outbounds_injected() {
        let cfg = EngineConfig::default().with_builtin_outbounds();
        let names: Vec<&str> = cfg.outbounds.iter().map(|o| o.name.as_str()).collect();
        for n in ["DIRECT", "REJECT", "PASS"] {
            assert!(names.contains(&n), "missing {n}");
        }
        // Idempotent.
        let cfg2 = cfg.clone().with_builtin_outbounds();
        assert_eq!(cfg2.outbounds.len(), cfg.outbounds.len());
    }

    #[test]
    fn validation_rejects_dangling_rule_target() {
        let cfg = EngineConfig {
            rules: vec!["MATCH,Nothing".to_string()],
            ..Default::default()
        }
        .with_builtin_outbounds();
        let err = validate(&cfg).err().unwrap();
        assert!(err.to_string().contains("not a configured proxy"));
    }

    #[test]
    fn validation_rejects_unknown_rule_set() {
        let cfg = EngineConfig {
            rules: vec!["RULE-SET,nope,DIRECT".to_string()],
            ..Default::default()
        }
        .with_builtin_outbounds();
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn mrs_providers_accepted() {
        // The binary reader sniffs the file magic; a declared mrs
        // provider no longer fails validation (a missing file only warns).
        let cfg = EngineConfig {
            rule_providers: vec![RuleProviderSpec {
                name: "cn".into(),
                path: "/dev/null".into(),
                behavior: ProviderBehavior::Domain,
                format: ProviderFormat::Mrs,
            }],
            ..Default::default()
        }
        .with_builtin_outbounds();
        assert!(validate(&cfg).is_ok());
    }

    #[test]
    fn mode_parsing() {
        assert_eq!(RuleMode::parse("rule").unwrap(), RuleMode::Rule);
        assert_eq!(RuleMode::parse("global").unwrap(), RuleMode::Global);
        assert_eq!(RuleMode::parse("direct").unwrap(), RuleMode::Direct);
        assert!(RuleMode::parse("wild").is_err());
        // mihomo lowercases before matching: ShellCrash's set.yaml
        // hardcodes the capitalized forms, which must parse.
        assert_eq!(RuleMode::parse("Rule").unwrap(), RuleMode::Rule);
        assert_eq!(RuleMode::parse("GLOBAL").unwrap(), RuleMode::Global);
        assert_eq!(RuleMode::parse("Direct").unwrap(), RuleMode::Direct);
        assert_eq!(RuleMode::parse("  Rule ").unwrap(), RuleMode::Rule);
        assert_eq!(GroupPolicy::parse("url-test").unwrap().as_str(), "URLTest");
    }

    #[test]
    fn controller_and_listen_mihomo_shorthands() {
        // Plain and bracketed hosts unchanged.
        assert_eq!(split_controller("127.0.0.1:9090"), ("127.0.0.1".into(), 9090));
        assert_eq!(split_controller("[::1]:9090"), ("::1".into(), 9090));
        assert_eq!(split_controller("127.0.0.1"), ("127.0.0.1".into(), 9090));
        // mihomo's leading-colon / `*` all-interfaces forms bind 0.0.0.0
        // (an empty host fails address lookup at bind time).
        assert_eq!(split_controller(":9999"), ("0.0.0.0".into(), 9999));
        assert_eq!(split_controller("*:9999"), ("0.0.0.0".into(), 9999));
        assert_eq!(normalize_listen(":1053"), "0.0.0.0:1053");
        assert_eq!(normalize_listen("0.0.0.0:1053"), "0.0.0.0:1053");
        assert_eq!(normalize_listen(" [::]:1053 "), "[::]:1053");
        assert!(normalize_listen(":1053").parse::<std::net::SocketAddr>().is_ok());
    }

    #[test]
    fn expected_status_parses_upstream_forms() {
        // common/utils/ranges.go newIntRanges: "" and "*" accept
        // everything; `,` == `/`; empty entries drop out.
        for any in ["", "*", "  "] {
            let s = ExpectedStatus::parse(any).unwrap();
            assert!(s.is_any());
            assert!(s.matches(200) && s.matches(500) && s.matches(0));
        }
        let single = ExpectedStatus::parse("204").unwrap();
        assert!(!single.is_any());
        assert!(single.matches(204));
        assert!(!single.matches(200) && !single.matches(205));

        // Lists, both separators.
        let list = ExpectedStatus::parse("200/302").unwrap();
        assert!(list.matches(200) && list.matches(302) && !list.matches(301));
        let commas = ExpectedStatus::parse("200,302").unwrap();
        assert_eq!(commas, list);

        // Ranges, mixed lists, inverted bounds (NewRange swaps).
        let mixed = ExpectedStatus::parse("200/204/401-429/501-503").unwrap();
        assert!(mixed.matches(200) && mixed.matches(429) && mixed.matches(503));
        assert!(!mixed.matches(400) && !mixed.matches(430) && !mixed.matches(504));
        let swapped = ExpectedStatus::parse("429-401").unwrap();
        assert!(swapped.matches(401) && swapped.matches(429));

        // Errors: garbage, lo-hi-extra, out-of-u16, >28 ranges.
        assert!(ExpectedStatus::parse("20x").is_err());
        assert!(ExpectedStatus::parse("200-204-399").is_err());
        assert!(ExpectedStatus::parse("70000").is_err());
        let many = std::iter::repeat_n("200", 29).collect::<Vec<_>>().join("/");
        assert!(ExpectedStatus::parse(&many).is_err());
        let max = std::iter::repeat_n("200", 28).collect::<Vec<_>>().join("/");
        assert!(ExpectedStatus::parse(&max).is_ok());
    }

    #[test]
    fn group_health_lazy_gate_matches_mihomo() {
        // healthcheck.go process(): non-lazy always checks.
        let eager = GroupHealth {
            lazy: false,
            ..Default::default()
        };
        let now = std::time::Instant::now();
        assert!(eager.due(std::time::Duration::from_secs(300), None, now));

        // Lazy: never touched → skip (upstream zero lastTouch).
        let lazy = GroupHealth::default();
        assert!(lazy.lazy);
        assert!(!lazy.due(std::time::Duration::from_secs(300), None, now));

        // Touched recently (within the interval) → check runs; touched
        // one interval ago → skipped.
        let fresh = now - std::time::Duration::from_secs(10);
        assert!(lazy.due(std::time::Duration::from_secs(300), Some(fresh), now));
        let stale = now - std::time::Duration::from_secs(300);
        assert!(!lazy.due(std::time::Duration::from_secs(300), Some(stale), now));
        assert!(lazy.expected_status.is_any());
    }

    #[test]
    fn compile_rules_attaches_actions_and_validate_skips_them() {
        let mut cfg = EngineConfig {
            rules: vec!["DST-PORT,443,NOSUCHOUTBOUND".to_string(), "MATCH,DIRECT".to_string()],
            rule_actions: std::collections::HashMap::from([(
                0,
                crate::rule::RuleAction::Sniff {
                    sniffer: vec!["tls".into()],
                },
            )]),
            ..Default::default()
        }
        .with_builtin_outbounds();

        let table = cfg.compile_rules().unwrap();
        assert_eq!(table.rules().len(), 2);
        assert_eq!(
            table.action(0),
            Some(&crate::rule::RuleAction::Sniff {
                sniffer: vec!["tls".to_string()]
            })
        );
        assert_eq!(table.action(1), None);

        // The action rule's placeholder outbound is not validated…
        assert!(validate(&cfg).is_ok());
        // …while a plain rule with a dangling target still fails.
        cfg.rule_actions.clear();
        assert!(validate(&cfg).is_err());

        // group_health accessor: absent (sing-box) = never skip; the
        // mihomo default entry is lazy.
        assert!(!cfg.group_health("G").lazy);
        assert!(cfg.group_health("G").expected_status.is_any());
        cfg.group_health.insert("G".into(), GroupHealth::default());
        assert!(cfg.group_health("G").lazy);
    }
}
