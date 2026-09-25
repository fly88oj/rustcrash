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
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "rule" => Ok(RuleMode::Rule),
            "global" => Ok(RuleMode::Global),
            "direct" => Ok(RuleMode::Direct),
            other => Err(Error::config(format!("bad mode {other:?}"))),
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
}

impl EngineConfig {
    /// Parse the raw rule lines; errors on the first malformed rule.
    pub fn parse_rules(&self) -> Result<Vec<Rule>> {
        self.rules.iter().map(|r| Rule::parse(r)).collect()
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
/// dialects.
pub fn split_controller(controller: &str) -> (String, u16) {
    match controller.rsplit_once(':') {
        Some((host, port)) => (
            host.trim_start_matches('[').trim_end_matches(']').to_string(),
            port.parse().unwrap_or(9090),
        ),
        None => ("127.0.0.1".to_string(), 9090),
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
    for r in &cfg.parse_rules()? {
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
        assert!(RuleMode::parse("wild").is_err());
        assert_eq!(GroupPolicy::parse("url-test").unwrap().as_str(), "URLTest");
    }
}
