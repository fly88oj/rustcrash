//! Routing rules: matchers, parsing from Clash-style rule lines, and
//! ordered evaluation with provider sets.

use std::net::IpAddr;
use std::str::FromStr;

use crate::addr::Host;
use crate::error::{Error, Result};

/// An IP network (`a.b.c.d/pl`, v4 or v6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    pub addr: IpAddr,
    pub prefix: u8,
}

impl IpNet {
    pub fn new(addr: IpAddr, prefix: u8) -> Result<Self> {
        let max = if addr.is_ipv4() { 32 } else { 128 };
        if prefix > max {
            return Err(Error::config(format!("prefix /{prefix} exceeds /{max}")));
        }
        Ok(IpNet { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(addr)) => {
                let p = self.prefix as u32;
                let mask = if p == 0 { 0 } else { u32::MAX << (32 - p) };
                (u32::from(net) & mask) == (u32::from(addr) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(addr)) => {
                let p = self.prefix as u32;
                let mask128 = if p == 0 {
                    u128::MIN
                } else {
                    u128::MAX << (128 - p)
                };
                (u128::from(net) & mask128) == (u128::from(addr) & mask128)
            }
            _ => false,
        }
    }
}

impl std::fmt::Display for IpNet {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

impl FromStr for IpNet {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        let (addr, prefix) = s
            .split_once('/')
            .ok_or_else(|| Error::config(format!("CIDR {s:?} missing prefix")))?;
        let addr: IpAddr = addr
            .parse()
            .map_err(|_| Error::config(format!("bad CIDR address {addr:?}")))?;
        let prefix = prefix
            .parse()
            .map_err(|_| Error::config(format!("bad CIDR prefix {prefix:?}")))?;
        IpNet::new(addr, prefix)
    }
}

/// Port matcher: single port or `start-end`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRange {
    pub start: u16,
    pub end: u16,
}

impl FromStr for PortRange {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if let Some((a, b)) = s.split_once('-') {
            Ok(PortRange {
                start: a
                    .parse()
                    .map_err(|_| Error::config(format!("bad port {a:?}")))?,
                end: b
                    .parse()
                    .map_err(|_| Error::config(format!("bad port {b:?}")))?,
            })
        } else {
            let p: u16 = s
                .parse()
                .map_err(|_| Error::config(format!("bad port {s:?}")))?;
            Ok(PortRange { start: p, end: p })
        }
    }
}

/// UID matcher: single uid or `start-end` (u32 — PortRange's u16 is
/// too small for uid values).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct U32Range {
    pub start: u32,
    pub end: u32,
}

impl U32Range {
    pub fn contains(&self, v: u32) -> bool {
        (self.start..=self.end).contains(&v)
    }
}

impl FromStr for U32Range {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self> {
        if let Some((a, b)) = s.split_once('-') {
            Ok(U32Range {
                start: a
                    .parse()
                    .map_err(|_| Error::config(format!("bad uid {a:?}")))?,
                end: b
                    .parse()
                    .map_err(|_| Error::config(format!("bad uid {b:?}")))?,
            })
        } else {
            let v: u32 = s
                .parse()
                .map_err(|_| Error::config(format!("bad uid {s:?}")))?;
            Ok(U32Range { start: v, end: v })
        }
    }
}

/// What a connection carries for rule evaluation.
pub struct ConnContext<'a> {
    pub host: &'a Host,
    pub port: u16,
    /// Source IP when known (transparent inbounds), else None.
    pub source_ip: Option<IpAddr>,
    pub source_port: Option<u16>,
    /// Resolved destination IPs (filled lazily by the router).
    pub resolved: Option<Vec<IpAddr>>,
    /// The engine's current mode (CLASH-MODE rules match against it).
    pub mode: crate::config::RuleMode,
    /// `tcp` or `udp` (NETWORK rules).
    pub network: Network,
    /// The inbound listener tag (IN-PORT/IN-NAME rules).
    pub inbound: &'a str,
    /// The inbound listener kind (`mixed`/`socks`/`http`/`redir`/
    /// `tproxy`/`tun`) — the listener's type, not its tag (IN-TYPE).
    pub inbound_kind: &'a str,
    /// Local port of the inbound listener (IN-PORT).
    pub inbound_port: Option<u16>,
    /// Process name/path for locally-originated connections (PROCESS
    /// rules, Linux /proc).
    pub process: Option<&'a str>,
    /// Owner uid of the client process (UID rules).
    pub uid: Option<u32>,
    /// Owner username of the client process (IN-USER rules).
    pub user: Option<&'a str>,
    /// IPv4 DSCP field, when the inbound carries it. Only meaningful
    /// on TUN inbounds upstream; always None from the current
    /// inbounds (DSCP rules never match until one provides it).
    pub dscp: Option<u8>,
}

/// Connection network type (NETWORK rule values).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Network {
    #[default]
    Tcp,
    Udp,
}

impl Network {
    pub fn as_str(self) -> &'static str {
        match self {
            Network::Tcp => "tcp",
            Network::Udp => "udp",
        }
    }
}

impl ConnContext<'_> {
    fn ips(&self) -> Vec<IpAddr> {
        match (self.host, &self.resolved) {
            (Host::Ip(ip), _) => vec![*ip],
            (_, Some(list)) => list.clone(),
            (_, None) => Vec::new(),
        }
    }
}

/// One parsed rule.
#[derive(Debug, Clone)]
pub enum RuleMatcher {
    Domain(String),
    DomainSuffix(String),
    DomainKeyword(String),
    DomainRegex(Box<regex::Regex>),
    IpCidr { net: IpNet, src: bool, no_resolve: bool },
    GeoIp { country: String, no_resolve: bool },
    Geosite { name: String },
    PortDst(PortRange),
    PortSrc(PortRange),
    RuleSet { name: String, no_resolve: bool },
    /// Matches only while the engine runs in the given mode
    /// (`rule`/`global`/`direct`) — sing-box's `clash_mode`.
    ClashMode(String),
    /// NETWORK,tcp|udp
    Network(Network),
    /// IN-PORT,<port or range> — the inbound listener's local port.
    InPort(PortRange),
    /// IN-NAME,<tag> — the inbound listener tag.
    InName(String),
    /// IN-TYPE,<kind[/kind...]> — the inbound listener kind
    /// (`mixed`/`socks`/`http`/`redir`/`tproxy`/`tun`), compared
    /// case-insensitively; `/`-separated lists like upstream mihomo.
    InType(String),
    /// UID,<uid or start-end> — owner uid of the client process.
    Uid(U32Range),
    /// IN-USER,<name[/name...]> — owner username of the client
    /// process, exact match per upstream mihomo.
    InUser(String),
    /// DSCP,<0-63> — IPv4 DSCP field; only TUN inbounds carry it.
    Dscp(u8),
    /// IP-ASN,<as-number> — destination ASN from the ASN mmdb;
    /// needs destination resolution like GEOIP unless `no-resolve`.
    IpAsn { asn: u32, no_resolve: bool },
    /// IP-SUFFIX,<dotted tail like `8.8`> — matches when the suffix
    /// equals the tail segments of any destination IP (v4: last
    /// octets, v6: last hextets, hex case-insensitive).
    IpSuffix { suffix: String, no_resolve: bool },
    /// PROCESS-NAME / PROCESS-PATH — matched against the resolved process.
    Process { pattern: String, path: bool },
    /// AND,(<sub-rules>) / OR,(<sub-rules>) logic rules. Sub-rules are
    /// the same clash-style rule strings, joined with `&&` inside the
    /// parentheses to stay comma-free.
    Logic { mode: LogicMode, sub: Vec<Rule> },
    MatchAll,
}

/// Logic rule combinators (mihomo AND/OR/NOT).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogicMode {
    And,
    Or,
    Not,
}

/// A rule with its outbound target.
#[derive(Debug, Clone)]
pub struct Rule {
    pub matcher: RuleMatcher,
    pub outbound: String,
}

impl Rule {
    /// Parse `TYPE,payload,outbound[,no-resolve]` (Clash syntax), plus
    /// the logic forms `AND/OR/NOT,((sub),(sub)),outbound`.
    pub fn parse(line: &str) -> Result<Self> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return Err(Error::config("empty rule"));
        }
        let head = line.split(',').next().unwrap_or_default();
        if matches!(head.to_ascii_uppercase().as_str(), "AND" | "OR" | "NOT") {
            return Self::parse_logic(line);
        }
        let parts: Vec<&str> = line.split(',').map(str::trim).collect();
        if parts.len() < 2 {
            return Err(Error::config(format!("malformed rule {line:?}")));
        }
        let no_resolve = parts.last() == Some(&"no-resolve");
        let needed = if no_resolve { parts.len() - 1 } else { parts.len() };
        let kind = parts[0].to_ascii_uppercase();
        let (matcher, outbound) = match (kind.as_str(), needed) {
            ("DOMAIN", 3) => (
                RuleMatcher::Domain(parts[1].to_ascii_lowercase()),
                parts[2].to_string(),
            ),
            ("DOMAIN-SUFFIX", 3) => (
                RuleMatcher::DomainSuffix(parts[1].trim_start_matches('.').to_ascii_lowercase()),
                parts[2].to_string(),
            ),
            ("DOMAIN-KEYWORD", 3) => (
                RuleMatcher::DomainKeyword(parts[1].to_ascii_lowercase()),
                parts[2].to_string(),
            ),
            ("DOMAIN-REGEX", 3) => (
                RuleMatcher::DomainRegex(Box::new(regex::Regex::new(parts[1]).map_err(
                    |e| Error::config(format!("bad rule regex {:?}: {e}", parts[1])),
                )?)),
                parts[2].to_string(),
            ),
            ("DOMAIN-WILDCARD", 3) => (
                // mihomo wildcard: `*` matches any run, `+.` = subdomain
                // OR apex; anchored like a full domain match.
                RuleMatcher::DomainRegex(Box::new(
                    regex::Regex::new(&wildcard_to_regex(parts[1])).map_err(|e| {
                        Error::config(format!("bad domain wildcard {:?}: {e}", parts[1]))
                    })?,
                )),
                parts[2].to_string(),
            ),
            ("IP-CIDR" | "IP-CIDR6", 3) => (
                RuleMatcher::IpCidr {
                    net: parts[1].parse()?,
                    src: false,
                    no_resolve,
                },
                parts[2].to_string(),
            ),
            ("SRC-IP-CIDR", 3) => (
                RuleMatcher::IpCidr {
                    net: parts[1].parse()?,
                    src: true,
                    no_resolve: false,
                },
                parts[2].to_string(),
            ),
            ("SRC-PORT", 3) => (
                RuleMatcher::PortSrc(parts[1].parse()?),
                parts[2].to_string(),
            ),
            ("DST-PORT", 3) => (
                RuleMatcher::PortDst(parts[1].parse()?),
                parts[2].to_string(),
            ),
            ("GEOIP", 3) => (
                RuleMatcher::GeoIp {
                    country: parts[1].to_ascii_uppercase(),
                    no_resolve,
                },
                parts[2].to_string(),
            ),
            ("GEOSITE", 3) => (
                RuleMatcher::Geosite {
                    name: parts[1].to_ascii_lowercase(),
                },
                parts[2].to_string(),
            ),
            ("RULE-SET", 3) => (
                RuleMatcher::RuleSet {
                    name: parts[1].to_string(),
                    no_resolve,
                },
                parts[2].to_string(),
            ),
            ("CLASH-MODE", 3) => (
                RuleMatcher::ClashMode(parts[1].to_ascii_lowercase()),
                parts[2].to_string(),
            ),
            ("NETWORK", 3) => (
                RuleMatcher::Network(match parts[1] {
                    "tcp" => Network::Tcp,
                    "udp" => Network::Udp,
                    other => {
                        return Err(Error::config(format!(
                            "NETWORK rule must be tcp or udp, got {other:?}"
                        )))
                    }
                }),
                parts[2].to_string(),
            ),
            ("IN-PORT", 3) => (RuleMatcher::InPort(parts[1].parse()?), parts[2].to_string()),
            ("IN-NAME", 3) => (
                RuleMatcher::InName(parts[1].to_string()),
                parts[2].to_string(),
            ),
            ("IN-TYPE", 3) => (
                RuleMatcher::InType(parse_in_list(parts[1], true)?),
                parts[2].to_string(),
            ),
            ("UID", 3) => (RuleMatcher::Uid(parts[1].parse()?), parts[2].to_string()),
            ("IN-USER", 3) => (
                RuleMatcher::InUser(parse_in_list(parts[1], false)?),
                parts[2].to_string(),
            ),
            ("DSCP", 3) => {
                // Upstream rejects DSCP values above the 6-bit field.
                let dscp: u8 = parts[1]
                    .parse()
                    .map_err(|_| Error::config(format!("bad DSCP value {:?}", parts[1])))?;
                if dscp > 63 {
                    return Err(Error::config(format!(
                        "DSCP must be 0-63, got {dscp}"
                    )));
                }
                (RuleMatcher::Dscp(dscp), parts[2].to_string())
            }
            ("IP-ASN", 3) => (
                RuleMatcher::IpAsn {
                    asn: parts[1]
                        .parse()
                        .map_err(|_| Error::config(format!("bad ASN {:?}", parts[1])))?,
                    no_resolve,
                },
                parts[2].to_string(),
            ),
            ("IP-SUFFIX", 3) => (
                RuleMatcher::IpSuffix {
                    suffix: parse_ip_suffix(parts[1])?,
                    no_resolve,
                },
                parts[2].to_string(),
            ),
            ("PROCESS-NAME", 3) => (
                RuleMatcher::Process { pattern: parts[1].to_string(), path: false },
                parts[2].to_string(),
            ),
            ("PROCESS-PATH", 3) => (
                RuleMatcher::Process { pattern: parts[1].to_string(), path: true },
                parts[2].to_string(),
            ),
            ("MATCH", 2) => (RuleMatcher::MatchAll, parts[1].to_string()),
            _ => {
                return Err(Error::config(format!(
                    "unsupported rule {line:?} (supported: DOMAIN, DOMAIN-SUFFIX, \
                     DOMAIN-KEYWORD, DOMAIN-REGEX, IP-CIDR, IP-CIDR6, SRC-IP-CIDR, \
                     DST-PORT, SRC-PORT, GEOIP, GEOSITE, RULE-SET, CLASH-MODE, MATCH, \
                     AND/OR/NOT, NETWORK, IN-PORT, IN-NAME, IN-TYPE, UID, IN-USER, \
                     DSCP, IP-ASN, IP-SUFFIX, PROCESS-NAME/PATH)"
                )))
            }
        };
        Ok(Rule { matcher, outbound })
    }

    /// `AND/OR/NOT,((sub),(sub)[...]),outbound` — sub-rules combine per
    /// the outer mode, so commas and `&&`/`||` are equally accepted as
    /// separators. Nested logic sub-rules recurse.
    fn parse_logic(line: &str) -> Result<Self> {
        let (kind, rest) = line
            .split_once(',')
            .ok_or_else(|| Error::config(format!("malformed logic rule {line:?}")))?;
        let mode = match kind.trim().to_ascii_uppercase().as_str() {
            "AND" => LogicMode::And,
            "OR" => LogicMode::Or,
            _ => LogicMode::Not,
        };
        let rest = rest.trim();
        if !rest.starts_with('(') {
            return Err(Error::config(format!(
                "logic rule payload must be parenthesized: {line:?}"
            )));
        }
        // The payload is the first balanced paren group.
        let mut depth = 0usize;
        let mut end = None;
        for (i, ch) in rest.char_indices() {
            match ch {
                '(' => depth += 1,
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        end = Some(i);
                        break;
                    }
                }
                _ => {}
            }
        }
        let Some(end) = end else {
            return Err(Error::config(format!("unbalanced parens in {line:?}")));
        };
        let payload = rest[1..end].trim();
        let outbound = rest[end + 1..].trim().trim_start_matches(',').trim();
        if payload.is_empty() {
            return Err(Error::config(format!("logic rule has no sub-rules: {line:?}")));
        }
        // Missing outbound (nested form) gets a stub the config
        // validator will reject if it ever leaks to the top level.
        let outbound = if outbound.is_empty() { "-" } else { outbound };
        let sub = split_sub_rules(payload)
            .into_iter()
            .map(|s| parse_sub_rule(&s))
            .collect::<Result<Vec<_>>>()?;
        if sub.is_empty() {
            return Err(Error::config(format!("logic rule has no sub-rules: {line:?}")));
        }
        // mihomo's NOT takes exactly one sub-rule — refuse the rest
        // rather than silently using the first.
        if mode == LogicMode::Not && sub.len() > 1 {
            return Err(Error::config(format!(
                "NOT rule takes exactly one sub-rule: {line:?}"
            )));
        }
        Ok(Rule {
            matcher: RuleMatcher::Logic { mode, sub },
            outbound: outbound.to_string(),
        })
    }

    /// Evaluate one rule. Fully synchronous: the router pre-resolves
    /// destination IPs once (see [`Rule::needs_ip`]), so logic sub-rules
    /// and classical set entries recurse plainly through this method —
    /// one evaluator, no async-future type recursion.
    pub fn evaluate(&self, ctx: &ConnContext<'_>, providers: &RuleSets, geo: &GeoLookups) -> bool {
        match &self.matcher {
            RuleMatcher::Domain(d) => ctx.host.as_domain() == Some(d.as_str()),
            RuleMatcher::DomainSuffix(suffix) => ctx
                .host
                .as_domain()
                .is_some_and(|d| domain_matches_suffix(d, suffix)),
            RuleMatcher::DomainKeyword(kw) => ctx
                .host
                .as_domain()
                .is_some_and(|d| d.contains(kw.as_str())),
            RuleMatcher::DomainRegex(re) => ctx
                .host
                .as_domain()
                .is_some_and(|d| re.is_match(d)),
            RuleMatcher::IpCidr { net, src, .. } => {
                if *src {
                    ctx.source_ip.is_some_and(|ip| net.contains(ip))
                } else {
                    ctx.ips().iter().any(|ip| net.contains(*ip))
                }
            }
            RuleMatcher::GeoIp { country, .. } => ctx
                .ips()
                .iter()
                .any(|ip| geo.country(*ip).as_deref() == Some(country.as_str())),
            RuleMatcher::Geosite { name } => ctx
                .host
                .as_domain()
                .is_some_and(|d| geo.geosite_matches(name, d)),
            RuleMatcher::PortDst(range) => (range.start..=range.end).contains(&ctx.port),
            RuleMatcher::PortSrc(range) => ctx
                .source_port
                .is_some_and(|p| (range.start..=range.end).contains(&p)),
            RuleMatcher::RuleSet { name, .. } => match providers.get(name) {
                None => false,
                Some(RuleSetKind::Domain(m)) => {
                    ctx.host.as_domain().is_some_and(|d| m.matches(d))
                }
                Some(RuleSetKind::IpCidr(nets)) => ctx
                    .ips()
                    .iter()
                    .any(|ip| nets.iter().any(|n| n.contains(*ip))),
                Some(RuleSetKind::Classical(rules)) => {
                    rules.iter().any(|r| r.evaluate(ctx, providers, geo))
                }
            },
            RuleMatcher::ClashMode(mode) => ctx.mode.as_str() == mode,
            RuleMatcher::Network(n) => ctx.network == *n,
            RuleMatcher::InPort(range) => ctx
                .inbound_port
                .is_some_and(|p| (range.start..=range.end).contains(&p)),
            RuleMatcher::InName(name) => ctx.inbound == name,
            RuleMatcher::InType(kinds) => kinds
                .split('/')
                .any(|k| ctx.inbound_kind.eq_ignore_ascii_case(k)),
            RuleMatcher::Uid(range) => ctx.uid.is_some_and(|u| range.contains(u)),
            RuleMatcher::InUser(users) => ctx
                .user
                .is_some_and(|u| users.split('/').any(|w| w == u)),
            RuleMatcher::Dscp(dscp) => ctx.dscp == Some(*dscp),
            RuleMatcher::IpAsn { asn, .. } => {
                ctx.ips().iter().any(|ip| geo.asn(*ip) == Some(*asn))
            }
            RuleMatcher::IpSuffix { suffix, .. } => {
                ctx.ips().iter().any(|ip| ip_matches_suffix(*ip, suffix))
            }
            RuleMatcher::Process { pattern, path: is_path } => ctx.process.is_some_and(|p| {
                if *is_path {
                    // mihomo matches PROCESS-PATH exactly.
                    p == pattern
                } else {
                    p.rsplit('/').next() == Some(pattern)
                }
            }),
            RuleMatcher::Logic { mode, sub } => match mode {
                LogicMode::And => sub.iter().all(|r| r.evaluate(ctx, providers, geo)),
                LogicMode::Or => sub.iter().any(|r| r.evaluate(ctx, providers, geo)),
                LogicMode::Not => sub
                    .first()
                    .is_some_and(|r| !r.evaluate(ctx, providers, geo)),
            },
            RuleMatcher::MatchAll => true,
        }
    }

    /// Whether matching this rule may require destination IPs obtained
    /// via DNS (drives the router's single pre-resolve). Rules carrying
    /// `no-resolve` never trigger resolution.
    pub fn needs_ip(&self) -> bool {
        matcher_needs_ip(&self.matcher)
    }
}

fn matcher_needs_ip(m: &RuleMatcher) -> bool {
    match m {
        RuleMatcher::IpCidr { src, no_resolve, .. } => !*src && !*no_resolve,
        RuleMatcher::GeoIp { no_resolve, .. } => !*no_resolve,
        RuleMatcher::IpAsn { no_resolve, .. } => !*no_resolve,
        RuleMatcher::IpSuffix { no_resolve, .. } => !*no_resolve,
        // The set contents load later; assume IP rules may appear.
        RuleMatcher::RuleSet { no_resolve, .. } => !*no_resolve,
        RuleMatcher::Logic { sub, .. } => sub.iter().any(|r| matcher_needs_ip(&r.matcher)),
        _ => false,
    }
}

/// `domain == suffix` or domain sits directly under `suffix`
/// (`a.b.com` matches `b.com`; `ab.com` does not).
pub(crate) fn domain_matches_suffix(domain: &str, suffix: &str) -> bool {
    domain == suffix || domain.ends_with(&format!(".{suffix}"))
}

/// Validate an IN-TYPE / IN-USER `/`-separated list payload (upstream
/// mihomo parses both as lists): entries are trimmed, IN-TYPE entries
/// lowercased (kinds compare case-insensitively), empty entries
/// rejected. Returns the re-joined payload.
fn parse_in_list(payload: &str, lowercase: bool) -> Result<String> {
    let mut entries = Vec::new();
    for entry in payload.split('/') {
        let e = entry.trim();
        if e.is_empty() {
            return Err(Error::config(format!(
                "rule payload {payload:?} has an empty entry"
            )));
        }
        entries.push(if lowercase {
            e.to_ascii_lowercase()
        } else {
            e.to_string()
        });
    }
    Ok(entries.join("/"))
}

/// Validate and normalize an IP-SUFFIX payload: trimmed, lowercased,
/// dotted segments; empty segments and more than 8 segments (an IPv6
/// address's full width) are rejected.
fn parse_ip_suffix(payload: &str) -> Result<String> {
    let segments: Vec<String> = payload
        .split('.')
        .map(|s| s.trim().to_ascii_lowercase())
        .collect();
    if segments.iter().any(|s| s.is_empty()) || segments.len() > 8 {
        return Err(Error::config(format!("bad IP-SUFFIX {payload:?}")));
    }
    Ok(segments.join("."))
}

/// IP-SUFFIX match: the dotted `suffix` equals the tail of the IP's
/// segments — v4 has 4 decimal octets, v6 8 lowercase hex hextets
/// (so hex compares case-insensitively). A short numeric suffix may
/// match either family; the segment counts never mix.
fn ip_matches_suffix(ip: IpAddr, suffix: &str) -> bool {
    let segments: Vec<String> = match ip {
        IpAddr::V4(v4) => v4.octets().iter().map(u8::to_string).collect(),
        IpAddr::V6(v6) => v6.segments().iter().map(|s| format!("{s:x}")).collect(),
    };
    let suffix_segments: Vec<&str> = suffix.split('.').collect();
    if suffix_segments.is_empty() || suffix_segments.len() > segments.len() {
        return false;
    }
    let tail = &segments[segments.len() - suffix_segments.len()..];
    tail.iter().zip(&suffix_segments).all(|(seg, s)| seg == s)
}


/// Loaded rule-provider sets.
#[derive(Default)]
pub struct RuleSets {
    sets: std::collections::HashMap<String, RuleSetKind>,
}

pub enum RuleSetKind {
    Domain(DomainMatcher),
    IpCidr(Vec<IpNet>),
    Classical(Vec<Rule>),
}

impl RuleSets {
    pub fn insert(&mut self, name: impl Into<String>, kind: RuleSetKind) {
        self.sets.insert(name.into(), kind);
    }

    pub fn get(&self, name: &str) -> Option<&RuleSetKind> {
        self.sets.get(name)
    }

}

/// Domain set with exact/suffix/keyword/regex parts.
#[derive(Debug, Default, Clone)]
pub struct DomainMatcher {
    exact: std::collections::HashSet<String>,
    suffix: Vec<String>,
    keyword: Vec<String>,
    regex: Vec<regex::Regex>,
}

impl DomainMatcher {
    pub fn add_domain_line(&mut self, line: &str) {
        let line = line.trim().to_ascii_lowercase();
        if line.is_empty() || line.starts_with('#') {
            return;
        }
        if let Some(rest) = line.strip_prefix("+.") {
            self.suffix.push(rest.to_string());
        } else if let Some(rest) = line.strip_prefix('.') {
            self.suffix.push(rest.to_string());
        } else if line.contains('*') {
            // Wildcard form: "*.example.com" → keyword between dots.
            if let Some(kw) = line.strip_prefix("*.") {
                self.suffix.push(kw.to_string());
            }
        } else {
            self.exact.insert(line);
        }
    }

    pub fn add_exact(&mut self, domain: &str) {
        self.exact.insert(domain.trim().to_ascii_lowercase());
    }

    pub fn add_suffix(&mut self, suffix: &str) {
        self.suffix.push(suffix.trim().trim_start_matches('.').to_ascii_lowercase());
    }

    pub fn add_keyword(&mut self, kw: &str) {
        self.keyword.push(kw.to_ascii_lowercase());
    }

    pub fn add_regex(&mut self, pattern: &str) -> Result<()> {
        self.regex.push(regex::Regex::new(pattern).map_err(|e| {
            Error::config(format!("bad domain-set regex {pattern:?}: {e}"))
        })?);
        Ok(())
    }

    pub fn matches(&self, domain: &str) -> bool {
        let d = domain.to_ascii_lowercase();
        if self.exact.contains(&d) {
            return true;
        }
        if self.suffix.iter().any(|s| d == *s || d.ends_with(&format!(".{s}"))) {
            return true;
        }
        if self.keyword.iter().any(|k| d.contains(k.as_str())) {
            return true;
        }
        self.regex.iter().any(|r| r.is_match(&d))
    }

}

/// GeoIP country lookup (mmdb) and geosite .dat matcher, wired in by the
/// engine when the databases exist.
#[derive(Default)]
pub struct GeoLookups {
    pub geoip: Option<maxminddb::Reader<Vec<u8>>>,
    /// ASN database (GeoLite2-ASN style mmdb) for IP-ASN rules; a
    /// separate reader from `geoip`, wired in by the engine when the
    /// configured file exists.
    pub asn_mmdb: Option<maxminddb::Reader<Vec<u8>>>,
    pub geosite: std::collections::HashMap<String, DomainMatcher>,
}



impl GeoLookups {
    /// ISO country code for an IP from the MaxMind database.
    pub fn country(&self, ip: IpAddr) -> Option<String> {
        let reader = self.geoip.as_ref()?;
        let val: serde_json::Value = reader.lookup(ip).ok()?;
        val["country"]["iso_code"]
            .as_str()
            .or_else(|| val["registered_country"]["iso_code"].as_str())
            .map(str::to_string)
    }

    /// Autonomous system number for an IP: a dedicated ASN mmdb when
    /// present, else the geoip metadb (mihomo reads both from one file);
    /// None when nothing is loaded or the IP has no entry.
    pub fn asn(&self, ip: IpAddr) -> Option<u32> {
        let reader = self.asn_mmdb.as_ref().or(self.geoip.as_ref())?;
        let val: serde_json::Value = reader.lookup(ip).ok()?;
        val["autonomous_system_number"]
            .as_u64()
            .and_then(|n| u32::try_from(n).ok())
    }

    /// GEOSITE match from the loaded .dat entries.
    pub fn geosite_matches(&self, name: &str, domain: &str) -> bool {
        self.geosite
            .get(name)
            .map(|m| m.matches(domain))
            .unwrap_or(false)
    }
}

/// Translate a mihomo DOMAIN-WILDCARD pattern to an anchored regex:
/// `*` matches any run, `?` exactly one character.
fn wildcard_to_regex(pattern: &str) -> String {
    let mut out = String::with_capacity(pattern.len() * 2 + 2);
    out.push('^');
    for ch in pattern.to_ascii_lowercase().chars() {
        match ch {
            '*' => out.push_str(".*"),
            '?' => out.push('.'),
            c if c.is_ascii_alphanumeric() => out.push(c),
            c => {
                out.push('\\');
                out.push(c);
            }
        }
    }
    out.push('$');
    out
}

/// Split a logic payload (`(a),(b)` or `(a)&&(b)`) at depth-0
/// separators, keeping each parenthesized sub-rule whole.
fn split_sub_rules(payload: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut cur = String::new();
    for ch in payload.chars() {
        match ch {
            '(' => {
                depth += 1;
                cur.push(ch);
            }
            ')' => {
                depth -= 1;
                cur.push(ch);
            }
            ',' | '&' if depth == 0 => {
                if !cur.trim().is_empty() {
                    out.push(cur.trim().to_string());
                }
                cur.clear();
            }
            _ => cur.push(ch),
        }
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_string());
    }
    out
}

/// Parse one sub-rule: mihomo sub-rules carry no outbound (a trailing
/// `no-resolve` is allowed), so a stub target is appended; nested
/// AND/OR/NOT recurses.
fn parse_sub_rule(s: &str) -> Result<Rule> {
    // Strip exactly ONE wrapping paren pair (nested sub-rules carry more).
    let s = s.trim();
    let s = if s.starts_with('(') && s.ends_with(')') {
        &s[1..s.len() - 1]
    } else {
        s
    }
    .trim();
    if s.is_empty() {
        return Err(Error::config("empty logic sub-rule"));
    }
    let head = s.split(',').next().unwrap_or_default();
    if matches!(head.to_ascii_uppercase().as_str(), "AND" | "OR" | "NOT") {
        return Rule::parse_logic(s);
    }
    Rule::parse(&format!("{s},-"))
}

/// Whether any top-level rule needs the client process (drives the
/// eager /proc lookup in the TCP relay).
pub fn needs_process(rules: &[Rule]) -> bool {
    rules.iter().any(|r| matcher_needs_process(&r.matcher))
}

fn matcher_needs_process(m: &RuleMatcher) -> bool {
    match m {
        RuleMatcher::Process { .. } => true,
        // UID / IN-USER read the client process owner through the same
        // /proc walk.
        RuleMatcher::Uid(_) | RuleMatcher::InUser(_) => true,
        RuleMatcher::Logic { sub, .. } => sub.iter().any(|r| matcher_needs_process(&r.matcher)),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx<'a>(host: &'a Host, port: u16) -> ConnContext<'a> {
        ConnContext {
            host,
            port,
            source_ip: None,
            source_port: None,
            resolved: None,
            mode: crate::config::RuleMode::Rule,
            network: Network::Tcp,
            inbound: "mixed",
            inbound_kind: "mixed",
            inbound_port: Some(7890),
            process: None,
            uid: None,
            user: None,
            dscp: None,
        }
    }

    #[test]
    fn ipnet_contains() {
        let net: IpNet = "192.168.0.0/16".parse().unwrap();
        assert!(net.contains("192.168.10.20".parse().unwrap()));
        assert!(!net.contains("192.169.0.1".parse().unwrap()));
        let all: IpNet = "0.0.0.0/0".parse().unwrap();
        assert!(all.contains("1.2.3.4".parse().unwrap()));
        let v6: IpNet = "2001:db8::/32".parse().unwrap();
        assert!(v6.contains("2001:db8::1".parse().unwrap()));
        assert!(!v6.contains("2001:db9::1".parse().unwrap()));
        assert!(!v6.contains("1.2.3.4".parse().unwrap()));
        assert!("10.0.0.0/33".parse::<IpNet>().is_err());
        assert!("10.0.0.0".parse::<IpNet>().is_err());
    }

    #[test]
    fn rule_parse_forms() {
        let r = Rule::parse("DOMAIN-SUFFIX,Google.com,PROXY").unwrap();
        assert!(matches!(&r.matcher, RuleMatcher::DomainSuffix(s) if s == "google.com"));
        assert_eq!(r.outbound, "PROXY");

        let r = Rule::parse("IP-CIDR,10.0.0.0/8,DIRECT,no-resolve").unwrap();
        assert!(matches!(&r.matcher, RuleMatcher::IpCidr { no_resolve: true, .. }));

        let r = Rule::parse("DST-PORT,8000-8080,PROXY").unwrap();
        assert!(matches!(&r.matcher, RuleMatcher::PortDst(PortRange { start: 8000, end: 8080 })));

        let r = Rule::parse("MATCH,Auto").unwrap();
        assert!(matches!(r.matcher, RuleMatcher::MatchAll));

        let r = Rule::parse("PROCESS-NAME,curl,DIRECT").unwrap();
        assert!(matches!(&r.matcher, RuleMatcher::Process { pattern, path: false } if pattern == "curl"));
        let r = Rule::parse("PROCESS-PATH,/usr/bin/curl,DIRECT").unwrap();
        assert!(matches!(&r.matcher, RuleMatcher::Process { path: true, .. }));

        assert!(Rule::parse("SUB-RULE,(A,B),X").is_err());
        assert!(Rule::parse("").is_err());
    }

    #[test]
    fn evaluate_logic_and_metadata_rules() {
        let host = Host::Domain("www.google.com".into());
        let mut c = ctx(&host, 443);
        c.network = Network::Tcp;
        c.inbound = "mixed";
        c.inbound_port = Some(7890);
        c.process = Some("/usr/bin/curl");
        let sets = RuleSets::default();
        let geo = GeoLookups::default();

        // AND — mihomo comma form and && form both parse.
        let and = Rule::parse("AND,((DOMAIN-SUFFIX,google.com),(DST-PORT,443)),P").unwrap();
        assert!(and.evaluate(&c, &sets, &geo));
        let and2 = Rule::parse("AND,((DOMAIN-SUFFIX,google.com)&&(DST-PORT,443)),P").unwrap();
        assert!(and2.evaluate(&c, &sets, &geo));
        let and_miss = Rule::parse("AND,((DOMAIN-SUFFIX,google.com),(DST-PORT,80)),P").unwrap();
        assert!(!and_miss.evaluate(&c, &sets, &geo));

        // OR / NOT.
        let or = Rule::parse("OR,((DOMAIN,evil.com),(NETWORK,udp)),P").unwrap();
        assert!(!or.evaluate(&c, &sets, &geo));
        c.network = Network::Udp;
        assert!(or.evaluate(&c, &sets, &geo));
        c.network = Network::Tcp;
        let not = Rule::parse("NOT,((NETWORK,udp)),P").unwrap();
        assert!(not.evaluate(&c, &sets, &geo));

        // Nested logic inside AND.
        let nested =
            Rule::parse("AND,((NETWORK,tcp),(NOT,((DST-PORT,80)))),P").unwrap();
        assert!(nested.evaluate(&c, &sets, &geo));

        // Metadata rules.
        assert!(Rule::parse("IN-NAME,mixed,P")
            .unwrap()
            .evaluate(&c, &sets, &geo));
        assert!(Rule::parse("IN-PORT,7890-8000,P")
            .unwrap()
            .evaluate(&c, &sets, &geo));
        assert!(!Rule::parse("IN-PORT,8000,P")
            .unwrap()
            .evaluate(&c, &sets, &geo));
        assert!(Rule::parse("PROCESS-NAME,curl,P")
            .unwrap()
            .evaluate(&c, &sets, &geo));
        assert!(Rule::parse("PROCESS-PATH,/usr/bin/curl,P")
            .unwrap()
            .evaluate(&c, &sets, &geo));
        assert!(Rule::parse("NETWORK,tcp,P")
            .unwrap()
            .evaluate(&c, &sets, &geo));
    }

    #[test]
    fn evaluate_domain_rules() {
        let host = Host::Domain("www.google.com".into());
        let c = ctx(&host, 443);
        let sets = RuleSets::default();
        let geo = GeoLookups::default();

        let suffix = Rule::parse("DOMAIN-SUFFIX,google.com,P").unwrap();
        assert!(suffix.evaluate(&c, &sets, &geo));

        let exact_miss = Rule::parse("DOMAIN,www.google.com,P").unwrap();
        assert!(exact_miss.evaluate(&c, &sets, &geo));

        let kw = Rule::parse("DOMAIN-KEYWORD,goog,P").unwrap();
        assert!(kw.evaluate(&c, &sets, &geo));

        let other = Rule::parse("DOMAIN-SUFFIX,example.com,P").unwrap();
        assert!(!other.evaluate(&c, &sets, &geo));

        // IP rules fall through without resolution data.
        let ip = Rule::parse("IP-CIDR,1.2.3.0/24,P").unwrap();
        assert!(!ip.evaluate(&c, &sets, &geo));
    }

    #[test]
    fn evaluate_ip_host_directly() {
        let host = Host::Ip("10.1.2.3".parse().unwrap());
        let c = ctx(&host, 80);
        let sets = RuleSets::default();
        let geo = GeoLookups::default();
        let ip = Rule::parse("IP-CIDR,10.0.0.0/8,DIRECT").unwrap();
        assert!(ip.evaluate(&c, &sets, &geo));
    }

    #[test]
    fn rule_set_domain_evaluation() {
        let mut sets = RuleSets::default();
        let mut m = DomainMatcher::default();
        m.add_domain_line("example.com");
        m.add_domain_line("+.google.com");
        sets.insert("myset", RuleSetKind::Domain(m));
        let geo = GeoLookups::default();

        let host = Host::Domain("mail.google.com".into());
        let c = ctx(&host, 443);
        let rule = Rule::parse("RULE-SET,myset,P").unwrap();
        assert!(rule.evaluate(&c, &sets, &geo));

        let host = Host::Domain("example.com".into());
        let c = ctx(&host, 443);
        assert!(rule.evaluate(&c, &sets, &geo));

        let host = Host::Domain("nope.test".into());
        let c = ctx(&host, 443);
        assert!(!rule.evaluate(&c, &sets, &geo));
    }

    #[test]
    fn domain_matcher_forms() {
        let mut m = DomainMatcher::default();
        m.add_domain_line("# comment");
        m.add_domain_line("");
        m.add_domain_line("Exact.test");
        m.add_domain_line("+.suffix.test");
        m.add_domain_line(".dotted.test");
        m.add_domain_line("*.wild.test");
        m.add_keyword("key");
        m.add_regex("^re[0-9]+\\.test$").unwrap();
        assert!(m.matches("exact.test"));
        assert!(m.matches("a.suffix.test"));
        assert!(m.matches("suffix.test"));
        assert!(m.matches("x.dotted.test"));
        assert!(m.matches("wild.test"));
        assert!(m.matches("has-key-inside.test"));
        assert!(m.matches("re123.test"));
        assert!(!m.matches("nope.test"));
        assert!(m.matches("re123.test"));
    }

    #[test]
    fn u32_range_parses_single_and_range() {
        assert_eq!(
            "1000".parse::<U32Range>().unwrap(),
            U32Range { start: 1000, end: 1000 }
        );
        assert_eq!(
            "1000-2000".parse::<U32Range>().unwrap(),
            U32Range { start: 1000, end: 2000 }
        );
        assert!(U32Range { start: 0, end: u32::MAX }.contains(u32::MAX));
        assert!(!U32Range { start: 100, end: 200 }.contains(99));
        // u32 bounds and garbage rejected.
        assert!("0-4294967296".parse::<U32Range>().is_err());
        assert!("-1".parse::<U32Range>().is_err());
        assert!("abc".parse::<U32Range>().is_err());
    }

    #[test]
    fn in_type_uid_in_user_dscp_rules() {
        let host = Host::Domain("example.com".into());
        let mut c = ctx(&host, 443);
        let sets = RuleSets::default();
        let geo = GeoLookups::default();

        // IN-TYPE: listener kind (not the tag), case-insensitive,
        // `/`-separated lists like upstream mihomo.
        let t = Rule::parse("IN-TYPE,mixed,PROXY").unwrap();
        assert!(matches!(&t.matcher, RuleMatcher::InType(s) if s == "mixed"));
        assert!(t.evaluate(&c, &sets, &geo));
        let t_list = Rule::parse("IN-TYPE,SOCKS/TUN,PROXY").unwrap();
        c.inbound_kind = "tun";
        assert!(t_list.evaluate(&c, &sets, &geo));
        assert!(!t.evaluate(&c, &sets, &geo));
        c.inbound_kind = "Mixed";
        assert!(t.evaluate(&c, &sets, &geo));
        c.inbound_kind = "mixed";

        // UID: single value and range against ctx.uid.
        let uid = Rule::parse("UID,1000,PROXY").unwrap();
        assert!(!uid.evaluate(&c, &sets, &geo)); // ctx.uid None
        c.uid = Some(1000);
        assert!(uid.evaluate(&c, &sets, &geo));
        let uid_range = Rule::parse("UID,2000-3000,PROXY").unwrap();
        assert!(!uid_range.evaluate(&c, &sets, &geo));
        c.uid = Some(2500);
        assert!(uid_range.evaluate(&c, &sets, &geo));
        c.uid = None;

        // IN-USER: exact username match (case-sensitive), list form.
        let user = Rule::parse("IN-USER,jeffrey/root,PROXY").unwrap();
        assert!(!user.evaluate(&c, &sets, &geo)); // ctx.user None
        c.user = Some("root");
        assert!(user.evaluate(&c, &sets, &geo));
        c.user = Some("Root");
        assert!(!user.evaluate(&c, &sets, &geo));
        c.user = None;

        // DSCP.
        let dscp = Rule::parse("DSCP,4,PROXY").unwrap();
        assert!(!dscp.evaluate(&c, &sets, &geo)); // ctx.dscp None
        c.dscp = Some(4);
        assert!(dscp.evaluate(&c, &sets, &geo));
        c.dscp = Some(46);
        assert!(!dscp.evaluate(&c, &sets, &geo));

        // Validation: DSCP above the 6-bit field, empty list entries,
        // bad uid payload.
        assert!(Rule::parse("DSCP,64,PROXY").is_err());
        assert!(Rule::parse("IN-TYPE,socks/,P").is_err());
        assert!(Rule::parse("IN-USER,,P").is_err());
        assert!(Rule::parse("UID,abc,PROXY").is_err());
    }

    #[test]
    fn ip_asn_rule_requires_ip_and_misses_without_db() {
        let host = Host::Domain("example.com".into());
        let c = ctx(&host, 443);
        let sets = RuleSets::default();
        let geo = GeoLookups::default();
        assert_eq!(geo.asn("1.1.1.1".parse().unwrap()), None);

        let r = Rule::parse("IP-ASN,13335,PROXY").unwrap();
        assert!(
            matches!(&r.matcher, RuleMatcher::IpAsn { asn: 13335, no_resolve: false })
        );
        assert!(r.needs_ip());
        // Without an ASN mmdb wired the rule never matches.
        assert!(!r.evaluate(&c, &sets, &geo));

        let nr = Rule::parse("IP-ASN,13335,PROXY,no-resolve").unwrap();
        assert!(matches!(&nr.matcher, RuleMatcher::IpAsn { no_resolve: true, .. }));
        assert!(!nr.needs_ip());
        assert!(Rule::parse("IP-ASN,not-a-number,P").is_err());

        // UID / IN-USER drive the eager process lookup like PROCESS.
        let with_uid = vec![
            Rule::parse("UID,1000,P").unwrap(),
            Rule::parse("IN-USER,root,P").unwrap(),
        ];
        assert!(needs_process(&with_uid));
        assert!(!needs_process(&[Rule::parse("DSCP,4,P").unwrap()]));
    }

    #[test]
    fn ip_suffix_matches_tail_segments() {
        let sets = RuleSets::default();
        let geo = GeoLookups::default();
        let ip = |s: &str| Host::Ip(s.parse().unwrap());

        let rule = Rule::parse("IP-SUFFIX,8.8,PROXY").unwrap();
        assert!(matches!(&rule.matcher, RuleMatcher::IpSuffix { suffix, no_resolve: false } if suffix == "8.8"));
        assert!(rule.needs_ip());
        // Tail octets of the destination.
        assert!(rule.evaluate(&ctx(&ip("1.2.8.8"), 53), &sets, &geo));
        assert!(rule.evaluate(&ctx(&ip("9.9.8.8"), 53), &sets, &geo));
        assert!(!rule.evaluate(&ctx(&ip("8.8.1.2"), 53), &sets, &geo));
        assert!(!rule.evaluate(&ctx(&ip("1.2.8.9"), 53), &sets, &geo));
        // Full-address suffix.
        let full = Rule::parse("IP-SUFFIX,1.2.8.8,PROXY").unwrap();
        assert!(full.evaluate(&ctx(&ip("1.2.8.8"), 53), &sets, &geo));
        assert!(!full.evaluate(&ctx(&ip("1.2.8.9"), 53), &sets, &geo));
        // Any resolved IP may satisfy it.
        let domain = Host::Domain("example.com".into());
        let mut c = ctx(&domain, 53);
        c.resolved = Some(vec!["10.0.0.1".parse().unwrap(), "10.0.8.8".parse().unwrap()]);
        assert!(rule.evaluate(&c, &sets, &geo));

        // IPv6: last hextets, hex compared case-insensitively (the
        // payload is lowercased; hextets render lowercase without
        // leading zeros).
        assert!(rule.evaluate(&ctx(&ip("2001:db8::8:8"), 53), &sets, &geo));
        assert!(!rule.evaluate(&ctx(&ip("2001:db8::1:2"), 53), &sets, &geo));
        let v6 = Rule::parse("IP-SUFFIX,AB.CD,PROXY").unwrap();
        assert!(matches!(&v6.matcher, RuleMatcher::IpSuffix { suffix, .. } if suffix == "ab.cd"));
        assert!(v6.evaluate(&ctx(&ip("2001:db8::ab:cd"), 53), &sets, &geo));
        assert!(!v6.evaluate(&ctx(&ip("2001:db8::ab:ce"), 53), &sets, &geo));
        // "05" never matches hextet 5 — no leading zeros on either side.
        assert!(!v6.evaluate(&ctx(&ip("2001:db8::5:6"), 53), &sets, &geo));
        let leading = Rule::parse("IP-SUFFIX,05.06,PROXY").unwrap();
        assert!(!leading.evaluate(&ctx(&ip("2001:db8::5:6"), 53), &sets, &geo));

        // no-resolve variant and payload validation.
        let nr = Rule::parse("IP-SUFFIX,8.8,P,no-resolve").unwrap();
        assert!(matches!(&nr.matcher, RuleMatcher::IpSuffix { no_resolve: true, .. }));
        assert!(!nr.needs_ip());
        assert!(Rule::parse("IP-SUFFIX,8..8,P").is_err());
        assert!(Rule::parse("IP-SUFFIX,.8,P").is_err());
    }
}
