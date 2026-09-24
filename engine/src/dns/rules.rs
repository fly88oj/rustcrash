//! sing-box `dns.rules`: ordered DNS routing rules — per-rule upstream
//! servers, cache bypass (`disable_cache`), answer TTL rewriting
//! (`rewrite_ttl`) and the per-rule EDNS client subnet (`client_subnet`,
//! RFC 7871).
//!
//! Matching follows sing-box's DNS matcher: rules are tried in order and
//! the **first** rule whose matcher accepts the query wins (a later
//! rule is never consulted). Within a rule every configured field must
//! accept the query — an unset field does not constrain, so a rule with
//! no matcher fields at all is a catch-all. `invert` flips the whole
//! result.
//!
//! All four domain lists (`domain`, `domain_suffix`, `domain_keyword`,
//! `domain_regex`) live in one [`DomainMatcher`], which ORs them: a name
//! hitting any configured kind is accepted by the domain half of the
//! rule. sing-box instead ANDs across field *types* — a rule with both
//! `domain_suffix` and `domain_keyword` needs both to hit — so this is
//! equivalent for the common case (one kind per rule) but is more
//! permissive for a rule that mixes kinds; a dialect that must reproduce
//! the strict upstream AND has to split such a rule. The AND across
//! *different* fields (domains vs `query_type` vs `network`) is
//! preserved.
//!
//! This module is dialect-neutral: [`RuleSpec`] is the conversion target
//! for config parsers (sing-box JSON → `RuleSpec`), servers are parsed
//! with [`crate::dns::upstream::parse_upstream`] and `client_subnet`
//! strings use the `addr/prefix` (or bare address) form of the sing-box
//! option.
//!
//! A matched rule with `server: None` means "keep the resolver's default
//! upstreams"; `disable_cache`, `rewrite_ttl` and `client_subnet` still
//! apply.

use crate::dns::edns::ClientSubnet;
use crate::dns::upstream::{parse_upstream, Upstream};
use crate::error::{Error, Result};
use crate::rule::{DomainMatcher, Network};

/// One dialect-neutral DNS rule, converted from a config dialect's rule
/// object (e.g. sing-box `dns.rules[i]`).
///
/// `domains` / `domain_suffix` / `domain_keyword` / `domain_regex` map to
/// the sing-box lists of the same names (suffixes match the apex and
/// anything under it, keywords are substrings, regexes are matched
/// against the lowercased name). `query_type` holds wire TYPE numbers
/// (1 = A, 28 = AAAA, 65 = HTTPS); an empty list means any type.
///
/// `server_urls` are upstream URLs (`udp://`, `tcp://`, `tls://`,
/// `https://`, `quic://`, `h3://` or a bare address) parsed with
/// [`parse_upstream`]; they are tried in order by the resolver.
/// `client_subnet` is `addr/prefix` — a bare address means the full host
/// (`/32` or `/128`).
#[derive(Debug, Clone, Default)]
pub struct RuleSpec {
    /// Exact domains (`domain`).
    pub domains: Vec<String>,
    /// Domain suffixes (`domain_suffix`): the apex and every subdomain.
    pub domain_suffix: Vec<String>,
    /// Substrings matched anywhere in the name (`domain_keyword`).
    pub domain_keyword: Vec<String>,
    /// Regexes matched against the lowercased name (`domain_regex`).
    pub domain_regex: Vec<String>,
    /// Wire query types this rule applies to; empty = any.
    pub query_type: Vec<u16>,
    /// Invert the match, like sing-box's rule `invert`.
    pub invert: bool,
    /// Upstream URLs for this rule; empty = the resolver's defaults.
    pub server_urls: Vec<String>,
    /// Bypass the resolver's DNS cache for queries matched by this rule.
    pub disable_cache: bool,
    /// Fixed TTL for every answer record of the response.
    pub rewrite_ttl: Option<u32>,
    /// EDNS client subnet sent upstream for this rule (`addr/prefix`).
    pub client_subnet: Option<String>,
}

/// One compiled rule: its matcher plus the per-rule response options.
#[derive(Debug, Clone, Default)]
pub struct DnsRule {
    pub matcher: DnsRuleMatcher,
    /// Parsed upstreams, in config order; `None` keeps the resolver's
    /// default list.
    pub server: Option<Vec<Upstream>>,
    /// Skip the resolver's DNS cache for queries this rule matched.
    pub disable_cache: bool,
    /// Overwrite every answer TTL with this value.
    pub rewrite_ttl: Option<u32>,
    /// Client subnet to send upstream (and, optionally, what the answer
    /// was scoped to).
    pub client_subnet: Option<ClientSubnet>,
}

/// The match half of a [`DnsRule`].
///
/// Every field is public so a dialect that needs a matcher shape
/// [`RuleSpec`] cannot express (e.g. a `network` constraint) can build one
/// directly; `Default` is a catch-all. Fields are conjunctive — a
/// configured field must accept the query — while an unset field
/// (`domains: None`, an empty `query_type` or `network`) imposes no
/// constraint. Note that `domains` ORs the four domain kinds together
/// (see the module docs).
#[derive(Debug, Default, Clone)]
pub struct DnsRuleMatcher {
    /// Domain patterns of all kinds, or `None` when the rule sets none.
    pub domains: Option<DomainMatcher>,
    /// Wire query types; empty = any.
    pub query_type: Vec<u16>,
    /// Transports the query may arrive on; empty = any. Only consulted by
    /// [`DnsRuleMatcher::matches_with_network`].
    pub network: Vec<Network>,
    /// Flip the field match (sing-box `invert`).
    pub invert: bool,
}

impl DnsRuleMatcher {
    /// Whether this matcher accepts a query, ignoring the `network`
    /// constraint (callers that know the transport should use
    /// [`DnsRuleMatcher::matches_with_network`]).
    pub fn matches(&self, name: &str, qtype: u16) -> bool {
        self.matches_with_network(name, qtype, None)
    }

    /// Whether this matcher accepts a query that arrived on `network`.
    /// `None` (transport unknown) leaves the `network` list unconsulted;
    /// otherwise a non-empty list must contain the transport.
    pub fn matches_with_network(&self, name: &str, qtype: u16, network: Option<Network>) -> bool {
        self.fields_match(name, qtype, network) != self.invert
    }

    /// The conjunctive field match, before `invert`.
    fn fields_match(&self, name: &str, qtype: u16, network: Option<Network>) -> bool {
        if let Some(domains) = &self.domains {
            if !domains.matches(name) {
                return false;
            }
        }
        if !self.query_type.is_empty() && !self.query_type.contains(&qtype) {
            return false;
        }
        if let Some(network) = network {
            if !self.network.is_empty() && !self.network.contains(&network) {
                return false;
            }
        }
        true
    }

    /// Compile the matcher half of a spec; `index` is only used to place
    /// the rule in error messages.
    fn from_spec(spec: &RuleSpec, index: usize) -> Result<Self> {
        let mut matcher = DomainMatcher::default();
        let mut has_domains = false;

        for pattern in &spec.domains {
            let pattern = pattern.trim();
            if pattern.is_empty() {
                return Err(rule_error(index, "empty domain pattern"));
            }
            // sing-box matches `domain` entries literally, so anything
            // wildcard-shaped can never hit; point at domain_suffix
            // instead of installing a dead rule.
            if pattern.contains('*') || pattern.starts_with('.') || pattern.starts_with("+.") {
                return Err(rule_error(
                    index,
                    format!(
                        "domain {pattern:?} looks like a wildcard/suffix pattern — sing-box \
                         matches `domain` literally, use domain_suffix"
                    ),
                ));
            }
            matcher.add_exact(pattern);
            has_domains = true;
        }

        for pattern in &spec.domain_suffix {
            // Tolerate the clash-style spellings `+.d` / `*.d` / `.d`
            // (the crate's DomainMatcher grammar) for the same suffix.
            let mut suffix = pattern.trim();
            for prefix in ["+.", "*."] {
                if let Some(rest) = suffix.strip_prefix(prefix) {
                    suffix = rest;
                }
            }
            let suffix = suffix.trim_start_matches('.');
            if suffix.is_empty() {
                return Err(rule_error(index, format!("empty domain_suffix {pattern:?}")));
            }
            if suffix.contains('*') {
                return Err(rule_error(
                    index,
                    format!("domain_suffix {pattern:?}: '*' is only valid as a leading \"*.\""),
                ));
            }
            matcher.add_suffix(suffix);
            has_domains = true;
        }

        for keyword in &spec.domain_keyword {
            let keyword = keyword.trim();
            if keyword.is_empty() {
                return Err(rule_error(index, "empty domain_keyword"));
            }
            matcher.add_keyword(keyword);
            has_domains = true;
        }

        for pattern in &spec.domain_regex {
            let pattern = pattern.trim();
            if pattern.is_empty() {
                return Err(rule_error(index, "empty domain_regex"));
            }
            if let Err(err) = matcher.add_regex(pattern) {
                // add_regex reports a config error already; keep its
                // message but add the rule index.
                let msg = match err {
                    Error::Config(msg) => msg,
                    other => other.to_string(),
                };
                return Err(rule_error(index, msg));
            }
            has_domains = true;
        }

        Ok(Self {
            domains: has_domains.then_some(matcher),
            query_type: spec.query_type.clone(),
            network: Vec::new(),
            invert: spec.invert,
        })
    }
}

/// Ordered DNS rules; [`DnsRules::match_rule`] returns the first match,
/// like sing-box's rule walk.
#[derive(Debug, Default, Clone)]
pub struct DnsRules {
    rules: Vec<DnsRule>,
}

impl DnsRules {
    /// Parse rule specs in config order.
    ///
    /// Every spec must do something: a rule with no matcher field and no
    /// response option would swallow every later rule while changing
    /// nothing, so it is rejected (sing-box rejects such rules as
    /// invalid too). Bad patterns, unparseable server URLs, malformed
    /// client subnets and bad regexes are config errors naming the rule
    /// index.
    pub fn parse(specs: &[RuleSpec]) -> Result<Self> {
        let mut rules = Vec::with_capacity(specs.len());
        for (index, spec) in specs.iter().enumerate() {
            let matcher = DnsRuleMatcher::from_spec(spec, index)?;
            let configured = matcher.domains.is_some()
                || !spec.query_type.is_empty()
                || !spec.server_urls.is_empty()
                || spec.disable_cache
                || spec.rewrite_ttl.is_some()
                || spec.client_subnet.is_some();
            if !configured {
                return Err(rule_error(
                    index,
                    "rule has no matcher fields and no options — it would match every query \
                     and change nothing; remove it",
                ));
            }

            let server = if spec.server_urls.is_empty() {
                None
            } else {
                let mut upstreams = Vec::with_capacity(spec.server_urls.len());
                for url in &spec.server_urls {
                    let url = url.trim();
                    if url.is_empty() {
                        return Err(rule_error(index, "empty server URL"));
                    }
                    match parse_upstream(url) {
                        Some(upstream) => upstreams.push(upstream),
                        None => {
                            return Err(rule_error(
                                index,
                                format!(
                                    "unsupported server {url:?} (udp://, tcp://, tls://, \
                                     https://, quic://, h3://)"
                                ),
                            ))
                        }
                    }
                }
                Some(upstreams)
            };

            let client_subnet = match spec.client_subnet.as_deref() {
                Some(raw) => Some(parse_client_subnet(raw).map_err(|msg| rule_error(index, msg))?),
                None => None,
            };

            rules.push(DnsRule {
                matcher,
                server,
                disable_cache: spec.disable_cache,
                rewrite_ttl: spec.rewrite_ttl,
                client_subnet,
            });
        }
        Ok(Self { rules })
    }

    /// The first rule accepting `(name, qtype)`, or `None` when no rule
    /// applies — the resolver then uses its default upstreams. The
    /// `network` constraint of the matcher is not consulted; use
    /// [`DnsRules::match_rule_with_network`] when the transport the query
    /// arrived on is known.
    pub fn match_rule(&self, name: &str, qtype: u16) -> Option<&DnsRule> {
        self.rules
            .iter()
            .find(|rule| rule.matcher.matches(name, qtype))
    }

    /// Like [`DnsRules::match_rule`] but also honors each matcher's
    /// `network` list.
    pub fn match_rule_with_network(
        &self,
        name: &str,
        qtype: u16,
        network: Network,
    ) -> Option<&DnsRule> {
        self.rules
            .iter()
            .find(|rule| rule.matcher.matches_with_network(name, qtype, Some(network)))
    }

    /// The parsed rules, in config order.
    pub fn rules(&self) -> &[DnsRule] {
        &self.rules
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }
}

/// Overwrite the TTL of every answer record (ANCOUNT) in a raw DNS
/// response with `ttl`, in place.
///
/// The walker is wire-level: DNS header, question section, then each
/// answer's owner name (labels, or a compression pointer — the two
/// pointer bytes are skipped, never followed), TYPE, CLASS, TTL,
/// RDLENGTH and rdata. Bounds are checked at every step. Authority,
/// additional and OPT records are left alone (an OPT RR's "TTL" field
/// holds EDNS flags, not a lifetime), as is rdata.
///
/// Apply this to the response **before** inserting it into the cache:
/// sing-box folds `rewrite_ttl` into the response and then caches the
/// rewritten message, deriving the cache lifetime from the rewritten
/// value, so the served copy and the cache expiry stay consistent. A
/// response with no answers (NXDOMAIN, empty NOERROR) is unchanged and
/// returns `Ok`.
pub fn rewrite_ttl(resp: &mut [u8], ttl: u32) -> Result<()> {
    if resp.len() < 12 {
        return Err(Error::dns("message shorter than header"));
    }
    let qdcount = u16::from_be_bytes([resp[4], resp[5]]) as usize;
    let ancount = u16::from_be_bytes([resp[6], resp[7]]) as usize;

    let mut off = 12usize;
    for _ in 0..qdcount {
        off = skip_name(resp, off)?;
        if resp.len() < off + 4 {
            return Err(Error::dns("truncated question"));
        }
        off += 4;
    }

    for _ in 0..ancount {
        off = skip_name(resp, off)?;
        // TYPE(2) CLASS(2) TTL(4) RDLENGTH(2).
        if resp.len() < off + 10 {
            return Err(Error::dns("truncated record"));
        }
        resp[off + 4..off + 8].copy_from_slice(&ttl.to_be_bytes());
        let rdlength = u16::from_be_bytes([resp[off + 8], resp[off + 9]]) as usize;
        off += 10;
        if resp.len() < off + rdlength {
            return Err(Error::dns("truncated rdata"));
        }
        off += rdlength;
    }
    Ok(())
}

/// Step past one (possibly compressed) domain name and return the offset
/// just after it. A compression pointer ends the name; its two bytes are
/// consumed and the target is not followed, since only the length
/// matters here.
fn skip_name(msg: &[u8], mut off: usize) -> Result<usize> {
    loop {
        let Some(&len) = msg.get(off) else {
            return Err(Error::dns("name runs past end"));
        };
        match len & 0xC0 {
            0x00 => {
                off += 1;
                if len == 0 {
                    return Ok(off);
                }
                let len = len as usize;
                if msg.len() < off + len {
                    return Err(Error::dns("label runs past end"));
                }
                off += len;
            }
            0xC0 => {
                if msg.len() < off + 2 {
                    return Err(Error::dns("truncated pointer"));
                }
                return Ok(off + 2);
            }
            _ => return Err(Error::dns("reserved label type")),
        }
    }
}

/// Parse a `client_subnet` value: `addr/prefix` or a bare address
/// (treated as the full host, `/32` for IPv4 and `/128` for IPv6 — the
/// same grammar as the sing-box option). The error string is the rule
/// detail, prefixed with the rule index by the caller.
fn parse_client_subnet(raw: &str) -> std::result::Result<ClientSubnet, String> {
    let raw = raw.trim();
    let (addr_str, prefix) = match raw.split_once('/') {
        Some((addr, prefix)) => {
            let prefix: u8 = prefix
                .trim()
                .parse()
                .map_err(|_| format!("bad client_subnet {raw:?}: prefix {:?} is not a number", prefix.trim()))?;
            (addr.trim(), Some(prefix))
        }
        None => (raw, None),
    };
    let addr: std::net::IpAddr = addr_str
        .parse()
        .map_err(|_| format!("bad client_subnet {raw:?}: {addr_str:?} is not an IP address"))?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    let source_prefix = prefix.unwrap_or(max);
    if source_prefix > max {
        return Err(format!(
            "bad client_subnet {raw:?}: prefix /{source_prefix} exceeds /{max} for {addr}"
        ));
    }
    Ok(ClientSubnet {
        addr,
        source_prefix,
        scope_prefix: 0,
    })
}

/// A rule-local config error, tagged with the rule's position.
fn rule_error(index: usize, msg: impl std::fmt::Display) -> Error {
    Error::config(format!("dns.rules[{index}]: {msg}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::wire;

    fn strs(values: &[&str]) -> Vec<String> {
        values.iter().map(|s| s.to_string()).collect()
    }

    fn servers(rule: &DnsRule) -> Vec<String> {
        rule.server
            .as_ref()
            .expect("rule has servers")
            .iter()
            .map(Upstream::to_string)
            .collect()
    }

    fn ip(s: &str) -> std::net::IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn first_matching_rule_wins_in_config_order() {
        let suffix = || RuleSpec {
            domain_suffix: strs(&["corp.test"]),
            server_urls: strs(&["udp://192.0.2.1"]),
            ..Default::default()
        };
        let keyword = || RuleSpec {
            domain_keyword: strs(&["corp"]),
            server_urls: strs(&["udp://192.0.2.2"]),
            ..Default::default()
        };

        // Both rules accept a.corp.test; the earlier suffix rule wins.
        let rules = DnsRules::parse(&[suffix(), keyword()]).unwrap();
        assert_eq!(rules.len(), 2);
        assert!(!rules.is_empty());
        assert_eq!(
            servers(rules.match_rule("a.corp.test", wire::TYPE_A).unwrap()),
            vec!["udp://192.0.2.1:53"]
        );
        // A name only the keyword rule accepts falls through to it.
        assert_eq!(
            servers(rules.match_rule("mycorp.example", wire::TYPE_A).unwrap()),
            vec!["udp://192.0.2.2:53"]
        );
        // No rule accepts other.test: the resolver keeps its defaults.
        assert!(rules.match_rule("other.test", wire::TYPE_A).is_none());

        // Swapping the order swaps the winner — precedence is purely
        // positional.
        let rules = DnsRules::parse(&[keyword(), suffix()]).unwrap();
        assert_eq!(
            servers(rules.match_rule("a.corp.test", wire::TYPE_A).unwrap()),
            vec!["udp://192.0.2.2:53"]
        );
        // An empty rule list matches nothing.
        assert!(DnsRules::parse(&[]).unwrap().match_rule("x.test", wire::TYPE_A).is_none());
    }

    #[test]
    fn domain_kinds_and_cross_field_gating() {
        let rules = DnsRules::parse(&[
            RuleSpec {
                domains: strs(&["exact.test"]),
                server_urls: strs(&["udp://192.0.2.1"]),
                ..Default::default()
            },
            RuleSpec {
                domain_suffix: strs(&[".suffix.test"]),
                server_urls: strs(&["udp://192.0.2.2"]),
                ..Default::default()
            },
            RuleSpec {
                domain_regex: strs(&[r"^ads[0-9]+\.test$"]),
                server_urls: strs(&["udp://192.0.2.3"]),
                ..Default::default()
            },
        ])
        .unwrap();
        // Exact: only the name itself, case-insensitively.
        assert_eq!(servers(rules.match_rule("EXACT.test", wire::TYPE_A).unwrap())[0], "udp://192.0.2.1:53");
        assert!(rules.match_rule("sub.exact.test", wire::TYPE_A).is_none());
        // A leading dot is accepted as the suffix form: apex + subdomains.
        assert_eq!(servers(rules.match_rule("suffix.test", wire::TYPE_A).unwrap())[0], "udp://192.0.2.2:53");
        assert_eq!(
            servers(rules.match_rule("deep.a.suffix.test", wire::TYPE_A).unwrap())[0],
            "udp://192.0.2.2:53"
        );
        assert!(rules.match_rule("xsuffix.test", wire::TYPE_A).is_none());
        // Regex is matched against the lowercased name.
        assert_eq!(servers(rules.match_rule("Ads12.test", wire::TYPE_A).unwrap())[0], "udp://192.0.2.3:53");
        assert!(rules.match_rule("ads.test", wire::TYPE_A).is_none());

        // The four kinds share one DomainMatcher, so they are ORed: a
        // name hitting either the suffix or the keyword is accepted.
        // (sing-box ANDs across field types; configs use one kind per
        // rule, where the two agree.)
        let rules = DnsRules::parse(&[RuleSpec {
            domain_suffix: strs(&["corp.test"]),
            domain_keyword: strs(&["admin"]),
            server_urls: strs(&["udp://192.0.2.9"]),
            ..Default::default()
        }])
        .unwrap();
        assert!(rules.match_rule("admin.corp.test", wire::TYPE_A).is_some());
        assert!(rules.match_rule("a.corp.test", wire::TYPE_A).is_some());
        assert!(rules.match_rule("admin.example", wire::TYPE_A).is_some());
        assert!(rules.match_rule("other.example", wire::TYPE_A).is_none());
    }

    #[test]
    fn invert_flips_the_whole_match() {
        let rules = DnsRules::parse(&[
            RuleSpec {
                domain_suffix: strs(&["block.test"]),
                invert: true,
                server_urls: strs(&["udp://192.0.2.9"]),
                ..Default::default()
            },
            // Catch-all fallback (no matcher fields, only a server).
            RuleSpec {
                server_urls: strs(&["udp://192.0.2.1"]),
                ..Default::default()
            },
        ])
        .unwrap();
        // The inverted rule rejects its own suffix: block.test falls
        // through to the catch-all.
        assert_eq!(servers(rules.match_rule("a.block.test", wire::TYPE_A).unwrap())[0], "udp://192.0.2.1:53");
        assert_eq!(servers(rules.match_rule("block.test", wire::TYPE_A).unwrap())[0], "udp://192.0.2.1:53");
        // Everything else matches the inverted rule.
        assert_eq!(servers(rules.match_rule("any.test", wire::TYPE_A).unwrap())[0], "udp://192.0.2.9:53");
    }

    #[test]
    fn query_type_gates_matching() {
        let rules = DnsRules::parse(&[
            RuleSpec {
                domains: strs(&["dual.test"]),
                query_type: vec![wire::TYPE_AAAA],
                server_urls: strs(&["tls://192.0.2.53"]),
                ..Default::default()
            },
            RuleSpec {
                server_urls: strs(&["udp://192.0.2.1"]),
                ..Default::default()
            },
        ])
        .unwrap();
        // A is not in the rule's type list → the catch-all handles it.
        assert_eq!(servers(rules.match_rule("dual.test", wire::TYPE_A).unwrap())[0], "udp://192.0.2.1:53");
        assert_eq!(servers(rules.match_rule("dual.test", wire::TYPE_AAAA).unwrap())[0], "tls://192.0.2.53:853");

        // A type-only rule (any name, one type).
        let rules = DnsRules::parse(&[RuleSpec {
            query_type: vec![wire::TYPE_A],
            server_urls: strs(&["udp://192.0.2.1"]),
            ..Default::default()
        }])
        .unwrap();
        assert!(rules.match_rule("x.test", wire::TYPE_A).is_some());
        assert!(rules.match_rule("x.test", wire::TYPE_AAAA).is_none());
        // Same for a name-only rule, which is type-agnostic.
        let rules = DnsRules::parse(&[RuleSpec {
            domains: strs(&["x.test"]),
            ..Default::default()
        }])
        .unwrap();
        assert!(rules.match_rule("x.test", 65).is_some());
        assert!(rules.match_rule("x.test", wire::TYPE_AAAA).is_some());
    }

    #[test]
    fn action_fields_round_trip() {
        let rules = DnsRules::parse(&[RuleSpec {
            domain_suffix: strs(&["corp.test"]),
            server_urls: strs(&["https://192.0.2.10/dns-query", "tcp://192.0.2.11:5353"]),
            disable_cache: true,
            rewrite_ttl: Some(60),
            client_subnet: Some("192.0.2.0/24".into()),
            ..Default::default()
        }])
        .unwrap();
        let rule = rules.match_rule("corp.test", wire::TYPE_A).unwrap();
        assert!(rule.disable_cache);
        assert_eq!(rule.rewrite_ttl, Some(60));
        let cs = rule.client_subnet.unwrap();
        assert_eq!(cs.addr, ip("192.0.2.0"));
        assert_eq!(cs.source_prefix, 24);
        assert_eq!(cs.scope_prefix, 0);
        assert_eq!(
            servers(rule),
            vec!["https://192.0.2.10:443", "tcp://192.0.2.11:5353"]
        );
        assert!(matches!(&rule.server.as_ref().unwrap()[0], Upstream::Https { path, .. } if path == "/dns-query"));

        // Defaults: no servers keeps the resolver's list, cache on, no
        // TTL rewrite, no subnet.
        let rules = DnsRules::parse(&[RuleSpec {
            domains: strs(&["plain.test"]),
            ..Default::default()
        }])
        .unwrap();
        let rule = rules.match_rule("plain.test", wire::TYPE_A).unwrap();
        assert!(rule.server.is_none());
        assert!(!rule.disable_cache);
        assert_eq!(rule.rewrite_ttl, None);
        assert!(rule.client_subnet.is_none());
        assert!(rule.matcher.query_type.is_empty());
        assert!(rule.matcher.network.is_empty());
        assert!(!rule.matcher.invert);
    }

    #[test]
    fn client_subnet_bare_address_is_the_full_host() {
        let rules = DnsRules::parse(&[
            RuleSpec {
                domains: strs(&["v4.test"]),
                client_subnet: Some("192.0.2.7".into()),
                ..Default::default()
            },
            RuleSpec {
                domains: strs(&["v6.test"]),
                client_subnet: Some(" 2001:db8::7 ".into()),
                ..Default::default()
            },
        ])
        .unwrap();
        let cs = rules.match_rule("v4.test", wire::TYPE_A).unwrap().client_subnet.unwrap();
        assert!(cs.addr.is_ipv4());
        assert_eq!(cs.source_prefix, 32);
        let cs = rules.match_rule("v6.test", wire::TYPE_A).unwrap().client_subnet.unwrap();
        assert!(cs.addr.is_ipv6());
        assert_eq!(cs.source_prefix, 128);
    }

    #[test]
    fn network_constraint_when_the_transport_is_known() {
        // RuleSpec has no network field (the dialect layer sets it on the
        // matcher); build the rule directly.
        let matcher = DnsRuleMatcher {
            network: vec![Network::Tcp],
            ..Default::default()
        };
        let rules = DnsRules {
            rules: vec![DnsRule {
                matcher,
                ..Default::default()
            }],
        };
        assert!(rules
            .match_rule_with_network("x.test", wire::TYPE_A, Network::Tcp)
            .is_some());
        assert!(rules
            .match_rule_with_network("x.test", wire::TYPE_A, Network::Udp)
            .is_none());
        // Without transport knowledge the list is not consulted.
        assert!(rules.match_rule("x.test", wire::TYPE_A).is_some());

        // An unconstrained rule accepts either transport.
        let rules = DnsRules::parse(&[RuleSpec {
            server_urls: strs(&["udp://192.0.2.1"]),
            ..Default::default()
        }])
        .unwrap();
        assert!(rules
            .match_rule_with_network("x.test", wire::TYPE_A, Network::Udp)
            .is_some());
        assert!(rules
            .match_rule_with_network("x.test", wire::TYPE_A, Network::Tcp)
            .is_some());
    }

    #[test]
    fn bad_server_url_names_the_rule_and_the_url() {
        let err = DnsRules::parse(&[
            RuleSpec {
                domains: strs(&["ok.test"]),
                ..Default::default()
            },
            RuleSpec {
                domains: strs(&["bad.test"]),
                server_urls: strs(&["frobnicate://x"]),
                ..Default::default()
            },
        ])
        .expect_err("an unknown scheme must be rejected");
        assert!(matches!(err, Error::Config(_)));
        let msg = err.to_string();
        assert!(msg.contains("dns.rules[1]"), "message: {msg}");
        assert!(msg.contains("frobnicate://x"), "message: {msg}");
        // Empty entries are rejected too, and a bad URL aborts the whole
        // parse even when later rules are fine.
        assert!(DnsRules::parse(&[RuleSpec {
            server_urls: strs(&[""]),
            ..Default::default()
        }])
        .is_err());
        assert!(DnsRules::parse(&[
            RuleSpec {
                server_urls: strs(&["udp://192.0.2.1", "quic://192.0.2.2"]),
                ..Default::default()
            },
            RuleSpec {
                domains: strs(&["fine.test"]),
                server_urls: strs(&["%zz"]),
                ..Default::default()
            },
        ])
        .is_err());
    }

    #[test]
    fn malformed_rules_are_rejected() {
        // client_subnet: bad prefix, bad address, out-of-range prefix.
        for cs in ["192.0.2.0/33", "not-an-ip", "192.0.2.0/", "2001:db8::1/200", "1.2.3.4/24/8"] {
            let err = DnsRules::parse(&[RuleSpec {
                domains: strs(&["a.test"]),
                client_subnet: Some(cs.to_string()),
                ..Default::default()
            }])
            .expect_err(cs);
            let msg = err.to_string();
            assert!(msg.contains("dns.rules[0]"), "{cs}: {msg}");
            assert!(msg.contains("client_subnet"), "{cs}: {msg}");
        }
        // Bad regex keeps add_regex's message and gains the index.
        let err = DnsRules::parse(&[RuleSpec {
            domain_regex: strs(&["(unclosed"]),
            ..Default::default()
        }])
        .expect_err("bad regex must be rejected");
        let msg = err.to_string();
        assert!(msg.contains("dns.rules[0]"), "message: {msg}");
        assert!(msg.contains("regex"), "message: {msg}");
        // A rule that would match everything and do nothing.
        let err = DnsRules::parse(&[RuleSpec::default()]).expect_err("empty rule");
        assert!(err.to_string().contains("dns.rules[0]"), "message: {err}");
        // Invert alone does not make an empty rule meaningful.
        assert!(DnsRules::parse(&[RuleSpec {
            invert: true,
            ..Default::default()
        }])
        .is_err());
        // Empty patterns and misplaced wildcards.
        assert!(DnsRules::parse(&[RuleSpec {
            domains: strs(&["  "]),
            ..Default::default()
        }])
        .is_err());
        assert!(DnsRules::parse(&[RuleSpec {
            domain_keyword: strs(&[""]),
            ..Default::default()
        }])
        .is_err());
        let err = DnsRules::parse(&[RuleSpec {
            domains: strs(&["*.exact.test"]),
            ..Default::default()
        }])
        .expect_err("wildcard in domain list must point at domain_suffix");
        assert!(err.to_string().contains("domain_suffix"), "message: {err}");
        assert!(DnsRules::parse(&[RuleSpec {
            domain_suffix: strs(&["a.*.test"]),
            ..Default::default()
        }])
        .is_err());
    }

    #[test]
    fn rewrite_ttl_single_answer_is_bytes_exact() {
        let query = wire::parse(&wire::build_query(0x1234, "a.test", wire::TYPE_A)).unwrap();
        let original = wire::build_response(&query, wire::RCODE_NOERROR, &[(ip("198.18.0.5"), 300)]);
        // header(12) + question("a.test" = 8 labels + 4) = 24; the answer
        // is pointer(2) type(2) class(2) ttl(4) rdlen(2) rdata(4) — the
        // TTL sits at 24 + 6 = 30.
        assert_eq!(original.len(), 40);
        assert_eq!(&original[30..34], &300u32.to_be_bytes());

        let mut rewritten = original.clone();
        rewrite_ttl(&mut rewritten, 60).unwrap();
        assert_eq!(&rewritten[30..34], &60u32.to_be_bytes());
        // Nothing but the TTL bytes changed.
        assert_eq!(rewritten.len(), original.len());
        for (i, (before, after)) in original.iter().zip(&rewritten).enumerate() {
            if !(30..34).contains(&i) {
                assert_eq!(before, after, "byte {i} changed");
            }
        }
        let parsed = wire::parse(&rewritten).unwrap();
        assert_eq!(parsed.answers[0].ttl, 60);
        assert_eq!(parsed.answers[0].rdata, vec![198, 18, 0, 5]);
        assert_eq!(parsed.questions[0].name, "a.test");
        assert_eq!(parsed.id, 0x1234);
    }

    #[test]
    fn rewrite_ttl_multiple_answers_of_mixed_types() {
        let query = wire::parse(&wire::build_query(9, "multi.test", wire::TYPE_A)).unwrap();
        // question "multi.test" = 12 + 4 → answers start at 28; A record
        // 16 bytes, AAAA 28 bytes, A 16 bytes; TTLs at +6 within each.
        let original = wire::build_response(
            &query,
            wire::RCODE_NOERROR,
            &[(ip("198.18.0.1"), 1), (ip("2001:db8::1"), 2), (ip("198.18.0.2"), 3)],
        );
        assert_eq!(original.len(), 88);
        assert_eq!(&original[34..38], &1u32.to_be_bytes());
        assert_eq!(&original[50..54], &2u32.to_be_bytes());
        assert_eq!(&original[78..82], &3u32.to_be_bytes());

        let mut rewritten = original.clone();
        rewrite_ttl(&mut rewritten, 45).unwrap();
        assert_eq!(&rewritten[34..38], &45u32.to_be_bytes());
        assert_eq!(&rewritten[50..54], &45u32.to_be_bytes());
        assert_eq!(&rewritten[78..82], &45u32.to_be_bytes());
        let parsed = wire::parse(&rewritten).unwrap();
        assert_eq!(parsed.answers.len(), 3);
        for rr in &parsed.answers {
            assert_eq!(rr.ttl, 45);
        }
        // rdata and the AAAA length survive untouched.
        assert_eq!(parsed.answers[0].rdata, vec![198, 18, 0, 1]);
        assert_eq!(parsed.answers[1].rdata.len(), 16);
        assert_eq!(parsed.answers[2].rdata, vec![198, 18, 0, 2]);
    }

    #[test]
    fn rewrite_ttl_handles_compression_pointers_and_inline_names() {
        let query = wire::parse(&wire::build_query(0x55, "plain.test", wire::TYPE_A)).unwrap();
        let resp = wire::build_response(&query, wire::RCODE_NOERROR, &[(ip("198.18.0.5"), 111)]);
        // question "plain.test" = 12-byte name + 4 → answers at 28.
        // build_response writes the owner as a pointer to the question.
        assert_eq!(&resp[28..30], &[0xC0, 0x0C]);
        let mut rewritten = resp.clone();
        rewrite_ttl(&mut rewritten, 30).unwrap();
        assert_eq!(wire::parse(&rewritten).unwrap().answers[0].ttl, 30);

        // The same message with the owner name spelled out: the walker
        // must skip the labels instead of trusting a pointer.
        let mut inline = resp[..28].to_vec();
        inline.extend_from_slice(&[5, b'p', b'l', b'a', b'i', b'n', 4, b't', b'e', b's', b't', 0]);
        inline.extend_from_slice(&resp[30..]);
        assert_eq!(inline.len(), resp.len() + 10); // 12-byte name vs pointer
        assert_eq!(wire::parse(&inline).unwrap().answers[0].ttl, 111);
        rewrite_ttl(&mut inline, 30).unwrap();
        // TTL moved with the name: 28 + 12 + 4 = 44.
        assert_eq!(&inline[44..48], &30u32.to_be_bytes());
        let parsed = wire::parse(&inline).unwrap();
        assert_eq!(parsed.answers[0].ttl, 30);
        assert_eq!(parsed.answers[0].rdata, vec![198, 18, 0, 5]);
        assert_eq!(parsed.questions[0].name, "plain.test");
    }

    #[test]
    fn rewrite_ttl_noop_without_answers_and_ignores_additional_records() {
        let query = wire::parse(&wire::build_query(3, "nx.test", wire::TYPE_A)).unwrap();
        // NXDOMAIN with no answers: byte-for-byte no-op.
        let nxdomain = wire::build_response(&query, wire::RCODE_NXDOMAIN, &[]);
        let mut copy = nxdomain.clone();
        rewrite_ttl(&mut copy, 1).unwrap();
        assert_eq!(copy, nxdomain);
        let parsed = wire::parse(&copy).unwrap();
        assert_eq!(parsed.rcode, wire::RCODE_NXDOMAIN);
        assert!(parsed.answers.is_empty());

        // Only answers are rewritten: an OPT RR in the additional section
        // holds EDNS flags in its TTL field and must survive.
        let original = wire::build_response(&query, wire::RCODE_NOERROR, &[(ip("198.18.0.5"), 300)]);
        let mut with_opt = original.clone();
        crate::dns::edns::append_to_query(&mut with_opt, None);
        let opt_at = with_opt.len() - 11;
        let opt_bytes = with_opt[opt_at..].to_vec();
        // question "nx.test" = 9 + 4 → answer TTL at 25 + 6 = 31.
        assert_eq!(&with_opt[31..35], &300u32.to_be_bytes());
        rewrite_ttl(&mut with_opt, 7).unwrap();
        assert_eq!(&with_opt[31..35], &7u32.to_be_bytes());
        // The OPT RR (EDNS flags share the TTL field) is untouched.
        assert_eq!(&with_opt[opt_at..], opt_bytes.as_slice());
    }

    #[test]
    fn rewrite_ttl_errors_on_truncated_or_inconsistent_messages() {
        let query = wire::parse(&wire::build_query(3, "cut.test", wire::TYPE_A)).unwrap();
        let full = wire::build_response(&query, wire::RCODE_NOERROR, &[(ip("198.18.0.1"), 300)]);

        // Shorter than a header, cut header, cut question, cut rdata.
        assert!(rewrite_ttl(&mut [], 1).is_err());
        assert!(rewrite_ttl(&mut full[..11].to_vec(), 1).is_err());
        assert!(rewrite_ttl(&mut full[..20].to_vec(), 1).is_err());
        assert!(rewrite_ttl(&mut full[..full.len() - 1].to_vec(), 1).is_err());
        // ANCOUNT claims records that are not there.
        let mut lying = full.clone();
        lying[6..8].copy_from_slice(&9u16.to_be_bytes());
        assert!(rewrite_ttl(&mut lying, 1).is_err());
        // QDCOUNT claims questions that are not there.
        let mut no_question = full.clone();
        no_question[4..6].copy_from_slice(&2u16.to_be_bytes());
        assert!(rewrite_ttl(&mut no_question, 1).is_err());
        // A reserved label type in the question name.
        let mut reserved = wire::build_query(2, "x.test", wire::TYPE_A);
        reserved[12] = 0x80;
        assert!(rewrite_ttl(&mut reserved, 1).is_err());
        // A name that runs off the end of the buffer.
        let mut dangling = wire::build_query(2, "x.test", wire::TYPE_A);
        dangling[12] = 0x3F;
        assert!(rewrite_ttl(&mut dangling, 1).is_err());
        // The intact message still rewrites fine.
        let mut ok = full.clone();
        rewrite_ttl(&mut ok, 9).unwrap();
        assert_eq!(wire::parse(&ok).unwrap().answers[0].ttl, 9);
    }
}