//! Per-domain nameserver policy: mihomo `nameserver-policy` map entries
//! and the domain-matching half of sing-box `dns.rules` server
//! selection, as a pure lookup structure. Keys use the same pattern
//! grammar as rule-provider domain sets (`DomainMatcher::add_domain_line`):
//! exact domains, `+.suffix` / `.suffix` (suffix + apex) and `*.suffix`
//! wildcards. Each rule carries its own parsed upstreams so the resolver
//! can exchange against them directly without consulting its default
//! list.

use crate::dns::upstream::{parse_upstream, Upstream};
use crate::error::{Error, Result};
use crate::rule::DomainMatcher;

/// Ordered domain-to-upstreams rules; the first matching rule wins.
#[derive(Debug, Default, Clone)]
pub struct NameserverPolicy {
    rules: Vec<(DomainMatcher, Vec<Upstream>)>,
}

impl NameserverPolicy {
    /// Parse policy map entries: `(key, nameserver URLs)`.
    ///
    /// Key grammar follows [`DomainMatcher::add_domain_line`]: an exact
    /// domain matches only itself, `+.d` / `.d` match `d` and anything
    /// under it, and `*.d` behaves as the suffix form. Keys are
    /// lowercased before matching.
    ///
    /// `geosite:` (and any other `prefix:` set reference such as
    /// `rule-set:`) is rejected with a config error: the geosite `.dat`
    /// and rule-provider data are loaded by the app layer and may not be
    /// available when the policy is parsed. Expand such keys into plain
    /// domain patterns at config load time, before calling this.
    ///
    /// Values are nameserver URL strings parsed with
    /// [`crate::dns::upstream::parse_upstream`] (`udp://`, `tcp://`,
    /// `tls://`, `https://` or a bare address); every entry must parse
    /// and each rule needs at least one server.
    pub fn parse(specs: &[(String, Vec<String>)]) -> Result<Self> {
        let mut rules = Vec::with_capacity(specs.len());
        for (key, servers) in specs {
            let key = key.trim();
            if key.is_empty() {
                return Err(Error::config(format!(
                    "nameserver-policy key {key:?} is empty"
                )));
            }
            if key.starts_with('#') {
                return Err(Error::config(format!(
                    "nameserver-policy key {key:?} looks like a comment"
                )));
            }
            // A ':' never occurs in a plain domain; the only prefixed keys
            // mihomo supports here are set references (geosite:/rule-set:)
            // which need provider data that is not loaded at this stage.
            if key.contains(':') {
                return Err(Error::config(format!(
                    "nameserver-policy key {key:?}: set prefixes (geosite:, rule-set:) are \
                     not supported here — the provider data is not loaded at policy parse \
                     time; expand the set to plain domain patterns first"
                )));
            }
            // add_domain_line silently drops wildcards it does not
            // understand; reject them loudly instead of installing a rule
            // that can never match.
            if key.contains('*') && !key.starts_with("*.") {
                return Err(Error::config(format!(
                    "nameserver-policy key {key:?}: only the \"*.domain\" wildcard form \
                     is supported"
                )));
            }
            if servers.is_empty() {
                return Err(Error::config(format!(
                    "nameserver-policy for {key:?}: no nameservers given"
                )));
            }
            let mut matcher = DomainMatcher::default();
            matcher.add_domain_line(key);
            let mut upstreams = Vec::with_capacity(servers.len());
            for server in servers {
                match parse_upstream(server.trim()) {
                    Some(u) => upstreams.push(u),
                    None => {
                        return Err(Error::config(format!(
                            "nameserver-policy for {key:?}: unsupported nameserver \
                             {server:?} (udp://, tcp://, tls://, https://)"
                        )))
                    }
                }
            }
            rules.push((matcher, upstreams));
        }
        Ok(Self { rules })
    }

    /// Upstreams of the first rule whose matcher matches `name`, or
    /// `None` when no rule applies — the caller then falls back to its
    /// default upstream list. Matching is case-insensitive.
    pub fn match_upstreams(&self, name: &str) -> Option<&[Upstream]> {
        self.rules
            .iter()
            .find(|(matcher, _)| matcher.matches(name))
            .map(|(_, upstreams)| upstreams.as_slice())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Only documentation-range addresses (RFC 5737 / 3849) so the tests
    /// never touch a real resolver.
    fn spec(key: &str, servers: &[&str]) -> (String, Vec<String>) {
        (
            key.to_string(),
            servers.iter().map(|s| s.to_string()).collect(),
        )
    }

    #[test]
    fn bare_address_values_default_ports() {
        // Bare addresses (no scheme) take the udp:// form with default
        // ports, same as parse_upstream.
        let policy = NameserverPolicy::parse(&[spec("bare.test", &["192.0.2.9"])]).unwrap();
        let ups = policy.match_upstreams("bare.test").unwrap();
        assert_eq!(ups[0].to_string(), "udp://192.0.2.9:53");
    }

    #[test]
    fn exact_key_matches_only_exact() {
        let policy =
            NameserverPolicy::parse(&[spec("internal.example", &["udp://192.0.2.53"])]).unwrap();
        assert!(policy.match_upstreams("internal.example").is_some());
        // Matching is case-insensitive (DomainMatcher lowercases).
        assert!(policy.match_upstreams("INTERNAL.Example").is_some());
        assert!(policy.match_upstreams("sub.internal.example").is_none());
        assert!(policy.match_upstreams("xinternal.example").is_none());
        assert!(policy.match_upstreams("internal.example.org").is_none());
    }

    #[test]
    fn suffix_keys_plus_and_wildcard() {
        let policy = NameserverPolicy::parse(&[
            spec("+.corp.test", &["udp://192.0.2.1"]),
            spec("*.wild.test", &["udp://192.0.2.2"]),
        ])
        .unwrap();
        // `+.corp.test`: apex and subdomains, not other suffixes.
        let ups = policy.match_upstreams("corp.test").unwrap();
        assert_eq!(ups.len(), 1);
        assert_eq!(ups[0].to_string(), "udp://192.0.2.1:53");
        assert!(policy.match_upstreams("a.corp.test").is_some());
        assert!(policy.match_upstreams("deep.a.corp.test").is_some());
        assert!(policy.match_upstreams("acorp.test").is_none());
        // `*.wild.test` takes the suffix form (apex + subdomains).
        let ups = policy.match_upstreams("wild.test").unwrap();
        assert_eq!(ups.first().unwrap().to_string(), "udp://192.0.2.2:53");
        assert!(policy.match_upstreams("nested.wild.test").is_some());
        assert!(policy.match_upstreams("wild.test.org").is_none());
        // Leading-dot form is accepted like `+.`.
        let dotted = NameserverPolicy::parse(&[spec(".dot.test", &["udp://192.0.2.3"])]).unwrap();
        assert!(dotted.match_upstreams("a.dot.test").is_some());
    }

    #[test]
    fn multiple_values_keep_order() {
        let policy = NameserverPolicy::parse(&[spec(
            "multi.test",
            &[
                "udp://192.0.2.1:5353",
                "tcp://192.0.2.2",
                "tls://192.0.2.53",
                "https://192.0.2.10/dns-query",
                "udp://[2001:db8::53]:53",
            ],
        )])
        .unwrap();
        let ups = policy.match_upstreams("multi.test").unwrap();
        assert_eq!(ups.len(), 5);
        assert!(matches!(&ups[0], Upstream::Udp(a) if a.port() == 5353));
        assert!(matches!(&ups[1], Upstream::Tcp(a) if a.port() == 53));
        assert!(matches!(&ups[2], Upstream::Tls { addr, .. } if addr.port() == 853));
        assert!(
            matches!(&ups[3], Upstream::Https { addr, path, .. } if addr.port() == 443 && path == "/dns-query")
        );
        assert!(matches!(&ups[4], Upstream::Udp(a) if a.is_ipv6()));
    }

    #[test]
    fn geosite_and_set_keys_are_rejected() {
        let err = NameserverPolicy::parse(&[spec("geosite:cn", &["udp://192.0.2.1"])])
            .expect_err("geosite key must be rejected");
        assert!(err.to_string().contains("geosite"), "message: {err}");
        let err = NameserverPolicy::parse(&[spec("rule-set:ads", &["udp://192.0.2.1"])])
            .expect_err("rule-set key must be rejected");
        assert!(matches!(err, Error::Config(_)));
    }

    #[test]
    fn bad_keys_and_values_are_rejected() {
        // Unsupported wildcard placement would silently never match.
        assert!(NameserverPolicy::parse(&[spec("a.*.test", &["udp://192.0.2.1"])]).is_err());
        assert!(NameserverPolicy::parse(&[spec("", &["udp://192.0.2.1"])]).is_err());
        assert!(NameserverPolicy::parse(&[spec("# comment", &["udp://192.0.2.1"])]).is_err());
        // Values must parse and must exist. quic:// (DoQ) is supported
        // now, so an unsupported scheme like dhcp:// is the reject case.
        assert!(NameserverPolicy::parse(&[spec("ok.test", &["quic://192.0.2.1"])]).is_ok());
        assert!(NameserverPolicy::parse(&[spec("ok.test", &["frobnicate://x"])]).is_err());
        assert!(NameserverPolicy::parse(&[spec("ok.test", &[])]).is_err());
        // A good entry followed by a bad one still fails the whole parse.
        assert!(NameserverPolicy::parse(&[
            spec("good.test", &["udp://192.0.2.1"]),
            spec("bad.test", &["dhcp://en0"]),
        ])
        .is_err());
    }

    #[test]
    fn no_match_returns_none() {
        let policy = NameserverPolicy::parse(&[spec("+.corp.test", &["udp://192.0.2.1"])]).unwrap();
        assert!(policy.match_upstreams("example.com").is_none());
        // Empty policy matches nothing.
        let empty = NameserverPolicy::default();
        assert!(empty.match_upstreams("anything.test").is_none());
    }

    #[test]
    fn first_matching_rule_wins() {
        let policy = NameserverPolicy::parse(&[
            spec("+.dual.test", &["udp://192.0.2.1"]),
            spec("hit.dual.test", &["udp://192.0.2.2"]),
        ])
        .unwrap();
        // Both rules match; the earlier entry takes precedence.
        let ups = policy.match_upstreams("hit.dual.test").unwrap();
        assert_eq!(ups[0].to_string(), "udp://192.0.2.1:53");
        // A name only the second rule matches still resolves to it.
        let solo = NameserverPolicy::parse(&[spec("solo.test", &["udp://192.0.2.2"])]).unwrap();
        let ups = solo.match_upstreams("solo.test").unwrap();
        assert_eq!(ups[0].to_string(), "udp://192.0.2.2:53");
    }
}
