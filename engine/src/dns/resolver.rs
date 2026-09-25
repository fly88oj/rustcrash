//! The DNS engine: hijack server (fake-ip / redir-host), upstream
//! forwarding with cache, static hosts overrides, and the resolver the
//! router uses.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::config::DnsConfig;
use crate::dns::fakeip::FakeIpPool;
use crate::dns::upstream::{parse_upstream, Upstream};
use crate::dns::wire::{self, DnsMessage};
use crate::error::{Error, Result};
use crate::rule::DomainMatcher;

/// Cached entry: addresses + expiry.
struct CacheEntry {
    addrs: Vec<IpAddr>,
    ttl_until: Instant,
}

pub struct DnsEngine {
    cfg: DnsConfig,
    fakeip: Option<FakeIpPool>,
    fakeip_filter: DomainMatcher,
    cache: Mutex<HashMap<(String, u16), CacheEntry>>,
    query_id: AtomicU32,
    upstreams: Vec<Upstream>,
    /// Static hosts overrides (`hosts:` in mihomo config / sing-box hosts).
    hosts: HashMap<String, Vec<IpAddr>>,
    /// Per-domain upstream override (mihomo nameserver-policy).
    policy: Option<crate::dns::policy::NameserverPolicy>,
    /// sing-box dns.rules (per-rule server/ttl/cache).
    rules: Option<crate::dns::rules::DnsRules>,
}

impl DnsEngine {
    pub fn new(cfg: DnsConfig, fakeip_filter: DomainMatcher) -> Result<Arc<Self>> {
        let fakeip = if cfg.enhanced_mode == crate::config::EnhancedMode::FakeIp {
            Some(match &cfg.fakeip_store {
                Some(path) => FakeIpPool::load_from(&cfg.fakeip_range, path)?,
                None => FakeIpPool::new(&cfg.fakeip_range)?,
            })
        } else {
            None
        };
        let mut upstreams = Vec::new();
        for ns in cfg.nameservers.iter().chain(cfg.fallback.iter()) {
            match parse_upstream(ns) {
                Some(u) => upstreams.push(u),
                None => {
                    tracing::warn!(target: "engine", "skipping unsupported nameserver {ns:?}");
                }
            }
        }
        if upstreams.is_empty() {
            return Err(Error::dns(
                "no usable nameservers (udp/tcp/tls/https are supported)",
            ));
        }
        let policy = if cfg.nameserver_policy.is_empty() {
            None
        } else {
            match crate::dns::policy::NameserverPolicy::parse(&cfg.nameserver_policy) {
                Ok(p) => Some(p),
                Err(e) => {
                    tracing::warn!(target: "engine", "nameserver-policy disabled: {e}");
                    None
                }
            }
        };
        let rules = if cfg.rules.is_empty() {
            None
        } else {
            match crate::dns::rules::DnsRules::parse(&cfg.rules) {
                Ok(r) => Some(r),
                Err(e) => {
                    tracing::warn!(target: "engine", "dns rules disabled: {e}");
                    None
                }
            }
        };
        // Fold plain patterns from the config into the filter; `geosite:`
        // references are merged by the app layer once the .dat is loaded.
        let mut fakeip_filter = fakeip_filter;
        for pattern in &cfg.fakeip_filter {
            if !pattern.starts_with("geosite:") {
                fakeip_filter.add_domain_line(pattern);
            }
        }
        let hosts = cfg
            .hosts
            .iter()
            .map(|(k, v)| (k.to_ascii_lowercase(), v.clone()))
            .collect();
        Ok(Arc::new(DnsEngine {
            cfg,
            fakeip,
            fakeip_filter,
            cache: Mutex::new(HashMap::new()),
            query_id: AtomicU32::new(1),
            upstreams,
            hosts,
            policy,
            rules,
        }))
    }

    pub fn fakeip(&self) -> Option<&FakeIpPool> {
        self.fakeip.as_ref()
    }

    /// Handle one raw DNS query; returns the response bytes.
    pub async fn handle(&self, query: &[u8]) -> Vec<u8> {
        let msg = match wire::parse(query) {
            Ok(m) => m,
            Err(e) => {
                tracing::debug!(target: "engine", "dns: unparseable query: {e}");
                return Vec::new();
            }
        };
        let Some(q) = msg.first_question().cloned() else {
            return wire::build_response(&msg, wire::RCODE_NOERROR, &[]);
        };
        let qtype = q.qtype;

        // Static hosts override first (mihomo semantics: hosts answer
        // before any other path).
        if matches!(qtype, wire::TYPE_A | wire::TYPE_AAAA) {
            if let Some(addrs) = self.hosts.get(&q.name) {
                let matching: Vec<(IpAddr, u32)> = addrs
                    .iter()
                    .filter(|ip| {
                        (qtype == wire::TYPE_A && ip.is_ipv4())
                            || (qtype == wire::TYPE_AAAA && ip.is_ipv6())
                    })
                    .map(|ip| (*ip, 3600))
                    .collect();
                if !matching.is_empty() {
                    return wire::build_response(&msg, wire::RCODE_NOERROR, &matching);
                }
            }
        }

        // Fake-IP interception.
        if self
            .fakeip
            .as_ref()
            .is_some_and(|_| matches!(qtype, wire::TYPE_A | wire::TYPE_AAAA))
        {
            if self.fakeip_filter.matches(&q.name) {
                // Real resolution for filtered domains.
                return self.forward(&msg, &q.name, qtype).await;
            }
            if qtype == wire::TYPE_AAAA && !self.cfg.ipv6 {
                // No AAAA in fake-ip mode without ipv6: empty NOERROR.
                return wire::build_response(&msg, wire::RCODE_NOERROR, &[]);
            }
            let ip = self.fakeip.as_ref().unwrap().lookup_or_alloc(&q.name);
            if qtype == wire::TYPE_AAAA && ip.is_ipv4() {
                return wire::build_response(&msg, wire::RCODE_NOERROR, &[]);
            }
            return wire::build_response(&msg, wire::RCODE_NOERROR, &[(ip, 1)]);
        }

        self.forward(&msg, &q.name, qtype).await
    }

    /// Resolve through cache or upstreams; used by the router.
    pub async fn resolve(&self, name: &str, qtype: u16) -> Option<Vec<IpAddr>> {
        if let Some(hit) = self.hosts.get(name) {
            let v4: Vec<IpAddr> = hit.iter().copied().filter(|ip| ip.is_ipv4()).collect();
            if !v4.is_empty() {
                return Some(v4);
            }
        }
        let rule = self.rules.as_ref().and_then(|r| r.match_rule(name, qtype));
        let cache_ok = rule.is_none_or(|r| !r.disable_cache);
        if cache_ok {
            if let Some(hit) = self.cache_get(name, qtype) {
                return Some(hit);
            }
        }
        let wire_query = wire::build_query(self.next_id(), name, qtype);
        let parsed = wire::parse(&wire_query).ok()?;
        let resp = self.forward(&parsed, name, qtype).await;
        if cache_ok {
            if let Some(hit) = self.cache_get(name, qtype) {
                return Some(hit);
            }
        }
        extract_ips(&resp, qtype)
    }

    async fn forward(&self, query: &DnsMessage, name: &str, qtype: u16) -> Vec<u8> {
        // sing-box dns.rules take precedence over the nameserver policy
        // and the default list.
        let rule = self.rules.as_ref().and_then(|r| r.match_rule(name, qtype));
        let cache_ok = rule.is_none_or(|r| !r.disable_cache);
        if cache_ok {
            if let Some(hit) = self.cache_get(name, qtype) {
                return wire::build_response(query, wire::RCODE_NOERROR, &hit.iter().map(|ip| (*ip, 30)).collect::<Vec<_>>());
            }
        }
        // nameserver-policy overrides the default upstream list for
        // matching domains.
        let default = self.upstreams.clone();
        let upstreams: &[Upstream] = rule
            .and_then(|r| r.server.as_deref())
            .or_else(|| {
                self.policy
                    .as_ref()
                    .and_then(|p| p.match_upstreams(name))
            })
            .unwrap_or(&default);
        // Effective EDNS client subnet: the rule's overrides the global.
        let subnet = rule
            .and_then(|r| r.client_subnet.as_ref())
            .or(self.cfg.client_subnet.as_ref());
        // Ask each upstream in order until one answers; the outgoing query
        // carries the client's id so the answer maps back without state.
        for upstream in upstreams {
            let mut outbound = wire::build_query(0, name, qtype);
            if subnet.is_some() {
                crate::dns::edns::append_to_query(&mut outbound, subnet);
            }
            outbound[0..2].copy_from_slice(&query.id.to_be_bytes());
            match upstream.exchange(&outbound).await {
                Ok(mut resp) => {
                    resp[0..2].copy_from_slice(&query.id.to_be_bytes());
                    // TTL rewrite happens BEFORE caching so the served
                    // TTL and the cache expiry agree (sing-box does the
                    // same in applyResponseOptions → storeCache).
                    if let Some(ttl) = rule.and_then(|r| r.rewrite_ttl) {
                        if let Err(e) = crate::dns::rules::rewrite_ttl(&mut resp, ttl) {
                            tracing::debug!(target: "engine", "dns ttl rewrite: {e}");
                        }
                    }
                    if cache_ok {
                        self.cache_insert(name, qtype, &resp);
                    }
                    return resp;
                }
                Err(e) => {
                    tracing::debug!(target: "engine", "dns upstream {upstream}: {e}");
                }
            }
        }
        wire::build_response(query, wire::RCODE_NXDOMAIN, &[])
    }

    fn cache_get(&self, name: &str, qtype: u16) -> Option<Vec<IpAddr>> {
        let cache = self.cache.lock().unwrap();
        let e = cache.get(&(name.to_string(), qtype))?;
        if Instant::now() > e.ttl_until {
            return None;
        }
        Some(e.addrs.clone())
    }

    fn cache_insert(&self, name: &str, qtype: u16, resp: &[u8]) {
        let Some(msg) = wire::parse(resp).ok() else { return };
        let mut min_ttl = u32::MAX;
        let mut addrs = Vec::new();
        for rr in &msg.answers {
            if rr.rtype == qtype {
                min_ttl = min_ttl.min(rr.ttl);
                if let Some(ip) = rdata_ip(&rr.rdata) {
                    addrs.push(ip);
                }
            }
        }
        if addrs.is_empty() || min_ttl == u32::MAX {
            return;
        }
        let ttl = min_ttl.clamp(5, 300);
        self.cache.lock().unwrap().insert(
            (name.to_string(), qtype),
            CacheEntry {
                addrs,
                ttl_until: Instant::now() + Duration::from_secs(ttl as u64),
            },
        );
    }

    fn next_id(&self) -> u16 {
        (self.query_id.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u16
    }
}

fn rdata_ip(rdata: &[u8]) -> Option<IpAddr> {
    match rdata.len() {
        4 => Some(IpAddr::V4(<[u8; 4]>::try_from(rdata).unwrap().into())),
        16 => Some(IpAddr::V6(<[u8; 16]>::try_from(rdata).unwrap().into())),
        _ => None,
    }
}

fn extract_ips(resp: &[u8], qtype: u16) -> Option<Vec<IpAddr>> {
    let msg = wire::parse(resp).ok()?;
    let ips: Vec<IpAddr> = msg
        .answers
        .iter()
        .filter(|rr| rr.rtype == qtype)
        .filter_map(|rr| rdata_ip(&rr.rdata))
        .collect();
    (!ips.is_empty()).then_some(ips)
}

/// Kept for the config-dialect test surface (parses into a UDP upstream).
pub fn parse_nameserver(ns: &str) -> Option<SocketAddr> {
    match parse_upstream(ns)? {
        Upstream::Udp(a) => Some(a),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dns_config() -> DnsConfig {
        DnsConfig {
            fakeip_store: None,
            enable: true,
            listen: Some("127.0.0.1:0".into()),
            enhanced_mode: crate::config::EnhancedMode::FakeIp,
            ipv6: false,
            nameservers: vec!["udp://127.0.0.1:1".into()],
            fallback: vec![],
            fakeip_range: "198.18.0.1/15".into(),
            fakeip_filter: vec!["*.lan".into()],
            hosts: HashMap::new(),
            nameserver_policy: Vec::new(),
            client_subnet: None,
            rules: Vec::new(),
        }
    }

    #[tokio::test]
    async fn fakeip_allocation_and_reverse() {
        let engine = DnsEngine::new(dns_config(), DomainMatcher::default()).unwrap();
        let query = wire::build_query(7, "web.test", wire::TYPE_A);
        let resp = engine.handle(&query).await;
        let msg = wire::parse(&resp).unwrap();
        assert!(msg.is_response());
        assert_eq!(msg.answers.len(), 1);
        let ip = rdata_ip(&msg.answers[0].rdata).unwrap();
        assert!(engine.fakeip().unwrap().contains(ip));
        assert_eq!(engine.fakeip().unwrap().reverse(ip).unwrap(), "web.test");

        // Same domain → same address.
        let resp2 = engine.handle(&query).await;
        let msg2 = wire::parse(&resp2).unwrap();
        assert_eq!(rdata_ip(&msg2.answers[0].rdata).unwrap(), ip);
    }

    #[tokio::test]
    async fn fakeip_filter_bypasses_fake_answers() {
        // Filtered domain with a dead upstream → NXDOMAIN, not a fake ip.
        let engine = DnsEngine::new(
            DnsConfig {
            fakeip_store: None,
                fakeip_filter: vec!["filtered.test".into()],
                ..dns_config()
            },
            DomainMatcher::default(),
        )
        .unwrap();
        let query = wire::build_query(9, "filtered.test", wire::TYPE_A);
        let resp = engine.handle(&query).await;
        let msg = wire::parse(&resp).unwrap();
        assert_eq!(msg.rcode, 3);
        assert!(msg.answers.is_empty());
    }

    #[tokio::test]
    async fn aaaa_without_ipv6_gets_empty_answer() {
        let engine = DnsEngine::new(dns_config(), DomainMatcher::default()).unwrap();
        let query = wire::build_query(11, "v6.test", wire::TYPE_AAAA);
        let resp = engine.handle(&query).await;
        let msg = wire::parse(&resp).unwrap();
        assert_eq!(msg.rcode, 0);
        assert!(msg.answers.is_empty());
    }

    #[tokio::test]
    async fn hosts_override_wins() {
        let engine = DnsEngine::new(
            DnsConfig {
            fakeip_store: None,
                hosts: HashMap::from([(
                    "static.test".to_string(),
                    vec!["9.9.9.9".parse().unwrap()],
                )]),
                ..dns_config()
            },
            DomainMatcher::default(),
        )
        .unwrap();
        let query = wire::build_query(13, "static.test", wire::TYPE_A);
        let resp = engine.handle(&query).await;
        let msg = wire::parse(&resp).unwrap();
        // Even in fake-ip mode, hosts answer with the configured address.
        assert_eq!(rdata_ip(&msg.answers[0].rdata).unwrap().to_string(), "9.9.9.9");
    }

    #[tokio::test]
    async fn dead_upstreams_rejected() {
        let cfg = DnsConfig {
            fakeip_store: None,
            nameservers: vec![],
            ..dns_config()
        };
        assert!(DnsEngine::new(cfg, DomainMatcher::default()).is_err());
    }

    #[test]
    fn nameserver_parsing() {
        assert_eq!(
            parse_nameserver("udp://1.1.1.1"),
            Some("1.1.1.1:53".parse().unwrap())
        );
        assert_eq!(
            parse_nameserver("8.8.8.8:5353"),
            Some("8.8.8.8:5353".parse().unwrap())
        );
        assert_eq!(parse_nameserver("https://dns.test/dns-query"), None);
        assert_eq!(parse_nameserver("tcp://1.1.1.1"), None);
    }
}
