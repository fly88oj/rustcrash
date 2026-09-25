//! The engine application: wires config → listeners → router → outbounds,
//! runs the DNS server, tracks connections, and serves the Clash API.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;

use crate::addr::{Host, NetAddr};
use crate::config::{EngineConfig, RuleMode};
use crate::dns::resolver::DnsEngine;
use crate::dns::wire;
use crate::error::{Error, Result};
use crate::inbound::{RelayHandler, TcpMeta};
use crate::outbound::Registry;
use crate::rule::{ConnContext, GeoLookups, Network, Rule, RuleSetKind, RuleSets};
use crate::stats::Stats;
use crate::stream::{BoxProxyStream, CountingStream};

/// Inbound metadata bundle for routing (TcpMeta-shaped).
struct RouteMeta<'a> {
    network: Network,
    inbound: &'a str,
    inbound_kind: &'a str,
    inbound_port: Option<u16>,
    proc_info: Option<&'a crate::process::ProcessInfo>,
}

/// A running engine.
pub struct Engine {
    cfg: EngineConfig,
    registry: Arc<Registry>,
    rules: Vec<Rule>,
    rule_sets: RuleSets,
    geo: GeoLookups,
    dns: Option<Arc<DnsEngine>>,
    stats: Arc<Stats>,
    /// Runtime rule mode — the one genuinely hot-reloadable config knob,
    /// read per-connection in route_with. This is the seam PATCH/PUT
    /// /configs {"mode": ...} writes (mihomo patchConfigs' mode swap);
    /// everything listener-bound (ports, allow-lan) is NOT hot: see run().
    mode: tokio::sync::RwLock<RuleMode>,
    /// Whether any rule needs PROCESS lookups (avoids /proc scans otherwise).
    needs_process: bool,
    /// Whether any rule may need DNS-resolved destination IPs (drives
    /// the router's single pre-resolve).
    needs_ip: bool,
}

impl Engine {
    /// Build (without starting) from a normalized config: loads rule
    /// providers, geo databases, and constructs the outbound registry.
    pub fn build(cfg: EngineConfig) -> Result<Arc<Self>> {
        let cfg = cfg.with_builtin_outbounds();
        let rules = cfg.parse_rules()?;
        let mut rule_sets = RuleSets::default();
        let mut geo = GeoLookups::default();

        // GeoIP.
        if let Some(mmdb) = &cfg.geo.geoip_mmdb {
            match maxminddb::Reader::open_readfile(mmdb) {
                Ok(reader) => geo.geoip = Some(reader),
                Err(e) => tracing::warn!(target: "engine", "geoip {}: {e}", mmdb),
            }
        }
        // Dedicated ASN db (optional; IP-ASN falls back to the geoip
        // metadb when absent, like mihomo's single-metadb behavior).
        if let Some(mmdb) = &cfg.geo.asn_mmdb {
            match maxminddb::Reader::open_readfile(mmdb) {
                Ok(reader) => geo.asn_mmdb = Some(reader),
                Err(e) => tracing::warn!(target: "engine", "asn {}: {e}", mmdb),
            }
        }
        // Geosite: only entries referenced by rules or fake-ip filters.
        let mut wanted = Vec::new();
        for r in &rules {
            if let crate::rule::RuleMatcher::Geosite { name } = &r.matcher {
                wanted.push(name.clone());
            }
        }
        if let Some(dat) = &cfg.geo.geosite_dat {
            match std::fs::read(dat) {
                Ok(bytes) => match crate::geosite::load_filtered(
                    &bytes,
                    (!wanted.is_empty()).then_some(&wanted),
                ) {
                    Ok(map) => geo.geosite = map,
                    Err(e) => tracing::warn!(target: "engine", "geosite {dat}: {e}"),
                },
                Err(e) => tracing::warn!(target: "engine", "geosite {dat}: {e}"),
            }
        }

        // Rule providers.
        for p in &cfg.rule_providers {
            load_provider(p, &mut rule_sets);
        }

        // DNS.
        let dns = match &cfg.dns {
            Some(d) if d.enable => {
                let mut filter = crate::rule::DomainMatcher::default();
                for pattern in &d.fakeip_filter {
                    if let Some(name) = pattern.strip_prefix("geosite:") {
                        if let Some(m) = geo.geosite.get(name) {
                            // Merge the geosite entries as suffix/exact hits.
                            filter = m.clone();
                        } else {
                            tracing::warn!(target: "engine", "fake-ip-filter geosite:{name} not loaded");
                        }
                    }
                }
                Some(DnsEngine::new(d.clone(), filter)?)
            }
            _ => None,
        };

        let registry = Arc::new(Registry::build(
            cfg.outbounds.clone(),
            cfg.groups.clone(),
            dns.as_ref(),
        )?);
        let mode = tokio::sync::RwLock::new(cfg.mode);
        let needs_process = crate::rule::needs_process(&rules);
        let needs_ip = rules.iter().any(|r| r.needs_ip());

        let engine = Arc::new(Engine {
            cfg,
            registry,
            rules,
            rule_sets,
            geo,
            dns,
            stats: Stats::new(),
            mode,
            needs_process,
            needs_ip,
        });
        Ok(engine)
    }

    pub fn stats(&self) -> &Arc<Stats> {
        &self.stats
    }

    pub fn registry(&self) -> &Arc<Registry> {
        &self.registry
    }

    pub fn dns(&self) -> Option<&Arc<DnsEngine>> {
        self.dns.as_ref()
    }

    pub fn rules(&self) -> &[Rule] {
        &self.rules
    }

    pub async fn mode(&self) -> RuleMode {
        *self.mode.read().await
    }

    pub async fn set_mode(&self, mode: RuleMode) {
        *self.mode.write().await = mode;
    }

    pub fn config(&self) -> &EngineConfig {
        &self.cfg
    }

    /// Start everything and serve until shutdown.
    pub async fn run(self: &Arc<Self>) -> Result<()> {
        // Listeners. HOT-RELOAD BOUNDARY: sockets bind exactly once here
        // and the engine holds `cfg` immutably, so any config change that
        // moves a port, bind address, or allow-lan (i.e. re-spawns an
        // inbound) has no runtime path — PUT /configs rejects those fields
        // with a restart reason instead of pretending to apply them.
        let bound =
            crate::inbound::spawn_all(&self.cfg.listeners, self.clone() as Arc<dyn RelayHandler>)
                .await?;
        for (tag, addr) in &bound {
            tracing::info!(target: "engine", "inbound {tag} listening on {addr}");
        }

        // Server-side proxy listeners (act as a proxy server).
        for server in &self.cfg.proxy_servers {
            let relay = self.clone() as Arc<dyn RelayHandler>;
            let addr = crate::inbound::proxy_server::serve(server, relay).await?;
            tracing::info!(target: "engine",
                "server {} ({}) listening on {addr}", server.tag, server.protocol_name());
        }

        // WireGuard endpoints (sing-box `endpoints`): the WG server mode —
        // handshake responder + cryptokey routing into this relay.
        for ep in &self.cfg.wg_endpoints {
            let relay = self.clone() as Arc<dyn RelayHandler>;
            let cfg = ep.clone();
            let tag = ep.tag.clone();
            // serve_endpoint runs the socket loop forever; spawn so
            // later endpoints and the rest of startup continue.
            tokio::spawn(async move {
                match crate::proto::wireguard::serve_endpoint(&cfg, relay).await {
                    Ok(addr) => tracing::info!(target: "engine",
                        "endpoint {tag} (wireguard) listening on {addr}"),
                    Err(e) => tracing::error!(target: "engine",
                        "endpoint {tag} (wireguard) failed: {e}"),
                }
            });
        }

        // TUN device inbound (netstack bridged into the same relay).
        if let Some(tun_cfg) = &self.cfg.tun {
            let relay = self.clone() as Arc<dyn RelayHandler>;
            let hooks = crate::inbound::tun::TunHooks {
                dns: self.dns.clone(),
            };
            let cfg = tun_cfg.clone();
            // serve() runs the netstack loop forever; setup errors (no
            // /dev/net/tun, no CAP_NET_ADMIN) surface inside the task.
            tokio::spawn(async move {
                if let Err(e) = crate::inbound::tun::serve(&cfg, relay, hooks).await {
                    tracing::error!(target: "engine", "tun {}: {e}", cfg.tag);
                }
            });
            tracing::info!(target: "engine",
                "tun {} (netstack) starting on {:?}", tun_cfg.tag, tun_cfg.name);
        }

        // DNS server (UDP + TCP on the same port).
        if let (Some(dns_cfg), Some(dns)) = (&self.cfg.dns, self.dns.clone()) {
            if dns_cfg.enable {
                if let Some(listen) = &dns_cfg.listen {
                    spawn_dns_server(listen, dns).await?;
                }
            }
        }

        // Clash API.
        if let Some(api) = &self.cfg.api {
            crate::api::serve(api.clone(), self.clone()).await?;
        }

        // Health checks for url-test/fallback groups.
        let any_health = self
            .cfg
            .groups
            .iter()
            .any(|g| matches!(g.policy, crate::outbound::GroupPolicy::UrlTest | crate::outbound::GroupPolicy::Fallback));
        if any_health {
            let engine = self.clone();
            tokio::spawn(async move {
                loop {
                    engine.registry.health_round().await;
                    let interval = engine
                        .cfg
                        .groups
                        .iter()
                        .filter(|g| g.interval > 0)
                        .map(|g| g.interval)
                        .min()
                        .unwrap_or(300);
                    tokio::time::sleep(Duration::from_secs(interval.max(30))).await;
                }
            });
        }

        // Traffic sampler.
        {
            let stats = self.stats.clone();
            tokio::spawn(async move {
                loop {
                    tokio::time::sleep(Duration::from_secs(1)).await;
                    stats.publish();
                }
            });
        }

        // Await shutdown signals.
        wait_for_shutdown().await;
        tracing::info!(target: "engine", "shutting down");
        Ok(())
    }

    /// Full route with connection metadata for the extended rule types.
    /// The inbound metadata rides one struct (TcpMeta-shaped); UDP
    /// callers pass a synthetic one.
    async fn route_with(
        &self,
        target: &NetAddr,
        source: SocketAddr,
        meta: RouteMeta<'_>,
    ) -> (String, String) {
        let mode = *self.mode.read().await;
        match mode {
            RuleMode::Direct => return ("mode:direct".into(), "DIRECT".into()),
            RuleMode::Global => {
                // GLOBAL semantics: prefer the first group (the config's
                // primary selector), else the first outbound.
                let name = self
                    .registry
                    .group_names()
                    .first()
                    .cloned()
                    .or_else(|| self.registry.leaf_names().first().cloned())
                    .unwrap_or_else(|| "DIRECT".to_string());
                return ("mode:global".into(), name);
            }
            RuleMode::Rule => {}
        }

        // Reverse fake-ip before matching.
        let effective = self.unfake_target(target);

        // One pre-resolve for every IP-hungry rule (IP-CIDR/GEOIP/rule-set
        // without no-resolve); the evaluator itself stays synchronous.
        let resolved = match (&self.dns, effective.host.as_domain()) {
            (Some(dns), Some(name)) if self.needs_ip && !name.is_empty() => {
                dns.resolve(name, wire::TYPE_A).await
            }
            _ => None,
        };
        let ctx = ConnContext {
            host: &effective.host,
            port: effective.port,
            source_ip: Some(source.ip()),
            source_port: Some(source.port()),
            resolved,
            mode,
            network: meta.network,
            inbound: meta.inbound,
            inbound_kind: meta.inbound_kind,
            inbound_port: meta.inbound_port,
            process: meta.proc_info.map(|p| p.exe.as_str()),
            uid: meta.proc_info.and_then(|p| p.uid),
            user: meta.proc_info.and_then(|p| p.user.as_deref()),
            dscp: None,
        };
        for rule in &self.rules {
            if rule.evaluate(&ctx, &self.rule_sets, &self.geo) {
                return (format_rule(rule), rule.outbound.clone());
            }
        }
        ("no-match".into(), "DIRECT".into())
    }

    async fn relay_tcp(self: Arc<Self>, meta: TcpMeta, mut client: BoxProxyStream) {
        // Sniff the first client bytes (TLS SNI / HTTP Host) and replay
        // them loss-free; the override policy lives in apply_sniffed.
        let (target, client): (NetAddr, BoxProxyStream) = if self.cfg.sniff.enabled() {
            let (sniffed, peeked) =
                Self::sniff_client(&mut client, &self.cfg.sniff, meta.target.port).await;
            let client: BoxProxyStream =
                Box::new(crate::inbound::PrependStream::new(client, peeked));
            match &sniffed {
                res @ (crate::sniffer::SniffResult::Tls(_)
                | crate::sniffer::SniffResult::Http(_)
                | crate::sniffer::SniffResult::Quic(_)) => {
                    match crate::sniffer::apply_sniffed(&meta.target, res, &self.cfg.sniff) {
                        Some(t) => {
                            tracing::debug!(target: "engine",
                                "sniff {} -> {}", meta.target, t);
                            (t, client)
                        }
                        None => (meta.target.clone(), client),
                    }
                }
                crate::sniffer::SniffResult::Unknown => (meta.target.clone(), client),
            }
        } else {
            (meta.target.clone(), client)
        };
        // /proc scan only when a PROCESS/UID/IN-USER rule can consume it.
        let proc_info = if self.needs_process {
            crate::process::find_info_by_socket(meta.source, true)
        } else {
            None
        };
        let (rule, outbound_name) = self
            .route_with(
                &target,
                meta.source,
                RouteMeta {
                    network: Network::Tcp,
                    inbound: &meta.inbound,
                    inbound_kind: meta.inbound_kind,
                    inbound_port: meta.inbound_port,
                    proc_info: proc_info.as_ref(),
                },
            )
            .await;
        let outbound = match self.registry.resolve(&outbound_name).await {
            Ok(o) => o,
            Err(e) => {
                tracing::warn!(target: "engine", "route {}: {e}", target);
                return;
            }
        };
        if outbound.is_reject() {
            return;
        }
        let (id, counters, cancel) = self.stats.open(&meta.inbound, "tcp", &target, meta.source);
        self.stats.annotate(id, &rule, &outbound_name);
        tracing::debug!(target: "engine",
            "tcp {} -> {} via {} ({})", meta.source, target, outbound_name, rule);

        // Fake-IP targets dial by DOMAIN so the remote resolves the real
        // address (and SNI stays correct).
        let dial_target = self.unfake_target(&target);

        match outbound.connect(&dial_target).await {
            Ok(remote) => {
                let client_side = CountingStream::new(client, counters.clone());
                let remote_side = CountingStream::new(remote, counters.clone());
                let (mut a, mut b) = (client_side, remote_side);
                // The API's DELETE /connections handlers cancel this
                // connection's stats token mid-copy (mihomo connections.go
                // closeConnection/closeAllConnections): winning the select
                // drops the copy future, and the counting streams (and the
                // sockets they wrap) drop at scope end — the client sees
                // EOF while stats.close below folds the counters.
                let result = tokio::select! {
                    r = tokio::io::copy_bidirectional(&mut a, &mut b) => Some(r),
                    _ = cancel.cancelled() => {
                        tracing::debug!(target: "engine",
                            "relay {} via {}: closed by api", target, outbound_name);
                        None
                    }
                };
                if let Some(Err(e)) = &result {
                    tracing::warn!(target: "engine",
                        "relay {} via {}: {e}", target, outbound_name);
                }
            }
            Err(e) => {
                tracing::warn!(target: "engine",
                    "connect {} via {}: {e}", target, outbound_name);
            }
        }
        self.stats.close(id, &counters);
    }

    /// Read the first client bytes (deadline-bounded) and sniff them
    /// with per-protocol port gating. Returns the result plus every
    /// byte read — the caller replays them via `PrependStream`.
    async fn sniff_client(
        client: &mut BoxProxyStream,
        cfg: &crate::sniffer::SniffConfig,
        port: u16,
    ) -> (crate::sniffer::SniffResult, Vec<u8>) {
        use tokio::io::AsyncReadExt;

        let mut buf = Vec::with_capacity(1024);
        let found = tokio::time::timeout(std::time::Duration::from_millis(500), async {
            loop {
                let mut chunk = [0u8; 1024];
                let Ok(n) = client.read(&mut chunk).await else {
                    return crate::sniffer::SniffResult::Unknown;
                };
                if n == 0 {
                    return crate::sniffer::SniffResult::Unknown;
                }
                buf.extend_from_slice(&chunk[..n]);
                match crate::sniffer::sniff(&buf, cfg, port) {
                    crate::sniffer::SniffResult::Unknown => {}
                    found => return found,
                }
                if buf.len() >= crate::sniffer::MAX_SNIFF {
                    return crate::sniffer::SniffResult::Unknown;
                }
            }
        })
        .await
        .unwrap_or(crate::sniffer::SniffResult::Unknown);
        (found, buf)
    }
}

impl RelayHandler for Engine {
    fn handle_tcp(self: Arc<Self>, meta: TcpMeta, client: BoxProxyStream) {
        tokio::spawn(async move {
            self.relay_tcp(meta, client).await;
        });
    }

    fn handle_udp(
        self: Arc<Self>,
        source: SocketAddr,
        inbound: String,
        uplink: mpsc::Receiver<(NetAddr, Vec<u8>)>,
        downlink: mpsc::Sender<(NetAddr, Vec<u8>)>,
    ) {
        tokio::spawn(async move {
            self.relay_udp_inner(source, inbound, uplink, downlink).await;
        });
    }
}

// ---------------------------------------------------------------------------
// UDP relay
// ---------------------------------------------------------------------------

impl Engine {
    async fn relay_udp_inner(
        self: &Arc<Self>,
        source: SocketAddr,
        inbound: String,
        mut uplink: mpsc::Receiver<(NetAddr, Vec<u8>)>,
        downlink: mpsc::Sender<(NetAddr, Vec<u8>)>,
    ) {
        // First packet decides the outbound (rules see the first target).
        let Some((first_target, first_data)) = uplink.recv().await else {
            return;
        };
        let effective = self.unfake_target(&first_target);
        // /proc scan for PROCESS/UID rules works for UDP sessions too.
        let proc_info = if self.needs_process {
            crate::process::find_info_by_socket(source, false)
        } else {
            None
        };
        let (rule, outbound_name) = self
            .route_with(
                &effective,
                source,
                RouteMeta {
                    network: Network::Udp,
                    inbound: &inbound,
                    inbound_kind: "", // UDP sessions carry no listener kind today
                    inbound_port: None,
                    proc_info: proc_info.as_ref(),
                },
            )
            .await;
        let Ok(outbound) = self.registry.resolve(&outbound_name).await else {
            return;
        };
        if !outbound.udp || outbound.is_reject() {
            return;
        }
        let Ok(mut channel) = outbound.udp(&effective).await else {
            tracing::debug!(target: "engine", "udp {} via {}: channel failed", effective, outbound_name);
            return;
        };
        tracing::debug!(target: "engine",
            "udp {} -> {} via {} ({})", source, effective, outbound_name, rule);
        let (id, counters, cancel) = self.stats.open(&inbound, "udp", &effective, source);
        self.stats.annotate(id, &rule, &outbound_name);

        let mut last_active = tokio::time::Instant::now();
        // Send the first packet BEFORE entering the select loop — waiting
        // for a response that the packet itself triggers would deadlock.
        if let Err(e) = channel.send(&self.unfake_target(&first_target), &first_data).await {
            tracing::debug!(target: "engine", "udp send: {e}");
            self.stats.close(id, &counters);
            return;
        }
        loop {
            let timeout = tokio::time::sleep_until(last_active + Duration::from_secs(60));
            tokio::select! {
                _ = timeout => break,
                // API force-close (DELETE /connections[/id]): unwind the
                // session; stats.close below folds the counters.
                _ = cancel.cancelled() => {
                    tracing::debug!(target: "engine",
                        "udp {effective} via {outbound_name}: closed by api");
                    break;
                }
                up = uplink.recv() => {
                    match up {
                        Some((target, data)) => {
                            last_active = tokio::time::Instant::now();
                            if let Err(e) = channel.send(&self.unfake_target(&target), &data).await {
                                tracing::debug!(target: "engine", "udp send: {e}");
                                break;
                            }
                        }
                        None => break,
                    }
                }
                down = channel.recv() => {
                    match down {
                        Ok((from, data)) => {
                            last_active = tokio::time::Instant::now();
                            if downlink.send((from, data)).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            }
        }
        self.stats.close(id, &counters);
    }

    /// Reverse a fake-IP target back to its domain (no-op otherwise):
    /// rules match on the domain and outbounds dial by domain so SNI stays
    /// correct.
    fn unfake_target(&self, target: &NetAddr) -> NetAddr {
        if let (Host::Ip(ip), Some(dns)) = (&target.host, &self.dns) {
            if let Some(domain) = dns.fakeip().and_then(|f| f.reverse(*ip)) {
                return NetAddr::new(Host::Domain(domain), target.port);
            }
        }
        target.clone()
    }
}

fn format_rule(rule: &Rule) -> String {
    let matcher = match &rule.matcher {
        crate::rule::RuleMatcher::Domain(d) => format!("DOMAIN({d})"),
        crate::rule::RuleMatcher::DomainSuffix(s) => format!("DOMAIN-SUFFIX({s})"),
        crate::rule::RuleMatcher::DomainKeyword(k) => format!("DOMAIN-KEYWORD({k})"),
        crate::rule::RuleMatcher::DomainRegex(_) => "DOMAIN-REGEX".to_string(),
        crate::rule::RuleMatcher::IpCidr { net, .. } => format!("IP-CIDR({net:?})"),
        crate::rule::RuleMatcher::GeoIp { country, .. } => format!("GEOIP({country})"),
        crate::rule::RuleMatcher::Geosite { name } => format!("GEOSITE({name})"),
        crate::rule::RuleMatcher::PortDst(p) => format!("DST-PORT({}-{})", p.start, p.end),
        crate::rule::RuleMatcher::PortSrc(p) => format!("SRC-PORT({}-{})", p.start, p.end),
        crate::rule::RuleMatcher::RuleSet { name, .. } => format!("RULE-SET({name})"),
        crate::rule::RuleMatcher::ClashMode(m) => format!("CLASH-MODE({m})"),
        crate::rule::RuleMatcher::Network(n) => format!("NETWORK({})", n.as_str()),
        crate::rule::RuleMatcher::InPort(p) => format!("IN-PORT({}-{})", p.start, p.end),
        crate::rule::RuleMatcher::InName(n) => format!("IN-NAME({n})"),
        crate::rule::RuleMatcher::InType(t) => format!("IN-TYPE({t})"),
        crate::rule::RuleMatcher::Uid(u) => format!("UID({}-{})", u.start, u.end),
        crate::rule::RuleMatcher::InUser(u) => format!("IN-USER({u})"),
        crate::rule::RuleMatcher::Dscp(d) => format!("DSCP({d})"),
        crate::rule::RuleMatcher::IpAsn { asn, .. } => format!("IP-ASN({asn})"),
        crate::rule::RuleMatcher::IpSuffix { suffix, .. } => format!("IP-SUFFIX({suffix})"),
        crate::rule::RuleMatcher::Process { pattern, .. } => format!("PROCESS({pattern})"),
        crate::rule::RuleMatcher::Logic { mode, .. } => format!("LOGIC({mode:?})"),
        crate::rule::RuleMatcher::MatchAll => "MATCH".to_string(),
    };
    format!("{matcher} => {}", rule.outbound)
}

fn load_provider(p: &crate::config::RuleProviderSpec, sets: &mut RuleSets) {
    // Binary formats (.srs / .mrs) are sniffed from the file magic —
    // they override the declared behavior (the binary carries both
    // domain and ip-cidr data) and fold into a classical set.
    if let Ok(bytes) = std::fs::read(&p.path) {
        let parsed: std::result::Result<Vec<String>, crate::error::Error> =
            if bytes.starts_with(b"SRS") {
                crate::ruleset_bin::parse_srs(&bytes).map(|srs| {
                    srs.domains
                        .iter()
                        .map(|d| match d {
                            crate::ruleset_bin::SrsDomain::Exact(v) => format!("DOMAIN,{v},DIRECT"),
                            crate::ruleset_bin::SrsDomain::Suffix(v) => {
                                format!("DOMAIN-SUFFIX,{v},DIRECT")
                            }
                            crate::ruleset_bin::SrsDomain::Keyword(v) => {
                                format!("DOMAIN-KEYWORD,{v},DIRECT")
                            }
                            crate::ruleset_bin::SrsDomain::Regex(v) => {
                                format!("DOMAIN-REGEX,{v},DIRECT")
                            }
                        })
                        .chain(srs.ip_cidrs.iter().map(|c| format!("IP-CIDR,{c},DIRECT")))
                        .collect()
                })
            } else if bytes.starts_with(b"MRS") {
                crate::ruleset_bin::parse_mrs(&bytes).map(|mrs| {
                    mrs.suffixes
                        .iter()
                        .map(|v| format!("DOMAIN-SUFFIX,{v},DIRECT"))
                        .chain(mrs.exacts.iter().map(|v| format!("DOMAIN,{v},DIRECT")))
                        .chain(mrs.ip_cidrs.iter().map(|c| format!("IP-CIDR,{c},DIRECT")))
                        .collect()
                })
            } else {
                Ok(Vec::new())
            };
        if let Ok(lines) = parsed {
            if !lines.is_empty() {
                let rules = lines
                    .iter()
                    .filter_map(|l| match crate::rule::Rule::parse(l) {
                        Ok(r) => Some(r),
                        Err(e) => {
                            tracing::warn!(target: "engine",
                                "provider {}: bad binary rule {l:?}: {e}", p.name);
                            None
                        }
                    })
                    .collect::<Vec<_>>();
                if !rules.is_empty() {
                    sets.insert(p.name.clone(), RuleSetKind::Classical(rules));
                    return;
                }
            }
        } else if let Err(e) = parsed {
            tracing::warn!(target: "engine", "rule provider {} binary: {e}", p.name);
            return;
        }
    }
    let Ok(content) = std::fs::read_to_string(&p.path) else {
        tracing::warn!(target: "engine", "rule provider {}: cannot read {}", p.name, p.path);
        return;
    };
    let kind = match (p.behavior, p.format) {
        (crate::config::ProviderBehavior::Domain, crate::config::ProviderFormat::Text) => {
            let mut m = crate::rule::DomainMatcher::default();
            for line in content.lines() {
                m.add_domain_line(line);
            }
            RuleSetKind::Domain(m)
        }
        (crate::config::ProviderBehavior::IpCidr, crate::config::ProviderFormat::Text) => {
            let mut nets = Vec::new();
            for line in content.lines() {
                let line = line.split('#').next().unwrap_or("").trim();
                if line.is_empty() {
                    continue;
                }
                match line.parse() {
                    Ok(net) => nets.push(net),
                    Err(e) => tracing::warn!(target: "engine", "provider {}: bad cidr {line:?}: {e}", p.name),
                }
            }
            RuleSetKind::IpCidr(nets)
        }
        (crate::config::ProviderBehavior::Classical, crate::config::ProviderFormat::Text) => {
            let mut rules = Vec::new();
            for line in content.lines() {
                let line = line.split('#').next().unwrap_or("").trim();
                if line.is_empty() {
                    continue;
                }
                // Classical text: bare domains/cidrs default to the
                // provider target DIRECT (mihomo requires full lines).
                match crate::rule::Rule::parse(line) {
                    Ok(r) => rules.push(r),
                    Err(_) => {
                        // Fallback: treat as domain suffix.
                        rules.push(
                            crate::rule::Rule::parse(&format!("DOMAIN-SUFFIX,{line},DIRECT"))
                                .unwrap_or_else(|_| {
                                    crate::rule::Rule {
                                        matcher: crate::rule::RuleMatcher::MatchAll,
                                        outbound: "DIRECT".into(),
                                    }
                                }),
                        );
                    }
                }
            }
            RuleSetKind::Classical(rules)
        }
        (behavior, format) => {
            tracing::warn!(target: "engine",
                "rule provider {}: behavior {behavior:?} with format {format:?} not supported yet",
                p.name);
            return;
        }
    };
    sets.insert(p.name.clone(), kind);
}

/// DNS hijack server (UDP + TCP with length-prefix framing).
async fn spawn_dns_server(listen: &str, dns: Arc<DnsEngine>) -> Result<()> {
    let addr: SocketAddr = listen
        .parse()
        .map_err(|_| Error::config(format!("bad dns listen {listen:?}")))?;
    // UDP.
    let udp = tokio::net::UdpSocket::bind(addr)
        .await
        .map_err(|e| Error::network(format!("dns bind {addr}: {e}")))?;
    let udp_local = udp.local_addr().ok();
    tracing::info!(target: "engine", "dns listening on {:?}", udp_local);
    let udp = Arc::new(udp);
    tokio::spawn({
        let udp = udp.clone();
        let dns = dns.clone();
        async move {
            let mut buf = vec![0u8; 4096];
            loop {
                let Ok((n, peer)) = udp.recv_from(&mut buf).await else {
                    continue;
                };
                let query = buf[..n].to_vec();
                let udp = udp.clone();
                let dns = dns.clone();
                tokio::spawn(async move {
                    let resp = dns.handle(&query).await;
                    if !resp.is_empty() {
                        let _ = udp.send_to(&resp, peer).await;
                    }
                });
            }
        }
    });
    // TCP + DoH on the same port (mihomo parity: an HTTP request on the
    // TCP DNS port is served as RFC 8484 over HTTP/1.1; anything else
    // is length-framed wireformat).
    let tcp = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| Error::network(format!("dns tcp bind {addr}: {e}")))?;
    tokio::spawn(async move {
        loop {
            let Ok((mut sock, _)) = tcp.accept().await else {
                continue;
            };
            let dns = dns.clone();
            tokio::spawn(async move {
                serve_dns_tcp(&mut sock, dns).await;
            });
        }
    });
    Ok(())
}

/// One DNS-over-TCP connection: first two bytes disambiguate DoH from
/// the length-framed wireformat (an HTTP method start vs a frame
/// length), re-checked between requests for keep-alive.
async fn serve_dns_tcp(sock: &mut tokio::net::TcpStream, dns: Arc<DnsEngine>) {
    use tokio::io::AsyncReadExt;
    let mut pre = [0u8; 2];
    if sock.read_exact(&mut pre).await.is_err() {
        return;
    }
    loop {
        if is_http_prefix(&pre) {
            serve_doh_connection(sock, dns, pre).await;
            return;
        }
        let n = u16::from_be_bytes(pre) as usize;
        if !(12..=4096).contains(&n) {
            return;
        }
        let mut query = vec![0u8; n];
        if sock.read_exact(&mut query).await.is_err() {
            return;
        }
        let resp = dns.handle(&query).await;
        if resp.is_empty() {
            return;
        }
        let mut framed = (resp.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&resp);
        if sock.write_all(&framed).await.is_err() {
            return;
        }
        if sock.read_exact(&mut pre).await.is_err() {
            return;
        }
    }
}

fn is_http_prefix(pre: &[u8; 2]) -> bool {
    matches!(pre, b"GE" | b"PO" | b"PU" | b"DE" | b"HE" | b"OP")
}

/// Minimal RFC 8484 HTTP/1.1 server on the DNS TCP port: POST/GET
/// /dns-query with a wireformat body (Content-Length bounded; no
/// chunked — DoH clients universally send Content-Length). Serves
/// keep-alive until the peer stops sending HTTP.
async fn serve_doh_connection(
    sock: &mut tokio::net::TcpStream,
    dns: Arc<DnsEngine>,
    first_pre: [u8; 2],
) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let _ = sock.set_nodelay(true);
    let mut pre = first_pre;
    loop {
        // Read the request head (2 method bytes already consumed).
        let mut buf = pre.to_vec();
        loop {
            let mut byte = [0u8; 1];
            if sock.read_exact(&mut byte).await.is_err() {
                return;
            }
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") {
                break;
            }
            if buf.len() > 16 * 1024 {
                return;
            }
        }
        let head = String::from_utf8_lossy(&buf);
        let mut lines = head.split("\r\n");
        let request_line = lines.next().unwrap_or_default().to_string();
        let mut parts = request_line.split_whitespace();
        let method = parts.next().unwrap_or_default().to_ascii_uppercase();
        let path = parts.next().unwrap_or_default().to_string();
        let mut content_length = 0usize;
        let mut keep_alive = false;
        for line in lines {
            let Some((k, v)) = line.split_once(':') else { continue };
            let v = v.trim();
            if k.eq_ignore_ascii_case("content-length") {
                content_length = v.parse().unwrap_or(0);
            }
            if k.eq_ignore_ascii_case("connection") && v.eq_ignore_ascii_case("keep-alive") {
                keep_alive = true;
            }
        }
        if content_length > 64 * 1024 {
            return;
        }
        let query: Option<Vec<u8>> = if method == "POST" {
            let mut body = vec![0u8; content_length];
            if sock.read_exact(&mut body).await.is_err() {
                return;
            }
            Some(body)
        } else if method == "GET" {
            extract_doh_get(&path)
        } else {
            None
        };
        let Some(query) = query.filter(|q| q.len() >= 12) else {
            let resp = if method == "GET" || method == "POST" {
                "HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n"
            } else {
                "HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n"
            };
            let _ = sock.write_all(resp.as_bytes()).await;
            return;
        };
        let answer = dns.handle(&query).await;
        if answer.is_empty() {
            let resp = "HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n";
            let _ = sock.write_all(resp.as_bytes()).await;
            return;
        }
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\n\r\n",
            answer.len()
        );
        let mut resp = head.into_bytes();
        resp.extend_from_slice(&answer);
        if sock.write_all(&resp).await.is_err() {
            return;
        }
        if !keep_alive {
            return;
        }
        if sock.read_exact(&mut pre).await.is_err() || !is_http_prefix(&pre) {
            return;
        }
    }
}

/// `?dns=<base64url-unpadded>` from a GET query string.
fn extract_doh_get(path: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    let raw = path.split_once("?dns=")?.1.split('&').next()?;
    let std = raw.replace('-', "+").replace('_', "/");
    let mut b = std.into_bytes();
    while b.len() % 4 != 0 {
        b.push(b'=');
    }
    base64::engine::general_purpose::STANDARD.decode(&b).ok()
}

async fn wait_for_shutdown() {
    use tokio::signal::unix::{signal, SignalKind};
    let mut term = signal(SignalKind::terminate()).expect("SIGTERM handler");
    let mut int = signal(SignalKind::interrupt()).expect("SIGINT handler");
    tokio::select! {
        _ = term.recv() => {}
        _ = int.recv() => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{DnsConfig, EngineConfig};
    use crate::inbound::{ListenerConfig, ListenerKind};

    fn minimal_config() -> EngineConfig {
        EngineConfig {
            mode: RuleMode::Rule,
            ipv6: false,
            listeners: vec![ListenerConfig {
                tag: "mixed".into(),
                bind: "127.0.0.1".into(),
                port: 0,
                kind: ListenerKind::Mixed,
            }],
            outbounds: vec![],
            groups: vec![],
            rules: vec!["MATCH,DIRECT".into()],
            sniff: Default::default(),
            dns: Some(DnsConfig {
            fakeip_store: None,
                enable: true,
                listen: Some("127.0.0.1:0".into()),
                ..Default::default()
            }),
            api: None,
            rule_providers: vec![],
            geo: Default::default(),
            proxy_servers: vec![],
            tun: None,
            wg_endpoints: vec![],
        }
        .with_builtin_outbounds()
    }

    #[tokio::test]
    async fn engine_builds_and_routes_to_direct() {
        let engine = Engine::build(minimal_config()).unwrap();
        let (rule, outbound) = engine
            .route_with(
                &NetAddr::domain("example.com", 443).unwrap(),
                "127.0.0.1:50000".parse().unwrap(),
                RouteMeta {
                    network: Network::Tcp,
                    inbound: "",
                    inbound_kind: "",
                    inbound_port: None,
                    proc_info: None,
                },
            )
            .await;
        assert_eq!(outbound, "DIRECT");
        assert!(rule.contains("MATCH"));
    }

    #[tokio::test]
    async fn global_mode_uses_first_group() {
        let mut cfg = minimal_config();
        cfg.mode = RuleMode::Global;
        cfg.groups = vec![crate::outbound::GroupConfig {
            name: "Auto".into(),
            members: vec!["DIRECT".into()],
            policy: crate::outbound::GroupPolicy::Select,
            url: None,
            interval: 0,
            tolerance: 0,
        }];
        let engine = Engine::build(cfg).unwrap();
        let (_, outbound) = engine
            .route_with(
                &NetAddr::domain("x.test", 80).unwrap(),
                "127.0.0.1:1".parse().unwrap(),
                RouteMeta {
                    network: Network::Tcp,
                    inbound: "",
                    inbound_kind: "",
                    inbound_port: None,
                    proc_info: None,
                },
            )
            .await;
        assert_eq!(outbound, "Auto");
    }

    #[tokio::test]
    async fn dns_server_answers_fakeip() {
        let engine = Engine::build(minimal_config()).unwrap();
        let dns = engine.dns().unwrap().clone();
        let resp = dns.handle(&wire::build_query(3, "probe.test", wire::TYPE_A)).await;
        let msg = wire::parse(&resp).unwrap();
        assert_eq!(msg.answers.len(), 1);
    }

    #[tokio::test]
    async fn dns_tcp_port_serves_doh_and_framed() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let engine = super::Engine::build(minimal_config()).unwrap();
        let dns = engine.dns().unwrap().clone();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn({
            let dns = dns.clone();
            async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else { continue };
                    let dns = dns.clone();
                    tokio::spawn(async move {
                        serve_dns_tcp(&mut sock, dns).await;
                    });
                }
            }
        });

        // DoH POST.
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        let q = wire::build_query(7, "probe.test", wire::TYPE_A);
        let req = format!(
            "POST /dns-query HTTP/1.1\r\nHost: dns.test\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            q.len()
        );
        c.write_all(req.as_bytes()).await.unwrap();
        c.write_all(&q).await.unwrap();
        let mut resp = Vec::new();
        c.read_to_end(&mut resp).await.unwrap();
        // Keep bytes: the DNS answer is binary (fake-ip bytes >= 0x80).
        assert!(resp.starts_with(b"HTTP/1.1 200 OK"));
        let head_end = resp.windows(4).position(|w| w == b"\r\n\r\n").unwrap();
        assert!(resp[..head_end].starts_with(b"HTTP/1.1 200 OK"));
        let msg = wire::parse(&resp[head_end + 4..]).unwrap();
        assert_eq!(msg.id, 7);

        // GET with ?dns=.
        use base64::Engine;
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(&q);
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        let req = format!("GET /dns-query?dns={b64} HTTP/1.1\r\nHost: dns.test\r\nConnection: close\r\n\r\n");
        c.write_all(req.as_bytes()).await.unwrap();
        let mut resp = Vec::new();
        c.read_to_end(&mut resp).await.unwrap();
        assert!(resp.starts_with(b"HTTP/1.1 200 OK"));

        // Length-framed TCP DNS still works on the same port.
        let mut c = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut framed = (q.len() as u16).to_be_bytes().to_vec();
        framed.extend_from_slice(&q);
        c.write_all(&framed).await.unwrap();
        let mut len = [0u8; 2];
        c.read_exact(&mut len).await.unwrap();
        let n = u16::from_be_bytes(len) as usize;
        let mut body = vec![0u8; n];
        c.read_exact(&mut body).await.unwrap();
        let msg = wire::parse(&body).unwrap();
        assert_eq!(msg.id, 7);
    }
}
