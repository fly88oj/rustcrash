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
use crate::rule::{ConnContext, GeoLookups, MatchOutcome, Network, Rule, RuleSetKind, RuleSets};
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
    /// The compiled action-aware rule table the router walks
    /// (`action: sniff/resolve/hijack-dns` ride a per-index side table;
    /// the plain mihomo walk is the no-actions degenerate case).
    rule_table: crate::rule::RuleTable,
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
    /// Last time each GROUP was routed through (mihomo healthcheck.go
    /// `touch`): a lazy group's periodic check only runs when this is
    /// within its interval.
    last_touch: std::sync::Mutex<std::collections::HashMap<String, std::time::Instant>>,
}

impl Engine {
    /// Build (without starting) from a normalized config: loads rule
    /// providers, geo databases, and constructs the outbound registry.
    pub fn build(cfg: EngineConfig) -> Result<Arc<Self>> {
        // Log broadcast tap (the /logs endpoint's event source): create
        // the process-wide bus and best-effort install it as the
        // global tracing subscriber. Must precede any engine tracing
        // that /logs should carry.
        crate::api::init_log_broadcast();

        let cfg = cfg.with_builtin_outbounds();
        let rule_table = cfg.compile_rules()?;
        let rules = rule_table.rules();
        let rule_sets = RuleSets::default();
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
        for r in rules {
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
            load_provider(p, &rule_sets);
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
        let needs_process = rule_table.needs_process();
        let needs_ip = rule_table.needs_ip();

        let engine = Arc::new(Engine {
            cfg,
            registry,
            rule_table,
            rule_sets,
            geo,
            dns,
            stats: Stats::new(),
            mode,
            needs_process,
            needs_ip,
            last_touch: std::sync::Mutex::new(std::collections::HashMap::new()),
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
        self.rule_table.rules()
    }

    pub async fn mode(&self) -> RuleMode {
        *self.mode.read().await
    }

    pub async fn set_mode(&self, mode: RuleMode) {
        *self.mode.write().await = mode;
    }

    /// Runtime rule-provider reload — mihomo hub/route/provider.go
    /// updateRuleProvider → `RP.Initial()` re-fetch: re-read the
    /// provider's file, re-parse it, and swap the matcher set behind
    /// rule evaluation. The set is fully built BEFORE the swap, so a
    /// parse failure leaves the live table untouched; on success the
    /// next relay's RULE-SET evaluation follows the new set (in-flight
    /// evaluations keep the snapshot they cloned).
    pub fn reload_rule_provider(&self, name: &str) -> std::result::Result<(), String> {
        let Some(spec) = self.cfg.rule_providers.iter().find(|p| p.name == name) else {
            return Err(format!("provider {name:?} not found"));
        };
        let kind = try_load_provider(spec)?;
        self.rule_sets.insert(spec.name.clone(), kind);
        tracing::info!(target: "engine",
            "rule provider {} reloaded from {}", spec.name, spec.path);
        Ok(())
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

        // Health checks for url-test/fallback groups — per-group lazy
        // gating exactly per mihomo adapter/provider/healthcheck.go
        // process(): on each interval tick, a lazy group that has not
        // been touched (routed through) within its interval skips the
        // round; each probe counts only when its status matches the
        // group's expected-status.
        let any_health = self
            .cfg
            .groups
            .iter()
            .any(|g| matches!(g.policy, crate::outbound::GroupPolicy::UrlTest | crate::outbound::GroupPolicy::Fallback));
        if any_health {
            let engine = self.clone();
            tokio::spawn(async move {
                loop {
                    engine.health_tick().await;
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
    /// callers pass a synthetic one. `sniffable` lends the caller's
    /// client stream so an `action: sniff` rule can read the first
    /// bytes at match time (None when the caller cannot sniff — UDP
    /// sessions today); the stream is always handed back. Returns
    /// (rule display, outbound, effective target) — the effective
    /// target is what the relay should DIAL: unfaked, and with the
    /// sniffed host applied when a sniff action overrode it.
    async fn route_with(
        &self,
        target: &NetAddr,
        source: SocketAddr,
        meta: RouteMeta<'_>,
        sniffable: Option<&mut Option<BoxProxyStream>>,
    ) -> (String, String, NetAddr) {
        let mode = *self.mode.read().await;
        let routed = match mode {
            RuleMode::Direct => {
                ("mode:direct".into(), "DIRECT".into(), self.unfake_target(target))
            }
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
                ("mode:global".into(), name, self.unfake_target(target))
            }
            RuleMode::Rule => self.route_rules(target, source, meta, sniffable).await,
        };
        // mihomo healthcheck.go `touch`: routing through a group marks it
        // used, so a lazy group's next interval tick runs its check
        // (idle lazy groups skip). Only the group the ROUTE selected is
        // touched; transitive sub-groups keep their own touches.
        if self.registry.group(&routed.1).is_some() {
            self.last_touch
                .lock()
                .unwrap()
                .insert(routed.1.clone(), std::time::Instant::now());
        }
        routed
    }

    /// The rule-mode walk: sing-box route/route.go `matchRule`
    /// semantics — the first matching rule routes UNLESS it carries a
    /// non-final action (`sniff`/`resolve`), in which case the action
    /// mutates the match context and the walk CONTINUES from the next
    /// rule instead of restarting. `resume_at` strictly increases, so
    /// the loop runs at most rules.len() steps; the iteration cap is a
    /// defensive guard. Without actions (mihomo dialect) this is exactly
    /// the old single-pass walk.
    async fn route_rules(
        &self,
        target: &NetAddr,
        source: SocketAddr,
        meta: RouteMeta<'_>,
        mut sniffable: Option<&mut Option<BoxProxyStream>>,
    ) -> (String, String, NetAddr) {
        // Reverse fake-ip before matching.
        let mut effective = self.unfake_target(target);

        // One pre-resolve for every IP-hungry rule (IP-CIDR/GEOIP/rule-set
        // without no-resolve); the evaluator itself stays synchronous. A
        // walk-time `action: resolve` fills the same field on demand.
        let mut resolved = self.pre_resolve(&effective).await;

        let cap = self.rule_table.rules().len() + 1;
        let mut at = 0usize;
        for _ in 0..cap {
            let ctx = ConnContext {
                host: &effective.host,
                port: effective.port,
                source_ip: Some(source.ip()),
                source_port: Some(source.port()),
                resolved: resolved.clone(),
                mode: RuleMode::Rule,
                network: meta.network,
                inbound: meta.inbound,
                inbound_kind: meta.inbound_kind,
                inbound_port: meta.inbound_port,
                process: meta.proc_info.map(|p| p.exe.as_str()),
                uid: meta.proc_info.and_then(|p| p.uid),
                user: meta.proc_info.and_then(|p| p.user.as_deref()),
                dscp: None,
            };
            match self.rule_table.match_from(at, &ctx, &self.rule_sets, &self.geo) {
                MatchOutcome::Route { rule, .. } => {
                    return (format_rule(rule), rule.outbound.clone(), effective);
                }
                MatchOutcome::Sniff { action, resume_at, .. } => {
                    // The action sniffs independently of the config-level
                    // sniffer: its protocol subset (empty = all) narrows
                    // the global policy via for_action, and every byte
                    // read is replayed loss-free below (PrependStream),
                    // exactly like the config-level sniff in relay_tcp.
                    // (The walk only yields Sniff for a Sniff action.)
                    let crate::rule::RuleAction::Sniff { sniffer } = action else {
                        at = resume_at;
                        continue;
                    };
                    let sniff_cfg = self.cfg.sniff.for_action(sniffer);
                    if let Some(slot) = sniffable.as_deref_mut() {
                        if let Some(mut stream) = slot.take() {
                            let (sniffed, peeked) =
                                Self::sniff_client(&mut stream, &sniff_cfg, effective.port).await;
                            let stream: BoxProxyStream = if peeked.is_empty() {
                                stream
                            } else {
                                Box::new(crate::inbound::PrependStream::new(stream, peeked))
                            };
                            *slot = Some(stream);
                            // Shared override policy (apply_sniffed): an IP
                            // target always takes the sniffed domain; a
                            // domain target only with override-destination
                            // or a force-domain match.
                            if let Some(t) =
                                crate::sniffer::apply_sniffed(&effective, &sniffed, &sniff_cfg)
                            {
                                tracing::debug!(target: "engine",
                                    "action sniff {} -> {}", effective, t);
                                effective = t;
                                // The pre-resolve belonged to the old
                                // host: re-derive (or clear) for the new
                                // one.
                                resolved = self.pre_resolve(&effective).await;
                            }
                        }
                    }
                    at = resume_at;
                }
                MatchOutcome::Resolve { resume_at, .. } => {
                    // `action: resolve`: fill ConnContext::resolved from
                    // the engine resolver (mirrors the pre-resolve above;
                    // IP targets need nothing — ctx.ips() reads them
                    // directly).
                    if let (Some(dns), Some(name)) = (&self.dns, effective.host.as_domain()) {
                        if !name.is_empty() {
                            resolved = dns.resolve(name, wire::TYPE_A).await;
                        }
                    }
                    at = resume_at;
                }
                MatchOutcome::HijackDns { index } => {
                    // Route to the registry's `dns` outbound (sing-box's
                    // builtin tag): its TCP arm answers length-framed
                    // DNS-over-TCP and its UDP arm echoes datagrams, both
                    // via the engine resolver.
                    let rule = &self.rule_table.rules()[index];
                    return (
                        format_rule_target(rule, "hijack-dns"),
                        "dns".to_string(),
                        effective,
                    );
                }
                MatchOutcome::NoMatch => break,
            }
        }
        ("no-match".into(), "DIRECT".into(), effective)
    }

    /// The router's single pre-resolve: when any rule is IP-hungry and
    /// the target is a domain, resolve it once up front (None keeps the
    /// walk IP-blind; `action: resolve` fills the field later).
    async fn pre_resolve(&self, target: &NetAddr) -> Option<Vec<std::net::IpAddr>> {
        match (&self.dns, target.host.as_domain()) {
            (Some(dns), Some(name)) if self.needs_ip && !name.is_empty() => {
                dns.resolve(name, wire::TYPE_A).await
            }
            _ => None,
        }
    }

    /// One health-check tick (the run() interval task's body, mihomo
    /// healthcheck.go process()): compute the due set — every
    /// url-test/fallback group whose lazy gate passes (non-lazy always
    /// due; lazy due iff touched within its interval) — and probe it,
    /// scoring each member against the group's expected-status.
    pub async fn health_tick(&self) {
        let now = std::time::Instant::now();
        let mut due: Vec<(String, crate::config::ExpectedStatus)> = Vec::new();
        {
            let touches = self.last_touch.lock().unwrap();
            for g in &self.cfg.groups {
                if !matches!(
                    g.policy,
                    crate::outbound::GroupPolicy::UrlTest | crate::outbound::GroupPolicy::Fallback
                ) {
                    continue;
                }
                let interval = Duration::from_secs(g.interval.max(1));
                let health = self.cfg.group_health(&g.name);
                let last_touch = touches.get(&g.name).copied();
                if health.due(interval, last_touch, now) {
                    due.push((g.name.clone(), health.expected_status));
                }
            }
        }
        self.registry.health_round(&due).await;
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
        // The client stream rides an Option slot so an `action: sniff`
        // rule can borrow it for the first-bytes sniff inside route_with
        // (bytes replayed loss-free); route_with always hands it back.
        let mut client_slot = Some(client);
        let (rule, outbound_name, target) = self
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
                Some(&mut client_slot),
            )
            .await;
        let client = client_slot.expect("route_with returns the client stream");
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
        let (rule, outbound_name, effective) = self
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
                None,
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
    format_rule_target(rule, &rule.outbound)
}

/// Matcher rendering with an explicit target — action outcomes display
/// the action name instead of the converted line's placeholder outbound.
fn format_rule_target(rule: &Rule, target: &str) -> String {
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
    format!("{matcher} => {target}")
}

/// Config-build provider load: parse the file and insert the set,
/// warning (never failing) on error — a bad provider must not abort
/// engine startup. Runtime reload uses [`Engine::reload_rule_provider`],
/// which surfaces the same errors to the API caller.
fn load_provider(p: &crate::config::RuleProviderSpec, sets: &RuleSets) {
    match try_load_provider(p) {
        Ok(kind) => sets.insert(p.name.clone(), kind),
        Err(e) => tracing::warn!(target: "engine", "rule provider {}: {e}", p.name),
    }
}

/// Read and parse one rule-provider file into a fresh set — the shared
/// path between config-build loading and the runtime reload. `Err`
/// carries the human-facing reason (surfaced as the 503 body by
/// `PUT /providers/rules/{name}`, mirroring upstream's
/// updateRuleProvider → provider.Update() error path).
fn try_load_provider(p: &crate::config::RuleProviderSpec) -> std::result::Result<RuleSetKind, String> {
    let bytes = std::fs::read(&p.path)
        .map_err(|e| format!("cannot read {}: {e}", p.path))?;
    // Binary formats (.srs / .mrs) are sniffed from the file magic —
    // they override the declared behavior (the binary carries both
    // domain and ip-cidr data) and fold into a classical set.
    if bytes.starts_with(b"SRS") || bytes.starts_with(b"MRS") {
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
            } else {
                crate::ruleset_bin::parse_mrs(&bytes).map(|mrs| {
                    mrs.suffixes
                        .iter()
                        .map(|v| format!("DOMAIN-SUFFIX,{v},DIRECT"))
                        .chain(mrs.exacts.iter().map(|v| format!("DOMAIN,{v},DIRECT")))
                        .chain(mrs.ip_cidrs.iter().map(|c| format!("IP-CIDR,{c},DIRECT")))
                        .collect()
                })
            };
        match parsed {
            Ok(lines) if !lines.is_empty() => {
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
                    return Ok(RuleSetKind::Classical(rules));
                }
                // An empty binary folds through to the text path below,
                // matching the config-build loader.
            }
            Ok(_) => { /* empty binary: fall through to text */ }
            Err(e) => return Err(format!("binary parse: {e}")),
        }
    }
    let content = String::from_utf8(bytes)
        .map_err(|_| format!("{} is not valid UTF-8 text", p.path))?;
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
            return Err(format!(
                "behavior {behavior:?} with format {format:?} not supported yet"
            ));
        }
    };
    Ok(kind)
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
            group_health: Default::default(),
            rule_actions: Default::default(),
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
        let (rule, outbound, _) = engine
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
                None,
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
        let (_, outbound, _) = engine
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
                None,
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

    // -----------------------------------------------------------------
    // Rule-action re-entry (sing-box `action:` rules) + health glue
    // -----------------------------------------------------------------

    /// Hand-built minimal TLS ClientHello carrying `sni` (same shape as
    /// the sniffer's own fixture: record → handshake → SNI extension).
    fn client_hello(sni: &str) -> Vec<u8> {
        let name = sni.as_bytes();
        let mut ext = Vec::new();
        ext.extend_from_slice(&((name.len() + 3) as u16).to_be_bytes());
        ext.push(0x00); // host_name
        ext.extend_from_slice(&(name.len() as u16).to_be_bytes());
        ext.extend_from_slice(name);
        let mut ext_block = Vec::new();
        ext_block.extend_from_slice(&0u16.to_be_bytes()); // server_name type
        ext_block.extend_from_slice(&(ext.len() as u16).to_be_bytes());
        ext_block.extend_from_slice(&ext);

        let mut body = Vec::new();
        body.push(0x01); // ClientHello
        body.extend_from_slice(&[0, 0, 0]); // length, patched below
        body.extend_from_slice(&0x0303u16.to_be_bytes());
        body.extend(&[0x42u8; 32]); // random
        body.push(0); // session_id_len
        body.extend_from_slice(&2u16.to_be_bytes()); // cipher_suites len
        body.extend_from_slice(&0x1301u16.to_be_bytes());
        body.push(1); // compression methods len
        body.push(0);
        body.extend_from_slice(&(ext_block.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext_block);
        let handshake_len = (body.len() - 4) as u32;
        body[1..4].copy_from_slice(&handshake_len.to_be_bytes()[1..4]);

        let mut rec = Vec::new();
        rec.push(0x16);
        rec.extend_from_slice(&0x0301u16.to_be_bytes());
        rec.extend_from_slice(&(body.len() as u16).to_be_bytes());
        rec.extend_from_slice(&body);
        rec
    }

    /// A minimal in-test SOCKS5 upstream: completes the no-auth
    /// handshake, grants every CONNECT (recording the requested target),
    /// then serves one canned HTTP status to whatever follows. The
    /// handshake count is the "was this outbound used / probed" signal.
    async fn spawn_socks_upstream(
        status_line: &'static str,
    ) -> (
        SocketAddr,
        std::sync::Arc<std::sync::atomic::AtomicUsize>,
        std::sync::Arc<std::sync::Mutex<Vec<String>>>,
    ) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let count = std::sync::Arc::new(AtomicUsize::new(0));
        let targets = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        tokio::spawn({
            let count = count.clone();
            let targets = targets.clone();
            async move {
                loop {
                    let Ok((mut sock, _)) = listener.accept().await else {
                        continue;
                    };
                    let count = count.clone();
                    let targets = targets.clone();
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        // Greeting: VER NMETHODS METHODS...
                        let mut head = [0u8; 2];
                        if sock.read_exact(&mut head).await.is_err() {
                            return;
                        }
                        let mut methods = vec![0u8; head[1] as usize];
                        if sock.read_exact(&mut methods).await.is_err() {
                            return;
                        }
                        if sock.write_all(&[0x05, 0x00]).await.is_err() {
                            return;
                        }
                        // Request: VER CMD RSV ATYP ...
                        let mut req = [0u8; 4];
                        if sock.read_exact(&mut req).await.is_err() {
                            return;
                        }
                        let tail = match req[3] {
                            0x01 => 4 + 2,
                            0x03 => {
                                let mut l = [0u8; 1];
                                if sock.read_exact(&mut l).await.is_err() {
                                    return;
                                }
                                l[0] as usize + 2
                            }
                            0x04 => 16 + 2,
                            _ => return,
                        };
                        let mut rest = vec![0u8; tail];
                        if sock.read_exact(&mut rest).await.is_err() {
                            return;
                        }
                        if req[3] == 0x03 && tail >= 2 {
                            let n = tail - 2;
                            targets
                                .lock()
                                .unwrap()
                                .push(String::from_utf8_lossy(&rest[..n]).to_string());
                        }
                        // Grant.
                        let ok = [0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
                        if sock.write_all(&ok).await.is_err() {
                            return;
                        }
                        count.fetch_add(1, Ordering::SeqCst);
                        // Serve the follow-up request (health probe GET /
                        // replayed sniff bytes), then close.
                        let mut buf = Vec::new();
                        let mut byte = [0u8; 1];
                        loop {
                            match sock.read(&mut byte).await {
                                Ok(0) | Err(_) => break,
                                Ok(_) => {
                                    buf.push(byte[0]);
                                    if buf.ends_with(b"\r\n\r\n") || buf.len() > 16 * 1024 {
                                        break;
                                    }
                                }
                            }
                        }
                        let resp = format!(
                            "HTTP/1.1 {status_line}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                        );
                        let _ = sock.write_all(resp.as_bytes()).await;
                    });
                }
            }
        });
        (addr, count, targets)
    }

    fn socks_outbound(name: &str, server: &str, port: u16) -> crate::outbound::OutboundConfig {
        crate::outbound::OutboundConfig {
            name: name.into(),
            udp: false,
            kind: crate::outbound::OutboundKind::Socks {
                server: server.into(),
                port,
                username: None,
                password: None,
            },
        }
    }

    fn tcp_meta(target: NetAddr, source: SocketAddr) -> TcpMeta {
        TcpMeta {
            target,
            source,
            inbound: "in".into(),
            inbound_port: Some(17890),
            inbound_kind: "mixed",
        }
    }

    /// `action: sniff` re-enters the walk with the sniffed host: a real
    /// TLS ClientHello through an in-test listener (the client pair)
    /// makes the SNI replace the bare-IP destination, so the LATER
    /// DOMAIN-SUFFIX rule routes to the socks upstream — which sees a
    /// CONNECT for the sniffed domain.
    #[cfg(feature = "singbox")]
    #[tokio::test]
    async fn sniff_action_reroutes_on_sniffed_sni() {
        use tokio::io::AsyncWriteExt;
        let (upstream, count, targets) = spawn_socks_upstream("204 No Content").await;
        let cfg = crate::config_singbox::load(&format!(
            r#"{{
              "inbounds": [{{"type": "mixed", "listen": "127.0.0.1", "listen_port": 17890, "tag": "in"}}],
              "outbounds": [
                {{"type": "direct", "tag": "direct"}},
                {{"type": "socks", "tag": "probe-b", "server": "127.0.0.1", "server_port": {}}}
              ],
              "route": {{"rules": [
                {{"port": 443, "action": "sniff", "sniffer": ["tls"]}},
                {{"domain_suffix": ["sniffed.test"], "outbound": "probe-b"}}
              ], "final": "direct"}}
            }}"#,
            upstream.port()
        ))
        .unwrap();
        let engine = Engine::build(cfg).unwrap();

        // The inbound client: a real TCP pair (listener stands in for
        // the inbound); the test side writes the ClientHello.
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let laddr = listener.local_addr().unwrap();
        let mut test_client = tokio::net::TcpStream::connect(laddr).await.unwrap();
        let (client_sock, peer) = listener.accept().await.unwrap();
        test_client.write_all(&client_hello("www.sniffed.test")).await.unwrap();

        let relay_engine = engine.clone();
        let relay = tokio::spawn(async move {
            relay_engine
                .relay_tcp(
                    tcp_meta(NetAddr::ip("203.0.113.9".parse().unwrap(), 443), peer),
                    Box::new(client_sock),
                )
                .await;
        });

        // The socks upstream granted a CONNECT — for the SNI domain.
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while count.load(std::sync::atomic::Ordering::SeqCst) == 0 {
            assert!(std::time::Instant::now() < deadline, "upstream never saw the CONNECT");
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        drop(test_client); // EOF unwinds the relay copy
        let _ = tokio::time::timeout(Duration::from_secs(5), relay).await;
        let seen = targets.lock().unwrap();
        assert!(
            seen.iter().any(|t| t == "www.sniffed.test"),
            "CONNECT targets: {seen:?}"
        );
    }

    /// `action: resolve` fills `resolved` at walk time: the IP-CIDR rule
    /// carries no-resolve (so the router's pre-resolve is OFF) and only
    /// matches after the action resolved the domain through the engine
    /// resolver (static hosts).
    #[tokio::test]
    async fn resolve_action_fills_resolved_for_ip_rules() {
        let mut cfg = minimal_config();
        cfg.rules = vec![
            "DOMAIN,ipflag.test,-".into(), // action: resolve rides index 0
            "IP-CIDR,203.0.113.0/24,PROXY-OUT,no-resolve".into(),
        ];
        cfg.rule_actions =
            std::collections::HashMap::from([(0, crate::rule::RuleAction::Resolve)]);
        cfg.outbounds.push(crate::outbound::OutboundConfig {
            name: "PROXY-OUT".into(),
            udp: false,
            kind: crate::outbound::OutboundKind::Reject,
        });
        if let Some(d) = &mut cfg.dns {
            d.hosts.insert(
                "ipflag.test".into(),
                vec!["203.0.113.7".parse().unwrap()],
            );
        }
        let engine = Engine::build(cfg).unwrap();
        let (rule, outbound, _) = engine
            .route_with(
                &NetAddr::domain("ipflag.test", 80).unwrap(),
                "127.0.0.1:50000".parse().unwrap(),
                RouteMeta {
                    network: Network::Tcp,
                    inbound: "",
                    inbound_kind: "",
                    inbound_port: None,
                    proc_info: None,
                },
                None,
            )
            .await;
        assert_eq!(outbound, "PROXY-OUT", "IP-CIDR must match after the resolve action");
        assert!(rule.contains("IP-CIDR"), "{rule}");

        // Control: strip the action and the same walk stays IP-blind
        // (no-resolve suppresses the pre-resolve) → no-match → DIRECT.
        let mut bare = minimal_config();
        bare.rules = vec![
            "DOMAIN,ipflag.test,DIRECT".into(),
            "IP-CIDR,203.0.113.0/24,PROXY-OUT,no-resolve".into(),
        ];
        bare.outbounds.push(crate::outbound::OutboundConfig {
            name: "PROXY-OUT".into(),
            udp: false,
            kind: crate::outbound::OutboundKind::Reject,
        });
        if let Some(d) = &mut bare.dns {
            d.hosts.insert(
                "ipflag.test".into(),
                vec!["203.0.113.7".parse().unwrap()],
            );
        }
        let engine = Engine::build(bare).unwrap();
        let (_, outbound, _) = engine
            .route_with(
                &NetAddr::domain("ipflag.test", 80).unwrap(),
                "127.0.0.1:50000".parse().unwrap(),
                RouteMeta {
                    network: Network::Tcp,
                    inbound: "",
                    inbound_kind: "",
                    inbound_port: None,
                    proc_info: None,
                },
                None,
            )
            .await;
        assert_eq!(outbound, "DIRECT");
    }

    /// `action: hijack-dns` lands on the registry's `dns` outbound: a
    /// DNS query in (TCP length-framed, and a UDP datagram) is answered
    /// by the engine resolver through the relay.
    #[tokio::test]
    async fn hijack_dns_action_answers_via_dns_outbound() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut cfg = minimal_config();
        cfg.rules = vec!["DST-PORT,53,-".into(), "MATCH,DIRECT".into()];
        cfg.rule_actions =
            std::collections::HashMap::from([(0, crate::rule::RuleAction::HijackDns)]);
        cfg.outbounds.push(crate::outbound::OutboundConfig {
            name: "dns".into(),
            udp: true,
            kind: crate::outbound::OutboundKind::Dns,
        });
        let engine = Engine::build(cfg).unwrap();

        // The route decision itself.
        let (rule, outbound, _) = engine
            .route_with(
                &NetAddr::ip("8.8.8.8".parse().unwrap(), 53),
                "127.0.0.1:50000".parse().unwrap(),
                RouteMeta {
                    network: Network::Tcp,
                    inbound: "",
                    inbound_kind: "",
                    inbound_port: None,
                    proc_info: None,
                },
                None,
            )
            .await;
        assert_eq!(outbound, "dns");
        assert!(rule.contains("hijack-dns"), "{rule}");

        // TCP: length-framed DNS-over-TCP in through the relay, framed
        // answer back.
        let (mut asker, gate) = tokio::io::duplex(4096);
        let source: SocketAddr = "127.0.0.1:50001".parse().unwrap();
        let relay_engine = engine.clone();
        let relay = tokio::spawn(async move {
            relay_engine
                .relay_tcp(
                    tcp_meta(NetAddr::ip("8.8.8.8".parse().unwrap(), 53), source),
                    Box::new(gate),
                )
                .await;
        });
        let q = wire::build_query(9, "probe.test", wire::TYPE_A);
        asker.write_all(&(q.len() as u16).to_be_bytes()).await.unwrap();
        asker.write_all(&q).await.unwrap();
        let mut len = [0u8; 2];
        asker.read_exact(&mut len).await.unwrap();
        let n = u16::from_be_bytes(len) as usize;
        let mut body = vec![0u8; n];
        asker.read_exact(&mut body).await.unwrap();
        let msg = wire::parse(&body).unwrap();
        assert_eq!(msg.id, 9);
        assert_eq!(msg.answers.len(), 1, "fake-ip engine answers");
        drop(asker);
        let _ = tokio::time::timeout(Duration::from_secs(5), relay).await;

        // UDP: one datagram in, answered.
        let (up_tx, up_rx) = mpsc::channel(4);
        let (dl_tx, mut dl_rx) = mpsc::channel(4);
        up_tx
            .send((NetAddr::ip("8.8.8.8".parse().unwrap(), 53), q))
            .await
            .unwrap();
        let udp_engine = engine.clone();
        tokio::spawn(async move {
            udp_engine
                .relay_udp_inner(source, "in".into(), up_rx, dl_tx)
                .await;
        });
        let answered = tokio::time::timeout(Duration::from_secs(5), dl_rx.recv()).await;
        let (_, data) = answered.unwrap().unwrap();
        assert_eq!(wire::parse(&data).unwrap().id, 9);
    }

    /// Lazy groups (mihomo `lazy`, default true): untouched → the health
    /// round skips them (upstream sees no probe); routed through once →
    /// the next round probes.
    #[tokio::test]
    async fn lazy_group_skips_probe_until_routed() {
        use std::sync::atomic::Ordering;
        let (upstream, count, _targets) = spawn_socks_upstream("204 No Content").await;
        let mut cfg = minimal_config();
        cfg.outbounds
            .push(socks_outbound("up", "127.0.0.1", upstream.port()));
        cfg.groups = vec![crate::outbound::GroupConfig {
            name: "Lazy".into(),
            members: vec!["up".into()],
            policy: crate::outbound::GroupPolicy::UrlTest,
            url: Some("http://health.test/check".into()),
            interval: 300,
            tolerance: 0,
        }];
        cfg.group_health.insert(
            "Lazy".into(),
            crate::config::GroupHealth {
                lazy: true,
                ..Default::default()
            },
        );
        cfg.rules = vec!["MATCH,Lazy".into()];
        let engine = Engine::build(cfg).unwrap();

        // Idle: the lazy gate skips the whole round.
        engine.health_tick().await;
        assert_eq!(count.load(Ordering::SeqCst), 0, "idle lazy group must not probe");

        // Route through the group (touch), then the round probes.
        let (rule, outbound, _) = engine
            .route_with(
                &NetAddr::domain("x.test", 80).unwrap(),
                "127.0.0.1:50000".parse().unwrap(),
                RouteMeta {
                    network: Network::Tcp,
                    inbound: "",
                    inbound_kind: "",
                    inbound_port: None,
                    proc_info: None,
                },
                None,
            )
            .await;
        assert_eq!(outbound, "Lazy");
        assert!(rule.contains("MATCH"));
        engine.health_tick().await;
        assert_eq!(count.load(Ordering::SeqCst), 1, "touched lazy group must probe");
        let latencies = engine.registry().latency_snapshot().await;
        assert!(
            latencies.get("up").is_some_and(|s| s.is_some()),
            "probe succeeded (a fast loopback probe may legitimately be 0 ms): {latencies:?}"
        );
    }

    /// expected-status flows through the health round: against a
    /// 404-returning health URL, a group expecting 404 scores healthy
    /// while a group expecting 204 scores dead.
    #[tokio::test]
    async fn expected_status_scores_health_probes() {
        let (upstream, count, _targets) = spawn_socks_upstream("404 Not Found").await;
        let mut cfg = minimal_config();
        cfg.outbounds
            .push(socks_outbound("up-a", "127.0.0.1", upstream.port()));
        cfg.outbounds
            .push(socks_outbound("up-b", "127.0.0.1", upstream.port()));
        let eager = |name: &str, member: &str, expected: &str| {
            (
                crate::outbound::GroupConfig {
                    name: name.into(),
                    members: vec![member.into()],
                    policy: crate::outbound::GroupPolicy::UrlTest,
                    url: Some("http://health.test/check".into()),
                    interval: 300,
                    tolerance: 0,
                },
                crate::config::GroupHealth {
                    lazy: false,
                    expected_status: crate::config::ExpectedStatus::parse(expected).unwrap(),
                },
            )
        };
        let (g404, h404) = eager("Want404", "up-a", "404");
        let (g204, h204) = eager("Want204", "up-b", "204");
        cfg.groups = vec![g404, g204];
        cfg.group_health.insert("Want404".into(), h404);
        cfg.group_health.insert("Want204".into(), h204);
        cfg.rules = vec!["MATCH,DIRECT".into()];
        let engine = Engine::build(cfg).unwrap();

        engine.health_tick().await;
        assert_eq!(count.load(std::sync::atomic::Ordering::SeqCst), 2);
        let latencies = engine.registry().latency_snapshot().await;
        assert!(
            latencies.get("up-a").is_some_and(|s| s.is_some()),
            "404 expected → healthy probe: {latencies:?}"
        );
        assert_eq!(
            latencies.get("up-b"),
            Some(&None),
            "204 expected on a 404 → failed probe (None): {latencies:?}"
        );
    }
}
