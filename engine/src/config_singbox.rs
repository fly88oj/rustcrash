//! sing-box JSON config dialect → [`crate::config::EngineConfig`].

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::Value as Json;

use crate::config::{ApiConfig, DnsConfig, EngineConfig, EnhancedMode};
use crate::error::{Error, Result};
use crate::inbound::{ListenerConfig, ListenerKind};
use crate::outbound::{GroupConfig, GroupPolicy, OutboundConfig, OutboundKind, TransportKind};
use crate::proto::shadowsocks::SsMethod;
use crate::proto::vmess::VmessSecurity;
use crate::transport::TlsSettings;

#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(default)]
    inbounds: Vec<BTreeMap<String, Json>>,
    #[serde(default)]
    endpoints: Vec<BTreeMap<String, Json>>,
    #[serde(default)]
    outbounds: Vec<BTreeMap<String, Json>>,
    #[serde(default)]
    route: Option<RawRoute>,
    #[serde(default)]
    dns: Option<RawDns>,
    #[serde(default)]
    experimental: Option<RawExperimental>,
}

#[derive(Debug, Deserialize, Default)]
struct RawRoute {
    #[serde(default)]
    rules: Vec<BTreeMap<String, Json>>,
    #[serde(default)]
    final_outbound: Option<String>,
    #[serde(rename = "final")]
    final_alias: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RawDns {
    #[serde(default)]
    servers: Vec<BTreeMap<String, Json>>,
    #[serde(default)]
    rules: Vec<BTreeMap<String, Json>>,
    #[serde(default)]
    strategy: Option<String>,
    #[serde(default)]
    fakeip: Option<RawFakeip>,
    #[serde(default)]
    hosts: Option<std::collections::HashMap<String, Json>>,
}

#[derive(Debug, Deserialize, Default)]
struct RawFakeip {
    #[serde(default)]
    enabled: bool,
    #[serde(default, rename = "inet4_range")]
    inet4_range: Option<String>,
}

#[derive(Debug, Deserialize, Default)]
struct RawExperimental {
    #[serde(default)]
    clash_api: Option<RawClashApi>,
}

#[derive(Debug, Deserialize, Default)]
struct RawClashApi {
    #[serde(default, rename = "external_controller")]
    external_controller: Option<String>,
    #[serde(default)]
    secret: Option<String>,
    #[serde(default, rename = "default_mode")]
    default_mode: Option<String>,
}

/// sing-box duration strings (`"300s"`, `"5m"`, plain seconds as
/// numbers are handled by the caller).
fn parse_duration(s: &str) -> Option<std::time::Duration> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix('s') {
        return n.parse::<u64>().ok().map(std::time::Duration::from_secs);
    }
    if let Some(n) = s.strip_suffix('m') {
        return n.parse::<u64>().ok().map(std::time::Duration::from_secs).map(|d| d * 60);
    }
    if let Some(n) = s.strip_suffix('h') {
        return n
            .parse::<u64>()
            .ok()
            .map(std::time::Duration::from_secs)
            .map(|d| d * 3600);
    }
    s.parse::<u64>().ok().map(std::time::Duration::from_secs)
}

fn json_str(entry: &BTreeMap<String, Json>, key: &str) -> Option<String> {
    entry.get(key).and_then(|v| match v {
        Json::String(s) => Some(s.clone()),
        Json::Number(n) => Some(n.to_string()),
        Json::Bool(b) => Some(b.to_string()),
        _ => None,
    })
}

fn json_u16(entry: &BTreeMap<String, Json>, key: &str) -> Option<u16> {
    entry.get(key).and_then(Json::as_u64).map(|v| v as u16)
}

/// Load from JSON text.
pub fn load(text: &str) -> Result<EngineConfig> {
    let raw: RawConfig = serde_json::from_str(text)
        .map_err(|e| Error::config(format!("sing-box config: {e}")))?;

    if raw.outbounds.is_empty() {
        return Err(Error::config("sing-box config has no outbounds"));
    }
    // sing-box always provides direct/block/dns even when undeclared.
    let declared: Vec<String> = raw
        .outbounds
        .iter()
        .filter_map(|o| json_str(o, "tag"))
        .collect();
    let mut outbounds_raw = raw.outbounds.clone();
    for builtin in ["direct", "block", "dns"] {
        if !declared.iter().any(|t| t == builtin) {
            let mut entry = BTreeMap::new();
            entry.insert("type".to_string(), Json::String(builtin.to_string()));
            entry.insert("tag".to_string(), Json::String(builtin.to_string()));
            outbounds_raw.push(entry);
        }
    }
    let raw_outbounds = outbounds_raw;

    let mut listeners = Vec::new();
    // Inbound-level sniff flags (pre-1.11 options) fold into one engine
    // sniffer: any inbound opting in enables TLS+HTTP sniffing.
    let mut sniff = crate::sniffer::SniffConfig::default();
    let mut proxy_servers = Vec::new();
    let mut tun: Option<crate::inbound::tun::TunConfig> = None;
    for (i, inbound) in raw.inbounds.iter().enumerate() {
        let kind_str = json_str(inbound, "type").unwrap_or_default();
        let tag = json_str(inbound, "tag").unwrap_or_else(|| format!("in-{i}"));
        let listen = json_str(inbound, "listen").unwrap_or_else(|| "0.0.0.0".to_string());
        // Server-side inbound types act as a proxy server (mihomo
        // `listeners:` equivalent) rather than a local proxy entry.
        if matches!(
            kind_str.as_str(),
            "shadowsocks" | "trojan" | "vmess" | "vless" | "hysteria2" | "tuic"
        ) {
            let port =
                json_u16(inbound, "listen_port").or_else(|| json_u16(inbound, "listen-port"))
                    .ok_or_else(|| {
                        Error::config(format!("inbound {tag:?} (#{i}) has no listen_port"))
                    })?;
            proxy_servers.push(parse_server_inbound(inbound, &kind_str, tag, listen, port)?);
            continue;
        }
        // Local proxy inbounds: the TYPE check runs first so unsupported
        // types keep their precise error even without a port.
        // The tun inbound is a TUN device, not a listener port.
        if kind_str == "tun" {
            if tun.is_some() {
                return Err(Error::config("only one tun inbound is supported"));
            }
            tun = Some(parse_tun_inbound(inbound, tag.clone())?);
            continue;
        }
        let kind = ListenerKind::parse(&kind_str)?;
        let tag = json_str(inbound, "tag").unwrap_or_else(|| kind.name().to_string());
        let port = json_u16(inbound, "listen_port").or_else(|| json_u16(inbound, "listen-port"))
            .ok_or_else(|| {
                Error::config(format!("inbound {tag:?} (#{i}) has no listen_port"))
            })?;
        if inbound.get("sniff").and_then(Json::as_bool).unwrap_or(false) {
            sniff.tls = true;
            sniff.http = true;
            if inbound
                .get("sniff_override_destination")
                .and_then(Json::as_bool)
                .unwrap_or(false)
            {
                sniff.override_destination = true;
            }
        }
        listeners.push(ListenerConfig {
            tag,
            bind: listen,
            port,
            kind,
        });
    }
    if listeners.is_empty() && proxy_servers.is_empty() && tun.is_none() {
        return Err(Error::config("sing-box config defines no inbounds"));
    }

    let mut outbounds = Vec::new();
    let mut groups = Vec::new();
    for (i, outbound) in raw_outbounds.iter().enumerate() {
        let otype = json_str(outbound, "type").unwrap_or_default();
        let tag = json_str(outbound, "tag").unwrap_or_else(|| format!("out-{i}"));
        match otype.as_str() {
            "direct" => outbounds.push(OutboundConfig {
                name: tag.clone(),
                udp: true,
                kind: OutboundKind::Direct,
            }),
            "block" => outbounds.push(OutboundConfig {
                name: tag.clone(),
                udp: false,
                kind: OutboundKind::Reject,
            }),
            // sing-box's dns outbound is an internal DNS server (upstream
            // protocol/dns: "no outbound connections, all requests are
            // handled internally") — the engine's Dns kind answers TCP
            // length-framed queries and UDP datagrams via the resolver.
            // `udp: true` keeps the UDP arm reachable: the relay's UDP
            // gate refuses outbounds with udp=false, which would
            // blackhole hijacked UDP :53 (the common DNS transport).
            "dns" => outbounds.push(OutboundConfig {
                name: tag.clone(),
                udp: true,
                kind: OutboundKind::Dns,
            }),
            "socks" => outbounds.push(OutboundConfig {
                name: tag.clone(),
                udp: true,
                kind: OutboundKind::Socks {
                    server: server_of(outbound, &tag)?,
                    port: port_of(outbound, &tag)?,
                    username: json_str(outbound, "username"),
                    password: json_str(outbound, "password"),
                },
            }),
            "http" => outbounds.push(OutboundConfig {
                name: tag.clone(),
                udp: false,
                kind: OutboundKind::Http {
                    server: server_of(outbound, &tag)?,
                    port: port_of(outbound, &tag)?,
                    username: json_str(outbound, "username"),
                    password: json_str(outbound, "password"),
                },
            }),
            "shadowsocks" => outbounds.push(OutboundConfig {
                name: tag.clone(),
                udp: true,
                kind: OutboundKind::Shadowsocks {
                    server: server_of(outbound, &tag)?,
                    port: port_of(outbound, &tag)?,
                    method: SsMethod::parse(&json_str(outbound, "method").unwrap_or_default())?,
                    password: json_str(outbound, "password").unwrap_or_default(),
                    obfs: parse_singbox_obfs(outbound)?,
                    // sing-box has no SIP003 external-plugin spawn field
                    // (plugins are not its model).
                    plugin: None,
                },
            }),
            "vmess" => outbounds.push(OutboundConfig {
                name: tag.clone(),
                udp: true,
                kind: OutboundKind::Vmess {
                    server: server_of(outbound, &tag)?,
                    port: port_of(outbound, &tag)?,
                    uuid: uuid_of(outbound, &tag)?,
                    security: VmessSecurity::parse(
                        &json_str(outbound, "security").unwrap_or_else(|| "auto".into()),
                    )?,
                    transport: transport_of(outbound)?,
                    tls: tls_of(outbound)?,
                    // mihomo-only TLS options (jls/tlsmirror/ech) — sing-box
                    // has no such fields upstream.
                    jls: None,
                    tlsmirror: None,
                    ech: None,
                },
            }),
            "vless" => {
                let vision = match json_str(outbound, "flow").as_deref() {
                    None | Some("") => false,
                    Some("xtls-rprx-vision") => true,
                    Some(other) => {
                        return Err(Error::config(format!(
                            "outbound {tag:?}: vless flow {other:?} is not implemented yet \
                             (xtls-rprx-vision is)"
                        )))
                    }
                };
                if vision {
                    tracing::debug!(target: "engine",
                        "outbound {tag:?}: xtls-rprx-vision (full splice on reality \
                         outers; framing mode on opaque TLS outers)");
                }
                let tls = tls_of(outbound)?;
                let reality = reality_of(outbound, &tag, &tls)?;
                let fingerprint = if reality.is_none() {
                    utls_of(outbound, &tag)?
                } else {
                    None
                };
                outbounds.push(OutboundConfig {
                    name: tag.clone(),
                    udp: true,
                    kind: OutboundKind::Vless {
                        server: server_of(outbound, &tag)?,
                        port: port_of(outbound, &tag)?,
                        uuid: uuid_of(outbound, &tag)?,
                        transport: transport_of(outbound)?,
                        tls,
                        reality,
                        fingerprint,
                        vision,
                        jls: None,
                        ech: None,
                    },
                })
            }
            "trojan" => {
                // sing-box trojan is likewise TLS-by-default.
                let mut tls = tls_of(outbound)?;
                tls.enabled = outbound
                    .get("tls")
                    .and_then(Json::as_object)
                    .map(|t| t.get("enabled").and_then(Json::as_bool).unwrap_or(true))
                    .unwrap_or(true);
                outbounds.push(OutboundConfig {
                    name: tag.clone(),
                    udp: true,
                    kind: OutboundKind::Trojan {
                        server: server_of(outbound, &tag)?,
                        port: port_of(outbound, &tag)?,
                        password: json_str(outbound, "password").unwrap_or_default(),
                        transport: transport_of(outbound)?,
                        tls,
                        jls: None,
                        ech: None,
                    },
                })
            }
            "hysteria2" => {
                // salamander obfs: {"obfs": {"type": "salamander", "password": k}}
                let obfs = outbound
                    .get("obfs")
                    .and_then(Json::as_object)
                    .and_then(|o| {
                        let ty = o.get("type").and_then(Json::as_str)?;
                        (ty == "salamander").then(|| {
                            o.get("password")
                                .and_then(Json::as_str)
                                .map(str::to_string)
                                .unwrap_or_default()
                        })
                    });
                outbounds.push(OutboundConfig {
                    name: tag.clone(),
                    udp: true,
                    kind: OutboundKind::Hysteria2 {
                        server: server_of(outbound, &tag)?,
                        port: port_of(outbound, &tag)?,
                        password: json_str(outbound, "password").unwrap_or_default(),
                        sni: json_tls_name(outbound),
                        skip_verify: outbound
                            .get("tls")
                            .and_then(Json::as_object)
                            .and_then(|t| t.get("insecure").and_then(Json::as_bool))
                            .unwrap_or(false),
                        obfs,
                        ech: None,
                    },
                })
            }
            "tuic" => {
                outbounds.push(OutboundConfig {
                    name: tag.clone(),
                    udp: true,
                    kind: OutboundKind::Tuic {
                        server: server_of(outbound, &tag)?,
                        port: port_of(outbound, &tag)?,
                        uuid: uuid_of(outbound, &tag)?,
                        password: json_str(outbound, "password").unwrap_or_default(),
                        sni: json_tls_name(outbound),
                        skip_verify: outbound
                            .get("tls")
                            .and_then(Json::as_object)
                            .and_then(|t| t.get("insecure").and_then(Json::as_bool))
                            .unwrap_or(false),
                        udp_relay_mode: crate::proto::tuic::UdpRelayMode::parse(
                            &json_str(outbound, "udp_relay_mode")
                                .unwrap_or_else(|| "native".into()),
                        )?,
                        ech: None,
                    },
                })
            }
            "anytls" => {
                let mut tls = tls_of(outbound)?;
                if !tls.enabled {
                    // anytls is TLS-by-definition upstream.
                    tls.enabled = true;
                }
                outbounds.push(OutboundConfig {
                    name: tag.clone(),
                    udp: true,
                    kind: OutboundKind::AnyTls(crate::proto::anytls::AnyTlsOut {
                        password: json_str(outbound, "password").unwrap_or_default(),
                        sni: json_tls_name(outbound).unwrap_or_default(),
                        skip_verify: outbound
                            .get("tls")
                            .and_then(Json::as_object)
                            .and_then(|t| t.get("insecure").and_then(Json::as_bool))
                            .unwrap_or(false),
                        udp: true,
                        server: server_of(outbound, &tag)?,
                        port: port_of(outbound, &tag)?,
                        jls: None,
                        ech: None,
                    }),
                })
            }
            "wireguard" => {
                let local_ip = outbound
                    .get("local_address")
                    .and_then(Json::as_array)
                    .and_then(|a| {
                        a.iter().filter_map(Json::as_str).find_map(|s| s.split('/').next())
                    })
                    .and_then(|ip| ip.parse().ok())
                    .unwrap_or(std::net::Ipv4Addr::new(172, 16, 0, 1));
                let local_ipv6 = outbound
                    .get("local_address")
                    .and_then(Json::as_array)
                    .and_then(|a| {
                        a.iter().filter_map(Json::as_str).find(|s| s.contains(':'))
                    })
                    .and_then(|s| s.split('/').next())
                    .and_then(|ip| ip.parse().ok());
                outbounds.push(OutboundConfig {
                    name: tag.clone(),
                    udp: true,
                    kind: OutboundKind::Wireguard(crate::proto::wireguard::WgOut {
                        server: server_of(outbound, &tag)?,
                        port: port_of(outbound, &tag)?,
                        private_key: json_str(outbound, "private_key").unwrap_or_default(),
                        peer_public_key: json_str(outbound, "peer_public_key").unwrap_or_default(),
                        pre_shared_key: json_str(outbound, "pre_shared_key")
                            .filter(|k| !k.is_empty()),
                        local_ip,
                        local_ipv6,
                        mtu: json_u16(outbound, "mtu").unwrap_or(0),
                        reserved: [0u8; 3],
                        udp: true,
                    }),
                })
            }
            "selector" | "urltest" => groups.push(GroupConfig {
                name: tag.clone(),
                members: string_list(outbound, "outbounds"),
                policy: if otype == "selector" {
                    GroupPolicy::Select
                } else {
                    GroupPolicy::UrlTest
                },
                url: json_str(outbound, "url"),
                interval: outbound
                    .get("interval")
                    .and_then(Json::as_str)
                    .and_then(parse_duration_secs)
                    .or_else(|| outbound.get("interval").and_then(Json::as_u64))
                    .unwrap_or(300),
                tolerance: json_u16(outbound, "tolerance").unwrap_or(50),
            }),
            other => {
                return Err(Error::config(format!(
                    "outbound {tag:?}: type {other:?} is not supported by the Rust engine yet \
                     (supported: direct, block, socks, http, shadowsocks, vmess, vless, trojan, \
                     selector, urltest)"
                )))
            }
        }
    }

    // Route rules → clash-style rule lines. sing-box rule actions
    // (option/rule_action.go) ride a side table keyed by converted-line
    // index — the clash line syntax itself has no action slot.
    let mut rules = Vec::new();
    let mut rule_actions: std::collections::HashMap<usize, crate::rule::RuleAction> =
        std::collections::HashMap::new();
    if let Some(route) = &raw.route {
        for rule in &route.rules {
            match route_rule_action(rule)? {
                // route-options is non-final and its fields map onto
                // nothing here — dropping the rule keeps upstream's
                // "continue matching" semantics (options lost, warned).
                RouteActionDirective::Unsupported => continue,
                RouteActionDirective::Route => {}
                RouteActionDirective::Action(action) => {
                    let base = rules.len();
                    rules.extend(rule_to_clash(rule)?);
                    for i in base..rules.len() {
                        rule_actions.insert(i, action.clone());
                    }
                    continue;
                }
            }
            rules.extend(rule_to_clash(rule)?);
        }
        let final_tag = route
            .final_alias
            .clone()
            .or_else(|| route.final_outbound.clone())
            // sing-box: no final → the first outbound.
            .or_else(|| outbounds.first().map(|o| o.name.clone()))
            .unwrap_or_else(|| "direct".to_string());
        rules.push(format!("MATCH,{final_tag}"));
    } else {
        rules.push("MATCH,direct".to_string());
    }

    // DNS.
    let mut dns_rules: Vec<crate::dns::rules::RuleSpec> = Vec::new();
    let dns = raw.dns.map(|d| {
        let mut nameservers = Vec::new();
        let mut tag_urls: BTreeMap<String, String> = BTreeMap::new();
        for server in &d.servers {
            if let Some(address) = json_str(server, "address") {
                // udp/tcp/tls/https/h3/quic upstreams are all supported;
                // the legacy bare-host form means UDP.
                let converted = if address.contains("://")
                    || matches!(address.as_str(), "system" | "local")
                {
                    address.clone()
                } else {
                    format!("udp://{address}")
                };
                if crate::dns::upstream::parse_upstream(&converted).is_some() {
                    if let Some(tag) = json_str(server, "tag") {
                        tag_urls.insert(tag, converted.clone());
                    }
                    nameservers.push(converted);
                } else {
                    tracing::warn!(target: "engine", "dns server {address:?} not supported; skipped");
                }
            }
        }
        // dns.rules reference servers by tag; resolve them here.
        dns_rules = parse_dns_rules(&d.rules, &tag_urls);
        let fakeip = d.fakeip.unwrap_or_default();
        // EDNS0 client subnet: sing-box dns server `client_subnet`
        // ("1.2.3.0/24" or a bare address; a /32-ish single host).
        let client_subnet = d.servers.iter().find_map(|s| {
            let cs = s.get("client_subnet").and_then(Json::as_str)?;
            parse_client_subnet(cs)
        });
        DnsConfig {
            enable: !nameservers.is_empty(),
            listen: None,
            enhanced_mode: if fakeip.enabled {
                EnhancedMode::FakeIp
            } else {
                EnhancedMode::RedirHost
            },
            ipv6: matches!(d.strategy.as_deref(), Some("prefer_ipv6" | "ipv6_only")),
            nameservers,
            fallback: Vec::new(),
            fakeip_range: fakeip.inet4_range.unwrap_or_else(|| "198.18.0.1/15".into()),
            fakeip_store: None,
            fakeip_filter: Vec::new(),
            hosts: parse_json_hosts(d.hosts.as_ref()),
            nameserver_policy: Vec::new(),
            client_subnet,
            rules: std::mem::take(&mut dns_rules),
        }
    });

    let clash_api = raw
        .experimental
        .as_ref()
        .and_then(|e| e.clash_api.as_ref());
    let api = clash_api.and_then(|c| {
        c.external_controller.as_ref().map(|controller| {
            let (bind, port) = crate::config::split_controller(controller);
            ApiConfig {
                bind,
                port,
                secret: c.secret.clone().filter(|s| !s.is_empty()),
            }
        })
    });

    let mode = clash_api
        .and_then(|c| c.default_mode.clone())
        .map(|m| match m.as_str() {
            "global" => crate::config::RuleMode::Global,
            "direct" => crate::config::RuleMode::Direct,
            _ => crate::config::RuleMode::Rule,
        })
        .unwrap_or_default();

    Ok(EngineConfig {
        mode,
        ipv6: false,
        listeners,
        outbounds,
        groups,
        rules,
        dns,
        api,
        rule_providers: Vec::new(),
        geo: Default::default(),
        sniff,
        proxy_servers,
        tun,
        wg_endpoints: parse_wireguard_endpoints(&raw.endpoints)?,
        // sing-box urltest groups carry no lazy/expected-status
        // upstream (option/group.go URLTestOutboundOptions) — the map
        // stays empty and EngineConfig::group_health falls back to
        // never-skip/any-status.
        group_health: Default::default(),
        rule_actions,
        // sing-box has no inbound-credential or routing-mark equivalent
        // on the JSON dialect's proxy inbounds (auth rides per-listener
        // `users`; marks ride route rules) — both stay empty here.
        authentication: Vec::new(),
        routing_mark: None,
    })
}

/// sing-box `endpoints: [{type: wireguard, ...}]` → the WG server mode
/// (sing-box protocol/wireguard/endpoint.go: private_key, listen_port,
/// address[], mtu, udp_timeout, peers[{public_key, pre_shared_key,
/// allowed_ips[], persistent_keepalive}]).
fn parse_wireguard_endpoints(
    endpoints: &[BTreeMap<String, Json>],
) -> Result<Vec<crate::proto::wireguard::WgEndpointCfg>> {
    let mut out = Vec::new();
    for (i, ep) in endpoints.iter().enumerate() {
        let etype = json_str(ep, "type").unwrap_or_default();
        if etype != "wireguard" {
            return Err(Error::config(format!(
                "endpoint {i}: type {etype:?} is not supported (wireguard is)"
            )));
        }
        let tag = json_str(ep, "tag").unwrap_or_else(|| format!("wg-endpoint-{i}"));
        let parse_prefix = |s: &str| -> Option<(std::net::IpAddr, u8)> {
            let (addr, prefix) = s.split_once('/')?;
            Some((addr.parse().ok()?, prefix.parse().ok()?))
        };
        let mut address = None;
        let mut inet6_address = None;
        if let Some(Json::Array(list)) = ep.get("address") {
            for a in list.iter().filter_map(Json::as_str) {
                if let Some((ip, p)) = parse_prefix(a) {
                    match ip {
                        std::net::IpAddr::V4(v4) if address.is_none() => {
                            address = Some((v4, p))
                        }
                        std::net::IpAddr::V6(v6) if inet6_address.is_none() => {
                            inet6_address = Some((v6, p))
                        }
                        _ => {}
                    }
                }
            }
        }
        let mut peers = Vec::new();
        if let Some(Json::Array(list)) = ep.get("peers") {
            for peer in list.iter().filter_map(Json::as_object) {
                let get = |k: &str| {
                    peer.get(k)
                        .and_then(Json::as_str)
                        .map(str::to_string)
                };
                let allowed_ips = peer
                    .get("allowed_ips")
                    .and_then(Json::as_array)
                    .map(|l| {
                        l.iter()
                            .filter_map(Json::as_str)
                            .filter_map(parse_prefix)
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                peers.push(crate::proto::wireguard::WgEndpointPeer {
                    public_key: get("public_key").unwrap_or_default(),
                    pre_shared_key: get("pre_shared_key").filter(|s| !s.is_empty()),
                    allowed_ips,
                    persistent_keepalive: peer
                        .get("persistent_keepalive")
                        .and_then(Json::as_u64)
                        .map(|v| v as u16),
                });
            }
        }
        out.push(crate::proto::wireguard::WgEndpointCfg {
            tag: tag.clone(),
            private_key: json_str(ep, "private_key").unwrap_or_default(),
            listen_port: ep
                .get("listen_port")
                .and_then(Json::as_u64)
                .unwrap_or(0) as u16,
            mtu: ep.get("mtu").and_then(Json::as_u64).unwrap_or(0) as u16,
            address,
            inet6_address,
            udp_timeout: ep
                .get("udp_timeout")
                .and_then(Json::as_str)
                .and_then(parse_duration),
            peers,
        });
    }
    Ok(out)
}

/// sing-box tun inbound → engine TunConfig. `address` is an array of
/// CIDRs; the first IPv4 entry wins. `auto_route` is owned by the crash
/// firewall layer (logged), matching the mihomo dialect's split.
fn parse_tun_inbound(
    inbound: &BTreeMap<String, Json>,
    tag: String,
) -> Result<crate::inbound::tun::TunConfig> {
    if inbound
        .get("auto_route")
        .and_then(Json::as_bool)
        .unwrap_or(false)
    {
        tracing::warn!(target: "engine",
            "tun auto_route is handled by the crash firewall layer, not the engine");
    }
    let addr_spec = inbound
        .get("address")
        .and_then(Json::as_array)
        .and_then(|a| a.iter().filter_map(Json::as_str).find(|s| !s.contains(':')))
        .map(str::to_string)
        .unwrap_or_else(|| "172.19.0.1/30".to_string());
    let (address, netmask) = addr_spec
        .split_once('/')
        .and_then(|(ip, p)| Some((ip.parse().ok()?, p.parse::<u8>().ok()?)))
        .filter(|(_, p)| *p <= 32)
        .ok_or_else(|| {
            Error::config(format!("tun address {addr_spec:?} is not an IPv4 CIDR"))
        })?;
    // The first v6 CIDR in `address`, when present.
    let inet6_address = inbound
        .get("address")
        .and_then(Json::as_array)
        .and_then(|a| {
            a.iter().filter_map(Json::as_str).find(|s| s.contains(':'))
        })
        .and_then(|spec| {
            let (ip, p) = spec.split_once('/')?;
            let ip: std::net::Ipv6Addr = ip.parse().ok()?;
            let p: u8 = p.parse().ok()?;
            (p <= 128).then_some((ip, p))
        });
    // dns hijack: sing-box hijacks via route rules (action hijack-dns);
    // the common shorthand is a `dns` field on the old inbound form.
    let dns_hijack = inbound
        .get("dns_hijack")
        .and_then(Json::as_array)
        .map(|list| {
            list.iter()
                .filter_map(Json::as_str)
                .filter_map(|s| s.trim().parse().ok())
                .collect()
        })
        .unwrap_or_default();
    Ok(crate::inbound::tun::TunConfig {
        tag,
        name: json_str(inbound, "interface_name").unwrap_or_default(),
        address,
        netmask,
        mtu: json_u16(inbound, "mtu").unwrap_or(9000),
        dns_hijack,
        inet6_address,
    })
}

/// sing-box `hosts` values: string or array of strings.
fn parse_json_hosts(raw: Option<&std::collections::HashMap<String, Json>>) -> std::collections::HashMap<String, Vec<std::net::IpAddr>> {
    let mut out = std::collections::HashMap::new();
    let Some(map) = raw else { return out };
    for (domain, value) in map {
        let mut addrs = Vec::new();
        match value {
            Json::String(s) => {
                if let Ok(ip) = s.trim().parse() {
                    addrs.push(ip);
                }
            }
            Json::Array(items) => {
                for item in items {
                    if let Some(s) = item.as_str() {
                        if let Ok(ip) = s.trim().parse() {
                            addrs.push(ip);
                        }
                    }
                }
            }
            _ => {}
        }
        if !addrs.is_empty() {
            out.insert(domain.to_ascii_lowercase(), addrs);
        }
    }
    out
}

/// sing-box server inbound → engine ServerConfig.
fn parse_server_inbound(
    inbound: &BTreeMap<String, Json>,
    kind: &str,
    tag: String,
    bind: String,
    port: u16,
) -> Result<crate::inbound::proxy_server::ServerConfig> {
    use crate::inbound::proxy_server::{ServerConfig, ServerProtocol, ServerTls};
    // TLS: inline `tls.certificate_path`/`key_path` (sing-box naming).
    let tls = inbound
        .get("tls")
        .and_then(Json::as_object)
        .and_then(|t| {
            let cert = t.get("certificate_path").and_then(Json::as_str)?;
            let key = t.get("key_path").and_then(Json::as_str)?;
            Some(ServerTls {
                cert_pem: cert.to_string(),
                key_pem: key.to_string(),
            })
        });
    let first_user_field = |key: &str| -> Option<String> {
        inbound
            .get("users")
            .and_then(Json::as_array)
            .and_then(|u| u.first())
            .and_then(Json::as_object)
            .and_then(|u| u.get(key))
            .and_then(Json::as_str)
            .map(str::to_string)
    };
    let protocol = match kind {
        "shadowsocks" => ServerProtocol::Shadowsocks {
            method: json_str(inbound, "method").unwrap_or_default(),
            password: json_str(inbound, "password").unwrap_or_default(),
            // SIP023 multi-user `users` parsing is wired by the
            // integrator; the single-PSK shape stays as-is.
            users: Vec::new(),
        },
        "trojan" => ServerProtocol::Trojan {
            password: first_user_field("password")
                .or_else(|| json_str(inbound, "password"))
                .unwrap_or_default(),
            tls,
        },
        "vmess" => ServerProtocol::Vmess {
            uuid: first_user_field("uuid")
                .or_else(|| json_str(inbound, "uuid"))
                .unwrap_or_default(),
            security: json_str(inbound, "security").unwrap_or_else(|| "auto".into()),
        },
        "vless" => ServerProtocol::Vless {
            uuid: first_user_field("uuid")
                .or_else(|| json_str(inbound, "uuid"))
                .unwrap_or_default(),
            tls,
        },
        "hysteria2" => ServerProtocol::Hysteria2 {
            password: json_str(inbound, "password").unwrap_or_default(),
            obfs: match inbound.get("obfs").and_then(Json::as_object) {
                None => None,
                Some(_) => {
                    return Err(Error::config(format!(
                        "inbound {tag:?}: hysteria2 server-side obfs is not implemented yet"
                    )))
                }
            },
            tls,
        },
        "tuic" => ServerProtocol::Tuic {
            uuid: first_user_field("uuid")
                .or_else(|| json_str(inbound, "uuid"))
                .unwrap_or_default(),
            password: first_user_field("password")
                .or_else(|| json_str(inbound, "password"))
                .unwrap_or_default(),
            tls,
        },
        other => {
            return Err(Error::config(format!(
                "server inbound {other:?} not supported"
            )))
        }
    };
    Ok(ServerConfig {
        tag,
        bind,
        port,
        protocol,
    })
}

/// sing-box `dns.rules` → dialect-neutral rule specs. `tag_urls` maps
/// the `dns.servers[].tag` values to their converted URLs so rule
/// `server` references resolve (a rule may also carry a bare URL).
fn parse_dns_rules(
    raw: &[BTreeMap<String, Json>],
    tag_urls: &BTreeMap<String, String>,
) -> Vec<crate::dns::rules::RuleSpec> {
    let mut out = Vec::new();
    for rule in raw {
        let strings = |key: &str| -> Vec<String> { string_list(rule, key) };
        let mut server_urls: Vec<String> = Vec::new();
        for server in strings("server") {
            if server.contains("://") {
                server_urls.push(server);
            } else if let Some(url) = tag_urls.get(&server) {
                server_urls.push(url.clone());
            } else {
                tracing::warn!(target: "engine",
                    "dns rule server {server:?} is neither a URL nor a known dns.servers tag");
            }
        }
        let spec = crate::dns::rules::RuleSpec {
            domains: strings("domain"),
            domain_suffix: strings("domain_suffix"),
            domain_keyword: strings("domain_keyword"),
            domain_regex: strings("domain_regex"),
            query_type: rule
                .get("query_type")
                .and_then(Json::as_array)
                .map(|a| {
                    a.iter()
                        .filter_map(|v| v.as_u64().and_then(|n| u16::try_from(n).ok()))
                        .collect()
                })
                .unwrap_or_default(),
            invert: rule.get("invert").and_then(Json::as_bool).unwrap_or(false),
            server_urls,
            disable_cache: rule
                .get("disable_cache")
                .and_then(Json::as_bool)
                .unwrap_or(false),
            rewrite_ttl: rule
                .get("rewrite_ttl")
                .and_then(Json::as_u64)
                .and_then(|n| u32::try_from(n).ok())
                .or_else(|| {
                    // "5m"/"30s" duration strings.
                    rule.get("rewrite_ttl")
                        .and_then(Json::as_str)
                        .and_then(parse_duration_secs)
                        .and_then(|s| u32::try_from(s).ok())
                }),
            client_subnet: rule
                .get("client_subnet")
                .and_then(Json::as_str)
                .map(str::to_string),
        };
        out.push(spec);
    }
    out
}

/// sing-box shadowsocks plugin: `plugin: "obfs-local"` with
/// `plugin_opts: "obfs=http;obfs-host=x"`.
fn parse_singbox_obfs(
    outbound: &BTreeMap<String, Json>,
) -> Result<Option<crate::outbound::ObfsMode>> {
    let Some(plugin) = json_str(outbound, "plugin") else {
        return Ok(None);
    };
    if plugin != "obfs-local" && plugin != "simple-obfs" {
        return Err(Error::config(format!(
            "shadowsocks plugin {plugin:?} is not supported (only obfs-local)"
        )));
    }
    let opts = json_str(outbound, "plugin_opts").unwrap_or_default();
    let mut http = true;
    let mut host = None;
    for kv in opts.split(';') {
        let Some((k, v)) = kv.split_once('=') else { continue };
        match k.trim() {
            "obfs" | "mode" => {
                http = match v.trim() {
                    "http" => true,
                    "tls" => false,
                    other => {
                        return Err(Error::config(format!(
                            "unsupported obfs mode {other:?} (http|tls)"
                        )))
                    }
                }
            }
            "obfs-host" | "host" => host = Some(v.trim().to_string()),
            _ => {}
        }
    }
    Ok(Some(crate::outbound::ObfsMode {
        http,
        host: host.unwrap_or_else(|| "bing.com".to_string()),
    }))
}

/// sing-box `tls.reality` → RealityCfg (vless only).
fn reality_of(
    outbound: &BTreeMap<String, Json>,
    tag: &str,
    tls: &TlsSettings,
) -> Result<Option<crate::proto::reality::RealityCfg>> {
    let Some(reality) = outbound
        .get("tls")
        .and_then(Json::as_object)
        .and_then(|t| t.get("reality"))
        .and_then(Json::as_object)
    else {
        return Ok(None);
    };
    if !reality
        .get("enabled")
        .and_then(Json::as_bool)
        .unwrap_or(true)
    {
        return Ok(None);
    }
    let public_key = reality
        .get("public_key")
        .and_then(Json::as_str)
        .ok_or_else(|| Error::config(format!("outbound {tag:?}: tls.reality requires public_key")))?;
    let short_id = reality
        .get("short_id")
        .and_then(Json::as_str)
        .unwrap_or("")
        .to_string();
    Ok(Some(crate::proto::reality::RealityCfg {
        server_name: tls
            .server_name
            .clone()
            .or_else(|| json_str(outbound, "server"))
            .unwrap_or_default(),
        public_key: public_key.to_string(),
        short_id,
        fingerprint: utls_of(outbound, tag)?
            .unwrap_or(crate::proto::reality::UtslProfile::Chrome),
        spider_x: None,
    }))
}

/// sing-box `tls.utls.fingerprint` → a profile (chrome/firefox only).
fn utls_of(
    outbound: &BTreeMap<String, Json>,
    tag: &str,
) -> Result<Option<crate::proto::reality::UtslProfile>> {
    let Some(utls) = outbound
        .get("tls")
        .and_then(Json::as_object)
        .and_then(|t| t.get("utls"))
        .and_then(Json::as_object)
    else {
        return Ok(None);
    };
    if !utls
        .get("enabled")
        .and_then(Json::as_bool)
        .unwrap_or(true)
    {
        return Ok(None);
    }
    match utls
        .get("fingerprint")
        .and_then(Json::as_str)
        .unwrap_or("chrome")
        .to_ascii_lowercase()
        .as_str()
    {
        "chrome" => Ok(Some(crate::proto::reality::UtslProfile::Chrome)),
        "firefox" => Ok(Some(crate::proto::reality::UtslProfile::Firefox)),
        other => Err(Error::config(format!(
            "outbound {tag:?}: utls fingerprint {other:?} is not implemented yet \
             (chrome, firefox)"
        ))),
    }
}

/// TLS server_name from the `tls` object (hy2/tuic outbounds).
fn json_tls_name(entry: &BTreeMap<String, Json>) -> Option<String> {
    entry
        .get("tls")
        .and_then(Json::as_object)
        .and_then(|t| t.get("server_name"))
        .and_then(Json::as_str)
        .map(str::to_string)
}

/// sing-box `client_subnet`: "addr/prefix" (or a bare address = /32,/128).
fn parse_client_subnet(cs: &str) -> Option<crate::dns::edns::ClientSubnet> {
    let (addr, prefix) = match cs.split_once('/') {
        Some((a, p)) => (a, p.parse::<u8>().ok()?),
        None => (cs, 32),
    };
    let addr: std::net::IpAddr = addr.parse().ok()?;
    let max = if addr.is_ipv4() { 32 } else { 128 };
    if prefix > max {
        return None;
    }
    Some(crate::dns::edns::ClientSubnet {
        addr,
        source_prefix: prefix,
        scope_prefix: 0,
    })
}

fn server_of(entry: &BTreeMap<String, Json>, tag: &str) -> Result<String> {    json_str(entry, "server")
        .ok_or_else(|| Error::config(format!("outbound {tag:?} missing server")))
}

fn port_of(entry: &BTreeMap<String, Json>, tag: &str) -> Result<u16> {
    json_u16(entry, "server_port")
        .or_else(|| json_u16(entry, "server-port"))
        .ok_or_else(|| Error::config(format!("outbound {tag:?} missing server_port")))
}

fn uuid_of(entry: &BTreeMap<String, Json>, tag: &str) -> Result<uuid::Uuid> {
    let s = json_str(entry, "uuid").unwrap_or_default();
    uuid::Uuid::parse_str(&s)
        .map_err(|_| Error::config(format!("outbound {tag:?} has an invalid uuid")))
}

fn string_list(entry: &BTreeMap<String, Json>, key: &str) -> Vec<String> {
    match entry.get(key) {
        Some(Json::Array(arr)) => arr
            .iter()
            .filter_map(Json::as_str)
            .map(str::to_string)
            .collect(),
        // Several sing-box fields accept a bare string (`network: "udp"`).
        Some(Json::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

/// Parse a sing-box duration ("30", "5m", "1h30m") into seconds — proper
/// unit sums, not digit-stripping (which turned "1h30m" into 130m).
fn parse_duration_secs(s: &str) -> Option<u64> {
    let mut total: u64 = 0;
    let mut num_start = 0;
    let bytes = s.as_bytes();
    for (i, b) in bytes.iter().enumerate() {
        if b.is_ascii_digit() {
            continue;
        }
        let unit = match b {
            b's' => 1,
            b'm' => 60,
            b'h' => 3600,
            _ => return None,
        };
        let n: u64 = s[num_start..i].parse().ok()?;
        total += n.checked_mul(unit)?;
        num_start = i + 1;
    }
    if num_start < s.len() {
        // Trailing unit-less number = seconds.
        let n: u64 = s[num_start..].parse().ok()?;
        total += n;
    }
    Some(total)
}

fn transport_of(entry: &BTreeMap<String, Json>) -> Result<TransportKind> {
    let Some(transport) = entry.get("transport").and_then(Json::as_object) else {
        return Ok(TransportKind::Tcp);
    };
    let map: BTreeMap<String, Json> = transport.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
    // ws and httpupgrade share path/host(+headers.Host) fields.
    let path = map
        .get("path")
        .and_then(Json::as_str)
        .unwrap_or("/")
        .to_string();
    let host = map
        .get("host")
        .and_then(Json::as_str)
        .map(str::to_string)
        .or_else(|| {
            map.get("headers")
                .and_then(Json::as_object)
                .and_then(|h| h.get("Host"))
                .and_then(Json::as_str)
                .map(str::to_string)
        });
    match json_str(&map, "type").as_deref() {
        None | Some("") => Ok(TransportKind::Tcp),
        Some("ws") => Ok(TransportKind::Ws { path, host }),
        Some("httpupgrade") => Ok(TransportKind::HttpUpgrade { path, host }),
        Some("grpc") => Ok(TransportKind::Grpc {
            service_name: map
                .get("service_name")
                .and_then(Json::as_str)
                .unwrap_or("TunService")
                .to_string(),
            host,
        }),
        Some(other) => Err(Error::config(format!(
            "transport {other:?} is not supported by the Rust engine yet (supported: tcp, ws, httpupgrade, grpc)"
        ))),
    }
}

fn tls_of(entry: &BTreeMap<String, Json>) -> Result<TlsSettings> {
    let Some(tls) = entry.get("tls").and_then(Json::as_object) else {
        return Ok(TlsSettings::default());
    };
    let enabled = tls.get("enabled").and_then(Json::as_bool).unwrap_or(false);
    let server_name = tls
        .get("server_name")
        .and_then(Json::as_str)
        .map(str::to_string);
    let skip_cert_verify = tls
        .get("insecure")
        .and_then(Json::as_bool)
        .unwrap_or(false);
    Ok(TlsSettings {
        enabled,
        server_name,
        skip_cert_verify,
        alpn: Vec::new(),
    })
}

/// Convert one sing-box route rule into clash rule lines.
fn rule_to_clash(rule: &BTreeMap<String, Json>) -> Result<Vec<String>> {
    if json_str(rule, "type").as_deref() == Some("logical") {
        return logical_rule_to_clash(rule);
    }
    let outbound = rule_outbound(rule);
    let invert = rule.get("invert").and_then(Json::as_bool).unwrap_or(false);
    let groups = rule_groups(rule)?;
    combine_groups(&groups, "AND", &outbound, invert)
}

/// The outbound a converted rule line targets. Plain rules (and
/// `action: route`, which carries its own `outbound`) use the outbound
/// field, default `direct`; `action: reject` remaps to the dialect's
/// `block` outbound — the engine has a single Reject behavior, so the
/// docs' `method` default/drop/reply distinction (RejectActionOptions)
/// maps to one target.
fn rule_outbound(rule: &BTreeMap<String, Json>) -> String {
    match json_str(rule, "action").as_deref() {
        Some("reject") => "block".to_string(),
        _ => json_str(rule, "outbound").unwrap_or_else(|| "direct".into()),
    }
}

/// What the engine should do with one sing-box route rule's `action:`
/// field (option/rule_action.go enum: route, route-options, direct,
/// bypass, reject, hijack-dns, sniff, resolve).
enum RouteActionDirective {
    /// Route via the (possibly remapped) outbound: no action, or the
    /// route-family actions.
    Route,
    /// A portable action carried on the rule instead of routing.
    Action(crate::rule::RuleAction),
    /// `route-options`: non-final and none of its fields map onto
    /// engine machinery — the rule is dropped from the converted list
    /// (a dropped non-final rule ≈ upstream's "continue matching").
    Unsupported,
}

/// Sniffer names the upstream action enum recognizes
/// (RouteActionSniff); the engine sniffs the first three.
const ACTION_SNIFFERS: &[&str] = &["tls", "http", "quic", "dns", "stun", "bittorrent", "dtls", "ssh", "rdp", "ntp"];

fn route_rule_action(rule: &BTreeMap<String, Json>) -> Result<RouteActionDirective> {
    let Some(action) = json_str(rule, "action") else {
        return Ok(RouteActionDirective::Route);
    };
    match action.as_str() {
        // Route-family actions fold into the line's outbound
        // (see rule_outbound).
        "route" | "direct" | "bypass" | "reject" => Ok(RouteActionDirective::Route),
        "sniff" => {
            let requested = string_list(rule, "sniffer");
            let mut sniffer = Vec::with_capacity(requested.len());
            for name in requested {
                if !ACTION_SNIFFERS.contains(&name.as_str()) {
                    // Upstream's JSON schema rejects unknown enum values.
                    return Err(Error::config(format!(
                        "unknown sniffer {name:?} in action sniff"
                    )));
                }
                if !["tls", "http", "quic"].contains(&name.as_str()) {
                    tracing::warn!(target: "engine",
                        "action sniff sniffer {name:?} not supported by the Rust engine; \
                         ignoring (supported: tls, http, quic)");
                    continue;
                }
                sniffer.push(name);
            }
            Ok(RouteActionDirective::Action(crate::rule::RuleAction::Sniff { sniffer }))
        }
        "resolve" => {
            if let Some(server) = json_str(rule, "server").filter(|s| !s.is_empty()) {
                tracing::warn!(target: "engine",
                    "action resolve server {server:?}: the engine resolves through its \
                     own resolver; the per-server selection is ignored");
            }
            Ok(RouteActionDirective::Action(crate::rule::RuleAction::Resolve))
        }
        "hijack-dns" => Ok(RouteActionDirective::Action(
            crate::rule::RuleAction::HijackDns,
        )),
        "route-options" => {
            tracing::warn!(target: "engine",
                "route rule action route-options: override_address/port, udp_connect etc. \
                 are not supported by the Rust engine yet; the rule is dropped");
            Ok(RouteActionDirective::Unsupported)
        }
        other => Err(Error::config(format!(
            "unknown rule action {other:?} (supported: route, route-options, direct, \
             bypass, reject, hijack-dns, sniff, resolve)"
        ))),
    }
}

/// sing-box logical rule: `type: "logical"`, `mode: and|or`, `rules` is
/// an array of sub-rule objects (no outbounds of their own).
fn logical_rule_to_clash(rule: &BTreeMap<String, Json>) -> Result<Vec<String>> {
    let outbound = rule_outbound(rule);
    let invert = rule.get("invert").and_then(Json::as_bool).unwrap_or(false);
    let mode = json_str(rule, "mode").unwrap_or_else(|| "and".into());
    let mode = if mode.eq_ignore_ascii_case("or") { "OR" } else { "AND" };
    let Some(subs) = rule.get("rules").and_then(Json::as_array) else {
        return Ok(vec![]);
    };
    let mut parts = Vec::new();
    for sub in subs {
        let Some(obj) = sub.as_object() else { continue };
        let obj: BTreeMap<String, Json> = obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect();
        if json_str(&obj, "type").as_deref() == Some("logical") {
            // Nested logical: recurse into a single-condition line.
            let nested = logical_rule_to_clash(&obj)?;
            for line in nested {
                if let Some((cond, _)) = line.rsplit_once(',') {
                    parts.push(format!("({cond})"));
                }
            }
            continue;
        }
        let groups = rule_groups(&obj)?;
        if groups.is_empty() {
            continue;
        }
        // A sub-rule with several field kinds ANDs them; values within a
        // kind OR.
        let joined = groups.iter().map(|g| group_payload(g)).collect::<Vec<_>>().join(",");
        if groups.len() == 1 {
            parts.push(joined);
        } else {
            parts.push(format!("AND,({joined})"));
        }
    }
    if parts.is_empty() {
        return Ok(vec![]);
    }
    let joined = parts.join(",");
    let line = if invert {
        format!("NOT,(({mode},({joined}))),{outbound}")
    } else {
        format!("{mode},({joined}),{outbound}")
    };
    Ok(vec![line])
}

/// Condition groups for one sing-box rule object: sing-box ANDs every
/// populated FIELD and ORs the values within a field, so each field is
/// its own group.
fn rule_groups(rule: &BTreeMap<String, Json>) -> Result<Vec<Vec<String>>> {
    let mut groups: Vec<Vec<String>> = Vec::new();

    for (key, kind) in [
        ("domain", "DOMAIN"),
        ("domain_suffix", "DOMAIN-SUFFIX"),
        ("domain_keyword", "DOMAIN-KEYWORD"),
        ("domain_regex", "DOMAIN-REGEX"),
    ] {
        let conds: Vec<String> = string_list(rule, key)
            .iter()
            .map(|v| format!("{kind},{v}"))
            .collect();
        if !conds.is_empty() {
            groups.push(conds);
        }
    }

    let ip_conds: Vec<String> = string_list(rule, "ip_cidr")
        .iter()
        .map(|c| format!("IP-CIDR,{c}"))
        .collect();
    if !ip_conds.is_empty() {
        groups.push(ip_conds);
    }
    // sing-box's ip_is_private is a BOOLEAN that expands to the standard
    // private ranges — its own AND item, separate from ip_cidr.
    if rule
        .get("ip_is_private")
        .and_then(Json::as_bool)
        .unwrap_or(false)
    {
        groups.push(
            [
                "10.0.0.0/8",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "169.254.0.0/16",
                "fc00::/7",
                "fe80::/10",
                "::1/128",
            ]
            .iter()
            .map(|c| format!("IP-CIDR,{c}"))
            .collect(),
        );
    }

    let src: Vec<String> = string_list(rule, "source_ip_cidr")
        .iter()
        .map(|c| format!("SRC-IP-CIDR,{c}"))
        .collect();
    if !src.is_empty() {
        groups.push(src);
    }

    // Ports: numbers or strings, plain or ranges. sing-box renders
    // ranges as "80:90" (`port_range`); clash uses "80-90".
    for (key, kind) in [
        ("port", "DST-PORT"),
        ("port_range", "DST-PORT"),
        ("source_port", "SRC-PORT"),
        ("source_port_range", "SRC-PORT"),
    ] {
        let conds: Vec<String> = port_list(rule, key)
            .iter()
            .map(|p| format!("{kind},{p}"))
            .collect();
        if !conds.is_empty() {
            groups.push(conds);
        }
    }

    let nets: Vec<String> = string_list(rule, "network")
        .iter()
        .map(|n| format!("NETWORK,{}", n.to_ascii_lowercase()))
        .collect();
    if !nets.is_empty() {
        groups.push(nets);
    }

    let inbs: Vec<String> = string_list(rule, "inbound")
        .iter()
        .map(|t| format!("IN-NAME,{t}"))
        .collect();
    if !inbs.is_empty() {
        groups.push(inbs);
    }

    let proc_names: Vec<String> = string_list(rule, "process_name")
        .iter()
        .map(|v| format!("PROCESS-NAME,{v}"))
        .collect();
    if !proc_names.is_empty() {
        groups.push(proc_names);
    }
    let proc_paths: Vec<String> = string_list(rule, "process_path")
        .iter()
        .map(|v| format!("PROCESS-PATH,{v}"))
        .collect();
    if !proc_paths.is_empty() {
        groups.push(proc_paths);
    }

    // clash_mode ANDs with the other conditions, like any field.
    if let Some(mode) = json_str(rule, "clash_mode") {
        groups.push(vec![format!("CLASH-MODE,{}", mode.to_ascii_lowercase())]);
    }

    if rule.get("protocol").is_some() {
        tracing::warn!(target: "engine",
            "sing-box route rule 'protocol' matches sniffed protocols; not supported, ignoring");
    }
    if let Some(provider_path) = json_str(rule, "rule_set") {
        // sing-box rule-sets are srs binary — unsupported; surface an error.
        return Err(Error::config(format!(
            "route rule references rule-set {provider_path:?}; the srs binary format is not \
             supported by the Rust engine yet — inline the rule domains/ip_cidr instead"
        )));
    }
    Ok(groups)
}

/// Port values for one key: numbers, strings, and `80:90` ranges
/// (normalized to clash's `80-90`). An empty result means the key is
/// absent — a populated-but-unparseable value errors instead of
/// silently dropping the rule.
fn port_list(rule: &BTreeMap<String, Json>, key: &str) -> Vec<String> {
    let mut out = Vec::new();
    let push_one = |v: &str| -> Option<String> {
        let v = v.trim();
        if let Some((lo, hi)) = v.split_once(':') {
            let (lo, hi) = (lo.trim(), hi.trim());
            if lo.parse::<u16>().is_ok() && hi.parse::<u16>().is_ok() {
                return Some(format!("{lo}-{hi}"));
            }
            return None;
        }
        v.parse::<u16>().is_ok().then(|| v.to_string())
    };
    match rule.get(key) {
        Some(Json::Array(items)) => {
            for item in items {
                if let Some(n) = item.as_u64() {
                    if n <= u16::MAX as u64 {
                        out.push(n.to_string());
                    }
                } else if let Some(s) = item.as_str() {
                    if let Some(p) = push_one(s) {
                        out.push(p);
                    }
                }
            }
        }
        Some(Json::Number(n)) => {
            if n.as_u64().is_some_and(|n| n <= u16::MAX as u64) {
                out.push(n.to_string());
            }
        }
        Some(Json::String(s)) => {
            if let Some(p) = push_one(s) {
                out.push(p);
            }
        }
        _ => {}
    }
    out
}

/// Render one condition group as a logic payload element: `(cond)` or
/// `(OR,((c1),(c2)))`.
fn group_payload(conds: &[String]) -> String {
    if conds.len() == 1 {
        format!("({})", conds[0])
    } else {
        let inner = conds
            .iter()
            .map(|c| format!("({c})"))
            .collect::<Vec<_>>()
            .join(",");
        format!("(OR,({inner}))")
    }
}

/// Join condition groups into final rule lines. One group without
/// inversion flattens to plain lines (sequential first-match = OR);
/// otherwise the groups AND (invertible).
fn combine_groups(
    groups: &[Vec<String>],
    mode: &str,
    outbound: &str,
    invert: bool,
) -> Result<Vec<String>> {
    if groups.is_empty() {
        return Ok(vec![]);
    }
    if groups.len() == 1 && groups[0].len() == 1 {
        let c = &groups[0][0];
        let line = if invert {
            format!("NOT,(({c})),{outbound}")
        } else {
            format!("{c},{outbound}")
        };
        return Ok(vec![line]);
    }
    if groups.len() == 1 && !invert {
        return Ok(groups[0]
            .iter()
            .map(|c| format!("{c},{outbound}"))
            .collect());
    }
    let joined = groups.iter().map(|g| group_payload(g)).collect::<Vec<_>>().join(",");
    let line = if invert {
        format!("NOT,(({mode},({joined}))),{outbound}")
    } else {
        format!("{mode},({joined}),{outbound}")
    };
    Ok(vec![line])
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
{
  "inbounds": [
    {"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 2080},
    {"type": "tproxy", "tag": "tun-in", "listen": "0.0.0.0", "listen_port": 2081}
  ],
  "outbounds": [
    {"type": "shadowsocks", "tag": "proxy", "server": "10.1.2.3", "server_port": 8388,
     "method": "2022-blake3-aes-256-gcm", "password": "c29tZXRoaW5n"},
    {"type": "vmess", "tag": "vm", "server": "vm.example", "server_port": 443,
     "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "security": "auto",
     "transport": {"type": "ws", "path": "/ws"},
     "tls": {"enabled": true, "server_name": "vm.example"}},
    {"type": "selector", "tag": "select", "outbounds": ["proxy", "direct"]},
    {"type": "direct", "tag": "direct"}
  ],
  "route": {
    "rules": [
      {"domain_suffix": ["internal.test"], "outbound": "direct"},
      {"ip_cidr": ["10.0.0.0/8"], "outbound": "direct"},
      {"port": ["80", "8080-8090"], "outbound": "proxy"}
    ],
    "final": "select"
  },
  "dns": {
    "servers": [{"tag": "local", "address": "udp://223.5.5.5"}],
    "fakeip": {"enabled": true, "inet4_range": "198.18.0.0/15"}
  },
  "experimental": {
    "clash_api": {"external_controller": "127.0.0.1:9090", "secret": "s3cret", "default_mode": "rule"}
  }
}
"#;

    #[test]
    fn loads_full_config() {
        let cfg = load(SAMPLE).unwrap();
        assert_eq!(cfg.listeners.len(), 2);
        assert_eq!(cfg.listeners[0].kind, ListenerKind::Mixed);
        assert_eq!(cfg.listeners[1].kind, ListenerKind::Tproxy);
        // ss, vmess, direct (declared) + block, dns (implicit builtins).
        assert_eq!(cfg.outbounds.len(), 5);
        assert_eq!(cfg.groups.len(), 1); // selector
        assert_eq!(cfg.groups[0].members, vec!["proxy", "direct"]);
        // Rules + final.
        assert!(cfg.rules.iter().any(|r| r.starts_with("DOMAIN-SUFFIX,internal.test,direct")));
        assert!(cfg.rules.iter().any(|r| r.starts_with("IP-CIDR,10.0.0.0/8,")));
        assert_eq!(cfg.rules.last().unwrap(), "MATCH,select");
        let dns = cfg.dns.unwrap();
        assert!(dns.enable);
        assert_eq!(dns.nameservers, vec!["udp://223.5.5.5"]);
        assert_eq!(dns.enhanced_mode, EnhancedMode::FakeIp);
        let api = cfg.api.unwrap();
        assert_eq!(api.port, 9090);
        assert_eq!(api.secret.as_deref(), Some("s3cret"));
    }

    #[test]
    fn rejects_srs_rule_sets() {
        let cfg = r#"
{"inbounds": [{"type": "mixed", "listen_port": 1}],
 "outbounds": [{"type": "direct", "tag": "direct"}],
 "route": {"rules": [{"rule_set": "geosite-cn", "outbound": "direct"}]}}
"#;
        let err = load(cfg).err().unwrap().to_string();
        assert!(err.contains("rule-set"), "{err}");
        assert!(err.contains("srs"), "{err}");
    }

    #[test]
    fn server_inbounds_and_dns_rules_convert() {
        let cfg = r#"
{"inbounds": [
    {"type": "shadowsocks", "tag": "srv-ss", "listen": "0.0.0.0", "listen_port": 38388,
     "method": "aes-256-gcm", "password": "pw"},
    {"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 2080}
 ],
 "outbounds": [{"type": "direct", "tag": "direct"}],
 "dns": {
   "servers": [
     {"tag": "plain", "address": "udp://1.1.1.1"},
     {"tag": "secure", "address": "quic://192.0.2.1"}
   ],
   "rules": [
     {"domain_suffix": ["corp.test"], "server": "secure", "rewrite_ttl": "5m"},
     {"domain": ["x.test"], "server": "plain", "disable_cache": true}
   ]
 }
}
"#;
        let parsed = load(cfg).unwrap();
        // Server inbound drives proxy_servers; the mixed one stays local.
        assert_eq!(parsed.proxy_servers.len(), 1);
        assert!(matches!(
            &parsed.proxy_servers[0].protocol,
            crate::inbound::proxy_server::ServerProtocol::Shadowsocks { method, .. }
                if method == "aes-256-gcm"
        ));
        assert_eq!(parsed.listeners.len(), 1);
        // dns.rules resolve `server` tags through dns.servers.
        let dns = parsed.dns.unwrap();
        assert_eq!(dns.rules.len(), 2);
        assert_eq!(dns.rules[0].server_urls, vec!["quic://192.0.2.1"]);
        assert_eq!(dns.rules[0].rewrite_ttl, Some(300));
        assert_eq!(dns.rules[1].server_urls, vec!["udp://1.1.1.1"]);
        assert!(dns.rules[1].disable_cache);
    }

    #[test]
    fn anytls_outbound_parses() {
        let cfg = r#"
{"inbounds": [{"type": "mixed", "listen_port": 1}],
 "outbounds": [
   {"type": "anytls", "tag": "a", "server": "a.example", "server_port": 443,
    "password": "pw",
    "tls": {"enabled": true, "server_name": "a.example", "insecure": true}},
   {"type": "direct", "tag": "direct"}]}
"#;
        let parsed = load(cfg).unwrap();
        let a = parsed.outbounds.iter().find(|o| o.name == "a").unwrap();
        match &a.kind {
            crate::outbound::OutboundKind::AnyTls(c) => {
                assert_eq!(c.sni, "a.example");
                assert!(c.skip_verify);
            }
            other => panic!("unexpected {other:?}"),
        }
    }

    #[test]
    fn hysteria2_and_tuic_parse() {
        let cfg = r#"
{"inbounds": [{"type": "mixed", "listen_port": 1}],
 "outbounds": [
  {"type": "hysteria2", "tag": "h", "server": "x", "server_port": 1, "password": "p",
   "obfs": {"type": "salamander", "password": "k"}, "tls": {"enabled": true, "server_name": "x", "insecure": true}},
  {"type": "tuic", "tag": "t", "server": "x", "server_port": 2,
   "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "password": "p",
   "udp_relay_mode": "quic", "tls": {"enabled": true, "server_name": "x"}}]}
"#;
        let parsed = load(cfg).unwrap();
        let h = parsed.outbounds.iter().find(|o| o.name == "h").unwrap();
        assert!(matches!(
            &h.kind,
            OutboundKind::Hysteria2 { obfs: Some(k), skip_verify: true, .. } if k == "k"
        ));
        let t = parsed.outbounds.iter().find(|o| o.name == "t").unwrap();
        assert!(matches!(
            &t.kind,
            OutboundKind::Tuic { udp_relay_mode: crate::proto::tuic::UdpRelayMode::Quic, .. }
        ));
    }

    #[test]
    fn duration_parsing() {
        assert_eq!(parse_duration_secs("5m"), Some(300));
        assert_eq!(parse_duration_secs("1h"), Some(3600));
        assert_eq!(parse_duration_secs("30"), Some(30));
        // Unit sums, not digit-stripping ("1h30m" must be 5400s, not 130m).
        assert_eq!(parse_duration_secs("1h30m"), Some(5400));
        assert_eq!(parse_duration_secs("1m30s"), Some(90));
        assert_eq!(parse_duration_secs("1x"), None);
        assert_eq!(parse_duration_secs(""), Some(0));
    }

    #[test]
    fn clash_mode_and_ip_is_private_rules() {
        let cfg = r#"
{"inbounds": [{"type": "mixed", "listen_port": 1}],
 "outbounds": [{"type": "direct", "tag": "direct"}],
 "route": {"rules": [
    {"clash_mode": "Direct", "ip_is_private": true, "outbound": "direct"},
    {"domain_suffix": ["x.test"], "outbound": "direct"}
 ]}}
"#;
        let parsed = load(cfg).unwrap();
        // clash_mode ANDs with the other fields (sing-box semantics),
        // so one combined logic rule is emitted — not separate lines.
        let combined = parsed
            .rules
            .iter()
            .find(|r| r.contains("CLASH-MODE,direct") && r.contains("IP-CIDR"))
            .expect("combined clash-mode + private ranges rule");
        assert!(combined.starts_with("AND,("));
        assert!(combined.contains("IP-CIDR,10.0.0.0/8"));
        assert!(combined.contains("IP-CIDR,fc00::/7"));
        assert!(combined.ends_with(",direct"));
        assert!(!parsed.rules.iter().any(|r| r.contains("IP-CIDR,true")));
        // Single-field rules stay plain.
        assert!(parsed.rules.contains(&"DOMAIN-SUFFIX,x.test,direct".to_string()));
    }

    #[test]
    fn numeric_ports_and_ranges_convert() {
        let cfg = r#"
{"inbounds": [{"type": "mixed", "listen_port": 1, "tag": "in"}],
 "outbounds": [{"type": "socks", "tag": "first", "server": "127.0.0.1", "server_port": 2}, {"type": "direct", "tag": "direct"}],
 "route": {"rules": [
    {"port": 80, "outbound": "direct"},
    {"port_range": ["8080:8090"], "outbound": "direct"}
 ]}}
"#;
        let parsed = load(cfg).unwrap();
        assert!(parsed.rules.contains(&"DST-PORT,80,direct".to_string()),
            "numeric port must not silently vanish: {:?}", parsed.rules);
        assert!(parsed.rules.contains(&"DST-PORT,8080-8090,direct".to_string()),
            "colon ranges normalize: {:?}", parsed.rules);
        // No explicit final → sing-box uses the FIRST outbound.
        assert_eq!(parsed.rules.last().unwrap(), "MATCH,first");
    }

    #[test]
    fn ip_is_private_ands_with_ip_cidr() {
        let cfg = r#"
{"inbounds": [{"type": "mixed", "listen_port": 1, "tag": "in"}],
 "outbounds": [{"type": "direct", "tag": "direct"}],
 "route": {"rules": [
    {"ip_cidr": ["1.2.3.4/32"], "ip_is_private": true, "outbound": "direct"}
 ]}}
"#;
        let parsed = load(cfg).unwrap();
        let combined = parsed.rules.iter().find(|r| r.starts_with("AND,")).unwrap();
        // Two separate AND items, not one OR group.
        assert!(combined.contains("(IP-CIDR,1.2.3.4/32)"), "{combined}");
        assert!(combined.contains("(OR,((IP-CIDR,10.0.0.0/8)"), "{combined}");
    }

    #[test]
    fn sniffer_block_parses() {
        let cfg = r#"
{"inbounds": [{"type": "mixed", "listen_port": 1, "sniff": true, "sniff_override_destination": true}],
 "outbounds": [{"type": "direct", "tag": "direct"}]}
"#;
        let parsed = load(cfg).unwrap();
        assert!(parsed.sniff.enabled());
        assert!(parsed.sniff.tls && parsed.sniff.http);
        assert!(parsed.sniff.override_destination);
    }

    #[test]
    fn logical_and_metadata_rules_convert() {
        let cfg = r#"
{"inbounds": [{"type": "mixed", "listen_port": 1, "tag": "in"}],
 "outbounds": [{"type": "direct", "tag": "direct"}],
 "route": {"rules": [
    {"type": "logical", "mode": "and", "outbound": "direct",
     "rules": [{"domain_suffix": ["a.test"]}, {"port": ["80", "443"]}]} ,
    {"network": "udp", "outbound": "direct"},
    {"inbound": ["in"], "outbound": "direct"},
    {"process_name": ["curl"], "outbound": "direct"},
    {"domain_suffix": ["b.test"], "invert": true, "outbound": "direct"}
 ]}}
"#;
        let parsed = load(cfg).unwrap();
        let and = parsed
            .rules
            .iter()
            .find(|r| r.starts_with("AND,"))
            .expect("logical rule converted");
        assert!(and.contains("(DOMAIN-SUFFIX,a.test)"), "{and}");
        assert!(and.contains("(OR,((DST-PORT,80),(DST-PORT,443))))"), "{and}");
        assert!(parsed.rules.contains(&"NETWORK,udp,direct".to_string()));
        assert!(parsed.rules.contains(&"IN-NAME,in,direct".to_string()));
        assert!(parsed.rules.contains(&"PROCESS-NAME,curl,direct".to_string()));
        assert!(parsed.rules.contains(&"NOT,((DOMAIN-SUFFIX,b.test)),direct".to_string()));
    }

    #[test]
    fn route_rule_actions_parse() {
        let cfg = r#"
{"inbounds": [{"type": "mixed", "listen_port": 1, "tag": "in"}],
 "outbounds": [{"type": "direct", "tag": "direct"}],
 "route": {"rules": [
    {"port": 443, "action": "sniff", "sniffer": ["tls", "dns"]},
    {"domain_suffix": ["resolve-me.test"], "action": "resolve"},
    {"port": 53, "action": "hijack-dns"},
    {"domain_suffix": ["ads.test"], "action": "reject", "method": "drop"},
    {"domain_suffix": ["ok.test"], "outbound": "direct"}
 ], "final": "direct"}}
"#;
        let parsed = load(cfg).unwrap();
        // Converted lines keep their order; only the final MATCH follows.
        assert_eq!(parsed.rules.len(), 6);
        assert_eq!(parsed.rules[0], "DST-PORT,443,direct"); // placeholder target
        assert_eq!(parsed.rules[1], "DOMAIN-SUFFIX,resolve-me.test,direct");
        assert_eq!(parsed.rules[2], "DST-PORT,53,direct");
        assert_eq!(parsed.rules[3], "DOMAIN-SUFFIX,ads.test,block");
        assert_eq!(parsed.rules[4], "DOMAIN-SUFFIX,ok.test,direct");
        assert_eq!(parsed.rules[5], "MATCH,direct");

        // Actions attach to the converted line indexes — dns was warned
        // away, leaving the tls subset on the sniff rule.
        use crate::rule::RuleAction;
        assert_eq!(
            parsed.rule_actions.get(&0),
            Some(&RuleAction::Sniff {
                sniffer: vec!["tls".to_string()]
            })
        );
        assert_eq!(parsed.rule_actions.get(&1), Some(&RuleAction::Resolve));
        assert_eq!(parsed.rule_actions.get(&2), Some(&RuleAction::HijackDns));
        // reject routes via the block outbound — no action entry.
        assert!(!parsed.rule_actions.contains_key(&3));

        // compile_rules pairs the lines with their actions.
        let table = parsed.compile_rules().unwrap();
        assert!(table.action(0).is_some());
        assert_eq!(table.rules().len(), 6);
    }

    #[test]
    fn route_rule_action_variants_validate() {
        // Unknown action → error (mirrors the upstream schema enum).
        let bad = load(
            r#"
{"inbounds": [{"type": "mixed", "listen_port": 1}],
 "outbounds": [{"type": "direct", "tag": "direct"}],
 "route": {"rules": [{"port": 80, "action": "sniff-all"}]}}
"#,
        );
        assert!(bad.is_err());

        // Unknown sniffer name → error.
        let bad = load(
            r#"
{"inbounds": [{"type": "mixed", "listen_port": 1}],
 "outbounds": [{"type": "direct", "tag": "direct"}],
 "route": {"rules": [{"port": 80, "action": "sniff", "sniffer": ["smb"]} ]}}
"#,
        );
        assert!(bad.is_err());

        // route-options is dropped (non-final; options unsupported) —
        // the later plain rule still converts, so the config loads.
        let cfg = load(
            r#"
{"inbounds": [{"type": "mixed", "listen_port": 1}],
 "outbounds": [{"type": "direct", "tag": "direct"}],
 "route": {"rules": [
    {"port": 80, "action": "route-options", "udp_connect": true},
    {"domain_suffix": ["x.test"], "outbound": "direct"}
 ]}}
"#,
        )
        .unwrap();
        assert_eq!(cfg.rules, vec!["DOMAIN-SUFFIX,x.test,direct", "MATCH,direct"]);

        // Action on a logical rule attaches to the combined line.
        let cfg = load(
            r#"
{"inbounds": [{"type": "mixed", "listen_port": 1}],
 "outbounds": [{"type": "direct", "tag": "direct"}],
 "route": {"rules": [
    {"type": "logical", "mode": "and", "action": "sniff",
     "rules": [{"domain_suffix": ["a.test"]}, {"port": [443]}]}
 ]}}
"#,
        )
        .unwrap();
        assert!(cfg.rules[0].starts_with("AND,("));
        assert!(matches!(
            cfg.rule_actions.get(&0),
            Some(crate::rule::RuleAction::Sniff { sniffer }) if sniffer.is_empty()
        ));

        // An action rule's placeholder outbound is exempt from
        // validation; plain dangling targets still fail.
        let mut cfg = cfg;
        cfg.rules.push("DOMAIN-SUFFIX,broken.test,NOSUCH".to_string());
        assert!(crate::config::validate(&cfg.with_builtin_outbounds()).is_err());
    }

    #[test]
    fn reality_and_utls_parse() {
        let cfg = r#"
{"inbounds": [{"type": "mixed", "listen_port": 1}],
 "outbounds": [
   {"type": "vless", "tag": "v", "server": "x", "server_port": 1,
    "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
    "tls": {"enabled": true, "server_name": "cam.example",
            "reality": {"enabled": true, "public_key": "cGs=", "short_id": "0102"},
            "utls": {"enabled": true, "fingerprint": "firefox"}}},
   {"type": "vless", "tag": "u", "server": "y", "server_port": 2,
    "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
    "tls": {"enabled": true, "server_name": "plain.example",
            "utls": {"enabled": true, "fingerprint": "chrome"}}}]}
"#;
        let parsed = load(cfg).unwrap();
        let v = parsed.outbounds.iter().find(|o| o.name == "v").unwrap();
        match &v.kind {
            crate::outbound::OutboundKind::Vless { reality, fingerprint, .. } => {
                let r = reality.as_ref().expect("reality parsed");
                assert_eq!(r.server_name, "cam.example");
                assert_eq!(r.short_id, "0102");
                assert!(matches!(
                    r.fingerprint,
                    crate::proto::reality::UtslProfile::Firefox
                ));
                assert!(fingerprint.is_none(), "reality carries the fingerprint");
            }
            other => panic!("unexpected {other:?}"),
        }
        let u = parsed.outbounds.iter().find(|o| o.name == "u").unwrap();
        assert!(matches!(
            &u.kind,
            crate::outbound::OutboundKind::Vless { fingerprint: Some(_), reality: None, .. }
        ));
    }

    #[test]
    fn unknown_fingerprint_rejected() {
        let cfg = r#"
{"inbounds": [{"type": "mixed", "listen_port": 1}],
 "outbounds": [{"type": "vless", "tag": "v", "server": "x", "server_port": 1,
   "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811",
   "tls": {"enabled": true, "utls": {"enabled": true, "fingerprint": "safari"}}}]}
"#;
        let err = load(cfg).err().unwrap().to_string();
        assert!(err.contains("safari"), "{err}");
        assert!(err.contains("not implemented yet"), "{err}");
    }

    #[test]
    fn vless_vision_flow_parses() {
        let cfg = r#"
{"inbounds": [{"type": "mixed", "listen_port": 1}],
 "outbounds": [
   {"type": "vless", "tag": "v", "server": "x", "server_port": 1,
    "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "flow": "xtls-rprx-vision"},
   {"type": "vless", "tag": "w", "server": "y", "server_port": 2,
    "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "flow": "xtls-rprx-direct"}]}
"#;
        let err = load(cfg).err().unwrap().to_string();
        assert!(err.contains("xtls-rprx-direct"), "{err}");
        assert!(err.contains("not implemented yet"), "{err}");
    }

    #[test]
    fn vless_vision_flow_accepted() {
        let cfg = r#"
{"inbounds": [{"type": "mixed", "listen_port": 1}],
 "outbounds": [{"type": "vless", "tag": "v", "server": "x", "server_port": 1,
   "uuid": "b831381d-6324-4d53-ad4f-8cda48b30811", "flow": "xtls-rprx-vision"}]}
"#;
        let parsed = load(cfg).unwrap();
        let v = parsed.outbounds.iter().find(|o| o.name == "v").unwrap();
        assert!(matches!(
            &v.kind,
            crate::outbound::OutboundKind::Vless { vision: true, .. }
        ));
    }

    #[test]
    fn tun_inbound_parses() {
        let cfg = r#"
{"inbounds": [{"type": "tun", "tag": "t", "address": ["172.19.0.1/30"],
   "mtu": 1500, "dns_hijack": ["198.18.0.0"]}],
 "outbounds": [{"type": "direct", "tag": "direct"}]}
"#;
        let parsed = load(cfg).unwrap();
        let tun = parsed.tun.unwrap();
        assert_eq!(tun.tag, "t");
        assert_eq!(tun.address.to_string(), "172.19.0.1");
        assert_eq!(tun.netmask, 30);
        assert_eq!(tun.mtu, 1500);
        assert_eq!(tun.dns_hijack.len(), 1);
    }

    /// A declared `{"type": "dns"}` outbound maps to the engine's Dns
    /// kind (answered by the resolver), NOT Reject; `block` stays
    /// Reject; arbitrary tags keep the Dns kind (upstream docs'
    /// example tag is `dns-out`).
    #[test]
    fn dns_outbound_is_dns_kind_not_reject() {
        let cfg = r#"
{"inbounds": [{"type": "mixed", "listen_port": 1, "tag": "in"}],
 "outbounds": [
   {"type": "dns", "tag": "dns"},
   {"type": "block", "tag": "block"},
   {"type": "dns", "tag": "dns-out"},
   {"type": "direct", "tag": "direct"}]}
"#;
        let parsed = load(cfg).unwrap();
        let dns = parsed.outbounds.iter().find(|o| o.name == "dns").unwrap();
        assert!(matches!(dns.kind, OutboundKind::Dns), "declared dns must be Dns");
        assert!(dns.udp, "dns outbound must allow UDP (hijacked UDP :53)");
        let block = parsed.outbounds.iter().find(|o| o.name == "block").unwrap();
        assert!(matches!(block.kind, OutboundKind::Reject));
        assert!(!block.udp);
        let custom = parsed.outbounds.iter().find(|o| o.name == "dns-out").unwrap();
        assert!(matches!(custom.kind, OutboundKind::Dns));
    }

    /// An UNDECLARED `dns` tag still works: the loader appends the
    /// builtin entry, and it must be Dns too — the router's hijack-dns
    /// action routes to the literal "dns" tag through the registry.
    #[test]
    fn undeclared_dns_builtin_is_dns_kind() {
        let cfg = r#"
{"inbounds": [{"type": "mixed", "listen_port": 1, "tag": "in"}],
 "outbounds": [{"type": "direct", "tag": "direct"}],
 "route": {"rules": [{"port": 53, "action": "hijack-dns"}], "final": "direct"}}
"#;
        let parsed = load(cfg).unwrap();
        let dns = parsed.outbounds.iter().find(|o| o.name == "dns").unwrap();
        assert!(matches!(dns.kind, OutboundKind::Dns));
        assert!(dns.udp);
    }

    /// End-to-end through the engine with a LOADER-produced config:
    /// a hijack-dns action rule + the dns outbound answers a DNS
    /// query from the registry's "dns" outbound channel (fake-ip
    /// pool — hermetic, the TEST-NET upstream is never contacted).
    /// Before the loader fix this config produced a Reject-kind
    /// "dns" outbound: `udp()` errors and DNS is blackholed.
    #[tokio::test]
    async fn loader_hijack_dns_config_answers_through_dns_outbound() {
        let cfg = load(
            r#"
{"inbounds": [{"type": "mixed", "tag": "in", "listen": "127.0.0.1", "listen_port": 2080}],
 "outbounds": [{"type": "direct", "tag": "direct"}, {"type": "dns", "tag": "dns"}],
 "route": {"rules": [{"port": 53, "action": "hijack-dns"}], "final": "direct"},
 "dns": {"servers": [{"tag": "local", "address": "udp://192.0.2.53"}],
         "fakeip": {"enabled": true, "inet4_range": "198.18.0.0/15"}}}
"#,
        )
        .unwrap();

        // Config level: the loaded outbounds carry a Dns-kind "dns", and
        // the hijack-dns action rides the converted rule's index.
        let dns = cfg.outbounds.iter().find(|o| o.name == "dns").unwrap();
        assert!(matches!(dns.kind, OutboundKind::Dns));
        assert_eq!(
            cfg.rule_actions.get(&0),
            Some(&crate::rule::RuleAction::HijackDns)
        );
        assert_eq!(cfg.rules[0], "DST-PORT,53,direct");
        let table = cfg.compile_rules().unwrap();
        assert_eq!(table.rules()[0].outbound, "direct");
        assert!(matches!(
            table.action(0),
            Some(crate::rule::RuleAction::HijackDns)
        ));

        // Engine level: the registry resolves the "dns" tag and the
        // outbound's UDP channel answers the datagram via the resolver.
        let engine = crate::app::Engine::build(cfg).unwrap();
        let outbound = engine.registry().resolve("dns").await.unwrap();
        assert_eq!(outbound.kind_name(), "Dns");
        assert!(!outbound.is_reject());
        assert!(outbound.udp);
        let target = crate::addr::NetAddr::ip("8.8.8.8".parse().unwrap(), 53);
        let mut channel = outbound.udp(&target).await.expect("dns outbound UDP channel");
        let query = crate::dns::wire::build_query(9, "probe.test", crate::dns::wire::TYPE_A);
        channel.send(&target, &query).await.unwrap();
        let answered =
            tokio::time::timeout(std::time::Duration::from_secs(5), channel.recv()).await;
        let (_, data) = answered.expect("answer within 5s").unwrap();
        let msg = crate::dns::wire::parse(&data).unwrap();
        assert_eq!(msg.id, 9);
        assert_eq!(msg.answers.len(), 1, "fake-ip engine answers");
    }
}
