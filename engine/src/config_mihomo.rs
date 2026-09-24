//! mihomo (Clash) YAML config dialect → [`crate::config::EngineConfig`].
//! Accepts the subset the engine implements; unknown keys are ignored,
//! unsupported protocol features produce precise errors.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_yaml::Value as Yaml;

use crate::config::{
    ApiConfig, DnsConfig, EngineConfig, EnhancedMode, ProviderBehavior, ProviderFormat,
    RuleProviderSpec,
};
use crate::error::{Error, Result};
use crate::inbound::{ListenerConfig, ListenerKind};
use crate::outbound::{GroupConfig, GroupPolicy, OutboundConfig, OutboundKind, TransportKind};
use crate::proto::shadowsocks::SsMethod;
use crate::proto::vmess::VmessSecurity;
use crate::transport::TlsSettings;

#[derive(Debug, Deserialize)]
struct RawConfig {
    #[serde(default)]
    port: Option<u16>,
    #[serde(default, rename = "socks-port")]
    socks_port_alt: Option<u16>,
    #[serde(default, rename = "mixed-port")]
    mixed_port: Option<u16>,
    #[serde(default, rename = "redir-port")]
    redir_port: Option<u16>,
    #[serde(default, rename = "tproxy-port")]
    tproxy_port: Option<u16>,
    #[serde(default, rename = "allow-lan", alias = "allow_lan")]
    allow_lan: bool,
    #[serde(default)]
    bind_address: Option<String>,
    #[serde(default)]
    mode: Option<String>,
    #[serde(default)]
    ipv6: bool,
    #[serde(default, rename = "external-controller")]
    external_controller: Option<String>,
    #[serde(default)]
    secret: Option<String>,
    #[serde(default)]
    dns: Option<RawDns>,
    #[serde(default)]
    proxies: Vec<BTreeMap<String, Yaml>>,
    #[serde(default, rename = "proxy-groups")]
    proxy_groups: Vec<RawGroup>,
    #[serde(default, rename = "rule-providers")]
    rule_providers: Option<BTreeMap<String, RawProvider>>,
    #[serde(default)]
    rules: Vec<String>,
    #[serde(default, rename = "sub-rules")]
    sub_rules: Option<BTreeMap<String, Vec<String>>>,
    #[serde(default)]
    sniffer: Option<BTreeMap<String, Yaml>>,
    #[serde(default)]
    listeners: Option<Vec<BTreeMap<String, Yaml>>>,
    #[serde(default)]
    tun: Option<BTreeMap<String, Yaml>>,
}

#[derive(Debug, Deserialize)]
struct RawDns {
    #[serde(default)]
    enable: bool,
    #[serde(default)]
    listen: Option<String>,
    #[serde(default, rename = "enhanced-mode")]
    enhanced_mode: Option<String>,
    #[serde(default)]
    ipv6: bool,
    #[serde(default)]
    nameserver: Option<Vec<String>>,
    #[serde(default)]
    fallback: Option<Vec<String>>,
    #[serde(default, rename = "fake-ip-range")]
    fake_ip_range: Option<String>,
    #[serde(default, rename = "fake-ip-filter")]
    fake_ip_filter: Option<Vec<String>>,
    #[serde(default)]
    hosts: Option<std::collections::HashMap<String, Yaml>>,
    /// `nameserver-policy`: domain → one URL or a list; normalized to
    /// Vec<(domain, urls)> after deserialize.
    #[serde(default, rename = "nameserver-policy")]
    nameserver_policy: Option<std::collections::HashMap<String, Yaml>>,
}

#[derive(Debug, Deserialize)]
struct RawGroup {
    name: String,
    #[serde(rename = "type")]
    group_type: String,
    #[serde(default)]
    proxies: Vec<String>,
    #[serde(default)]
    url: Option<String>,
    #[serde(default)]
    interval: Option<u64>,
    #[serde(default)]
    tolerance: Option<u16>,
}

#[derive(Debug, Deserialize)]
struct RawProvider {
    #[serde(default)]
    behavior: Option<String>,
    #[serde(default)]
    format: Option<String>,
    #[serde(default)]
    path: Option<String>,
}

/// Load from YAML text.
pub fn load(text: &str) -> Result<EngineConfig> {
    let raw: RawConfig = serde_yaml::from_str(text)
        .map_err(|e| Error::config(format!("mihomo config: {e}")))?;

    if raw.proxies.is_empty() && raw.proxy_groups.is_empty() {
        return Err(Error::config("mihomo config has no proxies"));
    }

    let bind = if raw.allow_lan {
        raw.bind_address
            .clone()
            .unwrap_or_else(|| "*".to_string())
    } else {
        "127.0.0.1".to_string()
    };
    let bind = if bind == "*" {
        "0.0.0.0".to_string()
    } else {
        bind
    };

    let mut listeners = Vec::new();
    let mut add = |kind: ListenerKind, port: Option<u16>, default_tag: &str| {
        if let Some(port) = port.filter(|p| *p > 0) {
            listeners.push(ListenerConfig {
                tag: default_tag.to_string(),
                bind: bind.clone(),
                port,
                kind,
            });
        }
    };
    add(ListenerKind::Mixed, raw.mixed_port, "mixed");
    add(ListenerKind::Socks, raw.socks_port_alt, "socks");
    add(ListenerKind::Http, raw.port, "http");
    add(ListenerKind::Redir, raw.redir_port, "redir");
    add(ListenerKind::Tproxy, raw.tproxy_port, "tproxy");
    // A TUN-only config is valid: the device is declared in its own block.
    let tun_enabled = raw
        .tun
        .as_ref()
        .and_then(|t| t.get("enable"))
        .and_then(Yaml::as_bool)
        .unwrap_or(false);
    if listeners.is_empty() && !tun_enabled {
        return Err(Error::config(
            "mihomo config defines no inbound ports (mixed-port/port/redir-port/tproxy-port) \
             and no tun block",
        ));
    }

    let outbounds = raw
        .proxies
        .iter()
        .enumerate()
        .map(|(i, entry)| parse_proxy(entry, i, &raw.proxies))
        .collect::<Result<Vec<_>>>()?;

    let mut groups = Vec::new();
    for g in &raw.proxy_groups {
        groups.push(GroupConfig {
            name: g.name.clone(),
            members: g.proxies.clone(),
            policy: GroupPolicy::parse(&g.group_type)?,
            url: g.url.clone(),
            interval: g.interval.unwrap_or(300),
            tolerance: g.tolerance.unwrap_or(50),
        });
    }

    let mut providers = Vec::new();
    if let Some(map) = &raw.rule_providers {
        for (name, p) in map {
            let path = p.path.clone().ok_or_else(|| {
                Error::config(format!("rule provider {name} has no path (http-only providers need the manager to download first"))
            })?;
            providers.push(RuleProviderSpec {
                name: name.clone(),
                path,
                behavior: p
                    .behavior
                    .as_deref()
                    .map(ProviderBehavior::parse)
                    .transpose()?
                    .unwrap_or(ProviderBehavior::Classical),
                format: p
                    .format
                    .as_deref()
                    .map(ProviderFormat::parse)
                    .transpose()?
                    .unwrap_or(ProviderFormat::Text),
            });
        }
    }

    let dns = raw
        .dns
        .map(|d| -> Result<DnsConfig> {
            Ok(DnsConfig {
                enable: d.enable,
                listen: d.listen.clone(),
                enhanced_mode: match d.enhanced_mode.as_deref() {
                    None | Some("fake-ip") => EnhancedMode::FakeIp,
                    Some("redir-host") => EnhancedMode::RedirHost,
                    Some(other) => {
                        return Err(Error::config(format!(
                            "unsupported dns enhanced-mode {other:?}"
                        )))
                    }
                },
                ipv6: d.ipv6,
                nameservers: d.nameserver.clone().unwrap_or_default(),
                fallback: d.fallback.clone().unwrap_or_default(),
                fakeip_range: d
                    .fake_ip_range
                    .clone()
                    .unwrap_or_else(|| "198.18.0.1/15".to_string()),
                fakeip_filter: d.fake_ip_filter.clone().unwrap_or_default(),
                hosts: parse_hosts(d.hosts.as_ref()),
                nameserver_policy: parse_nameserver_policy(d.nameserver_policy.as_ref()),
                client_subnet: None,
                rules: Vec::new(),
            })
        })
        .transpose()?;

    let api = raw.external_controller.as_deref().map(|controller| {
        let (bind, port) = crate::config::split_controller(controller);
        ApiConfig {
            bind,
            port,
            secret: raw.secret.clone().filter(|s| !s.is_empty()),
        }
    });

    let tun = parse_tun(raw.tun.as_ref())?;

    Ok(EngineConfig {
        mode: raw
            .mode
            .as_deref()
            .map(crate::config::RuleMode::parse)
            .transpose()?
            .unwrap_or_default(),
        ipv6: raw.ipv6,
        listeners,
        outbounds,
        groups,
        rules: expand_sub_rules(raw.rules, &raw.sub_rules)?,
        sniff: parse_sniffer(raw.sniffer.as_ref()),
        dns,
        api,
        rule_providers: providers,
        geo: Default::default(),
        proxy_servers: parse_proxy_servers(raw.listeners.as_deref())?,
        tun,
    })
}

/// mihomo `tun:` block → a TUN inbound config. Route/DNS-server management
/// stays with the crash firewall layer (the same split as tproxy: the
/// firewall owns routes and the resolver address; the engine owns the
/// netstack). `auto-route`/`auto-detect-interface`/`stack` are accepted
/// and logged — the engine always uses its own userspace stack.
fn parse_tun(raw: Option<&BTreeMap<String, Yaml>>) -> Result<Option<crate::inbound::tun::TunConfig>> {
    let Some(map) = raw else {
        return Ok(None);
    };
    if !map
        .get("enable")
        .and_then(Yaml::as_bool)
        .unwrap_or(false)
    {
        return Ok(None);
    }
    if map.get("auto-route").and_then(Yaml::as_bool) == Some(true) {
        tracing::warn!(target: "engine",
            "tun.auto-route is handled by the crash firewall layer, not the engine; \
             ensure the firewall TUN mode is enabled");
    }
    if let Some(stack) = yaml_str(map, "stack") {
        if !stack.is_empty() {
            tracing::debug!(target: "engine",
                "tun.stack {stack:?} ignored: the engine always uses its userspace stack");
        }
    }
    // Address: `inet4-address: 172.19.0.1/30` (or the legacy `interface-name` family).
    let addr_spec = yaml_str(map, "inet4-address")
        .or_else(|| yaml_str(map, "inet4_address"))
        .unwrap_or_else(|| "172.19.0.1/30".to_string());
    let (address, netmask) = parse_cidr_v4(&addr_spec).ok_or_else(|| {
        Error::config(format!("tun.inet4-address {addr_spec:?} is not an IPv4 CIDR"))
    })?;
    let mtu = map
        .get("mtu")
        .and_then(Yaml::as_u64)
        .and_then(|m| u16::try_from(m).ok())
        .unwrap_or(9000);
    let dns_hijack: Vec<std::net::IpAddr> = map
        .get("dns-hijack")
        .and_then(Yaml::as_sequence)
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str())
                .filter_map(|s| s.trim().parse().ok())
                .collect()
        })
        .unwrap_or_default();
    Ok(Some(crate::inbound::tun::TunConfig {
        tag: yaml_str(map, "tag").unwrap_or_else(|| "tun".to_string()),
        name: yaml_str(map, "device").or_else(|| yaml_str(map, "interface-name")).unwrap_or_default(),
        address,
        netmask,
        mtu,
        dns_hijack,
        inet6_address: parse_inet6_address(map),
    }))
}

/// `inet6-address: fd00::1/126` (mihomo also accepts a bare address).
fn parse_inet6_address(map: &BTreeMap<String, Yaml>) -> Option<(std::net::Ipv6Addr, u8)> {
    let spec = yaml_str(map, "inet6-address")?;
    let (ip, prefix) = spec.trim().split_once('/')?;
    let ip: std::net::Ipv6Addr = ip.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    (prefix <= 128).then_some((ip, prefix))
}

fn parse_cidr_v4(s: &str) -> Option<(std::net::Ipv4Addr, u8)> {
    let (ip, prefix) = s.trim().split_once('/')?;
    let ip: std::net::Ipv4Addr = ip.parse().ok()?;
    let prefix: u8 = prefix.parse().ok()?;
    (prefix <= 32).then_some((ip, prefix))
}

/// mihomo `listeners:` — server-side proxy listeners. Supported types:
/// shadowsocks, trojan, vmess, vless (+ optional TLS via
/// certificate/private-key PEM paths).
fn parse_proxy_servers(
    raw: Option<&[BTreeMap<String, Yaml>]>,
) -> Result<Vec<crate::inbound::proxy_server::ServerConfig>> {
    use crate::inbound::proxy_server::{ServerConfig, ServerProtocol, ServerTls};
    let Some(list) = raw else {
        return Ok(Vec::new());
    };
    let mut out = Vec::with_capacity(list.len());
    for (i, entry) in list.iter().enumerate() {
        let tag = yaml_str(entry, "name").unwrap_or_else(|| format!("listener-{i}"));
        let ltype = yaml_str(entry, "type").unwrap_or_default();
        let bind = yaml_str(entry, "listen").unwrap_or_else(|| "0.0.0.0".to_string());
        let port: u16 = entry
            .get("port")
            .and_then(Yaml::as_u64)
            .map(|p| p as u16)
            .or_else(|| yaml_str(entry, "port").and_then(|p| p.parse().ok()))
            .ok_or_else(|| Error::config(format!("listener {tag:?} missing port")))?;
        let tls = match (
            yaml_str(entry, "certificate"),
            yaml_str(entry, "private-key"),
        ) {
            (Some(cert_pem), Some(key_pem)) => Some(ServerTls { cert_pem, key_pem }),
            _ => None,
        };
        // users: [{uuid/password: ...}] — first entry, mihomo style.
        let user_field = |key: &str| -> Option<String> {
            entry
                .get("users")
                .and_then(Yaml::as_sequence)
                .and_then(|u| u.first())
                .and_then(|u| u.get(key))
                .and_then(Yaml::as_str)
                .map(str::to_string)
        };
        let protocol = match ltype.as_str() {
            "shadowsocks" => ServerProtocol::Shadowsocks {
                method: yaml_str(entry, "cipher").unwrap_or_default(),
                password: yaml_str(entry, "password").unwrap_or_default(),
            },
            "trojan" => ServerProtocol::Trojan {
                password: user_field("password")
                    .or_else(|| yaml_str(entry, "password"))
                    .unwrap_or_default(),
                tls,
            },
            "vmess" => ServerProtocol::Vmess {
                uuid: user_field("uuid")
                    .or_else(|| yaml_str(entry, "uuid"))
                    .unwrap_or_default(),
                security: yaml_str(entry, "cipher").unwrap_or_else(|| "auto".into()),
            },
            "vless" => ServerProtocol::Vless {
                uuid: user_field("uuid")
                    .or_else(|| yaml_str(entry, "uuid"))
                    .unwrap_or_default(),
                tls,
            },
            "hysteria2" | "hy2" => ServerProtocol::Hysteria2 {
                password: user_field("password")
                    .or_else(|| yaml_str(entry, "password"))
                    .or_else(|| yaml_str(entry, "auth"))
                    .unwrap_or_default(),
                obfs: match yaml_str(entry, "obfs").as_deref() {
                    None | Some("") => None,
                    // Server-side salamander is not implemented; refuse.
                    Some(_) => {
                        return Err(Error::config(format!(
                            "listener {tag:?}: hysteria2 server-side obfs is not \
                             implemented yet; drop the obfs keys"
                        )))
                    }
                },
                tls,
            },
            "tuic" => ServerProtocol::Tuic {
                uuid: user_field("uuid")
                    .or_else(|| yaml_str(entry, "uuid"))
                    .unwrap_or_default(),
                password: user_field("password")
                    .or_else(|| yaml_str(entry, "password"))
                    .unwrap_or_default(),
                tls,
            },
            other => {
                return Err(Error::config(format!(
                    "listener {tag:?}: type {other:?} is not supported as a server yet \
                     (supported: shadowsocks, trojan, vmess, vless, hysteria2, tuic)"
                )))
            }
        };
        out.push(ServerConfig {
            tag,
            bind,
            port,
            protocol,
        });
    }
    Ok(out)
}

/// Expand mihomo `SUB-RULE,<condition>,<bundle-name>` lines: when the
/// condition holds, the named bundle's rules run with THEIR outbounds;
/// if none of them matches, evaluation continues past the reference.
/// Equivalent sequential form: each bundle rule gated by the condition
/// (`AND,(<cond>),(<bundle rule>),<bundle outbound>`). Nested SUB-RULE
/// references inside bundles recurse (with a depth guard).
fn expand_sub_rules(
    rules: Vec<String>,
    bundles: &Option<BTreeMap<String, Vec<String>>>,
) -> Result<Vec<String>> {
    fn expand(
        rules: &[String],
        bundles: &BTreeMap<String, Vec<String>>,
        depth: usize,
    ) -> Result<Vec<String>> {
        let mut out = Vec::with_capacity(rules.len());
        for rule in rules {
            let line = rule.trim();
            let Some(rest) = line
                .strip_prefix("SUB-RULE,")
                .or_else(|| line.strip_prefix("sub-rule,"))
            else {
                out.push(rule.clone());
                continue;
            };
            if depth > 8 {
                return Err(Error::config("sub-rules nested too deeply"));
            }
            // The bundle name is the last comma token; everything before
            // is the condition, a parenthesized rule without outbound
            // (e.g. `(AND,((NETWORK,UDP),(DOMAIN,x.com)))`).
            let (cond, name) = rest
                .rsplit_once(',')
                .ok_or_else(|| Error::config(format!("malformed SUB-RULE {line:?}")))?;
            let cond = cond.trim();
            let cond_core = cond
                .strip_prefix('(')
                .and_then(|c| c.strip_suffix(')'))
                .unwrap_or(cond);
            if cond_core.is_empty() {
                return Err(Error::config(format!("SUB-RULE without condition: {line:?}")));
            }
            let name = name.trim();
            let Some(bundle) = bundles.get(name) else {
                return Err(Error::config(format!(
                    "SUB-RULE references unknown sub-rule {name:?}"
                )));
            };
            for sub in expand(bundle, bundles, depth + 1)? {
                // A trailing `no-resolve` sits after the outbound.
                let (sub, tail) = match sub.trim().strip_suffix(",no-resolve") {
                    Some(head) => (head, ",no-resolve"),
                    None => (sub.trim(), ""),
                };
                if let Some((body, outbound)) = sub.rsplit_once(',') {
                    if body.trim().eq_ignore_ascii_case("MATCH") {
                        out.push(format!("AND,(({cond_core})),{outbound}{tail}"));
                    } else {
                        out.push(format!("AND,(({cond_core}),({body})),{outbound}{tail}"));
                    }
                } else {
                    out.push(sub.to_string());
                }
            }
        }
        Ok(out)
    }
    let bundles = match bundles {
        Some(b) => b,
        None => &BTreeMap::new(),
    };
    expand(&rules, bundles, 0)
}

/// mihomo `plugin: obfs` + `plugin-opts: {mode: http|tls, host}`.
fn parse_obfs(entry: &BTreeMap<String, Yaml>) -> Result<Option<crate::outbound::ObfsMode>> {
    let Some(plugin) = yaml_str(entry, "plugin") else {
        // Obsolete flat spelling: `obfs: http` / `obfs-host: x`.
        return match yaml_str(entry, "obfs") {
            None => Ok(None),
            Some(mode) => Ok(Some(crate::outbound::ObfsMode {
                http: match mode.as_str() {
                    "http" => true,
                    "tls" => false,
                    other => {
                        return Err(Error::config(format!(
                            "unsupported obfs mode {other:?} (http|tls)"
                        )))
                    }
                },
                host: yaml_str(entry, "obfs-host").unwrap_or_else(|| "bing.com".to_string()),
            })),
        };
    };
    if plugin != "obfs" {
        return Err(Error::config(format!(
            "shadowsocks plugin {plugin:?} is not supported (only simple-obfs)"
        )));
    }
    let (mut http, mut host) = (true, None);
    if let Some(Yaml::Mapping(opts)) = entry.get("plugin-opts") {
        if let Some(mode) = opts
            .get(Yaml::String("mode".into()))
            .and_then(Yaml::as_str)
        {
            http = match mode {
                "http" => true,
                "tls" => false,
                other => {
                    return Err(Error::config(format!(
                        "unsupported obfs mode {other:?} (http|tls)"
                    )))
                }
            };
        }
        host = opts
            .get(Yaml::String("host".into()))
            .and_then(Yaml::as_str)
            .map(str::to_string);
    }
    Ok(Some(crate::outbound::ObfsMode {
        http,
        host: host.unwrap_or_else(|| "bing.com".to_string()),
    }))
}

/// Resolve a shadowtls inner proxy by name to its leaf kind (nested
/// shadowtls is refused; depth guard).
fn resolve_inner_kind(
    name: &str,
    all: &[BTreeMap<String, Yaml>],
    depth: usize,
) -> Result<crate::outbound::OutboundKind> {
    if depth > 4 {
        return Err(Error::config("shadowtls proxy nesting too deep"));
    }
    let Some(entry) = all
        .iter()
        .find(|e| yaml_str(e, "name").as_deref() == Some(name))
    else {
        return Err(Error::config(format!(
            "shadowtls references unknown proxy {name:?}"
        )));
    };
    let ptype = yaml_str(entry, "type").unwrap_or_default();
    if ptype == "shadowtls" {
        return Err(Error::config(
            "shadowtls cannot wrap another shadowtls outbound",
        ));
    }
    let cfg = parse_proxy(entry, 0, all)?;
    Ok(cfg.kind)
}

/// `client-fingerprint: chrome|firefox` (mihomo's uTLS profiles).
fn parse_fingerprint(
    entry: &BTreeMap<String, Yaml>,
    name: &str,
) -> Result<Option<crate::proto::reality::UtslProfile>> {
    let Some(fp) = yaml_str(entry, "client-fingerprint") else {
        return Ok(None);
    };
    match fp.to_ascii_lowercase().as_str() {
        "" => Ok(None),
        "chrome" => Ok(Some(crate::proto::reality::UtslProfile::Chrome)),
        "firefox" => Ok(Some(crate::proto::reality::UtslProfile::Firefox)),
        other => Err(Error::config(format!(
            "proxy {name:?}: client-fingerprint {other:?} is not implemented yet              (chrome, firefox)"
        ))),
    }
}

fn yaml_str(entry: &BTreeMap<String, Yaml>, key: &str) -> Option<String> {
    entry.get(key).and_then(|v| match v {
        Yaml::String(s) => Some(s.clone()),
        Yaml::Number(n) => Some(n.to_string()),
        Yaml::Bool(b) => Some(b.to_string()),
        _ => None,
    })
}

fn parse_proxy(
    entry: &BTreeMap<String, Yaml>,
    index: usize,
    all: &[BTreeMap<String, Yaml>],
) -> Result<OutboundConfig> {
    let name = yaml_str(entry, "name")
        .unwrap_or_else(|| format!("proxy-{index}"));
    let ptype = yaml_str(entry, "type").unwrap_or_default();
    // Wireguard carries server/port on peers[0], not the entry itself.
    let is_wireguard = ptype == "wireguard";
    let server = if is_wireguard {
        String::new()
    } else {
        yaml_str(entry, "server").ok_or_else(|| {
            Error::config(format!("proxy {name:?} missing server"))
        })?
    };
    let port: u16 = if is_wireguard {
        0
    } else {
        entry
            .get("port")
            .and_then(Yaml::as_u64)
            .map(|p| p as u16)
            .or_else(|| yaml_str(entry, "port").and_then(|p| p.parse().ok()))
            .ok_or_else(|| Error::config(format!("proxy {name:?} missing port")))?
    };
    // mihomo's default is udp: false.
    let udp = entry
        .get("udp")
        .and_then(Yaml::as_bool)
        .unwrap_or(false);

    let tls = parse_tls(entry);
    let transport = parse_transport(entry)?;

    let kind = match ptype.as_str() {
        "ss" => OutboundKind::Shadowsocks {
            method: SsMethod::parse(&yaml_str(entry, "cipher").unwrap_or_default())?,
            password: yaml_str(entry, "password").unwrap_or_default(),
            obfs: parse_obfs(entry)?,
            server,
            port,
        },
        "vmess" => {
            let uuid = yaml_str(entry, "uuid").unwrap_or_default();
            let uuid = uuid::Uuid::parse_str(&uuid)
                .map_err(|_| Error::config(format!("proxy {name:?} has an invalid uuid")))?;
            // The engine speaks AEAD VMess only; a non-zero alterId means a
            // legacy server that would only fail at connect time.
            let alter_id = entry
                .get("alterId")
                .or_else(|| entry.get("alter-id"))
                .and_then(Yaml::as_u64)
                .or_else(|| yaml_str(entry, "alterId").and_then(|v| v.parse().ok()))
                .unwrap_or(0);
            if alter_id != 0 {
                return Err(Error::config(format!(
                    "proxy {name:?}: vmess alterId={alter_id} (legacy, non-AEAD) is not \
                     supported by the Rust engine; use an alterId 0 server"
                )));
            }
            OutboundKind::Vmess {
                security: VmessSecurity::parse(&yaml_str(entry, "cipher").unwrap_or_default())?,
                uuid,
                server,
                port,
                transport,
                tls,
            }
        }
        "vless" => {
            let vision = match yaml_str(entry, "flow").as_deref() {
                None | Some("") => false,
                Some("xtls-rprx-vision") => true,
                Some(other) => {
                    return Err(Error::config(format!(
                        "proxy {name:?}: vless flow {other:?} is not implemented yet \
                         (xtls-rprx-vision is)"
                    )))
                }
            };
            if vision {
                tracing::debug!(target: "engine",
                    "proxy {name:?}: xtls-rprx-vision (direct splice mode is not \
                     implemented; framing mode only)");
            }
            let uuid = yaml_str(entry, "uuid").unwrap_or_default();
            let uuid = uuid::Uuid::parse_str(&uuid)
                .map_err(|_| Error::config(format!("proxy {name:?} has an invalid uuid")))?;
            // REALITY: `reality-opts: {public-key, short-id}` + the
            // proxy-level `client-fingerprint` (reality implies one).
            let fp = parse_fingerprint(entry, &name)?;
            let reality = match entry.get("reality-opts") {
                Some(Yaml::Mapping(opts)) => {
                    let public_key = opts
                        .get(Yaml::String("public-key".into()))
                        .and_then(Yaml::as_str)
                        .ok_or_else(|| {
                            Error::config(format!(
                                "proxy {name:?}: reality-opts requires public-key"
                            ))
                        })?;
                    let short_id = opts
                        .get(Yaml::String("short-id".into()))
                        .and_then(Yaml::as_str)
                        .unwrap_or("")
                        .to_string();
                    Some(crate::proto::reality::RealityCfg {
                        server_name: tls
                            .server_name
                            .clone()
                            .or_else(|| yaml_str(entry, "server"))
                            .unwrap_or_default(),
                        public_key: public_key.to_string(),
                        short_id,
                        fingerprint: fp.unwrap_or(crate::proto::reality::UtslProfile::Chrome),
                        spider_x: None,
                    })
                }
                _ => None,
            };
            // A plain fingerprint applies only without reality.
            let fingerprint = if reality.is_some() { None } else { fp };
            OutboundKind::Vless {
                uuid,
                server,
                port,
                transport,
                tls,
                reality,
                fingerprint,
                vision,
            }
        }
        "trojan" => {
            // mihomo treats trojan as TLS-by-default (the protocol is
            // defined over TLS); `tls: false` is the explicit opt-out.
            let tls_enabled = entry
                .get("tls")
                .and_then(Yaml::as_bool)
                .unwrap_or(true);
            let mut tls = tls;
            tls.enabled = tls_enabled;
            OutboundKind::Trojan {
                password: yaml_str(entry, "password").unwrap_or_default(),
                server,
                port,
                transport,
                tls,
            }
        }
        "socks5" => OutboundKind::Socks {
            username: yaml_str(entry, "username"),
            password: yaml_str(entry, "password"),
            server,
            port,
        },
        "http" => OutboundKind::Http {
            username: yaml_str(entry, "username"),
            password: yaml_str(entry, "password"),
            server,
            port,
        },
        "hysteria2" | "hy2" => OutboundKind::Hysteria2 {
            password: yaml_str(entry, "password").unwrap_or_default(),
            sni: yaml_str(entry, "sni"),
            skip_verify: entry
                .get("skip-cert-verify")
                .and_then(Yaml::as_bool)
                .unwrap_or(false),
            // Only salamander exists upstream; an unknown obfs errors.
            obfs: match yaml_str(entry, "obfs").as_deref() {
                None | Some("") => None,
                Some("salamander") => yaml_str(entry, "obfs-password"),
                Some(other) => {
                    return Err(Error::config(format!(
                        "proxy {name:?}: obfs {other:?} not supported (salamander)"
                    )))
                }
            },
            server,
            port,
        },
        "tuic" => OutboundKind::Tuic {
            uuid: yaml_str(entry, "uuid")
                .unwrap_or_default()
                .parse()
                .map_err(|e| Error::config(format!("proxy {name:?}: bad uuid: {e}")))?,
            password: yaml_str(entry, "password").unwrap_or_default(),
            sni: yaml_str(entry, "sni"),
            skip_verify: entry
                .get("skip-cert-verify")
                .and_then(Yaml::as_bool)
                .unwrap_or(false),
            udp_relay_mode: crate::proto::tuic::UdpRelayMode::parse(
                &yaml_str(entry, "udp-relay-mode").unwrap_or_else(|| "native".into()),
            )?,
            server,
            port,
        },
        "ssh" => OutboundKind::Ssh {
            user: yaml_str(entry, "user")
                .or_else(|| yaml_str(entry, "username"))
                .unwrap_or_default(),
            password: yaml_str(entry, "password"),
            private_key: yaml_str(entry, "private-key").or_else(|| yaml_str(entry, "private_key")),
            private_key_passphrase: yaml_str(entry, "private-key-passphrase"),
            host_key: entry
                .get("host-key")
                .and_then(Yaml::as_sequence)
                .map(|list| {
                    list.iter()
                        .filter_map(|v| v.as_str().map(str::to_string))
                        .collect()
                })
                .unwrap_or_default(),
            server,
            port,
        },
        "shadowtls" => {
            // v1/v2 are deprecated upstream; only v3 is implemented.
            match yaml_str(entry, "version").as_deref() {
                None | Some("3") => {}
                Some(other) => {
                    return Err(Error::config(format!(
                        "proxy {name:?}: shadowtls version {other:?} not supported (only 3)"
                    )))
                }
            }
            let inner_name = yaml_str(entry, "proxy").ok_or_else(|| {
                Error::config(format!(
                    "proxy {name:?}: shadowtls requires `proxy: <inner outbound>`"
                ))
            })?;
            let inner = resolve_inner_kind(&inner_name, all, 0)?;
            OutboundKind::ShadowTls {
                server,
                port,
                password: yaml_str(entry, "password").unwrap_or_default(),
                sni: yaml_str(entry, "sni").unwrap_or_default(),
                skip_verify: entry
                    .get("skip-cert-verify")
                    .and_then(Yaml::as_bool)
                    .unwrap_or(false),
                inner: Box::new(inner),
            }
        }
        "wireguard" => {
            let peer = entry
                .get("peers")
                .and_then(Yaml::as_sequence)
                .and_then(|p| p.first())
                .ok_or_else(|| {
                    Error::config(format!("proxy {name:?}: wireguard requires peers[0]"))
                })?;
            let peers_entry: BTreeMap<String, Yaml> = match peer {
                Yaml::Mapping(m) => m
                    .iter()
                    .filter_map(|(k, v)| {
                        k.as_str().map(|ks| (ks.to_string(), v.clone()))
                    })
                    .collect(),
                _ => return Err(Error::config(format!(
                    "proxy {name:?}: wireguard peers[0] must be a mapping"
                ))),
            };
            OutboundKind::Wireguard(crate::proto::wireguard::WgOut {
                server: yaml_str(&peers_entry, "server").ok_or_else(|| {
                    Error::config(format!("proxy {name:?}: wireguard peer missing server"))
                })?,
                port: peers_entry
                    .get("port")
                    .and_then(Yaml::as_u64)
                    .and_then(|p| u16::try_from(p).ok())
                    .or_else(|| yaml_str(&peers_entry, "port").and_then(|p| p.parse().ok()))
                    .ok_or_else(|| {
                        Error::config(format!("proxy {name:?}: wireguard peer missing port"))
                    })?,
                private_key: yaml_str(entry, "private-key").unwrap_or_default(),
                peer_public_key: yaml_str(&peers_entry, "public-key").unwrap_or_default(),
                pre_shared_key: yaml_str(&peers_entry, "pre-shared-key")
                    .filter(|k| !k.is_empty()),
                local_ip: yaml_str(entry, "ip")
                    .and_then(|ip| ip.parse().ok())
                    .unwrap_or(std::net::Ipv4Addr::new(172, 16, 0, 1)),
                local_ipv6: yaml_str(entry, "ipv6").and_then(|ip| ip.parse().ok()),
                mtu: entry
                    .get("mtu")
                    .and_then(Yaml::as_u64)
                    .and_then(|m| u16::try_from(m).ok())
                    .unwrap_or(0),
                reserved: entry
                    .get("reserved")
                    .and_then(Yaml::as_sequence)
                    .map(|list| {
                        let mut r = [0u8; 3];
                        for (i, v) in list.iter().take(3).enumerate() {
                            r[i] = v.as_u64().unwrap_or(0) as u8;
                        }
                        r
                    })
                    .unwrap_or([0u8; 3]),
                // mihomo's wireguard is udp-capable unless opted out.
                udp: entry
                    .get("udp")
                    .and_then(Yaml::as_bool)
                    .unwrap_or(true),
            })
        }
        other => {
            let supported = "ss, vmess, vless, trojan, socks5, http, hysteria2, tuic, wireguard";
            return Err(Error::config(format!(
                "proxy {name:?}: type {other:?} is not supported by the Rust engine yet \
                 (supported: {supported})"
            )));
        }
    };
    // hy2/tuic are UDP-native: mihomo defaults their udp to true.
    let udp = match &kind {
        OutboundKind::Hysteria2 { .. } | OutboundKind::Tuic { .. } => {
            entry.get("udp").and_then(Yaml::as_bool).unwrap_or(true)
        }
        _ => udp,
    };
    Ok(OutboundConfig {
        name,
        udp,
        kind,
    })
}

/// mihomo `hosts:` values may be an IP string, an IP list, or (legacy) an
/// int; collect every parseable address per lowercase domain.
fn parse_nameserver_policy(
    raw: Option<&std::collections::HashMap<String, Yaml>>,
) -> Vec<(String, Vec<String>)> {
    let mut out = Vec::new();
    let Some(map) = raw else { return out };
    for (domain, value) in map {
        // Value: one nameserver string or a sequence of them.
        let urls: Vec<String> = match value {
            Yaml::String(s) => vec![s.clone()],
            Yaml::Sequence(items) => items
                .iter()
                .filter_map(|i| i.as_str().map(str::to_string))
                .collect(),
            _ => continue,
        };
        if !urls.is_empty() {
            out.push((domain.clone(), urls));
        }
    }
    out
}

fn parse_hosts(raw: Option<&std::collections::HashMap<String, Yaml>>) -> std::collections::HashMap<String, Vec<std::net::IpAddr>> {
    let mut out = std::collections::HashMap::new();
    let Some(map) = raw else { return out };
    for (domain, value) in map {
        let mut addrs = Vec::new();
        match value {
            Yaml::String(s) => {
                if let Ok(ip) = s.trim().parse() {
                    addrs.push(ip);
                }
            }
            Yaml::Number(n) => {
                if let Ok(ip) = n.to_string().parse() {
                    addrs.push(ip);
                }
            }
            Yaml::Sequence(items) => {
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

/// mihomo `sniffer:` block: `enable`, `override-destination` (mihomo
/// defaults it to true), `sniff: {TLS: .., HTTP: .., QUIC: ..}` (absent =
/// all on), `skip-domain` and `force-domain` (plain domains; `geosite:`
/// entries warn).
fn parse_sniffer(raw: Option<&BTreeMap<String, Yaml>>) -> crate::sniffer::SniffConfig {
    let Some(map) = raw else {
        return Default::default();
    };
    if !map
        .get("enable")
        .and_then(Yaml::as_bool)
        .unwrap_or(false)
    {
        return Default::default();
    }
    let (tls, http, quic) = match map.get("sniff") {
        Some(Yaml::Mapping(sub)) => {
            let has = |key: &str| {
                sub.keys().any(|k| {
                    k.as_str()
                        .is_some_and(|s| s.eq_ignore_ascii_case(key))
                })
            };
            (has("TLS"), has("HTTP"), has("QUIC"))
        }
        _ => (true, true, true),
    };
    // Per-protocol `ports: [...]` gates (`sniff: {TLS: {ports: [443]}}`).
    let ports_of = |key: &str| -> Vec<u16> {
        let Some(Yaml::Mapping(sub)) = map.get("sniff") else {
            return Vec::new();
        };
        let entry = sub.iter().find_map(|(k, v)| {
            let ks = k.as_str()?;
            ks.eq_ignore_ascii_case(key).then_some(v)
        });
        let Some(Yaml::Mapping(entry)) = entry else {
            return Vec::new();
        };
        let Some(Yaml::Sequence(list)) = entry.get("ports") else {
            return Vec::new();
        };
        list.iter()
            .filter_map(|v| match v {
                Yaml::Number(n) => n.as_u64().and_then(|p| u16::try_from(p).ok()),
                Yaml::String(s) => s.parse().ok(),
                _ => None,
            })
            .collect()
    };
    let domain_list = |key: &str| match map.get(key) {
        Some(Yaml::Sequence(items)) => items
            .iter()
            .filter_map(|i| i.as_str())
            // `+.domain` is mihomo's suffix wildcard; the suffix checks
            // match the plain form.
            .map(|d| d.strip_prefix("+.").unwrap_or(d).to_string())
            .filter(|d| {
                if d.starts_with("geosite:") || d.contains('*') {
                    tracing::warn!(target: "engine", "sniffer {key} {d:?} not supported");
                    false
                } else {
                    true
                }
            })
            .collect(),
        _ => Vec::new(),
    };
    crate::sniffer::SniffConfig {
        tls,
        http,
        quic,
        override_destination: map
            .get("override-destination")
            .and_then(Yaml::as_bool)
            .unwrap_or(true),
        skip_domains: domain_list("skip-domain"),
        force_domains: domain_list("force-domain"),
        tls_ports: ports_of("TLS"),
        http_ports: ports_of("HTTP"),
        quic_ports: ports_of("QUIC"),
    }
}

fn parse_tls(entry: &BTreeMap<String, Yaml>) -> TlsSettings {
    let enabled = entry
        .get("tls")
        .and_then(Yaml::as_bool)
        .unwrap_or(false);
    TlsSettings {
        enabled,
        server_name: yaml_str(entry, "sni")
            .or_else(|| yaml_str(entry, "servername")),
        skip_cert_verify: entry
            .get("skip-cert-verify")
            .and_then(Yaml::as_bool)
            .unwrap_or(false),
        alpn: Vec::new(),
    }
}

#[allow(clippy::needless_borrows_for_generic_args)]
fn parse_transport(entry: &BTreeMap<String, Yaml>) -> Result<TransportKind> {
    let network = yaml_str(entry, "network").unwrap_or_default();
    // httpupgrade shares ws-opts for path/headers (mihomo convention).
    let (ws_path, ws_host) = ws_opts(entry);
    match network.as_str() {
        "" | "tcp" => Ok(TransportKind::Tcp),
        "ws" => Ok(TransportKind::Ws {
            path: ws_path,
            host: ws_host,
        }),
        "httpupgrade" => Ok(TransportKind::HttpUpgrade {
            path: ws_path,
            host: ws_host,
        }),
        "grpc" => {
            let mut service = "TunService".to_string();
            let mut host = None;
            if let Some(Yaml::Mapping(opts)) = entry.get("grpc-opts") {
                if let Some(s) = opts
                    .get(Yaml::String("grpc-service-name".into()))
                    .and_then(Yaml::as_str)
                {
                    service = s.to_string();
                }
                if let Some(Yaml::Mapping(headers)) = opts.get(Yaml::String("headers".into())) {
                    if let Some(h) = headers
                        .get(Yaml::String("Host".into()))
                        .and_then(Yaml::as_str)
                    {
                        host = Some(h.to_string());
                    }
                }
            }
            Ok(TransportKind::Grpc {
                service_name: service,
                host,
            })
        }
        other => Err(Error::config(format!(
            "transport {other:?} is not supported by the Rust engine yet (supported: tcp, ws, httpupgrade, grpc)"
        ))),
    }
}

/// `ws-opts: {path, headers: {Host: x}}` — shared by ws and httpupgrade.
fn ws_opts(entry: &BTreeMap<String, Yaml>) -> (String, Option<String>) {
    let mut path = "/".to_string();
    let mut host = None;
    if let Some(Yaml::Mapping(opts)) = entry.get("ws-opts") {
        if let Some(p) = opts.get(Yaml::String("path".into())) {
            if let Some(s) = p.as_str() {
                path = s.to_string();
            }
        }
        if let Some(Yaml::Mapping(headers)) = opts.get(Yaml::String("headers".into())) {
            if let Some(h) = headers.get(Yaml::String("Host".into())) {
                if let Some(s) = h.as_str() {
                    host = Some(s.to_string());
                }
            }
        }
    }
    (path, host)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
mixed-port: 7890
redir-port: 7891
tproxy-port: 7893
allow-lan: true
mode: rule
ipv6: false
external-controller: 127.0.0.1:9090
secret: ""
dns:
  enable: true
  listen: 0.0.0.0:7892
  enhanced-mode: fake-ip
  nameserver:
    - udp://223.5.5.5
  fake-ip-range: 198.18.0.1/15
  fake-ip-filter:
    - '*.lan'
proxies:
  - name: node-ss
    type: ss
    server: 10.0.0.5
    port: 8388
    cipher: aes-256-gcm
    password: psk-placeholder
    udp: true
  - name: node-vmess
    type: vmess
    server: vm.example
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 0
    cipher: auto
    tls: true
    network: ws
    ws-opts:
      path: /path
      headers:
        Host: cdn.example
  - name: node-trojan
    type: trojan
    server: t.example
    port: 443
    password: pw-placeholder
    sni: t.example
proxy-groups:
  - name: Auto
    type: url-test
    url: http://www.gstatic.com/generate_204
    interval: 300
    tolerance: 50
    proxies:
      - node-ss
      - node-vmess
  - name: Manual
    type: select
    proxies:
      - Auto
      - DIRECT
rules:
  - DOMAIN-SUFFIX,internal.test,DIRECT
  - GEOIP,CN,DIRECT
  - MATCH,Auto
"#;

    #[test]
    fn loads_full_config() {
        let cfg = load(SAMPLE).unwrap();
        assert_eq!(cfg.listeners.len(), 3);
        assert!(cfg.listeners.iter().any(|l| l.kind == ListenerKind::Mixed && l.port == 7890));
        assert!(cfg.listeners.iter().any(|l| l.kind == ListenerKind::Redir));
        assert!(cfg.listeners.iter().any(|l| l.kind == ListenerKind::Tproxy));
        assert_eq!(cfg.listeners[0].bind, "0.0.0.0");
        assert_eq!(cfg.outbounds.len(), 3);
        assert_eq!(cfg.groups.len(), 2);
        assert_eq!(cfg.rules.len(), 3);
        let dns = cfg.dns.as_ref().unwrap();
        assert!(dns.enable);
        assert_eq!(dns.listen.as_deref(), Some("0.0.0.0:7892"));
        assert_eq!(dns.fakeip_range, "198.18.0.1/15");
        let api = cfg.api.as_ref().unwrap();
        assert_eq!(api.port, 9090);
    }

    #[test]
    fn rejects_unsupported_types_precisely() {
        let cfg = r#"
mixed-port: 7890
proxies:
  - name: ssr
    type: ssr
    server: h.example
    port: 443
    cipher: aes-128-cfb
    password: x
    protocol: origin
    obfs: plain
rules:
  - MATCH,ssr
"#;
        let err = load(cfg).err().unwrap().to_string();
        assert!(err.contains("ssr"), "{err}");
        assert!(err.contains("not supported"), "{err}");
    }

    #[test]
    fn wireguard_parses() {
        let cfg = r#"
mixed-port: 7890
proxies:
  - name: wg
    type: wireguard
    private-key: aGkK
    ip: 172.16.0.2
    ipv6: fd00::2
    mtu: 1408
    reserved: [1, 2, 3]
    peers:
      - {server: wg.example, port: 51820, public-key: cHViCg==,
         pre-shared-key: cHNrCg==}
rules:
  - MATCH,wg
"#;
        let parsed = load(cfg).unwrap();
        let wg = parsed.outbounds.iter().find(|o| o.name == "wg").unwrap();
        match &wg.kind {
            OutboundKind::Wireguard(w) => {
                assert_eq!(w.server, "wg.example");
                assert_eq!(w.port, 51820);
                assert_eq!(w.peer_public_key, "cHViCg==");
                assert_eq!(w.pre_shared_key.as_deref(), Some("cHNrCg=="));
                assert_eq!(w.local_ip.to_string(), "172.16.0.2");
                assert_eq!(w.local_ipv6.map(|i| i.to_string()).as_deref(), Some("fd00::2"));
                assert_eq!(w.mtu, 1408);
                assert_eq!(w.reserved, [1, 2, 3]);
                assert!(w.udp, "mihomo defaults wg udp to true via our udp default");
            }
            other => panic!("unexpected kind {other:?}"),
        }
    }

    #[test]
    fn hysteria2_tuic_listeners_parse() {
        let cfg = r#"
mixed-port: 7890
proxies:
  - {name: n, type: socks5, server: 127.0.0.1, port: 1}
listeners:
  - {name: in-hy2, type: hysteria2, port: 38453, password: hpw}
  - {name: in-tu, type: tuic, port: 38454,
     users: [{uuid: b831381d-6324-4d53-ad4f-8cda48b30811, password: tpw}]}
rules:
  - MATCH,n
"#;
        let parsed = load(cfg).unwrap();
        let hy2 = &parsed.proxy_servers[0];
        assert!(matches!(
            &hy2.protocol,
            crate::inbound::proxy_server::ServerProtocol::Hysteria2 { password, .. }
                if password == "hpw"
        ));
        let tu = &parsed.proxy_servers[1];
        assert!(matches!(
            &tu.protocol,
            crate::inbound::proxy_server::ServerProtocol::Tuic { uuid, password, .. }
                if uuid == "b831381d-6324-4d53-ad4f-8cda48b30811" && password == "tpw"
        ));
    }

    #[test]
    fn hysteria2_and_tuic_parse() {
        let cfg = r#"
mixed-port: 7890
proxies:
  - {name: h2, type: hysteria2, server: h.example, port: 443, password: pw,
     sni: h.example, skip-cert-verify: true, obfs: salamander, obfs-password: k}
  - {name: tu, type: tuic, server: t.example, port: 443,
     uuid: b831381d-6324-4d53-ad4f-8cda48b30811, password: pw,
     sni: t.example, udp-relay-mode: native}
rules:
  - MATCH,h2
"#;
        let parsed = load(cfg).unwrap();
        let h2 = parsed.outbounds.iter().find(|o| o.name == "h2").unwrap();
        assert!(h2.udp, "hy2 defaults udp to true");
        assert!(matches!(
            &h2.kind,
            OutboundKind::Hysteria2 { obfs, skip_verify, .. }
                if obfs.as_deref() == Some("k") && *skip_verify
        ));
        let tu = parsed.outbounds.iter().find(|o| o.name == "tu").unwrap();
        assert!(tu.udp, "tuic defaults udp to true");
        assert!(matches!(&tu.kind, OutboundKind::Tuic { .. }));
    }

    #[test]
    fn vision_flow_no_longer_rejected() {
        // Vision is implemented now (framing mode); the old rejection
        // must not come back.
        let cfg = r#"
mixed-port: 7890
proxies:
  - name: v
    type: vless
    server: v.example
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    flow: xtls-rprx-vision
rules:
  - MATCH,v
"#;
        let parsed = load(cfg).unwrap();
        let v = parsed.outbounds.iter().find(|o| o.name == "v").unwrap();
        assert!(matches!(&v.kind, OutboundKind::Vless { vision: true, .. }));
    }

    #[test]
    fn tun_block_parses() {
        let cfg = r#"
mixed-port: 7890
proxies:
  - {name: a, type: socks5, server: 127.0.0.1, port: 1}
rules:
  - MATCH,a
tun:
  enable: true
  device: utun9
  stack: system
  inet4-address: 172.19.0.1/30
  mtu: 1500
  dns-hijack: [198.18.0.0]
"#;
        let parsed = load(cfg).unwrap();
        let tun = parsed.tun.unwrap();
        assert_eq!(tun.name, "utun9");
        assert_eq!(tun.netmask, 30);
        assert_eq!(tun.mtu, 1500);
        assert_eq!(tun.dns_hijack.len(), 1);
    }

    #[test]
    fn tun_disabled_is_none() {
        let cfg = r#"
mixed-port: 7890
proxies:
  - {name: a, type: socks5, server: 127.0.0.1, port: 1}
rules:
  - MATCH,a
tun:
  enable: false
"#;
        assert!(load(cfg).unwrap().tun.is_none());
    }

    #[test]
    fn legacy_alter_id_rejected() {
        let cfg = r#"
mixed-port: 7890
proxies:
  - name: v
    type: vmess
    server: v.example
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    alterId: 16
    cipher: auto
rules:
  - MATCH,v
"#;
        let err = load(cfg).err().unwrap().to_string();
        assert!(err.contains("alterId=16"), "{err}");
    }

    #[test]
    fn udp_defaults_false_like_mihomo() {
        let cfg = load(SAMPLE).unwrap();
        // SAMPLE sets udp: true explicitly on node-ss.
        assert!(cfg.outbounds.iter().any(|o| o.name == "node-ss" && o.udp));
        let minimal = r#"
mixed-port: 7890
proxies:
  - {name: n, type: socks5, server: 127.0.0.1, port: 1}
rules:
  - MATCH,n
"#;
        let parsed = load(minimal).unwrap();
        let node = parsed.outbounds.iter().find(|o| o.name == "n").unwrap();
        assert!(!node.udp, "omitted udp must default to false (mihomo default)");
    }

    #[test]
    fn loopback_bind_without_allow_lan() {
        let cfg = r#"
mixed-port: 7890
proxies:
  - {name: a, type: socks5, server: 127.0.0.1, port: 1}
rules:
  - MATCH,a
"#;
        let parsed = load(cfg).unwrap();
        assert_eq!(parsed.listeners[0].bind, "127.0.0.1");
    }

    #[test]
    fn sniffer_block_parses() {
        let cfg = r#"
mixed-port: 7890
proxies:
  - {name: n, type: socks5, server: 127.0.0.1, port: 1}
sniffer:
  enable: true
  override-destination: false
  sniff:
    TLS: {ports: [443]}
  skip-domain: ["ignored.test", "+.wild.test", "geosite:cn"]
rules:
  - MATCH,n
"#;
        let parsed = load(cfg).unwrap();
        assert!(parsed.sniff.enabled());
        assert!(parsed.sniff.tls);
        assert!(!parsed.sniff.http, "HTTP not listed under sniff:");
        assert!(!parsed.sniff.override_destination);
        // Suffix wildcards normalize; geosite refs drop with a warning.
        assert_eq!(parsed.sniff.skip_domains, vec!["ignored.test", "wild.test"]);
    }

    #[test]
    fn sniffer_disabled_by_default() {
        let cfg = r#"
mixed-port: 7890
proxies:
  - {name: n, type: socks5, server: 127.0.0.1, port: 1}
rules:
  - MATCH,n
"#;
        let parsed = load(cfg).unwrap();
        assert!(!parsed.sniff.enabled());
    }

    #[test]
    fn httpupgrade_transport_parses() {
        let cfg = r#"
mixed-port: 7890
proxies:
  - name: vm
    type: vmess
    server: 127.0.0.1
    port: 443
    uuid: b831381d-6324-4d53-ad4f-8cda48b30811
    cipher: auto
    network: httpupgrade
    ws-opts:
      path: /up
      headers: {Host: up.test}
rules:
  - MATCH,vm
"#;
        let parsed = load(cfg).unwrap();
        let vm = parsed
            .outbounds
            .iter()
            .find(|o| o.name == "vm")
            .unwrap();
        let transport = match &vm.kind {
            crate::outbound::OutboundKind::Vmess { transport, .. } => transport.clone(),
            other => panic!("unexpected outbound kind {other:?}"),
        };
        assert!(matches!(
            &transport,
            crate::outbound::TransportKind::HttpUpgrade { path, host }
                if path == "/up" && host.as_deref() == Some("up.test")
        ));
    }

    #[test]
    fn server_listeners_parse() {
        let cfg = r#"
mixed-port: 7890
proxies:
  - {name: n, type: socks5, server: 127.0.0.1, port: 1}
listeners:
  - {name: in-ss, type: shadowsocks, port: 38388, cipher: aes-256-gcm, password: pw}
  - {name: in-tr, type: trojan, port: 38403, users: [{password: tpw}],
     certificate: /c.pem, private-key: /k.pem}
  - {name: in-vm, type: vmess, port: 38401, users: [{uuid: b831381d-6324-4d53-ad4f-8cda48b30811}]}
rules:
  - MATCH,n
"#;
        let parsed = load(cfg).unwrap();
        assert_eq!(parsed.proxy_servers.len(), 3);
        let ss = &parsed.proxy_servers[0];
        assert_eq!(ss.tag, "in-ss");
        assert_eq!(ss.port, 38388);
        assert!(matches!(
            &ss.protocol,
            crate::inbound::proxy_server::ServerProtocol::Shadowsocks { method, password }
                if method == "aes-256-gcm" && password == "pw"
        ));
        let tr = &parsed.proxy_servers[1];
        assert!(matches!(
            &tr.protocol,
            crate::inbound::proxy_server::ServerProtocol::Trojan { password, tls: Some(_) }
                if password == "tpw"
        ));
        let vm = &parsed.proxy_servers[2];
        assert!(matches!(
            &vm.protocol,
            crate::inbound::proxy_server::ServerProtocol::Vmess { security, .. }
                if security == "auto"
        ));
    }

    #[test]
    fn ss_obfs_parses() {
        let cfg = r#"
mixed-port: 7890
proxies:
  - {name: n, type: ss, server: h.example, port: 443, cipher: aes-256-gcm,
     password: pw, plugin: obfs, plugin-opts: {mode: tls, host: obfs.example}}
rules:
  - MATCH,n
"#;
        let parsed = load(cfg).unwrap();
        let n = parsed.outbounds.iter().find(|o| o.name == "n").unwrap();
        assert!(matches!(
            &n.kind,
            OutboundKind::Shadowsocks { obfs: Some(m), .. }
                if !m.http && m.host == "obfs.example"
        ));
    }

    #[test]
    fn ssh_and_shadowtls_parse() {
        let cfg = r#"
mixed-port: 7890
proxies:
  - {name: inner-trojan, type: trojan, server: t.example, port: 443,
     password: tpw, sni: t.example, skip-cert-verify: true}
  - {name: sh, type: shadowtls, server: st.example, port: 443,
     password: stpw, sni: st.example, version: 3, proxy: inner-trojan}
  - {name: s1, type: ssh, server: ssh.example, port: 22, user: root,
     private-key: "-----BEGIN OPENSSH PRIVATE KEY-----\nfake\n-----END OPENSSH PRIVATE KEY-----"}
rules:
  - MATCH,sh
"#;
        let parsed = load(cfg).unwrap();
        let sh = parsed.outbounds.iter().find(|o| o.name == "sh").unwrap();
        match &sh.kind {
            OutboundKind::ShadowTls {
                password, inner, ..
            } => {
                assert_eq!(password, "stpw");
                assert!(matches!(**inner, OutboundKind::Trojan { .. }));
            }
            other => panic!("unexpected kind {other:?}"),
        }
        let s1 = parsed.outbounds.iter().find(|o| o.name == "s1").unwrap();
        assert!(matches!(
            &s1.kind,
            OutboundKind::Ssh { user, private_key: Some(_), .. } if user == "root"
        ));
    }

    #[test]
    fn shadowtls_v2_rejected() {
        let cfg = r#"
mixed-port: 7890
proxies:
  - {name: inner, type: trojan, server: t.example, port: 443, password: tpw}
  - {name: sh, type: shadowtls, server: st.example, port: 443,
     password: p, sni: s, version: 2, proxy: inner}
rules:
  - MATCH,sh
"#;
        let err = load(cfg).err().unwrap().to_string();
        assert!(err.contains("version"), "{err}");
    }

    #[test]
    fn vless_reality_and_fingerprint_parse() {
        let cfg = r#"
mixed-port: 7890
proxies:
  - {name: r, type: vless, server: x, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811,
     tls: true, servername: cam.example, client-fingerprint: firefox,
     reality-opts: {public-key: cGs=, short-id: "0102"}}
  - {name: u, type: vless, server: y, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811,
     tls: true, servername: plain.example, client-fingerprint: chrome}
rules:
  - MATCH,r
"#;
        let parsed = load(cfg).unwrap();
        let r = parsed.outbounds.iter().find(|o| o.name == "r").unwrap();
        match &r.kind {
            OutboundKind::Vless { reality: Some(rc), fingerprint: None, .. } => {
                assert_eq!(rc.server_name, "cam.example");
                assert_eq!(rc.short_id, "0102");
                assert!(matches!(rc.fingerprint, crate::proto::reality::UtslProfile::Firefox));
            }
            other => panic!("unexpected {other:?}"),
        }
        let u = parsed.outbounds.iter().find(|o| o.name == "u").unwrap();
        assert!(matches!(
            &u.kind,
            OutboundKind::Vless { fingerprint: Some(_), reality: None, .. }
        ));
    }

    #[test]
    fn vless_vision_flow_parses() {
        let cfg = r#"
mixed-port: 7890
proxies:
  - {name: v, type: vless, server: x, port: 443,
     uuid: b831381d-6324-4d53-ad4f-8cda48b30811, tls: true,
     flow: xtls-rprx-vision, reality-opts: {public-key: cGs=, short-id: "01"}}
rules:
  - MATCH,v
"#;
        let parsed = load(cfg).unwrap();
        let v = parsed.outbounds.iter().find(|o| o.name == "v").unwrap();
        assert!(matches!(
            &v.kind,
            OutboundKind::Vless { vision: true, reality: Some(_), .. }
        ));

        let bad = r#"
mixed-port: 7890
proxies:
  - {name: v, type: vless, server: x, port: 443,
     uuid: b831381d-6324-4d53-ad4f-8cda48b30811, flow: xtls-rprx-origin}
rules:
  - MATCH,v
"#;
        let err = load(bad).err().unwrap().to_string();
        assert!(err.contains("xtls-rprx-origin"), "{err}");
    }

    #[test]
    fn unknown_fingerprint_rejected() {
        let cfg = r#"
mixed-port: 7890
proxies:
  - {name: n, type: vless, server: x, port: 443, uuid: b831381d-6324-4d53-ad4f-8cda48b30811,
     tls: true, client-fingerprint: safari}
rules:
  - MATCH,n
"#;
        let err = load(cfg).err().unwrap().to_string();
        assert!(err.contains("safari") && err.contains("not implemented yet"), "{err}");
    }

    #[test]
    fn sub_rules_expand_in_place() {
        let cfg = r#"
mixed-port: 7890
proxies:
  - {name: n, type: socks5, server: 127.0.0.1, port: 1}
sub-rules:
  private:
    - IP-CIDR,10.0.0.0/8,DIRECT
    - DOMAIN-SUFFIX,corp.test,DIRECT
    - MATCH,n
rules:
  - SUB-RULE,(OR,((DOMAIN-SUFFIX,corp.test),(NETWORK,udp))),private
  - MATCH,n
"#;
        let parsed = load(cfg).unwrap();
        // Each bundle rule is gated by the SUB-RULE condition, keeping
        // its own outbound; the bundle's MATCH gates to the condition.
        assert_eq!(
            parsed.rules[0],
            "AND,((OR,((DOMAIN-SUFFIX,corp.test),(NETWORK,udp))),(IP-CIDR,10.0.0.0/8)),DIRECT"
        );
        assert_eq!(
            parsed.rules[1],
            "AND,((OR,((DOMAIN-SUFFIX,corp.test),(NETWORK,udp))),(DOMAIN-SUFFIX,corp.test)),DIRECT"
        );
        assert_eq!(
            parsed.rules[2],
            "AND,((OR,((DOMAIN-SUFFIX,corp.test),(NETWORK,udp)))),n"
        );
        assert_eq!(parsed.rules[3], "MATCH,n");
        // The generated forms must actually parse and evaluate.
        let mut c = crate::rule::ConnContext {
            host: &crate::addr::Host::Domain("a.corp.test".into()),
            port: 443,
            source_ip: None,
            source_port: None,
            resolved: None,
            mode: crate::config::RuleMode::Rule,
            network: crate::rule::Network::Tcp,
            inbound: "",
            inbound_kind: "",
            inbound_port: None,
            process: None,
            uid: None,
            user: None,
            dscp: None,
        };
        let rule = crate::rule::Rule::parse(&parsed.rules[1]).unwrap();
        let sets = crate::rule::RuleSets::default();
        let geo = crate::rule::GeoLookups::default();
        assert!(rule.evaluate(&c, &sets, &geo));
        c.network = crate::rule::Network::Udp;
        let gated_match = crate::rule::Rule::parse(&parsed.rules[2]).unwrap();
        assert!(gated_match.evaluate(&c, &sets, &geo));
    }

    #[test]
    fn sub_rules_unknown_name_fails() {
        let cfg = r#"
mixed-port: 7890
proxies:
  - {name: n, type: socks5, server: 127.0.0.1, port: 1}
rules:
  - SUB-RULE,(DOMAIN,x.test),nope
  - MATCH,n
"#;
        assert!(load(cfg).is_err());
    }
}
