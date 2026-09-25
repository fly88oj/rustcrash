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
        wg_endpoints: Vec::new(),
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
                // SIP023 multi-user `users:` parsing is wired by the
                // integrator; the single-PSK shape stays as-is.
                users: Vec::new(),
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
            "restls" => ServerProtocol::Restls {
                password: yaml_str(entry, "password").unwrap_or_default(),
                restls_script: yaml_str(entry, "restls-script").filter(|s| !s.is_empty()),
                min_record_len: yaml_u64(entry, "min-record-len") as u32,
                rate_limit: yaml_u64(entry, "rate-limit") as u32,
                dest: yaml_str(entry, "dest")
                    .ok_or_else(|| {
                        Error::config(format!(
                            "listener {tag:?}: restls requires dest (the camouflage target)"
                        ))
                    })?,
            },
            "tlsmirror" => {
                let primary_key = yaml_str(entry, "primary-key").unwrap_or_default();
                if primary_key.is_empty() {
                    return Err(Error::config(format!(
                        "listener {tag:?}: tlsmirror requires primary-key"
                    )));
                }
                let suites = entry
                    .get("explicit-nonce-ciphersuites")
                    .and_then(Yaml::as_sequence)
                    .map(|list| {
                        list.iter()
                            .filter_map(|v| match v {
                                Yaml::Number(n) => n.as_u64().map(|x| x as u16),
                                Yaml::String(s) => s.parse().ok(),
                                _ => None,
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let mut defer_write_time = (0u64, 0u64);
                if let Some(Yaml::Mapping(sub)) =
                    entry.get("defer-instance-derived-write-time")
                {
                    defer_write_time = (
                        sub.get(Yaml::String("base-nanoseconds".into()))
                            .and_then(Yaml::as_u64)
                            .unwrap_or(0),
                        sub.get(Yaml::String("uniform-random-multiplier-nanoseconds".into()))
                            .and_then(Yaml::as_u64)
                            .unwrap_or(0),
                    );
                }
                let mut transport_padding = false;
                if let Some(Yaml::Mapping(sub)) = entry.get("transport-layer-padding") {
                    transport_padding = sub
                        .get(Yaml::String("enabled".into()))
                        .and_then(Yaml::as_bool)
                        .unwrap_or(false);
                }
                let enrolment = entry.get("connection-enrolment").and_then(|v| {
                    let m = v.as_mapping()?;
                    let get = |k: &str| {
                        m.get(Yaml::String(k.into()))
                            .and_then(Yaml::as_str)
                            .unwrap_or("")
                            .to_string()
                    };
                    Some((get("primary-ingress-outbound"), get("primary-egress-outbound")))
                });
                ServerProtocol::TlsMirror {
                    primary_key,
                    explicit_nonce_cipher_suites: suites,
                    defer_write_time,
                    transport_padding,
                    enrolment,
                    sequence_watermarking: entry
                        .get("sequence-watermarking-enabled")
                        .and_then(Yaml::as_bool)
                        .unwrap_or(false),
                    dest: yaml_str(entry, "dest")
                        .ok_or_else(|| {
                            Error::config(format!(
                                "listener {tag:?}: tlsmirror requires dest (the carrier target)"
                            ))
                        })?,
                }
            }
            "jls" => {
                let users = parse_user_list(entry, "users");
                if users.is_empty() {
                    return Err(Error::config(format!(
                        "listener {tag:?}: jls requires users (username/password pairs)"
                    )));
                }
                ServerProtocol::Jls {
                    sni: yaml_str(entry, "sni").unwrap_or_default(),
                    dest: yaml_str(entry, "dest")
                        .ok_or_else(|| {
                            Error::config(format!(
                                "listener {tag:?}: jls requires dest (the fallback target)"
                            ))
                        })?,
                    users,
                    alpn: yaml_str_list(entry, "alpn"),
                    rate_limit: yaml_u64(entry, "rate-limit") as u32,
                }
            }
            "snell" => {
                let raw_version = entry
                    .get("version")
                    .and_then(Yaml::as_u64)
                    .map(|v| v as u8)
                    .unwrap_or(0);
                let version = crate::proto::snell::parse_server_version(raw_version)
                    .map_err(|e| Error::config(format!("listener {tag:?}: {e}")))?;
                ServerProtocol::Snell {
                    psk: yaml_str(entry, "psk").unwrap_or_default(),
                    version,
                    obfs_mode: yaml_str(entry, "obfs-mode").unwrap_or_default(),
                    obfs_host: yaml_str(entry, "obfs-host").unwrap_or_default(),
                    shadow_tls: None,
                    res_tls: None,
                    jls: None,
                }
            }
            "anytls" => ServerProtocol::AnyTls {
                password: yaml_str(entry, "password").unwrap_or_default(),
                users: parse_user_list(entry, "users"),
                tls,
            },
            other => {
                return Err(Error::config(format!(
                    "listener {tag:?}: type {other:?} is not supported as a server yet \
                     (supported: shadowsocks, trojan, vmess, vless, hysteria2, tuic, restls, tlsmirror, jls, snell, anytls)"
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
        // Not the in-process simple-obfs: an external SIP003 child
        // (parse_sip003_plugin owns those) — no in-process obfs here.
        return Ok(None);
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

/// mihomo `plugin`/`plugin-opts` → an external SIP003 child process
/// (any plugin name other than the in-process `obfs`): obfs-local /
/// simple-obfs, v2ray-plugin, or a raw program with a `k=v;k2=v2`
/// options string per the SIP003 spec.
fn parse_sip003_plugin(
    entry: &BTreeMap<String, Yaml>,
    name: &str,
) -> Result<Option<crate::proto::sip003::Sip003Plugin>> {
    let Some(plugin) = yaml_str(entry, "plugin") else {
        return Ok(None);
    };
    match plugin.as_str() {
        "" | "obfs" => Ok(None), // in-process simple-obfs
        "obfs-local" | "simple-obfs" => {
            let mode = plugin_opt(entry, "mode").unwrap_or_else(|| "http".into());
            let host = plugin_opt(entry, "host");
            crate::proto::sip003::Sip003Plugin::obfs(&mode, host.as_deref())
                .map(Some)
                .map_err(|e| Error::config(format!("proxy {name:?}: {e}")))
        }
        "v2ray-plugin" => {
            let get = |k: &str| plugin_opt(entry, k);
            let opts = crate::proto::sip003::V2rayPluginOpts {
                mode: get("mode"),
                tls: plugin_bool(entry, "tls"),
                host: get("host"),
                path: get("path"),
                loglevel: get("loglevel"),
                mux: !plugin_bool_str(entry, "mux", "false"),
            };
            crate::proto::sip003::Sip003Plugin::v2ray("v2ray-plugin", &opts)
                .map(Some)
                .map_err(|e| Error::config(format!("proxy {name:?}: {e}")))
        }
        program => {
            let opts = entry
                .get("plugin-opts")
                .and_then(Yaml::as_mapping)
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, v)| {
                            let k = k.as_str()?;
                            let v = match v {
                                Yaml::String(s) => s.clone(),
                                Yaml::Bool(b) => b.to_string(),
                                Yaml::Number(n) => n.to_string(),
                                _ => return None,
                            };
                            Some(format!("{k}={v}"))
                        })
                        .collect::<Vec<_>>()
                        .join(";")
                })
                .unwrap_or_default();
            crate::proto::sip003::Sip003Plugin::raw(program, &opts)
                .map(Some)
                .map_err(|e| Error::config(format!("proxy {name:?}: {e}")))
        }
    }
}

fn plugin_opt(entry: &BTreeMap<String, Yaml>, key: &str) -> Option<String> {
    entry
        .get("plugin-opts")
        .and_then(Yaml::as_mapping)
        .and_then(|m| m.get(Yaml::String(key.into())))
        .and_then(|v| match v {
            Yaml::String(s) => Some(s.clone()),
            Yaml::Number(n) => Some(n.to_string()),
            _ => None,
        })
}

fn plugin_bool(entry: &BTreeMap<String, Yaml>, key: &str) -> bool {
    entry
        .get("plugin-opts")
        .and_then(Yaml::as_mapping)
        .and_then(|m| m.get(Yaml::String(key.into())))
        .and_then(Yaml::as_bool)
        .unwrap_or(false)
}

fn plugin_bool_str(entry: &BTreeMap<String, Yaml>, key: &str, default: &str) -> bool {
    entry
        .get("plugin-opts")
        .and_then(Yaml::as_mapping)
        .and_then(|m| m.get(Yaml::String(key.into())))
        .and_then(|v| match v {
            Yaml::Bool(b) => Some(*b),
            Yaml::String(s) => Some(s == "true"),
            _ => None,
        })
        .unwrap_or(default == "true")
}

/// mihomo listener `users:` — either a list of {username, password}
/// maps or a name→password map (both accepted like upstream's
/// structure.RawUsers variants).
fn parse_user_list(entry: &BTreeMap<String, Yaml>, key: &str) -> Vec<(String, String)> {
    let mut out = Vec::new();
    match entry.get(key) {
        Some(Yaml::Sequence(list)) => {
            for u in list {
                if let Yaml::Mapping(m) = u {
                    let user = m
                        .get(Yaml::String("username".into()))
                        .or_else(|| m.get(Yaml::String("user".into())))
                        .and_then(Yaml::as_str)
                        .unwrap_or("");
                    let password = m
                        .get(Yaml::String("password".into()))
                        .and_then(Yaml::as_str)
                        .unwrap_or("");
                    if !user.is_empty() {
                        out.push((user.to_string(), password.to_string()));
                    }
                }
            }
        }
        Some(Yaml::Mapping(m)) => {
            for (k, v) in m {
                if let (Yaml::String(user), Yaml::String(pw)) = (k, v) {
                    out.push((user.clone(), pw.clone()));
                }
            }
        }
        _ => {}
    }
    out
}

/// Scalar yaml helpers for the wave-7 outbound options.
fn yaml_bool(entry: &BTreeMap<String, Yaml>, key: &str) -> bool {
    entry.get(key).and_then(Yaml::as_bool).unwrap_or(false)
}

fn yaml_u64(entry: &BTreeMap<String, Yaml>, key: &str) -> u64 {
    entry
        .get(key)
        .and_then(|v| match v {
            Yaml::Number(n) => n.as_u64(),
            Yaml::String(s) => s.parse().ok(),
            _ => None,
        })
        .unwrap_or(0)
}

fn yaml_i64(entry: &BTreeMap<String, Yaml>, key: &str) -> Option<i64> {
    entry.get(key).and_then(|v| match v {
        Yaml::Number(n) => n.as_i64(),
        Yaml::String(s) => s.parse().ok(),
        _ => None,
    })
}

fn yaml_str_list(entry: &BTreeMap<String, Yaml>, key: &str) -> Vec<String> {
    entry
        .get(key)
        .and_then(Yaml::as_sequence)
        .map(|list| {
            list.iter()
                .filter_map(|v| v.as_str().map(str::to_string))
                .collect()
        })
        .unwrap_or_default()
}

/// `jls-opts: {username, password}` (mihomo JLSOptions → jls.NewConfig:
/// both fields required when the block is present). JLS replaces the TLS
/// handshake and rides raw TCP — layered transports are rejected here.
fn parse_jls_opts(
    entry: &BTreeMap<String, Yaml>,
    name: &str,
    transport: &TransportKind,
) -> Result<Option<crate::proto::jls::JlsUser>> {
    let Some(Yaml::Mapping(opts)) = entry.get("jls-opts") else {
        return Ok(None);
    };
    if !matches!(transport, TransportKind::Tcp) {
        return Err(Error::config(format!(
            "proxy {name:?}: jls-opts rides raw TCP and cannot combine with a layered \
             transport (see transport/jls)"
        )));
    }
    let username = opts
        .get(Yaml::String("username".into()))
        .and_then(Yaml::as_str)
        .unwrap_or("");
    let password = opts
        .get(Yaml::String("password".into()))
        .and_then(Yaml::as_str)
        .unwrap_or("");
    crate::proto::jls::parse(username, password)
        .map_err(|e| Error::config(format!("proxy {name:?}: jls-opts: {e}")))
}

/// `ech-opts: {enable, config, query-server-name}` (mihomo ECHOptions).
/// Parsed 1:1; when enabled it substitutes the TLS dial with the engine's
/// own ECH-capable TLS 1.3 stack — so, like jls-opts, it rides raw TCP
/// and cannot combine with a layered transport.
fn parse_ech_opts(
    entry: &BTreeMap<String, Yaml>,
    name: &str,
    transport: &TransportKind,
) -> Option<crate::proto::ech::EchOptions> {
    let Yaml::Mapping(opts) = entry.get("ech-opts")? else {
        return None;
    };
    let enable = opts
        .get(Yaml::String("enable".into()))
        .and_then(Yaml::as_bool)
        .unwrap_or(false);
    if enable && !matches!(transport, TransportKind::Tcp) {
        // Surface at connect instead: the value is still parsed 1:1, but
        // this misconfiguration is caught the moment it happens.
        tracing::debug!(target: "engine",
            "proxy {name:?}: ech-opts.enable with a layered transport will fail at \
             connect (ECH owns the TLS dial over raw TCP)");
    }
    let get = |k: &str| {
        opts.get(Yaml::String(k.into()))
            .and_then(Yaml::as_str)
            .unwrap_or("")
            .to_string()
    };
    Some(crate::proto::ech::EchOptions {
        enable,
        config: get("config"),
        query_server_name: get("query-server-name"),
    })
}

/// `tlsmirror-opts` on vmess (mihomo TLSMirrorOptions → tlsmirror.Config;
/// absent or without `primary-key` means disabled). The carrier TLS knobs
/// come from the proxy-level tls/sni fields.
fn parse_tlsmirror_opts(
    entry: &BTreeMap<String, Yaml>,
    name: &str,
    tls: &TlsSettings,
    transport: &TransportKind,
) -> Result<Option<crate::proto::tlsmirror::TlsMirrorOut>> {
    let Some(Yaml::Mapping(opts)) = entry.get("tlsmirror-opts") else {
        return Ok(None);
    };
    if !matches!(transport, TransportKind::Tcp) {
        return Err(Error::config(format!(
            "proxy {name:?}: tlsmirror-opts rides raw TCP and cannot combine with a \
             layered transport"
        )));
    }
    let primary_key = opts
        .get(Yaml::String("primary-key".into()))
        .and_then(Yaml::as_str)
        .unwrap_or("");
    if primary_key.is_empty() {
        return Ok(None);
    }
    let server_name = tls
        .server_name
        .clone()
        .or_else(|| yaml_str(entry, "server"))
        .unwrap_or_default();
    let mut out = crate::proto::tlsmirror::TlsMirrorOut::new(primary_key, &server_name);
    out.skip_cert_verify = tls.skip_cert_verify;
    // The sub-structs (defer write time, padding, enrolment, generator
    // steps) are validated by the proto module on use; carry the raw
    // fields across.
    if let Some(Yaml::Mapping(sub)) = opts.get(Yaml::String(
        "defer-instance-derived-write-time".into(),
    )) {
        out.defer_instance_derived_write = crate::proto::tlsmirror::TimeSpec {
            base_nanoseconds: sub
                .get(Yaml::String("base-nanoseconds".into()))
                .and_then(Yaml::as_u64)
                .unwrap_or(0),
            uniform_random_multiplier_nanoseconds: sub
                .get(Yaml::String("uniform-random-multiplier-nanoseconds".into()))
                .and_then(Yaml::as_u64)
                .unwrap_or(0),
        };
    }
    if let Some(Yaml::Mapping(sub)) =
        opts.get(Yaml::String("transport-layer-padding".into()))
    {
        out.transport_layer_padding = sub
            .get(Yaml::String("enabled".into()))
            .and_then(Yaml::as_bool)
            .unwrap_or(false);
    }
    out.sequence_watermarking_enabled = opts
        .get(Yaml::String("sequence-watermarking-enabled".into()))
        .and_then(Yaml::as_bool)
        .unwrap_or(false);
    let _ = name;
    Ok(Some(out))
}

fn parse_proxy(
    entry: &BTreeMap<String, Yaml>,
    index: usize,
    all: &[BTreeMap<String, Yaml>],
) -> Result<OutboundConfig> {
    let name = yaml_str(entry, "name")
        .unwrap_or_else(|| format!("proxy-{index}"));
    let ptype = yaml_str(entry, "type").unwrap_or_default();
    // Wireguard carries server/port on peers[0], not the entry itself;
    // tailscale dials itself through the tsnet stack (no server field
    // upstream either).
    let is_wireguard = ptype == "wireguard"
        || ptype == "tailscale"
        || ptype == "zerotier"
        || ptype == "easytier";
    let server = if is_wireguard {
        String::new()
    } else {
        yaml_str(entry, "server").ok_or_else(|| {
            Error::config(format!("proxy {name:?} missing server"))
        })?
    };
    let port: u16 = if is_wireguard {
        0
    } else if ptype == "mieru" && entry.get("port-range").is_some() {
        // mieru: `port-range` substitutes for `port` (adapter/outbound/
        // mieru.go:152-156); the range must carry a parseable begin.
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
    // Overlay outbounds (zerotier) use `network:` for the network id —
    // their type branches read it themselves; no layered transport.
    let transport = if ptype == "zerotier" {
        TransportKind::Tcp
    } else {
        parse_transport(entry)?
    };

    let kind = match ptype.as_str() {
        "ss" => {
            // `plugin: obfs` stays the in-process simple-obfs (mihomo's
            // mapping); any other plugin name is an external SIP003
            // child process (obfs-local, v2ray-plugin, ...).
            let plugin = parse_sip003_plugin(entry, &name)?;
            OutboundKind::Shadowsocks {
                method: SsMethod::parse(&yaml_str(entry, "cipher").unwrap_or_default())?,
                password: yaml_str(entry, "password").unwrap_or_default(),
                obfs: parse_obfs(entry)?,
                plugin,
                server,
                port,
            }
        }
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
            let jls = parse_jls_opts(entry, &name, &transport)?;
            let tlsmirror = parse_tlsmirror_opts(entry, &name, &tls, &transport)?;
            let ech = parse_ech_opts(entry, &name, &transport);
            if jls.is_some() && ech.as_ref().is_some_and(|o| o.enable) {
                return Err(Error::config(format!(
                    "proxy {name:?}: jls-opts and ech-opts both replace the TLS                      handshake and cannot combine"
                )));
            }
            OutboundKind::Vmess {
                security: VmessSecurity::parse(&yaml_str(entry, "cipher").unwrap_or_default())?,
                uuid,
                server,
                port,
                transport,
                tls,
                jls,
                tlsmirror,
                ech,
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
                    "proxy {name:?}: xtls-rprx-vision (full splice on reality outers; \
                     framing mode on opaque TLS outers)");
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
            let jls = parse_jls_opts(entry, &name, &transport)?;
            let ech = parse_ech_opts(entry, &name, &transport);
            if ech.as_ref().is_some_and(|o| o.enable) {
                if reality.is_some() || fingerprint.is_some() {
                    return Err(Error::config(format!(
                        "proxy {name:?}: ech-opts.enable cannot combine with reality-opts \
                         or client-fingerprint (ECH owns the ClientHello)"
                    )));
                }
                if jls.is_some() {
                    return Err(Error::config(format!(
                        "proxy {name:?}: jls-opts and ech-opts both replace the TLS                          handshake and cannot combine"
                    )));
                }
            }
            OutboundKind::Vless {
                uuid,
                server,
                port,
                transport,
                tls,
                reality,
                fingerprint,
                vision,
                jls,
                ech,
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
            let jls = parse_jls_opts(entry, &name, &transport)?;
            let ech = parse_ech_opts(entry, &name, &transport);
            if jls.is_some() && ech.as_ref().is_some_and(|o| o.enable) {
                return Err(Error::config(format!(
                    "proxy {name:?}: jls-opts and ech-opts both replace the TLS                      handshake and cannot combine"
                )));
            }
            OutboundKind::Trojan {
                password: yaml_str(entry, "password").unwrap_or_default(),
                server,
                port,
                transport,
                tls,
                jls,
                ech,
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
            ech: parse_ech_opts(entry, &name, &TransportKind::Tcp),
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
            ech: parse_ech_opts(entry, &name, &TransportKind::Tcp),
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
        "snell" => {
            let raw_version = entry
                .get("version")
                .and_then(Yaml::as_u64)
                .map(|v| v as u8)
                .unwrap_or(0);
            // parse_version applies mihomo's DEFAULT_SNELL_VERSION (1) and
            // the v5→v4 mapping; validate_udp gates UDP to v3+.
            let version = crate::proto::snell::parse_version(raw_version)
                .map_err(|e| Error::config(format!("proxy {name:?}: {e}")))?;
            crate::proto::snell::validate_udp(version, udp)
                .map_err(|e| Error::config(format!("proxy {name:?}: {e}")))?;
            OutboundKind::Snell(crate::proto::snell::SnellOut {
                psk: yaml_str(entry, "psk").unwrap_or_default(),
                version,
                udp,
                server,
                port,
            })
        }
        "anytls" => OutboundKind::AnyTls(crate::proto::anytls::AnyTlsOut {
            password: yaml_str(entry, "password").unwrap_or_default(),
            sni: yaml_str(entry, "sni").unwrap_or_default(),
            skip_verify: entry
                .get("skip-cert-verify")
                .and_then(Yaml::as_bool)
                .unwrap_or(false),
            udp,
            server,
            port,
            jls: parse_jls_opts(entry, &name, &TransportKind::Tcp)?,
            ech: parse_ech_opts(entry, &name, &TransportKind::Tcp),
        }),
        "mieru" => {
            let transport = crate::proto::mieru::MieruTransport::parse(
                &yaml_str(entry, "transport").unwrap_or_else(|| "TCP".into()),
            )?;
            let port_range = match yaml_str(entry, "port-range") {
                Some(spec) => Some(crate::proto::mieru::parse_port_range(&spec)?),
                None => None,
            };
            crate::proto::mieru::validate_ports(port, port_range)?;
            // `multiplexing` (mihomo MieruOption): low is mieru's default;
            // carried on the outbound for the pool dial (see outbound.rs).
            let multiplexing = yaml_str(entry, "multiplexing")
                .map(|s| crate::proto::mieru::Multiplexing::parse(&s))
                .transpose()?
                .unwrap_or_default();
            OutboundKind::Mieru(crate::proto::mieru::MieruOut {
                username: yaml_str(entry, "username").unwrap_or_default(),
                password: yaml_str(entry, "password").unwrap_or_default(),
                transport,
                server,
                port,
                port_range,
                multiplexing,
            })
        }
        "restls" => OutboundKind::Restls {
            cfg: crate::proto::restls::RestlsOut {
                password: yaml_str(entry, "password").unwrap_or_default(),
                sni: yaml_str(entry, "sni").unwrap_or_default(),
                version: {
                    let v = yaml_str(entry, "version-hint")
                        .or_else(|| yaml_str(entry, "version"))
                        .unwrap_or_else(|| "tls13".into());
                    if v.eq_ignore_ascii_case("tls12") {
                        return Err(Error::config(format!(
                            "proxy {name:?}: restls version-hint tls12 is not \
                             implementable over rustls yet"
                        )));
                    }
                    v
                },
                restls_script: yaml_str(entry, "restls-script").filter(|s| !s.is_empty()),
                skip_cert_verify: entry
                    .get("skip-cert-verify")
                    .and_then(Yaml::as_bool)
                    .unwrap_or(false),
                udp,
            },
            server,
            port,
        },
        "shadowquic" => {
            let mut opt = crate::proto::shadowquic::ShadowQuicOption::new(
                server.clone(),
                port,
            );
            opt.name = name.clone();
            opt.username = yaml_str(entry, "username").unwrap_or_default();
            opt.password = yaml_str(entry, "password").unwrap_or_default();
            opt.sni = yaml_str(entry, "sni").unwrap_or_default();
            opt.alpn = yaml_str_list(entry, "alpn");
            opt.quic_versions = yaml_str_list(entry, "quic-versions");
            opt.udp_over_stream = yaml_bool(entry, "udp-over-stream");
            opt.zero_rtt = yaml_bool(entry, "zero-rtt");
            opt.keep_alive_interval = yaml_u64(entry, "keep-alive-interval");
            opt.congestion_controller =
                yaml_str(entry, "congestion-controller").unwrap_or_default();
            opt.up = yaml_str(entry, "up").unwrap_or_default();
            opt.down = yaml_str(entry, "down").unwrap_or_default();
            opt.cwnd = yaml_u64(entry, "cwnd") as u32;
            opt.bbr_profile = yaml_str(entry, "bbr-profile").unwrap_or_default();
            opt.recv_window_conn = yaml_u64(entry, "recv-window-conn") as u32;
            opt.recv_window = yaml_u64(entry, "recv-window") as u32;
            opt.disable_mtu_discovery = yaml_bool(entry, "disable-mtu-discovery");
            opt.max_datagram_frame_size = yaml_u64(entry, "max-datagram-frame-size") as u32;
            opt.max_open_streams = yaml_u64(entry, "max-open-streams") as u32;
            opt.skip_cert_verify = yaml_bool(entry, "skip-cert-verify");
            // JLS-in-QUIC-TLS cannot ride quinn/rustls — surface the
            // module's precise error at parse time when credentials are
            // set (upstream always enables JLS; the empty-credential
            // framing-only mode is this port's documented delta).
            crate::proto::shadowquic::parse_quic_versions(&opt.quic_versions).map_err(
                |e| Error::config(format!("proxy {name:?}: shadowquic: {e}")),
            )?;
            OutboundKind::ShadowQuic(opt)
        }
        "sudoku" => {
            let key = yaml_str(entry, "key").unwrap_or_default();
            let mut cfg = crate::proto::sudoku::SudokuOut::new(&server, port, &key);
            cfg.aead_method = yaml_str(entry, "aead-method");
            cfg.padding_min = yaml_i64(entry, "padding-min");
            cfg.padding_max = yaml_i64(entry, "padding-max");
            cfg.table_type = yaml_str(entry, "table-type").unwrap_or_default();
            cfg.enable_pure_downlink = entry.get("enable-pure-downlink").and_then(Yaml::as_bool);
            cfg.http_mask = entry.get("http-mask").and_then(Yaml::as_bool);
            cfg.http_mask_mode =
                yaml_str(entry, "http-mask-mode").unwrap_or_default();
            cfg.http_mask_tls = yaml_bool(entry, "http-mask-tls");
            cfg.http_mask_host = yaml_str(entry, "http-mask-host").unwrap_or_default();
            cfg.path_root = yaml_str(entry, "path-root").unwrap_or_default();
            cfg.multiplex = yaml_str(entry, "multiplex")
                .or_else(|| yaml_str(entry, "http-mask-multiplex"))
                .unwrap_or_default();
            cfg.custom_table = yaml_str(entry, "custom-table").unwrap_or_default();
            cfg.custom_tables = yaml_str_list(entry, "custom-tables");
            // The `httpmask:{...}` nested block mirrors the flat fields.
            if let Some(Yaml::Mapping(sub)) = entry.get("httpmask") {
                let sub_get = |k: &str| {
                    sub.get(Yaml::String(k.into()))
                        .and_then(Yaml::as_str)
                        .map(str::to_string)
                };
                if let Some(v) = sub_get("mode") {
                    cfg.http_mask_mode = v;
                }
                if let Some(v) = sub_get("host") {
                    cfg.http_mask_host = v;
                }
                if let Some(v) = sub_get("path-root") {
                    cfg.path_root = v;
                }
                if let Some(v) = sub_get("multiplex") {
                    cfg.multiplex = v;
                }
                if let Some(Yaml::Bool(b)) = sub.get(Yaml::String("disable".into())) {
                    cfg.http_mask = Some(!*b);
                }
                if let Some(Yaml::Bool(b)) = sub.get(Yaml::String("tls".into())) {
                    cfg.http_mask_tls = *b;
                }
            }
            OutboundKind::Sudoku(cfg)
        }
        "gost-relay" => {
            let mut cfg = crate::proto::gost_relay::GostRelayOut::new(&server, port);
            cfg.forward = yaml_bool(entry, "forward");
            cfg.udp = udp;
            cfg.tls = yaml_bool(entry, "tls");
            cfg.mux = yaml_bool(entry, "mux");
            cfg.sni = yaml_str(entry, "sni").unwrap_or_default();
            cfg.username = yaml_str(entry, "username").unwrap_or_default();
            cfg.password = yaml_str(entry, "password").unwrap_or_default();
            cfg.skip_cert_verify = yaml_bool(entry, "skip-cert-verify");
            cfg.name_cert_verify =
                yaml_str(entry, "name-cert-verify").unwrap_or_default();
            cfg.fingerprint = yaml_str(entry, "fingerprint").unwrap_or_default();
            cfg.certificate = yaml_str(entry, "certificate").unwrap_or_default();
            cfg.private_key = yaml_str(entry, "private-key").unwrap_or_default();
            cfg.client_fingerprint =
                yaml_str(entry, "client-fingerprint").unwrap_or_default();
            OutboundKind::GostRelay(cfg)
        }
        "trusttunnel" => {
            let mut cfg = crate::proto::trusttunnel::TrustTunnelOut::new(&server, port);
            cfg.username = yaml_str(entry, "username").unwrap_or_default();
            cfg.password = yaml_str(entry, "password").unwrap_or_default();
            cfg.alpn = yaml_str_list(entry, "alpn");
            cfg.sni = yaml_str(entry, "sni").unwrap_or_default();
            cfg.skip_cert_verify = yaml_bool(entry, "skip-cert-verify");
            cfg.name_cert_verify =
                yaml_str(entry, "name-cert-verify").unwrap_or_default();
            cfg.fingerprint = yaml_str(entry, "fingerprint").unwrap_or_default();
            cfg.certificate = yaml_str(entry, "certificate").unwrap_or_default();
            cfg.private_key = yaml_str(entry, "private-key").unwrap_or_default();
            cfg.client_fingerprint =
                yaml_str(entry, "client-fingerprint").unwrap_or_default();
            cfg.udp = udp;
            cfg.health_check = yaml_bool(entry, "health-check");
            cfg.quic = yaml_bool(entry, "quic");
            cfg.congestion_controller =
                yaml_str(entry, "congestion-controller").unwrap_or_default();
            cfg.cwnd = yaml_i64(entry, "cwnd").unwrap_or(0);
            cfg.bbr_profile = yaml_str(entry, "bbr-profile").unwrap_or_default();
            cfg.max_connections = yaml_i64(entry, "max-connections").unwrap_or(0);
            cfg.min_streams = yaml_i64(entry, "min-streams").unwrap_or(0);
            cfg.max_streams = yaml_i64(entry, "max-streams").unwrap_or(0);
            cfg.ech = parse_ech_opts(entry, &name, &TransportKind::Tcp);
            OutboundKind::TrustTunnel(cfg)
        }
        "masque" => {
            let cfg = crate::proto::masque::MasqueOption {
                server: server.clone(),
                port,
                private_key: yaml_str(entry, "private-key").unwrap_or_default(),
                public_key: yaml_str(entry, "public-key").unwrap_or_default(),
                ip: yaml_str(entry, "ip").unwrap_or_default(),
                ipv6: yaml_str(entry, "ipv6").unwrap_or_default(),
                uri: yaml_str(entry, "uri").unwrap_or_default(),
                sni: yaml_str(entry, "sni").unwrap_or_default(),
                mtu: yaml_u64(entry, "mtu") as u32,
                udp,
                handshake_timeout: yaml_u64(entry, "handshake-timeout"),
                skip_cert_verify: yaml_bool(entry, "skip-cert-verify"),
                name_cert_verify: yaml_str(entry, "name-cert-verify").unwrap_or_default(),
                network: yaml_str(entry, "network").unwrap_or_default(),
                congestion_controller: yaml_str(entry, "congestion-controller")
                    .unwrap_or_default(),
                cwnd: yaml_i64(entry, "cwnd").unwrap_or(0),
                bbr_profile: yaml_str(entry, "bbr-profile").unwrap_or_default(),
                remote_dns_resolve: yaml_bool(entry, "remote-dns-resolve"),
                dns: yaml_str_list(entry, "dns"),
                ip_stack: {
                    let mut ip_stack = crate::proto::masque::IpStackOption::default();
                    if let Some(Yaml::Mapping(sub)) = entry.get("ip-stack") {
                        ip_stack.mode = sub
                            .get(Yaml::String("mode".into()))
                            .and_then(Yaml::as_str)
                            .unwrap_or_default()
                            .to_string();
                    }
                    ip_stack
                },
            };
            // The module's own validate (TUN mode, negative timeout, ...)
            // runs on connect; parse-time validation mirrors masque.go.
            if let Some(ht) = yaml_i64(entry, "handshake-timeout") {
                if ht < 0 {
                    return Err(Error::config(format!(
                        "proxy {name:?}: masque handshake timeout must be non-negative"
                    )));
                }
            }
            OutboundKind::Masque(cfg)
        }
        "openvpn" => {
            let ca = yaml_str(entry, "ca").unwrap_or_default();
            if ca.is_empty() {
                return Err(Error::config(format!(
                    "proxy {name:?}: openvpn requires ca (inline <ca> PEM)"
                )));
            }
            let peer_info = entry
                .get("peer-info")
                .and_then(Yaml::as_mapping)
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, v)| {
                            Some((
                                k.as_str().map(str::to_string)?,
                                v.as_str().map(str::to_string)?,
                            ))
                        })
                        .collect()
                })
                .unwrap_or_default();
            let mut ip_stack = crate::proto::openvpn::IpStackOption::default();
            if let Some(Yaml::Mapping(sub)) = entry.get("ip-stack") {
                ip_stack.mode = sub
                    .get(Yaml::String("mode".into()))
                    .and_then(Yaml::as_str)
                    .unwrap_or_default()
                    .to_string();
            }
            OutboundKind::OpenVpn(crate::proto::openvpn::OpenVpnOut {
                name: name.clone(),
                server,
                port,
                proto: yaml_str(entry, "proto"),
                dev: yaml_str(entry, "dev").unwrap_or_default(),
                cipher: yaml_str(entry, "cipher").unwrap_or_default(),
                data_ciphers: yaml_str_list(entry, "data-ciphers"),
                data_cipher_fallback: yaml_str(entry, "data-ciphers-fallback")
                    .unwrap_or_default(),
                auth: yaml_str(entry, "auth").unwrap_or_default(),
                comp_lzo: yaml_str(entry, "comp-lzo").unwrap_or_default(),
                ca,
                cert: yaml_str(entry, "cert"),
                key: yaml_str(entry, "key"),
                tls_auth: yaml_str(entry, "tls-auth"),
                key_direction: yaml_str(entry, "key-direction"),
                tls_crypt: yaml_str(entry, "tls-crypt"),
                tls_crypt_v2: yaml_str(entry, "tls-crypt-v2"),
                username: yaml_str(entry, "username"),
                password: yaml_str(entry, "password"),
                peer_info,
                ping: yaml_u64(entry, "ping"),
                ping_restart: yaml_u64(entry, "ping-restart"),
                tran_window: yaml_i64(entry, "tran-window"),
                handshake_timeout: yaml_i64(entry, "handshake-timeout").unwrap_or(0),
                mtu: yaml_u64(entry, "mtu") as u32,
                ip_stack,
                remote_dns_resolve: yaml_bool(entry, "remote-dns-resolve"),
                dns: yaml_str_list(entry, "dns"),
            })
        }
        "tailscale" => {
            OutboundKind::Tailscale(crate::proto::tailscale::TailscaleConfig {
                name: name.clone(),
                hostname: yaml_str(entry, "hostname"),
                auth_key: yaml_str(entry, "auth-key"),
                control_url: yaml_str(entry, "control-url"),
                state_dir: yaml_str(entry, "state-dir"),
                ephemeral: yaml_bool(entry, "ephemeral"),
                udp: yaml_bool(entry, "udp"),
                accept_routes: entry.get("accept-routes").and_then(Yaml::as_bool),
                exit_node: yaml_str(entry, "exit-node"),
                exit_node_allow_lan_access: entry
                    .get("exit-node-allow-lan-access")
                    .and_then(Yaml::as_bool),
            })
        }
        "zerotier" => {
            let ip_stack = match yaml_str(entry, "ip-stack") {
                Some(s) => crate::proto::zerotier::IpStack::parse(&s)
                    .map_err(|e| Error::config(format!("proxy {name:?}: {e}")))?,
                None => Default::default(),
            };
            let mut cfg = crate::proto::zerotier::ZeroTierConfig {
                name: name.clone(),
                network: yaml_str(entry, "network").unwrap_or_default(),
                state_dir: yaml_str(entry, "state-dir"),
                identity_secret: yaml_str(entry, "identity-secret"),
                planet: yaml_str(entry, "planet"),
                mtu: yaml_i64(entry, "mtu").unwrap_or(0),
                ip_stack,
                physical_mtu: yaml_i64(entry, "physical-mtu").unwrap_or(0),
                udp: yaml_bool(entry, "udp"),
                remote_dns_resolve: yaml_bool(entry, "remote-dns-resolve"),
                dns: yaml_str_list(entry, "dns"),
                low_bandwidth: yaml_bool(entry, "low-bandwidth"),
                encrypted_hello: yaml_bool(entry, "encrypted-hello"),
                primary_port: yaml_i64(entry, "primary-port").unwrap_or(0),
                secondary_port: yaml_i64(entry, "secondary-port").unwrap_or(0),
                tcp_fallback_mode: yaml_str(entry, "tcp-fallback-mode"),
                tcp_fallback_relay: yaml_str(entry, "tcp-fallback-relay"),
                ..Default::default()
            };
            if let Some(Yaml::Sequence(list)) = entry.get("orbit") {
                for o in list.iter().filter_map(Yaml::as_mapping) {
                    let world = o
                        .get(Yaml::String("world".into()))
                        .and_then(Yaml::as_u64)
                        .unwrap_or(0);
                    let seed = o
                        .get(Yaml::String("seed".into()))
                        .and_then(Yaml::as_str)
                        .unwrap_or("");
                    cfg.orbit.push(crate::proto::zerotier::ZeroTierOrbit {
                        world,
                        seed: seed.to_string(),
                    });
                }
            }
            crate::proto::zerotier::parse_network_id(&cfg.network)
                .map_err(|e| Error::config(format!("proxy {name:?}: {e}")))?;
            OutboundKind::ZeroTier(cfg)
        }
        "easytier" => {
            let cfg = crate::proto::easytier::EasyTierConfig {
                name: name.clone(),
                network_name: yaml_str(entry, "network-name").unwrap_or_default(),
                network_secret: yaml_str(entry, "network-secret").unwrap_or_default(),
                hostname: yaml_str(entry, "hostname"),
                ipv4: yaml_str(entry, "ipv4"),
                dhcp: yaml_bool(entry, "dhcp"),
                peers: yaml_str_list(entry, "peers"),
                listeners: yaml_str_list(entry, "listeners"),
                no_listener: entry.get("no-listener").and_then(Yaml::as_bool),
                mapped_listeners: yaml_str_list(entry, "mapped-listeners"),
                exit_nodes: yaml_str_list(entry, "exit-nodes"),
                proxy_networks: yaml_str_list(entry, "proxy-networks"),
                instance_name: yaml_str(entry, "instance-name"),
                state_dir: yaml_str(entry, "state-dir"),
                udp: yaml_bool(entry, "udp"),
                accept_dns: entry.get("accept-dns").and_then(Yaml::as_bool),
                enable_exit_node: entry.get("enable-exit-node").and_then(Yaml::as_bool),
                ..Default::default()
            };
            OutboundKind::EasyTier(cfg)
        }
        other => {
            let supported = "ss, vmess, vless, trojan, socks5, http, hysteria2, tuic, wireguard, snell, anytls, mieru, restls, shadowquic, sudoku, gost-relay, trusttunnel, masque, openvpn, tailscale, zerotier, easytier";
            return Err(Error::config(format!(
                "proxy {name:?}: type {other:?} is not supported by the Rust engine yet \
                 (supported: {supported})"
            )));
        }
    };
    // hy2/tuic are UDP-native and the wave-7 QUIC/UoT transports always
    // answer UDP: mihomo defaults their udp to true.
    let udp = match &kind {
        OutboundKind::Hysteria2 { .. }
        | OutboundKind::Tuic { .. }
        | OutboundKind::ShadowQuic(_)
        | OutboundKind::Sudoku(_)
        | OutboundKind::Masque(_) => {
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
    fn wave6_transports_parse() {
        let cfg = r#"
mixed-port: 7890
proxies:
  - {name: sn, type: snell, server: s.example, port: 443, psk: pk, version: 4}
  - {name: at, type: anytls, server: a.example, port: 443, password: pw, sni: a.example}
  - {name: mi, type: mieru, server: m.example, port: 8964, username: u, password: p, transport: TCP}
  - {name: rl, type: restls, server: r.example, port: 443, password: pw, sni: r.example,
     version-hint: tls13}
rules:
  - MATCH,sn
"#;
        let parsed = load(cfg).unwrap();
        let sn = parsed.outbounds.iter().find(|o| o.name == "sn").unwrap();
        assert!(matches!(&sn.kind, OutboundKind::Snell(c) if c.version == 4 && c.psk == "pk"));
        let at = parsed.outbounds.iter().find(|o| o.name == "at").unwrap();
        assert!(matches!(&at.kind, OutboundKind::AnyTls(c) if c.sni == "a.example"));
        let mi = parsed.outbounds.iter().find(|o| o.name == "mi").unwrap();
        assert!(matches!(&mi.kind, OutboundKind::Mieru(c) if c.username == "u"));
        let rl = parsed.outbounds.iter().find(|o| o.name == "rl").unwrap();
        assert!(matches!(
            &rl.kind,
            OutboundKind::Restls { cfg: c, .. } if c.version == "tls13"
        ));

        // Deferred surfaces fail loudly.
        let bad = |extra: &str| {
            let cfg = format!(
                "mixed-port: 7890\nproxies:\n  - name: b\n    type: {{t}}\n    server: x\n    port: 1\n{extra}\nrules:\n  - MATCH,b\n"
            );
            cfg
        };
        let _ = bad;
        let mieru_udp = r#"
mixed-port: 7890
proxies:
  - {name: b, type: mieru, server: x, port: 1, username: u, password: p, transport: UDP}
rules:
  - MATCH,b
"#;
        // Wave-8: the mieru UDP packet transport is implemented now —
        // the same config parses.
        let m = load(mieru_udp).unwrap();
        match &m.outbounds.iter().find(|o| o.name == "b").unwrap().kind {
            crate::outbound::OutboundKind::Mieru(c) => assert!(matches!(
                c.transport,
                crate::proto::mieru::MieruTransport::Udp
            )),
            other => panic!("wrong kind: {other:?}"),
        }
        let restls12 = r#"
mixed-port: 7890
proxies:
  - {name: b, type: restls, server: x, port: 1, password: p, version-hint: tls12}
rules:
  - MATCH,b
"#;
        let err = load(restls12).err().unwrap().to_string();
        assert!(err.contains("tls12"), "{err}");
    }

    /// Wave-7: the five new outbound types parse with their option
    /// fields, and the TLS options (jls-opts / ech-opts / tlsmirror-opts)
    /// land on their carrying outbounds.
    #[test]
    fn wave7_transports_parse_and_options() {
        // shadowquic — every tuning knob accepted.
        let sq = load(
            r#"
mixed-port: 7890
proxies:
  - name: sq
    type: shadowquic
    server: sq.example
    port: 443
    username: u1
    password: p1
    sni: s.example
    alpn: [h3]
    quic-versions: [v1]
    udp-over-stream: true
    keep-alive-interval: 2000
    congestion-controller: bbr
    up: "50 Mbps"
    down: "100 Mbps"
    cwnd: 32
    recv-window-conn: 65536
    recv-window: 262144
    disable-mtu-discovery: true
    max-open-streams: 64
rules:
  - MATCH,sq
"#,
        )
        .unwrap();
        let at = sq
            .outbounds
            .iter()
            .find(|o| o.name == "sq")
            .expect("shadowquic outbound");
        match &at.kind {
            crate::outbound::OutboundKind::ShadowQuic(opt) => {
                assert_eq!(opt.username, "u1");
                assert_eq!(opt.alpn, vec!["h3".to_string()]);
                assert!(opt.udp_over_stream);
                assert_eq!(opt.keep_alive_interval, 2000);
                assert!(opt.disable_mtu_discovery);
                assert_eq!(opt.max_open_streams, 64);
            }
            other => panic!("wrong kind: {other:?}"),
        }

        // sudoku / gost-relay / trusttunnel / masque parse with defaults.
        let probe = |ptype: &str| {
            let cfg = format!(
                "mixed-port: 7890\nproxies:\n  - {{name: w7, type: {ptype}, server: h.example, port: 443}}\nrules:\n  - MATCH,w7\n"
            );
            let parsed = load(&cfg).unwrap_or_else(|e| panic!("{ptype}: {e}"));
            parsed
                .outbounds
                .iter()
                .find(|o| o.name == "w7")
                .expect("outbound")
                .clone()
        };
        use crate::outbound::OutboundKind;
        assert!(matches!(probe("sudoku").kind, OutboundKind::Sudoku(_)));
        assert!(matches!(probe("gost-relay").kind, OutboundKind::GostRelay(_)));
        assert!(matches!(probe("trusttunnel").kind, OutboundKind::TrustTunnel(_)));
        assert!(matches!(probe("masque").kind, OutboundKind::Masque(_)));
        // Upstream: shadowquic/sudoku/masque are UDP-capable by default;
        // gost-relay/trusttunnel UDP is opt-in (`udp: true`).
        for ptype in ["sudoku", "masque"] {
            assert!(probe(ptype).udp, "{ptype} defaults to udp-capable");
        }
        for ptype in ["gost-relay", "trusttunnel"] {
            assert!(!probe(ptype).udp, "{ptype} udp is opt-in");
        }

        // jls-opts on trojan (vless/vmess/anytls share the helper).
        let jls = load(
            r#"
mixed-port: 7890
proxies:
  - {name: tj, type: trojan, server: t.example, port: 443, password: pw, jls-opts: {username: u, password: p}}
rules:
  - MATCH,tj
"#,
        )
        .unwrap();
        match &jls.outbounds.iter().find(|o| o.name == "tj").unwrap().kind {
            crate::outbound::OutboundKind::Trojan { jls, .. } => {
                assert!(jls.is_some(), "jls-opts parsed");
            }
            other => panic!("wrong kind: {other:?}"),
        }

        // jls-opts with a layered transport fails at parse.
        let bad = r#"
mixed-port: 7890
proxies:
  - {name: bj, type: trojan, server: t.example, port: 443, password: pw, network: ws, ws-opts: {path: /x}, jls-opts: {username: u, password: p}}
rules:
  - MATCH,bj
"#;
        let err = load(bad).err().unwrap().to_string();
        assert!(err.contains("jls-opts rides raw TCP"), "{err}");

        // ech-opts + tlsmirror-opts carry through.
        let opts = load(
            r#"
mixed-port: 7890
proxies:
  - {name: vm, type: vmess, server: v.example, port: 443, uuid: 66666666-6666-6666-6666-666666666666, cipher: auto, ech-opts: {enable: true, config: aGVsbG8=}, tlsmirror-opts: {primary-key: cHJpbWFyeS1rZXktdmFsdWUtMzItYnl0ZXMhIQ==}}
rules:
  - MATCH,vm
"#,
        )
        .unwrap();
        match &opts.outbounds.iter().find(|o| o.name == "vm").unwrap().kind {
            crate::outbound::OutboundKind::Vmess { ech, tlsmirror, .. } => {
                let ech = ech.as_ref().expect("ech-opts parsed");
                assert!(ech.enable);
                assert_eq!(ech.config, "aGVsbG8=");
                assert!(tlsmirror.is_some(), "tlsmirror-opts parsed");
            }
            other => panic!("wrong kind: {other:?}"),
        }
    }

    /// Wave-10: the jls/snell/anytls listeners parse, and the
    /// zerotier/easytier overlay outbounds carry their config surface.
    #[test]
    fn wave10_listeners_and_overlays_parse() {
        let cfg = load(
            r#"mixed-port: 7890
listeners:
  - name: jl
    type: jls
    listen: 127.0.0.1
    port: 18445
    sni: j.example
    dest: camo.example:443
    users:
      - {username: alice, password: pw1}
      - {username: bob, password: pw2}
    rate-limit: 1024
proxies:
  - {name: d, type: socks5, server: 127.0.0.1, port: 1080}
rules:
  - MATCH,d
"#,
        )
        .unwrap();
        let jl = cfg.proxy_servers.iter().find(|l| l.tag == "jl").unwrap();
        match &jl.protocol {
            crate::inbound::proxy_server::ServerProtocol::Jls { users, dest, .. } => {
                assert_eq!(users.len(), 2);
                assert_eq!(dest, "camo.example:443");
            }
            other => panic!("wrong protocol: {other:?}"),
        }

        let cfg = load(
            "mixed-port: 7890\nlisteners:\n  - {name: sn, type: snell, listen: 127.0.0.1, port: 18446, psk: k, version: 4}\nproxies:\n  - {name: d, type: socks5, server: 127.0.0.1, port: 1080}\nrules:\n  - MATCH,d\n",
        )
        .unwrap();
        let sn = cfg.proxy_servers.iter().find(|l| l.tag == "sn").unwrap();
        match &sn.protocol {
            crate::inbound::proxy_server::ServerProtocol::Snell { psk, version, .. } => {
                assert_eq!(psk, "k");
                assert_eq!(*version, 4);
            }
            other => panic!("wrong protocol: {other:?}"),
        }

        let cfg = load(
            "mixed-port: 7890\nlisteners:\n  - {name: at, type: anytls, listen: 127.0.0.1, port: 18447, password: pw, users: {alice: pw1, bob: pw2}}\nproxies:\n  - {name: d, type: socks5, server: 127.0.0.1, port: 1080}\nrules:\n  - MATCH,d\n",
        )
        .unwrap();
        let at = cfg.proxy_servers.iter().find(|l| l.tag == "at").unwrap();
        match &at.protocol {
            crate::inbound::proxy_server::ServerProtocol::AnyTls { users, .. } => {
                assert_eq!(users.len(), 2);
            }
            other => panic!("wrong protocol: {other:?}"),
        }

        let cfg = load(
            "mixed-port: 7890\nproxies:\n  - {name: zt, type: zerotier, network: a84ac5c10a1d86e9, udp: true}\nrules:\n  - MATCH,zt\n",
        )
        .unwrap();
        match &cfg.outbounds.iter().find(|o| o.name == "zt").unwrap().kind {
            crate::outbound::OutboundKind::ZeroTier(c) => {
                assert_eq!(c.network, "a84ac5c10a1d86e9");
            }
            other => panic!("wrong kind: {other:?}"),
        }
        let err = load(
            "mixed-port: 7890\nproxies:\n  - {name: bad, type: zerotier, network: nothex}\nrules:\n  - MATCH,bad\n",
        )
        .err()
        .unwrap()
        .to_string();
        assert!(err.contains("network"), "{err}");

        let cfg = load(
            "mixed-port: 7890\nproxies:\n  - {name: et, type: easytier, network-name: mesh, network-secret: s3cret, peers: [tcp://p.example:11010], hostname: node1}\nrules:\n  - MATCH,et\n",
        )
        .unwrap();
        match &cfg.outbounds.iter().find(|o| o.name == "et").unwrap().kind {
            crate::outbound::OutboundKind::EasyTier(c) => {
                assert_eq!(c.network_name, "mesh");
                assert_eq!(c.peers, vec!["tcp://p.example:11010".to_string()]);
            }
            other => panic!("wrong kind: {other:?}"),
        }
    }

    /// Wave-9: snell v1/v2 default + UDP gates, mieru port-range/
    /// multiplexing, the ss SIP003 plugin surface, and the tailscale
    /// outbound config.
    #[test]
    fn wave9_snell_mieru_plugin_tailscale_parse() {
        // snell: default version is 1 (mihomo DEFAULT_SNELL_VERSION);
        // v5 maps to the v4 wire; UDP below v3 is rejected.
        let s1 = load(
            "mixed-port: 7890\nproxies:\n  - {name: s, type: snell, server: x, port: 1, psk: k}\nrules:\n  - MATCH,s\n",
        )
        .unwrap();
        match &s1.outbounds.iter().find(|o| o.name == "s").unwrap().kind {
            crate::outbound::OutboundKind::Snell(c) => assert_eq!(c.version, 1),
            other => panic!("wrong kind: {other:?}"),
        }
        let s5 = load(
            "mixed-port: 7890\nproxies:\n  - {name: s, type: snell, server: x, port: 1, psk: k, version: 5}\nrules:\n  - MATCH,s\n",
        )
        .unwrap();
        match &s5.outbounds.iter().find(|o| o.name == "s").unwrap().kind {
            crate::outbound::OutboundKind::Snell(c) => assert_eq!(c.version, 4, "v5 rides v4"),
            other => panic!("wrong kind: {other:?}"),
        }
        let err = load(
            "mixed-port: 7890\nproxies:\n  - {name: s, type: snell, server: x, port: 1, psk: k, version: 2, udp: true}\nrules:\n  - MATCH,s\n",
        )
        .err()
        .unwrap()
        .to_string();
        assert!(err.contains("not support UDP"), "{err}");

        // mieru port-range + multiplexing.
        let m = load(
            "mixed-port: 7890\nproxies:\n  - {name: m, type: mieru, server: x, port-range: 20000-20010, username: u, password: p, multiplexing: MULTIPLEXING_HIGH}\nrules:\n  - MATCH,m\n",
        )
        .unwrap();
        match &m.outbounds.iter().find(|o| o.name == "m").unwrap().kind {
            crate::outbound::OutboundKind::Mieru(c) => {
                assert_eq!(c.port_range, Some((20000, 20010)));
                assert_eq!(c.port, 0);
                assert_eq!(c.multiplexing, crate::proto::mieru::Multiplexing::High);
            }
            other => panic!("wrong kind: {other:?}"),
        }

        // ss external plugin (SIP003): anything but in-process "obfs".
        let ss = load(
            r#"mixed-port: 7890
proxies:
  - name: p
    type: ss
    server: x
    port: 1
    cipher: aes-256-gcm
    password: pw
    plugin: v2ray-plugin
    plugin-opts:
      mode: websocket
      host: h.example
      path: /ws
      tls: true
rules:
  - MATCH,p
"#,
        )
        .unwrap();
        match &ss.outbounds.iter().find(|o| o.name == "p").unwrap().kind {
            crate::outbound::OutboundKind::Shadowsocks { plugin, .. } => {
                let plugin = plugin.as_ref().expect("sip003 plugin parsed");
                assert_eq!(plugin.program(), "v2ray-plugin");
            }
            other => panic!("wrong kind: {other:?}"),
        }

        // tailscale config surface.
        let ts = load(
            r#"mixed-port: 7890
proxies:
  - name: t
    type: tailscale
    hostname: node1
    control-url: https://ctrl.example
    state-dir: /tmp/ts
    ephemeral: true
    accept-routes: true
    exit-node: "auto:"
rules:
  - MATCH,t
"#,
        )
        .unwrap();
        match &ts.outbounds.iter().find(|o| o.name == "t").unwrap().kind {
            crate::outbound::OutboundKind::Tailscale(c) => {
                assert_eq!(c.hostname.as_deref(), Some("node1"));
                assert!(c.ephemeral);
                assert_eq!(c.accept_routes, Some(true));
                assert_eq!(c.exit_node.as_deref(), Some("auto:"));
            }
            other => panic!("wrong kind: {other:?}"),
        }
    }

    /// Wave-8: openvpn parses with its option surface; the restls and
    /// tlsmirror listeners parse into ServerProtocol; ECH conflicts are
    /// rejected at parse time.
    #[test]
    fn wave8_openvpn_listeners_and_ech_guards() {
        let cfg = load(
            r#"
mixed-port: 7890
proxies:
  - name: ovpn
    type: openvpn
    server: v.example
    port: 1194
    proto: udp
    cipher: AES-256-GCM
    auth: SHA256
    comp-lzo: "no"
    ca: |
      -----BEGIN CERTIFICATE-----
      fake
      -----END CERTIFICATE-----
    username: u
    password: p
    tran-window: 100
    handshake-timeout: 20
    mtu: 1400
rules:
  - MATCH,ovpn
"#,
        )
        .unwrap();
        match &cfg.outbounds.iter().find(|o| o.name == "ovpn").unwrap().kind {
            crate::outbound::OutboundKind::OpenVpn(c) => {
                assert_eq!(c.proto.as_deref(), Some("udp"));
                assert_eq!(c.cipher, "AES-256-GCM");
                assert_eq!(c.tran_window, Some(100));
                assert_eq!(c.handshake_timeout, 20);
                assert_eq!(c.mtu, 1400);
            }
            other => panic!("wrong kind: {other:?}"),
        }

        // openvpn without ca is a parse error.
        let bad = r#"
mixed-port: 7890
proxies:
  - {name: ovpn2, type: openvpn, server: v.example, port: 1194}
rules:
  - MATCH,ovpn2
"#;
        let err = load(bad).err().unwrap().to_string();
        assert!(err.contains("openvpn requires ca"), "{err}");

        // restls + tlsmirror listeners.
        let lcfg = load(
            r#"
mixed-port: 7891
listeners:
  - name: rl
    type: restls
    listen: 127.0.0.1
    port: 18443
    password: pw
    restls-script: "250?100<1"
    min-record-len: 100
    rate-limit: 5
    dest: camo.example:443
proxies:
  - {name: d, type: socks5, server: 127.0.0.1, port: 1080}
rules:
  - MATCH,d
"#,
        )
        .unwrap();
        let rl = lcfg
            .proxy_servers
            .iter()
            .find(|l| l.tag == "rl")
            .expect("restls listener");
        assert_eq!(rl.protocol_name(), "restls");
        match &rl.protocol {
            crate::inbound::proxy_server::ServerProtocol::Restls {
                password, dest, ..
            } => {
                assert_eq!(password, "pw");
                assert_eq!(dest, "camo.example:443");
            }
            other => panic!("wrong protocol: {other:?}"),
        }

        let tm = load(
            r#"
mixed-port: 7892
listeners:
  - name: tm
    type: tlsmirror
    listen: 127.0.0.1
    port: 18444
    primary-key: cHJpbWFyeS1rZXktdmFsdWUtMzItYnl0ZXMhIQ==
    explicit-nonce-ciphersuites: [0x1302, 49199]
    defer-instance-derived-write-time: {base-nanoseconds: 100, uniform-random-multiplier-nanoseconds: 50}
    transport-layer-padding: {enabled: true}
    connection-enrolment: {primary-ingress-outbound: in, primary-egress-outbound: out}
    sequence-watermarking-enabled: true
    dest: carrier.example:443
proxies:
  - {name: d2, type: socks5, server: 127.0.0.1, port: 1080}
rules:
  - MATCH,d2
"#,
        )
        .unwrap();
        let tm = tm
            .proxy_servers
            .iter()
            .find(|l| l.tag == "tm")
            .expect("tlsmirror listener");
        assert_eq!(tm.protocol_name(), "tlsmirror");
        match &tm.protocol {
            crate::inbound::proxy_server::ServerProtocol::TlsMirror {
                primary_key,
                defer_write_time,
                enrolment,
                sequence_watermarking,
                dest,
                ..
            } => {
                assert!(!primary_key.is_empty());
                assert_eq!(*defer_write_time, (100, 50));
                assert_eq!(enrolment.as_ref(), Some(&("in".to_string(), "out".to_string())));
                assert!(*sequence_watermarking);
                assert_eq!(dest, "carrier.example:443");
            }
            other => panic!("wrong protocol: {other:?}"),
        }

        // ECH conflict guards.
        let both = r#"
mixed-port: 7893
proxies:
  - {name: bt, type: trojan, server: t.example, port: 443, password: pw, jls-opts: {username: u, password: p}, ech-opts: {enable: true, config: aGVsbG8=}}
rules:
  - MATCH,bt
"#;
        let err = load(both).err().unwrap().to_string();
        assert!(err.contains("cannot combine"), "{err}");

        let with_reality = r#"
mixed-port: 7894
proxies:
  - name: br
    type: vless
    server: v.example
    port: 443
    uuid: 66666666-6666-6666-6666-666666666666
    reality-opts: {public-key: x, short-id: y}
    ech-opts: {enable: true, config: aGVsbG8=}
rules:
  - MATCH,br
"#;
        let err = load(with_reality).err().unwrap().to_string();
        assert!(err.contains("cannot combine with reality-opts"), "{err}");
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
            crate::inbound::proxy_server::ServerProtocol::Shadowsocks { method, password, .. }
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
