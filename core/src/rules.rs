//! External rule provider management (Phase 13).
//!
//! Downloads rule provider payloads (yaml / mrs / list) referenced from
//! `config.rule_providers` into `<crash_dir>/configs/ruleset/`, tracks
//! last-update times in a sidecar state file, and refreshes providers whose
//! interval has elapsed. Files are replaced atomically.

use crate::config::{Config, ConfigManager, RuleProvider};
use crate::error::{Error, Result};
use crate::platform::Platform;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::PathBuf;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProviderState {
    /// Unix timestamp of the last successful download.
    pub last_updated: i64,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct StateFile {
    providers: BTreeMap<String, ProviderState>,
}

#[derive(Debug)]
pub struct RulesUpdateReport {
    pub updated: Vec<String>,
    pub failed: Vec<(String, String)>,
    pub skipped: Vec<String>,
}

pub struct RuleProviderManager {
    platform: Platform,
    client: reqwest::Client,
}

/// Derive the TPROXY listener port: the first free port past proxy+2,
/// skipping every occupied listener (redir, mixed, dns, dashboard). This
/// is the ONE definition — general_section, validate and the firewall CLI
/// all must agree on it, or TPROXY lands on someone else's socket.
pub fn derive_tproxy_port(config: &Config) -> std::result::Result<u16, Error> {
    let proxy = config.proxy_port;
    let occupied = [
        Some(proxy),
        config.mixed_port,
        Some(config.dns_port),
        Some(config.dashboard_port),
    ];
    let mut offset = 2u16;
    loop {
        let candidate = proxy
            .checked_add(offset)
            .filter(|p| (1..=65535).contains(p))
            .ok_or_else(|| {
                Error::Config(format!(
                    "proxy_port {proxy} leaves no room for the tproxy listener port"
                ))
            })?;
        if !occupied.contains(&Some(candidate)) {
            return Ok(candidate);
        }
        offset = offset.saturating_add(1);
    }
}

/// The general/kernel section prepended to generated Clash configs so the
/// firewall's redirects actually land somewhere: mixed + redirect + tproxy
/// listeners on the configured ports, a DNS listener on dns_port, and the
/// mode-appropriate dns enhanced-mode.
pub fn general_section(config: &Config) -> Result<String> {
    // Mix mode (ShellCrash 1.9.3+): fake-ip with a CN fake-ip-filter —
    // proxied domains resolve through fake-ip, CN domains get real answers
    // (ping works, speed tests unaffected).
    let (dns_mode, fakeip_filter) = match config.dns_mode.as_str() {
        "RedirHost" | "Local" => ("redir-host", None),
        "Mix" => ("fake-ip", Some(true)),
        _ => ("fake-ip", None),
    };
    let ipv6 = config.ipv6_enabled;
    let port = config.proxy_port;
    let dns_port = config.dns_port;
    let dashboard_port = config.dashboard_port;
    // Distinct listeners (one port = one socket; sharing them makes the
    // kernel bind only the first and silently drop the rest — community
    // #919 stays broken that way). mixed from config (default proxy+1),
    // redir = proxy_port (the firewall's redirect target), tproxy = the
    // TUN port when set, else the shared skip-occupied walk.
    // Checked derivation: a wrapped port (u16 overflow) would emit an
    // invalid listener — error instead of panicking (generate runs from
    // unattended paths on unvalidated configs).
    let derived = |offset: u16| -> Result<u16> {
        port.checked_add(offset)
            .filter(|p| (1..=65535).contains(p))
            .ok_or_else(|| {
                Error::Config(format!(
                    "proxy_port {port} leaves no room for the derived listener port (+{offset})"
                ))
            })
    };
    let mixed = config.mixed_port.unwrap_or(derived(1)?);
    // TPROXY skips every occupied listener (redir, mixed, dns, dashboard)
    // via the shared walk — the default dns_port 7892 == proxy+2, so a
    // blind proxy+2 collides with the DNS listener (live: TProxy/DNS-TCP
    // 'address already in use', UDP interception dead).
    let tproxy = config.tun_port.unwrap_or(derive_tproxy_port(config)?);
    let mut s = String::new();
    s.push_str("\n# General — listeners and DNS matching the firewall rules\n");
    s.push_str(&format!("mixed-port: {mixed}\n"));
    s.push_str(&format!("redir-port: {port}\n"));
    s.push_str(&format!("tproxy-port: {tproxy}\n"));
    s.push_str(&format!(
        "allow-lan: true\nbind-address: '*'\nmode: rule\nlog-level: info\nipv6: {ipv6}\nexternal-controller: 127.0.0.1:{dashboard_port}\n"
    ));
    // Dashboard panel: the kernel downloads and serves the UI itself
    // (ShellCrash 1.9.3 added Zashboard/MetaXD — zashboard is the default).
    s.push_str("external-ui: ui\nexternal-ui-url: \"https://github.com/Zephyruso/zashboard/archive/refs/heads/gh-pages.zip\"\n");
    s.push_str(&format!(
        "dns:\n  enable: true\n  listen: 0.0.0.0:{dns_port}\n  enhanced-mode: {dns_mode}\n  ipv6: {ipv6}\n"
    ));
    // ShellCrash 1.9.5: fakeip range moved to 198.18.0.0/15 (the mihomo
    // default 198.18.0.1/16 overlaps reserved ranges on some devices).
    if dns_mode == "fake-ip" {
        s.push_str("  fake-ip-range: 198.18.0.1/15\n");
    }
    if fakeip_filter == Some(true) {
        // CN domains bypass fake-ip (mix-mode semantics). geosite:cn only —
        // a rule-set reference without a matching rule-provider makes the
        // kernel reject the whole config (verified: mihomo -t 'not found
        // rule-set: cn').
        s.push_str("  fake-ip-filter:\n    - \"geosite:cn\"\n    - '*.lan'\n    - '*.local'\n");
    }
    s.push_str("  default-nameserver:\n    - 223.5.5.5\n    - 119.29.29.29\n");
    s.push_str(
        "  nameserver:\n    - https://223.5.5.5/dns-query\n    - https://doh.pub/dns-query\n",
    );
    Ok(s)
}

/// Derive the stored file name for a provider URL: final URL component
/// (sanitized), prefixed with the provider name for uniqueness.
pub fn provider_file_name(name: &str, url: &str) -> String {
    // Final URL component, sanitized; the provider name already makes the
    // result unique.
    let base = url
        .trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|s| !s.is_empty() && s.len() <= 128)
        .map(|s| {
            s.chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-' || *c == '_')
                .collect::<String>()
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "provider.dat".to_string());
    format!("{name}-{base}")
}

/// Validate a provider URL: http(s) with a host.
pub fn validate_provider_url(url: &str) -> Result<()> {
    let ok = (url.starts_with("https://") || url.starts_with("http://"))
        && url.len() <= 4096
        && !url.contains(char::is_whitespace)
        && url
            .split("://")
            .nth(1)
            .map(|rest| rest.contains('.'))
            .unwrap_or(false);
    if ok {
        Ok(())
    } else {
        Err(Error::Security(format!("invalid rule provider url: {url}")))
    }
}

impl RuleProviderManager {
    pub fn new(platform: &Platform) -> Self {
        RuleProviderManager {
            platform: platform.clone(),
            client: crate::notify::shared_client().clone(),
        }
    }

    pub fn ruleset_dir(&self) -> PathBuf {
        PathBuf::from(format!("{}/configs/ruleset", self.platform.crash_dir()))
    }

    fn state_path(&self) -> PathBuf {
        self.ruleset_dir().join(".state.json")
    }

    fn load_state(&self) -> StateFile {
        std::fs::read(self.state_path())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    fn save_state(&self, state: &StateFile) -> Result<()> {
        let dir = self.ruleset_dir();
        std::fs::create_dir_all(&dir)?;
        let tmp = dir.join(".state.json.tmp");
        std::fs::write(&tmp, serde_json::to_vec_pretty(state)?)?;
        std::fs::rename(tmp, self.state_path())?;
        Ok(())
    }

    /// Providers whose update interval has elapsed (or never updated).
    pub fn due_providers(&self, config: &Config, now: i64) -> Vec<RuleProvider> {
        let state = self.load_state();
        config
            .rule_providers
            .iter()
            .filter(|p| {
                let interval = p.interval.max(1) as i64;
                state
                    .providers
                    .get(&p.name)
                    .map(|s| now - s.last_updated >= interval)
                    .unwrap_or(true)
            })
            .cloned()
            .collect()
    }

    /// Update every provider due for refresh. Downloads run concurrently
    /// (bounded) — typical subscriptions carry dozens of providers.
    pub async fn update_due(&self, config: &Config) -> RulesUpdateReport {
        const MAX_CONCURRENT: usize = 4;
        let now = chrono::Utc::now().timestamp();
        let due = self.due_providers(config, now);
        let skipped: Vec<String> = config
            .rule_providers
            .iter()
            .filter(|p| !due.iter().any(|d| d.name == p.name))
            .map(|p| p.name.clone())
            .collect();

        let mut report = RulesUpdateReport {
            updated: Vec::new(),
            failed: Vec::new(),
            skipped,
        };

        // Fetch concurrently with a small semaphore bound.
        let semaphore = std::sync::Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT));
        let mut results: Vec<(RuleProvider, std::result::Result<Vec<u8>, Error>)> =
            Vec::with_capacity(due.len());
        let mut set = tokio::task::JoinSet::new();
        for provider in due {
            let Ok(permit) = semaphore.clone().acquire_owned().await else {
                continue;
            };
            let this = Self {
                platform: self.platform.clone(),
                client: self.client.clone(),
            };
            set.spawn(async move {
                let result = this.fetch_provider(&provider).await;
                drop(permit);
                (provider, result)
            });
        }
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok(pair) => results.push(pair),
                Err(e) => report.failed.push(("task".to_string(), e.to_string())),
            }
        }

        let mut state = self.load_state();
        for (provider, outcome) in results {
            match outcome {
                Ok(bytes) => match self.store_provider(&provider, &bytes) {
                    Ok(()) => {
                        state
                            .providers
                            .insert(provider.name.clone(), ProviderState { last_updated: now });
                        report.updated.push(provider.name.clone());
                    }
                    Err(e) => report.failed.push((provider.name.clone(), e.to_string())),
                },
                Err(e) => report.failed.push((provider.name.clone(), e.to_string())),
            }
        }

        if !report.updated.is_empty() {
            if let Err(e) = self.save_state(&state) {
                report.failed.push(("state".to_string(), e.to_string()));
            }
        }
        report
    }

    async fn fetch_provider(&self, provider: &RuleProvider) -> Result<Vec<u8>> {
        validate_provider_url(&provider.url)?;
        let bytes = self
            .client
            .get(&provider.url)
            .send()
            .await
            .map_err(|e| Error::Download(format!("rule provider fetch failed: {e}")))?
            .error_for_status()
            .map_err(|e| Error::Download(format!("rule provider http error: {e}")))?
            .bytes()
            .await
            .map_err(|e| Error::Download(format!("rule provider read failed: {e}")))?;
        if bytes.is_empty() {
            return Err(Error::Download(format!(
                "rule provider {} returned empty payload",
                provider.name
            )));
        }
        Ok(bytes.to_vec())
    }

    fn store_provider(&self, provider: &RuleProvider, bytes: &[u8]) -> Result<()> {
        let dir = self.ruleset_dir();
        std::fs::create_dir_all(&dir)?;
        let name = provider_file_name(&provider.name, &provider.url);
        let final_path = dir.join(&name);
        let tmp = dir.join(format!(".{name}.tmp"));
        std::fs::write(&tmp, bytes)?;
        std::fs::rename(&tmp, &final_path)?;
        Ok(())
    }

    /// Path a kernel config should reference for a provider.
    pub fn provider_path(&self, provider: &RuleProvider) -> PathBuf {
        self.ruleset_dir()
            .join(provider_file_name(&provider.name, &provider.url))
    }
}

/// Convenience: load config for a platform and update due providers.
pub async fn update_due_for(platform: &Platform) -> Result<RulesUpdateReport> {
    let config = ConfigManager::new(platform).load()?;
    Ok(RuleProviderManager::new(platform).update_due(&config).await)
}

/// Render the `rule-providers:` YAML section for the configured providers,
/// pointing each entry at the file the RuleProviderManager downloads.
/// Behavior is inferred from the URL: `.mrs` with an ip-ish name is ipcidr,
/// other `.mrs` are domain, everything else classical.
///
/// `ruleset_dir` is embedded as an absolute path — mihomo resolves relative
/// rule-provider paths against its `-d` working dir, which is the log dir
/// here, not the storage location.
pub fn rule_providers_yaml(providers: &[RuleProvider], ruleset_dir: &str) -> Result<String> {
    if providers.is_empty() {
        return Ok(String::new());
    }
    let mut out = String::from("\nrule-providers:\n");
    for p in providers {
        // Validate before interpolating into YAML: names are keys, URLs are
        // scalar values — neither may carry structure characters.
        sanitize_name(&p.name)?;
        validate_provider_url(&p.url)?;
        let lower = p.url.to_ascii_lowercase();
        let (behavior, format) = if lower.ends_with(".mrs") {
            let name = p.name.to_ascii_lowercase();
            let behavior = if name.contains("ip") || name.contains("cidr") {
                "ipcidr"
            } else {
                "domain"
            };
            (behavior, "mrs")
        } else if lower.ends_with(".yaml") || lower.ends_with(".yml") {
            ("classical", "yaml")
        } else {
            ("classical", "text")
        };
        let file = provider_file_name(&p.name, &p.url);
        out.push_str(&format!(
            "  {}:\n    type: http\n    behavior: {behavior}\n    format: {format}\n    url: {}\n    path: {ruleset_dir}/{file}\n    interval: {}\n",
            p.name, p.url, p.interval.max(1)
        ));
    }
    Ok(out)
}

/// Build the kernel config for the selected subscription: URI lists are
/// converted through the subconverter (proxy groups with url-test
/// tolerance, then the rule-providers section from config); content that is
/// already a full config passes through untouched.
///
/// `crash_dir` anchors the absolute rule-provider paths (mihomo resolves
/// relative paths against its `-d` dir, which differs from storage).
pub fn generate_kernel_config(
    config: &Config,
    kernel: crate::platform::ProxyKernel,
    crash_dir: &str,
) -> Result<String> {
    let sub = config
        .subscriptions
        .get(config.selected_sub)
        .ok_or_else(|| Error::Config("no subscription selected".into()))?;
    let content = sub
        .raw_config
        .as_deref()
        .filter(|c| !c.is_empty())
        .ok_or_else(|| Error::Config("subscription content not fetched yet".into()))?;

    let target = match kernel {
        crate::platform::ProxyKernel::SingBox => crate::subconverter::TargetFormat::SingBox,
        _ => crate::subconverter::TargetFormat::Clash,
    };
    // Only URI lists need conversion; full-config subscriptions pass through.
    let format = crate::subscription::SubscriptionManager::detect_format(content);
    if format != crate::subscription::SubscriptionFormat::UriList {
        return Ok(content.to_string());
    }

    let uris: Vec<String> = content
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect();
    let nodes = crate::subconverter::uri::parse_uri_list(&uris.join("\n"));
    if nodes.is_empty() {
        return Err(Error::Subscription("no valid nodes in subscription".into()));
    }
    // expand=false: the built-in template rules reference their own
    // rule-providers; we emit the configured ones instead below so the
    // generated config never has two `rule-providers:` mappings.
    let mut out = crate::subconverter::formats::convert_nodes_with_options(
        &nodes, target, false, false, None,
    );
    if target == crate::subconverter::TargetFormat::Clash {
        // The general section makes the config actually usable as a
        // transparent proxy: without listening ports the firewall has
        // nowhere to redirect to, and without a dns section the kernel
        // never hijacks DNS (ShellCrash community issue #919 — the
        // "gateway+DNS pointed at the box but nothing goes through"
        // class). bind-address stays on loopback+LAN unless the user
        // opens it up; hijacked LAN source ranges are the firewall's
        // job, not the listener's.
        out.push_str(&general_section(config)?);
        let ruleset_dir = format!("{crash_dir}/configs/ruleset");
        out.push_str(&rule_providers_yaml(&config.rule_providers, &ruleset_dir)?);
        // A rules section is always emitted (a Clash config without one is
        // invalid); RULE-SET lines reference the configured providers.
        out.push_str("\nrules:\n");
        for p in &config.rule_providers {
            out.push_str(&format!(
                "  - RULE-SET,{},DIRECT\n",
                sanitize_name(&p.name)?
            ));
        }
        out.push_str("  - MATCH,Auto\n");
    }
    Ok(out)
}

/// Provider names become YAML keys and RULE-SET references — restrict them
/// to a safe charset (no quoting/structure injection).
fn sanitize_name(name: &str) -> Result<&str> {
    let valid = !name.is_empty()
        && name.len() <= 64
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_');
    if valid {
        Ok(name)
    } else {
        Err(Error::Security(format!(
            "rule provider name must be alphanumeric/-/_ (max 64): {name}"
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(name: &str, url: &str, interval: u64) -> RuleProvider {
        RuleProvider {
            name: name.to_string(),
            url: url.to_string(),
            interval,
        }
    }

    #[test]
    fn file_name_sanitizes_url_component() {
        assert_eq!(
            provider_file_name("cn", "https://example.com/rules/cn.mrs"),
            "cn-cn.mrs"
        );
        // No usable final component → generic fallback stays inside the dir.
        let name = provider_file_name("x", "https://example.com/");
        assert!(name.starts_with("x-"));
        assert!(!name.contains('/'));
        // Query strings are not part of the path component here because the
        // caller passes clean URLs; traversal attempts get filtered.
        let evil = provider_file_name("e", "https://example.com/../../etc/passwd");
        assert!(!evil.contains(".."), "{evil}");
    }

    #[test]
    fn url_validation() {
        assert!(validate_provider_url("https://example.com/r.yaml").is_ok());
        assert!(validate_provider_url("http://example.com/r.mrs").is_ok());
        assert!(validate_provider_url("ftp://example.com/r").is_err());
        assert!(validate_provider_url("not a url").is_err());
        assert!(validate_provider_url("https://").is_err());
        assert!(validate_provider_url("file:///etc/passwd").is_err());
    }

    #[test]
    fn rule_providers_yaml_behavior_inference() {
        let providers = vec![
            provider("cn", "https://example.com/cn.mrs", 86400),
            provider("cnip", "https://example.com/cnip.mrs", 86400),
            provider("custom", "https://example.com/list.yaml", 3600),
        ];
        let yaml = rule_providers_yaml(&providers, "/etc/rc/configs/ruleset").unwrap();
        assert!(yaml.contains("  cn:\n    type: http\n    behavior: domain\n    format: mrs"));
        assert!(yaml.contains("  cnip:\n    type: http\n    behavior: ipcidr\n    format: mrs"));
        assert!(
            yaml.contains("  custom:\n    type: http\n    behavior: classical\n    format: yaml")
        );
        assert!(yaml.contains("path: /etc/rc/configs/ruleset/cn-cn.mrs"));
        assert!(yaml.contains("interval: 86400"));
        // Empty providers → no section.
        assert!(rule_providers_yaml(&[], "/etc/rc/configs/ruleset")
            .unwrap()
            .is_empty());
    }

    #[test]
    fn rule_providers_yaml_rejects_injection() {
        let bad_name = provider("a\nb: injected", "https://example.com/r.mrs", 60);
        assert!(rule_providers_yaml(&[bad_name], "/x").is_err());
        let bad_url = provider("cn", "https://example.com/r\nx: 1", 60);
        assert!(rule_providers_yaml(&[bad_url], "/x").is_err());
    }

    #[test]
    fn generate_kernel_config_passes_full_configs_through() {
        let mut config = Config::default();
        config.subscriptions = vec![crate::config::Subscription {
            name: "s".into(),
            url: "https://example.com/sub".into(),
            updated_at: None,
            raw_config: Some("proxies:\n  - name: a\n".into()),
        }];
        let out = generate_kernel_config(&config, crate::platform::ProxyKernel::Mihomo, "/etc/rc")
            .unwrap();
        assert_eq!(out, "proxies:\n  - name: a\n");
    }

    #[test]
    fn general_section_tproxy_skips_occupied_listeners() {
        // Default config: dns_port 7892 == proxy+2 — tproxy must skip it.
        let section = general_section(&Config::default()).unwrap();
        assert!(section.contains("tproxy-port: 7893"));
        assert!(section.contains("listen: 0.0.0.0:7892"), "dns keeps 7892");
        // Custom: dns far away -> plain proxy+2.
        let config = Config {
            dns_port: 11053,
            ..Default::default()
        };
        let section = general_section(&config).unwrap();
        assert!(section.contains("tproxy-port: 7892"));
    }

    #[test]
    fn general_section_syncs_latest_shellcrash_defaults() {
        // 1.9.5: fake-ip range 198.18.0.0/15; external-ui panel served by
        // the kernel; Mix mode = fake-ip + CN fake-ip-filter.
        let section = general_section(&Config::default()).unwrap();
        assert!(section.contains("fake-ip-range: 198.18.0.1/15"));
        assert!(section.contains("external-ui: ui"));
        assert!(section.contains("zashboard"));
        assert!(!section.contains("fake-ip-filter:"));

        let mix = Config {
            dns_mode: "Mix".to_string(),
            ..Default::default()
        };
        let section = general_section(&mix).unwrap();
        assert!(section.contains("enhanced-mode: fake-ip"));
        assert!(section.contains("fake-ip-filter:"));
        assert!(section.contains("geosite:cn"));
        // R26: a rule-set reference without a matching provider makes the
        // kernel reject the whole config ('not found rule-set: cn').
        assert!(!section.contains("rule-set:"));

        // RedirHost unchanged: no fake-ip fields.
        let rh = Config {
            dns_mode: "RedirHost".to_string(),
            ..Default::default()
        };
        let section = general_section(&rh).unwrap();
        assert!(section.contains("enhanced-mode: redir-host"));
        assert!(!section.contains("fake-ip-range"));
    }

    #[test]
    fn general_section_ports_are_distinct() {
        // One port per listener: a shared port binds only the first socket
        // and the kernel silently drops the rest (round-19 live finding).
        let config = Config::default(); // proxy 7890
        let section = general_section(&config).unwrap();
        let ports: Vec<u16> = ["mixed-port", "redir-port", "tproxy-port"]
            .iter()
            .filter_map(|k| {
                section
                    .lines()
                    .find(|l| l.starts_with(&format!("{k}: ")))
                    .and_then(|l| l.split(": ").nth(1))
                    .and_then(|v| v.trim().parse().ok())
            })
            .collect();
        assert_eq!(ports.len(), 3);
        // Default config: mixed 7891, redir 7890, tproxy skips DNS 7892
        // (occupied) -> 7893.
        assert_eq!(ports, vec![7891, 7890, 7893]);
        let mut seen = std::collections::HashSet::new();
        for p in ports {
            assert!(seen.insert(p), "port {p} used by two listeners");
        }
    }

    #[test]
    fn general_section_makes_generated_config_a_working_proxy() {
        // Regression (community issue class #919): the generated kernel
        // config had no listeners/DNS — the firewall redirected to ports
        // nothing listened on.
        let config = Config {
            proxy_port: 18080,
            dns_port: 11053,
            dns_mode: "RedirHost".to_string(),
            mixed_port: None, // exercise the derived default (proxy+1)
            ..Default::default()
        };
        let section = general_section(&config).unwrap();
        for needle in [
            "mixed-port: 18081",
            "redir-port: 18080",
            "tproxy-port: 18082",
            "allow-lan: true",
            "listen: 0.0.0.0:11053",
            "enhanced-mode: redir-host",
            "external-controller: 127.0.0.1:9090",
        ] {
            assert!(section.contains(needle), "missing {needle} in:\n{section}");
        }
        // fake-ip default
        assert!(general_section(&Config::default())
            .unwrap()
            .contains("enhanced-mode: fake-ip"));
    }

    #[test]
    fn generate_kernel_config_converts_uri_lists_with_providers() {
        let mut config = Config::default();
        // Known-good base64 vmess URI (same vector as the uri tests).
        let vmess = "vmess://eyJ2IjoiMiIsInBzIjoiVGVzdCIsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTIzNDU2NzgtMTIzNC0xMjM0LTEyMzQtMTIzNDU2Nzg5YWJjIiwiYWlkIjoiMCIsIm5ldCI6IndzIiwidGxzIjoidGxzIn0=";
        config.subscriptions = vec![crate::config::Subscription {
            name: "s".into(),
            url: "https://example.com/sub".into(),
            updated_at: None,
            raw_config: Some(vmess.to_string()),
        }];
        config.rule_providers = vec![provider("cn", "https://example.com/cn.mrs", 86400)];

        let out = generate_kernel_config(&config, crate::platform::ProxyKernel::Mihomo, "/etc/rc")
            .unwrap();
        assert!(out.contains("proxies:"));
        assert!(out.contains("proxy-groups:"));
        assert!(out.contains("type: url-test"));
        assert!(out.contains("tolerance: 50"));
        // General section present: listeners (distinct ports!) + dns.
        assert!(out.contains("mixed-port: 7891"));
        assert!(out.contains("redir-port: 7890"));
        assert!(out.contains("tproxy-port: 7893"));
        assert!(out.contains("dns:"));
        assert!(out.contains("listen: 0.0.0.0:7892"));
        // Exactly one rule-providers mapping (no duplicate key), with rules
        // referencing the configured provider.
        assert_eq!(out.matches("rule-providers:").count(), 1);
        assert!(out.contains("behavior: domain"));
        assert!(out.contains("rules:"));
        assert!(out.contains("RULE-SET,cn,DIRECT"));
        assert!(out.contains("MATCH,Auto"));
    }

    #[test]
    fn generate_kernel_config_errors_without_subscription() {
        let config = Config::default();
        assert!(
            generate_kernel_config(&config, crate::platform::ProxyKernel::Mihomo, "/etc/rc")
                .is_err()
        );
    }

    #[test]
    fn generate_kernel_config_with_empty_providers_has_valid_rules() {
        let mut config = Config::default();
        let vmess = "vmess://eyJ2IjoiMiIsInBzIjoiVGVzdCIsImFkZCI6ImV4YW1wbGUuY29tIiwicG9ydCI6IjQ0MyIsImlkIjoiMTIzNDU2NzgtMTIzNC0xMjM0LTEyMzQtMTIzNDU2Nzg5YWJjIiwiYWlkIjoiMCIsIm5ldCI6IndzIiwidGxzIjoidGxzIn0=";
        config.subscriptions = vec![crate::config::Subscription {
            name: "s".into(),
            url: "https://example.com/sub".into(),
            updated_at: None,
            raw_config: Some(vmess.to_string()),
        }];
        // No providers configured: rules must still form a valid section.
        let out = generate_kernel_config(&config, crate::platform::ProxyKernel::Mihomo, "/etc/rc")
            .unwrap();
        assert!(out.contains("\nrules:\n"));
        let rules_pos = out.find("\nrules:\n").unwrap();
        let match_pos = out.find("MATCH,Auto").unwrap();
        assert!(match_pos > rules_pos, "MATCH must follow the rules key");
        assert!(!out.contains("rule-providers:"));
    }

    #[test]
    fn due_providers_respect_interval() {
        let tmp = tempfile::TempDir::new().unwrap();
        let platform = Platform::for_crash_dir(tmp.path().to_str().unwrap());
        let mgr = RuleProviderManager::new(&platform);

        let config = Config {
            rule_providers: vec![
                provider("never", "https://example.com/a.yaml", 86400),
                provider("fresh", "https://example.com/b.yaml", 86400),
            ],
            ..Default::default()
        };
        let now = 1_000_000;

        // Mark "fresh" as updated right now.
        let mut state = StateFile::default();
        state
            .providers
            .insert("fresh".to_string(), ProviderState { last_updated: now });
        std::fs::create_dir_all(mgr.ruleset_dir()).unwrap();
        std::fs::write(mgr.state_path(), serde_json::to_vec(&state).unwrap()).unwrap();

        let due = mgr.due_providers(&config, now);
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].name, "never");

        // A day later both are due.
        let due = mgr.due_providers(&config, now + 86400);
        assert_eq!(due.len(), 2);
    }

    #[tokio::test]
    async fn update_due_downloads_and_persists_state() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/rules/cn.yaml"))
            .respond_with(wiremock::ResponseTemplate::new(200).set_body_string("payload: v1\n"))
            .mount(&server)
            .await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .and(wiremock::matchers::path("/rules/broken.yaml"))
            .respond_with(wiremock::ResponseTemplate::new(500))
            .mount(&server)
            .await;

        let tmp = tempfile::TempDir::new().unwrap();
        let platform = Platform::for_crash_dir(tmp.path().to_str().unwrap());
        let mgr = RuleProviderManager::new(&platform);

        let config = Config {
            rule_providers: vec![
                provider("cn", &format!("{}/rules/cn.yaml", server.uri()), 86400),
                provider(
                    "broken",
                    &format!("{}/rules/broken.yaml", server.uri()),
                    86400,
                ),
            ],
            ..Default::default()
        };

        let report = mgr.update_due(&config).await;
        assert_eq!(report.updated, vec!["cn"]);
        assert_eq!(report.failed.len(), 1);
        assert_eq!(report.failed[0].0, "broken");

        // File stored under the ruleset dir.
        let stored = mgr.provider_path(&config.rule_providers[0]);
        assert!(stored.exists());
        assert_eq!(std::fs::read_to_string(stored).unwrap(), "payload: v1\n");

        // State persisted: second run skips the fresh provider.
        let report2 = mgr.update_due(&config).await;
        assert!(report2.updated.is_empty());
        assert_eq!(report2.skipped, vec!["cn"]);
    }

    #[tokio::test]
    async fn empty_payload_rejected() {
        let server = wiremock::MockServer::start().await;
        wiremock::Mock::given(wiremock::matchers::method("GET"))
            .respond_with(wiremock::ResponseTemplate::new(200))
            .mount(&server)
            .await;
        let tmp = tempfile::TempDir::new().unwrap();
        let platform = Platform::for_crash_dir(tmp.path().to_str().unwrap());
        let mgr = RuleProviderManager::new(&platform);
        let config = Config {
            rule_providers: vec![provider("e", &format!("{}/x", server.uri()), 60)],
            ..Default::default()
        };
        let report = mgr.update_due(&config).await;
        assert_eq!(report.failed.len(), 1);
        assert!(report.failed[0].1.contains("empty"));
    }

    #[test]
    fn state_roundtrip() {
        let tmp = tempfile::TempDir::new().unwrap();
        let platform = Platform::for_crash_dir(tmp.path().to_str().unwrap());
        let mgr = RuleProviderManager::new(&platform);
        let mut state = StateFile::default();
        state
            .providers
            .insert("a".into(), ProviderState { last_updated: 42 });
        mgr.save_state(&state).unwrap();
        let loaded = mgr.load_state();
        assert_eq!(loaded.providers["a"].last_updated, 42);
    }
}
