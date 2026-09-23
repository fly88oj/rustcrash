//! Configuration management for mihomo/sing-box

use crate::error::{Error, Result};
use crate::firewall::{
    FirewallConfig, MacFilterType, DEFAULT_DNS_PORT, DEFAULT_MIXED_PORT, DEFAULT_PROXY_PORT,
};
use crate::platform::{Platform, ProxyKernel};
use serde::{Deserialize, Serialize};
use std::fmt;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub enum ConfigVariant {
    Full,
    FullNoAds,
    #[default]
    Lite,
    LiteNoAds,
    Light,
    Nano,
}

impl fmt::Display for ConfigVariant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Full => write!(f, "Full"),
            Self::FullNoAds => write!(f, "FullNoAds"),
            Self::Lite => write!(f, "Lite"),
            Self::LiteNoAds => write!(f, "LiteNoAds"),
            Self::Light => write!(f, "Light"),
            Self::Nano => write!(f, "Nano"),
        }
    }
}

impl ConfigVariant {
    pub fn rule_count(&self) -> usize {
        match self {
            Self::Full => 18,
            Self::FullNoAds => 17,
            Self::Lite => 13,
            Self::LiteNoAds => 12,
            Self::Light => 7,
            Self::Nano => 3,
        }
    }

    pub fn has_ads_block(&self) -> bool {
        matches!(self, Self::Full | Self::Lite)
    }
}

/// Proxy mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ProxyMode {
    #[default]
    Router,
    Local,
    Pure,
}

/// DNS mode
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ConfigDnsMode {
    #[default]
    FakeIp,
    RedirHost,
    Local,
}

/// Rule provider source
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleProvider {
    pub name: String,
    pub url: String,
    pub interval: u64,
}

/// Main configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub kernel: String,
    pub kernel_version: String,
    pub variant: String,
    pub mode: String,
    pub dns_mode: String,
    pub proxy_port: u16,
    pub dns_port: u16,
    pub tun_port: Option<u16>,
    pub mixed_port: Option<u16>,
    pub auto_update: bool,
    pub update_interval: String,
    pub subscriptions: Vec<Subscription>,
    pub selected_sub: usize,
    pub rule_providers: Vec<RuleProvider>,
    pub config_path: Option<String>,
    pub dashboard: bool,
    pub dashboard_port: u16,
    pub log_level: String,
    // Advanced firewall settings (Phase 7)
    pub tun_enabled: bool,
    pub ipv6_enabled: bool,
    pub ipv6_redir: bool,
    pub vm_ipv4: Option<String>,
    pub vm_redir: bool,
    pub macfilter_type: Option<String>,
    pub macfilter_addrs: Vec<String>,
    pub ip_filter: Option<String>,
    pub cn_ip_route: bool,
    pub quic_reject: bool,
    pub common_ports: Vec<u16>,
    /// LAN source subnets eligible for prerouting hijack (default:
    /// RFC1918). Empty means default.
    #[serde(default)]
    pub hijack_subnets: Vec<String>,
    // Telegram bot (Phase 9). The token is a secret: it is read from the
    // config file or the RUSTCRASH_TGBOT_TOKEN env var, never hardcoded.
    #[serde(default)]
    pub tgbot_enable: bool,
    #[serde(default)]
    pub tgbot_token: Option<String>,
    #[serde(default)]
    pub tgbot_chat_ids: Vec<i64>,
    /// Mode to restore when leaving Pure mode via the bot.
    #[serde(default = "default_mode_before_pure")]
    pub mode_before_pure: String,
    // Notification channels (Phase 10). Credentials live in config or env
    // only; see core/src/notify.rs.
    #[serde(default)]
    pub notifications: Vec<crate::notify::NotifyConfig>,
    /// Event ids that trigger notifications: start|stop|restart|sub_update|kernel_update|error
    #[serde(default)]
    pub notify_events: Vec<String>,
    // REST API (Phase 11). Token read from config or RUSTCRASH_API_TOKEN.
    #[serde(default)]
    pub api_enabled: bool,
    #[serde(default = "default_api_port")]
    pub api_port: u16,
    #[serde(default)]
    pub api_token: Option<String>,
    // Geo data sources (Phase 12).
    #[serde(default = "default_geo_repo")]
    pub geo_repo: String,
    /// Optional mirror prefix for GitHub downloads (CDN optimization).
    #[serde(default)]
    pub geo_mirror: Option<String>,
}

fn default_api_port() -> u16 {
    9097
}

fn default_geo_repo() -> String {
    crate::geo::DEFAULT_GEO_REPO.to_string()
}

fn default_mode_before_pure() -> String {
    "Router".to_string()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Subscription {
    pub name: String,
    pub url: String,
    pub updated_at: Option<i64>,
    pub raw_config: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            kernel: "mihomo".to_string(),
            kernel_version: String::new(),
            variant: "Lite".to_string(),
            mode: "Router".to_string(),
            dns_mode: "FakeIp".to_string(),
            proxy_port: DEFAULT_PROXY_PORT,
            dns_port: DEFAULT_DNS_PORT,
            tun_port: None,
            mixed_port: Some(DEFAULT_MIXED_PORT),
            auto_update: true,
            update_interval: "24h".to_string(),
            subscriptions: Vec::new(),
            selected_sub: 0,
            rule_providers: Vec::new(),
            config_path: None,
            dashboard: true,
            dashboard_port: 9090,
            log_level: "info".to_string(),
            tun_enabled: false,
            ipv6_enabled: false,
            ipv6_redir: false,
            vm_ipv4: None,
            vm_redir: false,
            macfilter_type: None,
            macfilter_addrs: Vec::new(),
            ip_filter: None,
            cn_ip_route: false,
            quic_reject: false,
            common_ports: Vec::new(),
            hijack_subnets: Vec::new(),
            tgbot_enable: false,
            tgbot_token: None,
            tgbot_chat_ids: Vec::new(),
            mode_before_pure: default_mode_before_pure(),
            notifications: Vec::new(),
            notify_events: Vec::new(),
            api_enabled: false,
            api_port: default_api_port(),
            api_token: None,
            geo_repo: default_geo_repo(),
            geo_mirror: None,
        }
    }
}

impl Config {
    /// A clone with every secret replaced by `"***"` — the shape the REST
    /// API returns. Typed, so field renames can't silently miss a secret.
    pub fn redacted(&self) -> Config {
        let mut c = self.clone();
        if c.tgbot_token
            .as_deref()
            .map(|t| !t.is_empty())
            .unwrap_or(false)
        {
            c.tgbot_token = Some("***".to_string());
        }
        if c.api_token
            .as_deref()
            .map(|t| !t.is_empty())
            .unwrap_or(false)
        {
            c.api_token = Some("***".to_string());
        }
        for ch in &mut c.notifications {
            for field in [&mut ch.token, &mut ch.user] {
                if field.as_deref().map(|t| !t.is_empty()).unwrap_or(false) {
                    *field = Some("***".to_string());
                }
            }
        }
        for sub in &mut c.subscriptions {
            if let Some(q) = sub.url.find('?') {
                sub.url.truncate(q);
                sub.url.push_str("?…");
            }
        }
        c
    }

    /// The proxy kernel this configuration selects.
    pub fn active_kernel(&self) -> ProxyKernel {
        if self.kernel == "sing-box" {
            ProxyKernel::SingBox
        } else {
            ProxyKernel::Mihomo
        }
    }

    pub fn to_firewall_config(&self) -> Result<FirewallConfig> {
        let macfilter = self.macfilter_type.as_ref().map(|t| {
            if t == "whitelist" {
                MacFilterType::Whitelist
            } else {
                MacFilterType::Blacklist
            }
        });

        Ok(FirewallConfig {
            // tun_port is None until a user sets one — derive the actual
            // TPROXY listener via the shared skip-occupied walk so
            // 'tun_enabled: true' with no explicit port still gets tproxy
            // rules (was a silent no-op) and the firewall and kernel
            // config agree on the port.
            tun_port: if self.tun_enabled {
                match self.tun_port {
                    Some(t) => Some(t),
                    None => Some(crate::rules::derive_tproxy_port(self)?),
                }
            } else {
                None
            },
            vm_ipv4: self.vm_ipv4.clone(),
            vm_redir: self.vm_redir,
            ipv6_enabled: self.ipv6_enabled,
            macfilter_type: macfilter,
            macfilter_addrs: self.macfilter_addrs.clone(),
            ip_filter: self.ip_filter.clone(),
            cn_ip_route: self.cn_ip_route,
            quic_reject: self.quic_reject,
            common_ports: self.common_ports.clone(),
            dns_port: self.dns_port,
            proxy_port: self.proxy_port,
            mixed_port: self.mixed_port.unwrap_or(self.proxy_port.wrapping_add(1)),
            hijack_subnets: if self.hijack_subnets.is_empty() {
                crate::firewall::DEFAULT_HIJACK_SUBNETS
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            } else {
                self.hijack_subnets.clone()
            },
        })
    }
}

/// Configuration manager
pub struct ConfigManager {
    #[allow(dead_code)]
    platform: Platform,
    crash_dir: String,
}

impl ConfigManager {
    pub fn new(platform: &Platform) -> Self {
        ConfigManager {
            platform: platform.clone(),
            crash_dir: platform.crash_dir(),
        }
    }

    pub fn config_path(&self) -> String {
        format!("{}/config.yaml", self.crash_dir)
    }

    pub fn load(&self) -> Result<Config> {
        let path = self.config_path();
        if !Path::new(&path).exists() {
            return Ok(Config::default());
        }
        let content = fs::read_to_string(&path)?;
        let config: Config = serde_yaml::from_str(&content)
            .map_err(|e| Error::Config(format!("Failed to parse config: {e}")))?;
        Ok(config)
    }

    pub fn save(&self, config: &Config) -> Result<()> {
        let path = self.config_path();
        let dir = Path::new(&path).parent().unwrap();
        fs::create_dir_all(dir)?;
        let content = serde_yaml::to_string(config)
            .map_err(|e| Error::Config(format!("Failed to serialize config: {e}")))?;
        fs::write(&path, content)?;
        restrict_permissions(&path);
        Ok(())
    }

    pub fn kernel_config_path(&self, kernel: ProxyKernel) -> String {
        // Kernel configs live under configs/, never at config.yaml — that
        // path is the management config (generating a kernel config used
        // to clobber it).
        match kernel {
            ProxyKernel::Mihomo => format!("{}/configs/mihomo.yaml", self.crash_dir),
            ProxyKernel::SingBox => format!("{}/configs/sing-box.json", self.crash_dir),
        }
    }

    pub fn has_kernel_config(&self, kernel: ProxyKernel) -> bool {
        Path::new(&self.kernel_config_path(kernel)).exists()
    }

    pub fn load_kernel_config(&self, kernel: ProxyKernel) -> Result<String> {
        let path = self.kernel_config_path(kernel);
        if !Path::new(&path).exists() {
            return Err(Error::Config(format!("Config not found: {}", path)));
        }
        let content = fs::read_to_string(&path)?;
        Ok(content)
    }

    pub fn save_kernel_config(&self, kernel: ProxyKernel, content: &str) -> Result<()> {
        let path = self.kernel_config_path(kernel);
        fs::write(&path, content)?;
        restrict_permissions(&path);
        Ok(())
    }

    pub fn crash_dir(&self) -> &str {
        &self.crash_dir
    }
}

/// Configs carry subscription tokens and proxy passwords — keep them
/// owner-only even under a permissive umask.
#[cfg(unix)]
fn restrict_permissions(path: &str) {
    use std::os::unix::fs::PermissionsExt;
    if let Ok(meta) = fs::metadata(path) {
        let mut perms = meta.permissions();
        perms.set_mode(0o600);
        let _ = fs::set_permissions(path, perms);
    }
}

#[cfg(not(unix))]
fn restrict_permissions(_path: &str) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_config_paths_never_collide_with_management_config() {
        // Regression: the mihomo kernel config used to live at
        // {crash_dir}/config.yaml — the same path as the management config —
        // so generating a kernel config clobbered it.
        let platform = crate::platform::Platform::for_crash_dir("/tmp/rc-test");
        let cm = ConfigManager::new(&platform);
        assert_eq!(cm.config_path(), "/tmp/rc-test/config.yaml");
        assert_eq!(
            cm.kernel_config_path(ProxyKernel::Mihomo),
            "/tmp/rc-test/configs/mihomo.yaml"
        );
        assert_eq!(
            cm.kernel_config_path(ProxyKernel::SingBox),
            "/tmp/rc-test/configs/sing-box.json"
        );
        assert_ne!(cm.config_path(), cm.kernel_config_path(ProxyKernel::Mihomo));
    }

    #[test]
    fn test_config_variant_rule_count() {
        assert_eq!(ConfigVariant::Full.rule_count(), 18);
        assert_eq!(ConfigVariant::FullNoAds.rule_count(), 17);
        assert_eq!(ConfigVariant::Lite.rule_count(), 13);
        assert_eq!(ConfigVariant::LiteNoAds.rule_count(), 12);
        assert_eq!(ConfigVariant::Light.rule_count(), 7);
        assert_eq!(ConfigVariant::Nano.rule_count(), 3);
    }

    #[test]
    fn test_config_variant_ads_block() {
        assert!(ConfigVariant::Full.has_ads_block());
        assert!(!ConfigVariant::FullNoAds.has_ads_block());
        assert!(ConfigVariant::Lite.has_ads_block());
        assert!(!ConfigVariant::LiteNoAds.has_ads_block());
        assert!(!ConfigVariant::Light.has_ads_block());
        assert!(!ConfigVariant::Nano.has_ads_block());
    }

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.kernel, "mihomo");
        assert_eq!(config.proxy_port, 7890);
        assert_eq!(config.dns_port, 7892);
        assert!(config.auto_update);
        assert_eq!(config.update_interval, "24h");
    }

    #[test]
    fn test_config_serialize_deserialize() {
        let config = Config::default();
        let yaml = serde_yaml::to_string(&config).unwrap();
        let parsed: Config = serde_yaml::from_str(&yaml).unwrap();
        assert_eq!(parsed.kernel, config.kernel);
        assert_eq!(parsed.proxy_port, config.proxy_port);
    }

    #[test]
    fn test_subscription_serialize() {
        let sub = Subscription {
            name: "test".to_string(),
            url: "https://example.com/sub".to_string(),
            updated_at: Some(1234567890),
            raw_config: Some("proxies: []".to_string()),
        };
        let yaml = serde_yaml::to_string(&sub).unwrap();
        assert!(yaml.contains("test"));
        assert!(yaml.contains("example.com"));
    }

    #[test]
    fn test_config_firewall_fields_default() {
        let config = Config::default();
        assert!(!config.tun_enabled);
        assert!(!config.ipv6_enabled);
        assert!(!config.ipv6_redir);
        assert!(!config.vm_redir);
        assert!(!config.quic_reject);
        assert!(config.common_ports.is_empty());
        assert!(config.macfilter_addrs.is_empty());
        assert!(config.vm_ipv4.is_none());
        assert!(config.macfilter_type.is_none());
        assert!(config.ip_filter.is_none());
        assert!(!config.cn_ip_route);
    }

    #[test]
    fn test_config_to_firewall_config() {
        let config = Config {
            tun_enabled: true,
            tun_port: Some(7890),
            ipv6_enabled: true,
            quic_reject: true,
            common_ports: vec![80, 443, 8080],
            ..Default::default()
        };

        let fw_config = config.to_firewall_config().unwrap();
        assert_eq!(fw_config.tun_port, Some(7890));
        assert!(fw_config.ipv6_enabled);
        assert!(fw_config.quic_reject);
        assert_eq!(fw_config.common_ports, vec![80, 443, 8080]);
    }

    #[test]
    fn test_config_macfilter_conversion() {
        let config = Config {
            macfilter_type: Some("whitelist".to_string()),
            macfilter_addrs: vec!["aa:bb:cc:dd:ee:ff".to_string()],
            ..Default::default()
        };

        let fw_config = config.to_firewall_config().unwrap();
        assert!(matches!(
            fw_config.macfilter_type,
            Some(crate::firewall::MacFilterType::Whitelist)
        ));
    }
}
