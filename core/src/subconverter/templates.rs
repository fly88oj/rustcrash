//! Rule-base templates for Clash/SingBox configuration generation
//!
//! Provides predefined rule templates that can be used when generating
//! Clash rule-providers or SingBox routing rules.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Rule type for matching
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleType {
    /// Domain matching
    Domain,
    /// Domain suffix matching
    DomainSuffix,
    /// Domain keyword matching
    DomainKeyword,
    /// IP-CIDR matching
    IpCidr,
    /// IP-CIDR6 matching
    IpCidr6,
    /// GEOIP matching
    GeoIp,
    /// Process matching (not widely supported)
    Process,
    /// Rule-set (Clash rule-provider)
    RuleSet,
    /// URL-ismatch (HTTP(S) path matching)
    UrlMatch,
    /// Rule-set with behavior hint
    RuleSetDomain,
    RuleSetIpCidr,
    RuleSetClassical,
}

/// Rule action
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum RuleAction {
    /// Direct connection
    Direct,
    /// Proxy connection
    Proxy,
    /// Reject connection
    Reject,
    /// Use proxy group by name
    ProxyGroup(String),
}

impl RuleAction {
    /// Convert to string representation
    pub fn as_str(&self) -> &'static str {
        match self {
            RuleAction::Direct => "DIRECT",
            RuleAction::Proxy => "Proxy",
            RuleAction::Reject => "REJECT",
            RuleAction::ProxyGroup(_) => "Proxy",
        }
    }
}

/// Single rule entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleEntry {
    /// Rule type
    pub rule_type: RuleType,
    /// Pattern to match
    pub pattern: String,
    /// Action to take
    pub action: RuleAction,
    /// Optional comment/description
    pub comment: Option<String>,
}

impl RuleEntry {
    /// Create a domain rule
    pub fn domain(domain: &str, action: RuleAction) -> Self {
        Self {
            rule_type: RuleType::Domain,
            pattern: domain.to_string(),
            action,
            comment: None,
        }
    }

    /// Create a domain suffix rule
    pub fn domain_suffix(suffix: &str, action: RuleAction) -> Self {
        Self {
            rule_type: RuleType::DomainSuffix,
            pattern: suffix.to_string(),
            action,
            comment: None,
        }
    }

    /// Create a domain keyword rule
    pub fn domain_keyword(keyword: &str, action: RuleAction) -> Self {
        Self {
            rule_type: RuleType::DomainKeyword,
            pattern: keyword.to_string(),
            action,
            comment: None,
        }
    }

    /// Create an IP-CIDR rule
    pub fn ip_cidr(cidr: &str, action: RuleAction) -> Self {
        Self {
            rule_type: RuleType::IpCidr,
            pattern: cidr.to_string(),
            action,
            comment: None,
        }
    }

    /// Create a GEOIP rule
    pub fn geoip(code: &str, action: RuleAction) -> Self {
        Self {
            rule_type: RuleType::GeoIp,
            pattern: code.to_string(),
            action,
            comment: None,
        }
    }

    /// Create a rule-set rule
    pub fn ruleset(provider: &str, action: RuleAction) -> Self {
        Self {
            rule_type: RuleType::RuleSet,
            pattern: provider.to_string(),
            action,
            comment: None,
        }
    }

    /// Add a comment
    pub fn with_comment(mut self, comment: &str) -> Self {
        self.comment = Some(comment.to_string());
        self
    }
}

/// Rule provider definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleProviderDef {
    /// Provider name
    pub name: String,
    /// Behavior type
    pub behavior: ProviderBehavior,
    /// Provider type (file or http)
    pub provider_type: String,
    /// Path or URL
    pub path: String,
    /// Update interval in seconds
    pub interval: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProviderBehavior {
    Domain,
    IpCidr,
    Classical,
}

impl ProviderBehavior {
    pub fn as_str(&self) -> &'static str {
        match self {
            ProviderBehavior::Domain => "domain",
            ProviderBehavior::IpCidr => "ipcidr",
            ProviderBehavior::Classical => "classical",
        }
    }
}

/// Rule template with a name and rule list
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuleTemplate {
    /// Template name
    pub name: String,
    /// Template description
    pub description: String,
    /// Rules in this template
    pub rules: Vec<RuleEntry>,
    /// Rule providers (for modern style)
    pub rule_providers: Vec<RuleProviderDef>,
    /// Whether this is a classic (non-provider) template
    pub is_classic: bool,
}

impl RuleTemplate {
    /// Generate Clash rules YAML
    pub fn to_clash_yaml(&self, use_providers: bool) -> String {
        let mut output = String::new();

        if use_providers && !self.rule_providers.is_empty() {
            // Generate rule-providers section
            output.push_str("rule-providers:\n");
            for provider in &self.rule_providers {
                output.push_str(&format!("  {}:\n", provider.name));
                output.push_str(&format!("    type: {}\n", provider.provider_type));
                output.push_str(&format!("    behavior: {}\n", provider.behavior.as_str()));
                output.push_str(&format!(
                    "    path: ./ruleset/{}.{}\n",
                    provider.name,
                    provider.behavior.as_str()
                ));
                output.push_str(&format!("    interval: {}\n", provider.interval));
                output.push('\n');
            }
            output.push('\n');
        }

        // Generate rules section
        output.push_str("rules:\n");
        for rule in &self.rules {
            let line = rule.to_clash_line(use_providers);
            if let Some(ref comment) = rule.comment {
                output.push_str(&format!("  # {}\n", comment));
            }
            output.push_str(&format!("  - {}\n", line));
        }

        output
    }

    /// Generate classical (inline) Clash rules
    pub fn to_classic_yaml(&self) -> String {
        let mut output = String::from("rules:\n");
        for rule in &self.rules {
            // Skip rule-set rules in classic mode
            if rule.rule_type == RuleType::RuleSet
                || rule.rule_type == RuleType::RuleSetDomain
                || rule.rule_type == RuleType::RuleSetIpCidr
            {
                continue;
            }
            let line = rule.to_classic_line();
            if let Some(ref comment) = rule.comment {
                output.push_str(&format!("  # {}\n", comment));
            }
            output.push_str(&format!("  - {}\n", line));
        }
        output
    }
}

impl RuleEntry {
    /// Convert to Clash rule line
    fn to_clash_line(&self, use_providers: bool) -> String {
        match self.rule_type {
            RuleType::Domain => format!("DOMAIN,{},{}", self.pattern, self.action.as_str()),
            RuleType::DomainSuffix => {
                format!("DOMAIN-SUFFIX,{},{}", self.pattern, self.action.as_str())
            }
            RuleType::DomainKeyword => {
                format!("DOMAIN-KEYWORD,{},{}", self.pattern, self.action.as_str())
            }
            RuleType::IpCidr => format!("IP-CIDR,{},{}", self.pattern, self.action.as_str()),
            RuleType::IpCidr6 => format!("IP-CIDR6,{},{}", self.pattern, self.action.as_str()),
            RuleType::GeoIp => format!("GEOIP,{},{}", self.pattern, self.action.as_str()),
            RuleType::Process => format!("PROCESS-NAME,{},{}", self.pattern, self.action.as_str()),
            RuleType::RuleSet
            | RuleType::RuleSetDomain
            | RuleType::RuleSetIpCidr
            | RuleType::RuleSetClassical => {
                if use_providers {
                    format!("RULE-SET,{},{}", self.pattern, self.action.as_str())
                } else {
                    // Skip rule-set if providers not used
                    format!("DOMAIN-SUFFIX,{},{}", self.pattern, self.action.as_str())
                }
            }
            RuleType::UrlMatch => format!("URL-REGEX,{},{}", self.pattern, self.action.as_str()),
        }
    }

    /// Convert to classic Clash rule line (no providers)
    fn to_classic_line(&self) -> String {
        match self.rule_type {
            RuleType::Domain => format!("DOMAIN,{},{}", self.pattern, self.action.as_str()),
            RuleType::DomainSuffix => {
                format!("DOMAIN-SUFFIX,{},{}", self.pattern, self.action.as_str())
            }
            RuleType::DomainKeyword => {
                format!("DOMAIN-KEYWORD,{},{}", self.pattern, self.action.as_str())
            }
            RuleType::IpCidr => format!("IP-CIDR,{},{}", self.pattern, self.action.as_str()),
            RuleType::IpCidr6 => format!("IP-CIDR6,{},{}", self.pattern, self.action.as_str()),
            RuleType::GeoIp => format!("GEOIP,{},{}", self.pattern, self.action.as_str()),
            RuleType::Process => format!("PROCESS-NAME,{},{}", self.pattern, self.action.as_str()),
            RuleType::RuleSet
            | RuleType::RuleSetDomain
            | RuleType::RuleSetIpCidr
            | RuleType::RuleSetClassical => {
                // Convert rule-set to actual rules for classic mode
                format!("DOMAIN-SUFFIX,{},{}", self.pattern, self.action.as_str())
            }
            RuleType::UrlMatch => format!("URL-REGEX,{},{}", self.pattern, self.action.as_str()),
        }
    }
}

/// Built-in rule templates
pub struct RuleTemplates;

impl RuleTemplates {
    /// Default template with basic rules
    pub fn default_template() -> RuleTemplate {
        RuleTemplate {
            name: "default".to_string(),
            description: "Default rule template with common rules".to_string(),
            rules: vec![
                // Localhost
                RuleEntry::ip_cidr("127.0.0.0/8", RuleAction::Direct).with_comment("Localhost"),
                RuleEntry::ip_cidr("::1/128", RuleAction::Direct).with_comment("IPv6 Localhost"),
                // LAN
                RuleEntry::ip_cidr("10.0.0.0/8", RuleAction::Direct).with_comment("Private LAN"),
                RuleEntry::ip_cidr("172.16.0.0/12", RuleAction::Direct),
                RuleEntry::ip_cidr("192.168.0.0/16", RuleAction::Direct),
                RuleEntry::ip_cidr("255.255.255.255/32", RuleAction::Direct),
                // China mainland
                RuleEntry::geoip("CN", RuleAction::Direct).with_comment("China Mainland"),
                // Final rule
                RuleEntry::domain_suffix("", RuleAction::Proxy),
            ],
            rule_providers: vec![
                RuleProviderDef {
                    name: "china".to_string(),
                    behavior: ProviderBehavior::Domain,
                    provider_type: "file".to_string(),
                    path: "./ruleset/china.domain".to_string(),
                    interval: 86400,
                },
                RuleProviderDef {
                    name: "cncidr".to_string(),
                    behavior: ProviderBehavior::IpCidr,
                    provider_type: "file".to_string(),
                    path: "./ruleset/cncidr.ipcidr".to_string(),
                    interval: 86400,
                },
            ],
            is_classic: false,
        }
    }

    /// Lite template - fewer rules for reduced overhead
    pub fn lite_template() -> RuleTemplate {
        RuleTemplate {
            name: "lite".to_string(),
            description: "Lite rule template with essential rules only".to_string(),
            rules: vec![
                RuleEntry::ip_cidr("127.0.0.0/8", RuleAction::Direct),
                RuleEntry::ip_cidr("10.0.0.0/8", RuleAction::Direct),
                RuleEntry::ip_cidr("172.16.0.0/12", RuleAction::Direct),
                RuleEntry::ip_cidr("192.168.0.0/16", RuleAction::Direct),
                RuleEntry::geoip("CN", RuleAction::Direct),
                RuleEntry::domain_suffix("", RuleAction::Proxy),
            ],
            rule_providers: vec![RuleProviderDef {
                name: "cncidr".to_string(),
                behavior: ProviderBehavior::IpCidr,
                provider_type: "file".to_string(),
                path: "./ruleset/cncidr.ipcidr".to_string(),
                interval: 86400,
            }],
            is_classic: false,
        }
    }

    /// Full template - comprehensive rules including ads blocking
    pub fn full_template() -> RuleTemplate {
        RuleTemplate {
            name: "full".to_string(),
            description: "Full rule template with ads blocking and comprehensive rules".to_string(),
            rules: vec![
                // Localhost
                RuleEntry::ip_cidr("127.0.0.0/8", RuleAction::Direct).with_comment("Localhost"),
                RuleEntry::ip_cidr("::1/128", RuleAction::Direct),
                // LAN
                RuleEntry::ip_cidr("10.0.0.0/8", RuleAction::Direct),
                RuleEntry::ip_cidr("172.16.0.0/12", RuleAction::Direct),
                RuleEntry::ip_cidr("192.168.0.0/16", RuleAction::Direct),
                // Ads domains
                RuleEntry::domain_suffix("adservice.google.com", RuleAction::Reject)
                    .with_comment("Google Ads"),
                RuleEntry::domain_suffix("ads.facebook.com", RuleAction::Reject),
                RuleEntry::domain_suffix("ads.twitter.com", RuleAction::Reject),
                RuleEntry::domain_keyword("ads", RuleAction::Reject).with_comment("General Ads"),
                RuleEntry::domain_keyword("tracking", RuleAction::Reject),
                // China
                RuleEntry::geoip("CN", RuleAction::Direct).with_comment("China Mainland"),
                RuleEntry::domain_suffix("", RuleAction::Proxy),
            ],
            rule_providers: vec![
                RuleProviderDef {
                    name: "china".to_string(),
                    behavior: ProviderBehavior::Domain,
                    provider_type: "file".to_string(),
                    path: "./ruleset/china.domain".to_string(),
                    interval: 86400,
                },
                RuleProviderDef {
                    name: "cncidr".to_string(),
                    behavior: ProviderBehavior::IpCidr,
                    provider_type: "file".to_string(),
                    path: "./ruleset/cncidr.ipcidr".to_string(),
                    interval: 86400,
                },
                RuleProviderDef {
                    name: "ads".to_string(),
                    behavior: ProviderBehavior::Domain,
                    provider_type: "file".to_string(),
                    path: "./ruleset/ads.domain".to_string(),
                    interval: 86400,
                },
            ],
            is_classic: false,
        }
    }

    /// Classical template (no rule providers)
    pub fn classical_template() -> RuleTemplate {
        RuleTemplate {
            name: "classical".to_string(),
            description: "Classical rule template without rule providers".to_string(),
            rules: vec![
                RuleEntry::ip_cidr("127.0.0.0/8", RuleAction::Direct),
                RuleEntry::ip_cidr("::1/128", RuleAction::Direct),
                RuleEntry::ip_cidr("10.0.0.0/8", RuleAction::Direct),
                RuleEntry::ip_cidr("172.16.0.0/12", RuleAction::Direct),
                RuleEntry::ip_cidr("192.168.0.0/16", RuleAction::Direct),
                RuleEntry::domain_suffix("cn", RuleAction::Direct).with_comment("China domains"),
                RuleEntry::domain_keyword("baidu", RuleAction::Direct),
                RuleEntry::domain_keyword("alibaba", RuleAction::Direct),
                RuleEntry::domain_keyword("tencent", RuleAction::Direct),
                RuleEntry::geoip("CN", RuleAction::Direct),
                RuleEntry::domain_suffix("", RuleAction::Proxy),
            ],
            rule_providers: vec![],
            is_classic: true,
        }
    }

    /// Gaming template - optimized for low latency
    pub fn gaming_template() -> RuleTemplate {
        RuleTemplate {
            name: "gaming".to_string(),
            description: "Gaming optimized template with minimal rules".to_string(),
            rules: vec![
                RuleEntry::ip_cidr("127.0.0.0/8", RuleAction::Direct),
                RuleEntry::ip_cidr("10.0.0.0/8", RuleAction::Direct),
                RuleEntry::ip_cidr("172.16.0.0/12", RuleAction::Direct),
                RuleEntry::ip_cidr("192.168.0.0/16", RuleAction::Direct),
                RuleEntry::ip_cidr("0.0.0.0/8", RuleAction::Direct),
                RuleEntry::geoip("CN", RuleAction::Direct).with_comment("China Game Servers"),
                // Game-related domains often use these
                RuleEntry::domain_suffix("battle.net", RuleAction::Proxy)
                    .with_comment("Battle.net"),
                RuleEntry::domain_suffix("steampowered.com", RuleAction::Proxy),
                RuleEntry::domain_suffix("riotgames.com", RuleAction::Proxy),
                RuleEntry::domain_suffix("nintendo.net", RuleAction::Proxy),
                RuleEntry::domain_suffix("", RuleAction::Proxy),
            ],
            rule_providers: vec![],
            is_classic: true,
        }
    }

    /// Streaming template - optimized for video streaming
    pub fn streaming_template() -> RuleTemplate {
        RuleTemplate {
            name: "streaming".to_string(),
            description: "Streaming optimized template".to_string(),
            rules: vec![
                RuleEntry::ip_cidr("127.0.0.0/8", RuleAction::Direct),
                RuleEntry::ip_cidr("10.0.0.0/8", RuleAction::Direct),
                RuleEntry::ip_cidr("172.16.0.0/12", RuleAction::Direct),
                RuleEntry::ip_cidr("192.168.0.0/16", RuleAction::Direct),
                RuleEntry::geoip("CN", RuleAction::Direct),
                // Streaming services
                RuleEntry::domain_suffix("netflix.com", RuleAction::Proxy).with_comment("Netflix"),
                RuleEntry::domain_suffix("nflxvideo.net", RuleAction::Proxy),
                RuleEntry::domain_suffix("youtube.com", RuleAction::Proxy).with_comment("YouTube"),
                RuleEntry::domain_suffix("googlevideo.com", RuleAction::Proxy),
                RuleEntry::domain_suffix("youtubeeducation.com", RuleAction::Proxy),
                RuleEntry::domain_suffix("twitch.tv", RuleAction::Proxy).with_comment("Twitch"),
                RuleEntry::domain_suffix("hbogo.com", RuleAction::Proxy).with_comment("HBO"),
                RuleEntry::domain_suffix("hbo.com", RuleAction::Proxy),
                RuleEntry::domain_suffix("disneyplus.com", RuleAction::Proxy)
                    .with_comment("Disney+"),
                RuleEntry::domain_suffix("disney-plus.net", RuleAction::Proxy),
                RuleEntry::domain_suffix("primevideo.com", RuleAction::Proxy)
                    .with_comment("Prime Video"),
                RuleEntry::domain_suffix("pbs.org", RuleAction::Proxy).with_comment("PBS"),
                RuleEntry::domain_suffix("spotify.com", RuleAction::Proxy).with_comment("Spotify"),
                RuleEntry::domain_suffix("scdn.co", RuleAction::Proxy),
                RuleEntry::domain_suffix("", RuleAction::Proxy),
            ],
            rule_providers: vec![],
            is_classic: true,
        }
    }

    /// Get all built-in templates
    pub fn all_templates() -> HashMap<String, RuleTemplate> {
        let mut templates = HashMap::new();
        templates.insert("default".to_string(), Self::default_template());
        templates.insert("lite".to_string(), Self::lite_template());
        templates.insert("full".to_string(), Self::full_template());
        templates.insert("classical".to_string(), Self::classical_template());
        templates.insert("gaming".to_string(), Self::gaming_template());
        templates.insert("streaming".to_string(), Self::streaming_template());
        templates
    }

    /// Get a template by name
    pub fn get(name: &str) -> Option<RuleTemplate> {
        match name.to_lowercase().as_str() {
            "default" => Some(Self::default_template()),
            "lite" => Some(Self::lite_template()),
            "full" => Some(Self::full_template()),
            "classical" => Some(Self::classical_template()),
            "gaming" => Some(Self::gaming_template()),
            "streaming" => Some(Self::streaming_template()),
            _ => None,
        }
    }

    /// List all available template names
    pub fn list_names() -> Vec<&'static str> {
        vec![
            "default",
            "lite",
            "full",
            "classical",
            "gaming",
            "streaming",
        ]
    }
}

/// Rule repository for loading custom templates
pub struct RuleRepository {
    templates: HashMap<String, RuleTemplate>,
}

impl RuleRepository {
    /// Create a new repository with built-in templates
    pub fn new() -> Self {
        Self {
            templates: RuleTemplates::all_templates(),
        }
    }

    /// Load a template from YAML content
    pub fn load_template(&mut self, name: &str, yaml: &str) -> std::result::Result<(), String> {
        let template: RuleTemplate = serde_yaml::from_str(yaml)
            .map_err(|e| format!("Failed to parse template YAML: {}", e))?;
        self.templates.insert(name.to_string(), template);
        Ok(())
    }

    /// Get a template by name
    pub fn get(&self, name: &str) -> Option<&RuleTemplate> {
        self.templates.get(name)
    }

    /// List all template names
    pub fn list(&self) -> Vec<&String> {
        self.templates.keys().collect()
    }

    /// Add a custom template
    pub fn add(&mut self, template: RuleTemplate) {
        self.templates.insert(template.name.clone(), template);
    }
}

impl Default for RuleRepository {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rule_entry_domain() {
        let rule = RuleEntry::domain("example.com", RuleAction::Direct);
        assert_eq!(rule.rule_type, RuleType::Domain);
        assert_eq!(rule.pattern, "example.com");
    }

    #[test]
    fn test_rule_entry_with_comment() {
        let rule =
            RuleEntry::domain("example.com", RuleAction::Direct).with_comment("Test comment");
        assert_eq!(rule.comment, Some("Test comment".to_string()));
    }

    #[test]
    fn test_default_template() {
        let template = RuleTemplates::default_template();
        assert_eq!(template.name, "default");
        assert!(!template.rules.is_empty());
    }

    #[test]
    fn test_template_to_yaml() {
        let template = RuleTemplates::default_template();
        let yaml = template.to_clash_yaml(true);
        assert!(yaml.contains("rules:"));
        assert!(yaml.contains("rule-providers:"));
    }

    #[test]
    fn test_classic_template_to_yaml() {
        let template = RuleTemplates::classical_template();
        let yaml = template.to_classic_yaml();
        assert!(yaml.contains("rules:"));
        assert!(!yaml.contains("rule-providers:"));
    }

    #[test]
    fn test_all_templates() {
        let templates = RuleTemplates::all_templates();
        assert!(templates.len() >= 6);
    }

    #[test]
    fn test_get_template() {
        assert!(RuleTemplates::get("default").is_some());
        assert!(RuleTemplates::get("lite").is_some());
        assert!(RuleTemplates::get("full").is_some());
        assert!(RuleTemplates::get("unknown").is_none());
    }

    #[test]
    fn test_list_template_names() {
        let names = RuleTemplates::list_names();
        assert!(names.contains(&"default"));
        assert!(names.contains(&"lite"));
    }

    #[test]
    fn test_repository() {
        let repo = RuleRepository::new();
        assert!(repo.get("default").is_some());
        assert_eq!(repo.list().len(), 6);
    }

    #[test]
    fn test_repository_add() {
        let mut repo = RuleRepository::new();
        let custom = RuleTemplate {
            name: "custom".to_string(),
            description: "Custom template".to_string(),
            rules: vec![RuleEntry::domain("custom.com", RuleAction::Direct)],
            rule_providers: vec![],
            is_classic: true,
        };
        repo.add(custom);
        assert!(repo.get("custom").is_some());
    }

    #[test]
    fn test_rule_provider_def() {
        let provider = RuleProviderDef {
            name: "test".to_string(),
            behavior: ProviderBehavior::Domain,
            provider_type: "file".to_string(),
            path: "./ruleset/test.domain".to_string(),
            interval: 86400,
        };
        assert_eq!(provider.behavior.as_str(), "domain");
    }

    #[test]
    fn test_geoip_rule() {
        let rule = RuleEntry::geoip("CN", RuleAction::Direct);
        assert_eq!(rule.rule_type, RuleType::GeoIp);
    }

    #[test]
    fn test_ruleset_rule() {
        let rule = RuleEntry::ruleset("china", RuleAction::Direct);
        assert_eq!(rule.rule_type, RuleType::RuleSet);
    }
}
