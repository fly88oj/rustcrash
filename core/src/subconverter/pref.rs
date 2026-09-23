//! External configuration system (pref.ini profiles)
//!
//! Provides profile-based configuration management similar to subconverter's pref.ini.
//! Supports loading/saving user preferences and named conversion profiles.

use crate::error::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::path::Path;

/// Preference/Profile entry
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PrefEntry {
    /// Profile name (used as key)
    pub name: String,
    /// Default target format for this profile
    pub target: Option<String>,
    /// Include regex pattern
    pub include: Option<String>,
    /// Exclude regex pattern
    pub exclude: Option<String>,
    /// Rename rules
    pub rename: Option<String>,
    /// Enable emoji
    pub emoji: Option<bool>,
    /// Remove emoji
    pub remove_emoji: Option<bool>,
    /// Sort nodes
    pub sort: Option<bool>,
    /// Append type prefix
    pub append_type: Option<bool>,
    /// New name format
    pub new_name: Option<bool>,
    /// Append server:port info
    pub append_info: Option<bool>,
    /// Filter unsupported types
    pub fdn: Option<bool>,
    /// Expand rules
    pub expand: Option<bool>,
    /// Use classic rule providers
    pub classic: Option<bool>,
    /// TCP Fast Open
    pub tfo: Option<bool>,
    /// UDP support
    pub udp: Option<bool>,
    /// Skip TLS verification
    pub scv: Option<bool>,
    /// TLS 1.3
    pub tls13: Option<bool>,
    /// Rule provider template name
    pub rule_provider: Option<String>,
    /// Custom notes
    pub notes: Option<String>,
}

/// Global preferences section
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GlobalPrefs {
    /// Default target format
    pub default_target: Option<String>,
    /// Default emoji setting
    pub emoji: Option<bool>,
    /// Default remove_emoji
    pub remove_emoji: Option<bool>,
    /// Default sort setting
    pub sort: Option<bool>,
    /// Default rule provider template
    pub rule_provider: Option<String>,
    /// Display name format
    pub display_name: Option<String>,
    /// Whether to use surge property
    pub surge_property: Option<bool>,
    /// Whether to enable UDP
    pub udp: Option<bool>,
    /// Whether to enable TFO
    pub tfo: Option<bool>,
    /// Whether to skip TLS verification
    pub scv: Option<bool>,
    /// Whether to enable TLS 1.3
    pub tls13: Option<bool>,
}

impl Default for GlobalPrefs {
    fn default() -> Self {
        Self {
            default_target: Some("clash".to_string()),
            emoji: Some(true),
            remove_emoji: None,
            sort: Some(false),
            rule_provider: Some("default".to_string()),
            display_name: None,
            surge_property: Some(false),
            udp: Some(true),
            tfo: Some(false),
            scv: Some(false),
            tls13: Some(false),
        }
    }
}

/// Complete pref.ini structure
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PrefIni {
    /// Global preferences
    pub global: GlobalPrefs,
    /// Named profiles
    pub profiles: HashMap<String, PrefEntry>,
    /// Custom emoji rules
    pub emoji_rules: Option<HashMap<String, String>>,
    /// Custom rename rules
    pub rename_rules: Option<HashMap<String, String>>,
}

impl PrefIni {
    /// Create a new empty pref.ini
    pub fn new() -> Self {
        Self::default()
    }

    /// Load pref.ini from file
    pub fn load(path: &Path) -> Result<Self> {
        if !path.exists() {
            return Ok(Self::default());
        }

        let content = fs::read_to_string(path)?;
        Self::parse(&content)
    }

    /// Save pref.ini to file
    pub fn save(&self, path: &Path) -> Result<()> {
        let content = self.to_string();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(path, content)?;
        Ok(())
    }

    /// Parse pref.ini from string content
    pub fn parse(content: &str) -> Result<Self> {
        let mut pref = Self::default();
        let mut current_section = String::new();
        let mut current_profile_name: Option<String> = None;
        let mut current_profile: Option<PrefEntry> = None;

        for line in content.lines() {
            let line = line.trim();

            // Skip empty lines and comments
            if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                continue;
            }

            // Section header
            if line.starts_with('[') && line.ends_with(']') {
                // Save previous profile if any
                if let Some(name) = current_profile_name.take() {
                    if let Some(mut p) = current_profile.take() {
                        p.name = name.clone();
                        pref.profiles.insert(name, p);
                    }
                }

                let section = &line[1..line.len() - 1];

                match section {
                    "global" => {
                        current_section = "global".to_string();
                    }
                    s if s.starts_with("profile.") => {
                        let profile_name = s.trim_start_matches("profile.");
                        current_section = profile_name.to_string();
                        current_profile_name = Some(profile_name.to_string());
                        current_profile = Some(PrefEntry::default());
                    }
                    "emoji" => {
                        current_section = "emoji".to_string();
                    }
                    "rename" => {
                        current_section = "rename".to_string();
                    }
                    _ => {
                        current_section = String::new();
                    }
                }
                continue;
            }

            // Parse key=value
            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();

                match current_section.as_str() {
                    "global" => {
                        Self::apply_global(&mut pref.global, key, value);
                    }
                    s if pref.profiles.contains_key(s) || current_profile.is_some() => {
                        if let Some(ref mut profile) = current_profile {
                            Self::apply_profile(profile, key, value);
                        }
                    }
                    "emoji" => {
                        if pref.emoji_rules.is_none() {
                            pref.emoji_rules = Some(HashMap::new());
                        }
                        if let Some(ref mut rules) = pref.emoji_rules {
                            rules.insert(key.to_string(), value.to_string());
                        }
                    }
                    "rename" => {
                        if pref.rename_rules.is_none() {
                            pref.rename_rules = Some(HashMap::new());
                        }
                        if let Some(ref mut rules) = pref.rename_rules {
                            rules.insert(key.to_string(), value.to_string());
                        }
                    }
                    _ => {}
                }
            }
        }

        // Save last profile
        if let Some(name) = current_profile_name {
            if let Some(mut p) = current_profile.take() {
                p.name = name.clone();
                pref.profiles.insert(name, p);
            }
        }

        Ok(pref)
    }

    fn apply_global(global: &mut GlobalPrefs, key: &str, value: &str) {
        match key {
            "default_target" => global.default_target = Some(value.to_string()),
            "emoji" => global.emoji = Some(Self::parse_bool(value)),
            "remove_emoji" => global.remove_emoji = Some(Self::parse_bool(value)),
            "sort" => global.sort = Some(Self::parse_bool(value)),
            "rule_provider" => global.rule_provider = Some(value.to_string()),
            "display_name" => global.display_name = Some(value.to_string()),
            "surge_property" => global.surge_property = Some(Self::parse_bool(value)),
            "udp" => global.udp = Some(Self::parse_bool(value)),
            "tfo" => global.tfo = Some(Self::parse_bool(value)),
            "scv" => global.scv = Some(Self::parse_bool(value)),
            "tls13" => global.tls13 = Some(Self::parse_bool(value)),
            _ => {}
        }
    }

    fn apply_profile(profile: &mut PrefEntry, key: &str, value: &str) {
        match key {
            "target" => profile.target = Some(value.to_string()),
            "include" => profile.include = Some(value.to_string()),
            "exclude" => profile.exclude = Some(value.to_string()),
            "rename" => profile.rename = Some(value.to_string()),
            "emoji" => profile.emoji = Some(Self::parse_bool(value)),
            "remove_emoji" => profile.remove_emoji = Some(Self::parse_bool(value)),
            "sort" => profile.sort = Some(Self::parse_bool(value)),
            "append_type" => profile.append_type = Some(Self::parse_bool(value)),
            "new_name" => profile.new_name = Some(Self::parse_bool(value)),
            "append_info" => profile.append_info = Some(Self::parse_bool(value)),
            "fdn" => profile.fdn = Some(Self::parse_bool(value)),
            "expand" => profile.expand = Some(Self::parse_bool(value)),
            "classic" => profile.classic = Some(Self::parse_bool(value)),
            "tfo" => profile.tfo = Some(Self::parse_bool(value)),
            "udp" => profile.udp = Some(Self::parse_bool(value)),
            "scv" => profile.scv = Some(Self::parse_bool(value)),
            "tls13" => profile.tls13 = Some(Self::parse_bool(value)),
            "rule_provider" => profile.rule_provider = Some(value.to_string()),
            "notes" => profile.notes = Some(value.to_string()),
            _ => {}
        }
    }

    fn parse_bool(value: &str) -> bool {
        let lower = value.to_lowercase();
        lower == "true" || lower == "1" || lower == "yes" || lower == "on" || lower == "enabled"
    }
}

/// INI text is the canonical Display form of a PrefIni (to_string comes from the trait).
impl std::fmt::Display for PrefIni {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut output = String::new();

        // Global section
        output.push_str("[global]\n");
        if let Some(ref v) = self.global.default_target {
            output.push_str(&format!("default_target={}\n", v));
        }
        if let Some(v) = self.global.emoji {
            output.push_str(&format!("emoji={}\n", v));
        }
        if let Some(v) = self.global.remove_emoji {
            output.push_str(&format!("remove_emoji={}\n", v));
        }
        if let Some(v) = self.global.sort {
            output.push_str(&format!("sort={}\n", v));
        }
        if let Some(ref v) = self.global.rule_provider {
            output.push_str(&format!("rule_provider={}\n", v));
        }
        if let Some(ref v) = self.global.display_name {
            output.push_str(&format!("display_name={}\n", v));
        }
        if let Some(v) = self.global.surge_property {
            output.push_str(&format!("surge_property={}\n", v));
        }
        if let Some(v) = self.global.udp {
            output.push_str(&format!("udp={}\n", v));
        }
        if let Some(v) = self.global.tfo {
            output.push_str(&format!("tfo={}\n", v));
        }
        if let Some(v) = self.global.scv {
            output.push_str(&format!("scv={}\n", v));
        }
        if let Some(v) = self.global.tls13 {
            output.push_str(&format!("tls13={}\n", v));
        }

        // Emoji rules section
        if let Some(ref rules) = self.emoji_rules {
            if !rules.is_empty() {
                output.push_str("\n[emoji]\n");
                for (k, v) in rules {
                    output.push_str(&format!("{}={}\n", k, v));
                }
            }
        }

        // Rename rules section
        if let Some(ref rules) = self.rename_rules {
            if !rules.is_empty() {
                output.push_str("\n[rename]\n");
                for (k, v) in rules {
                    output.push_str(&format!("{}={}\n", k, v));
                }
            }
        }

        // Profile sections
        for (name, profile) in &self.profiles {
            output.push_str(&format!("\n[profile.{name}]\n"));
            if let Some(ref v) = profile.target {
                output.push_str(&format!("target={}\n", v));
            }
            if let Some(ref v) = profile.include {
                output.push_str(&format!("include={}\n", v));
            }
            if let Some(ref v) = profile.exclude {
                output.push_str(&format!("exclude={}\n", v));
            }
            if let Some(ref v) = profile.rename {
                output.push_str(&format!("rename={}\n", v));
            }
            if let Some(v) = profile.emoji {
                output.push_str(&format!("emoji={}\n", v));
            }
            if let Some(v) = profile.remove_emoji {
                output.push_str(&format!("remove_emoji={}\n", v));
            }
            if let Some(v) = profile.sort {
                output.push_str(&format!("sort={}\n", v));
            }
            if let Some(v) = profile.append_type {
                output.push_str(&format!("append_type={}\n", v));
            }
            if let Some(v) = profile.new_name {
                output.push_str(&format!("new_name={}\n", v));
            }
            if let Some(v) = profile.append_info {
                output.push_str(&format!("append_info={}\n", v));
            }
            if let Some(v) = profile.fdn {
                output.push_str(&format!("fdn={}\n", v));
            }
            if let Some(v) = profile.expand {
                output.push_str(&format!("expand={}\n", v));
            }
            if let Some(v) = profile.classic {
                output.push_str(&format!("classic={}\n", v));
            }
            if let Some(v) = profile.tfo {
                output.push_str(&format!("tfo={}\n", v));
            }
            if let Some(v) = profile.udp {
                output.push_str(&format!("udp={}\n", v));
            }
            if let Some(v) = profile.scv {
                output.push_str(&format!("scv={}\n", v));
            }
            if let Some(v) = profile.tls13 {
                output.push_str(&format!("tls13={}\n", v));
            }
            if let Some(ref v) = profile.rule_provider {
                output.push_str(&format!("rule_provider={}\n", v));
            }
            if let Some(ref v) = profile.notes {
                output.push_str(&format!("notes={}\n", v));
            }
        }

        f.write_str(&output)
    }
}

impl PrefIni {
    /// Get a profile by name
    pub fn get_profile(&self, name: &str) -> Option<&PrefEntry> {
        self.profiles.get(name)
    }

    /// Add or update a profile
    pub fn set_profile(&mut self, name: &str, profile: PrefEntry) {
        self.profiles.insert(name.to_string(), profile);
    }

    /// Remove a profile
    pub fn remove_profile(&mut self, name: &str) -> bool {
        self.profiles.remove(name).is_some()
    }

    /// List all profile names
    pub fn profile_names(&self) -> Vec<&String> {
        self.profiles.keys().collect()
    }

    /// Create a profile with default settings
    pub fn create_profile(name: &str) -> PrefEntry {
        PrefEntry {
            name: name.to_string(),
            ..Default::default()
        }
    }

    /// Generate default pref.ini content
    pub fn generate_default() -> String {
        let default = Self::default();
        default.to_string()
    }
}

impl PrefEntry {
    /// Create a new empty profile entry
    pub fn new() -> Self {
        Self {
            name: String::new(),
            target: None,
            include: None,
            exclude: None,
            rename: None,
            emoji: None,
            remove_emoji: None,
            sort: None,
            append_type: None,
            new_name: None,
            append_info: None,
            fdn: None,
            expand: None,
            classic: None,
            tfo: None,
            udp: None,
            scv: None,
            tls13: None,
            rule_provider: None,
            notes: None,
        }
    }

    /// Create a profile with a name
    pub fn with_name(name: &str) -> Self {
        let mut profile = Self::new();
        profile.name = name.to_string();
        profile
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_empty() {
        let pref = PrefIni::parse("").unwrap();
        assert!(pref.global.default_target.is_some());
        assert!(pref.profiles.is_empty());
    }

    #[test]
    fn test_parse_global() {
        let content = r#"
[global]
default_target=clash
emoji=true
remove_emoji=false
sort=false
rule_provider=default
"#;
        let pref = PrefIni::parse(content).unwrap();
        assert_eq!(pref.global.default_target, Some("clash".to_string()));
        assert_eq!(pref.global.emoji, Some(true));
        assert_eq!(pref.global.remove_emoji, Some(false));
    }

    #[test]
    fn test_parse_profile() {
        let content = r#"
[profile.myprofile]
target=singbox
exclude=流量
emoji=true
sort=true
"#;
        let pref = PrefIni::parse(content).unwrap();
        let profile = pref.get_profile("myprofile").unwrap();
        assert_eq!(profile.target, Some("singbox".to_string()));
        assert_eq!(profile.exclude, Some("流量".to_string()));
        assert_eq!(profile.emoji, Some(true));
        assert_eq!(profile.sort, Some(true));
    }

    #[test]
    fn test_parse_emoji_rules() {
        let content = r#"
[emoji]
美国=🇺🇸
日本=🇯🇵
香港=🇭🇰
"#;
        let pref = PrefIni::parse(content).unwrap();
        let rules = pref.emoji_rules.unwrap();
        assert_eq!(rules.get("美国"), Some(&"🇺🇸".to_string()));
        assert_eq!(rules.get("日本"), Some(&"🇯🇵".to_string()));
    }

    #[test]
    fn test_to_string() {
        let pref = PrefIni::default();
        let output = pref.to_string();
        assert!(output.contains("[global]"));
    }

    #[test]
    fn test_roundtrip() {
        let content = r#"
[global]
default_target=clash
emoji=true

[profile.myprofile]
target=singbox
exclude=流量
emoji=true

[emoji]
美国=🇺🇸
"#;
        let pref = PrefIni::parse(content).unwrap();
        let output = pref.to_string();
        let reparsed = PrefIni::parse(&output).unwrap();
        assert_eq!(reparsed.global.default_target, Some("clash".to_string()));
        assert_eq!(
            reparsed.get_profile("myprofile").unwrap().target,
            Some("singbox".to_string())
        );
    }

    #[test]
    fn test_bool_parsing() {
        assert!(PrefIni::parse_bool("true"));
        assert!(PrefIni::parse_bool("True"));
        assert!(PrefIni::parse_bool("TRUE"));
        assert!(PrefIni::parse_bool("1"));
        assert!(PrefIni::parse_bool("yes"));
        assert!(PrefIni::parse_bool("on"));
        assert!(PrefIni::parse_bool("enabled"));
        assert!(!PrefIni::parse_bool("false"));
        assert!(!PrefIni::parse_bool("0"));
        assert!(!PrefIni::parse_bool("no"));
    }

    #[test]
    fn test_profile_crud() {
        let mut pref = PrefIni::new();
        assert!(pref.get_profile("test").is_none());

        let profile = PrefEntry::with_name("test");
        pref.set_profile("test", profile);
        assert!(pref.get_profile("test").is_some());

        assert!(pref.remove_profile("test"));
        assert!(pref.get_profile("test").is_none());
    }

    #[test]
    fn test_generate_default() {
        let default = PrefIni::generate_default();
        assert!(default.contains("[global]"));
        assert!(default.contains("default_target=clash"));
    }
}
