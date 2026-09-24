//! Configuration validation module for RustCrash
//!
//! Provides comprehensive validation for:
//! - Port ranges
//! - Required fields
//! - YAML/JSON syntax
//! - Subscription URIs
//! - Rule syntax
//! - Backend compatibility

use crate::config::Config;
use crate::error::{Error, Result};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;

pub const MIN_PORT: u16 = 1;
pub const MAX_PORT: u16 = 65535;

/// Validation error severity
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ErrorSeverity {
    Error,
    Warning,
    Info,
}

/// Validation error
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationError {
    pub field: String,
    pub message: String,
    pub severity: ErrorSeverity,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[{:?}] {}: {}", self.severity, self.field, self.message)
    }
}

/// Validation result
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub errors: Vec<ValidationError>,
    pub warnings: Vec<String>,
}

impl ValidationResult {
    pub fn new() -> Self {
        Self {
            is_valid: true,
            errors: Vec::new(),
            warnings: Vec::new(),
        }
    }

    pub fn add_error(&mut self, field: impl Into<String>, message: impl Into<String>) {
        self.errors.push(ValidationError {
            field: field.into(),
            message: message.into(),
            severity: ErrorSeverity::Error,
        });
        self.is_valid = false;
    }

    pub fn add_warning(&mut self, message: impl Into<String>) {
        self.warnings.push(message.into());
    }

    pub fn merge(&mut self, other: ValidationResult) {
        self.errors.extend(other.errors);
        self.warnings.extend(other.warnings);
        if !other.is_valid {
            self.is_valid = false;
        }
    }
}

/// Configuration validator
#[derive(Debug, Clone)]
pub struct ConfigValidator {
    strict: bool,
}

impl ConfigValidator {
    pub fn new(strict: bool) -> Self {
        Self { strict }
    }

    pub fn validate(&self, config: &Config) -> ValidationResult {
        let mut result = ValidationResult::new();

        self.validate_ports(config, &mut result);
        self.validate_required_fields(config, &mut result);
        self.validate_kernel(config, &mut result);
        self.validate_mode(config, &mut result);
        self.validate_dns_mode(config, &mut result);
        self.validate_ports_available(config, &mut result);

        if self.strict {
            self.validate_advanced(config, &mut result);
        }

        if result.errors.is_empty() {
            result.is_valid = true;
        }

        result
    }

    fn validate_ports(&self, config: &Config, result: &mut ValidationResult) {
        if config.proxy_port < MIN_PORT {
            result.add_error("proxy_port", format!("Port must be at least {}", MIN_PORT));
        }

        if config.dns_port < MIN_PORT {
            result.add_error("dns_port", format!("Port must be at least {}", MIN_PORT));
        }

        if let Some(mixed_port) = config.mixed_port {
            if mixed_port < MIN_PORT {
                result.add_error("mixed_port", format!("Port must be at least {}", MIN_PORT));
            }
        }

        if let Some(tun_port) = config.tun_port {
            if tun_port < MIN_PORT {
                result.add_error("tun_port", format!("Port must be at least {}", MIN_PORT));
            }
        }

        if config.dashboard_port < MIN_PORT {
            result.add_error(
                "dashboard_port",
                format!("Port must be at least {}", MIN_PORT),
            );
        }
    }

    fn validate_ports_available(&self, config: &Config, result: &mut ValidationResult) {
        if config.proxy_port == config.dns_port {
            result.add_error("proxy_port", "Proxy port conflicts with DNS port");
        }

        if config.proxy_port == config.dashboard_port {
            result.add_error("proxy_port", "Proxy port conflicts with dashboard port");
        }

        if Some(config.proxy_port) == config.mixed_port {
            result.add_error("mixed_port", "Mixed port conflicts with proxy port");
        }

        // The manager API and the kernel's external-controller both bind
        // loopback; an equal pair fails at runtime, silently.
        if config.api_enabled && config.api_port == config.dashboard_port {
            result.add_error(
                "api_port",
                "REST API port conflicts with dashboard (external-controller) port",
            );
        }

        // Port ceilings: derived listeners (proxy+1/+2) must stay in range.
        if config.proxy_port > 65533 {
            result.add_error(
                "proxy_port",
                "Proxy port must be <= 65533 (leaves room for the derived mixed/tproxy ports)",
            );
        }

        // The actual tproxy listener: tun_port when set, else the shared
        // skip-occupied walk (same derivation as general_section).
        let tproxy_port = match config.tun_port {
            Some(t) => t,
            None => match crate::rules::derive_tproxy_port(config) {
                Ok(p) => p,
                Err(e) => {
                    result.add_error("proxy_port", e.to_string());
                    return;
                }
            },
        };
        if config.mixed_port == Some(tproxy_port) {
            result.add_error("mixed_port", "Mixed port conflicts with the tproxy port");
        }
        if config.tun_port.is_some_and(|t| t == config.proxy_port) {
            result.add_error("tun_port", "TUN/tproxy port conflicts with the proxy port");
        }
        if config
            .tun_port
            .is_some_and(|t| config.mixed_port == Some(t))
        {
            result.add_error("tun_port", "TUN/tproxy port conflicts with the mixed port");
        }
        if config.tun_port.is_some_and(|t| t == config.dns_port) {
            result.add_error("tun_port", "TUN/tproxy port conflicts with the dns port");
        }
        if config.tun_port.is_some_and(|t| t == config.dashboard_port) {
            result.add_error(
                "tun_port",
                "TUN/tproxy port conflicts with the dashboard port",
            );
        }
        if config.mixed_port == Some(config.dns_port) {
            result.add_error("mixed_port", "Mixed port conflicts with the dns port");
        }
    }

    fn validate_required_fields(&self, config: &Config, result: &mut ValidationResult) {
        if config.kernel.is_empty() {
            result.add_error("kernel", "Kernel cannot be empty");
        }

        match crate::engine::KernelSelection::parse(&config.kernel) {
            crate::engine::KernelSelection::Engine(flavor) => {
                if !crate::engine::flavor_supported(flavor) {
                    result.add_error(
                        "kernel",
                        format!(
                            "{} was not compiled into this binary; rebuild with \
                             `cargo build --features {}` or use mihomo/sing-box",
                            config.kernel,
                            flavor.feature_name()
                        ),
                    );
                }
            }
            crate::engine::KernelSelection::External(_) => {
                let valid_kernels = ["mihomo", "sing-box", "meta", "clash"];
                if !valid_kernels.contains(&config.kernel.as_str()) {
                    result.add_warning(format!("Unknown kernel: {}", config.kernel));
                }
            }
        }

        if config.variant.is_empty() {
            result.add_error("variant", "Variant cannot be empty");
        }
    }

    fn validate_kernel(&self, config: &Config, result: &mut ValidationResult) {
        if config.kernel == "sing-box" && config.mode == "Pure" {
            result.add_warning("sing-box does not support Pure mode, using Router instead");
        }
    }

    fn validate_mode(&self, config: &Config, result: &mut ValidationResult) {
        let valid_modes = ["Router", "Local", "Pure"];
        if !valid_modes.contains(&config.mode.as_str()) {
            result.add_error(
                "mode",
                format!(
                    "Invalid mode: {}. Valid modes: {:?}",
                    config.mode, valid_modes
                ),
            );
        }
    }

    fn validate_dns_mode(&self, config: &Config, result: &mut ValidationResult) {
        let valid_dns_modes = ["FakeIp", "RedirHost", "Mix", "Local"];
        if !valid_dns_modes.contains(&config.dns_mode.as_str()) {
            result.add_error("dns_mode", format!("Invalid DNS mode: {}", config.dns_mode));
        }
    }

    fn validate_advanced(&self, config: &Config, result: &mut ValidationResult) {
        if config.auto_update && config.update_interval.is_empty() {
            result.add_error(
                "update_interval",
                "Update interval cannot be empty when auto_update is enabled",
            );
        }

        if config.dashboard && config.dashboard_port < 1000 {
            result.add_warning(format!(
                "Dashboard port {} is below 1000, may conflict with system services",
                config.dashboard_port
            ));
        }
    }
}

/// Validate subscription URL format
pub fn validate_subscription_url(url: &str) -> Result<()> {
    if url.is_empty() {
        return Err(Error::Config("Subscription URL cannot be empty".into()));
    }

    if url.len() > 4096 {
        return Err(Error::Config(
            "Subscription URL too long (max 4096 characters)".into(),
        ));
    }

    if !url.starts_with("http://") && !url.starts_with("https://") {
        return Err(Error::Config(
            "Subscription URL must start with http:// or https://".into(),
        ));
    }

    if url.contains("<") || url.contains(">") || url.contains("\"") || url.contains("'") {
        return Err(Error::Config(
            "Subscription URL contains invalid characters".into(),
        ));
    }

    Ok(())
}

/// Validate rule syntax
pub fn validate_rule(rule: &str) -> Result<()> {
    if rule.is_empty() {
        return Err(Error::Config("Rule cannot be empty".into()));
    }

    if rule.starts_with('#') {
        return Ok(());
    }

    let rule_regex = Regex::new(r"^(DOMAIN|DOMAIN-SUFFIX|DOMAIN-KEYWORD|GEOIP|GEOIP-SET|IP-CIDR|IP-CIDR6|IP-CIDR6-SET|SRC-IP-CIDR|MATCH|DIRECT|PROXY|DOMAIN-SUFFIX|DOMAIN-KEYWORD)").unwrap();

    let parts: Vec<&str> = rule.split(',').collect();
    if parts.is_empty() {
        return Err(Error::Config("Invalid rule format".into()));
    }

    let rule_type = parts[0];
    if !rule_regex.is_match(rule_type) {
        return Err(Error::Config(format!("Unknown rule type: {}", rule_type)));
    }

    Ok(())
}

/// Validate YAML syntax
pub fn validate_yaml(yaml_content: &str) -> Result<()> {
    serde_yaml::from_str::<serde_yaml::Value>(yaml_content)
        .map_err(|e| Error::Config(format!("Invalid YAML syntax: {}", e)))?;
    Ok(())
}

/// Validate JSON syntax
pub fn validate_json(json_content: &str) -> Result<()> {
    serde_json::from_str::<serde_json::Value>(json_content)
        .map_err(|e| Error::Config(format!("Invalid JSON syntax: {}", e)))?;
    Ok(())
}

/// Validate a config file
pub fn validate_config_file(path: &Path) -> Result<ValidationResult> {
    let content = std::fs::read_to_string(path)?;
    let config: Config = serde_yaml::from_str(&content)
        .map_err(|e| Error::Config(format!("Failed to parse config: {}", e)))?;

    let validator = ConfigValidator::new(true);
    Ok(validator.validate(&config))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validation_result_new() {
        let result = ValidationResult::new();
        assert!(result.is_valid);
        assert!(result.errors.is_empty());
        assert!(result.warnings.is_empty());
    }

    #[test]
    fn test_validation_result_add_error() {
        let mut result = ValidationResult::new();
        result.add_error("port", "Invalid port");
        assert!(!result.is_valid);
        assert_eq!(result.errors.len(), 1);
    }

    #[test]
    fn test_validation_result_add_warning() {
        let mut result = ValidationResult::new();
        result.add_warning("Test warning");
        assert!(result.is_valid);
        assert_eq!(result.warnings.len(), 1);
    }

    #[test]
    fn test_validate_ports_valid() {
        let config = Config {
            proxy_port: 7890,
            dns_port: 7892,
            mixed_port: Some(7891),
            tun_port: None,
            dashboard_port: 9090,
            ..Default::default()
        };

        let validator = ConfigValidator::new(false);
        let result = validator.validate(&config);
        assert!(result.is_valid);
    }

    #[test]
    fn test_validate_ports_invalid() {
        let config = Config {
            proxy_port: 0,
            dns_port: 7892,
            mixed_port: None,
            tun_port: None,
            dashboard_port: 9090,
            ..Default::default()
        };

        let validator = ConfigValidator::new(false);
        let result = validator.validate(&config);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_validate_ports_conflict() {
        let config = Config {
            proxy_port: 7890,
            dns_port: 7890,
            mixed_port: None,
            tun_port: None,
            dashboard_port: 9090,
            ..Default::default()
        };

        let validator = ConfigValidator::new(false);
        let result = validator.validate(&config);
        assert!(!result.is_valid);
    }

    #[test]
    fn test_validate_subscription_url_valid() {
        assert!(validate_subscription_url("https://example.com/sub").is_ok());
        assert!(validate_subscription_url("http://example.com/sub").is_ok());
    }

    #[test]
    fn test_validate_subscription_url_invalid() {
        assert!(validate_subscription_url("").is_err());
        assert!(validate_subscription_url("ftp://example.com").is_err());
        assert!(validate_subscription_url("https://example.com\"test").is_err());
    }

    #[test]
    fn test_validate_subscription_url_too_long() {
        let long_url = format!("https://example.com/{}", "a".repeat(5000));
        assert!(validate_subscription_url(&long_url).is_err());
    }

    #[test]
    fn test_validate_yaml_valid() {
        let yaml = "key: value\nlist:\n  - item1\n  - item2";
        assert!(validate_yaml(yaml).is_ok());
    }

    #[test]
    fn test_validate_yaml_invalid() {
        let yaml = "key: value\n  invalid_indent:";
        assert!(validate_yaml(yaml).is_err());
    }

    #[test]
    fn test_validate_json_valid() {
        let json = r#"{"key": "value", "list": ["item1", "item2"]}"#;
        assert!(validate_json(json).is_ok());
    }

    #[test]
    fn test_validate_json_invalid() {
        let json = r#"{"key": "value", invalid"#;
        assert!(validate_json(json).is_err());
    }

    #[test]
    fn test_validate_rule_valid() {
        assert!(validate_rule("DOMAIN-SUFFIX,example.com").is_ok());
        assert!(validate_rule("DOMAIN-KEYWORD,google").is_ok());
        assert!(validate_rule("IP-CIDR,192.168.0.0/16").is_ok());
        assert!(validate_rule("# This is a comment").is_ok());
        assert!(validate_rule("MATCH,DIRECT").is_ok());
    }

    #[test]
    fn test_validate_rule_invalid() {
        assert!(validate_rule("").is_err());
        assert!(validate_rule("INVALID_TYPE,test").is_err());
    }

    #[test]
    fn test_config_validator_strict_mode() {
        let config = Config {
            auto_update: true,
            update_interval: "24h".to_string(),
            dashboard_port: 80,
            ..Default::default()
        };

        let validator = ConfigValidator::new(true);
        let result = validator.validate(&config);

        assert!(result.is_valid);
        assert!(!result.warnings.is_empty());
    }
}
