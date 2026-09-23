//! Import/Export module for RustCrash configuration
//!
//! Provides functionality to:
//! - Import config from YAML/JSON files
//! - Export config to YAML/JSON files
//! - Detect file format

use crate::config::Config;
use crate::error::{Error, Result};
use crate::validate::{ConfigValidator, ValidationResult};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConfigFormat {
    Yaml,
    Json,
}

impl ConfigFormat {
    pub fn from_path(path: &Path) -> Option<Self> {
        path.extension().and_then(|e| e.to_str()).and_then(|ext| {
            match ext.to_lowercase().as_str() {
                "yaml" | "yml" => Some(ConfigFormat::Yaml),
                "json" => Some(ConfigFormat::Json),
                _ => None,
            }
        })
    }

    pub fn extension(&self) -> &'static str {
        match self {
            ConfigFormat::Yaml => "yaml",
            ConfigFormat::Json => "json",
        }
    }
}

pub fn import_config(path: &Path) -> Result<(Config, ValidationResult)> {
    if !path.exists() {
        return Err(Error::Config(format!("File not found: {}", path.display())));
    }

    let content = std::fs::read_to_string(path)?;
    let format = ConfigFormat::from_path(path)
        .ok_or_else(|| Error::Config("Unsupported file format".into()))?;

    let config = match format {
        ConfigFormat::Yaml => serde_yaml::from_str(&content)
            .map_err(|e| Error::Config(format!("Failed to parse YAML: {}", e)))?,
        ConfigFormat::Json => serde_json::from_str(&content)
            .map_err(|e| Error::Config(format!("Failed to parse JSON: {}", e)))?,
    };

    let validator = ConfigValidator::new(true);
    let validation = validator.validate(&config);

    Ok((config, validation))
}

pub fn export_config(config: &Config, path: &Path, format: ConfigFormat) -> Result<()> {
    let content = match format {
        ConfigFormat::Yaml => serde_yaml::to_string(config)
            .map_err(|e| Error::Config(format!("Failed to serialize to YAML: {}", e)))?,
        ConfigFormat::Json => serde_json::to_string_pretty(config)
            .map_err(|e| Error::Config(format!("Failed to serialize to JSON: {}", e)))?,
    };

    if let Some(parent) = path.parent() {
        if !parent.exists() {
            fs::create_dir_all(parent)?;
        }
    }

    fs::write(path, content)?;
    tracing::info!("Exported config to: {}", path.display());
    Ok(())
}

pub fn export_config_auto(config: &Config, path: &Path) -> Result<()> {
    let format = ConfigFormat::from_path(path).unwrap_or(ConfigFormat::Yaml);
    export_config(config, path, format)
}

pub fn detect_format(path: &Path) -> Result<ConfigFormat> {
    if !path.exists() {
        return Err(Error::Config(format!("File not found: {}", path.display())));
    }

    ConfigFormat::from_path(path)
        .ok_or_else(|| Error::Config("Could not detect file format from extension".into()))
}

pub fn validate_config_file(path: &Path) -> Result<ValidationResult> {
    if !path.exists() {
        return Err(Error::Config(format!("File not found: {}", path.display())));
    }

    let content = fs::read_to_string(path)?;
    let format = ConfigFormat::from_path(path)
        .ok_or_else(|| Error::Config("Unsupported file format".into()))?;

    let config = match format {
        ConfigFormat::Yaml => serde_yaml::from_str(&content)
            .map_err(|e| Error::Config(format!("Invalid YAML: {}", e)))?,
        ConfigFormat::Json => serde_json::from_str(&content)
            .map_err(|e| Error::Config(format!("Invalid JSON: {}", e)))?,
    };

    let validator = ConfigValidator::new(true);
    Ok(validator.validate(&config))
}

pub fn yaml_to_json(yaml_path: &Path, json_path: &Path) -> Result<()> {
    let content = fs::read_to_string(yaml_path)?;
    let config: Config = serde_yaml::from_str(&content)
        .map_err(|e| Error::Config(format!("Failed to parse YAML: {}", e)))?;

    let json_content = serde_json::to_string_pretty(&config)
        .map_err(|e| Error::Config(format!("Failed to serialize to JSON: {}", e)))?;

    fs::write(json_path, json_content)?;
    tracing::info!(
        "Converted {} to {}",
        yaml_path.display(),
        json_path.display()
    );
    Ok(())
}

pub fn json_to_yaml(json_path: &Path, yaml_path: &Path) -> Result<()> {
    let content = fs::read_to_string(json_path)?;
    let config: Config = serde_json::from_str(&content)
        .map_err(|e| Error::Config(format!("Failed to parse JSON: {}", e)))?;

    let yaml_content = serde_yaml::to_string(&config)
        .map_err(|e| Error::Config(format!("Failed to serialize to YAML: {}", e)))?;

    fs::write(yaml_path, yaml_content)?;
    tracing::info!(
        "Converted {} to {}",
        json_path.display(),
        yaml_path.display()
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_config_format_from_path_yaml() {
        let path = Path::new("/path/to/config.yaml");
        assert_eq!(ConfigFormat::from_path(path), Some(ConfigFormat::Yaml));
    }

    #[test]
    fn test_config_format_from_path_json() {
        let path = Path::new("/path/to/config.json");
        assert_eq!(ConfigFormat::from_path(path), Some(ConfigFormat::Json));
    }

    #[test]
    fn test_config_format_from_path_unknown() {
        let path = Path::new("/path/to/config.txt");
        assert_eq!(ConfigFormat::from_path(path), None);
    }

    #[test]
    fn test_config_format_extension() {
        assert_eq!(ConfigFormat::Yaml.extension(), "yaml");
        assert_eq!(ConfigFormat::Json.extension(), "json");
    }

    #[test]
    fn test_import_export_yaml() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let yaml_path = temp_dir.path().join("config.yaml");

        let config = Config::default();
        export_config(&config, &yaml_path, ConfigFormat::Yaml).unwrap();

        let (imported, validation) = import_config(&yaml_path).unwrap();
        assert!(validation.is_valid);
        assert_eq!(imported.kernel, config.kernel);
    }

    #[test]
    fn test_import_export_json() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let json_path = temp_dir.path().join("config.json");

        let config = Config {
            kernel: "sing-box".to_string(),
            ..Default::default()
        };
        export_config(&config, &json_path, ConfigFormat::Json).unwrap();

        let (imported, validation) = import_config(&json_path).unwrap();
        assert!(validation.is_valid);
        assert_eq!(imported.kernel, "sing-box");
    }

    #[test]
    fn test_yaml_to_json_conversion() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let yaml_path = temp_dir.path().join("config.yaml");
        let json_path = temp_dir.path().join("config.json");

        let config = Config {
            kernel: "mihomo".to_string(),
            ..Default::default()
        };
        export_config(&config, &yaml_path, ConfigFormat::Yaml).unwrap();

        yaml_to_json(&yaml_path, &json_path).unwrap();
        assert!(json_path.exists());

        let content = fs::read_to_string(&json_path).unwrap();
        assert!(content.contains("mihomo"));
    }

    #[test]
    fn test_json_to_yaml_conversion() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let json_path = temp_dir.path().join("config.json");
        let yaml_path = temp_dir.path().join("config.yaml");

        let config = Config {
            kernel: "meta".to_string(),
            ..Default::default()
        };
        export_config(&config, &json_path, ConfigFormat::Json).unwrap();

        json_to_yaml(&json_path, &yaml_path).unwrap();
        assert!(yaml_path.exists());

        let content = fs::read_to_string(&yaml_path).unwrap();
        assert!(content.contains("meta"));
    }

    #[test]
    fn test_validate_config_file_valid() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let yaml_path = temp_dir.path().join("config.yaml");

        let config = Config::default();
        export_config(&config, &yaml_path, ConfigFormat::Yaml).unwrap();

        let result = validate_config_file(&yaml_path).unwrap();
        assert!(result.is_valid);
    }

    #[test]
    fn test_validate_config_file_invalid() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let yaml_path = temp_dir.path().join("invalid.yaml");

        fs::write(&yaml_path, "invalid: [yaml: content").unwrap();
        let result = validate_config_file(&yaml_path);
        assert!(result.is_err());
    }
}
