//! Template management module for RustCrash
//!
//! Provides functionality to:
//! - List built-in templates
//! - List user templates
//! - Create/update/delete user templates
//! - Export/import templates

use crate::config::{Config, ConfigVariant};
use crate::error::{Error, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Template {
    pub name: String,
    pub description: String,
    pub variant: ConfigVariant,
    pub is_builtin: bool,
    pub config_overrides: TemplateOverrides,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TemplateOverrides {
    pub kernel: Option<String>,
    pub mode: Option<String>,
    pub dns_mode: Option<String>,
    pub proxy_port: Option<u16>,
    pub dns_port: Option<u16>,
    pub mixed_port: Option<u16>,
}

impl Template {
    pub fn to_config(&self) -> Config {
        let mut config = Config {
            variant: self.variant.to_string(),
            ..Default::default()
        };

        if let Some(kernel) = &self.config_overrides.kernel {
            config.kernel = kernel.clone();
        }
        if let Some(mode) = &self.config_overrides.mode {
            config.mode = mode.clone();
        }
        if let Some(dns_mode) = &self.config_overrides.dns_mode {
            config.dns_mode = dns_mode.clone();
        }
        if let Some(port) = self.config_overrides.proxy_port {
            config.proxy_port = port;
        }
        if let Some(port) = self.config_overrides.dns_port {
            config.dns_port = port;
        }
        if let Some(port) = self.config_overrides.mixed_port {
            config.mixed_port = Some(port);
        }

        config
    }
}

pub struct TemplateManager {
    user_template_dir: PathBuf,
}

impl TemplateManager {
    pub fn new() -> Self {
        let user_template_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("rustcrash")
            .join("templates");

        Self { user_template_dir }
    }

    pub fn user_template_dir(&self) -> &Path {
        &self.user_template_dir
    }

    pub fn ensure_user_template_dir(&self) -> Result<()> {
        if !self.user_template_dir.exists() {
            fs::create_dir_all(&self.user_template_dir)?;
        }
        Ok(())
    }

    pub fn list_builtins() -> Vec<Template> {
        vec![
            Template {
                name: "Full".to_string(),
                description: "Full feature set with all rules".to_string(),
                variant: ConfigVariant::Full,
                is_builtin: true,
                config_overrides: TemplateOverrides {
                    kernel: None,
                    mode: None,
                    dns_mode: None,
                    proxy_port: None,
                    dns_port: None,
                    mixed_port: None,
                },
            },
            Template {
                name: "FullNoAds".to_string(),
                description: "Full features without ads blocking".to_string(),
                variant: ConfigVariant::FullNoAds,
                is_builtin: true,
                config_overrides: TemplateOverrides::default(),
            },
            Template {
                name: "Lite".to_string(),
                description: "Reduced rule set, smaller footprint".to_string(),
                variant: ConfigVariant::Lite,
                is_builtin: true,
                config_overrides: TemplateOverrides::default(),
            },
            Template {
                name: "LiteNoAds".to_string(),
                description: "Lite features without ads blocking".to_string(),
                variant: ConfigVariant::LiteNoAds,
                is_builtin: true,
                config_overrides: TemplateOverrides::default(),
            },
            Template {
                name: "Light".to_string(),
                description: "Minimal rules for basic usage".to_string(),
                variant: ConfigVariant::Light,
                is_builtin: true,
                config_overrides: TemplateOverrides::default(),
            },
            Template {
                name: "Nano".to_string(),
                description: "Bare minimum for minimal resources".to_string(),
                variant: ConfigVariant::Nano,
                is_builtin: true,
                config_overrides: TemplateOverrides {
                    proxy_port: Some(7890),
                    dns_port: Some(7892),
                    mixed_port: Some(7891),
                    ..Default::default()
                },
            },
        ]
    }

    pub fn list_user_templates(&self) -> Result<Vec<Template>> {
        self.ensure_user_template_dir()?;

        let mut templates = Vec::new();

        if !self.user_template_dir.exists() {
            return Ok(templates);
        }

        for entry in fs::read_dir(&self.user_template_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path
                .extension()
                .map(|e| e == "yaml" || e == "yml")
                .unwrap_or(false)
            {
                if let Ok(content) = fs::read_to_string(&path) {
                    if let Ok(template) = serde_yaml::from_str::<Template>(&content) {
                        templates.push(template);
                    }
                }
            }
        }

        templates.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(templates)
    }

    pub fn list_all(&self) -> Result<Vec<Template>> {
        let mut all = Self::list_builtins();
        all.extend(self.list_user_templates()?);
        Ok(all)
    }

    pub fn get_builtin(name: &str) -> Option<Template> {
        Self::list_builtins().into_iter().find(|t| t.name == name)
    }

    pub fn get_user(&self, name: &str) -> Result<Option<Template>> {
        Ok(self
            .list_user_templates()?
            .into_iter()
            .find(|t| t.name == name))
    }

    pub fn get(&self, name: &str) -> Result<Option<Template>> {
        if let Some(template) = Self::get_builtin(name) {
            return Ok(Some(template));
        }
        self.get_user(name)
    }

    pub fn create_template(
        &self,
        name: &str,
        description: &str,
        config: &Config,
    ) -> Result<Template> {
        self.ensure_user_template_dir()?;

        if Self::get_builtin(name).is_some() {
            return Err(Error::Config(format!(
                "Cannot override built-in template: {}",
                name
            )));
        }

        let variant = ConfigVariant::from_str(&config.variant).unwrap_or(ConfigVariant::Lite);

        let template = Template {
            name: name.to_string(),
            description: description.to_string(),
            variant,
            is_builtin: false,
            config_overrides: TemplateOverrides {
                kernel: Some(config.kernel.clone()),
                mode: Some(config.mode.clone()),
                dns_mode: Some(config.dns_mode.clone()),
                proxy_port: Some(config.proxy_port),
                dns_port: Some(config.dns_port),
                mixed_port: config.mixed_port,
            },
        };

        let path = self.user_template_dir.join(format!("{}.yaml", name));
        let content = serde_yaml::to_string(&template)?;
        fs::write(&path, content)?;

        tracing::info!("Created template: {} at {}", name, path.display());
        Ok(template)
    }

    pub fn update_template(&self, name: &str, template: &Template) -> Result<()> {
        if template.is_builtin {
            return Err(Error::Config("Cannot modify built-in template".into()));
        }

        let path = self.user_template_dir.join(format!("{}.yaml", name));
        if !path.exists() {
            return Err(Error::Config(format!("Template not found: {}", name)));
        }

        let content = serde_yaml::to_string(&template)?;
        fs::write(&path, content)?;

        tracing::info!("Updated template: {}", name);
        Ok(())
    }

    pub fn delete_template(&self, name: &str) -> Result<()> {
        if Self::get_builtin(name).is_some() {
            return Err(Error::Config("Cannot delete built-in template".into()));
        }

        let path = self.user_template_dir.join(format!("{}.yaml", name));
        if !path.exists() {
            return Err(Error::Config(format!("Template not found: {}", name)));
        }

        fs::remove_file(&path)?;
        tracing::info!("Deleted template: {}", name);
        Ok(())
    }

    pub fn export_template(&self, name: &str, export_path: &Path) -> Result<()> {
        let template = self
            .get(name)?
            .ok_or_else(|| Error::Config(format!("Template not found: {}", name)))?;

        let extension = export_path
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("yaml");
        let content = match extension {
            "json" => serde_json::to_string_pretty(&template)?,
            _ => serde_yaml::to_string(&template)?,
        };

        fs::write(export_path, content)?;
        tracing::info!("Exported template {} to {}", name, export_path.display());
        Ok(())
    }

    pub fn import_template(&self, import_path: &Path) -> Result<Template> {
        let content = fs::read_to_string(import_path)?;
        let mut template: Template = if import_path
            .extension()
            .and_then(|e| e.to_str())
            .map(|e| e == "json")
            .unwrap_or(false)
        {
            serde_json::from_str(&content)?
        } else {
            serde_yaml::from_str(&content)?
        };

        if template.is_builtin {
            return Err(Error::Config("Cannot import built-in template".into()));
        }

        template.is_builtin = false;

        if Self::get_builtin(&template.name).is_some() {
            return Err(Error::Config(format!(
                "Template name conflicts with built-in: {}",
                template.name
            )));
        }

        let path = self
            .user_template_dir
            .join(format!("{}.yaml", template.name));
        if path.exists() {
            return Err(Error::Config(format!(
                "Template already exists: {}",
                template.name
            )));
        }

        self.ensure_user_template_dir()?;
        let content = serde_yaml::to_string(&template)?;
        fs::write(&path, content)?;

        tracing::info!(
            "Imported template: {} from {}",
            template.name,
            import_path.display()
        );
        Ok(template)
    }
}

impl ConfigVariant {
    // ShellCrash-parity API: returns Option, not FromStr's Result.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "full" => Some(ConfigVariant::Full),
            "fullnoads" => Some(ConfigVariant::FullNoAds),
            "lite" => Some(ConfigVariant::Lite),
            "litenoads" => Some(ConfigVariant::LiteNoAds),
            "light" => Some(ConfigVariant::Light),
            "nano" => Some(ConfigVariant::Nano),
            _ => None,
        }
    }
}

impl Default for TemplateManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_builtins() {
        let builtins = TemplateManager::list_builtins();
        assert_eq!(builtins.len(), 6);
        assert!(builtins.iter().all(|t| t.is_builtin));
    }

    #[test]
    fn test_get_builtin() {
        let template = TemplateManager::get_builtin("Full");
        assert!(template.is_some());
        assert_eq!(template.unwrap().name, "Full");
    }

    #[test]
    fn test_get_nonexistent_builtin() {
        let template = TemplateManager::get_builtin("NonExistent");
        assert!(template.is_none());
    }

    #[test]
    fn test_template_to_config() {
        let template = Template {
            name: "Test".to_string(),
            description: "Test template".to_string(),
            variant: ConfigVariant::Full,
            is_builtin: true,
            config_overrides: TemplateOverrides {
                kernel: Some("sing-box".to_string()),
                mode: Some("Local".to_string()),
                dns_mode: None,
                proxy_port: Some(8080),
                dns_port: Some(5353),
                mixed_port: Some(8080),
            },
        };

        let config = template.to_config();
        assert_eq!(config.kernel, "sing-box");
        assert_eq!(config.mode, "Local");
        assert_eq!(config.proxy_port, 8080);
        assert_eq!(config.dns_port, 5353);
        assert_eq!(config.mixed_port, Some(8080));
    }

    #[test]
    fn test_template_manager_creation() {
        let manager = TemplateManager::new();
        assert!(manager.user_template_dir().ends_with("templates"));
    }

    #[test]
    fn test_config_variant_from_str() {
        assert_eq!(ConfigVariant::from_str("Full"), Some(ConfigVariant::Full));
        assert_eq!(ConfigVariant::from_str("full"), Some(ConfigVariant::Full));
        assert_eq!(ConfigVariant::from_str("FULL"), Some(ConfigVariant::Full));
        assert_eq!(ConfigVariant::from_str("invalid"), None);
    }

    #[test]
    fn test_user_template_crud() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let manager = TemplateManager {
            user_template_dir: temp_dir.path().to_path_buf(),
        };

        let config = Config::default();
        let template = manager.create_template("TestTemplate", "Test description", &config);
        assert!(template.is_ok());

        let templates = manager.list_user_templates().unwrap();
        assert_eq!(templates.len(), 1);

        let deleted = manager.delete_template("TestTemplate");
        assert!(deleted.is_ok());

        let templates = manager.list_user_templates().unwrap();
        assert!(templates.is_empty());
    }

    #[test]
    fn test_cannot_delete_builtin() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let manager = TemplateManager {
            user_template_dir: temp_dir.path().to_path_buf(),
        };

        let result = manager.delete_template("Full");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("built-in"));
    }

    #[test]
    fn test_cannot_override_builtin() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let manager = TemplateManager {
            user_template_dir: temp_dir.path().to_path_buf(),
        };

        let config = Config::default();
        let result = manager.create_template("Full", "Override", &config);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("Cannot override"));
    }
}
