//! Scheduled kernel auto-update (D-21: fetch version info, download if newer)

use crate::kernels::KernelManager;
use crate::platform::{Platform, ProxyKernel};
use chrono::{DateTime, Utc};
use std::path::Path;

#[derive(Debug)]
pub struct KernelUpdateReport {
    pub updated: bool,
    pub current_version: String,
    pub new_version: Option<String>,
    pub error: Option<String>,
    pub timestamp: DateTime<Utc>,
}

pub struct KernelUpdater;

impl KernelUpdater {
    pub fn check_and_update(crash_dir: &Path) -> anyhow::Result<KernelUpdateReport> {
        let config_path = crash_dir.join("config.yaml");
        let config_content = if config_path.exists() {
            std::fs::read_to_string(&config_path)?
        } else {
            String::new()
        };

        let config: serde_yaml::Value = serde_yaml::from_str(&config_content)
            .unwrap_or(serde_yaml::Value::Mapping(serde_yaml::Mapping::new()));

        let kernel_str = config
            .get("kernel")
            .and_then(|v| v.as_str())
            .unwrap_or("mihomo");

        let current_version = config
            .get("kernel_version")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown")
            .to_string();

        let proxy_kernel = match kernel_str {
            "sing-box" | "singbox" => ProxyKernel::SingBox,
            _ => ProxyKernel::Mihomo,
        };

        let platform = Platform::detect_for_dir(crash_dir);
        let km = KernelManager::new(&platform);

        let rt = tokio::runtime::Runtime::new()?;

        let latest_version = match rt.block_on(async { km.get_latest_version(proxy_kernel).await })
        {
            Ok(v) => v,
            Err(e) => {
                eprintln!("[ERROR] Kernel version check failed: {}", e);
                return Ok(KernelUpdateReport {
                    updated: false,
                    current_version,
                    new_version: None,
                    error: Some(e.to_string()),
                    timestamp: Utc::now(),
                });
            }
        };

        if Self::is_newer_version(&current_version, &latest_version) {
            match rt.block_on(async { km.install(proxy_kernel, Some(&latest_version)).await }) {
                Ok(_) => {
                    // Best-effort push notification for the kernel_update event.
                    let nm = crate::notify::NotificationManager::from_platform(
                        &Platform::detect_for_dir(crash_dir),
                    );
                    let msg = format!(
                        "{kernel} updated to {latest_version}",
                        kernel = proxy_kernel.binary_name()
                    );
                    rt.block_on(async { nm.notify_event("kernel_update", &msg).await });
                    Ok(KernelUpdateReport {
                        updated: true,
                        current_version,
                        new_version: Some(latest_version),
                        error: None,
                        timestamp: Utc::now(),
                    })
                }
                Err(e) => {
                    eprintln!("[ERROR] Kernel install failed: {}", e);
                    Ok(KernelUpdateReport {
                        updated: false,
                        current_version,
                        new_version: None,
                        error: Some(e.to_string()),
                        timestamp: Utc::now(),
                    })
                }
            }
        } else {
            Ok(KernelUpdateReport {
                updated: false,
                current_version,
                new_version: None,
                error: None,
                timestamp: Utc::now(),
            })
        }
    }

    pub fn is_newer_version(current: &str, new: &str) -> bool {
        if current == "unknown" || current.is_empty() {
            return true;
        }

        let current_parts: Vec<u32> = current
            .trim_start_matches('v')
            .split('.')
            .filter_map(|s| s.parse().ok())
            .collect();

        let new_parts: Vec<u32> = new
            .trim_start_matches('v')
            .split('.')
            .filter_map(|s| s.parse().ok())
            .collect();

        for (c, n) in current_parts.iter().zip(new_parts.iter()) {
            if n > c {
                return true;
            } else if n < c {
                return false;
            }
        }

        false
    }
}

impl Platform {
    pub fn detect_for_dir(_dir: &Path) -> Self {
        Platform::detect().unwrap_or_else(|_| Platform::for_crash_dir("/etc/ShellCrash"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version_comparison_newer_minor() {
        assert!(KernelUpdater::is_newer_version("1.2.3", "1.3.0"));
    }

    #[test]
    fn test_version_comparison_newer_major() {
        assert!(KernelUpdater::is_newer_version("1.2.3", "2.0.0"));
    }

    #[test]
    fn test_version_comparison_same() {
        assert!(!KernelUpdater::is_newer_version("1.2.3", "1.2.3"));
    }

    #[test]
    fn test_version_comparison_older() {
        assert!(!KernelUpdater::is_newer_version("1.3.0", "1.2.3"));
    }

    #[test]
    fn test_version_comparison_with_v_prefix() {
        assert!(KernelUpdater::is_newer_version("v1.2.3", "v1.3.0"));
    }

    #[test]
    fn test_version_comparison_unknown_is_newer() {
        assert!(KernelUpdater::is_newer_version("unknown", "1.0.0"));
    }

    #[test]
    fn test_kernel_update_report_structure() {
        let report = KernelUpdateReport {
            updated: false,
            current_version: "1.2.3".to_string(),
            new_version: None,
            error: Some("network error".to_string()),
            timestamp: Utc::now(),
        };
        assert_eq!(report.current_version, "1.2.3");
        assert!(report.error.is_some());
    }
}
