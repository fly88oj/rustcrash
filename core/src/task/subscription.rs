//! Scheduled subscription auto-update (D-20: silent fetch and replace)

use crate::platform::Platform;
use crate::subscription::SubscriptionManager;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Serialize, Deserialize)]
struct MinimalConfig {
    subscriptions: Vec<MinimalSubscription>,
}

#[derive(Debug, Serialize, Deserialize)]
struct MinimalSubscription {
    name: String,
    url: String,
    #[serde(default)]
    raw_config: Option<String>,
    #[serde(default)]
    updated_at: Option<i64>,
}

#[derive(Debug)]
pub struct UpdateReport {
    pub updated: Vec<String>,
    pub failed: Vec<(String, String)>,
    pub timestamp: DateTime<Utc>,
}

pub struct SubscriptionUpdater;

impl SubscriptionUpdater {
    pub fn update_all(crash_dir: &Path) -> anyhow::Result<UpdateReport> {
        let config_path = crash_dir.join("config.yaml");

        if !config_path.exists() {
            return Ok(UpdateReport {
                updated: Vec::new(),
                failed: Vec::new(),
                timestamp: Utc::now(),
            });
        }

        let content = std::fs::read_to_string(&config_path)?;
        let mut config: MinimalConfig = serde_yaml::from_str(&content)?;

        let mut report_updated = Vec::new();
        let mut report_failed = Vec::new();

        let rt = tokio::runtime::Runtime::new()?;

        for sub in &mut config.subscriptions {
            match rt.block_on(async { SubscriptionManager::fetch(&sub.url).await }) {
                Ok(info) => {
                    sub.raw_config = Some(info.content);
                    sub.updated_at = Some(Utc::now().timestamp());
                    report_updated.push(sub.name.clone());
                }
                Err(e) => {
                    eprintln!("[ERROR] Failed to update {}: {}", sub.name, e);
                    report_failed.push((sub.name.clone(), e.to_string()));
                }
            }
        }

        let new_content = serde_yaml::to_string(&config)?;
        std::fs::write(&config_path, new_content)?;

        // Best-effort push notification for the sub_update event.
        let nm =
            crate::notify::NotificationManager::from_platform(&Platform::detect_for_dir(crash_dir));
        let summary = format!(
            "updated: {}  failed: {}",
            report_updated.join(", "),
            report_failed
                .iter()
                .map(|(n, e)| format!("{n}: {e}"))
                .collect::<Vec<_>>()
                .join(", ")
        );
        rt.block_on(async { nm.notify_event("sub_update", &summary).await });

        Ok(UpdateReport {
            updated: report_updated,
            failed: report_failed,
            timestamp: Utc::now(),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_update_report_structure() {
        let report = UpdateReport {
            updated: vec!["sub1".to_string()],
            failed: vec![("sub2".to_string(), "error".to_string())],
            timestamp: Utc::now(),
        };
        assert_eq!(report.updated.len(), 1);
        assert_eq!(report.failed.len(), 1);
    }
}
