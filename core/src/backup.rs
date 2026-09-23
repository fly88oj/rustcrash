//! Backup and restore module for RustCrash configuration
//!
//! Provides functionality to:
//! - Create timestamped backups
//! - Restore from backups
//! - List available backups
//! - Delete old backups

use crate::error::{Error, Result};
use chrono::{DateTime, Local};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

const BACKUP_SUBDIRS: &[&str] = &["configs", "yamls", "jsons", "ruleset", "providers"];

/// Backup information
#[derive(Debug, Clone)]
pub struct BackupInfo {
    pub path: PathBuf,
    pub name: String,
    pub size: u64,
    pub created_at: DateTime<Local>,
}

/// Backup manager for creating and restoring configurations
#[derive(Debug)]
pub struct BackupManager {
    crash_dir: PathBuf,
    backup_dir: PathBuf,
}

impl BackupManager {
    /// Create a new BackupManager
    pub fn new(crash_dir: impl Into<PathBuf>, backup_dir: impl Into<PathBuf>) -> Self {
        Self {
            crash_dir: crash_dir.into(),
            backup_dir: backup_dir.into(),
        }
    }

    /// Get the default backup directory
    pub fn default_backup_dir() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from("."))
            .join("rustcrash")
            .join("backups")
    }

    /// Create a backup of the current configuration
    pub fn create_backup(&self) -> Result<BackupInfo> {
        let timestamp = Local::now().format("%Y%m%d_%H%M%S_%f");
        let backup_name = format!("backup_{}.tar.gz", timestamp);
        let backup_path = self.backup_dir.join(&backup_name);

        fs::create_dir_all(&self.backup_dir)?;

        let tar_gz = File::create(&backup_path)?;
        let encoder = GzEncoder::new(tar_gz, Compression::default());
        let mut tar_builder = tar::Builder::new(encoder);

        for subdir in BACKUP_SUBDIRS {
            let source_dir = self.crash_dir.join(subdir);
            if source_dir.exists() && source_dir.is_dir() {
                self.add_directory_to_tar(&mut tar_builder, &source_dir, subdir)?;
            }
        }

        tar_builder.finish()?;
        drop(tar_builder);

        let metadata = fs::metadata(&backup_path)?;
        let created_at = Local::now();

        tracing::info!("Created backup: {}", backup_path.display());

        Ok(BackupInfo {
            path: backup_path,
            name: backup_name,
            size: metadata.len(),
            created_at,
        })
    }

    /// Add a directory to the tar archive
    fn add_directory_to_tar(
        &self,
        tar_builder: &mut tar::Builder<GzEncoder<File>>,
        dir: &Path,
        prefix: &str,
    ) -> Result<()> {
        if !dir.exists() {
            return Ok(());
        }

        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            let name = format!("{}/{}", prefix, path.file_name().unwrap().to_string_lossy());

            if path.is_file() {
                let mut file = File::open(&path)?;
                tar_builder.append_file(&name, &mut file)?;
            } else if path.is_dir() {
                self.add_directory_to_tar(tar_builder, &path, &name)?;
            }
        }

        Ok(())
    }

    /// Restore from a backup
    pub fn restore_backup(&self, backup_path: &Path) -> Result<()> {
        if !backup_path.exists() {
            return Err(Error::Config(format!(
                "Backup file not found: {}",
                backup_path.display()
            )));
        }

        let tar_gz = File::open(backup_path)?;
        let decoder = GzDecoder::new(tar_gz);
        let mut tar_archive = tar::Archive::new(decoder);

        for entry in tar_archive.entries()? {
            let mut entry = entry?;
            let path = entry.path()?;

            let relative_path = path.to_string_lossy();

            for subdir in BACKUP_SUBDIRS {
                if relative_path.starts_with(subdir) {
                    let dest_path = self.crash_dir.join(relative_path.as_ref());
                    if let Some(parent) = dest_path.parent() {
                        fs::create_dir_all(parent)?;
                        entry.unpack(&dest_path)?;
                    }
                    break;
                }
            }
        }

        tracing::info!("Restored backup from: {}", backup_path.display());
        Ok(())
    }

    /// List all available backups
    pub fn list_backups(&self) -> Result<Vec<BackupInfo>> {
        let mut backups = Vec::new();

        if !self.backup_dir.exists() {
            return Ok(backups);
        }

        for entry in fs::read_dir(&self.backup_dir)? {
            let entry = entry?;
            let path = entry.path();

            if path.extension().map(|e| e == "gz").unwrap_or(false)
                && path
                    .file_name()
                    .map(|n| n.to_string_lossy().starts_with("backup_"))
                    .unwrap_or(false)
            {
                let metadata = fs::metadata(&path)?;
                let created_at = metadata
                    .modified()
                    .ok()
                    .map(DateTime::<Local>::from)
                    .unwrap_or_else(Local::now);

                backups.push(BackupInfo {
                    path: path.clone(),
                    name: path.file_name().unwrap().to_string_lossy().to_string(),
                    size: metadata.len(),
                    created_at,
                });
            }
        }

        backups.sort_by_key(|b| std::cmp::Reverse(b.created_at));
        Ok(backups)
    }

    /// Delete a backup
    pub fn delete_backup(&self, backup_path: &Path) -> Result<()> {
        if !backup_path.exists() {
            return Err(Error::Config(format!(
                "Backup not found: {}",
                backup_path.display()
            )));
        }

        fs::remove_file(backup_path)?;
        tracing::info!("Deleted backup: {}", backup_path.display());
        Ok(())
    }

    /// Clean old backups, keeping only the specified number
    pub fn clean_old_backups(&self, keep: usize) -> Result<usize> {
        let mut backups = self.list_backups()?;

        if backups.len() <= keep {
            return Ok(0);
        }

        let to_delete = backups.split_off(keep);
        let count = to_delete.len();

        for backup in to_delete {
            let _ = self.delete_backup(&backup.path);
        }

        tracing::info!("Cleaned {} old backups", count);
        Ok(count)
    }
}

/// Create a backup with default settings
pub fn quick_backup(crash_dir: &Path) -> Result<BackupInfo> {
    let backup_dir = BackupManager::default_backup_dir();
    let manager = BackupManager::new(crash_dir, backup_dir);
    manager.create_backup()
}

/// Quick restore from a backup file
pub fn quick_restore(crash_dir: &Path, backup_path: &Path) -> Result<()> {
    let backup_dir = BackupManager::default_backup_dir();
    let manager = BackupManager::new(crash_dir, backup_dir);
    manager.restore_backup(backup_path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_backup_manager_creation() {
        let manager = BackupManager::new("/tmp/test_crash", "/tmp/test_backups");
        assert_eq!(manager.crash_dir, PathBuf::from("/tmp/test_crash"));
        assert_eq!(manager.backup_dir, PathBuf::from("/tmp/test_backups"));
    }

    #[test]
    fn test_backup_and_restore() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let crash_dir = temp_dir.path().join("crash");
        let backup_dir = temp_dir.path().join("backups");

        fs::create_dir_all(crash_dir.join("configs")).unwrap();
        fs::create_dir_all(crash_dir.join("yamls")).unwrap();

        fs::write(crash_dir.join("configs/test.cfg"), "test config").unwrap();
        fs::write(crash_dir.join("yamls/config.yaml"), "test yaml").unwrap();

        let manager = BackupManager::new(&crash_dir, &backup_dir);
        let backup_info = manager.create_backup().unwrap();

        assert!(backup_info.path.exists());
        assert!(backup_info.name.starts_with("backup_"));
        assert!(backup_info.name.ends_with(".tar.gz"));

        fs::remove_file(crash_dir.join("configs/test.cfg")).unwrap();
        fs::remove_file(crash_dir.join("yamls/config.yaml")).unwrap();

        manager.restore_backup(&backup_info.path).unwrap();

        assert!(crash_dir.join("configs/test.cfg").exists());
        assert!(crash_dir.join("yamls/config.yaml").exists());
    }

    #[test]
    fn test_list_backups_empty() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let manager = BackupManager::new(temp_dir.path(), temp_dir.path().join("backups"));
        let backups = manager.list_backups().unwrap();
        assert!(backups.is_empty());
    }

    #[test]
    fn test_list_backups() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let crash_dir = temp_dir.path();
        let backup_dir = temp_dir.path().join("backups");

        fs::create_dir_all(crash_dir.join("configs")).unwrap();
        fs::write(crash_dir.join("configs/test.cfg"), "test").unwrap();

        let manager = BackupManager::new(crash_dir, &backup_dir);
        manager.create_backup().unwrap();

        let backups = manager.list_backups().unwrap();
        assert_eq!(backups.len(), 1);
    }

    #[test]
    fn test_delete_backup() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let crash_dir = temp_dir.path();
        let backup_dir = temp_dir.path().join("backups");

        fs::create_dir_all(crash_dir.join("configs")).unwrap();
        fs::write(crash_dir.join("configs/test.cfg"), "test").unwrap();

        let manager = BackupManager::new(crash_dir, &backup_dir);
        let backup_info = manager.create_backup().unwrap();

        assert!(backup_info.path.exists());
        manager.delete_backup(&backup_info.path).unwrap();
        assert!(!backup_info.path.exists());
    }

    #[test]
    fn test_clean_old_backups() {
        let temp_dir = tempfile::TempDir::new().unwrap();
        let crash_dir = temp_dir.path();
        let backup_dir = temp_dir.path().join("backups");

        fs::create_dir_all(crash_dir.join("configs")).unwrap();
        fs::write(crash_dir.join("configs/test.cfg"), "test").unwrap();

        let manager = BackupManager::new(crash_dir, &backup_dir);

        for _ in 0..5 {
            manager.create_backup().unwrap();
        }

        let remaining = manager.clean_old_backups(2).unwrap();
        assert_eq!(remaining, 3);

        let backups = manager.list_backups().unwrap();
        assert_eq!(backups.len(), 2);
    }
}
