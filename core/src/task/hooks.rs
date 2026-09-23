//! Task hook execution (bfstart, afstart, affirewall)

use crate::task::{Task, TaskManager, TaskType};
use std::path::Path;
use std::process::Command;

#[derive(Debug, thiserror::Error)]
pub enum HookError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Task error: {0}")]
    Task(String),
}

pub struct HookRunner;

impl HookRunner {
    pub fn new() -> Self {
        Self
    }

    pub fn run_bfstart(&self, crash_dir: &Path) -> Result<(), HookError> {
        let tasks = TaskManager::load_tasks(crash_dir, TaskType::BfStart)?;
        for task in tasks {
            Self::execute_hook(crash_dir, &task, "bfstart")?;
        }
        Ok(())
    }

    pub fn run_afstart(&self, crash_dir: &Path) -> Result<(), HookError> {
        let tasks = TaskManager::load_tasks(crash_dir, TaskType::AfStart)?;
        for task in tasks {
            Self::execute_hook(crash_dir, &task, "afstart")?;
        }
        Ok(())
    }

    pub fn run_affirewall(&self, crash_dir: &Path) -> Result<(), HookError> {
        let tasks = TaskManager::load_tasks(crash_dir, TaskType::Affirewall)?;
        for task in tasks {
            Self::execute_hook(crash_dir, &task, "affirewall")?;
        }
        Ok(())
    }

    fn execute_hook(crash_dir: &Path, task: &Task, hook_type: &str) -> Result<(), HookError> {
        let output = Command::new(format!("{}/task/task.sh", crash_dir.display()))
            .arg(task.id.to_string())
            .arg(hook_type)
            .output()
            .map_err(HookError::Io)?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(HookError::Task(format!(
                "Hook {} failed: {}",
                task.name, stderr
            )));
        }
        Ok(())
    }
}

impl Default for HookRunner {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_env() -> TempDir {
        let dir = TempDir::new().unwrap();
        let task_dir = dir.path().join("task");
        fs::create_dir_all(&task_dir).unwrap();

        let task_sh = dir.path().join("task/task.sh");
        fs::write(&task_sh, "#!/bin/sh\necho \"Running: $1 $2\"\n").unwrap();

        dir
    }

    #[test]
    fn test_run_bfstart_empty() {
        let dir = create_test_env();
        let bfstart_file = dir.path().join("task/bfstart");
        fs::write(&bfstart_file, "").unwrap();

        let result = HookRunner::new().run_bfstart(dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_bfstart_with_tasks() {
        let dir = create_test_env();
        let bfstart_file = dir.path().join("task/bfstart");
        fs::write(&bfstart_file, "101#echo hello#Test Task\n").unwrap();

        let tasks = TaskManager::load_tasks(dir.path(), TaskType::BfStart).unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].id, 101);
        assert_eq!(tasks[0].command, "echo hello");
    }

    #[test]
    fn test_run_afstart_empty() {
        let dir = create_test_env();
        let result = HookRunner::new().run_afstart(dir.path());
        assert!(result.is_ok());
    }

    #[test]
    fn test_run_affirewall_empty() {
        let dir = create_test_env();
        let result = HookRunner::new().run_affirewall(dir.path());
        assert!(result.is_ok());
    }
}
