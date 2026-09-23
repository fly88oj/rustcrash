//! Task scheduling and management (D-01 to D-22)

pub mod hooks;
pub mod kernel_update;
pub mod subscription;

pub use hooks::{HookError, HookRunner};
pub use kernel_update::{KernelUpdateReport, KernelUpdater};
pub use subscription::{SubscriptionUpdater, UpdateReport};

use std::fmt;
use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskType {
    Cron,
    BfStart,
    AfStart,
    Running,
    Affirewall,
    TaskUser,
}

impl TaskType {
    // ShellCrash-parity API: returns Option, not FromStr's Result.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s {
            "cron" => Some(Self::Cron),
            "bfstart" => Some(Self::BfStart),
            "afstart" => Some(Self::AfStart),
            "running" => Some(Self::Running),
            "affirewall" => Some(Self::Affirewall),
            "task.user" => Some(Self::TaskUser),
            _ => None,
        }
    }

    pub fn file_name(&self) -> &'static str {
        match self {
            Self::Cron => "cron",
            Self::BfStart => "bfstart",
            Self::AfStart => "afstart",
            Self::Running => "running",
            Self::Affirewall => "affirewall",
            Self::TaskUser => "task.user",
        }
    }
}

impl fmt::Display for TaskType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.file_name())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CronExpr {
    pub minute: String,
    pub hour: String,
    pub dom: String,
    pub mon: String,
    pub dow: String,
}

#[derive(Debug, thiserror::Error)]
pub enum CronError {
    #[error("Invalid cron field: {0}")]
    InvalidField(String),
    #[error("Missing required field")]
    MissingField,
}

impl CronExpr {
    pub fn parse(expr: &str) -> Result<Self, CronError> {
        let parts: Vec<&str> = expr.split_whitespace().collect();
        if parts.len() != 5 {
            return Err(CronError::InvalidField(expr.to_string()));
        }

        Ok(Self {
            minute: parts[0].to_string(),
            hour: parts[1].to_string(),
            dom: parts[2].to_string(),
            mon: parts[3].to_string(),
            dow: parts[4].to_string(),
        })
    }

    pub fn to_cron_line(&self, crash_dir: &str, task_id: &str, command: &str) -> String {
        format!(
            "{} {} {}/task/task.sh {} {}",
            self.minute, self.hour, crash_dir, task_id, command
        )
    }
}

#[derive(Debug, Clone)]
pub struct Task {
    pub id: u32,
    pub command: String,
    pub name: String,
    pub task_type: TaskType,
}

impl Task {
    pub fn from_line(line: &str, task_type: TaskType) -> Result<Self, String> {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            return Err("Empty or comment line".to_string());
        }

        let parts: Vec<&str> = line.splitn(3, '#').collect();
        if parts.len() != 3 {
            return Err(format!("Invalid task line format: {}", line));
        }

        let id: u32 = parts[0]
            .parse()
            .map_err(|_| format!("Invalid task ID: {}", parts[0]))?;

        Ok(Self {
            id,
            command: parts[1].to_string(),
            name: parts[2].to_string(),
            task_type,
        })
    }

    pub fn to_line(&self) -> String {
        format!("{}#{}#{}", self.id, self.command, self.name)
    }
}

pub struct TaskManager;

impl TaskManager {
    pub fn load_tasks(crash_dir: &Path, task_type: TaskType) -> std::io::Result<Vec<Task>> {
        let task_file = crash_dir.join("task").join(task_type.file_name());

        if !task_file.exists() {
            return Ok(Vec::new());
        }

        let content = fs::read_to_string(&task_file)?;
        let mut tasks = Vec::new();

        for line in content.lines() {
            match Task::from_line(line, task_type) {
                Ok(task) => tasks.push(task),
                Err(_) => continue,
            }
        }

        Ok(tasks)
    }

    pub fn save_task(crash_dir: &Path, task: &Task) -> std::io::Result<()> {
        let task_dir = crash_dir.join("task");
        fs::create_dir_all(&task_dir)?;

        let mut tasks: Vec<Task> = Self::load_tasks(crash_dir, task.task_type)?
            .into_iter()
            .filter(|t| t.id != task.id)
            .collect();

        tasks.push(task.clone());

        let task_file = task_dir.join(task.task_type.file_name());
        let content: String = tasks
            .iter()
            .map(|t| t.to_line())
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&task_file, content)?;

        Ok(())
    }

    pub fn delete_task(crash_dir: &Path, task_id: u32, task_type: TaskType) -> std::io::Result<()> {
        let task_file = crash_dir.join("task").join(task_type.file_name());

        if !task_file.exists() {
            return Ok(());
        }

        let tasks: Vec<Task> = Self::load_tasks(crash_dir, task_type)?
            .into_iter()
            .filter(|t| t.id != task_id)
            .collect();

        let content: String = tasks
            .iter()
            .map(|t| t.to_line())
            .collect::<Vec<_>>()
            .join("\n");
        fs::write(&task_file, content)?;

        Ok(())
    }

    pub fn cron_dir() -> std::io::Result<std::path::PathBuf> {
        let dirs = [
            "/var/spool/cron/crontabs",
            "/etc/storage/cron/crontabs",
            "/etc/spool/cron/crontabs",
        ];

        for dir in &dirs {
            let path = std::path::Path::new(dir);
            if path.exists() && std::fs::OpenOptions::new().append(true).open(path).is_ok() {
                return Ok(path.to_path_buf());
            }
        }

        Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            "No writable cron directory found",
        ))
    }
}

pub struct RunningTaskManager;

impl RunningTaskManager {
    pub fn setup(crash_dir: &Path, interval_minutes: u32) -> std::io::Result<String> {
        let task_id = 106;

        let task = Task {
            id: task_id,
            command: format!("*/{}", interval_minutes),
            name: "Runtime monitoring".to_string(),
            task_type: TaskType::Running,
        };

        TaskManager::save_task(crash_dir, &task)?;

        let cron_line = format!(
            "*/{} * * * * {}/task/task.sh {} running",
            interval_minutes,
            crash_dir.display(),
            task_id
        );

        Ok(cron_line)
    }

    pub fn remove(crash_dir: &Path, task_id: u32) -> std::io::Result<()> {
        TaskManager::delete_task(crash_dir, task_id, TaskType::Running)
    }
}

pub struct TaskUserManager;

impl TaskUserManager {
    pub fn add(crash_dir: &Path, command: &str, name: &str) -> std::io::Result<u32> {
        let tasks = Self::list(crash_dir)?;

        let max_id = tasks.iter().map(|t| t.id).max().unwrap_or(199);
        let new_id = max_id + 1;

        let task = Task {
            id: new_id,
            command: command.to_string(),
            name: name.to_string(),
            task_type: TaskType::TaskUser,
        };

        TaskManager::save_task(crash_dir, &task)?;

        Ok(new_id)
    }

    pub fn del(crash_dir: &Path, id: u32) -> std::io::Result<()> {
        TaskManager::delete_task(crash_dir, id, TaskType::TaskUser)
    }

    pub fn list(crash_dir: &Path) -> std::io::Result<Vec<Task>> {
        TaskManager::load_tasks(crash_dir, TaskType::TaskUser)
    }
}

pub fn cronset(crash_dir: &Path, keyword: &str, cron_line: &str) -> std::io::Result<()> {
    let current = load_crontab()?;

    let filtered: String = current
        .lines()
        .filter(|line| !line.contains(keyword))
        .collect::<Vec<_>>()
        .join("\n");

    let new_cron = if filtered.is_empty() {
        cron_line.to_string()
    } else {
        format!("{}\n{}", filtered, cron_line)
    };

    save_crontab(&new_cron)?;

    if crash_dir.join("task").exists() {
        let task_cron = crash_dir.join("task/cron");
        if std::fs::OpenOptions::new()
            .write(true)
            .open(&task_cron)
            .is_ok()
        {
            std::fs::write(&task_cron, &new_cron)?;
        }
    }

    Ok(())
}

fn load_crontab() -> std::io::Result<String> {
    if let Ok(output) = std::process::Command::new("crontab").arg("-l").output() {
        if output.status.success() {
            return Ok(String::from_utf8_lossy(&output.stdout).to_string());
        }
    }

    let cron_dir = TaskManager::cron_dir()?;
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "root".to_string());

    let cron_file = cron_dir.join(&user);
    if cron_file.exists() {
        std::fs::read_to_string(&cron_file)
    } else {
        Ok(String::new())
    }
}

fn save_crontab(content: &str) -> std::io::Result<()> {
    let result = std::process::Command::new("crontab")
        .arg("-")
        .arg(content)
        .output();

    if result.is_ok() && result.as_ref().unwrap().status.success() {
        return Ok(());
    }

    let cron_dir = TaskManager::cron_dir()?;
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("USERNAME"))
        .unwrap_or_else(|_| "root".to_string());

    let cron_file = cron_dir.join(&user);
    std::fs::write(&cron_file, content)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cron_expr_standard() {
        let expr = CronExpr::parse("0 4 * * *").unwrap();
        assert_eq!(expr.minute, "0");
        assert_eq!(expr.hour, "4");
        assert_eq!(expr.dom, "*");
        assert_eq!(expr.mon, "*");
        assert_eq!(expr.dow, "*");
    }

    #[test]
    fn test_cron_expr_interval() {
        let expr = CronExpr::parse("*/5 * * * *").unwrap();
        assert_eq!(expr.minute, "*/5");
    }

    #[test]
    fn test_cron_expr_invalid() {
        assert!(CronExpr::parse("invalid").is_err());
        assert!(CronExpr::parse("").is_err());
    }

    #[test]
    fn test_cron_expr_weekly() {
        let expr = CronExpr::parse("0 4 * * 1").unwrap();
        assert_eq!(expr.dow, "1");
    }

    #[test]
    fn test_task_from_line() {
        let task = Task::from_line("103#subscription update#Auto update", TaskType::Cron).unwrap();
        assert_eq!(task.id, 103);
        assert_eq!(task.command, "subscription update");
        assert_eq!(task.name, "Auto update");
        assert_eq!(task.task_type, TaskType::Cron);
    }

    #[test]
    fn test_task_from_line_with_bfstart() {
        let task =
            Task::from_line("103#subscription update#Auto update", TaskType::BfStart).unwrap();
        assert_eq!(task.task_type, TaskType::BfStart);
    }

    #[test]
    fn test_task_to_line() {
        let task = Task {
            id: 103,
            command: "subscription update".to_string(),
            name: "Auto update".to_string(),
            task_type: TaskType::Cron,
        };
        assert_eq!(task.to_line(), "103#subscription update#Auto update");
    }

    #[test]
    fn test_task_type_file_name() {
        assert_eq!(TaskType::Cron.file_name(), "cron");
        assert_eq!(TaskType::BfStart.file_name(), "bfstart");
        assert_eq!(TaskType::AfStart.file_name(), "afstart");
        assert_eq!(TaskType::Running.file_name(), "running");
        assert_eq!(TaskType::Affirewall.file_name(), "affirewall");
        assert_eq!(TaskType::TaskUser.file_name(), "task.user");
    }

    #[test]
    fn test_task_type_from_str() {
        assert_eq!(TaskType::from_str("cron"), Some(TaskType::Cron));
        assert_eq!(TaskType::from_str("bfstart"), Some(TaskType::BfStart));
        assert_eq!(TaskType::from_str("afstart"), Some(TaskType::AfStart));
        assert_eq!(TaskType::from_str("running"), Some(TaskType::Running));
        assert_eq!(TaskType::from_str("affirewall"), Some(TaskType::Affirewall));
        assert_eq!(TaskType::from_str("task.user"), Some(TaskType::TaskUser));
        assert_eq!(TaskType::from_str("invalid"), None);
    }
}

#[cfg(test)]
mod task_manager_tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_crashdir() -> TempDir {
        let dir = TempDir::new().unwrap();
        let task_dir = dir.path().join("task");
        fs::create_dir_all(&task_dir).unwrap();
        dir
    }

    #[test]
    fn test_load_tasks_empty() {
        let dir = create_test_crashdir();
        let tasks = TaskManager::load_tasks(dir.path(), TaskType::Cron).unwrap();
        assert!(tasks.is_empty());
    }

    #[test]
    fn test_load_tasks_with_data() {
        let dir = create_test_crashdir();
        let cron_file = dir.path().join("task/cron");
        fs::write(&cron_file, "103#subscription update#Auto update\n").unwrap();

        let tasks = TaskManager::load_tasks(dir.path(), TaskType::Cron).unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].id, 103);
        assert_eq!(tasks[0].command, "subscription update");
    }

    #[test]
    fn test_save_and_load_task() {
        let dir = create_test_crashdir();
        let task = Task {
            id: 104,
            command: "kernel update check".to_string(),
            name: "Check kernel".to_string(),
            task_type: TaskType::Cron,
        };

        TaskManager::save_task(dir.path(), &task).unwrap();

        let loaded = TaskManager::load_tasks(dir.path(), TaskType::Cron).unwrap();
        assert_eq!(loaded.len(), 1);
        assert_eq!(loaded[0].id, 104);
    }

    #[test]
    fn test_delete_task() {
        let dir = create_test_crashdir();
        let cron_file = dir.path().join("task/cron");
        fs::write(
            &cron_file,
            "103#subscription update#Auto update\n104#kernel check#Kernel check\n",
        )
        .unwrap();

        TaskManager::delete_task(dir.path(), 103, TaskType::Cron).unwrap();

        let tasks = TaskManager::load_tasks(dir.path(), TaskType::Cron).unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].id, 104);
    }
}

#[cfg(test)]
mod running_tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_env() -> TempDir {
        let dir = TempDir::new().unwrap();
        let task_dir = dir.path().join("task");
        fs::create_dir_all(&task_dir).unwrap();
        dir
    }

    #[test]
    fn test_setup_running_task() {
        let dir = create_test_env();
        let result = RunningTaskManager::setup(dir.path(), 10);
        assert!(result.is_ok());
        let cron_line = result.unwrap();
        assert!(cron_line.contains("*/10"));
    }

    #[test]
    fn test_remove_running_task() {
        let dir = create_test_env();
        let running_file = dir.path().join("task/running");
        fs::write(&running_file, "106#test#Test\n").unwrap();

        let result = RunningTaskManager::remove(dir.path(), 106);
        assert!(result.is_ok());

        let tasks = TaskManager::load_tasks(dir.path(), TaskType::Running).unwrap();
        assert!(tasks.is_empty());
    }
}

#[cfg(test)]
mod task_user_tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    fn create_test_env() -> TempDir {
        let dir = TempDir::new().unwrap();
        let task_dir = dir.path().join("task");
        fs::create_dir_all(&task_dir).unwrap();
        dir
    }

    #[test]
    fn test_add_user_task() {
        let dir = create_test_env();
        let result = TaskUserManager::add(dir.path(), "echo hello", "Test command");
        assert!(result.is_ok());
        let id = result.unwrap();
        assert!(id >= 200);
    }

    #[test]
    fn test_list_user_tasks() {
        let dir = create_test_env();
        let task_user_file = dir.path().join("task/task.user");
        fs::write(&task_user_file, "200#echo hello#Test\n").unwrap();

        let tasks = TaskUserManager::list(dir.path()).unwrap();
        assert_eq!(tasks.len(), 1);
        assert_eq!(tasks[0].command, "echo hello");
    }

    #[test]
    fn test_del_user_task() {
        let dir = create_test_env();
        let task_user_file = dir.path().join("task/task.user");
        fs::write(&task_user_file, "200#echo hello#Test\n").unwrap();

        TaskUserManager::del(dir.path(), 200).unwrap();

        let tasks = TaskUserManager::list(dir.path()).unwrap();
        assert!(tasks.is_empty());
    }
}

#[cfg(test)]
mod cronset_tests {
    #[test]
    fn test_cronset_keyword_filtering() {
        let current = "0 * * * * some_task\n0 4 * * * keyword_entry\n";
        let filtered: String = current
            .lines()
            .filter(|line| !line.contains("keyword_entry"))
            .collect::<Vec<_>>()
            .join("\n");

        assert!(!filtered.contains("keyword_entry"));
        assert!(filtered.contains("some_task"));
    }
}
