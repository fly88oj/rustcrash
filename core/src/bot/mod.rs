//! Telegram bot for remote control and monitoring, mirroring ShellCrash's
//! `tg_bot` behaviour: long polling, inline-keyboard menus, chat-ID
//! whitelist, log retrieval and file transfer.

pub mod api;

use crate::config::{Config, ConfigManager};
use crate::error::{Error, Result};
use crate::firewall::Firewall;
use crate::platform::Platform;
use crate::service::ServiceManager;
use crate::task::subscription::SubscriptionUpdater;
use api::{HttpTgApi, TgApi, TgUpdate, TELEGRAM_API_BASE};
use std::fs;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

/// Bot credentials and access list. The token is only ever read from the
/// config file or the `RUSTCRASH_TGBOT_TOKEN` environment variable.
#[derive(Debug, Clone)]
pub struct BotConfig {
    pub token: String,
    pub chat_ids: Vec<i64>,
    pub enabled: bool,
}

impl BotConfig {
    pub fn from_config(cfg: &Config) -> Self {
        let token = std::env::var("RUSTCRASH_TGBOT_TOKEN")
            .ok()
            .filter(|t| !t.trim().is_empty())
            .or_else(|| cfg.tgbot_token.clone().filter(|t| !t.trim().is_empty()))
            .unwrap_or_default();
        BotConfig {
            token,
            chat_ids: cfg.tgbot_chat_ids.clone(),
            enabled: cfg.tgbot_enable,
        }
    }

    pub fn is_ready(&self) -> bool {
        self.enabled && !self.token.is_empty() && !self.chat_ids.is_empty()
    }
}

/// Pending input the bot is waiting for, persisted across restarts.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BotAwait {
    None,
    /// Waiting for a subscription URL.
    Sub,
    /// Waiting for a file upload of the given kind.
    Upload(UploadKind),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UploadKind {
    Core,
    Backup,
    Config,
}

impl UploadKind {
    fn as_str(&self) -> &'static str {
        match self {
            UploadKind::Core => "core",
            UploadKind::Backup => "bak",
            UploadKind::Config => "ccf",
        }
    }

    fn from_str(s: &str) -> Option<Self> {
        match s {
            "core" => Some(UploadKind::Core),
            "bak" => Some(UploadKind::Backup),
            "ccf" => Some(UploadKind::Config),
            _ => None,
        }
    }
}

/// Display name for a kernel identifier, following ShellCrash's menu style.
pub fn kernel_display_name(kernel: &str) -> &str {
    match kernel {
        "mihomo" => "Mihomo",
        "sing-box" => "SingBox",
        other => other,
    }
}

/// Main menu inline keyboard (same actions as ShellCrash's bot).
pub fn main_keyboard() -> serde_json::Value {
    serde_json::json!({
        "inline_keyboard": [
            [
                {"text": "▶ Enable Hijack", "callback_data": "start_redir"},
                {"text": "■ Pure Mode", "callback_data": "stop_redir"},
                {"text": "🔄 Restart Kernel", "callback_data": "restart"}
            ],
            [
                {"text": "🌀 Update Subscriptions", "callback_data": "refresh"},
                {"text": "📝 Add Subscription", "callback_data": "set_sub"}
            ],
            [
                {"text": "📄 Read Logs", "callback_data": "readlog"},
                {"text": "📁 File Transfer", "callback_data": "transport"}
            ]
        ]
    })
}

/// File-transfer submenu: download or upload logs/backups/configs.
pub fn transport_keyboard() -> serde_json::Value {
    serde_json::json!({
        "inline_keyboard": [
            [
                {"text": "⬇ Get Logs", "callback_data": "ts_get_log"},
                {"text": "⬇ Get Backup", "callback_data": "ts_get_bak"},
                {"text": "⬇ Get Config", "callback_data": "ts_get_ccf"}
            ],
            [
                {"text": "⬆ Upload Kernel", "callback_data": "ts_up_core"},
                {"text": "⬆ Upload Backup", "callback_data": "ts_up_bak"},
                {"text": "⬆ Upload Config", "callback_data": "ts_up_ccf"}
            ],
            [
                {"text": "↩ Back", "callback_data": "noop"}
            ]
        ]
    })
}

/// Bot commands registered with Telegram (shown as `/crash` and `/help`).
pub fn bot_commands() -> serde_json::Value {
    serde_json::json!([
        {"command": "crash", "description": "Show the RustCrash menu"},
        {"command": "help", "description": "Show help"}
    ])
}

pub const HELP_TEXT: &str = "\
*RustCrash Telegram Bot*

/crash - show the control menu
/help - show this help

Project: https://github.com/juewuy/ShellCrash (ShellCrash, the original)";

/// Long-poll timeout in seconds, matching ShellCrash.
const POLL_TIMEOUT_SECS: u64 = 25;

pub struct TelegramBot {
    api: Arc<dyn TgApi>,
    cfg: BotConfig,
    platform: Platform,
    state_path: PathBuf,
    log_path: PathBuf,
}

impl TelegramBot {
    pub fn new(api: Arc<dyn TgApi>, cfg: BotConfig, platform: &Platform) -> Self {
        Self::with_paths(
            api,
            cfg,
            platform,
            PathBuf::from("/tmp/rustcrash/tgbot_state"),
            PathBuf::from("/tmp/rustcrash/tgbot.log"),
        )
    }

    /// Constructor with explicit state/log paths (used by tests and embedders).
    pub fn with_paths(
        api: Arc<dyn TgApi>,
        cfg: BotConfig,
        platform: &Platform,
        state_path: PathBuf,
        log_path: PathBuf,
    ) -> Self {
        TelegramBot {
            api,
            cfg,
            platform: platform.clone(),
            state_path,
            log_path,
        }
    }

    /// Build a bot backed by the real Telegram API from a loaded config.
    pub fn from_config(cfg: &Config, platform: &Platform) -> Result<Self> {
        let bot_cfg = BotConfig::from_config(cfg);
        if !bot_cfg.is_ready() {
            return Err(Error::Bot(
                "bot is not configured: need token, chat ids and enabled=true".into(),
            ));
        }
        api::validate_token(&bot_cfg.token)?;
        let api = HttpTgApi::new(TELEGRAM_API_BASE, &bot_cfg.token)?;
        Ok(Self::new(Arc::new(api), bot_cfg, platform))
    }

    /// Whitelist check — unauthorized chats are dropped silently.
    pub fn is_authorized(&self, chat_id: i64) -> bool {
        self.cfg.chat_ids.contains(&chat_id)
    }

    /// Register commands, then poll forever. Intended to run as a tokio task.
    pub async fn run(&self) -> Result<()> {
        if let Err(e) = self.api.set_my_commands(bot_commands()).await {
            tracing::warn!("failed to register bot commands: {e}");
        }
        let mut offset: u64 = 0;
        loop {
            match self.poll_once(offset).await {
                Ok(next) => offset = next,
                Err(e) => {
                    tracing::error!("bot poll failed: {e}");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }

    /// Fetch one batch of updates, dispatch them, return the next offset.
    pub async fn poll_once(&self, offset: u64) -> Result<u64> {
        let updates = self.api.get_updates(offset, POLL_TIMEOUT_SECS).await?;
        let mut next = offset;
        for upd in &updates {
            next = next.max(upd.update_id + 1);
            self.dispatch(upd).await;
        }
        Ok(next)
    }

    async fn dispatch(&self, upd: &TgUpdate) {
        let Some(chat_id) = upd.chat_id() else {
            return;
        };
        if !self.is_authorized(chat_id) {
            tracing::warn!("dropping update from unauthorized chat {chat_id}");
            return;
        }
        if let Some(cq) = &upd.callback_query {
            if !cq.id.is_empty() {
                let _ = self.api.answer_callback(&cq.id).await;
            }
            if let Some(data) = cq.data.as_deref() {
                self.on_callback(chat_id, data).await;
            }
            return;
        }
        if let Some(doc) = upd.document() {
            if !doc.file_id.is_empty() {
                self.on_document(chat_id, doc.file_id.clone(), doc.file_name.clone())
                    .await;
            }
            return;
        }
        if let Some(text) = upd.text() {
            self.on_text(chat_id, text).await;
        }
    }

    async fn on_text(&self, chat_id: i64, text: &str) {
        let text = text.trim();
        match self.read_state() {
            BotAwait::Sub => {
                self.write_state(BotAwait::None);
                self.add_subscription(chat_id, text).await;
            }
            BotAwait::Upload(_kind) => {
                // A text message cancels a pending upload.
                self.write_state(BotAwait::None);
                let _ = self
                    .api
                    .send_message(chat_id, "Upload cancelled.", None)
                    .await;
            }
            BotAwait::None => match text {
                "/crash" | "/start" => self.send_menu(chat_id).await,
                "/help" => {
                    let _ = self.api.send_message(chat_id, HELP_TEXT, None).await;
                }
                _ => {}
            },
        }
    }

    async fn on_callback(&self, chat_id: i64, data: &str) {
        let config = self.load_config();
        match data {
            "start_redir" => {
                if config.mode == "Pure" {
                    self.do_start_redir(chat_id, &config).await;
                } else {
                    let _ = self
                        .api
                        .send_message(chat_id, &format!("Already in {} mode.", config.mode), None)
                        .await;
                    self.send_menu(chat_id).await;
                }
            }
            "stop_redir" => {
                if config.mode != "Pure" {
                    self.do_stop_redir(chat_id, &config).await;
                } else {
                    let _ = self
                        .api
                        .send_message(chat_id, "Already in Pure mode.", None)
                        .await;
                    self.send_menu(chat_id).await;
                }
            }
            "restart" => {
                self.do_restart(chat_id).await;
            }
            "refresh" => {
                self.do_refresh(chat_id).await;
            }
            "readlog" | "ts_get_log" => {
                self.send_log_document(chat_id).await;
            }
            "transport" => {
                let _ = self
                    .api
                    .send_message(
                        chat_id,
                        "File transfer — choose an action:",
                        Some(transport_keyboard()),
                    )
                    .await;
            }
            "set_sub" => {
                self.write_state(BotAwait::Sub);
                let _ = self
                    .api
                    .send_message(chat_id, "Send the new subscription URL:", None)
                    .await;
            }
            "ts_get_bak" => {
                self.send_backup_document(chat_id).await;
            }
            "ts_get_ccf" => {
                self.send_config_document(chat_id).await;
            }
            "ts_up_core" | "ts_up_bak" | "ts_up_ccf" => {
                let kind =
                    UploadKind::from_str(&data["ts_up_".len()..]).unwrap_or(UploadKind::Config);
                self.write_state(BotAwait::Upload(kind));
                let what = match kind {
                    UploadKind::Core => "kernel binary",
                    UploadKind::Backup => "backup archive",
                    UploadKind::Config => "kernel config",
                };
                let _ = self
                    .api
                    .send_message(chat_id, &format!("Send the {what} as a file:"), None)
                    .await;
            }
            "noop" => {
                self.send_menu(chat_id).await;
            }
            _ => {}
        }
    }

    // ----- menu / status -----

    /// Fresh config for each action (the bot's own writes must be visible
    /// immediately); parse failures are logged, never fatal.
    fn load_config(&self) -> Config {
        match ConfigManager::new(&self.platform).load() {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("config load failed, using defaults: {e}");
                Config::default()
            }
        }
    }

    /// Status menu text: version, kernel, running state, memory, uptime.
    pub fn status_text(&self) -> String {
        let config = self.load_config();
        let kernel = config.active_kernel();
        let sm = ServiceManager::new(&self.platform);
        let status = sm.status(kernel);

        let (run, mem, up) = if status.running {
            ("Running", status.memory_display(), status.uptime_display())
        } else {
            ("Stopped", String::new(), String::new())
        };
        let name = kernel_display_name(&config.kernel);
        format!(
            "*Welcome to RustCrash!* Version: {}\n{} service: {}  [{}]\nMemory: {}  Uptime: {}\nChoose an action:",
            env!("CARGO_PKG_VERSION"),
            name,
            run,
            config.mode,
            mem,
            up
        )
    }

    async fn send_menu(&self, chat_id: i64) {
        let text = self.status_text();
        let _ = self
            .api
            .send_message(chat_id, &text, Some(main_keyboard()))
            .await;
    }

    // ----- actions -----

    async fn do_start_redir(&self, chat_id: i64, config: &Config) {
        let mut new_cfg = config.clone();
        new_cfg.mode = if new_cfg.mode_before_pure.is_empty() {
            "Router".to_string()
        } else {
            new_cfg.mode_before_pure.clone()
        };
        let cm = ConfigManager::new(&self.platform);
        let _ = cm.save(&new_cfg);

        // The config's firewall fields are the single source of truth —
        // the same apply_full path the CLI uses.
        let platform = self.platform.clone();
        let fw_config = new_cfg.to_firewall_config();
        let res = tokio::task::spawn_blocking(move || {
            let fw_config = fw_config?;
            Firewall::new(&platform).apply_full(&fw_config)
        })
        .await;

        let msg = match res {
            Ok(Ok(())) => format!("Switched to {} mode!", new_cfg.mode),
            Ok(Err(e)) => format!("Firewall setup failed: {e}"),
            Err(e) => format!("Internal error: {e}"),
        };
        self.log_action(&msg);
        let _ = self.api.send_message(chat_id, &msg, None).await;
        self.send_menu(chat_id).await;
    }

    async fn do_stop_redir(&self, chat_id: i64, config: &Config) {
        let mut new_cfg = config.clone();
        if new_cfg.mode != "Pure" {
            new_cfg.mode_before_pure = new_cfg.mode.clone();
        }
        new_cfg.mode = "Pure".to_string();
        let cm = ConfigManager::new(&self.platform);
        let _ = cm.save(&new_cfg);

        let platform = self.platform.clone();
        let res = tokio::task::spawn_blocking(move || Firewall::new(&platform).cleanup()).await;

        let msg = match res {
            Ok(Ok(())) => "Switched to Pure mode.".to_string(),
            Ok(Err(e)) => format!("Firewall cleanup failed: {e}"),
            Err(e) => format!("Internal error: {e}"),
        };
        self.log_action(&msg);
        let _ = self.api.send_message(chat_id, &msg, None).await;
        self.send_menu(chat_id).await;
    }

    async fn do_restart(&self, chat_id: i64) {
        let config = self.load_config();
        let kernel = config.active_kernel();
        let sm = ServiceManager::new(&self.platform);
        let res = sm.restart(kernel).await;

        let msg = match res {
            Ok(pid) => format!("Service restarted (PID {pid})."),
            Err(e) => format!("Restart failed: {e}"),
        };
        self.log_action(&msg);
        let _ = self.api.send_message(chat_id, &msg, None).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
        self.send_menu(chat_id).await;
    }

    async fn do_refresh(&self, chat_id: i64) {
        let crash_dir = PathBuf::from(self.platform.crash_dir());
        // update_all builds its own tokio runtime, so it must stay off the
        // async worker threads.
        let res =
            tokio::task::spawn_blocking(move || SubscriptionUpdater::update_all(&crash_dir)).await;

        let msg = match res {
            Ok(Ok(report)) => {
                let text = if report.updated.is_empty() && report.failed.is_empty() {
                    "No subscriptions configured.".to_string()
                } else {
                    format!(
                        "Updated: {}  Failed: {}",
                        report.updated.join(", "),
                        report
                            .failed
                            .iter()
                            .map(|(n, e)| format!("{n}: {e}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    )
                };
                text
            }
            Ok(Err(e)) => format!("Update failed: {e}"),
            Err(e) => format!("Internal error: {e}"),
        };
        self.log_action(&msg);
        let _ = self
            .api
            .send_message(chat_id, &format!("Subscription refresh done.\n{msg}"), None)
            .await;
        self.send_menu(chat_id).await;
    }

    async fn add_subscription(&self, chat_id: i64, url: &str) {
        let validation = crate::subscription::SubscriptionManager::validate_url(url);
        if !validation.is_valid {
            let _ = self
                .api
                .send_message(chat_id, "Invalid subscription URL.", None)
                .await;
            return;
        }
        let cm = ConfigManager::new(&self.platform);
        let mut config = match cm.load() {
            Ok(c) => c,
            Err(e) => {
                let _ = self
                    .api
                    .send_message(chat_id, &format!("Config load failed: {e}"), None)
                    .await;
                return;
            }
        };
        let name = format!("sub{}", config.subscriptions.len() + 1);
        config.subscriptions.push(crate::config::Subscription {
            name,
            url: url.to_string(),
            updated_at: None,
            raw_config: None,
        });
        if let Err(e) = cm.save(&config) {
            let _ = self
                .api
                .send_message(chat_id, &format!("Config save failed: {e}"), None)
                .await;
            return;
        }
        let _ = self
            .api
            .send_message(
                chat_id,
                "Subscription added. Use Update Subscriptions to fetch it.",
                None,
            )
            .await;
        self.send_menu(chat_id).await;
    }

    // ----- file transfer -----

    /// Tail of the most recent kernel log, capped to keep uploads small.
    fn log_tail(&self) -> Option<Vec<u8>> {
        let path =
            crate::logging::newest_file(std::path::Path::new(&self.platform.log_dir()), |n| {
                n.ends_with(".log")
            })?;
        let content = fs::read(path).ok()?;
        const MAX: usize = 64 * 1024;
        if content.len() > MAX {
            // Back up to a char boundary so the first byte we keep is not
            // mid-UTF-8-sequence.
            let mut start = content.len() - MAX;
            while start < content.len() && (content[start] & 0xC0) == 0x80 {
                start += 1;
            }
            Some(content[start..].to_vec())
        } else {
            Some(content)
        }
    }

    async fn send_log_document(&self, chat_id: i64) {
        match self.log_tail() {
            Some(content) => {
                let _ = self
                    .api
                    .send_document(chat_id, "rustcrash.log", content)
                    .await;
            }
            None => {
                let _ = self
                    .api
                    .send_message(chat_id, "No log file found.", None)
                    .await;
            }
        }
    }

    async fn send_backup_document(&self, chat_id: i64) {
        let backup_dir = format!("{}/backup", self.platform.crash_dir());
        match crate::logging::newest_file(std::path::Path::new(&backup_dir), |n| {
            n.ends_with(".tar.gz") || n.ends_with(".gz")
        }) {
            Some(path) => {
                if let Ok(content) = fs::read(&path) {
                    let name = path
                        .file_name()
                        .and_then(|n| n.to_str())
                        .unwrap_or("backup.tar.gz")
                        .to_string();
                    let _ = self.api.send_document(chat_id, &name, content).await;
                } else {
                    let _ = self
                        .api
                        .send_message(chat_id, "Failed to read backup.", None)
                        .await;
                }
            }
            None => {
                let _ = self
                    .api
                    .send_message(chat_id, "No backup found.", None)
                    .await;
            }
        }
    }

    async fn send_config_document(&self, chat_id: i64) {
        let config = self.load_config();
        let kernel = config.active_kernel();
        let path = ConfigManager::new(&self.platform).kernel_config_path(kernel);
        match fs::read_to_string(&path) {
            Ok(content) => {
                let name = PathBuf::from(&path)
                    .file_name()
                    .and_then(|n| n.to_str())
                    .unwrap_or("config.yaml")
                    .to_string();
                let _ = self
                    .api
                    .send_document(chat_id, &name, content.into_bytes())
                    .await;
            }
            Err(_) => {
                let _ = self
                    .api
                    .send_message(chat_id, "No kernel config found.", None)
                    .await;
            }
        }
    }

    async fn on_document(&self, chat_id: i64, file_id: String, file_name: Option<String>) {
        let state = self.read_state();
        let BotAwait::Upload(kind) = state else {
            let _ = self
                .api
                .send_message(
                    chat_id,
                    "Not waiting for a file. Use File Transfer first.",
                    None,
                )
                .await;
            return;
        };
        self.write_state(BotAwait::None);

        // Only the final path component is kept — no traversal via filenames.
        let safe_name = file_name
            .as_deref()
            .map(|n| {
                PathBuf::from(n)
                    .file_name()
                    .and_then(|f| f.to_str())
                    .unwrap_or("upload.bin")
                    .to_string()
            })
            .unwrap_or_else(|| "upload.bin".to_string());

        let download = match self.api.get_file_path(&file_id).await {
            Ok(path) => self.api.download_file(&path).await,
            Err(e) => Err(e),
        };
        let content = match download {
            Ok(c) => c,
            Err(e) => {
                let _ = self
                    .api
                    .send_message(chat_id, &format!("Download failed: {e}"), None)
                    .await;
                return;
            }
        };

        let target = self.upload_target(kind, &safe_name);
        let write_result = target.and_then(|path| {
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            fs::write(&path, &content)?;
            if kind == UploadKind::Core {
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&path, fs::Permissions::from_mode(0o755))?;
                }
            }
            Ok(path)
        });

        let msg = match write_result {
            Ok(path) => format!("Saved to {}", path.display()),
            Err(e) => format!("Save failed: {e}"),
        };
        self.log_action(&msg);
        let _ = self.api.send_message(chat_id, &msg, None).await;
        self.send_menu(chat_id).await;
    }

    fn upload_target(&self, kind: UploadKind, safe_name: &str) -> Result<PathBuf> {
        let config = self.load_config();
        match kind {
            UploadKind::Core => {
                let km = crate::kernels::KernelManager::new(&self.platform);
                Ok(PathBuf::from(km.kernel_path(config.active_kernel())))
            }
            UploadKind::Backup => Ok(PathBuf::from(format!(
                "{}/backup/{safe_name}",
                self.platform.crash_dir()
            ))),
            UploadKind::Config => Ok(PathBuf::from(
                ConfigManager::new(&self.platform).kernel_config_path(config.active_kernel()),
            )),
        }
    }

    // ----- state & log persistence -----

    fn read_state(&self) -> BotAwait {
        match fs::read_to_string(&self.state_path) {
            Ok(s) if s.trim() == "await_sub" => BotAwait::Sub,
            Ok(s) if s.trim().starts_with("await_upload:") => BotAwait::Upload(
                UploadKind::from_str(&s.trim()["await_upload:".len()..])
                    .unwrap_or(UploadKind::Config),
            ),
            _ => BotAwait::None,
        }
    }

    fn write_state(&self, state: BotAwait) {
        if let Some(parent) = self.state_path.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let content: String = match state {
            BotAwait::None => String::new(),
            BotAwait::Sub => "await_sub".to_string(),
            BotAwait::Upload(kind) => format!("await_upload:{}", kind.as_str()),
        };
        let _ = fs::write(&self.state_path, content);
    }

    fn log_action(&self, msg: &str) {
        // Rotated append: the action log is capped like ShellCrash's logger.
        let _ = crate::logging::append_rotated(&self.log_path, msg);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use crate::platform::ProxyKernel;
    use api::{TgChat, TgMessage};
    use std::sync::Mutex;

    fn bot_config(chat_ids: Vec<i64>) -> BotConfig {
        BotConfig {
            // Placeholder token — never a real credential.
            token: "123456:TEST_TOKEN".to_string(),
            chat_ids,
            enabled: true,
        }
    }

    /// In-memory API mock that records outgoing traffic.
    struct MockApi {
        messages: Mutex<Vec<(i64, String, bool)>>,
        documents: Mutex<Vec<(i64, String, Vec<u8>)>>,
        updates: Vec<TgUpdate>,
    }

    impl MockApi {
        fn with_updates(updates: Vec<TgUpdate>) -> Arc<Self> {
            Arc::new(MockApi {
                messages: Mutex::new(Vec::new()),
                documents: Mutex::new(Vec::new()),
                updates,
            })
        }

        fn texts(&self) -> Vec<String> {
            self.messages
                .lock()
                .unwrap()
                .iter()
                .map(|(_, t, _)| t.clone())
                .collect()
        }
    }

    impl TgApi for MockApi {
        fn get_updates(&self, _offset: u64, _t: u64) -> api::BoxFut<Result<Vec<TgUpdate>>> {
            let updates = self.updates.clone();
            Box::pin(async move { Ok(updates) })
        }
        fn send_message(
            &self,
            chat_id: i64,
            text: &str,
            keyboard: Option<serde_json::Value>,
        ) -> api::BoxFut<Result<()>> {
            self.messages
                .lock()
                .unwrap()
                .push((chat_id, text.to_string(), keyboard.is_some()));
            Box::pin(async move { Ok(()) })
        }
        fn send_document(
            &self,
            chat_id: i64,
            filename: &str,
            content: Vec<u8>,
        ) -> api::BoxFut<Result<()>> {
            self.documents
                .lock()
                .unwrap()
                .push((chat_id, filename.to_string(), content));
            Box::pin(async move { Ok(()) })
        }
        fn answer_callback(&self, _id: &str) -> api::BoxFut<Result<()>> {
            Box::pin(async move { Ok(()) })
        }
        fn set_my_commands(&self, _c: serde_json::Value) -> api::BoxFut<Result<()>> {
            Box::pin(async move { Ok(()) })
        }
        fn get_file_path(&self, _file_id: &str) -> api::BoxFut<Result<String>> {
            Box::pin(async move { Ok("documents/file.bin".into()) })
        }
        fn download_file(&self, _path: &str) -> api::BoxFut<Result<Vec<u8>>> {
            Box::pin(async move { Ok(b"payload".to_vec()) })
        }
    }

    fn test_bot(api: Arc<MockApi>, chat_ids: Vec<i64>) -> (TelegramBot, PathBuf, PathBuf) {
        // keep(): the directory outlives the TempDir guard for the whole test.
        let tmp = tempfile::TempDir::new().unwrap().keep();
        let platform = Platform::for_crash_dir(tmp.to_str().unwrap());
        let state = tmp.join("state");
        let log = tmp.join("bot.log");
        let bot = TelegramBot::with_paths(
            api,
            bot_config(chat_ids),
            &platform,
            state.clone(),
            log.clone(),
        );
        (bot, state, log)
    }

    fn msg_update(id: u64, chat_id: i64, text: &str) -> TgUpdate {
        TgUpdate {
            update_id: id,
            message: Some(TgMessage {
                message_id: 1,
                chat: TgChat { id: chat_id },
                text: Some(text.to_string()),
                document: None,
            }),
            callback_query: None,
        }
    }

    // -- pure helpers --

    #[test]
    fn kernel_display_names() {
        assert_eq!(kernel_display_name("mihomo"), "Mihomo");
        assert_eq!(kernel_display_name("sing-box"), "SingBox");
    }

    #[test]
    fn bot_config_reads_env_token_first() {
        // SAFETY: single-threaded test mutation of env.
        unsafe { std::env::set_var("RUSTCRASH_TGBOT_TOKEN", "111:ENV") };
        let cfg = BotConfig::from_config(&Config::default());
        assert_eq!(cfg.token, "111:ENV");
        unsafe { std::env::remove_var("RUSTCRASH_TGBOT_TOKEN") };

        let c = Config {
            tgbot_token: Some("222:CFG".into()),
            tgbot_enable: true,
            tgbot_chat_ids: vec![42],
            ..Default::default()
        };
        let cfg = BotConfig::from_config(&c);
        assert_eq!(cfg.token, "222:CFG");
        assert!(cfg.is_ready());
    }

    #[test]
    fn bot_config_not_ready_when_disabled() {
        let cfg = BotConfig::from_config(&Config::default());
        assert!(!cfg.is_ready());
    }

    #[test]
    fn upload_kind_roundtrip() {
        for k in [UploadKind::Core, UploadKind::Backup, UploadKind::Config] {
            assert_eq!(UploadKind::from_str(k.as_str()), Some(k));
        }
        assert_eq!(UploadKind::from_str("nope"), None);
    }

    // -- whitelist & dispatch --

    #[tokio::test]
    async fn unauthorized_chat_is_dropped() {
        let api = MockApi::with_updates(vec![msg_update(1, 999, "/crash")]);
        let (bot, _, _) = test_bot(api.clone(), vec![100]);
        let next = bot.poll_once(0).await.unwrap();
        assert_eq!(next, 2);
        assert!(api.texts().is_empty(), "no reply to unauthorized chat");
    }

    #[tokio::test]
    async fn crash_command_sends_menu() {
        let api = MockApi::with_updates(vec![msg_update(3, 100, "/crash")]);
        let (bot, _, _) = test_bot(api.clone(), vec![100]);
        bot.poll_once(0).await.unwrap();
        let texts = api.texts();
        assert!(texts[0].contains("Welcome to RustCrash"));
        assert!(texts[0].contains("Mihomo"));
    }

    #[tokio::test]
    async fn help_command_replies() {
        let api = MockApi::with_updates(vec![msg_update(1, 100, "/help")]);
        let (bot, _, _) = test_bot(api.clone(), vec![100]);
        bot.poll_once(0).await.unwrap();
        assert!(api.texts()[0].contains("/crash"));
    }

    #[tokio::test]
    async fn start_command_shows_menu() {
        let api = MockApi::with_updates(vec![msg_update(1, 100, "/start")]);
        let (bot, _, _) = test_bot(api.clone(), vec![100]);
        bot.poll_once(0).await.unwrap();
        assert!(api.texts()[0].contains("Welcome to RustCrash"));
    }

    #[tokio::test]
    async fn unknown_text_is_ignored() {
        let api = MockApi::with_updates(vec![msg_update(1, 100, "hello there")]);
        let (bot, _, _) = test_bot(api.clone(), vec![100]);
        bot.poll_once(0).await.unwrap();
        assert!(api.texts().is_empty());
    }

    #[tokio::test]
    async fn offset_advances_to_last_update_plus_one() {
        let api = MockApi::with_updates(vec![msg_update(5, 100, "x"), msg_update(9, 100, "y")]);
        let (bot, _, _) = test_bot(api, vec![100]);
        let next = bot.poll_once(0).await.unwrap();
        assert_eq!(next, 10);
    }

    // -- set_sub flow --

    #[tokio::test]
    async fn set_sub_prompts_then_saves_url() {
        let api = MockApi::with_updates(vec![]);
        let (bot, state, _) = test_bot(api.clone(), vec![100]);

        bot.on_callback(100, "set_sub").await;
        assert_eq!(bot.read_state(), BotAwait::Sub);
        assert!(api.texts()[0].contains("subscription URL"));

        bot.on_text(100, "https://example.com/sub?token=x").await;
        assert_eq!(bot.read_state(), BotAwait::None);
        // Config now contains the subscription.
        let platform = bot.platform.clone();
        let cfg = ConfigManager::new(&platform).load().unwrap();
        assert_eq!(cfg.subscriptions.len(), 1);
        assert_eq!(cfg.subscriptions[0].url, "https://example.com/sub?token=x");
        assert!(state.exists());
    }

    #[tokio::test]
    async fn set_sub_rejects_invalid_url() {
        let api = MockApi::with_updates(vec![]);
        let (bot, _, _) = test_bot(api.clone(), vec![100]);
        bot.on_callback(100, "set_sub").await;
        bot.on_text(100, "not a url").await;
        assert!(api
            .texts()
            .iter()
            .any(|t| t.contains("Invalid subscription URL")));
        let platform = bot.platform.clone();
        let cfg = ConfigManager::new(&platform).load().unwrap();
        assert!(cfg.subscriptions.is_empty());
    }

    // -- upload flow --

    #[tokio::test]
    async fn upload_flow_saves_file_and_clears_state() {
        let api = MockApi::with_updates(vec![]);
        let (bot, _, _) = test_bot(api.clone(), vec![100]);

        bot.on_callback(100, "ts_up_ccf").await;
        assert_eq!(bot.read_state(), BotAwait::Upload(UploadKind::Config));

        // Kernel config must exist for the upload target to resolve.
        let platform = bot.platform.clone();
        let cm = ConfigManager::new(&platform);
        let cfg_path = cm.kernel_config_path(ProxyKernel::Mihomo);
        std::fs::create_dir_all(std::path::Path::new(&cfg_path).parent().unwrap()).unwrap();
        std::fs::write(&cfg_path, "old: true").unwrap();

        bot.on_document(100, "file1".into(), Some("../../etc/passwd".into()))
            .await;
        assert_eq!(bot.read_state(), BotAwait::None);
        let texts = api.texts();
        assert!(texts.iter().any(|t| t.contains("Saved to")), "{texts:?}");
        // Traversal name was sanitized to the final component only.
        assert!(std::fs::read_to_string(&cfg_path).unwrap() == "payload");
    }

    #[tokio::test]
    async fn document_without_pending_upload_is_rejected() {
        let api = MockApi::with_updates(vec![]);
        let (bot, _, _) = test_bot(api.clone(), vec![100]);
        bot.on_document(100, "file1".into(), Some("x.bin".into()))
            .await;
        assert!(api
            .texts()
            .iter()
            .any(|t| t.contains("Not waiting for a file")));
    }

    // -- menus & misc --

    #[tokio::test]
    async fn transport_menu_sent_on_callback() {
        let api = MockApi::with_updates(vec![]);
        let (bot, _, _) = test_bot(api.clone(), vec![100]);
        bot.on_callback(100, "transport").await;
        assert!(api.texts()[0].contains("File transfer"));
    }

    #[tokio::test]
    async fn noop_callback_returns_to_menu() {
        let api = MockApi::with_updates(vec![]);
        let (bot, _, _) = test_bot(api.clone(), vec![100]);
        bot.on_callback(100, "noop").await;
        assert!(api.texts()[0].contains("Welcome to RustCrash"));
    }

    #[tokio::test]
    async fn readlog_without_logs_sends_notice() {
        let api = MockApi::with_updates(vec![]);
        let (bot, _, _) = test_bot(api.clone(), vec![100]);
        bot.on_callback(100, "readlog").await;
        assert!(api.texts().iter().any(|t| t.contains("No log file found")));
    }

    #[tokio::test]
    async fn readlog_sends_document_tail() {
        let api = MockApi::with_updates(vec![]);
        let (bot, _, _) = test_bot(api.clone(), vec![100]);
        let log_dir = bot.platform.log_dir();
        std::fs::create_dir_all(&log_dir).unwrap();
        std::fs::write(format!("{log_dir}/mihomo.log"), "line1\nline2\n").unwrap();
        bot.on_callback(100, "readlog").await;
        let docs = api.documents.lock().unwrap();
        assert_eq!(docs.len(), 1);
        assert_eq!(docs[0].1, "rustcrash.log");
        assert_eq!(docs[0].2, b"line1\nline2\n");
    }

    #[tokio::test]
    async fn status_text_shows_mode_and_kernel() {
        let api = MockApi::with_updates(vec![]);
        let (bot, _, _) = test_bot(api, vec![100]);
        let text = bot.status_text();
        assert!(text.contains("Mihomo"));
        assert!(text.contains("[Router]"));
    }

    #[tokio::test]
    async fn state_file_roundtrip() {
        let api = MockApi::with_updates(vec![]);
        let (bot, _, _) = test_bot(api, vec![100]);
        bot.write_state(BotAwait::Sub);
        assert_eq!(bot.read_state(), BotAwait::Sub);
        bot.write_state(BotAwait::Upload(UploadKind::Core));
        assert_eq!(bot.read_state(), BotAwait::Upload(UploadKind::Core));
        bot.write_state(BotAwait::None);
        assert_eq!(bot.read_state(), BotAwait::None);
    }

    #[tokio::test]
    async fn from_config_requires_full_configuration() {
        let platform = Platform::for_crash_dir("/tmp/rustcrash-bot-test");
        assert!(TelegramBot::from_config(&Config::default(), &platform).is_err());
        let c = Config {
            tgbot_enable: true,
            tgbot_token: Some("123:abc".into()),
            tgbot_chat_ids: vec![1],
            ..Default::default()
        };
        assert!(TelegramBot::from_config(&c, &platform).is_ok());
    }
}
