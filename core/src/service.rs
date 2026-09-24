//! Kernel service lifecycle management.
//!
//! Shared by CLI binaries and the Telegram bot: start/stop/restart the proxy
//! kernel and query runtime status (PID, memory, uptime). The kernel is
//! spawned with an argument vector (no shell), after both the binary path and
//! config path have been validated and canonicalized.

use crate::error::{Error, Result};
use crate::kernels::KernelManager;
use crate::platform::{Platform, ProxyKernel};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Runtime status of the proxy kernel process.
#[derive(Debug, Clone, PartialEq)]
pub struct ServiceStatus {
    pub kernel: ProxyKernel,
    pub running: bool,
    pub pid: Option<u32>,
    /// Resident memory in MB, from `/proc/<pid>/status`.
    pub memory_mb: Option<f64>,
    /// Seconds since the kernel was started, from the start-time file.
    pub uptime_secs: Option<u64>,
}

impl ServiceStatus {
    /// Uptime formatted as `Xd Xh Xm Xs` with the day part omitted when zero,
    /// matching ShellCrash's bot display.
    pub fn uptime_display(&self) -> String {
        match self.uptime_secs {
            None => String::new(),
            Some(secs) => format_uptime(secs),
        }
    }

    /// Memory formatted as `X.XX MB`, mirroring ShellCrash's `VmRSS` output.
    pub fn memory_display(&self) -> String {
        match self.memory_mb {
            None => String::new(),
            Some(mb) => format!("{mb:.2} MB"),
        }
    }
}

/// Format seconds as `Xd Xh Xm Xs`; the day part is omitted when zero.
pub fn format_uptime(secs: u64) -> String {
    let days = secs / 86400;
    let hours = (secs % 86400) / 3600;
    let mins = (secs % 3600) / 60;
    let s = secs % 60;
    if days == 0 {
        format!("{hours}h {mins}m {s}s")
    } else {
        format!("{days}d {hours}h {mins}m {s}s")
    }
}

/// Validate that a path is safe to execute: absolute, canonicalized, and an
/// existing regular file. Prevents launching binaries from relative or
/// attacker-controlled locations.
pub(crate) fn validated_executable(path: &str) -> Result<PathBuf> {
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err(Error::Security(format!(
            "refusing to launch non-absolute kernel path: {path}"
        )));
    }
    let canonical = p
        .canonicalize()
        .map_err(|e| Error::Security(format!("kernel path {path} cannot be resolved: {e}")))?;
    if !canonical.is_file() {
        return Err(Error::Security(format!(
            "kernel path is not a regular file: {}",
            canonical.display()
        )));
    }
    Ok(canonical)
}

/// Config paths are data files (not executed), so they must exist and be
/// absolute but need not pass executable checks.
fn validated_config(path: &str) -> Result<PathBuf> {
    let p = Path::new(path);
    if !p.is_absolute() {
        return Err(Error::Security(format!(
            "refusing non-absolute config path: {path}"
        )));
    }
    if !p.is_file() {
        return Err(Error::Config(format!("kernel config not found: {path}")));
    }
    Ok(p.to_path_buf())
}

/// Manages the proxy kernel process lifecycle for one install directory.
pub struct ServiceManager {
    platform: Platform,
}

impl ServiceManager {
    pub fn new(platform: &Platform) -> Self {
        ServiceManager {
            platform: platform.clone(),
        }
    }

    fn run_dir(&self) -> String {
        format!("{}/run", self.platform.crash_dir())
    }

    fn pid_file(&self, kernel: ProxyKernel) -> String {
        format!("{}/{}.pid", self.run_dir(), kernel.binary_name())
    }

    /// The integrated Rust engine runs as a supervised self-spawn of this
    /// binary (`crash engine run …`), so its lifecycle mirrors a kernel's.
    fn engine_pid_file(&self) -> String {
        format!("{}/rustcrash-engine.pid", self.run_dir())
    }

    fn start_time_file(&self) -> String {
        format!("{}/crash_start_time", self.run_dir())
    }

    pub fn is_running(&self, kernel: ProxyKernel) -> bool {
        self.read_pid(kernel)
            .map(|pid| send_signal(pid, 0))
            .unwrap_or(false)
    }

    fn read_pid(&self, kernel: ProxyKernel) -> Option<u32> {
        let content = fs::read_to_string(self.pid_file(kernel)).ok()?;
        content.trim().parse::<u32>().ok()
    }

    /// Start the kernel if installed and not already running.
    /// Returns the new PID. Must be called inside a tokio runtime.
    pub async fn start(&self, kernel: ProxyKernel) -> Result<u32> {
        self.start_inner(kernel, true).await
    }

    /// `notify`: emit the "start" event (restart suppresses it and emits a
    /// single "restart" event instead).
    async fn start_inner(&self, kernel: ProxyKernel, notify: bool) -> Result<u32> {
        let km = KernelManager::new(&self.platform);
        if !km.is_installed(kernel) {
            return Err(Error::Process(format!(
                "{} is not installed; run crash install first",
                kernel.binary_name()
            )));
        }
        if let Some(pid) = self.read_pid(kernel) {
            if send_signal(pid, 0) {
                return Ok(pid);
            }
        }

        fs::create_dir_all(self.run_dir())?;

        let bin_path = validated_executable(&km.kernel_path(kernel))?;
        let config_path =
            crate::config::ConfigManager::new(&self.platform).kernel_config_path(kernel);
        let cfg_path = validated_config(&config_path)?;

        // Anti-loop identity (ShellCrash's crashgid): the firewall exempts
        // the kernel's OWN outbound connections via the supplementary gid
        // (7890), so the proxy never redirects its own node dials back
        // into itself. Ensure the group exists, then tag the child.
        ensure_crash_group();
        // Prefer a group actually holding gid 7890 — a leftover group
        // named 'rustcrash' with a DIFFERENT gid (from older versions)
        // would silently leave the exemption unmatched.
        let crash_gid = lookup_group_name_by_gid(CRASH_GID)
            .map(|_| CRASH_GID)
            .or_else(|| lookup_group_gid(CRASH_GID_NAME));
        if let Some(wrong) = crash_gid.filter(|g| *g != CRASH_GID) {
            tracing::warn!(
                "group {CRASH_GID_NAME} has gid {wrong}, but the firewall exempts gid \
                 {CRASH_GID}; the anti-loop exemption will NOT match"
            );
        }
        if crash_gid.is_none() {
            tracing::warn!(
                "starting {} without the anti-loop gid; its own outbound traffic \
                 may be redirected back into itself",
                kernel.binary_name()
            );
        }

        // Spawned with an argument vector — no shell is involved. The child
        // outlives this handle; dropping it does not kill the kernel.
        let mut cmd = tokio::process::Command::new(bin_path.as_os_str());
        cmd.arg("-f")
            .arg(cfg_path.as_os_str())
            .arg("-d")
            .arg(self.platform.log_dir());
        #[cfg(unix)]
        if let Some(gid) = crash_gid {
            unsafe {
                cmd.pre_exec(move || {
                    // Supplementary group only — uid/gid stay unchanged.
                    // setgroups returns errno on failure; surface it so the
                    // child aborts rather than starting untagged silently.
                    if libc::setgroups(1, [gid as libc::gid_t].as_ptr()) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let child = cmd.spawn().map_err(|e| {
            Error::Process(format!("failed to start {}: {e}", kernel.binary_name()))
        })?;
        let pid = child.id();

        if let Some(pid) = pid {
            fs::write(self.pid_file(kernel), pid.to_string())?;
            fs::write(self.start_time_file(), now_secs().to_string())?;
        }
        if notify {
            // Best-effort push notification for the "start" event.
            let nm = crate::notify::NotificationManager::from_platform(&self.platform);
            let name = kernel.binary_name().to_string();
            let pid_text = pid.unwrap_or(0).to_string();
            tokio::spawn(async move {
                nm.notify_event("start", &format!("{name} started (PID {pid_text})"))
                    .await;
            });
        }
        Ok(pid.unwrap_or(0))
    }

    /// Stop both kernels (SIGTERM, wait, then SIGKILL) and clean PID files.
    pub fn stop(&self) -> Result<()> {
        self.stop_inner(true)
    }

    fn stop_inner(&self, notify: bool) -> Result<()> {
        for kernel in [ProxyKernel::Mihomo, ProxyKernel::SingBox] {
            if let Some(pid) = self.read_pid(kernel) {
                send_signal(pid, libc::SIGTERM);
                let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
                while std::time::Instant::now() < deadline {
                    if !send_signal(pid, 0) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(100));
                }
                if send_signal(pid, 0) {
                    send_signal(pid, libc::SIGKILL);
                }
            }
            let _ = fs::remove_file(self.pid_file(kernel));
        }
        // The integrated engine stops with the same handshake (it exits on
        // SIGTERM; the run loop's signal handler completes the shutdown).
        if let Some(pid) = self.read_engine_pid() {
            send_signal(pid, libc::SIGTERM);
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(2);
            while std::time::Instant::now() < deadline {
                if !send_signal(pid, 0) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            if send_signal(pid, 0) {
                send_signal(pid, libc::SIGKILL);
            }
        }
        let _ = fs::remove_file(self.engine_pid_file());
        let _ = fs::remove_file(self.start_time_file());
        if notify {
            // A restart emits its own single "restart" event, not stop+restart.
            self.notify_best_effort("stop", "kernel stopped");
        }
        Ok(())
    }

    pub async fn restart(&self, kernel: ProxyKernel) -> Result<u32> {
        // stop blocks (SIGTERM wait) — keep it off the async workers.
        let stopper = ServiceManager {
            platform: self.platform.clone(),
        };
        tokio::task::spawn_blocking(move || stopper.stop_inner(false))
            .await
            .map_err(|e| Error::Process(format!("restart join failed: {e}")))??;
        // start_inner(false): restart emits exactly one "restart" event,
        // not start+restart.
        let pid = self.start_inner(kernel, false).await?;
        self.notify_best_effort("restart", &format!("kernel restarted (PID {pid})"));
        Ok(pid)
    }

    // -- Integrated Rust engine lifecycle --------------------------------

    /// Whether the engine selection (external kernel or integrated Rust
    /// engine) has a live process.
    pub fn is_running_selection(&self, selection: crate::engine::KernelSelection) -> bool {
        match selection {
            crate::engine::KernelSelection::External(kernel) => self.is_running(kernel),
            crate::engine::KernelSelection::Engine(_) => self
                .read_engine_pid()
                .map(|pid| send_signal(pid, 0))
                .unwrap_or(false),
        }
    }

    fn read_engine_pid(&self) -> Option<u32> {
        let content = fs::read_to_string(self.engine_pid_file()).ok()?;
        content.trim().parse::<u32>().ok()
    }

    /// Start whatever the config selects (external kernel or the Rust
    /// engine self-spawn). Returns the new PID.
    pub async fn start_selection(
        &self,
        selection: crate::engine::KernelSelection,
    ) -> Result<u32> {
        match selection {
            crate::engine::KernelSelection::External(kernel) => self.start(kernel).await,
            crate::engine::KernelSelection::Engine(flavor) => {
                self.start_engine(flavor, true).await
            }
        }
    }

    /// Restart the selection (single "restart" notification).
    pub async fn restart_selection(
        &self,
        selection: crate::engine::KernelSelection,
    ) -> Result<u32> {
        let stopper = ServiceManager {
            platform: self.platform.clone(),
        };
        tokio::task::spawn_blocking(move || stopper.stop_inner(false))
            .await
            .map_err(|e| Error::Process(format!("restart join failed: {e}")))??;
        let pid = match selection {
            crate::engine::KernelSelection::External(kernel) => self.start_inner(kernel, false).await?,
            crate::engine::KernelSelection::Engine(flavor) => self.start_engine(flavor, false).await?,
        };
        self.notify_best_effort("restart", &format!("kernel restarted (PID {pid})"));
        Ok(pid)
    }

    /// Spawn the engine as a child of this same binary: config is
    /// validated first (fail fast, like `mihomo -t`), the process gets the
    /// anti-loop supplementary gid, and logs land in the log dir.
    async fn start_engine(&self, flavor: crate::engine::EngineFlavor, notify: bool) -> Result<u32> {
        crate::engine::ensure_supported(flavor)?;
        if let Some(pid) = self.read_engine_pid() {
            if send_signal(pid, 0) {
                return Ok(pid);
            }
        }
        fs::create_dir_all(self.run_dir())?;

        let config_path =
            crate::config::ConfigManager::new(&self.platform).kernel_config_path(flavor.kernel());
        let cfg_path = validated_config(&config_path)?;
        // Fail fast on a broken config (the engine has no supervisor to
        // hide behind at this point).
        #[cfg(any(feature = "engine-mihomo", feature = "engine-singbox"))]
        {
            let warnings = crate::engine::test(flavor, cfg_path.to_str().unwrap_or(""), &self.platform)?;
            for w in warnings {
                tracing::warn!("engine config: {w}");
            }
        }

        let exe = validated_executable(
            std::env::current_exe()
                .map_err(|e| Error::Process(format!("current_exe: {e}")))?
                .to_str()
                .ok_or_else(|| Error::Process("current_exe not utf-8".into()))?,
        )?;

        // Anti-loop gid, identical to the external-kernel path.
        ensure_crash_group();
        let crash_gid = lookup_group_name_by_gid(CRASH_GID)
            .map(|_| CRASH_GID)
            .or_else(|| lookup_group_gid(CRASH_GID_NAME));

        // Engine logs go to their own file (the kernel binaries write
        // their own logs under -d too).
        let log_dir = self.platform.log_dir();
        fs::create_dir_all(&log_dir)?;
        let engine_log = std::path::Path::new(&log_dir).join("rustcrash-engine.log");
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&engine_log)
            .map_err(|e| Error::Process(format!("open {}: {e}", engine_log.display())))?;

        let dup_fd = log_file
            .try_clone()
            .map_err(|e| Error::Process(format!("dup log fd: {e}")))?;
        let mut cmd = tokio::process::Command::new(exe.as_os_str());
        cmd.arg("engine")
            .arg("run")
            .arg("--flavor")
            .arg(flavor.as_str())
            .arg("--config")
            .arg(cfg_path.as_os_str())
            .stdout(std::process::Stdio::from(dup_fd))
            .stderr(std::process::Stdio::from(log_file));
        #[cfg(unix)]
        if let Some(gid) = crash_gid {
            unsafe {
                cmd.pre_exec(move || {
                    if libc::setgroups(1, [gid as libc::gid_t].as_ptr()) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
        }
        let child = cmd.spawn().map_err(|e| {
            Error::Process(format!("failed to start the rust engine: {e}"))
        })?;
        let pid = child.id();

        if let Some(pid) = pid {
            fs::write(self.engine_pid_file(), pid.to_string())?;
            fs::write(self.start_time_file(), now_secs().to_string())?;
        }
        if notify {
            let nm = crate::notify::NotificationManager::from_platform(&self.platform);
            let pid_text = pid.unwrap_or(0).to_string();
            let flavor_text = flavor.as_str().to_string();
            tokio::spawn(async move {
                nm.notify_event(
                    "start",
                    &format!("rust engine ({flavor_text}) started (PID {pid_text})"),
                )
                .await;
            });
        }
        Ok(pid.unwrap_or(0))
    }

    /// Status for either selection. The engine's `kernel` field carries the
    /// flavor's external-kernel counterpart purely as a label.
    pub fn status_selection(&self, selection: crate::engine::KernelSelection) -> ServiceStatus {
        match selection {
            crate::engine::KernelSelection::External(kernel) => self.status(kernel),
            crate::engine::KernelSelection::Engine(flavor) => {
                let pid = self.read_engine_pid();
                let running = pid.map(|p| send_signal(p, 0)).unwrap_or(false);
                let (memory_mb, uptime_secs) = if running {
                    (read_vm_rss_mb(pid.unwrap()), self.read_start_time())
                } else {
                    (None, None)
                };
                ServiceStatus {
                    kernel: flavor.kernel(),
                    running,
                    pid,
                    memory_mb,
                    uptime_secs,
                }
            }
        }
    }

    /// Fire a notification event when a tokio runtime is available; silently
    /// skip otherwise (sync CLI contexts).
    fn notify_best_effort(&self, event: &str, message: &str) {
        if let Ok(handle) = tokio::runtime::Handle::try_current() {
            let nm = crate::notify::NotificationManager::from_platform(&self.platform);
            let message = message.to_string();
            let event = event.to_string();
            handle.spawn(async move {
                nm.notify_event(&event, &message).await;
            });
        }
    }

    /// Gather runtime status: running state, PID, VmRSS memory and uptime.
    pub fn status(&self, kernel: ProxyKernel) -> ServiceStatus {
        let pid = self.read_pid(kernel);
        let running = pid.map(|p| send_signal(p, 0)).unwrap_or(false);
        let (memory_mb, uptime_secs) = if running {
            (read_vm_rss_mb(pid.unwrap()), self.read_start_time())
        } else {
            (None, None)
        };
        ServiceStatus {
            kernel,
            running,
            pid,
            memory_mb,
            uptime_secs,
        }
    }

    fn read_start_time(&self) -> Option<u64> {
        let started: u64 = fs::read_to_string(self.start_time_file())
            .ok()?
            .trim()
            .parse()
            .ok()?;
        let now = now_secs();
        if started <= now {
            Some(now - started)
        } else {
            None
        }
    }
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// The anti-loop supplementary group. The gid is FIXED at 7890 — the
/// firewall exemptions (`meta skgid`, `--gid-owner`) match the numeric
/// gid, so an auto-allocated gid would never match.
pub const CRASH_GID_NAME: &str = "rustcrash";
pub const CRASH_GID: u32 = 7890;

/// Create the crash group with the fixed gid if missing (best-effort,
/// requires root). Shadow groupadd first, BusyBox addgroup fallback.
#[cfg(unix)]
fn ensure_crash_group() {
    if lookup_group_gid(CRASH_GID_NAME).is_some() || lookup_group_name_by_gid(CRASH_GID).is_some() {
        return;
    }
    // Literal argv only — fixed gid, fixed name, no interpolated values.
    let shadow = std::process::Command::new("groupadd")
        .args(["-g", "7890", "-f", "rustcrash"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if shadow {
        return;
    }
    let busybox = std::process::Command::new("addgroup")
        .args(["-g", "7890", "-S", "rustcrash"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !busybox {
        tracing::warn!(
            "could not create group {CRASH_GID_NAME} (gid {CRASH_GID}); the kernel will \
             start without the anti-loop tag and its own traffic may loop"
        );
    }
}

#[cfg(not(unix))]
fn ensure_crash_group() {}

/// Resolve a group name to its gid via /etc/group.
#[cfg(unix)]
pub(crate) fn lookup_group_gid(name: &str) -> Option<u32> {
    let content = fs::read_to_string("/etc/group").ok()?;
    for line in content.lines() {
        let mut parts = line.split(':');
        if parts.next() == Some(name) {
            // name:passwd:gid:members
            let gid = parts.nth(1)?.parse().ok()?;
            return Some(gid);
        }
    }
    None
}

/// Resolve a gid back to its name (a differently-named group already
/// holding gid 7890 is just as good for the exemption).
#[cfg(unix)]
fn lookup_group_name_by_gid(gid: u32) -> Option<String> {
    let content = fs::read_to_string("/etc/group").ok()?;
    for line in content.lines() {
        let mut parts = line.split(':');
        let name = parts.next()?;
        if parts.nth(1)?.parse::<u32>().ok()? == gid {
            return Some(name.to_string());
        }
    }
    None
}

#[cfg(not(unix))]
fn lookup_group_gid(_name: &str) -> Option<u32> {
    None
}

/// Send a signal via `libc::kill` directly — no shell, no subprocess.
/// Signal 0 is the standard liveness probe.
fn send_signal(pid: u32, sig: i32) -> bool {
    // SAFETY: libc::kill takes numeric pid/signal with no pointers to validate.
    unsafe { libc::kill(pid as libc::pid_t, sig) == 0 }
}

/// Read `VmRSS` from `/proc/<pid>/status` and convert kB to MB.
pub fn read_vm_rss_mb(pid: u32) -> Option<f64> {
    let status = fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("VmRSS:") {
            let kb: f64 = rest.trim().trim_end_matches("kB").trim().parse().ok()?;
            return Some(kb / 1000.0);
        }
    }
    None
}

/// Long-running supervisor shared by every front-end: REST API (when
/// enabled in config), Telegram bot (when configured), and a kernel
/// watchdog — all in one process.
pub async fn serve(
    platform: &Platform,
    config: &crate::config::Config,
    interval: u64,
) -> Result<()> {
    let selection = config.kernel_selection();
    let sm = std::sync::Arc::new(ServiceManager::new(platform));

    if config.api_enabled {
        let token = crate::api::ApiServer::token_from(platform);
        let has_token = token.is_some();
        let server = std::sync::Arc::new(crate::api::ApiServer::new(platform, token));
        let listener = tokio::net::TcpListener::bind(("127.0.0.1", config.api_port))
            .await
            .map_err(|e| {
                Error::Process(format!("failed to bind API port {}: {e}", config.api_port))
            })?;
        tracing::info!(
            "REST API listening on 127.0.0.1:{} (auth: {})",
            config.api_port,
            if has_token { "token" } else { "none" }
        );
        tokio::spawn(async move {
            if let Err(e) = server.serve(listener).await {
                tracing::error!("api server error: {e}");
            }
        });
    }

    let bot_config = crate::bot::BotConfig::from_config(config);
    if bot_config.is_ready() {
        match crate::bot::TelegramBot::from_config(config, platform) {
            Ok(bot) => {
                let bot = std::sync::Arc::new(bot);
                tokio::spawn(async move {
                    if let Err(e) = bot.run().await {
                        tracing::error!("bot polling failed: {e}");
                    }
                });
                tracing::info!("Telegram bot started");
            }
            Err(e) => tracing::warn!("bot not started: {e}"),
        }
    }

    loop {
        tokio::time::sleep(std::time::Duration::from_secs(interval)).await;
        rotate_kernel_logs(platform);
        if !sm.is_running_selection(selection) {
            tracing::warn!("kernel stopped, watchdog restarting...");
            // start_selection() fires the "start" event itself — no duplicate here.
            if let Err(e) = sm.start_selection(selection).await {
                tracing::error!("watchdog failed to restart: {e}");
                let nm = crate::notify::NotificationManager::from_platform(platform);
                nm.notify_event("error", &format!("watchdog restart failed: {e}"))
                    .await;
            }
        }
    }
}

/// Cap kernel logs so routers don't fill their storage: when a log exceeds
/// `max_bytes`, keep only the trailing half (atomic replace).
pub fn rotate_kernel_logs(platform: &Platform) {
    const MAX_BYTES: u64 = 5 * 1024 * 1024;
    let Ok(dir) = fs::read_dir(platform.log_dir()) else {
        return;
    };
    for entry in dir.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("log") {
            continue;
        }
        let Ok(meta) = entry.metadata() else { continue };
        if meta.len() <= MAX_BYTES {
            continue;
        }
        // Read the trailing half and swap it in atomically.
        if let Ok(content) = fs::read(&path) {
            let keep_from = content.len() / 2;
            let tail = &content[keep_from..];
            let tmp = path.with_extension("log.tmp");
            if fs::write(&tmp, tail).is_ok() {
                let _ = fs::rename(&tmp, &path);
                tracing::info!("rotated {} from {} bytes", path.display(), content.len());
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_uptime_under_one_day() {
        assert_eq!(format_uptime(0), "0h 0m 0s");
        assert_eq!(format_uptime(59), "0h 0m 59s");
        assert_eq!(format_uptime(3661), "1h 1m 1s");
    }

    #[test]
    fn format_uptime_over_one_day() {
        assert_eq!(format_uptime(86400), "1d 0h 0m 0s");
        assert_eq!(format_uptime(90061), "1d 1h 1m 1s");
    }

    #[test]
    fn status_display_helpers() {
        let st = ServiceStatus {
            kernel: ProxyKernel::Mihomo,
            running: false,
            pid: None,
            memory_mb: Some(12.345),
            uptime_secs: Some(86400 + 3661),
        };
        assert_eq!(st.memory_display(), "12.35 MB");
        assert_eq!(st.uptime_display(), "1d 1h 1m 1s");

        let empty = ServiceStatus {
            kernel: ProxyKernel::Mihomo,
            running: false,
            pid: None,
            memory_mb: None,
            uptime_secs: None,
        };
        assert_eq!(empty.memory_display(), "");
        assert_eq!(empty.uptime_display(), "");
    }

    #[test]
    fn vm_rss_parses_proc_status() {
        let pid = std::process::id();
        let mb = read_vm_rss_mb(pid);
        assert!(mb.is_some(), "should read VmRSS for current process");
        assert!(mb.unwrap() > 0.0);
    }

    #[test]
    fn vm_rss_missing_process_is_none() {
        // PID 4194303 is the upper bound on Linux and effectively never alive.
        assert!(read_vm_rss_mb(4194303).is_none());
    }

    #[test]
    fn executable_validation_rejects_relative_paths() {
        assert!(validated_executable("relative/mihomo").is_err());
    }

    #[test]
    fn executable_validation_rejects_missing_files() {
        assert!(validated_executable("/nonexistent/mihomo").is_err());
    }

    #[test]
    fn executable_validation_accepts_real_file() {
        let path = std::env::current_exe().unwrap();
        let ok = validated_executable(path.to_str().unwrap());
        assert!(ok.is_ok());
    }

    #[test]
    fn config_validation_rejects_relative_and_missing() {
        assert!(validated_config("config.yaml").is_err());
        assert!(validated_config("/nonexistent/config.yaml").is_err());
    }

    #[test]
    fn is_running_false_without_pid_file() {
        let tmp = tempfile::tempdir().unwrap();
        let platform = Platform::for_crash_dir(tmp.path().to_str().unwrap());
        let sm = ServiceManager::new(&platform);
        assert!(!sm.is_running(ProxyKernel::Mihomo));
    }

    #[test]
    fn is_running_false_for_dead_pid() {
        let tmp = tempfile::tempdir().unwrap();
        let run_dir = tmp.path().join("run");
        fs::create_dir_all(&run_dir).unwrap();
        fs::write(run_dir.join("mihomo.pid"), "4194303").unwrap();
        let platform = Platform::for_crash_dir(tmp.path().to_str().unwrap());
        let sm = ServiceManager::new(&platform);
        assert!(!sm.is_running(ProxyKernel::Mihomo));
    }

    #[test]
    fn status_reports_stopped_when_no_pid() {
        let tmp = tempfile::tempdir().unwrap();
        let platform = Platform::for_crash_dir(tmp.path().to_str().unwrap());
        let sm = ServiceManager::new(&platform);
        let status = sm.status(ProxyKernel::Mihomo);
        assert!(!status.running);
        assert_eq!(status.memory_mb, None);
        assert_eq!(status.uptime_secs, None);
    }

    #[test]
    fn stop_cleans_pid_files() {
        let tmp = tempfile::tempdir().unwrap();
        let run_dir = tmp.path().join("run");
        fs::create_dir_all(&run_dir).unwrap();
        fs::write(run_dir.join("mihomo.pid"), "4194303").unwrap();
        fs::write(run_dir.join("crash_start_time"), "0").unwrap();
        let platform = Platform::for_crash_dir(tmp.path().to_str().unwrap());
        let sm = ServiceManager::new(&platform);
        sm.stop().unwrap();
        assert!(!run_dir.join("mihomo.pid").exists());
        assert!(!run_dir.join("crash_start_time").exists());
    }

    #[test]
    fn signal_zero_detects_live_process() {
        let pid = std::process::id();
        assert!(send_signal(pid, 0));
        assert!(!send_signal(4194303, 0));
    }

    #[tokio::test]
    async fn start_rejects_missing_kernel() {
        let tmp = tempfile::tempdir().unwrap();
        let platform = Platform::for_crash_dir(tmp.path().to_str().unwrap());
        let sm = ServiceManager::new(&platform);
        let err = sm.start(ProxyKernel::Mihomo).await.unwrap_err();
        assert!(err.to_string().contains("not installed"));
    }
}
