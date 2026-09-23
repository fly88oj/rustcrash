//! crash - Main RustCrash CLI entry point
//!
//! Consolidated binary containing all functionality:
//!   - Interactive TUI (default)
//!   - Non-interactive command execution via --exec
//!   - Subcommands: init, config, firewall, start, task, install, debug, setboot, sub

use anyhow::Result;
use clap::{Parser, Subcommand};
use rustcrash_core::{
    platform::{Detect, InitSystem},
    Config, ConfigManager, Firewall, KernelManager, Platform, ProxyKernel, SubscriptionManager,
};
use std::process;

mod tui;

#[derive(Parser, Debug)]
#[command(
    name = "crash",
    about = "RustCrash - Cross-platform mihomo/sing-box management",
    version,
    infer_subcommands = true
)]
struct Args {
    /// Crash directory (overrides default)
    #[arg(short, long, global = true)]
    crashdir: Option<String>,

    /// Run a specific command non-interactively (start|stop|restart|status|version)
    #[arg(short, long)]
    exec: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

// CLI definition: clap subcommand variants differ in size by design.
#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
enum Commands {
    /// Initialize directory structure
    Init {
        /// Skip confirmation prompts
        #[arg(short, long)]
        force: bool,

        /// Create init system integration
        #[arg(short, long)]
        init: bool,
    },

    /// Configuration management
    Config {
        #[command(subcommand)]
        action: ConfigAction,
    },

    /// Firewall management
    Firewall {
        #[command(subcommand)]
        action: FirewallAction,
    },

    /// Kernel control (start/stop/restart/status)
    Start {
        #[command(subcommand)]
        action: StartAction,
    },

    /// Task scheduling
    Task {
        #[command(subcommand)]
        action: TaskAction,
    },

    /// Kernel installation
    Install {
        /// Kernel to install (mihomo or sing-box)
        #[arg(short, long, default_value = "mihomo")]
        kernel: String,

        /// Specific version to install (default: latest)
        #[arg(short, long)]
        version: Option<String>,

        /// List available versions instead of installing (ShellCrash-style
        /// rollback support: pick any listed version for --version)
        #[arg(short, long)]
        list: bool,

        /// Force reinstall
        #[arg(short, long)]
        force: bool,
    },

    /// Debug dump: service status, kernel log tail, crash reports
    Debug,

    /// Boot management
    Setboot {
        #[command(subcommand)]
        action: SetbootAction,
    },

    /// Subscription conversion (native Rust implementation)
    Sub {
        #[command(subcommand)]
        action: SubAction,
    },
}

#[derive(Subcommand, Debug)]
pub enum ConfigAction {
    /// Show current configuration
    Show,
    /// Validate configuration
    Validate,
    /// Export configuration for debugging
    Export,
    /// Import subscription from URL
    Import {
        /// Subscription URL
        url: String,
        /// Name for this subscription
        #[arg(short, long)]
        name: Option<String>,
    },
    /// List all subscriptions
    List,
    /// Select active subscription
    Select {
        /// Subscription index
        index: usize,
    },
    /// Generate config from subscription
    Generate {
        /// Kernel: mihomo or sing-box
        #[arg(short, long, default_value = "mihomo")]
        kernel: String,
    },
    /// Edit config (runs vi; edit `<crashdir>`/config.yaml for other editors)
    Edit,
}

#[derive(Subcommand, Debug)]
pub enum FirewallAction {
    /// Setup firewall rules for router mode
    Setup {
        /// Proxy port (default: 7890)
        #[arg(short, long)]
        port: Option<u16>,
        /// DNS port (default: 7892)
        #[arg(short, long)]
        dns_port: Option<u16>,
        /// Enable TUN mode
        #[arg(long)]
        tun: bool,
        /// TUN port (default: proxy port)
        #[arg(long)]
        tun_port: Option<u16>,
        /// Enable IPv6 transparent proxy
        #[arg(long)]
        ipv6: bool,
        /// VM subnet for prerouting_vm chain (e.g., 192.168.1.0/24)
        #[arg(long)]
        vm_ipv4: Option<String>,
        /// Enable VM redirection rules
        #[arg(long)]
        vm_redir: bool,
        /// Block QUIC (UDP 443)
        #[arg(long)]
        quic_reject: bool,
        /// Common ports to proxy (comma-separated)
        #[arg(long, value_delimiter = ',')]
        common_ports: Vec<u16>,
    },
    /// Cleanup all firewall rules
    Cleanup,
    /// Show current firewall rules
    Show,
    /// Generate firewall script (don't apply)
    Generate {
        /// Backend: iptables or nftables
        #[arg(short, long, default_value = "nftables")]
        backend: String,
    },
    /// Apply firewall rules
    Apply,
}

#[derive(Subcommand, Debug)]
pub enum StartAction {
    /// Start the proxy kernel
    Start,
    /// Stop the proxy kernel
    Stop,
    /// Restart the proxy kernel
    Restart,
    /// Show kernel status
    Status,
    /// View kernel logs
    Logs {
        /// Follow log output
        #[arg(short, long)]
        follow: bool,
    },
    /// Watch kernel and restart on crash
    Watchdog {
        /// Check interval in seconds
        #[arg(short, long, default_value = "30")]
        interval: u64,
    },
    /// Run the Telegram bot (foreground, long-running)
    Bot,
    /// Supervisor: REST API + Telegram bot + watchdog in one process
    Serve {
        /// Watchdog check interval in seconds
        #[arg(short, long, default_value = "30")]
        interval: u64,
    },
}

#[derive(Subcommand, Debug)]
pub enum TaskAction {
    /// Enable auto-update
    Enable {
        /// Update interval (e.g., "24h", "12h", "daily")
        #[arg(short, long, default_value = "24h")]
        interval: String,
    },
    /// Disable auto-update
    Disable,
    /// List scheduled tasks
    List,
    /// Run update now
    RunNow,
    /// Update GeoIP/GeoSite databases
    Geo {
        /// Repository in owner/name form (default from config)
        #[arg(short, long)]
        repo: Option<String>,
        /// Mirror prefix for GitHub downloads
        #[arg(long)]
        mirror: Option<String>,
    },
    /// Update external rule providers now
    Rules,
}

#[derive(Subcommand, Debug)]
pub enum SetbootAction {
    /// Enable boot start
    Enable,
    /// Disable boot start
    Disable,
    /// Show current status
    Status,
    /// Check if enabled at boot
    IsEnabled,
}

// CLI definition: clap subcommand variants differ in size by design.
#[derive(Subcommand, Debug)]
#[allow(clippy::large_enum_variant)]
pub enum SubAction {
    /// Convert subscription to target format using native Rust implementation
    Convert {
        /// Subscription URL (required for fetch-and-convert mode)
        #[arg(short = 'i', long)]
        url: Option<String>,
        /// Input URI(s) directly (one or more, comma or space separated)
        #[arg(short = 'I', long, num_args = 1..)]
        input: Option<Vec<String>>,
        /// Target format (clash, clashr, singbox, quan, quanx, loon, surge, v2ray, ss, trojan)
        #[arg(short = 't', long, default_value = "clash")]
        target: String,
        /// Group name for the subscription
        #[arg(short = 'n', long)]
        name: Option<String>,
        /// Regex pattern to exclude matching nodes
        #[arg(long)]
        exclude: Option<String>,
        /// Regex pattern to include only matching nodes
        #[arg(long)]
        include: Option<String>,
        /// Rename rules: pattern->replacement;...
        #[arg(long)]
        rename: Option<String>,
        /// Remove emoji from node names
        #[arg(long, default_value = "false")]
        remove_emoji: bool,
        /// Enable emoji in node names
        #[arg(long, default_value = "false")]
        emoji: bool,
        /// Sort nodes by name
        #[arg(long, default_value = "false")]
        sort: bool,
        /// Enable TCP Fast Open
        #[arg(long, default_value = "false")]
        tfo: bool,
        /// Enable UDP support
        #[arg(long, default_value = "false")]
        udp: bool,
        /// Skip TLS certificate verification
        #[arg(long, default_value = "false")]
        scv: bool,
        /// Output file (default: stdout)
        #[arg(short = 'o', long)]
        output: Option<String>,
        /// Keep only UDP-capable nodes ("true") or UDP-incapable ones ("false")
        #[arg(long)]
        udp_filter: Option<bool>,
        /// Max nodes per (server, port) pair — dedup mirror spam
        #[arg(long)]
        max_link: Option<usize>,
        /// Preset sort: name|name-desc|server|port|protocol
        #[arg(long)]
        sort_algorithm: Option<String>,
        /// url-test group switching tolerance in ms (Clash targets)
        #[arg(long)]
        tolerance: Option<u32>,
        /// Keep only these countries (codes or aliases, comma-separated,
        /// e.g. US,HK,Japan)
        #[arg(long, value_delimiter = ',')]
        country: Vec<String>,
    },
    /// Fetch subscription and display raw content
    Fetch {
        /// Subscription URL
        url: String,
    },
    /// Merge multiple subscriptions into one
    Merge {
        /// Subscription URLs (use multiple --url flags)
        #[arg(short = 'u', long, num_args = 1..)]
        urls: Vec<String>,
        /// Target format
        #[arg(short = 't', long, default_value = "clash")]
        target: String,
        /// Sort nodes by name
        #[arg(long, default_value = "false")]
        sort: bool,
        /// Remove emoji from node names
        #[arg(long, default_value = "false")]
        remove_emoji: bool,
    },
    /// Check if subconverter is available
    Check {},
}

fn main() {
    let args = Args::parse();

    // Set CRASHDIR env if provided
    if let Some(ref dir) = args.crashdir {
        std::env::set_var("CRASHDIR", dir);
    }

    // Detect platform
    let platform = match Detect::platform() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to detect platform: {e}");
            process::exit(1);
        }
    };

    // Logging (config log_level, RUST_LOG wins) and panic crash reports for
    // every invocation, not just the supervisor.
    let log_level = ConfigManager::new(&platform)
        .load()
        .map(|c| c.log_level)
        .unwrap_or_else(|_| "info".to_string());
    rustcrash_core::logging::init_logging(&log_level);
    rustcrash_core::logging::install_crash_reporting(&platform);

    // Handle --exec mode (non-interactive)
    if let Some(ref cmd) = args.exec {
        handle_exec(cmd, &platform);
        return;
    }

    // Handle subcommands
    if let Some(command) = args.command {
        if let Err(e) = handle_command(command, &platform) {
            eprintln!("Error: {e}");
            process::exit(1);
        }
        return;
    }

    // Run interactive TUI (default)
    if let Err(e) = tui::run_tui(&platform) {
        eprintln!("Error: {e}");
        process::exit(1);
    }
}

fn handle_exec(cmd: &str, platform: &Platform) {
    match cmd {
        "start" => {
            let config = ConfigManager::new(platform).load().unwrap_or_default();
            let kernel = config.active_kernel();

            let installed = tokio::runtime::Runtime::new()
                .ok()
                .and_then(|rt| {
                    rt.block_on(KernelManager::new(platform).installed_kernel(kernel))
                        .ok()
                })
                .flatten();
            match installed {
                Some(_) => {
                    println!("Starting {}...", kernel.binary_name());
                    if let Err(e) = start_kernel(platform, kernel) {
                        eprintln!("Failed to start: {e}");
                    }
                }
                None => {
                    eprintln!("Kernel not installed. Run 'crash install' first.");
                }
            }
        }
        "stop" => {
            if let Err(e) = stop_kernel(platform) {
                eprintln!("Failed to stop: {e}");
            }
        }
        "restart" => {
            let _ = stop_kernel(platform);
            let config = ConfigManager::new(platform).load().unwrap_or_default();
            let kernel = config.active_kernel();
            if let Err(e) = start_kernel(platform, kernel) {
                eprintln!("Failed to restart: {e}");
            }
        }
        "status" => {
            if let Err(e) = show_status(platform) {
                eprintln!("Error: {e}");
            }
        }
        "version" => {
            let config = ConfigManager::new(platform).load().unwrap_or_default();
            let kernel = config.active_kernel();
            let probed = tokio::runtime::Runtime::new().ok().and_then(|rt| {
                rt.block_on(KernelManager::new(platform).get_kernel_version(kernel))
                    .ok()
            });
            match probed {
                Some(v) => println!("{} version: {v}", kernel.binary_name()),
                None => println!("Kernel not installed"),
            }
        }
        _ => {
            eprintln!("Unknown command: {cmd}");
            eprintln!("Available: start, stop, restart, status, version");
        }
    }
}

fn handle_command(cmd: Commands, platform: &Platform) -> Result<()> {
    match cmd {
        Commands::Init { force, init } => {
            handle_init(platform, force, init)?;
        }
        Commands::Config { action } => {
            handle_config(platform, action)?;
        }
        Commands::Firewall { action } => {
            handle_firewall(platform, action)?;
        }
        Commands::Start { action } => {
            handle_start(platform, action)?;
        }
        Commands::Task { action } => {
            handle_task(platform, action)?;
        }
        Commands::Install {
            kernel,
            version,
            list,
            force,
        } => {
            if list {
                handle_version_list(platform, &kernel)?;
            } else {
                handle_install(platform, kernel, version, force)?;
            }
        }
        Commands::Debug => {
            handle_debug(platform)?;
        }
        Commands::Setboot { action } => {
            handle_setboot(platform, action)?;
        }
        Commands::Sub { action } => {
            handle_sub(action)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Init Handler
// ---------------------------------------------------------------------------

fn handle_init(platform: &Platform, force: bool, init_system: bool) -> Result<()> {
    let crash_dir = platform.crash_dir();

    println!("RustCrash v{}", env!("CARGO_PKG_VERSION"));
    println!();
    println!("Initializing directory structure...");
    println!("  CrashDir: {}", crash_dir);

    let crash_path = std::path::Path::new(&crash_dir);
    if crash_path.exists() && !force {
        println!();
        println!("Directory already exists. Use --force to reinitialize.");
    }

    // Create directory structure (matches ConfigManager/kernel expectations)
    let dirs = [
        "",
        "/bin",
        "/bin/geodata",
        "/configs",
        "/configs/ruleset",
        "/data",
        "/run",
        "/logs",
        "/backup",
    ];
    for dir in dirs {
        let path = format!("{}{}", crash_dir, dir);
        std::fs::create_dir_all(&path)?;
        println!("  Created: {}{}", crash_dir, dir);
    }

    // Write the typed default config at the path ConfigManager reads
    // ({crash_dir}/config.yaml). Never overwrite an existing one.
    let config_path = format!("{}/config.yaml", crash_dir);
    if !std::path::Path::new(&config_path).exists() || force {
        let default_config = Config::default();
        std::fs::write(&config_path, serde_yaml::to_string(&default_config)?)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600));
        }
        println!("  Created: {config_path}");
    }

    if init_system {
        setup_init_system(platform, &crash_dir)?;
    }

    println!();
    println!("Directory structure created successfully!");
    Ok(())
}

fn setup_init_system(platform: &Platform, crash_dir: &str) -> Result<()> {
    // Resolve the real binary path — the scripts must survive reboots
    // without PATH assumptions.
    let exe = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "/usr/local/bin/crash".to_string());
    match platform.init_system {
        InitSystem::OpenRC => {
            let init_script = format!("{}/init.d/rustcrash", crash_dir);
            std::fs::create_dir_all(format!("{}/init.d", crash_dir))?;
            std::fs::write(
                &init_script,
                rustcrash_core::init::openrc_script(&exe, crash_dir),
            )?;
            println!("  OpenRC init script: {}", init_script);
            let _ = std::process::Command::new("rc-update")
                .args(["add", "rustcrash", "default"])
                .output();
        }
        InitSystem::Systemd => {
            let unit_path = "/etc/systemd/system/rustcrash.service";
            std::fs::write(
                unit_path,
                rustcrash_core::init::systemd_unit(&exe, crash_dir),
            )?;
            println!("  Systemd unit: {}", unit_path);
            let _ = std::process::Command::new("systemctl")
                .args(["daemon-reload"])
                .output();
        }
        InitSystem::InitD => {
            let init_script = format!("{}/init.d/rustcrash", crash_dir);
            std::fs::create_dir_all(format!("{}/init.d", crash_dir))?;
            std::fs::write(
                &init_script,
                rustcrash_core::init::initd_script(&exe, crash_dir),
            )?;
            println!("  init.d script: {}", init_script);
        }
        InitSystem::None => {
            println!("  No init system detected. Skipping init integration.");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Config Handler
// ---------------------------------------------------------------------------

fn handle_config(platform: &Platform, action: ConfigAction) -> Result<()> {
    let cm = ConfigManager::new(platform);

    match action {
        ConfigAction::Show => {
            let config = cm.load()?;
            println!("{}", serde_yaml::to_string(&config)?);
        }
        ConfigAction::Validate => {
            let config = cm.load()?;
            // Parse-only success is NOT validity: run the full validator
            // (port collisions, kernel names, ranges) — rounds of checks
            // were dead code when only serde was exercised.
            let result = rustcrash_core::ConfigValidator::new(true).validate(&config);
            if result.is_valid {
                println!("Configuration is valid.");
            } else {
                for err in &result.errors {
                    eprintln!(
                        "[{field}] {message}",
                        field = err.field,
                        message = err.message
                    );
                }
                anyhow::bail!("configuration has {} error(s)", result.errors.len());
            }
        }
        ConfigAction::Export => {
            let config = cm.load()?;
            println!("# Exported configuration");
            println!("# Generated by RustCrash v{}", env!("CARGO_PKG_VERSION"));
            println!();
            println!("{}", serde_yaml::to_string(&config)?);
        }
        ConfigAction::Import { url, name } => {
            println!("Fetching subscription: {}", url);
            let rt = tokio::runtime::Runtime::new()?;
            let content = rt.block_on(async { SubscriptionManager::fetch(&url).await })?;
            println!("Subscription format: {:?}", content.format);
            let name = name.unwrap_or_else(|| "Default".to_string());
            let mut config = cm.load()?;
            config.subscriptions.push(rustcrash_core::Subscription {
                name: name.clone(),
                url: url.clone(),
                updated_at: Some(chrono::Utc::now().timestamp()),
                raw_config: Some(content.content),
            });
            cm.save(&config)?;
            println!("[OK] Subscription '{name}' added");
        }
        ConfigAction::List => {
            let config = cm.load()?;
            println!("=== Subscriptions ===");
            for (i, sub) in config.subscriptions.iter().enumerate() {
                let marker = if i == config.selected_sub {
                    "[*]"
                } else {
                    "[ ]"
                };
                let updated = sub
                    .updated_at
                    .map(|ts| {
                        chrono::DateTime::from_timestamp(ts, 0)
                            .map(|dt| dt.format("%Y-%m-%d %H:%M").to_string())
                            .unwrap_or_default()
                    })
                    .unwrap_or_default();
                println!("{marker} {i}: {} ({}) {}", sub.name, sub.url, updated);
            }
        }
        ConfigAction::Select { index } => {
            let mut config = cm.load()?;
            if index >= config.subscriptions.len() {
                anyhow::bail!("Invalid subscription index: {index}");
            }
            config.selected_sub = index;
            cm.save(&config)?;
            println!(
                "[OK] Selected subscription: {}",
                config.subscriptions[index].name
            );
        }
        ConfigAction::Generate { kernel } => {
            let config = cm.load()?;
            if config.subscriptions.is_empty() {
                anyhow::bail!("No subscription configured. Import one first.");
            }
            let kernel = if kernel == "sing-box" {
                ProxyKernel::SingBox
            } else {
                ProxyKernel::Mihomo
            };
            // Converts URI subscriptions through the native subconverter
            // and appends the configured rule-providers section.
            let content = rustcrash_core::rules::generate_kernel_config(
                &config,
                kernel,
                &platform.crash_dir(),
            )?;
            cm.save_kernel_config(kernel, &content)?;
            println!("[OK] Config generated for {}", kernel.binary_name());
        }
        ConfigAction::Edit => {
            let config = cm.load()?;
            let yaml = serde_yaml::to_string(&config)?;
            // The config embeds secrets, so editing goes through a private
            // NamedTempFile (0600, unpredictable path, removed on drop even
            // when parsing fails). Only vi is spawned — for any other
            // editor, edit <crashdir>/config.yaml directly.
            let mut tmp = tempfile::NamedTempFile::new()
                .map_err(|e| anyhow::anyhow!("failed to create temp file: {e}"))?;
            use std::io::Write as _;
            tmp.write_all(yaml.as_bytes())?;
            tmp.flush()?;
            let path = tmp.path().to_path_buf();
            let status = std::process::Command::new("vi")
                .arg(&path)
                .status()
                .map_err(|e| anyhow::anyhow!("failed to run vi: {e}"))?;
            if !status.success() {
                anyhow::bail!("editor exited with {status}");
            }
            let edited = std::fs::read_to_string(&path)?;
            let parsed: rustcrash_core::Config = serde_yaml::from_str(&edited)?;
            cm.save(&parsed)?;
            println!("[OK] Config saved");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Firewall Handler
// ---------------------------------------------------------------------------

fn handle_firewall(platform: &Platform, action: FirewallAction) -> Result<()> {
    let firewall = Firewall::new(platform);

    match action {
        FirewallAction::Setup {
            port,
            dns_port,
            tun,
            tun_port,
            ipv6,
            vm_ipv4,
            vm_redir,
            quic_reject,
            common_ports,
        } => {
            platform.require_root()?;
            let port = port.unwrap_or(7890);
            let dns_port = dns_port.unwrap_or(7892);
            // TPROXY listener via the shared derivation (needed for the
            // banner AND the rule set — one source of truth).
            let live_cfg = ConfigManager::new(platform).load()?;
            let tproxy_listen = match tun_port {
                Some(t) => t,
                None => rustcrash_core::rules::derive_tproxy_port(&live_cfg)?,
            };
            println!("Setting up {} firewall rules...", platform.firewall_backend);
            println!("  Proxy port: {port}");
            println!("  DNS port: {dns_port}");
            if tun {
                println!("  TUN mode: enabled (tproxy listener: {tproxy_listen})");
            }
            if ipv6 {
                println!("  IPv6: enabled");
            }
            if vm_redir {
                println!("  VM redirect: enabled (subnet: {vm_ipv4:?})");
            }
            if quic_reject {
                println!("  QUIC reject: enabled");
            }
            if !common_ports.is_empty() {
                println!("  Common ports: {common_ports:?}");
            }

            // Full rule set (FR-2.5/2.8/2.9): TUN, IPv6, VM, QUIC and port
            // filters all flow through FirewallConfig -> apply_full;
            // tproxy_listen was derived above (shared derivation). The
            // mixed listener comes from the LIVE config (a custom
            // mixed_port must be WAN-guarded or it stays an open proxy).
            let config = rustcrash_core::FirewallConfig {
                tun_port: tun.then_some(tproxy_listen),
                vm_ipv4: vm_ipv4.clone(),
                vm_redir,
                ipv6_enabled: ipv6,
                proxy_port: port,
                dns_port,
                mixed_port: live_cfg.mixed_port.unwrap_or(port.wrapping_add(1)),
                ..rustcrash_core::FirewallConfig::default()
            }
            .with_quic_reject(quic_reject)
            .with_common_ports(&common_ports);

            if let Err(e) = firewall.apply_full(&config) {
                anyhow::bail!("Failed to apply firewall rules: {e}");
            }
            println!("[OK] Firewall rules applied");
        }
        FirewallAction::Cleanup => {
            platform.require_root()?;
            println!("Cleaning up firewall rules...");
            firewall.cleanup()?;
            println!("[OK] Firewall rules cleaned");
        }
        FirewallAction::Show => {
            println!("Firewall backend: {}", platform.firewall_backend);
            println!("Available: {}", firewall.is_available());
        }
        FirewallAction::Generate { backend } => {
            // Preview exactly what `apply` runs — same config-driven full
            // script, same dual-stack append, same TUN routing.
            let config = ConfigManager::new(platform).load()?;
            let fw_config = config.to_firewall_config()?;
            let mut out = if backend == "iptables" {
                eprintln!("Generating iptables script (from config)...\n");
                if fw_config.ipv6_enabled {
                    anyhow::bail!(
                        "ipv6_enabled is only implemented on the nftables backend; \
                         use --backend nftables or disable ipv6"
                    );
                }
                firewall.generate_full_iptables_script(&fw_config)
            } else {
                eprintln!("Generating nftables script (from config)...\n");
                let mut nft = firewall.generate_full_nft_script(&fw_config)?;
                if fw_config.ipv6_enabled {
                    nft.push_str("\n# IPv6 dual-stack\n");
                    nft.push_str(&firewall.generate_nft_dual_stack_script(&fw_config));
                }
                // Same routing the apply path runs: TUN + IPv6 TPROXY.
                let mut routing = firewall.generate_tun_routing_script(&fw_config);
                if fw_config.ipv6_enabled {
                    routing.push_str(&firewall.generate_ipv6_routing_script());
                }
                if routing.is_empty() {
                    nft
                } else {
                    // One runnable file: the shell driver feeds the nft
                    // ruleset via a quoted heredoc, then applies routing.
                    // (nft parses batches atomically, so mixed content
                    // could never load directly.)
                    format!("#!/bin/sh\nset -e\nnft -f - <<'NFT_EOF'\n{nft}NFT_EOF\n{routing}")
                }
            };
            if !out.ends_with('\n') {
                out.push('\n');
            }
            print!("{out}");
        }
        FirewallAction::Apply => {
            platform.require_root()?;
            println!("Applying firewall rules...");
            let config = ConfigManager::new(platform).load()?;
            let fw_config = config.to_firewall_config()?;
            firewall.apply_full(&fw_config)?;
            println!("[OK] Firewall rules applied");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Start Handler
// ---------------------------------------------------------------------------

fn handle_start(platform: &Platform, action: StartAction) -> Result<()> {
    let config = ConfigManager::new(platform).load()?;
    let kernel = config.active_kernel();

    match action {
        StartAction::Start => {
            start_kernel(platform, kernel)?;
        }
        StartAction::Stop => {
            stop_kernel(platform)?;
        }
        StartAction::Restart => {
            stop_kernel(platform)?;
            start_kernel(platform, kernel)?;
        }
        StartAction::Status => {
            show_status(platform)?;
        }
        StartAction::Logs { follow } => {
            show_kernel_logs(platform, follow)?;
        }
        StartAction::Watchdog { interval } => {
            watchdog(platform, kernel, interval)?;
        }
        StartAction::Bot => {
            let bot = rustcrash_core::TelegramBot::from_config(
                &ConfigManager::new(platform).load()?,
                platform,
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("Starting Telegram bot (Ctrl+C to stop)");
            tokio::runtime::Runtime::new()?.block_on(bot.run())?;
        }
        StartAction::Serve { interval } => {
            println!("Starting supervisor (watchdog interval: {interval}s, Ctrl+C to stop)");
            let config = ConfigManager::new(platform).load()?;
            rustcrash_core::logging::init_logging(&config.log_level);
            rustcrash_core::logging::install_crash_reporting(platform);
            tokio::runtime::Runtime::new()?.block_on(async {
                rustcrash_core::serve_supervisor(platform, &config, interval).await
            })?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Task Handler
// ---------------------------------------------------------------------------

fn handle_task(platform: &Platform, action: TaskAction) -> Result<()> {
    match action {
        TaskAction::Enable { interval } => {
            enable_task(platform, &interval)?;
            println!("[OK] Auto-update enabled ({interval})");
        }
        TaskAction::Disable => {
            disable_task(platform)?;
            println!("[OK] Auto-update disabled");
        }
        TaskAction::List => {
            list_tasks(platform)?;
        }
        TaskAction::RunNow => {
            println!("Running update...");
            run_update_now(platform)?;
            println!("[OK] Update complete");
        }
        TaskAction::Geo { repo, mirror } => {
            let config = ConfigManager::new(platform).load()?;
            let repo = repo.unwrap_or(config.geo_repo);
            let mirror = mirror.or_else(|| config.geo_mirror.clone());
            let geodata_dir = format!("{}/bin/geodata", platform.crash_dir());
            println!("Updating geo data from {repo}...");
            let report = tokio::runtime::Runtime::new()?.block_on(async {
                rustcrash_core::GeoUpdater::new()
                    .update(std::path::Path::new(&geodata_dir), &repo, mirror.as_deref())
                    .await
            })?;
            for name in &report.updated {
                println!("  Updated: {name}");
            }
            for (name, err) in &report.failed {
                eprintln!("  Failed: {name}: {err}");
            }
            println!("[OK] Geo data at tag {}", report.tag);
        }
        TaskAction::Rules => {
            println!("Updating rule providers...");
            let report = tokio::runtime::Runtime::new()?
                .block_on(async { rustcrash_core::rules::update_due_for(platform).await })?;
            for name in &report.updated {
                println!("  Updated: {name}");
            }
            for (name, err) in &report.failed {
                eprintln!("  Failed: {name}: {err}");
            }
            if !report.skipped.is_empty() {
                println!("  Fresh (skipped): {}", report.skipped.join(", "));
            }
            println!("[OK] Rule providers updated");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Install Handler
// ---------------------------------------------------------------------------

/// List recent kernel release versions (rollback support: any listed
/// version can be passed to `crash install --version`).
fn handle_version_list(platform: &Platform, kernel_str: &str) -> Result<()> {
    let kernel = if kernel_str == "sing-box" {
        ProxyKernel::SingBox
    } else {
        ProxyKernel::Mihomo
    };
    let km = KernelManager::new(platform);
    println!("Fetching recent {} releases…", kernel.binary_name());
    let versions = tokio::runtime::Runtime::new()?.block_on(km.list_releases(kernel, 15))?;
    if versions.is_empty() {
        println!("No releases found (network or rate limit?)");
        return Ok(());
    }
    println!("Recent {} versions:", kernel.binary_name());
    for v in &versions {
        println!("  {v}");
    }
    println!("Install any with: crash install --kernel {kernel_str} --version <version>");
    Ok(())
}

/// Debug dump (ShellCrash's `crash -d`): everything needed to diagnose a
/// broken install in one command.
fn handle_debug(platform: &Platform) -> Result<()> {
    println!(
        "=== RustCrash debug dump v{} ===",
        env!("CARGO_PKG_VERSION")
    );
    println!(
        "Platform: {} {} ({})",
        platform.os, platform.arch, platform.init_system
    );
    println!("CrashDir: {}", platform.crash_dir());
    println!("Root: {}", platform.is_root());
    let config = ConfigManager::new(platform).load()?;
    let kernel = config.active_kernel();
    println!(
        "Kernel: {} (mode {}, dns {})",
        config.kernel, config.mode, config.dns_mode
    );
    let sm = rustcrash_core::ServiceManager::new(platform);
    let st = sm.status(kernel);
    println!(
        "Service: {} (pid {:?}, mem {}, uptime {})",
        if st.running { "RUNNING" } else { "STOPPED" },
        st.pid,
        st.memory_display(),
        st.uptime_display()
    );
    println!(
        "ip_forward: {}",
        std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
            .map(|v| v.trim().to_string())
            .unwrap_or_else(|_| "unknown".into())
    );
    println!("\n--- kernel log tail ---");
    for line in rustcrash_core::logging::tail_file(
        std::path::Path::new(&format!(
            "{}/{}.log",
            platform.log_dir(),
            kernel.binary_name()
        )),
        30,
    ) {
        println!("{line}");
    }
    println!("\n--- crash reports ---");
    if let Ok(dir) = std::fs::read_dir(platform.log_dir()) {
        let mut reports: Vec<_> = dir
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n.starts_with("crash-report-"))
                    .unwrap_or(false)
            })
            .collect();
        reports.sort();
        if reports.is_empty() {
            println!("(none)");
        }
        for r in reports.iter().rev().take(3) {
            println!("{}:", r.display());
            if let Ok(content) = std::fs::read_to_string(r) {
                for line in content.lines().take(10) {
                    println!("  {line}");
                }
            }
        }
    }
    Ok(())
}

fn handle_install(
    platform: &Platform,
    kernel_str: String,
    version: Option<String>,
    force: bool,
) -> Result<()> {
    let kernel = if kernel_str == "sing-box" {
        ProxyKernel::SingBox
    } else {
        ProxyKernel::Mihomo
    };

    let km = KernelManager::new(platform);

    if !force && km.is_installed(kernel) {
        println!("{} is already installed", kernel.binary_name());
        let probed = tokio::runtime::Runtime::new()
            .ok()
            .and_then(|rt| rt.block_on(km.installed_kernel(kernel)).ok())
            .flatten();
        if let Some(info) = probed {
            println!("Version: {}", info.version);
            println!("Path: {}", info.path);
        }
        return Ok(());
    }

    if !platform.is_root() {
        println!("Warning: Not running as root. Installation may fail.");
    }

    println!("Installing {}...", kernel.binary_name());
    let rt = tokio::runtime::Runtime::new()?;
    rt.block_on(async { km.install(kernel, version.as_deref()).await })?;

    let installed = rt.block_on(km.installed_kernel(kernel)).ok().flatten();
    if let Some(info) = installed {
        println!(
            "\n[OK] {} v{} installed successfully",
            kernel.binary_name(),
            info.version
        );
        println!("Path: {}", info.path);
        println!(
            "Size: {} bytes ({} MB)",
            info.size,
            info.size as f64 / 1_048_576_f64
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Setboot Handler
// ---------------------------------------------------------------------------

fn handle_setboot(platform: &Platform, action: SetbootAction) -> Result<()> {
    match action {
        SetbootAction::Enable => {
            enable_boot(platform)?;
            println!("[OK] RustCrash will start on boot");
        }
        SetbootAction::Disable => {
            disable_boot(platform)?;
            println!("[OK] RustCrash boot start disabled");
        }
        SetbootAction::Status => {
            show_boot_status(platform)?;
        }
        SetbootAction::IsEnabled => {
            let output = std::process::Command::new("systemctl")
                .args(["is-enabled", "rustcrash"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();
            if output.trim() == "enabled" {
                println!("Boot start: [ENABLED]");
            } else {
                println!("Boot start: [DISABLED]");
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Sub Handler
// ---------------------------------------------------------------------------

fn handle_sub(action: SubAction) -> Result<()> {
    match action {
        SubAction::Convert {
            url,
            input,
            target,
            name,
            exclude,
            include,
            rename,
            remove_emoji,
            emoji,
            sort,
            tfo,
            udp,
            scv,
            output,
            udp_filter,
            max_link,
            sort_algorithm,
            tolerance,
            country,
        } => {
            let target_str = target.to_lowercase();
            let mut opts = rustcrash_core::subscription::ConvertOptions::new(&target_str);

            if let Some(n) = &name {
                opts = opts.group(n);
            }
            if let Some(e) = &exclude {
                opts = opts.exclude(e);
            }
            if let Some(i) = &include {
                opts = opts.include(i);
            }
            if let Some(r) = &rename {
                opts = opts.rename(r);
            }
            if remove_emoji {
                opts = opts.remove_emoji(true);
            }
            if emoji {
                opts = opts.add_emoji(true);
            }
            if sort {
                opts = opts.sort(true);
            }
            if tfo {
                opts = opts.tfo(true);
            }
            if udp {
                opts = opts.udp(true);
            }
            if scv {
                opts = opts.scv(true);
            }
            if let Some(uf) = udp_filter {
                opts.udp_filter = Some(uf);
            }
            if let Some(ml) = max_link {
                opts.max_link = Some(ml);
            }
            if let Some(sa) = &sort_algorithm {
                if rustcrash_core::subconverter::filters::SortAlgorithm::from_str(sa).is_none() {
                    anyhow::bail!(
                        "invalid --sort-algorithm '{sa}': use name|name-desc|server|port|protocol"
                    );
                }
                opts.sort_algorithm = Some(sa.clone());
            }
            if let Some(t) = tolerance {
                opts.tolerance = Some(t);
            }
            if !country.is_empty() {
                opts.country = Some(country.clone());
            }

            let uris: Vec<String> = if let Some(inputs) = input {
                inputs
                    .iter()
                    .flat_map(|s| s.split(',').map(String::from).collect::<Vec<_>>())
                    .collect()
            } else if let Some(url_str) = &url {
                println!("Fetching subscription from: {}", url_str);
                let rt = tokio::runtime::Runtime::new()?;
                let info = rt.block_on(async { SubscriptionManager::fetch(url_str).await })?;
                SubscriptionManager::extract_uris(&info.content, info.format)
            } else {
                anyhow::bail!("Either --url (-i) or --input (-I) must be provided");
            };

            if uris.is_empty() {
                anyhow::bail!("No valid proxy URIs found");
            }

            println!("Processing {} proxy URIs...", uris.len());
            let output_str = SubscriptionManager::convert_with_options(&uris, &opts)?;

            if let Some(out_path) = output {
                std::fs::write(&out_path, &output_str)?;
                println!("Output written to: {}", out_path);
            } else {
                println!("{}", output_str);
            }
        }
        SubAction::Fetch { url } => {
            println!("Fetching subscription: {}", url);
            let rt = tokio::runtime::Runtime::new()?;
            let info = rt.block_on(async { SubscriptionManager::fetch(&url).await })?;
            println!("Format detected: {:?}", info.format);
            println!("Content length: {} bytes", info.content.len());
            println!();
            println!("--- Raw Content ---");
            println!("{}", info.content);
        }
        SubAction::Merge {
            urls,
            target,
            sort,
            remove_emoji,
        } => {
            let target_str = target.to_lowercase();
            println!("Merging {} subscription sources...", urls.len());
            let mut opts = rustcrash_core::subscription::ConvertOptions::new(&target_str);
            if sort {
                opts = opts.sort(true);
            }
            if remove_emoji {
                opts = opts.remove_emoji(true);
            }

            let rt = tokio::runtime::Runtime::new()?;
            let mut all_uris: Vec<String> = Vec::new();

            for url in &urls {
                println!("Fetching: {}", url);
                match rt.block_on(async { SubscriptionManager::fetch(url).await }) {
                    Ok(info) => {
                        let uris = SubscriptionManager::extract_uris(&info.content, info.format);
                        all_uris.extend(uris);
                    }
                    Err(e) => {
                        eprintln!("Warning: Failed to fetch {}: {}", url, e);
                    }
                }
            }

            if all_uris.is_empty() {
                anyhow::bail!("No valid proxy URIs found from any source");
            }

            println!("Total URIs collected: {}", all_uris.len());
            let output_str = SubscriptionManager::convert_with_options(&all_uris, &opts)?;
            println!("{}", output_str);
        }
        SubAction::Check {} => {
            println!("[OK] Native subconverter implementation available");
            println!();
            println!("Supported formats (target parameter):");
            println!("  clash, clashr, singbox, quan, quanx, loon, surge, v2ray, ss, trojan");
            println!();
            println!("Filter options:");
            println!("  --exclude <regex>   Exclude nodes matching pattern");
            println!("  --include <regex>   Include only nodes matching pattern");
            println!("  --rename <rules>   Rename nodes");
            println!("  --remove-emoji      Remove emoji from node names");
            println!("  --sort              Sort nodes by name");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Kernel Control Helpers
// ---------------------------------------------------------------------------

fn start_kernel(platform: &Platform, kernel: ProxyKernel) -> Result<()> {
    // Delegates to the shared ServiceManager: validated spawn paths,
    // libc::kill signalling, start-time file, "start" notifications.
    let sm = rustcrash_core::ServiceManager::new(platform);
    let pid = tokio::runtime::Runtime::new()?.block_on(sm.start(kernel))?;
    println!("Started {} (PID: {pid})", kernel.binary_name());
    Ok(())
}

fn stop_kernel(platform: &Platform) -> Result<()> {
    let sm = rustcrash_core::ServiceManager::new(platform);
    sm.stop()?;
    println!("Stopped kernel");
    Ok(())
}

fn show_status(platform: &Platform) -> Result<()> {
    println!("=== RustCrash Status ===");
    println!(
        "Platform: {} {} ({})",
        platform.os, platform.arch, platform.init_system
    );
    println!("CrashDir: {}", platform.crash_dir());
    println!("Firewall: {}", platform.firewall_backend);
    println!("OpenWRT: {}", platform.is_openwrt);
    println!("Docker: {}", platform.is_docker);
    println!("Root: {}", platform.is_root());
    println!();

    let config = ConfigManager::new(platform).load()?;
    println!("Kernel: {}", config.kernel);
    println!("Mode: {}", config.mode);
    println!();

    let km = KernelManager::new(platform);
    let rt = tokio::runtime::Runtime::new()?;
    for kernel in [ProxyKernel::Mihomo, ProxyKernel::SingBox] {
        if km.is_installed(kernel) {
            let info = rt
                .block_on(km.installed_kernel(kernel))?
                .expect("is_installed was just checked");
            println!(
                "[+] {} v{} installed ({})",
                kernel.binary_name(),
                info.version,
                info.path
            );
        } else {
            println!("[-] {} not installed", kernel.binary_name());
        }
    }

    Ok(())
}

fn watchdog(platform: &Platform, kernel: ProxyKernel, interval: u64) -> Result<()> {
    println!("Starting watchdog (interval: {interval}s, Ctrl+C to stop)");

    let sm = rustcrash_core::ServiceManager::new(platform);
    let runtime = tokio::runtime::Runtime::new()?;
    loop {
        std::thread::sleep(std::time::Duration::from_secs(interval));

        if !sm.is_running(kernel) {
            println!("[WATCHDOG] Kernel stopped, restarting...");
            if let Err(e) = runtime.block_on(sm.start(kernel)) {
                eprintln!("[WATCHDOG] Failed to restart: {e}");
            }
        }
    }
}

fn show_kernel_logs(platform: &Platform, follow: bool) -> Result<()> {
    let log_dir = platform.log_dir();
    loop {
        let lines =
            match rustcrash_core::logging::newest_file(std::path::Path::new(&log_dir), |n| {
                n.ends_with(".log")
            }) {
                Some(path) => rustcrash_core::logging::tail_file(&path, 50),
                None => {
                    if follow {
                        std::thread::sleep(std::time::Duration::from_secs(2));
                        continue;
                    }
                    Vec::new()
                }
            };
        let empty = lines.is_empty();
        for line in &lines {
            println!("{line}");
        }
        if !follow {
            if empty {
                println!("No kernel log found in {log_dir}");
            }
            return Ok(());
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    }
}

// ---------------------------------------------------------------------------
// Boot Control Helpers
// ---------------------------------------------------------------------------

fn enable_boot(platform: &Platform) -> Result<()> {
    match platform.init_system {
        InitSystem::OpenRC => {
            let init_script = format!("{}/init.d/rustcrash", platform.crash_dir());
            if !std::path::Path::new(&init_script).exists() {
                anyhow::bail!("Init script not found. Run crash init --init first.");
            }
            std::process::Command::new("rc-update")
                .arg("add")
                .arg("rustcrash")
                .arg("default")
                .output()?;
        }
        InitSystem::Systemd => {
            std::process::Command::new("systemctl")
                .arg("enable")
                .arg("rustcrash")
                .output()?;
        }
        InitSystem::InitD => {
            // Standard SysV path: link into the boot runlevel directory.
            let init_script = format!("{}/init.d/rustcrash", platform.crash_dir());
            if !std::path::Path::new(&init_script).exists() {
                anyhow::bail!("Init script not found. Run crash init --init first.");
            }
            let link = std::path::Path::new("/etc/rcS.d/S90rustcrash");
            std::fs::create_dir_all(link.parent().unwrap())?;
            // Idempotent: replace any previous link to this or another target.
            let _ = std::fs::remove_file(link);
            std::os::unix::fs::symlink(&init_script, link).map_err(|e| {
                anyhow::anyhow!("failed to link {init_script} -> {}: {e}", link.display())
            })?;
        }
        InitSystem::None => {
            let rc_local = "/etc/rc.local";
            let exe = std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "crash".to_string());
            let crash_start = rustcrash_core::init::rc_local_line(&exe, &platform.crash_dir());
            let current = std::fs::read_to_string(rc_local).unwrap_or_default();
            if !current.contains(crash_start.trim()) {
                // rc.local conventionally ends with `exit 0` — append the
                // bootstrap BEFORE it, or it never runs.
                let updated = if let Some(pos) = current.rfind("exit 0") {
                    format!("{}{}{}", &current[..pos], crash_start, &current[pos..])
                } else {
                    current + &crash_start
                };
                std::fs::write(rc_local, updated)?;
            }
        }
    }
    Ok(())
}

fn disable_boot(platform: &Platform) -> Result<()> {
    match platform.init_system {
        InitSystem::OpenRC => {
            std::process::Command::new("rc-update")
                .arg("del")
                .arg("rustcrash")
                .arg("default")
                .output()?;
        }
        InitSystem::Systemd => {
            std::process::Command::new("systemctl")
                .arg("disable")
                .arg("rustcrash")
                .output()?;
        }
        InitSystem::InitD => {
            // Mirror of enable: remove the boot-runlevel link.
            let _ = std::fs::remove_file("/etc/rcS.d/S90rustcrash");
        }
        InitSystem::None => {
            let rc_local = "/etc/rc.local";
            let exe = std::env::current_exe()
                .map(|p| p.display().to_string())
                .unwrap_or_else(|_| "crash".to_string());
            // Match the exact line enable writes (binary/dir names may not
            // contain "rustcrash").
            let written = rustcrash_core::init::rc_local_line(&exe, &platform.crash_dir())
                .trim()
                .to_string();
            let current = std::fs::read_to_string(rc_local).unwrap_or_default();
            let filtered: String = current
                .lines()
                .filter(|line| line.trim() != written)
                .collect::<Vec<_>>()
                .join("\n");
            std::fs::write(rc_local, filtered)?;
        }
    }
    Ok(())
}

fn show_boot_status(platform: &Platform) -> Result<()> {
    println!("Init system: {}", platform.init_system);

    match platform.init_system {
        InitSystem::OpenRC => {
            let output = std::process::Command::new("rc-status")
                .arg("default")
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();
            if output.contains("rustcrash") {
                println!("Boot start: [ENABLED]");
            } else {
                println!("Boot start: [DISABLED]");
            }
        }
        InitSystem::Systemd => {
            let output = std::process::Command::new("systemctl")
                .args(["is-enabled", "rustcrash"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();
            if output.trim() == "enabled" {
                println!("Boot start: [ENABLED]");
            } else {
                println!("Boot start: [DISABLED]");
            }
        }
        _ => {
            println!("Boot start: [UNKNOWN - init system not fully detected]");
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Task Helpers
// ---------------------------------------------------------------------------

fn enable_task(platform: &Platform, interval: &str) -> Result<()> {
    let cron_expr = match interval {
        "12h" => "0 */12 * * *",
        "daily" | "24h" => "0 4 * * *",
        "6h" => "0 */6 * * *",
        _ => {
            if interval.matches('*').count() >= 4 {
                interval
            } else {
                if let Ok(hours) = interval.trim_end_matches('h').parse::<u32>() {
                    &format!("0 */{} * * *", hours)
                } else {
                    "0 4 * * *"
                }
            }
        }
    };

    let crash_bin = std::env::current_exe()
        .map(|p| p.display().to_string())
        .unwrap_or_else(|_| "crash".to_string());
    // The marker makes re-running `task enable` idempotent regardless of
    // where the binary lives or which crash dir is used.
    const CRON_MARKER: &str = "# rustcrash:autoupdate";
    let task_line = format!(
        "{cron_expr} {crash_bin} -c {} task run-now >> {}/logs/update.log 2>&1 {CRON_MARKER}",
        platform.crash_dir(),
        platform.crash_dir()
    );

    let current = std::process::Command::new("crontab")
        .arg("-l")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let filtered: String = current
        .lines()
        .filter(|line| {
            !line.contains(CRON_MARKER)
                && !line.contains("rustcrash")
                && !line.contains("ShellCrash")
        })
        .collect::<Vec<_>>()
        .join("\n");

    let new_cron = if filtered.is_empty() {
        task_line
    } else {
        format!("{}\n{}", filtered, task_line)
    };

    write_crontab(&new_cron)
}

/// Replace the user crontab with `content` (fed via stdin, never argv).
fn write_crontab(content: &str) -> Result<()> {
    use std::io::Write;
    let mut child = std::process::Command::new("crontab")
        .arg("-")
        .stdin(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn crontab: {e}"))?;
    if let Some(ref mut stdin) = child.stdin {
        stdin.write_all(content.as_bytes())?;
    }
    let status = child.wait()?;
    if !status.success() {
        anyhow::bail!("crontab update failed: {status}");
    }
    Ok(())
}

fn disable_task(_platform: &Platform) -> Result<()> {
    let current = std::process::Command::new("crontab")
        .arg("-l")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let filtered: String = current
        .lines()
        .filter(|line| !line.contains("rustcrash") && !line.contains("ShellCrash"))
        .collect::<Vec<_>>()
        .join("\n");

    if filtered.is_empty() {
        let _ = std::process::Command::new("crontab").arg("-r").output();
    } else {
        write_crontab(&filtered)?;
    }
    Ok(())
}

fn list_tasks(_platform: &Platform) -> Result<()> {
    let current = std::process::Command::new("crontab")
        .arg("-l")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let rustcrash_tasks: Vec<_> = current
        .lines()
        .filter(|line| line.contains("rustcrash") || line.contains("ShellCrash"))
        .collect();

    if rustcrash_tasks.is_empty() {
        println!("No scheduled tasks configured.");
    } else {
        println!("=== Scheduled Tasks ===");
        for task in rustcrash_tasks {
            println!("{}", task);
        }
    }
    Ok(())
}

fn run_update_now(platform: &Platform) -> Result<()> {
    let cm = ConfigManager::new(platform);

    // One refresh path for CLI, bot and API: the shared updater
    // (fetch, persist, notifications). update_all is synchronous — it
    // builds its own short-lived runtime internally.
    let crash_dir = std::path::PathBuf::from(platform.crash_dir());
    let report = rustcrash_core::task::subscription::SubscriptionUpdater::update_all(&crash_dir)?;
    for name in &report.updated {
        println!("  Updated: {name}");
    }
    for (name, err) in &report.failed {
        eprintln!("  Failed: {name}: {err}");
    }

    // Regenerate the kernel config from the fresh subscription (incl.
    // rule providers), then restart in-process.
    let config = cm.load()?;
    let kernel = config.active_kernel();
    let generated =
        rustcrash_core::rules::generate_kernel_config(&config, kernel, &platform.crash_dir())?;
    cm.save_kernel_config(kernel, &generated)?;
    println!("  Kernel config regenerated");

    let sm = rustcrash_core::ServiceManager::new(platform);
    let runtime = tokio::runtime::Runtime::new()?;
    match runtime.block_on(sm.restart(kernel)) {
        Ok(pid) => println!("  Kernel restarted (PID {pid})"),
        Err(e) => eprintln!("  Kernel not restarted: {e}"),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use rustcrash_core::platform::{Detect, FirewallBackend, InitSystem, Platform};
    use rustcrash_core::{Config, ProxyKernel};
    use tempfile::TempDir;

    fn test_platform() -> Platform {
        Detect::platform().unwrap()
    }

    #[test]
    fn test_proxy_kernel_binary_names() {
        assert_eq!(ProxyKernel::Mihomo.binary_name(), "mihomo");
        assert_eq!(ProxyKernel::SingBox.binary_name(), "sing-box");
    }

    #[test]
    fn test_kernel_selection_from_config_mihomo() {
        let config = Config {
            kernel: "mihomo".to_string(),
            ..Default::default()
        };
        let kernel = config.active_kernel();
        assert!(matches!(kernel, ProxyKernel::Mihomo));
    }

    #[test]
    fn test_kernel_selection_from_config_singbox() {
        let config = Config {
            kernel: "sing-box".to_string(),
            ..Default::default()
        };
        let kernel = config.active_kernel();
        assert!(matches!(kernel, ProxyKernel::SingBox));
    }

    #[test]
    fn test_platform_info_display() {
        let platform = test_platform();
        assert_eq!(platform.os, "linux");
        assert!(matches!(
            platform.init_system,
            InitSystem::Systemd | InitSystem::OpenRC | InitSystem::InitD | InitSystem::None
        ));
        assert!(matches!(
            platform.firewall_backend,
            FirewallBackend::Nftables | FirewallBackend::Iptables
        ));
    }

    #[test]
    fn test_runtime_dir_pid_file_path() {
        let platform = test_platform();
        let runtime_dir = platform.runtime_dir();
        let pid_file = format!("{}/mihomo.pid", runtime_dir);
        assert!(pid_file.contains("run"));
        assert!(pid_file.contains("mihomo.pid"));
    }

    #[test]
    fn test_config_default_kernel() {
        let config = Config::default();
        assert_eq!(config.kernel, "mihomo");
        assert_eq!(config.mode, "Router");
    }

    #[test]
    fn test_is_running_returns_false_when_no_pid_file() {
        let tmpdir = TempDir::new().unwrap();
        let platform = Platform::for_crash_dir(tmpdir.path().to_str().unwrap());
        let sm = rustcrash_core::ServiceManager::new(&platform);
        assert!(!sm.is_running(ProxyKernel::Mihomo));
    }

    #[test]
    fn test_is_running_returns_false_for_invalid_pid() {
        let tmpdir = TempDir::new().unwrap();
        let run_dir = tmpdir.path().join("run");
        std::fs::create_dir_all(&run_dir).unwrap();
        let pid_file = run_dir.join("mihomo.pid");
        std::fs::write(&pid_file, "999999").unwrap();

        let platform = Platform::for_crash_dir(tmpdir.path().to_str().unwrap());
        let sm = rustcrash_core::ServiceManager::new(&platform);
        assert!(!sm.is_running(ProxyKernel::Mihomo));
    }
}
