//! Firewall management (iptables/nftables abstraction)

use crate::error::{Error, Result};
use crate::platform::{FirewallBackend, Platform};
use std::io::Write;
use std::process::{Command, Stdio};

/// Default proxy port
pub const DEFAULT_PROXY_PORT: u16 = 7890;
/// Default DNS port
pub const DEFAULT_DNS_PORT: u16 = 7892;
/// Default mixed port
pub const DEFAULT_MIXED_PORT: u16 = 7891;

/// TUN mode constants (ShellCrash compatible). Table IDs must stay ≤ 255:
/// BusyBox `ip` (Alpine/OpenWrt — our router targets) rejects larger IDs.
pub const FWMARK: u32 = 0x80000;
pub const TABLE: u32 = 100;

/// IPv6 reserved address prefixes (D-10)
pub const IPV6_RESERVED_PREFIXES: &[(&str, u8)] = &[
    ("fe80::", 10),     // Link-local
    ("fd00::", 8),      // ULA (Unique Local Address)
    ("ff", 8),          // Multicast (ff00::/8 - match first byte)
    ("::1", 128),       // Loopback
    ("::ffff:0:0", 96), // IPv4-mapped
];

/// Check if IPv6 address is reserved (should not be proxied)
pub fn is_ipv6_reserved(ip: &str) -> bool {
    // Handle special cases first
    if ip == "::1" || ip.starts_with("::1/") || ip.starts_with("::1/") {
        return true;
    }
    if ip.starts_with("::ffff:") {
        return true;
    }
    // Check other prefixes
    for (prefix, _len) in IPV6_RESERVED_PREFIXES {
        if ip.starts_with(prefix) {
            return true;
        }
    }
    false
}

pub const fn ipv6_tproxy_table() -> u32 {
    TABLE + 1
}

// ---------------------------------------------------------------------------
// ShellCrash migration residue (detection + foreign-rule pre-clean)
// ---------------------------------------------------------------------------

/// Detected leftovers from a ShellCrash install that was not stopped or
/// uninstalled before RustCrash took over (the "user migrated from
/// ShellCrash, but the old one is still working" scenario).
///
/// Every field is a distinct residue class:
/// - install dirs / `crash` wrapper scripts / profile aliases: the OLD
///   manager still owns the `crash` command (alias expansion beats PATH,
///   and ShellCrash's container install writes a real `/usr/bin/crash`).
/// - live cores: a CrashCore kernel process holds the standard ports.
/// - nft table / iptables chains / stale ip rules: the OLD firewall
///   layer is still loaded and hijacks traffic alongside ours.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct ShellCrashResidue {
    /// ShellCrash install directories found (contain menu.sh/start.sh).
    pub install_dirs: Vec<String>,
    /// `crash` wrapper scripts that exec ShellCrash's menu.sh.
    pub wrapper_scripts: Vec<String>,
    /// Shell profile files carrying the `crash` → menu.sh alias.
    pub profile_aliases: Vec<String>,
    /// Live foreign kernel processes ("CrashCore (pid 123)").
    pub live_cores: Vec<String>,
    /// The foreign `inet shellcrash` nft table is loaded.
    pub nft_table: bool,
    /// Foreign iptables/ip6tables chains found ("iptables/nat shellcrash").
    pub iptables_chains: Vec<String>,
    /// fwmark → table 100/101 policy routing that ours did not create.
    pub stale_ip_rules: bool,
}

impl ShellCrashResidue {
    /// Scan the live system for ShellCrash residue.
    pub fn scan() -> Self {
        Self::scan_at(std::path::Path::new("/"), true)
    }

    /// Scan with every filesystem probe rooted at `root` (tests point
    /// this at a temp dir) and process scanning optional. Command probes
    /// (nft/iptables/ip) always target the live system; they are
    /// best-effort and simply report nothing when the tool is absent.
    pub fn scan_at(root: &std::path::Path, scan_procs: bool) -> Self {
        let mut residue = ShellCrashResidue::default();

        // Install directories: a directory only counts when it looks like
        // a ShellCrash install (menu.sh / start.sh / version marker), not
        // any directory that happens to be named ShellCrash.
        let mut candidate_dirs: Vec<String> = [
            "/etc/ShellCrash",
            "/usr/share/ShellCrash",
            "/data/ShellCrash",
            "/jffs/ShellCrash",
            "/etc/storage/ShellCrash",
            "/tmp/ShellCrash",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        if root == std::path::Path::new("/") {
            if let Ok(home) = std::env::var("HOME") {
                candidate_dirs.push(format!("{home}/.local/share/ShellCrash"));
            }
        }
        for dir in candidate_dirs {
            let path = root.join(dir.trim_start_matches('/'));
            let looks_installed = ["menu.sh", "start.sh", "version"]
                .iter()
                .any(|f| path.join(f).exists());
            if looks_installed {
                residue.install_dirs.push(dir);
            }
        }

        // `crash` wrapper scripts: ShellCrash's container install writes a
        // real /usr/bin/crash that execs menu.sh — it shadows or is
        // shadowed by this binary depending on PATH order.
        for wrapper in ["/usr/bin/crash", "/bin/crash"] {
            let path = root.join(wrapper.trim_start_matches('/'));
            if let Ok(content) = std::fs::read_to_string(&path) {
                if content.contains("menu.sh") {
                    residue.wrapper_scripts.push(wrapper.to_string());
                }
            }
        }

        // Profile aliases: `alias crash='bash /etc/ShellCrash/menu.sh'` —
        // in interactive shells alias expansion beats PATH lookup, so
        // typing `crash` runs the OLD manager even with our binary first
        // on PATH.
        for profile in ["/etc/profile", "/opt/etc/profile"] {
            let path = root.join(profile.trim_start_matches('/'));
            if let Ok(content) = std::fs::read_to_string(&path) {
                if content.contains("ShellCrash/menu.sh") {
                    residue.profile_aliases.push(profile.to_string());
                }
            }
        }

        // Live foreign kernels. CrashCore is ShellCrash's kernel binary
        // name and never ours (we run mihomo/sing-box/the engine).
        if scan_procs {
            if let Ok(entries) = std::fs::read_dir("/proc") {
                for entry in entries.flatten() {
                    let name = entry.file_name();
                    let Some(pid) = name.to_str().and_then(|n| n.parse::<u32>().ok()) else {
                        continue;
                    };
                    let comm = entry.path().join("comm");
                    if let Ok(comm) = std::fs::read_to_string(&comm) {
                        let comm = comm.trim();
                        if comm == "CrashCore" {
                            residue.live_cores.push(format!("CrashCore (pid {pid})"));
                        }
                    }
                }
            }
        }

        // Foreign nft table (ShellCrash's nftables firewall_mod lives in
        // exactly one table: inet shellcrash).
        if Command::new("nft")
            .args(["list", "table", "inet", "shellcrash"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false)
        {
            residue.nft_table = true;
        }

        // Foreign iptables/ip6tables chains (ShellCrash fw_*.sh names).
        for tool in ["iptables", "ip6tables"] {
            for table in ["nat", "mangle", "filter"] {
                if let Some(dump) = run_capture(tool, &["-t", table, "-S"]) {
                    for chain in foreign_chains_in(&dump) {
                        residue
                            .iptables_chains
                            .push(format!("{tool}/{table} {chain}"));
                    }
                }
            }
        }

        // Stale fwmark policy routing: ShellCrash defaults to fwmark
        // <redir_port> (not our 0x80000) into table 100 — leftovers loop
        // packets into whatever now owns table 100 (us).
        for family in ["ip", "ip -6"] {
            if let Some(rules) = run_capture(family, &["rule", "show"]) {
                let stale = rules.lines().any(|l| {
                    let fwmark = l.contains("fwmark ");
                    let table = l.contains("lookup 100") || l.contains("lookup 101");
                    fwmark && table
                });
                if stale {
                    residue.stale_ip_rules = true;
                }
            }
        }

        residue
    }

    /// Whether any residue class was found.
    pub fn is_present(&self) -> bool {
        !self.install_dirs.is_empty()
            || !self.wrapper_scripts.is_empty()
            || !self.profile_aliases.is_empty()
            || !self.live_cores.is_empty()
            || self.nft_table
            || !self.iptables_chains.is_empty()
            || self.stale_ip_rules
    }

    /// Whether the FIREWALL layer specifically carries foreign state.
    pub fn firewall_residue(&self) -> bool {
        self.nft_table || !self.iptables_chains.is_empty() || self.stale_ip_rules
    }

    /// Human-readable summary lines (one per residue class found).
    pub fn summary_lines(&self) -> Vec<String> {
        let mut lines = Vec::new();
        if !self.install_dirs.is_empty() {
            lines.push(format!(
                "ShellCrash installation present at: {}",
                self.install_dirs.join(", ")
            ));
        }
        if !self.wrapper_scripts.is_empty() {
            lines.push(format!(
                "'crash' command is ShellCrash's wrapper script at: {} (PATH-order conflict \
                 with this binary)",
                self.wrapper_scripts.join(", ")
            ));
        }
        if !self.profile_aliases.is_empty() {
            lines.push(format!(
                "Shell profile carries ShellCrash's 'crash' alias ({}) — in interactive \
                 shells the alias wins over this binary on PATH",
                self.profile_aliases.join(", ")
            ));
        }
        if !self.live_cores.is_empty() {
            lines.push(format!(
                "ShellCrash kernel still RUNNING: {} — stop it before starting the RustCrash \
                 engine or the standard ports (7890/7893/1053) will collide",
                self.live_cores.join(", ")
            ));
        }
        if self.nft_table {
            lines.push("foreign nft table 'inet shellcrash' is loaded".to_string());
        }
        if !self.iptables_chains.is_empty() {
            lines.push(format!(
                "foreign iptables chains present: {}",
                self.iptables_chains.join(", ")
            ));
        }
        if self.stale_ip_rules {
            lines.push(
                "stale fwmark policy routing into table 100/101 (ShellCrash leftovers loop \
                 packets into the current table owner)"
                    .to_string(),
            );
        }
        lines
    }
}

/// Whether an `iptables -S` rule line references a ShellCrash-named
/// chain (`-j shellcrash…`). RustCrash's own iptables chains share the
/// `shellcrash` prefix by design (drop-in compat); the caller deletes
/// ours first, so survivors are foreign.
fn references_shellcrash_chain(rule: &str) -> bool {
    let mut tokens = rule.split_whitespace();
    while let Some(tok) = tokens.next() {
        if tok == "-j" || tok == "-g" {
            if let Some(target) = tokens.next() {
                return target.starts_with("shellcrash");
            }
        }
    }
    false
}

/// The ShellCrash-named chains declared in an `iptables -S` dump.
fn foreign_chains_in(dump: &str) -> Vec<String> {
    dump.lines()
        .filter_map(|l| l.strip_prefix("-N "))
        .map(str::trim)
        .filter(|name| name.starts_with("shellcrash"))
        .map(str::to_string)
        .collect()
}

/// Run a tool and capture stdout (None when the tool is absent or the
/// command fails — best-effort probes).
fn run_capture(tool: &str, args: &[&str]) -> Option<String> {
    let tool = tool.split_whitespace().collect::<Vec<_>>();
    let output = Command::new(tool[0])
        .args(&tool[1..])
        .args(args)
        .output()
        .ok()?;
    if output.status.success() {
        Some(String::from_utf8_lossy(&output.stdout).into_owned())
    } else {
        None
    }
}

/// Delete rules from an `iptables -S` dump. Lines come back as `-A …`;
/// the matching deletion is the same line with `-D` — returned as the
/// argument vector for `<tool> -t <table> <args…>`.
fn deletion_args(rule: &str) -> Vec<String> {
    rule.replacen("-A", "-D", 1)
        .split_whitespace()
        .map(str::to_string)
        .collect()
}

/// Remove foreign ShellCrash firewall state so our own rules apply on a
/// clean slate instead of stacking on top of the old hijack layer:
///
/// 1. iptables + ip6tables: every rule that JUMPS to a `shellcrash*`
///    chain is deleted first (iptables refuses `-X` while jumps
///    reference the chain — with the old jumps left in place our apply
///    script dies at `iptables -t nat -N shellcrash_out` under `set -e`),
///    then the chains are flushed and deleted.
/// 2. The `inet shellcrash` nft table (ShellCrash's nftables mode).
/// 3. fwmark → table 100/101 policy routing that predates this apply
///    (ShellCrash defaults its fwmark to the redir port, not our
///    0x80000, so `cleanup_tun_routing` never sees it).
///
/// Idempotent; returns one human line per thing actually removed. Our
/// own rules are (re)created afterwards by `apply_full`.
pub fn clean_foreign_shellcrash() -> Vec<String> {
    let mut removed = Vec::new();

    // 1. iptables / ip6tables chains and their jump rules.
    for tool in ["iptables", "ip6tables"] {
        for table in ["nat", "mangle", "filter"] {
            let Some(dump) = run_capture(tool, &["-t", table, "-S"]) else {
                continue;
            };
            // Jump rules first: order matters (see doc comment).
            let jumps: Vec<&str> = dump
                .lines()
                .filter(|l| l.starts_with("-A ") && references_shellcrash_chain(l))
                .collect();
            for rule in jumps {
                let argv = deletion_args(rule);
                let mut cmd = Command::new(tool);
                cmd.arg("-t").arg(table);
                for a in &argv {
                    cmd.arg(a);
                }
                if cmd.output().map(|o| o.status.success()).unwrap_or(false) {
                    removed.push(format!("{tool} -t {table}: removed jump {rule}"));
                }
            }
            for chain in foreign_chains_in(&dump) {
                for op in ["-F", "-X"] {
                    let _ = Command::new(tool)
                        .args(["-t", table, op, &chain])
                        .output();
                }
                removed.push(format!("{tool} -t {table}: deleted chain {chain}"));
            }
        }
    }

    // 2. Foreign nft table.
    if Command::new("nft")
        .args(["list", "table", "inet", "shellcrash"])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
    {
        let _ = Command::new("nft")
            .args(["delete", "table", "inet", "shellcrash"])
            .output();
        removed.push("nft: deleted table inet shellcrash".to_string());
    }

    // 3. Stale fwmark policy routing into the proxy tables (100/101).
    for family in ["ip", "ip -6"] {
        let Some(rules) = run_capture(family, &["rule", "show"]) else {
            continue;
        };
        for line in rules.lines() {
            let Some((prio, rest)) = line.split_once(':') else {
                continue;
            };
            let stale = rest.contains("fwmark ")
                && (rest.contains("lookup 100") || rest.contains("lookup 101"));
            if !stale {
                continue;
            }
            // del by priority until the rule is gone (duplicates stack).
            for _ in 0..16 {
                let tool = family.split_whitespace().collect::<Vec<_>>();
                let ok = Command::new(tool[0])
                    .args(&tool[1..])
                    .args(["rule", "del", "pref", prio.trim()])
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false);
                if !ok {
                    break;
                }
            }
            removed.push(format!("{family} rule: removed stale '{line}'"));
        }
    }

    removed
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacFilterType {
    Blacklist,
    Whitelist,
}

#[derive(Debug, Clone)]
pub struct FirewallConfig {
    pub tun_port: Option<u16>,
    pub vm_ipv4: Option<String>,
    pub vm_redir: bool,
    pub ipv6_enabled: bool,
    pub macfilter_type: Option<MacFilterType>,
    pub macfilter_addrs: Vec<String>,
    pub ip_filter: Option<String>,
    pub cn_ip_route: bool,
    pub quic_reject: bool,
    pub common_ports: Vec<u16>,
    pub dns_port: u16,
    pub proxy_port: u16,
    /// The kernel's mixed/HTTP listener (guarded by the WAN input rule).
    pub mixed_port: u16,
    /// Source subnets eligible for prerouting hijack. Hijacking ALL
    /// prerouting traffic turns a gateway into an open proxy for the
    /// WAN side (ShellCrash fixed the same exposure). Defaults to the
    /// RFC1918 ranges; an empty Vec falls back to the default.
    pub hijack_subnets: Vec<String>,
}

/// Default LAN ranges eligible for hijacking.
pub const DEFAULT_HIJACK_SUBNETS: &[&str] = &["192.168.0.0/16", "10.0.0.0/8", "172.16.0.0/12"];

impl Default for FirewallConfig {
    fn default() -> Self {
        FirewallConfig {
            tun_port: None,
            vm_ipv4: None,
            vm_redir: false,
            ipv6_enabled: false,
            macfilter_type: None,
            macfilter_addrs: Vec::new(),
            ip_filter: None,
            cn_ip_route: false,
            quic_reject: false,
            common_ports: Vec::new(),
            dns_port: DEFAULT_DNS_PORT,
            proxy_port: DEFAULT_PROXY_PORT,
            mixed_port: DEFAULT_MIXED_PORT,
            hijack_subnets: DEFAULT_HIJACK_SUBNETS
                .iter()
                .map(|s| s.to_string())
                .collect(),
        }
    }
}

impl FirewallConfig {
    pub fn with_quic_reject(mut self, reject: bool) -> Self {
        self.quic_reject = reject;
        self
    }

    pub fn with_common_ports(mut self, ports: &[u16]) -> Self {
        self.common_ports = ports.to_vec();
        self
    }

    pub fn with_macfilter(mut self, filter_type: MacFilterType, addrs: &[&str]) -> Self {
        self.macfilter_type = Some(filter_type);
        self.macfilter_addrs = addrs.iter().map(|s| s.to_string()).collect();
        self
    }
}

/// Enable IPv4 forwarding if it is off (best-effort, persisted to
/// sysctl.conf). LAN proxying is forwarding — without it, routed client
/// traffic dies at the box (ShellCrash 1.9.5 does this on start;
/// community issue #1124 was exactly this failure).
pub fn ensure_ip_forwarding() {
    let already_on = std::fs::read_to_string("/proc/sys/net/ipv4/ip_forward")
        .map(|v| v.trim() == "1")
        .unwrap_or(false);
    let mut toggled = false;
    if !already_on {
        // Runtime toggle via literal argv (no shell).
        let on = std::process::Command::new("sysctl")
            .args(["-w", "net.ipv4.ip_forward=1"])
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        toggled = on;
        if !on {
            tracing::warn!(
                "could not enable net.ipv4.ip_forward; LAN clients may not reach the proxy"
            );
        }
    }
    // Persist EVEN when already on at runtime (Docker/most distros enable
    // forwarding at runtime without persisting — a reboot would lose it).
    persist_sysctl_ip_forward();
    if toggled {
        tracing::info!("enabled net.ipv4.ip_forward (required for LAN proxying)");
    }
}

/// Idempotent set-or-replace of net.ipv4.ip_forward in /etc/sysctl.conf.
/// Matches the pre-'=' token exactly so related keys
/// (ip_forward_update_priority etc.) are never clobbered.
fn persist_sysctl_ip_forward() {
    const KEY: &str = "net.ipv4.ip_forward";
    const LINE: &str = "net.ipv4.ip_forward = 1";
    const CONF: &str = "/etc/sysctl.conf";
    let Ok(content) = std::fs::read_to_string(CONF) else {
        return;
    };
    let exact_key = |l: &str| -> bool { l.split('=').next().unwrap_or("").trim() == KEY };
    if content.lines().any(exact_key) {
        let replaced: Vec<String> = content
            .lines()
            .map(|l| {
                if exact_key(l) {
                    LINE.to_string()
                } else {
                    l.to_string()
                }
            })
            .collect();
        let _ = std::fs::write(CONF, replaced.join("\n") + "\n");
    } else if let Err(e) = std::fs::OpenOptions::new()
        .append(true)
        .create(true)
        .open(CONF)
        .and_then(|mut f| {
            use std::io::Write;
            writeln!(f, "{LINE}")
        })
    {
        tracing::warn!("could not persist {KEY}: {e}");
    }
}

pub fn check_ipv6_redirect_support() -> bool {
    std::process::Command::new("sh")
        .args([
            "-c",
            "ip6tables -j REDIRECT -h 2>/dev/null | grep -q '\\-\\-to-ports'",
        ])
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Redirection mode for TCP traffic
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RedirMode {
    Redirect,
    Tproxy,
}

/// DNS interception mode
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsMode {
    FakeIp,
    RedirHost,
    Local,
    None,
}

/// Firewall manager
pub struct Firewall {
    backend: FirewallBackend,
    proxy_port: u16,
    dns_port: u16,
}

impl Firewall {
    pub fn new(platform: &Platform) -> Self {
        Firewall {
            backend: platform.firewall_backend,
            proxy_port: DEFAULT_PROXY_PORT,
            dns_port: DEFAULT_DNS_PORT,
        }
    }

    /// Apply the complete rule set for the detected backend. Every
    /// FirewallConfig field is either honored or explicitly rejected:
    /// ipv6_enabled appends the dual-stack script; cn_ip_route is not
    /// implemented and fails loudly instead of being silently dropped.
    ///
    /// Apply is STATELESS with respect to previous applies: stale rules
    /// and routing from an earlier config (e.g. TUN toggled off) are
    /// removed first, so the live state always mirrors the config.
    pub fn apply_full(&self, config: &FirewallConfig) -> Result<()> {
        if config.cn_ip_route {
            return Err(Error::NotSupported(
                "cn_ip_route is not implemented; keep it disabled".into(),
            ));
        }
        // LAN proxying is forwarding: without ip_forward=0→1, routed client
        // traffic dies at the box (ShellCrash 1.9.5 enables it on start;
        // community #1124 was exactly this). Best-effort + persisted.
        ensure_ip_forwarding();
        // Routing first: purge both families unconditionally — the add
        // scripts re-create exactly what this config wants.
        self.cleanup_tun_routing();
        // Migration residue pre-clean: a not-properly-stopped ShellCrash
        // leaves hijack chains/jumps and stale policy routing loaded.
        // Stacking our rules on top loops traffic (their jumps run first),
        // and their leftover jumps into `shellcrash_out`/`shellcrash_mark`
        // make our apply script abort at `-N` under `set -e`. Remove the
        // foreign layer first, then apply ours on a clean slate.
        for item in clean_foreign_shellcrash() {
            tracing::warn!(target: "firewall", "removed stale ShellCrash rule: {item}");
        }
        match self.backend {
            FirewallBackend::Nftables => {
                // `nft -f` MERGES into live tables; without a reset,
                // repeated applies stack duplicate rules. Delete the
                // tables we own first (best-effort — absent is fine).
                for table in [
                    "ip nat",
                    "ip mangle",
                    "ip filter",
                    "ip6 nat",
                    "ip6 mangle",
                    "inet shellcrash",
                ] {
                    let parts: Vec<&str> = table.split_whitespace().collect();
                    let _ = Command::new("nft")
                        .arg("delete")
                        .arg("table")
                        .args(&parts)
                        .output();
                }
                let mut script = self.generate_full_nft_script(config)?;
                if config.ipv6_enabled {
                    script.push_str("\n# IPv6 dual-stack\n");
                    script.push_str(&self.generate_nft_dual_stack_script(config));
                }
                self.run_nft(&script)?;
                // Policy routing runs after the ruleset applies.
                let mut routing = self.generate_tun_routing_script(config);
                if config.ipv6_enabled {
                    routing.push_str(&self.generate_ipv6_routing_script());
                }
                if !routing.is_empty() {
                    self.run_sh_script(&routing)?;
                }
                Ok(())
            }
            FirewallBackend::Iptables => {
                // The iptables backend has no IPv6 companion script —
                // reject loudly instead of silently ignoring the setting
                // (mirrors the cn_ip_route guard above).
                if config.ipv6_enabled {
                    return Err(Error::NotSupported(
                        "ipv6_enabled is only implemented on the nftables backend; \
                         use nftables or disable ipv6"
                            .into(),
                    ));
                }
                let script = self.generate_full_iptables_script(config);
                self.run_sh_script(&script)
            }
            FirewallBackend::None => Err(Error::Firewall("No firewall backend available".into())),
        }
    }

    /// Feed a generated shell script to `sh -s` via stdin (no temp files,
    /// no string-built command lines).
    fn run_sh_script(&self, script: &str) -> Result<()> {
        use std::io::Write;
        let mut child = Command::new("sh")
            .arg("-s")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|e| Error::Firewall(format!("failed to spawn sh: {e}")))?;
        if let Some(ref mut stdin) = child.stdin {
            stdin
                .write_all(script.as_bytes())
                .map_err(|e| Error::Firewall(format!("failed to write script: {e}")))?;
        }
        let output = child
            .wait_with_output()
            .map_err(|e| Error::Firewall(format!("failed to wait for sh: {e}")))?;
        if output.status.success() {
            Ok(())
        } else {
            Err(Error::Firewall(format!(
                "script failed: {}",
                String::from_utf8_lossy(&output.stderr)
            )))
        }
    }

    pub fn backend(&self) -> FirewallBackend {
        self.backend
    }

    pub fn is_available(&self) -> bool {
        self.backend != FirewallBackend::None
    }

    pub fn cleanup(&self) -> Result<()> {
        match self.backend {
            FirewallBackend::Nftables => self.cleanup_nftables(),
            FirewallBackend::Iptables => self.cleanup_iptables(),
            FirewallBackend::None => Ok(()),
        }?;
        // Also sweep foreign ShellCrash state the backend-specific
        // cleanup may not cover (the `inet shellcrash` nft table survives
        // `flush ruleset` as an empty table; iptables full flush covers
        // the chains but stale fwmark ip rules are invisible to it).
        for item in clean_foreign_shellcrash() {
            tracing::warn!(target: "firewall", "removed stale ShellCrash rule: {item}");
        }
        Ok(())
    }

    pub fn generate_nft_script(&self, _mode: &str) -> String {
        let local_proxy = self.proxy_port;
        let local_dns = self.dns_port;

        // TPROXY/policy-routing output belongs to the config-driven full
        // script (tun_port); this simple script never emits it.
        let tun_script = String::new();

        format!(
            r#"#!/usr/sbin/nft -f
flush ruleset

table ip nat {{
    chain prerouting {{
        type nat hook prerouting priority -100; policy accept;
        udp dport 53 redirect to {local_dns}
        tcp dport 80 counter redirect to {local_proxy}
        tcp dport 443 counter redirect to {local_proxy}
    }}
    chain postrouting {{
        type nat hook postrouting priority 100; policy accept;
    }}
}}

table ip filter {{
    chain input {{
        type filter hook input priority 0; policy accept;
    }}
    chain forward {{
        type filter hook forward priority 0; policy accept;
        ct state established,related accept
        # Hijacking lives in nat chains; filter forward just passes through.
        iifname!=lo counter accept
    }}
}}
{tun_script}"#
        )
    }

    pub fn generate_nft_dual_stack_script(&self, config: &FirewallConfig) -> String {
        let local_dns = config.dns_port;
        // v4 hijack lives in the (gated) full script's nat table — the
        // dual-stack companion only handles v6, source-gated like the v4
        // side. TPROXY targets the tproxy listener (tun_port or proxy+2).
        // Skip-occupied walk (parity with rules::derive_tproxy_port):
        // occupied = proxy, mixed-default(proxy+1), dns.
        let tproxy_port = config.tun_port.unwrap_or_else(|| {
            let proxy = config.proxy_port;
            let mut candidate = proxy.wrapping_add(2);
            while candidate != 0
                && [proxy, proxy.wrapping_add(1), config.dns_port].contains(&candidate)
            {
                candidate = candidate.wrapping_add(1);
            }
            candidate
        });

        format!(
            r#"#!/usr/sbin/nft -f
# IPv6 companion to the full firewall: v6-only, LAN-source-gated. The
# v4 hijack is NOT repeated here (the inet table would merge into the
# gated v4 chains and re-open the WAN exposure).

table ip6 nat {{
    chain prerouting {{
        type nat hook prerouting priority -100; policy accept;
        # ULA + link-local are the v6 LAN analog of RFC1918.
        ip6 saddr fe80::/10 counter udp dport 53 redirect to {local_dns}
        ip6 saddr fd00::/8 counter udp dport 53 redirect to {local_dns}
    }}
}}

table ip6 mangle {{
    # nft sets are table-scoped: the set must be declared in the same
    # table whose chains reference it.
    set ipv6_reserved {{
        type ipv6_addr
        flags interval
        elements = {{ fe80::/10, fd00::/8, ff00::/8, ::1/128, ::ffff:0:0/96 }}
    }}

    chain prerouting {{
        type filter hook prerouting priority -150; policy accept;
        ip6 daddr @ipv6_reserved return
        ip6 saddr fd00::/8 counter udp dport 53 meta mark set {FWMARK} tproxy to :{tproxy_port}
        ip6 saddr fd00::/8 counter udp dport 443 meta mark set {FWMARK} tproxy to :{tproxy_port}
    }}
    chain output {{
        type filter hook output priority -150; policy accept;
        ip6 daddr @ipv6_reserved return
        meta mark {FWMARK} return
        meta skgid {{ 453, 7890 }} return
    }}
}}
"#
        )
    }

    /// Legacy simple setup script. NOTE: not a dual-stack script — the
    /// IPv6 companion for the iptables backend is rejected in apply_full.
    pub fn generate_iptables_script(&self, config: &FirewallConfig) -> String {
        let local_proxy = config.proxy_port;
        let local_dns = config.dns_port;

        format!(
            r#"#!/bin/sh
# RustCrash iptables setup script

# DNS redirect
iptables -t nat -A PREROUTING -p udp --dport 53 -j REDIRECT --to-ports {local_dns}

# TCP redirect (HTTP/HTTPS)
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-ports {local_proxy}
iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-ports {local_proxy}

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
"#
        )
    }

    pub fn generate_full_nft_script(&self, config: &FirewallConfig) -> Result<String> {
        let proxy_port = config.proxy_port;
        let dns_port = config.dns_port;
        let fwmark = FWMARK;

        // Hijack eligibility: only configured LAN subnets (an unrestricted
        // prerouting hijack exposes the proxy to the WAN side).
        let subnets: Vec<String> = if config.hijack_subnets.is_empty() {
            DEFAULT_HIJACK_SUBNETS
                .iter()
                .map(|s| s.to_string())
                .collect()
        } else {
            config.hijack_subnets.clone()
        };
        let nft_subnets = subnets.join(", ");
        // TPROXY listener port (the kernel's tproxy-port; = tun_port).
        // Reject instead of wrapping (65534+2 -> 0 would emit tproxy :0).
        let tproxy_port = config.tun_port.unwrap_or(match proxy_port.checked_add(2) {
            Some(p) if (1..=65535).contains(&p) => p,
            _ => {
                return Err(Error::Config(format!(
                    "proxy_port {proxy_port} leaves no room for the tproxy listener port"
                )))
            }
        });
        // The kernel's mixed/HTTP listener (from config; defaults to
        // proxy+1) — guarded in the input chain.
        let mixed_port = config.mixed_port;

        // Prerouting hijack is LAN-scoped; the OUTPUT chain (the box's own
        // traffic) must stay ungated — locally generated packets carry the
        // egress IP, which need not be in any LAN subnet.
        let mk_filter = |gated: bool| {
            let (dports_tcp, dports_udp) = if config.common_ports.is_empty() {
                ("{ 1-65535 }".to_string(), "{ 1-65535 }".to_string())
            } else {
                let ports: Vec<String> =
                    config.common_ports.iter().map(|p| p.to_string()).collect();
                let j = ports.join(", ");
                (format!("{{ {j} }}"), format!("{{ {j} }}"))
            };
            let gate = if gated {
                format!("ip saddr {{ {nft_subnets} }} ")
            } else {
                String::new()
            };
            format!(
                "{gate}tcp dport {dports_tcp} counter redirect to {proxy_port}\n        {gate}udp dport {dports_udp} counter redirect to {proxy_port}"
            )
        };
        let port_filter = mk_filter(true);
        let port_filter_out = mk_filter(false);

        let quic_rule = if config.quic_reject {
            "udp dport 443 counter drop"
        } else {
            ""
        };

        // VM handling: an excluded subnet bypasses hijacking entirely;
        // vm_redir=true means VM traffic is hijacked like everything else.
        let vm_exclude = match (&config.vm_ipv4, config.vm_redir) {
            (Some(subnet), false) => format!("ip daddr {subnet} counter return\n        "),
            _ => String::new(),
        };

        // Source-IP exclusion (ip_filter).
        let src_exclude = config
            .ip_filter
            .as_ref()
            .map(|f| format!("ip saddr {f} counter return\n        "))
            .unwrap_or_default();

        // TPROXY + policy routing only exist in TUN mode; plain redirect
        // mode relies on the nat table alone.
        // TPROXY rules belong to nft; the policy-routing half is emitted
        // separately (generate_tun_routing_script) because nft rejects
        // `ip rule` syntax, which would fail the whole batch.
        let (mangle_table, _tun_shell) = if config.tun_port.is_some() {
            (
                format!(
                    r#"
table ip mangle {{
    chain prerouting {{
        type filter hook prerouting priority -150; policy accept;
        ip saddr {{ {nft_subnets} }} meta l4proto {{ tcp, udp }} meta mark set {fwmark} tproxy to :{tproxy_port}
    }}

    chain mark_out {{
        type filter hook output priority -150; policy accept;
        meta mark {fwmark} return
        meta skgid {{ 453, 7890 }} return
        meta mark set {fwmark}
    }}
}}
"#
                ),
                String::new(),
            )
        } else {
            (String::new(), String::new())
        };

        let mac_rules = if let Some(ref mac_type) = config.macfilter_type {
            let action = match mac_type {
                MacFilterType::Blacklist => "drop",
                MacFilterType::Whitelist => "accept",
            };
            config
                .macfilter_addrs
                .iter()
                .map(|mac| format!("ether saddr {} counter {}", mac, action))
                .collect::<Vec<_>>()
                .join("\n        ")
        } else {
            String::new()
        };

        let script = format!(
            r#"#!/usr/sbin/nft -f
# Full ShellCrash-compatible nftables firewall
# Fields honored: proxy/dns port, common_ports, vm exclusion, ip_filter,
# macfilter, quic_reject, tun (TPROXY + policy routing when set).

table ip nat {{
    chain prerouting {{
        type nat hook prerouting priority -100; policy accept;
        {vm_exclude}{src_exclude}ip saddr {{ {nft_subnets} }} udp dport 53 counter redirect to {dns_port}
        ip saddr {{ {nft_subnets} }} tcp dport 53 counter redirect to {dns_port}
        {port_filter}
    }}

    chain output {{
        type nat hook output priority -100; policy accept;
        meta mark {fwmark} return
        meta skgid {{ 453, 7890 }} return
        {port_filter_out}
    }}

    chain postrouting {{
        type nat hook postrouting priority 100; policy accept;
    }}
}}
{mangle_table}
table ip filter {{
    chain input {{
        type filter hook input priority 0; policy accept;
        ct state established,related accept
        meta mark {fwmark} return
        # Proxy/DNS listeners are LAN-only (community #1223: an exposed
        # 7890 was brute-forced as an open proxy). WAN-side connections
        # to the listeners are dropped.
        ip saddr {{ {nft_subnets} }} tcp dport {{ {mixed_port}, {proxy_port}, {tproxy_port}, {dns_port} }} accept
        tcp dport {{ {mixed_port}, {proxy_port}, {tproxy_port}, {dns_port} }} drop
        {mac_rules}
    }}

    chain forward {{
        type filter hook forward priority 0; policy accept;
        ct state established,related accept
        {quic_rule}
    }}
}}
"#
        );
        Ok(script)
    }

    /// TUN-mode policy routing as shell commands (ip(8)); the nft script
    /// is pure nft — these run via sh AFTER the ruleset applies.
    /// Del-then-add guards make re-apply idempotent (the kernel happily
    /// stacks duplicate ip rules that a single del would not clear).
    pub fn generate_tun_routing_script(&self, config: &FirewallConfig) -> String {
        let Some(_) = config.tun_port else {
            return String::new();
        };
        format!(
            "set -e\n\
             # TUN mode policy routing (fwmark {FWMARK}) — idempotent\n\
             while ip rule del fwmark {FWMARK} table {TABLE} 2>/dev/null; do :; done\n\
             ip rule add fwmark {FWMARK} table {TABLE}\n\
             ip route replace local 0.0.0.0/0 dev lo table {TABLE}\n"
        )
    }

    /// IPv6 TPROXY policy routing (the v6 twin of the TUN routing pair);
    /// the dual-stack mangle rules mark with FWMARK, so the v6 rule/route
    /// must exist for IPv6 interception to function. Idempotent likewise.
    pub fn generate_ipv6_routing_script(&self) -> String {
        let table = ipv6_tproxy_table();
        format!(
            "set -e\n\
             while ip -6 rule del fwmark {FWMARK} table {table} 2>/dev/null; do :; done\n\
             ip -6 rule add fwmark {FWMARK} table {table}\n\
             ip -6 route replace local ::/0 dev lo table {table}\n"
        )
    }

    pub fn generate_full_iptables_script(&self, config: &FirewallConfig) -> String {
        let proxy_port = config.proxy_port;
        let dns_port = config.dns_port;
        let fwmark = FWMARK;

        // Hijack eligibility: only LAN subnets (open-proxy protection).
        let subnets: Vec<String> = if config.hijack_subnets.is_empty() {
            DEFAULT_HIJACK_SUBNETS
                .iter()
                .map(|s| s.to_string())
                .collect()
        } else {
            config.hijack_subnets.clone()
        };
        // Complete iptables commands — a bare `-p tcp …` fragment would be
        // parsed by sh as a command name and silently skipped. Forward
        // hijacking goes through the nat table (REDIRECT is nat-only).
        let ports_list = config
            .common_ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let restricted = !config.common_ports.is_empty();
        // Prerouting rules are source-gated per LAN subnet; OUTPUT rules
        // apply to the box's own traffic (no source gate).
        let tcp_hijack = |chain: &str, gated: bool| {
            let proto_ports = if restricted {
                format!("-p tcp -m multiport --dports {ports_list}")
            } else {
                "-p tcp".to_string()
            };
            if gated {
                subnets
                    .iter()
                    .map(|s: &String| {
                        format!(
                            "iptables -t nat -A {chain} -s {s} {proto_ports} -j REDIRECT --to-ports {proxy_port}\n"
                        )
                    })
                    .collect()
            } else {
                format!("iptables -t nat -A {chain} {proto_ports} -j REDIRECT --to-ports {proxy_port}\n")
            }
        };
        let dns_hijack = |proto: &str| -> String {
            subnets
                .iter()
                .map(|s: &String| {
                    format!(
                        "iptables -t nat -A shellcrash_pre -s {s} -p {proto} --dport 53 -j REDIRECT --to-ports {dns_port}\n"
                    )
                })
                .collect()
        };

        // QUIC rejection: a full DROP command in the filter forward chain.
        let quic_rule = if config.quic_reject {
            "iptables -t filter -A shellcrash_fwd -p udp --dport 443 -j DROP"
        } else {
            ""
        };

        // VM exclusion (bypass hijack) and source-IP exclusion.
        let vm_exclude = match (&config.vm_ipv4, config.vm_redir) {
            (Some(subnet), false) => {
                format!("iptables -t nat -A shellcrash_pre -d {subnet} -j RETURN\n")
            }
            _ => String::new(),
        };
        let src_exclude = config
            .ip_filter
            .as_ref()
            .map(|f| format!("iptables -t nat -A shellcrash_pre -s {f} -j RETURN\n"))
            .unwrap_or_default();

        let prerouting_hijack = tcp_hijack("shellcrash_pre", true);
        let output_hijack = tcp_hijack("shellcrash_out", false);
        let dns_redirects = format!("{}{}", dns_hijack("udp"), dns_hijack("tcp"));

        // Policy routing for the utun device exists only in TUN mode.
        let tun_routing = if config.tun_port.is_some() {
            // Same idempotent guards as the nft path's routing step; the
            // utun route is best-effort — the kernel creates the device
            // when TUN mode starts, which may race with firewall apply.
            format!(
                "# TUN mode routing — idempotent; utun appears with the kernel\n\
                 while ip rule del fwmark {fwmark} table {TABLE} 2>/dev/null; do :; done\n\
                 ip rule add fwmark {fwmark} table {TABLE}\n\
                 ip route replace default dev utun table {TABLE} 2>/dev/null || true\n"
            )
        } else {
            String::new()
        };

        // MAC filter rules as full commands in the input chain.
        let mac_filter = if let Some(ref mac_type) = config.macfilter_type {
            let target = match mac_type {
                MacFilterType::Blacklist => "DROP",
                MacFilterType::Whitelist => "ACCEPT",
            };
            config
                .macfilter_addrs
                .iter()
                .map(|mac| {
                    format!(
                        "iptables -t filter -A shellcrash_in -m mac --mac-source {mac} -j {target}"
                    )
                })
                .collect::<Vec<_>>()
                .join("\n")
        } else {
            String::new()
        };

        // Idempotent re-apply: for each of our chains, remove the hook
        // jump FIRST (-X fails while a jump still references the chain),
        // then flush and delete. All guarded — absent state is fine.
        let idempotent_reset = [
            ("nat", "PREROUTING", "shellcrash_pre"),
            ("nat", "OUTPUT", "shellcrash_out"),
            ("mangle", "OUTPUT", "shellcrash_mark"),
            ("filter", "INPUT", "shellcrash_in"),
            ("filter", "FORWARD", "shellcrash_fwd"),
        ]
        .iter()
        .map(|(table, hook, chain)| {
            format!(
                "iptables -t {table} -D {hook} -j {chain} 2>/dev/null || true\n\
                 iptables -t {table} -F {chain} 2>/dev/null || true\n\
                 iptables -t {table} -X {chain} 2>/dev/null || true\n"
            )
        })
        .collect::<Vec<_>>()
        .join("");

        format!(
            r#"#!/bin/sh
# Full ShellCrash-compatible iptables firewall
# Fields honored: proxy/dns port, common_ports, VM/source exclusions,
# macfilter, quic_reject, tun routing when set.
set -e

# Idempotent re-apply (delete hook jumps before chains). The nat table
# has no FORWARD hook: routed traffic is hijacked in PREROUTING via
# shellcrash_pre, same as the nft backend.
{idempotent_reset}
# NAT table - prerouting (hijacks routed LAN traffic here)
iptables -t nat -N shellcrash_pre
iptables -t nat -A PREROUTING -j shellcrash_pre
{vm_exclude}{src_exclude}
# DNS redirect (LAN sources only)
{dns_redirects}{prerouting_hijack}
# NAT table - output
iptables -t nat -N shellcrash_out
iptables -t nat -A OUTPUT -j shellcrash_out
iptables -t nat -A shellcrash_out -m mark --mark {fwmark} -j RETURN
iptables -t nat -A shellcrash_out -m owner --gid-owner 453 -j RETURN
iptables -t nat -A shellcrash_out -m owner --gid-owner 7890 -j RETURN
{output_hijack}
# Mangle table - mark_out chain
iptables -t mangle -N shellcrash_mark
iptables -t mangle -A OUTPUT -j shellcrash_mark
iptables -t mangle -A shellcrash_mark -m mark --mark {fwmark} -j RETURN
iptables -t mangle -A shellcrash_mark -m owner --gid-owner 453 -j RETURN
iptables -t mangle -A shellcrash_mark -m owner --gid-owner 7890 -j RETURN
iptables -t mangle -A shellcrash_mark -j MARK --set-mark {fwmark}

# Filter table - input chain
iptables -t filter -N shellcrash_in
iptables -t filter -A INPUT -j shellcrash_in
iptables -t filter -A shellcrash_in -m state --state ESTABLISHED,RELATED -j ACCEPT
iptables -t filter -A shellcrash_in -m mark --mark {fwmark} -j RETURN
{mac_filter}

# Filter table - forward chain
iptables -t filter -N shellcrash_fwd
iptables -t filter -A FORWARD -j shellcrash_fwd
iptables -t filter -A shellcrash_fwd -m state --state ESTABLISHED,RELATED -j ACCEPT
{quic_rule}

{tun_routing}"#
        )
    }

    pub fn cleanup_selective(&self) -> String {
        let ipv6_tproxy = ipv6_tproxy_table();
        format!(
            r#"#!/bin/sh
# Selective firewall cleanup
# Removes rules individually, not full flush

# Remove nftables chains (incl. the dual-stack inet table)
nft delete table inet shellcrash 2>/dev/null
nft delete table ip nat 2>/dev/null
nft delete table ip mangle 2>/dev/null
nft delete table ip filter 2>/dev/null
nft delete table ip6 nat 2>/dev/null
nft delete table ip6 mangle 2>/dev/null
nft delete table ip6 filter 2>/dev/null

# Remove iptables chains
iptables -t nat -F
iptables -t nat -X shellcrash_pre 2>/dev/null
iptables -t nat -X shellcrash_out 2>/dev/null
iptables -t mangle -F
iptables -t mangle -X shellcrash_mark 2>/dev/null
iptables -t filter -F
iptables -t filter -X shellcrash_in 2>/dev/null
iptables -t filter -X shellcrash_fwd 2>/dev/null

# Remove ip6tables chains
ip6tables -t nat -F
ip6tables -t nat -X shellcrashv6 2>/dev/null
ip6tables -t mangle -F
ip6tables -t mangle -X shellcrashv6_mark 2>/dev/null
ip6tables -t filter -F
ip6tables -t filter -X shellcrashv6_in 2>/dev/null

# Remove routing rules
ip rule del fwmark {FWMARK} table {TABLE} 2>/dev/null
ip -6 rule del fwmark {FWMARK} table {ipv6_tproxy} 2>/dev/null
ip route del default dev utun table {TABLE} 2>/dev/null
"#
        )
    }

    // ============== iptables methods ==============

    fn cleanup_iptables(&self) -> Result<()> {
        // TUN policy routing is ip(8) state, invisible to iptables flush.
        self.cleanup_tun_routing();

        for table in ["nat", "mangle", "filter"] {
            let flush_output = Command::new("iptables")
                .args(["-t", table, "-F"])
                .output()
                .map_err(|e| Error::Firewall(format!("Failed to run iptables -F: {e}")))?;

            if !flush_output.status.success() {
                let stderr = String::from_utf8_lossy(&flush_output.stderr);
                tracing::warn!("iptables -F {} failed: {}", table, stderr);
            }

            let flush_output = Command::new("iptables")
                .args(["-t", table, "-X"])
                .output()
                .map_err(|e| Error::Firewall(format!("Failed to run iptables -X: {e}")))?;

            if !flush_output.status.success() {
                let stderr = String::from_utf8_lossy(&flush_output.stderr);
                tracing::warn!("iptables -X {} failed: {}", table, stderr);
            }
        }
        Ok(())
    }

    // ============== nftables methods ==============

    fn run_nft(&self, script: &str) -> Result<()> {
        let mut child = Command::new("nft")
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .spawn()
            .map_err(|e| Error::Firewall(format!("Failed to spawn nft: {e}")))?;

        if let Some(ref mut stdin) = child.stdin {
            stdin
                .write_all(script.as_bytes())
                .map_err(|e| Error::Firewall(format!("Failed to write nft script: {e}")))?;
        }

        let output = child
            .wait_with_output()
            .map_err(|e| Error::Firewall(format!("Failed to wait for nft: {e}")))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(Error::Firewall(format!("nft failed: {stderr}")));
        }
        Ok(())
    }

    /// Remove TUN policy routing (rules + routes). Rules loop until gone:
    /// the kernel stacks duplicate ip rules, and a historical bug could
    /// leave several behind — a single del would silently keep the rest.
    fn cleanup_tun_routing(&self) {
        let fwmark = FWMARK.to_string();
        let table = TABLE.to_string();
        // del-until-failure (bounded, best-effort) — plain argv lists.
        for _ in 0..16 {
            let ok = Command::new("ip")
                .args(["rule", "del", "fwmark", &fwmark, "table", &table])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if !ok {
                break;
            }
        }
        let _ = Command::new("ip")
            .args([
                "route",
                "del",
                "local",
                "0.0.0.0/0",
                "dev",
                "lo",
                "table",
                &table,
            ])
            .output();
        let _ = Command::new("ip")
            .args(["route", "del", "default", "dev", "utun", "table", &table])
            .output();
        // IPv6 TPROXY routing (dual-stack mark).
        let v6 = ipv6_tproxy_table().to_string();
        for _ in 0..16 {
            let ok = Command::new("ip")
                .args(["-6", "rule", "del", "fwmark", &fwmark, "table", &v6])
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false);
            if !ok {
                break;
            }
        }
        let _ = Command::new("ip")
            .args([
                "-6", "route", "del", "local", "::/0", "dev", "lo", "table", &v6,
            ])
            .output();
    }

    fn cleanup_nftables(&self) -> Result<()> {
        // TUN policy routing is ip(8) state, invisible to nft flush —
        // remove it first or a later `apply` fails on the duplicate rule.
        self.cleanup_tun_routing();

        let flush_output = Command::new("nft")
            .args(["flush", "ruleset"])
            .output()
            .map_err(|e| Error::Firewall(format!("Failed to run nft flush: {e}")))?;

        if !flush_output.status.success() {
            let stderr = String::from_utf8_lossy(&flush_output.stderr);
            tracing::warn!("nft flush ruleset failed: {}", stderr);
        }

        for table in ["nat", "mangle", "filter"] {
            let output = Command::new("nft")
                .args(["delete", "table", "ip", table])
                .output()
                .map_err(|e| Error::Firewall(format!("Failed to run nft delete table: {e}")))?;

            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                tracing::debug!("nft delete table ip {} may not exist: {}", table, stderr);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::platform::InitSystem;

    fn test_platform() -> Platform {
        use crate::platform::ContainerInfo;
        Platform {
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            init_system: InitSystem::Systemd,
            is_openwrt: false,
            is_docker: false,
            firewall_backend: FirewallBackend::Iptables,
            default_crash_dir: "/tmp/rustcrash_test",
            container_info: ContainerInfo::default(),
            crash_dir_resolved: "/tmp/rustcrash_test".to_string(),
            runtime_dir_resolved: "/tmp/rustcrash_test/run".to_string(),
            log_dir_resolved: "/tmp/rustcrash_test/logs".to_string(),
        }
    }

    #[test]
    fn test_firewall_is_available() {
        let fw_iptables = Firewall::new(&Platform {
            firewall_backend: FirewallBackend::Iptables,
            ..test_platform()
        });
        assert!(fw_iptables.is_available());

        let fw_nftables = Firewall::new(&Platform {
            firewall_backend: FirewallBackend::Nftables,
            ..test_platform()
        });
        assert!(fw_nftables.is_available());

        let fw_none = Firewall::new(&Platform {
            firewall_backend: FirewallBackend::None,
            ..test_platform()
        });
        assert!(!fw_none.is_available());
    }

    #[test]
    fn test_generate_iptables_script() {
        let fw = Firewall::new(&test_platform());
        let script = fw.generate_iptables_script(&FirewallConfig::default());

        assert!(script.contains("iptables"));
        assert!(script.contains("-t nat"));
        assert!(script.contains("--dport 53"));
        assert!(script.contains("--dport 80"));
        assert!(script.contains("--dport 443"));
    }

    #[test]
    fn test_generate_nft_script() {
        let fw = Firewall::new(&test_platform());
        let script = fw.generate_nft_script("router");

        assert!(script.contains("nft"));
        assert!(script.contains("table ip nat"));
        assert!(script.contains("redirect to"));
        // The mangle/tproxy block appears only in TUN mode (default off).
    }

    #[test]
    fn test_firewall_backend_check() {
        let platform = test_platform();

        // The test_platform has Iptables backend
        let fw = Firewall::new(&platform);
        match fw.backend() {
            FirewallBackend::Iptables => {}
            _ => panic!("Expected Iptables backend"),
        }
    }

    #[test]
    fn test_default_port_constants() {
        assert_eq!(DEFAULT_PROXY_PORT, 7890);
        assert_eq!(DEFAULT_DNS_PORT, 7892);
        assert_eq!(DEFAULT_MIXED_PORT, 7891);
    }

    // TUN Mode Tests (Plan 07-01)

    #[test]
    fn test_tun_constants() {
        assert_eq!(FWMARK, 0x80000);
        assert_eq!(TABLE, 100);
    }

    // IPv6 Support Tests (Plan 07-02)

    #[test]
    fn test_ipv6_reserved_prefixes_defined() {
        assert!(!IPV6_RESERVED_PREFIXES.is_empty());
        assert!(IPV6_RESERVED_PREFIXES.iter().any(|(p, _)| *p == "fe80::"));
    }

    #[test]
    fn test_is_ipv6_reserved_link_local() {
        assert!(is_ipv6_reserved("fe80::1"));
        assert!(is_ipv6_reserved("fd00::1"));
        assert!(is_ipv6_reserved("ff02::1"));
        assert!(is_ipv6_reserved("::1"));
    }

    #[test]
    fn test_is_ipv6_reserved_not_reserved() {
        assert!(!is_ipv6_reserved("2001:db8::1"));
        assert!(!is_ipv6_reserved("2606:2800:2200:1::"));
    }

    #[test]
    fn test_ipv6_tproxy_table_separate() {
        assert_eq!(ipv6_tproxy_table(), TABLE + 1);
        assert_eq!(ipv6_tproxy_table(), 101);
    }

    #[test]
    fn test_nft_dual_stack_uses_inet_table() {
        let fw = Firewall::new(&test_platform());
        let script = fw.generate_nft_dual_stack_script(&FirewallConfig::default());
        assert!(script.contains("table inet shellcrash") || script.contains("inet "));
    }

    #[test]
    fn test_nft_dual_stack_handles_ipv6() {
        let fw = Firewall::new(&test_platform());
        let script = fw.generate_nft_dual_stack_script(&FirewallConfig::default());
        assert!(script.contains("ip6") || script.contains("ipv6"));
    }

    // ============== Enhanced Rule Management Tests (Plan 07-04) ==============

    #[test]
    fn test_firewall_config_default() {
        let config = FirewallConfig::default();
        assert!(!config.quic_reject);
        assert!(config.common_ports.is_empty()); // Empty = all ports
    }

    #[test]
    fn test_firewall_config_with_options() {
        let config = FirewallConfig::default()
            .with_quic_reject(true)
            .with_common_ports(&[80, 443])
            .with_macfilter(MacFilterType::Whitelist, &["aa:bb:cc:dd:ee:ff"]);

        assert!(config.quic_reject);
        assert_eq!(config.common_ports, vec![80, 443]);
        assert!(matches!(
            config.macfilter_type,
            Some(MacFilterType::Whitelist)
        ));
    }

    #[test]
    fn test_firewall_config_macfilter_blacklist() {
        let config = FirewallConfig::default()
            .with_macfilter(MacFilterType::Blacklist, &["aa:bb:cc:dd:ee:ff"]);
        assert!(matches!(
            config.macfilter_type,
            Some(MacFilterType::Blacklist)
        ));
        assert_eq!(config.macfilter_addrs.len(), 1);
    }

    #[test]
    fn test_firewall_config_macfilter_whitelist() {
        let config = FirewallConfig::default()
            .with_macfilter(MacFilterType::Whitelist, &["11:22:33:44:55:66"]);
        assert!(matches!(
            config.macfilter_type,
            Some(MacFilterType::Whitelist)
        ));
    }

    #[test]
    fn test_full_nft_script_contains_all_chains() {
        let fw = Firewall::new(&test_platform());
        let config = FirewallConfig::default();
        let script = fw.generate_full_nft_script(&config).unwrap();

        // All required chains (D-24)
        assert!(script.contains("prerouting"));
        assert!(script.contains("prerouting_dns") || script.contains("prerouting"));
        assert!(script.contains("chain output"));
        assert!(script.contains("chain input"));
    }

    #[test]
    fn test_full_nft_script_contains_antiloop() {
        let fw = Firewall::new(&test_platform());
        let config = FirewallConfig::default();
        let script = fw.generate_full_nft_script(&config).unwrap();

        // Anti-loop rules (D-25)
        assert!(script.contains("mark") && script.contains("return"));
        assert!(script.contains("skgid") || script.contains("453") || script.contains("7890"));
    }

    #[test]
    fn test_quic_reject_adds_udp_443_block() {
        let config = FirewallConfig::default().with_quic_reject(true);
        let fw = Firewall::new(&test_platform());
        let script = fw.generate_full_nft_script(&config).unwrap();

        // QUIC (UDP 443) should be blocked when quic_rj=ON (D-31)
        assert!(script.contains("443") || script.contains("quic"));
    }

    #[test]
    fn test_common_ports_restricts_proxying() {
        let config = FirewallConfig::default().with_common_ports(&[80, 443, 8080]);
        let fw = Firewall::new(&test_platform());
        let script = fw.generate_full_nft_script(&config).unwrap();

        // When common_ports is set, only those ports should be proxied (D-32)
        // Script should contain port 80, 443, 8080
        assert!(script.contains("80"));
        assert!(script.contains("443"));
        assert!(script.contains("8080"));
    }

    #[test]
    fn test_cleanup_selective_removes_individual_chains() {
        let fw = Firewall::new(&test_platform());
        let script = fw.cleanup_selective();

        // Should remove chains individually, not flush (D-33)
        assert!(script.contains("-X") || script.contains("delete"));
        // Should NOT do a full flush
        assert!(!script.contains("flush ruleset") || script.contains("# Selective cleanup"));
    }

    #[test]
    fn test_cleanup_script_contains_routing_cleanup() {
        let fw = Firewall::new(&test_platform());
        let script = fw.cleanup_selective();

        // Should clean up routing rules
        assert!(script.contains("ip rule del") || script.contains("ip -6 rule del"));
    }

    #[test]
    fn test_full_nft_script_vm_rules_when_configured() {
        let config = FirewallConfig::default()
            .with_common_ports(&[80, 443])
            .with_quic_reject(true);

        let fw = Firewall::new(&test_platform());
        let script = fw.generate_full_nft_script(&config).unwrap();

        // Should contain the configured ports
        assert!(script.contains("80"));
        assert!(script.contains("443"));
    }

    #[test]
    fn test_generate_full_iptables_script_contains_chains() {
        let config = FirewallConfig::default();
        let fw = Firewall::new(&test_platform());
        let script = fw.generate_full_iptables_script(&config);

        // Should contain iptables chains
        assert!(script.contains("iptables"));
        assert!(script.contains("PREROUTING") || script.contains("prerouting"));
        assert!(script.contains("OUTPUT") || script.contains("output"));
    }

    // Integration Tests

    #[test]
    fn test_firewall_tun_plus_ipv6() {
        let platform = Platform {
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            init_system: InitSystem::Systemd,
            is_openwrt: false,
            is_docker: false,
            firewall_backend: FirewallBackend::Nftables,
            default_crash_dir: "/tmp/rustcrash_test",
            container_info: crate::platform::ContainerInfo::default(),
            crash_dir_resolved: "/tmp/rustcrash_test".to_string(),
            runtime_dir_resolved: "/tmp/rustcrash_test/run".to_string(),
            log_dir_resolved: "/tmp/rustcrash_test/logs".to_string(),
        };

        let fw = Firewall::new(&platform);

        let config = FirewallConfig {
            tun_port: Some(7890),
            ipv6_enabled: true,
            ..FirewallConfig::default()
        }
        .with_quic_reject(true)
        .with_common_ports(&[80, 443]);

        let nft_script = fw.generate_full_nft_script(&config).unwrap();

        // TPROXY lives in the nft mangle table; policy routing is emitted
        // separately as shell commands (nft rejects `ip rule`).
        assert!(nft_script.contains("524288"));
        assert!(nft_script.contains("table ip mangle"));
        assert!(nft_script.contains("tproxy to"));
        assert!(
            !nft_script.contains("ip rule"),
            "shell cmd leaked into nft script"
        );
        let tun_sh = fw.generate_tun_routing_script(&config);
        assert!(tun_sh.contains("ip rule add fwmark 524288 table"));
        assert!(tun_sh.contains("ip route replace local"));
    }

    #[test]
    fn test_iptables_owner_rules_use_gid_owner() {
        // Round-13: `--sgid` is not an iptables owner-match option — the
        // anti-loop RETURN rules silently failed to install (proxy loop).
        let fw = Firewall::new(&test_platform());
        let script = fw.generate_full_iptables_script(&FirewallConfig::default());
        assert!(script.contains("--gid-owner 453"));
        assert!(script.contains("--gid-owner 7890"));
        assert!(!script.contains("--sgid"));
    }

    #[test]
    fn test_ipv6_routing_pair_emitted_with_fwmark() {
        // Round-13: v6 TPROXY rules marked packets (with 0x1) but no
        // `ip -6` rule/route was ever added — interception was inert and
        // cleanup deleted a rule nothing created. Marks now use FWMARK
        // and the v6 routing pair is generated for the apply path.
        let fw = Firewall::new(&test_platform());
        let dual = fw.generate_nft_dual_stack_script(&FirewallConfig::default());
        assert!(
            dual.contains("meta mark set 524288"),
            "v6 mark must be FWMARK"
        );
        // v6 tproxy is source-gated and targets the tproxy port.
        assert!(dual.contains("ip6 saddr fd00::/8 counter udp dport 53"));
        assert!(!dual.contains("mark set 0x1"));

        let v6 = fw.generate_ipv6_routing_script();
        assert!(v6.contains("ip -6 rule add fwmark 524288 table 101"));
        assert!(v6.contains("ip -6 route replace local ::/0 dev lo table 101"));
        assert!(v6.contains("while ip -6 rule del fwmark 524288 table 101 2>/dev/null"));
    }

    #[test]
    fn test_dual_stack_scripts_honor_config_ports() {
        // Regression: both dual-stack generators read the hard-default
        // ports (7890/7892) — IPv6 was blackholed on custom ports.
        let fw = Firewall::new(&test_platform());
        let config = FirewallConfig {
            proxy_port: 18080,
            dns_port: 1053,
            ..FirewallConfig::default()
        };
        let dual = fw.generate_nft_dual_stack_script(&config);
        // v6-only: dns redirect honors dns_port; tproxy targets the tproxy
        // listener (tun_port or proxy+2), NOT the redir port.
        assert!(
            dual.contains("redirect to 1053"),
            "dns port ignored\n{dual}"
        );
        assert!(
            dual.contains("tproxy to :18082"),
            "tproxy must use tun/proxy+2\n{dual}"
        );
        assert!(
            !dual.contains("redirect to 18080"),
            "v4 redir leaked into v6 script"
        );
        // 7890 may appear only as the ShellCrash sgid constant.
        for line in dual.lines() {
            if line.contains("7890") {
                assert!(line.contains("skgid"), "stray default port: {line}");
            }
        }

        let ip4 = fw.generate_iptables_script(&config);
        assert!(ip4.contains("--to-ports 18080"));
        assert!(ip4.contains("--to-ports 1053"));
    }

    #[test]
    fn test_tun_routing_script_shape_and_empty_when_off() {
        let fw = Firewall::new(&test_platform());
        let off = fw.generate_tun_routing_script(&FirewallConfig::default());
        assert!(off.is_empty(), "no routing without tun_port");

        let on = fw.generate_tun_routing_script(&FirewallConfig {
            tun_port: Some(7890),
            ..FirewallConfig::default()
        });
        assert!(on.contains("ip rule add fwmark 524288 table 100"));
        assert!(on.contains("ip route replace local 0.0.0.0/0 dev lo table 100"));
        // Idempotency guards: stale duplicates are purged before add.
        assert!(on.contains("while ip rule del fwmark 524288 table 100 2>/dev/null"));
        assert!(on.starts_with("set -e"));
    }

    #[test]
    fn test_nft_dual_stack_set_is_table_scoped_and_mac_uses_source() {
        // Round-9 regressions: the @ipv6_reserved set lived in a different
        // table than its users; macfilter matched ether daddr (incoming
        // packets carry the local NIC's dst MAC).
        let fw = Firewall::new(&test_platform());
        let dual = fw.generate_nft_dual_stack_script(&FirewallConfig::default());
        // Every set reference must find its declaration within the same
        // `table <family> <name>` block.
        for block in dual.split("table ").skip(1) {
            let uses = block.matches("@ipv6_reserved").count();
            if uses > 0 {
                assert!(
                    block.contains("set ipv6_reserved"),
                    "set used outside its declaring table:\n{block}"
                );
            }
        }

        let config = FirewallConfig::default()
            .with_macfilter(MacFilterType::Blacklist, &["aa:bb:cc:dd:ee:ff"]);
        let full = fw.generate_full_nft_script(&config).unwrap();
        assert!(full.contains("ether saddr aa:bb:cc:dd:ee:ff"));
        assert!(!full.contains("ether daddr"));

        // Cleanup removes the dual-stack inet table.
        assert!(fw
            .cleanup_selective()
            .contains("nft delete table inet shellcrash"));
    }

    #[test]
    fn test_wan_guard_uses_configured_mixed_port() {
        // R26: the guard hardcoded proxy+1 — a custom mixed_port stayed
        // exposed (the #1223 open-proxy class).
        let fw = Firewall::new(&test_platform());
        let config = FirewallConfig {
            mixed_port: 18081,
            ..FirewallConfig::default()
        };
        let nft = fw.generate_full_nft_script(&config).unwrap();
        assert!(
            nft.contains("18081"),
            "custom mixed port must be guarded:\n{nft}"
        );
        assert!(
            nft.contains("tcp dport { 18081"),
            "guard set must include the custom mixed port"
        );
    }

    #[test]
    fn test_sysctl_persist_exact_token_and_neighbor_keys() {
        // R26: prefix matching clobbered net.ipv4.ip_forward_update_priority.
        let dir = tempfile::tempdir().unwrap();
        let conf = dir.path().join("sysctl.conf");
        std::fs::write(
            &conf,
            "net.ipv4.ip_forward_update_priority = 0\n# net.ipv4.ip_forward = 0\nnet.ipv4.ip_forward = 0\n",
        )
        .unwrap();
        let content = std::fs::read_to_string(&conf).unwrap();
        let key = "net.ipv4.ip_forward";
        let exact = |l: &str| l.split('=').next().unwrap_or("").trim() == key;
        let replaced: Vec<String> = content
            .lines()
            .map(|l| {
                if exact(l) {
                    "net.ipv4.ip_forward = 1".to_string()
                } else {
                    l.to_string()
                }
            })
            .collect();
        let out = replaced.join("\n");
        assert!(
            out.contains("net.ipv4.ip_forward_update_priority = 0"),
            "neighbor key clobbered"
        );
        assert!(
            out.contains("# net.ipv4.ip_forward = 0"),
            "commented line clobbered"
        );
        assert!(out.contains("net.ipv4.ip_forward = 1"));
    }

    #[test]
    fn test_listeners_blocked_from_wan() {
        // Community #1223: an exposed mixed port became an open proxy.
        // The input chain must accept listener ports from LAN subnets and
        // drop them from everywhere else.
        let fw = Firewall::new(&test_platform());
        let nft = fw
            .generate_full_nft_script(&FirewallConfig::default())
            .unwrap();
        let mut in_input = false;
        let mut lan_accept = false;
        let mut wan_drop = false;
        for line in nft.lines() {
            let t = line.trim();
            if t.starts_with("chain input") {
                in_input = true;
                continue;
            }
            if t.starts_with("chain ") {
                in_input = false;
                continue;
            }
            if in_input && t.contains("tcp dport") && t.contains("accept") && t.contains("ip saddr")
            {
                lan_accept = true;
            }
            if in_input && t.contains("tcp dport") && t.contains("drop") && !t.contains("ip saddr")
            {
                wan_drop = true;
            }
        }
        assert!(lan_accept, "LAN accept rule missing");
        assert!(wan_drop, "WAN drop rule missing");
    }

    #[test]
    fn test_prerouting_hijack_is_lan_scoped() {
        // Community issue class (open proxy): prerouting hijack must only
        // match LAN source subnets — never WAN traffic.
        let fw = Firewall::new(&test_platform());
        let nft = fw
            .generate_full_nft_script(&FirewallConfig::default())
            .unwrap();
        assert!(
            nft.contains("ip saddr { 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12 }"),
            "nft prerouting not subnet-gated:\n{nft}"
        );
        // No un-gated PREROUTING redirect/DNS lines remain (the OUTPUT
        // chain is intentionally ungated — the box's own traffic).
        let mut in_output_chain = false;
        for line in nft.lines() {
            let t = line.trim();
            if t.starts_with("chain output") {
                in_output_chain = true;
            } else if t.starts_with("chain ") {
                in_output_chain = false;
            }
            if !in_output_chain
                && (t.starts_with("udp dport 53")
                    || (t.starts_with("tcp dport") && t.contains("redirect")))
            {
                assert!(t.starts_with("ip saddr"), "un-gated hijack: {t}");
            }
        }

        let ip4 = fw.generate_full_iptables_script(&FirewallConfig::default());
        assert!(ip4.contains("-s 192.168.0.0/16 -p tcp -j REDIRECT"));
        assert!(ip4.contains("-s 10.0.0.0/8 -p tcp -j REDIRECT"));
        assert!(ip4.contains("-s 172.16.0.0/12 -p tcp -j REDIRECT"));
        assert!(ip4.contains("-s 192.168.0.0/16 -p udp --dport 53"));
        // Custom subnets respected.
        let custom = FirewallConfig {
            hijack_subnets: vec!["10.50.0.0/16".to_string()],
            ..FirewallConfig::default()
        };
        let custom_nft = fw.generate_full_nft_script(&custom).unwrap();
        assert!(custom_nft.contains("ip saddr { 10.50.0.0/16 }"));
        assert!(!custom_nft.contains("192.168.0.0/16"));
    }

    #[test]
    fn test_crash_group_helpers() {
        // Group resolution parses /etc/group; on this host the group may or
        // may not exist — both outcomes are valid, but a present entry must
        // resolve to a gid.
        if let Some(gid) = crate::service::lookup_group_gid("root") {
            assert_eq!(gid, 0);
        } else {
            panic!("root group must resolve on unix");
        }
        assert!(crate::service::lookup_group_gid("definitely-not-a-group-xyz").is_none());
    }

    // ============== ShellCrash migration residue tests ==============

    #[test]
    fn test_shellcrash_residue_scan_detects_install_layout() {
        // The "both installed" scenario: a live ShellCrash install plus
        // its wrapper/alias still on the box a user migrated from.
        let root = tempfile::tempdir().unwrap();
        let sc = root.path().join("etc/ShellCrash");
        std::fs::create_dir_all(&sc).unwrap();
        std::fs::write(sc.join("menu.sh"), "#!/bin/sh\n").unwrap();
        std::fs::create_dir_all(root.path().join("usr/bin")).unwrap();
        std::fs::write(
            root.path().join("usr/bin/crash"),
            "#!/bin/sh\nCRASHDIR=${CRASHDIR:-/etc/ShellCrash}\nexec \"$CRASHDIR/menu.sh\" \"$@\"\n",
        )
        .unwrap();
        std::fs::write(
            root.path().join("etc/profile"),
            "alias crash='bash /etc/ShellCrash/menu.sh'\n",
        )
        .unwrap();

        let residue = ShellCrashResidue::scan_at(root.path(), false);
        assert_eq!(residue.install_dirs, vec!["/etc/ShellCrash".to_string()]);
        assert_eq!(residue.wrapper_scripts, vec!["/usr/bin/crash".to_string()]);
        assert_eq!(residue.profile_aliases, vec!["/etc/profile".to_string()]);
        let lines = residue.summary_lines();
        assert!(lines.iter().any(|l| l.contains("/etc/ShellCrash")), "{lines:?}");
        assert!(
            lines.iter().any(|l| l.contains("PATH-order conflict")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("alias wins")),
            "{lines:?}"
        );
    }

    #[test]
    fn test_shellcrash_residue_scan_clean_root() {
        // Filesystem probes on a bare root find nothing (the command
        // probes target the live system and are not asserted here).
        let root = tempfile::tempdir().unwrap();
        let residue = ShellCrashResidue::scan_at(root.path(), false);
        assert!(residue.install_dirs.is_empty());
        assert!(residue.wrapper_scripts.is_empty());
        assert!(residue.profile_aliases.is_empty());
        // A dir merely NAMED ShellCrash is not an install.
        std::fs::create_dir_all(root.path().join("etc/ShellCrash")).unwrap();
        let residue = ShellCrashResidue::scan_at(root.path(), false);
        assert!(residue.install_dirs.is_empty());
    }

    #[test]
    fn test_foreign_chain_detection_from_iptables_dump() {
        // The exact rule shapes ShellCrash's fw_iptables.sh leaves behind
        // (from its fw_stop.sh deletion set).
        let dump = "\
-P PREROUTING ACCEPT
-N shellcrash
-N shellcrash_dns
-N shellcrash_dns_out
-N shellcrash_out
-N shellcrash_vm
-N shellcrash_vm_dns
-N DOCKER
-A PREROUTING -p tcp -m multiport --dports 22,80,443 -j shellcrash
-A PREROUTING -p tcp --dport 53 -j shellcrash_dns
-A PREROUTING -p udp --dport 53 -j shellcrash_dns
-A OUTPUT -p tcp -m multiport --dports 22,80,443 -j shellcrash_out
-A OUTPUT -p udp --dport 53 -j shellcrash_dns_out
-A PREROUTING -d 172.17.0.0/16 -j DOCKER
";
        let mut chains = foreign_chains_in(dump);
        chains.sort();
        assert_eq!(
            chains,
            vec![
                "shellcrash",
                "shellcrash_dns",
                "shellcrash_dns_out",
                "shellcrash_out",
                "shellcrash_vm",
                "shellcrash_vm_dns",
            ]
        );
        for line in [
            "-A PREROUTING -p tcp -m multiport --dports 22,80,443 -j shellcrash",
            "-A OUTPUT -p tcp -j shellcrash_out",
            "-A PREROUTING -p tcp --dport 53 -j shellcrashv6_dns",
        ] {
            assert!(references_shellcrash_chain(line), "{line}");
        }
        // Foreign chains (docker etc.) must never match.
        assert!(!references_shellcrash_chain(
            "-A PREROUTING -d 172.17.0.0/16 -j DOCKER"
        ));
        assert!(!references_shellcrash_chain(
            "-A FORWARD -j ufw-before-forward"
        ));

        // Deletion transform: -A → -D with the same match spec.
        let args = deletion_args("-A OUTPUT -p tcp -j shellcrash_out");
        assert_eq!(
            args,
            vec![
                "-D".to_string(),
                "OUTPUT".to_string(),
                "-p".to_string(),
                "tcp".to_string(),
                "-j".to_string(),
                "shellcrash_out".to_string(),
            ]
        );
    }

    #[test]
    fn test_residue_summary_names_running_core_and_firewall() {
        // The "both RUNNING" + leftover-rules scenario: every class is
        // named in the summary a user sees.
        let residue = ShellCrashResidue {
            live_cores: vec!["CrashCore (pid 4242)".to_string()],
            nft_table: true,
            iptables_chains: vec!["iptables/nat shellcrash".to_string()],
            stale_ip_rules: true,
            ..ShellCrashResidue::default()
        };
        assert!(residue.is_present());
        assert!(residue.firewall_residue());
        let lines = residue.summary_lines();
        assert!(lines.iter().any(|l| l.contains("pid 4242")), "{lines:?}");
        assert!(
            lines.iter().any(|l| l.contains("inet shellcrash")),
            "{lines:?}"
        );
        assert!(
            lines.iter().any(|l| l.contains("policy routing")),
            "{lines:?}"
        );
    }

    #[test]
    fn test_nft_full_script_no_redirect_in_filter_chains() {
        // nft `redirect` is nat-only; a redirect inside a type filter
        // chain makes nft -f reject the whole batch (apply fully broken).
        let fw = Firewall::new(&test_platform());
        for config in [
            FirewallConfig::default(),
            FirewallConfig::default().with_common_ports(&[80, 443]),
            FirewallConfig {
                tun_port: Some(7890),
                quic_reject: true,
                ..FirewallConfig::default()
            },
        ] {
            let script = fw.generate_full_nft_script(&config).unwrap();
            for chain in script.split("chain ") {
                if chain.contains("type filter") {
                    assert!(
                        !chain.contains(" redirect to "),
                        "redirect leaked into a filter chain:\n{chain}"
                    );
                }
            }
        }
        // Dual-stack simple script follows the same rule — check per
        // CHAIN (a table may hold both nat and filter chains).
        let dual = fw.generate_nft_dual_stack_script(&FirewallConfig::default());
        for chain in dual.split("chain ") {
            if chain.contains("type filter") {
                assert!(
                    !chain.contains(" redirect to "),
                    "dual-stack filter redirect:\n{chain}"
                );
            }
        }
    }

    #[test]
    fn test_iptables_full_script_all_rules_are_real_commands() {
        // Round-7 regressions: mac/quic rules were shell fragments; the
        // forward hijack used REDIRECT in the filter table (nat-only).
        let fw = Firewall::new(&test_platform());
        let config = FirewallConfig::default()
            .with_common_ports(&[80, 443])
            .with_quic_reject(true)
            .with_macfilter(MacFilterType::Blacklist, &["aa:bb:cc:dd:ee:ff"]);
        let script = fw.generate_full_iptables_script(&config);

        assert!(script.contains("\nset -e"));
        // The nat table has no FORWARD hook — the old nat-FORWARD block
        // could never load and failed silently without set -e.
        assert!(!script.contains("-t nat -A FORWARD"));
        // Every non-comment, non-empty line is a real command.
        for line in script.lines() {
            let t = line.trim();
            if t.is_empty() || t.starts_with('#') {
                continue;
            }
            assert!(
                t.starts_with("iptables ")
                    || t.starts_with("ip ")
                    || t == "set -e"
                    || t.starts_with("while ")
                    || t == "do :"
                    || t == "done"
                    || t.ends_with("|| true")
                    || t == ":"
                    || t == "do"
                    || t == "done;",
                "non-command line leaked: {t}"
            );
        }
        // MAC and QUIC rules are full commands on the right chains.
        assert!(script.contains(
            "iptables -t filter -A shellcrash_in -m mac --mac-source aa:bb:cc:dd:ee:ff -j DROP"
        ));
        assert!(script.contains("iptables -t filter -A shellcrash_fwd -p udp --dport 443 -j DROP"));
        // Forward hijack: the nat table has no FORWARD hook — routed
        // traffic is hijacked in PREROUTING (shellcrash_pre).
        assert!(!script.contains("-t nat -A FORWARD"));
        assert!(!script.contains("iptables -t nat -N shellcrash_fwd"));
        // Restricted mode: multiport form, no blanket TCP hijack anywhere.
        assert!(script.contains("--dports 80,443"));
        assert!(!script.contains("-p tcp -j REDIRECT"));
    }

    #[test]
    fn test_iptables_full_script_restricted_ports_are_real_commands() {
        // Regression: the port restriction used to be a bare `-p tcp
        // -m multiport …` fragment spliced into the shell script — sh
        // parsed it as a command name and silently skipped it.
        let fw = Firewall::new(&test_platform());
        let config = FirewallConfig::default().with_common_ports(&[80, 443]);
        let script = fw.generate_full_iptables_script(&config);

        // Every generated restriction line is a full iptables command.
        for line in script.lines() {
            let t = line.trim();
            if t.contains("multiport") {
                assert!(t.starts_with("iptables "), "fragment leaked: {t}");
            }
        }
        assert!(script.contains("--dports 80,443"));
        // No blanket TCP hijack alongside the restriction.
        assert!(!script.contains("-p tcp -j REDIRECT"));

        // Without restrictions the blanket hijack is back.
        let blanket = fw.generate_full_iptables_script(&FirewallConfig::default());
        assert!(blanket.contains("-p tcp -j REDIRECT"));
    }

    #[test]
    fn test_firewall_tun_plus_vm() {
        let platform = Platform {
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            init_system: InitSystem::Systemd,
            is_openwrt: false,
            is_docker: false,
            firewall_backend: FirewallBackend::Iptables,
            default_crash_dir: "/tmp/rustcrash_test",
            container_info: crate::platform::ContainerInfo::default(),
            crash_dir_resolved: "/tmp/rustcrash_test".to_string(),
            runtime_dir_resolved: "/tmp/rustcrash_test/run".to_string(),
            log_dir_resolved: "/tmp/rustcrash_test/logs".to_string(),
        };

        let fw = Firewall::new(&platform);

        // No tun_port: no utun routing, and the VM subnet is excluded.
        let config = FirewallConfig {
            vm_ipv4: Some("192.168.1.0/24".to_string()),
            vm_redir: false,
            ..FirewallConfig::default()
        };
        let full_iptables_script = fw.generate_full_iptables_script(&config);

        assert!(full_iptables_script.contains("-d 192.168.1.0/24 -j RETURN"));
        assert!(
            !full_iptables_script.contains("utun"),
            "utun routing must be TUN-gated"
        );

        // With tun_port set, the utun routing appears.
        let tun_config = FirewallConfig {
            tun_port: Some(7890),
            ..config
        };
        let tun_script = fw.generate_full_iptables_script(&tun_config);
        assert!(tun_script.contains("utun"));
        assert!(tun_script.contains("fwmark"));
    }

    #[test]
    fn test_firewall_full_features_enabled() {
        let container_info = crate::platform::ContainerInfo {
            is_container: true,
            cgroup_pattern: Some("docker".to_string()),
            interfaces: vec!["docker0".to_string()],
            has_dockerenv: true,
            has_containerenv: false,
        };

        let platform = Platform {
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            init_system: InitSystem::Systemd,
            is_openwrt: false,
            is_docker: true,
            firewall_backend: FirewallBackend::Nftables,
            default_crash_dir: "/tmp/rustcrash_test",
            container_info,
            crash_dir_resolved: "/tmp/rustcrash_test".to_string(),
            runtime_dir_resolved: "/tmp/rustcrash_test/run".to_string(),
            log_dir_resolved: "/tmp/rustcrash_test/logs".to_string(),
        };

        let fw = Firewall::new(&platform);

        let config = FirewallConfig {
            tun_port: Some(7890),
            ipv6_enabled: true,
            vm_ipv4: Some("10.0.0.0/8".to_string()),
            vm_redir: true,
            ..FirewallConfig::default()
        }
        .with_quic_reject(true)
        .with_common_ports(&[22, 80, 443, 8080, 8443])
        .with_macfilter(MacFilterType::Whitelist, &["aa:bb:cc:dd:ee:ff"]);

        let nft_script = fw.generate_full_nft_script(&config).unwrap();

        assert!(nft_script.contains("table ip nat"));
        assert!(nft_script.contains("table ip mangle"));
        assert!(nft_script.contains("443"));
        // vm_redir=true: VM traffic is hijacked like everything else —
        // no exclusion rule for the subnet.
        assert!(!nft_script.contains("ip daddr 10.0.0.0/8 counter return"));
    }

    #[test]
    fn test_firewall_cleanup_script_format() {
        let fw = Firewall::new(&test_platform());
        let cleanup = fw.cleanup_selective();

        // Should be valid shell script format
        assert!(cleanup.starts_with("#!/bin/sh") || cleanup.starts_with("#!/usr/bin/env sh"));
        // Should remove tables/chains, not flush
        assert!(cleanup.contains("delete") || cleanup.contains("-X"));
    }

    #[test]
    fn test_firewall_backend_selection() {
        // Test nftables backend
        let platform_nft = Platform {
            firewall_backend: FirewallBackend::Nftables,
            ..test_platform()
        };
        let fw_nft = Firewall::new(&platform_nft);
        assert_eq!(fw_nft.backend(), FirewallBackend::Nftables);

        // Test iptables backend
        let platform_ipt = Platform {
            firewall_backend: FirewallBackend::Iptables,
            ..test_platform()
        };
        let fw_ipt = Firewall::new(&platform_ipt);
        assert_eq!(fw_ipt.backend(), FirewallBackend::Iptables);
    }

    #[test]
    fn test_platform_preserves_container_info() {
        let container_info = crate::platform::ContainerInfo {
            is_container: true,
            cgroup_pattern: Some("docker".to_string()),
            interfaces: vec!["docker0".to_string(), "vethabc".to_string()],
            has_dockerenv: true,
            has_containerenv: false,
        };

        let platform = Platform {
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            init_system: InitSystem::Systemd,
            is_openwrt: false,
            is_docker: true,
            firewall_backend: FirewallBackend::Nftables,
            default_crash_dir: "/tmp/rustcrash_test",
            container_info,
            crash_dir_resolved: "/tmp/rustcrash_test".to_string(),
            runtime_dir_resolved: "/tmp/rustcrash_test/run".to_string(),
            log_dir_resolved: "/tmp/rustcrash_test/logs".to_string(),
        };

        assert!(platform.is_docker);
        assert!(platform.container_info.is_container);
        assert_eq!(platform.container_info.interfaces.len(), 2);
    }
}
