//! Platform detection and abstraction

use crate::error::{Error, Result};
use std::fs;
use std::path::Path;

/// Supported init systems
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InitSystem {
    OpenRC,
    Systemd,
    InitD,
    None,
}

/// Supported proxy kernels
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProxyKernel {
    Mihomo,
    SingBox,
}

impl ProxyKernel {
    pub fn binary_name(&self) -> &'static str {
        match self {
            ProxyKernel::Mihomo => "mihomo",
            ProxyKernel::SingBox => "sing-box",
        }
    }

    pub fn default_port(&self) -> u16 {
        7890
    }
}

impl std::fmt::Display for InitSystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            InitSystem::OpenRC => write!(f, "OpenRC"),
            InitSystem::Systemd => write!(f, "systemd"),
            InitSystem::InitD => write!(f, "init.d"),
            InitSystem::None => write!(f, "none"),
        }
    }
}

/// Container environment information (D-15 to D-21)
#[derive(Debug, Clone, Default)]
pub struct ContainerInfo {
    pub is_container: bool,
    pub cgroup_pattern: Option<String>,
    pub interfaces: Vec<String>,
    pub has_dockerenv: bool,
    pub has_containerenv: bool,
}

/// Virtual interface name prefixes to exclude when detecting LAN subnets (D-21)
const VIRTUAL_INTERFACE_PREFIXES: &[&str] = &[
    "docker",
    "podman",
    "virbr",
    "vnet",
    "ovs",
    "vmbr",
    "veth",
    "vmnic",
    "vboxnet",
    "lxcbr",
    "xenbr",
    "vEthernet",
    "cni",
    "flannel",
    "cali",
    "cilium",
    "weave",
    "vmnet", // VMware virtual interfaces
    "venet", // OpenVZ virtual interfaces
    "vmmon", // VMware monitor interface
    "vz",    // OpenVZ virtual environments
];

/// Check if a network interface name is a virtual/container interface (D-21)
pub fn is_virtual_interface(name: &str) -> bool {
    for prefix in VIRTUAL_INTERFACE_PREFIXES {
        if name.starts_with(prefix) {
            return true;
        }
    }
    false
}

/// Detect container environment (D-16, D-17)
pub fn detect_containers() -> ContainerInfo {
    let mut info = ContainerInfo {
        // /.dockerenv and /run/.containerenv presence (D-17)
        has_dockerenv: Path::new("/.dockerenv").exists(),
        has_containerenv: Path::new("/run/.containerenv").exists(),
        ..Default::default()
    };

    // Check /proc/1/cgroup for container patterns (D-16)
    if let Ok(cgroup) = fs::read_to_string("/proc/1/cgroup") {
        let patterns = ["docker", "lxc", "kubepods", "crio", "containerd"];
        for pattern in patterns {
            if cgroup.contains(pattern) {
                info.is_container = true;
                info.cgroup_pattern = Some(pattern.to_string());
                break;
            }
        }
    }

    // Also check /proc/1/comm for container runtime
    if let Ok(comm) = fs::read_to_string("/proc/1/comm") {
        let runtime_patterns = ["docker", "containerd", "cri-o", "kubelet"];
        for runtime in runtime_patterns {
            if comm.trim().contains(runtime) {
                info.is_container = true;
                if info.cgroup_pattern.is_none() {
                    info.cgroup_pattern = Some(runtime.to_string());
                }
                break;
            }
        }
    }

    // Get container interfaces
    info.interfaces = detect_virtual_interfaces();

    info
}

/// Detect virtual network interfaces (D-18)
pub fn detect_virtual_interfaces() -> Vec<String> {
    let mut interfaces = Vec::new();
    let net_path = Path::new("/sys/class/net");

    if let Ok(entries) = fs::read_dir(net_path) {
        for entry in entries.flatten() {
            if let Ok(name) = entry.file_name().into_string() {
                if is_virtual_interface(&name) {
                    interfaces.push(name);
                }
            }
        }
    }

    interfaces
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FirewallBackend {
    Nftables,
    Iptables,
    None,
}

impl std::fmt::Display for FirewallBackend {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FirewallBackend::Nftables => write!(f, "nftables"),
            FirewallBackend::Iptables => write!(f, "iptables"),
            FirewallBackend::None => write!(f, "none"),
        }
    }
}

/// Detected platform information
#[derive(Debug, Clone)]
pub struct Platform {
    pub os: String,
    pub arch: String,
    pub init_system: InitSystem,
    pub is_openwrt: bool,
    pub is_docker: bool,
    pub firewall_backend: FirewallBackend,
    pub default_crash_dir: &'static str,
    pub container_info: ContainerInfo,
    /// Directories resolved once at detect time. Snapshotting keeps a
    /// `Platform` value stable even if the process environment changes
    /// later (and keeps tests free of env-var races).
    pub crash_dir_resolved: String,
    pub runtime_dir_resolved: String,
    pub log_dir_resolved: String,
}

impl Platform {
    /// Build a platform rooted at an explicit crash directory, without
    /// touching the process environment. Useful for tests and embedders.
    pub fn for_crash_dir(crash_dir: &str) -> Self {
        let crash_dir_resolved = crash_dir.to_string();
        Platform {
            os: std::env::consts::OS.to_string(),
            arch: std::env::consts::ARCH.to_string(),
            init_system: InitSystem::None,
            is_openwrt: false,
            is_docker: false,
            firewall_backend: FirewallBackend::None,
            default_crash_dir: "/etc/rustcrash",
            container_info: ContainerInfo::default(),
            runtime_dir_resolved: format!("{crash_dir_resolved}/run"),
            log_dir_resolved: format!("{crash_dir_resolved}/logs"),
            crash_dir_resolved,
        }
    }

    pub fn detect() -> Result<Self> {
        let os = std::env::consts::OS.to_string();
        let arch = std::env::consts::ARCH.to_string();

        let init_system = Self::detect_init_system();
        let is_openwrt = Self::detect_openwrt();
        let firewall_backend = Self::detect_firewall_backend();
        let container_info = detect_containers();

        let default_crash_dir = if is_openwrt {
            "/etc/ShellCrash"
        } else {
            "/etc/rustcrash"
        };

        let crash_dir_resolved = std::env::var("CRASHDIR")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("CRASH_DIR").ok().filter(|s| !s.is_empty()))
            .unwrap_or_else(|| default_crash_dir.to_string());
        let runtime_dir_resolved = std::env::var("RUNTIME_DIR")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| {
                std::env::var("XDG_RUNTIME_DIR")
                    .ok()
                    .filter(|s| !s.is_empty())
            })
            .unwrap_or_else(|| format!("{crash_dir_resolved}/run"));
        let log_dir_resolved = std::env::var("LOG_DIR")
            .ok()
            .filter(|s| !s.is_empty())
            .or_else(|| std::env::var("XDG_LOG_DIR").ok().filter(|s| !s.is_empty()))
            .unwrap_or_else(|| format!("{crash_dir_resolved}/logs"));

        Ok(Platform {
            os,
            arch,
            init_system,
            is_openwrt,
            is_docker: container_info.is_container,
            firewall_backend,
            default_crash_dir,
            container_info,
            crash_dir_resolved,
            runtime_dir_resolved,
            log_dir_resolved,
        })
    }

    fn detect_init_system() -> InitSystem {
        if Path::new("/run/systemd/system").exists() {
            return InitSystem::Systemd;
        }
        if Path::new("/etc/openrc").exists() || Path::new("/etc/rc.common").exists() {
            return InitSystem::OpenRC;
        }
        if Path::new("/etc/init.d").exists() {
            return InitSystem::InitD;
        }
        InitSystem::None
    }

    fn detect_openwrt() -> bool {
        Path::new("/etc/openwrt_release").exists()
            || (Path::new("/usr/lib/os-release").exists()
                && fs::read_to_string("/usr/lib/os-release")
                    .map(|s| s.contains("OpenWrt"))
                    .unwrap_or(false))
    }

    fn detect_firewall_backend() -> FirewallBackend {
        if Self::command_exists("nft") {
            return FirewallBackend::Nftables;
        }
        if Self::command_exists("iptables") {
            return FirewallBackend::Iptables;
        }
        FirewallBackend::None
    }

    fn command_exists(cmd: &str) -> bool {
        if !Self::is_valid_command_name(cmd) {
            return false;
        }

        std::process::Command::new("sh")
            .args(["-c", &format!("command -v {} >/dev/null 2>&1", cmd)])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn is_valid_command_name(cmd: &str) -> bool {
        if cmd.is_empty() {
            return false;
        }
        cmd.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    }

    pub fn crash_dir(&self) -> String {
        self.crash_dir_resolved.clone()
    }

    pub fn runtime_dir(&self) -> String {
        self.runtime_dir_resolved.clone()
    }

    pub fn log_dir(&self) -> String {
        self.log_dir_resolved.clone()
    }

    pub fn log_path(&self) -> String {
        format!("{}/rustcrash.log", self.log_dir())
    }

    pub fn normalized_arch(&self) -> String {
        match self.arch.as_str() {
            "x86_64" => "amd64".to_string(),
            "aarch64" => "arm64".to_string(),
            "arm" => {
                if cfg!(target_feature = "v7") || cfg!(target_feature = "neon") {
                    "armv7".to_string()
                } else {
                    "arm".to_string()
                }
            }
            other => other.to_string(),
        }
    }

    pub fn is_root(&self) -> bool {
        unsafe { libc::geteuid() == 0 }
    }

    pub fn require_root(&self) -> Result<()> {
        if !self.is_root() {
            return Err(Error::PermissionDenied);
        }
        Ok(())
    }
}

pub struct Detect;

impl Detect {
    pub fn platform() -> Result<Platform> {
        Platform::detect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_normalized_arch() {
        // This test verifies the normalized_arch method exists and is callable
        // The actual normalization depends on target feature flags
        let platform = Platform {
            os: "linux".to_string(),
            arch: std::env::consts::ARCH.to_string(),
            init_system: InitSystem::Systemd,
            is_openwrt: false,
            is_docker: false,
            firewall_backend: FirewallBackend::Iptables,
            default_crash_dir: "/etc/rustcrash",
            container_info: ContainerInfo::default(),
            crash_dir_resolved: "/etc/rustcrash".to_string(),
            runtime_dir_resolved: "/etc/rustcrash/run".to_string(),
            log_dir_resolved: "/etc/rustcrash/logs".to_string(),
        };

        let arch = platform.normalized_arch();
        assert!(!arch.is_empty(), "normalized_arch should not be empty");
    }

    #[test]
    fn test_platform_directories_snapshot() {
        let crash_dir_path = tempfile::TempDir::new().unwrap().keep();
        let crash_dir_str = crash_dir_path.to_string_lossy().to_string();

        let platform = Platform::for_crash_dir(&crash_dir_str);
        assert_eq!(platform.crash_dir(), crash_dir_str);
        assert_eq!(platform.runtime_dir(), format!("{crash_dir_str}/run"));
        assert_eq!(platform.log_dir(), format!("{crash_dir_str}/logs"));

        // Directories are snapshotted: changing the env afterwards has no
        // effect on an existing Platform value.
        std::env::set_var("CRASHDIR", "/tmp/other-dir");
        assert_eq!(platform.crash_dir(), crash_dir_str);
        std::env::remove_var("CRASHDIR");
    }

    #[test]
    fn test_proxy_kernel_info() {
        for kernel in [ProxyKernel::Mihomo, ProxyKernel::SingBox] {
            assert!(!kernel.binary_name().is_empty());
            assert!(kernel.default_port() > 0);
        }
    }

    #[test]
    fn test_init_system_display() {
        assert_eq!(format!("{}", InitSystem::Systemd), "systemd");
        assert_eq!(format!("{}", InitSystem::OpenRC), "OpenRC");
        assert_eq!(format!("{}", InitSystem::InitD), "init.d");
        assert_eq!(format!("{}", InitSystem::None), "none");
    }

    #[test]
    fn test_firewall_backend_display() {
        assert_eq!(format!("{}", FirewallBackend::Iptables), "iptables");
        assert_eq!(format!("{}", FirewallBackend::Nftables), "nftables");
        assert_eq!(format!("{}", FirewallBackend::None), "none");
    }

    #[test]
    fn test_require_root_returns_error_when_not_root() {
        let platform = Platform {
            os: "linux".to_string(),
            arch: "x86_64".to_string(),
            init_system: InitSystem::Systemd,
            is_openwrt: false,
            is_docker: false,
            firewall_backend: FirewallBackend::Iptables,
            default_crash_dir: "/etc/rustcrash",
            container_info: ContainerInfo::default(),
            crash_dir_resolved: "/etc/rustcrash".to_string(),
            runtime_dir_resolved: "/etc/rustcrash/run".to_string(),
            log_dir_resolved: "/etc/rustcrash/logs".to_string(),
        };

        // When running as non-root, require_root should return error
        // (This test might pass or fail depending on execution context)
        let result = platform.require_root();
        if platform.is_root() {
            assert!(result.is_ok());
        } else {
            assert!(result.is_err());
            assert!(matches!(result.unwrap_err(), Error::PermissionDenied));
        }
    }

    #[test]
    fn test_is_valid_command_name_valid() {
        assert!(Platform::is_valid_command_name("nft"));
        assert!(Platform::is_valid_command_name("iptables"));
        assert!(Platform::is_valid_command_name("command_name"));
        assert!(Platform::is_valid_command_name("command-name"));
        assert!(Platform::is_valid_command_name("cmd123"));
        assert!(Platform::is_valid_command_name("a"));
    }

    #[test]
    fn test_is_valid_command_name_invalid() {
        assert!(!Platform::is_valid_command_name("rm -rf"));
        assert!(!Platform::is_valid_command_name("cat /etc/passwd"));
        assert!(!Platform::is_valid_command_name("cmd;ls"));
        assert!(!Platform::is_valid_command_name("cmd|ls"));
        assert!(!Platform::is_valid_command_name("cmd`ls`"));
        assert!(!Platform::is_valid_command_name("cmd$(ls)"));
        assert!(!Platform::is_valid_command_name("cmd\nls"));
        assert!(!Platform::is_valid_command_name(""));
    }

    #[test]
    fn test_command_exists_valid_command() {
        assert!(Platform::command_exists("sh"));
        assert!(Platform::command_exists("echo"));
    }

    #[test]
    fn test_command_exists_invalid_command() {
        assert!(!Platform::command_exists("nonexistent_command_xyz123"));
        assert!(!Platform::command_exists(""));
        assert!(!Platform::command_exists("rm -rf"));
    }

    #[test]
    fn test_container_info_default() {
        let info = ContainerInfo::default();
        assert!(!info.is_container);
        assert!(info.interfaces.is_empty());
    }

    #[test]
    fn test_virtual_interface_patterns_defined() {
        assert!(!VIRTUAL_INTERFACE_PREFIXES.is_empty());
        assert!(VIRTUAL_INTERFACE_PREFIXES.contains(&"docker"));
        assert!(VIRTUAL_INTERFACE_PREFIXES.contains(&"veth"));
        assert!(VIRTUAL_INTERFACE_PREFIXES.contains(&"virbr"));
    }

    #[test]
    fn test_is_virtual_interface_docker() {
        assert!(is_virtual_interface("docker0"));
        assert!(is_virtual_interface("docker-peer1"));
    }

    #[test]
    fn test_is_virtual_interface_veth() {
        assert!(is_virtual_interface("veth1a2b3c"));
        assert!(is_virtual_interface("vethabc123"));
        assert!(is_virtual_interface("veth-peer1"));
    }

    #[test]
    fn test_is_virtual_interface_virbr() {
        assert!(is_virtual_interface("virbr0"));
        assert!(is_virtual_interface("virbr1"));
        assert!(is_virtual_interface("virbr-nic"));
    }

    #[test]
    fn test_is_virtual_interface_not_virtual() {
        assert!(!is_virtual_interface("eth0"));
        assert!(!is_virtual_interface("enp0s3"));
        assert!(!is_virtual_interface("ens33"));
        assert!(!is_virtual_interface("lo"));
        assert!(!is_virtual_interface("wlan0"));
        assert!(!is_virtual_interface("wlp2s0"));
    }

    #[test]
    fn test_is_virtual_interface_vmware() {
        assert!(is_virtual_interface("vmnet1"));
        assert!(is_virtual_interface("vmnet8"));
        assert!(is_virtual_interface("vmnic0"));
        assert!(is_virtual_interface("vmmon0"));
    }

    #[test]
    fn test_is_virtual_interface_openvz() {
        assert!(is_virtual_interface("venet0"));
        assert!(is_virtual_interface("vzfs"));
    }

    #[test]
    fn test_platform_contains_container_info() {
        let platform = Platform::detect().expect("Platform::detect() should work");
        // container_info should be populated (fields readable in either state)
        let _ = platform.container_info.is_container;
        let _ = platform.container_info.interfaces.len();
    }

    #[test]
    fn test_detect_virtual_interfaces_returns_list() {
        let interfaces = detect_virtual_interfaces();
        // Should return a list (may be empty on non-container)
        let _len = interfaces.len();
    }

    #[test]
    fn test_detect_containers_returns_info() {
        let info = detect_containers();
        // Should always return valid info
        let _len = info.interfaces.len();
        // If is_container is true, should have a cgroup pattern
        if info.is_container {
            assert!(info.cgroup_pattern.is_some());
        }
    }
}
