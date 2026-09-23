//! Subconverter - Native subscription format conversion
//!
//! This module provides pure-Rust subscription parsing and conversion
//! without requiring external subconverter binary.

pub mod filters;
pub mod formats;
pub mod merge;
pub mod pref;
pub mod script;
pub mod templates;
pub mod uri;

use serde::{Deserialize, Serialize};

/// Unified proxy node representation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProxyNode {
    pub name: String,
    pub protocol: ProxyProtocol,
    pub server: String,
    pub port: u16,
    pub extra: ProxyExtra,
}

/// Supported proxy protocols
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProxyProtocol {
    Shadowsocks,
    ShadowSocksR,
    VMess,
    VLESS,
    Trojan,
    Hysteria2,
    Tuic,
    WireGuard,
    Unknown,
}

/// Protocol-specific extra fields
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct ProxyExtra {
    /// Explicit UDP support flag from the URI (`udp=1`/`udp=0`).
    /// None means "use the protocol default" (see `node_supports_udp`).
    pub udp: Option<bool>,

    // Shadowsocks
    pub cipher: Option<String>,
    pub password: Option<String>,

    // VMess
    pub uuid: Option<String>,
    pub alter_id: Option<u16>,
    pub transport: Option<TransportType>,
    pub tls: bool,
    pub sni: Option<String>,

    // VLESS
    pub vless_uuid: Option<String>,
    pub vless_flow: Option<String>,

    // Trojan
    pub trojan_password: Option<String>,

    // Hysteria2
    pub hy2_password: Option<String>,
    pub hy2_obfs: Option<String>,

    // TUIC
    pub tuic_uuid: Option<String>,
    pub tuic_password: Option<String>,
    pub tuic_congestion_control: Option<String>,

    // WireGuard
    pub wg_private_key: Option<String>,
    pub wg_public_key: Option<String>,
    pub wg_preshared_key: Option<String>,
    pub wg_endpoint: Option<String>,
    pub wg_mtu: Option<u16>,
    pub wg_addresses: Vec<String>,

    // ShadowSocksR
    pub ssr_protocol: Option<String>,
    pub ssr_method: Option<String>,
    pub ssr_obfs: Option<String>,
    pub ssr_obfs_param: Option<String>,
}

/// VMess/VLESS transport type
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub enum TransportType {
    #[default]
    Tcp,
    WebSocket,
    Http,
    Grpc,
}

/// Convert target format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetFormat {
    Clash,
    ClashR,
    SingBox,
    Quantumult,
    QuantumultX,
    Loon,
    Surge,
    Surfboard,
    Stash,
    V2Ray,
    SS,
    SSR,
    SSD,
    Trojan,
    Mixed,
    Mellow,
}

impl TargetFormat {
    // ShellCrash-parity API: returns Option, not FromStr's Result.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Option<Self> {
        match s.to_lowercase().as_str() {
            "clash" => Some(TargetFormat::Clash),
            "clashr" => Some(TargetFormat::ClashR),
            "singbox" | "sing-box" => Some(TargetFormat::SingBox),
            "quan" | "quantumult" => Some(TargetFormat::Quantumult),
            "quanx" | "quantumultx" => Some(TargetFormat::QuantumultX),
            "loon" => Some(TargetFormat::Loon),
            "surge" => Some(TargetFormat::Surge),
            "surge&ver=2" => Some(TargetFormat::Surge),
            "surge&ver=3" => Some(TargetFormat::Surge),
            "surge&ver=4" => Some(TargetFormat::Surge),
            "surfboard" => Some(TargetFormat::Surfboard),
            "stash" => Some(TargetFormat::Stash),
            "v2ray" => Some(TargetFormat::V2Ray),
            "ss" | "sssub" => Some(TargetFormat::SS),
            "ssr" => Some(TargetFormat::SSR),
            "ssd" => Some(TargetFormat::SSD),
            "trojan" => Some(TargetFormat::Trojan),
            "mixed" => Some(TargetFormat::Mixed),
            "mellow" => Some(TargetFormat::Mellow),
            _ => None,
        }
    }
}

/// Surge version for format differences
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum SurgeVersion {
    #[default]
    V4,
    V3,
    V2,
}

impl SurgeVersion {
    // ShellCrash-parity API: infallible with a default, not FromStr's Result.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Self {
        match s {
            "ver=2" | "2" => SurgeVersion::V2,
            "ver=3" | "3" => SurgeVersion::V3,
            _ => SurgeVersion::V4,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_target_format_from_str() {
        assert_eq!(TargetFormat::from_str("clash"), Some(TargetFormat::Clash));
        assert_eq!(
            TargetFormat::from_str("singbox"),
            Some(TargetFormat::SingBox)
        );
        assert_eq!(
            TargetFormat::from_str("quan"),
            Some(TargetFormat::Quantumult)
        );
        assert_eq!(TargetFormat::from_str("surge"), Some(TargetFormat::Surge));
        assert_eq!(TargetFormat::from_str("unknown"), None);
    }
}
