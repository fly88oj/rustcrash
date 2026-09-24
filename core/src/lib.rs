//! RustCrash Core Library

pub mod api;
pub mod backup;
pub mod bot;
pub mod config;
pub mod engine;
pub mod error;
pub mod firewall;
pub mod geo;
pub mod import_export;
pub mod init;
pub mod kernels;
pub mod logging;
pub mod notify;
pub mod platform;
pub mod rules;
pub mod service;
pub mod subconverter;
pub mod subscription;
pub mod task;
pub mod template;
pub mod validate;

pub use api::ApiServer;
pub use backup::{BackupInfo, BackupManager};
pub use bot::{BotAwait, BotConfig, TelegramBot, UploadKind};
pub use config::{
    Config, ConfigDnsMode, ConfigManager, ConfigVariant, ProxyMode, RuleProvider, Subscription,
};
pub use error::{Error, Result};
pub use firewall::{
    DnsMode, Firewall, FirewallConfig, MacFilterType, RedirMode, DEFAULT_DNS_PORT,
    DEFAULT_MIXED_PORT, DEFAULT_PROXY_PORT,
};
pub use geo::{GeoUpdateReport, GeoUpdater, DEFAULT_GEO_REPO};
pub use import_export::{export_config, export_config_auto, import_config, ConfigFormat};
pub use kernels::sha256_hex;
pub use kernels::{KernelInfo, KernelManager};
pub use logging::{append_rotated, init_logging, install_crash_reporting, tail_file};
pub use notify::{NotificationManager, NotifyConfig};
pub use platform::{
    Detect, FirewallBackend, InitSystem as PlatformInitSystem, Platform, ProxyKernel,
};
pub use rules::{RuleProviderManager, RulesUpdateReport};
pub use service::{serve as serve_supervisor, ServiceManager, ServiceStatus};
pub use subconverter::formats::convert_nodes;
pub use subconverter::merge::{merge_uris, MergeResult};
pub use subconverter::pref::{GlobalPrefs, PrefEntry, PrefIni};
pub use subconverter::templates::{
    ProviderBehavior, RuleAction, RuleEntry, RuleProviderDef, RuleTemplate, RuleTemplates, RuleType,
};
pub use subconverter::uri::{parse_uri, parse_uri_list};
pub use subconverter::{ProxyNode, ProxyProtocol, TargetFormat};
pub use subscription::{
    SubscriptionFormat, SubscriptionInfo, SubscriptionManager, UrlValidationResult,
};
pub use template::{Template, TemplateManager};
pub use validate::{ConfigValidator, ValidationError, ValidationResult};
