//! rustcrash-engine: a Rust-native rewrite of the mihomo / sing-box data
//! plane. Protocol codecs, inbounds, outbounds, routing, DNS and the Clash
//! RESTful API — no external kernel process.

pub mod addr;
pub mod api;
pub mod app;
#[cfg(feature = "mihomo")]
pub mod config_mihomo;
#[cfg(feature = "singbox")]
pub mod config_singbox;
pub mod config;
pub mod dns;
pub mod error;
pub mod geosite;
pub mod grpc;
pub mod inbound;
pub mod outbound;
pub mod process;
pub mod proto;
pub mod quic;
pub mod rule;
pub mod ruleset_bin;
pub mod sniffer;
pub mod stats;
pub mod stream;
pub mod transport;

pub use app::Engine;
pub use config::EngineConfig;

pub use error::{Error, Result};

/// Engine version (crate version, surfaced by the CLI and the API).
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
