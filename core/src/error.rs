//! Error types for RustCrash

use std::fmt;

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Platform(String),
    Firewall(String),
    Download(String),
    Config(String),
    Subscription(String),
    Process(String),
    Engine(String),
    Init(String),
    InitSystem(String),
    NotSupported(String),
    PermissionDenied,
    Security(String),
    Bot(String),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(e) => write!(f, "IO error: {e}"),
            Error::Platform(s) => write!(f, "Platform error: {s}"),
            Error::Firewall(s) => write!(f, "Firewall error: {s}"),
            Error::Download(s) => write!(f, "Download error: {s}"),
            Error::Config(s) => write!(f, "Config error: {s}"),
            Error::Subscription(s) => write!(f, "Subscription error: {s}"),
            Error::Process(s) => write!(f, "Process error: {s}"),
            Error::Engine(s) => write!(f, "Engine error: {s}"),
            Error::Init(s) => write!(f, "Init error: {s}"),
            Error::InitSystem(s) => write!(f, "Init system error: {s}"),
            Error::NotSupported(s) => write!(f, "Not supported: {s}"),
            Error::PermissionDenied => write!(f, "Permission denied: root privileges required"),
            Error::Security(s) => write!(f, "Security error: {s}"),
            Error::Bot(s) => write!(f, "Bot error: {s}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(e: std::io::Error) -> Self {
        Error::Io(e)
    }
}

impl From<serde_yaml::Error> for Error {
    fn from(e: serde_yaml::Error) -> Self {
        Error::Config(format!("YAML error: {}", e))
    }
}

impl From<serde_json::Error> for Error {
    fn from(e: serde_json::Error) -> Self {
        Error::Config(format!("JSON error: {}", e))
    }
}

#[cfg(any(feature = "engine-mihomo", feature = "engine-singbox"))]
impl From<rustcrash_engine::Error> for Error {
    fn from(e: rustcrash_engine::Error) -> Self {
        Error::Engine(e.to_string())
    }
}
