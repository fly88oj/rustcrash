//! Bridge between the manager and the Rust-native proxy engine.
//!
//! Users select the engine through `config.yaml`'s `kernel` field:
//! `mihomo` / `sing-box` manage an external kernel binary (unchanged
//! behaviour), `rust-mihomo` / `rust-sing-box` run the integrated Rust
//! engine in-process. The engine flavors only exist in builds compiled
//! with the `engine-mihomo` / `engine-singbox` cargo features.

use crate::error::{Error, Result};
use crate::platform::{Platform, ProxyKernel};

/// Which engine dialect to run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EngineFlavor {
    /// Clash/mihomo YAML config dialect.
    Mihomo,
    /// sing-box JSON config dialect.
    SingBox,
}

impl EngineFlavor {
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "rust-mihomo" => Some(EngineFlavor::Mihomo),
            "rust-sing-box" => Some(EngineFlavor::SingBox),
            _ => None,
        }
    }

    /// The value used in the `kernel` config field.
    pub fn as_str(&self) -> &'static str {
        match self {
            EngineFlavor::Mihomo => "rust-mihomo",
            EngineFlavor::SingBox => "rust-sing-box",
        }
    }

    /// The cargo feature that compiles this flavor in — used in error
    /// messages and validation, so the mapping lives in one place.
    pub fn feature_name(self) -> &'static str {
        match self {
            EngineFlavor::Mihomo => "engine-mihomo",
            EngineFlavor::SingBox => "engine-singbox",
        }
    }

    /// The kernel config file this flavor consumes (same files the
    /// external kernels use, so switching is a one-line config change).
    pub fn kernel(self) -> ProxyKernel {
        match self {
            EngineFlavor::Mihomo => ProxyKernel::Mihomo,
            EngineFlavor::SingBox => ProxyKernel::SingBox,
        }
    }

    /// Resolve a flavor name from CLI input plus the config path the
    /// engine should use when the caller didn't pass one explicitly.
    /// Shared by the CLI's Run and Test arms (design rule 4: the binary
    /// stays thin).
    pub fn resolve(
        name: &str,
        config: Option<&str>,
        platform: &Platform,
    ) -> Result<(EngineFlavor, String)> {
        let flavor = EngineFlavor::parse(name).ok_or_else(|| {
            Error::Process(format!(
                "unknown flavor {name:?} (expected rust-mihomo or rust-sing-box)"
            ))
        })?;
        ensure_supported(flavor)?;
        let path = match config {
            Some(p) => p.to_string(),
            None => crate::config::ConfigManager::new(platform).kernel_config_path(flavor.kernel()),
        };
        Ok((flavor, path))
    }
}

/// The complete choice of data plane.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelSelection {
    /// Download and supervise the external kernel binary (status quo).
    External(ProxyKernel),
    /// Run the integrated Rust engine.
    Engine(EngineFlavor),
}

impl KernelSelection {
    /// Parse the `kernel` config value.
    pub fn parse(s: &str) -> Self {
        if s == "sing-box" {
            KernelSelection::External(ProxyKernel::SingBox)
        } else if let Some(flavor) = EngineFlavor::parse(s) {
            KernelSelection::Engine(flavor)
        } else {
            KernelSelection::External(ProxyKernel::Mihomo)
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            KernelSelection::External(k) => k.binary_name(),
            KernelSelection::Engine(f) => f.as_str(),
        }
    }
}

/// Flavors compiled into this binary (build-time feature flags).
pub fn available_flavors() -> &'static [&'static str] {
    &[
        #[cfg(feature = "engine-mihomo")]
        "rust-mihomo",
        #[cfg(feature = "engine-singbox")]
        "rust-sing-box",
    ]
}

/// Whether the flavor's engine code is compiled in.
pub fn flavor_supported(flavor: EngineFlavor) -> bool {
    match flavor {
        EngineFlavor::Mihomo => cfg!(feature = "engine-mihomo"),
        EngineFlavor::SingBox => cfg!(feature = "engine-singbox"),
    }
}

/// Fail with a precise message when the flavor was not compiled in.
pub fn ensure_supported(flavor: EngineFlavor) -> Result<()> {
    if flavor_supported(flavor) {
        Ok(())
    } else {
        Err(Error::Config(format!(
            "this crash binary was built without the {} engine; rebuild with \
             `cargo build --features {}` or switch kernel back to mihomo/sing-box",
            flavor.as_str(),
            flavor.feature_name()
        )))
    }
}

/// Engine version line (in-process; no kernel binary needed).
pub fn version() -> &'static str {
    #[cfg(any(feature = "engine-mihomo", feature = "engine-singbox"))]
    {
        concat!("rustcrash-engine ", env!("CARGO_PKG_VERSION"))
    }
    #[cfg(not(any(feature = "engine-mihomo", feature = "engine-singbox")))]
    {
        "rustcrash-engine (not compiled in)"
    }
}

#[cfg(any(feature = "engine-mihomo", feature = "engine-singbox"))]
mod imp {
    use super::*;

    /// Load and normalize the kernel config for a flavor, wiring geo
    /// database paths from the install directory.
    pub fn load(flavor: EngineFlavor, path: &str, platform: &Platform) -> Result<rustcrash_engine::EngineConfig> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| Error::Config(format!("engine config {path}: {e}")))?;
        let mut cfg = match flavor {
            #[cfg(feature = "engine-mihomo")]
            EngineFlavor::Mihomo => rustcrash_engine::config_mihomo::load(&text)?,
            #[cfg(not(feature = "engine-mihomo"))]
            EngineFlavor::Mihomo => {
                return Err(Error::Config(
                    "mihomo dialect not compiled in (feature engine-mihomo)".into(),
                ))
            }
            #[cfg(feature = "engine-singbox")]
            EngineFlavor::SingBox => rustcrash_engine::config_singbox::load(&text)?,
            #[cfg(not(feature = "engine-singbox"))]
            EngineFlavor::SingBox => {
                return Err(Error::Config(
                    "sing-box dialect not compiled in (feature engine-singbox)".into(),
                ))
            }
        };
        // Geo data lives where the geo updater installs it.
        let geodata = format!("{}/bin/geodata", platform.crash_dir());
        let mmdb = format!("{geodata}/country.mmdb");
        let dat = format!("{geodata}/geosite.dat");
        if std::path::Path::new(&mmdb).exists() {
            cfg.geo.geoip_mmdb = Some(mmdb);
        }
        if std::path::Path::new(&dat).exists() {
            cfg.geo.geosite_dat = Some(dat);
        }
        // DIRECT/REJECT/PASS are always available in mihomo semantics and
        // sing-box users pin them explicitly anyway.
        Ok(cfg.with_builtin_outbounds())
    }

    /// Parse + validate; returns the warnings a config test should print.
    pub fn test(flavor: EngineFlavor, path: &str, platform: &Platform) -> Result<Vec<String>> {
        let cfg = load(flavor, path, platform)?;
        Ok(rustcrash_engine::config::validate(&cfg)?)
    }

    /// Run the engine in the foreground (used by `crash engine run` and by
    /// the supervised self-spawn). Owns a multi-thread runtime — callers
    /// are process entry points, not async contexts.
    pub fn run(flavor: EngineFlavor, path: &str, platform: &Platform) -> Result<()> {
        ensure_supported(flavor)?;
        let cfg = load(flavor, path, platform)?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(|e| Error::Process(format!("engine runtime: {e}")))?;
        let engine = rustcrash_engine::Engine::build(cfg)?;
        let result = runtime.block_on(engine.run());
        // Bounded teardown: DROPPING a runtime blocks until every
        // blocking-pool task finishes — an in-flight getaddrinfo under
        // an unreachable resolver can hang for many seconds, and a
        // manager's stop path (ShellCrash's start.sh stop) must see the
        // process exit within a couple of seconds of SIGTERM. Cap the
        // wait; anything still running is reclaimed by process exit,
        // exactly like mihomo's prompt TERM shutdown.
        runtime.shutdown_timeout(std::time::Duration::from_secs(1));
        result.map_err(|e| e.into())
    }
}

#[cfg(any(feature = "engine-mihomo", feature = "engine-singbox"))]
pub use imp::{run, test};

#[cfg(not(any(feature = "engine-mihomo", feature = "engine-singbox")))]
pub use stubs::{run, test};

#[cfg(not(any(feature = "engine-mihomo", feature = "engine-singbox")))]
mod stubs {
    use super::*;

    pub fn test(_flavor: EngineFlavor, _path: &str, _platform: &Platform) -> Result<Vec<String>> {
        Err(no_engine_error())
    }

    pub fn run(_flavor: EngineFlavor, _path: &str, _platform: &Platform) -> Result<()> {
        Err(no_engine_error())
    }

    fn no_engine_error() -> Error {
        Error::Config(
            "no engine flavor is compiled into this binary; rebuild with \
             `cargo build --features engine-mihomo,engine-singbox`"
                .into(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selection_parsing() {
        assert_eq!(
            KernelSelection::parse("mihomo"),
            KernelSelection::External(ProxyKernel::Mihomo)
        );
        assert_eq!(
            KernelSelection::parse("sing-box"),
            KernelSelection::External(ProxyKernel::SingBox)
        );
        assert_eq!(
            KernelSelection::parse("rust-mihomo"),
            KernelSelection::Engine(EngineFlavor::Mihomo)
        );
        assert_eq!(
            KernelSelection::parse("rust-sing-box"),
            KernelSelection::Engine(EngineFlavor::SingBox)
        );
        // Unknown values fall back to mihomo (validator warns separately);
        // undocumented aliases are rejected so configs stay portable.
        assert_eq!(
            KernelSelection::parse("whatever"),
            KernelSelection::External(ProxyKernel::Mihomo)
        );
        assert!(EngineFlavor::parse("rust-clash").is_none());
        assert!(EngineFlavor::parse("rust-momo").is_none());
        assert!(EngineFlavor::parse("rust-singbox").is_none());
    }

    #[test]
    fn feature_names_are_cargo_features() {
        assert_eq!(EngineFlavor::Mihomo.feature_name(), "engine-mihomo");
        assert_eq!(EngineFlavor::SingBox.feature_name(), "engine-singbox");
    }

    #[test]
    fn resolve_rejects_unknown_flavor() {
        let platform = Platform::for_crash_dir("/tmp/rc-engine-resolve");
        let err = EngineFlavor::resolve("bogus", None, &platform).unwrap_err();
        assert!(err.to_string().contains("unknown flavor"), "{err}");
    }

    #[test]
    fn flavor_support_matches_features() {
        assert_eq!(flavor_supported(EngineFlavor::Mihomo), cfg!(feature = "engine-mihomo"));
        assert_eq!(flavor_supported(EngineFlavor::SingBox), cfg!(feature = "engine-singbox"));
        if !available_flavors().is_empty() {
            for name in available_flavors() {
                assert!(EngineFlavor::parse(name).is_some());
            }
        }
    }

    #[test]
    fn unsupported_flavor_error_names_the_feature() {
        if flavor_supported(EngineFlavor::Mihomo) {
            assert!(ensure_supported(EngineFlavor::Mihomo).is_ok());
        } else {
            let err = ensure_supported(EngineFlavor::Mihomo).unwrap_err().to_string();
            assert!(err.contains("engine-mihomo"), "{err}");
        }
    }
}
