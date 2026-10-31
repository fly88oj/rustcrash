//! Shared reqwest plumbing for every outbound HTTPS path in core
//! (subscription fetch, kernel/geodata/rules downloads, notify
//! webhooks, bot API).
//!
//! reqwest 0.13 ships rustls without a bundled crypto provider
//! (`rustls-no-provider`: its `rustls` feature pins aws-lc-rs, which
//! needs cmake for the musl cross builds this project ships — see the
//! engine Cargo.toml note) and verifies against the platform store by
//! default. This module installs the ring provider as the process
//! default (reqwest consults it even for plain-HTTP clients) and
//! preconfigures a rustls `ClientConfig` with the bundled Mozilla
//! roots, so verification matches the reqwest 0.12 `rustls-tls`
//! behaviour exactly: no dependency on the host having a system trust
//! store (bare containers keep working).

use std::sync::{Arc, OnceLock};

/// Install the ring CryptoProvider as the process default (idempotent;
/// a no-op when something already installed one, e.g. a test harness).
pub fn ensure_ring_provider() {
    static INSTALLED: OnceLock<()> = OnceLock::new();
    INSTALLED.get_or_init(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

fn rustls_config() -> rustls::ClientConfig {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("ring provider supports the default protocol versions")
        .with_root_certificates(roots)
        .with_no_client_auth()
}

/// A `Client::builder()` preconfigured for the bundled-roots TLS
/// policy described above.
pub(crate) fn tls_builder() -> reqwest::ClientBuilder {
    ensure_ring_provider();
    static CONFIG: OnceLock<rustls::ClientConfig> = OnceLock::new();
    reqwest::Client::builder().tls_backend_preconfigured(CONFIG.get_or_init(rustls_config).clone())
}

/// A plain `reqwest::Client::new()` equivalent that works under the
/// no-provider build: ring provider installed, default TLS settings.
#[allow(dead_code)] // test-only: the api tests build plain-HTTP clients
pub(crate) fn plain_client() -> reqwest::Client {
    ensure_ring_provider();
    reqwest::Client::new()
}
