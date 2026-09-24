//! Plain uTLS fingerprint TLS: the `tls.utls` / `client-fingerprint` feature
//! without REALITY.
//!
//! Same ClientHello templates as REALITY (that is the entire point of the
//! feature: the server must see a browser's hello), but the certificate is
//! verified the normal way: full webpki path building and name checking
//! through rustls' own `rustls::client::WebPkiServerVerifier` (the exact
//! verifier rustls uses for its own client, ring backend — we only feed it
//! the certificate list we parsed out of the handshake).

use rand::RngCore;
use rustls::RootCertStore;

use crate::error::{Error, Result};
use crate::stream::BoxProxyStream;

use super::profiles::{self, UtslProfile};
use super::tls13::{self, ServerAuth};

/// Fingerprint-TLS configuration.
#[derive(Debug, Clone)]
pub struct UtlsCfg {
    /// SNI to present and the name the certificate must match.
    pub server_name: String,
    /// ClientHello template.
    pub profile: UtslProfile,
    /// ALPN protocols; empty means the profile's own list (h2, http/1.1).
    pub alpn: Vec<String>,
}

impl UtlsCfg {
    /// Config with the profile's default ALPN list.
    pub fn new(server_name: impl Into<String>, profile: UtslProfile) -> Self {
        UtlsCfg {
            server_name: server_name.into(),
            profile,
            alpn: Vec::new(),
        }
    }
}

/// Trust anchors for [`utls_connect`]: the platform store, falling back to
/// the bundled webpki roots for containers without one. (Same policy as
/// `crate::transport::tls_client_config`; kept local because this module is
/// the only place that needs the store itself rather than a rustls config.)
fn root_store() -> Result<RootCertStore> {
    let mut roots = RootCertStore::empty();
    let mut loaded = 0usize;
    for cert in rustls_native_certs::load_native_certs()
        .map_err(|e| Error::config(format!("utls: native cert store: {e}")))?
    {
        if roots.add(cert).is_ok() {
            loaded += 1;
        }
    }
    if loaded == 0 {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }
    Ok(roots)
}

/// Connect with a uTLS-style ClientHello and standard webpki verification.
///
/// `transport` is the dialled TCP stream; the returned stream is the TLS
/// session (usable as a [`BoxProxyStream`] for any protocol that expects a
/// raw byte tunnel).
pub async fn utls_connect(cfg: &UtlsCfg, transport: BoxProxyStream) -> Result<BoxProxyStream> {
    let mut random = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut random);
    // A fresh random legacy session id, like Chrome's (32 bytes, no
    // resumption in this client).
    let mut session_id = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut session_id);
    let (secret, public) = tls13::x25519_keygen();

    let alpn = if cfg.alpn.is_empty() {
        None
    } else {
        Some(cfg.alpn.as_slice())
    };
    let hello = profiles::build_client_hello_alpn(
        cfg.profile,
        &cfg.server_name,
        &random,
        &session_id,
        &public,
        alpn,
    );

    let auth = ServerAuth::WebPki {
        roots: std::sync::Arc::new(root_store()?),
        server_name: cfg.server_name.clone(),
    };
    let stream = tls13::connect(transport, &hello, &secret, auth).await?;
    Ok(Box::new(stream))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::reality::tls13::test_server::{self, ClientHelloInfo};
    use crate::proto::reality::tls13::CipherSuite;
    use std::sync::mpsc;
    use tokio::io::AsyncReadExt;

    fn self_signed(name: &str) -> (Vec<u8>, rustls::pki_types::PrivateKeyDer<'static>) {
        let key_pair = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let params = rcgen::CertificateParams::new(vec![name.to_string()]).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        (
            cert.der().to_vec(),
            rustls::pki_types::PrivateKeyDer::Pkcs8(key_pair.serialize_der().into()),
        )
    }

    /// `utls_connect` must (a) send the template hello with the requested SNI
    /// and ALPN, and (b) still refuse a certificate that does not chain to a
    /// public CA — this test's server is self-signed, so the handshake fails
    /// at verification even though everything else worked.
    #[tokio::test]
    async fn sends_the_template_hello_but_still_verifies_certificates() {
        let (der, key) = self_signed("www.example.com");
        let (tx, rx) = mpsc::channel::<ClientHelloInfo>();
        let (client, server) = tokio::io::duplex(64 * 1024);

        let server_task = tokio::spawn(async move {
            let offered_alpn = test_server::accept(
                Box::new(server),
                CipherSuite::Aes128GcmSha256,
                move |hello| {
                    let _ = tx.send(ClientHelloInfo {
                        raw: hello.raw.clone(),
                        random: hello.random,
                        session_id: hello.session_id.clone(),
                        x25519_share: hello.x25519_share,
                        sni: hello.sni.clone(),
                        alpn: hello.alpn.clone(),
                        cipher_suites: hello.cipher_suites.clone(),
                    });
                    Ok((der.clone(), rustls::crypto::ring::sign::any_supported_type(&key).unwrap()))
                },
            )
            .await;
            // The client refuses the certificate and drops the connection, so
            // the server's handshake must not complete either.
            assert!(offered_alpn.is_err());
        });

        let cfg = UtlsCfg {
            server_name: "www.example.com".into(),
            profile: UtslProfile::Firefox,
            alpn: vec!["http/1.1".to_string()],
        };
        let err = match utls_connect(&cfg, Box::new(client)).await {
            Ok(_) => panic!("a self-signed certificate must not pass webpki verification"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("certificate verification failed"),
            "unexpected error: {err}"
        );

        let hello = rx.recv().expect("the server saw a ClientHello");
        assert_eq!(hello.sni.as_deref(), Some("www.example.com"));
        assert_eq!(hello.alpn, vec!["http/1.1".to_string()]);
        assert_eq!(hello.session_id.len(), 32);
        assert_ne!(hello.session_id, vec![0u8; 32], "session id is freshly random");
        assert!(!hello.x25519_share.iter().all(|b| *b == 0));
        assert_eq!(hello.cipher_suites, UtslProfile::Firefox.cipher_suites().to_vec());
        let _ = server_task.await;
    }

    #[test]
    fn root_store_is_never_empty() {
        // Either the platform store or the bundled webpki roots are present.
        assert!(!root_store().unwrap().is_empty());
    }

    #[test]
    fn config_constructors() {
        let cfg = UtlsCfg::new("example.org", UtslProfile::Chrome);
        assert_eq!(cfg.server_name, "example.org");
        assert_eq!(cfg.profile, UtslProfile::Chrome);
        assert!(cfg.alpn.is_empty());
        assert_eq!(cfg.profile.as_str(), "chrome");
    }

    /// A quick check that the handshake reaches the ServerHello with the
    /// configured profile even when the peer is rustls (covered in depth by
    /// the tls13 tests; here it also exercises `root_store` loading).
    #[tokio::test]
    async fn failure_surfaces_before_any_tunnel_bytes() {
        let (client, mut server) = tokio::io::duplex(4096);
        let cfg = UtlsCfg::new("unreachable.test", UtslProfile::Chrome);
        let handle = tokio::spawn(async move {
            // Not a TLS server at all: it just reads the hello and closes.
            let mut buf = [0u8; 64];
            let n = server.read(&mut buf).await.unwrap();
            assert!(n > 0);
            assert_eq!(&buf[..3], &[0x16, 0x03, 0x01], "ClientHello record prefix");
            drop(server);
        });
        let err = match utls_connect(&cfg, Box::new(client)).await {
            Ok(_) => panic!("a non-TLS server must fail"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("closed during the handshake"),
            "unexpected error: {err}"
        );
        handle.await.unwrap();
    }
}