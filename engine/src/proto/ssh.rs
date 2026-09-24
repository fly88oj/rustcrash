//! SSH outbound (russh): password or private-key authentication on a fresh
//! SSH session, then a `direct-tcpip` channel towards the routing target
//! spliced into a raw byte stream.
//!
//! Mirrors mihomo's `ssh` outbound (`adapter/outbound/ssh.go`): the proxy
//! carries `server:port`, `username`, one of `password` / `private-key`
//! (+ optional `private-key-passphrase`), an optional pinned `host-key`
//! list, and tunnels with a `direct-tcpip` channel opened via
//! `Client.Dial("tcp", target)` — i.e. `direct-tcpip` with the target
//! host/port and a fixed `127.0.0.1:0` originator. mihomo keeps one SSH
//! connection and multiplexes every request over it; the engine's contract
//! is one stream per dial, so each [`connect`] uses its own session whose
//! lifetime is tied to the returned stream.

use std::borrow::Cow;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{ready, Context, Poll};

use rand::Rng;
use russh::client::{self, Config, Handle, Msg};
use russh::keys::{
    decode_secret_key, parse_public_key_base64, PrivateKeyWithHashAlg, PublicKey,
    PublicKeyBase64, PublicKeyOrCertificate,
};
use russh::{ChannelStream, SshId};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tracing::{debug, warn};

use crate::addr::NetAddr;
use crate::error::{Error, Result};
use crate::stream::BoxProxyStream;

/// Originator address announced in the `direct-tcpip` open request. mihomo
/// (through x/crypto/ssh) always sends loopback port 0.
const ORIGINATOR_HOST: &str = "127.0.0.1";
const ORIGINATOR_PORT: u32 = 0;

/// Outbound SSH endpoint.
#[derive(Debug, Clone)]
pub struct SshOut {
    pub server: String,
    pub port: u16,
    pub user: String,
    pub password: Option<String>,
    /// OpenSSH/PKCS#8 private key text (not a file path — the engine has no
    /// config-path plumbing, mihomo resolves a path for non-PEM values).
    pub private_key: Option<String>,
    pub private_key_passphrase: Option<String>,
    /// Pinned server host keys, in OpenSSH one-line (`ssh-ed25519 AAAA…`)
    /// or bare base64 form. Empty accepts any key, with a warning — mihomo
    /// parity.
    pub host_key: Vec<String>,
}

/// A parsed host-key pin: algorithm label (for diagnostics) + SSH wire blob.
type HostKeyPin = (String, Vec<u8>);

/// Parse configured host-key pins into SSH wire blobs (`key.Marshal()`
/// equivalents, algorithm name included).
fn parse_host_keys(entries: &[String]) -> Result<Vec<HostKeyPin>> {
    let mut pins = Vec::with_capacity(entries.len());
    for raw in entries {
        let entry = raw.trim();
        if entry.is_empty() {
            continue;
        }
        // `PublicKey::from_openssh` covers "algo base64 [comment]";
        // `parse_public_key_base64` also takes a bare base64 blob.
        let key = PublicKey::from_openssh(entry).or_else(|_| parse_public_key_base64(entry));
        let key = key
            .map_err(|e| Error::config(format!("ssh: unusable host-key entry {entry:?}: {e}")))?;
        let blob = key
            .to_bytes()
            .map_err(|e| Error::config(format!("ssh: cannot encode host-key entry {entry:?}: {e}")))?;
        pins.push((key.algorithm().to_string(), blob));
    }
    Ok(pins)
}

/// The server key's SSH wire blob, for both plain keys and OpenSSH
/// certificates (a certificate authenticates the key it wraps).
fn server_key_blob(key: &PublicKeyOrCertificate) -> Vec<u8> {
    match key {
        PublicKeyOrCertificate::PublicKey { key, .. } => key.to_bytes().unwrap_or_default(),
        PublicKeyOrCertificate::Certificate(cert) => PublicKey::new(cert.public_key().clone(), "")
            .to_bytes()
            .unwrap_or_default(),
    }
}

/// Does `key` match one of the pins? (Split out so the pinning rule is
/// unit-testable without an SSH session.)
fn host_key_matches(pins: &[HostKeyPin], key: &PublicKeyOrCertificate) -> bool {
    let blob = server_key_blob(key);
    !blob.is_empty() && pins.iter().any(|(_, pin)| pin == &blob)
}

/// Client handler implementing mihomo's host-key policy.
struct Handler {
    /// Pinned keys; empty = accept any.
    pinned: Vec<HostKeyPin>,
    /// The accept-any warning is emitted once per session, not per kex.
    warned_accept_any: bool,
}

impl client::Handler for Handler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &PublicKeyOrCertificate,
    ) -> std::result::Result<bool, Self::Error> {
        if self.pinned.is_empty() {
            if !self.warned_accept_any {
                self.warned_accept_any = true;
                warn!(
                    target: "engine",
                    "ssh: no host-key configured, accepting the server key unverified"
                );
            }
            return Ok(true);
        }
        if host_key_matches(&self.pinned, server_public_key) {
            return Ok(true);
        }
        match server_public_key {
            PublicKeyOrCertificate::PublicKey { key, .. } => warn!(
                target: "engine",
                "ssh: host key mismatch, server sent {} {}",
                key.algorithm(),
                key.public_key_base64()
            ),
            PublicKeyOrCertificate::Certificate(cert) => warn!(
                target: "engine",
                "ssh: host key mismatch, server sent a {} certificate",
                cert.algorithm()
            ),
        }
        Ok(false)
    }
}

/// Client config: mihomo randomizes the client banner over OpenSSH 7.x/8.x
/// and lets Go set TCP_NODELAY; keep both behaviours.
fn client_config() -> Config {
    let mut rng = rand::thread_rng();
    let id = if rng.gen_bool(0.5) {
        format!("SSH-2.0-OpenSSH_7.{}", rng.gen_range(0..10))
    } else {
        format!("SSH-2.0-OpenSSH_8.{}", rng.gen_range(0..9))
    };
    Config {
        client_id: SshId::Standard(Cow::Owned(id)),
        nodelay: true,
        ..Config::default()
    }
}

/// Authenticate `session` for `cfg`. mihomo registers the private-key
/// method before the password method; x/crypto/ssh then tries them in
/// order, so a rejected key still falls through to the password.
async fn authenticate(session: &mut Handle<Handler>, cfg: &SshOut) -> Result<()> {
    if let Some(pem) = cfg.private_key.as_deref() {
        let key = decode_secret_key(pem, cfg.private_key_passphrase.as_deref())
            .map_err(|e| Error::config(format!("ssh: private key: {e}")))?;
        // OpenSSH servers reject plain ssh-rsa (SHA-1) signatures, so RSA
        // keys are offered as rsa-sha2-256.
        let hash_alg = key
            .algorithm()
            .is_rsa()
            .then_some(russh::keys::HashAlg::Sha256);
        let key = PrivateKeyWithHashAlg::new(Arc::new(key), hash_alg);
        let res = session
            .authenticate_publickey(&cfg.user, key)
            .await
            .map_err(|e| Error::network(format!("ssh: public-key auth against {}:{}: {e}", cfg.server, cfg.port)))?;
        if res.success() {
            return Ok(());
        }
        debug!(target: "engine", "ssh: server rejected the private key, trying password");
    }
    if let Some(password) = cfg.password.as_deref() {
        let res = session
            .authenticate_password(&cfg.user, password)
            .await
            .map_err(|e| Error::network(format!("ssh: password auth against {}:{}: {e}", cfg.server, cfg.port)))?;
        if res.success() {
            return Ok(());
        }
    }
    Err(Error::protocol(format!(
        "ssh: authentication as {:?} rejected by {}:{}",
        cfg.user, cfg.server, cfg.port
    )))
}

/// Dial `target` through the SSH endpoint described by `cfg`: connect (over
/// the plain TCP dialer the plugin wrapper supplies upstream — this
/// function performs the TCP connect itself), authenticate, then open a
/// `direct-tcpip` channel and hand it back as a byte stream.
pub async fn connect(cfg: &SshOut, target: &NetAddr) -> Result<BoxProxyStream> {
    if cfg.user.is_empty() {
        return Err(Error::config("ssh: username is required"));
    }
    if cfg.password.is_none() && cfg.private_key.is_none() {
        return Err(Error::config("ssh: password or private-key is required"));
    }
    let pinned = parse_host_keys(&cfg.host_key)?;
    let handler = Handler {
        pinned,
        warned_accept_any: false,
    };
    let mut session = client::connect(Arc::new(client_config()), (cfg.server.as_str(), cfg.port), handler)
        .await
        .map_err(|e| Error::network(format!("ssh: connect {}:{}: {e}", cfg.server, cfg.port)))?;

    authenticate(&mut session, cfg).await?;

    // x/crypto/ssh's `Dial` sends host_to_connect/port_to_connect plus
    // originator "127.0.0.1:0"; the target host is forwarded verbatim
    // (no local DNS resolution).
    let channel = session
        .channel_open_direct_tcpip(
            target.host.to_text(),
            u32::from(target.port),
            ORIGINATOR_HOST,
            ORIGINATOR_PORT,
        )
        .await
        .map_err(|e| Error::network(format!("ssh: direct-tcpip to {target}: {e}")))?;
    debug!(target: "engine", %target, "ssh: direct-tcpip channel open");
    Ok(Box::new(SshStream {
        inner: channel.into_stream(),
        eof: false,
    }))
}

/// A `direct-tcpip` channel as an `AsyncRead + AsyncWrite` stream.
///
/// Wraps russh's [`ChannelStream`], which adapts the channel's incoming
/// [`russh::ChannelMsg`] queue (`Data` / `Eof` / `Close`) into reads and the
/// channel write half (with SSH window flow control) into writes.
pub struct SshStream {
    inner: ChannelStream<Msg>,
    /// Set once the channel reported EOF: later reads must keep reporting
    /// EOF instead of re-polling the channel queue.
    eof: bool,
}

impl AsyncRead for SshStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if self.eof {
            return Poll::Ready(Ok(()));
        }
        let before = buf.filled().len();
        ready!(Pin::new(&mut self.inner).poll_read(cx, buf))?;
        if buf.filled().len() == before {
            self.eof = true;
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for SshStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        // russh's channel writer rejects empty buffers; callers may not.
        if buf.is_empty() {
            return Poll::Ready(Ok(0));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::net::{Ipv4Addr, SocketAddr};
    use std::sync::Mutex;
    use std::time::Duration;

    use russh::keys::ssh_key::LineEnding;
    use russh::keys::{Algorithm, PrivateKey};
    use russh::server;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// A recorded `direct-tcpip` open: host, port, originator, originator port.
    type DirectTcpipOpen = (String, u32, String, u32);

    /// Everything the test SSH server needs to know, all generated in-test
    /// (no credential literals).
    struct ServerPlan {
        host_key: PrivateKey,
        password: String,
        /// direct-tcpip requests the server observed.
        opened: Arc<Mutex<Vec<DirectTcpipOpen>>>,
    }

    /// The test server's handler: accepts the plan's password, any public
    /// key, records `direct-tcpip` opens and echoes channel data.
    struct TestHandler {
        plan: Arc<ServerPlan>,
    }

    impl server::Handler for TestHandler {
        type Error = russh::Error;

        async fn auth_password(
            &mut self,
            user: &str,
            password: &str,
        ) -> std::result::Result<server::Auth, Self::Error> {
            let ok = user == "tester" && password == self.plan.password;
            Ok(if ok { server::Auth::Accept } else { reject() })
        }

        async fn auth_publickey(
            &mut self,
            user: &str,
            _key: &PublicKey,
        ) -> std::result::Result<server::Auth, Self::Error> {
            Ok(if user == "tester" { server::Auth::Accept } else { reject() })
        }

        async fn channel_open_direct_tcpip(
            &mut self,
            _channel: russh::Channel<server::Msg>,
            host_to_connect: &str,
            port_to_connect: u32,
            originator_address: &str,
            originator_port: u32,
            reply: server::ChannelOpenHandle,
            _session: &mut server::Session,
        ) -> std::result::Result<(), Self::Error> {
            self.plan.opened.lock().unwrap().push((
                host_to_connect.to_string(),
                port_to_connect,
                originator_address.to_string(),
                originator_port,
            ));
            reply.accept().await;
            Ok(())
        }

        async fn data(
            &mut self,
            channel: russh::ChannelId,
            data: &[u8],
            session: &mut server::Session,
        ) -> std::result::Result<(), Self::Error> {
            session.data(channel, data.to_vec())?;
            Ok(())
        }
    }

    fn reject() -> server::Auth {
        server::Auth::Reject {
            proceed_with_methods: None,
            partial_success: false,
        }
    }

    /// Bind a loopback listener, serve one SSH connection from it with
    /// `plan`, and return the listener's address.
    async fn spawn_server(plan: Arc<ServerPlan>) -> SocketAddr {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = Arc::new(server::Config {
            keys: vec![plan.host_key.clone()],
            inactivity_timeout: Some(Duration::from_secs(30)),
            ..server::Config::default()
        });
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            let handler = TestHandler { plan };
            // Driving the session until the client disconnects: an Err after
            // the test finishes is expected and ignored.
            let _ = server::run_stream(config, socket, handler).await;
        });
        addr
    }

    fn plan(password: &str) -> Arc<ServerPlan> {
        Arc::new(ServerPlan {
            host_key: PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519)
                .unwrap(),
            password: password.to_string(),
            opened: Arc::new(Mutex::new(Vec::new())),
        })
    }

    fn cfg_for(addr: SocketAddr, plan: &ServerPlan) -> SshOut {
        SshOut {
            server: addr.ip().to_string(),
            port: addr.port(),
            user: "tester".to_string(),
            password: Some(plan.password.clone()),
            private_key: None,
            private_key_passphrase: None,
            host_key: vec![plan.host_key.public_key().public_key_base64()],
        }
    }

    #[test]
    fn host_key_pins_accept_both_spellings() {
        let key = PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519)
            .unwrap();
        let public = key.public_key().clone();
        let bare = public.public_key_base64();
        let line = public.to_openssh().unwrap();

        let pins = parse_host_keys(&[bare.clone(), line, "  ".to_string()]).unwrap();
        assert_eq!(pins.len(), 2, "blank entries are skipped");
        assert!(host_key_matches(&pins, &public.clone().into()));
        assert_eq!(pins[0].1, public.to_bytes().unwrap());

        let other = PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519)
            .unwrap();
        assert!(!host_key_matches(&pins, &other.public_key().clone().into()));
        assert!(parse_host_keys(&["not a key".to_string()]).is_err());
        assert!(!host_key_matches(&[], &public.into()), "no pins is a don't-care");
    }

    #[tokio::test]
    async fn password_auth_tunnels_and_echoes() {
        let plan = plan("pw-A1b2C3d4-e5f6");
        let addr = spawn_server(plan.clone()).await;
        let cfg = cfg_for(addr, &plan);
        let target = NetAddr::new(crate::addr::Host::Domain("target.example".into()), 8443);

        let mut stream = connect(&cfg, &target).await.unwrap();
        stream.write_all(b"hello ssh").await.unwrap();
        let mut buf = [0u8; 9];
        tokio::time::timeout(Duration::from_secs(10), stream.read_exact(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf, b"hello ssh");

        // More than one channel window: exercises flow control.
        let payload: Vec<u8> = (0..64 * 1024).map(|i| (i % 251) as u8).collect();
        let (mut rd, mut wr) = tokio::io::split(stream);
        let expected_len = payload.len();
        let echoed = tokio::spawn(async move {
            let mut got = vec![0u8; expected_len];
            rd.read_exact(&mut got).await.unwrap();
            got
        });
        wr.write_all(&payload).await.unwrap();
        wr.flush().await.unwrap();
        let got = tokio::time::timeout(Duration::from_secs(20), echoed)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(got, payload);

        let opened = plan.opened.lock().unwrap().clone();
        assert_eq!(
            opened,
            vec![(
                "target.example".to_string(),
                8443,
                ORIGINATOR_HOST.to_string(),
                ORIGINATOR_PORT
            )]
        );
    }

    #[tokio::test]
    async fn private_key_auth_with_passphrase() {
        let plan = plan("unused-password");
        let addr = spawn_server(plan.clone()).await;
        let key = PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519)
            .unwrap();
        let passphrase = "generated-passphrase-9f2c";
        let encrypted = key
            .encrypt(&mut russh::keys::key::safe_rng(), passphrase)
            .unwrap()
            .to_openssh(LineEnding::LF)
            .unwrap()
            .to_string();

        let mut cfg = cfg_for(addr, &plan);
        cfg.password = None;
        cfg.private_key = Some(encrypted);
        cfg.private_key_passphrase = Some(passphrase.to_string());

        let target = NetAddr::new(crate::addr::Host::Domain("key.test".into()), 22);
        let mut stream = connect(&cfg, &target).await.unwrap();
        stream.write_all(b"via key").await.unwrap();
        let mut buf = [0u8; 7];
        stream.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"via key");
    }

    #[tokio::test]
    async fn pinned_host_key_mismatch_is_refused() {
        let plan = plan("pw");
        let addr = spawn_server(plan.clone()).await;
        let other = PrivateKey::random(&mut russh::keys::key::safe_rng(), Algorithm::Ed25519)
            .unwrap();
        let mut cfg = cfg_for(addr, &plan);
        cfg.host_key = vec![other.public_key().public_key_base64()];

        let target = NetAddr::new(crate::addr::Host::Domain("t.test".into()), 80);
        let err = match connect(&cfg, &target).await {
            Ok(_) => panic!("mismatching host key must not connect"),
            Err(e) => e,
        };
        assert!(err.to_string().starts_with("network: ssh:"), "{err}");
    }

    #[tokio::test]
    async fn wrong_password_is_refused() {
        let plan = plan("the-right-password");
        let addr = spawn_server(plan.clone()).await;
        let mut cfg = cfg_for(addr, &plan);
        cfg.password = Some("the-wrong-password".to_string());

        let target = NetAddr::new(crate::addr::Host::Domain("t.test".into()), 80);
        let err = match connect(&cfg, &target).await {
            Ok(_) => panic!("wrong password must not connect"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("rejected"), "{err}");
    }

    #[tokio::test]
    async fn missing_credentials_are_rejected_without_dialing() {
        let cfg = SshOut {
            server: "127.0.0.1".to_string(),
            port: 1,
            user: "tester".to_string(),
            password: None,
            private_key: None,
            private_key_passphrase: None,
            host_key: Vec::new(),
        };
        let target = NetAddr::new(crate::addr::Host::Domain("t.test".into()), 80);
        let err = match connect(&cfg, &target).await {
            Ok(_) => panic!("missing credentials must not dial"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("password or private-key"), "{err}");
    }

    #[tokio::test]
    async fn unusable_host_key_pin_is_a_config_error() {
        let plan = plan("pw");
        let mut cfg = cfg_for(
            SocketAddr::new(std::net::IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            &plan,
        );
        cfg.host_key = vec!["ssh-ed25519 not-base64!!".to_string()];
        let target = NetAddr::new(crate::addr::Host::Domain("t.test".into()), 80);
        let err = match connect(&cfg, &target).await {
            Ok(_) => panic!("a bad pin must fail before dialing"),
            Err(e) => e,
        };
        assert!(err.to_string().contains("unusable host-key"), "{err}");
    }
}