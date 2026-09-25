//! `controlhttp`: upgrading an HTTP(S) connection into the Noise
//! controlbase transport — the client half of the `/ts2021` dance.
//!
//! Port of `tailscale.com/control/controlhttp` (client.go +
//! constants.go + controlhttpcommon/controlhttpcommon.go; cached at
//! `/tmp/wave10-upstream/control_controlhttp_*.go`, upstream `main`
//! as of 2026-09).
//!
//! The happy-path wire exchange (client.go:539-571): a single
//! cleartext POST to `/ts2021` carrying the Noise initiation base64'd
//! in the `X-Tailscale-Handshake` header (saving the RTT the
//! `ClientDeferred` split exists for, client.go:57-67), the server
//! answering `101 Switching Protocols` with
//! `Upgrade: tailscale-control-protocol`, and the rest of the Noise
//! handshake plus all session frames flowing over the same TCP/TLS
//! stream. The compatibility path wraps the same exchange in TLS
//! (double crypto; client.go:16-19).
//!
//! Upstream races the port-80 and port-443 legs with a 500 ms
//! fallback timer (client.go:288-305); this port tries HTTP first and
//! falls back to HTTPS on failure — the same wire, sequentially. See
//! the module docs of `super::super` (deltas).

use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::error::{Error, Result};
use crate::stream::BoxProxyStream;
use crate::transport::{tls_connect, TlsSettings};

use super::noise::{
    client_deferred, MachinePrivateKey, MachinePublicKey, NoiseConn, CURRENT_PROTOCOL_VERSION,
};

/// `serverUpgradePath` — where the protocol-switch handler lives
/// (controlhttp/constants.go:15).
pub const SERVER_UPGRADE_PATH: &str = "/ts2021";

/// `UpgradeHeaderValue` (controlhttpcommon.go:13).
pub const UPGRADE_HEADER_VALUE: &str = "tailscale-control-protocol";

/// `HandshakeHeaderName` — the request header carrying the base64
/// initial handshake payload (controlhttpcommon.go:18).
pub const HANDSHAKE_HEADER_NAME: &str = "X-Tailscale-Handshake";

/// `NoPort` sentinel — HTTPS disabled (constants.go:22). Modeled by
/// `ControlHttpDialer::https_port == None`; kept for wire parity
/// documentation.
#[allow(dead_code)]
pub const NO_PORT: &str = "none";

/// Configuration for one control dial — the wire-relevant subset of
/// `controlhttp.Dialer` (client_common.go:41-...): Hostname,
/// MachineKey, ControlKey, ProtocolVersion, HTTPPort, HTTPSPort.
#[derive(Debug, Clone)]
pub struct ControlHttpDialer {
    /// Host to connect to, without port (`Dialer.Hostname`).
    pub hostname: String,
    /// This machine's private key (`Dialer.MachineKey`).
    pub machine_key: MachinePrivateKey,
    /// The expected control-server static public key (`Dialer.ControlKey`).
    pub control_key: MachinePublicKey,
    /// Noise protocol version to negotiate (`Dialer.ProtocolVersion`).
    pub protocol_version: u16,
    /// Port for the cleartext HTTP leg (`Dialer.HTTPPort`, default 80).
    pub http_port: u16,
    /// Port for the HTTPS leg (`Dialer.HTTPSPort`, default 443;
    /// `None` = the Go `NoPort` "none" sentinel, HTTPS disabled).
    pub https_port: Option<u16>,
    /// Skip TLS certificate verification on the HTTPS leg. Upstream
    /// demotes cert errors to log lines because the Noise layer
    /// authenticates the server itself via the pinned control key
    /// (client.go:493-502); the engine keeps verification on by
    /// default.
    pub skip_cert_verify: bool,
}

impl ControlHttpDialer {
    /// Build a dialer for a control URL (`http://host[:port]` or
    /// `https://host[:port]`). An explicit port sets only that leg;
    /// `https` keeps the 80→443 fallback pair (client.go:251-263).
    pub fn from_url(
        url: &str,
        machine_key: MachinePrivateKey,
        control_key: MachinePublicKey,
    ) -> Result<Self> {
        let (scheme, host, port) = parse_control_url(url)?;
        let mut dialer = ControlHttpDialer {
            hostname: host,
            machine_key,
            control_key,
            protocol_version: CURRENT_PROTOCOL_VERSION,
            http_port: 80,
            https_port: Some(443),
            skip_cert_verify: false,
        };
        match (scheme.as_str(), port) {
            ("http", Some(p)) => {
                dialer.http_port = p;
                dialer.https_port = None; // Go: only the URL's port is hit
            }
            ("http", None) => {
                dialer.http_port = 80;
                dialer.https_port = None;
            }
            ("https", Some(p)) => {
                dialer.http_port = 80;
                dialer.https_port = Some(p);
            }
            ("https", None) => {}
            _ => return Err(Error::config(format!("control url {url:?}: unknown scheme"))),
        }
        Ok(dialer)
    }

    /// `Dial` → `dialHostOpt` (client.go:67-72, 239-340): try the
    /// cleartext HTTP leg, fall back to HTTPS. `dialURL`
    /// (client.go:346-363) is the per-leg core: fresh deferred Noise
    /// handshake, upgrade, then `continueHandshake`.
    pub async fn dial(&self) -> Result<NoiseConn<BoxProxyStream>> {
        // Port-80 leg first (client.go:290-293).
        let err80 = match self.dial_url(false).await {
            Ok(conn) => return Ok(conn),
            Err(e) => e,
        };

        // Fallback leg (client.go:296-305).
        let err443 = if let Some(port) = self.https_port {
            match self.dial_url_https(port).await {
                Ok(conn) => return Ok(conn),
                Err(e) => Some(e),
            }
        } else {
            None
        };

        Err(Error::network(format!(
            "controlhttp: all connection attempts failed (HTTP: {}, HTTPS: {})",
            err80,
            err443.map(|e: Error| e.to_string()).unwrap_or_else(|| "not tried".into()),
        )))
    }

    /// One upgrade attempt over a fresh TCP connection
    /// (`dialURL`, client.go:346-363).
    async fn dial_url(&self, tls: bool) -> Result<NoiseConn<BoxProxyStream>> {
        let port = if tls {
            self.https_port.unwrap_or(443)
        } else {
            self.http_port
        };
        let (init, cont) = client_deferred(
            &self.machine_key,
            &self.control_key,
            self.protocol_version,
        )?;
        let tcp = TcpStream::connect((self.hostname.as_str(), port))
            .await
            .map_err(|e| {
                Error::network(format!(
                    "controlhttp: connect {}:{}: {e}",
                    self.hostname, port
                ))
            })?;
        let stream: BoxProxyStream = if tls {
            let settings = TlsSettings {
                enabled: true,
                server_name: Some(self.hostname.clone()),
                skip_cert_verify: self.skip_cert_verify,
                alpn: Vec::new(),
            };
            tls_connect(Box::new(tcp), &self.hostname, &settings)
                .await
                .map_err(|e| Error::network(format!("controlhttp: tls: {e}")))?
        } else {
            Box::new(tcp)
        };
        let stream = upgrade_over(stream, &self.host_header(), &init).await?;
        cont.continue_handshake(stream)
            .await
            .map_err(|e| Error::network(format!("controlhttp: noise handshake: {e}")))
    }

    async fn dial_url_https(&self, port: u16) -> Result<NoiseConn<BoxProxyStream>> {
        let mut leg = self.clone();
        leg.https_port = Some(port);
        leg.dial_url(true).await
    }

    fn host_header(&self) -> String {
        self.hostname.clone()
    }
}

/// `tryURLUpgrade` (client.go:405-581): write the POST
/// `/ts2021` request with the three upgrade headers, read the
/// response head, require `101` (client.go:555-557) and the matching
/// `Upgrade` header (client.go:569-571), and hand back the stream
/// positioned exactly at the first post-101 Noise byte.
///
/// Generic over the stream so tests can drive it over in-memory or
/// loopback mimics; the byte-at-a-time head read never crosses into
/// the Noise bytes.
pub async fn upgrade_over<S>(mut stream: S, host: &str, init: &[u8]) -> Result<S>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let b64 = base64::engine::general_purpose::STANDARD.encode(init);
    let req = format!(
        "POST {SERVER_UPGRADE_PATH} HTTP/1.1\r\n\
         Host: {host}\r\n\
         Upgrade: {UPGRADE_HEADER_VALUE}\r\n\
         Connection: upgrade\r\n\
         {HANDSHAKE_HEADER_NAME}: {b64}\r\n\
         Content-Length: 0\r\n\
         \r\n"
    );
    stream
        .write_all(req.as_bytes())
        .await
        .map_err(|e| Error::network(format!("controlhttp: writing upgrade request: {e}")))?;

    let head = read_head(&mut stream).await?;
    let mut lines = head.split("\r\n");
    let status = lines.next().unwrap_or_default();
    if !status.contains(" 101") {
        // client.go:555-557: "unexpected HTTP response: %s"
        return Err(Error::protocol(format!(
            "controlhttp: unexpected HTTP response: {status}"
        )));
    }
    let mut ok_upgrade = false;
    for line in lines {
        let Some((k, v)) = line.split_once(':') else { continue };
        if k.eq_ignore_ascii_case("upgrade") && v.trim() == UPGRADE_HEADER_VALUE {
            ok_upgrade = true;
        }
    }
    if !ok_upgrade {
        // client.go:569-571: server switched to unexpected protocol.
        return Err(Error::protocol(
            "controlhttp: server switched to an unexpected protocol",
        ));
    }
    Ok(stream)
}

/// Read one HTTP head through `\r\n\r\n` (capped like
/// `transport::read_head`), byte-at-a-time so the stream stays
/// byte-exact for the protocol that follows.
async fn read_head<S>(stream: &mut S) -> Result<String>
where
    S: AsyncRead + Unpin,
{
    let mut buf = Vec::with_capacity(512);
    let mut byte = [0u8; 1];
    loop {
        let n = stream
            .read(&mut byte)
            .await
            .map_err(|e| Error::network(format!("controlhttp: reading response: {e}")))?;
        if n == 0 {
            return Err(Error::protocol("controlhttp: EOF before headers"));
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > 16 * 1024 {
            return Err(Error::protocol("controlhttp: response head too large"));
        }
    }
    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Parse `scheme://host[:port][/...]` into its parts.
fn parse_control_url(url: &str) -> Result<(String, String, Option<u16>)> {
    let (scheme, rest) = url
        .split_once("://")
        .ok_or_else(|| Error::config(format!("control url {url:?}: missing scheme")))?;
    let authority = rest.split('/').next().unwrap_or(rest);
    let authority = authority.split('@').next_back().unwrap_or(authority);
    let (host, port) = match authority.rsplit_once(':') {
        Some((h, p)) if p.chars().all(|c| c.is_ascii_digit()) && !p.is_empty() => {
            (h.to_string(), p.parse::<u16>().ok())
        }
        _ => (authority.to_string(), None),
    };
    // Strip IPv6 literal brackets for the tokio (host, port) dial form.
    let host = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .map(|h| h.to_string())
        .unwrap_or(host);
    if host.is_empty() {
        return Err(Error::config(format!("control url {url:?}: empty host")));
    }
    Ok((scheme.to_ascii_lowercase(), host, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::tailscale::noise::server_handshake;

    #[test]
    fn control_url_parsing() {
        let (s, h, p) = parse_control_url("https://controlplane.tailscale.com").unwrap();
        assert_eq!((s.as_str(), h.as_str(), p), ("https", "controlplane.tailscale.com", None));
        let (s, h, p) = parse_control_url("http://127.0.0.1:8080/x").unwrap();
        assert_eq!((s.as_str(), h.as_str(), p), ("http", "127.0.0.1", Some(8080)));
        let (s, h, p) = parse_control_url("https://[::1]:9443/").unwrap();
        // IPv6 literals keep their brackets-stripped host + port.
        assert_eq!((s.as_str(), p), ("https", Some(9443)));
        assert!(h.contains("::1"));
        assert!(parse_control_url("controlplane.tailscale.com").is_err());
    }

    #[test]
    fn constants_match_upstream() {
        // controlhttp/constants.go:15, controlhttpcommon.go:13,18.
        assert_eq!(SERVER_UPGRADE_PATH, "/ts2021");
        assert_eq!(UPGRADE_HEADER_VALUE, "tailscale-control-protocol");
        assert_eq!(HANDSHAKE_HEADER_NAME, "X-Tailscale-Handshake");
    }

    #[tokio::test]
    async fn ts2021_upgrade_and_noise_handshake_end_to_end() {
        let control_key = MachinePrivateKey::generate();
        let machine_key = MachinePrivateKey::generate();
        let control_pub = control_key.public();

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let key = control_key.clone();
        tokio::spawn(async move {
            let (socket, _) = listener.accept().await.expect("mimic accept");
            let (mut read_half, mut write_half) = tokio::io::split(socket);

            // Read the head.
            let mut head = Vec::new();
            loop {
                let mut b = [0u8; 1];
                use tokio::io::AsyncReadExt;
                if read_half.read_exact(&mut b).await.unwrap() == 0 {
                    panic!("eof");
                }
                head.push(b[0]);
                if head.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let head = String::from_utf8_lossy(&head).into_owned();
            assert!(head.starts_with("POST /ts2021 HTTP/1.1"), "{head}");
            assert!(head.contains("Upgrade: tailscale-control-protocol"));
            assert!(head.contains("Connection: upgrade"));
            let b64 = head
                .lines()
                .find_map(|l| l.strip_prefix("X-Tailscale-Handshake: "))
                .expect("handshake header");
            let init = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .unwrap();
            assert_eq!(init.len(), 101, "the whole initiation rides the header");

            // 101 (controlhttpserver.go:78-80).
            write_all(
                &mut write_half,
                b"HTTP/1.1 101 Switching Protocols\r\n\
                  Upgrade: tailscale-control-protocol\r\n\
                  Connection: upgrade\r\n\r\n",
            )
            .await;

            // Rejoin and run the controlbase server half with the
            // header-carried init (controlhttpserver.go:100).
            let socket = read_half.unsplit(write_half);
            let mut conn = server_handshake(socket, &key, Some(init)).await.unwrap();
            // Echo records back.
            let got = conn.recv().await.unwrap();
            conn.send(&got).await.unwrap();
        });

        let url = format!("http://{}", addr);
        let dialer = ControlHttpDialer::from_url(&url, machine_key, control_pub).unwrap();
        // The URL's explicit port is the only leg for http:// URLs.
        assert_eq!(dialer.https_port, None);
        assert_eq!(dialer.protocol_version, CURRENT_PROTOCOL_VERSION);

        let mut conn = dialer.dial().await.expect("control dial");
        assert_eq!(conn.protocol_version(), CURRENT_PROTOCOL_VERSION);
        conn.send(b"ping-over-noise").await.unwrap();
        let back = conn.recv().await.unwrap();
        assert_eq!(back, b"ping-over-noise");
    }

    async fn write_all<W: AsyncWrite + Unpin>(w: &mut W, buf: &[u8]) {
        use tokio::io::AsyncWriteExt;
        w.write_all(buf).await.unwrap();
        w.flush().await.unwrap();
    }

    #[tokio::test]
    async fn upgrade_rejects_non_101_responses() {
        // A proxy answering 200 must fail the upgrade
        // (client.go:555-557).
        let (mut a, mut b) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            a.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                .await
                .unwrap();
            // Keep the pipe open while the client reads the head.
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });
        let err = upgrade_over(&mut b, "x", &[0u8; 101]).await.unwrap_err();
        assert!(err.to_string().contains("unexpected HTTP response"));
    }

    #[tokio::test]
    async fn upgrade_rejects_wrong_upgrade_header() {
        // A 101 without Upgrade: tailscale-control-protocol fails
        // (client.go:569-571).
        let (mut a, mut b) = tokio::io::duplex(1024);
        tokio::spawn(async move {
            use tokio::io::AsyncWriteExt;
            a.write_all(
                b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n",
            )
            .await
            .unwrap();
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        });
        let err = upgrade_over(&mut b, "x", &[0u8; 101]).await.unwrap_err();
        assert!(err.to_string().contains("unexpected protocol"));
    }
}
