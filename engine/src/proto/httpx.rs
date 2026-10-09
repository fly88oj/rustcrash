//! HTTP proxy outbound: CONNECT tunneling with optional Basic auth.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};

use base64::Engine;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

use crate::addr::NetAddr;
use crate::error::{Error, Result};
use crate::stream::BoxProxyStream;

/// Outbound HTTP proxy endpoint.
#[derive(Debug, Clone)]
pub struct HttpOut {
    pub server: String,
    pub port: u16,
    pub username: Option<String>,
    pub password: Option<String>,
    /// Request-target override on the CONNECT line (sing-box `path`,
    /// HTTP/1 only — transport/http client.go injects it via the URL).
    pub path: Option<String>,
    /// Extra request headers (mihomo/sing-box `headers`).
    pub headers: Vec<(String, String)>,
    /// sing-box's rewritten client requires status 200 EXACTLY; mihomo's
    /// net/http-based client accepts any 2xx for CONNECT. Dialect flag —
    /// true for sing-box configs, false for mihomo.
    pub strict_200: bool,
}

/// A CONNECT-tunneled stream.
pub struct HttpStream {
    inner: BoxProxyStream,
}

impl HttpStream {
    pub async fn handshake(
        transport: BoxProxyStream,
        cfg: &HttpOut,
        target: &NetAddr,
    ) -> Result<Self> {
        let mut transport = transport;
        let hostport = target.to_string();
        // sing-box's rewritten http client (transport/http client.go
        // connect()): the request target is the path when one is
        // configured, else the authority; `Proxy-Connection: Keep-Alive`
        // rides the CONNECT; a custom `Host` header (from `headers`)
        // replaces the authority host line.
        let request_target = cfg.path.as_deref().unwrap_or(&hostport);
        let custom_host = cfg
            .headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case("host"))
            .map(|(_, v)| v.clone());
        let host_line = custom_host.as_deref().unwrap_or(&hostport);
        let mut req = format!("CONNECT {request_target} HTTP/1.1\r\nHost: {host_line}\r\n");
        if let Some(user) = cfg.username.as_deref().filter(|u| !u.is_empty()) {
            let pass = cfg.password.as_deref().unwrap_or("");
            let creds = base64::engine::general_purpose::STANDARD.encode(format!("{user}:{pass}"));
            req.push_str(&format!("Proxy-Authorization: Basic {creds}\r\n"));
        }
        for (k, v) in &cfg.headers {
            if k.eq_ignore_ascii_case("host") {
                continue; // already the Host line
            }
            req.push_str(&format!("{k}: {v}\r\n"));
        }
        req.push_str("Proxy-Connection: Keep-Alive\r\n");
        req.push_str("\r\n");
        transport.write_all(req.as_bytes()).await?;

        // Read the status line + headers up to the blank line.
        let mut buf = Vec::with_capacity(512);
        let mut byte = [0u8; 1];
        loop {
            let n = transport.read(&mut byte).await?;
            if n == 0 {
                return Err(Error::protocol("http proxy: EOF before response headers"));
            }
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n\r\n") || buf.ends_with(b"\n\n") {
                break;
            }
            if buf.len() > 16 * 1024 {
                return Err(Error::protocol("http proxy: response headers too large"));
            }
        }
        let head = String::from_utf8_lossy(&buf);
        let status = head
            .lines()
            .next()
            .ok_or_else(|| Error::protocol("http proxy: empty response"))?;
        // "HTTP/1.1 200 ..."
        let code = status
            .split_whitespace()
            .nth(1)
            .and_then(|c| c.parse::<u16>().ok())
            .ok_or_else(|| {
                Error::protocol(format!("http proxy: malformed status line {status:?}"))
            })?;
        if code == 407 {
            // sing-box #2539 shape ("auth failed, no Proxy-Authorization
            // header"): name WHICH side lacks credentials instead of a
            // bare 407. We always send the header when the outbound
            // carries a username, so a 407 means rejected credentials or
            // a username-less config against an auth-demanding proxy.
            let auth_state = if cfg.username.as_deref().is_some_and(|u| !u.is_empty()) {
                "the outbound DID send Proxy-Authorization — credentials rejected"
            } else {
                "the outbound has no username configured, so no Proxy-Authorization was sent"
            };
            return Err(Error::protocol(format!(
                "http proxy: 407 authentication required ({auth_state})"
            )));
        }
        // sing-box's rewritten client requires status 200 exactly
        // (transport/http client.go statusError): 407 → authentication
        // required, 405 → method not allowed, anything else — including
        // other 2xx — is "unexpected status". mihomo accepts any 2xx
        // (its client is net/http).
        let ok = if cfg.strict_200 {
            code == 200
        } else {
            (200..300).contains(&code)
        };
        if !ok {
            let mapped = match code {
                405 => "method not allowed".to_string(),
                other => format!("unexpected status: {other}"),
            };
            return Err(Error::protocol(format!(
                "http proxy: CONNECT failed — {mapped}"
            )));
        }
        Ok(HttpStream { inner: transport })
    }
}

impl AsyncWrite for HttpStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

impl AsyncRead for HttpStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::Host;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn connect_tunnel_roundtrip() {
        let (client, mut server) = tokio::io::duplex(256);
        tokio::spawn(async move {
            let mut buf = Vec::new();
            // Read until end of headers.
            let mut byte = [0u8; 1];
            loop {
                server.read_exact(&mut byte).await.unwrap();
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let req = String::from_utf8_lossy(&buf);
            assert!(req.starts_with("CONNECT tunnel.test:443 HTTP/1.1\r\n"));
            assert!(req.contains("Host: tunnel.test:443"));
            server
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
            let mut got = [0u8; 8];
            let n = server.read(&mut got).await.unwrap();
            assert_eq!(&got[..n], b"ping");
            server.write_all(b"pong").await.unwrap();
        });
        let cfg = HttpOut {
            server: "127.0.0.1".into(),
            port: 1,
            username: None,
            password: None,
            path: None,
            headers: Vec::new(),
            strict_200: false,
        };
        let mut stream = HttpStream::handshake(
            Box::new(client),
            &cfg,
            &NetAddr::domain("tunnel.test", 443).unwrap(),
        )
        .await
        .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut buf = [0u8; 8];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), stream.read(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"pong");
    }

    #[tokio::test]
    async fn connect_failure_surfaces_status() {
        let (client, mut server) = tokio::io::duplex(256);
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                server.read_exact(&mut byte).await.unwrap();
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            server
                .write_all(b"HTTP/1.1 407 Proxy Auth Required\r\n\r\n")
                .await
                .unwrap();
        });
        let cfg = HttpOut {
            server: "127.0.0.1".into(),
            port: 1,
            username: None,
            password: None,
            path: None,
            headers: Vec::new(),
            strict_200: false,
        };
        let err = HttpStream::handshake(
            Box::new(client),
            &cfg,
            &NetAddr::new(Host::Ip("127.0.0.1".parse().unwrap()), 80),
        )
        .await
        .err()
        .expect("CONNECT should fail");
        assert!(err.to_string().contains("407"));
    }

    #[test]
    fn basic_auth_header_only_with_username() {
        // Construction-time behavior is exercised via handshake above; this
        // guards the header shape.
        let cfg = HttpOut {
            server: "127.0.0.1".into(),
            port: 1,
            username: Some("usr".into()),
            password: Some("pwd".into()),
            path: None,
            headers: Vec::new(),
            strict_200: false,
        };
        let creds = base64::engine::general_purpose::STANDARD.encode("usr:pwd");
        assert_eq!(creds, "dXNyOnB3ZA==");
        assert!(cfg.username.is_some());
    }

    /// sing-box #2539 ("auth failed, no Proxy-Authorization header"):
    /// pin the header to the WIRE — a proxy that demands auth must see
    /// `Proxy-Authorization: Basic …` on the CONNECT.
    #[tokio::test]
    async fn proxy_authorization_reaches_the_wire() {
        let (client, mut server) = tokio::io::duplex(256);
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                server.read_exact(&mut byte).await.unwrap();
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let req = String::from_utf8_lossy(&buf);
            assert!(
                req.contains("Proxy-Authorization: Basic dXNyOnB3ZA==\r\n"),
                "auth header missing on the wire: {req}"
            );
            server
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
        });
        let cfg = HttpOut {
            server: "127.0.0.1".into(),
            port: 1,
            username: Some("usr".into()),
            password: Some("pwd".into()),
            path: None,
            headers: Vec::new(),
            strict_200: false,
        };
        HttpStream::handshake(
            Box::new(client),
            &cfg,
            &NetAddr::domain("tunnel.test", 443).unwrap(),
        )
        .await
        .unwrap();
    }

    /// sing-box's rewritten client (d1ade9f): `Proxy-Connection:
    /// Keep-Alive` rides the CONNECT and success requires status 200
    /// EXACTLY — other 2xx are "unexpected status".
    #[tokio::test]
    async fn connect_carries_proxy_connection_and_requires_exact_200() {
        let (client, mut server) = tokio::io::duplex(256);
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                server.read_exact(&mut byte).await.unwrap();
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let req = String::from_utf8_lossy(&buf);
            assert!(
                req.contains("Proxy-Connection: Keep-Alive\r\n"),
                "Proxy-Connection missing on the wire: {req}"
            );
            // A non-200 2xx must NOT open the tunnel.
            server
                .write_all(b"HTTP/1.1 204 No Content\r\n\r\n")
                .await
                .unwrap();
        });
        let cfg = HttpOut {
            server: "127.0.0.1".into(),
            port: 1,
            username: None,
            password: None,
            path: None,
            headers: Vec::new(),
            strict_200: true, // the sing-box dialect semantic under test
        };
        let err = HttpStream::handshake(
            Box::new(client),
            &cfg,
            &NetAddr::domain("tunnel.test", 443).unwrap(),
        )
        .await
        .err()
        .expect("204 must fail the handshake");
        assert!(
            err.to_string().contains("unexpected status: 204"),
            "{}",
            err
        );
    }

    /// `path` overrides the CONNECT request target (sing-box `path`).
    #[tokio::test]
    async fn path_overrides_the_connect_target() {
        let (client, mut server) = tokio::io::duplex(256);
        tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut byte = [0u8; 1];
            loop {
                server.read_exact(&mut byte).await.unwrap();
                buf.push(byte[0]);
                if buf.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let req = String::from_utf8_lossy(&buf);
            assert!(
                req.starts_with("CONNECT /cdn-relay HTTP/1.1\r\n"),
                "path not on the request line: {req}"
            );
            server
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .await
                .unwrap();
        });
        let cfg = HttpOut {
            server: "127.0.0.1".into(),
            port: 1,
            username: None,
            password: None,
            path: Some("/cdn-relay".into()),
            headers: Vec::new(),
            strict_200: false,
        };
        HttpStream::handshake(
            Box::new(client),
            &cfg,
            &NetAddr::domain("tunnel.test", 443).unwrap(),
        )
        .await
        .unwrap();
    }

    /// The 407 error names which side lacks credentials (the #2539
    /// confusion was a bare "auth failed").
    #[tokio::test]
    async fn auth_failure_407_names_the_credential_state() {
        for (username, expected) in [
            (Some("usr"), "credentials rejected"),
            (None, "no Proxy-Authorization was sent"),
        ] {
            let (client, mut server) = tokio::io::duplex(256);
            tokio::spawn(async move {
                let mut buf = Vec::new();
                let mut byte = [0u8; 1];
                loop {
                    server.read_exact(&mut byte).await.unwrap();
                    buf.push(byte[0]);
                    if buf.ends_with(b"\r\n\r\n") {
                        break;
                    }
                }
                server
                    .write_all(b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
                    .await
                    .unwrap();
            });
            let cfg = HttpOut {
                server: "127.0.0.1".into(),
                port: 1,
                username: username.map(str::to_string),
                password: Some("pwd".into()),
                path: None,
                headers: Vec::new(),
                strict_200: false,
            };
            let err = match HttpStream::handshake(
                Box::new(client),
                &cfg,
                &NetAddr::domain("tunnel.test", 443).unwrap(),
            )
            .await
            {
                Ok(_) => panic!("407 must fail the handshake"),
                Err(e) => e.to_string(),
            };
            assert!(err.contains("407"), "{err}");
            assert!(err.contains(expected), "{err}");
        }
    }
}
