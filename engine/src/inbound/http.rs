//! HTTP proxy inbound: CONNECT tunnels and absolute-form requests (the
//! request itself is replayed into the tunnel).

use std::net::SocketAddr;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use crate::addr::{Host, NetAddr};
use crate::error::{Error, Result};
use crate::inbound::{ListenerConfig, SharedRelay, TcpMeta};
use crate::stream::BoxProxyStream;

/// Serve an HTTP proxy listener; returns the bound address.
pub async fn serve(cfg: &ListenerConfig, relay: SharedRelay) -> Result<SocketAddr> {
    let listener = TcpListener::bind((cfg.bind.as_str(), cfg.port))
        .await
        .map_err(|e| Error::network(format!("bind {}:{}: {e}", cfg.bind, cfg.port)))?;
    let addr = listener.local_addr().map_err(|e| Error::network(e.to_string()))?;
    let tag = cfg.tag.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                continue;
            };
            let _ = stream.set_nodelay(true);
            let port = stream.local_addr().map(|a| a.port()).ok();
            let relay = relay.clone();
            let tag = tag.clone();
            tokio::spawn(async move {
                if let Err(e) = handle(Box::new(stream), peer, tag, port, "http", relay).await {
                    tracing::debug!(target: "engine", "http-in {peer}: {e}");
                }
            });
        }
    });
    Ok(addr)
}

/// Drive one HTTP proxy connection over an established stream.
pub async fn handle_stream(
    stream: BoxProxyStream,
    peer: SocketAddr,
    tag: String,
    inbound_port: Option<u16>,
    inbound_kind: &'static str,
    relay: SharedRelay,
) -> Result<()> {
    handle(stream, peer, tag, inbound_port, inbound_kind, relay).await
}

async fn handle(
    mut stream: BoxProxyStream,
    peer: SocketAddr,
    tag: String,
    inbound_port: Option<u16>,
    inbound_kind: &'static str,
    relay: SharedRelay,
) -> Result<()> {
    // Read the request head (bounded).
    let head = crate::transport::read_head(&mut stream, "http-in").await?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().unwrap_or_default().to_string();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or_default().to_ascii_uppercase();
    let uri = parts.next().unwrap_or_default().to_string();

    if method == "CONNECT" {
        let target = parse_hostport(&uri)?;
        stream
            .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
            .await?;
        relay.handle_tcp(
            TcpMeta {
                target,
                source: peer,
                inbound: tag,
                inbound_port,
                inbound_kind,
            },
            Box::new(stream),
        );
        Ok(())
    } else {
        // Absolute-form proxying: rewrite to origin-form and replay.
        let target = parse_absolute_uri(&uri)?;
        let after_scheme = uri.split_once("://").map(|(_, r)| r).unwrap_or(uri.as_str());
        let origin_path = match after_scheme.find('/') {
            Some(i) => &after_scheme[i..],
            None => "/",
        }
        .to_string();
        let mut rebuilt = format!("{method} {origin_path} HTTP/1.1\r\n");
        for line in lines {
            if line.is_empty() {
                continue;
            }
            // Drop proxy-scoped headers.
            let lower = line.to_ascii_lowercase();
            if lower.starts_with("proxy-connection:") || lower.starts_with("proxy-authorization:") {
                continue;
            }
            rebuilt.push_str(line);
            rebuilt.push_str("\r\n");
        }
        rebuilt.push_str("\r\n");
        // Plain HTTP proxying relays the origin's response verbatim — no
        // intermediate 200 here (that would shadow the real response).
        relay.handle_tcp(
            TcpMeta {
                target,
                source: peer,
                inbound: tag,
                inbound_port,
                inbound_kind,
            },
            Box::new(crate::inbound::PrependStream::new(
                stream,
                rebuilt.into_bytes(),
            )),
        );
        Ok(())
    }
}

/// `host:port` (port defaults to 80).
pub fn parse_hostport(s: &str) -> Result<NetAddr> {
    let (host, port) = split_hostport(s, 80)?;
    Ok(NetAddr::new(host, port))
}

fn split_hostport(s: &str, default_port: u16) -> Result<(Host, u16)> {
    if let Some(rest) = s.strip_prefix('[') {
        // [v6]:port
        let (v6, port) = rest
            .split_once(']')
            .ok_or_else(|| Error::protocol(format!("bad address {s:?}")))?;
        let port = port
            .strip_prefix(':')
            .map(|p| p.parse().unwrap_or(default_port))
            .unwrap_or(default_port);
        let host: std::net::IpAddr = v6
            .parse()
            .map_err(|_| Error::protocol(format!("bad ipv6 {v6:?}")))?;
        Ok((Host::Ip(host), port))
    } else {
        match s.rsplit_once(':') {
            Some((h, p)) => {
                let port = p.parse().unwrap_or(default_port);
                Ok((Host::parse(h)?, port))
            }
            None => Ok((Host::parse(s)?, default_port)),
        }
    }
}

fn parse_absolute_uri(uri: &str) -> Result<NetAddr> {
    let rest = uri
        .split_once("://")
        .map(|(_, r)| r)
        .unwrap_or(uri);
    // authority is up to the first '/', '?' or '#'
    let authority = rest
        .split(['/', '?', '#'])
        .next()
        .unwrap_or_default();
    let (host, port) = split_hostport(authority, 80)?;
    Ok(NetAddr::new(host, port))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbound::RelayHandler;
    use crate::inbound::{ListenerConfig, ListenerKind};
    use tokio::io::AsyncReadExt;
    use std::sync::Arc;
    use tokio::sync::mpsc;

    struct Capture(std::sync::Mutex<Vec<NetAddr>>);

    impl RelayHandler for Capture {
        fn handle_tcp(self: std::sync::Arc<Self>, meta: TcpMeta, mut client: BoxProxyStream) {
            self.0.lock().unwrap().push(meta.target.clone());
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut all = Vec::new();
                let mut buf = [0u8; 128];
                loop {
                    let n = tokio::time::timeout(
                        std::time::Duration::from_millis(300),
                        client.read(&mut buf),
                    )
                    .await;
                    match n {
                        Ok(Ok(0)) | Err(_) => break,
                        Ok(Ok(n)) => all.extend_from_slice(&buf[..n]),
                        Ok(Err(_)) => break,
                    }
                    if all.len() > 1024 {
                        break;
                    }
                }
                let _ = client.write_all(&all).await;
            });
        }

        fn handle_udp(
            self: std::sync::Arc<Self>,
            _: SocketAddr,
            _: String,
            _: mpsc::Receiver<(NetAddr, Vec<u8>)>,
            _: mpsc::Sender<(NetAddr, Vec<u8>)>,
        ) {
        }
    }

    #[tokio::test]
    async fn connect_tunnel() {
        let cfg = ListenerConfig {
            tag: "t".into(),
            bind: "127.0.0.1".into(),
            port: 0,
            kind: ListenerKind::Http,
        };
        let capture = Arc::new(Capture(std::sync::Mutex::new(vec![])));
        let bound = serve(&cfg, capture.clone()).await.unwrap();
        let mut c = tokio::net::TcpStream::connect(bound).await.unwrap();
        c.write_all(b"CONNECT site.test:443 HTTP/1.1\r\nHost: site.test:443\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 64];
        let n = c.read(&mut buf).await.unwrap();
        assert!(buf[..n].starts_with(b"HTTP/1.1 200"));
        c.write_all(b"raw-tunnel-data").await.unwrap();
        let mut got = vec![0u8; 32];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), c.read(&mut got))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&got[..n], b"raw-tunnel-data");
        assert_eq!(
            capture.0.lock().unwrap()[0].host,
            Host::Domain("site.test".into())
        );
    }

    #[tokio::test]
    async fn absolute_form_replayed() {
        let cfg = ListenerConfig {
            tag: "t".into(),
            bind: "127.0.0.1".into(),
            port: 0,
            kind: ListenerKind::Http,
        };
        let capture = Arc::new(Capture(std::sync::Mutex::new(vec![])));
        let bound = serve(&cfg, capture.clone()).await.unwrap();
        let mut c = tokio::net::TcpStream::connect(bound).await.unwrap();
        c.write_all(b"GET http://plain.test/path?q=1 HTTP/1.1\r\nHost: plain.test\r\n\r\nmore")
            .await
            .unwrap();
        let mut got = vec![0u8; 128];
        let n = tokio::time::timeout(std::time::Duration::from_secs(5), c.read(&mut got))
            .await
            .unwrap()
            .unwrap();
        let echoed = String::from_utf8_lossy(&got[..n]).to_string();
        assert!(echoed.contains("GET /path?q=1 HTTP/1.1"));
        assert!(echoed.contains("Host: plain.test"));
        assert!(echoed.ends_with("more"));
        assert_eq!(
            capture.0.lock().unwrap()[0].host,
            Host::Domain("plain.test".into())
        );
    }

    #[test]
    fn hostport_parsing() {
        let a = parse_hostport("example.com:8080").unwrap();
        assert_eq!(a.host, Host::Domain("example.com".into()));
        assert_eq!(a.port, 8080);
        let a = parse_hostport("example.com").unwrap();
        assert_eq!(a.port, 80);
        let a = parse_hostport("[::1]:443").unwrap();
        assert_eq!(a.host, Host::Ip("::1".parse().unwrap()));
        assert_eq!(a.port, 443);
        assert!(parse_hostport("bad host").is_err());
    }
}
