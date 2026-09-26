//! Mixed inbound: peeks the first byte to route each connection to the
//! SOCKS5 or HTTP handler.

use std::net::SocketAddr;

use tokio::io::AsyncReadExt;
use tokio::net::TcpListener;

use crate::error::{Error, Result};
use crate::inbound::{ListenerConfig, SharedRelay};
use crate::stream::BoxProxyStream;

/// Serve a mixed listener; returns the bound address.
pub async fn serve(
    cfg: &ListenerConfig,
    authentication: &[(String, String)],
    relay: SharedRelay,
) -> Result<SocketAddr> {
    let listener = TcpListener::bind((cfg.bind.as_str(), cfg.port))
        .await
        .map_err(|e| crate::inbound::bind_failure("mixed", format!("{}:{}", cfg.bind, cfg.port), e))?;
    let addr = listener.local_addr().map_err(|e| Error::network(e.to_string()))?;
    let tag = cfg.tag.clone();
    let authentication = authentication.to_vec();
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                continue;
            };
            let _ = stream.set_nodelay(true);
            let relay = relay.clone();
            let tag = tag.clone();
            let authentication = authentication.clone();
            tokio::spawn(async move {
                if let Err(e) = route(stream, peer, tag, authentication, relay).await {
                    tracing::debug!(target: "engine", "mixed {peer}: {e}");
                }
            });
        }
    });
    Ok(addr)
}

async fn route(
    mut stream: tokio::net::TcpStream,
    peer: SocketAddr,
    tag: String,
    authentication: Vec<(String, String)>,
    relay: SharedRelay,
) -> Result<()> {
    let inbound_port = stream.local_addr().map(|a| a.port()).ok();
    let mut first = [0u8; 1];
    stream.read_exact(&mut first).await?;
    let stream: BoxProxyStream = Box::new(crate::inbound::PrependStream::new(
        Box::new(stream),
        first.to_vec(),
    ));
    match first[0] {
        0x05 => {
            crate::inbound::socks::handle_stream(
                stream,
                peer,
                tag,
                inbound_port,
                "mixed",
                authentication,
                relay,
            )
            .await
        }
        b'C' | b'G' | b'H' | b'P' | b'D' | b'O' | b'T' | b'U' | b'c' | b'g' | b'h' | b'p' | b'd' | b'o' | b't' | b'u' => {
            crate::inbound::http::handle_stream(
                stream,
                peer,
                tag,
                inbound_port,
                "mixed",
                authentication,
                relay,
            )
            .await
        }
        other => Err(Error::protocol(format!(
            "mixed: unrecognized first byte {other:#x}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::NetAddr;
    use crate::inbound::{ListenerKind, RelayHandler, TcpMeta};
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;
    use tokio::sync::mpsc;

    struct Capture(std::sync::Mutex<Vec<NetAddr>>);

    impl RelayHandler for Capture {
        fn handle_tcp(self: std::sync::Arc<Self>, meta: TcpMeta, mut client: BoxProxyStream) {
            self.0.lock().unwrap().push(meta.target.clone());
            tokio::spawn(async move {
                use tokio::io::AsyncReadExt;
                let mut buf = [0u8; 64];
                let _ = client.read(&mut buf).await;
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
    async fn dispatches_socks_and_http() {
        let cfg = ListenerConfig {
            tag: "m".into(),
            bind: "127.0.0.1".into(),
            port: 0,
            kind: ListenerKind::Mixed,
        };
        let capture = Arc::new(Capture(std::sync::Mutex::new(vec![])));
        let bound = serve(&cfg, &[], capture.clone()).await.unwrap();

        // SOCKS5 greeting goes down the socks path.
        let mut c = tokio::net::TcpStream::connect(bound).await.unwrap();
        c.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut r = [0u8; 2];
        c.read_exact(&mut r).await.unwrap();
        assert_eq!(&r, &[0x05, 0x00]);

        // An HTTP CONNECT goes down the http path.
        let mut c = tokio::net::TcpStream::connect(bound).await.unwrap();
        c.write_all(b"CONNECT h.test:81 HTTP/1.1\r\nHost: h.test:81\r\n\r\n")
            .await
            .unwrap();
        let mut buf = vec![0u8; 64];
        let n = c.read(&mut buf).await.unwrap();
        assert!(buf[..n].starts_with(b"HTTP/1.1 200"));
    }

    #[tokio::test]
    async fn second_instance_bind_failure_names_the_old_one() {
        // Migration residue (the "both RUNNING" case): a second engine
        // starting while the old instance (ShellCrash/CrashCore or a
        // previous engine) still holds the port must fail with a message
        // that NAMES the likely cause and the stop command — the bare
        // "Address already in use (os error 98)" names nobody.
        let holder = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = holder.local_addr().unwrap().port();
        let cfg = ListenerConfig {
            tag: "m".into(),
            bind: "127.0.0.1".into(),
            port,
            kind: ListenerKind::Mixed,
        };
        let capture = Arc::new(Capture(std::sync::Mutex::new(vec![])));
        let err = serve(&cfg, &[], capture).await.unwrap_err().to_string();
        assert!(err.contains("already in use"), "{err}");
        assert!(err.contains("ShellCrash"), "{err}");
        assert!(err.contains("start.sh stop"), "{err}");
        assert!(err.contains("crash start stop"), "{err}");
        assert!(err.contains("127.0.0.1"), "{err}");
    }
}
