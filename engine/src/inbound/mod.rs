//! Inbound listeners: mixed/socks/http/redir/tproxy plus the DNS server.
//!
//! Inbounds parse client protocol, recover the intended destination, and
//! hand (target, stream) pairs to the engine through [`RelayHandler`].

pub mod http;
pub mod mixed;
pub mod proxy_server;
pub mod redir;
pub mod socks;
pub mod tproxy;
pub mod tun;

use std::net::SocketAddr;
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::addr::NetAddr;
use crate::error::Result;
use crate::stream::BoxProxyStream;

/// One inbound listener from the config.
#[derive(Debug, Clone)]
pub struct ListenerConfig {
    pub tag: String,
    pub bind: String,
    pub port: u16,
    pub kind: ListenerKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ListenerKind {
    /// SOCKS5 (with UDP associate).
    Socks,
    /// HTTP CONNECT proxy.
    Http,
    /// Port-detects SOCKS5 vs HTTP per connection.
    Mixed,
    /// Linux NAT REDIRECT target (TCP).
    Redir,
    /// Linux TPROXY target (TCP + UDP).
    Tproxy,
}

impl ListenerKind {
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "socks" => Ok(ListenerKind::Socks),
            "http" => Ok(ListenerKind::Http),
            "mixed" => Ok(ListenerKind::Mixed),
            "redir" | "redirect" => Ok(ListenerKind::Redir),
            "tproxy" => Ok(ListenerKind::Tproxy),
            // sing-box's tun inbound is a real TUN device, not tproxy —
            // remapping it silently would change semantics.
            "tun" => Err(crate::error::Error::config(
                "the tun inbound has no listen port; declare it via the config's \
                 tun section instead (both dialects parse it into TunConfig)",
            )),
            other => Err(crate::error::Error::config(format!(
                "unsupported inbound {other:?} (supported: mixed, socks, http, redir, tproxy)"
            ))),
        }
    }

    pub fn name(&self) -> &'static str {
        match self {
            ListenerKind::Socks => "socks",
            ListenerKind::Http => "http",
            ListenerKind::Mixed => "mixed",
            ListenerKind::Redir => "redir",
            ListenerKind::Tproxy => "tproxy",
        }
    }

}

/// Metadata for one relayed TCP connection.
#[derive(Debug, Clone)]
pub struct TcpMeta {
    pub target: NetAddr,
    pub source: SocketAddr,
    pub inbound: String,
    /// Listener's local port (IN-PORT rules).
    pub inbound_port: Option<u16>,
    /// Listener kind name (mixed/socks/http/redir/tproxy) for IN-TYPE.
    pub inbound_kind: &'static str,
}

/// The engine's entry points, handed to every listener.
pub trait RelayHandler: Send + Sync + 'static {
    /// Relay a TCP connection (spawns internally; must not block). The
    /// Arc receiver lets impls spawn tasks that own the engine.
    fn handle_tcp(self: Arc<Self>, meta: TcpMeta, client: BoxProxyStream);

    /// Open a UDP relay session: the inbound feeds uplink datagrams and
    /// drains downlink datagrams until both channels close.
    fn handle_udp(
        self: Arc<Self>,
        source: SocketAddr,
        inbound: String,
        uplink: mpsc::Receiver<(NetAddr, Vec<u8>)>,
        downlink: mpsc::Sender<(NetAddr, Vec<u8>)>,
    );
}

pub type SharedRelay = Arc<dyn RelayHandler>;

/// Bind every configured listener; returns the bound addresses (for logs
/// and port-echo tests).
pub async fn spawn_all(
    listeners: &[ListenerConfig],
    relay: SharedRelay,
) -> Result<Vec<(String, SocketAddr)>> {
    let mut out = Vec::new();
    for l in listeners {
        let addr = match l.kind {
            ListenerKind::Socks => socks::serve(l, relay.clone()).await?,
            ListenerKind::Http => http::serve(l, relay.clone()).await?,
            ListenerKind::Mixed => mixed::serve(l, relay.clone()).await?,
            ListenerKind::Redir => redir::serve(l, relay.clone()).await?,
            ListenerKind::Tproxy => tproxy::serve(l, relay.clone()).await?,
        };
        out.push((l.tag.clone(), addr));
    }
    Ok(out)
}

/// A stream wrapper that replays captured bytes before the live stream
/// (used when an HTTP proxy request itself must ride the tunnel).
pub struct PrependStream {
    inner: BoxProxyStream,
    pending: Vec<u8>,
}

impl PrependStream {
    pub fn new(inner: BoxProxyStream, pending: Vec<u8>) -> Self {
        PrependStream { inner, pending }
    }
}

impl tokio::io::AsyncRead for PrependStream {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        use std::task::Poll;
        if !self.pending.is_empty() {
            let n = self.pending.len().min(buf.remaining());
            buf.put_slice(&self.pending[..n]);
            self.pending.drain(..n);
            return Poll::Ready(Ok(()));
        }
        std::pin::Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for PrependStream {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listener_kind_parsing() {
        assert_eq!(ListenerKind::parse("mixed").unwrap(), ListenerKind::Mixed);
        assert_eq!(ListenerKind::parse("tproxy").unwrap(), ListenerKind::Tproxy);
        assert_eq!(ListenerKind::parse("redirect").unwrap(), ListenerKind::Redir);
        // A tun device has no listen port — it is declared via the
        // config's tun section, so the kind parser points there.
        let err = ListenerKind::parse("tun").unwrap_err().to_string();
        assert!(err.contains("tun section"), "{err}");
        assert!(ListenerKind::parse("tun-socket").is_err());
    }

    #[tokio::test]
    async fn prepend_stream_replays_then_passes_through() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (mut a, b) = tokio::io::duplex(64);
        a.write_all(b"live").await.unwrap();
        let mut s = PrependStream::new(Box::new(b), b"pending".to_vec());
        let mut buf = vec![0u8; 7];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"pending");
        let mut buf = vec![0u8; 4];
        s.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"live");
    }
}
