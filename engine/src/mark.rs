//! Process-wide outbound routing mark (mihomo `routing-mark`): every
//! socket the engine DIALS carries SO_MARK so a transparent-proxy
//! firewall can exempt the engine's own traffic from re-interception —
//! mihomo stamps its dialers the same way (adapter/dialer dialer.go
//! `setMark`). Without the mark, the firewall's `meta mark <mark>
//! return` loop-guard never matches and each relay dials straight back
//! into the tproxy/redir port: a self-relay storm that exhausts FDs in
//! seconds.
//!
//! The mark is process-wide by design (one engine per process), set
//! once at [`crate::app::Engine::build`] from the config. Zero means
//! "unmarked" and every helper degrades to the plain tokio call.

use std::io;
use std::os::fd::AsFd;
use std::sync::atomic::{AtomicU32, Ordering};

static OUTBOUND_MARK: AtomicU32 = AtomicU32::new(0);

/// Install the outbound mark (0 disables). Called once at engine start.
pub fn set(mark: u32) {
    OUTBOUND_MARK.store(mark, Ordering::Relaxed);
}

/// The currently-configured outbound mark (0 = none).
pub fn get() -> u32 {
    OUTBOUND_MARK.load(Ordering::Relaxed)
}

/// Apply the configured mark to an already-created socket. Sufficient
/// for UDP (routing decides per packet, not per connect) and for
/// accepted/established streams whose packets have not flowed yet.
/// Best-effort: without CAP_NET_ADMIN/CAP_NET_RAW the setsockopt fails
/// and the socket stays unmarked — the mark is only ever a
/// firewall-configuration concern, never a functional one.
pub fn apply<S: AsFd>(sock: &S) {
    let mark = get();
    if mark == 0 {
        return;
    }
    if let Err(e) = socket2::SockRef::from(sock).set_mark(mark) {
        tracing::debug!(target: "engine",
            "SO_MARK {mark} failed (needs CAP_NET_ADMIN): {e}");
    }
}

/// TCP connect to `host:port` with the mark applied BEFORE the SYN
/// leaves — an unmarked handshake would be re-intercepted by the
/// firewall before the mark could matter. The unmarked path (mark 0) is
/// exactly `TcpStream::connect`, resolution included; the marked path
/// resolves first (tokio lookup, same as tokio's own connect) and then
/// connects each address through a pre-marked non-blocking socket.
pub async fn tcp_connect(host: &str, port: u16) -> io::Result<tokio::net::TcpStream> {
    let mark = get();
    if mark == 0 {
        return tokio::net::TcpStream::connect((host, port)).await;
    }
    let addrs: Vec<std::net::SocketAddr> = tokio::net::lookup_host((host, port))
        .await?
        .collect();
    let mut last: Option<io::Error> = None;
    for addr in addrs {
        match marked_connect_addr(addr, mark).await {
            Ok(stream) => return Ok(stream),
            Err(e) => last = Some(e),
        }
    }
    Err(last.unwrap_or_else(|| {
        io::Error::new(io::ErrorKind::AddrNotAvailable, format!("no address for {host}:{port}"))
    }))
}

/// One pre-marked connect attempt: create the socket, stamp it, start
/// the non-blocking handshake, then wait for writability and check
/// SO_ERROR — the same completion dance tokio's own connector runs.
async fn marked_connect_addr(
    addr: std::net::SocketAddr,
    mark: u32,
) -> io::Result<tokio::net::TcpStream> {
    let domain = if addr.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::STREAM, Some(socket2::Protocol::TCP))?;
    socket.set_nonblocking(true)?;
    if let Err(e) = socket.set_mark(mark) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("SO_MARK {mark} failed (needs CAP_NET_ADMIN): {e}"),
        ));
    }
    match socket.connect(&addr.into()) {
        Ok(()) => {}
        // A non-blocking connect reports EINPROGRESS while the handshake
        // runs; anything else is a real failure for this address.
        Err(e) if e.raw_os_error() == Some(libc::EINPROGRESS) => {}
        Err(e) => return Err(e),
    }
    let stream = tokio::net::TcpStream::from_std(socket.into())?;
    stream.writable().await?;
    match stream.take_error() {
        Ok(None) => Ok(stream),
        Ok(Some(e)) => Err(e),
        Err(e) => Err(e),
    }
}

/// [`tcp_connect`] over an already-resolved address (DNS upstreams and
/// other callers that carry a SocketAddr).
pub async fn tcp_connect_addr(addr: std::net::SocketAddr) -> io::Result<tokio::net::TcpStream> {
    let mark = get();
    if mark == 0 {
        return tokio::net::TcpStream::connect(addr).await;
    }
    marked_connect_addr(addr, mark).await
}

/// UDP socket bound to an ephemeral port with the mark applied — the
/// Direct UDP relay path.
pub async fn udp_bind_ephemeral() -> io::Result<tokio::net::UdpSocket> {
    let socket = tokio::net::UdpSocket::bind("0.0.0.0:0").await?;
    apply(&socket);
    Ok(socket)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mark_store_roundtrip_and_zero_default() {
        assert_eq!(get(), 0);
        set(7894);
        assert_eq!(get(), 7894);
        set(0);
        assert_eq!(get(), 0);
    }

    #[tokio::test]
    async fn tcp_connect_unmarked_matches_plain_connect() {
        // With no mark configured the helper is a plain loopback
        // connect (an established stream, not an error).
        set(0);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let _stream = tcp_connect("127.0.0.1", addr.port()).await.unwrap();
    }
}
