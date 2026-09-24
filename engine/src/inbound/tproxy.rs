//! TPROXY inbound (Linux): transparent TCP listener and UDP interception
//! with `IP_TRANSPARENT` + `IP_RECVORIGDSTADDR`.

use std::net::SocketAddr;
use std::os::fd::AsRawFd;
use std::sync::Arc;

use socket2::{Protocol, SockRef, Socket};
use tokio::sync::mpsc;

use crate::addr::{NetAddr};
use crate::error::{Error, Result};
use crate::inbound::{ListenerConfig, SharedRelay, TcpMeta};

/// Serve a tproxy listener (TCP + UDP); returns the bound TCP address.
pub async fn serve(cfg: &ListenerConfig, relay: SharedRelay) -> Result<SocketAddr> {
    let bind_ip: std::net::IpAddr = cfg
        .bind
        .parse()
        .map_err(|_| Error::config(format!("bad tproxy bind {:?}", cfg.bind)))?;

    // TCP: transparent listener; accepted sockets inherit the original
    // destination as their local address.
    let tcp = TcpTransparentListener::bind(bind_ip, cfg.port).await?;
    let bound = tcp.local_addr().await?;
    let port = bound.port();

    // UDP: single transparent socket receiving (data, src, orig-dst).
    let udp = UdpTransparentSocket::bind(bind_ip, cfg.port).await?;

    let tag = cfg.tag.clone();
    let relay_tcp = relay.clone();
    tokio::spawn(async move {
        loop {
            match tcp.accept().await {
                Ok((stream, peer, target)) => {
                    let _ = stream.set_nodelay(true);
                    relay_tcp.clone().handle_tcp(
                        TcpMeta {
                            target,
                            source: peer,
                            inbound: tag.clone(),
                            inbound_port: Some(port),
                            inbound_kind: "tproxy",
                        },
                        Box::new(stream),
                    );
                }
                Err(e) => {
                    tracing::warn!(target: "engine", "tproxy tcp accept: {e}");
                }
            }
        }
    });

    let tag_udp = cfg.tag.clone();
    tokio::spawn(async move {
        if let Err(e) = udp_pump(udp, relay, tag_udp).await {
            tracing::warn!(target: "engine", "tproxy udp: {e}");
        }
    });

    Ok(bound)
}

/// A TCP listener marked transparent.
struct TcpTransparentListener {
    inner: tokio::net::TcpListener,
}

impl TcpTransparentListener {
    async fn bind(ip: std::net::IpAddr, port: u16) -> Result<Self> {
        let domain = if ip.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let socket = Socket::new(domain, socket2::Type::STREAM, Some(Protocol::TCP))
            .map_err(|e| Error::network(format!("tproxy socket: {e}")))?;
        socket
            .set_reuse_port(true)
            .map_err(|e| Error::network(format!("tproxy reuse_port: {e}")))?;
        set_transparent(&SockRef::from(&socket), ip.is_ipv4())?;
        let addr = SocketAddr::new(ip, port);
        socket
            .bind(&addr.into())
            .map_err(|e| Error::network(format!("tproxy bind {addr}: {e}")))?;
        socket
            .listen(1024)
            .map_err(|e| Error::network(format!("tproxy listen: {e}")))?;
        socket
            .set_nonblocking(true)
            .map_err(|e| Error::network(format!("tproxy nonblocking: {e}")))?;
        let inner = tokio::net::TcpListener::from_std(socket.into())?;
        Ok(TcpTransparentListener { inner })
    }

    async fn local_addr(&self) -> Result<SocketAddr> {
        self.inner
            .local_addr()
            .map_err(|e| Error::network(e.to_string()))
    }

    async fn accept(&self) -> Result<(tokio::net::TcpStream, SocketAddr, NetAddr)> {
        let (stream, peer) = self
            .inner
            .accept()
            .await
            .map_err(|e| Error::network(e.to_string()))?;
        // The accepted socket's local address IS the original destination.
        let local = stream
            .local_addr()
            .map_err(|e| Error::network(e.to_string()))?;
        // Replies must also be able to leave from the transparent address.
        set_transparent(&SockRef::from(&stream), peer.is_ipv4())?;
        Ok((stream, peer, NetAddr::ip(local.ip(), local.port())))
    }
}

/// A UDP socket marked transparent with orig-dst delivery.
struct UdpTransparentSocket {
    inner: tokio::net::UdpSocket,
    is_v4: bool,
}

impl UdpTransparentSocket {
    async fn bind(ip: std::net::IpAddr, port: u16) -> Result<Self> {
        let domain = if ip.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let socket = Socket::new(domain, socket2::Type::DGRAM, Some(Protocol::UDP))
            .map_err(|e| Error::network(format!("tproxy udp socket: {e}")))?;
        socket
            .set_reuse_port(true)
            .map_err(|e| Error::network(format!("tproxy udp reuse_port: {e}")))?;
        set_transparent(&SockRef::from(&socket), ip.is_ipv4())?;
        set_recv_orig_dst(&SockRef::from(&socket), ip.is_ipv4())?;
        let addr = SocketAddr::new(ip, port);
        socket
            .bind(&addr.into())
            .map_err(|e| Error::network(format!("tproxy udp bind {addr}: {e}")))?;
        socket
            .set_nonblocking(true)
            .map_err(|e| Error::network(format!("tproxy udp nonblocking: {e}")))?;
        let inner = tokio::net::UdpSocket::from_std(socket.into())?;
        Ok(UdpTransparentSocket {
            inner,
            is_v4: ip.is_ipv4(),
        })
    }
}

fn set_transparent(sock: &SockRef<'_>, v4: bool) -> Result<()> {
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            if v4 { libc::SOL_IP } else { libc::SOL_IPV6 },
            if v4 {
                libc::IP_TRANSPARENT
            } else {
                libc::IPV6_TRANSPARENT
            },
            &1i32 as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(Error::network(format!(
            "IP_TRANSPARENT failed (needs CAP_NET_ADMIN): {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

fn set_recv_orig_dst(sock: &SockRef<'_>, v4: bool) -> Result<()> {
    let opt = if v4 {
        libc::IP_RECVORIGDSTADDR
    } else {
        libc::IPV6_RECVORIGDSTADDR
    };
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            if v4 { libc::SOL_IP } else { libc::SOL_IPV6 },
            opt,
            &1i32 as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        )
    };
    if rc != 0 {
        return Err(Error::network(format!(
            "RECVORIGDSTADDR failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// One received datagram with its original destination.
struct Intercepted {
    data: Vec<u8>,
    src: SocketAddr,
    orig_dst: SocketAddr,
}

fn recvmsg_intercepted(fd: std::os::fd::RawFd, buf: &mut [u8], is_v4: bool) -> Result<Intercepted> {
    let mut iov = libc::iovec {
        iov_base: buf.as_mut_ptr() as *mut libc::c_void,
        iov_len: buf.len(),
    };
    // Control buffer sized for one sockaddr (in_pktinfo or in6_pktinfo).
    let mut control = [0u8; 128];
    let mut name: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_name = &mut name as *mut _ as *mut libc::c_void;
    msg.msg_namelen = std::mem::size_of::<libc::sockaddr_storage>() as libc::socklen_t;
    msg.msg_iov = &mut iov;
    msg.msg_iovlen = 1;
    msg.msg_control = control.as_mut_ptr() as *mut libc::c_void;
    // glibc types this as size_t, musl as socklen_t — infer per target.
    msg.msg_controllen = control.len() as _;
    let n = unsafe { libc::recvmsg(fd, &mut msg, libc::MSG_DONTWAIT) };
    if n < 0 {
        return Err(Error::network(std::io::Error::last_os_error().to_string()));
    }
    let src = storage_to_addr(&name)
        .ok_or_else(|| Error::network("tproxy udp: no source address"))?;
    let dst = parse_orig_dst(&control, msg.msg_controllen as usize, is_v4)?;
    Ok(Intercepted {
        data: buf[..n as usize].to_vec(),
        src,
        orig_dst: dst,
    })
}

fn storage_to_addr(s: &libc::sockaddr_storage) -> Option<SocketAddr> {
    match s.ss_family as libc::c_int {
        libc::AF_INET => unsafe {
            let a: &libc::sockaddr_in = &*(s as *const _ as *const libc::sockaddr_in);
            Some(SocketAddr::new(
                std::net::IpAddr::V4(u32::from_be(a.sin_addr.s_addr).into()),
                u16::from_be(a.sin_port),
            ))
        },
        libc::AF_INET6 => unsafe {
            let a: &libc::sockaddr_in6 = &*(s as *const _ as *const libc::sockaddr_in6);
            Some(SocketAddr::new(a.sin6_addr.s6_addr.into(), u16::from_be(a.sin6_port)))
        },
        _ => None,
    }
}

/// cmsg type delivered by `IP_RECVORIGDSTADDR` (aliased in the kernel
/// headers; the libc crate does not export it).
pub const IP_ORIGINAL_DST: libc::c_int = 20;
pub const IPV6_ORIGDSTADDR: libc::c_int = 74;

/// Walk cmsgs for the original-destination sockaddr (address AND port).
fn parse_orig_dst(control: &[u8], len: usize, is_v4: bool) -> Result<SocketAddr> {
    let mut off = 0usize;
    while off + std::mem::size_of::<libc::cmsghdr>() <= len {
        let hdr =
            unsafe { &*(control.as_ptr().add(off) as *const libc::cmsghdr) };
        let data_off = off + std::mem::size_of::<libc::cmsghdr>();
        let data_len = hdr.cmsg_len.saturating_sub(std::mem::size_of::<libc::cmsghdr>());
        if off + hdr.cmsg_len > len || data_off + data_len > control.len() {
            break;
        }
        let data = &control[data_off..data_off + data_len];
        if is_v4
            && hdr.cmsg_level == libc::SOL_IP
            && hdr.cmsg_type as libc::c_int == IP_ORIGINAL_DST
        {
            let sa = unsafe { &*(data.as_ptr() as *const libc::sockaddr_in) };
            return Ok(SocketAddr::new(
                std::net::IpAddr::V4(u32::from_be(sa.sin_addr.s_addr).into()),
                u16::from_be(sa.sin_port),
            ));
        }
        if !is_v4
            && hdr.cmsg_level == libc::SOL_IPV6
            && hdr.cmsg_type as libc::c_int == IPV6_ORIGDSTADDR
        {
            let sa = unsafe { &*(data.as_ptr() as *const libc::sockaddr_in6) };
            return Ok(SocketAddr::new(
                sa.sin6_addr.s6_addr.into(),
                u16::from_be(sa.sin6_port),
            ));
        }
        off += hdr.cmsg_len;
    }
    Err(Error::network("tproxy udp: no orig-dst cmsg"))
}

/// UDP interception loop: every (src, orig-dst) pair becomes an engine
/// session; replies are sent from a transparent socket bound to orig-dst.
async fn udp_pump(sock: UdpTransparentSocket, relay: SharedRelay, tag: String) -> Result<()> {
    let is_v4 = sock.is_v4;
    // The tokio UdpSocket already registers with the runtime's epoll
    // instance — wrapping it in another AsyncFd double-registers (EEXIST).
    // Use its own readiness API and drain with non-blocking recvmsg.
    let io = sock.inner;
    // Sessions keyed by (src, orig-dst).
    type SessionMap =
        std::collections::HashMap<(SocketAddr, SocketAddr), mpsc::Sender<(NetAddr, Vec<u8>)>>;
    let sessions: Arc<tokio::sync::Mutex<SessionMap>> =
        Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new()));

    loop {
        let mut buf = vec![0u8; 65536];
        let fd = io.as_raw_fd();
        match recvmsg_intercepted(fd, &mut buf, is_v4) {
            Ok(pkt) => {
                let key = (pkt.src, pkt.orig_dst);
                let mut table = sessions.lock().await;
                let sender = match table.get(&key) {
                    Some(s) => s.clone(),
                    None => {
                        let (up_tx, up_rx) = mpsc::channel::<(NetAddr, Vec<u8>)>(64);
                        let (down_tx, mut down_rx) = mpsc::channel::<(NetAddr, Vec<u8>)>(64);
                        relay.clone().handle_udp(
                            pkt.src,
                            tag.clone(),
                            up_rx,
                            down_tx,
                        );
                        // Reply pump: sends from a transparent socket
                        // bound to the original destination so the client
                        // sees the answer coming from where it sent.
                        let orig_dst = pkt.orig_dst;
                        tokio::spawn(async move {
                            while let Some((_from, data)) = down_rx.recv().await {
                                if let Err(e) = send_from_transparent(orig_dst, &data).await {
                                    tracing::debug!(target: "engine", "tproxy reply: {e}");
                                    break;
                                }
                            }
                        });
                        table.insert(key, up_tx.clone());
                        // Session GC: drop the entry once the engine closed
                        // the uplink (idle sessions expire server-side).
                        let sessions_gc = sessions.clone();
                        let key_clone = key;
                        let up_tx_watch = up_tx.clone();
                        tokio::spawn(async move {
                            while !up_tx_watch.is_closed() {
                                tokio::time::sleep(std::time::Duration::from_secs(30)).await;
                            }
                            sessions_gc.lock().await.remove(&key_clone);
                        });
                        up_tx
                    }
                };
                let target = NetAddr::ip(pkt.orig_dst.ip(), pkt.orig_dst.port());
                let _ = sender.try_send((target, pkt.data));
            }
            Err(e) => {
                let text = e.to_string();
                if text.contains("EAGAIN") || text.contains("WouldBlock") || text.contains("os error 11") {
                    // Socket drained — wait for the next readiness edge.
                    io.readable().await?;
                } else {
                    return Err(e);
                }
            }
        }
    }
}

/// Send a datagram with source = orig_dst (transparent).
async fn send_from_transparent(orig_dst: SocketAddr, data: &[u8]) -> Result<()> {
    // A dedicated socket per destination preserves the illusion; pooling
    // would be nicer but v1 keeps it simple (bind per send is expensive —
    // cache in the caller instead).
    let sock = Socket::new(
        if orig_dst.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        },
        socket2::Type::DGRAM,
        Some(Protocol::UDP),
    )
    .map_err(|e| Error::network(e.to_string()))?;
    set_transparent(&SockRef::from(&sock), orig_dst.is_ipv4())?;
    // Binding TO the original destination is exactly what IP_TRANSPARENT
    // permits — the reply then leaves from the address the client dialed.
    sock.bind(&orig_dst.into())
        .map_err(|e| Error::network(format!("tproxy reply bind {orig_dst}: {e}")))?;
    sock.set_nonblocking(true)
        .map_err(|e| Error::network(e.to_string()))?;
    let udp = tokio::net::UdpSocket::from_std(sock.into())?;
    udp.send_to(data, orig_dst)
        .await
        .map_err(|e| Error::network(e.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbound::RelayHandler;

    #[tokio::test]
    async fn tproxy_bind_needs_caps_or_skips() {
        // Binding transparent sockets requires CAP_NET_ADMIN; in test
        // environments without it we merely confirm the error surfaces.
        let cfg = ListenerConfig {
            tag: "t".into(),
            bind: "127.0.0.1".into(),
            port: 0,
            kind: crate::inbound::ListenerKind::Tproxy,
        };
        let relay: SharedRelay = Arc::new(NoopRelay);
        let result = serve(&cfg, relay).await;
        // Rooted CI can bind; unprivileged local runs get a clean error.
        match result {
            Ok(_) => {}
            Err(e) => assert!(e.to_string().contains("CAP_NET_ADMIN") || e.to_string().contains("Permission")),
        }
    }

    struct NoopRelay;

    impl RelayHandler for NoopRelay {
        fn handle_tcp(self: std::sync::Arc<Self>, _meta: TcpMeta, _client: crate::stream::BoxProxyStream) {}
        fn handle_udp(
            self: std::sync::Arc<Self>,
            _: SocketAddr,
            _: String,
            _: mpsc::Receiver<(NetAddr, Vec<u8>)>,
            _: mpsc::Sender<(NetAddr, Vec<u8>)>,
        ) {
        }
    }
}
