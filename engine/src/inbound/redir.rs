//! NAT REDIRECT inbound (Linux): accepted connections recover their
//! original destination via `SO_ORIGINAL_DST`.

use std::net::SocketAddr;
use std::os::fd::AsRawFd;

use tokio::net::TcpListener;

use crate::addr::NetAddr;
use crate::error::{Error, Result};
use crate::inbound::{ListenerConfig, SharedRelay, TcpMeta};

/// Serve a redirect listener; returns the bound address.
pub async fn serve(cfg: &ListenerConfig, relay: SharedRelay) -> Result<SocketAddr> {
    let listener = TcpListener::bind((cfg.bind.as_str(), cfg.port))
        .await
        .map_err(|e| {
            crate::inbound::bind_failure("redir", format!("{}:{}", cfg.bind, cfg.port), e)
        })?;
    let addr = listener.local_addr().map_err(|e| Error::network(e.to_string()))?;
    let port = addr.port();
    let tag = cfg.tag.clone();
    tokio::spawn(async move {
        loop {
            let Ok((stream, peer)) = listener.accept().await else {
                // Under fd exhaustion accept fails instantly; a bare
                // continue would hot-spin. Back off briefly.
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            };
            let Ok(target) = original_dst(&stream) else {
                tracing::debug!(target: "engine", "redir: no original dst for {peer}");
                continue;
            };
            // On a connection that never went through NAT, Linux can
            // still answer SO_ORIGINAL_DST with the socket's OWN local
            // address. Relaying that would dial ourselves — through the
            // proxy back into this listener — an infinite, fd-eating
            // cascade. Not-redirected connections are dropped, like mihomo.
            if let Ok(local) = stream.local_addr() {
                if target.port == local.port()
                    && matches!(&target.host, crate::addr::Host::Ip(ip) if *ip == local.ip())
                {
                    tracing::debug!(target: "engine", "redir: {peer} not redirected, closing");
                    continue;
                }
            }
            let _ = stream.set_nodelay(true);
            relay.clone().handle_tcp(
                TcpMeta {
                    target,
                    source: peer,
                    inbound: tag.clone(),
                    inbound_port: Some(port),
                    inbound_kind: "redir",
                },
                Box::new(stream),
            );
        }
    });
    Ok(addr)
}

/// `SO_ORIGINAL_DST` on an accepted NAT-redirected socket.
fn original_dst(stream: &tokio::net::TcpStream) -> Result<NetAddr> {
    let fd = stream.as_raw_fd();
    let peer = stream.peer_addr().map_err(|e| Error::network(e.to_string()))?;
    unsafe {
        if peer.is_ipv4() {
            let mut addr: libc::sockaddr_in = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t;
            if libc::getsockopt(
                fd,
                libc::SOL_IP,
                libc::SO_ORIGINAL_DST,
                &mut addr as *mut _ as *mut libc::c_void,
                &mut len,
            ) != 0
            {
                return Err(Error::network("SO_ORIGINAL_DST failed (not redirected?)"));
            }
            Ok(NetAddr::ip(
                std::net::IpAddr::V4(u32::from_be(addr.sin_addr.s_addr).into()),
                u16::from_be(addr.sin_port),
            ))
        } else {
            let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
            let mut len = std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t;
            if libc::getsockopt(
                fd,
                libc::IPPROTO_IPV6,
                crate::inbound::redir::IP6T_SO_ORIGINAL_DST,
                &mut addr as *mut _ as *mut libc::c_void,
                &mut len,
            ) != 0
            {
                return Err(Error::network("IP6T_SO_ORIGINAL_DST failed"));
            }
            Ok(NetAddr::ip(
                std::net::IpAddr::V6(addr.sin6_addr.s6_addr.into()),
                u16::from_be(addr.sin6_port),
            ))
        }
    }
}

/// `IP6T_SO_ORIGINAL_DST` — stable kernel ABI value the libc crate does
/// not export (linux/netfilter_ipv6/ip6_tables.h).
pub const IP6T_SO_ORIGINAL_DST: libc::c_int = 80;

