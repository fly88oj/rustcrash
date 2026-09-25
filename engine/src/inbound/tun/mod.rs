//! TUN inbound: a real TUN device with an in-process smoltcp stack.
//!
//! This is the mihomo `tun:` / sing-box `tun` inbound. The device is the
//! platform's native one — `/dev/net/tun` (`IFF_TUN | IFF_NO_PI`) on Linux,
//! utun on macOS, WinTUN on Windows (see [`device`]) — given an address
//! (v4 always; v6 when `inet6_address` is set) and brought up; every packet
//! the kernel sends out of the interface is fed to a smoltcp stack, and the
//! TCP connections / UDP associations the stack accepts are handed to the
//! engine's [`RelayHandler`](crate::inbound::RelayHandler) exactly like any
//! other inbound. ICMP echo requests ("ping") are answered by the stack
//! itself on both families, mihomo-style; DNS hijack and the IPv6
//! extension-header walk are platform-independent (see [`netstack`]).
//!
//! ```no_run
//! # async fn example(engine: std::sync::Arc<rustcrash_engine::Engine>) -> rustcrash_engine::Result<()> {
//! use rustcrash_engine::inbound::tun::{self, TunConfig, TunHooks};
//! let cfg = TunConfig {
//!     tag: "tun-in".into(),
//!     name: "rustcrash0".into(),
//!     address: "172.19.0.1".parse().unwrap(),
//!     netmask: 30,
//!     mtu: 1500,
//!     dns_hijack: vec!["172.19.0.2".parse().unwrap()],
//!     inet6_address: Some(("fd00::1".parse().unwrap(), 64)),
//! };
//! let hooks = TunHooks { dns: engine.dns().cloned() };
//! let relay = engine as std::sync::Arc<dyn rustcrash_engine::inbound::RelayHandler>;
//! // `serve` runs until the device dies, so spawn it rather than awaiting it.
//! let task = tokio::spawn(async move { tun::serve(&cfg, relay, hooks).await });
//! # let _ = task;
//! # Ok(())
//! # }
//! ```
//!
//! Linux needs CAP_NET_ADMIN (or root) plus `/dev/net/tun`; macOS needs root
//! to open a utun unit; Windows needs `wintun.dll` (shipped with the
//! official WireGuard clients) and the adapter driver installed once.
//! Failures say which of these is missing.
//!
//! Known limitation, logged at debug rather than dropped silently: TCP
//! behind IPv6 extension headers is not relayed — smoltcp does not follow
//! chains (UDP, DNS hijack and ICMPv6 echo behind chains are handled; see
//! `netstack`'s docs).

#[cfg(target_os = "linux")]
mod device_linux;
#[cfg(target_os = "macos")]
mod device_macos;
#[cfg(target_os = "windows")]
mod device_windows;
/// The platform-dispatched device layer: `device::TunDevice` is the Linux
/// `/dev/net/tun` backend, WinTUN on Windows and utun on macOS (the latter
/// two cfg'd out here but compiled and layout-tested on their targets).
pub mod device;
/// The async device IO surface (`TunIo`) and the reader pump that bridges
/// the blocking device into the netstack's async loop.
pub(crate) mod io;
pub mod netstack;
/// An in-memory TUN double (`LoopbackTun`): the kernel side of a tunnel for
/// hermetic full-path netstack tests, no real device or privileges needed.
#[cfg(test)]
pub(crate) mod testdev;

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use crate::dns::resolver::DnsEngine;
use crate::error::{Error, Result};
use crate::inbound::SharedRelay;

/// One `tun:` inbound from the config.
#[derive(Debug, Clone)]
pub struct TunConfig {
    /// Inbound tag, used for IN-TYPE / routing like every other listener.
    pub tag: String,
    /// Interface name; created if it does not exist. Empty lets the kernel
    /// pick (`tun%d`).
    pub name: String,
    /// Address assigned to the interface — the tunnel peer's gateway.
    pub address: Ipv4Addr,
    /// Prefix length (mihomo's `inet4-address: 172.19.0.1/30` -> 30).
    pub netmask: u8,
    /// Interface MTU; also the stack's MTU and its read buffer size.
    pub mtu: u16,
    /// UDP destinations answered by the engine's own resolver instead of
    /// being relayed (mihomo `dns-hijack`). Matched by address, either
    /// family.
    pub dns_hijack: Vec<IpAddr>,
    /// Optional IPv6 address + prefix for the interface (mihomo's
    /// `inet6-address: fd00::1/64`, an `(addr, prefix)` pair). When set, the
    /// interface gets the address through the platform's v6 assignment path
    /// (the AF_INET6 `SIOCSIFADDR` ioctl on Linux/macOS, an IP Helper
    /// unicast-address row on Windows) and the netstack carries IPv6
    /// symmetric to IPv4: TCP, UDP, DNS hijack by v6 address, and ICMPv6
    /// echo. `None` keeps the inbound IPv4-only.
    pub inet6_address: Option<(Ipv6Addr, u8)>,
}

/// Optional pieces the inbound can use. A missing resolver only disables DNS
/// hijacking; everything else keeps working.
#[derive(Clone)]
pub struct TunHooks {
    pub dns: Option<Arc<DnsEngine>>,
}

/// Create the platform device, configure it, and relay through the stack
/// forever.
///
/// Platform split: Linux and macOS configure their interface *by name*
/// (ioctls on an AF_INET/AF_INET6 socket); Windows identifies interfaces by
/// LUID for its IP Helper calls, so it configures through
/// [`device::TunDevice::luid`] — and because WinTUN adapters are created and
/// re-opened *by name*, an empty `name` (which on Linux means "kernel
/// picks") is a config error there.
///
/// Returns `Err` only for setup failures (missing `/dev/net/tun`, no
/// CAP_NET_ADMIN/root, missing `wintun.dll`, bad prefix length) or when the
/// device dies. Callers normally `tokio::spawn` this rather than awaiting
/// it, since a live TUN inbound never returns on its own. Dropping the
/// future stops the reader pump and closes the device, which detaches (and
/// on Linux removes) the interface.
pub async fn serve(cfg: &TunConfig, relay: SharedRelay, hooks: TunHooks) -> Result<()> {
    if cfg.netmask > 32 {
        return Err(Error::config(format!(
            "tun {}: invalid netmask /{} (expected 0-32)",
            cfg.name, cfg.netmask
        )));
    }
    if let Some((_, prefix)) = cfg.inet6_address {
        if prefix > 128 {
            return Err(Error::config(format!(
                "tun {}: invalid inet6 prefix /{prefix} (expected 0-128)",
                cfg.name
            )));
        }
    }
    #[cfg(target_os = "windows")]
    {
        if cfg.name.is_empty() {
            return Err(Error::config(
                "tun: the adapter name must be set on Windows (a WinTUN adapter is \
                 created and re-opened by name; there is no kernel-assigned default)",
            ));
        }
    }
    let dev = Arc::new(device::TunDevice::open(&cfg.name)?);

    // Address/netmask/MTU/bring-up, then v6: `ip addr add` normally runs on
    // an up interface, and the address brings its own prefix route.
    #[cfg(not(target_os = "windows"))]
    let configured = {
        let name = dev.name().to_string();
        device::configure_interface(&name, cfg.address, cfg.netmask, cfg.mtu).and_then(
            |()| match cfg.inet6_address {
                Some((inet6, prefix)) => device::assign_inet6(&name, inet6, prefix),
                None => Ok(()),
            },
        )
    };
    #[cfg(target_os = "windows")]
    let configured = {
        let luid = dev.luid();
        device::configure_interface(luid, cfg.address, cfg.netmask, cfg.mtu).and_then(|()| {
            match cfg.inet6_address {
                Some((inet6, prefix)) => device::assign_inet6(luid, inet6, prefix),
                None => Ok(()),
            }
        })
    };
    configured?;
    let name = dev.name();
    match cfg.inet6_address {
        Some((inet6, prefix)) => tracing::info!(
            target: "engine",
            "tun {name} up: {}/{} + {}/{} mtu {} ({} dns-hijack addresses)",
            cfg.address,
            cfg.netmask,
            inet6,
            prefix,
            cfg.mtu,
            cfg.dns_hijack.len()
        ),
        None => tracing::info!(
            target: "engine",
            "tun {name} up: {}/{} mtu {} ({} dns-hijack addresses)",
            cfg.address,
            cfg.netmask,
            cfg.mtu,
            cfg.dns_hijack.len()
        ),
    }
    netstack::run(dev, cfg.clone(), relay, hooks).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::NetAddr;
    use crate::inbound::{RelayHandler, TcpMeta};
    use crate::stream::BoxProxyStream;
    use std::net::SocketAddr;
    use std::sync::Mutex;
    use tokio::sync::mpsc;

    struct NoopRelay;

    impl RelayHandler for NoopRelay {
        fn handle_tcp(self: Arc<Self>, _meta: TcpMeta, _client: BoxProxyStream) {}
        fn handle_udp(
            self: Arc<Self>,
            _source: SocketAddr,
            _inbound: String,
            _uplink: mpsc::Receiver<(NetAddr, Vec<u8>)>,
            _downlink: mpsc::Sender<(NetAddr, Vec<u8>)>,
        ) {
        }
    }

    /// Echoes uplink datagrams back on the downlink and records them.
    struct EchoRelay(Mutex<Vec<(SocketAddr, NetAddr, Vec<u8>)>>);

    impl RelayHandler for EchoRelay {
        fn handle_tcp(self: Arc<Self>, _meta: TcpMeta, _client: BoxProxyStream) {}

        fn handle_udp(
            self: Arc<Self>,
            source: SocketAddr,
            _inbound: String,
            mut uplink: mpsc::Receiver<(NetAddr, Vec<u8>)>,
            downlink: mpsc::Sender<(NetAddr, Vec<u8>)>,
        ) {
            tokio::spawn(async move {
                while let Some((target, data)) = uplink.recv().await {
                    self.0
                        .lock()
                        .unwrap()
                        .push((source, target.clone(), data.clone()));
                    let _ = downlink.send((target, data)).await;
                }
            });
        }
    }

    #[tokio::test]
    async fn invalid_netmask_is_a_config_error() {
        let cfg = TunConfig {
            tag: "t".into(),
            name: "rc-bad".into(),
            address: Ipv4Addr::new(10, 0, 0, 1),
            netmask: 33,
            mtu: 1500,
            dns_hijack: Vec::new(),
            inet6_address: None,
        };
        let err = serve(&cfg, Arc::new(NoopRelay), TunHooks { dns: None })
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid netmask"), "{err}");
    }

    #[tokio::test]
    async fn invalid_inet6_prefix_is_a_config_error() {
        let cfg = TunConfig {
            tag: "t".into(),
            name: "rc-bad6".into(),
            address: Ipv4Addr::new(10, 0, 0, 1),
            netmask: 24,
            mtu: 1500,
            dns_hijack: Vec::new(),
            inet6_address: Some((Ipv6Addr::LOCALHOST, 129)),
        };
        let err = serve(&cfg, Arc::new(NoopRelay), TunHooks { dns: None })
            .await
            .unwrap_err()
            .to_string();
        assert!(err.contains("invalid inet6 prefix"), "{err}");
    }

    /// Interface names are capped at 15 bytes and must be unique per process.
    fn test_iface_name(tag: u32) -> String {
        format!("rctun{}", (std::process::id() % 100_000) + tag)
    }

    /// Attach a real TUN device and relay one UDP round trip through it.
    ///
    /// Skips (never fails) without the privileges a unit-test environment
    /// lacks — the same contract as `tproxy_bind_needs_caps_or_skips`. With
    /// CAP_NET_ADMIN (the docker e2e container) it proves the whole path: the
    /// kernel routes a datagram out of the interface, the netstack relays it
    /// to the engine, and the relay's reply is written back through the
    /// device to the client socket.
    #[tokio::test]
    async fn tun_attach_skips_without_caps() {
        // Probe first, so the skip decision is deterministic and does not
        // race the spawned serve task.
        let probe = test_iface_name(0);
        if let Err(e) = device::TunDevice::open(&probe) {
            let text = e.to_string();
            assert!(
                text.contains("CAP_NET_ADMIN")
                    || text.contains("Permission")
                    || text.contains("tun module"),
                "unprivileged tun open must be a clear error, got: {text}"
            );
            return; // skip: no CAP_NET_ADMIN in this environment
        }

        let name = test_iface_name(1);
        let cfg = TunConfig {
            tag: "tun-e2e".into(),
            name,
            // A /30 so the peer address has a connected route: the kernel
            // needs no extra route to send through the interface.
            address: Ipv4Addr::new(192, 0, 2, 1),
            netmask: 30,
            mtu: 1500,
            dns_hijack: Vec::new(),
            inet6_address: None,
        };
        let peer = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 2)), 5353);
        let relay = Arc::new(EchoRelay(Mutex::new(Vec::new())));
        let served = cfg.clone();
        let relay_for_task: Arc<dyn RelayHandler> = relay.clone();
        let serve_task =
            tokio::spawn(
                async move { serve(&served, relay_for_task, TunHooks { dns: None }).await },
            );

        // The client is an ordinary socket bound to the interface address:
        // its datagrams to the peer are routed out of the tun by the kernel.
        // The address only exists once `serve` has configured it, so retry
        // the bind until the interface is up. Deadlines here use the real
        // (std) clock, never tokio timers: a test runtime with a paused
        // clock would expire them instantly.
        let client_addr = SocketAddr::new(IpAddr::V4(cfg.address), 0);
        let mut sock = None;
        let bind_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < bind_deadline {
            if let Ok(s) = tokio::net::UdpSocket::bind(client_addr).await {
                sock = Some(s);
                break;
            }
            if serve_task.is_finished() {
                break; // report the setup failure below instead of hanging
            }
            tokio::task::yield_now().await;
        }
        let Some(sock) = sock else {
            let outcome = match serve_task.await {
                Ok(r) => format!("{r:?}"),
                Err(e) => format!("{e}"),
            };
            panic!("the tun interface never became usable (serve: {outcome})");
        };
        let local = sock.local_addr().expect("bound socket has an address");

        let mut heard = None;
        let mut echoed = None;
        let mut buf = [0u8; 64];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline && echoed.is_none() {
            let _ = sock.send_to(b"tun-probe", peer).await;
            if let Ok((n, from)) = sock.try_recv_from(&mut buf) {
                echoed = Some((n, from));
            }
            if heard.is_none() {
                heard = relay.0.lock().unwrap().first().cloned();
            }
            // Let the netstack task run between attempts.
            tokio::task::yield_now().await;
        }
        serve_task.abort();

        let (source, target, payload) =
            heard.expect("kernel traffic out of the tun must reach the relay");
        assert_eq!(source, local, "relay sees the client socket as the source");
        assert_eq!(target.to_string(), format!("192.0.2.2:{}", peer.port()));
        assert_eq!(payload, b"tun-probe");

        let (n, from) = echoed.expect("the relayed reply must come back through the device");
        assert_eq!(
            from, peer,
            "reply must appear to come from the dialled peer"
        );
        assert_eq!(&buf[..n], b"tun-probe");
    }

    /// The IPv6 mirror of `tun_attach_skips_without_caps`: same capability
    /// contract (skips without CAP_NET_ADMIN), but the interface carries a
    /// v6 address assigned through the AF_INET6 ioctl and the client socket
    /// is a v6 socket on it. Proves the whole v6 path with CAP_NET_ADMIN
    /// (the docker e2e container): the kernel routes a v6 datagram out of
    /// the interface, the netstack relays it, and the reply is written back
    /// through the device.
    #[tokio::test]
    async fn tun_attach_ipv6_skips_without_caps() {
        let probe = test_iface_name(2);
        if let Err(e) = device::TunDevice::open(&probe) {
            let text = e.to_string();
            assert!(
                text.contains("CAP_NET_ADMIN")
                    || text.contains("Permission")
                    || text.contains("tun module"),
                "unprivileged tun open must be a clear error, got: {text}"
            );
            return; // skip: no CAP_NET_ADMIN in this environment
        }

        let name = test_iface_name(3);
        // A /126 for the same reason the v4 test uses a /30: a connected
        // route to the peer, no default route needed.
        let inet6 = Ipv6Addr::new(0xfd00, 0x2026, 9, 0, 0, 0, 0, 1);
        let cfg = TunConfig {
            tag: "tun-e2e6".into(),
            name,
            address: Ipv4Addr::new(192, 0, 2, 1),
            netmask: 30,
            mtu: 1500,
            dns_hijack: Vec::new(),
            inet6_address: Some((inet6, 126)),
        };
        let peer = SocketAddr::new(
            IpAddr::V6(Ipv6Addr::new(0xfd00, 0x2026, 9, 0, 0, 0, 0, 2)),
            5353,
        );
        let relay = Arc::new(EchoRelay(Mutex::new(Vec::new())));
        let served = cfg.clone();
        let relay_for_task: Arc<dyn RelayHandler> = relay.clone();
        let serve_task =
            tokio::spawn(
                async move { serve(&served, relay_for_task, TunHooks { dns: None }).await },
            );

        // Bind a v6 socket to the interface's v6 address once `serve` has
        // assigned it; real-clock deadlines, never tokio timers.
        let client_addr = SocketAddr::new(IpAddr::V6(inet6), 0);
        let mut sock = None;
        let bind_deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
        while std::time::Instant::now() < bind_deadline {
            if let Ok(s) = tokio::net::UdpSocket::bind(client_addr).await {
                sock = Some(s);
                break;
            }
            if serve_task.is_finished() {
                break;
            }
            tokio::task::yield_now().await;
        }
        let Some(sock) = sock else {
            let outcome = match serve_task.await {
                Ok(r) => format!("{r:?}"),
                Err(e) => format!("{e}"),
            };
            panic!("the tun interface's v6 address never became usable (serve: {outcome})");
        };
        let local = sock.local_addr().expect("bound socket has an address");

        let mut heard = None;
        let mut echoed = None;
        let mut buf = [0u8; 64];
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        while std::time::Instant::now() < deadline && echoed.is_none() {
            let _ = sock.send_to(b"tun6-probe", peer).await;
            if let Ok((n, from)) = sock.try_recv_from(&mut buf) {
                echoed = Some((n, from));
            }
            if heard.is_none() {
                heard = relay.0.lock().unwrap().first().cloned();
            }
            tokio::task::yield_now().await;
        }
        serve_task.abort();

        let (source, target, payload) =
            heard.expect("kernel v6 traffic out of the tun must reach the relay");
        assert_eq!(
            source, local,
            "relay sees the v6 client socket as the source"
        );
        assert_eq!(
            target.to_string(),
            format!("[fd00:2026:9::2]:{}", peer.port())
        );
        assert_eq!(payload, b"tun6-probe");

        let (n, from) = echoed.expect("the relayed v6 reply must come back through the device");
        assert_eq!(
            from, peer,
            "reply must appear to come from the dialled v6 peer"
        );
        assert_eq!(&buf[..n], b"tun6-probe");
    }
}
