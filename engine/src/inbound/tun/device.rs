//! Linux TUN device plumbing: `/dev/net/tun` open + `TUNSETIFF`, then
//! address/netmask/MTU assignment and link-up through ioctl(2) on a single
//! AF_INET socket (no netlink dependency). IPv6 addresses use the parallel
//! AF_INET6 ioctl path ([`assign_inet6`]), also netlink-free.
//!
//! ## io model
//!
//! The fd is opened `O_NONBLOCK` and is the only handle — a TUN fd cannot be
//! split, and both directions are plain `read(2)`/`write(2)` on it. The
//! netstack drives reads from tokio's `AsyncFd` readiness and writes with a
//! nonblocking `write(2)` from its smoltcp `TxToken`; a full device queue
//! (`EAGAIN`) drops the packet, which is what a real NIC does and what TCP
//! retransmission is for (see `netstack.rs`).
//!
//! Direction convention (easy to get backwards): writing to the fd injects a
//! packet *into* the kernel as if it had arrived on the interface; reading
//! from the fd returns packets the kernel wants to *send out* of it.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, RawFd};

use crate::error::{Error, Result};

/// Name pattern used when the config leaves the interface name empty: the
/// kernel then assigns the first free `tunN`.
const DEFAULT_NAME_PATTERN: &str = "tun%d";

/// Smallest MTU we accept — RFC 791's minimum IPv4 MTU.
const MIN_MTU: u16 = 576;

/// An attached TUN interface. Dropping it closes the fd, which detaches the
/// queue and (the interface not being persistent) removes the interface.
pub struct TunDevice {
    fd: RawFd,
    name: String,
}

impl TunDevice {
    /// Attach to (creating it if needed) the tun interface `name` and put it
    /// into `IFF_TUN | IFF_NO_PI` mode: raw IPv4/IPv6 packets, no 4-byte
    /// packet-information prefix. An empty `name` lets the kernel pick.
    ///
    /// Needs CAP_NET_ADMIN (or a pre-created interface owned by us); the
    /// error says which of the two failures happened.
    pub fn open(name: &str) -> Result<TunDevice> {
        let cpath = std::ffi::CString::new("/dev/net/tun")
            .map_err(|_| Error::network("tun: bad device path"))?;
        // O_CLOEXEC: the fd must not leak into child processes.
        let fd = unsafe {
            libc::open(
                cpath.as_ptr(),
                libc::O_RDWR | libc::O_NONBLOCK | libc::O_CLOEXEC,
            )
        };
        if fd < 0 {
            let e = io::Error::last_os_error();
            return Err(Error::network(format!(
                "tun: open /dev/net/tun: {e}{}",
                if e.kind() == io::ErrorKind::NotFound {
                    " (is the tun module loaded?)"
                } else {
                    ""
                }
            )));
        }

        let wanted = if name.is_empty() {
            DEFAULT_NAME_PATTERN
        } else {
            name
        };
        let mut req = make_ifreq(wanted)?;
        req.ifr_ifru.ifru_flags = (libc::IFF_TUN | libc::IFF_NO_PI) as libc::c_short;
        if let Err(e) = ioctl_ifreq(fd, libc::TUNSETIFF as libc::Ioctl, &mut req) {
            unsafe { libc::close(fd) };
            return Err(Error::network(format!(
                "tun: TUNSETIFF {wanted:?}: {e}{}",
                cap_hint(&e)
            )));
        }
        // The kernel fills in the real name (matters for the tun%d pattern).
        let actual = ifreq_name(&req).unwrap_or_else(|| wanted.to_string());
        Ok(TunDevice { fd, name: actual })
    }

    /// Read one packet. Nonblocking: `WouldBlock` when the queue is empty.
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let n = unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(n as usize)
    }

    /// Hand one packet to the kernel (as if it had arrived on the interface).
    /// Nonblocking; a full queue yields `WouldBlock` and the caller drops.
    pub fn send(&self, pkt: &[u8]) -> io::Result<()> {
        let n = unsafe { libc::write(self.fd, pkt.as_ptr() as *const libc::c_void, pkt.len()) };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }

    /// The interface name as configured (or as assigned by the kernel).
    pub fn name(&self) -> &str {
        &self.name
    }
}

impl AsRawFd for TunDevice {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        unsafe { libc::close(self.fd) };
    }
}

/// Assign `addr / prefix` and `mtu` to interface `name`, then bring it up.
///
/// Uses one ephemeral AF_INET socket for all four ioctls. Every failure is
/// reported with the interface name and, for EPERM/EACCES, a CAP_NET_ADMIN
/// hint — this is the call that fails first in an unprivileged test run.
pub fn configure_interface(name: &str, addr: Ipv4Addr, prefix: u8, mtu: u16) -> Result<()> {
    if prefix > 32 {
        return Err(Error::config(format!(
            "tun: netmask /{prefix} is not a valid IPv4 prefix length"
        )));
    }
    let mtu = mtu.max(MIN_MTU);
    let sock = unsafe { libc::socket(libc::AF_INET, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(Error::network(format!(
            "tun: ifconfig socket: {}",
            io::Error::last_os_error()
        )));
    }
    let res = (|| -> Result<()> {
        // Address. (Taking a reference to a union field is unsafe by language
        // rule; the union was fully zeroed above, so the reference is sound.)
        let mut req = make_ifreq(name)?;
        unsafe { set_sockaddr(&mut req.ifr_ifru.ifru_addr, addr) };
        ioctl_ifreq(sock, libc::SIOCSIFADDR as libc::Ioctl, &mut req)
            .map_err(|e| iface_err(name, "SIOCSIFADDR", e))?;

        // Netmask (prefix -> dotted mask).
        let mask = if prefix == 0 {
            0
        } else {
            u32::MAX << (32 - prefix)
        };
        let mut req = make_ifreq(name)?;
        unsafe { set_sockaddr(&mut req.ifr_ifru.ifru_netmask, Ipv4Addr::from(mask)) };
        ioctl_ifreq(sock, libc::SIOCSIFNETMASK as libc::Ioctl, &mut req)
            .map_err(|e| iface_err(name, "SIOCSIFNETMASK", e))?;

        // MTU: smoltcp is configured with the same value, so the kernel never
        // hands us a packet larger than the stack's buffers.
        let mut req = make_ifreq(name)?;
        req.ifr_ifru.ifru_mtu = mtu as libc::c_int;
        ioctl_ifreq(sock, libc::SIOCSIFMTU as libc::Ioctl, &mut req)
            .map_err(|e| iface_err(name, "SIOCSIFMTU", e))?;

        // Read-modify-write the flags so IFF_POINTOPOINT/IFF_NOARP survive.
        let mut req = make_ifreq(name)?;
        ioctl_ifreq(sock, libc::SIOCGIFFLAGS as libc::Ioctl, &mut req)
            .map_err(|e| iface_err(name, "SIOCGIFFLAGS", e))?;
        let flags = unsafe { req.ifr_ifru.ifru_flags } as libc::c_int;
        let mut req = make_ifreq(name)?;
        req.ifr_ifru.ifru_flags = (flags | libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        ioctl_ifreq(sock, libc::SIOCSIFFLAGS as libc::Ioctl, &mut req)
            .map_err(|e| iface_err(name, "SIOCSIFFLAGS", e))?;
        Ok(())
    })();
    unsafe { libc::close(sock) };
    res
}

/// `struct in6_ifreq` from the kernel UAPI (`include/uapi/linux/ipv6.h`):
///
/// ```c
/// struct in6_ifreq {
///     struct in6_addr ifr6_addr;
///     __u32           ifr6_prefixlen;
///     int             ifr6_ifindex;
/// };
/// ```
///
/// IPv6 address ioctls are the one family that does NOT use `struct ifreq`
/// (netdevice(7): "AF_INET6 is an exception. It passes an in6_ifreq
/// structure") — the interface is named by index, and the prefix length is
/// part of the request, like `ip -6 addr add addr/prefixlen`.
#[repr(C)]
struct In6Ifreq {
    addr: libc::in6_addr,
    prefixlen: u32,
    ifindex: libc::c_int,
}

/// Assign `addr / prefix` as an IPv6 address of interface `name`.
///
/// `ip -6 addr add` uses netlink (RTM_NEWADDR); this is the legacy ioctl
/// path that `ifconfig` uses, verified against the kernel source:
///
/// * `inet6_ioctl` (net/ipv6/af_inet6.c) dispatches `SIOCSIFADDR` on an
///   AF_INET6 socket to `addrconf_add_ifaddr`,
/// * `addrconf_add_ifaddr` (net/ipv6/addrconf.c) requires CAP_NET_ADMIN,
///   copies an `in6_ifreq` and calls the same `inet6_addr_add` netlink
///   uses, with `IFA_F_PERMANENT` and infinite lifetimes,
/// * `inet6_addr_add` also installs the connected prefix route
///   (`addrconf_prefix_route`) unless `IFA_F_NOPREFIXROUTE` — so a /64
///   (or a /126 point-to-point) makes the kernel route v6 through the
///   interface without any extra route command.
///
/// Plain `ifreq` with a `sockaddr_in6` in `ifr_addr` is NOT what the kernel
/// takes on the v6 path — that idea from the design notes does not hold.
///
/// Call after [`configure_interface`] (the interface is up by then, which is
/// also the state `ip addr add` normally operates on).
pub fn assign_inet6(name: &str, addr: Ipv6Addr, prefix: u8) -> Result<()> {
    if prefix > 128 {
        return Err(Error::config(format!(
            "tun: /{prefix} is not a valid IPv6 prefix length"
        )));
    }
    let cname = std::ffi::CString::new(name)
        .map_err(|_| Error::config(format!("tun: bad interface name {name:?}")))?;
    let ifindex = unsafe { libc::if_nametoindex(cname.as_ptr()) };
    if ifindex == 0 {
        return Err(Error::network(format!(
            "tun: if_nametoindex {name:?}: {} (no such interface?)",
            io::Error::last_os_error()
        )));
    }
    let sock = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(Error::network(format!(
            "tun: ifconfig inet6 socket: {}",
            io::Error::last_os_error()
        )));
    }
    let mut req = In6Ifreq {
        addr: libc::in6_addr {
            s6_addr: addr.octets(),
        },
        prefixlen: prefix as u32,
        ifindex: ifindex as libc::c_int,
    };
    let rc = unsafe {
        libc::ioctl(
            sock,
            libc::SIOCSIFADDR as libc::Ioctl,
            &mut req as *mut In6Ifreq,
        )
    };
    unsafe { libc::close(sock) };
    if rc < 0 {
        let e = io::Error::last_os_error();
        return Err(Error::network(format!(
            "tun: SIOCSIFADDR(inet6) {name:?} {addr}/{prefix}: {e}{}",
            cap_hint(&e)
        )));
    }
    Ok(())
}

/// `ifreq` with `ifr_name` set (everything else zeroed).
fn make_ifreq(name: &str) -> Result<libc::ifreq> {
    if name.len() >= libc::IFNAMSIZ {
        return Err(Error::config(format!(
            "tun: interface name {name:?} is longer than {} bytes",
            libc::IFNAMSIZ - 1
        )));
    }
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in name.as_bytes().iter().enumerate() {
        req.ifr_name[i] = *b as libc::c_char;
    }
    Ok(req)
}

/// Read the kernel-assigned interface name back out of an `ifreq`.
pub(crate) fn ifreq_name(req: &libc::ifreq) -> Option<String> {
    let bytes: Vec<u8> = req
        .ifr_name
        .iter()
        .take_while(|c| **c != 0)
        .map(|c| *c as u8)
        .collect();
    if bytes.is_empty() {
        None
    } else {
        Some(String::from_utf8_lossy(&bytes).into_owned())
    }
}

/// Fill the `sockaddr` inside an `ifreq` union with `AF_INET` + `addr`.
///
/// The union's `sockaddr` and `sockaddr_in` share a layout prefix, so writing
/// through the `sockaddr_in` view is the intended use; the port field stays
/// zero (these ioctls only read family + address).
fn set_sockaddr(slot: &mut libc::sockaddr, addr: Ipv4Addr) {
    unsafe {
        let sin = slot as *mut libc::sockaddr as *mut libc::sockaddr_in;
        (*sin).sin_family = libc::AF_INET as libc::sa_family_t;
        // s_addr is network byte order: `to_bits().to_be()` puts the octets
        // into memory in address order (`Ipv4Addr::from(1,2,3,4).to_bits()`
        // is 0x01020304).
        (*sin).sin_addr.s_addr = addr.to_bits().to_be();
    }
}

fn ioctl_ifreq(fd: RawFd, request: libc::Ioctl, req: &mut libc::ifreq) -> io::Result<()> {
    let rc = unsafe { libc::ioctl(fd, request, req as *mut libc::ifreq) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Name one of the four ifconfig ioctls in the error (a bare EPERM is
/// otherwise indistinguishable from a bad interface name).
fn iface_err(name: &str, op: &str, e: io::Error) -> Error {
    Error::network(format!("tun: {op} {name:?}: {e}{}", cap_hint(&e)))
}

fn cap_hint(e: &io::Error) -> &'static str {
    match e.raw_os_error() {
        Some(libc::EPERM) | Some(libc::EACCES) => " (needs CAP_NET_ADMIN)",
        Some(libc::ENODEV) => " (no such interface; create it with `ip tuntap add`)",
        _ => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ifreq_name_roundtrip() {
        let req = make_ifreq("rc-tun0").unwrap();
        assert_eq!(ifreq_name(&req).as_deref(), Some("rc-tun0"));
        // Over-long names are a config error, not a truncation.
        let long = "x".repeat(libc::IFNAMSIZ);
        assert!(make_ifreq(&long).is_err());
    }

    #[test]
    fn ifreq_name_stops_at_nul() {
        let mut req = make_ifreq("tun0").unwrap();
        // Pretend the kernel wrote a shorter name over ours.
        req.ifr_name[1] = 0;
        assert_eq!(ifreq_name(&req).as_deref(), Some("t"));
        let empty: libc::ifreq = unsafe { std::mem::zeroed() };
        assert_eq!(ifreq_name(&empty), None);
    }

    #[test]
    fn sockaddr_layout_is_network_order() {
        let mut slot: libc::sockaddr = unsafe { std::mem::zeroed() };
        set_sockaddr(&mut slot, Ipv4Addr::new(10, 7, 0, 1));
        let bytes = unsafe {
            let sin = &slot as *const libc::sockaddr as *const libc::sockaddr_in;
            (*sin).sin_addr.s_addr.to_ne_bytes()
        };
        assert_eq!(bytes, [10, 7, 0, 1]);
        let family = unsafe {
            (&slot as *const libc::sockaddr as *const libc::sockaddr_in)
                .as_ref()
                .unwrap()
                .sin_family
        };
        assert_eq!(family as libc::c_int, libc::AF_INET);
    }

    #[test]
    fn prefix_length_is_validated() {
        let err = configure_interface("rc-tun0", Ipv4Addr::new(10, 0, 0, 1), 33, 1500)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a valid IPv4 prefix"), "{err}");
    }

    #[test]
    fn inet6_prefix_length_is_validated() {
        let err = assign_inet6("rc-tun0", Ipv6Addr::LOCALHOST, 129)
            .unwrap_err()
            .to_string();
        assert!(err.contains("not a valid IPv6 prefix"), "{err}");
    }

    /// No privileges needed: an interface that does not exist must fail in
    /// `if_nametoindex`, before any privileged call.
    #[test]
    fn inet6_unknown_interface_is_a_clear_error() {
        let err = assign_inet6("rc-no-such-iface9", Ipv6Addr::LOCALHOST, 64)
            .unwrap_err()
            .to_string();
        assert!(err.contains("if_nametoindex"), "{err}");
    }

    /// Pin the UAPI layout the kernel `copy_from_user`s: `in6_addr` then
    /// `__u32 prefixlen` then `int ifindex`, no padding anywhere.
    #[test]
    fn in6_ifreq_layout_matches_the_uapi() {
        assert_eq!(std::mem::size_of::<In6Ifreq>(), 24);
        assert_eq!(std::mem::offset_of!(In6Ifreq, prefixlen), 16);
        assert_eq!(std::mem::offset_of!(In6Ifreq, ifindex), 20);
    }

    /// With CAP_NET_ADMIN: attach, configure v4 and assign a v6 address, then
    /// read it back from `/proc/net/if_inet6` (the netlink-free view of v6
    /// addresses). Without the capability this skips, like every attach test.
    #[test]
    fn inet6_assign_needs_caps_or_skips() {
        let name = format!("rctun6{}", std::process::id() % 100_000);
        let Ok(dev) = TunDevice::open(&name) else {
            return; // skip: no CAP_NET_ADMIN (or no tun module) here
        };
        let addr = Ipv6Addr::new(0xfd00, 0xd00d, 0, 0, 0, 0, 0, 1);
        let res = configure_interface(&name, Ipv4Addr::new(192, 0, 2, 1), 30, 1500)
            .and_then(|()| assign_inet6(&name, addr, 120));
        drop(dev);
        res.expect("privileged run must assign the v6 address");
        // /proc/net/if_inet6 prints "address plen scope flags use name" with
        // the address as four 32-bit words, each little-endian in hex.
        let table = std::fs::read_to_string("/proc/net/if_inet6").expect("/proc must exist");
        let mut addr_hex = String::new();
        for group in addr.octets().chunks(4) {
            addr_hex.push_str(&format!(
                "{:02x}{:02x}{:02x}{:02x}",
                group[3], group[2], group[1], group[0]
            ));
        }
        let line = table
            .lines()
            .find(|l| l.split_whitespace().last() == Some(&name))
            .unwrap_or_else(|| panic!("v6 address not in /proc/net/if_inet6:\n{table}"));
        // Columns: address hex, ifindex, prefix len, scope, flags, name.
        let mut cols = line.split_whitespace();
        assert_eq!(cols.next(), Some(addr_hex.as_str()));
        let _ifindex = cols.next();
        assert_eq!(cols.next(), Some("78"), "prefix 120 (0x78), line: {line}");
    }

    /// A missing `/dev/net/tun` and a missing CAP_NET_ADMIN must both surface
    /// as a clear, non-panicking error (this is what the attach test keys on).
    #[test]
    fn open_failure_is_clear() {
        match TunDevice::open("rctun-none") {
            Ok(dev) => {
                // Privileged environment: the interface really was created.
                assert_eq!(dev.name(), "rctun-none");
            }
            Err(e) => {
                let text = e.to_string();
                assert!(
                    text.contains("CAP_NET_ADMIN")
                        || text.contains("Permission")
                        || text.contains("operation not permitted")
                        || text.contains("tun module"),
                    "unexpected tun open error: {text}"
                );
            }
        }
    }
}
