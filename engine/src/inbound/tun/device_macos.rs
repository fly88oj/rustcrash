//! macOS TUN device plumbing: the utun kernel-control socket and the
//! ioctl address configuration, ported line-for-line from the two upstream
//! implementations mihomo/sing-box ride on:
//!
//! * WireGuard/wireguard-go `tun/tun_darwin.go` — the socket dance
//!   (`CreateTUN`, lines 85-133): `socket(AF_SYSTEM, SOCK_DGRAM,
//!   SYSPROTO_CONTROL)`, `CTLIOCGINFO` on `com.apple.net.utun_control`,
//!   `connect` with a `sockaddr_ctl` whose `sc_unit` is the requested unit
//!   + 1 (0 = kernel-picked), nonblocking, name read back with
//!   `getsockopt(SYSPROTO_CONTROL, UTUN_OPT_IFNAME)` (lines 179-194). The
//!   4-byte address-family packet header on both directions (lines 204-244).
//! * sagernet/sing-tun `tun_darwin.go` — the address/MTU half: `SIOCSIFMTU`
//!   with an ifreq (lines 250-258), v4 addresses via `SIOCAIFADDR` on an
//!   `ifaliasreq { name, addr, dstaddr, mask }` (lines 211-216, 262-297) and
//!   v6 via `SIOCAIFADDR_IN6` on `ifAliasReq6` with `IN6_IFF_NODAD |
//!   IN6_IFF_SECURED` and `ND6_INFINITE_LIFETIME` (lines 204-232, 298-340).
//!
//! The 4-byte-header codec, the sockaddr/ifaliasreq layouts and the ioctl
//! numbers live in [`super::device::abi`] and are unit-tested on every host;
//! only the syscalls themselves are cfg'd to macOS here.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::os::fd::{AsRawFd, RawFd};

use crate::error::{Error, Result};

use super::device::abi::{
    self, CtlInfo, IfAliasReq, IfAliasReq6, SockaddrCtl, DARWIN_CTLIOCGINFO, DARWIN_SYSPROTO_CONTROL,
    DARWIN_UTUN_OPT_IFNAME,
};

/// Smallest MTU we accept — mirrors the Linux backend's RFC 791 floor.
const MIN_MTU: u16 = 576;
/// `struct iovec` count for the two-part utun write (header + packet).
const TX_IOVS: usize = 2;

/// An attached utun interface. Dropping it closes the control socket, which
/// destroys the interface.
pub struct TunDevice {
    fd: RawFd,
    name: String,
}

impl TunDevice {
    /// Attach to (creating it if needed) the utun unit in `name`:
    /// `""` or `"utun"` lets the kernel pick the first free unit;
    /// `"utun7"` requests unit 7 (sent on the wire as `sc_unit = 8`,
    /// wireguard-go tun_darwin.go:87-92, 109). Any other shape is a config
    /// error — utun interfaces only ever have these names.
    pub fn open(name: &str) -> Result<TunDevice> {
        let unit: u32 = match name {
            "" | "utun" => 0, // kernel-assigned
            _ => {
                let Some(rest) = name.strip_prefix("utun") else {
                    return Err(Error::config(format!(
                        "tun: interface name {name:?} must be utun[0-9]* on macOS"
                    )));
                };
                match rest.parse::<u32>() {
                    Ok(n) => n,
                    _ => {
                        return Err(Error::config(format!(
                            "tun: interface name {name:?} must be utun[0-9]* on macOS"
                        )))
                    }
                }
            }
        };

        // wireguard-go tun_darwin.go:94 — AF_SYSTEM + SOCK_DGRAM + SYSPROTO_CONTROL.
        // macOS has no SOCK_CLOEXEC; set the flag after, exactly like
        // wireguard-go's socketCloexec (tun_darwin.go:310-320).
        let fd = unsafe {
            libc::socket(
                abi::DARWIN_AF_SYSTEM as libc::c_int,
                libc::SOCK_DGRAM,
                DARWIN_SYSPROTO_CONTROL as libc::c_int,
            )
        };
        if fd < 0 {
            return Err(Error::network(format!(
                "tun: socket(AF_SYSTEM, SYSPROTO_CONTROL): {}",
                io::Error::last_os_error()
            )));
        }
        let cleanup = |fd: RawFd| unsafe { libc::close(fd) };
        if unsafe { libc::fcntl(fd, libc::F_SETFD, libc::FD_CLOEXEC) } < 0 {
            let e = io::Error::last_os_error();
            cleanup(fd);
            return Err(Error::network(format!("tun: fcntl(FD_CLOEXEC): {e}")));
        }

        // CTLIOCGINFO: control name -> kernel-assigned control id
        // (wireguard-go tun_darwin.go:99-105).
        let mut info = CtlInfo::for_utun();
        let rc = unsafe {
            libc::ioctl(
                fd,
                DARWIN_CTLIOCGINFO as libc::c_ulong,
                &mut info as *mut CtlInfo,
            )
        };
        if rc < 0 {
            let e = io::Error::last_os_error();
            cleanup(fd);
            return Err(Error::network(format!(
                "tun: CTLIOCGINFO({}): {e}{}",
                String::from_utf8_lossy(abi::DARWIN_UTUN_CONTROL_NAME),
                if e.kind() == io::ErrorKind::PermissionDenied {
                    " (needs root)"
                } else {
                    ""
                }
            )));
        }

        // connect(2) with sockaddr_ctl; sc_unit = requested index + 1
        // (wireguard-go tun_darwin.go:107-116, sing-tun tun_darwin.go:242-248).
        let sc = SockaddrCtl::new(info.ctl_id, unit + 1);
        let rc = unsafe {
            libc::connect(
                fd,
                &sc as *const SockaddrCtl as *const libc::sockaddr,
                std::mem::size_of::<SockaddrCtl>() as libc::socklen_t,
            )
        };
        if rc < 0 {
            let e = io::Error::last_os_error();
            cleanup(fd);
            return Err(Error::network(format!(
                "tun: connect(utun unit {}): {e}",
                unit + 1
            )));
        }

        // Nonblocking (wireguard-go tun_darwin.go:118-122, sing-tun
        // tun_darwin.go:344-347).
        if unsafe { libc::fcntl(fd, libc::F_SETFL, libc::O_NONBLOCK) } < 0 {
            let e = io::Error::last_os_error();
            cleanup(fd);
            return Err(Error::network(format!("tun: fcntl(O_NONBLOCK): {e}")));
        }

        // Read the real name back: getsockopt(SYSPROTO_CONTROL,
        // UTUN_OPT_IFNAME) (wireguard-go tun_darwin.go:179-194, sing-tun
        // tun_darwin.go:86-92).
        let mut nbuf = [0u8; 64];
        let mut len = nbuf.len() as libc::socklen_t;
        let rc = unsafe {
            libc::getsockopt(
                fd,
                DARWIN_SYSPROTO_CONTROL as libc::c_int,
                DARWIN_UTUN_OPT_IFNAME,
                nbuf.as_mut_ptr() as *mut libc::c_void,
                &mut len,
            )
        };
        if rc < 0 {
            let e = io::Error::last_os_error();
            cleanup(fd);
            return Err(Error::network(format!("tun: getsockopt(UTUN_OPT_IFNAME): {e}")));
        }
        let actual = nbuf[..(len as usize).min(nbuf.len())]
            .iter()
            .take_while(|&&b| b != 0)
            .copied()
            .collect::<Vec<u8>>();
        let actual = String::from_utf8_lossy(&actual).into_owned();
        Ok(TunDevice { fd, name: actual })
    }

    /// Read one packet. The kernel hands over the 4-byte address-family
    /// header followed by the IP packet (wireguard-go tun_darwin.go:204-220
    /// reads at `offset - 4` and reports `n - 4`; sing-tun truncates
    /// `PacketOffset` the same way, tun_darwin.go:387); the header is
    /// stripped in place, so `buf` needs 4 bytes of headroom beyond the MTU.
    /// `WouldBlock` when nothing is queued; a datagram whose family is
    /// neither AF_INET nor AF_INET6 is consumed and dropped (0 bytes).
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let n = unsafe {
            libc::read(
                self.fd,
                buf.as_mut_ptr() as *mut libc::c_void,
                buf.len() as libc::size_t,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        let n = n as usize;
        match abi::utun_strip(buf, n) {
            Some(payload) => Ok(payload),
            // Either a sub-header read or a family we do not route; both are
            // consumed (the datagram is out of the socket) and reported as
            // "no packet", which the netstack drain loop treats as a pause.
            None => Ok(0),
        }
    }

    /// Hand one packet to the kernel, prepending the 4-byte family header in
    /// a `writev` (sing-tun's two-iovec layout, tun_darwin.go:59-73, 411-438;
    /// wireguard-go tun_darwin.go:222-244 fills `buf[offset-4..]`). A full
    /// socket queue yields `WouldBlock` and the caller drops the packet.
    pub fn send(&self, pkt: &[u8]) -> io::Result<()> {
        let Some(hdr) = abi::utun_header(pkt) else {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "utun: packet is neither IPv4 nor IPv6",
            ));
        };
        let iovs = [
            libc::iovec {
                iov_base: hdr.as_ptr() as *mut libc::c_void,
                iov_len: hdr.len(),
            },
            libc::iovec {
                iov_base: pkt.as_ptr() as *mut libc::c_void,
                iov_len: pkt.len(),
            },
        ];
        let n = unsafe {
            libc::writev(
                self.fd,
                iovs.as_ptr(),
                TX_IOVS as libc::c_int,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        if n as usize != hdr.len() + pkt.len() {
            // A utun socket writes datagrams whole; anything else is a bug.
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "utun: short write",
            ));
        }
        Ok(())
    }

    /// The interface name as assigned by the kernel (`utunN`).
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

/// `ifreq` with `ifr_name` set (everything else zeroed) — darwin flavor:
/// `IFNAMSIZ` is 16 like Linux, but the socketaddrs carry `sa_len`.
fn make_ifreq(name: &str) -> Result<libc::ifreq> {
    if name.len() >= 16 {
        return Err(Error::config(format!(
            "tun: interface name {name:?} is longer than 15 bytes"
        )));
    }
    let mut req: libc::ifreq = unsafe { std::mem::zeroed() };
    for (i, b) in name.as_bytes().iter().enumerate() {
        req.ifr_name[i] = *b as libc::c_char;
    }
    Ok(req)
}

fn ioctl_mut<T>(fd: RawFd, request: libc::c_ulong, arg: *mut T) -> io::Result<()> {
    let rc = unsafe { libc::ioctl(fd, request, arg as *mut libc::c_void) };
    if rc < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn iface_err(name: &str, op: &str, e: io::Error) -> Error {
    Error::network(format!("tun: {op} {name:?}: {e}"))
}

/// Assign `addr / prefix` and `mtu` to interface `name` (a `utunN`), then
/// bring it up — the macOS twin of the Linux
/// [`configure_interface`](super::device_linux::configure_interface).
///
/// * MTU: `SIOCSIFMTU` with an ifreq (sing-tun tun_darwin.go:250-258,
///   wireguard-go tun_darwin.go:263-284).
/// * Address: `SIOCAIFADDR` with `ifaliasreq { name, addr, dstaddr=addr,
///   mask }` on an AF_INET socket (sing-tun tun_darwin.go:262-297).
/// * Up: `SIOCGIFFLAGS` -> `SIOCSIFFLAGS` read-modify-write with
///   `IFF_UP | IFF_RUNNING`, mirroring the Linux path — the utun comes up by
///   itself once connected, so this is a no-op confirmation.
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
        // MTU first, address second — sing-tun's order (tun_darwin.go:250+).
        let mut req = make_ifreq(name)?;
        req.ifr_ifru.ifru_mtu = mtu as libc::c_int;
        ioctl_mut(sock, abi::DARWIN_SIOCSIFMTU as libc::c_ulong, &mut req)
            .map_err(|e| iface_err(name, "SIOCSIFMTU", e))?;

        // The whole v4 address in one ifaliasreq (sing-tun tun_darwin.go:262-297).
        let mut alias = IfAliasReq::new(name, addr, prefix)
            .ok_or_else(|| Error::config(format!("tun: bad address {addr}/{prefix}")))?;
        ioctl_mut(sock, abi::DARWIN_SIOCAIFADDR as libc::c_ulong, &mut alias)
            .map_err(|e| iface_err(name, "SIOCAIFADDR", e))?;

        // Up: read-modify-write the flags so point-to-point bits survive
        // (the Linux path's last step, kept for symmetry).
        let mut req = make_ifreq(name)?;
        ioctl_mut(sock, abi::DARWIN_SIOCGIFFLAGS as libc::c_ulong, &mut req)
            .map_err(|e| iface_err(name, "SIOCGIFFLAGS", e))?;
        let flags = unsafe { req.ifr_ifru.ifru_flags } as libc::c_int;
        let mut req = make_ifreq(name)?;
        req.ifr_ifru.ifru_flags = (flags | libc::IFF_UP | libc::IFF_RUNNING) as libc::c_short;
        ioctl_mut(sock, abi::DARWIN_SIOCSIFFLAGS as libc::c_ulong, &mut req)
            .map_err(|e| iface_err(name, "SIOCSIFFLAGS", e))?;
        Ok(())
    })();
    unsafe { libc::close(sock) };
    res
}

/// Assign `addr / prefix` as an IPv6 address of interface `name` via
/// `SIOCAIFADDR_IN6` on an AF_INET6 socket — sing-tun tun_darwin.go:298-340:
/// the `ifAliasReq6` carries the address, the prefix mask, NODAD|SECURED
/// flags and infinite lifetimes; a /128 also carries the numerically-next
/// address as the point-to-point destination (tun_darwin.go:317-323).
///
/// Call after [`configure_interface`], like the Linux twin.
pub fn assign_inet6(name: &str, addr: Ipv6Addr, prefix: u8) -> Result<()> {
    if prefix > 128 {
        return Err(Error::config(format!(
            "tun: /{prefix} is not a valid IPv6 prefix length"
        )));
    }
    let sock = unsafe { libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0) };
    if sock < 0 {
        return Err(Error::network(format!(
            "tun: ifconfig inet6 socket: {}",
            io::Error::last_os_error()
        )));
    }
    let mut alias = IfAliasReq6::new(name, addr, prefix)
        .ok_or_else(|| Error::config(format!("tun: bad interface name {name:?}")))?;
    let rc = ioctl_mut(
        sock,
        abi::DARWIN_SIOCAIFADDR_IN6 as libc::c_ulong,
        &mut alias,
    )
    .map_err(|e| iface_err(name, "SIOCAIFADDR_IN6", e));
    unsafe { libc::close(sock) };
    rc
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The utun unit parser's rejects: wireguard-go accepts `utun`, `utunN`
    /// or a kernel-picked unit (tun_darwin.go:87-92) and nothing else; the
    /// rejects fail before any syscall, so they are observable on any host
    /// (this test runs under a macOS `cargo test`).
    #[test]
    fn unit_names_parse_like_wireguard_go() {
        for bad in [
            "tun0",
            "utunx",
            "utun-1",
            "utun_1",
            "wg0",
            "utun99999999999999999999",
            "utun 1",
        ] {
            let err = TunDevice::open(bad).err().map(|e| e.to_string());
            assert!(
                err.is_some_and(|e| e.contains("utun[0-9]*")),
                "{bad:?} must be a config error, got {err:?}"
            );
        }
    }
}
