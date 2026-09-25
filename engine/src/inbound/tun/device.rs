//! TUN device plumbing, dispatched per host OS.
//!
//! | target | backend | upstream the port follows |
//! |---|---|---|
//! | Linux | `/dev/net/tun` + `TUNSETIFF`, ioctl address config (`device_linux`) | this crate (the original backend) |
//! | Windows | WinTUN ring buffer, `wintun.dll` loaded at runtime (`device_windows`) | WireGuard/wintun `api/wintun.h`; wireguard-windows (the DLL ships with the client) |
//! | macOS | utun kernel-control socket (`device_macos`) | WireGuard/wireguard-go `tun/tun_darwin.go`; sagernet/sing-tun `tun_darwin.go` |
//!
//! Every backend exposes the same names: [`TunDevice`] with
//! `open`/`recv`/`send`/`name`, plus [`configure_interface`] and
//! [`assign_inet6`] for address/netmask/MTU/bring-up (Windows identifies the
//! interface by LUID rather than name — the IP Helper API it uses is
//! LUID-based; see `device_windows`).
//!
//! Direction convention everywhere (easy to get backwards): sending into the
//! device injects a packet *into the kernel* as if it had arrived on the
//! interface; receiving returns packets the kernel wants to *send out* of it.
//! `recv` reports an empty queue as `WouldBlock` on every platform, matching
//! the Linux backend's `O_NONBLOCK` reads.
//!
//! The [`abi`] module holds the platform-independent facts of the two new
//! backends — the utun 4-byte address-family header codec, the WinTUN ring
//! capacity rules, and the `#[repr(C)]` layouts of every structure handed to
//! the kernels — so they are compiled (and unit-tested) on every host,
//! including this Linux development machine where the syscalls cannot run.

#[cfg(target_os = "linux")]
pub use super::device_linux::{assign_inet6, configure_interface, TunDevice};
#[cfg(target_os = "macos")]
pub use super::device_macos::{assign_inet6, configure_interface, TunDevice};
#[cfg(target_os = "windows")]
pub use super::device_windows::{assign_inet6, configure_interface, TunDevice};

pub mod abi {
    //! Platform ABI facts for the non-Linux backends: sizes, offsets and
    //! codecs pinned to the platform headers, cited per item. Compiled (and
    //! unit-tested) on every host — this is how a Linux development machine
    //! verifies the Windows/macOS backends — and public so the layouts stay
    //! outside the `dead_code` analysis on hosts whose backend is cfg'd out.

    use std::net::{Ipv4Addr, Ipv6Addr};

    // -----------------------------------------------------------------------
    // macOS: utun kernel control (XNU bsd/kern_control.h, sys/socket.h)
    // -----------------------------------------------------------------------

    /// `com.apple.net.utun_control` (wireguard-go tun_darwin.go:20,
    /// sing-tun tun_darwin.go:202).
    pub const DARWIN_UTUN_CONTROL_NAME: &[u8] = b"com.apple.net.utun_control";

    /// `AF_SYSTEM` (XNU sys/socket.h; the socket(2) domain for kernel
    /// controls).
    pub const DARWIN_AF_SYSTEM: u8 = 32;
    /// `SYSPROTO_CONTROL` — the protocol of an AF_SYSTEM control socket
    /// (wireguard-go tun_darwin.go:94 `unix.Socket(AF_SYSTEM, SOCK_DGRAM, 2)`).
    pub const DARWIN_SYSPROTO_CONTROL: u8 = 2;
    /// `AF_SYS_CONTROL` — the `ss_sysaddr` of a connected control socket
    /// (XNU sys/socket.h `sockaddr_ctl`).
    pub const DARWIN_AF_SYS_CONTROL: u8 = 2;
    /// `CTLIOCGINFO` = `_IOWR('N', 3, struct ctl_info)` = `_IOWR` with
    /// 100-byte `ctl_info` (golang.org/x/sys/unix zerrors_darwin: 0xc0644e03).
    pub const DARWIN_CTLIOCGINFO: u64 = 0xC064_4E03;
    /// `UTUN_OPT_IFNAME` — getsockopt(SYSPROTO_CONTROL) option returning the
    /// interface name (wireguard-go tun_darwin.go:179-194).
    pub const DARWIN_UTUN_OPT_IFNAME: i32 = 2;
    /// `AF_INET` on darwin (same value everywhere).
    pub const DARWIN_AF_INET: u8 = 2;
    /// `AF_INET6` on darwin — 30, NOT the Linux value 10; the utun packet
    /// header carries it, so the codec below must use this constant.
    pub const DARWIN_AF_INET6: u8 = 30;

    /// `SIOCAIFADDR` = `_IOW('i', 26, struct ifaliasreq)` with the 64-byte
    /// `ifaliasreq` (sing-tun tun_darwin.go:286 uses it for utun addresses).
    pub const DARWIN_SIOCAIFADDR: u64 = 0x8040_691A;
    /// `SIOCAIFADDR_IN6` — sing-tun tun_darwin.go:205 declares the literal
    /// 2155899162 (= 0x8080691A) from netinet6/in6_var.h; pinned below.
    pub const DARWIN_SIOCAIFADDR_IN6: u64 = 2_155_899_162;
    /// `SIOCSIFMTU` (x/sys/unix zerrors_darwin: 0x80206934; the libc crate
    /// does not export the SIOCS* family for apple targets).
    pub const DARWIN_SIOCSIFMTU: u64 = 0x8020_6934;
    /// `SIOCGIFFLAGS` (x/sys/unix zerrors_darwin: 0xc0206911).
    pub const DARWIN_SIOCGIFFLAGS: u64 = 0xC020_6911;
    /// `SIOCSIFFLAGS` (x/sys/unix zerrors_darwin: 0x80206910).
    pub const DARWIN_SIOCSIFFLAGS: u64 = 0x8020_6910;
    /// `IN6_IFF_NODAD` (netinet6/in6_var.h, via sing-tun tun_darwin.go:206).
    pub const DARWIN_IN6_IFF_NODAD: u32 = 0x0020;
    /// `IN6_IFF_SECURED` (sing-tun tun_darwin.go:207).
    pub const DARWIN_IN6_IFF_SECURED: u32 = 0x0400;
    /// `ND6_INFINITE_LIFETIME` (netinet6/nd6.h, sing-tun tun_darwin.go:208).
    pub const DARWIN_ND6_INFINITE_LIFETIME: u32 = 0xFFFF_FFFF;

    /// `struct sockaddr_ctl` (XNU sys/socket.h): the connect(2) target of a
    /// utun control socket. `sc_unit` is the requested unit + 1; 0 lets the
    /// kernel pick (wireguard-go tun_darwin.go:107-112).
    #[repr(C)]
    pub struct SockaddrCtl {
        pub sc_len: u8,
        pub sc_family: u8,
        pub ss_sysaddr: u32,
        pub sc_id: u32,
        pub sc_unit: u32,
        pub sc_reserved: [u32; 5],
    }

    impl SockaddrCtl {
        /// A ready-to-connect socket address for kernel-control `id` and
        /// `unit` (unit as passed to connect: requested index + 1, or 0 for
        /// kernel-assigned).
        pub fn new(id: u32, unit: u32) -> Self {
            SockaddrCtl {
                sc_len: std::mem::size_of::<SockaddrCtl>() as u8,
                sc_family: DARWIN_AF_SYSTEM,
                ss_sysaddr: DARWIN_AF_SYS_CONTROL as u32,
                sc_id: id,
                sc_unit: unit,
                sc_reserved: [0; 5],
            }
        }
    }

    /// `struct ctl_info` (XNU sys/kern_control.h): the CTLIOCGINFO argument;
    /// `ctl_name` in, `ctl_id` out.
    #[repr(C)]
    pub struct CtlInfo {
        pub ctl_id: u32,
        pub ctl_name: [u8; 96],
    }

    impl CtlInfo {
        /// A request for [`DARWIN_UTUN_CONTROL_NAME`].
        pub fn for_utun() -> Self {
            let mut info = CtlInfo {
                ctl_id: 0,
                ctl_name: [0; 96],
            };
            info.ctl_name[..DARWIN_UTUN_CONTROL_NAME.len()]
                .copy_from_slice(DARWIN_UTUN_CONTROL_NAME);
            info
        }
    }

    /// darwin `sockaddr_in` (16 bytes; `sin_len` leads — unlike Linux).
    /// Port stays zero: address ioctls only read family + address.
    #[repr(C)]
    pub struct SockaddrIn4Ctl {
        pub len: u8,
        pub family: u8,
        pub port_be: u16,
        pub addr: [u8; 4],
        pub zero: [u8; 8],
    }

    impl SockaddrIn4Ctl {
        pub fn new(addr: Ipv4Addr) -> Self {
            SockaddrIn4Ctl {
                len: 16,
                family: DARWIN_AF_INET,
                port_be: 0,
                addr: addr.octets(),
                zero: [0; 8],
            }
        }
    }

    /// darwin `sockaddr_in6` (28 bytes; `sin6_len` leads).
    #[repr(C)]
    pub struct SockaddrIn6Ctl {
        pub len: u8,
        pub family: u8,
        pub port_be: u16,
        pub flowinfo: u32,
        pub addr: [u8; 16],
        pub scope_id: u32,
    }

    impl SockaddrIn6Ctl {
        pub fn new(addr: Ipv6Addr) -> Self {
            SockaddrIn6Ctl {
                len: 28,
                family: DARWIN_AF_INET6,
                port_be: 0,
                flowinfo: 0,
                addr: addr.octets(),
                scope_id: 0,
            }
        }

        /// The all-ones host mask for a prefix length, as a sockaddr_in6
        /// (`net.CIDRMask(bits, 128)` in sing-tun tun_darwin.go:309).
        pub fn mask(prefix: u8) -> Self {
            let mut m = Ipv6Addr::from([0u8; 16]).octets();
            for i in 0..prefix as usize {
                m[i / 8] |= 0x80 >> (i % 8);
            }
            SockaddrIn6Ctl::new(Ipv6Addr::from(m))
        }
    }

    /// `struct ifaliasreq` — the SIOCAIFADDR argument (sing-tun
    /// tun_darwin.go:211-216). `dstaddr` repeats the address, exactly as
    /// sing-tun fills it (tun_darwin.go:269-274).
    #[repr(C)]
    pub struct IfAliasReq {
        pub name: [u8; 16],
        pub addr: SockaddrIn4Ctl,
        pub dstaddr: SockaddrIn4Ctl,
        pub mask: SockaddrIn4Ctl,
    }

    impl IfAliasReq {
        /// An alias request assigning `addr / prefix` to interface `name`.
        pub fn new(name: &str, addr: Ipv4Addr, prefix: u8) -> Option<Self> {
            if name.len() >= 16 || prefix > 32 {
                return None;
            }
            let mut mask = 0u32;
            if prefix > 0 {
                mask = u32::MAX << (32 - prefix);
            }
            Some(IfAliasReq {
                name: {
                    let mut n = [0u8; 16];
                    n[..name.len()].copy_from_slice(name.as_bytes());
                    n
                },
                addr: SockaddrIn4Ctl::new(addr),
                dstaddr: SockaddrIn4Ctl::new(addr),
                mask: SockaddrIn4Ctl::new(Ipv4Addr::from(mask)),
            })
        }
    }

    /// `struct in6_addrlifetime` — sing-tun's `addrLifetime6`
    /// (tun_darwin.go:227-232; time_t slots carried as 8-byte fields).
    #[repr(C)]
    pub struct AddrLifetime6 {
        pub expire: u64,
        pub preferred: u64,
        pub vltime: u32,
        pub pltime: u32,
    }

    /// `struct in6_aliasreq` — the SIOCAIFADDR_IN6 argument (sing-tun
    /// `ifAliasReq6`, tun_darwin.go:218-225): name, address, [dstaddr,]
    /// prefix mask, flags, lifetime. `__attribute__((aligned(8)))` on the C
    /// side is the natural align of these fields.
    #[repr(C)]
    pub struct IfAliasReq6 {
        pub name: [u8; 16],
        pub addr: SockaddrIn6Ctl,
        pub dstaddr: SockaddrIn6Ctl,
        pub mask: SockaddrIn6Ctl,
        pub flags: u32,
        pub lifetime: AddrLifetime6,
    }

    impl IfAliasReq6 {
        /// An alias request assigning `addr / prefix`, infinite lifetimes,
        /// NODAD|SECURED — the sing-tun shape (tun_darwin.go:300-316). A /128
        /// carries the next address as the point-to-point destination
        /// (tun_darwin.go:317-323).
        pub fn new(name: &str, addr: Ipv6Addr, prefix: u8) -> Option<Self> {
            if name.len() >= 16 || prefix > 128 {
                return None;
            }
            let dst = if prefix == 128 {
                SockaddrIn6Ctl::new(next_ipv6(addr))
            } else {
                SockaddrIn6Ctl::new(addr)
            };
            Some(IfAliasReq6 {
                name: {
                    let mut n = [0u8; 16];
                    n[..name.len()].copy_from_slice(name.as_bytes());
                    n
                },
                addr: SockaddrIn6Ctl::new(addr),
                dstaddr: dst,
                mask: SockaddrIn6Ctl::mask(prefix),
                flags: DARWIN_IN6_IFF_NODAD | DARWIN_IN6_IFF_SECURED,
                lifetime: AddrLifetime6 {
                    expire: 0,
                    preferred: 0,
                    vltime: DARWIN_ND6_INFINITE_LIFETIME,
                    pltime: DARWIN_ND6_INFINITE_LIFETIME,
                },
            })
        }
    }

    /// `addr.Next()` — the numerically following address (sing-tun
    /// tun_darwin.go:321), big-endian increment of the 128-bit value.
    fn next_ipv6(addr: Ipv6Addr) -> Ipv6Addr {
        let mut o = addr.octets();
        for b in o.iter_mut().rev() {
            match b {
                0xff => *b = 0,
                b => {
                    *b += 1;
                    break;
                }
            }
        }
        Ipv6Addr::from(o)
    }

    /// Strip the utun 4-byte address-family header from a `read(2)` of
    /// `n` bytes, moving the IP packet to the buffer front. `None` for a
    /// short read or a family that is neither INET nor INET6 (drop those —
    /// wireguard-go tun_darwin.go:204-220 reads `n - 4`, sing-tun truncates
    /// `PacketOffset = 4` the same way, tun_darwin.go:27,387).
    pub fn utun_strip(buf: &mut [u8], n: usize) -> Option<usize> {
        if n < 4 || n > buf.len() {
            return None;
        }
        match buf[3] {
            DARWIN_AF_INET | DARWIN_AF_INET6 => {}
            _ => return None,
        }
        buf.copy_within(4..n, 0);
        Some(n - 4)
    }

    /// The 4-byte header an outbound utun packet carries: `[0, 0, 0, af]`
    /// with the *darwin* AF value for the packet's IP version (sing-tun
    /// tun_darwin.go:190-195 `packetHeader4`/`packetHeader6`; wireguard-go
    /// tun_darwin.go:226-238 sets `buf[3]` the same way). `None` for a
    /// non-IP packet.
    pub fn utun_header(pkt: &[u8]) -> Option<[u8; 4]> {
        match pkt.first()? >> 4 {
            4 => Some([0, 0, 0, DARWIN_AF_INET]),
            6 => Some([0, 0, 0, DARWIN_AF_INET6]),
            _ => None,
        }
    }

    // -----------------------------------------------------------------------
    // Windows: wintun.dll (WireGuard/wintun api/wintun.h) + IP Helper
    // -----------------------------------------------------------------------

    /// `WINTUN_MIN_RING_CAPACITY` = 128 KiB (wintun.h:153).
    pub const WINTUN_MIN_RING_CAPACITY: u32 = 0x20000;
    /// `WINTUN_MAX_RING_CAPACITY` = 64 MiB (wintun.h:158).
    pub const WINTUN_MAX_RING_CAPACITY: u32 = 0x4000000;
    /// `WINTUN_MAX_IP_PACKET_SIZE` (wintun.h:203).
    pub const WINTUN_MAX_IP_PACKET_SIZE: usize = 0xFFFF;
    /// `ERROR_NO_MORE_ITEMS` — the ring is drained; poll the read-wait event
    /// (wintun.h:194-197). Surfaced as `WouldBlock` to match the Linux fd.
    pub const WIN_ERROR_NO_MORE_ITEMS: i32 = 232;
    /// `ERROR_BUFFER_OVERFLOW` — the send ring is full (wintun.h:250).
    pub const WIN_ERROR_BUFFER_OVERFLOW: i32 = 234;
    /// `ERROR_HANDLE_EOF` — the adapter is terminating (wintun.h:216).
    pub const WIN_ERROR_HANDLE_EOF: i32 = 38;
    /// `ERROR_OBJECT_ALREADY_EXISTS` — CreateUnicastIpAddressEntry when the
    /// address is already assigned (treated as success, like re-running
    /// ifconfig on Linux).
    pub const WIN_ERROR_OBJECT_ALREADY_EXISTS: u32 = 5010;
    /// `AF_INET` for the IP Helper `ADDRESS_FAMILY` (a u16 on Windows).
    pub const WIN_AF_INET: u16 = 2;
    /// `AF_INET6` for the IP Helper (23 — the Windows value).
    pub const WIN_AF_INET6: u16 = 23;

    /// Ring capacity rule from wintun.h:170-172: a power of two within
    /// [WINTUN_MIN_RING_CAPACITY, WINTUN_MAX_RING_CAPACITY].
    pub fn wintun_ring_capacity_ok(cap: u32) -> bool {
        cap.is_power_of_two() && (WINTUN_MIN_RING_CAPACITY..=WINTUN_MAX_RING_CAPACITY).contains(&cap)
    }

    /// The capacity this backend starts sessions with: 4 MiB — the
    /// wireguard-windows service's ring size, well above the minimum and a
    /// rounding-friendly power of two.
    pub fn wintun_default_ring_capacity() -> u32 {
        0x400000
    }

    /// A Windows `GUID` (16 bytes; passed to WintunCreateAdapter — we pass
    /// null so the system picks, but the pointer type needs the layout).
    #[repr(C)]
    pub struct Guid {
        pub data1: u32,
        pub data2: u16,
        pub data3: u16,
        pub data4: [u8; 8],
    }

    /// `SOCKADDR_INET` storage for `MIB_UNICASTIPADDRESS_ROW::Address` — the
    /// union of `sockaddr_in` (16 bytes) and `sockaddr_in6` (28 bytes) as a
    /// flat 28-byte blob; the two `sockaddr_inet_*` fillers below write the
    /// documented member layouts into it at the right offsets.
    pub type SockaddrInetBuf = [u8; 28];

    /// `sockaddr_in` bytes: family(2) port(2) addr(4) zero(8) — no `sin_len`
    /// on Windows (ws2def.h).
    pub fn sockaddr_inet_v4(addr: Ipv4Addr) -> SockaddrInetBuf {
        let mut b = [0u8; 28];
        b[0..2].copy_from_slice(&WIN_AF_INET.to_le_bytes());
        // port stays zero: the row only carries the address.
        b[4..8].copy_from_slice(&addr.octets());
        b
    }

    /// `sockaddr_in6` bytes: family(2) port(2) flowinfo(4) addr(16)
    /// scope_id(4) (ws2ipdef.h).
    pub fn sockaddr_inet_v6(addr: Ipv6Addr) -> SockaddrInetBuf {
        let mut b = [0u8; 28];
        b[0..2].copy_from_slice(&WIN_AF_INET6.to_le_bytes());
        b[8..24].copy_from_slice(&addr.octets());
        b
    }

    /// `MIB_UNICASTIPADDRESS_ROW` (netioapi.h) — the
    /// CreateUnicastIpAddressEntry argument. The 28-byte `SOCKADDR_INET`
    /// union is followed by padding to the 8-byte-aligned `NET_LUID`; the
    /// offsets are pinned by test. Same call path as wireguard-windows'
    /// winipcfg `LUID.AddIPAddress`.
    #[repr(C)]
    pub struct MibUnicastIpAddressRow {
        pub address: SockaddrInetBuf,
        pub interface_luid: u64,
        pub interface_index: u32,
        pub prefix_origin: u32,
        pub suffix_origin: u32,
        pub valid_lifetime: u32,
        pub preferred_lifetime: u32,
        pub on_link_prefix_length: u8,
        pub skip_as_source: u8,
        pub dad_state: u32,
    }

    impl MibUnicastIpAddressRow {
        /// All-zero start; `InitializeUnicastIpAddressEntry` fills the
        /// defaults before we set the fields we care about.
        pub fn zeroed() -> Self {
            // SAFETY: every field is plain old data and zero is a valid
            // pre-initialization state for this C struct.
            unsafe { std::mem::zeroed() }
        }
    }

    /// `MIB_IPINTERFACE_ROW` (netioapi.h) — the Get/SetIpInterfaceEntry
    /// argument; we only read and write `NlMtu`. All-members layout so the
    /// offsets the API expects hold; sizes pinned by test (x64).
    #[allow(clippy::struct_field_names)]
    #[repr(C)]
    pub struct MibIpInterfaceRow {
        pub family: u16,
        pub interface_luid: u64,
        pub interface_index: u32,
        pub max_reassembly_size: u32,
        pub interface_identifier: u64,
        pub min_router_advert_interval: u32,
        pub max_router_advert_interval: u32,
        pub advertising_enabled: u8,
        pub forwarding: u8,
        pub weak_host_send: u8,
        pub weak_host_receive: u8,
        pub use_automatic_metric: u8,
        pub use_neighbor_unreachability_detection: u8,
        pub managed_address_config_supported: u8,
        pub other_stateful_config_supported: u8,
        pub advertise_default_route: u8,
        pub router_discovery_behavior: i32,
        pub dad_transmits: u32,
        pub base_reachable_time: u32,
        pub retransmit_time: u32,
        pub path_mtu_discovery_timeout: u32,
        pub link_local_address_behavior: i32,
        pub link_local_address_timeout: u32,
        pub zone_indices: [u32; 16],
        pub site_prefix_length: u32,
        pub metric: u32,
        pub nl_mtu: u32,
        pub connected: u8,
        pub supports_wake_up_patterns: u8,
        pub supports_neighbor_discovery: u8,
        pub supports_router_discovery: u8,
        pub reachable_time: u32,
        pub transmit_offload: u8,
        pub receive_offload: u8,
        pub disable_default_routes: u8,
    }

    impl MibIpInterfaceRow {
        /// All-zero start; `InitializeIpInterfaceEntry` fills the defaults.
        pub fn zeroed() -> Self {
            // SAFETY: plain old data; zero precedes the Initialize call by
            // contract.
            unsafe { std::mem::zeroed() }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        // -- utun frame codec ------------------------------------------------

        #[test]
        fn utun_header_matches_the_packet_family() {
            let v4 = [0x45, 0, 0, 1];
            let v6 = [0x60, 0, 0, 0];
            assert_eq!(utun_header(&v4), Some([0, 0, 0, 2]));
            assert_eq!(utun_header(&v6), Some([0, 0, 0, 30]), "darwin AF_INET6 is 30");
            assert_eq!(utun_header(&[]), None);
            assert_eq!(utun_header(&[0x00, 1, 2]), None, "not an IP version");
        }

        #[test]
        fn utun_strip_moves_the_packet_forward() {
            let mut buf = [0u8; 16];
            let pkt = [0x45u8, 1, 2, 3, 4];
            buf[..4].copy_from_slice(&[0, 0, 0, DARWIN_AF_INET]);
            buf[4..4 + pkt.len()].copy_from_slice(&pkt);
            let n = utun_strip(&mut buf, 4 + pkt.len()).expect("v4 header strips");
            assert_eq!(&buf[..n], &pkt);
            assert_eq!(n, 5);

            // v6 header uses 30, not the Linux value 10.
            let mut b6 = [0u8; 16];
            b6[..4].copy_from_slice(&[0, 0, 0, DARWIN_AF_INET6]);
            b6[4..8].copy_from_slice(&[0x60, 0, 0, 0]);
            assert_eq!(utun_strip(&mut b6, 8), Some(4));

            // Short reads and foreign families are dropped, not parsed.
            assert_eq!(utun_strip(&mut [0u8; 8], 3), None);
            let mut bad = [0u8; 8];
            bad[3] = 10; // AF_INET6 on Linux — invalid on the wire here
            assert_eq!(utun_strip(&mut bad, 8), None);
            assert_eq!(utun_strip(&mut [0u8; 4], 99), None, "n above the buffer");
        }

        #[test]
        fn utun_roundtrip_header_then_strip() {
            let pkt = [0x60u8, 0x12, 3];
            let hdr = utun_header(&pkt).unwrap();
            let mut buf = [0u8; 8];
            buf[..4].copy_from_slice(&hdr);
            buf[4..7].copy_from_slice(&pkt);
            assert_eq!(utun_strip(&mut buf, 7), Some(3));
            assert_eq!(&buf[..3], &pkt);
        }

        // -- sockaddr layouts -------------------------------------------------

        #[test]
        fn sockaddr_ctl_layout() {
            // XNU sys/socket.h: sc_len + sc_family + 2 pad + 3*4 + 5*4 = 36,
            // align 4.
            assert_eq!(std::mem::size_of::<SockaddrCtl>(), 36);
            let sc = SockaddrCtl::new(0x1122_3344, 5);
            assert_eq!(sc.sc_len, 36);
            assert_eq!(sc.sc_family, DARWIN_AF_SYSTEM);
            assert_eq!(sc.ss_sysaddr, 2);
            assert_eq!(sc.sc_id, 0x1122_3344);
            assert_eq!(sc.sc_unit, 5);
            assert_eq!(std::mem::offset_of!(SockaddrCtl, sc_id), 8);
        }

        #[test]
        fn ctl_info_layout_and_name() {
            // struct ctl_info: u32 id + char name[96] = 100 (XUN kern_control.h).
            assert_eq!(std::mem::size_of::<CtlInfo>(), 100);
            assert_eq!(std::mem::offset_of!(CtlInfo, ctl_name), 4);
            let info = CtlInfo::for_utun();
            let name = info
                .ctl_name
                .iter()
                .take_while(|&&b| b != 0)
                .copied()
                .collect::<Vec<_>>();
            assert_eq!(name, DARWIN_UTUN_CONTROL_NAME);
        }

        #[test]
        fn darwin_sockaddr_sizes() {
            assert_eq!(std::mem::size_of::<SockaddrIn4Ctl>(), 16);
            assert_eq!(std::mem::size_of::<SockaddrIn6Ctl>(), 28);
            let a = SockaddrIn4Ctl::new(Ipv4Addr::new(10, 7, 0, 1));
            assert_eq!((a.len, a.family, a.addr), (16, 2, [10, 7, 0, 1]));
            let m = SockaddrIn6Ctl::mask(120);
            let mut expected = [0xffu8; 16];
            expected[15] = 0;
            assert_eq!(m.addr, expected);
            assert_eq!(SockaddrIn6Ctl::mask(64).addr[..8], [0xff; 8]);
            assert_eq!(SockaddrIn6Ctl::mask(0).addr, [0u8; 16]);
        }

        #[test]
        fn ifaliasreq_layouts_match_sing_tun() {
            // sing-tun tun_darwin.go:211-216: name[16] + three sockaddr_in.
            assert_eq!(std::mem::size_of::<IfAliasReq>(), 64);
            assert_eq!(std::mem::offset_of!(IfAliasReq, addr), 16);
            assert_eq!(std::mem::offset_of!(IfAliasReq, mask), 48);
            let req = IfAliasReq::new("utun7", Ipv4Addr::new(198, 18, 0, 1), 30).unwrap();
            assert_eq!(&req.name[..5], b"utun7");
            assert_eq!(req.mask.addr, [255, 255, 255, 252]);
            assert_eq!(req.dstaddr.addr, req.addr.addr);
            assert!(IfAliasReq::new("an-interface-name-over-16", Ipv4Addr::LOCALHOST, 24).is_none());
            assert!(IfAliasReq::new("utun7", Ipv4Addr::LOCALHOST, 33).is_none());

            // sing-tun tun_darwin.go:218-232: name[16] + three sockaddr_in6 +
            // flags u32 + lifetime{2x8,2x4}, aligned 8 -> 128 total.
            assert_eq!(std::mem::size_of::<IfAliasReq6>(), 128);
            assert_eq!(std::mem::align_of::<IfAliasReq6>(), 8);
            assert_eq!(std::mem::offset_of!(IfAliasReq6, dstaddr), 44);
            assert_eq!(std::mem::offset_of!(IfAliasReq6, mask), 72);
            assert_eq!(std::mem::offset_of!(IfAliasReq6, flags), 100);
            assert_eq!(std::mem::offset_of!(IfAliasReq6, lifetime), 104);
            assert_eq!(std::mem::offset_of!(AddrLifetime6, vltime), 16);
            let req6 = IfAliasReq6::new("utun7", Ipv6Addr::LOCALHOST, 128).unwrap();
            assert_eq!(req6.flags, DARWIN_IN6_IFF_NODAD | DARWIN_IN6_IFF_SECURED);
            assert_eq!(req6.lifetime.vltime, u32::MAX);
            // A /128 carries addr+1 as the point-to-point destination.
            assert_eq!(req6.dstaddr.addr, Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 2).octets());
            assert_eq!(
                IfAliasReq6::new("utun7", Ipv6Addr::LOCALHOST, 64).unwrap().dstaddr.addr,
                Ipv6Addr::LOCALHOST.octets(),
                "non-/128 keeps the address as destination"
            );
        }

        #[test]
        fn sing_tun_ioctl_literals() {
            // 2155899162 == 0x8080691A == _IOW('i', 26, 128-byte ifAliasReq6).
            assert_eq!(DARWIN_SIOCAIFADDR_IN6, 2_155_899_162);
            assert_eq!(DARWIN_SIOCAIFADDR_IN6, 0x8080_691A);
            // The v4 twin: _IOW('i', 26, 64-byte ifaliasreq).
            assert_eq!(DARWIN_SIOCAIFADDR, 0x8040_691A);
            // The ifconfig ioctls the bring-up path drives (values from
            // x/sys/unix zerrors_darwin_amd64.go — the libc crate does not
            // export them for apple).
            assert_eq!(DARWIN_SIOCSIFMTU, 0x8020_6934);
            assert_eq!(DARWIN_SIOCGIFFLAGS, 0xC020_6911);
            assert_eq!(DARWIN_SIOCSIFFLAGS, 0x8020_6910);
            // CTLIOCGINFO = _IOWR('N', 3, 100-byte ctl_info).
            assert_eq!(DARWIN_CTLIOCGINFO, 0xC064_4E03);
            // darwin AF values the packet codec depends on.
            assert_eq!(DARWIN_AF_SYSTEM, 32);
            assert_ne!(DARWIN_AF_INET6, 10, "darwin AF_INET6 must not be the Linux value");
        }

        // -- wintun ring math + IP Helper layouts ------------------------------

        #[test]
        fn wintun_ring_capacity_bounds() {
            assert!(!wintun_ring_capacity_ok(WINTUN_MIN_RING_CAPACITY >> 1));
            assert!(wintun_ring_capacity_ok(WINTUN_MIN_RING_CAPACITY));
            assert!(wintun_ring_capacity_ok(0x100000));
            assert!(wintun_ring_capacity_ok(WINTUN_MAX_RING_CAPACITY));
            assert!(!wintun_ring_capacity_ok(WINTUN_MAX_RING_CAPACITY << 1));
            // Powers of two only.
            assert!(!wintun_ring_capacity_ok(0x20001));
            assert!(!wintun_ring_capacity_ok(0x30000));
            assert!(wintun_ring_capacity_ok(wintun_default_ring_capacity()));
            assert!(wintun_default_ring_capacity() < WINTUN_MAX_RING_CAPACITY);
        }

        #[test]
        fn sockaddr_inet_fillers() {
            let v4 = sockaddr_inet_v4(Ipv4Addr::new(192, 0, 2, 1));
            assert_eq!(&v4[0..2], &2u16.to_le_bytes());
            assert_eq!(&v4[4..8], &[192, 0, 2, 1]);
            assert!(v4[8..].iter().all(|&b| b == 0));
            let v6 = sockaddr_inet_v6(Ipv6Addr::new(0xfd00, 1, 2, 3, 4, 5, 6, 7));
            assert_eq!(&v6[0..2], &23u16.to_le_bytes());
            assert_eq!(&v6[4..8], &[0; 4], "flowinfo zero");
            assert_eq!(&v6[8..24], &Ipv6Addr::new(0xfd00, 1, 2, 3, 4, 5, 6, 7).octets());
            assert_eq!(&v6[24..], &[0; 4], "scope id zero");
        }

        #[test]
        fn unicast_address_row_layout() {
            // netioapi.h (x64): SOCKADDR_INET(28) + pad(4) + NET_LUID@32 +
            // index@40 + origins@44/48 + lifetimes@52/56 + prefix-len@60 +
            // skip@61 + DadState@64 -> 72 with align 8.
            assert_eq!(std::mem::size_of::<MibUnicastIpAddressRow>(), 72);
            assert_eq!(std::mem::align_of::<MibUnicastIpAddressRow>(), 8);
            assert_eq!(std::mem::offset_of!(MibUnicastIpAddressRow, interface_luid), 32);
            assert_eq!(std::mem::offset_of!(MibUnicastIpAddressRow, interface_index), 40);
            assert_eq!(std::mem::offset_of!(MibUnicastIpAddressRow, on_link_prefix_length), 60);
            assert_eq!(std::mem::offset_of!(MibUnicastIpAddressRow, dad_state), 64);
        }

        #[test]
        fn ip_interface_row_layout() {
            // netioapi.h (x64): family@0, LUID@8 (after 2+6 pad), index@16,
            // ZoneIndices@80..144, Metric@148, NlMtu@152, tail (3 bools +
            // u32 + 2 offload bytes + bool) -> 168 with align 8.
            assert_eq!(std::mem::size_of::<MibIpInterfaceRow>(), 168);
            assert_eq!(std::mem::align_of::<MibIpInterfaceRow>(), 8);
            assert_eq!(std::mem::offset_of!(MibIpInterfaceRow, interface_luid), 8);
            assert_eq!(std::mem::offset_of!(MibIpInterfaceRow, interface_index), 16);
            assert_eq!(std::mem::offset_of!(MibIpInterfaceRow, zone_indices), 80);
            assert_eq!(std::mem::offset_of!(MibIpInterfaceRow, metric), 148);
            assert_eq!(std::mem::offset_of!(MibIpInterfaceRow, nl_mtu), 152);
            // The one field the backend writes.
            let mut row = MibIpInterfaceRow::zeroed();
            row.nl_mtu = 1500;
            assert_eq!(row.nl_mtu, 1500);
        }

        #[test]
        fn guid_is_sixteen_bytes() {
            assert_eq!(std::mem::size_of::<Guid>(), 16);
            assert_eq!(std::mem::offset_of!(Guid, data4), 8);
        }
    }
}
