//! Windows TUN device plumbing: the WinTUN ring-buffer adapter, driven
//! through `wintun.dll` loaded at runtime — no compile-time dependency, the
//! DLL ships next to the user's binary exactly as the official WireGuard
//! clients ship it (wintun.h: "Wintun is a single-file driver + DLL";
//! wireguard-windows embeds and extracts the same DLL).
//!
//! ## API shape
//!
//! The ten exported entry points are declared as `unsafe extern "system"`
//! function-pointer types transcribed one-for-one from
//! WireGuard/wintun `api/wintun.h` (see each type below for its header
//! lines), resolved with `GetProcAddress` after a `LoadLibraryW("wintun.dll")`
//! (or `$WINTUN_DLL`). The loader itself is the stable Win32 trio
//! `LoadLibraryW`/`GetProcAddress`/`FreeLibrary` from kernel32, linked the
//! ordinary way.
//!
//! ## io model
//!
//! `recv` polls `WintunReceivePacket`; `ERROR_NO_MORE_ITEMS` (232) means the
//! ring is drained and is reported as `WouldBlock`, the same contract a
//! non-blocking Linux tun fd gives (wintun.h:194-197 says to wait on the
//! session's read event then retry — [`TunDevice::read_wait_event`] exposes
//! that event for a future readiness integration). `send` copies into a
//! `WintunAllocateSendPacket` slot and hands it to `WintunSendPacket`; a full
//! ring (`ERROR_BUFFER_OVERFLOW`, 234) is `WouldBlock`, and the caller drops
//! the packet — what a full Linux tun tx queue does.
//!
//! Address/netmask/MTU go through the IP Helper API (`iphlpapi.dll`,
//! `CreateUnicastIpAddressEntry` + `Get/SetIpInterfaceEntry`), the same calls
//! wireguard-windows' `winipcfg` package drives; the interface is identified
//! by its LUID (`WintunGetAdapterLuid`), so `configure_interface`/
//! `assign_inet6` take a LUID where the Linux twins take a name.

use std::ffi::c_void;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::OnceLock;

use crate::error::{Error, Result};

use super::device::abi::{
    self, Guid, MibIpInterfaceRow, MibUnicastIpAddressRow, WIN_ERROR_BUFFER_OVERFLOW,
    WIN_ERROR_NO_MORE_ITEMS, WIN_ERROR_OBJECT_ALREADY_EXISTS, WINTUN_MAX_IP_PACKET_SIZE,
};

/// Smallest MTU we accept — mirrors the Linux backend's RFC 791 floor.
const MIN_MTU: u16 = 576;
/// `ERROR_NOT_FOUND` — the interface has no row of that family yet (v6
/// before [`assign_inet6`]); tolerated on the best-effort v6 MTU set.
const WIN_ERROR_NOT_FOUND: u32 = 1168;

// -- kernel32: the loader (stable Win32, linked at build time) --------------

#[link(name = "kernel32")]
extern "system" {
    fn LoadLibraryW(name: *const u16) -> *mut c_void;
    fn GetProcAddress(module: *mut c_void, name: *const u8) -> *mut c_void;
    fn FreeLibrary(module: *mut c_void) -> i32;
}

// -- wintun.dll: resolved at runtime, signatures from api/wintun.h ----------

/// `WINTUN_CREATE_ADAPTER_FUNC` (wintun.h:64-65): creates the adapter.
type WintunCreateAdapterFn =
    unsafe extern "system" fn(name: *const u16, tunnel_type: *const u16, requested_guid: *const Guid) -> *mut c_void;
/// `WINTUN_OPEN_ADAPTER_FUNC` (wintun.h:80): opens an existing one.
type WintunOpenAdapterFn = unsafe extern "system" fn(name: *const u16) -> *mut c_void;
/// `WINTUN_CLOSE_ADAPTER_FUNC` (wintun.h:87): closes, and removes adapters
/// this process created.
type WintunCloseAdapterFn = unsafe extern "system" fn(adapter: *mut c_void);
/// `WINTUN_GET_ADAPTER_LUID_FUNC` (wintun.h:105): LUID out-param.
type WintunGetAdapterLuidFn = unsafe extern "system" fn(adapter: *mut c_void, luid: *mut u64);
/// `WINTUN_START_SESSION_FUNC` (wintun.h:179): ring-capacity session.
type WintunStartSessionFn = unsafe extern "system" fn(adapter: *mut c_void, capacity: u32) -> *mut c_void;
/// `WINTUN_END_SESSION_FUNC` (wintun.h:186).
type WintunEndSessionFn = unsafe extern "system" fn(session: *mut c_void);
/// `WINTUN_GET_READ_WAIT_EVENT_FUNC` (wintun.h:198): the ring's read event.
type WintunGetReadWaitEventFn = unsafe extern "system" fn(session: *mut c_void) -> *mut c_void;
/// `WINTUN_RECEIVE_PACKET_FUNC` (wintun.h:224): pointer into the ring until
/// the matching release call.
type WintunReceivePacketFn = unsafe extern "system" fn(session: *mut c_void, size: *mut u32) -> *mut u8;
/// `WINTUN_RELEASE_RECEIVE_PACKET_FUNC` (wintun.h:234).
type WintunReleaseReceivePacketFn = unsafe extern "system" fn(session: *mut c_void, packet: *const u8);
/// `WINTUN_ALLOCATE_SEND_PACKET_FUNC` (wintun.h:255): writable slot in the
/// send ring.
type WintunAllocateSendPacketFn = unsafe extern "system" fn(session: *mut c_void, size: u32) -> *mut u8;
/// `WINTUN_SEND_PACKET_FUNC` (wintun.h:266).
type WintunSendPacketFn = unsafe extern "system" fn(session: *mut c_void, packet: *const u8);

/// The ten resolved entry points plus the module handle.
struct Wintun {
    module: *mut c_void,
    create_adapter: WintunCreateAdapterFn,
    open_adapter: WintunOpenAdapterFn,
    close_adapter: WintunCloseAdapterFn,
    get_adapter_luid: WintunGetAdapterLuidFn,
    start_session: WintunStartSessionFn,
    end_session: WintunEndSessionFn,
    get_read_wait_event: WintunGetReadWaitEventFn,
    receive_packet: WintunReceivePacketFn,
    release_receive_packet: WintunReleaseReceivePacketFn,
    allocate_send_packet: WintunAllocateSendPacketFn,
    send_packet: WintunSendPacketFn,
}

/// One module-wide load; every [`TunDevice`] shares it.
static WINTUN: OnceLock<Option<Wintun>> = OnceLock::new();

/// A NUL-terminated UTF-16 string, as the wide-char Win32 APIs take.
fn wide(s: &str) -> Vec<u16> {
    s.encode_utf16().chain(std::iter::once(0)).collect()
}

impl Wintun {
    /// Resolve every entry point; `None` (with the reason logged) when the
    /// DLL is missing or incomplete.
    fn load() -> Option<Wintun> {
        let path = std::env::var("WINTUN_DLL").unwrap_or_else(|_| "wintun.dll".to_string());
        let module = unsafe { LoadLibraryW(wide(&path).as_ptr()) };
        if module.is_null() {
            tracing::debug!(
                target: "engine",
                "tun: cannot load {path:?}: {} (the WinTUN backend needs wintun.dll \
                 next to the binary, or $WINTUN_DLL pointing at it)",
                io::Error::last_os_error()
            );
            return None;
        }
        let missing = |what: &str| {
            tracing::debug!(target: "engine", "tun: {path:?} has no {what} export");
            None::<Wintun>
        };
        let mut procs: Vec<(&'static [u8], *mut c_void)> = Vec::new();
        for name in [
            b"WintunCreateAdapter\0".as_slice(),
            b"WintunOpenAdapter\0".as_slice(),
            b"WintunCloseAdapter\0".as_slice(),
            b"WintunGetAdapterLuid\0".as_slice(),
            b"WintunStartSession\0".as_slice(),
            b"WintunEndSession\0".as_slice(),
            b"WintunGetReadWaitEvent\0".as_slice(),
            b"WintunReceivePacket\0".as_slice(),
            b"WintunReleaseReceivePacket\0".as_slice(),
            b"WintunAllocateSendPacket\0".as_slice(),
            b"WintunSendPacket\0".as_slice(),
        ] {
            let p = unsafe { GetProcAddress(module, name.as_ptr()) };
            if p.is_null() {
                return missing(&String::from_utf8_lossy(&name[..name.len() - 1]));
            }
            procs.push((name, p));
        }
        // SAFETY: GetProcAddress returns FARPROC; every target type is the
        // documented signature of exactly the named export (wintun.h).
        let f = |i: usize| procs[i].1;
        Some(Wintun {
            module,
            // SAFETY: see above; indices follow the name list.
            create_adapter: unsafe { std::mem::transmute::<*mut c_void, WintunCreateAdapterFn>(f(0)) },
            open_adapter: unsafe { std::mem::transmute::<*mut c_void, WintunOpenAdapterFn>(f(1)) },
            close_adapter: unsafe { std::mem::transmute::<*mut c_void, WintunCloseAdapterFn>(f(2)) },
            get_adapter_luid: unsafe { std::mem::transmute::<*mut c_void, WintunGetAdapterLuidFn>(f(3)) },
            start_session: unsafe { std::mem::transmute::<*mut c_void, WintunStartSessionFn>(f(4)) },
            end_session: unsafe { std::mem::transmute::<*mut c_void, WintunEndSessionFn>(f(5)) },
            get_read_wait_event: unsafe {
                std::mem::transmute::<*mut c_void, WintunGetReadWaitEventFn>(f(6))
            },
            receive_packet: unsafe { std::mem::transmute::<*mut c_void, WintunReceivePacketFn>(f(7)) },
            release_receive_packet: unsafe {
                std::mem::transmute::<*mut c_void, WintunReleaseReceivePacketFn>(f(8))
            },
            allocate_send_packet: unsafe {
                std::mem::transmute::<*mut c_void, WintunAllocateSendPacketFn>(f(9))
            },
            send_packet: unsafe { std::mem::transmute::<*mut c_void, WintunSendPacketFn>(f(10)) },
        })
    }

    /// The process-wide instance, or a clear error naming the DLL.
    fn shared() -> Result<&'static Wintun> {
        WINTUN
            .get_or_init(Wintun::load)
            .as_ref()
            .ok_or_else(|| {
                Error::network(
                    "tun: wintun.dll is not loadable (place it next to the executable or set \
                     WINTUN_DLL; it ships with the official WireGuard clients)",
                )
            })
    }
}

impl Drop for Wintun {
    fn drop(&mut self) {
        unsafe { FreeLibrary(self.module) };
    }
}

// SAFETY: the struct is a Win32 module handle plus function pointers into
// it, both valid and callable from any thread for the process's lifetime
// (the Win32 loader contract; wintun.h documents its calls thread-safe), so
// the process-wide static below is sound.
unsafe impl Send for Wintun {}
unsafe impl Sync for Wintun {}

// -- the device -------------------------------------------------------------

/// An attached WinTUN adapter with a live session. Dropping it ends the
/// session and closes (removing, when we created it) the adapter.
pub struct TunDevice {
    api: &'static Wintun,
    adapter: *mut c_void,
    session: *mut c_void,
    name: String,
    /// Ring capacity the session started with (diagnostics).
    ring: u32,
}

// SAFETY: every Wintun session call we make is documented thread-safe
// (wintun.h:207 "This function is thread-safe", likewise for send/release);
// the handles are pointers, not Rust-owned data.
unsafe impl Send for TunDevice {}
unsafe impl Sync for TunDevice {}

impl TunDevice {
    /// Attach to the adapter `name`, creating it if it does not exist, and
    /// start a ring session on it (wintun.h's create-or-open pattern, the
    /// one wireguard-windows uses).
    pub fn open(name: &str) -> Result<TunDevice> {
        let api = Wintun::shared()?;
        let wname = wide(name);
        // SAFETY: valid UTF-16 strings; a null return is the documented
        // failure (GetLastError speaks through io::Error).
        let mut adapter = unsafe { (api.open_adapter)(wname.as_ptr()) };
        if adapter.is_null() {
            adapter = unsafe { (api.create_adapter)(wname.as_ptr(), wide("WireGuard").as_ptr(), std::ptr::null()) };
            if adapter.is_null() {
                return Err(Error::network(format!(
                    "tun: WintunCreateAdapter {name:?}: {} (the driver must be installed once; \
                     the official clients bundle the same DLL)",
                    io::Error::last_os_error()
                )));
            }
        }
        let capacity = abi::wintun_default_ring_capacity();
        // SAFETY: adapter came from open/create above.
        let session = unsafe { (api.start_session)(adapter, capacity) };
        if session.is_null() {
            let e = io::Error::last_os_error();
            unsafe { (api.close_adapter)(adapter) };
            return Err(Error::network(format!(
                "tun: WintunStartSession({capacity:#x}): {e}"
            )));
        }
        Ok(TunDevice {
            api,
            adapter,
            session,
            name: name.to_string(),
            ring: capacity,
        })
    }

    /// Read one packet from the ring into `buf`; an empty ring is
    /// `WouldBlock` (wintun.h:194-197's ERROR_NO_MORE_ITEMS contract).
    pub fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        let mut size: u32 = 0;
        // SAFETY: session is live for &self; size is a valid out-param.
        let pkt = unsafe { (self.api.receive_packet)(self.session, &mut size) };
        if pkt.is_null() {
            let e = io::Error::last_os_error();
            return Err(if e.raw_os_error() == Some(WIN_ERROR_NO_MORE_ITEMS) {
                io::Error::new(io::ErrorKind::WouldBlock, "wintun ring drained")
            } else {
                e
            });
        }
        let n = size as usize;
        if n > buf.len() {
            // Cannot happen with an MTU-sized buffer; release the slot
            // regardless — the ring must not leak ring space.
            // SAFETY: pkt came from receive_packet on this session.
            unsafe { (self.api.release_receive_packet)(self.session, pkt) };
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "wintun packet larger than the read buffer",
            ));
        }
        // SAFETY: pkt[..n] is readable ring memory until the release below.
        unsafe {
            std::ptr::copy_nonoverlapping(pkt, buf.as_mut_ptr(), n);
            (self.api.release_receive_packet)(self.session, pkt);
        }
        Ok(n)
    }

    /// Hand one packet to the kernel. A full send ring is `WouldBlock`; the
    /// caller drops the packet, as the Linux backend does on `EAGAIN`.
    pub fn send(&self, pkt: &[u8]) -> io::Result<()> {
        if pkt.len() > WINTUN_MAX_IP_PACKET_SIZE {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "wintun packet over WINTUN_MAX_IP_PACKET_SIZE",
            ));
        }
        // SAFETY: session is live; the slot is pkt.len() writable bytes.
        let slot = unsafe { (self.api.allocate_send_packet)(self.session, pkt.len() as u32) };
        if slot.is_null() {
            let e = io::Error::last_os_error();
            return Err(if e.raw_os_error() == Some(WIN_ERROR_BUFFER_OVERFLOW) {
                io::Error::new(io::ErrorKind::WouldBlock, "wintun send ring full")
            } else {
                e
            });
        }
        // SAFETY: slot[..len] writable; send consumes it.
        unsafe {
            std::ptr::copy_nonoverlapping(pkt.as_ptr(), slot, pkt.len());
            (self.api.send_packet)(self.session, slot);
        }
        Ok(())
    }

    /// The adapter name as configured.
    pub fn name(&self) -> &str {
        &self.name
    }

    /// The adapter's interface LUID — the handle the IP Helper APIs below
    /// identify interfaces by (wintun.h:99-105).
    pub fn luid(&self) -> u64 {
        let mut luid: u64 = 0;
        // SAFETY: adapter is live; luid is a valid out-param.
        unsafe { (self.api.get_adapter_luid)(self.adapter, &mut luid) };
        luid
    }

    /// The session's read-wait event (wintun.h:190-198): signaled when the
    /// ring has data after ERROR_NO_MORE_ITEMS. A future readiness layer
    /// waits on this the way the Linux backend waits on the fd.
    pub fn read_wait_event(&self) -> *mut c_void {
        // SAFETY: session is live; the event is owned by the session.
        unsafe { (self.api.get_read_wait_event)(self.session) }
    }

    /// The ring capacity the session started with (diagnostics).
    pub fn ring_capacity(&self) -> u32 {
        self.ring
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        // SAFETY: both handles are live until here and each call is
        // exactly-once by construction (Drop).
        unsafe {
            (self.api.end_session)(self.session);
            (self.api.close_adapter)(self.adapter);
        }
    }
}

// -- address / MTU configuration (iphlpapi, linked at build time) -----------

#[link(name = "iphlpapi")]
extern "system" {
    /// netioapi.h: fill a row with API defaults before the fields we set.
    fn InitializeUnicastIpAddressEntry(row: *mut MibUnicastIpAddressRow);
    /// netioapi.h: NETIO_STATUS (u32; 0 = success).
    fn CreateUnicastIpAddressEntry(row: *const MibUnicastIpAddressRow) -> u32;
    /// netioapi.h: initialize the per-family interface row.
    fn InitializeIpInterfaceEntry(row: *mut MibIpInterfaceRow);
    /// netioapi.h: fetch the row (keyed by family + LUID).
    fn GetIpInterfaceEntry(row: *mut MibIpInterfaceRow) -> u32;
    /// netioapi.h: write it back (mutable row, unlike the unicast twin).
    fn SetIpInterfaceEntry(row: *mut MibIpInterfaceRow) -> u32;
}

/// Set one address row: LUID + family address + on-link prefix, infinite
/// lifetimes — the wireguard-windows `winipcfg` shape. An already-assigned
/// address is success (the idempotent re-run).
fn add_unicast(row: &mut MibUnicastIpAddressRow) -> Result<()> {
    // SAFETY: rows are the documented argument types, fully initialized by
    // the Initialize call plus the fields we set.
    unsafe {
        InitializeUnicastIpAddressEntry(row);
        let rc = CreateUnicastIpAddressEntry(row);
        if rc != 0 && rc != WIN_ERROR_OBJECT_ALREADY_EXISTS {
            return Err(Error::network(format!(
                "tun: CreateUnicastIpAddressEntry failed with win32 error {rc}"
            )));
        }
    }
    Ok(())
}

/// Set the interface (per-family) MTU via the read-modify-write the IP Helper
/// requires. `tolerate_missing` lets the v6 attempt run before any v6 address
/// exists.
fn set_mtu(luid: u64, family: u16, mtu: u16, tolerate_missing: bool) -> Result<()> {
    // SAFETY: same argument contract as add_unicast.
    unsafe {
        let mut row = MibIpInterfaceRow::zeroed();
        InitializeIpInterfaceEntry(&mut row);
        row.family = family;
        row.interface_luid = luid;
        let rc = GetIpInterfaceEntry(&mut row);
        if rc != 0 {
            if tolerate_missing && rc == WIN_ERROR_NOT_FOUND {
                return Ok(());
            }
            return Err(Error::network(format!(
                "tun: GetIpInterfaceEntry(family {family}) failed with win32 error {rc}"
            )));
        }
        row.nl_mtu = mtu.max(MIN_MTU) as u32;
        let rc = SetIpInterfaceEntry(&mut row);
        if rc != 0 {
            return Err(Error::network(format!(
                "tun: SetIpInterfaceEntry(mtu {}) failed with win32 error {rc}",
                row.nl_mtu
            )));
        }
    }
    Ok(())
}

/// Assign `addr / prefix` and `mtu` to the interface with LUID `luid`, then
/// make sure it is usable — the Windows twin of the Linux
/// [`configure_interface`](super::device_linux::configure_interface). A
/// WinTUN adapter is "connected" while a session runs, so there is no
/// explicit IFF_UP step here. The v6 MTU row is best-effort (it does not
/// exist until [`assign_inet6`] adds a v6 address).
pub fn configure_interface(luid: u64, addr: Ipv4Addr, prefix: u8, mtu: u16) -> Result<()> {
    if prefix > 32 {
        return Err(Error::config(format!(
            "tun: netmask /{prefix} is not a valid IPv4 prefix length"
        )));
    }
    let mut row = MibUnicastIpAddressRow::zeroed();
    row.address = abi::sockaddr_inet_v4(addr);
    row.interface_luid = luid;
    row.on_link_prefix_length = prefix;
    row.valid_lifetime = u32::MAX;
    row.preferred_lifetime = u32::MAX;
    add_unicast(&mut row)?;
    set_mtu(luid, abi::WIN_AF_INET, mtu, false)?;
    set_mtu(luid, abi::WIN_AF_INET6, mtu, true)
}

/// Assign `addr / prefix` as an IPv6 address of the interface with LUID
/// `luid` — the twin of the Linux [`assign_inet6`](super::device_linux::assign_inet6).
pub fn assign_inet6(luid: u64, addr: Ipv6Addr, prefix: u8) -> Result<()> {
    if prefix > 128 {
        return Err(Error::config(format!(
            "tun: /{prefix} is not a valid IPv6 prefix length"
        )));
    }
    let mut row = MibUnicastIpAddressRow::zeroed();
    row.address = abi::sockaddr_inet_v6(addr);
    row.interface_luid = luid;
    row.on_link_prefix_length = prefix;
    row.valid_lifetime = u32::MAX;
    row.preferred_lifetime = u32::MAX;
    add_unicast(&mut row)
}
