//! Best-effort client process discovery for PROCESS-NAME /
//! PROCESS-PATH / UID / IN-USER rules (Linux): map the connection's
//! source socket to the owning process through `/proc`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Resolved owner of a locally-originated connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessInfo {
    /// Full executable path of the owning process.
    pub exe: String,
    /// Owner uid (real) from `/proc/<pid>/status`.
    pub uid: Option<u32>,
    /// Owner username via `getpwuid_r` (None when the uid has no
    /// passwd entry or the lookup fails).
    pub user: Option<String>,
}

/// Full executable path of the process holding a connection whose
/// local address is `source` (the client side of the socket pair).
/// `tcp` selects the /proc/net/tcp(6) or udp(6) table.
pub fn find_by_socket(source: SocketAddr, tcp: bool) -> Option<String> {
    find_info_by_socket(source, tcp).map(|info| info.exe)
}

/// Like [`find_by_socket`] but also resolves the owner's uid and
/// username for the UID / IN-USER rules.
pub fn find_info_by_socket(source: SocketAddr, tcp: bool) -> Option<ProcessInfo> {
    let family = if source.is_ipv4() { "" } else { "6" };
    let table_name = if tcp {
        format!("/proc/net/tcp{family}")
    } else {
        format!("/proc/net/udp{family}")
    };
    let table = std::fs::read_to_string(table_name).ok()?;
    let inode = inode_from_table(&table, source, tcp)?;
    let pid = inode_owner_pid(inode)?;
    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
        .ok()
        .map(|p| p.to_string_lossy().into_owned())?;
    let uid = std::fs::read_to_string(format!("/proc/{pid}/status"))
        .ok()
        .as_deref()
        .and_then(parse_uid_from_status);
    let user = uid.and_then(username_from_uid);
    Some(ProcessInfo { exe, uid, user })
}

/// Scan a /proc/net/tcp(6)/udp(6) dump for the socket bound to
/// `source`; returns its inode. Columns: sl, local, rem, st, tx:rx,
/// tr:when, retrnsmt, uid, timeout, inode (tx/rx render as one token).
/// TCP rows must be ESTABLISHED (01); UDP sockets carry no meaningful
/// state, so every row matches.
fn inode_from_table(table: &str, source: SocketAddr, tcp: bool) -> Option<u32> {
    for line in table.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        if tcp && cols[3] != "01" {
            continue;
        }
        if parse_proc_addr(cols[1]) != Some(source) {
            continue;
        }
        return cols[9].parse().ok();
    }
    None
}

/// Parse a `/proc` address field (`0100007F:1F90`) into a socket
/// address. Both halves are hex; the address words are little-endian.
fn parse_proc_addr(field: &str) -> Option<SocketAddr> {
    let (addr, port) = field.split_once(':')?;
    let port = u16::from_str_radix(port, 16).ok()?;
    let ip = match addr.len() {
        8 => {
            let v = u32::from_str_radix(addr, 16).ok()?;
            IpAddr::from(Ipv4Addr::from(v.swap_bytes()))
        }
        32 => {
            // Four little-endian u32 words in sequence.
            let mut octets = [0u8; 16];
            for (i, word) in addr.as_bytes().chunks(8).enumerate() {
                let w = u32::from_str_radix(std::str::from_utf8(word).ok()?, 16).ok()?;
                octets[i * 4..i * 4 + 4].copy_from_slice(&w.to_le_bytes());
            }
            IpAddr::from(Ipv6Addr::from(octets))
        }
        _ => return None,
    };
    Some(SocketAddr::from((ip, port)))
}

/// Find the pid of the process owning `inode` by walking
/// `/proc/<pid>/fd` for the matching `socket:[inode]` link.
fn inode_owner_pid(inode: u32) -> Option<u32> {
    let needle = format!("socket:[{inode}]");
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry.file_name().to_str().and_then(|s| s.parse::<u32>().ok()) else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
            continue; // not ours (or no permission) — keep scanning
        };
        for fd in fds.flatten() {
            if std::fs::read_link(fd.path())
                .map(|l| l.to_string_lossy() == needle)
                .unwrap_or(false)
            {
                return Some(pid);
            }
        }
    }
    None
}

/// Parse the owner uid from a `/proc/<pid>/status` dump: the `Uid:`
/// line carries four fields (real, effective, saved, fs) — take the
/// real uid, the first number.
fn parse_uid_from_status(status: &str) -> Option<u32> {
    for line in status.lines() {
        if let Some(rest) = line.strip_prefix("Uid:") {
            return rest.split_whitespace().next()?.parse().ok();
        }
    }
    None
}

/// Resolve a uid to its username via `getpwuid_r` (best-effort:
/// returns None on lookup failure or missing passwd entry). Exercised
/// only manually — unit tests cover the `/proc` status parsing.
fn username_from_uid(uid: u32) -> Option<String> {
    // 4 KiB covers NSS entries (glibc's recommended _SC_GETPW_R_SIZE_MAX
    // baseline); on ERANGE we simply give up — this is best-effort.
    let mut buf = [0u8; 4096];
    let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result: *mut libc::passwd = std::ptr::null_mut();
    let rc = unsafe {
        libc::getpwuid_r(
            uid as libc::uid_t,
            &mut pwd,
            buf.as_mut_ptr().cast(),
            buf.len(),
            &mut result,
        )
    };
    if rc != 0 || result.is_null() {
        return None;
    }
    let name = unsafe { std::ffi::CStr::from_ptr(pwd.pw_name) };
    Some(name.to_string_lossy().into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_proc_addr() {
        assert_eq!(
            parse_proc_addr("0100007F:1F90"),
            Some("127.0.0.1:8080".parse().unwrap())
        );
        assert_eq!(
            parse_proc_addr("00000000:0016"),
            Some("0.0.0.0:22".parse().unwrap())
        );
    }

    #[test]
    fn parses_ipv6_proc_addr() {
        // ::1 rendered as four little-endian words.
        assert_eq!(
            parse_proc_addr("00000000000000000000000001000000:0035"),
            Some("[::1]:53".parse().unwrap())
        );
        assert!(parse_proc_addr("ZZZZ").is_none());
    }

    #[test]
    fn finds_inode_for_established_socket() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n \
                     0: 0100007F:C765 0100007F:1F90 01 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 20 0 0 10 0\n \
                     1: 0100007F:C766 0A000001:0050 06 00000000:00000000 00:00000000 00000000     0        0 99999 1 0000000000000000 20 0 0 10 0\n";
        assert_eq!(
            inode_from_table(table, "127.0.0.1:51045".parse().unwrap(), true),
            Some(12345)
        );
        // The TIME_WAIT row (st 06) must not match for TCP.
        assert_eq!(
            inode_from_table(table, "127.0.0.1:51046".parse().unwrap(), true),
            None
        );
        // UDP rows match regardless of state.
        let udp = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer\n \
                   10: 0100007F:C765 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 42424 2 0000000000000000\n";
        assert_eq!(
            inode_from_table(udp, "127.0.0.1:51045".parse().unwrap(), false),
            Some(42424)
        );
    }

    #[test]
    fn parses_uid_from_status_line() {
        let status = "Name:\tcurl\nUmask:\t0022\nState:\tS (sleeping)\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n";
        assert_eq!(parse_uid_from_status(status), Some(1000));
        // Only the first (real) uid of the four fields.
        assert_eq!(parse_uid_from_status("Name:\tdaemon\nUid:\t0\t1000\t1000\t1000\n"), Some(0));
        // Missing Uid line / garbage number.
        assert_eq!(parse_uid_from_status("Name:\tcurl\nState:\tR\n"), None);
        assert_eq!(parse_uid_from_status("Uid:\tnot-a-number 1 1 1\n"), None);
    }

    #[test]
    fn username_lookup_shape() {
        // Hermetic shape check only: unknown uids on the running system
        // resolve to None or a name without panicking; the happy path
        // (current user) is verified manually.
        let uid = parse_uid_from_status("Uid:\t12345 12345 12345 12345\n").unwrap();
        let _ = username_from_uid(uid);
        let _ = username_from_uid(u32::MAX);
    }
}
