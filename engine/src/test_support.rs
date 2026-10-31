//! Shared helpers for the engine's in-crate tests.
//!
//! Nothing here is compiled into release builds; the module exists so
//! every test module draws shared resources (listener ports today)
//! through ONE policy instead of re-inventing per-file schemes that
//! collide under parallel runners.

/// Draw a listener port for a test.
///
/// Unique across every concurrently running test process on the host:
/// a file-locked counter under /tmp hands out strictly sequential
/// ports in 21000..=32699 — deliberately BELOW the kernel's ephemeral
/// source-port range (`ip_local_port_range`, typically 32768-60999),
/// so the kernel can never hand the same number to a concurrent
/// test's outbound source port (an active socket ignores SO_REUSEADDR,
/// so that collision kills the listener bind — see git d2c31a3 for the
/// observed CI failure). The counter also removes in-process
/// collisions by construction.
///
/// Cross-process safety is what separates this from the
/// random-base + atomic-counter scheme it replaces: runners like
/// cargo-nextest give every test its own process, and enough random
/// bases landing within each other's drawn range made collisions a
/// per-run certainty rather than a tail risk.
///
/// The counter file is per-uid (dev boxes are single-user, CI
/// containers doubly so; the suffix just keeps distinct users from
/// lock-fighting). It wraps after ~11.7k draws — a number no test run
/// approaches; on wrap the sequence restarts and a port could in
/// principle meet a still-live socket from the first lap, which fails
/// the bind loudly rather than corrupting a test.
pub(crate) fn unique_test_port() -> u16 {
    use std::fs::OpenOptions;
    use std::io::{Read, Seek, SeekFrom, Write};
    use std::os::unix::io::AsRawFd;
    use std::path::PathBuf;

    const BASE: u32 = 21_000;
    const LIMIT: u32 = 32_700; // stay below ip_local_port_range

    // Literal /tmp, not std::env::temp_dir(): every process must agree
    // on the ONE counter file, whatever TMPDIR a runner injects.
    let path = PathBuf::from("/tmp").join(format!("rustcrash-test-ports.{}", nix_uid()));
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .expect("open test-port counter");

    flock_exclusive(file.as_raw_fd());

    let mut buf = String::new();
    file.read_to_string(&mut buf)
        .expect("read test-port counter");
    let mut next: u32 = buf.trim().parse().unwrap_or(BASE);
    if next >= LIMIT {
        next = BASE;
    }
    let drawn = next;

    file.set_len(0).expect("reset test-port counter");
    file.seek(SeekFrom::Start(0))
        .expect("seek test-port counter");
    write!(file, "{}", drawn + 1).expect("write test-port counter");

    // flock releases on close; unlock explicitly so a panicking
    // team-mate later in the function cannot theorize about it.
    unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_UN) };
    u16::try_from(drawn).expect("port counter stays inside u16")
}

/// Hold an exclusive flock, retrying on EINTR.
fn flock_exclusive(fd: std::os::unix::io::RawFd) {
    loop {
        let rc = unsafe { libc::flock(fd, libc::LOCK_EX) };
        if rc == 0 {
            return;
        }
        if std::io::Error::last_os_error().raw_os_error() != Some(libc::EINTR) {
            panic!(
                "flock test-port counter: {}",
                std::io::Error::last_os_error()
            );
        }
    }
}

fn nix_uid() -> u32 {
    // getuid is infallible and cannot fail; the unsafe read is a
    // plain integer load with no invariants to uphold.
    unsafe { libc::getuid() }
}
