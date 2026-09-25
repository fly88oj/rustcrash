//! Async device IO for the netstack: a dedicated blocking-reader pump.
//!
//! The netstack task never blocks on the device. Instead — the wireguard-go
//! shape (`RoutineReadFromTUN`, device/send.go:206, "Routine: TUN reader") —
//! one OS thread blocks on the device and hands packets to the async side
//! through a bounded channel; sing-tun's gvisor link endpoint does the same
//! with a goroutine (`Attach` -> `dispatchLoop` -> `BatchRead` ->
//! `DeliverNetworkPacket`, tun_linux_gvisor.go:115-169). Writes stay on the
//! netstack task: every backend's `send` is a nonblocking try-write that
//! reports `WouldBlock` when its queue/ring is full, and the smoltcp transmit
//! path drops on `WouldBlock` — what a full NIC tx ring does (TCP
//! retransmits; UDP is lossy anyway).
//!
//! Why a thread instead of tokio's `AsyncFd`: the Windows backend has no fd
//! at all (a WinTUN session signals a HANDLE event, wintun.h:190-198), so a
//! single readiness mechanism must be an abstraction, not a type. That
//! abstraction is [`TunIo::wait_readable`]:
//!
//! | backend | wait | upstream shape |
//! |---|---|---|
//! | Linux `/dev/net/tun` | `poll(2)` `POLLIN` on the fd | sing-tun's epoll/poll-registered fd |
//! | macOS utun | `poll(2)` on the control-socket fd | ditto (a socket fd polls like any other) |
//! | Windows WinTUN | `WaitForSingleObject` on the ring's read event | wintun.h:190-198 ("use it to wait for packets to arrive"), wireguard-windows' receive loop |
//! | in-memory double | condvar | `testdev.rs` |
//!
//! Backpressure is the channel: `blocking_send` parks the reader thread when
//! the netstack is behind, so the kernel's device queue fills and drops — the
//! same overload behavior the previous AsyncFd drain loop had. The stop flag
//! is checked at least once per [`POLL_TICK`], so dropping the [`DeviceReader`]
//! (which happens when the `serve` future is dropped) releases the device
//! within one tick; `Drop` deliberately does not join the thread, because
//! dropping an inbound must never block the runtime.

use std::io;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Duration;

use tokio::sync::mpsc;

use crate::inbound::tun::device::TunDevice;

/// How long one `wait_readable` may park before the stop flag is rechecked.
/// Only bounds shutdown latency — packet arrival still wakes immediately.
pub(crate) const POLL_TICK: Duration = Duration::from_millis(100);

/// The device surface the netstack consumes, async-flavored exactly once:
/// one nonblocking read, one nonblocking write, and one blocking "wait until
/// a read may succeed" with a timeout. `recv`'s contract matches every
/// backend: `Ok(0)` = consumed but nothing to hand over (a dropped non-IP
/// utun frame), `WouldBlock` = queue empty, any other error is fatal.
pub(crate) trait TunIo: Send + Sync + 'static {
    /// Read one packet into `buf`; `WouldBlock` when the device is empty.
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize>;
    /// Write one packet; `WouldBlock` when the device's queue is full.
    fn send(&self, pkt: &[u8]) -> io::Result<()>;
    /// Block until `recv` may succeed, for at most `timeout`. `Ok(true)` =
    /// readable now, `Ok(false)` = timed out (the caller rechecks its stop
    /// flag and waits again).
    fn wait_readable(&self, timeout: Duration) -> io::Result<bool>;
}

// -- the platform device ------------------------------------------------------

#[cfg(unix)]
impl TunIo for TunDevice {
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        TunDevice::recv(self, buf)
    }

    fn send(&self, pkt: &[u8]) -> io::Result<()> {
        TunDevice::send(self, pkt)
    }

    /// `poll(2)` for `POLLIN` on the TUN fd (Linux) / utun control socket
    /// (macOS). Level-triggered, so the drain-then-wait loop in the reader
    /// thread cannot lose a wakeup: if a packet arrives between the last
    /// `recv` and this call, `poll` returns immediately.
    fn wait_readable(&self, timeout: Duration) -> io::Result<bool> {
        use std::os::fd::AsRawFd;
        let mut pfd = libc::pollfd {
            fd: self.as_raw_fd(),
            events: libc::POLLIN,
            revents: 0,
        };
        let ms = timeout.as_millis().min(i32::MAX as u128) as i32;
        // SAFETY: `pfd` is a valid one-element poll set for the call.
        let rc = unsafe { libc::poll(&mut pfd, 1, ms) };
        if rc < 0 {
            let e = io::Error::last_os_error();
            if e.kind() == io::ErrorKind::Interrupted {
                // EINTR: pretend we timed out; the caller rechecks stop and
                // re-waits.
                return Ok(false);
            }
            return Err(e);
        }
        Ok(rc > 0)
    }
}

#[cfg(target_os = "windows")]
impl TunIo for TunDevice {
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        TunDevice::recv(self, buf)
    }

    fn send(&self, pkt: &[u8]) -> io::Result<()> {
        TunDevice::send(self, pkt)
    }

    /// `WaitForSingleObject` on the session's read-wait event — the exact
    /// contract wintun.h:190-198 documents for `ERROR_NO_MORE_ITEMS`
    /// ("use the read wait event to wait until packets are available").
    fn wait_readable(&self, timeout: Duration) -> io::Result<bool> {
        win::wait(self.read_wait_event(), timeout)
    }
}

#[cfg(target_os = "windows")]
mod win {
    //! The one kernel32 call the pump needs on Windows (linked at build time
    //! like the loader trio in `device_windows`).

    use std::ffi::c_void;
    use std::io;
    use std::time::Duration;

    #[link(name = "kernel32")]
    extern "system" {
        fn WaitForSingleObject(handle: *mut c_void, milliseconds: u32) -> u32;
    }

    const WAIT_OBJECT_0: u32 = 0x0000_0000;
    const WAIT_TIMEOUT: u32 = 0x0000_0102;

    pub(super) fn wait(handle: *mut c_void, timeout: Duration) -> io::Result<bool> {
        let ms = timeout.as_millis().min(u32::MAX as u128) as u32;
        // SAFETY: the handle is the live session's read event (owned by the
        // TunDevice outliving this call); WaitForSingleObject only observes
        // its signaled state.
        let rc = unsafe { WaitForSingleObject(handle, ms) };
        match rc {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            rc => Err(io::Error::other(format!(
                "tun: WaitForSingleObject(read event) returned {rc:#x}"
            ))),
        }
    }
}

// -- the reader pump -----------------------------------------------------------

/// The reading half of the device, as the netstack sees it: a packet
/// receiver plus the fate of the reader thread (stopped cleanly, or dead
/// with the error that killed it). Dropping it asks the thread to stop.
pub(crate) struct DeviceReader {
    rx: Option<mpsc::Receiver<Vec<u8>>>,
    stop: Arc<AtomicBool>,
    error: Arc<Mutex<Option<io::Error>>>,
    join: Option<JoinHandle<()>>,
}

impl DeviceReader {
    /// Start the reader thread for `dev`. `buf_size` is the per-read buffer
    /// (MTU-sized, with headroom for the utun 4-byte header); `chan` bounds
    /// the packet queue between the thread and the async side. Fails only
    /// if the OS refuses the thread (the old AsyncFd registration error's
    /// counterpart).
    pub(crate) fn spawn(
        dev: Arc<dyn TunIo>,
        buf_size: usize,
        chan: usize,
    ) -> io::Result<DeviceReader> {
        let (tx, rx) = mpsc::channel::<Vec<u8>>(chan);
        let stop = Arc::new(AtomicBool::new(false));
        let error = Arc::new(Mutex::new(None));
        let join = std::thread::Builder::new()
            .name("tun-reader".into())
            .spawn({
                let dev = dev.clone();
                let stop = stop.clone();
                let error = error.clone();
                move || reader_thread(dev, stop, error, tx, vec![0u8; buf_size])
            })
            .map_err(|e| {
                io::Error::new(
                    e.kind(),
                    format!("tun: cannot spawn the reader thread: {e}"),
                )
            })?;
        Ok(DeviceReader {
            rx: Some(rx),
            stop,
            error,
            join: Some(join),
        })
    }

    /// Take the packet stream: yields every packet the device delivers, in
    /// order, and ends when the thread stops (device error or drop). Once,
    /// by construction of the netstack loop.
    pub(crate) fn take_receiver(&mut self) -> Option<mpsc::Receiver<Vec<u8>>> {
        self.rx.take()
    }

    /// The error that ended the reader, if it died on one.
    pub(crate) fn take_error(&self) -> Option<String> {
        self.error
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
            .map(|e| e.to_string())
    }

    /// Whether the reader thread has exited (used by the drop-timing test).
    pub(crate) fn is_finished(&self) -> bool {
        self.join.as_ref().is_some_and(|j| j.is_finished())
    }
}

impl Drop for DeviceReader {
    fn drop(&mut self) {
        // Ask the thread to stop; never join — dropping an inbound must not
        // block the runtime. The thread checks the flag at least once per
        // POLL_TICK, then exits and releases its Arcs (the device included)
        // on its own. The handle is only read (its thread id, for the trace)
        // — joining it here would hang up to one tick on a stuck device.
        self.stop.store(true, Ordering::Release);
        if let Some(handle) = self.join.take() {
            tracing::trace!(
                target: "engine",
                "tun: reader thread {:?} asked to stop",
                handle.thread().id()
            );
        }
    }
}

/// The reader thread body — wireguard-go's `RoutineReadFromTUN` in Rust: one
/// blocking loop, forever, handing every packet to the channel.
///
/// Draining is exactly the previous AsyncFd loop's discipline: after a
/// successful read, keep reading while packets are there (the Linux comment
/// was "readiness is edge-driven, so stopping early would park the loop with
/// packets still queued" — with poll's level-triggered readiness the wait
/// would return immediately, but batching is cheaper); on `WouldBlock`/`Ok(0)`
/// park in `wait_readable` until the device says otherwise.
fn reader_thread(
    dev: Arc<dyn TunIo>,
    stop: Arc<AtomicBool>,
    error: Arc<Mutex<Option<io::Error>>>,
    tx: mpsc::Sender<Vec<u8>>,
    mut buf: Vec<u8>,
) {
    loop {
        if stop.load(Ordering::Acquire) {
            return;
        }
        match dev.recv(&mut buf) {
            Ok(0) => {} // consumed, nothing to hand over: pause
            Ok(n) => {
                // `blocking_send` is legal here (a plain std thread) and is
                // the backpressure: a slow netstack parks the reader, the
                // kernel queue fills, packets drop — as before.
                if tx.blocking_send(buf[..n].to_vec()).is_err() {
                    return; // the netstack is gone; stop quietly
                }
                continue; // more may be queued: keep draining
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {}
            Err(e) => {
                *error.lock().unwrap_or_else(|e| e.into_inner()) = Some(e);
                return;
            }
        }
        match dev.wait_readable(POLL_TICK) {
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                *error.lock().unwrap_or_else(|e| e.into_inner()) = Some(e);
                return;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::atomic::AtomicUsize;

    /// A scriptable device: queued read results, delivered in order, plus
    /// call counters so the tests can see the pump's wait/drain discipline.
    struct ScriptDevice {
        script: Mutex<VecDeque<io::Result<Vec<u8>>>>,
        reads: AtomicUsize,
        waits: AtomicUsize,
        cv: std::sync::Condvar,
    }

    impl ScriptDevice {
        fn new() -> Arc<Self> {
            Arc::new(ScriptDevice {
                script: Mutex::new(VecDeque::new()),
                reads: AtomicUsize::new(0),
                waits: AtomicUsize::new(0),
                cv: std::sync::Condvar::new(),
            })
        }

        fn push(&self, r: io::Result<Vec<u8>>) {
            self.script.lock().unwrap().push_back(r);
            self.cv.notify_all();
        }
    }

    impl TunIo for ScriptDevice {
        fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
            self.reads.fetch_add(1, Ordering::SeqCst);
            match self.script.lock().unwrap().pop_front() {
                Some(Ok(pkt)) => {
                    let n = pkt.len().min(buf.len());
                    buf[..n].copy_from_slice(&pkt[..n]);
                    Ok(n)
                }
                Some(Err(e)) => Err(e),
                None => Err(io::Error::new(io::ErrorKind::WouldBlock, "empty")),
            }
        }

        fn send(&self, _pkt: &[u8]) -> io::Result<()> {
            Ok(())
        }

        fn wait_readable(&self, timeout: Duration) -> io::Result<bool> {
            self.waits.fetch_add(1, Ordering::SeqCst);
            let deadline = std::time::Instant::now() + timeout;
            let mut q = self.script.lock().unwrap();
            while q.is_empty() {
                let now = std::time::Instant::now();
                if now >= deadline {
                    return Ok(false);
                }
                let (guard, _res) = self
                    .cv
                    .wait_timeout(q, deadline.saturating_duration_since(now))
                    .unwrap();
                q = guard;
            }
            Ok(true)
        }
    }

    fn pkt(b: &[u8]) -> io::Result<Vec<u8>> {
        Ok(b.to_vec())
    }

    fn recv_one(
        rx: &mut mpsc::Receiver<Vec<u8>>,
    ) -> Option<Vec<u8>> {
        // Real-clock deadline; the thread runs independently of this runtime.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            match rx.try_recv() {
                Ok(v) => return Some(v),
                Err(mpsc::error::TryRecvError::Disconnected) => return None,
                Err(mpsc::error::TryRecvError::Empty) => {
                    if std::time::Instant::now() > deadline {
                        return None;
                    }
                    std::thread::sleep(Duration::from_millis(2));
                }
            }
        }
    }

    #[test]
    fn pump_delivers_packets_in_order_and_waits_between_bursts() {
        let dev = ScriptDevice::new();
        let mut pump = DeviceReader::spawn(dev.clone(), 1500 + 64, 16).unwrap();
        dev.push(pkt(b"one"));
        dev.push(pkt(b"two"));

        // The first burst flows before any wait is needed... well, after the
        // burst the pump parks in wait_readable; both orders are fine, what
        // matters is order + no loss.
        let rx = &mut pump.take_receiver().unwrap();
        assert_eq!(recv_one(rx).as_deref(), Some(&b"one"[..]));
        assert_eq!(recv_one(rx).as_deref(), Some(&b"two"[..]));

        // A late packet still arrives: the pump is parked in wait_readable,
        // the script's condvar wakes it.
        dev.push(pkt(b"three"));
        assert_eq!(recv_one(rx).as_deref(), Some(&b"three"[..]));
        assert!(dev.waits.load(Ordering::SeqCst) >= 1, "pump must park");
        drop(pump);
    }

    #[test]
    fn pump_surfaces_a_fatal_read_error() {
        let dev = ScriptDevice::new();
        let mut pump = DeviceReader::spawn(dev.clone(), 1500 + 64, 16).unwrap();
        dev.push(pkt(b"first"));
        dev.push(Err(io::Error::new(
            io::ErrorKind::BrokenPipe,
            "device went away",
        )));

        let rx = &mut pump.take_receiver().unwrap();
        assert_eq!(recv_one(rx).as_deref(), Some(&b"first"[..]));
        // The channel ends and the error is retrievable.
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while !pump.is_finished() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(2));
        }
        assert!(pump.is_finished(), "reader must exit on a fatal error");
        let err = pump.take_error().expect("the error must be recorded");
        assert!(err.contains("device went away"), "{err}");
        drop(pump);
    }

    #[test]
    fn pump_backpressure_is_the_channel_bound() {
        let dev = ScriptDevice::new();
        let cap = 2;
        let mut pump = DeviceReader::spawn(dev.clone(), 1500 + 64, cap).unwrap();
        // More packets than the channel holds: the reader parks in
        // blocking_send until this side drains.
        for i in 0..10 {
            dev.push(pkt(format!("p{i}").as_bytes()));
        }
        let rx = &mut pump.take_receiver().unwrap();
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        while rx.len() < cap && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(2));
        }
        assert_eq!(rx.len(), cap, "no more than the channel bound queued");

        // Draining lets the rest through — nothing was dropped, the thread
        // was just parked.
        let mut got = Vec::new();
        for _ in 0..10 {
            match recv_one(rx) {
                Some(v) => got.push(String::from_utf8(v).unwrap()),
                None => break,
            }
        }
        assert_eq!(got.len(), 10, "all packets survive backpressure: {got:?}");
        assert!(got[0] == "p0" && got[9] == "p9");
        drop(pump);
    }

    #[test]
    fn pump_stops_promptly_when_dropped() {
        let dev = ScriptDevice::new();
        let mut pump = DeviceReader::spawn(dev.clone(), 1500 + 64, 16).unwrap();
        let _rx = pump.take_receiver().unwrap();
        // Idle: the thread is parked in wait_readable for at most POLL_TICK.
        std::thread::sleep(Duration::from_millis(50));
        assert!(!pump.is_finished());
        drop(pump);
        drop(_rx);
        // Within a couple of ticks the thread must have noticed and exited
        // (releasing the device Arc — strong_count back to ours).
        let deadline = std::time::Instant::now() + POLL_TICK * 5;
        while Arc::strong_count(&dev) > 1 && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(
            Arc::strong_count(&dev),
            1,
            "the reader thread must release the device after drop"
        );
    }
}
