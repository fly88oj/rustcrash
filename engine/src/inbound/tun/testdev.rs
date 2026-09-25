//! An in-memory TUN device double: the "kernel side" of a tunnel, for tests.
//!
//! [`LoopbackTun`] implements [`TunIo`](super::io::TunIo) over two queues:
//! [`LoopbackTun::inject`] is "the kernel routes a packet out of the
//! interface" (what the reader pump receives) and everything the netstack
//! transmits lands where [`LoopbackTun::take_egress`] drains it — so the
//! *whole* inbound path (pump thread, select loop, classifier, smoltcp,
//! DNS hijack, ICMP responder) runs hermetically: no `/dev/net/tun`, no
//! CAP_NET_ADMIN, no network, and identical code on every OS.
//!
//! This is the same role sing-tun's tests give gvisor's
//! `stack.LinkEndpoint` (a channel-based loopback endpoint): a duplex packet
//! mailbox the test drives from the far side.

use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Condvar, Mutex};
use std::time::{Duration, Instant};

use super::io::TunIo;

/// A duplex in-memory device. Cheap to make; share it as an `Arc`.
pub(crate) struct LoopbackTun {
    /// Packets waiting for the netstack to read (the test plays the kernel).
    ingress: Mutex<VecDeque<Vec<u8>>>,
    /// Packets the netstack transmitted (the test plays the far peer).
    egress: Mutex<VecDeque<Vec<u8>>>,
    /// Signaled on inject / kill so `wait_readable` wakes like a fd would.
    ready: Condvar,
    /// Kill switch: the next `recv` fails with this, ending the reader.
    fail: Mutex<Option<io::Error>>,
}

impl LoopbackTun {
    pub(crate) fn new() -> Arc<Self> {
        Arc::new(LoopbackTun {
            ingress: Mutex::new(VecDeque::new()),
            egress: Mutex::new(VecDeque::new()),
            ready: Condvar::new(),
            fail: Mutex::new(None),
        })
    }

    /// The kernel sends a packet out of the tunnel (towards the stack).
    pub(crate) fn inject(&self, pkt: &[u8]) {
        self.ingress.lock().unwrap().push_back(pkt.to_vec());
        self.ready.notify_all();
    }

    /// Take everything the netstack has transmitted so far, oldest first.
    pub(crate) fn take_egress(&self) -> Vec<Vec<u8>> {
        self.egress.lock().unwrap().drain(..).collect()
    }

    /// Make the next read fail with `msg` — proves the reader thread's error
    /// path reaches `run()`'s caller.
    pub(crate) fn kill(&self, msg: &str) {
        *self.fail.lock().unwrap() = Some(io::Error::other(msg));
        self.ready.notify_all();
    }
}

impl TunIo for LoopbackTun {
    fn recv(&self, buf: &mut [u8]) -> io::Result<usize> {
        if let Some(e) = self.fail.lock().unwrap().take() {
            return Err(e);
        }
        match self.ingress.lock().unwrap().pop_front() {
            Some(pkt) => {
                let n = pkt.len().min(buf.len());
                buf[..n].copy_from_slice(&pkt[..n]);
                Ok(n)
            }
            None => Err(io::Error::new(io::ErrorKind::WouldBlock, "empty")),
        }
    }

    fn send(&self, pkt: &[u8]) -> io::Result<()> {
        self.egress.lock().unwrap().push_back(pkt.to_vec());
        Ok(())
    }

    fn wait_readable(&self, timeout: Duration) -> io::Result<bool> {
        let deadline = Instant::now() + timeout;
        let mut q = self.ingress.lock().unwrap();
        loop {
            if !q.is_empty() || self.fail.lock().unwrap().is_some() {
                return Ok(true);
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(false);
            }
            let (guard, _timed_out) = self
                .ready
                .wait_timeout(q, deadline.saturating_duration_since(now))
                .unwrap();
            q = guard;
        }
    }
}
