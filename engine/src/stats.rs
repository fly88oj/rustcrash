//! Connection table and traffic statistics (feeds the Clash API).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::addr::NetAddr;
use crate::stream::ByteCounters;

/// The relay-side view of one connection's cancellation state: parks in
/// a `select!` until the connection is force-closed from the API.
///
/// Hand-rolled instead of tokio_util's CancellationToken (tokio-util is
/// only a transitive dep here — via quinn — and not declared for direct
/// use). Built on a `watch` channel because its borrow-then-`changed()`
/// cycle is race-free: a `cancel()` that fires after the flag check
/// still wakes the parked waiter (a bare AtomicBool+Notify pair has a
/// missed-wakeup window between check and registration).
pub struct CancelHandle {
    rx: tokio::sync::watch::Receiver<bool>,
}

impl CancelHandle {
    pub fn is_cancelled(&self) -> bool {
        *self.rx.borrow()
    }

    /// Resolves once the token fires (or the token is dropped with the
    /// connection table entry it lives in). Works on `&self` by cloning
    /// the watch receiver — cheap, and keeps select! call sites simple.
    pub async fn cancelled(&self) {
        let mut rx = self.rx.clone();
        loop {
            if *rx.borrow_and_update() {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    }
}

/// The controller half kept inside a `ConnEntry` — the seam the API's
/// DELETE /connections handlers use to tear live relays down (mihomo's
/// equivalent is `trackerConn.Close()` from hub/route/connections.go
/// closeConnection/closeAllConnections).
struct CancelToken {
    tx: tokio::sync::watch::Sender<bool>,
}

impl CancelToken {
    fn new() -> Self {
        let (tx, _rx) = tokio::sync::watch::channel(false);
        CancelToken { tx }
    }

    fn cancel(&self) {
        let _ = self.tx.send(true);
    }

    fn handle(&self) -> CancelHandle {
        CancelHandle {
            rx: self.tx.subscribe(),
        }
    }
}

/// One tracked connection.
#[derive(Clone)]
pub struct ConnSnapshot {
    pub id: u64,
    pub inbound: String,
    pub network: &'static str,
    pub host: String,
    pub destination_port: u16,
    pub source: SocketAddr,
    pub outbound: String,
    pub rule: String,
    pub started_unix: u64,
    pub upload: u64,
    pub download: u64,
}

struct ConnEntry {
    meta: ConnMeta,
    counters: Arc<ByteCounters>,
    outbound: Mutex<String>,
    rule: Mutex<String>,
    /// Set by force_close/force_close_all; observed by the relay loops.
    cancel: CancelToken,
}

struct ConnMeta {
    inbound: String,
    network: &'static str,
    host: String,
    port: u16,
    source: SocketAddr,
    started_unix: u64,
}

/// Global engine statistics.
#[derive(Default)]
pub struct Stats {
    up: AtomicU64,
    down: AtomicU64,
    next_id: AtomicU64,
    conns: Mutex<HashMap<u64, ConnEntry>>,
    /// Watch channel for /traffic websocket consumers.
    traffic_tx: tokio::sync::watch::Sender<(u64, u64)>,
}

impl Stats {
    pub fn new() -> Arc<Self> {
        let (tx, _rx) = tokio::sync::watch::channel((0u64, 0u64));
        Arc::new(Stats {
            traffic_tx: tx,
            ..Default::default()
        })
    }

    pub fn subscribe_traffic(&self) -> tokio::sync::watch::Receiver<(u64, u64)> {
        self.traffic_tx.subscribe()
    }

    /// Register a connection; returns its id, counter handle, and the
    /// cancellation handle the relay selects on.
    pub fn open(
        &self,
        inbound: &str,
        network: &'static str,
        target: &NetAddr,
        source: SocketAddr,
    ) -> (u64, Arc<ByteCounters>, CancelHandle) {
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let counters = Arc::new(ByteCounters::default());
        let cancel = CancelToken::new();
        let handle = cancel.handle();
        self.conns.lock().unwrap().insert(
            id,
            ConnEntry {
                meta: ConnMeta {
                    inbound: inbound.to_string(),
                    network,
                    host: target.host.to_text(),
                    port: target.port,
                    source,
                    started_unix: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .map(|d| d.as_secs())
                        .unwrap_or(0),
                },
                counters: counters.clone(),
                outbound: Mutex::new(String::new()),
                rule: Mutex::new(String::new()),
                cancel,
            },
        );
        (id, counters, handle)
    }

    /// Record which outbound/rule served a connection.
    pub fn annotate(&self, id: u64, rule: &str, outbound: &str) {
        if let Some(entry) = self.conns.lock().unwrap().get(&id) {
            *entry.rule.lock().unwrap() = rule.to_string();
            *entry.outbound.lock().unwrap() = outbound.to_string();
        }
    }

    /// Remove a connection and fold its counters into the totals.
    pub fn close(&self, id: u64, counters: &Arc<ByteCounters>) {
        self.conns.lock().unwrap().remove(&id);
        let (rx, tx) = counters.snapshot();
        self.down.fetch_add(rx, Ordering::Relaxed);
        self.up.fetch_add(tx, Ordering::Relaxed);
    }

    /// mihomo hub/route/connections.go closeConnection(): signal one
    /// tracked relay to unwind (the entry leaves the table when the
    /// relay itself observes the token and calls `close`). Returns
    /// whether the id was tracked.
    pub fn force_close(&self, id: u64) -> bool {
        match self.conns.lock().unwrap().get(&id) {
            Some(entry) => {
                entry.cancel.cancel();
                true
            }
            None => false,
        }
    }

    /// mihomo hub/route/connections.go closeAllConnections(): signal
    /// every tracked relay. Returns how many were signalled.
    pub fn force_close_all(&self) -> usize {
        let conns = self.conns.lock().unwrap();
        let mut n = 0;
        for entry in conns.values() {
            entry.cancel.cancel();
            n += 1;
        }
        n
    }

    pub fn totals(&self) -> (u64, u64) {
        (
            self.down.load(Ordering::Relaxed),
            self.up.load(Ordering::Relaxed),
        )
    }

    /// Push the current totals to /traffic subscribers (called by the
    /// engine's 1-second sampler).
    pub fn publish(&self) {
        let _ = self.traffic_tx.send(self.totals());
    }

    pub fn conn_count(&self) -> usize {
        self.conns.lock().unwrap().len()
    }

    pub fn snapshot_conns(&self) -> Vec<ConnSnapshot> {
        let conns = self.conns.lock().unwrap();
        let mut out = Vec::with_capacity(conns.len());
        for (id, e) in conns.iter() {
            let (rx, tx) = e.counters.snapshot();
            out.push(ConnSnapshot {
                id: *id,
                inbound: e.meta.inbound.clone(),
                network: e.meta.network,
                host: e.meta.host.clone(),
                destination_port: e.meta.port,
                source: e.meta.source,
                outbound: e.outbound.lock().unwrap().clone(),
                rule: e.rule.lock().unwrap().clone(),
                started_unix: e.meta.started_unix,
                upload: tx,
                download: rx,
            });
        }
        out.sort_by_key(|c| c.id);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::Host;
    use std::net::{IpAddr, Ipv4Addr, SocketAddrV4};

    #[test]
    fn open_annotate_close_lifecycle() {
        let stats = Stats::new();
        let target = NetAddr::new(Host::Domain("x.test".into()), 443);
        let source = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5555));
        let (id, counters, cancel) = stats.open("mixed", "tcp", &target, source);
        assert!(!cancel.is_cancelled());
        stats.annotate(id, "MATCH,Auto", "Auto");
        counters.rx.store(100, Ordering::Relaxed);
        counters.tx.store(50, Ordering::Relaxed);
        let snap = stats.snapshot_conns();
        assert_eq!(snap.len(), 1);
        assert_eq!(snap[0].host, "x.test");
        assert_eq!(snap[0].outbound, "Auto");
        assert_eq!(snap[0].download, 100);
        stats.close(id, &counters);
        assert_eq!(stats.conn_count(), 0);
        assert_eq!(stats.totals(), (100, 50));
    }

    #[test]
    fn totals_and_publish() {
        let stats = Stats::new();
        let mut rx = stats.subscribe_traffic();
        let (id, counters, _cancel) = stats.open(
            "t",
            "tcp",
            &NetAddr::ip(IpAddr::V4(Ipv4Addr::LOCALHOST), 1),
            SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 1)),
        );
        counters.tx.store(7, Ordering::Relaxed);
        stats.close(id, &counters);
        stats.publish();
        assert_eq!(*rx.borrow_and_update(), (0, 7));
    }

    #[tokio::test]
    async fn force_close_fires_the_relay_handle() {
        let stats = Stats::new();
        let target = NetAddr::new(Host::Domain("x.test".into()), 443);
        let source = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5555));
        let (id, _, cancel) = stats.open("mixed", "tcp", &target, source);
        // Unknown ids are not tracked (mihomo still answers 204).
        assert!(!stats.force_close(999));
        assert!(stats.force_close(id));
        assert!(cancel.is_cancelled());
        // The parked relay waiter resolves (race-free: cancel-before-
        // park is covered by the flag, cancel-after by watch::changed).
        tokio::time::timeout(std::time::Duration::from_secs(1), cancel.cancelled())
            .await
            .expect("cancelled resolves");
    }

    #[tokio::test]
    async fn force_close_before_and_after_parking_both_wake() {
        let stats = Stats::new();
        let target = NetAddr::new(Host::Domain("y.test".into()), 443);
        let source = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 5556));
        // Cancel BEFORE the relay parks: the flag check catches it.
        let (a, _, h1) = stats.open("mixed", "tcp", &target, source);
        stats.force_close(a);
        h1.cancelled().await;

        // Cancel AFTER the relay parks: watch::changed wakes it.
        let (_, _, h2) = stats.open("mixed", "tcp", &target, source);
        let parked =
            tokio::task::spawn(async move {
                h2.cancelled().await;
            });
        // Give the waiter a beat to actually park on the watch.
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(!parked.is_finished());
        let n = stats.force_close_all();
        assert!(n >= 1);
        tokio::time::timeout(std::time::Duration::from_secs(1), parked)
            .await
            .expect("parked waiter woken")
            .unwrap();
    }
}
