//! Fake-IP pool (mihomo `fake-ip-range`): bidirectional LRU map between
//! domains and addresses carved out of a reserved range.
//!
//! Persistence (sing-box `dns/transport/fakeip/store.go`, mihomo's
//! bbolt cachefile bucket behind `profile.store-fake-ip`): the pool can
//! be written to and reloaded from a JSON file holding the range, the
//! allocation cursor and the full domain↔ip map, so fake addresses
//! survive a restart. The Rust port uses the engine's own JSON format
//! instead of bbolt (a Go-only embedded database).

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::sync::Mutex;

use serde::{Deserialize, Serialize};

use crate::error::{Error, Result};

/// Pool sizing: 198.18.0.0/15 holds 131070 hosts; the LRU evicts the
/// least-recently-used domain when the map is full.
pub struct FakeIpPool {
    base: u32,
    prefix: u32,
    size: u32,
    inner: Mutex<Inner>,
}

struct Inner {
    /// Next candidate offset (wraps; skips in-use entries).
    cursor: u32,
    by_domain: HashMap<String, IpAddr>,
    by_ip: HashMap<IpAddr, String>,
    order: Vec<String>, // approximate LRU: append on (re)use, evict front
}

/// On-disk shape of the pool (version 1). `mappings` are stored in LRU
/// order (least-recently-used first) so eviction order survives too.
#[derive(Serialize, Deserialize)]
struct StoreFile {
    version: u32,
    /// Canonical `network/prefix` the mappings were carved from.
    range: String,
    /// Next allocation offset (the sing-box `inet4Current` cursor).
    next: u32,
    mappings: Vec<(String, String)>,
}

impl FakeIpPool {
    /// Build from a CIDR like `198.18.0.1/15` (network+broadcast excluded,
    /// matching mihomo).
    pub fn new(cidr: &str) -> Result<Self> {
        let (base, prefix, size) = parse_range(cidr)?;
        Ok(FakeIpPool {
            base,
            prefix,
            size,
            inner: Mutex::new(Inner {
                cursor: 0,
                by_domain: HashMap::new(),
                by_ip: HashMap::new(),
                order: Vec::new(),
            }),
        })
    }

    /// Build from a CIDR and reload the persisted state at `path`
    /// (sing-box `Store.Start`): a missing file starts a fresh pool,
    /// a store written for a DIFFERENT range is discarded (upstream
    /// calls `FakeIPReset()` in that case), and a corrupt file is a
    /// loud error rather than a silent wipe.
    pub fn load_from(cidr: &str, path: &Path) -> Result<Self> {
        let pool = Self::new(cidr)?;
        let canonical = pool.canonical_range();
        let raw = match std::fs::read(path) {
            Ok(raw) => raw,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Ok(pool); // first boot
            }
            Err(e) => {
                return Err(Error::config(format!(
                    "fake-ip store {}: {e}",
                    path.display()
                )))
            }
        };
        let store: StoreFile = serde_json::from_slice(&raw).map_err(|e| {
            Error::config(format!(
                "fake-ip store {}: corrupt ({e})",
                path.display()
            ))
        })?;
        if store.version != 1 {
            return Err(Error::config(format!(
                "fake-ip store {}: unsupported version {}",
                path.display(),
                store.version
            )));
        }
        if store.range != canonical {
            // Range changed since the store was written: the addresses
            // mean something else now, so start over (sing-box resets
            // the storage and persists fresh metadata).
            tracing::info!(
                target: "engine",
                "fake-ip store {} was written for {} (now {canonical}) — resetting",
                path.display(),
                store.range
            );
            return Ok(pool);
        }
        if store.mappings.len() as u32 > pool.size {
            return Err(Error::config(format!(
                "fake-ip store {}: {} mappings exceed pool size {}",
                path.display(),
                store.mappings.len(),
                pool.size
            )));
        }
        let mut inner = pool.inner.lock().unwrap();
        for (domain, ip) in &store.mappings {
            let ip: IpAddr = ip.parse().map_err(|_| {
                Error::config(format!(
                    "fake-ip store {}: bad address {ip:?} for {domain:?}",
                    path.display()
                ))
            })?;
            if !pool.contains(ip) {
                return Err(Error::config(format!(
                    "fake-ip store {}: address {ip} outside {canonical}",
                    path.display()
                )));
            }
            if inner.by_domain.contains_key(domain) || inner.by_ip.contains_key(&ip) {
                return Err(Error::config(format!(
                    "fake-ip store {}: duplicate mapping for {domain:?}",
                    path.display()
                )));
            }
            inner.by_domain.insert(domain.clone(), ip);
            inner.by_ip.insert(ip, domain.clone());
            inner.order.push(domain.clone());
        }
        inner.cursor = store.next % pool.size;
        drop(inner);
        Ok(pool)
    }

    /// Write the pool to `path` (sing-box `Store.Close` /
    /// `FakeIPSaveMetadata` + address pairs). The write is atomic:
    /// serialize to `<path>.tmp`, then rename over the target.
    pub fn persist_to(&self, path: &Path) -> Result<()> {
        let inner = self.inner.lock().unwrap();
        let store = StoreFile {
            version: 1,
            range: self.canonical_range(),
            next: inner.cursor,
            mappings: inner
                .order
                .iter()
                .filter_map(|d| inner.by_domain.get(d).map(|ip| (d.clone(), ip.to_string())))
                .collect(),
        };
        let bytes = serde_json::to_vec(&store)
            .map_err(|e| Error::config(format!("fake-ip store encode: {e}")))?;
        drop(inner);
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| Error::config(format!("fake-ip store dir: {e}")))?;
            }
        }
        let tmp = path.with_extension("json.tmp");
        std::fs::write(&tmp, &bytes)
            .map_err(|e| Error::config(format!("fake-ip store {}: {e}", tmp.display())))?;
        std::fs::rename(&tmp, path).map_err(|e| {
            Error::config(format!(
                "fake-ip store {} -> {}: {e}",
                tmp.display(),
                path.display()
            ))
        })
    }

    /// Drop every mapping and restart allocation (mihomo
    /// `resolver.FlushFakeIP`, behind `POST /cache/fakeip/flush`;
    /// sing-box `Store.Reset`).
    pub fn flush(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.cursor = 0;
        inner.by_domain.clear();
        inner.by_ip.clear();
        inner.order.clear();
    }

    /// Canonical `network/prefix` of this pool (base masked).
    pub fn canonical_range(&self) -> String {
        format!("{}/{}", Ipv4Addr::from(self.base), self.prefix)
    }

    /// Get (or allocate) the fake address for a domain.
    pub fn lookup_or_alloc(&self, domain: &str) -> IpAddr {
        let mut inner = self.inner.lock().unwrap();
        if let Some(ip) = inner.by_domain.get(domain).copied() {
            touch(&mut inner.order, domain);
            return ip;
        }
        // Evict when full.
        if inner.by_domain.len() as u32 >= self.size {
            if let Some(victim) = inner.order.first().cloned() {
                if let Some(ip) = inner.by_domain.remove(&victim) {
                    inner.by_ip.remove(&ip);
                }
                inner.order.remove(0);
            }
        }
        // Find a free slot (at most `size` iterations).
        let mut ip = None;
        for _ in 0..self.size {
            let candidate = self.base + 1 + (inner.cursor % self.size);
            inner.cursor = inner.cursor.wrapping_add(1);
            let candidate = IpAddr::V4(Ipv4Addr::from(candidate));
            if !inner.by_ip.contains_key(&candidate) {
                ip = Some(candidate);
                break;
            }
        }
        let ip = ip.unwrap_or_else(|| {
            IpAddr::V4(Ipv4Addr::from(self.base + 1 + (inner.cursor % self.size)))
        });
        inner.by_domain.insert(domain.to_string(), ip);
        inner.by_ip.insert(ip, domain.to_string());
        inner.order.push(domain.to_string());
        ip
    }

    /// Reverse lookup: domain for a fake address.
    pub fn reverse(&self, ip: IpAddr) -> Option<String> {
        let mut inner = self.inner.lock().unwrap();
        let domain = inner.by_ip.get(&ip).cloned()?;
        touch(&mut inner.order, &domain);
        Some(domain)
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        let IpAddr::V4(v4) = ip else { return false };
        let v = u32::from(v4);
        // Membership: within [base+1, base+1+size).
        v > self.base && v <= self.base + 1 + self.size
    }

    pub fn len(&self) -> usize {
        self.inner.lock().unwrap().by_domain.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn mask_of(prefix: u32) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

/// Split a `a.b.c.d/p` fake-ip-range into (base, prefix, usable-size).
fn parse_range(cidr: &str) -> Result<(u32, u32, u32)> {
    let (addr, prefix) = cidr
        .split_once('/')
        .ok_or_else(|| Error::config(format!("bad fake-ip-range {cidr:?}")))?;
    let addr: Ipv4Addr = addr
        .parse()
        .map_err(|_| Error::config(format!("bad fake-ip address {addr:?}")))?;
    let prefix: u32 = prefix
        .parse()
        .map_err(|_| Error::config(format!("bad fake-ip prefix {prefix:?}")))?;
    if !(2..=32).contains(&prefix) {
        return Err(Error::config(format!(
            "fake-ip prefix /{prefix} out of range"
        )));
    }
    let base = u32::from(addr) & mask_of(prefix);
    let size = (1u32 << (32 - prefix)).saturating_sub(2).max(1);
    Ok((base, prefix, size))
}

fn touch(order: &mut Vec<String>, domain: &str) {
    if let Some(pos) = order.iter().position(|d| d == domain) {
        let d = order.remove(pos);
        order.push(d);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn alloc_and_reverse() {
        let pool = FakeIpPool::new("198.18.0.1/15").unwrap();
        let a = pool.lookup_or_alloc("a.test");
        let b = pool.lookup_or_alloc("b.test");
        assert_ne!(a, b);
        assert_eq!(pool.reverse(a).unwrap(), "a.test");
        assert_eq!(pool.reverse(b).unwrap(), "b.test");
        // Stable allocation.
        assert_eq!(pool.lookup_or_alloc("a.test"), a);
        assert_eq!(pool.len(), 2);
    }

    #[test]
    fn contains_bounds() {
        let pool = FakeIpPool::new("198.18.0.1/15").unwrap();
        let a = pool.lookup_or_alloc("x.test");
        assert!(pool.contains(a));
        assert!(!pool.contains("8.8.8.8".parse().unwrap()));
        assert!(!pool.contains("::1".parse().unwrap()));
    }

    #[test]
    fn lru_eviction() {
        // /30 → 2 usable slots.
        let pool = FakeIpPool::new("10.99.0.1/30").unwrap();
        let a = pool.lookup_or_alloc("first.test");
        let b = pool.lookup_or_alloc("second.test");
        assert_eq!(pool.len(), 2);
        // Touch `first` via reverse lookup so `second` is the LRU victim.
        assert_eq!(pool.reverse(a).as_deref(), Some("first.test"));
        // Allocating `third` evicts `second` and hands its address over.
        let _c = pool.lookup_or_alloc("third.test");
        assert_eq!(pool.len(), 2);
        // `first` survived; `second` no longer maps to its old address.
        assert_eq!(pool.reverse(a).as_deref(), Some("first.test"));
        let second_now = pool.reverse(b);
        assert!(
            second_now.is_none() || second_now.as_deref() != Some("second.test"),
            "evicted entry must not still map: {second_now:?}"
        );
    }

    #[test]
    fn bad_ranges_rejected() {
        assert!(FakeIpPool::new("198.18.0.0").is_err());
        assert!(FakeIpPool::new("nonsense/24").is_err());
        assert!(FakeIpPool::new("10.0.0.1/1").is_err());
    }

    #[test]
    fn flush_clears_everything() {
        let pool = FakeIpPool::new("198.18.0.1/15").unwrap();
        let a = pool.lookup_or_alloc("gone.test");
        assert_eq!(pool.len(), 1);
        pool.flush();
        assert!(pool.is_empty());
        assert_eq!(pool.reverse(a), None);
        // Allocation restarts from the beginning of the range.
        assert_eq!(
            pool.lookup_or_alloc("fresh.test"),
            IpAddr::V4(Ipv4Addr::new(198, 18, 0, 1))
        );
    }

    // ---- persistence -------------------------------------------------

    use std::sync::atomic::{AtomicU32, Ordering as AtomicOrdering};

    static TEST_FILE_SEQ: AtomicU32 = AtomicU32::new(0);

    /// A unique temp path per test (tempfile is not an engine dep).
    fn temp_store(tag: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!(
            "rustcrash-fakeip-{}-{tag}-{}.json",
            std::process::id(),
            TEST_FILE_SEQ.fetch_add(1, AtomicOrdering::Relaxed)
        ))
    }

    #[test]
    fn persist_reload_roundtrip() {
        let path = temp_store("roundtrip");
        let pool = FakeIpPool::new("198.18.0.1/15").unwrap();
        let a = pool.lookup_or_alloc("a.test");
        let b = pool.lookup_or_alloc("b.test");
        // Touch `a` so it is the most-recently-used; file order is LRU.
        assert_eq!(pool.reverse(a).as_deref(), Some("a.test"));
        pool.persist_to(&path).unwrap();

        let reloaded = FakeIpPool::load_from("198.18.0.1/15", &path).unwrap();
        assert_eq!(reloaded.len(), 2);
        // Same addresses handed out for the same domains.
        assert_eq!(reloaded.lookup_or_alloc("a.test"), a);
        assert_eq!(reloaded.lookup_or_alloc("b.test"), b);
        assert_eq!(reloaded.reverse(b).as_deref(), Some("b.test"));
        assert_eq!(reloaded.canonical_range(), "198.18.0.0/15");
        // A fresh allocation continues after the restored block.
        let c = reloaded.lookup_or_alloc("c.test");
        assert_ne!(c, a);
        assert_ne!(c, b);
        assert!(reloaded.contains(c));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn reload_with_different_range_resets() {
        let path = temp_store("range-change");
        let pool = FakeIpPool::new("10.99.0.1/24").unwrap();
        pool.lookup_or_alloc("stale.test");
        pool.persist_to(&path).unwrap();

        // The configured range shrank: the stored addresses may no
        // longer be carve-able from it, so the store is discarded
        // (sing-box resets storage on metadata mismatch).
        let reloaded = FakeIpPool::load_from("10.99.0.1/25", &path).unwrap();
        assert!(reloaded.is_empty());
        assert_eq!(reloaded.canonical_range(), "10.99.0.0/25");
        // The store on disk is untouched until someone persists again.
        assert!(path.exists());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn missing_store_starts_fresh() {
        let path = temp_store("missing");
        let pool = FakeIpPool::load_from("198.18.0.1/15", &path).unwrap();
        assert!(pool.is_empty());
        assert!(pool.lookup_or_alloc("new.test").is_ipv4());
    }

    #[test]
    fn corrupt_or_hostile_stores_fail_loudly() {
        let path = temp_store("corrupt");
        std::fs::write(&path, b"definitely not json").unwrap();
        assert!(FakeIpPool::load_from("198.18.0.1/15", &path).is_err());

        // Out-of-range address inside a syntactically valid store.
        std::fs::write(
            &path,
            br#"{"version":1,"range":"198.18.0.0/15","next":0,"mappings":[["a.test","8.8.8.8"]]}"#,
        )
        .unwrap();
        assert!(FakeIpPool::load_from("198.18.0.1/15", &path).is_err());

        // Unknown future version.
        std::fs::write(
            &path,
            br#"{"version":2,"range":"198.18.0.0/15","next":0,"mappings":[]}"#,
        )
        .unwrap();
        assert!(FakeIpPool::load_from("198.18.0.1/15", &path).is_err());
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn persist_creates_parent_directories() {
        let dir = std::env::temp_dir().join(format!(
            "rustcrash-fakeip-dirs-{}-{}",
            std::process::id(),
            TEST_FILE_SEQ.fetch_add(1, AtomicOrdering::Relaxed)
        ));
        let path = dir.join("nested").join("store.json");
        let pool = FakeIpPool::new("198.18.0.1/15").unwrap();
        pool.lookup_or_alloc("dir.test");
        pool.persist_to(&path).unwrap();
        assert!(path.is_file());
        let reloaded = FakeIpPool::load_from("198.18.0.1/15", &path).unwrap();
        assert_eq!(reloaded.len(), 1);
        std::fs::remove_file(&path).ok();
        std::fs::remove_dir(dir.join("nested")).ok();
        std::fs::remove_dir(&dir).ok();
    }
}
