//! Fake-IP pool (mihomo `fake-ip-range`): bidirectional LRU map between
//! domains and addresses carved out of a reserved range.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Mutex;

/// Pool sizing: 198.18.0.0/15 holds 131070 hosts; the LRU evicts the
/// least-recently-used domain when the map is full.
pub struct FakeIpPool {
    base: u32,
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

impl FakeIpPool {
    /// Build from a CIDR like `198.18.0.1/15` (network+broadcast excluded,
    /// matching mihomo).
    pub fn new(cidr: &str) -> crate::error::Result<Self> {
        let (addr, prefix) = cidr
            .split_once('/')
            .ok_or_else(|| crate::error::Error::config(format!("bad fake-ip-range {cidr:?}")))?;
        let addr: Ipv4Addr = addr
            .parse()
            .map_err(|_| crate::error::Error::config(format!("bad fake-ip address {addr:?}")))?;
        let prefix: u32 = prefix
            .parse()
            .map_err(|_| crate::error::Error::config(format!("bad fake-ip prefix {prefix:?}")))?;
        if !(2..=32).contains(&prefix) {
            return Err(crate::error::Error::config(format!(
                "fake-ip prefix /{prefix} out of range"
            )));
        }
        let base = u32::from(addr) & mask_of(prefix);
        let size = (1u32 << (32 - prefix)).saturating_sub(2).max(1);
        Ok(FakeIpPool {
            base,
            size,
            inner: Mutex::new(Inner {
                cursor: 0,
                by_domain: HashMap::new(),
                by_ip: HashMap::new(),
                order: Vec::new(),
            }),
        })
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
}
