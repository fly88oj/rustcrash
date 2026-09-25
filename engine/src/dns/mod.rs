//! DNS subsystem: wire codec, fake-IP pool, resolver, upstream transports.

pub mod edns;
pub mod fakeip;
pub mod policy;
pub mod resolver;
pub mod rules;
pub mod upstream;
pub mod wire;

/// The `dns` outbound's UDP echo (mihomo RelayDnsPacket, adapter/
/// outbound/dns.go:134-156): every datagram is answered by the engine
/// resolver and echoed back from the fixed 127.0.0.2:53 source.
pub struct DnsUdpEcho {
    engine: std::sync::Arc<resolver::DnsEngine>,
    pending: tokio::sync::Mutex<std::collections::VecDeque<(crate::addr::NetAddr, Vec<u8>)>>,
}

impl DnsUdpEcho {
    pub fn new(engine: std::sync::Arc<resolver::DnsEngine>) -> Self {
        DnsUdpEcho {
            engine,
            pending: tokio::sync::Mutex::new(Default::default()),
        }
    }

    pub async fn send(&self, data: &[u8]) -> crate::error::Result<()> {
        let resp = self.engine.handle(data).await;
        self.pending.lock().await.push_back((
            crate::addr::NetAddr::ip("127.0.0.2".parse().unwrap(), 53),
            resp,
        ));
        Ok(())
    }

    pub async fn recv(&self) -> crate::error::Result<(crate::addr::NetAddr, Vec<u8>)> {
        self.pending
            .lock()
            .await
            .pop_front()
            .ok_or_else(|| crate::error::Error::network("dns echo channel closed"))
    }
}
