//! Transport stream plumbing: the boxed stream every protocol returns,
//! and the byte-counting wrapper feeding traffic statistics.

use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Any duplex byte stream the engine can proxy over.
pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> ProxyStream for T {}

/// Owned, type-erased proxy stream.
pub type BoxProxyStream = Box<dyn ProxyStream>;

/// Shared byte counters (one pair per connection, aggregated by the
/// connection table).
#[derive(Debug, Default)]
pub struct ByteCounters {
    pub rx: AtomicU64,
    pub tx: AtomicU64,
}

impl ByteCounters {
    pub fn snapshot(&self) -> (u64, u64) {
        (self.rx.load(Ordering::Relaxed), self.tx.load(Ordering::Relaxed))
    }
}

/// Wraps a stream, tallying bytes in both directions.
pub struct CountingStream<S> {
    inner: S,
    counters: Arc<ByteCounters>,
}

impl<S> CountingStream<S> {
    pub fn new(inner: S, counters: Arc<ByteCounters>) -> Self {
        CountingStream { inner, counters }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for CountingStream<S> {
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &mut ReadBuf<'_>) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let out = Pin::new(&mut self.inner).poll_read(cx, buf);
        if let Poll::Ready(Ok(())) = &out {
            let n = buf.filled().len().saturating_sub(before);
            if n > 0 {
                self.counters.rx.fetch_add(n as u64, Ordering::Relaxed);
            }
        }
        out
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for CountingStream<S> {
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<io::Result<usize>> {
        let out = Pin::new(&mut self.inner).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = &out {
            self.counters.tx.fetch_add(*n as u64, Ordering::Relaxed);
        }
        out
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn counting_stream_tallies_both_directions() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let counters = Arc::new(ByteCounters::default());
        let (mut a, b) = tokio::io::duplex(64);
        let mut counted = CountingStream::new(b, counters.clone());
        a.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        counted.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"hello");
        assert_eq!(counters.snapshot(), (5, 0));
        counted.write_all(b"world!").await.unwrap();
        let mut buf = [0u8; 6];
        a.read_exact(&mut buf).await.unwrap();
        assert_eq!(&buf, b"world!");
        assert_eq!(counters.snapshot(), (5, 6));
    }
}
