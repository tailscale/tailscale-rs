use core::task::Context;
use std::{io, pin::Pin, task::Poll};

use bytes::{BufMut, Bytes};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

pin_project_lite::pin_project! {
    /// I/O wrapper that has data prefixed before the inner reader.
    ///
    /// This can't use [`tokio::io::Chain`] because it doesn't impl `AsyncWrite` for the inner type,
    /// and we need both.
    pub struct PrefixedReader<T> {
        prefix: Bytes,
        #[pin]
        inner: T,
    }
}

impl<T> PrefixedReader<T> {
    pub fn new(inner: T, prefix: Bytes) -> PrefixedReader<T> {
        PrefixedReader { prefix, inner }
    }
}

impl<T: AsyncRead> AsyncRead for PrefixedReader<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let slf = self.project();

        if slf.prefix.is_empty() {
            return slf.inner.poll_read(cx, buf);
        }

        buf.put(slf.prefix);
        Poll::Ready(Ok(()))
    }
}

impl<T: AsyncWrite> AsyncWrite for PrefixedReader<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.project().inner.poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}
