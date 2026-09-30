use std::{
    pin::Pin,
    task::{Context, Poll, ready},
};

use bytes::Buf;
use futures_util::{Sink, Stream};
use tokio::io::{AsyncBufRead, AsyncRead, AsyncWrite, ReadBuf};

pin_project_lite::pin_project! {
    /// Simultaneous implementation of [`tokio_util::io::StreamReader`] and
    /// [`tokio_util::io::SinkWriter`], a wrapper that turns an inner `Stream<B1>` +
    /// `Sink<B2>` into `AsyncRead` + `AsyncWrite` (for bytes-like types `B1`, `B2`).
    ///
    /// This avoids interposing the superfluous mutexes required to split the original
    /// `Stream` + `Sink` then re-`join` them into a combined `AsyncRead` + `AsyncWrite`.
    /// We know the mutexes are superfluous because only one of `poll_read` and
    /// `poll_write` can be called at a time, as they take `Pin<&mut Self>`.
    ///
    /// This is a direct copy-paste of the `tokio_util` implementations; there's no
    /// clear reason that they're not the same type there.
    pub struct FramedIo<T, B> {
        #[pin]
        inner: T,
        chunk: Option<B>,
    }
}

impl<T, B> FramedIo<T, B> {
    /// Construct a new `FramedIo` around the inner `Stream` + `Sink`.
    pub const fn new(inner: T) -> Self {
        Self { inner, chunk: None }
    }

    /// Convert this into the inner I
    pub fn into_inner(self) -> (T, Option<B>) {
        (self.inner, self.chunk)
    }
}

impl<T, B> FramedIo<T, B>
where
    B: Buf,
{
    /// Do we have a chunk and is it non-empty?
    fn has_chunk(&self) -> bool {
        if let Some(ref chunk) = self.chunk {
            chunk.remaining() > 0
        } else {
            false
        }
    }
}

impl<T, B, E> AsyncRead for FramedIo<T, B>
where
    T: Stream<Item = Result<B, E>>,
    B: Buf,
    E: Into<std::io::Error>,
{
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        let inner_buf = match self.as_mut().poll_fill_buf(cx) {
            Poll::Ready(Ok(buf)) => buf,
            Poll::Ready(Err(err)) => return Poll::Ready(Err(err)),
            Poll::Pending => return Poll::Pending,
        };
        let len = std::cmp::min(inner_buf.len(), buf.remaining());
        buf.put_slice(&inner_buf[..len]);

        self.consume(len);
        Poll::Ready(Ok(()))
    }
}

impl<T, B, E> AsyncBufRead for FramedIo<T, B>
where
    T: Stream<Item = Result<B, E>>,
    B: Buf,
    E: Into<std::io::Error>,
{
    fn poll_fill_buf(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<std::io::Result<&[u8]>> {
        loop {
            if self.as_mut().has_chunk() {
                // This unwrap is very sad, but it can't be avoided.
                let buf = self.project().chunk.as_ref().unwrap().chunk();
                return Poll::Ready(Ok(buf));
            } else {
                match self.as_mut().project().inner.poll_next(cx) {
                    Poll::Ready(Some(Ok(chunk))) => {
                        // Go around the loop in case the chunk is empty.
                        *self.as_mut().project().chunk = Some(chunk);
                    }
                    Poll::Ready(Some(Err(err))) => return Poll::Ready(Err(err.into())),
                    Poll::Ready(None) => return Poll::Ready(Ok(&[])),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
    }

    fn consume(self: Pin<&mut Self>, amt: usize) {
        if amt > 0 {
            self.project()
                .chunk
                .as_mut()
                .expect("No chunk present")
                .advance(amt);
        }
    }
}

impl<T, B, E> AsyncWrite for FramedIo<T, B>
where
    T: for<'a> Sink<&'a [u8], Error = E>,
    E: Into<std::io::Error>,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let mut this = self.project();

        ready!(this.inner.as_mut().poll_ready(cx).map_err(Into::into))?;
        match this.inner.as_mut().start_send(buf) {
            Ok(()) => Poll::Ready(Ok(buf.len())),
            Err(e) => Poll::Ready(Err(e.into())),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx).map_err(Into::into)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_close(cx).map_err(Into::into)
    }
}
