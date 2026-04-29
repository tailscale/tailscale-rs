use core::{
    fmt::{Debug, Formatter},
    net::SocketAddr,
};

use bytes::Bytes;
use netcore::{DisplayExt, HasChannel, Response, smoltcp::iface::SocketHandle, tcp};

#[cfg(any(feature = "tokio", feature = "futures-io"))]
type PinBoxFut<T> = core::pin::Pin<alloc::boxed::Box<dyn Future<Output = T> + Send>>;

/// A TCP stream.
pub struct TcpStream {
    sender: netcore::Channel,
    handle: SocketHandle,

    local: SocketAddr,
    remote: SocketAddr,

    #[cfg(any(feature = "tokio", feature = "futures-io"))]
    read_fut: Option<PinBoxFut<Result<Bytes, netcore::Error>>>,
    #[cfg(any(feature = "tokio", feature = "futures-io"))]
    write_fut: Option<PinBoxFut<Result<usize, netcore::Error>>>,
}

impl TcpStream {
    pub(crate) const fn new(
        sender: netcore::Channel,
        handle: SocketHandle,
        remote: SocketAddr,
        local: SocketAddr,
    ) -> Self {
        Self {
            sender,
            handle,
            remote,
            local,

            #[cfg(any(feature = "tokio", feature = "futures-io"))]
            read_fut: None,

            #[cfg(any(feature = "tokio", feature = "futures-io"))]
            write_fut: None,
        }
    }
}

// SAFETY: unsafe because of the contained futures which are not necessarily Sync. We know
// however that they're guaranteed to only be accessed or mutated via a &mut ref
// (in the Async{Read,Write} impls), implying no simultaneous cross-thread access is possible.
#[cfg(any(feature = "tokio", feature = "futures-io"))]
unsafe impl Sync for TcpStream {}

impl Debug for TcpStream {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcpStream")
            .field("handle", &self.handle.as_display_debug())
            .field("local_endpoint", &self.local)
            .field("remote_endpoint", &self.remote)
            .finish()
    }
}

impl TcpStream {
    /// Report the local endpoint to which this stream is connected.
    pub const fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Report the remote endpoint to which this stream is connected.
    pub const fn remote_addr(&self) -> SocketAddr {
        self.remote
    }

    /// Send bytes to the remote.
    ///
    /// Blocks until at least one byte can be queued. The return value is the number of
    /// bytes actually sent.
    pub fn send_blocking(&self, b: &[u8]) -> Result<usize, netcore::Error> {
        let resp = self.request_blocking(tcp::stream::Command::Send {
            buf: Bytes::copy_from_slice(b),
        })?;

        self._send(resp)
    }

    /// Send bytes to the remote.
    ///
    /// Blocks until at least one byte can be queued. The return value is the number of
    /// bytes actually sent.
    pub async fn send(&self, b: &[u8]) -> Result<usize, netcore::Error> {
        let resp = self
            .request(tcp::stream::Command::Send {
                buf: Bytes::copy_from_slice(b),
            })
            .await?;

        self._send(resp)
    }

    fn _send(&self, resp: Response) -> Result<usize, netcore::Error> {
        netcore::try_response_as!(resp, tcp::stream::Response::Sent { n });
        Ok(n)
    }

    /// Receive bytes from the remote.
    ///
    /// Returns the number of bytes actually received (blocks until there is at least one).
    pub fn recv_blocking(&self, b: &mut [u8]) -> Result<usize, netcore::Error> {
        let resp = self.request_blocking(tcp::stream::Command::Recv {
            max_len: Some(b.len()),
        })?;

        self._recv(resp, b)
    }

    /// Receive bytes from the remote into the supplied buffer.
    ///
    /// Returns the number of bytes actually received (blocks until there is at least one).
    pub async fn recv(&self, b: &mut [u8]) -> Result<usize, netcore::Error> {
        let resp = self
            .request(tcp::stream::Command::Recv {
                max_len: Some(b.len()),
            })
            .await?;

        self._recv(resp, b)
    }

    /// Receive bytes from the remote.
    ///
    /// Returns the number of bytes actually received (blocks until there is at least one).
    pub fn recv_bytes_blocking(&self) -> Result<Bytes, netcore::Error> {
        let resp = self.request_blocking(tcp::stream::Command::Recv { max_len: None })?;

        self._recv_bytes(resp)
    }

    /// Receive bytes from the remote.
    pub async fn recv_bytes(&self) -> Result<Bytes, netcore::Error> {
        let resp = self
            .request(tcp::stream::Command::Recv { max_len: None })
            .await?;

        self._recv_bytes(resp)
    }

    fn _recv(&self, resp: Response, b: &mut [u8]) -> Result<usize, netcore::Error> {
        let buf = self._recv_bytes(resp)?;

        let n = buf.len().min(b.len());
        b[..n].copy_from_slice(&buf[..n]);

        Ok(n)
    }

    fn _recv_bytes(&self, resp: Response) -> Result<Bytes, netcore::Error> {
        if matches!(resp, Response::TcpStream(tcp::stream::Response::Finished)) {
            return Ok(Bytes::new());
        }

        netcore::try_response_as!(resp, tcp::stream::Response::Recv { buf });
        Ok(buf)
    }

    #[cfg(any(feature = "tokio", feature = "futures-io"))]
    fn poll_read(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context,
        buf: &mut [u8],
    ) -> core::task::Poll<std::io::Result<usize>> {
        use netcore::HasChannel;

        let handle = self.handle;
        let cap = buf.len();

        loop {
            match self.read_fut.as_mut() {
                None => {
                    let sender = self.sender.clone();

                    let _ret = self.read_fut.insert(alloc::boxed::Box::pin(async move {
                        let resp = sender
                            .request(
                                Some(handle),
                                tcp::stream::Command::Recv { max_len: Some(cap) },
                            )
                            .await?;

                        match resp.try_into()? {
                            tcp::stream::Response::Recv { buf } => Ok(buf),
                            tcp::stream::Response::Finished => Ok(Bytes::new()),
                            _ => Err(netcore::Error::wrong_type()),
                        }
                    }));
                }

                Some(x) => {
                    let poll_result = x.as_mut().poll(cx);
                    let ret = core::task::ready!(poll_result)?;

                    buf[..ret.len()].copy_from_slice(&ret);

                    self.read_fut.take();

                    break core::task::Poll::Ready(Ok(ret.len()));
                }
            }
        }
    }

    #[cfg(any(feature = "tokio", feature = "futures-io"))]
    fn poll_write(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &[u8],
    ) -> core::task::Poll<std::io::Result<usize>> {
        use netcore::HasChannel;

        let handle = self.handle;

        loop {
            match &mut self.write_fut {
                None => {
                    let b = Bytes::copy_from_slice(buf);
                    let sender = self.sender.clone();

                    let _ret = self.write_fut.insert(alloc::boxed::Box::pin(async move {
                        let resp = sender
                            .request(Some(handle), tcp::stream::Command::Send { buf: b })
                            .await?;

                        netcore::try_response_as!(resp, tcp::stream::Response::Sent { n });
                        Ok(n)
                    }));
                }

                Some(x) => {
                    let poll_result = x.as_mut().poll(cx);
                    let ret = core::task::ready!(poll_result)?;

                    self.write_fut.take();

                    break core::task::Poll::Ready(Ok(ret));
                }
            }
        }
    }

    socket_requestor_impl!();
}

impl Drop for TcpStream {
    fn drop(&mut self) {
        if let Err(e) = self
            .sender
            .request_nonblocking(Some(self.handle), tcp::stream::Command::Close)
        {
            tracing::warn!(err = %e, "possible socket leak");
        }
    }
}

#[cfg(feature = "std")]
impl std::io::Read for TcpStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        self.recv_blocking(buf).map_err(netcore::Error::into)
    }
}

#[cfg(feature = "std")]
impl std::io::Write for TcpStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.send_blocking(buf).map_err(netcore::Error::into)
    }

    fn write_all(&mut self, buf: &[u8]) -> std::io::Result<()> {
        let mut buf = Bytes::copy_from_slice(buf);

        while !buf.is_empty() {
            let resp = self.request_blocking(tcp::stream::Command::Send { buf: buf.clone() })?;
            netcore::try_response_as!(resp, tcp::stream::Response::Sent { n });

            let _consumed = buf.split_to(n);
        }

        Ok(())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[cfg(feature = "tokio")]
impl tokio::io::AsyncRead for TcpStream {
    fn poll_read(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> core::task::Poll<tokio::io::Result<()>> {
        let n = core::task::ready!(self.poll_read(cx, buf.initialize_unfilled()))?;
        buf.advance(n);

        core::task::Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "tokio")]
impl tokio::io::AsyncWrite for TcpStream {
    fn poll_write(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &[u8],
    ) -> core::task::Poll<std::io::Result<usize>> {
        self.poll_write(cx, buf)
    }

    fn poll_flush(
        self: core::pin::Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        core::task::Poll::Ready(Ok(()))
    }

    fn poll_shutdown(
        self: core::pin::Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        // NOTE(npry): explicit shutdown semantics don't make sense for us because we have to
        // support closing the socket out-of-band anyway, since we can't rely on an async runtime
        // driving us. This creates this unfortunate situation where calling shutdown doesn't
        // actually confirm that we're closed, so any dependents using close for signaling (before
        // dropping the socket) could hang here.
        core::task::Poll::Ready(Ok(()))
    }
}

#[cfg(feature = "futures-io")]
impl futures_io::AsyncRead for TcpStream {
    fn poll_read(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &mut [u8],
    ) -> core::task::Poll<std::io::Result<usize>> {
        self.poll_read(cx, buf)
    }
}

#[cfg(feature = "futures-io")]
impl futures_io::AsyncWrite for TcpStream {
    fn poll_write(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &[u8],
    ) -> core::task::Poll<std::io::Result<usize>> {
        self.poll_write(cx, buf)
    }

    fn poll_flush(
        self: core::pin::Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        core::task::Poll::Ready(Ok(()))
    }

    fn poll_close(
        self: core::pin::Pin<&mut Self>,
        _cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        // See note above in poll_shutdown.
        core::task::Poll::Ready(Ok(()))
    }
}
