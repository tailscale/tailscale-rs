use core::{
    borrow::Borrow,
    pin::Pin,
    task::{Context, Poll},
};
use std::{io::Read, os::fd::AsRawFd};

use futures_util::Stream;
use libc::{PF_ROUTE, SO_USELOOPBACK, SOL_SOCKET};
use nom::Parser;
use socket2::{Domain, Socket, Type};
use tokio::io::{Interest, unix::AsyncFd};
use zerocopy::IntoBytes;

use crate::bsd::net_table;

/// A socket handling [`PF_ROUTE`] messages to/from a BSD kernel.
pub struct RouteSocket {
    fd: AsyncFd<Socket>,
}

impl RouteSocket {
    /// Construct a new [`RouteSocket`].
    pub fn new() -> std::io::Result<Self> {
        let sock = Socket::new(Domain::from(PF_ROUTE), Type::RAW, None)?;
        sock.set_nonblocking(true)?;

        // SAFETY: this usage of the `setsockopt` API is correct.
        unsafe {
            libc::setsockopt(
                sock.as_raw_fd(),
                SOL_SOCKET,
                SO_USELOOPBACK,
                &0u8 as *const u8 as *const _,
                1,
            );
        }

        let fd = AsyncFd::new(sock)?;
        Ok(Self { fd })
    }

    /// Produce a stream of raw messages as [`bytes::BytesMut`].
    ///
    /// The contents are not interpreted or guaranteed to be valid, the messages are simply deframed
    /// according to the initial length word.
    pub fn raw_msg_stream(&self) -> MsgStream<&Self> {
        MsgStream {
            rtsock: self,
            buf: bytes::BytesMut::new(),
        }
    }

    /// Send a message over the route socket.
    pub async fn send_raw(&self, msg: &[u8]) -> std::io::Result<usize> {
        self.fd
            .async_io(Interest::WRITABLE, |sock| sock.send(msg))
            .await
    }
}

/// A stream of raw messages from a [`RouteSocket`].
pub struct MsgStream<RS> {
    /// The socket from which we're streaming packets.
    rtsock: RS,

    /// Working buffer which holds undecoded state.
    ///
    /// We receive from the socket into this buffer and then yield messages out of it one-at-a-time
    /// until it empties (then repeat).
    ///
    /// This is stored as a field rather than as a local var on [`MsgStream`] to avoid thrashing
    /// allocations where possible; it's likely that we'll end up with a bigger chunk of memory than
    /// we need and will be able to skip allocating in some cases.
    buf: bytes::BytesMut,
}

impl<RS> MsgStream<RS> {
    /// Construct a new [`MsgStream`] around the given routing socket.
    pub fn new(rs: RS) -> MsgStream<RS> {
        Self {
            rtsock: rs,
            buf: bytes::BytesMut::new(),
        }
    }
}

impl<RS> MsgStream<RS> {
    /// Nominal buffer size for receiving from a `PF_ROUTE` socket.
    const BUF_SIZE: usize = 8192;
}

impl<RS> Stream for MsgStream<RS>
where
    RS: Borrow<RouteSocket> + Unpin,
{
    type Item = std::io::Result<bytes::BytesMut>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut slf = self.as_mut();

        loop {
            while !slf.buf.is_empty() {
                let msg_len = match net_table::msg_chunk().parse_complete(slf.buf.as_bytes()) {
                    Ok((rest, _msg)) => {
                        let full_msg_len = slf.buf.len() - rest.len();
                        debug_assert_eq!(_msg.len(), full_msg_len);

                        tracing::trace!(rest_len = rest.len(), full_msg_len, msg_len = _msg.len());

                        Some(full_msg_len)
                    }

                    // Fine to bail here, the error condition here is that the message didn't start
                    // with a valid length u16, i.e. the rest of the input wasn't long enough.
                    Err(nom::Err::Failure(e) | nom::Err::Error(e)) => {
                        tracing::error!(error = ?e, "malformed PF_ROUTE message");
                        None
                    }

                    // Chunk was truncated in the input. Not possible because we're calling
                    // `parse_complete` above, so incompletes get converted to errors.
                    Err(nom::Err::Incomplete(_n)) => {
                        unreachable!("incomplete PF_ROUTE message");
                    }
                };

                tracing::trace!(?msg_len);

                let Some(msg_len) = msg_len else {
                    slf.buf.clear();
                    continue;
                };

                // Re-split the message; this is fine because net_table::msg_chunk() doesn't discard
                // data, it's actual-size.
                let msg = slf.buf.split_to(msg_len);
                return Poll::Ready(Some(Ok(msg)));
            }

            loop {
                let Self { rtsock, buf } = &mut *slf;
                let rtsock: &RouteSocket = (*rtsock).borrow();

                let mut rdy = core::task::ready!(rtsock.fd.poll_read_ready(cx))?;
                buf.resize(Self::BUF_SIZE, 0);

                let n = match rdy.try_io(|sock| {
                    let mut sock = sock.get_ref();
                    sock.read(buf.as_mut())
                }) {
                    Err(_) => {
                        buf.clear();
                        continue;
                    }
                    Ok(n) => n?,
                };

                buf.truncate(n);
                break;
            }
        }
    }
}

#[cfg(test)]
mod test {
    use std::os::fd::FromRawFd;

    use bytes::{BufMut, BytesMut};
    use futures_util::StreamExt;

    use super::*;

    /// Just assert that opening the socket works.
    #[tokio::test]
    async fn open() {
        RouteSocket::new().unwrap();
    }

    fn mock_socket() -> Result<(tokio::net::UnixDatagram, RouteSocket), Box<dyn std::error::Error>>
    {
        let (sock_tx, sock_rx) = std::os::unix::net::UnixDatagram::pair()?;

        sock_tx.set_nonblocking(true)?;
        sock_rx.set_nonblocking(true)?;

        let sock_tx = tokio::net::UnixDatagram::from_std(sock_tx)?;

        let sock = unsafe { Socket::from_raw_fd(sock_rx.as_raw_fd()) };
        core::mem::forget(sock_rx);

        Ok((
            sock_tx,
            RouteSocket {
                fd: AsyncFd::new(sock)?,
            },
        ))
    }

    async fn assert_roundtrip(
        sock_tx: &tokio::net::UnixDatagram,
        rtsock: &RouteSocket,
        msg: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        let mut stream = rtsock.raw_msg_stream();
        sock_tx.send(msg).await?;

        let next = stream.next().await.unwrap()?;
        assert_eq!(next.as_bytes(), msg);

        Ok(())
    }

    #[tracing_test::traced_test]
    #[tokio::test]
    async fn simple() -> Result<(), Box<dyn std::error::Error>> {
        let (sock_tx, rtsock) = mock_socket()?;

        assert_roundtrip(&sock_tx, &rtsock, &2u16.to_ne_bytes()).await?;
        assert_roundtrip(
            &sock_tx,
            &rtsock,
            &[&4u16.to_ne_bytes()[..], &[1, 2]].concat(),
        )
        .await?;
        assert_roundtrip(
            &sock_tx,
            &rtsock,
            &[&34u16.to_ne_bytes()[..], &[0xab; 32][..]].concat(),
        )
        .await?;

        Ok(())
    }

    proptest::proptest! {
        #[test]
        fn arb_msg(
            payload in proptest::collection::vec(
                proptest::prelude::any::<u8>(),
                0..2046,
            )
        ) {
            let mut b = BytesMut::new();
            b.put_u16_ne((payload.len() as u16).checked_add(2).unwrap());
            b.put_slice(&payload);

            tokio::runtime::Runtime::new()?.block_on(async move {
                let (sock_tx, rtsock) = mock_socket().unwrap();
                assert_roundtrip(&sock_tx, &rtsock, &b).await.unwrap();
            });
        }
    }
}
