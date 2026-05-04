use core::borrow::Borrow;

use smoltcp::iface::SocketHandle;

use crate::{ChannelClosedError, Command, Error, Netstack, Response, command::Request};

/// Channel type through which commands to the netstack flow.
// NOTE(npry): command channels are weak because the netstack holds a strong sender handle
// internally, as flume doesn't support cloning out senders from just a receiver. If this
// ever fails to upgrade, it means that the netstack we're talking to has been dropped, which is
// pretty error-shaped (the commands you submit over the channel will never complete). Maintaining
// this as a weak channel forces callers to handle the upgrade-failure case.
pub type Channel = flume::WeakSender<Request>;

/// Helper methods for types that can provide a [`Channel`].
pub trait HasChannel {
    /// Retrieve a [`Channel`] borrow.
    ///
    /// This is the only required method for this trait.
    fn borrow_channel(&self) -> impl Borrow<Channel> + Send;

    /// Clone a new command channel.
    fn command_channel(&self) -> Channel {
        self.borrow_channel().borrow().clone()
    }

    /// Send a request through the channel.
    ///
    /// Convenience wrapper around [`request_blocking`][crate::request_blocking].
    fn request_blocking(
        &self,
        handle: Option<SocketHandle>,
        command: impl Into<Command>,
    ) -> Result<Response, ChannelClosedError> {
        crate::request_blocking(self.borrow_channel().borrow(), handle, command)
    }

    /// Asynchronously send a request through the channel.
    ///
    /// Convenience wrapper around [`request`][crate::request].
    fn request(
        &self,
        handle: Option<SocketHandle>,
        command: impl Into<Command>,
    ) -> impl Future<Output = Result<Response, Error>> + Send {
        let ch = self.command_channel();
        let command = command.into();

        async move { crate::request(&ch, handle, command).await }
    }

    /// Send a nonblocking request, discarding any response.
    ///
    /// This is mainly intended for use in [`Drop`] implementations, as they can't be `async`
    /// and it would be frequently be surprising if they blocked the calling thread.
    ///
    /// Convenience wrapper around [`request_nonblocking`][crate::request_nonblocking].
    fn request_nonblocking(
        &self,
        handle: Option<SocketHandle>,
        command: impl Into<Command>,
    ) -> Result<(), ChannelClosedError> {
        crate::request_nonblocking(self.borrow_channel().borrow(), handle, command)
    }
}

impl HasChannel for Netstack {
    fn borrow_channel(&self) -> impl Borrow<Channel> + Send {
        self.command_tx.downgrade()
    }
}

impl HasChannel for Channel {
    fn borrow_channel(&self) -> impl Borrow<Channel> + Send {
        self
    }
}

impl<T> HasChannel for &T
where
    T: HasChannel,
{
    fn borrow_channel(&self) -> impl Borrow<Channel> + Send {
        (**self).borrow_channel()
    }
}

impl<T> HasChannel for &mut T
where
    T: HasChannel,
{
    fn borrow_channel(&self) -> impl Borrow<Channel> + Send {
        (**self).borrow_channel()
    }
}
