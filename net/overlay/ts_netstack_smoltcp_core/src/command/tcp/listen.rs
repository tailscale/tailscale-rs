//! TCP listener commands.

use core::net::SocketAddr;

use smoltcp::iface::SocketHandle;

use crate::{command, socket_impl::tcp::ListenerHandle};

/// Commands to control TCP listeners.
#[derive(Debug)]
pub enum Command {
    /// Begin listening on the given endpoint.
    Listen {
        /// The endpoint to begin listening on.
        local_endpoint: SocketAddr,
    },

    /// Accept an incoming connection on the given listener.
    ///
    /// Response channel blocks until a connection is made.
    Accept {
        /// The handle of the listener to accept on.
        handle: ListenerHandle,
    },

    /// Close the given listener.
    ///
    /// Happy-path response: [`Response::Ok`][command::Response::Ok].
    Close {
        /// The handle of hte listener to close.
        handle: ListenerHandle,
    },
}

impl From<Command> for command::Command {
    fn from(value: Command) -> Self {
        command::Command::TcpListen(value)
    }
}

/// Responses to TCP listener [`Command`]s.
#[derive(Debug)]
pub enum Response {
    /// Successfully listening on the requested endpoint.
    Listening {
        /// Handle of the new listener.
        handle: ListenerHandle,
    },
    /// Successfully accepted an incoming TCP connection.
    Accepted {
        /// Address of the remote that initiated the connection.
        remote: SocketAddr,
        /// Handle of the new TCP connection.
        handle: SocketHandle,
    },
}

impl From<Response> for command::Response {
    fn from(value: Response) -> Self {
        Self::TcpListen(value)
    }
}
