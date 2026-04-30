//! Messages for TCP streams.

use core::{
    fmt::{Debug, Formatter},
    net::SocketAddr,
};

use bytes::Bytes;
use smoltcp::iface::SocketHandle;

use crate::command;

/// The connection was reset or closed.
#[derive(thiserror::Error, Debug, Copy, Clone, PartialEq, Eq)]
#[error("connection reset or closed")]
pub struct ConnectionResetOrClosed;

#[cfg(feature = "std")]
impl From<ConnectionResetOrClosed> for std::io::Error {
    fn from(_: ConnectionResetOrClosed) -> Self {
        std::io::ErrorKind::ConnectionReset.into()
    }
}

/// Commands for controlling TCP streams.
pub enum Command {
    /// Connect from the given local endpoint to the given remote endpoint.
    ///
    /// Neither endpoint may use an unspecified (zero) port.
    Connect {
        /// The local endpoint to connect from.
        local_endpoint: SocketAddr,
        /// The remote endpoint to connect to.
        remote_endpoint: SocketAddr,
    },

    /// Receive data incoming on the socket.
    ///
    /// Blocks until at least one byte can be received (or the remote closes its end of the
    /// stream).
    Recv {
        /// If `Some`, limit the length of the received data to at most the contained value.
        /// Otherwise, no limit.
        ///
        /// The payload may contain less data than specified here.
        ///
        /// Intended to be used to emulate socket APIs where the caller provides a byte
        /// buffer -- e.g. `sock.recv(&mut [u8])` -- where providing more data than the
        /// available buffer length would cause data loss.
        max_len: Option<usize>,
    },

    /// Send bytes over the connection.
    ///
    /// Blocks until at least one byte can be sent.
    Send {
        /// Bytes to send over the connection.
        buf: Bytes,
    },

    /// Close this connection.
    ///
    /// This message causes the connection to enter the closing state, but responds
    /// immediately -- the netstack does not wait to respond until the state machine
    /// finishes closing gracefully (this occurs in the background).
    Close,
}

impl Debug for Command {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Connect {
                local_endpoint,
                remote_endpoint,
            } => f
                .debug_struct("Connect")
                .field("local_endpoint", local_endpoint)
                .field("remote_endpoint", remote_endpoint)
                .finish(),
            Self::Recv { max_len } => f.debug_struct("Recv").field("max_len", max_len).finish(),
            Self::Send { buf } => f.debug_struct("Send").field("buf_len", &buf.len()).finish(),
            Self::Close => f.write_str("Close"),
        }
    }
}

impl From<Command> for command::Command {
    fn from(value: Command) -> Self {
        command::Command::TcpStream(value)
    }
}

/// Responses to TCP stream [`Command`]s.
pub enum Response {
    /// Connection opened successfully.
    Connected {
        /// Handle for the newly created socket.
        handle: SocketHandle,
    },

    /// Sent `n` bytes over the connection
    Sent {
        /// The number of bytes of the original buffer that were accepted to be sent.
        ///
        /// Always at least 1.
        n: usize,
    },

    /// Received the contained bytes from the remote.
    Recv {
        /// Bytes received from the remote.
        buf: Bytes,
    },

    /// The remote has closed the sending side of its connection and will not send any more
    /// data; EOF.
    Finished,
}

impl From<Response> for command::Response {
    fn from(value: Response) -> Self {
        Self::TcpStream(value)
    }
}

impl Debug for Response {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Connected { handle } => {
                f.debug_struct("Connected").field("handle", handle).finish()
            }
            Self::Sent { n } => f.debug_struct("Sent").field("n", n).finish(),
            Self::Recv { buf } => f.debug_struct("Recv").field("buf_len", &buf.len()).finish(),
            Self::Finished => f.write_str("Finished"),
        }
    }
}
