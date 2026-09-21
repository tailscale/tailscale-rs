//! Commands for raw sockets.

use core::{
    fmt::{Debug, Formatter},
    num::NonZeroUsize,
};

use bytes::Bytes;
use smoltcp::{iface::SocketHandle, wire};

use crate::command;

/// Commands to control raw IP sockets.
pub enum Command {
    /// Open a raw socket with the given IP version and protocol.
    ///
    /// This socket should be expected to intercept _all_ matching traffic, overriding
    /// protocol-specific sockets.
    Open {
        /// The IP version the socket will match.
        ip_version: wire::IpVersion,
        /// The IP protocol the socket will match.
        protocol: wire::IpProtocol,
    },
    /// Send a raw IP packet.
    Send {
        /// The raw packet bytes.
        buf: Bytes,
    },
    /// Receive a raw IP packet.
    Recv {
        /// If `Some`, limit the max length of the response to this length.
        ///
        /// [`Response::Recv::truncated`] will be populated if there was not enough space
        /// available.
        max_len: Option<NonZeroUsize>,
    },
    /// Close the socket.
    ///
    /// This message must be sent once socket operations are complete to avoid a resource
    /// leak; we have no other way to detect that the remote socket channel has closed.
    Close,
}

impl From<Command> for command::Command {
    fn from(value: Command) -> Self {
        command::Command::Raw(value)
    }
}

impl Debug for Command {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Open {
                ip_version,
                protocol,
            } => f
                .debug_struct("Open")
                .field("ip_version", ip_version)
                .field("protocol", protocol)
                .finish(),
            Self::Send { buf } => f.debug_struct("Send").field("buf_len", &buf.len()).finish(),
            Self::Recv { max_len } => f.debug_struct("Recv").field("max_len", max_len).finish(),
            Self::Close => f.write_str("Close"),
        }
    }
}

/// Responses to raw socket [`Command`]s.
pub enum Response {
    /// Socket was opened successfully.
    Opened {
        /// The handle of the opened socket.
        handle: SocketHandle,
    },

    /// An IP packet was received.
    Recv {
        /// The raw packet payload.
        buf: Bytes,

        /// If `Some`, the `buf` field was truncated because the [`Command::Recv::max_len`]
        /// was shorter than the actual received packet length.
        ///
        /// Holds the original length of `buf` before truncation.
        truncated: Option<usize>,
    },
}

impl From<Response> for command::Response {
    fn from(value: Response) -> Self {
        Self::Raw(value)
    }
}

impl Debug for Response {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Opened { handle } => f.debug_struct("Opened").field("handle", handle).finish(),
            Self::Recv { buf, truncated } => f
                .debug_struct("Recv")
                .field("buf_len", &buf.len())
                .field("truncated", truncated)
                .finish(),
        }
    }
}
