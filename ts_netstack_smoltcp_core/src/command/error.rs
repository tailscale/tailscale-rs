use std::fmt;

use smoltcp::socket::{
    icmp::BindError as IcmpBindError,
    raw::BindError as RawBindError,
    tcp::{ConnectError, ListenError, SendError as TcpSendError},
    udp::{BindError as UdpBindError, SendError as UdpSendError},
};

use crate::command;

/// Error while interacting with the netstack.
#[derive(thiserror::Error, Debug, Clone, Copy, Eq, PartialEq)]
pub enum Error {
    /// The request contained invalid parameters. Retrying will not resolve this issue.
    ///
    /// Common causes for this error are that a specified address was invalid, there is not enough
    /// memory available in the current configuration to complete the request, or the packet to be
    /// sent was too large for the socket's buffer capacity.
    #[error("invalid request ({0})")]
    BadRequest(BadRequestReason),

    /// An internal error occured.
    ///
    /// These errors are either unrevocerable, due to a bug in our code, or caused by a rare
    /// and intermittent issue.
    #[error("An internal error occured: {0}")]
    Internal(InternalErrorKind),

    /// A TCP connection was reset.
    ///
    /// These errors can often be handled by retrying.
    #[error("connection reset")]
    ConnectionReset,
}

impl Error {
    /// Error constructor for the wrong type of command response.
    pub fn wrong_type() -> Self {
        Error::Internal(InternalErrorKind::InternalResponseMismatch)
    }

    /// Error constructor for an invalid socket state.
    pub fn invalid_socket_state() -> Self {
        Error::Internal(InternalErrorKind::InvalidSocketState)
    }

    /// Error constructor for a missing TCP listener.
    pub fn missing_listener() -> Self {
        Error::Internal(InternalErrorKind::BadListenerHandle)
    }

    /// Error constructor for a missing socket.
    pub fn missing_socket() -> Self {
        Error::Internal(InternalErrorKind::BadSocketHandle)
    }

    /// Error constructor for an over-size packet.
    pub fn big_packet() -> Self {
        Error::BadRequest(BadRequestReason::BigPacket)
    }

    /// Error constructor for out-of-memory (likely in a specific component, rather than a system OOM).
    pub fn buffer_full() -> Self {
        Error::Internal(InternalErrorKind::BufferFull)
    }

    /// Error constructor for an unaddressable packet.
    pub fn unaddressable() -> Self {
        Error::BadRequest(BadRequestReason::Unaddressable)
    }

    /// Error constructor for a zero-sized buffer.
    pub fn zero_buffer() -> Self {
        Error::BadRequest(BadRequestReason::ZeroSizeBuffer)
    }
}

/// Informational detail on the kind of internal error.
///
/// This detail is unlikely to help in error recovery but could be used in logs or user-facing
/// reporting to add detail to an error report.
// If adding variants, be sure to add them to `tailscale::error::InternalErrorKind` too (including
// the `From` impl, which will panic otherwise).
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum InternalErrorKind {
    /// Invalid socket state.
    InvalidSocketState,
    /// Response type mismatched to request type.
    InternalResponseMismatch,
    /// Channel closed.
    InternalChannelClosed,
    /// Handle to invalid TCP listener.
    BadListenerHandle,
    /// Handle to invalid socket.
    BadSocketHandle,
    /// UDP buffer full
    BufferFull,
}

impl fmt::Display for InternalErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            InternalErrorKind::InvalidSocketState => write!(f, "invalid socket state"),
            InternalErrorKind::InternalResponseMismatch => {
                write!(f, "response type mismatched to request type")
            }
            InternalErrorKind::InternalChannelClosed => write!(f, "channel closed"),
            InternalErrorKind::BadListenerHandle => write!(f, "handle to invalid TCP listener"),
            InternalErrorKind::BadSocketHandle => write!(f, "handle to invalid socket"),
            InternalErrorKind::BufferFull => write!(f, "buffer full"),
        }
    }
}

/// The reason for an [`Error::BadRequest`] error.
#[non_exhaustive]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BadRequestReason {
    /// Packet unaddressable.
    Unaddressable,
    /// Packet is too large to fit in socket buffer".
    BigPacket,
    /// The size of a user-supplied is zero, so cannot store a packet.
    ZeroSizeBuffer,
}

impl fmt::Display for BadRequestReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BadRequestReason::Unaddressable => write!(f, "packet unaddressable"),
            BadRequestReason::BigPacket => write!(f, "packet is too large to fit in socket buffer"),
            BadRequestReason::ZeroSizeBuffer => write!(f, "the size of a user-supplied is zero"),
        }
    }
}

impl From<Error> for command::Response {
    fn from(value: Error) -> Self {
        command::Response::Error(value)
    }
}

impl<T> From<flume::SendError<T>> for Error {
    fn from(_: flume::SendError<T>) -> Self {
        Error::Internal(InternalErrorKind::InternalChannelClosed)
    }
}

impl From<flume::RecvError> for Error {
    fn from(_: flume::RecvError) -> Self {
        Error::Internal(InternalErrorKind::InternalChannelClosed)
    }
}

impl From<ListenError> for Error {
    fn from(value: ListenError) -> Self {
        match value {
            ListenError::InvalidState => Error::invalid_socket_state(),
            ListenError::Unaddressable => Error::unaddressable(),
        }
    }
}

impl From<ConnectError> for Error {
    fn from(value: ConnectError) -> Self {
        match value {
            ConnectError::InvalidState => Error::invalid_socket_state(),
            ConnectError::Unaddressable => Error::unaddressable(),
        }
    }
}

impl From<UdpBindError> for Error {
    fn from(value: UdpBindError) -> Self {
        match value {
            UdpBindError::InvalidState => Error::invalid_socket_state(),
            UdpBindError::Unaddressable => Error::unaddressable(),
        }
    }
}

impl From<RawBindError> for Error {
    fn from(value: RawBindError) -> Self {
        match value {
            RawBindError::InvalidState => Error::invalid_socket_state(),
            RawBindError::Unaddressable => Error::unaddressable(),
        }
    }
}

impl From<IcmpBindError> for Error {
    fn from(value: IcmpBindError) -> Self {
        match value {
            IcmpBindError::InvalidState => Error::invalid_socket_state(),
            IcmpBindError::Unaddressable => Error::unaddressable(),
        }
    }
}

impl From<TcpSendError> for Error {
    fn from(value: TcpSendError) -> Self {
        match value {
            TcpSendError::InvalidState => Error::ConnectionReset,
        }
    }
}

impl From<UdpSendError> for Error {
    fn from(value: UdpSendError) -> Self {
        match value {
            UdpSendError::Unaddressable => Error::unaddressable(),
            UdpSendError::BufferFull => Error::buffer_full(),
        }
    }
}

#[cfg(feature = "std")]
impl From<Error> for std::io::Error {
    fn from(value: Error) -> Self {
        match value {
            Error::BadRequest(_) => std::io::ErrorKind::InvalidInput.into(),
            Error::ConnectionReset => std::io::ErrorKind::ConnectionReset.into(),
            other => std::io::Error::other(other),
        }
    }
}
