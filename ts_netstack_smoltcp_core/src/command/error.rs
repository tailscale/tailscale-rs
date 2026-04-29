use std::fmt;

use smoltcp::socket::{
    icmp::BindError as IcmpBindError,
    raw::BindError as RawBindError,
    tcp::{ConnectError, ListenError, SendError as TcpSendError},
    udp::{BindError as UdpBindError, SendError as UdpSendError},
};

use crate::command;

/// Error while interacting with the netstack.
#[derive(thiserror::Error, Debug, Clone)]
pub enum Error {
    /// The request contained invalid parameters. Retrying will not resolve this issue.
    ///
    /// Common causes for this error are that a specified address was invalid, the socket
    /// a handle refers to no longer exists, or the packet to be sent was too large for the
    /// socket's buffer capacity.
    #[error("invalid request ({0})")]
    BadRequest(BadRequestReason),

    /// The supplied buffer was unsuitable (e.g., zero-size).
    #[error("the supplied buffer was unsuitable")]
    BadBuffer,

    /// An internal error occured.
    #[error("An internal error occured: {0}")]
    Internal(InternalErrorKind),

    /// A TCP connection was reset.
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
    pub fn oom() -> Self {
        Error::BadRequest(BadRequestReason::OutOfMemory)
    }

    /// Error constructor for zero port number.
    pub fn zero_port() -> Self {
        Error::BadRequest(BadRequestReason::ZeroPort)
    }

    /// Error constructor for an unaddressable packet.
    pub fn unaddressable() -> Self {
        Error::BadRequest(BadRequestReason::Unaddressable)
    }
}

/// Informational detail on the kind of internal error.
#[derive(Debug, Clone)]
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
        }
    }
}

/// The reason for an [`Error::BadRequest`] error.
#[derive(Debug, Clone)]
pub enum BadRequestReason {
    /// Packet unaddressable.
    Unaddressable,
    /// Packet too large.
    BigPacket,
    /// Not enough memory to complete operation.
    OutOfMemory,
    /// 0 port specified.
    ZeroPort,
}

impl fmt::Display for BadRequestReason {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BadRequestReason::Unaddressable => write!(f, "packet unaddressable"),
            BadRequestReason::BigPacket => write!(f, "packet too large"),
            BadRequestReason::OutOfMemory => write!(f, "not enough memory to complete operation"),
            BadRequestReason::ZeroPort => write!(f, "0 port specified"),
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
            UdpSendError::BufferFull => Error::oom(),
        }
    }
}

#[cfg(feature = "std")]
impl From<Error> for std::io::Error {
    fn from(value: Error) -> Self {
        use std::io::{Error as StdErr, ErrorKind};

        match value {
            Error::BadRequest(_) => StdErr::new(ErrorKind::InvalidInput, value),
            Error::ConnectionReset => {
                std::io::Error::new(std::io::ErrorKind::ConnectionReset, value)
            }
            other => StdErr::other(other),
        }
    }
}
