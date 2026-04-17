use crate::netstack::Error as NetstackError;

/// Errors that may occur while interacting with a device.
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Internal operation failed, likely a bug.
    #[error("internal operation returned an error")]
    InternalFailure,

    /// The runtime state was degraded: a component that we expected to be able to
    /// communicate with hung up or could not be reached.
    ///
    /// This usually means that an internal component has panicked or is wedged.
    #[error("runtime degraded, component unreachable")]
    RuntimeDegraded,

    /// An operation timed out.
    #[error("operation timed out")]
    Timeout,

    /// A connection was reset.
    #[error("connection reset")]
    ConnectionReset,
}

impl From<ts_runtime::Error> for Error {
    fn from(value: ts_runtime::Error) -> Self {
        match value.kind {
            ts_runtime::ErrorKind::Timeout => Error::Timeout,
            ts_runtime::ErrorKind::ActorGone => Error::RuntimeDegraded,
            ts_runtime::ErrorKind::MailboxFull | ts_runtime::ErrorKind::ReplyErr => {
                Error::InternalFailure
            }
        }
    }
}

impl From<NetstackError> for Error {
    fn from(value: NetstackError) -> Self {
        match value {
            NetstackError::ChannelClosed => Error::RuntimeDegraded,

            NetstackError::WrongType
            | NetstackError::BadRequest
            | NetstackError::InvariantViolated => Error::InternalFailure,

            NetstackError::TcpStream(_) => Error::ConnectionReset,
        }
    }
}
