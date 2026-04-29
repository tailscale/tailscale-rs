use std::fmt;

use crate::netstack::Error as NetstackError;

/// Errors that may occur while interacting with a device.
#[derive(Debug, Clone, thiserror::Error)]
pub enum Error {
    /// Internal operation failed, likely a bug.
    #[error("internal error ({0})")]
    Internal(InternalErrorKind),

    /// An operation timed out.
    #[error("operation timed out")]
    Timeout,

    /// A connection was reset.
    #[error("connection reset")]
    ConnectionReset,

    /// An error reading or parsing the key file.
    #[error("an error reading or parsing the key file")]
    KeyFileRead,

    /// An error writing out the key file.
    #[error("an error writing out the key file")]
    KeyFileWrite,

    /// The environment variable `TS_RS_EXPERIMENT` was not set.
    #[error("the environment variable `{}` was not set", crate::ENV_MAGIC_VAR)]
    UnstableEnvVar,
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
    /// Bad request.
    BadRequest,
    /// Invalid buffer.
    BadBuffer,
    /// Actor missing or shutdown.
    Actor,
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
            InternalErrorKind::BadRequest => write!(f, "bad request"),
            InternalErrorKind::BadBuffer => write!(f, "invalid buffer"),
            InternalErrorKind::Actor => write!(f, "actor missing or shutdown"),
        }
    }
}

impl From<crate::netstack::InternalErrorKind> for InternalErrorKind {
    fn from(e: crate::netstack::InternalErrorKind) -> Self {
        match e {
            crate::netstack::InternalErrorKind::InvalidSocketState => {
                InternalErrorKind::InvalidSocketState
            }
            crate::netstack::InternalErrorKind::InternalResponseMismatch => {
                InternalErrorKind::InternalResponseMismatch
            }
            crate::netstack::InternalErrorKind::InternalChannelClosed => {
                InternalErrorKind::InternalChannelClosed
            }
            crate::netstack::InternalErrorKind::BadListenerHandle => {
                InternalErrorKind::BadListenerHandle
            }
            crate::netstack::InternalErrorKind::BadSocketHandle => {
                InternalErrorKind::BadSocketHandle
            }
        }
    }
}

impl From<ts_runtime::Error> for Error {
    fn from(value: ts_runtime::Error) -> Self {
        match value.kind {
            ts_runtime::ErrorKind::Timeout => Error::Timeout,
            ts_runtime::ErrorKind::ActorGone
            | ts_runtime::ErrorKind::MailboxFull
            | ts_runtime::ErrorKind::ReplyErr => Error::Internal(InternalErrorKind::Actor),
        }
    }
}

impl From<NetstackError> for Error {
    fn from(value: NetstackError) -> Self {
        match value {
            NetstackError::Internal(k) => Error::Internal(k.into()),
            NetstackError::ConnectionReset => Error::ConnectionReset,
            NetstackError::BadRequest(_) => Error::Internal(InternalErrorKind::BadRequest),
            NetstackError::BadBuffer => Error::Internal(InternalErrorKind::BadBuffer),
        }
    }
}
