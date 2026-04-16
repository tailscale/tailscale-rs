use netstack::netcore;

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

    /// A configuration environment variable held an unparseable or non-UTF-8 value.
    ///
    /// The wrapped `&'static str` names the offending variable (e.g. `"TS_CONTROL_URL"`).
    /// The underlying parse error is logged at the call site via `tracing::error!`.
    #[error("invalid value for config env var {0}")]
    InvalidConfigEnv(&'static str),
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

impl From<netcore::Error> for Error {
    fn from(value: netcore::Error) -> Self {
        match value {
            netcore::Error::ChannelClosed => Error::RuntimeDegraded,

            netcore::Error::WrongType
            | netcore::Error::BadRequest
            | netcore::Error::InvariantViolated => Error::InternalFailure,

            netcore::Error::TcpStream(netcore::tcp::stream::Error::Reset) => Error::ConnectionReset,
        }
    }
}
