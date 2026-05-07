/// Errors encountered during derp client operation.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Error failed to parse.
    #[error(transparent)]
    BadUrl(#[from] url::ParseError),

    /// Deserializing JSON failed.
    #[error(transparent)]
    Deserialize(#[from] serde_json::Error),

    /// There was an error parsing the derp frame.
    #[error(transparent)]
    Frame(#[from] crate::frame::Error),

    /// An underlying IO error was encountered.
    #[error(transparent)]
    IoFailure(#[from] std::io::Error),

    /// Unsupported derp protocol version.
    #[error("unsupported DERP protocol version {0}, only supported version is {1}")]
    UnsupportedProtocolVersion(usize, usize),

    /// Received an unknown frame type.
    #[error("received unexpected DERP frame type '{0}'")]
    UnexpectedRecvFrameType(crate::frame::FrameType),

    /// Error in HTTP connection.
    #[error("http error")]
    Http,
}

impl From<ts_http_util::Error> for Error {
    fn from(_: ts_http_util::Error) -> Self {
        Error::Http
    }
}
