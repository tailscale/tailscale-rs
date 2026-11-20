use reqwest::header::InvalidHeaderValue;
use std::fmt;
use std::fmt::{Display, Formatter};

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("{0}")]
    Internal(InternalErrorKind)
}

#[non_exhaustive]
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum InternalErrorKind {
    /// An error in URL parsing.
    Url,
    /// An unsuccessful HTTP request or upgrade.
    Http,
    /// An error in serialization or deserialization.
    SerDe,
    /// An error in I/O.
    Io,
}

impl Display for InternalErrorKind {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            InternalErrorKind::Url => write!(f, "URL parsing error"),
            InternalErrorKind::Http => write!(f, "unsuccessful HTTP request or upgrade"),
            InternalErrorKind::SerDe => write!(f, "serialization/deserialization error"),
            InternalErrorKind::Io => write!(f, "I/O error"),
        }
    }
}

impl From<serde_json::Error> for Error {
    fn from(error: serde_json::Error) -> Self {
        tracing::error!(%error, "json error");
        Error::Internal(InternalErrorKind::SerDe)
    }
}

impl From<reqwest_middleware::Error> for Error {
    fn from(error: reqwest_middleware::Error) -> Self {
        tracing::error!(%error, "http error");
        Error::Internal(InternalErrorKind::Http)
    }
}

impl From<InvalidHeaderValue> for Error {
    fn from(error: InvalidHeaderValue) -> Self {
        tracing::error!(%error, "invalid header value");
        Error::Internal(InternalErrorKind::SerDe)
    }
}