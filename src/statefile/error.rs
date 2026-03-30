/// Errors encountered loading / saving state files.
#[derive(Debug, Copy, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// Tried to load a state from the future and couldn't migrate to it.
    #[error("state is from the future")]
    Future,

    /// I/O error encountered while saving or loading state.
    #[error("i/o error encountered while loading or saving")]
    Io,

    /// Invalid data format.
    #[error("invalid data format")]
    DataFormat,
}

impl From<tokio::io::Error> for Error {
    fn from(_: tokio::io::Error) -> Self {
        Self::Io
    }
}

impl From<serde_json::Error> for Error {
    fn from(_: serde_json::Error) -> Self {
        Self::DataFormat
    }
}
