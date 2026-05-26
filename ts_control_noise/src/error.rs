use zerocopy::{SizeError, TryCastError};

/// Error encountered with Noise communication.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid message format.
    #[error("invalid message format")]
    BadFormat,

    /// Handshake failed.
    #[error("handshake failed to complete")]
    HandshakeFailed,

    /// Underlying I/O failure.
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl<M> From<TryCastError<&[u8], M>> for Error
where
    M: ?Sized + zerocopy::TryFromBytes,
{
    #[inline]
    fn from(_value: TryCastError<&[u8], M>) -> Self {
        Error::BadFormat
    }
}

impl<M> From<TryCastError<&mut [u8], M>> for Error
where
    M: ?Sized + zerocopy::TryFromBytes,
{
    #[inline]
    fn from(_value: TryCastError<&mut [u8], M>) -> Self {
        Error::BadFormat
    }
}

impl<M> From<SizeError<&M, &mut [u8]>> for Error
where
    M: zerocopy::TryFromBytes,
{
    #[inline]
    fn from(_value: SizeError<&M, &mut [u8]>) -> Self {
        Error::BadFormat
    }
}

impl From<core::str::Utf8Error> for Error {
    #[inline]
    fn from(_value: core::str::Utf8Error) -> Self {
        Error::BadFormat
    }
}

impl From<Error> for std::io::Error {
    #[inline]
    fn from(value: Error) -> Self {
        std::io::Error::other(value.to_string())
    }
}
