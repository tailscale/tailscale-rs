/// Errors that may be encountered during disco message processing.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, thiserror::Error)]
pub enum Error {
    /// Encryption or decryption failed.
    #[error("crypto operation failed")]
    CryptoFailed,

    /// Message had the wrong magic bytes.
    #[error("wrong magic bytes sequence")]
    WrongMagic,

    /// The version number of a decrypted message was incorrect.
    #[error("disco version other than 0")]
    UnknownVersion,

    /// The message was too short to decode.
    #[error("message was too short")]
    TooShort,

    /// Alignment issue while decoding.
    #[error("misaligned body while decoding")]
    Alignment,

    /// Validity issue while decoding.
    #[error("invalid value")]
    Validity,
}

impl<A, S, V> From<zerocopy::ConvertError<A, S, V>> for Error {
    fn from(value: zerocopy::ConvertError<A, S, V>) -> Self {
        match value {
            zerocopy::ConvertError::Size(..) => Error::TooShort,
            zerocopy::ConvertError::Alignment(..) => Error::Alignment,
            zerocopy::ConvertError::Validity(..) => Error::Validity,
        }
    }
}
