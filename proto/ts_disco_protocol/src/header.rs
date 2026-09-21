use ts_keys::DiscoPublicKey;
use zerocopy::TryFromBytes;

use crate::Error;

/// A disco message header.
///
/// This is the outer message header that isn't part of the encrypted payload.
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    Hash,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::FromBytes,
    zerocopy::IntoBytes,
    zerocopy::Unaligned,
)]
#[repr(C, packed)]
pub struct Header {
    magic: [u8; Header::MAGIC.len()],
    pub(crate) sender_pub: DiscoPublicKey,
    pub(crate) nonce: [u8; Header::NONCE_LEN],
}

impl Header {
    /// Magic bytes indicating that this is a disco message.
    /// "TS" followed by UTF-8 speech bubble.
    pub const MAGIC: [u8; 6] = *b"TS\xf0\x9f\x92\xac";

    /// Length in bytes of the nonce field.
    pub const NONCE_LEN: usize = 24;

    /// Construct a new [`Header`] with the given pubkey and nonce.
    pub const fn new(sender_pub: DiscoPublicKey, nonce: [u8; 24]) -> Self {
        Self {
            magic: Self::MAGIC,
            sender_pub,
            nonce,
        }
    }

    /// Parse header from buffer, validating that message has the correct magic bytes.
    pub fn from_bytes(buf: &[u8]) -> Result<(&Self, &[u8]), Error> {
        let (slf, rest) = Self::try_ref_from_prefix(buf)?;
        slf.validate()?;

        Ok((slf, rest))
    }

    /// Report whether this is a valid disco header.
    ///
    /// This requires the magic bytes to match.
    pub const fn is_valid(&self) -> bool {
        matches!(self.magic, Self::MAGIC)
    }

    /// Validate that this header has the right magic number, and throw an error if not.
    pub const fn validate(&self) -> Result<(), Error> {
        if !self.is_valid() {
            return Err(Error::WrongMagic);
        }

        Ok(())
    }
}
