use std::fmt;

use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

/// Newtype wrapper around an 8-byte array so we can implement [`fmt::Display`] and use the
/// type in error enums/messages.
#[derive(
    Debug,
    Copy,
    Clone,
    Eq,
    PartialEq,
    PartialOrd,
    Ord,
    IntoBytes,
    KnownLayout,
    Immutable,
    FromBytes,
    Unaligned,
)]
#[repr(C)]
pub struct Magic([u8; 8]);

impl Magic {
    /// DERP magic number, sent in the [`ServerKey`][crate::frame::ServerKey] frame upon
    /// initial connection. Byte representation of the string "DERP🔑".
    pub const MAGIC: Magic = Magic([0x44, 0x45, 0x52, 0x50, 0xF0, 0x9F, 0x94, 0x91]);

    /// Report whether this magic number matches the expected value.
    pub const fn is_valid(&self) -> bool {
        matches!(self, &Self::MAGIC)
    }
}

impl AsRef<[u8]> for Magic {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for Magic {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            f.write_fmt(format_args!("{b:02X}"))?;
        }
        Ok(())
    }
}
