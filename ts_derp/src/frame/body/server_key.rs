use ts_keys::DerpServerPublicKey;
use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    frame,
    frame::{Body, FrameType},
};

/// Sent from the server to the client as part of the initial handshake to provide the derp
/// server's public key.
#[derive(
    Debug, Copy, Clone, PartialEq, KnownLayout, Immutable, IntoBytes, FromBytes, Unaligned,
)]
#[repr(C, packed)]
pub struct ServerKey {
    /// Magic byte sequence to validate that this is a DERP server behaving as expected.
    ///
    /// Users should call [`ServerKey::validate`] to check that these magic bytes are valid.
    pub magic: frame::Magic,

    /// The server's public key.
    pub key: DerpServerPublicKey,
}

impl ServerKey {
    /// Ensure the magic number for this serverkey is valid.
    pub fn validate(&self) -> Result<(), frame::Error> {
        if !self.magic.is_valid() {
            return Err(frame::Error::InvalidMagic);
        }

        Ok(())
    }
}

impl Body for ServerKey {
    const FRAME_TYPE: FrameType = FrameType::ServerKey;
}
