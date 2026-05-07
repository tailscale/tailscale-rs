use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Unaligned};

use crate::{
    Nonce,
    frame::{Body, FrameType},
};

/// Part of the initial derp handshake, providing info about the server.
///
/// The payload follows as an encrypted JSON blob in the format specified by
/// [`ServerInfoPayload`].
#[derive(
    Debug, Copy, Clone, PartialEq, KnownLayout, Immutable, IntoBytes, FromBytes, Unaligned,
)]
#[repr(C, packed)]
pub struct ServerInfo {
    /// Nonce to use for decrypting the additional payload.
    pub nonce: Nonce,
}

impl Body for ServerInfo {
    const FRAME_TYPE: FrameType = FrameType::ServerInfo;
}

/// Associated payload to [`ServerInfo`], containing runtime info for the server.
#[derive(Debug, Copy, Clone, Default, serde::Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ServerInfoPayload {
    /// Version of the server.
    pub version: i32,
    /// Sustained refill rate of the server's token bucket.
    pub token_bucket_bytes_per_second: Option<i32>,
    /// The burst rate for the server's token bucket.
    pub token_bucket_bytes_burst: Option<i32>,
}

impl ServerInfoPayload {
    /// Get the server's sustained token bucket refill rate as a usize.
    pub fn token_bucket_bytes_per_second(&self) -> Option<usize> {
        self.token_bucket_bytes_per_second.map(|v| v as usize)
    }

    /// Get the server's token bucket burst rate as a usize.
    pub fn token_bucket_bytes_burst(&self) -> Option<usize> {
        self.token_bucket_bytes_burst.map(|v| v as usize)
    }

    /// Get the server's version as a usize.
    pub fn version(&self) -> usize {
        self.version as usize
    }
}
