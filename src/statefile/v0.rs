//! V0 config file format.

use crate::statefile::FormatVersion;

/// A tailscale-rs statefile.
///
/// Not compatible with tailscale-go state files.
#[derive(Debug, Clone, serde::Deserialize, serde::Serialize)]
pub struct State {
    /// The version of this statefile.
    ///
    /// Defaults to v0 for existing state files that don't have this field.
    #[serde(default = "this_version")]
    pub version: FormatVersion,

    /// The cryptographic keys stored here.
    pub keys: ts_keys::NodeState,
}

fn this_version() -> FormatVersion {
    FormatVersion::V0
}

impl Default for State {
    fn default() -> State {
        Self {
            version: FormatVersion::V0,
            keys: ts_keys::NodeState::default(),
        }
    }
}
