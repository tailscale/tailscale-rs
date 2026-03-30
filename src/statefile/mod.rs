//! Filesystem state storage.
//!
//! Currently primarily concerned with storing cryptographic keys.

use std::path::Path;

mod error;
pub mod v0;

pub use error::Error;

/// What to do if the state file can't be parsed.
///
/// Default behavior: return an error.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum BadFormatBehavior {
    /// Return an error.
    #[default]
    Error,
    /// Overwrite with the default value.
    OverwriteDefault,
}

/// Attempt to load state from a path. If it doesn't exist, create it with the
/// specified default value.
pub async fn load_or_init<State>(
    path: impl AsRef<Path>,
    default: impl FnOnce() -> State,
    expected_version: FormatVersion,
    bad_format_behavior: BadFormatBehavior,
) -> Result<State, Error>
where
    State: serde::Serialize + serde::de::DeserializeOwned,
{
    let path = path.as_ref();

    tokio::fs::create_dir_all(path.parent().unwrap()).await?;

    match tokio::fs::read(path).await {
        Ok(contents) => match serde_json::from_slice::<LoadVersion>(&contents) {
            Ok(version) => {
                if version.version == expected_version {
                    return Ok(serde_json::from_slice::<State>(&contents)
                        .inspect_err(|e| tracing::error!(error = %e, "parsing statefile"))?);
                } else if !version.version.is_known() {
                    return Err(Error::Future);
                } else {
                    tracing::warn!(
                        loaded_version = ?version.version,
                        ?expected_version,
                        "statefile version mismatch, overwriting",
                    );
                }
            }
            Err(e) => match bad_format_behavior {
                BadFormatBehavior::Error => {
                    tracing::error!(error = %e, "parsing statefile");
                    return Err(Error::DataFormat);
                }
                BadFormatBehavior::OverwriteDefault => {
                    tracing::warn!(
                        error = %e,
                        config_file_contents_len = contents.len(),
                        "failed loading version from statefile, overwriting",
                    );
                }
            },
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::error!(error = %e, path = %path.display(), "reading statefile");
            return Err(e.into());
        }
    }

    let value = default();
    tokio::fs::write(path, serde_json::to_vec(&value)?).await?;

    Ok(value)
}

/// Helper struct that enables loading just the format version from a serialized statefile.
#[derive(Debug, Copy, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct LoadVersion {
    /// The version of this state format.
    ///
    /// Defaults to v0 if not present for compat with existing state files that don't have
    /// this field.
    #[serde(default = "v0")]
    pub version: FormatVersion,
}

fn v0() -> FormatVersion {
    FormatVersion::V0
}

/// Version of the statefile format.
///
/// Gets incremented whenever a change is made to the format. The sequence of version
/// numbers is monotonic.
#[derive(
    Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Deserialize, serde::Serialize,
)]
pub struct FormatVersion(u32);

impl FormatVersion {
    /// Initial version of the statefile holding just a key state.
    pub const V0: Self = Self(0);

    /// The latest version of the statefile.
    ///
    /// Always updated when a new version is added.
    pub const LATEST: Self = Self::V0;

    /// Report whether this format version is known (<= [`FormatVersion::LATEST`]).
    pub const fn is_known(&self) -> bool {
        #[allow(clippy::absurd_extreme_comparisons)]
        {
            self.0 <= Self::LATEST.0
        }
    }

    /// Report whether this format version is the current one.
    pub const fn is_current(&self) -> bool {
        self.0 == Self::LATEST.0
    }
}

impl From<FormatVersion> for u32 {
    fn from(value: FormatVersion) -> Self {
        value.0
    }
}
