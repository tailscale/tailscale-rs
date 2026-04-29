//! Types and utilities for configuring a Tailscale [`Device`](crate::Device).

use std::path::Path;

use serde::Serializer;
use ts_keys::PersistState;

use crate::keys::NodeState;

const CONTROL_URL_VAR: &str = "TS_CONTROL_URL";
const HOSTNAME_VAR: &str = "TS_HOSTNAME";
const AUTHKEY_VAR: &str = "TS_AUTH_KEY";

/// Config for connecting to Tailscale.
pub struct Config {
    /// The cryptographic keys representing this node's identity.
    pub key_state: PersistState,

    // TODO(npry): let clients also define an app name once the sdk-level name moves
    //  to a dedicated field
    /// The name of this client.
    ///
    /// This is reported to control in the `Hostinfo.App` field.
    pub client_name: Option<String>,

    /// The URL of the control server to connect to.
    pub control_server_url: url::Url,

    /// The hostname this node will request.
    ///
    /// If left blank, uses the hostname reported by the OS.
    pub requested_hostname: Option<String>,

    /// Tags this node will request.
    pub requested_tags: Vec<String>,
}

impl Config {
    /// Create a new config with its [`key_state`](Config::key_state) populated from the specified key file and using
    /// default options for other configuration.
    ///
    /// See [`load_key_file`] for more details and an alternative with more options for reading
    /// the key file.
    pub async fn default_with_key_file(p: impl AsRef<Path>) -> Result<Self, crate::Error> {
        Ok(Config {
            key_state: load_key_file(p, Default::default()).await?,
            ..Default::default()
        })
    }

    /// Construct a default config, setting certain fields from environment variables.
    ///
    /// The fields are only set if the corresponding environment variable is present, using
    /// the default value otherwise.
    ///
    /// Loads:
    ///
    /// - `control_server_url` from `TS_CONTROL_URL`
    /// - `requested_hostname` from `TS_HOSTNAME`
    pub fn default_from_env() -> Config {
        let mut config = Config::default();

        if let Ok(u) = std::env::var(CONTROL_URL_VAR) {
            match u.parse() {
                Ok(u) => config.control_server_url = u,
                Err(e) => {
                    tracing::error!(error = %e, "parsing {CONTROL_URL_VAR} (fall back to default value)");
                }
            }
        };

        config.requested_hostname = std::env::var(HOSTNAME_VAR).ok();

        config
    }
}

/// Load an auth key from the `TS_AUTH_KEY` environment variable.
pub fn auth_key_from_env() -> Option<String> {
    std::env::var(AUTHKEY_VAR).ok()
}

/// Load key state from a path on the filesystem, or create a file with a new key state if
/// one doesn't exist.
///
/// The `bad_format` argument allows you to specify whether an existing file should be
/// overwritten if the contents can't be parsed.
pub async fn load_key_file(
    p: impl AsRef<Path>,
    bad_format: BadFormatBehavior,
) -> Result<PersistState, crate::Error> {
    let p = p.as_ref();

    tracing::trace!(key_file = %p.display(), "loading key file");

    let key_file = load_or_init::<KeyFile>(
        &p,
        Default::default,
        |x| match x {
            #[allow(deprecated)]
            KeyFile::Old(old) => Some(KeyFile::New(KeyFileNew {
                key_state: PersistState::from(&old.key_state),
            })),
            _ => None,
        },
        bad_format,
    )
    .await?;
    Ok(key_file.key_state())
}

#[derive(serde::Deserialize)]
#[serde(untagged)]
enum KeyFile {
    #[deprecated]
    Old(KeyFileOld),
    New(KeyFileNew),
}

impl KeyFile {
    #[allow(deprecated)]
    pub fn key_state(&self) -> PersistState {
        match self {
            Self::Old(old) => (&old.key_state).into(),
            Self::New(new) => new.key_state.clone(),
        }
    }
}

impl Default for KeyFile {
    fn default() -> Self {
        KeyFile::New(KeyFileNew::default())
    }
}

impl serde::Serialize for KeyFile {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        KeyFileNew {
            key_state: self.key_state(),
        }
        .serialize(serializer)
    }
}

#[derive(serde::Deserialize, serde::Serialize, Default)]
struct KeyFileNew {
    key_state: PersistState,
}

#[derive(serde::Deserialize)]
struct KeyFileOld {
    key_state: NodeState,
}

impl From<&Config> for ts_control::Config {
    fn from(value: &Config) -> ts_control::Config {
        ts_control::Config {
            client_name: value.client_name.clone(),
            hostname: value.requested_hostname.clone(),
            server_url: value.control_server_url.clone(),
            tags: value.requested_tags.clone(),
        }
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            key_state: Default::default(),
            client_name: None,
            control_server_url: ts_control::DEFAULT_CONTROL_SERVER.clone(),
            requested_hostname: None,
            requested_tags: vec![],
        }
    }
}

/// What to do if the key file can't be parsed.
///
/// Default behavior: return an error.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Default)]
pub enum BadFormatBehavior {
    /// Return an error.
    #[default]
    Error,

    /// Overwrite the file with a newly-generated set of keys.
    Overwrite,
}

/// Attempt to load a file from a path. If it doesn't exist, create it with the
/// specified default value.
#[tracing::instrument(skip_all, fields(?bad_format_behavior, path = %path.as_ref().display()))]
async fn load_or_init<KeyState>(
    path: impl AsRef<Path>,
    default: impl FnOnce() -> KeyState,
    migrate: impl FnOnce(&KeyState) -> Option<KeyState>,
    bad_format_behavior: BadFormatBehavior,
) -> Result<KeyState, crate::Error>
where
    KeyState: serde::Serialize + serde::de::DeserializeOwned,
{
    let path = path.as_ref();

    tokio::fs::create_dir_all(path.parent().unwrap())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "creating parent dirs for key file");
            crate::Error::KeyFileWrite
        })?;

    match tokio::fs::read(path).await {
        Ok(contents) => match serde_json::from_slice::<KeyState>(&contents) {
            Ok(state) => {
                if let Some(migrated) = migrate(&state) {
                    match try_write(path, &migrated).await {
                        Ok(_) => {
                            tracing::info!("migrated key file to new disco-less format");
                            return Ok(migrated);
                        }
                        Err(e) => {
                            tracing::error!(error = %e, "unable to migrate key file");
                        }
                    }
                }

                return Ok(state);
            }
            Err(e) => match bad_format_behavior {
                BadFormatBehavior::Error => {
                    tracing::error!(error = %e, "parsing key file");
                    return Err(crate::Error::KeyFileRead);
                }
                BadFormatBehavior::Overwrite => {
                    tracing::warn!(
                        error = %e,
                        config_file_contents_len = contents.len(),
                        "failed loading version from key file, overwriting",
                    );
                }
            },
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => {
            tracing::error!(error = %e, path = %path.display(), "reading key file");
            return Err(crate::Error::KeyFileRead);
        }
    }

    let value = default();
    try_write(path, &value).await?;
    Ok(value)
}

async fn try_write(
    path: impl AsRef<Path>,
    value: &impl serde::Serialize,
) -> Result<(), crate::Error> {
    tokio::fs::write(
        path,
        serde_json::to_vec(value).map_err(|e| {
            tracing::error!(error = %e, "serializing key state");
            crate::Error::KeyFileWrite
        })?,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "saving key state");
        crate::Error::KeyFileWrite
    })?;

    Ok(())
}
