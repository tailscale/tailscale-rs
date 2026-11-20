//! Types and utilities for configuring a Tailscale [`Device`](crate::Device).

use std::path::Path;

use ts_keys::PersistState;

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

    /// Whether this node should register itself as ephemeral.
    ///
    /// This means that the node will be deleted from the tailnet after it is offline for a brief
    /// period. It can be registered again with the same keys in the future but will have a
    /// different node id.
    ///
    /// See the [KB article on ephemeral nodes] for more information.
    ///
    /// [KB article on ephemeral nodes]: https://tailscale.com/docs/features/ephemeral-nodes
    pub ephemeral: bool,

    #[cfg(feature = "metrics")]
    pub export_metrics: bool,

    #[cfg(feature = "metrics")]
    pub logtail_id: ts_logtail::id::LogtailPrivateId,
}

impl Config {
    /// Create a new config with its [`key_state`](Config::key_state) populated from the specified key file and using
    /// default options for other configuration.
    ///
    /// If metrics are enabled (default behavior) then also loads logging system state from the specified logtail file.
    ///
    /// See [`load_key_file`] for more details and an alternative with more options for reading
    /// the key file.
    pub async fn default_with_state_files(key_file_path: impl AsRef<Path>, #[cfg(feature = "metrics")] logtail_file_path: impl AsRef<Path>) -> Result<Self, crate::Error> {
        Ok(Config {
            key_state: load_key_file(key_file_path, Default::default()).await?,
            #[cfg(feature = "metrics")]
            logtail_id: load_logtail_file(logtail_file_path, Default::default()).await?,
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

    #[cfg(feature = "metrics")]
    pub const FEATURES: &'static str = env!("TS_ENABLED_FEATURES");
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
    load_state_file::<KeyFile>(p, bad_format).await
}

#[cfg(feature = "metrics")]
pub async fn load_logtail_file(
    p: impl AsRef<Path>,
    bad_format: BadFormatBehavior,
) -> Result<ts_logtail::id::LogtailPrivateId, crate::Error> {
    load_state_file::<LogtailFile>(p, bad_format).await
}

async fn load_state_file<T: StateFile>(p: impl AsRef<Path>, bad_format: BadFormatBehavior) -> Result<T::State, crate::Error> {
    let p = p.as_ref();

    tracing::trace!(state_file = %p.display(), "loading state file");

    let state_file = load_or_init::<T>(&p, bad_format).await?;
    Ok(state_file.into_state())
}

trait StateFile: Default + serde::Serialize + serde::de::DeserializeOwned {
    type State;

    fn into_state(self) -> Self::State;
}

#[derive(serde::Deserialize, serde::Serialize, Default)]
struct KeyFile {
    key_state: PersistState,
}

impl StateFile for KeyFile {
    type State = PersistState;

    fn into_state(self) -> Self::State {
        self.key_state
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
#[cfg(feature = "metrics")]
struct LogtailFile {
    logtail_id: ts_logtail::id::LogtailPrivateId,
}

#[cfg(feature = "metrics")]
impl StateFile for LogtailFile {
    type State = ts_logtail::id::LogtailPrivateId;

    fn into_state(self) -> Self::State {
        self.logtail_id
    }
}

#[cfg(feature = "metrics")]
impl Default for LogtailFile {
    fn default() -> Self {
        let mut result = LogtailFile {
            logtail_id: ts_logtail::id::LogtailPrivateId::default(),
        };
        result
    }
}

impl From<&Config> for ts_control::Config {
    fn from(value: &Config) -> ts_control::Config {
        ts_control::Config {
            client_name: value.client_name.clone(),
            hostname: value.requested_hostname.clone(),
            server_url: value.control_server_url.clone(),
            tags: value.requested_tags.clone(),
            ephemeral: value.ephemeral,
        }
    }
}

impl From<PersistState> for Config {
    fn from(key_state: PersistState) -> Config {
        Config {
            key_state,
            ..Default::default()
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
            ephemeral: false,
            #[cfg(feature = "metrics")]
            export_metrics: true,
            #[cfg(feature = "metrics")]
            logtail_id: ts_logtail::id::LogtailPrivateId::default(),
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
async fn load_or_init<State: StateFile>(
    path: impl AsRef<Path>,
    bad_format_behavior: BadFormatBehavior,
) -> Result<State, crate::Error>
{
    let path = path.as_ref();

    tokio::fs::create_dir_all(path.parent().unwrap())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "creating parent dirs for key file");
            crate::Error::KeyFileWrite
        })?;

    match tokio::fs::read(path).await {
        Ok(contents) => match serde_json::from_slice::<State>(&contents) {
            Ok(state) => return Ok(state),
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

    let value = State::default();
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
