use std::path::Path;

use url::Url;

/// Environment variable consulted for [`Config::control_server_url`] when that
/// field is `None`.
pub const ENV_CONTROL_URL: &str = "TS_CONTROL_URL";
/// Environment variable consulted for [`Config::requested_hostname`] when that
/// field is `None`.
pub const ENV_HOSTNAME: &str = "TS_HOSTNAME";
/// Environment variable consulted for [`Config::client_name`] when that field
/// is `None`.
pub const ENV_CLIENT_NAME: &str = "TS_CLIENT_NAME";
/// Environment variable consulted for the auth key passed to
/// [`crate::Device::new`] when the `auth_key` parameter is `None`.
pub const ENV_AUTH_KEY: &str = "TS_AUTH_KEY";

/// Config for connecting to Tailscale.
#[derive(Default)]
pub struct Config {
    /// The path of the file used to store cryptographic keys.
    ///
    /// This file represents this node's identity. The key file format is specific to
    /// tailscale-rs; key files are not interchangeable with those produced by other
    /// implementations of Tailscale, e.g. `tailscaled` or `tsnet`.
    pub key_state: crate::NodeState,

    // TODO(npry): let clients also define an app name once the sdk-level name moves
    //  to a dedicated field
    /// The name of this client.
    ///
    /// This is reported to control in the `Hostinfo.App` field.
    pub client_name: Option<String>,

    /// The URL of the control server to connect to.
    ///
    /// When `None`, [`crate::Device::new`] reads [`ENV_CONTROL_URL`] from the
    /// environment. If that is also unset, the built-in Tailscale default
    /// ([`ts_control::DEFAULT_CONTROL_SERVER`]) is used.
    pub control_server_url: Option<Url>,

    /// The hostname this node will request.
    ///
    /// If `None`, [`crate::Device::new`] reads [`ENV_HOSTNAME`] from the
    /// environment. If that is also unset, the hostname reported by the OS is
    /// used.
    pub requested_hostname: Option<String>,

    /// Tags this node will request.
    pub requested_tags: Vec<String>,
}

/// Load key state from a path on the filesystem, or create a file with a new key state if
/// one doesn't exist.
///
/// The `bad_format` argument allows you to specify whether an existing file should be
/// overwritten if the contents can't be parsed.
pub async fn load_key_file(
    p: impl AsRef<Path>,
    bad_format: BadFormatBehavior,
) -> Result<crate::NodeState, crate::Error> {
    let p = p.as_ref();

    tracing::trace!(key_file = %p.display(), "loading key file");

    let key_file = load_or_init::<KeyFile>(&p, Default::default, bad_format).await?;
    Ok(key_file.key_state)
}

#[derive(serde::Serialize, serde::Deserialize, Default)]
struct KeyFile {
    key_state: crate::NodeState,
}

impl From<&Config> for ts_control::Config {
    fn from(value: &Config) -> ts_control::Config {
        ts_control::Config {
            client_name: value.client_name.clone(),
            hostname: value.requested_hostname.clone(),
            server_url: value
                .control_server_url
                .clone()
                .unwrap_or_else(|| ts_control::DEFAULT_CONTROL_SERVER.clone()),
        }
    }
}

/// Resolve the control server URL.
///
/// Precedence: `configured.is_some()` > [`ENV_CONTROL_URL`] >
/// [`ts_control::DEFAULT_CONTROL_SERVER`]. A malformed env value returns
/// [`crate::Error::InvalidConfigEnv`].
pub(crate) fn resolve_control_url(
    configured: &Option<Url>,
    get: impl Fn(&str) -> Option<String>,
) -> Result<Url, crate::Error> {
    if let Some(url) = configured {
        return Ok(url.clone());
    }
    let Some(raw) = get(ENV_CONTROL_URL) else {
        return Ok(ts_control::DEFAULT_CONTROL_SERVER.clone());
    };
    Url::parse(&raw).map_err(|e| {
        tracing::error!(
            error = %e,
            var = ENV_CONTROL_URL,
            "parsing control server URL from environment",
        );
        crate::Error::InvalidConfigEnv(ENV_CONTROL_URL)
    })
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
            crate::Error::InternalFailure
        })?;

    match tokio::fs::read(path).await {
        Ok(contents) => match serde_json::from_slice::<KeyState>(&contents) {
            Ok(state) => {
                return Ok(state);
            }
            Err(e) => match bad_format_behavior {
                BadFormatBehavior::Error => {
                    tracing::error!(error = %e, "parsing key file");
                    return Err(crate::Error::InternalFailure);
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
            return Err(crate::Error::InternalFailure);
        }
    }

    let value = default();
    tokio::fs::write(
        path,
        serde_json::to_vec(&value).map_err(|e| {
            tracing::error!(error = %e, "serializing key state");
            crate::Error::InternalFailure
        })?,
    )
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "saving key state");
        crate::Error::InternalFailure
    })?;

    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn one(var: &'static str, value: &'static str) -> impl Fn(&str) -> Option<String> {
        move |name| (name == var).then(|| value.to_owned())
    }

    #[test]
    fn control_url_default_when_nothing_set() {
        let url = resolve_control_url(&None, |_| None).unwrap();
        assert_eq!(url, *ts_control::DEFAULT_CONTROL_SERVER);
    }

    #[test]
    fn control_url_env_wins_when_config_is_none() {
        let url =
            resolve_control_url(&None, one(ENV_CONTROL_URL, "https://env.example.com/")).unwrap();
        assert_eq!(url.as_str(), "https://env.example.com/");
    }

    #[test]
    fn control_url_explicit_wins_over_env() {
        let explicit: Url = "https://explicit.example.com/".parse().unwrap();
        let url = resolve_control_url(
            &Some(explicit.clone()),
            one(ENV_CONTROL_URL, "https://env.example.com/"),
        )
        .unwrap();
        assert_eq!(url, explicit);
    }

    #[test]
    fn control_url_malformed_env_returns_typed_error() {
        let result = resolve_control_url(&None, one(ENV_CONTROL_URL, "not a url"));
        assert!(
            matches!(result, Err(crate::Error::InvalidConfigEnv(ENV_CONTROL_URL))),
            "expected InvalidConfigEnv(TS_CONTROL_URL)",
        );
    }
}
