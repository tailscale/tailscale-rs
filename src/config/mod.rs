use std::path::PathBuf;

use crate::statefile;

/// Config for connecting to Tailscale.
pub struct Config {
    /// The path of the file used to store cryptographic keys.
    ///
    /// This file represents this node's identity. State files are not interchangeable with
    /// those produce by the Go version of tailscale.
    pub statefile: PathBuf,

    /// An auth key issued by your control server, which will be used to register this node.
    ///
    /// You only need to provide the auth key if the node is not registered (i.e. it has not
    /// yet been registered or has expired).
    pub auth_key: Option<String>,

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
    /// Construct a [`ts_control::Config`] from this config.
    pub fn control_config(&self) -> ts_control::Config {
        ts_control::Config {
            client_name: None,
            hostname: self.requested_hostname.clone(),
            server_url: self.control_server_url.clone(),
        }
    }

    /// Load the state from a path on the filesystem, or create the statefile if it doesn't
    /// exist.
    pub async fn load_statefile(&self) -> Result<statefile::v0::State, statefile::Error> {
        tracing::trace!(statefile = %self.statefile.display(), "loading statefile");

        statefile::load_or_init(
            &self.statefile,
            Default::default,
            statefile::FormatVersion::V0,
            Default::default(),
        )
        .await
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            statefile: "tsrs_state.json".to_owned().into(),
            auth_key: None,
            control_server_url: ts_control::DEFAULT_CONTROL_SERVER.clone(),
            requested_hostname: None,
            requested_tags: vec![],
        }
    }
}
