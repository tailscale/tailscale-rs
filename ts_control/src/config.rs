use core::fmt::Debug;

use url::Url;

lazy_static::lazy_static! {
    /// The default [`Url`] of the control plane server (aka "coordination server").
    pub static ref DEFAULT_CONTROL_SERVER: Url = Url::parse("https://controlplane.tailscale.com/").unwrap();
}

/// Configuration for the control server.
#[derive(Clone, serde::Serialize, serde::Deserialize)]
pub struct Config {
    /// The URL of the control server to connect to.
    pub server_url: Url,

    /// The hostname of the current node.
    pub hostname: Option<String>,

    /// A name for this type of client.
    ///
    /// This will be reported to the control server in the `HostInfo.App` field.
    pub client_name: Option<String>,
}

impl Config {
    /// Get the full client name as a string.
    ///
    /// This takes the form `tailscale-rs ({client_name})`, where the parenthetical is only
    /// provided if self.client_name is set.
    pub fn format_client_name(&self) -> String {
        let mut full_name = "tailscale-rs".to_owned();
        if let Some(client_name) = &self.client_name {
            full_name.push_str(&format!(" ({client_name})"));
        }

        full_name
    }
}

impl Debug for Config {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Config")
            .field("hostname", &self.hostname)
            .field("server_url", &self.server_url.as_str())
            .field("client_name", &self.client_name)
            .finish()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            server_url: DEFAULT_CONTROL_SERVER.clone(),
            hostname: gethostname::gethostname().into_string().ok(),
            client_name: None,
        }
    }
}
