use serde::Deserialize;
use url::Url;

/// Information about the latest Tailscale version that's available for this node's platform and
/// packaging type, including whether this node is already running it.
///
/// This type does not include a URL to download the latest version, as that varies by platform.
#[derive(Default, Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct ClientVersion<'a> {
    /// If `true`, this Tailscale node is running the latest available version for this platform
    /// and package type.
    pub running_latest: bool,
    /// If populated, contains the latest semantic version available for download for this
    /// Tailscale node's platform and package type. This will be `None` only if
    /// [`ClientVersion::running_latest`] is `true`.
    #[serde(borrow)]
    pub latest_version: &'a str,
    /// Indicates this Tailscale node is missing an important security update. The update may be in
    /// [`ClientVersion::latest_version`] or any earlier version.
    ///
    /// This field should always be `false` if [`ClientVersion::running_latest`] is `true`.
    pub urgent_security_update: bool,
    /// Whether this Tailscale node should raise an OS-specific notification about a new version
    /// being available. The node must only raise a notification once for any given version,
    /// regardless of how many times it receives a [`ClientVersion`] with this field set to `true`
    /// for the same version. In other words, it's the node's job to track if it's already raised a
    /// notification for a specific version.
    ///
    /// This field should always be `false` if [`ClientVersion::running_latest`] is `true`.
    pub notify: bool,
    /// A [`Url`] to open in the platform's web browser when the user clicks on the notification.
    /// Only populated when [`ClientVersion::notify`] is `true`.
    pub notify_url: Option<Url>,
    /// The text to show in the notification. Only populated when [`ClientVersion::notify`] is
    /// `true`.
    #[serde(borrow)]
    pub notify_text: Option<&'a str>,
}
