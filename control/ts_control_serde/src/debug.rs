use core::time::Duration;

use serde::Deserialize;

/// Deprecated. A miscellaneous set of declarative debug config changes and imperative debug
/// commands sent from the control server to a Tailscale node. They've since been mostly
/// migrated to node attributes in [`Node::capabilities`][crate::Node::capabilities] for
/// the declarative things and control-to-node (c2n) requests for the imperative things.
/// Not much remains here; don't add more.
#[serde_with::serde_as]
#[derive(Default, Debug, Clone, Deserialize)]
#[serde(rename_all = "PascalCase", default)]
pub struct Debug {
    /// Requests that this Tailscale node sleep for the provided number of seconds.
    ///
    /// The node can (and should) limit the maximum time, such as 5 minutes. This exists as a
    /// safety measure to slow down spinning Tailscale nodes, in case we introduce a bug in the
    /// state machine.
    #[serde_as(as = "serde_with::DurationSeconds<f64>")]
    pub sleep_seconds: Duration,

    /// Disables the `logtail` package in the Go client; ignored by the Rust client. Primarily
    /// used by Headscale.
    pub disable_log_tail: bool,

    /// If populated, indicates that this Tailscale node's process should exit with the given
    /// return code. This is a safety measure in case a node is crash-looping or in an unsafe
    /// state and we need to remotely shut it down.
    pub exit: Option<i64>,
}
