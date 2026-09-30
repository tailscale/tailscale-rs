use alloc::vec::Vec;

use serde::{Deserialize, Serialize};

use crate::{
    env_type::EnvType, location::Location, net_info::NetInfo, service::Service, tpm::TpmInfo,
};

/// A summary of a Tailscale host that a Tailscale node is running on. Includes information about
/// the version of Tailscale running on the host, the operating system, running services, and
/// various diagnostic/logging and configuration values.
#[serde_with::apply(
    bool => #[serde(skip_serializing_if = "crate::util::is_default")],
    &str => #[serde(borrow)] #[serde(skip_serializing_if = "str::is_empty")],
    Option => #[serde(skip_serializing_if = "Option::is_none")],
     _ => #[serde(default)],
)]
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct HostInfo<'a> {
    /// Version of the Tailscale code running on this Tailscale node, in long format.
    pub ipn_version: &'a str,
    /// Logtail ID of the Tailscale frontend (CLI) instance.
    pub frontend_log_id: &'a str,
    /// Logtail ID of the Tailscale frontend (daemon) instance.
    pub backend_log_id: &'a str,
    /// A string indicating the operating system running on the Tailscale host.
    pub os: &'a str,
    /// The version of the operating system, if available. The format is highly OS, version, and
    /// Tailscale version-specific.
    ///
    /// # Examples
    /// - Android: "10", "11", "12"
    /// - FreeBSD: "12.3-STABLE"
    /// - iOS/macOS: "15.6.1", "12.4.0"
    /// - Linux (before Tailscale 1.32): "Debian 10.4; kernel=5.10.0-17-amd64; container; env=kn"
    /// - Linux (Tailscale 1.32+): "5.10.0-17-amd64" (kernel version only)
    /// - Windows: "10.0.19044.1889"
    pub os_version: &'a str,

    /// Indicates whether this Tailscale node is running inside a container. Detection is best-
    /// effort only, and may not be accurate.
    pub container: Option<bool>,
    /// Represents the type of runtime environment that this Tailscale node is running in.
    #[serde(skip_serializing_if = "crate::util::is_default")]
    pub env: EnvType,
    /// The name of the Linux distribution this Tailscale node is installed on (e.g. "debian",
    /// "ubuntu", "nixos", etc).
    pub distro: &'a str,
    /// The version string of the Linux distribution this Tailscale node is installed on. For
    /// example, this field may be "20.04" or "24.04.3" on on Ubuntu installs.
    pub distro_version: &'a str,
    /// The code name of the Linux distribution this Tailscale node is installed on. For example,
    /// this field may be "jammy" or "bullseye" on Debian Linux installs.
    pub distro_code_name: &'a str,

    /// Disambiguates Tailscale nodes that run using `tsnet` (e.g. "k8s-operator", "golinks", etc).
    pub app: &'a str,
    /// Indicates whether a desktop environment was detected. Used only for Linux devices.
    pub desktop: Option<bool>,
    /// How this Tailscale node was packaged/delivered to the device (e.g. "choco", "appstore",
    /// etc.) Empty string if the packaging mechanism is unknown.
    pub package: &'a str,
    /// Model of mobile phone for mobile devices (e.g. "Pixel 3a", "iPhone12,3").
    pub device_model: &'a str,
    /// Device token for sending push notifications to devices. Currently used for Apple Push
    /// Notifications (APNs) on iOS/macOS; will be used for Android in the future.
    pub push_device_token: &'a str,
    /// Hostname of this Tailscale node's host.
    pub hostname: Option<&'a str>,

    /// Indicates whether this Tailscale node's host is blocking incoming connections.
    pub shields_up: bool,
    /// Indicates this Tailscale node exists in the netmap because it's owned by a shared-to user.
    pub sharee_node: bool,
    /// Indicates the user has opted out of sending logs and receiving support from Tailscale.
    pub no_logs_no_support: bool,
    /// Indicates this Tailscale node would like to be wired up server-side (DNS, etc) to be
    /// able to use Tailscale Funnel, even if it's not currently enabled.
    ///
    /// For example, the user might only use it for intermittent foreground CLI serve sessions, for
    /// which they'd like it to work right away, even if it's disabled most of the time. As an
    /// optimization, this is only sent if [`HostInfo::ingress_enabled`] is `false`, as
    /// [`HostInfo::ingress_enabled`] implies that this option is `true`.
    pub wire_ingress: bool,
    /// Indicates whether this Tailscale node has any Tailscale Funnel endpoints enabled.
    pub ingress_enabled: bool,
    /// Indicates that this Tailscale node has opted-in to remote updates triggered by the admin
    /// console.
    pub allows_update: bool,

    /// The machine type (architecture) of this Tailscale node's host. Equivalent to the output of
    /// `uname --machine` on Linux.
    pub machine: &'a str,
    /// The `GOARCH` value of this Tailscale node's binary.
    pub go_arch: &'a str,
    /// The `GOARM`/`GOAMD64`/etc value of this Tailscale node's binary.
    pub go_arch_var: &'a str,
    /// The Go version this Tailscale node's binary was built with.
    pub go_version: &'a str,

    /// The set of IP ranges this Tailscale node can route.
    pub routable_ips: Option<Vec<ipnet::IpNet>>,
    /// The set of ACL tags this Tailscale node wants to claim.
    pub request_tags: Option<Vec<&'a str>>,
    /// MAC address(es) to send Wake-on-LAN packets to wake this node. Each address is formatted as
    /// a lowercase hexadecimal string, with each byte of the address separated by colons.
    pub wol_macs: Option<Vec<&'a str>>,
    /// Services running on the Tailscale node's host to advertise to the Tailnet.
    pub services: Option<Vec<Service<'a>>>,

    /// Information about the host's network state and configuration, if available. Includes
    /// DERP home region and latencies to DERP regions, availability/status of various layer 3 and
    /// 4 protocols, types of NAT hole-punching available on the LAN, etc.
    pub net_info: Option<NetInfo<'a>>,

    /// The Tailscale node's SSH host public keys, if advertised.
    pub ssh_host_keys: Option<Vec<&'a str>>,

    /// If populated, the name of the cloud provider this Tailscale node is running in, such as
    /// "Amazon EC2", "DigitalOcean", etc. An empty string means the node isn't running in a cloud,
    /// or isn't able to determine if it's running in a cloud.
    pub cloud: &'a str,

    /// Indicates whether the Tailscale node is running in userspace (netstack) mode.
    pub userspace: Option<bool>,
    /// Indicates whether the Tailscale node's subnet router is running in userspace (netstack)
    /// mode.
    pub userspace_router: Option<bool>,

    /// Indicates whether the Tailscale node is running the app-connector service.
    pub app_connector: Option<bool>,
    /// Opaque hash of the most recent list of Tailnet services. A change in the hash value
    /// indicates the control server should fetch the new list of services from the Tailscale node
    /// via c2n (control-to-node).
    pub services_hash: &'a str,

    /// The Tailscale node's selected exit node. Empty when unselected.
    pub exit_node_id: &'a str,
    /// Geographical location data about a Tailscale host. Location is optional and only set if
    /// explicitly declared by a node.
    pub location: Option<Location<'a>>,

    /// TPM device metadata, if available.
    pub tpm: Option<TpmInfo<'a>>,
    /// Reports whether the node state is stored encrypted on-disk. The actual mechanism is
    /// platform-specific:
    /// * Apple nodes use the Keychain
    /// * Linux and Windows nodes use the TPM
    /// * Android apps use `EncryptedSharedPreferences`
    pub state_encrypted: Option<bool>,
}
