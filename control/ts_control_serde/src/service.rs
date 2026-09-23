use serde::{Deserialize, Serialize};

/// The protocol that a running service uses to communicate. Most services use the
/// [`ServiceProto::Tcp`] or [`ServiceProto::Udp`] values.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ServiceProto {
    /// Standard TCP over either IPv4 or IPv6.
    Tcp,
    /// Standard UDP over either IPv4 or IPv6.
    Udp,
    /// A transport-layer protocol that provides access to a Tailscale node's PeerAPI service over
    /// IPv4.
    PeerApi4,
    /// A transport-layer protocol that provides access to a Tailscale node's PeerAPI service over
    /// IPv6.
    PeerApi6,
    /// A transport-layer protocol that provides DNS lookup proxying on Tailscale exit nodes for
    /// other nodes in the Tailnet.
    #[serde(rename = "peerapi-dns-proxy")]
    PeerApiDnsProxy,
}

/// Represents a service running on a Tailscale node.
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
pub struct Service<'a> {
    /// The protocol that a running service uses to communicate. It's usually [`ServiceProto::Tcp`]
    /// or [`ServiceProto::Udp`].
    pub proto: ServiceProto,
    /// The transport-layer port number that the service is listening on.
    ///
    /// If [`Service::proto`] is [`ServiceProto::PeerApiDnsProxy`], this field must be set to `1`.
    pub port: u16,
    /// Free-form textual description of the running service. Typically this is the name of the
    /// running service process.
    #[serde(borrow)]
    pub description: &'a str,
}
