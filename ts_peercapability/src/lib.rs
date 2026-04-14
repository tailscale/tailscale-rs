#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

use alloc::{collections::BTreeMap, vec::Vec};

/// A map of application-specific capabilities to optional associated values. An empty
/// value set still represents a grant of the capability.
///
/// Values and keys are opaque and application-specific; they are visible to applications
/// via the `WhoIs` API.
pub type Map<'a> = BTreeMap<PeerCap<'a>, Vec<&'a str>>;

/// Shorthand for declaring a `const` peercap name.
///
/// # Examples
///
/// ```rust
/// # use ts_peercapability::PeerCap;
/// ts_peercapability::peercap!(MY_PEERCAP, "https://my_peercap.com");
///
/// // equivalent to:
/// pub const MY_PEERCAP_2: PeerCap = PeerCap::new("https://my_peercap.com");
///
/// assert_eq!(MY_PEERCAP, MY_PEERCAP_2);
/// ```
#[macro_export]
macro_rules! peercap {
    ($(#[$m:meta])* $name:ident, $cap:expr) => {
        $(#[$m])*
        pub const $name: $crate::PeerCap<'static> = $crate::PeerCap::new($cap);
    };
}

/// Shorthand for declaring a Tailscale-owned peercap name.
macro_rules! ts_peercap {
    ($(#[$m:meta])* $name:ident, $cap:literal) => {
        ts_peercap!(_internal, $name, $cap, "https://tailscale.com/cap/", $(#[$m])*);
    };

    // Many of the caps defined in the Go codebase are not proper URLs: they lack the
    // scheme component. Define ours the same way to enable string matching.
    ($(#[$m:meta])* $name:ident, $cap:literal, improper_url) => {
        ts_peercap!(_internal, $name, $cap, "tailscale.com/cap/", $(#[$m])*);
    };

    (_internal, $name:ident, $cap:literal, $pfx:literal, $(#[$m:meta])*) => {
        $crate::peercap!($(#[$m])* $name, concat!($pfx, $cap));
    };
}

/// An application-layer capability granted to a tailnet peer by a packet filter rule.
///
/// Capabilities should be URLs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct PeerCap<'a>(#[cfg_attr(feature = "serde", serde(borrow))] pub &'a str);

impl<'a> PeerCap<'a> {
    ts_peercap!(
        /// Grants the current node the ability to send files to peers with this capability.
        FILE_SHARING_TARGET,
        "file-sharing-target"
    );
    ts_peercap!(
        /// Grants the ability to receive files from a node that's owned by a different
        /// user.
        FILE_SHARING_SEND,
        "file-send"
    );
    ts_peercap!(
        /// Grants the ability for a peer to read this node's goroutines, metrics, magicsock
        /// internal state, etc.
        DEBUG_PEER, "debug-peer"
    );
    ts_peercap!(
        /// Grants the ability to send a Wake-On-LAN packet.
        WAKE_ON_LAN, "wake-on-lan"
    );
    ts_peercap!(
        /// Grants the ability for a peer to send ingress traffic.
        INGRESS, "ingress"
    );
    ts_peercap!(
        /// Grants the ability for a peer to edit features from the device Web UI.
        WEB_UI, "webui", improper_url
    );
    ts_peercap!(
        /// Grants the ability for a peer to access Taildrive shares.
        TAILDRIVE, "drive", improper_url
    );
    ts_peercap!(
        /// Indicates that a peer has the ability to share folders with us.
        TAILDRIVE_SHARER, "drive-sharer", improper_url
    );
    ts_peercap!(
        /// Grants a peer Kubernetes-specific capabilities, such as the ability to
        /// impersonate specific Tailscale user groups as Kubernetes user groups.
        /// This capability is read by Tailscale Kubernetes operators.
        KUBERNETES, "kubernetes", improper_url
    );
    ts_peercap!(
        /// Grants the ability for a peer to allocate relay endpoints.
        RELAY, "relay", improper_url
    );
    ts_peercap!(
        /// Grants the current node the ability to allocate relay endpoints to the peer
        /// which has this capability.
        RELAY_TARGET, "relay-target", improper_url
    );
    ts_peercap!(
        /// Grants a peer tsidp-specific capabilities, such as the ability to add user
        /// groups to the OIDC claim.
        TS_IDP, "tsidp", improper_url
    );

    /// Convenience function to construct a new `PeerCap` from `&str`.
    #[inline]
    pub const fn new(s: &'a str) -> Self {
        Self(s)
    }

    /// Parse this `PeerCapability` as a URL.
    ///
    /// This function attempts to correct for improperly-formatted URLs that are missing
    /// a scheme by prepending `https://` if the first attempt at parsing fails.
    #[inline]
    pub fn parse_url(&self) -> Option<url::Url> {
        url::Url::parse(self.as_ref())
            .or_else(|e| {
                // No need to double-prepend
                if self.as_ref().starts_with("https://") {
                    return Err(e);
                }

                let s = alloc::format!("https://{}", self.as_ref());
                url::Url::parse(&s)
            })
            .ok()
    }
}

impl AsRef<str> for PeerCap<'_> {
    #[inline]
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> From<&'a str> for PeerCap<'a> {
    #[inline]
    fn from(value: &'a str) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn improper_url() {
        PeerCap::RELAY.parse_url().unwrap();
    }
}
