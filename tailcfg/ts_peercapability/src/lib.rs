#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

use alloc::{collections::BTreeMap, vec::Vec};

/// A map of application-specific capability names to an optional list of associated values.
/// An empty list of values may still represent a meaningful capability grant, though the
/// meaning depends on the application.
///
/// The values in each list are opaque and application-specific; the only constraint is that
/// they must be valid JSON. _Conventionally_, and as the KB docs indicate, they are JSON
/// objects with fields representing specific parameters, e.g.
///
/// ```json
/// {
///     "example.com/cap": [
///         { "parameter1": $ANY_JSON_VALUE },
///         { "parameter2": $ANY_JSON_VALUE, "parameter3": $ANY_JSON_VALUE }
///     ]
/// }
/// ```
///
/// However, the following is also a valid capmap -- each list element can be any valid JSON
/// value:
///
/// ```json
/// {
///     "example.com/cap": [
///         true,
///         null,
///         [64],
///         "myvalue"
///     ]
/// }
/// ```
///
/// Since we don't know the representation, the list values are represented as uninterpreted
/// raw JSON strings.
pub type Map<'a> = BTreeMap<Name<'a>, Vec<&'a str>>;

/// Shorthand for declaring a `const` peercap name.
///
/// # Examples
///
/// ```rust
/// # use ts_peercapability::Name;
/// ts_peercapability::peercap!(MY_PEERCAP, "https://my_peercap.com");
///
/// // equivalent to:
/// pub const MY_PEERCAP_2: Name = Name::new("https://my_peercap.com");
///
/// assert_eq!(MY_PEERCAP, MY_PEERCAP_2);
/// ```
#[macro_export]
macro_rules! peercap {
    ($(#[$m:meta])* $name:ident, $cap:expr) => {
        $(#[$m])*
        pub const $name: $crate::Name<'static> = $crate::Name::new($cap);
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

/// The name of an application-layer capability granted to a tailnet peer by a packet filter
/// rule.
///
/// Capability names should be URLs.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Name<'a>(#[cfg_attr(feature = "serde", serde(borrow))] pub &'a str);

impl<'a> Name<'a> {
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
        DEBUG_PEER,
        "debug-peer"
    );
    ts_peercap!(
        /// Grants the ability to send a Wake-On-LAN packet.
        WAKE_ON_LAN,
        "wake-on-lan"
    );
    ts_peercap!(
        /// Grants the ability for a peer to send ingress traffic.
        INGRESS,
        "ingress"
    );
    ts_peercap!(
        /// Grants the ability for a peer to edit features from the device Web UI.
        WEB_UI,
        "webui",
        improper_url
    );
    ts_peercap!(
        /// Grants the ability for a peer to access Taildrive shares.
        TAILDRIVE,
        "drive",
        improper_url
    );
    ts_peercap!(
        /// Indicates that a peer has the ability to share folders with us.
        TAILDRIVE_SHARER,
        "drive-sharer",
        improper_url
    );
    ts_peercap!(
        /// Grants a peer Kubernetes-specific capabilities, such as the ability to
        /// impersonate specific Tailscale user groups as Kubernetes user groups.
        /// This capability is read by Tailscale Kubernetes operators.
        KUBERNETES,
        "kubernetes",
        improper_url
    );
    ts_peercap!(
        /// Grants the ability for a peer to allocate relay endpoints.
        RELAY,
        "relay",
        improper_url
    );
    ts_peercap!(
        /// Grants the current node the ability to allocate relay endpoints to the peer
        /// which has this capability.
        RELAY_TARGET,
        "relay-target",
        improper_url
    );
    ts_peercap!(
        /// Grants a peer tsidp-specific capabilities, such as the ability to add user
        /// groups to the OIDC claim.
        TS_IDP,
        "tsidp",
        improper_url
    );

    /// Convenience function to construct a new `Name` from `&str`.
    pub const fn new(s: &'a str) -> Self {
        Self(s)
    }

    /// Parse this `Name` as a URL.
    ///
    /// This function attempts to correct for improperly-formatted URLs that are missing
    /// a scheme by prepending `https://` if the first attempt at parsing fails.
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

    /// Split this `Name` to domain and capability-name parts.
    ///
    /// Any preceding `https://` prefix is stripped. The name must contain at least one `/`.
    /// Everything before the first `/` is the domain, everything after is the capability
    /// name.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ts_peercapability::Name;
    /// assert_eq!(Name("tailscale.com/cap/relay").split(), Some(("tailscale.com", "cap/relay")));
    /// assert_eq!(Name("https://tailscale.com/cap/tsidp").split(), Some(("tailscale.com", "cap/tsidp")));
    /// assert_eq!(Name("improper_cap_name").split(), None);
    /// ```
    pub fn split(&self) -> Option<(&str, &str)> {
        let s = self.0.strip_prefix("https://").unwrap_or(self.0);
        let (domain, cap_name) = s.split_once('/')?;

        Some((domain, cap_name))
    }
}

impl AsRef<str> for Name<'_> {
    fn as_ref(&self) -> &str {
        self.0
    }
}

impl<'a> From<&'a str> for Name<'a> {
    fn from(value: &'a str) -> Self {
        Self(value)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn improper_url() {
        Name::RELAY.parse_url().unwrap();
    }

    #[test]
    fn split() {
        assert_eq!(
            Name::INGRESS.split().unwrap(),
            ("tailscale.com", "cap/ingress")
        );
        assert_eq!(Name::RELAY.split().unwrap(), ("tailscale.com", "cap/relay"));
        assert_eq!(Name("abc").split(), None);
    }
}
