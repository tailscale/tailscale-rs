#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

use alloc::{collections::BTreeMap, vec::Vec};

/// A map of node capabilities to their optional values. It is valid for a capability to have
/// `None` as a value; such capabilities can be tested for by using the
/// [`Map::contains_key`] method.
///
/// See [`NodeCap`] for more information on keys.
pub type Map<'a> = BTreeMap<NodeCap<'a>, Values<'a>>;

/// Represents a capability granted to a node.
///
/// All capabilities must be a URL like `https://tailscale.com/cap/file-sharing`, or a
/// well-known capability name like `funnel`. The latter is only allowed for
/// Tailscale-defined capabilities.
///
/// Unlike `PeerCapability` (`ts_peercap`), [`NodeCap`] is not in context of a peer
/// and is granted to the node itself. These are also referred to as "Node Attributes" in
/// the ACL policy file.
pub type NodeCap<'a> = &'a str;

// TODO(npry): NodeCapability -> enum covering special caps w/ catchall, associated consts
//              for well-known URL caps

cfg_if::cfg_if! {
    if #[cfg(feature = "serde")] {
        /// The type of the entry in a [`Values`].
        ///
        /// Defined as a type alias to allow switching based on serde support.
        pub type Value<'a> = &'a serde_json::value::RawValue;
    } else {
        /// The type of the entry in a [`Values`].
        ///
        /// Defined as a type alias to allow switching based on serde support.
        pub type Value<'a> = &'a str;
    }
}

/// The types of values that can be associated with a single [`NodeCap`] in a
/// [`Map`].
#[derive(Clone, Debug)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Values<'a>(
    #[cfg_attr(
        feature = "serde",
        serde(borrow, deserialize_with = "deserialize_nodecap")
    )]
    pub Vec<Value<'a>>,
);

#[cfg(feature = "serde")]
fn deserialize_nodecap<'a, 'de, D>(
    deserializer: D,
) -> Result<Vec<&'a serde_json::value::RawValue>, D::Error>
where
    'de: 'a,
    D: serde::Deserializer<'de>,
{
    use serde::Deserialize;

    let val = <Option<Vec<&'a serde_json::value::RawValue>>>::deserialize(deserializer)?
        .unwrap_or_else(Vec::new);

    Ok(val)
}
