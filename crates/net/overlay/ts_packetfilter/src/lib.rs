#![doc = include_str!("../README.md")]
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(any(feature = "std", test))]
extern crate std;

use alloc::{collections::BTreeMap, string::String};
use core::net::IpAddr;

#[cfg(feature = "checking-filter")]
mod checking_filter;
pub mod filter;
mod ip_proto;
mod rule;
mod state;

#[cfg(feature = "checking-filter")]
pub use checking_filter::CheckingFilter;
#[doc(inline)]
pub use filter::{Filter, FilterAndStorage, FilterExt, FilterStorage, FilterStorageExt};
#[doc(inline)]
pub use ip_proto::IpProto;
#[doc(inline)]
pub use rule::{DstMatch, Rule, Ruleset, SrcMatch};
#[doc(inline)]
pub use state::apply_update;

use crate::filter::CapIter;

/// The name of the default ruleset, i.e. the key the filter in
/// `MapResponse::packet_filter` should use.
pub const DEFAULT_RULESET_NAME: &str = "base";

/// The special ruleset name that clears the packet filter state if it's present
/// with a `null` value.
pub const CLEAR_MAP_KEY: &str = "*";

/// Metadata about an IP packet.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct PacketInfo {
    /// The address of the sender of the packet.
    pub src: IpAddr,
    /// The address of the receiver of the packet.
    pub dst: IpAddr,
    /// The IP protocol number.
    pub ip_proto: IpProto,
    /// The port number.
    pub port: u16,
}

/// Trivial filter that drops all traffic.
///
/// Can be used as an initial filter before the actual filter has been downloaded from
/// control.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash)]
pub struct DropAllFilter;

impl Filter for DropAllFilter {
    fn match_for(&self, info: &PacketInfo, caps: CapIter) -> Option<&str> {
        tracing::trace!(?info, caps = ?caps.into_iter().collect::<alloc::vec::Vec<_>>(), "drop all: drop!");

        None
    }
}

/// Alias representing a BTreeMap-based filter.
pub type BTreeFilter = BTreeMap<String, Ruleset>;

/// Alias representing a [`hashbrown::HashMap`]-based filter.
pub type HashbrownFilter = hashbrown::HashMap<String, Ruleset>;

/// Alias representing a [`HashMap`][std::collections::HashMap]-based filter.
#[cfg(feature = "std")]
pub type HashMapFilter = std::collections::HashMap<String, Ruleset>;

static_assertions::assert_impl_all!(BTreeFilter: Filter, FilterStorage);
static_assertions::assert_impl_all!(HashbrownFilter: Filter, FilterStorage);
#[cfg(feature = "std")]
static_assertions::assert_impl_all!(HashMapFilter: Filter, FilterStorage);
