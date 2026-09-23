#![doc = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md"))]
#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

mod allot;
mod base_index;
pub mod iptrie;
mod lpm;
mod node;
pub mod table;
#[cfg(test)]
pub mod test_util;

pub use allot::{fringe as allot_fringe, prefix as allot_prefix};
pub use base_index::BaseIndex;
#[doc(inline)]
pub use iptrie::RouteModification;
pub use lpm::lookup as lpm;
pub use node::{
    BoxStorage, Child, DefaultNode, DefaultStorage, InlineStorage, Node, PrefixOps, PrefixOpsExt,
    PrefixReadOps, Stats, Storage, StrideBase, StrideOps, StrideOpsExt,
};
#[doc(inline)]
pub use table::{RoutingTable, RoutingTableExt};

/// Total memory usage of all lookup tables in the crate.
#[cfg(feature = "lut")]
pub const LUT_MEMORY: usize = allot::LUT_SIZE + ts_bitset::RANK_LUT_SIZE + lpm::LUT_SIZE;

/// General-purpose table type.
///
/// Type alias around [`table::SplitStackTable`] that specializes the node type
/// to canonical [`Node`] with boxed child storage ([`BoxStorage`]).
/// The type parameter is the contained route value type.
pub type Table<T> = table::SplitStackTable<DefaultNode<T>>;

/// Table for single-IP-stack environments.
///
/// Type alias around [`table::SimpleTable`] that specializes the node type to
/// the canonical [`Node`] with boxed child storage
/// ([`BoxStorage`]). The type parameter is the contained route value type.
pub type SimpleTable<T> = table::SimpleTable<DefaultNode<T>>;

#[cfg(test)]
mod test {
    #[cfg(feature = "lut")]
    #[test]
    fn lut_size() {
        std::println!("LUT memory usage: {}B", super::LUT_MEMORY);

        assert_eq!(
            super::LUT_MEMORY,
            32 * 1024,
            "lut memory usage changed, please update the test if this was intentional",
        );
    }
}
