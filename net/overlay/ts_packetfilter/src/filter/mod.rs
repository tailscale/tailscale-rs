//! Packet filter traits and abstractions.

use crate::{PacketInfo, rule::Rule};

mod map_impl;

/// An iterator that lists the capabilities available for a given source.
pub type CapIter<'c, 's> = &'c mut dyn Iterator<Item = &'s str>;

/// A packet filter that can verify whether a specific source can access a given
/// destination.
///
/// Filters packets on L3 and L4 attributes (source and destination IP,
/// protocol, ports) and arbitrary capability strings delivered out-of-band by
/// the control server (node capabilities).
pub trait Filter {
    /// Check whether the given `src` can access `dst` on proto `proto` and port
    /// `port`. `caps` iterates the capabilities of the source.
    fn match_for(&self, info: &PacketInfo, caps: CapIter) -> Option<&str>;

    /// Report whether the given `info` and `caps` are permitted via the filter.
    ///
    /// This is just sugar over `match_for().is_some()` by default (when the name of the
    /// matching filter isn't needed), but implementations may override if they can provide
    /// a faster implementation by skipping name lookup.
    fn matches(&self, info: &PacketInfo, caps: CapIter) -> bool {
        self.match_for(info, caps).is_some()
    }
}

/// A type that can store packet filters organized by named key.
///
/// Typically, [`FilterStorage`] types will also implement [`Filter`]: the
/// traits are separate to permit implementations of [`Filter`] that don't
/// implement _this_ trait, e.g. a static filter or a fn-based filter, and for
/// mutability reasons (`&T` can implement [`Filter`], but this trait needs
/// `&mut`).
pub trait FilterStorage {
    /// Insert a new ruleset into the packet filter storage under the given key.
    ///
    /// See [`FilterStorageExt::insert`] for a more-ergonomic version of this
    /// function (but which isn't object-safe, and therefor isn't included
    /// here).
    fn insert_dyn(&mut self, name: &str, ruleset: &mut dyn Iterator<Item = Rule>);

    /// Remove a ruleset from the packet filter storage by key.
    fn remove(&mut self, name: &str);

    /// Clear all filters.
    fn clear(&mut self);
}

static_assertions::assert_obj_safe!(FilterStorage);
static_assertions::assert_obj_safe!(Filter);

impl<T> Filter for &T
where
    T: Filter + ?Sized,
{
    fn match_for(&self, info: &PacketInfo, caps: CapIter) -> Option<&str> {
        (*self).match_for(info, caps)
    }
}

impl<T> Filter for &mut T
where
    T: Filter + ?Sized,
{
    fn match_for(&self, info: &PacketInfo, caps: CapIter) -> Option<&str> {
        (**self).match_for(info, caps)
    }
}

impl<T> FilterStorage for &mut T
where
    T: FilterStorage + ?Sized,
{
    fn insert_dyn(&mut self, name: &str, ruleset: &mut dyn Iterator<Item = Rule>) {
        (*self).insert_dyn(name, ruleset)
    }

    fn remove(&mut self, name: &str) {
        (*self).remove(name)
    }

    fn clear(&mut self) {
        (*self).clear()
    }
}

/// Extension methods for [`Filter`].
pub trait FilterExt: Filter {
    /// Report whether the given `src` can access `dst` with the given `proto`
    /// and `port`. `caps` iterates the capabilities for the source IP.
    ///
    /// Sugar over [`Filter::match_for`] for cases where the name of the matched
    /// ruleset isn't needed.
    fn can_access<'s>(&self, info: &PacketInfo, caps: impl IntoIterator<Item = &'s str>) -> bool {
        let mut cap_iter = caps.into_iter();
        self.matches(info, &mut cap_iter)
    }
}

impl<T> FilterExt for T where T: Filter + ?Sized {}

/// Extension methods for [`FilterStorage`].
pub trait FilterStorageExt: FilterStorage {
    /// Insert a new ruleset into packet filter storage under the given key.
    fn insert(&mut self, name: &str, ruleset: impl IntoIterator<Item = Rule>) {
        let mut it = ruleset.into_iter();
        self.insert_dyn(name, &mut it)
    }
}

impl<T> FilterStorageExt for T where T: FilterStorage + ?Sized {}

/// Convenience trait that can be used to select _both_ [`Filter`] and
/// [`FilterStorage`] simultaneously in a `dyn Trait`.
pub trait FilterAndStorage: Filter + FilterStorage {}

impl<T> FilterAndStorage for T where T: Filter + FilterStorage + ?Sized {}
static_assertions::assert_obj_safe!(FilterAndStorage);
