//! Facilities for complete routing tables.

use core::net::IpAddr;

mod simple;
mod split_stack;

pub use simple::SimpleTable;
pub use split_stack::SplitStackTable;

use crate::RouteModification;

/// A dynamically-dispatched function that can be used to modify a table entry
/// in-place.
pub type DynModifyFn<'a, T> = &'a mut dyn FnMut(Option<&mut T>) -> RouteModification<T>;

/// Abstracts routing table operations.
pub trait RoutingTable {
    /// The value stored in each route.
    type Value: 'static;

    /// Report whether `ip` is covered by a route in the table.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ts_bart::{Table, RoutingTable};
    /// let mut table = Table::default();
    /// let pfx = "1.2.3.0/24".parse().unwrap();
    ///
    /// table.insert(pfx, 12);
    /// assert!(table.contains("1.2.3.4".parse().unwrap()));
    /// assert!(!table.contains("1.2.4.4".parse().unwrap()));
    fn contains(&self, ip: IpAddr) -> bool;

    /// Insert a route into the table at `prefix`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ts_bart::{Table, RoutingTable};
    /// let mut table = Table::default();
    /// let pfx = "0.0.0.0/0".parse().unwrap();
    ///
    /// assert_eq!(None, table.insert(pfx, 12));
    /// // Table has the value now
    /// assert_eq!(Some(&12), table.lookup_prefix_exact(pfx));
    /// // Repeated insert returns the removed value
    /// assert_eq!(Some(12), table.insert(pfx, 13));
    /// ```
    fn insert(&mut self, prefix: ipnet::IpNet, val: Self::Value) -> Option<Self::Value>;

    /// Remove the route from the table with the given `prefix`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ts_bart::{Table, RoutingTable};
    /// let mut table = Table::default();
    /// let pfx = "0.0.0.0/0".parse().unwrap();
    ///
    /// // remove without a route returns `None`
    /// assert_eq!(None, table.remove(pfx));
    ///
    /// // insert then remove returns the value that was inserted
    /// assert_eq!(None, table.insert(pfx, 12));
    /// assert_eq!(Some(12), table.remove(pfx));
    /// ```
    fn remove(&mut self, prefix: ipnet::IpNet) -> Option<Self::Value>;

    /// Wipe the whole table.
    fn clear(&mut self);

    // This non-obvious API is designed this way to make this trait object-safe.
    // `FnOnce` can only be taken by value, hence it can only be passed as an
    // `impl Trait`, which are object-unsafe. So instead we accept &mut dyn FnMut
    // and promise to not call it more than once. That allows us to provide
    // RoutingTableExt::modify with the intended interface. The #[doc(hidden)]
    // is just a hacky way to suggest to consumers to use that more-accessible
    // interface.
    #[doc(hidden)]
    fn modify_impl(
        &mut self,
        prefix: ipnet::IpNet,
        modify: DynModifyFn<Self::Value>,
    ) -> Option<Self::Value>;

    /// Lookup the route that most closely covers `ip`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ts_bart::{Table, RoutingTable};
    /// let mut table = Table::default();
    ///
    /// table.insert("1.2.0.0/16".parse().unwrap(), "value");
    /// assert_eq!(Some(&"value"), table.lookup("1.2.3.4".parse().unwrap()));
    /// ```
    fn lookup(&self, ip: IpAddr) -> Option<&Self::Value>;

    /// Lookup all matches that cover `ip`.
    ///
    /// The iterator yields prefixes in reverse length order (most specific to least).
    fn lookup_all(&self, ip: IpAddr) -> crate::iptrie::LookupIter<'_, Self::Value>;

    /// Lookup a route that exactly matches `prefix` (supernets do not match).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ts_bart::{Table, RoutingTable};
    /// let mut table = Table::default();
    /// let pfx = "1.2.0.0/16".parse().unwrap();
    ///
    /// table.insert(pfx, "route");
    ///
    /// // Exact prefix matches
    /// assert_eq!(Some(&"route"), table.lookup_prefix_exact(pfx));
    /// // Subnet does not
    /// assert_eq!(
    ///     None,
    ///     table.lookup_prefix_exact("1.2.3.0/24".parse().unwrap())
    /// );
    /// ```
    fn lookup_prefix_exact(&self, prefix: ipnet::IpNet) -> Option<&Self::Value>;

    /// Lookup the route that most closely covers `prefix`.
    ///
    /// This represents a slight optimization over
    /// [`lookup_prefix_lpm`][Self::lookup_prefix_lpm] if the matched prefix
    /// isn't needed.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ts_bart::{Table, RoutingTable};
    /// let mut table = Table::default();
    /// let pfx = "1.2.0.0/16".parse().unwrap();
    ///
    /// table.insert(pfx, 1234);
    ///
    /// // subnet lookup gets only the value in the table
    /// assert_eq!(
    ///     Some(&1234),
    ///     table.lookup_prefix("1.2.3.4/30".parse().unwrap())
    /// );
    /// ```
    fn lookup_prefix(&self, prefix: ipnet::IpNet) -> Option<&Self::Value>;

    /// Lookup the route that most closely covers `prefix`, and return that
    /// matching prefix.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ts_bart::{Table, RoutingTable};
    /// let mut table = Table::default();
    /// let pfx = "1.2.0.0/16".parse().unwrap();
    ///
    /// table.insert(pfx, true);
    ///
    /// // subnet lookup returns the matching prefix and route value in the table
    /// assert_eq!(
    ///     Some((pfx, &true)),
    ///     table.lookup_prefix_lpm("1.2.12.143/32".parse().unwrap())
    /// );
    /// ```
    fn lookup_prefix_lpm(&self, prefix: ipnet::IpNet) -> Option<(ipnet::IpNet, &Self::Value)>;

    /// Report the number of routes stored in the table.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ts_bart::{Table, RoutingTable};
    /// let mut table = Table::default();
    /// assert_eq!(0, table.size());
    ///
    /// table.insert("0.0.0.0/0".parse().unwrap(), true);
    /// assert_eq!(1, table.size());
    /// ```
    fn size(&self) -> usize;
}

static_assertions::assert_obj_safe!(RoutingTable<Value = ()>);

impl<T> RoutingTable for &mut T
where
    T: RoutingTable,
{
    type Value = T::Value;

    fn insert(&mut self, prefix: ipnet::IpNet, val: Self::Value) -> Option<Self::Value> {
        (*self).insert(prefix, val)
    }

    fn remove(&mut self, prefix: ipnet::IpNet) -> Option<Self::Value> {
        (*self).remove(prefix)
    }

    fn clear(&mut self) {
        (*self).clear()
    }

    fn modify_impl(
        &mut self,
        prefix: ipnet::IpNet,
        modify: DynModifyFn<Self::Value>,
    ) -> Option<Self::Value> {
        (*self).modify_impl(prefix, modify)
    }

    fn contains(&self, ip: IpAddr) -> bool {
        (**self).contains(ip)
    }

    fn lookup(&self, ip: IpAddr) -> Option<&Self::Value> {
        (**self).lookup(ip)
    }

    fn lookup_all(&self, ip: IpAddr) -> crate::iptrie::LookupIter<'_, Self::Value> {
        (**self).lookup_all(ip)
    }

    fn lookup_prefix_exact(&self, prefix: ipnet::IpNet) -> Option<&Self::Value> {
        (**self).lookup_prefix_exact(prefix)
    }

    fn lookup_prefix(&self, prefix: ipnet::IpNet) -> Option<&Self::Value> {
        (**self).lookup_prefix(prefix)
    }

    fn lookup_prefix_lpm(&self, prefix: ipnet::IpNet) -> Option<(ipnet::IpNet, &Self::Value)> {
        (**self).lookup_prefix_lpm(prefix)
    }

    fn size(&self) -> usize {
        (**self).size()
    }
}

mod private {
    pub trait Sealed {}
}

/// Automatic extension methods for implementors of [`RoutingTable`].
pub trait RoutingTableExt: RoutingTable + private::Sealed {
    /// Modify the route at `prefix` using the `modify` closure.
    ///
    /// The closure may return:
    ///
    /// - [`RouteModification::Insert`]: a route will be inserted with the
    ///   provided value (or replaced if it already exists).
    /// - [`RouteModification::Remove`]: the route will be removed (if it
    ///   exists).
    /// - [`RouteModification::Noop`]: the table will not be modified. The
    ///   closure may modify the value stored in the route (if present).
    ///
    /// If the route was replaced or removed, the return value contains the
    /// value that was previously stored.
    ///
    /// Prefer to use [`insert`][RoutingTable::insert] or
    /// [`remove`][RoutingTable::remove] if possible; this function is
    /// intended as a more-efficient alternative to
    /// [`lookup_prefix_exact`][RoutingTable::lookup_prefix_exact]-then-mutate.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ts_bart::{SimpleTable, RouteModification, RoutingTable, RoutingTableExt};
    /// let mut table = SimpleTable::default();
    /// let result = table.modify("0.0.0.0/0".parse().unwrap(), |node| {
    ///     assert_eq!(None, node);
    ///     RouteModification::Insert(4)
    /// });
    /// assert_eq!(None, result);
    /// assert_eq!(Some(&4), table.lookup("1.2.3.4".parse().unwrap()));
    /// ```
    fn modify(
        &mut self,
        prefix: ipnet::IpNet,
        modify: impl FnOnce(Option<&mut Self::Value>) -> RouteModification<Self::Value>,
    ) -> Option<Self::Value> {
        let mut modify = Some(modify);
        self.modify_impl(prefix, &mut move |val| {
            modify
                .take()
                .expect("modify implementation called closure more than once")(val)
        })
    }
}

impl<T> private::Sealed for T where T: RoutingTable {}
impl<T> RoutingTableExt for T where T: RoutingTable {}
