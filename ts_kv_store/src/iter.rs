//! Iterate over a table

use std::{hash::Hash, marker::PhantomData, ops::Deref};

use crate::{
    schema::{IndexDesc, TableDesc},
    storage::{StorageLike, Table},
};

/// Phantom type to iterate over keys.
#[doc(hidden)]
pub struct Keys;
/// Phantom type to iterate over Values.
#[doc(hidden)]
pub struct Values;
/// Phantom type to iterate over key/value pairs.
#[doc(hidden)]
pub struct KeysAndValues;

type IndexHandle<'guard, D> =
    &'guard Table<<D as IndexDesc>::BaseTable, <<D as IndexDesc>::BaseTable as TableDesc>::Indexes>;

type TableIter<'guard, D> =
    std::collections::hash_map::Iter<'guard, <D as TableDesc>::Key, <D as TableDesc>::Value>;

/// An iterator for a single table (described by the generic parameter `D`) in the KV store.
///
/// This is basically just a wrapper for an iterator over the `HashMap` representing the table.
/// However, we must hold a guard for the `KvStore`'s storage for the lifetime of the iterator.
pub struct TableIterator<'guard, Guard, D: TableDesc, Kind> {
    /// Guard on the KV store's storage (all of it).
    guard: Guard,
    /// An iterator over the `HashMap` representing the table.
    ///
    /// Invariants:
    ///   - `inner.is_some()` once `new` has completed.
    inner: Option<TableIter<'guard, D>>,
    _kind: PhantomData<Kind>,
}

impl<'guard, Guard, D: TableDesc, Kind> TableIterator<'guard, Guard, D, Kind> {
    /// Create an iterator over the table described by `D`.
    pub(crate) fn new(guard: Guard) -> Self
    where
        Guard: Deref + 'guard,
        <Guard as Deref>::Target: StorageLike<Generated = D::Storage>,
        D: 'guard,
    {
        let mut result = TableIterator {
            guard,
            inner: None,
            _kind: PhantomData,
        };
        result.inner = Some(inner_iter::<D, Guard>(&result.guard));
        result
    }

    fn inner_next(&mut self) -> Option<(&'guard D::Key, &'guard D::Value)> {
        self.inner.as_mut().unwrap().next()
    }
}

impl<'guard, Guard, D: TableDesc> Iterator for TableIterator<'guard, Guard, D, KeysAndValues> {
    type Item = (&'guard D::Key, &'guard D::Value);

    fn next(&mut self) -> Option<Self::Item> {
        // Iterate by delegating to the `HashMap` iterator.
        self.inner_next()
    }
}

impl<'guard, Guard, D: TableDesc> Iterator for TableIterator<'guard, Guard, D, Keys> {
    type Item = &'guard D::Key;

    fn next(&mut self) -> Option<Self::Item> {
        // Iterate by delegating to the `HashMap` iterator.
        self.inner_next().map(|(k, _)| k)
    }
}

impl<'guard, Guard, D: TableDesc> Iterator for TableIterator<'guard, Guard, D, Values> {
    type Item = &'guard D::Value;

    fn next(&mut self) -> Option<Self::Item> {
        // Iterate by delegating to the `HashMap` iterator.
        self.inner_next().map(|(_, v)| v)
    }
}

impl<Guard, D: TableDesc, Kind> Drop for TableIterator<'_, Guard, D, Kind> {
    fn drop(&mut self) {
        // Ensure that `self.inner` is dropped before `self.guard`.
        self.inner = None;
    }
}

/// An iterator for an indexed table (described by the generic parameter `D`) in the KV
/// store.
pub struct IndexIterator<'guard, Guard, D: IndexDesc, Kind> {
    /// Guard on the KV store's storage (all of it).
    guard: Guard,
    /// An iterator over the `HashMap` representing the index.
    ///
    /// Invariants:
    ///   - `inner.is_some()` once `new` has completed.
    inner: Option<(IndexHandle<'guard, D>, TableIter<'guard, D>)>,
    _kind: PhantomData<Kind>,
}

impl<'guard, Guard, D: IndexDesc, Kind> IndexIterator<'guard, Guard, D, Kind> {
    /// Create an iterator over the table described by `D` (the index).
    pub(crate) fn new(guard: Guard) -> Self
    where
        Guard: Deref + 'guard,
        <Guard as Deref>::Target: StorageLike<Generated = D::Storage>,
        D: 'guard,
    {
        let mut result = IndexIterator {
            guard,
            inner: None,
            _kind: PhantomData,
        };

        let base_table = <D::BaseTable as TableDesc>::get_table(result.guard.tables());

        result.inner = Some((
            // SAFETY: for the same reasoning as `inner_iter`, we're extending the lifetime of this
            // internal reference to 'guard. This is safe for the same reasons, i.e. we ensure that
            // guard is dropped first.
            unsafe { &*(base_table as *const _) },
            inner_iter::<D, Guard>(&result.guard),
        ));

        result
    }
}

impl<'guard, Guard, D: IndexDesc> Iterator for IndexIterator<'guard, Guard, D, KeysAndValues>
where
    D::Value: Hash + Eq,
{
    type Item = (&'guard D::Key, &'guard <D::BaseTable as TableDesc>::Value);

    fn next(&mut self) -> Option<Self::Item> {
        // Iterate by delegating to the `HashMap` iterator.
        let (base, iter) = self.inner.as_mut().unwrap();
        let (k, bk) = iter.next()?;

        Some((k, base.data.get(bk)?))
    }
}

impl<'guard, Guard, D: IndexDesc> Iterator for IndexIterator<'guard, Guard, D, Keys> {
    type Item = &'guard D::Key;

    fn next(&mut self) -> Option<Self::Item> {
        // Iterate by delegating to the `HashMap` iterator.
        let (_, iter) = self.inner.as_mut().unwrap();
        iter.next().map(|(k, _)| k)
    }
}

impl<'guard, Guard, D: IndexDesc> Iterator for IndexIterator<'guard, Guard, D, Values>
where
    D::Value: Hash + Eq,
{
    type Item = &'guard <D::BaseTable as TableDesc>::Value;

    fn next(&mut self) -> Option<Self::Item> {
        // Iterate by delegating to the `HashMap` iterator.
        let (base, iter) = self.inner.as_mut().unwrap();
        let (_, bk) = iter.next()?;

        base.data.get(bk)
    }
}

impl<Guard, D: IndexDesc, Kind> Drop for IndexIterator<'_, Guard, D, Kind> {
    fn drop(&mut self) {
        // Ensure that `self.inner` is dropped before `self.guard`.
        self.inner = None;
    }
}

// Create an iterator over a table's data to use as a base for these iterators.
fn inner_iter<'guard, D, Guard>(
    guard: &Guard,
) -> std::collections::hash_map::Iter<'guard, D::Key, D::Value>
where
    D: TableDesc + 'guard,
    Guard: Deref + 'guard,
    <Guard as Deref>::Target: StorageLike<Generated = D::Storage>,
{
    let tables: *const _ = guard.tables();
    // SAFETY: here we're extending the lifetime of the reference to the KV storage to `'guard`.
    // We can't use a raw pointer because we won't be able to use that as input to create an
    // iterator. To ensure safety we must ensure that `self.guard` outlives `self.inner`. We can
    // outlive the temporary because guard holds a pointer to the storage and `tables` follows that
    // pointer (via the `Deref` impl) to the tables field. So even if the temporary is dropped and
    // `result` is moved, `&result.guard.tables` will point at the same address which is guaranteed
    // to outlive `'guard`.
    let tables = unsafe { &*tables };
    D::get_table(tables).data.iter()
}
