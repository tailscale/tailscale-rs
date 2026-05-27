//! Iterate over a table

use std::{marker::PhantomData, ops::Deref};

use crate::{
    schema::{self, IndexDesc, TableDesc},
    storage::Storage,
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

/// An iterator for a single table (described by the generic parameter `D`) in the KV store.
///
/// Clones the key and value as we iterate. This is necessary to avoid returning references which
/// might outlive the iterator, and thus its lock on the store being dropped.
///
/// This is basically just a wrapper for an iterator over the `HashMap` representing the table.
/// However, we must hold a guard for the `KvStore`'s storage for the lifetime of the iterator.
pub struct TableIterator<
    'store: 'guard,
    'guard,
    Guard: Deref<Target = Storage<TableStorage>> + 'guard,
    TableStorage: schema::GeneratedStorage,
    D: TableDesc<Storage = TableStorage>,
    Kind,
> {
    /// Guard on the KV store's storage (all of it).
    guard: Guard,
    /// An iterator over the `HashMap` representing the table.
    ///
    /// Invariants:
    ///   - `inner.is_some()` once `new` has completed.
    inner: Option<std::collections::hash_map::Iter<'guard, D::Key, D::Value>>,
    _kind: PhantomData<(Kind, &'store ())>,
}

impl<
    'store: 'guard,
    'guard,
    Guard: Deref<Target = Storage<TableStorage>> + 'guard,
    TableStorage: schema::GeneratedStorage + 'store,
    D: TableDesc<Storage = TableStorage> + 'store,
    Kind,
> TableIterator<'store, 'guard, Guard, TableStorage, D, Kind>
{
    /// Create an iterator over the table described by `D`.
    pub(crate) fn new(guard: Guard) -> Self {
        let mut result = TableIterator {
            guard,
            inner: None,
            _kind: PhantomData,
        };
        result.inner = Some(inner_iter::<_, _, D>(&result.guard));
        result
    }

    fn inner_next(&mut self) -> Option<(&'guard D::Key, &'guard D::Value)> {
        self.inner.as_mut().unwrap().next()
    }
}

impl<
    'store: 'guard,
    'guard,
    Guard: Deref<Target = Storage<TableStorage>> + 'guard,
    TableStorage: schema::GeneratedStorage + 'store,
    D: TableDesc<Storage = TableStorage> + 'store,
> Iterator for TableIterator<'store, 'guard, Guard, TableStorage, D, KeysAndValues>
{
    type Item = (&'guard D::Key, &'guard D::Value);

    fn next(&mut self) -> Option<Self::Item> {
        // Iterate by delegating to the `HashMap` iterator.
        self.inner_next()
    }
}

impl<
    'store: 'guard,
    'guard,
    Guard: Deref<Target = Storage<TableStorage>> + 'guard,
    TableStorage: schema::GeneratedStorage + 'store,
    D: TableDesc<Storage = TableStorage> + 'store,
> Iterator for TableIterator<'store, 'guard, Guard, TableStorage, D, Keys>
{
    type Item = &'guard D::Key;

    fn next(&mut self) -> Option<Self::Item> {
        // Iterate by delegating to the `HashMap` iterator.
        self.inner_next().map(|(k, _)| k)
    }
}

impl<
    'store: 'guard,
    'guard,
    Guard: Deref<Target = Storage<TableStorage>> + 'guard,
    TableStorage: schema::GeneratedStorage + 'store,
    D: TableDesc<Storage = TableStorage> + 'store,
> Iterator for TableIterator<'store, 'guard, Guard, TableStorage, D, Values>
{
    type Item = &'guard D::Value;

    fn next(&mut self) -> Option<Self::Item> {
        // Iterate by delegating to the `HashMap` iterator.
        self.inner_next().map(|(_, v)| v)
    }
}
impl<
    'store: 'guard,
    'guard,
    Guard: Deref<Target = Storage<TableStorage>> + 'guard,
    TableStorage: schema::GeneratedStorage,
    D: TableDesc<Storage = TableStorage>,
    Kind,
> Drop for TableIterator<'store, 'guard, Guard, TableStorage, D, Kind>
{
    fn drop(&mut self) {
        // Ensure that `self.inner` is dropped before `self.guard`.
        self.inner = None;
    }
}

/// An iterator for an indexed table (described by the generic parameter `B`, the index is described
/// by `D`) in the KV store.
///
/// Clones the key and value as we iterate. This is necessary to avoid returning references which
/// might outlive the iterator, and thus its lock on the store being dropped.
pub struct IndexIterator<
    'store: 'guard,
    'guard,
    Guard: Deref<Target = Storage<TableStorage>> + 'guard,
    TableStorage: schema::GeneratedStorage + 'store,
    D: IndexDesc<Storage = TableStorage, BaseTable = B>,
    B: TableDesc<Storage = TableStorage>,
    Kind,
> where
    Self: 'guard,
{
    /// Guard on the KV store's storage (all of it).
    guard: Guard,
    /// An iterator over the `HashMap` representing the index.
    ///
    /// Invariants:
    ///   - `inner.is_some()` once `new` has completed.
    inner: Option<std::collections::hash_map::Iter<'guard, D::Key, D::Value>>,
    _kind: PhantomData<(Kind, &'store ())>,
}

impl<
    'store: 'guard,
    'guard,
    Guard: Deref<Target = Storage<TableStorage>> + 'guard,
    TableStorage: schema::GeneratedStorage + 'store,
    D: IndexDesc<Storage = TableStorage, BaseTable = B>,
    B: TableDesc<Storage = TableStorage>,
    Kind,
> IndexIterator<'store, 'guard, Guard, TableStorage, D, B, Kind>
{
    /// Create an iterator over the table described by `D` (the index).
    pub(crate) fn new(guard: Guard) -> Self {
        let mut result = IndexIterator {
            guard,
            inner: None,
            _kind: PhantomData,
        };
        result.inner = Some(inner_iter::<_, _, D>(&result.guard));
        result
    }

    fn get_tables(&self) -> &'guard TableStorage {
        let tables = &self.guard.tables as *const _;
        unsafe { &*tables }
    }
}

impl<
    'store: 'guard,
    'guard,
    Guard: Deref<Target = Storage<TableStorage>> + 'guard,
    TableStorage: schema::GeneratedStorage + 'store,
    D: IndexDesc<Storage = TableStorage, BaseTable = B, Value = B::Key>,
    B: TableDesc<Storage = TableStorage>,
> Iterator for IndexIterator<'store, 'guard, Guard, TableStorage, D, B, KeysAndValues>
{
    type Item = (&'guard D::Key, &'guard B::Value);

    fn next(&mut self) -> Option<Self::Item> {
        // Iterate by delegating to the `HashMap` iterator.
        self.inner
            .as_mut()
            .unwrap()
            .next()
            .and_then(move |(k, bk)| {
                let tables = self.get_tables();
                let base = B::get_table(tables);
                Some((k, base.data.get(bk)?))
            })
    }
}

impl<
    'store: 'guard,
    'guard,
    Guard: Deref<Target = Storage<TableStorage>> + 'guard,
    TableStorage: schema::GeneratedStorage + 'store,
    D: IndexDesc<Storage = TableStorage, BaseTable = B, Value = B::Key>,
    B: TableDesc<Storage = TableStorage>,
> Iterator for IndexIterator<'store, 'guard, Guard, TableStorage, D, B, Keys>
{
    type Item = &'guard D::Key;

    fn next(&mut self) -> Option<Self::Item> {
        // Iterate by delegating to the `HashMap` iterator.
        self.inner.as_mut().unwrap().next().map(|(k, _)| k)
    }
}

impl<
    'store: 'guard,
    'guard,
    Guard: Deref<Target = Storage<TableStorage>> + 'guard,
    TableStorage: schema::GeneratedStorage + 'store,
    D: IndexDesc<Storage = TableStorage, BaseTable = B, Value = B::Key>,
    B: TableDesc<Storage = TableStorage>,
> Iterator for IndexIterator<'store, 'guard, Guard, TableStorage, D, B, Values>
{
    type Item = &'guard B::Value;

    fn next(&mut self) -> Option<Self::Item> {
        // Iterate by delegating to the `HashMap` iterator.
        self.inner.as_mut().unwrap().next().and_then(|(_, bk)| {
            let tables = self.get_tables();
            let base = B::get_table(tables);
            base.data.get(bk)
        })
    }
}

impl<
    'store: 'guard,
    'guard,
    Guard: Deref<Target = Storage<TableStorage>> + 'guard,
    TableStorage: schema::GeneratedStorage + 'store,
    D: IndexDesc<Storage = TableStorage, BaseTable = B>,
    B: TableDesc<Storage = TableStorage>,
    Kind,
> Drop for IndexIterator<'store, 'guard, Guard, TableStorage, D, B, Kind>
{
    fn drop(&mut self) {
        // Ensure that `self.inner` is dropped before `self.guard`.
        self.inner = None;
    }
}

// Create an iterator over a table's data to use as a base for these iterators.
fn inner_iter<
    'store: 'guard,
    'guard,
    Guard: Deref<Target = Storage<TableStorage>> + 'guard,
    TableStorage: schema::GeneratedStorage + 'store,
    D: TableDesc<Storage = TableStorage> + 'store,
>(
    guard: &Guard,
) -> std::collections::hash_map::Iter<'guard, D::Key, D::Value> {
    let tables: *const _ = &guard.tables;
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
