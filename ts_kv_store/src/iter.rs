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
    'a,
    Guard: Deref<Target = Storage<TableStorage>> + 'a,
    TableStorage: schema::GeneratedStorage + 'a,
    D: TableDesc<Storage = TableStorage> + 'a,
    Kind,
> {
    /// Guard on the KV store's storage (all of it).
    guard: Guard,
    /// An iterator over the `HashMap` representing the table.
    ///
    /// Invariants:
    ///   - `inner.is_some()` once `new` has completed.
    inner: Option<std::collections::hash_map::Iter<'a, D::Key, D::Value>>,
    _kind: PhantomData<Kind>,
}

impl<
    'a,
    Guard: Deref<Target = Storage<TableStorage>> + 'a,
    TableStorage: schema::GeneratedStorage + 'a,
    D: TableDesc<Storage = TableStorage> + 'a,
    Kind,
> TableIterator<'a, Guard, TableStorage, D, Kind>
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

    fn inner_next(&mut self) -> Option<(&D::Key, &D::Value)> {
        self.inner.as_mut().unwrap().next()
    }
}

impl<
    'a,
    Guard: Deref<Target = Storage<TableStorage>> + 'a,
    TableStorage: schema::GeneratedStorage + 'a,
    D: TableDesc<Storage = TableStorage> + 'a,
> Iterator for TableIterator<'a, Guard, TableStorage, D, KeysAndValues>
where
    D::Key: Clone,
    D::Value: Clone,
{
    type Item = (D::Key, D::Value);

    fn next(&mut self) -> Option<Self::Item> {
        // Iterate by delegating to the `HashMap` iterator.
        self.inner_next().map(|(k, v)| (k.clone(), v.clone()))
    }
}

impl<
    'a,
    Guard: Deref<Target = Storage<TableStorage>> + 'a,
    TableStorage: schema::GeneratedStorage + 'a,
    D: TableDesc<Storage = TableStorage> + 'a,
> Iterator for TableIterator<'a, Guard, TableStorage, D, Keys>
where
    D::Key: Clone,
{
    type Item = D::Key;

    fn next(&mut self) -> Option<Self::Item> {
        // Iterate by delegating to the `HashMap` iterator.
        self.inner_next().map(|(k, _)| k.clone())
    }
}

impl<
    'a,
    Guard: Deref<Target = Storage<TableStorage>> + 'a,
    TableStorage: schema::GeneratedStorage + 'a,
    D: TableDesc<Storage = TableStorage> + 'a,
> Iterator for TableIterator<'a, Guard, TableStorage, D, Values>
where
    D::Value: Clone,
{
    type Item = D::Value;

    fn next(&mut self) -> Option<Self::Item> {
        // Iterate by delegating to the `HashMap` iterator.
        self.inner_next().map(|(_, v)| v.clone())
    }
}
impl<
    'a,
    Guard: Deref<Target = Storage<TableStorage>> + 'a,
    TableStorage: schema::GeneratedStorage + 'a,
    D: TableDesc<Storage = TableStorage> + 'a,
    Kind,
> Drop for TableIterator<'a, Guard, TableStorage, D, Kind>
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
    'a,
    Guard: Deref<Target = Storage<TableStorage>> + 'a,
    TableStorage: schema::GeneratedStorage + 'a,
    D: IndexDesc<Storage = TableStorage, BaseTable = B> + 'a,
    B: TableDesc<Storage = TableStorage>,
    Kind,
> {
    /// Guard on the KV store's storage (all of it).
    guard: Guard,
    /// An iterator over the `HashMap` representing the index.
    ///
    /// Invariants:
    ///   - `inner.is_some()` once `new` has completed.
    inner: Option<std::collections::hash_map::Iter<'a, D::Key, D::Value>>,
    _kind: PhantomData<Kind>,
}

impl<
    'a,
    Guard: Deref<Target = Storage<TableStorage>> + 'a,
    TableStorage: schema::GeneratedStorage + 'a,
    D: IndexDesc<Storage = TableStorage, BaseTable = B> + 'a,
    B: TableDesc<Storage = TableStorage>,
    Kind,
> IndexIterator<'a, Guard, TableStorage, D, B, Kind>
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
}

impl<
    'a,
    Guard: Deref<Target = Storage<TableStorage>> + 'a,
    TableStorage: schema::GeneratedStorage + 'a,
    D: IndexDesc<Storage = TableStorage, BaseTable = B, Value = B::Key> + 'a,
    B: TableDesc<Storage = TableStorage>,
> Iterator for IndexIterator<'a, Guard, TableStorage, D, B, KeysAndValues>
where
    D::Key: Clone,
    B::Value: Clone,
{
    type Item = (D::Key, B::Value);

    fn next(&mut self) -> Option<Self::Item> {
        // Iterate by delegating to the `HashMap` iterator.
        self.inner.as_mut().unwrap().next().and_then(|(k, bk)| {
            let tables = &self.guard.tables;
            let base = B::get_table(tables);
            Some((k.clone(), base.data.get(bk)?.clone()))
        })
    }
}

impl<
    'a,
    Guard: Deref<Target = Storage<TableStorage>> + 'a,
    TableStorage: schema::GeneratedStorage + 'a,
    D: IndexDesc<Storage = TableStorage, BaseTable = B, Value = B::Key> + 'a,
    B: TableDesc<Storage = TableStorage>,
> Iterator for IndexIterator<'a, Guard, TableStorage, D, B, Keys>
where
    D::Key: Clone,
{
    type Item = D::Key;

    fn next(&mut self) -> Option<Self::Item> {
        // Iterate by delegating to the `HashMap` iterator.
        self.inner.as_mut().unwrap().next().map(|(k, _)| k.clone())
    }
}

impl<
    'a,
    Guard: Deref<Target = Storage<TableStorage>> + 'a,
    TableStorage: schema::GeneratedStorage + 'a,
    D: IndexDesc<Storage = TableStorage, BaseTable = B, Value = B::Key> + 'a,
    B: TableDesc<Storage = TableStorage>,
> Iterator for IndexIterator<'a, Guard, TableStorage, D, B, Values>
where
    B::Value: Clone,
{
    type Item = B::Value;

    fn next(&mut self) -> Option<Self::Item> {
        // Iterate by delegating to the `HashMap` iterator.
        self.inner.as_mut().unwrap().next().and_then(|(_, bk)| {
            let tables = &self.guard.tables;
            let base = B::get_table(tables);
            Some(base.data.get(bk)?.clone())
        })
    }
}

impl<
    'a,
    Guard: Deref<Target = Storage<TableStorage>> + 'a,
    TableStorage: schema::GeneratedStorage + 'a,
    D: IndexDesc<Storage = TableStorage, BaseTable = B> + 'a,
    B: TableDesc<Storage = TableStorage>,
    Kind,
> Drop for IndexIterator<'a, Guard, TableStorage, D, B, Kind>
{
    fn drop(&mut self) {
        // Ensure that `self.inner` is dropped before `self.guard`.
        self.inner = None;
    }
}

// Create an iterator over a table's data to use as a base for these iterators.
fn inner_iter<
    'a,
    Guard: Deref<Target = Storage<TableStorage>> + 'a,
    TableStorage: schema::GeneratedStorage + 'a,
    D: TableDesc<Storage = TableStorage> + 'a,
>(
    guard: &Guard,
) -> std::collections::hash_map::Iter<'a, D::Key, D::Value> {
    let tables: *const _ = &guard.tables;
    // SAFETY: here we're extending the lifetime of the reference to the KV storage to `'a`.
    // We can't use a raw pointer because we won't be able to use that as input to create an
    // iterator. To ensure safety we must ensure that `self.guard` outlives `self.inner`. We can
    // outlive the temporary because guard holds a pointer to the storage and `tables` follows that
    // pointer (via the `Deref` impl) to the tables field. So even if the temporary is dropped and
    // `result` is moved, `&result.guard.tables` will point at the same address which is guaranteed
    // to outlive `'a`.
    let tables = unsafe { &*tables };
    D::get_table(tables).data.iter()
}
