//! Iterate over a table

use std::{collections::HashSet, hash::Hash, marker::PhantomData};

use crate::{
    Owner,
    operations::{StorageGuard, StorageGuardMut},
    schema::{IndexDesc, TableDesc},
    storage::{Table, TableIterator as InnerIterator, TableIteratorMut as InnerIteratorMut},
    transactions::TxnId,
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

type Indexes<D> =
    Table<<D as IndexDesc>::BaseTable, <<D as IndexDesc>::BaseTable as TableDesc>::Indexes>;

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
    inner: Option<InnerIterator<'guard, D>>,
    _kind: PhantomData<(D, Kind)>,
}

impl<'guard, Guard, D: TableDesc, Kind> TableIterator<'guard, Guard, D, Kind> {
    /// Create an iterator over the table described by `D`.
    pub(crate) fn new(guard: Guard) -> Self
    where
        Guard: StorageGuard<D::Storage> + 'guard,
        D: 'guard,
    {
        let mut result = TableIterator {
            guard,
            inner: None,
            _kind: PhantomData,
        };
        result.inner = Some(inner_iter::<D, Guard>(
            &result.guard,
            result.guard.storage().txn_id(),
        ));
        result
    }

    fn inner_next(&mut self) -> Option<(&'guard D::Key, &'guard D::Value)> {
        self.inner.as_mut().unwrap().next()
    }
}

impl<'guard, Guard: StorageGuard<D::Storage>, D: TableDesc> Iterator
    for TableIterator<'guard, Guard, D, KeysAndValues>
{
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

impl<'guard, Guard: StorageGuard<D::Storage>, D: TableDesc> Iterator
    for TableIterator<'guard, Guard, D, Values>
{
    type Item = &'guard D::Value;

    fn next(&mut self) -> Option<Self::Item> {
        // Iterate by delegating to the `HashMap` iterator.
        self.inner_next().map(|(_, v)| v)
    }
}

impl<'guard, Guard, D: TableDesc, Kind> Drop for TableIterator<'guard, Guard, D, Kind> {
    fn drop(&mut self) {
        // Ensure that `self.inner` is dropped before `self.guard`.
        self.inner = None;
    }
}

/// An iterator giving mutable access to values.
pub struct TableIteratorMut<'guard, Guard: StorageGuardMut<D::Storage> + 'guard, D: TableDesc, Kind>
{
    /// Guard on the KV store's storage (all of it).
    guard: Guard,
    /// An iterator over the `HashMap` representing the table.
    ///
    /// Invariants:
    ///   - `inner.is_some()` once `new` has completed.
    inner: Option<InnerIteratorMut<'guard, D, D::Indexes>>,
    /// Tracks keys of yielded values for rebuilding indexes in `drop`.
    modified: HashSet<D::Key>,
    _kind: PhantomData<(D, Kind)>,
}

impl<'guard, Guard: StorageGuardMut<D::Storage> + 'guard, D: TableDesc, Kind>
    TableIteratorMut<'guard, Guard, D, Kind>
where
    D::Value: Clone,
{
    /// Create an iterator over the table described by `D`.
    pub(crate) fn new(guard: Guard, owner: Owner) -> Self
    where
        D: 'guard,
    {
        let mut result = TableIteratorMut {
            guard,
            inner: None,
            modified: HashSet::new(),
            _kind: PhantomData,
        };
        let txn_id = result.guard.storage().txn_id();
        let max_transaction_id = result.guard.storage().max_committed_id();
        result.inner = Some(inner_iter_mut::<D, Guard>(
            &mut result.guard,
            txn_id,
            max_transaction_id,
            owner,
        ));
        result
    }

    fn inner_next(&mut self) -> Option<(&'guard D::Key, &'guard mut D::Value)> {
        let (k, v) = self.inner.as_mut().unwrap().next()?;
        // The inner iterator has de-indexed this row; record the key for later re-indexing.
        self.modified.insert(k.clone());
        Some((k, v))
    }
}

impl<'guard, Guard: StorageGuardMut<D::Storage>, D: TableDesc, Kind> Drop
    for TableIteratorMut<'guard, Guard, D, Kind>
{
    fn drop(&mut self) {
        let storage = self.guard.storage();
        let txn_id = storage.txn_id();
        let max_transaction_id = storage.max_committed_id();
        let table = D::get_table_mut(&mut storage.tables);
        for k in &self.modified {
            table.rebuild_indexes_for_key(k, txn_id, max_transaction_id);
        }
    }
}

impl<'guard, Guard: StorageGuardMut<D::Storage>, D: TableDesc> Iterator
    for TableIteratorMut<'guard, Guard, D, KeysAndValues>
where
    D::Value: Clone,
{
    type Item = (&'guard D::Key, &'guard mut D::Value);

    fn next(&mut self) -> Option<Self::Item> {
        self.inner_next()
    }
}

impl<'guard, Guard: StorageGuardMut<D::Storage>, D: TableDesc> Iterator
    for TableIteratorMut<'guard, Guard, D, Values>
where
    D::Value: Clone,
{
    type Item = &'guard mut D::Value;

    fn next(&mut self) -> Option<Self::Item> {
        self.inner_next().map(|(_, v)| v)
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
    inner: Option<(&'guard Indexes<D>, InnerIterator<'guard, D>)>,
    _kind: PhantomData<Kind>,
}

impl<'guard, Guard, D: IndexDesc, Kind> IndexIterator<'guard, Guard, D, Kind> {
    /// Create an iterator over the table described by `D` (the index).
    pub(crate) fn new(guard: Guard) -> Self
    where
        Guard: StorageGuard<D::Storage> + 'guard,
        D: 'guard,
    {
        let mut result = IndexIterator {
            guard,
            inner: None,
            _kind: PhantomData,
        };

        let base_table = <D::BaseTable as TableDesc>::get_table(&result.guard.storage().tables);

        result.inner = Some((
            // SAFETY: for the same reasoning as `inner_iter`, we're extending the lifetime of this
            // internal reference to 'guard. This is safe for the same reasons, i.e. we ensure that
            // guard is dropped last.
            unsafe { &*(base_table as *const _) },
            inner_iter::<D, Guard>(&result.guard, result.guard.storage().txn_id()),
        ));

        result
    }
}

impl<'guard, Guard: StorageGuard<D::Storage>, D: IndexDesc> Iterator
    for IndexIterator<'guard, Guard, D, KeysAndValues>
where
    D::Value: Hash + Eq,
{
    type Item = (
        &'guard D::Key,
        &'guard <D::BaseTable as TableDesc>::Key,
        &'guard <D::BaseTable as TableDesc>::Value,
    );

    fn next(&mut self) -> Option<Self::Item> {
        let (base, iter) = self.inner.as_mut().unwrap();
        let (k, bk) = iter.next()?;
        let value = base.get(bk, self.guard.storage().txn_id())?;

        Some((k, bk, value))
    }
}

impl<'guard, Guard, D: IndexDesc> Iterator for IndexIterator<'guard, Guard, D, Keys> {
    type Item = &'guard D::Key;

    fn next(&mut self) -> Option<Self::Item> {
        let (_, iter) = self.inner.as_mut().unwrap();
        iter.next().map(|(k, _)| k)
    }
}

impl<'guard, Guard: StorageGuard<D::Storage>, D: IndexDesc> Iterator
    for IndexIterator<'guard, Guard, D, Values>
where
    D::Value: Hash + Eq,
{
    type Item = (
        &'guard <D::BaseTable as TableDesc>::Key,
        &'guard <D::BaseTable as TableDesc>::Value,
    );

    fn next(&mut self) -> Option<Self::Item> {
        let (base, iter) = self.inner.as_mut().unwrap();
        let (_, bk) = iter.next()?;
        let value = base.get(bk, self.guard.storage().txn_id())?;

        Some((bk, value))
    }
}

impl<'guard, Guard, D: IndexDesc, Kind> Drop for IndexIterator<'guard, Guard, D, Kind> {
    fn drop(&mut self) {
        // Ensure that `self.inner` is dropped before `self.guard`.
        self.inner = None;
    }
}

/// An iterator for an indexed table (described by the generic parameter `D`) in the KV
/// store. Gives mutable access to base table values.
pub struct IndexIteratorMut<'guard, Guard: StorageGuardMut<D::Storage> + 'guard, D: IndexDesc, Kind>
{
    /// Guard on the KV store's storage (all of it).
    guard: Guard,
    /// An iterator over the `HashMap` representing the table.
    ///
    /// Invariants:
    ///   - `inner.is_some()` once `new` has completed.
    inner: Option<(&'guard mut Indexes<D>, InnerIterator<'guard, D>)>,
    modified: HashSet<D::Value>,
    _kind: PhantomData<Kind>,
}

impl<'guard, Guard: StorageGuardMut<D::Storage> + 'guard, D: IndexDesc, Kind>
    IndexIteratorMut<'guard, Guard, D, Kind>
where
    <<D as IndexDesc>::BaseTable as TableDesc>::Value: Clone,
{
    /// Create an iterator over the table described by `D`.
    pub(crate) fn new(guard: Guard, owner: Owner) -> Self
    where
        D: 'guard,
    {
        let mut result = IndexIteratorMut {
            guard,
            inner: None,
            modified: HashSet::new(),
            _kind: PhantomData,
        };
        let txn_id = result.guard.storage().txn_id();

        let base_table = <D::BaseTable as TableDesc>::get_table_mut(
            &mut <Guard as StorageGuardMut<D::Storage>>::storage(&mut result.guard).tables,
        );
        base_table.assert_owner(owner);

        result.inner = Some((
            // SAFETY: for the same reasoning as `inner_iter`, we're extending the lifetime of this
            // internal reference to 'guard. This is safe for the same reasons, i.e. we ensure that
            // guard is dropped last.
            unsafe { &mut *(base_table as *mut _) },
            inner_iter_mut_guard::<D, Guard>(&mut result.guard, txn_id),
        ));
        result
    }

    #[allow(clippy::type_complexity)]
    fn inner_next(
        &mut self,
    ) -> Option<(
        &'guard D::Key,
        &'guard <D::BaseTable as TableDesc>::Key,
        &'guard mut <D::BaseTable as TableDesc>::Value,
    )>
    where
        D::Value: Clone + Hash + Eq,
        <<D as IndexDesc>::BaseTable as TableDesc>::Value: Clone,
    {
        let max_transaction_id = self.guard.storage().max_committed_id();
        let (base, iter) = self.inner.as_mut().unwrap();
        let (k, bk) = iter.next()?;
        // SAFETY: we are making a mutable reference to the base table. The borrow checker does not
        // allow this because in safe code because the lifetime of `value` is the function lifetime
        // rather than `'guard`, due to the lifetime introduced by `as_mut` above. Working around
        // this restriction allows `next` to be called multiple times and get multiple mutable
        // references. This is safe because each call will return a references to a different item
        // in the underlying collection. Furthermore, the extended lifetime `'guard` ensures that
        // the reference does not outlive the guarding lock.
        let base: &'guard mut Indexes<D> = unsafe { &mut *(&mut **base as *mut _) };
        let value = base.get_mut(bk, self.guard.storage().txn_id(), max_transaction_id)?;
        self.modified.insert(bk.clone());

        Some((k, bk, value))
    }
}

impl<'guard, Guard: StorageGuardMut<D::Storage>, D: IndexDesc, Kind> Drop
    for IndexIteratorMut<'guard, Guard, D, Kind>
{
    fn drop(&mut self) {
        let storage = self.guard.storage();
        let txn_id = storage.txn_id();
        let max_transaction_id = storage.max_committed_id();
        let table = <D::BaseTable as TableDesc>::get_table_mut(&mut storage.tables);
        for k in &self.modified {
            table.rebuild_indexes_for_key(k, txn_id, max_transaction_id);
        }
    }
}

impl<'guard, Guard: StorageGuardMut<D::Storage>, D: IndexDesc> Iterator
    for IndexIteratorMut<'guard, Guard, D, KeysAndValues>
where
    D::Value: Clone + Hash + Eq,
    <<D as IndexDesc>::BaseTable as TableDesc>::Value: Clone,
{
    type Item = (
        &'guard D::Key,
        &'guard <D::BaseTable as TableDesc>::Key,
        &'guard mut <D::BaseTable as TableDesc>::Value,
    );

    fn next(&mut self) -> Option<Self::Item> {
        self.inner_next()
    }
}

impl<'guard, Guard: StorageGuardMut<D::Storage>, D: IndexDesc> Iterator
    for IndexIteratorMut<'guard, Guard, D, Values>
where
    D::Value: Clone + Hash + Eq,
    <<D as IndexDesc>::BaseTable as TableDesc>::Value: Clone,
{
    type Item = (
        &'guard <D::BaseTable as TableDesc>::Key,
        &'guard mut <D::BaseTable as TableDesc>::Value,
    );

    fn next(&mut self) -> Option<Self::Item> {
        self.inner_next().map(|(_, bk, v)| (bk, v))
    }
}

// Create an iterator over a table's data to use as a base for the above iterators.
fn inner_iter<'guard, D, Guard>(guard: &Guard, txn_id: TxnId) -> InnerIterator<'guard, D>
where
    D: TableDesc + 'guard,
    Guard: StorageGuard<D::Storage> + 'guard,
{
    let tables: *const _ = &guard.storage().tables;
    // SAFETY: here we're extending the lifetime of the reference to the KV storage to `'guard`.
    // We can't use a raw pointer because we won't be able to use that as input to create an
    // iterator. To ensure safety we must ensure that `self.guard` outlives `self.inner`. We can
    // outlive the temporary because guard holds a pointer to the storage and `tables` follows that
    // pointer (via the `Deref` impl) to the tables field. So even if the temporary is dropped and
    // `result` is moved, `&result.guard.tables` will point at the same address which is guaranteed
    // to outlive `'guard`.
    let tables = unsafe { &*tables };
    D::get_table(tables).iter(txn_id)
}

// Create an immutable iterator from a mutable guard (`StorageGuardMut`).
fn inner_iter_mut_guard<'guard, D, Guard>(
    guard: &mut Guard,
    txn_id: TxnId,
) -> InnerIterator<'guard, D>
where
    D: TableDesc + 'guard,
    Guard: StorageGuardMut<D::Storage> + 'guard,
{
    let tables: *const _ = &mut guard.storage().tables;
    // SAFETY: see `inner_iter`.
    let tables = unsafe { &*tables };
    D::get_table(tables).iter(txn_id)
}

// Create a mutable iterator from a mutable guard.
fn inner_iter_mut<'guard, D, Guard>(
    guard: &mut Guard,
    txn_id: TxnId,
    max_transaction_id: TxnId,
    owner: Owner,
) -> InnerIteratorMut<'guard, D, D::Indexes>
where
    D: TableDesc + 'guard,
    Guard: StorageGuardMut<D::Storage> + 'guard,
{
    let tables: *mut _ = &mut guard.storage().tables;
    // SAFETY: see `inner_iter`.
    let tables = unsafe { &mut *tables };
    let table = D::get_table_mut(tables);
    table.assert_owner(owner);
    table.iter_mut(txn_id, max_transaction_id)
}
