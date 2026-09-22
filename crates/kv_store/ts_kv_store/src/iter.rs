//! Iterate over tables and indexes.
//!
//! These functions borrow the store's data via a guard, so the caller must hold a lock on the
//! store for as long as the returned iterators (and their items) are used.

use std::hash::Hash;

use crate::{
    Owner,
    operations::{BaseKey, BaseValue, StorageGuard, StorageGuardMut, assert_owner},
    schema::{IndexDesc, TableDesc},
};

/// Iterate the key/value pairs of the table `D`.
pub(crate) fn table_iter<D: TableDesc>(
    guard: &impl StorageGuard<D::Storage>,
) -> impl Iterator<Item = (&D::Key, &D::Value)> {
    guard.table::<D>().iter(guard.txn_id())
}

/// Iterate the index `D`, yielding each index key with the corrsponding base table key, and value.
pub(crate) fn index_iter<D: IndexDesc>(
    guard: &impl StorageGuard<D::Storage>,
) -> impl Iterator<Item = (&D::Key, &BaseKey<D>, &BaseValue<D>)>
where
    D::Value: Hash + Eq,
{
    let txn_id = guard.txn_id();
    let base = guard.table::<D::BaseTable>();
    guard
        .table::<D>()
        .iter(txn_id)
        .filter_map(move |(k, bk)| Some((k, bk, base.get(bk, txn_id)?)))
}

/// (Possibly) mutating iteration over a table `D`.
///
/// If `f` panics, the panic is caught and the current transaction is rolled-back. Otherwise, indexes
/// are rebuilt when `f` returns.
pub(crate) fn with_table_iter_mut<D, T>(
    guard: &mut impl StorageGuardMut<D::Storage>,
    owner: Owner,
    f: impl for<'a> FnOnce(&mut dyn Iterator<Item = (&'a D::Key, &'a mut D::Value)>) -> T,
) -> T
where
    D: TableDesc,
    D::Value: Clone + PartialEq,
{
    let txn_id = guard.txn_id();
    let table = guard.table_mut::<D>();
    assert_owner(D::OWNER, owner);

    let mut yielded = Vec::new();
    let result = f(&mut table
        .iter_mut(txn_id)
        .inspect(|(k, _)| yielded.push((*k).clone())));

    for k in &yielded {
        table.rebuild_indexes_for_key(k, txn_id);
    }
    result
}
