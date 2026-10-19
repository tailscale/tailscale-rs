//! Iterate over tables or indexes.

use core::hash::Hash;

use crate::{
    operations::{BaseKey, BaseValue, IndexKey, IndexValue, StorageGuard},
    schema::{IndexDesc, TableDesc},
};

/// Iterate the key/value pairs of the table `D`.
///
/// # Safety
///
/// There must be no live mutable reference to the table described by `D` while the returned
/// iterator is live.
pub(crate) unsafe fn table_iter<D: TableDesc>(
    guard: &impl StorageGuard<D::Storage>,
) -> impl Iterator<Item = (&D::Key, &D::Value)> {
    // SAFETY: by the function's contract.
    unsafe { guard.table::<D>() }.iter(guard.txn_id())
}

/// Iterate the index `D`, yielding each index key with the corresponding base table key, and value.
///
/// # Safety
///
/// There must be no live mutable reference to the tables described by `D` or `D::BaseTable` while
/// the returned iterator is live.
pub(crate) unsafe fn index_iter<D: IndexDesc>(
    guard: &impl StorageGuard<D::Storage>,
) -> impl Iterator<Item = (&IndexKey<D>, &BaseKey<D>, &BaseValue<D>)>
where
    IndexValue<D>: Hash + Eq,
{
    let txn_id = guard.txn_id();
    // SAFETY (for both tables): by the function's contract.
    let base = unsafe { guard.table::<D::BaseTable>() };
    unsafe { guard.table::<D>() }
        .iter(txn_id)
        .filter_map(move |(k, bk)| Some((k, bk, base.get(bk, txn_id)?)))
}
