//! Iterate over tables or indexes.

use core::{hash::Hash, slice};
use std::collections::{HashSet, hash_map};

use crate::{
    operations::{BaseKey, BaseKeyMulti, BaseValue, BaseValueMulti, IndexKey, StorageGuard},
    schema::{IndexDesc, MultiIndexDesc, TableDesc},
    storage::{Table, VersionedValue},
    transactions::TxnId,
};

/// Iterator over the key/value pairs of the table `D`.
pub struct TableIter<'a, D: TableDesc> {
    pub(crate) data: hash_map::Iter<'a, D::Key, VersionedValue<D::Value>>,
    pub(crate) removed: Option<&'a HashSet<D::Key>>,
    pub(crate) txn_id: TxnId,
}

impl<'a, D: TableDesc> Iterator for TableIter<'a, D> {
    type Item = (&'a D::Key, &'a D::Value);

    fn next(&mut self) -> Option<Self::Item> {
        self.data.find_map(|(k, v)| {
            if self.removed.is_some_and(|removed| removed.contains(k)) {
                return None;
            }
            Some((k, v.get(self.txn_id)?))
        })
    }
}

/// Iterator over the index `D`, yielding each index key with the corresponding base table key and
/// value.
pub struct IndexIter<'a, D: IndexDesc> {
    index: TableIter<'a, D>,
    base: &'a Table<D::BaseTable>,
}

impl<'a, D: IndexDesc> Iterator for IndexIter<'a, D>
where
    BaseKey<D>: Hash + Eq,
{
    type Item = (&'a IndexKey<D>, &'a BaseKey<D>, &'a BaseValue<D>);

    fn next(&mut self) -> Option<Self::Item> {
        let txn_id = self.index.txn_id;
        self.index
            .find_map(|(k, bk)| Some((k, bk, self.base.get(bk, txn_id)?)))
    }
}

/// Iterator over the multi-index `D`, yielding each index key with an iterator over the
/// corresponding rows of the base table.
pub struct MultiIndexIter<'a, D: MultiIndexDesc> {
    index: TableIter<'a, D>,
    base: &'a Table<D::BaseTable>,
}

impl<'a, D: MultiIndexDesc> Iterator for MultiIndexIter<'a, D> {
    type Item = (&'a IndexKey<D>, BaseRows<'a, D>);

    fn next(&mut self) -> Option<Self::Item> {
        let (k, base_keys) = self.index.next()?;
        Some((k, BaseRows::new(base_keys, self.base, self.index.txn_id)))
    }
}

/// Iterator over the base table keys and values for a single key of the multi-index `D`.
pub struct BaseRows<'a, D: MultiIndexDesc> {
    keys: slice::Iter<'a, BaseKeyMulti<D>>,
    base: &'a Table<D::BaseTable>,
    txn_id: TxnId,
}

impl<'a, D: MultiIndexDesc> BaseRows<'a, D> {
    pub(crate) fn new(
        keys: &'a [BaseKeyMulti<D>],
        base: &'a Table<D::BaseTable>,
        txn_id: TxnId,
    ) -> Self {
        BaseRows {
            keys: keys.iter(),
            base,
            txn_id,
        }
    }
}

impl<'a, D: MultiIndexDesc> Iterator for BaseRows<'a, D> {
    type Item = (&'a BaseKeyMulti<D>, &'a BaseValueMulti<D>);

    fn next(&mut self) -> Option<Self::Item> {
        self.keys
            .find_map(|k| Some((k, self.base.get(k, self.txn_id)?)))
    }
}

/// Iterate the key/value pairs of the table `D`.
///
/// # Safety
///
/// There must be no live mutable reference to the table described by `D` while the returned
/// iterator is live.
pub(crate) unsafe fn table_iter<D: TableDesc>(
    guard: &impl StorageGuard<D::Storage>,
) -> TableIter<'_, D> {
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
) -> IndexIter<'_, D> {
    // SAFETY (for both tables): by the function's contract.
    IndexIter {
        index: unsafe { table_iter::<D>(guard) },
        base: unsafe { guard.table::<D::BaseTable>() },
    }
}

/// Iterate the multi-index `D`, yielding each index key with an iterator over the corresponding
/// rows of the base table.
///
/// # Safety
///
/// There must be no live mutable reference to the tables described by `D` or `D::BaseTable` while
/// the returned iterator is live.
pub(crate) unsafe fn multi_index_iter<D: MultiIndexDesc>(
    guard: &impl StorageGuard<D::Storage>,
) -> MultiIndexIter<'_, D> {
    // SAFETY (for both tables): by the function's contract.
    MultiIndexIter {
        index: unsafe { table_iter::<D>(guard) },
        base: unsafe { guard.table::<D::BaseTable>() },
    }
}
