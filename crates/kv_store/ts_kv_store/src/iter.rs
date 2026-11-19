//! Iterate over tables or indexes.

use std::collections::{HashSet, hash_map};

use crate::{
    operations::{BaseKey, BaseValue, IndexKey, StorageGuard},
    schema::{
        MultiIndexDesc, PrimaryTableDesc, TableDesc, UniqueIndexDesc,
        index::{IndexRead, MultiIndexRead},
    },
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
pub struct IndexIter<'a, D: UniqueIndexDesc> {
    index: <D::IndexStorage as IndexRead<IndexKey<D>, BaseKey<D>>>::Iter<'a>,
    base: &'a Table<D::BaseTable>,
    txn_id: TxnId,
}

impl<'a, D: UniqueIndexDesc> Iterator for IndexIter<'a, D> {
    type Item = (&'a IndexKey<D>, &'a BaseKey<D>, &'a BaseValue<D>);

    fn next(&mut self) -> Option<Self::Item> {
        self.index
            .find_map(|(k, bk)| Some((k, bk, self.base.get(bk, self.txn_id)?)))
    }
}

/// Iterator over the multi-index `D`, yielding each index key with an iterator over the
/// corresponding rows of the base table.
pub struct MultiIndexIter<'a, D: MultiIndexDesc> {
    index: <D::IndexStorage as MultiIndexRead<IndexKey<D>, BaseKey<D>>>::Iter<'a>,
    base: &'a Table<D::BaseTable>,
    txn_id: TxnId,
}

impl<'a, D: MultiIndexDesc> Iterator for MultiIndexIter<'a, D> {
    type Item = (&'a IndexKey<D>, BaseRows<'a, D>);

    fn next(&mut self) -> Option<Self::Item> {
        let (k, base_keys) = self.index.next()?;
        Some((k, BaseRows::new(base_keys, self.base, self.txn_id)))
    }
}

/// Iterator over the base table keys and values for a single key of the multi-index `D`.
pub struct BaseRows<'a, D: MultiIndexDesc> {
    keys: <D::IndexStorage as MultiIndexRead<IndexKey<D>, BaseKey<D>>>::BaseKeys<'a>,
    base: &'a Table<D::BaseTable>,
    txn_id: TxnId,
}

impl<'a, D: MultiIndexDesc> BaseRows<'a, D> {
    pub(crate) fn new(
        keys: <D::IndexStorage as MultiIndexRead<IndexKey<D>, BaseKey<D>>>::BaseKeys<'a>,
        base: &'a Table<D::BaseTable>,
        txn_id: TxnId,
    ) -> Self {
        BaseRows { keys, base, txn_id }
    }
}

impl<'a, D: MultiIndexDesc> Iterator for BaseRows<'a, D> {
    type Item = (&'a BaseKey<D>, &'a BaseValue<D>);

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
pub(crate) unsafe fn table_iter<D: PrimaryTableDesc>(
    guard: &impl StorageGuard<D::Storage>,
) -> TableIter<'_, D> {
    // SAFETY: by the function's contract.
    unsafe { guard.table::<D>() }.iter(guard.txn_id())
}

/// Iterate the index `D`, yielding each index key with the corresponding base table key, and value.
///
/// # Safety
///
/// There must be no live mutable reference to the index described by `D` or to `D::BaseTable`
/// while the returned iterator is live.
pub(crate) unsafe fn index_iter<D: UniqueIndexDesc>(
    guard: &impl StorageGuard<D::Storage>,
) -> IndexIter<'_, D> {
    let txn_id = guard.txn_id();
    // SAFETY (for the index and the table): by the function's contract.
    IndexIter {
        index: unsafe { guard.index::<D>() }.iter(txn_id),
        base: unsafe { guard.table::<D::BaseTable>() },
        txn_id,
    }
}

/// Iterate the multi-index `D`, yielding each index key with an iterator over the corresponding
/// rows of the base table.
///
/// # Safety
///
/// There must be no live mutable reference to the index described by `D` or to `D::BaseTable`
/// while the returned iterator is live.
pub(crate) unsafe fn multi_index_iter<D: MultiIndexDesc>(
    guard: &impl StorageGuard<D::Storage>,
) -> MultiIndexIter<'_, D> {
    let txn_id = guard.txn_id();
    // SAFETY (for the index and the table): by the function's contract.
    MultiIndexIter {
        index: unsafe { guard.index::<D>() }.iter(txn_id),
        base: unsafe { guard.table::<D::BaseTable>() },
        txn_id,
    }
}
