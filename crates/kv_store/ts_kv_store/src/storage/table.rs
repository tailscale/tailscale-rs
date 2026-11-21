use core::{borrow::Borrow, hash::Hash};
use std::collections::{HashMap, HashSet};

use super::{VersionedValue, delete_mask::DeleteMask};
use crate::{
    Error, Result,
    iter::TableIter,
    pub_sub::WatchedEvent,
    schema::{self, PrimaryTableDesc, index::IndexWrite},
    transactions::TxnId,
};

/// Tabular data in the KV store. There will be one of these for each logical table in the concrete
/// impl of `TableStorage`.
#[doc(hidden)]
pub struct Table<D: schema::TableDesc> {
    /// KV data.
    data: HashMap<D::Key, VersionedValue<D::Value>>,
    /// A mask of deleted rows in the table. Should be checked before reading from `data`.
    delete_mask: DeleteMask<D::Key, D::Value>,
    /// Keys modified (includes inserts, but not deletes) by the given transaction.
    modified: Option<TxnMutations<D::Key>>,
    /// True if the table was empty at the start of the current transaction.
    ///
    /// This is maintained by updating it when a transaction is committed. No action is required on
    /// roll-back because `cleared` is not changed during a transaction.
    cleared: bool,
    /// All indexes of this table (empty if there are no indexes or this table is itself an index).
    pub indexes: D::IndexStorage,
}

impl<D: schema::TableDesc> Default for Table<D> {
    fn default() -> Self {
        Self {
            data: HashMap::new(),
            delete_mask: DeleteMask::None,
            modified: None,
            cleared: true,
            indexes: D::IndexStorage::default(),
        }
    }
}

impl<D: schema::TableDesc> Table<D> {
    /// Rebuild all indexes for a specific key in this table.
    fn rebuild_indexes_for_key(&mut self, key: &D::Key, txn_id: TxnId) {
        if let Some(v) = self.delete_mask.lookup(&self.data, key, txn_id) {
            self.indexes.on_insert(key, v, txn_id);
        }
    }

    /// Cleanup a rolled-back transaction.
    ///
    /// Returns `true` if the transaction modified the table (and so may have modified its indexes).
    pub fn gc_txn(&mut self, txn_id: TxnId) -> bool {
        let deleted = !matches!(core::mem::take(&mut self.delete_mask), DeleteMask::None);

        let Some(modified) = &self.modified else {
            return deleted;
        };

        assert_eq!(
            modified.txn_id, txn_id,
            "Found mismatched modified set to GC"
        );

        for k in modified.keys.iter().chain(&modified.ref_keys) {
            if let Some(value) = self.data.get_mut(k) {
                value.gc_txn(txn_id);

                // We don't need to do this, but I think we may as well free up the space.
                if value.is_empty() {
                    self.data.remove(k);
                }
            }
        }

        self.modified = None;
        true
    }

    /// This table's indexes and its rows visible to `txn_id`.
    ///
    /// Ignores any transaction state, so should only be used when there is no pending transaction
    /// (e.g., after `gc_txn`).
    pub fn indexes_and_rows(
        &mut self,
        txn_id: TxnId,
    ) -> (
        &mut D::IndexStorage,
        impl Iterator<Item = (&D::Key, &D::Value)>,
    ) {
        debug_assert!(matches!(self.delete_mask, DeleteMask::None));
        let rows = self
            .data
            .iter()
            .filter_map(move |(k, v)| Some((k, v.get(txn_id)?)));
        (&mut self.indexes, rows)
    }

    /// Check if this table's transaction state is consistent for commit.
    ///
    /// Must be called (and succeed) before calling `commit_primary_table` or
    /// `commit_without_notifications`. Because of the global lock, the transaction
    /// should not conflict. But if we were to allow transactions to be timed-out (or multiple
    /// mutating transaction), or in the presence of unsafe code, then inconsistency could happen.
    pub fn check_txn_consistency(&self, txn_id: TxnId) -> Result<()> {
        if let Some(modified) = &self.modified
            && modified.txn_id != txn_id
        {
            return Err(Error::TransactionFailed);
        }

        if !self.delete_mask.check_txn_id(txn_id) {
            return Err(Error::TransactionFailed);
        }

        Ok(())
    }

    /// Apply this table's transaction state to its storage.
    ///
    /// If `collect_notifications`, returns a record of mutations that occurred during the transaction.
    ///
    /// Precondition: `self.check_txn_consistency` returns `Ok`.
    ///
    /// Panics if `self.check_txn_consistency` would return an error.
    pub fn commit_primary_table(
        &mut self,
        txn_id: TxnId,
        collect_notifications: bool,
    ) -> HashMap<D::Key, WatchedEvent<D::NotificationValue>>
    where
        D: PrimaryTableDesc,
    {
        // The modified set is only used for notifications, so don't pay for filtering the mutable
        // refs if there is nobody to notify.
        if !collect_notifications {
            self.commit_without_notifications(txn_id);
            return HashMap::new();
        }

        assert!(self.delete_mask.check_txn_id(txn_id));

        let modified = self.modified.take().map(|mut m| {
            assert_eq!(m.txn_id, txn_id);
            self.filter_mutated_refs(&mut m.ref_keys);
            m.keys.extend(m.ref_keys);
            m.keys
        });

        let result = match core::mem::take(&mut self.delete_mask) {
            DeleteMask::All(_, data) => {
                // Only keys which were visible before this transaction can be notifiably removed;
                // a key created and cleared within this transaction was never seen by subscribers.
                let mut result: HashMap<_, _> = self
                    .data
                    .iter()
                    .filter(|(k, v)| v.has_prior_value(txn_id) && !data.contains_key(*k))
                    .map(|(k, _)| (k.clone(), WatchedEvent::Clear))
                    .collect();
                result.extend(
                    data.keys()
                        .map(|k| (k.clone(), WatchedEvent::KeyOnlyUpsert)),
                );
                self.data = data;
                result
            }
            DeleteMask::Some(_, removed) => {
                let mut modified = modified.unwrap_or_default();
                let mut result: HashMap<_, _> = removed
                    .into_iter()
                    .filter_map(|k| {
                        modified.remove(&k);
                        let value = self.data.remove(&k)?;
                        // A key which was both created and removed within this transaction was
                        // never visible to subscribers, so its removal is not a notifiable event.
                        value
                            .has_prior_value(txn_id)
                            .then_some((k, WatchedEvent::Remove))
                    })
                    .collect();
                result.extend(modified.into_iter().map(|k| self.upsert_event(k, txn_id)));
                result
            }
            DeleteMask::None => {
                let Some(modified) = modified else {
                    return HashMap::new();
                };

                if self.cleared {
                    modified
                        .into_iter()
                        .map(|k| (k, WatchedEvent::KeyOnlyUpsert))
                        .collect()
                } else {
                    modified
                        .into_iter()
                        .map(|k| self.upsert_event(k, txn_id))
                        .collect()
                }
            }
        };

        self.cleared = self.data.is_empty();

        result
    }

    /// Create an upsert event for `key`.
    ///
    /// Panics if a value for `key` is not present at `txn_id`.
    fn upsert_event(
        &self,
        key: D::Key,
        txn_id: TxnId,
    ) -> (D::Key, WatchedEvent<D::NotificationValue>)
    where
        D: PrimaryTableDesc,
    {
        let value = self.data.get(&key).unwrap().get(txn_id).unwrap();
        let value = D::clone_value_for_notification(value);
        (key, WatchedEvent::Upsert(value))
    }

    /// Apply this table's transaction state to its storage without collecting notifications.
    ///
    /// Precondition: `self.check_txn_consistency` returns `Ok`.
    ///
    /// Panics if `self.check_txn_consistency` would return an error.
    pub(crate) fn commit_without_notifications(&mut self, txn_id: TxnId) {
        assert!(self.delete_mask.check_txn_id(txn_id));

        match core::mem::take(&mut self.delete_mask) {
            DeleteMask::All(_, data) => {
                self.data = data;
            }
            DeleteMask::Some(_, removed) => {
                removed.iter().for_each(|k| {
                    self.data.remove(k);
                });
            }
            DeleteMask::None => {}
        }
        self.modified = None;
        self.cleared = self.data.is_empty();
    }

    /// Takes a set of keys which may have been mutated and removes any keys where the values are unchanged
    /// in the most recent transaction.
    fn filter_mutated_refs(&self, refs: &mut HashSet<D::Key>)
    where
        D: PrimaryTableDesc,
    {
        match &self.delete_mask {
            DeleteMask::None => {}
            DeleteMask::All(..) => {
                refs.clear();
                return;
            }
            DeleteMask::Some(_, removed_keys) => {
                refs.retain(|k| !removed_keys.contains(k));
            }
        }

        refs.retain(|k| {
            self.data
                .get(k)
                .map(|vv| vv.was_mutated::<D>())
                .unwrap_or(false)
        });
    }

    pub(crate) fn len(&self, txn_id: TxnId) -> usize {
        match &self.delete_mask {
            // In this case, we can ignore the main data and just count the new data in the delete mask.
            DeleteMask::All(dm_id, pending) if *dm_id == txn_id => pending.len(),
            _ => self.iter(txn_id).count(),
        }
    }

    pub(crate) fn is_empty(&self, txn_id: TxnId) -> bool {
        self.iter(txn_id).next().is_none()
    }

    /// Iterate the key-value pairs in the table, as visible to the transaction with id `txn_id`.
    pub(crate) fn iter(&self, txn_id: TxnId) -> TableIter<'_, D> {
        let (data, removed) = match &self.delete_mask {
            DeleteMask::None => (&self.data, None),
            DeleteMask::Some(_, removed) => (&self.data, Some(removed)),
            DeleteMask::All(_, pending) => (pending, None),
        };

        TableIter {
            data: data.iter(),
            removed,
            txn_id,
        }
    }

    /// Get a mutable iterator over the table.
    ///
    /// Each yielded row is recorded as mutated (as it is yielded, so that if the caller panics
    /// while using the iterator, the row is still rolled back). The index entries of each yielded
    /// row are removed (since the row may be mutated), but not rebuilt: the caller must call
    /// `rebuild_indexes_for_key` for every key the iterator yields once it is done with the values.
    fn iter_mut(&mut self, txn_id: TxnId) -> impl Iterator<Item = (&D::Key, &mut D::Value)>
    where
        D::Value: Clone + PartialEq,
    {
        debug_assert!(self.delete_mask.check_txn_id(txn_id));

        let (data, removed) = match &mut self.delete_mask {
            DeleteMask::None => (self.data.iter_mut(), None),
            DeleteMask::Some(_, removed) => (self.data.iter_mut(), Some(&*removed)),
            DeleteMask::All(_, pending) => (pending.iter_mut(), None),
        };
        let indexes = &mut self.indexes;
        let modified = &mut self.modified;

        data.filter(move |(k, _)| removed.is_none_or(|removed| !removed.contains(*k)))
            .filter_map(move |(k, v)| {
                let v = v.internal_clone(txn_id)?;
                // Recorded before handing out the value so that it is rolled back by `gc_txn` even
                // if the caller panics while using it.
                record_mut_ref(modified, k, txn_id);
                indexes.on_remove(k, v, txn_id);
                Some((k, v))
            })
    }

    /// Pass a mutable iterator over the table to `f`.
    ///
    /// The index entries of every row `f` visits are rebuilt once `f` returns, so `f` may
    /// (temporarily) give rows duplicate index keys.
    pub(crate) fn with_iter_mut<T>(
        &mut self,
        txn_id: TxnId,
        f: impl for<'a> FnOnce(&mut dyn Iterator<Item = (&'a D::Key, &'a mut D::Value)>) -> T,
    ) -> T
    where
        D::Value: Clone + PartialEq,
    {
        self.with_iter_mut_and_remove(txn_id, |iter, _| f(iter))
    }

    /// Remove every row for which `f` returns `false`.
    pub(crate) fn retain(
        &mut self,
        mut f: impl FnMut(&D::Key, &mut D::Value) -> bool,
        txn_id: TxnId,
    ) where
        D::Value: Clone + PartialEq,
    {
        self.with_iter_mut_and_remove(txn_id, |iter, removed| {
            for (k, v) in iter {
                if !f(k, v) {
                    removed.push(k.clone());
                }
            }
        });
    }

    /// Pass a mutable iterator over the table to `f`, then remove the rows whose keys `f` pushes
    /// onto its second argument, then rebuild the index entries of the remaining rows `f` visited.
    fn with_iter_mut_and_remove<T>(
        &mut self,
        txn_id: TxnId,
        f: impl for<'a> FnOnce(
            &mut dyn Iterator<Item = (&'a D::Key, &'a mut D::Value)>,
            &mut Vec<D::Key>,
        ) -> T,
    ) -> T
    where
        D::Value: Clone + PartialEq,
    {
        let mut removed = Vec::new();
        let mut yielded = Vec::new();
        let result = f(
            &mut self
                .iter_mut(txn_id)
                .inspect(|(k, _)| yielded.push((*k).clone())),
            &mut removed,
        );

        // `iter_mut` has removed the index entries of every row it yielded. Removed rows must not
        // go through `Table::delete`, which would remove their (possibly mutated) index keys a
        // second time, and those might now belong to another row.
        for k in &removed {
            self.delete_mask.remove(k, txn_id, &self.data);
        }
        // Removed rows are no longer visible, so this does not rebuild their index entries.
        for k in &yielded {
            self.rebuild_indexes_for_key(k, txn_id);
        }
        result
    }

    pub fn get<Q>(&self, key: &Q, txn_id: TxnId) -> Option<&D::Value>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        self.delete_mask.lookup(&self.data, key, txn_id)
    }

    pub(crate) fn with_mut<Q, T>(
        &mut self,
        key: &Q,
        f: impl FnOnce(&mut D::Value) -> T,
        txn_id: TxnId,
    ) -> Option<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = D::Key>,
        D::Value: Clone + PartialEq,
    {
        let value = self.delete_mask.lookup_mut(&mut self.data, key, txn_id)?;
        // Recorded before calling `f` so that if `f` panics, the (already cloned) value is still
        // rolled back by `gc_txn`.
        record_mut_ref(&mut self.modified, key, txn_id);
        self.indexes.on_remove(key, value, txn_id);
        let result = f(value);
        self.indexes.on_insert(key, value, txn_id);
        Some(result)
    }

    pub(crate) fn insert(&mut self, key: D::Key, value: D::Value, txn_id: TxnId) {
        // Before touching the indexes, so that `gc_txn` rolls them back if they panic.
        mutations(&mut self.modified, txn_id);
        if let Some(old_value) = self.delete_mask.lookup(&self.data, &key, txn_id) {
            self.indexes.on_remove(&key, old_value, txn_id);
        }
        self.indexes.on_insert(&key, &value, txn_id);

        if let Some((key, value)) = self.delete_mask.insert(key, value, txn_id) {
            record_mutation(&mut self.modified, &key, txn_id);
            self.data.entry(key).or_default().set(value, txn_id);
        }
    }

    pub(crate) fn delete<Q>(&mut self, key: &Q, txn_id: TxnId)
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = D::Key>,
    {
        // Before touching the indexes, so that `gc_txn` rolls them back if they panic.
        mutations(&mut self.modified, txn_id);
        // Only the value visible to this transaction is indexed. Any other value for `key` in
        // `self.data` (e.g., if `key` has already been removed in this transaction) may share
        // an index key with a different row, whose index entry must be kept.
        if let Some(value) = self.delete_mask.lookup(&self.data, key, txn_id) {
            self.indexes.on_remove(key, value, txn_id);
        }
        self.delete_mask.remove(key, txn_id, &self.data);
    }

    pub(crate) fn clear(&mut self, txn_id: TxnId) {
        self.delete_mask.clear(txn_id);
        self.indexes.clear(txn_id);
    }
}

struct TxnMutations<K> {
    txn_id: TxnId,
    keys: HashSet<K>,
    // Keys where we've returned a mutable reference to that key to the user. We don't know for sure
    // if the corresponding value was modified, so we'll check at commit time for notifications.
    // For indexing, we'll just assume they've been modified. For rollback, we need to rollback
    // whether or not the value was mutated because we will have cloned the value in any case.
    ref_keys: HashSet<K>,
}

/// The mutations recorded for `txn_id`, creating an empty record if there is none.
fn mutations<K>(modified: &mut Option<TxnMutations<K>>, txn_id: TxnId) -> &mut TxnMutations<K> {
    let modified = modified.get_or_insert_with(|| TxnMutations {
        txn_id,
        keys: HashSet::new(),
        ref_keys: HashSet::new(),
    });
    assert_eq!(modified.txn_id, txn_id);
    modified
}

fn record_mutation<K, Q>(modified: &mut Option<TxnMutations<K>>, key: &Q, txn_id: TxnId)
where
    K: Borrow<Q> + Hash + Eq,
    Q: ?Sized + Hash + Eq + ToOwned<Owned = K>,
{
    mutations(modified, txn_id).keys.insert(key.to_owned());
}

fn record_mut_ref<K, Q>(modified: &mut Option<TxnMutations<K>>, key: &Q, txn_id: TxnId)
where
    K: Borrow<Q> + Hash + Eq,
    Q: ?Sized + Hash + Eq + ToOwned<Owned = K>,
{
    mutations(modified, txn_id).ref_keys.insert(key.to_owned());
}
