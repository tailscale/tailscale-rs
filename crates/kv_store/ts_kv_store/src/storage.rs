use std::{
    borrow::Borrow,
    collections::{HashMap, HashSet},
    hash::Hash,
    sync::Weak,
};

use crate::{
    Error, Notifier, Result,
    pub_sub::{Notifications, Subscriptions, WatchedEvent},
    schema::{self, IndexStorage, Notifiable, TableDesc},
    transactions::TxnId,
};

/// Where data is actually stored.
#[doc(hidden)]
pub struct Storage<TableStorage: schema::GeneratedStorage> {
    /// Storage for tabular data. The concrete type will be macro-generated, see the [`crate::schema`]
    /// module.
    pub(crate) tables: TableStorage,

    /// The id of the most-recently committed transaction.
    committed: TxnId,
    /// `None` if there is no transaction in progress. `Some` if there is a transaction in progress
    /// or a transaction has been aborted without proper rollback. `pending_txn` must not be cleared
    /// until a transaction has been fully committed or fully rolled-back.
    ///
    /// `self.tables` may only contain un-committed state if `pending_txn.is_some()`.
    pending_txn: Option<TxnId>,
    /// Counter for creating new transaction ids.
    next_txn: TxnId,
    /// Subscription metadata for the store.
    pub(crate) subscriptions: Subscriptions<TableStorage::Notification>,
}

impl<TableStorage: schema::GeneratedStorage> Storage<TableStorage> {
    /// Create a new storage with no data.
    #[allow(clippy::new_without_default)]
    pub fn new(notifier: Weak<dyn Notifier<Notification = TableStorage::Notification>>) -> Self {
        Storage {
            tables: TableStorage::default(),
            committed: TxnId::FIRST,
            pending_txn: None,
            next_txn: TxnId::FIRST.next(),
            subscriptions: Subscriptions::new(notifier),
        }
    }

    /// Returns the transaction id of the current transaction, or the last committed transaction if there
    /// is no current transaction.
    ///
    /// Note that calling this without first ensuring that any aborted transaction has been cleaned
    /// may cause this method to be inaccurate.
    pub(crate) fn txn_id(&self) -> TxnId {
        self.pending_txn.unwrap_or(self.committed)
    }

    pub(crate) fn current_txn(&self) -> Option<TxnId> {
        self.pending_txn
    }

    #[cfg(test)]
    fn insert_singleton<D: schema::SingletonDesc<Storage = TableStorage>>(
        &mut self,
        value: D::Value,
        txn_id: TxnId,
    ) {
        D::get_mut(&mut self.tables).set(Some(value), txn_id);
    }

    #[cfg(test)]
    fn get_singleton_value<D: schema::SingletonDesc<Storage = TableStorage>>(
        &self,
        txn_id: TxnId,
    ) -> Option<&D::Value> {
        D::get_ref(&self.tables).get(txn_id)?.as_ref()
    }

    pub(crate) fn get_singleton_notification_value<
        D: schema::SingletonDesc<Storage = TableStorage>,
    >(
        &self,
        txn_id: TxnId,
    ) -> Option<D::NotificationValue> {
        D::get_cloned(&self.tables, txn_id)
    }

    /// Begin a new transaction. Returns the transaction's unique id.
    pub(crate) fn begin_transaction(&mut self) -> TxnId {
        let new_txn_id = self.next_txn;
        self.pending_txn = Some(new_txn_id);
        self.next_txn = new_txn_id.next();
        new_txn_id
    }

    /// Commit a transaction. Returns an error if committing fails, likely because the store's
    /// current transaction does not match the `txn_id` (which should be impossible with only safe
    /// code).
    pub(crate) fn commit_transaction(
        &mut self,
        txn_id: TxnId,
    ) -> Result<Notifications<TableStorage::Notification>> {
        if self.pending_txn != Some(txn_id) {
            return Err(Error::TransactionFailed);
        }

        let mut notifications = Notifications::default();
        self.tables
            .commit_txn(txn_id, &mut notifications, &self.subscriptions)?;
        self.committed = txn_id;
        self.pending_txn = None;
        Ok(notifications)
    }

    /// Rollback a transaction. Never returns an error. If `txn_id` does not match the store's current
    /// transaction, then nothing happens (the `txn_id` transaction must already have been committed
    /// or rolled back).
    pub(crate) fn rollback_transaction(&mut self, txn_id: TxnId) {
        if self.pending_txn == Some(txn_id) {
            self.clear_transaction();
        }
    }

    /// Clear any in-progress transaction.
    pub(crate) fn clear_transaction(&mut self) {
        if let Some(id) = self.pending_txn {
            self.tables.gc_txn(id);
            self.pending_txn = None;
        }
    }
}

/// An MVCC value with only two versions (versioned by [`TxnId`]).
#[doc(hidden)]
#[derive(Debug)]
pub struct VersionedValue<T> {
    slot_a: Option<(TxnId, T)>,
    slot_b: Option<(TxnId, T)>,
}

impl<T> Default for VersionedValue<T> {
    fn default() -> Self {
        VersionedValue {
            slot_a: None,
            slot_b: None,
        }
    }
}

impl<T: Clone + PartialEq> VersionedValue<Option<T>> {
    /// Pass a mutable reference to the value visible to `txn_id` (if there is one) to `f`.
    ///
    /// Returns `None` (and does not call `f`) if there is no value.
    pub(crate) fn with_mut_value<R>(
        &mut self,
        txn_id: TxnId,
        f: impl FnOnce(&mut T) -> R,
    ) -> Option<R> {
        // Check for a value before cloning: a removed singleton is stored as a `None` in an occupied
        // slot, and cloning that into the free slot would look like a mutation and cause a spurious
        // `Remove` notification.
        self.get(txn_id)?.as_ref()?;

        // If this transaction has already written to the singleton, then it counts as mutated.
        let previously_written = self.modified_in_txn(txn_id).is_some();

        let value = self.internal_clone(txn_id)?.as_mut()?;
        let old_value = (!previously_written).then(|| value.clone());
        let result = f(value);

        if old_value.is_some_and(|old_value| *value == old_value) {
            // `f` left the value alone, so discard the clone.
            self.gc_txn(txn_id);
        }

        Some(result)
    }
}

impl<T> VersionedValue<T> {
    pub(crate) fn new(t: T, id: TxnId) -> Self {
        VersionedValue {
            slot_a: Some((id, t)),
            slot_b: None,
        }
    }

    pub fn gc_txn(&mut self, txn_id: TxnId) {
        if let Some((id, _)) = self.slot_a
            && id == txn_id
        {
            self.slot_a = None;
        }
        if let Some((id, _)) = self.slot_b
            && id == txn_id
        {
            self.slot_b = None;
        }
    }

    /// The value written by `txn_id`, if that transaction wrote to either slot.
    pub fn modified_in_txn(&self, txn_id: TxnId) -> Option<&T> {
        if let Some((id, v)) = &self.slot_a
            && *id == txn_id
        {
            return Some(v);
        }
        if let Some((id, v)) = &self.slot_b
            && *id == txn_id
        {
            return Some(v);
        }
        None
    }

    /// True if neither slot holds a value.
    fn is_empty(&self) -> bool {
        self.slot_a.is_none() && self.slot_b.is_none()
    }

    /// True if either slot holds a value committed before `txn_id` (i.e., from an earlier transaction).
    fn has_prior_value(&self, txn_id: TxnId) -> bool {
        let older = |slot: &Option<(TxnId, T)>| matches!(slot, Some((id, _)) if *id < txn_id);
        older(&self.slot_a) || older(&self.slot_b)
    }

    /// If there is a value visible to `txn_id` in one slot, clone it into the other slot and return
    /// a mutable reference to it.
    fn internal_clone(&mut self, txn_id: TxnId) -> Option<&mut T>
    where
        T: Clone,
    {
        if self.slot_a.is_none() && self.slot_b.is_none() {
            return None;
        }

        // The unpleasantness with `unwrap`s is to work around lifetime issues.
        if let Some((aid, a)) = &mut self.slot_a {
            if txn_id == *aid {
                Some(&mut self.slot_a.as_mut().unwrap().1)
            } else if let Some((bid, b)) = &mut self.slot_b {
                // Use the current transaction's value or the older of the other two (committed) values.
                if txn_id == *bid {
                    Some(&mut self.slot_b.as_mut().unwrap().1)
                } else if aid > bid {
                    debug_assert!(txn_id > *aid && txn_id > *bid);
                    self.slot_b = Some((txn_id, a.clone()));
                    Some(&mut self.slot_b.as_mut().unwrap().1)
                } else {
                    debug_assert!(txn_id > *aid && txn_id > *bid);
                    self.slot_a = Some((txn_id, b.clone()));
                    Some(&mut self.slot_a.as_mut().unwrap().1)
                }
            } else {
                self.slot_b = Some((txn_id, a.clone()));
                Some(&mut self.slot_b.as_mut().unwrap().1)
            }
        } else if let Some((bid, b)) = &mut self.slot_b {
            if txn_id == *bid {
                Some(b)
            } else {
                self.slot_a = Some((txn_id, b.clone()));
                Some(&mut self.slot_a.as_mut().unwrap().1)
            }
        } else {
            unreachable!();
        }
    }

    fn was_mutated<D: TableDesc<Value = T>>(&self) -> bool {
        if self.slot_a.is_none() || self.slot_b.is_none() {
            return false;
        }

        !D::value_eq(
            &self.slot_a.as_ref().unwrap().1,
            &self.slot_b.as_ref().unwrap().1,
        )
    }

    pub fn get(&self, id: TxnId) -> Option<&T> {
        // This could be expressed more simply with a match, but that doesn't work for `get_mut` because
        // of mutable borrows. Since the functions do the same thing, I use the more complex code
        // here too.
        if let Some((aid, a)) = &self.slot_a
            && id >= *aid
        {
            if let Some((bid, b)) = &self.slot_b
                && id >= *bid
            {
                debug_assert_ne!(aid, bid);
                if aid > bid { Some(a) } else { Some(b) }
            } else {
                Some(a)
            }
        } else if let Some((bid, b)) = &self.slot_b
            && id >= *bid
        {
            Some(b)
        } else {
            None
        }
    }

    pub(crate) fn get_mut(&mut self, id: TxnId) -> Option<&mut T> {
        if let Some((aid, a)) = &mut self.slot_a
            && id >= *aid
        {
            if let Some((bid, b)) = &mut self.slot_b
                && id >= *bid
            {
                debug_assert_ne!(aid, bid);
                if aid > bid { Some(a) } else { Some(b) }
            } else {
                Some(a)
            }
        } else if let Some((bid, b)) = &mut self.slot_b
            && id >= *bid
        {
            Some(b)
        } else {
            None
        }
    }

    pub(crate) fn set(&mut self, value: T, id: TxnId) {
        match (&mut self.slot_a, &mut self.slot_b) {
            (Some((vid, v)), _) | (_, Some((vid, v))) if id == *vid => {
                // Overwrite a value from the current transaction.
                *v = value;
            }
            (Some((aid, a)), Some((bid, b))) => {
                // Overwrite the older of two committed values.
                if aid > bid {
                    *b = value;
                    *bid = id;
                } else {
                    *a = value;
                    *aid = id;
                }
            }
            (None, _) => {
                // Write into an empty slot (the other must be committed or also empty).
                self.slot_a = Some((id, value));
            }
            (_, None) => {
                // Write into an empty slot (the other must be committed).
                self.slot_b = Some((id, value));
            }
        }
    }
}

/// Tracks deletes in a transaction without modifying the permanent storage (to allow rollback).
#[derive(Default, Debug)]
enum DeleteMask<K: Hash + Eq, V> {
    /// No delete mask, storage should be accessed directly.
    #[default]
    None,

    /// The whole table has been deleted, the second field contains new key-value pairs.
    ///
    /// The `VersionedValue` will always have a single value with the same transaction id as the first
    /// field. We use this layout so that the delete mask can be committed with a single pointer swap
    /// and so that it can be iterated with the same type of iterator as the main storage.
    All(TxnId, HashMap<K, VersionedValue<V>>),

    /// Some rows in the table have been deleted, tracked in the second field.
    Some(TxnId, HashSet<K>),
}

impl<K: Hash + Eq, V> DeleteMask<K, V> {
    fn check_txn_id(&self, txn_id: TxnId) -> bool {
        match self {
            DeleteMask::None => true,
            DeleteMask::All(self_id, _) | DeleteMask::Some(self_id, _) => *self_id == txn_id,
        }
    }

    fn clear(&mut self, txn_id: TxnId) {
        debug_assert!(self.check_txn_id(txn_id));
        *self = Self::All(txn_id, HashMap::new());
    }

    fn remove<Q>(&mut self, k: &Q, txn_id: TxnId, data: &HashMap<K, VersionedValue<V>>)
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = K>,
    {
        debug_assert!(self.check_txn_id(txn_id));

        // Only record a delete for a key that is actually present (and visible to this transaction).
        let present = data.get(k).and_then(|v| v.get(txn_id)).is_some();

        match self {
            DeleteMask::None => {
                if present {
                    let mut removed: HashSet<K> = HashSet::new();
                    removed.insert(k.to_owned());
                    *self = Self::Some(txn_id, removed);
                }
            }
            DeleteMask::All(_, present_rows) => {
                present_rows.remove(k);
            }
            DeleteMask::Some(_, removed) => {
                if present {
                    removed.insert(k.to_owned());
                }
            }
        }
    }

    fn get<Q>(&self, k: &Q, txn_id: TxnId) -> MaskStatus<&V>
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        debug_assert!(self.check_txn_id(txn_id));
        match self {
            DeleteMask::All(self_id, present) if *self_id == txn_id => match present.get(k) {
                Some(v) => match v.get(txn_id) {
                    Some(v) => MaskStatus::Overwritten(v),
                    None => MaskStatus::Unknown,
                },
                None => MaskStatus::Removed,
            },
            DeleteMask::Some(self_id, removed) if *self_id == txn_id => {
                if removed.contains(k) {
                    MaskStatus::Removed
                } else {
                    MaskStatus::Unknown
                }
            }
            _ => MaskStatus::Unknown,
        }
    }

    fn get_mut<Q>(&mut self, k: &Q, txn_id: TxnId) -> MaskStatus<&mut V>
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        debug_assert!(self.check_txn_id(txn_id));
        match self {
            DeleteMask::None => MaskStatus::Unknown,
            DeleteMask::All(self_id, present) if *self_id == txn_id => match present.get_mut(k) {
                Some(v) => match v.get_mut(txn_id) {
                    Some(v) => MaskStatus::Overwritten(v),
                    None => MaskStatus::Unknown,
                },
                None => MaskStatus::Removed,
            },
            DeleteMask::Some(self_id, removed) if *self_id == txn_id => {
                if removed.contains(k) {
                    MaskStatus::Removed
                } else {
                    MaskStatus::Unknown
                }
            }
            _ => MaskStatus::Unknown,
        }
    }

    /// Write `k` and `v` into the delete mask if the table has been cleared in this transaction.
    ///
    /// Otherwise, returns `k` and `v`, which should be written to the table's main storage.
    fn insert(&mut self, k: K, v: V, txn_id: TxnId) -> Option<(K, V)> {
        debug_assert!(self.check_txn_id(txn_id));
        match self {
            DeleteMask::None => Some((k, v)),
            DeleteMask::All(_, present) => {
                present.insert(k, VersionedValue::new(v, txn_id));
                None
            }
            DeleteMask::Some(_, removed) => {
                removed.remove(&k);
                Some((k, v))
            }
        }
    }
}

/// The status of a row of a table in the delete mask.
enum MaskStatus<T> {
    /// No presence in the delete mask.
    Unknown,
    /// The key has been deleted.
    Removed,
    /// The key has been deleted, then a new value written.
    Overwritten(T),
}

/// Tabular data in the KV store. There will be one of these for each logical table in the concrete
/// impl of `TableStorage`.
#[doc(hidden)]
pub struct Table<D: schema::TableDesc, I> {
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
    /// A flag indicating if the table has become inconsistent.
    ///
    /// Currently this is used for indexes if multiple primary keys are stored for a single index key.
    poisoned: VersionedValue<bool>,
    /// All indexes of this table (empty if there are no indexes or this table is itself an index).
    pub indexes: I,
}

impl<D: schema::TableDesc, I: Default> Default for Table<D, I> {
    fn default() -> Self {
        Self {
            data: HashMap::new(),
            delete_mask: DeleteMask::None,
            modified: None,
            cleared: true,
            poisoned: VersionedValue::new(false, TxnId::FIRST),
            indexes: I::default(),
        }
    }
}

impl<D: schema::TableDesc, I: IndexStorage<D::Key, D::Value>> Table<D, I> {
    pub fn set_poisoned(&mut self, txn_id: TxnId) {
        self.poisoned.set(true, txn_id);
    }

    pub(crate) fn is_poisoned(&self, txn_id: TxnId) -> bool {
        *self.poisoned.get(txn_id).unwrap_or(&false)
    }

    /// Rebuild all indexes for a specific key in this table.
    pub(crate) fn rebuild_indexes_for_key(&mut self, key: &D::Key, txn_id: TxnId) {
        if let Some(v) = get_from_table::<D, D::Key>(&self.delete_mask, &self.data, key, txn_id) {
            self.indexes.on_insert(key, v, txn_id);
        }
    }

    /// Cleanup a rolled-back transaction.
    pub fn gc_txn(&mut self, txn_id: TxnId) {
        self.delete_mask = DeleteMask::None;
        self.poisoned.gc_txn(txn_id);

        let Some(modified) = &self.modified else {
            return;
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
    }

    /// Check if this table's transaction state is consistent for commit.
    ///
    /// Must be called (and succeed) before calling `commit_txn`. Will error if an index has been
    /// poisoned during the transaction. Because of the global lock, the transaction
    /// should not conflict. But if we were to allow transactions to be timed-out (or multiple
    /// mutating transaction), or in the presence of unsafe code, then inconsistency could happen.
    pub fn check_txn_consistency(&self, txn_id: TxnId) -> Result<()> {
        if let Some(modified) = &self.modified
            && modified.txn_id != txn_id
        {
            return Err(Error::TransactionFailed);
        }

        if self.is_poisoned(txn_id) {
            return Err(crate::Error::NonUniqueIndexKey(D::NAME));
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
        D: Notifiable,
    {
        // The modified set is only used for notifications, so don't pay for filtering the mutable
        // refs if there is nobody to notify.
        if !collect_notifications {
            self.commit_without_notifications(txn_id);
            return HashMap::new();
        }

        let modified = self.modified.take().map(|mut m| {
            assert_eq!(m.txn_id, txn_id);
            self.filter_mutated_refs(&mut m.ref_keys);
            m.keys.extend(m.ref_keys);
            m.keys
        });

        let result = match std::mem::take(&mut self.delete_mask) {
            DeleteMask::All(dm_id, data) if dm_id == txn_id => {
                // Only keys which were visible before this transaction can be notifiably removed;
                // a key created and cleared within this transaction was never seen by subscribers.
                let removed: HashSet<_> = self
                    .data
                    .iter()
                    .filter(|(_, v)| v.has_prior_value(txn_id))
                    .map(|(k, _)| k.clone())
                    .collect();
                self.data = data;
                let replaced = self.data.keys().cloned().collect();
                let removed = removed.difference(&replaced).cloned();
                let mut result: HashMap<_, _> = removed.map(|k| (k, WatchedEvent::Clear)).collect();
                let replaced = replaced
                    .into_iter()
                    .map(|k| (k, WatchedEvent::KeyOnlyUpsert));
                result.extend(replaced);
                result
            }
            DeleteMask::Some(dm_id, removed) if dm_id == txn_id => {
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
            _ => unreachable!(),
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
        D: Notifiable,
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
    pub fn commit_without_notifications(&mut self, txn_id: TxnId) {
        match std::mem::take(&mut self.delete_mask) {
            DeleteMask::All(dm_id, data) if dm_id == txn_id => {
                self.data = data;
            }
            DeleteMask::Some(dm_id, removed) if dm_id == txn_id => {
                removed.iter().for_each(|k| {
                    self.data.remove(k);
                });
            }
            DeleteMask::None => {}
            _ => unreachable!(),
        }
        self.modified = None;
        self.cleared = self.data.is_empty();
    }

    /// Takes a set of keys which may have been mutated and removes any keys where the values are unchanged
    /// in the most recent transaction.
    fn filter_mutated_refs(&self, refs: &mut HashSet<D::Key>) {
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
        self.iter(txn_id).count()
    }

    pub(crate) fn is_empty(&self, txn_id: TxnId) -> bool {
        self.iter(txn_id).next().is_none()
    }

    /// Iterate the key-value pairs in the table, as visible to the transaction with id `txn_id`.
    pub(crate) fn iter(&self, txn_id: TxnId) -> impl Iterator<Item = (&D::Key, &D::Value)> {
        let (data, removed) = match &self.delete_mask {
            DeleteMask::None => (&self.data, None),
            DeleteMask::Some(_, removed) => (&self.data, Some(removed)),
            DeleteMask::All(_, pending) => (pending, None),
        };

        data.iter()
            .filter(move |(k, _)| removed.is_none_or(|removed| !removed.contains(*k)))
            .filter_map(move |(k, v)| Some((k, v.get(txn_id)?)))
    }

    /// Get a mutable iterator over the table.
    ///
    /// Each yielded row is recorded as mutated (as it is yielded, so that if the caller panics
    /// while using the iterator, the row is still rolled back). The index entries of each yielded
    /// row are removed (since the row may be mutated), but not rebuilt: the caller must call
    /// `rebuild_indexes_for_key` for every key the iterator yields once it is done with the values.
    pub(crate) fn iter_mut(
        &mut self,
        txn_id: TxnId,
    ) -> impl Iterator<Item = (&D::Key, &mut D::Value)>
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
                indexes.on_remove(v, txn_id);
                Some((k, v))
            })
    }

    pub fn get<Q>(&self, key: &Q, txn_id: TxnId) -> Option<&D::Value>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        if self.is_poisoned(txn_id) {
            return None;
        }
        get_from_table::<D, Q>(&self.delete_mask, &self.data, key, txn_id)
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
        let value = get_from_table_mut::<D, Q>(&mut self.delete_mask, &mut self.data, key, txn_id)?;
        // Recorded before calling `f` so that if `f` panics, the (already cloned) value is still
        // rolled back by `gc_txn`.
        record_mut_ref(&mut self.modified, key, txn_id);
        self.indexes.on_remove(value, txn_id);
        let result = f(value);
        self.indexes.on_insert(key, value, txn_id);
        Some(result)
    }

    pub fn insert(&mut self, key: D::Key, value: D::Value, txn_id: TxnId) {
        if let Some(old_value) =
            get_from_table::<D, D::Key>(&self.delete_mask, &self.data, &key, txn_id)
        {
            self.indexes.on_remove(old_value, txn_id);
        }
        self.indexes.on_insert(&key, &value, txn_id);

        if let Some((key, value)) = self.delete_mask.insert(key, value, txn_id) {
            record_mutation(&mut self.modified, &key, txn_id);
            self.data.entry(key).or_default().set(value, txn_id);
        }
    }

    pub fn remove<Q>(&mut self, key: &Q, txn_id: TxnId)
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = D::Key>,
    {
        // Only the value visible to this transaction is indexed. Any other value for `key` in
        // `self.data` (e.g., if `key` has already been removed in this transaction) may share
        // an index key with a different row, whose index entry must be kept.
        if let Some(value) = get_from_table::<D, Q>(&self.delete_mask, &self.data, key, txn_id) {
            self.indexes.on_remove(value, txn_id);
        }
        self.delete_mask.remove(key, txn_id, &self.data);
    }

    pub fn clear(&mut self, txn_id: TxnId) {
        self.delete_mask.clear(txn_id);
        self.poisoned.set(false, txn_id);
        self.indexes.clear(txn_id);
    }
}

/// Helper function for getting a reference from a table taking into account the delete mask.
///
/// Making this a method could cause lifetime issues.
fn get_from_table<'a, D: schema::TableDesc, Q>(
    delete_mask: &'a DeleteMask<D::Key, D::Value>,
    data: &'a HashMap<D::Key, VersionedValue<D::Value>>,
    key: &Q,
    txn_id: TxnId,
) -> Option<&'a D::Value>
where
    D::Key: Borrow<Q>,
    Q: ?Sized + Hash + Eq,
{
    Some(match delete_mask.get(key, txn_id) {
        MaskStatus::Unknown => data.get(key)?.get(txn_id)?,
        MaskStatus::Removed => return None,
        MaskStatus::Overwritten(v) => v,
    })
}

/// Helper function for getting a mutable reference from a table taking into account the delete mask.
///
/// Making this a method could cause lifetime issues.
fn get_from_table_mut<'a, D: schema::TableDesc, Q>(
    delete_mask: &'a mut DeleteMask<D::Key, D::Value>,
    data: &'a mut HashMap<D::Key, VersionedValue<D::Value>>,
    key: &Q,
    txn_id: TxnId,
) -> Option<&'a mut D::Value>
where
    D::Key: Borrow<Q>,
    D::Value: Clone,
    Q: ?Sized + Hash + Eq,
{
    match delete_mask.get_mut(key, txn_id) {
        MaskStatus::Unknown => data.get_mut(key)?.internal_clone(txn_id),
        MaskStatus::Removed => None,
        MaskStatus::Overwritten(v) => Some(v),
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

fn with_mutations<K>(
    modified: &mut Option<TxnMutations<K>>,
    txn_id: TxnId,
    f: impl FnOnce(&mut TxnMutations<K>),
) {
    let modified = modified.get_or_insert_with(|| TxnMutations {
        txn_id,
        keys: HashSet::new(),
        ref_keys: HashSet::new(),
    });
    assert_eq!(modified.txn_id, txn_id);
    f(modified);
}

fn record_mutation<K, Q>(modified: &mut Option<TxnMutations<K>>, key: &Q, txn_id: TxnId)
where
    K: Borrow<Q> + Hash + Eq,
    Q: ?Sized + Hash + Eq + ToOwned<Owned = K>,
{
    with_mutations(modified, txn_id, |m| {
        m.keys.insert(key.to_owned());
    });
}

fn record_mut_ref<K, Q>(modified: &mut Option<TxnMutations<K>>, key: &Q, txn_id: TxnId)
where
    K: Borrow<Q> + Hash + Eq,
    Q: ?Sized + Hash + Eq + ToOwned<Owned = K>,
{
    with_mutations(modified, txn_id, |m| {
        m.ref_keys.insert(key.to_owned());
    });
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::transactions::TxnId;

    #[test]
    fn get_returns_none_when_empty() {
        let v: VersionedValue<u32> = VersionedValue::default();
        assert!(v.get(TxnId::new(2)).is_none());
    }

    #[test]
    fn get_returns_value_from_slot_a() {
        let v = VersionedValue {
            slot_a: Some((TxnId::new(2), 42u32)),
            slot_b: None,
        };
        assert_eq!(v.get(TxnId::new(2)), Some(&42));
    }

    #[test]
    fn get_returns_value_from_slot_b() {
        let v = VersionedValue {
            slot_a: None,
            slot_b: Some((TxnId::new(2), 42u32)),
        };
        assert_eq!(v.get(TxnId::new(2)), Some(&42));
    }

    #[test]
    fn get_returns_none_when_id_less_than_slot_id() {
        let v = VersionedValue {
            slot_a: Some((TxnId::new(3), 42u32)),
            slot_b: None,
        };
        assert!(v.get(TxnId::new(2)).is_none());
    }

    #[test]
    fn get_returns_most_recent_when_both_slots_visible() {
        let v = VersionedValue {
            slot_a: Some((TxnId::new(3), 10u32)),
            slot_b: Some((TxnId::new(2), 20u32)),
        };
        assert_eq!(v.get(TxnId::new(5)), Some(&10));
    }

    #[test]
    fn get_returns_value_when_id_exceeds_slot_id() {
        let v = VersionedValue {
            slot_a: Some((TxnId::new(2), 42u32)),
            slot_b: None,
        };
        assert_eq!(v.get(TxnId::new(5)), Some(&42));
    }

    #[test]
    fn get_returns_visible_value_when_one_slot_is_not_visible() {
        let v = VersionedValue {
            slot_a: Some((TxnId::new(5), 10u32)),
            slot_b: Some((TxnId::new(2), 20u32)),
        };
        assert_eq!(v.get(TxnId::new(3)), Some(&20));
    }

    #[test]
    fn internal_clone_returns_none_when_empty() {
        let mut v: VersionedValue<u32> = VersionedValue::default();
        assert!(v.internal_clone(TxnId::new(2)).is_none());
    }

    #[test]
    fn internal_clone_copies_committed_value_into_free_slot() {
        let mut v = VersionedValue {
            slot_a: Some((TxnId::new(2), 10u32)),
            slot_b: None,
        };
        *v.internal_clone(TxnId::new(4)).unwrap() = 99;
        // The committed value is left intact so that the transaction can be rolled back.
        assert_eq!(v.slot_a, Some((TxnId::new(2), 10)));
        assert_eq!(v.slot_b, Some((TxnId::new(4), 99)));
    }

    #[test]
    fn internal_clone_reuses_slot_from_same_txn() {
        let mut v = VersionedValue {
            slot_a: Some((TxnId::new(2), 10u32)),
            slot_b: Some((TxnId::new(4), 99u32)),
        };
        *v.internal_clone(TxnId::new(4)).unwrap() += 1;
        assert_eq!(v.slot_a, Some((TxnId::new(2), 10)));
        assert_eq!(v.slot_b, Some((TxnId::new(4), 100)));
    }

    #[test]
    fn internal_clone_overwrites_older_of_two_committed_slots() {
        let mut v = VersionedValue {
            slot_a: Some((TxnId::new(3), 10u32)),
            slot_b: Some((TxnId::new(2), 20u32)),
        };
        // The most recently committed value is the one cloned, and the older one is overwritten.
        *v.internal_clone(TxnId::new(5)).unwrap() = 99;
        assert_eq!(v.slot_a, Some((TxnId::new(3), 10)));
        assert_eq!(v.slot_b, Some((TxnId::new(5), 99)));
    }

    #[test]
    fn set_into_empty_writes_to_slot_a() {
        let mut v: VersionedValue<u32> = VersionedValue::default();
        v.set(42, TxnId::new(2));
        assert_eq!(v.slot_a, Some((TxnId::new(2), 42)));
        assert!(v.slot_b.is_none());
    }

    #[test]
    fn set_overwrites_same_txn_id_in_slot_a() {
        let mut v = VersionedValue {
            slot_a: Some((TxnId::new(2), 1u32)),
            slot_b: None,
        };
        v.set(99, TxnId::new(2));
        assert_eq!(v.slot_a, Some((TxnId::new(2), 99)));
    }

    #[test]
    fn set_overwrites_same_txn_id_in_slot_b() {
        let mut v = VersionedValue {
            slot_a: None,
            slot_b: Some((TxnId::new(2), 1u32)),
        };
        v.set(99, TxnId::new(2));
        assert_eq!(v.slot_b, Some((TxnId::new(2), 99)));
    }

    #[test]
    fn set_overwrites_older_slot_when_both_valid() {
        let mut v = VersionedValue {
            slot_a: Some((TxnId::new(3), 10u32)),
            slot_b: Some((TxnId::new(2), 20u32)),
        };
        v.set(99, TxnId::new(4));
        assert_eq!(v.slot_a, Some((TxnId::new(3), 10)));
        assert_eq!(v.slot_b, Some((TxnId::new(4), 99)));
    }

    #[test]
    fn set_writes_to_empty_slot_a_when_slot_b_populated() {
        let mut v = VersionedValue {
            slot_a: None,
            slot_b: Some((TxnId::new(2), 20u32)),
        };
        v.set(99, TxnId::new(3));
        assert_eq!(v.slot_a, Some((TxnId::new(3), 99)));
        assert_eq!(v.slot_b, Some((TxnId::new(2), 20)));
    }

    #[test]
    fn set_writes_to_slot_b_when_slot_a_populated() {
        let mut v = VersionedValue {
            slot_a: Some((TxnId::new(2), 10u32)),
            slot_b: None,
        };
        v.set(99, TxnId::new(3));
        assert_eq!(v.slot_a, Some((TxnId::new(2), 10)));
        assert_eq!(v.slot_b, Some((TxnId::new(3), 99)));
    }
}

#[cfg(test)]
mod txn_test {
    // The `tables!` macro generates a `KvStore` wrapper, which these storage-level tests
    // (operating on `Storage` directly) do not use.
    #![allow(dead_code)]

    use crate::{Error, pub_sub::NoOpNotifier, storage::Storage, store};

    store!(kvs: { Count(u64; "owner") });

    #[test]
    fn commit_with_mismatched_id_fails() {
        let mut storage =
            Storage::<TableStorage>::new(std::sync::Arc::downgrade(&NoOpNotifier::new()));
        let id = storage.begin_transaction();
        // A commit must target the in-progress transaction.
        assert!(matches!(
            storage.commit_transaction(id.next()),
            Err(Error::TransactionFailed)
        ));
    }

    #[test]
    fn commit_then_recommit_fails() {
        let mut storage =
            Storage::<TableStorage>::new(std::sync::Arc::downgrade(&NoOpNotifier::new()));
        let id = storage.begin_transaction();
        assert!(storage.commit_transaction(id).is_ok());
        // No transaction is pending after a successful commit.
        assert!(matches!(
            storage.commit_transaction(id),
            Err(Error::TransactionFailed)
        ));
    }

    #[test]
    fn clear_transaction_rolls_back_and_frees_singleton_entry() {
        let mut storage =
            Storage::<TableStorage>::new(std::sync::Arc::downgrade(&NoOpNotifier::new()));
        let id = storage.begin_transaction();
        storage.insert_singleton::<Count>(42, id);
        // Visible to the in-progress transaction.
        assert_eq!(storage.get_singleton_value::<Count>(id), Some(&42));

        // Simulate cleanup of an abandoned transaction.
        storage.clear_transaction();

        assert!(storage.current_txn().is_none());
        let now = storage.txn_id();
        assert!(storage.get_singleton_value::<Count>(now).is_none());
    }
}
