use std::{
    any::Any,
    borrow::Borrow,
    collections::{HashMap, HashSet},
    hash::Hash,
    sync::Arc,
};

use crate::{
    Error, Owner, Result,
    schema::{self, IndexStorage},
    transactions::TxnId,
};

/// Where we store the data.
#[doc(hidden)]
pub struct Storage<TableStorage: schema::GeneratedStorage> {
    /// Storage for tabular data. The concrete type will be macro-generated, see the [`crate::schema`]
    /// module.
    pub(crate) tables: TableStorage,

    /// The id of the most-recently committed transaction.
    pub(crate) committed: TxnId,
    /// `None` if there is no transaction in progress. `Some` if there is a transaction in progress
    /// or a transaction has been aborted without proper rollback. `pending_txn` must not be cleared
    /// until a transaction has been fully committed or fully rolled-back.
    ///
    /// `self.tables` may only contain un-committed state if `pending_txn.is_some()`.
    pending_txn: Option<TxnId>,
    /// Counter for creating new transaction ids.
    next_txn: TxnId,
}

impl<TableStorage: schema::GeneratedStorage> Storage<TableStorage> {
    /// Create a new storage with no data.
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Storage {
            tables: TableStorage::default(),
            committed: TxnId::FIRST,
            pending_txn: None,
            next_txn: TxnId::FIRST.next(),
        }
    }

    /// Returns the transaction id of the current transaction, or the last committed transaction if there
    /// is no current transaction.
    ///
    /// Note that calling this without first ensuring that any aborted transaction has been cleaned
    /// may cause this method to be inaccurate.
    pub(crate) fn txn_id(&self) -> TxnId {
        self.current_txn().unwrap_or(self.committed)
    }

    pub(crate) fn current_txn(&self) -> Option<TxnId> {
        self.pending_txn
    }

    pub(crate) fn max_committed_id(&self) -> TxnId {
        self.committed
    }

    pub(crate) fn insert_singleton<D: schema::Singleton<Storage = TableStorage>>(
        &mut self,
        value: D::ArgValue,
        txn_id: TxnId,
    ) {
        D::field_ref_mut(&mut self.tables).set(D::to_value(value), txn_id);
    }

    pub(crate) fn remove_singleton<D: schema::Singleton<Storage = TableStorage>>(
        &mut self,
        txn_id: TxnId,
    ) {
        D::field_ref_mut(&mut self.tables).set(SinValue::None, txn_id);
    }

    /// Retrieve a singleton value from the store using the given type-key.
    pub(crate) fn get_singleton_value<D: schema::Singleton<Storage = TableStorage>>(
        &self,
        txn_id: TxnId,
    ) -> Option<&D::Value> {
        map_singleton_value(D::field_ref(&self.tables), txn_id, |v| D::from_value_ref(v))
    }

    /// Retrieve a singleton value from the store using the given type-key.
    pub(crate) fn get_singleton_arc<D: schema::ArcSingleton<Storage = TableStorage>>(
        &self,
        txn_id: TxnId,
    ) -> Option<Arc<D::Value>> {
        map_singleton_value(D::field_ref(&self.tables), txn_id, |v| D::from_value_arc(v))
    }

    /// Begin a new transaction. Returns the transactions unique id.
    pub(crate) fn begin_transaction(&mut self) -> TxnId {
        let new_txn_id = self.next_txn;
        self.pending_txn = Some(new_txn_id);
        self.next_txn = new_txn_id.next();
        new_txn_id
    }

    /// Commit a transaction. Returns an error if committing fails, usually because the store's
    /// current transaction does not match the `txn_id` (which should be impossible with only safe
    /// code).
    pub(crate) fn commit_transaction(&mut self, txn_id: TxnId) -> Result<()> {
        let Some(pending_txn) = self.pending_txn else {
            return Err(Error::TransactionFailed);
        };
        if pending_txn != txn_id {
            return Err(Error::TransactionFailed);
        }

        self.tables.commit_txn(txn_id)?;
        self.committed = pending_txn;
        self.pending_txn = None;
        Ok(())
    }

    /// Rollback a transaction. Never returns an error. If `txn_id` does not match the store's current
    /// transaction, then nothing happens (the `txn_id` transaction must already have been committed
    /// or rolled back).
    pub(crate) fn rollback_transaction(&mut self, txn_id: TxnId) {
        let Some(pending_txn) = self.pending_txn else {
            return;
        };
        if pending_txn != txn_id {
            return;
        }

        self.clear_transaction();
    }

    /// Garbage-collects the remnants of any in-progress transaction, leaving the store ready to begin
    /// another transaction or perform raw operations.
    pub(crate) fn clear_transaction(&mut self) {
        if let Some(id) = &self.pending_txn {
            self.tables.gc_txn(*id);
            // Must do this last so it is only cleared if we've successfully GCed the store.
            self.pending_txn = None;
        }
    }
}

/// Internal storage for singleton values.
#[doc(hidden)]
#[derive(Default)]
pub enum SinValue {
    /// Tombstone value.
    #[default]
    None,
    // TODO add other special cases
    /// A single, inline `u64`.
    U64(u64),
    /// A boxed value.
    Box(Box<dyn Any + Send + Sync>),
    /// A shared reference in the store.
    Arc(Arc<dyn Any + Send + Sync>),
    /// A static reference in the store.
    Ref(&'static (dyn Any + Send + Sync)),
}

fn map_singleton_value<'a, T>(
    value: &'a VersionedValue<SinValue>,
    id: TxnId,
    f: impl FnOnce(&'a SinValue) -> T,
) -> Option<T> {
    match &value.get(id)? {
        SinValue::None => None,
        v => Some(f(v)),
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

    /// True if neither slot holds a value.
    fn is_empty(&self) -> bool {
        self.slot_a.is_none() && self.slot_b.is_none()
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

    pub(crate) fn get(&self, id: TxnId) -> Option<&T> {
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

    pub(crate) fn take(&mut self, id: TxnId) -> Option<T> {
        match (&mut self.slot_a, &mut self.slot_b) {
            (Some((aid, a)), Some((bid, b))) if id >= *aid && id >= *bid => {
                debug_assert_ne!(aid, bid);
                if aid > bid {
                    self.slot_a.take().map(|(_, v)| v)
                } else {
                    self.slot_b.take().map(|(_, v)| v)
                }
            }
            (Some((vid, v)), _) if id >= *vid => self.slot_a.take().map(|(_, v)| v),
            (_, Some((vid, v))) if id >= *vid => self.slot_b.take().map(|(_, v)| v),
            _ => None,
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

    fn remove<Q>(&mut self, k: &Q, txn_id: TxnId, data: &HashMap<K, VersionedValue<V>>) -> Option<V>
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
                None
            }
            DeleteMask::All(_, present_rows) => {
                present_rows.remove(k).and_then(|mut v| v.take(txn_id))
            }
            DeleteMask::Some(_, removed) => {
                if present {
                    removed.insert(k.to_owned());
                }
                None
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

    fn insert(&mut self, k: K, v: V, txn_id: TxnId) -> MaskInsertResult<K, V> {
        debug_assert!(self.check_txn_id(txn_id));
        match self {
            DeleteMask::None => MaskInsertResult::NotWritten(k, v),
            DeleteMask::All(_, present) => MaskInsertResult::Written(
                present
                    .insert(k, VersionedValue::new(v, txn_id))
                    .and_then(|mut v| v.take(txn_id)),
            ),
            DeleteMask::Some(_, removed) => {
                removed.remove(&k);
                MaskInsertResult::NotWritten(k, v)
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

/// The result of attempting to write into a delete mask.
enum MaskInsertResult<K, V> {
    /// The field is the key and value which was intended to be written.
    NotWritten(K, V),
    /// The field is the previous value in the delete mask, if there is one.
    Written(Option<V>),
}

/// Tabular data in the KV store, there will be one of these for each logical table in the storage
/// implementing `TableStorage` in [`Storage`].
#[doc(hidden)]
pub struct Table<D: schema::TableDesc, I> {
    /// KV data.
    data: HashMap<D::Key, VersionedValue<D::Value>>,
    /// A mask of deleted rows in the table. Should be checked before reading from `data`.
    delete_mask: DeleteMask<D::Key, D::Value>,
    /// A list of keys modified (includes inserts, but not deletes) by the given transaction.
    ///
    /// Can be an over-approximation, but not an under-approximation.
    modified: Option<TxnMutations<D::Key>>,
    /// A flag indicating if the table has become inconsistent.
    ///
    /// Currently this is used for indexes if multiple primary keys are stored for a single index key.
    poisoned: VersionedValue<bool>,
    /// All indexes of this table (empty if there are no indexes or this table itself is an index).
    pub indexes: I,
}

impl<D: schema::TableDesc, I: Default> Default for Table<D, I> {
    fn default() -> Self {
        Self {
            data: HashMap::new(),
            delete_mask: DeleteMask::None,
            modified: None,
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

        for k in &modified.keys {
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
    /// Must be called before calling `commit_txn`. In theory, because of the global lock, the transaction
    /// should not conflict. But if we were to allow transactions to be timed-out (or multiple
    /// mutating transaction), or in the presence of unsafe code, then inconsistency could happen.
    ///
    /// This will error too if an index has been poisoned during the transaction.
    pub fn check_txn_consistency(&self, txn_id: TxnId) -> Result<()> {
        if let Some(modified) = &self.modified
            && modified.txn_id != txn_id
        {
            return Err(Error::TransactionFailed);
        }

        if self.is_poisoned(txn_id) {
            return Err(crate::Error::NonUniqueIndexKey(D::NAME));
        }

        match &self.delete_mask {
            DeleteMask::All(dm_id, data) if *dm_id == txn_id => Ok(()),
            DeleteMask::Some(dm_id, removed) if *dm_id == txn_id => Ok(()),
            DeleteMask::None => Ok(()),
            _ => Err(Error::TransactionFailed),
        }
    }

    /// Apply this table's transaction state to its storage.
    ///
    /// Precondition: `self.check_txn_consistency` returns `Ok`. (Otherwise, commit may not be atomic).
    ///
    /// Panics if `self.check_txn_consistency` would return an error.
    pub fn commit_txn(&mut self, txn_id: TxnId) {
        if let Some(modified) = &self.modified {
            assert_eq!(modified.txn_id, txn_id);
            self.modified = None;
        }

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
    }

    pub(crate) fn len(&self, txn_id: TxnId) -> usize {
        match &self.delete_mask {
            DeleteMask::None => self.iter_data(txn_id).count(),
            DeleteMask::All(_, pending) => pending.len(),
            // Note that this only works because we take care in `VersionedValue::remove` only to track
            // removals where the value is already in the main data.
            DeleteMask::Some(_, removed) => self.iter_data(txn_id).count() - removed.len(),
        }
    }

    pub(crate) fn is_empty(&self, txn_id: TxnId) -> bool {
        match &self.delete_mask {
            DeleteMask::None => self.iter_data(txn_id).count() == 0,
            DeleteMask::All(_, pending) => pending.is_empty(),
            DeleteMask::Some(..) if self.data.is_empty() => true,
            // Note that this only works because we take care in `VersionedValue::remove` only to track
            // removals where the value is already in the main data.
            DeleteMask::Some(_, removed) => self.iter_data(txn_id).count() - removed.len() == 0,
        }
    }

    pub(crate) fn iter<'a>(&'a self, txn_id: TxnId) -> TableIterator<'a, D> {
        let data = match &self.delete_mask {
            DeleteMask::None | DeleteMask::Some(..) => &self.data,
            DeleteMask::All(_, pending) => pending,
        };

        TableIterator::<D> {
            data: data.iter(),
            delete_mask: &self.delete_mask,
            txn_id,
        }
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
        max_committed_id: TxnId,
    ) -> Option<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = D::Key>,
        D::Value: Clone,
    {
        let value = match self.delete_mask.get_mut(key, txn_id) {
            MaskStatus::Unknown => self.data.get_mut(key)?.internal_clone(txn_id)?,
            MaskStatus::Removed => return None,
            MaskStatus::Overwritten(v) => v,
        };

        self.indexes.on_remove(value, txn_id, max_committed_id);
        record_mutation(&mut self.modified, key, txn_id, max_committed_id);
        let result = f(value);
        self.indexes.on_insert(key, value, txn_id, max_committed_id);
        Some(result)
    }

    fn iter_data(&self, txn_id: TxnId) -> impl Iterator<Item = (&D::Key, &D::Value)> {
        self.data
            .iter()
            .filter_map(move |(k, v)| Some((k, v.get(txn_id)?)))
    }

    fn iter_data_mut(
        data: &mut HashMap<D::Key, VersionedValue<D::Value>>,
        txn_id: TxnId,
    ) -> impl Iterator<Item = (&D::Key, &mut D::Value)>
    where
        D::Value: Clone,
    {
        data.iter_mut()
            .filter_map(move |(k, v)| Some((k, v.internal_clone(txn_id)?)))
    }

    pub(crate) fn for_each_mut(
        &mut self,
        mut f: impl FnMut(&D::Key, &mut D::Value),
        txn_id: TxnId,
        max_committed_id: TxnId,
    ) where
        D::Value: Clone,
    {
        match &mut self.delete_mask {
            DeleteMask::None => {
                self.indexes.clear(txn_id, max_committed_id);
                Self::iter_data_mut(&mut self.data, txn_id).for_each(|(k, v)| {
                    record_mutation(&mut self.modified, k, txn_id, max_committed_id);
                    f(k, v);
                    self.indexes.on_insert(k, v, txn_id, max_committed_id);
                })
            }
            DeleteMask::All(_, pending) => {
                self.indexes.clear(txn_id, max_committed_id);
                pending.iter_mut().for_each(|(k, v)| {
                    if let Some(v) = v.get_mut(txn_id) {
                        record_mutation(&mut self.modified, k, txn_id, max_committed_id);
                        f(k, v);
                        self.indexes.on_insert(k, v, txn_id, max_committed_id);
                    }
                })
            }
            DeleteMask::Some(_, removed) => {
                Self::iter_data_mut(&mut self.data, txn_id).for_each(|(k, v)| {
                    if removed.contains(k) {
                        return;
                    }
                    self.indexes.on_remove(v, txn_id, max_committed_id);
                    record_mutation(&mut self.modified, k, txn_id, max_committed_id);
                    f(k, v);
                    self.indexes.on_insert(k, v, txn_id, max_committed_id);
                })
            }
        }
    }

    pub fn insert(&mut self, key: D::Key, value: D::Value, txn_id: TxnId, max_committed_id: TxnId) {
        if let Some(old_value) =
            get_from_table::<D, D::Key>(&self.delete_mask, &self.data, &key, txn_id)
        {
            self.indexes.on_remove(old_value, txn_id, max_committed_id);
        }
        self.indexes
            .on_insert(&key, &value, txn_id, max_committed_id);

        match self.delete_mask.insert(key, value, txn_id) {
            MaskInsertResult::NotWritten(key, value) => {
                record_mutation(&mut self.modified, &key, txn_id, max_committed_id);
                let entry = self.data.entry(key).or_default();
                entry.set(value, txn_id);
            }
            MaskInsertResult::Written(_) => {}
        }
    }

    pub fn remove<Q>(&mut self, key: &Q, txn_id: TxnId, max_committed_id: TxnId)
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = D::Key>,
    {
        if txn_id > max_committed_id {
            let dm_result = self.delete_mask.remove(key, txn_id, &self.data);
            if let Some(value) = dm_result
                .as_ref()
                .or_else(|| self.data.get(key).and_then(|v| v.get(txn_id)))
            {
                self.indexes.on_remove(value, txn_id, max_committed_id);
            }
        } else {
            unreachable!(
                "current transaction id less than committed id: {txn_id:?} <= {max_committed_id:?}"
            );
        }
    }

    pub fn clear(&mut self, txn_id: TxnId, max_committed_id: TxnId) {
        if txn_id > max_committed_id {
            self.delete_mask.clear(txn_id);
        } else {
            unreachable!(
                "current transaction id less than committed id: {txn_id:?} <= {max_committed_id:?}"
            );
        }

        self.poisoned.set(false, txn_id);

        self.indexes.clear(txn_id, max_committed_id);
    }

    pub(crate) fn assert_owner(&mut self, owner: Owner) {
        debug_assert_eq!(
            D::OWNER,
            owner,
            "Ownership violation: expected {}, found {owner}",
            D::OWNER,
        );
    }
}

// Helper function for `get`, since calling `self.get` can cause lifetime issues.
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

struct TxnMutations<K> {
    txn_id: TxnId,
    keys: Vec<K>,
}

fn record_mutation<K, Q>(
    modified: &mut Option<TxnMutations<K>>,
    key: &Q,
    txn_id: TxnId,
    max_committed_id: TxnId,
) where
    K: Borrow<Q>,
    Q: ?Sized + Hash + Eq + ToOwned<Owned = K>,
{
    if txn_id != max_committed_id {
        let key = key.to_owned();
        match modified {
            Some(modified) => {
                assert_eq!(modified.txn_id, txn_id);
                modified.keys.push(key);
            }
            None => {
                *modified = Some(TxnMutations {
                    txn_id,
                    keys: vec![key],
                });
            }
        }
    }
}

/// Iterate the key-value pairs in a table.
///
/// Takes into account the state of the table as visible to the transaction with id `self.txn_id`.
pub struct TableIterator<'a, D: schema::TableDesc> {
    data: std::collections::hash_map::Iter<'a, D::Key, VersionedValue<D::Value>>,
    delete_mask: &'a DeleteMask<D::Key, D::Value>,
    txn_id: TxnId,
}

impl<'a, D: schema::TableDesc> Iterator for TableIterator<'a, D> {
    type Item = (&'a D::Key, &'a D::Value);

    fn next(&mut self) -> Option<Self::Item> {
        match &self.delete_mask {
            DeleteMask::None | DeleteMask::All(..) => {
                for (k, v) in &mut self.data {
                    if let Some(v) = v.get(self.txn_id) {
                        return Some((k, v));
                    }
                }
                None
            }
            DeleteMask::Some(_, removed) => {
                for (k, v) in &mut self.data {
                    if !removed.contains(k)
                        && let Some(v) = v.get(self.txn_id)
                    {
                        return Some((k, v));
                    }
                }
                None
            }
        }
    }
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

    // take

    #[test]
    fn take_returns_none_when_empty() {
        let mut v: VersionedValue<u32> = VersionedValue::default();
        assert!(v.take(TxnId::new(2)).is_none());
    }

    #[test]
    fn take_returns_and_clears_slot_a() {
        let mut v = VersionedValue {
            slot_a: Some((TxnId::new(2), 42u32)),
            slot_b: None,
        };
        assert_eq!(v.take(TxnId::new(2)), Some(42));
        assert!(v.slot_a.is_none());
    }

    #[test]
    fn take_returns_and_clears_slot_b() {
        let mut v = VersionedValue {
            slot_a: None,
            slot_b: Some((TxnId::new(2), 42u32)),
        };
        assert_eq!(v.take(TxnId::new(2)), Some(42));
        assert!(v.slot_b.is_none());
    }

    #[test]
    fn take_returns_most_recent_and_clears_its_slot() {
        let mut v = VersionedValue {
            slot_a: Some((TxnId::new(3), 10u32)),
            slot_b: Some((TxnId::new(2), 20u32)),
        };
        assert_eq!(v.take(TxnId::new(5)), Some(10));
        assert!(v.slot_a.is_none());
        assert!(v.slot_b.is_some());
    }

    #[test]
    fn take_returns_none_when_id_less_than_slot_id() {
        let mut v = VersionedValue {
            slot_a: Some((TxnId::new(3), 42u32)),
            slot_b: None,
        };
        assert!(v.take(TxnId::new(2)).is_none());
        assert!(v.slot_a.is_some());
    }

    #[test]
    fn take_returns_visible_value_when_one_slot_is_not_visible() {
        let mut v = VersionedValue {
            slot_a: Some((TxnId::new(5), 10u32)),
            slot_b: Some((TxnId::new(2), 20u32)),
        };
        assert_eq!(v.take(TxnId::new(3)), Some(20));
        assert!(v.slot_b.is_none());
        assert!(v.slot_a.is_some());
    }

    // set

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

    use crate::{Error, storage::Storage, store};

    store!(kvs: { Count(u64; "owner") });

    #[test]
    fn commit_with_mismatched_id_fails() {
        let mut storage = Storage::<TableStorage>::new();
        let id = storage.begin_transaction();
        // A commit must target the in-progress transaction.
        assert!(matches!(
            storage.commit_transaction(id.next()),
            Err(Error::TransactionFailed)
        ));
    }

    #[test]
    fn commit_then_recommit_fails() {
        let mut storage = Storage::<TableStorage>::new();
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
        let mut storage = Storage::<TableStorage>::new();
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
