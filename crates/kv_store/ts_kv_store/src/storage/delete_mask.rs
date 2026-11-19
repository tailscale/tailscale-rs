use core::{borrow::Borrow, hash::Hash};
use std::collections::{HashMap, HashSet};

use super::VersionedValue;
use crate::transactions::TxnId;

/// Tracks deletes in a transaction without modifying the permanent storage (to allow rollback).
#[derive(Default, Debug)]
pub(super) enum DeleteMask<K: Hash + Eq, V> {
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
    pub(super) fn check_txn_id(&self, txn_id: TxnId) -> bool {
        match self {
            DeleteMask::None => true,
            DeleteMask::All(self_id, _) | DeleteMask::Some(self_id, _) => *self_id == txn_id,
        }
    }

    pub(super) fn clear(&mut self, txn_id: TxnId) {
        debug_assert!(self.check_txn_id(txn_id));
        *self = Self::All(txn_id, HashMap::new());
    }

    pub(super) fn remove<Q>(&mut self, k: &Q, txn_id: TxnId, data: &HashMap<K, VersionedValue<V>>)
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
                    *self = Self::Some(txn_id, HashSet::from([k.to_owned()]));
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

    /// Get the value for `k` visible to `txn_id`, from the delete mask if `k` is in it, otherwise
    /// from the table's main storage, `data`.
    pub(super) fn lookup<'a, Q>(
        &'a self,
        data: &'a HashMap<K, VersionedValue<V>>,
        k: &Q,
        txn_id: TxnId,
    ) -> Option<&'a V>
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        debug_assert!(self.check_txn_id(txn_id));
        match self {
            DeleteMask::All(self_id, present) if *self_id == txn_id => present.get(k)?.get(txn_id),
            DeleteMask::Some(self_id, removed) if *self_id == txn_id && removed.contains(k) => None,
            _ => data.get(k)?.get(txn_id),
        }
    }

    /// Like `lookup`, but if the value is in the table's main storage, it is cloned into
    /// `txn_id`'s slot (see `VersionedValue::internal_clone`).
    pub(super) fn lookup_mut<'a, Q>(
        &'a mut self,
        data: &'a mut HashMap<K, VersionedValue<V>>,
        k: &Q,
        txn_id: TxnId,
    ) -> Option<&'a mut V>
    where
        K: Borrow<Q>,
        V: Clone,
        Q: ?Sized + Hash + Eq,
    {
        debug_assert!(self.check_txn_id(txn_id));
        match self {
            DeleteMask::All(self_id, present) if *self_id == txn_id => {
                present.get_mut(k)?.get_mut(txn_id)
            }
            DeleteMask::Some(self_id, removed) if *self_id == txn_id && removed.contains(k) => None,
            _ => data.get_mut(k)?.internal_clone(txn_id),
        }
    }

    /// Write `k` and `v` into the delete mask if the table has been cleared in this transaction.
    ///
    /// Otherwise, returns `k` and `v`, which should be written to the table's main storage.
    pub(super) fn insert(&mut self, k: K, v: V, txn_id: TxnId) -> Option<(K, V)> {
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
