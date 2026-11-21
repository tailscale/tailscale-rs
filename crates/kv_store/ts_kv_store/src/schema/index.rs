//! Traits for index implementation.

use core::{any::Any, borrow::Borrow, hash::Hash};

use crate::{Result, transactions::TxnId};

/// Operations on the indexes of a table.
#[doc(hidden)]
pub trait IndexWrite<K: Hash + Eq, V: Any + Send + Sync>: Default {
    /// Clear the whole index.
    fn clear(&mut self, txn_id: TxnId);

    /// An item has been inserted into the base table.
    fn on_insert<Q>(&mut self, key: &Q, value: &V, txn_id: TxnId)
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = K>;

    /// An item has been removed from the base table.
    fn on_remove<Q>(&mut self, key: &Q, value: &V, txn_id: TxnId)
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq;
}

impl<K: Hash + Eq, V: Any + Send + Sync> IndexWrite<K, V> for () {
    fn clear(&mut self, _txn_id: TxnId) {}

    fn on_insert<Q>(&mut self, _key: &Q, _value: &V, _txn_id: TxnId)
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
    }

    fn on_remove<Q>(&mut self, _key: &Q, _value: &V, _txn_id: TxnId)
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
    }
}

/// Maintenance of a user-implemented index which maps index keys (`K`) to keys of the base table
/// (`B`), as rows of the base table are inserted and removed. Every custom index implements this
/// trait, plus [`UniqueIndexRead`] or [`MultiIndexRead`] for read access.
///
/// Custom indexes are not externally versioned: mutations are applied immediately, and the store calls
/// `commit` or `rollback` when the transaction which made them is committed or rolled back. Only
/// one transaction can mutate the store at a time, and readers are excluded while it is live.
///
/// See the docs for the [`store`](crate::store) macro for how to declare a custom index.
pub trait IndexMaintenance<K: Hash + Eq, B>: Default {
    /// Map `key` to `base_key` in transaction `txn_id`.
    ///
    /// For a [`UniqueIndexRead`], `key` may already be present in the index (mapped to a different
    /// base key). The implementation may handle this however it likes, e.g., by replacing the
    /// existing entry, or by poisoning the index (see `check_consistent`).
    fn insert(&mut self, key: K, base_key: B, txn_id: TxnId);

    /// Remove the mapping from `key` to `base_key` in transaction `txn_id`.
    ///
    /// For a [`UniqueIndexRead`], `key` must only be removed if it is mapped to `base_key`, since it
    /// may have been replaced by an entry for another row.
    fn remove<R>(&mut self, key: &K, base_key: &R, txn_id: TxnId)
    where
        B: Borrow<R>,
        R: ?Sized + Eq;

    /// Remove all entries from the index in transaction `txn_id`.
    fn clear(&mut self, txn_id: TxnId);

    /// Returns an error if the index, as visible to `txn_id`, is inconsistent (e.g., because it
    /// has non-unique keys).
    ///
    /// Accessing an inconsistent index returns an error or panics, and a transaction cannot be
    /// committed while an index is inconsistent.
    fn check_consistent(&self, _txn_id: TxnId) -> Result<()> {
        Ok(())
    }

    /// Transaction `txn_id` has been committed.
    fn commit(&mut self, txn_id: TxnId);

    /// Rollback transaction `txn_id`.
    ///
    /// `committed` yields the index key and base key of every entry as of the last committed
    /// transaction. The default implementation rebuilds the index from it.
    ///
    /// Only called if the transaction modified the base table.
    fn rollback<'a>(&mut self, txn_id: TxnId, committed: impl Iterator<Item = (K, &'a B)>)
    where
        B: 'a + Clone,
    {
        self.clear(txn_id);
        for (key, base_key) in committed {
            self.insert(key, base_key.clone(), txn_id);
        }
    }
}

/// Read access to a user-implemented index which maps each index key (`K`) to a key of the base
/// table (`B`).
pub trait UniqueIndexRead<K: Hash + Eq, B>: IndexMaintenance<K, B> {
    /// The base key for `key`, as visible to `txn_id`, if there is one.
    fn get<Q>(&self, key: &Q, txn_id: TxnId) -> Option<&B>
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = K>;
}

/// A [`UniqueIndexRead`] which supports iteration.
pub trait UniqueIndexIterable<K: Hash + Eq, B>: UniqueIndexRead<K, B> {
    /// Iterator over the index's key/base key pairs.
    type Iter<'a>: Iterator<Item = (&'a K, &'a B)>
    where
        Self: 'a,
        K: 'a,
        B: 'a;

    /// Iterate the index's key/base key pairs, as visible to `txn_id`.
    fn iter(&self, txn_id: TxnId) -> Self::Iter<'_>;
}

/// Read access to a user-implemented index which maps each index key (`K`) to zero or more keys of
/// the base table (`B`).
///
/// A multi-index should never be inconsistent since it can always handle non-unique index keys.
pub trait MultiIndexRead<K: Hash + Eq, B>: IndexMaintenance<K, B> {
    /// Iterator over the base keys for an index key.
    type BaseKeys<'a>: Iterator<Item = &'a B>
    where
        Self: 'a,
        B: 'a;

    /// The base keys for `key`, as visible to `txn_id`, if there are any.
    fn get<Q>(&self, key: &Q, txn_id: TxnId) -> Option<Self::BaseKeys<'_>>
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = K>;
}

/// A [`MultiIndexRead`] which supports iteration.
pub trait MultiIndexIterable<K: Hash + Eq, B>: MultiIndexRead<K, B> {
    /// Iterator over the index's keys and their base keys.
    type Iter<'a>: Iterator<Item = (&'a K, Self::BaseKeys<'a>)>
    where
        Self: 'a,
        K: 'a,
        B: 'a;

    /// Iterate the index's keys and their base keys, as visible to `txn_id`.
    fn iter(&self, txn_id: TxnId) -> Self::Iter<'_>;
}
