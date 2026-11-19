//! Traits for index implementation.

use core::{any::Any, borrow::Borrow, hash::Hash};

use crate::{Result, transactions::TxnId};

/// Read access to an index which maps keys of type `K` to base table keys of type `B`.
#[doc(hidden)]
pub trait IndexRead<K, B> {
    /// Iterator over the index's key/base key pairs.
    type Iter<'a>: Iterator<Item = (&'a K, &'a B)>
    where
        Self: 'a,
        K: 'a,
        B: 'a;

    /// The base key for `key`, as visible to `txn_id`.
    fn get<Q>(&self, key: &Q, txn_id: TxnId) -> Option<&B>
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq;

    /// Iterate the index, as visible to `txn_id`.
    fn iter(&self, txn_id: TxnId) -> Self::Iter<'_>;

    /// Returns an error if the index is inconsistent (e.g., poisoned).
    fn check_consistent(&self, txn_id: TxnId) -> Result<()>;
}

/// Read access to an index which maps keys of type `K` to zero or more base table keys of type `B`.
#[doc(hidden)]
pub trait MultiIndexRead<K, B> {
    /// Iterator over the base keys for an index key.
    type BaseKeys<'a>: Iterator<Item = &'a B>
    where
        Self: 'a,
        B: 'a;

    /// Iterator over the index's keys and their base keys.
    type Iter<'a>: Iterator<Item = (&'a K, Self::BaseKeys<'a>)>
    where
        Self: 'a,
        K: 'a,
        B: 'a;

    /// The base keys for `key`, as visible to `txn_id`.
    fn get<Q>(&self, key: &Q, txn_id: TxnId) -> Option<Self::BaseKeys<'_>>
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq;

    /// Iterate the index, as visible to `txn_id`.
    fn iter(&self, txn_id: TxnId) -> Self::Iter<'_>;
}

/// Transaction lifecycle operations on the storage of an index which maps keys of type `K` to keys
/// of the base table of type `B`.
#[doc(hidden)]
pub trait IndexLifecycle<K, B> {
    /// Returns an error if transaction `txn_id` cannot be committed.
    fn check_consistent(&self, txn_id: TxnId) -> Result<()>;

    /// Commit transaction `txn_id`.
    fn commit(&mut self, txn_id: TxnId);

    /// Clear the whole index in transaction `txn_id`.
    fn clear(&mut self, txn_id: TxnId);

    /// Rollback transaction `txn_id`. `committed` yields the index key and base key of every entry
    /// as of the last committed transaction.
    fn rollback<'a>(&mut self, txn_id: TxnId, committed: impl Iterator<Item = (K, &'a B)>)
    where
        B: 'a;
}

/// Maintains an index (other than a built-in unique index) as base table rows are added and removed.
#[doc(hidden)]
pub trait BaseKeyWrite<K, B> {
    /// Map `index_key` to `base_key`.
    fn insert_base_key<Q>(&mut self, index_key: K, base_key: &Q, txn_id: TxnId)
    where
        B: Borrow<Q>,
        Q: ?Sized + Eq + ToOwned<Owned = B>;

    /// Remove the mapping from `index_key` to `base_key`, if there is one.
    fn remove_base_key<Q>(&mut self, index_key: &K, base_key: &Q, txn_id: TxnId)
    where
        B: Borrow<Q>,
        Q: ?Sized + Eq;
}

/// Operations on the indexes of a table.
#[doc(hidden)]
pub trait IndexWrite<K: Hash + Eq, V: Any + Send + Sync>: Default {
    /// Whether there are any indexes, i.e., whether the methods of this trait do anything. If
    /// `false`, callers may skip work which only serves to maintain indexes.
    const HAS_INDEXES: bool = true;

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
    const HAS_INDEXES: bool = false;

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

/// A user-implemented index which maps index keys (`K`) to keys of the base table (`B`).
///
/// Custom indexes are not externally versioned: mutations are applied immediately, and the store calls
/// `commit` or `rollback` when the transaction which made them is committed or rolled back. Only
/// one transaction can mutate the store at a time, and readers are excluded while it is live.
///
/// See the docs for the [`store`](crate::store) macro for how to declare a custom index.
pub trait CustomIndex<K: Hash + Eq, B>: Default {
    /// Iterator over the index's key/base key pairs.
    type Iter<'a>: Iterator<Item = (&'a K, &'a B)>
    where
        Self: 'a,
        K: 'a,
        B: 'a;

    /// The base key for `key`, as visible to `txn_id`, if there is one.
    fn get<Q>(&self, key: &Q, txn_id: TxnId) -> Option<&B>
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq;

    /// Iterate the index's key/base key pairs, as visible to `txn_id`.
    fn iter(&self, txn_id: TxnId) -> Self::Iter<'_>;

    /// Map `key` to `base_key` in transaction `txn_id`.
    ///
    /// `key` may already be present in the index (mapped to a different base key). The
    /// implementation may handle this however it likes, e.g., by replacing the existing entry, or
    /// by poisoning the index (see `check_consistent`).
    fn insert(&mut self, key: K, base_key: B, txn_id: TxnId);

    /// Remove `key` from the index in transaction `txn_id`.
    fn remove(&mut self, key: &K, txn_id: TxnId);

    /// Remove all entries from the index in transaction `txn_id`.
    fn clear(&mut self, txn_id: TxnId);

    /// Returns an error if the index, as visible to `txn_id`, is inconsistent (e.g., because it
    /// has non-unique keys).
    ///
    /// Accessing an inconsistent index returns an error or panics, and a transaction cannot be
    /// committed while an index is inconsistent.
    fn check_consistent(&self, txn_id: TxnId) -> Result<()>;

    /// Transaction `txn_id` has been committed.
    fn commit(&mut self, txn_id: TxnId);

    /// Rollback transaction `txn_id`.
    ///
    /// Returns `true` if the transaction could be rolled back. Returning `false` is not considered
    /// an error condition, and implementers may always return false, in which case the store calls
    /// `rebuild`.
    fn rollback(&mut self, txn_id: TxnId) -> bool;

    /// Rebuild the whole index from `data` (the index key and base key of every entry, as of the
    /// last committed transaction). Implementers may choose to clear and reindex, or to do
    /// something more incremental.
    fn rebuild<'a>(&mut self, data: impl Iterator<Item = (K, &'a B)>)
    where
        B: 'a;
}

/// A user-implemented index which maps each index key (`K`) to zero or more keys of the base table
/// (`B`).
///
/// Like [`CustomIndex`], except that the index may have many base keys for each index key, it
/// has the API of a multi-index, and it cannot be inconsistent.
pub trait CustomMultiIndex<K: Hash + Eq, B>: Default {
    /// Iterator over the base keys for an index key.
    type BaseKeys<'a>: Iterator<Item = &'a B>
    where
        Self: 'a,
        B: 'a;

    /// Iterator over the index's keys and their base keys.
    type Iter<'a>: Iterator<Item = (&'a K, Self::BaseKeys<'a>)>
    where
        Self: 'a,
        K: 'a,
        B: 'a;

    /// The base keys for `key`, as visible to `txn_id`, if there are any.
    fn get<Q>(&self, key: &Q, txn_id: TxnId) -> Option<Self::BaseKeys<'_>>
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq;

    /// Iterate the index's keys and their base keys, as visible to `txn_id`.
    fn iter(&self, txn_id: TxnId) -> Self::Iter<'_>;

    /// Add `base_key` to the base keys for `key` in transaction `txn_id`.
    fn insert(&mut self, key: K, base_key: B, txn_id: TxnId);

    /// Remove `base_key` from the base keys for `key` in transaction `txn_id`.
    fn remove<R>(&mut self, key: &K, base_key: &R, txn_id: TxnId)
    where
        B: Borrow<R>,
        R: ?Sized + Eq;

    /// Remove all entries from the index in transaction `txn_id`.
    fn clear(&mut self, txn_id: TxnId);

    /// See [`CustomIndex::commit`].
    fn commit(&mut self, txn_id: TxnId);

    /// See [`CustomIndex::rollback`].
    fn rollback(&mut self, txn_id: TxnId) -> bool;

    /// See [`CustomIndex::rebuild`].
    fn rebuild<'a>(&mut self, data: impl Iterator<Item = (K, &'a B)>)
    where
        B: 'a;
}
