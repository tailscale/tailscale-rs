//! KvStore transactional API.
//!
//! Most of the implementation of transactions is in the [`storage`](crate::storage) module.

use std::{
    borrow::Borrow,
    cell::UnsafeCell,
    hash::Hash,
    num::NonZeroU64,
    sync::{Arc, RwLockReadGuard, RwLockWriteGuard, TryLockError},
};

use crate::{
    KvStore, Owner, Result,
    index::{KvTableRoTransactionalIndex, KvTableTransactionalIndex},
    operations::{Ops, OpsMut, SingletonOps, SingletonOpsMut, TabularOps, TabularOpsMut},
    schema::{self, TableDesc},
    storage::Storage,
};

/// Uniquely identifies a transaction.
///
/// Guaranteed to be non-zero so that `size_of::<Option<TxnId>>() == size_of::<TxnId>()`.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct TxnId(NonZeroU64);

impl TxnId {
    pub(crate) const FIRST: Self = TxnId(NonZeroU64::new(1).unwrap());

    pub(crate) fn next(self) -> Self {
        TxnId(self.0.checked_add(1).unwrap())
    }

    #[cfg(test)]
    pub(crate) fn new(n: u64) -> Self {
        TxnId(NonZeroU64::new(n).unwrap())
    }
}

impl<TableStorage: schema::GeneratedStorage> KvStore<TableStorage> {
    /// Start a transaction.
    ///
    /// Blocks until the store's global lock is available for write access.
    pub fn begin_transaction(&self, owner: Owner) -> Transaction<'_, TableStorage> {
        let mut guard = self.get_write_lock();
        let id = guard.begin_transaction();

        Transaction {
            guard,
            owner,
            id,
            _not_send_or_sync: UnsafeCell::new(()),
        }
    }

    /// Start a transaction.
    ///
    /// Returns `None` if the store's global lock is unavailable for write access.
    pub fn try_begin_transaction(&self, owner: Owner) -> Option<Transaction<'_, TableStorage>> {
        self.clear_lock_poison();
        let mut guard = match self.storage.try_write() {
            Ok(g) => g,
            Err(TryLockError::WouldBlock) => return None,
            Err(TryLockError::Poisoned(_)) => panic!(),
        };

        // Garbage-collect any abandoned transaction before starting a new one (matches the blocking
        // `begin_transaction`, which goes through `get_write_lock`).
        guard.clear_transaction();
        let id = guard.begin_transaction();

        Some(Transaction {
            guard,
            owner,
            id,
            _not_send_or_sync: UnsafeCell::new(()),
        })
    }

    /// Start a read-only transaction (i.e., only supports non-mutating access to the store, but
    /// all reads are guaranteed to be atomic).
    ///
    /// Blocks until the store's global lock is available for read access.
    pub fn begin_ro_transaction(&self, owner: Owner) -> RoTransaction<'_, TableStorage> {
        let guard = self.get_read_lock();

        RoTransaction { guard, owner }
    }

    /// Start a read-only transaction (i.e., only supports non-mutating access to the store, but
    /// all reads are guaranteed to be atomic).
    ///
    /// Returns `None` if the store's global lock is unavailable for read access.
    pub fn try_begin_ro_transaction(
        &self,
        owner: Owner,
    ) -> Option<RoTransaction<'_, TableStorage>> {
        self.clear_lock_poison();
        let guard = match self.storage.try_read() {
            Ok(g) => g,
            Err(TryLockError::WouldBlock) => return None,
            Err(TryLockError::Poisoned(_)) => panic!(),
        };

        // Fast path: no abandoned transaction to clean up.
        if guard.current_txn().is_none() {
            return Some(RoTransaction { guard, owner });
        }

        // Otherwise garbage-collect the abandoned transaction under a write lock before reading
        // (matches the blocking `begin_ro_transaction`, which goes through `get_read_lock`).
        drop(guard);
        let mut wguard = match self.storage.try_write() {
            Ok(g) => g,
            Err(TryLockError::WouldBlock) => return None,
            Err(TryLockError::Poisoned(_)) => panic!(),
        };
        wguard.clear_transaction();
        drop(wguard);

        let guard = match self.storage.try_read() {
            Ok(g) => g,
            Err(TryLockError::WouldBlock) => return None,
            Err(TryLockError::Poisoned(_)) => panic!(),
        };
        Some(RoTransaction { guard, owner })
    }

    // TODO single-table transactions?
}

/// A read/write transaction over a [`KvStore`].
///
/// Create a transaction by calling [`KvStore::begin_transaction`] or [`KvStore::try_begin_transaction`].
/// A transaction holds a write lock on the whole store while it is active so ensure that code within
/// a transaction is relatively quick to execute and that you drop transactions as soon as possible
/// ([`Transaction::commit`] can be used for this).
///
/// A transaction must not be kept alive over an `await` point. This can lead to deadlock.
pub struct Transaction<'guard, TableStorage: schema::GeneratedStorage> {
    pub(crate) guard: RwLockWriteGuard<'guard, Storage<TableStorage>>,
    pub(crate) owner: Owner,
    id: TxnId,
    // Enforce the transaction is not `Send` or `Sync` so that it isn't accidentally held over an
    // await point (at least with a parallel async runtime), etc.
    _not_send_or_sync: UnsafeCell<()>,
}

impl<'guard, TableStorage: schema::GeneratedStorage> Drop for Transaction<'guard, TableStorage> {
    fn drop(&mut self) {
        self.guard.rollback_transaction(self.id);
    }
}

impl<'guard, 'a, TableStorage: schema::GeneratedStorage> Ops<TableStorage>
    for &'a Transaction<'guard, TableStorage>
{
    type ReadLock = &'a RwLockWriteGuard<'guard, Storage<TableStorage>>;

    fn read_lock(self) -> Self::ReadLock {
        &self.guard
    }
}

impl<TableStorage: schema::GeneratedStorage> SingletonOps<TableStorage>
    for &Transaction<'_, TableStorage>
{
}

impl<'guard, 'a, TableStorage: schema::GeneratedStorage> OpsMut<TableStorage>
    for &'a mut Transaction<'guard, TableStorage>
{
    type WriteLock = &'a mut RwLockWriteGuard<'guard, Storage<TableStorage>>;

    fn write_lock(self) -> Self::WriteLock {
        &mut self.guard
    }
}

impl<TableStorage: schema::GeneratedStorage> SingletonOpsMut<TableStorage>
    for &mut Transaction<'_, TableStorage>
{
}

impl<'guard, TableStorage: schema::GeneratedStorage> Transaction<'guard, TableStorage> {
    /// Commit this transaction.
    ///
    /// This simply moves and drops the `Transaction` object. It is optional to call and currently
    /// always succeeds. You can use this method to release the transaction's lock on the store
    /// without needing an explicit scope.
    pub fn commit(mut self) -> Result<()> {
        self.guard.commit_transaction(self.id)
        // drop `self` to release the lock.
    }

    /// Operate on tables of key/values in the store.
    ///
    /// Example:
    /// ```rust,ignore
    /// let txn = store.begin_ro_transaction(OWNER);
    /// let value = txn.table::<Foo>().get(key).unwrap();
    /// ```
    pub fn table<D: TableDesc<Storage = TableStorage>>(
        &mut self,
    ) -> KvTableTransactional<'guard, '_, D> {
        KvTableTransactional { txn: self }
    }

    /// Access a table via an index.
    ///
    /// # Example:
    ///
    /// ```rust,ignore
    /// let txn = store.begin_ro_transaction(OWNER);
    /// let value = txn.table_by::<index::Foo::bar>(OWNER).get(foreign_key).unwrap();
    /// ```
    ///
    /// Here `Foo` describes a tables and `bar` describes an index over `Foo` using the `bar` field
    /// as foreign key.
    pub fn table_by<D: schema::IndexDesc<Storage = TableStorage>>(
        &mut self,
    ) -> KvTableTransactionalIndex<'guard, '_, D> {
        KvTableTransactionalIndex { txn: self }
    }

    /// Get a single value from the store by cloning the value.
    ///
    /// Returns `None` if there is no value for the specified key.
    pub fn get<D: schema::Singleton>(&self) -> Option<D::Value>
    where
        D::Value: Clone,
    {
        <&Self as SingletonOps<_>>::get::<D>(self, self.owner)
    }

    /// Get a single value from the store by cloning an `Arc`.
    ///
    /// Returns `None` if there is no value for the specified key. Panics if the value is not an `Arc`.
    pub fn get_arc<D: schema::ArcSingleton>(&self) -> Option<Arc<D::Value>> {
        <&Self as SingletonOps<_>>::get_arc::<D>(self, self.owner)
    }

    /// Get immutable access to a value in the store by reference.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    pub fn with<D: schema::Singleton, T>(&self, f: impl FnOnce(&D::Value) -> T) -> Option<T> {
        <&Self as SingletonOps<_>>::with::<D, T>(self, f, self.owner)
    }

    /// Insert a single value into the store.
    ///
    /// Returns the previous value if there is one, or `None` if there is no value for the specified key.
    // Question: do we need separate insert/update/upsert methods?
    pub fn insert<D: schema::Singleton>(&mut self, value: D::ArgValue) {
        <&mut Self as SingletonOpsMut<_>>::insert::<D>(self, value, self.owner)
    }

    /// Remove a single value from the store.
    ///
    /// Returns the previous value if there is one, or `None` if there is no value for the specified key.
    pub fn remove<D: schema::Singleton>(&mut self) {
        <&mut Self as SingletonOpsMut<_>>::remove::<D>(self, self.owner)
    }
}

/// Abstracts a table of key/values pairs in the store accessed as part of a transaction.
pub struct KvTableTransactional<'guard, 'txn, D: TableDesc> {
    txn: &'txn mut Transaction<'guard, D::Storage>,
}

impl<'guard, 'txn, 'table, D: TableDesc> Ops<D::Storage>
    for &'table KvTableTransactional<'guard, 'txn, D>
{
    type ReadLock = &'table RwLockWriteGuard<'guard, Storage<D::Storage>>;

    fn read_lock(self) -> Self::ReadLock {
        &self.txn.guard
    }
}

impl<'guard, 'txn, 'table, D: TableDesc> OpsMut<D::Storage>
    for &'table mut KvTableTransactional<'guard, 'txn, D>
{
    type WriteLock = &'table mut RwLockWriteGuard<'guard, Storage<D::Storage>>;

    fn write_lock(self) -> Self::WriteLock {
        &mut self.txn.guard
    }
}

impl<'guard, D: TableDesc> TabularOps<D::Storage> for &KvTableTransactional<'guard, '_, D> {
    type TableDesc = D;
}

impl<'guard, D: TableDesc> TabularOpsMut<D::Storage> for &mut KvTableTransactional<'guard, '_, D> {
    type TableDesc = D;
}

impl<'guard, D: TableDesc> KvTableTransactional<'guard, '_, D> {
    /// Initialize a table by setting its owner.
    ///
    /// Calling this function is optional, a table can be used without initialization in which case,
    /// its owner is set to the owner specified in the first write.
    ///
    /// Returns an error (containing the current owner of the table) if the table has already been
    /// initialized. In this case, the table will be in a consistent state and can be used as normal.
    pub fn init(&mut self) -> Result<()> {
        <&mut Self as TabularOpsMut<_>>::init(self, self.txn.owner)
    }

    /// The number of key/value pairs in the table.
    pub fn len(&self) -> usize {
        <&Self as TabularOps<_>>::len(self)
    }

    /// True if the table is empty.
    pub fn is_empty(&self) -> bool {
        <&Self as TabularOps<_>>::is_empty(self)
    }

    /// Clear a table by removing all its KVs, but preserving ownership.
    pub fn clear(&mut self) {
        <&mut Self as TabularOpsMut<_>>::clear(self, self.txn.owner)
    }

    /// Get a row of the table from the store by cloning the value.
    ///
    /// Returns `None` if there is no value for the specified key.
    pub fn get<Q>(&self, key: &Q) -> Option<D::Value>
    where
        D::Value: Clone,
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        <&Self as TabularOps<_>>::get::<Q>(self, key, self.txn.owner)
    }

    /// Get immutable access to a row of the table in the store by reference.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    pub fn with<Q, T>(&self, key: &Q, f: impl FnOnce(&D::Value) -> T) -> Option<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        <&Self as TabularOps<_>>::with::<Q, T>(self, key, f, self.txn.owner)
    }

    /// Insert a value into the table.
    ///
    /// Returns the previous value if there is one, or `None` if there is no value for the specified key.
    pub fn insert(&mut self, key: D::Key, value: D::Value)
    where
        D::Key: Clone,
    {
        <&mut Self as TabularOpsMut<_>>::insert(self, key, value, self.txn.owner)
    }

    /// Get mutable access to a row of the table in the store in the store.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    pub fn with_mut<Q, T>(&mut self, key: &Q, f: impl FnOnce(&mut D::Value) -> T) -> Option<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = D::Key>,
        D::Value: Clone,
    {
        <&mut Self as TabularOpsMut<_>>::with_mut(self, key, f, self.txn.owner)
    }

    /// Remove a row from the table.
    ///
    /// Returns the previous value if there is one, or `None` if there is no value for the specified key.
    pub fn remove<Q>(&mut self, key: &Q)
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = D::Key>,
    {
        <&mut Self as TabularOpsMut<_>>::remove(self, key, self.txn.owner)
    }

    /// Iterate all the key/value pairs in a table.
    pub fn iter(&self) -> impl Iterator<Item = (&D::Key, &D::Value)> {
        <&Self as TabularOps<_>>::iter(self, self.txn.owner)
    }

    /// Iterate all the keys in a table.
    pub fn keys(&self) -> impl Iterator<Item = &D::Key> {
        <&Self as TabularOps<_>>::keys(self, self.txn.owner)
    }

    /// Iterate all the values in a table.
    pub fn values(&self) -> impl Iterator<Item = &D::Value> {
        <&Self as TabularOps<_>>::values(self, self.txn.owner)
    }

    /// Iterate all the key/value pairs in a table. Values are mutable.
    pub fn for_each_mut(&mut self, f: impl FnMut(&D::Key, &mut D::Value))
    where
        D::Value: Clone,
    {
        <&mut Self as TabularOpsMut<_>>::for_each_mut(self, f, self.txn.owner)
    }
}

/// A read-only transaction over a [`KvStore`].
///
/// Create a read-only transaction by calling [`KvStore::begin_ro_transaction`] or [`KvStore::try_begin_ro_transaction`].
/// A read-only transaction holds a read lock on the whole store while it is active so ensure that
/// code within a transaction is relatively quick to execute and that you drop transactions as soon
/// as possible([`RoTransaction::commit`] can be used for this).
///
/// A transaction must not be kept alive over an `await` point. This can lead to deadlock.
pub struct RoTransaction<'guard, TableStorage: schema::GeneratedStorage> {
    pub(crate) guard: RwLockReadGuard<'guard, Storage<TableStorage>>,
    pub(crate) owner: Owner,
}

impl<'guard, 'txn, TableStorage: schema::GeneratedStorage> Ops<TableStorage>
    for &'txn RoTransaction<'guard, TableStorage>
{
    type ReadLock = &'txn RwLockReadGuard<'guard, Storage<TableStorage>>;

    fn read_lock(self) -> Self::ReadLock {
        &self.guard
    }
}

impl<'guard, TableStorage: schema::GeneratedStorage> SingletonOps<TableStorage>
    for &RoTransaction<'guard, TableStorage>
{
}

impl<'guard, 'txn, D: TableDesc> Ops<D::Storage> for &'_ KvTableRoTransactional<'guard, 'txn, D> {
    type ReadLock = &'txn RwLockReadGuard<'guard, Storage<D::Storage>>;

    fn read_lock(self) -> Self::ReadLock {
        &self.txn.guard
    }
}

impl<'guard, D: TableDesc> TabularOps<D::Storage> for &KvTableRoTransactional<'guard, '_, D> {
    type TableDesc = D;
}

impl<'guard, TableStorage: schema::GeneratedStorage> RoTransaction<'guard, TableStorage> {
    /// Commit this transaction.
    ///
    /// This simply moves and drops the `RoTransaction` object. It is optional to call and currently
    /// always succeeds. You can use this method to release the transaction's lock on the store
    /// without needing an explicit scope.
    pub fn commit(self) -> Result<()> {
        // drop `self` to release the lock.
        Ok(())
    }

    /// Operate on tables of key/values in the store.
    ///
    /// Example:
    /// ```rust,ignore
    /// let txn = store.begin_ro_transaction(OWNER);
    /// let value = txn.table::<Foo>().get(key).unwrap();
    /// ```
    pub fn table<D: TableDesc<Storage = TableStorage>>(
        &self,
    ) -> KvTableRoTransactional<'guard, '_, D> {
        KvTableRoTransactional { txn: self }
    }

    /// Access a table via an index.
    ///
    /// # Example:
    ///
    /// ```rust,ignore
    /// let txn = store.begin_ro_transaction(OWNER);
    /// let value = txn.table_by::<index::Foo::bar>(OWNER).get(foreign_key).unwrap();
    /// ```
    ///
    /// Here `Foo` describes a tables and `bar` describes an index over `Foo` using the `bar` field
    /// as foreign key.
    pub fn table_by<D: schema::IndexDesc<Storage = TableStorage>>(
        &self,
    ) -> KvTableRoTransactionalIndex<'guard, '_, D> {
        KvTableRoTransactionalIndex { txn: self }
    }

    /// Get a single value from the store by cloning the value.
    ///
    /// Returns `None` if there is no value for the specified key.
    pub fn get<D: schema::Singleton>(&self) -> Option<D::Value>
    where
        D::Value: Clone,
    {
        <&Self as SingletonOps<_>>::get::<D>(self, self.owner)
    }

    /// Get a single value from the store by cloning an `Arc`.
    ///
    /// Returns `None` if there is no value for the specified key. Panics if the value is not an `Arc`.
    pub fn get_arc<D: schema::ArcSingleton>(&self) -> Option<Arc<D::Value>> {
        <&Self as SingletonOps<_>>::get_arc::<D>(self, self.owner)
    }

    /// Get immutable access to a value in the store by reference.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    pub fn with<D: schema::Singleton, T>(&self, f: impl FnOnce(&D::Value) -> T) -> Option<T> {
        <&Self as SingletonOps<_>>::with::<D, T>(self, f, self.owner)
    }
}

/// Abstracts a table of key/values pairs in the store as part of a read-only transaction.
pub struct KvTableRoTransactional<'guard, 'txn, D: TableDesc> {
    txn: &'txn RoTransaction<'guard, D::Storage>,
}

impl<'guard, D: TableDesc> KvTableRoTransactional<'guard, '_, D> {
    /// The number of key/value pairs in the table.
    pub fn len(&self) -> usize {
        <&Self as TabularOps<_>>::len(self)
    }

    /// True if the table is empty.
    pub fn is_empty(&self) -> bool {
        <&Self as TabularOps<_>>::is_empty(self)
    }

    /// Get a row of the table from the store by cloning the value.
    ///
    /// Returns `None` if there is no value for the specified key.
    pub fn get<Q>(&self, key: &Q) -> Option<D::Value>
    where
        D::Value: Clone,
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        <&Self as TabularOps<_>>::get::<Q>(self, key, self.txn.owner)
    }

    /// Get immutable access to a row of the table in the store by reference.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    pub fn with<Q, T>(&self, key: &Q, f: impl FnOnce(&D::Value) -> T) -> Option<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        <&Self as TabularOps<_>>::with::<Q, T>(self, key, f, self.txn.owner)
    }

    /// Iterate all the key/value pairs in a table.
    pub fn iter(&self) -> impl Iterator<Item = (&D::Key, &D::Value)>
    where
        D: 'guard,
    {
        <&Self as TabularOps<_>>::iter(self, self.txn.owner)
    }

    /// Iterate all the keys in a table.
    pub fn keys(&self) -> impl Iterator<Item = &D::Key>
    where
        D: 'guard,
    {
        <&Self as TabularOps<_>>::keys(self, self.txn.owner)
    }

    /// Iterate all the values in a table.
    pub fn values(&self) -> impl Iterator<Item = &D::Value>
    where
        D: 'guard,
    {
        <&Self as TabularOps<_>>::values(self, self.txn.owner)
    }
}

#[cfg(test)]
mod test {
    use std::{any::Any, sync::Arc};

    use crate::{Error, singleton, tables};

    singleton!(Count(u64));
    singleton!(Shared(String as Arc));

    tables!(Items(&'static str => String), Counters(u32 => u64));

    const OWNER: &str = "owner";
    #[cfg(debug_assertions)]
    const OTHER: &str = "other";

    #[test]
    fn begin_transaction_works() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.insert::<Count>(42);
        assert_eq!(txn.get::<Count>(), Some(42));
    }

    #[test]
    fn try_begin_transaction_returns_some_when_unlocked() {
        let store = KvStore::new();
        assert!(store.try_begin_transaction(OWNER).is_some());
    }

    #[test]
    fn begin_ro_transaction_works() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 7);
        let txn = store.begin_ro_transaction(OWNER);
        assert_eq!(txn.get::<Count>(), Some(7));
    }

    #[test]
    fn try_begin_ro_transaction_returns_some_when_unlocked() {
        let store = KvStore::new();
        assert!(store.try_begin_ro_transaction(OWNER).is_some());
    }

    #[test]
    fn try_begin_transaction_after_commit_sees_committed() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.insert::<Count>(7);
        txn.commit().unwrap();

        let txn = store.try_begin_transaction(OWNER).unwrap();
        assert_eq!(txn.get::<Count>(), Some(7));
    }

    #[test]
    fn try_begin_transaction_after_rollback_sees_pre_txn() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.insert::<Count>(2);
            // dropped without commit -> rolled back
        }
        let txn = store.try_begin_transaction(OWNER).unwrap();
        assert_eq!(txn.get::<Count>(), Some(1));
    }

    #[test]
    fn try_begin_ro_transaction_after_commit_sees_committed() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.insert::<Count>(7);
        txn.commit().unwrap();

        let txn = store.try_begin_ro_transaction(OWNER).unwrap();
        assert_eq!(txn.get::<Count>(), Some(7));
    }

    #[test]
    fn try_begin_ro_transaction_after_rollback_sees_pre_txn() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.insert::<Count>(2);
        }
        let txn = store.try_begin_ro_transaction(OWNER).unwrap();
        assert_eq!(txn.get::<Count>(), Some(1));
    }

    #[test]
    fn txn_get_returns_none_when_absent() {
        let store = KvStore::new();
        let txn = store.begin_transaction(OWNER);
        assert!(txn.get::<Count>().is_none());
    }

    #[test]
    fn txn_get_returns_value_inserted_in_same_txn() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.insert::<Count>(42);
        assert_eq!(txn.get::<Count>(), Some(42));
    }

    #[test]
    fn txn_get_returns_value_inserted_before_txn() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 5);
        let txn = store.begin_transaction(OWNER);
        assert_eq!(txn.get::<Count>(), Some(5));
    }

    #[test]
    fn txn_get_arc_returns_none_when_absent() {
        let store = KvStore::new();
        let txn = store.begin_transaction(OWNER);
        assert!(txn.get_arc::<Shared>().is_none());
    }

    #[test]
    fn txn_get_arc_returns_arc_after_insert() {
        let store = KvStore::new();
        store.insert::<Shared>(OWNER, Arc::new("hello".to_owned()));
        let txn = store.begin_transaction(OWNER);
        let arc = txn.get_arc::<Shared>().unwrap();
        assert_eq!(*arc, "hello");
    }

    #[test]
    fn txn_get_arc_shares_allocation() {
        let store = KvStore::new();
        store.insert::<Shared>(OWNER, Arc::new("hello".to_owned()));
        let txn = store.begin_transaction(OWNER);
        let arc1 = txn.get_arc::<Shared>().unwrap();
        let arc2 = txn.get_arc::<Shared>().unwrap();
        assert!(Arc::ptr_eq(&arc1, &arc2));
    }

    #[test]
    fn txn_with_returns_none_and_does_not_call_f_when_absent() {
        let store = KvStore::new();
        let txn = store.begin_transaction(OWNER);
        let mut called = false;
        let result = txn.with::<Count, ()>(|_| {
            called = true;
        });
        assert!(result.is_none());
        assert!(!called);
    }

    #[test]
    fn txn_with_returns_result_of_f() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.insert::<Count>(5);
        assert_eq!(txn.with::<Count, _>(|v| v * 2), Some(10));
    }

    #[test]
    fn txn_remove_makes_get_return_none() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.insert::<Count>(1);
        txn.remove::<Count>();
        assert!(txn.get::<Count>().is_none());
    }

    #[test]
    fn txn_writes_visible_after_drop() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.insert::<Count>(42);
        txn.commit().unwrap();

        assert_eq!(store.get::<Count>(OWNER), Some(42));
    }

    #[test]
    fn txn_table_writes_visible_after_drop() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Items>().insert("k", "v".to_owned());
        txn.commit().unwrap();

        assert_eq!(store.table::<Items>(OWNER).get("k"), Some("v".to_owned()));
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Ownership violation")]
    fn txn_insert_wrong_owner_panics() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        let mut txn = store.begin_transaction(OTHER);
        txn.insert::<Count>(5);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Ownership violation")]
    fn txn_remove_wrong_owner_panics() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        let mut txn = store.begin_transaction(OTHER);
        txn.remove::<Count>();
    }

    #[test]
    fn txn_table_init_succeeds() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let mut table = txn.table::<Items>();
        assert!(table.init().is_ok());
    }

    #[test]
    fn txn_table_init_second_call_err() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let mut table = txn.table::<Items>();
        table.init().unwrap();
        let err = table.init().unwrap_err();
        assert!(matches!(err, Error::AlreadyInit(o) if o == OWNER));
    }

    #[test]
    fn txn_table_get_returns_none_when_absent() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let table = txn.table::<Items>();
        assert!(table.get("missing").is_none());
    }

    #[test]
    fn txn_table_get_returns_value_after_insert() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let mut table = txn.table::<Items>();
        table.insert("k", "val".to_owned());
        assert_eq!(table.get("k"), Some("val".to_owned()));
    }

    #[test]
    fn txn_table_with_returns_none_and_does_not_call_f_when_absent() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let table = txn.table::<Items>();
        let mut called = false;
        let result = table.with("missing", |_| {
            called = true;
        });
        assert!(result.is_none());
        assert!(!called);
    }

    #[test]
    fn txn_table_with_returns_some_after_insert() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let mut table = txn.table::<Items>();
        table.insert("k", "val".to_owned());
        assert_eq!(table.with("k", |s| s.len()), Some(3));
    }

    #[test]
    fn txn_table_mutate_returns_none_when_absent() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let mut table = txn.table::<Items>();
        table.init().unwrap();
        assert!(table.with_mut(&"missing", |v| v.len()).is_none());
    }

    #[test]
    fn txn_table_mutate_modifies_value() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let mut table = txn.table::<Items>();
        table.insert("k", "hello".to_owned());
        table.with_mut(&"k", |v| v.push('!'));
        assert_eq!(table.get("k"), Some("hello!".to_owned()));
    }

    #[test]
    fn txn_table_remove_makes_get_return_none() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let mut table = txn.table::<Items>();
        table.insert("k", "v".to_owned());
        table.remove(&"k");
        assert!(table.get("k").is_none());
    }

    #[test]
    fn txn_table_clear_removes_all_rows() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let mut table = txn.table::<Items>();
        table.insert("a", "alpha".to_owned());
        table.insert("b", "beta".to_owned());
        table.insert("c", "gamma".to_owned());
        table.clear();
        assert!(table.is_empty());
    }

    #[test]
    fn txn_table_is_empty_on_fresh_store() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let table = txn.table::<Items>();
        assert!(table.is_empty());
    }

    #[test]
    fn txn_table_len_reflects_inserts() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let mut table = txn.table::<Items>();
        table.insert("a", "alpha".to_owned());
        table.insert("b", "beta".to_owned());
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn txn_table_iter_empty() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let table = txn.table::<Items>();
        assert_eq!(table.iter().count(), 0);
    }

    #[test]
    fn txn_table_iter_yields_inserted_rows() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let mut table = txn.table::<Items>();
        table.insert("a", "alpha".to_owned());
        table.insert("b", "beta".to_owned());
        let mut items: Vec<_> = table.iter().collect();
        items.sort();
        assert_eq!(
            items,
            vec![(&"a", &"alpha".to_owned()), (&"b", &"beta".to_owned())]
        );
    }

    #[test]
    fn txn_table_for_each_empty_calls_closure_zero_times() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let table = txn.table::<Items>();
        let mut count = 0;
        table.iter().for_each(|_| count += 1);
        assert_eq!(count, 0);
    }

    #[test]
    fn txn_table_for_each_yields_all_rows() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let mut table = txn.table::<Items>();
        table.insert("a", "alpha".to_owned());
        table.insert("b", "beta".to_owned());
        let mut items: Vec<_> = Vec::new();
        table.iter().for_each(|(k, v)| items.push((*k, v.clone())));
        items.sort();
        assert_eq!(
            items,
            vec![("a", "alpha".to_owned()), ("b", "beta".to_owned())]
        );
    }

    #[test]
    fn txn_table_for_each_mut_empty_calls_closure_zero_times() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let mut table = txn.table::<Items>();
        let mut count = 0;
        table.for_each_mut(|_, _| count += 1);
        assert_eq!(count, 0);
    }

    #[test]
    fn txn_table_for_each_mut_modifies_values() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let mut table = txn.table::<Items>();
        table.insert("k", "hello".to_owned());
        table.for_each_mut(|_, v| v.push('!'));
        assert_eq!(table.get("k"), Some("hello!".to_owned()));
    }

    #[test]
    fn txn_table_iter_keys_cloned_empty() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let table = txn.table::<Items>();
        let keys: Vec<_> = table.keys().collect();
        assert!(keys.is_empty());
    }

    #[test]
    fn txn_table_iter_keys_cloned_yields_all_keys() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let mut table = txn.table::<Items>();
        table.insert("a", "alpha".to_owned());
        table.insert("b", "beta".to_owned());
        let mut keys: Vec<_> = table.keys().copied().collect();
        keys.sort();
        assert_eq!(keys, vec!["a", "b"]);
    }

    #[test]
    fn txn_table_iter_values_cloned_empty() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let table = txn.table::<Items>();
        let values: Vec<_> = table.values().collect();
        assert!(values.is_empty());
    }

    #[test]
    fn txn_table_iter_values_cloned_yields_all_values() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let mut table = txn.table::<Items>();
        table.insert("a", "alpha".to_owned());
        table.insert("b", "beta".to_owned());
        let mut values: Vec<_> = table.values().collect();
        values.sort();
        assert_eq!(values, vec!["alpha", "beta"]);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Ownership violation")]
    fn txn_table_insert_wrong_owner_panics() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).init().unwrap();
        let mut txn = store.begin_transaction(OTHER);
        txn.table::<Items>().insert("k", "v".to_owned());
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Ownership violation")]
    fn txn_table_mutate_wrong_owner_panics() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).init().unwrap();
        let mut txn = store.begin_transaction(OTHER);
        txn.table::<Items>()
            .with_mut(&"k", |v: &mut String| v.len());
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Ownership violation")]
    fn txn_table_remove_wrong_owner_panics() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).init().unwrap();
        let mut txn = store.begin_transaction(OTHER);
        txn.table::<Items>().remove(&"k");
    }

    #[test]
    fn ro_txn_get_returns_none_when_absent() {
        let store = KvStore::new();
        let txn = store.begin_ro_transaction(OWNER);
        assert!(txn.get::<Count>().is_none());
    }

    #[test]
    fn ro_txn_get_returns_value_inserted_before_txn() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 42);
        let txn = store.begin_ro_transaction(OWNER);
        assert_eq!(txn.get::<Count>(), Some(42));
    }

    #[test]
    fn ro_txn_get_arc_returns_none_when_absent() {
        let store = KvStore::new();
        let txn = store.begin_ro_transaction(OWNER);
        assert!(txn.get_arc::<Shared>().is_none());
    }

    #[test]
    fn ro_txn_get_arc_returns_arc() {
        let store = KvStore::new();
        store.insert::<Shared>(OWNER, Arc::new("hello".to_owned()));
        let txn = store.begin_ro_transaction(OWNER);
        let arc = txn.get_arc::<Shared>().unwrap();
        assert_eq!(*arc, "hello");
    }

    #[test]
    fn ro_txn_with_returns_none_and_does_not_call_f_when_absent() {
        let store = KvStore::new();
        let txn = store.begin_ro_transaction(OWNER);
        let mut called = false;
        let result = txn.with::<Count, ()>(|_| {
            called = true;
        });
        assert!(result.is_none());
        assert!(!called);
    }

    #[test]
    fn ro_txn_with_returns_some_after_insert() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 4);
        let txn = store.begin_ro_transaction(OWNER);
        assert_eq!(txn.with::<Count, _>(|v| v * 2), Some(8));
    }

    #[test]
    fn ro_txn_table_get_returns_none_when_absent() {
        let store = KvStore::new();
        let txn = store.begin_ro_transaction(OWNER);
        let table = txn.table::<Items>();
        assert!(table.get("missing").is_none());
    }

    #[test]
    fn ro_txn_table_get_returns_value_inserted_before_txn() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("k", "val".to_owned());
        let txn = store.begin_ro_transaction(OWNER);
        let table = txn.table::<Items>();
        assert_eq!(table.get("k"), Some("val".to_owned()));
    }

    #[test]
    fn ro_txn_table_with_returns_none_and_does_not_call_f_when_absent() {
        let store = KvStore::new();
        let txn = store.begin_ro_transaction(OWNER);
        let table = txn.table::<Items>();
        let mut called = false;
        let result = table.with("missing", |_| {
            called = true;
        });
        assert!(result.is_none());
        assert!(!called);
    }

    #[test]
    fn ro_txn_table_with_returns_some() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("k", "val".to_owned());
        let txn = store.begin_ro_transaction(OWNER);
        let table = txn.table::<Items>();
        assert_eq!(table.with("k", |s| s.len()), Some(3));
    }

    #[test]
    fn ro_txn_table_len_zero_when_empty() {
        let store = KvStore::new();
        let txn = store.begin_ro_transaction(OWNER);
        let table = txn.table::<Items>();
        assert_eq!(table.len(), 0);
    }

    #[test]
    fn ro_txn_table_len_reflects_pre_txn_inserts() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("a", "alpha".to_owned());
        store.table::<Items>(OWNER).insert("b", "beta".to_owned());
        let txn = store.begin_ro_transaction(OWNER);
        let table = txn.table::<Items>();
        assert_eq!(table.len(), 2);
    }

    #[test]
    fn ro_txn_table_is_empty_true_when_no_rows() {
        let store = KvStore::new();
        let txn = store.begin_ro_transaction(OWNER);
        let table = txn.table::<Items>();
        assert!(table.is_empty());
    }

    #[test]
    fn ro_txn_table_is_empty_false_after_inserts() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("k", "v".to_owned());
        let txn = store.begin_ro_transaction(OWNER);
        let table = txn.table::<Items>();
        assert!(!table.is_empty());
    }

    #[test]
    fn ro_txn_table_iter_empty() {
        let store = KvStore::new();
        let txn = store.begin_ro_transaction(OWNER);
        let table = txn.table::<Items>();
        assert_eq!(table.iter().count(), 0);
    }

    #[test]
    fn ro_txn_table_iter_yields_pre_txn_rows() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("a", "alpha".to_owned());
        store.table::<Items>(OWNER).insert("b", "beta".to_owned());
        let txn = store.begin_ro_transaction(OWNER);
        let table = txn.table::<Items>();
        let mut items: Vec<_> = table.iter().collect();
        items.sort();
        assert_eq!(
            items,
            vec![(&"a", &"alpha".to_owned()), (&"b", &"beta".to_owned())]
        );
    }

    #[test]
    fn ro_txn_table_for_each_empty_calls_closure_zero_times() {
        let store = KvStore::new();
        let txn = store.begin_ro_transaction(OWNER);
        let table = txn.table::<Items>();
        let mut count = 0;
        table.iter().for_each(|_| count += 1);
        assert_eq!(count, 0);
    }

    #[test]
    fn ro_txn_table_for_each_yields_pre_txn_rows() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("a", "alpha".to_owned());
        store.table::<Items>(OWNER).insert("b", "beta".to_owned());
        let txn = store.begin_ro_transaction(OWNER);
        let table = txn.table::<Items>();
        let mut items: Vec<_> = Vec::new();
        table.iter().for_each(|(k, v)| items.push((*k, v.clone())));
        items.sort();
        assert_eq!(
            items,
            vec![("a", "alpha".to_owned()), ("b", "beta".to_owned())]
        );
    }

    #[test]
    fn ro_txn_table_iter_keys_cloned_empty() {
        let store = KvStore::new();
        let txn = store.begin_ro_transaction(OWNER);
        let table = txn.table::<Items>();
        let keys: Vec<_> = table.keys().collect();
        assert!(keys.is_empty());
    }

    #[test]
    fn ro_txn_table_iter_keys_cloned_yields_pre_txn_keys() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("a", "alpha".to_owned());
        store.table::<Items>(OWNER).insert("b", "beta".to_owned());
        let txn = store.begin_ro_transaction(OWNER);
        let table = txn.table::<Items>();
        let mut keys: Vec<_> = table.keys().copied().collect();
        keys.sort();
        assert_eq!(keys, vec!["a", "b"]);
    }

    #[test]
    fn ro_txn_table_iter_values_cloned_empty() {
        let store = KvStore::new();
        let txn = store.begin_ro_transaction(OWNER);
        let table = txn.table::<Items>();
        let values: Vec<_> = table.values().collect();
        assert!(values.is_empty());
    }

    #[test]
    fn ro_txn_table_iter_values_cloned_yields_pre_txn_values() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("a", "alpha".to_owned());
        store.table::<Items>(OWNER).insert("b", "beta".to_owned());
        let txn = store.begin_ro_transaction(OWNER);
        let table = txn.table::<Items>();
        let mut values: Vec<_> = table.values().collect();
        values.sort();
        assert_eq!(values, vec!["alpha", "beta"]);
    }

    #[test]
    fn commit_returns_ok() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.insert::<Count>(1);
        assert!(txn.commit().is_ok());
    }

    #[test]
    fn txn_table_remove_then_commit_row_absent() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("k", "v".to_owned());

        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Items>().remove(&"k");
        txn.commit().unwrap();

        assert_eq!(store.table::<Items>(OWNER).get("k"), None);
    }

    #[test]
    fn txn_table_clear_then_commit_empty() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("a", "1".to_owned());
        store.table::<Items>(OWNER).insert("b", "2".to_owned());

        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Items>().clear();
        txn.commit().unwrap();

        assert!(store.table::<Items>(OWNER).is_empty());
    }

    #[test]
    fn txn_singleton_remove_then_commit_absent() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 7);

        let mut txn = store.begin_transaction(OWNER);
        txn.remove::<Count>();
        txn.commit().unwrap();

        assert_eq!(store.get::<Count>(OWNER), None);
    }

    #[test]
    fn txn_singleton_insert_rolled_back_on_drop() {
        let store = KvStore::new();
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.insert::<Count>(42);
            // dropped here without commit
        }
        assert_eq!(store.get::<Count>(OWNER), None);
    }

    #[test]
    fn txn_singleton_insert_over_existing_rolled_back_on_drop() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.insert::<Count>(2);
        }
        assert_eq!(store.get::<Count>(OWNER), Some(1));
    }

    #[test]
    fn txn_singleton_remove_rolled_back_on_drop() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 7);
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.remove::<Count>();
        }
        assert_eq!(store.get::<Count>(OWNER), Some(7));
    }

    #[test]
    fn txn_table_insert_rolled_back_on_drop() {
        let store = KvStore::new();
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.table::<Items>().insert("k", "v".to_owned());
        }
        assert_eq!(store.table::<Items>(OWNER).get("k"), None);
    }

    #[test]
    fn txn_table_insert_over_existing_rolled_back_on_drop() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("k", "orig".to_owned());
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.table::<Items>().insert("k", "new".to_owned());
        }
        assert_eq!(
            store.table::<Items>(OWNER).get("k"),
            Some("orig".to_owned())
        );
    }

    #[test]
    fn txn_table_mutate_rolled_back_on_drop() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("k", "orig".to_owned());
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.table::<Items>()
                .with_mut(&"k", |v| *v = "new".to_owned());
        }
        assert_eq!(
            store.table::<Items>(OWNER).get("k"),
            Some("orig".to_owned())
        );
    }

    #[test]
    fn txn_table_remove_rolled_back_on_drop() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("k", "v".to_owned());
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.table::<Items>().remove(&"k");
        }
        assert_eq!(store.table::<Items>(OWNER).get("k"), Some("v".to_owned()));
    }

    #[test]
    fn txn_table_clear_rolled_back_on_drop() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("a", "1".to_owned());
        store.table::<Items>(OWNER).insert("b", "2".to_owned());
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.table::<Items>().clear();
        }
        assert_eq!(store.table::<Items>(OWNER).len(), 2);
    }

    #[test]
    fn txn_multiple_writes_all_visible_after_commit() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.insert::<Count>(1);
        txn.table::<Items>().insert("k", "v".to_owned());
        txn.table::<Counters>().insert(9u32, 99u64);
        txn.commit().unwrap();

        assert_eq!(store.get::<Count>(OWNER), Some(1));
        assert_eq!(store.table::<Items>(OWNER).get("k"), Some("v".to_owned()));
        assert_eq!(store.table::<Counters>(OWNER).get(&9u32), Some(99));
    }

    #[test]
    fn txn_multiple_writes_none_visible_after_rollback() {
        let store = KvStore::new();
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.insert::<Count>(1);
            txn.table::<Items>().insert("k", "v".to_owned());
            txn.table::<Counters>().insert(9u32, 99u64);
        }
        assert_eq!(store.get::<Count>(OWNER), None);
        assert_eq!(store.table::<Items>(OWNER).get("k"), None);
        assert_eq!(store.table::<Counters>(OWNER).get(&9u32), None);
    }

    #[test]
    fn txn_mixed_insert_and_remove_commit_consistent() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("keep", "old".to_owned());
        store.table::<Items>(OWNER).insert("drop", "bye".to_owned());

        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Items>().insert("keep", "new".to_owned());
        txn.table::<Items>().remove(&"drop");
        txn.table::<Items>().insert("add", "hi".to_owned());
        txn.commit().unwrap();

        let table = store.table::<Items>(OWNER);
        assert_eq!(table.get("keep"), Some("new".to_owned()));
        assert_eq!(table.get("drop"), None);
        assert_eq!(table.get("add"), Some("hi".to_owned()));
    }

    #[test]
    fn store_usable_after_rollback() {
        let store = KvStore::new();
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.insert::<Count>(5);
        }
        assert_eq!(store.get::<Count>(OWNER), None);

        // A subsequent raw operation round-trips normally.
        store.insert::<Count>(OWNER, 9);
        assert_eq!(store.get::<Count>(OWNER), Some(9));
    }

    #[test]
    fn try_begin_transaction_succeeds_after_rollback() {
        let store = KvStore::new();
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.insert::<Count>(1);
        }
        // The dropped transaction released the write lock.
        assert!(store.try_begin_transaction(OWNER).is_some());
    }

    #[test]
    fn new_txn_after_rollback_sees_committed_value() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.insert::<Count>(2);
        }
        let txn2 = store.begin_transaction(OWNER);
        assert_eq!(txn2.get::<Count>(), Some(1));
    }

    #[test]
    fn panic_in_transaction_rolls_back() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);

        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut txn = store.begin_transaction(OWNER);
            txn.insert::<Count>(99);
            panic!();
        }))
        .unwrap_err();

        // The panicked transaction must have rolled back to the pre-transaction value.
        assert_eq!(store.get::<Count>(OWNER), Some(1));
    }

    #[test]
    fn store_recovers_after_panicked_transaction() {
        let store = KvStore::new();

        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut txn = store.begin_transaction(OWNER);
            txn.insert::<Count>(5);
            panic!();
        }))
        .unwrap_err();

        // The store recovers from the poisoned lock and remains usable.
        store.insert::<Count>(OWNER, 7);
        assert_eq!(store.get::<Count>(OWNER), Some(7));

        let mut txn = store.begin_transaction(OWNER);
        txn.insert::<Count>(8);
        txn.commit().unwrap();
        assert_eq!(store.get::<Count>(OWNER), Some(8));
    }

    #[test]
    fn early_return_in_transaction_rolls_back() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);

        // Returns early (without committing) when `fail` is set, otherwise commits.
        let run = |fail: bool| -> std::result::Result<(), ()> {
            let mut txn = store.begin_transaction(OWNER);
            txn.insert::<Count>(50);
            if fail {
                return Err(());
            }
            txn.commit().unwrap();
            Ok(())
        };

        assert!(run(true).is_err());
        assert_eq!(store.get::<Count>(OWNER), Some(1));

        assert!(run(false).is_ok());
        assert_eq!(store.get::<Count>(OWNER), Some(50));
    }

    #[test]
    fn singleton_three_commits_same_key_latest_wins() {
        let store = KvStore::new();

        for v in [10u64, 20, 30] {
            let mut txn = store.begin_transaction(OWNER);
            // Each transaction sees the value committed by the previous one.
            txn.insert::<Count>(v);
            txn.commit().unwrap();
            assert_eq!(store.get::<Count>(OWNER), Some(v));
        }
        assert_eq!(store.get::<Count>(OWNER), Some(30));
    }

    #[test]
    fn table_three_commits_same_key_latest_wins() {
        let store = KvStore::new();

        for v in ["one", "two", "three"] {
            let mut txn = store.begin_transaction(OWNER);
            txn.table::<Items>().insert("k", v.to_owned());
            txn.commit().unwrap();
            assert_eq!(store.table::<Items>(OWNER).get("k"), Some(v.to_owned()));
        }
        assert_eq!(
            store.table::<Items>(OWNER).get("k"),
            Some("three".to_owned())
        );
    }

    #[test]
    fn singleton_many_commits_same_key() {
        let store = KvStore::new();
        for v in 0..10u64 {
            let mut txn = store.begin_transaction(OWNER);
            txn.insert::<Count>(v);
            txn.commit().unwrap();
        }
        assert_eq!(store.get::<Count>(OWNER), Some(9));
    }

    // A new transaction begun after a rollback, with two committed versions of the key already
    // live in the two slots, must still observe the last committed value.
    #[test]
    fn singleton_rollback_after_two_commits_keeps_committed() {
        let store = KvStore::new();
        // First committed version (raw write).
        store.insert::<Count>(OWNER, 1);
        // Second committed version (fills the second slot).
        let mut txn = store.begin_transaction(OWNER);
        txn.insert::<Count>(2);
        txn.commit().unwrap();
        // Third write overwrites a slot, then rolls back.
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.insert::<Count>(3);
        }
        assert_eq!(store.get::<Count>(OWNER), Some(2));
        // And a fresh transaction also sees the committed value, not the rolled-back one.
        let txn = store.begin_transaction(OWNER);
        assert_eq!(txn.get::<Count>(), Some(2));
    }

    #[test]
    fn table_rollback_after_two_commits_keeps_committed() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("k", "v1".to_owned());
        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Items>().insert("k", "v2".to_owned());
        txn.commit().unwrap();
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.table::<Items>().insert("k", "v3".to_owned());
        }
        assert_eq!(store.table::<Items>(OWNER).get("k"), Some("v2".to_owned()));
        let mut txn = store.begin_transaction(OWNER);
        assert_eq!(txn.table::<Items>().get("k"), Some("v2".to_owned()));
    }

    #[test]
    fn raw_insert_then_txn_overwrite_commit_visible_raw() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        let mut txn = store.begin_transaction(OWNER);
        txn.insert::<Count>(2);
        txn.commit().unwrap();
        assert_eq!(store.get::<Count>(OWNER), Some(2));
    }

    #[test]
    fn raw_insert_then_txn_overwrite_rollback_keeps_raw() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.insert::<Count>(2);
        }
        assert_eq!(store.get::<Count>(OWNER), Some(1));
    }

    #[test]
    fn txn_commit_then_raw_overwrite_then_txn_read() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.insert::<Count>(1);
        txn.commit().unwrap();

        // A raw write at the committed id overwrites the committed value...
        store.insert::<Count>(OWNER, 2);
        assert_eq!(store.get::<Count>(OWNER), Some(2));

        // ...and the next transaction observes it.
        let txn = store.begin_transaction(OWNER);
        assert_eq!(txn.get::<Count>(), Some(2));
    }

    #[test]
    fn raw_table_remove_then_txn_reinsert_commit() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("k", "v".to_owned());
        store.table::<Items>(OWNER).remove(&"k");
        assert_eq!(store.table::<Items>(OWNER).get("k"), None);

        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Items>().insert("k", "again".to_owned());
        txn.commit().unwrap();
        assert_eq!(
            store.table::<Items>(OWNER).get("k"),
            Some("again".to_owned())
        );
    }

    #[test]
    fn interleave_raw_and_txn_different_keys() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("a", "A".to_owned());

        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Items>().insert("b", "B".to_owned());
        txn.commit().unwrap();
        assert_eq!(store.table::<Items>(OWNER).get("a"), Some("A".to_owned()));
        assert_eq!(store.table::<Items>(OWNER).get("b"), Some("B".to_owned()));

        // A rolled-back transaction touching both keys leaves them as they were.
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.table::<Items>().remove(&"a");
            txn.table::<Items>().insert("c", "C".to_owned());
        }
        assert_eq!(store.table::<Items>(OWNER).get("a"), Some("A".to_owned()));
        assert_eq!(store.table::<Items>(OWNER).get("c"), None);
    }

    #[test]
    fn txn_len_unchanged_after_removing_absent_key() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("a", "1".to_owned());
        store.table::<Items>(OWNER).insert("b", "2".to_owned());

        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Items>().remove(&"zzz");
        assert_eq!(txn.table::<Items>().len(), 2);
    }

    #[test]
    fn txn_is_empty_false_after_removing_absent_key() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("a", "1".to_owned());

        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Items>().remove(&"zzz");
        assert!(!txn.table::<Items>().is_empty());
    }

    #[test]
    fn txn_len_after_removing_several_absent_keys() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("a", "1".to_owned());

        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Items>().remove(&"x");
        txn.table::<Items>().remove(&"y");
        txn.table::<Items>().remove(&"z");
        assert_eq!(txn.table::<Items>().len(), 1);
    }

    #[test]
    fn txn_len_reflects_mixed_insert_remove() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("a", "1".to_owned());
        store.table::<Items>(OWNER).insert("b", "2".to_owned());
        store.table::<Items>(OWNER).insert("c", "3".to_owned());

        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Items>().remove(&"b");
        txn.table::<Items>().insert("d", "4".to_owned());
        assert_eq!(txn.table::<Items>().len(), 3);
    }

    #[test]
    fn txn_iter_reflects_committed_plus_pending_minus_removed() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("a", "1".to_owned());
        store.table::<Items>(OWNER).insert("b", "2".to_owned());
        store.table::<Items>(OWNER).insert("c", "3".to_owned());

        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Items>().remove(&"b");
        txn.table::<Items>().insert("d", "4".to_owned());

        let table = txn.table::<Items>();
        let mut keys: Vec<_> = table.keys().copied().collect();
        keys.sort();
        assert_eq!(keys, vec!["a", "c", "d"]);
    }

    #[test]
    fn txn_clear_then_insert_len_and_iter() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("a", "1".to_owned());
        store.table::<Items>(OWNER).insert("b", "2".to_owned());

        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Items>().clear();
        txn.table::<Items>().insert("x", "9".to_owned());

        let table = txn.table::<Items>();
        assert_eq!(table.len(), 1);
        let keys: Vec<_> = table.keys().copied().collect();
        assert_eq!(keys, vec!["x"]);
    }

    #[test]
    fn txn_is_empty_after_clear() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("a", "1".to_owned());
        store.table::<Items>(OWNER).insert("b", "2".to_owned());

        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Items>().clear();
        assert!(txn.table::<Items>().is_empty());
        assert_eq!(txn.table::<Items>().len(), 0);
    }

    #[test]
    fn txn_mutate_committed_value_commit_persists() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("k", "orig".to_owned());

        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Items>().with_mut(&"k", |v| v.push('!'));
        txn.commit().unwrap();

        assert_eq!(
            store.table::<Items>(OWNER).get("k"),
            Some("orig!".to_owned())
        );
    }

    #[test]
    fn txn_for_each_mut_committed_values_commit_persists() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("a", "x".to_owned());
        store.table::<Items>(OWNER).insert("b", "y".to_owned());

        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Items>().for_each_mut(|_, v| v.push('!'));
        txn.commit().unwrap();

        assert_eq!(store.table::<Items>(OWNER).get("a"), Some("x!".to_owned()));
        assert_eq!(store.table::<Items>(OWNER).get("b"), Some("y!".to_owned()));
    }

    #[test]
    fn ro_txn_after_commit_sees_committed() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.insert::<Count>(7);
        txn.commit().unwrap();

        let txn = store.begin_ro_transaction(OWNER);
        assert_eq!(txn.get::<Count>(), Some(7));
    }

    #[test]
    fn ro_txn_after_rollback_sees_pre_txn() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.insert::<Count>(2);
        }
        let txn = store.begin_ro_transaction(OWNER);
        assert_eq!(txn.get::<Count>(), Some(1));
    }

    #[test]
    fn ro_txn_after_multiple_commits_sees_latest() {
        let store = KvStore::new();
        for v in [10u64, 20, 30] {
            let mut txn = store.begin_transaction(OWNER);
            txn.insert::<Count>(v);
            txn.commit().unwrap();
        }
        let txn = store.begin_ro_transaction(OWNER);
        assert_eq!(txn.get::<Count>(), Some(30));
    }

    #[test]
    fn try_begin_transaction_none_while_rw_txn_active() {
        let store = KvStore::new();
        let _txn = store.begin_transaction(OWNER);
        assert!(store.try_begin_transaction(OWNER).is_none());
    }

    #[test]
    fn try_begin_ro_transaction_none_while_rw_txn_active() {
        let store = KvStore::new();
        let _txn = store.begin_transaction(OWNER);
        assert!(store.try_begin_ro_transaction(OWNER).is_none());
    }

    #[test]
    fn try_begin_transaction_none_while_ro_txn_active() {
        let store = KvStore::new();
        let _txn = store.begin_ro_transaction(OWNER);
        assert!(store.try_begin_transaction(OWNER).is_none());
    }
}
