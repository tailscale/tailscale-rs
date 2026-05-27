//! KvStore transactional API.

use std::{
    borrow::Borrow,
    hash::Hash,
    marker::PhantomData,
    sync::{Arc, RwLockReadGuard, RwLockWriteGuard, TryLockError},
};

use crate::{
    KvStore, Owner, RefReadGuard, RefWriteGuard, RefWriteGuardMut, Result,
    index::{KvTableRoTransactionalIndex, KvTableTransactionalIndex},
    operations::{Ops, OpsMut, SingletonOps, SingletonOpsMut, TabularOps, TabularOpsMut},
    schema::{self, TableDesc},
    storage::Storage,
};

impl<TableStorage: schema::GeneratedStorage> KvStore<TableStorage> {
    /// Start a transaction.
    ///
    /// Blocks until the store's global lock is available for write access.
    pub fn begin_transaction(&self, owner: Owner) -> Transaction<'_, TableStorage> {
        Transaction {
            guard: self.storage.write().unwrap(),
            owner,
        }
    }

    /// Start a transaction.
    ///
    /// Returns `None` if the store's global lock is unavailable for write access.
    pub fn try_begin_transaction(&self, owner: Owner) -> Option<Transaction<'_, TableStorage>> {
        let guard = match self.storage.try_write() {
            Ok(g) => g,
            Err(TryLockError::WouldBlock) => return None,
            Err(TryLockError::Poisoned(_)) => panic!(),
        };
        Some(Transaction { guard, owner })
    }

    /// Start a read-only transaction (i.e., only supports non-mutating access to the store, but
    /// all reads are guaranteed to be atomic).
    ///
    /// Blocks until the store's global lock is available for read access.
    pub fn begin_ro_transaction(&self, owner: Owner) -> RoTransaction<'_, TableStorage> {
        RoTransaction {
            guard: self.storage.read().unwrap(),
            owner,
        }
    }

    /// Start a read-only transaction (i.e., only supports non-mutating access to the store, but
    /// all reads are guaranteed to be atomic).
    ///
    /// Returns `None` if the store's global lock is unavailable for read access.
    pub fn try_begin_ro_transaction(
        &self,
        owner: Owner,
    ) -> Option<RoTransaction<'_, TableStorage>> {
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
// TODO do we need to be able to abort a transaction?
pub struct Transaction<'guard, TableStorage: schema::GeneratedStorage> {
    pub(crate) guard: RwLockWriteGuard<'guard, Storage<TableStorage>>,
    pub(crate) owner: Owner,
}

impl<'store: 'guard, 'guard: 'r, 'r, TableStorage: schema::GeneratedStorage + 'store>
    Ops<'r, TableStorage> for &'r Transaction<'guard, TableStorage>
{
    type ReadLock = RefWriteGuard<'r, 'guard, Storage<TableStorage>>;

    fn read_lock(self) -> Self::ReadLock {
        RefWriteGuard(&self.guard)
    }
}

impl<'store: 'guard, 'guard: 'r, 'r, TableStorage: schema::GeneratedStorage + 'store>
    SingletonOps<'r, TableStorage> for &'r Transaction<'guard, TableStorage>
{
}

impl<'store: 'guard, 'guard: 'r, 'r, TableStorage: schema::GeneratedStorage + 'store>
    OpsMut<'r, TableStorage> for &'r mut Transaction<'guard, TableStorage>
{
    type WriteLock = RefWriteGuardMut<'r, 'guard, Storage<TableStorage>>;

    fn write_lock(self) -> Self::WriteLock {
        RefWriteGuardMut(&mut self.guard)
    }
}

impl<'store: 'guard, 'guard: 'r, 'r, TableStorage: schema::GeneratedStorage + 'store>
    SingletonOpsMut<'r, TableStorage> for &'r mut Transaction<'guard, TableStorage>
{
}

impl<'guard, TableStorage: schema::GeneratedStorage> Transaction<'guard, TableStorage> {
    /// Commit this transaction.
    ///
    /// This simply moves and drops the `Transaction` object. It is optional to call and currently
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
    pub fn table<'r, D: schema::TableDesc<Storage = TableStorage>>(
        &'r mut self,
    ) -> KvTableTransactional<'guard, 'r, TableStorage, D> {
        KvTableTransactional {
            txn: self,
            table: PhantomData,
        }
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
    pub fn table_by<'r, D: schema::IndexDesc<Storage = TableStorage>>(
        &'r mut self,
    ) -> KvTableTransactionalIndex<'guard, 'r, TableStorage, D, D::BaseTable> {
        KvTableTransactionalIndex {
            txn: self,
            index: PhantomData,
            base: PhantomData,
        }
    }

    /// Get a single value from the store by cloning the value.
    ///
    /// Returns `None` if there is no value for the specified key.
    pub fn get<D: schema::Singleton>(&self) -> Option<D::Value>
    where
        D::Value: Clone,
    {
        <&Self as SingletonOps<'_, TableStorage>>::get::<D>(self, self.owner)
    }

    /// Get a single value from the store by cloning an `Arc`.
    ///
    /// Returns `None` if there is no value for the specified key. Panics if the value is not an `Arc`.
    pub fn get_arc<D: schema::ArcSingleton>(&self) -> Option<Arc<D::Value>> {
        <&Self as SingletonOps<'_, TableStorage>>::get_arc::<D>(self, self.owner)
    }

    /// Get immutable access to a value in the store by reference.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    pub fn with<D: schema::Singleton, T>(&self, f: impl FnOnce(&D::Value) -> T) -> Option<T> {
        <&Self as SingletonOps<'_, TableStorage>>::with::<D, T>(self, f, self.owner)
    }

    /// Insert a single value into the store.
    ///
    /// Returns the previous value if there is one, or `None` if there is no value for the specified key.
    // Question: do we need separate insert/update/upsert methods?
    pub fn insert<D: schema::Singleton>(&mut self, value: D::ArgValue) -> Option<D::ArgValue> {
        <&mut Self as SingletonOpsMut<'_, TableStorage>>::insert::<D>(self, value, self.owner)
    }

    /// Get mutable access to a value in the store.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    pub fn with_mut<D: schema::MutSingleton, T>(
        &mut self,
        f: impl FnOnce(&mut D::Value) -> T,
    ) -> Option<T> {
        <&mut Self as SingletonOpsMut<'_, TableStorage>>::with_mut::<D, T>(self, f, self.owner)
    }

    /// Remove a single value from the store.
    ///
    /// Returns the previous value if there is one, or `None` if there is no value for the specified key.
    pub fn remove<D: schema::Singleton>(&mut self) -> Option<D::ArgValue> {
        <&mut Self as SingletonOpsMut<'_, TableStorage>>::remove::<D>(self, self.owner)
    }

    /// Remove a single value from the store while preserving ownership of the key/value.
    ///
    /// Can also be used to initialize a key/value with a key but without a value.
    ///
    /// Returns the previous value if there is one, or `None` if there is no value for the specified key.
    pub fn clear<D: schema::Singleton>(&mut self) -> Option<D::ArgValue> {
        <&mut Self as SingletonOpsMut<'_, TableStorage>>::clear::<D>(self, self.owner)
    }
}

/// Abstracts a table of key/values pairs in the store accessed as part of a transaction.
pub struct KvTableTransactional<
    'guard: 'tx,
    'tx,
    TableStorage: schema::GeneratedStorage,
    D: schema::TableDesc<Storage = TableStorage>,
> {
    txn: &'tx mut Transaction<'guard, TableStorage>,
    table: PhantomData<D>,
}

impl<
    'store: 'guard,
    'guard: 'tx,
    'tx: 'table,
    'table,
    TableStorage: schema::GeneratedStorage + 'store,
    D: TableDesc<Storage = TableStorage> + 'store,
> Ops<'store, TableStorage> for &'table KvTableTransactional<'guard, 'tx, TableStorage, D>
{
    type ReadLock = RefWriteGuard<'table, 'guard, Storage<TableStorage>>;

    fn read_lock(self) -> Self::ReadLock {
        RefWriteGuard(&self.txn.guard)
    }
}

impl<
    'store: 'guard,
    'guard: 'tx,
    'tx: 'table,
    'table,
    TableStorage: schema::GeneratedStorage + 'store,
    D: TableDesc<Storage = TableStorage> + 'store,
> OpsMut<'store, TableStorage> for &'table mut KvTableTransactional<'guard, 'tx, TableStorage, D>
{
    type WriteLock = RefWriteGuardMut<'table, 'guard, Storage<TableStorage>>;

    fn write_lock(self) -> Self::WriteLock {
        RefWriteGuardMut(&mut self.txn.guard)
    }
}

impl<
    'store: 'guard,
    'guard: 'tx,
    'tx,
    TableStorage: schema::GeneratedStorage + 'store,
    D: TableDesc<Storage = TableStorage> + 'store,
> TabularOps<'store, TableStorage, D> for &KvTableTransactional<'guard, 'tx, TableStorage, D>
{
}

impl<
    'store: 'guard,
    'guard: 'tx,
    'tx,
    TableStorage: schema::GeneratedStorage + 'store,
    D: TableDesc<Storage = TableStorage> + 'store,
> TabularOpsMut<'store, TableStorage, D>
    for &mut KvTableTransactional<'guard, 'tx, TableStorage, D>
{
}

impl<
    'store: 'guard,
    'guard: 'tx,
    'tx,
    TableStorage: schema::GeneratedStorage + 'store,
    D: TableDesc<Storage = TableStorage> + 'store,
> KvTableTransactional<'guard, 'tx, TableStorage, D>
{
    /// Initialize a table by setting its owner.
    ///
    /// Calling this function is optional, a table can be used without initialization in which case,
    /// its owner is set to the owner specifed in the first write.
    ///
    /// Returns an error (containing the current owner of the table) if the table has already been
    /// initialized. In this case, the table will be in a consistent state and can be used as normal.
    pub fn init(&mut self) -> Result<()> {
        <&mut Self as TabularOpsMut<'_, TableStorage, D>>::init(self, self.txn.owner)
    }

    /// The number of key/value pairs in the table.
    pub fn len(&self) -> usize {
        <&Self as TabularOps<'_, TableStorage, D>>::len(self)
    }

    /// True if the table is empty.
    pub fn is_empty(&self) -> bool {
        <&Self as TabularOps<'_, TableStorage, D>>::is_empty(self)
    }

    /// Clear a table by removing all its KVs, but preserving ownership.
    pub fn clear(&mut self) {
        <&mut Self as TabularOpsMut<'_, TableStorage, D>>::clear(self, self.txn.owner)
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
        <&Self as TabularOps<'_, TableStorage, D>>::get::<Q>(self, key, self.txn.owner)
    }

    /// Get immutable access to a row of the table in the store by reference.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    pub fn with<Q, T>(&self, key: &Q, f: impl FnOnce(&D::Value) -> T) -> Option<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        <&Self as TabularOps<'_, TableStorage, D>>::with::<Q, T>(self, key, f, self.txn.owner)
    }

    /// Insert a value into the table.
    ///
    /// Returns the previous value if there is one, or `None` if there is no value for the specified key.
    pub fn insert(&mut self, key: D::Key, value: D::Value) -> Option<D::Value>
    where
        D::Key: Clone,
    {
        <&mut Self as TabularOpsMut<'_, TableStorage, D>>::insert(self, key, value, self.txn.owner)
    }

    /// Get mutable access to a row of the table in the store in the store.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    pub fn with_mut<Q, T>(&mut self, key: &Q, f: impl FnOnce(&mut D::Value) -> T) -> Option<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = D::Key>,
    {
        <&mut Self as TabularOpsMut<'_, TableStorage, D>>::with_mut(self, key, f, self.txn.owner)
    }

    /// Remove a row from the table.
    ///
    /// Returns the previous value if there is one, or `None` if there is no value for the specified key.
    pub fn remove<Q>(&mut self, key: &Q) -> Option<D::Value>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        <&mut Self as TabularOpsMut<'_, TableStorage, D>>::remove(self, key, self.txn.owner)
    }

    /// Iterate all the key/value pairs in a table.
    pub fn iter(&self) -> impl Iterator<Item = (&D::Key, &D::Value)> {
        <&Self as TabularOps<'_, TableStorage, D>>::iter(self, self.txn.owner)
    }

    /// Iterate all the keys in a table.
    pub fn keys(&self) -> impl Iterator<Item = &D::Key> {
        <&Self as TabularOps<'_, TableStorage, D>>::keys(self, self.txn.owner)
    }

    /// Iterate all the values in a table.
    pub fn values(&self) -> impl Iterator<Item = &D::Value> {
        <&Self as TabularOps<'_, TableStorage, D>>::values(self, self.txn.owner)
    }

    /// Iterate all the key/value pairs in a table. Values are mutable.
    pub fn for_each_mut(&mut self, f: impl FnMut(&D::Key, &mut D::Value)) {
        <&mut Self as TabularOpsMut<'_, TableStorage, D>>::for_each_mut(self, f, self.txn.owner)
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

impl<'store: 'guard, 'guard: 'tx, 'tx, TableStorage: schema::GeneratedStorage + 'store>
    Ops<'store, TableStorage> for &'tx RoTransaction<'guard, TableStorage>
{
    type ReadLock = RefReadGuard<'tx, 'guard, Storage<TableStorage>>;

    fn read_lock(self) -> Self::ReadLock {
        RefReadGuard(&self.guard)
    }
}

impl<'store: 'guard, 'guard, TableStorage: schema::GeneratedStorage + 'store>
    SingletonOps<'store, TableStorage> for &RoTransaction<'guard, TableStorage>
{
}

impl<
    'store: 'guard,
    'guard: 'tx,
    'tx: 'table,
    'table,
    TableStorage: schema::GeneratedStorage + 'store,
    D: TableDesc<Storage = TableStorage>,
> Ops<'store, TableStorage> for &'table KvTableRoTransactional<'guard, 'tx, TableStorage, D>
{
    type ReadLock = RefReadGuard<'table, 'guard, Storage<TableStorage>>;

    fn read_lock(self) -> Self::ReadLock {
        RefReadGuard(&self.txn.guard)
    }
}

impl<
    'store: 'guard,
    'guard: 'tx,
    'tx,
    TableStorage: schema::GeneratedStorage + 'store,
    D: TableDesc<Storage = TableStorage>,
> TabularOps<'store, TableStorage, D> for &KvTableRoTransactional<'guard, 'tx, TableStorage, D>
{
}

impl<'store: 'guard, 'guard, TableStorage: schema::GeneratedStorage + 'store>
    RoTransaction<'guard, TableStorage>
{
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
    pub fn table<'tx, D: schema::TableDesc<Storage = TableStorage>>(
        &'tx self,
    ) -> KvTableRoTransactional<'guard, 'tx, TableStorage, D> {
        KvTableRoTransactional {
            txn: self,
            table: PhantomData,
        }
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
    pub fn table_by<'tx, D: schema::IndexDesc<Storage = TableStorage>>(
        &'tx self,
    ) -> KvTableRoTransactionalIndex<'guard, 'tx, TableStorage, D, D::BaseTable> {
        KvTableRoTransactionalIndex {
            txn: self,
            index: PhantomData,
            base: PhantomData,
        }
    }

    /// Get a single value from the store by cloning the value.
    ///
    /// Returns `None` if there is no value for the specified key.
    pub fn get<D: schema::Singleton>(&self) -> Option<D::Value>
    where
        D::Value: Clone,
    {
        <&Self as SingletonOps<'_, TableStorage>>::get::<D>(self, self.owner)
    }

    /// Get a single value from the store by cloning an `Arc`.
    ///
    /// Returns `None` if there is no value for the specified key. Panics if the value is not an `Arc`.
    pub fn get_arc<D: schema::ArcSingleton>(&self) -> Option<Arc<D::Value>> {
        <&Self as SingletonOps<'_, TableStorage>>::get_arc::<D>(self, self.owner)
    }

    /// Get immutable access to a value in the store by reference.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    pub fn with<D: schema::Singleton, T>(&self, f: impl FnOnce(&D::Value) -> T) -> Option<T> {
        <&Self as SingletonOps<'_, TableStorage>>::with::<D, T>(self, f, self.owner)
    }
}

/// Abstracts a table of key/values pairs in the store as part of a read-only transaction.
pub struct KvTableRoTransactional<
    'guard: 'tx,
    'tx,
    TableStorage: schema::GeneratedStorage,
    D: schema::TableDesc<Storage = TableStorage>,
> {
    txn: &'tx RoTransaction<'guard, TableStorage>,
    table: PhantomData<D>,
}

impl<
    'store: 'guard,
    'guard: 'tx,
    'tx,
    TableStorage: schema::GeneratedStorage + 'store,
    D: schema::TableDesc<Storage = TableStorage>,
> KvTableRoTransactional<'guard, 'tx, TableStorage, D>
{
    /// The number of key/value pairs in the table.
    pub fn len(&self) -> usize {
        <&Self as TabularOps<'_, TableStorage, D>>::len(self)
    }

    /// True if the table is empty.
    pub fn is_empty(&self) -> bool {
        <&Self as TabularOps<'_, TableStorage, D>>::is_empty(self)
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
        <&Self as TabularOps<'_, TableStorage, D>>::get::<Q>(self, key, self.txn.owner)
    }

    /// Get immutable access to a row of the table in the store by reference.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    pub fn with<Q, T>(&self, key: &Q, f: impl FnOnce(&D::Value) -> T) -> Option<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        <&Self as TabularOps<'_, TableStorage, D>>::with::<Q, T>(self, key, f, self.txn.owner)
    }

    /// Iterate all the key/value pairs in a table.
    ///
    /// Clones both keys and values and provides them by-value. To iterate without cloning, see
    /// [`Self::for_each`].
    pub fn iter(&self) -> impl Iterator<Item = (&D::Key, &D::Value)>
    where
        D: 'store,
    {
        <&Self as TabularOps<'_, TableStorage, D>>::iter(self, self.txn.owner)
    }

    /// Iterate all the keys in a table.
    ///
    /// Clones the keys and provides them by-value. To iterate without cloning, see
    /// [`Self::for_each`].
    pub fn keys(&self) -> impl Iterator<Item = &D::Key>
    where
        D: 'store,
    {
        <&Self as TabularOps<'_, TableStorage, D>>::keys(self, self.txn.owner)
    }

    /// Iterate all the values in a table.
    ///
    /// Clones values and provides them by-value. To iterate without cloning, see
    /// [`Self::for_each`].
    pub fn values(&self) -> impl Iterator<Item = &D::Value>
    where
        D: 'store,
    {
        <&Self as TabularOps<'_, TableStorage, D>>::values(self, self.txn.owner)
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
    fn txn_get_returns_none_after_clear_in_same_txn() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.insert::<Count>(1);
        txn.clear::<Count>();
        assert!(txn.get::<Count>().is_none());
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
    fn txn_insert_returns_none_on_first() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        assert!(txn.insert::<Count>(1).is_none());
    }

    #[test]
    fn txn_insert_returns_previous_value() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.insert::<Count>(1);
        assert_eq!(txn.insert::<Count>(2), Some(1));
    }

    #[test]
    fn txn_insert_over_tombstone_returns_none() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.insert::<Count>(1);
        txn.clear::<Count>();
        assert!(txn.insert::<Count>(2).is_none());
    }

    #[test]
    fn txn_mutate_returns_none_and_does_not_call_f_when_absent() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let mut called = false;
        let result = txn.with_mut::<Count, ()>(|_| {
            called = true;
        });
        assert!(result.is_none());
        assert!(!called);
    }

    #[test]
    fn txn_mutate_modifies_value_in_place() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.insert::<Count>(10);
        assert_eq!(
            txn.with_mut::<Count, _>(|v| {
                *v += 5;
                *v
            }),
            Some(15)
        );
        assert_eq!(txn.get::<Count>(), Some(15));
    }

    #[test]
    fn txn_remove_returns_none_when_absent() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        assert!(txn.remove::<Count>().is_none());
    }

    #[test]
    fn txn_remove_returns_previous_value() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.insert::<Count>(7);
        assert_eq!(txn.remove::<Count>(), Some(7));
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
    fn txn_clear_returns_none_when_absent() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        assert!(txn.clear::<Count>().is_none());
    }

    #[test]
    fn txn_clear_returns_previous_value() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.insert::<Count>(3);
        assert_eq!(txn.clear::<Count>(), Some(3));
    }

    #[test]
    fn txn_clear_makes_get_return_none() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.insert::<Count>(1);
        txn.clear::<Count>();
        assert!(txn.get::<Count>().is_none());
    }

    #[test]
    fn txn_double_clear_returns_none() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.insert::<Count>(1);
        txn.clear::<Count>();
        assert!(txn.clear::<Count>().is_none());
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
    fn txn_mutate_visible_after_drop() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        let mut txn = store.begin_transaction(OWNER);
        txn.with_mut::<Count, ()>(|v| *v = 100);
        txn.commit().unwrap();

        assert_eq!(store.get::<Count>(OWNER), Some(100));
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
    fn txn_mutate_wrong_owner_panics() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        let mut txn = store.begin_transaction(OTHER);
        txn.with_mut::<Count, ()>(|_| {});
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
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Ownership violation")]
    fn txn_clear_wrong_owner_panics() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        let mut txn = store.begin_transaction(OTHER);
        txn.clear::<Count>();
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
    fn txn_table_insert_returns_none_on_first() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let mut table = txn.table::<Items>();
        assert!(table.insert("k", "v".to_owned()).is_none());
    }

    #[test]
    fn txn_table_insert_returns_previous() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let mut table = txn.table::<Items>();
        table.insert("k", "v1".to_owned());
        assert_eq!(table.insert("k", "v2".to_owned()), Some("v1".to_owned()));
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
    fn txn_table_remove_returns_none_when_absent() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let mut table = txn.table::<Items>();
        assert!(table.remove("missing").is_none());
    }

    #[test]
    fn txn_table_remove_returns_previous_value() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let mut table = txn.table::<Items>();
        table.insert("k", "v".to_owned());
        assert_eq!(table.remove("k"), Some("v".to_owned()));
    }

    #[test]
    fn txn_table_remove_makes_get_return_none() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let mut table = txn.table::<Items>();
        table.insert("k", "v".to_owned());
        table.remove("k");
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
        txn.table::<Items>().remove("k");
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
}
