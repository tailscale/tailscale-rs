use alloc::sync::Arc;
use core::{borrow::Borrow, hash::Hash, marker::PhantomData};
use std::sync::RwLockReadGuard;

use crate::{
    KvStore, Owner, Result, RoTableTransaction, TableTransaction,
    iter::{self, IndexIter},
    operations::{BaseKey, BaseValue, IndexKey, IndexedOps, Ops, StorageGuard},
    schema::{Desc, IndexDesc},
    storage::Storage,
    transactions::TransactionInner,
};

/// Non-transactional accessor for a table of key/values pairs via an index.
///
/// `D` describes the index table, its base table is `D::BaseTable`.
pub struct Index<D: IndexDesc> {
    store: Arc<KvStore<D::Storage>>,
    owner: Owner,
}

impl<D: IndexDesc> Index<D> {
    /// Create an index accessor for `store`.
    #[doc(hidden)]
    pub fn new(store: Arc<KvStore<D::Storage>>, owner: Owner) -> Self {
        Index { store, owner }
    }

    /// Returns `Ok` if the index is consistent, and an error with some kind of explanation if not.
    pub fn check_consistent(&self) -> Result<()> {
        <&Self as IndexedOps<_>>::check_consistent(self)
    }

    /// Get a row of the table from the store by cloning the value.
    ///
    /// Returns `None` if there is no value for the specified key.
    ///
    /// Panics if the index is inconsistent (see [`Self::check_consistent`]).
    pub fn get<Q>(&self, key: &Q) -> Option<(BaseKey<D>, BaseValue<D>)>
    where
        BaseKey<D>: Clone + Eq + Hash,
        BaseValue<D>: Clone,
        IndexKey<D>: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        <&Self as IndexedOps<_>>::get(self, key, self.owner).unwrap()
    }

    /// Get immutable access to a row of the table in the store by reference.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    ///
    /// Panics if the index is inconsistent (see [`Self::check_consistent`]).
    pub fn with<Q, T>(&self, key: &Q, f: impl FnOnce(&BaseKey<D>, &BaseValue<D>) -> T) -> Option<T>
    where
        IndexKey<D>: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        BaseKey<D>: Eq + Hash,
    {
        <&Self as IndexedOps<_>>::with::<Q, T>(self, key, f, self.owner).unwrap()
    }

    /// Iterate over all key/value pairs in the table.
    ///
    /// Access is scoped by a closure (rather than returning an iterator) because the store is
    /// locked while iterating, and so references into the store must not outlive the iterator.
    /// Use a (read-only) transaction to get an iterator.
    pub fn with_iter<F, T>(&self, f: F) -> T
    where
        BaseKey<D>: Eq + Hash,
        F: for<'a> FnOnce(
            &mut dyn Iterator<Item = (&'a IndexKey<D>, &'a BaseKey<D>, &'a BaseValue<D>)>,
        ) -> T,
    {
        <&Self as IndexedOps<_>>::with_iter(self, f)
    }

    /// Iterate over all rows in the index, calling `f` for each index key, base key, and value.
    pub fn for_each<F>(&self, mut f: F)
    where
        BaseKey<D>: Eq + Hash,
        F: for<'a> FnMut(&'a IndexKey<D>, &'a BaseKey<D>, &'a BaseValue<D>),
    {
        self.with_iter(|it| it.for_each(|(k, bk, v)| f(k, bk, v)))
    }

    /// Iterate over all keys in the table.
    pub fn with_keys<F, T>(&self, f: F) -> T
    where
        BaseKey<D>: Eq + Hash,
        F: for<'a> FnOnce(&mut dyn Iterator<Item = &'a IndexKey<D>>) -> T,
    {
        <&Self as IndexedOps<_>>::with_keys(self, f)
    }

    /// Iterate over all values in the table.
    pub fn with_values<F, T>(&self, f: F) -> T
    where
        BaseKey<D>: Eq + Hash,
        F: for<'a> FnOnce(&mut dyn Iterator<Item = (&'a BaseKey<D>, &'a BaseValue<D>)>) -> T,
    {
        <&Self as IndexedOps<_>>::with_values(self, f)
    }

    /// Get mutable access to a row of the table. `f` is passed the row's key in the base table and
    /// its value.
    ///
    /// Returns `Ok(None)` (and does not call `f`) if there is no value for the specified key.
    /// Returns [`Error::NonUniqueIndexKey`](crate::Error::NonUniqueIndexKey) if `f` makes a unique
    /// index key non-unique, in which case the mutation is not applied.
    pub fn try_with_mut<Q, T>(
        &self,
        key: &Q,
        f: impl FnOnce(&BaseKey<D>, &mut BaseValue<D>) -> T,
    ) -> Result<Option<T>>
    where
        BaseKey<D>: Clone + Eq + Hash,
        BaseValue<D>: Clone + PartialEq,
        IndexKey<D>: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        self.in_txn(|index| index.with_mut(key, f))
    }

    /// Get mutable access to a row of the table. `f` is passed the row's key in the base table and
    /// its value.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    ///
    /// Panics if `f` makes a unique index key non-unique.
    pub fn with_mut<Q, T>(
        &self,
        key: &Q,
        f: impl FnOnce(&BaseKey<D>, &mut BaseValue<D>) -> T,
    ) -> Option<T>
    where
        BaseKey<D>: Clone + Eq + Hash,
        BaseValue<D>: Clone + PartialEq,
        IndexKey<D>: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        self.try_with_mut(key, f).unwrap()
    }

    /// Update the value indexed by `key` if there is an entry for `key`, otherwise insert `value`
    /// into the base table, using `base_key` to produce the base table key. Returns the base key in
    /// either case.
    ///
    /// Returns [`Error::NonUniqueIndexKey`](crate::Error::NonUniqueIndexKey) (without updating)
    /// if the insert/update would make an index non-unique. Panics instead if that index is declared
    /// with `assert`.
    pub fn try_upsert<Q>(
        &self,
        key: &Q,
        value: &BaseValue<D>,
        base_key: impl FnOnce() -> BaseKey<D>,
    ) -> Result<BaseKey<D>>
    where
        BaseKey<D>: Clone + Eq + Hash,
        BaseValue<D>: Clone + PartialEq,
        IndexKey<D>: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        self.in_txn(|index| index.upsert(key, value, base_key))
    }

    /// Update the value indexed by `key` if there is an entry for `key`, otherwise insert `value`
    /// into the base table, using `base_key` to produce the base table key. Returns the base key in
    /// either case.
    ///
    /// Panics (without updating) if the insert/update would make an index non-unique.
    pub fn upsert<Q>(
        &self,
        key: &Q,
        value: &BaseValue<D>,
        base_key: impl FnOnce() -> BaseKey<D>,
    ) -> BaseKey<D>
    where
        BaseKey<D>: Clone + Eq + Hash,
        BaseValue<D>: Clone + PartialEq,
        IndexKey<D>: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        self.try_upsert(key, value, base_key).unwrap()
    }

    /// Delete a row from the table, returning its key in the base table.
    ///
    /// Returns `None` if there is no value for the specified key.
    pub fn delete<Q>(&self, key: &Q) -> Option<BaseKey<D>>
    where
        BaseKey<D>: Clone + Eq + Hash,
        IndexKey<D>: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        self.in_txn(|index| index.delete(key)).unwrap()
    }

    /// Apply `f` to a view of a new transaction which contains only that operation, then commit it.
    ///
    /// Returns the error from committing, if there is one.
    fn in_txn<T>(&self, f: impl FnOnce(&mut IndexTransaction<'_, '_, D>) -> T) -> Result<T> {
        crate::raw::table_in_txn(&self.store, self.owner, |txn| {
            f(&mut IndexTransaction::new(txn))
        })
    }
}

impl<'store, D: IndexDesc> Ops<D::Storage> for &'store Index<D> {
    type ReadLock = RwLockReadGuard<'store, Storage<D::Storage>>;

    fn read_lock(self) -> Self::ReadLock {
        self.store.get_read_lock()
    }
}

// SAFETY: `Ops::read_lock` returns a read lock on the whole store, so there are no mutable references into it.
unsafe impl<D: IndexDesc> IndexedOps<D::Storage> for &Index<D> {
    type IndexDesc = D;
}

/// Read-only, transactional accessor for a table of key/values pairs via an index.
///
/// Usually used via its aliases: [`RoIndexTransaction`] and [`RoRoIndexTransaction`] (built from a
/// read-only or read/write transaction, respectively).
///
/// `D` describes the index table, its base table is `D::BaseTable`. `G` is the storage guard of
/// the transaction.
pub struct IndexGuard<'txn, D: IndexDesc, G> {
    /// Only used to access `D` and `D::BaseTable`.
    /// Invariant: there are no mutating references to `D::BaseTable` or any of its indexes
    /// (including `D`).
    guard: &'txn G,
    owner: Owner,
    _index: PhantomData<D>,
}

/// Read-only, transactional accessor for a table of key/values pairs via an index, built from a
/// read-only transaction.
pub type RoRoIndexTransaction<'txn, D> = IndexGuard<'txn, D, Storage<<D as Desc>::Storage>>;

/// Read-only, transactional accessor for a table of key/values pairs via an index, built from a
/// read/write transaction.
pub type RoIndexTransaction<'guard, 'txn, D> =
    IndexGuard<'txn, D, TransactionInner<'guard, <D as Desc>::Storage>>;

impl<'guard, 'txn, D: IndexDesc> From<&'txn TableTransaction<'guard, D::BaseTable>>
    for RoIndexTransaction<'guard, 'txn, D>
{
    fn from(base: &'txn TableTransaction<'guard, D::BaseTable>) -> Self {
        // Upholds the invariant on `guard`: only `base` can mutate the base
        // table or its indexes, and it can't while it is borrowed for `'txn`.
        IndexGuard {
            guard: base.read_lock(),
            owner: base.owner(),
            _index: PhantomData,
        }
    }
}

impl<'txn, D: IndexDesc> From<&'txn RoTableTransaction<'_, D::BaseTable>>
    for RoRoIndexTransaction<'txn, D>
{
    fn from(base: &'txn RoTableTransaction<'_, D::BaseTable>) -> Self {
        // Upholds the invariant on `guard`: the store is read-locked for `'txn`.
        IndexGuard {
            guard: base.read_lock(),
            owner: base.owner(),
            _index: PhantomData,
        }
    }
}

impl<'txn, D: IndexDesc, G: StorageGuard<D::Storage>> Ops<D::Storage> for &IndexGuard<'txn, D, G> {
    type ReadLock = &'txn G;

    fn read_lock(self) -> Self::ReadLock {
        self.guard
    }
}

// SAFETY: there are no mutating references to `D` or `D::BaseTable`, by `IndexGuard::guard`'s invariant.
unsafe impl<D: IndexDesc, G: StorageGuard<D::Storage>> IndexedOps<D::Storage>
    for &IndexGuard<'_, D, G>
{
    type IndexDesc = D;
}

impl<D: IndexDesc, G: StorageGuard<D::Storage>> IndexGuard<'_, D, G> {
    /// Returns `Ok` if the index is consistent, and an error with some kind of explanation if not.
    pub fn check_consistent(&self) -> Result<()> {
        <&Self as IndexedOps<_>>::check_consistent(self)
    }

    /// Get a row of the table from the store by cloning the value.
    ///
    /// Returns `None` if there is no value for the specified key.
    ///
    /// Panics if the index is inconsistent (see [`Self::check_consistent`]).
    pub fn get<Q>(&self, key: &Q) -> Option<(BaseKey<D>, BaseValue<D>)>
    where
        BaseKey<D>: Clone + Eq + Hash,
        BaseValue<D>: Clone,
        IndexKey<D>: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        <&Self as IndexedOps<_>>::get::<Q>(self, key, self.owner).unwrap()
    }

    /// Get immutable access to a row of the table in the store by reference.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    ///
    /// Panics if the index is inconsistent (see [`Self::check_consistent`]).
    pub fn with<Q, T>(&self, key: &Q, f: impl FnOnce(&BaseKey<D>, &BaseValue<D>) -> T) -> Option<T>
    where
        IndexKey<D>: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        BaseKey<D>: Eq + Hash,
    {
        <&Self as IndexedOps<_>>::with::<Q, T>(self, key, f, self.owner).unwrap()
    }

    /// Iterate all the keys in the index and values in the base table.
    pub fn iter(&self) -> IndexIter<'_, D>
    where
        BaseKey<D>: Eq + Hash,
    {
        // SAFETY: by `IndexGuard::guard`'s invariant.
        unsafe { iter::index_iter::<D>(self.guard) }
    }

    /// Iterate all the keys in the index.
    pub fn keys(&self) -> impl Iterator<Item = &IndexKey<D>>
    where
        BaseKey<D>: Eq + Hash,
    {
        self.iter().map(|(k, ..)| k)
    }
}

impl<'a, D: IndexDesc, G: StorageGuard<D::Storage>> IntoIterator for &'a IndexGuard<'_, D, G>
where
    BaseKey<D>: Eq + Hash,
{
    type Item = (&'a IndexKey<D>, &'a BaseKey<D>, &'a BaseValue<D>);
    type IntoIter = IndexIter<'a, D>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

/// Read/write, transactional accessor for a table of key/value pairs via an index.
///
/// Created via [`TableTransaction::indexes`]. Mutably borrows the base table's view of the
/// transaction, so at most one exists for a base table at any time.
///
/// `D` describes the index table, its base table is `D::BaseTable`.
pub struct IndexTransaction<'guard, 'txn, D: IndexDesc> {
    base: &'txn mut TableTransaction<'guard, D::BaseTable>,
    _index: PhantomData<D>,
}

impl<'guard, 'txn, D: IndexDesc> IndexTransaction<'guard, 'txn, D> {
    /// Create a mutable view of the index `D` from `base`.
    #[doc(hidden)]
    pub fn new(base: &'txn mut TableTransaction<'guard, D::BaseTable>) -> Self {
        IndexTransaction {
            base,
            _index: PhantomData,
        }
    }

    fn base_key<Q>(&self, key: &Q) -> Result<Option<BaseKey<D>>>
    where
        BaseKey<D>: Clone,
        IndexKey<D>: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        BaseKey<D>: Eq + Hash,
    {
        <&Self as IndexedOps<_>>::with_base_key(self, key, Clone::clone)
    }

    /// Returns `Ok` if the index is consistent, and an error with some kind of explanation if not.
    pub fn check_consistent(&self) -> Result<()> {
        <&Self as IndexedOps<_>>::check_consistent(self)
    }

    /// Get a row of the table from the store by cloning the value.
    ///
    /// Returns `None` if there is no value for the specified key.
    ///
    /// Panics if the index is inconsistent (see [`Self::check_consistent`]).
    pub fn get<Q>(&self, key: &Q) -> Option<(BaseKey<D>, BaseValue<D>)>
    where
        BaseKey<D>: Clone + Eq + Hash,
        BaseValue<D>: Clone,
        IndexKey<D>: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        <&Self as IndexedOps<_>>::get::<Q>(self, key, self.base.owner()).unwrap()
    }

    /// Get immutable access to a row of the table in the store by reference.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    ///
    /// Panics if the index is inconsistent (see [`Self::check_consistent`]).
    pub fn with<Q, T>(&self, key: &Q, f: impl FnOnce(&BaseKey<D>, &BaseValue<D>) -> T) -> Option<T>
    where
        IndexKey<D>: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        BaseKey<D>: Eq + Hash,
    {
        <&Self as IndexedOps<_>>::with::<Q, T>(self, key, f, self.base.owner()).unwrap()
    }

    /// Iterate all the keys in the index and values in the base table.
    pub fn iter(&self) -> IndexIter<'_, D>
    where
        BaseKey<D>: Eq + Hash,
    {
        // SAFETY: `self` is borrowed for as long as the iterator is live, so `self.base` cannot
        // mutate the base table or its indexes.
        unsafe { iter::index_iter::<D>(self.read_lock()) }
    }

    /// Iterate all the keys in the index.
    pub fn keys(&self) -> impl Iterator<Item = &IndexKey<D>>
    where
        BaseKey<D>: Eq + Hash,
    {
        self.iter().map(|(k, ..)| k)
    }

    /// Get mutable access to a row of the table. `f` is passed the row's key in the base table and
    /// its value.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    ///
    /// Panics if the index is inconsistent. If `f` makes a unique index key non-unique, the
    /// mutation is applied and the index is poisoned: later accesses via the index will panic, and
    /// committing the transaction will return [`Error::NonUniqueIndexKey`](crate::Error::NonUniqueIndexKey).
    pub fn with_mut<Q, T>(
        &mut self,
        key: &Q,
        f: impl FnOnce(&BaseKey<D>, &mut BaseValue<D>) -> T,
    ) -> Option<T>
    where
        BaseKey<D>: Clone + Eq + Hash,
        BaseValue<D>: Clone + PartialEq,
        IndexKey<D>: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        let base_key = self.base_key(key).unwrap()?;
        self.base.with_mut(&base_key, |v| f(&base_key, v))
    }

    /// Update the value indexed by `key` if there is an entry for `key`, otherwise insert `value`
    /// into the base table, using `base_key` to produce the base table key.
    ///
    /// There is no requirement for the new value to match the current value's index key, and the
    /// index will be updated as a result of this operation.
    ///
    /// Panics if the index is inconsistent. If insert/update makes a unique index key non-unique,
    /// the mutation is applied and the index is poisoned: later accesses via the index will panic,
    /// and committing the transaction will return [`Error::NonUniqueIndexKey`](crate::Error::NonUniqueIndexKey).
    pub fn upsert<Q>(
        &mut self,
        key: &Q,
        value: &BaseValue<D>,
        base_key: impl FnOnce() -> BaseKey<D>,
    ) -> BaseKey<D>
    where
        BaseKey<D>: Clone + Eq + Hash,
        BaseValue<D>: Clone + PartialEq,
        IndexKey<D>: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        if let Some(k) = self.with_mut(key, |k, v| {
            *v = value.clone();
            k.clone()
        }) {
            return k;
        }

        let key = base_key();
        self.base.insert(key.clone(), value.clone());
        key
    }

    /// Delete a row from the table, returning its key in the base table.
    ///
    /// Returns `None` if there is no value for the specified key.
    ///
    /// Panics if the index is inconsistent.
    pub fn delete<Q>(&mut self, key: &Q) -> Option<BaseKey<D>>
    where
        BaseKey<D>: Clone + Eq + Hash,
        IndexKey<D>: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        let base_key = self.base_key(key).unwrap();
        if let Some(base_key) = &base_key {
            self.base.delete(base_key);
        }
        base_key
    }
}

impl<'a, D: IndexDesc> IntoIterator for &'a IndexTransaction<'_, '_, D>
where
    BaseKey<D>: Eq + Hash,
{
    type Item = (&'a IndexKey<D>, &'a BaseKey<D>, &'a BaseValue<D>);
    type IntoIter = IndexIter<'a, D>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, 'guard, D: IndexDesc> Ops<D::Storage> for &'a IndexTransaction<'guard, '_, D> {
    type ReadLock = &'a TransactionInner<'guard, D::Storage>;

    fn read_lock(self) -> Self::ReadLock {
        (&*self.base).read_lock()
    }
}

// SAFETY: `IndexTransaction` holds the only (mutable) reference to the base table's view, and the
// base table and its indexes are only mutated via a mutable borrow of this accessor, which cannot
// coexist with the shared borrow held by `read_lock`'s guard.
unsafe impl<D: IndexDesc> IndexedOps<D::Storage> for &IndexTransaction<'_, '_, D> {
    type IndexDesc = D;
}

#[cfg(test)]
mod test {
    use crate::{Error, Owner, store};

    #[derive(Clone, Debug, PartialEq)]
    pub struct Row {
        pub name: String,
    }

    fn row(name: &str) -> Row {
        Row {
            name: name.to_owned(),
        }
    }

    store!(tables: { Users(u32 => Row; OWNER; index(name: String)) });

    const OWNER: Owner = Owner("owner");

    #[test]
    fn index_get_returns_none_when_absent() {
        let store = KvStore::new();
        assert!(store.Users.indexes(OWNER).name.get("Alice").is_none());
    }

    #[test]
    fn index_get_returns_value_after_base_insert() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));
        let table = store.with_owner(OWNER).Users.indexes().name;
        let value = table.get("Alice").unwrap();
        assert_eq!(value, (1, row("Alice")));
    }

    #[test]
    fn index_with_returns_none_and_does_not_call_f_when_absent() {
        let store = KvStore::new();
        let mut called = false;
        let result = store.Users.indexes(OWNER).name.with("Alice", |_, _| {
            called = true;
        });
        assert!(result.is_none());
        assert!(!called);
    }

    #[test]
    fn index_with_returns_result_of_f() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));
        let len = store.Users.indexes(OWNER).name.with("Alice", |k, v| {
            assert_eq!(*k, 1);
            v.name.len()
        });
        assert_eq!(len, Some(5));
    }

    #[test]
    fn base_remove_makes_index_absent() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));
        store.Users.delete(OWNER, &1);
        assert!(store.Users.indexes(OWNER).name.get("Alice").is_none());
    }

    #[test]
    fn index_iter_empty_on_fresh_store() {
        let store = KvStore::new();
        let index = store.with_owner(OWNER).Users.indexes().name;
        let count = index.with_iter(|i| i.count());
        assert_eq!(count, 0);
    }

    #[test]
    fn index_iter_yields_index_key_and_base_value() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));
        let items: Vec<_> = store
            .Users
            .indexes(OWNER)
            .name
            .with_iter(|i| i.map(|(k, bk, v)| (k.clone(), *bk, v.clone())).collect());
        assert_eq!(items, vec![("Alice".to_owned(), 1, row("Alice"))]);
    }

    #[test]
    fn index_iter_yields_all_rows() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));
        store.Users.insert(OWNER, 2, row("Bob"));
        let mut items: Vec<_> = store
            .Users
            .indexes(OWNER)
            .name
            .with_iter(|i| i.map(|(k, bk, v)| (k.clone(), *bk, v.clone())).collect());
        items.sort_by_key(|(k, ..)| k.clone());
        assert_eq!(
            items,
            vec![
                ("Alice".to_owned(), 1, row("Alice")),
                ("Bob".to_owned(), 2, row("Bob")),
            ]
        );
    }

    #[test]
    fn index_iter_keys_cloned_empty() {
        let store = KvStore::new();
        let table = store.with_owner(OWNER).Users.indexes().name;

        let count = table.with_keys(|i| i.count());
        assert_eq!(count, 0);
    }

    #[test]
    fn index_iter_keys_cloned_yields_index_keys() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));
        store.Users.insert(OWNER, 2, row("Bob"));

        let table = store.with_owner(OWNER).Users.indexes().name;
        let mut keys: Vec<_> = table.with_keys(|i| i.cloned().collect());
        keys.sort();
        assert_eq!(keys, vec!["Alice", "Bob"]);
    }

    #[test]
    fn table_with_values_mut_non_unique_index_key_rolls_back() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));
        store.Users.insert(OWNER, 2, row("Bob"));
        let result = store.Users.try_with_values_mut(OWNER, |values| {
            for v in values {
                v.name = "Alice".to_owned();
            }
        });
        assert!(matches!(result, Err(Error::NonUniqueIndexKey(_))));
        assert_eq!(store.Users.get(OWNER, &2), Some(row("Bob")));
        assert_eq!(
            store.Users.indexes(OWNER).name.get("Bob").unwrap(),
            (2, row("Bob")),
        );
    }

    #[test]
    fn table_with_iter_mut_non_unique_index_key_rolls_back() {
        let store = KvStore::new();
        let users = store.with_owner(OWNER).Users;
        users.insert(1, row("Alice"));
        users.insert(2, row("Bob"));
        let result = users.try_with_iter_mut(|i| {
            for (_, v) in i {
                v.name = "Alice".to_owned();
            }
        });
        assert!(matches!(result, Err(Error::NonUniqueIndexKey(_))));
        assert_eq!(users.get(&2), Some(row("Bob")));
    }

    #[test]
    fn table_retain_updates_index() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));
        store.Users.insert(OWNER, 2, row("Bob"));
        store.Users.retain(OWNER, |k, v| {
            v.name.push('!');
            *k == 1
        });

        let index = store.with_owner(OWNER).Users.indexes().name;
        assert!(index.check_consistent().is_ok());
        assert!(index.get("Alice").is_none());
        assert!(index.get("Bob").is_none());
        assert!(index.get("Bob!").is_none());
        assert_eq!(index.get("Alice!").unwrap(), (1, row("Alice!")));
    }

    // A removed row whose index key is mutated to that of a retained row must not remove the
    // retained row's index entry.
    #[test]
    fn table_retain_removed_row_mutated_to_retained_rows_key_keeps_index_entry() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));
        store.Users.insert(OWNER, 2, row("Bob"));
        store.Users.retain(OWNER, |k, v| {
            if *k == 1 {
                v.name = "Bob".to_owned();
                false
            } else {
                true
            }
        });

        let index = store.with_owner(OWNER).Users.indexes().name;
        assert!(index.check_consistent().is_ok());
        assert!(index.get("Alice").is_none());
        assert_eq!(index.get("Bob").unwrap(), (2, row("Bob")));
    }

    #[test]
    fn table_retain_non_unique_index_key_rolls_back() {
        let store = KvStore::new();
        let users = store.with_owner(OWNER).Users;
        users.insert(1, row("Alice"));
        users.insert(2, row("Bob"));
        users.insert(3, row("Charlie"));
        let result = users.try_retain(|k, v| {
            v.name = "Alice".to_owned();
            *k != 3
        });
        assert!(matches!(result, Err(Error::NonUniqueIndexKey(_))));
        assert_eq!(users.get(&2), Some(row("Bob")));
        assert_eq!(users.get(&3), Some(row("Charlie")));
        assert_eq!(
            users.indexes().name.get("Charlie").unwrap(),
            (3, row("Charlie"))
        );
    }

    #[test]
    #[should_panic(expected = "NonUniqueIndexKey")]
    fn table_retain_non_unique_index_key_panics() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));
        store.Users.insert(OWNER, 2, row("Bob"));
        store.Users.retain(OWNER, |_, v| {
            v.name = "Alice".to_owned();
            true
        });
    }

    #[test]
    fn table_with_iter_mut_updates_index() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));
        store
            .Users
            .with_iter_mut(OWNER, |i| i.next().unwrap().1.name = "Charlie".to_owned());
        assert!(store.Users.indexes(OWNER).name.get("Alice").is_none());
        assert_eq!(
            store.Users.indexes(OWNER).name.get("Charlie").unwrap(),
            (1, row("Charlie")),
        );
    }

    #[test]
    fn base_insert_overwrite_updates_index() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));
        store.Users.insert(OWNER, 1, row("Bob"));

        let index = store.with_owner(OWNER).Users.indexes().name;
        assert!(index.check_consistent().is_ok());
        assert!(index.get("Alice").is_none());
        assert_eq!(index.get("Bob").unwrap(), (1, row("Bob")));
    }

    #[test]
    fn base_with_mut_updates_index() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));
        store
            .Users
            .with_mut(OWNER, &1, |r| r.name = "Bob".to_owned())
            .unwrap();

        let index = store.with_owner(OWNER).Users.indexes().name;
        assert!(index.check_consistent().is_ok());
        assert!(index.get("Alice").is_none());
        assert_eq!(index.get("Bob").unwrap(), (1, row("Bob")));
    }

    #[test]
    fn index_with_values_yields_base_keys_and_values() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));
        store.Users.insert(OWNER, 2, row("Bob"));

        let mut values: Vec<_> = store
            .Users
            .indexes(OWNER)
            .name
            .with_values(|i| i.map(|(bk, v)| (*bk, v.clone())).collect());
        values.sort_by_key(|(bk, _)| *bk);
        assert_eq!(values, vec![(1, row("Alice")), (2, row("Bob"))]);

        let index = store.with_owner(OWNER).Users.indexes().name;
        assert_eq!(index.with_values(|i| i.count()), 2);
    }

    #[test]
    fn index_with_mut_updates_row_and_index() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));
        let result = store.Users.indexes(OWNER).name.with_mut("Alice", |k, v| {
            v.name = "Bob".to_owned();
            (*k, v.name.len())
        });
        assert_eq!(result, Some((1, 3)));

        let index = store.with_owner(OWNER).Users.indexes().name;
        assert!(index.check_consistent().is_ok());
        assert!(index.get("Alice").is_none());
        assert_eq!(index.get("Bob").unwrap(), (1, row("Bob")));
    }

    #[test]
    fn index_with_mut_non_unique_index_key_rolls_back() {
        let store = KvStore::new();
        let users = store.with_owner(OWNER).Users;
        users.insert(1, row("Alice"));
        users.insert(2, row("Bob"));
        let result = users
            .indexes()
            .name
            .try_with_mut("Bob", |_, v| v.name = "Alice".to_owned());
        assert!(matches!(result, Err(Error::NonUniqueIndexKey(_))));
        assert_eq!(users.get(&2), Some(row("Bob")));
        assert_eq!(users.indexes().name.get("Bob").unwrap(), (2, row("Bob")));
    }

    #[test]
    fn index_upsert_inserts_when_absent() {
        let store = KvStore::new();
        let users = store.with_owner(OWNER).Users;
        assert_eq!(users.indexes().name.upsert("Alice", &row("Alice"), || 1), 1);
        assert_eq!(users.get(&1), Some(row("Alice")));
        assert_eq!(
            users.indexes().name.get("Alice").unwrap(),
            (1, row("Alice"))
        );
    }

    #[test]
    fn index_upsert_updates_when_present() {
        let store = KvStore::new();
        let users = store.with_owner(OWNER).Users;
        users.insert(1, row("Alice"));
        let key = users
            .indexes()
            .name
            .upsert("Alice", &row("Bob"), || unreachable!());
        assert_eq!(key, 1);

        let index = users.indexes().name;
        assert!(index.check_consistent().is_ok());
        assert!(index.get("Alice").is_none());
        assert_eq!(index.get("Bob").unwrap(), (1, row("Bob")));
    }

    #[test]
    fn index_try_upsert_non_unique_index_key_rolls_back() {
        let store = KvStore::new();
        let users = store.with_owner(OWNER).Users;
        users.insert(1, row("Alice"));
        users.insert(2, row("Bob"));
        let index = users.indexes().name;

        let result = index.try_upsert("Bob", &row("Alice"), || unreachable!());
        assert!(matches!(result, Err(Error::NonUniqueIndexKey(_))));
        let result = index.try_upsert("Carol", &row("Alice"), || 3);
        assert!(matches!(result, Err(Error::NonUniqueIndexKey(_))));

        assert_eq!(users.get(&2), Some(row("Bob")));
        assert!(users.get(&3).is_none());
        assert!(index.check_consistent().is_ok());
    }
}

#[cfg(test)]
mod test_two_indexes {
    use crate::{Owner, store};

    #[derive(Clone, Debug, PartialEq)]
    pub struct Person {
        pub email: String,
        pub username: Vec<u8>,
    }

    fn person(email: &str, username: &[u8]) -> Person {
        Person {
            email: email.to_owned(),
            username: username.to_owned(),
        }
    }

    store!(tables: { People(u32 => Person; OWNER; index(email: String); index(username: Vec<u8>)) });

    const OWNER: Owner = Owner("owner");

    #[test]
    fn each_index_returns_correct_value() {
        let store = KvStore::new();
        store
            .People
            .insert(OWNER, 1, person("a@example.com", b"alice"));
        store
            .People
            .insert(OWNER, 2, person("b@example.com", b"bob"));

        assert_eq!(
            store
                .People
                .indexes(OWNER)
                .email
                .get("a@example.com")
                .unwrap(),
            (1, person("a@example.com", b"alice"))
        );
        assert_eq!(
            store
                .People
                .indexes(OWNER)
                .username
                .get(b"bob".as_slice())
                .unwrap(),
            (2, person("b@example.com", b"bob"))
        );
    }

    #[test]
    fn base_remove_clears_both_indexes() {
        let store = KvStore::new();
        store
            .People
            .insert(OWNER, 1, person("a@example.com", b"alice"));
        store.People.delete(OWNER, &1);
        assert!(
            store
                .People
                .indexes(OWNER)
                .email
                .get("a@example.com")
                .is_none()
        );
        assert!(
            store
                .People
                .indexes(OWNER)
                .username
                .get(b"alice".as_slice())
                .is_none()
        );
    }

    #[test]
    fn base_clear_clears_both_indexes() {
        let store = KvStore::new();
        store
            .People
            .insert(OWNER, 1, person("a@example.com", b"alice"));
        store.People.clear(OWNER);
        assert!(
            store
                .People
                .indexes(OWNER)
                .email
                .get("a@example.com")
                .is_none()
        );
        assert!(
            store
                .People
                .indexes(OWNER)
                .username
                .get(b"alice".as_slice())
                .is_none()
        );
    }

    #[test]
    fn table_with_iter_mut_updates_both_indexes() {
        let store = KvStore::new();
        store
            .People
            .insert(OWNER, 1, person("a@example.com", b"alice"));
        store.People.with_iter_mut(OWNER, |i| {
            let v = &mut i.next().unwrap().1;
            v.email = "b@example.com".to_owned();
            v.username = b"bob".to_vec();
        });
        assert!(
            store
                .People
                .indexes(OWNER)
                .email
                .get("a@example.com")
                .is_none()
        );
        assert!(
            store
                .People
                .indexes(OWNER)
                .username
                .get(b"alice".as_slice())
                .is_none()
        );
        assert!(
            store
                .People
                .indexes(OWNER)
                .email
                .get("b@example.com")
                .is_some()
        );
        assert!(
            store
                .People
                .indexes(OWNER)
                .username
                .get(b"bob".as_slice())
                .is_some()
        );
    }

    #[test]
    fn txn_mutate_via_each_index() {
        let store = KvStore::new();
        store
            .People
            .insert(OWNER, 1, person("a@example.com", b"alice"));
        store
            .People
            .insert(OWNER, 2, person("b@example.com", b"bob"));

        let mut txn = store.begin_transaction(OWNER);
        let mut indexes = txn.People.indexes();
        indexes
            .email()
            .with_mut("a@example.com", |_, v| v.username = b"carol".to_vec());
        indexes.username().delete(b"bob".as_slice());
        txn.commit().unwrap();

        let indexes = store.with_owner(OWNER).People.indexes();
        assert_eq!(
            indexes.username.get(b"carol".as_slice()).unwrap(),
            (1, person("a@example.com", b"carol"))
        );
        assert!(indexes.email.get("b@example.com").is_none());
    }
}

#[cfg(test)]
mod test_transactional_index {
    use crate::{Error, Owner, store};

    #[derive(Clone, Debug, PartialEq)]
    pub struct Row {
        pub name: String,
        pub age: u32,
    }

    fn row(name: &str) -> Row {
        Row {
            name: name.to_owned(),
            age: 0,
        }
    }

    store!(tables: { Users(u32 => Row; OWNER; index(name: String)) });

    const OWNER: Owner = Owner("owner");

    #[test]
    fn txn_index_get_returns_none_when_absent() {
        let store = KvStore::new();
        let txn = store.begin_transaction(OWNER);
        assert!(txn.Users.ro_indexes().name.get("Alice").is_none());
    }

    #[test]
    fn txn_base_insert_updates_index() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.Users.insert(1, row("Alice"));
        assert_eq!(
            txn.Users.ro_indexes().name.get("Alice").unwrap(),
            (1, row("Alice"))
        );
    }

    #[test]
    fn txn_base_mutate_updates_index_on_field_change() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.Users.insert(1, row("Alice"));
        txn.Users.with_mut(&1, |v| v.name = "Bob".to_owned());
        assert!(txn.Users.ro_indexes().name.get("Alice").is_none());
        assert_eq!(
            txn.Users.ro_indexes().name.get("Bob").unwrap(),
            (
                1,
                Row {
                    name: "Bob".to_owned(),
                    age: 0
                }
            )
        );
    }

    #[test]
    fn txn_base_remove_updates_index() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.Users.insert(1, row("Alice"));
        txn.Users.delete(&1);
        assert!(txn.Users.ro_indexes().name.get("Alice").is_none());
    }

    #[test]
    fn txn_base_clear_updates_index() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.Users.insert(1, row("Alice"));
        txn.Users.insert(2, row("Bob"));
        txn.Users.clear();
        assert!(txn.Users.ro_indexes().name.get("Alice").is_none());
        assert!(txn.Users.ro_indexes().name.get("Bob").is_none());
    }

    #[test]
    fn txn_remove_already_removed_key_keeps_other_rows_index_entry() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));

        let mut txn = store.begin_transaction(OWNER);
        txn.Users.delete(&1);
        txn.Users.insert(2, row("Alice"));
        // A no-op, but row 1's stale value shares an index key with row 2.
        txn.Users.delete(&1);
        assert_eq!(
            txn.Users.ro_indexes().name.get("Alice").unwrap(),
            (2, row("Alice"))
        );
        txn.commit().unwrap();

        assert_eq!(
            store.Users.indexes(OWNER).name.get("Alice").unwrap(),
            (2, row("Alice"))
        );
    }

    #[test]
    fn txn_remove_absent_key_after_clear_keeps_other_rows_index_entry() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));

        let mut txn = store.begin_transaction(OWNER);
        txn.Users.clear();
        txn.Users.insert(2, row("Alice"));
        // A no-op, but row 1's cleared value shares an index key with row 2.
        txn.Users.delete(&1);
        assert_eq!(
            txn.Users.ro_indexes().name.get("Alice").unwrap(),
            (2, row("Alice"))
        );
        txn.commit().unwrap();

        assert_eq!(
            store.Users.indexes(OWNER).name.get("Alice").unwrap(),
            (2, row("Alice"))
        );
    }

    #[test]
    fn txn_base_iter_mut_updates_index_on_field_change() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.Users.insert(1, row("Alice"));
        txn.Users
            .with_iter_mut(|i| i.next().unwrap().1.name = "Charlie".to_owned());
        assert!(txn.Users.ro_indexes().name.get("Alice").is_none());
        assert_eq!(
            txn.Users.ro_indexes().name.get("Charlie").unwrap(),
            (
                1,
                Row {
                    name: "Charlie".to_owned(),
                    age: 0
                }
            )
        );
    }

    #[test]
    fn txn_base_retain_after_clear_keeps_index_consistent() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));

        let mut txn = store.begin_transaction(OWNER);
        txn.Users.clear();
        txn.Users.insert(2, row("Alice"));
        txn.Users.insert(3, row("Bob"));
        txn.Users.retain(|k, _| *k == 2);
        assert_eq!(
            txn.Users.ro_indexes().name.get("Alice").unwrap(),
            (2, row("Alice"))
        );
        assert!(txn.Users.ro_indexes().name.get("Bob").is_none());
        txn.commit().unwrap();

        let index = store.with_owner(OWNER).Users.indexes().name;
        assert!(index.check_consistent().is_ok());
        assert_eq!(index.get("Alice").unwrap(), (2, row("Alice")));
        assert!(index.get("Bob").is_none());
    }

    // Rows inserted after a `clear()` in the same transaction live in the delete
    // mask's pending map, not in `data`. Iterating the base table mutably must still leave those
    // rows correctly indexed.
    #[test]
    fn txn_base_iter_mut_after_clear_keeps_new_rows_indexed() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.Users.insert(1, row("Alice"));
        txn.Users.clear();
        txn.Users.insert(2, row("Bob"));
        txn.Users.with_iter_mut(|i| {
            for (_, v) in i {
                v.name.push('!');
            }
        });
        txn.commit().unwrap();

        let index = store.with_owner(OWNER).Users.indexes().name;
        assert!(index.get("Alice").is_none());
        assert!(index.get("Bob").is_none());
        assert_eq!(index.get("Bob!").unwrap(), (2, row("Bob!")));
    }

    #[test]
    fn txn_base_iter_mut_after_clear_unmodified_stays_indexed() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.Users.clear();
        txn.Users.insert(2, row("Bob"));
        txn.Users.with_iter_mut(|i| i.for_each(|_| {}));
        txn.commit().unwrap();

        let index = store.with_owner(OWNER).Users.indexes().name;
        assert_eq!(index.get("Bob").unwrap(), (2, row("Bob")));
    }

    // Removing a key then iterating mutably: the removed row must not be re-indexed, and a surviving
    // row mutated through the iterator must be re-indexed under its new key.
    #[test]
    fn txn_base_iter_mut_after_remove_keeps_index_consistent() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.Users.insert(1, row("Alice"));
        txn.Users.insert(2, row("Bob"));
        txn.Users.delete(&1);
        txn.Users.with_iter_mut(|i| {
            for (_, v) in i {
                v.name.push('!');
            }
        });
        txn.commit().unwrap();

        let index = store.with_owner(OWNER).Users.indexes().name;
        assert!(index.get("Alice").is_none());
        assert!(index.get("Alice!").is_none());
        assert!(index.get("Bob").is_none());
        assert_eq!(index.get("Bob!").unwrap(), (2, row("Bob!")));
    }

    #[test]
    fn ro_txn_index_get_returns_none_when_absent() {
        let store = KvStore::new();
        let txn = store.begin_ro_transaction(OWNER);
        assert!(txn.Users.indexes().name.get("Alice").is_none());
    }

    #[test]
    fn ro_txn_index_get_returns_value_inserted_before_txn() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));
        let txn = store.begin_ro_transaction(OWNER);
        assert_eq!(
            txn.Users.indexes().name.get("Alice").unwrap(),
            (1, row("Alice"))
        );
    }

    #[test]
    fn ro_txn_index_with_returns_some() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));
        let txn = store.begin_ro_transaction(OWNER);
        assert_eq!(
            txn.Users
                .indexes()
                .name
                .with("Alice", |k, v| {
                    assert_eq!(*k, 1);
                    v.name.len()
                })
                .unwrap(),
            5
        );
    }

    #[test]
    fn ro_txn_index_iter_cloned_yields_rows() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));
        store.Users.insert(OWNER, 2, row("Bob"));
        let txn = store.begin_ro_transaction(OWNER);

        let table = txn.Users.indexes().name;
        let mut rows: Vec<_> = table.iter().collect();
        rows.sort_by(|a, b| a.0.cmp(b.0));
        assert_eq!(
            rows,
            vec![
                (&"Alice".to_owned(), &1, &row("Alice")),
                (&"Bob".to_owned(), &2, &row("Bob"))
            ]
        );
    }

    #[test]
    fn ro_txn_index_keys_yields_index_keys() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));
        store.Users.insert(OWNER, 2, row("Bob"));
        let txn = store.begin_ro_transaction(OWNER);

        let mut keys: Vec<_> = txn.Users.indexes().name.keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, vec!["Alice", "Bob"]);
    }

    #[test]
    fn txn_index_iter_and_keys_see_pending_changes() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));

        let mut txn = store.begin_transaction(OWNER);
        txn.Users.insert(2, row("Bob"));
        txn.Users.delete(&1);
        txn.Users.insert(3, row("Carol"));

        let index = txn.Users.ro_indexes().name;
        let mut rows: Vec<_> = index
            .iter()
            .map(|(k, bk, v)| (k.clone(), *bk, v.clone()))
            .collect();
        rows.sort_by_key(|(_, bk, _)| *bk);
        assert_eq!(
            rows,
            vec![
                ("Bob".to_owned(), 2, row("Bob")),
                ("Carol".to_owned(), 3, row("Carol")),
            ]
        );

        let mut keys: Vec<_> = index.keys().cloned().collect();
        keys.sort();
        assert_eq!(keys, vec!["Bob", "Carol"]);
    }

    #[test]
    fn txn_index_changes_rolled_back_on_drop() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));
        store.Users.insert(OWNER, 2, row("Bob"));
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.Users.insert(3, row("Carol"));
            txn.Users.delete(&1);
            txn.Users.with_mut(&2, |r| r.name = "Robert".to_owned());
        }

        let index = store.with_owner(OWNER).Users.indexes().name;
        assert!(index.check_consistent().is_ok());
        assert!(index.get("Carol").is_none());
        assert!(index.get("Robert").is_none());
        assert_eq!(index.get("Alice").unwrap(), (1, row("Alice")));
        assert_eq!(index.get("Bob").unwrap(), (2, row("Bob")));
    }

    #[test]
    fn txn_index_clear_rolled_back_on_drop() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));
        store.Users.insert(OWNER, 2, row("Bob"));
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.Users.clear();
            // Reuses an index key of a cleared row.
            txn.Users.insert(3, row("Alice"));
        }

        let index = store.with_owner(OWNER).Users.indexes().name;
        assert!(index.check_consistent().is_ok());
        assert_eq!(index.with_keys(|i| i.count()), 2);
        assert_eq!(index.get("Alice").unwrap(), (1, row("Alice")));
        assert_eq!(index.get("Bob").unwrap(), (2, row("Bob")));
    }

    // `with_mut` updates the index after each row, so swapping two rows' index keys one row at a
    // time passes through a state where both rows have the same key, which poisons the index.
    #[test]
    fn txn_swap_index_keys_with_mut_poisons_index() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));
        store.Users.insert(OWNER, 2, row("Bob"));

        let mut txn = store.begin_transaction(OWNER);
        txn.Users.with_mut(&1, |r| r.name = "Bob".to_owned());
        txn.Users.with_mut(&2, |r| r.name = "Alice".to_owned());
        assert_eq!(txn.commit(), Err(Error::NonUniqueIndexKey("Users by name")));

        let index = store.with_owner(OWNER).Users.indexes().name;
        assert_eq!(index.get("Alice").unwrap(), (1, row("Alice")));
        assert_eq!(index.get("Bob").unwrap(), (2, row("Bob")));
    }

    // `with_iter_mut` only rebuilds the index once every row has been visited, so the same swap
    // succeeds.
    #[test]
    fn txn_swap_index_keys_with_iter_mut_succeeds() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));
        store.Users.insert(OWNER, 2, row("Bob"));

        let mut txn = store.begin_transaction(OWNER);
        txn.Users.with_iter_mut(|i| {
            for (_, r) in i {
                r.name = if r.name == "Alice" { "Bob" } else { "Alice" }.to_owned();
            }
        });
        txn.commit().unwrap();

        let index = store.with_owner(OWNER).Users.indexes().name;
        assert!(index.check_consistent().is_ok());
        assert_eq!(index.get("Alice").unwrap(), (2, row("Alice")));
        assert_eq!(index.get("Bob").unwrap(), (1, row("Bob")));
    }

    #[test]
    fn txn_index_with_mut_updates_row_and_index() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));

        let mut txn = store.begin_transaction(OWNER);
        let result = txn.Users.indexes().name().with_mut("Alice", |k, v| {
            v.name = "Bob".to_owned();
            (*k, v.name.len())
        });
        assert_eq!(result, Some((1, 3)));
        txn.commit().unwrap();

        let index = store.with_owner(OWNER).Users.indexes().name;
        assert!(index.get("Alice").is_none());
        assert_eq!(index.get("Bob").unwrap(), (1, row("Bob")));
    }

    #[test]
    fn txn_index_with_mut_non_unique_index_key_fails_commit() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));
        store.Users.insert(OWNER, 2, row("Bob"));

        let mut txn = store.begin_transaction(OWNER);
        let mut indexes = txn.Users.indexes();
        let mut name = indexes.name();
        name.with_mut("Bob", |_, v| v.name = "Alice".to_owned());
        assert!(matches!(
            name.check_consistent(),
            Err(Error::NonUniqueIndexKey(_))
        ));
        assert!(matches!(txn.commit(), Err(Error::NonUniqueIndexKey(_))));
        assert_eq!(store.Users.get(OWNER, &2), Some(row("Bob")));
    }

    #[test]
    fn txn_index_reads_see_mutations() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));

        let mut txn = store.begin_transaction(OWNER);
        let mut indexes = txn.Users.indexes();
        let mut name = indexes.name();
        name.with_mut("Alice", |_, v| v.name = "Bob".to_owned());
        assert!(name.get("Alice").is_none());
        assert_eq!(name.get("Bob").unwrap(), (1, row("Bob")));
        assert_eq!(name.keys().collect::<Vec<_>>(), ["Bob"]);
    }

    #[test]
    fn txn_index_delete_removes_row() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));

        let mut txn = store.begin_transaction(OWNER);
        assert_eq!(txn.Users.indexes().name().delete("Alice"), Some(1));
        assert_eq!(txn.Users.indexes().name().delete("Bob"), None);
        txn.commit().unwrap();

        assert!(store.Users.get(OWNER, &1).is_none());
        assert!(store.Users.indexes(OWNER).name.get("Alice").is_none());
    }

    #[test]
    fn txn_index_upsert_inserts_and_updates() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice"));

        let mut txn = store.begin_transaction(OWNER);
        let mut indexes = txn.Users.indexes();
        let mut name = indexes.name();
        let alice = Row {
            name: "Alice".to_owned(),
            age: 30,
        };
        assert_eq!(name.upsert("Alice", &alice, || unreachable!()), 1);
        assert_eq!(name.upsert("Bob", &row("Bob"), || 2), 2);
        assert_eq!(name.get("Bob").unwrap(), (2, row("Bob")));
        txn.commit().unwrap();

        let index = store.with_owner(OWNER).Users.indexes().name;
        assert!(index.check_consistent().is_ok());
        assert_eq!(index.get("Alice").unwrap(), (1, alice));
        assert_eq!(index.get("Bob").unwrap(), (2, row("Bob")));
    }
}

#[cfg(test)]
mod test_poison {
    use core::panic::AssertUnwindSafe;
    use std::panic::catch_unwind;

    use crate::{Error, Owner, store};

    #[derive(Clone, Debug, PartialEq)]
    pub struct Row {
        pub name: String,
        pub email: String,
    }

    fn row(name: &str, email: &str) -> Row {
        Row {
            name: name.to_owned(),
            email: email.to_owned(),
        }
    }

    store!(
        tables: {
            Users(u32 => Row; OWNER; index(name: String); index(email: String; poison)),
            AssertingUsers(u32 => Row; OWNER; index(name: String; assert)),
            ReplacingUsers(u32 => Row; OWNER; index(name: String; replace)),
            IgnoringUsers(u32 => Row; OWNER; index(name: String; ignore)),
        }
    );

    const OWNER: Owner = Owner("owner");

    #[test]
    fn ops_return_error_when_poisoned() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.Users.insert(1, row("Alice", "alice1@x.com"));
        txn.Users.insert(2, row("Alice", "alice2@x.com"));

        let index_name = txn.Users.ro_indexes().name;
        assert_eq!(
            index_name.check_consistent(),
            Err(Error::NonUniqueIndexKey("Users by name"))
        );
    }

    #[test]
    #[should_panic(expected = "NonUniqueIndexKey")]
    fn get_panics_when_poisoned() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.Users.insert(1, row("Alice", "alice1@x.com"));
        txn.Users.insert(2, row("Alice", "alice2@x.com"));

        txn.Users.ro_indexes().name.get("Alice");
    }

    #[test]
    #[should_panic(expected = "NonUniqueIndexKey")]
    fn with_panics_when_poisoned() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.Users.insert(1, row("Alice", "alice1@x.com"));
        txn.Users.insert(2, row("Alice", "alice2@x.com"));

        txn.Users.ro_indexes().name.with("Alice", |_, _| ());
    }

    #[test]
    fn check_consistent_ok_when_unique() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice", "alice1@x.com"));
        assert!(store.Users.indexes(OWNER).name.check_consistent().is_ok());
    }

    #[test]
    fn base_table_unaffected_when_index_poisoned() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.Users.insert(1, row("Alice", "alice1@x.com"));
        txn.Users.insert(2, row("Alice", "alice2@x.com"));

        // The `name` index is poisoned, but the base table can still be read by primary key.
        assert_eq!(txn.Users.get(&1), Some(row("Alice", "alice1@x.com")));
        assert_eq!(txn.Users.get(&2), Some(row("Alice", "alice2@x.com")));
    }

    #[test]
    fn sibling_index_not_poisoned() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.Users.insert(1, row("Alice", "alice1@x.com"));
        txn.Users.insert(2, row("Alice", "alice2@x.com"));

        // `name` is poisoned (both "Alice")...
        assert!(matches!(
            txn.Users.ro_indexes().name.check_consistent(),
            Err(Error::NonUniqueIndexKey(_))
        ));
        // ...but `email` has distinct keys and stays consistent.
        let email_index = txn.Users.ro_indexes().email;
        assert!(email_index.check_consistent().is_ok());
        assert_eq!(
            email_index.get("alice1@x.com").unwrap(),
            (1, row("Alice", "alice1@x.com"))
        );
        assert_eq!(
            email_index.get("alice2@x.com").unwrap(),
            (2, row("Alice", "alice2@x.com"))
        );
    }

    #[test]
    fn txn_commit_fails_when_index_poisoned() {
        let store = KvStore::new();
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.Users.insert(1, row("Alice", "alice1@x.com"));
            txn.Users.insert(2, row("Alice", "alice2@x.com"));
            assert!(matches!(txn.commit(), Err(Error::NonUniqueIndexKey(_))));
        }

        // The failed commit rolled everything back: the store is clean and consistent.
        assert!(store.Users.get(OWNER, &1).is_none());
        assert!(store.Users.get(OWNER, &2).is_none());
        assert!(store.Users.indexes(OWNER).name.check_consistent().is_ok());
    }

    #[test]
    fn txn_poison_rolled_back_on_drop() {
        let store = KvStore::new();
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.Users.insert(1, row("Alice", "alice1@x.com"));
            txn.Users.insert(2, row("Alice", "alice2@x.com"));
            // dropped without committing
        }

        let index = store.with_owner(OWNER).Users.indexes().name;
        assert!(index.check_consistent().is_ok());
        assert!(index.get("Alice").is_none());
        assert!(store.Users.is_empty());
    }

    #[test]
    fn txn_poison_against_committed_rolled_back() {
        let store = KvStore::new();
        // Commit Alice(1) first, so the "Alice" name-index entry is already committed.
        store.Users.insert(OWNER, 1, row("Alice", "alice1@x.com"));

        {
            // This txn collides with the *already-committed* "Alice" index entry, so the index is
            // poisoned without it ever being recorded as `modified` within the txn.
            let mut txn = store.begin_transaction(OWNER);
            txn.Users.insert(2, row("Alice", "alice2@x.com"));
            // rollback on drop
        }

        // An unrelated, valid commit must succeed — the rolled-back poison must not leak into it.
        let mut txn = store.begin_transaction(OWNER);
        txn.Users.insert(3, row("Bob", "bob@x.com"));
        txn.commit().unwrap();

        let index = store.with_owner(OWNER).Users.indexes().name;
        assert!(
            index.check_consistent().is_ok(),
            "index should not be poisoned after the colliding txn was rolled back"
        );
        assert_eq!(
            index.get("Alice").unwrap(),
            (1, row("Alice", "alice1@x.com"))
        );
        assert_eq!(index.get("Bob").unwrap(), (3, row("Bob", "bob@x.com")));
    }

    #[test]
    fn txn_poison_healed_by_clear() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.Users.insert(1, row("Alice", "alice1@x.com"));
        txn.Users.insert(2, row("Alice", "alice2@x.com"));
        txn.Users.clear();
        txn.Users.insert(3, row("Alice", "alice3@x.com"));
        assert!(txn.Users.ro_indexes().name.check_consistent().is_ok());
        txn.commit().unwrap();

        let index = store.with_owner(OWNER).Users.indexes().name;
        assert_eq!(
            index.get("Alice").unwrap(),
            (3, row("Alice", "alice3@x.com"))
        );
    }

    #[test]
    fn assert_distinct_keys_ok() {
        let store = KvStore::new();
        store
            .AssertingUsers
            .insert(OWNER, 1, row("Alice", "alice1@x.com"));
        store
            .AssertingUsers
            .insert(OWNER, 2, row("Bob", "bob@x.com"));
        assert_eq!(
            store
                .AssertingUsers
                .indexes(OWNER)
                .name
                .get("Alice")
                .unwrap(),
            (1, row("Alice", "alice1@x.com"))
        );
    }

    #[test]
    fn replace_keeps_newest_row() {
        let store = KvStore::new();
        store
            .ReplacingUsers
            .insert(OWNER, 1, row("Alice", "alice1@x.com"));
        store
            .ReplacingUsers
            .insert(OWNER, 2, row("Alice", "alice2@x.com"));
        let index = store.with_owner(OWNER).ReplacingUsers.indexes().name;
        assert_eq!(
            index.get("Alice").unwrap(),
            (2, row("Alice", "alice2@x.com"))
        );

        // Deleting the replaced row does not remove the newer row's entry.
        store.ReplacingUsers.delete(OWNER, &1);
        assert_eq!(
            index.get("Alice").unwrap(),
            (2, row("Alice", "alice2@x.com"))
        );
    }

    #[test]
    fn ignore_keeps_oldest_row() {
        let store = KvStore::new();
        store
            .IgnoringUsers
            .insert(OWNER, 1, row("Alice", "alice1@x.com"));
        store
            .IgnoringUsers
            .insert(OWNER, 2, row("Alice", "alice2@x.com"));
        let index = store.with_owner(OWNER).IgnoringUsers.indexes().name;
        assert_eq!(
            index.get("Alice").unwrap(),
            (1, row("Alice", "alice1@x.com"))
        );

        // Deleting the ignored row does not remove the older row's entry.
        store.IgnoringUsers.delete(OWNER, &2);
        assert_eq!(
            index.get("Alice").unwrap(),
            (1, row("Alice", "alice1@x.com"))
        );
    }

    #[test]
    #[should_panic(expected = "non-unique")]
    fn assert_duplicate_base_insert_panics() {
        let store = KvStore::new();
        store
            .AssertingUsers
            .insert(OWNER, 1, row("Alice", "alice1@x.com"));
        store
            .AssertingUsers
            .insert(OWNER, 2, row("Alice", "alice2@x.com"));
    }

    #[test]
    fn raw_base_try_insert_duplicate_errors_and_rolls_back() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice", "alice1@x.com"));

        // The duplicate "Alice" name-index key makes the insert fail.
        assert!(matches!(
            store
                .Users
                .try_insert(OWNER, 2, row("Alice", "alice2@x.com")),
            Err(Error::NonUniqueIndexKey(_))
        ));

        // The failed insert rolled back: the index is consistent and only the original row remains.
        let index = store.with_owner(OWNER).Users.indexes().name;
        assert!(index.check_consistent().is_ok());
        assert_eq!(
            index.get("Alice").unwrap(),
            (1, row("Alice", "alice1@x.com"))
        );
        assert_eq!(
            store.Users.get(OWNER, &1),
            Some(row("Alice", "alice1@x.com"))
        );
        assert_eq!(store.Users.get(OWNER, &2), None);
    }

    #[test]
    fn raw_base_insert_duplicate_panics_and_rolls_back() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice", "alice1@x.com"));

        let result = catch_unwind(AssertUnwindSafe(|| {
            store.Users.insert(OWNER, 2, row("Alice", "alice2@x.com"));
        }));
        assert!(result.is_err(), "duplicate raw insert should panic");

        // The panicked insert has been rolled back, leaving the store consistent.
        let index = store.with_owner(OWNER).Users.indexes().name;
        assert!(index.check_consistent().is_ok());
        assert_eq!(
            index.get("Alice").unwrap(),
            (1, row("Alice", "alice1@x.com"))
        );
        assert_eq!(store.Users.get(OWNER, &2), None);
    }

    #[test]
    fn raw_with_mut_collision_returns_error_and_rolls_back() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice", "alice1@x.com"));
        store.Users.insert(OWNER, 2, row("Bob", "bob@x.com"));

        // Renaming Bob to "Alice" collides on the `name` index, so the mini-transaction fails.
        assert!(matches!(
            store
                .Users
                .try_with_mut(OWNER, &2, |r| r.name = "Alice".to_owned()),
            Err(Error::NonUniqueIndexKey(_))
        ));

        // Rolled back: Bob is unchanged and the index is consistent.
        assert_eq!(store.Users.get(OWNER, &2), Some(row("Bob", "bob@x.com")));
        let index = store.with_owner(OWNER).Users.indexes().name;
        assert!(index.check_consistent().is_ok());
        assert_eq!(index.get("Bob").unwrap(), (2, row("Bob", "bob@x.com")));
        assert_eq!(
            index.get("Alice").unwrap(),
            (1, row("Alice", "alice1@x.com"))
        );
    }

    #[test]
    fn raw_with_mut_panic_rolls_back() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice", "alice1@x.com"));

        let result = catch_unwind(AssertUnwindSafe(|| {
            let _ = store.Users.with_mut(OWNER, &1, |r| {
                r.name = "Zelda".to_owned();
                panic!("boom");
            });
        }));
        assert!(result.is_err(), "panicking closure should propagate");

        // The mutation (and its index update) rolled back; "Alice" is intact and queryable.
        assert_eq!(
            store.Users.get(OWNER, &1),
            Some(row("Alice", "alice1@x.com"))
        );
        let index = store.with_owner(OWNER).Users.indexes().name;
        assert!(index.check_consistent().is_ok());
        assert_eq!(
            index.get("Alice").unwrap(),
            (1, row("Alice", "alice1@x.com"))
        );
        assert!(index.get("Zelda").is_none());
    }

    #[test]
    fn txn_with_mut_caught_panic_fails_commit() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice", "alice1@x.com"));

        let mut txn = store.begin_transaction(OWNER);
        catch_unwind(AssertUnwindSafe(|| {
            txn.Users.with_mut(&1, |_| panic!("boom"))
        }))
        .unwrap_err();
        // The row's index entries were removed, but not re-added.
        assert_eq!(txn.commit(), Err(Error::TransactionFailed));

        let index = store.with_owner(OWNER).Users.indexes().name;
        assert!(index.check_consistent().is_ok());
        assert_eq!(
            index.get("Alice").unwrap(),
            (1, row("Alice", "alice1@x.com"))
        );
    }

    #[test]
    fn txn_with_iter_mut_caught_panic_fails_commit() {
        let store = KvStore::new();
        store.Users.insert(OWNER, 1, row("Alice", "alice1@x.com"));

        let mut txn = store.begin_transaction(OWNER);
        catch_unwind(AssertUnwindSafe(|| {
            txn.Users.with_iter_mut(|iter| {
                for (_, r) in iter {
                    r.name = "Zelda".to_owned();
                }
                panic!("boom");
            })
        }))
        .unwrap_err();
        // The rows' index entries were removed, but not rebuilt.
        assert_eq!(txn.commit(), Err(Error::TransactionFailed));

        assert_eq!(
            store.Users.get(OWNER, &1),
            Some(row("Alice", "alice1@x.com"))
        );
        let index = store.with_owner(OWNER).Users.indexes().name;
        assert_eq!(
            index.get("Alice").unwrap(),
            (1, row("Alice", "alice1@x.com"))
        );
        assert!(index.get("Zelda").is_none());
    }

    #[test]
    fn txn_assert_caught_panic_fails_commit() {
        let store = KvStore::new();
        store
            .AssertingUsers
            .insert(OWNER, 1, row("Alice", "alice1@x.com"));
        store
            .AssertingUsers
            .insert(OWNER, 2, row("Bob", "bob@x.com"));

        let mut txn = store.begin_transaction(OWNER);
        catch_unwind(AssertUnwindSafe(|| {
            // Removes the "Bob" index entry, then panics adding the (non-unique) "Alice" entry.
            txn.AssertingUsers.insert(2, row("Alice", "alice2@x.com"))
        }))
        .unwrap_err();
        assert_eq!(txn.commit(), Err(Error::TransactionFailed));

        let index = store.with_owner(OWNER).AssertingUsers.indexes().name;
        assert_eq!(index.get("Bob").unwrap(), (2, row("Bob", "bob@x.com")));
    }
}

#[cfg(test)]
mod test_computed_index {
    use crate::{Error, Owner, store};

    #[derive(Clone, Debug, PartialEq)]
    pub struct Post {
        pub tags: Vec<String>,
    }

    fn post(tags: &[&str]) -> Post {
        Post {
            tags: tags.iter().map(|t| (*t).to_owned()).collect(),
        }
    }

    // Each post is indexed under each of its tags, i.e., zero or more keys per row.
    store!(tables: { Posts(u32 => Post; OWNER; index(tag: String = |p: &Post| p.tags.clone())) });

    const OWNER: Owner = Owner("owner");

    #[test]
    fn row_with_no_index_keys_is_not_indexed() {
        let store = KvStore::new();
        store.Posts.insert(OWNER, 1, post(&[]));

        let index = store.with_owner(OWNER).Posts.indexes().tag;
        assert!(index.check_consistent().is_ok());
        assert_eq!(index.with_keys(|i| i.count()), 0);
        assert_eq!(store.Posts.get(OWNER, &1), Some(post(&[])));
    }

    #[test]
    fn row_is_indexed_under_each_key() {
        let store = KvStore::new();
        store.Posts.insert(OWNER, 1, post(&["a", "b"]));
        store.Posts.insert(OWNER, 2, post(&["c"]));

        let index = store.with_owner(OWNER).Posts.indexes().tag;
        assert_eq!(index.get("a").unwrap(), (1, post(&["a", "b"])));
        assert_eq!(index.get("b").unwrap(), (1, post(&["a", "b"])));
        assert_eq!(index.get("c").unwrap(), (2, post(&["c"])));
    }

    #[test]
    fn remove_removes_every_index_key() {
        let store = KvStore::new();
        store.Posts.insert(OWNER, 1, post(&["a", "b"]));
        store.Posts.delete(OWNER, &1);

        let index = store.with_owner(OWNER).Posts.indexes().tag;
        assert_eq!(index.with_keys(|i| i.count()), 0);
    }

    #[test]
    fn with_mut_updates_index_keys() {
        let store = KvStore::new();
        store.Posts.insert(OWNER, 1, post(&["a", "b"]));
        store
            .Posts
            .with_mut(OWNER, &1, |p| p.tags = vec!["b".to_owned(), "c".to_owned()])
            .unwrap();

        let index = store.with_owner(OWNER).Posts.indexes().tag;
        assert!(index.get("a").is_none());
        assert_eq!(index.get("b").unwrap(), (1, post(&["b", "c"])));
        assert_eq!(index.get("c").unwrap(), (1, post(&["b", "c"])));
    }

    #[test]
    fn rows_sharing_an_index_key_poison_the_index() {
        let store = KvStore::new();
        store.Posts.insert(OWNER, 1, post(&["a"]));
        assert_eq!(
            store.Posts.try_insert(OWNER, 2, post(&["b", "a"])),
            Err(Error::NonUniqueIndexKey("Posts by tag"))
        );
        assert_eq!(store.Posts.get(OWNER, &2), None);
    }
}
