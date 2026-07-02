use std::{
    borrow::Borrow,
    hash::Hash,
    sync::{RwLockReadGuard, RwLockWriteGuard},
};

use crate::{
    KvStore, Owner, Result, RoTransaction, Transaction,
    operations::{Base, BaseKey, BaseValue, IndexValue, IndexedOps, IndexedOpsMut, Ops, OpsMut},
    schema::IndexDesc,
    storage::Storage,
};

/// An abstraction for operating on a table of key/values pairs via an index.
///
/// `KvTableIndex` has no transactional semantics and only exists as a convenience for accessing
/// tabular data.
///
/// `D` describes the index table.
/// `B` describes the base table.
///
/// SAFETY: `D` and `B` must describe different tables (this is enforced by the macros, but possible
/// to violate if building a schema by hand).
pub struct KvTableIndex<'store, D: IndexDesc> {
    pub(crate) store: &'store KvStore<D::Storage>,
    pub(crate) owner: Owner,
}

impl<'idx, D: IndexDesc> Ops<D::Storage> for &'idx KvTableIndex<'_, D> {
    type ReadLock = std::sync::RwLockReadGuard<'idx, Storage<D::Storage>>;

    fn read_lock(self) -> Self::ReadLock {
        self.store.get_read_lock()
    }
}

impl<D: IndexDesc> IndexedOps<D::Storage> for &KvTableIndex<'_, D> {
    type IndexDesc = D;
}

impl<'store, D: IndexDesc> KvTableIndex<'store, D> {
    /// The number of key/value pairs in the base table.
    pub fn len(&self) -> usize {
        <&Self as IndexedOps<_>>::len(self)
    }

    /// True if the table is empty.
    pub fn is_empty(&self) -> bool {
        <&Self as IndexedOps<_>>::is_empty(self)
    }

    /// Returns `Ok` if the index is consistent, and an error with some kind of explanation if not.
    pub fn check_consistent(&self) -> Result<()> {
        <&Self as IndexedOps<_>>::check_consistent(self)
    }

    /// Clear the base table by removing all its KVs.
    pub fn clear(&self)
    where
        IndexValue<D>: Eq + Hash,
    {
        let mut txn = self.store.begin_transaction(self.owner);
        let mut txn_table = KvTableTransactionalIndex::<D> { txn: &mut txn };
        IndexedOpsMut::clear(&mut txn_table, self.owner);
        // Should never panic since transaction should only fail on index inserts.
        txn.commit().unwrap();
    }

    /// Get a row of the table from the store by cloning the value.
    ///
    /// Returns `Error::NotPresent` if there is no value for the specified key.
    pub fn get<Q>(&self, key: &Q) -> Result<(BaseKey<D>, BaseValue<D>)>
    where
        BaseKey<D>: Clone,
        BaseValue<D>: Clone,
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOps<_>>::get(self, key, self.owner)
    }

    /// Get immutable access to a row of the table in the store by reference.
    ///
    /// Returns `Error::NotPresent` (and does not call `f`) if there is no value for the specified key.
    pub fn with<Q, T>(&self, key: &Q, f: impl FnOnce(&BaseKey<D>, &BaseValue<D>) -> T) -> Result<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOps<_>>::with::<Q, T>(self, key, f, self.owner)
    }

    /// Insert a value into the table using the base table's key.
    ///
    /// Panics if the value is already indexed with the same index key.
    pub fn insert(&self, key: BaseKey<D>, value: BaseValue<D>)
    where
        IndexValue<D>: Eq + Hash,
    {
        self.try_insert(key, value).unwrap();
    }

    /// Insert a value into the table using the base table's key.
    ///
    /// Returns an error if `insert` would panic.
    pub fn try_insert(&self, key: BaseKey<D>, value: BaseValue<D>) -> Result<()>
    where
        IndexValue<D>: Eq + Hash,
    {
        let mut txn = self.store.begin_transaction(self.owner);
        let mut txn_table = KvTableTransactionalIndex::<D> { txn: &mut txn };
        IndexedOpsMut::insert(&mut txn_table, key, value, self.owner);
        txn.commit()
    }

    /// Get mutable access to a row of the table in the store in the store.
    ///
    /// Returns `Error::NotPresent` (and does not call `f`) if there is no value for the specified key.
    pub fn with_mut<Q, T>(
        &self,
        key: &Q,
        f: impl FnOnce(&BaseKey<D>, &mut BaseValue<D>) -> T,
    ) -> Result<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        BaseKey<D>: Clone,
        BaseValue<D>: Clone,
        IndexValue<D>: Eq + Hash,
    {
        let mut txn = self.store.begin_transaction(self.owner);
        let mut txn_table = KvTableTransactionalIndex::<D> { txn: &mut txn };
        let result = IndexedOpsMut::with_mut(&mut txn_table, key, f, self.owner);
        txn.commit()?;
        result
    }

    /// Remove a row from the table.
    pub fn remove<Q>(&self, key: &Q)
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = D::Key>,
        IndexValue<D>: Eq + Hash + ToOwned<Owned = BaseKey<D>>,
    {
        let mut txn = self.store.begin_transaction(self.owner);
        let mut txn_table = KvTableTransactionalIndex::<D> { txn: &mut txn };
        IndexedOpsMut::remove(&mut txn_table, key, self.owner);
        // Should never panic since transaction should only fail on index inserts.
        txn.commit().unwrap();
    }

    /// Iterate all the keys in the index and value in the base table.
    pub fn iter(&self) -> impl Iterator<Item = (&D::Key, &BaseKey<D>, &BaseValue<D>)>
    where
        D: 'store,
        Base<D>: 'store,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOps<_>>::iter(self, self.owner)
    }

    /// Iterate all the keys in the index.
    pub fn keys(&self) -> impl Iterator<Item = &D::Key>
    where
        D: 'store,
        Base<D>: 'store,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOps<_>>::keys(self, self.owner)
    }

    /// Iterate all the values in the base table.
    pub fn values(&self) -> impl Iterator<Item = (&BaseKey<D>, &BaseValue<D>)>
    where
        D: 'store,
        Base<D>: 'store,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOps<_>>::values(self, self.owner)
    }

    /// Iterate all the key/value pairs in a table.
    ///
    /// If you need a mutable iterator without access scoped by a closure, use `iter_mut` within a
    /// transaction.
    pub fn with_iter_mut<F, T>(&self, mut f: F) -> T
    where
        F: for<'a> FnMut(
            Box<dyn Iterator<Item = (&D::Key, &'a BaseKey<D>, &'a mut BaseValue<D>)> + 'a>,
        ) -> T,
        IndexValue<D>: Eq + Hash + Clone,
        BaseValue<D>: Clone,
    {
        let mut txn = self.store.begin_transaction(self.owner);
        let mut txn_table = KvTableTransactionalIndex::<D> { txn: &mut txn };
        let iter = IndexedOpsMut::iter_mut(&mut txn_table, self.owner);
        let result = f(Box::new(iter));
        // Should never panic since transaction should only fail on index inserts.
        txn.commit().unwrap();
        result
    }
}

/// An abstraction for operating on a table of key/values pairs (accessed as part of a transaction) via an index.
///
/// `D` describes the index table.
/// `B` describes the base table.
///
/// SAFETY: `D` and `B` must describe different tables (this is enforced by the macros, but possible
/// to violate if building a schema by hand).
pub struct KvTableTransactionalIndex<'guard, 'txn, D: IndexDesc> {
    pub(crate) txn: &'txn mut Transaction<'guard, D::Storage>,
}

impl<'guard, 'txn, 'a, D: IndexDesc> Ops<D::Storage>
    for &'a KvTableTransactionalIndex<'guard, 'txn, D>
{
    type ReadLock = &'a RwLockWriteGuard<'guard, Storage<D::Storage>>;

    fn read_lock(self) -> Self::ReadLock {
        &self.txn.guard
    }
}

impl<'guard, 'txn, 'a, D: IndexDesc> OpsMut<D::Storage>
    for &'a mut KvTableTransactionalIndex<'guard, 'txn, D>
{
    type WriteLock = &'a mut RwLockWriteGuard<'guard, Storage<D::Storage>>;

    fn write_lock(self) -> Self::WriteLock {
        &mut self.txn.guard
    }
}

impl<'guard, 'txn, D: IndexDesc> IndexedOps<D::Storage>
    for &KvTableTransactionalIndex<'guard, 'txn, D>
{
    type IndexDesc = D;
}

impl<'guard, 'txn, D: IndexDesc> IndexedOpsMut<D::Storage>
    for &mut KvTableTransactionalIndex<'guard, 'txn, D>
{
    type IndexDesc = D;
}

impl<'guard, 'txn, D: IndexDesc> KvTableTransactionalIndex<'guard, 'txn, D> {
    /// The number of key/value pairs in the base table.
    pub fn len(&self) -> usize {
        <&Self as IndexedOps<_>>::len(self)
    }

    /// True if the table is empty.
    pub fn is_empty(&self) -> bool {
        <&Self as IndexedOps<_>>::is_empty(self)
    }

    pub fn check_consistent(&self) -> Result<()> {
        <&Self as IndexedOps<_>>::check_consistent(self)
    }

    /// Clear the base table by removing all its KVs.
    pub fn clear(&mut self)
    where
        IndexValue<D>: Eq + Hash,
    {
        <&mut Self as IndexedOpsMut<_>>::clear(self, self.txn.owner)
    }

    /// Get a row of the table from the store by cloning the value.
    ///
    /// Returns `Error::NotPresent` if there is no value for the specified key.
    pub fn get<Q>(&self, key: &Q) -> Result<(BaseKey<D>, BaseValue<D>)>
    where
        BaseKey<D>: Clone,
        BaseValue<D>: Clone,
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOps<_>>::get::<Q>(self, key, self.txn.owner)
    }

    /// Get immutable access to a row of the table in the store by reference.
    ///
    /// Returns `Error::NotPresent` (and does not call `f`) if there is no value for the specified key.
    pub fn with<Q, T>(&self, key: &Q, f: impl FnOnce(&BaseKey<D>, &BaseValue<D>) -> T) -> Result<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOps<_>>::with::<Q, T>(self, key, f, self.txn.owner)
    }

    /// Insert a value into the table using the base table's key.
    pub fn insert(&mut self, key: BaseKey<D>, value: BaseValue<D>)
    where
        BaseKey<D>: Clone,
        IndexValue<D>: Eq + Hash,
    {
        <&mut Self as IndexedOpsMut<_>>::insert(self, key, value, self.txn.owner)
    }

    /// Get mutable access to a row of the table in the store in the store.
    ///
    /// Returns `Error::NotPresent` (and does not call `f`) if there is no value for the specified key.
    pub fn with_mut<Q, T>(
        &mut self,
        key: &Q,
        f: impl FnOnce(&BaseKey<D>, &mut BaseValue<D>) -> T,
    ) -> Result<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        BaseKey<D>: Clone,
        BaseValue<D>: Clone,
        IndexValue<D>: Eq + Hash,
    {
        <&mut Self as IndexedOpsMut<_>>::with_mut::<Q, T>(self, key, f, self.txn.owner)
    }

    /// Remove a row from the table.
    pub fn remove<Q>(&mut self, key: &Q)
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = D::Key>,
        IndexValue<D>: Eq + Hash + ToOwned<Owned = BaseKey<D>>,
    {
        <&mut Self as IndexedOpsMut<_>>::remove::<Q>(self, key, self.txn.owner)
    }

    /// Iterate all the keys in the index and value in the base table.
    pub fn iter(&self) -> impl Iterator<Item = (&D::Key, &BaseKey<D>, &BaseValue<D>)>
    where
        D: 'guard,
        Base<D>: 'guard,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOps<_>>::iter(self, self.txn.owner)
    }

    /// Iterate all the keys in the index.
    pub fn keys(&self) -> impl Iterator<Item = &D::Key>
    where
        D: 'guard,
        Base<D>: 'guard,
    {
        <&Self as IndexedOps<_>>::keys(self, self.txn.owner)
    }

    /// Iterate all the values in the base table.
    pub fn values(&self) -> impl Iterator<Item = (&BaseKey<D>, &BaseValue<D>)>
    where
        D: 'guard,
        Base<D>: 'guard,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOps<_>>::values(self, self.txn.owner)
    }

    /// Iterate all the key/value pairs in a table.
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&D::Key, &BaseKey<D>, &mut BaseValue<D>)>
    where
        IndexValue<D>: Eq + Hash + Clone,
        BaseValue<D>: Clone,
    {
        let owner = self.txn.owner;
        IndexedOpsMut::iter_mut(self, owner)
    }

    /// Iterate all the values in a table.
    pub fn values_mut(&mut self) -> impl Iterator<Item = (&BaseKey<D>, &mut BaseValue<D>)>
    where
        IndexValue<D>: Eq + Hash + Clone,
        BaseValue<D>: Clone,
    {
        let owner = self.txn.owner;
        IndexedOpsMut::values_mut(self, owner)
    }
}

/// An abstraction for operating on a table of key/values pairs (accessed as part of a transaction) via an index.
///
/// `D` describes the index table.
/// `B` describes the base table.
///
/// SAFETY: `D` and `B` must describe different tables (this is enforced by the macros, but possible
/// to violate if building a schema by hand).
pub struct KvTableRoTransactionalIndex<'guard, 'txn, D: IndexDesc> {
    pub(crate) txn: &'txn RoTransaction<'guard, D::Storage>,
}

impl<'guard, 'txn, 'a, D: IndexDesc> Ops<D::Storage>
    for &'a KvTableRoTransactionalIndex<'guard, 'txn, D>
{
    type ReadLock = &'a RwLockReadGuard<'guard, Storage<D::Storage>>;

    fn read_lock(self) -> Self::ReadLock {
        &self.txn.guard
    }
}

impl<'guard, 'txn, D: IndexDesc> IndexedOps<D::Storage>
    for &KvTableRoTransactionalIndex<'guard, 'txn, D>
{
    type IndexDesc = D;
}

impl<'guard, 'txn, D: IndexDesc> KvTableRoTransactionalIndex<'guard, 'txn, D> {
    /// The number of key/value pairs in the base table.
    pub fn len(&self) -> usize {
        <&Self as IndexedOps<_>>::len(self)
    }

    /// True if the table is empty.
    pub fn is_empty(&self) -> bool {
        <&Self as IndexedOps<_>>::is_empty(self)
    }

    pub fn check_consistent(&self) -> Result<()> {
        <&Self as IndexedOps<_>>::check_consistent(self)
    }

    /// Get a row of the table from the store by cloning the value.
    ///
    /// Returns `Error::NotPresent` if there is no value for the specified key.
    pub fn get<Q>(&self, key: &Q) -> Result<(BaseKey<D>, BaseValue<D>)>
    where
        BaseKey<D>: Clone,
        BaseValue<D>: Clone,
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOps<_>>::get::<Q>(self, key, self.txn.owner)
    }

    /// Get immutable access to a row of the table in the store by reference.
    ///
    /// Returns `Error::NotPresent` (and does not call `f`) if there is no value for the specified key.
    pub fn with<Q, T>(&self, key: &Q, f: impl FnOnce(&BaseKey<D>, &BaseValue<D>) -> T) -> Result<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOps<_>>::with::<Q, T>(self, key, f, self.txn.owner)
    }

    /// Iterate all the keys in the index and value in the base table.
    pub fn iter(&self) -> impl Iterator<Item = (&D::Key, &BaseKey<D>, &BaseValue<D>)>
    where
        D: 'guard,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOps<_>>::iter(self, self.txn.owner)
    }

    /// Iterate all the keys in the index.
    pub fn keys(&self) -> impl Iterator<Item = &D::Key>
    where
        D: 'guard,
    {
        <&Self as IndexedOps<_>>::keys(self, self.txn.owner)
    }

    /// Iterate all the values in the base table.
    pub fn values(&self) -> impl Iterator<Item = (&BaseKey<D>, &BaseValue<D>)>
    where
        D: 'guard,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOps<_>>::values(self, self.txn.owner)
    }
}

#[cfg(test)]
mod test {
    use crate::{KvErrorExt, store};

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

    const OWNER: &str = "owner";
    const OTHER: &str = "other";

    #[test]
    fn index_len_is_zero_on_fresh_store() {
        let store = KvStore::new();
        assert_eq!(store.table_by::<index::Users::name>(OWNER).len(), 0);
    }

    #[test]
    fn index_is_empty_on_fresh_store() {
        let store = KvStore::new();
        assert!(store.table_by::<index::Users::name>(OWNER).is_empty());
    }

    #[test]
    fn index_len_increases_with_inserts() {
        let store = KvStore::new();
        let index = store.table_by::<index::Users::name>(OWNER);
        index.insert(1, row("Alice"));
        index.insert(2, row("Bob"));
        assert_eq!(index.len(), 2);
    }

    #[test]
    fn index_is_empty_false_after_insert() {
        let store = KvStore::new();
        store
            .table_by::<index::Users::name>(OWNER)
            .insert(1, row("Alice"));
        assert!(!store.table_by::<index::Users::name>(OWNER).is_empty());
    }

    #[test]
    fn index_get_returns_none_when_absent() {
        let store = KvStore::new();
        assert!(
            store
                .table_by::<index::Users::name>(OWNER)
                .get("Alice")
                .is_none()
        );
    }

    #[test]
    fn index_get_returns_value_after_base_insert() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        let table = store.table_by::<index::Users::name>(OWNER);
        let value = table.get("Alice").unwrap();
        assert_eq!(value, (1, row("Alice")));
    }

    #[test]
    fn index_get_returns_value_after_index_insert() {
        let store = KvStore::new();
        store
            .table_by::<index::Users::name>(OWNER)
            .insert(1, row("Alice"));

        let table = store.table_by::<index::Users::name>(OWNER);

        let value = table.get("Alice").unwrap();
        assert_eq!(value, (1, row("Alice")));
    }

    #[test]
    fn index_with_returns_none_and_does_not_call_f_when_absent() {
        let store = KvStore::new();
        let mut called = false;
        let result = store
            .table_by::<index::Users::name>(OWNER)
            .with("Alice", |_, _| {
                called = true;
            });
        assert!(result.is_none());
        assert!(!called);
    }

    #[test]
    fn index_with_returns_result_of_f() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        let len = store
            .table_by::<index::Users::name>(OWNER)
            .with("Alice", |k, v| {
                assert_eq!(*k, 1);
                v.name.len()
            });
        assert_eq!(len.unwrap_opt(), Some(5));
    }

    #[test]
    fn index_insert_is_visible_via_base_table() {
        let store = KvStore::new();
        store
            .table_by::<index::Users::name>(OWNER)
            .insert(1, row("Alice"));
        let value = store.table::<Users>(OWNER).get(&1).unwrap();
        assert_eq!(value, row("Alice"));
    }

    #[test]
    fn base_insert_is_visible_via_index() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        assert!(
            store
                .table_by::<index::Users::name>(OWNER)
                .get("Alice")
                .is_some()
        );
    }

    #[test]
    fn index_remove_makes_base_absent() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        store.table_by::<index::Users::name>(OWNER).remove("Alice");
        assert!(store.table::<Users>(OWNER).get(&1).is_none());
    }

    #[test]
    fn index_remove_makes_index_absent() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        store.table_by::<index::Users::name>(OWNER).remove("Alice");
        assert!(
            store
                .table_by::<index::Users::name>(OWNER)
                .get("Alice")
                .is_none()
        );
    }

    #[test]
    fn base_remove_makes_index_absent() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        store.table::<Users>(OWNER).remove(&1);
        assert!(
            store
                .table_by::<index::Users::name>(OWNER)
                .get("Alice")
                .is_none()
        );
    }

    #[test]
    fn index_mutate_returns_none_when_absent() {
        let store = KvStore::new();
        let result = store
            .table_by::<index::Users::name>(OWNER)
            .with_mut("Alice", |_, v| v.name.len());
        assert!(result.is_none());
    }

    #[test]
    fn index_mutate_modifies_value() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        store
            .table_by::<index::Users::name>(OWNER)
            .with_mut("Alice", |k, v| {
                assert_eq!(*k, 1);
                v.name.push_str(" Smith")
            })
            .unwrap();
        let value = store.table::<Users>(OWNER).get(&1).unwrap();
        assert_eq!(value.name, "Alice Smith");
    }

    #[test]
    fn index_mutate_updates_index_on_field_change() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        store
            .table_by::<index::Users::name>(OWNER)
            .with_mut("Alice", |_, v| {
                v.name = "Charlie".to_owned();
            })
            .unwrap();
        assert!(
            store
                .table_by::<index::Users::name>(OWNER)
                .get("Alice")
                .is_none()
        );
        let value = store
            .table_by::<index::Users::name>(OWNER)
            .get("Charlie")
            .unwrap();
        assert_eq!(value, (1, row("Charlie")));
    }

    #[test]
    fn index_clear_removes_all_rows() {
        let store = KvStore::new();
        let index = store.table_by::<index::Users::name>(OWNER);
        index.insert(1, row("Alice"));
        index.insert(2, row("Bob"));
        index.clear();
        assert!(index.is_empty());
    }

    #[test]
    fn index_clear_removes_index_entries() {
        let store = KvStore::new();
        let index = store.table_by::<index::Users::name>(OWNER);
        index.insert(1, row("Alice"));
        index.clear();
        assert!(index.get("Alice").is_none());
    }

    #[test]
    fn base_clear_removes_index_entries() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        store.table::<Users>(OWNER).clear();
        assert!(
            store
                .table_by::<index::Users::name>(OWNER)
                .get("Alice")
                .is_none()
        );
    }

    #[test]
    fn index_iter_empty_on_fresh_store() {
        let store = KvStore::new();
        let index = store.table_by::<index::Users::name>(OWNER);
        let items: Vec<_> = index.iter().collect();
        assert!(items.is_empty());
    }

    #[test]
    fn index_iter_yields_index_key_and_base_value() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        let items: Vec<_> = store
            .table_by::<index::Users::name>(OWNER)
            .iter()
            .map(|(k, bk, v)| (k.clone(), *bk, v.clone()))
            .collect();
        assert_eq!(items, vec![("Alice".to_owned(), 1, row("Alice"))]);
    }

    #[test]
    fn index_iter_yields_all_rows() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        store.table::<Users>(OWNER).insert(2, row("Bob"));
        let mut items: Vec<_> = store
            .table_by::<index::Users::name>(OWNER)
            .iter()
            .map(|(k, bk, v)| (k.clone(), *bk, v.clone()))
            .collect();
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
        let table = store.table_by::<index::Users::name>(OWNER);

        let keys: Vec<_> = table.keys().collect();
        assert!(keys.is_empty());
    }

    #[test]
    fn index_iter_keys_cloned_yields_index_keys() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        store.table::<Users>(OWNER).insert(2, row("Bob"));

        let table = store.table_by::<index::Users::name>(OWNER);
        let mut keys: Vec<_> = table.keys().collect();
        keys.sort();
        assert_eq!(keys, vec!["Alice", "Bob"]);
    }

    #[test]
    fn index_iter_values_cloned_empty() {
        let store = KvStore::new();
        let table = store.table_by::<index::Users::name>(OWNER);
        let values: Vec<_> = table.values().collect();
        assert!(values.is_empty());
    }

    #[test]
    fn index_iter_values_cloned_yields_base_values() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        store.table::<Users>(OWNER).insert(2, row("Bob"));
        let table = store.table_by::<index::Users::name>(OWNER);
        let mut values: Vec<_> = table.values().collect();
        values.sort_by_key(|(_, r)| r.name.clone());
        assert_eq!(values, vec![(&1, &row("Alice")), (&2, &row("Bob"))]);
    }

    #[test]
    fn index_for_each_empty_calls_closure_zero_times() {
        let store = KvStore::new();
        let index = store.table_by::<index::Users::name>(OWNER);
        let mut count = 0;
        index.iter().for_each(|_| count += 1);
        assert_eq!(count, 0);
    }

    #[test]
    fn index_for_each_yields_index_key_and_base_value() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        let index = store.table_by::<index::Users::name>(OWNER);
        let mut items: Vec<_> = Vec::new();
        index
            .iter()
            .for_each(|(k, bk, v)| items.push((k.clone(), *bk, v.clone())));
        assert_eq!(items, vec![("Alice".to_owned(), 1, row("Alice"))]);
    }

    #[test]
    fn index_for_each_yields_all_rows() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        store.table::<Users>(OWNER).insert(2, row("Bob"));
        let index = store.table_by::<index::Users::name>(OWNER);
        let mut items: Vec<_> = Vec::new();
        index
            .iter()
            .for_each(|(k, bk, v)| items.push((k.clone(), *bk, v.clone())));
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
    fn index_with_iter_mut_modifies_base_values() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        let index = store.table_by::<index::Users::name>(OWNER);
        index.with_iter_mut(|mut i| i.next().unwrap().2.name.push('!'));
        assert_eq!(store.table::<Users>(OWNER).get(&1), Some(row("Alice!")));
    }

    #[test]
    fn table_with_iter_mut_updates_index() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        store
            .table::<Users>(OWNER)
            .with_iter_mut(|mut i| i.next().unwrap().1.name = "Charlie".to_owned());
        assert!(
            store
                .table_by::<index::Users::name>(OWNER)
                .get("Alice")
                .is_none()
        );
        assert_eq!(
            store
                .table_by::<index::Users::name>(OWNER)
                .get("Charlie")
                .unwrap(),
            (1, row("Charlie")),
        );
    }

    #[test]
    fn index_with_iter_mut_updates_index() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        store
            .table_by::<index::Users::name>(OWNER)
            .with_iter_mut(|mut i| i.next().unwrap().2.name = "Charlie".to_owned());
        assert!(
            store
                .table_by::<index::Users::name>(OWNER)
                .get("Alice")
                .is_none()
        );
        assert_eq!(
            store
                .table_by::<index::Users::name>(OWNER)
                .get("Charlie")
                .unwrap(),
            (1, row("Charlie"))
        );
    }

    #[test]
    fn index_with_iter_mut_empty_yields_none() {
        let store = KvStore::new();
        let index = store.table_by::<index::Users::name>(OWNER);
        let count = index.with_iter_mut(|i| i.count());
        assert_eq!(count, 0);
    }

    // Mutating every row through a multi-row index iterator must rebuild the index for all of
    // them (the single-row tests can't catch aliasing or partial-rebuild bugs).
    #[test]
    fn index_with_iter_mut_updates_all_rows() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        store.table::<Users>(OWNER).insert(2, row("Bob"));
        store
            .table_by::<index::Users::name>(OWNER)
            .with_iter_mut(|i| {
                for (_, _, v) in i {
                    v.name.push('!');
                }
            });
        let index = store.table_by::<index::Users::name>(OWNER);
        assert!(index.get("Alice").is_none());
        assert!(index.get("Bob").is_none());
        assert_eq!(index.get("Alice!").unwrap(), (1, row("Alice!")));
        assert_eq!(index.get("Bob!").unwrap(), (2, row("Bob!")));
    }

    // Visiting a row without mutating it still tears down and rebuilds its index entry (via
    // `get_mut` -> `on_remove` then `rebuild_indexes_for_key` on drop), so a row left unchanged
    // must remain correctly indexed alongside one that was changed.
    #[test]
    fn index_with_iter_mut_visited_unmodified_row_stays_indexed() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        store.table::<Users>(OWNER).insert(2, row("Bob"));
        store
            .table_by::<index::Users::name>(OWNER)
            .with_iter_mut(|i| {
                for (_, base_key, v) in i {
                    if *base_key == 1 {
                        v.name = "Zara".to_owned();
                    }
                }
            });
        let index = store.table_by::<index::Users::name>(OWNER);
        assert!(index.get("Alice").is_none());
        assert_eq!(index.get("Zara").unwrap(), (1, row("Zara")));
        // Bob was visited but not modified; its index entry must be intact.
        assert_eq!(index.get("Bob").unwrap(), (2, row("Bob")));
    }

    #[test]
    #[cfg_attr(debug_assertions, should_panic(expected = "Ownership violation"))]
    fn index_insert_wrong_owner_panics() {
        let store = KvStore::new();
        store
            .table_by::<index::Users::name>(OTHER)
            .insert(1, row("Alice"));
    }

    #[test]
    #[cfg_attr(debug_assertions, should_panic(expected = "Ownership violation"))]
    fn index_clear_wrong_owner_panics() {
        let store = KvStore::new();
        store.table_by::<index::Users::name>(OTHER).clear();
    }
}

#[cfg(test)]
mod test_two_indexes {
    use crate::{KvErrorExt, store};

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

    const OWNER: &str = "owner";

    #[test]
    fn both_indexes_queryable_after_base_insert() {
        let store = KvStore::new();
        store
            .table::<People>(OWNER)
            .insert(1, person("a@example.com", b"alice"));
        assert!(
            store
                .table_by::<index::People::email>(OWNER)
                .get("a@example.com")
                .is_some()
        );
        assert!(
            store
                .table_by::<index::People::username>(OWNER)
                .get(b"alice".as_slice())
                .is_some()
        );
    }

    #[test]
    fn both_indexes_queryable_after_email_index_insert() {
        let store = KvStore::new();
        store
            .table_by::<index::People::email>(OWNER)
            .insert(1, person("a@example.com", b"alice"));
        assert_eq!(
            store
                .table_by::<index::People::email>(OWNER)
                .get("a@example.com")
                .unwrap(),
            (1, person("a@example.com", b"alice"))
        );
        assert_eq!(
            store
                .table_by::<index::People::username>(OWNER)
                .get(b"alice".as_slice())
                .unwrap(),
            (1, person("a@example.com", b"alice"))
        );
    }

    #[test]
    fn both_indexes_queryable_after_username_index_insert() {
        let store = KvStore::new();
        store
            .table_by::<index::People::username>(OWNER)
            .insert(1, person("a@example.com", b"alice"));
        assert_eq!(
            store
                .table_by::<index::People::email>(OWNER)
                .get("a@example.com")
                .unwrap(),
            (1, person("a@example.com", b"alice"))
        );
        assert_eq!(
            store
                .table_by::<index::People::username>(OWNER)
                .get(b"alice".as_slice())
                .unwrap(),
            (1, person("a@example.com", b"alice"))
        );
    }

    #[test]
    fn each_index_returns_correct_value() {
        let store = KvStore::new();
        store
            .table::<People>(OWNER)
            .insert(1, person("a@example.com", b"alice"));
        store
            .table::<People>(OWNER)
            .insert(2, person("b@example.com", b"bob"));

        assert_eq!(
            store
                .table_by::<index::People::email>(OWNER)
                .get("a@example.com")
                .unwrap(),
            (1, person("a@example.com", b"alice"))
        );
        assert_eq!(
            store
                .table_by::<index::People::username>(OWNER)
                .get(b"bob".as_slice())
                .unwrap(),
            (2, person("b@example.com", b"bob"))
        );
    }

    #[test]
    fn base_remove_clears_both_indexes() {
        let store = KvStore::new();
        store
            .table::<People>(OWNER)
            .insert(1, person("a@example.com", b"alice"));
        store.table::<People>(OWNER).remove(&1);
        assert!(
            store
                .table_by::<index::People::email>(OWNER)
                .get("a@example.com")
                .is_none()
        );
        assert!(
            store
                .table_by::<index::People::username>(OWNER)
                .get(b"alice".as_slice())
                .is_none()
        );
    }

    #[test]
    fn email_index_remove_clears_both_indexes() {
        let store = KvStore::new();
        store
            .table::<People>(OWNER)
            .insert(1, person("a@example.com", b"alice"));
        store
            .table_by::<index::People::email>(OWNER)
            .remove("a@example.com");
        assert!(
            store
                .table_by::<index::People::email>(OWNER)
                .get("a@example.com")
                .is_none()
        );
        assert!(
            store
                .table_by::<index::People::username>(OWNER)
                .get(b"alice".as_slice())
                .is_none()
        );
    }

    #[test]
    fn username_index_remove_clears_both_indexes() {
        let store = KvStore::new();
        store
            .table::<People>(OWNER)
            .insert(1, person("a@example.com", b"alice"));
        store
            .table_by::<index::People::username>(OWNER)
            .remove(b"alice".as_slice());
        assert!(
            store
                .table_by::<index::People::email>(OWNER)
                .get("a@example.com")
                .is_none()
        );
        assert!(
            store
                .table_by::<index::People::username>(OWNER)
                .get(b"alice".as_slice())
                .is_none()
        );
    }

    #[test]
    fn index_remove_removes_from_base_table() {
        let store = KvStore::new();
        store
            .table::<People>(OWNER)
            .insert(1, person("a@example.com", b"alice"));
        store
            .table_by::<index::People::email>(OWNER)
            .remove("a@example.com");
        assert!(store.table::<People>(OWNER).get(&1).is_none());
    }

    #[test]
    fn base_clear_clears_both_indexes() {
        let store = KvStore::new();
        store
            .table::<People>(OWNER)
            .insert(1, person("a@example.com", b"alice"));
        store.table::<People>(OWNER).clear();
        assert!(
            store
                .table_by::<index::People::email>(OWNER)
                .get("a@example.com")
                .is_none()
        );
        assert!(
            store
                .table_by::<index::People::username>(OWNER)
                .get(b"alice".as_slice())
                .is_none()
        );
    }

    #[test]
    fn email_index_clear_clears_both_indexes() {
        let store = KvStore::new();
        store
            .table::<People>(OWNER)
            .insert(1, person("a@example.com", b"alice"));
        store.table_by::<index::People::email>(OWNER).clear();
        assert!(
            store
                .table_by::<index::People::email>(OWNER)
                .get("a@example.com")
                .is_none()
        );
        assert!(
            store
                .table_by::<index::People::username>(OWNER)
                .get(b"alice".as_slice())
                .is_none()
        );
    }

    #[test]
    fn table_with_iter_mut_updates_both_indexes() {
        let store = KvStore::new();
        store
            .table::<People>(OWNER)
            .insert(1, person("a@example.com", b"alice"));
        store.table::<People>(OWNER).with_iter_mut(|mut i| {
            let v = &mut i.next().unwrap().1;
            v.email = "b@example.com".to_owned();
            v.username = b"bob".to_vec();
        });
        assert!(
            store
                .table_by::<index::People::email>(OWNER)
                .get("a@example.com")
                .is_none()
        );
        assert!(
            store
                .table_by::<index::People::username>(OWNER)
                .get(b"alice".as_slice())
                .is_none()
        );
        assert!(
            store
                .table_by::<index::People::email>(OWNER)
                .get("b@example.com")
                .is_some()
        );
        assert!(
            store
                .table_by::<index::People::username>(OWNER)
                .get(b"bob".as_slice())
                .is_some()
        );
    }

    #[test]
    fn email_index_with_iter_mut_updates_both_indexes() {
        let store = KvStore::new();
        store
            .table::<People>(OWNER)
            .insert(1, person("a@example.com", b"alice"));
        store
            .table_by::<index::People::email>(OWNER)
            .with_iter_mut(|iter| {
                iter.for_each(|(_, _, v)| {
                    v.email = "b@example.com".to_owned();
                    v.username = b"bob".to_vec();
                });
            });
        assert!(
            store
                .table_by::<index::People::email>(OWNER)
                .get("a@example.com")
                .is_none()
        );
        assert!(
            store
                .table_by::<index::People::username>(OWNER)
                .get(b"alice".as_slice())
                .is_none()
        );
        assert!(
            store
                .table_by::<index::People::email>(OWNER)
                .get("b@example.com")
                .is_some()
        );
        assert!(
            store
                .table_by::<index::People::username>(OWNER)
                .get(b"bob".as_slice())
                .is_some()
        );
    }
}

#[cfg(test)]
mod test_transactional_index {
    use crate::{KvErrorExt, store};

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

    const OWNER: &str = "owner";
    const OTHER: &str = "other";

    #[test]
    fn txn_index_get_returns_none_when_absent() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        assert!(txn.table_by::<index::Users::name>().get("Alice").is_none());
    }

    #[test]
    fn txn_index_insert_is_visible_via_index() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table_by::<index::Users::name>().insert(1, row("Alice"));
        assert_eq!(
            txn.table_by::<index::Users::name>().get("Alice").unwrap(),
            (1, row("Alice"))
        );
        txn.commit().unwrap();
        assert_eq!(
            store
                .table_by::<index::Users::name>(OWNER)
                .get("Alice")
                .unwrap(),
            (1, row("Alice"))
        );

        let mut txn = store.begin_transaction(OWNER);
        txn.table_by::<index::Users::name>().remove("Alice");
        txn.commit().unwrap();
        assert!(
            store
                .table_by::<index::Users::name>(OWNER)
                .get("Alice")
                .is_none()
        );
    }

    #[test]
    fn txn_index_insert_is_visible_via_base() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table_by::<index::Users::name>().insert(1, row("Alice"));
        assert_eq!(txn.table::<Users>().get(&1), Some(row("Alice")));
    }

    #[test]
    fn txn_index_with_returns_some_after_insert() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table_by::<index::Users::name>().insert(1, row("Alice"));
        assert_eq!(
            txn.table_by::<index::Users::name>()
                .with("Alice", |k, v| {
                    assert_eq!(*k, 1);
                    v.name.len()
                })
                .unwrap(),
            5
        );
    }

    #[test]
    fn txn_index_mutate_updates_index_on_field_change() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table_by::<index::Users::name>().insert(1, row("Alice"));
        txn.table_by::<index::Users::name>()
            .with_mut("Alice", |_, v| v.name = "Bob".to_owned())
            .unwrap();
        assert!(txn.table_by::<index::Users::name>().get("Alice").is_none());
        assert_eq!(
            txn.table_by::<index::Users::name>().get("Bob").unwrap(),
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
    fn txn_index_mutate_non_indexed_field_preserves_index() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table_by::<index::Users::name>().insert(1, row("Alice"));
        txn.table_by::<index::Users::name>()
            .with_mut("Alice", |_, v| v.age = 42)
            .unwrap();
        assert_eq!(
            txn.table_by::<index::Users::name>().get("Alice").unwrap(),
            (
                1,
                Row {
                    name: "Alice".to_owned(),
                    age: 42
                }
            )
        );
    }

    #[test]
    fn txn_index_remove_removes_from_index() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table_by::<index::Users::name>().insert(1, row("Alice"));
        txn.table_by::<index::Users::name>().remove("Alice");
        assert!(txn.table_by::<index::Users::name>().get("Alice").is_none());
    }

    #[test]
    fn txn_index_remove_removes_from_base() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table_by::<index::Users::name>().insert(1, row("Alice"));
        txn.table_by::<index::Users::name>().remove("Alice");
        assert!(txn.table::<Users>().get(&1).is_none());
        txn.commit().unwrap();
        assert!(store.table::<Users>(OWNER).get(&1).is_none());
    }

    #[test]
    fn txn_index_clear_removes_from_index() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table_by::<index::Users::name>().insert(1, row("Alice"));
        txn.table_by::<index::Users::name>().insert(2, row("Bob"));
        txn.table_by::<index::Users::name>().clear();
        assert!(txn.table_by::<index::Users::name>().get("Alice").is_none());
        assert!(txn.table_by::<index::Users::name>().get("Bob").is_none());
    }

    #[test]
    fn txn_index_iter_mut_updates_index_on_field_change() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table_by::<index::Users::name>().insert(1, row("Alice"));
        txn.table_by::<index::Users::name>()
            .iter_mut()
            .for_each(|(_, _, v)| v.name = "Charlie".to_owned());
        assert!(txn.table_by::<index::Users::name>().get("Alice").is_none());
        assert_eq!(
            txn.table_by::<index::Users::name>().get("Charlie").unwrap(),
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
    fn txn_index_values_mut_updates_index_on_field_change() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table_by::<index::Users::name>().insert(1, row("Alice"));
        txn.table_by::<index::Users::name>()
            .values_mut()
            .for_each(|(_, v)| v.name = "Charlie".to_owned());
        assert!(txn.table_by::<index::Users::name>().get("Alice").is_none());
        assert_eq!(
            txn.table_by::<index::Users::name>().get("Charlie").unwrap(),
            (
                1,
                Row {
                    name: "Charlie".to_owned(),
                    age: 0
                }
            )
        );
    }

    // Multi-row transactional index mutation: every row must be re-indexed under its new key.
    #[test]
    fn txn_index_iter_mut_updates_multiple_rows() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table_by::<index::Users::name>().insert(1, row("Alice"));
        txn.table_by::<index::Users::name>().insert(2, row("Bob"));
        txn.table_by::<index::Users::name>()
            .iter_mut()
            .for_each(|(_, _, v)| v.name.push('!'));

        assert!(txn.table_by::<index::Users::name>().get("Alice").is_none());
        assert!(txn.table_by::<index::Users::name>().get("Bob").is_none());
        assert_eq!(
            txn.table_by::<index::Users::name>().get("Alice!").unwrap(),
            (1, row("Alice!"))
        );
        assert_eq!(
            txn.table_by::<index::Users::name>().get("Bob!").unwrap(),
            (2, row("Bob!"))
        );
    }

    // A row visited by the index iterator but left unmodified must remain correctly indexed.
    #[test]
    fn txn_index_iter_mut_visited_unmodified_row_stays_indexed() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table_by::<index::Users::name>().insert(1, row("Alice"));
        txn.table_by::<index::Users::name>().insert(2, row("Bob"));
        txn.table_by::<index::Users::name>()
            .iter_mut()
            .for_each(|(_, base_key, v)| {
                if *base_key == 1 {
                    v.name = "Zara".to_owned();
                }
            });

        assert!(txn.table_by::<index::Users::name>().get("Alice").is_none());
        assert_eq!(
            txn.table_by::<index::Users::name>().get("Zara").unwrap(),
            (1, row("Zara"))
        );
        assert_eq!(
            txn.table_by::<index::Users::name>().get("Bob").unwrap(),
            (2, row("Bob"))
        );
    }

    #[test]
    fn txn_base_insert_updates_index() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Users>().insert(1, row("Alice"));
        assert_eq!(
            txn.table_by::<index::Users::name>().get("Alice").unwrap(),
            (1, row("Alice"))
        );
    }

    #[test]
    fn txn_base_mutate_updates_index_on_field_change() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Users>().insert(1, row("Alice"));
        txn.table::<Users>()
            .with_mut(&1, |v| v.name = "Bob".to_owned());
        assert!(txn.table_by::<index::Users::name>().get("Alice").is_none());
        assert_eq!(
            txn.table_by::<index::Users::name>().get("Bob").unwrap(),
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
        txn.table::<Users>().insert(1, row("Alice"));
        txn.table::<Users>().remove(&1);
        assert!(txn.table_by::<index::Users::name>().get("Alice").is_none());
    }

    #[test]
    fn txn_base_clear_updates_index() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Users>().insert(1, row("Alice"));
        txn.table::<Users>().insert(2, row("Bob"));
        txn.table::<Users>().clear();
        assert!(txn.table_by::<index::Users::name>().get("Alice").is_none());
        assert!(txn.table_by::<index::Users::name>().get("Bob").is_none());
    }

    #[test]
    fn txn_base_iter_mut_updates_index_on_field_change() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Users>().insert(1, row("Alice"));
        txn.table::<Users>().iter_mut().next().unwrap().1.name = "Charlie".to_owned();
        assert!(txn.table_by::<index::Users::name>().get("Alice").is_none());
        assert_eq!(
            txn.table_by::<index::Users::name>().get("Charlie").unwrap(),
            (
                1,
                Row {
                    name: "Charlie".to_owned(),
                    age: 0
                }
            )
        );
    }

    // Rows inserted after a `clear()` in the same transaction live in the delete
    // mask's pending map, not in `data`. Iterating the base table mutably must still leave those
    // rows correctly indexed.
    #[test]
    fn txn_base_iter_mut_after_clear_keeps_new_rows_indexed() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Users>().insert(1, row("Alice"));
        txn.table::<Users>().clear();
        txn.table::<Users>().insert(2, row("Bob"));
        for (_, v) in txn.table::<Users>().iter_mut() {
            v.name.push('!');
        }
        txn.commit().unwrap();

        let index = store.table_by::<index::Users::name>(OWNER);
        assert!(index.get("Alice").is_none());
        assert!(index.get("Bob").is_none());
        assert_eq!(index.get("Bob!").unwrap(), (2, row("Bob!")));
    }

    #[test]
    fn txn_base_iter_mut_after_clear_unmodified_stays_indexed() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Users>().clear();
        txn.table::<Users>().insert(2, row("Bob"));
        for (_, _v) in txn.table::<Users>().iter_mut() {}
        txn.commit().unwrap();

        let index = store.table_by::<index::Users::name>(OWNER);
        assert_eq!(index.get("Bob").unwrap(), (2, row("Bob")));
    }

    // Removing a key then iterating mutably: the removed row must not be re-indexed, and a surviving
    // row mutated through the iterator must be re-indexed under its new key.
    #[test]
    fn txn_base_iter_mut_after_remove_keeps_index_consistent() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Users>().insert(1, row("Alice"));
        txn.table::<Users>().insert(2, row("Bob"));
        txn.table::<Users>().remove(&1);
        for (_, v) in txn.table::<Users>().iter_mut() {
            v.name.push('!');
        }
        txn.commit().unwrap();

        let index = store.table_by::<index::Users::name>(OWNER);
        assert!(index.get("Alice").is_none());
        assert!(index.get("Alice!").is_none());
        assert!(index.get("Bob").is_none());
        assert_eq!(index.get("Bob!").unwrap(), (2, row("Bob!")));
    }

    #[test]
    fn ro_txn_index_get_returns_none_when_absent() {
        let store = KvStore::new();
        let txn = store.begin_ro_transaction(OWNER);
        assert!(txn.table_by::<index::Users::name>().get("Alice").is_none());
    }

    #[test]
    fn ro_txn_index_get_returns_value_inserted_before_txn() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        let txn = store.begin_ro_transaction(OWNER);
        assert_eq!(
            txn.table_by::<index::Users::name>().get("Alice").unwrap(),
            (1, row("Alice"))
        );
    }

    #[test]
    fn ro_txn_index_with_returns_some() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        let txn = store.begin_ro_transaction(OWNER);
        assert_eq!(
            txn.table_by::<index::Users::name>()
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
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        store.table::<Users>(OWNER).insert(2, row("Bob"));
        let txn = store.begin_ro_transaction(OWNER);

        let table = txn.table_by::<index::Users::name>();
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
    fn ro_txn_index_for_each_yields_rows() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        store.table::<Users>(OWNER).insert(2, row("Bob"));
        let txn = store.begin_ro_transaction(OWNER);
        let mut names: Vec<String> = Vec::new();
        txn.table_by::<index::Users::name>()
            .iter()
            .for_each(|(k, ..)| names.push(k.clone()));
        names.sort();
        assert_eq!(names, vec!["Alice".to_owned(), "Bob".to_owned()]);
    }

    #[test]
    #[cfg_attr(debug_assertions, should_panic(expected = "Ownership violation"))]
    fn txn_index_insert_wrong_owner_panics() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OTHER);
        txn.table_by::<index::Users::name>().insert(1, row("Alice"));
    }

    #[test]
    #[cfg_attr(debug_assertions, should_panic(expected = "Ownership violation"))]
    fn txn_index_clear_wrong_owner_panics() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OTHER);
        txn.table_by::<index::Users::name>().clear();
    }

    #[test]
    #[cfg_attr(debug_assertions, should_panic(expected = "Ownership violation"))]
    fn txn_index_iter_mut_wrong_owner_panics() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OTHER);
        let mut table = txn.table_by::<index::Users::name>();
        let _iter = table.iter_mut();
    }

    #[test]
    fn txn_index_insert_rolled_back_on_drop() {
        let store = KvStore::new();
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.table_by::<index::Users::name>().insert(1, row("Alice"));
        }
        assert!(
            store
                .table_by::<index::Users::name>(OWNER)
                .get("Alice")
                .is_none()
        );
        assert!(store.table::<Users>(OWNER).get(&1).is_none());
    }

    #[test]
    fn txn_index_base_mutate_indexed_field_rolled_back() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.table_by::<index::Users::name>()
                .with_mut("Alice", |_, v| v.name = "Bob".to_owned())
                .unwrap();
        }
        assert_eq!(
            store
                .table_by::<index::Users::name>(OWNER)
                .get("Alice")
                .unwrap(),
            (1, row("Alice"))
        );
        assert!(
            store
                .table_by::<index::Users::name>(OWNER)
                .get("Bob")
                .is_none()
        );
        assert_eq!(store.table::<Users>(OWNER).get(&1), Some(row("Alice")));
    }

    #[test]
    fn txn_index_remove_rolled_back_on_drop() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.table_by::<index::Users::name>().remove("Alice");
        }
        assert_eq!(
            store
                .table_by::<index::Users::name>(OWNER)
                .get("Alice")
                .unwrap(),
            (1, row("Alice"))
        );
        assert_eq!(store.table::<Users>(OWNER).get(&1), Some(row("Alice")));
    }

    #[test]
    fn txn_index_clear_rolled_back_on_drop() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        store.table::<Users>(OWNER).insert(2, row("Bob"));
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.table_by::<index::Users::name>().clear();
        }
        assert_eq!(
            store
                .table_by::<index::Users::name>(OWNER)
                .get("Alice")
                .unwrap(),
            (1, row("Alice"))
        );
        assert_eq!(
            store
                .table_by::<index::Users::name>(OWNER)
                .get("Bob")
                .unwrap(),
            (2, row("Bob"))
        );
    }

    #[test]
    fn raw_base_then_txn_index_insert_commit_both_visible() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));

        let mut txn = store.begin_transaction(OWNER);
        txn.table_by::<index::Users::name>().insert(2, row("Bob"));
        txn.commit().unwrap();

        assert_eq!(
            store
                .table_by::<index::Users::name>(OWNER)
                .get("Alice")
                .unwrap(),
            (1, row("Alice"))
        );
        assert_eq!(
            store
                .table_by::<index::Users::name>(OWNER)
                .get("Bob")
                .unwrap(),
            (2, row("Bob"))
        );
        assert_eq!(store.table::<Users>(OWNER).get(&1), Some(row("Alice")));
        assert_eq!(store.table::<Users>(OWNER).get(&2), Some(row("Bob")));
    }
}

#[cfg(test)]
mod test_poison {
    use crate::{Error, KvErrorExt, store};

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
            Users(u32 => Row; OWNER; index(name: String); index(email: String)),
            AssertingUsers(u32 => Row; OWNER; index(name: String; assert_unique)),
        }
    );

    const OWNER: &str = "owner";

    #[test]
    fn ops_return_error_when_poisoned() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Users>().insert(1, row("Alice", "alice1@x.com"));
        txn.table::<Users>().insert(2, row("Alice", "alice2@x.com"));

        let mut index_name = txn.table_by::<index::Users::name>();
        assert_eq!(
            index_name.check_consistent(),
            Err(Error::NonUniqueIndexKey("Users by name"))
        );

        let result = index_name.get("Alice");
        assert!(matches!(result, Err(Error::NonUniqueIndexKey(_))));

        // The `panic`s ensure that the closure is not called.
        let result = index_name.with("Alice", |_, _| panic!());
        assert!(matches!(result, Err(Error::NonUniqueIndexKey(_))));

        let result = index_name.with_mut("Alice", |_, _| panic!());
        assert!(matches!(result, Err(Error::NonUniqueIndexKey(_))));
    }

    #[test]
    fn check_consistent_ok_when_unique() {
        let store = KvStore::new();
        store
            .table::<Users>(OWNER)
            .insert(1, row("Alice", "alice1@x.com"));
        assert!(
            store
                .table_by::<index::Users::name>(OWNER)
                .check_consistent()
                .is_ok()
        );
    }

    #[test]
    fn poisoned_via_index_insert() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        let mut index = txn.table_by::<index::Users::name>();
        index.insert(1, row("Alice", "alice1@x.com"));
        index.insert(2, row("Alice", "alice2@x.com"));

        assert!(matches!(
            index.check_consistent(),
            Err(Error::NonUniqueIndexKey(_))
        ));
        assert!(matches!(
            index.get("Alice"),
            Err(Error::NonUniqueIndexKey(_))
        ));
    }

    #[test]
    fn base_table_unaffected_when_index_poisoned() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Users>().insert(1, row("Alice", "alice1@x.com"));
        txn.table::<Users>().insert(2, row("Alice", "alice2@x.com"));

        // The `name` index is poisoned, but the base table can still be read by primary key.
        assert_eq!(
            txn.table::<Users>().get(&1),
            Some(row("Alice", "alice1@x.com"))
        );
        assert_eq!(
            txn.table::<Users>().get(&2),
            Some(row("Alice", "alice2@x.com"))
        );
    }

    #[test]
    fn sibling_index_not_poisoned() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Users>().insert(1, row("Alice", "alice1@x.com"));
        txn.table::<Users>().insert(2, row("Alice", "alice2@x.com"));

        // `name` is poisoned (both "Alice")...
        assert!(matches!(
            txn.table_by::<index::Users::name>().check_consistent(),
            Err(Error::NonUniqueIndexKey(_))
        ));
        // ...but `email` has distinct keys and stays consistent.
        let email_index = txn.table_by::<index::Users::email>();
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
    fn clear_unpoisons() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Users>().insert(1, row("Alice", "alice1@x.com"));
        txn.table::<Users>().insert(2, row("Alice", "alice2@x.com"));

        let mut index = txn.table_by::<index::Users::name>();
        assert!(index.check_consistent().is_err());

        index.clear();
        assert!(index.check_consistent().is_ok());
        assert!(index.get("Alice").is_none());
    }

    #[test]
    fn txn_get_returns_error_when_poisoned() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Users>().insert(1, row("Alice", "alice1@x.com"));
        txn.table::<Users>().insert(2, row("Alice", "alice2@x.com"));

        assert!(matches!(
            txn.table_by::<index::Users::name>().get("Alice"),
            Err(Error::NonUniqueIndexKey(_))
        ));
    }

    #[test]
    fn txn_check_consistent_errors_when_poisoned() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Users>().insert(1, row("Alice", "alice1@x.com"));
        txn.table::<Users>().insert(2, row("Alice", "alice2@x.com"));

        assert!(matches!(
            txn.table_by::<index::Users::name>().check_consistent(),
            Err(Error::NonUniqueIndexKey(_))
        ));
    }

    #[test]
    fn txn_commit_fails_when_index_poisoned() {
        let store = KvStore::new();
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.table::<Users>().insert(1, row("Alice", "alice1@x.com"));
            txn.table::<Users>().insert(2, row("Alice", "alice2@x.com"));
            assert!(matches!(txn.commit(), Err(Error::NonUniqueIndexKey(_))));
        }

        // The failed commit rolled everything back: the store is clean and consistent.
        assert!(store.table::<Users>(OWNER).get(&1).is_none());
        assert!(store.table::<Users>(OWNER).get(&2).is_none());
        assert!(
            store
                .table_by::<index::Users::name>(OWNER)
                .check_consistent()
                .is_ok()
        );
    }

    #[test]
    fn txn_poison_rolled_back_on_drop() {
        let store = KvStore::new();
        {
            let mut txn = store.begin_transaction(OWNER);
            txn.table::<Users>().insert(1, row("Alice", "alice1@x.com"));
            txn.table::<Users>().insert(2, row("Alice", "alice2@x.com"));
            // dropped without committing
        }

        let index = store.table_by::<index::Users::name>(OWNER);
        assert!(index.check_consistent().is_ok());
        assert!(index.get("Alice").is_none());
        assert!(store.table::<Users>(OWNER).is_empty());
    }

    #[test]
    fn txn_poison_against_committed_rolled_back() {
        let store = KvStore::new();
        // Commit Alice(1) first, so the "Alice" name-index entry is already committed.
        store
            .table::<Users>(OWNER)
            .insert(1, row("Alice", "alice1@x.com"));

        {
            // This txn collides with the *already-committed* "Alice" index entry, so the index is
            // poisoned without it ever being recorded as `modified` within the txn.
            let mut txn = store.begin_transaction(OWNER);
            txn.table::<Users>().insert(2, row("Alice", "alice2@x.com"));
            // rollback on drop
        }

        // An unrelated, valid commit must succeed — the rolled-back poison must not leak into it.
        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Users>().insert(3, row("Bob", "bob@x.com"));
        txn.commit().unwrap();

        let index = store.table_by::<index::Users::name>(OWNER);
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
    fn assert_unique_distinct_keys_ok() {
        let store = KvStore::new();
        store
            .table::<AssertingUsers>(OWNER)
            .insert(1, row("Alice", "alice1@x.com"));
        store
            .table::<AssertingUsers>(OWNER)
            .insert(2, row("Bob", "bob@x.com"));
        assert_eq!(
            store
                .table_by::<index::AssertingUsers::name>(OWNER)
                .get("Alice")
                .unwrap(),
            (1, row("Alice", "alice1@x.com"))
        );
    }

    #[test]
    #[should_panic(expected = "non-unique")]
    fn assert_unique_duplicate_base_insert_panics() {
        let store = KvStore::new();
        store
            .table::<AssertingUsers>(OWNER)
            .insert(1, row("Alice", "alice1@x.com"));
        store
            .table::<AssertingUsers>(OWNER)
            .insert(2, row("Alice", "alice2@x.com"));
    }

    #[test]
    fn raw_base_try_insert_duplicate_errors_and_rolls_back() {
        let store = KvStore::new();
        store
            .table::<Users>(OWNER)
            .insert(1, row("Alice", "alice1@x.com"));

        // The duplicate "Alice" name-index key makes the insert fail.
        assert!(matches!(
            store
                .table::<Users>(OWNER)
                .try_insert(2, row("Alice", "alice2@x.com")),
            Err(Error::NonUniqueIndexKey(_))
        ));

        // The failed insert rolled back: the index is consistent and only the original row remains.
        let index = store.table_by::<index::Users::name>(OWNER);
        assert!(index.check_consistent().is_ok());
        assert_eq!(
            index.get("Alice").unwrap(),
            (1, row("Alice", "alice1@x.com"))
        );
        assert_eq!(
            store.table::<Users>(OWNER).get(&1),
            Some(row("Alice", "alice1@x.com"))
        );
        assert_eq!(store.table::<Users>(OWNER).get(&2), None);
    }

    #[test]
    fn raw_base_insert_duplicate_panics_and_rolls_back() {
        let store = KvStore::new();
        store
            .table::<Users>(OWNER)
            .insert(1, row("Alice", "alice1@x.com"));

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            store
                .table::<Users>(OWNER)
                .insert(2, row("Alice", "alice2@x.com"));
        }));
        assert!(result.is_err(), "duplicate raw insert should panic");

        // The panicked insert has been rolled back, leaving the store consistent.
        let index = store.table_by::<index::Users::name>(OWNER);
        assert!(index.check_consistent().is_ok());
        assert_eq!(
            index.get("Alice").unwrap(),
            (1, row("Alice", "alice1@x.com"))
        );
        assert_eq!(store.table::<Users>(OWNER).get(&2), None);
    }

    #[test]
    fn raw_index_try_insert_duplicate_errors_and_rolls_back() {
        let store = KvStore::new();
        store
            .table_by::<index::Users::name>(OWNER)
            .insert(1, row("Alice", "alice1@x.com"));

        assert!(matches!(
            store
                .table_by::<index::Users::name>(OWNER)
                .try_insert(2, row("Alice", "alice2@x.com")),
            Err(Error::NonUniqueIndexKey(_))
        ));

        let index = store.table_by::<index::Users::name>(OWNER);
        assert!(index.check_consistent().is_ok());
        assert_eq!(
            index.get("Alice").unwrap(),
            (1, row("Alice", "alice1@x.com"))
        );
    }

    #[test]
    fn raw_with_mut_collision_returns_error_and_rolls_back() {
        let store = KvStore::new();
        store
            .table::<Users>(OWNER)
            .insert(1, row("Alice", "alice1@x.com"));
        store
            .table::<Users>(OWNER)
            .insert(2, row("Bob", "bob@x.com"));

        // Renaming Bob to "Alice" collides on the `name` index, so the mini-transaction fails.
        assert!(matches!(
            store
                .table::<Users>(OWNER)
                .with_mut(&2, |r| r.name = "Alice".to_owned()),
            Err(Error::NonUniqueIndexKey(_))
        ));

        // Rolled back: Bob is unchanged and the index is consistent.
        assert_eq!(
            store.table::<Users>(OWNER).get(&2),
            Some(row("Bob", "bob@x.com"))
        );
        let index = store.table_by::<index::Users::name>(OWNER);
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
        store
            .table::<Users>(OWNER)
            .insert(1, row("Alice", "alice1@x.com"));

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = store.table::<Users>(OWNER).with_mut(&1, |r| {
                r.name = "Zelda".to_owned();
                panic!("boom");
            });
        }));
        assert!(result.is_err(), "panicking closure should propagate");

        // The mutation (and its index update) rolled back; "Alice" is intact and queryable.
        assert_eq!(
            store.table::<Users>(OWNER).get(&1),
            Some(row("Alice", "alice1@x.com"))
        );
        let index = store.table_by::<index::Users::name>(OWNER);
        assert!(index.check_consistent().is_ok());
        assert_eq!(
            index.get("Alice").unwrap(),
            (1, row("Alice", "alice1@x.com"))
        );
        assert!(index.get("Zelda").is_none());
    }
}
