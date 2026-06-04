use std::{borrow::Borrow, hash::Hash};

use crate::{
    KvStore, Owner, RefReadGuard, RefWriteGuard, RefWriteGuardMut, Result, RoTransaction,
    Transaction,
    operations::{Base, BaseKey, BaseValue, IndexValue, IndexedOps, IndexedOpsMut, Ops, OpsMut},
    schema::{IndexDesc, TableDesc},
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

impl<'idx, D: IndexDesc> Ops for &'idx KvTableIndex<'_, D> {
    type ReadLock = std::sync::RwLockReadGuard<'idx, Self::Storage>;
    type Storage = Storage<D::Storage>;

    fn read_lock(self) -> Self::ReadLock {
        self.store.storage.read().unwrap()
    }
}

impl<'idx, D: IndexDesc> OpsMut for &'idx KvTableIndex<'_, D> {
    type WriteLock = std::sync::RwLockWriteGuard<'idx, Self::Storage>;
    type Storage = Storage<D::Storage>;

    fn write_lock(self) -> Self::WriteLock {
        self.store.storage.write().unwrap()
    }
}

impl<D: IndexDesc> IndexedOps for &KvTableIndex<'_, D> {
    type IndexDesc = D;
}
impl<D: IndexDesc> IndexedOpsMut for &KvTableIndex<'_, D> {
    type IndexDesc = D;
}

impl<'store, D: IndexDesc> KvTableIndex<'store, D> {
    /// Initialize the base table by setting its owner (indexes don't have an owner).
    ///
    /// Calling this function is optional, a table can be used without initialization in which case,
    /// its owner is set to the owner specifed in the first write.
    ///
    /// Returns an error (containing the current owner of the table) if the table has already been
    /// initialized. In this case, the table will be in a consistent state and can be used as normal.
    pub fn init(&self) -> Result<()> {
        <&Self as IndexedOpsMut>::init(self, self.owner)
    }

    /// The number of key/value pairs in the base table.
    pub fn len(&self) -> usize {
        <&Self as IndexedOps>::len(self)
    }

    /// True if the table is empty.
    pub fn is_empty(&self) -> bool {
        <&Self as IndexedOps>::is_empty(self)
    }

    /// Clear the base table by removing all its KVs, but preserving ownership.
    pub fn clear(&self)
    where
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOpsMut>::clear(self, self.owner)
    }

    /// Get a row of the table from the store by cloning the value.
    ///
    /// Returns `None` if there is no value for the specified key.
    pub fn get<Q>(&self, key: &Q) -> Option<BaseValue<D>>
    where
        BaseValue<D>: Clone,
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOps>::get(self, key, self.owner)
    }

    /// Get immutable access to a row of the table in the store by reference.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    pub fn with<Q, T>(&self, key: &Q, f: impl FnOnce(&BaseValue<D>) -> T) -> Option<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOps>::with::<Q, T>(self, key, f, self.owner)
    }

    /// Insert a value into the table using the base table's key.
    ///
    /// Returns the previous value if there is one, or `None` if there is no value for the specified key.
    pub fn insert(&self, key: BaseKey<D>, value: BaseValue<D>) -> Option<BaseValue<D>>
    where
        <<D as IndexDesc>::BaseTable as TableDesc>::Key: Clone,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOpsMut>::insert(self, key, value, self.owner)
    }

    /// Get mutable access to a row of the table in the store in the store.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    pub fn with_mut<Q, T>(&self, key: &Q, f: impl FnOnce(&mut BaseValue<D>) -> T) -> Option<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        BaseKey<D>: Clone,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOpsMut>::with_mut(self, key, f, self.owner)
    }

    /// Remove a row from the table.
    ///
    /// Returns the previous value if there is one, or `None` if there is no value for the specified key.
    pub fn remove<Q>(&self, key: &Q) -> Option<BaseValue<D>>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOpsMut>::remove(self, key, self.owner)
    }

    /// Iterate all the keys in the index and value in the base table.
    pub fn iter(&self) -> impl Iterator<Item = (&D::Key, &BaseValue<D>)>
    where
        D: 'store,
        Base<D>: 'store,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOps>::iter(self, self.owner)
    }

    /// Iterate all the keys in the index.
    pub fn keys(&self) -> impl Iterator<Item = &D::Key>
    where
        D: 'store,
        Base<D>: 'store,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOps>::keys(self, self.owner)
    }

    /// Iterate all the values in the base table.
    pub fn values(&self) -> impl Iterator<Item = &BaseValue<D>>
    where
        D: 'store,
        Base<D>: 'store,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOps>::values(self, self.owner)
    }

    /// Iterate all the key/value pairs in a table. Values are mutable.
    pub fn for_each_mut(&self, f: impl FnMut(&D::Key, &mut BaseValue<D>))
    where
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOpsMut>::for_each_mut(self, f, self.owner)
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
    pub(crate) txn: &'txn mut Transaction<'guard, Storage<D::Storage>>,
}

impl<'guard, 'txn, 'a, D: IndexDesc> Ops for &'a KvTableTransactionalIndex<'guard, 'txn, D> {
    type ReadLock = RefWriteGuard<'a, 'guard, Self::Storage>;
    type Storage = Storage<D::Storage>;

    fn read_lock(self) -> Self::ReadLock {
        RefWriteGuard(&self.txn.guard)
    }
}

impl<'guard, 'txn, 'a, D: IndexDesc> OpsMut for &'a mut KvTableTransactionalIndex<'guard, 'txn, D> {
    type WriteLock = RefWriteGuardMut<'a, 'guard, Self::Storage>;
    type Storage = Storage<D::Storage>;

    fn write_lock(self) -> Self::WriteLock {
        RefWriteGuardMut(&mut self.txn.guard)
    }
}

impl<'guard, 'txn, D: IndexDesc> IndexedOps for &KvTableTransactionalIndex<'guard, 'txn, D> {
    type IndexDesc = D;
}

impl<'guard, 'txn, D: IndexDesc> IndexedOpsMut for &mut KvTableTransactionalIndex<'guard, 'txn, D> {
    type IndexDesc = D;
}

impl<'guard, 'txn, D: IndexDesc> KvTableTransactionalIndex<'guard, 'txn, D> {
    /// Initialize the base table by setting its owner (indexes don't have an owner).
    ///
    /// Calling this function is optional, a table can be used without initialization in which case,
    /// its owner is set to the owner specifed in the first write.
    ///
    /// Returns an error (containing the current owner of the table) if the table has already been
    /// initialized. In this case, the table will be in a consistent state and can be used as normal.
    pub fn init(&mut self) -> Result<()> {
        <&mut Self as IndexedOpsMut>::init(self, self.txn.owner)
    }

    /// The number of key/value pairs in the base table.
    pub fn len(&self) -> usize {
        <&Self as IndexedOps>::len(self)
    }

    /// True if the table is empty.
    pub fn is_empty(&self) -> bool {
        <&Self as IndexedOps>::is_empty(self)
    }

    /// Clear the base table by removing all its KVs, but preserving ownership.
    pub fn clear(&mut self)
    where
        IndexValue<D>: Eq + Hash,
    {
        <&mut Self as IndexedOpsMut>::clear(self, self.txn.owner)
    }

    /// Get a row of the table from the store by cloning the value.
    ///
    /// Returns `None` if there is no value for the specified key.
    pub fn get<Q>(&self, key: &Q) -> Option<BaseValue<D>>
    where
        BaseValue<D>: Clone,
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOps>::get::<Q>(self, key, self.txn.owner)
    }

    /// Get immutable access to a row of the table in the store by reference.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    pub fn with<Q, T>(&self, key: &Q, f: impl FnOnce(&BaseValue<D>) -> T) -> Option<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOps>::with::<Q, T>(self, key, f, self.txn.owner)
    }

    /// Insert a value into the table using the base table's key.
    ///
    /// Returns the previous value if there is one, or `None` if there is no value for the specified key.
    pub fn insert(&mut self, key: BaseKey<D>, value: BaseValue<D>) -> Option<BaseValue<D>>
    where
        BaseKey<D>: Clone,
        IndexValue<D>: Eq + Hash,
    {
        <&mut Self as IndexedOpsMut>::insert(self, key, value, self.txn.owner)
    }

    /// Get mutable access to a row of the table in the store in the store.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    pub fn with_mut<Q, T>(&mut self, key: &Q, f: impl FnOnce(&mut BaseValue<D>) -> T) -> Option<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        BaseKey<D>: Clone,
        IndexValue<D>: Eq + Hash,
    {
        <&mut Self as IndexedOpsMut>::with_mut::<Q, T>(self, key, f, self.txn.owner)
    }

    /// Remove a row from the table.
    ///
    /// Returns the previous value if there is one, or `None` if there is no value for the specified key.
    pub fn remove<Q>(&mut self, key: &Q) -> Option<BaseValue<D>>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        IndexValue<D>: Eq + Hash,
    {
        <&mut Self as IndexedOpsMut>::remove::<Q>(self, key, self.txn.owner)
    }

    /// Iterate all the keys in the index and value in the base table.
    pub fn iter(&self) -> impl Iterator<Item = (&D::Key, &BaseValue<D>)>
    where
        D: 'guard,
        Base<D>: 'guard,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOps>::iter(self, self.txn.owner)
    }

    /// Iterate all the keys in the index.
    pub fn keys(&self) -> impl Iterator<Item = &D::Key>
    where
        D: 'guard,
        Base<D>: 'guard,
    {
        <&Self as IndexedOps>::keys(self, self.txn.owner)
    }

    /// Iterate all the values in the base table.
    pub fn values(&self) -> impl Iterator<Item = &BaseValue<D>>
    where
        D: 'guard,
        Base<D>: 'guard,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOps>::values(self, self.txn.owner)
    }

    /// Iterate all the key/value pairs in a table. Values are mutable.
    pub fn for_each_mut(&mut self, f: impl FnMut(&D::Key, &mut BaseValue<D>))
    where
        IndexValue<D>: Eq + Hash,
    {
        <&mut Self as IndexedOpsMut>::for_each_mut(self, f, self.txn.owner)
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
    pub(crate) txn: &'txn RoTransaction<'guard, Storage<D::Storage>>,
}

impl<'guard, 'txn, 'a, D: IndexDesc> Ops for &'a KvTableRoTransactionalIndex<'guard, 'txn, D> {
    type ReadLock = RefReadGuard<'a, 'guard, Self::Storage>;
    type Storage = Storage<D::Storage>;

    fn read_lock(self) -> Self::ReadLock {
        RefReadGuard(&self.txn.guard)
    }
}

impl<'guard, 'txn, D: IndexDesc> IndexedOps for &KvTableRoTransactionalIndex<'guard, 'txn, D> {
    type IndexDesc = D;
}

impl<'guard, 'txn, D: IndexDesc> KvTableRoTransactionalIndex<'guard, 'txn, D> {
    /// The number of key/value pairs in the base table.
    pub fn len(&self) -> usize {
        <&Self as IndexedOps>::len(self)
    }

    /// True if the table is empty.
    pub fn is_empty(&self) -> bool {
        <&Self as IndexedOps>::is_empty(self)
    }

    /// Get a row of the table from the store by cloning the value.
    ///
    /// Returns `None` if there is no value for the specified key.
    pub fn get<Q>(&self, key: &Q) -> Option<BaseValue<D>>
    where
        BaseValue<D>: Clone,
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOps>::get::<Q>(self, key, self.txn.owner)
    }

    /// Get immutable access to a row of the table in the store by reference.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    pub fn with<Q, T>(&self, key: &Q, f: impl FnOnce(&BaseValue<D>) -> T) -> Option<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOps>::with::<Q, T>(self, key, f, self.txn.owner)
    }

    /// Iterate all the keys in the index and value in the base table.
    pub fn iter(&self) -> impl Iterator<Item = (&D::Key, &BaseValue<D>)>
    where
        D: 'guard,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOps>::iter(self, self.txn.owner)
    }

    /// Iterate all the keys in the index.
    pub fn keys(&self) -> impl Iterator<Item = &D::Key>
    where
        D: 'guard,
    {
        <&Self as IndexedOps>::keys(self, self.txn.owner)
    }

    /// Iterate all the values in the base table.
    pub fn values(&self) -> impl Iterator<Item = &BaseValue<D>>
    where
        D: 'guard,
        IndexValue<D>: Eq + Hash,
    {
        <&Self as IndexedOps>::values(self, self.txn.owner)
    }
}

#[cfg(test)]
mod test {
    use crate::{Error, tables};

    #[derive(Clone, Debug, PartialEq)]
    pub struct Row {
        pub name: String,
    }

    fn row(name: &str) -> Row {
        Row {
            name: name.to_owned(),
        }
    }

    tables!(Users(u32 => Row; index(name: String)));

    const OWNER: &str = "owner";
    const OTHER: &str = "other";

    #[test]
    fn index_init_succeeds_on_fresh_table() {
        let store = KvStore::new();
        assert!(store.table_by::<index::Users::name>(OWNER).init().is_ok());
    }

    #[test]
    fn index_init_second_call_returns_err() {
        let store = KvStore::new();
        store.table_by::<index::Users::name>(OWNER).init().unwrap();
        let err = store
            .table_by::<index::Users::name>(OWNER)
            .init()
            .unwrap_err();
        assert!(matches!(err, Error::AlreadyInit(o) if o == OWNER));
    }

    #[test]
    fn index_init_with_different_owner_returns_err() {
        let store = KvStore::new();
        store.table_by::<index::Users::name>(OWNER).init().unwrap();
        let err = store
            .table_by::<index::Users::name>(OTHER)
            .init()
            .unwrap_err();
        assert!(matches!(err, Error::AlreadyInit(o) if o == OWNER));
    }

    #[test]
    fn index_init_and_base_init_share_owner() {
        let store = KvStore::new();
        store.table_by::<index::Users::name>(OWNER).init().unwrap();
        let err = store.table::<Users>(OWNER).init().unwrap_err();
        assert!(matches!(err, Error::AlreadyInit(o) if o == OWNER));
    }

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
        assert_eq!(value, row("Alice"));
    }

    #[test]
    fn index_get_returns_value_after_index_insert() {
        let store = KvStore::new();
        store
            .table_by::<index::Users::name>(OWNER)
            .insert(1, row("Alice"));

        let table = store.table_by::<index::Users::name>(OWNER);

        let value = table.get("Alice").unwrap();
        assert_eq!(value, row("Alice"));
    }

    #[test]
    fn index_with_returns_none_and_does_not_call_f_when_absent() {
        let store = KvStore::new();
        let mut called = false;
        let result = store
            .table_by::<index::Users::name>(OWNER)
            .with("Alice", |_| {
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
            .with("Alice", |v| v.name.len());
        assert_eq!(len, Some(5));
    }

    #[test]
    fn index_insert_returns_none_on_first() {
        let store = KvStore::new();
        assert!(
            store
                .table_by::<index::Users::name>(OWNER)
                .insert(1, row("Alice"))
                .is_none()
        );
    }

    #[test]
    fn index_insert_returns_previous_value_when_overwriting_base_key() {
        let store = KvStore::new();
        store
            .table_by::<index::Users::name>(OWNER)
            .insert(1, row("Alice"));
        let old = store
            .table_by::<index::Users::name>(OWNER)
            .insert(1, row("Alice"));
        assert_eq!(old, Some(row("Alice")));
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
    fn index_remove_returns_none_when_absent() {
        let store = KvStore::new();
        assert!(
            store
                .table_by::<index::Users::name>(OWNER)
                .remove("Alice")
                .is_none()
        );
    }

    #[test]
    fn index_remove_returns_value() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        let value = store.table_by::<index::Users::name>(OWNER).remove("Alice");
        assert_eq!(value, Some(row("Alice")));
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
            .with_mut("Alice", |v| v.name.len());
        assert!(result.is_none());
    }

    #[test]
    fn index_mutate_modifies_value() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        store
            .table_by::<index::Users::name>(OWNER)
            .with_mut("Alice", |v| v.name.push_str(" Smith"));
        let value = store.table::<Users>(OWNER).get(&1).unwrap();
        assert_eq!(value.name, "Alice Smith");
    }

    #[test]
    fn index_mutate_updates_index_on_field_change() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        store
            .table_by::<index::Users::name>(OWNER)
            .with_mut("Alice", |v| {
                v.name = "Charlie".to_owned();
            });
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
        assert_eq!(value.name, "Charlie");
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
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        assert_eq!(items, vec![("Alice".to_owned(), row("Alice"))]);
    }

    #[test]
    fn index_iter_yields_all_rows() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        store.table::<Users>(OWNER).insert(2, row("Bob"));
        let mut items: Vec<_> = store
            .table_by::<index::Users::name>(OWNER)
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        items.sort_by_key(|(k, _)| k.clone());
        assert_eq!(
            items,
            vec![
                ("Alice".to_owned(), row("Alice")),
                ("Bob".to_owned(), row("Bob")),
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
        values.sort_by_key(|r| r.name.clone());
        assert_eq!(values, vec![&row("Alice"), &row("Bob")]);
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
            .for_each(|(k, v)| items.push((k.clone(), v.clone())));
        assert_eq!(items, vec![("Alice".to_owned(), row("Alice"))]);
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
            .for_each(|(k, v)| items.push((k.clone(), v.clone())));
        items.sort_by_key(|(k, _)| k.clone());
        assert_eq!(
            items,
            vec![
                ("Alice".to_owned(), row("Alice")),
                ("Bob".to_owned(), row("Bob")),
            ]
        );
    }

    #[test]
    fn index_for_each_mut_empty_calls_closure_zero_times() {
        let store = KvStore::new();
        let index = store.table_by::<index::Users::name>(OWNER);
        let mut count = 0;
        index.for_each_mut(|_, _| count += 1);
        assert_eq!(count, 0);
    }

    #[test]
    fn index_for_each_mut_modifies_base_values() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        let index = store.table_by::<index::Users::name>(OWNER);
        index.for_each_mut(|_, v| v.name.push('!'));
        assert_eq!(store.table::<Users>(OWNER).get(&1), Some(row("Alice!")));
    }

    #[test]
    fn table_for_each_mut_updates_index() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        store
            .table::<Users>(OWNER)
            .for_each_mut(|_, v| v.name = "Charlie".to_owned());
        assert!(
            store
                .table_by::<index::Users::name>(OWNER)
                .get("Alice")
                .is_none()
        );
        assert_eq!(
            store.table_by::<index::Users::name>(OWNER).get("Charlie"),
            Some(row("Charlie"))
        );
    }

    #[test]
    fn index_for_each_mut_updates_index() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        store
            .table_by::<index::Users::name>(OWNER)
            .for_each_mut(|_, v| v.name = "Charlie".to_owned());
        assert!(
            store
                .table_by::<index::Users::name>(OWNER)
                .get("Alice")
                .is_none()
        );
        assert_eq!(
            store.table_by::<index::Users::name>(OWNER).get("Charlie"),
            Some(row("Charlie"))
        );
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Ownership violation")]
    fn index_insert_wrong_owner_panics() {
        let store = KvStore::new();
        store.table_by::<index::Users::name>(OWNER).init().unwrap();
        store
            .table_by::<index::Users::name>(OTHER)
            .insert(1, row("Alice"));
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Ownership violation")]
    fn index_clear_wrong_owner_panics() {
        let store = KvStore::new();
        store.table_by::<index::Users::name>(OWNER).init().unwrap();
        store.table_by::<index::Users::name>(OTHER).clear();
    }
}

#[cfg(test)]
mod test_two_indexes {
    use crate::tables;

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

    tables!(People(u32 => Person; index(email: String); index(username: Vec<u8>)));

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
                .get("a@example.com"),
            Some(person("a@example.com", b"alice"))
        );
        assert_eq!(
            store
                .table_by::<index::People::username>(OWNER)
                .get(b"alice".as_slice()),
            Some(person("a@example.com", b"alice"))
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
                .get("a@example.com"),
            Some(person("a@example.com", b"alice"))
        );
        assert_eq!(
            store
                .table_by::<index::People::username>(OWNER)
                .get(b"alice".as_slice()),
            Some(person("a@example.com", b"alice"))
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
                .get("a@example.com"),
            Some(person("a@example.com", b"alice"))
        );
        assert_eq!(
            store
                .table_by::<index::People::username>(OWNER)
                .get(b"bob".as_slice()),
            Some(person("b@example.com", b"bob"))
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
    fn table_for_each_mut_updates_both_indexes() {
        let store = KvStore::new();
        store
            .table::<People>(OWNER)
            .insert(1, person("a@example.com", b"alice"));
        store.table::<People>(OWNER).for_each_mut(|_, v| {
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
    fn email_index_for_each_mut_updates_both_indexes() {
        let store = KvStore::new();
        store
            .table::<People>(OWNER)
            .insert(1, person("a@example.com", b"alice"));
        store
            .table_by::<index::People::email>(OWNER)
            .for_each_mut(|_, v| {
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
}

#[cfg(test)]
mod test_transactional_index {
    use crate::tables;

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

    tables!(Users(u32 => Row; index(name: String)));

    const OWNER: &str = "owner";
    #[cfg(debug_assertions)]
    const OTHER: &str = "other";

    // Group A: KvTableTransactionalIndex - index maintenance

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
            txn.table_by::<index::Users::name>().get("Alice"),
            Some(row("Alice"))
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
                .with("Alice", |v| v.name.len()),
            Some(5)
        );
    }

    #[test]
    fn txn_index_mutate_updates_index_on_field_change() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table_by::<index::Users::name>().insert(1, row("Alice"));
        txn.table_by::<index::Users::name>()
            .with_mut("Alice", |v| v.name = "Bob".to_owned());
        assert!(txn.table_by::<index::Users::name>().get("Alice").is_none());
        assert_eq!(
            txn.table_by::<index::Users::name>().get("Bob"),
            Some(Row {
                name: "Bob".to_owned(),
                age: 0
            })
        );
    }

    #[test]
    fn txn_index_mutate_non_indexed_field_preserves_index() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table_by::<index::Users::name>().insert(1, row("Alice"));
        txn.table_by::<index::Users::name>()
            .with_mut("Alice", |v| v.age = 42);
        assert_eq!(
            txn.table_by::<index::Users::name>().get("Alice"),
            Some(Row {
                name: "Alice".to_owned(),
                age: 42
            })
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
    fn txn_index_for_each_mut_updates_index_on_field_change() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table_by::<index::Users::name>().insert(1, row("Alice"));
        txn.table_by::<index::Users::name>()
            .for_each_mut(|_, v| v.name = "Charlie".to_owned());
        assert!(txn.table_by::<index::Users::name>().get("Alice").is_none());
        assert_eq!(
            txn.table_by::<index::Users::name>().get("Charlie"),
            Some(Row {
                name: "Charlie".to_owned(),
                age: 0
            })
        );
    }

    // Group B: KvTableTransactional (base table) - index maintenance

    #[test]
    fn txn_base_insert_updates_index() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Users>().insert(1, row("Alice"));
        assert_eq!(
            txn.table_by::<index::Users::name>().get("Alice"),
            Some(row("Alice"))
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
            txn.table_by::<index::Users::name>().get("Bob"),
            Some(Row {
                name: "Bob".to_owned(),
                age: 0
            })
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
    fn txn_base_for_each_mut_updates_index_on_field_change() {
        let store = KvStore::new();
        let mut txn = store.begin_transaction(OWNER);
        txn.table::<Users>().insert(1, row("Alice"));
        txn.table::<Users>()
            .for_each_mut(|_, v| v.name = "Charlie".to_owned());
        assert!(txn.table_by::<index::Users::name>().get("Alice").is_none());
        assert_eq!(
            txn.table_by::<index::Users::name>().get("Charlie"),
            Some(Row {
                name: "Charlie".to_owned(),
                age: 0
            })
        );
    }

    // Group C: KvTableRoTransactionalIndex - reads via index in RO transaction

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
            txn.table_by::<index::Users::name>().get("Alice"),
            Some(row("Alice"))
        );
    }

    #[test]
    fn ro_txn_index_with_returns_some() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).insert(1, row("Alice"));
        let txn = store.begin_ro_transaction(OWNER);
        assert_eq!(
            txn.table_by::<index::Users::name>()
                .with("Alice", |v| v.name.len()),
            Some(5)
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
                (&"Alice".to_owned(), &row("Alice")),
                (&"Bob".to_owned(), &row("Bob"))
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
            .for_each(|(k, _)| names.push(k.clone()));
        names.sort();
        assert_eq!(names, vec!["Alice".to_owned(), "Bob".to_owned()]);
    }

    // Group D: Ownership enforcement

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Ownership violation")]
    fn txn_index_insert_wrong_owner_panics() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).init().unwrap();
        let mut txn = store.begin_transaction(OTHER);
        txn.table_by::<index::Users::name>().insert(1, row("Alice"));
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Ownership violation")]
    fn txn_index_clear_wrong_owner_panics() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).init().unwrap();
        let mut txn = store.begin_transaction(OTHER);
        txn.table_by::<index::Users::name>().clear();
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Ownership violation")]
    fn txn_index_for_each_mut_wrong_owner_panics() {
        let store = KvStore::new();
        store.table::<Users>(OWNER).init().unwrap();
        let mut txn = store.begin_transaction(OTHER);
        txn.table_by::<index::Users::name>().for_each_mut(|_, _| {});
    }
}
