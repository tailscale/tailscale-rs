//! KvStore non-transactional API.

use std::{borrow::Borrow, hash::Hash, sync::Arc};

use crate::{
    KvStore, Owner, Result,
    index::KvTableIndex,
    operations::{Ops, OpsMut, SingletonOps, SingletonOpsMut, TabularOps, TabularOpsMut},
    schema,
    storage::Storage,
};

impl<TableStorage: schema::GeneratedStorage> SingletonOps for &KvStore<TableStorage> {}
impl<TableStorage: schema::GeneratedStorage> SingletonOpsMut for &KvStore<TableStorage> {}

impl<'r, D: schema::TableDesc> Ops for &'r KvTable<'_, D> {
    type ReadLock = std::sync::RwLockReadGuard<'r, Self::Storage>;
    type Storage = Storage<D::Storage>;

    fn read_lock(self) -> Self::ReadLock {
        self.store.storage.read().unwrap()
    }
}

impl<D: schema::TableDesc> TabularOps for &KvTable<'_, D> {
    type Desc = D;
}

impl<'r, D: schema::TableDesc> OpsMut for &'r KvTable<'_, D> {
    type WriteLock = std::sync::RwLockWriteGuard<'r, Self::StorageMut>;
    type StorageMut = Storage<D::Storage>;

    fn write_lock(self) -> Self::WriteLock {
        self.store.storage.write().unwrap()
    }
}

impl<D: schema::TableDesc> TabularOpsMut for &KvTable<'_, D> {
    type DescMut = D;
}

impl<TableStorage: schema::GeneratedStorage> KvStore<TableStorage> {
    /// Operate on tables of key/values in the store.
    ///
    /// # Example:
    ///
    /// ```rust,ignore
    /// let value = store.table::<Foo>(OWNER).get(key).unwrap();
    /// ```
    pub fn table<D: schema::TableDesc<Storage = TableStorage>>(
        &self,
        owner: Owner,
    ) -> KvTable<'_, D> {
        KvTable { store: self, owner }
    }

    /// Access a table via an index.
    ///
    /// # Example:
    ///
    /// ```rust,ignore
    /// let value = store.table_by::<index::Foo::bar>(OWNER).get(key).unwrap();
    /// ```
    ///
    /// Here `Foo` describes a tables and `bar` describes an index over `Foo` using the `bar` field
    /// as foreign key.
    pub fn table_by<D: schema::IndexDesc<Storage = TableStorage>>(
        &self,
        owner: Owner,
    ) -> KvTableIndex<'_, D> {
        KvTableIndex { store: self, owner }
    }

    /// Get a single value from the store by cloning the value.
    ///
    /// Returns `None` if there is no value for the specified key.
    pub fn get<D: schema::Singleton>(&self, owner: Owner) -> Option<D::Value>
    where
        D::Value: Clone,
    {
        <&Self as SingletonOps>::get::<D>(self, owner)
    }

    /// Get a single value from the store by cloning an `Arc`.
    ///
    /// Returns `None` if there is no value for the specified key. Panics if the value is not an `Arc`.
    pub fn get_arc<D: schema::ArcSingleton>(&self, owner: Owner) -> Option<Arc<D::Value>> {
        <&Self as SingletonOps>::get_arc::<D>(self, owner)
    }

    /// Get immutable access to a value in the store by reference.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    pub fn with<D: schema::Singleton, T>(
        &self,
        owner: Owner,
        f: impl FnOnce(&D::Value) -> T,
    ) -> Option<T> {
        <&Self as SingletonOps>::with::<D, T>(self, f, owner)
    }

    /// Insert a single value into the store.
    ///
    /// Returns the previous value if there is one, or `None` if there is no value for the specified key.
    // Question: do we need separate insert/update/upsert methods?
    pub fn insert<D: schema::Singleton>(
        &self,
        owner: Owner,
        value: D::ArgValue,
    ) -> Option<D::ArgValue> {
        <&Self as SingletonOpsMut>::insert::<D>(self, value, owner)
    }

    /// Get mutable access to a value in the store.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    pub fn with_mut<D: schema::MutSingleton, T>(
        &self,
        owner: Owner,
        f: impl FnOnce(&mut D::Value) -> T,
    ) -> Option<T> {
        <&Self as SingletonOpsMut>::with_mut::<D, T>(self, f, owner)
    }

    /// Remove a single value from the store.
    ///
    /// Returns the previous value if there is one, or `None` if there is no value for the specified key.
    pub fn remove<D: schema::Singleton>(&self, owner: Owner) -> Option<D::ArgValue> {
        <&Self as SingletonOpsMut>::remove::<D>(self, owner)
    }

    /// Remove a single value from the store while preserving ownership of the key/value.
    ///
    /// Can also be used to initialize a key/value with a key but without a value.
    ///
    /// Returns the previous value if there is one, or `None` if there is no value for the specified key.
    pub fn clear<D: schema::Singleton>(&self, owner: Owner) -> Option<D::ArgValue> {
        <&Self as SingletonOpsMut>::clear::<D>(self, owner)
    }
}

/// Abstracts a table of key/values pairs in the store.
///
/// `KvTable` has no transactional semantics and only exists as a convenience for accessing
/// tabular data.
pub struct KvTable<'store, D: schema::TableDesc> {
    store: &'store KvStore<D::Storage>,
    owner: Owner,
}

impl<D: schema::TableDesc> KvTable<'_, D> {
    /// Initialize a table by setting its owner.
    ///
    /// Calling this function is optional, a table can be used without initialization in which case,
    /// its owner is set to the owner specifed in the first write.
    ///
    /// Returns an error (containing the current owner of the table) if the table has already been
    /// initialized. In this case, the table will be in a consistent state and can be used as normal.
    pub fn init(&self) -> Result<()> {
        <&Self as TabularOpsMut>::init(self, self.owner)
    }

    /// The number of key/value pairs in the table.
    pub fn len(&self) -> usize {
        <&Self as TabularOps>::len(self)
    }

    /// True if the table is empty.
    pub fn is_empty(&self) -> bool {
        <&Self as TabularOps>::is_empty(self)
    }

    /// Clear a table by removing all its KVs, but preserve ownership.
    pub fn clear(&self) {
        <&Self as TabularOpsMut>::clear(self, self.owner)
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
        <&Self as TabularOps>::get(self, key, self.owner)
    }

    /// Get immutable access to a row of the table in the store by reference.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    pub fn with<Q, T>(&self, key: &Q, f: impl FnOnce(&D::Value) -> T) -> Option<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        <&Self as TabularOps>::with(self, key, f, self.owner)
    }

    /// Insert a value into the table.
    ///
    /// Returns the previous value if there is one, or `None` if there is no value for the specified key.
    pub fn insert(&self, key: D::Key, value: D::Value) -> Option<D::Value>
    where
        D::Key: Clone,
    {
        <&Self as TabularOpsMut>::insert(self, key, value, self.owner)
    }

    /// Get mutable access to a row of the table in the store in the store.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    pub fn with_mut<Q, T>(&self, key: &Q, f: impl FnOnce(&mut D::Value) -> T) -> Option<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = D::Key>,
    {
        <&Self as TabularOpsMut>::with_mut(self, key, f, self.owner)
    }

    /// Remove a row from the table.
    ///
    /// Returns the previous value if there is one, or `None` if there is no value for the specified key.
    pub fn remove<Q>(&self, key: &Q) -> Option<D::Value>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        <&Self as TabularOpsMut>::remove(self, key, self.owner)
    }

    /// Iterate all the key/value pairs in a table.
    pub fn iter(&self) -> impl Iterator<Item = (&D::Key, &D::Value)> {
        <&Self as TabularOps>::iter(self, self.owner)
    }

    /// Iterate all the keys in a table.
    pub fn keys(&self) -> impl Iterator<Item = &D::Key> {
        <&Self as TabularOps>::keys(self, self.owner)
    }

    /// Iterate all the values in a table.
    pub fn values(&self) -> impl Iterator<Item = &D::Value> {
        <&Self as TabularOps>::values(self, self.owner)
    }

    /// Iterate all the key/value pairs in a table. Values are mutable.
    pub fn for_each_mut(&self, f: impl FnMut(&D::Key, &mut D::Value)) {
        <&Self as TabularOpsMut>::for_each_mut(self, f, self.owner)
    }
}

#[cfg(test)]
mod test {
    use std::{any::Any, sync::Arc};

    use crate::{Error, singleton, tables};

    singleton!(Count(u64));
    singleton!(Name(String as Box));
    singleton!(Shared(String as Arc));
    singleton!(Label(u64 as Ref));

    tables!(Items(&'static str => String), Counters(u32 => u64));

    const OWNER: &str = "owner";
    const OTHER: &str = "other";

    #[test]
    fn get_returns_none_when_absent() {
        let store = KvStore::new();
        assert!(store.get::<Count>(OWNER).is_none());
    }

    #[test]
    fn get_returns_value_after_insert() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 42);
        assert_eq!(store.get::<Count>(OWNER), Some(42));
    }

    #[test]
    fn get_returns_none_after_clear() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        store.clear::<Count>(OWNER);
        assert!(store.get::<Count>(OWNER).is_none());
    }

    #[test]
    fn get_returns_none_after_remove() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        store.remove::<Count>(OWNER);
        assert!(store.get::<Count>(OWNER).is_none());
    }

    #[test]
    fn get_ref_singleton() {
        static STATIC_LABEL: u64 = 99;
        let store = KvStore::new();
        store.insert::<Label>(OWNER, &STATIC_LABEL);
        assert_eq!(store.get::<Label>(OWNER), Some(99));
    }

    #[test]
    fn get_arc_returns_none_when_absent() {
        let store = KvStore::new();
        assert!(store.get_arc::<Shared>(OWNER).is_none());
    }

    #[test]
    fn get_arc_returns_arc_after_insert() {
        let store = KvStore::new();
        store.insert::<Shared>(OWNER, Arc::new("hello".to_owned()));
        let arc = store.get_arc::<Shared>(OWNER).unwrap();
        assert_eq!(*arc, "hello");
    }

    #[test]
    fn get_arc_shares_allocation() {
        let store = KvStore::new();
        store.insert::<Shared>(OWNER, Arc::new("hello".to_owned()));
        let arc1 = store.get_arc::<Shared>(OWNER).unwrap();
        let arc2 = store.get_arc::<Shared>(OWNER).unwrap();
        assert!(Arc::ptr_eq(&arc1, &arc2));
    }

    #[test]
    fn with_returns_none_and_does_not_call_f_when_absent() {
        let store = KvStore::new();
        let mut called = false;
        let result = store.with::<Count, ()>(OWNER, |_| {
            called = true;
        });
        assert!(result.is_none());
        assert!(!called);
    }

    #[test]
    fn with_returns_result_of_f() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 5);
        assert_eq!(store.with::<Count, _>(OWNER, |v| v * 2), Some(10));
    }

    #[test]
    fn insert_returns_none_on_first_insert() {
        let store = KvStore::new();
        assert!(store.insert::<Count>(OWNER, 1).is_none());
    }

    #[test]
    fn insert_returns_previous_value() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        assert_eq!(store.insert::<Count>(OWNER, 2), Some(1));
    }

    #[test]
    fn insert_over_tombstone_returns_none() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        store.clear::<Count>(OWNER);
        assert!(store.insert::<Count>(OWNER, 2).is_none());
    }

    #[test]
    fn insert_over_removed_returns_none() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        store.remove::<Count>(OWNER);
        assert!(store.insert::<Count>(OWNER, 2).is_none());
    }

    #[test]
    fn mutate_returns_none_and_does_not_call_f_when_absent() {
        let store = KvStore::new();
        let mut called = false;
        let result = store.with_mut::<Count, ()>(OWNER, |_| {
            called = true;
        });
        assert!(result.is_none());
        assert!(!called);
    }

    #[test]
    fn mutate_modifies_value_in_place() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 10);
        assert_eq!(
            store.with_mut::<Count, _>(OWNER, |v| {
                *v += 5;
                *v
            }),
            Some(15)
        );
        assert_eq!(store.get::<Count>(OWNER), Some(15));
    }

    #[test]
    fn mutate_on_tombstone_returns_none() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        store.clear::<Count>(OWNER);
        assert!(store.with_mut::<Count, ()>(OWNER, |_| {}).is_none());
    }

    #[test]
    fn mutate_box_singleton() {
        let store = KvStore::new();
        store.insert::<Name>(OWNER, "hello".to_owned());
        store.with_mut::<Name, ()>(OWNER, |s| s.push_str(" world"));
        assert_eq!(store.get::<Name>(OWNER), Some("hello world".to_owned()));
    }

    #[test]
    fn remove_returns_none_when_absent() {
        let store = KvStore::new();
        assert!(store.remove::<Count>(OWNER).is_none());
    }

    #[test]
    fn remove_returns_previous_value() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 7);
        assert_eq!(store.remove::<Count>(OWNER), Some(7));
    }

    #[test]
    fn remove_makes_entry_absent() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        store.remove::<Count>(OWNER);
        assert!(store.get::<Count>(OWNER).is_none());
    }

    #[test]
    fn remove_allows_reinsert_by_other_owner() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        store.remove::<Count>(OWNER);
        // Entry is fully gone — any owner can insert
        store.insert::<Count>(OTHER, 2);
        assert_eq!(store.get::<Count>(OTHER), Some(2));
    }

    #[test]
    fn clear_returns_none_when_absent() {
        let store = KvStore::new();
        assert!(store.clear::<Count>(OWNER).is_none());
    }

    #[test]
    fn clear_returns_previous_value() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 3);
        assert_eq!(store.clear::<Count>(OWNER), Some(3));
    }

    #[test]
    fn clear_makes_get_return_none() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        store.clear::<Count>(OWNER);
        assert!(store.get::<Count>(OWNER).is_none());
    }

    #[test]
    fn double_clear_returns_none() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        store.clear::<Count>(OWNER);
        assert!(store.clear::<Count>(OWNER).is_none());
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Ownership violation")]
    fn singleton_insert_wrong_owner_panics() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        store.insert::<Count>(OTHER, 2);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Ownership violation")]
    fn singleton_mutate_wrong_owner_panics() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        store.with_mut::<Count, ()>(OTHER, |_| {});
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Ownership violation")]
    fn singleton_remove_wrong_owner_panics() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        store.remove::<Count>(OTHER);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Ownership violation")]
    fn singleton_clear_wrong_owner_panics() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        store.clear::<Count>(OTHER);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Ownership violation")]
    fn singleton_clear_blocks_other_owner() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        store.clear::<Count>(OWNER);
        // Tombstone preserves OWNER — OTHER cannot insert
        store.insert::<Count>(OTHER, 2);
    }

    #[test]
    fn table_init_succeeds_on_fresh_table() {
        let store = KvStore::new();
        assert!(store.table::<Items>(OWNER).init().is_ok());
    }

    #[test]
    fn table_init_second_call_returns_err() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).init().unwrap();
        let err = store.table::<Items>(OWNER).init().unwrap_err();
        assert!(matches!(err, Error::AlreadyInit(o) if o == OWNER));
    }

    #[test]
    fn table_init_with_different_owner_returns_err() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).init().unwrap();
        let err = store.table::<Items>(OTHER).init().unwrap_err();
        assert!(matches!(err, Error::AlreadyInit(o) if o == OWNER));
    }

    #[test]
    fn table_init_is_optional() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("k", "v".to_owned());
        assert_eq!(store.table::<Items>(OWNER).get("k"), Some("v".to_owned()));
    }

    #[test]
    fn table_get_returns_none_when_absent() {
        let store = KvStore::new();
        assert!(store.table::<Items>(OWNER).get("missing").is_none());
    }

    #[test]
    fn table_insert_returns_none_on_first() {
        let store = KvStore::new();
        assert!(
            store
                .table::<Items>(OWNER)
                .insert("k", "v".to_owned())
                .is_none()
        );
    }

    #[test]
    fn table_insert_returns_previous_value() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("k", "v1".to_owned());
        assert_eq!(
            store.table::<Items>(OWNER).insert("k", "v2".to_owned()),
            Some("v1".to_owned()),
        );
    }

    #[test]
    fn table_get_returns_value_after_insert() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("k", "val".to_owned());
        assert_eq!(store.table::<Items>(OWNER).get("k"), Some("val".to_owned()));
    }

    #[test]
    fn table_get_with_borrow_type() {
        let store = KvStore::new();
        store.table::<Counters>(OWNER).insert(42u32, 100u64);
        assert_eq!(store.table::<Counters>(OWNER).get(&42u32), Some(100u64));
    }

    #[test]
    fn table_with_returns_none_and_does_not_call_f_when_absent() {
        let store = KvStore::new();
        let mut called = false;
        let result = store.table::<Items>(OWNER).with("missing", |_| {
            called = true;
        });
        assert!(result.is_none());
        assert!(!called);
    }

    #[test]
    fn table_with_returns_some_after_insert() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("k", "val".to_owned());
        assert_eq!(store.table::<Items>(OWNER).with("k", |s| s.len()), Some(3));
    }

    #[test]
    fn table_mutate_returns_none_when_absent() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).init().unwrap();
        assert!(
            store
                .table::<Items>(OWNER)
                .with_mut(&"missing", |v| v.len())
                .is_none()
        );
    }

    #[test]
    fn table_mutate_modifies_value() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("k", "hello".to_owned());
        store.table::<Items>(OWNER).with_mut(&"k", |v| v.push('!'));
        assert_eq!(
            store.table::<Items>(OWNER).get("k"),
            Some("hello!".to_owned())
        );
    }

    #[test]
    fn table_remove_returns_none_when_absent() {
        let store = KvStore::new();
        assert!(store.table::<Items>(OWNER).remove("missing").is_none());
    }

    #[test]
    fn table_remove_returns_previous_value() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("k", "v".to_owned());
        assert_eq!(
            store.table::<Items>(OWNER).remove("k"),
            Some("v".to_owned())
        );
    }

    #[test]
    fn table_remove_makes_get_return_none() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("k", "v".to_owned());
        store.table::<Items>(OWNER).remove("k");
        assert!(store.table::<Items>(OWNER).get("k").is_none());
    }

    #[test]
    fn table_clear_removes_all_rows() {
        let store = KvStore::new();
        let table = store.table::<Items>(OWNER);
        table.insert("a", "alpha".to_owned());
        table.insert("b", "beta".to_owned());
        table.insert("c", "gamma".to_owned());
        table.clear();
        assert!(table.is_empty());
    }

    #[test]
    fn table_clear_preserves_ownership() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("k", "v".to_owned());
        store.table::<Items>(OWNER).clear();
        // Same owner can still write after clear
        store.table::<Items>(OWNER).insert("k2", "v2".to_owned());
        assert_eq!(store.table::<Items>(OWNER).get("k2"), Some("v2".to_owned()));
    }

    #[test]
    fn table_is_empty_on_fresh_store() {
        let store = KvStore::new();
        assert!(store.table::<Items>(OWNER).is_empty());
    }

    #[test]
    fn table_len_zero_on_fresh_store() {
        let store = KvStore::new();
        assert_eq!(store.table::<Items>(OWNER).len(), 0);
    }

    #[test]
    fn table_len_increases_with_inserts() {
        let store = KvStore::new();
        let table = store.table::<Items>(OWNER);
        table.insert("a", "alpha".to_owned());
        table.insert("b", "beta".to_owned());
        table.insert("c", "gamma".to_owned());
        assert_eq!(table.len(), 3);
    }

    #[test]
    fn table_len_decreases_after_remove() {
        let store = KvStore::new();
        let table = store.table::<Items>(OWNER);
        table.insert("a", "alpha".to_owned());
        table.insert("b", "beta".to_owned());
        table.remove("a");
        assert_eq!(table.len(), 1);
    }

    #[test]
    fn table_is_empty_false_after_insert() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("k", "v".to_owned());
        assert!(!store.table::<Items>(OWNER).is_empty());
    }

    #[test]
    fn table_iter_empty_on_fresh_store() {
        let store = KvStore::new();
        let table = store.table::<Items>(OWNER);
        let items: Vec<_> = table.iter().collect();
        assert!(items.is_empty());
    }

    #[test]
    fn table_iter_yields_all_rows() {
        let store = KvStore::new();
        let table = store.table::<Items>(OWNER);
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
    fn table_iter_reflects_mutations() {
        let store = KvStore::new();
        let table = store.table::<Items>(OWNER);
        table.insert("k", "v1".to_owned());
        table.with_mut(&"k", |v| {
            v.clear();
            v.push_str("v2");
        });
        let items: Vec<_> = table.iter().collect();
        assert_eq!(items, vec![(&"k", &"v2".to_owned())]);
    }

    #[test]
    fn table_for_each_empty_calls_closure_zero_times() {
        let store = KvStore::new();
        let table = store.table::<Items>(OWNER);
        let mut count = 0;
        table.iter().for_each(|_| count += 1);
        assert_eq!(count, 0);
    }

    #[test]
    fn table_for_each_yields_all_rows() {
        let store = KvStore::new();
        let table = store.table::<Items>(OWNER);
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
    fn table_for_each_mut_empty_calls_closure_zero_times() {
        let store = KvStore::new();
        let table = store.table::<Items>(OWNER);
        let mut count = 0;
        table.for_each_mut(|_, _| count += 1);
        assert_eq!(count, 0);
    }

    #[test]
    fn table_for_each_mut_modifies_values() {
        let store = KvStore::new();
        let table = store.table::<Items>(OWNER);
        table.insert("k", "hello".to_owned());
        table.for_each_mut(|_, v| v.push('!'));
        assert_eq!(table.get("k"), Some("hello!".to_owned()));
    }

    #[test]
    fn table_iter_keys_cloned_empty() {
        let store = KvStore::new();
        let table = store.table::<Items>(OWNER);
        let keys: Vec<_> = table.keys().collect();
        assert!(keys.is_empty());
    }

    #[test]
    fn table_iter_keys_cloned_yields_all_keys() {
        let store = KvStore::new();
        let table = store.table::<Items>(OWNER);
        table.insert("a", "alpha".to_owned());
        table.insert("b", "beta".to_owned());
        let mut keys: Vec<_> = table.keys().copied().collect();
        keys.sort();
        assert_eq!(keys, vec!["a", "b"]);
    }

    #[test]
    fn table_iter_values_cloned_empty() {
        let store = KvStore::new();
        let table = store.table::<Items>(OWNER);
        let values: Vec<_> = table.values().collect();
        assert!(values.is_empty());
    }

    #[test]
    fn table_iter_values_cloned_yields_all_values() {
        let store = KvStore::new();
        let table = store.table::<Items>(OWNER);
        table.insert("a", "alpha".to_owned());
        table.insert("b", "beta".to_owned());
        let mut values: Vec<_> = table.values().collect();
        values.sort();
        assert_eq!(values, vec!["alpha", "beta"]);
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Ownership violation")]
    fn table_insert_wrong_owner_panics() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).init().unwrap();
        store.table::<Items>(OTHER).insert("k", "v".to_owned());
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Ownership violation")]
    fn table_mutate_wrong_owner_panics() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).init().unwrap();
        store.table::<Items>(OTHER).with_mut(&"k", |v| v.len());
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Ownership violation")]
    fn table_remove_wrong_owner_panics() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).init().unwrap();
        store.table::<Items>(OTHER).remove("k");
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Ownership violation")]
    fn table_clear_wrong_owner_panics() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).init().unwrap();
        store.table::<Items>(OTHER).clear();
    }
}
