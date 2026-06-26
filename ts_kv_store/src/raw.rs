//! KvStore non-transactional API.

use std::{borrow::Borrow, hash::Hash, sync::Arc};

use crate::{
    Error, KvStore, KvTableTransactional, Owner, Result, StoreWithOwner,
    index::KvTableIndex,
    operations::{Ops, SingletonOps, SingletonOpsMut, TabularOps, TabularOpsMut},
    schema,
    storage::Storage,
};

impl<'store, TableStorage: schema::GeneratedStorage> Ops<TableStorage>
    for &'store KvStore<TableStorage>
{
    type ReadLock = std::sync::RwLockReadGuard<'store, Storage<TableStorage>>;

    fn read_lock(self) -> Self::ReadLock {
        self.get_read_lock()
    }
}

impl<TableStorage: schema::GeneratedStorage> SingletonOps<TableStorage> for &KvStore<TableStorage> {}

impl<'a, D: schema::TableDesc> Ops<D::Storage> for &'a KvTable<'_, D> {
    type ReadLock = std::sync::RwLockReadGuard<'a, Storage<D::Storage>>;

    fn read_lock(self) -> Self::ReadLock {
        self.store.get_read_lock()
    }
}

impl<D: schema::TableDesc> TabularOps<D::Storage> for &KvTable<'_, D> {
    type TableDesc = D;
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
        <&Self as SingletonOps<_>>::get::<D>(self, owner)
    }

    /// Get a single value from the store by cloning an `Arc`.
    ///
    /// Returns `None` if there is no value for the specified key. Panics if the value is not an `Arc`.
    pub fn get_arc<D: schema::ArcSingleton>(&self, owner: Owner) -> Option<Arc<D::Value>> {
        <&Self as SingletonOps<_>>::get_arc::<D>(self, owner)
    }

    /// Get immutable access to a value in the store by reference.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    pub fn with<D: schema::Singleton, T>(
        &self,
        owner: Owner,
        f: impl FnOnce(&D::Value) -> T,
    ) -> Option<T> {
        <&Self as SingletonOps<_>>::with::<D, T>(self, f, owner)
    }

    /// Insert a single value into the store.
    pub fn insert<D: schema::Singleton>(&self, owner: Owner, value: D::ArgValue) {
        let mut txn = self.begin_transaction(owner);
        SingletonOpsMut::insert::<D>(&mut txn, value, owner);
        // Should never panic since transaction should only fail on index inserts.
        txn.commit().unwrap();
    }

    /// Remove a single value from the store.
    pub fn remove<D: schema::Singleton>(&self, owner: Owner) {
        let mut txn = self.begin_transaction(owner);
        SingletonOpsMut::remove::<D>(&mut txn, owner);
        // Should never panic since transaction should only fail on index inserts.
        txn.commit().unwrap();
    }
}

impl<'a, TableStorage: schema::GeneratedStorage> StoreWithOwner<'a, TableStorage> {
    /// Operate on tables of key/values in the store.
    ///
    /// # Example:
    ///
    /// ```rust,ignore
    /// let value = store.table::<Foo>().get(key).unwrap();
    /// ```
    pub fn table<D: schema::TableDesc<Storage = TableStorage>>(&self) -> KvTable<'_, D> {
        KvTable {
            store: self.store,
            owner: self.owner,
        }
    }

    /// Access a table via an index.
    ///
    /// # Example:
    ///
    /// ```rust,ignore
    /// let value = store.table_by::<index::Foo::bar>().get(key).unwrap();
    /// ```
    ///
    /// Here `Foo` describes a tables and `bar` describes an index over `Foo` using the `bar` field
    /// as foreign key.
    pub fn table_by<D: schema::IndexDesc<Storage = TableStorage>>(&self) -> KvTableIndex<'_, D> {
        KvTableIndex {
            store: self.store,
            owner: self.owner,
        }
    }

    /// Get a single value from the store by cloning the value.
    ///
    /// Returns `None` if there is no value for the specified key.
    pub fn get<D: schema::Singleton>(&self) -> Option<D::Value>
    where
        D::Value: Clone,
    {
        self.store.get::<D>(self.owner)
    }

    /// Get a single value from the store by cloning an `Arc`.
    ///
    /// Returns `None` if there is no value for the specified key. Panics if the value is not an `Arc`.
    pub fn get_arc<D: schema::ArcSingleton>(&self) -> Option<Arc<D::Value>> {
        self.store.get_arc::<D>(self.owner)
    }

    /// Get immutable access to a value in the store by reference.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    pub fn with<D: schema::Singleton, T>(&self, f: impl FnOnce(&D::Value) -> T) -> Option<T> {
        self.store.with::<D, T>(self.owner, f)
    }

    /// Insert a single value into the store.
    pub fn insert<D: schema::Singleton>(&self, value: D::ArgValue) {
        self.store.insert::<D>(self.owner, value)
    }

    /// Remove a single value from the store.
    pub fn remove<D: schema::Singleton>(&self) {
        self.store.remove::<D>(self.owner)
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
    /// The number of key/value pairs in the table.
    pub fn len(&self) -> usize {
        <&Self as TabularOps<_>>::len(self)
    }

    /// True if the table is empty.
    pub fn is_empty(&self) -> bool {
        <&Self as TabularOps<_>>::is_empty(self)
    }

    /// Clear a table by removing all its KVs.
    pub fn clear(&self) {
        let mut txn = self.store.begin_transaction(self.owner);
        let mut txn_table = KvTableTransactional::<D> { txn: &mut txn };
        TabularOpsMut::clear(&mut txn_table, self.owner);
        // Should never panic since transaction should only fail on index inserts.
        txn.commit().unwrap();
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
        <&Self as TabularOps<_>>::get(self, key, self.owner)
    }

    /// Get immutable access to a row of the table in the store by reference.
    ///
    /// Returns `None` (and does not call `f`) if there is no value for the specified key.
    pub fn with<Q, T>(&self, key: &Q, f: impl FnOnce(&D::Value) -> T) -> Option<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        <&Self as TabularOps<_>>::with(self, key, f, self.owner)
    }

    /// Insert a `value` into the table.
    ///
    /// Panics if the value is already indexed with the same index key.
    pub fn insert(&self, key: D::Key, value: D::Value)
    where
        D::Key: Clone,
    {
        self.try_insert(key, value).unwrap();
    }

    /// Insert a `value` into the table.
    ///
    /// Returns an error if `insert` would panic.
    pub fn try_insert(&self, key: D::Key, value: D::Value) -> Result<()>
    where
        D::Key: Clone,
    {
        let mut txn = self.store.begin_transaction(self.owner);
        let mut txn_table = KvTableTransactional::<D> { txn: &mut txn };
        TabularOpsMut::insert(&mut txn_table, key, value, self.owner);
        txn.commit()
    }

    /// Get mutable access to a row of the table in the store in the store.
    ///
    /// Returns `Error::NotPresent` (and does not call `f`) if there is no value for the specified key.
    pub fn with_mut<Q, T>(&self, key: &Q, f: impl FnOnce(&mut D::Value) -> T) -> Result<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = D::Key>,
        D::Value: Clone,
    {
        let mut txn = self.store.begin_transaction(self.owner);
        let mut txn_table = KvTableTransactional::<D> { txn: &mut txn };
        let result = TabularOpsMut::with_mut(&mut txn_table, key, f, self.owner);
        txn.commit()?;
        result.ok_or(Error::NotPresent)
    }

    /// Remove a row from the table.
    pub fn remove<Q>(&self, key: &Q)
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = D::Key>,
    {
        let mut txn = self.store.begin_transaction(self.owner);
        let mut txn_table = KvTableTransactional::<D> { txn: &mut txn };
        TabularOpsMut::remove(&mut txn_table, key, self.owner);
        // Should never panic since transaction should only fail on index inserts.
        txn.commit().unwrap();
    }

    /// Iterate all the key/value pairs in a table.
    pub fn iter(&self) -> impl Iterator<Item = (&D::Key, &D::Value)> {
        <&Self as TabularOps<_>>::iter(self, self.owner)
    }

    /// Iterate all the keys in a table.
    pub fn keys(&self) -> impl Iterator<Item = &D::Key> {
        <&Self as TabularOps<_>>::keys(self, self.owner)
    }

    /// Iterate all the values in a table.
    pub fn values(&self) -> impl Iterator<Item = &D::Value> {
        <&Self as TabularOps<_>>::values(self, self.owner)
    }

    /// Iterate all the key/value pairs in a table. Values are mutable.
    pub fn for_each_mut(&self, f: impl FnMut(&D::Key, &mut D::Value))
    where
        D::Value: Clone,
    {
        let mut txn = self.store.begin_transaction(self.owner);
        let mut txn_table = KvTableTransactional::<D> { txn: &mut txn };
        TabularOpsMut::for_each_mut(&mut txn_table, f, self.owner);
        txn.commit().unwrap();
    }
}

#[cfg(test)]
mod test {
    use std::{any::Any, sync::Arc};

    use crate::{KvErrorExt, singleton, tables};

    singleton!(Count(u64; OWNER));
    singleton!(Shared(String as Arc; OWNER));
    singleton!(Label(u64 as Ref; OWNER));

    tables!(Items(&'static str => String; OWNER), Counters(u32 => u64; OWNER));

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
    fn remove_makes_entry_absent() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        store.remove::<Count>(OWNER);
        assert!(store.get::<Count>(OWNER).is_none());
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
    fn singleton_remove_wrong_owner_panics() {
        let store = KvStore::new();
        store.insert::<Count>(OWNER, 1);
        store.remove::<Count>(OTHER);
    }

    #[test]
    fn table_get_returns_none_when_absent() {
        let store = KvStore::new();
        assert!(store.table::<Items>(OWNER).get("missing").is_none());
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
        store
            .table::<Items>(OWNER)
            .with_mut(&"k", |v| v.push('!'))
            .unwrap();
        assert_eq!(
            store.table::<Items>(OWNER).get("k"),
            Some("hello!".to_owned())
        );
    }

    #[test]
    fn table_remove_makes_get_return_none() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("k", "v".to_owned());
        store.table::<Items>(OWNER).remove(&"k");
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
        table.remove(&"a");
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
        table
            .with_mut(&"k", |v| {
                v.clear();
                v.push_str("v2");
            })
            .unwrap();
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
        store.table::<Items>(OTHER).insert("k", "v".to_owned());
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Ownership violation")]
    fn table_mutate_wrong_owner_panics() {
        let store = KvStore::new();
        store
            .table::<Items>(OTHER)
            .with_mut(&"k", |v| v.len())
            .unwrap();
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Ownership violation")]
    fn table_remove_wrong_owner_panics() {
        let store = KvStore::new();
        store.table::<Items>(OTHER).remove(&"k");
    }

    #[test]
    #[cfg(debug_assertions)]
    #[should_panic(expected = "Ownership violation")]
    fn table_clear_wrong_owner_panics() {
        let store = KvStore::new();
        store.table::<Items>(OTHER).clear();
    }

    // `remove` no longer returns the removed value: it is used in statement position and its only
    // observable effect is that the row becomes absent.
    #[test]
    fn table_remove_used_in_statement_position() {
        let store = KvStore::new();
        store.table::<Items>(OWNER).insert("k", "v".to_owned());
        store.table::<Items>(OWNER).remove(&"k");
        assert_eq!(store.table::<Items>(OWNER).get("k"), None);
    }
}
