//! Generic implementations of the various storage operations.
//!
//! The high-level setup is that `Ops` and `OpsMut` abstract access to the underlying storage of the
//! KvStore. That access might be via a transaction or table or index or direct. The actual functionality
//! is implemented on subtraits of these: `SingletonOps` and `SingletonOpsMut` for operating on singleton
//! key/values, `TabularOps` and `TabularOpsMut` for operating on tables of data, and `IndexedOps` and
//! `IndexedOpsMut` for operating on tables via an index.

#![allow(clippy::wrong_self_convention)]

use std::{
    any::TypeId,
    borrow::Borrow,
    hash::Hash,
    ops::{Deref, DerefMut},
    sync::Arc,
};

use crate::{
    IndexIterator, Owner, Result, TableIterator, iter,
    schema::{self, IndexDesc, IndexStorage, TableDesc},
    singleton::{OptSingletonValue, assert_owner},
    storage::{SinValue, Storage},
};

pub(crate) trait Ops<'store, TableStorage: schema::GeneratedStorage + 'store>:
    Sized
{
    type ReadLock: Deref<Target = Storage<TableStorage>>;
    fn read_lock(self) -> Self::ReadLock;
}

pub(crate) trait SingletonOps<'store, TableStorage: schema::GeneratedStorage + 'store>:
    Ops<'store, TableStorage>
{
    fn get<D: schema::Singleton>(self, _owner: Owner) -> Option<D::Value>
    where
        D::Value: Clone,
    {
        let storage = self.read_lock();
        let key = TypeId::of::<D>();
        storage
            .get_singleton_value(&key)
            .map_singleton_value(|v| D::Value::clone(D::from_value_ref(v)))
    }

    fn get_arc<D: schema::ArcSingleton>(self, _owner: Owner) -> Option<Arc<D::Value>> {
        let storage = self.read_lock();
        let key = TypeId::of::<D>();
        storage
            .get_singleton_value(&key)
            .map_singleton_value(|v| D::from_value_arc(v))
    }

    fn with<D: schema::Singleton, T>(
        self,
        f: impl FnOnce(&D::Value) -> T,
        _owner: Owner,
    ) -> Option<T> {
        let storage = self.read_lock();
        let key = TypeId::of::<D>();
        storage
            .get_singleton_value(&key)
            .map_singleton_value(|v| f(D::from_value_ref(v)))
    }
}

pub(crate) trait TabularOps<
    'store,
    TableStorage: schema::GeneratedStorage + 'store,
    D: schema::TableDesc<Storage = TableStorage>,
>: Ops<'store, TableStorage>
{
    fn len(self) -> usize {
        let storage = self.read_lock();
        let table = D::get_table(&storage.tables);
        table.data.len()
    }

    fn is_empty(self) -> bool {
        let storage = self.read_lock();
        let table = D::get_table(&storage.tables);
        table.data.is_empty()
    }

    fn get<Q>(self, key: &Q, _owner: Owner) -> Option<D::Value>
    where
        D::Value: Clone,
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        let storage = self.read_lock();
        let table = D::get_table(&storage.tables);
        table.data.get(key).cloned()
    }

    fn with<Q, T>(self, key: &Q, f: impl FnOnce(&D::Value) -> T, _owner: Owner) -> Option<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        let storage = self.read_lock();
        let table = D::get_table(&storage.tables);
        let value = table.data.get(key)?;

        Some(f(value))
    }

    fn iter<'guard>(self, _owner: Owner) -> impl Iterator<Item = (&'guard D::Key, &'guard D::Value)>
    where
        Self: 'guard,
        'store: 'guard,
        D: 'store,
    {
        let guard = self.read_lock();
        TableIterator::<'store, 'guard, Self::ReadLock, TableStorage, D, iter::KeysAndValues>::new(
            guard,
        )
    }

    fn keys<'guard>(self, _owner: Owner) -> impl Iterator<Item = &'guard D::Key>
    where
        Self: 'guard,
        'store: 'guard,
        D: 'store,
    {
        let guard = self.read_lock();
        TableIterator::<'store, 'guard, Self::ReadLock, TableStorage, D, iter::Keys>::new(guard)
    }

    fn values<'guard>(self, _owner: Owner) -> impl Iterator<Item = &'guard D::Value>
    where
        Self: 'guard,
        'store: 'guard,
        D: 'store,
    {
        let guard = self.read_lock();
        TableIterator::<'store, 'guard, Self::ReadLock, TableStorage, D, iter::Values>::new(guard)
    }
}

pub(crate) trait IndexedOps<
    'store,
    TableStorage: schema::GeneratedStorage + 'store,
    D: IndexDesc<Storage = TableStorage, BaseTable = B, Value = B::Key>,
    B: TableDesc<Storage = TableStorage>,
>: Ops<'store, TableStorage>
{
    fn len(self) -> usize {
        let storage = self.read_lock();
        let base = B::get_table(&storage.tables);
        base.data.len()
    }

    fn is_empty(self) -> bool {
        let storage = self.read_lock();
        let base = B::get_table(&storage.tables);
        base.data.is_empty()
    }

    fn get<Q>(self, key: &Q, _owner: Owner) -> Option<B::Value>
    where
        B::Value: Clone,
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        let storage = self.read_lock();
        let base = B::get_table(&storage.tables);
        let index = D::get_table(&storage.tables);
        let base_key = index.data.get(key)?;
        base.data.get(base_key).cloned()
    }

    fn with<Q, T>(self, key: &Q, f: impl FnOnce(&B::Value) -> T, _owner: Owner) -> Option<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        let storage = self.read_lock();
        let base = B::get_table(&storage.tables);
        let index = D::get_table(&storage.tables);
        let base_key = index.data.get(key)?;
        let value = base.data.get(base_key)?;

        Some(f(value))
    }

    fn iter<'guard>(self, _owner: Owner) -> impl Iterator<Item = (&'guard D::Key, &'guard B::Value)>
    where
        Self: 'guard,
        'store: 'guard,
        B: 'store,
        D: 'store,
    {
        let guard = self.read_lock();
        IndexIterator::<'store, 'guard, Self::ReadLock, TableStorage, D, B, iter::KeysAndValues>::new(guard)
    }

    fn keys<'guard>(self, _owner: Owner) -> impl Iterator<Item = &'guard D::Key>
    where
        Self: 'guard,
        'store: 'guard,
        B: 'store,
        D: 'store,
    {
        let guard = self.read_lock();
        IndexIterator::<'store, 'guard, Self::ReadLock, TableStorage, D, B, iter::Keys>::new(guard)
    }

    fn values<'guard>(self, _owner: Owner) -> impl Iterator<Item = &'guard B::Value>
    where
        Self: 'guard,
        'store: 'guard,
        B: 'store,
        D: 'store,
    {
        let guard = self.read_lock();
        IndexIterator::<'store, 'guard, Self::ReadLock, TableStorage, D, B, iter::Values>::new(
            guard,
        )
    }
}

pub(crate) trait OpsMut<'store, TableStorage: schema::GeneratedStorage + 'store>:
    Sized
{
    type WriteLock: DerefMut<Target = Storage<TableStorage>>;

    fn write_lock(self) -> Self::WriteLock;
}

pub(crate) trait SingletonOpsMut<'store, TableStorage: schema::GeneratedStorage + 'store>:
    OpsMut<'store, TableStorage>
{
    fn insert<D: schema::Singleton>(self, value: D::ArgValue, owner: Owner) -> Option<D::ArgValue> {
        let mut storage = self.write_lock();
        let key = TypeId::of::<D>();
        assert_owner(owner, &key, &storage);
        storage
            .singletons
            .insert(key, (owner, D::to_value(value)))
            .map_singleton_value(|v| D::from_value(v))
    }

    fn with_mut<D: schema::MutSingleton, T>(
        self,
        f: impl FnOnce(&mut D::Value) -> T,
        owner: Owner,
    ) -> Option<T> {
        let mut storage = self.write_lock();
        let key = TypeId::of::<D>();
        assert_owner(owner, &key, &storage);
        storage
            .get_singleton_value_mut(&key)
            .map_singleton_value(|v| f(D::from_value_mut(v)))
    }

    fn remove<D: schema::Singleton>(self, owner: Owner) -> Option<D::ArgValue> {
        let mut storage = self.write_lock();
        let key = TypeId::of::<D>();
        assert_owner(owner, &key, &storage);
        storage
            .singletons
            .remove(&key)
            .map_singleton_value(|v| D::from_value(v))
    }

    fn clear<D: schema::Singleton>(self, owner: Owner) -> Option<D::ArgValue> {
        let mut storage = self.write_lock();
        let key = TypeId::of::<D>();
        assert_owner(owner, &key, &storage);
        storage
            .singletons
            .insert(key, (owner, SinValue::None))
            .map_singleton_value(|v| D::from_value(v))
    }
}

pub(crate) trait TabularOpsMut<
    'store,
    TableStorage: schema::GeneratedStorage + 'store,
    D: schema::TableDesc<Storage = TableStorage>,
>: OpsMut<'store, TableStorage>
{
    fn init(self, owner: Owner) -> Result<()> {
        let mut storage = self.write_lock();
        let table = D::get_table_mut(&mut storage.tables);
        table.try_set_owner(owner)
    }

    fn clear(self, owner: Owner) {
        let mut storage = self.write_lock();
        let table = D::get_table_mut(&mut storage.tables);
        table.assert_or_set_owner(owner);
        table.indexes.clear();
        table.data.clear();
    }

    fn insert(self, key: D::Key, value: D::Value, owner: Owner) -> Option<D::Value>
    where
        D::Key: Clone,
    {
        let mut storage = self.write_lock();
        let table = D::get_table_mut(&mut storage.tables);
        table.assert_or_set_owner(owner);
        if let Some(old_value) = table.data.get(&key) {
            table.indexes.on_remove(old_value);
        }
        table.indexes.on_insert(&key, &value);
        table.data.insert(key, value)
    }

    // TODO if `f` panics then the indexes will be left in an inconsistent state.
    fn with_mut<Q, T>(self, key: &Q, f: impl FnOnce(&mut D::Value) -> T, owner: Owner) -> Option<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = D::Key>,
    {
        let mut storage = self.write_lock();
        let table = D::get_table_mut(&mut storage.tables);
        table.assert_owner(owner);
        let value = table.data.get_mut(key)?;

        table.indexes.on_remove(value);
        let result = f(value);
        table.indexes.on_insert(key, value);

        Some(result)
    }

    fn remove<Q>(self, key: &Q, owner: Owner) -> Option<D::Value>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        let mut storage = self.write_lock();
        let table = D::get_table_mut(&mut storage.tables);
        table.assert_owner(owner);
        let value = table.data.remove(key.borrow())?;
        table.indexes.on_remove(&value);
        Some(value)
    }

    // TODO if `f` panics then the indexes will be left in an inconsistent state.
    fn for_each_mut(self, mut f: impl FnMut(&D::Key, &mut D::Value), owner: Owner) {
        let mut storage = self.write_lock();
        let table = D::get_table_mut(&mut storage.tables);
        table.assert_owner(owner);

        for (k, v) in &mut table.data {
            f(k, v);
        }

        table.indexes.clear();
        table.indexes.build(table.data.iter());
    }
}

pub(crate) trait IndexedOpsMut<
    'store,
    TableStorage: schema::GeneratedStorage + 'store,
    D: IndexDesc<Storage = TableStorage, BaseTable = B, Value = B::Key>,
    B: TableDesc<Storage = TableStorage>,
>: OpsMut<'store, TableStorage>
{
    fn init(self, owner: Owner) -> Result<()> {
        let mut storage = self.write_lock();
        let base = B::get_table_mut(&mut storage.tables);
        base.try_set_owner(owner)
    }

    fn clear(self, owner: Owner) {
        let mut storage = self.write_lock();
        let base: &mut crate::storage::Table<B, <B as TableDesc>::Indexes> =
            B::get_table_mut(&mut storage.tables);
        base.assert_or_set_owner(owner);
        base.indexes.clear();
        base.data.clear();
    }

    fn insert(self, key: B::Key, value: B::Value, owner: Owner) -> Option<B::Value>
    where
        B::Key: Clone,
    {
        let mut storage = self.write_lock();
        let base = B::get_table_mut(&mut storage.tables);
        base.assert_or_set_owner(owner);
        if let Some(old_value) = base.data.get(&key) {
            base.indexes.on_remove(old_value);
        }
        base.indexes.on_insert(&key, &value);

        base.data.insert(key, value)
    }

    // TODO if `f` panics then the indexes will be left in an inconsistent state.
    fn with_mut<Q, T>(self, key: &Q, f: impl FnOnce(&mut B::Value) -> T, owner: Owner) -> Option<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        B::Key: Clone,
    {
        let mut storage = self.write_lock();
        let index = D::get_table(&storage.tables);
        let base_key: *const <B as TableDesc>::Key = index.data.get(key)? as *const _;
        // SAFETY: `B` and `D` are different tables, so `get_table[_mut]` will return pointers to
        // different `Table` objects. `base_key` is a pointer into `index` and cannot be a pointer
        // into `base`.
        let base_key = unsafe { &*base_key };
        let base = B::get_table_mut(&mut storage.tables);
        base.assert_owner(owner);
        let value = base.data.get_mut(base_key)?;
        // TODO we could be more efficient and only update indexes if the foreign key changes
        base.indexes.on_remove(value);
        let result = f(value);
        base.indexes.on_insert(base_key, value);

        Some(result)
    }

    fn remove<Q>(self, key: &Q, owner: Owner) -> Option<B::Value>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        let mut storage = self.write_lock();

        // First check ownership, then do the operation.
        let base = B::get_table_mut(&mut storage.tables);
        base.assert_owner(owner);

        let index = D::get_table_mut(&mut storage.tables);
        let base_key = index.data.remove(key)?;
        let base = B::get_table_mut(&mut storage.tables);
        let value = base.data.remove(base_key.borrow())?;
        base.indexes.on_remove(&value);
        Some(value)
    }

    // TODO if `f` panics then the indexes will be left in an inconsistent state.
    fn for_each_mut(self, mut f: impl FnMut(&D::Key, &mut B::Value), owner: Owner) {
        let mut storage = self.write_lock();
        let tables: *mut _ = &mut storage.tables;
        // SAFETY: `B` and `D` are different tables, so `get_table[_mut]` will return pointers to
        // different `Table` objects. Although the compiler treats `base` and `index` as having
        // a reference to `storage.tables`, they do not, so the references here are transient and
        // all mutable references are unique.
        let base = B::get_table_mut(unsafe { &mut *tables });
        base.assert_owner(owner);
        let index = D::get_table(&storage.tables);

        for (k, base_key) in &index.data {
            let Some(v) = base.data.get_mut(base_key) else {
                continue;
            };
            f(k, v);
        }

        // TODO we could be more efficient and only update indexes if the foreign key changes
        base.indexes.clear();
        base.indexes.build(base.data.iter());
    }
}
