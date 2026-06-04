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
    storage::{SinValue, StorageLike},
};

pub(crate) trait Ops: Sized {
    type ReadLock: Deref<Target = Self::Storage>;
    type Storage: StorageLike;

    fn read_lock(self) -> Self::ReadLock;
}

pub(crate) trait SingletonOps: Ops {
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
pub(crate) trait TabularOps: Ops {
    type TableDesc: TableDesc<Storage = <Self::Storage as StorageLike>::Generated>;

    fn len(self) -> usize {
        let storage = self.read_lock();
        let table = <Self::TableDesc as TableDesc>::get_table(storage.tables());
        table.data.len()
    }

    fn is_empty(self) -> bool {
        let storage = self.read_lock();
        let table = <Self::TableDesc as TableDesc>::get_table(storage.tables());
        table.data.is_empty()
    }

    fn get<Q>(self, key: &Q, _owner: Owner) -> Option<<Self::TableDesc as TableDesc>::Value>
    where
        <Self::TableDesc as TableDesc>::Value: Clone,
        <Self::TableDesc as TableDesc>::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        let storage = self.read_lock();
        let table = <Self::TableDesc as TableDesc>::get_table(storage.tables());
        table.data.get(key).cloned()
    }

    fn with<Q, T>(
        self,
        key: &Q,
        f: impl FnOnce(&<Self::TableDesc as TableDesc>::Value) -> T,
        _owner: Owner,
    ) -> Option<T>
    where
        <Self::TableDesc as TableDesc>::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        let storage = self.read_lock();
        let table = <Self::TableDesc as TableDesc>::get_table(storage.tables());
        let value = table.data.get(key)?;

        Some(f(value))
    }

    fn iter<'guard>(
        self,
        _owner: Owner,
    ) -> impl Iterator<
        Item = (
            &'guard <Self::TableDesc as TableDesc>::Key,
            &'guard <Self::TableDesc as TableDesc>::Value,
        ),
    >
    where
        Self::ReadLock: 'guard,
        Self::TableDesc: 'guard,
    {
        let guard = self.read_lock();
        TableIterator::<'guard, Self::ReadLock, Self::TableDesc, iter::KeysAndValues>::new(guard)
    }

    fn keys<'guard>(
        self,
        _owner: Owner,
    ) -> impl Iterator<Item = &'guard <Self::TableDesc as TableDesc>::Key>
    where
        Self::ReadLock: 'guard,
        Self::TableDesc: 'guard,
    {
        let guard = self.read_lock();
        TableIterator::<'guard, Self::ReadLock, Self::TableDesc, iter::Keys>::new(guard)
    }

    fn values<'guard>(
        self,
        _owner: Owner,
    ) -> impl Iterator<Item = &'guard <Self::TableDesc as TableDesc>::Value>
    where
        Self::ReadLock: 'guard,
        Self::TableDesc: 'guard,
    {
        let guard = self.read_lock();
        TableIterator::<'guard, Self::ReadLock, Self::TableDesc, iter::Values>::new(guard)
    }
}

pub(crate) type Base<T> = <T as IndexDesc>::BaseTable;
pub(crate) type BaseKey<T> = <<T as IndexDesc>::BaseTable as TableDesc>::Key;
pub(crate) type BaseValue<T> = <<T as IndexDesc>::BaseTable as TableDesc>::Value;
pub(crate) type IndexKey<T> = <T as TableDesc>::Key;
pub(crate) type IndexValue<T> = <T as TableDesc>::Value;

pub(crate) trait IndexedOps: Ops {
    type IndexDesc: IndexDesc<Storage = <Self::Storage as StorageLike>::Generated>;

    fn len(self) -> usize {
        let storage = self.read_lock();
        let base = Base::<Self::IndexDesc>::get_table(storage.tables());
        base.data.len()
    }

    fn is_empty(self) -> bool {
        let storage = self.read_lock();
        let base = Base::<Self::IndexDesc>::get_table(storage.tables());
        base.data.is_empty()
    }

    fn get<Q>(self, key: &Q, _owner: Owner) -> Option<BaseValue<Self::IndexDesc>>
    where
        IndexKey<Self::IndexDesc>: Borrow<Q>,
        IndexValue<Self::IndexDesc>: Hash + Eq,
        BaseValue<Self::IndexDesc>: Clone,
        Q: ?Sized + Hash + Eq,
    {
        let storage = self.read_lock();
        let base = Base::<Self::IndexDesc>::get_table(storage.tables());
        let index = <Self::IndexDesc as TableDesc>::get_table(storage.tables());
        let base_key = index.data.get(key)?;
        base.data.get(base_key).cloned()
    }

    fn with<Q, T>(
        self,
        key: &Q,
        f: impl FnOnce(&BaseValue<Self::IndexDesc>) -> T,
        _owner: Owner,
    ) -> Option<T>
    where
        IndexKey<Self::IndexDesc>: Borrow<Q>,
        IndexValue<Self::IndexDesc>: Hash + Eq,
        Q: ?Sized + Hash + Eq,
    {
        let storage = self.read_lock();
        let base = Base::<Self::IndexDesc>::get_table(storage.tables());
        let index = <Self::IndexDesc>::get_table(storage.tables());
        let base_key = index.data.get(key)?;
        let value = base.data.get(base_key)?;

        Some(f(value))
    }

    fn iter<'guard>(
        self,
        _owner: Owner,
    ) -> impl Iterator<
        Item = (
            &'guard IndexKey<Self::IndexDesc>,
            &'guard BaseValue<Self::IndexDesc>,
        ),
    >
    where
        Self::ReadLock: 'guard,
        Self::IndexDesc: 'guard,
        IndexValue<Self::IndexDesc>: Hash + Eq,
    {
        let guard = self.read_lock();
        IndexIterator::<'guard, <Self as Ops>::ReadLock, Self::IndexDesc, iter::KeysAndValues>::new(
            guard,
        )
    }

    fn keys<'guard>(self, _owner: Owner) -> impl Iterator<Item = &'guard IndexKey<Self::IndexDesc>>
    where
        Self::ReadLock: 'guard,
        Self::IndexDesc: 'guard,
    {
        let guard = self.read_lock();
        IndexIterator::<'guard, <Self as Ops>::ReadLock, Self::IndexDesc, iter::Keys>::new(guard)
    }

    fn values<'guard>(
        self,
        _owner: Owner,
    ) -> impl Iterator<Item = &'guard BaseValue<Self::IndexDesc>>
    where
        Self::ReadLock: 'guard,
        Self::IndexDesc: 'guard,
        IndexValue<Self::IndexDesc>: Hash + Eq,
    {
        let guard = self.read_lock();
        IndexIterator::<'guard, <Self as Ops>::ReadLock, Self::IndexDesc, iter::Values>::new(guard)
    }
}

pub(crate) trait OpsMut: Sized {
    type WriteLock: DerefMut<Target = Self::Storage>;
    type Storage: StorageLike;

    fn write_lock(self) -> Self::WriteLock;
}

pub(crate) trait SingletonOpsMut: OpsMut {
    fn insert<D: schema::Singleton>(self, value: D::ArgValue, owner: Owner) -> Option<D::ArgValue> {
        let mut storage = self.write_lock();
        let key = TypeId::of::<D>();
        assert_owner(owner, &key, &*storage);

        storage
            .insert_singleton(key, owner, D::to_value(value))
            .map_singleton_value(|v| D::from_value(v))
    }

    fn with_mut<D: schema::MutSingleton, T>(
        self,
        f: impl FnOnce(&mut D::Value) -> T,
        owner: Owner,
    ) -> Option<T> {
        let mut storage = self.write_lock();
        let key = TypeId::of::<D>();
        assert_owner(owner, &key, &*storage);
        storage
            .get_singleton_value_mut(&key)
            .map_singleton_value(|v| f(D::from_value_mut(v)))
    }

    fn remove<D: schema::Singleton>(self, owner: Owner) -> Option<D::ArgValue> {
        let mut storage = self.write_lock();
        let key = TypeId::of::<D>();
        assert_owner(owner, &key, &*storage);

        storage
            .remove_singleton(&key)
            .map_singleton_value(|v| D::from_value(v))
    }

    fn clear<D: schema::Singleton>(self, owner: Owner) -> Option<D::ArgValue> {
        let mut storage = self.write_lock();
        let key = TypeId::of::<D>();
        assert_owner(owner, &key, &*storage);

        storage
            .insert_singleton(key, owner, SinValue::None)
            .map_singleton_value(|v| D::from_value(v))
    }
}

pub(crate) trait TabularOpsMut: OpsMut {
    type TableDesc: TableDesc<Storage = <Self::Storage as StorageLike>::Generated>;

    fn init(self, owner: Owner) -> Result<()> {
        let mut storage = self.write_lock();

        let table = Self::TableDesc::get_table_mut(storage.tables_mut());
        table.try_set_owner(owner)
    }

    fn clear(self, owner: Owner) {
        let mut storage = self.write_lock();
        let table = Self::TableDesc::get_table_mut(storage.tables_mut());
        table.assert_or_set_owner(owner);
        table.indexes.clear();
        table.data.clear();
    }

    fn insert(
        self,
        key: <Self::TableDesc as TableDesc>::Key,
        value: <Self::TableDesc as TableDesc>::Value,
        owner: Owner,
    ) -> Option<<Self::TableDesc as TableDesc>::Value>
    where
        <Self::TableDesc as TableDesc>::Key: Clone,
    {
        let mut storage = self.write_lock();
        let table = Self::TableDesc::get_table_mut(storage.tables_mut());
        table.assert_or_set_owner(owner);
        if let Some(old_value) = table.data.get(&key) {
            table.indexes.on_remove(old_value);
        }
        table.indexes.on_insert(&key, &value);
        table.data.insert(key, value)
    }

    // TODO if `f` panics then the indexes will be left in an inconsistent state.
    fn with_mut<Q, T>(
        self,
        key: &Q,
        f: impl FnOnce(&mut <Self::TableDesc as TableDesc>::Value) -> T,
        owner: Owner,
    ) -> Option<T>
    where
        <Self::TableDesc as TableDesc>::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = <Self::TableDesc as TableDesc>::Key>,
    {
        let mut storage = self.write_lock();
        let table = Self::TableDesc::get_table_mut(storage.tables_mut());
        table.assert_owner(owner);
        let value = table.data.get_mut(key)?;

        table.indexes.on_remove(value);
        let result = f(value);
        table.indexes.on_insert(key, value);

        Some(result)
    }

    fn remove<Q>(self, key: &Q, owner: Owner) -> Option<<Self::TableDesc as TableDesc>::Value>
    where
        <Self::TableDesc as TableDesc>::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        let mut storage = self.write_lock();
        let table = Self::TableDesc::get_table_mut(storage.tables_mut());
        table.assert_owner(owner);
        let value = table.data.remove(key.borrow())?;
        table.indexes.on_remove(&value);
        Some(value)
    }

    // TODO if `f` panics then the indexes will be left in an inconsistent state.
    fn for_each_mut(
        self,
        mut f: impl FnMut(
            &<Self::TableDesc as TableDesc>::Key,
            &mut <Self::TableDesc as TableDesc>::Value,
        ),
        owner: Owner,
    ) {
        let mut storage = self.write_lock();
        let table = Self::TableDesc::get_table_mut(storage.tables_mut());
        table.assert_owner(owner);

        for (k, v) in &mut table.data {
            f(k, v);
        }

        table.indexes.clear();
        table.indexes.build(table.data.iter());
    }
}

pub(crate) trait IndexedOpsMut: OpsMut {
    type IndexDesc: IndexDesc<Storage = <Self::Storage as StorageLike>::Generated>;

    fn init(self, owner: Owner) -> Result<()> {
        let mut storage = self.write_lock();
        let base = Base::<Self::IndexDesc>::get_table_mut(storage.tables_mut());
        base.try_set_owner(owner)
    }

    fn clear(self, owner: Owner)
    where
        IndexValue<Self::IndexDesc>: Hash + Eq,
    {
        let mut storage = self.write_lock();
        let base: &mut crate::storage::Table<
            Base<Self::IndexDesc>,
            <Base<Self::IndexDesc> as TableDesc>::Indexes,
        > = Base::<Self::IndexDesc>::get_table_mut(storage.tables_mut());
        base.assert_or_set_owner(owner);
        base.indexes.clear();
        base.data.clear();
    }

    fn insert(
        self,
        key: BaseKey<Self::IndexDesc>,
        value: BaseValue<Self::IndexDesc>,
        owner: Owner,
    ) -> Option<BaseValue<Self::IndexDesc>>
    where
        BaseKey<Self::IndexDesc>: Clone,
        IndexValue<Self::IndexDesc>: Hash + Eq,
    {
        let mut storage = self.write_lock();
        let base = <<Self::IndexDesc as IndexDesc>::BaseTable>::get_table_mut(storage.tables_mut());
        base.assert_or_set_owner(owner);
        if let Some(old_value) = base.data.get(&key) {
            base.indexes.on_remove(old_value);
        }
        base.indexes.on_insert(&key, &value);

        base.data.insert(key, value)
    }

    // TODO if `f` panics then the indexes will be left in an inconsistent state.
    fn with_mut<Q, T>(
        self,
        key: &Q,
        f: impl FnOnce(&mut BaseValue<Self::IndexDesc>) -> T,
        owner: Owner,
    ) -> Option<T>
    where
        IndexKey<Self::IndexDesc>: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        BaseKey<Self::IndexDesc>: Clone,
        IndexValue<Self::IndexDesc>: Hash + Eq,
    {
        let mut storage = self.write_lock();
        let index = <Self::IndexDesc as TableDesc>::get_table(storage.tables_mut());
        let base_key: *const BaseKey<Self::IndexDesc> = index.data.get(key)? as *const _;
        // SAFETY: `B` and `D` are different tables, so `get_table[_mut]` will return pointers to
        // different `Table` objects. `base_key` is a pointer into `index` and cannot be a pointer
        // into `base`.
        let base_key = unsafe { &*base_key };
        let base = Base::<Self::IndexDesc>::get_table_mut(storage.tables_mut());
        base.assert_owner(owner);
        let value = base.data.get_mut(base_key)?;
        // TODO we could be more efficient and only update indexes if the foreign key changes
        base.indexes.on_remove(value);
        let result = f(value);
        base.indexes.on_insert(base_key, value);

        Some(result)
    }

    fn remove<Q>(self, key: &Q, owner: Owner) -> Option<BaseValue<Self::IndexDesc>>
    where
        IndexKey<Self::IndexDesc>: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        IndexValue<Self::IndexDesc>: Hash + Eq,
    {
        let mut storage = self.write_lock();

        // First check ownership, then do the operation.
        let base = Base::<Self::IndexDesc>::get_table_mut(storage.tables_mut());
        base.assert_owner(owner);

        let index = <Self::IndexDesc as TableDesc>::get_table_mut(storage.tables_mut());
        let base_key = index.data.remove(key)?;
        let base = Base::<Self::IndexDesc>::get_table_mut(storage.tables_mut());
        let value = base.data.remove(base_key.borrow())?;
        base.indexes.on_remove(&value);
        Some(value)
    }

    // TODO if `f` panics then the indexes will be left in an inconsistent state.
    fn for_each_mut(
        self,
        mut f: impl FnMut(&IndexKey<Self::IndexDesc>, &mut BaseValue<Self::IndexDesc>),
        owner: Owner,
    ) where
        IndexValue<Self::IndexDesc>: Hash + Eq,
    {
        let mut storage = self.write_lock();
        let tables: *mut _ = storage.tables_mut();
        // SAFETY: `B` and `D` are different tables, so `get_table[_mut]` will return pointers to
        // different `Table` objects. Although the compiler treats `base` and `index` as having
        // a reference to `storage.tables`, they do not, so the references here are transient and
        // all mutable references are unique.
        let base =
            <<Self::IndexDesc as IndexDesc>::BaseTable>::get_table_mut(unsafe { &mut *tables });
        base.assert_owner(owner);
        let index = <Self::IndexDesc as TableDesc>::get_table(storage.tables_mut());

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
