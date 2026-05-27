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
    type Desc: TableDesc<Storage = <Self::Storage as StorageLike>::Generated>;

    fn len(self) -> usize {
        let storage = self.read_lock();
        let table = <Self::Desc as TableDesc>::get_table(storage.tables());
        table.data.len()
    }

    fn is_empty(self) -> bool {
        let storage = self.read_lock();
        let table = <Self::Desc as TableDesc>::get_table(storage.tables());
        table.data.is_empty()
    }

    fn get<Q>(self, key: &Q, _owner: Owner) -> Option<<Self::Desc as TableDesc>::Value>
    where
        <Self::Desc as TableDesc>::Value: Clone,
        <Self::Desc as TableDesc>::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        let storage = self.read_lock();
        let table = <Self::Desc as TableDesc>::get_table(storage.tables());
        table.data.get(key).cloned()
    }

    fn with<Q, T>(
        self,
        key: &Q,
        f: impl FnOnce(&<Self::Desc as TableDesc>::Value) -> T,
        _owner: Owner,
    ) -> Option<T>
    where
        <Self::Desc as TableDesc>::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        let storage = self.read_lock();
        let table = <Self::Desc as TableDesc>::get_table(storage.tables());
        let value = table.data.get(key)?;

        Some(f(value))
    }

    fn iter<'guard>(
        self,
        _owner: Owner,
    ) -> impl Iterator<
        Item = (
            &'guard <Self::Desc as TableDesc>::Key,
            &'guard <Self::Desc as TableDesc>::Value,
        ),
    >
    where
        Self::ReadLock: 'guard,
        Self::Desc: 'guard,
    {
        let guard = self.read_lock();
        TableIterator::<'guard, Self::ReadLock, Self::Desc, iter::KeysAndValues>::new(guard)
    }

    fn keys<'guard>(
        self,
        _owner: Owner,
    ) -> impl Iterator<Item = &'guard <Self::Desc as TableDesc>::Key>
    where
        Self::ReadLock: 'guard,
        Self::Desc: 'guard,
    {
        let guard = self.read_lock();
        TableIterator::<'guard, Self::ReadLock, Self::Desc, iter::Keys>::new(guard)
    }

    fn values<'guard>(
        self,
        _owner: Owner,
    ) -> impl Iterator<Item = &'guard <Self::Desc as TableDesc>::Value>
    where
        Self::ReadLock: 'guard,
        Self::Desc: 'guard,
    {
        let guard = self.read_lock();
        TableIterator::<'guard, Self::ReadLock, Self::Desc, iter::Values>::new(guard)
    }
}

pub(crate) trait IndexedOps: Ops {
    type Index: IndexDesc<Storage = <Self::Storage as StorageLike>::Generated>;

    fn len(self) -> usize {
        let storage = self.read_lock();
        let base =
            <<Self::Index as IndexDesc>::BaseTable as TableDesc>::get_table(storage.tables());
        base.data.len()
    }

    fn is_empty(self) -> bool {
        let storage = self.read_lock();
        let base =
            <<Self::Index as IndexDesc>::BaseTable as TableDesc>::get_table(storage.tables());
        base.data.is_empty()
    }

    fn get<Q>(self, key: &Q, _owner: Owner) -> Option<BaseVal<Self::Index>>
    where
        <Self::Index as TableDesc>::Key: Borrow<Q>,
        <Self::Index as TableDesc>::Value: Hash + Eq,
        BaseVal<Self::Index>: Clone,
        Q: ?Sized + Hash + Eq,
    {
        let storage = self.read_lock();
        let base =
            <<Self::Index as IndexDesc>::BaseTable as TableDesc>::get_table(storage.tables());
        let index = <Self::Index as TableDesc>::get_table(storage.tables());
        let base_key = index.data.get(key)?;
        base.data.get(base_key).cloned()
    }

    fn with<Q, T>(
        self,
        key: &Q,
        f: impl FnOnce(&<<Self::Index as IndexDesc>::BaseTable as TableDesc>::Value) -> T,
        _owner: Owner,
    ) -> Option<T>
    where
        <Self::Index as TableDesc>::Key: Borrow<Q>,
        <Self::Index as TableDesc>::Value: Hash + Eq,
        Q: ?Sized + Hash + Eq,
    {
        let storage = self.read_lock();
        let base =
            <<Self::Index as IndexDesc>::BaseTable as TableDesc>::get_table(storage.tables());
        let index = <Self::Index>::get_table(storage.tables());
        let base_key = index.data.get(key)?;
        let value = base.data.get(base_key)?;

        Some(f(value))
    }

    fn iter<'guard>(
        self,
        _owner: Owner,
    ) -> impl Iterator<
        Item = (
            &'guard <Self::Index as TableDesc>::Key,
            &'guard <<Self::Index as IndexDesc>::BaseTable as TableDesc>::Value,
        ),
    >
    where
        Self::ReadLock: 'guard,
        Self::Index: 'guard,
        <Self::Index as TableDesc>::Value: Hash + Eq,
    {
        let guard = self.read_lock();
        IndexIterator::<'guard, <Self as Ops>::ReadLock, Self::Index, iter::KeysAndValues>::new(
            guard,
        )
    }

    fn keys<'guard>(
        self,
        _owner: Owner,
    ) -> impl Iterator<Item = &'guard <Self::Index as TableDesc>::Key>
    where
        Self::ReadLock: 'guard,
        Self::Index: 'guard,
    {
        let guard = self.read_lock();
        IndexIterator::<'guard, <Self as Ops>::ReadLock, Self::Index, iter::Keys>::new(guard)
    }

    fn values<'guard>(
        self,
        _owner: Owner,
    ) -> impl Iterator<Item = &'guard <<Self::Index as IndexDesc>::BaseTable as TableDesc>::Value>
    where
        Self::ReadLock: 'guard,
        Self::Index: 'guard,
        <Self::Index as TableDesc>::Value: Hash + Eq,
    {
        let guard = self.read_lock();
        IndexIterator::<'guard, <Self as Ops>::ReadLock, Self::Index, iter::Values>::new(guard)
    }
}

pub(crate) trait OpsMut: Sized {
    type WriteLock: DerefMut<Target = Self::StorageMut>;
    type StorageMut: StorageLike;

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
    type DescMut: TableDesc<Storage = <Self::StorageMut as StorageLike>::Generated>;

    fn init(self, owner: Owner) -> Result<()> {
        let mut storage = self.write_lock();

        let table = Self::DescMut::get_table_mut(storage.tables_mut());
        table.try_set_owner(owner)
    }

    fn clear(self, owner: Owner) {
        let mut storage = self.write_lock();
        let table = Self::DescMut::get_table_mut(storage.tables_mut());
        table.assert_or_set_owner(owner);
        table.indexes.clear();
        table.data.clear();
    }

    fn insert(
        self,
        key: <Self::DescMut as TableDesc>::Key,
        value: <Self::DescMut as TableDesc>::Value,
        owner: Owner,
    ) -> Option<<Self::DescMut as TableDesc>::Value>
    where
        <Self::DescMut as TableDesc>::Key: Clone,
    {
        let mut storage = self.write_lock();
        let table = Self::DescMut::get_table_mut(storage.tables_mut());
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
        f: impl FnOnce(&mut <Self::DescMut as TableDesc>::Value) -> T,
        owner: Owner,
    ) -> Option<T>
    where
        <Self::DescMut as TableDesc>::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = <Self::DescMut as TableDesc>::Key>,
    {
        let mut storage = self.write_lock();
        let table = Self::DescMut::get_table_mut(storage.tables_mut());
        table.assert_owner(owner);
        let value = table.data.get_mut(key)?;

        table.indexes.on_remove(value);
        let result = f(value);
        table.indexes.on_insert(key, value);

        Some(result)
    }

    fn remove<Q>(self, key: &Q, owner: Owner) -> Option<<Self::DescMut as TableDesc>::Value>
    where
        <Self::DescMut as TableDesc>::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        let mut storage = self.write_lock();
        let table = Self::DescMut::get_table_mut(storage.tables_mut());
        table.assert_owner(owner);
        let value = table.data.remove(key.borrow())?;
        table.indexes.on_remove(&value);
        Some(value)
    }

    // TODO if `f` panics then the indexes will be left in an inconsistent state.
    fn for_each_mut(
        self,
        mut f: impl FnMut(&<Self::DescMut as TableDesc>::Key, &mut <Self::DescMut as TableDesc>::Value),
        owner: Owner,
    ) {
        let mut storage = self.write_lock();
        let table = Self::DescMut::get_table_mut(storage.tables_mut());
        table.assert_owner(owner);

        for (k, v) in &mut table.data {
            f(k, v);
        }

        table.indexes.clear();
        table.indexes.build(table.data.iter());
    }
}

type Base<T> = <T as IndexDesc>::BaseTable;
type BaseKey<T> = <<T as IndexDesc>::BaseTable as TableDesc>::Key;
type BaseVal<T> = <<T as IndexDesc>::BaseTable as TableDesc>::Value;
type IKey<T> = <T as TableDesc>::Key;
type IVal<T> = <T as TableDesc>::Value;

pub(crate) trait IndexedOpsMut: OpsMut {
    type IndexMut: IndexDesc<Storage = <Self::StorageMut as StorageLike>::Generated>;

    fn init(self, owner: Owner) -> Result<()> {
        let mut storage = self.write_lock();
        let base = Base::<Self::IndexMut>::get_table_mut(storage.tables_mut());
        base.try_set_owner(owner)
    }

    fn clear(self, owner: Owner)
    where
        <Self::IndexMut as TableDesc>::Value: Hash + Eq,
    {
        let mut storage = self.write_lock();
        let base: &mut crate::storage::Table<
            <Self::IndexMut as IndexDesc>::BaseTable,
            <<Self::IndexMut as IndexDesc>::BaseTable as TableDesc>::Indexes,
        > = <Self::IndexMut as IndexDesc>::BaseTable::get_table_mut(storage.tables_mut());
        base.assert_or_set_owner(owner);
        base.indexes.clear();
        base.data.clear();
    }

    fn insert(
        self,
        key: BaseKey<Self::IndexMut>,
        value: BaseVal<Self::IndexMut>,
        owner: Owner,
    ) -> Option<BaseVal<Self::IndexMut>>
    where
        BaseKey<Self::IndexMut>: Clone,
        IVal<Self::IndexMut>: Hash + Eq,
    {
        let mut storage = self.write_lock();
        let base = <<Self::IndexMut as IndexDesc>::BaseTable>::get_table_mut(storage.tables_mut());
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
        f: impl FnOnce(&mut <<Self::IndexMut as IndexDesc>::BaseTable as TableDesc>::Value) -> T,
        owner: Owner,
    ) -> Option<T>
    where
        IKey<Self::IndexMut>: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        BaseKey<Self::IndexMut>: Clone,
        IVal<Self::IndexMut>: Hash + Eq,
    {
        let mut storage = self.write_lock();
        let index = <Self::IndexMut as TableDesc>::get_table(storage.tables_mut());
        let base_key: *const <<Self::IndexMut as IndexDesc>::BaseTable as TableDesc>::Key =
            index.data.get(key)? as *const _;
        // SAFETY: `B` and `D` are different tables, so `get_table[_mut]` will return pointers to
        // different `Table` objects. `base_key` is a pointer into `index` and cannot be a pointer
        // into `base`.
        let base_key = unsafe { &*base_key };
        let base = <<Self::IndexMut as IndexDesc>::BaseTable>::get_table_mut(storage.tables_mut());
        base.assert_owner(owner);
        let value = base.data.get_mut(base_key)?;
        // TODO we could be more efficient and only update indexes if the foreign key changes
        base.indexes.on_remove(value);
        let result = f(value);
        base.indexes.on_insert(base_key, value);

        Some(result)
    }

    fn remove<Q>(self, key: &Q, owner: Owner) -> Option<BaseVal<Self::IndexMut>>
    where
        IKey<Self::IndexMut>: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        IVal<Self::IndexMut>: Hash + Eq,
    {
        let mut storage = self.write_lock();

        // First check ownership, then do the operation.
        let base = <<Self::IndexMut as IndexDesc>::BaseTable>::get_table_mut(storage.tables_mut());
        base.assert_owner(owner);

        let index = <Self::IndexMut as TableDesc>::get_table_mut(storage.tables_mut());
        let base_key = index.data.remove(key)?;
        let base = <<Self::IndexMut as IndexDesc>::BaseTable>::get_table_mut(storage.tables_mut());
        let value = base.data.remove(base_key.borrow())?;
        base.indexes.on_remove(&value);
        Some(value)
    }

    // TODO if `f` panics then the indexes will be left in an inconsistent state.
    fn for_each_mut(
        self,
        mut f: impl FnMut(
            &<Self::IndexMut as TableDesc>::Key,
            &mut <<Self::IndexMut as IndexDesc>::BaseTable as TableDesc>::Value,
        ),
        owner: Owner,
    ) where
        IVal<Self::IndexMut>: Hash + Eq,
    {
        let mut storage = self.write_lock();
        let tables: *mut _ = storage.tables_mut();
        // SAFETY: `B` and `D` are different tables, so `get_table[_mut]` will return pointers to
        // different `Table` objects. Although the compiler treats `base` and `index` as having
        // a reference to `storage.tables`, they do not, so the references here are transient and
        // all mutable references are unique.
        let base =
            <<Self::IndexMut as IndexDesc>::BaseTable>::get_table_mut(unsafe { &mut *tables });
        base.assert_owner(owner);
        let index = <Self::IndexMut as TableDesc>::get_table(storage.tables_mut());

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
