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
    sync::{Arc, RwLockReadGuard, RwLockWriteGuard},
};

use crate::{
    AccessError, AccessResult, IndexIterator, Owner, Result, TableIterator, iter,
    schema::{self, IndexDesc, TableDesc},
    storage::Storage,
};

pub(crate) trait Ops<TableStorage: schema::GeneratedStorage>: Sized {
    type ReadLock: StorageGuard<TableStorage>;

    fn read_lock(self) -> Self::ReadLock;
}

pub(crate) trait StorageGuardMut<TableStorage: schema::GeneratedStorage> {
    fn storage(&mut self) -> &mut Storage<TableStorage>;
}

pub(crate) trait StorageGuard<TableStorage: schema::GeneratedStorage> {
    fn storage(&self) -> &Storage<TableStorage>;
}

impl<'store, TableStorage: schema::GeneratedStorage> StorageGuard<TableStorage>
    for RwLockReadGuard<'store, Storage<TableStorage>>
{
    fn storage(&self) -> &Storage<TableStorage> {
        self
    }
}

impl<'store, TableStorage: schema::GeneratedStorage> StorageGuardMut<TableStorage>
    for RwLockWriteGuard<'store, Storage<TableStorage>>
{
    fn storage(&mut self) -> &mut Storage<TableStorage> {
        self
    }
}

impl<'a, 'inner, TableStorage: schema::GeneratedStorage> StorageGuard<TableStorage>
    for &'a RwLockReadGuard<'inner, Storage<TableStorage>>
{
    fn storage(&self) -> &Storage<TableStorage> {
        self
    }
}

impl<'a, 'inner, TableStorage: schema::GeneratedStorage> StorageGuard<TableStorage>
    for &'a RwLockWriteGuard<'inner, Storage<TableStorage>>
{
    fn storage(&self) -> &Storage<TableStorage> {
        self
    }
}

impl<'a, 'inner, TableStorage: schema::GeneratedStorage> StorageGuardMut<TableStorage>
    for &'a mut RwLockWriteGuard<'inner, Storage<TableStorage>>
{
    fn storage(&mut self) -> &mut Storage<TableStorage> {
        self
    }
}

pub(crate) trait SingletonOps<TableStorage: schema::GeneratedStorage>:
    Ops<TableStorage>
{
    fn get<D: schema::Singleton>(self, _owner: Owner) -> Option<D::Value>
    where
        D::Value: Clone,
    {
        let storage = self.read_lock();
        let storage = storage.storage();
        let key = TypeId::of::<D>();
        let txn_id = storage.txn_id();
        storage.get_singleton_value::<D>(key, txn_id).cloned()
    }

    fn get_arc<D: schema::ArcSingleton>(self, _owner: Owner) -> Option<Arc<D::Value>> {
        let storage = self.read_lock();
        let storage = storage.storage();
        let key = TypeId::of::<D>();
        let txn_id = storage.txn_id();
        storage.get_singleton_arc::<D>(key, txn_id)
    }

    fn with<D: schema::Singleton, T>(
        self,
        f: impl FnOnce(&D::Value) -> T,
        _owner: Owner,
    ) -> Option<T> {
        let storage = self.read_lock();
        let storage = storage.storage();
        let key = TypeId::of::<D>();
        let txn_id = storage.txn_id();
        let value = storage.get_singleton_value::<D>(key, txn_id)?;
        Some(f(value))
    }
}

pub(crate) trait TabularOps<TableStorage: schema::GeneratedStorage>:
    Ops<TableStorage>
{
    type TableDesc: TableDesc<Storage = TableStorage>;

    fn len(self) -> usize {
        let storage = self.read_lock();
        let storage = storage.storage();
        let table = Self::TableDesc::get_table(&storage.tables);
        table.len(storage.txn_id())
    }

    fn is_empty(self) -> bool {
        let storage = self.read_lock();
        let storage = storage.storage();
        let table = Self::TableDesc::get_table(&storage.tables);
        table.is_empty(storage.txn_id())
    }

    fn get<Q>(self, key: &Q, _owner: Owner) -> Option<<Self::TableDesc as TableDesc>::Value>
    where
        <Self::TableDesc as TableDesc>::Value: Clone,
        <Self::TableDesc as TableDesc>::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        let storage = self.read_lock();
        let storage = storage.storage();
        let table = Self::TableDesc::get_table(&storage.tables);
        table.get(key, storage.txn_id()).cloned()
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
        let storage = storage.storage();
        let table = Self::TableDesc::get_table(&storage.tables);
        let value = table.get(key, storage.txn_id())?;
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

pub(crate) trait IndexedOps<TableStorage: schema::GeneratedStorage>:
    Ops<TableStorage>
{
    type IndexDesc: IndexDesc<Storage = TableStorage>;

    fn len(self) -> usize {
        let storage = self.read_lock();
        let storage = storage.storage();
        let base = Base::<Self::IndexDesc>::get_table(&storage.tables);
        base.len(storage.txn_id())
    }

    fn is_empty(self) -> bool {
        let storage = self.read_lock();
        let storage = storage.storage();
        let base = Base::<Self::IndexDesc>::get_table(&storage.tables);
        base.is_empty(storage.txn_id())
    }

    fn check_consistent(self) -> Result<()> {
        let storage = self.read_lock();
        let storage = storage.storage();
        let index = <Self::IndexDesc as TableDesc>::get_table(&storage.tables);

        if index.is_poisoned(storage.txn_id()) {
            Err(crate::Error::NonUniqueIndexKey(
                <Self::IndexDesc as TableDesc>::NAME,
            ))
        } else {
            Ok(())
        }
    }

    fn get<Q>(self, key: &Q, _owner: Owner) -> AccessResult<BaseValue<Self::IndexDesc>>
    where
        IndexKey<Self::IndexDesc>: Borrow<Q>,
        IndexValue<Self::IndexDesc>: Hash + Eq,
        BaseValue<Self::IndexDesc>: Clone,
        Q: ?Sized + Hash + Eq,
    {
        let storage = self.read_lock();
        let storage = storage.storage();
        let base = Base::<Self::IndexDesc>::get_table(&storage.tables);
        let index = <Self::IndexDesc as TableDesc>::get_table(&storage.tables);
        if index.is_poisoned(storage.txn_id()) {
            return Err(AccessError::NonUniqueIndexKey(
                <Self::IndexDesc as TableDesc>::NAME,
            ));
        }
        let base_key = index
            .get(key, storage.txn_id())
            .ok_or(AccessError::NotPresent)?;
        base.get(base_key, storage.txn_id())
            .cloned()
            .ok_or(AccessError::NotPresent)
    }

    fn with<Q, T>(
        self,
        key: &Q,
        f: impl FnOnce(&BaseValue<Self::IndexDesc>) -> T,
        _owner: Owner,
    ) -> AccessResult<T>
    where
        IndexKey<Self::IndexDesc>: Borrow<Q>,
        IndexValue<Self::IndexDesc>: Hash + Eq,
        Q: ?Sized + Hash + Eq,
    {
        let storage = self.read_lock();
        let storage = storage.storage();
        let base = Base::<Self::IndexDesc>::get_table(&storage.tables);
        let index = <Self::IndexDesc>::get_table(&storage.tables);
        if index.is_poisoned(storage.txn_id()) {
            return Err(AccessError::NonUniqueIndexKey(
                <Self::IndexDesc as TableDesc>::NAME,
            ));
        }
        let base_key = index
            .get(key, storage.txn_id())
            .ok_or(AccessError::NotPresent)?;
        let value = base
            .get(base_key, storage.txn_id())
            .ok_or(AccessError::NotPresent)?;

        Ok(f(value))
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
        IndexIterator::<'guard, <Self as Ops<_>>::ReadLock, Self::IndexDesc, iter::KeysAndValues>::new(
            guard,
        )
    }

    fn keys<'guard>(self, _owner: Owner) -> impl Iterator<Item = &'guard IndexKey<Self::IndexDesc>>
    where
        Self::ReadLock: 'guard,
        Self::IndexDesc: 'guard,
    {
        let guard = self.read_lock();
        IndexIterator::<'guard, <Self as Ops<_>>::ReadLock, Self::IndexDesc, iter::Keys>::new(guard)
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
        IndexIterator::<'guard, <Self as Ops<_>>::ReadLock, Self::IndexDesc, iter::Values>::new(
            guard,
        )
    }
}

pub(crate) trait OpsMut<TableStorage: schema::GeneratedStorage>: Sized {
    type WriteLock: StorageGuardMut<TableStorage>;

    fn write_lock(self) -> Self::WriteLock;
}

pub(crate) trait SingletonOpsMut<TableStorage: schema::GeneratedStorage>:
    OpsMut<TableStorage>
{
    fn insert<D: schema::Singleton>(self, value: D::ArgValue, owner: Owner) {
        let mut storage = self.write_lock();
        let storage = storage.storage();
        let key = TypeId::of::<D>();
        assert_owner(owner, key, storage);

        let txn_id = storage.txn_id();
        storage.insert_singleton::<D>(key, owner, value, txn_id);
    }

    fn remove<D: schema::Singleton>(self, owner: Owner) {
        let mut storage = self.write_lock();
        let storage = storage.storage();
        let key = TypeId::of::<D>();
        assert_owner(owner, key, storage);

        let txn_id = storage.txn_id();
        storage.remove_singleton(key, txn_id);
    }
}

pub(crate) trait TabularOpsMut<TableStorage: schema::GeneratedStorage>:
    OpsMut<TableStorage>
{
    type TableDesc: TableDesc<Storage = TableStorage>;

    fn init(self, owner: Owner) -> Result<()> {
        let mut storage = self.write_lock();

        let table = Self::TableDesc::get_table_mut(&mut storage.storage().tables);
        table.try_set_owner(owner)
    }

    fn clear(self, owner: Owner) {
        let mut storage = self.write_lock();
        let storage = storage.storage();
        let txn_id = storage.txn_id();
        let max_committed_id = storage.max_committed_id();

        let table = Self::TableDesc::get_table_mut(&mut storage.tables);
        table.assert_or_set_owner(owner);
        table.clear(txn_id, max_committed_id);
    }

    fn insert(
        self,
        key: <Self::TableDesc as TableDesc>::Key,
        value: <Self::TableDesc as TableDesc>::Value,
        owner: Owner,
    ) where
        <Self::TableDesc as TableDesc>::Key: Clone,
    {
        let mut storage = self.write_lock();
        let storage = storage.storage();
        let txn_id = storage.txn_id();
        let max_committed_id = storage.max_committed_id();
        let table = Self::TableDesc::get_table_mut(&mut storage.tables);
        table.assert_or_set_owner(owner);

        table.insert(key, value, txn_id, max_committed_id);
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
        <Self::TableDesc as TableDesc>::Value: Clone,
    {
        let mut storage = self.write_lock();
        let storage = storage.storage();
        let txn_id = storage.txn_id();
        let max_committed_id = storage.max_committed_id();
        let table = Self::TableDesc::get_table_mut(&mut storage.tables);
        table.assert_owner(owner);

        table.with_mut(key, f, txn_id, max_committed_id)
    }

    fn remove<Q>(self, key: &Q, owner: Owner)
    where
        <Self::TableDesc as TableDesc>::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = <Self::TableDesc as TableDesc>::Key>,
    {
        let mut storage = self.write_lock();
        let storage = storage.storage();
        let txn_id = storage.txn_id();
        let max_committed_id = storage.max_committed_id();
        let table = Self::TableDesc::get_table_mut(&mut storage.tables);
        table.assert_owner(owner);
        table.remove(key, txn_id, max_committed_id);
    }

    // TODO if `f` panics then the indexes will be left in an inconsistent state.
    fn for_each_mut(
        self,
        f: impl FnMut(&<Self::TableDesc as TableDesc>::Key, &mut <Self::TableDesc as TableDesc>::Value),
        owner: Owner,
    ) where
        <Self::TableDesc as TableDesc>::Value: Clone,
    {
        let mut storage = self.write_lock();
        let storage = storage.storage();
        let txn_id = storage.txn_id();
        let max_committed_id = storage.max_committed_id();
        let table = Self::TableDesc::get_table_mut(&mut storage.tables);
        table.assert_owner(owner);

        table.for_each_mut(f, txn_id, max_committed_id);
    }
}

pub(crate) trait IndexedOpsMut<TableStorage: schema::GeneratedStorage>:
    OpsMut<TableStorage>
{
    type IndexDesc: IndexDesc<Storage = TableStorage>;

    fn init(self, owner: Owner) -> Result<()> {
        let mut storage = self.write_lock();
        let storage = storage.storage();
        let base = Base::<Self::IndexDesc>::get_table_mut(&mut storage.tables);
        base.try_set_owner(owner)
    }

    fn clear(self, owner: Owner)
    where
        IndexValue<Self::IndexDesc>: Hash + Eq,
    {
        let mut storage = self.write_lock();
        let storage = storage.storage();
        let txn_id = storage.txn_id();
        let max_committed_id = storage.max_committed_id();

        let base = Base::<Self::IndexDesc>::get_table_mut(&mut storage.tables);
        base.assert_or_set_owner(owner);
        base.clear(txn_id, max_committed_id);
    }

    fn insert(self, key: BaseKey<Self::IndexDesc>, value: BaseValue<Self::IndexDesc>, owner: Owner)
    where
        BaseKey<Self::IndexDesc>: Clone,
        IndexValue<Self::IndexDesc>: Hash + Eq,
    {
        let mut storage = self.write_lock();
        let storage = storage.storage();
        let txn_id = storage.txn_id();
        let max_committed_id = storage.max_committed_id();
        let base = Base::<Self::IndexDesc>::get_table_mut(&mut storage.tables);
        base.assert_or_set_owner(owner);

        base.insert(key, value, txn_id, max_committed_id);
    }

    // TODO if `f` panics then the indexes will be left in an inconsistent state.
    fn with_mut<Q, T>(
        self,
        key: &Q,
        f: impl FnOnce(&mut BaseValue<Self::IndexDesc>) -> T,
        owner: Owner,
    ) -> AccessResult<T>
    where
        IndexKey<Self::IndexDesc>: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
        BaseKey<Self::IndexDesc>: Clone,
        IndexValue<Self::IndexDesc>: Hash + Eq,
        BaseValue<Self::IndexDesc>: Clone,
    {
        let mut storage = self.write_lock();
        let storage = storage.storage();
        let txn_id = storage.txn_id();
        let max_committed_id = storage.max_committed_id();
        let (base, index) = schema::get_two_tables_mut::<_, Base<Self::IndexDesc>, Self::IndexDesc>(
            &mut storage.tables,
        );
        if index.is_poisoned(txn_id) {
            return Err(AccessError::NonUniqueIndexKey(
                <Self::IndexDesc as TableDesc>::NAME,
            ));
        }
        base.assert_owner(owner);

        let base_key = index.get(key, txn_id).ok_or(AccessError::NotPresent)?;
        base.with_mut(base_key, f, txn_id, max_committed_id)
            .ok_or(AccessError::NotPresent)
    }

    fn remove<Q>(self, key: &Q, owner: Owner)
    where
        IndexKey<Self::IndexDesc>: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = IndexKey<Self::IndexDesc>>,
        IndexValue<Self::IndexDesc>: Hash + Eq + ToOwned<Owned = BaseKey<Self::IndexDesc>>,
    {
        let mut storage = self.write_lock();
        let storage = storage.storage();
        let txn_id = storage.txn_id();
        let max_committed_id = storage.max_committed_id();

        let (base, index) = schema::get_two_tables_mut::<_, Base<Self::IndexDesc>, Self::IndexDesc>(
            &mut storage.tables,
        );
        // First check ownership, then do the operation.
        base.assert_owner(owner);

        let Some(base_key) = index.get(key, txn_id) else {
            return;
        };
        base.remove(base_key, txn_id, max_committed_id);
        index.remove(key, txn_id, max_committed_id);
    }

    // TODO if `f` panics then the indexes will be left in an inconsistent state.
    fn for_each_mut(
        self,
        mut f: impl FnMut(&IndexKey<Self::IndexDesc>, &mut BaseValue<Self::IndexDesc>),
        owner: Owner,
    ) where
        IndexValue<Self::IndexDesc>: Hash + Eq,
        BaseKey<Self::IndexDesc>: Clone,
        BaseValue<Self::IndexDesc>: Clone,
    {
        let mut storage = self.write_lock();
        let storage = storage.storage();
        let txn_id = storage.txn_id();
        let max_committed_id = storage.max_committed_id();

        let (base, index) = schema::get_two_tables_mut::<_, Base<Self::IndexDesc>, Self::IndexDesc>(
            &mut storage.tables,
        );
        base.assert_owner(owner);

        for (k, base_key) in index.iter(txn_id) {
            base.with_mut(
                base_key,
                |value| {
                    f(k, value);
                },
                txn_id,
                max_committed_id,
            );
        }
    }
}

#[allow(unused_variables)]
#[track_caller]
fn assert_owner(owner: Owner, key: TypeId, storage: &Storage<impl schema::GeneratedStorage>) {
    #[cfg(debug_assertions)]
    if let Some(prev_owner) = storage.get_singleton_owner(key) {
        assert_eq!(
            prev_owner, owner,
            "Ownership violation: expected {prev_owner}, found {owner}"
        );
    }
}
