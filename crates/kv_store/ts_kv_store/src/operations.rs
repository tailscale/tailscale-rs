//! Generic implementations of the various storage operations.
//!
//! The high-level setup is that `Ops` and `OpsMut` abstract access to the underlying storage of the
//! KvStore. That access might be via a transaction or table or index or direct. The actual functionality
//! is implemented on subtraits of these: `SingletonOps` and `SingletonOpsMut` for operating on singleton
//! key/values, `TabularOps` and `TabularOpsMut` for operating on tables of data, and `IndexedOps` for
//! operating on tables via an index.

use std::{borrow::Borrow, hash::Hash, sync::RwLockReadGuard};

use crate::{
    Error, Owner, Result, iter,
    schema::{self, IndexDesc, SingletonDesc, TableDesc},
    storage::{Storage, Table, VersionedValue},
    transactions::TxnId,
};

pub(crate) trait Ops<TableStorage: schema::GeneratedStorage>: Sized {
    type ReadLock: StorageGuard<TableStorage>;

    fn read_lock(self) -> Self::ReadLock;
}

/// Read access to the store's data for an operation.
///
/// Operations only access the table or singleton they operate on (and, for an index, its base
/// table), never the whole store.
pub(crate) trait StorageGuard<TableStorage: schema::GeneratedStorage> {
    /// The id of the current transaction.
    fn txn_id(&self) -> TxnId;

    /// The table accessor for `D`.
    fn table<D: TableDesc<Storage = TableStorage>>(&self) -> &Table<D, D::IndexStorage>;

    /// The value of the singleton described by `S`.
    fn singleton<S: SingletonDesc<Storage = TableStorage>>(
        &self,
    ) -> &VersionedValue<Option<S::Value>>;
}

/// Write access to the store's data for an operation.
pub(crate) trait StorageGuardMut<TableStorage: schema::GeneratedStorage> {
    /// The id of the current transaction.
    fn txn_id(&self) -> TxnId;

    /// The table accessor for `D`.
    fn table_mut<D: TableDesc<Storage = TableStorage>>(&mut self)
    -> &mut Table<D, D::IndexStorage>;

    /// The value of the singleton described by `S`.
    fn singleton_mut<S: SingletonDesc<Storage = TableStorage>>(
        &mut self,
    ) -> &mut VersionedValue<Option<S::Value>>;
}

impl<TableStorage: schema::GeneratedStorage> StorageGuard<TableStorage> for Storage<TableStorage> {
    fn txn_id(&self) -> TxnId {
        Storage::txn_id(self)
    }

    fn table<D: TableDesc<Storage = TableStorage>>(&self) -> &Table<D, D::IndexStorage> {
        D::get_table(&self.tables)
    }

    fn singleton<S: SingletonDesc<Storage = TableStorage>>(
        &self,
    ) -> &VersionedValue<Option<S::Value>> {
        S::get_ref(&self.tables)
    }
}

impl<TableStorage: schema::GeneratedStorage> StorageGuard<TableStorage>
    for RwLockReadGuard<'_, Storage<TableStorage>>
{
    fn txn_id(&self) -> TxnId {
        (**self).txn_id()
    }

    fn table<D: TableDesc<Storage = TableStorage>>(&self) -> &Table<D, D::IndexStorage> {
        (**self).table::<D>()
    }

    fn singleton<S: SingletonDesc<Storage = TableStorage>>(
        &self,
    ) -> &VersionedValue<Option<S::Value>> {
        (**self).singleton::<S>()
    }
}

impl<TableStorage: schema::GeneratedStorage, G: StorageGuard<TableStorage> + ?Sized>
    StorageGuard<TableStorage> for &G
{
    fn txn_id(&self) -> TxnId {
        (**self).txn_id()
    }

    fn table<D: TableDesc<Storage = TableStorage>>(&self) -> &Table<D, D::IndexStorage> {
        (**self).table::<D>()
    }

    fn singleton<S: SingletonDesc<Storage = TableStorage>>(
        &self,
    ) -> &VersionedValue<Option<S::Value>> {
        (**self).singleton::<S>()
    }
}

pub(crate) trait SingletonOps<TableStorage: schema::GeneratedStorage>:
    Ops<TableStorage>
{
    fn get<D: schema::SingletonDesc<Storage = TableStorage>>(self, owner: Owner) -> Option<D::Value>
    where
        D::Value: Clone,
    {
        self.with::<D, _>(D::Value::clone, owner)
    }

    fn with<D: schema::SingletonDesc<Storage = TableStorage>, T>(
        self,
        f: impl FnOnce(&D::Value) -> T,
        _owner: Owner,
    ) -> Option<T> {
        let guard = self.read_lock();
        let value = guard.singleton::<D>().get(guard.txn_id())?.as_ref()?;
        Some(f(value))
    }
}

pub(crate) trait TabularOps<TableStorage: schema::GeneratedStorage>:
    Ops<TableStorage>
{
    type TableDesc: TableDesc<Storage = TableStorage>;

    fn len(self) -> usize {
        let guard = self.read_lock();
        guard.table::<Self::TableDesc>().len(guard.txn_id())
    }

    #[allow(clippy::wrong_self_convention)]
    fn is_empty(self) -> bool {
        let guard = self.read_lock();
        guard.table::<Self::TableDesc>().is_empty(guard.txn_id())
    }

    fn get<Q>(self, key: &Q, owner: Owner) -> Option<<Self::TableDesc as TableDesc>::Value>
    where
        <Self::TableDesc as TableDesc>::Value: Clone,
        <Self::TableDesc as TableDesc>::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        self.with(key, Clone::clone, owner)
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
        let guard = self.read_lock();
        let value = guard.table::<Self::TableDesc>().get(key, guard.txn_id())?;
        Some(f(value))
    }

    fn with_iter<T>(
        self,
        f: impl for<'a> FnOnce(
            &mut dyn Iterator<
                Item = (
                    &'a <Self::TableDesc as TableDesc>::Key,
                    &'a <Self::TableDesc as TableDesc>::Value,
                ),
            >,
        ) -> T,
    ) -> T {
        let guard = self.read_lock();
        f(&mut iter::table_iter::<Self::TableDesc>(&guard))
    }

    fn with_keys<T>(
        self,
        f: impl for<'a> FnOnce(&mut dyn Iterator<Item = &'a <Self::TableDesc as TableDesc>::Key>) -> T,
    ) -> T {
        let guard = self.read_lock();
        f(&mut iter::table_iter::<Self::TableDesc>(&guard).map(|(k, _)| k))
    }

    fn with_values<T>(
        self,
        f: impl for<'a> FnOnce(&mut dyn Iterator<Item = &'a <Self::TableDesc as TableDesc>::Value>) -> T,
    ) -> T {
        let guard = self.read_lock();
        f(&mut iter::table_iter::<Self::TableDesc>(&guard).map(|(_, v)| v))
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

    fn check_consistent(self) -> Result<()> {
        check_consistent::<Self::IndexDesc>(&self.read_lock())
    }

    #[allow(clippy::type_complexity)]
    fn get<Q>(
        self,
        key: &Q,
        owner: Owner,
    ) -> Result<(BaseKey<Self::IndexDesc>, BaseValue<Self::IndexDesc>)>
    where
        BaseKey<Self::IndexDesc>: Clone,
        BaseValue<Self::IndexDesc>: Clone,
        IndexKey<Self::IndexDesc>: Borrow<Q>,
        IndexValue<Self::IndexDesc>: Hash + Eq,
        Q: ?Sized + Hash + Eq,
    {
        self.with(key, |k, v| (k.clone(), v.clone()), owner)
    }

    fn with<Q, T>(
        self,
        key: &Q,
        f: impl FnOnce(&BaseKey<Self::IndexDesc>, &BaseValue<Self::IndexDesc>) -> T,
        _owner: Owner,
    ) -> Result<T>
    where
        IndexKey<Self::IndexDesc>: Borrow<Q>,
        IndexValue<Self::IndexDesc>: Hash + Eq,
        Q: ?Sized + Hash + Eq,
    {
        let guard = self.read_lock();
        check_consistent::<Self::IndexDesc>(&guard)?;
        let txn_id = guard.txn_id();
        let base_key = guard
            .table::<Self::IndexDesc>()
            .get(key, txn_id)
            .ok_or(Error::NotPresent)?;
        let value = guard
            .table::<Base<Self::IndexDesc>>()
            .get(base_key, txn_id)
            .ok_or(Error::NotPresent)?;

        Ok(f(base_key, value))
    }

    #[allow(clippy::type_complexity)]
    fn with_iter<T>(
        self,
        f: impl for<'a> FnOnce(
            &mut dyn Iterator<
                Item = (
                    &'a IndexKey<Self::IndexDesc>,
                    &'a BaseKey<Self::IndexDesc>,
                    &'a BaseValue<Self::IndexDesc>,
                ),
            >,
        ) -> T,
    ) -> T
    where
        IndexValue<Self::IndexDesc>: Hash + Eq,
    {
        let guard = self.read_lock();
        f(&mut iter::index_iter::<Self::IndexDesc>(&guard))
    }

    fn with_keys<T>(
        self,
        f: impl for<'a> FnOnce(&mut dyn Iterator<Item = &'a IndexKey<Self::IndexDesc>>) -> T,
    ) -> T
    where
        IndexValue<Self::IndexDesc>: Hash + Eq,
    {
        let guard = self.read_lock();
        f(&mut iter::index_iter::<Self::IndexDesc>(&guard).map(|(k, ..)| k))
    }

    #[allow(clippy::type_complexity)]
    fn with_values<T>(
        self,
        f: impl for<'a> FnOnce(
            &mut dyn Iterator<Item = (&'a BaseKey<Self::IndexDesc>, &'a BaseValue<Self::IndexDesc>)>,
        ) -> T,
    ) -> T
    where
        IndexValue<Self::IndexDesc>: Hash + Eq,
    {
        let guard = self.read_lock();
        f(&mut iter::index_iter::<Self::IndexDesc>(&guard).map(|(_, bk, v)| (bk, v)))
    }
}

/// Returns an error if the index `D` is poisoned (i.e., has non-unique keys).
fn check_consistent<D: IndexDesc>(guard: &impl StorageGuard<D::Storage>) -> Result<()> {
    if guard.table::<D>().is_poisoned(guard.txn_id()) {
        Err(Error::NonUniqueIndexKey(D::NAME))
    } else {
        Ok(())
    }
}

pub(crate) trait OpsMut<TableStorage: schema::GeneratedStorage>: Sized {
    type WriteLock: StorageGuardMut<TableStorage>;

    fn write_lock(self) -> Self::WriteLock;
}

pub(crate) trait SingletonOpsMut<TableStorage: schema::GeneratedStorage>:
    OpsMut<TableStorage>
{
    fn insert<D: schema::SingletonDesc<Storage = TableStorage>>(
        self,
        value: D::Value,
        owner: Owner,
    ) {
        let mut guard = self.write_lock();
        assert_owner(D::OWNER, owner);

        let txn_id = guard.txn_id();
        guard.singleton_mut::<D>().set(Some(value), txn_id);
    }

    fn remove<D: schema::SingletonDesc<Storage = TableStorage>>(self, owner: Owner) {
        let mut guard = self.write_lock();
        assert_owner(D::OWNER, owner);

        let txn_id = guard.txn_id();
        guard.singleton_mut::<D>().set(None, txn_id);
    }

    fn with_mut<D: schema::SingletonDesc<Storage = TableStorage>, T>(
        self,
        f: impl FnOnce(&mut D::Value) -> T,
        owner: Owner,
    ) -> Option<T>
    where
        D::Value: Clone + PartialEq,
    {
        let mut guard = self.write_lock();
        assert_owner(D::OWNER, owner);

        let txn_id = guard.txn_id();
        guard.singleton_mut::<D>().with_mut_value(txn_id, f)
    }
}

pub(crate) trait TabularOpsMut<TableStorage: schema::GeneratedStorage>:
    OpsMut<TableStorage>
{
    type TableDesc: TableDesc<Storage = TableStorage>;

    fn clear(self, owner: Owner) {
        let mut guard = self.write_lock();
        let txn_id = guard.txn_id();

        let table = guard.table_mut::<Self::TableDesc>();
        assert_owner(Self::TableDesc::OWNER, owner);
        table.clear(txn_id);
    }

    fn insert(
        self,
        key: <Self::TableDesc as TableDesc>::Key,
        value: <Self::TableDesc as TableDesc>::Value,
        owner: Owner,
    ) where
        <Self::TableDesc as TableDesc>::Key: Clone,
    {
        let mut guard = self.write_lock();
        let txn_id = guard.txn_id();
        let table = guard.table_mut::<Self::TableDesc>();
        assert_owner(Self::TableDesc::OWNER, owner);

        table.insert(key, value, txn_id);
    }

    fn with_mut<Q, T>(
        self,
        key: &Q,
        f: impl FnOnce(&mut <Self::TableDesc as TableDesc>::Value) -> T,
        owner: Owner,
    ) -> Option<T>
    where
        <Self::TableDesc as TableDesc>::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = <Self::TableDesc as TableDesc>::Key>,
        <Self::TableDesc as TableDesc>::Value: Clone + PartialEq,
    {
        let mut guard = self.write_lock();
        let txn_id = guard.txn_id();
        let table = guard.table_mut::<Self::TableDesc>();
        assert_owner(Self::TableDesc::OWNER, owner);

        table.with_mut(key, f, txn_id)
    }

    fn remove<Q>(self, key: &Q, owner: Owner)
    where
        <Self::TableDesc as TableDesc>::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = <Self::TableDesc as TableDesc>::Key>,
    {
        let mut guard = self.write_lock();
        let txn_id = guard.txn_id();
        let table = guard.table_mut::<Self::TableDesc>();
        assert_owner(Self::TableDesc::OWNER, owner);
        table.remove(key, txn_id);
    }

    fn with_iter_mut<T>(
        self,
        owner: Owner,
        f: impl for<'a> FnOnce(
            &mut dyn Iterator<
                Item = (
                    &'a <Self::TableDesc as TableDesc>::Key,
                    &'a mut <Self::TableDesc as TableDesc>::Value,
                ),
            >,
        ) -> T,
    ) -> T
    where
        <Self::TableDesc as TableDesc>::Value: Clone + PartialEq,
    {
        let mut guard = self.write_lock();
        iter::with_table_iter_mut::<Self::TableDesc, T>(&mut guard, owner, f)
    }

    fn with_values_mut<T>(
        self,
        owner: Owner,
        f: impl for<'a> FnOnce(
            &mut dyn Iterator<Item = &'a mut <Self::TableDesc as TableDesc>::Value>,
        ) -> T,
    ) -> T
    where
        <Self::TableDesc as TableDesc>::Value: Clone + PartialEq,
    {
        self.with_iter_mut(owner, |iter| f(&mut iter.map(|(_, v)| v)))
    }
}

/// Assert that `found` is the `expected` owner of some data (only in debug builds).
#[track_caller]
pub(crate) fn assert_owner(expected: Owner, found: Owner) {
    debug_assert_eq!(
        expected, found,
        "Ownership violation: expected {expected}, found {found}"
    );
}
