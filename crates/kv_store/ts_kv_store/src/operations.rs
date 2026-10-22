//! Generic implementations of the various storage operations.
//!
//! The high-level setup is that `Ops` and `OpsMut` abstract access to the underlying storage of the
//! KvStore. That access might be via a transaction or table or index or direct. The `StorageGuard`
//! traits abstract lock objects which guard that access.
//!
//! The actual functionality is implemented on subtraits of `Ops` and `OpsMut`: `SingletonOps` and
//! `SingletonOpsMut` for operating on singleton key/values, `TabularOps` and `TabularOpsMut` for
//! operating on tables of data, and `IndexedOps` for operating on tables via an index.

use core::{borrow::Borrow, hash::Hash, ops::Deref};

use crate::{
    Error, GeneratedStorage, Owner, Result, iter,
    schema::{self, Desc, IndexDesc, IndexStorage, PrimaryDesc, SingletonDesc, TableDesc},
    storage::{Storage, Table, VersionedValue},
    transactions::{TransactionRef, TxnId},
};

/// Read access to the store's data for an operation.
///
/// Operations only access the table or singleton they operate on (and, for an index, its base
/// table), never the whole store.
pub trait StorageGuard<TableStorage: GeneratedStorage>: Sized {
    /// The id of the current transaction.
    fn txn_id(&self) -> TxnId;

    /// The table accessor for `D`.
    ///
    /// # Safety
    ///
    /// There must be no live mutable reference to the table described by `D` while the returned
    /// reference is live.
    unsafe fn table<D: TableDesc<Storage = TableStorage>>(&self) -> &Table<D>;

    /// The value of the singleton described by `S`.
    ///
    /// # Safety
    ///
    /// There must be no live mutable reference to the singleton described by `S` while the
    /// returned reference is live.
    unsafe fn singleton<S: SingletonDesc<Storage = TableStorage>>(
        &self,
    ) -> &VersionedValue<Option<S::Value>>;
}

impl<TableStorage: GeneratedStorage> StorageGuard<TableStorage> for Storage<TableStorage> {
    fn txn_id(&self) -> TxnId {
        Storage::txn_id(self)
    }

    unsafe fn table<D: TableDesc<Storage = TableStorage>>(&self) -> &Table<D> {
        D::get_table(&self.tables)
    }

    unsafe fn singleton<S: SingletonDesc<Storage = TableStorage>>(
        &self,
    ) -> &VersionedValue<Option<S::Value>> {
        S::get_ref(&self.tables)
    }
}

pub(crate) trait Ops<TableStorage: GeneratedStorage>: Sized {
    type ReadLock: Deref<Target: StorageGuard<TableStorage>>;

    fn read_lock(self) -> Self::ReadLock;
}

/// Read operations on a singleton.
///
/// # Safety
///
/// While a guard returned by `Ops::read_lock` is live, there must be no live mutable reference to the
/// singleton described by `Self::Desc`.
pub(crate) unsafe trait SingletonOps<TableStorage: GeneratedStorage>:
    Ops<TableStorage>
{
    type Desc: SingletonDesc<Storage = TableStorage>;

    fn get(self, owner: Owner) -> Option<<Self::Desc as SingletonDesc>::Value>
    where
        <Self::Desc as SingletonDesc>::Value: Clone,
    {
        self.with(Clone::clone, owner)
    }

    fn with<T>(
        self,
        f: impl FnOnce(&<Self::Desc as SingletonDesc>::Value) -> T,
        _owner: Owner,
    ) -> Option<T> {
        let guard = self.read_lock();
        // SAFETY: `guard` is from `read_lock`, so by the trait's contract there are no mutable
        // references to `Self::Desc`'s value.
        let value = unsafe { guard.singleton::<Self::Desc>() }
            .get(guard.txn_id())?
            .as_ref()?;
        Some(f(value))
    }
}

/// Read operations on a table.
///
/// # Safety
///
/// While a guard returned by `read_lock` is live, there must be no live mutable reference to the
/// table described by `Self::Desc`.
pub(crate) unsafe trait TabularOps<TableStorage: GeneratedStorage>:
    Ops<TableStorage>
{
    type Desc: TableDesc<Storage = TableStorage>;

    fn len(self) -> usize {
        let guard = self.read_lock();
        // SAFETY: `guard` is from `read_lock` (see the trait's contract).
        unsafe { guard.table::<Self::Desc>() }.len(guard.txn_id())
    }

    #[allow(clippy::wrong_self_convention)]
    fn is_empty(self) -> bool {
        let guard = self.read_lock();
        // SAFETY: `guard` is from `read_lock` (see the trait's contract).
        unsafe { guard.table::<Self::Desc>() }.is_empty(guard.txn_id())
    }

    fn get<Q>(self, key: &Q, owner: Owner) -> Option<<Self::Desc as TableDesc>::Value>
    where
        <Self::Desc as TableDesc>::Value: Clone,
        <Self::Desc as TableDesc>::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        self.with(key, Clone::clone, owner)
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
        let guard = self.read_lock();
        // SAFETY: `guard` is from `read_lock` (see the trait's contract).
        let value = unsafe { guard.table::<Self::Desc>() }.get(key, guard.txn_id())?;
        Some(f(value))
    }

    fn with_iter<T>(
        self,
        f: impl for<'a> FnOnce(
            &mut dyn Iterator<
                Item = (
                    &'a <Self::Desc as TableDesc>::Key,
                    &'a <Self::Desc as TableDesc>::Value,
                ),
            >,
        ) -> T,
    ) -> T {
        let guard = self.read_lock();
        // SAFETY: `guard` is from `read_lock` (see the trait's contract).
        f(&mut unsafe { iter::table_iter::<Self::Desc>(&*guard) })
    }

    fn with_keys<T>(
        self,
        f: impl for<'a> FnOnce(&mut dyn Iterator<Item = &'a <Self::Desc as TableDesc>::Key>) -> T,
    ) -> T {
        let guard = self.read_lock();
        // SAFETY: `guard` is from `read_lock` (see the trait's contract).
        f(&mut unsafe { iter::table_iter::<Self::Desc>(&*guard) }.map(|(k, _)| k))
    }

    fn with_values<T>(
        self,
        f: impl for<'a> FnOnce(&mut dyn Iterator<Item = &'a <Self::Desc as TableDesc>::Value>) -> T,
    ) -> T {
        let guard = self.read_lock();
        // SAFETY: `guard` is from `read_lock` (see the trait's contract).
        f(&mut unsafe { iter::table_iter::<Self::Desc>(&*guard) }.map(|(_, v)| v))
    }
}

pub(crate) type BaseKey<T> = <<T as IndexDesc>::BaseTable as TableDesc>::Key;
pub(crate) type BaseValue<T> = <<T as IndexDesc>::BaseTable as TableDesc>::Value;
pub(crate) type IndexKey<T> = <T as TableDesc>::Key;
pub(crate) type IndexValue<T> = <T as TableDesc>::Value;

/// Read operations on a table via an index.
///
/// # Safety
///
/// While a guard returned by `Ops::read_lock` is live, there must be no live mutable reference to the
/// table described by `Self::IndexDesc`, or to its base table.
pub(crate) unsafe trait IndexedOps<TableStorage: GeneratedStorage>:
    Ops<TableStorage>
{
    type IndexDesc: IndexDesc<Storage = TableStorage>;

    fn check_consistent(self) -> Result<()> {
        // SAFETY: the guard is from `read_lock` (see the trait's contract).
        unsafe { check_consistent::<Self::IndexDesc>(&*self.read_lock()) }
    }

    #[allow(clippy::type_complexity)]
    fn get<Q>(
        self,
        key: &Q,
        owner: Owner,
    ) -> Result<Option<(BaseKey<Self::IndexDesc>, BaseValue<Self::IndexDesc>)>>
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
    ) -> Result<Option<T>>
    where
        IndexKey<Self::IndexDesc>: Borrow<Q>,
        IndexValue<Self::IndexDesc>: Hash + Eq,
        Q: ?Sized + Hash + Eq,
    {
        let guard = self.read_lock();
        // SAFETY (for all uses of `guard`): `guard` is from `read_lock` (see the trait's
        // contract).
        unsafe { check_consistent::<Self::IndexDesc>(&*guard) }?;
        let txn_id = guard.txn_id();
        let Some(base_key) = unsafe { guard.table::<Self::IndexDesc>() }.get(key, txn_id) else {
            return Ok(None);
        };
        let Some(value) = unsafe { guard.table::<<Self::IndexDesc as IndexDesc>::BaseTable>() }
            .get(base_key, txn_id)
        else {
            return Ok(None);
        };

        Ok(Some(f(base_key, value)))
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
        // SAFETY: `guard` is from `read_lock` (see the trait's contract).
        f(&mut unsafe { iter::index_iter::<Self::IndexDesc>(&*guard) })
    }

    fn with_keys<T>(
        self,
        f: impl for<'a> FnOnce(&mut dyn Iterator<Item = &'a IndexKey<Self::IndexDesc>>) -> T,
    ) -> T
    where
        IndexValue<Self::IndexDesc>: Hash + Eq,
    {
        let guard = self.read_lock();
        // SAFETY: `guard` is from `read_lock` (see the trait's contract).
        f(&mut unsafe { iter::index_iter::<Self::IndexDesc>(&*guard) }.map(|(k, ..)| k))
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
        // SAFETY: `guard` is from `read_lock` (see the trait's contract).
        f(&mut unsafe { iter::index_iter::<Self::IndexDesc>(&*guard) }.map(|(_, bk, v)| (bk, v)))
    }
}

/// Returns an error if the index `D` is poisoned (i.e., has non-unique keys).
///
/// # Safety
///
/// Precondition: there must be no live mutable reference to the table described by `D`.
unsafe fn check_consistent<D: IndexDesc>(guard: &impl StorageGuard<D::Storage>) -> Result<()> {
    // SAFETY: guaranteed by the precondition.
    if unsafe { guard.table::<D>() }.is_poisoned(guard.txn_id()) {
        Err(Error::NonUniqueIndexKey(D::NAME))
    } else {
        Ok(())
    }
}

pub(crate) trait OpsMut<'txn, D: Desc>: Sized {
    fn write_lock(self) -> TransactionRef<'txn, D>;
}

pub(crate) trait SingletonOpsMut<'txn, D: schema::SingletonDesc>: OpsMut<'txn, D> {
    fn insert(self, value: D::Value, owner: Owner) {
        let mut guard = self.write_lock();
        assert_owner(D::OWNER, owner);
        let txn_id = guard.txn_id();

        guard.singleton_mut().set(Some(value), txn_id);
    }

    fn delete(self, owner: Owner) {
        let mut guard = self.write_lock();
        assert_owner(D::OWNER, owner);
        let txn_id = guard.txn_id();

        guard.singleton_mut().set(None, txn_id);
    }

    fn with_mut<T>(self, f: impl FnOnce(&mut D::Value) -> T, owner: Owner) -> Option<T>
    where
        D::Value: Clone + PartialEq,
    {
        let mut guard = self.write_lock();
        assert_owner(D::OWNER, owner);
        let txn_id = guard.txn_id();

        guard.singleton_mut().with_mut_value(txn_id, f)
    }
}

pub(crate) trait TabularOpsMut<'txn, D: PrimaryDesc>: OpsMut<'txn, D> {
    /// Run `f` on the underlying table, checking that `owner` owns it.
    ///
    /// The write lock is held while `f` runs.
    #[track_caller]
    fn with_table_mut<T>(self, owner: Owner, f: impl FnOnce(&mut Table<D>, TxnId) -> T) -> T {
        let mut guard = self.write_lock();
        let txn_id = guard.txn_id();
        let table = guard.table_mut();
        assert_owner(D::OWNER, owner);

        f(table, txn_id)
    }

    fn clear(self, owner: Owner) {
        self.with_table_mut(owner, |table, txn_id| {
            table.clear(txn_id);
        })
    }

    fn insert(self, key: D::Key, value: D::Value, owner: Owner)
    where
        D::Key: Clone,
    {
        self.with_table_mut(owner, |table, txn_id| {
            table.insert(key, value, txn_id);
        })
    }

    fn with_mut<Q, T>(self, key: &Q, f: impl FnOnce(&mut D::Value) -> T, owner: Owner) -> Option<T>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = D::Key>,
        D::Value: Clone + PartialEq,
    {
        self.with_table_mut(owner, |table, txn_id| table.with_mut(key, f, txn_id))
    }

    fn delete<Q>(self, key: &Q, owner: Owner)
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = D::Key>,
    {
        self.with_table_mut(owner, |table, txn_id| {
            table.delete(key, txn_id);
        })
    }

    fn with_iter_mut<T>(
        self,
        owner: Owner,
        f: impl for<'a> FnOnce(&mut dyn Iterator<Item = (&'a D::Key, &'a mut D::Value)>) -> T,
    ) -> T
    where
        D::Value: Clone + PartialEq,
    {
        self.with_table_mut(owner, |table, txn_id| {
            if !<D::IndexStorage as IndexStorage<_, _>>::HAS_INDEXES {
                return f(&mut table.iter_mut(txn_id));
            }

            let mut yielded = Vec::new();
            let result = f(&mut table
                .iter_mut(txn_id)
                .inspect(|(k, _)| yielded.push((*k).clone())));

            for k in &yielded {
                table.rebuild_indexes_for_key(k, txn_id);
            }
            result
        })
    }

    fn retain(self, owner: Owner, f: impl FnMut(&D::Key, &mut D::Value) -> bool)
    where
        D::Value: Clone + PartialEq,
    {
        self.with_table_mut(owner, |table, txn_id| {
            table.retain(f, txn_id);
        })
    }

    fn with_values_mut<T>(
        self,
        owner: Owner,
        f: impl for<'a> FnOnce(&mut dyn Iterator<Item = &'a mut D::Value>) -> T,
    ) -> T
    where
        D::Value: Clone + PartialEq,
    {
        self.with_iter_mut(owner, |iter| f(&mut iter.map(|(_, v)| v)))
    }
}

/// Assert that `found` is the `expected` owner of some data (only in debug builds).
#[track_caller]
fn assert_owner(expected: Owner, found: Owner) {
    debug_assert_eq!(
        expected, found,
        "Ownership violation: expected {expected}, found {found}"
    );
}
