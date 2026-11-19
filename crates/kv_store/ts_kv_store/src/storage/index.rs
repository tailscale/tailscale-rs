use core::{borrow::Borrow, hash::Hash, iter::Map, marker::PhantomData, slice};

use super::{Table, VersionedValue};
use crate::{
    Error, Result,
    iter::TableIter,
    schema::{
        TableDesc,
        index::{
            BaseKeyWrite, CustomIndex, CustomMultiIndex, IndexLifecycle, IndexRead, MultiIndexRead,
        },
    },
    transactions::TxnId,
};

/// Storage for a custom index.
#[doc(hidden)]
#[derive(Debug, Default)]
pub struct CustomIndexStorage<T>(pub T);

/// Storage for a custom multi-index.
#[doc(hidden)]
#[derive(Debug, Default)]
pub struct CustomMultiIndexStorage<T>(pub T);

impl<K: Hash + Eq, B, T: CustomIndex<K, B>> IndexLifecycle<K, B> for CustomIndexStorage<T> {
    fn check_consistent(&self, txn_id: TxnId) -> Result<()> {
        self.0.check_consistent(txn_id)
    }

    fn commit(&mut self, txn_id: TxnId) {
        self.0.commit(txn_id);
    }

    fn clear(&mut self, txn_id: TxnId) {
        self.0.clear(txn_id);
    }

    fn rollback<'a>(&mut self, txn_id: TxnId, committed: impl Iterator<Item = (K, &'a B)>)
    where
        B: 'a,
    {
        if !self.0.rollback(txn_id) {
            self.0.rebuild(committed);
        }
    }
}

impl<K: Hash + Eq, B, T: CustomIndex<K, B>> BaseKeyWrite<K, B> for CustomIndexStorage<T> {
    fn insert_base_key<Q>(&mut self, index_key: K, base_key: &Q, txn_id: TxnId)
    where
        B: Borrow<Q>,
        Q: ?Sized + Eq + ToOwned<Owned = B>,
    {
        self.0.insert(index_key, base_key.to_owned(), txn_id);
    }

    fn remove_base_key<Q>(&mut self, index_key: &K, base_key: &Q, txn_id: TxnId)
    where
        B: Borrow<Q>,
        Q: ?Sized + Eq,
    {
        // The entry may belong to another row.
        if self
            .0
            .get(index_key, txn_id)
            .is_some_and(|k| k.borrow() == base_key)
        {
            self.0.remove(index_key, txn_id);
        }
    }
}

impl<K: Hash + Eq, B, T: CustomMultiIndex<K, B>> IndexLifecycle<K, B>
    for CustomMultiIndexStorage<T>
{
    fn check_consistent(&self, _txn_id: TxnId) -> Result<()> {
        Ok(())
    }

    fn commit(&mut self, txn_id: TxnId) {
        self.0.commit(txn_id);
    }

    fn clear(&mut self, txn_id: TxnId) {
        self.0.clear(txn_id);
    }

    fn rollback<'a>(&mut self, txn_id: TxnId, committed: impl Iterator<Item = (K, &'a B)>)
    where
        B: 'a,
    {
        if !self.0.rollback(txn_id) {
            self.0.rebuild(committed);
        }
    }
}

impl<K: Hash + Eq, B, T: CustomMultiIndex<K, B>> BaseKeyWrite<K, B> for CustomMultiIndexStorage<T> {
    fn insert_base_key<Q>(&mut self, index_key: K, base_key: &Q, txn_id: TxnId)
    where
        B: Borrow<Q>,
        Q: ?Sized + Eq + ToOwned<Owned = B>,
    {
        self.0.insert(index_key, base_key.to_owned(), txn_id);
    }

    fn remove_base_key<Q>(&mut self, index_key: &K, base_key: &Q, txn_id: TxnId)
    where
        B: Borrow<Q>,
        Q: ?Sized + Eq,
    {
        self.0.remove(index_key, base_key, txn_id);
    }
}

impl<K: Hash + Eq, B, T: CustomIndex<K, B>> IndexRead<K, B> for CustomIndexStorage<T> {
    type Iter<'a>
        = T::Iter<'a>
    where
        T: 'a,
        K: 'a,
        B: 'a;

    fn get<Q>(&self, key: &Q, txn_id: TxnId) -> Option<&B>
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        self.0.get(key, txn_id)
    }

    fn iter(&self, txn_id: TxnId) -> T::Iter<'_> {
        self.0.iter(txn_id)
    }

    fn check_consistent(&self, txn_id: TxnId) -> Result<()> {
        self.0.check_consistent(txn_id)
    }
}

impl<K: Hash + Eq, B, T: CustomMultiIndex<K, B>> MultiIndexRead<K, B>
    for CustomMultiIndexStorage<T>
{
    type BaseKeys<'a>
        = T::BaseKeys<'a>
    where
        T: 'a,
        B: 'a;

    type Iter<'a>
        = T::Iter<'a>
    where
        T: 'a,
        K: 'a,
        B: 'a;

    fn get<Q>(&self, key: &Q, txn_id: TxnId) -> Option<T::BaseKeys<'_>>
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        self.0.get(key, txn_id)
    }

    fn iter(&self, txn_id: TxnId) -> T::Iter<'_> {
        self.0.iter(txn_id)
    }
}

/// A built-in unique index, which handles non-unique index keys according to `P`.
#[doc(hidden)]
pub struct UniqueIndex<D: TableDesc, P> {
    table: Table<D>,
    /// Set if a non-unique index key was inserted (with the `poison` policy).
    poisoned: VersionedValue<bool>,
    _policy: PhantomData<P>,
}

impl<D: TableDesc, P> Default for UniqueIndex<D, P> {
    fn default() -> Self {
        UniqueIndex {
            table: Table::default(),
            poisoned: VersionedValue::new(false, TxnId::FIRST),
            _policy: PhantomData,
        }
    }
}

impl<D: TableDesc, P> UniqueIndex<D, P> {
    fn is_poisoned(&self, txn_id: TxnId) -> bool {
        self.poisoned.get(txn_id).copied().unwrap_or(false)
    }
}

/// The policies for handling non-unique index keys, named by their keywords in `store!`.
#[doc(hidden)]
#[allow(non_camel_case_types)]
pub mod policy {
    use super::{TableDesc, TxnId, UniqueIndex};

    /// How a [`UniqueIndex`] handles an index key which is already present (see `store!`).
    #[doc(hidden)]
    pub trait UniquePolicy: Sized {
        /// `key` is already present in `index`, and is being inserted again with `base_key`.
        fn on_non_unique<D: TableDesc>(
            index: &mut UniqueIndex<D, Self>,
            key: D::Key,
            base_key: D::Value,
            txn_id: TxnId,
        );
    }

    /// The `poison` policy.
    pub struct poison;

    impl UniquePolicy for poison {
        fn on_non_unique<D: TableDesc>(
            index: &mut UniqueIndex<D, Self>,
            _: D::Key,
            _: D::Value,
            txn_id: TxnId,
        ) {
            index.poisoned.set(true, txn_id);
        }
    }

    /// The `assert` policy.
    pub struct assert;

    impl UniquePolicy for assert {
        fn on_non_unique<D: TableDesc>(
            _: &mut UniqueIndex<D, Self>,
            _: D::Key,
            _: D::Value,
            _: TxnId,
        ) {
            panic!("Index key is non-unique for index `{}`", D::NAME);
        }
    }

    /// The `replace` policy.
    pub struct replace;

    impl UniquePolicy for replace {
        fn on_non_unique<D: TableDesc>(
            index: &mut UniqueIndex<D, Self>,
            key: D::Key,
            base_key: D::Value,
            txn_id: TxnId,
        ) {
            index.table.insert(key, base_key, txn_id);
        }
    }

    /// The `ignore` policy.
    pub struct ignore;

    impl UniquePolicy for ignore {
        fn on_non_unique<D: TableDesc>(
            _: &mut UniqueIndex<D, Self>,
            _: D::Key,
            _: D::Value,
            _: TxnId,
        ) {
        }
    }
}

impl<D: TableDesc, P: policy::UniquePolicy> CustomIndex<D::Key, D::Value> for UniqueIndex<D, P> {
    type Iter<'a>
        = TableIter<'a, D>
    where
        P: 'a;

    fn get<Q>(&self, key: &Q, txn_id: TxnId) -> Option<&D::Value>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        if self.is_poisoned(txn_id) {
            return None;
        }
        self.table.get(key, txn_id)
    }

    fn iter(&self, txn_id: TxnId) -> TableIter<'_, D> {
        self.table.iter(txn_id)
    }

    fn insert(&mut self, key: D::Key, base_key: D::Value, txn_id: TxnId) {
        if self.get(&key, txn_id).is_none() {
            self.table.insert(key, base_key, txn_id);
        } else {
            P::on_non_unique(self, key, base_key, txn_id);
        }
    }

    fn remove(&mut self, key: &D::Key, txn_id: TxnId) {
        self.table.delete(key, txn_id);
    }

    fn clear(&mut self, txn_id: TxnId) {
        self.table.clear(txn_id);
        self.poisoned.set(false, txn_id);
    }

    fn check_consistent(&self, txn_id: TxnId) -> Result<()> {
        self.table.check_txn_consistency(txn_id)?;
        if self.is_poisoned(txn_id) {
            return Err(Error::NonUniqueIndexKey(D::NAME));
        }
        Ok(())
    }

    fn commit(&mut self, txn_id: TxnId) {
        self.table.commit_without_notifications(txn_id);
    }

    fn rollback(&mut self, txn_id: TxnId) -> bool {
        self.table.gc_txn(txn_id);
        self.poisoned.gc_txn(txn_id);
        true
    }

    fn rebuild<'a>(&mut self, _: impl Iterator<Item = (D::Key, &'a D::Value)>)
    where
        D::Value: 'a,
    {
        unreachable!("rollback always succeeds");
    }
}

impl<B: Clone + PartialEq, D: TableDesc<Value = Vec<B>>> CustomMultiIndex<D::Key, B> for Table<D> {
    type BaseKeys<'a>
        = slice::Iter<'a, B>
    where
        B: 'a;

    type Iter<'a>
        = Map<TableIter<'a, D>, fn((&'a D::Key, &'a Vec<B>)) -> (&'a D::Key, slice::Iter<'a, B>)>
    where
        B: 'a;

    fn get<Q>(&self, key: &Q, txn_id: TxnId) -> Option<slice::Iter<'_, B>>
    where
        D::Key: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
        Table::get(self, key, txn_id).map(|keys| keys.iter())
    }

    fn iter(&self, txn_id: TxnId) -> Self::Iter<'_> {
        Table::iter(self, txn_id).map(|(k, v)| (k, v.iter()))
    }

    fn insert(&mut self, key: D::Key, base_key: B, txn_id: TxnId) {
        match Table::get(self, &key, txn_id) {
            Some(keys) if keys.contains(&base_key) => {}
            Some(_) => {
                self.with_mut(&key, |keys| keys.push(base_key), txn_id);
            }
            None => Table::insert(self, key, vec![base_key], txn_id),
        }
    }

    fn remove<R>(&mut self, key: &D::Key, base_key: &R, txn_id: TxnId)
    where
        B: Borrow<R>,
        R: ?Sized + Eq,
    {
        let empty = self.with_mut(
            key,
            |keys| {
                keys.retain(|k| k.borrow() != base_key);
                keys.is_empty()
            },
            txn_id,
        );
        if empty == Some(true) {
            self.delete(key, txn_id);
        }
    }

    fn clear(&mut self, txn_id: TxnId) {
        Table::clear(self, txn_id);
    }

    fn commit(&mut self, txn_id: TxnId) {
        self.commit_without_notifications(txn_id);
    }

    fn rollback(&mut self, txn_id: TxnId) -> bool {
        self.gc_txn(txn_id);
        true
    }

    fn rebuild<'a>(&mut self, _: impl Iterator<Item = (D::Key, &'a B)>)
    where
        B: 'a,
    {
        unreachable!("rollback always succeeds");
    }
}
