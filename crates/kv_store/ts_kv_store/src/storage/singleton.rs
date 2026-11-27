use super::VersionedValue;
use crate::transactions::TxnId;

/// Storage for a singleton's value. A singleton always has a value (initially the default value).
///
/// Deleting the value is just writing the default value (so it is notified as an upsert).
#[doc(hidden)]
#[derive(Debug)]
pub struct SingletonValue<T>(VersionedValue<T>);

impl<T: Default> Default for SingletonValue<T> {
    fn default() -> Self {
        SingletonValue(VersionedValue::new(T::default(), TxnId::FIRST))
    }
}

impl<T: Default> SingletonValue<T> {
    /// The value visible to `txn_id`.
    pub(crate) fn get(&self, txn_id: TxnId) -> &T {
        self.0.get(txn_id).expect("singleton has no value")
    }

    pub(crate) fn with<R>(&self, txn_id: TxnId, f: impl FnOnce(&T) -> R) -> R {
        f(self.get(txn_id))
    }

    pub(crate) fn with_mut<R>(&mut self, txn_id: TxnId, f: impl FnOnce(&mut T) -> R) -> R
    where
        T: Clone + PartialEq,
    {
        self.0
            .with_mut_value(txn_id, f)
            .expect("singleton has no value")
    }

    pub(crate) fn insert(&mut self, value: T, txn_id: TxnId) {
        self.0.set(value, txn_id);
    }

    pub(crate) fn delete(&mut self, txn_id: TxnId) {
        self.0.set(T::default(), txn_id);
    }

    pub(crate) fn remove(&mut self, txn_id: TxnId) -> T
    where
        T: Clone,
    {
        let result = self.get(txn_id).clone();
        self.delete(txn_id);
        result
    }

    /// The value written by `txn_id`, if that transaction wrote the value.
    pub fn modified_in_txn(&self, txn_id: TxnId) -> Option<&T> {
        self.0.modified_in_txn(txn_id)
    }

    /// Cleanup a rolled-back transaction.
    pub fn gc_txn(&mut self, txn_id: TxnId) {
        self.0.gc_txn(txn_id);
    }
}
