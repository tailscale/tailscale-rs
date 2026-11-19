use super::VersionedValue;
use crate::transactions::TxnId;

/// Storage for a singleton's value.
///
/// Implemented by `VersionedValue<Option<T>>` for singletons which may have no value, and by
/// `DefaultValue<T>` for singletons declared with `default`, which always have a value.
#[doc(hidden)]
pub trait SingletonSlot: Default {
    /// The type of the singleton's value.
    type Value;
    /// The result type of operations which might not find a value: `Option<T>` if the singleton
    /// may have no value, `T` if it always has a value.
    type Maybe<T>;

    /// Convert the result of an operation which might not find a value to `Self::Maybe`.
    ///
    /// Panics if `result` is `None` and the singleton always has a value.
    fn from_option<R>(result: Option<R>) -> Self::Maybe<R>;

    /// The value visible to `txn_id`, if there is one.
    fn get(&self, txn_id: TxnId) -> Option<&Self::Value>;

    /// Pass a reference to the value visible to `txn_id` (if there is one) to `f`.
    fn with<R>(&self, txn_id: TxnId, f: impl FnOnce(&Self::Value) -> R) -> Self::Maybe<R> {
        Self::from_option(self.get(txn_id).map(f))
    }

    /// Pass a mutable reference to the value visible to `txn_id` (if there is one) to `f`.
    fn with_mut<R>(
        &mut self,
        txn_id: TxnId,
        f: impl FnOnce(&mut Self::Value) -> R,
    ) -> Self::Maybe<R>
    where
        Self::Value: Clone + PartialEq;

    /// Write `value` in transaction `txn_id`.
    fn insert(&mut self, value: Self::Value, txn_id: TxnId);

    /// Delete the value in transaction `txn_id`.
    fn delete(&mut self, txn_id: TxnId);

    /// Delete the value in transaction `txn_id`, returning a clone of the deleted value (if there
    /// was one).
    fn remove(&mut self, txn_id: TxnId) -> Self::Maybe<Self::Value>
    where
        Self::Value: Clone,
    {
        let result = self.get(txn_id).cloned();
        // Only delete a value which is present, otherwise the delete would count as a write.
        if result.is_some() {
            self.delete(txn_id);
        }
        Self::from_option(result)
    }

    /// How the value was changed by transaction `txn_id`.
    ///
    /// Returns `None` if the transaction did not write the value, `Some(None)` if the transaction
    /// deleted the value, and `Some(Some(value))` if the transaction inserted or mutated the value.
    fn change_in_txn(&self, txn_id: TxnId) -> Option<Option<&Self::Value>>;

    /// Cleanup a rolled-back transaction.
    fn gc_txn(&mut self, txn_id: TxnId);
}

/// A singleton which may have no value. A deleted value is stored as a `None` tombstone.
impl<T> SingletonSlot for VersionedValue<Option<T>> {
    type Value = T;
    type Maybe<R> = Option<R>;

    fn from_option<R>(result: Option<R>) -> Option<R> {
        result
    }

    fn get(&self, txn_id: TxnId) -> Option<&T> {
        self.get(txn_id)?.as_ref()
    }

    fn with_mut<R>(&mut self, txn_id: TxnId, f: impl FnOnce(&mut T) -> R) -> Option<R>
    where
        T: Clone + PartialEq,
    {
        // Check for a value before cloning: a deleted singleton is stored as a `None` in an
        // occupied slot, and cloning that into the free slot would look like a mutation and cause
        // a spurious `Remove` notification.
        SingletonSlot::get(self, txn_id)?;

        self.with_mut_value(txn_id, |value| value.as_mut().map(f))?
    }

    fn insert(&mut self, value: T, txn_id: TxnId) {
        self.set(Some(value), txn_id);
    }

    fn delete(&mut self, txn_id: TxnId) {
        self.set(None, txn_id);
    }

    fn change_in_txn(&self, txn_id: TxnId) -> Option<Option<&T>> {
        self.modified_in_txn(txn_id).map(Option::as_ref)
    }

    fn gc_txn(&mut self, txn_id: TxnId) {
        VersionedValue::gc_txn(self, txn_id);
    }
}

/// Storage for a singleton declared with `default`, which always has a value.
///
/// Deleting the value is just writing the default value (so it is notified as an upsert).
#[doc(hidden)]
#[derive(Debug)]
pub struct DefaultValue<T>(VersionedValue<T>);

impl<T: Default> Default for DefaultValue<T> {
    fn default() -> Self {
        DefaultValue(VersionedValue::new(T::default(), TxnId::FIRST))
    }
}

impl<T: Default> SingletonSlot for DefaultValue<T> {
    type Value = T;
    type Maybe<R> = R;

    fn from_option<R>(result: Option<R>) -> R {
        result.expect("defaulting singleton has no value")
    }

    fn get(&self, txn_id: TxnId) -> Option<&T> {
        self.0.get(txn_id)
    }

    fn with_mut<R>(&mut self, txn_id: TxnId, f: impl FnOnce(&mut T) -> R) -> R
    where
        T: Clone + PartialEq,
    {
        Self::from_option(self.0.with_mut_value(txn_id, f))
    }

    fn insert(&mut self, value: T, txn_id: TxnId) {
        self.0.set(value, txn_id);
    }

    fn delete(&mut self, txn_id: TxnId) {
        self.0.set(T::default(), txn_id);
    }

    fn change_in_txn(&self, txn_id: TxnId) -> Option<Option<&T>> {
        // The value is never deleted, so any write is an upsert.
        self.0.modified_in_txn(txn_id).map(Some)
    }

    fn gc_txn(&mut self, txn_id: TxnId) {
        self.0.gc_txn(txn_id);
    }
}
