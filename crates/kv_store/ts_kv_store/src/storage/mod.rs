use alloc::sync::Weak;

pub use self::{
    index::{CustomIndexStorage, CustomMultiIndexStorage, UniqueIndex, policy},
    singleton::{DefaultValue, SingletonSlot},
    table::Table,
    versioned::VersionedValue,
};
use crate::{
    Error, Notifier, Result,
    pub_sub::{Notifications, Subscriptions},
    schema,
    transactions::TxnId,
};

mod delete_mask;
mod index;
mod singleton;
mod table;
mod versioned;

/// Where data is actually stored.
#[doc(hidden)]
pub struct Storage<TableStorage: schema::GeneratedStorage> {
    /// Storage for tabular data. The concrete type will be macro-generated, see the [`crate::schema`]
    /// module.
    pub(crate) tables: TableStorage,

    /// The id of the most-recently committed transaction.
    committed: TxnId,
    /// `None` if there is no transaction in progress. `Some` if there is a transaction in progress
    /// or a transaction has been aborted without proper rollback. `pending_txn` must not be cleared
    /// until a transaction has been fully committed or fully rolled-back.
    ///
    /// `self.tables` may only contain un-committed state if `pending_txn.is_some()`.
    pending_txn: Option<TxnId>,
    /// Counter for creating new transaction ids.
    next_txn: TxnId,
    /// Subscription metadata for the store.
    pub(crate) subscriptions: Subscriptions<TableStorage::Notification>,
}

impl<TableStorage: schema::GeneratedStorage> Storage<TableStorage> {
    /// Create a new storage with no data.
    #[allow(clippy::new_without_default)]
    pub fn new(notifier: Weak<dyn Notifier<Notification = TableStorage::Notification>>) -> Self {
        Storage {
            tables: TableStorage::default(),
            committed: TxnId::FIRST,
            pending_txn: None,
            next_txn: TxnId::FIRST.next(),
            subscriptions: Subscriptions::new(notifier),
        }
    }

    /// Returns the transaction id of the current transaction, or the last committed transaction if there
    /// is no current transaction.
    ///
    /// Note that calling this without first ensuring that any aborted transaction has been cleaned
    /// may cause this method to be inaccurate.
    pub(crate) fn txn_id(&self) -> TxnId {
        self.pending_txn.unwrap_or(self.committed)
    }

    pub(crate) fn current_txn(&self) -> Option<TxnId> {
        self.pending_txn
    }

    /// Begin a new transaction. Returns the transaction's unique id.
    pub(crate) fn begin_transaction(&mut self) -> TxnId {
        let new_txn_id = self.next_txn;
        self.pending_txn = Some(new_txn_id);
        self.next_txn = new_txn_id.next();
        new_txn_id
    }

    /// Commit a transaction. Returns an error if committing fails, either because an index was made
    /// non-unique, or because the store's current transaction does not match the `txn_id` (which
    /// should be impossible with only safe code).
    pub(crate) fn commit_transaction(
        &mut self,
        txn_id: TxnId,
    ) -> Result<Notifications<TableStorage::Notification>> {
        if self.pending_txn != Some(txn_id) {
            return Err(Error::TransactionFailed);
        }

        let mut notifications = Notifications::default();
        self.tables
            .commit_txn(txn_id, &mut notifications, &self.subscriptions)?;
        self.committed = txn_id;
        self.pending_txn = None;
        Ok(notifications)
    }

    /// Rollback a transaction. Never returns an error. If `txn_id` does not match the store's current
    /// transaction, then nothing happens (the `txn_id` transaction must already have been committed
    /// or rolled back).
    pub(crate) fn rollback_transaction(&mut self, txn_id: TxnId) {
        if self.pending_txn == Some(txn_id) {
            self.clear_transaction();
        }
    }

    /// Clear any in-progress transaction.
    pub(crate) fn clear_transaction(&mut self) {
        if let Some(id) = self.pending_txn {
            self.tables.gc_txn(id);
            self.pending_txn = None;
        }
    }
}

#[cfg(test)]
mod txn_test {
    // The `store!` macro generates a `KvStore` wrapper, which these storage-level tests
    // (operating on `Storage` directly) do not use.
    #![allow(dead_code)]

    use crate::{Error, Owner, pub_sub::NoOpNotifier, storage::Storage, store};

    store!(kvs: { Count(u64; Owner("owner")) });

    #[test]
    fn commit_with_mismatched_id_fails() {
        let mut storage =
            Storage::<TableStorage>::new(alloc::sync::Arc::downgrade(&NoOpNotifier::new()));
        let id = storage.begin_transaction();
        // A commit must target the in-progress transaction.
        assert!(matches!(
            storage.commit_transaction(id.next()),
            Err(Error::TransactionFailed)
        ));
    }

    #[test]
    fn commit_then_recommit_fails() {
        let mut storage =
            Storage::<TableStorage>::new(alloc::sync::Arc::downgrade(&NoOpNotifier::new()));
        let id = storage.begin_transaction();
        assert!(storage.commit_transaction(id).is_ok());
        // No transaction is pending after a successful commit.
        assert!(matches!(
            storage.commit_transaction(id),
            Err(Error::TransactionFailed)
        ));
    }

    #[test]
    fn clear_transaction_rolls_back_and_frees_singleton_entry() {
        let mut storage =
            Storage::<TableStorage>::new(alloc::sync::Arc::downgrade(&NoOpNotifier::new()));
        let id = storage.begin_transaction();
        storage.tables.Count.set(Some(42), id);
        // Visible to the in-progress transaction.
        assert_eq!(storage.tables.Count.get(id), Some(&Some(42)));

        // Simulate cleanup of an abandoned transaction.
        storage.clear_transaction();

        assert!(storage.current_txn().is_none());
        let now = storage.txn_id();
        assert!(storage.tables.Count.get(now).is_none());
    }
}
