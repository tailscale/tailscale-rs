//! # ts-kvstore
//!
//! An in-memory, async, concurrent, ACID, and strongly-typed KV store for the Rust Tailscale client.
//!
//! # Example:
//!
//! ```rust
//! # use ts_kv_store::{Owner, singleton, tables};
//! # const OWNER: Owner = "owner";
//! singleton!(foo(u64; OWNER));
//! tables!(Nodes(u32 => String; OWNER));
//!
//! pub fn main() {
//!     let store = KvStore::new();
//!
//!     store.insert::<foo>(OWNER, 42);
//!
//!     let nodes = store.table::<Nodes>(OWNER);
//!     nodes.insert(4, "a".to_owned());
//!     nodes.insert(0, "b".to_owned());
//!     nodes.insert(10, "c".to_owned());
//!     nodes.insert(400, "d".to_owned());
//!
//!     assert_eq!(nodes.len(), 4);
//!
//!     println!(
//!         "singleton: {}, row 4: {}",
//!         store.get::<foo>(OWNER).unwrap(),
//!         nodes.get(&4).unwrap(),
//!     );
//! }
//! ```
//!
//! # Concepts
//!
//! There are two broad kinds of data which can be stored in a KV store: singleton data and tabular
//! data. The former are simple key/value pairs, the latter are tables of data where a key identifies
//! a row in the table. Due to implementation details there are some differences in the APIs for each
//! kind of data, but they have roughly the same operations available.
//!
//! The store is strongly typed. Both singletons and tables must be statically declared and both keys
//! and values have types from these declarations. Macros for these declarations are in the [`schema`]
//! module. They expand into an empty type for each singleton or table, and trait impls for these
//! types. The types are then used as type parameters for all operations.
//!
//! Each singleton KV pair has its own types. A table has a single key type and single value type
//! for all rows in the table.
//!
//! The data store has raw and transactional APIs. The raw API guarantees that each operation is
//! atomic, but has no guarantees across multiple operatons. The transactional API groups operations
//! into transactions which are atomic and serializable. Both singleton and tabular data can be part
//! of a transaction. The `Table` types used for accessing tabular data do not add any transactional
//! elements. That is, operations on a `Table` created from the main store are not part of a transaction,
//! and operations on a `Table` created from a transaction are only part of that transaction.
//!
//! Transactions may be read/write or read-only. Transactions can be committed or rolled-back, if a
//! transaction is dropped without being committed, then it is rolled-back. The system should handle
//! a panic or early return at any stage of a transaction (they are always atomic and leave the store
//! internally consistent; i.e., transactions are ACID).
//!
//! All data is owned. An owner is a simple token, its up to the user of the library to decide how
//! to use these tokens and what rules to follow. Every KV pair has a single owner and can only be
//! mutated by that owner. Reading data is not protected by ownership. A table has a single owner for
//! all rows.
//!
//! An index is a table in the store that is derived from its base table and provides direct access
//! to elements in the base table. Indexes are maintained by the store and are atomically updated
//! when the base table is modified.
//!
//! For example, consider a table `Base` which maps `u64` keys to `Foo` values where `Foo` has a
//! field `bar: Url` (and `bar` is a unique identifier for a `Foo` in `Base`). The schema would look
//! like `tables!(Base(u64 => Foo; OWNER; index(bar: Url)));` which will create a `Base` table and an
//! `index::Base::bar` table. By using `store.table_by::<index::Base::bar>(...)` the `Base` table
//! can be accessed as if it were a table mapping `Url`s to `Foo`s. The index is maintained whenever
//! `Base` is modified (directly or via any index) by using the `bar` field of the values in `Base`.
//!
//! The index table can be accessed directly like a normal table (`Url`), but I don't recommend it.
//! The key type is `Url` and the value type is `u64`.
//!
//! Index fields must uniquely identify a row in the base table. If multiple rows in the base table
//! have the same key in the index, then either a panic is triggered, or accessing or committing a
//! non-unique index will cause an error. See the schema macro docs for more.
//!
//! # Async access
//!
//! ts-kvstore has a synchronous API and no async functions. It is safe to use it in an async, as
//! long as there are **no `await` points inside a transaction** (which can lead to degraded
//! performance or deadlock).
//!
//! A global lock is used internally and is held for the duration of a transaction. This is a `std`
//! `RwLock` and so waiting for it will block the waiting thread (not just the async task). This is
//! unlikely to be an issue as long as transactions are kept short and don't `await` (which could
//! cause the task with the lock to yield to another task which might block waiting for that lock).
//!
//! # Implementation notes.
//!
//! The schema macros are an 'essential' component of the system, not just a convenience. Unfortunately
//! Rust macros do not have visibility/privacy hygiene, so many internal types and traits are public.
//! Anything marked as `doc(hidden)` is meant for internal use only and should not be considered
//! part of the API.
//!
//! Part of the work of the macros is to generate an internal storage struct. To ensure an ergonomic
//! API, the generic [`KvStore`] is wrapped in a local `KvStore` which can be deref-ed to the inner,
//! generic type. Users of the library should only use the generated type, but see the generic type
//! for documentation.
//!
//! The implementation of storage for tabular data is one HashMap per table, and otherwise
//! straightforward. For singleton data, we use a single HashMap which maps `TypeId` to `(Owner, SinValue)`.
//! Where the `TypeId` id the id of the type used to describe the singleton. Values can be
//! stored in different ways (inline, via an `Arc`, etc.) each of which is a variant of `SinValue`.
//! The store transparently converts keys and values to their declared types.
//!
//! The implementation of the storage operations (`get`, `insert`, etc.) is somewhat shared between
//! the various types which support them (`KvStore`, the table types, the transaction types, index
//! types, and transactional index types). These are implemented on traits in the `operations` module.
//! For ease of use and documentation, the functions are implemented on each concrete type and
//! delegated to the trait implementations. I.e., the traits and impls are an implementation detail.
//!
//! Transactions have an internal id (`TxnId`). Since we use a global lock to ensure serializability,
//! transactions are only used to ensure atomicity. There can only ever be one (mutating) transaction
//! in progress at a time. The store tracks the most recently committed transaction id, and optionally
//! a current transaction id. Raw (non-transactional) writes are 'mini-transactions' of just a single
//! operation. That means even raw operations consisting of multiple sub-operations are atomic. Raw
//! reads use the most recently committed transaction id as their 'transaction' id.
//!
//! The KV store uses a simplified version of MVCC to implement transactions. Only two versions are
//! required for each key, one will be the currently committed version and one will either be empty,
//! the version belonging to the currently in-progress transaction, or the version belonging to a
//! partially rolled-back or abandoned transaction. So, every value in the store is stored internally as a
//! `VersionedValue`, which has these two slots and a version and value in each. Deletes are stored
//! outside of the main storage in a per-table delete mask.
//!
//! Singletons work slightly differently: they still use a `VersionedValue`, but use a tombstone value
//! for deletes (`SinValue::None`) rather than a delete mask.
//!
//! To commit a transaction, the delete masks are applied to their corresponding tables, the committed
//! transaction id in the store is set to the committed transaction's, and the pending transaction
//! id is cleared. Applying delete masks is implemented such that it will not panic or otherwise fail
//! once application is started. That and the global lock ensures atomicity of commits.
//!
//! To rollback a transaction, all transaction state (i.e., versions belonging to the transaction and
//! delete masks) is deleted, then the store's pending transaction id is cleared. If a transaction
//! is abandoned without a proper rollback, then accessing the store and finding a pending transaction
//! id will trigger garbage collection. A panic which poisons the global lock can be resolved by
//! rolling back any pending transaction and un-poisoning.
//!
//! There is no way to time-out a transaction. So if a transaction takes the global lock and
//! never gives it up (e.g., by panicking without calling destructors, or leaking the transaction
//! handle), then the KV store cannot be recovered.

use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};

mod index;
mod iter;
mod operations;
mod raw;
pub mod schema;
#[doc(hidden)]
pub mod storage;
#[doc(hidden)]
pub mod transactions;

#[doc(inline)]
pub use index::KvTableIndex;
#[doc(inline)]
pub use iter::{IndexIterator, TableIterator};
#[doc(inline)]
pub use raw::KvTable;
#[doc(inline)]
pub use transactions::{KvTableRoTransactional, KvTableTransactional, RoTransaction, Transaction};

/// A key-value store. See the crate docs for details. Its schema is described by `TableStorage`.
pub struct KvStore<TableStorage: schema::GeneratedStorage> {
    /// All data is stored behind the RW lock (see `storage` and `schema` modules).
    storage: RwLock<storage::Storage<TableStorage>>,
}

impl<TableStorage: schema::GeneratedStorage> KvStore<TableStorage> {
    #[doc(hidden)]
    /// Constructor intended to be used by macros. Avoid using this and prefer to use the generated
    /// `new` for a specialized `KvStore`.
    pub fn new_with_storage(storage: RwLock<storage::Storage<TableStorage>>) -> Self {
        KvStore { storage }
    }

    /// Might (theoretically) panic, see the note on [`clear_lock_poison`].
    fn get_read_lock(&self) -> RwLockReadGuard<'_, storage::Storage<TableStorage>> {
        self.clear_lock_poison();

        let lock = self.storage.read().unwrap();
        if lock.current_txn().is_none() {
            return lock;
        }

        let mut lock = self.storage.write().unwrap();
        lock.clear_transaction();
        RwLockWriteGuard::downgrade(lock)
    }

    /// Might (theoretically) panic, see the note on [`clear_lock_poison`].
    fn get_write_lock(&self) -> RwLockWriteGuard<'_, storage::Storage<TableStorage>> {
        self.clear_lock_poison();
        let mut lock = self.storage.write().unwrap();
        lock.clear_transaction();
        lock
    }

    /// Clear poison on the internal lock and recover the store.
    ///
    /// In theory, after calling this function, another thread could get the lock, panic, and poison
    /// it again, so calling `clear_lock_poison` immediately followed by `get_read_lock` or `get_write_lock`
    /// could panic. However, there is no easy way to avoid this because of the poisoning API.
    /// Hopefully, the chance of that happening is small.
    fn clear_lock_poison(&self) {
        if self.storage.is_poisoned() {
            self.storage.clear_poison();
            let mut lock = self.storage.write().unwrap();
            // The store should always be in a consistent state, so all we need to do is clear
            // the current transaction (if there is one) and we're good to go.
            lock.clear_transaction();
        }
    }
}

/// A token indicating ownership of a KV singleton or table. See crate docs for what ownership means
/// for a store.
pub type Owner = &'static str;

/// An error from a [`KvStore`].
#[derive(thiserror::Error, Debug, Clone, PartialEq)]
pub enum Error {
    /// The requested key is not present in the store.
    #[error("Key not found")]
    NotPresent,
    /// An inconsistency caused a transaction to fail. It has not been committed and can be re-tried.
    #[error("Transaction Failed")]
    TransactionFailed,
    /// An index had multiple primary keys for a single index key. If returned when committing a
    /// transaction, the transaction will not have been committed.
    #[error("An attempt to store a non-unique index key in `{0}`")]
    NonUniqueIndexKey(&'static str),
}

/// `Result` alias for a KvStore [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// Helper trait for making it easier for [`Error`] and `Option` to interoperate.
///
/// `Err(Error::NotPresent)` for `Result<T, Error>`has the same meaning as `None` for `Option<T>`
/// for most map operations. This trait allows treating `Result<T, Error>` a bit more like
/// an `Option` in various ways so that using functions which return `Result<T, Error>` can be
/// more ergonomic. (Annoyingly we can't implement helpers directly on `Result` or make conversion
/// via `From` work).
pub trait KvErrorExt<T> {
    /// Convert a `Result<T, Error>` into `Result<Option<T>, Error>`.
    fn try_opt(self) -> Result<Option<T>>;
    /// Convert a `Result<T, Error>` into `Option<T>`, panicking if the `Error` is anything
    /// other than `NotPresent`.
    fn unwrap_opt(self) -> Option<T>;
    /// Convert a `&Result<T, Error>` into `Option<&T>`, panicking if the `Error` is anything
    /// other than `NotPresent`.
    fn unwrap_opt_ref(&self) -> Option<&T>;
    /// True if self is `Ok`, i.e., there was no error and the requested key was present.
    fn is_some(&self) -> bool;
    /// True if self is `Err(Error::NotPresent)`, i.e., there was no other error and the requested
    /// key was not present.
    fn is_none(&self) -> bool;
}

impl<T> KvErrorExt<T> for Result<T> {
    fn try_opt(self) -> Result<Option<T>> {
        match self {
            Ok(t) => Ok(Some(t)),
            Err(Error::NotPresent) => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn unwrap_opt(self) -> Option<T> {
        match self {
            Ok(t) => Some(t),
            Err(Error::NotPresent) => None,
            Err(e) => {
                panic!("Expected `Ok` or not present, found: {e}")
            }
        }
    }

    fn unwrap_opt_ref(&self) -> Option<&T> {
        match self {
            Ok(t) => Some(t),
            Err(Error::NotPresent) => None,
            Err(e) => {
                panic!("Expected `Ok` or not present, found: {e}")
            }
        }
    }

    fn is_some(&self) -> bool {
        self.is_ok()
    }

    fn is_none(&self) -> bool {
        matches!(self, Err(Error::NotPresent))
    }
}
