//! # ts-kvstore
//!
//! An in-memory, async, concurrent, and strongly-typed KV store for the Rust Tailscale client.
//!
//! # Example:
//!
//! ```rust
//! # use ts_kv_store::{Owner, singleton, tables};
//! # const OWNER: Owner = "owner";
//! singleton!(foo(u64));
//! tables!(Nodes(u32 => String));
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
//! and values have types from these declarations. Macros for these declations are in the [`schema`]
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
//! and operations on a `Table` created from a transaction are only part of that transacton.
//!
//! Transactions may be read/write or read-only. Transactions don't need to be explicitly committed,
//! the effect is 'commit on drop' and currently operations are committed as they are called (with
//! no rollback).
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
//! like `tables!(Base(u64 => Foo; index(bar: Url)));` which will create a `Base` table and an
//! `index::Base::bar` table. By using `store.table_by::<index::Base::bar>(...)` the `Base` table
//! can be accessed as if it were a table mapping `Url`s to `Foo`s. The index is maintained whenever
//! `Base` is modified (directly or via any index) by using the `bar` field of the values in `Base`.
//!
//! The index table can be accessed directly like a normal table (`Url`), but I don't recommend it.
//! The key type is `Url` and the value type is `u64`.
//!
//! Index fields must uniquely identify a row in the base table. If multiple rows in the base table
//! have the same key in the index, then behavior is unspecified (might give partial or incorrect
//! result, might panic, etc.).
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
//! straighforward. For singleton data, we use a single HashMap which maps `TypeId` to `(Owner, SinValue)`.
//! Where the `TypeId` id the id of the type used to describe the singleton. Values can be
//! stored in different ways (inline, via an `Arc`, etc.) each of which is a variant of `SinValue`.
//! The store transparently converts keys and values to their declared types.
//!
//! The implementation of the storage operations (`get`, `insert`, etc.) is somewhat shared between
//! the various types which support them (`KvStore`, the table types, the transaction types, index
//! types, and transactional index types). These are implemented on traits in the `operations` module.
//! For ease of use and documentation, the functions are implemented on each concrete type and
//! delegated to the trait implementations. I.e., the traits and impls are an implementation detail.

use std::{
    ops::{Deref, DerefMut},
    sync::{RwLock, RwLockReadGuard, RwLockWriteGuard},
};

mod index;
mod iter;
mod operations;
mod raw;
pub mod schema;
mod singleton;
#[doc(hidden)]
pub mod storage;
mod transactions;

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
}

impl<'store, TableStorage: schema::GeneratedStorage> operations::Ops<TableStorage>
    for &'store KvStore<TableStorage>
{
    type ReadLock = RwLockReadGuard<'store, storage::Storage<TableStorage>>;

    fn read_lock(self) -> Self::ReadLock {
        self.storage.read().unwrap()
    }
}

impl<'store, TableStorage: schema::GeneratedStorage> operations::OpsMut<TableStorage>
    for &'store KvStore<TableStorage>
{
    type WriteLock = RwLockWriteGuard<'store, storage::Storage<TableStorage>>;

    fn write_lock(self) -> Self::WriteLock {
        self.storage.write().unwrap()
    }
}

/// A token indicating ownership of a KV singleton or table. See crate docs for what ownership means
/// for a store.
pub type Owner = &'static str;

/// An error from a [`KvStore`].
// TODO derive(Error)
#[derive(Debug, Clone)]
pub enum Error {
    /// A table was expected to not be initialized, but was by the specifed `Owner`.
    AlreadyInit(Owner),
}

/// `Result` alias for a KvStore [`Error`].
pub type Result<T> = std::result::Result<T, Error>;

/// Helper type for using a reference to a [`RwLockWriteGuard`] as a generic argument
/// with a `Deref` bound. Required because checking trait bounds does not take into account
/// transitivity of `Deref`.
struct RefWriteGuard<'a, 'inner, T>(&'a RwLockWriteGuard<'inner, T>);

impl<'a, 'inner, T> Deref for RefWriteGuard<'a, 'inner, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

/// Helper type for using a mut reference to a [`RwLockWriteGuard`] as a generic argument
/// with `Deref` and `DerefMut` bounds. Required because checking trait bounds does not take into
/// account transitivity of `Deref`.
struct RefWriteGuardMut<'a, 'inner, T>(&'a mut RwLockWriteGuard<'inner, T>);

impl<'a, 'inner, T> Deref for RefWriteGuardMut<'a, 'inner, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}
impl<'a, 'inner, T> DerefMut for RefWriteGuardMut<'a, 'inner, T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        self.0.deref_mut()
    }
}
/// Helper type for using a reference to a [`RwLockReadGuard`] as a generic argument
/// with a `Deref` bound. Required because checking trait bounds does not take into account
/// transitivity of `Deref`.
struct RefReadGuard<'a, 'inner, T>(&'a RwLockReadGuard<'inner, T>);

impl<'a, 'inner, T> Deref for RefReadGuard<'a, 'inner, T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}
