//! Traits and macros for defining the KvStore schema.

use alloc::sync::Arc;
use core::{any::Any, hash::Hash, ops::Deref};

use crate::{
    Owner,
    pub_sub::Subscriptions,
    schema::index::{IndexRead, IndexWrite, MultiIndexRead},
    storage::{DefaultValue, SingletonSlot, Table, VersionedValue},
    transactions::TxnId,
};

pub mod index;
mod store_macros;

/// Describes a kind of data in the store, either a singleton or table.
#[doc(hidden)]
pub trait Desc: Sized + 'static {
    /// The data's owner.
    const OWNER: Owner;
    /// The storage for this data.
    type Storage: GeneratedStorage;
}

/// A singleton key/value.
///
/// Prefer to use the macros in this module rather than this trait directly.
///
/// # Safety
///
/// `value_ptr` must return a pointer derived from its argument `storage` without
/// creating a reference to `*storage`, and which does not overlap any other singleton's value or any
/// table in `Self::Storage`. The transactional API relies on this to give each
/// view of a transaction exclusive access to its own data.
#[doc(hidden)]
pub unsafe trait SingletonDesc: Desc {
    /// The type of the value.
    type Value: Any + Send + Sync;
    /// How the value is stored (determines whether the singleton is optional, or uses a default).
    type Slot: SingletonSlot<Value = Self::Value>;
    /// The type of the notification for this singleton (either `Self::Value` or `()`).
    type NotificationValue: Clone;

    /// Get a reference to the field storing this singleton in `storage`.
    fn get_ref(storage: &Self::Storage) -> &Self::Slot;

    /// Project a pointer to the storage to a pointer to the field storing this singleton, without
    /// creating a reference to the storage.
    ///
    /// # Safety
    ///
    /// `storage` must be valid for reads and writes (i.e., dereferenceable).
    unsafe fn value_ptr(storage: *mut Self::Storage) -> *mut Self::Slot;

    /// Convert a reference to this singleton's value to its notification value.
    fn notification_value(value: &Self::Value) -> &Self::NotificationValue;

    /// Create a notification from an event.
    fn make_notification(
        event: crate::SingletonEvent<Self>,
    ) -> <Self::Storage as GeneratedStorage>::Notification;
}

/// A singleton which may have no value (i.e., which is declared without `default`).
#[doc(hidden)]
pub trait OptionalSingletonDesc:
    SingletonDesc<Slot = VersionedValue<Option<<Self as SingletonDesc>::Value>>>
{
}

impl<S> OptionalSingletonDesc for S where
    S: SingletonDesc<Slot = VersionedValue<Option<<S as SingletonDesc>::Value>>>
{
}

/// A singleton declared with `default`, which always has a value.
#[doc(hidden)]
pub trait DefaultSingletonDesc:
    SingletonDesc<Slot = DefaultValue<<Self as SingletonDesc>::Value>, Value: Default>
{
}

impl<S> DefaultSingletonDesc for S where
    S: SingletonDesc<Slot = DefaultValue<<S as SingletonDesc>::Value>, Value: Default>
{
}

/// Describes tabular key/values in the store.
///
/// Prefer to use the macros in this module rather than this trait directly.
#[doc(hidden)]
pub trait TableDesc: Desc {
    /// The name of the table.
    const NAME: &'static str;

    /// The type of the key.
    type Key: Hash + Eq + Clone;
    /// The type of the value.
    type Value: Any + Send + Sync;
    /// The storage type for this table's indexes.
    type IndexStorage: IndexWrite<Self::Key, Self::Value>;
}

/// A primary table (i.e., not an index).
///
/// Among other things, only these tables can generate notifications to subscribers.
///
/// # Safety
///
/// `table_ptr` must return a pointer derived from its argument `storage` without creating a
/// reference to `*storage`, and which does not overlap any singleton's value or any other table in
/// `Self::Storage`. The transactional API relies on this to give each view of a transaction
/// exclusive access to its own data.
#[doc(hidden)]
pub unsafe trait PrimaryTableDesc: TableDesc {
    /// The type of the notification for this table (either `Self::Value` or `()`).
    type NotificationValue: Clone;

    /// Get a reference to the table in `storage`.
    fn get_table(storage: &Self::Storage) -> &Table<Self>;

    /// Project a pointer to the storage to a pointer to this table, without creating a reference
    /// to the storage.
    ///
    /// # Safety
    ///
    /// `storage` must be valid for reads and writes (i.e., dereferenceable).
    unsafe fn table_ptr(storage: *mut Self::Storage) -> *mut Table<Self>;

    /// Compare two references to this table's value type, returns `true` if the value type impls
    /// `PartialEq` and the values are equal.
    ///
    /// **Panics** if `Self::Value` does not impl `PartialEq`.
    fn value_eq(a: &Self::Value, b: &Self::Value) -> bool;

    /// Create a notification from an event.
    fn make_notification(
        event: crate::Event<Self>,
    ) -> <Self::Storage as GeneratedStorage>::Notification;

    /// Create a value for a notification, possibly by cloning `value`.
    fn clone_value_for_notification(value: &Self::Value) -> Self::NotificationValue;
}

/// A table which may have indexes.
#[doc(hidden)]
pub trait Indexable: PrimaryTableDesc {
    /// An object containing this table's indexes (with an owner).
    type Indexes: From<(Arc<crate::KvStore<Self::Storage>>, Owner)>;

    /// An object giving read/write access to this table's indexes in a transaction.
    type TransactionIndexes<'guard, 'txn>: From<&'txn mut crate::TableTransaction<'guard, Self>>
    where
        'guard: 'txn;

    /// An object giving read-only access to this table's indexes in a read/write transaction.
    type RoTransactionIndexes<'guard, 'txn>: From<&'txn crate::TableTransaction<'guard, Self>>
    where
        'guard: 'txn;

    /// An object giving read-only access to this table's indexes in a read-only transaction.
    type RoRoTransactionIndexes<'guard, 'txn>: From<&'txn crate::RoTableTransaction<'guard, Self>>
    where
        'guard: 'txn;
}

/// An index of a table.
///
/// # Safety
///
/// `index_ptr` must return a pointer derived from its argument `storage` without creating a
/// reference to `*storage`, which is contained in the table of `Self::BaseTable` (as returned by its
/// `table_ptr`), and which does not overlap any other index.
#[doc(hidden)]
pub unsafe trait IndexDesc: Desc {
    /// The type of the index key.
    type Key: Hash + Eq;
    /// The table which is indexed.
    type BaseTable: PrimaryTableDesc + TableDesc<Storage = Self::Storage>;
    /// How the index is stored.
    type IndexStorage;

    /// Get a reference to the index in `storage`.
    fn get_index(storage: &Self::Storage) -> &Self::IndexStorage;

    /// Project a pointer to the storage to a pointer to this index, without creating a reference
    /// to the storage.
    ///
    /// # Safety
    ///
    /// `storage` must be valid for reads and writes (i.e., dereferenceable).
    unsafe fn index_ptr(storage: *mut Self::Storage) -> *mut Self::IndexStorage;
}

/// An index where each index key maps to a single row of the base table.
#[doc(hidden)]
pub trait UniqueIndexDesc:
    IndexDesc<
    IndexStorage: IndexRead<
        <Self as IndexDesc>::Key,
        <<Self as IndexDesc>::BaseTable as TableDesc>::Key,
    >,
>
{
}

impl<D> UniqueIndexDesc for D where
    D: IndexDesc<
        IndexStorage: IndexRead<
            <D as IndexDesc>::Key,
            <<D as IndexDesc>::BaseTable as TableDesc>::Key,
        >,
    >
{
}

/// An index where each index key may map to multiple rows of the base table.
#[doc(hidden)]
pub trait MultiIndexDesc:
    IndexDesc<
    IndexStorage: MultiIndexRead<
        <Self as IndexDesc>::Key,
        <<Self as IndexDesc>::BaseTable as TableDesc>::Key,
    >,
>
{
}

impl<D> MultiIndexDesc for D where
    D: IndexDesc<
        IndexStorage: MultiIndexRead<
            <D as IndexDesc>::Key,
            <<D as IndexDesc>::BaseTable as TableDesc>::Key,
        >,
    >
{
}

/// A storage implementation.
///
/// This should be considered a sealed trait and not implemented except by the macros in this module.
/// Unfortunately it has to be public because of macro visibility hygiene.
#[doc(hidden)]
pub trait GeneratedStorage: Default + Send + Sync + 'static {
    /// An enum of all notification types.
    type Notification: Clone + Send + 'static;
    /// The type of transactions for a store.
    ///
    /// Will contain a field for each singleton and table.
    type Transaction<'a>: Into<crate::Transaction<'a, Self>>
    where
        Self: 'a;
    /// A read-only version of `Transaction`.
    type RoTransaction<'a>: Into<crate::RoTransaction<'a, Self>>
    where
        Self: 'a;

    /// Commit a transaction by applying all tables' transaction state to their permanent data.
    ///
    /// This operation must be atomic. I.e., it will only fail without any tables committed, and if it
    /// succeeds, then all masks have committed.
    fn commit_txn(
        &mut self,
        txn_id: TxnId,
        notifications: &mut crate::Notifications<Self::Notification>,
        subscriptions: &Subscriptions<Self::Notification>,
    ) -> crate::Result<()>;

    /// Delete any uncommitted per-transaction state associated with `txn_id` held in tables.
    fn gc_txn(&mut self, txn_id: TxnId);

    /// Create a schema-specific transaction from a general transaction object.
    fn make_txn<'a>(store_txn: crate::Transaction<'a, Self>) -> Self::Transaction<'a>;

    /// Create a schema-specific read-only transaction from a general transaction object.
    fn make_ro_txn<'a>(store_txn: crate::RoTransaction<'a, Self>) -> Self::RoTransaction<'a>;
}

/// Implemented by stores generated by the schema macros.
pub trait GeneratedStore:
    'static + Send + Sync + Deref<Target = crate::KvStore<Self::Storage>>
{
    /// The underlying storage for the store.
    type Storage: GeneratedStorage;

    /// Create a new, empty KV store as described by the schema macros, which sends
    /// notifications of changes to `notifier`.
    ///
    /// The store keeps only a weak reference to `notifier`, so the caller is responsible for
    /// keeping the notifier alive (e.g. via the subscribers it hands out). Once the last
    /// strong reference is dropped the store stops sending notifications.
    fn from_notifier(
        n: alloc::sync::Weak<
            dyn crate::Notifier<Notification = <Self::Storage as GeneratedStorage>::Notification>,
        >,
    ) -> Self;
}

#[cfg(test)]
mod test {
    use alloc::sync::Arc;

    use crate::{Owner, store};

    const OWNER: Owner = Owner("owner");

    mod single {
        use super::*;

        store!(
            kvs: {
                Foo(Box<u64>; OWNER; notify(Clone)),
                Bar(Arc<u64>; OWNER; notify(None)),
                Baz(&'static u64; OWNER),
                Qux(u64; OWNER),
            }
        );

        #[test]
        fn single() {
            let store = KvStore::new();
            store.Foo.insert(OWNER, Box::new(42));
            assert_eq!(store.Foo.get(OWNER).unwrap(), Box::new(42));
        }
    }

    mod table {
        use super::*;

        store!(tables: { Foo(&'static str => String; OWNER; notify(Clone)), Bar(u32 => Vec<String>; OWNER)});

        #[test]
        fn table() {
            let store = KvStore::new();

            store.Foo.insert(OWNER, "hello", "world".to_owned());
            assert_eq!(store.Foo.get(OWNER, "hello").unwrap(), "world");

            store
                .Bar
                .insert(OWNER, 5, vec!["boo".to_owned(), "bang".to_owned()]);
            assert_eq!(
                store.Bar.get(OWNER, &5).unwrap(),
                vec!["boo".to_owned(), "bang".to_owned()]
            );
        }

        #[test]
        fn send_and_sync() {
            fn require_send<T: Send>(_t: T) {}
            fn require_sync<T: Sync>(_t: T) {}

            require_send(KvStore::new());
            require_sync(KvStore::new());
        }
    }

    mod table_with_indexes {
        use super::*;

        #[derive(Clone, Debug)]
        pub struct BarT {
            a: String,
        }

        store!(
            tables: {
                Foo(&'static str => String; OWNER; index(len: usize = |v: &String| [v.len()])),
                Bar(u32 => BarT; OWNER; index(a: String; assert)),
            }
        );

        #[test]
        fn table_with_indexes() {
            let store = KvStore::new();
            store.Bar.insert(
                OWNER,
                5,
                BarT {
                    a: "hello".to_owned(),
                },
            );
            let value = store.Bar.indexes(OWNER).a.get("hello").unwrap();
            assert_eq!(value.1.a, "hello");

            store.Foo.insert(OWNER, "foo", "hello".to_owned());
            let value = store.Foo.indexes(OWNER).len.get(&5).unwrap();
            assert_eq!(value, ("foo", "hello".to_owned()));
        }
    }
}
