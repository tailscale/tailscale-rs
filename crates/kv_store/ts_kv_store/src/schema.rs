//! Traits and macros for defining the KvStore schema.

use alloc::sync::Arc;
use core::{any::Any, borrow::Borrow, hash::Hash, ops::Deref};

use crate::{
    Owner,
    pub_sub::Subscriptions,
    storage::{Table, VersionedValue},
    transactions::TxnId,
};

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
    /// The type of the notification for this singleton (either `Self::Value` or `()`).
    type NotificationValue: Clone;

    /// Get a reference to the field storing this singleton in `storage`.
    fn get_ref(storage: &Self::Storage) -> &VersionedValue<Option<Self::Value>>;

    /// Project a pointer to the storage to a pointer to the field storing this singleton, without
    /// creating a reference to the storage.
    ///
    /// # Safety
    ///
    /// `storage` must be valid for reads and writes (i.e., dereferenceable).
    unsafe fn value_ptr(storage: *mut Self::Storage) -> *mut VersionedValue<Option<Self::Value>>;

    /// Convert an optional reference to this singleton's value to its notification value.
    fn notification_value(value: &Option<Self::Value>) -> &Option<Self::NotificationValue>;

    /// Create a notification from an event.
    fn make_notification(
        event: crate::SingletonEvent<Self>,
    ) -> <Self::Storage as GeneratedStorage>::Notification;
}

/// Describes tabular key/values in the store.
///
/// Prefer to use the macros in this module rather than this trait directly.
///
/// # Safety
///
/// `table_ptr` must return a pointer derived from its argument `storage` without creating a
/// reference to `*storage`, and which does not overlap any singleton's value or any other table in
/// `Self::Storage` (except that an index's table is contained in its base table (see
/// [`IndexDesc`])). The transactional API relies on this to give each view of a transaction exclusive
/// access to its own data.
#[doc(hidden)]
pub unsafe trait TableDesc: Desc {
    /// The name of the table.
    const NAME: &'static str;

    /// The type of the key.
    type Key: Hash + Eq + Clone;
    /// The type of the value.
    type Value: Any + Send + Sync;
    /// The storage type for this table's indexes.
    type IndexStorage: IndexStorage<Self::Key, Self::Value>;

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
}

/// A primary table (i.e., not an index).
///
/// Among other things, only these tables can generate notifications to subscribers.
#[doc(hidden)]
pub trait PrimaryDesc: TableDesc {
    /// The type of the notification for this table (either `Self::Value` or `()`).
    type NotificationValue: Clone;

    /// Create a notification from an event.
    fn make_notification(
        event: crate::Event<Self>,
    ) -> <Self::Storage as GeneratedStorage>::Notification;

    /// Create a value for a notification, possibly by cloning `value`.
    fn clone_value_for_notification(value: &Self::Value) -> Self::NotificationValue;
}

/// A table which may have indexes.
#[doc(hidden)]
pub trait Indexable: PrimaryDesc {
    /// An object containing this table's indexes.
    type Indexes: From<Arc<crate::KvStore<Self::Storage>>>;

    /// An object containing this table's indexes (with an owner).
    type IndexesWithOwner: From<(Arc<crate::KvStore<Self::Storage>>, Owner)>;

    /// An object containing this table's indexes.
    type TransactionIndexes<'guard, 'txn>: From<&'txn crate::TableTransaction<'guard, Self>>
    where
        'guard: 'txn;

    /// An object containing this table's indexes.
    type RoTransactionIndexes<'guard, 'txn>: From<&'txn crate::RoTableTransaction<'guard, Self>>
    where
        'guard: 'txn;
}

/// A table used as an index.
///
/// # Safety
///
/// This index's table (as returned by `TableDesc::table_ptr`) must be contained in the table of
/// `Self::BaseTable` (as returned by its `table_ptr`), and must not overlap any other index's table.
#[doc(hidden)]
pub unsafe trait IndexDesc: TableDesc {
    /// The table which is indexed.
    type BaseTable: PrimaryDesc + TableDesc<Storage = Self::Storage, Key = Self::Value>;
}

/// Operations on the indexes of a table.
#[doc(hidden)]
pub trait IndexStorage<K: Hash + Eq, V: Any + Send + Sync>: Default {
    /// Whether there are any indexes, i.e., whether the methods of this trait do anything. If
    /// `false`, callers may skip work which only serves to maintain indexes.
    const HAS_INDEXES: bool = true;

    /// Clear the whole index.
    fn clear(&mut self, txn_id: TxnId);

    /// An item has been inserted into the base table.
    fn on_insert<Q>(&mut self, key: &Q, value: &V, txn_id: TxnId)
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq + ToOwned<Owned = K>;

    /// An item has been removed from the base table.
    fn on_remove(&mut self, value: &V, txn_id: TxnId);
}

impl<K: Hash + Eq, V: Any + Send + Sync> IndexStorage<K, V> for () {
    const HAS_INDEXES: bool = false;

    fn clear(&mut self, _txn_id: TxnId) {}

    fn on_insert<Q>(&mut self, _key: &Q, _value: &V, _txn_id: TxnId)
    where
        K: Borrow<Q>,
        Q: ?Sized + Hash + Eq,
    {
    }

    fn on_remove(&mut self, _value: &V, _txn_id: TxnId) {}
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

/// Declare the schema of a key/value store. Generates the store itself with the specified tables and
/// singletons.
///
/// The syntax is:
/// ```ignore
/// store!(
///   kvs: { Name(ValueType; owner; notify(None|Clone)?),* }
///   tables: { Name(KeyType => ValueType; owner; indexes?; notify(None|Clone)?),* }
/// )
/// ```
/// where `Name` is an identifier to name the table or singleton (in which case it is also the key),
/// `KeyType` and `ValueType` are types. `owner` is an expression which evaluates to an `Owner`.
/// `Name` is also the name of the field of the generated store used to access the table or
/// singleton. Names (of tables, singletons, and indexes) should not start with `__`.
///
/// # Example:
///
/// ```rust
/// # use ts_kv_store::store;
/// # use std::sync::Arc;
/// # const GRAPH_OWNER: ts_kv_store::Owner = "foo";
/// # const NODES_OWNER: ts_kv_store::Owner = "bar";
/// # const EDGES_OWNER: ts_kv_store::Owner = "baz";
/// # pub struct Node;
/// # #[derive(Clone, PartialEq)]
/// # pub struct Gid;
/// # pub trait Edge {}
/// store!(
///   kvs: {
///     GraphId(Arc<Gid>; GRAPH_OWNER),
///   }
///   tables: {
///     Nodes(&'static str => Node; NODES_OWNER),
///     Edges(u32 => Box<dyn Edge + Send + Sync>; EDGES_OWNER),
///   }
/// );
/// ```
///
/// # Indexes
///
/// The syntax of an index is `index(field: Type (= closure)? (; assert_unique)?)` where `field` is
/// the name of the index and `Type` is the type of the index key. By default, `field` is also the
/// name of a field in the value type of the base table, whose value is used as the index key;
/// `closure` can be specified to compute the index key instead. You can specify multiple indexes
/// for each table, separated with a semicolon. E.g.,
///
/// ```rust
/// # use ts_kv_store::store;
/// # const NODES_OWNER: ts_kv_store::Owner = "foo";
/// # pub struct Node { a: u32, b: String };
/// store!(
///   tables: {
///     Nodes(
///       &'static str => Node;
///       NODES_OWNER;
///       index(a: u32);
///       index(b: String; assert_unique);
///       index(c: String = |node: &Node| [format!("{}-{}", node.a, node.b)]);
///     )
///   }
/// );
/// ```
///
/// This will create indexes `a`, `b`, and `c` on nodes. `c`'s index key is
/// computed by the specified closure, which is expected to return
/// `impl IntoIterator<Item = I>` (where `I` is the index key type), for example an `Option<I>` for
/// zero or one index keys per value.
///
/// Index fields must uniquely identify a row in the base table. If multiple rows in the base table
/// have the same key in the index, then by default the index will be 'poisoned' and accessing the
/// index or trying to commit a transaction where an index is poisoned will return an error (`NonUniqueIndexKey`).
/// By adding `assert_unique` to an index declaration (after the index field, separated with a semicolon),
/// attempting to store multiple rows with the same index key will cause a panic.
///
/// # Notifications
///
/// The `notify(...)` argument is used to control notifications about the table or singleton. Accepted
/// values are `Clone` and `None`. The default is `None`.
///
/// The `None` behaviour is that only keys are sent in notifications. The `Clone` behaviour is
/// that values are cloned and included in notifications. This requires that the value type implements
/// the `Clone` trait.
#[macro_export]
macro_rules! store {
    (
        $(kvs: { $($sname:ident($svalue_ty:ty; $sowner:expr $(; notify($snotif:ident))?)),* $(,)? })?
        $(tables: { $(
            $name:ident (
                $key_ty:ty => $value_ty:ty;
                $owner:expr
                $(; index($field:ident: $field_ty:ty $(= $get_idx:expr)? $(; $unique:ident)?))*
                $(; notify($notif:ident))?
                $(;)?
            )
        ),* $(,)? })?
    ) => {
        $($(
            /// Describes a singleton in the KV store.
            #[allow(non_camel_case_types)]
            pub enum $sname {}

            impl $crate::schema::Desc for $sname {
                const OWNER: $crate::Owner = $sowner;
                type Storage = TableStorage;
            }

            // SAFETY: `value_ptr` points to the singleton's own field of `TableStorage`.
            unsafe impl $crate::schema::SingletonDesc for $sname {
                type Value = $svalue_ty;
                type NotificationValue = $crate::notification_value_type!($svalue_ty $(; notify($snotif))?);

                fn get_ref(storage: &Self::Storage) -> &$crate::storage::VersionedValue<::core::option::Option<Self::Value>> {
                    &storage.$sname
                }

                unsafe fn value_ptr(storage: *mut Self::Storage) -> *mut $crate::storage::VersionedValue<::core::option::Option<Self::Value>> {
                    // SAFETY: `storage` is dereferenceable (by the caller's contract). This only
                    // computes a place, it does not create a reference to the storage.
                    unsafe { &raw mut (*storage).$sname }
                }

                fn notification_value(_value: &::core::option::Option<Self::Value>) -> &::core::option::Option<Self::NotificationValue> {
                    $crate::notification_value!(_value $(; notify($snotif))? )
                }

                fn make_notification(
                    event: $crate::SingletonEvent<Self>,
                ) -> <Self::Storage as $crate::schema::GeneratedStorage>::Notification {
                    Notification::$sname(event)
                }
            }
        )*)?
        $($(
            /// Describes a table in the KV store.
            pub enum $name {}

            impl $crate::schema::Desc for $name {
                const OWNER: $crate::Owner = $owner;
                type Storage = TableStorage;
            }

            // SAFETY: `table_ptr` points to the table's own field of `TableStorage`.
            unsafe impl $crate::schema::TableDesc for $name {
                const NAME: &'static str = ::core::stringify!($name);
                type Key = $key_ty;
                type Value = $value_ty;
                type IndexStorage = index::$name::Storage;

                fn get_table(storage: &TableStorage) -> &$crate::storage::Table<Self> {
                    &storage.$name
                }
                unsafe fn table_ptr(storage: *mut TableStorage) -> *mut $crate::storage::Table<Self> {
                    // SAFETY: `storage` is dereferenceable (by the caller's contract). This only
                    // computes a place, it does not create a reference to the storage.
                    unsafe { &raw mut (*storage).$name }
                }

                $crate::value_eq!(Self::Value);
            }

            impl $crate::schema::PrimaryDesc for $name {
                type NotificationValue = $crate::notification_value_type!($value_ty $(; notify($notif))?);

                fn make_notification(event: $crate::Event<Self>) -> <Self::Storage as $crate::schema::GeneratedStorage>::Notification {
                    Notification::$name(event)
                }
                fn clone_value_for_notification(_value: &Self::Value) -> Self::NotificationValue {
                    $crate::notification_clone_value!(_value $(; notify($notif))?)
                }
            }

            impl $crate::schema::Indexable for $name {
                type Indexes = index::$name::Indexes;
                type IndexesWithOwner = index::$name::IndexesWithOwner;
                type TransactionIndexes<'guard, 'txn> = index::$name::TransactionIndexes<'guard, 'txn> where 'guard: 'txn;
                type RoTransactionIndexes<'guard, 'txn> = index::$name::RoTransactionIndexes<'txn> where 'guard: 'txn;
            }

            $(

                impl $crate::schema::Desc for index::$name::$field {
                    const OWNER: $crate::Owner = $owner;
                    type Storage = TableStorage;
                }

                // SAFETY: `table_ptr` points to the index's own field of its base table's
                // `indexes`.
                unsafe impl $crate::schema::TableDesc for index::$name::$field where $field_ty: ::core::clone::Clone {
                    const NAME: &'static str = ::core::stringify!($name by $field);
                    type Key = $field_ty;
                    type Value = $key_ty;
                    type IndexStorage = ();

                    fn get_table(storage: &TableStorage) -> &$crate::storage::Table<Self> {
                        &storage.$name.indexes.$field
                    }
                    unsafe fn table_ptr(storage: *mut TableStorage) -> *mut $crate::storage::Table<Self> {
                        // SAFETY: `storage` is dereferenceable (by the caller's contract). This
                        // only computes a place, it does not create a reference to the storage or
                        // the base table.
                        unsafe { &raw mut (*storage).$name.indexes.$field }
                    }
                    $crate::value_eq!(Self::Value);
                }

                // SAFETY: the index's table is a field of `$name`'s table (see `table_ptr`).
                unsafe impl $crate::schema::IndexDesc for index::$name::$field {
                    type BaseTable = $name;
                }
            )*
        )*)?

        /// Macro-generated storage for all data.
        #[derive(::core::default::Default)]
        #[allow(non_snake_case)]
        pub struct TableStorage {
            $($($name: $crate::storage::Table<$name>,)*)?
            $($($sname: $crate::storage::VersionedValue<::core::option::Option<$svalue_ty>>,)*)?
        }

        /// Macro-generated notification type, there is a variant for each table and singleton with
        /// the appropriate types (wrapping event types in `ts_kv_store`). For notifications which
        /// don't include a value (either by default or by opting-out using `notify(None)`), the value
        /// type is `()`.
        #[derive(::core::clone::Clone)]
        #[allow(unused)]
        #[allow(non_camel_case_types)]
        pub enum Notification {
            $($($name($crate::Event<$name>),)*)?
            $($($sname($crate::SingletonEvent<$sname>),)*)?
        }

        impl ::core::fmt::Debug for Notification {
            fn fmt(&self, f: &mut ::core::fmt::Formatter<'_>) -> ::core::fmt::Result {
                match self {
                    $($(Notification::$name(..) => ::core::write!(f, ::core::stringify!($name)),)*)?
                    $($(Notification::$sname(..) => ::core::write!(f, ::core::stringify!($sname)),)*)?
                }
            }
        }

        impl $crate::schema::GeneratedStorage for TableStorage {
            type Notification = Notification;
            type Transaction<'a> = Transaction<'a>;
            type RoTransaction<'a> = RoTransaction<'a>;

            fn commit_txn(&mut self, _txn_id: $crate::transactions::TxnId, _notifications: &mut $crate::Notifications<Notification>, _subscriptions: &$crate::pub_sub::Subscriptions<Self::Notification>) -> $crate::Result<()> {
                $(
                    $(
                        self.$name.check_txn_consistency(_txn_id)?;
                        $(self.$name.indexes.$field.check_txn_consistency(_txn_id)?;)*
                    )*
                )?
                $(
                    $(
                        if _subscriptions.has_singleton_subscribers::<$sname>()
                            && let ::core::option::Option::Some(event) = self.$sname.modified_in_txn(_txn_id)
                        {
                            _subscriptions.collect_singleton_events::<$sname>(_notifications, <$sname as $crate::schema::SingletonDesc>::notification_value(event));
                        }
                    )*
                )?
                $(
                    $(
                        let events = self.$name.commit_primary_table(_txn_id, _subscriptions.has_subscribers::<$name>());
                        if !events.is_empty() {
                            _subscriptions.collect_events::<$name>(_notifications, events);
                        }
                        $(self.$name.indexes.$field.commit_without_notifications(_txn_id);)*
                    )*
                )?

                ::core::result::Result::Ok(())
            }

            fn gc_txn(&mut self, _txn_id: $crate::transactions::TxnId) {
                $(
                    $(
                        self.$name.gc_txn(_txn_id);
                        $(self.$name.indexes.$field.gc_txn(_txn_id);)*
                    )*
                )?
                $(
                    $(
                        self.$sname.gc_txn(_txn_id);
                    )*
                )?
            }

            fn make_txn<'a>(store_txn: $crate::Transaction<'a, Self>) -> Self::Transaction<'a> {
                Transaction::new(store_txn)
            }

            fn make_ro_txn<'a>(store_txn: $crate::RoTransaction<'a, Self>) -> Self::RoTransaction<'a> {
                RoTransaction::new(store_txn)
            }
        }

        pub mod index {
            $($(
                #[allow(non_snake_case)]
                pub mod $name {
                    $(
                        #[allow(non_camel_case_types)]
                        pub struct $field;
                    )*

                    /// Storage for the table's indexes.
                    #[derive(::core::default::Default)]
                    pub struct Storage {
                        $(
                            #[allow(dead_code)]
                            pub $field: $crate::storage::Table<$field>,
                        )*
                    }

                    /// Access to the table's indexes, with a field for each index.
                    ///
                    /// Returned by `Table::indexes`.
                    pub struct Indexes {
                        $(
                            #[allow(dead_code)]
                            pub $field: $crate::Index<$field>,
                        )*
                    }

                    /// Access to the table's indexes with a fixed owner, with a field for each index.
                    ///
                    /// Returned by `TableWithOwner::indexes`.
                    pub struct IndexesWithOwner {
                        $(
                            #[allow(dead_code)]
                            pub $field: $crate::IndexWithOwner<$field>,
                        )*
                    }

                    /// Access to the table's indexes within a transaction, with a field for each index.
                    ///
                    /// Returned by `TableTransaction::indexes`.
                    pub struct TransactionIndexes<'guard, 'txn> {
                        #[doc(hidden)]
                        pub(in super::super) __txn: ::core::marker::PhantomData<(&'txn (), &'guard ())>,
                        $(
                            #[allow(dead_code)]
                            pub $field: $crate::IndexTransaction<'guard, 'txn, $field>,
                        )*
                    }

                    /// Access to the table's indexes within a read-only transaction, with a field
                    /// for each index.
                    ///
                    /// Returned by `RoTableTransaction::indexes`.
                    pub struct RoTransactionIndexes<'txn> {
                        #[doc(hidden)]
                        pub(in super::super) __txn: ::core::marker::PhantomData<&'txn ()>,
                        $(
                            #[allow(dead_code)]
                            pub $field: $crate::RoIndexTransaction<'txn, $field>,
                        )*
                    }
                }
            )*)?
        }

        $($(
            impl ::core::convert::From<$crate::__alloc::sync::Arc<$crate::KvStore<TableStorage>>> for index::$name::Indexes {
                fn from(_store: $crate::__alloc::sync::Arc<$crate::KvStore<TableStorage>>) -> Self {
                    index::$name::Indexes {
                        $($field: $crate::Index::new(::core::clone::Clone::clone(&_store)),)*
                    }
                }
            }

            impl ::core::convert::From<($crate::__alloc::sync::Arc<$crate::KvStore<TableStorage>>, $crate::Owner)> for index::$name::IndexesWithOwner {
                fn from((_store, _owner): ($crate::__alloc::sync::Arc<$crate::KvStore<TableStorage>>, $crate::Owner)) -> Self {
                    index::$name::IndexesWithOwner {
                        $($field: $crate::IndexWithOwner::new(::core::clone::Clone::clone(&_store), _owner),)*
                    }
                }
            }

            impl<'guard, 'txn> ::core::convert::From<&'txn $crate::TableTransaction<'guard, $name>> for index::$name::TransactionIndexes<'guard, 'txn> {
                fn from(_base: &'txn $crate::TableTransaction<'guard, $name>) -> Self {
                    index::$name::TransactionIndexes {
                        __txn: ::core::marker::PhantomData,
                        $($field: $crate::IndexTransaction::new(_base),)*
                    }
                }
            }

            impl<'guard, 'txn> ::core::convert::From<&'txn $crate::RoTableTransaction<'guard, $name>> for index::$name::RoTransactionIndexes<'txn> {
                fn from(_base: &'txn $crate::RoTableTransaction<'guard, $name>) -> Self {
                    index::$name::RoTransactionIndexes {
                        __txn: ::core::marker::PhantomData,
                        $($field: $crate::RoIndexTransaction::new(_base),)*
                    }
                }
            }

            impl index::$name::Storage {
                $(
                    fn $field(val: &$value_ty) -> impl ::core::iter::IntoIterator<Item = $field_ty> {
                        ($crate::get_index_fn!($value_ty, $field $(, $get_idx)?))(val)
                    }
                )*
            }

            impl $crate::schema::IndexStorage<$key_ty, $value_ty> for index::$name::Storage {
                fn clear(&mut self, _txn_id: $crate::transactions::TxnId) {
                    $(
                        self.$field.clear(_txn_id);
                    )*
                }

                fn on_insert<Q>(&mut self, _key: &Q, _value: &$value_ty, _txn_id: $crate::transactions::TxnId)
                where
                    $key_ty: ::core::borrow::Borrow<Q>,
                    Q: ?::core::marker::Sized + ::core::hash::Hash + ::core::cmp::Eq + $crate::__alloc::borrow::ToOwned<Owned = $key_ty>
                {
                    $(
                        $crate::on_insert_each!($name, $field: $field_ty; (self, _key, _value, _txn_id) $(; $unique)?);
                    )*
                }

                fn on_remove(&mut self, _value: &$value_ty, _txn_id: $crate::transactions::TxnId) {
                    $({
                        for value in index::$name::Storage::$field(_value) {
                            self.$field.remove(&value, _txn_id);
                        }
                    })*
                }
            }
        )*)?

        /// A key-value store.
        ///
        /// See `ts_kv_store::KvStore` (which this type implicitly dereferences to) for full docs.
        #[allow(non_snake_case)]
        pub struct KvStore {
            __store: $crate::__alloc::sync::Arc<$crate::KvStore<TableStorage>>,

            $($(#[allow(dead_code)] pub $name: $crate::Table<$name>,)*)?
            $($(#[allow(dead_code)] pub $sname: $crate::Singleton<$sname>,)*)?
        }

        impl KvStore {
            /// Create a new, empty KV store as described by the schema macros.
            ///
            /// The store has no notifier, so it does not support subscriptions: subscribing returns
            /// `ts_kv_store::Error::MissingNotifier`.
            #[allow(dead_code, clippy::new_without_default)]
            pub fn new() -> Self {
                // The store only holds a weak reference to its notifier, so downgrading a
                // throwaway no-op notifier leaves the store with a dead weak reference. Upgrading it
                // always fails, which means no notifications are ever sent.
                <Self as $crate::GeneratedStore>::from_notifier($crate::__alloc::sync::Arc::downgrade(&$crate::NoOpNotifier::new()))
            }

            /// A convenience for operating on the store with a specified owner.
            #[allow(dead_code)]
            pub fn with_owner(&self, owner: $crate::Owner) -> KvStoreWithOwner<'_> {
                KvStoreWithOwner {
                    $($($name: $crate::TableWithOwner::new(::core::clone::Clone::clone(&self.__store), owner),)*)?
                    $($($sname: $crate::SingletonWithOwner::new(::core::clone::Clone::clone(&self.__store), owner),)*)?
                    __store: &self.__store,
                    __owner: owner,
                }
            }
        }

        impl ::core::ops::Deref for KvStore {
            type Target = $crate::KvStore<TableStorage>;

            fn deref(&self) -> &Self::Target {
                &self.__store
            }
        }

        impl $crate::GeneratedStore for KvStore {
            type Storage = TableStorage;

            fn from_notifier(notifier: $crate::__alloc::sync::Weak<dyn $crate::Notifier<Notification = <TableStorage as $crate::schema::GeneratedStorage>::Notification>>) -> Self {
                let store = $crate::__alloc::sync::Arc::new($crate::KvStore::from_notifier(notifier));
                KvStore {
                    $($($name: $crate::Table::new(::core::clone::Clone::clone(&store)),)*)?
                    $($($sname: $crate::Singleton::new(::core::clone::Clone::clone(&store)),)*)?
                    __store: store,
                }
            }

        }

        /// A key-value store with a fixed owner.
        ///
        /// Created by `KvStore::with_owner`. Operations on its fields do not take an owner, they
        /// use the owner supplied to `KvStore::with_owner`.
        #[allow(non_snake_case)]
        pub struct KvStoreWithOwner<'a> {
            __store: &'a $crate::KvStore<TableStorage>,
            __owner: $crate::Owner,

            $($(#[allow(dead_code)] pub $name: $crate::TableWithOwner<$name>,)*)?
            $($(#[allow(dead_code)] pub $sname: $crate::SingletonWithOwner<$sname>,)*)?
        }

        #[allow(dead_code)]
        impl<'a> KvStoreWithOwner<'a> {
            /// Start a transaction.
            ///
            /// Blocks until the store's global lock is available for write access.
            pub fn begin_transaction(&self) -> Transaction<'a> {
                self.__store.begin_transaction(self.__owner)
            }

            /// Start a transaction.
            ///
            /// Returns `None` if the store's global lock is unavailable for write access.
            pub fn try_begin_transaction(&self) -> ::core::option::Option<Transaction<'a>> {
                self.__store.try_begin_transaction(self.__owner)
            }

            /// Start a read-only transaction (i.e., only supports non-mutating access to the store,
            /// but all reads are guaranteed to be atomic).
            ///
            /// Blocks until the store's global lock is available for read access.
            pub fn begin_ro_transaction(&self) -> RoTransaction<'a> {
                self.__store.begin_ro_transaction(self.__owner)
            }

            /// Start a read-only transaction (i.e., only supports non-mutating access to the store,
            /// but all reads are guaranteed to be atomic).
            ///
            /// Returns `None` if the store's global lock is unavailable for read access.
            pub fn try_begin_ro_transaction(&self) -> ::core::option::Option<RoTransaction<'a>> {
                self.__store.try_begin_ro_transaction(self.__owner)
            }

            /// Register a new subscriber (with the owner supplied to `with_owner`) to the store.
            ///
            /// Does not create any subscriptions.
            pub fn register_subscriber(&self) -> $crate::Subscriber {
                self.__store.register_subscriber(self.__owner)
            }

            /// Remove a subscriber from the store, along with all of its subscriptions.
            ///
            /// The subscriber receives no further notifications and cannot subscribe again
            /// (subscribing with a removed subscriber gives
            /// `ts_kv_store::Error::UnknownSubscriber`). Unsubscribing any of its subscriptions is
            /// harmless but pointless.
            ///
            /// Does nothing if the subscriber is unknown (e.g., because it has already been
            /// removed).
            pub fn remove_subscriber(&self, subscriber: impl ::core::convert::Into<$crate::Subscriber>) {
                self.__store.remove_subscriber(subscriber)
            }

            /// Subscribe to the whole store.
            pub fn subscribe_global(
                &self,
                subscriber: impl ::core::convert::Into<$crate::Subscriber>,
            ) -> $crate::Result<$crate::Subscription> {
                self.__store.subscribe_global(subscriber)
            }

            /// Remove a subscription to the whole store.
            pub fn unsubscribe_global(&self, subscription: $crate::Subscription) {
                self.__store.unsubscribe_global(subscription);
            }
        }

        #[allow(non_snake_case)]
        #[allow(dead_code)]
        pub struct Transaction<'a> {
            // Shared with every view (field) of the transaction.
            __store_txn: $crate::__alloc::rc::Rc<$crate::Transaction<'a, TableStorage>>,

            $($(pub $name: $crate::TableTransaction<'a, $name>,)*)?
            $($(pub $sname: $crate::SingletonTransaction<'a, $sname>,)*)?
        }

        #[allow(dead_code)]
        impl<'a> Transaction<'a> {
            fn new(store_txn: $crate::Transaction<'a, TableStorage>) -> Self {
                let store_txn = $crate::__alloc::rc::Rc::new(store_txn);

                Transaction {
                    $($(
                        // SAFETY: this is the only view of `$name`.
                        $name: unsafe { $crate::TableTransaction::new(::core::clone::Clone::clone(&store_txn)) },
                    )*)?
                    $($(
                        // SAFETY: this is the only view of `$sname`.
                        $sname: unsafe { $crate::SingletonTransaction::new(::core::clone::Clone::clone(&store_txn)) },
                    )*)?

                    __store_txn: store_txn,
                }
            }

            /// Commit this transaction.
            ///
            /// Returns `ts_kv_store::Error::TransactionFailed` (and rolls back the transaction) if
            /// a panic unwound out of an operation on the transaction and was caught.
            ///
            /// Returns `ts_kv_store::Error::NonUniqueIndexKey` (and rolls back the transaction) if
            /// the transaction made an index non-unique.
            ///
            /// Panics if any of this transaction's fields have been moved out but are still live.
            pub fn commit(self) -> $crate::Result<()> {
                ::core::convert::Into::<$crate::Transaction<'_, _>>::into(self).commit()
            }

            /// Explicitly rollback this transaction.
            ///
            /// A transaction can also be rolled-back by dropping it without first calling `commit`.
            pub fn rollback(self) {
                // Dropping `self` causes the rollback.
            }
        }

        impl<'a> ::core::convert::From<Transaction<'a>> for $crate::Transaction<'a, TableStorage> {
            fn from(t: Transaction<'a>) -> $crate::Transaction<'a, TableStorage> {
                let store_txn = ::core::clone::Clone::clone(&t.__store_txn);
                // Drop all views so that `store_txn` is the only reference to the transaction.
                ::core::mem::drop(t);

                $crate::__alloc::rc::Rc::into_inner(store_txn).unwrap()
            }
        }

        #[allow(non_snake_case)]
        #[allow(dead_code)]
        pub struct RoTransaction<'a> {
            __store_txn: $crate::__alloc::rc::Rc<$crate::RoTransaction<'a, TableStorage>>,

            $($(pub $name: $crate::RoTableTransaction<'a, $name>,)*)?
            $($(pub $sname: $crate::RoSingletonTransaction<'a, $sname>,)*)?
        }

        #[allow(dead_code)]
        impl<'a> RoTransaction<'a> {
            fn new(store_txn: $crate::RoTransaction<'a, TableStorage>) -> Self {
                let store_txn = $crate::__alloc::rc::Rc::new(store_txn);

                RoTransaction {
                    $($($name: $crate::RoTableTransaction::new(::core::clone::Clone::clone(&store_txn)),)*)?
                    $($($sname: $crate::RoSingletonTransaction::new(::core::clone::Clone::clone(&store_txn)),)*)?

                    __store_txn: store_txn,
                }
            }

            /// 'Commit' this transaction.
            ///
            /// This simply drops the transaction (releasing its lock on the store) and always
            /// succeeds.
            pub fn commit(self) -> $crate::Result<()> {
                ::core::result::Result::Ok(())
            }

            /// 'Rollback' this transaction.
            ///
            /// Like `commit`, this only drops this transaction's lock.
            pub fn rollback(self) {
                // Dropping `self` causes the rollback.
            }
        }

        impl<'a> ::core::convert::From<RoTransaction<'a>> for $crate::RoTransaction<'a, TableStorage> {
            fn from(t: RoTransaction<'a>) -> $crate::RoTransaction<'a, TableStorage> {
                let store_txn = ::core::clone::Clone::clone(&t.__store_txn);
                // Drop all views so that `store_txn` is the only reference to the transaction.
                ::core::mem::drop(t);

                $crate::__alloc::rc::Rc::into_inner(store_txn).unwrap()
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! get_index_fn {
    ($value_ty:ty, $field:ident) => {
        |value: &$value_ty| [::core::clone::Clone::clone(&value.$field)]
    };
    ($value_ty:ty, $field:ident, $get_idx:expr) => {
        $get_idx
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! on_insert_each {
    (
        $name:ident,
        $field:ident :
        $field_ty:ty;
        ($self:ident, $key:ident, $value:ident, $txn_id:ident); assert_unique
    ) => {
        for index_key in index::$name::Storage::$field($value) {
            let unique = $self.$field.get::<$field_ty>(&index_key, $txn_id).is_none();
            ::core::assert!(
                unique,
                "Index key is non-unique for index `{}` of table `{}`",
                ::core::stringify!($field),
                ::core::stringify!($name),
            );
            $self.$field.insert(
                index_key,
                $crate::__alloc::borrow::ToOwned::to_owned($key),
                $txn_id,
            );
        }
    };
    (
        $name:ident,
        $field:ident :
        $field_ty:ty;
        ($self:ident, $key:ident, $value:ident, $txn_id:ident)
    ) => {
        for index_key in index::$name::Storage::$field($value) {
            let unique = $self.$field.get::<$field_ty>(&index_key, $txn_id).is_none();
            if unique {
                $self.$field.insert(
                    index_key,
                    $crate::__alloc::borrow::ToOwned::to_owned($key),
                    $txn_id,
                );
            } else {
                $self.$field.set_poisoned($txn_id);
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! value_eq {
    ($t:ty) => {
        fn value_eq(a: &$t, b: &$t) -> bool {
            // Use the 'autoref specialization' trick (https://github.com/dtolnay/case-studies/tree/master/autoref-specialization)
            // to compare values if possible and panic if not. Panicking is safe here because
            // this method is only called for possibly mutated values, and values can only be
            // mutated if they impl `PartialEq`.
            #[allow(dead_code)]
            trait HasEq {
                fn veq(&self, other: &Self) -> bool;
            }
            #[allow(dead_code)]
            trait MaybeEq {
                fn veq(&self, other: Self) -> bool;
            }
            impl<T: ::core::cmp::PartialEq> HasEq for T {
                fn veq(&self, other: &Self) -> bool {
                    self == other
                }
            }
            impl<T> MaybeEq for &T {
                fn veq(&self, _other: Self) -> bool {
                    ::core::unreachable!();
                }
            }

            a.veq(b)
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! notification_value_type {
    ($value_ty:ty; notify(Clone)) => {
        $value_ty
    };
    ($value_ty:ty $(; notify(None))?) => {
        ()
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! notification_clone_value {
    ($value:ident; notify(Clone)) => {
        ::core::clone::Clone::clone($value)
    };
    ($value:ident $(; notify(None))?) => {
        ()
    };
}
#[doc(hidden)]
#[macro_export]
macro_rules! notification_value {
    ($value:ident; notify(Clone)) => {
        $value
    };
    ($value:ident $(; notify(None))?) => {
        if $value.is_some() {
            &::core::option::Option::Some(())
        } else {
            &::core::option::Option::None
        }
    };
}

#[cfg(test)]
mod test {
    use alloc::sync::Arc;

    #[test]
    fn single() {
        store!(
            kvs: {
                Foo(Box<u64>; "owner"; notify(Clone)),
                Bar(Arc<u64>; "owner"; notify(None)),
                Baz(&'static u64; "owner"),
                Qux(u64; "owner"),
            }
        );

        let store = KvStore::new();
        store.Foo.insert("owner", Box::new(42));
        assert_eq!(store.Foo.get("owner").unwrap(), Box::new(42));
    }

    #[test]
    fn table() {
        store!(tables: { Foo(&'static str => String; "owner"; notify(Clone)), Bar(u32 => Vec<String>; "owner")});

        let store = KvStore::new();

        store.Foo.insert("owner", "hello", "world".to_owned());
        assert_eq!(store.Foo.get("owner", "hello").unwrap(), "world");

        store
            .Bar
            .insert("owner", 5, vec!["boo".to_owned(), "bang".to_owned()]);
        assert_eq!(
            store.Bar.get("owner", &5).unwrap(),
            vec!["boo".to_owned(), "bang".to_owned()]
        );
    }

    #[test]
    fn send_and_sync() {
        fn require_send<T: Send>(_t: T) {}
        fn require_sync<T: Sync>(_t: T) {}

        store!(tables: { Foo(&'static str => String; "owner"; notify(Clone)), Bar(u32 => Vec<String>; "owner")});

        require_send(KvStore::new());
        require_sync(KvStore::new());
    }

    #[test]
    fn table_with_indexes() {
        #[derive(Clone, Debug)]
        pub struct BarT {
            a: String,
        }
        store!(
            tables: {
                Foo(&'static str => String; "owner"; index(len: usize = |v: &String| [v.len()])),
                Bar(u32 => BarT; "owner"; index(a: String; assert_unique)),
            }
        );

        let store = KvStore::new();
        store.Bar.insert(
            "owner",
            5,
            BarT {
                a: "hello".to_owned(),
            },
        );
        let value = store.Bar.indexes().a.get("owner", "hello").unwrap();
        assert_eq!(value.1.a, "hello");

        store.Foo.insert("owner", "foo", "hello".to_owned());
        let value = store.Foo.indexes().len.get("owner", &5).unwrap();
        assert_eq!(value, ("foo", "hello".to_owned()));
    }
}
