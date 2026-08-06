//! Traits and macros for defining the KvStore schema.

use std::{
    any::{Any, TypeId},
    hash::Hash,
};

use crate::{
    Owner,
    pub_sub::Subscriptions,
    storage::{Table, VersionedValue},
    transactions::TxnId,
};

/// A singleton key/value.
///
/// Prefer to use the macros in this module rather than this trait directly.
pub trait Singleton: Sized + 'static {
    /// The datum's owner.
    const OWNER: Owner;

    /// The type of the value.
    type Value: Any + Send + Sync;
    /// The type of the notification for this singleton (either `Self::Value` or `()`).
    type NotificationValue: Clone;
    /// The storage for this singleton KV.
    type Storage: GeneratedStorage;

    /// Get a clone of the value from `storage` if the singleton uses cloning for notification values,
    /// or `()` if not.
    fn get_cloned(storage: &Self::Storage, txn_id: TxnId) -> Option<Self::NotificationValue>;
    /// Get a reference to the field storing this singleton in `storage`.
    fn get_ref(storage: &Self::Storage) -> &VersionedValue<Option<Self::Value>>;
    /// Get a mutable reference to the field storing this singleton in `storage`.
    fn get_mut(storage: &mut Self::Storage) -> &mut VersionedValue<Option<Self::Value>>;
    /// Convert an optional reference to this singleton's value to it's notification value.
    fn notif_value(value: &Option<Self::Value>) -> &Option<Self::NotificationValue>;
    /// Create a notification from an event.
    fn make_notification(
        event: crate::SingletonEvent<Self, Self::NotificationValue>,
    ) -> <Self::Storage as GeneratedStorage>::Notification;
}

/// Describes tabular key/values in the store.
///
/// Prefer to use the macros in this module rather than this trait directly.
pub trait TableDesc: Sized + 'static {
    /// The name of the table.
    const NAME: &'static str;
    /// The table's owner.
    const OWNER: Owner;

    /// The type of the key.
    type Key: Hash + Eq + Clone;
    /// The type of the value.
    type Value: Any + Send + Sync;
    /// The type of the notification for this table (either `Self::Value` or `()`).
    type NotificationValue: Clone;
    /// The storage for the table.
    type Storage: GeneratedStorage;
    /// The storage type for keeping this table's indexes.
    type Indexes: IndexStorage<Self::Key, Self::Value>;

    /// Get a reference to the table in storage.
    fn get_table(storage: &Self::Storage) -> &Table<Self, Self::Indexes>;
    /// Get a mutable reference to the table in storage.
    fn get_table_mut(storage: &mut Self::Storage) -> &mut Table<Self, Self::Indexes>;

    /// Create a notification from an event.
    fn make_notification(
        event: crate::Event<Self, Self::Key, Self::NotificationValue>,
    ) -> <Self::Storage as GeneratedStorage>::Notification;
    /// Create a value for a notification, possibly by cloning `value`.
    fn clone_value_for_notification(value: &Self::Value) -> Self::NotificationValue;

    /// Compare two references to this table's value type, returns `true` if the value type impls
    /// `PartialEq` and the values are equal. **Panics** if `Self::Value` does not impl `PartialEq`.
    fn value_eq(a: &Self::Value, b: &Self::Value) -> bool;
}

/// Similar to `TableDesc::get_table_mut`, but allows for getting two different tables at one time.
///
/// SAFETY: A and B must represent distinct tables.
#[allow(clippy::type_complexity)]
pub(crate) fn get_two_tables_mut<
    Storage: GeneratedStorage,
    A: TableDesc<Storage = Storage> + Any,
    B: TableDesc<Storage = Storage> + Any,
>(
    storage: &mut Storage,
) -> (&mut Table<A, A::Indexes>, &mut Table<B, B::Indexes>) {
    debug_assert_ne!(TypeId::of::<A>(), TypeId::of::<B>());

    // SAFETY: `A` and `B` are different tables, so `get_table_mut` will return pointers to
    // different `Table` objects.
    let storage = storage as *mut _;
    let a = A::get_table_mut(unsafe { &mut *storage });
    let b = B::get_table_mut(unsafe { &mut *storage });
    (a, b)
}

/// Describes a table used as an index.
pub trait IndexDesc: TableDesc {
    /// The table which is indexed.
    type BaseTable: TableDesc<Storage = Self::Storage, Key = Self::Value>;
}

/// Operations on an index.
pub trait IndexStorage<K: Hash + Eq, V: Any + Send + Sync>: Default {
    /// Clear the whole index.
    fn clear(
        &mut self,
        txn_id: crate::transactions::TxnId,
        max_committed_id: crate::transactions::TxnId,
    );

    /// An item has been inserted into the index.
    fn on_insert<Q>(
        &mut self,
        key: &Q,
        value: &V,
        txn_id: crate::transactions::TxnId,
        max_committed_id: crate::transactions::TxnId,
    ) where
        K: std::borrow::Borrow<Q>,
        Q: ?Sized + std::hash::Hash + Eq + std::borrow::ToOwned<Owned = K>;

    /// An item has been removed from the index.
    fn on_remove(
        &mut self,
        value: &V,
        txn_id: crate::transactions::TxnId,
        max_committed_id: crate::transactions::TxnId,
    );
}

impl<K: Hash + Eq, V: Any + Send + Sync> IndexStorage<K, V> for () {
    fn clear(
        &mut self,
        _txn_id: crate::transactions::TxnId,
        _max_committed_id: crate::transactions::TxnId,
    ) {
    }

    fn on_insert<Q>(
        &mut self,
        _key: &Q,
        _value: &V,
        _id: crate::transactions::TxnId,
        _max_committed_id: crate::transactions::TxnId,
    ) where
        K: std::borrow::Borrow<Q>,
        Q: ?Sized + std::hash::Hash + Eq,
    {
    }

    fn on_remove(
        &mut self,
        _value: &V,
        _txn_id: crate::transactions::TxnId,
        _max_committed_id: crate::transactions::TxnId,
    ) {
    }
}

/// A storage implementation.
///
/// This should be considered a sealed trait and not implemented except by the macros in this module.
/// Unfortunately it has to be public because of macro visibility hygiene.
#[doc(hidden)]
pub trait GeneratedStorage: Default + Send + Sync {
    type Notification: Clone + Send + 'static;
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
/// `Name` is used as a type argument to KvStore methods to identify the table or singleton.
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
/// The syntax of an index is `index(field: Type(; assert_unique)?)` where `field` is the name of
/// a field in the value type of the base table and `Type` is the type of that field. You can
/// specify multiple indexes for each table, separated with a semicolon. E.g.,
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
/// This will create indexes on nodes for fields `a`, `b`, and `c`. `c`'s index key is
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
/// ## Notifications
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
            pub struct $sname;

            impl $crate::schema::Singleton for $sname {
                const OWNER: $crate::Owner = $sowner;
                type Value = $svalue_ty;
                type NotificationValue = $crate::notification_value_type!($svalue_ty $(; notify($snotif))?);
                type Storage = TableStorage;

                fn get_cloned(_storage: &Self::Storage, _txn_id: $crate::transactions::TxnId) -> Option<Self::NotificationValue> {
                    $crate::get_cloned_notification_value!($sname, _storage, _txn_id $(; notify($snotif))?)
                }

                fn get_ref(storage: &Self::Storage) -> &$crate::storage::VersionedValue<Option<Self::Value>> {
                    &storage.$sname
                }

                fn get_mut(storage: &mut Self::Storage) -> &mut $crate::storage::VersionedValue<Option<Self::Value>>{
                    &mut storage.$sname
                }

                fn notif_value(_value: &Option<Self::Value>) -> &Option<Self::NotificationValue> {
                    $crate::notification_value!(_value $(; notify($snotif))? )
                }

                fn make_notification(
                    event: $crate::SingletonEvent<Self, Self::NotificationValue>,
                ) -> <Self::Storage as $crate::schema::GeneratedStorage>::Notification {
                    Notification::$sname(event)
                }
            }
        )*)?
        $($(
            /// Describes a table in the KV store.
            #[derive(Default)]
            pub struct $name;

            impl $crate::schema::TableDesc for $name {
                const NAME: &'static str = stringify!($name);
                const OWNER: $crate::Owner = $owner;
                type Key = $key_ty;
                type Value = $value_ty;
                type NotificationValue = $crate::notification_value_type!($value_ty $(; notify($notif))?);
                type Storage = TableStorage;
                type Indexes = index::$name::Indexes;

                fn get_table(storage: &TableStorage) -> &$crate::storage::Table<Self, Self::Indexes> {
                    &storage.$name
                }
                fn get_table_mut(storage: &mut TableStorage) -> &mut $crate::storage::Table<Self, Self::Indexes> {
                    &mut storage.$name
                }

                fn make_notification(event: $crate::Event<Self, Self::Key, Self::NotificationValue>) -> <Self::Storage as $crate::schema::GeneratedStorage>::Notification {
                    Notification::$name(event)
                }
                fn clone_value_for_notification(_value: &Self::Value) -> Self::NotificationValue {
                    $crate::notification_clone_value!(_value $(; notify($notif))?)
                }

                $crate::value_eq!(Self::Value);
            }

            $(
                impl $crate::schema::TableDesc for index::$name::$field where $field_ty: Clone {
                    const NAME: &'static str = stringify!($name by $field);
                    const OWNER: $crate::Owner = $owner;
                    type Key = $field_ty;
                    type Value = $key_ty;
                    type NotificationValue = ();
                    type Storage = TableStorage;
                    type Indexes = ();

                    fn get_table(storage: &TableStorage) -> &$crate::storage::Table<Self, Self::Indexes> {
                        &storage.$name.indexes.$field
                    }
                    fn get_table_mut(storage: &mut TableStorage) -> &mut $crate::storage::Table<Self, Self::Indexes> {
                        &mut storage.$name.indexes.$field
                    }

                    fn make_notification(_: $crate::Event<Self, Self::Key, Self::NotificationValue>) -> <Self::Storage as $crate::schema::GeneratedStorage>::Notification {
                        unreachable!();
                    }
                    fn clone_value_for_notification(_value: &Self::Value) -> Self::NotificationValue {}

                    $crate::value_eq!(Self::Value);
                }

                impl $crate::schema::IndexDesc for index::$name::$field {
                    type BaseTable = $name;
                }
            )*
        )*)?

        /// Macro-generated storage for all data.
        #[derive(Default)]
        #[allow(non_snake_case)]
        pub struct TableStorage {
            $($($name: $crate::storage::Table<$name, index::$name::Indexes>,)*)?
            $($($sname: $crate::storage::VersionedValue<Option<$svalue_ty>>,)*)?
        }

        /// Macro-generated notification type, there is a variant for each table and singleton with
        /// the appropriate types (wrapping event types in `ts_kv_store`). For notifications which
        /// don't include a value (either by default or by opting-out using `notify(None)`, the value
        /// type is `()`.
        #[derive(Clone)]
        #[allow(unused)]
        pub enum Notification {
            $($($name($crate::Event<$name, <$name as $crate::schema::TableDesc>::Key, <$name as $crate::schema::TableDesc>::NotificationValue>),)*)?
            $($($sname($crate::SingletonEvent<$sname, <$sname as $crate::schema::Singleton>::NotificationValue>),)*)?
        }

        impl std::fmt::Debug for Notification {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                match self {
                    $($(Notification::$name(..) => write!(f, stringify!($name)),)*)?
                    $($(Notification::$sname(..) => write!(f, stringify!($sname)),)*)?
                }
            }
        }

        impl $crate::schema::GeneratedStorage for TableStorage {
            type Notification = Notification;

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
                            && let Some(event) = self.$sname.modified_in_txn(_txn_id)
                        {
                            _subscriptions.collect_singleton_events::<$sname>(_notifications, <$sname as $crate::schema::Singleton>::notif_value(event));
                        }
                    )*
                )?
                $(
                    $(
                        let events = self.$name.commit_txn(_txn_id, _subscriptions.has_subscribers::<$name>());
                        if !events.is_empty() {
                            _subscriptions.collect_events::<$name>(_notifications, events);
                        }
                        $(self.$name.indexes.$field.commit_txn(_txn_id, false);)*
                    )*
                )?

                Ok(())
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
        }

        pub mod index {
            $($(
                #[allow(non_snake_case)]
                pub mod $name {
                    $(
                        #[allow(non_camel_case_types)]
                        pub struct $field;
                    )*

                    #[derive(Default)]
                    pub struct Indexes {
                        $(
                            pub $field: $crate::storage::Table<$field, ()>,
                        )*
                    }
                }
            )*)?
        }

        $($(
            impl index::$name::Indexes {
                $(
                    fn $field(val: &$value_ty) -> impl IntoIterator<Item = $field_ty> {
                        ($crate::get_index_fn!($value_ty, $field $(, $get_idx)?))(val)
                    }
                )*
            }

            impl $crate::schema::IndexStorage<$key_ty, $value_ty> for index::$name::Indexes {
                fn clear(&mut self, _txn_id: $crate::transactions::TxnId, _max_committed_id: $crate::transactions::TxnId) {
                    $(
                        self.$field.clear(_txn_id, _max_committed_id);
                    )*
                }

                $crate::on_insert!($name, $key_ty, $value_ty, $(index($field: $field_ty $(; $unique)?),)*);

                fn on_remove(&mut self, _value: &$value_ty, _txn_id: $crate::transactions::TxnId, _max_committed_id: $crate::transactions::TxnId) {
                    $({
                        for value in index::$name::Indexes::$field(_value) {
                            self.$field.remove(&value, _txn_id, _max_committed_id);
                        }
                    })*
                }
            }
        )*)?

        /// A key-value store.
        ///
        /// See [`$crate::KvStore`] (which this type implicitly derefences to) for full docs.
        pub struct KvStore($crate::KvStore<TableStorage>);

        impl KvStore {
            /// Create a new, empty KV store as described by the schema macros.
            ///
            /// The store has a no-op notifier, so subscribers are never notified of changes.
            #[allow(dead_code, clippy::new_without_default)]
            pub fn new() -> Self {
                // The store only holds a weak reference to its notifier, so downgrading a
                // throwaway no-op notifier leaves the store with a dead weak reference. Upgrading it
                // always fails, which means no notifications are ever sent.
                Self::with_notifier(std::sync::Arc::downgrade(&$crate::NoOpNotifier::new()))
            }

            /// Create a new, empty KV store as described by the schema macros, which sends
            /// notifications of changes to `notifier`.
            ///
            /// The store keeps only a weak reference to `notifier`, so the caller is responsible for
            /// keeping the notifier alive (e.g. via the subscribers it hands out). Once the last
            /// strong reference is dropped the store stops sending notifications.
            pub fn with_notifier(notifier: std::sync::Weak<dyn $crate::Notifier<Notification = <TableStorage as $crate::schema::GeneratedStorage>::Notification>>) -> Self {
                KvStore($crate::KvStore::new_with_storage(std::sync::RwLock::new($crate::storage::Storage::new(notifier))))
            }
        }

        impl std::ops::Deref for KvStore {
            type Target = $crate::KvStore<TableStorage>;

            fn deref(&self) -> &Self::Target {
                &self.0
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! get_index_fn {
    ($value_ty:ty, $field:ident) => {
        |value: &$value_ty| [value.$field.clone()]
    };
    ($value_ty:ty, $field:ident, $get_idx:expr) => {
        $get_idx
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! on_insert {
    ($name: ident, $key_ty: ty, $value_ty: ty, $(index($field: ident: $field_ty: ty $(; $unique:ident)?),)*) => {
        fn on_insert<Q>(&mut self, _key: &Q, _value: &$value_ty, _txn_id: $crate::transactions::TxnId, _max_committed_id: $crate::transactions::TxnId)
        where
            $key_ty: std::borrow::Borrow<Q>,
            Q: ?Sized + std::hash::Hash + Eq + std::borrow::ToOwned<Owned = $key_ty>
        {
            $(
                $crate::on_insert_each!($name, $field: $field_ty; (self, _key, _value, _txn_id, _max_committed_id) $(; $unique)?);
            )*
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! on_insert_each {
    (
        $name:ident,
        $field:ident :
        $field_ty:ty;
        ($self:ident, $key:ident, $value:ident, $txn_id:ident, $max_committed_id:ident); assert_unique
    ) => {
        for index_key in index::$name::Indexes::$field($value) {
            let unique = $self.$field.get::<$field_ty>(&index_key, $txn_id).is_none();
            assert!(
                unique,
                "Index key is non-unique for index `{}` of table `{}`",
                stringify!($field),
                stringify!($name),
            );
            $self
                .$field
                .insert(index_key, $key.to_owned(), $txn_id, $max_committed_id);
        }
    };
    (
        $name:ident,
        $field:ident :
        $field_ty:ty;
        ($self:ident, $key:ident, $value:ident, $txn_id:ident, $max_committed_id:ident)
    ) => {
        for index_key in index::$name::Indexes::$field($value) {
            let unique = $self.$field.get::<$field_ty>(&index_key, $txn_id).is_none();
            if unique {
                $self
                    .$field
                    .insert(index_key, $key.to_owned(), $txn_id, $max_committed_id);
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
            impl<T: core::cmp::PartialEq> HasEq for T {
                fn veq(&self, other: &Self) -> bool {
                    self == other
                }
            }
            impl<T> MaybeEq for &T {
                fn veq(&self, _other: Self) -> bool {
                    unreachable!();
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
        $value.clone()
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
        if $value.is_some() { &Some(()) } else { &None }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! get_cloned_notification_value {
    ($name:ident, $storage:ident, $txn_id:ident; notify(Clone)) => {
        $storage.$name.get($txn_id)?.as_ref().map(|v| v.clone())
    };
    ($name:ident, $storage:ident, $txn_id:ident $(; notify(None))?) => {
        $storage.$name.get($txn_id)?.as_ref().map(|_| ())
    };
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

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
        store.insert::<Foo>("owner", Box::new(42));
        assert_eq!(store.get::<Foo>("owner").unwrap(), Box::new(42));
    }

    #[test]
    fn table() {
        store!(tables: { Foo(&'static str => String; "owner"; notify(Clone)), Bar(u32 => Vec<String>; "owner")});

        let store = KvStore::new();

        store
            .table::<Foo>("owner")
            .insert("hello", "world".to_owned());
        assert_eq!(store.table::<Foo>("owner").get("hello").unwrap(), "world");

        store
            .table::<Bar>("owner")
            .insert(5, vec!["boo".to_owned(), "bang".to_owned()]);
        assert_eq!(
            store.table::<Bar>("owner").get(&5).unwrap(),
            vec!["boo".to_owned(), "bang".to_owned()]
        );
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
        store.table::<Bar>("owner").insert(
            5,
            BarT {
                a: "hello".to_owned(),
            },
        );
        let value = store
            .table_by::<index::Bar::a>("owner")
            .get("hello")
            .unwrap();
        assert_eq!(value.1.a, "hello");

        store
            .table::<Foo>("owner")
            .insert("foo", "hello".to_owned());
        let value = store.table_by::<index::Foo::len>("owner").get(&5).unwrap();
        assert_eq!(value, ("foo", "hello".to_owned()));
    }
}
