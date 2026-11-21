/// Declare the schema of a key/value store. Generates the store itself with the specified tables and
/// singletons.
///
/// The syntax is:
/// ```ignore
/// store!(
///   kvs: { Name(ValueType; owner; notify(None|Clone)?; default?),* }
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
/// # const GRAPH_OWNER: ts_kv_store::Owner = ts_kv_store::Owner("foo");
/// # const NODES_OWNER: ts_kv_store::Owner = ts_kv_store::Owner("bar");
/// # const EDGES_OWNER: ts_kv_store::Owner = ts_kv_store::Owner("baz");
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
/// # fn main() {}
/// ```
///
/// # Singelton defaults
///
/// By default (ha!), a singleton is optional: reading it returns an `Option`, and deleting it
/// leaves it with no value (`None`). A singleton declared with `default` always has a value, which is
/// initially `ValueType::default()`: reading it returns the bare value (not an `Option`), and
/// deleting it resets it to `ValueType::default()`. To use `default`, the type of the value
/// must implement `Default`. E.g.,
///
/// ```rust
/// # use ts_kv_store::store;
/// # const OWNER: ts_kv_store::Owner = ts_kv_store::Owner("foo");
/// store!(
///   kvs: {
///     Count(u64; OWNER; default),
///     Name(String; OWNER; notify(Clone); default),
///   }
/// );
///
/// fn main() {
///     let store = KvStore::new();
///     assert_eq!(store.Count.get(OWNER), 0);
///     store.Count.insert(OWNER, 42);
///     assert_eq!(store.Count.get(OWNER), 42);
///     store.Count.delete(OWNER);
///     assert_eq!(store.Count.get(OWNER), 0);
/// }
/// ```
///
/// # Indexes
///
/// The syntax of an index is `index(field: Type (= closure)? (; (poison | assert | replace | ignore | multi | custom(Impl) | custom_multi(Impl)))?)`
/// where `field` is the name of the index and `Type` is the type of the index key. By default,
/// `field` is also the name of a field in the value type of the base table, whose value is used as
/// the index key; `closure` can be specified to compute the index key instead. You can specify
/// multiple indexes for each table, separated with a semicolon. E.g.,
///
/// ```rust
/// # use ts_kv_store::store;
/// # const NODES_OWNER: ts_kv_store::Owner = ts_kv_store::Owner("foo");
/// # pub struct Node { a: u32, b: String }
/// store!(
///   tables: {
///     Nodes(
///       &'static str => Node;
///       NODES_OWNER;
///       index(a: u32);
///       index(b: String; assert);
///       index(c: String = |node: &Node| [format!("{}-{}", node.a, node.b)]);
///     )
///   }
/// );
/// # fn main() {}
/// ```
///
/// This will create indexes `a`, `b`, and `c` on nodes. `c`'s index key is
/// computed by the specified closure, which is expected to return
/// `impl IntoIterator<Item = I>` (where `I` is the index key type), for example an `Option<I>` for
/// zero or one index keys per value.
///
/// The final keyword defines the behaviour if multiple rows in the base table have the same key in
/// the index:
///
/// - `poison` (the default behaviour): the index will be 'poisoned' and accessing the index or trying
///   to commit a transaction where an index is poisoned will return an error (`NonUniqueIndexKey`).
/// - `assert`: panics immediately.
/// - `replace`: the old entry in the index is replaced with the new entry.
/// - `ignore`: the old entry in the index is preserved and the new entry is ignored.
/// - `multi`: all entries are kept and accessing the index may return multiple values (multi-indexes
///   have a different API to other indexes).
///
/// Note that if an index has `replace` or `ignore` behaviour, then it is possible to corrupt the
/// index by removing entries or mutating the indexed field.
///
/// ## Custom indexes
///
/// A custom index is declared with `index(field: Type (= closure)?; custom(Impl))`, where `Impl` is
/// a concrete type which implements [`UniqueIndexRead<Type, KeyType>`](crate::schema::index::UniqueIndexRead). `Impl` stores the
/// index and decides how non-unique index keys are handled. Custom indexes have the same user-facing
/// API as unique indexes.
///
/// A custom multi-index is declared with `custom_multi(Impl)`, where `Impl` implements
/// [`MultiIndexRead<Type, KeyType>`](crate::schema::index::MultiIndexRead). Custom multi-indexes have the same
/// user-facing API as `multi` indexes.
///
/// Both kinds of custom index must also implement
/// [`IndexMaintenance<Type, KeyType>`](crate::schema::index::IndexMaintenance). To support
/// iteration (`iter`, `keys`, and `IntoIterator`), they must implement
/// [`UniqueIndexIterable`](crate::schema::index::UniqueIndexIterable) or
/// [`MultiIndexIterable`](crate::schema::index::MultiIndexIterable), respectively.
///
/// # Notifications
///
/// The `notify(...)` argument is used to control notifications about the table or singleton. Accepted
/// values are `Clone` and `None`. The default is `None`.
///
/// The `None` behaviour is that only keys are sent in notifications. The `Clone` behaviour is
/// that values are cloned and included in notifications. This requires that the value type implements
/// the `Clone` trait.
///
/// A singleton declared with `default` always has a value, so it never gives a `Remove`
/// notification: deleting it is notified as an `Upsert` of the default value.
#[macro_export]
macro_rules! store {
    (
        // Singleton options are matched generically (as `; name` or `; name(arg)`), because
        // matching an optional `notify(...)` followed by an optional flag is ambiguous. Options are
        // checked by the `singleton_slot!` and `notification_*!` macros.
        $(kvs: { $($sname:ident($svalue_ty:ty; $sowner:expr $(; $sopt:ident $(($sarg:ident))?)*)),* $(,)? })?
        $(tables: { $(
            $name:ident (
                $key_ty:ty => $value_ty:ty;
                $owner:expr
                $(; index($field:ident: $field_ty:ty $(= $get_idx:expr)? $(; $unique:ident $(($cimpl:ty))?)?))*
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
                type Slot = $crate::singleton_slot!($svalue_ty $(; $sopt $(($sarg))?)*);
                type NotificationValue = $crate::notification_value_type!($svalue_ty $(; $sopt $(($sarg))?)*);

                fn get_ref(storage: &Self::Storage) -> &Self::Slot {
                    &storage.$sname
                }

                unsafe fn value_ptr(storage: *mut Self::Storage) -> *mut Self::Slot {
                    // SAFETY: `storage` is dereferenceable (by the caller's contract). This only
                    // computes a place, it does not create a reference to the storage.
                    unsafe { &raw mut (*storage).$sname }
                }

                fn notification_value(_value: &Self::Value) -> &Self::NotificationValue {
                    $crate::notification_value!(_value $(; $sopt $(($sarg))?)*)
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

            impl $crate::schema::TableDesc for $name {
                const NAME: &'static str = ::core::stringify!($name);
                type Key = $key_ty;
                type Value = $value_ty;
                type IndexStorage = index::$name::Storage;
            }

            // SAFETY: `table_ptr` points to the table's own field of `TableStorage`.
            unsafe impl $crate::schema::PrimaryTableDesc for $name {
                type NotificationValue = $crate::notification_value_type!($value_ty $(; notify($notif))?);

                fn get_table(storage: &TableStorage) -> &$crate::storage::Table<Self> {
                    &storage.$name
                }
                unsafe fn table_ptr(storage: *mut TableStorage) -> *mut $crate::storage::Table<Self> {
                    // SAFETY: `storage` is dereferenceable (by the caller's contract). This only
                    // computes a place, it does not create a reference to the storage.
                    unsafe { &raw mut (*storage).$name }
                }

                $crate::value_eq!(Self::Value);

                fn make_notification(event: $crate::Event<Self>) -> <Self::Storage as $crate::schema::GeneratedStorage>::Notification {
                    Notification::$name(event)
                }
                fn clone_value_for_notification(_value: &Self::Value) -> Self::NotificationValue {
                    $crate::notification_clone_value!(_value $(; notify($notif))?)
                }
            }

            impl $crate::schema::Indexable for $name {
                type Indexes = index::$name::Indexes;
                type TransactionIndexes<'guard, 'txn> = index::$name::TransactionIndexes<'guard, 'txn> where 'guard: 'txn;
                type RoTransactionIndexes<'guard, 'txn> = index::$name::RoTransactionIndexes<'txn, $crate::transactions::TransactionInner<'guard, TableStorage>> where 'guard: 'txn;
                type RoRoTransactionIndexes<'guard, 'txn> = index::$name::RoTransactionIndexes<'txn, $crate::storage::Storage<TableStorage>> where 'guard: 'txn;
            }

            $(

                impl $crate::schema::Desc for index::$name::$field {
                    const OWNER: $crate::Owner = $owner;
                    type Storage = TableStorage;
                }

                $crate::index_desc!($name, $field: $field_ty => $key_ty $(; $unique $(($cimpl))?)?);
            )*
        )*)?

        /// Macro-generated storage for all data.
        #[derive(::core::default::Default)]
        #[allow(non_snake_case)]
        pub struct TableStorage {
            $($($name: $crate::storage::Table<$name>,)*)?
            $($($sname: <$sname as $crate::schema::SingletonDesc>::Slot,)*)?
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

            fn commit_txn(
                &mut self,
                _txn_id: $crate::transactions::TxnId,
                _notifications: &mut $crate::Notifications<Notification>,
                _subscriptions: &$crate::pub_sub::Subscriptions<Self::Notification>,
            ) -> $crate::Result<()> {
                $(
                    $(
                        self.$name.check_txn_consistency(_txn_id)?;
                        $(<_ as $crate::schema::index::IndexMaintenance<$field_ty, $key_ty>>::check_consistent(&self.$name.indexes.$field, _txn_id)?;)*
                    )*
                )?
                $(
                    $(
                        if _subscriptions.has_singleton_subscribers::<$sname>()
                            && let ::core::option::Option::Some(change) = $crate::storage::SingletonSlot::change_in_txn(&self.$sname, _txn_id)
                        {
                            _subscriptions.collect_singleton_events::<$sname>(_notifications, change.map(<$sname as $crate::schema::SingletonDesc>::notification_value));
                        }
                    )*
                )?
                $(
                    $(
                        let events = self.$name.commit_primary_table(_txn_id, _subscriptions.has_subscribers::<$name>());
                        if !events.is_empty() {
                            _subscriptions.collect_events::<$name>(_notifications, events);
                        }
                        $(<_ as $crate::schema::index::IndexMaintenance<$field_ty, $key_ty>>::commit(&mut self.$name.indexes.$field, _txn_id);)*
                    )*
                )?

                ::core::result::Result::Ok(())
            }

            fn gc_txn(&mut self, _txn_id: $crate::transactions::TxnId) {
                $(
                    $(
                        // Indexes are only modified via their base table, so if the table is
                        // unmodified, so are its indexes.
                        if self.$name.gc_txn(_txn_id) {
                            $({
                                // The base table must already be rolled back, so that `rows` are the
                                // committed rows.
                                let (indexes, rows) = self.$name.indexes_and_rows(_txn_id);
                                <_ as $crate::schema::index::IndexMaintenance<$field_ty, $key_ty>>::rollback(
                                    &mut indexes.$field,
                                    _txn_id,
                                    rows.flat_map(|(k, v)| index::$name::Storage::$field(v).into_iter().map(move |ik| (ik, k))),
                                );
                            })*
                        }
                    )*
                )?
                $(
                    $(
                        $crate::storage::SingletonSlot::gc_txn(&mut self.$sname, _txn_id);
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
                            pub $field: <$field as $crate::schema::IndexDesc>::IndexStorage,
                        )*
                    }

                    /// Access to the table's indexes, with a field for each index.
                    ///
                    /// Returned by `Table::indexes`.
                    pub struct Indexes {
                        $(
                            #[allow(dead_code)]
                            pub $field: $crate::index_api_select!({
                                $crate::Index<$field>
                            } {
                                $crate::MultiIndex<$field>
                            } $(; $unique)?),
                        )*
                    }

                    /// Read/write access to the table's indexes within a transaction, with a
                    /// method for each index. Each method mutably borrows this struct, so only one
                    /// index can be used at a time.
                    ///
                    /// Returned by `TableTransaction::indexes`.
                    pub struct TransactionIndexes<'guard, 'txn> {
                        #[doc(hidden)]
                        pub(in super::super) __base:
                            &'txn mut $crate::TableTransaction<'guard, super::super::$name>,
                    }

                    /// Read-only access to the table's indexes within a transaction, with a field
                    /// for each index.
                    ///
                    /// Returned by `TableTransaction::ro_indexes` and `RoTableTransaction::indexes`.
                    pub struct RoTransactionIndexes<'txn, G> {
                        #[doc(hidden)]
                        pub(in super::super) __txn: ::core::marker::PhantomData<&'txn G>,
                        $(
                            #[allow(dead_code)]
                            pub $field: $crate::index_api_select!({
                                $crate::IndexGuard<'txn, $field, G>
                            } {
                                $crate::MultiIndexGuard<'txn, $field, G>
                            } $(; $unique)?),
                        )*
                    }
                }
            )*)?
        }

        $($(
            impl ::core::convert::From<($crate::__alloc::sync::Arc<$crate::KvStore<TableStorage>>, $crate::Owner)> for index::$name::Indexes {
                fn from((_store, _owner): ($crate::__alloc::sync::Arc<$crate::KvStore<TableStorage>>, $crate::Owner)) -> Self {
                    index::$name::Indexes {
                        $($field: $crate::index_api_select!({
                            $crate::Index::new
                        } {
                            $crate::MultiIndex::new
                        } $(; $unique)?)(::core::clone::Clone::clone(&_store), _owner),)*
                    }
                }
            }

            impl<'guard, 'txn> ::core::convert::From<&'txn mut $crate::TableTransaction<'guard, $name>>
                for index::$name::TransactionIndexes<'guard, 'txn>
            {
                fn from(base: &'txn mut $crate::TableTransaction<'guard, $name>) -> Self {
                    index::$name::TransactionIndexes { __base: base }
                }
            }

            impl<'guard, 'txn> index::$name::TransactionIndexes<'guard, 'txn> {
                $(
                    /// Read/write access to the table via this index.
                    #[allow(dead_code)]
                    pub fn $field(&mut self) -> $crate::index_api_select!({
                        $crate::IndexTransaction<'guard, '_, index::$name::$field>
                    } {
                        $crate::MultiIndexTransaction<'guard, '_, index::$name::$field>
                    } $(; $unique)?) {
                        $crate::index_api_select!({
                            $crate::IndexTransaction::new
                        } {
                            $crate::MultiIndexTransaction::new
                        } $(; $unique)?)(self.__base)
                    }
                )*
            }

            impl<'guard, 'txn> ::core::convert::From<&'txn $crate::TableTransaction<'guard, $name>>
                for index::$name::RoTransactionIndexes<'txn, $crate::transactions::TransactionInner<'guard, TableStorage>>
            {
                fn from(_base: &'txn $crate::TableTransaction<'guard, $name>) -> Self {
                    index::$name::RoTransactionIndexes {
                        __txn: ::core::marker::PhantomData,
                        $($field: ::core::convert::From::from(_base),)*
                    }
                }
            }

            impl<'guard, 'txn> ::core::convert::From<&'txn $crate::RoTableTransaction<'guard, $name>>
                for index::$name::RoTransactionIndexes<'txn, $crate::storage::Storage<TableStorage>>
            {
                fn from(_base: &'txn $crate::RoTableTransaction<'guard, $name>) -> Self {
                    index::$name::RoTransactionIndexes {
                        __txn: ::core::marker::PhantomData,
                        $($field: ::core::convert::From::from(_base),)*
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

            impl $crate::schema::index::IndexWrite<$key_ty, $value_ty> for index::$name::Storage {
                fn clear(&mut self, _txn_id: $crate::transactions::TxnId) {
                    $(<_ as $crate::schema::index::IndexMaintenance<$field_ty, $key_ty>>::clear(&mut self.$field, _txn_id);)*
                }

                fn on_insert<Q>(&mut self, _key: &Q, _value: &$value_ty, _txn_id: $crate::transactions::TxnId)
                where
                    $key_ty: ::core::borrow::Borrow<Q>,
                    Q: ?::core::marker::Sized + ::core::hash::Hash + ::core::cmp::Eq + $crate::__alloc::borrow::ToOwned<Owned = $key_ty>
                {
                    $({
                        for index_key in index::$name::Storage::$field(_value) {
                            <_ as $crate::schema::index::IndexMaintenance<$field_ty, $key_ty>>::insert(&mut self.$field, index_key, $crate::__alloc::borrow::ToOwned::to_owned(_key), _txn_id);
                        }
                    })*
                }

                fn on_remove<Q>(&mut self, _key: &Q, _value: &$value_ty, _txn_id: $crate::transactions::TxnId)
                where
                    $key_ty: ::core::borrow::Borrow<Q>,
                    Q: ?::core::marker::Sized + ::core::hash::Hash + ::core::cmp::Eq,
                {
                    $({
                        for index_key in index::$name::Storage::$field(_value) {
                            <_ as $crate::schema::index::IndexMaintenance<$field_ty, $key_ty>>::remove(&mut self.$field, &index_key, _key, _txn_id);
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
            $($(#[allow(dead_code)] pub $sname: $crate::singleton_type!(Singleton, DefaultSingleton, [$sname] $(; $sopt $(($sarg))?)*),)*)?
        }

        impl KvStore {
            /// Create a new, empty KV store as described by the schema macros.
            ///
            /// The store has no notifier, so it does not support subscriptions: subscribing returns
            /// `ts_kv_store::SubscriptionError::MissingNotifier`.
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
                    $($($sname: <$crate::singleton_type!(SingletonWithOwner, DefaultSingletonWithOwner, [$sname] $(; $sopt $(($sarg))?)*)>::new(::core::clone::Clone::clone(&self.__store), owner),)*)?
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
                    $($($sname: <$crate::singleton_type!(Singleton, DefaultSingleton, [$sname] $(; $sopt $(($sarg))?)*)>::new(::core::clone::Clone::clone(&store)),)*)?
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
            $($(#[allow(dead_code)] pub $sname: $crate::singleton_type!(SingletonWithOwner, DefaultSingletonWithOwner, [$sname] $(; $sopt $(($sarg))?)*),)*)?
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
            /// `ts_kv_store::SubscriptionError::UnknownSubscriber`). Unsubscribing any of its
            /// subscriptions is harmless but pointless.
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
            ) -> $crate::SubscriptionResult {
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
            $($(pub $sname: $crate::singleton_type!(SingletonTransaction, DefaultSingletonTransaction, ['a, $sname] $(; $sopt $(($sarg))?)*),)*)?
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
                        $sname: unsafe { <$crate::singleton_type!(SingletonTransaction, DefaultSingletonTransaction, ['a, $sname] $(; $sopt $(($sarg))?)*)>::new(::core::clone::Clone::clone(&store_txn)) },
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
            $($(pub $sname: $crate::singleton_type!(RoSingletonTransaction, RoDefaultSingletonTransaction, ['a, $sname] $(; $sopt $(($sarg))?)*),)*)?
        }

        #[allow(dead_code)]
        impl<'a> RoTransaction<'a> {
            fn new(store_txn: $crate::RoTransaction<'a, TableStorage>) -> Self {
                let store_txn = $crate::__alloc::rc::Rc::new(store_txn);

                RoTransaction {
                    $($($name: $crate::RoTableTransaction::new(::core::clone::Clone::clone(&store_txn)),)*)?
                    $($($sname: <$crate::singleton_type!(RoSingletonTransaction, RoDefaultSingletonTransaction, ['a, $sname] $(; $sopt $(($sarg))?)*)>::new(::core::clone::Clone::clone(&store_txn)),)*)?

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

/// Expands to the first group of tokens for an index with the unique index API, or the second for
/// an index with the multi-index API.
#[doc(hidden)]
#[macro_export]
macro_rules! index_api_select {
    ({ $($u:tt)* } { $($m:tt)* }; multi) => { $($m)* };
    ({ $($u:tt)* } { $($m:tt)* }; custom_multi) => { $($m)* };
    ({ $($u:tt)* } { $($m:tt)* } $(; $kind:ident)?) => { $($u)* };
}

/// Implements `TableDesc` for an index stored as a table.
#[doc(hidden)]
#[macro_export]
macro_rules! index_table_desc {
    ($name:ident, $field:ident : $field_ty:ty => $value_ty:ty) => {
        impl $crate::schema::TableDesc for index::$name::$field {
            const NAME: &'static str = ::core::stringify!($name by $field);
            type Key = $field_ty;
            type Value = $value_ty;
            type IndexStorage = ();
        }
    };
}

/// Implements `IndexDesc` (and `TableDesc` if the index is stored as a table) for an index of the
/// table `$name`, whose key type is `$key_ty`.
#[doc(hidden)]
#[macro_export]
macro_rules! index_desc {
    (@impl $name:ident, $field:ident : $field_ty:ty => $index_ty:ty) => {
        // SAFETY: `index_ptr` points to the index's own field of its base table's `indexes`.
        unsafe impl $crate::schema::IndexDesc for index::$name::$field {
            type Key = $field_ty;
            type BaseTable = $name;
            type IndexStorage = $index_ty;

            fn get_index(storage: &TableStorage) -> &Self::IndexStorage {
                &storage.$name.indexes.$field
            }
            unsafe fn index_ptr(storage: *mut TableStorage) -> *mut Self::IndexStorage {
                // SAFETY: `storage` is dereferenceable (by the caller's contract). This only
                // computes a place, it does not create a reference to the storage or the base
                // table.
                unsafe { &raw mut (*storage).$name.indexes.$field }
            }
        }
    };
    ($name:ident, $field:ident : $field_ty:ty => $key_ty:ty; custom($cimpl:ty)) => {
        $crate::index_desc!(@impl $name, $field: $field_ty => $cimpl);
    };
    ($name:ident, $field:ident : $field_ty:ty => $key_ty:ty; custom_multi($cimpl:ty)) => {
        $crate::index_desc!(@impl $name, $field: $field_ty => $cimpl);
    };
    ($name:ident, $field:ident : $field_ty:ty => $key_ty:ty; multi) => {
        $crate::index_table_desc!($name, $field: $field_ty => $crate::__alloc::vec::Vec<$key_ty>);
        $crate::index_desc!(@impl $name, $field: $field_ty => $crate::storage::Table<Self>);
    };
    ($name:ident, $field:ident : $field_ty:ty => $key_ty:ty; $policy:ident) => {
        $crate::index_table_desc!($name, $field: $field_ty => $key_ty);
        $crate::index_desc!(@impl $name, $field: $field_ty => $crate::storage::UniqueIndex<Self, $crate::storage::policy::$policy>);
    };
    ($name:ident, $field:ident : $field_ty:ty => $key_ty:ty) => {
        $crate::index_desc!($name, $field: $field_ty => $key_ty; poison);
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
macro_rules! singleton_slot {
    ($value_ty:ty $(; notify($notif:ident))?) => {
        $crate::storage::VersionedValue<::core::option::Option<$value_ty>>
    };
    ($value_ty:ty $(; notify($notif:ident))?; default) => {
        $crate::storage::DefaultValue<$value_ty>
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! singleton_type {
    ($optional:ident, $default:ident, [$($args:tt)*] $(; notify($notif:ident))?) => {
        $crate::$optional<$($args)*>
    };
    ($optional:ident, $default:ident, [$($args:tt)*] $(; notify($notif:ident))?; default) => {
        $crate::$default<$($args)*>
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! notification_value_type {
    ($value_ty:ty; notify(Clone) $(; default)?) => {
        $value_ty
    };
    ($value_ty:ty $(; notify(None))? $(; default)?) => {
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
    ($value:ident; notify(Clone) $(; default)?) => {
        $value
    };
    ($value:ident $(; notify(None))? $(; default)?) => {
        &()
    };
}
