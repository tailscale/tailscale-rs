//! Traits and macros for defining the KvStore schema.

use std::{
    any::{Any, TypeId},
    hash::Hash,
    sync::Arc,
};

use crate::{
    Owner,
    storage::{SinValue, Table, VersionedValue},
    transactions::TxnId,
};

/// A singleton key/value.
///
/// Prefer to use the macros in this module rather than this trait directly.
pub trait Singleton: 'static {
    /// The datum's owner.
    const OWNER: Owner;

    /// The type of the value.
    type Value: Any + Send + Sync;
    /// The type used to initialize and access the value. For values stored as `Arc`s this should be
    /// `Arc<Self::Value>`, for values stored by reference, this should be `&'static Self::Value`, and
    /// for other types, it should be the same as `Self::Value`.
    type ArgValue;
    /// The storage for this singleton KV.
    type Storage: GeneratedStorage;

    /// Unwrap a `SinValue` into a typed value.
    ///
    /// Panics if `value` is an unexpected variant.
    fn from_value(value: SinValue) -> Self::ArgValue;
    /// Unwrap a reference to a `SinValue` into a reference to a typed value.
    ///
    /// Panics if `value` is an unexpected variant.
    fn from_value_ref(value: &SinValue) -> &Self::Value;
    /// Wrap a typed value into a `SinValue`.
    fn to_value(value: Self::ArgValue) -> SinValue;
    /// Get a reference to the field storing this singleton in `storage`.
    fn field_ref(storage: &Self::Storage) -> &VersionedValue<SinValue>;
    /// Get a mutable reference to the field storing this singleton in `storage`.
    fn field_ref_mut(storage: &mut Self::Storage) -> &mut VersionedValue<SinValue>;
}

/// A singleton key/value which is store as an `Arc`.
///
/// Implementing this trait for non-`Arc` values will cause [`crate::KvStore::get_arc`] to panic (but is
/// not unsafe).
///
/// Prefer to use the macros in this module rather than this trait directly.
pub trait ArcSingleton: Singleton {
    /// Unwrap a reference to a `SinValue` into an `Arc` reference to a typed value.
    ///
    /// Panics if `value` is an unexpected variant.
    fn from_value_arc(value: &SinValue) -> Arc<Self::Value> {
        match value {
            SinValue::Arc(a) => a.clone().downcast().unwrap(),
            _ => unreachable!(),
        }
    }
}

/// Mark a singleton value as mutable (i.e., the value in the store is unique).
///
/// Prefer to use the macros in this module rather than this trait directly.
pub trait MutSingleton: Singleton {
    /// Unwrap a mutable reference to a `SinValue` into a mutable reference to a typed value.
    ///
    /// Panics if `value` is an unexpected variant.
    fn from_value_mut(value: &mut SinValue) -> &mut Self::Value;
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
    /// The storage for the table.
    type Storage: GeneratedStorage;
    /// The storage type for keeping this table's indexes.
    type Indexes: IndexStorage<Self::Key, Self::Value>;

    /// Get a reference to the table in storage.
    fn get_table(storage: &Self::Storage) -> &Table<Self, Self::Indexes>;
    /// Get a mutable reference to the table in storage.
    fn get_table_mut(storage: &mut Self::Storage) -> &mut Table<Self, Self::Indexes>;
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
pub trait GeneratedStorage: Default {
    /// Commit a transaction by applying all tables' transaction state to their permanent data.
    ///
    /// This operation must be atomic. I.e., it will only fail without any tables committed, and if it
    /// succeeds, then all masks have committed.
    fn commit_txn(&mut self, txn_id: TxnId) -> crate::Result<()>;

    /// Delete any uncommitted per-transaction state associated with `txn_id` held in tables.
    fn gc_txn(&mut self, txn_id: TxnId);
}

/// Declare the schema of a key/value store. Generates the store itself with the specified tables and
/// singletons.
///
/// The syntax is `store!(kvs: { Name(ValueKind; owner),* } tables: { Name(KeyType => ValueType; owner; indexes?),* })`,
/// where `Name` is an identifier to name the table or singleton (in which case it is also the key),
/// `KeyType` and `ValueType` are types, `ValueKind` is `u64 | ValueType as (Box | Arc | Ref)`.
/// `owner` is an expression which evaluates to an `Owner`. `Name` is used as a type argument to
/// KvStore methods to identify the table or singletone.
///
/// The storage kinds for singleton values are:
///
/// - `u64` a `u64` stored inline.
/// - `Box` a value with type `Box<ValueType>`.
/// - `Arc` a value with type `Arc<ValueType>`.
/// - `Ref` a value with type `&'static ValueType`.
///
/// # Example:
///
/// ```rust
/// # use ts_kv_store::store;
/// # const GRAPH_OWNER: ts_kv_store::Owner = "foo";
/// # const NODES_OWNER: ts_kv_store::Owner = "bar";
/// # const EDGES_OWNER: ts_kv_store::Owner = "baz";
/// # pub struct Node;
/// # pub struct Gid;
/// # pub trait Edge {}
/// store!(
///   kvs: {
///     GraphId(Gid as Arc; GRAPH_OWNER),
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
#[macro_export]
macro_rules! store {
    (
        $(kvs: { $($sname: ident $sbody: tt),* $(,)? })?
        $(tables: { $(
            $name: ident (
                $key_ty: ty => $value_ty: ty;
                $owner: expr
                $(; index($field: ident: $field_ty: ty $(= $get_idx: expr)? $(; $unique:ident)?))* $(;)?
            )
        ),* $(,)? })?
    ) => {
        $($($crate::singleton!($sname $sbody, TableStorage);)*)?
        $($(
            /// Describes a table in the KV store.
            #[derive(Default)]
            pub struct $name;

            impl $crate::schema::TableDesc for $name {
                const NAME: &'static str = stringify!($name);
                const OWNER: $crate::Owner = $owner;
                type Key = $key_ty;
                type Value = $value_ty;
                type Storage = TableStorage;
                type Indexes = index::$name::Indexes;

                fn get_table(storage: &TableStorage) -> &$crate::storage::Table<Self, Self::Indexes> {
                    &storage.$name
                }
                fn get_table_mut(storage: &mut TableStorage) -> &mut $crate::storage::Table<Self, Self::Indexes> {
                    &mut storage.$name
                }
            }

            $(
                impl $crate::schema::TableDesc for index::$name::$field where $field_ty: Clone {
                    const NAME: &'static str = stringify!($name by $field);
                    const OWNER: $crate::Owner = $owner;
                    type Key = $field_ty;
                    type Value = $key_ty;
                    type Storage = TableStorage;
                    type Indexes = ();

                    fn get_table(storage: &TableStorage) -> &$crate::storage::Table<Self, Self::Indexes> {
                        &storage.$name.indexes.$field
                    }
                    fn get_table_mut(storage: &mut TableStorage) -> &mut $crate::storage::Table<Self, Self::Indexes> {
                        &mut storage.$name.indexes.$field
                    }
                }

                impl $crate::schema::IndexDesc for index::$name::$field {
                    type BaseTable = $name;
                }
            )*
        )*)?

        /// Macro-generated storage for all tabular data.
        #[derive(Default)]
        #[allow(non_snake_case)]
        pub struct TableStorage {
            $($($name: $crate::storage::Table<$name, index::$name::Indexes>,)*)?
            $($($sname: $crate::storage::VersionedValue<$crate::storage::SinValue>,)*)?
        }

        impl $crate::schema::GeneratedStorage for TableStorage {
            fn commit_txn(&mut self, _txn_id: $crate::transactions::TxnId) -> $crate::Result<()> {
                $(
                    $(
                        self.$name.check_txn_consistency(_txn_id)?;
                        $(self.$name.indexes.$field.check_txn_consistency(_txn_id)?;)*
                    )*
                    $(
                        self.$name.commit_txn(_txn_id);
                        $(self.$name.indexes.$field.commit_txn(_txn_id);)*
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
            pub fn new() -> Self {
                KvStore($crate::KvStore::new_with_storage(std::sync::RwLock::new($crate::storage::Storage::new())))
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
macro_rules! singleton {
    ($name:ident(u64; $owner:expr), $storage:ident) => {
        $crate::singleton_types!($name(u64, u64, U64), $owner, $storage);

        impl $crate::schema::MutSingleton for $name {
            fn from_value_mut(value: &mut $crate::storage::SinValue) -> &mut Self::Value {
                match value {
                    $crate::match_helper_lhs!(U64, v) => $crate::match_helper_rhs_mut!(U64, v),
                    _ => unreachable!(),
                }
            }
        }
    };
    ($name:ident($value_ty:ty as Box; $owner:expr), $storage:ident) => {
        $crate::singleton_types!($name($value_ty, $value_ty, Box), $owner, $storage);

        impl $crate::schema::MutSingleton for $name {
            fn from_value_mut(value: &mut $crate::storage::SinValue) -> &mut Self::Value {
                match value {
                    $crate::match_helper_lhs!(Box, v) => $crate::match_helper_rhs_mut!(Box, v),
                    _ => unreachable!(),
                }
            }
        }
    };
    ($name:ident($value_ty:ty as Arc; $owner:expr), $storage:ident) => {
        $crate::singleton_types!(
            $name($value_ty, std::sync::Arc<$value_ty>, Arc),
            $owner,
            $storage
        );

        impl $crate::schema::ArcSingleton for $name {}
    };
    ($name:ident($value_ty:ty as Ref; $owner:expr), $storage:ident) => {
        $crate::singleton_types!($name($value_ty, &'static $value_ty, Ref), $owner, $storage);
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! singleton_types {
    ($name:ident($value_ty:ty, $arg_value_ty:ty, $variant:ident), $owner:expr, $storage:ident) => {
        /// Describes a singleton in the KV store.
        #[allow(non_camel_case_types)]
        pub struct $name;

        impl $crate::schema::Singleton for $name {
            const OWNER: $crate::Owner = $owner;
            type Value = $value_ty;
            type ArgValue = $arg_value_ty;
            type Storage = $storage;

            fn from_value(value: $crate::storage::SinValue) -> Self::ArgValue {
                match value {
                    $crate::match_helper_lhs!($variant, v) => {
                        $crate::match_helper_rhs!($variant, v)
                    }
                    _ => unreachable!(),
                }
            }

            fn from_value_ref(value: &$crate::storage::SinValue) -> &Self::Value {
                match value {
                    $crate::match_helper_lhs!($variant, v) => {
                        $crate::match_helper_rhs_ref!($variant, v)
                    }
                    _ => unreachable!(),
                }
            }

            fn to_value(value: Self::ArgValue) -> $crate::storage::SinValue {
                $crate::init_helper!($variant, value)
            }

            fn field_ref(
                storage: &Self::Storage,
            ) -> &$crate::storage::VersionedValue<$crate::storage::SinValue> {
                &storage.$name
            }

            fn field_ref_mut(
                storage: &mut Self::Storage,
            ) -> &mut $crate::storage::VersionedValue<$crate::storage::SinValue> {
                &mut storage.$name
            }
        }
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! init_helper {
    (U64, $value:ident) => {
        $crate::storage::SinValue::U64($value)
    };
    (Box, $value:ident) => {
        $crate::storage::SinValue::Box(
            std::boxed::Box::new($value) as Box<dyn std::any::Any + Send + Sync>
        )
    };
    (Arc, $value:ident) => {
        $crate::storage::SinValue::Arc(
            $value.clone() as std::sync::Arc<dyn std::any::Any + Send + Sync>
        )
    };
    (Ref, $value:ident) => {
        $crate::storage::SinValue::Ref($value as &'static (dyn std::any::Any + Send + Sync))
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! match_helper_lhs {
    (U64, $value:ident) => {
        $crate::storage::SinValue::U64($value)
    };
    ($variant:ident, $value:ident) => {
        $crate::storage::SinValue::$variant($value)
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! match_helper_rhs {
    (U64, $value:ident) => {
        $value
    };
    (Box, $value:ident) => {
        *$value.downcast().unwrap()
    };
    (Arc, $value:ident) => {
        $value.downcast().unwrap()
    };
    (Ref, $value:ident) => {
        $value.downcast_ref().unwrap()
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! match_helper_rhs_ref {
    (U64, $value:ident) => {
        $value
    };
    ($variant:ident, $value:ident) => {
        $value.downcast_ref().unwrap()
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! match_helper_rhs_mut {
    (U64, $value:ident) => {
        $value
    };
    ($variant:ident, $value:ident) => {
        $value.downcast_mut().unwrap()
    };
}

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn single() {
        store!(
            kvs: {
                Foo(u64 as Box; "owner"),
                Bar(u64 as Arc; "owner"),
                Baz(u64 as Ref; "owner"),
                Qux(u64; "owner"),
            }
        );

        assert_eq!(&42, Foo::from_value_ref(&Foo::to_value(42)));
        assert_eq!(&42, Bar::from_value_ref(&Bar::to_value(Arc::new(42))));
        assert_eq!(&42, Baz::from_value_ref(&Baz::to_value(&42)));
        assert_eq!(&42, Qux::from_value_ref(&Qux::to_value(42)));

        let store = KvStore::new();
        store.insert::<Foo>("owner", 42);
        assert_eq!(store.get::<Foo>("owner").unwrap(), 42);
    }

    #[test]
    fn table() {
        store!(tables: { Foo(&'static str => String; "owner"), Bar(u32 => Vec<String>; "owner")});

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
