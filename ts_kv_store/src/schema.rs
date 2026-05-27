//! Traits and macros for defining the KvStore schema.

use std::{any::Any, hash::Hash, sync::Arc};

use crate::storage::{SinValue, Table};

/// A singleton key/value.
///
/// Prefer to use the macros in this module rather than this trait directly.
pub trait Singleton: 'static {
    /// The type of the value.
    type Value: Any + Send + Sync;
    /// The type used to initialize and access the value. For values stored as `Arc`s this should be
    /// `Arc<Self::Value>`, for values stored by reference, this should be `&'static Self::Value`, and
    /// for other types, it should be the same as `Self::Value`.
    type ArgValue;

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
pub trait TableDesc: Sized {
    /// The type of the key.
    type Key: Hash + Eq;
    /// The type of the value.
    type Value: Any + Send + Sync;
    /// The storage for the table.
    type Storage: GeneratedStorage;
    /// The storage type for keeping this tables indexes.
    type Indexes: IndexStorage<Self::Key, Self::Value>;

    /// Get a reference to the table in storage.
    fn get_table(storage: &Self::Storage) -> &Table<Self, Self::Indexes>;
    /// Get a mutable reference to the table in storage.
    fn get_table_mut(storage: &mut Self::Storage) -> &mut Table<Self, Self::Indexes>;
}

/// Describes a table used as an index.
pub trait IndexDesc: TableDesc {
    /// The table which is indexed.
    type BaseTable: TableDesc<Storage = Self::Storage, Key = Self::Value>;
}

/// Operations on an index.
pub trait IndexStorage<K: Hash + Eq, V: Any + Send + Sync>: Default {
    /// Clear the whole index.
    fn clear(&mut self);
    /// An item has been inserted into the index.
    fn on_insert<Q>(&mut self, key: &Q, value: &V)
    where
        K: std::borrow::Borrow<Q>,
        Q: ?Sized + std::hash::Hash + Eq + std::borrow::ToOwned<Owned = K>;
    /// An item has been removed from the index.
    fn on_remove(&mut self, value: &V);
    /// Build the index from the base table.
    fn build<'a>(&mut self, kvs: impl Iterator<Item = (&'a K, &'a V)>)
    where
        K: 'a,
        V: 'a;
}

impl<K: Hash + Eq, V: Any + Send + Sync> IndexStorage<K, V> for () {
    fn clear(&mut self) {}
    fn on_insert<Q>(&mut self, _key: &Q, _value: &V)
    where
        K: std::borrow::Borrow<Q>,
        Q: ?Sized + std::hash::Hash + Eq,
    {
    }
    fn on_remove(&mut self, _value: &V) {}
    fn build<'a>(&mut self, _kvs: impl Iterator<Item = (&'a K, &'a V)>)
    where
        K: 'a,
        V: 'a,
    {
    }
}

/// Marker trait to indicate a storage implementation.
///
/// This should be considered a sealed trait and not implemented except by the macros in this module.
/// Unfortunately it has to be public because of macro visibility hygiene.
#[doc(hidden)]
pub trait GeneratedStorage: Default {}

/// Macro to declare a singleton key/value in the store.
///
/// Does not need to be used within or near the store declaration, but also is not linked to a specific
/// store. Using a generated accessor on a store different to the store the key/value was stored in
/// will have unpredictable results (panics, memory safety, etc.).
///
/// # Syntax:
///
/// - `singleton!(u64)` to declare a value with type `u64` and inline storage.
/// - `singleton!(ValueType as Box)` to declare a value with type `Box<ValueType>`.
/// - `singleton!(ValueType as Arc)` to declare a value with type `Arc<ValueType>`.
/// - `singleton!(ValueType as Ref)` to declare a value with type `&'static ValueType`.
///
/// The storage class is separate to the value type since they have different representations in the
/// store and slightly different APIs (e.g., whether mutable access is supported or access by cloning
/// or copying a shared reference).
#[macro_export]
macro_rules! singleton {
    ($name:ident(u64)) => {
        $crate::singleton_types!($name(u64, u64, U64));

        impl $crate::schema::MutSingleton for $name {
            fn from_value_mut(value: &mut $crate::storage::SinValue) -> &mut Self::Value {
                match value {
                    $crate::match_helper_lhs!(U64, v) => $crate::match_helper_rhs_mut!(U64, v),
                    _ => unreachable!(),
                }
            }
        }
    };
    ($name:ident($value_ty:ty as Box)) => {
        $crate::singleton_types!($name($value_ty, $value_ty, Box));

        impl $crate::schema::MutSingleton for $name {
            fn from_value_mut(value: &mut $crate::storage::SinValue) -> &mut Self::Value {
                match value {
                    $crate::match_helper_lhs!(Box, v) => $crate::match_helper_rhs_mut!(Box, v),
                    _ => unreachable!(),
                }
            }
        }
    };
    ($name:ident($value_ty:ty as Arc)) => {
        $crate::singleton_types!($name($value_ty, std::sync::Arc<$value_ty>, Arc));

        impl $crate::schema::ArcSingleton for $name {}
    };
    ($name:ident($value_ty:ty as Ref)) => {
        $crate::singleton_types!($name($value_ty, &'static $value_ty, Ref));
    };
}

#[doc(hidden)]
#[macro_export]
macro_rules! singleton_types {
    ($name:ident($value_ty:ty, $arg_value_ty:ty, $variant:ident)) => {
        /// Describes a singleton in the KV store.
        #[allow(non_camel_case_types)]
        pub struct $name;

        impl $crate::schema::Singleton for $name {
            type Value = $value_ty;
            type ArgValue = $arg_value_ty;

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
        $crate::storage::SinValue::Box(Box::new($value) as Box<dyn Any + Send + Sync>)
    };
    (Arc, $value:ident) => {
        $crate::storage::SinValue::Arc($value.clone() as Arc<dyn Any + Send + Sync>)
    };
    (Ref, $value:ident) => {
        $crate::storage::SinValue::Ref($value as &'static (dyn Any + Send + Sync))
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

/// Declare the tables in a key/value store. Generates the store itself with the specified tables.
///
/// The syntax is `tables!(Name(KeyType, ValueType indexes?),*)`, where `Name` is an identifier to name
/// the table, and `KeyType` and `ValueType` are types. `Name` is used as a type argument to
/// KvStore methods to identify the table. Use with an empty list of tables to generate a store
/// for use only with singleton key/value pairs.
///
/// # Example:
///
/// ```rust
/// # use ts_kv_store::tables;
/// # pub struct Node;
/// # pub trait Edge {}
/// tables!(
///   Nodes(&'static str => Node),
///   Edges(u32 => Box<dyn Edge + Send + Sync>)
/// );
/// ```
/// # Indexes
///
/// The syntax of an index is `index(field: Type)` where `field` is the name of a field in the value
/// type of the base table and `Type` is the type of that field. You can specify multiple indexes
/// for each table, separated with a semicolon. E.g.,
///
/// ```rust
/// # use ts_kv_store::tables;
/// # pub struct Node { a: u32, b: String};
/// tables!(
///   Nodes(&'static str => Node; index(a: u32); index(b: String))
/// );
/// ```
///
/// This will create two indexes on nodes for fields `a` and `b`.
///
/// Index fields must uniquely identify a row in the base table. If multiple rows in the base table
/// have the same key in the index, then behavior is unspecified (might give partial or incorrect
/// result, might panic, etc.). The type of an index key field and the type of the primary key of the
/// data being indexed must both be `Clone` (since they will be cloned when inserted into the index).
#[macro_export]
macro_rules! tables {
    ($($name: ident ($key_ty: ty => $value_ty: ty $(; index($field: ident: $field_ty: ty))*)),*) => {
        $(
            /// Describes a table in the KV store.
            #[derive(Default)]
            pub struct $name;

            impl $crate::schema::TableDesc for $name {
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
                impl $crate::schema::TableDesc for index::$name::$field {
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
        )*

        /// Macro-generated storage for all tabular data.
        #[derive(Default)]
        #[allow(non_snake_case)]
        pub struct TableStorage {
            $($name: $crate::storage::Table<$name, index::$name::Indexes>),*
        }
        impl $crate::schema::GeneratedStorage for TableStorage {}

        pub mod index {
            $(
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
            )*
        }

        $(
            impl $crate::schema::IndexStorage<$key_ty, $value_ty> for index::$name::Indexes {
                fn clear(&mut self) {
                    $(
                        self.$field.data.clear();
                    )*
                }

                fn on_insert<Q>(&mut self, _key: &Q, _value: &$value_ty)
                where
                    $key_ty: std::borrow::Borrow<Q>,
                    Q: ?Sized + std::hash::Hash + Eq + std::borrow::ToOwned<Owned = $key_ty>
                {
                    $(
                        self.$field.data.insert(_value.$field.clone(), _key.to_owned());
                    )*
                }

                fn on_remove(&mut self, _value: &$value_ty) {
                    $(
                        self.$field.data.remove(&_value.$field);
                    )*
                }

                fn build<'a>(&mut self, kvs: impl Iterator<Item = (&'a $key_ty, &'a $value_ty)>)
                where
                    $key_ty: 'a,
                    $value_ty: 'a,
                {
                    for (_k, _v) in kvs {
                        $(
                            self.$field.data.insert(_v.$field.clone(), _k.to_owned());
                        )*
                    }
                }
            }
        )*

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

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn single() {
        singleton!(Foo(u64 as Box));
        singleton!(Bar(u64 as Arc));
        singleton!(Baz(u64 as Ref));
        singleton!(Qux(u64));

        assert_eq!(&42, Foo::from_value_ref(&Foo::to_value(42)));
        assert_eq!(&42, Bar::from_value_ref(&Bar::to_value(Arc::new(42))));
        assert_eq!(&42, Baz::from_value_ref(&Baz::to_value(&42)));
        assert_eq!(&42, Qux::from_value_ref(&Qux::to_value(42)));

        tables!();

        let store = KvStore::new();
        store.insert::<Foo>("owner", 42);
        assert_eq!(store.get::<Foo>("owner").unwrap(), 42);
    }

    #[test]
    fn table() {
        tables!(Foo(&'static str => String), Bar(u32 => Vec<String>));

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
        tables!(Foo(&'static str => String), Bar(u32 => BarT; index(a: String)));

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
        assert_eq!(value.a, "hello")
    }
}
