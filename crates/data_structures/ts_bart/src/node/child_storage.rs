use alloc::boxed::Box;

/// Generic data storage mechanism.
///
/// Currently an abstraction over [`Box`] storage (much more memory-efficient)
/// and inlined structs (sometimes faster).
///
/// The particular structure of the trait (GAT for container type) is needed to
/// enable the storage type to not carry a parameter, e.g. `Node<T,
/// InlineStorage>` (rather than `Node<T, InlineStorage<T>>`). This is desirable
/// to make type inference and trait derivation much more straightforward.
pub trait Storage {
    /// The container type used to hold the value type.
    type Container<T>;

    /// Construct a new container.
    fn new<T>(t: T) -> Self::Container<T>;
    /// Destruct the container to retrieve the contained value.
    fn into_inner<T>(container: Self::Container<T>) -> T;
    /// Retrieve a reference to the contained value.
    fn as_ref<T>(container: &Self::Container<T>) -> &T;
    /// Retrieve a mutable reference to the contained value.
    fn as_mut<T>(container: &mut Self::Container<T>) -> &mut T;
    /// Clone the container.
    fn clone<T>(container: &Self::Container<T>) -> Self::Container<T>
    where
        T: Clone;
}

/// [`Storage`] that stores values inline.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum InlineStorage {}

/// [`Storage`] that stores values in boxes.
///
/// # Memory Efficiency
///
/// Vastly more memory-efficient than inline storage: `heaptrack` suggests on the order of 5x
/// better.
///
/// Notably, `size_of::<Box<T>>()` is always a single `usize`, while an inline `Node` is 2
/// `Array256`es, which are comparatively large (256-bit bitset + vec -> ~7x larger up to alignment
/// on a 64-bit arch). Suspect the large overhead for inline storage is mostly due to the
/// powers-of-two oversizing of the `Node::children` Vec storage: this is going to be costly in
/// direct proportion to the size of the contained value.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum BoxStorage {}

impl Storage for InlineStorage {
    type Container<T> = T;

    fn new<T>(t: T) -> Self::Container<T> {
        t
    }

    fn into_inner<T>(container: Self::Container<T>) -> T {
        container
    }

    fn as_ref<T>(container: &Self::Container<T>) -> &T {
        container
    }

    fn as_mut<T>(container: &mut Self::Container<T>) -> &mut T {
        container
    }

    fn clone<T>(container: &Self::Container<T>) -> Self::Container<T>
    where
        T: Clone,
    {
        container.clone()
    }
}

impl Storage for BoxStorage {
    type Container<T> = Box<T>;

    fn new<T>(t: T) -> Self::Container<T> {
        Box::new(t)
    }

    fn into_inner<T>(container: Self::Container<T>) -> T {
        *container
    }

    fn as_ref<T>(container: &Self::Container<T>) -> &T {
        container.as_ref()
    }

    fn as_mut<T>(container: &mut Self::Container<T>) -> &mut T {
        container.as_mut()
    }

    fn clone<T>(container: &Self::Container<T>) -> Self::Container<T>
    where
        T: Clone,
    {
        container.clone()
    }
}
