/// Backing storage for [`Array256`][crate::Array256].
pub trait ArrayStorage {
    /// The value contained in the storage.
    type T;

    /// Insert a value into the storage at `index`.
    fn insert(&mut self, index: usize, value: Self::T);
    /// Remove the value from the storage at `index`.
    fn remove(&mut self, index: usize) -> Self::T;

    /// Empty the whole storage.
    fn clear(&mut self);
}

static_assertions::assert_obj_safe!(ArrayStorage<T = ()>);

mod private {
    pub trait Sealed {}
}

/// Extension methods for [`ArrayStorage`].
#[allow(clippy::len_without_is_empty)]
pub trait ArrayStorageSliceExt: ArrayStorage + private::Sealed {
    /// Length of the storage.
    fn len(&self) -> usize
    where
        Self: AsRef<[Self::T]>,
    {
        self.as_ref().len()
    }

    /// Iterate mutable references to elements in the storage.
    fn iter(&self) -> core::slice::Iter<'_, Self::T>
    where
        Self: AsRef<[Self::T]>,
    {
        self.as_ref().iter()
    }

    /// Iterate mutable references to elements in the storage.
    fn iter_mut(&mut self) -> core::slice::IterMut<'_, Self::T>
    where
        Self: AsMut<[Self::T]>,
    {
        self.as_mut().iter_mut()
    }
}

impl<T> private::Sealed for T where T: ArrayStorage {}
impl<T> ArrayStorageSliceExt for T where T: ArrayStorage + private::Sealed {}

/// Const-construct an `ArrayStorage`.
pub trait ConstEmptyArrayStorage: ArrayStorage {
    /// The empty value for this storage.
    const EMPTY: Self;
}

impl<T> ArrayStorage for alloc::vec::Vec<T> {
    type T = T;

    fn insert(&mut self, index: usize, value: Self::T) {
        self.insert(index, value)
    }

    fn remove(&mut self, index: usize) -> Self::T {
        self.remove(index)
    }

    fn clear(&mut self) {
        self.clear()
    }
}

impl<T> ConstEmptyArrayStorage for alloc::vec::Vec<T> {
    const EMPTY: Self = alloc::vec::Vec::new();
}

impl<T, LenT, S> ArrayStorage for heapless::vec::VecInner<T, LenT, S>
where
    LenT: heapless::LenType,
    S: heapless::vec::VecStorage<T>,
{
    type T = T;

    fn insert(&mut self, index: usize, value: Self::T) {
        self.insert(index, value)
            .map_err(|_| ())
            .expect("heapless::Vec was too small to act as ArrayStorage");
    }

    fn remove(&mut self, index: usize) -> Self::T {
        self.remove(index)
    }

    fn clear(&mut self) {
        self.clear();
    }
}

impl<const N: usize, T, LenT> ConstEmptyArrayStorage for heapless::Vec<T, N, LenT>
where
    LenT: heapless::LenType,
{
    const EMPTY: Self = heapless::Vec::new();
}

#[cfg(feature = "smallvec")]
impl<A> ArrayStorage for smallvec::SmallVec<A>
where
    A: smallvec::Array,
{
    type T = A::Item;

    fn insert(&mut self, index: usize, value: Self::T) {
        self.insert(index, value)
    }

    fn remove(&mut self, index: usize) -> Self::T {
        self.remove(index)
    }

    fn clear(&mut self) {
        self.clear()
    }
}

#[cfg(feature = "smallvec")]
impl<T, const N: usize> ConstEmptyArrayStorage for smallvec::SmallVec<[T; N]> {
    const EMPTY: Self = smallvec::SmallVec::new_const();
}
