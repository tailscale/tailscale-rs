#![doc = include_str!("../README.md")]
#![no_std]
#![forbid(unsafe_code)]

extern crate alloc;
#[cfg(test)]
extern crate std;

use core::fmt::{self, Debug};

use ts_bitset::Bitset256;

mod storage;
pub use storage::*;

/// A sparse array of 256 elements.
///
/// Indexed by [`Bitset256`] and backed by a configurable [`ArrayStorage`],
/// which is a contiguous chunk of memory holding up to 256 values.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Array256<S> {
    bitset: Bitset256,
    storage: S,
}

impl<S> Debug for Array256<S>
where
    S: ArrayStorage + AsRef<[S::T]>,
    S::T: Debug,
{
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_map()
            .entries(self.bitset.bits().zip(self.storage.iter()))
            .finish()
    }
}

impl<S> Default for Array256<S>
where
    S: Default,
{
    #[inline]
    fn default() -> Self {
        Self {
            bitset: Bitset256::EMPTY,
            storage: Default::default(),
        }
    }
}

impl<S> Array256<S>
where
    S: ConstEmptyArrayStorage,
{
    /// The empty array.
    pub const EMPTY: Self = Self {
        bitset: Bitset256::EMPTY,
        storage: S::EMPTY,
    };
}

impl<S> Array256<S>
where
    S: ArrayStorage,
{
    /// Check if the specified index is occupied.
    pub fn test(&self, index: u8) -> bool {
        self.bitset.test(index as usize)
    }

    /// Check whether this array's occupancy intersects with the given bitset.
    pub fn intersects(&self, other: &Bitset256) -> bool {
        self.bitset.intersects(other)
    }

    /// Check whether this array's occupancy intersects with the given bitset, and if so,
    /// the highest set bit of that intersection.
    pub fn intersection_top(&self, other: &Bitset256) -> Option<u8> {
        self.bitset.intersection_top(other).map(|x| x as u8)
    }

    /// Return whether this array has no elements.
    pub const fn is_empty(&self) -> bool {
        self.bitset.is_empty()
    }

    // PERF(npry): delegate to `storage` because it doesn't need to count bits in the
    // bitset, just returns the inner Vec::len (a usize). This gets computed a lot -- saw a
    // substantial impact in benchmarks.
    /// Get the number of items in this array.
    pub fn len(&self) -> usize
    where
        S: AsRef<[S::T]>,
    {
        self.storage.len()
    }

    /// Get a reference to the element at the specified index, if there is one.
    pub fn get(&self, index: u8) -> Option<&S::T>
    where
        S: AsRef<[S::T]>,
    {
        if self.test(index) {
            Some(&self.storage.as_ref()[self.storage_index(index)])
        } else {
            None
        }
    }

    /// Get a mutable reference to the element at the specified index, if there
    /// is one.
    pub fn get_mut(&mut self, index: u8) -> Option<&mut S::T>
    where
        S: AsMut<[S::T]>,
    {
        if self.test(index) {
            let storage_index = self.storage_index(index);
            Some(&mut self.storage.as_mut()[storage_index])
        } else {
            None
        }
    }

    /// Insert an item at the specified index. Returns the previous occupant if
    /// there was one.
    pub fn insert(&mut self, index: u8, element: S::T) -> Option<S::T>
    where
        S: AsMut<[S::T]>,
    {
        if self.test(index) {
            let storage_idx = self.storage_index(index);

            return Some(core::mem::replace(
                &mut self.storage.as_mut()[storage_idx],
                element,
            ));
        }

        // order matters: set the value in bitset first so that storage_index is valid
        self.bitset.set(index as _);
        self.storage.insert(self.storage_index(index), element);

        None
    }

    /// Remove an item by index.
    pub fn remove(&mut self, index: u8) -> Option<S::T>
    where
        S: AsRef<[S::T]>,
    {
        if self.storage.len() == 0 || !self.test(index) {
            return None;
        }

        // order matters: get the storage_index before we remove the item from the
        // bitset
        let storage_idx = self.storage_index(index);
        let value = self.storage.remove(storage_idx);

        self.bitset.clear(index as _);

        Some(value)
    }

    /// Clear the array.
    pub fn clear(&mut self) {
        self.bitset = Bitset256::EMPTY;
        self.storage.clear();
    }

    /// Get a reference to the internal [`Bitset256`] which stores the occupied
    /// storage indices.
    #[inline]
    pub const fn bitset(&self) -> &Bitset256 {
        &self.bitset
    }

    /// Calculate the index at which item `idx` is stored in the internal `Vec`.
    ///
    /// Assumes that the bitset has _already_ been populated with the item at
    /// `idx`, may panic otherwise.
    #[inline]
    const fn storage_index(&self, idx: u8) -> usize {
        self.bitset.rank256(idx as _) - 1
    }

    /// Iterate over all occupied entries in the array.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = (u8, &S::T)>
    where
        S: AsRef<[S::T]>,
    {
        self.bitset.bits().map(|x| x as u8).zip(self.storage.iter())
    }

    /// Iterate over occupied entries in the array starting after index `n`.
    #[inline]
    pub fn iter_after(&self, n: u8) -> impl Iterator<Item = (u8, &S::T)>
    where
        S: AsRef<[S::T]>,
    {
        self.bitset.bits_after(n).map(|idx| {
            (
                idx as u8,
                &self.storage.as_ref()[self.storage_index(idx as _)],
            )
        })
    }

    /// Iterate over mutable references to all occupied entries in the array.
    #[inline]
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (u8, &mut S::T)>
    where
        S: AsMut<[S::T]>,
    {
        self.bitset
            .bits()
            .map(|x| x as u8)
            .zip(self.storage.iter_mut())
    }

    /// Provide a [`Debug`] instance for this value when `T` is not necessarily
    /// `Debug`.
    #[inline]
    pub fn custom_storage_fmt<'slf, 'f, U>(
        &'slf self,
        f: &'f dyn Fn(&'slf S::T) -> U,
    ) -> impl Debug + 'slf
    where
        'f: 'slf,
        U: Debug + 'slf,
        S: AsRef<[S::T]>,
    {
        struct CustomFmt<'slf, 'f, S, U>
        where
            S: ArrayStorage,
        {
            ary: &'slf Array256<S>,
            f: &'f dyn Fn(&'slf S::T) -> U,
        }

        impl<'slf, 'f, S, U> Debug for CustomFmt<'slf, 'f, S, U>
        where
            'f: 'slf,
            S: ArrayStorage + AsRef<[S::T]>,
            U: Debug + 'slf,
        {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.debug_map()
                    .entries(
                        self.ary
                            .bitset
                            .bits()
                            .zip(self.ary.storage.iter().map(self.f)),
                    )
                    .finish()
            }
        }

        CustomFmt { ary: self, f }
    }

    /// Clone self with a custom function supporting clone of &T.
    #[inline]
    pub fn clone_with(&self, f: &dyn Fn(&S::T) -> S::T) -> Self
    where
        S: FromIterator<S::T>,
        S: AsRef<[S::T]>,
    {
        Self {
            bitset: self.bitset,
            storage: self.storage.iter().map(f).collect(),
        }
    }
}

impl<S> core::ops::Index<u8> for Array256<S>
where
    S: ArrayStorage + AsRef<[S::T]>,
{
    type Output = S::T;

    #[inline]
    fn index(&self, index: u8) -> &Self::Output {
        self.get(index).unwrap()
    }
}

impl<S> core::ops::IndexMut<u8> for Array256<S>
where
    S: ArrayStorage + AsRef<[S::T]> + AsMut<[S::T]>,
{
    fn index_mut(&mut self, index: u8) -> &mut Self::Output {
        self.get_mut(index).unwrap()
    }
}

impl<S> FromIterator<(u8, S::T)> for Array256<S>
where
    S: ConstEmptyArrayStorage + AsMut<[S::T]>,
{
    #[inline]
    fn from_iter<I>(iter: I) -> Self
    where
        I: IntoIterator<Item = (u8, S::T)>,
    {
        let mut ary = Array256::<S>::EMPTY;

        for (addr, item) in iter {
            ary.insert(addr, item);
        }

        ary
    }
}

#[cfg(test)]
mod test {
    use super::*;

    type VecArray<T> = Array256<alloc::vec::Vec<T>>;

    lazy_static::lazy_static! {
        static ref IDX_FILLED: VecArray<u8> = {
            let mut ary = VecArray::EMPTY;

            for i in 0u8..=255 {
                assert_eq!(None, ary.insert(i, i));
            }

            ary
        };
    }

    #[test]
    fn new_array() {
        let ary = VecArray::<()>::default();

        assert_eq!(ary.len(), 0);
        assert!(ary.is_empty());
    }

    #[test]
    fn len() {
        let mut ary = IDX_FILLED.clone();
        assert_eq!(256, ary.len());

        assert_eq!(Some(255), ary.insert(255, 255));
        assert_eq!(256, ary.len());

        for i in 0u8..128 {
            assert_eq!(Some(i), ary.remove(i));
        }

        assert_eq!(128, ary.len());
    }

    proptest::proptest! {
        #[test]
        fn get_remove(i: u8) {
            let mut ary = IDX_FILLED.clone();
            proptest::prop_assert_eq!(Some(&i), ary.get(i));
            proptest::prop_assert_eq!(Some(i), ary.remove(i));
            proptest::prop_assert_eq!(None, ary.get(i));
        }

        #[test]
        fn remove_empty(i: u8) {
            let mut ary = VecArray::<u8>::EMPTY;
            proptest::prop_assert_eq!(None, ary.remove(i));
        }
    }
}
