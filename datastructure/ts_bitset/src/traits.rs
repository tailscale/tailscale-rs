/// A bitset that supports `const`-construction and reporting of bit length.
pub trait ConstBitset {
    /// The bitset with no bits set.
    const EMPTY: Self;

    /// The number of bits in this bitset.
    ///
    /// `None` if the value is unbounded.
    const BITS: Option<usize>;
}

/// Subset of bitset ops that support dynamic dispatch.
pub trait BitsetDyn {
    /// Report the length of this bitset in bits.
    ///
    /// Return `None` if the bitset length is unbounded.
    fn n_bits(&self) -> Option<usize>;

    /// Set the bit at index `bit` to 1.
    ///
    /// # Panics
    ///
    /// If `bit` > `Self::n_bits`. The implementation is not permitted to panic if
    /// `n_bits` returns `None`.
    fn set(&mut self, bit: usize);

    /// Clear `bit` (set it to 0).
    ///
    /// # Panics
    ///
    /// If `bit` > `Self::n_bits`. The implementation is not permitted to panic if
    /// `n_bits` returns `None`.
    fn clear(&mut self, bit: usize);

    /// Return true if `bit` is 1, else 0.
    ///
    /// # Panics
    ///
    /// If `bit` > `Self::n_bits`. The implementation is not permitted to panic if
    /// `n_bits` returns `None`.
    fn test(&self, bit: usize) -> bool;

    /// Retrieve the index of the lowest (first) set bit.
    fn first_set(&self) -> Option<usize>;

    /// Retrieve the index of the next set bit that is greater than or equal to
    /// `bit`.
    fn next_set(&self, bit: usize) -> Option<usize>;

    /// Retrieve the index of the last (highest) set bit.
    fn last_set(&self) -> Option<usize>;

    /// Report if all bits are empty.
    fn is_empty(&self) -> bool;

    /// The number of set bits.
    fn count_ones(&self) -> usize;

    /// Invert all bits in this bitset in-place.
    fn invert_inplace(&mut self);
}

static_assertions::assert_obj_safe!(BitsetDyn);

/// Subset of bitset ops that do not support dynamic dispatch.
pub trait BitsetStatic: BitsetDyn {
    /// The bitset with no bits set.
    fn empty() -> Self;

    /// Return a copy of this bitset with `bit` set.
    ///
    /// # Panics
    ///
    /// If `bit` > `Self::n_bits`. The implementation is not permitted to panic if
    /// `n_bits` returns `None`.
    fn with_bit(self, bit: usize) -> Self;

    /// Return a copy of this bitset with `bits` set.
    ///
    /// # Panics
    ///
    /// If `bit` > `Self::n_bits`. The implementation is not permitted to panic if
    /// `n_bits` returns `None`.
    fn with_bits(self, bits: &[usize]) -> Self;

    /// Return a copy of this bitset with `bit` cleared.
    ///
    /// # Panics
    ///
    /// If `bit` > `Self::n_bits`. The implementation is not permitted to panic if
    /// `n_bits` returns `None`.
    fn without_bit(self, bit: usize) -> Self;

    /// Return a copy of this bitset with `bits` set.
    ///
    /// # Panics
    ///
    /// If `bit` > `Self::n_bits`. The implementation is not permitted to panic if
    /// `n_bits` returns `None`.
    fn without_bits(self, bits: &[usize]) -> Self;

    /// Get the intersection of this bitset with another and return the topmost
    /// shared bit.
    fn intersection_top(&self, other: &Self) -> Option<usize>;

    /// Report whether this bitset intersects `other`.
    fn intersects(&self, other: &Self) -> bool;

    /// Union `other`'s bits by mutating this value in-place.
    fn union_inplace(&mut self, other: &Self);

    /// Intersect `other`'s bits by mutating this value in-place.
    fn intersect_inplace(&mut self, other: &Self);

    /// Get the indices of all set bits.
    ///
    /// # Example
    /// ```
    /// # use ts_bitset::Bitset256;
    /// let bs = Bitset256::default().with_bit(1);
    /// assert_eq!(bs.bits().collect::<Vec<_>>(), vec![1]);
    /// ```
    fn bits(&self) -> impl Iterator<Item = usize>;
}
