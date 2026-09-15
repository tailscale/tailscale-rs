use crate::{Bitset, Bitset256};

#[cfg(feature = "lut")]
/// Precomputed rank mask table, which can be used to rapidly calculate the rank
/// of a given bitset.
///
/// See [`Bitset256::rank`].
static RANK_MASK: [Bitset256; 256] = {
    let mut ret = [Bitset256::EMPTY; 256];

    let mut i = 0usize;
    while i < 256 {
        ret[i] = Bitset256::build_rank_mask(i);
        i += 1;
    }

    ret
};

/// The size of the [`Bitset256::rank`] lookup table in bytes.
#[cfg(feature = "lut")]
pub const LUT_SIZE: usize = size_of_val(&RANK_MASK);

impl Bitset256 {
    /// Returns the number of bits set up to and including the provided index,
    /// in order (counting up from the left).
    ///
    /// E.g. `bitset.rank256(1)` is the number of bits set in `bitset & 0b1000...`,
    /// `bitset.rank256(2)` is the number set in `bitset & 0b1100...`, etc.
    ///
    /// With the `lut` feature enabled, this uses a lookup table under the hood.
    /// This makes it much faster than [`Bitset::rank`].
    ///
    /// # Example
    /// ```
    /// # use ts_bitset::Bitset256;
    /// let b = Bitset256::EMPTY.with_bit(3).with_bit(5).with_bit(120);
    /// assert_eq!(b.rank256(5), 2);
    /// assert_eq!(b.rank256(119), 2);
    /// assert_eq!(b.rank256(120), 3);
    /// ```
    pub const fn rank256(&self, i: usize) -> usize {
        let mut mask = Self::rank_mask256(i);

        mask.intersect_inplace(self);
        mask.count_ones()
    }

    /// Return the bitset with all bits up to and including bit `n` set.
    /// This is a mask that can be used to calculate the [`Self::rank`] of
    /// another bitset.
    ///
    /// Uses a lookup-table if the `lut` feature is enabled.
    pub(super) const fn rank_mask256(n: usize) -> Self {
        cfg_if::cfg_if! {
            if #[cfg(feature = "lut")] {
               RANK_MASK[n]
            } else {
                Self::build_rank_mask(n)
            }
        }
    }
}

impl<const N_WORDS: usize> Bitset<N_WORDS> {
    /// Returns the number of bits set up to and including the provided index,
    /// in order (counting up from the left).
    ///
    /// E.g. `bitset.rank(1)` is the number of bits set in `bitset & 0b1000...`,
    /// `bitset.rank(2)` is the number set in `bitset & 0b1100...`, etc.
    ///
    /// # Example
    /// ```
    /// # use ts_bitset::Bitset256;
    /// let b = Bitset256::EMPTY.with_bit(3).with_bit(5).with_bit(120);
    /// assert_eq!(b.rank(5), 2);
    /// assert_eq!(b.rank(119), 2);
    /// assert_eq!(b.rank(120), 3);
    /// ```
    pub const fn rank(&self, i: usize) -> usize {
        let mut mask = Self::build_rank_mask(i);

        mask.intersect_inplace(self);
        mask.count_ones()
    }

    /// Build a bitset with all bits up to and including bit `n` set. This
    /// is a mask that can be used to calculate the [`Self::rank`] of another
    /// bitset.
    pub const fn build_rank_mask(n: usize) -> Self {
        let mut out = [0u64; N_WORDS];

        let mut i = 0;
        while i < N_WORDS {
            out[i] = mask_word(i, n);
            i += 1;
        }

        Self(out)
    }
}

/// Computes the u64 word at index `word_idx` for the rank mask of width `n`.
const fn mask_word(word_idx: usize, mut n: usize) -> u64 {
    // Want the nth bit to also be set / "up to and including"
    n += 1;

    let target_word = n / 64;

    if target_word > word_idx {
        u64::MAX
    } else if target_word < word_idx {
        0
    } else {
        (1 << (n % 64)) - 1
    }
}

#[cfg(test)]
mod test {
    use super::*;

    /// Ensure that `RANK_MASK` is constructed as expected (`RANK_MASK[i]` has
    /// all bits up to and including `i` set).
    #[test]
    fn rank_lut() {
        // NB: the actual mask calculation isn't done this way because we can't use for
        // loops in a const context.
        #[allow(clippy::needless_range_loop)]
        for i in 0..=255 {
            let mut expected = Bitset256::EMPTY;
            for j in 0..=i {
                expected.set(j);
            }

            #[cfg(feature = "lut")]
            assert_eq!(expected, RANK_MASK[i]);
            #[cfg(not(feature = "lut"))]
            assert_eq!(expected, Bitset256::build_rank_mask(i as usize));
        }
    }

    #[test]
    fn rank() {
        const TEST_BITSET: Bitset256 =
            Bitset256::EMPTY.with_bits(&[0, 3, 5, 7, 11, 62, 63, 64, 70, 150, 255]);

        assert_eq!(1, TEST_BITSET.rank(0));
        assert_eq!(1, TEST_BITSET.rank(1));
        assert_eq!(1, TEST_BITSET.rank(2));
        assert_eq!(2, TEST_BITSET.rank(3));
        assert_eq!(2, TEST_BITSET.rank(4));
        assert_eq!(6, TEST_BITSET.rank(62));
        assert_eq!(7, TEST_BITSET.rank(63));
        assert_eq!(8, TEST_BITSET.rank(64));
        assert_eq!(10, TEST_BITSET.rank(150));
        assert_eq!(10, TEST_BITSET.rank(254));
        assert_eq!(11, TEST_BITSET.rank(255));
    }
}
