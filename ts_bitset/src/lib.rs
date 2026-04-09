//! Provides [`Bitset256`], a compact, efficient, non-allocating 256-entry
//! bitset implementation supporting bitwise operations, iteration over set
//! bits, and rank calculation.
//!
//! Based on the package of the same name in golang's [bart].
//!
//! [bart]: <https://github.com/gaissmai/bart/blob/main/internal/bitset/bitset256.go>

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

use core::fmt::{Debug, Formatter, Write};

mod rank;
mod traits;

#[cfg(feature = "lut")]
pub use rank::LUT_SIZE as RANK_LUT_SIZE;
pub use traits::{BitsetDyn, BitsetStatic, ConstBitset};

/// Alias for a 256-bit bitset, which conveniently covers a whole `u8`.
pub type Bitset256 = Bitset<4>;

/// A compact, efficient, non-allocating 256-entry bitset supporting bitwise
/// operations, iteration over set bits, and rank calculation.
///
/// Bits are indexed low-to-high, i.e. bit 0 is leftmost.
///
/// The default value is empty.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Bitset<const N_WORDS: usize>(
    // Note: the bitset's notion of bit indexing aligns uses the "natural" bit
    // ordering in the u64 subwords, i.e. bitset[0] is `words[0] & (1 << 0)`, the
    // lsb of words[0]. This puts it at memory position 63.
    [u64; N_WORDS],
);

impl<const N_WORDS: usize> Default for Bitset<N_WORDS> {
    fn default() -> Self {
        Self([0; N_WORDS])
    }
}

impl<const N_WORDS: usize> Debug for Bitset<N_WORDS> {
    // Write the bitset out _in bit order_ (not as it's represented in memory).
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "Bitset<{}>(", N_WORDS)?;

        for (word_idx, word) in self.word_iter().enumerate() {
            write!(f, "[{}] ", word_idx * 64)?;

            for octet_idx in 0usize..8 {
                write!(
                    f,
                    "{:08b}",
                    (((word >> (octet_idx * 8)) & 0xff) as u8).reverse_bits()
                )?;

                if octet_idx != 7 {
                    f.write_char(' ')?;
                }
            }

            if word_idx + 1 != N_WORDS {
                f.write_char(' ')?;
            }
        }

        f.write_char(')')
    }
}

// Many of the functions here use awkward, C-reminiscent implementations
// without useful Rust sugar (most notably while loops with counters instead of
// iterators). This is to support them being `const fn`: we want to be able to
// construct and operate on `Bitset256`s at compile time for runtime speed. This
// capability is used e.g. to construct the lookup tables in `rank.rs`,
// `../allot.rs`, and `../lpm.rs`. `const` contexts still come with substantial
// restrictions, e.g. no traits, no `?`, which leads to the awkwardness of the
// implementations.

impl<const N_WORDS: usize> Bitset<N_WORDS> {
    /// The bitset with no bits set.
    pub const EMPTY: Self = Bitset([0u64; N_WORDS]);
    /// The bitset with all bits set.
    pub const FULL: Self = Bitset([u64::MAX; N_WORDS]);
    /// The number of bits in the bitset.
    pub const N_BITS: usize = N_WORDS * 64;

    /// Resize this bitset to a new one with `M` 64-bit words.
    ///
    /// `empty_value` specifies the bit state of any new bits: if `true`, all new bits are
    /// set, otherwise they're cleared.
    pub const fn resize<const M: usize>(self, empty_value: bool) -> Bitset<M> {
        let empty = if empty_value { u64::MAX } else { 0 };
        let mut out = [empty; M];

        let n = if N_WORDS <= M { N_WORDS } else { M };

        // Needed rather than range slicing because Index isn't const
        let (to_copy, _rest) = self.0.split_at(n);
        out.copy_from_slice(to_copy);

        Bitset(out)
    }

    /// Set `bit` to 1.
    ///
    /// # Panics
    ///
    /// If `bit` is out of the valid range for this bitset.
    #[inline]
    pub const fn set(&mut self, bit: usize) {
        self.0[word_idx(bit)] |= subword_idx(bit);
    }

    /// Return a copy of this bitset with `bit` set.
    ///
    /// # Panics
    ///
    /// If `bit` is out of the valid range for this bitset.
    #[inline]
    pub const fn with_bit(mut self, bit: usize) -> Self {
        self.set(bit);
        self
    }

    /// Return a copy of this bitset with `bits` set.
    ///
    /// # Panics
    ///
    /// If any bit in `bits` is out of the valid range for this bitset.
    #[inline]
    pub const fn with_bits(mut self, bits: &[usize]) -> Self {
        // While loop construction to support `const`: see the comment
        // at the top of the impl block for details.
        let mut i = 0;
        while i != bits.len() {
            self.set(bits[i]);
            i += 1;
        }

        self
    }

    /// Clear `bit` (set it to 0).
    ///
    /// # Panics
    ///
    /// If `bit` is out of the valid range for this bitset.
    #[inline]
    pub const fn clear(&mut self, bit: usize) {
        let idx = word_idx(bit);
        self.0[idx] &= !subword_idx(bit);
    }

    /// Return a copy of this bitset with `bit` cleared.
    ///
    /// # Panics
    ///
    /// If `bit` is out of the valid range for this bitset.
    #[inline]
    pub const fn without_bit(mut self, bit: usize) -> Self {
        self.clear(bit);
        self
    }

    /// Return a copy of this bitset with `bits` set.
    ///
    /// # Panics
    ///
    /// If any bit in `bits` is out of the valid range for this bitset.
    #[inline]
    pub const fn without_bits(mut self, bits: &[usize]) -> Self {
        let mut i = 0;

        while i != bits.len() {
            self.clear(bits[i]);
            i += 1;
        }

        self
    }

    /// Return true if `bit` is 1, else 0.
    ///
    /// # Panics
    ///
    /// If `bit` is out of the valid range for this bitset.
    #[inline]
    pub const fn test(&self, bit: usize) -> bool {
        (self.0[word_idx(bit)] & subword_idx(bit)) != 0
    }

    /// Retrieve the index of the lowest (first) set bit.
    pub const fn first_set(&self) -> Option<usize> {
        let mut i = 0;

        while i < self.0.len() {
            let zeroes = self.0[i].trailing_zeros();
            if zeroes != 64 {
                return Some(64 * i + zeroes as usize);
            }

            i += 1;
        }

        None
    }

    /// Retrieve the index of the next set bit that is greater than or equal to
    /// `bit`.
    pub const fn next_set(&self, bit: usize) -> Option<usize> {
        let word = word_idx(bit);

        let first = self.0[word].unbounded_shr((bit & 63) as _);
        if first != 0 {
            return Some(bit + first.trailing_zeros() as usize);
        }

        let mut word = word + 1;
        while word < N_WORDS {
            let value = self.0[word];
            if value == 0 {
                word += 1;
                continue;
            }

            return Some(word * 64 + value.trailing_zeros() as usize);
        }

        None
    }

    /// Retrieve the index of the last (highest) set bit.
    pub const fn last_set(&self) -> Option<usize> {
        let mut word = N_WORDS - 1;

        loop {
            let value = self.0[word];
            if value == 0 {
                if word == 0 {
                    break;
                } else {
                    word -= 1;
                    continue;
                }
            }

            return Some((word * 64) + (len(value) - 1));
        }

        None
    }

    /// Get the indices of all set bits.
    ///
    /// # Example
    /// ```
    /// # use ts_bitset::Bitset256;
    /// let bs = Bitset256::default().with_bit(1);
    /// assert_eq!(bs.bits().collect::<Vec<_>>(), vec![1]);
    /// ```
    pub fn bits(self) -> impl Iterator<Item = usize> {
        self.word_iter().enumerate().flat_map(|(i, mut word)| {
            let word_offset = i * 64;

            core::iter::from_fn(move || {
                let trailing_zeros = word.trailing_zeros() as usize;
                if trailing_zeros == u64::BITS as usize {
                    return None;
                }

                word &= word - 1;

                Some(word_offset + trailing_zeros)
            })
        })
    }

    /// Get the intersection of this bitset with another and return the topmost
    /// shared bit.
    pub fn intersection_top(&self, other: &Self) -> Option<usize> {
        for (word, (this, other)) in self.word_iter().zip(other.word_iter()).enumerate().rev() {
            let intersect = this & other;
            if intersect == 0 {
                continue;
            }

            return Some((word * 64) + (len(intersect) - 1));
        }

        None
    }

    /// Report if all bits are empty.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        let mut i = 0;

        while i < N_WORDS {
            if self.0[i] != 0 {
                return false;
            }

            i += 1
        }

        true
    }

    /// Report whether this bitset intersects `other`.
    #[inline]
    pub fn intersects(&self, other: &Self) -> bool {
        self.word_iter()
            .zip(other.word_iter())
            .any(|(x, y)| x & y != 0)
    }

    /// The number of set bits.
    #[inline]
    pub const fn count_ones(&self) -> usize {
        let mut i = 0;
        let mut sum = 0;

        while i < N_WORDS {
            sum += self.0[i].count_ones();
            i += 1;
        }

        sum as usize
    }

    /// Iterate over the values of the word in self in order.
    #[inline]
    fn word_iter(&self) -> impl DoubleEndedIterator<Item = u64> + ExactSizeIterator + use<N_WORDS> {
        self.0.into_iter()
    }

    /// Union `other`'s bits by mutating this value in-place.
    #[inline]
    pub const fn union_inplace(&mut self, other: &Self) {
        let mut i = 0;
        while i < N_WORDS {
            self.0[i] |= other.0[i];
            i += 1;
        }
    }

    /// Intersect `other`'s bits by mutating this value in-place.
    #[inline]
    pub const fn intersect_inplace(&mut self, other: &Self) {
        let mut i = 0;
        while i < N_WORDS {
            self.0[i] &= other.0[i];
            i += 1;
        }
    }

    /// Invert all bits in this bitset in-place.
    #[inline]
    pub const fn invert_inplace(&mut self) {
        let mut i = 0;

        while i < N_WORDS {
            self.0[i] = !self.0[i];
            i += 1;
        }
    }

    /// Construct a bitset with all bits set up to but excluding `bit_exclusive`.
    ///
    /// # Panics
    ///
    /// If `bit_exclusive` is out of range for this bitset.
    pub const fn with_bits_upto(bit_exclusive: usize) -> Self {
        let mut out = [0u64; N_WORDS];

        let full_set_words = bit_exclusive / 64;
        let mut i = 0;
        while i < full_set_words {
            out[i] = u64::MAX;
            i += 1;
        }

        let last_set_word = full_set_words;
        if last_set_word < N_WORDS {
            let n_bits = bit_exclusive % 64;
            out[last_set_word] = (1 << n_bits) - 1;
        }

        Self(out)
    }
}

impl<const N_WORDS: usize> ConstBitset for Bitset<N_WORDS> {
    const EMPTY: Self = Self::EMPTY;
    const BITS: Option<usize> = Some(N_WORDS * 64);
}

impl<const N_WORDS: usize> BitsetDyn for Bitset<N_WORDS> {
    fn n_bits(&self) -> Option<usize> {
        Self::BITS
    }

    fn set(&mut self, bit: usize) {
        self.set(bit)
    }

    fn clear(&mut self, bit: usize) {
        self.clear(bit)
    }

    fn test(&self, bit: usize) -> bool {
        self.test(bit)
    }

    fn first_set(&self) -> Option<usize> {
        self.first_set()
    }

    fn next_set(&self, bit: usize) -> Option<usize> {
        self.next_set(bit)
    }

    fn last_set(&self) -> Option<usize> {
        self.last_set()
    }

    fn is_empty(&self) -> bool {
        self.is_empty()
    }

    fn count_ones(&self) -> usize {
        self.count_ones()
    }

    fn invert_inplace(&mut self) {
        self.invert_inplace()
    }
}

impl<const N_WORDS: usize> BitsetStatic for Bitset<N_WORDS> {
    fn empty() -> Self {
        Self::EMPTY
    }

    fn bits(&self) -> impl Iterator<Item = usize> {
        (*self).bits()
    }

    fn with_bit(self, bit: usize) -> Self {
        self.with_bit(bit)
    }

    fn with_bits(self, bits: &[usize]) -> Self {
        self.with_bits(bits)
    }

    fn without_bit(self, bit: usize) -> Self {
        self.without_bit(bit)
    }

    fn without_bits(self, bits: &[usize]) -> Self {
        self.without_bits(bits)
    }

    fn intersection_top(&self, other: &Self) -> Option<usize> {
        self.intersection_top(other)
    }

    fn intersects(&self, other: &Self) -> bool {
        self.intersects(other)
    }

    fn union_inplace(&mut self, other: &Self) {
        self.union_inplace(other)
    }

    fn intersect_inplace(&mut self, other: &Self) {
        self.intersect_inplace(other)
    }
}

impl Bitset256 {
    /// Get the indices of all set bits starting after index `n`.
    pub fn bits_after(self, n: u8) -> impl Iterator<Item = usize> {
        let masked_value = !Self::rank_mask256(n as _) & self;
        masked_value.bits()
    }
}

// Bitwise ops below are duplicative of {intersect,union}_inplace because const
// traits aren't available in stable yet. In the future, ideally the *_inplace
// functions will be replaced by `impl const Bit*`.

impl<const N_WORDS: usize> core::ops::BitAnd for Bitset<N_WORDS> {
    type Output = Self;

    #[inline]
    fn bitand(mut self, rhs: Self) -> Self::Output {
        self.intersect_inplace(&rhs);
        self
    }
}

impl<const N_WORDS: usize> core::ops::BitAndAssign for Bitset<N_WORDS> {
    #[inline]
    fn bitand_assign(&mut self, rhs: Self) {
        self.intersect_inplace(&rhs);
    }
}

impl<const N_WORDS: usize> core::ops::BitOr for Bitset<N_WORDS> {
    type Output = Self;

    #[inline]
    fn bitor(mut self, rhs: Self) -> Self::Output {
        self.union_inplace(&rhs);
        self
    }
}

impl<const N_WORDS: usize> core::ops::BitOrAssign for Bitset<N_WORDS> {
    #[inline]
    fn bitor_assign(&mut self, rhs: Self) {
        self.union_inplace(&rhs);
    }
}

impl<const N_WORDS: usize> core::ops::Not for Bitset<N_WORDS> {
    type Output = Self;

    #[inline]
    fn not(mut self) -> Self::Output {
        self.invert_inplace();
        self
    }
}

impl<const N_WORDS: usize> Bitset<N_WORDS> {
    /// In-place unbounded shift left. Updates `self` to be `self << rhs`, without bounding
    /// the value of `rhs`.
    ///
    /// If `rhs` is larger or equal to `Self::N_BITS`, the entire value is shifted out, and
    /// `Self::EMPTY` is returned.
    ///
    /// # Panics
    ///
    /// If the shift amount cannot fit in a `usize`. This should only be possible on targets where
    /// `usize` is 16 bits, which the Rust specification allows but is extremely uncommon in
    /// practice.
    pub fn unbounded_shl_inplace(&mut self, rhs: u32) {
        // We need a usize to index the word array.
        // Per https://doc.rust-lang.org/reference/types/numeric.html, usize may be as small as
        // 16 bits, even though it's more commonly 32 or 64 bits.
        // For huge bitsets (hundreds of MiB), shift_words may be up to 26 bits. So, this
        // conversion may fail in extreme edge cases.
        let rhs: usize = rhs.try_into().unwrap();

        if rhs >= Self::N_BITS {
            *self = Self::EMPTY;
            return;
        }

        let shift_words: usize = rhs / 64;
        let shift_bits = rhs % 64;
        let shift_bits_inv = (64 - shift_bits) as u32;

        for tgt_idx in (shift_words..self.0.len()).rev() {
            let src_idx = tgt_idx - shift_words;
            let src_word1 = self.0[src_idx];
            let src_word2 = if src_idx == 0 { 0 } else { self.0[src_idx - 1] };
            self.0[tgt_idx] = (src_word1 << shift_bits) | (src_word2.unbounded_shr(shift_bits_inv));
        }
        self.0[..shift_words].fill(0);
    }

    /// Unbounded shift left. Computes `self << rhs`, without bounding the value of `rhs`.
    ///
    /// If `rhs` is larger or equal to `Self::N_BITS`, the entire value is shifted out, and
    /// `Self::EMPTY` is returned.
    ///
    /// # Panics
    ///
    /// If the shift amount cannot fit in a `usize`. This should only be possible on targets where
    /// `usize` is 16 bits, which the Rust specification allows but is extremely uncommon in
    /// practice.
    #[inline]
    pub fn unbounded_shl(mut self, rhs: u32) -> Self {
        self.unbounded_shl_inplace(rhs);
        self
    }

    /// In-place unbounded shift right. Updates `self` to be `self >> rhs`, without bounding
    /// the value of `rhs`.
    ///
    /// If `rhs` is larger or equal to `Self::N_BITS`, the entire value is shifted out, and
    /// `Self::EMPTY` is returned.
    ///
    /// # Panics
    ///
    /// If the shift amount cannot fit in a `usize`. This should only be possible on targets where
    /// `usize` is 16 bits, which the Rust specification allows but is extremely uncommon in
    /// practice.
    pub fn unbounded_shr_inplace(&mut self, rhs: u32) {
        // We need a usize to index the word array.
        // Per https://doc.rust-lang.org/reference/types/numeric.html, usize may be as small as
        // 16 bits, even though it's more commonly 32 or 64 bits.
        // For huge bitsets (hundreds of MiB), shift_words may be up to 26 bits. So, this
        // conversion may fail in extreme edge cases.
        let rhs: usize = rhs.try_into().unwrap();

        if rhs >= Self::N_BITS {
            *self = Self::EMPTY;
            return;
        }

        let shift_words: usize = rhs / 64;
        let shift_bits = rhs % 64;
        let shift_bits_inv = (64 - shift_bits) as u32;

        for tgt_idx in 0..N_WORDS - shift_words {
            let src_idx = tgt_idx + shift_words;
            let src_word1 = self.0[src_idx];
            let src_word2 = self.0.get(src_idx + 1).map_or(0, |v| *v);
            self.0[tgt_idx] = (src_word1 >> shift_bits) | (src_word2.unbounded_shl(shift_bits_inv));
        }
        self.0[N_WORDS - shift_words..].fill(0);
    }

    /// Unbounded shift right. Computes `self >> rhs`, without bounding the value of `rhs`.
    ///
    /// If `rhs` is larger or equal to `Self::N_BITS`, the entire value is shifted out, and
    /// `Self::EMPTY` is returned.
    ///
    /// # Panics
    ///
    /// If the shift amount cannot fit in a `usize`. This should only be possible on targets where
    /// `usize` is 16 bits, which the Rust specification allows but is extremely uncommon in
    /// practice.
    #[inline]
    pub fn unbounded_shr(mut self, rhs: u32) -> Self {
        self.unbounded_shr_inplace(rhs);
        self
    }
}

macro_rules! shift_impl {
    ($t:ty) => {
        impl<const N_WORDS: usize> core::ops::Shl<$t> for Bitset<N_WORDS> {
            type Output = Self;

            #[inline]
            fn shl(mut self, rhs: $t) -> Self::Output {
                self <<= rhs;
                self
            }
        }

        impl<const N_WORDS: usize> core::ops::ShlAssign<$t> for Bitset<N_WORDS> {
            #[inline]
            fn shl_assign(&mut self, rhs: $t) {
                // This comparison is a no-op for unsigned $t, but required for signed $t.
                #[allow(unused_comparisons)]
                if rhs < 0 {
                    panic!("negative shift");
                }

                // Cast may fail on 16b usize, see comment in unbounded_shl.
                let rhs: usize = rhs.try_into().unwrap();
                if rhs >= Self::N_BITS {
                    panic!("attempt to shift left with overflow");
                }

                self.unbounded_shl_inplace(rhs.try_into().unwrap());
            }
        }

        impl<const N_WORDS: usize> core::ops::Shr<$t> for Bitset<N_WORDS> {
            type Output = Self;

            #[inline]
            fn shr(mut self, rhs: $t) -> Self::Output {
                self >>= rhs;
                self
            }
        }

        impl<const N_WORDS: usize> core::ops::ShrAssign<$t> for Bitset<N_WORDS> {
            #[inline]
            fn shr_assign(&mut self, rhs: $t) {
                // This comparison is a no-op for unsigned $t, but required for signed $t.
                #[allow(unused_comparisons)]
                if rhs < 0 {
                    panic!("negative shift");
                }

                // Cast may fail on 16b usize, see comment in unbounded_shl.
                let rhs: usize = rhs.try_into().unwrap();
                if rhs >= Self::N_BITS {
                    panic!("attempt to shift left with overflow");
                }

                self.unbounded_shr_inplace(rhs.try_into().unwrap());
            }
        }
    };
}

shift_impl!(u8);
shift_impl!(u16);
shift_impl!(u32);
shift_impl!(u64);
shift_impl!(u128);

shift_impl!(i8);
shift_impl!(i16);
shift_impl!(i32);
shift_impl!(i64);
shift_impl!(i128);

shift_impl!(usize);
shift_impl!(isize);

impl<const N_WORDS: usize> From<[u64; N_WORDS]> for Bitset<N_WORDS> {
    #[inline]
    fn from(value: [u64; N_WORDS]) -> Self {
        Self(value)
    }
}

impl<const N_WORDS: usize> From<Bitset<N_WORDS>> for [u64; N_WORDS] {
    #[inline]
    fn from(value: Bitset<N_WORDS>) -> Self {
        value.0
    }
}

impl<const N_WORDS: usize> FromIterator<usize> for Bitset<N_WORDS> {
    fn from_iter<I: IntoIterator<Item = usize>>(iter: I) -> Self {
        let mut ret = Self::EMPTY;

        for bit in iter {
            ret.set(bit);
        }

        ret
    }
}

impl<'a, const N_WORDS: usize> FromIterator<&'a usize> for Bitset<N_WORDS> {
    #[inline]
    fn from_iter<I: IntoIterator<Item = &'a usize>>(iter: I) -> Self {
        Self::from_iter(iter.into_iter().copied())
    }
}

#[inline]
const fn word_idx(bit: usize) -> usize {
    bit / 64
}

#[inline]
const fn subword_idx(bit: usize) -> u64 {
    const MASK: usize = 63;

    1 << (bit & MASK)
}

/// Like go's `bits.Len64`: compute the number of bits required to represent
/// `val`.
#[inline]
const fn len(val: u64) -> usize {
    (u64::BITS - val.leading_zeros()) as _
}

#[cfg(test)]
mod test {
    use std::vec::Vec;

    use proptest::prelude::{Rng, Strategy};

    use super::*;

    #[test]
    fn is_empty() {
        let bs = Bitset256::EMPTY;
        assert!(bs.is_empty());
        assert_eq!(0, bs.count_ones());

        for w in bs.word_iter() {
            assert_eq!(0, w);
        }
    }

    #[test]
    fn first_last_set() {
        assert_eq!(None, Bitset256::EMPTY.first_set());
        assert_eq!(Some(0), Bitset256::EMPTY.with_bit(0).first_set());

        assert_eq!(None, Bitset256::EMPTY.last_set());
        assert_eq!(Some(0), Bitset256::EMPTY.with_bit(0).last_set());
    }

    #[test]
    fn debug_impl() {
        // Run tests with `cargo test -- --nocapture` to see this output
        std::println!("{:?}", Bitset256::EMPTY);
        std::println!(
            "{:?}",
            Bitset256::EMPTY
                .with_bit(0)
                .with_bit(8)
                .with_bit(64)
                .with_bit(63)
        );
    }

    #[test]
    fn bits_after() {
        let bs = Bitset256::EMPTY.with_bits(&[1, 2, 3]);

        assert_eq!(3, bs.bits().count());
        assert_eq!(3, bs.bits_after(0).count());
        assert_eq!(2, bs.bits_after(1).count());
        assert_eq!(1, bs.bits_after(2).count());

        for i in 3u8..=255 {
            assert_eq!(0, bs.bits_after(i).count());
        }
    }

    #[test]
    fn with_bits_upto() {
        let bs = Bitset256::with_bits_upto(0);
        assert!(bs.is_empty());

        let bs = Bitset256::with_bits_upto(1);
        assert_eq!(1, bs.count_ones());

        let bs = Bitset256::with_bits_upto(63);
        assert_eq!(63, bs.count_ones());

        let bs = Bitset256::with_bits_upto(64);
        assert_eq!(64, bs.count_ones());
        assert_eq!(u64::MAX, bs.0[0]);
        assert_eq!(0, bs.0[1]);
        assert_eq!(0, bs.0[2]);
        assert_eq!(0, bs.0[3]);

        let bs = Bitset256::with_bits_upto(256);
        assert_eq!(256, bs.count_ones());

        let bs = Bitset::<1>::with_bits_upto(0);
        assert!(bs.is_empty());

        let bs = Bitset::<1>::with_bits_upto(1);
        assert!(bs.test(0));
        assert!(!bs.test(1));

        let bs = Bitset::<1>::with_bits_upto(63);
        assert_eq!(63, bs.count_ones());

        let bs = Bitset::<1>::with_bits_upto(64);
        assert_eq!(64, bs.count_ones());
    }

    #[test]
    #[should_panic]
    fn with_bits_upto_overflow() {
        Bitset256::with_bits_upto(321);
    }

    #[test]
    fn shl() {
        // Exhaustive checking of every non-destructive left shift of a one-hot bitset,
        // as well as a zero shift and the shift amount that loses the hot bit.
        for i in 0..256 {
            let destructive_shift_amt = 256 - i;
            let bs = Bitset256::EMPTY.with_bit(i);
            assert_eq!(bs << 0usize, bs);
            for shift in 1..destructive_shift_amt {
                let shifted = bs << shift;
                assert_eq!(shifted.count_ones(), bs.count_ones());
                assert_eq!(shifted.first_set(), Some(i + shift));
            }
            assert_eq!(
                bs.unbounded_shl(destructive_shift_amt as u32),
                Bitset256::EMPTY
            );
        }
    }

    #[test]
    fn shr() {
        // Exhaustive checking of every non-destructive right shift of a one-hot bitset,
        // as well as a zero shift and the shift amount that loses the hot bit.
        for i in 0..256 {
            let destructive_shift_amt = 256 - i;
            let bs = Bitset256::EMPTY.with_bit(255 - i);
            assert_eq!(bs >> 0usize, bs);
            for shift in 1..destructive_shift_amt {
                let shifted = bs >> shift;
                assert_eq!(shifted.count_ones(), bs.count_ones());
                assert_eq!(shifted.first_set(), Some(255 - i - shift));
            }
            assert_eq!(
                bs.unbounded_shr(destructive_shift_amt as u32),
                Bitset256::EMPTY
            );
        }
    }

    #[test]
    #[should_panic]
    fn shl_overflow() {
        let bs = Bitset256::EMPTY.with_bit(0);
        let _ = bs << 256;
    }

    #[test]
    #[should_panic]
    fn shr_overflow() {
        let bs = Bitset256::EMPTY.with_bit(0);
        let _ = bs >> 256;
    }

    proptest::prop_compose! {
        fn bitset()(bs: [u64; 4]) -> Bitset256 {
            Bitset(bs)
        }
    }

    proptest::prop_compose! {
        fn bitvec()(elts: Vec<u8>) -> Vec<usize> {
            let mut elts: Vec<usize>  = elts.into_iter().map(Into::into).collect();

            elts.sort();
            elts.dedup();

            elts
        }
    }

    fn nonempty_bitvec() -> impl Strategy<Value = Vec<usize>> {
        bitvec().prop_perturb(|mut v, mut rng| {
            if v.is_empty() {
                v.push(rng.random::<u8>() as usize);
            }

            v
        })
    }

    proptest::proptest! {
        #[test]
        fn is_empty_size_exhaustive(bits in bitvec()) {
            let bs  = Bitset256::from_iter(&bits);
            proptest::prop_assert_eq!(bits.len(), bs.count_ones());

            if bits.is_empty() {
                proptest::prop_assert!(bs.is_empty());
            } else {
                proptest::prop_assert!(!bs.is_empty());
            }
        }

        #[test]
        fn set(i: u8) {
            let mut bs = Bitset256::EMPTY;
            bs.set(i as _);

            proptest::prop_assert_eq!(1, bs.count_ones());
            proptest::prop_assert!(!bs.is_empty());

            proptest::prop_assert_eq!(Bitset256::EMPTY.with_bit(i as _), bs);
        }

        #[test]
        fn first_last_set_multi(bits in nonempty_bitvec()) {
            let bs = Bitset256::from_iter(&bits);

            proptest::prop_assert!(!bs.is_empty());
            proptest::prop_assert_eq!(bits.len(), bs.count_ones());

            proptest::prop_assert_eq!(bits.first().copied(), bs.first_set());
            proptest::prop_assert_eq!(bits.last().copied(), bs.last_set());
        }

        #[test]
        fn bits(bits in bitvec()) {
            let bs = Bitset256::from_iter(&bits);

            proptest::prop_assert_eq!(bits.len(), bs.count_ones());
            proptest::prop_assert_eq!(bits, bs.bits().collect::<Vec<usize>>());
        }

        #[test]
        fn next_set_empty(i: u8) {
            proptest::prop_assert_eq!(None, Bitset256::EMPTY.next_set(i as _));
        }

        #[test]
        fn next_set_single(i: u8) {
            let bs = Bitset256::EMPTY.with_bit(i as _);

            for j in 0..=i {
                proptest::prop_assert_eq!(Some(i as usize), bs.next_set(j as usize));
            }

            let Some(upper) = i.checked_add(1) else {
                // i == 255, so can't check any further values
                return Ok(());
            };

            for j in upper..=255 {
                proptest::prop_assert_eq!(None, bs.next_set(j as usize));
            }
        }

        #[test]
        fn next_set_multi(bits in nonempty_bitvec()) {
            let bs = Bitset256::from_iter(&bits);

            for i in 0..=bits[0] {
                proptest::prop_assert_eq!(Some(bits[0]), bs.next_set(i));
            }

            for window in bits.windows(2) {
                let &[this, next] = window else {
                    unreachable!();
                };

                for i in (this + 1)..=next {
                    proptest::prop_assert_eq!(Some(next), bs.next_set(i));
                }
            }

            let Some(last) = bits.last().unwrap().checked_add(1) else {
                // last == 255
                return Ok(());
            };

            for i in last..=255 {
                proptest::prop_assert_eq!(None, bs.next_set(i));
            }
        }

        #[test]
        fn union(mut bits in bitvec(), other in bitvec()) {
            let union = Bitset256::from_iter(&bits) | Bitset256::from_iter(&other);

            bits.extend(other);
            bits.sort();
            bits.dedup();

            proptest::prop_assert_eq!(bits, union.bits().collect::<Vec<usize>>());
        }

        #[test]
        fn intersection(bits in bitvec(), other in bitvec()) {
            let bs1 = Bitset256::from_iter(&bits);
            let bs2 = Bitset256::from_iter(&other);

            let intersect = bs1 & bs2;

            let mut calced_intersect = std::collections::BTreeSet::from_iter(bits).intersection(&std::collections::BTreeSet::from_iter(other))
            .copied()
            .collect::<Vec<usize>>();
            calced_intersect.sort();

            let should_intersect = !calced_intersect.is_empty();
            let does_intersect = bs1.intersects(&bs2);
            proptest::prop_assert!(should_intersect == does_intersect);

            proptest::prop_assert_eq!(calced_intersect, intersect.bits().collect::<Vec<usize>>());
        }

        #[test]
        fn intersection_top(i: u8, mut bits in bitset(), mut other in bitset()) {
            for j in i..=255 {
                bits.clear(j as usize);
                other.clear(j as usize);
            }

            bits.set(i as _);
            other.set(i as _);

            proptest::prop_assert_eq!(Some(i as usize), bits.intersection_top(&other));
        }

        #[test]
        fn shifts(shift_amt in 0u32..257, bits in nonempty_bitvec()) {
            let bs = Bitset256::from_iter(&bits);

            let left = bs.unbounded_shl(shift_amt);
            proptest::prop_assert!(left.count_ones() <= bs.count_ones());
            let right = left.unbounded_shr(shift_amt);
            proptest::prop_assert_eq!(right.count_ones(), left.count_ones());
            proptest::prop_assert_eq!(bs | right, bs);

            let right = bs.unbounded_shr(shift_amt);
            proptest::prop_assert!(right.count_ones() <= bs.count_ones());
            let left = right.unbounded_shl(shift_amt);
            proptest::prop_assert_eq!(left.count_ones(), right.count_ones());
            proptest::prop_assert_eq!(bs | left, bs);
        }
    }
}
