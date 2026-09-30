#![doc = include_str!("../README.md")]
//! A dynamically-growable bitset built around a [`smallvec::SmallVec`] of [`ts_bitset`]s.

#![no_std]

extern crate alloc;
#[cfg(test)]
extern crate std;

use core::ops::{BitAnd, BitAndAssign, BitOr, BitOrAssign};

use ts_bitset::{BitsetDyn, BitsetStatic, ConstBitset};

/// A dynamically-growable bitset of `WORDS * VEC_SIZE` 64-bit words.
///
/// Only allocates if a bit is set with an index greater than `64 * WORDS * VEC_SIZE`.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DynBitset<const WORDS: usize = 1, const VEC_SIZE: usize = 1> {
    inner: smallvec::SmallVec<[ts_bitset::Bitset<WORDS>; VEC_SIZE]>,
}

impl<const WORDS: usize, const VEC_SIZE: usize> DynBitset<WORDS, VEC_SIZE> {
    const BITSET_WIDTH: usize = WORDS * 64;

    /// Shrink the backing storage to fit the actual set bits.
    ///
    /// This method may trigger a heap-to-inline copy or heap allocation resize.
    pub fn shrink_to_fit(&mut self) {
        self.inner.shrink_to_fit();
    }

    /// Clear all set bits.
    pub fn clear_all(&mut self) {
        self.inner.clear();
    }

    /// Zero all bits after and including the specified bit.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ts_dynbitset::DynBitset;
    /// # use ts_bitset::{BitsetDyn, BitsetStatic};
    /// let mut bs = DynBitset::<1, 1>::empty().with_bits(&[1, 2, 3, 4]);
    ///
    /// bs.zero_from(4);
    /// assert!(!bs.test(4));
    /// assert!(bs.test(3));
    ///
    /// bs.zero_from(0);
    /// assert!(!bs.test(1));
    ///
    /// bs.set(65);
    /// bs.zero_from(0);
    /// assert!(bs.is_empty());
    /// ```
    pub fn zero_from(&mut self, bit_inclusive: usize) {
        let (word, idx) = Self::bitset_and_idx(bit_inclusive);

        self.inner.truncate(word + 1);

        let Some(word) = self.inner.get_mut(word) else {
            return;
        };

        let mask = ts_bitset::Bitset::with_bits_upto(idx);
        word.intersect_inplace(&mask);

        self.truncate_empty();
    }

    fn ensure_capacity(&mut self, bit: usize) {
        let (bitset, _) = Self::bitset_and_idx(bit);

        while self.inner.len() <= bitset {
            self.inner.push(Default::default());
        }
    }

    fn bitset_and_idx(bit: usize) -> (usize, usize) {
        let bitset = bit / Self::BITSET_WIDTH;
        let idx = bit % Self::BITSET_WIDTH;

        (bitset, idx)
    }

    fn get_bitset_and_idx(&self, bit: usize) -> (Option<&ts_bitset::Bitset<WORDS>>, usize) {
        let (bitset, idx) = Self::bitset_and_idx(bit);
        (self.inner.get(bitset), idx)
    }

    fn truncate_empty(&mut self) {
        while self.inner.last().is_some_and(|x| x.is_empty()) {
            self.inner.pop();
        }
    }
}

impl<const WORDS: usize, const VEC_SIZE: usize> BitsetDyn for DynBitset<WORDS, VEC_SIZE> {
    fn n_bits(&self) -> Option<usize> {
        None
    }

    fn set(&mut self, bit: usize) {
        self.ensure_capacity(bit);

        let (bitset, idx) = Self::bitset_and_idx(bit);
        let bitset = &mut self.inner[bitset];

        bitset.set(idx);
    }

    fn clear(&mut self, bit: usize) {
        let (bitset_idx, idx) = Self::bitset_and_idx(bit);

        let Some(bitset) = self.inner.get_mut(bitset_idx) else {
            return;
        };

        bitset.clear(idx);

        self.truncate_empty();
    }

    fn test(&self, bit: usize) -> bool {
        let (Some(bitset), idx) = self.get_bitset_and_idx(bit) else {
            return false;
        };

        bitset.test(idx)
    }

    fn first_set(&self) -> Option<usize> {
        for (bs_idx, bitset) in self.inner.iter().enumerate() {
            if let Some(s) = bitset.first_set() {
                return Some(bs_idx * 64 + s);
            }
        }

        None
    }

    fn next_set(&self, bit: usize) -> Option<usize> {
        let (starting_bitset_idx, idx) = Self::bitset_and_idx(bit);

        for i in starting_bitset_idx..self.inner.len() {
            let bitset = &self.inner[i];

            let query = if i == starting_bitset_idx { idx } else { 0 };

            if let Some(x) = bitset.next_set(query) {
                return Some(x + i * Self::BITSET_WIDTH);
            }
        }

        None
    }

    fn last_set(&self) -> Option<usize> {
        self.inner
            .iter()
            .enumerate()
            .rev()
            .find_map(|(i, x)| x.last_set().map(|x| x + i * Self::BITSET_WIDTH))
    }

    fn is_empty(&self) -> bool {
        self.inner.iter().all(|x| x.is_empty())
    }

    fn count_ones(&self) -> usize {
        self.inner.iter().map(|x| x.count_ones()).sum()
    }

    fn invert_inplace(&mut self) {
        self.inner.iter_mut().for_each(|x| x.invert_inplace());
        self.truncate_empty();
    }
}

impl<const WORDS: usize, const VEC_SIZE: usize> ts_bitset::BitsetStatic
    for DynBitset<WORDS, VEC_SIZE>
{
    fn empty() -> Self {
        Self {
            inner: smallvec::SmallVec::new_const(),
        }
    }

    fn with_bit(mut self, bit: usize) -> Self {
        self.set(bit);
        self
    }

    fn with_bits(mut self, bits: &[usize]) -> Self {
        for &bit in bits {
            self.set(bit);
        }

        self
    }

    fn without_bit(mut self, bit: usize) -> Self {
        self.clear(bit);
        self.truncate_empty();

        self
    }

    fn without_bits(mut self, bits: &[usize]) -> Self {
        for &bit in bits {
            self.clear(bit);
        }

        self.truncate_empty();

        self
    }

    fn intersection_top(&self, other: &Self) -> Option<usize> {
        self.inner
            .iter()
            .enumerate()
            .zip(&other.inner)
            .rev()
            .find_map(|((i, this), other)| {
                this.intersection_top(other)
                    .map(|x| x + i * Self::BITSET_WIDTH)
            })
    }

    fn intersects(&self, other: &Self) -> bool {
        self.inner
            .iter()
            .zip(&other.inner)
            .any(|(x, y)| x.intersects(y))
    }

    fn union_inplace(&mut self, other: &Self) {
        self.inner
            .iter_mut()
            .zip(&other.inner)
            .for_each(|(x, y)| x.union_inplace(y));

        if let Some((_, rem_other)) = other.inner.split_at_checked(self.inner.len()) {
            self.inner.extend_from_slice(rem_other);
        }
    }

    fn intersect_inplace(&mut self, other: &Self) {
        self.inner.truncate(other.inner.len());

        self.inner
            .iter_mut()
            .zip(&other.inner)
            .for_each(|(x, y)| x.intersect_inplace(y));

        self.truncate_empty();
    }

    fn bits(&self) -> impl Iterator<Item = usize> {
        self.inner
            .iter()
            .enumerate()
            .flat_map(|(idx, bitset)| bitset.bits().map(move |x| x + idx * Self::BITSET_WIDTH))
    }
}

impl<const WORDS: usize, const VEC_SIZE: usize> ConstBitset for DynBitset<WORDS, VEC_SIZE> {
    const EMPTY: Self = Self {
        inner: smallvec::SmallVec::new_const(),
    };

    const BITS: Option<usize> = None;
}

impl<const WORDS: usize, const VEC_SIZE: usize> FromIterator<usize> for DynBitset<WORDS, VEC_SIZE> {
    fn from_iter<T: IntoIterator<Item = usize>>(iter: T) -> Self {
        let mut out = DynBitset::EMPTY;

        for bit in iter {
            out.set(bit);
        }

        out.truncate_empty();

        out
    }
}

impl<'a, const WORDS: usize, const VEC_SIZE: usize> FromIterator<&'a usize>
    for DynBitset<WORDS, VEC_SIZE>
{
    fn from_iter<T: IntoIterator<Item = &'a usize>>(iter: T) -> Self {
        Self::from_iter(iter.into_iter().copied())
    }
}

impl<const WORDS: usize, const VEC_SIZE: usize> BitAnd for DynBitset<WORDS, VEC_SIZE> {
    type Output = Self;

    fn bitand(mut self, rhs: Self) -> Self::Output {
        self.intersect_inplace(&rhs);
        self
    }
}

impl<const WORDS: usize, const VEC_SIZE: usize> BitOr for DynBitset<WORDS, VEC_SIZE> {
    type Output = Self;

    fn bitor(mut self, rhs: Self) -> Self::Output {
        self.union_inplace(&rhs);
        self
    }
}

impl<const WORDS: usize, const VEC_SIZE: usize> BitAndAssign for DynBitset<WORDS, VEC_SIZE> {
    fn bitand_assign(&mut self, rhs: Self) {
        self.intersect_inplace(&rhs);
    }
}

impl<const WORDS: usize, const VEC_SIZE: usize> BitOrAssign for DynBitset<WORDS, VEC_SIZE> {
    fn bitor_assign(&mut self, rhs: Self) {
        self.union_inplace(&rhs);
    }
}

#[cfg(test)]
mod test {
    use alloc::vec::Vec;

    use proptest::prelude::{Rng, Strategy};
    use ts_bitset::{BitsetDyn, BitsetStatic, ConstBitset};

    use super::*;

    type TestBitset = DynBitset<1, 4>;

    #[test]
    fn basic() {
        let mut bitset = TestBitset::EMPTY.with_bit(1);
        assert!(bitset.test(1));
        assert!(!bitset.test(2));
        assert!(!bitset.test(4096));

        bitset.set(4096);
        assert!(bitset.test(4096));
    }

    #[test]
    fn is_empty() {
        let bs = TestBitset::EMPTY;
        assert!(bs.is_empty());
        assert_eq!(0, bs.count_ones());

        for w in bs.inner.iter() {
            assert!(w.is_empty());
        }
    }

    #[test]
    fn first_last_set() {
        assert_eq!(None, TestBitset::EMPTY.first_set());
        assert_eq!(Some(0), TestBitset::EMPTY.with_bit(0).first_set());

        assert_eq!(None, TestBitset::EMPTY.last_set());
        assert_eq!(Some(0), TestBitset::EMPTY.with_bit(0).last_set());
    }

    #[test]
    fn debug_impl() {
        // Run tests with `cargo test -- --nocapture` to see this output
        std::println!("{:?}", TestBitset::EMPTY);
        std::println!(
            "{:?}",
            TestBitset::EMPTY
                .with_bit(0)
                .with_bit(8)
                .with_bit(64)
                .with_bit(63)
        );
    }

    #[test]
    fn next_set_64() {
        let bs = TestBitset::EMPTY.with_bit(64 as _);

        for j in 0..=64 {
            assert_eq!(Some(64), bs.next_set(j as usize), "next_set({j})");
        }
    }

    #[test]
    fn set_on_boundary() {
        let bs = TestBitset::EMPTY.with_bit(64);

        assert!(bs.test(64));
        assert_eq!(bs.inner.len(), 2);
    }

    #[test]
    fn intersection_top_multi_word() {
        let bs = TestBitset::EMPTY.with_bits(&[0, 64]);
        std::println!("{bs:?}");

        let intersection = bs.intersection_top(&bs);
        assert_eq!(Some(64), intersection);
    }

    proptest::prop_compose! {
        fn bitset()(bs: [u64; 4]) -> TestBitset {
            let mut out = TestBitset {
                inner: smallvec::smallvec![
                    ts_bitset::Bitset::from([bs[0]]),
                    ts_bitset::Bitset::from([bs[1]]),
                    ts_bitset::Bitset::from([bs[2]]),
                    ts_bitset::Bitset::from([bs[3]]),
                ]
            };

            out.truncate_empty();

            out
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
            let bs  = TestBitset::from_iter(&bits);
            proptest::prop_assert_eq!(bits.len(), bs.count_ones());

            if bits.is_empty() {
                proptest::prop_assert!(bs.is_empty());
            } else {
                proptest::prop_assert!(!bs.is_empty());
            }
        }

        #[test]
        fn set(i: u8) {
            let mut bs = TestBitset::EMPTY;
            bs.set(i as _);

            proptest::prop_assert_eq!(1, bs.count_ones());
            proptest::prop_assert!(!bs.is_empty());

            proptest::prop_assert_eq!(TestBitset::EMPTY.with_bit(i as _), bs);
        }

        #[test]
        fn first_last_set_multi(bits in nonempty_bitvec()) {
            let bs = TestBitset::from_iter(&bits);

            proptest::prop_assert!(!bs.is_empty());
            proptest::prop_assert_eq!(bits.len(), bs.count_ones());

            proptest::prop_assert_eq!(bits.first().copied(), bs.first_set());
            proptest::prop_assert_eq!(bits.last().copied(), bs.last_set());
        }

        #[test]
        fn bits(bits in bitvec()) {
            let bs = TestBitset::from_iter(&bits);

            proptest::prop_assert_eq!(bits.len(), bs.count_ones());
            proptest::prop_assert_eq!(bits, bs.bits().collect::<Vec<usize>>());
        }

        #[test]
        fn next_set_empty(i: u8) {
            proptest::prop_assert_eq!(None, TestBitset::EMPTY.next_set(i as _));
        }

        #[test]
        fn next_set_single(i: u8) {
            let bs = TestBitset::EMPTY.with_bit(i as _);

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
            let bs = TestBitset::from_iter(&bits);

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
            let union = TestBitset::from_iter(&bits) | TestBitset::from_iter(&other);

            bits.extend(other);
            bits.sort();
            bits.dedup();

            proptest::prop_assert_eq!(bits, union.bits().collect::<Vec<usize>>());
        }

        #[test]
        fn intersection(bits in bitvec(), other in bitvec()) {
            let bs1 = TestBitset::from_iter(&bits);
            let bs2 = TestBitset::from_iter(&other);

            let intersect = bs1.clone() & bs2.clone();

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
    }
}
