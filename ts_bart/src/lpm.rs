//! Longest prefix match, following from the bart module of the same name.

use core::borrow::Borrow;

use ts_bitset::Bitset256;

use crate::base_index::BaseIndex;

/// Retrieve the bitset that can be used to calculate the longest prefix match
/// for the given `index` in one shot.
///
/// # Example
///
/// ```rust
/// # use core::borrow::Borrow;
/// # use ts_bart::BaseIndex;
/// # use ts_bitset::Bitset256;
/// let prefix_set = Bitset256::EMPTY.with_bit(1);
/// let index = BaseIndex::from_pfx_7(1);
/// assert!(prefix_set.intersects(ts_bart::lpm(index).borrow()));
/// ```
pub const fn lookup(index: BaseIndex) -> impl Borrow<Bitset256> + 'static {
    // The `impl Borrow` return allows us to return either the bitset or a
    // 'static reference to one in the table independent of the "lut" flag.
    cfg_if::cfg_if! {
        if #[cfg(feature = "lut")] {
            &LUT[index.get() as usize]
        } else {
            lpm_entry(index.get())
        }
    }
}

const fn lpm_entry(i: u8) -> Bitset256 {
    let mut entry = Bitset256::EMPTY;

    let mut j = i;

    while j > 0 {
        entry.set(j as _);
        j = j.unbounded_shr(1);
    }

    entry
}

#[cfg(feature = "lut")]
static LUT: [Bitset256; 256] = {
    let mut ret = [Bitset256::EMPTY; 256];

    // for/iterators don't work in const
    let mut i = 1usize;
    while i < ret.len() {
        ret[i] = lpm_entry(i as u8);
        i += 1;
    }

    ret
};

#[cfg(feature = "lut")]
pub const LUT_SIZE: usize = size_of_val(&LUT);
