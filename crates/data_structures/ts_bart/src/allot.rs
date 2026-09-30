//! Fast prefix coverage queries.

use core::borrow::Borrow;

use ts_bitset::Bitset256;

use crate::base_index::BaseIndex;

// The `impl Borrow` returns allow us to return either the bitset or a
// 'static reference to one in the table independent of the "lut" flag.

/// Returns the bitsets for base indices 1..255 (prefixes up to /7).
/// For each `index`, the returned bitset contains all descendant (strictly
/// more-specific) indices in that are covered by the prefix indicated by
/// `index`.
///
/// # Examples
///
/// ```rust
/// # use core::borrow::Borrow;
/// # use ts_bart::BaseIndex;
/// # use ts_bitset::Bitset256;
/// let idx = BaseIndex::from_prefix(0, 0);
/// let prefixes = ts_bart::allot_prefix(idx);
/// let prefixes = prefixes.borrow();
/// let test_idx = BaseIndex::from_prefix(0, 5);
/// assert!(prefixes.intersects(&Bitset256::EMPTY.with_bit(test_idx.get() as _)));
/// ```
pub const fn prefix(index: BaseIndex) -> impl Borrow<Bitset256> + 'static {
    cfg_if::cfg_if! {
        if #[cfg(feature = "lut")] {
            &lut::PREFIX[index.get() as usize]
        } else {
            entry(index.get() as _).0
        }
    }
}

/// The returned bitset contains all `/8` fringe indices covered by the prefix
/// at `index`. This is essentially the 9th-bit extension of [`prefix`], where
/// we're using a priori knowledge to select the meaning of [`BaseIndex`]: a
/// "fringe" index is actually the index value plus 256 in terms of Knuth's
/// encoding.
pub const fn fringe(index: BaseIndex) -> impl Borrow<Bitset256> + 'static {
    cfg_if::cfg_if! {
        if #[cfg(feature = "lut")] {
            &lut::FRINGE[index.get() as usize]
        } else {
            entry(index.get() as _).1
        }
    }
}

#[cfg(feature = "lut")]
mod lut {
    use super::*;

    const fn build_tables() -> ([Bitset256; 256], [Bitset256; 256]) {
        let mut prefix = [Bitset256::EMPTY; 256];
        let mut fringe = [Bitset256::EMPTY; 256];

        let mut i = 1;
        while i < 256 {
            (prefix[i], fringe[i]) = entry(i);
            i += 1;
        }

        (prefix, fringe)
    }

    static LUTS: ([Bitset256; 256], [Bitset256; 256]) = build_tables();

    pub const PREFIX: &[Bitset256; 256] = &LUTS.0;
    pub const FRINGE: &[Bitset256; 256] = &LUTS.1;

    /// Memory usage for `allot` lookup tables.
    pub const SIZE: usize = size_of_val(&LUTS);
}

#[cfg(feature = "lut")]
pub use lut::SIZE as LUT_SIZE;

const fn entry(idx: usize) -> (Bitset256, Bitset256) {
    let mut stack = [0usize; 512];
    let mut len = 0;

    stack[0] = idx;
    len += 1;

    let mut pfx = Bitset256::EMPTY;
    let mut fringe = Bitset256::EMPTY;

    let mut i = 0;
    while i < len {
        let j = stack[i];
        i += 1;

        if j < 256 {
            pfx.set(j);
        } else {
            fringe.set(j % 256);
        }

        if j >= 256 {
            continue;
        }

        stack[len] = j * 2;
        stack[len + 1] = j * 2 + 1;
        len += 2;
    }

    (pfx, fringe)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn compare_bart() {
        // Smoke test: ensure match with a few samples from bart's generated tables.
        for (idx, (pfx, fringe)) in [
            (1, (Bitset256::FULL.without_bit(0), Bitset256::FULL)),
            (
                26,
                (
                    Bitset256::from([0x30000004000000, 0xf0000000000, 0, 0xff0000]),
                    Bitset256::from([0, 0, 0xffff00000000, 0]),
                ),
            ),
            (
                255,
                (
                    Bitset256::EMPTY.with_bit(255),
                    Bitset256::EMPTY.with_bits(&[254, 255]),
                ),
            ),
        ] {
            let (calc_pfx, calc_fringe) = entry(idx);

            assert_eq!(pfx, calc_pfx);
            assert_eq!(fringe, calc_fringe);
        }
    }
}
