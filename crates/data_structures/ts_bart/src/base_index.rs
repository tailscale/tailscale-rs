//! Prefix mapping described in Hariguchi's Allotment Routing Table paper.
//!
//! Ported fairly literally from the golang bart repo (where this file is
//! `internal/art.go`).

use core::{
    fmt::{Debug, Display, Formatter},
    num::NonZeroU8,
};

/// A "base index" as described in Hariguchi's ART paper; a linearized address
/// for a prefix/octet tuple when considering the hierarchy of possible prefixes
/// for a given 8-bit address.
///
/// Note that this only covers up to /7, fringes (/8s) would require a ninth
/// bit, which is encoded structurally in the trie as `children` (vs
/// `prefixes`).
#[repr(transparent)]
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BaseIndex(pub NonZeroU8);

impl Debug for BaseIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        let (pfx, bits) = self.prefix();
        write!(f, "BaseIndex({} => {pfx}/{bits})", self.0.get())
    }
}

impl Display for BaseIndex {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        Display::fmt(&self.0.get(), f)
    }
}

impl BaseIndex {
    /// Construct a new index value.
    ///
    /// # Panics
    ///
    /// If `val` is zero.
    pub const fn new(val: u8) -> Self {
        Self::try_new(val).expect("index value was zero")
    }

    /// Construct a new index value. Fails if the value is zero.
    pub const fn try_new(val: u8) -> Option<Self> {
        let Some(idx) = NonZeroU8::new(val) else {
            return None;
        };

        Some(Self(idx))
    }

    /// Retrieve the value of this index in its `u8` representation.
    pub const fn get(&self) -> u8 {
        self.0.get()
    }

    /// Maps 8-bit prefixes to numbers. The prefixes range from 0/0 to 255/7.
    /// Return values range from 1 to 255.
    ///
    /// # Panics
    ///
    /// If `prefix_len` >= 8.
    pub const fn from_prefix(octet: u8, prefix_len: u8) -> Self {
        assert!(
            prefix_len <= 7,
            "BaseIndex prefix length must be between 0 and 7"
        );
        BaseIndex::new(octet.unbounded_shr(8 - prefix_len as u32) + (1 << prefix_len))
    }

    /// Maps octet/7 prefixes to indices in `128..255`. Optimization over
    /// [`Self::from_prefix`] which saves a little bit of math if the prefix
    /// length is known to be `/7`.
    pub const fn from_pfx_7(octet: u8) -> Self {
        let ret = Self::new(0x80 + (octet.unbounded_shr(1)));
        debug_assert!(ret.prefix().1 == 7);
        ret
    }

    /// Computes the octet and prefix len of this index.
    /// Inverse of [`Self::from_prefix`].
    pub const fn prefix(self) -> (u8, u8) {
        let pfx_len = self.len() - 1;

        let shift_bits = 8 - pfx_len;
        let mask = 0xffu8.unbounded_shr(shift_bits as _);

        let octet = (self.get() & mask).unbounded_shl(shift_bits as _);

        (octet, pfx_len)
    }

    /// Compute the bit position of a prefix represented by this index at a
    /// given trie depth.
    pub const fn prefix_bits(&self, depth: usize) -> u8 {
        let pfx_len_in_stride = self.len() - 1;
        let base_bits = depth * 8;

        base_bits as u8 + pfx_len_in_stride
    }

    /// Range of octets covered by this index.
    ///
    /// This base index encodes a prefix of up to 8 bits inside a single stride
    /// (octet). This function computes the numerical start and end of the value
    /// range for that prefix.
    pub const fn range(&self) -> core::ops::RangeInclusive<u8> {
        let (first, pfx_len) = self.prefix();
        let last = first | !net_mask(pfx_len);

        first..=last
    }

    /// Like go's `bits.Len8`: compute the number of bits required to represent
    /// this index.
    #[allow(clippy::len_without_is_empty)]
    pub const fn len(&self) -> u8 {
        (u8::BITS - self.get().leading_zeros()) as _
    }

    /// Sort indexes in prefix sort order.
    pub fn cmp_rank(&self, other: &Self) -> core::cmp::Ordering {
        let (a_octet, a_bits) = self.prefix();
        let (b_octet, b_bits) = other.prefix();

        a_octet.cmp(&b_octet).then(a_bits.cmp(&b_bits))
    }

    /// Return a formatter for prefix notation: `addr/len`.
    pub const fn fmt_prefix(&self) -> impl Debug + use<> {
        struct PrefixFormatter(u8, u8);
        impl Debug for PrefixFormatter {
            fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
                write!(f, "{}/{}", self.0, self.1)
            }
        }

        let (prefix, bits) = self.prefix();
        PrefixFormatter(prefix, bits)
    }

    /// Return the direct parent of this index (if it's not the 0/0 index).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ts_bart::BaseIndex;
    /// let idx = BaseIndex::from_prefix(0, 4);
    /// assert_eq!(idx.parent(), Some(BaseIndex::from_prefix(0, 3)));
    /// ```
    pub const fn parent(&self) -> Option<BaseIndex> {
        let val = self.0.get();
        if val == 1 {
            return None;
        }

        Some(BaseIndex::new(val / 2))
    }

    /// Return the two direct children of this index (if it's not a /7).
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ts_bart::BaseIndex;
    /// let idx = BaseIndex::from_prefix(0, 0);
    /// assert_eq!(
    ///     idx.children(),
    ///     Some((BaseIndex::from_prefix(0, 1), BaseIndex::from_prefix(128, 1)))
    /// );
    /// ```
    pub const fn children(&self) -> Option<(BaseIndex, BaseIndex)> {
        let val = self.0.get();
        if val >= 128 {
            return None;
        }

        Some((BaseIndex::new(val * 2), BaseIndex::new(val * 2 + 1)))
    }
}

impl From<BaseIndex> for u8 {
    fn from(value: BaseIndex) -> Self {
        value.get()
    }
}

impl From<BaseIndex> for NonZeroU8 {
    fn from(value: BaseIndex) -> Self {
        value.0
    }
}

impl From<NonZeroU8> for BaseIndex {
    fn from(value: NonZeroU8) -> Self {
        Self(value)
    }
}

impl TryFrom<u8> for BaseIndex {
    type Error = ();

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        Self::try_new(value).ok_or(())
    }
}

/// 8-bit left-aligned network mask for the given number of prefix bits.
pub const fn net_mask(bits: u8) -> u8 {
    assert!(bits <= 8);

    0xffu8.unbounded_shl((8 - bits) as _)
}

/// Ported directly from bart.
#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_octet_to_idx() {
        assert_eq!(128, BaseIndex::from_pfx_7(0).get());
        assert_eq!(255, BaseIndex::from_pfx_7(255).get());
        assert_eq!(192, BaseIndex::from_pfx_7(128).get());
    }

    #[test]
    fn test_pfx_bits() {
        assert_eq!(0, BaseIndex::new(1).prefix_bits(0));
        assert_eq!(4, BaseIndex::new(19).prefix_bits(0));
        assert_eq!(124, BaseIndex::new(19).prefix_bits(15));
    }

    #[test]
    fn test_pfx_to_idx() {
        assert_eq!(1, BaseIndex::from_prefix(0, 0).get());
        assert_eq!(2, BaseIndex::from_prefix(0, 1).get());
        assert_eq!(3, BaseIndex::from_prefix(128, 1).get());
        assert_eq!(21, BaseIndex::from_prefix(80, 4).get());
        assert_eq!(255, BaseIndex::from_prefix(255, 7).get());
    }

    #[test]
    fn test_idx_to_pfx() {
        assert_eq!((0, 0), BaseIndex::new(1).prefix());
        assert_eq!((224, 3), BaseIndex::new(15).prefix());
        assert_eq!((254, 7), BaseIndex::new(255).prefix());

        // From nodebasics_test "special cases"
        assert_eq!((0, 1), BaseIndex::new(2).prefix());
        assert_eq!((128, 1), BaseIndex::new(3).prefix());

        assert_eq!((0, 2), BaseIndex::new(4).prefix());
        assert_eq!((64, 2), BaseIndex::new(5).prefix());
        assert_eq!((128, 2), BaseIndex::new(6).prefix());
        assert_eq!((192, 2), BaseIndex::new(7).prefix());

        assert_eq!((224, 3), BaseIndex::new(15).prefix());
        assert_eq!((240, 4), BaseIndex::new(31).prefix());
        assert_eq!((248, 5), BaseIndex::new(63).prefix());
        assert_eq!((252, 6), BaseIndex::new(127).prefix());
        assert_eq!((254, 7), BaseIndex::new(255).prefix());
    }

    #[test]
    fn test_idx_to_range() {
        assert_eq!(0..=255, BaseIndex::new(1).range());
        assert_eq!(0..=127, BaseIndex::new(2).range());
        assert_eq!(128..=255, BaseIndex::new(3).range());
        assert_eq!(0..=63, BaseIndex::new(4).range());
        assert_eq!(0..=31, BaseIndex::new(8).range());
        assert_eq!(160..=191, BaseIndex::new(13).range(),);
        assert_eq!(68..=71, BaseIndex::new(81).range());
        assert_eq!(252..=253, BaseIndex::new(254).range());
        assert_eq!(254..=255, BaseIndex::new(255).range());
    }

    #[test]
    fn test_net_mask() {
        assert_eq!(0, net_mask(0));
        assert_eq!(0x80, net_mask(1));
        assert_eq!(0xc0, net_mask(2));
        assert_eq!(0xe0, net_mask(3));
        assert_eq!(0xf0, net_mask(4));
        assert_eq!(0xf8, net_mask(5));
        assert_eq!(0xfc, net_mask(6));
        assert_eq!(0xfe, net_mask(7));
        assert_eq!(0xff, net_mask(8));
    }

    #[test]
    #[should_panic]
    fn test_net_mask_panics() {
        net_mask(9);
    }

    #[test]
    fn roundtrip_pfx_7() {
        let idx = BaseIndex::from_pfx_7(131);
        std::println!("{idx:?}");

        // from_pfx_7 maps to /7s
        let (_pfx, bits) = idx.prefix();
        assert_eq!(bits, 7);
    }
}
