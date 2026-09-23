use core::fmt::{
    Binary, Debug, Display, Formatter, LowerExp, LowerHex, Octal, Pointer, UpperExp, UpperHex,
};

/// Generic iterator formatter with an optional user-provided delimiter.
///
/// The formatter is passed to each element of the iterator as-is, which notably means that the
/// format arguments do _not_ apply to the top-level formatter but instead to each element
/// individually. The implication of this is that width, precision, padding, etc. apply to the whole
/// iterator at once.
///
/// # Examples
///
/// Intended usage is along the lines of contiguously hex-formatting a `[u8]` slice:
///
/// ```rust
/// # use ts_util::fmt::IterFmt;
/// let ary = [0x1u8, 0x2, 0x3, 0x4, 0xa, 0xb];
///
/// // Use the width specifier to indicate your desired element width:
/// assert_eq!(format!("{:02X}", IterFmt::contiguous(&ary)), "010203040A0B");
///
/// // If omitted, no padding:
/// assert_eq!(format!("{:x}", IterFmt::contiguous(&ary)), "1234ab");
/// ```
pub struct IterFmt<It> {
    iter: It,
    delim: &'static str,
}

impl<It> IterFmt<It> {
    /// Construct an [`IterFmt`] with no delimiter.
    pub const fn contiguous(it: It) -> Self {
        Self {
            iter: it,
            delim: "",
        }
    }

    /// Construct an [`IterFmt`] with the specified delimiter.
    pub fn delimited(it: It, delim: &'static str) -> Self {
        Self { iter: it, delim }
    }

    /// Common formatter implementation.
    ///
    /// `inner_fmt` abstracts which trait (in the macro below) we're using to do the item format.
    fn fmt(
        &self,
        f: &mut Formatter<'_>,
        inner_fmt: &dyn Fn(It::Item, &mut Formatter) -> core::fmt::Result,
    ) -> core::fmt::Result
    where
        It: IntoIterator + Clone,
    {
        let mut it = self.iter.clone().into_iter();

        if let Some(elem) = it.next() {
            inner_fmt(elem, f)?;
        }

        for elem in it {
            f.write_str(self.delim)?;
            inner_fmt(elem, f)?;
        }

        Ok(())
    }
}

macro_rules! impl_fmt {
    ($($trait_:ident),* $(,)?) => {
        $(
            impl<It> $trait_ for IterFmt<It>
            where
                It: IntoIterator + Clone,
                It::Item: $trait_,
            {
                fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
                    self.fmt(f, &|elem, f| elem.fmt(f))
                }
            }

        )*
    }
}

impl_fmt!(
    Debug, Display, LowerHex, UpperHex, Octal, Binary, Pointer, LowerExp, UpperExp
);
