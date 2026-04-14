#![doc = include_str!("../README.md")]
#![no_std]

#[cfg(feature = "alloc")]
extern crate alloc;

use core::{fmt, iter::FusedIterator};

/// The 16 hexadecimal digits as `char`s, with digits a-f as lowercase.
const LOWERCASE_HEX_CHARS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];

/// The 16 hexadecimal digits as `char`s, with digits A-F as uppercase.
const UPPERCASE_HEX_CHARS: [char; 16] = [
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F',
];

/// The maximum length (in chars) of a single hexdump line in classic 3-column format, including
/// the trailing newline.
///
/// The "classic 3-column format" is 2 columns of 8 bytes in hex format, followed by 1 column of
/// 16 ASCII character representations:
///
/// `"48 65 6c 6c 6f 20 54 61   69 6c 73 63 61 6c 65 21   Hello.Tailscale!\n"`
///
/// This breaks down to 69 characters as follows:
/// - A single byte is 3 chars (2 hex digits plus a space)
/// - An 8-byte hex column is (8*3) = 24 chars
/// - There are two 8-byte hex columns for (24 * 2) = 48 chars
/// - The two hex columns have an additional 2 spaces separating them = 50 chars
/// - The second hex column and the ASCII column have an additional 2 spaces separating
///   them = 52 chars
/// - The ASCII column is 16 chars = 68 chars
/// - There's a newline at the end of the line = 69 chars
///
/// Note that the last line in a hexdump may contain fewer than 16 bytes, therefore this is a
/// maximum line length rather than a fixed line length.
const MAX_HEXDUMP_LINE_CHARS: usize = 69;

/// The casing of the characters to use for the digits A-F when formatting a hexadecimal string.
#[derive(Clone, Copy, Debug)]
pub enum Case {
    /// Use lowercase characters for the hexadecimal digits a-f.
    Lower,
    /// Use lowercase characters for the hexadecimal digits A-F.
    Upper,
}

/// Returns the ASCII `char` representation of the given byte if it can be printed as part of the
/// ASCII column in a hexdump; otherwise, returns the `'.'` character.
///
/// Alphanumeric and punctuation ASCII characters are considered printable:
/// - U+0021 ..= U+002F ! " # $ % & ' ( ) * + , - . /, or
/// - U+0030 '0' ..= U+0039 '9',       or
/// - U+003A ..= U+0040 : ; < = > ? @, or
/// - U+0041 'A' ..= U+005A 'Z',       or
/// - U+005B ..= U+0060 [ \ ] ^ _ ` ,  or
/// - U+0061 'a' ..= U+007A 'z',       or
/// - U+007B ..= U+007E { | } ~
///
/// All other characters are considered unprintable, and are represented as a `'.'` character.
///
/// # Examples
/// ```
/// # use ts_hexdump::get_ascii_char_for_byte;
/// assert_eq!(get_ascii_char_for_byte(0x00), '.');
/// assert_eq!(get_ascii_char_for_byte(0x20), '.');
/// assert_eq!(get_ascii_char_for_byte(0x21), '!');
/// assert_eq!(get_ascii_char_for_byte(0x41), 'A');
/// assert_eq!(get_ascii_char_for_byte(0x7F), '.');
/// ```
pub fn get_ascii_char_for_byte(byte: u8) -> char {
    char::from_u32(byte as u32)
        .map(|v| {
            if v.is_ascii_alphanumeric() || v.is_ascii_punctuation() {
                v
            } else {
                '.'
            }
        })
        .unwrap_or('.')
}

/// Returns the 2-`char` representation of the given byte in hexadecimal format, eg
/// `0x1A -> ['1', 'A']`, with capitalization of digits A-F dependent on the `case` parameter.  The
/// returned characters are in `[hi_nybble, lo_nybble]` order.
///
/// # Examples
/// ```
/// # use ts_hexdump::{Case, get_hex_chars_for_byte};
/// assert_eq!(get_hex_chars_for_byte(0x00, Case::Upper), ['0', '0']);
/// assert_eq!(get_hex_chars_for_byte(0x20, Case::Upper), ['2', '0']);
/// assert_eq!(get_hex_chars_for_byte(0x20, Case::Lower), ['2', '0']);
/// assert_eq!(get_hex_chars_for_byte(0x21, Case::Upper), ['2', '1']);
/// assert_eq!(get_hex_chars_for_byte(0x4C, Case::Upper), ['4', 'C']);
/// assert_eq!(get_hex_chars_for_byte(0x4C, Case::Lower), ['4', 'c']);
/// assert_eq!(get_hex_chars_for_byte(0x7F, Case::Upper), ['7', 'F']);
/// ```
pub fn get_hex_chars_for_byte(byte: u8, case: Case) -> [char; 2] {
    let lo_nybble = (byte & 0x0f) as usize;
    let high_nybble = ((byte & 0xf0) >> 4) as usize;
    let charset = match case {
        Case::Lower => &LOWERCASE_HEX_CHARS,
        Case::Upper => &UPPERCASE_HEX_CHARS,
    };
    [charset[high_nybble], charset[lo_nybble]]
}

/// Iterator that yields the hexadecimal character representation of each byte element in the
/// source iterator.
///
/// This `struct` is created by the [`AsHexExt::hex`]. See its documentation for
/// more.
pub struct HexIter<I> {
    iter: I,
    case: Case,
}

impl<I> HexIter<I>
where
    I: IntoIterator,
{
    /// Construct a [`HexIter`] with the given `case` wrapping the given `iter`.
    pub fn new(iter: I, case: Case) -> Self {
        Self { iter, case }
    }
}

impl<'a, I: Iterator<Item = &'a u8>> Iterator for HexIter<I> {
    type Item = [char; 2];

    fn next(&mut self) -> Option<Self::Item> {
        Some(get_hex_chars_for_byte(*self.iter.next()?, self.case))
    }
}

/// Iterator that yields complete 3-column hexdump lines for up to 16 bytes at a time from the
/// source iterator.
///
/// This `struct` is created by [`AsHexExt::hexdump`]. See its documentation
/// for more.
pub struct HexdumpIter<I> {
    iter: I,
    case: Case,
    exhausted: bool,
}

impl<I: IntoIterator> HexdumpIter<I> {
    /// Construct a [`HexdumpIter`] with the given `case` wrapping the given `iter`.
    pub fn new(iter: I, case: Case) -> Self {
        Self {
            iter,
            case,
            exhausted: false,
        }
    }
}

impl<'a, I: Iterator<Item = &'a u8>> Iterator for HexdumpIter<I> {
    // Using a [`heapless::Vec`] allows us to return an owned "array-like" of chars that can be
    // *up to* [`MAX_HEXDUMP_LINE_CHARS`] long, but can be shorter than that, without allocating on
    // the heap.
    type Item = heapless::Vec<char, MAX_HEXDUMP_LINE_CHARS>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.exhausted {
            return None;
        }

        // Filling with spaces means we only have to overwrite hex chars, ASCII chars, and the
        // newline, letting us treat this more as an array than a Vec/String.
        let mut line = heapless::Vec::<char, MAX_HEXDUMP_LINE_CHARS>::from_array(
            [' '; MAX_HEXDUMP_LINE_CHARS],
        );
        let mut end_idx = 0;

        for (byte_idx, byte) in self.iter.by_ref().enumerate() {
            let hex_chars = get_hex_chars_for_byte(*byte, self.case);
            let ascii_char = get_ascii_char_for_byte(*byte);
            let hex_idx = if byte_idx < 8 {
                3 * byte_idx
            } else {
                3 * byte_idx + 2
            };
            let ascii_idx = 52 + byte_idx;
            end_idx = ascii_idx + 1;

            line[hex_idx] = hex_chars[0];
            line[hex_idx + 1] = hex_chars[1];
            line[ascii_idx] = ascii_char;

            // If this is a full line, tag the newline on the end and yield it.
            if byte_idx == 15 {
                line[end_idx] = '\n';
                return Some(line);
            }
        }

        // We can't reach here unless `self.iter.by_ref()` returned `None`, meaning the source
        // iterator is exhausted.
        self.exhausted = true;
        if end_idx == 0 {
            // Special case: the previous line actually exhausted the source iterator, so the
            // current line contains nothing. Return `None` to avoid returning an empty line of
            // spaces and indicate we're exhausted.
            None
        } else {
            // The last line isn't the full 16 bytes, so chop off the trailing spaces where more
            // ASCII characters would go, tag the newline on the end, and return the final line.
            line[end_idx] = '\n';
            line.truncate(end_idx + 1);
            Some(line)
        }
    }
}

/// Once a [`HexdumpIter`] is exhausted, it will always return `None`, so mark this as a [`FusedIterator`].
impl<'a, I: Iterator<Item = &'a u8>> FusedIterator for HexdumpIter<I> {}

/// Used to seal the [`AsHexExt`] trait to prevent external crates from implementing it and
/// breaking if we add new methods later on.
mod private {
    pub trait Sealed {}

    impl<'a, I> Sealed for I where I: IntoIterator<Item = &'a u8> {}
}

/// Provides methods to generate hexadecimal character and hexdump line iterators from iterators
/// over bytes. Intended for logging and debugging.
pub trait AsHexExt: IntoIterator + private::Sealed {
    /// Creates an iterator that yields the hexadecimal character representation of each input byte
    /// element. The casing of the hexadecimal characters is determined by the `uppercase`
    /// parameter.
    ///
    /// # Examples
    /// ```
    /// # use ts_hexdump::{AsHexExt, Case};
    /// let buf = b"Hello Tailscale!";
    /// let hsl = buf.iter().hex(Case::Lower).flatten().collect::<String>();
    /// assert_eq!(hsl, "48656c6c6f205461696c7363616c6521");
    /// let hsu = buf.iter().hex(Case::Upper).flatten().collect::<String>();
    /// assert_eq!(hsu, "48656C6C6F205461696C7363616C6521");
    /// ```
    fn hex(self, case: Case) -> HexIter<Self>
    where
        Self: Sized,
    {
        HexIter::new(self, case)
    }

    /// Creates an iterator that yields complete 3-column hexdump lines for up to 16 bytes at a
    /// time from the source iterator. The casing of the hexadecimal characters is determined by
    /// the `uppercase` parameter.
    ///
    /// # Examples
    /// ```
    /// # use ts_hexdump::{AsHexExt, Case};
    /// let buf = b"Hello Tailscale!";
    /// let hdl = buf.iter().hexdump(Case::Lower).flatten().collect::<String>();
    /// assert_eq!(hdl, "48 65 6c 6c 6f 20 54 61   69 6c 73 63 61 6c 65 21   Hello.Tailscale!\n");
    /// let hdu = buf.iter().hexdump(Case::Upper).flatten().collect::<String>();
    /// assert_eq!(hdu, "48 65 6C 6C 6F 20 54 61   69 6C 73 63 61 6C 65 21   Hello.Tailscale!\n");
    /// ```
    fn hexdump(self, case: Case) -> HexdumpIter<Self>
    where
        Self: Sized,
    {
        HexdumpIter::new(self, case)
    }

    /// Write a hexdump for this iterator out as a string.
    #[cfg(feature = "alloc")]
    fn hexdump_string<'a>(self, case: Case) -> alloc::string::String
    where
        Self: Sized,
        Self::IntoIter: Iterator<Item = &'a u8>,
    {
        self.into_iter().hexdump(case).flatten().collect()
    }
}

/// Write out the hex for the data contained in `i` to the given writer `w`.
///
/// # Examples
///
/// ```
/// # use ts_hexdump::{hex_fmt, Case};
/// let mut s = String::new();
/// hex_fmt(&[0xab, 0xcd, 0xef], Case::Lower, &mut s).unwrap();
/// assert_eq!("abcdef", s);
/// ```
#[inline]
pub fn hex_fmt<'a>(
    i: impl IntoIterator<Item = &'a u8>,
    case: Case,
    w: &mut dyn fmt::Write,
) -> fmt::Result {
    // Private helper to avoid monomorphizing
    fn _hex_fmt(
        i: &mut dyn Iterator<Item = &u8>,
        case: Case,
        w: &mut dyn fmt::Write,
    ) -> fmt::Result {
        for [hi, lo] in i.hex(case) {
            w.write_char(hi)?;
            w.write_char(lo)?;
        }

        Ok(())
    }

    _hex_fmt(&mut i.into_iter(), case, w)
}

impl<'a, I: IntoIterator<Item = &'a u8>> AsHexExt for I {}
