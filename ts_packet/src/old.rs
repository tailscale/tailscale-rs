//! Old packet types (being phased out).

use alloc::{borrow::ToOwned, string::String, vec::Vec};
use core::{
    fmt::{self, LowerHex, UpperHex},
    net::IpAddr,
    ops::{Index, IndexMut},
    slice::{Iter, IterMut, SliceIndex},
};

use bytes::{Buf, BufMut, Bytes, BytesMut, buf::UninitSlice};
use ts_hexdump::{AsHexExt, Case, hex_fmt};

/// An immutable, contiguous sequence of bytes, specialized for networking applications.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct Packet {
    contents: Bytes,
}

impl Packet {
    /// The empty packet.
    pub const EMPTY: Packet = Packet {
        contents: Bytes::from_static(&[]),
    };

    /// Returns `true` if this [`crate::old::Packet`] has a length of 0.
    ///
    /// # Examples
    /// ```
    /// # use ts_packet::old::Packet;
    /// let pkt = Packet::from(vec![]);
    /// assert!(pkt.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.contents.is_empty()
    }

    /// Returns an iterator over the bytes in this [`crate::old::Packet`]. The iterator yields all bytes in
    /// order from start to end.
    ///
    /// # Examples
    /// ```
    /// # use ts_packet::old::Packet;
    /// let pkt = Packet::from(vec![0xAA, 0xBB, 0xCC]);
    /// let mut iter = pkt.iter();
    /// assert_eq!(iter.next(), Some(&0xAA));
    /// assert_eq!(iter.next(), Some(&0xBB));
    /// assert_eq!(iter.next(), Some(&0xCC));
    /// assert_eq!(iter.next(), None);
    /// ```
    pub fn iter(&'_ self) -> Iter<'_, u8> {
        self.contents.iter()
    }

    /// Returns the number of bytes contained in this [`crate::old::Packet`].
    ///
    /// # Examples
    /// ```
    /// # use ts_packet::old::Packet;
    /// let pkt = Packet::from(vec![1, 2, 3]);
    /// assert_eq!(pkt.len(), 3);
    /// ```
    pub fn len(&self) -> usize {
        self.contents.len()
    }
}

impl fmt::Debug for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:X}")
    }
}

impl AsRef<[u8]> for Packet {
    fn as_ref(&self) -> &[u8] {
        self.contents.as_ref()
    }
}

impl Buf for Packet {
    fn remaining(&self) -> usize {
        self.contents.remaining()
    }

    fn chunk(&self) -> &[u8] {
        &self.contents
    }

    fn advance(&mut self, cnt: usize) {
        self.contents.advance(cnt);
    }
}

impl From<&[u8]> for Packet {
    fn from(value: &[u8]) -> Self {
        Self {
            contents: Bytes::from(value.to_owned()),
        }
    }
}
impl From<Bytes> for Packet {
    fn from(value: Bytes) -> Self {
        Self { contents: value }
    }
}

impl From<BytesMut> for Packet {
    fn from(value: BytesMut) -> Self {
        Self {
            contents: value.freeze(),
        }
    }
}

impl From<PacketMut> for Packet {
    fn from(value: PacketMut) -> Self {
        value.freeze()
    }
}

impl From<Vec<u8>> for Packet {
    fn from(value: Vec<u8>) -> Self {
        Self {
            contents: value.into(),
        }
    }
}

impl<T> Index<T> for Packet
where
    // This instance is provided by implicit deref to [u8] on Bytes
    [u8]: Index<T>,
{
    type Output = <[u8] as Index<T>>::Output;

    #[inline]
    fn index(&self, index: T) -> &Self::Output {
        self.contents.index(index)
    }
}

impl LowerHex for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.iter().hex(Case::Lower).flatten().collect::<String>()
        )
    }
}

impl UpperHex for Packet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}",
            self.iter().hex(Case::Upper).flatten().collect::<String>()
        )
    }
}

/// A mutable, contiguous, growable sequence of bytes, specialized for networking applications.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd)]
pub struct PacketMut {
    /// The backing buffer for this packet; effectively a pointer, length, and capacity of a
    /// contiguous slice of memory. Supports dynamic resizing/reallocation when necessary.
    contents: BytesMut,
}

impl PacketMut {
    /// Constructs a new [PacketMut] and allocates an underlying buffer of the given `size` on the
    /// heap. The newly-allocated underlying buffer is filled with zero bytes (`0u8`).
    ///
    /// # Examples
    /// ```
    /// # use ts_packet::old::PacketMut;
    /// let mut pkt = PacketMut::new(5);
    /// assert_eq!(pkt.len(), 5);
    /// assert_eq!(pkt.as_ref(), &[0, 0, 0, 0, 0]);
    /// pkt[4] = 42;
    /// assert_eq!(pkt.as_ref(), &[0, 0, 0, 0, 42]);
    /// ```
    pub fn new(size: usize) -> Self {
        Self {
            contents: BytesMut::zeroed(size),
        }
    }

    /// Constructs a new [PacketMut] with at least the specified capacity. The packet will be able
    /// to hold at least `size` bytes without reallocating.
    ///
    /// Note that the packet will have at least the given *capacity*, but will have a *length* of
    /// zero until bytes are added to it.
    ///
    /// # Examples
    /// ```
    /// # use ts_packet::old::PacketMut;
    /// let mut pkt = PacketMut::with_capacity(5);
    /// assert_eq!(pkt.len(), 0);
    /// assert_eq!(pkt.capacity(), 5);
    /// ```
    pub fn with_capacity(size: usize) -> Self {
        Self {
            contents: BytesMut::with_capacity(size),
        }
    }

    /// Returns the number of contiguous bytes the underlying buffer can hold without reallocating.
    ///
    /// # Examples
    /// ```
    /// # use ts_packet::old::PacketMut;
    /// let mut pkt = PacketMut::with_capacity(3);
    /// assert_eq!(pkt.len(), 0);
    /// assert_eq!(pkt.capacity(), 3);
    /// ```
    pub fn capacity(&self) -> usize {
        self.contents.capacity()
    }

    /// Appends the given bytes to the end of this [`PacketMut`]. The underlying buffer is
    /// resized if it does not have enough capacity.
    ///
    /// # Examples
    /// Extending within the underlying buffer's capacity increases the length, but not the
    /// capacity:
    /// ```
    /// # use ts_packet::old::PacketMut;
    /// let mut pkt = PacketMut::with_capacity(3);
    /// pkt.extend_from_slice(&[1, 2, 3]);
    /// assert_eq!(pkt.len(), 3);
    /// assert_eq!(pkt.capacity(), 3);
    /// ```
    ///
    /// Extending *beyond* the backing buffer's capacity triggers a reallocation, changing both the
    /// length and the capacity:
    /// ```
    /// # use ts_packet::old::PacketMut;
    /// let mut pkt = PacketMut::with_capacity(3);
    /// pkt.extend_from_slice(&[1, 2, 3, 4]);
    /// assert_eq!(pkt.len(), 4);
    /// assert_eq!(pkt.capacity(), 8);
    /// ```
    pub fn extend_from_slice(&mut self, slice: &[u8]) {
        self.contents.extend_from_slice(slice);
    }

    /// Add the given number of zero bytes to the front of this `[PacketMut]`. The underlying
    /// buffer is resized if it does not have enough capacity.
    pub fn grow_front(&mut self, len: usize) {
        let existing_len = self.contents.len();
        self.contents.resize(existing_len + len, 0);
        self.contents.copy_within(..existing_len, len);
        self.contents[..len].fill(0);
    }

    /// Prepends the given bytes to this [`PacketMut`]. The underlying buffer is resized if it
    /// does not have enough capacity.
    pub fn extend_front_from_slice(&mut self, slice: &[u8]) {
        self.grow_front(slice.len());
        self.contents[..slice.len()].copy_from_slice(slice);
    }

    /// Returns a reference to an element or subslice depending on the type of index.
    ///
    /// If given a position, returns a reference to the element at that position or None if out of bounds.
    /// If given a range, returns the subslice corresponding to that range, or None if out of bounds.
    pub fn get<I>(&self, index: I) -> Option<&<I as SliceIndex<[u8]>>::Output>
    where
        I: SliceIndex<[u8]>,
    {
        self.contents.get(index)
    }

    /// Returns a mutable reference to an element or subslice depending on the type of index.
    ///
    /// If given a position, returns a reference to the element at that position or None if out of bounds.
    /// If given a range, returns the subslice corresponding to that range, or None if out of bounds.
    pub fn get_mut<I>(&mut self, index: I) -> Option<&mut <I as SliceIndex<[u8]>>::Output>
    where
        I: SliceIndex<[u8]>,
    {
        self.contents.get_mut(index)
    }

    /// Converts `self` into an immutable [`Packet`]. This is a zero-cost type conversion simply to
    /// indicate the returned packet won't be mutated anymore, allowing the packet to be cheaply
    /// cloned and moved between execution contexts (threads/async tasks).
    ///
    /// # Examples
    ///  ```
    /// # use ts_packet::old::PacketMut;
    /// let mut pkt_mut = PacketMut::with_capacity(4);
    /// pkt_mut.extend_from_slice(b"hello world");
    /// let pkt1 = pkt_mut.freeze();
    /// let pkt2 = pkt1.clone();
    /// assert_eq!(pkt1, pkt2);
    /// let th = std::thread::spawn(move || {
    ///     assert_eq!(&pkt1[..], b"hello world");
    /// });
    /// assert_eq!(&pkt2[..], b"hello world");
    /// th.join().unwrap();
    /// ```
    pub fn freeze(self) -> Packet {
        Packet {
            contents: self.contents.freeze(),
        }
    }

    /// Returns `true` if this [`PacketMut`] has a length of 0.
    ///
    /// # Examples
    /// ```
    /// # use ts_packet::old::PacketMut;
    /// let pkt = PacketMut::from(&[]);
    /// assert!(pkt.is_empty());
    /// ```
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Returns an iterator over the bytes in this [`PacketMut`]. The iterator yields all bytes in
    /// order from start to end.
    ///
    /// # Examples
    /// ```
    /// # use ts_packet::old::PacketMut;
    /// let pkt = PacketMut::from(&[0xAA, 0xBB, 0xCC]);
    /// let mut iter = pkt.iter();
    /// assert_eq!(iter.next(), Some(&0xAA));
    /// assert_eq!(iter.next(), Some(&0xBB));
    /// assert_eq!(iter.next(), Some(&0xCC));
    /// assert_eq!(iter.next(), None);
    /// ```
    pub fn iter(&'_ self) -> Iter<'_, u8> {
        self.contents.iter()
    }

    /// Returns an iterator over the bytes in this [`PacketMut`] that allows modifying each value.
    /// The iterator yields all bytes in order from start to end.
    ///
    /// # Examples
    /// ```
    /// # use ts_packet::old::PacketMut;
    /// let mut pkt = PacketMut::from(&[0xAA, 0xBB, 0xCC]);
    /// for byte in pkt.iter_mut() {
    ///     *byte += 1;
    /// }
    /// assert_eq!(pkt.as_ref(), &[0xAB, 0xBC, 0xCD]);
    /// ```
    pub fn iter_mut(&'_ mut self) -> IterMut<'_, u8> {
        self.contents.iter_mut()
    }

    /// Returns the number of bytes contained in this [`PacketMut`].
    ///
    /// # Examples
    /// ```
    /// # use ts_packet::old::PacketMut;
    /// let pkt = PacketMut::from(&[1, 2, 3]);
    /// assert_eq!(pkt.len(), 3);
    /// ```
    pub fn len(&self) -> usize {
        self.contents.len()
    }

    /// Removes the last `count` bytes from the end of this [`PacketMut`], leaving
    /// `self.len() - count` bytes in the packet. Existing capacity is preserved and the backing
    /// buffer is not changed.
    ///
    /// # Examples
    /// ```
    /// # use ts_packet::old::PacketMut;
    /// let mut pkt = PacketMut::from(&[1, 2, 3, 4, 5]);
    /// pkt.truncate(3);
    /// assert_eq!(pkt, PacketMut::from(&[1, 2, 3]));
    /// ```
    pub fn truncate(&mut self, count: usize) {
        self.contents.truncate(count);
    }

    /// Removes the first `count` bytes from the front of this [`PacketMut`], leaving
    /// `self.len() - count` bytes in the packet. Existing capacity is preserved and the backing
    /// buffer is not changed.
    ///
    /// # Panics
    ///
    /// Panics if `at > self.len()`.
    ///
    /// # Examples
    /// ```
    /// # use ts_packet::old::PacketMut;
    /// let mut pkt = PacketMut::from(&[1, 2, 3, 4, 5]);
    /// pkt.truncate_front(2);
    /// assert_eq!(pkt, PacketMut::from(&[3, 4, 5]));
    /// ```
    pub fn truncate_front(&mut self, count: usize) {
        self.contents.advance(count);
    }

    /// Splits the [`PacketMut`] into two at the given index.
    ///
    /// After the call, `self` will contain the bytes `[0, at)`, and the returned [`PacketMut`]
    /// will contain the bytes `[at, capacity)`. Existing capacity is preserved, the backing buffer
    /// is not changed, and both `self` and the returned [`PacketMut`] share the same backing
    /// buffer.
    ///
    /// # Panics
    ///
    /// Panics if `at > len`.
    ///
    /// # Complexity
    ///
    /// O(1). Indices are adjusted and reference counts are updated, but none of the backing
    /// buffer is traversed or cloned.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ts_packet::old::PacketMut;
    /// let mut pkt1 = PacketMut::from(&[1, 2, 3, 4, 5]);
    /// let pkt2 = pkt1.split_off(2);
    /// assert_eq!(pkt1, PacketMut::from(&[1, 2]));
    /// assert_eq!(pkt2, PacketMut::from(&[3, 4, 5]));
    /// ```
    pub fn split_off(&mut self, at: usize) -> PacketMut {
        Self {
            contents: self.contents.split_off(at),
        }
    }

    /// Splits the [`PacketMut`] into two at the given index.
    ///
    /// After the call, `self` will contain the bytes `[at, len)`, and the returned [`PacketMut`]
    /// will contain the bytes `[0, at)`. Existing capacity is preserved, the backing buffer
    /// is not changed, and both `self` and the returned [`PacketMut`] share the same backing
    /// buffer.
    ///
    /// # Panics
    ///
    /// Panics if `at > len`.
    ///
    /// # Complexity
    ///
    /// O(1). Indices are adjusted and reference counts are updated, but none of the backing
    /// buffer is traversed or cloned.
    ///
    /// # Examples
    ///
    /// ```
    /// # use ts_packet::old::PacketMut;
    /// let mut pkt1 = PacketMut::from(&[1, 2, 3, 4, 5]);
    /// let pkt2 = pkt1.split_to(2);
    /// assert_eq!(pkt1, PacketMut::from(&[3, 4, 5]));
    /// assert_eq!(pkt2, PacketMut::from(&[1, 2]));
    /// ```
    pub fn split_to(&mut self, at: usize) -> PacketMut {
        Self {
            contents: self.contents.split_to(at),
        }
    }

    fn get_ip_family(&self) -> Option<u8> {
        match self.get(0)? >> 4 {
            4 => Some(4),
            6 => Some(6),
            _ => None,
        }
    }

    /// Returns the bytes at idx..idx+4 interpreted as a network-endian IPv4 address.
    fn ipv4_at(&self, idx: usize) -> Option<IpAddr> {
        let octets: [u8; 4] = self.get(idx..idx + 4)?.try_into().unwrap();
        Some(IpAddr::from(octets))
    }

    /// Returns the bytes at idx..idx+16 interpreted as a network-endian IPv6 address.
    fn ipv6_at(&self, idx: usize) -> Option<IpAddr> {
        let octets: [u8; 16] = self.get(idx..idx + 16)?.try_into().unwrap();
        Some(IpAddr::from(octets))
    }

    /// Returns the source IP address of the packet.
    ///
    /// Returns None if the packet structure doesn't match an IPv4 or IPv6 datagram.
    pub fn get_src_addr(&self) -> Option<IpAddr> {
        match self.get_ip_family() {
            Some(4) => self.ipv4_at(12),
            Some(6) => self.ipv6_at(8),
            _ => None,
        }
    }

    /// Returns the destination IP address of the packet.
    ///
    /// Returns None if the packet structure doesn't match an IPv4 or IPv6 datagram.
    pub fn get_dst_addr(&self) -> Option<IpAddr> {
        match self.get_ip_family() {
            Some(4) => self.ipv4_at(16),
            Some(6) => self.ipv6_at(24),
            _ => None,
        }
    }
}

impl fmt::Debug for PacketMut {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:X}")
    }
}

impl AsMut<[u8]> for PacketMut {
    fn as_mut(&mut self) -> &mut [u8] {
        self.contents.as_mut()
    }
}

impl AsRef<[u8]> for PacketMut {
    fn as_ref(&self) -> &[u8] {
        self.contents.as_ref()
    }
}

impl Buf for PacketMut {
    fn remaining(&self) -> usize {
        self.contents.remaining_mut()
    }

    fn chunk(&self) -> &[u8] {
        &self.contents
    }

    fn advance(&mut self, cnt: usize) {
        self.contents.advance(cnt)
    }
}

unsafe impl BufMut for PacketMut {
    fn remaining_mut(&self) -> usize {
        self.contents.remaining_mut()
    }

    unsafe fn advance_mut(&mut self, cnt: usize) {
        unsafe {
            self.contents.advance_mut(cnt);
        }
    }

    fn chunk_mut(&mut self) -> &mut UninitSlice {
        self.contents.chunk_mut()
    }
}

impl crypto_box::aead::Buffer for PacketMut {
    fn extend_from_slice(&mut self, other: &[u8]) -> crypto_box::aead::Result<()> {
        self.contents.extend_from_slice(other);
        Ok(())
    }

    fn truncate(&mut self, len: usize) {
        self.truncate(len);
    }
}

impl From<&[u8]> for PacketMut {
    fn from(value: &[u8]) -> Self {
        Self {
            contents: BytesMut::from(value),
        }
    }
}

impl<const N: usize> From<&[u8; N]> for PacketMut {
    fn from(value: &[u8; N]) -> Self {
        Self {
            contents: BytesMut::from(value.as_ref()),
        }
    }
}

impl From<Vec<u8>> for PacketMut {
    fn from(value: Vec<u8>) -> Self {
        Self {
            contents: BytesMut::from(value.as_slice()),
        }
    }
}

impl From<BytesMut> for PacketMut {
    fn from(value: BytesMut) -> Self {
        Self { contents: value }
    }
}

impl<T> Index<T> for PacketMut
where
    // This instance is provided by implicit deref to [u8] on BytesMut
    [u8]: Index<T>,
{
    type Output = <[u8] as Index<T>>::Output;

    #[inline]
    fn index(&self, index: T) -> &Self::Output {
        self.contents.index(index)
    }
}

impl<T> IndexMut<T> for PacketMut
where
    [u8]: IndexMut<T>,
{
    #[inline]
    fn index_mut(&mut self, index: T) -> &mut Self::Output {
        self.contents.index_mut(index)
    }
}

impl LowerHex for PacketMut {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex_fmt(self.iter(), Case::Lower, f)
    }
}

impl UpperHex for PacketMut {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        hex_fmt(self.iter(), Case::Upper, f)
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::String;
    use core::fmt::Write;

    use super::*;

    /// Simple byte sequence for testing hexdumps, etc.
    const BYTE_SEQUENCE_1: &[u8] = &[
        0x00u8, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E,
        0x0F, 0x10, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    ];

    /// Resembles a 5-byte DERP KeepAlive frame; the 4-byte length field doesn't include the type/
    /// length fields themselves, so is zero.
    const BYTE_SEQUENCE_2: &[u8] = &[0x06, 0x00, 0x00, 0x00, 0x00];

    #[test]
    fn test_packet_mut_hexdump() {
        let pkt = PacketMut::from(BYTE_SEQUENCE_1);

        let mut buf = String::new();
        write!(
            buf,
            "{}",
            pkt.iter()
                .hexdump(Case::Lower)
                .flatten()
                .collect::<String>()
        )
        .unwrap();
        assert_eq!(
            buf,
            "00 01 02 03 04 05 06 07   08 09 0a 0b 0c 0d 0e 0f   ................\n10 aa bb cc dd ee ff                                .......\n"
        );

        buf.clear();
        write!(
            buf,
            "{}",
            pkt.iter()
                .hexdump(Case::Upper)
                .flatten()
                .collect::<String>()
        )
        .unwrap();
        assert_eq!(
            buf,
            "00 01 02 03 04 05 06 07   08 09 0A 0B 0C 0D 0E 0F   ................\n10 AA BB CC DD EE FF                                .......\n"
        );
    }

    #[test]
    fn test_packet_mut_iter() {
        let pkt = PacketMut::from(BYTE_SEQUENCE_1);
        for (idx, byte) in pkt.iter().enumerate() {
            assert_eq!(
                *byte, BYTE_SEQUENCE_1[idx],
                "packet and original bytes should have identical values in same order"
            );
        }
    }

    #[test]
    fn test_packet_mut_iter_mut() {
        let mut pkt1 = PacketMut::from(BYTE_SEQUENCE_1);
        let pkt2 = PacketMut::from(BYTE_SEQUENCE_1);
        for byte in pkt1.iter_mut() {
            *byte = byte.wrapping_sub(0xFF);
        }

        for (idx, byte) in pkt1.iter().enumerate() {
            assert_eq!(
                *byte,
                BYTE_SEQUENCE_1[idx].wrapping_sub(0xFF),
                "pkt1 and original bytes should have values offset by 0xFF"
            );
            assert_eq!(
                pkt2[idx], BYTE_SEQUENCE_1[idx],
                "pkt2 and original bytes should have identical values in same order"
            );
            assert_eq!(
                pkt1[idx],
                pkt2[idx].wrapping_sub(0xFF),
                "pkt1 and pkt2 should have values offset by 0xFF"
            );
        }
    }

    #[test]
    fn test_packet_mut_prepend() {
        let mut pkt = PacketMut::from(BYTE_SEQUENCE_1);
        pkt.grow_front(5);
        assert_eq!(pkt.len(), BYTE_SEQUENCE_1.len() + 5);
        assert_eq!(pkt[..5], [0; 5]);
        assert_eq!(&pkt[5..], BYTE_SEQUENCE_1);

        let mut pkt = PacketMut::from(BYTE_SEQUENCE_1);
        pkt.extend_front_from_slice(BYTE_SEQUENCE_2);
        assert_eq!(pkt.len(), BYTE_SEQUENCE_1.len() + BYTE_SEQUENCE_2.len());
        assert_eq!(&pkt[..BYTE_SEQUENCE_2.len()], BYTE_SEQUENCE_2);
        assert_eq!(&pkt[BYTE_SEQUENCE_2.len()..], BYTE_SEQUENCE_1);
    }
}
