//! RIB (route table) and IFMIB (interface table) fetchers and parsers for BSD.
//!
//! Inspired by and substantially borrowed from <https://golang.org/x/net/route>, but implemented
//! using a mix of rust's [`zerocopy`] and [`nom`] libraries.
//!
//! Currently, this module targets macOS specifically (other BSDs are known not to work), but the
//! functionality here is expected to expand to FreeBSD (at least) eventually, as it has the same
//! `PF_ROUTE` socket and sysctl.
//!
//! Many of the struct definitions in the submodules are repeated from [`libc`]'s BSD/macOS
//! definitions – this is to enable [`zerocopy`] derives, cleaner field names, and inherent
//! utility methods.
//!
//! ## Overview
//!
//! The BSD net subsystem in XNU answers `PF_ROUTE` queries made via a sysctl (see [`dump`]) or
//! through a `PF_ROUTE` socket ([`RouteSocket`][crate::bsd::RouteSocket]). You can ask for both
//! actual routing table (RIB) entries and the table of network interfaces (IFMIB) through the
//! syscall; the socket just dumps everything as it changes.
//!
//! The messages are framed in a TLV [`Header`]. Each message type then has its own type-specific
//! inner header, and it is followed by a variable number of variable-length address
//! entries. The addresses present in a given message are indicated by an [`Addrs`] bitflag word;
//! they follow according to the order of the bits set in the flag word. E.g. if an `RTM_GET2`
//! message ([`Route2`]) were followed by `DESTINATION`, `GATEWAY`, and `NETMASK` addresses, these
//! bits would be set in its `addrs` word.
//!
//! The addrs can be parsed without knowledge of the flag word: they are just successive
//! 4-byte-aligned `sockaddr` structures, which are effectively TLVs: `sa_len` and the AF tell us
//! how to interpret the rest of the structure. Address parsing is implemented in the [`addr`]
//! module.
//!
//! The route and interface header structures can be found in the [`route_hdr`] and
//! [`interface_hdr`] modules, respectively.

use core::{ffi::c_int, fmt::Debug};

use libc::{AF_INET, AF_INET6, AF_LINK, AF_UNIX, AF_UNSPEC};
use nom::{AsBytes, IResult, Parser, combinator::peek, number::Endianness};
use zerocopy::{NativeEndian, TryFromBytes, U16};

use crate::{Family, FamilyOrBoth};

mod addr;
mod dump;
mod flags;
mod interface_hdr;
mod route_hdr;

pub use addr::{
    Address, LinkAddr, PrefixLen, partial_in6addr, partial_inaddr, partial_sockaddr,
    sockaddr_dl_body,
};
pub use dump::{DumpType, dump};
pub use flags::{Addrs, Flags, FlagsAddrs};
pub use interface_hdr::{
    Interface, Interface2, InterfaceAddr, InterfaceData, InterfaceData64, MulticastAddr,
    MulticastAddr2, Time, Time32,
};
pub use route_hdr::{Route, Route2};

type CUint = zerocopy::U32<NativeEndian>;
type CInt = zerocopy::I32<NativeEndian>;
type CUshort = U16<NativeEndian>;

const PAD_USHORT: usize = 4usize.strict_sub(size_of::<libc::c_ushort>());
pub type PadUshort = [u8; PAD_USHORT];

static_assertions::assert_eq_size!(CUint, core::ffi::c_uint);
static_assertions::assert_eq_size!(CInt, c_int);
static_assertions::assert_eq_size!(CUshort, core::ffi::c_ushort);

cfg_if::cfg_if! {
    if #[cfg(target_os = "macos")] {
        /// Message alignment for `PF_ROUTE` sockets in macOS is 4 bytes.
        const ALIGN: u8 = 4;
    }
}

impl From<Family> for c_int {
    fn from(value: Family) -> Self {
        match value {
            Family::Ipv4 => AF_INET,
            Family::Ipv6 => AF_INET6,
        }
    }
}

impl From<FamilyOrBoth> for c_int {
    fn from(value: FamilyOrBoth) -> Self {
        match value {
            FamilyOrBoth::Both => AF_UNSPEC,
            FamilyOrBoth::Single(family) => family.into(),
        }
    }
}

#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum MessageHeader<'a> {
    Route2(&'a Route2),
    Route(&'a Route),
    Interface2(&'a Interface2),
    Interface(&'a Interface),
    InterfaceAddr(&'a InterfaceAddr),
    MulticastAddr2(&'a MulticastAddr2),
    MulticastAddr(&'a MulticastAddr),
}

impl MessageHeader<'_> {
    /// Get the message header.
    pub const fn header(&self) -> Header {
        match self {
            Self::Route2(r) => r.header,
            Self::Route(r) => r.header,
            Self::Interface2(i) => i.header,
            Self::Interface(i) => i.header,
            Self::InterfaceAddr(i) => i.header,
            Self::MulticastAddr(i) => i.header,
            Self::MulticastAddr2(i) => i.header,
        }
    }

    /// Get the address flags for the contained message.
    pub const fn addrs(&self) -> Addrs {
        match self {
            Self::Route2(r) => r.flag_block.addrs(),
            Self::Route(r) => r.flag_block.addrs(),
            Self::Interface2(i) => i.flag_block.addrs(),
            Self::Interface(i) => i.flag_block.addrs(),
            Self::InterfaceAddr(i) => i.flag_block.addrs(),
            Self::MulticastAddr(i) => i.flag_block.addrs(),
            Self::MulticastAddr2(i) => i.flag_block.addrs(),
        }
    }

    /// Get the flags for the contained message.
    pub const fn flags(&self) -> Flags {
        match self {
            Self::Route2(r) => r.flag_block.flags(),
            Self::Route(r) => r.flag_block.flags(),
            Self::Interface2(i) => i.flag_block.flags(),
            Self::Interface(i) => i.flag_block.flags(),
            Self::InterfaceAddr(i) => i.flag_block.flags(),
            Self::MulticastAddr(i) => i.flag_block.flags(),
            Self::MulticastAddr2(i) => i.flag_block.flags(),
        }
    }
}

impl<'a> MessageHeader<'a> {
    pub fn parse(input: &'a [u8]) -> IResult<&'a [u8], (MessageType, Self)> {
        let (header, _rest) = Header::try_ref_from_prefix(input.as_bytes())
            .map_err(|e| format!("{e}"))
            .unwrap(); // TODO

        let (hdr, rest) = match header.ty {
            MessageType::Get2 => Route2::try_ref_from_prefix(input.as_bytes())
                .map(|(r2, rest)| (MessageHeader::Route2(r2), rest))
                .map_err(|e| format!("{e}")),

            MessageType::IfInfo2 => Interface2::try_ref_from_prefix(input.as_bytes())
                .map(|(r, rest)| (MessageHeader::Interface2(r), rest))
                .map_err(|e| format!("{e}")),

            MessageType::Get
            | MessageType::Add
            | MessageType::Delete
            | MessageType::Change
            | MessageType::Lock
            | MessageType::Losing
            | MessageType::Miss
            | MessageType::Resolve
            | MessageType::Redirect => Route::try_ref_from_prefix(input.as_bytes())
                .map(|(r, rest)| (MessageHeader::Route(r), rest))
                .map_err(|e| format!("{e}")),

            MessageType::IfInfo => Interface::try_ref_from_prefix(input.as_bytes())
                .map(|(r, rest)| (MessageHeader::Interface(r), rest))
                .map_err(|e| format!("{e}")),
            MessageType::NewAddr | MessageType::DelAddr => {
                InterfaceAddr::try_ref_from_prefix(input.as_bytes())
                    .map(|(r, rest)| (MessageHeader::InterfaceAddr(r), rest))
                    .map_err(|e| format!("{e}"))
            }
            MessageType::NewMaddr | MessageType::DelMaddr => {
                MulticastAddr::try_ref_from_prefix(input.as_bytes())
                    .map(|(r, rest)| (MessageHeader::MulticastAddr(r), rest))
                    .map_err(|e| format!("{e}"))
            }
            MessageType::NewMaddr2 => MulticastAddr2::try_ref_from_prefix(input.as_bytes())
                .map(|(r, rest)| (MessageHeader::MulticastAddr2(r), rest))
                .map_err(|e| format!("{e}")),
        }
        .unwrap(); // TODO

        let diff = input.len() - rest.len();
        let rest = &input[diff..];

        Ok((rest, (header.ty, hdr)))
    }
}

/// Parse the message header for the length field and take that many bytes.
///
/// The chunks include the length field, as the `{rt,if}_*hdr` structs canonically include it.
pub fn msg_chunk<I>() -> impl Parser<I, Output = I, Error = nom::error::Error<I>>
where
    I: nom::Input<Item = u8>,
{
    nom::multi::length_data(peek(nom::number::u16(Endianness::Native)))
}

/// Type of a `PF_ROUTE` message.
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    zerocopy::Immutable,
    zerocopy::Unaligned,
    zerocopy::KnownLayout,
    zerocopy::IntoBytes,
    zerocopy::TryFromBytes,
)]
#[repr(u8)]
pub enum MessageType {
    /// Add the given route.
    Add = libc::RTM_ADD as _,
    /// Delete the given route.
    Delete = libc::RTM_DELETE as _,
    /// Modify the given route.
    Change = libc::RTM_CHANGE as _,

    /// This is a request to get a specific route or a message from the kernel populated by a
    /// [`Route`].
    Get = libc::RTM_GET as _,
    /// This is a request to get a specific route or a message from the kernel populated by a
    /// [`Route2`].
    Get2 = libc::RTM_GET2 as _,
    /// Could not find a matching route for traffic.
    Miss = libc::RTM_MISS as _,

    /// Traffic using this route appears to be dropping packets.
    Losing = libc::RTM_LOSING as _,
    /// We have received an ICMP redirect for a destination.
    Redirect = libc::RTM_REDIRECT as _,

    /// Request to lock route attributes against modification by dynamically-learned routing info.
    Lock = libc::RTM_LOCK as _,
    /// Kernel requests userspace resolution of this route.
    Resolve = libc::RTM_RESOLVE as _,

    /// An interface has a new address.
    NewAddr = libc::RTM_NEWADDR as _,
    /// An address has been deleted from an interface.
    DelAddr = libc::RTM_DELADDR as _,
    /// Info about a given interface.
    ///
    /// Typically sent when the link status changes.
    IfInfo = libc::RTM_IFINFO as _,
    /// Info about a given interface.
    ///
    /// Typically sent when the link status changes.
    IfInfo2 = libc::RTM_IFINFO2 as _,
    /// Interface joined a multicast group.
    NewMaddr = libc::RTM_NEWMADDR as _,
    /// Interface joined a multicast group.
    NewMaddr2 = libc::RTM_NEWMADDR2 as _,
    /// Interface left a multicast group.
    DelMaddr = libc::RTM_DELMADDR as _,
}

/// `PF_ROUTE` message header.
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::IntoBytes,
    zerocopy::TryFromBytes,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub struct Header {
    /// Length of this message (including the header).
    pub len: U16<NativeEndian>,
    /// Version of the message.
    pub version: u8,
    /// Message type.
    pub ty: MessageType,
}

impl Default for Header {
    fn default() -> Self {
        Self {
            len: 0u16.into(),
            version: 5,
            ty: MessageType::Get,
        }
    }
}

/// Address families.
///
/// Provided as an enum just for cleaner debug output (so they're named rather than being numbers).
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(isize)]
pub enum Af {
    /// Unspecified address family.
    Unspec = AF_UNSPEC as _,
    /// IPv4.
    Inet = AF_INET as _,
    /// IPv6.
    Inet6 = AF_INET6 as _,
    /// Unix socket.
    Unix = AF_UNIX as _,
    /// L2 address family.
    Link = AF_LINK as _,
    /// Catchall for other address families.
    Other(isize),
}

impl From<CInt> for Af {
    fn from(value: CInt) -> Self {
        match value.get() {
            AF_UNSPEC => Self::Unspec,
            AF_INET => Self::Inet,
            AF_INET6 => Self::Inet6,
            AF_UNIX => Self::Unix,
            AF_LINK => Self::Link,
            other => Self::Other(other as _),
        }
    }
}

impl From<Af> for CInt {
    fn from(value: Af) -> Self {
        CInt::new(match value {
            Af::Unspec => AF_UNSPEC as _,
            Af::Inet => AF_INET as _,
            Af::Inet6 => AF_INET6 as _,
            Af::Unix => AF_UNIX as _,
            Af::Link => AF_LINK as _,
            Af::Other(x) => x as _,
        })
    }
}

/// Round up `len` to the next multiple of `align`.
///
/// # Panics
///
/// If `align` is not a power of 2.
const fn round_up(len: usize, align: usize) -> usize {
    assert!(align.is_power_of_two());

    (len + (align - 1)) & !(align - 1)
}
