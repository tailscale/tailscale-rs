//! Headers for interface table messages.

use core::{ffi::c_uchar, fmt::Debug};

use libc::{suseconds_t, time_t};
use zerocopy::{
    Unalign,
    native_endian::{I32, U32, U64},
};

use crate::bsd::net_table::{CInt, CUshort, Header, PadUshort, flags::AddrsFlags};

/// Header describing an interface.
///
/// macOS-specific extension which includes additional information. Indicated by the
/// [`MessageType::IfInfo2`][crate::bsd::net_table::MessageType::IfInfo2] (`RTM_IFINFO2`) message
/// type.
///
/// Called [`if_msghdr2`][libc::if_msghdr2] in libc.
#[cfg(target_os = "macos")]
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    zerocopy::TryFromBytes,
    zerocopy::KnownLayout,
    zerocopy::Immutable,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub struct Interface2 {
    /// The header for this message.
    ///
    /// It's included primarily because it includes the length of the whole message, which
    /// can be used to deduce the space used by sockaddrs following this header.
    pub header: Header,
    /// [`Addrs`][crate::bsd::net_table::Addrs] and [`Flags`][crate::bsd::net_table::Flags]
    /// for this message.
    pub flag_block: AddrsFlags,
    /// The index of this interface.
    pub index: CUshort,
    /// Padding (required for [`zerocopy::Unaligned`]).
    pub _pad: PadUshort,
    /// Send-queue current length.
    pub snd_len: CInt,
    /// Send-queue maximum length.
    pub snd_maxlen: CInt,
    /// Send-queue packet drops.
    pub snd_drops: CInt,
    /// Watchdog timer value.
    pub timer: CInt,
    /// Additional data for this interface.
    pub data: InterfaceData64,
}

#[cfg(target_os = "macos")]
static_assertions::assert_eq_size!(Interface2, libc::if_msghdr2);

/// Header describing an interface.
///
/// Describes a physical interface, commonly followed by a
/// [`LinkAddr`][crate::bsd::net_table::LinkAddr] bearing its name.
///
/// Called [`if_msghdr`][libc::if_msghdr] in libc.
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    zerocopy::TryFromBytes,
    zerocopy::KnownLayout,
    zerocopy::Immutable,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub struct Interface {
    /// The header for this message.
    ///
    /// It's included primarily because it includes the length of the whole message, which
    /// can be used to deduce the space used by sockaddrs following this header.
    pub header: Header,
    /// [`Addrs`][crate::bsd::net_table::Addrs] and [`Flags`][crate::bsd::net_table::Flags]
    /// for this message.
    pub flag_block: AddrsFlags,
    /// The index of this interface.
    pub index: CUshort,
    /// Padding (required for [`zerocopy::Unaligned`]).
    pub _pad: PadUshort,
    /// Additional data for this interface.
    pub data: InterfaceData,
}

static_assertions::assert_eq_size!(Interface, libc::if_msghdr);

/// Additional data associated with a given interface.
///
/// [`if_data`][libc::if_data] in libc.
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    zerocopy::FromBytes,
    zerocopy::KnownLayout,
    zerocopy::Immutable,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub struct InterfaceData {
    /// Layer 2 type.
    pub ty: c_uchar,
    /// Seemingly vestigial field, unused.
    pub _typelen: c_uchar,
    /// Physical layer type.
    pub physical: c_uchar,
    /// Media address length.
    pub addrlen: c_uchar,
    /// Media header length.
    pub hdrlen: c_uchar,
    /// Polling quota for receive interrupts.
    pub recvquota: c_uchar,
    /// Polling quota for transmit interrupts.
    pub xmitquota: c_uchar,
    /// Unused field.
    pub _unused1: c_uchar,
    /// MTU for this interface.
    pub mtu: U32,
    /// Routing metric for this interface.
    pub metric: U32,
    /// The line rate for this interface.
    pub baudrate: U32,
    /// Incoming packet counter.
    pub ipackets: U32,
    /// Incoming error counter.
    pub ierrors: U32,
    /// Outgoing packet counter.
    pub opackets: U32,
    /// Outgoing error counter.
    pub oerrors: U32,
    /// Collision counter.
    pub collisions: U32,
    /// Incoming byte counter.
    pub ibytes: U32,
    /// Outgoing byte counter.
    pub obytes: U32,
    /// Incoming multicast packet counter.
    pub imcasts: U32,
    /// Outgoing multicast packet counter.
    pub omcasts: U32,
    /// Packets dropped on input on this interface.
    pub iqdrops: U32,
    /// Packets with unsupported protocol.
    pub noproto: U32,
    /// Cumulative time spent receiving (usec).
    pub recvtiming: U32,
    /// Cumulative time spent transmitting (usec).
    pub xmittiming: U32,
    /// Timestamp of the last change to the interface.
    pub lastchange: Time32,
    /// Unused field.
    pub _unused2: U32,
    /// Hardware offload support (flags).
    pub hwassist: U32,
    /// Reserved field.
    pub _reserved1: U32,
    /// Reserved field.
    pub _reserved2: U32,
}

/// 64-bit version of [`InterfaceData`]; additional data associated with an interface.
///
/// macOS-specific, only appears in [`Interface2`].
///
/// Called [`if_data64`][libc::if_data64] in libc.
#[cfg(target_os = "macos")]
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    zerocopy::FromBytes,
    zerocopy::KnownLayout,
    zerocopy::Immutable,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub struct InterfaceData64 {
    /// Layer 2 type.
    pub ty: c_uchar,
    /// Seemingly vestigial field, unused.
    pub _typelen: c_uchar,
    /// Physical layer type.
    pub physical: c_uchar,
    /// Media address length.
    pub addrlen: c_uchar,
    /// Media header length.
    pub hdrlen: c_uchar,
    /// Polling quota for receive interrupts.
    pub recvquota: c_uchar,
    /// Polling quota for transmit interrupts.
    pub xmitquota: c_uchar,
    /// Unused field.
    pub _unused1: c_uchar,
    /// MTU for this interface.
    pub mtu: U32,
    /// Routing metric for this interface.
    pub metric: U32,
    /// The line rate for this interface.
    pub baudrate: U64,
    /// Incoming packet counter.
    pub ipackets: U64,
    /// Incoming error counter.
    pub ierrors: U64,
    /// Outgoing packet counter.
    pub opackets: U64,
    /// Outgoing error counter.
    pub oerrors: U64,
    /// Collision counter.
    pub collisions: U64,
    /// Incoming byte counter.
    pub ibytes: U64,
    /// Outgoing byte counter.
    pub obytes: U64,
    /// Incoming multicast packet counter.
    pub imcasts: U64,
    /// Outgoing multicast packet counter.
    pub omcasts: U64,
    /// Packets dropped on input on this interface.
    pub iqdrops: U64,
    /// Packets with unsupported protocol.
    pub noproto: U64,
    /// Time spent transmitting (usec).
    pub recvtiming: U32,
    /// Time spent receiving (usec).
    pub xmittiming: U32,
    #[cfg(target_pointer_width = "32")]
    /// Timestamp of the last change to the interface.
    pub ifi_lastchange: Time,
    #[cfg(not(target_pointer_width = "32"))]
    /// Timestamp of the last change to the interface.
    pub ifi_lastchange: Time32,
}

#[cfg(target_os = "macos")]
static_assertions::assert_eq_size!(InterfaceData64, libc::if_data64);

/// A point-in-time.
///
/// [`timeval`][libc::timeval] in libc.
#[derive(
    Copy,
    Clone,
    zerocopy::FromBytes,
    zerocopy::KnownLayout,
    zerocopy::Immutable,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub struct Time {
    /// Seconds part.
    pub sec: Unalign<time_t>,
    /// Microseconds part.
    pub usec: Unalign<suseconds_t>,
}

impl Debug for Time {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Time")
            .field("sec", &self.sec.get())
            .field("usec", &self.usec.get())
            .finish()
    }
}

impl PartialEq for Time {
    fn eq(&self, other: &Self) -> bool {
        self.sec.get() == other.sec.get() && self.usec.get() == other.usec.get()
    }
}

impl Eq for Time {}

/// A point-in-time, clamped to 32-bit fields.
///
/// This is a macOS-specific struct used to control the size of a time struct based on the platform
/// pointer width, used in [`InterfaceData64`].
///
/// Called [`timeval32`][libc::timeval32] in libc.
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    zerocopy::FromBytes,
    zerocopy::KnownLayout,
    zerocopy::Immutable,
    zerocopy::Unaligned,
)]
#[repr(C)]
#[cfg(target_os = "macos")]
pub struct Time32 {
    /// Seconds part.
    pub sec: I32,
    /// Microseconds part.
    pub usec: I32,
}

/// Message attributing an address
/// ([`Addrs::INTERFACE_ADDR`][crate::bsd::net_table::Addrs::INTERFACE_ADDR]) to a given interface.
///
/// Called [`ifa_msghdr`][libc::ifa_msghdr] in libc.
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    zerocopy::TryFromBytes,
    zerocopy::KnownLayout,
    zerocopy::Immutable,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub struct InterfaceAddr {
    /// The header for this message.
    ///
    /// It's included primarily because it includes the length of the whole message, which
    /// can be used to deduce the space used by sockaddrs following this header.
    pub header: Header,
    /// [`Addrs`][crate::bsd::net_table::Addrs] and [`Flags`][crate::bsd::net_table::Flags]
    /// for this message.
    pub flag_block: AddrsFlags,
    /// The index of the interface this message pertains to.
    pub index: CUshort,
    /// Padding (required for [`zerocopy::Unaligned`]).
    pub _pad: PadUshort,
    /// Metric for this address as a next-hop.
    pub metric: CInt,
}

static_assertions::assert_eq_size!(InterfaceAddr, libc::ifa_msghdr);

/// Message attributing a multicast address
/// ([`Addrs::INTERFACE_ADDR`][crate::bsd::net_table::Addrs::INTERFACE_ADDR]) to a given interface.
///
/// Called [`ifma_msghdr`][libc::ifma_msghdr] in libc.
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    zerocopy::TryFromBytes,
    zerocopy::KnownLayout,
    zerocopy::Immutable,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub struct MulticastAddr {
    /// The header for this message.
    ///
    /// It's included primarily because it includes the length of the whole message, which
    /// can be used to deduce the space used by sockaddrs following this header.
    pub header: Header,
    /// [`Addrs`][crate::bsd::net_table::Addrs] and [`Flags`][crate::bsd::net_table::Flags]
    /// for this message.
    pub flag_block: AddrsFlags,
    /// The index of the interface this message pertains to.
    pub index: CUshort,
    /// Padding (required for [`zerocopy::Unaligned`]).
    pub _pad: PadUshort,
}

static_assertions::assert_eq_size!(MulticastAddr, libc::ifma_msghdr);

/// Message attributing a multicast address
/// ([`Addrs::INTERFACE_ADDR`][crate::bsd::net_table::Addrs::INTERFACE_ADDR]) to a given interface.
///
/// This is a macOS-specific extension that includes a `refcount` field.
///
/// [`ifma_msghdr2`][libc::ifma_msghdr2] in libc.
#[cfg(target_os = "macos")]
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    zerocopy::TryFromBytes,
    zerocopy::KnownLayout,
    zerocopy::Immutable,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub struct MulticastAddr2 {
    /// The header for this message.
    ///
    /// It's included primarily because it includes the length of the whole message, which
    /// can be used to deduce the space used by sockaddrs following this header.
    pub header: Header,
    /// [`Addrs`][crate::bsd::net_table::Addrs] and [`Flags`][crate::bsd::net_table::Flags]
    /// for this message.
    pub flag_block: AddrsFlags,
    /// The index of the interface this message pertains to.
    pub index: CUshort,
    /// Padding (required for [`zerocopy::Unaligned`]).
    pub _pad: PadUshort,
    /// Refcount for this address.
    pub refcount: I32,
}

#[cfg(target_os = "macos")]
static_assertions::assert_eq_size!(MulticastAddr2, libc::ifma_msghdr2);
