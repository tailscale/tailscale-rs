//! IFMIB-related messages.

use core::{ffi::c_uchar, fmt::Debug};

use libc::{suseconds_t, time_t};
use zerocopy::{
    Unalign,
    native_endian::{I32, U32, U64},
};

use crate::bsd::net_table::{CInt, CUshort, Header, PadUshort, flags::AddrsFlags};

/// [`if_msghdr2`][libc::if_msghdr2].
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
    pub header: Header,
    pub flag_block: AddrsFlags,
    pub index: CUshort,
    pub _pad: PadUshort,
    pub snd_len: CInt,
    pub snd_maxlen: CInt,
    pub snd_drops: CInt,
    pub timer: CInt,
    pub data: InterfaceData64,
}

#[cfg(target_os = "macos")]
static_assertions::assert_eq_size!(Interface2, libc::if_msghdr2);

/// An interface table entry.
///
/// Describes a physical interface, commonly followed by a [`LinkAddress`] bearing its name.
///
/// [`if_msghdr`][libc::if_msghdr] in libc.
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
    pub header: Header,
    pub flag_block: AddrsFlags,
    pub index: CUshort,
    pub _pad: PadUshort,
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
    pub ty: c_uchar,
    pub typelen: c_uchar,
    pub physical: c_uchar,
    pub addrlen: c_uchar,
    pub hdrlen: c_uchar,
    pub recvquota: c_uchar,
    pub xmitquota: c_uchar,
    pub unused1: c_uchar,
    pub mtu: U32,
    pub metric: U32,
    pub baudrate: U32,
    pub ipackets: U32,
    pub ierrors: U32,
    pub opackets: U32,
    pub oerrors: U32,
    pub collisions: U32,
    pub ibytes: U32,
    pub obytes: U32,
    pub imcasts: U32,
    pub omcasts: U32,
    pub iqdrops: U32,
    pub noproto: U32,
    pub recvtiming: U32,
    pub xmittiming: U32,
    pub lastchange: Time32,
    pub unused2: U32,
    pub hwassist: U32,
    pub reserved1: U32,
    pub reserved2: U32,
}

/// 64-bit version of [`InterfaceData`].
///
/// [`if_data64`][libc::if_data64] in libc.
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
    pub ty: c_uchar,
    pub typelen: c_uchar,
    pub physical: c_uchar,
    pub addrlen: c_uchar,
    pub hdrlen: c_uchar,
    pub recvquota: c_uchar,
    pub xmitquota: c_uchar,
    pub unused1: c_uchar,
    pub mtu: U32,
    pub metric: U32,
    pub baudrate: U64,
    pub ipackets: U64,
    pub ierrors: U64,
    pub opackets: U64,
    pub oerrors: U64,
    pub collisions: U64,
    pub ibytes: U64,
    pub obytes: U64,
    pub imcasts: U64,
    pub omcasts: U64,
    pub iqdrops: U64,
    pub noproto: U64,
    pub recvtiming: U32,
    pub xmittiming: U32,
    #[cfg(target_pointer_width = "32")]
    pub ifi_lastchange: Time,
    #[cfg(not(target_pointer_width = "32"))]
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
    pub sec: Unalign<time_t>,
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
/// [`timeval32`][libc::timeval32] in libc.
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
    pub sec: I32,
    pub usec: I32,
}

/// [`ifa_msghdr`][libc::ifa_msghdr] in libc.
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
    pub header: Header,
    pub flag_block: AddrsFlags,
    pub index: CUshort,
    pub _pad: PadUshort,
    pub metric: CInt,
}

static_assertions::assert_eq_size!(InterfaceAddr, libc::ifa_msghdr);

/// [`ifma_msghdr`][libc::ifma_msghdr] in libc.
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
    pub header: Header,
    pub flag_block: AddrsFlags,
    pub index: CUshort,
    pub _pad: PadUshort,
}

static_assertions::assert_eq_size!(MulticastAddr, libc::ifma_msghdr);

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
    pub header: Header,
    pub flag_block: AddrsFlags,
    pub index: CUshort,
    pub _pad: PadUshort,
    pub refcount: I32,
}

#[cfg(target_os = "macos")]
static_assertions::assert_eq_size!(MulticastAddr2, libc::ifma_msghdr2);
