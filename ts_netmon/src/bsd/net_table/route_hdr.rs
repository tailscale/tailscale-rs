//! Headers for route messages.

use core::fmt::Debug;

use libc::pid_t;
use zerocopy::{
    Unalign,
    native_endian::{I32, U32},
};

use crate::bsd::net_table::{CInt, CUint, CUshort, Flags, FlagsAddrs, Header, PadUshort};

/// Encodes information about a route.
///
/// macOS-specific extension of [`Route`] with some additional information.
///
/// [`rt_msghdr2`][libc::rt_msghdr2] in libc.
#[cfg(target_os = "macos")]
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    zerocopy::Immutable,
    zerocopy::TryFromBytes,
    zerocopy::KnownLayout,
    zerocopy::Unaligned,
)]
#[repr(C)]
pub struct Route2 {
    /// The header for this message.
    ///
    /// It's included primarily because it includes the length of the whole message, which
    /// can be used to deduce the space used by sockaddrs following this header.
    pub header: Header,
    /// The index of the interface this route pertains to.
    pub index: CUshort,
    /// Padding (required for [`zerocopy::Unaligned`]).
    pub _pad: PadUshort,
    /// [`Addrs`][crate::bsd::net_table::Addrs] and [`Flags`][crate::bsd::net_table::Flags]
    /// for this message.
    pub flag_block: FlagsAddrs,
    /// Kernel refcount for this route.
    pub refcount: I32,
    /// Flags set on this message's parent, if it was cloned.
    ///
    /// See [`Route2::parent_flags`] for the interpretation of the field as [`Flags`].
    pub _parent_flags: U32,
    /// Reserved region.
    pub _reserved: CInt,
    /// Usage counter for this route (number of packets sent using the route).
    pub use_: CInt,
    /// Bitmask indicating which metrics to init/update (userspace -> kernel).
    pub inits: U32,
    /// Metrics for this route.
    pub metrics: Metrics,
}

#[cfg(target_os = "macos")]
static_assertions::assert_eq_size!(Route2, libc::rt_msghdr2);

#[cfg(target_os = "macos")]
impl Debug for Route2 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Route2")
            .field("header", &self.header)
            .field("index", &self.index)
            .field("flag_block", &self.flag_block)
            .field("refcount", &self.refcount)
            .field("parent_flags", &self.parent_flags())
            .field("use", &self.use_)
            .field("inits", &self.inits)
            .field("metrics", &self.metrics)
            .finish()
    }
}

#[cfg(target_os = "macos")]
impl Route2 {
    /// [`Flags`] set on this message's parent, if it was cloned.
    pub const fn parent_flags(&self) -> Flags {
        Flags::from_bits_retain(self._parent_flags.get())
    }
}

/// Message header encoding information about a route.
///
/// [`rt_msghdr`][libc::rt_msghdr] in libc.
#[derive(
    Copy,
    Clone,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::TryFromBytes,
    zerocopy::KnownLayout,
    zerocopy::Unaligned,
    Default,
)]
#[repr(C)]
pub struct Route {
    /// The header for this message.
    ///
    /// It's included primarily because it includes the length of the whole message, which
    /// can be used to deduce the space used by sockaddrs following this header.
    pub header: Header,
    /// The index of the interface this route pertains to.
    pub index: CUshort,
    /// Padding (required for [`zerocopy::Unaligned`]).
    pub _pad: PadUshort,
    /// [`Addrs`][crate::bsd::net_table::Addrs] and [`Flags`][crate::bsd::net_table::Flags]
    /// for this message.
    pub flag_block: FlagsAddrs,
    /// The pid of the process originating this message.
    pub pid: Unalign<pid_t>,
    /// Sequence number of the message.
    pub seq: CUint,
    /// Nonzero error number if the operation corresponding to `seq` failed.
    pub errno: CInt,
    /// Usage counter for this route (number of lookup hits for the route).
    pub use_: CUint,
    /// Bitmask indicating which metrics to init/update (userspace -> kernel).
    pub inits: U32,
    /// Metrics for this route.
    pub metrics: Metrics,
}

static_assertions::assert_eq_size!(Route, libc::rt_msghdr);

impl PartialEq for Route {
    fn eq(&self, other: &Self) -> bool {
        self.header == other.header
            && self.index == other.index
            && self.flag_block == other.flag_block
            && self.pid.get() == other.pid.get()
            && self.seq == other.seq
            && self.errno == other.errno
            && self.use_ == other.use_
            && self.inits == other.inits
            && self.metrics == other.metrics
    }
}

impl Eq for Route {}

impl Debug for Route {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Route")
            .field("header", &self.header)
            .field("index", &self.index)
            .field("flag_block", &self.flag_block)
            .field("pid", &self.pid.get())
            .field("seq", &self.seq)
            .field("errno", &self.errno)
            .field("use", &self.use_)
            .field("inits", &self.inits)
            .field("metrics", &self.metrics)
            .finish()
    }
}

/// Metrics for a given route, embedded in [`Route`] (and `Route2` on macOS).
///
/// [`rt_metrics`][libc::rt_metrics] in libc.
#[derive(
    Debug,
    Copy,
    Clone,
    PartialEq,
    Eq,
    zerocopy::Immutable,
    zerocopy::IntoBytes,
    zerocopy::TryFromBytes,
    zerocopy::KnownLayout,
    zerocopy::Unaligned,
    Default,
)]
#[repr(C)]
pub struct Metrics {
    /// Bitmasks indicating protection for other metrics field (kernel shouldn't update).
    pub locks: U32,
    /// MTU for this route.
    pub mtu: U32,
    /// Maximum hopcount for this route.
    pub hopcount: U32,
    /// Time remaining on a dynamic routing entry.
    pub expire: I32,
    /// TCP: receive buffer size.
    pub recvpipe: U32,
    /// TCP: send buffer size.
    pub sendpipe: U32,
    /// TCP: ssthresh.
    pub ssthresh: U32,
    /// TCP RTT.
    pub rtt: U32,
    /// TCP RTT variance.
    pub rttvar: U32,
    /// Packets sent using this route.
    pub pksent: U32,
    /// Reserved.
    pub _reserved: [U32; 4],
}

static_assertions::assert_eq_size!(Metrics, libc::rt_metrics);
