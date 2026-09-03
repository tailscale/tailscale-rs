//! Message headers for `NET_RT_DUMP[2]` messages.

use core::fmt::Debug;

use libc::pid_t;
use zerocopy::{
    Unalign,
    native_endian::{I32, U32},
};

use crate::bsd::net_table::{CInt, CUint, CUshort, Flags, FlagsAddrs, Header, PadUshort};

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
    pub header: Header,
    pub index: CUshort,
    _pad: PadUshort,
    pub flag_block: FlagsAddrs,
    pub refcount: I32,
    parent_flags: U32,
    _reserved: CInt,
    pub use_: CInt,
    pub inits: U32,
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
        Flags::from_bits_retain(self.parent_flags.get())
    }
}

/// Route header block.
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
    pub header: Header,
    pub index: CUshort,
    pub _pad: PadUshort,
    pub flag_block: FlagsAddrs,
    pub pid: Unalign<pid_t>,
    pub seq: CUint,
    pub errno: CInt,
    pub use_: CUint,
    pub inits: U32,
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

/// Metrics for a given route.
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
    pub locks: U32,
    pub mtu: U32,
    pub hopcount: U32,
    pub expire: I32,
    pub recvpipe: U32,
    pub sendpipe: U32,
    pub ssthresh: U32,
    pub rtt: U32,
    pub rttvar: U32,
    pub pksent: U32,
    _reserved: [U32; 4],
}

static_assertions::assert_eq_size!(Metrics, libc::rt_metrics);
