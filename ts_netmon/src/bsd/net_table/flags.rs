use core::{
    ffi::c_uint,
    fmt::{Debug, Formatter},
};

use crate::bsd::net_table::CUint;

/// Helper type which packs (addrs, flags) in that order and provides accessors for the [`Flags`]
/// and [`Addrs`] bitflags.
///
/// See [`FlagsAddrs`] for the other field order.
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::IntoBytes,
    zerocopy::FromBytes,
    zerocopy::Unaligned,
    Default,
)]
#[repr(C)]
pub struct AddrsFlags {
    addrs: CUint,
    flags: CUint,
}

impl Debug for AddrsFlags {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AddrsFlags")
            .field("addrs", &self.addrs())
            .field("flags", &self.flags())
            .finish()
    }
}

impl AddrsFlags {
    /// [`Flags`] set on this message.
    pub const fn flags(&self) -> Flags {
        Flags::from_bits_retain(self.flags.get())
    }

    /// Set the [`Flags`].
    pub const fn set_flags(&mut self, flags: Flags) {
        self.flags = CUint::new(flags.bits());
    }

    /// Addresses present in this message.
    pub const fn addrs(&self) -> Addrs {
        Addrs::from_bits_retain(self.addrs.get())
    }

    /// Set the [`Addrs`].
    pub const fn set_addrs(&mut self, addrs: Addrs) {
        self.addrs = CUint::new(addrs.bits());
    }
}

/// Helper type which packs (flags, addrs) in that order and provides accessors for the [`Flags`]
/// and [`Addrs`] bitflags.
///
/// See [`AddrsFlags`] for the other field order.
#[derive(
    Copy,
    Clone,
    PartialEq,
    Eq,
    zerocopy::Immutable,
    zerocopy::KnownLayout,
    zerocopy::IntoBytes,
    zerocopy::FromBytes,
    zerocopy::Unaligned,
    Default,
)]
#[repr(C)]
pub struct FlagsAddrs {
    flags: CUint,
    addrs: CUint,
}

impl Debug for FlagsAddrs {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FlagsAddrs")
            .field("flags", &self.flags())
            .field("addrs", &self.addrs())
            .finish()
    }
}

impl FlagsAddrs {
    /// [`Flags`] set on this message.
    pub const fn flags(&self) -> Flags {
        Flags::from_bits_retain(self.flags.get())
    }

    /// Set the [`Flags`].
    pub const fn set_flags(&mut self, flags: Flags) {
        self.flags = CUint::new(flags.bits());
    }

    /// Addresses present in this message.
    pub const fn addrs(&self) -> Addrs {
        Addrs::from_bits_retain(self.addrs.get())
    }

    /// Set the [`Addrs`].
    pub const fn set_addrs(&mut self, addrs: Addrs) {
        self.addrs = CUint::new(addrs.bits());
    }
}

bitflags::bitflags! {
    /// Flags indicating the address types present in a message.
    #[derive(
        Debug, Copy, Clone, PartialEq, Eq,
    )]
    pub struct Addrs: c_uint {
        // NOTE(npry): the specific form of these declarations is a load-bearing part of this API;
        // the addresses in a PF_ROUTE message are present in _this specific order_ if the relevant
        // bit is set, and the generated `.iter()` iterates them in declaration order. It is relied
        // upon elsewhere to be correct.

        /// Route destination is present.
        const DESTINATION = libc::RTA_DST as _;
        /// Route gateway is present.
        const GATEWAY = libc::RTA_GATEWAY as _;
        /// Netmask is present.
        const NETMASK = libc::RTA_NETMASK as _;
        /// Netmask for child (clone) routes of this route.
        const GENMASK = libc::RTA_GENMASK as _;
        /// The interface name is present.
        const INTERFACE_NAME = libc::RTA_IFP as _;
        /// THe interface address is present.
        const INTERFACE_ADDR = libc::RTA_IFA as _;
        /// If this route was authorized by a downstream gateway, its address is present.
        const REDIRECT_AUTHORIZER = libc::RTA_AUTHOR as _;
        /// The broadcast address is present.
        const BROADCAST_ADDR = libc::RTA_BRD as _;
    }
}

impl Default for Addrs {
    fn default() -> Self {
        Addrs::empty()
    }
}

bitflags::bitflags! {
    /// Flags set on a given route message.
    #[derive(
        Debug, Copy, Clone, PartialEq, Eq, Default,
    )]
    pub struct Flags: c_uint {
        /// The route is active.
        const UP = libc::RTF_UP as _;
        /// The route is inactive, typically because the underlying interface has been deleted or
        /// gone inactive and this route is going to be deleted.
        const DEAD = libc::RTF_DEAD as _;
        /// Route is pending deletion but has active references.
        const CONDEMNED = libc::RTF_CONDEMNED as _;

        /// This route will keep the corresponding network interface alive if it would otherwise be
        /// deleted.
        const IFREF = libc::RTF_IFREF as _;
        /// Prevent this route from keeping the corresponding interface alive (don't increment its
        /// refcount).
        const NO_IFREF = libc::RTF_NOIFREF as _;

        /// Whether this route has a gateway/next-hop or is on-link.
        const GATEWAY = libc::RTF_GATEWAY as _;
        /// The destination of this route is for a single host.
        const HOST = libc::RTF_HOST as _;
        /// The destination is an address on this host.
        const LOCAL = libc::RTF_LOCAL as _;
        /// The destination is a broadcast address.
        const BROADCAST = libc::RTF_BROADCAST as _;
        /// The destination is a multicast address.
        const MULTICAST = libc::RTF_MULTICAST as _;
        /// The destination is a next-hop router.
        const ROUTER = libc::RTF_ROUTER as _;
        /// Route leads to the public internet.
        const GLOBAL = libc::RTF_GLOBAL as _;

        /// The destination is unreachable; ICMP unreachables are returned.
        const REJECT = libc::RTF_REJECT as _;
        /// Packets matching this route are silently dropped.
        const BLACKHOLE = libc::RTF_BLACKHOLE as _;

        /// The route was configured administratively.
        const STATIC = libc::RTF_STATIC as _;
        /// Route is administratively pinned and can't be modified by a routing protocol.
        const PINNED = libc::RTF_PINNED as _;
        /// The route was created dynamically.
        const DYNAMIC = libc::RTF_DYNAMIC as _;
        /// This route was modified dynamically.
        const MODIFIED = libc::RTF_MODIFIED as _;

        /// The AF_ROUTE transaction this message is associated with is complete.
        const DONE = libc::RTF_DONE as _;

        /// This route has generic link-layer cloning behavior, typically just generating dynamic
        /// layer 2 routes from the ARP cache.
        const CLONING = libc::RTF_CLONING as _;
        /// Protocol-specific cloning behavior, i.e. like [`Flags::CLONING`] except that the L3
        /// network stack is ultimately responsible for creating the entry.
        const PRCLONING = libc::RTF_PRCLONING as _;
        /// This route was cloned from a parent.
        const WAS_CLONED = libc::RTF_WASCLONED as _;
        /// Child clone routes are proactively purged by the kernel if this route (the parent) is
        /// deleted.
        const DELCLONE = libc::RTF_DELCLONE as _;
        /// This is a layer 2 route, i.e. an ARP table or ND entry.
        const LLINFO = libc::RTF_LLINFO as _;
        /// This is a proxy ARP route for the destination.
        const PROXY_ARP = libc::RTF_PROXY as _;

        /// This route is resolved externally through a userspace routing daemon.
        const XRESOLVE = libc::RTF_XRESOLVE as _;

        /// This is an interface-scoped route.
        const IFSCOPE = libc::RTF_IFSCOPE as _;

        /// Flag for protocol-specific use with implementation-defined meaning.
        const PROTO1 = libc::RTF_PROTO1 as _;
        /// Flag for protocol-specific use with implementation-defined meaning.
        const PROTO2 = libc::RTF_PROTO2 as _;
        /// Flag for protocol-specific use with implementation-defined meaning.
        const PROTO3 = libc::RTF_PROTO3 as _;
    }
}
