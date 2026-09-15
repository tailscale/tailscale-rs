/// Type of a `PF_ROUTE` message indicated in the header's type field.
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
    /// [`Route`][crate::bsd::net_table::Route].
    Get = libc::RTM_GET as _,
    /// This is a request to get a specific route or a message from the kernel populated by a
    /// [`Route2`][crate::bsd::net_table::Route2].
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
