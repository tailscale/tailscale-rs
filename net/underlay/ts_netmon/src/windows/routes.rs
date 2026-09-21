use core::{
    ops::{Deref, DerefMut},
    ptr::{NonNull, null_mut},
};

use windows::Win32::NetworkManagement::IpHelper;

use crate::{FamilyOrBoth, Route, windows::sockaddr_inet_to_ipaddr};

/// A route table retrieved using [`IpHelper::GetIpForwardTable2`].
///
/// Derefs to `&[IpHelper::MIB_IPFORWARD_ROW2]`.
pub struct RouteTable {
    tab: NonNull<IpHelper::MIB_IPFORWARD_TABLE2>,
    _family: FamilyOrBoth,
}

impl RouteTable {
    /// Get the route table for the specified [`FamilyOrBoth`] from the kernel.
    pub fn get(family: FamilyOrBoth) -> windows::core::Result<Self> {
        let mut tab = null_mut();

        // SAFETY: this is the correct usage of the API per MS docs.
        unsafe { IpHelper::GetIpForwardTable2(family.into(), &mut tab) }.ok()?;

        // Invariant: RouteTable is only ever successfully constructed if GetIpForwardTable2
        // returned NO_ERROR, implying `tab` is a valid, nonnull pointer to a route table.
        Ok(Self {
            tab: NonNull::new(tab).unwrap(),
            _family: family,
        })
    }
}

// SAFETY: route table pointer isn't thread-local, it's just a pointer to a chunk of memory.
// FreeMibTable can be called from any thread.
unsafe impl Send for RouteTable {}

impl Deref for RouteTable {
    type Target = [IpHelper::MIB_IPFORWARD_ROW2];

    fn deref(&self) -> &Self::Target {
        // SAFETY: by invariant described in RouteTable::get, tab is a valid, non-null pointer.
        // Kernel guarantees the table is laid out as a C array, which is valid as a slice.
        unsafe {
            let tab = self.tab.as_ref();
            core::slice::from_raw_parts(tab.Table.as_ptr(), tab.NumEntries as _)
        }
    }
}

impl DerefMut for RouteTable {
    fn deref_mut(&mut self) -> &mut Self::Target {
        // SAFETY: by invariant described in RouteTable::get, tab is a valid, non-null pointer.
        // Kernel guarantees the table is laid out as a C array, which is valid as a slice.
        unsafe {
            let tab = self.tab.as_mut();
            core::slice::from_raw_parts_mut(tab.Table.as_mut_ptr(), tab.NumEntries as _)
        }
    }
}

impl Drop for RouteTable {
    fn drop(&mut self) {
        // SAFETY: by invariant described in RouteTabe::get, tab was successfully allocated by the
        // platform. This is the correct usage of the API per MS docs.
        unsafe { IpHelper::FreeMibTable(self.tab.as_ptr() as *const _) }
    }
}

impl From<&IpHelper::MIB_IPFORWARD_ROW2> for Route {
    fn from(route: &IpHelper::MIB_IPFORWARD_ROW2) -> Self {
        let next_hop = sockaddr_inet_to_ipaddr(&route.NextHop);
        let dest_ip = sockaddr_inet_to_ipaddr(&route.DestinationPrefix.Prefix);
        let dst = ipnet::IpNet::new(dest_ip, route.DestinationPrefix.PrefixLength).unwrap();

        Self {
            metric: route.Metric as _,
            gateway: if next_hop.is_unspecified() {
                // Windows uses the unspecified address to indicate no gateway
                smallvec::smallvec![]
            } else {
                smallvec::smallvec![next_hop]
            },
            dst,
        }
    }
}

impl From<IpHelper::MIB_IPFORWARD_ROW2> for Route {
    fn from(route: IpHelper::MIB_IPFORWARD_ROW2) -> Self {
        Self::from(&route)
    }
}
