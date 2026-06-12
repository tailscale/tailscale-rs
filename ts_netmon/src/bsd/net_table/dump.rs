//! Functionality supporting asking the kernel to dump the route or interface table via sysctl.

use core::{ffi::c_int, ptr::null_mut};
use std::io;

use libc::{CTL_NET, NET_RT_DUMP, NET_RT_IFLIST, NET_RT_IFLIST2, PF_ROUTE, size_t, sysctl};

use crate::FamilyOrBoth;

/// Which table dump to request.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DumpType {
    /// Get routes.
    Route = NET_RT_DUMP as _,
    /// Get interfaces.
    Interface = NET_RT_IFLIST as _,

    #[cfg(target_os = "macos")]
    /// Get routes in the route2 format (includes macOS-specific extended attributes).
    ///
    /// The returned routes are expected to be in [`Route2`][crate::bsd::net_table::Route2] format.
    Route2 = 7, // NET_RT_DUMP2 (not defined in rust libc)
    #[cfg(target_os = "macos")]
    /// Get interfaces in the interface2 format (includes macOS-specific extended attributes).
    ///
    /// The returned interfaces are expected to be in
    /// [`Interface2`][crate::bsd::net_table::Interface2] format.
    Interface2 = NET_RT_IFLIST2 as _,
}

/// Dump the given net table.
pub fn dump(af: FamilyOrBoth, ty: DumpType, arg: c_int) -> io::Result<Vec<u8>> {
    let mut mib = [CTL_NET, PF_ROUTE, 0, af.into(), ty as _, arg];
    let mut n: size_t = 0;

    // Call the sysctl once to populate `n`, the size of the buffer required to hold the table.
    let ret = unsafe {
        sysctl(
            mib.as_mut_ptr(),
            mib.len() as _,
            null_mut(),
            &mut n,
            null_mut(),
            0,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    if n == 0 {
        return Ok(vec![]);
    };

    // Allocate buffer and call the sysctl again to populate it.
    let mut buf = vec![0u8; n];

    let ret = unsafe {
        sysctl(
            mib.as_mut_ptr(),
            mib.len() as _,
            buf.as_mut_ptr() as *mut _,
            &mut n,
            null_mut(),
            0,
        )
    };

    // TODO(npry): retry a couple times. Per the Go implementation, this can race between the first
    //   and second calls; if the table grows in between, we'll fail here.
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    buf.truncate(n as usize);

    Ok(buf)
}
