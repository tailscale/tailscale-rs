//! Functionality supporting asking the kernel to dump the route or interface table via sysctl.

use core::{ffi::c_int, ptr::null_mut};
use std::io;

use libc::{CTL_NET, NET_RT_DUMP, NET_RT_IFLIST, NET_RT_IFLIST2, PF_ROUTE, size_t, sysctl};

use crate::FamilyOrBoth;

/// Which table dump to request.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum DumpType {
    /// Dump routes.
    Route = NET_RT_DUMP as _,
    /// Dump interfaces.
    Interface = NET_RT_IFLIST as _,

    #[cfg(target_os = "macos")]
    /// Dump routes in the macOS-specific [`Route2`][crate::bsd::net_table::Route2] format.
    // aka `NET_RT_DUMP2`, which isn't defined in rust libc, pending a release including
    // https://github.com/rust-lang/libc/pull/5442
    Route2 = 7,
    #[cfg(target_os = "macos")]
    /// Dump interfaces in the macOS-specific [`Interface2`][crate::bsd::net_table::Interface2]
    /// format.
    Interface2 = NET_RT_IFLIST2 as _,
}

impl DumpType {
    /// Report all [`DumpType`]s.
    pub fn all() -> &'static [Self] {
        cfg_if::cfg_if! {
            if #[cfg(target_os = "macos")] {
                &[
                    DumpType::Route,
                    DumpType::Route2,
                    DumpType::Interface,
                    DumpType::Interface2,
                ]
            } else {
                &[
                    DumpType::Route,
                    DumpType::Interface,
                ]
            }
        }
    }
}

/// Dump the given net table.
///
/// `arg` is the final (6th) argument to the sysctl, whose meaning is dependent on the
/// `DumpType`, typically filtering the dump by a specific parameter. Zero typically means
/// "give me everything". See your system's `man sysctl`
/// ([FreeBSD's, e.g.](https://man.freebsd.org/cgi/man.cgi?query=sysctl&sektion=3)) for more
/// details: the meanings of these parameters are known to differ between BSD kernels.
pub fn dump(af: FamilyOrBoth, ty: DumpType, arg: c_int) -> io::Result<Vec<u8>> {
    let mut mib_name = [CTL_NET, PF_ROUTE, 0, af.into(), ty as _, arg];
    let mut buf = vec![];
    let mut err: io::Error = io::ErrorKind::Other.into();

    // There can be a race that can cause reading the MIB to fail, so we retry a few times. See the
    // comment below for why this may occur.
    for _ in 0..3 {
        let mut n = get_mib_size(&mut mib_name[..])?;
        if n == 0 {
            return Ok(vec![]);
        };

        buf.resize(n, 0);

        // SAFETY: this is the correct way to hold `sysctl`. See `man 3 sysctl`.
        let ret = unsafe {
            sysctl(
                mib_name.as_mut_ptr(),
                mib_name.len() as _,
                buf.as_mut_ptr() as *mut _,
                &mut n,
                null_mut(),
                0,
            )
        };

        // It's possible that the MIB can change size substantially between get_mib_size and
        // the above sysctl invocation. The kernel optimistically tries to overestimate the MIB size
        // so that it doesn't fail in this way, but this may still occur. The kernel reports ENOMEM
        // if the error was for this reason (not enough space in the buffer).
        if ret < 0 {
            err = io::Error::last_os_error();

            // Retry if ENOMEM, else bail immediately.
            if err.kind() == io::ErrorKind::OutOfMemory {
                continue;
            }

            return Err(err);
        }

        buf.truncate(n as usize);

        return Ok(buf);
    }

    Err(err)
}

/// Get the size of the buffer required to hold the MIB table referenced by `mib_name`.
fn get_mib_size(mib_name: &mut [c_int]) -> io::Result<size_t> {
    let mut n: size_t = 0;

    // Per macOS `man 3 sysctl`:
    //
    // >The size of the available data can be determined by calling sysctl() with the NULL
    // >argument for oldp. The size of the available data will be returned in the location
    // >pointed to by oldlenp.
    //
    // SAFETY: this is the correct way to hold `sysctl`. See `man 3 sysctl`.
    let ret = unsafe {
        sysctl(
            mib_name.as_mut_ptr(),
            mib_name.len() as _,
            null_mut(),
            &mut n,
            null_mut(),
            0,
        )
    };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(n)
}

#[cfg(test)]
mod test {
    use super::*;

    /// Just the dump sysctl wrapper to ensure it doesn't error.
    #[test]
    fn dump() {
        for &ty in DumpType::all() {
            super::dump(FamilyOrBoth::Both, ty, 0).unwrap();
        }
    }
}
