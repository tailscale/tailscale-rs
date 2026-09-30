use std::{iter::FusedIterator, mem::MaybeUninit};

use windows::Win32::{Foundation, NetworkManagement::IpHelper};

use crate::FamilyOrBoth;

/// A set of network interfaces at a point in time, reported by Windows.
pub struct InterfaceReport {
    /// Backing storage holding the report which was filled by Windows.
    buf: Vec<MaybeUninit<u8>>,

    /// The address family this report was gathered against.
    _family: FamilyOrBoth,
}

impl InterfaceReport {
    /// Recommended initial size to avoid calling [`IpHelper::GetAdaptersAddresses`]
    /// multiple times.
    const INITIAL_SIZE: u32 = 15000;

    /// Get a report of available network interfaces for the given [`FamilyOrBoth`].
    ///
    /// The system call in this function is costly and may block the thread for on the
    /// order of milliseconds.
    pub fn get(family: FamilyOrBoth) -> windows::core::Result<Self> {
        let mut size = Self::INITIAL_SIZE;
        let mut v = vec![];

        let family_u32 = u32::from(family);

        loop {
            v.resize_with(size as usize, MaybeUninit::uninit);

            // SAFETY: all parameters are ok, see docs:
            // https://learn.microsoft.com/en-us/windows/win32/api/iphlpapi/nf-iphlpapi-getadaptersaddresses
            let result = unsafe {
                IpHelper::GetAdaptersAddresses(
                    family_u32,
                    IpHelper::GAA_FLAG_INCLUDE_ALL_INTERFACES,
                    None,
                    Some(v.as_mut_ptr() as _),
                    &mut size as *mut _,
                )
            };
            let result = Foundation::WIN32_ERROR(result).ok();

            match result {
                Ok(()) => {
                    // Invariants:
                    // - This type is only constructed if GetAdaptersAddresses succeeded.
                    // - self.buf's length is the actual size the kernel told us.

                    v.truncate(size as _);

                    break Ok(Self {
                        buf: v,
                        _family: family,
                    });
                }
                Err(e) if e.code() == Foundation::ERROR_BUFFER_OVERFLOW.to_hresult() => {
                    // need more space, and `size` now holds the new required allocation size, try
                    // again.
                    continue;
                }
                Err(e) => {
                    return Err(e);
                }
            }
        }
    }

    /// Return an iterator over the adapters in this report.
    pub fn iter(&self) -> ReportIter<'_> {
        let init = if self.buf.is_empty() {
            None
        } else {
            // SAFETY: two concerns:
            //
            // - Ref-convertibility of `self.buf` as `*const IP_ADAPTER_ADDRESSES_LH`: this is
            //   guaranteed by the kernel -- the first item in the allocation is the first entry in
            //   the linked list. By the length invariant in `get`, the buf-empty check here is
            //   sufficient to ensure we have at least one valid entry.
            // - Lifetime of the returned ref: the `IP_ADAPTER_ADDRESSES_LH` structure is a linked
            //   list with internal pointers that all point into the internal allocation
            //   (`self.buf`). Hence, it's fine to return a ref with the inferred `'self` lifetime
            //   here, as the `ReportIter` (and all its references into `self.buf`) must drop before
            //   we do (and hence `self.buf` does).
            unsafe { (self.buf.as_ptr() as *const IpHelper::IP_ADAPTER_ADDRESSES_LH).as_ref() }
        };

        ReportIter { next: init }
    }
}

/// Iterator over an [`InterfaceReport`].
pub struct ReportIter<'a> {
    next: Option<&'a IpHelper::IP_ADAPTER_ADDRESSES_LH>,
}

impl<'a> Iterator for ReportIter<'a> {
    type Item = &'a IpHelper::IP_ADAPTER_ADDRESSES_LH;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = self.next?;

        // SAFETY: the only way we can have a `ReportIter` is if it was produced by
        // `InterfaceReport::iter`, meaning that the lifetime 'a is the lifetime of the parent `buf`
        // holding a backing allocation. `ret.Next` points into that allocation, so its lifetime is
        // also 'a (as created here).
        //
        // The ref-convertibility of the pointer is ensured by the kernel if it's non-null.
        self.next = unsafe { ret.Next.as_ref() };

        Some(ret)
    }
}

impl FusedIterator for ReportIter<'_> {}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn report_to_interface() {
        let report = InterfaceReport::get(FamilyOrBoth::Both).unwrap();

        for interface in report.iter() {
            let interface = crate::Interface::from(interface);
            println!("{interface:?}");
        }
    }
}
