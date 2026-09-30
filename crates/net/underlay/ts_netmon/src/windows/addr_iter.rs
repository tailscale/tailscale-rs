//! Iterators over linked lists of addresses as provided by win32.

use core::{
    iter::FusedIterator,
    net::{Ipv4Addr, Ipv6Addr},
};

use windows::Win32::{NetworkManagement::IpHelper, Networking::WinSock};

trait WinAddr {
    fn sockaddr(&self) -> &WinSock::SOCKADDR;
    fn next(&self) -> Option<&dyn WinAddr>;
    fn prefix_len(&self) -> Option<u8>;
}

macro_rules! impl_winaddr {
    ($ty:ty) => {
        impl_winaddr!($ty, |_| None);
    };
    ($ty:ty, $pfx:expr) => {
        impl WinAddr for $ty {
            fn sockaddr(&self) -> &WinSock::SOCKADDR {
                // SAFETY: only used for kernel-provided values, ref-convertibility is guaranteed.
                unsafe { self.Address.lpSockaddr.as_ref() }.unwrap()
            }

            fn next(&self) -> Option<&dyn WinAddr> {
                // SAFETY: only used for kernel-provided values, ref-convertibility is guaranteed.
                // It's a Self, so it impls `dyn WinAddr`.
                unsafe { (self.Next as *const dyn WinAddr).as_ref() }
            }

            fn prefix_len(&self) -> Option<u8> {
                ($pfx)(self)
            }
        }
    };
}

impl_winaddr!(
    IpHelper::IP_ADAPTER_UNICAST_ADDRESS_LH,
    (|slf: &IpHelper::IP_ADAPTER_UNICAST_ADDRESS_LH| Some(slf.OnLinkPrefixLength))
);
impl_winaddr!(IpHelper::IP_ADAPTER_UNICAST_ADDRESS_XP);
impl_winaddr!(
    IpHelper::IP_ADAPTER_PREFIX_XP,
    |slf: &IpHelper::IP_ADAPTER_PREFIX_XP| Some(slf.PrefixLength as u8)
);

/// Iterator over a Windows linked-list-of-addresses type.
pub struct AddrIter<'a> {
    item: Option<&'a dyn WinAddr>,
}

macro_rules! iter_fn {
    ($name:ident, $field:ident) => {
        #[doc = concat!("Helper to iterate over the addresses in [`IpHelper::IP_ADAPTER_ADDRESSES_LH::", stringify!($field), "`].")]
        pub fn $name(addrs: &IpHelper::IP_ADAPTER_ADDRESSES_LH) -> AddrIter<'_> {
            AddrIter {
                // SAFETY: the kernel originally provided the value, so it's ref-convertible as its
                // type (if non-null), and the field type impls `WinAddr`.
                item: unsafe { (addrs.$field as *const dyn WinAddr).as_ref() },
            }
        }
    };
}

iter_fn!(iter_unicast, FirstUnicastAddress);
iter_fn!(iter_prefixes, FirstPrefix);

impl Iterator for AddrIter<'_> {
    type Item = ipnet::IpNet;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            let ret = self.item?;

            let sa = ret.sockaddr();
            self.item = ret.next();

            match sa.sa_family {
                WinSock::AF_INET => {
                    // SAFETY: this is the meaning of `sa_family = AF_INET`
                    let sa = unsafe {
                        core::mem::transmute::<&WinSock::SOCKADDR, &WinSock::SOCKADDR_IN>(sa)
                    };
                    // SAFETY: all bitpatterns are valid
                    let bytes = unsafe { sa.sin_addr.S_un.S_un_b };
                    let ip = Ipv4Addr::new(bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4);

                    break Some(
                        ipnet::IpNet::new(ip.into(), ret.prefix_len().unwrap_or(32)).unwrap(),
                    );
                }
                WinSock::AF_INET6 => {
                    // SAFETY: this is the meaning of `sa_family = AF_INET6`
                    let sa = unsafe {
                        core::mem::transmute::<&WinSock::SOCKADDR, &WinSock::SOCKADDR_IN6>(sa)
                    };
                    // SAFETY: all bitpatterns are valid for [u8; 16]
                    let ip = Ipv6Addr::from_octets(unsafe { sa.sin6_addr.u.Byte });

                    break Some(
                        ipnet::IpNet::new(ip.into(), ret.prefix_len().unwrap_or(128)).unwrap(),
                    );
                }
                _unknown => {
                    continue;
                }
            }
        }
    }
}

impl FusedIterator for AddrIter<'_> {}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{Family, FamilyOrBoth, windows::InterfaceReport};

    #[test]
    fn iter_report() {
        for family in [FamilyOrBoth::Both, Family::Ipv4.into(), Family::Ipv6.into()] {
            let report = InterfaceReport::get(family).unwrap();

            for elem in report.iter() {
                println!(
                    "{}/{}:",
                    unsafe { elem.AdapterName.to_string() }.unwrap(),
                    unsafe { elem.FriendlyName.to_string() }.unwrap()
                );

                print!("\tprefixes: ",);
                for pfx in iter_prefixes(elem) {
                    print!("{pfx}, ");
                }

                print!("\n\tunicast: ");
                for pfx in iter_unicast(elem) {
                    print!("{pfx}, ");
                }

                println!();
                println!();
            }

            println!();
            println!();
        }
    }
}
