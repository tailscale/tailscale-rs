use core::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use windows::Win32::{
    NetworkManagement::{IpHelper, Ndis},
    Networking::WinSock,
};

use crate::{Family, FamilyOrBoth, InterfaceId, MonType};

impl From<Ndis::NET_LUID_LH> for InterfaceId {
    fn from(luid: Ndis::NET_LUID_LH) -> InterfaceId {
        // SAFETY: all u64 bitpatterns are valid
        InterfaceId::new(MonType::WINDOWS_IPHLPAPI, unsafe { luid.Value })
    }
}

impl From<&Ndis::NET_LUID_LH> for InterfaceId {
    fn from(l: &Ndis::NET_LUID_LH) -> InterfaceId {
        (*l).into()
    }
}

/// Convert a [`WinSock::SOCKADDR_INET`] to [`IpAddr`].
pub fn sockaddr_inet_to_ipaddr(sin: &WinSock::SOCKADDR_INET) -> IpAddr {
    // SAFETY: all bitpatterns valid for u16
    match unsafe { sin.si_family } {
        WinSock::AF_INET => {
            // SAFETY: this is the meaning of `sa_family = AF_INET`
            let sa = unsafe { &sin.Ipv4 };
            // SAFETY: all bitpatterns are valid
            let bytes = unsafe { sa.sin_addr.S_un.S_un_b };
            let ip = Ipv4Addr::new(bytes.s_b1, bytes.s_b2, bytes.s_b3, bytes.s_b4);

            ip.into()
        }
        WinSock::AF_INET6 => {
            // SAFETY: this is the meaning of `sa_family = AF_INET6`
            let sa = unsafe { &sin.Ipv6 };
            // SAFETY: all bitpatterns are valid for [u8; 16]
            let ip = Ipv6Addr::from_octets(unsafe { sa.sin6_addr.u.Byte });

            ip.into()
        }
        _unknown => {
            unreachable!()
        }
    }
}

/// Convert [`IpHelper::MIB_UNICASTIPADDRESS_ROW`] to [`ipnet::IpNet`].
pub fn unicast_row_to_ipnet(row: &IpHelper::MIB_UNICASTIPADDRESS_ROW) -> ipnet::IpNet {
    let pfx_len = row.OnLinkPrefixLength;
    let ip = sockaddr_inet_to_ipaddr(&row.Address);
    ipnet::IpNet::new(ip, pfx_len).unwrap()
}

impl From<&IpHelper::IP_ADAPTER_ADDRESSES_LH> for crate::Interface {
    fn from(value: &IpHelper::IP_ADAPTER_ADDRESSES_LH) -> Self {
        let mac = &value.PhysicalAddress[..value.PhysicalAddressLength as _];

        crate::Interface {
            id: value.Luid.into(),

            // SAFETY: Windows handed us this value, so we can rely on it being correctly
            // NUL-terminated.
            name: String::from_utf16_lossy(unsafe { value.FriendlyName.as_wide() }),

            up: value.OperStatus == Ndis::IfOperStatusUp,

            mtu: if value.Mtu == 0 {
                None
            } else {
                Some(value.Mtu as _)
            },

            hardware_addr: if !mac.is_empty() {
                Some(mac.into())
            } else {
                None
            },

            metric_v4: value.Ipv4Metric as _,
            metric_v6: value.Ipv6Metric as _,
        }
    }
}

impl From<Family> for WinSock::ADDRESS_FAMILY {
    fn from(family: Family) -> Self {
        match family {
            Family::Ipv4 => WinSock::AF_INET,
            Family::Ipv6 => WinSock::AF_INET6,
        }
    }
}

impl From<Family> for u32 {
    fn from(family: Family) -> Self {
        WinSock::ADDRESS_FAMILY::from(family).0 as _
    }
}

impl From<FamilyOrBoth> for WinSock::ADDRESS_FAMILY {
    fn from(family: FamilyOrBoth) -> Self {
        match family {
            FamilyOrBoth::Both => WinSock::AF_UNSPEC,
            FamilyOrBoth::Single(family) => family.into(),
        }
    }
}

impl From<FamilyOrBoth> for u32 {
    fn from(family: FamilyOrBoth) -> Self {
        WinSock::ADDRESS_FAMILY::from(family).0 as _
    }
}

impl TryFrom<WinSock::ADDRESS_FAMILY> for FamilyOrBoth {
    type Error = ();
    fn try_from(family: WinSock::ADDRESS_FAMILY) -> Result<Self, Self::Error> {
        match family {
            WinSock::AF_UNSPEC => Ok(FamilyOrBoth::Both),
            WinSock::AF_INET => Ok(Family::Ipv4.into()),
            WinSock::AF_INET6 => Ok(Family::Ipv6.into()),
            _ => Err(()),
        }
    }
}
