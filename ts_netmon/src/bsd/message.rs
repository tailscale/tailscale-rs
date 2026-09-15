use std::net::IpAddr;

use ipnet::IpNet;
use nom::{Parser, multi::many0};

use crate::{
    Event, Family, Interface, InterfaceId, MonType, Route, bsd,
    bsd::{
        net_table,
        net_table::{Address, Addrs, Flags, LinkAddr, MessageHeader, PrefixLen},
    },
};

/// A `PF_ROUTE` message parsed from a buffer.
///
/// This is lifted out of [`net_table`] because it's essentially an adapter from the types there
/// into the [`ts_netmon`][crate] types.
#[derive(Debug, Clone)]
pub struct Message<'a> {
    /// Message header for this message.
    pub header: MessageHeader<'a>,
    /// Addresses parsed for this message.
    pub addrs: Vec<Option<Address>>,
}

impl<'a> Message<'a> {
    /// Parse a [`Message`] from a buffer.
    pub fn parse(buf: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (rest, payload) = net_table::msg_chunk().parse_complete(buf)?;
        let (addrs, (_ty, slf)) = MessageHeader::parse.parse_complete(payload)?;

        // NOTE: Typically, `_rest` will be empty here, but there's technically nothing requiring
        // that. The kernel could completely legally have given us a route message with an empty
        // address block and 32kB of padding if it so chose.
        let (_rest, parsed_addrs) = many0(nom::combinator::complete(Address::parse::<
            _,
            nom::error::Error<_>,
        >()))
        .parse(addrs)?;

        if parsed_addrs.len() != slf.addrs().bits().count_ones() as usize {
            let is_ipv6 = parsed_addrs.iter().any(|x| {
                let Some(x) = x else {
                    return false;
                };

                let Ok(addr) = IpAddr::try_from(x) else {
                    return false;
                };

                addr.is_ipv6()
            });

            let ends_with_broadcast = slf.addrs().iter().last() == Some(Addrs::BROADCAST_ADDR);

            // Don't warn if this is a known case where XNU will omit the address entirely.
            //
            // We've seen this occur when we would otherwise expect the final address to be nulled
            // out but padded up to 4 bytes.
            //
            // E.g., if the kernel handed me a message with RTA_IFA | RTA_BRD (in that order) and
            // the RTA_IFA was null but a RTA_BRD wasn't, it would need to put something
            // in the RTA_IFA spot to disambiguate the parse (so I know there's something before
            // the RTA_BRD). This is when it hands us [0, 0, 0, 0], which is special-cased in the
            // address parsing.
            //
            // If on the other hand it wanted to do the other thing (RTA_IFA present, RTA_BRD null),
            // it could maintain a disambiguous parse by just ending the address block after
            // RTA_IFA. In terms of parsing ambiguity, there's no need for a placeholder if there is
            // no later address, you can just omit it entirely, and the theory is that the user is
            // expected to just know how to interpret this (oh, I'm out of addresses to parse, that
            // means that all the following ones are null). It's unclear whether the kernel will do
            // this if there are multiple trailing missing addresses.
            //
            // This is a working theory backreasoned from this one example we have, which is a null
            // trailing IFA_BRD on IPv6 RTM_IFADDR messages. This address is always null because
            // IPv6 doesn't have broadcast addresses, but it seems that conventionally, RTM_IFADDR
            // always sets the bit, and it's typically the last bit set. So we see this situation a
            // lot, hence quieting the trace for that one case. We still want it to see if we can
            // catch any other scenarios where the kernel does this to validate the theory.
            if !(is_ipv6 && ends_with_broadcast) {
                tracing::warn!(
                    addrs = ?slf.addrs(),
                    parsed = ?parsed_addrs,
                    addr_payload = ?format_args!("{addrs:x?}"),
                    "parsed wrong addrs count",
                );
            }
        }

        Ok((
            rest,
            Message {
                header: slf,
                addrs: parsed_addrs,
            },
        ))
    }

    /// Report the destination address from `RTA_DEST`, if present.
    pub fn dest_addr(&self) -> Option<IpNet> {
        self.masked_addr(Addrs::DESTINATION)
    }

    /// Report the netmask len from the `RTA_NETMASK` address, if present.
    ///
    /// The `family` parameter informs how to interpret the netmask bytes, as they can't be
    /// parsed unambiguously.
    ///
    /// If the netmask was not valid as a strict prefix, `None` is returned.
    pub fn netmask_len(&self, family: Family) -> Option<u8> {
        match self.get_addr(Addrs::NETMASK)? {
            Address::Ipv4(ip) if family == Family::Ipv4 => net_table::netmask_to_prefix(&ip.into()),
            Address::Ipv6 { addr: ip, .. } if family == Family::Ipv6 => {
                net_table::netmask_to_prefix(&ip.into())
            }
            Address::PrefixLen(PrefixLen { v4, v6 }) => match family {
                Family::Ipv4 => v4,
                Family::Ipv6 => v6,
            },
            Address::Unspecified => Some(0),
            _ => None,
        }
    }

    /// Report the gateway address, if present.
    pub fn gateway(&self) -> Option<IpAddr> {
        self.get_addr(Addrs::GATEWAY)?.try_into().ok()
    }

    /// Report the `RTA_IFP` link address, which typically contains the interface name.
    pub fn interface_name(&self) -> Option<LinkAddr> {
        let addr = self.get_addr(Addrs::INTERFACE_NAME)?;
        let Address::Link(la) = addr else {
            return None;
        };

        Some(la)
    }

    /// Report the `RTA_IFA` interface address.
    pub fn interface_addr(&self) -> Option<IpNet> {
        self.masked_addr(Addrs::INTERFACE_ADDR)
    }

    /// Report whether this has `RTA_IFP` and the contained name is ignored by
    /// [`bsd::ignore_interface_name`].
    pub fn ignored_interface_name(&self) -> bool {
        let Some(ifp) = self.interface_name() else {
            return false;
        };

        bsd::ignore_interface_name(&ifp.name)
    }

    /// Get an address corresponding to the query. Only one address bit should be set.
    ///
    /// If the indicated address is not present in the underlying `addresses` vec, this is not taken
    /// to have been the result of a parsing error, but instead implies that the kernel meant to
    /// communicate an `AF_UNSPEC` address. This is due to undocumented truncation behavior
    /// previously witnessed in XNU, where trailing addresses that the kernel would have populated
    /// as `AF_UNSPEC` placeholders are dropped completely.
    pub fn get_addr(&self, query: Addrs) -> Option<Address> {
        debug_assert!(
            query.bits().count_ones() <= 1,
            "Message::get_addr with more than one address bit"
        );

        let pos = self.header.addrs().iter().position(|x| x == query)?;

        Some(
            self.addrs
                .get(pos)
                .cloned()
                .flatten()
                .unwrap_or(Address::Unspecified),
        )
    }

    /// Attempt to convert this message into an [`Event`].
    pub fn as_event(&self) -> Option<Event> {
        match &self.header {
            MessageHeader::Route(..) | MessageHeader::Route2(..) => {
                self.as_route().map(|(iid, rt)| Event::RouteUpsert(iid, rt))
            }
            MessageHeader::Interface(..) | MessageHeader::Interface2(..) => {
                self.as_interface().map(Event::InterfaceUpsert)
            }
            MessageHeader::InterfaceAddr(..) => self
                .as_interface_addr()
                .map(|(iid, addr)| Event::AddrUpsert(iid, addr)),
            MessageHeader::MulticastAddr(..) | MessageHeader::MulticastAddr2(..) => {
                tracing::trace!("drop multicast addr");
                None
            }
        }
    }

    /// Attempt to interpret this message as a [`net_table::InterfaceAddr`] and convert it to
    /// an [`IpNet`].
    pub fn as_interface_addr(&self) -> Option<(InterfaceId, IpNet)> {
        let MessageHeader::InterfaceAddr(net_table::InterfaceAddr { index, .. }) = self.header
        else {
            tracing::warn!("wrong message type (expected interface addr)");
            return None;
        };

        Some((bsd::iid(index.get()), self.interface_addr()?))
    }

    /// Attempt to convert this message to a [`Route`].
    ///
    /// Returns `None` if this isn't a route message or if it's dead or ignored.
    pub fn as_route(&self) -> Option<(InterfaceId, Route)> {
        if self.is_dead() || self.ignored_interface_name() {
            tracing::trace!("route is dead or interface is ignored");
            return None;
        }

        let (MessageHeader::Route(net_table::Route { index, .. })
        | MessageHeader::Route2(net_table::Route2 { index, .. })) = &self.header
        else {
            tracing::warn!("wrong message type (expected route)");
            return None;
        };

        Some((
            InterfaceId::new(MonType::PF_ROUTE, index.get() as _),
            Route {
                dst: self.dest_addr()?,
                gateway: self.gateway().into_iter().collect(),
                metric: 0, // macOS doesn't set a per-route metric, it comes from the interface
            },
        ))
    }

    /// Attempt to convert this to an [`Interface`].
    ///
    /// Returns `None` if this isn't an interface message or the interface is dead or ignored.
    pub fn as_interface(&self) -> Option<Interface> {
        if self.is_dead() || self.ignored_interface_name() {
            tracing::trace!("interface is dead or ignored");
            return None;
        }

        let (MessageHeader::Interface(net_table::Interface {
            index,
            data: net_table::InterfaceData { mtu, .. },
            ..
        })
        | MessageHeader::Interface2(net_table::Interface2 {
            index,
            data: net_table::InterfaceData64 { mtu, .. },
            ..
        })) = &self.header
        else {
            tracing::warn!("wrong message type (expected interface)");
            return None;
        };

        let la = self.interface_name()?;
        let mtu = (mtu.get() != 0).then_some(mtu.get() as _);

        Some(Interface {
            id: bsd::iid(index.get()),
            mtu,
            hardware_addr: if !la.addr.is_empty() {
                Some(la.addr.iter().copied().collect())
            } else {
                None
            },
            name: la.name.clone(),
            up: self.header.flags().contains(Flags::UP),
        })
    }

    /// Report whether the flags on this message indicate that the route or interface it represents
    /// is dead or inoperative.
    ///
    /// Asserts `RTF_UP` and not `RTF_BLACKHOLE | RTF_REJECT | RTF_DEAD`.
    pub fn is_dead(&self) -> bool {
        !self.header.flags().contains(Flags::UP)
            || self
                .header
                .flags()
                .intersects(Flags::BLACKHOLE | Flags::REJECT | Flags::DEAD)
    }

    /// Get the address specified by `addr_ty`, then mask it according to the netmask address.
    fn masked_addr(&self, addr_ty: Addrs) -> Option<IpNet> {
        let dest_ip: IpAddr = self.get_addr(addr_ty)?.try_into().ok()?;
        let mask = self.netmask_len(dest_ip.into())?;

        IpNet::new(dest_ip, mask).ok()
    }
}
