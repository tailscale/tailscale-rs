//! Linux network monitor implementation.

use std::{io, net::IpAddr};

use futures_util::{Stream, StreamExt, TryStreamExt};
use rtnetlink::{
    Handle, MulticastGroup, RouteMessageBuilder,
    packet_core::NetlinkPayload,
    packet_route::{
        AddressFamily, RouteNetlinkMessage,
        address::{AddressAttribute, AddressMessage},
        link::{LinkAttribute, LinkFlags, LinkLayerType, LinkMessage},
        route::{RouteAddress, RouteAttribute, RouteMessage, RouteType},
    },
};
use tokio::task::JoinSet;

use crate::{BoxStream, Event, Interface, InterfaceId, MonType, Netmon, Route};

/// Linux-platform [`Netmon`] implementation based on rtnetlink.
pub struct RtNetlinkMon;

impl Netmon for RtNetlinkMon {
    fn ty(&self) -> MonType {
        MonType::RTNETLINK
    }

    fn event_stream(&self) -> io::Result<BoxStream<io::Result<Event>>> {
        Ok(stream()?.boxed())
    }
}

/// Multicast groups subscribed to on rtnetlink.
///
/// Reused in some of the examples but not part of the API, so hidden.
#[doc(hidden)]
pub const NETLINK_GROUPS: &[MulticastGroup] = &[
    MulticastGroup::Link,
    MulticastGroup::Ipv4Route,
    MulticastGroup::Ipv6Route,
    MulticastGroup::Ipv4Ifaddr,
    MulticastGroup::Ipv6Ifaddr,
];

fn interface_id(idx: u32) -> InterfaceId {
    InterfaceId::new(MonType::RTNETLINK, idx as _)
}

fn link_state(handle: Handle) -> impl Stream<Item = Result<Event, rtnetlink::Error>> {
    handle
        .link()
        .get()
        .execute()
        .try_filter_map(async |link| Ok(link_event(link)))
}

fn addr_state(handle: Handle) -> impl Stream<Item = Result<Event, rtnetlink::Error>> {
    handle
        .address()
        .get()
        .execute()
        .try_filter_map(async |addr| Ok(addr_added_event(addr)))
}

fn route_state(handle: Handle) -> impl Stream<Item = Result<Event, rtnetlink::Error>> {
    handle
        .route()
        .get(RouteMessageBuilder::<IpAddr>::new().build())
        .execute()
        .try_filter_map(async |route| Ok(route_added_event(route)))
}

fn init_state(handle: Handle) -> impl Stream<Item = io::Result<Event>> {
    use tokio_stream::StreamExt;

    link_state(handle.clone())
        .merge(addr_state(handle.clone()))
        .merge(route_state(handle))
        .map_err(io::Error::other)
}

fn stream() -> io::Result<impl Stream<Item = io::Result<Event>>> {
    let (conn, handle, msgs) = rtnetlink::new_multicast_connection(NETLINK_GROUPS)?;

    let mut joinset = JoinSet::new();
    joinset.spawn(conn);

    let update_stream = msgs
        .filter_map(async |(msg, _sa)| match msg.payload {
            NetlinkPayload::InnerMessage(msg) => Some(Ok(msg)),
            NetlinkPayload::Error(msg) => Some(Err(msg.to_io())),
            _ => None,
        })
        .try_filter_map(async |msg| {
            let ret = match msg {
                RouteNetlinkMessage::NewRoute(rt) => route_added_event(rt),
                RouteNetlinkMessage::DelRoute(rt) => route_removed_event(rt),
                RouteNetlinkMessage::NewAddress(addr) => addr_added_event(addr),
                RouteNetlinkMessage::DelAddress(addr) => addr_removed_event(addr),
                RouteNetlinkMessage::NewLink(link) => link_event(link),
                RouteNetlinkMessage::DelLink(link) => {
                    Some(Event::InterfaceRemoved(interface_id(link.header.index)))
                }

                msg => {
                    tracing::warn!(?msg, "unhandled netlink message");
                    None
                }
            };

            Ok(ret)
        })
        // hacky way to move the joinset running the netlink `conn` into the stream so it isn't
        // dropped until the stream is (which would kill the runner -> stall the stream).
        .scan(
            joinset,
            #[allow(closure_returning_async_block)]
            |_, x| async move { Some(x) },
        );

    Ok(init_state(handle).chain(update_stream))
}

fn link_event(link: LinkMessage) -> Option<Event> {
    let iface = load_interface(link)?;
    Some(Event::InterfaceUpsert(iface))
}

fn addr_added_event(addr: AddressMessage) -> Option<Event> {
    let ip = addr_msg(&addr)?;

    Some(Event::AddrUpsert(interface_id(addr.header.index), ip))
}

fn addr_removed_event(addr: AddressMessage) -> Option<Event> {
    let ip = addr_msg(&addr)?;
    Some(Event::AddrRemoved(interface_id(addr.header.index), ip))
}

fn route_added_event(route: RouteMessage) -> Option<Event> {
    let (interface, route) = route_msg(&route)?;
    Some(Event::RouteUpsert(interface, route))
}

fn route_removed_event(route: RouteMessage) -> Option<Event> {
    let (interface, route) = route_msg(&route)?;
    Some(Event::RouteRemoved(interface, route))
}

#[tracing::instrument(skip_all, fields(id = link.header.index))]
fn load_interface(link: LinkMessage) -> Option<Interface> {
    let mut name = None;
    let mut mtu = None;
    let mut hardware_addr = None;

    for attr in link.attributes {
        match attr {
            LinkAttribute::IfName(new_name) => {
                name = Some(new_name);
            }
            LinkAttribute::Address(addr) => {
                if link.header.link_layer_type != LinkLayerType::Ether {
                    continue;
                }

                match addr.len() {
                    // MAC
                    6 => {
                        hardware_addr = Some(smallvec::SmallVec::from(addr));
                    }
                    _ => {
                        tracing::warn!(?addr, link_type = ?link.header.link_layer_type, "unknown link address type");
                        continue;
                    }
                }
            }
            LinkAttribute::Mtu(new_mtu) => {
                mtu = Some(new_mtu as usize);
            }
            _ => {}
        }
    }

    Some(Interface {
        up: link.header.flags.contains(LinkFlags::Up),
        id: interface_id(link.header.index),
        name: name?,
        mtu,
        hardware_addr,
        metric_v4: 0,
        metric_v6: 0,
    })
}

fn addr_msg(msg: &AddressMessage) -> Option<ipnet::IpNet> {
    for attr in &msg.attributes {
        if let AddressAttribute::Address(ip) = attr {
            return Some(ipnet::IpNet::new(*ip, msg.header.prefix_len).unwrap());
        }
    }

    None
}

fn route_msg(rt: &RouteMessage) -> Option<(InterfaceId, Route)> {
    let mut gateway = smallvec::smallvec![];
    // Lack of a destination attr with pfx len 0 means the destination should be treated as
    // unspecified.
    let mut dst = match rt.header.address_family {
        AddressFamily::Inet if rt.header.destination_prefix_length == 0 => {
            Some(ipnet::Ipv4Net::default().into())
        }
        AddressFamily::Inet6 if rt.header.destination_prefix_length == 0 => {
            Some(ipnet::Ipv6Net::default().into())
        }
        _ => None,
    };
    let mut metric = 0;
    let mut interface = None;

    // Only allow unicast routes
    match rt.header.kind {
        RouteType::Unicast | RouteType::Local => {}

        // TODO(npry): handling for negative routes? multiple tables?
        RouteType::Unreachable
        | RouteType::Prohibit
        | RouteType::BlackHole
        | RouteType::Throw
        | RouteType::Unspec => {
            return None;
        }

        _ => {
            return None;
        }
    }

    for attr in &rt.attributes {
        match attr {
            RouteAttribute::Destination(addr) => {
                dst = routeaddr_pfx(addr, rt.header.destination_prefix_length);
            }
            RouteAttribute::Gateway(addr) => {
                if let Some(addr) = routeaddr_ip(addr) {
                    gateway.push(addr);
                }
            }
            &RouteAttribute::Oif(idx) => {
                interface = Some(interface_id(idx));
            }
            &RouteAttribute::Priority(prio) => {
                metric = prio as _;
            }

            // TODO(npry): complicated routing scenarios -- multipath, src interface, off-AF
            // gateway, etc.
            RouteAttribute::MultiPath(next_hops) => {
                tracing::warn!(?next_hops, "route has multiple next-hops");
            }
            RouteAttribute::Iif(idx) => {
                tracing::warn!(input_idx = idx, "route has input interface specified");
            }
            RouteAttribute::Via(via) => {
                tracing::warn!(
                    ?via,
                    "route has `via` attribute (gateway in different AF), skipping"
                );
                return None;
            }
            _ => {}
        }
    }

    let route = Route {
        dst: dst?,
        metric,
        gateway,
    };

    Some((interface?, route))
}

fn routeaddr_ip(addr: &RouteAddress) -> Option<IpAddr> {
    let ip = match addr {
        RouteAddress::Inet(ip) => (*ip).into(),
        RouteAddress::Inet6(ip) => (*ip).into(),
        _ => return None,
    };

    Some(ip)
}

fn routeaddr_pfx(addr: &RouteAddress, pfx_len: u8) -> Option<ipnet::IpNet> {
    let ip = routeaddr_ip(addr)?;
    ipnet::IpNet::new(ip, pfx_len).ok()
}
