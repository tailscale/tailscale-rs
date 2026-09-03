#![allow(missing_docs)] // TODO

//! BSD network monitor implementation.
//!
//! There are two means of accessing routing and interface info: the `PF_ROUTE` socket, which
//! broadcasts routing and interface changes, and the `CTL_NET/PF_ROUTE` `sysctl` which can dump the
//! current route or interface table.
//!
//! We monitor the socket interface for changes using [`RouteSocket`], but it unfortunately doesn't
//! provide sufficient information in-band to fully determine system state: on macOS (at least), new
//! route notifications are issued before the corresponding interface is determined, so the
//! interface index is set to zero. You can ask the kernel to resolve the route completely, but this
//! requires superuser permissions, which we don't have in the general case. macOS also doesn't have
//! `RTA_IFANNOUNCE` as other BSDs do, so interface changes never appear on the socket other than
//! indirectly (via subsequent address and route assignments).
//!
//! For these reasons, we mirror the Go implementation and use the `PF_ROUTE` socket as a stream of
//! notifications of possible events of interest, which are themselves discarded, but trigger
//! updates via `sysctl` dumps (which are fully resolved, atomic snapshots of system state). We
//! still can't grab simultaneous snapshots of both the interface and route states, but we'll just
//! have to live with that minor potential for a race.

use core::net::IpAddr;
use std::{
    collections::{HashMap, HashSet},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use futures_util::{StreamExt, TryStreamExt};
use ipnet::IpNet;
use nom::{Parser, multi::many0};

pub mod net_table;
mod route_socket;

pub use route_socket::{MsgStream, RouteSocket};
use ts_future_util::DebounceExt;

use crate::{
    BoxStream, Event, FamilyOrBoth, Interface, InterfaceId, MonType, Netmon, Route, RouteUnique,
    bsd::net_table::{
        Address, Addrs, DumpType, Flags, LinkAddr, MessageHeader, MessageType, PrefixLen,
    },
};

/// Canonical platform [`Netmon`] for BSD based on `PF_ROUTE` sockets.
pub struct PfRouteMon;

enum UpdateKind {
    Interface,
    Route,
}

#[derive(Default, Debug)]
struct UpdateState {
    interface: AtomicBool,
    route: AtomicBool,
}

impl UpdateState {
    pub fn clear(&self) -> (bool, bool) {
        (
            self.interface.swap(false, Ordering::AcqRel),
            self.route.swap(false, Ordering::AcqRel),
        )
    }
}

#[derive(Default)]
struct State {
    routes: HashMap<(InterfaceId, RouteUnique), Route>,
    interfaces: HashMap<InterfaceId, (Interface, HashSet<IpNet>)>,
}

impl Netmon for PfRouteMon {
    fn ty(&self) -> MonType {
        MonType::PF_ROUTE
    }

    fn strong_delete_consistency(&self) -> bool {
        false
    }

    fn event_stream(&self) -> std::io::Result<BoxStream<std::io::Result<Event>>> {
        let sock = Arc::new(RouteSocket::new()?);
        let stream = MsgStream::new(sock);

        let update_state = Arc::new(UpdateState::default());

        let updates = stream
            .try_filter_map(process_msg)
            .inspect_ok({
                let update_state = update_state.clone();

                move |update| match update {
                    UpdateKind::Interface => update_state.interface.store(true, Ordering::Release),
                    UpdateKind::Route => update_state.route.store(true, Ordering::Release),
                }
            })
            .debounce(Duration::from_millis(50))
            .map_ok(move |_| update_state.clear());

        let stream = futures_util::stream::once(async move { Ok((true, true)) })
            .chain(updates)
            .and_then(|(iface, rt)| {
                let mut rt_dump = None;
                let mut if_dump = None;

                tracing::trace!(iface, rt, "update triggered");

                async move {
                    if rt {
                        rt_dump = Some(net_table::dump(FamilyOrBoth::Both, DumpType::Route2, 0)?);
                    }
                    if iface {
                        if_dump = Some(net_table::dump(
                            FamilyOrBoth::Both,
                            DumpType::Interface2,
                            0,
                        )?);
                    }

                    Ok((rt_dump, if_dump)) as std::io::Result<(Option<Vec<u8>>, Option<Vec<u8>>)>
                }
            })
            .scan(State::default(), |state, x| {
                let events = self::update_state(state, x);

                async move { Some(futures_util::stream::iter(events)) }
            })
            .flatten();

        Ok(Box::pin(stream))
    }
}

type OptDump = Option<Vec<u8>>;

fn update_state(
    state: &mut State,
    x: std::io::Result<(OptDump, OptDump)>,
) -> Vec<std::io::Result<Event>> {
    let mut events = vec![];

    let (rt_dump, if_dump) = match x {
        Ok(x) => x,
        Err(e) => return vec![Err(e)],
    };

    if let Some(rt_dump) = rt_dump {
        update_rt(state, &rt_dump, &mut events);
    }

    if let Some(if_dump) = if_dump {
        update_iface(state, &if_dump, &mut events);
    }

    events
}

/// Reconcile the route state with a new route dump, adding any deltas to the event vec.
fn update_rt(state: &mut State, mut input: &[u8], events: &mut Vec<std::io::Result<Event>>) {
    let mut routes_maybe_deleted = state.routes.keys().cloned().collect::<HashSet<_>>();

    while let Ok((rest, msg)) = MsgRef::parse.parse_complete(input) {
        input = rest;

        tracing::trace!(?msg);

        let Some(evt) = msg.as_event() else {
            continue;
        };

        tracing::trace!(?evt);

        match evt {
            Event::RouteUpsert(iid, rt) => {
                let key = (iid.clone(), rt.unique());

                routes_maybe_deleted.remove(&key);

                if let Some(cur_rt) = state.routes.get(&key)
                    && cur_rt == &rt
                {
                    if cur_rt == &rt {
                        continue;
                    }

                    tracing::debug!(old_rt = ?cur_rt, new_rt = ?rt, "update rt");
                }

                events.push(Ok(Event::RouteUpsert(iid, rt.clone())));
                state.routes.insert(key.clone(), rt);
            }

            _ => unreachable!(),
        }
    }

    for (iid, rtu) in routes_maybe_deleted {
        state.routes.remove(&(iid.clone(), rtu.clone()));

        events.push(Ok(Event::RouteRemoved(
            iid,
            Route {
                dst: rtu.0,
                gateway: rtu.1,
                metric: 0,
            },
        )));
    }
}

/// Reconcile the interface state with a new interface dump, adding any deltas to the event vec.
fn update_iface(state: &mut State, mut input: &[u8], events: &mut Vec<std::io::Result<Event>>) {
    let mut new_interface_state =
        HashMap::<InterfaceId, (Option<Interface>, HashSet<IpNet>)>::default();

    while let Ok((rest, msg)) = MsgRef::parse.parse_complete(input) {
        input = rest;

        tracing::trace!(?msg);

        let Some(evt) = msg.as_event() else {
            tracing::trace!("invalid event");
            continue;
        };

        tracing::trace!(?evt);

        match evt {
            Event::InterfaceUpsert(iface) => {
                let (iface_entry, _addrs) = new_interface_state
                    .entry(iface.id.clone())
                    .or_insert_with(|| (None, Default::default()));

                *iface_entry = Some(iface);
            }

            Event::AddrUpsert(iid, inet) => {
                let (_iface, addrs) = new_interface_state
                    .entry(iid)
                    .or_insert_with(|| (None, Default::default()));

                addrs.insert(inet);
            }

            _ => unreachable!(),
        }
    }

    new_interface_state.retain(|_iid, (iface, _addrs)| iface.is_some());

    let old_iids = state
        .interfaces
        .keys()
        .cloned()
        .collect::<HashSet<InterfaceId>>();
    let new_iids = new_interface_state
        .keys()
        .cloned()
        .collect::<HashSet<InterfaceId>>();

    for deleted in old_iids.difference(&new_iids) {
        events.push(Ok(Event::InterfaceRemoved(deleted.clone())));
        state.interfaces.remove(deleted);
    }

    for added in new_iids {
        let (iface, addrs) = new_interface_state.remove(&added).unwrap();
        let iface = iface.unwrap();

        match state.interfaces.get_mut(&added) {
            Some((old_iface, old_addrs)) => {
                // Reconcile addrs
                {
                    for &deleted in old_addrs.difference(&addrs) {
                        events.push(Ok(Event::AddrRemoved(iface.id.clone(), deleted)));
                    }

                    for &added in addrs.difference(old_addrs) {
                        events.push(Ok(Event::AddrUpsert(iface.id.clone(), added)));
                    }

                    *old_addrs = addrs;
                }

                if old_iface != &iface {
                    events.push(Ok(Event::InterfaceUpsert(iface.clone())));
                    *old_iface = iface;
                }
            }
            // New addr
            None => {
                for addr in addrs {
                    events.push(Ok(Event::AddrUpsert(iface.id.clone(), addr)));
                }

                events.push(Ok(Event::InterfaceUpsert(iface.clone())));
            }
        }
    }
}

#[derive(Debug, Clone)]
struct MsgRef<'a> {
    header: MessageHeader<'a>,
    addrs: Vec<Option<Address>>,
}

impl<'a> MsgRef<'a> {
    pub fn parse(buf: &'a [u8]) -> nom::IResult<&'a [u8], Self> {
        let (rest, payload) = net_table::msg_chunk().parse_complete(buf)?;
        let (addrs, (_ty, slf)) = MessageHeader::parse.parse_complete(payload)?;

        let (_rest, parsed_addrs) =
            many0(nom::combinator::complete(net_table::partial_sockaddr::<
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

            // Don't warn if this is a known case where XNU will omit the address entirely
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
            MsgRef {
                header: slf,
                addrs: parsed_addrs,
            },
        ))
    }

    pub fn dest_addr(&self) -> Option<IpNet> {
        self.masked_addr(Addrs::DESTINATION)
    }

    pub fn prefix_len(&self, ipv4: bool) -> Option<u8> {
        match self.get_addr(Addrs::NETMASK)? {
            Address::Ipv4(ip) => Some(u32::from(ip).count_ones() as _),
            Address::Ipv6 { addr: ip, .. } => Some(u128::from(ip).count_ones() as _),
            Address::PrefixLen(PrefixLen { v4, v6 }) => {
                if ipv4 {
                    v4
                } else {
                    v6
                }
            }
            Address::Unspecified => Some(0),
            _ => None,
        }
    }

    pub fn gateway(&self) -> Option<IpAddr> {
        self.get_addr(Addrs::GATEWAY)?.try_into().ok()
    }

    pub fn interface_name(&self) -> Option<LinkAddr> {
        let addr = self.get_addr(Addrs::INTERFACE_NAME)?;
        let Address::Link(la) = addr else {
            return None;
        };

        Some(la)
    }

    pub fn ignored_interface_name(&self) -> bool {
        let Some(ifp) = self.interface_name() else {
            return false;
        };

        ignore_interface_name(&ifp.name)
    }

    pub fn get_addr(&self, query: Addrs) -> Option<Address> {
        let pos = self.header.addrs().iter().position(|x| x == query)?;

        Some(
            self.addrs
                .get(pos)
                .cloned()
                .flatten()
                .unwrap_or(Address::Unspecified),
        )
    }

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

    pub fn as_interface_addr(&self) -> Option<(InterfaceId, IpNet)> {
        let MessageHeader::InterfaceAddr(net_table::InterfaceAddr { index, .. }) = self.header
        else {
            tracing::warn!("wrong message type (expected interface addr)");
            return None;
        };

        Some((iid(index.get()), self.masked_addr(Addrs::INTERFACE_ADDR)?))
    }

    pub fn as_route(&self) -> Option<(InterfaceId, Route)> {
        if self.is_dead() || self.ignored_interface_name() {
            tracing::trace!("route is dead or interface is ignored");
            return None;
        }

        let (MessageHeader::Route(net_table::Route { index, metrics, .. })
        | MessageHeader::Route2(net_table::Route2 { index, metrics, .. })) = &self.header
        else {
            tracing::warn!("wrong message type (expected route)");
            return None;
        };

        Some((
            InterfaceId::new(MonType::PF_ROUTE, index.get() as _),
            Route {
                dst: self.dest_addr()?,
                gateway: self.gateway().into_iter().collect(),
                metric: metrics.hopcount.get() as _, // TODO: correct?
            },
        ))
    }

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
            id: iid(index.get()),
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

    pub fn is_dead(&self) -> bool {
        !self.header.flags().contains(Flags::UP)
            || self
                .header
                .flags()
                .intersects(Flags::BLACKHOLE | Flags::REJECT | Flags::DEAD)
    }

    fn masked_addr(&self, addr_ty: Addrs) -> Option<IpNet> {
        let dest_ip: IpAddr = self.get_addr(addr_ty)?.try_into().ok()?;
        let mask = self.prefix_len(dest_ip.is_ipv4())?;

        IpNet::new(dest_ip, mask).ok()
    }
}

fn iid(index: impl Into<u64>) -> InterfaceId {
    InterfaceId::new(MonType::PF_ROUTE, index.into())
}

async fn process_msg(msg: bytes::BytesMut) -> std::io::Result<Option<UpdateKind>> {
    let (_rest, msg) = MsgRef::parse(msg.as_ref())
        .map_err(|e| e.to_string())
        .map_err(std::io::Error::other)?;

    match msg.header.header().ty {
        MessageType::Add
        | MessageType::Change
        | MessageType::Delete
        | MessageType::NewAddr
        | MessageType::DelAddr
        | MessageType::Get
        | MessageType::Get2 => {}
        // Reject don't-care message types (RTM_MISS, RTM_LOCK, RTM_RESOLVE, RTM_REDIRECT), etc.
        ty => {
            tracing::trace!(?ty, "irrelevant message type");
            return Ok(None);
        }
    }

    if msg.ignored_interface_name() {
        tracing::trace!(
            name = %msg.interface_name().unwrap().name,
            "ignored interface"
        );

        return Ok(None);
    }

    let dst = msg.dest_addr();
    if matches!(
        msg.header,
        MessageHeader::Route(..) | MessageHeader::Route2(..)
    ) && let Some(dst) = dst
        && is_unicast_link_local(dst.addr())
    {
        tracing::trace!("ignore unicast link local");
        return Ok(None);
    }

    // Explicitly reject multicast address updates. Following the Go, IfInfo
    // messages are also discarded (only care about routes and unicast addr changes).
    match msg.header {
        MessageHeader::MulticastAddr(..)
        | MessageHeader::MulticastAddr2(..)
        | MessageHeader::Interface(..)
        | MessageHeader::Interface2(..) => {
            tracing::trace!("ignore socket msg type");
            Ok(None)
        }
        MessageHeader::InterfaceAddr(_) => Ok(Some(UpdateKind::Interface)),
        MessageHeader::Route(_) | MessageHeader::Route2(_) => Ok(Some(UpdateKind::Route)),
    }
}

/// Report whether we should ignore route and interface changes related to the given interface name.
///
/// These interface names typically specify interfaces which do not provide meaningful underlay
/// routing opportunities.
///
/// See <https://github.com/tailscale/tailscale/tree/2767100/net/netmon/netmon_darwin.go#L134>
fn ignore_interface_name(name: &str) -> bool {
    regex::regex!(r#"^(:?llw|awdl|ipsec|gif|XHC|anpi|lo|utun)\d*$"#).is_match(name)
}

fn is_unicast_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_unicast_link_local(),
    }
}
