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
    sync::Arc,
    time::Duration,
};

use futures_util::{StreamExt, TryStreamExt};
use ipnet::IpNet;
use nom::Parser;
use ts_util::futures::DebounceExt;

mod message;
pub mod net_table;
mod route_socket;

pub use message::Message;
use net_table::{MessageHeader, MessageType};
pub use route_socket::{MsgStream, RouteSocket};

use crate::{
    BoxStream, Event, FamilyOrBoth, Interface, InterfaceId, MonType, Netmon, Route, RouteUnique,
    bsd::net_table::DumpType,
};

/// Canonical platform [`Netmon`] for BSD based on `PF_ROUTE` sockets.
pub struct PfRouteMon;

/// Whether this message indicates an update to the network interface state or the route
/// state.
enum UpdateKind {
    Interface,
    Route,
}

/// Aggregated network state we've seen so far.
///
/// Used to compute deltas to hand through the event stream interface.
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

        let socket_updates = stream.try_filter_map(process_raw_socket_msg).fold_debounce(
            Duration::from_millis(50),
            |acc: &mut Option<std::io::Result<(bool, bool)>>, x| {
                let Ok((iface, rt)) = acc.get_or_insert(Ok((false, false))) else {
                    return;
                };

                match x {
                    Ok(UpdateKind::Interface) => *iface = true,
                    Ok(UpdateKind::Route) => *rt = true,
                    Err(e) => *acc = Some(Err(e)),
                }
            },
        );

        // Force an update to both interfaces and routes to start, then chain updates from the
        // PF_ROUTE socket.
        let stream = futures_util::stream::once(async move { Ok((true, true)) })
            .chain(socket_updates)
            .and_then(|(iface, rt)| {
                tracing::trace!(iface, rt, "update triggered");

                async move {
                    let rt_dump = rt
                        .then(|| net_table::dump(FamilyOrBoth::Both, DumpType::Route2, 0))
                        .transpose()?;

                    let if_dump = iface
                        .then(|| net_table::dump(FamilyOrBoth::Both, DumpType::Interface2, 0))
                        .transpose()?;

                    Ok((rt_dump, if_dump)) as std::io::Result<(OptDump, OptDump)>
                }
            })
            .scan(State::default(), |state, x| {
                let events = update_state(state, x);

                async move { Some(futures_util::stream::iter(events)) }
            })
            .flatten();

        Ok(Box::pin(stream))
    }
}

/// Decode a message from the socket, rejecting irrelevant updates and reporting what
/// kind of update this represents ([`UpdateKind::Route`] or [`UpdateKind::Interface`]).
/// The relevant kind of update will eventually trigger a [`net_table::dump`] to update the
/// [`State`].
async fn process_raw_socket_msg(msg: bytes::BytesMut) -> std::io::Result<Option<UpdateKind>> {
    let (_rest, msg) = Message::parse(msg.as_ref())
        .map_err(|e| e.to_string())
        .map_err(std::io::Error::other)?;

    // Reject don't-care message types (RTM_MISS, RTM_LOCK, RTM_RESOLVE, RTM_REDIRECT), etc.
    if !matches!(
        msg.header.header().ty,
        MessageType::Add
            | MessageType::Change
            | MessageType::Delete
            | MessageType::NewAddr
            | MessageType::DelAddr
            | MessageType::Get
            | MessageType::Get2
    ) {
        tracing::trace!(ty = ?msg.header.header().ty, "irrelevant message type");
        return Ok(None);
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

type OptDump = Option<Vec<u8>>;

/// Process [`net_table::dump`]s, updating the current [`State`] and producing [`Event`]s
/// based on the delta.
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

    while let Ok((rest, msg)) = Message::parse.parse_complete(input) {
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

                if let Some(cur_rt) = state.routes.get(&key) {
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

    while let Ok((rest, msg)) = Message::parse.parse_complete(input) {
        input = rest;

        tracing::trace!(?msg);

        let Some(evt) = msg.as_event() else {
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

fn iid(index: impl Into<u64>) -> InterfaceId {
    InterfaceId::new(MonType::PF_ROUTE, index.into())
}

/// Report whether we should ignore route and interface changes related to the given interface name.
///
/// These interface names typically specify interfaces which do not provide meaningful underlay
/// routing opportunities.
///
/// See <https://github.com/tailscale/tailscale/tree/2767100/net/netmon/netmon_darwin.go#L134>
pub fn ignore_interface_name(name: &str) -> bool {
    regex::regex!(r#"^(:?llw|awdl|ipsec|gif|XHC|anpi|lo|utun)\d*$"#).is_match(name)
}

fn is_unicast_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => ip.is_link_local(),
        IpAddr::V6(ip) => ip.is_unicast_link_local(),
    }
}
