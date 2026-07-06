use std::{
    collections::HashMap,
    io,
    sync::{Arc, atomic::AtomicUsize},
    time::Duration,
};

use futures::StreamExt;
use kameo::{
    Actor,
    actor::ActorRef,
    message::{Context, Message, StreamMessage},
};
use smol_str::ToSmolStr;
use ts_netmon::{Event, Family, InterfaceId, Netmon};

use crate::env::Env;

pub struct NetmonActor {
    mon: Arc<dyn Netmon>,
    state: State,
    env: Env,
    _id: Id,
}

/// Map from the unique part of a route to its metric.
pub type Routes = HashMap<ts_netmon::RouteUnique, usize>;

/// The unique id of a [`NetmonActor`] instance.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id {
    pub ty: ts_netmon::MonType,
    pub id: usize,
}

impl Id {
    fn new(ty: ts_netmon::MonType) -> Self {
        static ID: AtomicUsize = AtomicUsize::new(0);

        Self {
            ty,
            id: ID.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
        }
    }
}

/// Netmon state at a point in time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct State {
    /// The id of the [`NetmonActor`] that generated this [`State`].
    pub id: Id,

    /// Interfaces detected on a [`Netmon`].
    pub interfaces: HashMap<InterfaceId, ts_netmon::Interface>,

    /// Routes per interface.
    pub routes: HashMap<InterfaceId, Routes>,

    /// Addresses per interface.
    ///
    /// To recover the full address with the prefix len, use key's `addr()` as the address
    /// and the value as the prefix len.
    ///
    /// The representation is split this way to support [`Netmon::interface_unique_addrs`].
    pub addrs: HashMap<InterfaceId, HashMap<ipnet::IpNet, u8>>,

    /// The interface that has the IPv4 default route, if any.
    pub default_route_interface_v4: Option<InterfaceId>,

    /// The interface that has the IPv6 default route, if any.
    pub default_route_interface_v6: Option<InterfaceId>,
}

impl State {
    /// Iterate the addresses on all interfaces in the `up` state.
    pub fn up_addrs(&self) -> impl Iterator<Item = (InterfaceId, ipnet::IpNet)> {
        self.addrs
            .iter()
            .filter_map(|(id, addrs)| {
                let interface = self.interfaces.get(id)?;
                if !interface.up {
                    return None;
                }

                Some(
                    addrs
                        .iter()
                        .map(|(ipn, &pfx)| (id.clone(), ipnet::IpNet::new_assert(ipn.addr(), pfx))),
                )
            })
            .flatten()
    }

    /// Iterate the routes on all interfaces in the `up` state.
    pub fn up_routes(&self) -> impl Iterator<Item = (InterfaceId, ts_netmon::Route)> {
        self.routes
            .iter()
            .filter_map(|(id, routes)| {
                let interface = self.interfaces.get(id)?;
                if !interface.up {
                    return None;
                }

                Some(routes.iter().map(|((dst, gws), &metric)| {
                    (
                        id.clone(),
                        ts_netmon::Route {
                            gateway: gws.clone(),
                            metric,
                            dst: *dst,
                        },
                    )
                }))
            })
            .flatten()
    }
}

impl Actor for NetmonActor {
    type Args = (Env, Arc<dyn Netmon>);
    type Error = io::Error;

    async fn on_start((env, mon): Self::Args, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        let id = Id::new(mon.ty());

        slf.attach_stream(
            {
                use tokio_stream::StreamExt;

                mon.with_default_route_events()?
                    .chunks_timeout(256, Duration::from_millis(100))
                    .boxed()
            },
            (),
            (),
        );

        env.register(Some(mon.ty().as_ref().to_smolstr()), &slf)
            .await
            .unwrap();

        Ok(Self {
            env,
            mon,
            state: State {
                id: id.clone(),
                addrs: Default::default(),
                routes: Default::default(),
                interfaces: Default::default(),
                default_route_interface_v4: None,
                default_route_interface_v6: None,
            },
            _id: id,
        })
    }
}

impl Message<StreamMessage<Vec<io::Result<Event>>, (), ()>> for NetmonActor {
    type Reply = ();

    async fn handle(
        &mut self,
        msg: StreamMessage<Vec<io::Result<Event>>, (), ()>,
        _ctx: &mut Context<Self, Self::Reply>,
    ) {
        let events = match msg {
            StreamMessage::Started(_) | StreamMessage::Finished(_) => {
                return;
            }
            StreamMessage::Next(val) => val,
        };

        if events.is_empty() {
            tracing::warn!("empty netmon event");
            return;
        }

        let mut modified = false;

        for event in &events {
            let event_modified = self.handle_event(event);
            if event_modified {
                tracing::trace!(mutating_netmon_event = ?event);
            }

            modified = modified || event_modified;
        }

        if !modified {
            return;
        }

        tracing::debug!(n_coalesced_events = events.len(), "netmon mutation");

        self.env
            .publish(Arc::new(self.state.clone()))
            .await
            .unwrap();
    }
}

impl NetmonActor {
    fn handle_event(&mut self, event: &io::Result<Event>) -> bool {
        let event = match event {
            Ok(event) => event,
            Err(e) => {
                tracing::error!(error = %e, "netmon error");
                return false;
            }
        };

        let mut modified = false;

        match &event {
            Event::RouteUpsert(interface, route) => {
                let old = self
                    .state
                    .routes
                    .entry(interface.clone())
                    .or_default()
                    .insert(route.unique(), route.metric);

                modified = old.is_none_or(|old| old != route.metric);
            }
            Event::RouteRemoved(interface, route) => {
                let mut empty = false;

                self.state.routes.entry(interface.clone()).and_modify(|r| {
                    modified = r.remove(&route.unique()).is_some();
                    empty = r.is_empty();
                });

                if empty {
                    self.state.routes.remove(interface);
                }
            }
            Event::AddrUpsert(interface, addr) => {
                let (addr, pfx_len) = self.split_interface_addr(addr);

                let old = self
                    .state
                    .addrs
                    .entry(interface.clone())
                    .or_default()
                    .insert(addr, pfx_len);

                modified = old.is_none_or(|old| old != pfx_len);
            }
            Event::AddrRemoved(interface, addr) => {
                let mut empty = false;
                let (addr, _pfx_len) = self.split_interface_addr(addr);

                self.state.addrs.entry(interface.clone()).and_modify(|e| {
                    modified = e.remove(&addr).is_some();
                    empty = e.is_empty();
                });

                if empty {
                    self.state.addrs.remove(interface);
                }
            }
            Event::InterfaceUpsert(interface) => {
                let old = self
                    .state
                    .interfaces
                    .insert(interface.id.clone(), interface.clone());

                modified = old.is_none_or(|old| &old != interface);
            }
            Event::InterfaceRemoved(interface) => {
                self.state.interfaces.retain(|x, _| {
                    let ret = x != interface;
                    if !ret {
                        modified = true;
                    }

                    ret
                });

                // NOTE(npry): the below modification of routes and addrs on link deletion is due to
                // divergence in platform behavior:
                //
                // - rtnetlink has a strongly-consistent event ordering model (as it's a single
                //   reliable socket) that orders route and address deletion events before link
                //   deletions, but it doesn't seem to _guarantee_ individual deletions for all
                //   routes and addresses related to a link when it's deleted; the link deletion
                //   itself seems to be intended to clean those up.
                // - Win32 notify APIs are, on the other hand, free to race between route, address,
                //   and link modifications, but are ordered within each logical resource stream and
                //   appear to exhaustively issue deletion events for all routes and addresses _at
                //   some point_ when a link is deleted. The link deletion event, however, may issue
                //   in an arbitrary order wrt. the other events. The implication of this is that we
                //   technically shouldn't proactively delete the other resources when the link is
                //   removed, since we could be deleting routes and addresses related to a future
                //   generation of the link in a race condition.
                //
                // This logic is meant to rectify that and make our state reflect what the platform
                // has told us it should be regardless of the underlying consistency model.
                if self.mon.strong_delete_consistency() {
                    modified = modified || self.state.routes.remove(interface).is_some();
                    modified = modified || self.state.addrs.remove(interface).is_some();
                }
            }
            Event::DefaultRouteInterface(iface, family) => {
                let pre_v4 = self.state.default_route_interface_v4.clone();
                let pre_v6 = self.state.default_route_interface_v6.clone();

                match family {
                    Family::Ipv4 => self.state.default_route_interface_v4 = iface.clone(),
                    Family::Ipv6 => self.state.default_route_interface_v6 = iface.clone(),
                }

                if pre_v4 != self.state.default_route_interface_v4
                    || pre_v6 != self.state.default_route_interface_v6
                {
                    modified = true;
                }
            }
        }

        if !modified {
            tracing::trace!(?event, "netmon event with no delta");
        }

        modified
    }

    /// Split the interface addr according to [`Netmon::interface_unique_addrs`]:
    ///
    /// - If interface addresses are unique, returns (addr/0, prefix_len)
    /// - If interface addresses are not unique, returns (addr/prefix_len, prefix_len)
    fn split_interface_addr(&self, addr: &ipnet::IpNet) -> (ipnet::IpNet, u8) {
        if self.mon.interface_unique_addrs() {
            (ipnet::IpNet::new_assert(addr.addr(), 0), addr.prefix_len())
        } else {
            (*addr, addr.prefix_len())
        }
    }
}
