use core::{net::IpAddr, pin::Pin};
use std::collections::{BTreeMap, BTreeSet, HashMap};

use futures_util::{Stream, StreamExt, stream};

#[cfg(target_os = "macos")]
pub use crate::bsd::PfRouteMon as PlatformMon;
#[cfg(target_os = "linux")]
pub use crate::linux::RtNetlinkMon as PlatformMon;
#[cfg(windows)]
pub use crate::windows::Winmon as PlatformMon;
use crate::{Event, Family, InterfaceId, Route, id::MonType};

/// A [`Pin`]-[`Box`]ed [`Send`] [`Stream`] with items of type `T`.
pub type BoxStream<T> = Pin<Box<dyn Stream<Item = T> + Send + 'static>>;

/// Get the platform [`Netmon`] implementation if there is one.
pub const fn platform_mon() -> Option<impl Netmon + 'static> {
    cfg_if::cfg_if! {
        if #[cfg(any(windows, target_os = "linux", target_os = "macos"))] {
            Some(&PlatformMon)
        } else {
            struct NoopMon;

            impl Netmon for NoopMon {
                fn ty(&self) -> MonType {
                    unimplemented!()
                }

                fn event_stream(&self) -> std::io::Result<BoxStream<std::io::Result<Event>>> {
                    unimplemented!()
                }
            }

            Option::<NoopMon>::None
        }
    }
}

/// A network monitor that tracks [`Event`]s related to platform
/// [`Interface`][crate::Interface]s.
pub trait Netmon: Send + Sync {
    /// Get the [`MonType`] of this [`Netmon`].
    ///
    /// The return value of this function should never change.
    fn ty(&self) -> MonType;

    /// Start monitoring for network [`Event`]s.
    ///
    /// Generally, implementors don't need to generate [`Event::DefaultRouteInterface`],
    /// since this can be provided by [`dyn Netmon::with_default_route_events`], which
    /// generic callers should prefer.
    ///
    /// [`dyn Netmon::with_default_route_events`]: trait.Netmon.html#method.with_default_route_events
    fn event_stream(&self) -> std::io::Result<BoxStream<std::io::Result<Event>>>;

    /// Report whether the event stream is strongly consistent with respect to delete
    /// ordering.
    ///
    /// If `true`, callers should interpret an interface deletion event as an immediate
    /// deletion of all resources related to the interface. Individual deletion events for
    /// those resources may or may not be issued.
    ///
    /// If `false`, callers should assume that individual deletion events will be issued
    /// for all resources on interface deletion, but they have no ordering guarantees wrt.
    /// the interface deletion event.
    ///
    /// The return value of this function should never change.
    fn strong_delete_consistency(&self) -> bool {
        true
    }

    /// Report whether addresses are unique per interface independent of netmask.
    ///
    /// Some netmon implementations (notably Windows) treat the address as unique
    /// per interface and permit in-place updates of the netmask.
    ///
    /// The return value of this function should never change.
    fn interface_unique_addrs(&self) -> bool {
        false
    }
}

impl<T> Netmon for &T
where
    T: Netmon + ?Sized,
{
    fn ty(&self) -> MonType {
        T::ty(self)
    }

    fn event_stream(&self) -> std::io::Result<BoxStream<std::io::Result<Event>>> {
        T::event_stream(self)
    }

    fn strong_delete_consistency(&self) -> bool {
        T::strong_delete_consistency(self)
    }

    fn interface_unique_addrs(&self) -> bool {
        T::interface_unique_addrs(self)
    }
}

impl dyn Netmon {
    /// Wrap [`Netmon::event_stream`] with automatically calculated
    /// [`Event::DefaultRouteInterface`].
    ///
    /// Suppresses any such events from the inner stream.
    pub fn with_default_route_events(
        &self,
    ) -> std::io::Result<impl Stream<Item = std::io::Result<Event>> + Send + use<>> {
        let strong_delete_consistency = self.strong_delete_consistency();

        let s = self
            .event_stream()?
            .filter(|x| {
                let result = !x
                    .as_ref()
                    .is_ok_and(|x| matches!(x, Event::DefaultRouteInterface(..)));

                async move { result }
            })
            .scan(
                (
                    DefaultRouteState::new(Family::Ipv4),
                    DefaultRouteState::new(Family::Ipv6),
                ),
                move |(state_v4, state_v6), x| {
                    let [e1, e2] = match &x {
                        Ok(Event::RouteUpsert(interface, route)) => [
                            state_v4.add_route(interface, route),
                            state_v6.add_route(interface, route),
                        ],
                        Ok(Event::RouteRemoved(interface, route)) => [
                            state_v4.remove_route(interface, route),
                            state_v6.remove_route(interface, route),
                        ],
                        Ok(Event::InterfaceUpsert(interface)) => [
                            state_v4.update_interface_state(
                                &interface.id,
                                interface.up,
                                interface.metric_v4,
                            ),
                            state_v6.update_interface_state(
                                &interface.id,
                                interface.up,
                                interface.metric_v6,
                            ),
                        ],
                        Ok(Event::InterfaceRemoved(i)) => {
                            if strong_delete_consistency {
                                let e1 = state_v4.remove_interface(i);
                                let e2 = state_v6.remove_interface(i);

                                [e1, e2]
                            } else {
                                // just wait for the route events
                                [None, None]
                            }
                        }
                        _ => [None, None],
                    };

                    async move {
                        Some(
                            stream::once(async move { x })
                                .chain(stream::iter(e1).map(Ok))
                                .chain(stream::iter(e2).map(Ok)),
                        )
                    }
                },
            )
            .flatten();

        Ok(s)
    }
}

type RouteGateways = smallvec::SmallVec<[IpAddr; 1]>;
type RouteId = usize;
type RouteMetric = usize;
type InterfaceMetric = usize;

/// Tracker for [`Event::DefaultRouteInterface`].
///
/// Ingests route events and interface removals to calculate the default route for a
/// [`Netmon`], emitting updates as [`Event::DefaultRouteInterface`].
#[derive(Debug)]
struct DefaultRouteState {
    /// `BTreeMap` sorted by metric key: iterating the map in increasing order yields routes
    /// of increasing total metric: the first acceptable route is the default route. The key
    /// holds the sum of the route metric and the interface metric for each route.
    ///
    /// It's possible that more than one default route has the same metric, which is why
    /// the value is a set.
    metrics: BTreeMap<RouteMetric, BTreeSet<(InterfaceId, RouteId)>>,

    /// Map of interfaces currently known.
    ///
    /// Interfaces in the down state with no known routes may be removed from this map; the
    /// lack of a map entry can be treated equivalently to this empty state.
    interfaces: HashMap<InterfaceId, InterfaceState>,

    /// The next route id to be allocated.
    ///
    /// Each route gets a unique id; they're not shared across interfaces.
    next_route_id: RouteId,

    /// The last [`InterfaceId`] we reported in an event. If routes change but this
    /// doesn't, we don't need to report a new event.
    last_id: Option<InterfaceId>,

    /// The IP family this covers.
    family: Family,
}

#[derive(Debug, Clone, Default)]
struct InterfaceState {
    /// Whether this interface is in the up state.
    ///
    /// Only `up` interfaces can provide a default route.
    up: bool,
    /// The metric for this interface.
    ///
    /// It's added to each route metric when they're added to
    /// [`DefaultRouteState::metrics`].
    metric: InterfaceMetric,
    /// Routes for this interface.
    routes: HashMap<RouteGateways, (RouteId, RouteMetric)>,
}

impl InterfaceState {
    fn is_removable(&self) -> bool {
        !self.up && self.routes.is_empty()
    }
}

impl DefaultRouteState {
    fn new(family: Family) -> Self {
        Self {
            metrics: Default::default(),
            last_id: None,
            interfaces: Default::default(),
            next_route_id: 0,
            family,
        }
    }

    /// Add or update the specified route for the given interface.
    fn add_route(&mut self, interface_id: &InterfaceId, route: &Route) -> Option<Event> {
        if route.family() != self.family || !route.is_default_route() {
            return None;
        }

        let mut gws = route.gateway.clone();
        gws.sort();

        let interface = self.interfaces.entry(interface_id.clone()).or_default();

        let id = match interface.routes.get_mut(&gws) {
            Some((id, metric)) => {
                if *metric == route.metric {
                    return None;
                }

                if interface.up {
                    let old_metric = route.metric + interface.metric;

                    if let Some(routes) = self.metrics.get_mut(&old_metric) {
                        routes.remove(&(interface_id.clone(), *id));
                        if routes.is_empty() {
                            self.metrics.remove(&old_metric);
                        }
                    }
                }

                *metric = route.metric;
                *id
            }
            None => {
                let id = self.next_route_id;
                self.next_route_id += 1;

                id
            }
        };

        if interface.up {
            let full_metric = interface.metric + route.metric;
            self.metrics
                .entry(full_metric)
                .or_default()
                .insert((interface_id.clone(), id));
        }

        interface.routes.insert(gws, (id, route.metric));

        self.update_best()
    }

    /// Remove the specified route for the given interface.
    fn remove_route(&mut self, interface_id: &InterfaceId, route: &Route) -> Option<Event> {
        if route.family() != self.family || !route.is_default_route() {
            return None;
        }

        let mut gws = route.gateway.clone();
        gws.sort();

        let iface = self.interfaces.get_mut(interface_id)?;
        let (id, route_metric) = iface.routes.remove(&gws)?;

        let full_metric = iface.metric + route_metric;

        if iface.is_removable() {
            self.interfaces.remove(interface_id);
        }

        let entry = self.metrics.get_mut(&full_metric)?;
        if !entry.remove(&(interface_id.clone(), id)) {
            return None;
        }

        if entry.is_empty() {
            self.metrics.remove(&full_metric);
        }

        self.update_best()
    }

    /// Set the interface to up or down, and update its metric if setting to up.
    fn update_interface_state(
        &mut self,
        interface_id: &InterfaceId,
        up: bool,
        metric: usize,
    ) -> Option<Event> {
        if up {
            let interface = self.interfaces.entry(interface_id.clone()).or_default();

            if interface.metric == metric && interface.up == up {
                return None;
            }

            if interface.metric != metric {
                Self::remove_metrics_for_interface(&mut self.metrics, interface_id, &*interface);
            }

            interface.metric = metric;
            interface.up = up;

            for &(route_id, route_metric) in interface.routes.values() {
                let full_metric = metric + route_metric;

                self.metrics
                    .entry(full_metric)
                    .or_default()
                    .insert((interface_id.clone(), route_id));
            }
        } else {
            let interface = self.interfaces.get_mut(interface_id)?;
            if !interface.up {
                return None;
            }

            interface.up = false;
            Self::remove_metrics_for_interface(&mut self.metrics, interface_id, interface);
        }

        self.update_best()
    }

    /// Remove the `self.metrics` entries associated with an interface.
    ///
    /// Reports whether a change in `self.metrics` occurred as a result.
    fn remove_metrics_for_interface(
        metrics: &mut BTreeMap<RouteMetric, BTreeSet<(InterfaceId, RouteId)>>,
        interface_id: &InterfaceId,
        interface: &InterfaceState,
    ) -> bool {
        let mut modified = false;

        for &(route_id, route_metric) in interface.routes.values() {
            let old_full_metric = interface.metric + route_metric;

            if let Some(ent) = metrics.get_mut(&old_full_metric) {
                modified = modified || ent.remove(&(interface_id.clone(), route_id));

                if ent.is_empty() {
                    metrics.remove(&old_full_metric);
                }
            }
        }

        modified
    }

    /// Remove all routes for the given interface from the state.
    ///
    /// We don't handle any logic re: [`Netmon::strong_delete_consistency`], the caller is
    /// responsible for deciding whether to call this function.
    fn remove_interface(&mut self, interface_id: &InterfaceId) -> Option<Event> {
        if let Some(iface) = self.interfaces.remove(interface_id)
            && iface.up
            && !Self::remove_metrics_for_interface(&mut self.metrics, interface_id, &iface)
        {
            return None;
        }

        self.update_best()
    }

    /// Update the best-route interface id, generating [`Event::DefaultRouteInterface`] if
    /// it has changed.
    fn update_best(&mut self) -> Option<Event> {
        let new_best_id = self
            .metrics
            .values()
            .flatten()
            .find_map(|(iid, _rtid)| {
                self.interfaces
                    .get(iid)
                    .is_some_and(|x| x.up)
                    .then_some(iid)
            })
            .cloned();

        if new_best_id == self.last_id {
            return None;
        }

        self.last_id = new_best_id.clone();

        Some(Event::DefaultRouteInterface(new_best_id, self.family))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const MONTYPE: MonType = MonType::new_static("test");

    #[test]
    fn different_gateway() -> Result<(), Box<dyn core::error::Error>> {
        let mut state = DefaultRouteState::new(Family::Ipv4);
        let interface = InterfaceId::new(MONTYPE, 0);

        let evt1 = state.update_interface_state(&interface, true, 0);

        let route1 = Route {
            metric: 0,
            gateway: smallvec::smallvec!["1.2.3.4".parse()?],
            dst: ipnet::Ipv4Net::default().into(),
        };

        let route2 = Route {
            metric: 0,
            gateway: smallvec::smallvec!["5.6.7.8".parse()?],
            dst: ipnet::Ipv4Net::default().into(),
        };

        assert!(route1.is_default_route() && route2.is_default_route());

        let evt2 = state.add_route(&interface, &route1);
        let evt3 = state.add_route(&interface, &route2);

        assert_eq!(state.last_id, Some(interface.clone()));

        assert_eq!(evt1, None);
        assert_eq!(
            evt2,
            Some(Event::DefaultRouteInterface(
                Some(interface.clone()),
                Family::Ipv4
            ))
        );
        assert_eq!(evt3, None);

        let rem1 = state.remove_route(&interface, &route1);
        let rem2 = state.remove_route(&interface, &route2);

        assert_eq!(state.last_id, None);
        assert_eq!(rem1, None);
        assert_eq!(rem2, Some(Event::DefaultRouteInterface(None, Family::Ipv4)));

        Ok(())
    }
}
