use core::{net::IpAddr, pin::Pin};
use std::collections::{BTreeMap, BTreeSet, HashSet};

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
                            state_v4.update_interface_state(&interface.id, interface.up),
                            state_v6.update_interface_state(&interface.id, interface.up),
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

/// The unique part of a default route: the interface and the set of gateways.
type DefaultRouteUnique = (InterfaceId, smallvec::SmallVec<[IpAddr; 1]>);

/// Tracker for [`Event::DefaultRouteInterface`].
///
/// Ingests route events and interface removals to calculate the default route for a
/// [`Netmon`], emitting updates as [`Event::DefaultRouteInterface`].
#[derive(Debug)]
struct DefaultRouteState {
    /// Metrics per (interface, gateways) tuple.
    ///
    /// Stored in btrees for ordering: we always want the minimum available metric
    /// (`BTreeMap`), and the inner `BTreeSet` is sorted to provide a stable answer if
    /// multiple interfaces have a route with the same metric. We have to store the set of
    /// gateways along with the interface, as technically the same interface could have
    /// multiple default routes with different sets of gateways (on platforms that permit
    /// this) and they would be distinguishable.
    metrics: BTreeMap<usize, BTreeSet<DefaultRouteUnique>>,

    /// Set of interfaces that are in the up state.
    ///
    /// Only these interfaces can be considered for being the default route interface.
    interfaces_up: HashSet<InterfaceId>,

    /// The last [`InterfaceId`] we reported in an event. If routes change but this
    /// doesn't, we don't need to report a new event.
    last_id: Option<InterfaceId>,

    /// The IP family this covers.
    family: Family,
}

impl DefaultRouteState {
    fn new(family: Family) -> Self {
        Self {
            metrics: Default::default(),
            last_id: None,
            interfaces_up: Default::default(),
            family,
        }
    }

    /// Add the specified route for the given interface.
    fn add_route(&mut self, interface_id: &InterfaceId, route: &Route) -> Option<Event> {
        if route.family() != self.family || !route.is_default_route() {
            return None;
        }

        let mut gws = route.gateway.clone();
        gws.sort();

        let modified = self
            .metrics
            .entry(route.metric)
            .or_default()
            .insert((interface_id.clone(), gws));

        if !modified {
            return None;
        }

        self.update_best()
    }

    /// Remove the specified route for the given interface.
    fn remove_route(&mut self, interface_id: &InterfaceId, route: &Route) -> Option<Event> {
        if route.family() != self.family || !route.is_default_route() {
            return None;
        }

        let entry = self.metrics.get_mut(&route.metric)?;
        let mut gws = route.gateway.clone();
        gws.sort();

        let modified = entry.remove(&(interface_id.clone(), gws));
        if !modified {
            return None;
        }

        if entry.is_empty() {
            self.metrics.remove(&route.metric);
        }

        self.update_best()
    }

    /// Set the interface to up or down.
    fn update_interface_state(&mut self, interface_id: &InterfaceId, up: bool) -> Option<Event> {
        if up {
            self.interfaces_up.insert(interface_id.clone())
        } else {
            self.interfaces_up.remove(interface_id)
        }
        .then(|| self.update_best())
        .flatten()
    }

    /// Remove all routes for the given interface from the state.
    ///
    /// We don't handle any logic re: [`Netmon::strong_delete_consistency`], the caller is
    /// responsible for deciding whether to call this function.
    fn remove_interface(&mut self, interface_id: &InterfaceId) -> Option<Event> {
        let mut metrics_modified = false;

        self.metrics.retain(|_, e| {
            e.retain(|(id, _)| {
                let ret = id == interface_id;
                metrics_modified = metrics_modified || ret;

                ret
            });

            !e.is_empty()
        });

        self.interfaces_up.remove(interface_id);

        if !metrics_modified {
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
            .find_map(|(id, _)| self.interfaces_up.contains(id).then(|| id.clone()));

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

        let evt1 = state.update_interface_state(&interface, true);

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
