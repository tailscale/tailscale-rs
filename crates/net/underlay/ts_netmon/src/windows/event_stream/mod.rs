use futures_util::{Stream, StreamExt, TryStreamExt};
use windows::Win32::{Foundation, NetworkManagement::IpHelper};

use crate::{
    Event, FamilyOrBoth,
    windows::{InterfaceReport, routes::RouteTable, unicast_row_to_ipnet},
};

mod notify_stream;
pub use notify_stream::{
    LinkChange, LinkStream, RouteChange, RouteStream, UnicastIpChange, UnicastIpStream,
};

use crate::windows::iter_unicast;

/// Produce a stream of [`Event`]s as reported by the Windows kernel.
///
/// At startup, this stream produces a set of events that establish the initial state.
pub fn stream() -> std::io::Result<impl Stream<Item = std::io::Result<Event>>> {
    let route_changes = RouteStream::new(FamilyOrBoth::Both)?;
    let unicast_changes = UnicastIpStream::new(FamilyOrBoth::Both)?;
    let link_changes = LinkStream::new(FamilyOrBoth::Both)?;

    let route_changes = route_changes
        .then(async |(ty, change)| {
            let a = handle_route_change(ty, change);
            futures_util::stream::iter(a)
        })
        .flatten();

    let unicast_changes =
        unicast_changes.filter_map(async |(ty, change)| handle_unicast_change(ty, change));

    let link_changes = link_changes
        .filter_map(async |(ty, change)| handle_link_change(ty, change).await.transpose());

    let init = futures_util::stream::once(init_state())
        .try_filter_map(async |x| Ok(Some(futures_util::stream::iter(x).map(Ok))))
        .try_flatten();

    let updates = {
        use tokio_stream::StreamExt;
        route_changes.merge(unicast_changes).merge(link_changes)
    };

    Ok(init.chain(updates))
}

/// Produce initial [`Event`]s representing the system state from an [`InterfaceReport`]
/// and [`RouteTable`].
async fn init_state() -> windows::core::Result<impl Iterator<Item = Event>> {
    let (report, route_table) = report_and_table(FamilyOrBoth::Both).await?;

    let interfaces = report
        .iter()
        .map(|adapter| Event::InterfaceUpsert(crate::Interface::from(adapter)))
        .collect::<Vec<_>>();

    let addrs = report
        .iter()
        .flat_map(|adapter| {
            iter_unicast(adapter).map(|x| Event::AddrUpsert(adapter.Luid.into(), x))
        })
        .collect::<Vec<Event>>();

    let init_routes = route_table
        .iter()
        .map(|row| Event::RouteUpsert(row.InterfaceLuid.into(), row.into()))
        .collect::<Vec<_>>();

    Ok(interfaces.into_iter().chain(addrs).chain(init_routes))
}

/// Handle a [`RouteChange`] event from the underlying notify stream.
fn handle_route_change(
    ty: IpHelper::MIB_NOTIFICATION_TYPE,
    mut change: IpHelper::MIB_IPFORWARD_ROW2,
) -> Option<std::io::Result<Event>> {
    let event = match ty {
        IpHelper::MibAddInstance | IpHelper::MibParameterNotification => {
            if let Err(e) = populate_route(&mut change) {
                return Some(Err(e));
            }

            Event::RouteUpsert(change.InterfaceLuid.into(), change.into())
        }
        IpHelper::MibDeleteInstance => {
            // On a deletion, the route info is gone already, so don't bother trying to load it.
            Event::RouteRemoved(change.InterfaceLuid.into(), change.into())
        }
        _ => return None,
    };

    Some(Ok(event))
}

/// Populate the route entry with additional info from the kernel.
///
/// This is needed because the changes loaded by the notify APIs do not include some
/// relevant information such as the `Metric` field. Even that info isn't typically fully
/// filled out; it usually omits the link metric, which also needs to be loaded and is
/// added to the route here.
///
/// This will only return successfully if the row is still in the route table. A route
/// produced by [`IpHelper::NotifyRouteChange2`] and accompanied by
/// [`IpHelper::MibDeleteInstance`] is no longer in the table, so this will return
/// [`std::io::ErrorKind::NotFound`].
pub fn populate_route(row: &mut IpHelper::MIB_IPFORWARD_ROW2) -> std::io::Result<()> {
    // SAFETY: this API is invoked correctly.
    tokio::task::block_in_place(|| unsafe {
        IpHelper::GetIpForwardEntry2(row).ok()?;

        Ok(())
    })
}

/// Handle a [`UnicastIpChange`] event from the underlying notify stream.
fn handle_unicast_change(
    ty: IpHelper::MIB_NOTIFICATION_TYPE,
    mut change: IpHelper::MIB_UNICASTIPADDRESS_ROW,
) -> Option<std::io::Result<Event>> {
    let result = unsafe { IpHelper::GetUnicastIpAddressEntry(&mut change as *mut _) };
    match result {
        Foundation::NO_ERROR | Foundation::ERROR_NOT_FOUND => {}
        e => {
            return Some(Err(e.ok().unwrap_err().into()));
        }
    }

    let ipn = || unicast_row_to_ipnet(&change);

    match ty {
        // On a parameter notification, the prefix is allowed to change on Windows, the address
        // itself is the unique key.
        IpHelper::MibAddInstance | IpHelper::MibParameterNotification => {
            Some(Ok(Event::AddrUpsert(change.InterfaceLuid.into(), ipn())))
        }
        IpHelper::MibDeleteInstance => {
            Some(Ok(Event::AddrRemoved(change.InterfaceLuid.into(), ipn())))
        }
        _ => None,
    }
}

/// Handle a [`LinkChange`] event from the underlying notify stream.
async fn handle_link_change(
    ty: IpHelper::MIB_NOTIFICATION_TYPE,
    change: IpHelper::MIB_IPINTERFACE_ROW,
) -> std::io::Result<Option<Event>> {
    match ty {
        IpHelper::MibAddInstance | IpHelper::MibParameterNotification => {
            let Ok(family) = change.Family.try_into() else {
                tracing::error!(
                    family = ?change.Family,
                    "unexpected address family for link change",
                );
                return Ok(None);
            };

            // Seemingly the only way to get a single interface definition in iphlpapi is to request
            // the complete interface report via GetAdaptersAddresses.
            let report = tokio::task::spawn_blocking(move || InterfaceReport::get(family))
                .await
                .unwrap()?; // intentionally forward internal panics

            if let Some(interface) = report
                .iter()
                // SAFETY: all u64 bitpatterns are valid
                .find(|x| unsafe { x.Luid.Value == change.InterfaceLuid.Value })
            {
                Ok(Some(Event::InterfaceUpsert(interface.into())))
            } else {
                Ok(None)
            }
        }
        IpHelper::MibDeleteInstance => {
            Ok(Some(Event::InterfaceRemoved(change.InterfaceLuid.into())))
        }
        _ => Ok(None),
    }
}

/// Convenience helper to grab an [`InterfaceReport`] and [`RouteTable`] for the given
/// [`FamilyOrBoth`] correctly wrapped with [`tokio::task::spawn_blocking`].
async fn report_and_table(family: FamilyOrBoth) -> std::io::Result<(InterfaceReport, RouteTable)> {
    tokio::task::spawn_blocking(move || {
        let adp = InterfaceReport::get(family)?;
        let mut route_table = RouteTable::get(family)?;

        for route in route_table.iter_mut() {
            populate_route(route)?;
        }

        Ok((adp, route_table)) as std::io::Result<_>
    })
    .await
    .unwrap() // intentionally forward internal panics
}
