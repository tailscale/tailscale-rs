//! Print routes gathered using iphlpapi.
//!
//! Notable observations:
//!
//! - The Win32 layer (or the kernel) spins up worker threads to run the notification
//!   callbacks; they do not execute on a user-controlled thread (like a Unix signal
//!   handler would).
//! - There appear not to be ordering guarantees between the notification streams.
//!   I have seen a route deletion come after a link deletion.

#[cfg(windows)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use core::{ffi, ptr::null};

    use ts_netmon::{
        FamilyOrBoth, Route,
        windows::{InterfaceReport, unicast_row_to_ipnet},
    };
    use windows::Win32::{
        Foundation::HANDLE,
        NetworkManagement::{IpHelper, Ndis},
        Networking::WinSock,
    };

    fn thread_id() -> std::thread::ThreadId {
        std::thread::current().id()
    }

    ts_cli_util::init_tracing();

    fn tyname(ty: IpHelper::MIB_NOTIFICATION_TYPE) -> String {
        match ty {
            IpHelper::MibAddInstance => "ADD".to_owned(),
            IpHelper::MibDeleteInstance => "DEL".to_owned(),
            IpHelper::MibParameterNotification => "UPD".to_owned(),
            ty => ty.0.to_string(),
        }
    }

    unsafe extern "system" fn route_cb(
        _ctx: *const ffi::c_void,
        row: *const IpHelper::MIB_IPFORWARD_ROW2,
        ty: IpHelper::MIB_NOTIFICATION_TYPE,
    ) {
        let mut row = unsafe { *row };

        if ty != IpHelper::MibDeleteInstance {
            ts_netmon::windows::populate_route(&mut row).unwrap();
        }

        let route = Route::from(row);
        let gw = match route.gateway.as_slice() {
            &[] => "ON-LINK".to_string(),
            &[gw] => {
                format!("VIA {gw}")
            }
            gws => {
                format!("VIA {gws:?}")
            }
        };

        eprintln!(
            "[{:2?}] {} ROUT {} {:32} {gw}",
            thread_id(),
            row.InterfaceIndex,
            tyname(ty),
            format!("{}", route.dst)
        );
    }

    let mut route_notif: HANDLE = HANDLE::default();
    unsafe {
        IpHelper::NotifyRouteChange2(
            WinSock::AF_UNSPEC,
            Some(route_cb),
            null(),
            false,
            &mut route_notif,
        )
        .ok()?
    };

    unsafe extern "system" fn addr_cb(
        _ctx: *const ffi::c_void,
        row: *const IpHelper::MIB_UNICASTIPADDRESS_ROW,
        ty: IpHelper::MIB_NOTIFICATION_TYPE,
    ) {
        let mut row = unsafe { *row };

        if ty != IpHelper::MibDeleteInstance {
            let _ = unsafe { IpHelper::GetUnicastIpAddressEntry(&mut row) };
        }

        eprintln!(
            "[{:2?}] {} ADDR {} {}",
            thread_id(),
            row.InterfaceIndex,
            tyname(ty),
            unicast_row_to_ipnet(&row)
        );
    }

    let mut addr_notif: HANDLE = HANDLE::default();
    unsafe {
        IpHelper::NotifyUnicastIpAddressChange(
            WinSock::AF_UNSPEC,
            Some(addr_cb),
            None,
            false,
            &mut addr_notif,
        )
        .ok()?
    };

    fn fmt_oper_status(status: Ndis::IF_OPER_STATUS) -> &'static str {
        match status {
            Ndis::IfOperStatusUp => " UP ",
            Ndis::IfOperStatusDown => "DOWN",
            Ndis::IfOperStatusLowerLayerDown => "LLDN",
            Ndis::IfOperStatusDormant => "DORM",
            _ => "UNKN",
        }
    }

    unsafe extern "system" fn interface_cb(
        _ctx: *const ffi::c_void,
        row: *const IpHelper::MIB_IPINTERFACE_ROW,
        ty: IpHelper::MIB_NOTIFICATION_TYPE,
    ) {
        let row = unsafe { row.as_ref() }.unwrap();

        let rpt = InterfaceReport::get(row.Family.try_into().unwrap()).unwrap();
        let interface = rpt
            .iter()
            .find(|x| unsafe { x.Luid.Value == row.InterfaceLuid.Value })
            .unwrap();

        eprintln!(
            "[{:2?}] {} LINK {} {} ({:?})",
            thread_id(),
            row.InterfaceIndex,
            tyname(ty),
            fmt_oper_status(interface.OperStatus),
            FamilyOrBoth::try_from(row.Family).unwrap()
        );
    }

    let mut interface_notif: HANDLE = HANDLE::default();
    unsafe {
        IpHelper::NotifyIpInterfaceChange(
            WinSock::AF_UNSPEC,
            Some(interface_cb),
            None,
            false,
            &mut interface_notif,
        )
        .ok()?
    };

    tracing::info!(thread_id = ?thread_id(), "notifications registered");

    loop {
        std::thread::park();
    }
}

#[cfg(not(windows))]
fn main() {
    eprintln!("this example is a no-op on non-windows targets")
}
