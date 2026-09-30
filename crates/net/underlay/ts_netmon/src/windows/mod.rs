//! Windows network monitor implementation.

use core::pin::Pin;

use futures_util::Stream;

use crate::Event;

mod addr_iter;
mod event_stream;
mod interface_report;
mod routes;
mod util;

pub use addr_iter::{AddrIter, iter_prefixes, iter_unicast};
pub use event_stream::{
    LinkChange, LinkStream, RouteChange, RouteStream, UnicastIpChange, UnicastIpStream,
    populate_route, stream as event_stream,
};
pub use interface_report::{InterfaceReport, ReportIter};
pub use routes::RouteTable;
pub use util::{sockaddr_inet_to_ipaddr, unicast_row_to_ipnet};

use crate::{id::MonType, netmon::Netmon};

/// Canonical Windows [`Netmon`] built on Win32's
/// [`<iphlpapi.h>`](https://learn.microsoft.com/en-us/windows/win32/api/_iphlp/).
#[derive(Debug, Copy, Clone, Default)]
pub struct Winmon;

impl Netmon for Winmon {
    fn ty(&self) -> MonType {
        MonType::WINDOWS_IPHLPAPI
    }

    fn event_stream(
        &self,
    ) -> std::io::Result<Pin<Box<dyn Stream<Item = std::io::Result<Event>> + Send>>> {
        Ok(Box::pin(event_stream()?))
    }

    fn strong_delete_consistency(&self) -> bool {
        false
    }

    fn interface_unique_addrs(&self) -> bool {
        true
    }
}
