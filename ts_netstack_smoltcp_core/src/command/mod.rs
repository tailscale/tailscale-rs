//! Command API definition.

use core::fmt::Debug;

use flume::Sender;
use smoltcp::iface::SocketHandle;

mod channel;
mod error;
pub mod raw;
mod request;
pub mod stack_control;
pub mod tcp;
pub mod udp;

pub use channel::{Channel, HasChannel};
pub use error::{Error, InternalErrorKind};
pub use request::{ChannelClosedError, request, request_blocking, request_nonblocking};

/// Request to a netstack bearing a command to execute.
///
/// This wraps [`Command`] to provide additional common metadata, including the handle to
/// the relevant socket (if there is one) and a channel through which the netstack should
/// respond to the request.
pub struct Request {
    /// Socket handle this message is associated with, if any.
    pub handle: Option<SocketHandle>,
    /// The command to run.
    pub command: Command,
    /// Oneshot response channel.
    pub resp: Sender<Response>,
}

/// Command that a netstack should execute.
#[derive(Debug)]
pub enum Command {
    /// Commands that configure the network stack itself (e.g. set interface IPs).
    StackControl(stack_control::Command),

    /// Commands for TCP listeners.
    TcpListen(tcp::listen::Command),
    /// Commands for TCP streams.
    TcpStream(tcp::stream::Command),
    /// Commands for UDP sockets.
    Udp(udp::Command),
    /// Commands for raw sockets.
    Raw(raw::Command),
}

/// Response to a command.
#[derive(Debug)]
pub enum Response {
    /// Unit return: operation succeeded with nothing to report.
    Ok,

    /// Operation failed with the given error.
    Error(Error),

    /// Operation is waiting for data: requeue it and try it again later.
    ///
    /// This variant is never returned to the caller over the response channel, it is just
    /// used for signaling internally.
    WouldBlock {
        /// The socket handle to retry against.
        handle: Option<SocketHandle>,
        /// The command to retry.
        command: Command,
    },

    /// Responses for UDP sockets.
    Udp(udp::Response),
    /// Responses for TCP listeners.
    TcpListen(tcp::listen::Response),
    /// Responses for TCP streams.
    TcpStream(tcp::stream::Response),
    /// Responses for raw sockets.
    Raw(raw::Response),
}

macro_rules! impl_try_from {
    ($ty:ty, $variant:ident) => {
        impl TryFrom<Response> for $ty {
            type Error = Error;

            fn try_from(response: Response) -> Result<Self, Self::Error> {
                match response {
                    Response::$variant(resp) => Ok(resp),
                    Response::Error(e) => Err(e),
                    _ => Err(Error::wrong_type()),
                }
            }
        }
    };
}

impl_try_from!(udp::Response, Udp);
impl_try_from!(raw::Response, Raw);
impl_try_from!(tcp::stream::Response, TcpStream);
impl_try_from!(tcp::listen::Response, TcpListen);

impl Response {
    /// Check if this response is the `Ok` variant, returning an error if not.
    pub fn to_ok(self) -> Result<(), Error> {
        match self {
            Response::Ok => Ok(()),
            Response::Error(e) => Err(e),
            _ => Err(Error::wrong_type()),
        }
    }
}

/// Attempt to convert a [`Response`] into a specific variant.
///
/// The second argument is a pattern, as if it were being used in a match expression.
///
/// # Example
///
/// ```rust
/// extern crate ts_netstack_smoltcp_core as netcore;
/// use netcore::{tcp, try_response_as};
/// # fn main() -> Result<(), netcore::Error> {
/// # let resp: netcore::Response = tcp::stream::Response::Sent { n: 42 }.into();
///
/// try_response_as!(resp, tcp::stream::Response::Sent { n });
/// assert_eq!(n, 42);
/// # Ok(())
/// # }
/// ```
#[macro_export]
macro_rules! try_response_as {
    ($resp:expr, $pat:pat) => {
        let $pat = $resp.try_into()? else {
            ::tracing::error!("invalid response type");

            return Err($crate::Error::wrong_type().into());
        };
    };
}
