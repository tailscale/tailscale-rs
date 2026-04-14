#![doc = include_str!("../README.md")]
#![no_std]

extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

pub extern crate ts_netstack_smoltcp_core as netcore;

#[doc(inline)]
pub use netcore::smoltcp::wire::IpProtocol;

/// Provide internal `request` and `request_async` helper methods for sockets, wrapping
/// [`netcore::request_blocking`] and [`netcore::request`]. Automatically passes
/// the internal socket `handle` and wraps/unwraps request and response types.
macro_rules! socket_requestor_impl {
    () => {
        fn request_blocking(
            &self,
            command: impl Into<$crate::netcore::Command>,
        ) -> Result<$crate::netcore::Response, $crate::netcore::Error> {
            ::netcore::HasChannel::request_blocking(&self.sender, Some(self.handle), command)
        }

        async fn request(
            &self,
            command: impl Into<$crate::netcore::Command>,
        ) -> Result<$crate::netcore::Response, $crate::netcore::Error> {
            ::netcore::HasChannel::request(&self.sender, Some(self.handle), command).await
        }
    };
}

mod create_socket;
pub use create_socket::CreateSocket;

mod raw;
mod tcp;
mod udp;

pub use raw::RawSocket;
pub use tcp::{TcpListener, TcpStream};
pub use udp::UdpSocket;
