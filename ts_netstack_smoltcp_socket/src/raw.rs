use core::{
    fmt::{Debug, Formatter},
    num::NonZeroUsize,
};

use bytes::Bytes;
use netcore::{
    DisplayExt, HasChannel, Response, raw,
    smoltcp::{
        iface::SocketHandle,
        wire::{IpProtocol, IpVersion},
    },
};

/// A raw IP socket.
///
/// This socket type intercepts all traffic for its protocol number, even if there are
/// protocol-specific sockets connected or listening.
pub struct RawSocket {
    handle: SocketHandle,
    ip_protocol: IpProtocol,
    ip_version: IpVersion,
    sender: netcore::Channel,
}

impl Debug for RawSocket {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("UdpSocket")
            .field("handle", &self.handle.as_display_debug())
            .field("version", &self.ip_version)
            .field("proto", &self.ip_protocol)
            .finish()
    }
}

impl RawSocket {
    pub(crate) fn new(
        sender: netcore::Channel,
        handle: SocketHandle,
        ip_protocol: IpProtocol,
        ip_version: IpVersion,
    ) -> Self {
        Self {
            handle,
            ip_protocol,
            ip_version,
            sender,
        }
    }

    /// Send the raw packet contained in `buf` over the network.
    pub fn send_blocking(&self, buf: &[u8]) -> Result<(), netcore::Error> {
        self.request_blocking(raw::Command::Send {
            buf: Bytes::copy_from_slice(buf),
        })?
        .to_ok()
    }

    /// Send the raw packet contained in `buf` over the network.
    pub async fn send(&self, buf: &[u8]) -> Result<(), netcore::Error> {
        self.request(raw::Command::Send {
            buf: Bytes::copy_from_slice(buf),
        })
        .await?
        .to_ok()
    }

    /// Receive a raw packet into `buf` from the network.
    pub fn recv_blocking(&self, buf: &mut [u8]) -> Result<usize, netcore::Error> {
        let len = NonZeroUsize::new(buf.len()).ok_or(netcore::Error::BadBuffer)?;
        let resp = self.request_blocking(raw::Command::Recv { max_len: Some(len) })?;

        self._recv(buf, resp)
    }

    /// Receive a raw packet into `buf` from the network.
    pub async fn recv(&self, buf: &mut [u8]) -> Result<usize, netcore::Error> {
        let len = NonZeroUsize::new(buf.len()).ok_or(netcore::Error::BadBuffer)?;
        let resp = self
            .request(raw::Command::Recv { max_len: Some(len) })
            .await?;

        self._recv(buf, resp)
    }

    /// Receive a raw packet into `buf` from the network.
    pub fn recv_bytes_blocking(&self) -> Result<Bytes, netcore::Error> {
        let resp = self.request_blocking(raw::Command::Recv { max_len: None })?;
        self._recv_bytes(resp)
    }

    /// Receive a raw packet into `buf` from the network.
    pub async fn recv_bytes(&self) -> Result<Bytes, netcore::Error> {
        let resp = self.request(raw::Command::Recv { max_len: None }).await?;
        self._recv_bytes(resp)
    }

    fn _recv(&self, buf: &mut [u8], resp: Response) -> Result<usize, netcore::Error> {
        let ret_buf = self._recv_bytes(resp)?;

        let len = buf.len().min(ret_buf.len());
        buf[..len].copy_from_slice(&ret_buf[..len]);

        Ok(len)
    }

    fn _recv_bytes(&self, resp: Response) -> Result<Bytes, netcore::Error> {
        netcore::try_response_as!(resp, raw::Response::Recv { buf, truncated });

        if let Some(truncated) = truncated {
            tracing::warn!(truncated, "packet was truncated");
        }

        Ok(buf)
    }

    socket_requestor_impl!();
}

impl Drop for RawSocket {
    fn drop(&mut self) {
        if let Err(e) = self
            .sender
            .request_nonblocking(Some(self.handle), raw::Command::Close)
        {
            tracing::warn!(err = %e, "possible socket leak");
        }
    }
}
