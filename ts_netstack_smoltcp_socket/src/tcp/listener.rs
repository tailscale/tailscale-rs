use core::{
    fmt::{Debug, Formatter},
    net::SocketAddr,
};

use netcore::{HasChannel, Response, tcp};

use crate::TcpStream;

/// A TCP listener waiting to accept connections.
pub struct TcpListener {
    pub(crate) handle: netcore::TcpListenerHandle,
    pub(crate) endpoint: SocketAddr,
    pub(crate) sender: netcore::Channel,
}

impl Debug for TcpListener {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcpListener")
            .field("endpoint", &self.endpoint)
            .field("handle", &self.handle)
            .finish()
    }
}

impl TcpListener {
    /// Accept a connection from a remote peer.
    ///
    /// Blocks until a connection is made.
    pub fn accept_blocking(&self) -> Result<TcpStream, netcore::Error> {
        let resp = self.sender.request_blocking(
            None,
            tcp::listen::Command::Accept {
                handle: self.handle,
            },
        )?;

        self._accept(resp)
    }

    /// Accept a connection from a remote peer.
    ///
    /// Blocks until a connection is made.
    pub async fn accept(&self) -> Result<TcpStream, netcore::Error> {
        let resp = self
            .sender
            .request(
                None,
                tcp::listen::Command::Accept {
                    handle: self.handle,
                },
            )
            .await?;

        self._accept(resp)
    }

    fn _accept(&self, response: Response) -> Result<TcpStream, netcore::Error> {
        netcore::try_response_as!(response, tcp::listen::Response::Accepted { handle, remote });

        Ok(TcpStream::new(
            self.sender.clone(),
            handle,
            remote,
            self.endpoint,
        ))
    }

    /// Report the local endpoint on which this is listening.
    pub const fn local_endpoint_addr(&self) -> SocketAddr {
        self.endpoint
    }
}

impl Drop for TcpListener {
    fn drop(&mut self) {
        if let Err(e) = self.sender.request_nonblocking(
            None,
            tcp::listen::Command::Close {
                handle: self.handle,
            },
        ) {
            tracing::warn!(error = %e, "possible socket leak on drop");
        }
    }
}
