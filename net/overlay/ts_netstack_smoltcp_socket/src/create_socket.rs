use core::net::SocketAddr;

use netcore::{Command, HasChannel, raw, smoltcp::wire, tcp, udp};

use crate::{RawSocket, TcpListener, TcpStream, UdpSocket};

/// API for creating sockets over a [`HasChannel`].
pub trait CreateSocket {
    /// Create and bind a new [`UdpSocket`] to the given local endpoint.
    fn udp_bind_blocking(&self, endpoint: SocketAddr) -> Result<UdpSocket, netcore::Error>;
    /// Asynchronously create and bind a new [`UdpSocket`] to the given local endpoint.
    fn udp_bind(
        &self,
        endpoint: SocketAddr,
    ) -> impl Future<Output = Result<UdpSocket, netcore::Error>> + Send;

    /// Create a new [`TcpListener`] on the given endpoint.
    fn tcp_listen_blocking(
        &self,
        local_endpoint: SocketAddr,
    ) -> Result<TcpListener, netcore::Error>;
    /// Asynchronously create a new [`TcpListener`] on the given endpoint.
    fn tcp_listen(
        &self,
        local_endpoint: SocketAddr,
    ) -> impl Future<Output = Result<TcpListener, netcore::Error>> + Send;

    /// Create a new [`TcpStream`] bound to the given `local` address and connected to
    /// the given `remote`.
    ///
    /// Waits for the handshake to complete before returning.
    fn tcp_connect_blocking(
        &self,
        local_endpoint: SocketAddr,
        remote_endpoint: SocketAddr,
    ) -> Result<TcpStream, netcore::Error>;
    /// Asynchronously create a new [`TcpStream`] bound to the given `local` address and
    /// connected to the given `remote`.
    ///
    /// Waits for the handshake to complete before returning.
    fn tcp_connect(
        &self,
        local_endpoint: SocketAddr,
        remote_endpoint: SocketAddr,
    ) -> impl Future<Output = Result<TcpStream, netcore::Error>> + Send;

    /// Create a new [`RawSocket`] on the selected ip version and protocol.
    ///
    /// NB: this will intercept _all_ matching traffic, even if you have other sockets open.
    fn raw_open_blocking(
        &self,
        ipv4: bool,
        ip_protocol: wire::IpProtocol,
    ) -> Result<RawSocket, netcore::Error>;
    /// Asynchronously create a new [`RawSocket`] on the selected ip version and protocol.
    ///
    /// NB: this will intercept _all_ matching traffic, even if you have other sockets open.
    fn raw_open(
        &self,
        ipv4: bool,
        ip_protocol: wire::IpProtocol,
    ) -> impl Future<Output = Result<RawSocket, netcore::Error>> + Send;
}

impl<T> CreateSocket for T
where
    T: HasChannel + Sync,
{
    fn udp_bind_blocking(&self, endpoint: SocketAddr) -> Result<UdpSocket, netcore::Error> {
        let resp = self.request_blocking(None, udp::Command::Bind { endpoint })?;

        netcore::try_response_as!(resp, udp::Response::Bound { local, handle });

        Ok(UdpSocket {
            sender: self.command_channel(),
            local,
            handle,
        })
    }

    async fn udp_bind(&self, endpoint: SocketAddr) -> Result<UdpSocket, netcore::Error> {
        let resp = self.request(None, udp::Command::Bind { endpoint }).await?;

        netcore::try_response_as!(resp, udp::Response::Bound { local, handle });

        Ok(UdpSocket {
            sender: self.command_channel(),
            local,
            handle,
        })
    }

    fn tcp_listen_blocking(
        &self,
        local_endpoint: SocketAddr,
    ) -> Result<TcpListener, netcore::Error> {
        let resp = self.request_blocking(None, tcp::listen::Command::Listen { local_endpoint })?;

        netcore::try_response_as!(resp, tcp::listen::Response::Listening { handle });

        Ok(TcpListener {
            sender: self.command_channel(),
            handle,
            endpoint: local_endpoint,
        })
    }

    async fn tcp_listen(&self, local_endpoint: SocketAddr) -> Result<TcpListener, netcore::Error> {
        let resp = self
            .request(None, tcp::listen::Command::Listen { local_endpoint })
            .await?;

        netcore::try_response_as!(resp, tcp::listen::Response::Listening { handle });

        Ok(TcpListener {
            sender: self.command_channel(),
            handle,
            endpoint: local_endpoint,
        })
    }

    fn tcp_connect_blocking(
        &self,
        local_endpoint: SocketAddr,
        remote_endpoint: SocketAddr,
    ) -> Result<TcpStream, netcore::Error> {
        let resp = self.request_blocking(
            None,
            tcp::stream::Command::Connect {
                remote_endpoint,
                local_endpoint,
            },
        )?;

        netcore::try_response_as!(resp, tcp::stream::Response::Connected { handle });

        Ok(TcpStream::new(
            self.command_channel(),
            handle,
            remote_endpoint,
            local_endpoint,
        ))
    }

    async fn tcp_connect(
        &self,
        local_endpoint: SocketAddr,
        remote_endpoint: SocketAddr,
    ) -> Result<TcpStream, netcore::Error> {
        let resp = self
            .request(
                None,
                tcp::stream::Command::Connect {
                    remote_endpoint,
                    local_endpoint,
                },
            )
            .await?;

        netcore::try_response_as!(resp, tcp::stream::Response::Connected { handle });

        Ok(TcpStream::new(
            self.command_channel(),
            handle,
            remote_endpoint,
            local_endpoint,
        ))
    }

    fn raw_open_blocking(
        &self,
        ipv4: bool,
        ip_protocol: wire::IpProtocol,
    ) -> Result<RawSocket, netcore::Error> {
        let ip_version = if ipv4 {
            wire::IpVersion::Ipv4
        } else {
            wire::IpVersion::Ipv6
        };

        let resp = self.request_blocking(
            None,
            Command::Raw(raw::Command::Open {
                ip_version,
                protocol: ip_protocol,
            }),
        )?;

        netcore::try_response_as!(resp, raw::Response::Opened { handle });

        Ok(RawSocket::new(
            self.command_channel(),
            handle,
            ip_protocol,
            ip_version,
        ))
    }

    async fn raw_open(
        &self,
        ipv4: bool,
        ip_protocol: wire::IpProtocol,
    ) -> Result<RawSocket, netcore::Error> {
        let ip_version = if ipv4 {
            wire::IpVersion::Ipv4
        } else {
            wire::IpVersion::Ipv6
        };

        let resp = self
            .request(
                None,
                Command::Raw(raw::Command::Open {
                    ip_version,
                    protocol: ip_protocol,
                }),
            )
            .await?;

        netcore::try_response_as!(resp, raw::Response::Opened { handle });

        Ok(RawSocket::new(
            self.command_channel(),
            handle,
            ip_protocol,
            ip_version,
        ))
    }
}
