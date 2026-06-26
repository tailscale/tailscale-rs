//! Functions and utilities for proxying bytes between TCP streams.

#![allow(missing_docs)]

use core::net::SocketAddr;

use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{
    Device, Error, TailnetAddr, netstack,
    proxy::{
        BridgedStreams, DEFAULT_PROXY_BUF_SIZE, ProxyHandler, ProxyServer, stream::ProxyStream,
    },
};

pub async fn tcp_connect_stream_builder(
    device: &Device,
    _remote_addr: SocketAddr,
    target_addr: SocketAddr,
) -> Result<Box<dyn ProxyStream<Addr = SocketAddr>>, Error> {
    let stream: Box<dyn ProxyStream<Addr = SocketAddr>> = if target_addr.is_tailnet_addr() {
        Box::new(device.tcp_connect(target_addr).await?)
    } else {
        Box::new(
            tokio::net::TcpStream::connect(target_addr)
                .await
                .map_err(|_| Error::ConnectionRefused)?,
        )
    };
    Ok(stream)
}

pub struct TcpReverseProxy {
    server: TcpProxy,
}

// TODO(dylan): refer to safe alternatives
// TODO(dylan): add example section
/// A low-level primitive for building TCP proxies. Bridges incoming TCP connections (called
/// _remote_ streams) to _target_ streams, copying data bidirectionally between each
/// `(remote, target)` pair of streams.
///
/// On accept, each remote stream is paired with a newly-constructed target stream; in other words,
/// this doesn't perform any (de-)multiplexing of remote stream data to/from a single target stream.
/// Different target stream implementations can be provided per-connection. Anything that implements
/// `TargetStream` can be a target - TCP/UDP endpoints (localhost, tailnet, or public internet),
/// Unix sockets, files, etc.
///
/// # Warning
/// Data sent/received over the _remote_ streams is encrypted, but data sent/received over the
/// _target_ streams *may be sent in plaintext*; it depends on the implementation of `TargetStream`
/// in use. For example, if the target stream is a [`netstack::TcpStream`] or
/// [`netstack::UdpSocket`], then the target stream will be encrypted; however, a
/// [`tokio::net::TcpStream`] target stream will send and receive unencrypted data. **It is your
/// responsibility to choose a `TargetStream` implementation that satisfies your threat model and
/// security requirements.**
pub struct TcpProxy {
    tasks: TaskTracker,
    cancel_token: CancellationToken,
}

impl ProxyServer for TcpProxy {
    type Handler = TcpProxyHandler;

    async fn start(
        device: &Device,
        listen_addr: <Self::Handler as ProxyHandler>::RemoteAddr,
        target_addr: <Self::Handler as ProxyHandler>::TargetAddr,
        cancel_token: Option<CancellationToken>,
    ) -> Result<Self, Error> {
        tracing::debug!("listening for incoming TCP connections to proxy");
        let tasks = TaskTracker::new();
        let cancel_token = cancel_token.unwrap_or_default();
        let task_token = cancel_token.clone();
        let handler = TcpProxyHandler {
            device: device.clone(),
            listener: device.tcp_listen(listen_addr).await?,
            remote_buf_len: DEFAULT_PROXY_BUF_SIZE,
            target_buf_len: DEFAULT_PROXY_BUF_SIZE,
            tasks: tasks.clone(),
        };

        tasks.spawn(async move {
            loop {
                tokio::select! {
                    _ = task_token.cancelled() => {
                        tracing::debug!("proxy task cancelled");
                        break;
                    }
                    res = handler.handle_one(target_addr, tcp_connect_stream_builder) => {
                        match res {
                            Ok(_) => {
                                tracing::info!("proxying connections");
                            }
                            Err(err) => {
                                tracing::error!(%err, "error proxying connections");
                            }
                        }
                    }
                }
            }
        });

        Ok(Self {
            tasks,
            cancel_token,
        })
    }

    async fn stop(self) -> Result<(), Error> {
        self.tasks.close();
        self.cancel_token.cancel();
        self.tasks.wait().await;
        tracing::info!("proxy task stopped");
        Ok(())
    }
}

impl ProxyStream for netstack::TcpStream {
    type Addr = SocketAddr;
}

impl ProxyStream for tokio::net::TcpStream {
    type Addr = SocketAddr;
}

pub struct TcpProxyHandler {
    device: Device,
    listener: netstack::TcpListener,
    remote_buf_len: usize,
    target_buf_len: usize,
    tasks: TaskTracker,
}

impl ProxyHandler for TcpProxyHandler {
    type RemoteAddr = SocketAddr;
    type RemoteStream = netstack::TcpStream;
    type TargetAddr = SocketAddr;
    type TargetStream = tokio::net::TcpStream;

    async fn handle_one(
        &self,
        target_addr: Self::TargetAddr,
        target_builder: impl AsyncFn(
            &Device,
            Self::RemoteAddr,
            Self::TargetAddr,
        )
            -> Result<Box<dyn ProxyStream<Addr = Self::TargetAddr>>, Error>,
    ) -> Result<BridgedStreams, Error> {
        tracing::debug!("listening for incoming connections to proxy");
        let remote_stream = self.listener.accept().await?;
        let remote = remote_stream.remote_addr();
        tracing::debug!(%remote, "accepted");

        let Self {
            remote_buf_len,
            target_buf_len,
            ..
        } = *self;

        let remote_addr = remote_stream.remote_addr();
        let target_stream = target_builder(&self.device, remote_addr, target_addr).await?;
        tracing::debug!("connected to proxy target");

        let bridge = BridgedStreams::start(
            remote_stream,
            target_stream,
            remote_buf_len,
            target_buf_len,
            &self.tasks,
        )
        .await?;

        Ok(bridge)
    }
}
