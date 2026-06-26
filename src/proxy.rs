//! Functions and utilities for proxying bytes between TCP streams.

use core::{
    fmt::{self, Display},
    net::SocketAddr,
};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::task::JoinHandle;
use ts_netstack_smoltcp::{CreateSocket, netcore::Channel};

use crate::{Error, InternalErrorKind, TailnetAddr, netstack};

/// Size (in bytes) of each buffer used to proxy data between two TCP streams. Each proxy uses two
/// buffers of this size.
pub const DEFAULT_PROXY_BUF_SIZE: usize = 8 * 1024;

// TODO (dylan): add doc comment
#[allow(dead_code)]
pub struct TcpProxyMetrics {
    /// Number of bytes sent by the remote stream that were proxied to the target stream.
    bytes_remote_to_target: u64,
    /// Number of bytes sent by the target stream that were proxied to the remote stream.
    bytes_target_to_remote: u64,
}

impl TcpProxyMetrics {
    // TODO (dylan): add doc comment
    pub fn new(bytes_remote_to_target: u64, bytes_target_to_remote: u64) -> Self {
        Self {
            bytes_remote_to_target,
            bytes_target_to_remote,
        }
    }
}

// TODO (dylan): add doc comment
#[allow(missing_docs)]
pub struct TcpProxy {
    channel: Channel,
    listener: netstack::TcpListener,
    remote_buf_len: usize,
    target_buf_len: usize,
}

#[allow(missing_docs)]
impl TcpProxy {
    // TODO (dylan): add doc comment
    pub fn new(
        channel: Channel,
        listener: netstack::TcpListener,
        remote_buf_len: Option<usize>,
        target_buf_len: Option<usize>,
    ) -> Self {
        Self {
            channel,
            listener,
            remote_buf_len: remote_buf_len.unwrap_or(DEFAULT_PROXY_BUF_SIZE),
            target_buf_len: target_buf_len.unwrap_or(DEFAULT_PROXY_BUF_SIZE),
        }
    }

    pub async fn accept_one(
        &self,
        mut builder: impl AsyncFnMut() -> Result<Box<dyn TargetStream>, Error>,
    ) -> Result<BridgedStreams, Error> {
        tracing::debug!("listening for incoming connections to proxy");
        let mut remote = self.listener.accept().await?;
        let remote_addr = remote.remote_addr();
        let proxy_addr = remote.local_addr();
        let span = tracing::debug_span!(
            "connect_to_target",
            remote_conn = %remote,
            target_conn = tracing::field::Empty,
        )
        .entered();
        tracing::debug!("accepted");

        let Self {
            remote_buf_len,
            target_buf_len,
            ..
        } = *self;

        let mut target_stream = builder().await?;
        let local_addr = target_stream.local_addr()?;
        let target_addr = target_stream.remote_addr()?;
        span.record(
            "target_conn",
            tracing::field::debug(format!("{}<->{}", local_addr, target_addr)),
        );
        tracing::debug!("connected to proxy target");

        let task = tokio::task::spawn(async move {
            tracing::debug!(%remote_addr, %proxy_addr, %target_addr, "proxying between remote/target");

            let (bytes_remote_to_target, bytes_target_to_remote) =
                tokio::io::copy_bidirectional_with_sizes(
                    &mut remote,
                    &mut target_stream,
                    remote_buf_len,
                    target_buf_len,
                )
                .await
                // TODO (dylan): better error handling
                .map_err(|_| Error::Internal(InternalErrorKind::InternalResponseMismatch))?;

            Ok(TcpProxyMetrics::new(
                bytes_remote_to_target,
                bytes_target_to_remote,
            ))
        });

        Ok(BridgedStreams {
            remote_conn: (remote_addr, proxy_addr),
            target_conn: (local_addr, target_addr),
            task,
        })
    }

    #[tracing::instrument(skip_all, fields(listen_addr=%self.listener.local_addr()), level = "debug")]
    pub async fn accept(&self, target_addr: SocketAddr) -> Result<BridgedStreams, Error> {
        // TODO(dylan): collision checking
        let ephemeral_port = rand::random_range(49152..=u16::MAX);
        let local = (self.listener.local_addr().ip(), ephemeral_port).into();
        self.accept_one(async || {
            let target_stream: Box<dyn TargetStream> = if target_addr.is_tailnet_addr() {
                Box::new(self.channel.tcp_connect(local, target_addr).await?)
            } else {
                Box::new(
                    tokio::net::TcpStream::connect(target_addr)
                        .await
                        .map_err(|_| crate::Error::ConnectionRefused)?,
                )
            };

            Ok(target_stream)
        })
        .await
    }
}

/// An established TCP stream that can be the target stream in a TCP proxy setup. This could be a
/// stream with a tailnet peer, a port on localhost, or an arbitrary public or private remote.
pub trait TargetStream: AsyncRead + AsyncWrite + Unpin + Send {
    /// The local endpoint to which this stream is connected.
    #[allow(dead_code)]
    fn local_addr(&self) -> Result<SocketAddr, Error>;

    /// The remote/peer endpoint to which this stream is connected.
    fn remote_addr(&self) -> Result<SocketAddr, Error>;
}

impl TargetStream for netstack::TcpStream {
    fn local_addr(&self) -> Result<SocketAddr, Error> {
        Ok(self.local_addr())
    }

    fn remote_addr(&self) -> Result<SocketAddr, Error> {
        Ok(self.remote_addr())
    }
}

impl TargetStream for tokio::net::TcpStream {
    fn local_addr(&self) -> Result<SocketAddr, Error> {
        self.local_addr()
            .map_err(|_| Error::Internal(InternalErrorKind::InvalidSocketState))
    }

    fn remote_addr(&self) -> Result<SocketAddr, Error> {
        self.peer_addr()
            .map_err(|_| Error::Internal(InternalErrorKind::InvalidSocketState))
    }
}

impl TargetStream for Box<dyn TargetStream> {
    fn local_addr(&self) -> Result<SocketAddr, Error> {
        self.as_ref().local_addr()
    }

    fn remote_addr(&self) -> Result<SocketAddr, Error> {
        self.as_ref().remote_addr()
    }
}

pub struct BridgedStreams {
    remote_conn: (SocketAddr, SocketAddr),
    target_conn: (SocketAddr, SocketAddr),
    #[allow(dead_code)]
    task: JoinHandle<Result<TcpProxyMetrics, Error>>,
}

impl BridgedStreams {
    pub fn remote_conn(&self) -> (SocketAddr, SocketAddr) {
        self.remote_conn
    }

    pub fn target_conn(&self) -> (SocketAddr, SocketAddr) {
        self.target_conn
    }
}

impl Display for BridgedStreams {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "tcp({}<->{}<->{}<->{})",
            self.remote_conn.0, self.remote_conn.1, self.target_conn.0, self.target_conn.1
        )
    }
}
