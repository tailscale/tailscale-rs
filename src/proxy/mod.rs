//! Proxy server implementations for common use cases, plus low-level primitives for implementing
//! proxies.
#![allow(dead_code, missing_docs)]

use tokio_util::{sync::CancellationToken, task::TaskTracker};

use crate::{Device, Error, InternalErrorKind};

pub mod stream;
pub use stream::ProxyStream;
pub mod tcp;
pub use tcp::TcpReverseProxy;

/// Size (in bytes) of each buffer used to proxy data between two streams. Each `StreamBridge` uses
/// two buffers of this size, one for each direction.
pub const DEFAULT_PROXY_BUF_SIZE: usize = 8 * 1024;

pub trait ProxyServer: Sized {
    type Handler: ProxyHandler;

    fn start(
        device: &Device,
        listen_addr: <Self::Handler as ProxyHandler>::RemoteAddr,
        target_addr: <Self::Handler as ProxyHandler>::TargetAddr,
        cancel_token: Option<CancellationToken>,
    ) -> impl Future<Output = Result<Self, Error>>;

    fn stop(self) -> impl Future<Output = Result<(), Error>>;
}

pub trait ProxyHandler {
    type RemoteAddr;
    type RemoteStream: ProxyStream;
    type TargetAddr;
    type TargetStream: ProxyStream;

    /// Accept an incoming connection as a remote stream, connect to a target stream, and copy data
    /// bidirectionally between the two streams.
    fn handle_one(
        &self,
        target_addr: Self::TargetAddr,
        target_builder: impl AsyncFn(
            &Device,
            Self::RemoteAddr,
            Self::TargetAddr,
        )
            -> Result<Box<dyn ProxyStream<Addr = Self::TargetAddr>>, Error>,
    ) -> impl Future<Output = Result<BridgedStreams, Error>>;
}

pub struct BridgedStreams {}

impl BridgedStreams {
    pub async fn start(
        mut remote: impl ProxyStream + 'static,
        mut target: impl ProxyStream + 'static,
        remote_buf_len: usize,
        target_buf_len: usize,
        tasks: &TaskTracker,
    ) -> Result<Self, Error> {
        tasks.spawn(async move {
            tracing::debug!("proxying between remote/target");

            let (bytes_remote_to_target, bytes_target_to_remote) =
                tokio::io::copy_bidirectional_with_sizes(
                    &mut remote,
                    &mut target,
                    remote_buf_len,
                    target_buf_len,
                )
                .await
                // TODO (dylan): better error handling
                .map_err(|_| Error::Internal(InternalErrorKind::InternalResponseMismatch))?;

            Ok::<(u64, u64), Error>((bytes_remote_to_target, bytes_target_to_remote))
        });

        Ok(Self {})
    }
}
