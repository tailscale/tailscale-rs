use alloc::sync::Arc;
use core::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::{Bytes, BytesMut};
use futures_util::task::AtomicWaker;
use netcore::{
    Pipe, flume, smoltcp,
    smoltcp::{
        phy::{ChecksumCapabilities, DeviceCapabilities, Medium},
        time::Instant,
    },
};

/// Bidirectional pipe carrying byte buffer payloads.
///
/// This is like [`netcore::Pipe`], except that it also implements
/// [`AsyncWakeDevice`][netcore::AsyncWakeDevice], which needs a bit of fiddling to adapt.
pub struct WakingPipe {
    /// The send side of the pipe.
    pub rx: WakingPipeReceiver,
    /// The transmit side of the pipe.
    pub tx: WakingPipeSender,
}

/// A [`flume::Receiver`] wrapped to support [`AsyncWakeDevice`][netcore::AsyncWakeDevice].
///
/// It wakes the remote [`WakingPipeSender`] when a message is received.
pub struct WakingPipeReceiver {
    rx: flume::Receiver<Bytes>,
    /// [`flume::Receiver`] doesn't expose a way to poll until a value is ready without
    /// consuming it. This holds the consumed value.
    buffered_rx: Option<Bytes>,

    /// The waker that this end of the pipe polls on in `poll_rx`.
    ///
    /// It is woken by the remote (tx) end of the pipe when a packet is sent, i.e. the
    /// readiness state of `poll_rx` changes.
    self_waker: Arc<AtomicWaker>,

    /// The waker for the remote (tx) end of the pipe.
    ///
    /// We wake this when we receive a packet (i.e. make room in the pipe). That only
    /// matters if `rx` is a bounded channel.
    remote_waker: Arc<AtomicWaker>,
}

/// A [`flume::Sender`] that wakes a remote [`WakingPipeReceiver`] when a message is sent.
#[derive(Clone)]
pub struct WakingPipeSender {
    tx: flume::Sender<Bytes>,

    /// The waker this end of the pipe polls on in `poll_tx`.
    ///
    /// It is woken by the remote (rx) end of the pipe when a packet is received, i.e. the
    /// readiness state of `poll_tx` changes.
    ///
    /// This only matters if `self.tx` is a bounded channel, otherwise in the unbounded case
    /// we're always ready to send.
    self_waker: Arc<AtomicWaker>,

    /// The waker for the remote (rx) end of the pipe.
    ///
    /// We wake this when we send a packet.
    remote_waker: Arc<AtomicWaker>,
}

impl WakingPipe {
    /// Construct a new pipe with the given optional capacity `limit`.
    pub fn new(limit: Option<usize>) -> (Self, Self) {
        if let Some(limit) = limit {
            Self::bounded(limit)
        } else {
            Self::unbounded()
        }
    }

    /// Construct a new unbounded pipe.
    pub fn unbounded() -> (Self, Self) {
        let (pipe1, pipe2) = Pipe::unbounded();

        Self::_new(pipe1, pipe2)
    }

    /// Construct a new pipe that can carry at most `limit` packets.
    pub fn bounded(limit: usize) -> (Self, Self) {
        let (pipe1, pipe2) = Pipe::bounded(limit);

        Self::_new(pipe1, pipe2)
    }

    fn _new(pipe1: Pipe, pipe2: Pipe) -> (Self, Self) {
        let pipe1_rx_waker = Arc::new(AtomicWaker::new());
        let pipe2_rx_waker = Arc::new(AtomicWaker::new());

        let pipe1_tx_waker = Arc::new(AtomicWaker::new());
        let pipe2_tx_waker = Arc::new(AtomicWaker::new());

        (
            Self {
                rx: WakingPipeReceiver {
                    rx: pipe1.rx,
                    buffered_rx: None,
                    self_waker: pipe1_rx_waker.clone(),
                    remote_waker: pipe2_tx_waker.clone(),
                },
                tx: WakingPipeSender {
                    tx: pipe1.tx,
                    remote_waker: pipe2_rx_waker.clone(),
                    self_waker: pipe1_tx_waker.clone(),
                },
            },
            Self {
                rx: WakingPipeReceiver {
                    rx: pipe2.rx,
                    buffered_rx: None,
                    self_waker: pipe2_rx_waker,
                    remote_waker: pipe1_tx_waker,
                },
                tx: WakingPipeSender {
                    tx: pipe2.tx,
                    remote_waker: pipe1_rx_waker,
                    self_waker: pipe2_tx_waker,
                },
            },
        )
    }
}

impl WakingPipeReceiver {
    /// Receive a packet.
    pub fn recv(&mut self) -> Option<Bytes> {
        if let Some(buf) = self.buffered_rx.take() {
            return Some(buf);
        }

        let ret = self.rx.recv().ok();
        self.remote_waker.wake();

        ret
    }

    /// Receive a packet asynchronously.
    pub async fn recv_async(&mut self) -> Option<Bytes> {
        if let Some(buf) = self.buffered_rx.take() {
            return Some(buf);
        }

        let ret = self.rx.recv_async().await.ok();
        self.remote_waker.wake();

        ret
    }

    /// Receive a packet if it's possible to do so without blocking.
    pub fn try_recv(&mut self) -> Option<Bytes> {
        if let Some(buf) = self.buffered_rx.take() {
            return Some(buf);
        }

        let ret = self.rx.recv().ok();
        self.remote_waker.wake();

        ret
    }

    /// Report whether there is a packet ready to be received.
    pub fn rx_ready(&self) -> bool {
        self.buffered_rx.is_some() || !self.rx.is_empty()
    }
}

impl WakingPipeSender {
    /// Send a packet, blocking until complete.
    pub fn send(&self, buf: &[u8]) {
        if let Err(_e) = self.tx.send(Bytes::copy_from_slice(buf)) {
            tracing::warn!("send dropped: remote end of pipe is gone");
            return;
        }

        self.remote_waker.wake();
    }

    /// Send a packet asynchronously.
    pub async fn send_async(&self, buf: &[u8]) {
        if let Err(_e) = self.tx.send_async(Bytes::copy_from_slice(buf)).await {
            tracing::warn!("send dropped: remote end of pipe is gone");
            return;
        }

        self.remote_waker.wake();
    }

    /// Send a packet if it's possible to do so without blocking.
    ///
    /// Returns whether the packet was actually sent.
    pub fn try_send(&self, buf: &[u8]) -> bool {
        match self.tx.try_send(Bytes::copy_from_slice(buf)) {
            Ok(()) => {
                self.remote_waker.wake();
                true
            }
            Err(flume::TrySendError::Full(..)) => false,
            Err(flume::TrySendError::Disconnected(..)) => {
                tracing::warn!("send dropped: remote end of pipe is gone");

                // Semantically, that the remote end was dropped can be thought of as deciding to
                // ignore all of our messages
                true
            }
        }
    }

    /// Report whether we can currently transmit.
    pub fn tx_ready(&self) -> bool {
        !self.tx.is_full()
    }
}

impl netcore::AsyncWakeDevice for WakingPipeDev {
    #[tracing::instrument(name = "WakingPipeDev::poll_tx", skip_all, level = "trace", ret)]
    fn poll_tx<'cx>(self: Pin<&mut Self>, cx: &mut Context<'cx>) -> Poll<()> {
        self.pipe.tx.self_waker.register(cx.waker());

        if self.pipe.tx.tx_ready() {
            return Poll::Ready(());
        }

        Poll::Pending
    }

    #[tracing::instrument(name = "WakingPipeDev::poll_rx", skip_all, level = "trace", ret)]
    fn poll_rx<'cx>(mut self: Pin<&mut Self>, cx: &mut Context<'cx>) -> Poll<()> {
        self.pipe.rx.self_waker.register(cx.waker());

        if self.pipe.rx.rx_ready() {
            // Check tx readiness so that we return Poll::Ready when Device::receive is actually
            // ready, which only occurs when both TxToken and RxToken can be constructed.
            core::task::ready!(self.as_mut().poll_tx(cx));

            return Poll::Ready(());
        }

        Poll::Pending
    }
}

impl smoltcp::phy::TxToken for WakingPipeSender {
    #[tracing::instrument(
        name = "WakingPipeSender::consume",
        skip_all,
        fields(len),
        level = "trace"
    )]
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut b = BytesMut::zeroed(len);

        let ret = f(&mut b);
        if self.tx.send(b.freeze()).is_err() {
            tracing::warn!("remote end of dropped on send");
        }

        self.remote_waker.wake();

        ret
    }
}

pub struct RxToken(Bytes);

impl smoltcp::phy::RxToken for RxToken {
    #[tracing::instrument(name = "WakingPipeRx::consume", skip_all, level = "trace")]
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

/// Wrapper around [`WakingPipe`] to implement [`smoltcp::phy::Device`].
///
/// Like [`netcore::PipeDev`] except that it implements
/// [`AsyncWakeDevice`][netcore::AsyncWakeDevice].
pub struct WakingPipeDev {
    /// End of a pipe that will be directly connected to the netstack, receiving packets
    /// to be sent and supplying packets to be received.
    pub pipe: WakingPipe,

    /// The type of network frame the pipe will carry.
    ///
    /// For our purposes, this will typically be [`Medium::Ip`].
    pub medium: Medium,
    /// The maximum packet size to be transmitted through the pipe.
    ///
    /// The implementation does not check or limit the actual size of packets flowing
    /// through it, this field is just informational for
    /// [`smoltcp::phy::Device::capabilities`].
    pub mtu: usize,
}

impl smoltcp::phy::Device for WakingPipeDev {
    type RxToken<'a>
        = RxToken
    where
        Self: 'a;

    type TxToken<'a>
        = WakingPipeSender
    where
        Self: 'a;

    #[tracing::instrument(skip(self), level = "trace")]
    fn receive(&mut self, timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let tx = self.transmit(timestamp)?;

        let b = if let Some(buf) = self.pipe.rx.buffered_rx.take() {
            buf
        } else {
            self.pipe.rx.rx.try_recv().ok()?
        };

        Some((RxToken(b), tx))
    }

    #[tracing::instrument(skip(self), level = "trace")]
    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        if self.pipe.tx.tx.is_disconnected() {
            return None;
        }

        Some(self.pipe.tx.clone())
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();

        caps.max_transmission_unit = self.mtu;
        caps.medium = self.medium;
        caps.checksum = ChecksumCapabilities::ignored();

        caps
    }
}
