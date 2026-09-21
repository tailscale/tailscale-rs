use bytes::{Bytes, BytesMut};
use smoltcp::{
    phy::{ChecksumCapabilities, DeviceCapabilities, Medium},
    time::Instant,
};

/// Dumb bidirectional pipe carrying [`Bytes`] (comes in pairs).
///
/// Used in [`PipeDev`] to provide a simple [`smoltcp::phy::Device`] implementation.
///
/// # Example
///
/// ```rust
/// # use ts_netstack_smoltcp_core::Pipe;
/// # use bytes::Bytes;
///
/// let (p1, p2) = Pipe::unbounded();
///
/// // Send on one channel
/// p1.tx.try_send(Bytes::copy_from_slice(b"hello"));
///
/// // Receive on the other
/// assert_eq!(p2.rx.recv().unwrap().as_ref(), b"hello");
/// ```
pub struct Pipe {
    /// Sender to be received by the remote end of the pipe.
    pub tx: flume::Sender<Bytes>,
    /// Receiver for messages from the remote end of the pipe.
    pub rx: flume::Receiver<Bytes>,
}

impl Pipe {
    /// Construct a pipe with unbounded capacity.
    pub fn unbounded() -> (Pipe, Pipe) {
        let (tx1, rx1) = flume::unbounded();
        let (tx2, rx2) = flume::unbounded();

        (Pipe { tx: tx1, rx: rx2 }, Pipe { tx: tx2, rx: rx1 })
    }

    /// Construct a new pipe that can contain at most `limit` packets.
    pub fn bounded(limit: usize) -> (Pipe, Pipe) {
        let (tx1, rx1) = flume::bounded(limit);
        let (tx2, rx2) = flume::bounded(limit);

        (Pipe { tx: tx1, rx: rx2 }, Pipe { tx: tx2, rx: rx1 })
    }
}

pub struct TxToken(flume::Sender<Bytes>);

impl smoltcp::phy::TxToken for TxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut b = BytesMut::zeroed(len);

        let ret = f(&mut b);
        if self.0.send(b.freeze()).is_err() {
            tracing::warn!("remote end of dropped on send");
        }

        ret
    }
}

pub struct RxToken(Bytes);

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

/// Wrapper around [`Pipe`] to implement [`smoltcp::phy::Device`].
pub struct PipeDev {
    /// End of a pipe that will be directly connected to the netstack, receiving packets
    /// to be sent and supplying packets to be received.
    pub pipe: Pipe,

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

impl smoltcp::phy::Device for PipeDev {
    type RxToken<'a>
        = RxToken
    where
        Self: 'a;

    type TxToken<'a>
        = TxToken
    where
        Self: 'a;

    fn receive(&mut self, timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let tx = self.transmit(timestamp)?;
        let b = self.pipe.rx.try_recv().ok()?;

        Some((RxToken(b), tx))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        let sender = (!self.pipe.tx.is_disconnected()).then(|| self.pipe.tx.clone())?;

        Some(TxToken(sender))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();

        caps.max_transmission_unit = self.mtu;
        caps.medium = self.medium;
        caps.checksum = ChecksumCapabilities::ignored();

        caps
    }
}
