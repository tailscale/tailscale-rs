use alloc::sync::Arc;
use core::{
    pin::Pin,
    task::{Context, Poll},
};

use bytes::BytesMut;
use netcore::{
    smoltcp,
    smoltcp::{phy::DeviceCapabilities, time::Instant},
};

/// TUN device implementing [`smoltcp::phy::Device`], wrapping [`tun_rs`].
pub struct TunRsDevice {
    tun: Arc<tun_rs::SyncDevice>,
    mtu: u16,
}

/// TUN device implementing [`smoltcp::phy::Device`], wrapping [`tun_rs`].
pub struct TunRsDeviceAsync {
    tun: Arc<tun_rs::AsyncDevice>,
    mtu: u16,
}

impl TunRsDevice {
    /// Construct a new tun device with the given `mtu`.
    pub fn new(mtu: u16) -> Result<TunRsDevice, std::io::Error> {
        let dev = tun_rs::DeviceBuilder::new().mtu(mtu as _).build_sync()?;

        #[cfg(unix)]
        dev.set_nonblocking(true)?;

        Ok(TunRsDevice {
            tun: Arc::new(dev),
            mtu,
        })
    }

    /// Get a reference to the inner device.
    pub fn inner(&self) -> &tun_rs::SyncDevice {
        &self.tun
    }
}

impl From<tun_rs::SyncDevice> for TunRsDevice {
    fn from(value: tun_rs::SyncDevice) -> Self {
        let mtu = value.mtu().unwrap();

        Self {
            tun: Arc::new(value),
            mtu,
        }
    }
}

impl TunRsDeviceAsync {
    /// Construct a new tun device with the given `mtu`.
    pub fn new(mtu: u16) -> Result<TunRsDeviceAsync, std::io::Error> {
        let dev = tun_rs::DeviceBuilder::new().mtu(mtu as _).build_async()?;

        Ok(TunRsDeviceAsync {
            tun: Arc::new(dev),
            mtu,
        })
    }

    /// Get a reference to the inner device.
    pub fn inner(&self) -> &tun_rs::AsyncDevice {
        &self.tun
    }
}

impl From<tun_rs::AsyncDevice> for TunRsDeviceAsync {
    fn from(value: tun_rs::AsyncDevice) -> Self {
        let mtu = value.mtu().unwrap();

        Self {
            tun: Arc::new(value),
            mtu,
        }
    }
}

impl netcore::AsyncWakeDevice for TunRsDeviceAsync {
    fn poll_rx<'cx>(self: Pin<&mut Self>, cx: &mut Context<'cx>) -> Poll<()> {
        let fut = self.tun.readable();
        let fut = core::pin::pin![fut];

        fut.poll(cx).map(|_| ())
    }

    fn poll_tx<'cx>(self: Pin<&mut Self>, _cx: &mut Context<'cx>) -> Poll<()> {
        // tun is always ready to accept packets
        Poll::Ready(())
    }
}

impl smoltcp::phy::Device for TunRsDevice {
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

        let mut buf = BytesMut::zeroed(self.mtu as _);

        // don't block
        #[cfg(windows)]
        let n = self.tun.try_recv(&mut buf).ok()?;
        #[cfg(unix)]
        let n = self.tun.recv(&mut buf).ok()?;

        buf.truncate(n);

        Some((RxToken(buf.freeze()), tx))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxToken(self.tun.clone()))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.mtu as _;

        caps
    }
}

impl smoltcp::phy::Device for TunRsDeviceAsync {
    type RxToken<'a>
        = RxToken
    where
        Self: 'a;

    type TxToken<'a>
        = TxTokenAsync
    where
        Self: 'a;

    fn receive(&mut self, timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let tx = self.transmit(timestamp)?;

        let mut buf = BytesMut::zeroed(self.mtu as _);

        let n = self.tun.try_recv(&mut buf).ok()?;
        buf.truncate(n);

        Some((RxToken(buf.freeze()), tx))
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        Some(TxTokenAsync(self.tun.clone()))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.max_transmission_unit = self.mtu as _;

        caps
    }
}

pub struct RxToken(bytes::Bytes);

impl smoltcp::phy::RxToken for RxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

pub struct TxToken(Arc<tun_rs::SyncDevice>);

impl smoltcp::phy::TxToken for TxToken {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut b = BytesMut::zeroed(len);
        let ret = f(&mut b);

        if let Err(e) = self.0.send(&b) {
            tracing::error!(error = %e, "writing to tun");
        }

        ret
    }
}

pub struct TxTokenAsync(Arc<tun_rs::AsyncDevice>);

impl smoltcp::phy::TxToken for TxTokenAsync {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut b = BytesMut::zeroed(len);
        let ret = f(&mut b);

        if let Err(e) = self.0.try_send(&b) {
            tracing::error!(error = %e, "writing to tun");
        }

        ret
    }
}
