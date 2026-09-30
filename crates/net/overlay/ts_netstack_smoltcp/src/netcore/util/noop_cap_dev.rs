use smoltcp::{
    phy::{DeviceCapabilities, Medium},
    time::Instant,
};

/// [`smoltcp::iface::Interface::new`] does not store the dev on the interface, it just
/// queries and stores its capabilities, which most relevantly include MTU, "medium" (frame
/// type), and checksum behavior. This type is a hack to enable us to "rewrite" this
/// constructor signature to just take the expected [`DeviceCapabilities`] directly, which
/// lets us avoid supplying the net device at netstack construction, as it's not actually
/// necessary at that point.
pub struct NoopCapDev {
    pub device_capabilities: DeviceCapabilities,
}

impl NoopCapDev {
    /// Default caps for this crate's expected operation (layer 3).
    pub fn default_caps() -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ip;
        caps.max_transmission_unit = 1500;

        caps
    }

    /// Construct a [`NoopCapDev`] with the given modifications to its
    /// [`DeviceCapabilities`].
    pub fn with_caps(f: impl FnOnce(&mut DeviceCapabilities)) -> Self {
        let mut caps = Self::default_caps();
        f(&mut caps);

        Self {
            device_capabilities: caps,
        }
    }
}

impl Default for NoopCapDev {
    fn default() -> Self {
        Self::with_caps(|_| {})
    }
}

impl smoltcp::phy::Device for NoopCapDev {
    type RxToken<'a>
        = NoopCapDev
    where
        Self: 'a;

    type TxToken<'a>
        = NoopCapDev
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: Instant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        None
    }

    fn transmit(&mut self, _timestamp: Instant) -> Option<Self::TxToken<'_>> {
        None
    }

    fn capabilities(&self) -> DeviceCapabilities {
        self.device_capabilities.clone()
    }
}

impl smoltcp::phy::RxToken for NoopCapDev {
    fn consume<R, F>(self, _f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        unreachable!("using noop dummy device for rx")
    }
}

impl smoltcp::phy::TxToken for NoopCapDev {
    fn consume<R, F>(self, _len: usize, _f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        unreachable!("using noop dummy device for tx")
    }
}
