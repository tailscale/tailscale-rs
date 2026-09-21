use core::{
    pin::Pin,
    task::{Context, Poll},
};

/// Indicates when a [`smoltcp::phy::Device`] may have new data available.
///
/// The point of this is to bolt a `poll` mechanism onto [`smoltcp::phy::Device`], as it
/// internally lacks any awareness of an external event loop.
pub trait AsyncWakeDevice {
    /// Poll the device to make progress on [`smoltcp::phy::Device::receive`].
    ///
    /// Must only return [`Poll::Ready`] when it's possible to call `receive` and get a
    /// token. Callers may assume they can call `.unwrap()` without panicking in this case.
    ///
    /// This implies that _both_ `RxToken` and `TxToken` are available (i.e.
    /// [`AsyncWakeDevice::poll_tx`] would return `Poll::Ready` as well), since `receive`
    /// needs to return both tokens.
    fn poll_rx(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()>;

    /// Poll the device to make progress on [`smoltcp::phy::Device::transmit`].
    ///
    /// Must only return [`Poll::Ready`] when it's possible to call `transmit` and get a
    /// token. Callers may assume that they can call `.unwrap()` without panicking in this
    /// case.
    fn poll_tx(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()>;
}
