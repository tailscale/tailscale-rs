//! [`Stream`] impls wrapping win32 [`IpHelper`] notify methods.

use core::{
    pin::Pin,
    task::{Context, Poll},
};

use futures_util::Stream;
use windows::Win32::{Foundation, NetworkManagement::IpHelper};

use crate::family::FamilyOrBoth;

macro_rules! notify_stream {
    ($name:ident, $msg:ident, $f:ident, $rowty:ty) => {
        notify_stream!($name, $msg, $f, $rowty, |x| x);
    };

    ($name:ident, $msg:ident, $f:ident, $rowty:ty, $helper:expr) => {
        #[doc = concat!("Type of event produced by [`", stringify!($name), "`].")]
        pub type $msg = (IpHelper::MIB_NOTIFICATION_TYPE, $rowty);

        pin_project_lite::pin_project! {
            #[doc = concat!("Implements [`Stream`] for events produced by [`IpHelper::", stringify!($f), "`].")]
            pub struct $name {
                #[pin]
                rx: flume::r#async::RecvStream<'static, $msg>,
                handle: DropHandle,
                // SAFETY: _tx must appear after handle, because handle bounds the lifetime of a
                // raw pointer to _tx that is handed to the OS. When dropping the struct,
                // DropHandle must die first to cancel the notification, before the pointed-to Box
                // is dropped.
                _tx: Box<flume::Sender<$msg >>,
            }
        }

        impl $name {
            /// Construct a new notify stream gathering events for `family`.
            pub fn new(family: FamilyOrBoth) -> windows::core::Result<Self> {
                let mut handle: Foundation::HANDLE = Foundation::HANDLE::default();
                let (tx, rx) = flume::unbounded();
                let tx = Box::new(tx);

                extern "system" fn notify(
                    ctx: *const core::ffi::c_void,
                    row: *const $rowty,
                    ty: IpHelper::MIB_NOTIFICATION_TYPE,
                ) {
                    let ctx = ctx as *const flume::Sender<$msg>;

                    // SAFETY: kernel hands us this pointer, should be ref-convertible.
                    let Some(sender) = (unsafe { ctx.as_ref() }) else {
                        return;
                    };

                    // SAFETY: kernel hands us this pointer, should be ref-convertible.
                    let Some(row) = (unsafe { row.as_ref() }) else {
                        return;
                    };

                    let _err = sender.send((ty, *row));
                }

                // SAFETY: correct usage per MS docs.
                unsafe {
                    IpHelper::$f(
                        family.into(),
                        Some(notify),
                        ($helper)(tx.as_ref() as *const _ as *const _),
                        true,
                        &mut handle as *mut _,
                    )
                }
                .ok()?;

                Ok(Self {
                    rx: rx.into_stream(),
                    _tx: tx,
                    handle: DropHandle { handle },
                })
            }
        }

        impl Stream for $name {
            type Item = $msg;

            fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
                self.project().rx.poll_next(cx)
            }
        }
    };
}

notify_stream!(
    RouteStream,
    RouteChange,
    NotifyRouteChange2,
    IpHelper::MIB_IPFORWARD_ROW2
);

notify_stream!(
    UnicastIpStream,
    UnicastIpChange,
    NotifyUnicastIpAddressChange,
    IpHelper::MIB_UNICASTIPADDRESS_ROW,
    Some
);

notify_stream!(
    LinkStream,
    LinkChange,
    NotifyIpInterfaceChange,
    IpHelper::MIB_IPINTERFACE_ROW,
    Some
);

struct DropHandle {
    handle: Foundation::HANDLE,
}

unsafe impl Send for DropHandle {}

impl Drop for DropHandle {
    fn drop(&mut self) {
        // SAFETY: handle is only constructed if the Notify* call succeeded, so it
        // should be valid.
        let _err = unsafe { IpHelper::CancelMibChangeNotify2(self.handle) };
    }
}
