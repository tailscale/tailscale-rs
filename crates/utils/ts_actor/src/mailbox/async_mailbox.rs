//! SPSC async channels wrapping a [`Mailbox`].

// TODO(npry): recv_where performance is expected to be pretty bad: it scans the whole
//  mailbox every time it's polled (~every time the sender sends a message), while in
//  principle it could track the messages it has seen and only look at new ones as they
//  arrive. We're leaning rather heavily on anticipated runtime characteristics right now:
//  this shouldn't be a big deal for actors I've written so far, but it's a bottleneck
//  and a waste in the general case.

use alloc::{sync::Arc, vec, vec::Vec};
use core::{
    future::poll_fn,
    task::{Poll, Waker},
};

use lock_api::{Mutex, RawMutex};

use crate::{Message, mailbox::Mailbox};

type Shared = Arc<dyn InnerLock>;

/// Construct an async mailbox with mutex type `R`.
pub fn async_mailbox<R>(mut mailbox: Mailbox) -> (Sender, Receiver)
where
    R: RawMutex + Send + Sync + 'static,
{
    mailbox.clear();

    let shared = Arc::new(Mutex::<R, _>::new(Inner {
        mailbox,
        send_full_waiters: vec![],
        recv_closed: false,

        recv_wakers: vec![],
        send_closed: false,
    }));

    (Sender(shared.clone()), Receiver(shared))
}

/// Dynamic dispatch wrapper to erase the raw mutex type from [`Shared`], [`Sender`], and
/// [`Receiver`].
trait InnerLock: Send + Sync {
    fn with_lock(&self, f: &mut dyn FnMut(&mut Inner));
}

impl<R> InnerLock for Mutex<R, Inner>
where
    R: RawMutex + Send + Sync,
{
    fn with_lock(&self, f: &mut dyn FnMut(&mut Inner)) {
        f(&mut self.lock())
    }
}

/// Mailbox sender handle.
pub struct Sender(Shared);

/// Mailbox receiver handle.
pub struct Receiver(Shared);

struct Inner {
    mailbox: Mailbox,

    send_full_waiters: Vec<Waker>,
    recv_closed: bool,

    recv_wakers: Vec<Waker>,
    send_closed: bool,
}

/// Error attempting to send a message.
pub enum TrySendError {
    /// Mailbox full.
    Full(Message),
    /// Remote end of the mailbox is closed.
    Closed(Message),
}

/// Error attempting to receive a message.
pub enum TryRecvError {
    /// Mailbox is empty.
    Empty,
    /// Remote end of the mailbox is closed.
    Closed,
}

impl Sender {
    /// Send a message to the receiver.
    ///
    /// Waits for capacity to be available, returning `Err(msg)` only if the remote end
    /// of the mailbox is closed (in `ts_actor`, this typically means the process died).
    pub fn send(&self, msg: Message) -> impl Future<Output = Result<(), Message>> + use<> {
        let mut msg = Some(msg);

        let shr = self.0.clone();

        poll_fn(move |ctx| {
            let mut result = Poll::Pending;

            shr.with_lock(&mut |inner| {
                if inner.recv_closed {
                    result = Poll::Ready(Err(msg.take().unwrap()));
                    return;
                }

                match inner.mailbox.push(msg.take().unwrap()) {
                    Ok(()) => {
                        for waker in inner.recv_wakers.drain(..) {
                            waker.wake();
                        }

                        result = Poll::Ready(Ok(()));
                    }
                    Err(m) => {
                        msg = Some(m);
                        inner.send_full_waiters.push(ctx.waker().clone());
                    }
                }
            });

            result
        })
    }

    /// Try to send a message to the receiver without waiting for capacity.
    pub fn try_send(&self, msg: Message) -> Result<(), TrySendError> {
        let mut result = Ok(());
        let mut msg = Some(msg);

        self.0.with_lock(&mut |inner| {
            let msg = msg.take().unwrap();

            if inner.recv_closed {
                result = Err(TrySendError::Closed(msg));
                return;
            }

            match inner.mailbox.push(msg) {
                Ok(()) => {
                    for waker in inner.recv_wakers.drain(..) {
                        waker.wake();
                    }
                }
                Err(msg) => {
                    result = Err(TrySendError::Full(msg));
                }
            }
        });

        result
    }
}

impl Drop for Sender {
    fn drop(&mut self) {
        self.0.with_lock(&mut |inner| {
            inner.send_closed = true;

            for waker in inner.recv_wakers.drain(..) {
                waker.wake();
            }
        });
    }
}

impl Receiver {
    /// Receive the first available message from the mailbox, waiting for one to become
    /// available. Only returns `None` if the sender handle is dropped.
    pub async fn recv(&self) -> Option<Message> {
        poll_fn(|ctx| {
            let mut result = Poll::Pending;

            self.0.with_lock(&mut |inner| {
                if inner.send_closed {
                    result = Poll::Ready(None);
                    return;
                }

                match inner.mailbox.pop() {
                    Some(x) => {
                        for waker in inner.send_full_waiters.drain(..) {
                            waker.wake();
                        }

                        result = Poll::Ready(Some(x));
                    }
                    None => {
                        inner.recv_wakers.push(ctx.waker().clone());
                    }
                }
            });

            result
        })
        .await
    }

    /// Receive the first available message from the mailbox without waiting for one to
    /// become available.
    pub fn try_recv(&self) -> Result<Message, TryRecvError> {
        let mut result = Err(TryRecvError::Empty);

        self.0.with_lock(&mut |inner| {
            if inner.send_closed {
                result = Err(TryRecvError::Closed);
                return;
            }

            if let Some(x) = inner.mailbox.pop() {
                for waker in inner.send_full_waiters.drain(..) {
                    waker.wake();
                }

                result = Ok(x);
            }
        });

        result
    }

    /// Receive the first message in the mailbox matching the predicate, waiting until such
    /// a message becomes available.
    ///
    /// Only returns `None` if the sender side is dropped.
    pub async fn recv_where(&self, mut pred: impl FnMut(&Message) -> bool) -> Option<Message> {
        poll_fn(|ctx| {
            let mut result = Poll::Pending;

            self.0.with_lock(&mut |inner| {
                if inner.send_closed {
                    result = Poll::Ready(None);
                    return;
                }

                match inner.mailbox.remove_first_where(&mut pred) {
                    Some(x) => {
                        for waker in inner.send_full_waiters.drain(..) {
                            waker.wake();
                        }

                        result = Poll::Ready(Some(x));
                    }
                    None => {
                        inner.recv_wakers.push(ctx.waker().clone());
                    }
                }
            });

            result
        })
        .await
    }

    /// Try to receive the first message in the mailbox matching the predicate, without
    /// waiting for such a message to become available.
    pub fn try_recv_where(
        &self,
        mut pred: impl FnMut(&Message) -> bool,
    ) -> Result<Message, TryRecvError> {
        let mut result = Err(TryRecvError::Empty);

        self.0.with_lock(&mut |inner| {
            if inner.send_closed {
                result = Err(TryRecvError::Closed);
                return;
            }

            if let Some(x) = inner.mailbox.remove_first_where(&mut pred) {
                for waker in inner.send_full_waiters.drain(..) {
                    waker.wake();
                }

                result = Ok(x);
            }
        });

        result
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.0.with_lock(&mut |inner| {
            inner.recv_closed = true;

            for waker in inner.send_full_waiters.drain(..) {
                waker.wake();
            }
        });
    }
}
