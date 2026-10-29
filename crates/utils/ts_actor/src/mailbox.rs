//! SPSC async channels where receivers can choose to receive the first message matching
//! a predicate.

// TODO(npry): recv_where performance is expected to be pretty bad: it scans the whole
//  mailbox every time it's polled (~every time the sender sends a message), while in
//  principle it could track the messages it has seen and only look at new ones as they
//  arrive. We're leaning rather heavily on anticipated runtime characteristics right now:
//  this shouldn't be a big deal for actors I've written so far, but it's a bottleneck
//  and a waste in the general case.

use alloc::{collections::VecDeque, sync::Arc, vec, vec::Vec};
use core::{
    future::poll_fn,
    task::{Poll, Waker},
};

use lock_api::{Mutex, RawMutex};

use crate::Message;

type Shared = Arc<dyn InnerLock>;

/// Construct an async mailbox with mutex type `R`.
pub fn async_mailbox<R>() -> (Sender, Receiver)
where
    R: RawMutex + Send + Sync + 'static,
{
    let shared = Arc::new(Mutex::<R, _>::new(Inner {
        mailbox: Default::default(),
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
    fn with_lock_dyn(&self, f: &mut dyn FnMut(&mut Inner));
}

impl<R> InnerLock for Mutex<R, Inner>
where
    R: RawMutex + Send + Sync,
{
    fn with_lock_dyn(&self, f: &mut dyn FnMut(&mut Inner)) {
        f(&mut self.lock())
    }
}

impl dyn InnerLock {
    fn with_lock<T>(&self, f: impl FnOnce(&mut Inner) -> T) -> T {
        let mut f = Some(f);
        let mut result = None;

        self.with_lock_dyn(&mut |x| {
            let f = f.take().unwrap();

            result = Some(f(x));
        });

        result.unwrap()
    }

    /// Report whether the mailbox is empty.
    fn is_empty(&self) -> bool {
        self.with_lock(|inner| inner.mailbox.is_empty())
    }

    /// Report the number of messages queued in the mailbox.
    fn len(&self) -> usize {
        self.with_lock(|inner| inner.mailbox.len())
    }
}

/// Mailbox sender handle.
pub struct Sender(Shared);

/// Mailbox receiver handle.
pub struct Receiver(Shared);

struct Inner {
    mailbox: VecDeque<Message>,

    send_full_waiters: Vec<Waker>,
    recv_closed: bool,

    recv_wakers: Vec<Waker>,
    send_closed: bool,
}

impl Inner {
    fn remove_first_where(&mut self, pred: &mut dyn FnMut(&Message) -> bool) -> Option<Message> {
        let idx = self
            .mailbox
            .iter()
            .enumerate()
            .find(|(_, msg)| pred(msg))
            .map(|(i, _msg)| i)?;

        Some(self.mailbox.remove(idx).unwrap())
    }
}

/// Error attempting to receive a message.
#[derive(Debug, PartialEq)]
pub enum TryRecvError {
    /// Mailbox is empty.
    Empty,
    /// Remote end of the mailbox is closed.
    Closed,
}

impl Sender {
    /// Send a message to the receiver.
    ///
    /// Returns `Err(msg)` if the remote end of the mailbox is closed (in `ts_actor`, this
    /// typically means the process died).
    pub fn send(&self, msg: Message) -> Result<(), Message> {
        let mut msg = Some(msg);

        self.0.with_lock(move |inner| {
            let msg = msg.take().unwrap();

            if inner.recv_closed {
                return Err(msg);
            }

            inner.mailbox.push_back(msg);
            for waker in inner.recv_wakers.drain(..) {
                waker.wake();
            }

            Ok(())
        })
    }

    /// Report whether the receiver end of this channel is closed.
    pub fn is_closed(&self) -> bool {
        self.0.with_lock(|inner| inner.recv_closed)
    }

    /// Report whether the mailbox is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Report the number of messages queued in the mailbox.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl Drop for Sender {
    fn drop(&mut self) {
        self.0.with_lock(|inner| {
            inner.send_closed = true;

            for waker in inner.recv_wakers.drain(..) {
                waker.wake();
            }
        });
    }
}

impl Receiver {
    /// Receive the first available message from the mailbox, waiting for one to become
    /// available.
    ///
    /// Returns `None` if mailbox is empty and the sender handle is dropped.
    pub async fn recv(&self) -> Option<Message> {
        poll_fn(|ctx| {
            self.0.with_lock(|inner| match inner.mailbox.pop_front() {
                Some(x) => {
                    for waker in inner.send_full_waiters.drain(..) {
                        waker.wake();
                    }

                    Poll::Ready(Some(x))
                }
                None if !inner.send_closed => {
                    inner.recv_wakers.push(ctx.waker().clone());
                    Poll::Pending
                }
                _ => Poll::Ready(None),
            })
        })
        .await
    }

    /// Receive the first available message from the mailbox without waiting for one to
    /// become available.
    pub fn try_recv(&self) -> Result<Message, TryRecvError> {
        self.0.with_lock(|inner| {
            if let Some(x) = inner.mailbox.pop_front() {
                for waker in inner.send_full_waiters.drain(..) {
                    waker.wake();
                }

                return Ok(x);
            }

            if inner.send_closed {
                Err(TryRecvError::Closed)
            } else {
                Err(TryRecvError::Empty)
            }
        })
    }

    /// Receive the first message in the mailbox matching the predicate, waiting until such
    /// a message becomes available.
    ///
    /// Returns `None` if no messages match in the mailbox and the sender side is dropped.
    /// This doesn't necessarily mean that the mailbox is empty (check with
    /// [`Receiver::is_empty`]).
    pub async fn recv_where(&self, mut pred: impl FnMut(&Message) -> bool) -> Option<Message> {
        poll_fn(|ctx| {
            self.0
                .with_lock(|inner| match inner.remove_first_where(&mut pred) {
                    Some(msg) => {
                        for waker in inner.send_full_waiters.drain(..) {
                            waker.wake();
                        }

                        Poll::Ready(Some(msg))
                    }
                    None if !inner.send_closed => {
                        inner.recv_wakers.push(ctx.waker().clone());
                        Poll::Pending
                    }
                    _ => Poll::Ready(None),
                })
        })
        .await
    }

    /// Try to receive the first message in the mailbox matching the predicate, without
    /// waiting for such a message to become available.
    ///
    /// [`TryRecvError::Closed`] is returned if the sender channel is closed and the
    /// predicate doesn't match. It doesn't necessarily mean that the mailbox is empty
    /// (check with [`Receiver::is_empty`]).
    pub fn try_recv_where(
        &self,
        mut pred: impl FnMut(&Message) -> bool,
    ) -> Result<Message, TryRecvError> {
        self.0.with_lock(|inner| {
            if let Some(x) = inner.remove_first_where(&mut pred) {
                for waker in inner.send_full_waiters.drain(..) {
                    waker.wake();
                }

                return Ok(x);
            }

            if inner.send_closed {
                Err(TryRecvError::Closed)
            } else {
                Err(TryRecvError::Empty)
            }
        })
    }

    /// Report whether the receiver end of this channel is closed.
    pub fn is_closed(&self) -> bool {
        self.0.with_lock(|inner| inner.send_closed)
    }

    /// Report whether the mailbox is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// Report the number of messages queued in the mailbox.
    pub fn len(&self) -> usize {
        self.0.len()
    }
}

impl Drop for Receiver {
    fn drop(&mut self) {
        self.0.with_lock(|inner| {
            inner.recv_closed = true;

            for waker in inner.send_full_waiters.drain(..) {
                waker.wake();
            }
        });
    }
}

#[cfg(test)]
mod test {
    use super::*;

    const N: usize = 32;

    #[tokio::test]
    async fn recv() {
        let (tx, rx) = async_mailbox::<parking_lot::RawMutex>();

        for i in 0usize..N {
            tx.send(Message::new(i)).unwrap();
        }

        for i in 0usize..N {
            let rxed = rx.recv().await.unwrap();
            let val = rxed.downcast::<usize>().unwrap();
            assert_eq!(val, i);
        }

        drop(tx);
        assert!(rx.is_closed());
        assert!(rx.recv().await.is_none());
    }

    #[tokio::test]
    async fn recv_where() {
        let (tx, rx) = async_mailbox::<parking_lot::RawMutex>();

        for i in 0usize..N {
            tx.send(Message::new(i)).unwrap();
        }

        for i in (0usize..N).rev() {
            let rxed = rx
                .recv_where(|x| *x.downcast_ref::<usize>().unwrap() == i)
                .await
                .unwrap();

            let val = rxed.downcast::<usize>().unwrap();
            assert_eq!(val, i);
        }

        drop(tx);
        assert!(rx.is_closed());
        assert!(rx.recv_where(|_| true).await.is_none());
    }

    #[test]
    fn try_recv() {
        let (tx, rx) = async_mailbox::<parking_lot::RawMutex>();

        for i in 0usize..N {
            assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));
            tx.send(Message::new(i)).unwrap();

            let rxed = rx.try_recv().unwrap();
            let val = rxed.downcast::<usize>().unwrap();
            assert_eq!(val, i);
        }

        drop(tx);
        assert!(rx.is_closed());
        assert!(matches!(rx.try_recv(), Err(TryRecvError::Closed)));
    }

    #[test]
    fn try_recv_where() {
        let (tx, rx) = async_mailbox::<parking_lot::RawMutex>();

        assert!(matches!(rx.try_recv(), Err(TryRecvError::Empty)));

        for i in 0usize..N {
            tx.send(Message::new(i)).unwrap();
        }

        for i in (0usize..N).rev() {
            let rxed = rx
                .try_recv_where(|x| *x.downcast_ref::<usize>().unwrap() == i)
                .unwrap();

            let val = rxed.downcast::<usize>().unwrap();
            assert_eq!(val, i);
        }

        drop(tx);
        assert!(rx.is_closed());
        assert!(matches!(
            rx.try_recv_where(|_| true),
            Err(TryRecvError::Closed)
        ));
    }

    #[test]
    fn sender_closed() {
        let (tx, rx) = async_mailbox::<parking_lot::RawMutex>();

        assert!(!tx.is_closed());
        drop(rx);

        assert!(tx.is_closed());
    }

    #[test]
    fn receiver_closed() {
        let (tx, rx) = async_mailbox::<parking_lot::RawMutex>();

        assert!(!rx.is_closed());
        drop(tx);

        assert!(rx.is_closed());
    }
}
