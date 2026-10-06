//! `#![no_std]` oneshot async channel based on atomics.
//!
//! Ported from <https://github.com/shaogme/lite-sync/blob/main/src/oneshot/common.rs> --
//! simplified to be only the generic variant, inlining the storage trait and refactoring a
//! bit.

use alloc::sync::Arc;
use core::{
    cell::UnsafeCell,
    fmt,
    future::Future,
    mem::MaybeUninit,
    pin::Pin,
    sync::atomic::{AtomicU8, Ordering},
    task::{Context, Poll},
};

use atomic_waker::AtomicWaker;

/// Inner state for oneshot channel
struct Shared<T> {
    waker: AtomicWaker,
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<T>>,
}

// SAFETY: the atomics are Send + Sync. The UnsafeCell<MaybeUninit<T>> is protected by the state
// machine (the sender must write before setting state -> Ready), and the receiver may only read if
// it sees the state is Ready. Only one thread can access the value at a time, so T does not need to
// be Sync.
unsafe impl<T> Send for Shared<T> where T: Send {}
unsafe impl<T> Sync for Shared<T> where T: Send {}

/// Possible states for the channel.
///
/// The state machine graph is:
///
/// - Initial: Empty
/// - Empty -> Ready
/// - Any -> SenderClosed | ReceiverClosed
///
/// The only time the receiver is allowed to read is if it sees the Ready state (which it
/// must unset). The sender may only set the Ready state after it writes a value, which it
/// may only do once.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
#[repr(u8)]
enum State {
    /// There is no value in the channel.
    Empty = 0,
    /// There is a value in the channel.
    Ready = 1,
    /// The sender has closed.
    SenderClosed = 2,
    /// The receiver has closed.
    ReceiverClosed = 3,
}

impl TryFrom<u8> for State {
    type Error = ();

    fn try_from(val: u8) -> Result<State, Self::Error> {
        Ok(match val {
            0 => State::Empty,
            1 => State::Ready,
            2 => State::SenderClosed,
            3 => State::ReceiverClosed,
            _ => return Err(()),
        })
    }
}

impl<T> Shared<T> {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            waker: AtomicWaker::new(),
            state: AtomicU8::new(State::Empty as _),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        })
    }
}

impl<S> fmt::Debug for Shared<S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Inner").finish_non_exhaustive()
    }
}

/// Oneshot sender.
pub struct Sender<T> {
    inner: Arc<Shared<T>>,
}

impl<T> fmt::Debug for Sender<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sender").finish_non_exhaustive()
    }
}

impl<T> Sender<T> {
    /// Send a value through the channel.
    ///
    /// Returns `Err(value)` if the receiver was already dropped or closed.
    pub fn send(self, value: T) -> Result<(), T> {
        if self.is_closed() {
            return Err(value);
        }
        self.send_unchecked(value);
        Ok(())
    }

    /// Send a value without checking if receiver is dropped.
    ///
    /// This is faster than `send()` as it skips the Arc reference count check.
    pub fn send_unchecked(self, value: T) {
        // SAFETY: value is only written by sender, consuming self (multiple mutable aliasing is
        // impossible). A concurrent read-ref from Receiver is not possible because this write
        // occurs before storing State::Ready in the state, which is the only case in which Receiver
        // can read.
        unsafe { (*self.inner.value.get()).write(value) };

        self.inner.state.store(State::Ready as _, Ordering::Release);
        self.inner.waker.wake();

        // Skip drop (don't store SenderClosed)
        core::mem::forget(self);
    }

    /// Check if the receiver has been closed or dropped
    pub fn is_closed(&self) -> bool {
        // Receiver is closed if it was explicitly closed or dropped (Arc count == 1)
        self.is_receiver_closed() || Arc::strong_count(&self.inner) == 1
    }

    fn is_receiver_closed(&self) -> bool {
        self.inner.state.load(Ordering::Acquire) == State::ReceiverClosed as u8
    }
}

impl<T> Drop for Sender<T> {
    fn drop(&mut self) {
        self.inner
            .state
            .store(State::SenderClosed as u8, Ordering::Release);

        self.inner.waker.wake();
    }
}

/// Oneshot receiver.
pub struct Receiver<T> {
    inner: Arc<Shared<T>>,
}

impl<T> fmt::Debug for Receiver<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Receiver").finish_non_exhaustive()
    }
}

impl<T> Receiver<T> {
    /// Poll the shared state for a value.
    ///
    /// This is a tightly-coupled helper for the [`Future::poll`] implementation.
    fn poll_recv(&self) -> Poll<Option<T>> {
        // It is fine to put `Empty` here. This function is only called by `poll`, and anything
        // other than Empty in the state causes the future to return Poll::Ready. This isn't a
        // safety issue (see the notes in the Ready branch below, which can only be called once
        // regardless): the worst that can happen is that this gets spuriously called again in state
        // Empty and returns Poll::Pending thereafter.
        let state = self.inner.state.swap(State::Empty as _, Ordering::AcqRel);

        match State::try_from(state).unwrap() {
            State::Ready => {
                let mut out = MaybeUninit::uninit();

                // SAFETY: we are in State::Ready, meaning that the sender has done its one-shot
                // write and we are clear to read the value (aliasing isn't possible).
                core::mem::swap(&mut out, unsafe { &mut *self.inner.value.get() });

                // SAFETY: per above, the sender has written to the value, so it's initialized.
                // Since we swap in State::Empty, we can only ever enter this branch at most once,
                // as the only way the state gets set to Ready is by the sender in a method that
                // consumes `self`.
                Poll::Ready(Some(unsafe { out.assume_init() }))
            }
            State::SenderClosed | State::ReceiverClosed => Poll::Ready(None),
            State::Empty => Poll::Pending,
        }
    }

    fn is_sender_dropped(&self) -> bool {
        self.inner.state.load(Ordering::Acquire) == State::SenderClosed as u8
    }
}

impl<T> Future for Receiver<T> {
    type Output = Option<T>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        // Fast path: check if value ready or closed
        if let Poll::Ready(t) = self.as_mut().poll_recv() {
            return Poll::Ready(t);
        }

        // Slow path: register waker, then check again
        self.as_mut().inner.waker.register(cx.waker());
        if let Poll::Ready(t) = self.as_mut().poll_recv() {
            return Poll::Ready(t);
        }

        // Also check via Arc
        if Arc::strong_count(&self.as_ref().inner) == 1 && self.is_sender_dropped() {
            return Poll::Ready(None);
        }

        Poll::Pending
    }
}

impl<T> Drop for Receiver<T> {
    fn drop(&mut self) {
        // It's fine to unconditionally run this store: the only critical feature of the state
        // machine ordering is that the sender must store Ready before the receiver reads. Since
        // we're dropping the receiver, this just notifies the sender (if it still exists) that
        // we've dropped and can't spoil that ordering.
        self.inner
            .state
            .store(State::ReceiverClosed as _, Ordering::Release);
    }
}

/// Create a oneshot channel with the given storage type
pub fn channel<T>() -> (Sender<T>, Receiver<T>) {
    let inner = Shared::new();
    let sender = Sender {
        inner: inner.clone(),
    };
    let receiver = Receiver { inner };
    (sender, receiver)
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn send_unchecked() {
        let (tx, rx) = channel();

        tx.send_unchecked(());
        assert_eq!(rx.await, Some(()));
    }

    #[tokio::test]
    async fn send() {
        let (tx, rx) = channel();

        assert!(tx.send(()).is_ok());
        assert_eq!(rx.await, Some(()));
    }

    #[tokio::test]
    async fn drop_tx() {
        let (tx, rx) = channel::<()>();

        drop(tx);
        assert_eq!(rx.await, None);
    }

    #[tokio::test]
    async fn drop_rx() {
        let (tx, rx) = channel::<()>();

        drop(rx);
        assert_eq!(tx.send(()), Err(()));
    }
}
