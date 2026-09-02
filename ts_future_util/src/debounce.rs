//! Modeled after
//! <https://github.com/yoshuawuyts/futures-time/blob/main/src/stream/debounce.rs>, with the
//! deviation that this yields on both the debounce window leading edge and trailing edge (if there
//! was anything received inside the window).

use core::{
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};

use futures_core::Stream;

/// [`Debounce`] using [`tokio::time::sleep`] as its timer.
#[cfg(feature = "tokio")]
pub type TokioDebounce<S> = Debounce<S, fn() -> tokio::time::Sleep, tokio::time::Sleep>;

pin_project_lite::pin_project! {
    /// A wrapper that debounces stream items.
    ///
    /// The initial element is always yielded immediately. Successive elements within a configurable
    /// debounce window are suppressed. If any elements were yielded during the window, the last one
    /// is yielded at the end of the window (starting a new window). All previous elements within
    /// the window are dropped.
    ///
    /// # Examples
    ///
    /// When elements are coming from the inner stream slower than the debounce window, `Debounce`
    /// is transparent:
    ///
    /// ```text
    /// input:      e1                e2
    /// windows:    |<--  w1  -->|    |<--  w2  -->|
    /// output:     e1                e2
    /// ```
    ///
    /// When elements come faster than the window, they're suppressed until the window elapses:
    ///
    /// ```text
    /// input:      e1 e2 e3         e4 e5
    /// windows:    |<--  w1  -->|<--  w2  -->|
    /// output:     e1          e3            e5
    /// ```
    pub struct Debounce<S, F, Timer>
    where
        S: Stream,
        S: ?Sized,
    {
        slot: Option<S::Item>,
        stream_done: bool,

        #[pin]
        timer: Option<Timer>,
        make_timer: F,
        window: Duration,

        #[pin]
        stream: S,
    }
}

impl<S, F, Timer> Debounce<S, F, Timer>
where
    S: Stream,
{
    /// Build a new [`Debounce`] with the given timer creation function and window duration.
    pub fn new(stream: S, make_timer: F, window: Duration) -> Self {
        Self {
            stream,
            timer: None,
            slot: None,
            stream_done: false,
            make_timer,
            window,
        }
    }
}

#[cfg(feature = "tokio")]
impl<S> Debounce<S, fn(Duration) -> tokio::time::Sleep, tokio::time::Sleep>
where
    S: Stream,
{
    /// Build a new [`Debounce`] using a tokio timer.
    pub fn tokio(stream: S, window: Duration) -> Self {
        Debounce::new(stream, tokio::time::sleep, window)
    }
}

impl<S, F, Timer> Stream for Debounce<S, F, Timer>
where
    S: Stream,
    F: FnMut(Duration) -> Timer,
    Timer: Future,
{
    type Item = S::Item;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let mut slf = self.as_mut().project();

        // Invariant: loop falls through when the stream is polled to exhaustion (once).
        loop {
            if *slf.stream_done {
                // If there's nothing in the slot, there never will be (the stream has stopped).
                // Drop the timer if we have one.
                if slf.slot.is_none() {
                    slf.timer.set(None);
                }

                // If the stream is done and there's no timer, we're done, stop polling.
                if slf.timer.is_none() {
                    return Poll::Ready(None);
                }
            }

            if let Some(timer) = slf.timer.as_mut().as_pin_mut() {
                match timer.poll(cx) {
                    Poll::Pending => {
                        // If the stream is done, the timer drives the future polling exclusively.
                        // We're just waiting for this debounce window to end in order to yield the
                        // final item.
                        if *slf.stream_done {
                            return Poll::Pending;
                        }

                        // Otherwise, fall through to poll the stream: we shouldn't yield anything
                        // from it until the timer is ready, but we need it to make progress and
                        // update the slot if it produces items.
                    }
                    Poll::Ready(_) => {
                        slf.timer.set(None);

                        // Timer was the first thing to be polled; there may be items available in
                        // the stream. Drain everything that's synchronously available before seeing
                        // if we can yield an item from the slot.
                        while !*slf.stream_done
                            && let Poll::Ready(x) = slf.stream.as_mut().poll_next(cx)
                        {
                            if let Some(item) = x {
                                *slf.slot = Some(item);
                            } else {
                                *slf.stream_done = true;
                            }
                        }

                        // If we have an item in the slot, yield it and start a new window timer.
                        if let Some(item) = slf.slot.take() {
                            // Don't bother with a new window if we know the stream won't yield
                            // anything else.
                            if !*slf.stream_done {
                                slf.timer.set(Some((slf.make_timer)(*slf.window)));
                            }

                            return Poll::Ready(Some(item));
                        }
                    }
                }
            }

            // Invariant: getting to this point means that an item is expected from the stream. If
            // it's done, there is no more work to do.
            if *slf.stream_done {
                debug_assert!(slf.timer.is_none());
                return Poll::Ready(None);
            }

            // Drain any ready items out of the stream.
            while let Some(item) = core::task::ready!(slf.stream.as_mut().poll_next(cx)) {
                // If we don't have a timer, we're not in a debounce window right now.
                // Start one and immediately yield the item.
                if slf.timer.is_none() {
                    debug_assert!(slf.slot.is_none());
                    slf.timer.set(Some((slf.make_timer)(*slf.window)));

                    return Poll::Ready(Some(item));
                }

                // We're in a debounce window: just update the value in the slot and try to read
                // more out of the stream.
                *slf.slot = Some(item);
            }

            // Stream has just been polled to exhaustion. Fall through the loop to try to poll the
            // timer.
            *slf.stream_done = true;
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        S::size_hint(&self.stream)
    }
}

/// Extension trait to add debounce wrapper methods to [`Stream`] implementors.
///
/// See [`Debounce`] for details on the returned stream wrapper.
pub trait DebounceExt: Stream + Sized {
    /// Debounce this stream using a window of duration `window`. Uses `tokio::time::sleep` as the
    /// timer future.
    ///
    /// See [`DebounceExt::debounce_with`] for more info on debouncing.
    #[cfg(feature = "tokio")]
    fn debounce(
        self,
        window: Duration,
    ) -> Debounce<Self, fn(Duration) -> tokio::time::Sleep, tokio::time::Sleep> {
        Debounce::tokio(self, window)
    }

    /// Debounce this stream with a configurable timer function.
    ///
    /// This debounce has both leading- and trailing-edge behavior. In the idle state, the first
    /// item from the underlying stream is yielded immediately. This puts the stream into a debounce
    /// state, where all items from the underlying stream are suppressed. At the end of the debounce
    /// window, if any stream items were suppressed, the most recent one is yielded and a new
    /// debounce window starts. If not, nothing is yielded and the stream returns to the idle state.
    ///
    /// This is useful e.g. in cases where the underlying stream is a series of full-state
    /// snapshots which may come in large bursts. In these cases, you don't necessarily need to see
    /// all the items from the stream, but you will always need to receive the final state in order
    /// to have an accurate view of the world in steady-state. The leading-edge behavior improves
    /// responsiveness in non-bursty scenarios.
    ///
    /// # Timer
    ///
    /// The return value of the timer function is any future: when it completes, the debounce window
    /// is considered elapsed. Generally, this will just be a constructor for a timer which elapses
    /// after the passed-in [`Duration`].
    fn debounce_with<F, Timer>(self, window: Duration, make_timer: F) -> Debounce<Self, F, Timer>
    where
        F: FnMut(Duration) -> Timer,
        Timer: Future,
    {
        Debounce::new(self, make_timer, window)
    }
}

impl<T> DebounceExt for T where T: Stream + Sized {}

#[cfg(test)]
mod test {
    use std::{boxed::Box, sync::Arc};

    use futures_util::StreamExt;
    use tokio::sync::{Mutex, mpsc};
    use tokio_stream::wrappers::UnboundedReceiverStream;

    use super::*;

    type BoxFut = Pin<Box<dyn Future<Output = ()> + Send>>;
    type BoxDebounce<S> = Debounce<S, Box<dyn FnMut(Duration) -> BoxFut>, BoxFut>;

    #[track_caller]
    fn with_noop_cx<T>(f: impl FnOnce(&mut Context) -> T) -> T {
        let mut cx = Context::from_waker(core::task::Waker::noop());
        f(&mut cx)
    }

    struct TestStream<T> {
        tx: Option<mpsc::UnboundedSender<T>>,
        timer: mpsc::UnboundedSender<()>,
        stream: Pin<Box<BoxDebounce<UnboundedReceiverStream<T>>>>,
    }

    impl<T> TestStream<T> {
        fn new() -> Self
        where
            T: Send + 'static,
        {
            let (stream_tx, stream_rx) = mpsc::unbounded_channel();

            // "Timer channel" simulates a timer without requiring an actual timer. Values yielded from
            // the channel represent the timer elapsing.
            let (timer_tx, timer_rx) = mpsc::unbounded_channel::<()>();
            let timer = Arc::new(Mutex::new(timer_rx));

            let debounced = UnboundedReceiverStream::new(stream_rx).debounce_with(
                Duration::from_secs(1),
                Box::new(move |_dur| {
                    let rx = timer.clone();

                    Box::pin(async move {
                        let mut rx = rx.lock().await;
                        rx.recv().await.unwrap();
                    }) as BoxFut
                }) as Box<dyn FnMut(Duration) -> BoxFut>,
            );

            Self {
                tx: Some(stream_tx),
                timer: timer_tx,
                stream: Box::pin(debounced),
            }
        }

        /// Assert that the stream is currently pending.
        #[track_caller]
        fn assert_pending(&mut self) {
            with_noop_cx(|cx| {
                assert!(self.stream.poll_next_unpin(cx).is_pending());
            });
        }

        /// Send the value through the sender and assert it comes back through the stream.
        #[track_caller]
        fn assert_roundtrip(&mut self, value: T)
        where
            T: PartialEq + Clone + core::fmt::Debug,
        {
            self.send(value.clone());
            self.assert_next(value);
        }

        /// Assert the value of the next item in the stream.
        #[track_caller]
        fn assert_next(&mut self, value: T)
        where
            T: PartialEq + core::fmt::Debug,
        {
            assert_eq!(
                with_noop_cx(|cx| self.stream.poll_next_unpin(cx)),
                Poll::Ready(Some(value)),
            )
        }

        /// Assert that the stream is done.
        #[track_caller]
        fn assert_done(&mut self)
        where
            T: PartialEq + core::fmt::Debug,
        {
            assert_eq!(
                with_noop_cx(|cx| self.stream.poll_next_unpin(cx)),
                Poll::Ready(None),
            );
            assert!(self.stream.stream_done);
        }

        fn send(&self, t: T) {
            self.tx.as_ref().unwrap().send(t).unwrap();
        }

        fn release_timer(&self) {
            self.timer.send(()).unwrap();
        }

        fn drop_sender(&mut self) {
            self.tx.take().unwrap();
        }
    }

    /// Send values through a debounced stream slowly enough to never trigger the debounce behavior.
    #[test]
    fn slow_transparent() {
        let mut ts = TestStream::new();

        for i in 0..30 {
            // Nothing available in the stream (stream channel is empty): nothing yielded.
            ts.assert_pending();
            ts.assert_roundtrip(i);
            ts.release_timer();
        }

        // When the underlying stream closes, the debounced one does as well (if nothing is in the
        // slot).
        ts.drop_sender();
        ts.assert_done();
    }

    /// Debounce one message.
    #[test]
    fn single_debounce() {
        let mut ts = TestStream::new();
        ts.assert_pending();

        // Initial message comes back.
        ts.assert_roundtrip(1234);

        // Second message is in window: nothing ready.
        ts.send(5678);
        ts.assert_pending();

        // Release timer, message comes back
        ts.release_timer();
        ts.assert_next(5678);

        // We're in another window: dropping the underlying stream with no items available will
        // immediately end the debounced stream.
        ts.assert_pending();
        ts.drop_sender();
        ts.assert_done();
    }

    /// Debounce many messages in one window.
    #[test]
    fn multi_debounce() {
        let mut ts = TestStream::new();
        ts.assert_pending();

        // Initial message comes back.
        ts.assert_roundtrip(1234);

        // Second message is in window: nothing ready.
        ts.send(5);
        ts.send(6);
        ts.send(7);
        ts.send(8);
        ts.assert_pending();

        // Release timer, only _last_ message comes back
        ts.release_timer();
        ts.assert_next(8);
        ts.assert_pending();

        // In another window – send a value but then drop the sender.
        ts.send(9);
        ts.drop_sender();
        ts.assert_pending();

        // Even after we drop tx, the slot item still yields.
        ts.release_timer();
        ts.assert_next(9);

        // But because we dropped tx, the stream could finish immediately.
        ts.assert_done();
    }
}
