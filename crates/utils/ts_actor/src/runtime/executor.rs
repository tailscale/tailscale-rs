use crate::{ProcFut, StaticStorage};

/// Abstraction around an async executor.
pub trait Executor: Send + Sync + 'static {
    /// Spawn a future onto the executor.
    fn spawn(&self, fut: StaticStorage<ProcFut>) -> StaticStorage<dyn TaskHandle>;
    /// Return a future that sleeps for the given duration.
    fn sleep(
        &self,
        duration: core::time::Duration,
    ) -> StaticStorage<dyn Future<Output = ()> + Send>;
}

/// Abstraction around an async task.
pub trait TaskHandle:
    Future<Output = Result<(), TaskError>> + Send + Sync + Unpin + 'static
{
    /// Report whether the task is finished.
    fn is_finished(&self) -> bool;
    /// Mark the task as aborted.
    fn abort(&mut self);
}

/// Errors which may occur while a [`TaskHandle`] is executing.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, thiserror::Error)]
pub enum TaskError {
    /// The task panicked.
    #[error("task panicked")]
    Panicked,
    /// The task was aborted.
    #[error("task was aborted")]
    Aborted,
    /// The task returned the contained [`Error`].
    #[error(transparent)]
    Inner(#[from] Error),
}

pin_project_lite::pin_project! {
    struct TaskBridge<T> {
        #[pin]
        fut: Option<T>
    }
}

#[cfg(feature = "tokio")]
mod _tokio {
    use alloc::boxed::Box;
    use core::{
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };

    use tap::Pipe;
    use tokio::task::JoinHandle;

    use super::*;

    /// A tokio executor bridge.
    pub struct Tokio(tokio::runtime::Handle);

    impl Tokio {
        /// Construct a bridge around the given handle.
        pub const fn new(handle: tokio::runtime::Handle) -> Self {
            Self(handle)
        }

        /// Construct a bridge from the current executor.
        ///
        /// # Panics
        ///
        /// If called from outside a running executor.
        pub fn current() -> Self {
            Self(tokio::runtime::Handle::current())
        }
    }

    impl Executor for Tokio {
        fn spawn(&self, fut: StaticStorage<ProcFut>) -> StaticStorage<dyn TaskHandle> {
            StaticStorage::Box(Box::new(TaskBridge {
                fut: Some(self.0.spawn(fut)),
            }))
        }

        fn sleep(&self, duration: Duration) -> StaticStorage<dyn Future<Output = ()> + Send> {
            StaticStorage::Box(Box::new(tokio::time::sleep(duration)))
        }
    }

    impl TaskHandle for TaskBridge<JoinHandle<Result<(), Error>>> {
        fn is_finished(&self) -> bool {
            self.fut.as_ref().is_none_or(|x| x.is_finished())
        }

        fn abort(&mut self) {
            if let Some(x) = &mut self.fut {
                x.abort();
            }
        }
    }

    impl<T> Future for TaskBridge<JoinHandle<Result<T, Error>>> {
        type Output = Result<T, TaskError>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let slf = self.project();

            let Some(fut) = slf.fut.as_pin_mut() else {
                return Poll::Ready(Err(TaskError::Aborted));
            };

            core::task::ready!(fut.poll(cx))
                .map_err(|e| {
                    if e.is_cancelled() {
                        return TaskError::Aborted;
                    }

                    if e.is_panic() {
                        tracing::error!(error = %e, "task panicked");
                        return TaskError::Panicked;
                    }

                    // tokio task errors are either panics or cancellations
                    unreachable!()
                })?
                .map_err(TaskError::Inner)
                .pipe(Poll::Ready)
        }
    }
}

#[cfg(feature = "tokio")]
pub use _tokio::*;

#[cfg(feature = "smol")]
mod _smol {
    use alloc::boxed::Box;
    use core::time::Duration;

    use crate::{
        ProcFut, StaticStorage,
        runtime::{Executor, TaskHandle, executor::TaskBridge},
    };

    /// An executor adapter for [`smol`].
    ///
    /// This is just a convenience wrapper around [`smol::spawn`] in case you don't want to run your
    /// own [`async_executor::Executor`] instance.
    pub struct Smol;

    impl Executor for Smol {
        fn spawn(&self, fut: StaticStorage<ProcFut>) -> StaticStorage<dyn TaskHandle> {
            let task = smol::spawn(fut);

            // NB: smol uses async-executor under the hood, hence this reuses the TaskHandle impl
            // from mod _async_exec below.
            StaticStorage::Box(Box::new(TaskBridge { fut: Some(task) }))
        }

        fn sleep(&self, duration: Duration) -> StaticStorage<dyn Future<Output = ()> + Send> {
            StaticStorage::Box(Box::new(async move {
                smol::Timer::after(duration).await;
            }))
        }
    }
}

#[cfg(feature = "smol")]
pub use _smol::*;

#[cfg(feature = "async-executor")]
mod _async_exec {
    use alloc::boxed::Box;
    use core::{
        borrow::Borrow,
        pin::Pin,
        task::{Context, Poll},
        time::Duration,
    };

    use async_executor::Task;
    use tap::Pipe;

    use super::*;
    use crate::util;

    /// An executor adapter for [`async_executor`].
    pub struct AsyncExecutor<B>(B);

    impl<B> AsyncExecutor<B> {
        /// Build a new adapter for the given executor.
        ///
        /// `exec` can be any type which borrows to [`async_executor::Executor`]. You can use a
        /// plain executor, but if you also need to spawn other futures onto it, you'll likely want
        /// to wrap it in `Arc`.
        pub const fn new(exec: B) -> Self {
            Self(exec)
        }
    }

    impl<B> Executor for AsyncExecutor<B>
    where
        B: Borrow<async_executor::Executor<'static>> + Send + Sync + 'static,
    {
        fn spawn(&self, fut: StaticStorage<ProcFut>) -> StaticStorage<dyn TaskHandle> {
            let task = self.0.borrow().spawn(fut);

            StaticStorage::Box(Box::new(TaskBridge { fut: Some(task) }))
        }

        fn sleep(&self, duration: Duration) -> StaticStorage<dyn Future<Output = ()> + Send> {
            StaticStorage::Box(Box::new(async move {
                async_io::Timer::after(duration).await;
            }))
        }
    }

    impl<M> TaskHandle for TaskBridge<Task<Result<(), Error>, M>>
    where
        M: Send + Sync + 'static,
    {
        fn is_finished(&self) -> bool {
            self.fut.as_ref().is_none_or(|x| x.is_finished())
        }

        fn abort(&mut self) {
            // Per `Task` docs, dropping the task cancels it.
            self.fut.take();
        }
    }

    impl<T, M> Future for TaskBridge<Task<Result<T, Error>, M>> {
        type Output = Result<T, TaskError>;

        fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
            let slf = self.project();

            let Some(fut) = slf.fut.as_pin_mut() else {
                return Poll::Ready(Err(TaskError::Aborted));
            };

            cfg_if::cfg_if! {
                if #[cfg(feature = "std")] {
                    match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| fut.poll(cx))) {
                        Ok(x) => core::task::ready!(x)
                            .map_err(TaskError::Inner),
                        Err(e) => {
                            tracing::error!(error = %util::panic_payload_as_str(&e), "task panicked");
                            Err(TaskError::Panicked)
                        },
                    }.pipe(Poll::Ready)
                } else {
                    core::task::ready!(fut.poll(cx))
                        .map_err(TaskError::Inner)
                        .pipe(Poll::Ready)
                }
            }
        }
    }
}

#[cfg(feature = "async-executor")]
pub use _async_exec::*;

use crate::error::Error;
