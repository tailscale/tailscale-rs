use core::{marker::PhantomData, panic::AssertUnwindSafe, pin::Pin};

use futures::FutureExt;
use kameo::{
    actor::{ActorRef, WeakActorRef},
    error::{ActorStopReason, Infallible},
    message::{Context, Message},
};
use tokio_util::task::AbortOnDropHandle;

/// An actor that runs a future and is associated bidirectionally with its lifecycle: the actor
/// dying stops the task, and the task dying kills the actor.
///
/// To support background tasks, [`Task`] holds its own [`ActorRef`] -- it doesn't die if you don't
/// hold a reference to it.
///
/// Kameo doesn't natively provide functionality for this -- [`ActorRef::attach_stream`] is the
/// closest thing, but it doesn't fit the mental model of a background task that doesn't necessarily
/// produce messages. So instead this is a thin wrapper around [`tokio::spawn`], and the inner
/// future kills the actor if the future completes.
///
/// [`Task`] implements [`Message<Infallible>`] so it can be addressed as a type-erased
/// [`Recipient`][kameo::prelude::Recipient] even though it doesn't accept any messages.
///
/// If you need to be generic over the task future or would need to name the type of an anonymous
/// future, it's recommended to box the future and use [`ErasedTask`] as the task type.
///
/// # Examples
///
/// Spawning a task that shares lifecycle with a parent:
///
/// ```
/// # use ts_runtime::Task;
/// # use core::time::Duration;
/// # use futures::FutureExt;
/// # use kameo::prelude::{Actor, Spawn, ActorRef};
/// struct Parent;
///
/// impl Actor for Parent {
///     type Error = ();
///     type Args = ();
///
///     async fn on_start(_: (), slf: ActorRef<Self>) -> Result<Self, ()> {
///         Task::spawn_link(&slf, async move {
///             for i in 0.. {
///                 println!("{i}");
///                 tokio::time::sleep(Duration::from_millis(25)).await;
///             }
///         });
///
///         // ... other self-init ...
///
///         Ok(Self)
///     }
/// }
///
/// # tokio_test::block_on(async move {
/// let parent = Parent::spawn(());
/// tokio::time::sleep(Duration::from_millis(99)).await;
/// parent.kill();
/// // prints 0, 1, 2, 3, then the parent and task are killed
/// # });
/// ```
pub struct Task<Fut>(Option<AbortOnDropHandle<()>>, PhantomData<Fut>);

/// A [`Task`] that was spawned with a boxed future.
///
/// This can be used to operate generically over collections of tasks with different worker futures.
pub type ErasedTask = Task<Pin<Box<dyn Future<Output = ()> + Send + 'static>>>;

/// Run the task future.
///
/// The `slf` as a strong [`ActorRef`] held throughout this future is load-bearing for the way we
/// expect to use [`Task`]: the [`Task`] keeps itself alive as long as its worker future is running
/// (a strong ref means kameo won't gc it).
async fn run_fut<Fut>(fut: Fut, slf: ActorRef<Task<Fut>>)
where
    Fut: Future<Output = ()> + Send + 'static,
{
    match AssertUnwindSafe(fut).catch_unwind().await {
        Ok(_) => {
            if slf.stop_gracefully().await.is_err() {
                slf.kill();
            }
        }
        Err(e) => {
            slf.kill();

            std::panic::resume_unwind(e)
        }
    }
}

impl<Fut> kameo::Actor for Task<Fut>
where
    Fut: Future<Output = ()> + Send + 'static,
{
    type Args = Fut;
    type Error = core::convert::Infallible;

    async fn on_start(fut: Self::Args, slf: ActorRef<Self>) -> Result<Self, Self::Error> {
        Ok(Self(
            Some(AbortOnDropHandle::new(tokio::spawn(run_fut(fut, slf)))),
            PhantomData,
        ))
    }

    // In case there's a condition where the actor is retained in memory for a while after it's
    // stopped, explicitly trigger abort here rather than waiting for the actor to be dropped.
    //
    // The AbortOnDropHandle conversely ensures that the task is aborted if `on_stop` is not called.
    async fn on_stop(
        &mut self,
        slf: WeakActorRef<Self>,
        reason: ActorStopReason,
    ) -> Result<(), Self::Error> {
        tracing::trace!(?slf, ?reason, "task stopping");

        // Unwrap is safe: on_stop is called exactly once and the option is always populated by
        // actor construction.
        //
        // This ensures that the task is aborted at the end of this scope if it's not already
        // finished (checked in the next block).
        let handle = self.0.take().unwrap();

        if handle.is_finished()
            && let Err(e) = handle.detach().await
        {
            // The task was never canceled because it was still in the abort handle (the
            // only way this particular task would be canceled), so the error must be due to
            // a panic. Rethrow it here to make it appear as this actor's panic to kameo.
            std::panic::resume_unwind(e.into_panic())
        }

        Ok(())
    }
}

impl<Fut> Message<Infallible> for Task<Fut>
where
    Fut: Future<Output = ()> + Send + 'static,
{
    type Reply = Infallible;

    async fn handle(&mut self, _: Infallible, _: &mut Context<Self, Self::Reply>) -> Infallible {
        unreachable!()
    }
}

#[cfg(test)]
mod test {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        time::Duration,
    };

    use kameo::{actor::Spawn, error::HookError};

    use super::*;

    #[tokio::test]
    async fn kill_stops_task() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(1);

        let task = Task::spawn(async move {
            loop {
                tx.send(()).await.unwrap();
            }
        });

        // can receive as many messages as we want
        for _ in 0..5 {
            rx.recv().await.unwrap();
        }

        task.kill();
        task.wait_for_shutdown().await;

        // drain final buffered message
        rx.recv().await.unwrap();

        assert!(rx.is_closed());
        assert!(rx.is_empty());
    }

    #[tokio::test]
    async fn task_complete_stops_actor() {
        let notify = Arc::new(tokio::sync::Notify::new());
        let completed = Arc::new(AtomicBool::new(false));

        let task = Task::spawn({
            let notify = notify.clone();
            let completed = completed.clone();

            async move {
                notify.notified().await;
                completed.store(true, Ordering::SeqCst);
            }
        });

        assert!(task.is_alive());
        assert!(!completed.load(Ordering::SeqCst));

        notify.notify_one();

        tokio::time::timeout(Duration::from_millis(100), task.wait_for_shutdown())
            .await
            .unwrap();

        assert!(!task.is_alive());
        assert!(completed.load(Ordering::SeqCst));

        let result = task.get_shutdown_result().unwrap();
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn task_panic_stops_actor() {
        let notify = Arc::new(tokio::sync::Notify::new());

        let task = Task::spawn({
            let notify = notify.clone();

            async move {
                notify.notified().await;
                panic!();
            }
        });

        assert!(task.is_alive());

        notify.notify_one();

        tokio::time::timeout(Duration::from_millis(100), task.wait_for_shutdown())
            .await
            .unwrap();

        assert!(!task.is_alive());

        let result = task.get_shutdown_result().unwrap().unwrap_err();
        assert!(matches!(result, HookError::Panicked(_)));
    }
}
