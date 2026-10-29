//! Actor runtime.

use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec};
use core::{
    future::poll_fn,
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
};

use lock_api::{Mutex, RawMutex, RawRwLockUpgrade, RwLock};

use crate::{
    Error, MakeProc, Message, Pid, ProcContext, ProcFuture, StaticStorage, actors::registry,
    gen_server, oneshot,
};

mod executor;
mod handle;
mod inner;
mod process;

#[cfg(feature = "async-executor")]
pub use executor::AsyncExecutor;
#[cfg(feature = "smol")]
pub use executor::Smol;
#[cfg(feature = "tokio")]
pub use executor::Tokio;
pub use executor::{Executor, TaskError, TaskHandle};
pub use handle::RtHandle;
use inner::Inner;
pub(crate) use inner::RtInner;
pub(crate) use process::{ProcessInitState, ProcessState};

/// Construct a new runtime around the given executor.
///
/// This uses `parking_lot` mutexes.
#[cfg(feature = "std")]
pub fn new(executor: impl Executor) -> Arc<dyn Rt> {
    new_with::<parking_lot::RawRwLock, parking_lot::RawMutex>(executor)
}

/// Construct a new runtime around the given executor with the given mutexes.
pub fn new_with<RW, M>(executor: impl Executor) -> Arc<dyn Rt>
where
    RW: RawRwLockUpgrade + Send + Sync + 'static,
    M: RawMutex + Send + Sync + 'static,
{
    new_ss_with::<RW, M>(StaticStorage::Box(Box::new(executor)))
}

/// Construct a new runtime around the given executor with the given mutexes and a
/// particular executor storage.
pub fn new_ss_with<RW, M>(executor: StaticStorage<dyn Executor>) -> Arc<dyn Rt>
where
    RW: RawRwLockUpgrade + Send + Sync + 'static,
    M: RawMutex + Send + Sync + 'static,
{
    let inner = Arc::new(Inner::<RW, M> {
        executor,
        next_pid: AtomicUsize::new(0),
        next_ref: AtomicU64::new(0),
        process_table: RwLock::new(BTreeMap::new()),
        ptable_empty_wakers: Mutex::new(vec![]),
        global_registry: Pid(0).into(),
    });

    let rt: &Arc<dyn Rt> = &(inner.clone() as _);
    let global_pid = rt.spawn(gen_server::start(registry::Registry, ())).unwrap();

    inner.global_registry.store(global_pid, Ordering::Release);

    inner as _
}

/// Public-facing representation of a runtime.
pub trait Rt: RtInner {}

impl<T> Rt for T where T: RtInner {}

impl dyn Rt {
    /// Send a message to `pid`.
    ///
    /// Returns [`Error::NoProc`] if the process doesn't exist.
    pub fn send(&self, pid: Pid, message: Message) -> Result<(), Error> {
        <dyn RtInner>::with_proc_mut(self, pid, move |p| p.mailbox.send(message))?
            .map_err(|_| Error::NoProc)
    }

    /// Spawn a process with the given process constructor, links, and monitors.
    pub fn spawn_ss(
        self: &Arc<Self>,
        mk_proc: &mut MakeProc<StaticStorage<ProcFuture>>,
        links: impl IntoIterator<Item = Pid>,
        monitors: impl IntoIterator<Item = Pid>,
    ) -> Result<Pid, Error> {
        let handle = RtHandle(Arc::downgrade(self));

        let mut links = links.into_iter();
        let mut mons = monitors.into_iter().map(|pid| (self.new_handle(), pid));

        let pid = self.spawn_direct(&move || handle.clone(), mk_proc, &mut links, &mut mons);

        Ok(pid)
    }

    /// Spawn a process.
    pub fn spawn<Fut>(
        self: &Arc<Self>,
        proc: impl FnOnce(ProcContext) -> Fut + 'static,
    ) -> Result<Pid, Error>
    where
        Fut: Future<Output = Result<(), Error>> + Send + 'static,
    {
        self.spawn_ss(
            &mut ts_util::fn_::fn_mut1(move |ctx| {
                StaticStorage::Box(Box::new(proc(ctx)) as Box<ProcFuture>)
            }),
            [],
            [],
        )
    }

    /// Check that the process corresponding to `pid` is alive.
    ///
    /// If not, returns `Err(Error::NoProc)`.
    pub fn check_proc(&self, pid: Pid) -> Result<(), Error> {
        <dyn RtInner>::with_proc(self, pid, |_| {})
    }

    /// Helper: run a process to completion, waiting for the result.
    pub async fn run<Fut, T>(
        self: &Arc<Self>,
        proc: impl FnOnce(ProcContext) -> Fut + Send + 'static,
    ) -> Result<T, Error>
    where
        Fut: Future<Output = Result<T, Error>> + Send,
        T: Send + 'static,
    {
        let (tx, rx) = oneshot::channel();

        self.spawn(async move |ctx| {
            tx.send_unchecked(proc(ctx).await);
            Ok(())
        })?;

        rx.await.ok_or(Error::Other).flatten()
    }

    /// Wait for all processes to complete.
    ///
    /// This does not shut down the runtime or abort processes proactively, it just waits
    /// for a state where there are no processes running.
    pub async fn wait_all_proc(&self) {
        poll_fn(|cx| self.poll_wait_all_proc(cx)).await
    }
}
