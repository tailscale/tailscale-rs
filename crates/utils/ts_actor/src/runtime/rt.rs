use alloc::{boxed::Box, sync::Arc};
use core::{
    future::{Future, poll_fn},
    task::{Context, Poll},
};

use crate::{
    Error, Message, MkProc, Pid, ProcContext, ProcFut, Ref, StaticStorage,
    mailbox::TrySendError,
    oneshot,
    runtime::{Executor, Handle, ProcessState},
};

/// Dynamically dispatched trait describing an actor runtime.
pub trait RtInternal: Send + Sync {
    /// Low-level method to spawn a process.
    ///
    /// Invariant: `mk_proc_fut` is invoked at most once; the `&mut dyn FnMut` is for
    /// object-safety.
    fn spawn_direct(
        &self,
        get_handle: &dyn Fn() -> Handle,
        mk_proc_fut: &mut MkProc<StaticStorage<ProcFut>>,
        links: &mut dyn Iterator<Item = Pid>,
        monitors: &mut dyn Iterator<Item = Pid>,
    ) -> Pid;

    /// Kill a process immediately.
    fn kill(&self, pid: Pid) -> Result<(), Error>;

    /// Link process `a` to process `b`. Order doesn't matter.
    fn link(&self, a: Pid, b: Pid) -> Result<(), Error>;

    /// Unlink process `a` from process `b`. Order doesn't matter.
    fn unlink(&self, a: Pid, b: Pid) -> Result<(), Error>;

    /// Establish a monitor from the `monitoring` process on the `monitored` process.
    fn monitor(&self, monitoring: Pid, monitored: Pid) -> Result<(), Error>;

    /// Remove the monitor from the `monitoring` process on the `monitored` process.
    fn unmonitor(&self, monitoring: Pid, monitored: Pid) -> Result<(), Error>;

    /// Get the process state for the given pid and invoke the closure with it.
    ///
    /// Invariant: either the closure will be called exactly once, or the return value is
    /// an error.
    fn with_proc_dyn(&self, pid: Pid, f: &mut dyn FnMut(&ProcessState)) -> Result<(), Error>;

    /// Get mutable process state for the given pid and invoke the closure with it.
    ///
    /// Invariant: either the closure will be called exactly once, or the return value is
    /// an error.
    fn with_proc_mut_dyn(
        &self,
        pid: Pid,
        f: &mut dyn FnMut(&mut ProcessState),
    ) -> Result<(), Error>;

    /// Internal: notify the runtime that the process corresponding to `pid` died.
    fn notify_proc_done(&self, pid: Pid);

    /// Get the pid of the global registry.
    fn global_registry(&self) -> Pid;

    /// Generate a new [`Ref`].
    fn new_ref(&self) -> Ref;

    /// Get a handle to the runtime's [`Executor`].
    fn executor(&self) -> &dyn Executor;

    /// Wait for all processes to complete.
    ///
    /// This does not shut down the runtime or abort processes proactively, it just waits
    /// for a state where there are no processes running.
    fn poll_wait_all_proc(&self, cx: &mut Context) -> Poll<()>;
}

/// Public-facing representation of a runtime.
pub trait Rt: RtInternal {}

impl<T> Rt for T where T: RtInternal {}

impl dyn Rt {
    /// Send a message to `pid`.
    ///
    /// Returns [`Error::NoProc`] if the process doesn't exist.
    pub async fn send(&self, pid: Pid, message: Message) -> Result<(), Error> {
        let mut fut = None;
        let mut msg = Some(message);

        self.with_proc_mut_dyn(pid, &mut |p| {
            fut = Some(p.mailbox.send(msg.take().unwrap()));
        })?;

        fut.unwrap().await.map_err(|_| Error::NoProc)
    }

    /// Try to send the message to the given `pid` synchronously.
    ///
    /// The return value is unconventional: if the receiver's mailbox was full,
    /// `Ok(Some(msg))` is returned (the message bounces). If the message was accepted,
    /// returns `Ok(None)`. This isn't treated as an error because it's not a sender-side
    /// error for the message to not make it into the receiver's queue; semantically, the
    /// receiver dropped it.
    ///
    /// This function is only async for the resolution of `name`: the actual `try_send` does
    /// not wait.
    pub fn try_send(&self, pid: Pid, message: Message) -> Result<Option<Message>, Error> {
        let mut result = None;
        let mut message = Some(message);

        self.with_proc_mut_dyn(pid, &mut |p| {
            result = Some(p.mailbox.try_send(message.take().unwrap()));
        })?;

        match result.unwrap() {
            Ok(_) => Ok(None),
            Err(TrySendError::Full(msg)) => Ok(Some(msg)),
            Err(TrySendError::Closed(_)) => Err(Error::NoProc),
        }
    }

    /// Spawn a process with the given process constructor, links, and monitors.
    pub fn spawn_ss(
        self: &Arc<Self>,
        mk_proc: &mut MkProc<StaticStorage<ProcFut>>,
        links: impl IntoIterator<Item = Pid>,
        monitors: impl IntoIterator<Item = Pid>,
    ) -> Result<Pid, Error> {
        let handle = Handle(Arc::downgrade(self));

        let mut links = links.into_iter();
        let mut mons = monitors.into_iter();

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
                StaticStorage::Box(Box::new(proc(ctx)) as Box<ProcFut>)
            }),
            [],
            [],
        )
    }

    /// Check that the process corresponding to `pid` is alive.
    ///
    /// If not, returns `Err(Error::NoProc)`.
    pub fn check_proc(&self, pid: Pid) -> Result<(), Error> {
        <dyn RtInternal>::with_proc(self, pid, |_| {})
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

impl dyn RtInternal {
    /// Execute the closure `f` on the [`ProcessState`] corresponding to `pid`.
    pub fn with_proc<T>(&self, pid: Pid, f: impl FnOnce(&ProcessState) -> T) -> Result<T, Error> {
        let mut f = Some(f);
        let mut out = None;

        self.with_proc_dyn(pid, &mut |state| out = Some(f.take().unwrap()(state)))?;

        Ok(out.unwrap())
    }

    /// Execute the closure `f` on a mutable ref to the [`ProcessState`] corresponding to
    /// `pid`.
    pub fn with_proc_mut<T>(
        &self,
        pid: Pid,
        f: impl FnOnce(&mut ProcessState) -> T,
    ) -> Result<T, Error> {
        let mut f = Some(f);
        let mut out = None;

        self.with_proc_mut_dyn(pid, &mut |state| out = Some(f.take().unwrap()(state)))?;

        Ok(out.unwrap())
    }
}
