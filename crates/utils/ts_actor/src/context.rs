use alloc::{boxed::Box, sync::Arc};
use core::any::Any;

use smol_str::SmolStr;

use crate::{
    Error, Message, ProcFut, ProcName, Ref, StaticStorage, ToProcName,
    actors::registry,
    mailbox::{Receiver, TryRecvError},
    pid::Pid,
    protocol,
    runtime::{Handle as RuntimeHandle, Rt},
};

/// Execution context of a process.
///
/// Provides access to runtime functionality and particular methods which must run from
/// within a process context. Notably: receiving messages requires a mailbox to be available
/// and therefore must run within a process.
pub struct ProcContext {
    pub(crate) handle: RuntimeHandle,
    pub(crate) this_pid: Pid,
    pub(crate) mbox_rx: Receiver,
}

impl ProcContext {
    /// Generate a new [`Ref`], which is completely unique compared to any [`Ref`] generated
    /// before.
    pub fn new_ref(&self) -> Result<Ref, Error> {
        Ok(self.rt()?.new_ref())
    }

    /// Spawn a new process.
    pub fn spawn<Fut>(&self, proc: impl FnOnce(ProcContext) -> Fut + 'static) -> Result<Pid, Error>
    where
        Fut: Future<Output = Result<(), Error>> + Send + 'static,
    {
        self.rt()?.spawn(proc)
    }

    /// Spawn a new process which is linked to this one.
    ///
    /// The spawned process is linked before it starts executing, meaning that any process
    /// failure will be delivered.
    pub fn spawn_link<Fut>(
        &self,
        proc: impl FnOnce(ProcContext) -> Fut + 'static,
    ) -> Result<Pid, Error>
    where
        Fut: Future<Output = Result<(), Error>> + Send + 'static,
    {
        let mut proc = Some(proc);

        self.rt()?.spawn_ss(
            &mut move |ctx| {
                let proc_fut = proc.take().unwrap()(ctx);
                StaticStorage::Box(Box::new(proc_fut) as Box<ProcFut>)
            },
            [self.this_pid],
            [],
        )
    }

    /// Spawn a new process which is monitored by this one.
    ///
    /// The spawned process is monitored before it starts executing, meaning that any
    /// process failure will be delivered.
    pub fn spawn_monitor<Fut>(
        &self,
        proc: impl FnOnce(ProcContext) -> Fut + 'static,
    ) -> Result<Pid, Error>
    where
        Fut: Future<Output = Result<(), Error>> + Send + 'static,
    {
        self.rt()?.spawn_ss(
            &mut ts_util::fn_::fn_mut1(move |ctx| {
                StaticStorage::Box(Box::new(proc(ctx)) as Box<ProcFut>)
            }),
            [],
            [self.this_pid],
        )
    }

    /// Get this process's pid.
    pub const fn pid(&self) -> Pid {
        self.this_pid
    }

    /// Resolve the given `proc_name` to a [`Pid`].
    ///
    /// Returns [`Error::NoProc`] if the process is not running.
    ///
    /// This function recurses to look up [`ProcName::Via`].
    pub async fn whereis(&self, proc_name: &dyn ToProcName) -> Result<Pid, Error> {
        let rt = self.rt()?;

        let (reg, name) = match proc_name.to_proc_name() {
            ProcName::Pid(pid) => {
                rt.check_proc(pid)?;
                return Ok(pid);
            }
            ProcName::Global(s) => (rt.global_registry(), s),
            ProcName::Via { registry, name } => {
                let resolver = Box::pin(self.whereis(&registry.as_ref())).await?;

                (resolver, name)
            }
        };

        let rf = rt.new_ref();
        rt.send(
            reg,
            crate::message![protocol::registry::Lookup {
                reply: self.pid(),
                rf,
                name: name.clone(),
            }],
        )
        .await?;

        let resp = self
            .recv_where_downcast::<protocol::registry::Reply>(|reply| reply.rf == rf)
            .await?;

        let pid = resp.pid.ok_or(Error::NoProc)?;

        rt.check_proc(pid)?;

        Ok(pid)
    }

    /// Link this process to the specified one.
    ///
    /// If either process dies, it kills the other one, unless it is
    /// [trapping exit messages][ProcContext::trap_exit], in which case a
    /// [`SystemMessage::LinkExit`][crate::SystemMessage::LinkExit] is delivered.
    pub async fn link(&self, name: &dyn ToProcName) -> Result<(), Error> {
        let pid = self.whereis(name).await?;

        self.rt()?.link(self.this_pid, pid)
    }

    /// Unlink this process from the specified one.
    pub async fn unlink(&self, name: &dyn ToProcName) -> Result<(), Error> {
        let pid = self.whereis(name).await?;

        self.rt()?.unlink(self.this_pid, pid)
    }

    /// Monitor the specified process.
    ///
    /// This causes the runtime to send [`SystemMessage::Down`][crate::SystemMessage::Down]
    /// messages when monitored processes die.
    pub async fn monitor(&self, name: &dyn ToProcName) -> Result<(), Error> {
        let pid = self.whereis(name).await?;

        self.rt()?.monitor(self.this_pid, pid)
    }

    /// Unmonitor the specified process.
    ///
    /// Inverse of [`ProcContext::monitor`].
    pub async fn unmonitor(&self, name: &dyn ToProcName) -> Result<(), Error> {
        let pid = self.whereis(name).await?;

        self.rt()?.unmonitor(self.this_pid, pid)
    }

    /// Configure this process to trap exits from linked processes.
    ///
    /// This causes the runtime to send a
    /// [`SystemMessage::LinkExit`][crate::SystemMessage::LinkExit] message to this
    /// process when its links die rather than killing it (which is the default behavior).
    pub fn trap_exit(&self, mut trap: bool) -> Result<bool, Error> {
        self.rt()?.with_proc_mut_dyn(self.this_pid, &mut |p| {
            core::mem::swap(&mut trap, &mut p.trap_exit);
        })?;

        Ok(trap)
    }

    /// Receive a message from our mailbox.
    pub async fn recv(&self) -> Result<Message, Error> {
        self.mbox_rx.recv().await.ok_or(Error::NoProc)
    }

    /// Try to receive a message from our mailbox.
    ///
    /// If no message is available, returns `Ok(None)`.
    pub fn try_recv(&self) -> Result<Option<Message>, Error> {
        match self.mbox_rx.try_recv() {
            Ok(msg) => Ok(Some(msg)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Closed) => Err(Error::NoProc),
        }
    }

    /// Receive the first message matching the predicate, waiting until such a message
    /// becomes available.
    ///
    /// # Usage model
    ///
    /// This function does _not_ remove messages not matching the predicate from
    /// the process mailbox, meaning that if `recv` is never called, the process's mailbox
    /// may fill up and have no way to empty:
    ///
    /// ```no_run
    /// # use ts_actor::runtime::{Tokio, self};
    /// # let rt = runtime::new(Tokio::current());
    /// # struct MyMsg1;
    /// # struct MyMsg2;
    /// # rt.run(async |ctx| {
    /// // This is prone to locking up if messages aren't received
    /// // exactly as you expect:
    /// loop {
    ///     ctx.recv_where(|msg| msg.is::<MyMsg1>()).await?;
    ///     ctx.recv_where(|msg| msg.is::<MyMsg2>()).await?;
    /// }
    ///
    /// // Prefer to use msg_match! with recv() for a general receive loop:
    /// loop {
    ///     ts_actor::msg_match! {
    ///         ctx.recv().await?,
    ///         MyMsg1: _ => { /* do something */ },
    ///         MyMsg2: _ => { /* do something else */ },
    ///         else _msg => { /* unknown message */ },
    ///     };
    /// }
    /// # Ok(())
    /// # });
    /// ```
    ///
    /// This function will instead generally be used to model RPC patterns where
    /// this actor expects specific message(s) in response to message(s) it sent:
    ///
    /// ```no_run
    /// # use ts_actor::runtime::{Tokio, self};
    /// # let rt = runtime::new(Tokio::current());
    /// # struct MyRequest(ts_actor::Ref);
    /// # struct MyResponse(ts_actor::Ref);
    /// # rt.run(async |ctx| {
    /// let rf = ctx.new_ref()?;
    ///
    /// ctx.send(&"target_pid", ts_actor::message![MyRequest(rf)]).await?;
    /// let rep = ctx.recv_where(|msg| {
    ///     if let Some(msg) = msg.downcast_ref::<MyResponse>() && msg.0 == rf {
    ///         true
    ///     } else {
    ///         false
    ///     }
    /// }).await?;
    /// # Ok(())
    /// # });
    /// ```
    pub async fn recv_where(&self, pred: impl Fn(&Message) -> bool) -> Result<Message, Error> {
        self.mbox_rx.recv_where(pred).await.ok_or(Error::NoProc)
    }

    /// Receive the next message and attempt to downcast it to `T`.
    ///
    /// This is a helper mostly useful for writing tests or very well-defined message
    /// exchanges.
    ///
    /// Returns `Error::BadArg` if the message is not `T`.
    pub async fn recv_downcast<T>(&self) -> Result<T, Error>
    where
        T: 'static,
    {
        self.recv_where_downcast::<T>(|_| true).await
    }

    /// Helper wrapping [`ProcContext::recv_where`] which downcasts the message type to `T`.
    pub async fn recv_where_downcast<T>(&self, pred: impl Fn(&T) -> bool) -> Result<T, Error>
    where
        T: Any,
    {
        let t = self
            .recv_where(|x| {
                let Some(x) = x.downcast_ref::<T>() else {
                    return false;
                };

                pred(x)
            })
            .await?;

        // Predicate only succeeded if the message was a `T`.
        Ok(t.downcast().unwrap())
    }

    /// Receive the first message matching the predicate, returning `None` if no such
    /// message is in this process's mailbox.
    pub fn try_recv_where(
        &self,
        pred: impl Fn(&Message) -> bool,
    ) -> Result<Option<Message>, Error> {
        match self.mbox_rx.try_recv_where(pred) {
            Ok(msg) => Ok(Some(msg)),
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Closed) => Err(Error::NoProc),
        }
    }

    /// Helper wrapping [`ProcContext::try_recv_where`] which downcasts the message type to `T`.
    pub fn try_recv_where_downcast<T>(&self, pred: impl Fn(&T) -> bool) -> Result<Option<T>, Error>
    where
        T: Any,
    {
        let t = self.try_recv_where(|x| {
            let Some(x) = x.downcast_ref::<T>() else {
                return false;
            };

            pred(x)
        })?;

        // Predicate only succeeded if the message was a `T`.
        Ok(t.map(|x| x.downcast().unwrap()))
    }

    /// Send `message` to the process specified by `pid`.
    ///
    /// Waits until there is capacity in the process's mailbox.
    pub async fn send(&self, name: &dyn ToProcName, message: Message) -> Result<(), Error> {
        let pid = self.whereis(name).await?;

        self.rt()?.send(pid, message).await
    }

    /// Try to send the message to the given process synchronously.
    ///
    /// The return value is unconventional: if the receiver's mailbox was full,
    /// `Ok(Some(msg))` is returned (the message bounces). If the message was accepted,
    /// returns `Ok(None)`. This isn't treated as an error because it's not a sender-side
    /// error for the message to not make it into the receiver's queue; semantically, the
    /// receiver dropped it.
    ///
    /// This function is only async for the resolution of `name`: the actual `try_send` does
    /// not wait.
    pub async fn try_send(
        &self,
        name: &dyn ToProcName,
        message: Message,
    ) -> Result<Option<Message>, Error> {
        let pid = self.whereis(name).await?;
        self.rt()?.try_send(pid, message)
    }

    /// Register this actor as `name` with the global registry.
    pub async fn register(&self, name: impl Into<SmolStr>) -> Result<(), Error> {
        self.register_other(self.this_pid, name.into()).await
    }

    /// Register another actor as `name` with the global registry.
    pub async fn register_other(&self, pid: Pid, name: impl Into<SmolStr>) -> Result<(), Error> {
        registry::register(self, &self.rt()?.global_registry(), pid, name.into()).await?;

        Ok(())
    }

    /// Wait for the given process name to be registered in the global registry.
    pub async fn wait_proc(&self, name: impl Into<SmolStr>) -> Result<Pid, Error> {
        registry::wait_for(self, &self.rt()?.global_registry(), name.into()).await
    }

    /// Check whether the proc identified by `pid` is alive.
    pub fn check_proc(&self, pid: Pid) -> Result<(), Error> {
        self.rt()?.check_proc(pid)
    }

    /// Report the [`Pid`] of the global registry.
    pub fn global_registry(&self) -> Result<Pid, Error> {
        Ok(self.rt()?.global_registry())
    }

    /// Sleep for the given [`Duration`][core::time::Duration].
    ///
    /// This uses the executor's sleep implementation.
    pub async fn sleep(&self, duration: core::time::Duration) -> Result<(), Error> {
        self.rt()?.executor().sleep(duration).await;
        Ok(())
    }

    pub(crate) fn rt(&self) -> Result<Arc<dyn Rt>, Error> {
        self.handle.runtime()
    }
}
