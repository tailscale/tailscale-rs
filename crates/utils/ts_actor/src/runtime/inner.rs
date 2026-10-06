use alloc::{
    boxed::Box,
    collections::{BTreeMap, BTreeSet},
    vec::Vec,
};
use core::{
    sync::atomic::{AtomicU64, AtomicUsize, Ordering},
    task::{Context, Poll, Waker},
};

use lock_api::{Mutex, RawMutex, RawRwLock, RawRwLockUpgrade, RwLock};

use crate::{
    AtomicPid, Error, LinkExitReason, MkProc, Pid, ProcContext, ProcFut, Ref, StaticStorage,
    SystemMessage,
    mailbox::{Mailbox, TrySendError, async_mailbox},
    message,
    runtime::{Executor, Handle, ProcessInitState, ProcessState, RtInternal},
};

struct ProcDoneGuard {
    pid: Pid,
    handle: Handle,
}

impl Drop for ProcDoneGuard {
    fn drop(&mut self) {
        let Ok(handle) = self.handle.runtime() else {
            return;
        };

        handle.notify_proc_done(self.pid);
    }
}

pub struct Inner<RW, M> {
    pub executor: StaticStorage<dyn Executor>,
    pub next_pid: AtomicUsize,
    pub next_ref: AtomicU64,
    pub process_table: RwLock<RW, BTreeMap<Pid, RwLock<RW, ProcessState>>>,
    pub process_complete_wakers: Mutex<M, Vec<Waker>>,
    pub global_registry: AtomicPid,
}

impl<RW, M> Inner<RW, M> {
    fn remove_proc(&self, pid: Pid, reason: LinkExitReason) -> Result<(), Error>
    where
        RW: RawRwLock,
        M: RawMutex,
    {
        // Minor optimization: run it first once with the specified pid explicitly, rather than
        // putting it into the set. If there are no links to kill, the set doesn't allocate.
        let mut pids = BTreeSet::new();
        self.remove_one(pid, &mut pids, reason.clone())?;

        while let Some(pid) = pids.pop_first() {
            self.remove_one(pid, &mut pids, reason.clone())?;
        }

        Ok(())
    }

    /// Remove a single process by pid.
    ///
    /// Adds any additional linked processes to remove to `pids_to_remove`. Done this way
    /// for tracking in the [`RtInternal::kill`] impl for `Inner`.
    fn remove_one(
        &self,
        pid: Pid,
        pids_to_remove: &mut BTreeSet<Pid>,
        reason: LinkExitReason,
    ) -> Result<(), Error>
    where
        RW: RawRwLock,
        M: RawMutex,
    {
        let proc = {
            let mut ptable = self.process_table.write();

            let Some(proc) = ptable.get(&pid) else {
                return Err(Error::NoProc);
            };

            {
                let mut proc = proc.write();
                if let ProcessInitState::Initialized(task) = &mut proc.init_state {
                    task.abort();
                }
            }

            let proc = ptable.remove(&pid);

            if ptable.is_empty() {
                for waker in self.process_complete_wakers.lock().drain(..) {
                    waker.wake();
                }
            }

            proc
        };

        pids_to_remove.remove(&pid);

        let Some(proc) = proc else {
            return Err(Error::NoProc);
        };

        let proc = proc.into_inner();
        let ptable = self.process_table.read();

        for monitor_pid in &proc.monitored_by {
            let Some(mon) = ptable.get(monitor_pid) else {
                tracing::warn!(%monitor_pid, "skip monitor missing from proc table");
                continue;
            };

            let mut mon = mon.write();
            if let Err(e) = mon.mailbox.try_send(message![SystemMessage::Down(pid)])
                && matches!(e, TrySendError::Full(_))
            {
                tracing::warn!(%monitor_pid, "failed to deliver DOWN");
            }

            mon.monitors.remove(&pid);
        }

        for monitored_pid in &proc.monitors {
            let Some(target) = ptable.get(monitored_pid) else {
                tracing::warn!(%monitored_pid, "skip monitored process missing from proc table");
                continue;
            };

            target.write().monitored_by.remove(&pid);
        }

        for link_pid in &proc.links {
            let Some(link) = ptable.get(link_pid) else {
                tracing::warn!(%link_pid, "skip link missing from proc table");
                continue;
            };

            let mut link = link.write();
            link.links.remove(&pid);

            if link.trap_exit {
                if let Err(e) = link.mailbox.try_send(message![SystemMessage::LinkExit {
                    linked_process: pid,
                    reason: reason.clone(),
                }]) && matches!(e, TrySendError::Full(_))
                {
                    tracing::warn!(%link_pid, "failed to deliver link exit (mailbox full)");
                }
            } else {
                pids_to_remove.insert(*link_pid);
                continue;
            }
        }

        Ok(())
    }
}

macro_rules! get_procs {
    ($process_table:expr $(, $name:ident => $pid:expr)* $(,)?) => {
        let ptab = $process_table.read();

        $(
            let $name = ptab.get(&$pid).ok_or(Error::NoProc)?;
        )*
    }
}

impl<RW, M> RtInternal for Inner<RW, M>
where
    RW: RawRwLockUpgrade + Send + Sync + 'static,
    M: RawMutex + Send + Sync + 'static,
{
    fn spawn_direct(
        &self,
        get_handle: &dyn Fn() -> Handle,
        f: &mut MkProc<StaticStorage<ProcFut>>,
        init_links: &mut dyn Iterator<Item = Pid>,
        init_monitors: &mut dyn Iterator<Item = Pid>,
    ) -> Pid {
        let pid = Pid(self.next_pid.fetch_add(1, Ordering::Relaxed));
        let mut my_links = BTreeSet::new();
        let mut monitored_by = BTreeSet::new();

        {
            let ptab = self.process_table.read();
            for link_pid in init_links {
                let Some(link) = ptab.get(&link_pid) else {
                    tracing::warn!(%link_pid, "no link process");
                    continue;
                };

                link.write().links.insert(pid);
                my_links.insert(link_pid);
            }

            for monitor_pid in init_monitors {
                let Some(mon) = ptab.get(&monitor_pid) else {
                    tracing::warn!(%monitor_pid, "no monitor process");
                    continue;
                };

                mon.write().monitors.insert(pid);
                monitored_by.insert(monitor_pid);
            }
        }

        let (tx, rx) = async_mailbox::<M>(Mailbox::new(32));

        // Insert the process state block first, with task in initializing state.
        {
            let mut pt = self.process_table.write();
            pt.insert(
                pid,
                RwLock::new(ProcessState {
                    init_state: ProcessInitState::Initializing,
                    monitors: Default::default(),
                    monitored_by,
                    links: my_links,
                    mailbox: tx,
                    trap_exit: false,
                }),
            );
        };

        let drop_guard = ProcDoneGuard {
            pid,
            handle: get_handle(),
        };

        // Compute the task future _after_ process insertion, so it can access its own state block
        // (outside the ptable lock -- user fn can kind of do anything here, so we can't be holding
        // it).

        let ctx = ProcContext {
            handle: get_handle(),
            this_pid: pid,
            mbox_rx: rx,
        };

        let future = f(ctx);

        let task = self.executor.spawn(StaticStorage::Box(Box::new(async move {
            let _guard = drop_guard;

            let result = future.await;
            if let Err(e) = result {
                tracing::error!(%pid, error = %e, "process failed");
            }

            result
        }) as Box<ProcFut>));

        // Finally, insert the task.
        {
            let pt = self.process_table.read();
            if let Some(proc) = pt.get(&pid) {
                let mut p = proc.write();
                p.init_state = ProcessInitState::Initialized(task);
            } else {
                tracing::warn!(%pid, "process removed from table before task startup");
            }
        }

        pid
    }

    #[tracing::instrument(skip_all, fields(%pid))]
    fn kill(&self, pid: Pid) -> Result<(), Error> {
        self.remove_proc(pid, LinkExitReason::Killed)
    }

    #[tracing::instrument(skip_all, fields(%a, %b))]
    fn link(&self, mut a: Pid, mut b: Pid) -> Result<(), Error> {
        if a == b {
            tracing::error!("trying to link pid to itself");
            return Err(Error::BadArg);
        }

        // Deadlock avoidance: always take simultaneous process locks in increasing-pid order.
        if a > b {
            core::mem::swap(&mut a, &mut b);
        }

        get_procs!(self.process_table, a_proc => a, b_proc => b);

        let mut a_proc = a_proc.write();
        let mut b_proc = b_proc.write();

        a_proc.links.insert(b);
        b_proc.links.insert(a);

        Ok(())
    }

    #[tracing::instrument(skip_all, fields(%a, %b))]
    fn unlink(&self, mut a: Pid, mut b: Pid) -> Result<(), Error> {
        if a == b {
            tracing::error!("trying to unlink pid from itself");
            return Err(Error::BadArg);
        }

        // Deadlock avoidance: always take simultaneous process locks in increasing-pid order.
        if a > b {
            core::mem::swap(&mut a, &mut b);
        }

        get_procs!(self.process_table, a_proc => a, b_proc => b);

        let mut a_proc = a_proc.write();
        let mut b_proc = b_proc.write();

        a_proc.links.remove(&b);
        b_proc.links.remove(&a);

        Ok(())
    }

    #[tracing::instrument(skip_all, fields(%monitoring_pid, %monitored_pid))]
    fn monitor(&self, monitoring_pid: Pid, monitored_pid: Pid) -> Result<(), Error> {
        if monitoring_pid == monitored_pid {
            tracing::error!("monitoring pid was the same as monitored pid");
            return Err(Error::BadArg);
        }

        get_procs!(self.process_table, monitoring_proc => monitoring_pid, monitored_proc => monitored_pid);

        // Deadlock avoidance: always take simultaneous process locks in increasing-pid order.
        let (mut monitoring_proc, mut monitored_proc) = if monitoring_pid < monitored_pid {
            let m1 = monitoring_proc.write();
            let m2 = monitored_proc.write();

            (m1, m2)
        } else {
            let m2 = monitored_proc.write();
            let m1 = monitoring_proc.write();

            (m1, m2)
        };

        monitoring_proc.monitors.insert(monitored_pid);
        monitored_proc.monitored_by.insert(monitoring_pid);

        Ok(())
    }

    #[tracing::instrument(skip_all, fields(%monitoring_pid, %monitored_pid))]
    fn unmonitor(&self, monitoring_pid: Pid, monitored_pid: Pid) -> Result<(), Error> {
        if monitoring_pid == monitored_pid {
            tracing::error!("monitoring pid was the same as monitored pid");
            return Err(Error::BadArg);
        }

        get_procs!(self.process_table, monitoring_proc => monitoring_pid, monitored_proc => monitored_pid);

        // Deadlock avoidance: always take simultaneous process locks in increasing-pid order.
        let (mut monitoring_proc, mut monitored_proc) = if monitoring_pid < monitored_pid {
            let m1 = monitoring_proc.write();
            let m2 = monitored_proc.write();

            (m1, m2)
        } else {
            let m2 = monitored_proc.write();
            let m1 = monitoring_proc.write();

            (m1, m2)
        };

        monitoring_proc.monitors.remove(&monitored_pid);
        monitored_proc.monitored_by.remove(&monitoring_pid);

        Ok(())
    }

    /// Get a read ref to a given process by pid, invoking the closure on it.
    fn with_proc_dyn(&self, pid: Pid, f: &mut dyn FnMut(&ProcessState)) -> Result<(), Error> {
        get_procs!(self.process_table, proc => pid);
        f(&proc.read());

        Ok(())
    }

    /// Get a mutable ref to a given process by pid, invoking the closure on it.
    fn with_proc_mut_dyn(
        &self,
        pid: Pid,
        f: &mut dyn FnMut(&mut ProcessState),
    ) -> Result<(), Error> {
        get_procs!(self.process_table, proc => pid);
        f(&mut proc.write());

        Ok(())
    }

    fn notify_proc_done(&self, pid: Pid) {
        let _result = self.remove_proc(pid, LinkExitReason::Normal);
    }

    /// Get the pid of the global registry.
    fn global_registry(&self) -> Pid {
        self.global_registry.load(Ordering::Acquire)
    }

    fn new_ref(&self) -> Ref {
        Ref(self.next_ref.fetch_add(1, Ordering::Relaxed))
    }

    fn executor(&self) -> &dyn Executor {
        self.executor.as_ref()
    }

    fn poll_wait_all_proc(&self, cx: &mut Context) -> Poll<()> {
        let reg_pid = self.global_registry.load(Ordering::Acquire);
        let proc_table = self.process_table.read();

        if proc_table.is_empty() || proc_table.iter().all(|(&x, _)| x == reg_pid) {
            return Poll::Ready(());
        };

        self.process_complete_wakers.lock().push(cx.waker().clone());

        Poll::Pending
    }
}
