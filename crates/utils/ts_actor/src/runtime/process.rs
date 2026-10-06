use alloc::collections::BTreeSet;

use crate::{mailbox::Sender, pid::Pid, runtime::TaskHandle, staticstorage::StaticStorage};

/// State of a process in the system.
pub struct ProcessState {
    /// The initialization state of this process.
    pub init_state: ProcessInitState,
    /// Processes this task is linked to.
    pub links: BTreeSet<Pid>,
    /// The processes this one monitors.
    pub monitors: BTreeSet<Pid>,
    /// Processes that monitor this one.
    pub monitored_by: BTreeSet<Pid>,
    /// Sender end of the process mailbox.
    pub mailbox: Sender,
    /// Whether this process traps exit messages.
    pub trap_exit: bool,
}

/// The process state block needs to be inserted into the process table before the process
/// task is available, because the task is constructed using the context of the process
/// (which may need to e.g. set the `trap_exit` flag or manipulate links/monitors).
///
/// Hence, the process task is set to `Initializing` before the task is available, and is
/// `Initialized` thereafter. `Initialized` does not mean "still running", just that the
/// task has been constructed and spawned on its executor.
pub enum ProcessInitState {
    /// The process initializer is still in the course of executing.
    Initializing,
    /// The process has been initialized with the given [`TaskHandle`].
    Initialized(StaticStorage<dyn TaskHandle>),
}
