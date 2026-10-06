use crate::{Error, Pid};

/// Messages the system may send to a process.
#[derive(Debug, Clone)]
pub enum SystemMessage {
    /// Monitored process died.
    Down(Pid),

    /// Linked process died.
    ///
    /// This message is only delivered if the process has 'trap exit' enabled.
    LinkExit {
        /// The [`Pid`] of the process which died.
        linked_process: Pid,
        /// The reason the linked process died.
        reason: LinkExitReason,
    },
}

/// The reason a linked process died.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkExitReason {
    /// The process terminated normally.
    Normal,
    /// The process was killed externally.
    Killed,
    /// A supervisor shut down the process.
    Shutdown,
    /// An error occurred.
    Error(Error),
}
