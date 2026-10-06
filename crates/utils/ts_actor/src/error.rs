/// Errors which may occur in the actor system.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, thiserror::Error)]
pub enum Error {
    /// The requested process wasn't found.
    ///
    /// It may not have been running, or, e.g. it was looked up in a registry and there was no
    /// process with the given name.
    #[error("no such process")]
    NoProc,
    /// A function or message handler was invoked with a bad argument.
    #[error("bad argument")]
    BadArg,
    /// The actor system terminated and so the request couldn't be executed.
    #[error("runtime is stopped")]
    RuntimeStopped,
    /// A process panicked.
    #[error("panic encountered")]
    Panic,
    /// An unknown error occurred.
    #[error("unknown error")]
    Other,
}
