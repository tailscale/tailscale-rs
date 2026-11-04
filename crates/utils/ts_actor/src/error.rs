//! Errors which may occur in `ts_actor`.

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

/// The requested process wasn't found.
///
/// It may not have been running, or, e.g. it was looked up in a registry and there was no
/// process with the given name.
///
/// This is separate from [`Error`] because it's relatively common for functions to only
/// have the possibility to produce [`Error::NoProc`].
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, thiserror::Error)]
#[error("no such process")]
pub struct NoProc;

impl From<NoProc> for Error {
    fn from(_: NoProc) -> Self {
        Error::NoProc
    }
}

/// Error which occurs when the runtime is stopped.
///
/// It's strongly preferred to use this error in a `Result` rather than panicking because
/// `panic = abort` would make a task-scoped panic halt the whole process, even if this is
/// an expected case during runtime shutdown. E.g. any [`ProcContext`][crate::ProcContext]
/// method requires the runtime to be available and could be written to panic if it wasn't.
/// With `panic = unwind`, this is fine, since the panic would be caught and converted into
/// [`Error::Panic`]. But with `panic = unwind`, halting the runtime would _always_ abort
/// the process. This is a relatively straightforward way to avoid that, even if it requires
/// a bit of extra accounting.
///
/// This is separated from [`Error`] to clearly indicate that a function call is "normally
/// infallible" -- this error occurring needs to be caught, but it won't be recoverable.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, thiserror::Error)]
#[error("runtime is stopped")]
pub struct RuntimeStopped;

impl From<RuntimeStopped> for Error {
    fn from(_: RuntimeStopped) -> Error {
        Error::RuntimeStopped
    }
}
