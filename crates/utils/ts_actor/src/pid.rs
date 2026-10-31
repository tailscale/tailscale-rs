use core::{
    fmt::{Debug, Display, Formatter},
    sync::atomic::{AtomicUsize, Ordering},
};

use crate::{ProcName, ToProcName};

/// A process id.
///
/// These are uniquely allocated by a given runtime for a given process. They are never
/// reused and so uniquely identify the process for the whole duration of the runtime.
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Pid(pub(crate) usize);

impl Display for Pid {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(f, "pid#{}", self.0)
    }
}

/// An atomic wrapper around [`Pid`].
pub struct AtomicPid(AtomicUsize);

impl AtomicPid {
    /// Construct a new [`AtomicPid`] with an initial value of `pid`.
    pub const fn new(pid: Pid) -> Self {
        Self(AtomicUsize::new(pid.0))
    }

    /// Load the value with the given `ordering`.
    pub fn load(&self, ordering: Ordering) -> Pid {
        Pid(self.0.load(ordering))
    }

    /// Store `val` with the given `ordering`.
    pub fn store(&self, val: Pid, ordering: Ordering) {
        self.0.store(val.0, ordering)
    }
}

impl Debug for AtomicPid {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("AtomicPid")
            .field(&self.0.load(Ordering::Relaxed))
            .finish()
    }
}

impl From<Pid> for AtomicPid {
    fn from(value: Pid) -> Self {
        AtomicPid(value.0.into())
    }
}

impl ToProcName for Pid {
    fn to_proc_name(&self) -> ProcName {
        self.into()
    }
}
