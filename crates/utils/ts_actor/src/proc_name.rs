use alloc::boxed::Box;

use smol_str::SmolStr;

use crate::Pid;

/// A name for a process.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ProcName {
    /// The literal pid of the process.
    Pid(Pid),
    /// A name registered in the global registry.
    Global(SmolStr),
    /// A name registered in a given registry. It will be resolved using the generic
    /// registry protocol.
    Via {
        /// The name of the registry process.
        registry: Box<ProcName>,
        /// The process name ot look up.
        name: SmolStr,
    },
}

impl From<Pid> for ProcName {
    fn from(value: Pid) -> Self {
        ProcName::Pid(value)
    }
}

impl From<&Pid> for ProcName {
    fn from(value: &Pid) -> Self {
        ProcName::Pid(*value)
    }
}

impl From<&str> for ProcName {
    fn from(value: &str) -> Self {
        ProcName::Global(value.into())
    }
}

impl From<SmolStr> for ProcName {
    fn from(value: SmolStr) -> Self {
        ProcName::Global(value)
    }
}

impl From<&SmolStr> for ProcName {
    fn from(value: &SmolStr) -> Self {
        ProcName::Global(value.clone())
    }
}

/// Types which can be converted into [`ProcName`].
///
/// This isn't just [`Into`] because [`ToProcName`] can be dynamically dispatched.
pub trait ToProcName: Send + Sync {
    /// Produce a [`ProcName`] from this value.
    fn to_proc_name(&self) -> ProcName;
}

impl<T> ToProcName for &T
where
    T: ToProcName + ?Sized,
{
    fn to_proc_name(&self) -> ProcName {
        T::to_proc_name(self)
    }
}

impl ToProcName for SmolStr {
    fn to_proc_name(&self) -> ProcName {
        self.into()
    }
}

impl ToProcName for str {
    fn to_proc_name(&self) -> ProcName {
        self.into()
    }
}

impl ToProcName for ProcName {
    fn to_proc_name(&self) -> ProcName {
        self.clone()
    }
}
