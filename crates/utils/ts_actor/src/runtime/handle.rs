use alloc::sync::{Arc, Weak};
use core::fmt::{Debug, Formatter};

use crate::{error::Error, runtime::Rt};

/// A weak handle to the runtime.
///
/// This doesn't keep it alive.
#[derive(Clone)]
pub struct RtHandle(pub(in crate::runtime) Weak<dyn Rt>);

impl Debug for RtHandle {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "RuntimeHandle{}",
            if self.0.strong_count() == 0 {
                "(dead)"
            } else {
                ""
            }
        )
    }
}

impl PartialEq for RtHandle {
    fn eq(&self, other: &Self) -> bool {
        self.0.ptr_eq(&other.0)
    }
}

impl Eq for RtHandle {}

impl RtHandle {
    /// Try to upgrade this handle to an `Arc<dyn RuntimeT>`.
    ///
    /// Returns `Error::RuntimeStopped` if the runtime has been dropped.
    pub fn runtime(&self) -> Result<Arc<dyn Rt>, Error> {
        self.0.upgrade().ok_or(Error::RuntimeStopped)
    }
}

impl<RT> From<Arc<RT>> for RtHandle
where
    RT: Rt + 'static,
{
    fn from(value: Arc<RT>) -> Self {
        (&value).into()
    }
}

impl<RT> From<&Arc<RT>> for RtHandle
where
    RT: Rt + 'static,
{
    fn from(value: &Arc<RT>) -> Self {
        RtHandle(Arc::downgrade(value) as _)
    }
}

impl<RT> From<Weak<RT>> for RtHandle
where
    RT: Rt + 'static,
{
    fn from(value: Weak<RT>) -> Self {
        RtHandle(value as _)
    }
}

impl<RT> From<&Weak<RT>> for RtHandle
where
    RT: Rt + 'static,
{
    fn from(value: &Weak<RT>) -> Self {
        RtHandle(value.clone() as _)
    }
}
