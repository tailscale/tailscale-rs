use alloc::sync::{Arc, Weak};
use core::fmt::{Debug, Formatter};

use crate::{error::Error, runtime::Rt};

/// A weak handle to the runtime.
///
/// This doesn't keep it alive.
#[derive(Clone)]
pub struct Handle(pub(in crate::runtime) Weak<dyn Rt>);

impl Debug for Handle {
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

impl PartialEq for Handle {
    fn eq(&self, other: &Self) -> bool {
        self.0.ptr_eq(&other.0)
    }
}

impl Eq for Handle {}

impl Handle {
    /// Try to upgrade this handle to an `Arc<dyn RuntimeT>`.
    ///
    /// Returns `Error::RuntimeStopped` if the runtime has been dropped.
    pub fn runtime(&self) -> Result<Arc<dyn Rt>, Error> {
        self.0.upgrade().ok_or(Error::RuntimeStopped)
    }
}

impl<RT> From<Arc<RT>> for Handle
where
    RT: Rt + 'static,
{
    fn from(value: Arc<RT>) -> Self {
        (&value).into()
    }
}

impl<RT> From<&Arc<RT>> for Handle
where
    RT: Rt + 'static,
{
    fn from(value: &Arc<RT>) -> Self {
        Handle(Arc::downgrade(value) as _)
    }
}

impl<RT> From<Weak<RT>> for Handle
where
    RT: Rt + 'static,
{
    fn from(value: Weak<RT>) -> Self {
        Handle(value as _)
    }
}

impl<RT> From<&Weak<RT>> for Handle
where
    RT: Rt + 'static,
{
    fn from(value: &Weak<RT>) -> Self {
        Handle(value.clone() as _)
    }
}
