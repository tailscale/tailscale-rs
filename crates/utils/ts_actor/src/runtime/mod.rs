//! Actor runtime.

mod executor;
mod handle;
mod inner;
mod process;
mod rt;

use alloc::{boxed::Box, collections::BTreeMap, sync::Arc, vec};
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

#[cfg(feature = "async-executor")]
pub use executor::AsyncExecutor;
#[cfg(feature = "smol")]
pub use executor::Smol;
#[cfg(feature = "tokio")]
pub use executor::Tokio;
pub use executor::{Executor, TaskError, TaskHandle};
pub use handle::Handle;
use inner::Inner;
use lock_api::{Mutex, RawMutex, RawRwLockUpgrade, RwLock};
pub(crate) use process::{ProcessInitState, ProcessState};
pub use rt::Rt;
pub(crate) use rt::RtInternal;

use crate::{Pid, StaticStorage, actors::registry, gen_server};

/// Construct a new runtime around the given executor.
///
/// This uses `parking_lot` mutexes.
#[cfg(feature = "std")]
pub fn new(executor: impl Executor) -> Arc<dyn Rt> {
    new_with::<parking_lot::RawRwLock, parking_lot::RawMutex>(executor)
}

/// Construct a new runtime around the given executor with the given mutexes.
pub fn new_with<RW, M>(executor: impl Executor) -> Arc<dyn Rt>
where
    RW: RawRwLockUpgrade + Send + Sync + 'static,
    M: RawMutex + Send + Sync + 'static,
{
    new_ss_with::<RW, M>(StaticStorage::Box(Box::new(executor)))
}

/// Construct a new runtime around the given executor with the given mutexes and a
/// particular executor storage.
pub fn new_ss_with<RW, M>(executor: StaticStorage<dyn Executor>) -> Arc<dyn Rt>
where
    RW: RawRwLockUpgrade + Send + Sync + 'static,
    M: RawMutex + Send + Sync + 'static,
{
    let inner = Arc::new(Inner::<RW, M> {
        executor,
        next_pid: AtomicUsize::new(0),
        next_ref: AtomicU64::new(0),
        process_table: RwLock::new(BTreeMap::new()),
        process_complete_wakers: Mutex::new(vec![]),
        global_registry: Pid(0).into(),
    });

    let rt: &Arc<dyn Rt> = &(inner.clone() as _);
    let global_pid = rt.spawn(gen_server::start(registry::Registry, ())).unwrap();

    inner.global_registry.store(global_pid, Ordering::Release);

    inner as _
}
