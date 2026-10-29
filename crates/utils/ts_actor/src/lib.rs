#![no_std]
#![doc = include_str!("../README.md")]

extern crate alloc;
pub extern crate smallbox;
#[cfg(feature = "std")]
extern crate std;

use core::fmt::{Debug, Formatter};

pub mod actors;
mod context;
mod error;
pub mod gen_server;
pub mod mailbox;
mod message;
pub mod oneshot;
mod pid;
mod proc_name;
pub mod protocol;
pub mod runtime;
mod static_storage;
pub mod supervisor;
mod system_message;
pub(crate) mod util;

pub use context::ProcContext;
pub use error::Error;
pub use message::Message;
pub use pid::{AtomicPid, Pid};
pub use proc_name::{ProcName, ToProcName};
#[doc(inline)]
pub use runtime::RtHandle;
pub use static_storage::StaticStorage;
pub use system_message::{LinkExitReason, SystemMessage};
pub use util::MonitorGuard;

/// Convenience alias for a function that makes a process future.
pub type MakeProc<Fut> = dyn FnMut(ProcContext) -> Fut;
/// Convenience alias for a process future.
pub type ProcFuture = dyn Future<Output = Result<(), Error>> + Send;
/// Convenience alias for [`ProcFuture`] with the additional constraint that the future is
/// `'static`.
pub type StaticProcFuture = dyn Future<Output = Result<(), Error>> + Send + 'static;

/// Unique, opaque type.
///
/// Commonly used as correlation ids between requests and responses.
///
/// Erlang calls this type `ref`, but we renamed to avoid colliding conceptually with Rust
/// references.
// TODO(npry): better repr? runtime-unique?
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Handle(u64);

impl core::fmt::Display for Handle {
    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
        f.debug_tuple("Handle").field(&self.0).finish()
    }
}
