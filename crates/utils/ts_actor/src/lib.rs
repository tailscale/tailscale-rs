#![no_std]

//! Experimental actor system built as an adaptation of Erlang into Rust idioms.
//!
//! `ts_actor` intentionally diverges from existing Rust ecosystem actor systems by adopting highly
//! dynamic message processing capabilities, rather than traits enforcing static message and reply
//! typing.

extern crate alloc;
pub extern crate smallbox;
#[cfg(feature = "std")]
extern crate std;

use core::fmt::Debug;

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
mod staticstorage;
mod system_message;
pub(crate) mod util;

pub use context::ProcContext;
pub use error::Error;
pub use message::Message;
pub use pid::{AtomicPid, Pid};
pub use proc_name::{ProcName, ToProcName};
#[doc(inline)]
pub use runtime::Handle as RtHandle;
pub use staticstorage::StaticStorage;
pub use system_message::{LinkExitReason, SystemMessage};

/// Convenience alias for a function that makes a process future.
pub type MkProc<Fut> = dyn FnMut(ProcContext) -> Fut;
/// Convenience alias for a process future.
pub type ProcFut = dyn Future<Output = Result<(), Error>> + Send;
/// Convenience alias for [`ProcFut`] with the additional constraint that the future is
/// `'static`.
pub type StaticProcFut = dyn Future<Output = Result<(), Error>> + Send + 'static;

/// Unique, opaque type.
///
/// Refs are commonly used as correlation ids between requests and responses.
// TODO(npry): better repr? runtime-unique?
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ref(u64);
