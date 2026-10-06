#![no_std]

//! Experimental actor system built as an adaptation of Erlang into Rust idioms.
//!
//! `ts_actor` intentionally diverges from existing Rust ecosystem actor systems by adopting highly
//! dynamic message processing capabilities, rather than traits enforcing static message and reply
//! typing.

extern crate alloc;
pub extern crate smallbox;

pub mod mailbox;
mod message;
pub mod oneshot;
mod pid;
mod proc_name;
mod staticstorage;

pub use message::Message;
pub use pid::{AtomicPid, Pid};
pub use proc_name::{ProcName, ToProcName};
pub use staticstorage::StaticStorage;

/// Unique, opaque type.
///
/// Refs are commonly used as correlation ids between requests and responses.
// TODO(npry): better repr? runtime-unique?
#[derive(Debug, Copy, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Ref(u64);
