#![no_std]

//! Experimental actor system built as an adaptation of Erlang into Rust idioms.
//!
//! `ts_actor` intentionally diverges from existing Rust ecosystem actor systems by adopting highly
//! dynamic message processing capabilities, rather than traits enforcing static message and reply
//! typing.

extern crate alloc;
pub extern crate smallbox;

mod message;
pub mod oneshot;
mod staticstorage;

pub use message::Message;
pub use staticstorage::StaticStorage;
